package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const apiKeyPrefix = "ip_live_"

type APIKey struct {
	ID          uuid.UUID  `json:"id"`
	OrgID       uuid.UUID  `json:"org_id"`
	UserID      uuid.UUID  `json:"user_id"`
	Name        string     `json:"name"`
	KeyPrefix   string     `json:"key_prefix"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

type CreateAPIKeyRequest struct {
	Name      string     `json:"name" binding:"required"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type CreateAPIKeyResponse struct {
	APIKey
	Key string `json:"key"` // Only returned once on creation
}

// generateAPIKey creates a new random API key in the format ip_live_<base64url>
func generateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate key bytes: %w", err)
	}
	return apiKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// hashAPIKey returns the SHA-256 hex hash of a key
func hashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// keyPrefix returns the display prefix (first 16 chars)
func keyDisplayPrefix(key string) string {
	if len(key) > 16 {
		return key[:16] + "..."
	}
	return key
}

func (h *Handler) listAPIKeys(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, user_id, name, key_prefix, last_used_at, created_at, expires_at
		FROM api_keys
		WHERE org_id = $1 AND user_id = $2
		ORDER BY created_at DESC
	`, orgID, userID)
	if err != nil {
		h.logger.Error("failed to list api keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list api keys"})
		return
	}
	defer rows.Close()

	keys := []APIKey{}
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.OrgID, &k.UserID, &k.Name, &k.KeyPrefix, &k.LastUsedAt, &k.CreatedAt, &k.ExpiresAt); err != nil {
			h.logger.Error("failed to scan api key", zap.Error(err))
			continue
		}
		keys = append(keys, k)
	}

	c.JSON(http.StatusOK, keys)
}

func (h *Handler) createAPIKey(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var req CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	key, err := generateAPIKey()
	if err != nil {
		h.logger.Error("failed to generate api key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate key"})
		return
	}

	keyHash := hashAPIKey(key)
	keyPrefix := keyDisplayPrefix(key)

	id := uuid.New()
	now := time.Now()

	_, err = h.db.Exec(c.Request.Context(), `
		INSERT INTO api_keys (id, org_id, user_id, name, key_prefix, key_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, id, orgID, userID, req.Name, keyPrefix, keyHash, now, req.ExpiresAt)
	if err != nil {
		h.logger.Error("failed to create api key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create api key"})
		return
	}

	c.JSON(http.StatusCreated, CreateAPIKeyResponse{
		APIKey: APIKey{
			ID:        id,
			OrgID:     orgID,
			UserID:    userID,
			Name:      req.Name,
			KeyPrefix: keyPrefix,
			CreatedAt: now,
			ExpiresAt: req.ExpiresAt,
		},
		Key: key,
	})
}

func (h *Handler) deleteAPIKey(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	keyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key id"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM api_keys WHERE id = $1 AND org_id = $2 AND user_id = $3
	`, keyID, orgID, userID)
	if err != nil {
		h.logger.Error("failed to delete api key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete api key"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "api key not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "api key deleted"})
}

// validateAPIKey looks up an API key by its hash and returns org_id/user_id/role.
// Returns an error if the key is not found, expired, or invalid.
func (h *Handler) validateAPIKey(c *gin.Context, key string) (orgID uuid.UUID, userID uuid.UUID, role string, err error) {
	keyHash := hashAPIKey(key)

	var expiresAt *time.Time
	var userRole string

	err = h.db.QueryRow(c.Request.Context(), `
		SELECT k.org_id, k.user_id, k.expires_at, u.role
		FROM api_keys k
		JOIN users u ON u.id = k.user_id
		WHERE k.key_hash = $1
	`, keyHash).Scan(&orgID, &userID, &expiresAt, &userRole)
	if err != nil {
		return uuid.Nil, uuid.Nil, "", fmt.Errorf("invalid api key")
	}

	if expiresAt != nil && time.Now().After(*expiresAt) {
		return uuid.Nil, uuid.Nil, "", fmt.Errorf("api key expired")
	}

	// Update last_used_at asynchronously
	go func() {
		_, _ = h.db.Exec(c.Request.Context(), `
			UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1
		`, keyHash)
	}()

	return orgID, userID, userRole, nil
}
