package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// AuthUser represents a basic auth user for a proxy
type AuthUser struct {
	ID        uuid.UUID `json:"id"`
	ProxyID   uuid.UUID `json:"proxy_id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CreateAuthUserRequest is the request body for creating an auth user
type CreateAuthUserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required,min=6"`
}

// listAuthUsers returns all auth users for a proxy
func (h *Handler) listAuthUsers(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	proxyIDStr := c.Param("pid")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	proxyID, err := uuid.Parse(proxyIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy ID"})
		return
	}

	// Verify proxy belongs to agent and org
	var exists bool
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(
			SELECT 1 FROM proxy_hosts p
			JOIN agents a ON p.agent_id = a.id
			WHERE p.id = $1 AND p.agent_id = $2 AND a.org_id = $3
		)
	`, proxyID, agentID, orgID).Scan(&exists)

	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy host not found"})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, proxy_id, username, created_at, updated_at
		FROM proxy_auth_users
		WHERE proxy_id = $1
		ORDER BY username ASC
	`, proxyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch auth users"})
		return
	}
	defer rows.Close()

	users := []AuthUser{}
	for rows.Next() {
		var u AuthUser
		if err := rows.Scan(&u.ID, &u.ProxyID, &u.Username, &u.CreatedAt, &u.UpdatedAt); err != nil {
			continue
		}
		users = append(users, u)
	}

	c.JSON(http.StatusOK, users)
}

// createAuthUser creates a new auth user for a proxy
func (h *Handler) createAuthUser(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	proxyIDStr := c.Param("pid")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	proxyID, err := uuid.Parse(proxyIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy ID"})
		return
	}

	var req CreateAuthUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate username (no colons allowed in htpasswd)
	if strings.Contains(req.Username, ":") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username cannot contain colons"})
		return
	}

	// Verify proxy belongs to agent and org
	var exists bool
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(
			SELECT 1 FROM proxy_hosts p
			JOIN agents a ON p.agent_id = a.id
			WHERE p.id = $1 AND p.agent_id = $2 AND a.org_id = $3
		)
	`, proxyID, agentID, orgID).Scan(&exists)

	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy host not found"})
		return
	}

	// Check if username already exists for this proxy
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(SELECT 1 FROM proxy_auth_users WHERE proxy_id = $1 AND username = $2)
	`, proxyID, req.Username).Scan(&exists)

	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "username already exists for this proxy"})
		return
	}

	// Generate bcrypt hash for htpasswd (cost 10 is standard for htpasswd)
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		h.logger.Error("Failed to hash password", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	// Insert auth user
	var authUserID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO proxy_auth_users (proxy_id, username, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id
	`, proxyID, req.Username, string(passwordHash)).Scan(&authUserID)

	if err != nil {
		h.logger.Error("Failed to create auth user", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	// Audit log
	h.auditLog(c, userID, orgID, "proxy.auth_user.create", "proxy_auth_user", authUserID, gin.H{"username": req.Username})

	// Dispatch updated htpasswd to agent (use background context since this runs in goroutine)
	// Add small delay to ensure INSERT is fully committed before querying
	go func() {
		time.Sleep(100 * time.Millisecond)
		h.dispatchHtpasswd(context.Background(), agentID, proxyID)
	}()

	// Fetch and return the created user
	var user AuthUser
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT id, proxy_id, username, created_at, updated_at
		FROM proxy_auth_users
		WHERE id = $1
	`, authUserID).Scan(&user.ID, &user.ProxyID, &user.Username, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch created user"})
		return
	}

	c.JSON(http.StatusCreated, user)
}

// deleteAuthUser deletes an auth user from a proxy
func (h *Handler) deleteAuthUser(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	proxyIDStr := c.Param("pid")
	authUserIDStr := c.Param("uid")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	proxyID, err := uuid.Parse(proxyIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid proxy ID"})
		return
	}

	authUserID, err := uuid.Parse(authUserIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid auth user ID"})
		return
	}

	// Verify proxy belongs to agent and org
	var exists bool
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT EXISTS(
			SELECT 1 FROM proxy_hosts p
			JOIN agents a ON p.agent_id = a.id
			WHERE p.id = $1 AND p.agent_id = $2 AND a.org_id = $3
		)
	`, proxyID, agentID, orgID).Scan(&exists)

	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "proxy host not found"})
		return
	}

	// Get username for audit log
	var username string
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT username FROM proxy_auth_users WHERE id = $1 AND proxy_id = $2
	`, authUserID, proxyID).Scan(&username)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth user not found"})
		return
	}

	// Delete auth user
	result, err := h.db.Exec(c.Request.Context(), `
		DELETE FROM proxy_auth_users WHERE id = $1 AND proxy_id = $2
	`, authUserID, proxyID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete auth user"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth user not found"})
		return
	}

	// Audit log
	h.auditLog(c, userID, orgID, "proxy.auth_user.delete", "proxy_auth_user", authUserID, gin.H{"username": username})

	// Dispatch updated htpasswd to agent (use background context since this runs in goroutine)
	// Add small delay to ensure DELETE is fully committed before querying
	go func() {
		time.Sleep(100 * time.Millisecond)
		h.dispatchHtpasswd(context.Background(), agentID, proxyID)
	}()

	c.JSON(http.StatusOK, gin.H{"message": "auth user deleted"})
}

// generateHtpasswd generates htpasswd file content for a proxy
func (h *Handler) generateHtpasswd(ctx context.Context, proxyID uuid.UUID) (string, error) {
	h.logger.Info("generateHtpasswd: querying users",
		zap.String("proxy_id", proxyID.String()),
	)

	rows, err := h.db.Query(ctx, `
		SELECT username, password_hash
		FROM proxy_auth_users
		WHERE proxy_id = $1
		ORDER BY username ASC
	`, proxyID)
	if err != nil {
		h.logger.Error("generateHtpasswd: query failed", zap.Error(err))
		return "", err
	}
	defer rows.Close()

	var lines []string
	for rows.Next() {
		var username, passwordHash string
		if err := rows.Scan(&username, &passwordHash); err != nil {
			h.logger.Error("generateHtpasswd: scan failed", zap.Error(err))
			continue
		}
		h.logger.Info("generateHtpasswd: found user", zap.String("username", username))
		lines = append(lines, fmt.Sprintf("%s:%s", username, passwordHash))
	}

	h.logger.Info("generateHtpasswd: result",
		zap.String("proxy_id", proxyID.String()),
		zap.Int("user_count", len(lines)),
	)

	return strings.Join(lines, "\n"), nil
}
