package api

import (
	"encoding/json"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/infrapilot/backend/internal/license"
)

// SetupStatusResponse represents the setup status
type SetupStatusResponse struct {
	SetupRequired     bool `json:"setup_required"`
	LicenseConfigured bool `json:"license_configured"`
	AdminCreated      bool `json:"admin_created"`
	UserCount         int  `json:"user_count"`
}

// SetupRequest represents the initial admin setup request
type SetupRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// SetupLicenseRequest represents the license key submission during setup
type SetupLicenseRequest struct {
	Key string `json:"key" binding:"required"`
}

// getSetupStatus checks if initial setup is required (no users exist)
func (h *Handler) getSetupStatus(c *gin.Context) {
	var count int
	err := h.db.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		h.logger.Error("Failed to count users")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check setup status"})
		return
	}

	// Check if license is already configured (env var, offline mode, or saved in DB)
	licenseConfigured := false
	if h.cfg.LicenseKey != "" || os.Getenv("LICENSE_OFFLINE") == "true" {
		licenseConfigured = true
	} else {
		var savedKey string
		_ = h.db.QueryRow(c.Request.Context(), `
			SELECT setting_value->>'key' FROM system_settings
			WHERE org_id = '00000000-0000-0000-0000-000000000001'
			AND setting_key = 'license_key'
		`).Scan(&savedKey)
		if savedKey != "" {
			licenseConfigured = true
		}
	}

	c.JSON(http.StatusOK, SetupStatusResponse{
		SetupRequired:     count == 0,
		LicenseConfigured: licenseConfigured,
		AdminCreated:      count > 0,
		UserCount:         count,
	})
}

// setupLicense validates and stores a license key during setup
func (h *Handler) setupLicense(c *gin.Context) {
	// Guard: if users exist, setup already completed
	var count int
	err := h.db.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		h.logger.Error("Failed to count users")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check setup status"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "setup already completed"})
		return
	}

	var req SetupLicenseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate the license key against infrapilot.sh
	client, err := license.NewClient(req.Key, h.cfg.DataDir, h.version, h.logger)
	if err != nil {
		h.logger.Error("Failed to initialize license client", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initialize license validation"})
		return
	}
	resp, err := client.Validate()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "license validation failed: " + err.Error()})
		return
	}
	if !resp.Valid {
		errMsg := "invalid license key"
		if resp.Error != "" {
			errMsg = resp.Error
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
		return
	}

	// Ensure default org exists first (same pattern as createInitialAdmin)
	orgID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	_, err = h.db.Exec(c.Request.Context(), `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'Default Organization', 'default')
		ON CONFLICT (id) DO NOTHING
	`, orgID)
	if err != nil {
		h.logger.Error("Failed to create organization", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create organization"})
		return
	}

	// Upsert license key into system_settings
	settingValue, err := json.Marshal(map[string]interface{}{
		"key":        req.Key,
		"tier":       resp.Tier,
		"max_agents": resp.MaxAgents,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encode license data"})
		return
	}
	_, err = h.db.Exec(c.Request.Context(), `
		INSERT INTO system_settings (org_id, setting_key, setting_value)
		VALUES ($1, 'license_key', $2)
		ON CONFLICT (org_id, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value
	`, orgID, string(settingValue))
	if err != nil {
		h.logger.Error("Failed to save license key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save license key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":      true,
		"tier":       resp.Tier,
		"max_agents": resp.MaxAgents,
		"features":   resp.Features,
	})
}

// createInitialAdmin creates the first admin user during setup
func (h *Handler) createInitialAdmin(c *gin.Context) {
	// First check if any users exist
	var count int
	err := h.db.QueryRow(c.Request.Context(), `SELECT COUNT(*) FROM users`).Scan(&count)
	if err != nil {
		h.logger.Error("Failed to count users")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check setup status"})
		return
	}

	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "setup already completed"})
		return
	}

	var req SetupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate password strength
	if len(req.Password) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password must be at least 8 characters"})
		return
	}

	// Hash password
	passwordHash, err := h.auth.HashPassword(req.Password)
	if err != nil {
		h.logger.Error("Failed to hash password")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create account"})
		return
	}

	// Ensure default organization exists
	orgID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	_, err = h.db.Exec(c.Request.Context(), `
		INSERT INTO organizations (id, name, slug)
		VALUES ($1, 'Default Organization', 'default')
		ON CONFLICT (id) DO NOTHING
	`, orgID)
	if err != nil {
		h.logger.Error("Failed to create organization")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create organization"})
		return
	}

	// Create admin user
	userID := uuid.New()
	_, err = h.db.Exec(c.Request.Context(), `
		INSERT INTO users (id, org_id, email, password_hash, role, mfa_enabled)
		VALUES ($1, $2, $3, $4, 'super_admin', false)
	`, userID, orgID, req.Email, passwordHash)

	if err != nil {
		h.logger.Error("Failed to create admin user")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create account"})
		return
	}

	// Audit log for setup
	h.db.Exec(c.Request.Context(), `
		INSERT INTO audit_logs (org_id, user_id, action, resource_type, resource_id, ip_address, user_agent)
		VALUES ($1, $2, 'setup.initial_admin_created', 'user', $2, $3, $4)
	`, orgID, userID, c.ClientIP(), c.Request.UserAgent())

	// Generate tokens for immediate login
	accessToken, err := h.auth.GenerateAccessToken(userID, orgID, req.Email, "super_admin", false)
	if err != nil {
		// User created but tokens failed - they can still login
		c.JSON(http.StatusOK, gin.H{
			"message": "Admin account created successfully. Please login.",
			"user_id": userID,
		})
		return
	}

	refreshToken, _ := h.auth.GenerateRefreshToken()

	c.JSON(http.StatusCreated, gin.H{
		"message":       "Admin account created successfully",
		"user_id":       userID,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}
