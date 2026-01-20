package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/infrapilot/backend/internal/auth"
)

// ==================== SSO Configuration Management ====================

// listSSOConfigs lists all SSO configurations for the organization
func (h *Handler) listSSOConfigs(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	ssoService := auth.NewSSOService(h.db, h.encryptionSvc, h.logger)
	configs, err := ssoService.ListSSOConfigs(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Convert to response format (exclude secrets)
	var response []map[string]interface{}
	for _, config := range configs {
		response = append(response, map[string]interface{}{
			"id":               config.ID,
			"provider":         config.Provider,
			"name":             config.Name,
			"enabled":          config.Enabled,
			"issuer_url":       config.IssuerURL,
			"client_id":        config.ClientID,
			"redirect_uri":     config.RedirectURI,
			"scopes":           config.Scopes,
			"jit_provisioning": config.JITProvisioning,
			"default_role":     config.DefaultRole,
			"allowed_domains":  config.AllowedDomains,
			"created_at":       config.CreatedAt,
			"updated_at":       config.UpdatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"sso_configurations": response})
}

// createSSOConfig creates a new SSO configuration
func (h *Handler) createSSOConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req auth.CreateSSOConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ssoService := auth.NewSSOService(h.db, h.encryptionSvc, h.logger)
	config, err := ssoService.CreateSSOConfig(c.Request.Context(), orgID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":       config.ID,
		"name":     config.Name,
		"provider": config.Provider,
		"message":  "SSO configuration created successfully",
	})
}

// getSSOConfig gets a specific SSO configuration
func (h *Handler) getSSOConfig(c *gin.Context) {
	configIDStr := c.Param("id")
	configID, err := uuid.Parse(configIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid configuration ID"})
		return
	}

	ssoService := auth.NewSSOService(h.db, h.encryptionSvc, h.logger)
	config, err := ssoService.GetSSOConfig(c.Request.Context(), configID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Verify org access
	orgID := c.MustGet("org_id").(uuid.UUID)
	if config.OrgID != orgID {
		c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"id":               config.ID,
		"provider":         config.Provider,
		"name":             config.Name,
		"enabled":          config.Enabled,
		"issuer_url":       config.IssuerURL,
		"client_id":        config.ClientID,
		"redirect_uri":     config.RedirectURI,
		"scopes":           config.Scopes,
		"email_claim":      config.EmailClaim,
		"name_claim":       config.NameClaim,
		"groups_claim":     config.GroupsClaim,
		"role_mappings":    config.RoleMappings,
		"jit_provisioning": config.JITProvisioning,
		"default_role":     config.DefaultRole,
		"allowed_domains":  config.AllowedDomains,
		"created_at":       config.CreatedAt,
		"updated_at":       config.UpdatedAt,
	})
}

// deleteSSOConfig deletes an SSO configuration
func (h *Handler) deleteSSOConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	configIDStr := c.Param("id")
	configID, err := uuid.Parse(configIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid configuration ID"})
		return
	}

	ssoService := auth.NewSSOService(h.db, h.encryptionSvc, h.logger)
	if err := ssoService.DeleteSSOConfig(c.Request.Context(), orgID, configID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "SSO configuration deleted"})
}

// ==================== SSO Authentication Flow ====================

// ssoLogin initiates the SSO login flow
func (h *Handler) ssoLogin(c *gin.Context) {
	configIDStr := c.Param("config_id")
	configID, err := uuid.Parse(configIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid configuration ID"})
		return
	}

	// Optional redirect_after parameter
	redirectAfter := c.Query("redirect_after")
	if redirectAfter == "" {
		redirectAfter = "/"
	}

	ssoService := auth.NewSSOService(h.db, h.encryptionSvc, h.logger)
	authURL, err := ssoService.GetOIDCAuthURL(c.Request.Context(), configID, redirectAfter)
	if err != nil {
		h.logger.Error("Failed to generate SSO auth URL",
			zap.Error(err),
			zap.String("config_id", configIDStr),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Redirect to the IdP
	c.Redirect(http.StatusFound, authURL)
}

// ssoCallback handles the SSO callback from the IdP
func (h *Handler) ssoCallback(c *gin.Context) {
	configIDStr := c.Param("config_id")
	_, err := uuid.Parse(configIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid configuration ID"})
		return
	}

	// Get code and state from query params
	code := c.Query("code")
	state := c.Query("state")

	if code == "" || state == "" {
		// Check for error response from IdP
		idpError := c.Query("error")
		idpErrorDesc := c.Query("error_description")
		if idpError != "" {
			h.logger.Warn("SSO error from IdP",
				zap.String("error", idpError),
				zap.String("description", idpErrorDesc),
			)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":       idpError,
				"description": idpErrorDesc,
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing code or state parameter"})
		return
	}

	ssoService := auth.NewSSOService(h.db, h.encryptionSvc, h.logger)
	userInfo, ssoConfig, err := ssoService.HandleOIDCCallback(c.Request.Context(), code, state)
	if err != nil {
		h.logger.Error("SSO callback failed",
			zap.Error(err),
			zap.String("config_id", configIDStr),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Check allowed domains if configured
	if len(ssoConfig.AllowedDomains) > 0 {
		emailParts := strings.Split(userInfo.Email, "@")
		if len(emailParts) != 2 {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid email format"})
			return
		}
		domain := emailParts[1]
		allowed := false
		for _, allowedDomain := range ssoConfig.AllowedDomains {
			if domain == allowedDomain {
				allowed = true
				break
			}
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "email domain not allowed"})
			return
		}
	}

	// Look up or create user
	ctx := c.Request.Context()
	var userID uuid.UUID
	var userRole string

	err = h.db.QueryRow(ctx, `
		SELECT id, role FROM users WHERE email = $1 AND org_id = $2
	`, userInfo.Email, ssoConfig.OrgID).Scan(&userID, &userRole)

	if err != nil {
		// User doesn't exist
		if !ssoConfig.JITProvisioning {
			c.JSON(http.StatusForbidden, gin.H{"error": "user not found and JIT provisioning is disabled"})
			return
		}

		// Create user (JIT provisioning)
		userRole = ssoService.MapUserRole(ssoConfig, userInfo.Groups)
		userID = uuid.New()

		_, err = h.db.Exec(ctx, `
			INSERT INTO users (id, org_id, email, name, role, sso_provider, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		`, userID, ssoConfig.OrgID, userInfo.Email, userInfo.Name, userRole, ssoConfig.Provider)

		if err != nil {
			h.logger.Error("Failed to create SSO user",
				zap.Error(err),
				zap.String("email", userInfo.Email),
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
			return
		}

		h.logger.Info("Created SSO user via JIT provisioning",
			zap.String("user_id", userID.String()),
			zap.String("email", userInfo.Email),
			zap.String("role", userRole),
		)
	}

	// Generate JWT tokens
	accessToken, err := h.auth.GenerateAccessToken(userID, ssoConfig.OrgID, userInfo.Email, userRole, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	refreshToken, err := h.auth.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	// Store refresh token
	_, err = h.db.Exec(ctx, `
		INSERT INTO refresh_tokens (id, user_id, token, expires_at)
		VALUES ($1, $2, $3, NOW() + INTERVAL '7 days')
	`, uuid.New(), userID, refreshToken)
	if err != nil {
		h.logger.Warn("Failed to store refresh token", zap.Error(err))
	}

	// Log the login
	h.logAuditEvent(c, "sso_login", "user", &userID, map[string]interface{}{
		"provider": ssoConfig.Provider,
		"email":    userInfo.Email,
	})

	// Return tokens (or redirect with tokens)
	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"user": gin.H{
			"id":    userID,
			"email": userInfo.Email,
			"name":  userInfo.Name,
			"role":  userRole,
		},
	})
}

// getAvailableSSOProviders returns enabled SSO providers for login page
func (h *Handler) getAvailableSSOProviders(c *gin.Context) {
	// This endpoint is public and returns minimal info for the login page
	orgIDStr := c.Query("org_id")
	if orgIDStr == "" {
		// Return empty list if no org specified
		c.JSON(http.StatusOK, gin.H{"providers": []interface{}{}})
		return
	}

	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization ID"})
		return
	}

	ssoService := auth.NewSSOService(h.db, h.encryptionSvc, h.logger)
	configs, err := ssoService.ListSSOConfigs(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"providers": []interface{}{}})
		return
	}

	var providers []map[string]interface{}
	for _, config := range configs {
		if config.Enabled {
			providers = append(providers, map[string]interface{}{
				"id":       config.ID,
				"name":     config.Name,
				"provider": config.Provider,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{"providers": providers})
}
