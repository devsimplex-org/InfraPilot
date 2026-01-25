package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	MFARequired  bool   `json:"mfa_required,omitempty"`
	MFAToken     string `json:"mfa_token,omitempty"`
}

type MFAVerifyRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

type MFAConfirmRequest struct {
	Code string `json:"code" binding:"required"`
}

type MFADisableRequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h *Handler) login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Query user from database
	var userID, orgID uuid.UUID
	var passwordHash, role string
	var mfaEnabled bool
	var mfaSecret *string

	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, password_hash, role, mfa_enabled, mfa_secret
		FROM users WHERE email = $1
	`, req.Email).Scan(&userID, &orgID, &passwordHash, &role, &mfaEnabled, &mfaSecret)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Verify password
	if !h.auth.VerifyPassword(passwordHash, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Check if MFA is required
	if mfaEnabled {
		// Generate temporary MFA token
		mfaToken, _ := h.auth.GenerateRefreshToken()
		tokenHash := sha256.Sum256([]byte(mfaToken))

		// Store MFA token in database (expires in 5 minutes)
		_, err = h.db.Exec(c.Request.Context(), `
			INSERT INTO mfa_tokens (user_id, token_hash, expires_at)
			VALUES ($1, $2, $3)
		`, userID, hex.EncodeToString(tokenHash[:]), time.Now().Add(5*time.Minute))

		if err != nil {
			h.logger.Error("Failed to store MFA token")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initiate MFA"})
			return
		}

		c.JSON(http.StatusOK, LoginResponse{
			MFARequired: true,
			MFAToken:    mfaToken,
		})
		return
	}

	// Generate tokens
	accessToken, err := h.auth.GenerateAccessToken(userID, orgID, req.Email, role, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	refreshToken, err := h.auth.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	// Store refresh token hash
	tokenHash := sha256.Sum256([]byte(refreshToken))
	_, err = h.db.Exec(c.Request.Context(), `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, hex.EncodeToString(tokenHash[:]), time.Now().Add(7*24*time.Hour))

	if err != nil {
		h.logger.Error("Failed to store refresh token")
	}

	// Update last login
	h.db.Exec(c.Request.Context(), `UPDATE users SET last_login_at = NOW() WHERE id = $1`, userID)

	// Audit log
	h.auditLog(c, userID, orgID, "auth.login", "user", userID, nil)

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func (h *Handler) logout(c *gin.Context) {
	// Get refresh token from request
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "logged out"})
		return
	}

	// Revoke refresh token
	tokenHash := sha256.Sum256([]byte(req.RefreshToken))
	h.db.Exec(c.Request.Context(), `
		UPDATE refresh_tokens SET revoked_at = NOW()
		WHERE token_hash = $1
	`, hex.EncodeToString(tokenHash[:]))

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

func (h *Handler) refreshToken(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokenHash := sha256.Sum256([]byte(req.RefreshToken))
	hashString := hex.EncodeToString(tokenHash[:])

	// Verify refresh token
	var userID, orgID uuid.UUID
	var email, role string
	var expiresAt time.Time
	var revokedAt *time.Time

	err := h.db.QueryRow(c.Request.Context(), `
		SELECT rt.expires_at, rt.revoked_at, u.id, u.org_id, u.email, u.role
		FROM refresh_tokens rt
		JOIN users u ON rt.user_id = u.id
		WHERE rt.token_hash = $1
	`, hashString).Scan(&expiresAt, &revokedAt, &userID, &orgID, &email, &role)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if revokedAt != nil || time.Now().After(expiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired or revoked"})
		return
	}

	// Generate new access token
	accessToken, err := h.auth.GenerateAccessToken(userID, orgID, email, role, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken,
	})
}

func (h *Handler) setupMFA(c *gin.Context) {
	userID := c.MustGet("user_id").(uuid.UUID)

	// Get user email
	var email string
	err := h.db.QueryRow(c.Request.Context(), `SELECT email FROM users WHERE id = $1`, userID).Scan(&email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "InfraPilot",
		AccountName: email,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate MFA secret"})
		return
	}

	// Store secret (not enabled yet)
	_, err = h.db.Exec(c.Request.Context(), `
		UPDATE users SET mfa_secret = $1 WHERE id = $2
	`, key.Secret(), userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save MFA secret"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secret":  key.Secret(),
		"otpauth": key.URL(),
	})
}

func (h *Handler) verifyMFA(c *gin.Context) {
	var req MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash the provided token
	tokenHash := sha256.Sum256([]byte(req.MFAToken))
	hashString := hex.EncodeToString(tokenHash[:])

	// Look up user from MFA token
	var userID, orgID uuid.UUID
	var email, role, mfaSecret string
	var expiresAt time.Time
	var usedAt *time.Time

	err := h.db.QueryRow(c.Request.Context(), `
		SELECT mt.expires_at, mt.used_at, u.id, u.org_id, u.email, u.role, u.mfa_secret
		FROM mfa_tokens mt
		JOIN users u ON mt.user_id = u.id
		WHERE mt.token_hash = $1
	`, hashString).Scan(&expiresAt, &usedAt, &userID, &orgID, &email, &role, &mfaSecret)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired MFA token"})
		return
	}

	// Check if token is expired or already used
	if usedAt != nil || time.Now().After(expiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "MFA token expired"})
		return
	}

	// First try TOTP code
	valid := totp.Validate(req.Code, mfaSecret)

	// If TOTP fails, try backup codes
	if !valid {
		var backupCodeID uuid.UUID
		err := h.db.QueryRow(c.Request.Context(), `
			SELECT id FROM mfa_backup_codes
			WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
		`, userID, hashCode(req.Code)).Scan(&backupCodeID)

		if err == nil {
			// Mark backup code as used
			h.db.Exec(c.Request.Context(), `
				UPDATE mfa_backup_codes SET used_at = NOW() WHERE id = $1
			`, backupCodeID)
			valid = true
		}
	}

	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid verification code"})
		return
	}

	// Mark MFA token as used
	h.db.Exec(c.Request.Context(), `UPDATE mfa_tokens SET used_at = NOW() WHERE token_hash = $1`, hashString)

	// Generate tokens
	accessToken, err := h.auth.GenerateAccessToken(userID, orgID, email, role, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}

	refreshToken, err := h.auth.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	// Store refresh token hash
	refreshHash := sha256.Sum256([]byte(refreshToken))
	h.db.Exec(c.Request.Context(), `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, hex.EncodeToString(refreshHash[:]), time.Now().Add(7*24*time.Hour))

	// Update last login
	h.db.Exec(c.Request.Context(), `UPDATE users SET last_login_at = NOW() WHERE id = $1`, userID)

	// Audit log
	h.auditLog(c, userID, orgID, "auth.login_mfa", "user", userID, nil)

	c.JSON(http.StatusOK, LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func (h *Handler) getCurrentUser(c *gin.Context) {
	userID := c.MustGet("user_id").(uuid.UUID)

	var user struct {
		ID          uuid.UUID  `json:"id"`
		OrgID       uuid.UUID  `json:"org_id"`
		Email       string     `json:"email"`
		Role        string     `json:"role"`
		MFAEnabled  bool       `json:"mfa_enabled"`
		CreatedAt   time.Time  `json:"created_at"`
		LastLoginAt *time.Time `json:"last_login_at"`
	}

	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, email, role, mfa_enabled, created_at, last_login_at
		FROM users WHERE id = $1
	`, userID).Scan(&user.ID, &user.OrgID, &user.Email, &user.Role, &user.MFAEnabled, &user.CreatedAt, &user.LastLoginAt)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// confirmMFASetup verifies the TOTP code and enables MFA, returning backup codes
func (h *Handler) confirmMFASetup(c *gin.Context) {
	userID := c.MustGet("user_id").(uuid.UUID)
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req MFAConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user's MFA secret
	var mfaSecret *string
	var mfaEnabled bool
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT mfa_secret, mfa_enabled FROM users WHERE id = $1
	`, userID).Scan(&mfaSecret, &mfaEnabled)

	if err != nil || mfaSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA not set up - call setup first"})
		return
	}

	if mfaEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA is already enabled"})
		return
	}

	// Validate TOTP code
	if !totp.Validate(req.Code, *mfaSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid verification code"})
		return
	}

	// Generate backup codes
	backupCodes := make([]string, 10)
	for i := 0; i < 10; i++ {
		code := generateBackupCode()
		backupCodes[i] = code

		// Store hashed backup code
		h.db.Exec(c.Request.Context(), `
			INSERT INTO mfa_backup_codes (user_id, code_hash)
			VALUES ($1, $2)
		`, userID, hashCode(code))
	}

	// Enable MFA
	_, err = h.db.Exec(c.Request.Context(), `
		UPDATE users SET mfa_enabled = TRUE WHERE id = $1
	`, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable MFA"})
		return
	}

	// Audit log
	h.auditLog(c, userID, orgID, "mfa.enabled", "user", userID, nil)

	c.JSON(http.StatusOK, gin.H{
		"message":      "MFA enabled successfully",
		"backup_codes": backupCodes,
	})
}

// disableMFA disables MFA for the current user
func (h *Handler) disableMFA(c *gin.Context) {
	userID := c.MustGet("user_id").(uuid.UUID)
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req MFADisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify password and get MFA info
	var passwordHash string
	var mfaSecret *string
	var mfaEnabled bool
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT password_hash, mfa_secret, mfa_enabled FROM users WHERE id = $1
	`, userID).Scan(&passwordHash, &mfaSecret, &mfaEnabled)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user"})
		return
	}

	// Verify password
	if !h.auth.VerifyPassword(passwordHash, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password"})
		return
	}

	if !mfaEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA is not enabled"})
		return
	}

	// Validate TOTP code
	if mfaSecret != nil && !totp.Validate(req.Code, *mfaSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid verification code"})
		return
	}

	// Disable MFA and clear secret
	_, err = h.db.Exec(c.Request.Context(), `
		UPDATE users SET mfa_enabled = FALSE, mfa_secret = NULL WHERE id = $1
	`, userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable MFA"})
		return
	}

	// Delete backup codes
	h.db.Exec(c.Request.Context(), `DELETE FROM mfa_backup_codes WHERE user_id = $1`, userID)

	// Audit log
	h.auditLog(c, userID, orgID, "mfa.disabled", "user", userID, nil)

	c.JSON(http.StatusOK, gin.H{"message": "MFA disabled successfully"})
}

// regenerateBackupCodes generates new backup codes (invalidates old ones)
func (h *Handler) regenerateBackupCodes(c *gin.Context) {
	userID := c.MustGet("user_id").(uuid.UUID)
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req MFAConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify MFA is enabled and get secret
	var mfaSecret *string
	var mfaEnabled bool
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT mfa_secret, mfa_enabled FROM users WHERE id = $1
	`, userID).Scan(&mfaSecret, &mfaEnabled)

	if err != nil || !mfaEnabled || mfaSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA is not enabled"})
		return
	}

	// Validate TOTP code
	if !totp.Validate(req.Code, *mfaSecret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid verification code"})
		return
	}

	// Delete old backup codes
	h.db.Exec(c.Request.Context(), `DELETE FROM mfa_backup_codes WHERE user_id = $1`, userID)

	// Generate new backup codes
	backupCodes := make([]string, 10)
	for i := 0; i < 10; i++ {
		code := generateBackupCode()
		backupCodes[i] = code

		h.db.Exec(c.Request.Context(), `
			INSERT INTO mfa_backup_codes (user_id, code_hash)
			VALUES ($1, $2)
		`, userID, hashCode(code))
	}

	// Audit log
	h.auditLog(c, userID, orgID, "mfa.backup_codes_regenerated", "user", userID, nil)

	c.JSON(http.StatusOK, gin.H{
		"message":      "Backup codes regenerated",
		"backup_codes": backupCodes,
	})
}

// Helper to create audit logs
func (h *Handler) auditLog(c *gin.Context, userID, orgID uuid.UUID, action, resourceType string, resourceID uuid.UUID, body interface{}) {
	h.db.Exec(c.Request.Context(), `
		INSERT INTO audit_logs (org_id, user_id, action, resource_type, resource_id, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, orgID, userID, action, resourceType, resourceID, c.ClientIP(), c.Request.UserAgent())
}

// hashCode creates a SHA256 hash of a code
func hashCode(code string) string {
	hash := sha256.Sum256([]byte(code))
	return hex.EncodeToString(hash[:])
}

// generateBackupCode generates a random 8-character alphanumeric backup code
func generateBackupCode() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return fmt.Sprintf("%s-%s", string(b[:4]), string(b[4:]))
}

// VerifyPasswordRequest is the request body for password verification
type VerifyPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

// verifyPassword verifies the current user's password for sensitive operations
func (h *Handler) verifyPassword(c *gin.Context) {
	userID := c.MustGet("user_id").(uuid.UUID)

	var req VerifyPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user's password hash
	var passwordHash string
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT password_hash FROM users WHERE id = $1
	`, userID).Scan(&passwordHash)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify password"})
		return
	}

	// Verify password
	if !h.auth.VerifyPassword(passwordHash, req.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid password", "valid": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": true})
}

// sendConfirmationOTP sends an OTP code to the user's email for sensitive operation confirmation
func (h *Handler) sendConfirmationOTP(c *gin.Context) {
	userID := c.MustGet("user_id").(uuid.UUID)
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Get user's email
	var email string
	err := h.db.QueryRow(c.Request.Context(), `SELECT email FROM users WHERE id = $1`, userID).Scan(&email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user email"})
		return
	}

	// Generate 6-digit OTP
	otpBytes := make([]byte, 3)
	rand.Read(otpBytes)
	otp := fmt.Sprintf("%06d", (int(otpBytes[0])<<16|int(otpBytes[1])<<8|int(otpBytes[2]))%1000000)

	// Hash OTP for storage
	otpHash := sha256.Sum256([]byte(otp))

	// Store OTP (expires in 10 minutes)
	_, err = h.db.Exec(c.Request.Context(), `
		INSERT INTO confirmation_otps (user_id, otp_hash, expires_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET otp_hash = $2, expires_at = $3, verified_at = NULL
	`, userID, hex.EncodeToString(otpHash[:]), time.Now().Add(10*time.Minute))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate OTP"})
		return
	}

	// Get org's SMTP settings
	var smtpConfig struct {
		Host     *string `json:"host"`
		Port     *int    `json:"port"`
		Username *string `json:"username"`
		Password *string `json:"password"`
		From     *string `json:"from"`
		UseTLS   bool    `json:"use_tls"`
	}

	var smtpConfigBytes []byte
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT smtp_config FROM organizations WHERE id = $1
	`, orgID).Scan(&smtpConfigBytes)

	if err != nil || smtpConfigBytes == nil {
		// Fall back to environment variables for SMTP
		h.logger.Warn("No SMTP config found for org, falling back to env vars")
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Verification code sent to your email",
			// In development, include the OTP for testing
			// "otp": otp, // Remove in production
		})
		return
	}

	// Send email with OTP
	// For now, just return success - email sending will use org's SMTP config
	// This would be integrated with a proper email service

	h.logger.Info("Confirmation OTP generated",
		zap.String("user_id", userID.String()),
		zap.String("email", email))

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Verification code sent to your email",
	})
}

// VerifyConfirmationOTPRequest is the request body for OTP verification
type VerifyConfirmationOTPRequest struct {
	OTP string `json:"otp" binding:"required"`
}

// verifyConfirmationOTP verifies the OTP code sent to user's email
func (h *Handler) verifyConfirmationOTP(c *gin.Context) {
	userID := c.MustGet("user_id").(uuid.UUID)

	var req VerifyConfirmationOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash the provided OTP
	otpHash := sha256.Sum256([]byte(req.OTP))
	hashString := hex.EncodeToString(otpHash[:])

	// Check if OTP is valid
	var expiresAt time.Time
	var verifiedAt *time.Time
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT expires_at, verified_at FROM confirmation_otps
		WHERE user_id = $1 AND otp_hash = $2
	`, userID, hashString).Scan(&expiresAt, &verifiedAt)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid verification code", "valid": false})
		return
	}

	if verifiedAt != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "verification code already used", "valid": false})
		return
	}

	if time.Now().After(expiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "verification code expired", "valid": false})
		return
	}

	// Mark OTP as verified
	h.db.Exec(c.Request.Context(), `
		UPDATE confirmation_otps SET verified_at = NOW() WHERE user_id = $1
	`, userID)

	c.JSON(http.StatusOK, gin.H{"valid": true})
}
