package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"golang.org/x/oauth2"

	"github.com/infrapilot/backend/internal/crypto"
)

// SSOProvider represents supported SSO provider types
type SSOProvider string

const (
	SSOProviderOIDC    SSOProvider = "oidc"
	SSOProviderOkta    SSOProvider = "okta"
	SSOProviderAzureAD SSOProvider = "azure_ad"
	SSOProviderGoogle  SSOProvider = "google"
)

// SSOConfig represents an SSO configuration
type SSOConfig struct {
	ID                    uuid.UUID         `json:"id"`
	OrgID                 uuid.UUID         `json:"org_id"`
	Provider              SSOProvider       `json:"provider"`
	Name                  string            `json:"name"`
	Enabled               bool              `json:"enabled"`
	IssuerURL             string            `json:"issuer_url"`
	ClientID              string            `json:"client_id"`
	ClientSecretEncrypted []byte            `json:"-"`
	RedirectURI           string            `json:"redirect_uri"`
	Scopes                []string          `json:"scopes"`
	EmailClaim            string            `json:"email_claim"`
	NameClaim             string            `json:"name_claim"`
	GroupsClaim           string            `json:"groups_claim"`
	RoleMappings          map[string]string `json:"role_mappings"`
	JITProvisioning       bool              `json:"jit_provisioning"`
	DefaultRole           string            `json:"default_role"`
	AllowedDomains        []string          `json:"allowed_domains,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// SSOSession represents a pending SSO authentication session
type SSOSession struct {
	ID            uuid.UUID `json:"id"`
	SSOConfigID   uuid.UUID `json:"sso_config_id"`
	State         string    `json:"state"`
	Nonce         string    `json:"nonce"`
	RedirectAfter string    `json:"redirect_after,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// SSOUserInfo represents user information from OIDC claims
type SSOUserInfo struct {
	Email  string   `json:"email"`
	Name   string   `json:"name"`
	Groups []string `json:"groups,omitempty"`
}

// CreateSSOConfigRequest represents a request to create an SSO config
type CreateSSOConfigRequest struct {
	Provider        SSOProvider       `json:"provider" binding:"required,oneof=oidc okta azure_ad google"`
	Name            string            `json:"name" binding:"required,min=1,max=100"`
	IssuerURL       string            `json:"issuer_url" binding:"required,url"`
	ClientID        string            `json:"client_id" binding:"required"`
	ClientSecret    string            `json:"client_secret" binding:"required"`
	RedirectURI     string            `json:"redirect_uri" binding:"required,url"`
	Scopes          []string          `json:"scopes,omitempty"`
	EmailClaim      string            `json:"email_claim,omitempty"`
	NameClaim       string            `json:"name_claim,omitempty"`
	GroupsClaim     string            `json:"groups_claim,omitempty"`
	RoleMappings    map[string]string `json:"role_mappings,omitempty"`
	JITProvisioning bool              `json:"jit_provisioning,omitempty"`
	DefaultRole     string            `json:"default_role,omitempty"`
	AllowedDomains  []string          `json:"allowed_domains,omitempty"`
}

// SSOService manages SSO/OIDC operations
type SSOService struct {
	db            *pgxpool.Pool
	encryptionSvc *crypto.EncryptionService
	logger        *zap.Logger
}

// NewSSOService creates a new SSO service
func NewSSOService(db *pgxpool.Pool, encryptionSvc *crypto.EncryptionService, logger *zap.Logger) *SSOService {
	return &SSOService{
		db:            db,
		encryptionSvc: encryptionSvc,
		logger:        logger,
	}
}

// CreateSSOConfig creates a new SSO configuration
func (s *SSOService) CreateSSOConfig(ctx context.Context, orgID uuid.UUID, req *CreateSSOConfigRequest) (*SSOConfig, error) {
	// Encrypt the client secret
	if s.encryptionSvc == nil {
		return nil, fmt.Errorf("encryption service not configured")
	}

	encryptedSecret, err := s.encryptionSvc.Encrypt([]byte(req.ClientSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt client secret: %w", err)
	}

	// Set defaults
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	emailClaim := req.EmailClaim
	if emailClaim == "" {
		emailClaim = "email"
	}

	nameClaim := req.NameClaim
	if nameClaim == "" {
		nameClaim = "name"
	}

	groupsClaim := req.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	defaultRole := req.DefaultRole
	if defaultRole == "" {
		defaultRole = "viewer"
	}

	roleMappingsJSON, err := json.Marshal(req.RoleMappings)
	if err != nil {
		roleMappingsJSON = []byte("{}")
	}

	config := &SSOConfig{
		ID:                    uuid.New(),
		OrgID:                 orgID,
		Provider:              req.Provider,
		Name:                  req.Name,
		Enabled:               true,
		IssuerURL:             req.IssuerURL,
		ClientID:              req.ClientID,
		ClientSecretEncrypted: encryptedSecret,
		RedirectURI:           req.RedirectURI,
		Scopes:                scopes,
		EmailClaim:            emailClaim,
		NameClaim:             nameClaim,
		GroupsClaim:           groupsClaim,
		RoleMappings:          req.RoleMappings,
		JITProvisioning:       req.JITProvisioning,
		DefaultRole:           defaultRole,
		AllowedDomains:        req.AllowedDomains,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
	}

	query := `
		INSERT INTO sso_configurations (
			id, org_id, provider, name, enabled,
			issuer_url, client_id, client_secret_encrypted, redirect_uri, scopes,
			email_claim, name_claim, groups_claim, role_mappings,
			jit_provisioning, default_role, allowed_domains,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
	`

	_, err = s.db.Exec(ctx, query,
		config.ID, config.OrgID, config.Provider, config.Name, config.Enabled,
		config.IssuerURL, config.ClientID, config.ClientSecretEncrypted, config.RedirectURI, config.Scopes,
		config.EmailClaim, config.NameClaim, config.GroupsClaim, roleMappingsJSON,
		config.JITProvisioning, config.DefaultRole, config.AllowedDomains,
		config.CreatedAt, config.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSO config: %w", err)
	}

	s.logger.Info("created SSO configuration",
		zap.String("config_id", config.ID.String()),
		zap.String("provider", string(config.Provider)),
		zap.String("name", config.Name),
	)

	return config, nil
}

// GetSSOConfig retrieves an SSO configuration by ID
func (s *SSOService) GetSSOConfig(ctx context.Context, configID uuid.UUID) (*SSOConfig, error) {
	query := `
		SELECT id, org_id, provider, name, enabled,
			issuer_url, client_id, client_secret_encrypted, redirect_uri, scopes,
			email_claim, name_claim, groups_claim, role_mappings,
			jit_provisioning, default_role, allowed_domains,
			created_at, updated_at
		FROM sso_configurations
		WHERE id = $1
	`

	var config SSOConfig
	var roleMappingsJSON []byte

	err := s.db.QueryRow(ctx, query, configID).Scan(
		&config.ID, &config.OrgID, &config.Provider, &config.Name, &config.Enabled,
		&config.IssuerURL, &config.ClientID, &config.ClientSecretEncrypted, &config.RedirectURI, &config.Scopes,
		&config.EmailClaim, &config.NameClaim, &config.GroupsClaim, &roleMappingsJSON,
		&config.JITProvisioning, &config.DefaultRole, &config.AllowedDomains,
		&config.CreatedAt, &config.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("SSO configuration not found")
		}
		return nil, fmt.Errorf("failed to get SSO config: %w", err)
	}

	if len(roleMappingsJSON) > 0 {
		json.Unmarshal(roleMappingsJSON, &config.RoleMappings)
	}

	return &config, nil
}

// ListSSOConfigs lists all SSO configurations for an organization
func (s *SSOService) ListSSOConfigs(ctx context.Context, orgID uuid.UUID) ([]*SSOConfig, error) {
	query := `
		SELECT id, org_id, provider, name, enabled,
			issuer_url, client_id, redirect_uri, scopes,
			email_claim, name_claim, groups_claim, role_mappings,
			jit_provisioning, default_role, allowed_domains,
			created_at, updated_at
		FROM sso_configurations
		WHERE org_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Query(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list SSO configs: %w", err)
	}
	defer rows.Close()

	var configs []*SSOConfig
	for rows.Next() {
		var config SSOConfig
		var roleMappingsJSON []byte

		err := rows.Scan(
			&config.ID, &config.OrgID, &config.Provider, &config.Name, &config.Enabled,
			&config.IssuerURL, &config.ClientID, &config.RedirectURI, &config.Scopes,
			&config.EmailClaim, &config.NameClaim, &config.GroupsClaim, &roleMappingsJSON,
			&config.JITProvisioning, &config.DefaultRole, &config.AllowedDomains,
			&config.CreatedAt, &config.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan SSO config: %w", err)
		}

		if len(roleMappingsJSON) > 0 {
			json.Unmarshal(roleMappingsJSON, &config.RoleMappings)
		}

		configs = append(configs, &config)
	}

	return configs, nil
}

// DeleteSSOConfig deletes an SSO configuration
func (s *SSOService) DeleteSSOConfig(ctx context.Context, orgID, configID uuid.UUID) error {
	query := `DELETE FROM sso_configurations WHERE id = $1 AND org_id = $2`

	result, err := s.db.Exec(ctx, query, configID, orgID)
	if err != nil {
		return fmt.Errorf("failed to delete SSO config: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("SSO configuration not found")
	}

	s.logger.Info("deleted SSO configuration", zap.String("config_id", configID.String()))
	return nil
}

// GetOIDCAuthURL generates the OIDC authorization URL
func (s *SSOService) GetOIDCAuthURL(ctx context.Context, configID uuid.UUID, redirectAfter string) (string, error) {
	config, err := s.GetSSOConfig(ctx, configID)
	if err != nil {
		return "", err
	}

	if !config.Enabled {
		return "", fmt.Errorf("SSO configuration is disabled")
	}

	// Create OIDC provider
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return "", fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Decrypt client secret
	clientSecret, err := s.decryptClientSecret(config.ClientSecretEncrypted)
	if err != nil {
		return "", err
	}

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  config.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.Scopes,
	}

	// Generate state and nonce
	state, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	nonce, err := generateRandomString(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Store session
	session := &SSOSession{
		ID:            uuid.New(),
		SSOConfigID:   configID,
		State:         state,
		Nonce:         nonce,
		RedirectAfter: redirectAfter,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}

	sessionQuery := `
		INSERT INTO sso_sessions (id, sso_config_id, state, nonce, redirect_after, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err = s.db.Exec(ctx, sessionQuery,
		session.ID, session.SSOConfigID, session.State, session.Nonce, session.RedirectAfter,
		session.CreatedAt, session.ExpiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create SSO session: %w", err)
	}

	// Generate auth URL
	authURL := oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce))

	return authURL, nil
}

// HandleOIDCCallback handles the OIDC callback and returns user info
func (s *SSOService) HandleOIDCCallback(ctx context.Context, code, state string) (*SSOUserInfo, *SSOConfig, error) {
	// Find session by state
	sessionQuery := `
		SELECT id, sso_config_id, nonce, redirect_after, expires_at
		FROM sso_sessions
		WHERE state = $1
	`

	var session SSOSession
	err := s.db.QueryRow(ctx, sessionQuery, state).Scan(
		&session.ID, &session.SSOConfigID, &session.Nonce, &session.RedirectAfter, &session.ExpiresAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil, fmt.Errorf("invalid or expired SSO session")
		}
		return nil, nil, fmt.Errorf("failed to find SSO session: %w", err)
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		return nil, nil, fmt.Errorf("SSO session expired")
	}

	// Delete session (one-time use)
	s.db.Exec(ctx, "DELETE FROM sso_sessions WHERE id = $1", session.ID)

	// Get SSO config
	config, err := s.GetSSOConfig(ctx, session.SSOConfigID)
	if err != nil {
		return nil, nil, err
	}

	// Create OIDC provider
	provider, err := oidc.NewProvider(ctx, config.IssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	// Decrypt client secret
	clientSecret, err := s.decryptClientSecret(config.ClientSecretEncrypted)
	if err != nil {
		return nil, nil, err
	}

	// Create OAuth2 config
	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: clientSecret,
		RedirectURL:  config.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.Scopes,
	}

	// Exchange code for token
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Verify ID token
	verifier := provider.Verifier(&oidc.Config{ClientID: config.ClientID})
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, nil, fmt.Errorf("no id_token in response")
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Verify nonce
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	if nonce, ok := claims["nonce"].(string); !ok || nonce != session.Nonce {
		return nil, nil, fmt.Errorf("invalid nonce")
	}

	// Extract user info
	userInfo := &SSOUserInfo{}

	if email, ok := claims[config.EmailClaim].(string); ok {
		userInfo.Email = email
	}
	if name, ok := claims[config.NameClaim].(string); ok {
		userInfo.Name = name
	}
	if groups, ok := claims[config.GroupsClaim].([]interface{}); ok {
		for _, g := range groups {
			if gStr, ok := g.(string); ok {
				userInfo.Groups = append(userInfo.Groups, gStr)
			}
		}
	}

	if userInfo.Email == "" {
		return nil, nil, fmt.Errorf("email claim not found in token")
	}

	s.logger.Info("SSO authentication successful",
		zap.String("email", userInfo.Email),
		zap.String("provider", string(config.Provider)),
	)

	return userInfo, config, nil
}

// MapUserRole determines the user role based on SSO groups and role mappings
func (s *SSOService) MapUserRole(config *SSOConfig, groups []string) string {
	if config.RoleMappings == nil || len(config.RoleMappings) == 0 {
		return config.DefaultRole
	}

	// Check if any group matches a role mapping
	for _, group := range groups {
		if role, ok := config.RoleMappings[group]; ok {
			return role
		}
	}

	return config.DefaultRole
}

// decryptClientSecret decrypts the client secret
func (s *SSOService) decryptClientSecret(encrypted []byte) (string, error) {
	if s.encryptionSvc == nil {
		return "", fmt.Errorf("encryption service not configured")
	}

	decrypted, err := s.encryptionSvc.Decrypt(encrypted)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt client secret: %w", err)
	}

	return string(decrypted), nil
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b)[:length], nil
}

// CleanupExpiredSessions removes expired SSO sessions
func (s *SSOService) CleanupExpiredSessions(ctx context.Context) (int64, error) {
	result, err := s.db.Exec(ctx, "DELETE FROM sso_sessions WHERE expires_at < NOW()")
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}
	return result.RowsAffected(), nil
}
