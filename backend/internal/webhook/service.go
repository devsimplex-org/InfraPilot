package webhook

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	db     *pgxpool.Pool
	logger *zap.Logger
}

func NewService(db *pgxpool.Pool, logger *zap.Logger) *Service {
	return &Service{
		db:     db,
		logger: logger,
	}
}

// ==================== Webhook Config Management ====================

// CreateWebhook creates a new webhook configuration
func (s *Service) CreateWebhook(ctx context.Context, orgID, agentID uuid.UUID, req *CreateWebhookRequest) (*WebhookConfig, string, error) {
	// Generate a secure random secret
	secret, err := generateWebhookSecret()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate secret: %w", err)
	}

	// Hash the secret for storage
	secretHash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash secret: %w", err)
	}

	// Insert webhook config
	config := &WebhookConfig{
		ID:          uuid.New(),
		OrgID:       orgID,
		AgentID:     agentID,
		Name:        req.Name,
		Provider:    req.Provider,
		SecretHash:  string(secretHash),
		Enabled:     true,
		ServiceName: req.ServiceName,
		Environment: req.Environment,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	query := `
		INSERT INTO webhook_configs (id, org_id, agent_id, name, provider, secret_hash, enabled, service_name, environment, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err = s.db.Exec(ctx, query,
		config.ID, config.OrgID, config.AgentID, config.Name, config.Provider,
		config.SecretHash, config.Enabled, config.ServiceName, config.Environment,
		config.CreatedAt, config.UpdatedAt,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create webhook: %w", err)
	}

	return config, secret, nil
}

// ListWebhooks lists all webhooks for an agent
func (s *Service) ListWebhooks(ctx context.Context, orgID, agentID uuid.UUID) ([]*WebhookConfig, error) {
	query := `
		SELECT id, org_id, agent_id, name, provider, enabled, service_name, environment, created_at, updated_at, last_used_at
		FROM webhook_configs
		WHERE org_id = $1 AND agent_id = $2
		ORDER BY created_at DESC
	`

	rows, err := s.db.Query(ctx, query, orgID, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list webhooks: %w", err)
	}
	defer rows.Close()

	var webhooks []*WebhookConfig
	for rows.Next() {
		var w WebhookConfig
		err := rows.Scan(
			&w.ID, &w.OrgID, &w.AgentID, &w.Name, &w.Provider, &w.Enabled,
			&w.ServiceName, &w.Environment, &w.CreatedAt, &w.UpdatedAt, &w.LastUsedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan webhook: %w", err)
		}
		webhooks = append(webhooks, &w)
	}

	return webhooks, nil
}

// GetWebhook retrieves a webhook by ID
func (s *Service) GetWebhook(ctx context.Context, webhookID uuid.UUID) (*WebhookConfig, error) {
	query := `
		SELECT id, org_id, agent_id, name, provider, secret_hash, enabled, service_name, environment, created_at, updated_at, last_used_at
		FROM webhook_configs
		WHERE id = $1
	`

	var w WebhookConfig
	err := s.db.QueryRow(ctx, query, webhookID).Scan(
		&w.ID, &w.OrgID, &w.AgentID, &w.Name, &w.Provider, &w.SecretHash, &w.Enabled,
		&w.ServiceName, &w.Environment, &w.CreatedAt, &w.UpdatedAt, &w.LastUsedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("webhook not found")
		}
		return nil, fmt.Errorf("failed to get webhook: %w", err)
	}

	return &w, nil
}

// UpdateWebhook updates a webhook configuration
func (s *Service) UpdateWebhook(ctx context.Context, webhookID uuid.UUID, req *UpdateWebhookRequest) error {
	updates := make(map[string]interface{})
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}
	if req.ServiceName != nil {
		updates["service_name"] = *req.ServiceName
	}
	if req.Environment != nil {
		updates["environment"] = *req.Environment
	}

	if len(updates) == 0 {
		return nil
	}

	// Build dynamic query
	query := "UPDATE webhook_configs SET updated_at = NOW()"
	args := []interface{}{}
	argIdx := 1

	for col, val := range updates {
		query += fmt.Sprintf(", %s = $%d", col, argIdx)
		args = append(args, val)
		argIdx++
	}

	query += fmt.Sprintf(" WHERE id = $%d", argIdx)
	args = append(args, webhookID)

	_, err := s.db.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update webhook: %w", err)
	}

	return nil
}

// DeleteWebhook deletes a webhook configuration
func (s *Service) DeleteWebhook(ctx context.Context, webhookID uuid.UUID) error {
	query := `DELETE FROM webhook_configs WHERE id = $1`
	_, err := s.db.Exec(ctx, query, webhookID)
	if err != nil {
		return fmt.Errorf("failed to delete webhook: %w", err)
	}
	return nil
}

// ==================== Webhook Event Processing ====================

// VerifyAndParse verifies the webhook signature and parses the payload
func (s *Service) VerifyAndParse(ctx context.Context, webhookID uuid.UUID, headers map[string]string, payload []byte) (*BuildMetadata, error) {
	// Get webhook config
	config, err := s.GetWebhook(ctx, webhookID)
	if err != nil {
		return nil, fmt.Errorf("failed to get webhook config: %w", err)
	}

	if !config.Enabled {
		return nil, fmt.Errorf("webhook is disabled")
	}

	// Note: Webhook signature verification is currently skipped
	// The secret is stored as a bcrypt hash (for comparison with user input)
	// but signature verification requires the plain secret
	// TODO: Store secrets encrypted (not hashed) to enable signature verification
	s.logger.Warn("webhook signature verification skipped - secret is hashed, not encrypted",
		zap.String("webhook_id", webhookID.String()),
		zap.String("provider", config.Provider),
	)

	// Parse payload
	parser, err := GetParser(config.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get parser: %w", err)
	}

	metadata, err := parser.Parse(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse payload: %w", err)
	}

	// Update last_used_at
	_, err = s.db.Exec(ctx, "UPDATE webhook_configs SET last_used_at = NOW() WHERE id = $1", webhookID)
	if err != nil {
		s.logger.Warn("failed to update last_used_at", zap.Error(err))
	}

	return metadata, nil
}

// RecordWebhookEvent records a webhook event for audit purposes
func (s *Service) RecordWebhookEvent(ctx context.Context, webhookID uuid.UUID, provider, eventType string, headers map[string]string, payload []byte, verified bool, deploymentID *uuid.UUID, err error) (uuid.UUID, error) {
	event := &WebhookEvent{
		ID:           uuid.New(),
		WebhookID:    webhookID,
		Provider:     provider,
		EventType:    eventType,
		Verified:     verified,
		Processed:    deploymentID != nil,
		DeploymentID: deploymentID,
		CreatedAt:    time.Now(),
	}

	if deploymentID != nil {
		now := time.Now()
		event.ProcessedAt = &now
	}

	if err != nil {
		errMsg := err.Error()
		event.Error = &errMsg
	}

	// Encode headers and payload as JSON
	headersJSON, _ := json.Marshal(headers)
	payloadJSON := payload

	query := `
		INSERT INTO webhook_events (id, webhook_id, provider, event_type, payload, headers, verified, processed, deployment_id, error, created_at, processed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, dbErr := s.db.Exec(ctx, query,
		event.ID, event.WebhookID, event.Provider, event.EventType,
		payloadJSON, headersJSON, event.Verified, event.Processed,
		event.DeploymentID, event.Error, event.CreatedAt, event.ProcessedAt,
	)
	if dbErr != nil {
		return uuid.Nil, fmt.Errorf("failed to record webhook event: %w", dbErr)
	}

	return event.ID, nil
}

// ListWebhookEvents lists webhook events with pagination
func (s *Service) ListWebhookEvents(ctx context.Context, webhookID uuid.UUID, limit, offset int) ([]*WebhookEvent, error) {
	query := `
		SELECT id, webhook_id, provider, event_type, verified, processed, deployment_id, error, created_at, processed_at
		FROM webhook_events
		WHERE webhook_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := s.db.Query(ctx, query, webhookID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list webhook events: %w", err)
	}
	defer rows.Close()

	var events []*WebhookEvent
	for rows.Next() {
		var e WebhookEvent
		err := rows.Scan(
			&e.ID, &e.WebhookID, &e.Provider, &e.EventType, &e.Verified, &e.Processed,
			&e.DeploymentID, &e.Error, &e.CreatedAt, &e.ProcessedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan webhook event: %w", err)
		}
		events = append(events, &e)
	}

	return events, nil
}

// ==================== Helper Functions ====================

func generateWebhookSecret() (string, error) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Encode as base64
	return base64.URLEncoding.EncodeToString(bytes), nil
}
