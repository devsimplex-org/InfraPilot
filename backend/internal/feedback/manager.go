package feedback

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// FeedbackManager implements the Manager interface
type FeedbackManager struct {
	db         *pgxpool.Pool
	logger     *zap.Logger
	deliverers map[Provider]Deliverer
}

// NewManager creates a new feedback manager
func NewManager(db *pgxpool.Pool, logger *zap.Logger) *FeedbackManager {
	return &FeedbackManager{
		db:         db,
		logger:     logger,
		deliverers: make(map[Provider]Deliverer),
	}
}

// RegisterDeliverer registers a VCS provider deliverer
func (m *FeedbackManager) RegisterDeliverer(deliverer Deliverer) {
	m.deliverers[deliverer.Provider()] = deliverer
	m.logger.Info("registered feedback deliverer", zap.String("provider", string(deliverer.Provider())))
}

// CreateFeedback creates a new feedback entry
func (m *FeedbackManager) CreateFeedback(ctx context.Context, feedback *Feedback) error {
	if feedback.ID == uuid.Nil {
		feedback.ID = uuid.New()
	}

	now := time.Now()
	feedback.CreatedAt = now
	feedback.UpdatedAt = now

	// Serialize metadata
	metadataJSON, err := json.Marshal(feedback.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO developer_feedback (
			id, org_id, source_type, source_id,
			provider, repo_full_name, pull_request_number, commit_sha, branch_name,
			severity, title, message, remediation,
			metadata, delivery_status,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7, $8, $9,
			$10, $11, $12, $13,
			$14, $15,
			$16, $17
		)
	`

	_, err = m.db.Exec(ctx, query,
		feedback.ID, feedback.OrgID, feedback.Type, feedback.SourceID,
		feedback.Target.Provider, feedback.Target.RepoFullName,
		feedback.Target.PullRequest, feedback.Target.CommitSHA, feedback.Target.BranchName,
		feedback.Content.Severity, feedback.Content.Title, feedback.Content.Message, feedback.Content.Remediation,
		metadataJSON, feedback.Status,
		feedback.CreatedAt, feedback.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert feedback: %w", err)
	}

	m.logger.Info("created feedback",
		zap.String("id", feedback.ID.String()),
		zap.String("type", string(feedback.Type)),
		zap.String("repo", feedback.Target.RepoFullName),
	)

	return nil
}

// DeliverFeedback delivers a specific feedback entry
func (m *FeedbackManager) DeliverFeedback(ctx context.Context, feedbackID uuid.UUID) error {
	// Retrieve feedback
	feedback, err := m.GetFeedback(ctx, feedbackID)
	if err != nil {
		return fmt.Errorf("failed to get feedback: %w", err)
	}

	// Check if already delivered
	if feedback.Status == StatusDelivered {
		m.logger.Info("feedback already delivered", zap.String("id", feedbackID.String()))
		return nil
	}

	// Get deliverer for provider
	deliverer, ok := m.deliverers[feedback.Target.Provider]
	if !ok {
		return m.markFailed(ctx, feedbackID, fmt.Sprintf("no deliverer registered for provider: %s", feedback.Target.Provider))
	}

	// Deliver based on target
	var externalID string
	var deliverErr error

	if feedback.Target.PullRequest != nil {
		externalID, deliverErr = deliverer.DeliverPRComment(ctx, feedback.Target, feedback.Content)
	} else if feedback.Target.CommitSHA != nil {
		externalID, deliverErr = deliverer.DeliverCommitComment(ctx, feedback.Target, feedback.Content)
	} else {
		return m.markFailed(ctx, feedbackID, "no valid target (PR or commit)")
	}

	if deliverErr != nil {
		return m.markFailed(ctx, feedbackID, deliverErr.Error())
	}

	// Mark as delivered
	return m.markDelivered(ctx, feedbackID, externalID)
}

// DeliverAll delivers all pending feedback
func (m *FeedbackManager) DeliverAll(ctx context.Context) error {
	status := StatusPending
	pending, err := m.ListFeedback(ctx, FeedbackFilters{
		Status: &status,
		Limit:  100,
	})
	if err != nil {
		return fmt.Errorf("failed to list pending feedback: %w", err)
	}

	m.logger.Info("delivering pending feedback", zap.Int("count", len(pending)))

	var errors []error
	for _, fb := range pending {
		if err := m.DeliverFeedback(ctx, fb.ID); err != nil {
			m.logger.Error("failed to deliver feedback",
				zap.String("id", fb.ID.String()),
				zap.Error(err),
			)
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to deliver %d feedback(s)", len(errors))
	}

	return nil
}

// GetFeedback retrieves feedback by ID
func (m *FeedbackManager) GetFeedback(ctx context.Context, feedbackID uuid.UUID) (*Feedback, error) {
	query := `
		SELECT
			id, org_id, source_type, source_id,
			provider, repo_full_name, pull_request_number, commit_sha, branch_name,
			severity, title, message, remediation,
			metadata, delivery_status, delivered_at, delivery_error, external_id,
			created_at, updated_at
		FROM developer_feedback
		WHERE id = $1
	`

	var fb Feedback
	var metadataJSON []byte

	err := m.db.QueryRow(ctx, query, feedbackID).Scan(
		&fb.ID, &fb.OrgID, &fb.Type, &fb.SourceID,
		&fb.Target.Provider, &fb.Target.RepoFullName,
		&fb.Target.PullRequest, &fb.Target.CommitSHA, &fb.Target.BranchName,
		&fb.Content.Severity, &fb.Content.Title, &fb.Content.Message, &fb.Content.Remediation,
		&metadataJSON, &fb.Status, &fb.DeliveredAt, &fb.DeliveryError, &fb.ExternalID,
		&fb.CreatedAt, &fb.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query feedback: %w", err)
	}

	// Deserialize metadata
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &fb.Metadata); err != nil {
			m.logger.Warn("failed to unmarshal metadata", zap.Error(err))
		}
	}

	return &fb, nil
}

// ListFeedback lists feedback with filters
func (m *FeedbackManager) ListFeedback(ctx context.Context, filters FeedbackFilters) ([]*Feedback, error) {
	query := `
		SELECT
			id, org_id, source_type, source_id,
			provider, repo_full_name, pull_request_number, commit_sha, branch_name,
			severity, title, message, remediation,
			metadata, delivery_status, delivered_at, delivery_error, external_id,
			created_at, updated_at
		FROM developer_feedback
		WHERE 1=1
	`

	args := []interface{}{}
	argPos := 1

	if filters.OrgID != nil {
		query += fmt.Sprintf(" AND org_id = $%d", argPos)
		args = append(args, *filters.OrgID)
		argPos++
	}

	if filters.SourceType != nil {
		query += fmt.Sprintf(" AND source_type = $%d", argPos)
		args = append(args, *filters.SourceType)
		argPos++
	}

	if filters.Status != nil {
		query += fmt.Sprintf(" AND delivery_status = $%d", argPos)
		args = append(args, *filters.Status)
		argPos++
	}

	if filters.Repo != nil {
		query += fmt.Sprintf(" AND repo_full_name = $%d", argPos)
		args = append(args, *filters.Repo)
		argPos++
	}

	if filters.PRNumber != nil {
		query += fmt.Sprintf(" AND pull_request_number = $%d", argPos)
		args = append(args, *filters.PRNumber)
		argPos++
	}

	query += " ORDER BY created_at DESC"

	if filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argPos)
		args = append(args, filters.Limit)
		argPos++
	}

	if filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argPos)
		args = append(args, filters.Offset)
		argPos++
	}

	rows, err := m.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query feedback: %w", err)
	}
	defer rows.Close()

	var feedbacks []*Feedback
	for rows.Next() {
		var fb Feedback
		var metadataJSON []byte

		err := rows.Scan(
			&fb.ID, &fb.OrgID, &fb.Type, &fb.SourceID,
			&fb.Target.Provider, &fb.Target.RepoFullName,
			&fb.Target.PullRequest, &fb.Target.CommitSHA, &fb.Target.BranchName,
			&fb.Content.Severity, &fb.Content.Title, &fb.Content.Message, &fb.Content.Remediation,
			&metadataJSON, &fb.Status, &fb.DeliveredAt, &fb.DeliveryError, &fb.ExternalID,
			&fb.CreatedAt, &fb.UpdatedAt,
		)
		if err != nil {
			m.logger.Error("failed to scan feedback row", zap.Error(err))
			continue
		}

		// Deserialize metadata
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &fb.Metadata); err != nil {
				m.logger.Warn("failed to unmarshal metadata", zap.Error(err))
			}
		}

		feedbacks = append(feedbacks, &fb)
	}

	return feedbacks, nil
}

// GetConfiguration retrieves VCS configuration
func (m *FeedbackManager) GetConfiguration(ctx context.Context, orgID uuid.UUID, provider Provider) (*VCSConfiguration, error) {
	query := `
		SELECT
			id, org_id, provider, enabled,
			auth_type, credentials_encrypted,
			app_id, installation_id,
			default_repo, auto_comment_on_pr, auto_comment_on_commit,
			created_at, updated_at
		FROM vcs_configurations
		WHERE org_id = $1 AND provider = $2
	`

	var config VCSConfiguration
	var credentialsEncrypted []byte

	err := m.db.QueryRow(ctx, query, orgID, provider).Scan(
		&config.ID, &config.OrgID, &config.Provider, &config.Enabled,
		&config.AuthType, &credentialsEncrypted,
		&config.AppID, &config.InstallationID,
		&config.DefaultRepo, &config.AutoCommentOnPR, &config.AutoCommentOnCommit,
		&config.CreatedAt, &config.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query configuration: %w", err)
	}

	// TODO: Decrypt credentials
	// For now, just deserialize as-is (implement proper encryption later)
	if len(credentialsEncrypted) > 0 {
		if err := json.Unmarshal(credentialsEncrypted, &config.Credentials); err != nil {
			return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
		}
	}

	return &config, nil
}

// SaveConfiguration saves or updates VCS configuration
func (m *FeedbackManager) SaveConfiguration(ctx context.Context, config *VCSConfiguration) error {
	if config.ID == uuid.Nil {
		config.ID = uuid.New()
	}

	now := time.Now()
	config.UpdatedAt = now
	if config.CreatedAt.IsZero() {
		config.CreatedAt = now
	}

	// Serialize credentials
	// TODO: Implement proper encryption
	credentialsJSON, err := json.Marshal(config.Credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	query := `
		INSERT INTO vcs_configurations (
			id, org_id, provider, enabled,
			auth_type, credentials_encrypted,
			app_id, installation_id,
			default_repo, auto_comment_on_pr, auto_comment_on_commit,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
		ON CONFLICT (org_id, provider)
		DO UPDATE SET
			enabled = EXCLUDED.enabled,
			auth_type = EXCLUDED.auth_type,
			credentials_encrypted = EXCLUDED.credentials_encrypted,
			app_id = EXCLUDED.app_id,
			installation_id = EXCLUDED.installation_id,
			default_repo = EXCLUDED.default_repo,
			auto_comment_on_pr = EXCLUDED.auto_comment_on_pr,
			auto_comment_on_commit = EXCLUDED.auto_comment_on_commit,
			updated_at = EXCLUDED.updated_at
	`

	_, err = m.db.Exec(ctx, query,
		config.ID, config.OrgID, config.Provider, config.Enabled,
		config.AuthType, credentialsJSON,
		config.AppID, config.InstallationID,
		config.DefaultRepo, config.AutoCommentOnPR, config.AutoCommentOnCommit,
		config.CreatedAt, config.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	m.logger.Info("saved VCS configuration",
		zap.String("org_id", config.OrgID.String()),
		zap.String("provider", string(config.Provider)),
	)

	return nil
}

// markDelivered marks feedback as successfully delivered
func (m *FeedbackManager) markDelivered(ctx context.Context, feedbackID uuid.UUID, externalID string) error {
	query := `
		UPDATE developer_feedback
		SET delivery_status = $1,
		    delivered_at = $2,
		    external_id = $3,
		    updated_at = $4
		WHERE id = $5
	`

	now := time.Now()
	_, err := m.db.Exec(ctx, query, StatusDelivered, now, externalID, now, feedbackID)
	if err != nil {
		return fmt.Errorf("failed to mark delivered: %w", err)
	}

	m.logger.Info("marked feedback as delivered",
		zap.String("id", feedbackID.String()),
		zap.String("external_id", externalID),
	)

	return nil
}

// markFailed marks feedback as failed to deliver
func (m *FeedbackManager) markFailed(ctx context.Context, feedbackID uuid.UUID, errorMsg string) error {
	query := `
		UPDATE developer_feedback
		SET delivery_status = $1,
		    delivery_error = $2,
		    updated_at = $3
		WHERE id = $4
	`

	now := time.Now()
	_, err := m.db.Exec(ctx, query, StatusFailed, errorMsg, now, feedbackID)
	if err != nil {
		return fmt.Errorf("failed to mark failed: %w", err)
	}

	m.logger.Error("marked feedback as failed",
		zap.String("id", feedbackID.String()),
		zap.String("error", errorMsg),
	)

	return fmt.Errorf("delivery failed: %s", errorMsg)
}
