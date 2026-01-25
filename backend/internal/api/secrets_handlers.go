package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	agentgrpc "github.com/infrapilot/backend/internal/grpc"
	"go.uber.org/zap"
)

// ============================================================================
// Types
// ============================================================================

// SecretInventory represents a tracked secret
type SecretInventory struct {
	ID                  uuid.UUID  `json:"id"`
	OrgID               uuid.UUID  `json:"org_id"`
	AgentID             *uuid.UUID `json:"agent_id,omitempty"`
	Name                string     `json:"name"`
	SecretType          string     `json:"secret_type"`
	Source              string     `json:"source"`
	Location            *string    `json:"location,omitempty"`
	DeploymentID        *uuid.UUID `json:"deployment_id,omitempty"`
	ContainerID         *string    `json:"container_id,omitempty"`
	ContainerName       *string    `json:"container_name,omitempty"`
	ServiceName         *string    `json:"service_name,omitempty"`
	Classification      string     `json:"classification"`
	Environment         string     `json:"environment"`
	IsSensitive         bool       `json:"is_sensitive"`
	AgeDays             *int       `json:"age_days,omitempty"`
	CreatedDate         *time.Time `json:"created_date,omitempty"`
	LastRotatedAt       *time.Time `json:"last_rotated_at,omitempty"`
	RotationPolicyDays  int        `json:"rotation_policy_days"`
	IsExpired           bool       `json:"is_expired"`
	NeedsRotation       bool       `json:"needs_rotation"`
	Strength            *string    `json:"strength,omitempty"`
	IsHardcoded         bool       `json:"is_hardcoded"`
	IsExposed           bool       `json:"is_exposed"`
	ExposureRisk        string     `json:"exposure_risk"`
	Description         *string    `json:"description,omitempty"`
	OwnerTeam           *string    `json:"owner_team,omitempty"`
	OwnerContact        *string    `json:"owner_contact,omitempty"`
	DiscoveredAt        time.Time  `json:"discovered_at"`
	AutoDiscovered      bool       `json:"auto_discovered"`
	LastScannedAt       *time.Time `json:"last_scanned_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// SecretRotationHistory represents a rotation event
type SecretRotationHistory struct {
	ID               uuid.UUID  `json:"id"`
	OrgID            uuid.UUID  `json:"org_id"`
	SecretID         uuid.UUID  `json:"secret_id"`
	RotationType     string     `json:"rotation_type"`
	TriggeredByEmail *string    `json:"triggered_by_email,omitempty"`
	Status           string     `json:"status"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	CompletedAt      *time.Time `json:"completed_at,omitempty"`
	OldStrength      *string    `json:"old_strength,omitempty"`
	NewStrength      *string    `json:"new_strength,omitempty"`
	ErrorMessage     *string    `json:"error_message,omitempty"`
	RestartRequired  bool       `json:"restart_required"`
	ServicesRestarted bool      `json:"services_restarted"`
	CreatedAt        time.Time  `json:"created_at"`
	// Joined fields
	SecretName *string `json:"secret_name,omitempty"`
}

// SecretExposureEvent represents an exposure incident
type SecretExposureEvent struct {
	ID               uuid.UUID  `json:"id"`
	OrgID            uuid.UUID  `json:"org_id"`
	SecretID         *uuid.UUID `json:"secret_id,omitempty"`
	DetectionType    string     `json:"detection_type"`
	DetectionSource  *string    `json:"detection_source,omitempty"`
	Severity         string     `json:"severity"`
	ExposureLocation *string    `json:"exposure_location,omitempty"`
	ExposureContent  *string    `json:"exposure_content,omitempty"`
	FilePath         *string    `json:"file_path,omitempty"`
	LineNumber       *int       `json:"line_number,omitempty"`
	CommitSHA        *string    `json:"commit_sha,omitempty"`
	RepositoryURL    *string    `json:"repository_url,omitempty"`
	Status           string     `json:"status"`
	AcknowledgedAt   *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedAt       *time.Time `json:"resolved_at,omitempty"`
	ResolutionNotes  *string    `json:"resolution_notes,omitempty"`
	PotentialImpact  *string    `json:"potential_impact,omitempty"`
	WasAccessed      *bool      `json:"was_accessed,omitempty"`
	AccessAttempts   int        `json:"access_attempts"`
	DetectedAt       time.Time  `json:"detected_at"`
	CreatedAt        time.Time  `json:"created_at"`
	// Joined fields
	SecretName *string `json:"secret_name,omitempty"`
}

// SecretRotationPolicy represents rotation rules
type SecretRotationPolicy struct {
	ID                    uuid.UUID `json:"id"`
	OrgID                 uuid.UUID `json:"org_id"`
	Name                  string    `json:"name"`
	Description           *string   `json:"description,omitempty"`
	MaxAgeDays            int       `json:"max_age_days"`
	MinStrength           string    `json:"min_strength"`
	RequireUnique         bool      `json:"require_unique"`
	AllowReuse            bool      `json:"allow_reuse"`
	ReuseHistoryCount     int       `json:"reuse_history_count"`
	AutoRotate            bool      `json:"auto_rotate"`
	RotationCron          *string   `json:"rotation_cron,omitempty"`
	NotifyBeforeDays      int       `json:"notify_before_days"`
	NotifyOnExpiry        bool      `json:"notify_on_expiry"`
	NotifyOnExposure      bool      `json:"notify_on_exposure"`
	Enabled               bool      `json:"enabled"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// SecretScanResult represents a scan result
type SecretScanResult struct {
	ID                uuid.UUID  `json:"id"`
	OrgID             uuid.UUID  `json:"org_id"`
	AgentID           *uuid.UUID `json:"agent_id,omitempty"`
	DeploymentID      *uuid.UUID `json:"deployment_id,omitempty"`
	ScanType          string     `json:"scan_type"`
	ScanTarget        *string    `json:"scan_target,omitempty"`
	Scanner           string     `json:"scanner"`
	Status            string     `json:"status"`
	StartedAt         time.Time  `json:"started_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	DurationSeconds   *int       `json:"duration_seconds,omitempty"`
	SecretsFound      int        `json:"secrets_found"`
	HighRiskFindings  int        `json:"high_risk_findings"`
	HardcodedSecrets  int        `json:"hardcoded_secrets"`
	ExpiredSecrets    int        `json:"expired_secrets"`
	WeakSecrets       int        `json:"weak_secrets"`
	FilesScanned      int        `json:"files_scanned"`
	ContainersScanned int        `json:"containers_scanned"`
	EnvVarsScanned    int        `json:"env_vars_scanned"`
	ErrorMessage      *string    `json:"error_message,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
}

// SecretsHygieneSummary represents hygiene statistics
type SecretsHygieneSummary struct {
	TotalSecrets     int     `json:"total_secrets"`
	NeedsRotation    int     `json:"needs_rotation"`
	ExpiredSecrets   int     `json:"expired_secrets"`
	WeakSecrets      int     `json:"weak_secrets"`
	HardcodedSecrets int     `json:"hardcoded_secrets"`
	ExposedSecrets   int     `json:"exposed_secrets"`
	CriticalRisk     int     `json:"critical_risk"`
	HighRisk         int     `json:"high_risk"`
	AvgAgeDays       float64 `json:"avg_age_days"`
}

// SecretExposureSummary represents exposure statistics
type SecretExposureSummary struct {
	TotalExposures    int `json:"total_exposures"`
	ActiveExposures   int `json:"active_exposures"`
	CriticalExposures int `json:"critical_exposures"`
	HighExposures     int `json:"high_exposures"`
	ExposuresLast7d   int `json:"exposures_last_7d"`
	ExposuresLast30d  int `json:"exposures_last_30d"`
}

// ============================================================================
// Request Types
// ============================================================================

type CreateSecretInventoryRequest struct {
	Name               string  `json:"name" binding:"required"`
	SecretType         string  `json:"secret_type" binding:"required"`
	Source             string  `json:"source" binding:"required"`
	Location           *string `json:"location,omitempty"`
	AgentID            *string `json:"agent_id,omitempty"`
	DeploymentID       *string `json:"deployment_id,omitempty"`
	ContainerID        *string `json:"container_id,omitempty"`
	ContainerName      *string `json:"container_name,omitempty"`
	ServiceName        *string `json:"service_name,omitempty"`
	Classification     string  `json:"classification"`
	Environment        string  `json:"environment"`
	RotationPolicyDays int     `json:"rotation_policy_days"`
	Description        *string `json:"description,omitempty"`
	OwnerTeam          *string `json:"owner_team,omitempty"`
	OwnerContact       *string `json:"owner_contact,omitempty"`
}

type TriggerSecretScanRequest struct {
	ScanType     string  `json:"scan_type"`
	ScanTarget   *string `json:"scan_target,omitempty"`
	AgentID      *string `json:"agent_id,omitempty"`
	DeploymentID *string `json:"deployment_id,omitempty"`
}

type UpdateExposureStatusRequest struct {
	Status          string  `json:"status" binding:"required"`
	ResolutionNotes *string `json:"resolution_notes,omitempty"`
}

type CreateRotationPolicyRequest struct {
	Name             string `json:"name" binding:"required"`
	Description      string `json:"description"`
	MaxAgeDays       int    `json:"max_age_days"`
	MinStrength      string `json:"min_strength"`
	AutoRotate       bool   `json:"auto_rotate"`
	RotationCron     string `json:"rotation_cron"`
	NotifyBeforeDays int    `json:"notify_before_days"`
	NotifyOnExpiry   bool   `json:"notify_on_expiry"`
	NotifyOnExposure bool   `json:"notify_on_exposure"`
}

// ============================================================================
// Handlers
// ============================================================================

// listSecrets returns secrets inventory
func (h *Handler) listSecrets(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	secretType := c.Query("secret_type")
	source := c.Query("source")
	exposureRisk := c.Query("exposure_risk")
	needsRotation := c.Query("needs_rotation")

	query := `
		SELECT id, org_id, agent_id, name, secret_type, source, location,
		       deployment_id, container_id, container_name, service_name,
		       classification, environment, is_sensitive, age_days, created_date,
		       last_rotated_at, rotation_policy_days, is_expired, needs_rotation,
		       strength, is_hardcoded, is_exposed, exposure_risk, description,
		       owner_team, owner_contact, discovered_at, auto_discovered,
		       last_scanned_at, created_at, updated_at
		FROM secrets_inventory
		WHERE org_id = $1`

	args := []interface{}{orgID}
	argCount := 1

	if secretType != "" {
		argCount++
		query += ` AND secret_type = $` + string(rune('0'+argCount))
		args = append(args, secretType)
	}

	if source != "" {
		argCount++
		query += ` AND source = $` + string(rune('0'+argCount))
		args = append(args, source)
	}

	if exposureRisk != "" {
		argCount++
		query += ` AND exposure_risk = $` + string(rune('0'+argCount))
		args = append(args, exposureRisk)
	}

	if needsRotation == "true" {
		query += ` AND needs_rotation = true`
	}

	query += ` ORDER BY exposure_risk DESC, needs_rotation DESC, name LIMIT 500`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to list secrets", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list secrets"})
		return
	}
	defer rows.Close()

	secrets := []SecretInventory{}
	for rows.Next() {
		var s SecretInventory
		err := rows.Scan(
			&s.ID, &s.OrgID, &s.AgentID, &s.Name, &s.SecretType, &s.Source, &s.Location,
			&s.DeploymentID, &s.ContainerID, &s.ContainerName, &s.ServiceName,
			&s.Classification, &s.Environment, &s.IsSensitive, &s.AgeDays, &s.CreatedDate,
			&s.LastRotatedAt, &s.RotationPolicyDays, &s.IsExpired, &s.NeedsRotation,
			&s.Strength, &s.IsHardcoded, &s.IsExposed, &s.ExposureRisk, &s.Description,
			&s.OwnerTeam, &s.OwnerContact, &s.DiscoveredAt, &s.AutoDiscovered,
			&s.LastScannedAt, &s.CreatedAt, &s.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan secret", zap.Error(err))
			continue
		}
		secrets = append(secrets, s)
	}

	c.JSON(http.StatusOK, secrets)
}

// getSecret returns a specific secret
func (h *Handler) getSecret(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	secretID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid secret ID"})
		return
	}

	var s SecretInventory
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, agent_id, name, secret_type, source, location,
		       deployment_id, container_id, container_name, service_name,
		       classification, environment, is_sensitive, age_days, created_date,
		       last_rotated_at, rotation_policy_days, is_expired, needs_rotation,
		       strength, is_hardcoded, is_exposed, exposure_risk, description,
		       owner_team, owner_contact, discovered_at, auto_discovered,
		       last_scanned_at, created_at, updated_at
		FROM secrets_inventory
		WHERE id = $1 AND org_id = $2`,
		secretID, orgID,
	).Scan(
		&s.ID, &s.OrgID, &s.AgentID, &s.Name, &s.SecretType, &s.Source, &s.Location,
		&s.DeploymentID, &s.ContainerID, &s.ContainerName, &s.ServiceName,
		&s.Classification, &s.Environment, &s.IsSensitive, &s.AgeDays, &s.CreatedDate,
		&s.LastRotatedAt, &s.RotationPolicyDays, &s.IsExpired, &s.NeedsRotation,
		&s.Strength, &s.IsHardcoded, &s.IsExposed, &s.ExposureRisk, &s.Description,
		&s.OwnerTeam, &s.OwnerContact, &s.DiscoveredAt, &s.AutoDiscovered,
		&s.LastScannedAt, &s.CreatedAt, &s.UpdatedAt,
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
		return
	}

	c.JSON(http.StatusOK, s)
}

// createSecret adds a new secret to inventory
func (h *Handler) createSecret(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req CreateSecretInventoryRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Classification == "" {
		req.Classification = "internal"
	}
	if req.Environment == "" {
		req.Environment = "production"
	}
	if req.RotationPolicyDays == 0 {
		req.RotationPolicyDays = 90
	}

	var agentID, deploymentID *uuid.UUID
	if req.AgentID != nil {
		if id, err := uuid.Parse(*req.AgentID); err == nil {
			agentID = &id
		}
	}
	if req.DeploymentID != nil {
		if id, err := uuid.Parse(*req.DeploymentID); err == nil {
			deploymentID = &id
		}
	}

	var secretID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO secrets_inventory (org_id, agent_id, name, secret_type, source, location,
		                               deployment_id, container_id, container_name, service_name,
		                               classification, environment, rotation_policy_days,
		                               description, owner_team, owner_contact, auto_discovered)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, false)
		RETURNING id`,
		orgID, agentID, req.Name, req.SecretType, req.Source, req.Location,
		deploymentID, req.ContainerID, req.ContainerName, req.ServiceName,
		req.Classification, req.Environment, req.RotationPolicyDays,
		req.Description, req.OwnerTeam, req.OwnerContact,
	).Scan(&secretID)

	if err != nil {
		h.logger.Error("Failed to create secret", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create secret"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": secretID})
}

// deleteSecret removes a secret from inventory
func (h *Handler) deleteSecret(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	secretID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid secret ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(),
		`DELETE FROM secrets_inventory WHERE id = $1 AND org_id = $2`,
		secretID, orgID,
	)
	if err != nil {
		h.logger.Error("Failed to delete secret", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete secret"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Secret not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Secret deleted"})
}

// getSecretsHygieneSummary returns hygiene statistics
func (h *Handler) getSecretsHygieneSummary(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var summary SecretsHygieneSummary
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT
			COALESCE(total_secrets, 0),
			COALESCE(needs_rotation, 0),
			COALESCE(expired_secrets, 0),
			COALESCE(weak_secrets, 0),
			COALESCE(hardcoded_secrets, 0),
			COALESCE(exposed_secrets, 0),
			COALESCE(critical_risk, 0),
			COALESCE(high_risk, 0),
			COALESCE(avg_age_days, 0)
		FROM v_secrets_hygiene_summary
		WHERE org_id = $1`,
		orgID,
	).Scan(
		&summary.TotalSecrets, &summary.NeedsRotation, &summary.ExpiredSecrets,
		&summary.WeakSecrets, &summary.HardcodedSecrets, &summary.ExposedSecrets,
		&summary.CriticalRisk, &summary.HighRisk, &summary.AvgAgeDays,
	)

	if err != nil {
		// Return empty summary if no data
		c.JSON(http.StatusOK, SecretsHygieneSummary{})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// listSecretExposures returns exposure events
func (h *Handler) listSecretExposures(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	status := c.Query("status")
	severity := c.Query("severity")

	query := `
		SELECT e.id, e.org_id, e.secret_id, e.detection_type, e.detection_source,
		       e.severity, e.exposure_location, e.exposure_content, e.file_path,
		       e.line_number, e.commit_sha, e.repository_url, e.status,
		       e.acknowledged_at, e.resolved_at, e.resolution_notes,
		       e.potential_impact, e.was_accessed, e.access_attempts,
		       e.detected_at, e.created_at,
		       s.name as secret_name
		FROM secret_exposure_events e
		LEFT JOIN secrets_inventory s ON s.id = e.secret_id
		WHERE e.org_id = $1`

	args := []interface{}{orgID}
	argCount := 1

	if status != "" {
		argCount++
		query += ` AND e.status = $` + string(rune('0'+argCount))
		args = append(args, status)
	}

	if severity != "" {
		argCount++
		query += ` AND e.severity = $` + string(rune('0'+argCount))
		args = append(args, severity)
	}

	query += ` ORDER BY e.detected_at DESC LIMIT 100`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to list secret exposures", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list exposures"})
		return
	}
	defer rows.Close()

	exposures := []SecretExposureEvent{}
	for rows.Next() {
		var e SecretExposureEvent
		err := rows.Scan(
			&e.ID, &e.OrgID, &e.SecretID, &e.DetectionType, &e.DetectionSource,
			&e.Severity, &e.ExposureLocation, &e.ExposureContent, &e.FilePath,
			&e.LineNumber, &e.CommitSHA, &e.RepositoryURL, &e.Status,
			&e.AcknowledgedAt, &e.ResolvedAt, &e.ResolutionNotes,
			&e.PotentialImpact, &e.WasAccessed, &e.AccessAttempts,
			&e.DetectedAt, &e.CreatedAt,
			&e.SecretName,
		)
		if err != nil {
			h.logger.Error("Failed to scan exposure", zap.Error(err))
			continue
		}
		exposures = append(exposures, e)
	}

	c.JSON(http.StatusOK, exposures)
}

// updateExposureStatus updates an exposure event status
func (h *Handler) updateExposureStatus(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	exposureID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid exposure ID"})
		return
	}

	var req UpdateExposureStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var query string
	var args []interface{}

	switch req.Status {
	case "acknowledged", "investigating":
		query = `UPDATE secret_exposure_events SET status = $1, acknowledged_by = $2, acknowledged_at = NOW(), updated_at = NOW()
		         WHERE id = $3 AND org_id = $4`
		args = []interface{}{req.Status, userID, exposureID, orgID}
	case "mitigated", "false_positive", "accepted_risk":
		query = `UPDATE secret_exposure_events SET status = $1, resolved_by = $2, resolved_at = NOW(),
		         resolution_notes = $3, updated_at = NOW()
		         WHERE id = $4 AND org_id = $5`
		args = []interface{}{req.Status, userID, req.ResolutionNotes, exposureID, orgID}
	default:
		query = `UPDATE secret_exposure_events SET status = $1, updated_at = NOW() WHERE id = $2 AND org_id = $3`
		args = []interface{}{req.Status, exposureID, orgID}
	}

	result, err := h.db.Exec(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to update exposure", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update exposure"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Exposure not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Exposure updated"})
}

// getExposureSummary returns exposure statistics
func (h *Handler) getSecretExposureSummary(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var summary SecretExposureSummary
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT
			COALESCE(total_exposures, 0),
			COALESCE(active_exposures, 0),
			COALESCE(critical_exposures, 0),
			COALESCE(high_exposures, 0),
			COALESCE(exposures_last_7d, 0),
			COALESCE(exposures_last_30d, 0)
		FROM v_secret_exposure_summary
		WHERE org_id = $1`,
		orgID,
	).Scan(
		&summary.TotalExposures, &summary.ActiveExposures,
		&summary.CriticalExposures, &summary.HighExposures,
		&summary.ExposuresLast7d, &summary.ExposuresLast30d,
	)

	if err != nil {
		c.JSON(http.StatusOK, SecretExposureSummary{})
		return
	}

	c.JSON(http.StatusOK, summary)
}

// listRotationHistory returns secret rotation history
func (h *Handler) listRotationHistory(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	secretID := c.Query("secret_id")

	query := `
		SELECT h.id, h.org_id, h.secret_id, h.rotation_type, h.triggered_by_email,
		       h.status, h.started_at, h.completed_at, h.old_strength, h.new_strength,
		       h.error_message, h.restart_required, h.services_restarted, h.created_at,
		       s.name as secret_name
		FROM secret_rotation_history h
		LEFT JOIN secrets_inventory s ON s.id = h.secret_id
		WHERE h.org_id = $1`

	args := []interface{}{orgID}

	if secretID != "" {
		if id, err := uuid.Parse(secretID); err == nil {
			query += ` AND h.secret_id = $2`
			args = append(args, id)
		}
	}

	query += ` ORDER BY h.created_at DESC LIMIT 100`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to list rotation history", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list rotation history"})
		return
	}
	defer rows.Close()

	history := []SecretRotationHistory{}
	for rows.Next() {
		var h SecretRotationHistory
		err := rows.Scan(
			&h.ID, &h.OrgID, &h.SecretID, &h.RotationType, &h.TriggeredByEmail,
			&h.Status, &h.StartedAt, &h.CompletedAt, &h.OldStrength, &h.NewStrength,
			&h.ErrorMessage, &h.RestartRequired, &h.ServicesRestarted, &h.CreatedAt,
			&h.SecretName,
		)
		if err != nil {
			continue
		}
		history = append(history, h)
	}

	c.JSON(http.StatusOK, history)
}

// listRotationPolicies returns rotation policies
func (h *Handler) listRotationPolicies(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, name, description, max_age_days, min_strength,
		       require_unique, allow_reuse, reuse_history_count, auto_rotate,
		       rotation_cron, notify_before_days, notify_on_expiry, notify_on_exposure,
		       enabled, created_at, updated_at
		FROM secret_rotation_policies
		WHERE org_id = $1
		ORDER BY name`,
		orgID,
	)
	if err != nil {
		h.logger.Error("Failed to list rotation policies", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list policies"})
		return
	}
	defer rows.Close()

	policies := []SecretRotationPolicy{}
	for rows.Next() {
		var p SecretRotationPolicy
		err := rows.Scan(
			&p.ID, &p.OrgID, &p.Name, &p.Description, &p.MaxAgeDays, &p.MinStrength,
			&p.RequireUnique, &p.AllowReuse, &p.ReuseHistoryCount, &p.AutoRotate,
			&p.RotationCron, &p.NotifyBeforeDays, &p.NotifyOnExpiry, &p.NotifyOnExposure,
			&p.Enabled, &p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan policy", zap.Error(err))
			continue
		}
		policies = append(policies, p)
	}

	c.JSON(http.StatusOK, policies)
}

// createRotationPolicy creates a new rotation policy
func (h *Handler) createRotationPolicy(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req CreateRotationPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.MaxAgeDays == 0 {
		req.MaxAgeDays = 90
	}
	if req.MinStrength == "" {
		req.MinStrength = "moderate"
	}
	if req.NotifyBeforeDays == 0 {
		req.NotifyBeforeDays = 14
	}

	var policyID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO secret_rotation_policies (org_id, name, description, max_age_days,
		                                      min_strength, auto_rotate, rotation_cron,
		                                      notify_before_days, notify_on_expiry, notify_on_exposure)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id`,
		orgID, req.Name, req.Description, req.MaxAgeDays,
		req.MinStrength, req.AutoRotate, req.RotationCron,
		req.NotifyBeforeDays, req.NotifyOnExpiry, req.NotifyOnExposure,
	).Scan(&policyID)

	if err != nil {
		h.logger.Error("Failed to create rotation policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create policy"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": policyID})
}

// deleteRotationPolicy removes a rotation policy
func (h *Handler) deleteRotationPolicy(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	policyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(),
		`DELETE FROM secret_rotation_policies WHERE id = $1 AND org_id = $2`,
		policyID, orgID,
	)
	if err != nil {
		h.logger.Error("Failed to delete rotation policy", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policy"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted"})
}

// listSecretScans returns secret scan results
func (h *Handler) listSecretScans(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, agent_id, deployment_id, scan_type, scan_target, scanner,
		       status, started_at, completed_at, duration_seconds, secrets_found,
		       high_risk_findings, hardcoded_secrets, expired_secrets, weak_secrets,
		       files_scanned, containers_scanned, env_vars_scanned, error_message, created_at
		FROM secret_scan_results
		WHERE org_id = $1
		ORDER BY started_at DESC
		LIMIT 50`,
		orgID,
	)
	if err != nil {
		h.logger.Error("Failed to list secret scans", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list scans"})
		return
	}
	defer rows.Close()

	scans := []SecretScanResult{}
	for rows.Next() {
		var s SecretScanResult
		err := rows.Scan(
			&s.ID, &s.OrgID, &s.AgentID, &s.DeploymentID, &s.ScanType, &s.ScanTarget, &s.Scanner,
			&s.Status, &s.StartedAt, &s.CompletedAt, &s.DurationSeconds, &s.SecretsFound,
			&s.HighRiskFindings, &s.HardcodedSecrets, &s.ExpiredSecrets, &s.WeakSecrets,
			&s.FilesScanned, &s.ContainersScanned, &s.EnvVarsScanned, &s.ErrorMessage, &s.CreatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan secret scan result", zap.Error(err))
			continue
		}
		scans = append(scans, s)
	}

	c.JSON(http.StatusOK, scans)
}

// triggerSecretScan starts a new secret scan
func (h *Handler) triggerSecretScan(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req TriggerSecretScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.ScanType == "" {
		req.ScanType = "full"
	}

	var agentID, deploymentID *uuid.UUID
	if req.AgentID != nil {
		if id, err := uuid.Parse(*req.AgentID); err == nil {
			agentID = &id
		}
	}
	if req.DeploymentID != nil {
		if id, err := uuid.Parse(*req.DeploymentID); err == nil {
			deploymentID = &id
		}
	}

	// Create scan record with running status
	var scanID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO secret_scan_results (org_id, agent_id, deployment_id, scan_type, scan_target, status)
		VALUES ($1, $2, $3, $4, $5, 'running')
		RETURNING id`,
		orgID, agentID, deploymentID, req.ScanType, req.ScanTarget,
	).Scan(&scanID)

	if err != nil {
		h.logger.Error("Failed to create secret scan", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start scan"})
		return
	}

	// Get agents to scan
	var agentsToScan []uuid.UUID
	if agentID != nil {
		agentsToScan = append(agentsToScan, *agentID)
	} else {
		// Get all active agents for this org
		rows, err := h.db.Query(c.Request.Context(), `
			SELECT id FROM agents WHERE org_id = $1 AND status = 'active'`,
			orgID,
		)
		if err != nil {
			h.logger.Error("Failed to get agents", zap.Error(err))
		} else {
			defer rows.Close()
			for rows.Next() {
				var id uuid.UUID
				if err := rows.Scan(&id); err == nil {
					agentsToScan = append(agentsToScan, id)
				}
			}
		}
	}

	// Run scan asynchronously (use background context since request may complete)
	go func() {
		ctx := context.Background()
		var totalSecrets, successCount, errorCount int

		for _, agID := range agentsToScan {
			secrets, err := h.scanAgentSecrets(ctx, orgID, agID, scanID)
			if err != nil {
				h.logger.Error("Failed to scan agent secrets",
					zap.String("agent_id", agID.String()),
					zap.Error(err),
				)
				errorCount++
				continue
			}
			successCount++
			totalSecrets += len(secrets)
		}

		// Update scan status
		status := "completed"
		if errorCount > 0 && successCount == 0 {
			status = "failed"
		} else if errorCount > 0 {
			status = "partial"
		}

		_, err := h.db.Exec(ctx, `
			UPDATE secret_scan_results
			SET status = $1, completed_at = NOW(), secrets_found = $2
			WHERE id = $3`,
			status, totalSecrets, scanID,
		)
		if err != nil {
			h.logger.Error("Failed to update scan status", zap.Error(err))
		}
	}()

	c.JSON(http.StatusCreated, gin.H{"id": scanID, "status": "running", "message": "Secret scan started"})
}

// scanAgentSecrets sends a scan_secrets command to an agent and processes results
func (h *Handler) scanAgentSecrets(ctx context.Context, orgID, agentID, scanID uuid.UUID) ([]agentgrpc.ScannedSecret, error) {
	// Build the scan command
	cmdPayload, _ := json.Marshal(agentgrpc.DockerResourceCommand{
		Action: agentgrpc.DockerActionScanSecrets,
	})
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	// Send command to agent - use longer timeout for scanning many containers/paths
	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 3*time.Minute)
	if err != nil {
		return nil, err
	}

	// Parse response
	result, err := resp.GetCommandResult()
	if err != nil || result == nil || !result.Success {
		if result != nil {
			return nil, err
		}
		return nil, err
	}

	// Parse scanned secrets
	var secrets []agentgrpc.ScannedSecret
	if err := json.Unmarshal(result.Data, &secrets); err != nil {
		return nil, err
	}

	// Store secrets in database
	now := time.Now()
	for _, secret := range secrets {
		// Create location identifier - use env file path if available, otherwise container ID
		location := secret.ContainerID
		if secret.EnvFilePath != "" {
			location = secret.ContainerID + ":" + secret.EnvFilePath
		} else if location == "" {
			location = secret.ContainerName
		}

		_, err := h.db.Exec(ctx, `
			INSERT INTO secrets_inventory (
				org_id, agent_id, name, secret_type, source, location,
				container_id, container_name, classification, environment,
				is_sensitive, strength, auto_discovered, discovered_at, last_scanned_at
			) VALUES (
				$1, $2, $3, $4, $5, $6,
				$7, $8, 'internal', 'unknown',
				$9, $10, true, $11, $11
			)
			ON CONFLICT (org_id, name, source, location)
			DO UPDATE SET
				last_scanned_at = $11,
				strength = $10`,
			orgID, agentID, secret.Name, secret.SecretType, secret.Source, location,
			secret.ContainerID, secret.ContainerName,
			secret.IsSensitive, secret.Strength, now,
		)
		if err != nil {
			h.logger.Warn("Failed to insert secret",
				zap.String("name", secret.Name),
				zap.Error(err),
			)
		}
	}

	return secrets, nil
}

// ============================================================================
// Secret Migration Types
// ============================================================================

// SecretMigration represents a migration job
type SecretMigration struct {
	ID                     uuid.UUID       `json:"id"`
	OrgID                  uuid.UUID       `json:"org_id"`
	AgentID                uuid.UUID       `json:"agent_id"`
	ContainerID            string          `json:"container_id"`
	ContainerName          string          `json:"container_name"`
	SourceType             string          `json:"source_type"`
	SourcePath             *string         `json:"source_path,omitempty"`
	Status                 string          `json:"status"`
	ErrorMessage           *string         `json:"error_message,omitempty"`
	OriginalContainerConfig json.RawMessage `json:"original_container_config,omitempty"`
	NewContainerID         *string         `json:"new_container_id,omitempty"`
	CreatedAt              time.Time       `json:"created_at"`
	UpdatedAt              time.Time       `json:"updated_at"`
	CompletedAt            *time.Time      `json:"completed_at,omitempty"`
	// Aggregated fields
	TotalSecrets     int `json:"total_secrets,omitempty"`
	CompletedSecrets int `json:"completed_secrets,omitempty"`
	FailedSecrets    int `json:"failed_secrets,omitempty"`
}

// SecretMigrationItem represents an individual secret in a migration
type SecretMigrationItem struct {
	ID           uuid.UUID  `json:"id"`
	MigrationID  uuid.UUID  `json:"migration_id"`
	SecretName   string     `json:"secret_name"`
	SecretType   *string    `json:"secret_type,omitempty"`
	OldSource    string     `json:"old_source"`
	NewSource    string     `json:"new_source"`
	Status       string     `json:"status"`
	MountPath    *string    `json:"mount_path,omitempty"`
	ErrorMessage *string    `json:"error_message,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// CreateMigrationRequest represents a request to create a new migration
type CreateMigrationRequest struct {
	ContainerID   string `json:"container_id" binding:"required"`
	ContainerName string `json:"container_name" binding:"required"`
	SourceType    string `json:"source_type" binding:"required"`
	SourcePath    string `json:"source_path,omitempty"`
	Secrets       []struct {
		Name  string `json:"name" binding:"required"`
		Value string `json:"value" binding:"required"`
		Type  string `json:"type,omitempty"`
	} `json:"secrets" binding:"required,min=1"`
}

// SecretMount is used in agent communication for secret migration
type SecretMount struct {
	Name      string `json:"name"`
	Value     string `json:"value,omitempty"`
	MountPath string `json:"mount_path"`
}

// ============================================================================
// Secret Migration Handlers
// ============================================================================

// listSecretMigrations returns migrations for an agent
func (h *Handler) listSecretMigrations(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}

	// Verify agent belongs to org
	var agentOrgID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(),
		`SELECT org_id FROM agents WHERE id = $1`, agentID,
	).Scan(&agentOrgID)
	if err != nil || agentOrgID != orgID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, agent_id, container_id, container_name, source_type, source_path,
		       status, error_message, new_container_id, created_at, updated_at, completed_at,
		       total_secrets, completed_secrets, failed_secrets
		FROM v_secret_migrations_summary
		WHERE org_id = $1 AND agent_id = $2
		ORDER BY created_at DESC
		LIMIT 100`,
		orgID, agentID,
	)
	if err != nil {
		h.logger.Error("Failed to list migrations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list migrations"})
		return
	}
	defer rows.Close()

	migrations := []SecretMigration{}
	for rows.Next() {
		var m SecretMigration
		err := rows.Scan(
			&m.ID, &m.OrgID, &m.AgentID, &m.ContainerID, &m.ContainerName, &m.SourceType, &m.SourcePath,
			&m.Status, &m.ErrorMessage, &m.NewContainerID, &m.CreatedAt, &m.UpdatedAt, &m.CompletedAt,
			&m.TotalSecrets, &m.CompletedSecrets, &m.FailedSecrets,
		)
		if err != nil {
			h.logger.Error("Failed to scan migration", zap.Error(err))
			continue
		}
		migrations = append(migrations, m)
	}

	c.JSON(http.StatusOK, migrations)
}

// getMigration returns a specific migration with its items
func (h *Handler) getMigration(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	migrationIDStr := c.Param("migration_id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}

	migrationID, err := uuid.Parse(migrationIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid migration ID"})
		return
	}

	// Get migration
	var m SecretMigration
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, agent_id, container_id, container_name, source_type, source_path,
		       status, error_message, original_container_config, new_container_id,
		       created_at, updated_at, completed_at
		FROM secret_migrations
		WHERE id = $1 AND org_id = $2 AND agent_id = $3`,
		migrationID, orgID, agentID,
	).Scan(
		&m.ID, &m.OrgID, &m.AgentID, &m.ContainerID, &m.ContainerName, &m.SourceType, &m.SourcePath,
		&m.Status, &m.ErrorMessage, &m.OriginalContainerConfig, &m.NewContainerID,
		&m.CreatedAt, &m.UpdatedAt, &m.CompletedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Migration not found"})
		return
	}

	// Get migration items
	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, migration_id, secret_name, secret_type, old_source, new_source,
		       status, mount_path, error_message, created_at
		FROM secret_migration_items
		WHERE migration_id = $1
		ORDER BY created_at`,
		migrationID,
	)
	if err != nil {
		h.logger.Error("Failed to get migration items", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get migration details"})
		return
	}
	defer rows.Close()

	items := []SecretMigrationItem{}
	for rows.Next() {
		var item SecretMigrationItem
		err := rows.Scan(
			&item.ID, &item.MigrationID, &item.SecretName, &item.SecretType, &item.OldSource, &item.NewSource,
			&item.Status, &item.MountPath, &item.ErrorMessage, &item.CreatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan migration item", zap.Error(err))
			continue
		}
		items = append(items, item)
	}

	c.JSON(http.StatusOK, gin.H{
		"migration": m,
		"items":     items,
	})
}

// createMigration creates a new migration job and executes it
func (h *Handler) createMigration(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}

	// Verify agent belongs to org and is active
	var agentOrgID uuid.UUID
	var agentStatus string
	err = h.db.QueryRow(c.Request.Context(),
		`SELECT org_id, status FROM agents WHERE id = $1`, agentID,
	).Scan(&agentOrgID, &agentStatus)
	if err != nil || agentOrgID != orgID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
		return
	}
	if agentStatus != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Agent is not active"})
		return
	}

	var req CreateMigrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create migration record
	var migrationID uuid.UUID
	sourcePath := &req.SourcePath
	if req.SourcePath == "" {
		sourcePath = nil
	}

	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO secret_migrations (org_id, agent_id, container_id, container_name, source_type, source_path, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending')
		RETURNING id`,
		orgID, agentID, req.ContainerID, req.ContainerName, req.SourceType, sourcePath,
	).Scan(&migrationID)

	if err != nil {
		h.logger.Error("Failed to create migration", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create migration"})
		return
	}

	// Create migration items
	for _, secret := range req.Secrets {
		secretType := &secret.Type
		if secret.Type == "" {
			secretType = nil
		}
		_, err := h.db.Exec(c.Request.Context(), `
			INSERT INTO secret_migration_items (migration_id, secret_name, secret_type, old_source, new_source, status)
			VALUES ($1, $2, $3, $4, 'file_secret', 'pending')`,
			migrationID, secret.Name, secretType, req.SourceType,
		)
		if err != nil {
			h.logger.Error("Failed to create migration item",
				zap.String("secret_name", secret.Name),
				zap.Error(err),
			)
		}
	}

	// Execute migration asynchronously
	go h.executeMigration(context.Background(), orgID, agentID, migrationID, req)

	c.JSON(http.StatusCreated, gin.H{"id": migrationID, "status": "pending"})
}

// executeMigration runs the migration process
func (h *Handler) executeMigration(ctx context.Context, orgID, agentID, migrationID uuid.UUID, req CreateMigrationRequest) {
	// Update status to creating_secrets
	h.updateMigrationStatus(ctx, migrationID, "creating_secrets", nil)

	// Build secrets list for agent command
	secrets := make([]SecretMount, 0, len(req.Secrets))
	removeEnvVars := make([]string, 0, len(req.Secrets))
	for _, s := range req.Secrets {
		secrets = append(secrets, SecretMount{
			Name:  s.Name,
			Value: s.Value,
		})
		removeEnvVars = append(removeEnvVars, s.Name)
	}

	// Build migrate command
	migrateCmd := struct {
		Action        string        `json:"action"`
		ContainerID   string        `json:"container_id"`
		Secrets       []SecretMount `json:"secrets"`
		RemoveEnvVars []string      `json:"remove_env_vars"`
	}{
		Action:        "migrate_secrets",
		ContainerID:   req.ContainerID,
		Secrets:       secrets,
		RemoveEnvVars: removeEnvVars,
	}

	cmdPayload, _ := json.Marshal(migrateCmd)
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	// Update status to stopping_container
	h.updateMigrationStatus(ctx, migrationID, "stopping_container", nil)

	// Send command to agent (longer timeout for container operations)
	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 300*time.Second)
	if err != nil {
		h.logger.Error("Migration command failed", zap.Error(err))
		errMsg := err.Error()
		h.updateMigrationStatus(ctx, migrationID, "failed", &errMsg)
		return
	}

	result, err := resp.GetCommandResult()
	if err != nil || result == nil || !result.Success {
		errMsg := "Migration command returned error"
		if result != nil && result.Message != "" {
			errMsg = result.Message
		}
		h.logger.Error("Migration failed", zap.String("error", errMsg))
		h.updateMigrationStatus(ctx, migrationID, "failed", &errMsg)
		return
	}

	// Parse migration result
	var migrationResult struct {
		NewContainerID  string          `json:"new_container_id"`
		MountedSecrets  []SecretMount   `json:"mounted_secrets"`
		RemovedEnvVars  []string        `json:"removed_env_vars"`
		OriginalConfig  json.RawMessage `json:"original_config"`
	}
	if err := json.Unmarshal(result.Data, &migrationResult); err != nil {
		h.logger.Error("Failed to parse migration result", zap.Error(err))
		errMsg := "Failed to parse migration result"
		h.updateMigrationStatus(ctx, migrationID, "failed", &errMsg)
		return
	}

	// Store original config and new container ID
	h.db.Exec(ctx, `
		UPDATE secret_migrations
		SET original_container_config = $1, new_container_id = $2, status = 'starting_container'
		WHERE id = $3`,
		migrationResult.OriginalConfig, migrationResult.NewContainerID, migrationID,
	)

	// Update migration items with mount paths
	for _, ms := range migrationResult.MountedSecrets {
		h.db.Exec(ctx, `
			UPDATE secret_migration_items
			SET status = 'created', mount_path = $1
			WHERE migration_id = $2 AND secret_name = $3`,
			ms.MountPath, migrationID, ms.Name,
		)
	}

	// Update status to verifying
	h.updateMigrationStatus(ctx, migrationID, "verifying", nil)

	// Send verify command
	expectedSecrets := make([]string, 0, len(req.Secrets))
	for _, s := range req.Secrets {
		expectedSecrets = append(expectedSecrets, s.Name)
	}

	verifyCmd := struct {
		Action          string   `json:"action"`
		ContainerID     string   `json:"container_id"`
		ExpectedSecrets []string `json:"expected_secrets"`
	}{
		Action:          "verify_migration",
		ContainerID:     migrationResult.NewContainerID,
		ExpectedSecrets: expectedSecrets,
	}

	verifyCmdPayload, _ := json.Marshal(verifyCmd)
	verifyMsg := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   verifyCmdPayload,
	}

	verifyResp, err := agentgrpc.SendCommand(agentID.String(), verifyMsg, 60*time.Second)
	if err != nil {
		h.logger.Warn("Verification command failed, but migration may still be successful", zap.Error(err))
	} else {
		verifyResult, _ := verifyResp.GetCommandResult()
		if verifyResult != nil && verifyResult.Success {
			// Update items as verified
			for _, s := range expectedSecrets {
				h.db.Exec(ctx, `
					UPDATE secret_migration_items
					SET status = 'completed'
					WHERE migration_id = $1 AND secret_name = $2`,
					migrationID, s,
				)
			}
		}
	}

	// Mark migration as completed
	h.db.Exec(ctx, `
		UPDATE secret_migrations
		SET status = 'completed', completed_at = NOW()
		WHERE id = $1`,
		migrationID,
	)

	// Update secrets_inventory to reflect new source
	for _, s := range req.Secrets {
		h.db.Exec(ctx, `
			UPDATE secrets_inventory
			SET source = 'file_secret', location = $1, updated_at = NOW()
			WHERE org_id = $2 AND name = $3 AND container_id = $4`,
			"/run/secrets/"+s.Name, orgID, s.Name, req.ContainerID,
		)
	}

	h.logger.Info("Migration completed successfully",
		zap.String("migration_id", migrationID.String()),
		zap.String("new_container_id", migrationResult.NewContainerID),
	)
}

// rollbackMigration triggers a rollback of a migration
func (h *Handler) rollbackMigration(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	agentIDStr := c.Param("id")
	migrationIDStr := c.Param("migration_id")

	agentID, err := uuid.Parse(agentIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}

	migrationID, err := uuid.Parse(migrationIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid migration ID"})
		return
	}

	// Get migration details
	var m SecretMigration
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, agent_id, container_id, container_name, source_type, source_path,
		       status, original_container_config, new_container_id
		FROM secret_migrations
		WHERE id = $1 AND org_id = $2 AND agent_id = $3`,
		migrationID, orgID, agentID,
	).Scan(
		&m.ID, &m.OrgID, &m.AgentID, &m.ContainerID, &m.ContainerName, &m.SourceType, &m.SourcePath,
		&m.Status, &m.OriginalContainerConfig, &m.NewContainerID,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Migration not found"})
		return
	}

	// Check if migration can be rolled back
	if m.Status == "pending" || m.Status == "rolled_back" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Migration cannot be rolled back in current status"})
		return
	}

	if m.OriginalContainerConfig == nil || m.NewContainerID == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Migration does not have rollback data"})
		return
	}

	// Get created secrets for cleanup
	rows, err := h.db.Query(c.Request.Context(), `
		SELECT secret_name FROM secret_migration_items WHERE migration_id = $1`,
		migrationID,
	)
	if err != nil {
		h.logger.Error("Failed to get migration items", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get migration details"})
		return
	}
	defer rows.Close()

	createdSecrets := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			createdSecrets = append(createdSecrets, name)
		}
	}

	// Build rollback command
	rollbackCmd := struct {
		Action         string          `json:"action"`
		ContainerID    string          `json:"container_id"`
		OriginalConfig json.RawMessage `json:"original_config"`
		CreatedSecrets []string        `json:"created_secrets"`
	}{
		Action:         "rollback_migration",
		ContainerID:    *m.NewContainerID,
		OriginalConfig: m.OriginalContainerConfig,
		CreatedSecrets: createdSecrets,
	}

	cmdPayload, _ := json.Marshal(rollbackCmd)
	cmd := &agentgrpc.BackendMessage{
		RequestId: uuid.New().String(),
		Type:      "docker",
		Command:   cmdPayload,
	}

	// Send rollback command
	resp, err := agentgrpc.SendCommand(agentID.String(), cmd, 300*time.Second)
	if err != nil {
		h.logger.Error("Rollback command failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Rollback command failed: " + err.Error()})
		return
	}

	result, err := resp.GetCommandResult()
	if err != nil || result == nil || !result.Success {
		errMsg := "Rollback failed"
		if result != nil && result.Message != "" {
			errMsg = result.Message
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": errMsg})
		return
	}

	// Update migration status
	h.db.Exec(c.Request.Context(), `
		UPDATE secret_migrations
		SET status = 'rolled_back', updated_at = NOW()
		WHERE id = $1`,
		migrationID,
	)

	// Update migration items status
	h.db.Exec(c.Request.Context(), `
		UPDATE secret_migration_items
		SET status = 'pending'
		WHERE migration_id = $1`,
		migrationID,
	)

	// Restore secrets_inventory source
	for _, secretName := range createdSecrets {
		h.db.Exec(c.Request.Context(), `
			UPDATE secrets_inventory
			SET source = $1, updated_at = NOW()
			WHERE org_id = $2 AND name = $3 AND container_id = $4`,
			m.SourceType, orgID, secretName, m.ContainerID,
		)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Migration rolled back successfully"})
}

// updateMigrationStatus updates the status of a migration
func (h *Handler) updateMigrationStatus(ctx context.Context, migrationID uuid.UUID, status string, errorMsg *string) {
	if errorMsg != nil {
		h.db.Exec(ctx, `
			UPDATE secret_migrations
			SET status = $1, error_message = $2, updated_at = NOW()
			WHERE id = $3`,
			status, *errorMsg, migrationID,
		)
	} else {
		h.db.Exec(ctx, `
			UPDATE secret_migrations
			SET status = $1, updated_at = NOW()
			WHERE id = $2`,
			status, migrationID,
		)
	}
}
