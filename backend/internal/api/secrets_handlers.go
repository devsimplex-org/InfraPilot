package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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
		h.logger.Error("Failed to list secrets", "error", err)
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
			h.logger.Error("Failed to scan secret", "error", err)
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
		h.logger.Error("Failed to create secret", "error", err)
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
		h.logger.Error("Failed to delete secret", "error", err)
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
		h.logger.Error("Failed to list secret exposures", "error", err)
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
			h.logger.Error("Failed to scan exposure", "error", err)
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
		h.logger.Error("Failed to update exposure", "error", err)
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
		h.logger.Error("Failed to list rotation history", "error", err)
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
		h.logger.Error("Failed to list rotation policies", "error", err)
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
			h.logger.Error("Failed to scan policy", "error", err)
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
		h.logger.Error("Failed to create rotation policy", "error", err)
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
		h.logger.Error("Failed to delete rotation policy", "error", err)
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
		h.logger.Error("Failed to list secret scans", "error", err)
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
			h.logger.Error("Failed to scan secret scan result", "error", err)
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

	var scanID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO secret_scan_results (org_id, agent_id, deployment_id, scan_type, scan_target, status)
		VALUES ($1, $2, $3, $4, $5, 'running')
		RETURNING id`,
		orgID, agentID, deploymentID, req.ScanType, req.ScanTarget,
	).Scan(&scanID)

	if err != nil {
		h.logger.Error("Failed to create secret scan", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start scan"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": scanID, "status": "running", "message": "Secret scan started"})
}
