package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Runtime Security Types

type DriftEvent struct {
	ID              uuid.UUID              `json:"id"`
	OrgID           uuid.UUID              `json:"org_id"`
	AgentID         uuid.UUID              `json:"agent_id"`
	DeploymentID    uuid.UUID              `json:"deployment_id"`
	ContainerID     string                 `json:"container_id"`
	ContainerName   string                 `json:"container_name"`
	DriftType       string                 `json:"drift_type"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	ExpectedState   map[string]interface{} `json:"expected_state"`
	ActualState     map[string]interface{} `json:"actual_state"`
	Diff            map[string]interface{} `json:"diff,omitempty"`
	Resolved        bool                   `json:"resolved"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy      *uuid.UUID             `json:"resolved_by,omitempty"`
	ResolutionNotes *string                `json:"resolution_notes,omitempty"`
	DetectedAt      time.Time              `json:"detected_at"`
	CreatedAt       time.Time              `json:"created_at"`
}

type BehavioralAnomaly struct {
	ID              uuid.UUID              `json:"id"`
	OrgID           uuid.UUID              `json:"org_id"`
	AgentID         uuid.UUID              `json:"agent_id"`
	DeploymentID    *uuid.UUID             `json:"deployment_id,omitempty"`
	ContainerID     *string                `json:"container_id,omitempty"`
	ContainerName   *string                `json:"container_name,omitempty"`
	AnomalyType     string                 `json:"anomaly_type"`
	Severity        string                 `json:"severity"`
	Description     string                 `json:"description"`
	Metrics         map[string]interface{} `json:"metrics"`
	Threshold       map[string]interface{} `json:"threshold"`
	Resolved        bool                   `json:"resolved"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy      *uuid.UUID             `json:"resolved_by,omitempty"`
	ResolutionNotes *string                `json:"resolution_notes,omitempty"`
	DetectedAt      time.Time              `json:"detected_at"`
	FirstSeenAt     time.Time              `json:"first_seen_at"`
	OccurrenceCount int                    `json:"occurrence_count"`
	CreatedAt       time.Time              `json:"created_at"`
}

type RuntimeSecurityConfig struct {
	ID                            uuid.UUID `json:"id"`
	OrgID                         uuid.UUID `json:"org_id"`
	DriftDetectionEnabled         bool      `json:"drift_detection_enabled"`
	BehavioralMonitoringEnabled   bool      `json:"behavioral_monitoring_enabled"`
	AutoResolveInfoDrift          bool      `json:"auto_resolve_info_drift"`
	AutoResolveAfterHours         int       `json:"auto_resolve_after_hours"`
	AlertOnCriticalDrift          bool      `json:"alert_on_critical_drift"`
	AlertOnHighDrift              bool      `json:"alert_on_high_drift"`
	AlertOnCriticalAnomaly        bool      `json:"alert_on_critical_anomaly"`
	AlertOnHighAnomaly            bool      `json:"alert_on_high_anomaly"`
	CrashLoopThreshold            int       `json:"crash_loop_threshold"`
	CrashLoopWindowMinutes        int       `json:"crash_loop_window_minutes"`
	LogVolumeSpikeMultiplier      float64   `json:"log_volume_spike_multiplier"`
	ErrorRateSpikeMultiplier      float64   `json:"error_rate_spike_multiplier"`
	CPUExhaustionThresholdPercent int       `json:"cpu_exhaustion_threshold_percent"`
	MemExhaustionThresholdPercent int       `json:"mem_exhaustion_threshold_percent"`
	NetworkSpikeMultiplier        float64   `json:"network_spike_multiplier"`
	ProcessSpawnThreshold         int       `json:"process_spawn_threshold"`
	CreatedAt                     time.Time `json:"created_at"`
	UpdatedAt                     time.Time `json:"updated_at"`
}

type RuntimeSecurityPosture struct {
	OverallStatus        string                 `json:"overall_status"`
	DriftEventsLast24h   int                    `json:"drift_events_last_24h"`
	AnomaliesLast24h     int                    `json:"anomalies_last_24h"`
	UnresolvedDrift      int                    `json:"unresolved_drift"`
	UnresolvedAnomalies  int                    `json:"unresolved_anomalies"`
	CriticalDrift        int                    `json:"critical_drift"`
	CriticalAnomalies    int                    `json:"critical_anomalies"`
	DriftByType          map[string]int         `json:"drift_by_type"`
	AnomalyByType        map[string]int         `json:"anomaly_by_type"`
	TopAffectedContainers []ContainerDriftSummary `json:"top_affected_containers"`
	RecentEvents         []interface{}          `json:"recent_events"`
}

type ContainerDriftSummary struct {
	ContainerName  string `json:"container_name"`
	DeploymentID   uuid.UUID `json:"deployment_id"`
	TotalDrift     int    `json:"total_drift"`
	UnresolvedDrift int   `json:"unresolved_drift"`
	LastDriftAt    time.Time `json:"last_drift_at"`
}

// GET /api/v1/runtime/drift-events
func (h *Handler) listDriftEvents(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Query parameters
	severity := c.Query("severity")
	driftType := c.Query("drift_type")
	resolved := c.Query("resolved")
	containerName := c.Query("container_name")
	limit := c.DefaultQuery("limit", "100")
	offset := c.DefaultQuery("offset", "0")

	query := `
		SELECT
			id, org_id, agent_id, deployment_id, container_id, container_name,
			drift_type, severity, description, expected_state, actual_state, diff,
			resolved, resolved_at, resolved_by, resolution_notes, detected_at, created_at
		FROM drift_events
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argCount := 1

	if severity != "" {
		argCount++
		query += ` AND severity = $` + string(rune(argCount+48))
		args = append(args, severity)
	}
	if driftType != "" {
		argCount++
		query += ` AND drift_type = $` + string(rune(argCount+48))
		args = append(args, driftType)
	}
	if resolved != "" {
		argCount++
		resolvedBool := resolved == "true"
		query += ` AND resolved = $` + string(rune(argCount+48))
		args = append(args, resolvedBool)
	}
	if containerName != "" {
		argCount++
		query += ` AND container_name ILIKE $` + string(rune(argCount+48))
		args = append(args, "%"+containerName+"%")
	}

	query += ` ORDER BY detected_at DESC LIMIT $` + string(rune(argCount+49)) + ` OFFSET $` + string(rune(argCount+50))
	args = append(args, limit, offset)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch drift events"})
		return
	}
	defer rows.Close()

	var events []DriftEvent
	for rows.Next() {
		var event DriftEvent
		err := rows.Scan(
			&event.ID, &event.OrgID, &event.AgentID, &event.DeploymentID,
			&event.ContainerID, &event.ContainerName, &event.DriftType,
			&event.Severity, &event.Description, &event.ExpectedState,
			&event.ActualState, &event.Diff, &event.Resolved,
			&event.ResolvedAt, &event.ResolvedBy, &event.ResolutionNotes,
			&event.DetectedAt, &event.CreatedAt,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse drift event"})
			return
		}
		events = append(events, event)
	}

	// Get total count
	countQuery := `SELECT COUNT(*) FROM drift_events WHERE org_id = $1`
	var total int
	err = h.db.QueryRow(c.Request.Context(), countQuery, orgID).Scan(&total)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count drift events"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"drift_events": events,
		"total":        total,
	})
}

// GET /api/v1/runtime/drift-events/:id
func (h *Handler) getDriftEvent(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	eventID := c.Param("id")

	eventUUID, err := uuid.Parse(eventID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid event ID"})
		return
	}

	query := `
		SELECT
			id, org_id, agent_id, deployment_id, container_id, container_name,
			drift_type, severity, description, expected_state, actual_state, diff,
			resolved, resolved_at, resolved_by, resolution_notes, detected_at, created_at
		FROM drift_events
		WHERE id = $1 AND org_id = $2
	`

	var event DriftEvent
	err = h.db.QueryRow(c.Request.Context(), query, eventUUID, orgID).Scan(
		&event.ID, &event.OrgID, &event.AgentID, &event.DeploymentID,
		&event.ContainerID, &event.ContainerName, &event.DriftType,
		&event.Severity, &event.Description, &event.ExpectedState,
		&event.ActualState, &event.Diff, &event.Resolved,
		&event.ResolvedAt, &event.ResolvedBy, &event.ResolutionNotes,
		&event.DetectedAt, &event.CreatedAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Drift event not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch drift event"})
		return
	}

	c.JSON(http.StatusOK, event)
}

// POST /api/v1/runtime/drift-events/:id/resolve
func (h *Handler) resolveDriftEvent(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	eventID := c.Param("id")

	eventUUID, err := uuid.Parse(eventID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid event ID"})
		return
	}

	var req struct {
		Notes string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	query := `
		UPDATE drift_events
		SET
			resolved = true,
			resolved_at = NOW(),
			resolved_by = $1,
			resolution_notes = $2
		WHERE id = $3 AND org_id = $4 AND resolved = false
		RETURNING id
	`

	var returnedID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), query, userID, req.Notes, eventUUID, orgID).Scan(&returnedID)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Drift event not found or already resolved"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve drift event"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Drift event resolved successfully"})
}

// GET /api/v1/runtime/anomalies
func (h *Handler) listBehavioralAnomalies(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Query parameters
	severity := c.Query("severity")
	anomalyType := c.Query("anomaly_type")
	resolved := c.Query("resolved")
	containerName := c.Query("container_name")
	limit := c.DefaultQuery("limit", "100")
	offset := c.DefaultQuery("offset", "0")

	query := `
		SELECT
			id, org_id, agent_id, deployment_id, container_id, container_name,
			anomaly_type, severity, description, metrics, threshold,
			resolved, resolved_at, resolved_by, resolution_notes,
			detected_at, first_seen_at, occurrence_count, created_at
		FROM behavioral_anomalies
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argCount := 1

	if severity != "" {
		argCount++
		query += ` AND severity = $` + string(rune(argCount+48))
		args = append(args, severity)
	}
	if anomalyType != "" {
		argCount++
		query += ` AND anomaly_type = $` + string(rune(argCount+48))
		args = append(args, anomalyType)
	}
	if resolved != "" {
		argCount++
		resolvedBool := resolved == "true"
		query += ` AND resolved = $` + string(rune(argCount+48))
		args = append(args, resolvedBool)
	}
	if containerName != "" {
		argCount++
		query += ` AND container_name ILIKE $` + string(rune(argCount+48))
		args = append(args, "%"+containerName+"%")
	}

	query += ` ORDER BY detected_at DESC LIMIT $` + string(rune(argCount+49)) + ` OFFSET $` + string(rune(argCount+50))
	args = append(args, limit, offset)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch behavioral anomalies"})
		return
	}
	defer rows.Close()

	var anomalies []BehavioralAnomaly
	for rows.Next() {
		var anomaly BehavioralAnomaly
		err := rows.Scan(
			&anomaly.ID, &anomaly.OrgID, &anomaly.AgentID, &anomaly.DeploymentID,
			&anomaly.ContainerID, &anomaly.ContainerName, &anomaly.AnomalyType,
			&anomaly.Severity, &anomaly.Description, &anomaly.Metrics,
			&anomaly.Threshold, &anomaly.Resolved, &anomaly.ResolvedAt,
			&anomaly.ResolvedBy, &anomaly.ResolutionNotes, &anomaly.DetectedAt,
			&anomaly.FirstSeenAt, &anomaly.OccurrenceCount, &anomaly.CreatedAt,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse behavioral anomaly"})
			return
		}
		anomalies = append(anomalies, anomaly)
	}

	// Get total count
	countQuery := `SELECT COUNT(*) FROM behavioral_anomalies WHERE org_id = $1`
	var total int
	err = h.db.QueryRow(c.Request.Context(), countQuery, orgID).Scan(&total)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count behavioral anomalies"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"anomalies": anomalies,
		"total":     total,
	})
}

// GET /api/v1/runtime/anomalies/:id
func (h *Handler) getBehavioralAnomaly(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	anomalyID := c.Param("id")

	anomalyUUID, err := uuid.Parse(anomalyID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid anomaly ID"})
		return
	}

	query := `
		SELECT
			id, org_id, agent_id, deployment_id, container_id, container_name,
			anomaly_type, severity, description, metrics, threshold,
			resolved, resolved_at, resolved_by, resolution_notes,
			detected_at, first_seen_at, occurrence_count, created_at
		FROM behavioral_anomalies
		WHERE id = $1 AND org_id = $2
	`

	var anomaly BehavioralAnomaly
	err = h.db.QueryRow(c.Request.Context(), query, anomalyUUID, orgID).Scan(
		&anomaly.ID, &anomaly.OrgID, &anomaly.AgentID, &anomaly.DeploymentID,
		&anomaly.ContainerID, &anomaly.ContainerName, &anomaly.AnomalyType,
		&anomaly.Severity, &anomaly.Description, &anomaly.Metrics,
		&anomaly.Threshold, &anomaly.Resolved, &anomaly.ResolvedAt,
		&anomaly.ResolvedBy, &anomaly.ResolutionNotes, &anomaly.DetectedAt,
		&anomaly.FirstSeenAt, &anomaly.OccurrenceCount, &anomaly.CreatedAt,
	)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Behavioral anomaly not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch behavioral anomaly"})
		return
	}

	c.JSON(http.StatusOK, anomaly)
}

// POST /api/v1/runtime/anomalies/:id/resolve
func (h *Handler) resolveBehavioralAnomaly(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	anomalyID := c.Param("id")

	anomalyUUID, err := uuid.Parse(anomalyID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid anomaly ID"})
		return
	}

	var req struct {
		Notes string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	query := `
		UPDATE behavioral_anomalies
		SET
			resolved = true,
			resolved_at = NOW(),
			resolved_by = $1,
			resolution_notes = $2
		WHERE id = $3 AND org_id = $4 AND resolved = false
		RETURNING id
	`

	var returnedID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), query, userID, req.Notes, anomalyUUID, orgID).Scan(&returnedID)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Behavioral anomaly not found or already resolved"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve behavioral anomaly"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Behavioral anomaly resolved successfully"})
}

// GET /api/v1/runtime/config
func (h *Handler) getRuntimeSecurityConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT
			id, org_id, drift_detection_enabled, behavioral_monitoring_enabled,
			auto_resolve_info_drift, auto_resolve_after_hours,
			alert_on_critical_drift, alert_on_high_drift,
			alert_on_critical_anomaly, alert_on_high_anomaly,
			crash_loop_threshold, crash_loop_window_minutes,
			log_volume_spike_multiplier, error_rate_spike_multiplier,
			cpu_exhaustion_threshold_percent, mem_exhaustion_threshold_percent,
			network_spike_multiplier, process_spawn_threshold,
			created_at, updated_at
		FROM runtime_security_config
		WHERE org_id = $1
	`

	var config RuntimeSecurityConfig
	err := h.db.QueryRow(c.Request.Context(), query, orgID).Scan(
		&config.ID, &config.OrgID, &config.DriftDetectionEnabled,
		&config.BehavioralMonitoringEnabled, &config.AutoResolveInfoDrift,
		&config.AutoResolveAfterHours, &config.AlertOnCriticalDrift,
		&config.AlertOnHighDrift, &config.AlertOnCriticalAnomaly,
		&config.AlertOnHighAnomaly, &config.CrashLoopThreshold,
		&config.CrashLoopWindowMinutes, &config.LogVolumeSpikeMultiplier,
		&config.ErrorRateSpikeMultiplier, &config.CPUExhaustionThresholdPercent,
		&config.MemExhaustionThresholdPercent, &config.NetworkSpikeMultiplier,
		&config.ProcessSpawnThreshold, &config.CreatedAt, &config.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// Initialize config if it doesn't exist
		initQuery := `SELECT initialize_runtime_security_config($1)`
		_, err = h.db.Exec(c.Request.Context(), initQuery, orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize runtime security config"})
			return
		}

		// Retry fetching
		err = h.db.QueryRow(c.Request.Context(), query, orgID).Scan(
			&config.ID, &config.OrgID, &config.DriftDetectionEnabled,
			&config.BehavioralMonitoringEnabled, &config.AutoResolveInfoDrift,
			&config.AutoResolveAfterHours, &config.AlertOnCriticalDrift,
			&config.AlertOnHighDrift, &config.AlertOnCriticalAnomaly,
			&config.AlertOnHighAnomaly, &config.CrashLoopThreshold,
			&config.CrashLoopWindowMinutes, &config.LogVolumeSpikeMultiplier,
			&config.ErrorRateSpikeMultiplier, &config.CPUExhaustionThresholdPercent,
			&config.MemExhaustionThresholdPercent, &config.NetworkSpikeMultiplier,
			&config.ProcessSpawnThreshold, &config.CreatedAt, &config.UpdatedAt,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch runtime security config"})
			return
		}
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch runtime security config"})
		return
	}

	c.JSON(http.StatusOK, config)
}

// PUT /api/v1/runtime/config
func (h *Handler) updateRuntimeSecurityConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req RuntimeSecurityConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}

	query := `
		UPDATE runtime_security_config
		SET
			drift_detection_enabled = $1,
			behavioral_monitoring_enabled = $2,
			auto_resolve_info_drift = $3,
			auto_resolve_after_hours = $4,
			alert_on_critical_drift = $5,
			alert_on_high_drift = $6,
			alert_on_critical_anomaly = $7,
			alert_on_high_anomaly = $8,
			crash_loop_threshold = $9,
			crash_loop_window_minutes = $10,
			log_volume_spike_multiplier = $11,
			error_rate_spike_multiplier = $12,
			cpu_exhaustion_threshold_percent = $13,
			mem_exhaustion_threshold_percent = $14,
			network_spike_multiplier = $15,
			process_spawn_threshold = $16,
			updated_at = NOW()
		WHERE org_id = $17
		RETURNING id
	`

	var returnedID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), query,
		req.DriftDetectionEnabled, req.BehavioralMonitoringEnabled,
		req.AutoResolveInfoDrift, req.AutoResolveAfterHours,
		req.AlertOnCriticalDrift, req.AlertOnHighDrift,
		req.AlertOnCriticalAnomaly, req.AlertOnHighAnomaly,
		req.CrashLoopThreshold, req.CrashLoopWindowMinutes,
		req.LogVolumeSpikeMultiplier, req.ErrorRateSpikeMultiplier,
		req.CPUExhaustionThresholdPercent, req.MemExhaustionThresholdPercent,
		req.NetworkSpikeMultiplier, req.ProcessSpawnThreshold,
		orgID,
	).Scan(&returnedID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update runtime security config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Runtime security config updated successfully"})
}

// GET /api/v1/runtime/posture
func (h *Handler) getRuntimeSecurityPosture(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Use the view for overall posture
	postureQuery := `SELECT * FROM v_runtime_security_posture WHERE org_id = $1`

	var posture RuntimeSecurityPosture
	var overallStatus string
	var driftLast24h, anomaliesLast24h, unresolvedDrift, unresolvedAnomalies int
	var criticalDrift, criticalAnomalies int

	err := h.db.QueryRow(c.Request.Context(), postureQuery, orgID).Scan(
		&orgID, &overallStatus, &driftLast24h, &anomaliesLast24h,
		&unresolvedDrift, &unresolvedAnomalies, &criticalDrift, &criticalAnomalies,
	)

	if err != nil && err != sql.ErrNoRows {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch runtime security posture"})
		return
	}

	posture.OverallStatus = overallStatus
	posture.DriftEventsLast24h = driftLast24h
	posture.AnomaliesLast24h = anomaliesLast24h
	posture.UnresolvedDrift = unresolvedDrift
	posture.UnresolvedAnomalies = unresolvedAnomalies
	posture.CriticalDrift = criticalDrift
	posture.CriticalAnomalies = criticalAnomalies

	// Get drift by type
	driftByTypeQuery := `
		SELECT drift_type, COUNT(*)
		FROM drift_events
		WHERE org_id = $1 AND detected_at > NOW() - INTERVAL '24 hours'
		GROUP BY drift_type
	`
	rows, err := h.db.Query(c.Request.Context(), driftByTypeQuery, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch drift by type"})
		return
	}
	defer rows.Close()

	driftByType := make(map[string]int)
	for rows.Next() {
		var driftType string
		var count int
		if err := rows.Scan(&driftType, &count); err != nil {
			continue
		}
		driftByType[driftType] = count
	}
	posture.DriftByType = driftByType

	// Get anomaly by type
	anomalyByTypeQuery := `
		SELECT anomaly_type, COUNT(*)
		FROM behavioral_anomalies
		WHERE org_id = $1 AND detected_at > NOW() - INTERVAL '24 hours'
		GROUP BY anomaly_type
	`
	rows, err = h.db.Query(c.Request.Context(), anomalyByTypeQuery, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch anomaly by type"})
		return
	}
	defer rows.Close()

	anomalyByType := make(map[string]int)
	for rows.Next() {
		var anomalyType string
		var count int
		if err := rows.Scan(&anomalyType, &count); err != nil {
			continue
		}
		anomalyByType[anomalyType] = count
	}
	posture.AnomalyByType = anomalyByType

	// Get top affected containers
	topContainersQuery := `
		SELECT * FROM v_container_drift_summary
		WHERE org_id = $1
		ORDER BY total_drift DESC
		LIMIT 5
	`
	rows, err = h.db.Query(c.Request.Context(), topContainersQuery, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch top affected containers"})
		return
	}
	defer rows.Close()

	var topContainers []ContainerDriftSummary
	for rows.Next() {
		var summary ContainerDriftSummary
		var orgID uuid.UUID
		if err := rows.Scan(&orgID, &summary.ContainerName, &summary.DeploymentID, &summary.TotalDrift, &summary.UnresolvedDrift, &summary.LastDriftAt); err != nil {
			continue
		}
		topContainers = append(topContainers, summary)
	}
	posture.TopAffectedContainers = topContainers

	// Get recent events (combined drift + anomalies)
	recentEventsQuery := `
		(SELECT 'drift' as type, id, container_name, drift_type as event_type, severity, detected_at
		 FROM drift_events
		 WHERE org_id = $1 AND detected_at > NOW() - INTERVAL '7 days')
		UNION ALL
		(SELECT 'anomaly' as type, id, container_name, anomaly_type as event_type, severity, detected_at
		 FROM behavioral_anomalies
		 WHERE org_id = $1 AND detected_at > NOW() - INTERVAL '7 days')
		ORDER BY detected_at DESC
		LIMIT 20
	`
	rows, err = h.db.Query(c.Request.Context(), recentEventsQuery, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch recent events"})
		return
	}
	defer rows.Close()

	var recentEvents []interface{}
	for rows.Next() {
		var eventType, id, containerName, eventTypeName, severity string
		var detectedAt time.Time
		if err := rows.Scan(&eventType, &id, &containerName, &eventTypeName, &severity, &detectedAt); err != nil {
			continue
		}
		recentEvents = append(recentEvents, map[string]interface{}{
			"type":           eventType,
			"id":             id,
			"container_name": containerName,
			"event_type":     eventTypeName,
			"severity":       severity,
			"detected_at":    detectedAt,
		})
	}
	posture.RecentEvents = recentEvents

	c.JSON(http.StatusOK, posture)
}
