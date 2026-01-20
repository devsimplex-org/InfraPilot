package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ============================================================================
// Types
// ============================================================================

// BackupJob represents a backup job execution
type BackupJob struct {
	ID              uuid.UUID  `json:"id"`
	OrgID           uuid.UUID  `json:"org_id"`
	PolicyID        *uuid.UUID `json:"policy_id,omitempty"`
	DatabaseID      *uuid.UUID `json:"database_id,omitempty"`
	JobType         string     `json:"job_type"`
	TriggeredBy     *string    `json:"triggered_by,omitempty"`
	Status          string     `json:"status"`
	ProgressPercent int        `json:"progress_percent"`
	CurrentStep     *string    `json:"current_step,omitempty"`
	ScheduledAt     *time.Time `json:"scheduled_at,omitempty"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	DurationSeconds *int       `json:"duration_seconds,omitempty"`
	BackupID        *uuid.UUID `json:"backup_id,omitempty"`
	ErrorMessage    *string    `json:"error_message,omitempty"`
	ErrorCode       *string    `json:"error_code,omitempty"`
	RetryCount      int        `json:"retry_count"`
	MaxRetries      int        `json:"max_retries"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	// Joined fields
	DatabaseName *string `json:"database_name,omitempty"`
	PolicyName   *string `json:"policy_name,omitempty"`
}

// RestoreOperation represents a backup restoration
type RestoreOperation struct {
	ID                uuid.UUID  `json:"id"`
	OrgID             uuid.UUID  `json:"org_id"`
	BackupID          uuid.UUID  `json:"backup_id"`
	SourceDatabaseID  uuid.UUID  `json:"source_database_id"`
	TargetType        string     `json:"target_type"`
	TargetDatabaseID  *uuid.UUID `json:"target_database_id,omitempty"`
	TargetName        *string    `json:"target_name,omitempty"`
	TargetHost        *string    `json:"target_host,omitempty"`
	TargetPort        *int       `json:"target_port,omitempty"`
	RestoreType       string     `json:"restore_type"`
	PointInTimeTarget *time.Time `json:"point_in_time_target,omitempty"`
	TriggeredByEmail  *string    `json:"triggered_by_email,omitempty"`
	Reason            *string    `json:"reason,omitempty"`
	Status            string     `json:"status"`
	ProgressPercent   int        `json:"progress_percent"`
	CurrentStep       *string    `json:"current_step,omitempty"`
	StartedAt         *time.Time `json:"started_at,omitempty"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	DurationSeconds   *int       `json:"duration_seconds,omitempty"`
	RowsRestored      *int64     `json:"rows_restored,omitempty"`
	TablesRestored    *int       `json:"tables_restored,omitempty"`
	SizeRestoredBytes *int64     `json:"size_restored_bytes,omitempty"`
	ErrorMessage      *string    `json:"error_message,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	// Joined fields
	SourceDatabaseName *string `json:"source_database_name,omitempty"`
	BackupName         *string `json:"backup_name,omitempty"`
}

// RecoveryTest represents a DR test
type RecoveryTest struct {
	ID                  uuid.UUID  `json:"id"`
	OrgID               uuid.UUID  `json:"org_id"`
	DatabaseID          uuid.UUID  `json:"database_id"`
	BackupID            *uuid.UUID `json:"backup_id,omitempty"`
	TestType            string     `json:"test_type"`
	TestName            *string    `json:"test_name,omitempty"`
	TestScenario        *string    `json:"test_scenario,omitempty"`
	TriggeredByEmail    *string    `json:"triggered_by_email,omitempty"`
	Status              string     `json:"status"`
	ScheduledAt         *time.Time `json:"scheduled_at,omitempty"`
	StartedAt           *time.Time `json:"started_at,omitempty"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
	ActualRTOSeconds    *int       `json:"actual_rto_seconds,omitempty"`
	ExpectedRTOSeconds  *int       `json:"expected_rto_seconds,omitempty"`
	ActualRPOSeconds    *int       `json:"actual_rpo_seconds,omitempty"`
	ExpectedRPOSeconds  *int       `json:"expected_rpo_seconds,omitempty"`
	RTOMet              *bool      `json:"rto_met,omitempty"`
	RPOMet              *bool      `json:"rpo_met,omitempty"`
	DataIntegrityCheck  *bool      `json:"data_integrity_check,omitempty"`
	ErrorMessage        *string    `json:"error_message,omitempty"`
	Notes               *string    `json:"notes,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	// Joined fields
	DatabaseName *string `json:"database_name,omitempty"`
}

// BackupAlert represents a backup-related alert
type BackupAlert struct {
	ID             uuid.UUID  `json:"id"`
	OrgID          uuid.UUID  `json:"org_id"`
	DatabaseID     *uuid.UUID `json:"database_id,omitempty"`
	BackupID       *uuid.UUID `json:"backup_id,omitempty"`
	PolicyID       *uuid.UUID `json:"policy_id,omitempty"`
	AlertType      string     `json:"alert_type"`
	Severity       string     `json:"severity"`
	Title          string     `json:"title"`
	Message        string     `json:"message"`
	Status         string     `json:"status"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	// Joined fields
	DatabaseName *string `json:"database_name,omitempty"`
}

// BackupStorage represents a backup storage location
type BackupStorage struct {
	ID                       uuid.UUID  `json:"id"`
	OrgID                    uuid.UUID  `json:"org_id"`
	Name                     string     `json:"name"`
	StorageType              string     `json:"storage_type"`
	Location                 string     `json:"location"`
	IsPrimary                bool       `json:"is_primary"`
	IsOffsite                bool       `json:"is_offsite"`
	EncryptionEnabled        bool       `json:"encryption_enabled"`
	CompressionEnabled       bool       `json:"compression_enabled"`
	TotalCapacityBytes       *int64     `json:"total_capacity_bytes,omitempty"`
	UsedBytes                int64      `json:"used_bytes"`
	WarningThresholdPercent  int        `json:"warning_threshold_percent"`
	CriticalThresholdPercent int        `json:"critical_threshold_percent"`
	Status                   string     `json:"status"`
	LastHealthCheck          *time.Time `json:"last_health_check,omitempty"`
	BackupCount              int        `json:"backup_count"`
	Enabled                  bool       `json:"enabled"`
	CreatedAt                time.Time  `json:"created_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
}

// BackupOverview represents backup statistics
type BackupOverview struct {
	DatabasesWithBackups     int     `json:"databases_with_backups"`
	TotalBackups             int     `json:"total_backups"`
	SuccessfulBackups        int     `json:"successful_backups"`
	FailedBackups            int     `json:"failed_backups"`
	BackupsLast24h           int     `json:"backups_last_24h"`
	BackupsLast7d            int     `json:"backups_last_7d"`
	TotalBackupSizeBytes     int64   `json:"total_backup_size_bytes"`
	LastBackupAt             *string `json:"last_backup_at,omitempty"`
	AvgBackupDurationSeconds *int    `json:"avg_backup_duration_seconds,omitempty"`
}

// RecoveryReadiness represents DR readiness for a database
type RecoveryReadiness struct {
	DatabaseID           uuid.UUID `json:"database_id"`
	DatabaseName         string    `json:"database_name"`
	DBType               string    `json:"db_type"`
	DataClassification   string    `json:"data_classification"`
	LastSuccessfulBackup *string   `json:"last_successful_backup,omitempty"`
	LastSuccessfulTest   *string   `json:"last_successful_test,omitempty"`
	LastRTOSeconds       *int      `json:"last_rto_seconds,omitempty"`
	LastRPOSeconds       *int      `json:"last_rpo_seconds,omitempty"`
	TestsLast90d         int       `json:"tests_last_90d"`
	ReadinessStatus      string    `json:"readiness_status"`
}

// ============================================================================
// Request Types
// ============================================================================

type TriggerBackupRequest struct {
	DatabaseID uuid.UUID `json:"database_id" binding:"required"`
	BackupType string    `json:"backup_type"`
	Reason     string    `json:"reason"`
}

type TriggerRestoreRequest struct {
	BackupID          uuid.UUID  `json:"backup_id" binding:"required"`
	TargetType        string     `json:"target_type" binding:"required"`
	TargetDatabaseID  *uuid.UUID `json:"target_database_id,omitempty"`
	TargetName        *string    `json:"target_name,omitempty"`
	RestoreType       string     `json:"restore_type"`
	PointInTimeTarget *time.Time `json:"point_in_time_target,omitempty"`
	Reason            string     `json:"reason"`
}

type TriggerRecoveryTestRequest struct {
	DatabaseID   uuid.UUID `json:"database_id" binding:"required"`
	TestType     string    `json:"test_type"`
	TestName     string    `json:"test_name"`
	TestScenario string    `json:"test_scenario"`
}

type CreateBackupStorageRequest struct {
	Name                     string `json:"name" binding:"required"`
	StorageType              string `json:"storage_type" binding:"required"`
	Location                 string `json:"location" binding:"required"`
	IsPrimary                bool   `json:"is_primary"`
	IsOffsite                bool   `json:"is_offsite"`
	EncryptionEnabled        bool   `json:"encryption_enabled"`
	CompressionEnabled       bool   `json:"compression_enabled"`
	TotalCapacityBytes       *int64 `json:"total_capacity_bytes,omitempty"`
	WarningThresholdPercent  int    `json:"warning_threshold_percent"`
	CriticalThresholdPercent int    `json:"critical_threshold_percent"`
}

type UpdateAlertStatusRequest struct {
	Status          string  `json:"status" binding:"required"`
	ResolutionNotes *string `json:"resolution_notes,omitempty"`
}

// ============================================================================
// Handlers
// ============================================================================

// listBackupJobs returns backup job history
func (h *Handler) listBackupJobs(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	status := c.Query("status")
	databaseID := c.Query("database_id")

	query := `
		SELECT bj.id, bj.org_id, bj.policy_id, bj.database_id, bj.job_type,
		       bj.triggered_by, bj.status, bj.progress_percent, bj.current_step,
		       bj.scheduled_at, bj.started_at, bj.completed_at, bj.duration_seconds,
		       bj.backup_id, bj.error_message, bj.error_code, bj.retry_count, bj.max_retries,
		       bj.created_at, bj.updated_at,
		       di.name as database_name, bp.name as policy_name
		FROM backup_jobs bj
		LEFT JOIN database_inventory di ON di.id = bj.database_id
		LEFT JOIN backup_policies bp ON bp.id = bj.policy_id
		WHERE bj.org_id = $1`

	args := []interface{}{orgID}
	argCount := 1

	if status != "" {
		argCount++
		query += ` AND bj.status = $` + string(rune('0'+argCount))
		args = append(args, status)
	}

	if databaseID != "" {
		if dbID, err := uuid.Parse(databaseID); err == nil {
			argCount++
			query += ` AND bj.database_id = $` + string(rune('0'+argCount))
			args = append(args, dbID)
		}
	}

	query += ` ORDER BY bj.created_at DESC LIMIT 100`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to list backup jobs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list backup jobs"})
		return
	}
	defer rows.Close()

	jobs := []BackupJob{}
	for rows.Next() {
		var job BackupJob
		err := rows.Scan(
			&job.ID, &job.OrgID, &job.PolicyID, &job.DatabaseID, &job.JobType,
			&job.TriggeredBy, &job.Status, &job.ProgressPercent, &job.CurrentStep,
			&job.ScheduledAt, &job.StartedAt, &job.CompletedAt, &job.DurationSeconds,
			&job.BackupID, &job.ErrorMessage, &job.ErrorCode, &job.RetryCount, &job.MaxRetries,
			&job.CreatedAt, &job.UpdatedAt,
			&job.DatabaseName, &job.PolicyName,
		)
		if err != nil {
			h.logger.Error("Failed to scan backup job", zap.Error(err))
			continue
		}
		jobs = append(jobs, job)
	}

	c.JSON(http.StatusOK, jobs)
}

// triggerBackup initiates a manual backup
func (h *Handler) triggerBackup(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userEmail := c.GetString("user_email")

	var req TriggerBackupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.BackupType == "" {
		req.BackupType = "full"
	}

	// Create backup job
	var jobID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO backup_jobs (org_id, database_id, job_type, triggered_by, status)
		VALUES ($1, $2, 'manual', $3, 'pending')
		RETURNING id`,
		orgID, req.DatabaseID, userEmail,
	).Scan(&jobID)

	if err != nil {
		h.logger.Error("Failed to create backup job", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup job"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": jobID, "status": "pending", "message": "Backup job created"})
}

// listRestoreOperations returns restore history
func (h *Handler) listRestoreOperations(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT ro.id, ro.org_id, ro.backup_id, ro.source_database_id,
		       ro.target_type, ro.target_database_id, ro.target_name, ro.target_host, ro.target_port,
		       ro.restore_type, ro.point_in_time_target, ro.triggered_by_email, ro.reason,
		       ro.status, ro.progress_percent, ro.current_step,
		       ro.started_at, ro.completed_at, ro.duration_seconds,
		       ro.rows_restored, ro.tables_restored, ro.size_restored_bytes, ro.error_message,
		       ro.created_at, ro.updated_at,
		       di.name as source_database_name, db.backup_name
		FROM restore_operations ro
		LEFT JOIN database_inventory di ON di.id = ro.source_database_id
		LEFT JOIN database_backups db ON db.id = ro.backup_id
		WHERE ro.org_id = $1
		ORDER BY ro.created_at DESC
		LIMIT 100`,
		orgID,
	)
	if err != nil {
		h.logger.Error("Failed to list restore operations", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list restore operations"})
		return
	}
	defer rows.Close()

	operations := []RestoreOperation{}
	for rows.Next() {
		var op RestoreOperation
		err := rows.Scan(
			&op.ID, &op.OrgID, &op.BackupID, &op.SourceDatabaseID,
			&op.TargetType, &op.TargetDatabaseID, &op.TargetName, &op.TargetHost, &op.TargetPort,
			&op.RestoreType, &op.PointInTimeTarget, &op.TriggeredByEmail, &op.Reason,
			&op.Status, &op.ProgressPercent, &op.CurrentStep,
			&op.StartedAt, &op.CompletedAt, &op.DurationSeconds,
			&op.RowsRestored, &op.TablesRestored, &op.SizeRestoredBytes, &op.ErrorMessage,
			&op.CreatedAt, &op.UpdatedAt,
			&op.SourceDatabaseName, &op.BackupName,
		)
		if err != nil {
			h.logger.Error("Failed to scan restore operation", zap.Error(err))
			continue
		}
		operations = append(operations, op)
	}

	c.JSON(http.StatusOK, operations)
}

// triggerRestore initiates a restore operation
func (h *Handler) triggerRestore(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userEmail := c.GetString("user_email")

	var req TriggerRestoreRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.RestoreType == "" {
		req.RestoreType = "full"
	}

	// Get source database from backup
	var sourceDatabaseID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(),
		`SELECT database_id FROM database_backups WHERE id = $1 AND org_id = $2`,
		req.BackupID, orgID,
	).Scan(&sourceDatabaseID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Backup not found"})
		return
	}

	// Create restore operation
	var opID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO restore_operations (org_id, backup_id, source_database_id, target_type,
		                                target_database_id, target_name, restore_type,
		                                point_in_time_target, triggered_by_email, reason, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending')
		RETURNING id`,
		orgID, req.BackupID, sourceDatabaseID, req.TargetType,
		req.TargetDatabaseID, req.TargetName, req.RestoreType,
		req.PointInTimeTarget, userEmail, req.Reason,
	).Scan(&opID)

	if err != nil {
		h.logger.Error("Failed to create restore operation", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create restore operation"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": opID, "status": "pending", "message": "Restore operation created"})
}

// listRecoveryTests returns recovery test history
func (h *Handler) listRecoveryTests(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	databaseID := c.Query("database_id")

	query := `
		SELECT rt.id, rt.org_id, rt.database_id, rt.backup_id, rt.test_type,
		       rt.test_name, rt.test_scenario, rt.triggered_by_email, rt.status,
		       rt.scheduled_at, rt.started_at, rt.completed_at,
		       rt.actual_rto_seconds, rt.expected_rto_seconds, rt.actual_rpo_seconds, rt.expected_rpo_seconds,
		       rt.rto_met, rt.rpo_met, rt.data_integrity_check, rt.error_message, rt.notes,
		       rt.created_at, rt.updated_at,
		       di.name as database_name
		FROM recovery_tests rt
		LEFT JOIN database_inventory di ON di.id = rt.database_id
		WHERE rt.org_id = $1`

	args := []interface{}{orgID}

	if databaseID != "" {
		if dbID, err := uuid.Parse(databaseID); err == nil {
			query += ` AND rt.database_id = $2`
			args = append(args, dbID)
		}
	}

	query += ` ORDER BY rt.created_at DESC LIMIT 100`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to list recovery tests", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list recovery tests"})
		return
	}
	defer rows.Close()

	tests := []RecoveryTest{}
	for rows.Next() {
		var test RecoveryTest
		err := rows.Scan(
			&test.ID, &test.OrgID, &test.DatabaseID, &test.BackupID, &test.TestType,
			&test.TestName, &test.TestScenario, &test.TriggeredByEmail, &test.Status,
			&test.ScheduledAt, &test.StartedAt, &test.CompletedAt,
			&test.ActualRTOSeconds, &test.ExpectedRTOSeconds, &test.ActualRPOSeconds, &test.ExpectedRPOSeconds,
			&test.RTOMet, &test.RPOMet, &test.DataIntegrityCheck, &test.ErrorMessage, &test.Notes,
			&test.CreatedAt, &test.UpdatedAt,
			&test.DatabaseName,
		)
		if err != nil {
			h.logger.Error("Failed to scan recovery test", zap.Error(err))
			continue
		}
		tests = append(tests, test)
	}

	c.JSON(http.StatusOK, tests)
}

// triggerRecoveryTest initiates a recovery test
func (h *Handler) triggerRecoveryTest(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userEmail := c.GetString("user_email")

	var req TriggerRecoveryTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.TestType == "" {
		req.TestType = "restore"
	}

	var testID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO recovery_tests (org_id, database_id, test_type, test_name, test_scenario,
		                            triggered_by_email, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending')
		RETURNING id`,
		orgID, req.DatabaseID, req.TestType, req.TestName, req.TestScenario, userEmail,
	).Scan(&testID)

	if err != nil {
		h.logger.Error("Failed to create recovery test", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create recovery test"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": testID, "status": "pending", "message": "Recovery test created"})
}

// listBackupAlerts returns backup alerts
func (h *Handler) listBackupAlerts(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	status := c.Query("status")
	severity := c.Query("severity")

	query := `
		SELECT ba.id, ba.org_id, ba.database_id, ba.backup_id, ba.policy_id,
		       ba.alert_type, ba.severity, ba.title, ba.message, ba.status,
		       ba.acknowledged_at, ba.resolved_at, ba.created_at,
		       di.name as database_name
		FROM backup_alerts ba
		LEFT JOIN database_inventory di ON di.id = ba.database_id
		WHERE ba.org_id = $1`

	args := []interface{}{orgID}
	argCount := 1

	if status != "" {
		argCount++
		query += ` AND ba.status = $` + string(rune('0'+argCount))
		args = append(args, status)
	}

	if severity != "" {
		argCount++
		query += ` AND ba.severity = $` + string(rune('0'+argCount))
		args = append(args, severity)
	}

	query += ` ORDER BY ba.created_at DESC LIMIT 100`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to list backup alerts", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list backup alerts"})
		return
	}
	defer rows.Close()

	alerts := []BackupAlert{}
	for rows.Next() {
		var alert BackupAlert
		err := rows.Scan(
			&alert.ID, &alert.OrgID, &alert.DatabaseID, &alert.BackupID, &alert.PolicyID,
			&alert.AlertType, &alert.Severity, &alert.Title, &alert.Message, &alert.Status,
			&alert.AcknowledgedAt, &alert.ResolvedAt, &alert.CreatedAt,
			&alert.DatabaseName,
		)
		if err != nil {
			h.logger.Error("Failed to scan backup alert", zap.Error(err))
			continue
		}
		alerts = append(alerts, alert)
	}

	c.JSON(http.StatusOK, alerts)
}

// updateBackupAlertStatus updates an alert's status
func (h *Handler) updateBackupAlertStatus(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	alertID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert ID"})
		return
	}

	var req UpdateAlertStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var query string
	var args []interface{}

	switch req.Status {
	case "acknowledged":
		query = `UPDATE backup_alerts SET status = $1, acknowledged_by = $2, acknowledged_at = NOW(), updated_at = NOW()
		         WHERE id = $3 AND org_id = $4`
		args = []interface{}{req.Status, userID, alertID, orgID}
	case "resolved":
		query = `UPDATE backup_alerts SET status = $1, resolved_by = $2, resolved_at = NOW(),
		         resolution_notes = $3, updated_at = NOW()
		         WHERE id = $4 AND org_id = $5`
		args = []interface{}{req.Status, userID, req.ResolutionNotes, alertID, orgID}
	default:
		query = `UPDATE backup_alerts SET status = $1, updated_at = NOW() WHERE id = $2 AND org_id = $3`
		args = []interface{}{req.Status, alertID, orgID}
	}

	result, err := h.db.Exec(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to update backup alert", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update alert"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Alert updated"})
}

// getBackupOverview returns backup statistics
func (h *Handler) getBackupOverview(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var overview BackupOverview
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT
			COALESCE(databases_with_backups, 0),
			COALESCE(total_backups, 0),
			COALESCE(successful_backups, 0),
			COALESCE(failed_backups, 0),
			COALESCE(backups_last_24h, 0),
			COALESCE(backups_last_7d, 0),
			COALESCE(total_backup_size, 0),
			last_backup_at,
			avg_backup_duration_seconds
		FROM v_backup_overview
		WHERE org_id = $1`,
		orgID,
	).Scan(
		&overview.DatabasesWithBackups,
		&overview.TotalBackups,
		&overview.SuccessfulBackups,
		&overview.FailedBackups,
		&overview.BackupsLast24h,
		&overview.BackupsLast7d,
		&overview.TotalBackupSizeBytes,
		&overview.LastBackupAt,
		&overview.AvgBackupDurationSeconds,
	)

	if err != nil {
		// Return empty overview if no data
		c.JSON(http.StatusOK, BackupOverview{})
		return
	}

	c.JSON(http.StatusOK, overview)
}

// getRecoveryReadiness returns DR readiness for all databases
func (h *Handler) getRecoveryReadiness(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT database_id, database_name, db_type, data_classification,
		       last_successful_backup, last_successful_test,
		       last_rto_seconds, last_rpo_seconds, tests_last_90d, readiness_status
		FROM v_recovery_readiness
		WHERE org_id = $1
		ORDER BY readiness_status DESC, database_name`,
		orgID,
	)
	if err != nil {
		h.logger.Error("Failed to get recovery readiness", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get recovery readiness"})
		return
	}
	defer rows.Close()

	readiness := []RecoveryReadiness{}
	for rows.Next() {
		var r RecoveryReadiness
		err := rows.Scan(
			&r.DatabaseID, &r.DatabaseName, &r.DBType, &r.DataClassification,
			&r.LastSuccessfulBackup, &r.LastSuccessfulTest,
			&r.LastRTOSeconds, &r.LastRPOSeconds, &r.TestsLast90d, &r.ReadinessStatus,
		)
		if err != nil {
			h.logger.Error("Failed to scan recovery readiness", zap.Error(err))
			continue
		}
		readiness = append(readiness, r)
	}

	c.JSON(http.StatusOK, readiness)
}

// listBackupStorage returns backup storage locations
func (h *Handler) listBackupStorage(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, name, storage_type, location, is_primary, is_offsite,
		       encryption_enabled, compression_enabled, total_capacity_bytes, used_bytes,
		       warning_threshold_percent, critical_threshold_percent, status,
		       last_health_check, backup_count, enabled, created_at, updated_at
		FROM backup_storage
		WHERE org_id = $1
		ORDER BY is_primary DESC, name`,
		orgID,
	)
	if err != nil {
		h.logger.Error("Failed to list backup storage", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list backup storage"})
		return
	}
	defer rows.Close()

	storages := []BackupStorage{}
	for rows.Next() {
		var s BackupStorage
		err := rows.Scan(
			&s.ID, &s.OrgID, &s.Name, &s.StorageType, &s.Location, &s.IsPrimary, &s.IsOffsite,
			&s.EncryptionEnabled, &s.CompressionEnabled, &s.TotalCapacityBytes, &s.UsedBytes,
			&s.WarningThresholdPercent, &s.CriticalThresholdPercent, &s.Status,
			&s.LastHealthCheck, &s.BackupCount, &s.Enabled, &s.CreatedAt, &s.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan backup storage", zap.Error(err))
			continue
		}
		storages = append(storages, s)
	}

	c.JSON(http.StatusOK, storages)
}

// createBackupStorage creates a new backup storage location
func (h *Handler) createBackupStorage(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req CreateBackupStorageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.WarningThresholdPercent == 0 {
		req.WarningThresholdPercent = 80
	}
	if req.CriticalThresholdPercent == 0 {
		req.CriticalThresholdPercent = 95
	}

	var storageID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO backup_storage (org_id, name, storage_type, location, is_primary, is_offsite,
		                            encryption_enabled, compression_enabled, total_capacity_bytes,
		                            warning_threshold_percent, critical_threshold_percent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id`,
		orgID, req.Name, req.StorageType, req.Location, req.IsPrimary, req.IsOffsite,
		req.EncryptionEnabled, req.CompressionEnabled, req.TotalCapacityBytes,
		req.WarningThresholdPercent, req.CriticalThresholdPercent,
	).Scan(&storageID)

	if err != nil {
		h.logger.Error("Failed to create backup storage", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup storage"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": storageID})
}

// deleteBackupStorage deletes a backup storage location
func (h *Handler) deleteBackupStorage(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	storageID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid storage ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(),
		`DELETE FROM backup_storage WHERE id = $1 AND org_id = $2`,
		storageID, orgID,
	)
	if err != nil {
		h.logger.Error("Failed to delete backup storage", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete backup storage"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Backup storage not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Backup storage deleted"})
}
