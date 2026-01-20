package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================================
// Types
// ============================================================================

// BackgroundJob represents a job execution
type BackgroundJob struct {
	ID                 uuid.UUID       `json:"id"`
	OrgID              uuid.UUID       `json:"org_id"`
	JobType            string          `json:"job_type"`
	JobName            string          `json:"job_name"`
	JobCategory        string          `json:"job_category"`
	TriggeredBy        *string         `json:"triggered_by,omitempty"`
	TriggeredByEmail   *string         `json:"triggered_by_email,omitempty"`
	TargetType         *string         `json:"target_type,omitempty"`
	TargetID           *uuid.UUID      `json:"target_id,omitempty"`
	TargetName         *string         `json:"target_name,omitempty"`
	Parameters         json.RawMessage `json:"parameters,omitempty"`
	Status             string          `json:"status"`
	Priority           int             `json:"priority"`
	ProgressPercent    int             `json:"progress_percent"`
	CurrentStep        *string         `json:"current_step,omitempty"`
	StepsTotal         int             `json:"steps_total"`
	StepsCompleted     int             `json:"steps_completed"`
	ScheduledAt        *time.Time      `json:"scheduled_at,omitempty"`
	QueuedAt           *time.Time      `json:"queued_at,omitempty"`
	StartedAt          *time.Time      `json:"started_at,omitempty"`
	CompletedAt        *time.Time      `json:"completed_at,omitempty"`
	TimeoutSeconds     int             `json:"timeout_seconds"`
	Result             json.RawMessage `json:"result,omitempty"`
	Output             *string         `json:"output,omitempty"`
	ErrorMessage       *string         `json:"error_message,omitempty"`
	ErrorCode          *string         `json:"error_code,omitempty"`
	RetryCount         int             `json:"retry_count"`
	MaxRetries         int             `json:"max_retries"`
	WorkerID           *string         `json:"worker_id,omitempty"`
	WorkerHostname     *string         `json:"worker_hostname,omitempty"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// JobSchedule represents a recurring job schedule
type JobSchedule struct {
	ID                         uuid.UUID       `json:"id"`
	OrgID                      uuid.UUID       `json:"org_id"`
	Name                       string          `json:"name"`
	Description                *string         `json:"description,omitempty"`
	JobType                    string          `json:"job_type"`
	JobName                    string          `json:"job_name"`
	JobCategory                string          `json:"job_category"`
	TargetType                 *string         `json:"target_type,omitempty"`
	TargetID                   *uuid.UUID      `json:"target_id,omitempty"`
	TargetName                 *string         `json:"target_name,omitempty"`
	CronExpression             string          `json:"cron_expression"`
	Timezone                   string          `json:"timezone"`
	Parameters                 json.RawMessage `json:"parameters,omitempty"`
	Priority                   int             `json:"priority"`
	TimeoutSeconds             int             `json:"timeout_seconds"`
	MaxRetries                 int             `json:"max_retries"`
	Enabled                    bool            `json:"enabled"`
	LastRunAt                  *time.Time      `json:"last_run_at,omitempty"`
	LastRunStatus              *string         `json:"last_run_status,omitempty"`
	LastRunDurationSeconds     *int            `json:"last_run_duration_seconds,omitempty"`
	NextRunAt                  *time.Time      `json:"next_run_at,omitempty"`
	RunCount                   int             `json:"run_count"`
	FailureCount               int             `json:"failure_count"`
	ConsecutiveFailures        int             `json:"consecutive_failures"`
	AlertOnFailure             bool            `json:"alert_on_failure"`
	AlertAfterConsecFailures   int             `json:"alert_after_consecutive_failures"`
	PauseAfterFailures         int             `json:"pause_after_failures"`
	CreatedAt                  time.Time       `json:"created_at"`
	UpdatedAt                  time.Time       `json:"updated_at"`
}

// Worker represents a worker process
type Worker struct {
	ID                  string     `json:"id"`
	OrgID               *uuid.UUID `json:"org_id,omitempty"`
	Hostname            string     `json:"hostname"`
	WorkerType          string     `json:"worker_type"`
	Version             *string    `json:"version,omitempty"`
	PID                 *int       `json:"pid,omitempty"`
	Status              string     `json:"status"`
	CurrentJobID        *uuid.UUID `json:"current_job_id,omitempty"`
	JobsProcessed       int        `json:"jobs_processed"`
	JobsFailed          int        `json:"jobs_failed"`
	MaxConcurrentJobs   int        `json:"max_concurrent_jobs"`
	CurrentJobs         int        `json:"current_jobs"`
	QueueSize           int        `json:"queue_size"`
	LastHeartbeatAt     time.Time  `json:"last_heartbeat_at"`
	StartedAt           time.Time  `json:"started_at"`
	StoppedAt           *time.Time `json:"stopped_at,omitempty"`
	HealthCheckFailures int        `json:"health_check_failures"`
	CPUPercent          *float64   `json:"cpu_percent,omitempty"`
	MemoryMB            *int       `json:"memory_mb,omitempty"`
	MemoryPercent       *float64   `json:"memory_percent,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// JobLog represents a job log entry
type JobLog struct {
	ID       uuid.UUID       `json:"id"`
	OrgID    uuid.UUID       `json:"org_id"`
	JobID    uuid.UUID       `json:"job_id"`
	LogLevel string          `json:"log_level"`
	Message  string          `json:"message"`
	Details  json.RawMessage `json:"details,omitempty"`
	LoggedAt time.Time       `json:"logged_at"`
}

// JobStatistics represents job statistics
type JobStatistics struct {
	JobType            string   `json:"job_type"`
	TotalJobs          int      `json:"total_jobs"`
	CompletedJobs      int      `json:"completed_jobs"`
	FailedJobs         int      `json:"failed_jobs"`
	RunningJobs        int      `json:"running_jobs"`
	PendingJobs        int      `json:"pending_jobs"`
	JobsLast24h        int      `json:"jobs_last_24h"`
	AvgDurationSeconds *float64 `json:"avg_duration_seconds,omitempty"`
	LastCompletedAt    *string  `json:"last_completed_at,omitempty"`
}

// WorkerSummary represents worker statistics
type WorkerSummary struct {
	TotalWorkers        int      `json:"total_workers"`
	IdleWorkers         int      `json:"idle_workers"`
	BusyWorkers         int      `json:"busy_workers"`
	UnhealthyWorkers    int      `json:"unhealthy_workers"`
	TotalJobsProcessed  int64    `json:"total_jobs_processed"`
	TotalJobsFailed     int64    `json:"total_jobs_failed"`
	AvgCPUPercent       *float64 `json:"avg_cpu_percent,omitempty"`
	AvgMemoryPercent    *float64 `json:"avg_memory_percent,omitempty"`
}

// ============================================================================
// Request Types
// ============================================================================

type CreateJobRequest struct {
	JobType        string          `json:"job_type" binding:"required"`
	JobName        string          `json:"job_name" binding:"required"`
	JobCategory    string          `json:"job_category"`
	TargetType     *string         `json:"target_type,omitempty"`
	TargetID       *string         `json:"target_id,omitempty"`
	TargetName     *string         `json:"target_name,omitempty"`
	Parameters     json.RawMessage `json:"parameters,omitempty"`
	Priority       int             `json:"priority"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	ScheduledAt    *time.Time      `json:"scheduled_at,omitempty"`
}

type CreateScheduleRequest struct {
	Name           string          `json:"name" binding:"required"`
	Description    string          `json:"description"`
	JobType        string          `json:"job_type" binding:"required"`
	JobName        string          `json:"job_name" binding:"required"`
	JobCategory    string          `json:"job_category"`
	CronExpression string          `json:"cron_expression" binding:"required"`
	Timezone       string          `json:"timezone"`
	TargetType     *string         `json:"target_type,omitempty"`
	TargetID       *string         `json:"target_id,omitempty"`
	TargetName     *string         `json:"target_name,omitempty"`
	Parameters     json.RawMessage `json:"parameters,omitempty"`
	Priority       int             `json:"priority"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	MaxRetries     int             `json:"max_retries"`
	AlertOnFailure bool            `json:"alert_on_failure"`
}

// ============================================================================
// Handlers
// ============================================================================

// listJobs returns background jobs
func (h *Handler) listJobs(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	status := c.Query("status")
	jobType := c.Query("job_type")
	category := c.Query("category")

	query := `
		SELECT id, org_id, job_type, job_name, job_category, triggered_by, triggered_by_email,
		       target_type, target_id, target_name, parameters, status, priority,
		       progress_percent, current_step, steps_total, steps_completed,
		       scheduled_at, queued_at, started_at, completed_at, timeout_seconds,
		       result, output, error_message, error_code, retry_count, max_retries,
		       worker_id, worker_hostname, created_at, updated_at
		FROM background_jobs
		WHERE org_id = $1`

	args := []interface{}{orgID}
	argCount := 1

	if status != "" {
		argCount++
		query += ` AND status = $` + string(rune('0'+argCount))
		args = append(args, status)
	}

	if jobType != "" {
		argCount++
		query += ` AND job_type = $` + string(rune('0'+argCount))
		args = append(args, jobType)
	}

	if category != "" {
		argCount++
		query += ` AND job_category = $` + string(rune('0'+argCount))
		args = append(args, category)
	}

	query += ` ORDER BY created_at DESC LIMIT 100`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to list jobs", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list jobs"})
		return
	}
	defer rows.Close()

	jobs := []BackgroundJob{}
	for rows.Next() {
		var job BackgroundJob
		err := rows.Scan(
			&job.ID, &job.OrgID, &job.JobType, &job.JobName, &job.JobCategory,
			&job.TriggeredBy, &job.TriggeredByEmail, &job.TargetType, &job.TargetID,
			&job.TargetName, &job.Parameters, &job.Status, &job.Priority,
			&job.ProgressPercent, &job.CurrentStep, &job.StepsTotal, &job.StepsCompleted,
			&job.ScheduledAt, &job.QueuedAt, &job.StartedAt, &job.CompletedAt, &job.TimeoutSeconds,
			&job.Result, &job.Output, &job.ErrorMessage, &job.ErrorCode, &job.RetryCount, &job.MaxRetries,
			&job.WorkerID, &job.WorkerHostname, &job.CreatedAt, &job.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan job", "error", err)
			continue
		}
		jobs = append(jobs, job)
	}

	c.JSON(http.StatusOK, jobs)
}

// getJob returns a specific job
func (h *Handler) getJob(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	var job BackgroundJob
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, job_type, job_name, job_category, triggered_by, triggered_by_email,
		       target_type, target_id, target_name, parameters, status, priority,
		       progress_percent, current_step, steps_total, steps_completed,
		       scheduled_at, queued_at, started_at, completed_at, timeout_seconds,
		       result, output, error_message, error_code, retry_count, max_retries,
		       worker_id, worker_hostname, created_at, updated_at
		FROM background_jobs
		WHERE id = $1 AND org_id = $2`,
		jobID, orgID,
	).Scan(
		&job.ID, &job.OrgID, &job.JobType, &job.JobName, &job.JobCategory,
		&job.TriggeredBy, &job.TriggeredByEmail, &job.TargetType, &job.TargetID,
		&job.TargetName, &job.Parameters, &job.Status, &job.Priority,
		&job.ProgressPercent, &job.CurrentStep, &job.StepsTotal, &job.StepsCompleted,
		&job.ScheduledAt, &job.QueuedAt, &job.StartedAt, &job.CompletedAt, &job.TimeoutSeconds,
		&job.Result, &job.Output, &job.ErrorMessage, &job.ErrorCode, &job.RetryCount, &job.MaxRetries,
		&job.WorkerID, &job.WorkerHostname, &job.CreatedAt, &job.UpdatedAt,
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
		return
	}

	c.JSON(http.StatusOK, job)
}

// createJob creates a new background job
func (h *Handler) createJob(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userEmail := c.GetString("user_email")

	var req CreateJobRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.JobCategory == "" {
		req.JobCategory = "user_triggered"
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = 3600
	}

	var targetID *uuid.UUID
	if req.TargetID != nil {
		if id, err := uuid.Parse(*req.TargetID); err == nil {
			targetID = &id
		}
	}

	triggeredBy := "manual"

	var jobID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO background_jobs (org_id, job_type, job_name, job_category,
		                             triggered_by, triggered_by_email, target_type,
		                             target_id, target_name, parameters, priority,
		                             timeout_seconds, scheduled_at, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'pending')
		RETURNING id`,
		orgID, req.JobType, req.JobName, req.JobCategory,
		triggeredBy, userEmail, req.TargetType,
		targetID, req.TargetName, req.Parameters, req.Priority,
		req.TimeoutSeconds, req.ScheduledAt,
	).Scan(&jobID)

	if err != nil {
		h.logger.Error("Failed to create job", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create job"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": jobID, "status": "pending"})
}

// cancelJob cancels a pending or running job
func (h *Handler) cancelJob(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		UPDATE background_jobs
		SET status = 'cancelled', completed_at = NOW(), updated_at = NOW()
		WHERE id = $1 AND org_id = $2 AND status IN ('pending', 'queued', 'running')`,
		jobID, orgID,
	)
	if err != nil {
		h.logger.Error("Failed to cancel job", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to cancel job"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found or cannot be cancelled"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Job cancelled"})
}

// retryJob retries a failed job
func (h *Handler) retryJob(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(), `
		UPDATE background_jobs
		SET status = 'pending', retry_count = retry_count + 1,
		    error_message = NULL, error_code = NULL, updated_at = NOW()
		WHERE id = $1 AND org_id = $2 AND status = 'failed' AND retry_count < max_retries`,
		jobID, orgID,
	)
	if err != nil {
		h.logger.Error("Failed to retry job", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retry job"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Job not found or cannot be retried"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Job queued for retry"})
}

// getJobLogs returns logs for a specific job
func (h *Handler) getJobLogs(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	jobID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid job ID"})
		return
	}

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, job_id, log_level, message, details, logged_at
		FROM job_logs
		WHERE job_id = $1 AND org_id = $2
		ORDER BY logged_at ASC`,
		jobID, orgID,
	)
	if err != nil {
		h.logger.Error("Failed to get job logs", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get logs"})
		return
	}
	defer rows.Close()

	logs := []JobLog{}
	for rows.Next() {
		var log JobLog
		err := rows.Scan(
			&log.ID, &log.OrgID, &log.JobID, &log.LogLevel, &log.Message, &log.Details, &log.LoggedAt,
		)
		if err != nil {
			continue
		}
		logs = append(logs, log)
	}

	c.JSON(http.StatusOK, logs)
}

// getJobStatistics returns job statistics by type
func (h *Handler) getJobStatistics(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT job_type, total_jobs, completed_jobs, failed_jobs, running_jobs,
		       pending_jobs, jobs_last_24h, avg_duration_seconds, last_completed_at
		FROM v_job_statistics
		WHERE org_id = $1
		ORDER BY total_jobs DESC`,
		orgID,
	)
	if err != nil {
		h.logger.Error("Failed to get job statistics", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get statistics"})
		return
	}
	defer rows.Close()

	stats := []JobStatistics{}
	for rows.Next() {
		var s JobStatistics
		err := rows.Scan(
			&s.JobType, &s.TotalJobs, &s.CompletedJobs, &s.FailedJobs, &s.RunningJobs,
			&s.PendingJobs, &s.JobsLast24h, &s.AvgDurationSeconds, &s.LastCompletedAt,
		)
		if err != nil {
			continue
		}
		stats = append(stats, s)
	}

	c.JSON(http.StatusOK, stats)
}

// listSchedules returns job schedules
func (h *Handler) listSchedules(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, name, description, job_type, job_name, job_category,
		       target_type, target_id, target_name, cron_expression, timezone,
		       parameters, priority, timeout_seconds, max_retries, enabled,
		       last_run_at, last_run_status, last_run_duration_seconds, next_run_at,
		       run_count, failure_count, consecutive_failures, alert_on_failure,
		       alert_after_consecutive_failures, pause_after_failures, created_at, updated_at
		FROM job_schedules
		WHERE org_id = $1
		ORDER BY name`,
		orgID,
	)
	if err != nil {
		h.logger.Error("Failed to list schedules", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list schedules"})
		return
	}
	defer rows.Close()

	schedules := []JobSchedule{}
	for rows.Next() {
		var s JobSchedule
		err := rows.Scan(
			&s.ID, &s.OrgID, &s.Name, &s.Description, &s.JobType, &s.JobName, &s.JobCategory,
			&s.TargetType, &s.TargetID, &s.TargetName, &s.CronExpression, &s.Timezone,
			&s.Parameters, &s.Priority, &s.TimeoutSeconds, &s.MaxRetries, &s.Enabled,
			&s.LastRunAt, &s.LastRunStatus, &s.LastRunDurationSeconds, &s.NextRunAt,
			&s.RunCount, &s.FailureCount, &s.ConsecutiveFailures, &s.AlertOnFailure,
			&s.AlertAfterConsecFailures, &s.PauseAfterFailures, &s.CreatedAt, &s.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan schedule", "error", err)
			continue
		}
		schedules = append(schedules, s)
	}

	c.JSON(http.StatusOK, schedules)
}

// createSchedule creates a new job schedule
func (h *Handler) createSchedule(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req CreateScheduleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.JobCategory == "" {
		req.JobCategory = "system"
	}
	if req.Timezone == "" {
		req.Timezone = "UTC"
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = 3600
	}
	if req.MaxRetries == 0 {
		req.MaxRetries = 3
	}

	var targetID *uuid.UUID
	if req.TargetID != nil {
		if id, err := uuid.Parse(*req.TargetID); err == nil {
			targetID = &id
		}
	}

	var scheduleID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		INSERT INTO job_schedules (org_id, name, description, job_type, job_name, job_category,
		                           cron_expression, timezone, target_type, target_id, target_name,
		                           parameters, priority, timeout_seconds, max_retries, alert_on_failure)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id`,
		orgID, req.Name, req.Description, req.JobType, req.JobName, req.JobCategory,
		req.CronExpression, req.Timezone, req.TargetType, targetID, req.TargetName,
		req.Parameters, req.Priority, req.TimeoutSeconds, req.MaxRetries, req.AlertOnFailure,
	).Scan(&scheduleID)

	if err != nil {
		h.logger.Error("Failed to create schedule", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create schedule"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": scheduleID})
}

// toggleSchedule enables or disables a schedule
func (h *Handler) toggleSchedule(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	scheduleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule ID"})
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.db.Exec(c.Request.Context(),
		`UPDATE job_schedules SET enabled = $1, updated_at = NOW() WHERE id = $2 AND org_id = $3`,
		req.Enabled, scheduleID, orgID,
	)
	if err != nil {
		h.logger.Error("Failed to update schedule", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update schedule"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Schedule updated", "enabled": req.Enabled})
}

// deleteSchedule removes a job schedule
func (h *Handler) deleteSchedule(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	scheduleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid schedule ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(),
		`DELETE FROM job_schedules WHERE id = $1 AND org_id = $2`,
		scheduleID, orgID,
	)
	if err != nil {
		h.logger.Error("Failed to delete schedule", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete schedule"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Schedule not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Schedule deleted"})
}

// listWorkers returns worker processes
func (h *Handler) listWorkers(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, org_id, hostname, worker_type, version, pid, status,
		       current_job_id, jobs_processed, jobs_failed, max_concurrent_jobs,
		       current_jobs, queue_size, last_heartbeat_at, started_at, stopped_at,
		       health_check_failures, cpu_percent, memory_mb, memory_percent,
		       created_at, updated_at
		FROM workers
		WHERE org_id IS NULL OR org_id = $1
		ORDER BY status, hostname`,
		orgID,
	)
	if err != nil {
		h.logger.Error("Failed to list workers", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list workers"})
		return
	}
	defer rows.Close()

	workers := []Worker{}
	for rows.Next() {
		var w Worker
		err := rows.Scan(
			&w.ID, &w.OrgID, &w.Hostname, &w.WorkerType, &w.Version, &w.PID, &w.Status,
			&w.CurrentJobID, &w.JobsProcessed, &w.JobsFailed, &w.MaxConcurrentJobs,
			&w.CurrentJobs, &w.QueueSize, &w.LastHeartbeatAt, &w.StartedAt, &w.StoppedAt,
			&w.HealthCheckFailures, &w.CPUPercent, &w.MemoryMB, &w.MemoryPercent,
			&w.CreatedAt, &w.UpdatedAt,
		)
		if err != nil {
			h.logger.Error("Failed to scan worker", "error", err)
			continue
		}
		workers = append(workers, w)
	}

	c.JSON(http.StatusOK, workers)
}

// getWorkerSummary returns worker statistics
func (h *Handler) getWorkerSummary(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var summary WorkerSummary
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT total_workers, idle_workers, busy_workers, unhealthy_workers,
		       total_jobs_processed, total_jobs_failed, avg_cpu_percent, avg_memory_percent
		FROM v_worker_summary
		WHERE org_id = $1 OR org_id = '00000000-0000-0000-0000-000000000000'`,
		orgID,
	).Scan(
		&summary.TotalWorkers, &summary.IdleWorkers, &summary.BusyWorkers, &summary.UnhealthyWorkers,
		&summary.TotalJobsProcessed, &summary.TotalJobsFailed, &summary.AvgCPUPercent, &summary.AvgMemoryPercent,
	)

	if err != nil {
		c.JSON(http.StatusOK, WorkerSummary{})
		return
	}

	c.JSON(http.StatusOK, summary)
}
