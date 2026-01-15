package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ============================================================================
// Types
// ============================================================================

type PlatformSecurityConfig struct {
	ID     uuid.UUID `json:"id"`
	OrgID  uuid.UUID `json:"org_id"`

	// Secure Defaults
	MFARequiredForAdmins      bool `json:"mfa_required_for_admins"`
	DockerSocketReadOnly      bool `json:"docker_socket_read_only"`
	TLSOnly                   bool `json:"tls_only"`
	MinPasswordLength         int  `json:"min_password_length"`
	PasswordRequireUppercase  bool `json:"password_require_uppercase"`
	PasswordRequireLowercase  bool `json:"password_require_lowercase"`
	PasswordRequireNumbers    bool `json:"password_require_numbers"`
	PasswordRequireSpecial    bool `json:"password_require_special"`
	SessionTimeoutMinutes     int  `json:"session_timeout_minutes"`
	AuditLoggingEnabled       bool `json:"audit_logging_enabled"`
	AuditLoggingImmutable     bool `json:"audit_logging_immutable"`

	// Self-Protection Policies
	BlockPrivilegedContainers bool `json:"block_privileged_containers"`
	BlockDockerSocketMounts   bool `json:"block_docker_socket_mounts"`
	BlockDockerAPIExposure    bool `json:"block_docker_api_exposure"`
	BlockRootContainers       bool `json:"block_root_containers"`
	BlockHostNetwork          bool `json:"block_host_network"`
	BlockHostPID              bool `json:"block_host_pid"`
	BlockHostIPC              bool `json:"block_host_ipc"`
	BlockCapabilityAdditions  bool `json:"block_capability_additions"`

	// Threat Detection
	TrackViolationAttempts     bool `json:"track_violation_attempts"`
	AlertOnViolations          bool `json:"alert_on_violations"`
	MaxViolationsBeforeLockout *int `json:"max_violations_before_lockout,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type PolicyViolation struct {
	ID            uuid.UUID  `json:"id"`
	OrgID         uuid.UUID  `json:"org_id"`
	ViolationType string     `json:"violation_type"`
	Severity      string     `json:"severity"`
	UserID        *uuid.UUID `json:"user_id,omitempty"`
	UserEmail     *string    `json:"user_email,omitempty"`
	IPAddress     *string    `json:"ip_address,omitempty"`
	UserAgent     *string    `json:"user_agent,omitempty"`
	AttemptedAction string   `json:"attempted_action"`
	Blocked       bool       `json:"blocked"`
	PolicyRule    *string    `json:"policy_rule,omitempty"`
	Description   string     `json:"description"`
	RequestPayload interface{} `json:"request_payload,omitempty"`
	Acknowledged  bool       `json:"acknowledged"`
	AcknowledgedBy *uuid.UUID `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	Notes         *string    `json:"notes,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

type PlatformSecurityCheck struct {
	ID               uuid.UUID   `json:"id"`
	OrgID            uuid.UUID   `json:"org_id"`
	CheckType        string      `json:"check_type"`
	CheckName        string      `json:"check_name"`
	CheckDescription *string     `json:"check_description,omitempty"`
	Status           string      `json:"status"`
	Severity         *string     `json:"severity,omitempty"`
	Message          string      `json:"message"`
	Recommendation   *string     `json:"recommendation,omitempty"`
	RemediationSteps *string     `json:"remediation_steps,omitempty"`
	Evidence         interface{} `json:"evidence,omitempty"`
	CheckDurationMS  *int        `json:"check_duration_ms,omitempty"`
	CreatedAt        time.Time   `json:"created_at"`
}

type SecurityPosture struct {
	OrgID            uuid.UUID `json:"org_id"`
	TotalChecks      int       `json:"total_checks"`
	PassedChecks     int       `json:"passed_checks"`
	FailedChecks     int       `json:"failed_checks"`
	WarningChecks    int       `json:"warning_checks"`
	CriticalFailures int       `json:"critical_failures"`
	HighFailures     int       `json:"high_failures"`
	LastCheckAt      time.Time `json:"last_check_at"`
	OverallStatus    string    `json:"overall_status"`
}

type ViolationSummary struct {
	OrgID          uuid.UUID `json:"org_id"`
	ViolationType  string    `json:"violation_type"`
	ViolationCount int       `json:"violation_count"`
	BlockedCount   int       `json:"blocked_count"`
	AllowedCount   int       `json:"allowed_count"`
	MaxSeverity    string    `json:"max_severity"`
	LastViolationAt time.Time `json:"last_violation_at"`
	UniqueUsers    int       `json:"unique_users"`
}

// ============================================================================
// Handlers - Configuration
// ============================================================================

// Get platform security configuration
func (h *Handler) getPlatformSecurityConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT
			id, org_id,
			mfa_required_for_admins, docker_socket_read_only, tls_only,
			min_password_length, password_require_uppercase, password_require_lowercase,
			password_require_numbers, password_require_special, session_timeout_minutes,
			audit_logging_enabled, audit_logging_immutable,
			block_privileged_containers, block_docker_socket_mounts, block_docker_api_exposure,
			block_root_containers, block_host_network, block_host_pid, block_host_ipc,
			block_capability_additions,
			track_violation_attempts, alert_on_violations, max_violations_before_lockout,
			created_at, updated_at
		FROM platform_security_config
		WHERE org_id = $1
	`

	var config PlatformSecurityConfig
	err := h.db.QueryRow(c.Request.Context(), query, orgID).Scan(
		&config.ID, &config.OrgID,
		&config.MFARequiredForAdmins, &config.DockerSocketReadOnly, &config.TLSOnly,
		&config.MinPasswordLength, &config.PasswordRequireUppercase, &config.PasswordRequireLowercase,
		&config.PasswordRequireNumbers, &config.PasswordRequireSpecial, &config.SessionTimeoutMinutes,
		&config.AuditLoggingEnabled, &config.AuditLoggingImmutable,
		&config.BlockPrivilegedContainers, &config.BlockDockerSocketMounts, &config.BlockDockerAPIExposure,
		&config.BlockRootContainers, &config.BlockHostNetwork, &config.BlockHostPID, &config.BlockHostIPC,
		&config.BlockCapabilityAdditions,
		&config.TrackViolationAttempts, &config.AlertOnViolations, &config.MaxViolationsBeforeLockout,
		&config.CreatedAt, &config.UpdatedAt,
	)

	if err != nil {
		// If not found, initialize with defaults
		_, err = h.db.Exec(c.Request.Context(), "SELECT initialize_platform_security_config($1)", orgID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize security config"})
			return
		}

		// Retry query
		err = h.db.QueryRow(c.Request.Context(), query, orgID).Scan(
			&config.ID, &config.OrgID,
			&config.MFARequiredForAdmins, &config.DockerSocketReadOnly, &config.TLSOnly,
			&config.MinPasswordLength, &config.PasswordRequireUppercase, &config.PasswordRequireLowercase,
			&config.PasswordRequireNumbers, &config.PasswordRequireSpecial, &config.SessionTimeoutMinutes,
			&config.AuditLoggingEnabled, &config.AuditLoggingImmutable,
			&config.BlockPrivilegedContainers, &config.BlockDockerSocketMounts, &config.BlockDockerAPIExposure,
			&config.BlockRootContainers, &config.BlockHostNetwork, &config.BlockHostPID, &config.BlockHostIPC,
			&config.BlockCapabilityAdditions,
			&config.TrackViolationAttempts, &config.AlertOnViolations, &config.MaxViolationsBeforeLockout,
			&config.CreatedAt, &config.UpdatedAt,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get security config"})
			return
		}
	}

	c.JSON(http.StatusOK, config)
}

// Update platform security configuration
func (h *Handler) updatePlatformSecurityConfig(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var req PlatformSecurityConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate: audit logging cannot be disabled if immutable
	if !req.AuditLoggingEnabled && req.AuditLoggingImmutable {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot disable audit logging when it's marked as immutable"})
		return
	}

	query := `
		UPDATE platform_security_config SET
			mfa_required_for_admins = $1,
			docker_socket_read_only = $2,
			tls_only = $3,
			min_password_length = $4,
			password_require_uppercase = $5,
			password_require_lowercase = $6,
			password_require_numbers = $7,
			password_require_special = $8,
			session_timeout_minutes = $9,
			audit_logging_enabled = $10,
			block_privileged_containers = $11,
			block_docker_socket_mounts = $12,
			block_docker_api_exposure = $13,
			block_root_containers = $14,
			block_host_network = $15,
			block_host_pid = $16,
			block_host_ipc = $17,
			block_capability_additions = $18,
			track_violation_attempts = $19,
			alert_on_violations = $20,
			max_violations_before_lockout = $21,
			updated_at = NOW()
		WHERE org_id = $22
	`

	_, err := h.db.Exec(c.Request.Context(), query,
		req.MFARequiredForAdmins, req.DockerSocketReadOnly, req.TLSOnly,
		req.MinPasswordLength, req.PasswordRequireUppercase, req.PasswordRequireLowercase,
		req.PasswordRequireNumbers, req.PasswordRequireSpecial, req.SessionTimeoutMinutes,
		req.AuditLoggingEnabled,
		req.BlockPrivilegedContainers, req.BlockDockerSocketMounts, req.BlockDockerAPIExposure,
		req.BlockRootContainers, req.BlockHostNetwork, req.BlockHostPID, req.BlockHostIPC,
		req.BlockCapabilityAdditions,
		req.TrackViolationAttempts, req.AlertOnViolations, req.MaxViolationsBeforeLockout,
		orgID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update security config"})
		return
	}

	// Log configuration change
	_, _ = h.db.Exec(c.Request.Context(),
		"SELECT log_platform_security_event($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
		orgID, "config_change", "configuration", "info", userID, nil, nil,
		"update_security_config", "Platform security configuration updated",
		nil, nil, nil,
	)

	c.JSON(http.StatusOK, gin.H{"message": "Security configuration updated successfully"})
}

// ============================================================================
// Handlers - Self-Check
// ============================================================================

// Run platform security self-check
func (h *Handler) runSecuritySelfCheck(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	type CheckResult struct {
		CheckName      string
		Status         string
		Severity       string
		Message        string
		Recommendation *string
	}

	query := `SELECT * FROM run_platform_security_selfcheck($1)`
	rows, err := h.db.Query(c.Request.Context(), query, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to run self-check"})
		return
	}
	defer rows.Close()

	var checks []CheckResult
	for rows.Next() {
		var check CheckResult
		err := rows.Scan(&check.CheckName, &check.Status, &check.Severity, &check.Message, &check.Recommendation)
		if err != nil {
			continue
		}
		checks = append(checks, check)
	}

	// Calculate summary
	totalChecks := len(checks)
	passedChecks := 0
	failedChecks := 0
	warningChecks := 0
	criticalFailures := 0
	highFailures := 0

	for _, check := range checks {
		switch check.Status {
		case "pass":
			passedChecks++
		case "fail":
			failedChecks++
			if check.Severity == "critical" {
				criticalFailures++
			} else if check.Severity == "high" {
				highFailures++
			}
		case "warning":
			warningChecks++
		}
	}

	overallStatus := "healthy"
	if criticalFailures > 0 {
		overallStatus = "critical"
	} else if highFailures > 0 {
		overallStatus = "warning"
	} else if failedChecks > 0 {
		overallStatus = "degraded"
	}

	c.JSON(http.StatusOK, gin.H{
		"checks": checks,
		"summary": gin.H{
			"total_checks":       totalChecks,
			"passed_checks":      passedChecks,
			"failed_checks":      failedChecks,
			"warning_checks":     warningChecks,
			"critical_failures":  criticalFailures,
			"high_failures":      highFailures,
			"overall_status":     overallStatus,
		},
	})
}

// Get security posture (from view)
func (h *Handler) getSecurityPosture(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT
			org_id, total_checks, passed_checks, failed_checks, warning_checks,
			critical_failures, high_failures, last_check_at, overall_status
		FROM v_platform_security_posture
		WHERE org_id = $1
	`

	var posture SecurityPosture
	err := h.db.QueryRow(c.Request.Context(), query, orgID).Scan(
		&posture.OrgID, &posture.TotalChecks, &posture.PassedChecks, &posture.FailedChecks, &posture.WarningChecks,
		&posture.CriticalFailures, &posture.HighFailures, &posture.LastCheckAt, &posture.OverallStatus,
	)

	if err != nil {
		// If no recent checks, run one
		h.runSecuritySelfCheck(c)
		return
	}

	c.JSON(http.StatusOK, posture)
}

// ============================================================================
// Handlers - Policy Violations
// ============================================================================

// List policy violations
func (h *Handler) listPolicyViolations(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	violationType := c.Query("violation_type")
	severity := c.Query("severity")
	blocked := c.Query("blocked")
	acknowledged := c.Query("acknowledged")

	query := `
		SELECT
			id, org_id, violation_type, severity, user_id, user_email, ip_address, user_agent,
			attempted_action, blocked, policy_rule, description, request_payload,
			acknowledged, acknowledged_by, acknowledged_at, notes, created_at
		FROM policy_violations
		WHERE org_id = $1
	`

	args := []interface{}{orgID}
	argCount := 1

	if violationType != "" {
		argCount++
		query += fmt.Sprintf(" AND violation_type = $%d", argCount)
		args = append(args, violationType)
	}

	if severity != "" {
		argCount++
		query += fmt.Sprintf(" AND severity = $%d", argCount)
		args = append(args, severity)
	}

	if blocked != "" {
		argCount++
		query += fmt.Sprintf(" AND blocked = $%d", argCount)
		args = append(args, blocked == "true")
	}

	if acknowledged != "" {
		argCount++
		query += fmt.Sprintf(" AND acknowledged = $%d", argCount)
		args = append(args, acknowledged == "true")
	}

	query += " ORDER BY created_at DESC LIMIT 100"

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query violations"})
		return
	}
	defer rows.Close()

	var violations []PolicyViolation
	for rows.Next() {
		var v PolicyViolation
		err := rows.Scan(
			&v.ID, &v.OrgID, &v.ViolationType, &v.Severity, &v.UserID, &v.UserEmail, &v.IPAddress, &v.UserAgent,
			&v.AttemptedAction, &v.Blocked, &v.PolicyRule, &v.Description, &v.RequestPayload,
			&v.Acknowledged, &v.AcknowledgedBy, &v.AcknowledgedAt, &v.Notes, &v.CreatedAt,
		)
		if err != nil {
			continue
		}
		violations = append(violations, v)
	}

	c.JSON(http.StatusOK, gin.H{
		"violations": violations,
		"count":      len(violations),
	})
}

// Get violation summary (from view)
func (h *Handler) getViolationSummary(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT
			org_id, violation_type, violation_count, blocked_count, allowed_count,
			max_severity, last_violation_at, unique_users
		FROM v_recent_policy_violations
		WHERE org_id = $1
		ORDER BY violation_count DESC
	`

	rows, err := h.db.Query(c.Request.Context(), query, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query violation summary"})
		return
	}
	defer rows.Close()

	var summaries []ViolationSummary
	for rows.Next() {
		var s ViolationSummary
		err := rows.Scan(
			&s.OrgID, &s.ViolationType, &s.ViolationCount, &s.BlockedCount, &s.AllowedCount,
			&s.MaxSeverity, &s.LastViolationAt, &s.UniqueUsers,
		)
		if err != nil {
			continue
		}
		summaries = append(summaries, s)
	}

	c.JSON(http.StatusOK, gin.H{
		"summaries": summaries,
		"count":     len(summaries),
	})
}

// Acknowledge a violation
func (h *Handler) acknowledgeViolation(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)
	violationID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid violation ID"})
		return
	}

	var req struct {
		Notes string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `
		UPDATE policy_violations
		SET acknowledged = TRUE, acknowledged_by = $1, acknowledged_at = NOW(), notes = $2
		WHERE id = $3 AND org_id = $4
	`

	result, err := h.db.Exec(c.Request.Context(), query, userID, req.Notes, violationID, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to acknowledge violation"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Violation not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Violation acknowledged"})
}

// ============================================================================
// Helper: Record Violation (called by policy engine)
// ============================================================================

func (h *Handler) RecordPolicyViolation(ctx context.Context, orgID, userID uuid.UUID, violationType, severity, attemptedAction, description string, blocked bool, policyRule string, payload interface{}) error {
	_, err := h.db.Exec(ctx,
		"SELECT record_policy_violation($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
		orgID, violationType, severity, userID, nil, nil, attemptedAction, blocked, policyRule, description, payload,
	)
	return err
}
