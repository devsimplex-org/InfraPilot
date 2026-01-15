package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ============================================================================
// Types
// ============================================================================

type CodeQualityResult struct {
	ID           uuid.UUID  `json:"id"`
	OrgID        uuid.UUID  `json:"org_id"`
	DeploymentID *uuid.UUID `json:"deployment_id,omitempty"`

	Tool        string  `json:"tool"`
	ToolVersion *string `json:"tool_version,omitempty"`

	ProjectKey  string  `json:"project_key"`
	ProjectName *string `json:"project_name,omitempty"`

	GitRepo      *string `json:"git_repo,omitempty"`
	GitBranch    *string `json:"git_branch,omitempty"`
	CommitSHA    *string `json:"commit_sha,omitempty"`
	CommitAuthor *string `json:"commit_author,omitempty"`

	Bugs              int `json:"bugs"`
	Vulnerabilities   int `json:"vulnerabilities"`
	CodeSmells        int `json:"code_smells"`
	SecurityHotspots  int `json:"security_hotspots"`

	CriticalIssues int `json:"critical_issues"`
	HighIssues     int `json:"high_issues"`
	MediumIssues   int `json:"medium_issues"`
	LowIssues      int `json:"low_issues"`
	InfoIssues     int `json:"info_issues"`

	Coverage             *float64 `json:"coverage,omitempty"`
	Complexity           *float64 `json:"complexity,omitempty"`
	Duplication          *float64 `json:"duplication,omitempty"`
	TechnicalDebtMinutes *int     `json:"technical_debt_minutes,omitempty"`

	QualityGate        *string `json:"quality_gate,omitempty"`
	QualityGateDetails *string `json:"quality_gate_details,omitempty"`

	ScanDurationMS *int `json:"scan_duration_ms,omitempty"`
	LinesOfCode    *int `json:"lines_of_code,omitempty"`
	FilesAnalyzed  *int `json:"files_analyzed,omitempty"`

	RawReport interface{} `json:"raw_report,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type CodeQualityIssue struct {
	ID                   uuid.UUID `json:"id"`
	CodeQualityResultID  uuid.UUID `json:"code_quality_result_id"`

	IssueKey  *string `json:"issue_key,omitempty"`
	RuleID    string  `json:"rule_id"`
	RuleName  *string `json:"rule_name,omitempty"`

	Severity  string `json:"severity"`
	IssueType string `json:"issue_type"`

	FilePath    string `json:"file_path"`
	StartLine   *int   `json:"start_line,omitempty"`
	EndLine     *int   `json:"end_line,omitempty"`
	StartColumn *int   `json:"start_column,omitempty"`
	EndColumn   *int   `json:"end_column,omitempty"`

	Message     string  `json:"message"`
	Description *string `json:"description,omitempty"`

	CWEIDs        []string `json:"cwe_ids,omitempty"`
	OWASPCategory *string  `json:"owasp_category,omitempty"`
	Confidence    *string  `json:"confidence,omitempty"`

	FixAvailable  bool    `json:"fix_available"`
	FixSuggestion *string `json:"fix_suggestion,omitempty"`

	Metadata interface{} `json:"metadata,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

type CodeQualityPolicy struct {
	ID          uuid.UUID `json:"id"`
	OrgID       uuid.UUID `json:"org_id"`

	Name        string  `json:"name"`
	Description *string `json:"description,omitempty"`

	Environments []string `json:"environments"`
	Projects     []string `json:"projects"`
	Tools        []string `json:"tools"`

	MaxCritical      *int     `json:"max_critical,omitempty"`
	MaxHigh          *int     `json:"max_high,omitempty"`
	MaxMedium        *int     `json:"max_medium,omitempty"`
	MaxVulnerabilities *int   `json:"max_vulnerabilities,omitempty"`
	MaxBugs          *int     `json:"max_bugs,omitempty"`
	MaxCodeSmells    *int     `json:"max_code_smells,omitempty"`

	MinCoverage    *float64 `json:"min_coverage,omitempty"`
	MaxComplexity  *float64 `json:"max_complexity,omitempty"`
	MaxDuplication *float64 `json:"max_duplication,omitempty"`

	Enforcement       string `json:"enforcement"`
	BlockDeployment   bool   `json:"block_deployment"`

	Version int  `json:"version"`
	Enabled bool `json:"enabled"`

	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type PolicyEvaluation struct {
	ID                   uuid.UUID  `json:"id"`
	CodeQualityResultID  uuid.UUID  `json:"code_quality_result_id"`
	PolicyID             *uuid.UUID `json:"policy_id,omitempty"`

	Decision           string      `json:"decision"`
	Reason             *string     `json:"reason,omitempty"`
	Violations         interface{} `json:"violations,omitempty"`
	EvaluationTimeMS   *int        `json:"evaluation_time_ms,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}

type ProjectQualitySummary struct {
	OrgID       uuid.UUID `json:"org_id"`
	ProjectKey  string    `json:"project_key"`
	ProjectName *string   `json:"project_name,omitempty"`
	Tool        string    `json:"tool"`

	TotalScans         int      `json:"total_scans"`
	AvgCoverage        *float64 `json:"avg_coverage,omitempty"`
	AvgComplexity      *float64 `json:"avg_complexity,omitempty"`
	AvgDuplication     *float64 `json:"avg_duplication,omitempty"`

	TotalBugs            int `json:"total_bugs"`
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	TotalCodeSmells      int `json:"total_code_smells"`
	TotalCritical        int `json:"total_critical"`
	TotalHigh            int `json:"total_high"`

	FailedGates int       `json:"failed_gates"`
	PassedGates int       `json:"passed_gates"`
	LastScanAt  time.Time `json:"last_scan_at"`
}

type QualityLeaderboard struct {
	OrgID       uuid.UUID `json:"org_id"`
	ProjectKey  string    `json:"project_key"`
	ProjectName *string   `json:"project_name,omitempty"`
	Tool        string    `json:"tool"`

	Coverage   *float64 `json:"coverage,omitempty"`
	Complexity *float64 `json:"complexity,omitempty"`

	TotalIssues    int `json:"total_issues"`
	CriticalIssues int `json:"critical_issues"`
	HighIssues     int `json:"high_issues"`

	QualityGate *string   `json:"quality_gate,omitempty"`
	LastScanAt  time.Time `json:"last_scan_at"`

	QualityScore int `json:"quality_score"`
}

type CreateCodeQualityResultRequest struct {
	DeploymentID *uuid.UUID `json:"deployment_id,omitempty"`

	Tool        string  `json:"tool" binding:"required"`
	ToolVersion *string `json:"tool_version,omitempty"`

	ProjectKey  string  `json:"project_key" binding:"required"`
	ProjectName *string `json:"project_name,omitempty"`

	GitRepo      *string `json:"git_repo,omitempty"`
	GitBranch    *string `json:"git_branch,omitempty"`
	CommitSHA    *string `json:"commit_sha,omitempty"`
	CommitAuthor *string `json:"commit_author,omitempty"`

	Bugs              int `json:"bugs"`
	Vulnerabilities   int `json:"vulnerabilities"`
	CodeSmells        int `json:"code_smells"`
	SecurityHotspots  int `json:"security_hotspots"`

	CriticalIssues int `json:"critical_issues"`
	HighIssues     int `json:"high_issues"`
	MediumIssues   int `json:"medium_issues"`
	LowIssues      int `json:"low_issues"`
	InfoIssues     int `json:"info_issues"`

	Coverage             *float64 `json:"coverage,omitempty"`
	Complexity           *float64 `json:"complexity,omitempty"`
	Duplication          *float64 `json:"duplication,omitempty"`
	TechnicalDebtMinutes *int     `json:"technical_debt_minutes,omitempty"`

	QualityGate        *string `json:"quality_gate,omitempty"`
	QualityGateDetails *string `json:"quality_gate_details,omitempty"`

	ScanDurationMS *int `json:"scan_duration_ms,omitempty"`
	LinesOfCode    *int `json:"lines_of_code,omitempty"`
	FilesAnalyzed  *int `json:"files_analyzed,omitempty"`

	RawReport interface{} `json:"raw_report,omitempty"`
	Issues    []CreateCodeQualityIssueRequest `json:"issues,omitempty"`
}

type CreateCodeQualityIssueRequest struct {
	IssueKey  *string `json:"issue_key,omitempty"`
	RuleID    string  `json:"rule_id" binding:"required"`
	RuleName  *string `json:"rule_name,omitempty"`

	Severity  string `json:"severity" binding:"required"`
	IssueType string `json:"issue_type" binding:"required"`

	FilePath    string `json:"file_path" binding:"required"`
	StartLine   *int   `json:"start_line,omitempty"`
	EndLine     *int   `json:"end_line,omitempty"`
	StartColumn *int   `json:"start_column,omitempty"`
	EndColumn   *int   `json:"end_column,omitempty"`

	Message     string  `json:"message" binding:"required"`
	Description *string `json:"description,omitempty"`

	CWEIDs        []string `json:"cwe_ids,omitempty"`
	OWASPCategory *string  `json:"owasp_category,omitempty"`
	Confidence    *string  `json:"confidence,omitempty"`

	FixAvailable  bool    `json:"fix_available"`
	FixSuggestion *string `json:"fix_suggestion,omitempty"`

	Metadata interface{} `json:"metadata,omitempty"`
}

// ============================================================================
// Handlers - Code Quality Results
// ============================================================================

// List code quality results with filtering
func (h *Handler) listCodeQualityResults(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Filters
	tool := c.Query("tool")
	projectKey := c.Query("project_key")
	commitSHA := c.Query("commit_sha")
	qualityGate := c.Query("quality_gate")
	limitStr := c.DefaultQuery("limit", "100")

	limit, _ := strconv.Atoi(limitStr)
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	query := `
		SELECT
			id, org_id, deployment_id, tool, tool_version, project_key, project_name,
			git_repo, git_branch, commit_sha, commit_author,
			bugs, vulnerabilities, code_smells, security_hotspots,
			critical_issues, high_issues, medium_issues, low_issues, info_issues,
			coverage, complexity, duplication, technical_debt_minutes,
			quality_gate, quality_gate_details,
			scan_duration_ms, lines_of_code, files_analyzed,
			created_at, updated_at
		FROM code_quality_results
		WHERE org_id = $1
	`

	args := []interface{}{orgID}
	argCount := 1

	if tool != "" {
		argCount++
		query += fmt.Sprintf(" AND tool = $%d", argCount)
		args = append(args, tool)
	}

	if projectKey != "" {
		argCount++
		query += fmt.Sprintf(" AND project_key = $%d", argCount)
		args = append(args, projectKey)
	}

	if commitSHA != "" {
		argCount++
		query += fmt.Sprintf(" AND commit_sha = $%d", argCount)
		args = append(args, commitSHA)
	}

	if qualityGate != "" {
		argCount++
		query += fmt.Sprintf(" AND quality_gate = $%d", argCount)
		args = append(args, qualityGate)
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", argCount+1)
	args = append(args, limit)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query results"})
		return
	}
	defer rows.Close()

	var results []CodeQualityResult
	for rows.Next() {
		var r CodeQualityResult
		err := rows.Scan(
			&r.ID, &r.OrgID, &r.DeploymentID, &r.Tool, &r.ToolVersion, &r.ProjectKey, &r.ProjectName,
			&r.GitRepo, &r.GitBranch, &r.CommitSHA, &r.CommitAuthor,
			&r.Bugs, &r.Vulnerabilities, &r.CodeSmells, &r.SecurityHotspots,
			&r.CriticalIssues, &r.HighIssues, &r.MediumIssues, &r.LowIssues, &r.InfoIssues,
			&r.Coverage, &r.Complexity, &r.Duplication, &r.TechnicalDebtMinutes,
			&r.QualityGate, &r.QualityGateDetails,
			&r.ScanDurationMS, &r.LinesOfCode, &r.FilesAnalyzed,
			&r.CreatedAt, &r.UpdatedAt,
		)
		if err != nil {
			continue
		}
		results = append(results, r)
	}

	// Get total count
	countQuery := `SELECT COUNT(*) FROM code_quality_results WHERE org_id = $1`
	var totalCount int
	_ = h.db.QueryRow(c.Request.Context(), countQuery, orgID).Scan(&totalCount)

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"count":   len(results),
		"total":   totalCount,
	})
}

// Get a specific code quality result
func (h *Handler) getCodeQualityResult(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	resultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid result ID"})
		return
	}

	query := `
		SELECT
			id, org_id, deployment_id, tool, tool_version, project_key, project_name,
			git_repo, git_branch, commit_sha, commit_author,
			bugs, vulnerabilities, code_smells, security_hotspots,
			critical_issues, high_issues, medium_issues, low_issues, info_issues,
			coverage, complexity, duplication, technical_debt_minutes,
			quality_gate, quality_gate_details,
			scan_duration_ms, lines_of_code, files_analyzed,
			raw_report,
			created_at, updated_at
		FROM code_quality_results
		WHERE id = $1 AND org_id = $2
	`

	var r CodeQualityResult
	err = h.db.QueryRow(c.Request.Context(), query, resultID, orgID).Scan(
		&r.ID, &r.OrgID, &r.DeploymentID, &r.Tool, &r.ToolVersion, &r.ProjectKey, &r.ProjectName,
		&r.GitRepo, &r.GitBranch, &r.CommitSHA, &r.CommitAuthor,
		&r.Bugs, &r.Vulnerabilities, &r.CodeSmells, &r.SecurityHotspots,
		&r.CriticalIssues, &r.HighIssues, &r.MediumIssues, &r.LowIssues, &r.InfoIssues,
		&r.Coverage, &r.Complexity, &r.Duplication, &r.TechnicalDebtMinutes,
		&r.QualityGate, &r.QualityGateDetails,
		&r.ScanDurationMS, &r.LinesOfCode, &r.FilesAnalyzed,
		&r.RawReport,
		&r.CreatedAt, &r.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Result not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query result"})
		return
	}

	c.JSON(http.StatusOK, r)
}

// Create a new code quality result
func (h *Handler) createCodeQualityResult(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req CreateCodeQualityResultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Start transaction
	tx, err := h.db.Begin(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to begin transaction"})
		return
	}
	defer tx.Rollback(c.Request.Context())

	// Insert code quality result
	var resultID uuid.UUID
	query := `
		INSERT INTO code_quality_results (
			org_id, deployment_id, tool, tool_version, project_key, project_name,
			git_repo, git_branch, commit_sha, commit_author,
			bugs, vulnerabilities, code_smells, security_hotspots,
			critical_issues, high_issues, medium_issues, low_issues, info_issues,
			coverage, complexity, duplication, technical_debt_minutes,
			quality_gate, quality_gate_details,
			scan_duration_ms, lines_of_code, files_analyzed,
			raw_report
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19,
			$20, $21, $22, $23, $24, $25, $26, $27, $28, $29
		) RETURNING id
	`

	err = tx.QueryRow(c.Request.Context(), query,
		orgID, req.DeploymentID, req.Tool, req.ToolVersion, req.ProjectKey, req.ProjectName,
		req.GitRepo, req.GitBranch, req.CommitSHA, req.CommitAuthor,
		req.Bugs, req.Vulnerabilities, req.CodeSmells, req.SecurityHotspots,
		req.CriticalIssues, req.HighIssues, req.MediumIssues, req.LowIssues, req.InfoIssues,
		req.Coverage, req.Complexity, req.Duplication, req.TechnicalDebtMinutes,
		req.QualityGate, req.QualityGateDetails,
		req.ScanDurationMS, req.LinesOfCode, req.FilesAnalyzed,
		req.RawReport,
	).Scan(&resultID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create result"})
		return
	}

	// Insert issues if provided
	if len(req.Issues) > 0 {
		issueQuery := `
			INSERT INTO code_quality_issues (
				code_quality_result_id, issue_key, rule_id, rule_name,
				severity, issue_type, file_path, start_line, end_line, start_column, end_column,
				message, description, cwe_ids, owasp_category, confidence,
				fix_available, fix_suggestion, metadata
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
			)
		`

		for _, issue := range req.Issues {
			_, err = tx.Exec(c.Request.Context(), issueQuery,
				resultID, issue.IssueKey, issue.RuleID, issue.RuleName,
				issue.Severity, issue.IssueType, issue.FilePath, issue.StartLine, issue.EndLine,
				issue.StartColumn, issue.EndColumn, issue.Message, issue.Description,
				issue.CWEIDs, issue.OWASPCategory, issue.Confidence,
				issue.FixAvailable, issue.FixSuggestion, issue.Metadata,
			)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create issue"})
				return
			}
		}
	}

	// Evaluate policies
	_, err = tx.Exec(c.Request.Context(), "SELECT evaluate_code_quality_policies($1)", resultID)
	if err != nil {
		// Don't fail the request if policy evaluation fails, just log it
		fmt.Printf("Failed to evaluate policies: %v\n", err)
	}

	// Commit transaction
	if err := tx.Commit(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":      resultID,
		"message": "Code quality result created successfully",
	})
}

// Get issues for a code quality result
func (h *Handler) getCodeQualityIssues(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	resultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid result ID"})
		return
	}

	// Verify result belongs to org
	var exists bool
	err = h.db.QueryRow(c.Request.Context(),
		"SELECT EXISTS(SELECT 1 FROM code_quality_results WHERE id = $1 AND org_id = $2)",
		resultID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Result not found"})
		return
	}

	// Get issues
	severity := c.Query("severity")
	issueType := c.Query("issue_type")

	query := `
		SELECT
			id, code_quality_result_id, issue_key, rule_id, rule_name,
			severity, issue_type, file_path, start_line, end_line, start_column, end_column,
			message, description, cwe_ids, owasp_category, confidence,
			fix_available, fix_suggestion, metadata, created_at
		FROM code_quality_issues
		WHERE code_quality_result_id = $1
	`

	args := []interface{}{resultID}
	argCount := 1

	if severity != "" {
		argCount++
		query += fmt.Sprintf(" AND severity = $%d", argCount)
		args = append(args, severity)
	}

	if issueType != "" {
		argCount++
		query += fmt.Sprintf(" AND issue_type = $%d", argCount)
		args = append(args, issueType)
	}

	query += " ORDER BY severity DESC, file_path, start_line"

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query issues"})
		return
	}
	defer rows.Close()

	var issues []CodeQualityIssue
	for rows.Next() {
		var i CodeQualityIssue
		err := rows.Scan(
			&i.ID, &i.CodeQualityResultID, &i.IssueKey, &i.RuleID, &i.RuleName,
			&i.Severity, &i.IssueType, &i.FilePath, &i.StartLine, &i.EndLine, &i.StartColumn, &i.EndColumn,
			&i.Message, &i.Description, &i.CWEIDs, &i.OWASPCategory, &i.Confidence,
			&i.FixAvailable, &i.FixSuggestion, &i.Metadata, &i.CreatedAt,
		)
		if err != nil {
			continue
		}
		issues = append(issues, i)
	}

	c.JSON(http.StatusOK, gin.H{
		"issues": issues,
		"count":  len(issues),
	})
}

// ============================================================================
// Handlers - Project Summaries & Leaderboard
// ============================================================================

// Get project quality summary
func (h *Handler) getProjectQualitySummary(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT
			org_id, project_key, project_name, tool, total_scans,
			avg_coverage, avg_complexity, avg_duplication,
			total_bugs, total_vulnerabilities, total_code_smells, total_critical, total_high,
			failed_gates, passed_gates, last_scan_at
		FROM v_project_quality_summary
		WHERE org_id = $1
		ORDER BY last_scan_at DESC
	`

	rows, err := h.db.Query(c.Request.Context(), query, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query summary"})
		return
	}
	defer rows.Close()

	var summaries []ProjectQualitySummary
	for rows.Next() {
		var s ProjectQualitySummary
		err := rows.Scan(
			&s.OrgID, &s.ProjectKey, &s.ProjectName, &s.Tool, &s.TotalScans,
			&s.AvgCoverage, &s.AvgComplexity, &s.AvgDuplication,
			&s.TotalBugs, &s.TotalVulnerabilities, &s.TotalCodeSmells, &s.TotalCritical, &s.TotalHigh,
			&s.FailedGates, &s.PassedGates, &s.LastScanAt,
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

// Get code quality leaderboard
func (h *Handler) getCodeQualityLeaderboard(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT
			org_id, project_key, project_name, tool,
			coverage, complexity, total_issues, critical_issues, high_issues,
			quality_gate, last_scan_at, quality_score
		FROM v_code_quality_leaderboard
		WHERE org_id = $1
		ORDER BY quality_score DESC
		LIMIT 50
	`

	rows, err := h.db.Query(c.Request.Context(), query, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query leaderboard"})
		return
	}
	defer rows.Close()

	var leaderboard []QualityLeaderboard
	for rows.Next() {
		var l QualityLeaderboard
		err := rows.Scan(
			&l.OrgID, &l.ProjectKey, &l.ProjectName, &l.Tool,
			&l.Coverage, &l.Complexity, &l.TotalIssues, &l.CriticalIssues, &l.HighIssues,
			&l.QualityGate, &l.LastScanAt, &l.QualityScore,
		)
		if err != nil {
			continue
		}
		leaderboard = append(leaderboard, l)
	}

	c.JSON(http.StatusOK, gin.H{
		"leaderboard": leaderboard,
		"count":       len(leaderboard),
	})
}

// ============================================================================
// Handlers - Policies
// ============================================================================

// List code quality policies
func (h *Handler) listCodeQualityPolicies(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT
			id, org_id, name, description, environments, projects, tools,
			max_critical, max_high, max_medium, max_vulnerabilities, max_bugs, max_code_smells,
			min_coverage, max_complexity, max_duplication,
			enforcement, block_deployment, version, enabled,
			created_by, created_at, updated_at
		FROM code_quality_policies
		WHERE org_id = $1
		ORDER BY created_at DESC
	`

	rows, err := h.db.Query(c.Request.Context(), query, orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query policies"})
		return
	}
	defer rows.Close()

	var policies []CodeQualityPolicy
	for rows.Next() {
		var p CodeQualityPolicy
		err := rows.Scan(
			&p.ID, &p.OrgID, &p.Name, &p.Description, &p.Environments, &p.Projects, &p.Tools,
			&p.MaxCritical, &p.MaxHigh, &p.MaxMedium, &p.MaxVulnerabilities, &p.MaxBugs, &p.MaxCodeSmells,
			&p.MinCoverage, &p.MaxComplexity, &p.MaxDuplication,
			&p.Enforcement, &p.BlockDeployment, &p.Version, &p.Enabled,
			&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		)
		if err != nil {
			continue
		}
		policies = append(policies, p)
	}

	c.JSON(http.StatusOK, gin.H{
		"policies": policies,
		"count":    len(policies),
	})
}

// Create a code quality policy
func (h *Handler) createCodeQualityPolicy(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	userID := c.MustGet("user_id").(uuid.UUID)

	var policy CodeQualityPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Defaults
	if policy.Environments == nil {
		policy.Environments = []string{}
	}
	if policy.Projects == nil {
		policy.Projects = []string{}
	}
	if policy.Tools == nil {
		policy.Tools = []string{}
	}

	query := `
		INSERT INTO code_quality_policies (
			org_id, name, description, environments, projects, tools,
			max_critical, max_high, max_medium, max_vulnerabilities, max_bugs, max_code_smells,
			min_coverage, max_complexity, max_duplication,
			enforcement, block_deployment, enabled, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		) RETURNING id, version, created_at, updated_at
	`

	err := h.db.QueryRow(c.Request.Context(), query,
		orgID, policy.Name, policy.Description, policy.Environments, policy.Projects, policy.Tools,
		policy.MaxCritical, policy.MaxHigh, policy.MaxMedium, policy.MaxVulnerabilities, policy.MaxBugs, policy.MaxCodeSmells,
		policy.MinCoverage, policy.MaxComplexity, policy.MaxDuplication,
		policy.Enforcement, policy.BlockDeployment, policy.Enabled, userID,
	).Scan(&policy.ID, &policy.Version, &policy.CreatedAt, &policy.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create policy"})
		return
	}

	policy.OrgID = orgID
	policy.CreatedBy = &userID

	c.JSON(http.StatusCreated, policy)
}

// Update a code quality policy
func (h *Handler) updateCodeQualityPolicy(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	policyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID"})
		return
	}

	var policy CodeQualityPolicy
	if err := c.ShouldBindJSON(&policy); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := `
		UPDATE code_quality_policies SET
			name = $1, description = $2, environments = $3, projects = $4, tools = $5,
			max_critical = $6, max_high = $7, max_medium = $8,
			max_vulnerabilities = $9, max_bugs = $10, max_code_smells = $11,
			min_coverage = $12, max_complexity = $13, max_duplication = $14,
			enforcement = $15, block_deployment = $16, enabled = $17,
			updated_at = NOW()
		WHERE id = $18 AND org_id = $19
	`

	result, err := h.db.Exec(c.Request.Context(), query,
		policy.Name, policy.Description, policy.Environments, policy.Projects, policy.Tools,
		policy.MaxCritical, policy.MaxHigh, policy.MaxMedium,
		policy.MaxVulnerabilities, policy.MaxBugs, policy.MaxCodeSmells,
		policy.MinCoverage, policy.MaxComplexity, policy.MaxDuplication,
		policy.Enforcement, policy.BlockDeployment, policy.Enabled,
		policyID, orgID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update policy"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Policy updated successfully"})
}

// Delete a code quality policy
func (h *Handler) deleteCodeQualityPolicy(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	policyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid policy ID"})
		return
	}

	result, err := h.db.Exec(c.Request.Context(),
		"DELETE FROM code_quality_policies WHERE id = $1 AND org_id = $2",
		policyID, orgID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete policy"})
		return
	}

	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Policy not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Policy deleted successfully"})
}

// Get policy evaluations for a code quality result
func (h *Handler) getCodeQualityPolicyEvaluations(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	resultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid result ID"})
		return
	}

	// Verify result belongs to org
	var exists bool
	err = h.db.QueryRow(c.Request.Context(),
		"SELECT EXISTS(SELECT 1 FROM code_quality_results WHERE id = $1 AND org_id = $2)",
		resultID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Result not found"})
		return
	}

	query := `
		SELECT id, code_quality_result_id, policy_id, decision, reason, violations, evaluation_time_ms, created_at
		FROM code_quality_policy_evaluations
		WHERE code_quality_result_id = $1
		ORDER BY created_at DESC
	`

	rows, err := h.db.Query(c.Request.Context(), query, resultID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query evaluations"})
		return
	}
	defer rows.Close()

	var evaluations []PolicyEvaluation
	for rows.Next() {
		var e PolicyEvaluation
		err := rows.Scan(&e.ID, &e.CodeQualityResultID, &e.PolicyID, &e.Decision, &e.Reason, &e.Violations, &e.EvaluationTimeMS, &e.CreatedAt)
		if err != nil {
			continue
		}
		evaluations = append(evaluations, e)
	}

	c.JSON(http.StatusOK, gin.H{
		"evaluations": evaluations,
		"count":       len(evaluations),
	})
}

// Manually evaluate policies for a code quality result
func (h *Handler) evaluateCodeQualityPolicies(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	resultID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid result ID"})
		return
	}

	// Verify result belongs to org
	var exists bool
	err = h.db.QueryRow(c.Request.Context(),
		"SELECT EXISTS(SELECT 1 FROM code_quality_results WHERE id = $1 AND org_id = $2)",
		resultID, orgID).Scan(&exists)
	if err != nil || !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Result not found"})
		return
	}

	// Call evaluation function
	type EvalResult struct {
		PolicyID   uuid.UUID
		PolicyName string
		Decision   string
		Reason     string
	}

	query := `SELECT * FROM evaluate_code_quality_policies($1)`
	rows, err := h.db.Query(context.Background(), query, resultID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to evaluate policies"})
		return
	}
	defer rows.Close()

	var results []EvalResult
	for rows.Next() {
		var r EvalResult
		if err := rows.Scan(&r.PolicyID, &r.PolicyName, &r.Decision, &r.Reason); err != nil {
			continue
		}
		results = append(results, r)
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"count":   len(results),
	})
}
