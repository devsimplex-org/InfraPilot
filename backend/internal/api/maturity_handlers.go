package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ==================== Types ====================

type SecurityScore struct {
	ID                     uuid.UUID `json:"id"`
	OrgID                  uuid.UUID `json:"org_id"`
	ScopeType              string    `json:"scope_type"`
	ScopeReference         string    `json:"scope_reference"`
	OverallScore           int       `json:"overall_score"`
	VulnerabilityScore     *int      `json:"vulnerability_score,omitempty"`
	PolicyScore            *int      `json:"policy_score,omitempty"`
	DeploymentScore        *int      `json:"deployment_score,omitempty"`
	ExceptionScore         *int      `json:"exception_score,omitempty"`
	ResponseScore          *int      `json:"response_score,omitempty"`
	TotalDeployments       int       `json:"total_deployments"`
	VulnerableDeployments  int       `json:"vulnerable_deployments"`
	CriticalVulns          int       `json:"critical_vulnerabilities"`
	HighVulns              int       `json:"high_vulnerabilities"`
	PolicyViolations       int       `json:"policy_violations"`
	ActiveExceptions       int       `json:"active_exceptions"`
	MeanTimeToFixHours     *float64  `json:"mean_time_to_fix_hours,omitempty"`
	CalculatedAt           time.Time `json:"calculated_at"`
	PeriodStart            time.Time `json:"period_start"`
	PeriodEnd              time.Time `json:"period_end"`
	CreatedAt              time.Time `json:"created_at"`
}

type TeamLeaderboard struct {
	OrgID              uuid.UUID `json:"org_id"`
	TeamName           string    `json:"team_name"`
	OverallScore       int       `json:"overall_score"`
	Rank               int       `json:"rank"`
	VulnerabilityScore *int      `json:"vulnerability_score,omitempty"`
	PolicyScore        *int      `json:"policy_score,omitempty"`
	ResponseScore      *int      `json:"response_score,omitempty"`
	CalculatedAt       time.Time `json:"calculated_at"`
}

type SecurityMetric struct {
	ID             uuid.UUID  `json:"id"`
	OrgID          uuid.UUID  `json:"org_id"`
	ScopeType      string     `json:"scope_type"`
	ScopeReference string     `json:"scope_reference"`
	MetricName     string     `json:"metric_name"`
	MetricValue    float64    `json:"metric_value"`
	MetricUnit     *string    `json:"metric_unit,omitempty"`
	RecordedAt     time.Time  `json:"recorded_at"`
	PeriodStart    *time.Time `json:"period_start,omitempty"`
	PeriodEnd      *time.Time `json:"period_end,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

type CalculateScoreRequest struct {
	ScopeType      string `json:"scope_type" binding:"required,oneof=organization team service"`
	ScopeReference string `json:"scope_reference" binding:"required"`
	PeriodDays     *int   `json:"period_days,omitempty"` // Default 30 days
}

// ==================== Security Scores Handlers ====================

func (h *Handler) listSecurityScores(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	scopeType := c.Query("scope_type")
	scopeReference := c.Query("scope_reference")
	limit := c.DefaultQuery("limit", "100")

	query := `
		SELECT id, org_id, scope_type, scope_reference,
		       overall_score, vulnerability_score, policy_score, deployment_score,
		       exception_score, response_score,
		       total_deployments, vulnerable_deployments,
		       critical_vulnerabilities, high_vulnerabilities,
		       policy_violations, active_exceptions, mean_time_to_fix_hours,
		       calculated_at, period_start, period_end, created_at
		FROM security_scores
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argIdx := 2

	if scopeType != "" {
		query += ` AND scope_type = $` + string(rune('0'+argIdx))
		args = append(args, scopeType)
		argIdx++
	}

	if scopeReference != "" {
		query += ` AND scope_reference = $` + string(rune('0'+argIdx))
		args = append(args, scopeReference)
		argIdx++
	}

	query += ` ORDER BY calculated_at DESC LIMIT $` + string(rune('0'+argIdx))
	args = append(args, limit)

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to list security scores", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list security scores"})
		return
	}
	defer rows.Close()

	var scores []SecurityScore
	for rows.Next() {
		var s SecurityScore
		err := rows.Scan(
			&s.ID, &s.OrgID, &s.ScopeType, &s.ScopeReference,
			&s.OverallScore, &s.VulnerabilityScore, &s.PolicyScore, &s.DeploymentScore,
			&s.ExceptionScore, &s.ResponseScore,
			&s.TotalDeployments, &s.VulnerableDeployments,
			&s.CriticalVulns, &s.HighVulns,
			&s.PolicyViolations, &s.ActiveExceptions, &s.MeanTimeToFixHours,
			&s.CalculatedAt, &s.PeriodStart, &s.PeriodEnd, &s.CreatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan security score", zap.Error(err))
			continue
		}
		scores = append(scores, s)
	}

	c.JSON(http.StatusOK, gin.H{
		"scores": scores,
		"count":  len(scores),
	})
}

func (h *Handler) getLatestTeamScores(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT org_id, team_name, overall_score,
		       vulnerability_score, policy_score, deployment_score,
		       exception_score, response_score,
		       total_deployments, vulnerable_deployments,
		       critical_vulnerabilities, high_vulnerabilities,
		       mean_time_to_fix_hours, calculated_at
		FROM v_latest_team_scores
		WHERE org_id = $1
		ORDER BY overall_score DESC
	`

	rows, err := h.db.Query(c.Request.Context(), query, orgID)
	if err != nil {
		h.logger.Error("failed to get latest team scores", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get team scores"})
		return
	}
	defer rows.Close()

	type TeamScore struct {
		OrgID              uuid.UUID `json:"org_id"`
		TeamName           string    `json:"team_name"`
		OverallScore       int       `json:"overall_score"`
		VulnerabilityScore *int      `json:"vulnerability_score,omitempty"`
		PolicyScore        *int      `json:"policy_score,omitempty"`
		DeploymentScore    *int      `json:"deployment_score,omitempty"`
		ExceptionScore     *int      `json:"exception_score,omitempty"`
		ResponseScore      *int      `json:"response_score,omitempty"`
		TotalDeployments   int       `json:"total_deployments"`
		VulnerableDeployments int    `json:"vulnerable_deployments"`
		CriticalVulns      int       `json:"critical_vulnerabilities"`
		HighVulns          int       `json:"high_vulnerabilities"`
		MeanTimeToFixHours *float64  `json:"mean_time_to_fix_hours,omitempty"`
		CalculatedAt       time.Time `json:"calculated_at"`
	}

	var teamScores []TeamScore
	for rows.Next() {
		var ts TeamScore
		err := rows.Scan(
			&ts.OrgID, &ts.TeamName, &ts.OverallScore,
			&ts.VulnerabilityScore, &ts.PolicyScore, &ts.DeploymentScore,
			&ts.ExceptionScore, &ts.ResponseScore,
			&ts.TotalDeployments, &ts.VulnerableDeployments,
			&ts.CriticalVulns, &ts.HighVulns,
			&ts.MeanTimeToFixHours, &ts.CalculatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan team score", zap.Error(err))
			continue
		}
		teamScores = append(teamScores, ts)
	}

	c.JSON(http.StatusOK, gin.H{
		"team_scores": teamScores,
		"count":       len(teamScores),
	})
}

func (h *Handler) getTeamLeaderboard(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	query := `
		SELECT org_id, team_name, overall_score, rank,
		       vulnerability_score, policy_score, response_score, calculated_at
		FROM v_team_leaderboard
		WHERE org_id = $1
		ORDER BY rank
		LIMIT 50
	`

	rows, err := h.db.Query(c.Request.Context(), query, orgID)
	if err != nil {
		h.logger.Error("failed to get team leaderboard", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get leaderboard"})
		return
	}
	defer rows.Close()

	var leaderboard []TeamLeaderboard
	for rows.Next() {
		var tl TeamLeaderboard
		err := rows.Scan(
			&tl.OrgID, &tl.TeamName, &tl.OverallScore, &tl.Rank,
			&tl.VulnerabilityScore, &tl.PolicyScore, &tl.ResponseScore, &tl.CalculatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan leaderboard entry", zap.Error(err))
			continue
		}
		leaderboard = append(leaderboard, tl)
	}

	c.JSON(http.StatusOK, gin.H{
		"leaderboard": leaderboard,
		"count":       len(leaderboard),
	})
}

func (h *Handler) calculateSecurityScore(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req CalculateScoreRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Default period: last 30 days
	periodDays := 30
	if req.PeriodDays != nil {
		periodDays = *req.PeriodDays
	}

	periodEnd := time.Now()
	periodStart := periodEnd.AddDate(0, 0, -periodDays)

	// Only support team scoring for now
	if req.ScopeType != "team" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only team scoring is supported"})
		return
	}

	// Call database function to calculate score
	var scoreID uuid.UUID
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT calculate_team_security_score($1, $2, $3, $4)
	`, orgID, req.ScopeReference, periodStart, periodEnd).Scan(&scoreID)

	if err != nil {
		h.logger.Error("failed to calculate security score",
			zap.Error(err),
			zap.String("team", req.ScopeReference),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to calculate score"})
		return
	}

	h.logger.Info("security score calculated",
		zap.String("score_id", scoreID.String()),
		zap.String("scope_type", req.ScopeType),
		zap.String("scope_reference", req.ScopeReference),
	)

	// Retrieve and return the calculated score
	var score SecurityScore
	err = h.db.QueryRow(c.Request.Context(), `
		SELECT id, org_id, scope_type, scope_reference,
		       overall_score, vulnerability_score, policy_score, deployment_score,
		       exception_score, response_score,
		       total_deployments, vulnerable_deployments,
		       critical_vulnerabilities, high_vulnerabilities,
		       policy_violations, active_exceptions, mean_time_to_fix_hours,
		       calculated_at, period_start, period_end, created_at
		FROM security_scores
		WHERE id = $1
	`, scoreID).Scan(
		&score.ID, &score.OrgID, &score.ScopeType, &score.ScopeReference,
		&score.OverallScore, &score.VulnerabilityScore, &score.PolicyScore, &score.DeploymentScore,
		&score.ExceptionScore, &score.ResponseScore,
		&score.TotalDeployments, &score.VulnerableDeployments,
		&score.CriticalVulns, &score.HighVulns,
		&score.PolicyViolations, &score.ActiveExceptions, &score.MeanTimeToFixHours,
		&score.CalculatedAt, &score.PeriodStart, &score.PeriodEnd, &score.CreatedAt,
	)

	if err != nil {
		h.logger.Error("failed to retrieve calculated score", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve score"})
		return
	}

	c.JSON(http.StatusCreated, score)
}

func (h *Handler) getScoreTrend(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	scopeType := c.Query("scope_type")
	scopeReference := c.Query("scope_reference")

	if scopeType == "" || scopeReference == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scope_type and scope_reference are required"})
		return
	}

	// Get scores for the last 90 days
	query := `
		SELECT id, overall_score, vulnerability_score, policy_score,
		       response_score, calculated_at, period_start, period_end
		FROM security_scores
		WHERE org_id = $1
		  AND scope_type = $2
		  AND scope_reference = $3
		  AND calculated_at >= NOW() - INTERVAL '90 days'
		ORDER BY calculated_at DESC
	`

	rows, err := h.db.Query(c.Request.Context(), query, orgID, scopeType, scopeReference)
	if err != nil {
		h.logger.Error("failed to get score trend", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get trend"})
		return
	}
	defer rows.Close()

	type TrendPoint struct {
		ID                 uuid.UUID  `json:"id"`
		OverallScore       int        `json:"overall_score"`
		VulnerabilityScore *int       `json:"vulnerability_score,omitempty"`
		PolicyScore        *int       `json:"policy_score,omitempty"`
		ResponseScore      *int       `json:"response_score,omitempty"`
		CalculatedAt       time.Time  `json:"calculated_at"`
		PeriodStart        time.Time  `json:"period_start"`
		PeriodEnd          time.Time  `json:"period_end"`
	}

	var trend []TrendPoint
	for rows.Next() {
		var tp TrendPoint
		err := rows.Scan(
			&tp.ID, &tp.OverallScore, &tp.VulnerabilityScore, &tp.PolicyScore,
			&tp.ResponseScore, &tp.CalculatedAt, &tp.PeriodStart, &tp.PeriodEnd,
		)
		if err != nil {
			h.logger.Error("failed to scan trend point", zap.Error(err))
			continue
		}
		trend = append(trend, tp)
	}

	// Calculate trend direction
	var trendDirection string
	if len(trend) >= 2 {
		latest := trend[0].OverallScore
		previous := trend[1].OverallScore
		diff := latest - previous

		if diff > 5 {
			trendDirection = "improving"
		} else if diff < -5 {
			trendDirection = "declining"
		} else {
			trendDirection = "stable"
		}
	} else {
		trendDirection = "insufficient_data"
	}

	c.JSON(http.StatusOK, gin.H{
		"scope_type":       scopeType,
		"scope_reference":  scopeReference,
		"trend":            trend,
		"trend_direction":  trendDirection,
		"data_points":      len(trend),
	})
}

// ==================== Security Metrics Handlers ====================

func (h *Handler) listSecurityMetrics(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	scopeType := c.Query("scope_type")
	scopeReference := c.Query("scope_reference")
	metricName := c.Query("metric_name")

	query := `
		SELECT id, org_id, scope_type, scope_reference,
		       metric_name, metric_value, metric_unit,
		       recorded_at, period_start, period_end, created_at
		FROM security_metrics
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argIdx := 2

	if scopeType != "" {
		query += ` AND scope_type = $` + string(rune('0'+argIdx))
		args = append(args, scopeType)
		argIdx++
	}

	if scopeReference != "" {
		query += ` AND scope_reference = $` + string(rune('0'+argIdx))
		args = append(args, scopeReference)
		argIdx++
	}

	if metricName != "" {
		query += ` AND metric_name = $` + string(rune('0'+argIdx))
		args = append(args, metricName)
		argIdx++
	}

	query += ` ORDER BY recorded_at DESC LIMIT 100`

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("failed to list security metrics", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list metrics"})
		return
	}
	defer rows.Close()

	var metrics []SecurityMetric
	for rows.Next() {
		var m SecurityMetric
		err := rows.Scan(
			&m.ID, &m.OrgID, &m.ScopeType, &m.ScopeReference,
			&m.MetricName, &m.MetricValue, &m.MetricUnit,
			&m.RecordedAt, &m.PeriodStart, &m.PeriodEnd, &m.CreatedAt,
		)
		if err != nil {
			h.logger.Error("failed to scan security metric", zap.Error(err))
			continue
		}
		metrics = append(metrics, m)
	}

	c.JSON(http.StatusOK, gin.H{
		"metrics": metrics,
		"count":   len(metrics),
	})
}

// ==================== Batch Calculate Scores ====================

func (h *Handler) calculateAllTeamScores(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Get all teams
	rows, err := h.db.Query(c.Request.Context(), `
		SELECT DISTINCT team_name FROM service_ownership WHERE org_id = $1 AND status = 'active'
	`, orgID)
	if err != nil {
		h.logger.Error("failed to get teams", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get teams"})
		return
	}
	defer rows.Close()

	var teams []string
	for rows.Next() {
		var team string
		if err := rows.Scan(&team); err != nil {
			continue
		}
		teams = append(teams, team)
	}

	// Calculate score for each team
	periodEnd := time.Now()
	periodStart := periodEnd.AddDate(0, 0, -30) // Last 30 days

	calculatedScores := 0
	for _, team := range teams {
		var scoreID uuid.UUID
		err := h.db.QueryRow(c.Request.Context(), `
			SELECT calculate_team_security_score($1, $2, $3, $4)
		`, orgID, team, periodStart, periodEnd).Scan(&scoreID)

		if err != nil {
			h.logger.Error("failed to calculate team score",
				zap.Error(err),
				zap.String("team", team),
			)
			continue
		}
		calculatedScores++
	}

	h.logger.Info("batch calculated team scores",
		zap.Int("total_teams", len(teams)),
		zap.Int("calculated", calculatedScores),
	)

	c.JSON(http.StatusOK, gin.H{
		"message":    "batch calculation complete",
		"total_teams": len(teams),
		"calculated":  calculatedScores,
	})
}
