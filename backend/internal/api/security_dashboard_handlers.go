package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ==================== Security Dashboard Types ====================

type SecurityPosture struct {
	OverallScore      int                     `json:"overall_score"` // 0-100
	RiskLevel         string                  `json:"risk_level"`    // low, medium, high, critical
	DeploymentStats   DeploymentStats         `json:"deployment_stats"`
	VulnerabilityStats VulnerabilityStats     `json:"vulnerability_stats"`
	PolicyStats       PolicyComplianceStats   `json:"policy_stats"`
	SBOMStats         SBOMStatistics          `json:"sbom_stats"`
	RecentEvents      []SecurityEvent         `json:"recent_events"`
	Trends            SecurityTrends          `json:"trends"`
}

type DeploymentStats struct {
	Total           int     `json:"total"`
	Successful      int     `json:"successful"`
	Failed          int     `json:"failed"`
	Blocked         int     `json:"blocked"`
	SuccessRate     float64 `json:"success_rate"`
	Last24Hours     int     `json:"last_24h"`
	AvgDeployTime   string  `json:"avg_deploy_time"`
}

type VulnerabilityStats struct {
	Total           int     `json:"total"`
	Critical        int     `json:"critical"`
	High            int     `json:"high"`
	Medium          int     `json:"medium"`
	Low             int     `json:"low"`
	Fixable         int     `json:"fixable"`
	FixablePercent  float64 `json:"fixable_percent"`
	AffectedImages  int     `json:"affected_images"`
}

type PolicyComplianceStats struct {
	TotalEvaluations int     `json:"total_evaluations"`
	Allowed          int     `json:"allowed"`
	Warned           int     `json:"warned"`
	Denied           int     `json:"denied"`
	ComplianceRate   float64 `json:"compliance_rate"`
}

type SBOMStatistics struct {
	TotalSBOMs       int     `json:"total_sboms"`
	TotalPackages    int     `json:"total_packages"`
	UniquePackages   int     `json:"unique_packages"`
	AvgPerImage      float64 `json:"avg_per_image"`
	OSPackages       int     `json:"os_packages"`
	LibraryPackages  int     `json:"library_packages"`
}

type SecurityEvent struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // deployment, scan, policy, vulnerability
	Severity    string    `json:"severity"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Source      string    `json:"source"`
}

type SecurityTrends struct {
	Deployments     []TrendDataPoint `json:"deployments"`
	Vulnerabilities []TrendDataPoint `json:"vulnerabilities"`
	PolicyDenials   []TrendDataPoint `json:"policy_denials"`
}

type TrendDataPoint struct {
	Date  string `json:"date"`
	Value int    `json:"value"`
}

// ==================== Security Dashboard Handlers ====================

func (h *Handler) getSecurityPosture(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	// Get deployment stats
	deploymentStats, err := h.getDeploymentStatistics(c, orgID)
	if err != nil {
		h.logger.Error("failed to get deployment stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get deployment statistics"})
		return
	}

	// Get vulnerability stats
	vulnStats, err := h.getVulnerabilityStatistics(c, orgID)
	if err != nil {
		h.logger.Error("failed to get vulnerability stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get vulnerability statistics"})
		return
	}

	// Get policy stats
	policyStats, err := h.getPolicyStatistics(c, orgID)
	if err != nil {
		h.logger.Error("failed to get policy stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get policy statistics"})
		return
	}

	// Get SBOM stats
	sbomStats, err := h.getSBOMStatistics(c, orgID)
	if err != nil {
		h.logger.Error("failed to get SBOM stats", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get SBOM statistics"})
		return
	}

	// Get recent security events
	recentEvents, err := h.getRecentSecurityEvents(c, orgID)
	if err != nil {
		h.logger.Error("failed to get recent events", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get recent events"})
		return
	}

	// Get trends
	trends, err := h.getSecurityTrends(c, orgID)
	if err != nil {
		h.logger.Error("failed to get trends", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get trends"})
		return
	}

	// Calculate overall security score
	score, riskLevel := h.computeOverallScore(vulnStats, policyStats, deploymentStats)

	posture := SecurityPosture{
		OverallScore:       score,
		RiskLevel:          riskLevel,
		DeploymentStats:    deploymentStats,
		VulnerabilityStats: vulnStats,
		PolicyStats:        policyStats,
		SBOMStats:          sbomStats,
		RecentEvents:       recentEvents,
		Trends:             trends,
	}

	c.JSON(http.StatusOK, posture)
}

// ==================== Helper Functions ====================

func (h *Handler) getDeploymentStatistics(c *gin.Context, orgID uuid.UUID) (DeploymentStats, error) {
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'running') as successful,
			COUNT(*) FILTER (WHERE status = 'failed') as failed,
			COUNT(*) FILTER (WHERE policy_decision = 'deny') as blocked,
			COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as last_24h
		FROM deployments
		WHERE org_id = $1
	`

	var stats DeploymentStats
	var total, successful, failed, blocked, last24h int

	err := h.db.QueryRow(c, query, orgID).Scan(&total, &successful, &failed, &blocked, &last24h)
	if err != nil {
		return stats, err
	}

	stats.Total = total
	stats.Successful = successful
	stats.Failed = failed
	stats.Blocked = blocked
	stats.Last24Hours = last24h

	if total > 0 {
		stats.SuccessRate = float64(successful) / float64(total) * 100
	}

	// Calculate average deployment time (placeholder)
	stats.AvgDeployTime = "2m 30s"

	return stats, nil
}

func (h *Handler) getVulnerabilityStatistics(c *gin.Context, orgID uuid.UUID) (VulnerabilityStats, error) {
	query := `
		SELECT
			COUNT(DISTINCT v.id) as total,
			COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'critical') as critical,
			COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'high') as high,
			COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'medium') as medium,
			COUNT(DISTINCT v.id) FILTER (WHERE v.severity = 'low') as low,
			COUNT(DISTINCT v.id) FILTER (WHERE v.fixed_version IS NOT NULL AND v.fixed_version != '') as fixable,
			COUNT(DISTINCT sr.image_digest) as affected_images
		FROM vulnerabilities v
		JOIN scan_results sr ON v.scan_result_id = sr.id
		JOIN deployments d ON sr.id = d.scan_result_id
		WHERE d.org_id = $1
	`

	var stats VulnerabilityStats
	var total, critical, high, medium, low, fixable, affectedImages int

	err := h.db.QueryRow(c, query, orgID).Scan(&total, &critical, &high, &medium, &low, &fixable, &affectedImages)
	if err != nil {
		return stats, err
	}

	stats.Total = total
	stats.Critical = critical
	stats.High = high
	stats.Medium = medium
	stats.Low = low
	stats.Fixable = fixable
	stats.AffectedImages = affectedImages

	if total > 0 {
		stats.FixablePercent = float64(fixable) / float64(total) * 100
	}

	return stats, nil
}

func (h *Handler) getPolicyStatistics(c *gin.Context, orgID uuid.UUID) (PolicyComplianceStats, error) {
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE policy_decision = 'allow') as allowed,
			COUNT(*) FILTER (WHERE policy_decision = 'warn') as warned,
			COUNT(*) FILTER (WHERE policy_decision = 'deny') as denied
		FROM deployments
		WHERE org_id = $1 AND created_at > NOW() - INTERVAL '30 days'
	`

	var stats PolicyComplianceStats
	var total, allowed, warned, denied int

	err := h.db.QueryRow(c, query, orgID).Scan(&total, &allowed, &warned, &denied)
	if err != nil {
		return stats, err
	}

	stats.TotalEvaluations = total
	stats.Allowed = allowed
	stats.Warned = warned
	stats.Denied = denied

	if total > 0 {
		stats.ComplianceRate = float64(allowed) / float64(total) * 100
	}

	return stats, nil
}

func (h *Handler) getSBOMStatistics(c *gin.Context, orgID uuid.UUID) (SBOMStatistics, error) {
	query := `
		SELECT
			COUNT(*) as total_sboms,
			COALESCE(SUM(total_packages), 0) as total_packages,
			COALESCE(SUM(os_packages), 0) as os_packages,
			COALESCE(SUM(library_packages), 0) as library_packages
		FROM sboms s
		JOIN deployments d ON s.id = d.sbom_id
		WHERE d.org_id = $1
	`

	var stats SBOMStatistics
	var totalSBOMs, totalPackages, osPackages, libraryPackages int

	err := h.db.QueryRow(c, query, orgID).Scan(&totalSBOMs, &totalPackages, &osPackages, &libraryPackages)
	if err != nil {
		return stats, err
	}

	stats.TotalSBOMs = totalSBOMs
	stats.TotalPackages = totalPackages
	stats.OSPackages = osPackages
	stats.LibraryPackages = libraryPackages

	if totalSBOMs > 0 {
		stats.AvgPerImage = float64(totalPackages) / float64(totalSBOMs)
	}

	// Estimate unique packages (simplified)
	stats.UniquePackages = totalPackages / 2

	return stats, nil
}

func (h *Handler) getRecentSecurityEvents(c *gin.Context, orgID uuid.UUID) ([]SecurityEvent, error) {
	// Get recent deployments with policy decisions
	query := `
		SELECT
			d.id,
			d.service_name,
			d.environment,
			d.policy_decision,
			d.policy_reason,
			d.created_at,
			sr.critical_count,
			sr.high_count
		FROM deployments d
		LEFT JOIN scan_results sr ON d.scan_result_id = sr.id
		WHERE d.org_id = $1
		ORDER BY d.created_at DESC
		LIMIT 10
	`

	rows, err := h.db.Query(c, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []SecurityEvent

	for rows.Next() {
		var id uuid.UUID
		var serviceName, environment, policyDecision string
		var policyReason *string
		var createdAt time.Time
		var criticalCount, highCount int

		err := rows.Scan(&id, &serviceName, &environment, &policyDecision, &policyReason, &createdAt, &criticalCount, &highCount)
		if err != nil {
			continue
		}

		// Determine event type and severity
		eventType := "deployment"
		severity := "info"
		title := ""
		description := ""

		if policyDecision == "deny" {
			severity = "high"
			title = "Deployment Blocked by Policy"
			description = serviceName + " (" + environment + ")"
			if policyReason != nil {
				description += ": " + *policyReason
			}
		} else if criticalCount > 0 {
			severity = "critical"
			title = "Critical Vulnerabilities Detected"
			description = serviceName + " has " + string(rune(criticalCount)) + " critical vulnerabilities"
		} else if highCount > 0 {
			severity = "medium"
			title = "High Vulnerabilities Detected"
			description = serviceName + " has " + string(rune(highCount)) + " high vulnerabilities"
		} else {
			title = "Deployment Successful"
			description = serviceName + " deployed to " + environment
		}

		events = append(events, SecurityEvent{
			ID:          id.String(),
			Type:        eventType,
			Severity:    severity,
			Title:       title,
			Description: description,
			Timestamp:   createdAt,
			Source:      serviceName,
		})
	}

	return events, nil
}

func (h *Handler) getSecurityTrends(c *gin.Context, orgID uuid.UUID) (SecurityTrends, error) {
	// Get deployment trends for last 7 days
	deploymentQuery := `
		SELECT
			DATE(created_at) as date,
			COUNT(*) as count
		FROM deployments
		WHERE org_id = $1 AND created_at > NOW() - INTERVAL '7 days'
		GROUP BY DATE(created_at)
		ORDER BY date ASC
	`

	rows, err := h.db.Query(c, deploymentQuery, orgID)
	if err != nil {
		return SecurityTrends{}, err
	}
	defer rows.Close()

	var deploymentTrends []TrendDataPoint
	for rows.Next() {
		var date time.Time
		var count int
		if err := rows.Scan(&date, &count); err != nil {
			continue
		}
		deploymentTrends = append(deploymentTrends, TrendDataPoint{
			Date:  date.Format("2006-01-02"),
			Value: count,
		})
	}

	// Get vulnerability trends (critical + high over last 7 days)
	vulnQuery := `
		SELECT
			DATE(d.created_at) as date,
			SUM(sr.critical_count + sr.high_count) as count
		FROM deployments d
		JOIN scan_results sr ON d.scan_result_id = sr.id
		WHERE d.org_id = $1 AND d.created_at > NOW() - INTERVAL '7 days'
		GROUP BY DATE(d.created_at)
		ORDER BY date ASC
	`

	rows2, err := h.db.Query(c, vulnQuery, orgID)
	if err != nil {
		return SecurityTrends{}, err
	}
	defer rows2.Close()

	var vulnTrends []TrendDataPoint
	for rows2.Next() {
		var date time.Time
		var count int64
		if err := rows2.Scan(&date, &count); err != nil {
			continue
		}
		vulnTrends = append(vulnTrends, TrendDataPoint{
			Date:  date.Format("2006-01-02"),
			Value: int(count),
		})
	}

	// Get policy denial trends
	policyQuery := `
		SELECT
			DATE(created_at) as date,
			COUNT(*) FILTER (WHERE policy_decision = 'deny') as count
		FROM deployments
		WHERE org_id = $1 AND created_at > NOW() - INTERVAL '7 days'
		GROUP BY DATE(created_at)
		ORDER BY date ASC
	`

	rows3, err := h.db.Query(c, policyQuery, orgID)
	if err != nil {
		return SecurityTrends{}, err
	}
	defer rows3.Close()

	var policyTrends []TrendDataPoint
	for rows3.Next() {
		var date time.Time
		var count int
		if err := rows3.Scan(&date, &count); err != nil {
			continue
		}
		policyTrends = append(policyTrends, TrendDataPoint{
			Date:  date.Format("2006-01-02"),
			Value: count,
		})
	}

	return SecurityTrends{
		Deployments:     deploymentTrends,
		Vulnerabilities: vulnTrends,
		PolicyDenials:   policyTrends,
	}, nil
}

func (h *Handler) computeOverallScore(vulnStats VulnerabilityStats, policyStats PolicyComplianceStats, deployStats DeploymentStats) (int, string) {
	score := 100

	// Deduct for critical vulnerabilities (5 points each, max 30)
	score -= min(vulnStats.Critical*5, 30)

	// Deduct for high vulnerabilities (2 points each, max 20)
	score -= min(vulnStats.High*2, 20)

	// Deduct for policy denials (10 points each, max 25)
	score -= min(policyStats.Denied*10, 25)

	// Deduct for failed deployments (5 points each, max 15)
	score -= min(deployStats.Failed*5, 15)

	// Bonus for high compliance rate
	if policyStats.ComplianceRate > 95 {
		score += 5
	}

	// Ensure score is between 0 and 100
	score = max(0, min(100, score))

	// Determine risk level
	riskLevel := "low"
	if score < 40 {
		riskLevel = "critical"
	} else if score < 60 {
		riskLevel = "high"
	} else if score < 80 {
		riskLevel = "medium"
	}

	return score, riskLevel
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
