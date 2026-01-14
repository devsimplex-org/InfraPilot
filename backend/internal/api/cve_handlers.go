package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ==================== CVE-Centric Types ====================

type CVESummary struct {
	CVEID            string   `json:"cve_id"`
	Severity         string   `json:"severity"`
	Score            *float64 `json:"cvss_v3_score,omitempty"`
	Description      string   `json:"description"`
	AffectedPackages []string `json:"affected_packages"`
	RunningCount     int      `json:"running_count"`     // Deployments running with this CVE
	BlockedCount     int      `json:"blocked_count"`     // Deployments blocked due to this CVE
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
}

type CVEDetail struct {
	CVEID                string                `json:"cve_id"`
	Severity             string                `json:"severity"`
	Score                *float64              `json:"cvss_v3_score,omitempty"`
	Description          string                `json:"description"`
	PublishedDate        *string               `json:"published_date,omitempty"`
	LastModifiedDate     *string               `json:"last_modified_date,omitempty"`
	References           []string              `json:"references,omitempty"`
	AffectedPackages     []AffectedPackageInfo `json:"affected_packages"`
	RunningDeployments   []DeploymentCVEInfo   `json:"running_deployments"`
	BlockedDeployments   []DeploymentCVEInfo   `json:"blocked_deployments"`
	FirstDetected        string                `json:"first_detected"`
	LastDetected         string                `json:"last_detected"`
	TotalOccurrences     int                   `json:"total_occurrences"`
}

type AffectedPackageInfo struct {
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	FixedVersion   string `json:"fixed_version,omitempty"`
}

type DeploymentCVEInfo struct {
	DeploymentID    string  `json:"deployment_id"`
	ServiceName     string  `json:"service_name"`
	Environment     string  `json:"environment"`
	ImageRepository string  `json:"image_repository"`
	ImageTag        string  `json:"image_tag"`
	Status          string  `json:"status"`
	CreatedAt       string  `json:"created_at"`
	PackageName     string  `json:"package_name"`
	PackageVersion  string  `json:"package_version"`
	PolicyBlocked   bool    `json:"policy_blocked"`
	PolicyReason    *string `json:"policy_reason,omitempty"`
}

// ==================== CVE Handlers ====================

// getCVESummaries returns a list of all unique CVEs with counts
func (h *Handler) getCVESummaries(c *gin.Context) {
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	// Get severity filter
	severityFilter := strings.ToLower(c.Query("severity"))

	// Query to get all unique CVEs with aggregated data
	query := `
		WITH cve_data AS (
			SELECT
				v.cve_id,
				v.severity,
				v.cvss_v3_score,
				v.description,
				v.package_name,
				MIN(v.created_at) as first_seen,
				MAX(v.created_at) as last_seen,
				d.id as deployment_id,
				d.status as deployment_status,
				d.policy_decision
			FROM vulnerabilities v
			JOIN scan_results sr ON v.scan_result_id = sr.id
			JOIN deployments d ON sr.image_digest = d.image_digest
			WHERE d.agent_id = $1 AND v.cve_id IS NOT NULL
	`

	args := []interface{}{agentID}
	if severityFilter != "" && severityFilter != "all" {
		query += " AND LOWER(v.severity) = $2"
		args = append(args, severityFilter)
	}

	query += `
			GROUP BY v.cve_id, v.severity, v.cvss_v3_score, v.description, v.package_name,
			         d.id, d.status, d.policy_decision
		)
		SELECT
			cve_id,
			severity,
			cvss_v3_score,
			description,
			ARRAY_AGG(DISTINCT package_name) as affected_packages,
			MIN(first_seen) as first_seen,
			MAX(last_seen) as last_seen,
			COUNT(DISTINCT CASE
				WHEN deployment_status IN ('running')
				THEN deployment_id
			END) as running_count,
			COUNT(DISTINCT CASE
				WHEN policy_decision::text = 'deny'
				THEN deployment_id
			END) as blocked_count
		FROM cve_data
		GROUP BY cve_id, severity, cvss_v3_score, description
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END,
			cvss_v3_score DESC NULLS LAST,
			cve_id
	`

	rows, err := h.db.Query(c, query, args...)
	if err != nil {
		h.logger.Error("failed to get CVE summaries", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch CVEs"})
		return
	}
	defer rows.Close()

	var cves []CVESummary
	for rows.Next() {
		var cve CVESummary
		var packages []string

		err := rows.Scan(
			&cve.CVEID,
			&cve.Severity,
			&cve.Score,
			&cve.Description,
			&packages,
			&cve.FirstSeen,
			&cve.LastSeen,
			&cve.RunningCount,
			&cve.BlockedCount,
		)
		if err != nil {
			h.logger.Error("failed to scan CVE row", zap.Error(err))
			continue
		}

		cve.AffectedPackages = packages
		cves = append(cves, cve)
	}

	if cves == nil {
		cves = []CVESummary{}
	}

	c.JSON(http.StatusOK, gin.H{
		"cves":  cves,
		"count": len(cves),
	})
}

// getCVEDetail returns detailed information about a specific CVE
func (h *Handler) getCVEDetail(c *gin.Context) {
	agentID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	cveID := c.Param("cve_id")
	if cveID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "CVE ID required"})
		return
	}

	// Get CVE basic info
	cveQuery := `
		SELECT
			v.cve_id,
			v.severity,
			v.cvss_v3_score,
			v.description,
			v.published_date,
			v.last_modified_date,
			MIN(v.created_at) as first_detected,
			MAX(v.created_at) as last_detected,
			COUNT(*) as total_occurrences
		FROM vulnerabilities v
		JOIN scan_results sr ON v.scan_result_id = sr.id
		JOIN deployments d ON sr.image_digest = d.image_digest
		WHERE d.agent_id = $1 AND v.cve_id = $2
		GROUP BY v.cve_id, v.severity, v.cvss_v3_score, v.description,
		         v.published_date, v.last_modified_date
	`

	var cve CVEDetail
	err = h.db.QueryRow(c, cveQuery, agentID, cveID).Scan(
		&cve.CVEID,
		&cve.Severity,
		&cve.Score,
		&cve.Description,
		&cve.PublishedDate,
		&cve.LastModifiedDate,
		&cve.FirstDetected,
		&cve.LastDetected,
		&cve.TotalOccurrences,
	)
	if err != nil {
		h.logger.Error("CVE not found", zap.String("cve_id", cveID), zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "CVE not found"})
		return
	}

	// Get affected packages
	packagesQuery := `
		SELECT DISTINCT
			v.package_name,
			v.package_version,
			v.fixed_version
		FROM vulnerabilities v
		JOIN scan_results sr ON v.scan_result_id = sr.id
		JOIN deployments d ON sr.image_digest = d.image_digest
		WHERE d.agent_id = $1 AND v.cve_id = $2
	`

	pkgRows, err := h.db.Query(c, packagesQuery, agentID, cveID)
	if err != nil {
		h.logger.Warn("failed to get affected packages", zap.Error(err))
	} else {
		defer pkgRows.Close()
		for pkgRows.Next() {
			var pkg AffectedPackageInfo
			if err := pkgRows.Scan(&pkg.PackageName, &pkg.PackageVersion, &pkg.FixedVersion); err == nil {
				cve.AffectedPackages = append(cve.AffectedPackages, pkg)
			}
		}
	}

	// Get running deployments affected by this CVE
	runningQuery := `
		SELECT DISTINCT
			d.id,
			d.service_name,
			d.environment,
			d.image_repository,
			d.image_tag,
			d.status,
			d.created_at,
			v.package_name,
			v.package_version,
			d.policy_decision::text = 'deny' as policy_blocked,
			d.policy_reason
		FROM deployments d
		JOIN scan_results sr ON d.image_digest = sr.image_digest
		JOIN vulnerabilities v ON sr.id = v.scan_result_id
		WHERE d.agent_id = $1
		  AND v.cve_id = $2
		  AND d.status IN ('running')
		ORDER BY d.created_at DESC
	`

	runningRows, err := h.db.Query(c, runningQuery, agentID, cveID)
	if err != nil {
		h.logger.Warn("failed to get running deployments", zap.Error(err))
	} else {
		defer runningRows.Close()
		for runningRows.Next() {
			var dep DeploymentCVEInfo
			if err := runningRows.Scan(
				&dep.DeploymentID,
				&dep.ServiceName,
				&dep.Environment,
				&dep.ImageRepository,
				&dep.ImageTag,
				&dep.Status,
				&dep.CreatedAt,
				&dep.PackageName,
				&dep.PackageVersion,
				&dep.PolicyBlocked,
				&dep.PolicyReason,
			); err == nil {
				cve.RunningDeployments = append(cve.RunningDeployments, dep)
			}
		}
	}

	// Get blocked deployments
	blockedQuery := `
		SELECT DISTINCT
			d.id,
			d.service_name,
			d.environment,
			d.image_repository,
			d.image_tag,
			d.status,
			d.created_at,
			v.package_name,
			v.package_version,
			true as policy_blocked,
			d.policy_reason
		FROM deployments d
		JOIN scan_results sr ON d.image_digest = sr.image_digest
		JOIN vulnerabilities v ON sr.id = v.scan_result_id
		WHERE d.agent_id = $1
		  AND v.cve_id = $2
		  AND d.policy_decision::text = 'deny'
		ORDER BY d.created_at DESC
	`

	blockedRows, err := h.db.Query(c, blockedQuery, agentID, cveID)
	if err != nil {
		h.logger.Warn("failed to get blocked deployments", zap.Error(err))
	} else {
		defer blockedRows.Close()
		for blockedRows.Next() {
			var dep DeploymentCVEInfo
			if err := blockedRows.Scan(
				&dep.DeploymentID,
				&dep.ServiceName,
				&dep.Environment,
				&dep.ImageRepository,
				&dep.ImageTag,
				&dep.Status,
				&dep.CreatedAt,
				&dep.PackageName,
				&dep.PackageVersion,
				&dep.PolicyBlocked,
				&dep.PolicyReason,
			); err == nil {
				cve.BlockedDeployments = append(cve.BlockedDeployments, dep)
			}
		}
	}

	// Initialize empty arrays if nil
	if cve.AffectedPackages == nil {
		cve.AffectedPackages = []AffectedPackageInfo{}
	}
	if cve.RunningDeployments == nil {
		cve.RunningDeployments = []DeploymentCVEInfo{}
	}
	if cve.BlockedDeployments == nil {
		cve.BlockedDeployments = []DeploymentCVEInfo{}
	}
	if cve.References == nil {
		cve.References = []string{}
	}

	c.JSON(http.StatusOK, cve)
}
