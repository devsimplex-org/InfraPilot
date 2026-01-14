package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ==================== Types ====================

type ScanImageRequest struct {
	Image       string `json:"image" binding:"required"`
	ImageDigest string `json:"image_digest"`
	ImageTag    string `json:"image_tag"`
}

type GenerateSBOMRequest struct {
	Image string `json:"image" binding:"required"`
}

// ==================== Trigger Image Scan ====================

func (h *Handler) triggerImageScan(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req ScanImageRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("Triggering vulnerability scan",
		zap.String("image", req.Image),
		zap.String("org_id", orgID.String()),
	)

	// Scan image with Trivy
	scanResult, err := h.scanner.ScanImage(c.Request.Context(), req.Image)
	if err != nil {
		h.logger.Error("Scan failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Scan failed: " + err.Error(),
		})
		return
	}

	// Use provided digest or the one from scan
	imageDigest := req.ImageDigest
	if imageDigest == "" {
		imageDigest = scanResult.ImageDigest
	}

	// Store scan result in database
	var scanID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO scan_results (
			org_id, image_digest, image_repository, image_tag,
			critical_count, high_count, medium_count, low_count, unknown_count,
			total_count, fixable_count,
			scanner_name, scan_duration_ms, raw_output
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id
	`, orgID, imageDigest, scanResult.ImageRepository, scanResult.ImageTag,
		scanResult.CriticalCount, scanResult.HighCount, scanResult.MediumCount,
		scanResult.LowCount, scanResult.UnknownCount,
		scanResult.TotalCount, scanResult.FixableCount,
		"trivy", scanResult.ScanDuration.Milliseconds(), scanResult.RawOutput,
	).Scan(&scanID)

	if err != nil {
		h.logger.Error("Failed to store scan result", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store scan result"})
		return
	}

	// Store individual vulnerabilities
	for _, vuln := range scanResult.Vulnerabilities {
		_, err = h.db.Exec(c.Request.Context(), `
			INSERT INTO vulnerabilities (
				scan_result_id, cve_id, severity,
				package_name, package_version, package_type,
				fixed_version, fix_available,
				title, description, cvss_v3_score, cvss_v3_vector,
				reference_urls
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		`, scanID, vuln.CVEID, strings.ToLower(vuln.Severity),
			vuln.PackageName, vuln.PackageVersion, vuln.PackageType,
			vuln.FixedVersion, vuln.FixAvailable,
			vuln.Title, vuln.Description, vuln.CVSSScore, vuln.CVSSVector,
			vuln.References,
		)
		if err != nil {
			h.logger.Warn("Failed to store vulnerability",
				zap.Error(err),
				zap.String("cve", vuln.CVEID),
			)
		}
	}

	h.logger.Info("Scan completed and stored",
		zap.String("scan_id", scanID.String()),
		zap.Int("total_vulns", scanResult.TotalCount),
	)

	c.JSON(http.StatusOK, gin.H{
		"id":             scanID,
		"image":          scanResult.ImageRepository,
		"critical":       scanResult.CriticalCount,
		"high":           scanResult.HighCount,
		"medium":         scanResult.MediumCount,
		"low":            scanResult.LowCount,
		"unknown":        scanResult.UnknownCount,
		"total":          scanResult.TotalCount,
		"fixable":        scanResult.FixableCount,
		"scan_duration":  scanResult.ScanDuration.String(),
	})
}

// ==================== List Scan Results ====================

func (h *Handler) listScans(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, image_repository, image_tag, image_digest,
		       critical_count, high_count, medium_count, low_count, unknown_count,
		       total_count, fixable_count,
		       scanner_name, scanner_version, scan_duration_ms,
		       scanned_at, created_at
		FROM scan_results
		WHERE org_id = $1
		ORDER BY scanned_at DESC
		LIMIT 100
	`, orgID)
	if err != nil {
		h.logger.Error("Failed to list scans", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list scans"})
		return
	}
	defer rows.Close()

	type ScanSummary struct {
		ID              uuid.UUID  `json:"id"`
		ImageRepository string     `json:"image_repository"`
		ImageTag        *string    `json:"image_tag"`
		ImageDigest     *string    `json:"image_digest"`
		Critical        int        `json:"critical"`
		High            int        `json:"high"`
		Medium          int        `json:"medium"`
		Low             int        `json:"low"`
		Unknown         int        `json:"unknown"`
		Total           int        `json:"total"`
		Fixable         int        `json:"fixable"`
		ScannerName     string     `json:"scanner_name"`
		ScannerVersion  *string    `json:"scanner_version"`
		ScanDurationMs  *int       `json:"scan_duration_ms"`
		ScannedAt       time.Time  `json:"scanned_at"`
		CreatedAt       time.Time  `json:"created_at"`
	}

	scans := []ScanSummary{}
	for rows.Next() {
		var s ScanSummary
		err := rows.Scan(
			&s.ID, &s.ImageRepository, &s.ImageTag, &s.ImageDigest,
			&s.Critical, &s.High, &s.Medium, &s.Low, &s.Unknown,
			&s.Total, &s.Fixable,
			&s.ScannerName, &s.ScannerVersion, &s.ScanDurationMs,
			&s.ScannedAt, &s.CreatedAt,
		)
		if err != nil {
			h.logger.Warn("Failed to scan row", zap.Error(err))
			continue
		}
		scans = append(scans, s)
	}

	c.JSON(http.StatusOK, scans)
}

// ==================== Get Scan Details ====================

func (h *Handler) getScanDetails(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	scanID := c.Param("sid")

	type ScanDetail struct {
		ID              uuid.UUID       `json:"id"`
		ImageRepository string          `json:"image_repository"`
		ImageTag        *string         `json:"image_tag"`
		ImageDigest     *string         `json:"image_digest"`
		Critical        int             `json:"critical"`
		High            int             `json:"high"`
		Medium          int             `json:"medium"`
		Low             int             `json:"low"`
		Unknown         int             `json:"unknown"`
		Total           int             `json:"total"`
		Fixable         int             `json:"fixable"`
		ScannerName     string          `json:"scanner_name"`
		ScanDurationMs  *int            `json:"scan_duration_ms"`
		ScannedAt       time.Time       `json:"scanned_at"`
	}

	var scan ScanDetail
	err := h.db.QueryRow(c.Request.Context(), `
		SELECT id, image_repository, image_tag, image_digest,
		       critical_count, high_count, medium_count, low_count, unknown_count,
		       total_count, fixable_count,
		       scanner_name, scan_duration_ms, scanned_at
		FROM scan_results
		WHERE id = $1 AND org_id = $2
	`, scanID, orgID).Scan(
		&scan.ID, &scan.ImageRepository, &scan.ImageTag, &scan.ImageDigest,
		&scan.Critical, &scan.High, &scan.Medium, &scan.Low, &scan.Unknown,
		&scan.Total, &scan.Fixable,
		&scan.ScannerName, &scan.ScanDurationMs, &scan.ScannedAt,
	)

	if err != nil {
		h.logger.Error("Scan not found", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "Scan not found"})
		return
	}

	c.JSON(http.StatusOK, scan)
}

// ==================== Get Vulnerabilities for Scan ====================

func (h *Handler) getScanVulnerabilities(c *gin.Context) {
	scanID := c.Param("sid")
	severity := c.Query("severity")

	query := `
		SELECT id, cve_id, severity, package_name, package_version, package_type,
		       fixed_version, fix_available, title, description,
		       cvss_v3_score, cvss_v3_vector, created_at
		FROM vulnerabilities
		WHERE scan_result_id = $1
	`
	args := []interface{}{scanID}

	if severity != "" {
		query += " AND severity = $2"
		args = append(args, severity)
	}
	query += " ORDER BY cvss_v3_score DESC NULLS LAST, severity DESC"

	rows, err := h.db.Query(c.Request.Context(), query, args...)
	if err != nil {
		h.logger.Error("Failed to list vulnerabilities", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list vulnerabilities"})
		return
	}
	defer rows.Close()

	type VulnDetail struct {
		ID             uuid.UUID `json:"id"`
		CVEID          string    `json:"cve_id"`
		Severity       string    `json:"severity"`
		PackageName    string    `json:"package_name"`
		PackageVersion *string   `json:"package_version"`
		PackageType    *string   `json:"package_type"`
		FixedVersion   *string   `json:"fixed_version"`
		FixAvailable   bool      `json:"fix_available"`
		Title          *string   `json:"title"`
		Description    *string   `json:"description"`
		CVSSScore      *float64  `json:"cvss_score"`
		CVSSVector     *string   `json:"cvss_vector"`
		CreatedAt      time.Time `json:"created_at"`
	}

	vulns := []VulnDetail{}
	for rows.Next() {
		var v VulnDetail
		err := rows.Scan(
			&v.ID, &v.CVEID, &v.Severity, &v.PackageName,
			&v.PackageVersion, &v.PackageType,
			&v.FixedVersion, &v.FixAvailable, &v.Title, &v.Description,
			&v.CVSSScore, &v.CVSSVector, &v.CreatedAt,
		)
		if err != nil {
			h.logger.Warn("Failed to scan vulnerability", zap.Error(err))
			continue
		}
		vulns = append(vulns, v)
	}

	c.JSON(http.StatusOK, vulns)
}

// ==================== Generate SBOM ====================

func (h *Handler) generateSBOM(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	var req GenerateSBOMRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.logger.Info("Generating SBOM",
		zap.String("image", req.Image),
	)

	// Generate SBOM with Syft
	sbomResult, err := h.sbomGenerator.GenerateSBOM(c.Request.Context(), req.Image)
	if err != nil {
		h.logger.Error("SBOM generation failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "SBOM generation failed: " + err.Error(),
		})
		return
	}

	// Store SBOM in database
	var sbomID uuid.UUID
	err = h.db.QueryRow(c.Request.Context(), `
		INSERT INTO sboms (
			org_id, image_digest, image_repository,
			format, spec_version,
			total_packages, os_packages, library_packages,
			sbom_json, generator_name, generator_version
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id
	`, orgID, sbomResult.ImageDigest, sbomResult.ImageRepository,
		sbomResult.Format, sbomResult.SpecVersion,
		sbomResult.TotalPackages, sbomResult.OSPackages, sbomResult.LibraryPackages,
		sbomResult.Raw, sbomResult.GeneratorName, sbomResult.GeneratorVersion,
	).Scan(&sbomID)

	if err != nil {
		h.logger.Error("Failed to store SBOM", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store SBOM"})
		return
	}

	h.logger.Info("SBOM generated and stored",
		zap.String("sbom_id", sbomID.String()),
		zap.Int("total_packages", sbomResult.TotalPackages),
	)

	c.JSON(http.StatusOK, gin.H{
		"id":               sbomID,
		"image":            sbomResult.ImageRepository,
		"format":           sbomResult.Format,
		"spec_version":     sbomResult.SpecVersion,
		"total_packages":   sbomResult.TotalPackages,
		"os_packages":      sbomResult.OSPackages,
		"library_packages": sbomResult.LibraryPackages,
	})
}

// ==================== List SBOMs ====================

func (h *Handler) listSBOMs(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)

	rows, err := h.db.Query(c.Request.Context(), `
		SELECT id, image_repository, image_digest,
		       format, spec_version,
		       total_packages, os_packages, library_packages,
		       generator_name, generator_version,
		       created_at
		FROM sboms
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT 100
	`, orgID)
	if err != nil {
		h.logger.Error("Failed to list SBOMs", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list SBOMs"})
		return
	}
	defer rows.Close()

	type SBOMSummary struct {
		ID              uuid.UUID `json:"id"`
		ImageRepository string    `json:"image_repository"`
		ImageDigest     *string   `json:"image_digest"`
		Format          string    `json:"format"`
		SpecVersion     string    `json:"spec_version"`
		TotalPackages   int       `json:"total_packages"`
		OSPackages      int       `json:"os_packages"`
		LibraryPackages int       `json:"library_packages"`
		GeneratorName   string    `json:"generator_name"`
		GeneratorVersion *string  `json:"generator_version"`
		CreatedAt       time.Time `json:"created_at"`
	}

	sboms := []SBOMSummary{}
	for rows.Next() {
		var s SBOMSummary
		err := rows.Scan(
			&s.ID, &s.ImageRepository, &s.ImageDigest,
			&s.Format, &s.SpecVersion,
			&s.TotalPackages, &s.OSPackages, &s.LibraryPackages,
			&s.GeneratorName, &s.GeneratorVersion,
			&s.CreatedAt,
		)
		if err != nil {
			h.logger.Warn("Failed to scan SBOM row", zap.Error(err))
			continue
		}
		sboms = append(sboms, s)
	}

	c.JSON(http.StatusOK, sboms)
}

// ==================== Download SBOM ====================

func (h *Handler) downloadSBOM(c *gin.Context) {
	orgID := c.MustGet("org_id").(uuid.UUID)
	sbomID := c.Param("sid")

	var sbomJSON []byte
	var imageRepo string
	var format string

	err := h.db.QueryRow(c.Request.Context(), `
		SELECT image_repository, format, sbom_json
		FROM sboms
		WHERE id = $1 AND org_id = $2
	`, sbomID, orgID).Scan(&imageRepo, &format, &sbomJSON)

	if err != nil {
		h.logger.Error("SBOM not found", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "SBOM not found"})
		return
	}

	// Set content type and headers for download
	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", "attachment; filename=sbom-"+sbomID+".json")

	c.Data(http.StatusOK, "application/json", sbomJSON)
}
