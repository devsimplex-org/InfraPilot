package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ==================== SBOM Package Types ====================

type SBOMPackage struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Type         string   `json:"type"` // library, os-package
	Language     *string  `json:"language,omitempty"`
	PURL         *string  `json:"purl,omitempty"`
	CPE          *string  `json:"cpe,omitempty"`
	Licenses     []string `json:"licenses,omitempty"`
	Locations    []string `json:"locations,omitempty"`
	Vulnerabilities int   `json:"vulnerabilities"` // Count of vulns affecting this package
}

type SBOMDetails struct {
	ID                string        `json:"id"`
	ImageRepository   string        `json:"image_repository"`
	ImageDigest       string        `json:"image_digest"`
	Format            string        `json:"format"`
	SpecVersion       string        `json:"spec_version"`
	GeneratorName     string        `json:"generator_name"`
	GeneratorVersion  string        `json:"generator_version"`
	TotalPackages     int           `json:"total_packages"`
	OSPackages        int           `json:"os_packages"`
	LibraryPackages   int           `json:"library_packages"`
	CreatedAt         string        `json:"created_at"`
	Packages          []SBOMPackage `json:"packages"`
	PackagesByType    map[string]int `json:"packages_by_type"`
	PackagesByLanguage map[string]int `json:"packages_by_language"`
}

// ==================== SBOM Detail Handlers ====================

func (h *Handler) getSBOMDetails(c *gin.Context) {
	sbomID, err := uuid.Parse(c.Param("sid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid SBOM ID"})
		return
	}

	// Get SBOM metadata
	query := `
		SELECT id, image_repository, image_digest, format, spec_version,
		       generator_name, generator_version, total_packages,
		       os_packages, library_packages, created_at, cyclonedx_data
		FROM sboms
		WHERE id = $1
	`

	var sbom SBOMDetails
	var cyclonedxData []byte
	var id uuid.UUID

	err = h.db.QueryRow(c, query, sbomID).Scan(
		&id,
		&sbom.ImageRepository,
		&sbom.ImageDigest,
		&sbom.Format,
		&sbom.SpecVersion,
		&sbom.GeneratorName,
		&sbom.GeneratorVersion,
		&sbom.TotalPackages,
		&sbom.OSPackages,
		&sbom.LibraryPackages,
		&sbom.CreatedAt,
		&cyclonedxData,
	)
	if err != nil {
		h.logger.Error("failed to get SBOM", zap.Error(err))
		c.JSON(http.StatusNotFound, gin.H{"error": "SBOM not found"})
		return
	}

	sbom.ID = id.String()

	// Parse CycloneDX data
	var cyclonedx struct {
		Components []struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			PURL      string `json:"purl"`
			CPE       string `json:"cpe"`
			Licenses  []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
			} `json:"licenses"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}

	if err := json.Unmarshal(cyclonedxData, &cyclonedx); err != nil {
		h.logger.Error("failed to parse CycloneDX", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse SBOM data"})
		return
	}

	// Get vulnerability counts per package
	vulnQuery := `
		SELECT package_name, COUNT(*) as vuln_count
		FROM vulnerabilities v
		JOIN scan_results sr ON v.scan_result_id = sr.id
		WHERE sr.image_digest = $1
		GROUP BY package_name
	`

	vulnRows, err := h.db.Query(c, vulnQuery, sbom.ImageDigest)
	if err != nil {
		h.logger.Warn("failed to get vulnerability counts", zap.Error(err))
	} else {
		defer vulnRows.Close()
		vulnCounts := make(map[string]int)
		for vulnRows.Next() {
			var pkgName string
			var count int
			if err := vulnRows.Scan(&pkgName, &count); err == nil {
				vulnCounts[pkgName] = count
			}
		}

		// Convert components to packages
		sbom.Packages = make([]SBOMPackage, 0, len(cyclonedx.Components))
		sbom.PackagesByType = make(map[string]int)
		sbom.PackagesByLanguage = make(map[string]int)

		for _, comp := range cyclonedx.Components {
			pkg := SBOMPackage{
				Name:            comp.Name,
				Version:         comp.Version,
				Type:            comp.Type,
				Vulnerabilities: vulnCounts[comp.Name],
			}

			if comp.PURL != "" {
				pkg.PURL = &comp.PURL
			}
			if comp.CPE != "" {
				pkg.CPE = &comp.CPE
			}

			// Extract licenses
			for _, lic := range comp.Licenses {
				if lic.License.ID != "" {
					pkg.Licenses = append(pkg.Licenses, lic.License.ID)
				} else if lic.License.Name != "" {
					pkg.Licenses = append(pkg.Licenses, lic.License.Name)
				}
			}

			// Extract language from properties
			for _, prop := range comp.Properties {
				if prop.Name == "syft:package:language" {
					pkg.Language = &prop.Value
					sbom.PackagesByLanguage[prop.Value]++
				}
				if prop.Name == "syft:location:0:path" {
					pkg.Locations = append(pkg.Locations, prop.Value)
				}
			}

			// Count by type
			sbom.PackagesByType[comp.Type]++

			sbom.Packages = append(sbom.Packages, pkg)
		}
	}

	c.JSON(http.StatusOK, sbom)
}

func (h *Handler) searchSBOMPackages(c *gin.Context) {
	sbomID, err := uuid.Parse(c.Param("sid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid SBOM ID"})
		return
	}

	searchTerm := c.Query("q")
	if searchTerm == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "search term required"})
		return
	}

	// Get CycloneDX data
	query := `SELECT cyclonedx_data FROM sboms WHERE id = $1`
	var cyclonedxData []byte
	err = h.db.QueryRow(c, query, sbomID).Scan(&cyclonedxData)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "SBOM not found"})
		return
	}

	// Parse and search
	var cyclonedx struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"components"`
	}

	if err := json.Unmarshal(cyclonedxData, &cyclonedx); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse SBOM"})
		return
	}

	// Simple search by package name
	var results []SBOMPackage
	searchLower := strings.ToLower(searchTerm)
	for _, comp := range cyclonedx.Components {
		if strings.Contains(strings.ToLower(comp.Name), searchLower) {
			results = append(results, SBOMPackage{
				Name:    comp.Name,
				Version: comp.Version,
				Type:    comp.Type,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"packages": results,
		"count":    len(results),
	})
}
