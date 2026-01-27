package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ScanResult represents a complete vulnerability scan result
type ScanResult struct {
	ID              string          `json:"id"`
	ImageDigest     string          `json:"image_digest"`
	ImageRepository string          `json:"image_repository"`
	ImageTag        string          `json:"image_tag,omitempty"`
	CriticalCount   int             `json:"critical_count"`
	HighCount       int             `json:"high_count"`
	MediumCount     int             `json:"medium_count"`
	LowCount        int             `json:"low_count"`
	UnknownCount    int             `json:"unknown_count"`
	TotalCount      int             `json:"total_count"`
	FixableCount    int             `json:"fixable_count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	ScanDuration    time.Duration   `json:"scan_duration"`
	RawOutput       json.RawMessage `json:"raw_output"`
}

// Vulnerability represents a single security vulnerability
type Vulnerability struct {
	CVEID          string   `json:"cve_id"`
	Severity       string   `json:"severity"`
	PackageName    string   `json:"package_name"`
	PackageVersion string   `json:"package_version"`
	PackageType    string   `json:"package_type"`
	FixedVersion   string   `json:"fixed_version,omitempty"`
	FixAvailable   bool     `json:"fix_available"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	CVSSScore      float64  `json:"cvss_score,omitempty"`
	CVSSVector     string   `json:"cvss_vector,omitempty"`
	References     []string `json:"references,omitempty"`
}

// Scanner handles vulnerability scanning with Trivy
type Scanner struct {
	trivyPath string
	logger    *zap.Logger
	mu        sync.Mutex // Mutex to serialize Trivy scans (prevents cache conflicts)
}

// NewScanner creates a new vulnerability scanner
func NewScanner(logger *zap.Logger) *Scanner {
	return &Scanner{
		trivyPath: "trivy",
		logger:    logger,
	}
}

// ScanImage scans a container image for vulnerabilities using Trivy
func (s *Scanner) ScanImage(ctx context.Context, imageRef string) (*ScanResult, error) {
	// Serialize scans to prevent Trivy cache conflicts
	// If another scan is in progress, this will wait
	s.logger.Debug("Acquiring scan lock", zap.String("image", imageRef))
	s.mu.Lock()
	defer s.mu.Unlock()

	start := time.Now()

	s.logger.Info("Starting vulnerability scan",
		zap.String("image", imageRef),
	)

	// Check if Trivy is installed
	if err := s.checkTrivyInstalled(ctx); err != nil {
		s.logger.Error("Trivy not available", zap.Error(err))
		return nil, fmt.Errorf("trivy not installed: %w", err)
	}

	// Run Trivy scan
	cmd := exec.CommandContext(ctx, s.trivyPath,
		"image",
		"--format", "json",
		"--quiet",
		"--timeout", "10m",
		"--scanners", "vuln",
		imageRef,
	)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			s.logger.Error("Trivy scan failed",
				zap.Error(err),
				zap.String("stderr", string(exitErr.Stderr)),
			)
		}
		return nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	// Parse Trivy output
	var trivyResult TrivyOutput
	if err := json.Unmarshal(output, &trivyResult); err != nil {
		s.logger.Error("Failed to parse Trivy output", zap.Error(err))
		return nil, fmt.Errorf("failed to parse scan results: %w", err)
	}

	// Convert to our format
	result := s.convertTrivyResult(trivyResult, imageRef)
	result.ScanDuration = time.Since(start)
	result.RawOutput = output

	s.logger.Info("Vulnerability scan complete",
		zap.String("image", imageRef),
		zap.Int("total_vulns", result.TotalCount),
		zap.Int("critical", result.CriticalCount),
		zap.Int("high", result.HighCount),
		zap.Duration("duration", result.ScanDuration),
	)

	return result, nil
}

// checkTrivyInstalled verifies Trivy is available
func (s *Scanner) checkTrivyInstalled(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.trivyPath, "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("trivy command not found or not executable")
	}
	return nil
}

// TrivyOutput represents the JSON output from Trivy
type TrivyOutput struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Metadata      TrivyMetadata `json:"Metadata"`
	Results       []TrivyTarget `json:"Results"`
}

type TrivyMetadata struct {
	ImageID     string   `json:"ImageID"`
	DiffIDs     []string `json:"DiffIDs"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
}

type TrivyTarget struct {
	Target          string      `json:"Target"`
	Class           string      `json:"Class"`
	Type            string      `json:"Type"`
	Vulnerabilities []TrivyVuln `json:"Vulnerabilities"`
}

type TrivyVuln struct {
	VulnerabilityID  string             `json:"VulnerabilityID"`
	PkgName          string             `json:"PkgName"`
	PkgPath          string             `json:"PkgPath"`
	InstalledVersion string             `json:"InstalledVersion"`
	FixedVersion     string             `json:"FixedVersion"`
	Status           string             `json:"Status"`
	Layer            TrivyLayer         `json:"Layer"`
	SeveritySource   string             `json:"SeveritySource"`
	PrimaryURL       string             `json:"PrimaryURL"`
	DataSource       TrivyDataSource    `json:"DataSource"`
	Title            string             `json:"Title"`
	Description      string             `json:"Description"`
	Severity         string             `json:"Severity"`
	CweIDs           []string           `json:"CweIDs"`
	CVSS             map[string]CVSSInfo `json:"CVSS"`
	References       []string           `json:"References"`
	PublishedDate    string             `json:"PublishedDate"`
	LastModifiedDate string             `json:"LastModifiedDate"`
}

type TrivyLayer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}

type TrivyDataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

type CVSSInfo struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}

// convertTrivyResult converts Trivy JSON output to our ScanResult format
func (s *Scanner) convertTrivyResult(trivy TrivyOutput, imageRef string) *ScanResult {
	result := &ScanResult{
		ImageRepository: imageRef,
	}

	// Extract image tag if present
	if len(trivy.Metadata.RepoTags) > 0 {
		result.ImageTag = trivy.Metadata.RepoTags[0]
	}

	// Extract digest
	if len(trivy.Metadata.RepoDigests) > 0 {
		result.ImageDigest = trivy.Metadata.RepoDigests[0]
	}

	// Process all vulnerabilities
	for _, target := range trivy.Results {
		for _, vuln := range target.Vulnerabilities {
			v := Vulnerability{
				CVEID:          vuln.VulnerabilityID,
				Severity:       vuln.Severity,
				PackageName:    vuln.PkgName,
				PackageVersion: vuln.InstalledVersion,
				PackageType:    target.Type,
				FixedVersion:   vuln.FixedVersion,
				FixAvailable:   vuln.FixedVersion != "" && vuln.FixedVersion != "0",
				Title:          vuln.Title,
				Description:    vuln.Description,
				References:     vuln.References,
			}

			// Get CVSS score - prefer NVD
			if nvd, ok := vuln.CVSS["nvd"]; ok && nvd.V3Score > 0 {
				v.CVSSScore = nvd.V3Score
				v.CVSSVector = nvd.V3Vector
			} else {
				// Fall back to other sources
				for _, cvss := range vuln.CVSS {
					if cvss.V3Score > 0 {
						v.CVSSScore = cvss.V3Score
						v.CVSSVector = cvss.V3Vector
						break
					}
				}
			}

			result.Vulnerabilities = append(result.Vulnerabilities, v)
			result.TotalCount++

			// Count by severity
			switch vuln.Severity {
			case "CRITICAL":
				result.CriticalCount++
			case "HIGH":
				result.HighCount++
			case "MEDIUM":
				result.MediumCount++
			case "LOW":
				result.LowCount++
			default:
				result.UnknownCount++
			}

			if v.FixAvailable {
				result.FixableCount++
			}
		}
	}

	return result
}
