package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"go.uber.org/zap"
)

// SBOM represents a Software Bill of Materials
type SBOM struct {
	Format          string          `json:"format"`
	SpecVersion     string          `json:"spec_version"`
	ImageRepository string          `json:"image_repository"`
	ImageDigest     string          `json:"image_digest"`
	TotalPackages   int             `json:"total_packages"`
	OSPackages      int             `json:"os_packages"`
	LibraryPackages int             `json:"library_packages"`
	GeneratorName   string          `json:"generator_name"`
	GeneratorVersion string         `json:"generator_version"`
	Raw             json.RawMessage `json:"raw"`
}

// SBOMGenerator handles SBOM generation with Syft
type SBOMGenerator struct {
	syftPath string
	logger   *zap.Logger
}

// NewSBOMGenerator creates a new SBOM generator
func NewSBOMGenerator(logger *zap.Logger) *SBOMGenerator {
	return &SBOMGenerator{
		syftPath: "syft",
		logger:   logger,
	}
}

// GenerateSBOM creates a CycloneDX SBOM for an image
func (g *SBOMGenerator) GenerateSBOM(ctx context.Context, imageRef string) (*SBOM, error) {
	g.logger.Info("Generating SBOM",
		zap.String("image", imageRef),
	)

	// Check if Syft is installed
	if err := g.checkSyftInstalled(ctx); err != nil {
		g.logger.Error("Syft not available", zap.Error(err))
		return nil, fmt.Errorf("syft not installed: %w", err)
	}

	// Run Syft to generate SBOM in CycloneDX JSON format
	cmd := exec.CommandContext(ctx, g.syftPath,
		imageRef,
		"-o", "cyclonedx-json",
		"--quiet",
	)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			g.logger.Error("Syft SBOM generation failed",
				zap.Error(err),
				zap.String("stderr", string(exitErr.Stderr)),
			)
		}
		return nil, fmt.Errorf("sbom generation failed: %w", err)
	}

	// Parse CycloneDX output
	var cyclonedx CycloneDXBOM
	if err := json.Unmarshal(output, &cyclonedx); err != nil {
		g.logger.Error("Failed to parse SBOM output", zap.Error(err))
		return nil, fmt.Errorf("failed to parse sbom: %w", err)
	}

	// Build our SBOM structure
	sbom := &SBOM{
		Format:          "cyclonedx",
		SpecVersion:     cyclonedx.SpecVersion,
		ImageRepository: imageRef,
		GeneratorName:   "syft",
		Raw:             output,
	}

	// Extract metadata if available
	if cyclonedx.Metadata.Component != nil {
		if len(cyclonedx.Metadata.Component.Version) > 0 {
			sbom.ImageDigest = cyclonedx.Metadata.Component.Version
		}
	}

	// Extract generator version
	if len(cyclonedx.Metadata.Tools) > 0 {
		sbom.GeneratorVersion = cyclonedx.Metadata.Tools[0].Version
	}

	// Count packages
	g.countPackages(sbom, &cyclonedx)

	g.logger.Info("SBOM generated successfully",
		zap.String("image", imageRef),
		zap.Int("total_packages", sbom.TotalPackages),
		zap.Int("os_packages", sbom.OSPackages),
		zap.Int("library_packages", sbom.LibraryPackages),
	)

	return sbom, nil
}

// checkSyftInstalled verifies Syft is available
func (g *SBOMGenerator) checkSyftInstalled(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, g.syftPath, "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("syft command not found or not executable")
	}
	return nil
}

// CycloneDX structures for parsing output
type CycloneDXBOM struct {
	BOMFormat   string            `json:"bomFormat"`
	SpecVersion string            `json:"specVersion"`
	Version     int               `json:"version"`
	Metadata    CycloneDXMetadata `json:"metadata"`
	Components  []CycloneDXComponent `json:"components"`
}

type CycloneDXMetadata struct {
	Timestamp string                 `json:"timestamp"`
	Tools     []CycloneDXTool        `json:"tools"`
	Component *CycloneDXComponent    `json:"component,omitempty"`
}

type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CycloneDXComponent struct {
	BOMRef     string                   `json:"bom-ref"`
	Type       string                   `json:"type"`
	Name       string                   `json:"name"`
	Version    string                   `json:"version"`
	Purl       string                   `json:"purl,omitempty"`
	Properties []CycloneDXProperty      `json:"properties,omitempty"`
}

type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// countPackages analyzes the SBOM and counts package types
func (g *SBOMGenerator) countPackages(sbom *SBOM, cyclonedx *CycloneDXBOM) {
	sbom.TotalPackages = len(cyclonedx.Components)

	// Count OS packages vs library packages
	for _, component := range cyclonedx.Components {
		// OS packages typically have type "operating-system" or are from system package managers
		if component.Type == "operating-system" {
			sbom.OSPackages++
		} else if isOSPackage(component) {
			sbom.OSPackages++
		} else {
			sbom.LibraryPackages++
		}
	}
}

// isOSPackage determines if a component is an OS package based on its properties
func isOSPackage(component CycloneDXComponent) bool {
	// Check if it's from a system package manager
	systemPackageManagers := []string{
		"apk",  // Alpine
		"dpkg", // Debian/Ubuntu
		"rpm",  // RedHat/CentOS
		"pacman", // Arch
	}

	for _, prop := range component.Properties {
		if prop.Name == "syft:package:foundBy" {
			for _, pm := range systemPackageManagers {
				if contains(prop.Value, pm) {
					return true
				}
			}
		}
	}

	return false
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
