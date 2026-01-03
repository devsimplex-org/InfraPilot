package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Edition represents the product edition
type Edition string

const (
	Community  Edition = "community"
	Enterprise Edition = "enterprise"
)

// Feature constants for enterprise features
const (
	FeatureSSOSAML       = "sso_saml"
	FeatureSSOOIDC       = "sso_oidc"
	FeatureSSOLDAP       = "sso_ldap"
	FeatureMultiTenant   = "multi_tenant"
	FeatureAuditUnlimited = "audit_unlimited"
	FeatureAuditExport   = "audit_export"
	FeatureAdvancedRBAC  = "advanced_rbac"
	FeatureCompliance    = "compliance_reports"
	FeatureHAClustering  = "ha_clustering"
	FeaturePrioritySupport = "priority_support"
)

// AllEnterpriseFeatures returns all available enterprise features
func AllEnterpriseFeatures() map[string]bool {
	return map[string]bool{
		FeatureSSOSAML:       true,
		FeatureSSOOIDC:       true,
		FeatureSSOLDAP:       true,
		FeatureMultiTenant:   true,
		FeatureAuditUnlimited: true,
		FeatureAuditExport:   true,
		FeatureAdvancedRBAC:  true,
		FeatureCompliance:    true,
		FeatureHAClustering:  true,
		FeaturePrioritySupport: true,
	}
}

// License represents the license configuration
type License struct {
	ID           string          `yaml:"id" json:"id"`
	Edition      Edition         `yaml:"edition" json:"edition"`
	Organization string          `yaml:"organization" json:"organization"`
	OrgID        string          `yaml:"org_id" json:"org_id"`
	Features     map[string]bool `yaml:"features" json:"features"`
	Limits       Limits          `yaml:"limits" json:"limits"`
	IssuedAt     time.Time       `yaml:"issued_at" json:"issued_at"`
	ExpiresAt    time.Time       `yaml:"expires_at" json:"expires_at"`
	Signature    string          `yaml:"signature" json:"signature"`
}

// Limits defines usage limits for the license
type Limits struct {
	MaxUsers     int `yaml:"max_users" json:"max_users"`
	MaxAgents    int `yaml:"max_agents" json:"max_agents"`
	MaxResources int `yaml:"max_resources" json:"max_resources"`
}

// LicenseFile wraps the license for YAML parsing
type LicenseFile struct {
	License License `yaml:"license"`
}

// Errors
var (
	ErrInvalidSignature  = errors.New("invalid license signature")
	ErrLicenseExpired    = errors.New("license has expired")
	ErrEnterpriseRequired = errors.New("enterprise license required")
	ErrFeatureNotLicensed = errors.New("feature not included in license")
)

// Global license instance
var (
	currentLicense *License
	licenseMu      sync.RWMutex
)

// DefaultCommunityLicense returns the default community license
func DefaultCommunityLicense() *License {
	return &License{
		ID:       "community",
		Edition:  Community,
		Features: map[string]bool{}, // No enterprise features
		Limits: Limits{
			MaxUsers:     -1, // Unlimited for community
			MaxAgents:    -1,
			MaxResources: -1,
		},
	}
}

// DefaultSaaSLicense returns the license used in InfraPilot Cloud
// This should only be called when INFRAPILOT_CLOUD=true
func DefaultSaaSLicense() *License {
	return &License{
		ID:       "infrapilot-cloud",
		Edition:  Enterprise,
		Features: AllEnterpriseFeatures(),
		Limits: Limits{
			MaxUsers:     -1, // Managed by SaaS tier
			MaxAgents:    -1,
			MaxResources: -1,
		},
	}
}

// Init initializes the license system
// Load order: INFRAPILOT_CLOUD env → INFRAPILOT_LICENSE env → license file → community default
func Init() error {
	// Check if running in InfraPilot Cloud (SaaS)
	if os.Getenv("INFRAPILOT_CLOUD") == "true" {
		SetCurrent(DefaultSaaSLicense())
		return nil
	}

	// Check for license in environment variable
	if licenseData := os.Getenv("INFRAPILOT_LICENSE"); licenseData != "" {
		lic, err := ParseAndValidate([]byte(licenseData))
		if err != nil {
			return err
		}
		SetCurrent(lic)
		return nil
	}

	// Check for license file
	licensePaths := []string{
		"/etc/infrapilot/license.yaml",
		"./license.yaml",
	}

	for _, path := range licensePaths {
		if data, err := os.ReadFile(path); err == nil {
			lic, err := ParseAndValidate(data)
			if err != nil {
				return err
			}
			SetCurrent(lic)
			return nil
		}
	}

	// Default to community edition
	SetCurrent(DefaultCommunityLicense())
	return nil
}

// ParseAndValidate parses and validates a license from YAML data
func ParseAndValidate(data []byte) (*License, error) {
	var licFile LicenseFile
	if err := yaml.Unmarshal(data, &licFile); err != nil {
		return nil, err
	}

	lic := &licFile.License

	// Skip signature validation in development mode
	if os.Getenv("INFRAPILOT_DEV") != "true" {
		if err := validateSignature(data, lic.Signature); err != nil {
			return nil, err
		}
	}

	// Check expiration
	if !lic.ExpiresAt.IsZero() && time.Now().After(lic.ExpiresAt) {
		return nil, ErrLicenseExpired
	}

	return lic, nil
}

// validateSignature validates the license signature using Ed25519
func validateSignature(data []byte, signature string) error {
	if signature == "" {
		return ErrInvalidSignature
	}

	pubKey := getEmbeddedPublicKey()
	if pubKey == nil {
		// No public key embedded, skip validation (development)
		return nil
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return ErrInvalidSignature
	}

	if !ed25519.Verify(pubKey, data, sigBytes) {
		return ErrInvalidSignature
	}

	return nil
}

// getEmbeddedPublicKey returns the embedded public key for license validation
// This will be populated during build for production releases
func getEmbeddedPublicKey() ed25519.PublicKey {
	// TODO: Embed actual public key during build
	// For now, return nil to skip validation in development
	return nil
}

// SetCurrent sets the current license
func SetCurrent(lic *License) {
	licenseMu.Lock()
	defer licenseMu.Unlock()
	currentLicense = lic
}

// Current returns the current license
func Current() *License {
	licenseMu.RLock()
	defer licenseMu.RUnlock()
	if currentLicense == nil {
		return DefaultCommunityLicense()
	}
	return currentLicense
}

// HasFeature checks if a specific feature is available
func (l *License) HasFeature(feature string) bool {
	if l.Edition == Community {
		return false
	}
	return l.Features[feature]
}

// IsEnterprise returns true if this is an enterprise license
func (l *License) IsEnterprise() bool {
	return l.Edition == Enterprise
}

// IsExpired returns true if the license has expired
func (l *License) IsExpired() bool {
	if l.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(l.ExpiresAt)
}

// Valid returns true if the license is valid and not expired
func (l *License) Valid() bool {
	return !l.IsExpired()
}

// Context key for license
type contextKey string

const licenseContextKey contextKey = "license"

// WithContext adds the license to the context
func WithContext(ctx context.Context, lic *License) context.Context {
	return context.WithValue(ctx, licenseContextKey, lic)
}

// FromContext retrieves the license from context
func FromContext(ctx context.Context) *License {
	if lic, ok := ctx.Value(licenseContextKey).(*License); ok {
		return lic
	}
	return Current()
}
