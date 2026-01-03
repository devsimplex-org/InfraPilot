package license

import (
	"context"
	"os"
	"sync"
)

// Edition represents the product edition
type Edition string

const (
	EditionCommunity Edition = "community"
	EditionSaaS      Edition = "saas"
)

// Feature constants for SaaS features
const (
	FeatureSSOSAML        = "sso_saml"
	FeatureSSOOIDC        = "sso_oidc"
	FeatureSSOLDAP        = "sso_ldap"
	FeatureMultiTenant    = "multi_tenant"
	FeatureAuditAdvanced  = "audit_advanced"
	FeatureAuditExport    = "audit_export"
	FeatureCompliance     = "compliance_reports"
	FeaturePolicyEngine   = "policy_engine"
	FeatureLogPersistence = "log_persistence"
	FeatureAgentEnroll    = "agent_enrollment"
)

// AllSaaSFeatures returns all available SaaS features
func AllSaaSFeatures() map[string]bool {
	return map[string]bool{
		FeatureSSOSAML:        true,
		FeatureSSOOIDC:        true,
		FeatureSSOLDAP:        true,
		FeatureMultiTenant:    true,
		FeatureAuditAdvanced:  true,
		FeatureAuditExport:    true,
		FeatureCompliance:     true,
		FeaturePolicyEngine:   true,
		FeatureLogPersistence: true,
		FeatureAgentEnroll:    true,
	}
}

// License represents the edition configuration
type License struct {
	Edition  Edition         `json:"edition"`
	Features map[string]bool `json:"features"`
	Limits   Limits          `json:"limits"`
}

// Limits defines usage limits
type Limits struct {
	MaxUsers     int `json:"max_users"`
	MaxAgents    int `json:"max_agents"`
	MaxResources int `json:"max_resources"`
}

// Global license instance
var (
	currentLicense *License
	licenseMu      sync.RWMutex
)

// CommunityLicense returns the community edition license
func CommunityLicense() *License {
	return &License{
		Edition:  EditionCommunity,
		Features: map[string]bool{}, // No SaaS features
		Limits: Limits{
			MaxUsers:     -1, // Unlimited for self-hosted
			MaxAgents:    1,  // Single agent (built-in)
			MaxResources: -1,
		},
	}
}

// SaaSLicense returns the SaaS edition license
func SaaSLicense() *License {
	return &License{
		Edition:  EditionSaaS,
		Features: AllSaaSFeatures(),
		Limits: Limits{
			MaxUsers:     -1, // Managed by billing plan
			MaxAgents:    -1, // Managed by billing plan
			MaxResources: -1, // Managed by billing plan
		},
	}
}

// Init initializes the edition system based on EDITION env var
// Defaults to "community" if not set
func Init() error {
	edition := os.Getenv("EDITION")

	switch Edition(edition) {
	case EditionSaaS:
		SetCurrent(SaaSLicense())
	default:
		// Default to community edition
		SetCurrent(CommunityLicense())
	}

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
		return CommunityLicense()
	}
	return currentLicense
}

// HasFeature checks if a specific feature is available
func (l *License) HasFeature(feature string) bool {
	if l.Edition == EditionCommunity {
		return false
	}
	return l.Features[feature]
}

// IsSaaS returns true if this is the SaaS edition
func (l *License) IsSaaS() bool {
	return l.Edition == EditionSaaS
}

// IsCommunity returns true if this is the community edition
func (l *License) IsCommunity() bool {
	return l.Edition == EditionCommunity
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
