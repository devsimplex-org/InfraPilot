package license

import (
	"context"
	"fmt"
)

// FeatureGateResult contains information about a feature gate check
type FeatureGateResult struct {
	Allowed bool
	Feature string
	Reason  string
	License *License
}

// RequireFeature checks if a feature is available in the current license
// Returns an error if the feature is not licensed
// This is the primary gate function - use it everywhere
func RequireFeature(ctx context.Context, feature string) error {
	lic := FromContext(ctx)

	if lic.Edition == Community {
		return fmt.Errorf("%w: %s requires enterprise license", ErrEnterpriseRequired, feature)
	}

	if !lic.HasFeature(feature) {
		return fmt.Errorf("%w: %s", ErrFeatureNotLicensed, feature)
	}

	if lic.IsExpired() {
		return fmt.Errorf("%w: license expired, %s unavailable", ErrLicenseExpired, feature)
	}

	return nil
}

// CheckFeature checks if a feature is available without returning an error
// Use this for conditional UI/logic, not for enforcement
func CheckFeature(ctx context.Context, feature string) FeatureGateResult {
	lic := FromContext(ctx)

	result := FeatureGateResult{
		Feature: feature,
		License: lic,
	}

	if lic.Edition == Community {
		result.Allowed = false
		result.Reason = "enterprise license required"
		return result
	}

	if !lic.HasFeature(feature) {
		result.Allowed = false
		result.Reason = "feature not included in license"
		return result
	}

	if lic.IsExpired() {
		result.Allowed = false
		result.Reason = "license expired"
		return result
	}

	result.Allowed = true
	result.Reason = "licensed"
	return result
}

// RequireEnterprise checks if any enterprise license is present
// Use this for features that require enterprise but don't need specific feature flags
func RequireEnterprise(ctx context.Context) error {
	lic := FromContext(ctx)

	if lic.Edition == Community {
		return ErrEnterpriseRequired
	}

	if lic.IsExpired() {
		return ErrLicenseExpired
	}

	return nil
}

// IsEnterprise returns true if an enterprise license is active
func IsEnterprise(ctx context.Context) bool {
	return FromContext(ctx).IsEnterprise()
}

// CheckLimit checks if a limit is within the license bounds
// Returns true if the current value is within limits
// -1 means unlimited
func CheckLimit(ctx context.Context, limitType string, currentValue int) bool {
	lic := FromContext(ctx)

	var limit int
	switch limitType {
	case "users":
		limit = lic.Limits.MaxUsers
	case "agents":
		limit = lic.Limits.MaxAgents
	case "resources":
		limit = lic.Limits.MaxResources
	default:
		return true // Unknown limit, allow
	}

	if limit == -1 {
		return true // Unlimited
	}

	return currentValue < limit
}

// EnterpriseFeatureInfo provides information about enterprise features for UI
type EnterpriseFeatureInfo struct {
	Feature     string `json:"feature"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Licensed    bool   `json:"licensed"`
}

// GetFeatureInfo returns information about all enterprise features
func GetFeatureInfo(ctx context.Context) []EnterpriseFeatureInfo {
	lic := FromContext(ctx)

	features := []EnterpriseFeatureInfo{
		{
			Feature:     FeatureSSOSAML,
			Name:        "SAML SSO",
			Description: "Single sign-on with SAML 2.0 identity providers",
			Licensed:    lic.HasFeature(FeatureSSOSAML),
		},
		{
			Feature:     FeatureSSOOIDC,
			Name:        "OIDC SSO",
			Description: "Single sign-on with OpenID Connect providers",
			Licensed:    lic.HasFeature(FeatureSSOOIDC),
		},
		{
			Feature:     FeatureSSOLDAP,
			Name:        "LDAP Authentication",
			Description: "Authenticate users against LDAP/Active Directory",
			Licensed:    lic.HasFeature(FeatureSSOLDAP),
		},
		{
			Feature:     FeatureMultiTenant,
			Name:        "Multi-Tenancy",
			Description: "Support multiple organizations in a single instance",
			Licensed:    lic.HasFeature(FeatureMultiTenant),
		},
		{
			Feature:     FeatureAuditUnlimited,
			Name:        "Unlimited Audit Logs",
			Description: "Retain audit logs indefinitely",
			Licensed:    lic.HasFeature(FeatureAuditUnlimited),
		},
		{
			Feature:     FeatureAuditExport,
			Name:        "Audit Log Export",
			Description: "Export audit logs to external systems",
			Licensed:    lic.HasFeature(FeatureAuditExport),
		},
		{
			Feature:     FeatureAdvancedRBAC,
			Name:        "Advanced RBAC",
			Description: "Custom roles and fine-grained permissions",
			Licensed:    lic.HasFeature(FeatureAdvancedRBAC),
		},
		{
			Feature:     FeatureCompliance,
			Name:        "Compliance Reports",
			Description: "Generate SOC2, HIPAA, and other compliance reports",
			Licensed:    lic.HasFeature(FeatureCompliance),
		},
		{
			Feature:     FeatureHAClustering,
			Name:        "High Availability",
			Description: "Multi-node clustering for high availability",
			Licensed:    lic.HasFeature(FeatureHAClustering),
		},
		{
			Feature:     FeaturePrioritySupport,
			Name:        "Priority Support",
			Description: "SLA-backed priority support channels",
			Licensed:    lic.HasFeature(FeaturePrioritySupport),
		},
	}

	return features
}
