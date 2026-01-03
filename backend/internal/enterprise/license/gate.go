package license

import (
	"context"
	"errors"
	"fmt"
)

// Errors
var (
	ErrSaaSRequired       = errors.New("SaaS edition required")
	ErrFeatureNotAvailable = errors.New("feature not available in this edition")
)

// FeatureGateResult contains information about a feature gate check
type FeatureGateResult struct {
	Allowed bool
	Feature string
	Reason  string
	Edition Edition
}

// RequireFeature checks if a feature is available in the current edition
// Returns an error if the feature is not available
func RequireFeature(ctx context.Context, feature string) error {
	lic := FromContext(ctx)

	if lic.Edition == EditionCommunity {
		return fmt.Errorf("%w: %s requires SaaS edition", ErrSaaSRequired, feature)
	}

	if !lic.HasFeature(feature) {
		return fmt.Errorf("%w: %s", ErrFeatureNotAvailable, feature)
	}

	return nil
}

// CheckFeature checks if a feature is available without returning an error
// Use this for conditional UI/logic, not for enforcement
func CheckFeature(ctx context.Context, feature string) FeatureGateResult {
	lic := FromContext(ctx)

	result := FeatureGateResult{
		Feature: feature,
		Edition: lic.Edition,
	}

	if lic.Edition == EditionCommunity {
		result.Allowed = false
		result.Reason = "SaaS edition required"
		return result
	}

	if !lic.HasFeature(feature) {
		result.Allowed = false
		result.Reason = "feature not available"
		return result
	}

	result.Allowed = true
	result.Reason = "available"
	return result
}

// RequireSaaS checks if SaaS edition is active
func RequireSaaS(ctx context.Context) error {
	lic := FromContext(ctx)

	if lic.Edition == EditionCommunity {
		return ErrSaaSRequired
	}

	return nil
}

// IsSaaS returns true if SaaS edition is active
func IsSaaS(ctx context.Context) bool {
	return FromContext(ctx).IsSaaS()
}

// IsCommunity returns true if Community edition is active
func IsCommunity(ctx context.Context) bool {
	return FromContext(ctx).IsCommunity()
}

// CheckLimit checks if a limit is within bounds
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

// SaaSFeatureInfo provides information about SaaS features for UI
type SaaSFeatureInfo struct {
	Feature     string `json:"feature"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Available   bool   `json:"available"`
}

// GetFeatureInfo returns information about all SaaS features
func GetFeatureInfo(ctx context.Context) []SaaSFeatureInfo {
	lic := FromContext(ctx)

	features := []SaaSFeatureInfo{
		{
			Feature:     FeatureSSOSAML,
			Name:        "SAML SSO",
			Description: "Single sign-on with SAML 2.0 identity providers",
			Available:   lic.HasFeature(FeatureSSOSAML),
		},
		{
			Feature:     FeatureSSOOIDC,
			Name:        "OIDC SSO",
			Description: "Single sign-on with OpenID Connect providers",
			Available:   lic.HasFeature(FeatureSSOOIDC),
		},
		{
			Feature:     FeatureSSOLDAP,
			Name:        "LDAP Authentication",
			Description: "Authenticate users against LDAP/Active Directory",
			Available:   lic.HasFeature(FeatureSSOLDAP),
		},
		{
			Feature:     FeatureMultiTenant,
			Name:        "Multi-Tenancy",
			Description: "Support multiple organizations with data isolation",
			Available:   lic.HasFeature(FeatureMultiTenant),
		},
		{
			Feature:     FeatureAuditAdvanced,
			Name:        "Advanced Audit",
			Description: "Extended audit log retention and configuration",
			Available:   lic.HasFeature(FeatureAuditAdvanced),
		},
		{
			Feature:     FeatureAuditExport,
			Name:        "Audit Log Export",
			Description: "Export audit logs to external systems (SIEM, S3)",
			Available:   lic.HasFeature(FeatureAuditExport),
		},
		{
			Feature:     FeatureCompliance,
			Name:        "Compliance Reports",
			Description: "Generate SOC2, HIPAA, and other compliance reports",
			Available:   lic.HasFeature(FeatureCompliance),
		},
		{
			Feature:     FeaturePolicyEngine,
			Name:        "Policy Engine",
			Description: "Define and enforce security policies across resources",
			Available:   lic.HasFeature(FeaturePolicyEngine),
		},
		{
			Feature:     FeatureLogPersistence,
			Name:        "Log Persistence",
			Description: "Centralized log storage for disaster recovery",
			Available:   lic.HasFeature(FeatureLogPersistence),
		},
		{
			Feature:     FeatureAgentEnroll,
			Name:        "Agent Enrollment",
			Description: "Remote agent enrollment with tokens",
			Available:   lic.HasFeature(FeatureAgentEnroll),
		},
	}

	return features
}
