package deployment.policy

import rego.v1

# Default decision
default decision := {
	"decision": "allow",
	"reason": "No policy violations detected",
	"warnings": [],
	"errors": []
}

# Main decision logic
decision := result if {
	result := deny_critical_in_prod
}

decision := result if {
	not deny_critical_in_prod
	result := deny_too_many_high_in_prod
}

decision := result if {
	not deny_critical_in_prod
	not deny_too_many_high_in_prod
	result := warn_high_vulnerabilities
}

decision := result if {
	not deny_critical_in_prod
	not deny_too_many_high_in_prod
	not warn_high_vulnerabilities
	result := allow_deployment
}

# ===== DENY RULES =====

# Block production deployments with any critical vulnerabilities
deny_critical_in_prod := {
	"decision": "deny",
	"reason": reason,
	"errors": [reason]
} if {
	input.deployment.environment == "prod"
	input.scan_result.critical_count > 0
	reason := sprintf("Production deployment blocked: %d critical vulnerabilities found", [input.scan_result.critical_count])
}

# Block production deployments with more than 5 high-severity vulnerabilities
deny_too_many_high_in_prod := {
	"decision": "deny",
	"reason": reason,
	"errors": [reason]
} if {
	input.deployment.environment == "prod"
	input.scan_result.high_count > 5
	reason := sprintf("Production deployment blocked: %d high-severity vulnerabilities found (threshold: 5)", [input.scan_result.high_count])
}

# Block staging deployments with more than 3 critical vulnerabilities
deny_staging_critical := {
	"decision": "deny",
	"reason": reason,
	"errors": [reason]
} if {
	input.deployment.environment == "staging"
	input.scan_result.critical_count > 3
	reason := sprintf("Staging deployment blocked: %d critical vulnerabilities found (threshold: 3)", [input.scan_result.critical_count])
}

# ===== WARN RULES =====

# Warn on high vulnerabilities in any environment
warn_high_vulnerabilities := {
	"decision": "warn",
	"reason": reason,
	"warnings": warnings
} if {
	total_high := input.scan_result.critical_count + input.scan_result.high_count
	total_high > 0
	reason := sprintf("Deployment contains %d critical and %d high-severity vulnerabilities", [
		input.scan_result.critical_count,
		input.scan_result.high_count
	])
	warnings := [
		sprintf("%d total high-risk vulnerabilities", [total_high]),
		sprintf("%d/%d vulnerabilities have fixes available", [
			input.scan_result.fixable_count,
			input.scan_result.total_count
		])
	]
}

# Warn on staging deployments with critical vulnerabilities
warn_staging_critical := {
	"decision": "warn",
	"reason": reason,
	"warnings": [reason]
} if {
	input.deployment.environment == "staging"
	input.scan_result.critical_count > 0
	input.scan_result.critical_count <= 3
	reason := sprintf("Staging deployment contains %d critical vulnerabilities", [input.scan_result.critical_count])
}

# ===== ALLOW RULES =====

# Allow deployment if no serious issues found
allow_deployment := {
	"decision": "allow",
	"reason": reason,
	"warnings": []
} if {
	reason := sprintf("Security scan passed: %d total vulnerabilities (%d critical, %d high, %d medium, %d low)", [
		input.scan_result.total_count,
		input.scan_result.critical_count,
		input.scan_result.high_count,
		input.scan_result.medium_count,
		input.scan_result.low_count
	])
}

# ===== HELPER RULES =====

# Check if image is from trusted registry
is_trusted_registry if {
	trusted_registries := ["docker.io", "gcr.io", "ghcr.io"]
	registry := split(input.deployment.image_repository, "/")[0]
	registry in trusted_registries
}

# Check if deployment has required metadata
has_metadata if {
	input.deployment.git_commit != ""
	input.deployment.git_branch != ""
}

# Calculate risk score
risk_score := score if {
	score := (input.scan_result.critical_count * 10) +
	         (input.scan_result.high_count * 5) +
	         (input.scan_result.medium_count * 2) +
	         (input.scan_result.low_count * 1)
}
