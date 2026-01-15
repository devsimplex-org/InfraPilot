# Self-Protection Policy: Block Root Containers
# Prevents containers from running as root user (UID 0)

package infrapilot.selfprotection

# Deny containers running as root (explicit)
deny[msg] {
    input.container.user == "root"
    msg := "Running containers as root user is forbidden - use non-root user"
}

# Deny containers with UID 0
deny[msg] {
    input.container.user == "0"
    msg := "Running containers as UID 0 (root) is forbidden - specify non-root user"
}

# Deny containers without explicit user specified (defaults to root)
warn[msg] {
    not input.container.user
    msg := "No user specified for container - will default to root (not recommended)"
}

# Deny RunAsUser: 0 in security context
deny[msg] {
    input.container.security_context.run_as_user == 0
    msg := "SecurityContext.RunAsUser set to 0 (root) is forbidden"
}

# Require run as non-root
deny[msg] {
    input.container.security_context.run_as_non_root != true
    msg := "SecurityContext.RunAsNonRoot must be set to true"
}

# Metadata for violation tracking
violation_type := "root_container"
severity := "medium"
