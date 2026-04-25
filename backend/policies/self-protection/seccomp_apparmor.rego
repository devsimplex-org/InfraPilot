# Self-Protection Policy: Require Security Profiles
# Enforces use of seccomp and AppArmor profiles for defense-in-depth

package infrapilot.selfprotection

# Warn if seccomp is disabled
warn[msg] {
    input.container.security_opt
    some opt
    input.container.security_opt[opt] == "seccomp=unconfined"
    msg := "Seccomp is disabled - strongly recommend enabling default seccomp profile"
}

# Warn if AppArmor is disabled
warn[msg] {
    input.container.security_opt
    some opt
    input.container.security_opt[opt] == "apparmor=unconfined"
    msg := "AppArmor is disabled - recommend enabling default AppArmor profile"
}

# Deny disabling all security options
deny[msg] {
    input.container.security_opt
    some opt
    input.container.security_opt[opt] == "no-new-privileges=false"
    msg := "Disabling no-new-privileges is forbidden - required for security"
}

# Require no-new-privileges flag
warn[msg] {
    not input.container.security_context.no_new_privileges
    msg := "no-new-privileges flag not set - recommend enabling to prevent privilege escalation"
}

# Deny SELinux type that allows unconfined access
deny[msg] {
    input.container.security_context.selinux_options.type == "spc_t"
    msg := "SELinux type spc_t (super privileged container) is forbidden"
}

# Metadata for violation tracking
violation_type := "security_profile"
severity := "medium"
