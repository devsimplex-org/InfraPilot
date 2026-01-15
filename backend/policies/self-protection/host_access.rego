# Self-Protection Policy: Block Host Namespace Access
# Prevents containers from accessing host network, PID, IPC namespaces

package infrapilot.selfprotection

# Deny host network mode
deny[msg] {
    input.container.host_config.network_mode == "host"
    msg := "Host network mode is forbidden - use bridge or custom networks"
}

# Deny host PID namespace
deny[msg] {
    input.container.host_config.pid_mode == "host"
    msg := "Host PID namespace is forbidden - enables process visibility and manipulation"
}

# Deny host IPC namespace
deny[msg] {
    input.container.host_config.ipc_mode == "host"
    msg := "Host IPC namespace is forbidden - enables shared memory access"
}

# Deny host UTS namespace (hostname)
deny[msg] {
    input.container.host_config.uts_mode == "host"
    msg := "Host UTS namespace is forbidden - allows hostname manipulation"
}

# Deny hostPath mounts to sensitive directories
sensitive_host_paths := {
    "/",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/proc",
    "/sys",
    "/usr"
}

deny[msg] {
    some mount
    input.container.mounts[mount].source
    startswith(input.container.mounts[mount].source, sensitive_host_paths[_])
    msg := sprintf("Mounting sensitive host path %s is forbidden", [input.container.mounts[mount].source])
}

# Deny /etc mounts (contains system configuration)
deny[msg] {
    some mount
    input.container.mounts[mount].source == "/etc"
    msg := "Mounting /etc is forbidden - contains system configuration and secrets"
}

# Deny /proc mounts (process information)
deny[msg] {
    some mount
    input.container.mounts[mount].source == "/proc"
    msg := "Mounting /proc is forbidden - exposes process information"
}

# Deny /sys mounts (kernel interfaces)
deny[msg] {
    some mount
    input.container.mounts[mount].source == "/sys"
    msg := "Mounting /sys is forbidden - exposes kernel interfaces"
}

# Metadata for violation tracking
violation_type := "host_namespace_access"
severity := "high"
