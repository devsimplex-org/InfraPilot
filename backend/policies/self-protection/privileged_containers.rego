# Self-Protection Policy: Block Privileged Containers
# Prevents deployment of privileged containers that could compromise the control plane

package infrapilot.selfprotection

# Deny privileged containers
deny[msg] {
    input.container.privileged == true
    msg := "Privileged containers are not allowed - this violates platform security policy"
}

# Deny containers with CAP_SYS_ADMIN (equivalent to privileged)
deny[msg] {
    some cap
    input.container.cap_add[cap] == "SYS_ADMIN"
    msg := "CAP_SYS_ADMIN capability is not allowed - equivalent to privileged mode"
}

# Deny containers with ALL capabilities
deny[msg] {
    some cap
    input.container.cap_add[cap] == "ALL"
    msg := "ALL capabilities are not allowed - use specific capabilities only"
}

# Critical capabilities that should be denied
forbidden_capabilities := {
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_PTRACE",
    "SYS_BOOT",
    "MAC_ADMIN",
    "MAC_OVERRIDE",
    "NET_ADMIN",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH"
}

# Deny containers with forbidden capabilities
deny[msg] {
    some cap
    input.container.cap_add[cap]
    forbidden_capabilities[input.container.cap_add[cap]]
    msg := sprintf("Capability %s is forbidden - creates security risk", [input.container.cap_add[cap]])
}

# Metadata for violation tracking
violation_type := "privileged_container"
severity := "critical"
