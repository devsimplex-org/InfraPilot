# Self-Protection Policy: Block Docker API Exposure
# Prevents exposure of Docker API ports that allow remote container management

package infrapilot.selfprotection

# Docker API ports
docker_api_ports := {2375, 2376, 2377}

# Deny exposure of Docker API ports
deny[msg] {
    some port
    input.container.ports[port].host_port
    docker_api_ports[input.container.ports[port].host_port]
    msg := sprintf("Exposing Docker API port %d is forbidden - allows remote container control", [input.container.ports[port].host_port])
}

# Deny containers exposing Docker API internally
deny[msg] {
    some port
    input.container.ports[port].container_port
    docker_api_ports[input.container.ports[port].container_port]
    msg := sprintf("Container exposing Docker API on port %d is forbidden", [input.container.ports[port].container_port])
}

# Deny port forwarding to Docker daemon
deny[msg] {
    some port
    input.container.ports[port].host_port == 2375
    msg := "Port forwarding to Docker daemon (2375) is forbidden - security risk"
}

deny[msg] {
    some port
    input.container.ports[port].host_port == 2376
    msg := "Port forwarding to Docker daemon TLS (2376) is forbidden - security risk"
}

# Deny containers listening on 0.0.0.0 for Docker API ports
deny[msg] {
    some port
    input.container.ports[port].host_ip == "0.0.0.0"
    docker_api_ports[input.container.ports[port].host_port]
    msg := sprintf("Binding Docker API port %d to 0.0.0.0 is forbidden - public exposure", [input.container.ports[port].host_port])
}

# Metadata for violation tracking
violation_type := "docker_api_exposure"
severity := "high"
