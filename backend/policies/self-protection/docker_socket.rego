# Self-Protection Policy: Block Docker Socket Mounts
# Prevents mounting of Docker socket which allows container escape

package infrapilot.selfprotection

# Docker socket paths
docker_socket_paths := {
    "/var/run/docker.sock",
    "/run/docker.sock",
    "//var/run/docker.sock",  # Windows UNC path
    "\\\\.\\pipe\\docker_engine"  # Windows named pipe
}

# Deny Docker socket mounts (any mode)
deny[msg] {
    some mount
    input.container.mounts[mount].source
    docker_socket_paths[input.container.mounts[mount].source]
    msg := sprintf("Mounting Docker socket (%s) is forbidden - allows container escape", [input.container.mounts[mount].source])
}

# Deny Docker socket volume mounts
deny[msg] {
    some volume
    input.container.volumes[volume]
    contains(input.container.volumes[volume], "docker.sock")
    msg := sprintf("Mounting Docker socket via volume (%s) is forbidden", [input.container.volumes[volume]])
}

# Deny /var/run mount that might include Docker socket
deny[msg] {
    some mount
    input.container.mounts[mount].source == "/var/run"
    input.container.mounts[mount].read_only != true
    msg := "Mounting /var/run writable is forbidden - may expose Docker socket"
}

# Deny bind mounts to Docker directories
docker_directories := {
    "/var/lib/docker",
    "/etc/docker",
    "/run/docker"
}

deny[msg] {
    some mount
    input.container.mounts[mount].source
    docker_directories[input.container.mounts[mount].source]
    msg := sprintf("Mounting Docker directory (%s) is forbidden - security risk", [input.container.mounts[mount].source])
}

# Metadata for violation tracking
violation_type := "docker_socket_mount"
severity := "critical"
