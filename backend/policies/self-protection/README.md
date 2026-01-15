# InfraPilot Self-Protection Policies

These OPA (Open Policy Agent) policies enforce security on InfraPilot itself, preventing the platform from becoming a security weakness.

## Philosophy

**"InfraPilot enforces security on itself"**

These policies ensure that InfraPilot cannot be used to:
- Escape containers
- Gain privileged access
- Expose the Docker API
- Compromise the host system
- Weaken the control plane

## Policies

### 1. Privileged Containers (`privileged_containers.rego`)

**Purpose**: Prevent deployment of privileged containers

**Blocks**:
- `privileged: true` containers
- CAP_SYS_ADMIN capability
- ALL capabilities
- Forbidden capabilities (SYS_MODULE, SYS_RAWIO, NET_ADMIN, etc.)

**Severity**: Critical

**Why**: Privileged containers can escape to the host and compromise the entire system.

---

### 2. Docker Socket (`docker_socket.rego`)

**Purpose**: Prevent mounting Docker socket

**Blocks**:
- `/var/run/docker.sock` mounts (any mode)
- `/run/docker.sock` mounts
- Windows Docker socket mounts
- Volume mounts containing `docker.sock`
- Writable `/var/run` mounts
- Docker directory mounts (`/var/lib/docker`, `/etc/docker`)

**Severity**: Critical

**Why**: Docker socket access allows complete container escape and host control.

---

### 3. Docker API Exposure (`docker_api.rego`)

**Purpose**: Prevent exposure of Docker API ports

**Blocks**:
- Port 2375 (Docker API HTTP)
- Port 2376 (Docker API HTTPS)
- Port 2377 (Docker Swarm)
- Port forwarding to Docker daemon
- Binding to 0.0.0.0 for Docker ports

**Severity**: High

**Why**: Exposed Docker API allows remote container management and potential compromise.

---

### 4. Root User (`root_user.rego`)

**Purpose**: Prevent containers from running as root

**Blocks**:
- `user: root` containers
- `user: 0` (UID 0)
- `RunAsUser: 0` in SecurityContext
- Containers without `RunAsNonRoot: true`

**Warns**:
- Containers without explicit user specified

**Severity**: Medium

**Why**: Root containers increase attack surface and privilege escalation risk.

---

### 5. Host Access (`host_access.rego`)

**Purpose**: Prevent access to host namespaces

**Blocks**:
- `network_mode: host`
- `pid_mode: host`
- `ipc_mode: host`
- `uts_mode: host`
- Mounts to sensitive paths (`/`, `/boot`, `/dev`, `/etc`, `/proc`, `/sys`, `/usr`)

**Severity**: High

**Why**: Host namespace access breaks container isolation and enables attacks.

---

### 6. Security Profiles (`seccomp_apparmor.rego`)

**Purpose**: Enforce security profiles for defense-in-depth

**Blocks**:
- `no-new-privileges=false`
- SELinux type `spc_t` (super privileged container)

**Warns**:
- `seccomp=unconfined`
- `apparmor=unconfined`
- Missing `no-new-privileges` flag

**Severity**: Medium

**Why**: Security profiles provide additional layers of protection.

---

## How Policies Are Evaluated

1. **On Container Deployment**:
   - All self-protection policies are evaluated
   - Any `deny` rule blocks the deployment
   - `warn` rules log warnings but don't block

2. **Violation Tracking**:
   - Failed deployments are logged as policy violations
   - Violations are stored in `policy_violations` table
   - Alerts can be triggered on repeated violations

3. **Audit Trail**:
   - All policy evaluations are logged
   - Immutable audit trail in `platform_security_audit`
   - Includes user, IP, timestamp, payload

## Policy Structure

Each policy follows this structure:

```rego
package infrapilot.selfprotection

# Deny rules (block deployment)
deny[msg] {
    <condition>
    msg := "<explanation>"
}

# Warning rules (log but don't block)
warn[msg] {
    <condition>
    msg := "<explanation>"
}

# Metadata for violation tracking
violation_type := "<type>"
severity := "<critical|high|medium|low>"
```

## Testing Policies

Test policies using OPA CLI:

```bash
# Test a single policy
opa test policies/self-protection/privileged_containers.rego

# Evaluate against sample input
opa eval -d policies/self-protection/ -i test-input.json "data.infrapilot.selfprotection.deny"
```

Example test input:

```json
{
  "container": {
    "privileged": true,
    "user": "root",
    "mounts": [
      {
        "source": "/var/run/docker.sock",
        "destination": "/var/run/docker.sock",
        "read_only": false
      }
    ],
    "ports": [
      {
        "host_port": 2375,
        "container_port": 2375
      }
    ]
  }
}
```

Expected result: Multiple deny messages

## Disabling Policies (Not Recommended)

Policies can be disabled in `platform_security_config`:

```sql
UPDATE platform_security_config
SET block_privileged_containers = FALSE
WHERE org_id = '<org-id>';
```

**Warning**: Disabling self-protection policies reduces platform security. Only disable for specific, documented reasons.

## Policy Updates

When updating policies:

1. Test changes with OPA CLI
2. Review impact on existing deployments
3. Document changes in migration notes
4. Consider backward compatibility

## Compliance Mapping

These policies help satisfy:

- **CIS Docker Benchmark**: 5.1, 5.2, 5.3, 5.4, 5.5, 5.7, 5.12
- **NIST 800-190**: 4.1, 4.2, 4.3, 4.4
- **PCI DSS**: 2.2, 6.5
- **SOC 2**: CC6.6, CC7.2

## References

- [OPA Documentation](https://www.openpolicyagent.org/docs/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST SP 800-190](https://csrc.nist.gov/publications/detail/sp/800-190/final)
