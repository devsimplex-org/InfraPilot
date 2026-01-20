# DevSecOps Epic Instructions

Detailed implementation instructions for transforming InfraPilot into a DevSecOps-first platform.

## Table of Contents

- [Epic 0: DevSecOps Foundations](#epic-0-devsecops-foundations)
- [Epic 1: Supply Chain Security](#epic-1-supply-chain-security)
- [Epic 2: Policy-as-Code](#epic-2-policy-as-code)
- [Epic 3: Runtime Security](#epic-3-runtime-security)
- [Epic 4: Dev Integration](#epic-4-dev-integration)
- [Epic 5: DevSecOps Observability](#epic-5-devsecops-observability)
- [Epic 6: DevSecOps Hardening](#epic-6-devsecops-hardening)
- [Epic 7: Research Readiness](#epic-7-research-readiness)

---

## Epic 0: DevSecOps Foundations

**Objective**: Redefine InfraPilot's core domain from "containers" to "secure deployments"

**Priority**: P0 (MANDATORY)

**Why This Epic Exists**: Without this, everything else is just tooling attached to Ops. The deployment entity is the foundation of DevSecOps traceability.

### 0.1 Deployment as First-Class Entity

**Description**: Create a new core domain object that represents a deployment, not just a container.

#### Database Schema

```sql
-- Migration: 010_create_deployments.up.sql

CREATE TYPE deployment_status AS ENUM ('pending', 'scanning', 'policy_check', 'deploying', 'running', 'failed', 'rolled_back');
CREATE TYPE policy_decision AS ENUM ('allow', 'warn', 'deny');

CREATE TABLE deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL REFERENCES agents(id),

    -- Service identification
    service_name VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),

    -- Image information
    image_registry VARCHAR(255),
    image_repository VARCHAR(255) NOT NULL,
    image_tag VARCHAR(255),
    image_digest VARCHAR(255) NOT NULL, -- sha256:...

    -- Provenance (traceability)
    git_repo VARCHAR(500),
    git_branch VARCHAR(255),
    git_commit VARCHAR(64),
    ci_provider VARCHAR(50),
    ci_pipeline_id VARCHAR(255),
    ci_build_url VARCHAR(500),

    -- Security
    scan_result_id UUID REFERENCES scan_results(id),
    sbom_id UUID REFERENCES sboms(id),
    policy_decision policy_decision NOT NULL DEFAULT 'allow',
    policy_reason TEXT,

    -- Status
    status deployment_status NOT NULL DEFAULT 'pending',

    -- Relationships
    replaces_deployment_id UUID REFERENCES deployments(id),
    rollback_of_deployment_id UUID REFERENCES deployments(id),

    -- Audit
    deployed_by UUID REFERENCES users(id),
    deployed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_deployments_org ON deployments(org_id);
CREATE INDEX idx_deployments_agent ON deployments(agent_id);
CREATE INDEX idx_deployments_service ON deployments(service_name, environment);
CREATE INDEX idx_deployments_image ON deployments(image_digest);
CREATE INDEX idx_deployments_git ON deployments(git_repo, git_commit);
CREATE INDEX idx_deployments_status ON deployments(status);
CREATE INDEX idx_deployments_created ON deployments(created_at DESC);
```

#### Go Model

```go
// backend/internal/db/models/deployment.go

package models

import (
    "time"
    "github.com/google/uuid"
)

type DeploymentStatus string
type PolicyDecision string

const (
    DeploymentStatusPending     DeploymentStatus = "pending"
    DeploymentStatusScanning    DeploymentStatus = "scanning"
    DeploymentStatusPolicyCheck DeploymentStatus = "policy_check"
    DeploymentStatusDeploying   DeploymentStatus = "deploying"
    DeploymentStatusRunning     DeploymentStatus = "running"
    DeploymentStatusFailed      DeploymentStatus = "failed"
    DeploymentStatusRolledBack  DeploymentStatus = "rolled_back"

    PolicyDecisionAllow PolicyDecision = "allow"
    PolicyDecisionWarn  PolicyDecision = "warn"
    PolicyDecisionDeny  PolicyDecision = "deny"
)

type Deployment struct {
    ID        uuid.UUID `json:"id"`
    OrgID     uuid.UUID `json:"org_id"`
    AgentID   uuid.UUID `json:"agent_id"`

    // Service
    ServiceName string `json:"service_name"`
    Environment string `json:"environment"`

    // Image
    ImageRegistry   string `json:"image_registry"`
    ImageRepository string `json:"image_repository"`
    ImageTag        string `json:"image_tag"`
    ImageDigest     string `json:"image_digest"`

    // Provenance
    GitRepo       string `json:"git_repo,omitempty"`
    GitBranch     string `json:"git_branch,omitempty"`
    GitCommit     string `json:"git_commit,omitempty"`
    CIProvider    string `json:"ci_provider,omitempty"`
    CIPipelineID  string `json:"ci_pipeline_id,omitempty"`
    CIBuildURL    string `json:"ci_build_url,omitempty"`

    // Security
    ScanResultID   *uuid.UUID     `json:"scan_result_id,omitempty"`
    SBOMID         *uuid.UUID     `json:"sbom_id,omitempty"`
    PolicyDecision PolicyDecision `json:"policy_decision"`
    PolicyReason   string         `json:"policy_reason,omitempty"`

    // Status
    Status DeploymentStatus `json:"status"`

    // Relationships
    ReplacesDeploymentID  *uuid.UUID `json:"replaces_deployment_id,omitempty"`
    RollbackOfDeploymentID *uuid.UUID `json:"rollback_of_deployment_id,omitempty"`

    // Audit
    DeployedBy *uuid.UUID `json:"deployed_by,omitempty"`
    DeployedAt *time.Time `json:"deployed_at,omitempty"`
    CreatedAt  time.Time  `json:"created_at"`
    UpdatedAt  time.Time  `json:"updated_at"`
}
```

#### API Endpoints

```go
// New deployment endpoints
POST   /api/v1/agents/:id/deployments              // Create deployment
GET    /api/v1/agents/:id/deployments              // List deployments
GET    /api/v1/agents/:id/deployments/:did         // Get deployment
GET    /api/v1/agents/:id/deployments/:did/history // Deployment history
POST   /api/v1/agents/:id/deployments/:did/rollback // Rollback deployment
DELETE /api/v1/agents/:id/deployments/:did         // Delete deployment

// Service-based endpoints
GET    /api/v1/services                            // List all services
GET    /api/v1/services/:name/deployments          // Deployments for service
GET    /api/v1/services/:name/current              // Current deployment
```

#### Acceptance Criteria

- [ ] Every container references a deployment
- [ ] No container runs without a deployment record
- [ ] Every restart is tied to deployment_id
- [ ] Can answer: "Which commit is running right now?"
- [ ] Can diff two deployments of the same service

#### Research Relevance

**Paper Section**: Provenance & Traceability
- Enables complete audit trail from code to runtime
- Supports supply chain integrity verification

---

### 0.2 Container-Deployment Relationship

**Description**: Link existing containers to deployments

#### Database Changes

```sql
-- Add deployment reference to containers
ALTER TABLE containers ADD COLUMN deployment_id UUID REFERENCES deployments(id);
CREATE INDEX idx_containers_deployment ON containers(deployment_id);
```

#### Implementation Notes

- Existing containers get `deployment_id = NULL` (legacy)
- New containers MUST have a deployment
- Container restart creates new container record with same deployment_id

---

## Epic 1: Supply Chain Security

**Objective**: No image runs unless it is scanned, attested, and policy-approved

**Priority**: P0

### 1.1 Image Scanning Pipeline

**Description**: Add a Scanner Service that scans images before deployment

#### Scanner Service Architecture

```
┌──────────────┐
│   Trivy      │ ◄── External binary
└──────┬───────┘
       │
┌──────▼───────┐
│   Scanner    │ ◄── Go service
│   Service    │
└──────┬───────┘
       │ gRPC
┌──────▼───────┐
│   Backend    │
└──────────────┘
```

#### Database Schema

```sql
-- Migration: 011_create_scan_results.up.sql

CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'unknown');

CREATE TABLE scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),

    -- Image
    image_digest VARCHAR(255) NOT NULL,
    image_repository VARCHAR(255) NOT NULL,
    image_tag VARCHAR(255),

    -- Summary
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    unknown_count INTEGER NOT NULL DEFAULT 0,
    total_count INTEGER NOT NULL DEFAULT 0,
    fixable_count INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    scanner_name VARCHAR(50) NOT NULL DEFAULT 'trivy',
    scanner_version VARCHAR(50),
    scan_duration_ms INTEGER,

    -- Raw data
    raw_output JSONB,

    -- Timestamps
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_result_id UUID NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,

    -- CVE info
    cve_id VARCHAR(50) NOT NULL,
    severity severity_level NOT NULL,

    -- Package info
    package_name VARCHAR(255) NOT NULL,
    package_version VARCHAR(100),
    package_type VARCHAR(50), -- os, library, etc.

    -- Fix info
    fixed_version VARCHAR(100),
    fix_available BOOLEAN NOT NULL DEFAULT FALSE,

    -- Details
    title VARCHAR(500),
    description TEXT,
    references JSONB,

    -- CVSS
    cvss_v3_score DECIMAL(3,1),
    cvss_v3_vector VARCHAR(100),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_scan_results_image ON scan_results(image_digest);
CREATE INDEX idx_scan_results_org ON scan_results(org_id);
CREATE INDEX idx_vulnerabilities_scan ON vulnerabilities(scan_result_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_cve ON vulnerabilities(cve_id);
```

#### Scanner Service Implementation

```go
// backend/internal/scanner/service.go

package scanner

import (
    "context"
    "encoding/json"
    "os/exec"
)

type ScanResult struct {
    ImageDigest     string `json:"image_digest"`
    CriticalCount   int    `json:"critical"`
    HighCount       int    `json:"high"`
    MediumCount     int    `json:"medium"`
    LowCount        int    `json:"low"`
    TotalCount      int    `json:"total"`
    FixableCount    int    `json:"fixable"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
    CVEID          string  `json:"cve_id"`
    Severity       string  `json:"severity"`
    PackageName    string  `json:"package_name"`
    PackageVersion string  `json:"package_version"`
    FixedVersion   string  `json:"fixed_version,omitempty"`
    FixAvailable   bool    `json:"fix_available"`
    Title          string  `json:"title"`
    Description    string  `json:"description"`
    CVSSScore      float64 `json:"cvss_score,omitempty"`
}

type Scanner struct {
    trivyPath string
}

func NewScanner() *Scanner {
    return &Scanner{trivyPath: "trivy"}
}

func (s *Scanner) ScanImage(ctx context.Context, imageRef string) (*ScanResult, error) {
    // Run Trivy
    cmd := exec.CommandContext(ctx, s.trivyPath,
        "image",
        "--format", "json",
        "--quiet",
        imageRef,
    )

    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    // Parse Trivy output
    var trivyResult TrivyOutput
    if err := json.Unmarshal(output, &trivyResult); err != nil {
        return nil, err
    }

    // Convert to our format
    return s.convertResult(trivyResult), nil
}
```

#### API Endpoints

```go
// Scanner endpoints
POST /api/v1/agents/:id/scan                    // Trigger scan
GET  /api/v1/agents/:id/scans                   // List scans
GET  /api/v1/agents/:id/scans/:sid              // Get scan result
GET  /api/v1/agents/:id/scans/:sid/vulnerabilities // List vulnerabilities
```

#### Acceptance Criteria

- [ ] Scan happens before container start
- [ ] Scan results stored immutably
- [ ] Scan is reproducible (same image = same results)
- [ ] Scan failure blocks deployment (configurable)

---

### 1.2 SBOM Generation

**Description**: Generate Software Bill of Materials for each image

#### Database Schema

```sql
-- Migration: 012_create_sboms.up.sql

CREATE TABLE sboms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),

    -- Image
    image_digest VARCHAR(255) NOT NULL,
    image_repository VARCHAR(255) NOT NULL,

    -- SBOM data
    format VARCHAR(20) NOT NULL CHECK (format IN ('cyclonedx', 'spdx')),
    version VARCHAR(20) NOT NULL,

    -- Package counts
    total_packages INTEGER NOT NULL DEFAULT 0,
    os_packages INTEGER NOT NULL DEFAULT 0,
    library_packages INTEGER NOT NULL DEFAULT 0,

    -- Raw SBOM
    sbom_json JSONB NOT NULL,

    -- Generator
    generator_name VARCHAR(50) NOT NULL DEFAULT 'syft',
    generator_version VARCHAR(50),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_sboms_image ON sboms(image_digest);
CREATE INDEX idx_sboms_org ON sboms(org_id);
```

#### Implementation

```go
// Generate SBOM using Syft
func (s *Scanner) GenerateSBOM(ctx context.Context, imageRef string) (*SBOM, error) {
    cmd := exec.CommandContext(ctx, "syft",
        imageRef,
        "-o", "cyclonedx-json",
    )

    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    var sbom SBOM
    if err := json.Unmarshal(output, &sbom); err != nil {
        return nil, err
    }

    return &sbom, nil
}
```

#### Acceptance Criteria

- [ ] SBOM generated for every deployment
- [ ] SBOM linked to image digest
- [ ] SBOM versioned
- [ ] SBOM downloadable via UI/API

---

## Epic 2: Policy-as-Code

**Objective**: Security decisions are automatic, versioned, and auditable

**Priority**: P0

### 2.1 OPA Policy Engine Integration

**Description**: Embed Open Policy Agent for policy decisions

#### Architecture

```
┌──────────────────┐
│  Policy Store    │ ◄── Git-backed policies
└────────┬─────────┘
         │
┌────────▼─────────┐
│   OPA Engine     │ ◄── Embedded or sidecar
└────────┬─────────┘
         │
┌────────▼─────────┐
│   Policy API     │ ◄── Decision endpoint
└────────┬─────────┘
         │
┌────────▼─────────┐
│  Deployment      │
│  Pipeline        │
└──────────────────┘
```

#### Database Schema

```sql
-- Migration: 013_create_policies.up.sql

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),

    -- Policy info
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Content
    rego_code TEXT NOT NULL,

    -- Scope
    environments TEXT[] NOT NULL DEFAULT '{}', -- empty = all
    services TEXT[] NOT NULL DEFAULT '{}',     -- empty = all

    -- Settings
    enforcement VARCHAR(20) NOT NULL DEFAULT 'enforce' CHECK (enforcement IN ('enforce', 'warn', 'disabled')),

    -- Versioning
    version INTEGER NOT NULL DEFAULT 1,

    -- Audit
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE policy_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id UUID NOT NULL REFERENCES deployments(id),
    policy_id UUID REFERENCES policies(id),

    -- Decision
    decision policy_decision NOT NULL,
    reason TEXT,

    -- Input/Output
    input_data JSONB,
    output_data JSONB,

    -- Timing
    evaluation_time_ms INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_policies_org ON policies(org_id);
CREATE INDEX idx_policy_decisions_deployment ON policy_decisions(deployment_id);
```

#### Default Policies

```rego
# policies/default/no_latest_tag.rego
package infrapilot.security

deny[msg] {
    input.image.tag == "latest"
    msg := "Using 'latest' tag is forbidden in production"
}

deny[msg] {
    input.image.tag == ""
    msg := "Image tag is required"
}
```

```rego
# policies/default/no_critical_vulns.rego
package infrapilot.security

deny[msg] {
    input.environment == "prod"
    input.scan.critical > 0
    msg := sprintf("Critical vulnerabilities detected: %d", [input.scan.critical])
}

warn[msg] {
    input.environment == "staging"
    input.scan.critical > 0
    msg := sprintf("Critical vulnerabilities detected: %d", [input.scan.critical])
}
```

```rego
# policies/default/no_high_vulns_prod.rego
package infrapilot.security

deny[msg] {
    input.environment == "prod"
    input.scan.high > 5
    msg := sprintf("Too many high vulnerabilities: %d (max 5)", [input.scan.high])
}
```

```rego
# policies/default/require_digest.rego
package infrapilot.security

deny[msg] {
    input.image.digest == ""
    msg := "Image digest is required for deployment"
}
```

#### Policy Engine Service

```go
// backend/internal/policy/engine.go

package policy

import (
    "context"
    "github.com/open-policy-agent/opa/rego"
)

type PolicyInput struct {
    Environment string     `json:"environment"`
    Service     string     `json:"service"`
    Image       ImageInfo  `json:"image"`
    Scan        ScanInfo   `json:"scan"`
    SBOM        SBOMInfo   `json:"sbom"`
    Deployment  DeployInfo `json:"deployment"`
}

type PolicyResult struct {
    Decision PolicyDecision
    Denies   []string
    Warnings []string
}

type PolicyEngine struct {
    query *rego.PreparedEvalQuery
}

func (e *PolicyEngine) Evaluate(ctx context.Context, input PolicyInput) (*PolicyResult, error) {
    results, err := e.query.Eval(ctx, rego.EvalInput(input))
    if err != nil {
        return nil, err
    }

    result := &PolicyResult{Decision: PolicyDecisionAllow}

    // Process deny rules
    if denies, ok := results[0].Bindings["deny"].([]interface{}); ok {
        for _, d := range denies {
            result.Denies = append(result.Denies, d.(string))
        }
        if len(result.Denies) > 0 {
            result.Decision = PolicyDecisionDeny
        }
    }

    // Process warn rules
    if warns, ok := results[0].Bindings["warn"].([]interface{}); ok {
        for _, w := range warns {
            result.Warnings = append(result.Warnings, w.(string))
        }
        if result.Decision == PolicyDecisionAllow && len(result.Warnings) > 0 {
            result.Decision = PolicyDecisionWarn
        }
    }

    return result, nil
}
```

#### API Endpoints

```go
// Policy endpoints
GET    /api/v1/policies                    // List policies
POST   /api/v1/policies                    // Create policy
GET    /api/v1/policies/:id                // Get policy
PUT    /api/v1/policies/:id                // Update policy
DELETE /api/v1/policies/:id                // Delete policy
POST   /api/v1/policies/evaluate           // Test policy evaluation
GET    /api/v1/policies/:id/decisions      // Policy decision history
```

#### Acceptance Criteria

- [ ] Policies block deployments
- [ ] Policy decision stored forever
- [ ] Policy changes are versioned
- [ ] Same image can pass dev but fail prod

---

### 2.2 Environment-Scoped Policies

**Description**: Policies differ by environment

| Environment | Behavior |
|-------------|----------|
| dev | Warn only |
| staging | Block critical |
| prod | Block high + critical |

#### Implementation

```rego
# Environment-aware policy
package infrapilot.security

default allow = true

deny[msg] {
    input.environment == "prod"
    input.scan.critical > 0
    msg := "Critical vulnerabilities not allowed in prod"
}

deny[msg] {
    input.environment == "prod"
    input.scan.high > 5
    msg := "Max 5 high vulnerabilities in prod"
}

warn[msg] {
    input.environment == "staging"
    input.scan.critical > 0
    msg := "Critical vulnerabilities detected in staging"
}
```

---

## Epic 3: Runtime Security

**Objective**: Detect security drift after deployment

**Priority**: P0

### 3.1 Drift Detection Engine

**Description**: Continuously compare desired vs actual state

#### Database Schema

```sql
-- Migration: 014_create_drift_events.up.sql

CREATE TYPE drift_type AS ENUM (
    'image_changed',
    'port_added',
    'port_removed',
    'privilege_escalation',
    'config_modified',
    'container_restarted',
    'resource_exceeded'
);

CREATE TYPE drift_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');

CREATE TABLE drift_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL REFERENCES agents(id),
    deployment_id UUID REFERENCES deployments(id),
    container_id VARCHAR(64),

    -- Drift info
    drift_type drift_type NOT NULL,
    severity drift_severity NOT NULL,

    -- Details
    description TEXT NOT NULL,
    expected_state JSONB,
    actual_state JSONB,

    -- Resolution
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID REFERENCES users(id),
    resolution_notes TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_drift_events_org ON drift_events(org_id);
CREATE INDEX idx_drift_events_deployment ON drift_events(deployment_id);
CREATE INDEX idx_drift_events_type ON drift_events(drift_type);
CREATE INDEX idx_drift_events_resolved ON drift_events(resolved);
```

#### Drift Detector Implementation

```go
// agent/internal/drift/detector.go

package drift

type DriftDetector struct {
    dockerClient *docker.Client
    grpcClient   *grpc.AgentClient
    interval     time.Duration
}

func (d *DriftDetector) Start(ctx context.Context) {
    ticker := time.NewTicker(d.interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            d.checkForDrift(ctx)
        }
    }
}

func (d *DriftDetector) checkForDrift(ctx context.Context) {
    containers, err := d.dockerClient.ContainerList(ctx, docker.ContainerListOptions{})
    if err != nil {
        return
    }

    for _, container := range containers {
        d.checkImageDrift(ctx, container)
        d.checkPortDrift(ctx, container)
        d.checkPrivilegeDrift(ctx, container)
        d.checkRestartDrift(ctx, container)
    }
}

func (d *DriftDetector) checkImageDrift(ctx context.Context, container docker.Container) {
    // Compare running image digest with deployment's expected digest
    expectedDigest := d.getExpectedDigest(container.ID)
    actualDigest := d.getActualDigest(ctx, container.ID)

    if expectedDigest != actualDigest {
        d.reportDrift(DriftEvent{
            Type:          DriftTypeImageChanged,
            Severity:      SeverityCritical,
            Description:   "Container image changed without deployment",
            ExpectedState: expectedDigest,
            ActualState:   actualDigest,
        })
    }
}
```

#### Detected Drift Types

| Drift Type | Severity | Description |
|------------|----------|-------------|
| `image_changed` | Critical | Image changed without deployment |
| `port_added` | High | New port exposed |
| `privilege_escalation` | Critical | Container gained privileges |
| `config_modified` | Medium | Nginx config changed manually |
| `container_restarted` | Info | Unexpected restart |

#### Acceptance Criteria

- [ ] Drift triggers alert
- [ ] Drift logged as security event
- [ ] Drift linked to deployment

---

### 3.2 Behavioral Monitoring

**Description**: Detect anomalous behavior patterns

#### Signals to Monitor

| Signal | Detection Method |
|--------|------------------|
| Crash loops | >3 restarts in 5 minutes |
| Log volume spike | >10x normal volume |
| Error rate spike | >50% 5xx responses |
| Resource exhaustion | >90% CPU/memory |

#### Implementation

```go
type BehaviorMonitor struct {
    metricsBuffer map[string][]Metric
}

func (m *BehaviorMonitor) DetectAnomalies(containerID string) []Anomaly {
    var anomalies []Anomaly

    metrics := m.metricsBuffer[containerID]

    // Crash loop detection
    if m.detectCrashLoop(metrics) {
        anomalies = append(anomalies, Anomaly{
            Type:     "crash_loop",
            Severity: "high",
        })
    }

    // Log volume spike
    if m.detectLogSpike(metrics) {
        anomalies = append(anomalies, Anomaly{
            Type:     "log_volume_spike",
            Severity: "medium",
        })
    }

    return anomalies
}
```

---

## Epic 4: Dev Integration

**Objective**: Close the Dev → Sec → Ops loop

**Priority**: P0

### 4.1 CI Webhook Ingestor

**Description**: Accept CI events from GitHub, GitLab, etc.

#### Supported Providers

| Provider | Events |
|----------|--------|
| GitHub Actions | `workflow_run`, `deployment` |
| GitLab CI | `Pipeline Hook`, `Deployment Hook` |
| Bitbucket | `repo:push`, `repo:deploy` |
| Generic | Custom webhook format |

#### Database Schema

```sql
-- Migration: 015_create_ci_events.up.sql

CREATE TABLE ci_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),

    -- Provider
    provider VARCHAR(50) NOT NULL,

    -- Repository
    repo_owner VARCHAR(255) NOT NULL,
    repo_name VARCHAR(255) NOT NULL,

    -- Commit
    commit_sha VARCHAR(64) NOT NULL,
    commit_message TEXT,
    commit_author VARCHAR(255),
    branch VARCHAR(255),

    -- Pipeline
    pipeline_id VARCHAR(255) NOT NULL,
    pipeline_url VARCHAR(500),
    pipeline_status VARCHAR(50),

    -- Image
    image_repository VARCHAR(255),
    image_tag VARCHAR(255),
    image_digest VARCHAR(255),

    -- Raw
    raw_payload JSONB,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_ci_events_org ON ci_events(org_id);
CREATE INDEX idx_ci_events_commit ON ci_events(commit_sha);
CREATE INDEX idx_ci_events_pipeline ON ci_events(pipeline_id);
```

#### API Endpoints

```go
// Webhook endpoints
POST /api/v1/webhooks/github         // GitHub webhook
POST /api/v1/webhooks/gitlab         // GitLab webhook
POST /api/v1/webhooks/bitbucket      // Bitbucket webhook
POST /api/v1/webhooks/generic        // Generic webhook

// CI event endpoints
GET  /api/v1/ci-events               // List CI events
GET  /api/v1/ci-events/:id           // Get CI event
```

#### Webhook Handler

```go
// backend/internal/api/webhook_handlers.go

func (h *Handler) handleGitHubWebhook(c *gin.Context) {
    // Verify webhook signature
    signature := c.GetHeader("X-Hub-Signature-256")
    if !h.verifyGitHubSignature(c.Request.Body, signature) {
        c.JSON(401, gin.H{"error": "Invalid signature"})
        return
    }

    var event GitHubEvent
    if err := c.BindJSON(&event); err != nil {
        c.JSON(400, gin.H{"error": "Invalid payload"})
        return
    }

    // Store CI event
    ciEvent := &models.CIEvent{
        Provider:      "github",
        RepoOwner:     event.Repository.Owner.Login,
        RepoName:      event.Repository.Name,
        CommitSHA:     event.HeadCommit.ID,
        CommitMessage: event.HeadCommit.Message,
        Branch:        event.Ref,
    }

    if err := h.db.CreateCIEvent(c, ciEvent); err != nil {
        c.JSON(500, gin.H{"error": "Failed to store event"})
        return
    }

    c.JSON(200, gin.H{"status": "received"})
}
```

---

### 4.2 Deployment Gate API

**Description**: CI can ask InfraPilot if deployment is allowed

#### API Endpoint

```go
// Deployment gate
POST /api/v1/gate/check

// Request
{
    "image": "myrepo/myapp:v1.2.3",
    "image_digest": "sha256:abc123...",
    "environment": "prod",
    "service": "api",
    "commit_sha": "abc123",
    "pipeline_id": "12345"
}

// Response (allowed)
{
    "decision": "allow",
    "scan": {
        "critical": 0,
        "high": 2,
        "medium": 5
    },
    "policies_evaluated": 5,
    "deployment_id": "uuid"
}

// Response (denied)
{
    "decision": "deny",
    "reasons": [
        "Critical vulnerabilities detected: 3",
        "Using 'latest' tag is forbidden"
    ],
    "scan": {
        "critical": 3,
        "high": 10,
        "medium": 15
    }
}
```

#### GitHub Actions Example

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Build and Push
        run: docker build -t myapp:${{ github.sha }} . && docker push myapp:${{ github.sha }}

      - name: Check Deployment Gate
        id: gate
        run: |
          RESPONSE=$(curl -s -X POST \
            -H "Authorization: Bearer ${{ secrets.INFRAPILOT_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d '{
              "image": "myapp:${{ github.sha }}",
              "environment": "prod",
              "commit_sha": "${{ github.sha }}",
              "pipeline_id": "${{ github.run_id }}"
            }' \
            https://infrapilot.example.com/api/v1/gate/check)

          DECISION=$(echo $RESPONSE | jq -r '.decision')
          if [ "$DECISION" != "allow" ]; then
            echo "Deployment blocked by policy"
            echo $RESPONSE | jq '.reasons'
            exit 1
          fi

      - name: Deploy
        if: steps.gate.outputs.decision == 'allow'
        run: |
          curl -X POST \
            -H "Authorization: Bearer ${{ secrets.INFRAPILOT_TOKEN }}" \
            https://infrapilot.example.com/api/v1/agents/$AGENT_ID/deployments \
            -d '{"image": "myapp:${{ github.sha }}", "service": "api"}'
```

---

## Epic 5: DevSecOps Observability

**Objective**: Make DevSecOps visible, explainable, and measurable

**Priority**: P1

### 5.1 Security Posture Dashboard

**Description**: Single-pane view of security status

#### Dashboard Components

1. **Risk Score** (0-100)
   - Based on vulnerabilities, policy violations, drift events

2. **Vulnerability Trend**
   - Critical/High/Medium over time
   - Per service breakdown

3. **Deployment Health**
   - Blocked vs allowed
   - Change failure rate

4. **Compliance Status**
   - Policy adherence
   - SBOM coverage

#### API Endpoints

```go
GET /api/v1/dashboard/security-posture    // Overall posture
GET /api/v1/dashboard/vulnerabilities     // Vulnerability stats
GET /api/v1/dashboard/deployments         // Deployment stats
GET /api/v1/dashboard/risk-score          // Risk calculation
```

---

### 5.2 Unified Audit Timeline

**Description**: Single timeline from code to incident

```
Timeline Entry Types:
├── CI Event (code pushed, build started)
├── Scan Event (scan started, completed)
├── Policy Event (policy evaluated, decision made)
├── Deployment Event (deployment started, completed)
├── Runtime Event (drift detected, anomaly)
├── Incident Event (alert triggered, resolved)
└── User Event (config changed, rollback)
```

#### Database Schema

```sql
-- Migration: 016_create_timeline.up.sql

CREATE TYPE timeline_event_type AS ENUM (
    'ci_push',
    'ci_build',
    'scan_started',
    'scan_completed',
    'policy_evaluated',
    'deployment_started',
    'deployment_completed',
    'deployment_failed',
    'drift_detected',
    'anomaly_detected',
    'alert_triggered',
    'incident_created',
    'incident_resolved',
    'rollback_initiated',
    'config_changed'
);

CREATE TABLE timeline_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),

    -- Type
    event_type timeline_event_type NOT NULL,

    -- Relationships
    deployment_id UUID REFERENCES deployments(id),
    service_name VARCHAR(255),

    -- Event data
    title VARCHAR(500) NOT NULL,
    description TEXT,
    metadata JSONB,

    -- Severity
    severity VARCHAR(20),

    -- Actor
    actor_type VARCHAR(20), -- user, system, ci
    actor_id UUID,
    actor_name VARCHAR(255),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_timeline_org ON timeline_events(org_id);
CREATE INDEX idx_timeline_deployment ON timeline_events(deployment_id);
CREATE INDEX idx_timeline_service ON timeline_events(service_name);
CREATE INDEX idx_timeline_created ON timeline_events(created_at DESC);
```

---

## Epic 6: DevSecOps Hardening

**Objective**: InfraPilot must enforce security on itself

**Priority**: P1

### 6.1 Secure Defaults

| Setting | Secure Default |
|---------|----------------|
| MFA | Required for admins |
| Docker socket | Read-only |
| TLS | Everywhere |
| Password length | 12+ characters |
| Session timeout | 30 minutes |

### 6.2 Self-Protection Policies

```rego
# InfraPilot cannot deploy privileged containers
deny[msg] {
    input.container.privileged == true
    msg := "Privileged containers are not allowed"
}

# InfraPilot cannot expose Docker API
deny[msg] {
    some port in input.container.ports
    port.private_port == 2375
    msg := "Docker API port exposure is forbidden"
}

# InfraPilot cannot run as root
deny[msg] {
    input.container.user == "root"
    input.container.user == "0"
    msg := "Running as root is not allowed"
}
```

---

## Epic 7: Research Readiness

**Objective**: Make InfraPilot measurable and publishable

**Priority**: P1

### 7.1 Experiment Harness

**Required Experiments**:

| Experiment | Description | Metric |
|------------|-------------|--------|
| Vulnerable Deploy | Attempt to deploy image with critical CVEs | Detection latency, block rate |
| Policy Block | Test policy enforcement | Success rate, decision time |
| Drift Injection | Manually modify running container | Detection accuracy, time |
| Incident Response | Simulate incident, measure response | MTTR |
| Overhead | Measure resource impact | CPU, memory, latency |

### 7.2 Metrics Export

```go
// Prometheus metrics
var (
    deploymentsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "infrapilot_deployments_total",
            Help: "Total deployments",
        },
        []string{"environment", "decision"},
    )

    scanDuration = prometheus.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "infrapilot_scan_duration_seconds",
            Help:    "Image scan duration",
            Buckets: prometheus.DefBuckets,
        },
    )

    policyEvalDuration = prometheus.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "infrapilot_policy_eval_duration_seconds",
            Help:    "Policy evaluation duration",
            Buckets: prometheus.DefBuckets,
        },
    )

    vulnerabilitiesDetected = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "infrapilot_vulnerabilities",
            Help: "Detected vulnerabilities by severity",
        },
        []string{"severity"},
    )

    driftEventsTotal = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "infrapilot_drift_events_total",
            Help: "Total drift events detected",
        },
    )
)
```

---

## Definition of Done

InfraPilot is **DevSecOps-complete** when:

- [ ] Vulnerable images cannot deploy (blocked by policy)
- [ ] Every runtime artifact is traceable to source code
- [ ] Policies block, not just warn
- [ ] Drift is detected automatically
- [ ] Humans only approve exceptions
- [ ] Metrics prove security improvement

---

**Last Updated**: 2026-01-14
**Status**: Epic Definition Complete
