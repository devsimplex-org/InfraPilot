# InfraPilot v2.0 — Complete Epic Specifications

> Consolidated epic specifications: v1 (complete) + v2 (planned)

---

## Table of Contents

### V1 Foundation (Complete)
1. [Epic 0: DevSecOps Foundations](#epic-0-devsecops-foundations-) ✅
2. [Epic 1: Supply Chain Security](#epic-1-supply-chain-security-) ✅
3. [Epic 2: Policy-as-Code](#epic-2-policy-as-code-) ✅
4. [Epic 3: Runtime Security](#epic-3-runtime-security-) ✅
5. [Epic 4: Dev Integration](#epic-4-dev-integration-) ✅
6. [Epic 5: DevSecOps Observability](#epic-5-devsecops-observability-) ✅
7. [Epic 6: Platform Hardening](#epic-6-platform-hardening-) ✅
8. [Epic 8: Developer Feedback](#epic-8-developer-feedback-) ✅
9. [Epic 9: Risk Acceptance](#epic-9-risk-acceptance-) ✅
10. [Epic 10: Ownership & Accountability](#epic-10-ownership--accountability-) ✅
11. [Epic 11: Security Maturity Scoring](#epic-11-security-maturity-scoring-) ✅
12. [Epic 12: Code Quality Integration](#epic-12-code-quality-integration-) ✅

### V2 Expansion (Planned)
13. [Epic 7: Research & Metrics Readiness](#epic-7-research--metrics-readiness)
14. [Epic 13: Traffic & Exposure Governance](#epic-13-traffic--exposure-governance)
15. [Epic 14: Database & Data Governance](#epic-14-database--data-governance)
16. [Epic 15: Backup & Recovery Visibility](#epic-15-backup--recovery-visibility)
17. [Epic 16: Secrets Hygiene](#epic-16-secrets-hygiene)
18. [Epic 17: Background Jobs & Workers](#epic-17-background-jobs--workers)
19. [Epic 18: External Dependency Mapping](#epic-18-external-dependency-mapping)
20. [Epic 19: UX & Navigation System](#epic-19-ux--navigation-system)

---

# V1 Foundation Epics (Complete)

## Epic 0: DevSecOps Foundations ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
Make deployments first-class, traceable, auditable.

### Key Deliverables
- ✅ Deployment as first-class entity
- ✅ Container-deployment relationships
- ✅ Deployment history tracking
- ✅ Provenance tracking (Git → CI → Image → Runtime)
- ✅ Deployment spine architecture

### Database Tables
- `deployments`
- `deployment_containers`

### API Endpoints
- `POST /api/v1/deployments` - Create deployment
- `GET /api/v1/deployments` - List deployments
- `GET /api/v1/deployments/:id` - Get deployment details
- `GET /api/v1/deployments/:id/history` - Get deployment history

---

## Epic 1: Supply Chain Security ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
No unknown or unsafe software reaches production.

### Key Deliverables
- ✅ Trivy vulnerability scanning (v0.68.2)
- ✅ SBOM generation via Syft (v1.40.0, CycloneDX format)
- ✅ CVE-centric vulnerability view
- ✅ Image → SBOM → Deployment linkage
- ✅ Vulnerability database in PostgreSQL
- ✅ Severity-based prioritization

### Database Tables
- `scan_results`
- `vulnerabilities`
- `sboms`
- `sbom_components`

### API Endpoints
- `POST /api/v1/containers/:id/scan` - Trigger scan
- `GET /api/v1/vulnerabilities` - List vulnerabilities
- `GET /api/v1/vulnerabilities/:cve` - Get CVE details
- `GET /api/v1/sboms` - List SBOMs
- `GET /api/v1/sboms/:id/components` - Get SBOM components

---

## Epic 2: Policy-as-Code ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
Security decisions are automated, consistent, and explainable.

### Key Deliverables
- ✅ OPA integration (v1.12.2 with Rego)
- ✅ Environment-aware policies (dev/staging/prod)
- ✅ Policy decision audit trail
- ✅ Deployment blocking on violations
- ✅ Policy management UI
- ✅ Pre-built policy templates

### Database Tables
- `policies`
- `policy_decisions`

### API Endpoints
- `POST /api/v1/policies` - Create policy
- `GET /api/v1/policies` - List policies
- `POST /api/v1/policies/:id/evaluate` - Evaluate policy
- `GET /api/v1/policy-decisions` - List decisions

---

## Epic 3: Runtime Security ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
Detect drift and risk after deployment.

### Key Deliverables
- ✅ Configuration drift detection
- ✅ Privilege escalation detection
- ✅ Unexpected port exposure detection
- ✅ Behavioral anomaly detection (crash loops, resource spikes)
- ✅ Runtime → Deployment linkage

### Database Tables
- `drift_events`
- `behavioral_anomalies`
- `runtime_security_config`

### API Endpoints
- `GET /api/v1/drift` - List drift events
- `GET /api/v1/anomalies` - List anomalies
- `POST /api/v1/runtime/config` - Configure runtime monitoring

---

## Epic 4: Dev Integration ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
Close the CI → Infra loop.

### Key Deliverables
- ✅ GitHub / GitLab / Jenkins webhook support
- ✅ Deployment gate API
- ✅ CI metadata ingestion
- ✅ Webhook management UI with full CRUD
- ✅ Build metadata tracking (Git commit, branch, CI job)

### Database Tables
- `webhooks`
- `webhook_deliveries`

### API Endpoints
- `POST /api/v1/webhooks` - Create webhook
- `GET /api/v1/webhooks` - List webhooks
- `POST /api/v1/webhooks/:id/ingest` - Ingest webhook payload
- `POST /api/v1/gates/check` - Check deployment gate

---

## Epic 5: DevSecOps Observability ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
Make risk visible at a glance.

### Key Deliverables
- ✅ Security posture dashboard (0-100 scoring)
- ✅ Vulnerability trends over time
- ✅ Deployment health metrics
- ✅ Policy compliance metrics
- ✅ Risk-based scoring algorithm

### API Endpoints
- `GET /api/v1/dashboard/posture` - Security posture score
- `GET /api/v1/dashboard/trends` - Vulnerability trends
- `GET /api/v1/dashboard/health` - Deployment health

---

## Epic 6: Platform Hardening ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
InfraPilot must enforce security on itself.

### Key Deliverables
- ✅ Secure defaults (MFA, TLS, password complexity, session timeouts)
- ✅ Self-protection policies via OPA
- ✅ No privileged containers enforcement
- ✅ Docker socket least-privilege
- ✅ Audit-first platform actions
- ✅ Platform security self-checks

### Database Tables
- `platform_security_config`
- `policy_violations`
- `platform_security_audit`
- `platform_security_checks`

### API Endpoints
- `GET /api/v1/platform/security` - Platform security status
- `GET /api/v1/platform/audit` - Platform audit log
- `POST /api/v1/platform/check` - Run security check

---

## Epic 8: Developer Feedback ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
Security findings change developer behavior.

### Key Deliverables
- ✅ GitHub PR comment integration
- ✅ GitLab MR support
- ✅ CI annotations
- ✅ Actionable remediation guidance
- ✅ Feedback templates and customization
- ✅ VCS configuration management
- ✅ Delivery status tracking

### Database Tables
- `developer_feedback`
- `vcs_configurations`
- `feedback_deliveries`

### API Endpoints
- `POST /api/v1/feedback` - Create feedback
- `GET /api/v1/feedback` - List feedback
- `POST /api/v1/feedback/:id/deliver` - Deliver to VCS
- `POST /api/v1/vcs/config` - Configure VCS integration

---

## Epic 9: Risk Acceptance ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
Enable governed exceptions, not security bypass.

### Key Deliverables
- ✅ Time-boxed exception model
- ✅ Approval workflow (pending → approved/denied)
- ✅ Audit history for all exceptions
- ✅ Auto-expiry enforcement
- ✅ OPA policy integration for exception checking

### Database Tables
- `risk_exceptions`
- `exception_approvals`

### API Endpoints
- `POST /api/v1/exceptions` - Create exception request
- `GET /api/v1/exceptions` - List exceptions
- `POST /api/v1/exceptions/:id/approve` - Approve exception
- `POST /api/v1/exceptions/:id/deny` - Deny exception

---

## Epic 10: Ownership & Accountability ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
Every risk has an owner.

### Key Deliverables
- ✅ Service-to-team ownership mapping
- ✅ Team metadata and contact management
- ✅ Alert routing by owner
- ✅ Ownership-aware dashboards
- ✅ Team member role assignment

### Database Tables
- `service_ownership`
- `teams`
- `team_members`

### API Endpoints
- `POST /api/v1/teams` - Create team
- `GET /api/v1/teams` - List teams
- `POST /api/v1/services/:id/owner` - Assign ownership
- `GET /api/v1/alerts/routing` - Get alert routing

---

## Epic 11: Security Maturity Scoring ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
Measure improvement, not perfection.

### Key Deliverables
- ✅ Weighted security scoring algorithm (0-100)
- ✅ Category breakdown:
  - Vulnerability Management (30%)
  - Policy Compliance (25%)
  - Deployment Security (20%)
  - Exception Management (15%)
  - Response Time (10%)
- ✅ Team leaderboards with rankings
- ✅ Historical trend tracking (90-day analysis)
- ✅ Comparative benchmarking

### Database Tables
- `security_scores`
- `security_metrics`
- `team_benchmarks`

### API Endpoints
- `GET /api/v1/maturity/score` - Get security score
- `GET /api/v1/maturity/leaderboard` - Team leaderboard
- `GET /api/v1/maturity/trends` - Historical trends

---

## Epic 12: Code Quality Integration ✅

**Status**: Complete | **Completed**: January 2026

### Purpose
Shift-left beyond security → quality.

### Key Deliverables
- ✅ Multi-tool support: Semgrep, SonarQube, ESLint, golangci-lint, Pylint
- ✅ Code quality result storage and analysis
- ✅ Quality gate policies with enforcement
- ✅ Project quality leaderboard
- ✅ Trend analysis and metrics
- ✅ CI/CD integration patterns

### Database Tables
- `code_quality_results`
- `code_quality_issues`
- `code_quality_policies`
- `code_quality_trends`

### API Endpoints
- `POST /api/v1/quality/results` - Submit quality results
- `GET /api/v1/quality/results` - List results
- `POST /api/v1/quality/policies` - Create quality policy
- `GET /api/v1/quality/leaderboard` - Quality leaderboard

---

# V1 Summary

| Metric | Value |
|--------|-------|
| **Epics Completed** | 11/12 (Epic 7 deferred) |
| **Database Tables** | 20+ |
| **API Endpoints** | 74+ |
| **Completion Date** | January 2026 |

---

# V2 Expansion Epics (Planned)

## Epic 7: Research & Metrics Readiness

**Priority**: Optional | **Effort**: Medium | **Status**: Planned

### Purpose

Measure impact, not just features. Enable data-driven validation of InfraPilot's effectiveness.

### User Stories

1. As a **platform operator**, I want to export metrics to Prometheus so I can integrate with existing monitoring.
2. As a **researcher**, I want to measure MTTD/MTTR so I can validate platform effectiveness.
3. As a **team lead**, I want to see security improvement trends over time.

### Features

#### 7.1 Prometheus Metrics Export

```
Endpoint: GET /metrics
Format: OpenMetrics / Prometheus text format
```

**Metrics to Export**:

```prometheus
# HELP infrapilot_vulnerabilities_total Total vulnerabilities by severity
# TYPE infrapilot_vulnerabilities_total gauge
infrapilot_vulnerabilities_total{severity="critical"} 5
infrapilot_vulnerabilities_total{severity="high"} 23

# HELP infrapilot_mttd_seconds Mean time to detect security issues
# TYPE infrapilot_mttd_seconds gauge
infrapilot_mttd_seconds 3600

# HELP infrapilot_mttr_seconds Mean time to resolve security issues
# TYPE infrapilot_mttr_seconds gauge
infrapilot_mttr_seconds 86400
```

#### 7.2 Experiment Harness

```go
type Experiment struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    Description string    `json:"description"`
    StartDate   time.Time `json:"start_date"`
    EndDate     time.Time `json:"end_date"`
    Status      string    `json:"status"` // running, completed, cancelled
    Metrics     []string  `json:"metrics"`
    Results     []Result  `json:"results"`
}
```

#### 7.3 MTTD/MTTR Tracking

**Database Schema**:

```sql
CREATE TABLE security_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    incident_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    acknowledged_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    source_entity_type VARCHAR(50),
    source_entity_id UUID,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/metrics` | Prometheus metrics |
| POST | `/api/v1/experiments` | Create experiment |
| GET | `/api/v1/experiments` | List experiments |
| GET | `/api/v1/experiments/:id/results` | Get results |

---

## Epic 13: Traffic & Exposure Governance

**Priority**: HIGH | **Effort**: Large | **Status**: Planned

### Purpose

Control what is publicly reachable. Answer: **"What is exposed to the internet right now?"**

### User Stories

1. As a **security engineer**, I want to see all publicly exposed endpoints.
2. As a **DevOps engineer**, I want to configure rate limiting per service.
3. As a **platform operator**, I want alerts when TLS certificates are expiring.
4. As a **team lead**, I want a TLS posture score.

### Features

#### 13.1 Public Exposure Map

**Database Schema**:

```sql
CREATE TABLE exposed_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    protocol VARCHAR(10) NOT NULL, -- http, https, tcp, udp
    path VARCHAR(500),
    is_public BOOLEAN DEFAULT true,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    container_id UUID REFERENCES containers(id),
    service_id UUID REFERENCES service_ownership(id),
    tls_enabled BOOLEAN DEFAULT false,
    tls_cert_expiry TIMESTAMP WITH TIME ZONE,
    tls_cert_issuer VARCHAR(255),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(organization_id, host, port, path)
);
```

#### 13.2 Rate Limiting Profiles

**Database Schema**:

```sql
CREATE TABLE rate_limit_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(100) NOT NULL,
    requests_per_second INTEGER NOT NULL,
    burst_size INTEGER NOT NULL,
    window_seconds INTEGER DEFAULT 1,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE rate_limit_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES rate_limit_profiles(id),
    endpoint_id UUID NOT NULL REFERENCES exposed_endpoints(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(endpoint_id)
);
```

#### 13.3 TLS Posture Scoring

```go
func CalculateTLSScore(endpoints []ExposedEndpoint) int {
    score := 100
    for _, ep := range endpoints {
        if ep.IsPublic {
            if !ep.TLSEnabled {
                score -= 20 // No TLS on public endpoint
            } else {
                daysUntilExpiry := time.Until(ep.TLSCertExpiry).Hours() / 24
                if daysUntilExpiry < 7 {
                    score -= 15
                } else if daysUntilExpiry < 30 {
                    score -= 5
                }
            }
        }
    }
    return max(score, 0)
}
```

#### 13.4 Certificate Expiry Alerting

```sql
CREATE TABLE tls_alert_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    warning_days INTEGER DEFAULT 30,
    critical_days INTEGER DEFAULT 7,
    notify_channels JSONB,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/exposure/endpoints` | List exposed endpoints |
| GET | `/api/v1/exposure/map` | Get exposure map |
| POST | `/api/v1/exposure/scan` | Trigger scan |
| GET | `/api/v1/ratelimits` | List rate limit profiles |
| POST | `/api/v1/ratelimits` | Create profile |
| GET | `/api/v1/tls/posture` | Get TLS posture score |

---

## Epic 14: Database & Data Governance

**Priority**: HIGH | **Effort**: Large | **Status**: Planned

### Purpose

Govern data without becoming a DB provider. Answer: **"Is my data safe, backed up, and owned?"**

### User Stories

1. As a **security engineer**, I want to see all databases and their exposure status.
2. As a **compliance officer**, I want to verify all production databases have TLS enabled.
3. As a **team lead**, I want to map database ownership.
4. As a **DevOps engineer**, I want backup visibility.

### Features

#### 14.1 Database Inventory

**Database Schema**:

```sql
CREATE TABLE database_inventory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    db_type VARCHAR(50) NOT NULL, -- postgres, mysql, redis, mongodb
    version VARCHAR(50),
    host VARCHAR(255) NOT NULL,
    port INTEGER NOT NULL,
    container_id UUID REFERENCES containers(id),
    is_exposed_public BOOLEAN DEFAULT false,
    tls_enabled BOOLEAN DEFAULT false,
    auth_method VARCHAR(50),
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    owner_team_id UUID REFERENCES teams(id),
    environment VARCHAR(50),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**Detection Logic**:

```go
var dbPorts = map[int]string{
    5432:  "postgres",
    3306:  "mysql",
    6379:  "redis",
    27017: "mongodb",
    9200:  "elasticsearch",
}

func DetectDatabases(containers []Container) []Database {
    var databases []Database
    for _, c := range containers {
        for port, dbType := range dbPorts {
            if containsPort(c.Ports, port) {
                databases = append(databases, Database{
                    Name:        c.Name,
                    DBType:      dbType,
                    Port:        port,
                    ContainerID: c.ID,
                })
            }
        }
    }
    return databases
}
```

#### 14.2 Database Security Posture

```go
type DBPostureCheck struct {
    Check       string `json:"check"`
    Status      string `json:"status"` // pass, fail, warning
    Remediation string `json:"remediation"`
}

func CheckDatabasePosture(db Database) []DBPostureCheck {
    return []DBPostureCheck{
        {Check: "public_exposure", Status: boolToStatus(!db.IsExposedPublic)},
        {Check: "tls_enabled", Status: boolToStatus(db.TLSEnabled)},
        {Check: "auth_configured", Status: boolToStatus(db.AuthMethod != "none")},
        {Check: "ownership_assigned", Status: boolToStatus(db.OwnerTeamID != nil)},
    }
}
```

#### 14.3 Database Backup Visibility

```sql
CREATE TABLE database_backups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id UUID NOT NULL REFERENCES database_inventory(id),
    backup_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    size_bytes BIGINT,
    storage_location VARCHAR(500),
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/databases` | List databases |
| GET | `/api/v1/databases/:id` | Get database details |
| PUT | `/api/v1/databases/:id/owner` | Assign owner |
| GET | `/api/v1/databases/:id/posture` | Get posture |
| POST | `/api/v1/databases/scan` | Trigger scan |
| GET | `/api/v1/databases/:id/backups` | List backups |

---

## Epic 15: Backup & Recovery Visibility

**Priority**: Medium | **Effort**: Medium | **Status**: Planned

### Purpose

Disaster readiness without complexity. Answer: **"Are all production services backed up?"**

### Features

#### 15.1 Backup Policy Engine

```sql
CREATE TABLE backup_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(100) NOT NULL,
    environment VARCHAR(50) NOT NULL, -- dev, staging, prod, all
    entity_type VARCHAR(50) NOT NULL, -- database, volume, service
    frequency VARCHAR(50) NOT NULL, -- daily, hourly, weekly
    retention_days INTEGER NOT NULL,
    required BOOLEAN DEFAULT false,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE backup_policy_compliance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES backup_policies(id),
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID NOT NULL,
    is_compliant BOOLEAN DEFAULT false,
    last_backup_at TIMESTAMP WITH TIME ZONE,
    next_backup_due TIMESTAMP WITH TIME ZONE,
    violation_reason TEXT,
    checked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/backups` | List all backups |
| GET | `/api/v1/backups/policies` | List policies |
| POST | `/api/v1/backups/policies` | Create policy |
| GET | `/api/v1/backups/compliance` | Get compliance |

---

## Epic 16: Secrets Hygiene

**Priority**: Medium | **Effort**: Medium | **Status**: Planned

### Purpose

Reduce credential-based breaches. Answer: **"How old are our secrets?"**

### Features

#### 16.1 Secret Inventory

```sql
CREATE TABLE secret_inventory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    secret_type VARCHAR(50) NOT NULL, -- api_key, password, certificate, token
    source VARCHAR(50) NOT NULL, -- env_var, secret_manager, config_file
    container_id UUID REFERENCES containers(id),
    service_id UUID REFERENCES service_ownership(id),
    created_at TIMESTAMP WITH TIME ZONE,
    last_rotated_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    rotation_policy_days INTEGER,
    is_exposed BOOLEAN DEFAULT false,
    owner_team_id UUID REFERENCES teams(id),
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### 16.2 Secret Detection Patterns

```go
var secretPatterns = []SecretPattern{
    {Name: "AWS Access Key", Pattern: `AKIA[0-9A-Z]{16}`},
    {Name: "GitHub Token", Pattern: `ghp_[a-zA-Z0-9]{36}`},
    {Name: "Slack Token", Pattern: `xox[baprs]-[0-9a-zA-Z-]{10,}`},
    {Name: "Private Key", Pattern: `-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`},
}
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/secrets` | List secrets |
| GET | `/api/v1/secrets/stale` | List stale secrets |
| GET | `/api/v1/secrets/exposed` | List exposed secrets |
| POST | `/api/v1/secrets/scan` | Scan for secrets |

---

## Epic 17: Background Jobs & Workers

**Priority**: Medium | **Effort**: Medium | **Status**: Planned

### Purpose

Make silent failures visible. Answer: **"Are all our cron jobs running on schedule?"**

### Features

#### 17.1 Job Inventory

```sql
CREATE TABLE background_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    job_type VARCHAR(50) NOT NULL, -- cron, worker, queue_processor
    schedule VARCHAR(100),
    container_id UUID REFERENCES containers(id),
    service_id UUID REFERENCES service_ownership(id),
    enabled BOOLEAN DEFAULT true,
    last_run_at TIMESTAMP WITH TIME ZONE,
    last_run_status VARCHAR(50),
    last_run_duration_ms INTEGER,
    failure_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    owner_team_id UUID REFERENCES teams(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE job_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES background_jobs(id),
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    completed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL,
    duration_ms INTEGER,
    exit_code INTEGER,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### 17.2 Retry Storm Detection

```go
func DetectRetryStorm(jobID string, window time.Duration) *Alert {
    executions := GetRecentExecutions(jobID, window)
    failedCount := countFailed(executions)
    if failedCount > 10 {
        return &Alert{
            Severity: "warning",
            Message:  fmt.Sprintf("Job %s has %d failures in %v", jobID, failedCount, window),
        }
    }
    return nil
}
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/jobs` | List jobs |
| GET | `/api/v1/jobs/:id/executions` | Get history |
| GET | `/api/v1/jobs/health` | Get job health |
| POST | `/api/v1/jobs/:id/trigger` | Manual trigger |

---

## Epic 18: External Dependency Mapping

**Priority**: Low | **Effort**: Medium | **Status**: Planned

### Purpose

Understand blast radius. Answer: **"If Stripe goes down, which services are affected?"**

### Features

#### 18.1 Dependency Inventory

```sql
CREATE TABLE external_dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL, -- payment, email, auth, storage
    vendor VARCHAR(255) NOT NULL, -- Stripe, SendGrid, Auth0, S3
    endpoint_url VARCHAR(500),
    status_page_url VARCHAR(500),
    criticality VARCHAR(20) NOT NULL,
    is_healthy BOOLEAN DEFAULT true,
    last_health_check TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE service_dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_id UUID NOT NULL REFERENCES service_ownership(id),
    dependency_id UUID NOT NULL REFERENCES external_dependencies(id),
    usage_type VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(service_id, dependency_id)
);
```

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/dependencies` | List dependencies |
| POST | `/api/v1/dependencies` | Add dependency |
| GET | `/api/v1/dependencies/graph` | Get dependency graph |
| GET | `/api/v1/dependencies/:id/impact` | Get impact analysis |

---

## Epic 19: UX & Navigation System

**Priority**: HIGH | **Effort**: Large | **Status**: Planned

### Purpose

Make power feel calm and obvious. Answer: **"How do I find what I need?"**

### Features

#### 19.1 Risk-Centric Navigation

```
/                          # Dashboard
├── /build                 # Build Layer
│   ├── /vulnerabilities
│   ├── /sboms
│   ├── /code-quality
│   └── /images
├── /deploy                # Deploy Layer
│   ├── /deployments
│   ├── /policies
│   ├── /webhooks
│   └── /gates
├── /run                   # Run Layer
│   ├── /containers
│   ├── /drift
│   ├── /anomalies
│   └── /exposure          # Epic 13
├── /govern                # Govern Layer
│   ├── /ownership
│   ├── /teams
│   ├── /exceptions
│   └── /maturity
├── /data                  # Data Layer (Epic 14, 15)
│   ├── /databases
│   ├── /backups
│   └── /secrets           # Epic 16
└── /settings
```

#### 19.2 Golden Page Pattern

```tsx
interface GoldenPageProps {
  entity: {
    id: string;
    name: string;
    type: string;
    status: 'healthy' | 'warning' | 'critical';
    owner?: Team;
  };
  breadcrumbs: Breadcrumb[];
  tabs: Tab[];
  actions: Action[];
}
```

#### 19.3 Keyboard Navigation

```typescript
const globalShortcuts = {
  'g h': 'Go to home/dashboard',
  'g b': 'Go to build',
  'g d': 'Go to deploy',
  'g r': 'Go to run',
  'g o': 'Go to govern',
  '/': 'Focus search',
  '?': 'Show shortcuts',
};
```

#### 19.4 Design System Components

```
components/
├── layout/
│   ├── AppShell.tsx
│   ├── Sidebar.tsx
│   ├── PageHeader.tsx
│   └── GoldenPage.tsx
├── navigation/
│   ├── Breadcrumbs.tsx
│   ├── TabNavigation.tsx
│   └── CommandPalette.tsx
├── data-display/
│   ├── DataTable.tsx
│   ├── StatusBadge.tsx
│   ├── ScoreGauge.tsx
│   └── TrendChart.tsx
└── entity/
    ├── EntityCard.tsx
    ├── EntityLink.tsx
    └── RelatedEntities.tsx
```

#### 19.5 Accessibility (WCAG 2.1 AA)

- [ ] Color contrast ratio ≥ 4.5:1
- [ ] Keyboard accessible
- [ ] Focus indicators visible
- [ ] ARIA labels
- [ ] Screen reader tested
- [ ] Reduced motion support

---

# V2 Summary

## New Database Tables

| Epic | Tables |
|------|--------|
| 7 | `experiments`, `security_incidents` |
| 13 | `exposed_endpoints`, `rate_limit_profiles`, `rate_limit_assignments`, `tls_alert_config` |
| 14 | `database_inventory`, `database_backups` |
| 15 | `backup_policies`, `backup_policy_compliance` |
| 16 | `secret_inventory` |
| 17 | `background_jobs`, `job_executions` |
| 18 | `external_dependencies`, `service_dependencies` |

**Total New Tables**: 14

## New API Endpoints

| Epic | Endpoints |
|------|-----------|
| 7 | 7 |
| 13 | 12 |
| 14 | 8 |
| 15 | 6 |
| 16 | 6 |
| 17 | 6 |
| 18 | 5 |

**Total New Endpoints**: ~50

---

# Combined Progress

| Version | Epics | Tables | Endpoints | Status |
|---------|-------|--------|-----------|--------|
| v1 | 11 | 20+ | 74+ | ✅ Complete |
| v2 | 8 | 14 | 50 | ⏳ Planned |
| **Total** | **19** | **34+** | **124+** | |
