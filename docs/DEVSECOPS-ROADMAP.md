# DevSecOps Transformation Roadmap

This document outlines InfraPilot's evolution into a complete DevSecOps platform, designed to support both product development and academic research publication.

## Table of Contents

- [Vision](#vision)
- [DevSecOps Definition](#devsecops-definition)
- [Current State](#current-state)
- [The Missing Piece](#the-missing-piece)
- [Target State](#target-state)
- [Epic Overview](#epic-overview)
- [Implementation Timeline](#implementation-timeline)
- [Research Paper Strategy](#research-paper-strategy)

## Vision

Transform InfraPilot from a security-aware deployment control plane into a **complete DevSecOps platform** that demonstrates:

> A single-node, container-native DevSecOps control plane can provide end-to-end traceability from code commit to runtime security posture, with policy-driven governance and shift-left feedback that measurably improves developer behavior.

This is both a **product goal** and a **research contribution**.

## DevSecOps Definition

InfraPilot is DevSecOps-complete when it satisfies **all four pillars**:

| Pillar | Description | Status |
|--------|-------------|--------|
| **Dev (Code & CI)** | Code quality, CI integration, developer feedback | 🟡 Partial |
| **Sec (Supply Chain, Policy)** | Scanning, SBOM, policy enforcement | ✅ Strong |
| **Ops (Runtime, Drift, Infra)** | Container mgmt, drift detection, monitoring | ✅ Strong |
| **Feedback & Governance** | Risk acceptance, ownership, behavior change | ❌ **Missing** |

**If any pillar is missing → it's not DevSecOps.**

## Current State

### What InfraPilot Currently Provides

InfraPilot today is:
- ✅ **A security-aware deployment control plane**
- ✅ **Detection & enforcement engine**
- ✅ **Supply chain visibility platform**

InfraPilot is NOT yet:
- ❌ **A feedback engine that changes developer behavior**
- ❌ **A governance platform with risk acceptance**
- ❌ **A complete DevSecOps platform**

### Capability Matrix

| Category | Capability | Status |
|----------|------------|--------|
| **Ops** | Container management | ✅ Complete |
| **Ops** | Reverse proxy (Nginx) | ✅ Complete |
| **Ops** | Log aggregation | ✅ Complete |
| **Ops** | Alerting | ✅ Complete |
| **Ops** | SSL automation | ✅ Complete |
| **Sec** | RBAC | ✅ Complete |
| **Sec** | MFA (TOTP) | ✅ Complete |
| **Sec** | Audit logs | ✅ Complete |
| **Sec** | TLS management | ✅ Complete |
| **Dev** | CI/CD integration (webhooks) | ✅ Complete |
| **Dev** | Build metadata tracking | ✅ Complete |
| **Sec** | Image scanning (Trivy) | ✅ Complete |
| **Sec** | SBOM generation (Syft) | ✅ Complete |
| **Sec** | Policy enforcement (OPA) | ✅ Complete |
| **Sec** | Vulnerability management | ✅ Complete |
| **Sec** | CVE-centric view | ✅ Complete |
| **Sec** | Security posture dashboard | ✅ Complete |
| **Sec** | Deployment spine (traceability) | ✅ Complete |
| **Feedback** | PR/CI developer feedback | ❌ **Missing** |
| **Feedback** | Risk acceptance & exceptions | ❌ **Missing** |
| **Governance** | Ownership & accountability | ❌ **Missing** |
| **Governance** | Security maturity scoring | ⏳ Partial |
| **Dev** | Code quality integration | ❌ **Missing** |
| **Ops** | Runtime drift detection | ❌ Missing |
| **Ops** | Behavioral monitoring | ❌ Missing |

### Current Coverage Assessment

**Core DevSecOps**: ~70% (strong detection & enforcement, weak feedback & governance)

**Complete DevSecOps**: ~40% (missing the human feedback loop)

## The Missing Piece

### The Incomplete Loop

**Current Flow:**
```
Code → CI → InfraPilot → Deploy / Block
```

**Needed Flow:**
```
Code → CI → InfraPilot → Feedback → Developer → Fix → Deploy
                    ↑_________________________________|
```

That feedback arrow is **the missing piece**.

### What's Actually Missing

#### ❌ 1. Developer Feedback Loop (Shift-Left)

**Right now:**
- InfraPilot blocks deployments
- InfraPilot logs policy decisions
- InfraPilot detects vulnerabilities

**But it does NOT:**
- Explain issues in developer language
- Feed results back into PRs/commits
- Teach developers how to fix issues

**Impact:** Developers discover issues too late. InfraPilot feels like a "blocker", not a partner.

#### ❌ 2. Ownership & Accountability Model

**Current state:**
- Security findings are technically correct
- Security findings are operationally visible

**But they are:**
- Socially unassigned

**Missing questions:**
- Who owns this vulnerability?
- Which team/service caused it?
- Who approved the exception?
- Is this accepted risk or negligence?

**Impact:** Security data exists, but security governance does not.

#### ❌ 3. Risk Acceptance & Exception Lifecycle

**Current capability:**
- Can deny / warn / allow via policy

**Cannot:**
- Time-box risk acceptance
- Assign risk owner
- Track exception expiry
- Audit why it was allowed

**Impact:** Binary security ("block or allow") instead of governed security ("accepted risk with expiry").

#### ❌ 4. Code Quality Integration

**Missing:**
- SAST integration (Semgrep, SonarQube)
- Code quality gates
- Complexity & maintainability tracking
- Technical debt signals

**Impact:** Only runtime/image security, missing source code security.

## Target State

### Complete DevSecOps Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        InfraPilot DevSecOps                          │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────────────── SHIFT-LEFT FEEDBACK ────────────────────┐  │
│  │                                                                 │  │
│  │  Developer → PR → CI → Scan → Policy → Feedback → Fix         │  │
│  │                                         │                       │  │
│  │  ┌──────────────────────────────────────▼──────────────────┐  │  │
│  │  │   GitHub PR Comments / CI Annotations / Slack          │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  ┌────────────────── DEPLOYMENT GATE ──────────────────────┐       │
│  │                                                           │       │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │       │
│  │  │ CI Webhook  │  │  Scanner    │  │   Policy    │     │       │
│  │  │  Ingestor   │  │ (Trivy +    │  │   Engine    │     │       │
│  │  │             │  │  Syft +     │  │    (OPA)    │     │       │
│  │  │             │  │  Semgrep)   │  │             │     │       │
│  │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘     │       │
│  │         │                │                │             │       │
│  │  ┌──────▼────────────────▼────────────────▼──────┐     │       │
│  │  │         Deployment Pipeline                   │     │       │
│  │  │  ┌────────┐  ┌────────┐  ┌────────┐  ┌────┐  │     │       │
│  │  │  │ Ingest │→ │  Scan  │→ │ Policy │→ │Run │  │     │       │
│  │  │  └────────┘  └────────┘  └────────┘  └────┘  │     │       │
│  │  └───────────────────────────────────────────────┘     │       │
│  └───────────────────────────────────────────────────────────┘       │
│                                                                      │
│  ┌────────────────── GOVERNANCE LAYER ─────────────────────┐       │
│  │                                                           │       │
│  │  ┌─────────────────┐  ┌─────────────────┐               │       │
│  │  │ Risk Exceptions │  │   Ownership     │               │       │
│  │  │  - Justification│  │  - Team mapping │               │       │
│  │  │  - Approval     │  │  - Alerting     │               │       │
│  │  │  - Expiry       │  │  - Routing      │               │       │
│  │  └─────────────────┘  └─────────────────┘               │       │
│  └───────────────────────────────────────────────────────────┘       │
│                                                                      │
│  ┌────────────────── RUNTIME SECURITY ─────────────────────┐       │
│  │                                                           │       │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                 │       │
│  │  │ Drift   │  │Behavior │  │Incident │                 │       │
│  │  │Detector │  │ Monitor │  │Response │                 │       │
│  │  └─────────┘  └─────────┘  └─────────┘                 │       │
│  └───────────────────────────────────────────────────────────┘       │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Deployment Flow (Complete DevSecOps)

```
Developer         CI/CD           InfraPilot        Runtime
    │               │                 │                │
    │ Push Code     │                 │                │
    ├──────────────►│                 │                │
    │               │ Build + Scan    │                │
    │               ├────────────────►│                │
    │               │                 │ Code Quality   │
    │               │                 ├───────────────►│
    │               │                 │ Image Scan     │
    │               │                 ├───────────────►│
    │               │                 │ SBOM Generate  │
    │               │                 ├───────────────►│
    │               │                 │ Policy Eval    │
    │               │                 ├───────────────►│
    │               │                 │                │
    │               │                 │ If BLOCKED:    │
    │◄──────────────┼─────────────────┤ → PR Comment   │
    │ "Fix CVE-..." │                 │ → Explain      │
    │               │                 │ → Suggest Fix  │
    │               │                 │                │
    │ (Fix & Push)  │                 │                │
    ├──────────────►│                 │                │
    │               │ Rebuild         │                │
    │               ├────────────────►│ Re-scan        │
    │               │                 ├───────────────►│
    │               │                 │ Allow          │
    │               │                 ├───────────────►│
    │               │                 │ Deploy         │
    │               │                 ├───────────────►│
    │               │                 │                │
    │               │                 │ Monitor Drift  │
    │               │                 │◄───────────────┤
    │               │                 │ Alert Owner    │
    │               │                 │────────────────►│
```

## Epic Overview

### Epic 0: DevSecOps Foundations ✅ COMPLETE

**Objective**: Redefine core domain from "containers" to "secure deployments"

| Task | Priority | Status |
|------|----------|--------|
| Deployment as first-class entity | P0 | ✅ Complete |
| Deployment-container relationship | P0 | ✅ Complete |
| Deployment history tracking | P0 | ✅ Complete |

### Epic 1: Supply Chain Security ✅ COMPLETE

**Objective**: No image runs unless scanned, attested, and policy-approved

| Task | Priority | Status | Notes |
|------|----------|--------|-------|
| Image scanning pipeline (Trivy) | P0 | ✅ Complete | Trivy v0.68.2 integrated |
| SBOM generation (CycloneDX) | P0 | ✅ Complete | Syft v1.40.0 integrated |
| Vulnerability database | P1 | ✅ Complete | PostgreSQL storage |
| CVE-centric vulnerability view | P1 | ✅ Complete | "Where is this CVE running?" |
| SBOM package explorer | P1 | ✅ Complete | Searchable package list |
| Deployment spine (traceability) | P0 | ✅ Complete | Complete CI→Runtime trace |

**Completed**: 2026-01-15
**Deliverables**:
- End-to-end traceability from commit to runtime
- CVE-centric view answering "Where is CVE-X running?"
- SBOM explorer with vulnerability linkage
- Timeline visualization of deployment flow

### Epic 2: Policy-as-Code ✅ COMPLETE

**Objective**: Security decisions are automatic, versioned, and auditable

| Task | Priority | Status | Notes |
|------|----------|--------|-------|
| OPA policy engine integration | P0 | ✅ Complete | OPA v1.12.2 with Rego |
| Environment-scoped policies | P0 | ✅ Complete | Prod/Staging/Dev rules |
| Policy management UI | P1 | ✅ Complete | View policies & decisions |
| Policy decision tracking | P1 | ✅ Complete | All decisions stored |

### Epic 3: Runtime Security

**Objective**: Detect security drift after deployment

| Task | Priority | Complexity |
|------|----------|------------|
| Configuration drift detection | P0 | High |
| Behavioral anomaly detection | P1 | Medium |
| Privilege escalation detection | P1 | Medium |
| Incident correlation | P2 | High |

### Epic 4: Dev Integration ✅ COMPLETE

**Objective**: Close the Dev → Sec → Ops loop (inbound)

| Task | Priority | Status | Notes |
|------|----------|--------|-------|
| CI webhook ingestor | P0 | ✅ Complete | GitHub, GitLab, Jenkins |
| Webhook management UI | P0 | ✅ Complete | Full CRUD with events |
| Build metadata tracking | P1 | ✅ Complete | Git commit, branch, CI |
| Deployment gate API | P1 | ✅ Complete | Webhook → Scan → Policy |

### Epic 5: DevSecOps Observability ✅ COMPLETE

**Objective**: Make DevSecOps visible, explainable, and measurable

| Task | Priority | Status | Notes |
|------|----------|--------|-------|
| Security posture dashboard | P0 | ✅ Complete | Real-time 0-100 scoring |
| Deployment health metrics | P1 | ✅ Complete | Success rate, trends |
| Security scoring | P1 | ✅ Complete | Risk-based calculation |
| Vulnerability tracking | P1 | ✅ Complete | CVE-centric with trends |
| Policy compliance metrics | P1 | ✅ Complete | Allow/warn/deny stats |

### Epic 6: DevSecOps Hardening

**Objective**: InfraPilot must enforce security on itself

| Task | Priority | Complexity |
|------|----------|------------|
| Secure defaults enforcement | P0 | Medium |
| Self-protection policies | P1 | Medium |
| Control plane security | P1 | Medium |

### Epic 7: Research Readiness

**Objective**: Make InfraPilot measurable and publishable

| Task | Priority | Complexity |
|------|----------|------------|
| Experiment harness | P0 | Medium |
| Metrics export | P1 | Low |
| Benchmark suite | P1 | Medium |

---

## 🚨 THE MISSING EPICS (Critical for Complete DevSecOps) 🚨

### Epic 8: Developer Feedback & Shift-Left Security ⏳ **IN PROGRESS (P0)**

**Objective**: Make InfraPilot teach developers, not just block them

**The Problem:**
- Developers discover security issues at deployment time (too late)
- Blocked deployments feel punitive, not collaborative
- No actionable guidance on how to fix issues

**The Solution:**
Feed security findings back to developers at PR/CI time with:
- Explanations in developer language
- Links to fixes and documentation
- Impact analysis (prod vs staging)

| Task | Priority | Status | Complexity |
|------|----------|--------|------------|
| **Feedback abstraction layer** | P0 | ⏳ In Progress | Medium |
| **GitHub PR integration** | P0 | ⏳ In Progress | Medium |
| **CI status checks** | P0 | 📋 Planned | Low |
| **Feedback message templates** | P1 | 📋 Planned | Low |
| **GitLab MR integration** | P1 | 📋 Planned | Medium |
| Slack notifications | P2 | 📋 Planned | Low |

**Database Schema:**
```sql
CREATE TABLE developer_feedback (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,

    -- Source
    source_type VARCHAR(50) NOT NULL, -- vulnerability, policy, quality
    source_id UUID NOT NULL,

    -- Target
    provider VARCHAR(50) NOT NULL, -- github, gitlab
    repo VARCHAR(255) NOT NULL,
    pull_request INTEGER,
    commit_sha VARCHAR(64),

    -- Content
    severity VARCHAR(20),
    title VARCHAR(255),
    message TEXT,
    remediation TEXT,

    -- Status
    delivered BOOLEAN DEFAULT FALSE,
    delivery_error TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**Example PR Comment:**
```markdown
🚫 **Deployment blocked by InfraPilot**

**Critical vulnerability detected:**
- **CVE-2024-3094**
- **Package:** xz-utils
- **Introduced via:** alpine:latest (base image)
- **Affects:** production deployment

✅ **Recommended fix:**
- Pin image to `alpine:3.19`
- OR upgrade package to `xz-utils >= 5.6.1`

⏱ **Impact:**
- ❌ Blocks production deployment
- ✅ Allowed in dev/staging

🔗 **View full context:**
[InfraPilot Dashboard](https://infrapilot.example.com/deployments/abc-123)
```

**Research Value:**
- Measure: Mean Time To Detect (MTTD) vs Mean Time To Fix (MTTF)
- Measure: Security debt reduction over time
- Measure: Developer behavior change (repeat violations)

---

### Epic 9: Risk Acceptance & Exception Management ⏳ **IN PROGRESS (P0)**

**Objective**: Support governed security, not binary security

**The Problem:**
- Real-world security is not binary (block vs allow)
- Sometimes risks must be accepted temporarily
- No way to time-box or audit accepted risks

**The Solution:**
Risk exceptions with:
- Explicit justification (required)
- Time-bound expiry (required)
- Approval tracking (required)
- Automatic re-blocking after expiry

| Task | Priority | Status | Complexity |
|------|----------|--------|------------|
| **Exception data model** | P0 | ⏳ In Progress | Low |
| **Exception request UI** | P0 | ⏳ In Progress | Medium |
| **Exception approval workflow** | P0 | ⏳ In Progress | Medium |
| **Policy integration (OPA)** | P0 | ⏳ In Progress | Low |
| **Automatic expiry enforcement** | P1 | 📋 Planned | Medium |
| Exception audit trail | P1 | 📋 Planned | Low |
| Exception renewal workflow | P2 | 📋 Planned | Medium |

**Database Schema:**
```sql
CREATE TABLE risk_exceptions (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,

    -- Scope
    scope_type VARCHAR(50) NOT NULL, -- cve, policy, deployment
    scope_reference VARCHAR(255) NOT NULL,

    -- Governance
    justification TEXT NOT NULL,
    approved_by UUID REFERENCES users(id),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Status
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**Policy Integration (OPA):**
```rego
package infrapilot.security

allow {
    # Check if there's a valid exception
    exception := data.exceptions[input.deployment.id]
    exception.approved == true
    exception.expires_at > time.now_ns()
    not exception.revoked
}
```

**UI Flow:**
1. Deployment blocked by policy
2. Button appears: **[Request Risk Exception]**
3. Modal requires:
   - **Justification** (required, min 50 chars)
   - **Expiry date** (required, max 90 days)
   - **Scope** (this CVE / this deployment / this service)
4. Exception logged, auditable, auto-expires

**Research Value:**
- Measure: Exception lifecycle (request → approval → expiry)
- Measure: Exception abuse (frequent requesters)
- Measure: Security debt visibility

---

### Epic 10: Ownership & Accountability Model (P1)

**Objective**: Security findings must have owners, not just exist

**The Problem:**
- Vulnerabilities are technically correct but socially unassigned
- No routing to responsible teams
- No accountability for security debt

**The Solution:**
Assign ownership to:
- Services (mapped to teams)
- Deployments (mapped to developers)
- Vulnerabilities (mapped to service owners)

| Task | Priority | Status | Complexity |
|------|----------|--------|------------|
| Service ownership model | P1 | 📋 Planned | Medium |
| Team metadata schema | P1 | 📋 Planned | Low |
| Alert routing by owner | P1 | 📋 Planned | Medium |
| Ownership UI | P2 | 📋 Planned | Medium |

**Database Schema:**
```sql
CREATE TABLE service_ownership (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    service_name VARCHAR(255) NOT NULL,

    -- Ownership
    team_name VARCHAR(255) NOT NULL,
    team_slack_channel VARCHAR(255),
    team_email VARCHAR(255),

    -- Contacts
    primary_contact UUID REFERENCES users(id),
    secondary_contact UUID REFERENCES users(id),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(org_id, service_name)
);
```

**Example Use Case:**
```
CVE-2024-1234 detected in "payments-api"
→ Look up service ownership
→ Route alert to: #payments-team on Slack
→ Tag: @alice (primary), @bob (secondary)
→ Track: Who acknowledged, who fixed
```

**Research Value:**
- Measure: Ownership impact on MTTR
- Measure: Team-level security maturity

---

### Epic 11: Security Posture & Maturity Scoring (P1)

**Objective**: Measure security improvement over time

**The Problem:**
- No way to answer "Are we getting better?"
- No way to compare teams or services
- No trend visibility beyond snapshots

**The Solution:**
Track and visualize:
- Security score per service (0-100)
- Trend over time (improving vs degrading)
- Team-level security maturity
- Policy compliance percentage

| Task | Priority | Status | Complexity |
|------|----------|--------|------------|
| Service-level scoring | P1 | ⏳ Partial | Medium |
| Historical trend tracking | P1 | 📋 Planned | Medium |
| Team security leaderboard | P2 | 📋 Planned | Low |
| Security maturity model | P2 | 📋 Planned | High |

**Research Value:**
- Measure: Security improvement correlation with feedback loops
- Measure: Policy effectiveness over time
- Measure: Security debt accumulation/reduction

---

### Epic 12: Code Quality Integration (P1)

**Objective**: Extend security to source code, not just containers

**The Problem:**
- InfraPilot only sees runtime/image security
- Missing: SAST, code complexity, technical debt
- Incomplete "shift-left"

**The Solution:**
Integrate code quality tools as orchestrated scanners:
- **Semgrep** (SAST - security issues in code)
- **SonarQube CE** (bugs, code smells, maintainability)
- Language-specific linters (ESLint, Golangci-lint, etc.)

**Architecture Principle:**
InfraPilot should:
- ❌ NOT scan source code itself
- ❌ NOT become a CI system
- ✅ Consume CI results (JSON reports)
- ✅ Evaluate via policy
- ✅ Store & visualize

| Task | Priority | Status | Complexity |
|------|----------|--------|------------|
| Code quality result schema | P1 | 📋 Planned | Low |
| Semgrep integration | P1 | 📋 Planned | Medium |
| SonarQube integration | P1 | 📋 Planned | Medium |
| Quality-based policies (OPA) | P1 | 📋 Planned | Medium |
| Code quality dashboard | P2 | 📋 Planned | Medium |

**Database Schema:**
```sql
CREATE TABLE code_quality_results (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL,
    deployment_id UUID REFERENCES deployments(id),

    tool VARCHAR(50) NOT NULL, -- semgrep, sonarqube
    project_key VARCHAR(255),
    commit_sha VARCHAR(64),

    -- Metrics
    bugs INTEGER DEFAULT 0,
    vulnerabilities INTEGER DEFAULT 0,
    code_smells INTEGER DEFAULT 0,
    security_hotspots INTEGER DEFAULT 0,
    coverage DECIMAL(5,2),
    complexity DECIMAL(6,2),

    quality_gate VARCHAR(20), -- pass, warn, fail
    raw_report JSONB,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

**Policy Example (OPA):**
```rego
package infrapilot.quality

deny[msg] {
    input.environment == "prod"
    input.code_quality.critical > 0
    msg := "Critical code quality issues detected"
}

deny[msg] {
    input.code_quality.coverage < 80
    msg := sprintf("Code coverage too low: %v%%", [input.code_quality.coverage])
}
```

**Research Value:**
- Measure: Code quality correlation with security incidents
- Measure: Technical debt impact on deployment frequency

---

## Implementation Timeline (Updated)

### Phase 1: Foundations ✅ COMPLETE

**Focus**: Core infrastructure for DevSecOps

- [x] Epic 0: Deployment entity
- [x] Epic 1.1: Image scanning (Trivy)
- [x] Epic 2.1: OPA integration

**Completed**: 2026-01-14

### Phase 2: Policy & Supply Chain ✅ COMPLETE

**Focus**: Complete security pipeline

- [x] Epic 1.2: SBOM generation
- [x] Epic 1.3: CVE-centric view
- [x] Epic 1.4: Deployment spine
- [x] Epic 2.2: Environment-scoped policies
- [x] Epic 4.1: CI webhook integration
- [x] Epic 5.1: Security posture dashboard

**Completed**: 2026-01-15

### Phase 3: Feedback & Governance ⏳ **IN PROGRESS (Current)**

**Focus**: Close the feedback loop

- [ ] **Epic 8.1: Developer Feedback (GitHub PR)** ← **CURRENT PRIORITY**
- [ ] **Epic 9.1: Risk Acceptance & Exceptions** ← **CURRENT PRIORITY**
- [ ] Epic 8.2: CI status checks
- [ ] Epic 9.2: Exception expiry automation
- [ ] Epic 10.1: Service ownership model

**Target**: 2026-01-30

**Deliverable**: Complete feedback loop (Code → InfraPilot → Feedback → Developer → Fix)

### Phase 4: Code Quality & Ownership (Month 3)

**Focus**: Shift-left completeness

- [ ] Epic 12.1: Semgrep integration
- [ ] Epic 12.2: Code quality policies
- [ ] Epic 10.2: Team routing & alerts
- [ ] Epic 11.1: Security maturity scoring

**Target**: 2026-02-28

### Phase 5: Runtime Security (Month 4)

**Focus**: Post-deployment monitoring

- [ ] Epic 3.1: Drift detection
- [ ] Epic 3.2: Behavioral monitoring
- [ ] Epic 6: DevSecOps hardening

**Target**: 2026-03-31

### Phase 6: Research & Publication (Month 5-6)

**Focus**: Experiments and paper

- [ ] Epic 7: Research readiness
- [ ] Experiments: MTTD, MTTR, behavior change
- [ ] Write paper
- [ ] Submit to arXiv → conference

**Target**: 2026-05-31

---

## Research Paper Strategy

### Novel Contribution (Updated)

> We demonstrate that complete DevSecOps—including shift-left feedback, policy-driven governance, and measurable behavior change—can be achieved on single-node Docker infrastructure without Kubernetes, using a feedback-first control plane architecture.

### Paper Title (Updated Options)

1. **Academic**: "InfraPilot: A Feedback-First DevSecOps Control Plane for Container-Native Production Systems"

2. **Applied**: "DevSecOps Without Kubernetes: Design, Implementation, and Evaluation of Shift-Left Feedback Loops"

3. **Research-Focused**: "Measurable Security Improvement Through Policy-Driven Feedback: The InfraPilot DevSecOps Platform"

### Target Venues

| Venue | Type | Fit | Rationale |
|-------|------|-----|-----------|
| IEEE Access | Journal | High | Systems + experiments |
| ACM SAC | Conference | High | Applied research |
| Journal of Cloud Computing | Journal | High | DevOps focus |
| USENIX SREcon | Conference | Medium | Practitioner audience |
| arXiv | Preprint | First | Immediate publication |

### Required Experiments (Updated)

| Experiment | Metric | Epic Required |
|------------|--------|---------------|
| Vulnerable image deployment | Detection latency | Epic 1 ✅ |
| Policy enforcement effectiveness | Block success rate | Epic 2 ✅ |
| Developer feedback impact | MTTF reduction | Epic 8 ⏳ |
| Risk exception lifecycle | Exception duration, abuse rate | Epic 9 ⏳ |
| Security posture improvement | Score delta over time | Epic 11 📋 |
| Code quality correlation | Quality vs incidents | Epic 12 📋 |
| Ownership impact on MTTR | MTTR with/without ownership | Epic 10 📋 |
| Configuration drift detection | Detection accuracy | Epic 3 📋 |

### Research Claims (Updated)

With complete implementation, InfraPilot can claim:

✅ **End-to-end traceability** from code commit to runtime security posture

✅ **Shift-left security** with actionable PR/CI feedback

✅ **Policy-driven governance** including risk acceptance and expiry

✅ **Measurable behavior change** via developer feedback loops

✅ **Security maturity scoring** with trend analysis

✅ **Ownership-based accountability** for security findings

✅ **Unified code + runtime security** in a single control plane

### Related Work Categories

1. DevSecOps Models and Frameworks
2. Kubernetes-Centric DevSecOps Platforms
3. Container Security and Supply Chain
4. Infrastructure Control Without SSH
5. **Shift-Left Security and Developer Feedback** ← New category
6. **Security Governance and Risk Acceptance** ← New category
7. Observability and Configuration Drift

---

## Success Criteria (Updated)

InfraPilot is **DevSecOps-complete** when:

### Core Functionality
- [x] Vulnerable images cannot deploy (blocked by policy)
- [x] Every runtime artifact is traceable to source code
- [x] Policies block, not just warn
- [ ] Developers receive actionable feedback in PRs **← Epic 8**
- [ ] Risk can be accepted with justification and expiry **← Epic 9**
- [ ] Security findings have owners and routing **← Epic 10**

### Governance
- [ ] Humans only approve exceptions, not normal flow
- [ ] All exceptions have expiry dates
- [ ] Expired exceptions automatically re-block

### Measurability
- [x] Security posture is scored (0-100)
- [ ] Security trends show improvement over time **← Epic 11**
- [ ] Developer behavior change is measurable **← Epic 8**
- [ ] Code quality gates exist **← Epic 12**

### Research Readiness
- [ ] Experiments can measure MTTD, MTTF, MTTR
- [ ] Metrics can demonstrate behavior change
- [ ] Platform is publishable and reproducible

---

## Next Immediate Steps

### Week 1: Epic 8 - Developer Feedback (GitHub PR)
1. [x] Create `developer_feedback` table schema
2. [ ] Implement feedback abstraction layer (Go)
3. [ ] GitHub App/token configuration UI
4. [ ] PR comment generation (vulnerability + policy)
5. [ ] Test with real PR in test repo

### Week 2: Epic 9 - Risk Acceptance
1. [ ] Create `risk_exceptions` table schema
2. [ ] Exception request UI modal
3. [ ] Exception approval workflow
4. [ ] OPA policy integration for exceptions
5. [ ] Automatic expiry enforcement

### Week 3: Integration & Testing
1. [ ] End-to-end test: Block → PR comment → Fix → Allow
2. [ ] End-to-end test: Block → Request exception → Approve → Allow
3. [ ] Documentation updates
4. [ ] Demo video

---

**Last Updated**: 2026-01-15
**Status**: Phase 3 In Progress (Epic 8 & 9)
**Next Milestone**: Complete feedback loop (Epic 8 + 9) by 2026-01-30
