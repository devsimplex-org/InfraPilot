# InfraPilot v2.0 — Strategic Roadmap

> **Vision**: Infrastructure Control, Without the Chaos

InfraPilot v2.0 evolves from a Docker-native DevSecOps tool into a **production infrastructure control plane** for small teams, agencies, and early-stage companies.

---

## North Star Definition

> **InfraPilot governs everything that runs your business in production — services, traffic, data, access, and risk — without owning your cloud or your code.**

### What This Means

| We Do | We Don't |
|-------|----------|
| Monitor and secure your containers | Host your containers |
| Govern your traffic exposure | Become your CDN |
| Track your database health | Manage your database |
| Alert on backup failures | Run your backups |
| Detect secret sprawl | Store your secrets |
| Map your dependencies | Replace your services |

---

## Strategic Positioning

### Target Users
- **Small engineering teams** (3-15 engineers)
- **Digital agencies** managing multiple client deployments
- **Early-stage startups** (Seed to Series A)
- **Consultants** setting up production infrastructure

### Key Value Propositions
1. **Enterprise visibility without enterprise complexity**
2. **Security posture awareness, not security products**
3. **Governance that helps, not governance that blocks**
4. **Single pane of glass for "what's running in prod"**

### Competitive Differentiation
- Not a cloud provider (like AWS, GCP, Azure)
- Not a container orchestrator (like Kubernetes)
- Not a CI/CD platform (like GitHub Actions, GitLab CI)
- Not a monitoring tool (like Datadog, New Relic)

**InfraPilot is the control plane that sits above all of these.**

---

## Epic Grouping Overview

| Layer | Focus | Epics |
|-------|-------|-------|
| **Build** | Shift-left security & quality | 1, 2, 8, 12 (v1 ✅) |
| **Deploy** | Safe, governed releases | 0, 4 (v1 ✅) |
| **Run** | Runtime awareness & protection | 3, 5, 6 (v1 ✅) |
| **Govern** | Ownership, risk, accountability | 9, 10, 11 (v1 ✅) |
| **Platform** | Secure control plane | 6, 7 |
| **Business Infra** | Databases, traffic, data | 13, 14, 15, 16, 17, 18 (v2 ✅) |
| **Experience** | UX, clarity, trust | 19 (v2 ✅) |

---

## V2.0 Epic Summary

### V1 Foundation (Completed)

| Epic | Name | Status |
|------|------|--------|
| 0 | DevSecOps Foundations | ✅ Complete |
| 1 | Supply Chain Security | ✅ Complete |
| 2 | Policy-as-Code | ✅ Complete |
| 3 | Runtime Security | ✅ Complete |
| 4 | Dev Integration | ✅ Complete |
| 5 | DevSecOps Observability | ✅ Complete |
| 6 | Platform Hardening | ✅ Complete |
| 8 | Developer Feedback | ✅ Complete |
| 9 | Risk Acceptance | ✅ Complete |
| 10 | Ownership & Accountability | ✅ Complete |
| 11 | Security Maturity Scoring | ✅ Complete |
| 12 | Code Quality Integration | ✅ Complete |

### V2 Core (Complete)

| Epic | Name | Priority | Purpose |
|------|------|----------|---------|
| 7 | Research & Metrics Readiness | Optional | Measure impact, not just features |
| 13 | Traffic & Exposure Governance | **HIGH** | Control what is publicly reachable |
| 14 | Database & Data Governance | **HIGH** | Govern data without becoming a DB provider |
| 15 | Backup & Recovery Visibility | Medium | Disaster readiness without complexity |
| 16 | Secrets Hygiene | Medium | Reduce credential-based breaches |
| 17 | Background Jobs & Workers | Medium | Make silent failures visible |
| 18 | External Dependency Mapping | Low | Understand blast radius |
| 19 | UX & Navigation System | **HIGH** | Make power feel calm and obvious |

---

## V2 Expansion Epics (Detailed)

### Epic 13 — Traffic & Exposure Governance (V2 PRIORITY)

**Purpose**: Control what is publicly reachable.

**Key Questions Answered**:
- What is exposed to the internet right now?
- What TLS certificates are about to expire?
- Which services have rate limiting configured?
- Are we protected against bot traffic?

**Features**:
- Load balancing visibility (L4/L7)
- Rate limiting profiles
- CAPTCHA / bot protection (proxy-level)
- Public exposure map
- TLS posture scoring
- Certificate expiry alerting

**Dependencies**: Nginx proxy (already integrated)

---

### Epic 14 — Database & Data Governance (V2 PRIORITY)

**Purpose**: Govern data without becoming a DB provider.

**Key Questions Answered**:
- Is my data safe, backed up, and owned?
- Are there any databases exposed publicly?
- Which databases don't have TLS enabled?
- Who owns this database?

**Features**:
- DB inventory (PostgreSQL, MySQL, Redis, MongoDB)
- Exposure detection (public/private)
- TLS & authentication posture
- Backup visibility (existence, not management)
- Ownership mapping (service → team → DB)

**Dependencies**: Docker socket access, port scanning

---

### Epic 15 — Backup & Recovery Visibility

**Purpose**: Disaster readiness without complexity.

**Key Questions Answered**:
- Are all production services backed up?
- When was the last successful backup?
- Are we compliant with our backup policy?

**Features**:
- Backup existence detection
- Freshness tracking (last backup timestamp)
- Policy enforcement ("prod must have daily backup")
- Alerting on failures
- Backup → Service mapping

**Dependencies**: Integration with backup tools (restic, borgmatic, or cloud snapshots)

---

### Epic 16 — Secrets Hygiene (Lightweight)

**Purpose**: Reduce credential-based breaches.

**Key Questions Answered**:
- How old are our secrets?
- Are there hardcoded secrets in our code?
- Which secrets haven't been rotated in 90+ days?

**Features**:
- Secret age tracking (via environment variables)
- Rotation reminders
- CI exposure detection (secrets in logs)
- Policy checks (no hardcoded secrets)
- Integration with secret managers (HashiCorp Vault, AWS Secrets Manager)

**Dependencies**: Code scanning (extend Epic 12), environment inspection

---

### Epic 17 — Background Jobs & Workers

**Purpose**: Make silent failures visible.

**Key Questions Answered**:
- Are all our cron jobs running on schedule?
- Which workers are failing silently?
- Are there any retry storms happening?

**Features**:
- Cron / worker visibility (scheduled tasks)
- Failure tracking
- Retry storm detection
- Last run status and timestamp
- Ownership & alert routing

**Dependencies**: Docker exec access, log parsing

---

### Epic 18 — External Dependency Mapping

**Purpose**: Understand blast radius.

**Key Questions Answered**:
- What external services are we dependent on?
- If Stripe goes down, which services are affected?
- What's our third-party vendor risk profile?

**Features**:
- Dependency inventory (Stripe, SendGrid, Auth0, S3, etc.)
- Dependency → Service mapping
- Health monitoring (external service status pages)
- Incident correlation
- Vendor risk scoring

**Dependencies**: Egress traffic analysis, manual configuration

---

### Epic 19 — UX & Navigation System (ENTERPRISE GRADE)

**Purpose**: Make power feel calm and obvious.

**Key Questions Answered**:
- How do I navigate complex security information?
- Where do I find what I need?
- How do I understand relationships between entities?

**Features**:
- Risk-centric navigation (Build / Deploy / Run / Govern)
- Design system + Storybook component library
- Golden page pattern (consistent entity pages)
- Entity cross-linking (click from vulnerability → container → deployment)
- Accessibility compliance (WCAG 2.1 AA)
- Performance optimization (< 100ms interactions)

**Dependencies**: Frontend architecture, design system

---

## Explicitly Out of Scope

To maintain focus and avoid scope creep:

| Out of Scope | Reason |
|--------------|--------|
| Kubernetes | Complexity exceeds target market needs |
| Cloud provisioning (Terraform) | Not our lane |
| CI hosting | GitHub Actions, GitLab CI are better |
| Feature flags | LaunchDarkly, Statsig exist |
| App hosting (PaaS) | Heroku, Fly.io, Render are better |
| FinOps dashboards | Separate product category |
| Log aggregation | Loki, ELK, Datadog are better |
| APM / tracing | Datadog, Honeycomb are better |

---

## Success Metrics

### V2 Launch Criteria

| Metric | Target |
|--------|--------|
| Epic completion | All HIGH priority epics (13, 14, 19) |
| UX satisfaction | > 4.0/5.0 user rating |
| Setup time | < 30 minutes to first value |
| Coverage | > 90% of running infrastructure visible |

### V2 Health Metrics

| Metric | Target |
|--------|--------|
| Time to detect exposure | < 5 minutes |
| False positive rate | < 5% |
| Dashboard load time | < 2 seconds |
| Alert delivery time | < 1 minute |

---

## V2.0 in One Sentence

> **InfraPilot v2.0 is the local control plane that gives small teams enterprise-grade visibility, security, and governance over everything they run in production — without complexity or lock-in.**
