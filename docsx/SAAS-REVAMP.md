# InfraPilot SaaS Revamp - Master Engineering Brief

> **Status:** Active Development
> **Owner:** DevSimplex Ltd
> **Target:** Complete SaaS + Enterprise + Community Platform

---

## 1. Executive Summary

InfraPilot is being revamped from a self-hosted Docker management tool into a **Hosted Control Plane** product with three editions:

1. **Community Edition** - Fully open source (Apache 2.0)
2. **Enterprise Edition** - Self-hosted with enterprise features (BSL 1.1)
3. **SaaS Edition** - Hosted control plane at infrapilot.sh

### Core Principle (Non-Negotiable)

```
InfraPilot is a CONTROL PLANE, not a HOSTING PLATFORM.

❌ We do NOT host customer containers
❌ We do NOT provide compute
✅ Customers run containers on THEIR servers
✅ InfraPilot hosts: dashboard, config, policies, identity, coordination
```

---

## 2. Product Domains

| Domain | Purpose | Repo |
|--------|---------|------|
| infrapilot.org | Marketing, docs, OSS landing | Separate repo |
| infrapilot.sh | SaaS product | This repo |
| app.infrapilot.sh | SaaS dashboard | This repo (frontend) |
| api.infrapilot.sh | SaaS API | This repo (backend) |
| get.infrapilot.sh | Agent installer | CDN / static hosting |

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     CUSTOMER SERVERS                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ Agent (Go)  │  │ Agent (Go)  │  │ Agent (Go)  │              │
│  │ - Docker    │  │ - Docker    │  │ - Docker    │              │
│  │ - Nginx     │  │ - Nginx     │  │ - Nginx     │              │
│  │ - Logs      │  │ - Logs      │  │ - Logs      │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         └────────────────┼────────────────┘                      │
│                          │ mTLS gRPC (outbound only)             │
└──────────────────────────┼──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│              INFRAPILOT CONTROL PLANE (SaaS)                     │
│                     api.infrapilot.sh                            │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Go Backend                              │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐         │   │
│  │  │ Auth/   │ │ Multi-  │ │ Policy  │ │ Audit/  │         │   │
│  │  │ SSO     │ │ Tenant  │ │ Engine  │ │ Comply  │         │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘         │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐         │   │
│  │  │ gRPC    │ │ License │ │ Billing │ │ Alerts  │         │   │
│  │  │ Server  │ │ Gate    │ │ (SaaS)  │ │ Engine  │         │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘         │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ PostgreSQL  │  │   Redis     │  │ ClickHouse  │              │
│  │ (Config)    │  │ (Pub/Sub)   │  │ (Logs) opt  │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                  INFRAPILOT DASHBOARD                            │
│                    app.infrapilot.sh                             │
│                   (Next.js 15 + React)                           │
└─────────────────────────────────────────────────────────────────┘
```

### Critical Guarantee

> **If the control plane goes offline, customer containers KEEP RUNNING.**
>
> The agent is autonomous. It executes the last known config.
> This is non-negotiable for enterprise trust.

---

## 4. Edition Comparison

| Feature | Community | Enterprise | SaaS |
|---------|-----------|------------|------|
| **Core Features** | | | |
| Docker management | ✅ | ✅ | ✅ |
| Nginx proxy + SSL | ✅ | ✅ | ✅ |
| Container logs | ✅ | ✅ | ✅ |
| Basic alerts | ✅ | ✅ | ✅ |
| Basic RBAC (3 roles) | ✅ | ✅ | ✅ |
| Single org | ✅ | ✅ | ✅ |
| **Enterprise Features** | | | |
| Multi-org / Multi-tenant | ❌ | ✅ | ✅ |
| SSO (SAML/OIDC/LDAP) | ❌ | ✅ | ✅ |
| Advanced RBAC | ❌ | ✅ | ✅ |
| Policy engine | ❌ | ✅ | ✅ |
| Unlimited audit logs | ❌ | ✅ | ✅ |
| Compliance exports | ❌ | ✅ | ✅ |
| SIEM integration | ❌ | ✅ | ✅ |
| **SaaS Exclusive** | | | |
| Hosted control plane | ❌ | ❌ | ✅ |
| Zero backend ops | ❌ | ❌ | ✅ |
| One-liner agent install | ❌ | ❌ | ✅ |
| Log persistence (disaster) | ❌ | ❌ | ✅ |
| Managed upgrades | ❌ | ❌ | ✅ |
| **Support** | | | |
| Community support | ✅ | ✅ | ✅ |
| Priority support | ❌ | ✅ | ✅ |
| SLA guarantee | ❌ | Optional | ✅ |

---

## 5. SaaS Onboarding Flow (The One-Liner)

### 5.1 User Journey

```
1. User visits infrapilot.sh
2. Signs up / Logs in
3. Creates organization
4. Gets enrollment token
5. Runs one-liner on their server
6. Agent appears in dashboard instantly
```

### 5.2 The One-Liner Install

```bash
curl -fsSL https://get.infrapilot.sh/agent | \
  INFRAPILOT_ENROLL_TOKEN=ip_enroll_xxxxxxxx \
  INFRAPILOT_ENDPOINT=https://api.infrapilot.sh \
  sh
```

What this does:
1. Downloads and installs agent binary
2. Registers with enrollment token
3. Receives mTLS certificate
4. Starts heartbeating
5. Appears in dashboard

### 5.3 Agent Registration Flow

```
Agent                           Backend (SaaS)
  │                                   │
  │  POST /api/v1/agents/enroll       │
  │  {enrollment_token, hostname}     │
  │ ─────────────────────────────────>│
  │                                   │
  │                                   │ Validate token
  │                                   │ Create agent record
  │                                   │ Generate mTLS cert
  │                                   │
  │<─────────────────────────────────│
  │  {agent_id, cert, key, endpoint}  │
  │                                   │
  │  gRPC CommandStream (mTLS)        │
  │ ═════════════════════════════════>│
  │                                   │
```

### 5.4 Enrollment Token Format

```json
{
  "id": "ip_enroll_xxxxxxxx",
  "org_id": "uuid",
  "created_by": "user_id",
  "expires_at": "2026-02-03T00:00:00Z",
  "max_uses": 10,
  "uses": 0,
  "labels": {
    "environment": "production",
    "region": "eu-west-1"
  }
}
```

---

## 6. Multi-Tenancy Model (E3)

### 6.1 Database Isolation

```sql
-- All tables have org_id
-- Row-Level Security (RLS) enforces isolation

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;

CREATE POLICY agents_org_isolation ON agents
  USING (org_id = current_setting('app.current_org_id')::uuid);

-- Similar for all tables:
-- proxy_hosts, containers, alert_rules, audit_logs, etc.
```

### 6.2 Org Structure

```sql
CREATE TABLE organizations (
    id              UUID PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) UNIQUE NOT NULL,
    plan            VARCHAR(50) DEFAULT 'free',  -- free, pro, enterprise

    -- Billing (SaaS only)
    stripe_customer_id VARCHAR(255),
    subscription_status VARCHAR(50),

    -- Limits
    max_users       INTEGER DEFAULT 5,
    max_agents      INTEGER DEFAULT 3,

    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE organization_members (
    id              UUID PRIMARY KEY,
    org_id          UUID REFERENCES organizations(id),
    user_id         UUID REFERENCES users(id),
    role            VARCHAR(50) NOT NULL,  -- owner, admin, member, viewer
    invited_by      UUID REFERENCES users(id),
    joined_at       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE organization_invitations (
    id              UUID PRIMARY KEY,
    org_id          UUID REFERENCES organizations(id),
    email           VARCHAR(255) NOT NULL,
    role            VARCHAR(50) NOT NULL,
    token           VARCHAR(64) UNIQUE NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    accepted_at     TIMESTAMPTZ,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

### 6.3 Context Propagation

```go
// Every request sets org context
func OrgMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Get org from JWT claims
        claims := auth.GetClaims(c)
        orgID := claims.OrgID

        // Set for RLS
        c.Set("org_id", orgID)

        // Set in DB session
        db.Exec("SET app.current_org_id = $1", orgID)

        c.Next()
    }
}
```

---

## 7. Policy Engine (E5)

### 7.1 Policy Types

| Policy | Description | Action |
|--------|-------------|--------|
| no_root_containers | Block containers running as root | Block/Warn |
| require_ssl | All public services must have SSL | Block/Warn |
| require_restart_policy | Containers must have restart policy | Block/Warn |
| no_exec_production | Block exec in production environments | Block |
| max_container_age | Alert on old containers | Warn |
| require_healthcheck | Containers must have healthcheck | Warn |

### 7.2 Policy Schema

```sql
CREATE TABLE policies (
    id              UUID PRIMARY KEY,
    org_id          UUID REFERENCES organizations(id),
    name            VARCHAR(255) NOT NULL,
    policy_type     VARCHAR(100) NOT NULL,
    conditions      JSONB NOT NULL,
    action          VARCHAR(20) NOT NULL,  -- block, warn, audit
    enabled         BOOLEAN DEFAULT true,
    applies_to      JSONB,  -- agent labels, environments
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE policy_violations (
    id              UUID PRIMARY KEY,
    policy_id       UUID REFERENCES policies(id),
    org_id          UUID REFERENCES organizations(id),
    agent_id        UUID REFERENCES agents(id),
    resource_type   VARCHAR(50),
    resource_id     VARCHAR(255),
    message         TEXT,
    resolved        BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
```

### 7.3 Policy Evaluation Flow

```
Request (e.g., start container)
         │
         ▼
┌─────────────────────┐
│  Load applicable    │
│  policies for org   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Evaluate each      │
│  policy condition   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────┐
│                Action                    │
├─────────────────────────────────────────┤
│  BLOCK: Return error, log violation     │
│  WARN:  Allow action, show warning      │
│  AUDIT: Allow action, log only          │
└─────────────────────────────────────────┘
```

---

## 8. Log Management (Disaster Recovery)

### 8.1 The Problem

> If logs are only on the server, and the server crashes, you can't debug.

### 8.2 The Solution

SaaS streams logs to central storage. When server dies, logs survive.

```
Agent → gRPC Stream → Backend → ClickHouse/PostgreSQL → Dashboard
```

### 8.3 Log Storage Options

| Option | Retention | Cost | Query Speed |
|--------|-----------|------|-------------|
| PostgreSQL | 7 days | Low | Medium |
| ClickHouse | Unlimited | Medium | Fast |
| S3 (cold) | Archive | Low | Slow |

### 8.4 Implementation

```sql
-- For SaaS, logs stored centrally
CREATE TABLE logs (
    id              UUID PRIMARY KEY,
    org_id          UUID NOT NULL,
    agent_id        UUID NOT NULL,
    source          VARCHAR(50),  -- container, nginx_access, nginx_error
    container_id    VARCHAR(64),
    level           VARCHAR(20),
    message         TEXT,
    metadata        JSONB,
    timestamp       TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ DEFAULT NOW()
);

-- Partition by time for performance
CREATE INDEX idx_logs_org_time ON logs(org_id, timestamp DESC);
```

---

## 9. Billing Infrastructure (SaaS Only)

### 9.1 Pricing Model

| Tier | Agents | Price | Features |
|------|--------|-------|----------|
| Free | 1 | $0 | Basic features |
| Pro | 10 | $X/mo | + More agents, logs |
| Team | 50 | $XX/mo | + SSO, policies |
| Enterprise | Unlimited | Custom | + HA, support, SLA |

### 9.2 Metering

```go
type UsageMetrics struct {
    OrgID          string
    AgentsCount    int
    UsersCount     int
    LogsGB         float64
    ProxyHostCount int
    Period         time.Time
}

// Collected daily, sent to billing system
```

### 9.3 Stripe Integration

```sql
CREATE TABLE subscriptions (
    id                  UUID PRIMARY KEY,
    org_id              UUID REFERENCES organizations(id),
    stripe_subscription_id VARCHAR(255),
    plan                VARCHAR(50),
    status              VARCHAR(50),
    current_period_end  TIMESTAMPTZ,
    cancel_at_period_end BOOLEAN DEFAULT false,
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE invoices (
    id                  UUID PRIMARY KEY,
    org_id              UUID REFERENCES organizations(id),
    stripe_invoice_id   VARCHAR(255),
    amount_cents        INTEGER,
    status              VARCHAR(50),
    period_start        TIMESTAMPTZ,
    period_end          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ DEFAULT NOW()
);
```

---

## 10. Implementation Phases

### Phase 1: Foundation ✅ (DONE)
- [x] License system (Ed25519)
- [x] Feature gates
- [x] License middleware
- [x] LICENSE files

### Phase 2: SSO ✅ (DONE)
- [x] SAML 2.0
- [x] OIDC
- [x] LDAP
- [x] JIT user provisioning
- [x] SSO UI

### Phase 3: Audit/Compliance ✅ (DONE)
- [x] Audit config (retention, forwarding)
- [x] Export (CSV, JSON, CEF, Syslog)
- [x] Compliance reports (SOC2, HIPAA)
- [x] Integrity verification

### Phase 4: Multi-Tenancy (E3) ⏳ (REQUIRED FOR SAAS)
- [ ] Org invitations
- [ ] Org switcher
- [ ] RLS enforcement
- [ ] Per-org limits
- [ ] Org settings UI

### Phase 5: SaaS Infrastructure ⏳
- [ ] Enrollment tokens
- [ ] One-liner installer
- [ ] Log persistence
- [ ] API subdomain support
- [ ] Health monitoring

### Phase 6: Policy Engine ⏳
- [ ] Policy schema
- [ ] Policy evaluation
- [ ] Built-in policies
- [ ] Policy UI
- [ ] Violation tracking

### Phase 7: Billing (SaaS) ⏳
- [ ] Stripe integration
- [ ] Usage metering
- [ ] Plan limits
- [ ] Invoice history
- [ ] Upgrade/downgrade

---

## 11. Environment Configuration

### 11.1 Self-Hosted (Community/Enterprise)

```bash
# .env
INFRAPILOT_MODE=self-hosted
DATABASE_URL=postgres://...
REDIS_URL=redis://...
JWT_SECRET=...
INFRAPILOT_LICENSE=...  # Enterprise only
```

### 11.2 SaaS Mode

```bash
# .env (production)
INFRAPILOT_MODE=saas
INFRAPILOT_CLOUD=true
DATABASE_URL=postgres://...
REDIS_URL=redis://...
CLICKHOUSE_URL=clickhouse://...  # Log storage
JWT_SECRET=...
STRIPE_SECRET_KEY=sk_...
BASE_URL=https://api.infrapilot.sh
FRONTEND_URL=https://app.infrapilot.sh
```

---

## 12. API Changes for SaaS

### 12.1 New Endpoints

```
# Enrollment
POST   /api/v1/agents/enroll        # Agent self-registration
GET    /api/v1/enrollment-tokens    # List tokens
POST   /api/v1/enrollment-tokens    # Create token
DELETE /api/v1/enrollment-tokens/:id

# Organizations
GET    /api/v1/orgs                 # List user's orgs
POST   /api/v1/orgs                 # Create org
GET    /api/v1/orgs/:id             # Org details
PUT    /api/v1/orgs/:id             # Update org
DELETE /api/v1/orgs/:id             # Delete org

# Org Members
GET    /api/v1/orgs/:id/members     # List members
POST   /api/v1/orgs/:id/members     # Add member
PUT    /api/v1/orgs/:id/members/:uid
DELETE /api/v1/orgs/:id/members/:uid

# Invitations
GET    /api/v1/orgs/:id/invitations
POST   /api/v1/orgs/:id/invitations
DELETE /api/v1/orgs/:id/invitations/:iid
POST   /api/v1/invitations/:token/accept

# Billing (SaaS only)
GET    /api/v1/billing/subscription
POST   /api/v1/billing/checkout
POST   /api/v1/billing/portal
GET    /api/v1/billing/invoices
GET    /api/v1/billing/usage

# Policies
GET    /api/v1/policies
POST   /api/v1/policies
GET    /api/v1/policies/:id
PUT    /api/v1/policies/:id
DELETE /api/v1/policies/:id
GET    /api/v1/policies/violations
```

---

## 13. Frontend Changes

### 13.1 New Pages

```
/                           # Landing (redirect to /dashboard or /login)
/login                      # Auth
/signup                     # Registration (SaaS)
/orgs                       # Org switcher
/orgs/new                   # Create org
/orgs/:id/settings          # Org settings
/orgs/:id/members           # Member management
/orgs/:id/invitations       # Pending invitations
/billing                    # Subscription (SaaS)
/billing/plans              # Plan selection
/policies                   # Policy management
/policies/new               # Create policy
/policies/:id               # Edit policy
/policies/violations        # Violation log
/onboarding                 # First-time setup
/onboarding/install         # Agent install instructions
```

### 13.2 Org Switcher Component

```tsx
// In header/sidebar
<OrgSwitcher
  currentOrg={currentOrg}
  orgs={userOrgs}
  onSwitch={(orgId) => switchOrg(orgId)}
/>
```

---

## 14. Data Privacy Rules

### 14.1 What SaaS Stores

✅ Allowed:
- Agent metadata (hostname, status, version)
- Container metadata (name, image, status)
- Proxy configurations
- Log messages (opt-in for SaaS)
- Audit trail
- User profiles

❌ Never Stored:
- Container payloads/data
- Environment variables (except names)
- Secrets/passwords
- File contents
- Network traffic

### 14.2 Data Isolation

- Each org's data completely isolated
- RLS enforced at database level
- No cross-org data access
- Audit log for all data access

---

## 15. Success Criteria

InfraPilot revamp is successful when:

1. **Startup Test**: A startup can connect 5 servers in 10 minutes
2. **Enterprise Test**: An enterprise can demand SAML + audit logs
3. **Homelab Test**: A homelab user can self-host fully offline
4. **Security Test**: No SSH access required anywhere
5. **Disaster Test**: Logs survive server crashes
6. **Trust Test**: InfraPilot becomes "the place you check first"

---

## 16. Files to Create/Modify

### Backend
```
internal/enterprise/
  ├── license/          ✅ Done
  ├── sso/              ✅ Done
  ├── audit/            ✅ Done
  ├── multitenancy/     ⏳ E3
  │   ├── org.go
  │   ├── members.go
  │   ├── invitations.go
  │   └── rls.go
  ├── policy/           ⏳ E5
  │   ├── engine.go
  │   ├── evaluator.go
  │   └── builtins.go
  └── billing/          ⏳ SaaS
      ├── stripe.go
      ├── metering.go
      └── webhooks.go

internal/api/
  ├── enrollment.go     ⏳ SaaS
  ├── orgs.go           ⏳ E3
  ├── policies.go       ⏳ E5
  └── billing.go        ⏳ SaaS
```

### Frontend
```
app/
  ├── (dashboard)/
  │   ├── orgs/         ⏳ E3
  │   ├── policies/     ⏳ E5
  │   ├── billing/      ⏳ SaaS
  │   └── onboarding/   ⏳ SaaS
  └── components/
      ├── OrgSwitcher   ⏳ E3
      ├── PolicyEditor  ⏳ E5
      └── BillingCard   ⏳ SaaS
```

---

## 17. One Sentence to Remember

> **InfraPilot is not hosting workloads. It hosts control, visibility, and trust.**

---

*Last Updated: 2026-01-03*
*Author: DevSimplex Ltd*
