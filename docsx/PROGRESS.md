# InfraPilot - Progress Tracker

> Last Updated: 2026-01-03

## Architecture Overview

InfraPilot has two editions:

| Edition | Deployment | Target | Features |
|---------|------------|--------|----------|
| **Community** | Self-hosted (Docker Hub) | Single node | Full proxy/container/logs/alerts, built-in agent |
| **SaaS** | Hosted (infrapilot.sh) | Multi-node | Multi-tenant, SSO, audit, policies, billing |

### Community Edition (Apache 2.0)
- **Deployment:** `docker pull infrapilot/infrapilot` + single docker-compose
- **Architecture:** Single node with built-in agent
- **Features:** All core features (proxy management, containers, logs, alerts)
- **Organization:** Single org, single node
- **Cost:** Free, open source

### SaaS Edition (infrapilot.sh)
- **Deployment:** Hosted control plane at app.infrapilot.sh
- **Architecture:** Central control plane + distributed agents
- **Features:** All Community features + SSO, audit/compliance, policy engine, multi-tenancy
- **Organization:** Multi-tenant with RLS data isolation
- **Cost:** Subscription-based (Stripe billing)

---

## Overall Status

### Community Edition

| Component | Status | Progress |
|-----------|--------|----------|
| Foundation | ✅ Complete | 100% |
| Nginx Proxy Management | ✅ Complete | 100% |
| Docker Operations | ✅ Complete | 100% |
| Unified Logs | ✅ Complete | 100% |
| Alerts & Notifications | ✅ Complete | 100% |
| Health Monitoring | ✅ Complete | 100% |
| User Management | ✅ Complete | 100% |
| MFA (TOTP) | ✅ Complete | 100% |

### SaaS Edition

| Component | Status | Progress |
|-----------|--------|----------|
| Multi-Tenancy (RLS) | ✅ Complete | 100% |
| SSO (SAML/OIDC/LDAP) | ✅ Complete | 100% |
| Audit & Compliance | ✅ Complete | 100% |
| Policy Engine | ✅ Complete | 100% |
| Agent Enrollment | ✅ Complete | 100% |
| Log Persistence | ✅ Complete | 100% |
| Billing (Stripe) | ⬜ Planned | 0% |
| Edition Toggle System | ⬜ Planned | 0% |

**Community Edition:** ✅ COMPLETE
**SaaS Edition:** 85% (Billing + Edition toggle remaining)

---

## Community Edition Features

### Foundation ✅
- Go backend with Gin HTTP router
- PostgreSQL database (15+ tables)
- Next.js 15 frontend with App Router
- JWT authentication with refresh tokens
- RBAC (super_admin, admin, operator, viewer)
- Docker Compose deployment
- Hot reload development (Air + Next.js)

### Nginx Proxy Management ✅
- Proxy host CRUD (domain, upstream, SSL settings)
- SSL/TLS automation via Let's Encrypt (ACME HTTP-01)
- Security headers configuration (HSTS, CSP, X-Frame-Options)
- Rate limiting per proxy
- Nginx config generation and validation
- Dynamic network attachment for container upstreams
- Config test and reload via Docker exec

### Docker Operations ✅
- Container list with real-time CPU/memory stats
- Container start/stop/restart with confirmation dialogs
- Container delete with name confirmation
- Container detail page (environment, mounts, network, config)
- Log viewer with level filtering and search
- WebSocket terminal (xterm.js) for exec
- Stack grouping (docker-compose projects)

### Unified Logs ✅
- Multi-container log aggregation
- Real-time WebSocket streaming
- Log level detection and filtering
- Search and container filtering
- CSV export

### Alerts & Notifications ✅
- Alert channels (SMTP, Slack, Webhook)
- Alert rules (container crash, high CPU/memory, restarts)
- Background evaluation loop (30s interval)
- Alert history tracking
- Cooldown to prevent spam

### Health Monitoring ✅
- TLS certificate health scoring
- Database health (latency, connections)
- System health (uptime, memory, goroutines)
- Health dashboard with score rings

### User Management ✅
- User CRUD with role assignment
- MFA (TOTP) with QR code setup
- Backup codes generation
- Audit logging for all actions

---

## SaaS Edition Features

### Multi-Tenancy ✅
- Organizations with plans and limits
- Row-Level Security (RLS) on all tables
- Organization members with roles
- Invitation system
- Org switcher in UI

### SSO Integration ✅
- SAML 2.0 (SP metadata, AuthnRequest, ACS)
- OIDC (Discovery, PKCE, token exchange)
- LDAP (TLS, bind auth, group lookup)
- JIT user provisioning
- Group-to-role mapping

### Audit & Compliance ✅
- Configurable retention (30-365 days)
- Export formats (CSV, JSON, CEF, Syslog)
- External forwarding (Webhook, Syslog, Splunk, S3)
- Compliance reports (SOC2, HIPAA)
- Hash chain integrity verification
- Immutable logs mode

### Policy Engine ✅
- Policy CRUD with conditions (JSON)
- 8 built-in templates (no_root, require_ssl, etc.)
- Container policy evaluation (start/stop/restart)
- Proxy policy evaluation (create/update/delete)
- Violation tracking and resolution
- Action types: block, warn, audit

### Agent Enrollment ✅
- Enrollment tokens with expiry and max uses
- One-liner agent install
- Fingerprint-based authentication
- Heartbeat loop for connectivity
- Auto re-enrollment on credential invalidation

### Log Persistence ✅
- Centralized log storage in PostgreSQL
- Per-org retention configuration
- Log ingestion from agents
- Query API with filters and pagination
- Usage tracking and cleanup

### Billing (Stripe) ⬜ Planned
- [ ] Subscriptions table
- [ ] Invoices table
- [ ] Usage metering
- [ ] Stripe checkout integration
- [ ] Customer portal
- [ ] Webhook handlers
- [ ] Plan limits enforcement
- [ ] Frontend billing page

### Edition Toggle ⬜ Planned
- [ ] EDITION env var (community/saas)
- [ ] Feature gates based on edition
- [ ] Community: single org, built-in agent
- [ ] SaaS: multi-org, enrollment tokens
- [ ] Remove license key system

---

## Deployment Configurations

### Community Edition
```yaml
# docker-compose.yml - Single node deployment
services:
  infrapilot:
    image: infrapilot/infrapilot:latest
    environment:
      - EDITION=community
    # Includes: backend, frontend, agent, nginx, postgres
```

### SaaS Edition
```yaml
# docker-compose.saas.yml - Control plane only
services:
  backend:
    image: infrapilot/backend:latest
    environment:
      - EDITION=saas
  frontend:
    image: infrapilot/frontend:latest
  postgres:
    image: postgres:16
  redis:
    image: redis:7
  # No nginx or agent - agents connect remotely
```

### Agent Installation (SaaS)
```bash
# One-liner install on customer nodes
curl -fsSL https://infrapilot.sh/install | sh -s -- --token=<enrollment_token>
```

---

## API Summary

### Public Endpoints
- `POST /api/v1/setup` - Initial admin setup
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/mfa/verify` - MFA verification
- `GET /api/v1/auth/sso/providers` - List SSO providers
- `POST /api/v1/agents/enroll` - Agent enrollment (SaaS)

### Protected Endpoints (require auth)
- `/api/v1/agents/*` - Agent management
- `/api/v1/agents/:id/proxies/*` - Proxy management
- `/api/v1/agents/:id/containers/*` - Container operations
- `/api/v1/alerts/*` - Alert channels and rules
- `/api/v1/logs/*` - Log queries
- `/api/v1/users/*` - User management (super_admin)
- `/api/v1/orgs/*` - Organization management (SaaS)
- `/api/v1/policies/*` - Policy engine (SaaS)
- `/api/v1/audit/*` - Audit logs (SaaS)
- `/api/v1/sso/*` - SSO providers (SaaS)

---

## Tech Stack

### Backend
- Go 1.21+
- Gin HTTP framework
- PostgreSQL 16 (pgx driver)
- Redis 7 (caching, sessions)
- Docker SDK
- gorilla/websocket

### Frontend
- Next.js 15 (App Router)
- React 19
- TailwindCSS
- React Query (TanStack)
- Zustand (state)
- xterm.js (terminal)

### Agent
- Go 1.21+
- Docker SDK
- WebSocket client
- ACME/Let's Encrypt (lego)

### Infrastructure
- Docker & Docker Compose
- Nginx (managed proxy)
- Let's Encrypt (SSL automation)

---

## Session Log

### Recent Sessions (2026-01-03)

**Session 14 - Container UX Improvements**
- Added real CPU/memory stats to container list and detail pages
- Created container detail page with tabs (Overview, Environment, Mounts, Network, Config, Logs, Terminal)
- Added delete container with name confirmation modal
- Added stop/restart confirmation dialogs
- Fixed policy creation permissions (added RoleAdmin)

**Session 13 - Enterprise Features Complete**
- Completed E3 Multi-Tenancy (OrgMiddleware, RLS)
- Completed E5 Policy Engine (evaluator, container/proxy integration)
- Created organization settings page
- Created policies management page
- Created OrgSwitcher component

**Session 12 - SaaS Foundation**
- Completed S2 Enrollment Tokens
- Completed S5 Agent-side Enrollment
- Created enrollment manager in agent
- WebSocket command streaming for agents

**Session 11 - Audit & Compliance**
- Completed E4 Audit/Compliance
- Export formats (CSV, JSON, CEF, Syslog)
- Compliance reports (SOC2, HIPAA)
- External forwarding (Webhook, Syslog, Splunk, S3)

**Session 10 - SSO Integration**
- Completed E2 SSO
- SAML 2.0, OIDC, LDAP implementations
- JIT user provisioning
- SSO buttons on login page

---

## Remaining Work

### Priority 1: Edition Toggle
1. Add EDITION env var to backend config
2. Create edition gate middleware
3. Community: disable multi-org, use built-in agent
4. SaaS: enable all features, require enrollment

### Priority 2: Deployment Configs
1. Create `docker-compose.yml` for Community
2. Create `docker-compose.saas.yml` for SaaS control plane
3. Create agent installer script
4. Docker Hub image publishing

### Priority 3: Stripe Billing
1. Database schema (subscriptions, invoices)
2. Stripe SDK integration
3. Checkout and portal flows
4. Webhook handlers
5. Frontend billing page
