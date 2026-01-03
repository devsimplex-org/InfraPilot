# InfraPilot - Product Roadmap

## Vision

InfraPilot is a Docker-native infrastructure cockpit for managing traffic, containers, logs, security, and alerts — without touching the host OS.

---

## MVP Scope (v0.1)

### Included ✅
- Nginx reverse proxy + SSL management
- Docker container operations
- Container exec (shell access)
- Unified log viewer
- Alerts (SMTP + Slack)
- RBAC + audit logs

### Excluded ❌ (Hard Lock)
- SSH access
- SSH logs
- Linux user management
- Kubernetes
- Cloud provider APIs

---

## Release Phases

### v0.1 - Foundation + Proxy (Current)
**Goal:** Basic proxy management working end-to-end

- [x] Backend API scaffold
- [x] Agent scaffold
- [x] Frontend scaffold
- [x] Nginx proxy CRUD
- [x] Nginx config generation & reload
- [x] **Dynamic network attachment (EPIC-04)**
  - [x] Container selection in proxy form
  - [x] Network detection & nginx attachment
  - [x] Safety validation (blocks host/none/overlay)
- [x] SSL automation (Let's Encrypt)
- [x] Full gRPC streaming for commands

### v0.2 - Container Operations ✅
**Goal:** Full Docker container management

- [x] Container list with metrics
- [x] Start/stop/restart controls
- [x] Container logs (paginated + streaming)
- [x] Container exec terminal
- [x] Docker Compose stack grouping

### v0.3 - Observability ✅
**Goal:** Unified logging and visibility

- [x] Nginx access/error logs
- [x] Container logs aggregation
- [x] Real-time log streaming
- [x] Search and filtering
- [ ] Error spike detection

### v0.4 - Alerting ✅
**Goal:** Proactive notifications

- [x] Alert channels (SMTP, Slack, Webhook)
- [x] Alert rules engine
- [x] Container crash alerts
- [x] SSL expiry alerts
- [x] High error rate alerts

### v0.5 - Security & Polish ✅
**Goal:** Production-ready security

- [x] MFA (TOTP) fully implemented
- [x] Complete audit trail
- [x] TLS health scoring
- [x] Rate limiting UI
- [x] Database health monitoring

### v1.0 - General Availability
**Goal:** Production release

- [ ] Full test coverage
- [ ] Performance optimization
- [ ] Documentation site
- [ ] Helm chart / easy deployment

---

## Enterprise Edition Roadmap

> Enterprise features are source-visible under BSL license.
> Primary revenue: SaaS at infrapilot.io

### v1.1 - Enterprise Foundation (Current)
**Goal:** License system and feature gating

- [x] License package (`internal/enterprise/license/`)
- [x] Feature constants and gates
- [x] License middleware
- [ ] Wire into main router
- [ ] License info API endpoint
- [ ] Frontend license status UI
- [ ] License generation CLI
- [ ] BSL license file

**Epic:** [EPIC-05-ENTERPRISE-FOUNDATION](epics/EPIC-05-ENTERPRISE-FOUNDATION.md)

### v1.2 - Enterprise SSO
**Goal:** SAML, OIDC, LDAP authentication

- [ ] SAML 2.0 (Okta, Azure AD, OneLogin)
- [ ] OIDC (Google Workspace, Auth0)
- [ ] LDAP/Active Directory
- [ ] JIT user provisioning
- [ ] Group-to-role mapping
- [ ] SSO provider management UI

**Epic:** [EPIC-06-SSO](epics/EPIC-06-SSO.md)

### v1.3 - Multi-Tenancy
**Goal:** Multiple organizations per instance

- [ ] Organization management
- [ ] User invitations
- [ ] Organization switching
- [ ] Row-Level Security (RLS)
- [ ] Per-org usage limits

**Epic:** [EPIC-07-MULTI-TENANT](epics/EPIC-07-MULTI-TENANT.md)

### v1.4 - Advanced Audit & Compliance
**Goal:** Enterprise audit and compliance

- [ ] Unlimited audit retention
- [ ] Export (CSV, JSON, CEF)
- [ ] External forwarding (Splunk, ELK)
- [ ] SOC2/HIPAA reports
- [ ] Compliance dashboards

**Epic:** [EPIC-08-ADVANCED-AUDIT](epics/EPIC-08-ADVANCED-AUDIT.md)

### v1.5 - Advanced RBAC
**Goal:** Custom roles and permissions

- [ ] Custom role definitions
- [ ] Fine-grained permissions
- [ ] Resource-level access control
- [ ] Permission inheritance
- [ ] Role templates

### v2.0 - SaaS Platform
**Goal:** Fully managed cloud offering

- [ ] Stripe billing integration
- [ ] Usage-based pricing
- [ ] Self-service onboarding
- [ ] SLA monitoring
- [ ] Customer success portal

---

## Future Considerations (Post v1.0)

### Possible Features
- Backup/restore for proxy configs
- Custom nginx snippets
- Load balancer health checks
- Blue/green deployment support
- Container resource limits UI
- Log retention policies
- Prometheus metrics export
- Grafana integration
- Network topology visualization
- Bulk network attachment management
- Automatic network cleanup on proxy deletion

### Explicitly Out of Scope (Community Edition)
- Multi-node / distributed agents
- SSH/shell access to host
- Kubernetes orchestration
- Cloud provider integration
- CI/CD pipelines
- Container image building
- Registry management

---

## Success Metrics

| Metric | Target |
|--------|--------|
| API response time | < 100ms p95 |
| Agent heartbeat | Every 30s |
| Log streaming latency | < 1s |
| Dashboard load time | < 2s |
| Container action response | < 3s |

---

## Technical Debt Tracker

| Item | Priority | Status |
|------|----------|--------|
| Add sqlc for type-safe queries | Medium | Planned |
| Implement proper gRPC streaming | High | ✅ Done |
| Add comprehensive error handling | Medium | Ongoing |
| Unit test coverage | High | Planned |
| Integration tests | Medium | Planned |
| API documentation (OpenAPI) | Low | Future |
| Wire up gRPC for network commands | Medium | ✅ Done |
| Network attachment cleanup on proxy delete | Low | Future |
