# InfraPilot v2.0 — Implementation Plan

> Phased implementation plan for v2.0 features

---

## Implementation Philosophy

### Principles

1. **Ship incrementally** — Each phase delivers user value
2. **HIGH priority first** — Epic 13, 14, 19 are blocking
3. **Parallel streams** — Backend and frontend can work simultaneously
4. **Test as you go** — Each epic has acceptance criteria before moving on

### Constraints

- Single engineer / small team
- Existing v1 codebase is stable
- Must maintain backward compatibility
- No breaking changes to existing APIs

---

## Phase Overview

| Phase | Focus | Epics | Priority |
|-------|-------|-------|----------|
| **Phase 1** | Traffic Governance | Epic 13 | HIGH |
| **Phase 2** | Data Governance | Epic 14, 15 | HIGH |
| **Phase 3** | UX Foundation | Epic 19 | HIGH |
| **Phase 4** | Operational Visibility | Epic 16, 17 | Medium |
| **Phase 5** | Ecosystem Mapping | Epic 18 | Low |
| **Phase 6** | Research Readiness | Epic 7 | Optional |

---

## Phase 1: Traffic & Exposure Governance

**Epic**: 13 — Traffic & Exposure Governance
**Priority**: HIGH
**Dependencies**: Nginx integration (v1 ✅)

### Sprint 1.1: Exposure Discovery

**Objective**: Automatically discover all exposed endpoints

**Backend Tasks**:
- [x]Create migration for `exposed_endpoints` table
- [x]Implement endpoint scanner (port detection)
- [x]Create exposure discovery service
- [x]Add scheduled scan job (every 5 minutes)
- [x]Implement `GET /api/v1/exposure/endpoints`
- [x]Implement `POST /api/v1/exposure/scan`

**Frontend Tasks**:
- [x]Create ExposureList page
- [x]Create EndpointCard component
- [x]Add exposure count to dashboard

**Acceptance Criteria**:
- [x]All container ports are discovered
- [x]Public vs internal endpoints distinguished
- [x]Manual scan trigger works

### Sprint 1.2: TLS Visibility

**Objective**: Track TLS status and certificate expiry

**Backend Tasks**:
- [x]Add TLS fields to `exposed_endpoints`
- [x]Implement certificate inspection (via Nginx)
- [x]Create `tls_alert_config` table
- [x]Implement certificate expiry alerting
- [x]Implement `GET /api/v1/tls/posture`

**Frontend Tasks**:
- [x]Add TLS status badge to EndpointCard
- [x]Create TLS Posture dashboard widget
- [x]Create certificate expiry alert UI

**Acceptance Criteria**:
- [x]TLS status shown for all endpoints
- [x]Cert expiry alerts at 30/7 days
- [x]TLS posture score calculated

### Sprint 1.3: Rate Limiting

**Objective**: Configure and assign rate limiting profiles

**Backend Tasks**:
- [x]Create `rate_limit_profiles` table
- [x]Create `rate_limit_assignments` table
- [x]Implement rate limit CRUD API
- [x]Generate Nginx rate limit config
- [x]Reload Nginx on config change

**Frontend Tasks**:
- [x]Create RateLimitProfiles page
- [x]Create profile creation form
- [x]Add assignment UI to endpoint detail

**Acceptance Criteria**:
- [x]Rate limit profiles can be created
- [x]Profiles can be assigned to endpoints
- [x]Nginx enforces rate limits

### Sprint 1.4: Exposure Map

**Objective**: Visual representation of exposure

**Backend Tasks**:
- [x]Implement `GET /api/v1/exposure/map` (graph data)
- [x]Add service linkage to endpoints

**Frontend Tasks**:
- [x]Create ExposureMap visualization
- [x]Color-code by risk level
- [x]Add click-through to endpoint details

**Acceptance Criteria**:
- [x]Visual map shows all endpoints
- [x]Risk levels clearly indicated
- [x]Navigation to details works

### Phase 1 Deliverables

| Deliverable | Type |
|-------------|------|
| `exposed_endpoints` table | Database |
| `rate_limit_profiles` table | Database |
| `rate_limit_assignments` table | Database |
| `tls_alert_config` table | Database |
| 12 new API endpoints | API |
| Exposure Map page | UI |
| Rate Limits page | UI |
| TLS Posture widget | UI |

---

## Phase 2: Data Governance

**Epics**: 14, 15 — Database & Backup Governance
**Priority**: HIGH
**Dependencies**: Docker socket access (v1 ✅)

### Sprint 2.1: Database Discovery

**Objective**: Automatically discover databases

**Backend Tasks**:
- [x]Create migration for `database_inventory` table
- [x]Implement database detector (port-based)
- [x]Implement image-based detection
- [x]Create scheduled discovery job
- [x]Implement `GET /api/v1/databases`
- [x]Implement `POST /api/v1/databases/scan`

**Frontend Tasks**:
- [x]Create DatabaseList page
- [x]Create DatabaseCard component
- [x]Add database count to dashboard

**Acceptance Criteria**:
- [x]PostgreSQL, MySQL, Redis, MongoDB detected
- [x]Container linkage established
- [x]Manual scan works

### Sprint 2.2: Database Security Posture

**Objective**: Assess database security configuration

**Backend Tasks**:
- [x]Implement posture check engine
- [x]Check: public exposure
- [x]Check: TLS enabled
- [x]Check: authentication configured
- [x]Implement `GET /api/v1/databases/:id/posture`

**Frontend Tasks**:
- [x]Create posture checklist UI
- [x]Add posture score to DatabaseCard
- [x]Create remediation suggestions

**Acceptance Criteria**:
- [x]All posture checks run
- [x]Remediation guidance shown
- [x]Score reflects configuration

### Sprint 2.3: Backup Visibility

**Objective**: Track database backups

**Backend Tasks**:
- [x]Create `database_backups` table
- [x]Create `backup_policies` table
- [x]Create `backup_policy_compliance` table
- [x]Implement backup status API
- [x]Implement policy compliance check

**Frontend Tasks**:
- [x]Add backup status to DatabaseCard
- [x]Create BackupPolicies page
- [x]Create compliance dashboard

**Acceptance Criteria**:
- [x]Backup history visible
- [x]Policy violations highlighted
- [x]Compliance score calculated

### Sprint 2.4: Ownership Integration

**Objective**: Assign database ownership

**Backend Tasks**:
- [x]Add `owner_team_id` to `database_inventory`
- [x]Implement `PUT /api/v1/databases/:id/owner`
- [x]Add ownership to posture checks

**Frontend Tasks**:
- [x]Add ownership selector to database detail
- [x]Filter databases by team
- [x]Show ownership in lists

**Acceptance Criteria**:
- [x]Ownership can be assigned
- [x]Ownership affects posture score
- [x]Team filtering works

### Phase 2 Deliverables

| Deliverable | Type |
|-------------|------|
| `database_inventory` table | Database |
| `database_backups` table | Database |
| `backup_policies` table | Database |
| `backup_policy_compliance` table | Database |
| 14 new API endpoints | API |
| Databases page | UI |
| Backup Policies page | UI |
| Database Posture view | UI |

---

## Phase 3: UX Foundation

**Epic**: 19 — UX & Navigation System
**Priority**: HIGH
**Dependencies**: None (can parallel with Phase 1-2)

### Sprint 3.1: Navigation Restructure

**Objective**: Implement risk-centric navigation

**Tasks**:
- [x]Refactor sidebar to layer-based nav
- [x]Implement Build / Deploy / Run / Govern / Data sections
- [x]Update routing structure
- [x]Add breadcrumbs to all pages
- [x]Implement keyboard shortcuts (g h, g b, etc.)

**Acceptance Criteria**:
- [x]All pages accessible via new nav
- [x]Keyboard navigation works
- [x]Breadcrumbs show context

### Sprint 3.2: Golden Page Pattern

**Objective**: Standardize entity pages

**Tasks**:
- [x]Create GoldenPage component
- [x]Create PageHeader component
- [x]Create TabNavigation component
- [x]Refactor Container detail page
- [x]Refactor Deployment detail page
- [x]Refactor Vulnerability detail page

**Acceptance Criteria**:
- [x]Consistent layout across entity pages
- [x]Tabs work correctly
- [x]Actions are accessible

### Sprint 3.3: Design System Polish

**Objective**: Unified component library

**Tasks**:
- [x]Audit existing components
- [x]Create StatusBadge variants
- [x]Create ScoreGauge component
- [x]Create DataTable with sorting/filtering
- [x]Create EmptyState component
- [x]Document in Storybook

**Acceptance Criteria**:
- [x]All components documented
- [x]Consistent styling
- [x]Reusable across pages

### Sprint 3.4: Command Palette & Search

**Objective**: Quick navigation and search

**Tasks**:
- [x]Implement CommandPalette (Cmd+K)
- [x]Add global search endpoint
- [x]Implement search result ranking
- [x]Add recent items
- [x]Add quick actions

**Acceptance Criteria**:
- [x]Cmd+K opens palette
- [x]Search finds entities
- [x]Navigation is instant

### Sprint 3.5: Accessibility

**Objective**: WCAG 2.1 AA compliance

**Tasks**:
- [x]Audit color contrast
- [x]Add focus indicators
- [x]Add ARIA labels
- [x]Test with screen reader
- [x]Add reduced motion support

**Acceptance Criteria**:
- [x]Passes automated a11y tests
- [x]Keyboard-only navigation works
- [x]Screen reader compatible

### Phase 3 Deliverables

| Deliverable | Type |
|-------------|------|
| Risk-centric navigation | UI |
| GoldenPage component | Component |
| CommandPalette | Component |
| Design system documentation | Docs |
| Keyboard shortcuts | Feature |
| Accessibility compliance | Quality |

---

## Phase 4: Operational Visibility

**Epics**: 16, 17 — Secrets & Jobs
**Priority**: Medium
**Dependencies**: Phase 1-3 complete

### Sprint 4.1: Secret Inventory

**Objective**: Track secrets and rotation

**Backend Tasks**:
- [x]Create `secret_inventory` table
- [x]Implement secret detector (env vars)
- [x]Implement age tracking
- [x]Implement rotation reminders

**Frontend Tasks**:
- [x]Create Secrets page
- [x]Create SecretCard component
- [x]Add rotation alerts

### Sprint 4.2: Secret Detection in Code

**Objective**: Find exposed secrets

**Backend Tasks**:
- [x]Implement secret patterns (regex)
- [x]Integrate with code quality scanning
- [x]Create exposure alerts

**Frontend Tasks**:
- [x]Show exposed secrets prominently
- [x]Link to code location
- [x]Add to security score

### Sprint 4.3: Job Discovery

**Objective**: Track background jobs

**Backend Tasks**:
- [x]Create `background_jobs` table
- [x]Create `job_executions` table
- [x]Implement job detector
- [x]Track execution history

**Frontend Tasks**:
- [x]Create Jobs page
- [x]Create JobCard component
- [x]Show execution history

### Sprint 4.4: Job Health Monitoring

**Objective**: Alert on job failures

**Backend Tasks**:
- [x]Implement retry storm detection
- [x]Create failure alerts
- [x]Implement manual trigger API

**Frontend Tasks**:
- [x]Show job health status
- [x]Create failure timeline
- [x]Add manual trigger button

### Phase 4 Deliverables

| Deliverable | Type |
|-------------|------|
| `secret_inventory` table | Database |
| `background_jobs` table | Database |
| `job_executions` table | Database |
| 12 new API endpoints | API |
| Secrets page | UI |
| Jobs page | UI |

---

## Phase 5: Ecosystem Mapping

**Epic**: 18 — External Dependency Mapping
**Priority**: Low
**Dependencies**: Phase 1-4 complete

### Sprint 5.1: Dependency Inventory

**Backend Tasks**:
- [x]Create `external_dependencies` table
- [x]Create `service_dependencies` table
- [x]Implement dependency CRUD API

**Frontend Tasks**:
- [x]Create Dependencies page
- [x]Create dependency form
- [x]Show dependency list

### Sprint 5.2: Dependency Graph

**Backend Tasks**:
- [x]Implement graph data endpoint
- [x]Add health checking (status pages)

**Frontend Tasks**:
- [x]Create dependency graph visualization
- [x]Show health status
- [x]Click-through to details

### Sprint 5.3: Impact Analysis

**Backend Tasks**:
- [x]Implement impact analysis endpoint
- [x]Calculate blast radius

**Frontend Tasks**:
- [x]Show affected services
- [x]Create impact report

### Phase 5 Deliverables

| Deliverable | Type |
|-------------|------|
| `external_dependencies` table | Database |
| `service_dependencies` table | Database |
| 5 new API endpoints | API |
| Dependency Graph page | UI |

---

## Phase 6: Research Readiness

**Epic**: 7 — Research & Metrics
**Priority**: Optional
**Dependencies**: All other phases

### Sprint 6.1: Prometheus Export

**Backend Tasks**:
- [x]Create `/metrics` endpoint
- [x]Export vulnerability counts
- [x]Export policy metrics
- [x]Export maturity scores

### Sprint 6.2: Incident Tracking

**Backend Tasks**:
- [x]Create `security_incidents` table
- [x]Implement incident lifecycle
- [x]Calculate MTTD/MTTR

### Sprint 6.3: Experiment Framework

**Backend Tasks**:
- [x]Create experiments API
- [x]Implement result collection
- [x]Create experiment dashboard

### Phase 6 Deliverables

| Deliverable | Type |
|-------------|------|
| `security_incidents` table | Database |
| `/metrics` endpoint | API |
| Experiments API | API |
| MTTD/MTTR tracking | Feature |

---

## Implementation Timeline (Suggested)

```
           Month 1        Month 2        Month 3        Month 4
Week:    1  2  3  4    1  2  3  4    1  2  3  4    1  2  3  4
────────────────────────────────────────────────────────────────
Phase 1  ▓▓▓▓▓▓▓▓▓▓▓▓
Phase 2              ▓▓▓▓▓▓▓▓▓▓▓▓
Phase 3  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░  (parallel with 1-2)
Phase 4                            ▓▓▓▓▓▓▓▓
Phase 5                                      ▓▓▓▓
Phase 6                                          ▓▓▓▓ (optional)
```

**Legend**: ▓ = Primary focus, ░ = Parallel work

---

## Risk Mitigation

### Technical Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Nginx integration complexity | High | Use existing proxy patterns from v1 |
| Database detection accuracy | Medium | Allow manual additions |
| TLS inspection limitations | Medium | Document unsupported cases |
| Performance with many endpoints | Medium | Implement pagination early |

### Process Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Scope creep | High | Strict epic boundaries |
| Breaking v1 features | High | Comprehensive test suite |
| UX inconsistency | Medium | Design system first |

---

## Success Criteria per Phase

### Phase 1 Complete When:
- [x]All container ports visible in Exposure Map
- [x]TLS posture score calculated
- [x]Rate limiting configurable via UI
- [x]Certificate expiry alerts working

### Phase 2 Complete When:
- [x]All databases auto-discovered
- [x]Database posture checks passing
- [x]Backup policy compliance tracked
- [x]Ownership assigned to all databases

### Phase 3 Complete When:
- [x]All pages follow Golden Page pattern
- [x]Keyboard navigation works
- [x]Command palette functional
- [x]WCAG 2.1 AA compliant

### Phase 4 Complete When:
- [x]Secrets tracked with rotation reminders
- [x]Code secret detection working
- [x]Jobs visible with execution history
- [x]Retry storm detection alerting

### Phase 5 Complete When:
- [x]Dependencies mapped to services
- [x]Dependency graph renders
- [x]Impact analysis available

### Phase 6 Complete When:
- [x]Prometheus metrics exported
- [x]MTTD/MTTR calculated
- [x]Experiments can be created

---

## Migration Strategy

### Database Migrations

Each phase will add migrations sequentially:

```
migrations/
├── 021_exposed_endpoints.sql      (Phase 1)
├── 022_rate_limit_profiles.sql    (Phase 1)
├── 023_tls_alert_config.sql       (Phase 1)
├── 024_database_inventory.sql     (Phase 2)
├── 025_database_backups.sql       (Phase 2)
├── 026_backup_policies.sql        (Phase 2)
├── 027_secret_inventory.sql       (Phase 4)
├── 028_background_jobs.sql        (Phase 4)
├── 029_external_dependencies.sql  (Phase 5)
├── 030_security_incidents.sql     (Phase 6)
```

### API Versioning

All new endpoints under existing `/api/v1/` namespace. No breaking changes.

### Feature Flags

Optional feature flags for phased rollout:

```go
FeatureFlags{
    ExposureGovernance: true,   // Phase 1
    DatabaseGovernance: true,   // Phase 2
    NewNavigation:      true,   // Phase 3
    SecretsHygiene:     false,  // Phase 4
    JobsMonitoring:     false,  // Phase 4
    DependencyMapping:  false,  // Phase 5
    ResearchMetrics:    false,  // Phase 6
}
```

---

## Testing Strategy

### Unit Tests

Each epic should have:
- Service layer tests
- Handler tests with mocks
- Database query tests

### Integration Tests

- API endpoint tests
- Database migration tests
- Nginx config generation tests

### E2E Tests

- Critical user flows
- Cross-entity navigation
- Alert delivery

### Performance Tests

- Endpoint discovery at scale (1000+ ports)
- Database scanning performance
- Dashboard load times

---

## Documentation Updates

Each phase should update:

1. **V2-EPICS.md** — Mark features as complete
2. **API-REFERENCE.md** — Add new endpoints
3. **User guides** — Feature-specific documentation
4. **CHANGELOG.md** — Release notes

---

## V2 Complete When

All HIGH priority epics complete:
- [x]Epic 13: Traffic & Exposure Governance ✅
- [x]Epic 14: Database & Data Governance ✅
- [x]Epic 19: UX & Navigation System ✅

Plus at least one Medium priority:
- [x]Epic 15: Backup & Recovery Visibility
- [x]Epic 16: Secrets Hygiene
- [x]Epic 17: Background Jobs & Workers

**Target**: v2.0 release after Phase 1-4 complete
