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
- [ ] Create migration for `exposed_endpoints` table
- [ ] Implement endpoint scanner (port detection)
- [ ] Create exposure discovery service
- [ ] Add scheduled scan job (every 5 minutes)
- [ ] Implement `GET /api/v1/exposure/endpoints`
- [ ] Implement `POST /api/v1/exposure/scan`

**Frontend Tasks**:
- [ ] Create ExposureList page
- [ ] Create EndpointCard component
- [ ] Add exposure count to dashboard

**Acceptance Criteria**:
- [ ] All container ports are discovered
- [ ] Public vs internal endpoints distinguished
- [ ] Manual scan trigger works

### Sprint 1.2: TLS Visibility

**Objective**: Track TLS status and certificate expiry

**Backend Tasks**:
- [ ] Add TLS fields to `exposed_endpoints`
- [ ] Implement certificate inspection (via Nginx)
- [ ] Create `tls_alert_config` table
- [ ] Implement certificate expiry alerting
- [ ] Implement `GET /api/v1/tls/posture`

**Frontend Tasks**:
- [ ] Add TLS status badge to EndpointCard
- [ ] Create TLS Posture dashboard widget
- [ ] Create certificate expiry alert UI

**Acceptance Criteria**:
- [ ] TLS status shown for all endpoints
- [ ] Cert expiry alerts at 30/7 days
- [ ] TLS posture score calculated

### Sprint 1.3: Rate Limiting

**Objective**: Configure and assign rate limiting profiles

**Backend Tasks**:
- [ ] Create `rate_limit_profiles` table
- [ ] Create `rate_limit_assignments` table
- [ ] Implement rate limit CRUD API
- [ ] Generate Nginx rate limit config
- [ ] Reload Nginx on config change

**Frontend Tasks**:
- [ ] Create RateLimitProfiles page
- [ ] Create profile creation form
- [ ] Add assignment UI to endpoint detail

**Acceptance Criteria**:
- [ ] Rate limit profiles can be created
- [ ] Profiles can be assigned to endpoints
- [ ] Nginx enforces rate limits

### Sprint 1.4: Exposure Map

**Objective**: Visual representation of exposure

**Backend Tasks**:
- [ ] Implement `GET /api/v1/exposure/map` (graph data)
- [ ] Add service linkage to endpoints

**Frontend Tasks**:
- [ ] Create ExposureMap visualization
- [ ] Color-code by risk level
- [ ] Add click-through to endpoint details

**Acceptance Criteria**:
- [ ] Visual map shows all endpoints
- [ ] Risk levels clearly indicated
- [ ] Navigation to details works

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
- [ ] Create migration for `database_inventory` table
- [ ] Implement database detector (port-based)
- [ ] Implement image-based detection
- [ ] Create scheduled discovery job
- [ ] Implement `GET /api/v1/databases`
- [ ] Implement `POST /api/v1/databases/scan`

**Frontend Tasks**:
- [ ] Create DatabaseList page
- [ ] Create DatabaseCard component
- [ ] Add database count to dashboard

**Acceptance Criteria**:
- [ ] PostgreSQL, MySQL, Redis, MongoDB detected
- [ ] Container linkage established
- [ ] Manual scan works

### Sprint 2.2: Database Security Posture

**Objective**: Assess database security configuration

**Backend Tasks**:
- [ ] Implement posture check engine
- [ ] Check: public exposure
- [ ] Check: TLS enabled
- [ ] Check: authentication configured
- [ ] Implement `GET /api/v1/databases/:id/posture`

**Frontend Tasks**:
- [ ] Create posture checklist UI
- [ ] Add posture score to DatabaseCard
- [ ] Create remediation suggestions

**Acceptance Criteria**:
- [ ] All posture checks run
- [ ] Remediation guidance shown
- [ ] Score reflects configuration

### Sprint 2.3: Backup Visibility

**Objective**: Track database backups

**Backend Tasks**:
- [ ] Create `database_backups` table
- [ ] Create `backup_policies` table
- [ ] Create `backup_policy_compliance` table
- [ ] Implement backup status API
- [ ] Implement policy compliance check

**Frontend Tasks**:
- [ ] Add backup status to DatabaseCard
- [ ] Create BackupPolicies page
- [ ] Create compliance dashboard

**Acceptance Criteria**:
- [ ] Backup history visible
- [ ] Policy violations highlighted
- [ ] Compliance score calculated

### Sprint 2.4: Ownership Integration

**Objective**: Assign database ownership

**Backend Tasks**:
- [ ] Add `owner_team_id` to `database_inventory`
- [ ] Implement `PUT /api/v1/databases/:id/owner`
- [ ] Add ownership to posture checks

**Frontend Tasks**:
- [ ] Add ownership selector to database detail
- [ ] Filter databases by team
- [ ] Show ownership in lists

**Acceptance Criteria**:
- [ ] Ownership can be assigned
- [ ] Ownership affects posture score
- [ ] Team filtering works

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
- [ ] Refactor sidebar to layer-based nav
- [ ] Implement Build / Deploy / Run / Govern / Data sections
- [ ] Update routing structure
- [ ] Add breadcrumbs to all pages
- [ ] Implement keyboard shortcuts (g h, g b, etc.)

**Acceptance Criteria**:
- [ ] All pages accessible via new nav
- [ ] Keyboard navigation works
- [ ] Breadcrumbs show context

### Sprint 3.2: Golden Page Pattern

**Objective**: Standardize entity pages

**Tasks**:
- [ ] Create GoldenPage component
- [ ] Create PageHeader component
- [ ] Create TabNavigation component
- [ ] Refactor Container detail page
- [ ] Refactor Deployment detail page
- [ ] Refactor Vulnerability detail page

**Acceptance Criteria**:
- [ ] Consistent layout across entity pages
- [ ] Tabs work correctly
- [ ] Actions are accessible

### Sprint 3.3: Design System Polish

**Objective**: Unified component library

**Tasks**:
- [ ] Audit existing components
- [ ] Create StatusBadge variants
- [ ] Create ScoreGauge component
- [ ] Create DataTable with sorting/filtering
- [ ] Create EmptyState component
- [ ] Document in Storybook

**Acceptance Criteria**:
- [ ] All components documented
- [ ] Consistent styling
- [ ] Reusable across pages

### Sprint 3.4: Command Palette & Search

**Objective**: Quick navigation and search

**Tasks**:
- [ ] Implement CommandPalette (Cmd+K)
- [ ] Add global search endpoint
- [ ] Implement search result ranking
- [ ] Add recent items
- [ ] Add quick actions

**Acceptance Criteria**:
- [ ] Cmd+K opens palette
- [ ] Search finds entities
- [ ] Navigation is instant

### Sprint 3.5: Accessibility

**Objective**: WCAG 2.1 AA compliance

**Tasks**:
- [ ] Audit color contrast
- [ ] Add focus indicators
- [ ] Add ARIA labels
- [ ] Test with screen reader
- [ ] Add reduced motion support

**Acceptance Criteria**:
- [ ] Passes automated a11y tests
- [ ] Keyboard-only navigation works
- [ ] Screen reader compatible

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
- [ ] Create `secret_inventory` table
- [ ] Implement secret detector (env vars)
- [ ] Implement age tracking
- [ ] Implement rotation reminders

**Frontend Tasks**:
- [ ] Create Secrets page
- [ ] Create SecretCard component
- [ ] Add rotation alerts

### Sprint 4.2: Secret Detection in Code

**Objective**: Find exposed secrets

**Backend Tasks**:
- [ ] Implement secret patterns (regex)
- [ ] Integrate with code quality scanning
- [ ] Create exposure alerts

**Frontend Tasks**:
- [ ] Show exposed secrets prominently
- [ ] Link to code location
- [ ] Add to security score

### Sprint 4.3: Job Discovery

**Objective**: Track background jobs

**Backend Tasks**:
- [ ] Create `background_jobs` table
- [ ] Create `job_executions` table
- [ ] Implement job detector
- [ ] Track execution history

**Frontend Tasks**:
- [ ] Create Jobs page
- [ ] Create JobCard component
- [ ] Show execution history

### Sprint 4.4: Job Health Monitoring

**Objective**: Alert on job failures

**Backend Tasks**:
- [ ] Implement retry storm detection
- [ ] Create failure alerts
- [ ] Implement manual trigger API

**Frontend Tasks**:
- [ ] Show job health status
- [ ] Create failure timeline
- [ ] Add manual trigger button

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
- [ ] Create `external_dependencies` table
- [ ] Create `service_dependencies` table
- [ ] Implement dependency CRUD API

**Frontend Tasks**:
- [ ] Create Dependencies page
- [ ] Create dependency form
- [ ] Show dependency list

### Sprint 5.2: Dependency Graph

**Backend Tasks**:
- [ ] Implement graph data endpoint
- [ ] Add health checking (status pages)

**Frontend Tasks**:
- [ ] Create dependency graph visualization
- [ ] Show health status
- [ ] Click-through to details

### Sprint 5.3: Impact Analysis

**Backend Tasks**:
- [ ] Implement impact analysis endpoint
- [ ] Calculate blast radius

**Frontend Tasks**:
- [ ] Show affected services
- [ ] Create impact report

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
- [ ] Create `/metrics` endpoint
- [ ] Export vulnerability counts
- [ ] Export policy metrics
- [ ] Export maturity scores

### Sprint 6.2: Incident Tracking

**Backend Tasks**:
- [ ] Create `security_incidents` table
- [ ] Implement incident lifecycle
- [ ] Calculate MTTD/MTTR

### Sprint 6.3: Experiment Framework

**Backend Tasks**:
- [ ] Create experiments API
- [ ] Implement result collection
- [ ] Create experiment dashboard

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
- [ ] All container ports visible in Exposure Map
- [ ] TLS posture score calculated
- [ ] Rate limiting configurable via UI
- [ ] Certificate expiry alerts working

### Phase 2 Complete When:
- [ ] All databases auto-discovered
- [ ] Database posture checks passing
- [ ] Backup policy compliance tracked
- [ ] Ownership assigned to all databases

### Phase 3 Complete When:
- [ ] All pages follow Golden Page pattern
- [ ] Keyboard navigation works
- [ ] Command palette functional
- [ ] WCAG 2.1 AA compliant

### Phase 4 Complete When:
- [ ] Secrets tracked with rotation reminders
- [ ] Code secret detection working
- [ ] Jobs visible with execution history
- [ ] Retry storm detection alerting

### Phase 5 Complete When:
- [ ] Dependencies mapped to services
- [ ] Dependency graph renders
- [ ] Impact analysis available

### Phase 6 Complete When:
- [ ] Prometheus metrics exported
- [ ] MTTD/MTTR calculated
- [ ] Experiments can be created

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
- [ ] Epic 13: Traffic & Exposure Governance ✅
- [ ] Epic 14: Database & Data Governance ✅
- [ ] Epic 19: UX & Navigation System ✅

Plus at least one Medium priority:
- [ ] Epic 15: Backup & Recovery Visibility
- [ ] Epic 16: Secrets Hygiene
- [ ] Epic 17: Background Jobs & Workers

**Target**: v2.0 release after Phase 1-4 complete
