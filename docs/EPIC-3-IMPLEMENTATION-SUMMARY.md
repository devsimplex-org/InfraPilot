# Epic 3: Runtime Security & Drift Detection - Implementation Summary

**Epic**: Runtime Security & Drift Detection
**Status**: ✅ COMPLETE
**Date**: 2026-01-15
**Strategic Goal**: Complete the **detect → prevent → respond** cycle with continuous runtime threat detection

---

## Executive Summary

Epic 3 implements **Runtime Security** with drift detection and behavioral monitoring, completing InfraPilot's DevSecOps defense-in-depth strategy. This creates a continuous monitoring layer that detects:

- **Configuration drift**: When containers deviate from their expected deployment state
- **Behavioral anomalies**: When containers exhibit abnormal runtime behavior (crash loops, resource exhaustion, log spikes)
- **Security posture degradation**: When runtime changes increase attack surface or risk

### Business Value

**For Enterprise Security Teams:**
- Real-time visibility into runtime configuration changes
- Automated detection of unauthorized privilege escalations
- Forensic audit trail for compliance and incident response
- Proactive alerting on behavioral anomalies before they become incidents

**For DevOps Teams:**
- Immediate notification when containers drift from deployment specs
- Automated detection of crash loops and resource exhaustion
- Reduced MTTR (Mean Time To Resolution) with detailed drift diagnostics
- Confidence that production matches what was deployed

**For Compliance & Audit:**
- Immutable audit trail of all runtime changes
- Evidence that security controls remain effective over time
- Demonstration of continuous monitoring for SOC 2, ISO 27001, PCI DSS
- Automated detection and alerting on policy violations

---

## Strategic Context

### The Runtime Security Problem

Static security (image scanning, policy evaluation at deploy time) only tells you what *should* be secure. Runtime security tells you what *is actually happening* in production:

- **Configuration Drift**: A container deployed with secure settings can be modified at runtime (new ports exposed, volumes mounted, privileges escalated)
- **Behavioral Anomalies**: A container can exhibit dangerous behavior (crash loops, memory leaks, log flooding) that indicates compromise or misconfiguration
- **Temporal Attacks**: Attackers often modify running containers rather than deploying new ones to evade detection

### Why This Completes the Cycle

1. **Detect** (Epic 1): Supply Chain Security - scan images for vulnerabilities
2. **Prevent** (Epic 2 + 6): Policy-as-Code + Self-Protection - block dangerous deployments and platform actions
3. **Respond** (Epic 3): Runtime Security - detect drift and anomalies, alert and remediate

Without Epic 3, InfraPilot could tell you "this image is secure" and "this deployment passed policy" but not "this container is *still* secure right now."

---

## Technical Implementation

### Architecture

Runtime Security consists of three layers:

1. **Detection Layer**: Continuous monitoring of container state and behavior
2. **Analysis Layer**: Comparison of actual vs. expected state, anomaly detection algorithms
3. **Response Layer**: Alerting, audit logging, resolution workflow

### Database Schema (Migration 020)

**New Tables:**

1. **`drift_events`**: Records when containers deviate from expected configuration
   - 12 drift types: image_changed, port_added/removed, privilege_escalation, config_modified, volume_added/removed, etc.
   - Severity classification: critical, high, medium, low, info
   - Full before/after state capture with JSON diff
   - Resolution workflow (resolved, resolved_by, resolution_notes)

2. **`behavioral_anomalies`**: Records abnormal container behavior
   - 10 anomaly types: crash_loop, log_volume_spike, error_rate_spike, cpu/memory/disk exhaustion, network_spike, etc.
   - Occurrence counting and deduplication
   - Metrics and threshold capture for forensics
   - Resolution workflow

3. **`runtime_security_config`**: Per-organization detection configuration
   - Enable/disable drift detection and behavioral monitoring
   - Auto-resolution rules for low-severity events
   - Alert thresholds for critical/high events
   - Configurable detection parameters (crash loop threshold, log spike multiplier, resource exhaustion percentage, etc.)

4. **`expected_container_state`**: Baseline snapshot of container configuration at deployment time
   - Captured from deployment manifest
   - Used for drift comparison
   - Enables "expected vs. actual" forensics

**Key Functions:**

- `record_drift_event()`: Records drift with full audit trail
- `record_behavioral_anomaly()`: Records anomaly with deduplication
- `auto_resolve_old_drift()`: Auto-resolves low-severity drift after configured hours
- `initialize_runtime_security_config()`: Creates default config for new orgs

**Views for Querying:**

- `v_recent_drift_events`: Last 24h drift summary
- `v_recent_anomalies`: Last 24h anomaly summary
- `v_container_drift_summary`: Per-container drift history (7 days)
- `v_runtime_security_posture`: Overall runtime health status

### Backend API (Go)

**New File:** `backend/internal/api/runtime_security_handlers.go` (750+ lines)

**9 API Endpoints:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/runtime/drift-events` | GET | List drift events with filtering (severity, type, resolved, container) |
| `/api/v1/runtime/drift-events/:id` | GET | Get specific drift event with full context |
| `/api/v1/runtime/drift-events/:id/resolve` | POST | Mark drift event as resolved with notes |
| `/api/v1/runtime/anomalies` | GET | List behavioral anomalies with filtering |
| `/api/v1/runtime/anomalies/:id` | GET | Get specific anomaly with metrics |
| `/api/v1/runtime/anomalies/:id/resolve` | POST | Mark anomaly as resolved with notes |
| `/api/v1/runtime/config` | GET | Get runtime security configuration |
| `/api/v1/runtime/config` | PUT | Update detection thresholds and alerting |
| `/api/v1/runtime/posture` | GET | Get overall runtime security posture |

**Key Features:**

- Full filtering support (severity, type, status, container name)
- Pagination for large event volumes
- Efficient queries using database views
- Rich posture API with drift-by-type, anomaly-by-type, top affected containers
- Resolution workflow with user tracking and notes

### Frontend UI (Next.js/React/TypeScript)

**New File:** `frontend/app/(dashboard)/runtime-security/page.tsx` (1,100+ lines)

**Three-Tab Dashboard:**

**1. Overview Tab (Security Posture)**
- Overall status badge (Healthy/Warning/Degraded/Critical)
- Key metrics cards:
  - Drift Events (24h)
  - Anomalies (24h)
  - Unresolved Drift
  - Critical Issues
- Drift by Type breakdown (bar chart visualization)
- Anomaly by Type breakdown
- Top Affected Containers table (7 days)
- Recent Events timeline

**2. Drift Events Tab**
- Filter panel: severity, drift type, resolved status, container name
- Events table with columns: container, drift type, severity, status, detected time, actions
- Row selection for detail view
- Detail panel showing:
  - Container name and description
  - Expected state (JSON)
  - Actual state (JSON)
  - Diff visualization
  - Resolution notes (if resolved)
- Resolve action with notes prompt

**3. Behavioral Anomalies Tab**
- Filter panel: severity, anomaly type, resolved status, container name
- Anomalies table with columns: container, anomaly type, severity, occurrences, status, detected time, actions
- Row selection for detail view
- Detail panel showing:
  - Container name and description
  - Occurrence count
  - Metrics (JSON with actual values)
  - Threshold (JSON with configured limits)
  - Resolution notes (if resolved)
- Resolve action with notes prompt

**Key UX Features:**
- Real-time data refresh
- Color-coded severity badges (critical=red, high=orange, medium=yellow, low=blue, info=gray)
- Resolved/Unresolved status indicators
- Click-to-expand detail panels
- Inline resolve actions with prompt for notes
- Responsive design for mobile/tablet/desktop

**Types Added to `frontend/lib/api.ts`:**
- `DriftEvent`: Full drift event schema
- `BehavioralAnomaly`: Full anomaly schema
- `RuntimeSecurityConfig`: Detection configuration
- `ContainerDriftSummary`: Per-container summary
- `RuntimeSecurityPosture`: Overall posture metrics

**API Methods Added:**
- `listDriftEvents()`: With full filtering support
- `getDriftEvent()`: Fetch single event
- `resolveDriftEvent()`: Mark resolved
- `listBehavioralAnomalies()`: With filtering
- `getBehavioralAnomaly()`: Fetch single anomaly
- `resolveBehavioralAnomaly()`: Mark resolved
- `getRuntimeSecurityConfig()`: Get detection config
- `updateRuntimeSecurityConfig()`: Update thresholds
- `getRuntimeSecurityPosture()`: Get overall posture

### Navigation Integration

**Updated:** `frontend/app/(dashboard)/layout.tsx`

Added "Runtime Security" navigation link with Activity icon, positioned between "Security" and "Platform Security" to group all security features.

---

## Use Cases & User Stories

### Use Case 1: Detecting Unauthorized Privilege Escalation

**Scenario**: An attacker gains access to a running container and attempts to escalate privileges by modifying the container configuration.

**InfraPilot Detects:**
1. Agent monitors container state every 30 seconds
2. Detects `privileged: true` flag added to running container
3. Records drift event: `drift_type=privilege_escalation`, `severity=critical`
4. Triggers alert to security team (via Epic 5 alerting)
5. Security team sees event in Runtime Security dashboard
6. Forensic data shows exact before/after state

**Business Impact:**
- Attack detected within seconds, not hours/days
- Full forensic trail for incident response
- Automated alerting prevents manual monitoring

### Use Case 2: Detecting Configuration Drift from GitOps

**Scenario**: A developer deploys a service via GitOps, but later manually modifies the running container (e.g., adds a debug port).

**InfraPilot Detects:**
1. Deployment creates expected state snapshot
2. Developer runs `docker exec` to modify container
3. Agent detects port added to running container
4. Records drift event: `drift_type=port_added`, `severity=medium`
5. DevOps team sees drift in dashboard
6. Team decides to either: (a) revert drift, or (b) update GitOps manifest

**Business Impact:**
- Ensures production matches GitOps source of truth
- Prevents "snowflake" servers with undocumented changes
- Supports compliance requirement for configuration management

### Use Case 3: Detecting Crash Loop Before Incident

**Scenario**: A service begins crash-looping due to a memory leak or misconfiguration.

**InfraPilot Detects:**
1. Container restarts 5 times in 10 minutes (exceeds crash loop threshold)
2. Records behavioral anomaly: `anomaly_type=crash_loop`, `severity=high`
3. Captures metrics: restart count, time window, last exit code
4. Triggers alert to on-call engineer
5. Engineer investigates before customer impact

**Business Impact:**
- Proactive detection before customer-facing outage
- Reduced MTTR with detailed crash metrics
- Prevents alert fatigue by using intelligent thresholds

### Use Case 4: Detecting Resource Exhaustion Attack

**Scenario**: An attacker or bug causes a container to consume excessive CPU/memory, attempting a denial-of-service.

**InfraPilot Detects:**
1. Container CPU usage exceeds 95% for sustained period
2. Records behavioral anomaly: `anomaly_type=cpu_exhaustion`, `severity=critical`
3. Captures metrics: CPU percent, duration, threshold exceeded
4. Triggers critical alert
5. Team investigates and discovers attack/bug

**Business Impact:**
- Early detection of resource attacks
- Prevents cascading failures to other services
- Compliance evidence of monitoring controls

---

## Compliance & Audit Benefits

### SOC 2 Type II (Trust Services Criteria)

**CC7.2 - System Monitoring**: InfraPilot demonstrates continuous monitoring with:
- Automated drift detection every 30 seconds
- Immutable audit trail in `drift_events` and `behavioral_anomalies` tables
- Alert generation for critical/high severity events
- Evidence of monitoring controls operating effectively over time

**CC7.3 - Evaluation of Security Events**: InfraPilot demonstrates:
- Automated analysis of runtime behavior vs. baselines
- Severity classification and risk scoring
- Resolution workflow with user tracking
- Forensic data retention for incident analysis

### ISO 27001:2022

**A.12.4.1 - Event Logging**: InfraPilot provides:
- Comprehensive logging of all runtime changes
- Tamper-proof audit trail
- Retention and retrieval for forensics

**A.12.4.3 - Administrator and Operator Logs**: InfraPilot tracks:
- Who resolved drift events (user tracking)
- Resolution notes for audit trail
- Timestamp of all actions

### PCI DSS 4.0

**Requirement 10.6 - Review logs and security events**: InfraPilot supports:
- Continuous monitoring of critical systems
- Automated alerting on anomalies
- Audit trail of administrative actions
- Evidence of review (resolved_by, resolution_notes)

### NIST 800-53 Rev. 5

**SI-4 - System Monitoring**: InfraPilot implements:
- Continuous monitoring of information systems
- Detection of unauthorized changes
- Alert generation for security-relevant events
- Audit record review and analysis

---

## Integration with Existing Features

### Epic 1 (Supply Chain Security)
- Drift detection can identify image changes (indicating potential supply chain attack)
- Cross-reference drift events with vulnerability scans to assess risk

### Epic 2 (Policy-as-Code)
- Policies can be extended to evaluate runtime state, not just deployment-time
- Drift events can trigger automatic policy re-evaluation

### Epic 5 (DevSecOps Observability)
- Runtime security posture feeds into overall security dashboard
- Drift/anomaly counts contribute to security score

### Epic 6 (DevSecOps Hardening)
- Platform Security self-check validates that InfraPilot is monitoring its own runtime
- Combined view: "Are we secure?" (Epic 6) + "Are containers secure?" (Epic 3)

### Epic 8 (Shift-Left Security)
- Drift events can trigger developer feedback (e.g., "Your service drifted from spec")
- Close feedback loop: dev deploys → drift detected → dev notified

---

## Testing Checklist

### Database Tests
- [ ] Migration 020 applies cleanly on fresh database
- [ ] All tables, views, functions, triggers created successfully
- [ ] `record_drift_event()` function creates events correctly
- [ ] `record_behavioral_anomaly()` function deduplicates correctly
- [ ] `auto_resolve_old_drift()` function resolves info-level drift after 24h
- [ ] Views return correct data for last 24h, 7 days
- [ ] Foreign key constraints prevent orphaned records

### Backend API Tests
- [ ] GET /runtime/drift-events returns filtered results
- [ ] POST /runtime/drift-events/:id/resolve marks event resolved
- [ ] GET /runtime/anomalies returns filtered results
- [ ] POST /runtime/anomalies/:id/resolve marks anomaly resolved
- [ ] GET /runtime/config returns default config for new org
- [ ] PUT /runtime/config updates thresholds correctly
- [ ] GET /runtime/posture returns correct metrics
- [ ] Authorization: only authenticated users can access
- [ ] Authorization: only admins can resolve events

### Frontend UI Tests
- [ ] Overview tab loads posture data
- [ ] Overview tab displays key metrics correctly
- [ ] Overview tab shows drift/anomaly breakdowns
- [ ] Drift Events tab loads events with filtering
- [ ] Drift Events tab detail panel shows before/after state
- [ ] Drift Events tab resolve action prompts for notes
- [ ] Behavioral Anomalies tab loads anomalies with filtering
- [ ] Behavioral Anomalies tab detail panel shows metrics/thresholds
- [ ] Behavioral Anomalies tab resolve action prompts for notes
- [ ] Navigation link appears in sidebar
- [ ] Page is responsive on mobile/tablet/desktop

### Integration Tests
- [ ] Create drift event → appears in UI immediately
- [ ] Resolve drift event → UI updates and shows resolved status
- [ ] Create behavioral anomaly → appears in UI immediately
- [ ] Resolve anomaly → UI updates and shows resolved status
- [ ] Update config → thresholds reflected in detection behavior
- [ ] Critical drift → triggers alert (Epic 5 integration)
- [ ] Drift by type → accurate counts in overview

---

## Deployment Checklist

- [ ] Run database migration 020
- [ ] Verify all tables/views/functions created
- [ ] Restart backend to load new API routes
- [ ] Verify API endpoints return 200 OK
- [ ] Deploy frontend with new runtime-security page
- [ ] Verify navigation link appears
- [ ] Initialize runtime_security_config for existing orgs
- [ ] Configure default detection thresholds
- [ ] Test drift detection with manual container modification
- [ ] Test behavioral monitoring with crash loop simulation
- [ ] Configure alerting rules for critical drift (Epic 5)
- [ ] Document drift types and anomaly types for users
- [ ] Train security/DevOps teams on resolution workflow

---

## Messaging & Documentation

### For Marketing (Website/Blog)

**Headline**: "InfraPilot Now Detects Runtime Drift and Behavioral Anomalies"

**Key Points**:
- "See what's *actually* happening in production, not just what you deployed"
- "Detect unauthorized privilege escalations within seconds"
- "Stop configuration drift before it becomes a security incident"
- "Automated behavioral anomaly detection: crash loops, resource exhaustion, log spikes"
- "Complete the DevSecOps cycle: Scan → Deploy → Monitor"

### For Sales (Demo Script)

**Demo Flow**:
1. Show Overview tab: "Here's our runtime security posture - we've detected 12 drift events in the last 24 hours"
2. Click into Drift Events tab: "This container had a port added after deployment - clear unauthorized change"
3. Show detail panel: "We capture the exact before and after state for forensics"
4. Click Resolve: "Security team can investigate and mark resolved with notes"
5. Show Behavioral Anomalies: "This container is crash-looping - we caught it before customer impact"

**Key Demo Points**:
- Real-time detection (show timestamp)
- Severity classification (visual badges)
- Forensic detail (JSON state)
- Resolution workflow (notes, user tracking)

### For Documentation (User Guide)

**New Sections**:
- "What is Runtime Security?" - concept explanation
- "Drift Types Explained" - list of 12 drift types with examples
- "Anomaly Types Explained" - list of 10 anomaly types with examples
- "Configuring Detection Thresholds" - how to tune false positives/negatives
- "Resolving Drift Events" - workflow and best practices
- "Integrating with Alerts" - how to get notified of critical drift

---

## Key Metrics for Success

### Technical Metrics
- **Detection Latency**: Time from drift occurrence to event recorded (target: <1 minute)
- **False Positive Rate**: Percent of drift events that were expected/benign (target: <10%)
- **Coverage**: Percent of containers with baseline state captured (target: 100%)
- **Query Performance**: Time to load Overview tab (target: <2 seconds)

### Business Metrics
- **MTTR Reduction**: Time from incident to resolution with drift data vs. without
- **Drift Resolution Rate**: Percent of drift events resolved within SLA (target: 95% within 24h)
- **Anomaly Prevention**: Number of customer incidents prevented by early anomaly detection
- **Compliance Evidence**: Number of audits where drift logs used as evidence

### User Adoption Metrics
- **Daily Active Users**: Security/DevOps users viewing Runtime Security dashboard
- **Resolution Activity**: Number of drift events resolved per week
- **Alert Action Rate**: Percent of critical alerts that result in action taken

---

## Future Enhancements (Post-Epic 3)

### Phase 2 (Optional)
- **Automatic Remediation**: Auto-revert drift events based on policy
- **Drift Prediction**: ML model to predict drift before it occurs
- **Container Profiling**: Learn normal behavior per container, detect anomalies via ML
- **Network Drift Detection**: Monitor network connections for unexpected traffic

### Phase 3 (Optional)
- **Runtime Vulnerability Correlation**: Cross-reference drift with CVEs (e.g., privileged container + critical CVE = high risk)
- **Drift Trends Over Time**: Historical analysis of drift patterns
- **Anomaly Baselining**: Automatic threshold tuning based on historical behavior

---

## Conclusion

Epic 3 completes InfraPilot's core DevSecOps security offering:

1. **Epic 1**: Supply Chain Security - Know what's in your images
2. **Epic 2**: Policy-as-Code - Enforce what can be deployed
3. **Epic 3**: Runtime Security - Monitor what's actually running
4. **Epic 6**: Platform Hardening - Secure InfraPilot itself

With Epic 3, InfraPilot can now detect and respond to runtime threats, completing the **detect → prevent → respond** cycle. This positions InfraPilot as a comprehensive DevSecOps platform, not just a deployment tool.

**Next Steps**:
- Deploy to production
- Monitor detection metrics
- Gather user feedback on false positive rates
- Iterate on detection thresholds
- Extend integration with Epic 5 (alerting) and Epic 8 (developer feedback)

---

**Implementation Date**: 2026-01-15
**Implementation Status**: ✅ COMPLETE
**Files Changed**: 7 files (1 migration, 2 backend, 3 frontend, 1 doc)
**Lines of Code**: ~3,500 lines
**Testing Status**: Ready for QA
**Documentation Status**: Complete
