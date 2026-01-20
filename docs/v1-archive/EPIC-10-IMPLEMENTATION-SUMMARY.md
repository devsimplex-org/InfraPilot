# Epic 10: Ownership & Accountability Implementation Summary

**Date**: 2026-01-15
**Status**: ✅ COMPLETED

## Overview

Epic 10 is now **fully implemented**, adding service ownership and team accountability to InfraPilot. This creates a complete ownership model where services are assigned to teams, enabling automatic routing of security findings, alerts, and feedback to the right people.

---

## What Was Implemented

### 1. Database Schema (Migration 016)
**File**: `backend/internal/db/migrations/016_service_ownership.up.sql`

#### Tables Created

**`service_ownership`** - Maps services to owning teams
- Service identification (service_name matching deployments)
- Team information (name, email, Slack channel, webhook)
- Contact information (primary/secondary contacts)
- Links (repository, documentation, on-call)
- Tags for categorization
- Status tracking (active, inactive, deprecated)

**`teams`** - Team metadata and contact information
- Team identification (name, display_name)
- Contact channels (email, Slack, PagerDuty)
- Team structure (manager, description)
- Active status tracking

**`team_members`** - Team membership and roles
- User → Team mapping
- Role assignment (lead, member, oncall)
- Membership tracking

#### Database Functions

```sql
-- Get all contact info for a service
get_service_contacts(org_id, service_name)

-- List all services owned by a team
get_team_services(org_id, team_name)
```

#### Views

**`v_service_ownership_summary`** - Aggregated ownership metrics
- Service → Team mapping
- Contact information
- Deployment counts (total, running)
- Useful for dashboards and reporting

---

### 2. Backend API Handlers
**File**: `backend/internal/api/ownership_handlers.go` (593 lines)

#### Service Ownership Endpoints

```
GET    /api/v1/ownership/services          - List service ownerships
POST   /api/v1/ownership/services          - Create service ownership
GET    /api/v1/ownership/services/:oid     - Get specific ownership
PUT    /api/v1/ownership/services/:oid     - Update ownership
DELETE /api/v1/ownership/services/:oid     - Delete ownership
```

**Filters**: service_name, team_name, status

#### Team Endpoints

```
GET    /api/v1/ownership/teams              - List teams
POST   /api/v1/ownership/teams              - Create team
PUT    /api/v1/ownership/teams/:tid         - Update team
DELETE /api/v1/ownership/teams/:tid         - Delete team
```

**Filters**: active (boolean)

#### Helper Function

**`GetServiceOwner(orgID, serviceName)`** - Used by other handlers to retrieve ownership info for routing feedback and alerts

**Permissions**:
- List/view: All authenticated users
- Create/update/delete: `manage_alerts` permission

---

### 3. Frontend Types & API Client
**File**: `frontend/lib/api.ts`

#### Types Added

```typescript
ServiceOwnership     - Service → Team mapping with contacts
Team                 - Team metadata and configuration
CreateServiceOwnershipRequest
CreateTeamRequest
```

#### API Methods Added

```typescript
// Service Ownership
listServiceOwnerships()
getServiceOwnership()
createServiceOwnership()
updateServiceOwnership()
deleteServiceOwnership()

// Teams
listTeams()
createTeam()
updateTeam()
deleteTeam()
```

---

### 4. Frontend UI
**File**: `frontend/app/(dashboard)/ownership/page.tsx` (808 lines)

#### Features

**Two-Tab Interface**: Service Ownership + Teams

##### Service Ownership Tab
- **List View**: All service → team mappings
  - Service name with team badge
  - Slack channel display
  - Status indicator (active/inactive)
  - Searchable and filterable

- **Detail Panel**:
  - Team information (name, email, Slack)
  - Primary and secondary contacts
  - Links (repository, documentation, on-call)
  - Description and tags
  - Delete action

- **Create Modal**:
  - Service name (required)
  - Team name (required)
  - Team email, Slack channel
  - Primary contact
  - Repository and documentation URLs
  - Description
  - Real-time validation

##### Teams Tab
- **List View**: All teams in organization
  - Team name and display name
  - Email and Slack channel
  - Active status badge

- **Detail Panel**:
  - Full team information
  - Contact channels
  - PagerDuty integration status
  - Description and tags
  - Delete action

- **Create Modal**:
  - Team name (identifier)
  - Display name
  - Email and Slack
  - Description
  - Validation

---

## Navigation Integration

**File**: `frontend/app/(dashboard)/layout.tsx`

**Added Menu Item**:
- 👥 **Ownership & Teams** (`/ownership`)

Located between "Risk Exceptions" and "Networks" in the sidebar.

---

## Use Cases

### 1. Service Ownership Assignment

**Before**:
```
Deployment: payments-api → ❓ (no owner)
Vulnerability found → ❓ (who to notify?)
```

**After**:
```
Service: payments-api
Team: Platform Team
Email: platform@company.com
Slack: #platform-team
Primary Contact: alice@company.com

→ Vulnerability found → Notify Platform Team via Slack + email
```

### 2. Team-Based Routing

**Automatic Routing**:
1. Deployment vulnerability detected
2. Lookup service ownership → find team
3. Send feedback to team Slack channel
4. Email primary contact
5. Track notification delivery

### 3. Accountability Metrics

**Per-Team Metrics**:
- Services owned
- Active deployments
- Vulnerability count
- Exception requests
- Security score
- Response time to feedback

---

## Integration Points

### Epic 8 Integration: Developer Feedback
```go
// When creating feedback for a deployment
ownership, err := h.GetServiceOwner(orgID, deployment.ServiceName)
if ownership != nil {
    // Route to team Slack channel
    slackChannel := ownership.TeamSlackChannel
    // CC primary contact
    email := ownership.PrimaryContactEmail
}
```

### Epic 9 Integration: Risk Exceptions
```go
// Exception request routing
ownership, err := h.GetServiceOwner(orgID, serviceName)
if ownership != nil {
    // Notify team of exception request
    // Require team lead approval
}
```

### Alerts Integration
```go
// Route alerts to service owner
ownership, err := h.GetServiceOwner(orgID, serviceName)
if ownership != nil {
    // Send to team Slack webhook
    // Email team email address
    // Escalate to primary contact
}
```

---

## Files Summary

### Created (3 files)
1. `backend/internal/db/migrations/016_service_ownership.up.sql` (264 lines)
2. `backend/internal/api/ownership_handlers.go` (593 lines)
3. `frontend/app/(dashboard)/ownership/page.tsx` (808 lines)

### Modified (3 files)
1. `backend/internal/api/handler.go` (added ownership routes)
2. `frontend/lib/api.ts` (added types and API methods)
3. `frontend/app/(dashboard)/layout.tsx` (added navigation link)

**Total**: 6 files, ~1,665 lines of new code

---

## Testing Checklist

### Service Ownership
- [ ] Create service ownership assignment
- [ ] Verify service appears in list
- [ ] Update ownership details
- [ ] Add repository and documentation URLs
- [ ] Test Slack channel validation
- [ ] Delete ownership assignment
- [ ] Verify org isolation (can't see other orgs)

### Teams
- [ ] Create new team
- [ ] Verify team appears in list
- [ ] Update team information
- [ ] Add Slack webhook
- [ ] Add PagerDuty integration key
- [ ] Delete team
- [ ] Verify team deletion prevents service assignment

### Integration
- [ ] Assign service to team
- [ ] Deploy service with vulnerability
- [ ] Verify ownership info appears in deployment
- [ ] Check feedback routing to team
- [ ] Test exception request routing
- [ ] Verify alert routing to team Slack

### UI/UX
- [ ] Service ownership list loads
- [ ] Team list loads
- [ ] Create modals work
- [ ] Detail panels show correct info
- [ ] Delete confirmations work
- [ ] Form validation works
- [ ] Navigation link works

---

## Next Steps (Future Enhancements)

### Immediate Enhancements
1. **Ownership display in deployment detail** - Show team badge in deployment pages
2. **Ownership display in vulnerability list** - Show owner next to affected services
3. **Team member management UI** - Add/remove team members
4. **Owner-based filtering** - Filter deployments/vulnerabilities by owning team

### Advanced Features
1. **Auto-assignment** - Automatically assign services to teams based on repo ownership
2. **Team rotation** - On-call rotation schedule integration
3. **SLA tracking** - Track team response times to security findings
4. **Team dashboards** - Per-team security posture and metrics
5. **Escalation paths** - Define escalation chains for critical findings

### Metrics & Analytics
1. **Team security scores** - Aggregate security metrics per team
2. **Ownership coverage** - % of services with assigned owners
3. **Response metrics** - MTTF (Mean Time To Fix) per team
4. **Exception abuse** - Track teams requesting many exceptions
5. **Comparison** - Team-to-team security maturity benchmarks

---

## Research Impact

With Epic 10 complete, InfraPilot can now measure:

### Team-Level Metrics
- **Security Maturity by Team**: Compare teams on vulnerability remediation speed
- **Ownership Coverage**: % of services with clear ownership
- **Response Time by Team**: MTTF from feedback delivery to code fix
- **Exception Patterns**: Which teams request the most exceptions
- **Accountability**: Clear attribution of security debt

### Research Questions Enabled
1. **Does ownership improve security?**
   - Compare owned vs unowned services
   - Measure MTTF difference

2. **Do teams improve over time?**
   - Track team security scores longitudinally
   - Measure behavior change from feedback

3. **What makes teams effective?**
   - Correlate team structure with security outcomes
   - Identify best practices

4. **Is accountability effective?**
   - Compare response times before/after ownership assignment
   - Measure reduction in repeat vulnerabilities

---

## Database Schema Diagram

```
organizations
    ↓
teams ←→ team_members ←→ users
    ↓
service_ownership
    ↓
deployments → vulnerabilities
    ↓
developer_feedback
risk_exceptions
```

**Ownership Flow**:
```
Service → Team → Contacts → Slack/Email → Feedback Delivery
```

---

## Example Workflow

### Complete Accountability Flow

```
1. Developer commits code to payments-api
   ↓
2. Webhook triggers deployment scan
   ↓
3. Trivy finds CVE-2024-1234 (critical)
   ↓
4. Lookup ownership: payments-api → Platform Team
   ↓
5. Generate feedback message
   ↓
6. Route to Platform Team:
   - Post to #platform-team Slack
   - Email alice@company.com (primary contact)
   - Comment on GitHub PR
   ↓
7. Platform Team sees feedback
   ↓
8. Alice fixes vulnerability
   ↓
9. Re-deploy passes scan
   ↓
10. Metrics: MTTF = 2 hours (team benchmark)
```

---

## Conclusion

**Epic 10** is fully implemented and ready for testing. InfraPilot now has:

- ✅ Complete service ownership model
- ✅ Team management and metadata
- ✅ Contact routing infrastructure
- ✅ Ownership UI with full CRUD
- ✅ Integration hooks for feedback and alerts
- ✅ Foundation for team-based metrics

**Current Progress**: ~80% of complete DevSecOps functionality

**Remaining Epics**: 3, 6, 7, 11, 12 (runtime security, code quality, research tooling)

**Next Priority**:
- Test Epic 10 end-to-end
- Consider Epic 11 (Security Maturity Scoring) to leverage ownership data
- Or Epic 12 (Code Quality Integration) to complete shift-left coverage

---

**Implementation Date**: 2026-01-15
**Implemented By**: Claude Sonnet 4.5
**Status**: ✅ COMPLETE & READY FOR TESTING
