# InfraPilot Platform-Wide Component Library

**Date**: 2026-01-15
**Scope**: Entire InfraPilot Platform (All Modules)
**Status**: 12/14 Components Complete (86%)

---

## 🎯 Vision

This component library serves **the entire InfraPilot platform** across the **DevSecOps lifecycle**. Every component is designed to be **generic, flexible, and reusable** across all lifecycle stages:

### DevSecOps Lifecycle Navigation

**🟦 Overview** (Executive & Entry Point)
- ✅ Dashboard - "Are we safe?" in 10 seconds
- ✅ Security Posture - Risk overview

**🟨 Build** (Shift Left – Developers)
- ✅ Code Quality - Prevent risk before deployment
- ✅ Developer Feedback - SAST, linting, best practices
- ✅ Policies - Security rules and enforcement

**🟧 Deploy** (Release & Supply Chain)
- ✅ **Deployments** - PRIMARY anchor page
- ✅ Vulnerabilities - CVE tracking
- ✅ SBOMs - Software Bill of Materials
- ✅ Images - Container image scanning

**🟥 Run** (Production Reality)
- ✅ Runtime Security - Drift and anomaly detection
- ✅ Containers - Running container management
- ✅ Logs - Event logs and debugging
- ✅ Alerts - Incident notifications

**🟪 Govern** (Control, Exceptions, Ownership)
- ✅ Risk Exceptions - Managed security exceptions
- ✅ Teams & Ownership - User and role management
- ✅ Security Maturity - Improvement tracking
- ✅ Webhooks - Event notifications

**⚙️ Platform** (Infrastructure & Admin)
- ✅ Platform Security - System hardening
- ✅ Proxies, Networks, Volumes - Infrastructure
- ✅ Health - System status
- ✅ Users & Settings - Administration

### Key Principles
- **InfraPilot is a DevSecOps control plane, not Docker Desktop**
- **Deployments is the anchor concept, not containers**
- **Navigation follows lifecycle: Build → Deploy → Run → Govern → Improve**
- **Governance is first-class, not hidden in Settings**

---

## 📊 Component Usage Across DevSecOps Lifecycle

### 1. Badge Component
**Generic Purpose**: Display categorized information with color-coding

**Use Cases Across Platform**:
- **Vulnerabilities**: Severity badges (Critical, High, Medium, Low)
- **Deployments**: Status badges (Healthy, Warning, Degraded, Critical)
- **Policies**: Compliance status (Passed, Failed, Warning)
- **Webhooks**: Delivery status (Delivered, Failed, Pending)
- **Runtime Security**: Event types (Drift, Anomaly, Config Change)
- **Teams**: User roles (Admin, Developer, Viewer)
- **Audit Logs**: Action types (Create, Update, Delete)
- **Platform**: Environment tags (Production, Staging, Development)

**Badge Variants**:
- `severity` - For risk/impact levels (any module)
- `status` - For health/state (any resource)
- `default` - For generic labels (tags, categories)

---

### 2. Card Component
**Generic Purpose**: Container for related content

**Use Cases Across Platform**:
- **Dashboard**: Metric cards, summary cards
- **Deployments**: Deployment detail cards
- **Vulnerabilities**: CVE information cards
- **Policies**: Policy rule cards
- **Webhooks**: Webhook configuration cards
- **Teams**: User profile cards
- **Settings**: Configuration section cards
- **Audit Logs**: Event detail cards

**Card Features**:
- Header with title + action buttons
- Body with flexible content
- Footer with action buttons
- Variants: default, elevated, bordered

---

### 3. StatCard Component
**Generic Purpose**: Display key metrics prominently

**Use Cases Across Platform**:
- **Dashboard**:
  - Total deployments, total users, total policies
  - System uptime, API response time
- **Deployments**:
  - Active deployments, successful deploys (7d)
  - Failed deployments, avg deploy time
- **Vulnerabilities**:
  - Critical count, resolved (7d), scan coverage
- **Policies**:
  - Total policies, enforcement rate, violations
- **Webhooks**:
  - Total webhooks, delivery rate, failed deliveries
- **Teams**:
  - Total users, active users, pending invites
- **Platform**:
  - CPU usage, memory usage, disk usage
  - Request rate, error rate

**StatCard Features**:
- Large number display (numeric or formatted)
- Trend indicators (up/down/neutral)
- Icons for visual context
- MetricsGrid for responsive layouts

---

### 4. Table Component
**Generic Purpose**: Display tabular data with sorting and selection

**Use Cases Across Platform**:
- **Dashboard**: Recent activity table
- **Deployments**: Deployments list
- **Vulnerabilities**: CVE list
- **Policies**: Policy rules list
- **Runtime Security**: Drift events, anomalies
- **Webhooks**: Webhook events log
- **Teams**: Users and roles table
- **Audit Logs**: Activity log table
- **Settings**: API keys, integrations

**Table Features**:
- Sortable columns
- Row selection
- Custom cell renderers
- Sticky header
- Loading/empty states
- Click handlers

---

### 5. SlideOver Component
**Generic Purpose**: Side panel for detailed views

**Use Cases Across Platform**:
- **Deployments**: Deployment details, logs, configuration
- **Vulnerabilities**: CVE details, affected deployments, remediation
- **Policies**: Policy details, violations, edit policy
- **Runtime Security**: Event details, container state
- **Webhooks**: Webhook configuration, delivery history
- **Teams**: User profile, permissions, activity
- **Audit Logs**: Event details, before/after state
- **Settings**: Edit settings, configure integrations

**SlideOver Features**:
- Sizes: sm, md, lg, xl, full
- Header with close button
- Scrollable body
- Footer with actions

---

### 6. EmptyState Component
**Generic Purpose**: Communicate absence of data

**Use Cases Across Platform**:
- **Dashboard**: No data available, first-time setup
- **Deployments**: No deployments yet, create first deployment
- **Vulnerabilities**: No vulnerabilities found (success state!)
- **Policies**: No policies configured, create first policy
- **Runtime Security**: No events detected
- **Webhooks**: No webhooks configured
- **Teams**: No team members, invite first user
- **Audit Logs**: No activity yet
- **Search Results**: No results found

**EmptyState Features**:
- Icon support
- Title + description
- Action button
- Sizes: sm, md, lg
- Custom icon colors

---

### 7. PageHeader Component
**Generic Purpose**: Standard page header

**Use Cases Across Platform**:
- **Every Page**:
  - Title + description
  - Breadcrumbs for navigation
  - Action buttons (Create, Export, Configure, etc.)

**Examples**:
- Dashboard → "Dashboard" + "Overview of your infrastructure"
- Deployments → "Deployments" + "Manage and monitor deployments" + "New Deployment"
- Policies → "Security Policies" + "Define and enforce policies" + "Create Policy"
- Teams → "Team Members" + "Manage users and permissions" + "Invite User"

---

### 8. Skeleton Component
**Generic Purpose**: Loading placeholders

**Use Cases Across Platform**:
- **All Modules**: Loading states for:
  - Cards (dashboard metrics, details)
  - Tables (data lists)
  - Text (descriptions, metadata)
  - User profiles
  - Lists

**Skeleton Variants**:
- `Skeleton` - Basic shapes (rectangular, circular, text)
- `Skeleton.Text` - Multi-line text
- `Skeleton.Card` - Card loading
- `Skeleton.Table` - Table loading

---

### 9. Spinner Component
**Generic Purpose**: Loading indicators

**Use Cases Across Platform**:
- **All Modules**:
  - Page loading (full page spinner)
  - Button loading (inline spinner)
  - Form submission (overlay spinner)
  - Data fetching (inline with text)
  - Background operations

**Spinner Variants**:
- `Spinner` - Basic spinner with label
- `Spinner.Page` - Full page loading
- `Spinner.Overlay` - Modal overlay

---

### 10. StatusIndicator Component
**Generic Purpose**: Real-time status with pulse

**Use Cases Across Platform**:
- **Dashboard**: Service status, system health
- **Deployments**:
  - Deployment health (healthy, warning, degraded, critical)
  - Container status
  - Replica status
- **Platform**:
  - Database connection status
  - Cache server status
  - Message queue status
  - Worker status
- **Webhooks**: Webhook endpoint status
- **Teams**: User online/offline status
- **Integrations**: Connection status

**StatusIndicator Features**:
- 4 status levels (healthy, warning, degraded, critical)
- Pulse animation for active states
- Sizes: sm, md, lg
- With/without labels

---

### 11. Timeline Component
**Generic Purpose**: Event history and audit trails

**Use Cases Across Platform**:
- **Deployments**: Deployment history (commit → build → scan → deploy)
- **Vulnerabilities**: Vulnerability lifecycle (detected → triaged → fixed → verified)
- **Policies**: Policy changes (created → updated → violations)
- **Runtime Security**: Event sequence (drift detected → investigated → resolved)
- **Webhooks**: Delivery attempts timeline
- **Teams**: User activity history
- **Audit Logs**: Activity timeline (who did what when)
- **Settings**: Configuration change history

**Timeline Features**:
- Icon support with custom colors
- Timestamp display
- Description text
- Additional content (badges, cards)

---

### 12. FilterPanel Component
**Generic Purpose**: Advanced data filtering

**Use Cases Across Platform**:
- **Deployments**: Filter by environment, status, vulnerabilities, namespace
- **Vulnerabilities**: Filter by severity, status, package, CVE ID
- **Policies**: Filter by type, enforcement, compliance
- **Runtime Security**: Filter by drift type, severity, container, resolved
- **Webhooks**: Filter by event type, status, endpoint
- **Teams**: Filter by role, status, permissions
- **Audit Logs**: Filter by user, action, resource, date range

**FilterPanel Features**:
- Checkbox groups (multi-select)
- Radio groups (single-select)
- Search inputs
- Collapsible
- Reset functionality
- Active filter indicators

---

## 🎨 Design Tokens (Platform-Wide)

### Color System

**Severity Colors** (Risk/Impact Levels):
- **Critical** - Red - High-priority security issues, failed deployments, system outages
- **High** - Orange - Important issues, degraded services, policy violations
- **Medium** - Yellow - Moderate concerns, warnings, pending actions
- **Low** - Blue - Informational, minor issues, suggestions
- **Info** - Gray - Neutral information, metadata, system messages

**Status Colors** (Health/State):
- **Healthy** - Green - Services running, tests passing, deployments successful
- **Warning** - Yellow - High resource usage, non-critical alerts
- **Degraded** - Orange - Partial failures, performance issues
- **Critical** - Red - Service down, deployment failed, security breach

**Use Across Modules**:
- Vulnerabilities → Severity colors
- Deployments → Status colors
- Policies → Status colors (passed/failed)
- Runtime Security → Severity colors
- Webhooks → Status colors (delivery status)
- Platform → Status colors (service health)

---

## 📱 Responsive Design (All Modules)

All components are **mobile-first** and responsive:

- **Desktop** (1280px+): Full layout, side-by-side panels
- **Tablet** (768px - 1279px): Adapted layout, stacked components
- **Mobile** (< 768px): Single column, collapsible navigation

**Examples**:
- **MetricsGrid**: 4 columns → 2 columns → 1 column
- **Table**: Horizontal scroll on mobile
- **SlideOver**: Full screen on mobile, side panel on desktop
- **FilterPanel**: Collapsible on mobile

---

## 🔧 Component Patterns (Platform-Wide)

### Data Display Pattern
```tsx
// Works for ANY data type
<PageHeader
  title="Resource Name"
  description="Description of resource"
  action={<button>Create New</button>}
/>

<MetricsGrid columns={4}>
  <StatCard label="Total" value={123} trend="up" />
  <StatCard label="Active" value={98} />
  <StatCard label="Failed" value={5} trend="down" />
  <StatCard label="Rate" value="95%" />
</MetricsGrid>

<Table
  columns={[...]}
  data={[...]}
  onRowClick={(row) => openDetails(row)}
/>
```

### Detail View Pattern
```tsx
// Works for ANY resource type
<SlideOver isOpen={isOpen} onClose={close} size="lg">
  <SlideOver.Header>
    <h2>Resource Details</h2>
  </SlideOver.Header>
  <SlideOver.Body>
    {/* Resource-specific content */}
  </SlideOver.Body>
  <SlideOver.Footer>
    <button>Action 1</button>
    <button>Action 2</button>
  </SlideOver.Footer>
</SlideOver>
```

### Empty State Pattern
```tsx
// Works for ANY empty scenario
<EmptyState
  icon={ResourceIcon}
  title="No resources yet"
  description="Get started by creating your first resource"
  action={<button>Create Resource</button>}
/>
```

---

## 🚀 Lifecycle-Specific Implementation Examples

### 🟦 Overview: Dashboard
```tsx
<PageHeader title="Dashboard" description="Overview of your infrastructure" />

<MetricsGrid columns={4}>
  <StatCard label="Total Deployments" value={156} icon={Package} />
  <StatCard label="Active Users" value={42} icon={Users} />
  <StatCard label="Total Policies" value={23} icon={Shield} />
  <StatCard label="System Uptime" value="99.9%" icon={Activity} />
</MetricsGrid>

<Card>
  <Card.Header>
    <h3>Recent Activity</h3>
  </Card.Header>
  <Card.Body>
    <Timeline>
      <Timeline.Item title="Deployment created" timestamp="2 min ago" />
      <Timeline.Item title="User invited" timestamp="5 min ago" />
      <Timeline.Item title="Policy updated" timestamp="10 min ago" />
    </Timeline>
  </Card.Body>
</Card>
```

### 🟨 Build: Code Quality
```tsx
<PageHeader
  title="Code Quality"
  description="Static analysis and security scanning results"
  breadcrumbs={<Breadcrumb items={['Build', 'Code Quality']} />}
  action={<button>Run Scan</button>}
/>

<MetricsGrid columns={4}>
  <StatCard label="Critical Issues" value={3} icon={XCircle} trend="down" iconColor="text-red-600" />
  <StatCard label="High Severity" value={12} icon={AlertTriangle} iconColor="text-orange-600" />
  <StatCard label="Code Coverage" value="87%" icon={Shield} trend="up" />
  <StatCard label="Last Scan" value="2 min ago" icon={Clock} />
</MetricsGrid>

<FilterPanel
  filters={[
    { id: 'severity', label: 'Severity', type: 'checkbox', options: [...] },
    { id: 'file', label: 'File Path', type: 'search' }
  ]}
/>

<Table
  columns={[
    { key: 'rule', header: 'Rule' },
    { key: 'file', header: 'File' },
    { key: 'severity', header: 'Severity', render: (v) => <SeverityBadge severity={v} /> }
  ]}
  data={findings}
/>
```

### 🟧 Deploy: Deployments (PRIMARY)
```tsx
<PageHeader
  title="Deployments"
  description="Manage and monitor your application deployments"
  action={<button>New Deployment</button>}
/>

<FilterPanel
  filters={[
    { id: 'env', label: 'Environment', type: 'checkbox', options: [...] },
    { id: 'status', label: 'Health Status', type: 'checkbox', options: [...] }
  ]}
/>

<Table
  columns={[
    { key: 'name', header: 'Name' },
    { key: 'environment', header: 'Environment' },
    { key: 'status', header: 'Status', render: (v) => <StatusIndicator status={v} /> }
  ]}
  data={deployments}
  onRowClick={(deployment) => openDeploymentDetails(deployment)}
/>
```

### 🟥 Run: Runtime Security
```tsx
<PageHeader
  title="Runtime Security"
  description="Drift detection and behavioral anomaly monitoring"
  breadcrumbs={<Breadcrumb items={['Run', 'Runtime Security']} />}
  action={<button>Configure Monitoring</button>}
/>

<MetricsGrid columns={4}>
  <StatCard label="Drift Events (24h)" value={5} icon={AlertTriangle} trend="down" />
  <StatCard label="Anomalies (24h)" value={12} icon={Activity} />
  <StatCard label="Unresolved" value={8} icon={XCircle} iconColor="text-red-600" />
  <StatCard label="Monitored Containers" value={156} icon={Package} />
</MetricsGrid>

<FilterPanel
  filters={[
    { id: 'type', label: 'Event Type', type: 'checkbox', options: [...] },
    { id: 'severity', label: 'Severity', type: 'checkbox', options: [...] },
    { id: 'container', label: 'Container Name', type: 'search' }
  ]}
/>

<Table
  columns={[
    { key: 'type', header: 'Event Type' },
    { key: 'container', header: 'Container' },
    { key: 'severity', header: 'Severity', render: (v) => <SeverityBadge severity={v} /> },
    { key: 'detected_at', header: 'Detected', render: (v) => formatTime(v) }
  ]}
  data={events}
  onRowClick={(event) => openEventDetails(event)}
/>
```

### 🟪 Govern: Risk Exceptions
```tsx
<PageHeader
  title="Risk Exceptions"
  description="Manage security exceptions and approvals"
  breadcrumbs={<Breadcrumb items={['Govern', 'Risk Exceptions']} />}
  action={<button>Request Exception</button>}
/>

<MetricsGrid columns={4}>
  <StatCard label="Pending Approval" value={3} icon={Clock} />
  <StatCard label="Approved" value={12} icon={CheckCircle2} iconColor="text-green-600" />
  <StatCard label="Denied" value={2} icon={XCircle} iconColor="text-red-600" />
  <StatCard label="Expired" value={5} icon={AlertTriangle} />
</MetricsGrid>

<Table
  columns={[
    { key: 'cve_id', header: 'CVE ID' },
    { key: 'deployment', header: 'Deployment' },
    { key: 'status', header: 'Status', render: (v) => <Badge variant="status" status={v}>{v}</Badge> },
    { key: 'expires_at', header: 'Expires', render: (v) => formatDate(v) }
  ]}
  data={exceptions}
  onRowClick={(exception) => openExceptionDetails(exception)}
/>
```

### 🟨 Build: Developer Feedback
```tsx
<PageHeader
  title="Developer Feedback"
  description="Security and quality feedback for your team"
  breadcrumbs={<Breadcrumb items={['Build', 'Developer Feedback']} />}
/>

<Card>
  <Card.Header>
    <h3>Recent Feedback</h3>
  </Card.Header>
  <Card.Body>
    <Timeline>
      <Timeline.Item
        icon={CheckCircle2}
        iconColor="text-green-600"
        title="All checks passed"
        description="feat-auth-improvements branch"
        timestamp="2 min ago"
      />
      <Timeline.Item
        icon={AlertTriangle}
        iconColor="text-orange-600"
        title="3 high severity issues found"
        description="main branch - SQL injection risk"
        timestamp="10 min ago"
      />
      <Timeline.Item
        icon={Shield}
        iconColor="text-blue-600"
        title="Security policy updated"
        description="New SAST rules enabled"
        timestamp="1 hour ago"
      />
    </Timeline>
  </Card.Body>
</Card>
```

### ⚙️ Platform: Platform Security
```tsx
<PageHeader
  title="Settings"
  description="Configure your organization"
/>

<Card>
  <Card.Header><h3>General Settings</h3></Card.Header>
  <Card.Body>
    {/* Form fields */}
  </Card.Body>
  <Card.Footer>
    <button>Save Changes</button>
  </Card.Footer>
</Card>

<Card>
  <Card.Header><h3>API Keys</h3></Card.Header>
  <Card.Body>
    <Table
      columns={[...]}
      data={apiKeys}
    />
  </Card.Body>
</Card>
```

---

## ✅ Design Principles (Platform-Wide)

1. **Generic First** - Components work for any data type, not just security data
2. **Composable** - Components combine to create complex UIs
3. **Consistent** - Same patterns across all modules
4. **Accessible** - WCAG AA compliant, keyboard navigation
5. **Responsive** - Mobile-first, works on all devices
6. **Dark Mode** - First-class support everywhere
7. **Type-Safe** - Full TypeScript types
8. **Documented** - Storybook examples for every use case

---

## 📦 Component Library Coverage Across Lifecycle

| Component | Overview | Build | Deploy | Run | Govern | Platform |
|-----------|----------|-------|--------|-----|--------|----------|
| Badge | Risk levels | Quality scores | Status | Severity | Exception status | Health |
| Card | Summary | Code metrics | Deployment info | Events | Policies | Config |
| StatCard | KPIs | Build stats | Deploy metrics | Runtime stats | Maturity | System |
| Table | Activity | Quality issues | Deployments | Events | Exceptions | Resources |
| SlideOver | Details | Issue details | Deploy details | Event details | Exception mgmt | Settings |
| EmptyState | First-time | No issues | No deploys | No events | No exceptions | No config |
| PageHeader | All pages | All pages | All pages | All pages | All pages | All pages |
| Skeleton | Loading | Loading | Loading | Loading | Loading | Loading |
| Spinner | Loading | Loading | Loading | Loading | Loading | Loading |
| StatusIndicator | Health | Build status | Deploy status | Runtime status | Compliance | Service status |
| Timeline | History | Build pipeline | Deploy history | Event sequence | Policy changes | Audit log |
| FilterPanel | Search | Filter issues | Filter deploys | Filter events | Filter exceptions | Filter resources |

**All 12 components work across ALL 6 lifecycle stages!**

### Lifecycle-Specific Examples

**🟦 Overview (Dashboard)**
- StatCard: "Total Deployments", "Critical CVEs", "Policy Compliance %"
- Card: Recent activity, system health summary
- StatusIndicator: Overall system health with pulse
- Timeline: Recent significant events

**🟨 Build (Code Quality)**
- Table: SAST findings, linting issues, test coverage
- Badge: Severity (Critical, High, Medium, Low)
- FilterPanel: Filter by file, severity, rule type
- EmptyState: "No issues found - great work!" (success state)

**🟧 Deploy (PRIMARY: Deployments)**
- Table: **Deployments list** (PRIMARY TABLE)
- StatCard: "Active Deployments", "Success Rate (7d)", "Blocked by Policy"
- SlideOver: Deployment details with logs, config, vulnerabilities
- StatusIndicator: Deployment health (Healthy, Warning, Degraded, Critical)
- Timeline: Deploy pipeline (commit → build → scan → deploy)

**🟥 Run (Runtime Security)**
- Table: Drift events, behavioral anomalies, containers
- FilterPanel: Filter by drift type, severity, container, resolved status
- SlideOver: Event details with before/after state
- Timeline: Event sequence and investigation history
- StatusIndicator: Container status, service health

**🟪 Govern (Risk Exceptions)**
- Table: Exception requests, team members, maturity scores
- Card: Policy rules, exception details
- Badge: Exception status (Approved, Pending, Denied)
- SlideOver: Exception review and approval workflow
- Timeline: Policy change history, exception lifecycle

**⚙️ Platform (Infrastructure)**
- Table: Proxies, networks, volumes, users
- StatusIndicator: Service status (DB, cache, queue, workers)
- Card: System configuration, health metrics
- Timeline: Configuration changes, system events

---

## 🎯 Next Steps: Lifecycle-Based Implementation

### Phase 3: Apply Components Across DevSecOps Lifecycle

**Implementation Order** (follows demo flow for YC/investors):

1. **🟦 Overview: Dashboard** - "Are we safe?" executive view
   - Metrics: Total deployments, critical CVEs, policy compliance
   - Recent activity timeline
   - System health indicators

2. **🟧 Deploy: Deployments** (PRIMARY ANCHOR PAGE)
   - Deployment list with status, environment, vulnerabilities
   - Deployment details in SlideOver
   - Deploy timeline (commit → build → scan → deploy)
   - Filter by environment, status, vulnerabilities

3. **🟧 Deploy: Vulnerabilities** - "We find it"
   - CVE list with severity badges
   - Affected deployments contextual link
   - CVE details in SlideOver
   - Filter by severity, status, package

4. **🟨 Build: Developer Feedback** - "We teach developers"
   - Feedback timeline
   - Code quality issues
   - Policy violations with remediation guidance

5. **🟪 Govern: Risk Exceptions** - "We govern reality"
   - Exception requests table
   - Approval workflow in SlideOver
   - Exception timeline and audit trail

6. **🟥 Run: Runtime Security** - "We detect drift"
   - Drift events and anomalies
   - Container runtime state
   - Event details and resolution

7. **🟨 Build: Code Quality** - Prevent risk before deployment
8. **🟨 Build: Policies** - Security rules and enforcement
9. **🟪 Govern: Security Maturity** - Improvement tracking
10. **🟪 Govern: Teams & Ownership** - User management
11. **⚙️ Platform** - Infrastructure and admin pages

### Navigation Implementation

Follow the enterprise-grade navigation structure:

**Sidebar Sections** (with section labels):
- 🟦 Overview
- 🟨 Build
- 🟧 Deploy
- 🟥 Run
- 🟪 Govern
- ⚙️ Platform

**URL Structure** (shallow, predictable):
```
/                        → Dashboard
/deployments             → Deployments list
/deployments/{id}        → Deployment details
/vulnerabilities         → CVE list
/vulnerabilities/{cve}   → CVE details
/code-quality            → SAST findings
/code-quality/{scan-id}  → Scan details
/exceptions              → Risk exceptions
/exceptions/{id}         → Exception review
```

**Contextual Navigation** (keep sidebar clean):
- From Vulnerability → "View affected deployments"
- From Deployment → "View code quality scan"
- From Exception → "View related policy"
- From Drift Event → "View container details"

This keeps sidebar items minimal while making InfraPilot feel connected.

---

**Last Updated**: 2026-01-15
**Status**: Ready for platform-wide implementation
**Component Library**: 12/14 complete (86%) - All critical components done
