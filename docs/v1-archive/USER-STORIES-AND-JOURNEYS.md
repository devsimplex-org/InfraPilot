# InfraPilot User Stories & Journey Maps

This document provides comprehensive user stories and journey maps for planning and developing InfraPilot as a complete DevSecOps platform.

## Table of Contents

- [User Personas](#user-personas)
- [User Journeys](#user-journeys)
- [Epic-Level User Stories](#epic-level-user-stories)
- [Feature-Level User Stories](#feature-level-user-stories)
- [Gap Analysis](#gap-analysis)

---

## User Personas

### 1. DevOps Engineer (Primary User)

**Name:** Alex
**Role:** DevOps Engineer
**Goals:**
- Deploy applications quickly and safely
- Automate deployment pipelines
- Monitor container health and logs
- Manage reverse proxies and SSL certificates

**Pain Points:**
- SSH-ing into servers for routine tasks
- Manual SSL certificate renewals
- No visibility into deployment security
- Scattered logs across multiple systems

**Technical Level:** High
**Frequency of Use:** Daily

---

### 2. Security Officer

**Name:** Sarah
**Role:** Security Engineer / AppSec
**Goals:**
- Ensure all deployments meet security standards
- Track and remediate vulnerabilities
- Enforce security policies
- Audit security posture over time

**Pain Points:**
- Deployments bypassing security checks
- No visibility into running vulnerabilities
- Manual CVE tracking
- Lack of policy enforcement

**Technical Level:** High
**Frequency of Use:** Daily

---

### 3. Developer

**Name:** Dev
**Role:** Software Developer
**Goals:**
- Deploy code changes to staging/production
- Debug issues using logs
- Understand why deployments are blocked
- Get fast feedback on security issues

**Pain Points:**
- Deployments blocked without explanation
- No visibility into security scan results
- Waiting for security approval
- Context switching between tools

**Technical Level:** Medium-High
**Frequency of Use:** Weekly

---

### 4. Team Lead / Engineering Manager

**Name:** Taylor
**Role:** Engineering Manager
**Goals:**
- Oversee team's deployment health
- Track security maturity improvement
- Manage service ownership
- Prioritize security debt

**Pain Points:**
- No visibility into team's security posture
- Can't compare teams objectively
- No trending data for improvement
- Unclear ownership of services

**Technical Level:** Medium
**Frequency of Use:** Weekly

---

### 5. Platform Administrator

**Name:** Admin
**Role:** Platform/System Administrator
**Goals:**
- Manage InfraPilot installation
- Configure system-wide settings
- Manage users and permissions
- Monitor system health

**Pain Points:**
- Complex initial setup
- Managing multiple agents
- User access management
- System troubleshooting

**Technical Level:** High
**Frequency of Use:** Weekly

---

### 6. Compliance Officer

**Name:** Chris
**Role:** Compliance / GRC Analyst
**Goals:**
- Generate compliance reports
- Audit security controls
- Track policy enforcement
- Document risk acceptance

**Pain Points:**
- Manual evidence collection
- No audit trail
- Can't prove control effectiveness
- Risk exceptions not documented

**Technical Level:** Low-Medium
**Frequency of Use:** Monthly

---

## User Journeys

### Journey 1: First-Time Setup (Platform Administrator)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JOURNEY: Initial InfraPilot Setup                                           │
│ PERSONA: Platform Administrator (Admin)                                     │
│ GOAL: Get InfraPilot running and connected to infrastructure                │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: Installation
─────────────────────
1. Deploy InfraPilot container on Docker host
   └─ docker-compose up -d

2. Access InfraPilot UI at https://infrapilot.example.com
   └─ Redirected to /auth/setup

3. Create initial admin account
   ├─ Set admin email & password
   ├─ Configure MFA (optional but recommended)
   └─ System creates organization

PHASE 2: Agent Configuration
────────────────────────────
4. Navigate to /settings → Agents
   └─ View enrollment instructions

5. Deploy agent on Docker hosts
   ├─ Copy enrollment token
   ├─ Run agent container with token
   └─ Agent registers with backend

6. Verify agent connectivity
   ├─ Agent appears in agents list
   ├─ Status shows "active"
   └─ Containers discovered automatically

PHASE 3: Registry Connection
────────────────────────────
7. Navigate to /registries
   └─ Click "Add Registry"

8. Configure registry credentials
   ├─ Select provider (GHCR/DockerHub)
   ├─ Enter credentials
   └─ Test connection

9. Browse available images
   └─ Verify repositories visible

PHASE 4: Basic Configuration
────────────────────────────
10. Configure domain settings
    └─ /settings → Domain

11. Set up alert channels
    ├─ /alerts → Channels
    ├─ Add Slack webhook
    └─ Test notification

12. Review security policies
    ├─ /policies → View default policies
    └─ Customize if needed

SUCCESS: InfraPilot is ready for team use
```

---

### Journey 2: CI/CD Pipeline Integration (DevOps Engineer)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JOURNEY: Automated Deployment Pipeline                                       │
│ PERSONA: DevOps Engineer (Alex)                                             │
│ GOAL: Connect CI/CD pipeline to InfraPilot for automated secure deployments │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: Webhook Setup
──────────────────────
1. Navigate to /webhooks
   └─ Click "Create Webhook"

2. Configure webhook
   ├─ Name: "api-service-prod"
   ├─ Provider: GitHub
   ├─ Service: "api"
   ├─ Environment: "production"
   └─ Save → Get webhook URL & secret

3. Copy webhook credentials
   └─ URL: https://infrapilot.example.com/api/v1/webhooks/{id}/receive
   └─ Secret: {generated-secret}

PHASE 2: CI/CD Configuration (GitHub Actions)
─────────────────────────────────────────────
4. Add secrets to GitHub repository
   ├─ INFRAPILOT_WEBHOOK_URL
   └─ INFRAPILOT_WEBHOOK_SECRET

5. Update GitHub Actions workflow
   └─ Add deployment notification step:

   - name: Notify InfraPilot
     run: |
       curl -X POST "$INFRAPILOT_WEBHOOK_URL" \
         -H "Content-Type: application/json" \
         -H "X-Hub-Signature-256: sha256=$(echo -n '$PAYLOAD' | openssl dgst -sha256 -hmac '$SECRET')" \
         -d '{
           "image": "ghcr.io/myorg/api:${{ github.sha }}",
           "git_repo": "${{ github.repository }}",
           "git_branch": "${{ github.ref_name }}",
           "git_commit": "${{ github.sha }}",
           "ci_provider": "github-actions",
           "ci_build_url": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
         }'

PHASE 3: Test Pipeline
──────────────────────
6. Push code change to trigger pipeline
   └─ git push origin main

7. Monitor in InfraPilot
   ├─ /webhooks → Events tab shows received event
   └─ /deployments → New deployment appears

8. Watch deployment pipeline
   ├─ Status: pending → scanning → policy_check → deploying → running
   ├─ View scan results (vulnerabilities found)
   └─ View policy decision (allow/warn/deny)

PHASE 4: Handle Blocked Deployment (if policy denies)
─────────────────────────────────────────────────────
9. If deployment blocked:
   ├─ View deployment details
   ├─ See policy reason: "Critical CVE detected"
   ├─ View affected vulnerabilities
   └─ Options:
       ├─ Fix vulnerabilities and re-push
       └─ Request risk exception (if justified)

SUCCESS: CI/CD pipeline automatically deploys through InfraPilot security gates
```

---

### Journey 3: Manual Deployment (DevOps Engineer)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JOURNEY: Manual Image Deployment                                            │
│ PERSONA: DevOps Engineer (Alex)                                             │
│ GOAL: Deploy a specific image version manually                              │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: Browse Available Images
────────────────────────────────
1. Navigate to /registries
   └─ Select "Browse Images" tab

2. Select registry
   └─ Choose from connected registries

3. Browse repositories
   ├─ See list of available repos
   └─ Click on target repo (e.g., "myorg/api")

4. View available tags
   ├─ See all tags with metadata
   ├─ Indicators show:
   │   ├─ 🟢 Running (currently deployed)
   │   ├─ 💾 Local (cached on host)
   │   └─ ⚪ Available (in registry only)
   └─ Select desired tag (e.g., "v2.1.0")

PHASE 2: Pre-Deployment Scan (Optional)
───────────────────────────────────────
5. Scan image before deployment
   ├─ Click shield icon on tag
   ├─ Scan modal opens
   └─ View vulnerability results

6. Review scan results
   ├─ Critical: 0, High: 2, Medium: 5
   ├─ View affected packages
   └─ Decide: proceed or fix first

PHASE 3: Create Deployment
──────────────────────────
7. Navigate to /deployments
   └─ Click "New Deployment"

8. Fill deployment form
   ├─ Service Name: "api"
   ├─ Environment: "staging"
   ├─ Image: "ghcr.io/myorg/api:v2.1.0"
   ├─ (Optional) Git commit reference
   └─ Submit

9. Monitor deployment
   ├─ Deployment created (pending)
   ├─ Scanning... (Trivy)
   ├─ Policy check... (OPA)
   └─ Deploying... → Running

SUCCESS: Image deployed through security pipeline
```

---

### Journey 4: Security Vulnerability Remediation (Security Officer)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JOURNEY: Vulnerability Discovery and Remediation                            │
│ PERSONA: Security Officer (Sarah)                                           │
│ GOAL: Identify, prioritize, and track vulnerability remediation             │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: Security Posture Review
────────────────────────────────
1. Navigate to /security (Dashboard)
   └─ View security posture score (e.g., 72/100)

2. Review vulnerability summary
   ├─ Critical: 3 across 2 services
   ├─ High: 15 across 5 services
   └─ Click "View Details"

PHASE 2: CVE Investigation
──────────────────────────
3. Navigate to /vulnerabilities
   └─ View CVE-centric list

4. Filter by severity
   ├─ Select: Critical only
   └─ See 3 critical CVEs

5. Investigate specific CVE
   ├─ Click on CVE-2024-1234
   ├─ View affected deployments:
   │   ├─ api-prod (running)
   │   ├─ api-staging (running)
   │   └─ worker-prod (running)
   ├─ View affected package: openssl 1.1.1k
   ├─ View fix available: openssl 1.1.1w
   └─ View CVSS: 9.8 (Critical)

PHASE 3: Notify and Track
─────────────────────────
6. Identify service owner
   ├─ /ownership → Search "api"
   ├─ Owner: Platform Team
   ├─ Contact: @platform-team (Slack)
   └─ Primary: alice@example.com

7. Create alert/notification
   ├─ Alert rule triggers
   └─ Slack notification sent to #platform-team

8. Track remediation
   ├─ Monitor /deployments for new deployment
   ├─ New deployment with updated image
   └─ Re-scan shows CVE resolved

PHASE 4: Exception Handling (if needed)
───────────────────────────────────────
9. If immediate fix not possible:
   ├─ Navigate to /exceptions
   ├─ Create exception request:
   │   ├─ Scope: CVE-2024-1234
   │   ├─ Justification: "Upstream fix not available, mitigated by WAF"
   │   ├─ Expiry: 30 days
   │   └─ Submit for approval
   └─ Approve exception (if authorized)

SUCCESS: Vulnerability tracked and remediated (or exception documented)
```

---

### Journey 5: Developer Deployment Feedback Loop (Developer)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JOURNEY: Understanding Blocked Deployment                                    │
│ PERSONA: Developer (Dev)                                                    │
│ GOAL: Understand why deployment was blocked and fix the issue               │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: Deployment Triggered
─────────────────────────────
1. Developer pushes code
   └─ git push origin feature/new-feature

2. CI/CD pipeline runs
   ├─ Build succeeds
   ├─ Tests pass
   └─ Deployment notification sent to InfraPilot

PHASE 2: Deployment Blocked
───────────────────────────
3. InfraPilot processes deployment
   ├─ Image scanned: 2 critical CVEs found
   ├─ Policy evaluated: DENY
   └─ Deployment status: blocked

4. Developer receives feedback (GitHub PR)
   └─ InfraPilot posts PR comment:

   ┌─────────────────────────────────────────────────────────────┐
   │ 🚫 Deployment blocked by InfraPilot                        │
   │                                                             │
   │ Critical vulnerability detected:                            │
   │ • CVE-2024-1234 (CVSS 9.8)                                 │
   │ • Package: openssl 1.1.1k                                  │
   │ • Introduced via: alpine:3.18 (base image)                 │
   │                                                             │
   │ ✅ Recommended fix:                                         │
   │ • Update base image to alpine:3.19                         │
   │ • OR pin openssl >= 1.1.1w                                 │
   │                                                             │
   │ 🔗 View full details: https://infrapilot.example.com/...   │
   └─────────────────────────────────────────────────────────────┘

PHASE 3: Issue Resolution
─────────────────────────
5. Developer investigates
   ├─ Click InfraPilot link
   ├─ View deployment details
   ├─ See full vulnerability info
   └─ Understand root cause: outdated base image

6. Developer fixes issue
   ├─ Update Dockerfile:
   │   - FROM alpine:3.18
   │   + FROM alpine:3.19
   └─ Commit and push fix

7. CI/CD re-runs
   ├─ New image built
   ├─ InfraPilot re-scans
   ├─ Policy: ALLOW
   └─ Deployment succeeds

PHASE 4: Verification
─────────────────────
8. Developer verifies
   ├─ Check /deployments → Status: running
   ├─ PR comment updated: "✅ Deployment successful"
   └─ Service accessible

SUCCESS: Developer understood and fixed security issue with clear feedback
```

---

### Journey 6: Reverse Proxy Setup (DevOps Engineer)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JOURNEY: Expose Service via Reverse Proxy                                   │
│ PERSONA: DevOps Engineer (Alex)                                             │
│ GOAL: Create reverse proxy with SSL and security headers                    │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: Create Proxy Host
──────────────────────────
1. Navigate to /proxies
   └─ Click "Add Proxy Host"

2. Configure basic settings
   ├─ Domain: api.example.com
   ├─ Upstream: http://api-container:8080
   └─ Enable: Force HTTPS, HTTP/2

3. Request SSL certificate
   ├─ Enable: SSL
   ├─ Method: Let's Encrypt
   ├─ Email: admin@example.com
   └─ Challenge: HTTP-01 (or DNS-01 for wildcard)

PHASE 2: Configure Security
───────────────────────────
4. Add security headers
   ├─ HSTS: max-age=31536000; includeSubDomains
   ├─ X-Frame-Options: DENY
   ├─ X-Content-Type-Options: nosniff
   ├─ CSP: default-src 'self'
   └─ X-XSS-Protection: 1; mode=block

5. Configure rate limiting
   ├─ Enable rate limiting
   ├─ Requests per second: 100
   ├─ Burst: 50
   └─ Key: $binary_remote_addr

6. Configure access control (optional)
   ├─ Add IP allowlist
   └─ Or add IP denylist

PHASE 3: Test and Deploy
────────────────────────
7. Test configuration
   ├─ Click "Test Config"
   └─ Verify nginx config valid

8. Save and apply
   ├─ Click "Save"
   ├─ Nginx config generated
   ├─ SSL certificate requested
   └─ Nginx reloaded

PHASE 4: Verify
───────────────
9. Test endpoint
   ├─ curl https://api.example.com/health
   ├─ Verify SSL certificate valid
   └─ Verify security headers present

SUCCESS: Service exposed securely with SSL and security hardening
```

---

### Journey 7: Security Maturity Tracking (Team Lead)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JOURNEY: Track Team Security Improvement                                    │
│ PERSONA: Team Lead (Taylor)                                                 │
│ GOAL: Monitor and improve team's security posture over time                 │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: Review Current State
─────────────────────────────
1. Navigate to /maturity
   └─ View security maturity dashboard

2. Check team score
   ├─ Team: Platform Team
   ├─ Score: 68/100
   ├─ Trend: ↗ Improving (+5 from last month)
   └─ Rank: #3 of 5 teams

3. Analyze score breakdown
   ├─ Vulnerability Management: 72/100
   ├─ Policy Compliance: 85/100
   ├─ Deployment Security: 65/100
   ├─ Exception Management: 50/100
   └─ Response Time (MTTF): 60/100

PHASE 2: Identify Improvement Areas
───────────────────────────────────
4. Drill into weak areas
   ├─ Exception Management (50/100)
   │   ├─ 3 expired exceptions not renewed
   │   └─ 2 exceptions without proper justification
   └─ Response Time (60/100)
       ├─ Average MTTF: 5 days
       └─ Target: 3 days

5. View team's services
   ├─ /ownership → Filter by "Platform Team"
   └─ See all 8 owned services

6. Check service-level scores
   ├─ api-service: 75/100
   ├─ worker-service: 62/100 ← Needs attention
   └─ frontend-service: 70/100

PHASE 3: Create Action Plan
───────────────────────────
7. Review worker-service issues
   ├─ 5 high vulnerabilities
   ├─ 1 expired exception
   └─ 2 policy violations

8. Assign remediation tasks
   ├─ Update base image (fixes 3 CVEs)
   ├─ Renew or resolve exception
   └─ Fix policy violations

PHASE 4: Track Progress
───────────────────────
9. Set up regular review
   ├─ Weekly score check
   └─ Monthly trend review

10. Monitor improvement
    ├─ /maturity → Score trend chart
    └─ Goal: Reach 80/100 by next quarter

SUCCESS: Team has clear visibility and action plan for security improvement
```

---

### Journey 8: Compliance Audit (Compliance Officer)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JOURNEY: Security Compliance Evidence Collection                            │
│ PERSONA: Compliance Officer (Chris)                                         │
│ GOAL: Gather evidence for security audit                                    │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: Policy Enforcement Evidence
────────────────────────────────────
1. Navigate to /policies
   └─ View policy configuration

2. Export policy decisions
   ├─ Filter by date range
   ├─ View all decisions (allow/warn/deny)
   └─ Export as CSV/JSON

3. Document policy effectiveness
   ├─ Total deployments: 150
   ├─ Blocked by policy: 12 (8%)
   └─ Evidence: Policy gates are active

PHASE 2: Vulnerability Management Evidence
──────────────────────────────────────────
4. Navigate to /vulnerabilities
   └─ View vulnerability summary

5. Export SBOM for audit
   ├─ /sboms → Select production services
   ├─ Download SBOM (CycloneDX format)
   └─ Document: Complete software inventory

6. Document remediation timeline
   ├─ Critical CVEs: Average fix time 2 days
   ├─ High CVEs: Average fix time 7 days
   └─ Evidence: Vulnerabilities tracked and fixed

PHASE 3: Access Control Evidence
────────────────────────────────
7. Navigate to /users
   └─ Export user list with roles

8. Navigate to /settings → Audit
   └─ Export audit logs for period

9. Document access controls
   ├─ Users with admin access: 3
   ├─ MFA enabled: 100%
   └─ Evidence: RBAC enforced

PHASE 4: Exception Management Evidence
──────────────────────────────────────
10. Navigate to /exceptions
    └─ View all exceptions with history

11. Document exception governance
    ├─ Active exceptions: 5
    ├─ All have justification: ✓
    ├─ All have expiry date: ✓
    └─ All have approval: ✓

12. Export exception history
    └─ Full audit trail of approvals

PHASE 5: Compile Report
───────────────────────
13. Generate compliance report
    ├─ Security posture score: 78/100
    ├─ Policy enforcement: Active
    ├─ Vulnerability management: Active
    ├─ Access control: Enforced
    └─ Risk management: Documented

SUCCESS: Complete audit evidence package collected
```

---

### Journey 9: Incident Response - Container Drift (Security Officer)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JOURNEY: Runtime Drift Detection and Response                               │
│ PERSONA: Security Officer (Sarah)                                           │
│ GOAL: Investigate and respond to runtime configuration drift                │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: Alert Received
───────────────────────
1. Receive Slack alert
   └─ "🚨 CRITICAL: Privilege escalation detected on api-prod"

2. Click alert link
   └─ Opens /runtime-security

PHASE 2: Investigate Drift
──────────────────────────
3. View drift event details
   ├─ Container: api-prod-7f8d9
   ├─ Drift Type: privilege_escalation
   ├─ Severity: Critical
   ├─ Detected: Container running with --privileged
   ├─ Expected: Non-privileged
   └─ Time: 2024-01-19 10:30:00 UTC

4. Compare expected vs actual
   ├─ Expected state (from deployment):
   │   └─ privileged: false
   └─ Actual state (runtime):
       └─ privileged: true

5. Check deployment history
   ├─ Navigate to /deployments
   ├─ Find api-prod deployment
   └─ Verify deployment config was correct

PHASE 3: Respond
────────────────
6. Determine cause
   ├─ Was container modified manually?
   ├─ Was there an unauthorized deployment?
   └─ Check audit logs

7. Take action
   ├─ Option A: Rollback to known-good deployment
   │   └─ /deployments → Rollback
   ├─ Option B: Stop compromised container
   │   └─ /containers → Stop
   └─ Option C: Mark as expected (if legitimate)
       └─ Add resolution note

8. Resolve drift event
   ├─ Navigate to drift event
   ├─ Add resolution notes
   └─ Mark as resolved

PHASE 4: Post-Incident
──────────────────────
9. Document incident
   ├─ Drift event ID
   ├─ Root cause analysis
   ├─ Actions taken
   └─ Prevention measures

10. Update policies
    └─ Add/enforce self-protection policy to block privileged containers

SUCCESS: Drift detected, investigated, and resolved with audit trail
```

---

### Journey 10: Service Onboarding (DevOps Engineer + Team Lead)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ JOURNEY: Onboard New Service to InfraPilot                                  │
│ PERSONAS: DevOps Engineer (Alex) + Team Lead (Taylor)                       │
│ GOAL: Register new service with ownership, webhooks, and security baseline  │
└─────────────────────────────────────────────────────────────────────────────┘

PHASE 1: Register Service Ownership (Team Lead)
───────────────────────────────────────────────
1. Navigate to /ownership
   └─ Click "Add Service"

2. Register service
   ├─ Service Name: "payment-api"
   ├─ Description: "Payment processing service"
   ├─ Team: "Payments Team"
   ├─ Primary Contact: alice@example.com
   ├─ Slack Channel: #payments-team
   ├─ Repository: github.com/myorg/payment-api
   └─ Documentation: wiki.myorg.com/payment-api

3. Verify team exists
   ├─ If not, create team first
   └─ Add team members

PHASE 2: Configure CI/CD Integration (DevOps)
─────────────────────────────────────────────
4. Create webhooks for each environment
   ├─ /webhooks → Create Webhook
   ├─ "payment-api-dev" → Environment: dev
   ├─ "payment-api-staging" → Environment: staging
   └─ "payment-api-prod" → Environment: prod

5. Configure CI/CD pipeline
   ├─ Add webhook URLs to pipeline
   └─ Test with dev deployment

PHASE 3: Establish Security Baseline
────────────────────────────────────
6. Initial image scan
   ├─ /registries → Browse → Find payment-api image
   ├─ Scan latest tag
   └─ Document baseline vulnerabilities

7. Review policy compliance
   ├─ /policies → Preview evaluation
   ├─ Input: payment-api:latest
   └─ Verify policy decision (should be ALLOW)

8. If issues found:
   ├─ Fix before production deployment
   └─ Or create justified exception

PHASE 4: First Deployment
─────────────────────────
9. Trigger deployment via CI/CD
   └─ Push to main branch

10. Monitor deployment
    ├─ /deployments → Watch status
    └─ Verify: pending → scanning → policy_check → deploying → running

11. Set up proxy (if needed)
    ├─ /proxies → Add Proxy Host
    ├─ Domain: payment-api.example.com
    └─ Configure SSL and security headers

PHASE 5: Verify and Document
────────────────────────────
12. Verify service running
    ├─ Check /containers
    └─ Test endpoint

13. Verify ownership routing
    ├─ Trigger test alert
    └─ Confirm Slack notification to #payments-team

14. Document in team wiki
    └─ InfraPilot integration complete

SUCCESS: Service fully onboarded with security, ownership, and automation
```

---

## Epic-Level User Stories

### Epic 1: Secure Deployment Pipeline

| ID | User Story | Acceptance Criteria |
|----|------------|---------------------|
| E1.1 | As a DevOps engineer, I want automated deployments through security gates so that all deployments are scanned and policy-checked | - Deployments go through scan → policy → deploy flow<br>- Blocked deployments have clear status |
| E1.2 | As a security officer, I want all deployments scanned for vulnerabilities so that no unscanned images reach production | - 100% of deployments are scanned<br>- Scan results linked to deployments |
| E1.3 | As a security officer, I want policy-based deployment gates so that risky deployments are blocked automatically | - Policies can block deployments<br>- Policy decisions are logged |
| E1.4 | As a developer, I want clear feedback when my deployment is blocked so that I can fix issues quickly | - PR comments explain blocking reason<br>- Remediation steps provided |

### Epic 2: Supply Chain Security

| ID | User Story | Acceptance Criteria |
|----|------------|---------------------|
| E2.1 | As a security officer, I want to scan container images for vulnerabilities so that I know what CVEs are in my infrastructure | - Trivy integration working<br>- CVEs with severity and fix info |
| E2.2 | As a compliance officer, I want SBOM generation for all images so that I can document software inventory | - SBOM in CycloneDX/SPDX format<br>- Downloadable per image |
| E2.3 | As a security officer, I want a CVE-centric view so that I can see all deployments affected by a specific CVE | - Search by CVE ID<br>- Shows all affected deployments |

### Epic 3: Runtime Security

| ID | User Story | Acceptance Criteria |
|----|------------|---------------------|
| E3.1 | As a security officer, I want drift detection so that I'm alerted when containers change from expected state | - Drift events detected automatically<br>- Alerts sent to configured channels |
| E3.2 | As a security officer, I want behavioral anomaly detection so that I catch suspicious container behavior | - Crash loops, resource spikes detected<br>- Anomalies logged with severity |
| E3.3 | As an operator, I want to resolve drift events so that I can track investigation and remediation | - Resolution workflow with notes<br>- Full audit trail |

### Epic 4: Risk Governance

| ID | User Story | Acceptance Criteria |
|----|------------|---------------------|
| E4.1 | As a security officer, I want risk exceptions with time-boxing so that accepted risks have expiry dates | - Exceptions require expiry date<br>- Auto-blocked after expiry |
| E4.2 | As a security officer, I want exception approval workflows so that risks are properly governed | - Approval required for exceptions<br>- Approver logged |
| E4.3 | As a compliance officer, I want exception audit trails so that I can document risk acceptance | - Full history of exception lifecycle<br>- Justifications preserved |

### Epic 5: Container Operations

| ID | User Story | Acceptance Criteria |
|----|------------|---------------------|
| E5.1 | As an operator, I want to manage containers without SSH so that I can start/stop/restart from the UI | - Container lifecycle controls work<br>- Actions logged |
| E5.2 | As an operator, I want container logs in the UI so that I can troubleshoot without SSH | - Logs viewable and searchable<br>- Real-time streaming available |
| E5.3 | As an operator, I want web terminal access so that I can execute commands in containers | - Terminal works in browser<br>- Commands logged |

### Epic 6: Traffic Management

| ID | User Story | Acceptance Criteria |
|----|------------|---------------------|
| E6.1 | As a DevOps engineer, I want reverse proxy management so that I can expose services without manual nginx config | - Proxy hosts configurable via UI<br>- Nginx reloaded automatically |
| E6.2 | As a DevOps engineer, I want automatic SSL certificates so that I don't have to manage certificates manually | - Let's Encrypt integration works<br>- Auto-renewal functional |
| E6.3 | As a security officer, I want security headers enforced so that web applications are hardened | - HSTS, CSP, X-Frame-Options configurable<br>- Headers verified in responses |

### Epic 7: Observability & Alerting

| ID | User Story | Acceptance Criteria |
|----|------------|---------------------|
| E7.1 | As an operator, I want centralized logs so that I can search across all services | - Logs from all containers collected<br>- Full-text search works |
| E7.2 | As an operator, I want configurable alerts so that I'm notified of important events | - Alert channels (Slack, email, webhook)<br>- Alert rules customizable |
| E7.3 | As a security officer, I want a security dashboard so that I can see overall security posture | - Posture score displayed<br>- Trend visible |

### Epic 8: Ownership & Accountability

| ID | User Story | Acceptance Criteria |
|----|------------|---------------------|
| E8.1 | As a team lead, I want service ownership mapping so that I know who owns what | - Services mapped to teams<br>- Contact info available |
| E8.2 | As a security officer, I want alert routing by owner so that the right team is notified | - Alerts routed to service owner<br>- Slack channels configurable |
| E8.3 | As a team lead, I want security maturity scores so that I can track my team's improvement | - Scores calculated per team<br>- Leaderboard available |

---

## Feature-Level User Stories

### Authentication & Authorization

| ID | User Story | Priority |
|----|------------|----------|
| AUTH-1 | As a user, I can log in with email and password | P0 |
| AUTH-2 | As an admin, I can enforce MFA for all users | P0 |
| AUTH-3 | As a user, I can set up TOTP-based MFA | P0 |
| AUTH-4 | As an admin, I can manage user roles (super_admin, operator, viewer) | P0 |
| AUTH-5 | As a user, I can generate backup codes for MFA recovery | P1 |
| AUTH-6 | As an admin, I can disable user accounts | P1 |

### Container Management

| ID | User Story | Priority |
|----|------------|----------|
| CONT-1 | As an operator, I can view all containers across all agents | P0 |
| CONT-2 | As an operator, I can start/stop/restart containers | P0 |
| CONT-3 | As an operator, I can view container logs | P0 |
| CONT-4 | As an operator, I can stream logs in real-time | P1 |
| CONT-5 | As an operator, I can execute commands in containers (web terminal) | P1 |
| CONT-6 | As an operator, I can filter containers by status | P1 |
| CONT-7 | As an operator, I can see container resource usage (CPU, memory) | P1 |
| CONT-8 | As an operator, I can delete stopped containers | P2 |

### Deployments

| ID | User Story | Priority |
|----|------------|----------|
| DEP-1 | As a DevOps engineer, I can create deployments with full provenance | P0 |
| DEP-2 | As a DevOps engineer, I can view deployment status and history | P0 |
| DEP-3 | As a DevOps engineer, I can rollback to previous deployments | P0 |
| DEP-4 | As a DevOps engineer, I can see deployment scan results | P0 |
| DEP-5 | As a DevOps engineer, I can see policy decisions for deployments | P0 |
| DEP-6 | As a DevOps engineer, I can filter deployments by service, environment, status | P1 |
| DEP-7 | As a DevOps engineer, I can view the deployment spine (full traceability) | P1 |
| DEP-8 | As a DevOps engineer, I can see cross-agent service deployments | P2 |

### Registries

| ID | User Story | Priority |
|----|------------|----------|
| REG-1 | As a DevOps engineer, I can connect to GHCR and DockerHub | P0 |
| REG-2 | As a DevOps engineer, I can browse repositories and tags | P0 |
| REG-3 | As a DevOps engineer, I can see which images are running | P1 |
| REG-4 | As a DevOps engineer, I can trigger image scans from registry browser | P1 |
| REG-5 | As a DevOps engineer, I can test registry connections | P1 |

### Webhooks & CI/CD

| ID | User Story | Priority |
|----|------------|----------|
| HOOK-1 | As a DevOps engineer, I can create webhooks for CI/CD integration | P0 |
| HOOK-2 | As a DevOps engineer, I can receive GitHub/GitLab/Jenkins webhooks | P0 |
| HOOK-3 | As a DevOps engineer, I can view webhook event history | P1 |
| HOOK-4 | As a DevOps engineer, I can enable/disable webhooks | P1 |
| HOOK-5 | As a DevOps engineer, I can regenerate webhook secrets | P2 |

### Scanning & Vulnerabilities

| ID | User Story | Priority |
|----|------------|----------|
| SCAN-1 | As a security officer, I can scan images for vulnerabilities | P0 |
| SCAN-2 | As a security officer, I can view vulnerability details (CVE, CVSS, fix) | P0 |
| SCAN-3 | As a security officer, I can generate SBOMs for images | P0 |
| SCAN-4 | As a security officer, I can download SBOMs in CycloneDX/SPDX format | P1 |
| SCAN-5 | As a security officer, I can search SBOM packages | P1 |
| SCAN-6 | As a security officer, I can see CVE-centric vulnerability view | P1 |
| SCAN-7 | As a security officer, I can filter vulnerabilities by severity | P1 |

### Policies

| ID | User Story | Priority |
|----|------------|----------|
| POL-1 | As a security officer, I can define OPA policies for deployments | P0 |
| POL-2 | As a security officer, I can see policy decisions with reasons | P0 |
| POL-3 | As a security officer, I can preview policy evaluation | P1 |
| POL-4 | As a security officer, I can view policy decision statistics | P1 |
| POL-5 | As a security officer, I can update policies without restart | P2 |

### Proxies & Traffic

| ID | User Story | Priority |
|----|------------|----------|
| PROXY-1 | As a DevOps engineer, I can create reverse proxy hosts | P0 |
| PROXY-2 | As a DevOps engineer, I can obtain SSL certificates automatically | P0 |
| PROXY-3 | As a DevOps engineer, I can configure security headers | P1 |
| PROXY-4 | As a DevOps engineer, I can configure rate limiting | P1 |
| PROXY-5 | As a DevOps engineer, I can configure IP allow/deny lists | P2 |
| PROXY-6 | As a DevOps engineer, I can test proxy configuration before applying | P1 |

### Alerts

| ID | User Story | Priority |
|----|------------|----------|
| ALERT-1 | As an operator, I can configure Slack/email/webhook alert channels | P0 |
| ALERT-2 | As an operator, I can create alert rules | P0 |
| ALERT-3 | As an operator, I can view alert history | P1 |
| ALERT-4 | As an operator, I can test alert channels | P1 |
| ALERT-5 | As an operator, I can set alert cooldown periods | P2 |

### Runtime Security

| ID | User Story | Priority |
|----|------------|----------|
| RUN-1 | As a security officer, I can see drift events | P0 |
| RUN-2 | As a security officer, I can see behavioral anomalies | P0 |
| RUN-3 | As a security officer, I can resolve drift events with notes | P1 |
| RUN-4 | As a security officer, I can configure drift detection thresholds | P2 |

### Exceptions

| ID | User Story | Priority |
|----|------------|----------|
| EXC-1 | As a developer, I can request a risk exception | P0 |
| EXC-2 | As a security officer, I can approve/deny exceptions | P0 |
| EXC-3 | As a security officer, I can set exception expiry dates | P0 |
| EXC-4 | As a security officer, I can revoke exceptions | P1 |
| EXC-5 | As a compliance officer, I can view exception history | P1 |

### Ownership & Maturity

| ID | User Story | Priority |
|----|------------|----------|
| OWN-1 | As a team lead, I can register service ownership | P1 |
| OWN-2 | As a team lead, I can manage team members | P1 |
| OWN-3 | As a team lead, I can view team security score | P1 |
| OWN-4 | As a team lead, I can see team leaderboard | P2 |
| OWN-5 | As a team lead, I can view score trends | P2 |

### Feedback

| ID | User Story | Priority |
|----|------------|----------|
| FEED-1 | As a developer, I receive PR comments for blocked deployments | P0 |
| FEED-2 | As a developer, I can see remediation suggestions in feedback | P1 |
| FEED-3 | As a DevOps engineer, I can configure VCS integration (GitHub/GitLab) | P1 |

---

## Gap Analysis

### Current Gaps Identified

| Gap | Description | Impact | Priority |
|-----|-------------|--------|----------|
| **Actual Container Deployment** | Pipeline stops at "deploying" status, doesn't actually start containers | Cannot complete deployment flow | P0 |
| **Webhook Signature Verification** | Signature verification marked as TODO | Security risk - webhooks could be spoofed | P0 |
| **Credential Encryption** | Registry credentials not fully encrypted | Security risk - credentials at risk | P0 |
| **Multi-Registry Support** | Only GHCR and DockerHub, missing AWS ECR, GCR, Azure ACR | Limited enterprise adoption | P1 |
| **Kubernetes Support** | Docker-only, no Kubernetes integration | Limited to Docker environments | P2 |
| **SSO/SAML/OIDC** | Only email/password auth | Enterprise users need SSO | P1 |
| **API Rate Limiting** | No rate limiting on InfraPilot APIs | DoS risk | P1 |
| **Backup/Restore** | No built-in backup for PostgreSQL data | Data loss risk | P1 |
| **High Availability** | Single-node only | Not suitable for enterprise | P2 |

### Recommended Next Steps

1. **P0 - Complete Core Flow**
   - Implement actual container deployment (start container after policy approval)
   - Implement webhook signature verification
   - Properly encrypt registry credentials

2. **P1 - Enterprise Readiness**
   - Add SSO/OIDC support
   - Add AWS ECR, GCR support
   - Implement API rate limiting
   - Add backup/restore functionality

3. **P2 - Scale & Advanced**
   - Kubernetes integration
   - High availability mode
   - Advanced RBAC (custom roles)

---

## Appendix: API Endpoint Summary

See [API-REFERENCE.md](./API-REFERENCE.md) for complete API documentation.

---

**Document Version:** 1.0
**Last Updated:** 2026-01-19
**Authors:** Generated from InfraPilot codebase analysis
