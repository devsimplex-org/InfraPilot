# Traffic & Exposure Governance v2 - Implementation Plan

## Executive Summary

This plan introduces **TrafficResource** as a first-class domain object, separating traffic intent from nginx implementation. The architecture shifts from "nginx-centric" to "traffic-resource-centric" where nginx becomes a "compiler target" that renders declarative traffic policies.

---

## Current State Analysis

### Existing Tables (Epic 13)
- `proxy_hosts` - Nginx reverse proxy configurations
- `exposed_endpoints` - Endpoint inventory with risk scoring
- `rate_limit_profiles` / `rate_limit_assignments` - Rate limiting
- `tls_scan_results` / `tls_alert_config` - TLS monitoring

### Limitations
1. **Nginx as source of truth** - Changes start from nginx config, not business intent
2. **No load balancing abstraction** - Upstreams are simple strings
3. **No traffic policies beyond rate limits** - Missing CAPTCHA, bot protection, geo-blocking
4. **No dry-run/validation workflow** - Changes applied directly without preview
5. **No separation of System vs Application traffic** - All traffic through one gateway

---

## Proposed Architecture

### Core Concept: TrafficResource

A **TrafficResource** represents a declarative traffic configuration:
- What domains/paths to expose
- What upstream services to route to (with load balancing)
- What policies to apply (rate limits, bot protection, auth)
- What TLS configuration to use

Nginx configuration becomes a **compiled output** from TrafficResource.

```
User Intent → TrafficResource → Policy Engine → Nginx Config → Agent Apply
```

---

## Phase 1: Database Schema (Migration 032)

### New Tables

#### 1. `traffic_resources` - Core domain object
```sql
CREATE TABLE traffic_resources (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID NOT NULL REFERENCES agents(id),

    -- Identity
    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Routing
    domains TEXT[] NOT NULL,                    -- ['api.example.com', '*.api.example.com']
    paths JSONB DEFAULT '[{"path": "/", "match": "prefix"}]',

    -- Gateway Type
    gateway_type VARCHAR(20) DEFAULT 'application', -- 'system', 'application'

    -- Status & Lifecycle
    status VARCHAR(20) DEFAULT 'draft',         -- 'draft', 'pending', 'active', 'disabled'
    desired_state JSONB,                        -- Full desired configuration
    applied_state JSONB,                        -- Last successfully applied
    last_applied_at TIMESTAMPTZ,
    last_error TEXT,

    -- Metadata
    labels JSONB DEFAULT '{}',
    annotations JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, agent_id, name)
);
```

#### 2. `traffic_upstreams` - Load balancing configuration
```sql
CREATE TABLE traffic_upstreams (
    id UUID PRIMARY KEY,
    traffic_resource_id UUID NOT NULL REFERENCES traffic_resources(id),

    -- Target
    name VARCHAR(100) NOT NULL,
    targets JSONB NOT NULL,                     -- [{"address": "10.0.0.1:8080", "weight": 1}]

    -- Load Balancing
    lb_method VARCHAR(20) DEFAULT 'round_robin', -- 'round_robin', 'least_conn', 'ip_hash', 'random'

    -- Health Checks
    health_check_enabled BOOLEAN DEFAULT TRUE,
    health_check_path VARCHAR(255) DEFAULT '/health',
    health_check_interval_sec INTEGER DEFAULT 30,
    health_check_timeout_sec INTEGER DEFAULT 5,
    healthy_threshold INTEGER DEFAULT 2,
    unhealthy_threshold INTEGER DEFAULT 3,

    -- Connection Management
    max_connections INTEGER,
    max_keepalive INTEGER DEFAULT 64,
    connect_timeout_sec INTEGER DEFAULT 5,
    read_timeout_sec INTEGER DEFAULT 60,

    -- Status
    last_health_check TIMESTAMPTZ,
    healthy_targets INTEGER DEFAULT 0,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### 3. `traffic_policies` - Unified policy configuration
```sql
CREATE TABLE traffic_policies (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES organizations(id),

    -- Identity
    name VARCHAR(100) NOT NULL,
    description TEXT,
    policy_type VARCHAR(50) NOT NULL,           -- 'rate_limit', 'bot_protection', 'geo_blocking',
                                                 -- 'captcha', 'ip_filtering', 'header_transform'

    -- Policy Configuration (type-specific)
    config JSONB NOT NULL,

    -- Scope
    is_global BOOLEAN DEFAULT FALSE,            -- Applies to all traffic resources
    priority INTEGER DEFAULT 0,

    -- Status
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);
```

#### 4. `traffic_policy_assignments` - Policy → Resource mapping
```sql
CREATE TABLE traffic_policy_assignments (
    id UUID PRIMARY KEY,
    policy_id UUID NOT NULL REFERENCES traffic_policies(id),
    traffic_resource_id UUID REFERENCES traffic_resources(id),

    -- Path-specific override (optional)
    path_pattern VARCHAR(255),                   -- Apply only to specific paths

    -- Override config (optional)
    config_override JSONB,

    priority INTEGER DEFAULT 0,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### 5. `traffic_tls_configs` - TLS settings per resource
```sql
CREATE TABLE traffic_tls_configs (
    id UUID PRIMARY KEY,
    traffic_resource_id UUID NOT NULL REFERENCES traffic_resources(id),

    -- Certificate Source
    cert_source VARCHAR(20) DEFAULT 'auto',     -- 'auto' (Let's Encrypt), 'manual', 'acme'
    cert_id UUID REFERENCES ssl_certificates(id),

    -- TLS Settings
    min_version VARCHAR(10) DEFAULT 'TLS1.2',
    max_version VARCHAR(10) DEFAULT 'TLS1.3',
    cipher_suites TEXT[],

    -- HSTS
    hsts_enabled BOOLEAN DEFAULT TRUE,
    hsts_max_age INTEGER DEFAULT 31536000,
    hsts_include_subdomains BOOLEAN DEFAULT TRUE,
    hsts_preload BOOLEAN DEFAULT FALSE,

    -- Client Cert (mTLS)
    mtls_enabled BOOLEAN DEFAULT FALSE,
    mtls_ca_cert_id UUID,
    mtls_verify_depth INTEGER DEFAULT 1,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### 6. `traffic_apply_history` - Audit trail for changes
```sql
CREATE TABLE traffic_apply_history (
    id UUID PRIMARY KEY,
    traffic_resource_id UUID NOT NULL REFERENCES traffic_resources(id),

    -- Change Info
    action VARCHAR(20) NOT NULL,                -- 'create', 'update', 'delete', 'rollback'
    previous_state JSONB,
    new_state JSONB,

    -- Validation
    dry_run_result JSONB,                       -- Result of pre-apply validation
    validation_passed BOOLEAN,

    -- Execution
    applied_by UUID REFERENCES users(id),
    applied_at TIMESTAMPTZ DEFAULT NOW(),
    apply_duration_ms INTEGER,
    success BOOLEAN,
    error_message TEXT,

    -- Rendered Config
    rendered_nginx_config TEXT                  -- The actual nginx config generated
);
```

---

## Phase 2: Backend Handlers

### New File: `/backend/internal/api/traffic_handlers.go`

#### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/traffic/resources` | List all traffic resources |
| GET | `/traffic/resources/:id` | Get single resource with computed state |
| POST | `/traffic/resources` | Create new traffic resource |
| PUT | `/traffic/resources/:id` | Update traffic resource |
| DELETE | `/traffic/resources/:id` | Delete traffic resource |
| POST | `/traffic/resources/:id/apply` | Apply resource to agent |
| POST | `/traffic/resources/:id/dry-run` | Validate without applying |
| POST | `/traffic/resources/:id/rollback` | Rollback to previous state |
| GET | `/traffic/resources/:id/history` | Get apply history |
| GET | `/traffic/policies` | List all policies |
| GET | `/traffic/policies/:id` | Get single policy |
| POST | `/traffic/policies` | Create policy |
| PUT | `/traffic/policies/:id` | Update policy |
| DELETE | `/traffic/policies/:id` | Delete policy |
| POST | `/traffic/policies/:id/assign` | Assign policy to resource |
| DELETE | `/traffic/policies/:id/assign/:assignment_id` | Remove assignment |
| GET | `/traffic/upstreams` | List upstreams |
| POST | `/traffic/upstreams` | Create upstream |
| GET | `/traffic/upstreams/:id/health` | Get upstream health status |

### Key Functions

```go
// traffic_handlers.go

// compileTrafficResource generates nginx config from TrafficResource
func (h *Handler) compileTrafficResource(ctx context.Context, resource *TrafficResource) (*CompiledConfig, error) {
    // 1. Load associated upstreams
    // 2. Load associated policies
    // 3. Load TLS config
    // 4. Render nginx configuration
    // 5. Return compiled config with validation
}

// applyTrafficResource sends compiled config to agent
func (h *Handler) applyTrafficResource(c *gin.Context) {
    // 1. Load resource
    // 2. Compile config
    // 3. Validate (dry-run)
    // 4. Send to agent via websocket
    // 5. Wait for confirmation
    // 6. Update applied_state
    // 7. Record in history
}

// validateTrafficResource performs dry-run validation
func (h *Handler) validateTrafficResource(c *gin.Context) {
    // 1. Compile config
    // 2. Run nginx -t simulation
    // 3. Check for conflicts with other resources
    // 4. Return validation result
}
```

---

## Phase 3: Frontend UI

### New/Updated Pages

#### 1. `/app/(dashboard)/traffic/page.tsx` - Traffic Dashboard
- Overview of all traffic resources
- Health status of upstreams
- Policy compliance summary
- Recent changes/deployments

#### 2. `/app/(dashboard)/traffic/resources/page.tsx` - Resource List
- Table of all traffic resources
- Status badges (draft/pending/active/error)
- Quick actions (apply, dry-run, disable)

#### 3. `/app/(dashboard)/traffic/resources/[id]/page.tsx` - Resource Detail
- Domain/path configuration
- Upstream configuration with health
- Assigned policies
- TLS settings
- Apply history timeline
- Diff view for pending changes

#### 4. `/app/(dashboard)/traffic/policies/page.tsx` - Policy Library
- All policy templates
- Policy types filter
- Assignment count per policy

#### 5. `/app/(dashboard)/traffic/create/page.tsx` - Create Wizard
- Step 1: Basic info (name, domains)
- Step 2: Upstream configuration
- Step 3: Policy selection
- Step 4: TLS configuration
- Step 5: Review & dry-run

### UI Components

```tsx
// TrafficResourceCard.tsx - Summary card for resource list
// UpstreamHealthBadge.tsx - Visual health indicator
// PolicyChip.tsx - Policy type badge
// DiffViewer.tsx - Show config differences
// ApplyModal.tsx - Confirmation with dry-run results
// TimelineHistory.tsx - Apply history visualization
```

---

## Phase 4: Policy Types

### Built-in Policies

#### 1. Rate Limiting (`rate_limit`)
```json
{
  "policy_type": "rate_limit",
  "config": {
    "requests_per_second": 100,
    "requests_per_minute": 1000,
    "burst_size": 50,
    "key": "ip",  // "ip", "header:X-API-Key", "cookie:session"
    "exceeded_action": "reject",  // "reject", "throttle", "queue"
    "exceeded_status": 429
  }
}
```

#### 2. Bot Protection (`bot_protection`)
```json
{
  "policy_type": "bot_protection",
  "config": {
    "mode": "challenge",  // "block", "challenge", "monitor"
    "challenge_type": "js",  // "js", "captcha"
    "bot_score_threshold": 30,
    "allow_verified_bots": true,  // GoogleBot, BingBot
    "custom_rules": []
  }
}
```

#### 3. Geo Blocking (`geo_blocking`)
```json
{
  "policy_type": "geo_blocking",
  "config": {
    "mode": "allowlist",  // "allowlist", "blocklist"
    "countries": ["US", "CA", "GB"],
    "action": "block",  // "block", "challenge"
    "blocked_message": "Service not available in your region"
  }
}
```

#### 4. CAPTCHA Protection (`captcha`)
```json
{
  "policy_type": "captcha",
  "config": {
    "provider": "cloudflare_turnstile",  // "recaptcha_v2", "recaptcha_v3", "hcaptcha"
    "site_key": "...",
    "trigger": "always",  // "always", "suspicious", "rate_exceeded"
    "paths": ["/login", "/signup"],
    "exempt_paths": ["/api/*"]
  }
}
```

#### 5. IP Filtering (`ip_filtering`)
```json
{
  "policy_type": "ip_filtering",
  "config": {
    "mode": "blocklist",
    "rules": [
      {"cidr": "10.0.0.0/8", "action": "allow"},
      {"cidr": "192.168.0.0/16", "action": "allow"}
    ]
  }
}
```

#### 6. Header Transform (`header_transform`)
```json
{
  "policy_type": "header_transform",
  "config": {
    "request_headers": {
      "add": {"X-Forwarded-Proto": "https"},
      "remove": ["X-Debug"]
    },
    "response_headers": {
      "add": {"X-Frame-Options": "DENY"},
      "remove": []
    }
  }
}
```

---

## Phase 5: Agent Integration

### Updated Agent Protocol

```go
// Agent receives compiled traffic configuration
type TrafficApplyRequest struct {
    ResourceID      string            `json:"resource_id"`
    Action          string            `json:"action"`  // "apply", "validate", "remove"
    NginxConfig     string            `json:"nginx_config"`
    Upstreams       []UpstreamConfig  `json:"upstreams"`
    Certificates    []CertConfig      `json:"certificates"`
    ValidateOnly    bool              `json:"validate_only"`  // Dry-run
}

type TrafficApplyResponse struct {
    ResourceID      string    `json:"resource_id"`
    Success         bool      `json:"success"`
    ValidationOK    bool      `json:"validation_ok"`
    AppliedAt       time.Time `json:"applied_at"`
    Error           string    `json:"error,omitempty"`
    NginxTestOutput string    `json:"nginx_test_output,omitempty"`
}
```

### Agent Workflow

1. Receive `TrafficApplyRequest`
2. Write nginx config to staging location
3. Run `nginx -t -c /staging/nginx.conf`
4. If `validate_only`, return validation result
5. If validation passes:
   - Backup current config
   - Move staging to active
   - Run `nginx -s reload`
   - Verify nginx is running
6. Report result to backend

---

## Migration Path

### Phase 1: Coexistence (Week 1-2)
- New `traffic_resources` table alongside existing `proxy_hosts`
- Both systems can manage nginx (feature flag)
- Agent supports both protocols

### Phase 2: Migration Tool (Week 2-3)
- `/traffic/migrate` endpoint to convert `proxy_hosts` → `traffic_resources`
- Automatic policy creation from existing `rate_limits`
- Preserve all configuration

### Phase 3: Deprecation (Week 4+)
- New resources created via TrafficResource only
- `proxy_hosts` becomes read-only
- UI redirects to new traffic pages

---

## Implementation Order

### Iteration 1: Foundation
1. [ ] Migration 032: Create all new tables
2. [ ] Backend: Basic CRUD for traffic_resources
3. [ ] Backend: Basic CRUD for traffic_policies
4. [ ] Frontend: Traffic resources list page

### Iteration 2: Compilation
1. [ ] Backend: Nginx config compiler
2. [ ] Backend: Dry-run validation endpoint
3. [ ] Frontend: Resource detail page with config preview
4. [ ] Frontend: Create wizard

### Iteration 3: Policies
1. [ ] Backend: Policy assignment logic
2. [ ] Backend: Rate limit policy implementation
3. [ ] Backend: Bot protection policy implementation
4. [ ] Frontend: Policy library page

### Iteration 4: Apply & Health
1. [ ] Backend: Apply workflow with history
2. [ ] Agent: Updated protocol support
3. [ ] Backend: Upstream health checks
4. [ ] Frontend: Apply modal with dry-run

### Iteration 5: Migration
1. [ ] Backend: Migration tool from proxy_hosts
2. [ ] Frontend: Migration wizard
3. [ ] Documentation

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Breaking existing nginx configs | Dry-run validation before all applies |
| Agent compatibility | Version negotiation, fallback to old protocol |
| Data loss during migration | Full backup before migration, rollback capability |
| Performance impact | Async compilation, cached rendered configs |

---

## Success Metrics

- **Zero downtime** during migration
- **< 5 second** apply time for configuration changes
- **100% parity** with existing proxy_hosts features
- **Policy reuse** across 80%+ of traffic resources
