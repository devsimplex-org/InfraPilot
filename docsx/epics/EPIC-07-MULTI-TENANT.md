# EPIC-07: Multi-Tenancy

> **Status:** Planned
> **Priority:** P1 - High
> **Estimated Effort:** Large
> **Dependencies:** EPIC-05 (Enterprise Foundation)
> **License Feature:** `multi_tenant`

## Overview

Enable true multi-tenancy where a single InfraPilot instance can serve multiple organizations with complete data isolation. Essential for SaaS deployment and enterprise customers with multiple business units.

## Goals

1. Complete data isolation between organizations
2. Organization management (create, update, delete)
3. User invitation and onboarding flow
4. Organization switching for users in multiple orgs
5. Per-organization billing and limits

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Multi-Tenant Architecture              │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │   Org A     │  │   Org B     │  │   Org C     │     │
│  │  ─────────  │  │  ─────────  │  │  ─────────  │     │
│  │  Users      │  │  Users      │  │  Users      │     │
│  │  Agents     │  │  Agents     │  │  Agents     │     │
│  │  Proxies    │  │  Proxies    │  │  Proxies    │     │
│  │  Alerts     │  │  Alerts     │  │  Alerts     │     │
│  │  Audit Logs │  │  Audit Logs │  │  Audit Logs │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│         │                │                │             │
│         └────────────────┼────────────────┘             │
│                          │                              │
│                          ▼                              │
│  ┌─────────────────────────────────────────────────────┐│
│  │              Shared Infrastructure                  ││
│  │  ─────────────────────────────────────────────────  ││
│  │  PostgreSQL (Row-Level Security)                    ││
│  │  Redis (Namespaced Keys)                            ││
│  │  API (org_id in JWT + RLS)                          ││
│  └─────────────────────────────────────────────────────┘│
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Database Schema

```sql
-- Organizations (already exists, may need updates)
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS
    subscription_tier VARCHAR(50) DEFAULT 'free',
    max_users INTEGER DEFAULT 3,
    max_agents INTEGER DEFAULT 1,
    features JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id),
    billing_email VARCHAR(255),
    logo_url VARCHAR(500);

-- Organization invitations
CREATE TABLE org_invitations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    token VARCHAR(255) NOT NULL UNIQUE,
    invited_by UUID NOT NULL REFERENCES users(id),
    expires_at TIMESTAMP NOT NULL,
    accepted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- User organization memberships (for multi-org users)
CREATE TABLE user_org_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    is_default BOOLEAN DEFAULT false,
    joined_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, org_id)
);

-- Row-Level Security policies
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE proxy_hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Example RLS policy
CREATE POLICY agents_org_isolation ON agents
    USING (org_id = current_setting('app.current_org_id')::uuid);
```

## Tasks

### Phase 1: Organization Management

#### Backend
- [ ] Create `internal/enterprise/tenant/` package
- [ ] Organization CRUD handlers
- [ ] Organization settings (logo, billing email)
- [ ] Subscription tier management
- [ ] Organization limits enforcement

#### Frontend
- [ ] Organization settings page
- [ ] Organization profile form (name, logo)
- [ ] Subscription tier display
- [ ] Usage statistics (users, agents count)

### Phase 2: User Invitations

#### Backend
- [ ] Invitation CRUD handlers
- [ ] Invitation email sending (via SMTP channel)
- [ ] Invitation acceptance endpoint
- [ ] Invitation expiry handling (7 days default)
- [ ] Resend invitation functionality

#### Frontend
- [ ] Team members page
- [ ] Invite user modal
- [ ] Pending invitations list
- [ ] Revoke invitation button
- [ ] Invitation acceptance page

### Phase 3: Multi-Organization Users

#### Backend
- [ ] User organization membership management
- [ ] Organization switching endpoint
- [ ] Default organization selection
- [ ] JWT updates with org_id claim

#### Frontend
- [ ] Organization switcher in header
- [ ] Organization list dropdown
- [ ] Set default organization
- [ ] Leave organization option

### Phase 4: Data Isolation

#### Backend
- [ ] PostgreSQL Row-Level Security (RLS) policies
- [ ] Middleware to set current_org_id
- [ ] Redis key namespacing
- [ ] Audit log isolation

#### Testing
- [ ] Isolation verification tests
- [ ] Cross-tenant access prevention tests

## API Endpoints

| Method | Path | Description | Feature Gate |
|--------|------|-------------|--------------|
| GET | `/api/v1/organizations` | List user's organizations | `multi_tenant` |
| POST | `/api/v1/organizations` | Create organization | `multi_tenant` |
| GET | `/api/v1/organizations/:id` | Get organization | `multi_tenant` |
| PUT | `/api/v1/organizations/:id` | Update organization | `multi_tenant` |
| DELETE | `/api/v1/organizations/:id` | Delete organization | `multi_tenant` |
| POST | `/api/v1/organizations/:id/switch` | Switch to organization | `multi_tenant` |
| GET | `/api/v1/organizations/:id/members` | List members | - |
| POST | `/api/v1/organizations/:id/invitations` | Send invitation | - |
| GET | `/api/v1/organizations/:id/invitations` | List invitations | - |
| DELETE | `/api/v1/organizations/:id/invitations/:iid` | Revoke invitation | - |
| POST | `/api/v1/invitations/:token/accept` | Accept invitation | - |
| GET | `/api/v1/organizations/:id/usage` | Get usage stats | - |

## UI Mockups

### Organization Switcher
```
┌─────────────────────────────────────────────────────────┐
│  ┌──────────────────┐                                   │
│  │ 🏢 Acme Corp  ▼  │                                   │
│  ├──────────────────┤                                   │
│  │ ✓ Acme Corp      │ ← Current                        │
│  │   Startup Inc    │                                   │
│  │   Personal       │                                   │
│  ├──────────────────┤                                   │
│  │ + Create New Org │                                   │
│  └──────────────────┘                                   │
└─────────────────────────────────────────────────────────┘
```

### Team Members Page
```
┌─────────────────────────────────────────────────────────┐
│  Settings → Team Members                   [+ Invite]   │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Members (5)                                            │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 👤 john@acme.com                  Admin    [Owner] │ │
│  │ 👤 jane@acme.com                  Admin    [Remove]│ │
│  │ 👤 bob@acme.com                   Operator [Remove]│ │
│  │ 👤 alice@acme.com                 Viewer   [Remove]│ │
│  │ 👤 charlie@acme.com               Viewer   [Remove]│ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  Pending Invitations (2)                                │
│  ┌────────────────────────────────────────────────────┐ │
│  │ ✉️ dave@acme.com      Viewer   Expires in 6 days   │ │
│  │                                   [Resend] [Revoke] │ │
│  │ ✉️ eve@acme.com       Operator Expires in 3 days   │ │
│  │                                   [Resend] [Revoke] │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Isolation Strategy

| Resource | Isolation Method |
|----------|------------------|
| Database tables | Row-Level Security (RLS) |
| Redis keys | Prefix with `org:{org_id}:` |
| File uploads | S3 prefix with org_id |
| API requests | JWT org_id claim + middleware |
| WebSocket | Room per org_id |

## Testing

- [ ] Unit tests for organization CRUD
- [ ] Unit tests for invitation flow
- [ ] Integration tests for RLS policies
- [ ] E2E test: create org → invite user → accept → verify access
- [ ] Security test: cross-tenant access attempts blocked

## Success Criteria

1. Users can create and manage multiple organizations
2. Users can be members of multiple organizations
3. Data is completely isolated between organizations
4. Invitations work end-to-end with email
5. Organization switching is seamless
6. Usage limits are enforced per organization

## Notes

- RLS must be thoroughly tested - any leak is critical
- Consider org deletion workflow (soft delete vs hard delete)
- Billing integration hooks for SaaS
- Rate limiting per organization
