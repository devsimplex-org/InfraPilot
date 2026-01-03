# EPIC-06: Enterprise SSO (SAML/OIDC/LDAP)

> **Status:** Planned
> **Priority:** P1 - High
> **Estimated Effort:** Large
> **Dependencies:** EPIC-05 (Enterprise Foundation)
> **License Feature:** `sso_saml`, `sso_oidc`, `sso_ldap`

## Overview

Implement enterprise Single Sign-On support with SAML 2.0, OpenID Connect (OIDC), and LDAP/Active Directory authentication. This is one of the most requested enterprise features.

## Goals

1. SAML 2.0 identity provider integration (Okta, Azure AD, etc.)
2. OIDC provider integration (Google Workspace, Auth0, etc.)
3. LDAP/Active Directory authentication
4. Just-in-time (JIT) user provisioning
5. Group-to-role mapping

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SSO Flow                              │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  User → InfraPilot Login → Choose SSO Provider           │
│                    ↓                                     │
│  ┌─────────────────────────────────────────────────────┐│
│  │  SAML Flow          OIDC Flow         LDAP Flow     ││
│  │  ────────           ─────────         ─────────     ││
│  │  1. AuthnRequest    1. /authorize     1. Bind       ││
│  │  2. Redirect to IdP 2. Redirect       2. Search     ││
│  │  3. User auth       3. User auth      3. Verify     ││
│  │  4. SAMLResponse    4. Callback       4. Get attrs  ││
│  │  5. Assertion       5. Token          5. Return     ││
│  └─────────────────────────────────────────────────────┘│
│                    ↓                                     │
│  JIT Provisioning → Create/Update User → Issue JWT      │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Database Schema

```sql
-- SSO Provider configurations
CREATE TABLE sso_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(20) NOT NULL, -- 'saml', 'oidc', 'ldap'
    enabled BOOLEAN DEFAULT true,

    -- SAML specific
    saml_entity_id VARCHAR(500),
    saml_sso_url VARCHAR(500),
    saml_certificate TEXT,
    saml_sign_requests BOOLEAN DEFAULT false,

    -- OIDC specific
    oidc_issuer VARCHAR(500),
    oidc_client_id VARCHAR(255),
    oidc_client_secret_encrypted TEXT,
    oidc_scopes VARCHAR(255) DEFAULT 'openid profile email',

    -- LDAP specific
    ldap_host VARCHAR(255),
    ldap_port INTEGER DEFAULT 389,
    ldap_use_tls BOOLEAN DEFAULT false,
    ldap_bind_dn VARCHAR(500),
    ldap_bind_password_encrypted TEXT,
    ldap_base_dn VARCHAR(500),
    ldap_user_filter VARCHAR(500) DEFAULT '(uid=%s)',
    ldap_group_filter VARCHAR(500),

    -- Common
    default_role VARCHAR(50) DEFAULT 'viewer',
    auto_create_users BOOLEAN DEFAULT true,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Group to role mappings
CREATE TABLE sso_role_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    external_group VARCHAR(255) NOT NULL, -- IdP group name
    role VARCHAR(50) NOT NULL,            -- InfraPilot role
    created_at TIMESTAMP DEFAULT NOW()
);

-- SSO sessions for tracking
CREATE TABLE sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    provider_id UUID NOT NULL REFERENCES sso_providers(id),
    external_id VARCHAR(255),  -- Subject ID from IdP
    session_index VARCHAR(255), -- SAML session index for SLO
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);
```

## Tasks

### Phase 1: SAML 2.0

#### Backend
- [ ] Create `internal/enterprise/sso/saml/` package
  - [ ] Service Provider (SP) metadata generation
  - [ ] AuthnRequest generation
  - [ ] SAMLResponse parsing and validation
  - [ ] Assertion signature verification
  - [ ] Attribute extraction (email, name, groups)
- [ ] Create SSO provider CRUD handlers
- [ ] Create SAML callback endpoint `/api/v1/auth/saml/callback`
- [ ] Create SAML metadata endpoint `/api/v1/auth/saml/metadata`
- [ ] Implement JIT user provisioning
- [ ] Implement group-to-role mapping

#### Frontend
- [ ] SSO provider management page
- [ ] SAML provider configuration form
- [ ] Metadata download button
- [ ] Test connection functionality
- [ ] Login page SSO button

### Phase 2: OpenID Connect

#### Backend
- [ ] Create `internal/enterprise/sso/oidc/` package
  - [ ] Discovery document fetching
  - [ ] Authorization URL generation
  - [ ] Token exchange
  - [ ] ID token validation
  - [ ] UserInfo endpoint fetching
- [ ] Create OIDC callback endpoint `/api/v1/auth/oidc/callback`
- [ ] OIDC configuration validation

#### Frontend
- [ ] OIDC provider configuration form
- [ ] Provider-specific presets (Google, Azure, Okta)
- [ ] Callback handling

### Phase 3: LDAP/Active Directory

#### Backend
- [ ] Create `internal/enterprise/sso/ldap/` package
  - [ ] LDAP connection pool
  - [ ] Bind authentication
  - [ ] User search
  - [ ] Group membership lookup
  - [ ] TLS/STARTTLS support
- [ ] Create LDAP auth endpoint `/api/v1/auth/ldap`
- [ ] LDAP connection testing

#### Frontend
- [ ] LDAP configuration form
- [ ] Connection test button
- [ ] User attribute mapping UI

## API Endpoints

| Method | Path | Description | Feature Gate |
|--------|------|-------------|--------------|
| GET | `/api/v1/sso/providers` | List SSO providers | `sso_*` |
| POST | `/api/v1/sso/providers` | Create SSO provider | `sso_*` |
| GET | `/api/v1/sso/providers/:id` | Get provider details | `sso_*` |
| PUT | `/api/v1/sso/providers/:id` | Update provider | `sso_*` |
| DELETE | `/api/v1/sso/providers/:id` | Delete provider | `sso_*` |
| POST | `/api/v1/sso/providers/:id/test` | Test connection | `sso_*` |
| GET | `/api/v1/sso/providers/:id/mappings` | Get role mappings | `sso_*` |
| POST | `/api/v1/sso/providers/:id/mappings` | Create role mapping | `sso_*` |
| DELETE | `/api/v1/sso/providers/:id/mappings/:mid` | Delete mapping | `sso_*` |
| GET | `/api/v1/auth/saml/metadata` | SAML SP metadata | `sso_saml` |
| POST | `/api/v1/auth/saml/callback` | SAML assertion consumer | `sso_saml` |
| GET | `/api/v1/auth/oidc/authorize` | OIDC authorization | `sso_oidc` |
| GET | `/api/v1/auth/oidc/callback` | OIDC callback | `sso_oidc` |
| POST | `/api/v1/auth/ldap` | LDAP authentication | `sso_ldap` |

## Libraries

```go
// SAML
"github.com/crewjam/saml"
"github.com/crewjam/saml/samlsp"

// OIDC
"github.com/coreos/go-oidc/v3/oidc"
"golang.org/x/oauth2"

// LDAP
"github.com/go-ldap/ldap/v3"
```

## UI Mockup

```
┌─────────────────────────────────────────────────────────┐
│  Settings → SSO Providers                    [+ Add]    │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 🔵 Okta (SAML)                          [Enabled]  │ │
│  │    Entity ID: https://okta.com/app/xxx             │ │
│  │    Last login: 2 hours ago                         │ │
│  │                              [Test] [Edit] [Delete]│ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 🟢 Google Workspace (OIDC)              [Enabled]  │ │
│  │    Client ID: xxx.apps.googleusercontent.com       │ │
│  │    Last login: 30 minutes ago                      │ │
│  │                              [Test] [Edit] [Delete]│ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 🟡 Active Directory (LDAP)             [Disabled]  │ │
│  │    Server: ldap.corp.example.com:636               │ │
│  │    TLS: Enabled                                    │ │
│  │                              [Test] [Edit] [Delete]│ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Login Page with SSO

```
┌─────────────────────────────────────────────────────────┐
│                                                          │
│                    🚀 InfraPilot                        │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │  Email                                             │ │
│  │  [_____________________________________________]   │ │
│  │                                                    │ │
│  │  Password                                          │ │
│  │  [_____________________________________________]   │ │
│  │                                                    │ │
│  │  [          Sign In with Email/Password         ]  │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│                    ──── or ────                         │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │  [🔵 Sign in with Okta                          ]  │ │
│  │  [🟢 Sign in with Google                        ]  │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Testing

- [ ] Unit tests for SAML assertion parsing
- [ ] Unit tests for OIDC token validation
- [ ] Unit tests for LDAP authentication
- [ ] Integration tests with mock IdP
- [ ] E2E tests for full SSO flow

## Success Criteria

1. SAML login works with Okta, Azure AD, OneLogin
2. OIDC login works with Google, Auth0, Keycloak
3. LDAP login works with Active Directory
4. JIT provisioning creates users automatically
5. Group-to-role mapping applies correct permissions
6. SSO sessions can be revoked

## Notes

- Encrypted storage for client secrets and bind passwords
- Support for Single Logout (SLO) in SAML
- PKCE support for OIDC (security best practice)
- Connection pooling for LDAP performance
