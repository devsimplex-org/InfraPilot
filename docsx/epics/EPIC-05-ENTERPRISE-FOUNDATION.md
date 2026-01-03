# EPIC-05: Enterprise Foundation

> **Status:** In Progress
> **Priority:** P0 - Critical Path
> **Estimated Effort:** Medium
> **Dependencies:** None (Foundation for all enterprise features)

## Overview

Implement the license validation system and feature gating infrastructure that enables all enterprise features. This is the foundation for the open-core model.

## Goals

1. Create offline license validation (Ed25519 signatures)
2. Implement centralized feature gates
3. Add license middleware for API requests
4. Create license info endpoint for UI
5. Support SaaS mode (always licensed)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    License Loading                       │
├─────────────────────────────────────────────────────────┤
│  1. INFRAPILOT_CLOUD=true → SaaS License (all features) │
│  2. INFRAPILOT_LICENSE env → Parse & Validate           │
│  3. /etc/infrapilot/license.yaml → Parse & Validate     │
│  4. Default → Community Edition (no enterprise)         │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   License Struct                         │
├─────────────────────────────────────────────────────────┤
│  Edition:   community | enterprise                       │
│  Features:  map[string]bool (sso_saml, audit_unlimited) │
│  Limits:    MaxUsers, MaxAgents, MaxResources           │
│  ExpiresAt: time.Time                                   │
│  Signature: Ed25519 (verified with embedded public key) │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   Feature Gates                          │
├─────────────────────────────────────────────────────────┤
│  RequireFeature(ctx, "sso_saml") → error                │
│  CheckFeature(ctx, "sso_saml") → FeatureGateResult      │
│  RequireEnterprise(ctx) → error                         │
│  CheckLimit(ctx, "users", count) → bool                 │
└─────────────────────────────────────────────────────────┘
```

## Tasks

### Backend - License Package ✅

- [x] Create `internal/enterprise/license/license.go`
  - [x] License struct with Edition, Features, Limits, Signature
  - [x] Edition constants (Community, Enterprise)
  - [x] Feature constants (FeatureSSOSAML, FeatureMultiTenant, etc.)
  - [x] DefaultCommunityLicense() function
  - [x] DefaultSaaSLicense() function
  - [x] Init() with load order (cloud → env → file → default)
  - [x] ParseAndValidate() with Ed25519 signature verification
  - [x] SetCurrent() and Current() for global access
  - [x] Context helpers (WithContext, FromContext)

- [x] Create `internal/enterprise/license/gate.go`
  - [x] RequireFeature() - returns error if not licensed
  - [x] CheckFeature() - returns FeatureGateResult (for UI)
  - [x] RequireEnterprise() - any enterprise license
  - [x] CheckLimit() - usage limit checking
  - [x] GetFeatureInfo() - all features with licensed status

- [x] Create `internal/enterprise/license/middleware.go`
  - [x] Middleware() - adds license to context, sets headers
  - [x] RequireFeatureMiddleware(feature) - route-level gate
  - [x] RequireEnterpriseMiddleware() - enterprise-only routes
  - [x] LicenseInfoHandler() - GET /api/v1/license

### Backend - Integration

- [ ] Wire license middleware into main router
- [ ] Add license info endpoint to routes
- [ ] Create enterprise route group with RequireEnterpriseMiddleware
- [ ] Add license init to main.go startup
- [ ] Add license status to health endpoint

### Backend - License Generation CLI

- [ ] Create `cmd/license-gen/main.go`
  - [ ] Generate Ed25519 key pair
  - [ ] Create signed license file
  - [ ] Validate existing license
  - [ ] List features available

### Frontend - License UI

- [ ] Add license types to api.ts
- [ ] Create license API methods (getLicenseInfo)
- [ ] Add license status to settings page
- [ ] Show enterprise feature badges in sidebar
- [ ] Create upgrade prompts for gated features
- [ ] Add license warning banner (expired/unlicensed)

### Documentation

- [ ] Update LICENSE file (Apache 2.0 for community)
- [ ] Create LICENSE-ENTERPRISE (BSL 1.1)
- [ ] Add license documentation to README

## Feature Constants

```go
const (
    FeatureSSOSAML       = "sso_saml"
    FeatureSSOOIDC       = "sso_oidc"
    FeatureSSOLDAP       = "sso_ldap"
    FeatureMultiTenant   = "multi_tenant"
    FeatureAuditUnlimited = "audit_unlimited"
    FeatureAuditExport   = "audit_export"
    FeatureAdvancedRBAC  = "advanced_rbac"
    FeatureCompliance    = "compliance_reports"
    FeatureHAClustering  = "ha_clustering"
    FeaturePrioritySupport = "priority_support"
)
```

## License File Format

```yaml
license:
  id: "lic_abc123"
  edition: "enterprise"
  organization: "Acme Corp"
  org_id: "00000000-0000-0000-0000-000000000001"

  features:
    sso_saml: true
    sso_oidc: true
    audit_unlimited: true
    multi_tenant: true

  limits:
    max_users: 100
    max_agents: 50
    max_resources: -1  # unlimited

  issued_at: "2026-01-03T00:00:00Z"
  expires_at: "2027-01-03T00:00:00Z"

  signature: "base64-encoded-ed25519-signature"
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/license` | Get current license info |
| GET | `/api/v1/license/features` | List all features with status |

## Response Headers

All API responses include:
- `X-InfraPilot-Edition: community|enterprise`
- `X-License-Status: community|valid|expired`

## Testing

- [ ] Unit tests for license parsing
- [ ] Unit tests for signature validation
- [ ] Unit tests for feature gates
- [ ] Integration test for middleware
- [ ] E2E test for license info endpoint

## Success Criteria

1. Community edition works without any license file
2. Enterprise features blocked with clear error messages
3. SaaS mode enables all features automatically
4. License expiry handled gracefully
5. UI shows appropriate upgrade prompts

## Files Created

- `backend/internal/enterprise/license/license.go` ✅
- `backend/internal/enterprise/license/gate.go` ✅
- `backend/internal/enterprise/license/middleware.go` ✅
- `backend/cmd/license-gen/main.go` (pending)

## Notes

- No license server required - offline validation only
- Public key embedded in binary during build
- Development mode skips signature validation (INFRAPILOT_DEV=true)
- Noisy, not blocky - features work but show warnings
