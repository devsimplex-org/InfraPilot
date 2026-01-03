# InfraPilot Enterprise Plan

## Executive Summary

**InfraPilot sells trust, governance, and convenience — not code.**

We follow an Open Core model where:
- **Community Edition** is fully open source (Apache 2.0)
- **Enterprise Edition** is source-visible but commercially licensed (BSL)
- **SaaS** is our primary revenue driver and real moat

The code is open. The value is in the managed service, compliance guarantees, and enterprise support. This is company architecture, not just a technical decision.

---

## Core Decisions (Validated)

| Decision | Status |
|----------|--------|
| Single repository | ✅ Confirmed |
| Open-core model | ✅ Confirmed |
| Enterprise code visible | ✅ Confirmed |
| SaaS as primary monetization | ✅ Confirmed |
| No mandatory licensing server | ✅ Confirmed |
| Offline license validation | ✅ Confirmed |
| Forks accepted as reality | ✅ Confirmed |

---

## Business Models Comparison

| Model | Code Visible? | Revenue Source | Examples |
|-------|---------------|----------------|----------|
| **Open Core (our choice)** | Yes (both editions) | SaaS, Support, License keys | GitLab, Sentry |
| Dual License | Community open, Enterprise closed | License sales | MongoDB (old) |
| Pure Open Source | Yes | Donations, Support only | Linux, PostgreSQL |

---

## How Others Do It (Accurate)

### GitLab (Our Closest Model)

- **Community Edition (CE)**: MIT license, fully open source
- **Enterprise Edition (EE)**: Proprietary license, source visible in same repo
- Enterprise features gated by license key
- SaaS at gitlab.com is primary revenue

### Sentry

- **Self-hosted**: BSL license, source available
- **SaaS**: sentry.io, primary revenue driver
- After 3 years, code converts to Apache 2.0

### Odoo (Corrected)

- **Community**: LGPL, fully open source
- **Enterprise**: Source-available under commercial license (NOT open source)
- **SaaS (Odoo Online/Odoo.sh)**: Fully proprietary service, primary revenue
- Revenue: SaaS + Enterprise licenses + Implementation services

> Odoo uses an open-core model: Community is LGPL, Enterprise is source-available under a commercial license, and SaaS is the primary revenue driver.

### Our Approach

Like **GitLab/Sentry hybrid**:
1. Single repo, all code visible
2. Community = Apache 2.0 (truly open source)
3. Enterprise = BSL (source-visible, not open source — becomes Apache after 4 years)
4. SaaS as primary revenue
5. Self-hosted enterprise licenses for those who need it

---

## Why We Do Not Prevent Forks

### The Reality

> "What if someone clones the repo and removes license checks?"

**They can. And we don't try to stop them.**

### Why This Is Okay

1. **Legal protection is sufficient**
   - BSL license prohibits production use without license
   - Companies that matter (enterprise customers) won't risk legal exposure

2. **Forks self-select out of our ICP**
   - If a company runs a forked control plane for production infra:
     - They won't buy support
     - They won't pass compliance audits
     - They won't scale safely
   - These are not our customers anyway

3. **SaaS is the real moat**
   - They can fork the code
   - They cannot fork our cloud infrastructure
   - They cannot fork our uptime guarantees
   - They cannot fork our compliance certifications

4. **Technical DRM creates more problems than it solves**
   - Phone-home breaks air-gapped deployments
   - Obfuscation breaks trust with enterprise security teams
   - Heavy-handed enforcement drives away legitimate users

### Our Approach: Noisy, Not Blocky

When enterprise features are used without a valid license:

| Response | Description |
|----------|-------------|
| UI warning banner | Visible reminder, doesn't block |
| Audit log entry | Creates compliance trail |
| API response header | `X-License-Status: unlicensed` |
| Degraded mode | Feature works but with limits |

This is how GitLab, Sentry, and Odoo handle it.

---

## How We Ship: Community vs Enterprise

### Single Repository Structure

```
infrapilot/
├── internal/
│   ├── core/           # Community features (Apache 2.0)
│   ├── enterprise/     # Enterprise features (BSL - source-visible, NOT Apache)
│   │   ├── sso/
│   │   ├── audit/
│   │   ├── rbac-advanced/
│   │   └── multi-tenant/
│   └── license/        # License validation
├── LICENSE             # Apache 2.0 (Community)
├── LICENSE-ENTERPRISE  # BSL (Enterprise)
```

### Feature Flags Implementation

```go
// internal/license/license.go
type License struct {
    Edition     string
    Features    map[string]bool
    ExpiresAt   time.Time
    MaxAgents   int
    Signature   string
}

// Load from env var or license file
func LoadLicense() (*License, error) {
    // 1. Check INFRAPILOT_LICENSE env var
    // 2. Check /etc/infrapilot/license.yaml
    // 3. Fall back to Community edition
}
```

### Centralized Feature Gates

```go
// internal/license/gate.go
func RequireFeature(ctx context.Context, feature string) error {
    lic := FromContext(ctx)
    if !lic.Features[feature] {
        // Log it (audit trail)
        audit.Log(ctx, "enterprise_feature_blocked", feature)
        return ErrEnterpriseRequired
    }
    return nil
}

// Usage everywhere:
func (h *AuthHandler) HandleSAMLLogin(c *gin.Context) {
    if err := license.RequireFeature(c, "sso_saml"); err != nil {
        c.JSON(403, gin.H{
            "error": "SAML SSO requires Enterprise license",
            "code":  "ENTERPRISE_REQUIRED",
        })
        return
    }
    // ... SAML logic
}
```

### SaaS Uses Same Code

```go
// In SaaS environment, license is always valid
func init() {
    if os.Getenv("INFRAPILOT_CLOUD") == "true" {
        // We control this environment
        license.SetDefault(&License{
            Edition:  "enterprise",
            Features: AllFeatures(),
            // Never expires in our cloud
        })
    }
}
```

---

## Feature Split: Community vs Enterprise

### Community (Free, Apache 2.0)

| Feature | Description |
|---------|-------------|
| Core Infrastructure Management | AWS, GCP, Azure basics |
| Basic RBAC | Admin, User, Viewer roles |
| Single Organization | One org per instance |
| API Access | Full REST/gRPC API |
| Basic Audit Logs | 7-day retention |
| Community Support | GitHub Issues, Discord |
| Self-hosted | Deploy anywhere |
| **Agents** | Always open source, forever |

### Enterprise (Licensed, BSL)

| Feature | Description |
|---------|-------------|
| Advanced SSO | SAML, OIDC, LDAP |
| Multi-tenancy | Multiple organizations |
| Advanced RBAC | Custom roles, permissions |
| Audit Logs Pro | Unlimited retention, export |
| Compliance Reports | SOC2, HIPAA |
| Priority Support | SLA, dedicated channels |
| Custom Integrations | Terraform, Pulumi, etc. |
| HA/Clustering | Multi-node deployment |

---

## Licensing Strategy

### License Format

```yaml
# license.yaml
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

  issued_at: "2026-01-03T00:00:00Z"
  expires_at: "2027-01-03T00:00:00Z"

  # Ed25519 signature (prevents tampering)
  signature: "base64-encoded-signature"
```

### Offline Validation (No Server Required)

```go
func ValidateLicense(data []byte) (*License, error) {
    var lic License
    yaml.Unmarshal(data, &lic)

    // Verify with embedded PUBLIC key
    pubKey := getEmbeddedPublicKey()
    if !ed25519.Verify(pubKey, data, lic.Signature) {
        return nil, ErrInvalidSignature
    }

    if time.Now().After(lic.ExpiresAt) {
        return nil, ErrLicenseExpired
    }

    return &lic, nil
}
```

**Why this works:**
- License signed with our PRIVATE key (kept secret)
- App verifies with PUBLIC key (embedded in binary)
- Cannot forge without private key
- Works 100% offline

---

## SaaS Strategy (Primary Revenue)

### Why SaaS Is Our Moat

| Advantage | Description |
|-----------|-------------|
| **Cannot be pirated** | They use our servers |
| **Recurring revenue** | Predictable monthly/annual |
| **Lower barrier** | No self-hosting complexity |
| **Trust & compliance** | We handle security, audits |
| **Always updated** | No version fragmentation |

### SaaS Tiers

| Tier | Price | Users | Key Features |
|------|-------|-------|--------------|
| **Free** | $0 | 3 | Core features, community support |
| **Team** | $29/user/mo | 50 | SSO (Google), 30-day audit |
| **Business** | $79/user/mo | Unlimited | SAML/OIDC, unlimited audit, priority support |
| **Enterprise** | Custom | Unlimited | Dedicated instance, custom SLA, compliance reports |

---

## Protection Strategies Summary

| Strategy | Description | Effectiveness |
|----------|-------------|---------------|
| **Legal (BSL)** | License prohibits unlicensed production use | Protects against companies |
| **Social** | Community goodwill, contribution back | Works for most users |
| **Technical** | Signature verification, feature gates | Stops casual bypass |
| **SaaS (Primary)** | They can't self-host our cloud | 100% effective |

---

## Implementation Roadmap

### Phase 1: Foundation (Current)
- [x] Core platform working
- [x] Basic authentication
- [x] Single-tenant setup

### Phase 2: Enterprise Features
- [ ] License validation system (`internal/enterprise/license/`)
- [ ] Feature flag infrastructure
- [ ] SSO (SAML/OIDC)
- [ ] Advanced RBAC
- [ ] Audit logging with retention policies

### Phase 3: SaaS Platform
- [ ] Multi-tenant architecture
- [ ] Billing integration (Stripe)
- [ ] Usage metering
- [ ] Self-service signup
- [ ] Subscription management

### Phase 4: Enterprise Sales
- [ ] License generation portal
- [ ] Customer portal
- [ ] Support ticketing integration
- [ ] SLA monitoring

---

## What to Implement First

### Step 1: Add License Object

```go
// internal/enterprise/license/license.go
type License struct {
    Edition     string
    Features    map[string]bool
    ExpiresAt   time.Time
    MaxAgents   int
}
```

Load from: env var → license file → default (community)

### Step 2: Centralized Feature Gates

```go
// internal/enterprise/license/gate.go
func RequireFeature(ctx context.Context, feature string) error {
    if !FromContext(ctx).Features[feature] {
        return errors.New("enterprise feature requires license")
    }
    return nil
}
```

### Step 3: Noisy Responses

- UI warning banner when unlicensed
- Audit log entries for blocked features
- Clear API error messages: `"code": "ENTERPRISE_REQUIRED"`

### Step 4: SaaS Environment

- Same codebase
- License always valid (we control it)
- This is the real moat

---

## Quick Reference

| Question | Answer |
|----------|--------|
| Is enterprise code open source? | No. Source-visible under BSL, not Apache |
| Can we SaaS? | Yes, primary revenue model |
| Need license server? | No, offline Ed25519 validation |
| What if code is forked? | Legal protection + SaaS is the moat |
| How to ship enterprise? | Feature flags in single repo |
| What about piracy? | Don't overthink it. SaaS + governance is the value |

---

## The Mental Anchor

> **InfraPilot sells trust, governance, and convenience — not code.**

Once you internalize this, the "what if someone clones it?" fear disappears.

Our customers pay for:
- Managed infrastructure they don't have to run
- Compliance certifications they don't have to obtain
- Support SLAs they can rely on
- Updates they don't have to manage

The code being visible is a feature, not a bug. It builds trust with enterprise security teams who want to audit what runs in their infrastructure.

---

## Next Steps

1. **Create `internal/enterprise/license/`** - License loading and validation
2. **Define feature constants** - `sso_saml`, `audit_unlimited`, etc.
3. **Add `RequireFeature()` gates** - Centralized, consistent
4. **Create `LICENSE-ENTERPRISE`** - BSL 1.1 terms
5. **Set up Stripe** - For SaaS billing
6. **Build license generation CLI** - For enterprise customers
