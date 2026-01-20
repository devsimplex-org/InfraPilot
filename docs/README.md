# InfraPilot Documentation

> **Current Version**: v2.0 (in development)
> **v1 Status**: Complete (archived)

---

## Quick Navigation

| I want to... | Go to |
|--------------|-------|
| Understand v2.0 vision | [V2 Roadmap](v2/V2-ROADMAP.md) |
| See all epic specifications | [V2 Epics](v2/V2-EPICS.md) |
| Follow the implementation plan | [V2 Implementation Plan](v2/V2-IMPLEMENTATION-PLAN.md) |
| Reference v1 documentation | [V1 Archive](v1-archive/) |

---

## What is InfraPilot?

InfraPilot is the **local control plane** that gives small teams enterprise-grade visibility, security, and governance over everything they run in production — without complexity or lock-in.

### North Star

> InfraPilot governs everything that runs your business in production — services, traffic, data, access, and risk — without owning your cloud or your code.

---

## Documentation Structure

```
docs/
├── README.md                    # You are here
├── v2/                          # Active development (v2.0)
│   ├── V2-ROADMAP.md           # Strategic vision & epic overview
│   ├── V2-EPICS.md             # Consolidated epic specifications (v1+v2)
│   └── V2-IMPLEMENTATION-PLAN.md # Phased implementation plan
└── v1-archive/                  # Completed v1 documentation
    ├── V1-COMPLETION-STATUS.md  # v1 completion summary
    ├── ARCHITECTURE.md          # System architecture
    ├── DEVSECOPS-EPICS.md       # Original epic definitions
    ├── API-REFERENCE.md         # REST API documentation
    ├── DEVELOPMENT.md           # Developer setup
    ├── DEPLOYMENT.md            # Production deployment
    ├── CONFIGURATION.md         # Environment variables
    ├── TROUBLESHOOTING.md       # Common issues
    └── EPIC-*-IMPLEMENTATION-SUMMARY.md  # Detailed implementation docs
```

---

## Version Overview

### v1.0 (Complete)

**Focus**: Docker-native DevSecOps control plane

**Completed Epics** (11/12):
- Epic 0: DevSecOps Foundations
- Epic 1: Supply Chain Security (Trivy, SBOM)
- Epic 2: Policy-as-Code (OPA)
- Epic 3: Runtime Security (Drift Detection)
- Epic 4: Dev Integration (Webhooks)
- Epic 5: DevSecOps Observability
- Epic 6: Platform Hardening
- Epic 8: Developer Feedback (PR Comments)
- Epic 9: Risk Acceptance (Exceptions)
- Epic 10: Ownership & Accountability
- Epic 11: Security Maturity Scoring
- Epic 12: Code Quality Integration

**Stats**: 74+ API endpoints, 20+ database tables

### v2.0 (In Development)

**Focus**: Production infrastructure control plane

**New Epics** (8 planned):
- Epic 7: Research & Metrics Readiness (Optional)
- Epic 13: Traffic & Exposure Governance (HIGH)
- Epic 14: Database & Data Governance (HIGH)
- Epic 15: Backup & Recovery Visibility
- Epic 16: Secrets Hygiene
- Epic 17: Background Jobs & Workers
- Epic 18: External Dependency Mapping
- Epic 19: UX & Navigation System (HIGH)

**Stats**: 50+ new API endpoints, 14 new database tables

---

## Key v2.0 Documents

### [V2-ROADMAP.md](v2/V2-ROADMAP.md)

Strategic vision document covering:
- North star definition
- Epic grouping by layer (Build/Deploy/Run/Govern/Data)
- Priority rankings
- Success metrics
- Out-of-scope items

### [V2-EPICS.md](v2/V2-EPICS.md)

Consolidated epic specifications including:
- All v1 epics (marked complete with deliverables)
- All v2 epics (with database schemas, API specs, implementation details)
- Progress tracking table

### [V2-IMPLEMENTATION-PLAN.md](v2/V2-IMPLEMENTATION-PLAN.md)

Phased implementation plan covering:
- 6 implementation phases
- Sprint-level task breakdowns
- Acceptance criteria
- Risk mitigation
- Migration strategy
- Testing strategy

---

## Quick Reference

### v1 Technical Docs (Archived)

| Document | Description |
|----------|-------------|
| [Architecture](v1-archive/ARCHITECTURE.md) | System design, components, data flows |
| [API Reference](v1-archive/API-REFERENCE.md) | REST API endpoints |
| [Development](v1-archive/DEVELOPMENT.md) | Local dev setup |
| [Deployment](v1-archive/DEPLOYMENT.md) | Production deployment |
| [Configuration](v1-archive/CONFIGURATION.md) | Environment variables |
| [Troubleshooting](v1-archive/TROUBLESHOOTING.md) | Common issues |

### Epic Implementation Details (v1)

| Epic | Document |
|------|----------|
| 3 | [Runtime Security](v1-archive/EPIC-3-IMPLEMENTATION-SUMMARY.md) |
| 6 | [Platform Hardening](v1-archive/EPIC-6-IMPLEMENTATION-SUMMARY.md) |
| 8-9 | [Developer Feedback & Risk Exceptions](v1-archive/EPIC-8-9-IMPLEMENTATION-SUMMARY.md) |
| 10 | [Ownership & Accountability](v1-archive/EPIC-10-IMPLEMENTATION-SUMMARY.md) |
| 11 | [Security Maturity Scoring](v1-archive/EPIC-11-IMPLEMENTATION-SUMMARY.md) |
| 12 | [Code Quality Integration](v1-archive/EPIC-12-IMPLEMENTATION-SUMMARY.md) |

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Backend | Go + Gin |
| Frontend | Next.js + React |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Scanner | Trivy 0.68.2 |
| SBOM | Syft 1.40.0 |
| Policy Engine | OPA 1.12.2 |
| Proxy | Nginx |
| Container | Docker 24+ |

---

## Getting Started

### For Users

1. See [main README](../README.md) for quick start
2. Review [Deployment Guide](v1-archive/DEPLOYMENT.md) for production setup
3. Configure via [Configuration Reference](v1-archive/CONFIGURATION.md)

### For Developers

1. Read [V2 Roadmap](v2/V2-ROADMAP.md) to understand direction
2. Review [V2 Epics](v2/V2-EPICS.md) for implementation specs
3. Follow [V2 Implementation Plan](v2/V2-IMPLEMENTATION-PLAN.md) for tasks
4. Reference [Architecture](v1-archive/ARCHITECTURE.md) for system design
5. Use [Development Guide](v1-archive/DEVELOPMENT.md) for local setup

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 - see [LICENSE](../LICENSE)
