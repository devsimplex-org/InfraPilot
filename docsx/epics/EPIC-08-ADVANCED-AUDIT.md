# EPIC-08: Advanced Audit & Compliance

> **Status:** Planned
> **Priority:** P2 - Medium
> **Estimated Effort:** Medium
> **Dependencies:** EPIC-05 (Enterprise Foundation)
> **License Features:** `audit_unlimited`, `audit_export`, `compliance_reports`

## Overview

Enhance the audit logging system with unlimited retention, export capabilities, and compliance reporting features for enterprise customers.

## Goals

1. Unlimited audit log retention (enterprise)
2. Export to CSV, JSON, SIEM formats
3. Advanced search and filtering
4. Compliance report generation (SOC2, HIPAA)
5. External log forwarding (Splunk, ELK, etc.)

## Community vs Enterprise

| Feature | Community | Enterprise |
|---------|-----------|------------|
| Retention | 7 days | Unlimited |
| Export | None | CSV, JSON, CEF |
| Search | Basic | Full-text + filters |
| Forwarding | None | Syslog, HTTP, S3 |
| Reports | None | SOC2, HIPAA templates |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Audit Log Pipeline                      │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Action → Audit Handler → ┬→ PostgreSQL (primary)       │
│                           ├→ S3/MinIO (archive)         │
│                           └→ External (Splunk/ELK)      │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │              Enterprise Features                    │ │
│  ├────────────────────────────────────────────────────┤ │
│  │  • Unlimited retention (no auto-delete)            │ │
│  │  • Export to CSV/JSON/CEF                          │ │
│  │  • Forward to Splunk/ELK/S3                        │ │
│  │  • Compliance report generation                    │ │
│  │  • Full-text search with filters                   │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## Database Schema

```sql
-- Enhanced audit log (may already exist)
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS
    resource_name VARCHAR(255),
    old_value JSONB,
    new_value JSONB,
    source_ip INET,
    user_agent TEXT,
    session_id UUID,
    correlation_id UUID,
    severity VARCHAR(20) DEFAULT 'info';

-- Audit log retention settings
CREATE TABLE audit_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    retention_days INTEGER DEFAULT 7, -- -1 for unlimited (enterprise)
    forward_enabled BOOLEAN DEFAULT false,
    forward_type VARCHAR(50), -- 'syslog', 'http', 's3'
    forward_config JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Compliance report templates
CREATE TABLE compliance_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'soc2', 'hipaa', 'custom'
    date_range_start TIMESTAMP NOT NULL,
    date_range_end TIMESTAMP NOT NULL,
    generated_by UUID REFERENCES users(id),
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'generating', 'completed', 'failed'
    file_path VARCHAR(500),
    created_at TIMESTAMP DEFAULT NOW()
);
```

## Tasks

### Phase 1: Unlimited Retention

#### Backend
- [ ] Create retention policy system
- [ ] Modify cleanup job to respect enterprise setting
- [ ] Add retention_days to organization settings
- [ ] Background job for archiving old logs

#### Frontend
- [ ] Retention settings in admin panel
- [ ] Warning when approaching storage limits

### Phase 2: Export Functionality

#### Backend
- [ ] Create `internal/enterprise/audit/export/` package
- [ ] CSV export with date range
- [ ] JSON export with date range
- [ ] CEF (Common Event Format) export
- [ ] Background job for large exports
- [ ] Pre-signed download URLs

#### Frontend
- [ ] Export button in audit log viewer
- [ ] Format selection (CSV, JSON, CEF)
- [ ] Date range picker
- [ ] Export progress indicator
- [ ] Download link when ready

### Phase 3: External Forwarding

#### Backend
- [ ] Create `internal/enterprise/audit/forward/` package
- [ ] Syslog forwarding (RFC 5424)
- [ ] HTTP webhook forwarding
- [ ] S3 bucket forwarding
- [ ] Buffering and retry logic

#### Frontend
- [ ] Forwarding configuration UI
- [ ] Test connection button
- [ ] Forward status indicator

### Phase 4: Compliance Reports

#### Backend
- [ ] Create `internal/enterprise/compliance/` package
- [ ] SOC2 report template
- [ ] HIPAA report template
- [ ] PDF generation (go-pdf or wkhtmltopdf)
- [ ] Report scheduling

#### Frontend
- [ ] Compliance reports page
- [ ] Generate report wizard
- [ ] Report history and downloads
- [ ] Schedule recurring reports

## API Endpoints

| Method | Path | Description | Feature Gate |
|--------|------|-------------|--------------|
| GET | `/api/v1/audit/settings` | Get audit settings | - |
| PUT | `/api/v1/audit/settings` | Update retention/forward | `audit_unlimited` |
| POST | `/api/v1/audit/export` | Start export job | `audit_export` |
| GET | `/api/v1/audit/export/:id` | Get export status | `audit_export` |
| GET | `/api/v1/audit/export/:id/download` | Download export | `audit_export` |
| POST | `/api/v1/audit/forward/test` | Test forwarding | `audit_export` |
| GET | `/api/v1/compliance/reports` | List reports | `compliance_reports` |
| POST | `/api/v1/compliance/reports` | Generate report | `compliance_reports` |
| GET | `/api/v1/compliance/reports/:id` | Get report status | `compliance_reports` |
| GET | `/api/v1/compliance/reports/:id/download` | Download PDF | `compliance_reports` |

## Export Formats

### CSV
```csv
timestamp,user_email,action,resource_type,resource_id,source_ip,details
2026-01-03T10:00:00Z,admin@example.com,create,proxy_host,uuid-123,192.168.1.1,"{""domain"":""example.com""}"
```

### CEF (Common Event Format)
```
CEF:0|InfraPilot|InfraPilot|1.0|create|Proxy Created|3|src=192.168.1.1 suser=admin@example.com cs1=proxy_host cs2=uuid-123
```

## UI Mockups

### Export Modal
```
┌─────────────────────────────────────────────────────────┐
│  Export Audit Logs                              [X]     │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Date Range                                             │
│  [2026-01-01] to [2026-01-31]                          │
│                                                          │
│  Format                                                 │
│  ○ CSV (Excel compatible)                               │
│  ● JSON (Machine readable)                              │
│  ○ CEF (SIEM compatible)                                │
│                                                          │
│  Filters                                                │
│  Action:  [All Actions        ▼]                        │
│  User:    [All Users          ▼]                        │
│                                                          │
│  Estimated size: ~2.5 MB                                │
│                                                          │
│                          [Cancel]  [Start Export]       │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Compliance Reports
```
┌─────────────────────────────────────────────────────────┐
│  Compliance → Reports                     [+ Generate]  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 📋 SOC2 Report - Q4 2025                           │ │
│  │    Generated: 2026-01-02                           │ │
│  │    Period: Oct 1 - Dec 31, 2025                    │ │
│  │    Status: ✅ Completed            [Download PDF]  │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 📋 HIPAA Audit Trail - January 2026                │ │
│  │    Generated: 2026-01-03                           │ │
│  │    Period: Jan 1 - Jan 31, 2026                    │ │
│  │    Status: ⏳ Generating (45%)                     │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

## SOC2 Report Sections

1. **Access Control Summary**
   - User count and role distribution
   - MFA adoption rate
   - Failed login attempts

2. **Change Management**
   - Configuration changes by category
   - Approval workflows (if applicable)

3. **Incident Response**
   - Alert triggers and resolutions
   - Response times

4. **Data Integrity**
   - Audit log completeness
   - Backup verification (if applicable)

## Testing

- [ ] Unit tests for export formats
- [ ] Unit tests for forwarding
- [ ] Integration tests for S3/syslog
- [ ] E2E test: generate SOC2 report
- [ ] Performance test: export 1M+ records

## Success Criteria

1. Enterprise customers can retain logs indefinitely
2. Export works for date ranges up to 1 year
3. Forward to Splunk/ELK verified working
4. SOC2 report generates within 5 minutes
5. PDF reports are professional quality

## Notes

- Large exports run as background jobs
- Consider pagination for very large date ranges
- GDPR considerations for log retention
- Encryption for forwarded logs
