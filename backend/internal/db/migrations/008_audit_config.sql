-- Migration: 008_audit_config.sql
-- Enterprise Phase E4: Advanced Audit & Compliance

-- ============ Audit Configuration ============

CREATE TABLE audit_config (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Retention settings
    retention_days  INTEGER DEFAULT 90,              -- 0 = unlimited (enterprise)
    retention_policy VARCHAR(50) DEFAULT 'delete',   -- 'delete', 'archive', 'export'

    -- Forwarding settings
    forwarding_enabled BOOLEAN DEFAULT FALSE,
    forwarding_type    VARCHAR(50),                  -- 'syslog', 'webhook', 'splunk', 's3'
    forwarding_config  JSONB,                        -- Type-specific config

    -- Compliance settings
    compliance_mode    VARCHAR(50),                  -- 'soc2', 'hipaa', 'gdpr', 'pci', null
    immutable_logs     BOOLEAN DEFAULT FALSE,        -- Cannot delete once written
    hash_chain_enabled BOOLEAN DEFAULT FALSE,        -- Cryptographic integrity chain

    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id)
);

-- ============ Audit Exports ============

CREATE TABLE audit_exports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,

    format          VARCHAR(20) NOT NULL,            -- 'csv', 'json', 'cef', 'syslog'
    status          VARCHAR(20) DEFAULT 'pending',   -- 'pending', 'processing', 'completed', 'failed'

    -- Filters applied
    start_date      TIMESTAMPTZ,
    end_date        TIMESTAMPTZ,
    filters         JSONB,                           -- action, resource_type, user_id filters

    -- Result
    row_count       INTEGER,
    file_size       BIGINT,
    file_path       TEXT,                            -- S3 or local path
    download_url    TEXT,                            -- Pre-signed URL
    expires_at      TIMESTAMPTZ,                     -- Download URL expiry

    error_message   TEXT,

    created_at      TIMESTAMPTZ DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_audit_exports_org ON audit_exports(org_id, created_at DESC);

-- ============ Audit Forwarding Log ============

CREATE TABLE audit_forwarding_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    audit_log_id    UUID REFERENCES audit_logs(id) ON DELETE SET NULL,

    forwarded_at    TIMESTAMPTZ DEFAULT NOW(),
    destination     VARCHAR(255) NOT NULL,           -- syslog://host:514, https://webhook.example.com
    status          VARCHAR(20) DEFAULT 'sent',      -- 'sent', 'failed', 'retrying'
    retry_count     INTEGER DEFAULT 0,
    error_message   TEXT,

    -- For hash chain integrity
    log_hash        VARCHAR(64),                     -- SHA256 of log content
    prev_hash       VARCHAR(64)                      -- Hash of previous log (chain)
);

CREATE INDEX idx_forwarding_log_org ON audit_forwarding_log(org_id, forwarded_at DESC);
CREATE INDEX idx_forwarding_log_status ON audit_forwarding_log(status) WHERE status = 'failed';

-- ============ Compliance Reports ============

CREATE TABLE compliance_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,

    report_type     VARCHAR(50) NOT NULL,            -- 'soc2', 'hipaa', 'access', 'activity', 'security'
    status          VARCHAR(20) DEFAULT 'pending',   -- 'pending', 'generating', 'completed', 'failed'

    -- Report period
    start_date      DATE NOT NULL,
    end_date        DATE NOT NULL,

    -- Generated content
    summary         JSONB,                           -- Key metrics summary
    file_path       TEXT,                            -- Full report PDF/HTML
    download_url    TEXT,

    created_at      TIMESTAMPTZ DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

CREATE INDEX idx_compliance_reports_org ON compliance_reports(org_id, created_at DESC);

-- ============ Add hash column to audit_logs for integrity chain ============

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS log_hash VARCHAR(64);
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prev_hash VARCHAR(64);

-- ============ Update trigger ============

CREATE TRIGGER update_audit_config_updated_at
    BEFORE UPDATE ON audit_config
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
