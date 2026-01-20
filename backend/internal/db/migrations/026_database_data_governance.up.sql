-- Epic 14: Database & Data Governance
-- Tables for tracking database inventory, backups, and data governance

-- Database Inventory: Track all databases across the infrastructure
CREATE TABLE IF NOT EXISTS database_inventory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,

    -- Database identification
    name VARCHAR(255) NOT NULL,
    db_type VARCHAR(50) NOT NULL,  -- 'postgresql', 'mysql', 'mongodb', 'redis', 'elasticsearch'
    version VARCHAR(50),
    container_id VARCHAR(255),
    container_name VARCHAR(255),

    -- Connection info (non-sensitive)
    host VARCHAR(255),
    port INTEGER,
    database_name VARCHAR(255),

    -- Classification
    data_classification VARCHAR(50) DEFAULT 'internal',  -- 'public', 'internal', 'confidential', 'restricted'
    environment VARCHAR(50) DEFAULT 'production',  -- 'production', 'staging', 'development', 'testing'
    is_primary BOOLEAN DEFAULT TRUE,
    is_replica BOOLEAN DEFAULT FALSE,
    replica_of UUID REFERENCES database_inventory(id) ON DELETE SET NULL,

    -- Compliance flags
    pii_data BOOLEAN DEFAULT FALSE,
    pci_data BOOLEAN DEFAULT FALSE,
    hipaa_data BOOLEAN DEFAULT FALSE,
    gdpr_relevant BOOLEAN DEFAULT FALSE,

    -- Size & metrics
    size_bytes BIGINT,
    table_count INTEGER,
    active_connections INTEGER,
    max_connections INTEGER,

    -- Health & status
    status VARCHAR(20) DEFAULT 'healthy',  -- 'healthy', 'degraded', 'unhealthy', 'offline'
    last_health_check TIMESTAMPTZ,
    replication_lag_seconds INTEGER,

    -- Ownership
    owner_team VARCHAR(100),
    owner_contact VARCHAR(255),
    description TEXT,
    tags TEXT[] DEFAULT '{}',

    -- Discovery
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    auto_discovered BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for database_inventory
CREATE INDEX IF NOT EXISTS idx_database_inventory_org_id ON database_inventory(org_id);
CREATE INDEX IF NOT EXISTS idx_database_inventory_agent_id ON database_inventory(agent_id);
CREATE INDEX IF NOT EXISTS idx_database_inventory_db_type ON database_inventory(db_type);
CREATE INDEX IF NOT EXISTS idx_database_inventory_status ON database_inventory(status);
CREATE INDEX IF NOT EXISTS idx_database_inventory_data_classification ON database_inventory(data_classification);
CREATE INDEX IF NOT EXISTS idx_database_inventory_environment ON database_inventory(environment);

-- Database Backups: Track backup status and history
CREATE TABLE IF NOT EXISTS database_backups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    database_id UUID NOT NULL REFERENCES database_inventory(id) ON DELETE CASCADE,

    -- Backup identification
    backup_type VARCHAR(50) NOT NULL,  -- 'full', 'incremental', 'differential', 'snapshot', 'wal'
    backup_name VARCHAR(255),
    backup_path VARCHAR(500),

    -- Backup details
    size_bytes BIGINT,
    compressed_size_bytes BIGINT,
    compression_ratio DECIMAL(5, 2),
    encryption_enabled BOOLEAN DEFAULT FALSE,
    encryption_algorithm VARCHAR(50),

    -- Timing
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'running',  -- 'running', 'completed', 'failed', 'cancelled', 'verified'
    error_message TEXT,

    -- Retention
    retention_days INTEGER DEFAULT 30,
    expires_at TIMESTAMPTZ,
    is_offsite BOOLEAN DEFAULT FALSE,
    offsite_location VARCHAR(255),

    -- Verification
    last_verified_at TIMESTAMPTZ,
    verification_status VARCHAR(20),  -- 'verified', 'failed', 'pending'
    verification_notes TEXT,

    -- Recovery info
    recovery_point_objective_minutes INTEGER,
    recovery_time_objective_minutes INTEGER,
    can_point_in_time_restore BOOLEAN DEFAULT FALSE,
    earliest_restore_point TIMESTAMPTZ,
    latest_restore_point TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for database_backups
CREATE INDEX IF NOT EXISTS idx_database_backups_org_id ON database_backups(org_id);
CREATE INDEX IF NOT EXISTS idx_database_backups_database_id ON database_backups(database_id);
CREATE INDEX IF NOT EXISTS idx_database_backups_status ON database_backups(status);
CREATE INDEX IF NOT EXISTS idx_database_backups_started_at ON database_backups(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_database_backups_expires_at ON database_backups(expires_at);

-- Backup Policies: Define automated backup schedules
CREATE TABLE IF NOT EXISTS backup_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Target selection
    target_db_types TEXT[] DEFAULT '{}',  -- Empty = all types
    target_environments TEXT[] DEFAULT '{}',  -- Empty = all environments
    target_data_classifications TEXT[] DEFAULT '{}',  -- Empty = all classifications
    target_database_ids UUID[] DEFAULT '{}',  -- Specific databases

    -- Schedule
    backup_type VARCHAR(50) NOT NULL DEFAULT 'full',
    schedule_cron VARCHAR(100),  -- Cron expression
    timezone VARCHAR(50) DEFAULT 'UTC',

    -- Retention
    retention_days INTEGER DEFAULT 30,
    keep_weekly INTEGER DEFAULT 4,
    keep_monthly INTEGER DEFAULT 12,
    keep_yearly INTEGER DEFAULT 1,

    -- Options
    compression_enabled BOOLEAN DEFAULT TRUE,
    encryption_enabled BOOLEAN DEFAULT TRUE,
    verify_after_backup BOOLEAN DEFAULT TRUE,
    offsite_copy BOOLEAN DEFAULT FALSE,
    offsite_destination VARCHAR(255),

    -- Status
    enabled BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(20),

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_backup_policies_org_id ON backup_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_backup_policies_enabled ON backup_policies(enabled);

-- Database Access Audit: Track who accessed what
CREATE TABLE IF NOT EXISTS database_access_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    database_id UUID NOT NULL REFERENCES database_inventory(id) ON DELETE CASCADE,

    -- Access details
    access_type VARCHAR(50) NOT NULL,  -- 'read', 'write', 'admin', 'backup', 'restore'
    user_identifier VARCHAR(255),
    source_ip VARCHAR(45),
    client_app VARCHAR(255),

    -- Query info (optional, for sensitive tracking)
    query_type VARCHAR(50),  -- 'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DDL'
    tables_accessed TEXT[],
    rows_affected INTEGER,

    -- Timing
    accessed_at TIMESTAMPTZ DEFAULT NOW(),
    duration_ms INTEGER,

    -- Risk indicators
    is_anomalous BOOLEAN DEFAULT FALSE,
    anomaly_reason TEXT,
    risk_score INTEGER DEFAULT 0
);

-- Partitioning-friendly index
CREATE INDEX IF NOT EXISTS idx_database_access_audit_org_id ON database_access_audit(org_id, accessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_database_access_audit_database_id ON database_access_audit(database_id);
CREATE INDEX IF NOT EXISTS idx_database_access_audit_accessed_at ON database_access_audit(accessed_at DESC);
CREATE INDEX IF NOT EXISTS idx_database_access_audit_is_anomalous ON database_access_audit(is_anomalous) WHERE is_anomalous = TRUE;

-- View: Database posture summary
CREATE OR REPLACE VIEW v_database_posture AS
SELECT
    org_id,
    COUNT(*) as total_databases,
    COUNT(*) FILTER (WHERE status = 'healthy') as healthy_databases,
    COUNT(*) FILTER (WHERE status = 'degraded') as degraded_databases,
    COUNT(*) FILTER (WHERE status = 'unhealthy') as unhealthy_databases,
    COUNT(*) FILTER (WHERE pii_data = true) as pii_databases,
    COUNT(*) FILTER (WHERE data_classification = 'restricted') as restricted_databases,
    COUNT(*) FILTER (WHERE is_replica = true) as replica_count,
    SUM(size_bytes) as total_size_bytes
FROM database_inventory
GROUP BY org_id;

-- View: Backup compliance summary
CREATE OR REPLACE VIEW v_backup_compliance AS
SELECT
    di.org_id,
    di.id as database_id,
    di.name as database_name,
    di.db_type,
    di.data_classification,
    (SELECT MAX(db.completed_at) FROM database_backups db WHERE db.database_id = di.id AND db.status = 'completed') as last_backup_at,
    (SELECT COUNT(*) FROM database_backups db WHERE db.database_id = di.id AND db.status = 'completed' AND db.completed_at > NOW() - INTERVAL '24 hours') as backups_last_24h,
    (SELECT COUNT(*) FROM database_backups db WHERE db.database_id = di.id AND db.status = 'completed' AND db.completed_at > NOW() - INTERVAL '7 days') as backups_last_7d,
    CASE
        WHEN di.data_classification IN ('restricted', 'confidential') AND
             NOT EXISTS (SELECT 1 FROM database_backups db WHERE db.database_id = di.id AND db.status = 'completed' AND db.completed_at > NOW() - INTERVAL '24 hours')
        THEN 'non_compliant'
        WHEN di.data_classification = 'internal' AND
             NOT EXISTS (SELECT 1 FROM database_backups db WHERE db.database_id = di.id AND db.status = 'completed' AND db.completed_at > NOW() - INTERVAL '7 days')
        THEN 'warning'
        ELSE 'compliant'
    END as compliance_status
FROM database_inventory di;

-- Comments
COMMENT ON TABLE database_inventory IS 'Inventory of all databases across the infrastructure';
COMMENT ON TABLE database_backups IS 'History of database backups';
COMMENT ON TABLE backup_policies IS 'Automated backup policy definitions';
COMMENT ON TABLE database_access_audit IS 'Audit trail of database access events';
