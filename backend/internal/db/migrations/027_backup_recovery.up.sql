-- Epic 15: Backup & Recovery Visibility
-- Additional tables for backup job management, restoration history, and recovery testing

-- Backup Jobs: Track scheduled and manual backup executions
CREATE TABLE IF NOT EXISTS backup_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES backup_policies(id) ON DELETE SET NULL,
    database_id UUID REFERENCES database_inventory(id) ON DELETE CASCADE,

    -- Job identification
    job_type VARCHAR(50) NOT NULL DEFAULT 'scheduled',  -- 'scheduled', 'manual', 'emergency'
    triggered_by VARCHAR(255),  -- User who triggered manual backup

    -- Execution status
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending', 'running', 'completed', 'failed', 'cancelled', 'skipped'
    progress_percent INTEGER DEFAULT 0,
    current_step VARCHAR(100),

    -- Timing
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,

    -- Results
    backup_id UUID REFERENCES database_backups(id) ON DELETE SET NULL,
    error_message TEXT,
    error_code VARCHAR(50),
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,

    -- Logs
    log_output TEXT,
    warnings TEXT[],

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backup_jobs_org_id ON backup_jobs(org_id);
CREATE INDEX IF NOT EXISTS idx_backup_jobs_policy_id ON backup_jobs(policy_id);
CREATE INDEX IF NOT EXISTS idx_backup_jobs_database_id ON backup_jobs(database_id);
CREATE INDEX IF NOT EXISTS idx_backup_jobs_status ON backup_jobs(status);
CREATE INDEX IF NOT EXISTS idx_backup_jobs_scheduled_at ON backup_jobs(scheduled_at);

-- Restore Operations: Track backup restoration history
CREATE TABLE IF NOT EXISTS restore_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    backup_id UUID NOT NULL REFERENCES database_backups(id) ON DELETE CASCADE,
    source_database_id UUID NOT NULL REFERENCES database_inventory(id) ON DELETE CASCADE,

    -- Restore target
    target_type VARCHAR(50) NOT NULL DEFAULT 'existing',  -- 'existing', 'new', 'test_environment'
    target_database_id UUID REFERENCES database_inventory(id) ON DELETE SET NULL,
    target_name VARCHAR(255),
    target_host VARCHAR(255),
    target_port INTEGER,

    -- Restore options
    restore_type VARCHAR(50) NOT NULL DEFAULT 'full',  -- 'full', 'partial', 'point_in_time'
    point_in_time_target TIMESTAMPTZ,
    include_tables TEXT[],
    exclude_tables TEXT[],
    drop_existing BOOLEAN DEFAULT FALSE,

    -- Execution
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    triggered_by_email VARCHAR(255),
    reason TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending', 'running', 'completed', 'failed', 'cancelled', 'rollback'
    progress_percent INTEGER DEFAULT 0,
    current_step VARCHAR(100),

    -- Timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_seconds INTEGER,

    -- Results
    rows_restored BIGINT,
    tables_restored INTEGER,
    size_restored_bytes BIGINT,
    error_message TEXT,
    log_output TEXT,

    -- Verification
    verification_status VARCHAR(20),  -- 'pending', 'passed', 'failed', 'skipped'
    verification_checks JSONB DEFAULT '{}',

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_restore_operations_org_id ON restore_operations(org_id);
CREATE INDEX IF NOT EXISTS idx_restore_operations_backup_id ON restore_operations(backup_id);
CREATE INDEX IF NOT EXISTS idx_restore_operations_source_database_id ON restore_operations(source_database_id);
CREATE INDEX IF NOT EXISTS idx_restore_operations_status ON restore_operations(status);
CREATE INDEX IF NOT EXISTS idx_restore_operations_created_at ON restore_operations(created_at DESC);

-- Recovery Tests: Track disaster recovery testing
CREATE TABLE IF NOT EXISTS recovery_tests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    database_id UUID NOT NULL REFERENCES database_inventory(id) ON DELETE CASCADE,
    backup_id UUID REFERENCES database_backups(id) ON DELETE SET NULL,

    -- Test configuration
    test_type VARCHAR(50) NOT NULL DEFAULT 'restore',  -- 'restore', 'failover', 'switchover', 'full_dr'
    test_name VARCHAR(255),
    test_scenario TEXT,

    -- Execution
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    triggered_by_email VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending', 'running', 'passed', 'failed', 'cancelled'

    -- Timing
    scheduled_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Metrics
    actual_rto_seconds INTEGER,  -- Actual Recovery Time
    expected_rto_seconds INTEGER,  -- Expected RTO from policy
    actual_rpo_seconds INTEGER,  -- Actual data loss in seconds
    expected_rpo_seconds INTEGER,  -- Expected RPO from policy
    rto_met BOOLEAN,
    rpo_met BOOLEAN,

    -- Results
    test_environment VARCHAR(255),
    data_integrity_check BOOLEAN,
    application_connectivity_check BOOLEAN,
    performance_check BOOLEAN,

    -- Findings
    findings JSONB DEFAULT '[]',  -- Array of {severity, description, recommendation}
    error_message TEXT,
    notes TEXT,

    -- Approval (for scheduled tests)
    requires_approval BOOLEAN DEFAULT FALSE,
    approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recovery_tests_org_id ON recovery_tests(org_id);
CREATE INDEX IF NOT EXISTS idx_recovery_tests_database_id ON recovery_tests(database_id);
CREATE INDEX IF NOT EXISTS idx_recovery_tests_status ON recovery_tests(status);
CREATE INDEX IF NOT EXISTS idx_recovery_tests_scheduled_at ON recovery_tests(scheduled_at);

-- Backup Alerts: Track backup-related alerts
CREATE TABLE IF NOT EXISTS backup_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    database_id UUID REFERENCES database_inventory(id) ON DELETE CASCADE,
    backup_id UUID REFERENCES database_backups(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES backup_policies(id) ON DELETE CASCADE,

    -- Alert details
    alert_type VARCHAR(50) NOT NULL,  -- 'backup_failed', 'backup_missed', 'storage_warning', 'retention_expiring', 'verification_failed', 'rpo_breach'
    severity VARCHAR(20) NOT NULL DEFAULT 'warning',  -- 'info', 'warning', 'critical'
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,

    -- Context
    context JSONB DEFAULT '{}',

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active',  -- 'active', 'acknowledged', 'resolved', 'snoozed'
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,

    -- Snooze
    snoozed_until TIMESTAMPTZ,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backup_alerts_org_id ON backup_alerts(org_id);
CREATE INDEX IF NOT EXISTS idx_backup_alerts_database_id ON backup_alerts(database_id);
CREATE INDEX IF NOT EXISTS idx_backup_alerts_status ON backup_alerts(status);
CREATE INDEX IF NOT EXISTS idx_backup_alerts_severity ON backup_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_backup_alerts_alert_type ON backup_alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_backup_alerts_created_at ON backup_alerts(created_at DESC);

-- Backup Storage: Track backup storage locations and quotas
CREATE TABLE IF NOT EXISTS backup_storage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Storage identification
    name VARCHAR(100) NOT NULL,
    storage_type VARCHAR(50) NOT NULL,  -- 'local', 's3', 'gcs', 'azure_blob', 'nfs'
    location VARCHAR(500) NOT NULL,

    -- Configuration
    is_primary BOOLEAN DEFAULT FALSE,
    is_offsite BOOLEAN DEFAULT FALSE,
    encryption_enabled BOOLEAN DEFAULT TRUE,
    compression_enabled BOOLEAN DEFAULT TRUE,

    -- Credentials reference (stored securely elsewhere)
    credentials_secret_name VARCHAR(255),

    -- Capacity
    total_capacity_bytes BIGINT,
    used_bytes BIGINT DEFAULT 0,
    reserved_bytes BIGINT DEFAULT 0,
    warning_threshold_percent INTEGER DEFAULT 80,
    critical_threshold_percent INTEGER DEFAULT 95,

    -- Health
    status VARCHAR(20) DEFAULT 'healthy',  -- 'healthy', 'degraded', 'unreachable', 'full'
    last_health_check TIMESTAMPTZ,
    last_health_error TEXT,

    -- Metrics
    backup_count INTEGER DEFAULT 0,
    oldest_backup_at TIMESTAMPTZ,
    newest_backup_at TIMESTAMPTZ,

    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_backup_storage_org_id ON backup_storage(org_id);
CREATE INDEX IF NOT EXISTS idx_backup_storage_storage_type ON backup_storage(storage_type);
CREATE INDEX IF NOT EXISTS idx_backup_storage_status ON backup_storage(status);

-- View: Backup overview summary
CREATE OR REPLACE VIEW v_backup_overview AS
SELECT
    org_id,
    COUNT(DISTINCT database_id) as databases_with_backups,
    COUNT(*) as total_backups,
    COUNT(*) FILTER (WHERE status = 'completed') as successful_backups,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_backups,
    COUNT(*) FILTER (WHERE completed_at > NOW() - INTERVAL '24 hours') as backups_last_24h,
    COUNT(*) FILTER (WHERE completed_at > NOW() - INTERVAL '7 days') as backups_last_7d,
    SUM(size_bytes) as total_backup_size,
    MAX(completed_at) as last_backup_at,
    AVG(duration_seconds) FILTER (WHERE status = 'completed') as avg_backup_duration_seconds
FROM database_backups
GROUP BY org_id;

-- View: Recovery readiness summary
CREATE OR REPLACE VIEW v_recovery_readiness AS
SELECT
    di.org_id,
    di.id as database_id,
    di.name as database_name,
    di.db_type,
    di.data_classification,
    (SELECT MAX(db.completed_at) FROM database_backups db WHERE db.database_id = di.id AND db.status = 'completed') as last_successful_backup,
    (SELECT MAX(rt.completed_at) FROM recovery_tests rt WHERE rt.database_id = di.id AND rt.status = 'passed') as last_successful_test,
    (SELECT rt.actual_rto_seconds FROM recovery_tests rt WHERE rt.database_id = di.id AND rt.status = 'passed' ORDER BY rt.completed_at DESC LIMIT 1) as last_rto_seconds,
    (SELECT rt.actual_rpo_seconds FROM recovery_tests rt WHERE rt.database_id = di.id AND rt.status = 'passed' ORDER BY rt.completed_at DESC LIMIT 1) as last_rpo_seconds,
    (SELECT COUNT(*) FROM recovery_tests rt WHERE rt.database_id = di.id AND rt.completed_at > NOW() - INTERVAL '90 days') as tests_last_90d,
    CASE
        WHEN NOT EXISTS (SELECT 1 FROM database_backups db WHERE db.database_id = di.id AND db.status = 'completed')
        THEN 'no_backup'
        WHEN NOT EXISTS (SELECT 1 FROM recovery_tests rt WHERE rt.database_id = di.id AND rt.status = 'passed' AND rt.completed_at > NOW() - INTERVAL '90 days')
        THEN 'untested'
        ELSE 'ready'
    END as readiness_status
FROM database_inventory di;

-- Comments
COMMENT ON TABLE backup_jobs IS 'Track scheduled and manual backup job executions';
COMMENT ON TABLE restore_operations IS 'History of backup restoration operations';
COMMENT ON TABLE recovery_tests IS 'Track disaster recovery testing results';
COMMENT ON TABLE backup_alerts IS 'Backup-related alerts and notifications';
COMMENT ON TABLE backup_storage IS 'Backup storage locations and configuration';
