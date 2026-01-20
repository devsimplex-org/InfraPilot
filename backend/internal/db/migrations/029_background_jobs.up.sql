-- Epic 17: Background Jobs & Workers
-- Tables for tracking background jobs, scheduled tasks, and worker health

-- Background Jobs: Track all background job executions
CREATE TABLE IF NOT EXISTS background_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Job identification
    job_type VARCHAR(100) NOT NULL,  -- 'scan', 'backup', 'cleanup', 'sync', 'report', 'notification', 'maintenance'
    job_name VARCHAR(255) NOT NULL,
    job_category VARCHAR(50) NOT NULL DEFAULT 'system',  -- 'system', 'security', 'maintenance', 'user_triggered'

    -- Execution context
    triggered_by VARCHAR(100),  -- 'schedule', 'manual', 'webhook', 'event', 'system'
    triggered_by_user UUID REFERENCES users(id) ON DELETE SET NULL,
    triggered_by_email VARCHAR(255),

    -- Target
    target_type VARCHAR(50),  -- 'agent', 'deployment', 'container', 'database', 'global'
    target_id UUID,
    target_name VARCHAR(255),

    -- Parameters
    parameters JSONB DEFAULT '{}',

    -- Execution status
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- 'pending', 'queued', 'running', 'completed', 'failed', 'cancelled', 'timeout', 'retrying'
    priority INTEGER DEFAULT 0,  -- Higher = more priority
    progress_percent INTEGER DEFAULT 0,
    current_step VARCHAR(255),
    steps_total INTEGER DEFAULT 0,
    steps_completed INTEGER DEFAULT 0,

    -- Timing
    scheduled_at TIMESTAMPTZ,
    queued_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    timeout_seconds INTEGER DEFAULT 3600,
    deadline_at TIMESTAMPTZ,

    -- Results
    result JSONB,
    output TEXT,
    error_message TEXT,
    error_code VARCHAR(50),
    error_stack TEXT,

    -- Retry handling
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    retry_delay_seconds INTEGER DEFAULT 60,
    next_retry_at TIMESTAMPTZ,

    -- Worker assignment
    worker_id VARCHAR(100),
    worker_hostname VARCHAR(255),

    -- Metadata
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_background_jobs_org_id ON background_jobs(org_id);
CREATE INDEX IF NOT EXISTS idx_background_jobs_job_type ON background_jobs(job_type);
CREATE INDEX IF NOT EXISTS idx_background_jobs_status ON background_jobs(status);
CREATE INDEX IF NOT EXISTS idx_background_jobs_created_at ON background_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_background_jobs_scheduled_at ON background_jobs(scheduled_at);
CREATE INDEX IF NOT EXISTS idx_background_jobs_queued_pending ON background_jobs(status, priority DESC) WHERE status IN ('pending', 'queued');

-- Job Schedules: Define recurring job schedules
CREATE TABLE IF NOT EXISTS job_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Schedule identification
    name VARCHAR(100) NOT NULL,
    description TEXT,
    job_type VARCHAR(100) NOT NULL,
    job_name VARCHAR(255) NOT NULL,
    job_category VARCHAR(50) NOT NULL DEFAULT 'system',

    -- Target
    target_type VARCHAR(50),
    target_id UUID,
    target_name VARCHAR(255),

    -- Schedule
    cron_expression VARCHAR(100) NOT NULL,  -- Cron expression
    timezone VARCHAR(50) DEFAULT 'UTC',

    -- Job parameters
    parameters JSONB DEFAULT '{}',
    priority INTEGER DEFAULT 0,
    timeout_seconds INTEGER DEFAULT 3600,
    max_retries INTEGER DEFAULT 3,

    -- Execution tracking
    enabled BOOLEAN DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(20),
    last_run_duration_seconds INTEGER,
    next_run_at TIMESTAMPTZ,
    run_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    consecutive_failures INTEGER DEFAULT 0,

    -- Alerting
    alert_on_failure BOOLEAN DEFAULT TRUE,
    alert_after_consecutive_failures INTEGER DEFAULT 3,
    pause_after_failures INTEGER DEFAULT 5,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_job_schedules_org_id ON job_schedules(org_id);
CREATE INDEX IF NOT EXISTS idx_job_schedules_enabled ON job_schedules(enabled);
CREATE INDEX IF NOT EXISTS idx_job_schedules_next_run_at ON job_schedules(next_run_at) WHERE enabled = TRUE;

-- Workers: Track worker processes
CREATE TABLE IF NOT EXISTS workers (
    id VARCHAR(100) PRIMARY KEY,  -- Worker unique ID
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,  -- NULL = global worker

    -- Worker identification
    hostname VARCHAR(255) NOT NULL,
    worker_type VARCHAR(50) NOT NULL DEFAULT 'general',  -- 'general', 'scan', 'backup', 'heavy'
    version VARCHAR(50),
    pid INTEGER,

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'starting',  -- 'starting', 'idle', 'busy', 'stopping', 'stopped', 'unhealthy'
    current_job_id UUID REFERENCES background_jobs(id) ON DELETE SET NULL,
    jobs_processed INTEGER DEFAULT 0,
    jobs_failed INTEGER DEFAULT 0,

    -- Capacity
    max_concurrent_jobs INTEGER DEFAULT 1,
    current_jobs INTEGER DEFAULT 0,
    queue_size INTEGER DEFAULT 0,

    -- Health
    last_heartbeat_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ DEFAULT NOW(),
    stopped_at TIMESTAMPTZ,
    health_check_failures INTEGER DEFAULT 0,

    -- Resource usage
    cpu_percent DECIMAL(5, 2),
    memory_mb INTEGER,
    memory_percent DECIMAL(5, 2),

    -- Metadata
    capabilities TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workers_org_id ON workers(org_id);
CREATE INDEX IF NOT EXISTS idx_workers_status ON workers(status);
CREATE INDEX IF NOT EXISTS idx_workers_worker_type ON workers(worker_type);
CREATE INDEX IF NOT EXISTS idx_workers_last_heartbeat ON workers(last_heartbeat_at);

-- Job Dependencies: Define job execution dependencies
CREATE TABLE IF NOT EXISTS job_dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES background_jobs(id) ON DELETE CASCADE,
    depends_on_job_id UUID NOT NULL REFERENCES background_jobs(id) ON DELETE CASCADE,
    dependency_type VARCHAR(20) DEFAULT 'completion',  -- 'completion', 'success', 'start'
    created_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(job_id, depends_on_job_id)
);

CREATE INDEX IF NOT EXISTS idx_job_dependencies_job_id ON job_dependencies(job_id);
CREATE INDEX IF NOT EXISTS idx_job_dependencies_depends_on ON job_dependencies(depends_on_job_id);

-- Job Logs: Detailed logs for job execution
CREATE TABLE IF NOT EXISTS job_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    job_id UUID NOT NULL REFERENCES background_jobs(id) ON DELETE CASCADE,

    log_level VARCHAR(20) NOT NULL DEFAULT 'info',  -- 'debug', 'info', 'warn', 'error'
    message TEXT NOT NULL,
    details JSONB,

    logged_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_job_logs_job_id ON job_logs(job_id);
CREATE INDEX IF NOT EXISTS idx_job_logs_logged_at ON job_logs(logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_job_logs_level ON job_logs(log_level);

-- View: Job statistics summary
CREATE OR REPLACE VIEW v_job_statistics AS
SELECT
    org_id,
    job_type,
    COUNT(*) as total_jobs,
    COUNT(*) FILTER (WHERE status = 'completed') as completed_jobs,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_jobs,
    COUNT(*) FILTER (WHERE status = 'running') as running_jobs,
    COUNT(*) FILTER (WHERE status IN ('pending', 'queued')) as pending_jobs,
    COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as jobs_last_24h,
    AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) FILTER (WHERE completed_at IS NOT NULL AND started_at IS NOT NULL) as avg_duration_seconds,
    MAX(completed_at) as last_completed_at
FROM background_jobs
GROUP BY org_id, job_type;

-- View: Worker summary
CREATE OR REPLACE VIEW v_worker_summary AS
SELECT
    COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid) as org_id,
    COUNT(*) as total_workers,
    COUNT(*) FILTER (WHERE status = 'idle') as idle_workers,
    COUNT(*) FILTER (WHERE status = 'busy') as busy_workers,
    COUNT(*) FILTER (WHERE status = 'unhealthy' OR last_heartbeat_at < NOW() - INTERVAL '5 minutes') as unhealthy_workers,
    SUM(jobs_processed) as total_jobs_processed,
    SUM(jobs_failed) as total_jobs_failed,
    AVG(cpu_percent) as avg_cpu_percent,
    AVG(memory_percent) as avg_memory_percent
FROM workers
WHERE status != 'stopped'
GROUP BY COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid);

-- Comments
COMMENT ON TABLE background_jobs IS 'Track all background job executions';
COMMENT ON TABLE job_schedules IS 'Define recurring job schedules';
COMMENT ON TABLE workers IS 'Track worker processes and health';
COMMENT ON TABLE job_dependencies IS 'Define job execution dependencies';
COMMENT ON TABLE job_logs IS 'Detailed logs for job execution';
