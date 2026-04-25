-- Migration: 044_nginx_analytics_timescale
-- Description: Create TimescaleDB hypertable for nginx access logs
-- Epic: Production-Grade Nginx Log Analytics System
-- Note: Uses Apache-licensed TimescaleDB features only (no continuous aggregates, compression, or retention policies)

-- =============================================================================
-- 1. Enable TimescaleDB Extension
-- =============================================================================
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- =============================================================================
-- 2. Create nginx_access_logs hypertable
-- =============================================================================
CREATE TABLE IF NOT EXISTS nginx_access_logs (
    time            TIMESTAMPTZ NOT NULL,
    org_id          UUID NOT NULL,
    agent_id        UUID NOT NULL,

    -- Client info
    client_ip       INET NOT NULL,

    -- Request info
    method          VARCHAR(10) NOT NULL,
    path            TEXT NOT NULL,
    query_string    TEXT,
    protocol        VARCHAR(20),

    -- Response info
    status_code     SMALLINT NOT NULL,
    response_bytes  BIGINT DEFAULT 0,
    response_time   DOUBLE PRECISION, -- in seconds

    -- Additional context
    host            TEXT,
    referer         TEXT,
    user_agent      TEXT,
    upstream        TEXT,

    -- Request ID for tracing (optional)
    request_id      TEXT
);

-- Convert to hypertable partitioned by day
SELECT create_hypertable(
    'nginx_access_logs',
    'time',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- =============================================================================
-- 3. Create indexes for common query patterns
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_nginx_logs_org_time
    ON nginx_access_logs (org_id, time DESC);

CREATE INDEX IF NOT EXISTS idx_nginx_logs_agent_time
    ON nginx_access_logs (agent_id, time DESC);

CREATE INDEX IF NOT EXISTS idx_nginx_logs_status
    ON nginx_access_logs (status_code, time DESC);

CREATE INDEX IF NOT EXISTS idx_nginx_logs_path
    ON nginx_access_logs (path, time DESC);

CREATE INDEX IF NOT EXISTS idx_nginx_logs_client_ip
    ON nginx_access_logs (client_ip, time DESC);

-- =============================================================================
-- 4. Create regular materialized views for analytics (refreshed manually/via cron)
-- Note: These replace continuous aggregates which require TSL license
-- =============================================================================

-- 1-minute stats view
CREATE MATERIALIZED VIEW IF NOT EXISTS nginx_stats_1m AS
SELECT
    time_bucket('1 minute', time) AS bucket,
    org_id,
    agent_id,
    COUNT(*) AS total_requests,
    COUNT(*) FILTER (WHERE status_code >= 200 AND status_code < 300) AS count_2xx,
    COUNT(*) FILTER (WHERE status_code >= 300 AND status_code < 400) AS count_3xx,
    COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS count_4xx,
    COUNT(*) FILTER (WHERE status_code >= 500) AS count_5xx,
    SUM(response_bytes) AS total_bytes,
    AVG(response_time) AS avg_response_time,
    MAX(response_time) AS max_response_time,
    MIN(response_time) AS min_response_time,
    COUNT(DISTINCT client_ip) AS unique_visitors
FROM nginx_access_logs
WHERE time > NOW() - INTERVAL '2 hours'
GROUP BY time_bucket('1 minute', time), org_id, agent_id
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_nginx_stats_1m_bucket ON nginx_stats_1m (bucket, org_id, agent_id);

-- 1-hour stats view
CREATE MATERIALIZED VIEW IF NOT EXISTS nginx_stats_1h AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    org_id,
    agent_id,
    COUNT(*) AS total_requests,
    COUNT(*) FILTER (WHERE status_code >= 200 AND status_code < 300) AS count_2xx,
    COUNT(*) FILTER (WHERE status_code >= 300 AND status_code < 400) AS count_3xx,
    COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS count_4xx,
    COUNT(*) FILTER (WHERE status_code >= 500) AS count_5xx,
    SUM(response_bytes) AS total_bytes,
    AVG(response_time) AS avg_response_time,
    MAX(response_time) AS max_response_time,
    MIN(response_time) AS min_response_time,
    COUNT(DISTINCT client_ip) AS unique_visitors
FROM nginx_access_logs
WHERE time > NOW() - INTERVAL '7 days'
GROUP BY time_bucket('1 hour', time), org_id, agent_id
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_nginx_stats_1h_bucket ON nginx_stats_1h (bucket, org_id, agent_id);

-- Daily stats view
CREATE MATERIALIZED VIEW IF NOT EXISTS nginx_stats_daily AS
SELECT
    time_bucket('1 day', time) AS bucket,
    org_id,
    agent_id,
    COUNT(*) AS total_requests,
    COUNT(*) FILTER (WHERE status_code >= 200 AND status_code < 300) AS count_2xx,
    COUNT(*) FILTER (WHERE status_code >= 300 AND status_code < 400) AS count_3xx,
    COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS count_4xx,
    COUNT(*) FILTER (WHERE status_code >= 500) AS count_5xx,
    SUM(response_bytes) AS total_bytes,
    AVG(response_time) AS avg_response_time,
    MAX(response_time) AS max_response_time,
    MIN(response_time) AS min_response_time,
    COUNT(DISTINCT client_ip) AS unique_visitors
FROM nginx_access_logs
WHERE time > NOW() - INTERVAL '90 days'
GROUP BY time_bucket('1 day', time), org_id, agent_id
WITH NO DATA;

CREATE UNIQUE INDEX IF NOT EXISTS idx_nginx_stats_daily_bucket ON nginx_stats_daily (bucket, org_id, agent_id);

-- Top paths view
CREATE MATERIALIZED VIEW IF NOT EXISTS nginx_top_paths_1h AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    org_id,
    agent_id,
    path,
    COUNT(*) AS request_count,
    SUM(response_bytes) AS total_bytes,
    AVG(response_time) AS avg_response_time,
    COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS count_4xx,
    COUNT(*) FILTER (WHERE status_code >= 500) AS count_5xx,
    COUNT(DISTINCT client_ip) AS unique_visitors
FROM nginx_access_logs
WHERE time > NOW() - INTERVAL '24 hours'
GROUP BY time_bucket('1 hour', time), org_id, agent_id, path
WITH NO DATA;

CREATE INDEX IF NOT EXISTS idx_nginx_top_paths_1h_bucket ON nginx_top_paths_1h (bucket, org_id, agent_id);

-- =============================================================================
-- 5. Create analytics configuration table
-- =============================================================================
CREATE TABLE IF NOT EXISTS nginx_analytics_config (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Retention settings (can override global)
    retention_days  INTEGER DEFAULT 90,

    -- Feature flags
    analytics_enabled BOOLEAN DEFAULT TRUE,
    real_time_enabled BOOLEAN DEFAULT TRUE,

    -- Sampling rate (1.0 = 100%, 0.1 = 10%)
    sampling_rate   DOUBLE PRECISION DEFAULT 1.0,

    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id)
);

-- Add trigger to update updated_at
CREATE OR REPLACE FUNCTION update_nginx_analytics_config_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_nginx_analytics_config_updated_at ON nginx_analytics_config;
CREATE TRIGGER trigger_nginx_analytics_config_updated_at
    BEFORE UPDATE ON nginx_analytics_config
    FOR EACH ROW
    EXECUTE FUNCTION update_nginx_analytics_config_updated_at();

-- =============================================================================
-- 6. Create function to refresh materialized views (call via cron/scheduler)
-- =============================================================================
CREATE OR REPLACE FUNCTION refresh_nginx_analytics_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY nginx_stats_1m;
    REFRESH MATERIALIZED VIEW CONCURRENTLY nginx_stats_1h;
    REFRESH MATERIALIZED VIEW CONCURRENTLY nginx_stats_daily;
    REFRESH MATERIALIZED VIEW CONCURRENTLY nginx_top_paths_1h;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 7. Create function to cleanup old data (call via cron/scheduler)
-- =============================================================================
CREATE OR REPLACE FUNCTION cleanup_old_nginx_logs(retention_interval INTERVAL DEFAULT INTERVAL '90 days')
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM nginx_access_logs WHERE time < NOW() - retention_interval;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
