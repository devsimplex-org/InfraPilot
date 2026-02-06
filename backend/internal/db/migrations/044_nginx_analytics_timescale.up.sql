-- Migration: 044_nginx_analytics_timescale
-- Description: Create TimescaleDB hypertable for nginx access logs with continuous aggregates
-- Epic: Production-Grade Nginx Log Analytics System

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
-- 4. Create 1-minute continuous aggregate for real-time dashboards
-- =============================================================================
CREATE MATERIALIZED VIEW IF NOT EXISTS nginx_stats_1m
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 minute', time) AS bucket,
    org_id,
    agent_id,

    -- Request counts by status code group
    COUNT(*) AS total_requests,
    COUNT(*) FILTER (WHERE status_code >= 200 AND status_code < 300) AS count_2xx,
    COUNT(*) FILTER (WHERE status_code >= 300 AND status_code < 400) AS count_3xx,
    COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS count_4xx,
    COUNT(*) FILTER (WHERE status_code >= 500) AS count_5xx,

    -- Bytes transferred
    SUM(response_bytes) AS total_bytes,

    -- Response time statistics
    AVG(response_time) AS avg_response_time,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time) AS p95_response_time,
    percentile_cont(0.99) WITHIN GROUP (ORDER BY response_time) AS p99_response_time,
    MAX(response_time) AS max_response_time,
    MIN(response_time) AS min_response_time,

    -- Unique visitors (approximate)
    COUNT(DISTINCT client_ip) AS unique_visitors
FROM nginx_access_logs
GROUP BY time_bucket('1 minute', time), org_id, agent_id
WITH NO DATA;

-- Add refresh policy: refresh every 30 seconds, start from 2 hours ago
SELECT add_continuous_aggregate_policy('nginx_stats_1m',
    start_offset => INTERVAL '2 hours',
    end_offset => INTERVAL '30 seconds',
    schedule_interval => INTERVAL '30 seconds',
    if_not_exists => TRUE
);

-- =============================================================================
-- 5. Create 1-hour continuous aggregate for historical dashboards
-- =============================================================================
CREATE MATERIALIZED VIEW IF NOT EXISTS nginx_stats_1h
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    org_id,
    agent_id,

    -- Request counts by status code group
    COUNT(*) AS total_requests,
    COUNT(*) FILTER (WHERE status_code >= 200 AND status_code < 300) AS count_2xx,
    COUNT(*) FILTER (WHERE status_code >= 300 AND status_code < 400) AS count_3xx,
    COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS count_4xx,
    COUNT(*) FILTER (WHERE status_code >= 500) AS count_5xx,

    -- Bytes transferred
    SUM(response_bytes) AS total_bytes,

    -- Response time statistics
    AVG(response_time) AS avg_response_time,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time) AS p95_response_time,
    percentile_cont(0.99) WITHIN GROUP (ORDER BY response_time) AS p99_response_time,
    MAX(response_time) AS max_response_time,
    MIN(response_time) AS min_response_time,

    -- Unique visitors (approximate)
    COUNT(DISTINCT client_ip) AS unique_visitors
FROM nginx_access_logs
GROUP BY time_bucket('1 hour', time), org_id, agent_id
WITH NO DATA;

-- Add refresh policy: refresh every 10 minutes
SELECT add_continuous_aggregate_policy('nginx_stats_1h',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '10 minutes',
    if_not_exists => TRUE
);

-- =============================================================================
-- 6. Create daily continuous aggregate for long-term trends
-- =============================================================================
CREATE MATERIALIZED VIEW IF NOT EXISTS nginx_stats_daily
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 day', time) AS bucket,
    org_id,
    agent_id,

    -- Request counts by status code group
    COUNT(*) AS total_requests,
    COUNT(*) FILTER (WHERE status_code >= 200 AND status_code < 300) AS count_2xx,
    COUNT(*) FILTER (WHERE status_code >= 300 AND status_code < 400) AS count_3xx,
    COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS count_4xx,
    COUNT(*) FILTER (WHERE status_code >= 500) AS count_5xx,

    -- Bytes transferred
    SUM(response_bytes) AS total_bytes,

    -- Response time statistics
    AVG(response_time) AS avg_response_time,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time) AS p95_response_time,
    percentile_cont(0.99) WITHIN GROUP (ORDER BY response_time) AS p99_response_time,
    MAX(response_time) AS max_response_time,
    MIN(response_time) AS min_response_time,

    -- Unique visitors (approximate)
    COUNT(DISTINCT client_ip) AS unique_visitors
FROM nginx_access_logs
GROUP BY time_bucket('1 day', time), org_id, agent_id
WITH NO DATA;

-- Add refresh policy: refresh daily at midnight
SELECT add_continuous_aggregate_policy('nginx_stats_daily',
    start_offset => INTERVAL '3 days',
    end_offset => INTERVAL '1 day',
    schedule_interval => INTERVAL '1 day',
    if_not_exists => TRUE
);

-- =============================================================================
-- 7. Create top paths continuous aggregate
-- =============================================================================
CREATE MATERIALIZED VIEW IF NOT EXISTS nginx_top_paths_1h
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    org_id,
    agent_id,
    path,

    -- Metrics per path
    COUNT(*) AS request_count,
    SUM(response_bytes) AS total_bytes,
    AVG(response_time) AS avg_response_time,
    percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time) AS p95_response_time,

    -- Error counts
    COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500) AS count_4xx,
    COUNT(*) FILTER (WHERE status_code >= 500) AS count_5xx,

    -- Unique visitors to this path
    COUNT(DISTINCT client_ip) AS unique_visitors
FROM nginx_access_logs
GROUP BY time_bucket('1 hour', time), org_id, agent_id, path
WITH NO DATA;

-- Add refresh policy: refresh every 10 minutes
SELECT add_continuous_aggregate_policy('nginx_top_paths_1h',
    start_offset => INTERVAL '3 hours',
    end_offset => INTERVAL '1 hour',
    schedule_interval => INTERVAL '10 minutes',
    if_not_exists => TRUE
);

-- =============================================================================
-- 8. Add compression policy (compress chunks older than 7 days)
-- =============================================================================
ALTER TABLE nginx_access_logs SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'org_id, agent_id',
    timescaledb.compress_orderby = 'time DESC'
);

SELECT add_compression_policy('nginx_access_logs', INTERVAL '7 days', if_not_exists => TRUE);

-- =============================================================================
-- 9. Add retention policy (drop data older than 90 days)
-- =============================================================================
SELECT add_retention_policy('nginx_access_logs', INTERVAL '90 days', if_not_exists => TRUE);

-- =============================================================================
-- 10. Create analytics configuration table
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
