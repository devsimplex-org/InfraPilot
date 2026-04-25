-- Migration: 044_nginx_analytics_timescale (DOWN)
-- Description: Rollback nginx analytics TimescaleDB schema

-- Remove policies first
SELECT remove_retention_policy('nginx_access_logs', if_exists => TRUE);
SELECT remove_compression_policy('nginx_access_logs', if_exists => TRUE);

-- Remove continuous aggregate policies
SELECT remove_continuous_aggregate_policy('nginx_top_paths_1h', if_not_exists => TRUE);
SELECT remove_continuous_aggregate_policy('nginx_stats_daily', if_not_exists => TRUE);
SELECT remove_continuous_aggregate_policy('nginx_stats_1h', if_not_exists => TRUE);
SELECT remove_continuous_aggregate_policy('nginx_stats_1m', if_not_exists => TRUE);

-- Drop continuous aggregates
DROP MATERIALIZED VIEW IF EXISTS nginx_top_paths_1h CASCADE;
DROP MATERIALIZED VIEW IF EXISTS nginx_stats_daily CASCADE;
DROP MATERIALIZED VIEW IF EXISTS nginx_stats_1h CASCADE;
DROP MATERIALIZED VIEW IF EXISTS nginx_stats_1m CASCADE;

-- Drop config table
DROP TRIGGER IF EXISTS trigger_nginx_analytics_config_updated_at ON nginx_analytics_config;
DROP FUNCTION IF EXISTS update_nginx_analytics_config_updated_at();
DROP TABLE IF EXISTS nginx_analytics_config CASCADE;

-- Drop main table (will also remove hypertable)
DROP TABLE IF EXISTS nginx_access_logs CASCADE;

-- Note: We don't drop the timescaledb extension as it may be used by other tables
