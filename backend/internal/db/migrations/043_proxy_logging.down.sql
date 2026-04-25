-- Remove logging configuration from proxy_hosts
ALTER TABLE proxy_hosts
DROP COLUMN IF EXISTS access_log,
DROP COLUMN IF EXISTS error_log,
DROP COLUMN IF EXISTS log_format;

-- Remove logging configuration from traffic_resources
ALTER TABLE traffic_resources
DROP COLUMN IF EXISTS access_log,
DROP COLUMN IF EXISTS error_log,
DROP COLUMN IF EXISTS log_format;

-- Drop index
DROP INDEX IF EXISTS idx_proxy_hosts_logging;
