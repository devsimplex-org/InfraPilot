-- Add logging configuration to proxy_hosts
ALTER TABLE proxy_hosts
ADD COLUMN IF NOT EXISTS access_log BOOLEAN DEFAULT true,
ADD COLUMN IF NOT EXISTS error_log BOOLEAN DEFAULT true,
ADD COLUMN IF NOT EXISTS log_format TEXT DEFAULT NULL;

-- Add logging configuration to traffic_resources
ALTER TABLE traffic_resources
ADD COLUMN IF NOT EXISTS access_log BOOLEAN DEFAULT true,
ADD COLUMN IF NOT EXISTS error_log BOOLEAN DEFAULT true,
ADD COLUMN IF NOT EXISTS log_format TEXT DEFAULT NULL;

-- Create index for log queries
CREATE INDEX IF NOT EXISTS idx_proxy_hosts_logging ON proxy_hosts(agent_id, access_log, error_log) WHERE access_log = true OR error_log = true;
