-- Add host resource metric columns to agents table
-- Populated on each heartbeat from the agent's gopsutil collector
ALTER TABLE agents
  ADD COLUMN IF NOT EXISTS cpu_percent     DOUBLE PRECISION DEFAULT 0,
  ADD COLUMN IF NOT EXISTS memory_used_mb  BIGINT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS memory_total_mb BIGINT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS disk_used_mb    BIGINT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS disk_total_mb   BIGINT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS uptime_seconds  BIGINT DEFAULT 0;
