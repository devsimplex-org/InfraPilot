-- Remove host resource metric columns from agents table
ALTER TABLE agents
  DROP COLUMN IF EXISTS cpu_percent,
  DROP COLUMN IF EXISTS memory_used_mb,
  DROP COLUMN IF EXISTS memory_total_mb,
  DROP COLUMN IF EXISTS disk_used_mb,
  DROP COLUMN IF EXISTS disk_total_mb,
  DROP COLUMN IF EXISTS uptime_seconds;
