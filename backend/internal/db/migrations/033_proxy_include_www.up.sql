-- Add include_www column to proxy_hosts table
-- When enabled, SSL certificates will be requested for both domain and www.domain,
-- and nginx config will serve both in server_name directive

ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS include_www BOOLEAN DEFAULT FALSE;
