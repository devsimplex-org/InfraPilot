-- Add basic_auth_excluded_paths column to proxy_hosts
-- This stores a JSON array of paths that should bypass basic auth (e.g., ["/api/", "/health"])
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS basic_auth_excluded_paths TEXT[] DEFAULT '{}';
