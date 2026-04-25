-- Migration: Add proxy redirect support
-- Allows proxies to redirect to external URLs instead of proxying to upstream containers

-- Add proxy_type column (default 'upstream' for normal proxies)
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS proxy_type VARCHAR(20) DEFAULT 'upstream';

-- Add redirect_url column (for redirect type proxies)
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS redirect_url TEXT;

-- Add redirect_code column (301 = permanent, 302 = temporary)
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS redirect_code INTEGER DEFAULT 301;

-- Add comments for documentation
COMMENT ON COLUMN proxy_hosts.proxy_type IS 'Type of proxy: upstream (normal proxy_pass) or redirect (HTTP redirect)';
COMMENT ON COLUMN proxy_hosts.redirect_url IS 'For redirect type: the URL to redirect to (e.g., https://example.com)';
COMMENT ON COLUMN proxy_hosts.redirect_code IS 'For redirect type: HTTP status code (301=permanent, 302=temporary)';

-- Add check constraint for valid proxy types
ALTER TABLE proxy_hosts ADD CONSTRAINT proxy_hosts_proxy_type_check
    CHECK (proxy_type IN ('upstream', 'redirect'));

-- Add check constraint for valid redirect codes
ALTER TABLE proxy_hosts ADD CONSTRAINT proxy_hosts_redirect_code_check
    CHECK (redirect_code IS NULL OR redirect_code IN (301, 302, 307, 308));
