-- Rollback: Remove proxy redirect support

-- Remove check constraints
ALTER TABLE proxy_hosts DROP CONSTRAINT IF EXISTS proxy_hosts_proxy_type_check;
ALTER TABLE proxy_hosts DROP CONSTRAINT IF EXISTS proxy_hosts_redirect_code_check;

-- Remove columns
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS proxy_type;
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS redirect_url;
ALTER TABLE proxy_hosts DROP COLUMN IF EXISTS redirect_code;
