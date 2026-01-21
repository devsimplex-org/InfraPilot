-- Basic auth configuration for proxies
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS basic_auth_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE proxy_hosts ADD COLUMN IF NOT EXISTS basic_auth_realm VARCHAR(255) DEFAULT 'Restricted';

-- Basic auth users table
CREATE TABLE IF NOT EXISTS proxy_auth_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proxy_id UUID NOT NULL REFERENCES proxy_hosts(id) ON DELETE CASCADE,
    username VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- bcrypt hash for htpasswd
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(proxy_id, username)
);

-- Index for fast lookups
CREATE INDEX IF NOT EXISTS idx_proxy_auth_users_proxy_id ON proxy_auth_users(proxy_id);
