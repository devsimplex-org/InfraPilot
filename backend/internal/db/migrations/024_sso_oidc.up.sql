-- SSO/OIDC Configuration table
CREATE TABLE IF NOT EXISTS sso_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,  -- 'oidc', 'okta', 'azure_ad', 'google'
    name VARCHAR(100) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,

    -- OIDC settings
    issuer_url VARCHAR(500),
    client_id VARCHAR(255),
    client_secret_encrypted BYTEA,  -- AES-256-GCM encrypted
    redirect_uri VARCHAR(500),
    scopes TEXT[] DEFAULT ARRAY['openid', 'email', 'profile'],

    -- Claim mappings
    email_claim VARCHAR(100) DEFAULT 'email',
    name_claim VARCHAR(100) DEFAULT 'name',
    groups_claim VARCHAR(100) DEFAULT 'groups',

    -- Role mappings (JSON: {"admin_group": "admin", "dev_group": "developer"})
    role_mappings JSONB DEFAULT '{}',

    -- User provisioning
    jit_provisioning BOOLEAN DEFAULT FALSE,  -- Just-In-Time user creation
    default_role VARCHAR(50) DEFAULT 'viewer',
    allowed_domains TEXT[],  -- Optional domain restrictions

    -- Metadata
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);

-- Index for lookups
CREATE INDEX IF NOT EXISTS idx_sso_configurations_org_id ON sso_configurations(org_id);
CREATE INDEX IF NOT EXISTS idx_sso_configurations_enabled ON sso_configurations(enabled) WHERE enabled = TRUE;

-- SSO sessions table for tracking OIDC state
CREATE TABLE IF NOT EXISTS sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sso_config_id UUID NOT NULL REFERENCES sso_configurations(id) ON DELETE CASCADE,
    state VARCHAR(255) NOT NULL UNIQUE,  -- OIDC state parameter
    nonce VARCHAR(255),  -- OIDC nonce for ID token validation
    redirect_after VARCHAR(500),  -- Where to redirect after successful auth
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Index for state lookup and cleanup
CREATE INDEX IF NOT EXISTS idx_sso_sessions_state ON sso_sessions(state);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_expires_at ON sso_sessions(expires_at);

-- Cleanup expired sessions (can be run periodically)
-- DELETE FROM sso_sessions WHERE expires_at < NOW();

COMMENT ON TABLE sso_configurations IS 'SSO/OIDC provider configurations for enterprise authentication';
COMMENT ON COLUMN sso_configurations.jit_provisioning IS 'Enable automatic user creation on first SSO login';
COMMENT ON COLUMN sso_configurations.role_mappings IS 'Map OIDC groups/claims to InfraPilot roles';
