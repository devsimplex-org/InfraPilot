-- SSO Provider configurations
CREATE TABLE IF NOT EXISTS sso_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    provider_type VARCHAR(20) NOT NULL CHECK (provider_type IN ('saml', 'oidc', 'ldap')),
    enabled BOOLEAN DEFAULT true,

    -- SAML specific
    saml_entity_id VARCHAR(500),
    saml_sso_url VARCHAR(500),
    saml_slo_url VARCHAR(500),
    saml_certificate TEXT,
    saml_sign_requests BOOLEAN DEFAULT false,
    saml_name_id_format VARCHAR(100) DEFAULT 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',

    -- OIDC specific
    oidc_issuer VARCHAR(500),
    oidc_client_id VARCHAR(255),
    oidc_client_secret_encrypted TEXT,
    oidc_scopes VARCHAR(255) DEFAULT 'openid profile email',
    oidc_redirect_uri VARCHAR(500),

    -- LDAP specific
    ldap_host VARCHAR(255),
    ldap_port INTEGER DEFAULT 389,
    ldap_use_tls BOOLEAN DEFAULT false,
    ldap_skip_verify BOOLEAN DEFAULT false,
    ldap_bind_dn VARCHAR(500),
    ldap_bind_password_encrypted TEXT,
    ldap_base_dn VARCHAR(500),
    ldap_user_filter VARCHAR(500) DEFAULT '(uid=%s)',
    ldap_group_filter VARCHAR(500),
    ldap_email_attr VARCHAR(100) DEFAULT 'mail',
    ldap_name_attr VARCHAR(100) DEFAULT 'cn',
    ldap_group_attr VARCHAR(100) DEFAULT 'memberOf',

    -- Common settings
    default_role VARCHAR(50) DEFAULT 'viewer',
    auto_create_users BOOLEAN DEFAULT true,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Group to role mappings for SSO
CREATE TABLE IF NOT EXISTS sso_role_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    external_group VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('super_admin', 'admin', 'operator', 'viewer')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider_id, external_group)
);

-- SSO sessions for tracking and SLO
CREATE TABLE IF NOT EXISTS sso_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES sso_providers(id) ON DELETE CASCADE,
    external_id VARCHAR(255),
    session_index VARCHAR(255),
    access_token_hash VARCHAR(64),
    refresh_token_encrypted TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_sso_providers_org ON sso_providers(org_id);
CREATE INDEX IF NOT EXISTS idx_sso_providers_type ON sso_providers(provider_type);
CREATE INDEX IF NOT EXISTS idx_sso_role_mappings_provider ON sso_role_mappings(provider_id);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_user ON sso_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_provider ON sso_sessions(provider_id);
CREATE INDEX IF NOT EXISTS idx_sso_sessions_expires ON sso_sessions(expires_at);

-- Add sso_provider_id to users table for tracking which SSO provider authenticated them
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider_id UUID REFERENCES sso_providers(id) ON DELETE SET NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_external_id VARCHAR(255);
