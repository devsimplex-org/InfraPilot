-- Migration: 009_multitenancy.sql
-- Enterprise Phase E3: Multi-Tenancy for SaaS

-- ============ Extend Organizations for SaaS ============

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS plan VARCHAR(50) DEFAULT 'free';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR(255);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS subscription_status VARCHAR(50);
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS max_users INTEGER DEFAULT 5;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS max_agents INTEGER DEFAULT 3;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{}';

-- Index for plan lookups
CREATE INDEX IF NOT EXISTS idx_organizations_plan ON organizations(plan);

-- ============ Organization Members ============

CREATE TABLE IF NOT EXISTS organization_members (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            VARCHAR(50) NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    invited_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    joined_at       TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_members_org ON organization_members(org_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);

-- ============ Organization Invitations ============

CREATE TABLE IF NOT EXISTS organization_invitations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL,
    role            VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'member', 'viewer')),
    token           VARCHAR(64) UNIQUE NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    accepted_at     TIMESTAMPTZ,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),

    -- Only one pending invitation per email per org
    UNIQUE(org_id, email) WHERE accepted_at IS NULL
);

CREATE INDEX IF NOT EXISTS idx_org_invitations_org ON organization_invitations(org_id);
CREATE INDEX IF NOT EXISTS idx_org_invitations_token ON organization_invitations(token);
CREATE INDEX IF NOT EXISTS idx_org_invitations_email ON organization_invitations(email);

-- ============ Enrollment Tokens (for SaaS one-liner install) ============

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token           VARCHAR(64) UNIQUE NOT NULL,
    name            VARCHAR(255),
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at      TIMESTAMPTZ,
    max_uses        INTEGER,
    use_count       INTEGER DEFAULT 0,
    labels          JSONB DEFAULT '{}',
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_org ON enrollment_tokens(org_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_token ON enrollment_tokens(token);

-- ============ Enable Row-Level Security ============

-- Organizations RLS
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON organizations
    USING (id = current_setting('app.current_org_id', true)::uuid);

-- Users RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY users_org_isolation ON users
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

-- Agents RLS
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;

CREATE POLICY agents_org_isolation ON agents
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

-- Alert Channels RLS
ALTER TABLE alert_channels ENABLE ROW LEVEL SECURITY;

CREATE POLICY alert_channels_org_isolation ON alert_channels
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

-- Alert Rules RLS
ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY alert_rules_org_isolation ON alert_rules
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

-- Audit Logs RLS
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY audit_logs_org_isolation ON audit_logs
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

-- Organization Members RLS
ALTER TABLE organization_members ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_members_isolation ON organization_members
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

-- Organization Invitations RLS
ALTER TABLE organization_invitations ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_invitations_isolation ON organization_invitations
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

-- Enrollment Tokens RLS
ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;

CREATE POLICY enrollment_tokens_isolation ON enrollment_tokens
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

-- SSO Providers RLS (if exists)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'sso_providers') THEN
        ALTER TABLE sso_providers ENABLE ROW LEVEL SECURITY;

        CREATE POLICY sso_providers_org_isolation ON sso_providers
            USING (org_id = current_setting('app.current_org_id', true)::uuid);
    END IF;
END $$;

-- Audit Config RLS (if exists)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_config') THEN
        ALTER TABLE audit_config ENABLE ROW LEVEL SECURITY;

        CREATE POLICY audit_config_org_isolation ON audit_config
            USING (org_id = current_setting('app.current_org_id', true)::uuid);
    END IF;
END $$;

-- ============ Bypass RLS for Service Account ============

-- Create a role for bypassing RLS when needed (e.g., for admin tasks)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'infrapilot_admin') THEN
        CREATE ROLE infrapilot_admin NOLOGIN;
    END IF;
END $$;

-- Grant bypass to admin role
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;
ALTER TABLE alert_channels FORCE ROW LEVEL SECURITY;
ALTER TABLE alert_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE organization_members FORCE ROW LEVEL SECURITY;
ALTER TABLE organization_invitations FORCE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens FORCE ROW LEVEL SECURITY;

-- ============ Helper Function for Setting Org Context ============

CREATE OR REPLACE FUNCTION set_org_context(p_org_id UUID)
RETURNS void AS $$
BEGIN
    PERFORM set_config('app.current_org_id', p_org_id::text, true);
END;
$$ LANGUAGE plpgsql;

-- ============ Helper Function for Checking Org Limits ============

CREATE OR REPLACE FUNCTION check_org_user_limit(p_org_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_max_users INTEGER;
    v_current_users INTEGER;
BEGIN
    SELECT max_users INTO v_max_users FROM organizations WHERE id = p_org_id;
    SELECT COUNT(*) INTO v_current_users FROM users WHERE org_id = p_org_id;

    RETURN v_current_users < v_max_users;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION check_org_agent_limit(p_org_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_max_agents INTEGER;
    v_current_agents INTEGER;
BEGIN
    SELECT max_agents INTO v_max_agents FROM organizations WHERE id = p_org_id;
    SELECT COUNT(*) INTO v_current_agents FROM agents WHERE org_id = p_org_id;

    RETURN v_current_agents < v_max_agents;
END;
$$ LANGUAGE plpgsql;

-- ============ Triggers ============

CREATE TRIGGER update_organization_members_updated_at
    BEFORE UPDATE ON organization_members
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
