-- Migration: 010_policy_engine.sql
-- Enterprise Phase E5: Policy Engine

-- ============ Policies ============

CREATE TABLE IF NOT EXISTS policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    policy_type     VARCHAR(100) NOT NULL,  -- 'container', 'proxy', 'access', 'security'

    -- Conditions (JSON-based rules)
    conditions      JSONB NOT NULL DEFAULT '{}',

    -- Action on violation
    action          VARCHAR(20) NOT NULL CHECK (action IN ('block', 'warn', 'audit')),

    -- Scope
    applies_to      JSONB DEFAULT '{}',     -- agent labels, environments, etc.

    -- Status
    enabled         BOOLEAN DEFAULT TRUE,
    priority        INTEGER DEFAULT 0,       -- Higher = evaluated first

    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_policies_org ON policies(org_id);
CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(org_id, enabled) WHERE enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(policy_type);

-- ============ Policy Templates ============
-- Pre-defined policy templates for common use cases

CREATE TABLE IF NOT EXISTS policy_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL UNIQUE,
    description     TEXT,
    policy_type     VARCHAR(100) NOT NULL,
    conditions      JSONB NOT NULL,
    recommended_action VARCHAR(20) NOT NULL,
    category        VARCHAR(100),           -- 'security', 'compliance', 'operations'
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ============ Policy Violations ============

CREATE TABLE IF NOT EXISTS policy_violations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id        UUID REFERENCES agents(id) ON DELETE SET NULL,

    -- What was violated
    resource_type   VARCHAR(100) NOT NULL,  -- 'container', 'proxy_host', 'exec', 'config'
    resource_id     VARCHAR(255),           -- container_id, proxy_id, etc.
    resource_name   VARCHAR(255),           -- human-readable name

    -- Violation details
    message         TEXT NOT NULL,
    details         JSONB,                  -- Extra context

    -- Action taken
    action_taken    VARCHAR(20) NOT NULL,   -- 'blocked', 'warned', 'audited'

    -- Resolution
    resolved        BOOLEAN DEFAULT FALSE,
    resolved_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at     TIMESTAMPTZ,
    resolution_note TEXT,

    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_violations_policy ON policy_violations(policy_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_violations_org ON policy_violations(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_violations_agent ON policy_violations(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_violations_unresolved ON policy_violations(org_id, resolved) WHERE resolved = FALSE;

-- ============ Enable RLS ============

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY policies_org_isolation ON policies
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

ALTER TABLE policy_violations ENABLE ROW LEVEL SECURITY;
CREATE POLICY violations_org_isolation ON policy_violations
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

-- ============ Triggers ============

CREATE TRIGGER update_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============ Insert Default Templates ============

INSERT INTO policy_templates (name, description, policy_type, conditions, recommended_action, category) VALUES
    ('no_root_containers', 'Block containers running as root user', 'container',
     '{"check": "user", "operator": "equals", "value": "root"}', 'block', 'security'),

    ('require_restart_policy', 'Containers must have a restart policy', 'container',
     '{"check": "restart_policy", "operator": "not_equals", "value": "no"}', 'warn', 'operations'),

    ('require_healthcheck', 'Containers should define a healthcheck', 'container',
     '{"check": "healthcheck", "operator": "exists"}', 'warn', 'operations'),

    ('require_ssl', 'All proxy hosts must have SSL enabled', 'proxy',
     '{"check": "ssl_enabled", "operator": "equals", "value": true}', 'warn', 'security'),

    ('no_exec_production', 'Block exec commands in production environments', 'access',
     '{"check": "action", "operator": "equals", "value": "exec", "environment": "production"}', 'block', 'security'),

    ('max_container_age', 'Alert on containers older than 30 days', 'container',
     '{"check": "age_days", "operator": "greater_than", "value": 30}', 'audit', 'operations'),

    ('require_resource_limits', 'Containers should have memory limits', 'container',
     '{"check": "memory_limit", "operator": "greater_than", "value": 0}', 'warn', 'operations'),

    ('no_privileged_containers', 'Block privileged containers', 'container',
     '{"check": "privileged", "operator": "equals", "value": true}', 'block', 'security')
ON CONFLICT (name) DO NOTHING;
