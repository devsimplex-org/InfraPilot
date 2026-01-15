-- Migration: 016_service_ownership
-- Description: Service ownership and team accountability model
-- Epic 10: Ownership & Accountability Model

-- ============ Service Ownership Table ============

CREATE TABLE service_ownership (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Service identification
    service_name VARCHAR(255) NOT NULL,

    -- Team information
    team_name VARCHAR(255) NOT NULL,
    team_email VARCHAR(255),
    team_slack_channel VARCHAR(255),
    team_slack_webhook VARCHAR(500),

    -- Contacts
    primary_contact_id UUID REFERENCES users(id) ON DELETE SET NULL,
    secondary_contact_id UUID REFERENCES users(id) ON DELETE SET NULL,
    primary_contact_email VARCHAR(255),
    secondary_contact_email VARCHAR(255),

    -- Additional metadata
    description TEXT,
    repository_url VARCHAR(500),
    documentation_url VARCHAR(500),
    oncall_url VARCHAR(500),

    -- Tags for categorization
    tags VARCHAR(50)[],

    -- Ownership status
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'deprecated')),

    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Unique constraint: one ownership record per service per org
    UNIQUE(org_id, service_name)
);

-- ============ Team Metadata Table ============

CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Team identification
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),

    -- Contact information
    email VARCHAR(255),
    slack_channel VARCHAR(255),
    slack_webhook VARCHAR(500),
    pagerduty_integration_key VARCHAR(255),

    -- Team details
    description TEXT,
    manager_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Tags
    tags VARCHAR(50)[],

    -- Status
    active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(org_id, name)
);

-- ============ Team Members Table ============

CREATE TABLE team_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Role in team
    role VARCHAR(50) NOT NULL DEFAULT 'member' CHECK (role IN ('lead', 'member', 'oncall')),

    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(team_id, user_id)
);

-- ============ Indexes ============

-- Service ownership indexes
CREATE INDEX idx_service_ownership_org ON service_ownership(org_id);
CREATE INDEX idx_service_ownership_service ON service_ownership(service_name);
CREATE INDEX idx_service_ownership_team ON service_ownership(team_name);
CREATE INDEX idx_service_ownership_status ON service_ownership(status);
CREATE INDEX idx_service_ownership_primary_contact ON service_ownership(primary_contact_id) WHERE primary_contact_id IS NOT NULL;

-- Teams indexes
CREATE INDEX idx_teams_org ON teams(org_id);
CREATE INDEX idx_teams_name ON teams(name);
CREATE INDEX idx_teams_active ON teams(active);
CREATE INDEX idx_teams_manager ON teams(manager_id) WHERE manager_id IS NOT NULL;

-- Team members indexes
CREATE INDEX idx_team_members_team ON team_members(team_id);
CREATE INDEX idx_team_members_user ON team_members(user_id);
CREATE INDEX idx_team_members_role ON team_members(role);

-- ============ Functions ============

-- Update timestamp function
CREATE OR REPLACE FUNCTION update_service_ownership_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for service_ownership
CREATE TRIGGER service_ownership_updated
    BEFORE UPDATE ON service_ownership
    FOR EACH ROW
    EXECUTE FUNCTION update_service_ownership_timestamp();

-- Trigger for teams
CREATE TRIGGER teams_updated
    BEFORE UPDATE ON teams
    FOR EACH ROW
    EXECUTE FUNCTION update_service_ownership_timestamp();

-- Function to get service owner contact info
CREATE OR REPLACE FUNCTION get_service_contacts(
    p_org_id UUID,
    p_service_name VARCHAR
)
RETURNS TABLE (
    team_name VARCHAR,
    team_email VARCHAR,
    team_slack_channel VARCHAR,
    primary_contact_email VARCHAR,
    secondary_contact_email VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        so.team_name,
        so.team_email,
        so.team_slack_channel,
        so.primary_contact_email,
        so.secondary_contact_email
    FROM service_ownership so
    WHERE so.org_id = p_org_id
      AND so.service_name = p_service_name
      AND so.status = 'active';
END;
$$ LANGUAGE plpgsql;

-- Function to get team services
CREATE OR REPLACE FUNCTION get_team_services(
    p_org_id UUID,
    p_team_name VARCHAR
)
RETURNS TABLE (
    service_name VARCHAR,
    status VARCHAR,
    primary_contact_email VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        so.service_name,
        so.status,
        so.primary_contact_email
    FROM service_ownership so
    WHERE so.org_id = p_org_id
      AND so.team_name = p_team_name
    ORDER BY so.service_name;
END;
$$ LANGUAGE plpgsql;

-- ============ Views ============

-- View: Service ownership summary
CREATE VIEW v_service_ownership_summary AS
SELECT
    so.org_id,
    so.service_name,
    so.team_name,
    so.team_email,
    so.team_slack_channel,
    u1.email as primary_contact_email,
    u2.email as secondary_contact_email,
    so.status,
    COUNT(DISTINCT d.id) as deployment_count,
    COUNT(DISTINCT CASE WHEN d.status = 'running' THEN d.id END) as running_deployments
FROM service_ownership so
LEFT JOIN users u1 ON so.primary_contact_id = u1.id
LEFT JOIN users u2 ON so.secondary_contact_id = u2.id
LEFT JOIN deployments d ON so.service_name = d.service_name AND so.org_id = d.org_id
GROUP BY so.org_id, so.service_name, so.team_name, so.team_email,
         so.team_slack_channel, u1.email, u2.email, so.status;

-- ============ Comments ============

COMMENT ON TABLE service_ownership IS 'Maps services to owning teams for accountability and routing';
COMMENT ON TABLE teams IS 'Team metadata for organizational structure';
COMMENT ON TABLE team_members IS 'Team membership and roles';

COMMENT ON COLUMN service_ownership.service_name IS 'Service name matching deployments.service_name';
COMMENT ON COLUMN service_ownership.team_name IS 'Owning team responsible for this service';
COMMENT ON COLUMN service_ownership.team_slack_channel IS 'Slack channel for notifications (e.g., #platform-team)';
COMMENT ON COLUMN service_ownership.team_slack_webhook IS 'Slack webhook URL for automated notifications';
COMMENT ON COLUMN service_ownership.primary_contact_email IS 'Fallback email if user reference is not available';
COMMENT ON COLUMN service_ownership.oncall_url IS 'PagerDuty or oncall schedule URL';

COMMENT ON FUNCTION get_service_contacts IS 'Retrieve all contact information for a service owner';
COMMENT ON FUNCTION get_team_services IS 'List all services owned by a team';

-- ============ Seed Data (Example) ============

-- Example team (only if organizations exist)
INSERT INTO teams (org_id, name, display_name, description, active)
SELECT
    id,
    'platform',
    'Platform Team',
    'Infrastructure and platform services',
    TRUE
FROM organizations
WHERE NOT EXISTS (
    SELECT 1 FROM teams WHERE name = 'platform'
)
LIMIT 1;
