-- Migration: 041_stacks
-- Description: Add stacks table for multi-service docker-compose deployments

-- ============ Enums ============

-- Stack status lifecycle
DO $$ BEGIN
    CREATE TYPE stack_status AS ENUM (
        'pending',    -- Stack created, waiting to start deployment
        'deploying',  -- Services are being deployed
        'running',    -- All services are running
        'partial',    -- Some services running, some failed
        'failed',     -- All services failed to deploy
        'stopped'     -- Stack was stopped
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============ Stacks Table ============

CREATE TABLE IF NOT EXISTS stacks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,

    -- Stack identification
    name VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),

    -- Compose configuration
    compose_yaml TEXT NOT NULL,
    variables JSONB DEFAULT '{}',

    -- Service counts for status tracking
    service_count INT DEFAULT 0,
    running_count INT DEFAULT 0,
    failed_count INT DEFAULT 0,

    -- Status
    status stack_status DEFAULT 'pending',
    status_message TEXT,

    -- Audit
    deployed_by UUID REFERENCES users(id),
    deployed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============ Link Deployments to Stacks ============

-- Add stack_id column to deployments if not exists
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS stack_id UUID REFERENCES stacks(id) ON DELETE SET NULL;

-- Add service_order for depends_on ordering within a stack
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS service_order INT DEFAULT 0;

-- ============ Indexes ============

CREATE INDEX IF NOT EXISTS idx_stacks_org ON stacks(org_id);
CREATE INDEX IF NOT EXISTS idx_stacks_agent ON stacks(agent_id);
CREATE INDEX IF NOT EXISTS idx_stacks_name ON stacks(name);
CREATE INDEX IF NOT EXISTS idx_stacks_status ON stacks(status);
CREATE INDEX IF NOT EXISTS idx_stacks_created ON stacks(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deployments_stack ON deployments(stack_id);

-- ============ Trigger for updated_at ============

DROP TRIGGER IF EXISTS update_stacks_updated_at ON stacks;
CREATE TRIGGER update_stacks_updated_at
    BEFORE UPDATE ON stacks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============ Comments ============

COMMENT ON TABLE stacks IS 'Groups multiple service deployments from docker-compose.yml files';
COMMENT ON COLUMN stacks.name IS 'User-defined name for the stack (e.g., "production-backend")';
COMMENT ON COLUMN stacks.environment IS 'Target environment: dev, staging, or prod';
COMMENT ON COLUMN stacks.compose_yaml IS 'Original docker-compose.yml content';
COMMENT ON COLUMN stacks.variables IS 'Variable substitutions applied to compose file';
COMMENT ON COLUMN stacks.service_count IS 'Total number of services in the stack';
COMMENT ON COLUMN stacks.running_count IS 'Number of services currently running';
COMMENT ON COLUMN stacks.failed_count IS 'Number of services that failed to deploy';
COMMENT ON COLUMN deployments.stack_id IS 'Reference to parent stack for multi-service deployments';
COMMENT ON COLUMN deployments.service_order IS 'Deployment order based on depends_on graph';
