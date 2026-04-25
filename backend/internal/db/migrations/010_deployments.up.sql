-- Migration: 010_deployments
-- Description: Add deployments entity for DevSecOps tracking
-- Epic 0: DevSecOps Foundations

-- ============ Enums ============

-- Deployment status lifecycle
DO $$ BEGIN
    CREATE TYPE deployment_status AS ENUM (
        'pending',      -- Deployment created, waiting to start
        'scanning',     -- Image is being scanned for vulnerabilities
        'policy_check', -- Evaluating security policies
        'deploying',    -- Starting container
        'running',      -- Container is running
        'failed',       -- Deployment failed
        'rolled_back',  -- Deployment was rolled back
        'stopped'       -- Deployment was stopped
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Policy decision result
DO $$ BEGIN
    CREATE TYPE policy_decision AS ENUM (
        'allow',  -- Deployment allowed
        'warn',   -- Deployment allowed with warnings
        'deny'    -- Deployment blocked
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============ Deployments Table ============

CREATE TABLE IF NOT EXISTS deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,

    -- Service identification
    service_name VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),

    -- Image information
    image_registry VARCHAR(255),
    image_repository VARCHAR(255) NOT NULL,
    image_tag VARCHAR(255),
    image_digest VARCHAR(255),

    -- Provenance (traceability)
    git_repo VARCHAR(500),
    git_branch VARCHAR(255),
    git_commit VARCHAR(64),
    ci_provider VARCHAR(50),
    ci_pipeline_id VARCHAR(255),
    ci_build_url VARCHAR(500),

    -- Security references (foreign keys will be added in later migrations)
    scan_result_id UUID,
    sbom_id UUID,
    policy_decision policy_decision NOT NULL DEFAULT 'allow',
    policy_reason TEXT,

    -- Status
    status deployment_status NOT NULL DEFAULT 'pending',
    status_message TEXT,

    -- Container mapping
    container_id VARCHAR(64),
    container_name VARCHAR(255),
    proxy_host_id UUID REFERENCES proxy_hosts(id),

    -- Relationships (deployment chain)
    replaces_deployment_id UUID REFERENCES deployments(id),
    rollback_of_deployment_id UUID REFERENCES deployments(id),

    -- Audit
    deployed_by UUID REFERENCES users(id),
    deployed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============ Indexes ============

CREATE INDEX IF NOT EXISTS idx_deployments_org ON deployments(org_id);
CREATE INDEX IF NOT EXISTS idx_deployments_agent ON deployments(agent_id);
CREATE INDEX IF NOT EXISTS idx_deployments_service ON deployments(service_name, environment);
CREATE INDEX IF NOT EXISTS idx_deployments_image ON deployments(image_digest);
CREATE INDEX IF NOT EXISTS idx_deployments_git ON deployments(git_repo, git_commit);
CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status);
CREATE INDEX IF NOT EXISTS idx_deployments_created ON deployments(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_deployments_container ON deployments(container_id);

-- ============ Link Containers to Deployments ============

-- Add deployment_id to existing containers table
ALTER TABLE containers ADD COLUMN IF NOT EXISTS deployment_id UUID REFERENCES deployments(id);
CREATE INDEX IF NOT EXISTS idx_containers_deployment ON containers(deployment_id);

-- ============ Trigger for updated_at ============

DROP TRIGGER IF EXISTS update_deployments_updated_at ON deployments;
CREATE TRIGGER update_deployments_updated_at
    BEFORE UPDATE ON deployments
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============ Comments ============

COMMENT ON TABLE deployments IS 'Tracks all deployment attempts with full provenance and security gates';
COMMENT ON COLUMN deployments.service_name IS 'Logical service name (e.g. "api", "frontend", "worker")';
COMMENT ON COLUMN deployments.environment IS 'Target environment: dev, staging, or prod';
COMMENT ON COLUMN deployments.policy_decision IS 'Security policy evaluation result';
COMMENT ON COLUMN deployments.replaces_deployment_id IS 'Previous deployment this replaces';
COMMENT ON COLUMN deployments.rollback_of_deployment_id IS 'Deployment this is rolling back from';
