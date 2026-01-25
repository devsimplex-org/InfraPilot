-- Migration: Add secret_migrations tracking tables for .env to Docker Secrets migration

-- secret_migrations: Track migration jobs
CREATE TABLE IF NOT EXISTS secret_migrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    container_id VARCHAR(255) NOT NULL,
    container_name VARCHAR(255) NOT NULL,
    source_type VARCHAR(50) NOT NULL CHECK (source_type IN ('env_file', 'env_var')),
    source_path VARCHAR(500),
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending',
        'creating_secrets',
        'stopping_container',
        'starting_container',
        'verifying',
        'completed',
        'failed',
        'rolled_back'
    )),
    error_message TEXT,
    original_container_config JSONB,
    new_container_id VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

COMMENT ON TABLE secret_migrations IS 'Tracks .env to Docker Secrets migration jobs';
COMMENT ON COLUMN secret_migrations.source_type IS 'Source of secrets: env_file or env_var';
COMMENT ON COLUMN secret_migrations.source_path IS 'Path to source file, e.g., /app/.env';
COMMENT ON COLUMN secret_migrations.status IS 'Migration status: pending → creating_secrets → stopping_container → starting_container → verifying → completed/failed/rolled_back';
COMMENT ON COLUMN secret_migrations.original_container_config IS 'Stored container config for rollback purposes';
COMMENT ON COLUMN secret_migrations.new_container_id IS 'ID of the newly created container after migration';

-- secret_migration_items: Individual secrets in a migration
CREATE TABLE IF NOT EXISTS secret_migration_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    migration_id UUID NOT NULL REFERENCES secret_migrations(id) ON DELETE CASCADE,
    secret_name VARCHAR(255) NOT NULL,
    secret_type VARCHAR(50),
    old_source VARCHAR(50) NOT NULL CHECK (old_source IN ('env_file', 'env_var')),
    new_source VARCHAR(50) NOT NULL DEFAULT 'file_secret' CHECK (new_source IN ('docker_secret', 'file_secret')),
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending',
        'created',
        'attached',
        'verified',
        'completed',
        'failed'
    )),
    mount_path VARCHAR(500),
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE secret_migration_items IS 'Individual secrets within a migration job';
COMMENT ON COLUMN secret_migration_items.secret_type IS 'Type of secret: api_key, password, token, etc.';
COMMENT ON COLUMN secret_migration_items.old_source IS 'Original source: env_file or env_var';
COMMENT ON COLUMN secret_migration_items.new_source IS 'New source after migration: docker_secret or file_secret';
COMMENT ON COLUMN secret_migration_items.mount_path IS 'Mount path in container, e.g., /run/secrets/DB_PASSWORD';

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_secret_migrations_org_id ON secret_migrations(org_id);
CREATE INDEX IF NOT EXISTS idx_secret_migrations_agent_id ON secret_migrations(agent_id);
CREATE INDEX IF NOT EXISTS idx_secret_migrations_status ON secret_migrations(status);
CREATE INDEX IF NOT EXISTS idx_secret_migrations_container_id ON secret_migrations(container_id);
CREATE INDEX IF NOT EXISTS idx_secret_migrations_created_at ON secret_migrations(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_secret_migration_items_migration_id ON secret_migration_items(migration_id);
CREATE INDEX IF NOT EXISTS idx_secret_migration_items_status ON secret_migration_items(status);

-- Partial index for active migrations (non-completed)
CREATE INDEX IF NOT EXISTS idx_secret_migrations_active ON secret_migrations(org_id, agent_id)
    WHERE status NOT IN ('completed', 'failed', 'rolled_back');

-- Update function for updated_at timestamp
CREATE OR REPLACE FUNCTION update_secret_migrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update updated_at
DROP TRIGGER IF EXISTS trigger_secret_migrations_updated_at ON secret_migrations;
CREATE TRIGGER trigger_secret_migrations_updated_at
    BEFORE UPDATE ON secret_migrations
    FOR EACH ROW
    EXECUTE FUNCTION update_secret_migrations_updated_at();

-- View for migration summary with item counts
CREATE OR REPLACE VIEW v_secret_migrations_summary AS
SELECT
    sm.id,
    sm.org_id,
    sm.agent_id,
    sm.container_id,
    sm.container_name,
    sm.source_type,
    sm.source_path,
    sm.status,
    sm.error_message,
    sm.new_container_id,
    sm.created_at,
    sm.updated_at,
    sm.completed_at,
    COUNT(smi.id) AS total_secrets,
    COUNT(CASE WHEN smi.status = 'completed' THEN 1 END) AS completed_secrets,
    COUNT(CASE WHEN smi.status = 'failed' THEN 1 END) AS failed_secrets
FROM secret_migrations sm
LEFT JOIN secret_migration_items smi ON sm.id = smi.migration_id
GROUP BY sm.id;

COMMENT ON VIEW v_secret_migrations_summary IS 'Migration summary with secret item counts';
