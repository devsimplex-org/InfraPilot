-- Add container_config JSONB column to deployments table
-- This stores environment variables, secrets, networks, and volumes configuration

ALTER TABLE deployments ADD COLUMN IF NOT EXISTS container_config JSONB;

-- Add index for efficient querying of container configs
CREATE INDEX IF NOT EXISTS idx_deployments_container_config ON deployments USING GIN (container_config);

-- Add comments for documentation
COMMENT ON COLUMN deployments.container_config IS 'JSONB containing container configuration including env_vars, secrets, networks, and volumes';
