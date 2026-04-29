-- Migration 021: Container Registries
-- Adds ability to connect to container registries (GHCR, Docker Hub) and browse images

-- ============================================================================
-- Registry Provider Enum
-- ============================================================================

CREATE TYPE registry_provider AS ENUM ('ghcr', 'dockerhub');

-- ============================================================================
-- Container Registries Table
-- ============================================================================

CREATE TABLE container_registries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    provider registry_provider NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    -- Authentication
    auth_type VARCHAR(50) NOT NULL, -- 'token', 'username_password'
    credentials_encrypted BYTEA NOT NULL, -- Encrypted JSON containing credentials

    -- Registry namespace (username/org for filtering)
    namespace VARCHAR(255),

    -- Connection status
    connection_status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending', 'connected', 'failed'
    connection_error TEXT,
    last_connected_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Unique constraint: one registry name per org
    UNIQUE(org_id, name)
);

-- ============================================================================
-- Indexes
-- ============================================================================

CREATE INDEX idx_container_registries_org ON container_registries(org_id);
CREATE INDEX idx_container_registries_provider ON container_registries(provider);
CREATE INDEX idx_container_registries_status ON container_registries(connection_status);
CREATE INDEX idx_container_registries_enabled ON container_registries(enabled);

-- ============================================================================
-- Comments
-- ============================================================================

COMMENT ON TABLE container_registries IS 'Container registry connections for browsing images from GHCR and Docker Hub';
COMMENT ON COLUMN container_registries.credentials_encrypted IS 'AES-encrypted JSON containing auth credentials (token or username/password)';
COMMENT ON COLUMN container_registries.namespace IS 'Username or organization name to filter repositories';
COMMENT ON COLUMN container_registries.connection_status IS 'Current connection status: pending, connected, or failed';
