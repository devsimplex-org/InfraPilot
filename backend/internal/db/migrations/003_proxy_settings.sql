-- Migration: 003_proxy_settings
-- Description: Store proxy mode settings per agent
-- Supports: managed (bundled nginx) or external (user's own proxy)

-- Proxy settings per agent
CREATE TABLE agent_proxy_settings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,

    -- Proxy mode: 'managed' (default) or 'external'
    proxy_mode      VARCHAR(20) DEFAULT 'managed'
                    CHECK (proxy_mode IN ('managed', 'external')),

    -- For managed mode: which container to use as nginx
    nginx_container_id   VARCHAR(64),
    nginx_container_name VARCHAR(255),

    -- For external mode: optional metadata
    external_proxy_type  VARCHAR(50),  -- 'nginx', 'traefik', 'caddy', 'haproxy', 'cloud', 'other'
    external_proxy_notes TEXT,

    -- Timestamps
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(agent_id)
);

-- Index
CREATE INDEX idx_agent_proxy_settings_agent ON agent_proxy_settings(agent_id);

-- Insert default managed settings for existing agents
INSERT INTO agent_proxy_settings (agent_id, proxy_mode, nginx_container_name)
SELECT id, 'managed', 'infrapilot-nginx'
FROM agents
ON CONFLICT (agent_id) DO NOTHING;

-- Trigger for updated_at
CREATE TRIGGER update_agent_proxy_settings_updated_at
    BEFORE UPDATE ON agent_proxy_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
