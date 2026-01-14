-- Migration: 002_network_attachments
-- Description: Track nginx network attachments for cross-network proxying
-- Epic: INFRA-EDGE-004

-- Track which networks InfraPilot has attached nginx to
CREATE TABLE nginx_network_attachments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    network_id      VARCHAR(64) NOT NULL,    -- Docker network ID (short form)
    network_name    VARCHAR(255) NOT NULL,   -- Docker network name for display
    attached_at     TIMESTAMPTZ DEFAULT NOW(),
    attached_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    status          VARCHAR(20) DEFAULT 'attached'
                    CHECK (status IN ('attached', 'detached', 'error')),
    error_message   TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(agent_id, network_id)
);

-- Indexes
CREATE INDEX idx_nginx_network_attachments_agent ON nginx_network_attachments(agent_id);
CREATE INDEX idx_nginx_network_attachments_status ON nginx_network_attachments(status);
CREATE INDEX idx_nginx_network_attachments_network ON nginx_network_attachments(network_name);

-- Extend containers table to cache network information
ALTER TABLE containers ADD COLUMN IF NOT EXISTS networks JSONB DEFAULT '[]'::jsonb;

-- Add trigger for updated_at
CREATE TRIGGER update_nginx_network_attachments_updated_at
    BEFORE UPDATE ON nginx_network_attachments
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
