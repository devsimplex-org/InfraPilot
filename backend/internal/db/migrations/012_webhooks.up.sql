-- Webhook configurations
CREATE TABLE IF NOT EXISTS webhook_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(50) NOT NULL CHECK (provider IN ('github', 'gitlab', 'jenkins', 'generic')),
    secret_hash TEXT NOT NULL, -- bcrypt hash of the webhook secret
    enabled BOOLEAN NOT NULL DEFAULT true,
    service_name VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(org_id, agent_id, name)
);

CREATE INDEX idx_webhook_configs_org_agent ON webhook_configs(org_id, agent_id);
CREATE INDEX idx_webhook_configs_enabled ON webhook_configs(enabled) WHERE enabled = true;

-- Webhook events (audit trail of received webhooks)
CREATE TABLE IF NOT EXISTS webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID NOT NULL REFERENCES webhook_configs(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    event_type VARCHAR(100),
    payload JSONB NOT NULL,
    headers JSONB NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT false,
    processed BOOLEAN NOT NULL DEFAULT false,
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    error TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_webhook_events_webhook_id ON webhook_events(webhook_id);
CREATE INDEX idx_webhook_events_deployment_id ON webhook_events(deployment_id);
CREATE INDEX idx_webhook_events_created_at ON webhook_events(created_at DESC);
CREATE INDEX idx_webhook_events_processed ON webhook_events(processed) WHERE NOT processed;

-- Update deployments table to add webhook_event_id reference
ALTER TABLE deployments ADD COLUMN IF NOT EXISTS webhook_event_id UUID REFERENCES webhook_events(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_deployments_webhook_event ON deployments(webhook_event_id);

-- Add comments for documentation
COMMENT ON TABLE webhook_configs IS 'Configured webhook endpoints for CI/CD integration';
COMMENT ON TABLE webhook_events IS 'Audit trail of received webhook events';
COMMENT ON COLUMN webhook_configs.secret_hash IS 'bcrypt hash of the webhook secret for signature verification';
COMMENT ON COLUMN webhook_events.verified IS 'Whether the webhook signature was successfully verified';
COMMENT ON COLUMN webhook_events.processed IS 'Whether the webhook has been processed into a deployment';
