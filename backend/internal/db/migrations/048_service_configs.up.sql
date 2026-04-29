-- service_configs stores the persistent definition of a service.
-- A service is the stable unit (y-app in dev). Deployments are events against it.
CREATE TABLE service_configs (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          UUID        NOT NULL,
  agent_id        UUID        NOT NULL,
  service_name    TEXT        NOT NULL,
  environment     TEXT        NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),

  -- Image (repository only — tag comes at deploy time)
  image_repository TEXT       NOT NULL,
  image_tag        TEXT       NOT NULL DEFAULT 'latest',

  -- Container runtime config (same shape as DeploymentContainerConfig)
  container_config JSONB      NOT NULL DEFAULT '{}',

  -- Metadata
  git_repo        TEXT,
  webhook_id      UUID,       -- linked webhook trigger (optional)

  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (org_id, agent_id, service_name, environment)
);

CREATE INDEX idx_service_configs_org     ON service_configs (org_id);
CREATE INDEX idx_service_configs_agent   ON service_configs (agent_id);
CREATE INDEX idx_service_configs_svc_env ON service_configs (service_name, environment);

-- Add service_config_id FK to deployments (nullable — existing rows remain valid)
ALTER TABLE deployments
  ADD COLUMN IF NOT EXISTS service_config_id UUID REFERENCES service_configs(id) ON DELETE SET NULL;
