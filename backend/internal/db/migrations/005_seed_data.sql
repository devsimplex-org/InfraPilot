-- Seed Data for InfraPilot
-- No default users - admin account is created during first-time setup

-- Default Organization
INSERT INTO organizations (id, name, slug)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default')
ON CONFLICT (id) DO NOTHING;

-- Default Agent (for local development / standalone mode)
INSERT INTO agents (id, org_id, name, status, fingerprint)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000001',
  'Local Agent',
  'active',
  'standalone'
)
ON CONFLICT (id) DO NOTHING;
