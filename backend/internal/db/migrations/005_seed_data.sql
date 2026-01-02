-- Seed Data for InfraPilot
-- Default admin user: admin@infrapilot.local / admin123

-- Default Organization
INSERT INTO organizations (id, name, slug)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default')
ON CONFLICT (id) DO NOTHING;

-- Default Admin User
-- Password: admin123 (bcrypt hash)
INSERT INTO users (id, org_id, email, password_hash, role)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000001',
  'admin@infrapilot.local',
  '$2a$10$sPMYdS3xTIj2yJ9Srt0UmeWmvB.M44Enw8NyBHuAtOWlFMoetN/Ay',
  'super_admin'
)
ON CONFLICT (id) DO NOTHING;

-- Default Agent (for demo purposes)
INSERT INTO agents (id, org_id, name, status)
VALUES (
  '00000000-0000-0000-0000-000000000001',
  '00000000-0000-0000-0000-000000000001',
  'Local Agent',
  'active'
)
ON CONFLICT (id) DO NOTHING;
