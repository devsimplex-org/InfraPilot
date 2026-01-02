-- InfraPilot Database Seed Script
-- Run with: psql -U infrapilot -d infrapilot -f scripts/seed.sql
-- Or: ./scripts/dev.sh seed

-- Create default organization
INSERT INTO organizations (id, name, slug)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default Organization', 'default')
ON CONFLICT (slug) DO NOTHING;

-- Create admin user
-- Password: admin123
INSERT INTO users (id, org_id, email, password_hash, role, mfa_enabled)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'admin@infrapilot.local',
    '$2a$10$Z.bIyREnf3EmZg6OE/nUqeZHlMRd3tDFAE/6lIgvvk0W3/Dt5L54q',
    'super_admin',
    false
)
ON CONFLICT (email) DO NOTHING;

-- Create operator user
-- Password: admin123 (same for simplicity in dev)
INSERT INTO users (id, org_id, email, password_hash, role, mfa_enabled)
VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001',
    'operator@infrapilot.local',
    '$2a$10$Z.bIyREnf3EmZg6OE/nUqeZHlMRd3tDFAE/6lIgvvk0W3/Dt5L54q',
    'operator',
    false
)
ON CONFLICT (email) DO NOTHING;

-- Create viewer user
-- Password: admin123 (same for simplicity in dev)
INSERT INTO users (id, org_id, email, password_hash, role, mfa_enabled)
VALUES (
    '00000000-0000-0000-0000-000000000003',
    '00000000-0000-0000-0000-000000000001',
    'viewer@infrapilot.local',
    '$2a$10$Z.bIyREnf3EmZg6OE/nUqeZHlMRd3tDFAE/6lIgvvk0W3/Dt5L54q',
    'viewer',
    false
)
ON CONFLICT (email) DO NOTHING;

-- Create a sample agent (pending enrollment)
INSERT INTO agents (id, org_id, name, enrollment_token, status)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'demo-server',
    'demo-enrollment-token-12345',
    'pending'
)
ON CONFLICT DO NOTHING;

-- Output confirmation
SELECT 'Seed data created successfully!' AS status;
SELECT 'Login credentials:' AS info;
SELECT '  admin@infrapilot.local / admin123' AS admin_user;
SELECT '  operator@infrapilot.local / operator123' AS operator_user;
SELECT '  viewer@infrapilot.local / viewer123' AS viewer_user;
