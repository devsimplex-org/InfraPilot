-- Migration: 011_seed_org_members.sql
-- Seed organization members for existing users

-- Add all existing users to the default organization as owners
-- This ensures backwards compatibility with existing setups
INSERT INTO organization_members (org_id, user_id, role)
SELECT
    '00000000-0000-0000-0000-000000000001'::uuid,
    u.id,
    CASE
        WHEN u.role = 'super_admin' THEN 'owner'
        WHEN u.role = 'admin' THEN 'admin'
        ELSE 'member'
    END
FROM users u
WHERE u.org_id = '00000000-0000-0000-0000-000000000001'
ON CONFLICT (org_id, user_id) DO NOTHING;

-- Update the default organization with the new required columns if not set
UPDATE organizations
SET
    plan = COALESCE(plan, 'free'),
    max_users = COALESCE(max_users, 100),
    max_agents = COALESCE(max_agents, 100)
WHERE id = '00000000-0000-0000-0000-000000000001';
