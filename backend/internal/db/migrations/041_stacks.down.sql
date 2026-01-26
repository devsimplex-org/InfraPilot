-- Migration: 041_stacks (rollback)
-- Description: Remove stacks table and related columns

-- Remove stack_id from deployments
ALTER TABLE deployments DROP COLUMN IF EXISTS stack_id;
ALTER TABLE deployments DROP COLUMN IF EXISTS service_order;

-- Drop indexes
DROP INDEX IF EXISTS idx_stacks_org;
DROP INDEX IF EXISTS idx_stacks_agent;
DROP INDEX IF EXISTS idx_stacks_name;
DROP INDEX IF EXISTS idx_stacks_status;
DROP INDEX IF EXISTS idx_stacks_created;
DROP INDEX IF EXISTS idx_deployments_stack;

-- Drop trigger
DROP TRIGGER IF EXISTS update_stacks_updated_at ON stacks;

-- Drop table
DROP TABLE IF EXISTS stacks;

-- Drop enum (only if no other tables use it)
DROP TYPE IF EXISTS stack_status;
