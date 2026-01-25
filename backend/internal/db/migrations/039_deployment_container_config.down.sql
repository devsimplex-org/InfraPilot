-- Rollback: Remove container_config column from deployments table

DROP INDEX IF EXISTS idx_deployments_container_config;
ALTER TABLE deployments DROP COLUMN IF EXISTS container_config;
