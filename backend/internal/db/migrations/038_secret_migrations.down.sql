-- Rollback: Remove secret_migrations tracking tables

DROP VIEW IF EXISTS v_secret_migrations_summary;
DROP TRIGGER IF EXISTS trigger_secret_migrations_updated_at ON secret_migrations;
DROP FUNCTION IF EXISTS update_secret_migrations_updated_at();
DROP INDEX IF EXISTS idx_secret_migrations_active;
DROP INDEX IF EXISTS idx_secret_migration_items_status;
DROP INDEX IF EXISTS idx_secret_migration_items_migration_id;
DROP INDEX IF EXISTS idx_secret_migrations_created_at;
DROP INDEX IF EXISTS idx_secret_migrations_container_id;
DROP INDEX IF EXISTS idx_secret_migrations_status;
DROP INDEX IF EXISTS idx_secret_migrations_agent_id;
DROP INDEX IF EXISTS idx_secret_migrations_org_id;
DROP TABLE IF EXISTS secret_migration_items;
DROP TABLE IF EXISTS secret_migrations;
