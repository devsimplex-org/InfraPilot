ALTER TABLE deployments DROP COLUMN IF EXISTS service_config_id;
DROP TABLE IF EXISTS service_configs;
