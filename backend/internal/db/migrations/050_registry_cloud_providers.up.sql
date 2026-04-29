-- Add cloud provider types to registry_provider enum
-- Note: PostgreSQL doesn't support IF NOT EXISTS for ADD VALUE in enums
-- So we need to check if the value exists first

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'ecr' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'registry_provider')) THEN
        ALTER TYPE registry_provider ADD VALUE 'ecr';
    END IF;
END$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'gcr' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'registry_provider')) THEN
        ALTER TYPE registry_provider ADD VALUE 'gcr';
    END IF;
END$$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'acr' AND enumtypid = (SELECT oid FROM pg_type WHERE typname = 'registry_provider')) THEN
        ALTER TYPE registry_provider ADD VALUE 'acr';
    END IF;
END$$;

COMMENT ON TYPE registry_provider IS 'Supported container registry providers: dockerhub, harbor, ecr (AWS), gcr (GCP), acr (Azure)';
