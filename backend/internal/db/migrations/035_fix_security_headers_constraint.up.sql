-- Add unique constraint on proxy_host_id for ON CONFLICT clause
-- Use DO block to handle case where constraint already exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'proxy_security_headers_proxy_host_id_key'
    ) THEN
        ALTER TABLE proxy_security_headers ADD CONSTRAINT proxy_security_headers_proxy_host_id_key UNIQUE (proxy_host_id);
    END IF;
END $$;
