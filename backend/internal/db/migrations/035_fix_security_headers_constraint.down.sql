-- Remove unique constraint (if it exists)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'proxy_security_headers_proxy_host_id_key'
    ) THEN
        ALTER TABLE proxy_security_headers DROP CONSTRAINT proxy_security_headers_proxy_host_id_key;
    END IF;
END $$;
