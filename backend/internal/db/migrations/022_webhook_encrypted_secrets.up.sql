-- Add encrypted secret column to webhook_configs
-- The secret_encrypted column stores AES-256-GCM encrypted secrets
-- Format: nonce (12 bytes) + ciphertext + tag (16 bytes)

ALTER TABLE webhook_configs ADD COLUMN IF NOT EXISTS secret_encrypted BYTEA;

-- Note: Existing webhooks will need their secrets regenerated since we cannot
-- recover the original secret from the bcrypt hash. The old secret_hash column
-- is kept temporarily for reference but will not be used for verification.

COMMENT ON COLUMN webhook_configs.secret_encrypted IS 'AES-256-GCM encrypted webhook secret for signature verification';
