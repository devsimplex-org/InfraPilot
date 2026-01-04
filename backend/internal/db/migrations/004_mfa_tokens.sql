-- Migration: 004_mfa_tokens
-- Description: MFA tokens and backup codes for two-factor authentication

-- ============ MFA Tokens ============
-- Temporary tokens for MFA verification flow

CREATE TABLE mfa_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(64) UNIQUE NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    used_at         TIMESTAMPTZ
);

CREATE INDEX idx_mfa_tokens_user ON mfa_tokens(user_id);
CREATE INDEX idx_mfa_tokens_hash ON mfa_tokens(token_hash);

-- ============ MFA Backup Codes ============
-- One-time use backup codes for account recovery

CREATE TABLE mfa_backup_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash       VARCHAR(64) NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_mfa_backup_codes_user ON mfa_backup_codes(user_id);

-- ============ Cleanup Function ============
-- Remove expired MFA tokens (run periodically)

CREATE OR REPLACE FUNCTION cleanup_expired_mfa_tokens()
RETURNS void AS $$
BEGIN
    DELETE FROM mfa_tokens WHERE expires_at < NOW() OR used_at IS NOT NULL;
END;
$$ LANGUAGE plpgsql;
