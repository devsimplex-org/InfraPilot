-- Confirmation OTPs table for sensitive operation verification
CREATE TABLE IF NOT EXISTS confirmation_otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS idx_confirmation_otps_user_id ON confirmation_otps(user_id);
CREATE INDEX IF NOT EXISTS idx_confirmation_otps_expires_at ON confirmation_otps(expires_at);
