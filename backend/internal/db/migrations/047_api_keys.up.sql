CREATE TABLE api_keys (
  id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       UUID        NOT NULL,
  user_id      UUID        NOT NULL,
  name         TEXT        NOT NULL,
  key_prefix   TEXT        NOT NULL,
  key_hash     TEXT        NOT NULL UNIQUE,
  last_used_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at   TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_org_id   ON api_keys (org_id);
CREATE INDEX idx_api_keys_user_id  ON api_keys (user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys (key_hash);
