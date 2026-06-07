CREATE TABLE IF NOT EXISTS identity.revocations (
  id         SERIAL PRIMARY KEY,
  token_id   TEXT UNIQUE NOT NULL,
  revoked_by TEXT NOT NULL,
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reason     TEXT
);

CREATE INDEX IF NOT EXISTS idx_revocations_token ON identity.revocations (token_id);
CREATE INDEX IF NOT EXISTS idx_revocations_time ON identity.revocations (revoked_at);
