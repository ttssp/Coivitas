CREATE TABLE IF NOT EXISTS policy.token_store (
  id          SERIAL PRIMARY KEY,
  token_id    TEXT UNIQUE NOT NULL,
  agent_did   TEXT NOT NULL,
  token       JSONB NOT NULL,
  valid_until TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_token_store_agent ON policy.token_store (agent_did);
CREATE INDEX IF NOT EXISTS idx_token_store_token ON policy.token_store (token_id);
