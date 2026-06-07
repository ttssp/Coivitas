CREATE SCHEMA IF NOT EXISTS identity;

CREATE TABLE IF NOT EXISTS identity.agents (
  id         SERIAL PRIMARY KEY,
  did        TEXT UNIQUE NOT NULL,
  document   JSONB NOT NULL,
  status     TEXT NOT NULL DEFAULT 'active'
             CHECK (status IN ('active', 'suspended', 'deactivated')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agents_did ON identity.agents (did);
CREATE INDEX IF NOT EXISTS idx_agents_status ON identity.agents (status);
