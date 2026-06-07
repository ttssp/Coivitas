CREATE SCHEMA IF NOT EXISTS policy;

CREATE TABLE IF NOT EXISTS policy.action_records (
  id                   SERIAL PRIMARY KEY,
  record_id            TEXT UNIQUE NOT NULL,
  agent_did            TEXT NOT NULL,
  principal_did        TEXT NOT NULL,
  action_type          TEXT NOT NULL,
  parameters_summary   JSONB,
  authorization_ref    JSONB,
  result_summary       JSONB,
  record_hash          TEXT NOT NULL,
  previous_record_hash TEXT NOT NULL DEFAULT '',
  actor_signature      TEXT NOT NULL,
  ledger_signature     TEXT NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_action_records_agent ON policy.action_records (agent_did);
CREATE INDEX IF NOT EXISTS idx_action_records_principal ON policy.action_records (principal_did);
CREATE INDEX IF NOT EXISTS idx_action_records_action ON policy.action_records (action_type);
CREATE INDEX IF NOT EXISTS idx_action_records_time ON policy.action_records (created_at);
