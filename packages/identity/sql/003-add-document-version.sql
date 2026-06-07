-- Backward compatible: ALTER TABLE ADD COLUMN IF NOT EXISTS + DEFAULT values
-- Existing rows automatically get: version=1, previous_document=NULL, rotation_state='ACTIVE', rotation_started_at=NULL
ALTER TABLE identity.agents
  ADD COLUMN IF NOT EXISTS version             INTEGER  NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS previous_document   JSONB,
  ADD COLUMN IF NOT EXISTS rotation_state      TEXT     NOT NULL DEFAULT 'ACTIVE'
      CHECK (rotation_state IN ('ACTIVE', 'ROTATING')),
  ADD COLUMN IF NOT EXISTS rotation_started_at TIMESTAMPTZ;

COMMENT ON COLUMN identity.agents.version IS
  'Document version starting at 1; incremented on each key rotation (optimistic lock via UPDATE ... WHERE version = $expected)';
COMMENT ON COLUMN identity.agents.previous_document IS
  'Snapshot of previous AgentIdentityDocument before last rotation; NULL for version=1';
COMMENT ON COLUMN identity.agents.rotation_state IS
  'Registry-authoritative Grace Period state: ACTIVE (normal) or ROTATING (old key still accepted within grace period)';
COMMENT ON COLUMN identity.agents.rotation_started_at IS
  'Server-side timestamp when key rotation was initiated; used for Grace Period expiry enforcement';
