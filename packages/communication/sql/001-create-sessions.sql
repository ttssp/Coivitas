CREATE SCHEMA IF NOT EXISTS communication;

CREATE TABLE IF NOT EXISTS communication.sessions (
  session_id              UUID PRIMARY KEY,
  initiator_did           TEXT NOT NULL,
  responder_did           TEXT NOT NULL,
  principal_did           TEXT NOT NULL,
  capability_token_id     TEXT
                          CHECK (
                              capability_token_id IS NULL
                              OR capability_token_id ~
                                 '^urn:cap:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                          ),
  capability_token_fingerprint TEXT
                          CHECK (
                              capability_token_fingerprint IS NULL
                              OR capability_token_fingerprint ~ '^[0-9a-f]{64}$'
                          ),
  state                   TEXT NOT NULL
                          CHECK (state IN ('CREATED', 'ACTIVE', 'IDLE', 'CLOSED')),
  negotiated_capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
  established_at          TIMESTAMPTZ,
  last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_authorized_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  idle_since              TIMESTAMPTZ,
  closed_at               TIMESTAMPTZ,
  close_reason            VARCHAR(32)
                          CHECK (close_reason IS NULL OR close_reason IN (
                              'IDLE_TIMEOUT','EXPLICIT_CLOSE','HANDSHAKE_REJECTED','ERROR','REVOKED_TOKEN'
                          )),
  supersedes_session_id   UUID
                          REFERENCES communication.sessions (session_id)
                          DEFERRABLE INITIALLY DEFERRED,
  did_pair_key            TEXT GENERATED ALWAYS AS (
                              LEAST(initiator_did, responder_did) || E'\\x00' ||
                              GREATEST(initiator_did, responder_did)
                          ) STORED,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revision                BIGINT NOT NULL DEFAULT 1,
  CONSTRAINT chk_sessions_closed_consistency
      CHECK ((state = 'CLOSED' AND closed_at IS NOT NULL AND close_reason IS NOT NULL)
             OR (state <> 'CLOSED' AND closed_at IS NULL AND close_reason IS NULL)),
  CONSTRAINT chk_sessions_idle_consistency
      CHECK ((state = 'IDLE' AND idle_since IS NOT NULL)
             OR (state <> 'IDLE' AND idle_since IS NULL)),
  CONSTRAINT chk_sessions_established_consistency
      CHECK ((state = 'CREATED' AND established_at IS NULL)
             OR (state IN ('ACTIVE', 'IDLE', 'CLOSED'))),
  CONSTRAINT chk_sessions_token_fingerprint_pairing
      CHECK ((capability_token_id IS NULL AND capability_token_fingerprint IS NULL)
             OR (capability_token_id IS NOT NULL AND capability_token_fingerprint IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_sessions_state_authorized
    ON communication.sessions (state, last_authorized_at);
CREATE INDEX IF NOT EXISTS idx_sessions_state_seen
    ON communication.sessions (state, last_seen_at);
CREATE INDEX IF NOT EXISTS idx_sessions_initiator
    ON communication.sessions (initiator_did);
CREATE INDEX IF NOT EXISTS idx_sessions_responder
    ON communication.sessions (responder_did);
CREATE INDEX IF NOT EXISTS idx_sessions_created
    ON communication.sessions (created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_supersedes
    ON communication.sessions (supersedes_session_id)
    WHERE supersedes_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_principal
    ON communication.sessions (principal_did);
CREATE INDEX IF NOT EXISTS idx_sessions_capability_token
    ON communication.sessions (capability_token_id)
    WHERE capability_token_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_sessions_live_per_pair
    ON communication.sessions (did_pair_key)
    WHERE state IN ('CREATED', 'ACTIVE', 'IDLE');
