-- Migration 004: add encryption-state columns to the session table
-- Aligned with the end-to-end encryption key lifecycle

-- [Field 1] encryption_state: session encryption state (OFF=unencrypted / REQUIRED=E2E encrypted)
-- Defaults to 'OFF' to keep pre-existing session rows forward-compatible; written by activate()/resume() after the handshake completes, then immutable
ALTER TABLE communication.sessions
    ADD COLUMN IF NOT EXISTS encryption_state TEXT NOT NULL DEFAULT 'OFF'
        CHECK (encryption_state IN ('OFF', 'REQUIRED'));

-- [Field 2] session_key_fingerprint: fingerprint of the current-generation session key (SHA-256 64-char hex)
-- Updated on every in-place re-handshake; always NULL while OFF
-- Format: '^[0-9a-f]{64}$' (same format spec as capability_token_fingerprint)
ALTER TABLE communication.sessions
    ADD COLUMN IF NOT EXISTS session_key_fingerprint TEXT
        CHECK (
            session_key_fingerprint IS NULL
            OR session_key_fingerprint ~ '^[0-9a-f]{64}$'
        );

-- [Field 3] rekey_count: cumulative count of in-place re-handshakes (+1 after swapForDualKey)
-- chain-key rekey is not counted; a close+fresh handshake yields a new session starting from 0
-- Always 0 while OFF
ALTER TABLE communication.sessions
    ADD COLUMN IF NOT EXISTS rekey_count INTEGER NOT NULL DEFAULT 0
        CHECK (rekey_count >= 0);

-- [Consistency constraint] consistency between encryption_state and the key fingerprint / rekey_count
-- When OFF: session_key_fingerprint must be NULL and rekey_count must be 0
-- When REQUIRED: no enforced constraint (the fingerprint is written by the business layer after the handshake completes)
ALTER TABLE communication.sessions
    ADD CONSTRAINT chk_sessions_encryption_state_consistency
        CHECK (
            (encryption_state = 'OFF' AND session_key_fingerprint IS NULL AND rekey_count = 0)
            OR (encryption_state = 'REQUIRED')
        );

-- [Index] filter by encryption state (for audit queries and monitoring)
CREATE INDEX IF NOT EXISTS idx_sessions_encryption_state
    ON communication.sessions (encryption_state)
    WHERE encryption_state = 'REQUIRED';
