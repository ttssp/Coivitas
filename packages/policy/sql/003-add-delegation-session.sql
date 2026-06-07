-- 003-add-delegation-session.sql
-- Add the delegation chain depth and session ID columns
ALTER TABLE policy.action_records
    ADD COLUMN IF NOT EXISTS delegation_depth INTEGER,
    ADD COLUMN IF NOT EXISTS session_id       TEXT;

CREATE INDEX IF NOT EXISTS idx_action_records_session
    ON policy.action_records (session_id, created_at);
