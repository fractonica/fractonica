-- A completed pairing is also the durable paired-device registry. Activity is
-- touched only after the pairing token and its capability grant both verify.
ALTER TABLE pairing_sessions
    ADD COLUMN last_seen_at_unix_ms INTEGER
    CHECK (last_seen_at_unix_ms IS NULL OR last_seen_at_unix_ms >= 0);

CREATE INDEX pairing_sessions_completed_activity_idx
    ON pairing_sessions (state, last_seen_at_unix_ms, completed_at_unix_ms);
