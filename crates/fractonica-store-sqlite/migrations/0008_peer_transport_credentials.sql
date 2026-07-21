-- Pairing-scoped bearer material is never stored directly. The node retains
-- only its SHA-256 digest and checks the pairing/grant on every request.
ALTER TABLE pairing_sessions
    ADD COLUMN peer_token_digest BLOB
    CHECK (peer_token_digest IS NULL OR length(peer_token_digest) = 32);

PRAGMA user_version = 8;
