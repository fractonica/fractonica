CREATE TABLE peer_request_nonces (
    invitation_id BLOB NOT NULL CHECK (length(invitation_id) = 16),
    nonce BLOB NOT NULL CHECK (length(nonce) = 16),
    expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms >= 0),
    consumed_at_unix_ms INTEGER NOT NULL CHECK (consumed_at_unix_ms >= 0),
    PRIMARY KEY (invitation_id, nonce),
    FOREIGN KEY (invitation_id) REFERENCES pairing_sessions(invitation_id) ON DELETE CASCADE
) WITHOUT ROWID, STRICT;

CREATE INDEX peer_request_nonces_expiry_idx
    ON peer_request_nonces (expires_at_unix_ms);
