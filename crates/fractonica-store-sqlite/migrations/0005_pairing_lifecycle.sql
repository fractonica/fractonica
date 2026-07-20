-- Pairing secrets never enter SQLite. This table is the durable, non-secret
-- lifecycle/index half of the pairing protocol from ADR 0011.
CREATE TABLE pairing_sessions (
    invitation_id BLOB PRIMARY KEY NOT NULL CHECK (length(invitation_id) = 16),
    descriptor_cbor BLOB NOT NULL CHECK (length(descriptor_cbor) BETWEEN 1 AND 4096),
    descriptor_digest BLOB NOT NULL UNIQUE CHECK (length(descriptor_digest) = 32),
    space_id TEXT NOT NULL,
    responder_node_id BLOB NOT NULL CHECK (length(responder_node_id) = 32),
    expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms >= 0),
    state TEXT NOT NULL CHECK (state IN (
        'created', 'claimed', 'confirmed', 'completed', 'cancelled', 'expired'
    )),
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
    claimed_at_unix_ms INTEGER,
    claimed_expires_at_unix_ms INTEGER,
    confirmed_at_unix_ms INTEGER,
    completed_at_unix_ms INTEGER,
    terminal_at_unix_ms INTEGER,
    claim_digest BLOB CHECK (claim_digest IS NULL OR length(claim_digest) = 32),
    handshake_hash BLOB CHECK (handshake_hash IS NULL OR length(handshake_hash) = 32),
    joiner_node_id BLOB CHECK (joiner_node_id IS NULL OR length(joiner_node_id) = 32),
    subject_actor_id BLOB CHECK (subject_actor_id IS NULL OR length(subject_actor_id) = 32),
    planned_grant_operation_id TEXT,
    planned_grant_json TEXT CHECK (
        planned_grant_json IS NULL OR (
            length(CAST(planned_grant_json AS BLOB)) BETWEEN 2 AND 262144
            AND json_valid(planned_grant_json)
            AND json_type(planned_grant_json) = 'object'
        )
    ),
    grant_planned_at_unix_ms INTEGER,
    grant_operation_id TEXT,
    FOREIGN KEY (space_id) REFERENCES spaces(space_id) ON DELETE RESTRICT,
    CHECK (created_at_unix_ms < expires_at_unix_ms),
    CHECK (
        (state = 'created'
            AND claimed_at_unix_ms IS NULL
            AND claimed_expires_at_unix_ms IS NULL
            AND claim_digest IS NULL
            AND handshake_hash IS NULL
            AND joiner_node_id IS NULL
            AND subject_actor_id IS NULL)
        OR
        (state IN ('claimed', 'confirmed', 'completed')
            AND claimed_at_unix_ms IS NOT NULL
            AND claimed_expires_at_unix_ms IS NOT NULL
            AND claim_digest IS NOT NULL
            AND handshake_hash IS NOT NULL
            AND joiner_node_id IS NOT NULL
            AND subject_actor_id IS NOT NULL)
        OR state IN ('cancelled', 'expired')
    ),
    CHECK ((state IN ('confirmed', 'completed')) = (confirmed_at_unix_ms IS NOT NULL)),
    CHECK (claimed_expires_at_unix_ms IS NULL OR claimed_expires_at_unix_ms <= expires_at_unix_ms),
    CHECK ((state = 'completed') = (completed_at_unix_ms IS NOT NULL)),
    CHECK ((state = 'completed') = (grant_operation_id IS NOT NULL)),
    CHECK ((planned_grant_operation_id IS NULL) = (planned_grant_json IS NULL)),
    CHECK ((planned_grant_operation_id IS NULL) = (grant_planned_at_unix_ms IS NULL)),
    CHECK (state <> 'completed' OR grant_operation_id = planned_grant_operation_id),
    CHECK ((state IN ('completed', 'cancelled', 'expired')) = (terminal_at_unix_ms IS NOT NULL))
) STRICT;

CREATE INDEX pairing_sessions_expiry_idx
    ON pairing_sessions (state, expires_at_unix_ms);

CREATE INDEX pairing_sessions_peer_idx
    ON pairing_sessions (space_id, joiner_node_id, subject_actor_id);

PRAGMA user_version = 5;
