-- The raw token is app-private pairing material received inside Noise. It is
-- scoped to one completed pairing and never exposed through JavaScript.
ALTER TABLE client_peers
    ADD COLUMN peer_transport_credential TEXT;

CREATE TABLE client_active_workspace (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    space_id TEXT NOT NULL,
    authorization_operation_id TEXT NOT NULL,
    peer_id TEXT,
    activated_at_unix_ms INTEGER NOT NULL CHECK (activated_at_unix_ms >= 0),
    FOREIGN KEY (authorization_operation_id)
        REFERENCES client_operations(operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (peer_id)
        REFERENCES client_peers(peer_id) ON DELETE RESTRICT
) STRICT;
