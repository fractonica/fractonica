CREATE TABLE client_operations (
    local_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE,
    space_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
    stored_at_unix_ms INTEGER NOT NULL CHECK (stored_at_unix_ms >= 0),
    locally_authored INTEGER NOT NULL CHECK (locally_authored IN (0, 1)),
    projection_json TEXT NOT NULL CHECK (json_valid(projection_json)),
    UNIQUE (space_id, entity_id, schema_id, operation_id)
) STRICT;

CREATE INDEX client_operations_entity_idx
    ON client_operations (space_id, entity_id, schema_id, local_sequence);

CREATE TABLE client_operation_parents (
    operation_id TEXT NOT NULL,
    parent_operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    PRIMARY KEY (operation_id, parent_operation_id),
    UNIQUE (operation_id, position),
    FOREIGN KEY (operation_id) REFERENCES client_operations(operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (parent_operation_id) REFERENCES client_operations(operation_id) ON DELETE RESTRICT,
    CHECK (operation_id <> parent_operation_id)
) STRICT;

CREATE TABLE client_operation_authorizations (
    operation_id TEXT NOT NULL,
    authorization_operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    PRIMARY KEY (operation_id, authorization_operation_id),
    UNIQUE (operation_id, position),
    FOREIGN KEY (operation_id) REFERENCES client_operations(operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (authorization_operation_id) REFERENCES client_operations(operation_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE client_entity_heads (
    space_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (space_id, entity_id, operation_id),
    FOREIGN KEY (space_id, entity_id, schema_id, operation_id)
        REFERENCES client_operations(space_id, entity_id, schema_id, operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX client_entity_heads_lookup_idx
    ON client_entity_heads (space_id, entity_id, schema_id, operation_id);

CREATE TABLE client_entity_visibility (
    space_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    PRIMARY KEY (space_id, entity_id),
    UNIQUE (space_id, entity_id, schema_id)
) STRICT;

CREATE TABLE client_projections (
    operation_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    schema_id TEXT NOT NULL CHECK (schema_id IN ('record', 'event', 'tag', 'profile')),
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    start_at_unix_ms INTEGER,
    end_at_unix_ms INTEGER,
    sort_text TEXT,
    resource_count INTEGER NOT NULL CHECK (resource_count >= 0),
    media_bytes INTEGER NOT NULL CHECK (media_bytes >= 0),
    FOREIGN KEY (space_id, entity_id, schema_id, operation_id)
        REFERENCES client_operations(space_id, entity_id, schema_id, operation_id)
        ON DELETE CASCADE
) STRICT;

CREATE INDEX client_projections_temporal_idx
    ON client_projections (space_id, schema_id, start_at_unix_ms DESC, entity_id, operation_id);

CREATE INDEX client_projections_text_idx
    ON client_projections (space_id, schema_id, sort_text, entity_id, operation_id);

CREATE TABLE client_peers (
    peer_id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    added_at_unix_ms INTEGER NOT NULL CHECK (added_at_unix_ms >= 0)
) STRICT;

CREATE TABLE client_peer_spaces (
    peer_id TEXT NOT NULL,
    space_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    grant_operation_id TEXT NOT NULL,
    pull_after INTEGER NOT NULL DEFAULT 0 CHECK (pull_after >= 0),
    next_pull_at_unix_ms INTEGER NOT NULL CHECK (next_pull_at_unix_ms >= 0),
    pull_failure_count INTEGER NOT NULL DEFAULT 0 CHECK (pull_failure_count >= 0),
    last_pull_error TEXT,
    last_pull_at_unix_ms INTEGER,
    PRIMARY KEY (peer_id, space_id),
    FOREIGN KEY (peer_id) REFERENCES client_peers(peer_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX client_peer_spaces_due_idx
    ON client_peer_spaces (next_pull_at_unix_ms, peer_id, space_id);

CREATE TABLE client_deliveries (
    peer_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'acknowledged', 'rejected')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at_unix_ms INTEGER NOT NULL CHECK (next_attempt_at_unix_ms >= 0),
    lease_id TEXT,
    lease_expires_at_unix_ms INTEGER,
    acknowledged_at_unix_ms INTEGER,
    last_error TEXT,
    PRIMARY KEY (peer_id, operation_id),
    FOREIGN KEY (peer_id) REFERENCES client_peers(peer_id) ON DELETE CASCADE,
    FOREIGN KEY (operation_id) REFERENCES client_operations(operation_id) ON DELETE RESTRICT,
    CHECK ((state = 'leased') = (lease_id IS NOT NULL)),
    CHECK ((state = 'leased') = (lease_expires_at_unix_ms IS NOT NULL)),
    CHECK ((state = 'acknowledged') = (acknowledged_at_unix_ms IS NOT NULL))
) STRICT;

CREATE INDEX client_deliveries_due_idx
    ON client_deliveries (peer_id, state, next_attempt_at_unix_ms, lease_expires_at_unix_ms);

PRAGMA user_version = 1;
