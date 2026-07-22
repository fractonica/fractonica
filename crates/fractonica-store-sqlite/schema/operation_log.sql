CREATE TABLE operations (
    local_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE,
    protocol_version INTEGER NOT NULL CHECK (protocol_version BETWEEN 1 AND 65535),
    entity_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('put', 'tombstone')),
    occurred_at_unix_ms INTEGER NOT NULL CHECK (occurred_at_unix_ms >= 0),
    received_at_unix_ms INTEGER NOT NULL CHECK (received_at_unix_ms >= 0),
    payload BLOB NOT NULL,
    UNIQUE (entity_id, operation_id),
    UNIQUE (entity_id, schema_id, operation_id)
) STRICT;

CREATE INDEX operations_entity_sequence_idx
    ON operations (schema_id, entity_id, local_sequence);

CREATE INDEX operations_actor_sequence_idx
    ON operations (actor_id, local_sequence);

CREATE TABLE operation_parents (
    entity_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    parent_operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    PRIMARY KEY (operation_id, parent_operation_id),
    UNIQUE (operation_id, position),
    FOREIGN KEY (entity_id, schema_id, operation_id)
        REFERENCES operations(entity_id, schema_id, operation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (entity_id, schema_id, parent_operation_id)
        REFERENCES operations(entity_id, schema_id, operation_id)
        ON DELETE RESTRICT,
    CHECK (operation_id <> parent_operation_id)
) STRICT;

CREATE INDEX operation_parents_parent_idx
    ON operation_parents (parent_operation_id, operation_id);

CREATE TABLE entity_heads (
    entity_id TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (entity_id, operation_id),
    FOREIGN KEY (entity_id, operation_id)
        REFERENCES operations(entity_id, operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX entity_heads_entity_idx
    ON entity_heads (entity_id, operation_id);

CREATE TABLE idempotency_receipts (
    actor_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    semantic_request_hash BLOB NOT NULL CHECK (length(semantic_request_hash) = 32),
    operation_id TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
    PRIMARY KEY (actor_id, idempotency_key),
    FOREIGN KEY (operation_id)
        REFERENCES operations(operation_id)
        ON DELETE RESTRICT,
    -- Mirrors fractonica_application::{MIN,MAX}_IDEMPOTENCY_KEY_LENGTH.
    CHECK (length(idempotency_key) BETWEEN 8 AND 200)
) STRICT;
