-- Disposable read model. The signed operation log and entity_heads are the
-- authority; this table may be dropped and rebuilt from admitted operations.
CREATE TABLE client_operation_projections (
    space_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    schema_id TEXT NOT NULL CHECK (schema_id IN ('record', 'event', 'tag', 'profile')),
    actor_id TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    tombstone INTEGER NOT NULL CHECK (tombstone IN (0, 1)),
    start_at_unix_ms INTEGER,
    end_at_unix_ms INTEGER,
    sort_text TEXT,
    resource_count INTEGER NOT NULL CHECK (resource_count >= 0),
    media_bytes INTEGER NOT NULL CHECK (media_bytes >= 0),
    body_json TEXT NOT NULL CHECK (json_valid(body_json)),
    PRIMARY KEY (space_id, operation_id),
    FOREIGN KEY (space_id, operation_id)
        REFERENCES operations (space_id, operation_id) ON DELETE CASCADE,
    FOREIGN KEY (space_id, entity_id, schema_id, operation_id)
        REFERENCES operations (space_id, entity_id, schema_id, operation_id)
        ON DELETE CASCADE
) STRICT;

CREATE INDEX client_projection_temporal_idx
    ON client_operation_projections (
        space_id, schema_id, start_at_unix_ms DESC, entity_id, operation_id
    );

CREATE INDEX client_projection_text_idx
    ON client_operation_projections (
        space_id, schema_id, sort_text, entity_id, operation_id
    );

CREATE INDEX client_projection_actor_idx
    ON client_operation_projections (space_id, schema_id, actor_id, entity_id);

PRAGMA user_version = 7;
