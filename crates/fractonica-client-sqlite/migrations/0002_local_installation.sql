CREATE TABLE client_local_installation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    phase TEXT NOT NULL CHECK (phase IN ('initializing', 'established')),
    node_id TEXT,
    space_id TEXT,
    controller_actor_id TEXT,
    local_writer_actor_id TEXT,
    genesis_operation_id TEXT,
    initial_grant_operation_id TEXT,
    display_name TEXT,
    created_at_unix_ms INTEGER CHECK (created_at_unix_ms >= 0),
    CHECK (
        (phase = 'initializing'
            AND node_id IS NULL
            AND space_id IS NULL
            AND controller_actor_id IS NULL
            AND local_writer_actor_id IS NULL
            AND genesis_operation_id IS NULL
            AND initial_grant_operation_id IS NULL
            AND display_name IS NULL
            AND created_at_unix_ms IS NULL)
        OR
        (phase = 'established'
            AND node_id IS NOT NULL
            AND space_id IS NOT NULL
            AND controller_actor_id IS NOT NULL
            AND local_writer_actor_id IS NOT NULL
            AND genesis_operation_id IS NOT NULL
            AND initial_grant_operation_id IS NOT NULL
            AND display_name IS NOT NULL
            AND created_at_unix_ms IS NOT NULL)
    ),
    FOREIGN KEY (genesis_operation_id)
        REFERENCES client_operations(operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (initial_grant_operation_id)
        REFERENCES client_operations(operation_id) ON DELETE RESTRICT
) STRICT;

PRAGMA user_version = 2;
