CREATE TABLE client_local_installation (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    node_id TEXT NOT NULL,
    controller_actor_id TEXT NOT NULL,
    local_writer_actor_id TEXT NOT NULL
) STRICT;

CREATE TABLE client_workspaces (
    space_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    genesis_operation_id TEXT NOT NULL UNIQUE,
    initial_grant_operation_id TEXT NOT NULL UNIQUE,
    controller_actor_id TEXT NOT NULL,
    local_writer_actor_id TEXT NOT NULL,
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
    FOREIGN KEY (genesis_operation_id)
        REFERENCES client_operations(operation_id) ON DELETE RESTRICT,
    FOREIGN KEY (initial_grant_operation_id)
        REFERENCES client_operations(operation_id) ON DELETE RESTRICT
) STRICT;
