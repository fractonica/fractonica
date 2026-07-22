CREATE TABLE blobs (
    content_id TEXT PRIMARY KEY NOT NULL,
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    stored_at_unix_ms INTEGER NOT NULL CHECK (stored_at_unix_ms >= 0)
) STRICT;

CREATE TABLE upload_sessions (
    upload_id TEXT PRIMARY KEY NOT NULL,
    upload_length INTEGER NOT NULL CHECK (upload_length >= 0),
    upload_offset INTEGER NOT NULL DEFAULT 0 CHECK (
        upload_offset >= 0 AND upload_offset <= upload_length
    ),
    state TEXT NOT NULL CHECK (state IN ('active', 'finalizing', 'complete')),
    expected_content_id TEXT,
    final_content_id TEXT,
    upload_metadata TEXT CHECK (
        upload_metadata IS NULL OR length(CAST(upload_metadata AS BLOB)) <= 8192
    ),
    media_type TEXT,
    original_name TEXT,
    created_at_unix_ms INTEGER NOT NULL CHECK (created_at_unix_ms >= 0),
    expires_at_unix_ms INTEGER NOT NULL CHECK (
        expires_at_unix_ms >= created_at_unix_ms
    ),
    CHECK (
        (state = 'active' AND final_content_id IS NULL)
        OR (state IN ('finalizing', 'complete') AND final_content_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX upload_sessions_state_expiry_idx
    ON upload_sessions (state, expires_at_unix_ms, upload_id);

CREATE TABLE operation_resources (
    operation_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    content_id TEXT NOT NULL,
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    media_type TEXT NOT NULL,
    role TEXT NOT NULL,
    original_name TEXT,
    PRIMARY KEY (operation_id, position),
    UNIQUE (operation_id, content_id),
    FOREIGN KEY (operation_id)
        REFERENCES operations(operation_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX operation_resources_content_idx
    ON operation_resources (content_id, operation_id);
