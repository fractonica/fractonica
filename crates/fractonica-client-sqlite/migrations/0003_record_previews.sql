ALTER TABLE client_projections ADD COLUMN preview_emoji TEXT;
ALTER TABLE client_projections ADD COLUMN preview_text TEXT;
ALTER TABLE client_projections ADD COLUMN preview_truncated INTEGER NOT NULL DEFAULT 0
    CHECK (preview_truncated IN (0, 1));

-- Existing development databases may already contain public records. Keep the
-- projection bounded while recovering enough display data for a feed card.
-- A Unicode scalar can occupy at most four UTF-8 bytes, so 32 and 192 scalars
-- respectively preserve the byte limits enforced by the Rust boundary.
UPDATE client_projections
SET preview_emoji = substr(
        (SELECT json_extract(o.projection_json, '$.body.payload.document.emoji')
         FROM client_operations o
         WHERE o.operation_id = client_projections.operation_id),
        1,
        32
    ),
    preview_text = substr(
        (SELECT json_extract(o.projection_json, '$.body.payload.document.text')
         FROM client_operations o
         WHERE o.operation_id = client_projections.operation_id),
        1,
        192
    ),
    preview_truncated = coalesce(
        (SELECT length(json_extract(o.projection_json, '$.body.payload.document.text')) > 192
         FROM client_operations o
         WHERE o.operation_id = client_projections.operation_id),
        0
    )
WHERE schema_id = 'record' AND visibility = 'public' AND tombstone = 0;

PRAGMA user_version = 3;
