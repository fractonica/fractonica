ALTER TABLE client_projections ADD COLUMN preview_emoji TEXT;
ALTER TABLE client_projections ADD COLUMN preview_text TEXT;
ALTER TABLE client_projections ADD COLUMN preview_truncated INTEGER NOT NULL DEFAULT 0
    CHECK (preview_truncated IN (0, 1));
