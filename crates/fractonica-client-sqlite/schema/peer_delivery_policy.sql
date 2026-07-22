-- Paired reads are available before actor-authenticated operation/content
-- writes. Keep those peers enabled for pull/download work without ever
-- queueing local operations or media for an unauthenticated push endpoint.
ALTER TABLE client_peers
    ADD COLUMN push_enabled INTEGER NOT NULL DEFAULT 1
    CHECK (push_enabled IN (0, 1));

ALTER TABLE client_peers
    ADD COLUMN content_read_enabled INTEGER NOT NULL DEFAULT 1
    CHECK (content_read_enabled IN (0, 1));
