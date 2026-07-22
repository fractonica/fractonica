-- A local-network permission prompt may interrupt the joiner's first HTTP
-- response after the responder has durably claimed the one-shot invitation.
-- Persist the exact opaque Noise response frames so an identical first frame
-- can be answered idempotently without reopening the invitation.
ALTER TABLE pairing_sessions
    ADD COLUMN first_frame_digest BLOB
    CHECK (first_frame_digest IS NULL OR length(first_frame_digest) = 32);

ALTER TABLE pairing_sessions
    ADD COLUMN response_frame BLOB
    CHECK (response_frame IS NULL OR length(response_frame) BETWEEN 1 AND 16384);

ALTER TABLE pairing_sessions
    ADD COLUMN receipt_frame BLOB
    CHECK (receipt_frame IS NULL OR length(receipt_frame) BETWEEN 1 AND 16384);
