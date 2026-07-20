# fractonica-sync

`fractonica-sync` is the supervised native synchronization worker for
Fractonica clients. It connects the durable client outbox to the signed node
API and consumes paired incremental change pages back into the local store.

One bounded cycle:

1. leases a small ordered delivery batch for each enabled peer;
2. submits unchanged signed operations;
3. acknowledges success, schedules retryable failures with exponential
   backoff, or retains permanent rejections for inspection;
4. reads due peer-space cursors with a fresh dual-signed proof;
5. verifies and commits every returned operation locally;
6. advances the durable cursor only after the complete page is committed.

All SQLite work runs through `spawn_blocking`. The async supervisor publishes a
small `watch` status snapshot and responds to a shutdown channel; UI code never
waits for a record-count scan or network request.

`SyncTransport` and `SyncClock` are injectable. `NodeHttpTransport` implements
the current signed admission and paired-read HTTP contract. `PeerProofCustody`
keeps detached proof signing behind a native boundary; the included software
adapter is intended for tests and protected headless agents.

The current paired-read endpoint remains loopback-only and does not provide
transport confidentiality. This worker does not change that boundary. LAN and
internet use still requires the planned encrypted session transport.

The HTTP adapter also provides bounded content primitives: ordered availability
queries, tus upload creation/status, one checksummed upload chunk, and one HTTP
range download chunk committed through `fractonica-client-content`. Each call
returns explicit progress suitable for durable scheduling; it never buffers a
whole media file. Automatic discovery and queueing of resources referenced by
new operations is the next integration step.
