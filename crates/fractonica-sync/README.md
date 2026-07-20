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
6. advances the durable cursor only after the complete page is committed;
7. reconciles locally authored resource descriptors with the private blob
   store;
8. advances a bounded number of resumable uploads or downloads by one bounded
   chunk each.

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

The worker automatically discovers immutable resources referenced by committed
operations. Locally authored resources wait until their digest and length are
verified, then fan out to enabled peers. Resources learned from a peer are
downloaded from that source and become eligible for other peers only after the
local content store verifies and atomically publishes the complete blob.

Availability checks avoid duplicate transfer. Upload URLs and offsets survive
worker restarts; download offsets are recovered from durable partial files.
Each leased job moves at most one configured chunk per cycle, so neither a
large video nor a large restore monopolizes the async executor. Missing media
is retry state and never prevents operation convergence.
