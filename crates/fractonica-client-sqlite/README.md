# fractonica-client-sqlite

This crate is the durable local-first store for native Fractonica clients. It
has a fresh client-specific SQLite schema and does not reuse the node database.

`commit_local` atomically stores one verified signed operation, advances causal
heads, updates the disposable client projection, and creates delivery rows for
every enabled peer. Returning success means the data is safely local; it does
not mean any node is online.

`commit_from_peer` records the source peer as acknowledged and queues the same
immutable operation for every other enabled peer. This lets a client converge
multiple home nodes without rewriting identities or signatures. `commit_remote`
is available for trusted local imports/bootstrap where no source-peer delivery
state should be inferred.

Background workers use `lease_due` with a unique `DeliveryLeaseId`. Leases
expire after crashes, stale workers cannot acknowledge a newer lease, and
retry/rejection state is durable. Batch size is bounded so the caller can run
each synchronous store call on a native blocking pool without monopolizing a
UI executor.

Every operation resource is also indexed by immutable content ID. The store
creates independent per-peer upload and download jobs, persists partial byte
progress and remote tus URLs, and leases that work with
`ResourceTransferLeaseId`. A local verification atomically unlocks every
waiting upload. A verified peer download completes redundant source jobs and
unlocks fan-out to other peers without changing the signed operation.

Resource bytes never enter SQLite. `fractonica-client-content` remains the
source of truth for local byte availability; SQLite stores only descriptors,
references, scheduling state, and aggregate progress.

Entity heads and client projections are derived entirely from immutable local
operations. `rebuild_derived_state` recreates both without altering delivery
state.

Every peer-space cursor records an explicit read mode. A supervised desktop
node uses its private loopback bearer channel; an independently paired peer
requires a pairing session and capability grant for dual-signed reads. The
store does not infer one trust mode from the presence of credentials.
