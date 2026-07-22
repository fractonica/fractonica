# Replication and anti-entropy

Fractonica replication is local-first. A successfully committed local operation
is durable before networking starts. Disconnecting, suspending, restarting, or
replacing a peer session may delay delivery, but must not remove the operation
from the local log or make it permanently ineligible for replication.

## Two complementary mechanisms

1. The durable outbox provides low-latency ordered delivery. Failed network
   requests remain pending with bounded backoff. A newly admitted peer session
   reopens every non-acknowledged operation and media upload for its space.
2. Anti-entropy inventories periodically prove whether two stores contain the
   same immutable objects. They repair missed notifications, lost receipts,
   restored backups, and stale delivery metadata.

Neither peer is authoritative. Every received operation still passes signature,
capability, causal-parent, and schema validation before entering the local log.

## Why the inventory is an octal radix tree

The tree has eight children per node, matching one MSB-first octal digit of a
256-bit object identifier. A branch is selected from the identifier itself, not
from local insertion position. Two offline nodes can therefore create objects
in different orders without shifting unrelated buckets.

A position-based tree where every eight appended records form a parent bucket
is unsuitable for multi-writer replication: local sequence numbers are not
global, and one insertion near the front changes every later bucket.

The canonical inventory primitive lives in `fractonica-replication`.

- radix: 8;
- direct-transfer bucket capacity: 8 entries;
- key: immutable 256-bit operation or content identifier;
- value digest: SHA-256 of the exact canonical object bytes;
- path: at most 86 MSB-first octal digits;
- hash: domain-separated SHA-256 binding namespace, prefix, subtree count,
  child digit, child count, and child hash;
- namespaces separate operation and content inventories.

## Reconciliation

For each shared space, authenticated peers exchange the operation root summary.

1. Equal root hash and count means the inventories are equal; stop.
2. Otherwise compare the eight child summaries.
3. Recurse only into missing or mismatched children.
4. A subtree containing at most eight entries is returned as a complete bucket.
5. Each side requests missing canonical operations. Operations are admitted in
   causal order; unresolved parents are requested before their descendants.
6. Repeat the root comparison until both roots match or a bounded session
   budget is exhausted.

The same exchange runs independently for content IDs. Media bytes remain
content-addressed and resumable; an inventory match never bypasses byte-length
or digest verification.

Record counts are useful telemetry but never a correctness proof. An edit or a
deletion adds a new immutable operation and can leave the visible record count
unchanged.

## Connection lifecycle

- Startup and network-path changes wake the durable outbox immediately.
- Online workspace members run a bounded anti-entropy exchange after
  membership authentication.
- A clean root is cached only as an optimization; peers recheck periodically.
- Mobile suspension is safe. The next foreground/network opportunity resumes
  from durable queues and inventory roots.
- A signed, workspace-scoped peer directory lets every discoverable member
  learn alternate routes; pairwise invitation secrets are never propagated.
- Mesh cycles are expected. Immutable operation/content IDs and inventories,
  rather than an acyclic topology, suppress duplicate relay.
- Edge unlinking stops one direct route without revoking workspace membership.
  Membership revocation is a separate administrative operation.
- Revocation stops admission immediately. Relinking after revocation requires
  a new active membership capability and reopens work rejected under the old
  grant.

## Implementation sequence

1. Deterministic inventory core and conformance vectors.
2. Incrementally maintained SQLite inventory nodes for operations.
3. Authenticated root, child-summary, and bucket endpoints.
4. Bounded client reconciliation with causal dependency fetching.
5. Independent content inventory and resumable media repair.
6. LAN discovery and connection wakeups; periodic reconciliation remains the
   correctness fallback.
