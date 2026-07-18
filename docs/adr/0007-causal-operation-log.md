# ADR 0007: Canonical causal operation log

- Status: Accepted
- Date: 2026-07-18

## Context

Fractonica needs one generic foundation for local-first data, conflict
retention, replication, provenance, and future model-derived projections. A
schema made only from mutable record rows would discard the causal information
needed to distinguish a linear edit, an offline concurrent edit, a deliberate
merge, and a deletion observed by only some peers.

The durable representation must remain independent of SQLite and HTTP. It also
must be deterministic so every node reduces the same accepted history to the
same heads without consulting a clock or relying on database row order.

## Decision

The canonical unit is a versioned immutable `OperationEnvelope`. It identifies
an operation, entity, schema and actor; carries a nonnegative occurrence time;
retains an ordered, duplicate-free list of direct causal parent operation IDs;
and contains a schema-specific body. Version 1 defines `record.v1`, whose body
is either a complete document `put` or a tombstone.

Entity history is a directed acyclic graph. An operation is accepted only after
all of its parents have been accepted for the same entity. This topological
requirement rejects missing and forward/cyclic parent references without a
graph search. Operation and parent-list order remain part of the envelope, but
the materialized head list is sorted by operation ID for deterministic output.

Reduction starts with no heads. Applying an operation removes its direct
parents from the head set and adds the new operation. Consequently:

- an edit referencing the current head replaces it;
- edits independently referencing the same earlier head survive concurrently;
- a merge referencing every current head collapses them into one new head;
- a tombstone is retained as an ordinary causal head and can conflict with a
  concurrent edit rather than silently erasing it.

The operation log is authoritative. Mutable query tables, search indexes,
embeddings, summaries, model states, and other projections are derived and may
be rebuilt. A derived value records its source operations and model or
transformation identity; it does not rewrite the canonical history.

The pure Rust implementation lives in `fractonica-data-model`. It has no
database, network, filesystem, async runtime, random-number, or system-clock
dependency. UUID creation and occurrence-time sampling happen at an
application boundary before validation.

SQLite stores accepted envelopes and may maintain transactional head and query
projections, but replication sends validated application operations rather
than database pages. Receipt time, transport retry state and local scheduling
metadata are storage concerns and are not canonical envelope fields.

This ADR does not select canonical signing bytes, content hashing, encryption,
actor key semantics, or authorization. Those remain subject to a dedicated
threat model and security ADR before network exposure.

## Bounds and compatibility

Protocol version, schema identifier, causal-parent count, text, emoji and JSON
metadata all have explicit bounds. Unsupported protocol or schema versions are
rejected; they are never guessed or reinterpreted. Breaking semantic changes
require a new version and conformance fixtures.

Operations use millisecond Unix timestamps in version 1 because that matches
the initial client data contract. Saros phase and glyph values are derived from
an explicit instant by the temporal engine; they are not duplicated as
independent canonical clocks in the operation envelope.

## Consequences

- Offline concurrency is preserved instead of being resolved by arrival time.
- Merges and tombstones have explicit, replayable causal meaning.
- Nodes can rebuild materialized state and future AI-derived representations.
- Every accepted operation requires bounded validation and existing parents.
- Importers must topologically order an entity's operations before submission.
- Garbage collection and history compaction require a future protocol decision;
  deleting ancestors locally would invalidate causal proofs and peer replay.
