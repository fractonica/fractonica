# ADR 0008: Content-addressed resources

- Status: Accepted
- Date: 2026-07-18

## Context

Fractonica operations need to reference photos, audio, video, model artefacts
and other potentially large byte sequences. Embedding those bytes in every
operation or SQLite row would make replication, deduplication, backup and
partial local availability unnecessarily expensive. At the same time, a
missing local file must not invalidate an otherwise authentic causal history.

## Decision

Immutable bytes live outside SQLite and are identified by a versioned,
algorithm-tagged `ContentId`. Version 1 accepts exactly this wire form:

```text
sha-256:<64 lowercase hexadecimal digits>
```

The algorithm tag leaves an explicit future migration path, but version 1
rejects every unknown algorithm, uppercase spelling, uppercase hexadecimal,
and malformed length. `ContentDescriptor` couples an identity to its asserted
byte length. `ResourceRef` adds a bounded media type, semantic role and
optional path-free original-name label.

`record.v1` may contain at most 64 resource references. Content IDs must be
unique within one document. The operation validator validates only the
reference contract: it does not consult a filesystem, network, blob database,
or availability index. Consequently, missing bytes never invalidate or remove
an accepted operation. Nodes can represent availability separately and fetch
content later.

Content bytes are immutable. Replacing content creates another `ContentId` and
a new record operation. The original name is display provenance only; it is
never interpreted as a filesystem path.

The pure implementation lives in `fractonica-content`. It has no filesystem,
network, async runtime, database or system-clock dependency. The data-model
crate depends on its values but remains unaware of content-store location.

SQLite stores descriptors, availability and short transfer-state transactions,
while the actual bytes live in a node-owned content directory. The filesystem
layout, atomic import protocol, resumable HTTP surface, and crash-recovery
rules are defined in [`docs/content-storage.md`](../content-storage.md). Helpers
receive bounded content handles or explicitly granted inputs, never arbitrary
store paths.

## Integrity and authority

SHA-256 identifies bytes and detects accidental or adversarial substitution;
it does not identify an author. An HTTP `Content-Digest` header is transport
integrity metadata and likewise is not evidence of authorship or authority.
Version 2 operations authenticate the `ResourceRef` fields through the signed
record body, as defined by
[ADR 0009](0009-signed-operation-trust-kernel.md), but that signature does not
prove that the referenced bytes are safe or confidential. The
[threat model](../threat-model.md) defines the metadata exposed by private
resource references.

## Lifecycle

No resource is automatically garbage-collected merely because a current head
is a tombstone or no materialized view references it. Historical operations,
concurrent branches, peers and backups may still require the bytes. Safe
garbage collection needs an explicit retention and distributed-reachability
protocol; until then deletion is an intentional administrative operation.

This addition completes and freezes the pre-release `record.v1` document
shape. Later incompatible content or record semantics require another schema
identifier rather than silently reinterpreting `record.v1`.

## Consequences

- Identical immutable bytes deduplicate across records and operations.
- Operations remain valid and reducible when content is locally unavailable.
- Replication can exchange operation metadata before large resource bytes.
- Nodes must verify byte length and SHA-256 before marking content available.
- Backups must preserve both SQLite state and the node-owned content store.
- Automatic content deletion remains deliberately unavailable.
