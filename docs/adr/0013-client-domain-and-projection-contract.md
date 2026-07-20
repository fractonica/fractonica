# ADR 0013: Client domain and projection contract

- Status: Accepted
- Date: 2026-07-20
- Scope: Minimum signed application vocabulary and rebuildable read model used
  by the first Fractonica desktop/web and iOS clients.

## Context

The signed operation v2 trust kernel intentionally began with only
`record.v1`. Exeligmos demonstrates the product surface we need to preserve,
but its password accounts, server revisions, CRUD commands, short record IDs,
and server-authoritative tables are not Fractonica protocol concepts.

The new clients need a small, stable vocabulary before UI or synchronization
code is migrated. Encoding product concepts as untyped metadata would make
authorization, indexing, references, encryption, and cross-platform
conformance impossible to review.

## Decision

Protocol v2 gains four client schemas while retaining `record.v1` only as an
already-published compatibility fixture:

- `record.v2`: temporal journal/data record with ordered immutable resources
  and typed references;
- `tag.v1`: reusable user-defined classification entity;
- `event.v1`: lightweight temporal interval with numeric type, label,
  metadata, and references, but no media;
- `profile.v1`: the public presentation of the signing actor, including its
  handle, display name, Saros anchor, and optional avatar resource.

Every mutable schema uses the existing causal operation rules. Creation has no
causal parents, edits name every head observed by the author, and deletion is
an immutable tombstone. Absence from a peer or projection never means delete.

### References

`EntityReferenceV1` is an ordered, signed value containing:

- a bounded lowercase relation token;
- either an actor target or an entity target;
- entity targets contain an exact `SpaceId`, `EntityId`, and optional pinned
  `OperationId` revision.

An unpinned entity reference follows the logical entity. A pinned reference
names immutable history. Cross-space targets are allowed and are not required
to exist locally at admission time. Reference order is semantic, duplicate
values are rejected, and references never confer authority.

The first clients use the relation tokens `tag`, `mentions`, `source`,
`reply-to`, `related`, and `device`, but the protocol accepts any bounded token
matching the shared grammar. Meaning can evolve without changing SQL columns.

### Profiles

A profile is authored only by the actor it presents. Its `EntityId` is
deterministically derived from the actor public key and the domain
`fractonica-profile-entity-v1`, preventing two offline devices from inventing
different profile entities for the same actor. Handles are presentation data,
not authentication identities or globally unique authority.

### Visibility and encryption

`public` means the signed application document is cleartext. `private` means
the signed body contains an `EncryptedPayloadV1` envelope instead of the
application document. The outer operation still exposes protocol version,
space, actor, entity, schema, causal and authorization references, operation
time, nonce, ciphertext length, key identifier, and encrypted-resource
descriptors. Application start/end times, labels, text, metadata, and semantic
references remain encrypted.

The envelope selects `aes-256-gcm`, a random 96-bit nonce, a 256-bit opaque key
identifier, and bounded ciphertext. Its associated data is deterministic CBOR
over the complete unsigned operation header plus the envelope version,
algorithm, and key identifier. This prevents moving ciphertext between actors,
spaces, entities, schemas, revisions, or authorization contexts.

Private resources are encrypted independently before hashing with a fresh
nonce. Their outer descriptors use `application/octet-stream`, role
`encrypted`, and no original filename. Key creation, distribution, rotation,
backup, and recovery are a separate key-custody protocol and MUST be complete
before private Exeligmos data is migrated. A `private` label without a valid
encrypted envelope is rejected for the new schemas.

### Capability scope

The previously committed `recordVisibilities` JSON name in
`capability.grant.v1` is replaced by the
semantically correct `visibilities` name before client release. Its canonical
CBOR position and codes remain unchanged. Visibility scope applies to every
client schema carrying a public/private payload, not only records.

`profile.v1` is public-only. Append authority for it is still explicit and the
profile signer/entity derivation rules are additionally enforced.

### Rebuildable projections

SQLite maintains disposable projections derived only from admitted
operations. The first query contract provides bounded, cursor-based reads for:

- records ordered by `startAtUnixMs`, then entity ID;
- events ordered by `startAtUnixMs`, then entity ID;
- tags ordered by normalized display name, then entity ID;
- profiles resolved by actor ID;
- aggregate record/media counts and media bytes.

Private entities remain visible to an authorized client as opaque heads until
that client supplies keys locally; the node never indexes encrypted temporal
or text fields. Query cursors are node-local projection cursors, not causal or
portable identifiers.

## Client boundaries

The desktop webview does not hold long-lived private keys in ordinary browser
storage. Its Tauri Rust layer owns the client actor and signs operations. iOS
uses the same client-core semantics through a reviewed native boundary and
keeps keys in Keychain-backed custody. Both implementations must pass the same
canonical operation, encryption-AAD, reference, and profile-ID vectors.

The first web client may use loopback projection routes. iOS synchronization
continues to use the signed operation log and content resources; it does not
depend on server projections being a replication format.

## Migration boundary

The v2 Exeligmos migration agent receives a dedicated capability grant and
creates newly signed Fractonica entities. Exeligmos UUIDs, short public IDs,
server revisions, device IDs, and source timestamps are retained as bounded
provenance, never reused as Fractonica operation identities or authority.

Migration cannot begin until tag/event/profile mappings and private key custody
are implemented and the destination can rebuild projections from an empty
database. Exeligmos remains read-only source material until count and content
hash verification succeeds.

## Consequences

- The new clients have a typed vocabulary without importing centralized
  account semantics.
- References remain descriptive graph data and cannot bypass capabilities.
- Public analytics are indexable; private analytics require local decryption.
- Adding the schemas requires a SQLite schema migration because the current
  `operations.schema_id` constraint is closed.
- Global handle uniqueness, public discovery, following, realtime publication,
  and encrypted LAN replication remain later protocols.
