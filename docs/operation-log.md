# Signed causal operation log

Fractonica's authoritative storage kernel is an append-only Merkle operation
graph. An operation has deterministic unsigned bytes, a SHA-256 identity, an
Ed25519 author signature, direct parent digests, and an explicit space
authorization chain. Mutable entity heads, search indexes, summaries, and
other query structures are projections of accepted operations.

This document describes the implemented operation protocol version 2. The
cryptographic contract is fixed by
[ADR 0009](adr/0009-signed-operation-trust-kernel.md), while space admission is
fixed by [ADR 0010](adr/0010-space-capabilities-and-pairing.md). The full node
enforces capability admission for signed operation writes. Pairing,
actor-authenticated remote reads, and non-loopback networking are not enabled;
the obsolete unsigned version 1 operation routes are rejected rather than
treated as authority.

## Operation envelope

The authoritative wire value is deterministic CBOR inside an exact COSE Sign1
Ed25519 envelope. JSON is a human/API projection and is never signed. The
unsigned payload commits to:

- the domain `org.fractonica.operation.v2` and protocol version `2`;
- a random 256-bit `SpaceId`;
- the author's Ed25519-public-key `ActorId`;
- the affected entity UUID and versioned schema;
- zero through 64 direct causal-parent operation digests;
- zero through 64 capability-operation digests used for authorization;
- a nonnegative actor-claimed Unix-millisecond occurrence time;
- a 16-byte uniqueness nonce; and
- the complete schema-defined deterministic-CBOR body.

Parent and authorization digest arrays are encoded unique and strictly
ascending by raw digest. That order is canonical, not temporal or semantic.
The operation ID is `sha-256:<lowercase hex digest>` of the exact unsigned
payload bytes; the signature is not part of the ID.

An operation is admitted only after its deterministic encoding, derived ID,
actor signature, schema body, parent graph, and capability chain all validate.
A valid signature proves authorship but does not grant permission. An
unavailable resource blob does not invalidate an otherwise admissible
operation.

`occurredAtUnixMs` is a signed claim, not a trusted clock. It determines
application time where the schema permits, but never causal ordering,
revocation order, or operation priority.

## Actors, installations, and spaces

`ActorId` contains the exact Ed25519 public key that verifies the operation.
Actors may represent user-controlled devices, automation agents, sensors, or a
node performing an explicitly granted system action. A node transport key has
a distinct `NodeId`; it does not silently authorize operations.

`InstallationId` identifies one local database lifecycle. It is not included in
the signed payload and has no authorship or authorization meaning. `SpaceId`
scopes an operation and its capabilities; knowing a space ID is not authority.

## Idempotent admission

Submitting the same signed COSE bytes more than once is idempotent because the
derived `OperationId` is unchanged. A receiver that already stores that exact
ID and payload returns the stored operation rather than adding another graph
node. The same ID paired with different payload bytes is a digest-integrity
failure, not an update.

HTTP idempotency keys, request IDs, upload IDs, receipt times, and retry counts
remain local transport or storage metadata. They are neither signed operation
fields nor replication identities. A new nonce creates a genuinely different
operation even when the remaining logical fields are equal.

## Causal heads and merging

Every named causal parent must already be available for admission, belong to
the same space, entity, and schema history permitted by that schema, and differ
from the new operation. Missing ancestors cause rejection or bounded
quarantine; a node never invents a parent.

When an operation is accepted, its direct parents stop being entity heads and
the new operation becomes a head. Existing heads not named by the operation
remain current. Consequently:

- an edit naming the current head advances one branch;
- offline edits naming the same earlier head remain concurrent;
- a merge naming every observed current head collapses those branches; and
- a tombstone is a durable signed head that can conflict with another branch.

Arrival order, claimed occurrence time, actor identity, signature bytes, and
digest lexical order do not pick a winner. An application resolves a conflict
by authoring a new operation whose causal parents name every head it has
considered.

A parent digest proves the exact operation the signer named. It does not prove
the signer knew every branch or that a peer has disclosed the complete graph.

## Capability admission

Except for the explicitly trusted `space.genesis.v1` bootstrap, every operation
names the immutable capability grants on which its actor relies. The receiver
verifies the complete issuer chain, subject, action, schema, restrictions,
delegation depth, and accepted revocations before applying the operation.

Authorization references are conjunctive, not alternatives whose permissions
are unioned. Every top-level reference must independently authorize the
requested operation, and every reference in each issuer chain must authorize
the delegated grant. The effective authority is therefore the intersection of
all referenced restrictions: adding a reference can only preserve or narrow
authority, never broaden it.

Grant windows use the receiver's durable admission-clock high-water mark, not
`occurredAtUnixMs` and not a wall-clock sample in isolation. Before capability
evaluation, the node commits `max(previousHighWater, sampledUnixMs)` and uses
that value for inclusive `notBeforeUnixMs` and exclusive `expiresAtUnixMs`
checks. The high-water mark advances even when a structurally valid request is
later denied, so moving the system clock backwards cannot reopen a window the
node has already observed as closed. This is local admission policy, not proof
of global time or a distributed revocation order.

A cryptographically valid operation with missing or insufficient capability
state may be retained only as untrusted quarantine. It MUST NOT become a head,
alter a projection, authorize a content upload, or issue another grant.
Revocation is append-only and does not invalidate historical signatures. The
future replication protocol must specify operations concurrent with a
revocation before distributed authorization is enabled.

## Record bodies and resources

`record.v1` bodies remain complete document puts or tombstones. A record put
defines its temporal fields, visibility, optional emoji/text/metadata, and up
to 64 ordered immutable resource references. Resource bytes are addressed
separately by content digest; their local availability is not part of operation
validity. See [content-addressed storage](content-storage.md).

The first put fixes one record entity's visibility domain. Every later put must
retain that visibility, and a tombstone is authorized against the inherited
entity visibility even though its body carries no document. This prevents a
public-only writer from rewriting or erasing a private record by naming one of
its heads. Missing or contradictory materialized visibility is storage
corruption and fails closed.

Each application schema must define one bounded semantic-to-CBOR body mapping.
Serializing a JSON object, retaining map insertion order, or signing HTTP bytes
is not a canonical mapping.

## Node-local change cursor

A stateful node assigns each admitted operation a monotonically increasing
local sequence for incremental reads. The cursor orders that node's admission
events only. It is not signed, not replicated, and is not an operation ID,
causal clock, event time, capability order, or global sequence. A cursor from
one node has no meaning on another node. The HTTP cursor is a nonnegative
signed 64-bit integer, matching the SQLite sequence domain.

## Version 1 migration

Unsigned UUID-based version 1 operations are not valid version 2 operations.
Version 2 receivers reject them and do not provide dual interpretation. A
migration re-encodes logical documents into deterministic CBOR, assigns a
space and actor, maps UUID parent references to operation digests, and signs
the resulting operations. Legacy UUIDs may be retained as application
provenance, but a new signature does not prove the legacy author's identity.

This intentional pre-release break prevents installation UUID attribution and
unsigned causal identifiers from becoming a permanent compatibility burden.
