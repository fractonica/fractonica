# ADR 0010: Space capabilities and QR pairing boundary

- Status: Accepted
- Date: 2026-07-18
- Implementation: Local trusted-space bootstrap, grant-chain evaluation, and
  revocation admission are implemented for signed v2 operations. The QR
  handshake, non-loopback transport, caller-authenticated `readSpace`, and
  space-authorized content transfer remain disabled.

## Context

An Ed25519 signature proves which actor key produced an operation, but key
possession alone must not allow an actor to change every user's data. Fractonica
also needs to add a phone, desktop, sensor, or automation agent without copying
another device's private key or depending on a central login service.

Authorization must be inspectable offline, scoped to a space, and compatible
with the causal operation graph. Pairing must make the human decision explicit
without treating LAN discovery, a QR image, or transport encryption as durable
authority.

## Decision

Each space has an explicit genesis trust anchor and grants authority to actor
keys through immutable signed capability operations. QR pairing is only the
short-lived ceremony used to authenticate a new node and request such a grant.
It never transfers an existing actor or node private key.

### Space bootstrap

A new space is assigned 32 cryptographically random bytes and encoded as
`space:<64 lowercase hex>`. Its first operation uses schema
`space.genesis.v1`, has no causal parents or authorization references, and is
signed by the initial controller actor named by its body. This is the only
self-authorized operation form.

A node may trust a genesis operation only when it created the space locally or
when a user explicitly confirms that exact genesis digest during a future
authenticated pairing ceremony. Receiving a genesis operation from an import,
feed, discovered endpoint, or untrusted peer MUST NOT make it trusted. Once a
node anchors one genesis digest for a `SpaceId`, a different genesis for the
same ID is a fatal trust conflict, not a concurrent branch.

The genesis operation grants its controller only the root actions needed to
issue and revoke capabilities and to maintain the capability schemas. It does
not turn the controller into an implicit signer for other actors.

### Capability grants

`capability.grant.v1` is an immutable operation in the space it authorizes. Its
body names:

- one subject `ActorId`;
- a nonempty set of enumerated actions;
- an explicit set of schemas for operation-append authority;
- visibility, content-role, byte, rate, or other bounds required by the
  granted actions;
- an optional local-admission `notBeforeUnixMs` and `expiresAtUnixMs`;
- a nonnegative delegation depth; and
- a human-readable label that is descriptive only and never used for policy.

Version 1 grants use enumerated actions and exact schema names; receivers MUST
reject unknown actions and MUST NOT interpret wildcards or name prefixes.
Omitted scope means no authority for that dimension, not unlimited authority.
An issuer may delegate only actions and limits it possesses, and a delegated
grant must be no broader than the intersection of its complete issuer chain.
Delegation depth decreases at every grant and cannot be reset by another actor.
The locally anchored genesis controller is the one special root: it may issue
any bounded v1 grant and revoke grants, but it has no ambient application-data
write authority.

Every non-genesis signed operation carries a canonical, sorted
`authorization` list of the grant-operation digests on which it relies. Before
admission, a node MUST verify that:

1. every referenced grant and its issuer chain is present, signature-valid,
   and in the same `SpaceId`;
2. the terminal subject equals the operation `ActorId`;
3. the effective intersection permits the requested action, schema,
   visibility, resource limits, and delegation;
4. no required grant is revoked in the node's accepted capability state; and
5. any local admission window is satisfied by the receiving node's trusted
   clock.

All top-level authorization references and all issuer-chain references are
conjunctive. Receivers intersect their effective restrictions and require each
referenced authority to permit the requested operation; references are never
unioned. Adding a reference therefore cannot broaden authority. Grant and
parent digest order is canonical rather than semantic. A syntactically valid
operation with missing grants may be quarantined, but it MUST NOT update heads,
indexes, or content authority. Capability operations themselves require an
authorization chain that includes `capability.issue`, except for the single
genesis bootstrap rule.

A capability is bound to its subject public key and is not a bearer token.
Login sessions, local HTTP bearer tokens, and API keys are transport
credentials that select or invoke an actor; they do not replace the signed
grant chain and MUST NOT be replicated as authority.

### Revocation and time

`capability.revoke.v1` is a signed, authorized operation naming one exact grant
operation digest and a machine-readable reason. It never edits or deletes the
grant. After a node accepts a revocation, it rejects later local admissions
that rely on that grant. Previously admitted operations and their signatures
remain valid and their IDs do not change.

Claimed operation time is controlled by the signer. It cannot prove that an
offline operation was created before expiration or revocation. In this
loopback-only phase, grant windows are local admission policy and revocation is
prospective from the accepting node's state. The future replication protocol
must define deterministic handling for an operation concurrent with a
revocation before multi-node capability convergence is claimed.

The implementation evaluates windows against a durable, nondecreasing
node-admission clock. Before capability evaluation it commits
`max(previousHighWater, sampledUnixMs)`, including for a request that is later
denied, then checks `notBeforeUnixMs` inclusively and `expiresAtUnixMs`
exclusively. This prevents a local wall-clock rollback from reopening a window
after the node has observed a later time. It does not create a global clock or
settle distributed revocation races.

### Pairing invitation

A future `pairing.v1` QR invitation will carry a bounded deterministic object
containing at least:

- protocol and invitation versions;
- a random invitation ID and at least 256 bits of one-time secret material;
- the responder `NodeId` and public key needed to verify it;
- the exact `SpaceId` and trusted genesis digest, when joining a space;
- an expiration instant and endpoint hints; and
- a human-readable summary of the requested capability template.

The responder stores only a protected verifier for the one-time secret where
the selected handshake permits it. Invitations are short-lived, single-use,
redacted from logs and crash reports, and consumed transactionally. The QR
payload MUST NOT contain a node private key, actor private key, space
encryption key, reusable API token, or an already-issued capability.

Scanning the QR does not itself grant authority. A complete pairing ceremony
must:

1. authenticate an ephemeral session and the responder key pinned by the QR;
2. bind both node identities, the invitation, negotiated version, requested
   scope, and complete handshake transcript;
3. show the peer fingerprint and effective capability summary for explicit
   user confirmation;
4. consume the invitation before committing the peer relationship;
5. generate new node and actor keys locally on the joining device; and
6. issue a separate controller-signed capability operation to the new
   `ActorId` only after confirmation.

Session keys, node keys, actor keys, and future payload-encryption keys are
distinct. Failure, cancellation, expiration, or replay produces no partial
grant. A stolen invitation may enable interception or denial of service until
it expires, so the final protocol must include a human-verifiable confirmation
step rather than relying on possession of the QR alone.

### Handshake and network gate

This ADR fixes the trust boundary, not the authenticated key-exchange wire
algorithm or HTTP endpoints. Before pairing is implemented, a follow-up ADR
must select the handshake, define transcript inputs and downgrade behavior,
bound every message, publish deterministic success/failure fixtures, and test
replay, relay, cancellation, and simultaneous use.

Until that work is accepted, the node MUST continue rejecting non-loopback
bind addresses. No LAN discovery, pairing endpoint, peer listener, reverse
proxy, or replication transport is authorized by this decision.

## Key lifecycle

Private keys are generated on the device that uses them and are not copied by
pairing. Rotation creates a new `ActorId` or `NodeId`: actor continuity is a
grant to the new actor followed by revocation of the old grant, while node
rotation requires re-pairing. Losing every controller key leaves existing
history verifiable but makes the space administratively unrecoverable.

Spaces SHOULD provision an independently protected recovery controller before
network use. Fractonica provides no vendor recovery key, implicit local-admin
override, or password reset that can forge a controller. A future encrypted
recovery-export format requires its own ADR and must never be confused with a
pairing invitation.

## Consequences

- A person, phone, automation agent, and embedded sensor can hold independent
  keys while sharing one space under explicit scopes.
- Authorization history is signed, append-only, and auditable with the same
  Merkle operation machinery as application data.
- Compromise can be contained by revoking a grant without invalidating past
  signatures or rewriting history.
- Space bootstrap and peer trust require an explicit local or human-confirmed
  anchor; network discovery is never enough.
- Distributed revocation races, the pairing handshake, replication, and
  private-payload key distribution remain explicit future protocol work.
