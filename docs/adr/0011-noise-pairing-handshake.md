# ADR 0011: Noise pairing handshake

- Status: Accepted; cryptographic wire and durable lifecycle implemented
- Date: 2026-07-18
- Scope: Pairing protocol and local state machine only. Non-loopback binding,
  discovery, replication, and payload-key distribution remain disabled.

The Rust pairing crate now implements the canonical invitation, dual-signed
claim, fixed Noise exchange, transcript receipt, and confirmation projection.
The SQLite pairing schema stores only non-secret lifecycle indexes. Short-lived
secret material is written atomically to a separate private vault and startup
reconciliation expires sessions, removes orphan secrets, and fails closed when
an active row has lost its secret. Loopback HTTP routes now expose bearer-gated
invitation administration plus cryptographically authenticated Noise claim and
acceptance exchanges. A successful claim durably prepares and signs exactly
one inert capability grant. The joining node must then sign an acceptance with
both its node and actor keys after the user compares the complete visual code.
Only that proof admits the prepared operation and completes the session. The
local control center renders the scannable app-opening QR and both clients
render the same two-glyph confirmation ceremony.

## Context

ADR 0010 fixes the pairing trust boundary but deliberately does not choose a
key-exchange algorithm. Fractonica needs one protocol that can be implemented
by desktop, mobile, headless, and embedded nodes without inventing a custom
Diffie-Hellman or AEAD construction.

The QR code is observable bearer material. Possessing it may start one pairing
attempt, but must not silently grant graph authority. Node identity,
application actor identity, capability issuance, and the encrypted transport
session remain separate cryptographic roles.

## Decision

Pairing v1 uses exactly:

```text
Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s
```

The responder creates an invitation-specific X25519 static key and a random
32-byte one-time secret. The Noise static key is not the responder's long-term
`NodeId`; the QR descriptor binds it to that node with an Ed25519 signature.
The initiator knows the invitation static public key and uses the one-time
secret at PSK position zero. The SHA-256 invitation-descriptor digest is the
Noise prologue. No pattern, primitive, version, or PSK-position negotiation is
performed. An unknown value is a hard failure rather than a downgrade.

This selection follows the Noise framework's `NK` semantics: the initiator has
advance knowledge of the responder static key, while the initiator is
authenticated at the application layer. `psk0` additionally authenticates QR
secret possession and encrypts the first handshake payload. The implementation
uses standard Noise message framing and retains the 65,535-byte Noise maximum,
with substantially smaller Fractonica bounds below.

The initial Rust adapter uses `snow` 0.10 with the standard 25519,
ChaChaPoly, and BLAKE2s primitives. `snow` states that it has not received a
formal audit. It is therefore an adapter behind Fractonica-owned deterministic
wire fixtures, not an unchangeable trust primitive. Before non-loopback release
we must complete interoperability testing with a second implementation and a
focused cryptographic review.

## Canonical invitation

The canonical invitation text is:

```text
fractonica-pairing:v1:<unpadded-base64url canonical-CBOR envelope>
```

The desktop QR encodes that invitation as the percent-encoded value of the
custom app link:

```text
fractonica://pair?invitation=<canonical invitation text>
```

The app link is only a navigation envelope. The invitation remains the exact
canonical value above and the mobile client rejects any malformed payload
before network access.

The closed envelope contains:

- the closed signed descriptor;
- its 64-byte responder-node Ed25519 signature; and
- the 32-byte one-time secret.

The signed descriptor contains exactly:

- pairing protocol version `1` and invitation version `1`;
- a random 16-byte invitation ID;
- the exact Noise protocol name;
- responder `NodeId`;
- invitation-specific 32-byte X25519 public key;
- exact `SpaceId` and trusted genesis `OperationId`;
- absolute expiration in nonnegative Unix milliseconds;
- zero through three bounded endpoint hints;
- a canonical requested-capability template; and
- SHA-256 of the one-time secret.

The descriptor, envelope, capability template, claims, and receipts use the
same deterministic RFC 8949 CBOR vocabulary as signed operations. Unknown,
duplicate, missing, noncanonical, or oversized fields are rejected before
cryptography. QR decoding is capped at 4 KiB. Invitation lifetime is at most
ten minutes. Endpoint hints are discovery hints only and convey no trust.

The QR secret, invitation X25519 private key, session keys, and transport
cipher state are always redacted from debug output. They must never be placed
in URLs, logs, SQLite, crash reports, analytics, or the signed graph.

## Initiator claim and proof of possession

The initiator generates new node-transport and application-actor Ed25519 keys
locally. Its first encrypted Noise payload is a canonical claim containing:

- version `1`, invitation ID, and descriptor digest;
- responder `NodeId`, `SpaceId`, and genesis digest;
- joining `NodeId` and requested subject `ActorId`;
- a random 32-byte claim nonce; and
- detached signatures by both joining keys over the same unsigned claim.

The two signatures prove possession of the joining node and actor keys. They
do not grant authority. The responder rejects a claim whose invitation fields,
requested scope, identities, signatures, or canonical bytes disagree.

After the two-message Noise handshake completes, both sides use Noise's
handshake hash as the channel binding. The responder's first encrypted
transport message contains a receipt binding the invitation digest, claim
digest, handshake hash, and both node identities. The receipt is also signed
by the responder `NodeId`, which independently pins the invitation Noise key
to the long-term node identity.

Both user interfaces derive a 30-bit confirmation value from:

```text
SHA-256("org.fractonica.pairing.confirmation.v1" || handshakeHash)
```

and display it as two five-digit MSB-first octal glyphs plus a two-row grid of
the ten octal digits. Confirmation compares the complete ten-digit value; it
is a human relay/interception check, not a replacement for Noise or
signatures.

After the human comparison, the joining client creates a canonical acceptance
that binds the invitation ID, exact claim digest, Noise handshake hash,
responder and joining node IDs, requested actor, space, immutable prepared
grant operation ID, and a fresh nonce. Both the joining node key and actor key
sign those exact fields under the `pairing-acceptance-v1` detached-signature
domain. The responder verifies both signatures and every session binding
before admitting the grant. Replaying the exact valid acceptance is
idempotent; a changed or unrelated acceptance fails closed.

## State machine

Responder state is strictly monotonic:

```text
created -> claimed -> confirmed -> completed
                 \-> cancelled
created ----------------> expired
```

- Creation durably stores the invitation ID, descriptor digest, expiry,
  requested template, X25519 private key, and secret in a protected secret
  backend. SQLite may store only non-secret indexes and lifecycle state.
- A valid first handshake message atomically changes `created` to `claimed`.
  Exactly one concurrent caller can win. The invitation cannot return to
  `created`, even if the process crashes or the user cancels.
- The claimed row also stores the first-frame digest and the exact opaque Noise
  response and receipt frames. An identical first frame may replay those bytes
  while the claimed session is live. This recovers a response lost when an OS
  local-network permission prompt interrupts the HTTP request without opening
  the invitation to a second claim or persisting plaintext secrets.
- The controller deterministically prepares and signs the candidate
  `capability.grant` while recording that claim, and returns its immutable
  operation ID to the joiner. The operation is not admitted and conveys no
  authority in the `claimed` state; this only lets the joiner prepare its
  first bounded authenticated read before confirmation.
- Invalid, expired, cancelled, or already-used invitations yield the same
  bounded public rejection and reveal no peer or space state.
- The joining app automatically claims a valid deep-linked invitation, shows
  the complete ten-octal-digit code, and requires an explicit Pair action.
- Pair creates the dual-signed acceptance. Only after the responder verifies
  it may the controller admit the already prepared `capability.grant`
  operation for the joining `ActorId`.
- Completion persists the paired `NodeId`, actor, space, grant digest, and
  transcript digest. It never persists Noise transport keys as graph
  authority.
- Failure before confirmation creates no capability. Failure after a grant is
  admitted is recovered by the durable grant/session binding rather than by
  issuing a second grant.

Invitation creation, cancellation, and inspection are local administrative
operations protected by the node bootstrap bearer until a stronger local UI
session exists. The claim and acceptance endpoints authenticate themselves
with the pairing protocol and must not require that bearer. The older local
administrative confirmation route remains available for diagnostics but is
not the user-facing completion path.

## Bounds and failure behavior

- QR envelope: 4 KiB encoded bytes maximum.
- Canonical claim or receipt: 4 KiB maximum.
- Noise handshake or transport frame: 8 KiB maximum at the HTTP boundary.
- Endpoint hints: at most three, each at most 256 ASCII bytes.
- Capability label: existing data-model bound.
- Invitation lifetime: one second through ten minutes.
- Claimed but unfinished session lifetime: two minutes.
- One invitation permits one distinct claim that passes cryptographic
  validation. An identical first frame receives the exact cached response;
  altered replay and simultaneous different use are rejected transactionally.
- Error bodies, metrics, and traces contain only stable codes and redacted
  invitation IDs. They never contain QR payloads, secrets, private keys,
  plaintext claims, handshake frames, or transcript hashes.

## Network gate

This ADR does not enable a public listener. The desktop may opt into an
authenticated unspecified-address listener solely to advertise a
private/link-local pairing endpoint. The control URL remains loopback. The
Noise receipt carries a random pairing-scoped transport credential, of which
the node stores only a digest; each operation/content request re-evaluates the
completed pairing grant. Public binding remains rejected. A confidential
persistent peer transport still requires:

1. durable single-use invitation and session recovery;
2. confirmation UI accessibility and shoulder-surfing review;
3. revocation recovery for paired-device grants;
4. caller-authenticated `readSpace` and content transfer;
5. replay, relay, downgrade, cancellation, expiry, restart, and concurrent-use
   tests;
6. second-implementation Noise interoperability fixtures; and
7. a reviewed LAN exposure and discovery threat model.

The current plain-HTTP data plane is therefore a trusted-private-network test
milestone. A passive observer on that network can observe payloads and the
pairing-scoped authorization header; it must not be used on public or untrusted
networks.

## Consequences

- QR possession and durable graph authority remain separate.
- The responder is pinned before the first network request; the joining node
  and actor prove their keys inside the encrypted handshake.
- A 30-bit Saros-glyph confirmation naturally reuses Fractonica's canonical
  two-glyph renderer.
- Embedded devices can implement a fixed standard Noise pattern plus bounded
  canonical messages without carrying the complete node database.
- Replication can later reuse the paired node identity and transcript binding,
  but transport resumption, rekeying, and synchronization remain separate
  protocol decisions.
