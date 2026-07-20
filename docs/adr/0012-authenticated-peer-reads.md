# ADR 0012: Authenticated peer reads and replay protection

- Status: Accepted; first loopback transport slice in implementation
- Date: 2026-07-19
- Scope: Authentication and authorization of bounded operation-page reads.
  Listener exposure, discovery, content transfer, writes, and continuous
  replication remain disabled.

## Context

Pairing v1 proves possession of a joining `NodeId` and `ActorId`, then admits a
controller-signed capability grant for that actor. The existing operation read
routes are local control-plane routes: a desktop bootstrap bearer may protect
them, but they do not prove a peer identity or evaluate `readSpace`.

A peer transport must not turn the capability operation ID into a bearer
credential. It must prove current possession of both paired private keys,
bind authorization to the exact request, reject replay after restart, and
re-evaluate the complete grant chain and revocation state at the receiving
node's clock.

This first slice remains loopback-only. Signed HTTP messages authenticate and
authorize the caller but do not encrypt response bodies or hide traffic
metadata. They are therefore insufficient by themselves for LAN or Internet
exposure.

## Decision

The first peer operation is a bounded page read:

```text
POST /api/peer/spaces/{spaceId}/changes
```

Its JSON body is a strict projection of one `PeerReadChangesProofV1`. The
unsigned deterministic-CBOR request contains exactly:

- protocol version and request kind;
- the completed pairing invitation/session ID;
- `SpaceId`, paired `NodeId`, paired `ActorId`, and exact grant operation ID;
- node-local `after` cursor and bounded page `limit`;
- issued-at and expires-at Unix milliseconds; and
- a random 128-bit request nonce.

The node and actor sign the same canonical bytes with separate closed detached
signature domains. The receiving node rejects unknown fields, noncanonical
identifiers, invalid keys, wrong signatures, path/space disagreement, and
request lifetimes longer than 30 seconds. A request may arrive at most five
seconds before its claimed issue time and must be unexpired according to the
receiving node clock.

The two signatures have different roles:

- the `NodeId` signature proves this is the transport endpoint paired in the
  completed ceremony; and
- the `ActorId` signature proves current possession of the subject key named by
  the capability grant.

Neither identity alone is sufficient.

## Transaction boundary

SQLite performs the following in one immediate transaction:

1. resolve the completed pairing row by invitation ID;
2. require exact equality of its space, joining node, subject actor, and issued
   grant operation ID with the signed request;
3. verify the proof again at the repository boundary;
4. evaluate the exact grant and complete issuer chain for `readSpace`, including
   windows and all admitted revocations, at the local receive time;
5. insert the pairing-scoped request nonce into a durable replay table; and
6. read the requested operation page before committing.

The nonce insertion and read are not separable. A duplicate nonce rolls back
without returning data. The replay table stores no signature or private
material, is bounded per pairing, and deletes expired entries in bounded
batches. Restart does not reopen the replay window.

Authorization references remain conjunctive. This v1 request names exactly one
pairing-issued grant, but the evaluator recursively checks all of that grant's
issuer references. Revoking the grant or any delegated ancestor immediately
stops later peer reads.

## Bounds

- encoded JSON request: 16 KiB maximum;
- canonical proof: 4 KiB maximum;
- request lifetime: 1 through 30 seconds;
- tolerated future issue skew: 5 seconds;
- nonce: exactly 16 random bytes;
- page limit: 1 through the existing 200-operation maximum; and
- active replay entries: at most 4,096 per completed pairing.

## Error and privacy behavior

Malformed projections return a stable malformed-peer-request problem. Invalid
signatures, unknown or mismatched pairings, replay, expired proof, revoked
authority, and missing `readSpace` all return the same peer-unauthorized
problem. This prevents the unauthenticated surface from becoming a pairing,
actor, grant, revocation, or space oracle.

Logs may contain the stable problem code and redacted request route. They must
not contain signatures, canonical proof bytes, nonces, or private record data.

## Consequences

- A capability digest is never accepted as a bearer credential.
- Request replay remains rejected across process restart.
- The local control-plane bearer and peer proof are separate authentication
  mechanisms with separate routes.
- A node can later place this same authenticated message inside TLS, Noise, or
  another confidentiality-preserving transport without changing graph
  authority semantics.
- This ADR does not enable a non-loopback listener. That requires encrypted
  transport, discovery/endpoint policy, interoperability fixtures, abuse
  controls, and a separate exposure review.
