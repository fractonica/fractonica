# Signed, space-scoped HTTP API

The canonical HTTP contract for signed operations is
[`contracts/openapi/api.yaml`](../contracts/openapi/api.yaml). It is a JSON
projection of the deterministic CBOR and COSE representation fixed by
[ADR 0009](adr/0009-signed-operation-trust-kernel.md); JSON bytes are never
signed.

## Admission

Clients retain their private keys. Fractonica deliberately exposes no generic
signing endpoint. A client submits a complete projection to:

```http
POST /api/spaces/{spaceId}/operations
Content-Type: application/json
```

The object contains `protocolVersion`, `operationId`, `spaceId`, `actorId`,
`entityId`, `schema`, sorted `causalParents`, sorted `authorization`,
`occurredAtUnixMs`, a 16-byte hexadecimal `nonce`, the schema-defined `body`,
and an unpadded-base64url `coseSign1` envelope. The COSE object embeds the exact
deterministic unsigned payload.

Admission performs these checks before changing durable projections:

1. Decode one bounded tagged COSE Sign1 object and reject alternative or
   noncanonical encodings.
2. Compare every JSON projection field with the embedded payload.
3. Require the signed and path space IDs to match.
4. Recompute `operationId` from the embedded unsigned payload.
5. Verify Ed25519 using the public key contained in `actorId`.
6. Require parents and grants to be in the same space.
7. Evaluate the complete capability chain and schema invariants.

Authorization references are conjunctive. Every named top-level grant and
every issuer-chain reference must permit the requested action after scope
intersection; adding a reference cannot combine disjoint permissions or widen
authority. Capability windows use the node's durable, nondecreasing admission
clock. The node commits the maximum of its previous high-water value and the
current receiver sample before authorization, including when authorization
later denies the request.

The operation digest is its idempotency key. First admission returns `201`.
Replaying the exact digest returns `200` with the original node-local sequence.
There is no `Idempotency-Key` header.

`space.genesis` is readable through this surface but is not POST-admissible.
Only the crash-safe local installation bootstrap may establish a genesis trust
anchor; future peer admission requires the separately specified pairing
ceremony.

## Reads and cursors

All stateful graph reads select one space explicitly:

```text
GET /api/spaces/{spaceId}/operations/{operationId}
GET /api/spaces/{spaceId}/entities/{entityId}
GET /api/spaces/{spaceId}/changes?after=0&limit=100
```

`localSequence` and the `after` cursor are assigned by one node and excluded
from signed data. They are useful for incremental synchronization only and are
not portable ordering or causality primitives. The HTTP projection is bounded
to the nonnegative signed 64-bit range used by SQLite; larger or negative
cursor input is rejected with `422 invalid_identifier`.

The OpenAPI document served by the node reflects its transport configuration:
it declares bearer-only security when `--bootstrap-token` is configured and
anonymous loopback access otherwise. This transport gate is independent of
operation signatures and capability authorization.

These GET routes are a loopback control-plane surface gated only by the node's
optional transport bearer. Paired actors use the separate proof-carrying route:

```text
POST /api/peer/spaces/{spaceId}/changes
```

Its strict body is signed by both the paired node and actor and binds the exact
session, space, pairing-issued grant, cursor, limit, time window, and nonce.
The node re-evaluates `readSpace` and consumes the durable nonce in the same
transaction as the page read. See [ADR 0012](adr/0012-authenticated-peer-reads.md).
This authenticates the request but does not encrypt it; non-loopback exposure
remains prohibited.

## Content boundary

Content-transfer mechanics are part of the composed node contract. Before
they move under `/api/spaces/{spaceId}`, the implementation must enforce
space capabilities for upload creation, resume, availability, reads, and
metadata inspection. Physical deduplication must never allow one space to test
another space's blob presence or retrieve its bytes.

## Stable errors

Errors use `application/problem+json` with a machine-readable `code`. Important
admission codes include:

- `malformed_signed_operation`, `noncanonical_operation`, and
  `signed_projection_mismatch` for representation failures;
- `operation_id_mismatch`, `invalid_signature`, and `actor_id_mismatch` for
  cryptographic failures;
- `authorization_required`, `authorization_missing`,
  `authorization_denied`, and `authorization_revoked` for capability failure;
- `space_not_found`, `space_id_mismatch`, and `cross_space_reference` for
  namespace failure.

The complete closed code set and HTTP status mapping live in the OpenAPI
contract. Error details are bounded and must not echo signed payloads, private
keys, invitation secrets, or transport credentials.

## Surfaces outside spaces

Saros and glyph calculations remain stateless and do not acquire a fake space
scope. Pairing uses the separately bounded Noise and
confirmation ceremony documented by ADR 0011; peer proof reads use ADR 0012.
