# Fractonica operation schema mappings

This document is normative for data-model protocol version 2. Each schema body
is one deterministic RFC 8949 CBOR value embedded at operation-payload index
10. Array positions and integer codes are protocol data, not implementation
details. An unknown code, missing field, extra field, non-canonical value, or
schema/body mismatch is rejected.

JSON is only a checked projection. A receiver verifies COSE, decodes the CBOR
body, and proves that every projected JSON field matches the signed bytes
before admitting an operation.

## Shared encodings

- `null` is CBOR null.
- Optional values are either their specified value or null; fields are never
  omitted from a CBOR array.
- Times are nonnegative Unix milliseconds encoded as unsigned integers.
- Actor IDs are their exact 32 Ed25519 public-key bytes.
- Operation and content IDs are their exact 32 digest bytes.
- Sets are arrays unique and strictly ascending in their stated order. Their
  order is canonical, not semantic.
- Text is valid UTF-8 and remains subject to the bounds in the Rust data model.

Metadata maps JSON values as follows: null, boolean, text, arrays, and maps map
directly; negative integers use a CBOR negative integer, nonnegative integers
use an unsigned integer, and non-integral finite JSON numbers use the shortest
deterministic CBOR float. Map keys are text and are ordered by their encoded
key bytes. Byte strings, non-text map keys, duplicate keys, NaN, and infinity
are not metadata values.

## `record.v1`

A tombstone is:

```text
[0]
```

The initial put fixes visibility for that entity history. Admission rejects a
later put with a different visibility, and authorizes tombstones against the
visibility inherited from the admitted origin put. Visibility changes require
a new entity plus an explicit future relationship rule; they are not an update
of `record.v1`.

A complete record put is:

```text
[
  1,
  startAtUnixMs,
  endAtUnixMs | null,
  visibility,
  emoji | null,
  text | null,
  metadata,
  resources
]
```

Visibility codes are `0 = public`, `1 = private`. Resource order is semantic.
Each resource is:

```text
[contentDigest32, byteLength, mediaType, role, originalName | null]
```

The record validator retains the temporal, text, metadata, resource-count,
resource-contract, and duplicate-content-ID bounds defined in the crate.

## `space.genesis.v1`

```text
[2, controllerActorPublicKey32]
```

The controller must equal the operation signer. Genesis has no causal parents
and no authorization references. Whether a node explicitly trusts this exact
genesis is an admission-policy decision above the pure data model.

## `capability.grant.v1`

```text
[
  3,
  subjectActorPublicKey32,
  actions,
  schemas,
  recordVisibilities,
  contentRoles,
  maxResourceByteLength | null,
  notBeforeUnixMs | null,
  expiresAtUnixMs | null,
  delegationDepth,
  label
]
```

Action codes, in canonical order, are:

| Code | JSON projection |
| ---: | --- |
| 0 | `appendOperation` |
| 1 | `issueCapability` |
| 2 | `revokeCapability` |
| 3 | `readSpace` |
| 4 | `writeContent` |

Actions are nonempty and strictly ordered by code. Schemas are exact known
schema names sorted by UTF-8 bytes. Record visibilities use the record codes
above. Content roles use the lowercase `ResourceRef` role grammar and are
sorted lexically.

`appendOperation` requires a nonempty schema set, and a schema set is invalid
without that action. A `record.v1` scope requires at least one allowed record
visibility. `writeContent` requires nonempty content roles and an explicit
maximum resource byte length; those constraints are invalid without that
action. The maximum cannot exceed the content contract's 1 TiB bound.

The optional admission window is locally evaluated and expiration must be
strictly after not-before. Delegation depth is at most 16. The descriptive
label contains 1 through 128 non-control Unicode scalar values and has no
authorization meaning.

## `capability.revoke.v1`

```text
[4, grantOperationDigest32, reason, detail | null]
```

Reason codes are:

| Code | JSON projection |
| ---: | --- |
| 0 | `keyCompromised` |
| 1 | `deviceLost` |
| 2 | `keyRotated` |
| 3 | `scopeChanged` |
| 4 | `administrative` |

Optional detail contains 1 through 512 non-control Unicode scalar values and
has no policy meaning. The pure data model proves the signed shape; capability
chain, issuer-scope intersection, and accepted-revocation evaluation belong to
the application admission layer.

## JSON signed-envelope projection

The strict camel-case JSON object contains `protocolVersion`, `operationId`,
`spaceId`, `actorId`, `entityId`, `schema`, sorted `causalParents`, sorted
`authorization`, `occurredAtUnixMs`, `nonce`, typed `body`, and `coseSign1`.
The nonce is exactly 32 lowercase hexadecimal digits. COSE is canonical
base64url without padding. Unknown JSON fields, protocol version 1, projection
drift, malformed or non-canonical COSE, invalid signatures, and unsupported
schema bodies are rejected.
