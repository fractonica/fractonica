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

`record.v1` is retained only as an already-published conformance fixture. New
clients write `record.v2`.

## Protected client documents

`record.v2`, `tag.v1`, and `event.v1` wrap their application document in:

```text
[visibility, documentOrEnvelope, outerResources]
```

For `public`, visibility is `0`, `documentOrEnvelope` is the schema document,
and `outerResources` is empty. For `private`, visibility is `1`, the second
field is the encrypted envelope below, and the outer resource array contains
only opaque encrypted descriptors:

```text
[0, keyId, nonceBase64url, ciphertextBase64url]
```

Encryption algorithm code `0` is `aes-256-gcm`. The nonce is exactly 12 bytes
and the ciphertext includes the 16-byte authentication tag. Key identifiers
use `key:aes256:` followed by 64 lowercase hexadecimal digits. Private resource
descriptors use media type `application/octet-stream`, role `encrypted`, and a
null original name.

## Typed references

A reference is `[relation, target]`. Actor targets are
`[0, actorPublicKey32]`. Entity targets are
`[1, spaceId32, entityUuid16, operationDigest32 | null]`. Reference order is
semantic; exact duplicates are invalid. References describe relationships and
never grant authority.

## `record.v2`

```text
[
  5,
  protected([
    startAtUnixMs,
    endAtUnixMs | null,
    emoji | null,
    text | null,
    metadata,
    resources,
    references
  ])
]
```

## `tag.v1`

```text
[6, protected([name, emoji | null, notes | null, colorHex | null, metadata, references])]
```

## `event.v1`

```text
[7, protected([startAtUnixMs, endAtUnixMs | null, label, typeNumber, metadata, references])]
```

Event type numbers are signed integers. Events cannot carry resources.

## `profile.v1`

```text
[8, [handle, displayName, sarosAnchor, avatarResource | null, metadata]]
```

Profiles are public. Their entity UUID is deterministically derived from the
actor public key under the `fractonica-profile-entity-v1` domain and uses the
UUID version-8/variant-1 bit layout. Saros anchors are bounded to 101 through
161.

All five mutable client schemas use `[0]` as their tombstone body.

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
  visibilities,
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
schema names sorted by UTF-8 bytes. Visibilities use the codes above. Content
roles use the lowercase `ResourceRef` role grammar and are
sorted lexically.

`appendOperation` requires a nonempty schema set, and a schema set is invalid
without that action. Every client schema requires a nonempty visibility scope;
`profile.v1` operations additionally require public visibility. `writeContent`
requires nonempty content roles and an explicit
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
