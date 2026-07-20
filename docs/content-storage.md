# Content-addressed storage

Fractonica records keep structured data in the causal operation log and refer
to large immutable byte resources by digest. Upload staging is mutable and
resumable; a committed blob is immutable and addressed only by the SHA-256 hash
of its complete bytes.

The HTTP contract is defined in
[`contracts/openapi/v1.yaml`](../contracts/openapi/v1.yaml). Upload behavior
follows the official [tus protocol 1.0.0](https://tus.io/protocols/resumable-upload),
and HTTP digest fields follow [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html).
All content routes require the stateful `node` profile. The stateless `saros`
profile returns `503` and creates no staging or blob directories.

These v1 routes are currently loopback content-transfer mechanics, not a
space-authorized remote API. They do not accept actor proof or evaluate
`readSpace`/`writeContent`; the optional node-wide bearer is transport gating
only. Before content moves under a v2 space path, upload, resume, availability,
metadata, and blob reads must enforce the applicable capability without leaking
cross-space blob presence through physical deduplication.

## Content identity and record references

A canonical content ID has exactly this form:

```text
sha-256:<64 lowercase hexadecimal characters>
```

The digest is calculated over the complete unencoded blob bytes. Filenames,
media types, upload metadata, record order, and the node that received the data
do not affect the ID. Equal bytes therefore converge on one immutable blob.

`record.v1` has an optional ordered `resources` array containing at most 64
`ResourceRef` objects. Each reference contains a canonical `contentId`,
`byteLength`, `mediaType`, and semantic `role`; it may also carry the display
label `originalName`. Array order is semantic and must be preserved.

An operation remains valid when one or more referenced blobs are absent from
the receiving node. Operation replication and causal validation must not depend
on local media availability. Clients can query up to 256 IDs at once with:

```http
POST /api/v1/blobs/availability
```

The response separates locally committed descriptors from missing IDs while
preserving request order within each group.

## Upload discovery and creation

The upload collection implements the tus core protocol plus `creation`,
`expiration`, and `checksum` extensions:

```http
OPTIONS /api/v1/uploads
```

The discovery response advertises:

```text
Tus-Version: 1.0.0
Tus-Resumable: 1.0.0
Tus-Extension: creation,expiration,checksum
Tus-Max-Size: 17179869184
Tus-Checksum-Algorithm: sha1,sha256
```

tus 1.0.0 requires checksum-extension servers to support `sha1`; Fractonica
also supports and recommends `sha256`. Chunk checksums protect transport and
staging. The final content ID is always independently calculated with SHA-256
over the complete committed bytes.

Create an upload with an empty `POST` containing `Tus-Resumable: 1.0.0` and a
nonnegative `Upload-Length`. Deferred lengths and creation-with-upload are not
advertised. The default maximum complete blob is 16 GiB. A successful response
is `201 Created` with `Location`, `Upload-Offset: 0`, `Tus-Resumable`, and
`Upload-Expires`. A zero-length upload can complete immediately.

`Upload-Metadata` uses the tus comma-separated key/Base64-value grammar. It is
untrusted staging metadata: implementations must reject malformed or duplicate
keys and must never copy unsanitized values into response headers or paths.

## Resume and append

Inspect an upload's durable progress with:

```http
HEAD /api/v1/uploads/{uploadId}
Tus-Resumable: 1.0.0
```

The response includes `Upload-Offset`, `Upload-Length`, `Upload-Expires`, and
`Cache-Control: no-store`. A client resumes only from the returned offset.

Append bytes with `PATCH`, `Content-Type: application/offset+octet-stream`, the
current `Upload-Offset`, and `Tus-Resumable: 1.0.0`. Each PATCH body is bounded
to 4 MiB. A client may include:

```text
Upload-Checksum: sha256 <Base64 digest of this PATCH body>
```

The server verifies a supplied checksum before advancing durable state. On
mismatch it returns tus status `460`, discards the chunk, and leaves the offset
unchanged. An offset mismatch returns `409` without applying bytes. A successful
append returns `204 No Content` and the new `Upload-Offset`.

When offset equals length, the node verifies the complete length, computes the
canonical SHA-256 content ID, durably commits the blob, and may return:

```text
Fractonica-Content-Id: sha-256:<digest>
```

Clients must tolerate completion recovery: if the final response is lost, they
can repeat `HEAD`, retry safely at the reported offset, or query blob
availability using the expected content ID.

## Expiration and crash recovery

`Upload-Expires` is an RFC 9110 HTTP-date and may change between responses.
Expiration applies only to unfinished staging resources. Requests for a known
expired upload return `410 Gone`; an implementation that no longer remembers
the staging ID may return `404`, as tus permits.

The durable implementation must observe these recovery rules:

1. Staged bytes and the reported offset survive an orderly node restart until
   expiration.
2. The node never reports an offset beyond bytes known to be durable. Startup
   reconciliation truncates an uncommitted tail or moves metadata back to the
   verified staged length.
3. Completion verifies length and SHA-256, flushes the completed temporary
   file, atomically publishes it under the content ID, and only then reports
   completion.
4. A crash during finalization may leave recoverable staging, but never a
   partially readable committed blob.
5. If another upload already committed the same ID, finalization reuses the
   existing immutable blob after verifying its descriptor.

Startup reconciliation drains every pending recovery batch. It also removes a
canonical `<upload UUID>.part` staging file when no durable upload session owns
it, covering a crash after staging-file creation but before the database insert.
Malformed, non-regular, or symlinked staging entries stop startup for operator
inspection rather than being followed or silently discarded.

## Reading immutable blobs

Committed bytes are streamed from:

```http
GET /api/v1/blobs/{contentId}
HEAD /api/v1/blobs/{contentId}
```

A complete `GET` returns `ETag`, `Accept-Ranges: bytes`, `Content-Length`, and an
RFC 9530 `Content-Digest` such as `sha-256=:<Base64 digest>:`. The digest covers
the actual full response content.

One RFC 9110 byte range is supported. A satisfiable request returns `206`,
`Content-Range`, the range `Content-Length`, and a `Content-Digest` calculated
over the bytes actually carried by that partial response. Multiple ranges are
not supported. An unsatisfiable range returns `416` and
`Content-Range: bytes */<complete length>`.

A `HEAD` response has no message content, so RFC 9530 `Content-Digest` would not
be the digest of the stored blob. Fractonica returns `Repr-Digest` for the full
selected representation instead, alongside the same strong `ETag`,
`Accept-Ranges`, and complete `Content-Length` metadata.

Before a blob is advertised or served, the node verifies its byte length and
SHA-256 content ID. A successful verification is cached against stable file
metadata (including device, inode, modification, and change metadata on Unix),
so unchanged large files are not re-read for every availability query. A
fingerprint change forces a complete re-verification; platforms that cannot
provide a stable fingerprint re-hash on every access. Symlinked blob files and
digest-path directories are rejected.

## Immutability and retention

There is no blob `DELETE` route and this phase implements no garbage collector.
Tombstoning a record or removing a resource reference never mutates or deletes
committed bytes. Backups and replication may copy blobs by content ID without
consulting record state.

Only expired, unfinished upload staging may be reclaimed. Any future retention
or garbage-collection design requires a separate protocol, safety model, and
recovery plan; it must not be inferred from temporary upload expiration.
