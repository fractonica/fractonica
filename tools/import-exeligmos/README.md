# Exeligmos HTTP importer

`@fractonica/import-exeligmos` is a one-way, API-only migration tool for moving
the current Exeligmos record collection into a Fractonica node. It never opens
the Exeligmos PostgreSQL database or media directory. Source access is read-only;
destination writes use Fractonica's public operation and content APIs.

This is deliberately an explicit migration tool, not a permanent compatibility
layer. The mapping contract is versioned as `exeligmos-record-v1`.

## Current scope

The importer migrates:

- public records, including occurrence interval, text, emoji, metadata, source,
  template attribution, references, and arbitrary payload fields;
- private records without decrypting them: the authenticated ciphertext becomes
  a content-addressed resource and its AES-GCM envelope remains in provenance;
- attached public or encrypted media as immutable content-addressed blobs;
- full definitions of tags referenced by records, embedded in migration
  provenance until Fractonica gains a canonical tag schema.

The complete Exeligmos tag catalog is read and counted during every run.
Unreferenced tags are not yet written as standalone Fractonica entities. Users,
devices, events, templates, API keys, deleted-record history, and Exeligmos
command history are also outside this first importer. Run `--dry-run` before a
real migration and retain the Exeligmos backup until these limits are acceptable.

## Prerequisites

- Node.js 24 or newer;
- a running Exeligmos server reachable over HTTP(S);
- a running stateful Fractonica `node` profile with the operation, blob
  availability, and TUS upload endpoints enabled;
- enough destination disk space for the content store;
- an Exeligmos JWT or API key with `records:read`, `tags:read`, and `media:read`;
- a Fractonica bearer token if the destination requires one. A loopback node may
  currently use its trusted local application context without a token.

### Transport security

Plain HTTP is accepted only for the explicitly local names and address ranges
`localhost`, `127.0.0.0/8`, and `[::1]`. Every other source or destination,
including a private-LAN address such as `192.168.0.24`, must use HTTPS. This rule
is checked before any network request and again when loading a checkpoint.

TUS `Location` responses and checkpointed upload URLs must also remain on the
destination origin. The importer refuses a cross-origin upload URL rather than
forwarding the destination bearer token to it. For LAN migration, terminate TLS
at the node or a trusted reverse proxy and pass its `https://` URL.

Install workspace dependencies once from the repository root:

```sh
pnpm install
```

## Dry run

Keep the Exeligmos source quiescent before starting: stop clients and agents
that create or edit records. Exeligmos cursors are stable for a fixed query, but
they are not a database snapshot boundary; updates during a scan can move a
record ahead of the saved cursor. Avoid concurrent writes to the same Fractonica
entities as well. The importer refreshes destination heads immediately before
append, but the current API has no transaction spanning that read and write.

Set tokens through the environment so they do not enter shell history:

```sh
export EXELIGMOS_TOKEN='...'
export FRACTONICA_TOKEN='...'

pnpm --filter @fractonica/import-exeligmos start -- \
  --source http://127.0.0.1:8788 \
  --destination http://127.0.0.1:8789 \
  --checkpoint "$HOME/.fractonica/import-exeligmos.json" \
  --dry-run
```

Dry-run mode reads and validates every source page, maps every record, inventories
media sizes, and reports unsupported records. It makes no destination requests
and does not create or modify a checkpoint.

The command exits with status `2` if any record was skipped because it could not
be represented without truncation. Other failures exit with status `1`.

## Migration

Remove `--dry-run` after reviewing its JSON summary:

```sh
pnpm --filter @fractonica/import-exeligmos start -- \
  --source http://127.0.0.1:8788 \
  --destination http://127.0.0.1:8789 \
  --checkpoint "$HOME/.fractonica/import-exeligmos.json"
```

Verification is on by default. `--no-verify` exists for diagnostics, but is not
recommended for the final migration. `--quiet` suppresses progress messages;
the machine-readable JSON summary is still written to standard output.

`--source-token` and `--destination-token` are supported, but environment
variables are preferred because command-line arguments can be visible to other
local processes and shell history.

## Deterministic mapping

For each source record:

| Exeligmos | Fractonica |
| --- | --- |
| `originId` | canonical `entityId` |
| origin UUID + source revision | deterministic RFC 9562 UUIDv8 `operationId` |
| operation UUID | `Idempotency-Key: exi-op-<uuid>` |
| `occurredAt` / `endedAt` | `startAtUnixMs` / `endAtUnixMs` |
| `updatedAt` | operation `occurredAtUnixMs` |
| media SHA-256 | `sha-256:<lowercase hex>` content ID |
| ordered unique media | ordered `document.resources` with role `attachment` |
| source-only fields | bounded `metadata.migration` provenance |

If a later Exeligmos revision is imported with the same checkpoint, its exact
causal parents are retained in that checkpoint. Before any new or resumed
planned operation, the importer reads `GET /api/v1/entities/{entityId}`. An absent
entity starts with no parent. If every current head is a provable operation from
the same deterministic Exeligmos mapping and has a lower source revision, the
new operation names all of those heads as parents. This also safely merges
recognized importer-created heads instead of creating another blind branch.

Duplicate byte-identical attachments are stored once because a Fractonica
document cannot contain the same content ID twice. Every source media ID remains
listed in provenance. A record is rejected instead of silently truncated if it
exceeds Fractonica's 64-unique-resource limit, text limit, or bounded metadata
contract.

Private occurrence time is inside Exeligmos ciphertext and is intentionally not
decrypted. `createdAt` is used as the structural start time and this fallback is
explicitly marked in provenance. The raw decoded ciphertext (including its GCM
tag) is uploaded as role `encrypted-record-payload`; the nonce, crypto version,
key version, content type, and ciphertext content ID remain available for a
future authenticated migration agent.

## HTTP pipeline

The source side uses only:

- `GET /v1/tags` with cursor pagination;
- `GET /v1/records` with cursor pagination (`limit=25`);
- each owner-only media `contentUrl` with the source bearer token.

The destination side uses only:

- `POST /api/v1/blobs/availability`;
- TUS `POST`, `HEAD`, and `PATCH /api/v1/uploads`;
- `GET /api/v1/entities/{entityId}` for causal preflight and checkpoint recovery;
- `POST /api/v1/operations`;
- `GET /api/v1/operations` for verification.

Media is never buffered as a whole. TUS PATCH chunks are at most 4 MiB and carry
`Upload-Checksum: sha256 <base64>`. On resume, the source is read again from byte
zero because Exeligmos does not promise Range support; bytes before the server's
TUS offset are hashed and discarded, then transfer continues. A lost PATCH
response is reconciled with TUS `HEAD` before retrying.

## Checkpoint and verification guarantees

The checkpoint is atomically replaced after every accepted upload chunk, blob
verification, operation append, and completed source page. New files use mode
`0600`. It contains endpoint identities, opaque source cursors, deterministic
mappings, TUS upload URLs and offsets, and destination local sequence numbers.
It never stores either bearer token.

A checkpoint can only be resumed with exactly the same normalized source and
destination URLs. Once a scan completes, the next run starts at the first source
page and uses the retained deterministic mappings to discover new records while
replaying nothing unnecessarily.

Before an operation is submitted, every referenced blob must appear in the
destination availability response with the expected byte length. After append,
verification reads the exact destination local sequence and compares the stored
operation (apart from the destination-resolved actor) with the deterministic
submission. Keep the checkpoint with the migration backup; deleting it does not
change deterministic operation IDs, but it does lose resumable-upload offsets
and saved destination sequence numbers.

Checkpoint loss does not authorize a blind, parentless append to an existing
entity. If the destination already contains the same deterministic operation,
the importer reconstructs its exact parents and idempotently replays it. If all
current heads are recognized lower Exeligmos revisions, it continues from all of
them. A manual operation, tombstone, different mapping, same-or-newer revision,
malformed provenance, or mixed conflict causes an explicit preflight failure
before blob or operation writes. Restore the original checkpoint or inspect and
explicitly merge that entity before retrying.

## Development checks

```sh
pnpm --filter @fractonica/import-exeligmos check
pnpm --filter @fractonica/import-exeligmos test
```

Tests cover UUID fixtures, public and private mapping, lossless-bound rejection,
checkpoint endpoint validation and permissions, HTTPS enforcement, bounded error
capture, source-stream cancellation, dry-run isolation, authenticated source
reads, content upload, lost-PATCH recovery, safe checkpoint-loss continuation and
rejection, operation append, verification, and a completed-checkpoint rerun.
