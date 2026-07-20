# Self-hosting and local operation

## Scope of this guide

At this milestone, self-hosting means running a Fractonica node on the same
machine that uses it. The default `full` profile owns a local SQLite database
and immutable content store;
the stateless `saros` profile exposes the verified Saros calculation and
geometry API without creating local storage. Both profiles expose a
loopback-only HTTP API for their local control center or local tools. They are
not yet public, LAN, or Internet-facing services.

This is deliberately a narrow boundary. The full node supports a local pairing
ceremony and confirmation UI for protocol development, but there is no
supported non-loopback pairing transport, replication, public-data publishing,
remote administration, or production VPS deployment flow yet. Do not
port-forward, reverse-proxy, tunnel, or otherwise expose the current node
outside the local machine.

## Run a standalone local node

Use an explicit development directory so that experiments do not share the
desktop application's data:

```sh
cargo run -p fractonica-node -- \
  --data-dir "$PWD/.local/fractonica-node" \
  --display-name "Development node"
```

Use a new directory for this signed-v2 milestone. A database or identity from
an earlier unsigned prototype has no installation binding and is deliberately
not adopted; migrate it explicitly or retain it under a separate path.

The standalone default is `http://127.0.0.1:8789`. Confirm the process and
database are ready from a second terminal:

```sh
curl --fail --silent --show-error http://127.0.0.1:8789/health/live
curl --fail --silent --show-error http://127.0.0.1:8789/health/ready
curl --fail --silent --show-error http://127.0.0.1:8789/api/v1/node
```

The currently implemented endpoints are:

| Endpoint | Current purpose |
| --- | --- |
| `GET /health/live` | Confirms that the HTTP process is alive. |
| `GET /health/ready` | Confirms that the local SQLite store is available and reports its schema version. |
| `GET /api/v1/node` | Returns local node metadata, public `NodeId`, spaces, and advertised capabilities. |
| `POST /api/v2/spaces/{spaceId}/operations` | Verifies, authorizes, and atomically admits one complete client-signed operation. |
| `GET /api/v2/spaces/{spaceId}/operations/{operationId}` | Returns one admitted signed operation and node-local receipt metadata. |
| `GET /api/v2/spaces/{spaceId}/changes` | Pages one space's admitted-operation feed by node-local cursor. |
| `GET /api/v2/spaces/{spaceId}/entities/{entityId}` | Returns the current signed heads and conflict state for one entity in one space. |
| `/api/v1/operations` and `/api/v1/entities/{entityId}` | Obsolete unsigned surfaces; all supported methods return `410 operation_v1_obsolete`. |
| `/api/v1/uploads` | Discovers and creates resumable tus uploads. |
| `/api/v1/uploads/{uploadId}` | Inspects or appends to one resumable upload. |
| `/api/v1/blobs/{contentId}` | Streams immutable content, including one byte range. |
| `POST /api/v1/blobs/availability` | Separates locally available and missing content IDs. |
| `/api/v1/saros` and `/api/v1/glyphs` | Serve stateless Saros and glyph calculations; detailed routes are in the v1 contract. |
| `/api/docs` | Serves Swagger with signed operations v2 as the primary contract and local temporal/glyph/content v1 as the secondary contract. |
| `GET /api/openapi.json` | Serves the primary signed-operation v2 contract as JSON. |
| `GET /api/openapi-v1.json` | Serves the remaining v1/local contract as JSON. |

Signed operation v2 is the authoritative stateful surface. Clients retain
their actor keys and submit a complete strict JSON projection plus embedded
COSE Sign1 envelope; the node has no generic sign-on-behalf endpoint. The full
node enforces the locally anchored genesis, grant chains, admission windows,
and accepted revocations before changing heads or projections.

The ordinary graph read and v1 content routes are deliberately local
control-plane building blocks protected by the optional node-wide loopback
bearer. Paired actors instead use `POST /api/v2/peer/spaces/{spaceId}/changes`,
which verifies dual signatures, the completed pairing, the exact `readSpace`
grant, and a durable one-use nonce. This authenticates a peer request but does
not encrypt it or authorize non-loopback exposure. V1 upload/blob routes do
not yet enforce space content capabilities, and the node does not yet
replicate with peers or publish data. See
[operation-log semantics](operation-log.md), the
[signed HTTP API](signed-operation-api.md), and
[content-addressed storage](content-storage.md) before building a client.

## Run a stateless Saros engine

The `saros` profile starts the same loopback-only HTTP server without opening
SQLite, creating a data directory, or taking a process lock. It serves the
checked-in, verified Saros engine and reviewed eclipse geometry for series
101–161. It is useful for local tools, desktop experiments, and a future
standalone temporal sidecar.

```sh
cargo run -p fractonica-node -- \
  --profile saros \
  --bind 127.0.0.1:8790 \
  --display-name "Local Saros engine"
```

Verify the engine from a second terminal:

```sh
curl --fail --silent --show-error http://127.0.0.1:8790/health/live
curl --fail --silent --show-error http://127.0.0.1:8790/health/ready
curl --fail --silent --show-error http://127.0.0.1:8790/api/v1/saros
curl --fail --silent --show-error \
  'http://127.0.0.1:8790/api/v1/saros/pulse?atUnixSeconds=0'
curl --fail --silent --show-error \
  'http://127.0.0.1:8790/api/v1/saros/series/141/reading?atUnixSeconds=0&precisionBits=30'
```

The Saros profile reports that no storage is configured in its readiness
response and identifies itself as the `saros` profile in node metadata. It is
read-only: it does not host records, accounts, pairing, replication, or any
write API. Requests for eclipse paths outside the reviewed 101–161 release are
explicitly unavailable rather than inferred.

`--data-dir` and `FRACTONICA_DATA_DIR` are intentionally rejected with
`--profile saros`. This prevents a directory from looking like persistent state
when the profile is deliberately stateless. Select the profile with
`--profile saros` or `FRACTONICA_PROFILE=saros`; `full` remains the default.

`--data-dir`, `--bind`, and `--display-name` are also available through
`FRACTONICA_DATA_DIR`, `FRACTONICA_BIND`, and `FRACTONICA_DISPLAY_NAME`.
The node accepts only loopback addresses. For example,
`FRACTONICA_BIND=0.0.0.0:8789` is intentionally rejected. A loopback address
with port `0` is valid for a local supervisor that needs an operating-system
assigned port.

Press `Ctrl-C` to stop a development node cleanly. On Unix, `SIGTERM` is also
handled as a clean shutdown signal.

## Data directory and ownership

If `--data-dir` is omitted, the node uses the platform-local data directory
reported by the startup log. Prefer an explicit `--data-dir` for development,
tests, and any manual recovery work so its ownership is unambiguous.

One node process owns one data directory. A process lock prevents two nodes
from using the same directory at once; do not work around that lock or point a
second process at the same directory.

An established full installation has three inseparable trust-critical units:

- `fractonica.db` contains the signed graph, trusted-space anchor, capability
  projections, durable admission-clock high-water mark, and content metadata;
- `identity/` contains the distinct node-transport, space-controller, and
  local-writer private seeds plus the default `SpaceId`;
- `installation.json` contains the non-secret public binding between the node,
  default space, exact signed genesis, initial writer grant, controller, and
  writer.

During the only valid first run, `installation.identity.pending.json` is
published before the keystore writes any key. A crash before, during, or just
after identity creation therefore resumes the same marked bootstrap and the
keystore's own atomic recovery protocol. Once the protected keys and exact
signed bootstrap exist, `installation.pending.json` is published before SQLite
receives the anchor. A crash can replay those exact operations. It never
generates a second genesis for the same space or replacement keys for a pending
anchor. Publication also recovers the private staging file on either side of
the atomic no-replace link; unrelated inodes still fail closed.

`content/` contains locally available immutable resource bytes. It is not part
of operation validity: a missing content tree is recreated empty and those
resources report unavailable until restored or fetched again. Treat it as
irreplaceable personal data when it is the only copy, even though it is not a
trust anchor.

On restart, the node validates the manifest against both protected identity and
database trust anchor. If an established database or identity directory is
missing, if either belongs to another installation, or if persistent state
exists without its binding, startup fails closed. The node does not silently
generate replacement controller keys, create a new trust anchor, or adopt an
untracked database. Explicit recovery or migration is required.

On Unix, newly created state uses these permissions, and established state with
different ownership, modes, or hard-link counts is rejected rather than
silently repaired:

- the data directory: `0700`;
- `fractonica.db`: `0600`;
- `node.lock`, both installation pending markers, and `installation.json`:
  `0600`;
- `identity/`: `0700`, with every identity role and manifest file `0600`;
- `content/`, its staging directory, and digest-prefix directories: `0700`;
- staged and committed content files: `0600`.

It also refuses a symbolic link where the data directory or database file is
expected. These controls protect local filesystem ownership only; they do not
encrypt the database. Store backups in a location with equivalent access
controls.

The current raw `FileKeyStore` is Unix-only because its security contract
depends on owner IDs, exact modes, single hard links, no-follow opens, and
durable directory operations. It intentionally refuses to run on Windows. A
Windows release needs a reviewed Credential Manager/DPAPI or equivalent secure
`KeyStore` backend; relaxing filesystem checks is not supported. Mode and owner
checks do not prove the absence of extended ACL entries on macOS or network
filesystems, so the raw backend is limited to a controlled single-user local
filesystem. A production macOS desktop release requires a reviewed Keychain
adapter.

The database uses SQLite WAL mode with `synchronous=FULL`. Blob bytes live
outside SQLite under `content/`; their descriptors and upload state live in
the database. Always back up the whole data directory when media preservation
matters. A database-only backup loses locally available media bytes; without
the matching `identity/` and `installation.json` it is also not a recoverable
established trust installation.

## Backup and recovery safety

Fractonica does not yet ship a backup or restore command. Until it does, use
this conservative procedure:

1. Stop the standalone node with `Ctrl-C`, or fully quit the desktop app so its
   sidecar has exited.
2. Verify that no Fractonica node process still owns the data directory.
3. Copy or archive the entire data directory to a trusted local backup
   location, preserving file names and permissions. At minimum, verify that the
   stopped snapshot contains `fractonica.db`, the complete `identity/`, the
   complete `content/`, and `installation.json`. Never mix the database,
   identity, or installation manifest between backups. A content tree may be
   restored independently by digest, but omitting it means those bytes are no
   longer locally available.
4. Do not take an opportunistic copy of only `fractonica.db` while a node is
   running. If SQLite sidecar files such as `fractonica.db-wal` or
   `fractonica.db-shm` are present, they belong to the same consistent SQLite
   state and must be kept together.
5. Test a backup by restoring it into a *different* data directory, starting a
   standalone node with that directory, and checking `/health/ready` and
   `/api/v1/node`. The returned public `NodeId`, `SpaceId`, genesis digest,
   controller, and local writer must match the backed-up installation.

Never replace an active data directory in place. Stop the node first, retain
the previous directory until the restored copy has passed its readiness check,
and use a separate directory for recovery testing. This is a manual local
recovery workflow, not a supported production restore system. Do not attempt to
"repair" partial loss by deleting `installation.json` or copying only an
identity directory: the fail-closed binding is what prevents silent identity
or trust-anchor replacement.

## Desktop application behavior

The desktop application is a local supervisor, not a second server type. It
starts the same `fractonica-node` executable as a sidecar, assigns it a random
loopback port, and gives its bundled control center a fresh per-launch bearer
token through Tauri's local invoke boundary. The token is not placed in a URL
or command-line argument. When the desktop app exits, it terminates the child
node and removes the private readiness handoff file.

Run a development desktop instance from the repository root:

```sh
pnpm desktop:dev
```

Build a local bundle with:

```sh
pnpm desktop:build
```

Do not treat the sidecar's readiness file or bootstrap token as a device API;
they are private process-supervision details. Likewise, do not launch a second
standalone node against the desktop node's data directory while the desktop
app is running.

## Local control-center development

Start a standalone node first, then run the web control center:

```sh
pnpm install
pnpm dev
```

It defaults to `http://127.0.0.1:8789`. To point the development UI at another
local node, set `VITE_FRACTONICA_NODE_URL` to that node's loopback URL before
starting Vite. The control center reads readiness and node metadata and can
administer the loopback pairing ceremony; it is not a general record-management
UI yet.

## Deliberately deferred deployment boundary

The following are not implemented and must not be inferred from the word
"self-hosted":

- public or non-loopback HTTP binding, TLS, reverse-proxy configuration, or
  public authentication;
- non-loopback device pairing, LAN discovery, peer-to-peer transport, or
  replication;
- encrypted/resumable peer sessions and multi-page replication orchestration
  beyond the bounded, dual-signed `readSpace` change-page primitive;
- space-capability enforcement for v1 content upload, availability, metadata,
  and blob reads;
- user accounts, remote API keys, higher-level event/tag CRUD facades, or
  public feed distribution;
- a supported Linux service unit, container image, VPS deployment workflow, or
  automated backup/restore tooling.

The [trust-kernel threat model](threat-model.md) and Phase 3 security ADRs fix
the signed-operation, capability, key-lifecycle, and QR-bootstrap boundaries.
The node now implements local trusted-space bootstrap, grant/revocation
admission, signed-v2 operation storage, the bounded Noise pairing handshake,
explicit local confirmation, and replay-safe paired reads; that does not
implement or authorize a network service. Before any deferred capability is enabled, Fractonica still
needs the applicable versioned wire contract, abuse bounds, interoperability
fixtures, operational runbook, and complete implementation review. The current
loopback-only restriction remains intentional until those pieces exist.
