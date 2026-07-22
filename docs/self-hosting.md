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

Use a dedicated directory for each node installation. Development builds may
reset that directory whenever the checked-in storage shape changes.

The standalone default is `http://127.0.0.1:8789`. Confirm the process and
database are ready from a second terminal:

```sh
curl --fail --silent --show-error http://127.0.0.1:8789/health/live
curl --fail --silent --show-error http://127.0.0.1:8789/health/ready
curl --fail --silent --show-error http://127.0.0.1:8789/api/node
```

The currently implemented endpoints are:

| Endpoint | Current purpose |
| --- | --- |
| `GET /health/live` | Confirms that the HTTP process is alive. |
| `GET /health/ready` | Confirms that the local SQLite store is available. |
| `GET /api/node` | Returns local node metadata, public `NodeId`, spaces, and advertised capabilities. |
| `POST /api/spaces/{spaceId}/operations` | Verifies, authorizes, and atomically admits one complete client-signed operation. |
| `GET /api/spaces/{spaceId}/operations/{operationId}` | Returns one admitted signed operation and node-local receipt metadata. |
| `GET /api/spaces/{spaceId}/changes` | Pages one space's admitted-operation feed by node-local cursor. |
| `GET /api/spaces/{spaceId}/entities/{entityId}` | Returns the current signed heads and conflict state for one entity in one space. |
| `GET /api/spaces/{spaceId}/records`, `/events`, `/tags`, `/profiles` | Bounded, cursor-based client projections rebuilt from admitted operations. |
| `GET /api/spaces/{spaceId}/stats` | Aggregate client entity and media statistics. |
| `/api/uploads` | Discovers and creates resumable tus uploads. |
| `/api/uploads/{uploadId}` | Inspects or appends to one resumable upload. |
| `/api/blobs/{contentId}` | Streams immutable content, including one byte range. |
| `POST /api/blobs/availability` | Separates locally available and missing content IDs. |
| `/api/saros` and `/api/glyphs` | Serve stateless Saros and glyph calculations. |
| `/api/docs` | Serves Swagger for the complete Fractonica API. |
| `GET /api/openapi.json` | Serves the complete contract as JSON. |

The signed operation log is the authoritative stateful surface. Clients retain
their actor keys and submit a complete strict JSON projection plus embedded
COSE Sign1 envelope; the node has no generic sign-on-behalf endpoint. The full
node enforces the locally anchored genesis, grant chains, admission windows,
and accepted revocations before changing heads or projections.

The ordinary graph and content routes are deliberately local
control-plane building blocks protected by the optional node-wide loopback
bearer. Paired actors instead use `POST /api/peer/spaces/{spaceId}/changes`,
which verifies dual signatures, the completed pairing, the exact `readSpace`
grant, and a durable one-use nonce. This authenticates a peer request but does
not encrypt it or authorize non-loopback exposure. Upload/blob routes do
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
curl --fail --silent --show-error http://127.0.0.1:8790/api/saros
curl --fail --silent --show-error \
  'http://127.0.0.1:8790/api/saros/pulse?atUnixSeconds=0'
curl --fail --silent --show-error \
  'http://127.0.0.1:8790/api/saros/series/141/reading?atUnixSeconds=0&precisionBits=30'
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

An established full installation has these local state units:

- `fractonica.db` contains zero or more independent signed workspace graphs,
  capability projections, delivery state, and content metadata;
- `identity/` contains the distinct node-transport, controller, and local-writer
  private seeds; and
- `installation.json` contains the non-secret binding between those public
  identities. It does not select or contain a workspace.

A fresh node opens at the workspace chooser with no workspace. Creating a
workspace writes a new signed root to SQLite. Linking adopts the selected
remote workspace as another independent root; neither action changes the
installation identity.

`content/` contains locally available immutable resource bytes. It is not part
of operation validity: a missing content tree is recreated empty and those
resources report unavailable until restored or fetched again. Treat it as
irreplaceable personal data when it is the only copy, even though it is not a
trust anchor.

On restart, the node validates the installation manifest against the protected
identity. Workspace anchors are verified independently when they are loaded.
During development, resetting the local installation removes both identity and
all workspace roots.

On Unix, newly created state uses these permissions, and established state with
different ownership, modes, or hard-link counts is rejected rather than
silently repaired:

- the data directory: `0700`;
- `fractonica.db`: `0600`;
- `node.lock`, the identity marker, and `installation.json`: `0600`;
- `identity/`: `0700`, with every identity role and manifest file `0600`;
- `content/`, its staging directory, and digest-prefix directories: `0700`;
- staged and committed content files: `0600`.

It also refuses a symbolic link where the data directory or database file is
expected. These controls protect local filesystem ownership only; they do not
encrypt the database. Store backups in a location with equivalent access
controls.

The raw-file form of `FileKeyStore` is used on Unix. On Windows, private
identity and pairing-secret payloads are encrypted with current-user DPAPI and
domain-specific entropy before filesystem publication. Mode and owner
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
   `/api/node`. The returned `NodeId` and complete workspace list must match the
   backed-up installation.

Never replace an active data directory in place. Stop the node first, retain
the previous directory until the restored copy has passed its readiness check,
and use a separate directory for recovery testing. This is a manual local
recovery workflow, not a supported production restore system. Do not attempt to
"repair" partial loss by deleting `installation.json` or copying only an
identity directory: the fail-closed binding is what prevents silent identity
or trust-anchor replacement.

## Desktop application behavior

The desktop application is a local supervisor, not a second server type. It
starts the same `fractonica-node` executable as a sidecar on an
operating-system-assigned port. Tauri receives a loopback control URL and a
fresh per-launch bearer token through its private invoke boundary; pairing QR
codes advertise a private-LAN URL for the same listener. The administrator
token is not placed in the QR, URL, or command-line arguments. When the desktop
app exits, it terminates the child node and removes the readiness handoff file.

Run a development desktop instance from the repository root:

```sh
pnpm desktop:dev
```

This command builds and starts the node automatically. Keep its terminal open
and do not start a second node against the desktop profile. The node watches
the desktop parent PID and shuts down if its supervisor disappears.

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
administer the pairing ceremony; it is not a general record-management
UI yet.

## Deliberately deferred deployment boundary

The following are not implemented and must not be inferred from the word
"self-hosted":

- public HTTP binding, TLS, reverse-proxy configuration, or public
  authentication;
- automatic LAN discovery, internet peer-to-peer transport, or public
  replication;
- a confidential persistent peer channel beyond the bounded Noise bootstrap,
  paired change-page proof, and grant-scoped private-LAN credential;
- user accounts, remote API keys, higher-level event/tag CRUD facades, or
  public feed distribution;
- a supported Linux service unit, container image, VPS deployment workflow, or
  automated backup/restore tooling.

The [trust-kernel threat model](threat-model.md) and Phase 3 security ADRs fix
the signed-operation, capability, key-lifecycle, and QR-bootstrap boundaries.
The node now implements local trusted-space bootstrap, grant/revocation
admission, signed operation storage, the bounded Noise pairing handshake,
explicit local confirmation, replay-safe paired reads, and private-LAN
record/media synchronization. Before any deferred capability is enabled, Fractonica still
needs the applicable versioned wire contract, abuse bounds, interoperability
fixtures, operational runbook, and complete implementation review. The current
listener must not be exposed to a public interface or untrusted network.
