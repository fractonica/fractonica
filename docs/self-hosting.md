# Self-hosting and local operation

## Scope of this guide

At this milestone, self-hosting means running a Fractonica node on the same
machine that uses it. The default `full` profile owns a local SQLite database
and immutable content store;
the stateless `saros` profile exposes the verified Saros calculation and
geometry API without creating local storage. Both profiles expose a
loopback-only HTTP API for their local control center or local tools. They are
not yet public, LAN, or Internet-facing services.

This is deliberately a narrow boundary. There is no supported pairing,
replication, public-data publishing, remote administration, or production VPS
deployment flow yet. Do not port-forward, reverse-proxy, tunnel, or otherwise
expose the current node outside the local machine.

## Run a standalone local node

Use an explicit development directory so that experiments do not share the
desktop application's data:

```sh
cargo run -p fractonica-node -- \
  --data-dir "$PWD/.local/fractonica-node" \
  --display-name "Development node"
```

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
| `GET /api/v1/node` | Returns the local installation descriptor. |
| `POST /api/v1/operations` | Validates and appends one causal record operation. |
| `GET /api/v1/operations` | Pages the node-local operation feed by local cursor. |
| `GET /api/v1/entities/{entityId}` | Returns the current heads and conflict state for an entity. |
| `/api/v1/uploads` | Discovers and creates resumable tus uploads. |
| `/api/v1/uploads/{uploadId}` | Inspects or appends to one resumable upload. |
| `/api/v1/blobs/{contentId}` | Streams immutable content, including one byte range. |
| `POST /api/v1/blobs/availability` | Separates locally available and missing content IDs. |
| `/api/docs` | Serves the Swagger UI for the checked-in OpenAPI document. |
| `GET /api/openapi.json` | Serves that OpenAPI document as JSON. |

The operation and content APIs are deliberately local building blocks. They do
not yet pair devices, replicate with peers, or publish data outside this node.
See [operation-log semantics](operation-log.md) and
[content-addressed storage](content-storage.md) before building an importer or
agent against them.

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

On Unix, the node creates or tightens these permissions:

- the data directory: `0700`;
- `fractonica.db`: `0600`;
- `node.lock`: `0600`.
- `content/`, its staging directory, and digest-prefix directories: `0700`;
- staged and committed content files: `0600`.

It also refuses a symbolic link where the data directory or database file is
expected. These controls protect local filesystem ownership only; they do not
encrypt the database. Store backups in a location with equivalent access
controls.

The database uses SQLite WAL mode with `synchronous=FULL`. Blob bytes live
outside SQLite under `content/`; their descriptors and upload state live in
the database. Always back up the whole data directory. A database-only backup
retains causal references but loses locally available media bytes.

## Backup and recovery safety

Fractonica does not yet ship a backup or restore command. Until it does, use
this conservative procedure:

1. Stop the standalone node with `Ctrl-C`, or fully quit the desktop app so its
   sidecar has exited.
2. Verify that no Fractonica node process still owns the data directory.
3. Copy or archive the entire data directory to a trusted local backup
   location, preserving file names and permissions.
4. Do not take an opportunistic copy of only `fractonica.db` while a node is
   running. If SQLite sidecar files such as `fractonica.db-wal` or
   `fractonica.db-shm` are present, they belong to the same consistent SQLite
   state and must be kept together.
5. Test a backup by restoring it into a *different* data directory, starting a
   standalone node with that directory, and checking `/health/ready` and
   `/api/v1/node`.

Never replace an active data directory in place. Stop the node first, retain
the previous directory until the restored copy has passed its readiness check,
and use a separate directory for recovery testing. This is a manual local
recovery workflow, not a supported production restore system.

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
starting Vite. The control center currently reads readiness and node metadata;
it is not a general record-management UI yet.

## Deliberately deferred deployment boundary

The following are not implemented and must not be inferred from the word
"self-hosted":

- public or non-loopback HTTP binding, TLS, reverse-proxy configuration, or
  public authentication;
- device pairing, QR pairing, LAN discovery, peer-to-peer transport, or
  replication;
- user accounts, remote API keys, record/event/tag/media APIs, or public feed
  distribution;
- a supported Linux service unit, container image, VPS deployment workflow, or
  automated backup/restore tooling.

Before any of those capabilities are added, Fractonica needs a versioned
protocol, threat model, authentication and key-lifecycle decision, operational
runbook, and corresponding contract/conformance coverage. The current
loopback-only restriction is intentional until those pieces exist.
