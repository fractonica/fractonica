# Fractonica

Fractonica is a local-first personal data network. The current node owns its
local storage and exposes an OpenAPI-described loopback API. Local pairing and
capability-authorized peer reads are implemented; encrypted transport,
replication, and public-data publishing remain planned.

This repository is intentionally independent from Exeligmos. Exeligmos is an
external data source: the future import agent will read it and author ordinary
Fractonica operations through the same client core as every other agent. Its
IDs, account model, storage layout, and API are not Fractonica concepts.

## Current milestone

The initial vertical slice provides:

- a Rust workspace with explicit core, temporal, storage, API, and executable boundaries;
- a dependency-free `no_std` temporal core suitable for constrained helpers;
- a portable, allocation-free C11 SDK for temporal pulse logic and glyph geometry;
- a migration-backed SQLite installation database;
- a signed, space-scoped Merkle operation graph with idempotent
  admission, durable tombstones, concurrent heads, node-local change cursors,
  capability grants, and append-only revocations;
- content-addressed record resources with tus 1.0.0 resumable staging,
  immutable SHA-256 blobs, availability checks, and byte-range streaming;
- loopback-only liveness, readiness, node metadata, and Swagger endpoints;
- a stateless `saros` node profile for exact temporal readings and reviewed
  eclipse geometry without local storage;
- a React control center that can inspect the local node and administer the
  loopback Noise pairing ceremony through a scannable QR and two-glyph human
  confirmation;
- dual-signed, pairing-bound `readSpace` change pages with durable replay
  protection;
- a thin Tauri desktop shell that owns the node process lifecycle;
- a platform-neutral Rust client authoring core with explicit native key
  custody and causal create, edit, delete, and profile operations;
- an independent client SQLite store with atomic offline commits, rebuildable
  heads/projections, and crash-recoverable operation and resource leases;
- a supervised native sync worker with bounded signed delivery, durable
  incremental cursors, capped retry backoff, cancellation, and compact status;
- a private crash-safe client blob store plus automatic durable media queues,
  bounded availability, tus upload, and resumable range downloads;
- a strict TypeScript node client for projection paging, statistics, immutable
  operation reads, and delivery of already-signed operations;
- protected Unix filesystem identity bootstrap with an explicit installation
  binding that persists the exact signed default-space bootstrap before the
  database is allowed to commit it;
- architecture and protocol contracts for the next replication work.

## Run the node

```sh
cargo run -p fractonica-node
```

The standalone node listens on `http://127.0.0.1:8789` by default. The desktop
application uses a private random loopback port instead. Useful endpoints:

- `GET /health/live`
- `GET /health/ready`
- `GET /api/node`
- `POST /api/spaces/{spaceId}/operations`
- `GET /api/spaces/{spaceId}/operations/{operationId}`
- `GET /api/spaces/{spaceId}/changes?after=0&limit=100`
- `GET /api/spaces/{spaceId}/entities/{entityId}`
- `GET /api/spaces/{spaceId}/records`
- `GET /api/spaces/{spaceId}/events`
- `GET /api/spaces/{spaceId}/tags`
- `GET /api/spaces/{spaceId}/profiles`
- `GET /api/spaces/{spaceId}/stats`
- `OPTIONS` / `POST /api/uploads`
- `HEAD` / `PATCH /api/uploads/{uploadId}`
- `GET` / `HEAD /api/blobs/{contentId}`
- `POST /api/blobs/availability`
- `GET /api/saros` and the Saros/glyph calculation routes
- `/api/docs`

Operation requests contain a complete, client-signed COSE
Sign1/Ed25519 envelope and strict JSON projection. The digest-derived
`OperationId` is the idempotency key; the node never derives the actor or signs
on the client's behalf. Concurrent entity heads are retained until a merge put
names every current head, tombstones remain in immutable history, and
`localSequence` is only a cursor for the node that assigned it. See
[operation-log semantics](docs/operation-log.md) and the
[signed HTTP API](docs/signed-operation-api.md).

Native clients must commit authored operations to their local store before
network delivery. The node is never the success boundary for a local write.
See the [client core and local-first write path](docs/client-core.md).

Record resources are ordered references to immutable IDs of the form
`sha-256:<64 lowercase hex>`. Missing local blobs do not invalidate operations;
clients can discover availability and resume bounded uploads independently.
Committed blobs have no direct deletion or garbage-collection API. See
[content-addressed storage](docs/content-storage.md).

Use `--data-dir` to keep development data outside the platform default:

```sh
cargo run -p fractonica-node -- --data-dir .local/node
```

Run the standalone temporal engine without opening SQLite or creating a data
directory:

```sh
cargo run -p fractonica-node -- --profile saros
```

The Saros profile serves `GET /api/saros`, pulse and reading routes, and
reviewed path geometry for Saros 101–161. It is loopback-only and read-only.

See [self-hosting and local operation](docs/self-hosting.md) for the current
local-only boundary, data-directory ownership, backup safety, desktop-sidecar
behavior, and the capabilities that are intentionally deferred.

## Run the control center

```sh
pnpm install
pnpm dev
```

## Run the desktop application

The desktop script builds a target-specific node sidecar before launching Tauri:

```sh
pnpm desktop:dev
```

Create a release bundle with:

```sh
pnpm desktop:build
```

## Validate

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
pnpm check
pnpm test
pnpm build
```

## License

Fractonica's node, desktop application, web application, firmware, and Rust
crates are licensed under the GNU Affero General Public License v3.0 or later;
see [LICENSE](LICENSE). Public contracts and the Embedded C SDK are licensed
under the Apache License 2.0 so independent clients and devices can implement
the protocol; see their directory-level license notices and
[LICENSES/Apache-2.0.txt](LICENSES/Apache-2.0.txt).
