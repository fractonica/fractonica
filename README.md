# Fractonica

Fractonica is a local-first personal data network. The current node owns its
local storage and exposes an OpenAPI-described loopback API. Local pairing and
capability-authorized peer reads are implemented; encrypted transport,
replication, and public-data publishing remain planned.

This repository is intentionally independent from Exeligmos. The historical
[Exeligmos importer](tools/import-exeligmos/README.md) is retained as an
explicitly legacy, unsigned-v1 migration tool; it refuses to target a signed-v2
node. A v2 migration must construct and sign new operations rather than assign
trust to legacy UUID operations.

## Current milestone

The initial vertical slice provides:

- a Rust workspace with explicit core, temporal, storage, API, and executable boundaries;
- a dependency-free `no_std` temporal core suitable for constrained helpers;
- a portable, allocation-free C11 SDK for temporal pulse logic and glyph geometry;
- a migration-backed SQLite installation database;
- a signed, space-scoped version 2 Merkle operation graph with idempotent
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
- `GET /api/v1/node`
- `POST /api/v2/spaces/{spaceId}/operations`
- `GET /api/v2/spaces/{spaceId}/operations/{operationId}`
- `GET /api/v2/spaces/{spaceId}/changes?after=0&limit=100`
- `GET /api/v2/spaces/{spaceId}/entities/{entityId}`
- `OPTIONS` / `POST /api/v1/uploads`
- `HEAD` / `PATCH /api/v1/uploads/{uploadId}`
- `GET` / `HEAD /api/v1/blobs/{contentId}`
- `POST /api/v1/blobs/availability`
- `GET /api/v1/saros` and the v1 Saros/glyph calculation routes
- `/api/docs`

Version 2 operation requests contain a complete, client-signed COSE
Sign1/Ed25519 envelope and strict JSON projection. The digest-derived
`OperationId` is the idempotency key; the node never derives the actor or signs
on the client's behalf. Concurrent entity heads are retained until a merge put
names every current head, tombstones remain in immutable history, and
`localSequence` is only a cursor for the node that assigned it. Unsigned
`/api/v1/operations` and `/api/v1/entities/{entityId}` requests return `410`
with `operation_v1_obsolete`; v1 Saros, glyph, and content-transfer routes
remain available on loopback. See [operation-log semantics](docs/operation-log.md)
and the [signed HTTP API](docs/signed-operation-api.md).

Record resources are ordered references to immutable IDs of the form
`sha-256:<64 lowercase hex>`. Missing local blobs do not invalidate operations;
clients can discover availability and resume bounded uploads independently.
Committed blobs have no direct deletion or garbage-collection API. See
[content-addressed storage](docs/content-storage.md).

To inventory an existing Exeligmos account or inspect the old development
migration flow, read the [legacy importer guide](tools/import-exeligmos/README.md).
Its dry run remains useful, but its write mode deliberately fails closed when
the destination exposes the signed-v2 boundary.

Use `--data-dir` to keep development data outside the platform default:

```sh
cargo run -p fractonica-node -- --data-dir .local/node
```

Run the standalone temporal engine without opening SQLite or creating a data
directory:

```sh
cargo run -p fractonica-node -- --profile saros
```

The Saros profile serves `GET /api/v1/saros`, pulse and reading routes, and
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
