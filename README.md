# Fractonica

Fractonica is a local-first personal data network. The current node owns its
local storage and exposes an OpenAPI-described control API. The desktop build
supervises that node, advertises a private-LAN pairing endpoint, and supports
capability-authorized bidirectional record and media synchronization. Public
transport, automatic discovery, and public-data publishing remain planned.

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
- authenticated liveness, readiness, node metadata, and Swagger endpoints;
- a stateless `saros` node profile for exact temporal readings and reviewed
  eclipse geometry without local storage;
- a React control center that can inspect the local node, issue private-LAN
  Noise invitations, pair mobile or desktop clients, and compare the complete
  two-glyph human confirmation;
- an Expo/React Native mobile foundation with a strict native-client boundary,
  canonical SVG glyph rendering, and an offline-first records surface;
- dual-signed, pairing-bound `readSpace` change pages plus a Noise-delivered,
  grant-scoped operation/content transport credential;
- a Tauri desktop shell that supervises the node and owns a native client
  runtime without exposing keys or storage handles to the webview;
- a platform-neutral Rust client authoring core with explicit native key
  custody and causal create, edit, delete, and profile operations;
- a composed native client runtime that verifies and adopts the bundled node's
  signed trust anchors, persists locally first, and supervises synchronization;
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
pnpm node:dev
```

The standalone node listens on `http://127.0.0.1:8789` by default. The desktop
application uses the same stable port: loopback remains its private control
plane, while authenticated pairing traffic is reachable on the private LAN.
Keeping the port stable is part of the durable device-link contract. Useful endpoints:

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

This is the normal way to launch the node for desktop/iOS pairing. Do not start
a second node separately: the command builds the target-specific sidecar,
launches it, waits for readiness, and then opens Tauri:

```sh
pnpm desktop:dev
```

Keep this terminal open. `Fractonica node available` in the desktop status and
a scannable pairing QR mean the supervised node is ready. If startup fails, the
desktop status now includes the node's actual stderr (for example, a retained
profile lock) rather than only saying that the node is unavailable.

To pair two desktops, open **Pair devices** on the inviting desktop, create an
invitation, and copy its payload. On the joining desktop, open **Pair devices**,
paste the payload under **Join another node**, compare both five-digit glyphs
and all ten octal digits, then choose whether to merge pre-pair records into the
joined space or keep them separate. Both desktops must be on the same trusted
private network.

Create a release bundle with:

```sh
pnpm desktop:build
```

## Run the mobile application

The mobile app requires an Expo development build because the Fractonica
client is an autolinked native module. Expo Go is not supported.

```sh
pnpm install
rustup target add aarch64-apple-ios-sim x86_64-apple-ios aarch64-apple-ios
pnpm mobile:native:ios
pnpm --filter @fractonica/mobile run prebuild
pnpm mobile:ios
```

For a fresh Android checkout, install the Rust targets for Expo's four default
ABIs, run `pnpm mobile:native:android` before prebuild, then use
`pnpm mobile:android`:

```sh
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

The top-level platform commands rebuild their Rust artifacts on later runs.
After the development build is installed, run `pnpm mobile:start` to start
Metro. The linked native module owns identity, SQLite, signing, and the local
commit boundary; it never substitutes a JavaScript database or mock records.

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
