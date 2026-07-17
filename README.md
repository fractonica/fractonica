# Fractonica

Fractonica is a local-first personal data network. The current node owns its
local storage and exposes an OpenAPI-described loopback API. Pairing,
replication, and public-data publishing are planned but are not implemented
yet.

This repository is intentionally independent from Exeligmos. Legacy data will
later be imported through the same public node API used by external agents.

## Current milestone

The initial vertical slice provides:

- a Rust workspace with explicit core, temporal, storage, API, and executable boundaries;
- a dependency-free `no_std` temporal core suitable for constrained helpers;
- a portable, allocation-free C11 SDK for temporal pulse logic and glyph geometry;
- a migration-backed SQLite installation database;
- loopback-only liveness, readiness, node metadata, and Swagger endpoints;
- a stateless `saros` node profile for exact temporal readings and reviewed
  eclipse geometry without local storage;
- a React control center that can inspect the local node;
- a thin Tauri desktop shell that owns the node process lifecycle;
- architecture and protocol contracts for the next pairing and replication work.

## Run the node

```sh
cargo run -p fractonica-node
```

The standalone node listens on `http://127.0.0.1:8789` by default. The desktop
application uses a private random loopback port instead. Useful endpoints:

- `GET /health/live`
- `GET /health/ready`
- `GET /api/v1/node`
- `/api/docs`

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
