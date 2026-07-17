# Fractonica Desktop

The desktop application is a thin Tauri supervisor around the same
`fractonica-node` binary used by headless installations. It bundles the
control-center web application, starts the node as a sidecar, and terminates
the child process when the desktop application exits.

From the repository root:

```sh
pnpm desktop:dev
```

The preparation script builds the node and copies it to Tauri's target-specific
sidecar path. Generated binaries are never committed.

Cross-target builds propagate `--target <triple>` to both Cargo and Tauri:

```sh
rustup target add aarch64-apple-darwin x86_64-apple-darwin
pnpm --filter @fractonica/desktop bundle -- --target x86_64-apple-darwin
```

`universal-apple-darwin` builds both architectures and combines their node
sidecars with `lipo`. The preparation script reads Cargo metadata, so a custom
`CARGO_TARGET_DIR` is respected.

Every desktop launch starts its child on an operating-system-assigned loopback
port. The node publishes that endpoint through a private readiness file and
requires a fresh bearer token handed directly from Tauri to the control center.
The token is never placed in a URL or process argument. This bootstrap channel
is local process supervision, not the future device-pairing protocol.
