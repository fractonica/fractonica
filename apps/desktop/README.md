# Fractonica Desktop

The desktop application owns two native services behind a thin Tauri command
boundary:

- the same `fractonica-node` binary used by headless installations, supervised
  as a sidecar; and
- `fractonica-client-runtime`, which owns the local client database, private
  content store, writer key custody, local operation authoring, and background
  synchronization.

The React webview never receives private keys, SQLite handles, or filesystem
paths. Local writes cross narrow semantic commands, return after the signed
operation is durable in client SQLite, and synchronize independently of UI
lifecycle or network latency.

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

The runtime uses separate directories below Tauri's platform application-data
directory:

```text
node/    protected node identity, node SQLite, and node content
client/  client SQLite and the private client content store
```

On first launch the runtime adopts the writer identity and signed default-space
trust anchors already established by the bundled node. It verifies that the
node metadata, protected key material, signed genesis operation, and initial
writer grant agree before opening synchronization. It does not mint a second
desktop account.

## Native command boundary

The current Tauri commands expose:

- `client_status` for lifecycle, operation queue, and resource progress;
- create and update commands for records, events, and tags;
- `client_put_profile`;
- `client_delete`;
- `client_list` for bounded local projection summaries;
- `client_list_records` for one-query timeline summaries with editable public
  documents and opaque private entries; and
- `client_import_attachments` for native selection and content-addressed import
  without exposing selected paths or file bytes to the webview.

The desktop opens directly into the Records workspace. It supports public
record creation, editing, local deletion, local-time start/end fields,
structured metadata, and synchronization progress. Existing attachments and
references are retained during edits. Users can add or remove up to 64 record
attachments; import, SHA-256 derivation, private storage, and deduplication run
off the UI thread. Private-record decryption remains a separate upcoming native
boundary.

`node_connection` remains temporarily available to the existing control-center
screens that inspect node and system APIs directly. Application data editing
should use the client commands; a node response is never the local-save success
boundary.

The sidecar and synchronization worker receive explicit cancellation when the
application exits. An unexpected sidecar exit removes the live client runtime
and is surfaced through `client_status` instead of silently leaving a stale
ready state.

Client directories are mode `0700` and client SQLite, WAL, and shared-memory
files are mode `0600` on Unix platforms.
