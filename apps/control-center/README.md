# Fractonica control center

React surface shared by the browser control center and Fractonica Desktop.
The browser surface can inspect and administer a local node. The desktop
surface additionally uses narrow Tauri commands to access the native
local-first client.

The node views read:

- `GET /health/ready`
- `GET /api/node`

For a full node it also drives the loopback pairing administration routes:

- `POST /api/pairing/invitations`
- `GET` and `DELETE /api/pairing/invitations/{invitationId}`
- `POST /api/pairing/invitations/{invitationId}/confirm`
- `GET /api/pairing/devices`
- `DELETE /api/pairing/devices/{invitationId}`

The invitation view renders the canonical QR payload. Once a joining client
claims it, the UI displays the complete confirmation as two five-digit,
MSB-first octal glyphs and issues the bounded capability only after explicit
local confirmation. The QR secret is retained only in component memory and is
discarded from the UI as soon as the invitation leaves `created`.
Completed sessions form the paired-device registry. The UI reports recent
authenticated activity as online and revokes access by admitting a
controller-signed `capability.revoke` operation; revoked rows remain visible
as an audit trail.

It validates the reported profile from both endpoints before rendering. The
`node` profile reports ready SQLite storage and its schema version; the
stateless `saros` profile reports that no local storage is configured.

The node base URL comes from `VITE_FRACTONICA_NODE_URL` and defaults to
`http://127.0.0.1:8789`.

Inside Tauri, Records is the default workspace. It lists public or opaque
private records from client SQLite, creates and edits public records, preserves
existing resources and entity references during edits, imports or removes
record attachments, performs two-step local deletion, and displays compact
operation/resource synchronization status. File selection, hashing, and
content-store import stay native; the webview receives only validated
content-addressed resource references, never keys, database handles,
filesystem paths, or file bytes. A normal browser intentionally shows a
desktop-required explanation instead of pretending it has access to native
client storage.

```sh
pnpm --filter @fractonica/control-center dev
pnpm --filter @fractonica/control-center test
pnpm --filter @fractonica/control-center build
```

The UI polls every 15 seconds and also checks again when the browser regains
connectivity or the page becomes visible. A five-second request timeout moves
the surface into its retryable offline state.

The desktop keeps its control URL and bootstrap bearer private while exposing
only the pairing/data plane on an explicitly selected private-LAN address.
Public listener exposure remains unsupported.
