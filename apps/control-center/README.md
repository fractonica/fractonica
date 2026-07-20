# Fractonica control center

React control surface for a local Fractonica node. It reads:

- `GET /health/ready`
- `GET /api/node`

For a full node it also drives the loopback pairing administration routes:

- `POST /api/pairing/invitations`
- `GET` and `DELETE /api/pairing/invitations/{invitationId}`
- `POST /api/pairing/invitations/{invitationId}/confirm`

The invitation view renders the canonical QR payload. Once a joining client
claims it, the UI displays the complete confirmation as two five-digit,
MSB-first octal glyphs and issues the bounded capability only after explicit
local confirmation. The QR secret is retained only in component memory and is
discarded from the UI as soon as the invitation leaves `created`.

It validates the reported profile from both endpoints before rendering. The
`node` profile reports ready SQLite storage and its schema version; the
stateless `saros` profile reports that no local storage is configured.

The node base URL comes from `VITE_FRACTONICA_NODE_URL` and defaults to
`http://127.0.0.1:8789`.

```sh
pnpm --filter @fractonica/control-center dev
pnpm --filter @fractonica/control-center test
pnpm --filter @fractonica/control-center build
```

The UI polls every 15 seconds and also checks again when the browser regains
connectivity or the page becomes visible. A five-second request timeout moves
the surface into its retryable offline state.

Pairing does not relax the listener boundary: the node remains loopback-only,
and the UI says so. LAN discovery and peer transport are a later protocol.
