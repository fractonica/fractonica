# Fractonica control center

Minimal React control surface for a local Fractonica node. It reads:

- `GET /health/ready`
- `GET /api/v1/node`

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
