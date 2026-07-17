# Contributing

Fractonica is being built contract-first. Changes should preserve the boundary
between deterministic domain logic and replaceable storage, transport, UI, and
device adapters.

## Development

Install the Rust toolchain declared in `rust-toolchain.toml`, Node.js 24 or
newer, and pnpm 11. Then run the validation commands documented in `README.md`.

Please include tests for behavior changes. Protocol, temporal, persistence, and
cryptographic changes additionally require conformance vectors or an ADR. Do
not introduce a network listener, signing format, key lifecycle, or pairing
flow without a documented threat model.

Never commit user databases, media, credentials, signing keys, `.env` files, or
production configuration. Fixtures must be synthetic and explicitly licensed.
