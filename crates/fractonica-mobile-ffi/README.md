# Fractonica mobile FFI

This crate is the only Rust API exported to Swift and Kotlin. It converts
bounded mobile DTOs into canonical Fractonica domain values and owns one
long-lived native client runtime. It does not expose identity material,
filesystem paths, SQLite handles, signed envelopes, or attachment bytes to
JavaScript.

Bindings are generated from the host library with the repository-pinned
`fractonica-uniffi-bindgen` tool. Do not install or invoke an unrelated global
`uniffi-bindgen`; generated code and Rust scaffolding must use the exact same
UniFFI version.
