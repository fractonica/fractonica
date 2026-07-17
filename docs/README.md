# Fractonica architecture documentation

Fractonica is a local-first personal data network. This directory records the
system boundaries and the decisions that implementations must preserve.

- [Architecture](architecture.md)
- [Self-hosting and local operation](self-hosting.md)
- [Eclipse data provenance](data-provenance.md)
- [Saros engine](saros-engine.md)
- [ADR 0001: Use a monorepo](adr/0001-monorepo.md)
- [ADR 0002: Rust core with C++ ESP-IDF helpers](adr/0002-rust-core-cpp-esp-idf-helpers.md)
- [ADR 0003: Node and helper process boundary](adr/0003-node-helper-boundary.md)
- [ADR 0004: SQLite-first persistence](adr/0004-sqlite-first.md)
- [ADR 0005: Saros engine, phase words, and reviewed geometry](adr/0005-saros-engine.md)
- [OpenAPI v1 contract](../contracts/openapi/v1.yaml)
- [Device protocol principles](../contracts/protocol/README.md)

Architecture changes that alter a trust boundary, public contract, persistence
model, or cross-platform semantic rule require an ADR and matching contract or
conformance updates.
