# Fractonica architecture documentation

Fractonica is a local-first personal data network. This directory records the
system boundaries and the decisions that implementations must preserve.

The current stateful contract is the signed, space-scoped operation protocol.
Capability grants and revocations are enforced for operation admission. The first
loopback-only Noise pairing ceremony is implemented through explicit human
confirmation. Confirmation atomically converges on one controller-signed
capability grant, and the local control center renders its QR and complete
two-glyph confirmation. Non-loopback transport, actor-authenticated reads, and
space-authorized content transfer remain deferred.

- [Architecture](architecture.md)
- [Trust-kernel threat model](threat-model.md)
- [Signed causal operation log](operation-log.md)
- [Content-addressed storage](content-storage.md)
- [Self-hosting and local operation](self-hosting.md)
- [Eclipse data provenance](data-provenance.md)
- [Saros engine](saros-engine.md)
- [Canonical octal glyphs](glyphs.md)
- [Signed, space-scoped HTTP API](signed-operation-api.md)
- [Client core and local-first write path](client-core.md)
- [ADR 0014: React Native mobile client boundary](adr/0014-react-native-mobile-client.md)
- [ADR 0001: Use a monorepo](adr/0001-monorepo.md)
- [ADR 0002: Rust core with C++ ESP-IDF helpers](adr/0002-rust-core-cpp-esp-idf-helpers.md)
- [ADR 0003: Node and helper process boundary](adr/0003-node-helper-boundary.md)
- [ADR 0004: SQLite-first persistence](adr/0004-sqlite-first.md)
- [ADR 0005: Saros engine, phase words, and reviewed geometry](adr/0005-saros-engine.md)
- [ADR 0006: Versioned canonical octal glyph grammar](adr/0006-canonical-octal-glyphs.md)
- [ADR 0007: Canonical causal operation log](adr/0007-causal-operation-log.md)
- [ADR 0008: Content-addressed resources](adr/0008-content-addressed-resources.md)
- [ADR 0009: Signed operation trust kernel](adr/0009-signed-operation-trust-kernel.md)
- [ADR 0010: Space capabilities and QR pairing boundary](adr/0010-space-capabilities-and-pairing.md)
- [ADR 0011: Noise pairing handshake](adr/0011-noise-pairing-handshake.md)
- [ADR 0012: Authenticated peer reads](adr/0012-authenticated-peer-reads.md)
- [ADR 0013: Client domain and projections](adr/0013-client-domain-and-projection-contract.md)
- [OpenAPI API contract](../contracts/openapi/api.yaml)
- [OpenAPI foundation contract](../contracts/openapi/services.yaml)
- [Device protocol principles](../contracts/protocol/README.md)

Architecture changes that alter a trust boundary, public contract, persistence
model, or cross-platform semantic rule require an ADR and matching contract or
conformance updates.
