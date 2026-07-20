# Architecture

## Purpose

Fractonica is a local-first personal data network. A node owns a user's local
data and makes it available to trusted applications and, eventually, paired
peers. The first implementation targets desktop and headless Linux nodes while
leaving explicit boundaries for mobile and constrained devices.

## System layers

1. **Contracts** define versioned HTTP and device-facing interfaces. They are
   reviewed independently of any implementation language.
2. **Rust core** owns canonical domain semantics, validation, protocol rules,
   migrations, and persistence orchestration.
3. **Node process** owns durable state, identity material, policy enforcement,
   network listeners, and helper lifecycle.
4. **Helpers and adapters** connect the node to operating-system or device
   facilities through narrow, bounded interfaces. The Apache-2.0 Embedded C
   SDK supplies allocation-free temporal and glyph primitives; C++ is
   permitted at the ESP-IDF boundary, but does not define a second domain
   model.
5. **Applications** such as Tauri/React desktop, headless administration, and
   future mobile clients consume node contracts rather than bypassing them.

The Rust core and public contracts are the semantic source of truth. Every
other implementation is checked against shared conformance fixtures.

## Process and trust boundaries

The node is the local admission and policy authority for its installation. It
is the only component that may write its SQLite database, request use of
long-lived identity material, enforce accepted space capabilities, or open
network listeners. Operation authorship belongs to an actor key, not to the
installation or database process. Helpers are replaceable, least-privileged
processes: they receive only the capability and bounded input required for one
job, and return a bounded result.

The standalone HTTP API listens only on `http://127.0.0.1:8789` by default.
The desktop supervisor instead assigns a random loopback port and a fresh
per-launch bearer token, then passes the verified endpoint to its webview over
Tauri's invoke boundary. Binding to a non-loopback interface is prohibited
until device pairing and authentication are specified and implemented. Network
input, helper output, and replicated data are untrusted until the node validates
them.

The cryptographic trust kernel distinguishes local `InstallationId`, transport
`NodeId`, authorization namespace `SpaceId`, and signing `ActorId`. Version 2
operations are a deterministic-CBOR Merkle DAG signed with COSE Sign1/Ed25519.
Signature validity is necessary but not sufficient: an operation also requires
a space capability chain. See the [threat model](threat-model.md),
[signed-operation ADR](adr/0009-signed-operation-trust-kernel.md), and
[capability/pairing ADR](adr/0010-space-capabilities-and-pairing.md).

The full profile binds three trust-critical units into one installation: the
SQLite database, protected `identity/` directory, and public
`installation.json`. First run publishes
`installation.identity.pending.json` before the keystore writes anything, so
an interrupted identity bootstrap resumes the same protected directory.
Before SQLite is created, `installation.pending.json` stores the exact signed
genesis and initial writer grant; an interrupted first run can replay those
same bytes but can never generate a lookalike anchor. Staged state publication
is recoverable both immediately before and after its atomic no-replace link. The
completed manifest contains no private keys, but retains that signed bootstrap
and pins the exact node, default space, controller, and writer identities. The
node refuses replacement when an established database or identity half is
missing or disagrees with the manifest.

The `content/` tree is independently addressable availability data rather than
part of operation validity: deleting it loses this node's local media bytes but
does not alter signed resource references. A complete personal-data backup
therefore still moves the entire stopped data directory, while the trust kernel
specifically requires the matching database, identity, and installation
manifest.

## Persistence and replication

SQLite is the initial durable store for desktop and headless nodes. The node
applies checked-in, ordered migrations and serializes writes through its
persistence layer. Backup and restore must use SQLite-safe mechanisms rather
than copying an active database opportunistically. The raw `FileKeyStore`
backend is intentionally Unix-only because its guarantees rely on Unix owner,
mode, hard-link, and no-follow semantics. It does not prove that a macOS or
network filesystem has no extended ACL, so it is currently a single-user local
backend; desktop production releases must use Keychain or another reviewed
platform store. Windows support requires a protected
Credential Manager/DPAPI or equivalently reviewed backend; weakening these
checks is not a portability strategy.

Replication belongs to the application protocol. Fractonica never treats raw
SQLite pages or database files as a replication format. A managed deployment
may add another storage implementation only after its operational and
consistency requirements are captured in a new ADR.

The future replication unit is a verified signed operation and, independently,
its immutable content resources. This statement does not enable replication:
peer discovery, graph exchange, revocation races, and transport security still
require a dedicated protocol decision.

## Compatibility and releases

Public HTTP descriptions are checked in under `contracts/openapi`. Device
messages use explicit versions and hard bounds. Breaking changes require a new
contract version and a rollout plan; implementations must reject unsupported
versions predictably instead of guessing. Because Fractonica is pre-release,
operation protocol version 2 intentionally replaces unsigned version 1 without
a dual-read compatibility mode; migration re-encodes and signs logical data.
The v2 space-scoped operation routes are the primary stateful API. The old v1
operation and entity routes return `410`, while stateless Saros/glyph and
loopback content-transfer mechanics remain on v1 until their respective
contracts advance.

Ed25519 actor and node identities, SHA-256 operation IDs, deterministic CBOR,
COSE Sign1, capability semantics, and the QR bootstrap boundary are selected by
the Phase 3 security decisions. Local trusted-space bootstrap, capability
grants, revocations, and v2 write admission are implemented. The authenticated
Noise pairing handshake, local QR/confirmation UI, controller-signed grant
issuance, and dual-signed `readSpace` change pages with durable replay
protection are implemented on loopback. Space-authorized content transfer,
payload encryption, replication, and non-loopback exposure remain
unimplemented and prohibited.
