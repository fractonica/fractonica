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

The node is the authority for its installation. It is the only component that
may write its SQLite database, access long-lived identity material, enforce
policy, or open network listeners. Helpers are replaceable, least-privileged
processes: they receive only the capability and bounded input required for one
job, and return a bounded result.

The standalone HTTP API listens only on `http://127.0.0.1:8789` by default.
The desktop supervisor instead assigns a random loopback port and a fresh
per-launch bearer token, then passes the verified endpoint to its webview over
Tauri's invoke boundary. Binding to a non-loopback interface is prohibited
until device pairing and authentication are specified and implemented. Network
input, helper output, and replicated data are untrusted until the node validates
them.

## Persistence and replication

SQLite is the initial durable store for desktop and headless nodes. The node
applies checked-in, ordered migrations and serializes writes through its
persistence layer. Backup and restore must use SQLite-safe mechanisms rather
than copying an active database opportunistically.

Replication belongs to the application protocol. Fractonica never treats raw
SQLite pages or database files as a replication format. A managed deployment
may add another storage implementation only after its operational and
consistency requirements are captured in a new ADR.

## Compatibility and releases

Public HTTP descriptions are checked in under `contracts/openapi`. Device
messages use explicit versions and hard bounds. Breaking changes require a new
contract version and a rollout plan; implementations must reject unsupported
versions predictably instead of guessing.

Cryptographic algorithms, key lifecycle, canonical signing bytes, and pairing
are intentionally not selected here. They require a threat model and a
dedicated security decision before any public network exposure.
