# ADR 0002: Rust core with C++ ESP-IDF helpers

- Status: Accepted
- Date: 2026-07-17

## Context

Fractonica needs one deterministic implementation of domain and protocol
semantics, while constrained ESP-IDF targets may require vendor C/C++ APIs and
toolchains.

## Decision

Rust is the canonical implementation language for the core, node, validation,
persistence orchestration, and protocol state machines. C++ is allowed only in
narrow ESP-IDF helpers or firmware integration where it materially simplifies
hardware access.

C++ helpers consume versioned contracts and shared conformance vectors. They do
not independently define record semantics, authorization rules, persistence
formats, or compatibility policy. Any unavoidable duplicated parser or
validator must be tested against the same accepted and rejected fixtures as the
Rust implementation.

## Consequences

- Domain behavior has one primary source of truth.
- Hardware integrations can use mature ESP-IDF interfaces.
- Contract fixtures and cross-language tests are release requirements.
- Helper interfaces must stay small enough to audit and replace.
