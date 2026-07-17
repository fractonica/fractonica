# ADR 0004: SQLite-first persistence

- Status: Accepted
- Date: 2026-07-17

## Context

The first Fractonica nodes run locally on desktop or as a single headless Linux
process. They need transactional durability, simple deployment, migration, and
backup without an external database service.

## Decision

SQLite is the default durable store. The node is its sole writer and applies
checked-in, ordered schema migrations inside controlled transactions. Database
configuration, migration state, backup, restore, and integrity verification are
operational features, not application-specific shortcuts.

The implementation uses SQLite-safe backup or snapshot mechanisms. P2P
replication operates on validated application messages and never replicates raw
SQLite pages or files.

Storage boundaries may be introduced where they improve testing or isolate
domain code, but Fractonica will not build a speculative lowest-common-
denominator abstraction for PostgreSQL. A managed service can add another
storage implementation after a separate ADR defines its concurrency,
consistency, migration, and operational requirements.

## Consequences

- A local or headless node remains a single-service deployment.
- Transactions, migrations, and backups can be tested deterministically.
- Horizontal multi-writer database scaling is not an initial capability.
- Long-running work must not hold write transactions unnecessarily.
