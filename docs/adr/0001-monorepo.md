# ADR 0001: Use a monorepo

- Status: Accepted
- Date: 2026-07-17

## Context

Fractonica spans a Rust core and node, desktop and headless applications,
device helpers, public contracts, migrations, and conformance fixtures. A
protocol change often requires coordinated updates across several of these
parts.

## Decision

Keep product source, contracts, tests, migrations, and architecture documents
in one repository. Cross-component changes are reviewed and tested atomically.
Directories remain independently buildable, and dependency direction follows
the layers in the architecture document.

Production infrastructure and managed-service operations may live elsewhere
when their access controls or release cadence require a separate trust
boundary. Their externally consumed contracts remain versioned here.

## Consequences

- Contract changes can ship with all affected implementations and fixtures.
- Repository-wide checks can detect semantic drift between platforms.
- Ownership and CI must avoid rebuilding unrelated targets unnecessarily.
- Directory boundaries must remain explicit so the repository does not become
  one inseparable application.
