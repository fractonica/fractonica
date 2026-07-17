# ADR 0005: Saros engine, phase words, and reviewed geometry

## Status

Accepted.

## Context

Fractonica needs one temporal system that can run in a server, desktop node,
browser adapter, and constrained helper. The legacy implementations used a
mix of floating-point clock calculations, fixed display depths, and separate
eclipse-path assets. That makes exact flip behaviour and cross-platform
conformance difficult.

The project also has a manually reviewed compact solar-eclipse path corpus for
Saros series 101 through 161. Geometry is important engine data, but it must
not make a clock-only helper allocate or ship a multi-megabyte catalogue.

## Decision

The public Saros engine is layered:

1. `fractonica-temporal-core` owns deterministic, allocation-free temporal
   arithmetic. It has no filesystem, HTTP, database, clock, or geometry
   dependency.
2. `fractonica-saros-geo` validates and reads immutable compact eclipse-path
   assets.
3. `fractonica-saros-engine` composes a temporal interval with an optional
   eclipse/geometry catalogue and is the only domain facade used by the node
   API.

### Phase representation

The source of truth for a reading is an exact ratio:

```text
phase = elapsed_since_previous_eclipse / interval_duration
```

Both values use integral nanoseconds. Intervals are half-open:

```text
[previous_eclipse, next_eclipse)
```

The engine derives `PhaseWord64`, an MSB-first Q0.64 fixed-point projection:

```text
floor(phase * 2^64)
```

Any prefix from one through 64 bits is available without recalculation. Octal
is a presentation projection: every complete octal digit consumes three
MSB-first bits. Therefore the existing pulse is a 30-bit projection rendered
as two five-digit glyphs. A 32-bit projection contains ten complete octal
digits plus two residual bits.

The exact ratio can stream further octal digits into a caller-provided buffer;
there is no semantic display-depth cap. HTTP endpoints still impose a bounded
response length. More digits never imply accuracy beyond the source eclipse
timestamps.

Rarity and named Saros periods operate only on complete three-bit groups.
They must always state their evaluated octal precision. Glyphs use MSB-first
digits; the least-significant five-digit half must never be substituted for
the leading glyph or rarity context.

### Geometry

Fractonica ships `reviewed-101-161.eclp`, a versioned `ECLP` v1 compact asset
with an adjacent JSON manifest. The release includes exactly Saros 101–161,
2,044 eclipse records, and 276,576 reviewed path points. A request outside
that scope receives an explicit geometry-unavailable result; it must not be
silently approximated.

Geometry is joined to a canonical eclipse by series and greatest-eclipse UTC
instant. A node lazily reads the required series/record and does not inflate
the complete corpus. Embedded targets use a bounded callback iterator over a
selected generated bundle rather than a heap-owning object graph.

### API

The API is read-only and deterministic. Public calculation routes require an
explicit instant; a future convenience `now` route samples the clock once and
returns that sampled instant. Responses carry the Saros semantics version and
the geometry asset identifier/hash where geometry participates.

Outside coverage is a domain error, never edge-interval extrapolation. Exact
eclipse timestamps resolve to the following interval when one exists.

## Consequences

- Rust, C, TypeScript, and future Swift bindings share conformance vectors.
- The standalone `saros` node profile can run without SQLite or an account.
- Clock-only helpers remain small; nodes can opt into geometry.
- The legacy `saros-geo` source format remains an import format. The checked-in
  Fractonica manifest gives a stable release identity while the original
  curation pipeline is preserved separately.
