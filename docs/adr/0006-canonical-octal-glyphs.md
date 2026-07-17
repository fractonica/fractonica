# ADR 0006: Versioned canonical octal glyph grammar

## Status

Accepted

## Context

Glyphs encode temporal addresses and are visible on web, iOS, desktop, API,
and constrained helper devices. Recreating them separately from screenshots or
each platform's line-drawing APIs would eventually create incompatible visual
addresses.

## Decision

Define the semantic `1 | 2 | 4` rhombic-lattice grammar in
`contracts/glyph/v1.json`, independently from visual fonts. Store the selected
default font in `contracts/glyph/fonts/fractonica-hex-v2.json`; its own ID,
semantic version, geometry version, and SHA-256 digest identify the visual
outlines. Generate adapter constants from both documents.

The Rust `fractonica-glyph` crate is the canonical host implementation and
offers both allocation-free geometry emission and caller-buffer RGBA8 output.
Its public vector plan uses compound primitives: the core has outer and inner
contours with even-odd filling, while each visible digit arm has one contour
with non-zero filling. Contour boundaries and fill rules are protocol data and
must not be inferred by clients.

Client adapters may render locally for offline responsiveness, but they must
consume generated spec constants and retain conformance tests for the binary
stroke mapping, MSB-first socket order, compound fill behavior, and stable
frame. The node exposes separate grammar and font identities, normalized
compound geometry, and raw raster bytes for integration and diagnostics.

## Consequences

- Grammar changes are protocol changes and require a new grammar version. A
  visual outline change that preserves the grammar requires a new font or font
  version and digest; it must not silently change an existing font document.
- The code generator check is part of workspace validation, preventing stale
  generated constants from landing.
- A platform can have its own renderer while retaining exactly the same semantic
  input and polygon coordinates.
- The server raster is an interoperability escape hatch, not a replacement for
  local rendering on latency- or privacy-sensitive clients.
