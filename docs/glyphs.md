# Canonical octal glyphs

Fractonica glyphs are a compact visual form of an MSB-first octal address.
They are part of the protocol surface, not application artwork: a pulse,
record, embedded display, server raster, and desktop interface must all mean
the same thing when they show the same glyph.

The normative grammar is
[`contracts/glyph/v1.json`](../contracts/glyph/v1.json). Its selected visual
form is the separately versioned
[`fractonica-hex-v2` font](../contracts/glyph/fonts/fractonica-hex-v2.json).
Generated constants in Rust, TypeScript, Swift, and C carry the grammar digest,
font digest, and combined specification digest. Do not edit generated files
directly.

The visual regression fixture is
[`fractonica-hex-v2-777777.svg`](../contracts/glyph/fixtures/fractonica-hex-v2-777777.svg):
it is the original depth-six `777777` rendering with frame
`-176 -200 352 400`. The default font preserves its authored core contour and
snaps arm endpoints to that contour; other supported depths derive a regular
core from the same font metrics.

```sh
node tools/glyph/generate-glyph-artifacts.mjs
node tools/glyph/generate-glyph-artifacts.mjs --check
```

## Digit grammar

Every octal digit is a three-bit mask laid on a rhombic lattice. The lattice
has a root **anchor** at the radial core and three outward destinations:
left, apex, and right. Each set bit turns on exactly one branch:

| Octal bit | Binary | Semantic connection |
| --- | --- | --- |
| `1` | `001` | anchor → left |
| `2` | `010` | anchor → apex |
| `4` | `100` | anchor → right |

The digit value is therefore the normal binary sum of its visible branches:

| Digit | Bits | Visible branches |
| --- | --- | --- |
| `0` | `000` | none |
| `1` | `001` | left |
| `2` | `010` | centre |
| `3` | `011` | left + centre |
| `4` | `100` | right |
| `5` | `101` | left + right |
| `6` | `110` | centre + right |
| `7` | `111` | left + centre + right |

`0` has no visible arm. In the default `fractonica-hex-v2` font, every non-zero
digit is one complete socket-local filled outline. Its visual branches are not
transported as separate `shaft`, `left`, `centre`, or `right` polygons. That
keeps the `1 | 2 | 4` grammar independent from the font used to depict it.

The vector plan contains two primitive kinds:

- `core` has an outer contour and an inner-hole contour and must be filled with
  the `evenodd` rule;
- `arm` has one contour, uses the `nonzero` rule, and carries its socket index,
  MSB-first digit index, and octal digit.

The core is emitted first, followed by one arm for each non-zero socket. Keeping
contours and fill rules explicit lets a tiny display use its polygon renderer
while a browser uses SVG or Canvas, without relying on implicit winding or
platform-specific line-cap behaviour.

## Address and socket order

Glyph input is strict ASCII octal and is always interpreted **MSB first**.
Depth is configurable from three through eight digits; five is the default.
Short inputs are left-padded; overlong input is rejected so an address prefix
is never silently discarded.

The radial sockets are ordered for a readable clock: socket zero carries the
most-significant digit, then sockets walk from the least-significant digit
back toward it. For a five-digit value `12345`, socket values are:

```text
socket:  0  1  2  3  4
digit:   1  5  4  3  2
```

This gives the fast-changing rightmost octal digit a stable radial location.
The Saros realtime pulse uses ten MSB-first digits displayed as two adjacent
five-digit glyphs.

## Coordinate and raster contract

Glyph geometry has its origin at the glyph centre. Positive X points right,
positive Y points down, and positive rotation is clockwise. Endpoint geometry
is expressed in the selected font's native units; the Rust `GlyphConfig.radius`
value is a scale multiplier for those units. Every plan returns a
value-invariant frame: changing `00000` to `77777` does not resize or shift its
view box.

The Rust core provides an allocation-free primitive callback and an
allocation-free, caller-buffer `RGBA8` rasterizer. Raw pixels are row-major,
straight alpha in `R, G, B, A` order; it uses a fixed 4×4 coverage grid for
deterministic antialiasing. The matching node endpoint is:

```text
GET /api/glyphs/{octal}/raster.rgba?depth=5&width=128&height=128
```

It returns `application/vnd.fractonica.rgba8` plus width, height, stride, pixel
format, grammar version, geometry version, and the font ID, version, and SHA-256
response headers. Use the geometry endpoint when a renderer needs to draw its
own vector form:

```text
GET /api/glyphs/{octal}/geometry?depth=5
```

The JSON geometry response repeats the grammar and font identity and returns
each primitive's fill rule and ordered contours. A consumer must preserve each
contour boundary; flattening the core's two contours into one polygon destroys
its aperture. See the OpenAPI explorer at `/api/docs` on a running node for the
exact schema and parameters.

## Adapters and conformance

The code generation step produces the shared numeric specification for:

- `fractonica-glyph`: no-std Rust geometry and raw pixel output;
- `@fractonica/glyph-core`: pure TypeScript geometry and Canvas 2D drawing;
- `@fractonica/glyph-react`: SVG React components, including the two-glyph
  Saros pulse pair;
- `sdk/swift/FractonicaGlyph`: Swift geometry plus `OctalGlyphView` for
  SwiftUI Canvas;
- `sdk/embedded-c`: dependency-free C11 polygon emitter for constrained
  devices.

The Rust, TypeScript, and Swift planners also accept data-only compatible font
objects. A custom font changes only outlines, metrics, frame spacing, and its
own identity; it cannot change parsing, MSB socket order, or digit semantics.
The bundled generated font carries the combined grammar-plus-font digest. A
custom font should carry its own source digest before its geometry is cached or
shared. The constrained C adapter deliberately links one generated font
catalogue at a time.

Each adapter tests the `1/2/4` mapping, MSB-first socket order, compound-core
fill rule, one-outline-per-arm contract, and value-invariant frame. The HTTP API
exposes separate grammar and font identities plus the combined specification
digest so an application can detect a semantic or visual mismatch before
caching or comparing geometry.
