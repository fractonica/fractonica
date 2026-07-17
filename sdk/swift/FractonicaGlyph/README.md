# FractonicaGlyph

`FractonicaGlyph` is the Swift and SwiftUI adapter for Fractonica's canonical
octal glyph grammar. It reads generated constants from the semantic
[`contracts/glyph/v1.json`](../../../contracts/glyph/v1.json) and the selected
[`fractonica-hex-v2` font](../../../contracts/glyph/fonts/fractonica-hex-v2.json),
the same source consumed by the Rust engine, browser packages, and embedded C
SDK.

```swift
import FractonicaGlyph

let glyph = try OctalGlyph("72444", depth: 5)
let plan = try glyph.plan()
// SwiftUI:
// OctalGlyphView(plan: plan, foreground: .cyan)
```

`GlyphFont.default` is the generated Hex v2 visual font. You can pass a
validated custom `GlyphFont` to `glyph.plan(font:)`; this changes contours and
font metadata only. Strict MSB-first octal parsing, socket order, and the
semantic `1 | 2 | 4` digit grammar remain invariant.

Run its conformance tests from this folder:

```sh
swift test
```
