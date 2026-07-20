# `@fractonica/glyph-react-native`

React Native SVG components for the canonical Fractonica octal glyph plan.
The package contains no glyph grammar of its own; it renders geometry produced
by `@fractonica/glyph-core`, preserving the same MSB-first socket order and
versioned default font used by the web, Rust, and embedded adapters.

The mobile application must include `react-native-svg` in its native build.
