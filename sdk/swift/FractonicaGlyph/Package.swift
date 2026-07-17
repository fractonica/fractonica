// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "FractonicaGlyph",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "FractonicaGlyph", targets: ["FractonicaGlyph"]),
    ],
    targets: [
        .target(name: "FractonicaGlyph"),
        .testTarget(name: "FractonicaGlyphTests", dependencies: ["FractonicaGlyph"]),
    ],
)
