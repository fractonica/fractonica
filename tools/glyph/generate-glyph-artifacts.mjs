#!/usr/bin/env node

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const root = resolve(scriptDirectory, "../..");
const grammarPath = resolve(root, "contracts/glyph/v1.json");
const checkOnly = process.argv.includes("--check");

const grammarRaw = await readFile(grammarPath, "utf8");
const grammar = JSON.parse(grammarRaw);
validateGrammar(grammar);

const fontPath = resolve(dirname(grammarPath), grammar.defaultFont.source);
const fontRaw = await readFile(fontPath, "utf8");
const font = JSON.parse(fontRaw);
validateFont(grammar, font);
await validateReferenceFixture(fontPath, font);

const grammarDigest = sha256(grammarRaw);
const fontDigest = sha256(fontRaw);
const sourceDigest = sha256(`${grammarRaw}\u0000${fontRaw}`);
const maxArmPoints = Math.max(...font.arms.map((arm) => arm.points.length));
const outputs = new Map([
  [
    resolve(root, "crates/fractonica-glyph/src/spec_generated.rs"),
    rustOutput(grammar, font, { grammarDigest, fontDigest, sourceDigest, maxArmPoints }),
  ],
  [
    resolve(root, "packages/glyph-core/src/spec.generated.ts"),
    typeScriptOutput(grammar, font, { grammarDigest, fontDigest, sourceDigest }),
  ],
  [
    resolve(
      root,
      "sdk/swift/FractonicaGlyph/Sources/FractonicaGlyph/GlyphSpec.generated.swift",
    ),
    swiftOutput(grammar, font, { grammarDigest, fontDigest, sourceDigest }),
  ],
  [
    resolve(root, "sdk/embedded-c/include/fractonica/embedded/glyph_spec.generated.h"),
    cOutput(grammar, font, { grammarDigest, fontDigest, sourceDigest, maxArmPoints }),
  ],
]);

let outOfDate = false;
for (const [path, content] of outputs) {
  let current = null;
  try {
    current = await readFile(path, "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  if (current === content) continue;
  outOfDate = true;
  if (!checkOnly) await writeFile(path, content, "utf8");
  console.error(`${checkOnly ? "out of date" : "generated"}: ${path}`);
}

if (checkOnly && outOfDate) process.exitCode = 1;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function validateGrammar(value) {
  if (value.radix !== 8) throw new Error("glyph grammar must use octal radix 8");
  if (value.digits.minimum !== 3 || value.digits.maximum !== 8 || value.digits.default !== 5) {
    throw new Error("glyph grammar depth contract must remain 3...8 with default 5");
  }
  if (
    !Array.isArray(value.strokeBits) ||
    value.strokeBits.length !== 3 ||
    value.strokeBits.map((stroke) => stroke.bit).join(",") !== "1,2,4"
  ) {
    throw new Error("glyph grammar must define the canonical 1, 2, 4 stroke bits");
  }
  if (!value.defaultFont || typeof value.defaultFont.source !== "string") {
    throw new Error("glyph grammar must name a default font source");
  }
}

function validateFont(grammarValue, value) {
  if (value.id !== grammarValue.defaultFont.id) {
    throw new Error("glyph font id must match grammar.defaultFont.id");
  }
  if (value.fontVersion !== grammarValue.defaultFont.version) {
    throw new Error("glyph font version must match grammar.defaultFont.version");
  }
  if (value.geometryVersion !== grammarValue.defaultFont.geometryVersion) {
    throw new Error("glyph font geometry version must match grammar.defaultFont.geometryVersion");
  }
  if (value.grammarVersion !== grammarValue.grammarVersion) {
    throw new Error("glyph font must declare compatibility with this grammar version");
  }
  for (const [name, number] of Object.entries({
    units: value.units,
    socketWidth: value.core?.socketWidth,
    coreRadius: value.core?.coreRadius,
    insetThickness: value.core?.insetThickness,
    gridSize: value.renderer?.gridSize,
    paddingCells: value.renderer?.paddingCells,
  })) {
    if (typeof number !== "number" || !Number.isFinite(number) || number <= 0) {
      throw new Error(`glyph font ${name} must be a finite positive number`);
    }
  }
  const outer = value.core?.legacyExactOuter;
  const hole = value.core?.legacyExactHole;
  if (!Number.isInteger(outer?.depth) || !Array.isArray(outer?.points) || outer.points.length < 3) {
    throw new Error("glyph font must provide a valid exact core-outer outline");
  }
  if (!Number.isInteger(hole?.depth) || !Array.isArray(hole?.points) || hole.points.length < 3) {
    throw new Error("glyph font must provide a valid exact core-hole outline");
  }
  if (!Array.isArray(value.arms) || value.arms.length !== grammarValue.radix) {
    throw new Error("glyph font must provide exactly one arm outline per octal digit");
  }
  value.arms.forEach((arm, index) => {
    if (arm.digit !== index || !Array.isArray(arm.points) || arm.points.length < 2) {
      throw new Error(`glyph font arm ${index} must provide its ordered socket-local outline`);
    }
    validatePoints(arm.points, `glyph font arm ${index}`);
  });
  validatePoints(outer.points, "glyph font exact core outer");
  validatePoints(hole.points, "glyph font exact core hole");
}

async function validateReferenceFixture(fontPathValue, value) {
  const fixture = value.provenance?.referenceFixture;
  if (fixture == null) return;
  if (typeof fixture !== "string" || !fixture.startsWith(".")) {
    throw new Error("glyph font referenceFixture must be a relative repository path when present");
  }
  const fixturePath = resolve(dirname(fontPathValue), fixture);
  const source = await readFile(fixturePath, "utf8");
  if (!source.includes("<svg") || !source.includes("viewBox")) {
    throw new Error("glyph font referenceFixture must be an SVG with a viewBox");
  }
}

function validatePoints(points, name) {
  points.forEach((point, index) => {
    if (!Array.isArray(point) || point.length !== 2 || !point.every(Number.isFinite)) {
      throw new Error(`${name} point ${index} must be a finite [x, y] tuple`);
    }
  });
}

function sourceBanner(comment, digests) {
  const lines = [
    `Generated by tools/glyph/generate-glyph-artifacts.mjs from contracts/glyph/v1.json and contracts/glyph/fonts/${digests.fontFile}.`,
    `Grammar SHA-256: ${digests.grammarDigest}`,
    `Font SHA-256: ${digests.fontDigest}`,
    `Combined SHA-256: ${digests.sourceDigest}`,
    "Do not edit by hand.",
  ];
  if (comment === "//") return `${lines.map((line) => `// ${line}`).join("\n")}\n\n`;
  return `/* ${lines.join("\n * ")} */\n\n`;
}

function number(value, suffix = "") {
  const text = Number(value).toString();
  return text.includes(".") ? `${text}${suffix}` : `${text}.0${suffix}`;
}

function rustPoint(point, indent = "    ") {
  return `${indent}GlyphPoint::new(${number(point[0])}, ${number(point[1])}),`;
}

function rustArm(arm, maxArmPoints) {
  const padded = [...arm.points];
  while (padded.length < maxArmPoints) padded.push([0, 0]);
  return `    [\n${padded.map((point) => rustPoint(point, "        ")).join("\n")}\n    ],`;
}

function rustOutput(grammarValue, fontValue, digests) {
  const source = { ...digests, fontFile: grammarValue.defaultFont.source.split("/").at(-1) };
  return `${sourceBanner("//", source)}use super::GlyphPoint;

pub const GRAMMAR_VERSION: &str = "${grammarValue.grammarVersion}";
pub const GEOMETRY_VERSION: &str = "${fontValue.geometryVersion}";
pub const FONT_ID: &str = "${fontValue.id}";
pub const FONT_VERSION: &str = "${fontValue.fontVersion}";
pub const GRAMMAR_SHA256: &str = "${digests.grammarDigest}";
pub const FONT_SHA256: &str = "${digests.fontDigest}";
pub const SPEC_SHA256: &str = "${digests.sourceDigest}";
pub const RADIX: u8 = ${grammarValue.radix};
pub const MIN_DIGITS: u8 = ${grammarValue.digits.minimum};
pub const MAX_DIGITS: u8 = ${grammarValue.digits.maximum};
pub const DEFAULT_DIGITS: u8 = ${grammarValue.digits.default};
pub const STROKE_LEFT: u8 = ${grammarValue.strokeBits[0].bit};
pub const STROKE_CENTRE: u8 = ${grammarValue.strokeBits[1].bit};
pub const STROKE_RIGHT: u8 = ${grammarValue.strokeBits[2].bit};
pub const FONT_UNITS: f32 = ${number(fontValue.units)};
pub const FONT_SOCKET_WIDTH: f32 = ${number(fontValue.core.socketWidth)};
pub const FONT_CORE_RADIUS: f32 = ${number(fontValue.core.coreRadius)};
pub const FONT_INSET_THICKNESS: f32 = ${number(fontValue.core.insetThickness)};
pub const FONT_GRID_SIZE: f32 = ${number(fontValue.renderer.gridSize)};
pub const FONT_PADDING_CELLS: f32 = ${number(fontValue.renderer.paddingCells)};
pub const FONT_LEGACY_OUTER_DEPTH: u8 = ${fontValue.core.legacyExactOuter.depth};
pub const FONT_LEGACY_HOLE_DEPTH: u8 = ${fontValue.core.legacyExactHole.depth};
pub const MAX_FONT_ARM_POINTS: usize = ${digests.maxArmPoints};

pub const FONT_LEGACY_OUTER: [GlyphPoint; ${fontValue.core.legacyExactOuter.points.length}] = [
${fontValue.core.legacyExactOuter.points.map((point) => rustPoint(point)).join("\n")}
];
pub const FONT_LEGACY_HOLE: [GlyphPoint; ${fontValue.core.legacyExactHole.points.length}] = [
${fontValue.core.legacyExactHole.points.map((point) => rustPoint(point)).join("\n")}
];
pub const FONT_ARM_POINT_COUNTS: [u8; ${grammarValue.radix}] = [${fontValue.arms.map((arm) => arm.points.length).join(", ")}];
pub const FONT_ARMS: [[GlyphPoint; MAX_FONT_ARM_POINTS]; ${grammarValue.radix}] = [
${fontValue.arms.map((arm) => rustArm(arm, digests.maxArmPoints)).join("\n")}
];
`;
}

function typeScriptOutput(grammarValue, fontValue, digests) {
  const source = { ...digests, fontFile: grammarValue.defaultFont.source.split("/").at(-1) };
  const font = {
    id: fontValue.id,
    name: fontValue.name,
    fontVersion: fontValue.fontVersion,
    geometryVersion: fontValue.geometryVersion,
    grammarVersion: fontValue.grammarVersion,
    sourceSha256: digests.sourceDigest,
    units: fontValue.units,
    armsCoordinateMode: fontValue.armsCoordinateMode,
    core: fontValue.core,
    renderer: fontValue.renderer,
    arms: fontValue.arms,
  };
  return `${sourceBanner("//", source)}export const glyphSpec = {
  grammarVersion: "${grammarValue.grammarVersion}",
  geometryVersion: "${fontValue.geometryVersion}",
  sourceSha256: "${digests.sourceDigest}",
  grammarSha256: "${digests.grammarDigest}",
  fontSha256: "${digests.fontDigest}",
  radix: ${grammarValue.radix},
  digits: ${JSON.stringify(grammarValue.digits)},
  coordinateSystem: ${JSON.stringify(grammarValue.coordinateSystem)},
  strokeBits: ${JSON.stringify(grammarValue.strokeBits)},
  lattice: ${JSON.stringify(grammarValue.lattice)},
  defaultFont: ${JSON.stringify(grammarValue.defaultFont)},
} as const;

export const defaultGlyphFont = ${JSON.stringify(font)} as const;

export type GlyphSpec = typeof glyphSpec;
export type DefaultGlyphFont = typeof defaultGlyphFont;
`;
}

function swiftPoint(point, indent = "        ") {
  return `${indent}GlyphPoint(x: ${number(point[0])}, y: ${number(point[1])}),`;
}

function swiftOutput(grammarValue, fontValue, digests) {
  const source = { ...digests, fontFile: grammarValue.defaultFont.source.split("/").at(-1) };
  return `${sourceBanner("//", source)}import CoreGraphics

enum GlyphSpec {
    static let grammarVersion = "${grammarValue.grammarVersion}"
    static let geometryVersion = "${fontValue.geometryVersion}"
    static let fontID = "${fontValue.id}"
    static let fontVersion = "${fontValue.fontVersion}"
    static let sourceSHA256 = "${digests.sourceDigest}"
    static let grammarSHA256 = "${digests.grammarDigest}"
    static let fontSHA256 = "${digests.fontDigest}"
    static let radix = ${grammarValue.radix}
    static let minimumDigits = ${grammarValue.digits.minimum}
    static let maximumDigits = ${grammarValue.digits.maximum}
    static let defaultDigits = ${grammarValue.digits.default}
    static let leftStroke: UInt8 = ${grammarValue.strokeBits[0].bit}
    static let centreStroke: UInt8 = ${grammarValue.strokeBits[1].bit}
    static let rightStroke: UInt8 = ${grammarValue.strokeBits[2].bit}
    static let units: CGFloat = ${number(fontValue.units)}
    static let socketWidth: CGFloat = ${number(fontValue.core.socketWidth)}
    static let coreRadius: CGFloat = ${number(fontValue.core.coreRadius)}
    static let insetThickness: CGFloat = ${number(fontValue.core.insetThickness)}
    static let gridSize: CGFloat = ${number(fontValue.renderer.gridSize)}
    static let paddingCells: CGFloat = ${number(fontValue.renderer.paddingCells)}
    static let legacyCoreOuterDepth = ${fontValue.core.legacyExactOuter.depth}
    static let legacyCoreHoleDepth = ${fontValue.core.legacyExactHole.depth}

    static let legacyCoreOuter: [GlyphPoint] = [
${fontValue.core.legacyExactOuter.points.map((point) => swiftPoint(point)).join("\n")}
    ]
    static let legacyCoreHole: [GlyphPoint] = [
${fontValue.core.legacyExactHole.points.map((point) => swiftPoint(point)).join("\n")}
    ]
    static let arms: [[GlyphPoint]] = [
${fontValue.arms
  .map((arm) => `        [\n${arm.points.map((point) => swiftPoint(point, "            ")).join("\n")}\n        ],`)
  .join("\n")}
    ]
}
`;
}

function cPoint(point) {
  return `{${number(point[0], "f")}, ${number(point[1], "f")}}`;
}

function cArm(arm, maxArmPoints) {
  const padded = [...arm.points];
  while (padded.length < maxArmPoints) padded.push([0, 0]);
  return `    {${padded.map(cPoint).join(", ")}},`;
}

function cOutput(grammarValue, fontValue, digests) {
  const source = { ...digests, fontFile: grammarValue.defaultFont.source.split("/").at(-1) };
  return `${sourceBanner("/*", source)}#ifndef FRACTONICA_EMBEDDED_GLYPH_SPEC_GENERATED_H
#define FRACTONICA_EMBEDDED_GLYPH_SPEC_GENERATED_H

#include <stdint.h>

#define FRACTONICA_GLYPH_GRAMMAR_VERSION "${grammarValue.grammarVersion}"
#define FRACTONICA_GLYPH_GEOMETRY_VERSION "${fontValue.geometryVersion}"
#define FRACTONICA_GLYPH_FONT_ID "${fontValue.id}"
#define FRACTONICA_GLYPH_FONT_VERSION "${fontValue.fontVersion}"
#define FRACTONICA_GLYPH_GRAMMAR_SHA256 "${digests.grammarDigest}"
#define FRACTONICA_GLYPH_FONT_SHA256 "${digests.fontDigest}"
#define FRACTONICA_GLYPH_SPEC_SHA256 "${digests.sourceDigest}"
#define FRACTONICA_GLYPH_SPEC_RADIX ${grammarValue.radix}u
#define FRACTONICA_GLYPH_SPEC_MIN_DIGITS ${grammarValue.digits.minimum}u
#define FRACTONICA_GLYPH_SPEC_MAX_DIGITS ${grammarValue.digits.maximum}u
#define FRACTONICA_GLYPH_SPEC_DEFAULT_DIGITS ${grammarValue.digits.default}u
#define FRACTONICA_GLYPH_SPEC_STROKE_LEFT 0x${grammarValue.strokeBits[0].bit.toString(16)}u
#define FRACTONICA_GLYPH_SPEC_STROKE_CENTRE 0x${grammarValue.strokeBits[1].bit.toString(16)}u
#define FRACTONICA_GLYPH_SPEC_STROKE_RIGHT 0x${grammarValue.strokeBits[2].bit.toString(16)}u
#define FRACTONICA_GLYPH_FONT_UNITS ${number(fontValue.units, "f")}
#define FRACTONICA_GLYPH_FONT_SOCKET_WIDTH ${number(fontValue.core.socketWidth, "f")}
#define FRACTONICA_GLYPH_FONT_CORE_RADIUS ${number(fontValue.core.coreRadius, "f")}
#define FRACTONICA_GLYPH_FONT_INSET_THICKNESS ${number(fontValue.core.insetThickness, "f")}
#define FRACTONICA_GLYPH_FONT_GRID_SIZE ${number(fontValue.renderer.gridSize, "f")}
#define FRACTONICA_GLYPH_FONT_PADDING_CELLS ${number(fontValue.renderer.paddingCells, "f")}
#define FRACTONICA_GLYPH_FONT_LEGACY_OUTER_DEPTH ${fontValue.core.legacyExactOuter.depth}u
#define FRACTONICA_GLYPH_FONT_LEGACY_OUTER_POINT_COUNT ${fontValue.core.legacyExactOuter.points.length}u
#define FRACTONICA_GLYPH_FONT_LEGACY_HOLE_DEPTH ${fontValue.core.legacyExactHole.depth}u
#define FRACTONICA_GLYPH_FONT_LEGACY_HOLE_POINT_COUNT ${fontValue.core.legacyExactHole.points.length}u
#define FRACTONICA_GLYPH_FONT_ARM_MAX_POINTS ${digests.maxArmPoints}u

typedef struct fractonica_glyph_spec_point {
    float x;
    float y;
} fractonica_glyph_spec_point_t;

static const fractonica_glyph_spec_point_t fractonica_glyph_font_legacy_outer[FRACTONICA_GLYPH_FONT_LEGACY_OUTER_POINT_COUNT] = {
    ${fontValue.core.legacyExactOuter.points.map(cPoint).join(",\n    ")}
};
static const fractonica_glyph_spec_point_t fractonica_glyph_font_legacy_hole[FRACTONICA_GLYPH_FONT_LEGACY_HOLE_POINT_COUNT] = {
    ${fontValue.core.legacyExactHole.points.map(cPoint).join(",\n    ")}
};
static const uint8_t fractonica_glyph_font_arm_point_counts[FRACTONICA_GLYPH_SPEC_RADIX] = {
    ${fontValue.arms.map((arm) => `${arm.points.length}u`).join(", ")}
};
static const fractonica_glyph_spec_point_t fractonica_glyph_font_arms[FRACTONICA_GLYPH_SPEC_RADIX][FRACTONICA_GLYPH_FONT_ARM_MAX_POINTS] = {
${fontValue.arms.map((arm) => cArm(arm, digests.maxArmPoints)).join("\n")}
};

#endif /* FRACTONICA_EMBEDDED_GLYPH_SPEC_GENERATED_H */
`;
}
