import { defaultGlyphFont, glyphSpec } from "./spec.generated";

export type GlyphPrimitiveKind = "core" | "arm";
export type GlyphFillRule = "evenodd" | "nonzero";

export interface GlyphPoint {
  readonly x: number;
  readonly y: number;
}

export interface GlyphContour {
  readonly points: readonly GlyphPoint[];
}

export interface GlyphFrame {
  readonly x: number;
  readonly y: number;
  readonly width: number;
  readonly height: number;
  readonly aspectRatio: number;
}

export interface GlyphPrimitive {
  readonly kind: GlyphPrimitiveKind;
  readonly fillRule: GlyphFillRule;
  readonly socketIndex?: number;
  readonly digitIndex?: number;
  readonly digit?: number;
  readonly contours: readonly GlyphContour[];
}

export interface GlyphFontPoint {
  readonly x: number;
  readonly y: number;
}

export interface GlyphArmOutline {
  readonly digit: number;
  readonly points: readonly GlyphFontPoint[];
}

/**
 * A data-only visual font for the invariant octal grammar.
 *
 * `arms` use socket-local coordinates: X follows the socket chord and
 * positive Y moves outward from the radial core. The grammar still decides
 * that digit 5 means `1 | 4`; the font simply decides its filled silhouette.
 */
export interface GlyphFont {
  readonly id: string;
  readonly name: string;
  readonly fontVersion: string;
  readonly geometryVersion: string;
  readonly grammarVersion: string;
  /** Digest of the complete grammar-plus-font source, when available. */
  readonly sourceSha256?: string;
  readonly units: number;
  readonly armsCoordinateMode: "socket";
  readonly core: {
    readonly socketWidth: number;
    readonly coreRadius: number;
    readonly insetThickness: number;
    readonly legacyExactOuter: {
      readonly depth: number;
      readonly points: readonly GlyphFontPoint[];
    };
    readonly legacyExactHole: {
      readonly depth: number;
      readonly points: readonly GlyphFontPoint[];
    };
  };
  readonly renderer: {
    readonly gridSize: number;
    readonly paddingCells: number;
  };
  readonly arms: readonly GlyphArmOutline[];
}

export interface OctalGlyphPlan {
  readonly grammarVersion: string;
  readonly geometryVersion: string;
  readonly specSha256: string;
  readonly fontId: string;
  readonly fontVersion: string;
  readonly normalizedValue: string;
  readonly depth: number;
  readonly coordinateSystem: typeof glyphSpec.coordinateSystem;
  readonly frame: GlyphFrame;
  readonly primitives: readonly GlyphPrimitive[];
}

export interface CreateOctalGlyphOptions {
  /** Three to eight sockets; five remains the pulse-glyph default. */
  readonly depth?: number;
  readonly centerX?: number;
  readonly centerY?: number;
  /** Scale multiplier applied to the font's native coordinate units. */
  readonly radius?: number;
  /** Clockwise radians in the positive-Y-down glyph plane. */
  readonly rotationRadians?: number;
  /** Defaults to the generated Fractonica Hex v2 font. */
  readonly font?: GlyphFont;
}

export class GlyphInputError extends Error {
  override readonly name = "GlyphInputError";
}

interface GlyphLayout {
  readonly centerX: number;
  readonly centerY: number;
  readonly radius: number;
  readonly rotationRadians: number;
}

interface SocketFrame {
  readonly center: GlyphPoint;
  readonly tangent: GlyphPoint;
  readonly outward: GlyphPoint;
  readonly length: number;
  readonly localToWorld: (tangentDistance: number, outwardDistance: number) => GlyphPoint;
}

const [leftStroke, centreStroke, rightStroke] = glyphSpec.strokeBits;
const LEFT_BIT = leftStroke.bit;
const CENTRE_BIT = centreStroke.bit;
const RIGHT_BIT = rightStroke.bit;

/** The bundled visual default, generated from the canonical font asset. */
export const DEFAULT_GLYPH_FONT: GlyphFont = normalizeGlyphFont(defaultGlyphFont);

/**
 * Validates and left-pads a strict MSB-first octal value.
 *
 * This rejects overlong values and non-octal characters: a glyph is an
 * address, so silently dropping its prefix would make two devices show
 * different meanings.
 */
export function normalizeOctalGlyph(
  value: string,
  depth: number = glyphSpec.digits.default,
): string {
  validateDepth(depth);
  if (value.length === 0) throw new GlyphInputError("Glyph value must not be empty.");
  if (value.length > depth) {
    throw new GlyphInputError(`Glyph value has ${value.length} digits but depth is ${depth}.`);
  }
  for (const [index, character] of [...value].entries()) {
    if (character < "0" || character > "7") {
      throw new GlyphInputError(`Glyph digit ${index} must be an ASCII octal digit.`);
    }
  }
  return value.padStart(depth, "0");
}

/** Returns the MSB-first digit index rendered at a radial socket. */
export function glyphDigitIndexForSocket(depth: number, socketIndex: number): number {
  validateDepth(depth);
  if (!Number.isInteger(socketIndex) || socketIndex < 0 || socketIndex >= depth) {
    throw new GlyphInputError(`Socket index must be an integer from 0 through ${depth - 1}.`);
  }
  return socketIndex === 0 ? 0 : depth - socketIndex;
}

/** Returns the grammar's canonical `1 | 2 | 4` semantic mask. */
export function glyphStrokeMask(digit: number): number {
  if (!Number.isInteger(digit) || digit < 0 || digit >= glyphSpec.radix) {
    throw new GlyphInputError("Glyph digit must be an integer from 0 through 7.");
  }
  return digit;
}

/**
 * Builds deterministic compound-outline geometry for SVG, Canvas, WebGL, or
 * a caller's own renderer. The core is a two-contour even-odd shape; every
 * nonzero digit becomes one arbitrary nonzero font outline.
 */
export function createOctalGlyph(
  value: string,
  options: CreateOctalGlyphOptions = {},
): OctalGlyphPlan {
  const depth = options.depth ?? glyphSpec.digits.default;
  validateDepth(depth);
  const layout = normalizeLayout(options);
  const font = normalizeGlyphFont(options.font ?? DEFAULT_GLYPH_FONT);
  const normalizedValue = normalizeOctalGlyph(value, depth);
  const digits = [...normalizedValue].map(Number);
  const primitives = buildPrimitives(depth, digits, layout, font);
  const frame = makeStableFrame(depth, layout, font);

  return Object.freeze({
    grammarVersion: glyphSpec.grammarVersion,
    geometryVersion: font.geometryVersion,
    specSha256: font.sourceSha256 ?? glyphSpec.grammarSha256,
    fontId: font.id,
    fontVersion: font.fontVersion,
    normalizedValue,
    depth,
    coordinateSystem: glyphSpec.coordinateSystem,
    frame,
    primitives: freezePrimitives(primitives),
  });
}

/** Serialises every contour in one primitive into SVG path data. */
export function glyphPrimitivePathData(primitive: Pick<GlyphPrimitive, "contours">): string {
  return primitive.contours
    .map((contour) => {
      const [first, ...rest] = contour.points;
      if (!first || contour.points.length < 3) return "";
      return [
        `M ${formatNumber(first.x)} ${formatNumber(first.y)}`,
        ...rest.map((point) => `L ${formatNumber(point.x)} ${formatNumber(point.y)}`),
        "Z",
      ].join(" ");
    })
    .filter(Boolean)
    .join(" ");
}

/** Validates a font and returns a frozen copy detached from caller mutation. */
export function normalizeGlyphFont(font: GlyphFont | typeof defaultGlyphFont): GlyphFont {
  if (!font || typeof font !== "object") throw new GlyphInputError("Glyph font must be an object.");
  const core = font.core;
  const renderer = font.renderer;
  const numericValues = [
    font.units,
    core?.socketWidth,
    core?.coreRadius,
    core?.insetThickness,
    renderer?.gridSize,
    renderer?.paddingCells,
  ];
  if (numericValues.some((value) => !Number.isFinite(value) || Number(value) <= 0)) {
    throw new GlyphInputError("Glyph font metrics must be finite positive numbers.");
  }
  if (font.grammarVersion !== glyphSpec.grammarVersion || font.armsCoordinateMode !== "socket") {
    throw new GlyphInputError("Glyph font is incompatible with the canonical grammar.");
  }
  if (font.sourceSha256 !== undefined && !/^[0-9a-f]{64}$/.test(font.sourceSha256)) {
    throw new GlyphInputError("Glyph font sourceSha256 must be a lowercase SHA-256 digest when supplied.");
  }
  if (!Array.isArray(font.arms) || font.arms.length !== glyphSpec.radix) {
    throw new GlyphInputError("Glyph font must define exactly eight arm outlines.");
  }
  const arms = font.arms.map((arm, index) => {
    if (arm.digit !== index || !Array.isArray(arm.points) || arm.points.length < 2) {
      throw new GlyphInputError(`Glyph font arm ${index} is invalid.`);
    }
    if (index > 0 && arm.points.length < 3) {
      throw new GlyphInputError(`Glyph font arm ${index} must be a filled outline.`);
    }
    return Object.freeze({
      digit: index,
      points: freezeFontPoints(arm.points),
    });
  });
  const legacyOuter = core?.legacyExactOuter;
  const legacyHole = core?.legacyExactHole;
  if (!Number.isInteger(legacyOuter?.depth) || !Array.isArray(legacyOuter?.points) || legacyOuter.points.length < 3) {
    throw new GlyphInputError("Glyph font must define a valid exact core-outer outline.");
  }
  if (
    legacyOuter.depth < glyphSpec.digits.minimum ||
    legacyOuter.depth > glyphSpec.digits.maximum ||
    legacyOuter.points.length !== legacyOuter.depth * 2
  ) {
    throw new GlyphInputError("Glyph font exact core outer must provide one chord for every override socket.");
  }
  if (!Number.isInteger(legacyHole?.depth) || !Array.isArray(legacyHole?.points) || legacyHole.points.length < 3) {
    throw new GlyphInputError("Glyph font must define a valid exact core-hole outline.");
  }
  if (legacyHole.depth < glyphSpec.digits.minimum || legacyHole.depth > glyphSpec.digits.maximum) {
    throw new GlyphInputError("Glyph font exact core hole must target a supported glyph depth.");
  }
  return Object.freeze({
    id: String(font.id),
    name: String(font.name),
    fontVersion: String(font.fontVersion),
    geometryVersion: String(font.geometryVersion),
    grammarVersion: String(font.grammarVersion),
    sourceSha256: font.sourceSha256,
    units: Number(font.units),
    armsCoordinateMode: "socket",
    core: Object.freeze({
      socketWidth: Number(core.socketWidth),
      coreRadius: Number(core.coreRadius),
      insetThickness: Number(core.insetThickness),
      legacyExactOuter: Object.freeze({
        depth: Number(legacyOuter.depth),
        points: freezeFontPoints(legacyOuter.points),
      }),
      legacyExactHole: Object.freeze({
        depth: Number(legacyHole.depth),
        points: freezeFontPoints(legacyHole.points),
      }),
    }),
    renderer: Object.freeze({
      gridSize: Number(renderer.gridSize),
      paddingCells: Number(renderer.paddingCells),
    }),
    arms: Object.freeze(arms),
  });
}

function normalizeLayout(options: CreateOctalGlyphOptions): GlyphLayout {
  const centerX = options.centerX ?? 0;
  const centerY = options.centerY ?? 0;
  const radius = options.radius ?? 1;
  const rotationRadians = options.rotationRadians ?? 0;
  if (!Number.isFinite(centerX) || !Number.isFinite(centerY) || !Number.isFinite(radius) || radius <= 0) {
    throw new GlyphInputError("Glyph centre and font scale must be finite; scale must be positive.");
  }
  if (!Number.isFinite(rotationRadians)) {
    throw new GlyphInputError("Glyph rotation must be finite.");
  }
  return Object.freeze({ centerX, centerY, radius, rotationRadians });
}

function validateDepth(depth: number): void {
  if (!Number.isInteger(depth) || depth < glyphSpec.digits.minimum || depth > glyphSpec.digits.maximum) {
    throw new GlyphInputError(
      `Glyph depth must be an integer from ${glyphSpec.digits.minimum} through ${glyphSpec.digits.maximum}.`,
    );
  }
}

function buildPrimitives(
  depth: number,
  digits: readonly number[],
  layout: GlyphLayout,
  font: GlyphFont,
): GlyphPrimitive[] {
  const outer = makeCoreOuter(depth, layout, font);
  const hole = makeCoreHole(depth, layout, font, outer);
  const primitives: GlyphPrimitive[] = [
    freezePrimitive({
      kind: "core",
      fillRule: "evenodd",
      contours: [
        { points: outer },
        { points: hole },
      ],
    }),
  ];

  for (let socketIndex = 0; socketIndex < depth; socketIndex += 1) {
    const digitIndex = glyphDigitIndexForSocket(depth, socketIndex);
    const digit = digits[digitIndex] ?? 0;
    if (digit === 0) continue;
    const points = transformArm(depth, socketIndex, digit, layout, font);
    if (points.length < 3) continue;
    primitives.push(
      freezePrimitive({
        kind: "arm",
        fillRule: "nonzero",
        socketIndex,
        digitIndex,
        digit,
        contours: [{ points }],
      }),
    );
  }
  return primitives;
}

function makeStableFrame(depth: number, layout: GlyphLayout, font: GlyphFont): GlyphFrame {
  const outer = makeCoreOuter(depth, layout, font);
  const hole = makeCoreHole(depth, layout, font, outer);
  const points: GlyphPoint[] = [...outer, ...hole];
  for (let socketIndex = 0; socketIndex < depth; socketIndex += 1) {
    for (let digit = 0; digit < glyphSpec.radix; digit += 1) {
      points.push(...transformArm(depth, socketIndex, digit, layout, font));
    }
  }
  const minX = Math.min(...points.map((point) => point.x));
  const maxX = Math.max(...points.map((point) => point.x));
  const minY = Math.min(...points.map((point) => point.y));
  const maxY = Math.max(...points.map((point) => point.y));
  const grid = font.renderer.gridSize * layout.radius;
  const padding = grid * font.renderer.paddingCells;
  const halfWidth = Math.ceil(Math.max(Math.abs(minX - layout.centerX), Math.abs(maxX - layout.centerX)) / grid) * grid + padding;
  const halfHeight = Math.ceil(Math.max(Math.abs(minY - layout.centerY), Math.abs(maxY - layout.centerY)) / grid) * grid + padding;
  return Object.freeze({
    x: layout.centerX - halfWidth,
    y: layout.centerY - halfHeight,
    width: halfWidth * 2,
    height: halfHeight * 2,
    aspectRatio: halfWidth / halfHeight,
  });
}

function makeCoreOuter(depth: number, layout: GlyphLayout, font: GlyphFont): readonly GlyphPoint[] {
  if (depth === font.core.legacyExactOuter.depth) {
    return freezePoints(font.core.legacyExactOuter.points.map((point) => transformGlobalPoint(point, layout)));
  }
  const points: GlyphPoint[] = [];
  for (let socketIndex = 0; socketIndex < depth; socketIndex += 1) {
    const socket = makeSocketFrame(depth, socketIndex, layout, font);
    points.push(socket.localToWorld(-socket.length / 2, 0));
    points.push(socket.localToWorld(socket.length / 2, 0));
  }
  return freezePoints(points);
}

function makeCoreHole(
  depth: number,
  layout: GlyphLayout,
  font: GlyphFont,
  outer: readonly GlyphPoint[],
): readonly GlyphPoint[] {
  if (depth === font.core.legacyExactHole.depth) {
    return freezePoints(font.core.legacyExactHole.points.map((point) => transformGlobalPoint(point, layout)));
  }
  return insetConvexPolygon(outer, font.core.insetThickness * layout.radius);
}

function transformArm(
  depth: number,
  socketIndex: number,
  digit: number,
  layout: GlyphLayout,
  font: GlyphFont,
): readonly GlyphPoint[] {
  const arm = font.arms[digit];
  if (!arm || arm.points.length < 2) return Object.freeze([]);
  const socket = makeSocketFrame(depth, socketIndex, layout, font);
  return freezePoints(
    arm.points.map((point, index) => {
      if (index === 0) return socket.localToWorld(-socket.length / 2, 0);
      if (index + 1 === arm.points.length) return socket.localToWorld(socket.length / 2, 0);
      return socket.localToWorld(point.x * layout.radius, point.y * layout.radius);
    }),
  );
}

function makeSocketFrame(depth: number, socketIndex: number, layout: GlyphLayout, font: GlyphFont): SocketFrame {
  if (depth === font.core.legacyExactOuter.depth) {
    const startTemplate = font.core.legacyExactOuter.points[socketIndex * 2];
    const endTemplate = font.core.legacyExactOuter.points[socketIndex * 2 + 1];
    if (startTemplate && endTemplate) {
      // The authored depth-six core is intentionally rounded. Derive the
      // socket from its exact chord so an arm meets the core without a tiny
      // trig-derived seam in SVG, Canvas, and software rasterizers.
      const start = transformGlobalPoint(startTemplate, layout);
      const end = transformGlobalPoint(endTemplate, layout);
      const delta = { x: end.x - start.x, y: end.y - start.y };
      const length = Math.max(Math.hypot(delta.x, delta.y), 0.001);
      const tangent = Object.freeze({ x: delta.x / length, y: delta.y / length });
      const center = Object.freeze({ x: (start.x + end.x) / 2, y: (start.y + end.y) / 2 });
      const outward = Object.freeze({ x: tangent.y, y: -tangent.x });
      return Object.freeze({
        center,
        tangent,
        outward,
        length,
        localToWorld: (tangentDistance: number, outwardDistance: number) =>
          Object.freeze(add(add(center, scale(tangent, tangentDistance)), scale(outward, outwardDistance))),
      });
    }
  }
  const angle = layout.rotationRadians + (2 * Math.PI * socketIndex) / depth;
  const tangent = Object.freeze({ x: Math.cos(angle), y: Math.sin(angle) });
  // Rotate the source font's top-facing `(0, -1)` radial vector clockwise
  // in the positive-Y-down plane. This keeps socket 1 at the upper-right,
  // matching the historical Hex v2 SVG rather than mirroring its arms.
  const outward = Object.freeze({ x: Math.sin(angle), y: -Math.cos(angle) });
  const center = Object.freeze(add({ x: layout.centerX, y: layout.centerY }, scale(outward, font.core.coreRadius * layout.radius)));
  const length = font.core.socketWidth * layout.radius;
  return Object.freeze({
    center,
    tangent,
    outward,
    length,
    localToWorld: (tangentDistance: number, outwardDistance: number) =>
      Object.freeze(add(add(center, scale(tangent, tangentDistance)), scale(outward, outwardDistance))),
  });
}

function transformGlobalPoint(point: GlyphFontPoint, layout: GlyphLayout): GlyphPoint {
  const x = point.x * layout.radius;
  const y = point.y * layout.radius;
  const cosine = Math.cos(layout.rotationRadians);
  const sine = Math.sin(layout.rotationRadians);
  return Object.freeze({
    x: layout.centerX + x * cosine - y * sine,
    y: layout.centerY + x * sine + y * cosine,
  });
}

function insetConvexPolygon(points: readonly GlyphPoint[], thickness: number): readonly GlyphPoint[] {
  if (points.length < 3 || thickness <= 0) return freezePoints(points);
  const inwardSign = signedArea(points) >= 0 ? 1 : -1;
  const lines = points.map((point, index) => {
    const next = points[(index + 1) % points.length] ?? point;
    const dx = next.x - point.x;
    const dy = next.y - point.y;
    const length = Math.max(Math.hypot(dx, dy), 0.001);
    const normal = { x: (-dy / length) * inwardSign, y: (dx / length) * inwardSign };
    return {
      point: add(point, scale(normal, thickness)),
      direction: { x: dx, y: dy },
    };
  });
  return freezePoints(
    points.map((point, index) => {
      const previous = lines[(index + lines.length - 1) % lines.length];
      const current = lines[index];
      return !previous || !current
        ? point
        : intersectLines(previous.point, previous.direction, current.point, current.direction) ?? point;
    }),
  );
}

function signedArea(points: readonly GlyphPoint[]): number {
  return points.reduce((area, point, index) => {
    const next = points[(index + 1) % points.length] ?? point;
    return area + point.x * next.y - next.x * point.y;
  }, 0);
}

function intersectLines(
  pointA: GlyphPoint,
  directionA: GlyphPoint,
  pointB: GlyphPoint,
  directionB: GlyphPoint,
): GlyphPoint | null {
  const cross = directionA.x * directionB.y - directionA.y * directionB.x;
  if (Math.abs(cross) < 0.000001) return null;
  const delta = { x: pointB.x - pointA.x, y: pointB.y - pointA.y };
  const t = (delta.x * directionB.y - delta.y * directionB.x) / cross;
  return Object.freeze({ x: pointA.x + directionA.x * t, y: pointA.y + directionA.y * t });
}

function add(left: GlyphPoint, right: GlyphPoint): GlyphPoint {
  return { x: left.x + right.x, y: left.y + right.y };
}

function scale(point: GlyphPoint, factor: number): GlyphPoint {
  return { x: point.x * factor, y: point.y * factor };
}

function freezeFontPoints(points: readonly (GlyphFontPoint | readonly [number, number])[]): readonly GlyphFontPoint[] {
  return Object.freeze(
    points.map((point) => {
      const tuplePoint = point as readonly [number, number];
      const objectPoint = point as GlyphFontPoint;
      const x = Array.isArray(point) ? tuplePoint[0] : objectPoint.x;
      const y = Array.isArray(point) ? tuplePoint[1] : objectPoint.y;
      if (!Number.isFinite(x) || !Number.isFinite(y)) throw new GlyphInputError("Glyph font points must be finite.");
      return Object.freeze({ x, y });
    }),
  );
}

function freezePoints(points: readonly GlyphPoint[]): readonly GlyphPoint[] {
  return Object.freeze(points.map((point) => Object.freeze({ x: point.x, y: point.y })));
}

function freezePrimitive(primitive: GlyphPrimitive): GlyphPrimitive {
  return Object.freeze({
    ...primitive,
    contours: Object.freeze(
      primitive.contours.map((contour) => Object.freeze({ points: freezePoints(contour.points) })),
    ),
  });
}

function freezePrimitives(primitives: readonly GlyphPrimitive[]): readonly GlyphPrimitive[] {
  return Object.freeze(primitives.map(freezePrimitive));
}

function formatNumber(value: number): string {
  return Number.isInteger(value) ? String(value) : String(Number(value.toFixed(6)));
}
