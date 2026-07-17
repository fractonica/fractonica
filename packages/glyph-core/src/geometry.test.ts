import { describe, expect, it } from "vitest";

import {
  createOctalGlyph,
  DEFAULT_GLYPH_FONT,
  glyphDigitIndexForSocket,
  glyphStrokeMask,
  normalizeOctalGlyph,
} from "./index";

describe("canonical octal glyph geometry", () => {
  it("preserves the MSB-first socket order", () => {
    expect(normalizeOctalGlyph("17", 5)).toBe("00017");
    expect([0, 1, 2, 3, 4].map((socket) => glyphDigitIndexForSocket(5, socket))).toEqual([
      0, 4, 3, 2, 1,
    ]);
  });

  it("uses the 1/2/4 binary stroke grammar", () => {
    expect(glyphStrokeMask(1)).toBe(1);
    expect(glyphStrokeMask(2)).toBe(2);
    expect(glyphStrokeMask(4)).toBe(4);
    expect(
      createOctalGlyph("7", { depth: 3 }).primitives.map((primitive) => primitive.kind),
    ).toEqual(["core", "arm"]);
  });

  it("keeps the frame invariant while values change", () => {
    const zero = createOctalGlyph("0", { depth: 5 });
    const all = createOctalGlyph("77777", { depth: 5 });
    expect(zero.frame).toEqual(all.frame);
    expect(all.specSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(all.specSha256).toBe(DEFAULT_GLYPH_FONT.sourceSha256);
  });

  it("uses the verified Hex v2 depth-six fixture geometry", () => {
    const glyph = createOctalGlyph("777777", { depth: 6 });
    expect(DEFAULT_GLYPH_FONT.id).toBe("fractonica-hex-v2");
    expect(glyph.frame).toEqual({
      x: -176,
      y: -200,
      width: 352,
      height: 400,
      aspectRatio: 0.88,
    });
    expect(glyph.primitives).toHaveLength(7);
    const [core, firstArm] = glyph.primitives;
    expect(core).toMatchObject({ kind: "core", fillRule: "evenodd" });
    expect(core?.contours.map((contour) => contour.points.length)).toEqual([12, 7]);
    expect(firstArm).toMatchObject({
      kind: "arm",
      fillRule: "nonzero",
      socketIndex: 0,
      digitIndex: 0,
      digit: 7,
    });
    const expectedArm = [
      { x: -8, y: -41.57 },
      { x: -40, y: -96.99 },
      { x: 0, y: -166.28 },
      { x: 40, y: -96.99 },
      { x: 32, y: -83.14 },
      { x: 0, y: -138.56 },
      { x: -24, y: -96.99 },
      { x: 8, y: -41.57 },
    ];
    expect(firstArm?.contours[0]?.points).toHaveLength(expectedArm.length);
    firstArm?.contours[0]?.points.forEach((point, index) => {
      expect(point.x).toBeCloseTo(expectedArm[index]?.x ?? 0, 4);
      expect(point.y).toBeCloseTo(expectedArm[index]?.y ?? 0, 4);
    });
    const clockwiseSocketOne = createOctalGlyph("111111", { depth: 6 }).primitives[2];
    expect(clockwiseSocketOne?.contours[0]?.points[0]).toEqual({ x: 32, y: -27.71 });
  });

  it("keeps the MSB at the primary socket for non-repdigit addresses", () => {
    const glyph = createOctalGlyph("12345", { depth: 5 });
    expect(glyph.primitives.slice(1).map((primitive) => [primitive.socketIndex, primitive.digitIndex, primitive.digit])).toEqual([
      [0, 0, 1],
      [1, 4, 5],
      [2, 3, 4],
      [3, 2, 3],
      [4, 1, 2],
    ]);
  });

  it("accepts a custom font without changing octal semantics", () => {
    const font = {
      ...DEFAULT_GLYPH_FONT,
      id: "example-outline",
      fontVersion: "0.1.0",
      geometryVersion: "example-geometry-1",
      sourceSha256: "a".repeat(64),
      core: {
        ...DEFAULT_GLYPH_FONT.core,
        coreRadius: 80,
      },
    };
    const glyph = createOctalGlyph("700", { depth: 3, font });
    expect(glyph.fontId).toBe("example-outline");
    expect(glyph.geometryVersion).toBe("example-geometry-1");
    expect(glyph.specSha256).toBe("a".repeat(64));
    expect(glyph.primitives[0]?.contours[0]?.points[0]).toEqual({ x: -8, y: -80 });
    expect(glyph.primitives[1]?.digit).toBe(7);
    expect(glyphStrokeMask(7)).toBe(7);
  });
});
