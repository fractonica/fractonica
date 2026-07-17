import { describe, expect, it } from "vitest";

import { drawOctalGlyphCanvas } from "./canvas";
import { createOctalGlyph } from "./geometry";

describe("Canvas glyph adapter", () => {
  it("preserves the compound font fill rules", () => {
    const fillRules: string[] = [];
    const context = {
      canvas: { width: 352, height: 400 },
      save() {},
      restore() {},
      clearRect() {},
      fillRect() {},
      beginPath() {},
      moveTo() {},
      lineTo() {},
      closePath() {},
      fill(rule?: string) {
        fillRules.push(rule ?? "nonzero");
      },
      fillStyle: "",
    } as unknown as CanvasRenderingContext2D;

    drawOctalGlyphCanvas(context, createOctalGlyph("777777", { depth: 6 }));

    expect(fillRules).toEqual([
      "evenodd",
      "nonzero",
      "nonzero",
      "nonzero",
      "nonzero",
      "nonzero",
      "nonzero",
    ]);
  });
});
