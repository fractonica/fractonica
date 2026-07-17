import type { GlyphFrame, GlyphPoint, GlyphPrimitive, OctalGlyphPlan } from "./geometry";

export type CanvasGlyphFillStyle = string | CanvasGradient | CanvasPattern;

export interface CanvasGlyphRenderOptions {
  readonly x?: number;
  readonly y?: number;
  readonly width?: number;
  readonly height?: number;
  readonly foreground?: CanvasGlyphFillStyle;
  /** `null` preserves transparency in the central cutout. */
  readonly background?: CanvasGlyphFillStyle | null;
  /** Clears the destination rectangle before painting. Defaults to true. */
  readonly clear?: boolean;
}

/**
 * Draws a canonical glyph through the browser's native Canvas 2D API.
 *
 * It consumes the same plan used by SVG and React instead of redrawing the
 * glyph with independent, hand-maintained line logic. Canvas callers retain
 * full control of their surface and can reuse plans across frames.
 */
export function drawOctalGlyphCanvas(
  context: CanvasRenderingContext2D,
  plan: OctalGlyphPlan,
  options: CanvasGlyphRenderOptions = {},
): void {
  const x = options.x ?? 0;
  const y = options.y ?? 0;
  const width = options.width ?? context.canvas.width;
  const height = options.height ?? context.canvas.height;
  if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) {
    throw new RangeError("Canvas glyph destination must have finite positive dimensions.");
  }

  const foreground = options.foreground ?? "currentColor";
  const background = options.background ?? null;
  const clear = options.clear ?? true;
  const transform = containFit(plan.frame, x, y, width, height);

  context.save();
  if (clear) context.clearRect(x, y, width, height);
  if (background !== null) {
    context.fillStyle = background;
    context.fillRect(x, y, width, height);
  }
  context.fillStyle = foreground;
  for (const primitive of plan.primitives) {
    fillPrimitive(context, primitive, transform);
  }
  context.restore();
}

interface CanvasTransform {
  readonly scale: number;
  readonly offsetX: number;
  readonly offsetY: number;
  readonly frame: GlyphFrame;
}

function containFit(frame: GlyphFrame, x: number, y: number, width: number, height: number): CanvasTransform {
  const scale = Math.min(width / frame.width, height / frame.height);
  return {
    scale,
    offsetX: x + (width - frame.width * scale) / 2,
    offsetY: y + (height - frame.height * scale) / 2,
    frame,
  };
}

function fillPrimitive(
  context: CanvasRenderingContext2D,
  primitive: GlyphPrimitive,
  transform: CanvasTransform,
): void {
  context.beginPath();
  for (const contour of primitive.contours) {
    const [first, ...rest] = contour.points;
    if (!first) continue;
    context.moveTo(
      transform.offsetX + (first.x - transform.frame.x) * transform.scale,
      transform.offsetY + (first.y - transform.frame.y) * transform.scale,
    );
    for (const point of rest) {
      context.lineTo(
        transform.offsetX + (point.x - transform.frame.x) * transform.scale,
        transform.offsetY + (point.y - transform.frame.y) * transform.scale,
      );
    }
    context.closePath();
  }
  context.fill(primitive.fillRule);
}
