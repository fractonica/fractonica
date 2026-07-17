import { useMemo, type SVGProps } from "react";

import {
  createOctalGlyph,
  glyphPrimitivePathData,
  type CreateOctalGlyphOptions,
} from "@fractonica/glyph-core";

type ManagedSvgProps =
  | "aria-hidden"
  | "aria-label"
  | "children"
  | "height"
  | "role"
  | "radius"
  | "viewBox"
  | "width";

export interface OctalGlyphProps
  extends Omit<SVGProps<SVGSVGElement>, ManagedSvgProps>,
    CreateOctalGlyphOptions {
  readonly value: string;
  readonly size?: number | string;
  readonly width?: number | string;
  readonly height?: number | string;
  readonly foreground?: string;
  /** Fills the aperture; leave unset to preserve transparency. */
  readonly background?: string;
  readonly label?: string;
  readonly decorative?: boolean;
}

/**
 * Server-renderable SVG React adapter for the canonical glyph plan.
 *
 * The font owns its compound paths: the core is filled with SVG's even-odd
 * rule, so its aperture stays transparent over any parent background.
 */
export function OctalGlyph({
  value,
  depth,
  centerX,
  centerY,
  radius,
  rotationRadians,
  font,
  size = "1em",
  width,
  height,
  foreground = "currentColor",
  background,
  label,
  decorative = false,
  preserveAspectRatio = "xMidYMid meet",
  ...svgProps
}: OctalGlyphProps) {
  const plan = useMemo(
    () =>
      createOctalGlyph(value, {
        depth,
        centerX,
        centerY,
        radius,
        rotationRadians,
        font,
      }),
    [value, depth, centerX, centerY, radius, rotationRadians, font],
  );
  const accessibleLabel = label ?? `Octal glyph ${plan.normalizedValue}`;
  const coreHole = plan.primitives[0]?.kind === "core" ? plan.primitives[0].contours[1] : undefined;
  const resolvedWidth = width ?? size;
  const resolvedHeight = height ?? size;

  return (
    <svg
      {...svgProps}
      aria-hidden={decorative || undefined}
      aria-label={decorative ? undefined : accessibleLabel}
      focusable={false}
      height={resolvedHeight}
      role={decorative ? undefined : "img"}
      viewBox={`${plan.frame.x} ${plan.frame.y} ${plan.frame.width} ${plan.frame.height}`}
      width={resolvedWidth}
      preserveAspectRatio={preserveAspectRatio}
    >
      <g fill={foreground}>
        {plan.primitives.map((primitive, index) => (
          <path
            d={glyphPrimitivePathData(primitive)}
            data-digit={primitive.digit}
            data-glyph-primitive={primitive.kind}
            data-socket-index={primitive.socketIndex}
            fillRule={primitive.fillRule}
            key={`${primitive.kind}-${primitive.socketIndex ?? "core"}-${index}`}
          />
        ))}
      </g>
      {background && coreHole ? (
        <path d={glyphPrimitivePathData({ contours: [coreHole] })} fill={background} />
      ) : null}
    </svg>
  );
}
