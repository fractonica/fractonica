import { useMemo } from "react";
import Svg, { G, Path, type NumberProp, type SvgProps } from "react-native-svg";

import {
  createOctalGlyph,
  glyphPrimitivePathData,
  type CreateOctalGlyphOptions,
} from "@fractonica/glyph-core/geometry";

type ManagedSvgProps =
  | "accessibilityLabel"
  | "accessibilityRole"
  | "children"
  | "font"
  | "height"
  | "viewBox"
  | "width";

export interface OctalGlyphProps
  extends Omit<SvgProps, ManagedSvgProps>,
    CreateOctalGlyphOptions {
  readonly value: string;
  readonly size?: NumberProp;
  readonly width?: NumberProp;
  readonly height?: NumberProp;
  readonly foreground?: string;
  /** Fills the central aperture; leave unset to preserve transparency. */
  readonly background?: string;
  readonly label?: string;
  readonly decorative?: boolean;
}

/**
 * React Native SVG adapter for the canonical, MSB-first glyph geometry.
 *
 * It contains no independent stroke rules: web, mobile, Rust, and embedded
 * renderers all consume geometry derived from the same versioned font asset.
 */
export function OctalGlyph({
  value,
  depth,
  centerX,
  centerY,
  radius,
  rotationRadians,
  font,
  size = 24,
  width,
  height,
  foreground = "currentColor",
  background,
  label,
  decorative = false,
  ...svgProps
}: OctalGlyphProps) {
  const plan = useMemo(
    () =>
      createOctalGlyph(value, {
        ...(depth === undefined ? {} : { depth }),
        ...(centerX === undefined ? {} : { centerX }),
        ...(centerY === undefined ? {} : { centerY }),
        ...(radius === undefined ? {} : { radius }),
        ...(rotationRadians === undefined ? {} : { rotationRadians }),
        ...(font === undefined ? {} : { font }),
      }),
    [value, depth, centerX, centerY, radius, rotationRadians, font],
  );
  const coreHole = plan.primitives[0]?.kind === "core" ? plan.primitives[0].contours[1] : undefined;
  const accessibleLabel = label ?? `Octal glyph ${plan.normalizedValue}`;

  return (
    <Svg
      {...svgProps}
      accessible={!decorative}
      {...(decorative ? {} : { accessibilityLabel: accessibleLabel })}
      {...(decorative ? {} : { accessibilityRole: "image" as const })}
      height={height ?? size}
      importantForAccessibility={decorative ? "no" : "yes"}
      viewBox={`${plan.frame.x} ${plan.frame.y} ${plan.frame.width} ${plan.frame.height}`}
      width={width ?? size}
    >
      <G fill={foreground}>
        {plan.primitives.map((primitive, index) => (
          <Path
            d={glyphPrimitivePathData(primitive)}
            fillRule={primitive.fillRule}
            key={`${primitive.kind}-${primitive.socketIndex ?? "core"}-${index}`}
          />
        ))}
      </G>
      {background && coreHole ? (
        <Path d={glyphPrimitivePathData({ contours: [coreHole] })} fill={background} />
      ) : null}
    </Svg>
  );
}
