import type { CSSProperties, HTMLAttributes } from "react";

import { OctalGlyph, type OctalGlyphProps } from "./octal-glyph";

export interface SarosPulseGlyphPairProps
  extends Omit<HTMLAttributes<HTMLSpanElement>, "children"> {
  readonly mostSignificant: string;
  readonly leastSignificant: string;
  readonly glyphSize?: OctalGlyphProps["size"];
  readonly foreground?: string;
  readonly background?: string;
  readonly glyphProps?: Omit<OctalGlyphProps, "value" | "depth" | "size" | "foreground" | "background">;
}

/** Renders the canonical ten-digit realtime pulse as two five-digit glyphs. */
export function SarosPulseGlyphPair({
  mostSignificant,
  leastSignificant,
  glyphSize = "1.25em",
  foreground,
  background,
  glyphProps,
  style,
  ...spanProps
}: SarosPulseGlyphPairProps) {
  const pairStyle: CSSProperties = {
    alignItems: "center",
    display: "inline-flex",
    gap: "0.18em",
    lineHeight: 1,
    ...style,
  };
  return (
    <span {...spanProps} style={pairStyle}>
      <OctalGlyph
        {...glyphProps}
        decorative={glyphProps?.decorative ?? true}
        value={mostSignificant}
        depth={5}
        size={glyphSize}
        foreground={foreground}
        background={background}
      />
      <OctalGlyph
        {...glyphProps}
        decorative={glyphProps?.decorative ?? true}
        value={leastSignificant}
        depth={5}
        size={glyphSize}
        foreground={foreground}
        background={background}
      />
    </span>
  );
}
