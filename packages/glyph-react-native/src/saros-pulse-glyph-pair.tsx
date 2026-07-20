import { StyleSheet, View, type ViewProps } from "react-native";

import { OctalGlyph, type OctalGlyphProps } from "./octal-glyph";

export interface SarosPulseGlyphPairProps extends Omit<ViewProps, "children"> {
  readonly mostSignificant: string;
  readonly leastSignificant: string;
  readonly glyphSize?: OctalGlyphProps["size"];
  readonly foreground?: string;
  readonly background?: string;
  readonly glyphProps?: Omit<
    OctalGlyphProps,
    "value" | "depth" | "size" | "foreground" | "background"
  >;
}

/** Renders the canonical ten-digit realtime pulse as two five-digit glyphs. */
export function SarosPulseGlyphPair({
  mostSignificant,
  leastSignificant,
  glyphSize = 32,
  foreground,
  background,
  glyphProps,
  style,
  ...viewProps
}: SarosPulseGlyphPairProps) {
  return (
    <View {...viewProps} style={[styles.pair, style]}>
      <OctalGlyph
        {...glyphProps}
        {...(background === undefined ? {} : { background })}
        decorative={glyphProps?.decorative ?? true}
        depth={5}
        {...(foreground === undefined ? {} : { foreground })}
        size={glyphSize}
        value={mostSignificant}
      />
      <OctalGlyph
        {...glyphProps}
        {...(background === undefined ? {} : { background })}
        decorative={glyphProps?.decorative ?? true}
        depth={5}
        {...(foreground === undefined ? {} : { foreground })}
        size={glyphSize}
        value={leastSignificant}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  pair: {
    alignItems: "center",
    flexDirection: "row",
    gap: 5,
  },
});
