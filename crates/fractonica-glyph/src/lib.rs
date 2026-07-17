#![no_std]
#![forbid(unsafe_code)]
//! Canonical Fractonica octal glyph grammar and default outline font.
//!
//! A glyph address is MSB-first octal. Each digit is a semantic three-bit
//! mask: bit `1` enables the left connection, bit `2` the centre connection,
//! and bit `4` the right connection on a rhombic lattice. That grammar is
//! deliberately independent from its visual form.
//!
//! The bundled `fractonica-hex-v2` font depicts each of the eight masks with
//! one filled, socket-local outline plus a compound even-odd core ring. Other
//! [`GlyphFont`] values can use different outline data without changing what
//! an address means. The core stays allocation-free and can emit vector
//! contours or rasterise raw RGBA8 directly into caller-owned memory.

#[cfg(feature = "alloc")]
extern crate alloc;

use core::{f32::consts::PI, fmt};

use libm::{ceilf, cosf, sinf, sqrtf};

/// A point in the canonical glyph coordinate plane.
///
/// The origin is the glyph centre, positive X points right, positive Y points
/// down, and positive rotation is clockwise. Default geometry uses the
/// bundled font's native units; [`GlyphConfig::radius`] is a scale factor for
/// those units.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct GlyphPoint {
    pub x: f32,
    pub y: f32,
}

impl GlyphPoint {
    pub const ZERO: Self = Self { x: 0.0, y: 0.0 };

    #[must_use]
    pub const fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }
}

mod spec_generated;

pub use spec_generated::{
    DEFAULT_DIGITS, FONT_ID, FONT_SHA256, FONT_VERSION, GEOMETRY_VERSION, GRAMMAR_SHA256,
    GRAMMAR_VERSION, MAX_DIGITS, MIN_DIGITS, RADIX, SPEC_SHA256,
};

/// The bit that connects a digit anchor to its left lattice vertex.
pub const STROKE_LEFT: u8 = spec_generated::STROKE_LEFT;
/// The bit that connects a digit anchor to its apex lattice vertex.
pub const STROKE_CENTRE: u8 = spec_generated::STROKE_CENTRE;
/// The bit that connects a digit anchor to its right lattice vertex.
pub const STROKE_RIGHT: u8 = spec_generated::STROKE_RIGHT;
/// Maximum number of points in a default-font arm template.
pub const MAX_FONT_ARM_POINTS: usize = spec_generated::MAX_FONT_ARM_POINTS;
/// Maximum points in a core or generic inset-hole contour.
pub const MAX_POLYGON_POINTS: usize = (MAX_DIGITS as usize) * 2;
/// The compound core has an outer contour and a hole.
pub const MAX_CONTOURS_PER_PRIMITIVE: usize = 2;
/// A glyph emits one compound core plus at most one arm per socket.
pub const MAX_PRIMITIVES: usize = 1 + MAX_DIGITS as usize;
/// The deterministic RGBA8 sample grid used by [`OctalGlyph::rasterize_rgba8`].
pub const RASTER_SUBPIXEL_GRID: usize = 4;

/// A filled-outline font compatible with the canonical octal grammar.
///
/// Arm points are in socket-local font units: X follows the socket chord and
/// positive Y travels outward from the core. The first and last points are
/// snapped to the actual socket chord, allowing the same font to scale and
/// rotate cleanly at every supported depth. Digit zero may use a two-point
/// degenerate outline to indicate an invisible arm.
#[derive(Clone, Copy, Debug)]
pub struct GlyphFont<'a> {
    pub id: &'a str,
    pub version: &'a str,
    pub geometry_version: &'a str,
    /// Optional combined grammar-plus-font source digest. A custom font can
    /// leave this unset while being designed, but should set it before its
    /// geometry is persisted or exchanged.
    pub source_sha256: Option<&'a str>,
    pub units: f32,
    pub socket_width: f32,
    pub core_radius: f32,
    pub inset_thickness: f32,
    pub grid_size: f32,
    pub padding_cells: f32,
    /// Exact outer core contour for the historical Hex v2 six-socket design.
    /// Other supported depths derive a regular core from the same metrics.
    pub legacy_core_outer_depth: u8,
    pub legacy_core_outer: &'a [GlyphPoint],
    /// Exact aperture contour paired with [`Self::legacy_core_outer`].
    pub legacy_core_hole_depth: u8,
    pub legacy_core_hole: &'a [GlyphPoint],
    pub arm_points: &'a [[GlyphPoint; MAX_FONT_ARM_POINTS]; RADIX as usize],
    pub arm_point_counts: &'a [u8; RADIX as usize],
}

impl<'a> GlyphFont<'a> {
    #[must_use]
    pub fn arm(self, digit: u8) -> Option<&'a [GlyphPoint]> {
        let index = usize::from(digit);
        let points = self.arm_points.get(index)?;
        let count = usize::from(*self.arm_point_counts.get(index)?);
        points.get(..count)
    }
}

/// The default visual font, ported from the verified Hex v2 source and used
/// by SwiftUI and embedded renderers. Its identity and digest are exposed by
/// the node API.
pub const DEFAULT_GLYPH_FONT: GlyphFont<'static> = GlyphFont {
    id: spec_generated::FONT_ID,
    version: spec_generated::FONT_VERSION,
    geometry_version: spec_generated::GEOMETRY_VERSION,
    source_sha256: Some(spec_generated::SPEC_SHA256),
    units: spec_generated::FONT_UNITS,
    socket_width: spec_generated::FONT_SOCKET_WIDTH,
    core_radius: spec_generated::FONT_CORE_RADIUS,
    inset_thickness: spec_generated::FONT_INSET_THICKNESS,
    grid_size: spec_generated::FONT_GRID_SIZE,
    padding_cells: spec_generated::FONT_PADDING_CELLS,
    legacy_core_outer_depth: spec_generated::FONT_LEGACY_OUTER_DEPTH,
    legacy_core_outer: &spec_generated::FONT_LEGACY_OUTER,
    legacy_core_hole_depth: spec_generated::FONT_LEGACY_HOLE_DEPTH,
    legacy_core_hole: &spec_generated::FONT_LEGACY_HOLE,
    arm_points: &spec_generated::FONT_ARMS,
    arm_point_counts: &spec_generated::FONT_ARM_POINT_COUNTS,
};

/// A fixed bounding frame that is stable for every value at one glyph depth.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GlyphFrame {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl GlyphFrame {
    #[must_use]
    pub const fn aspect_ratio(self) -> f32 {
        self.width / self.height
    }
}

/// A configured radial layout for one glyph.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GlyphConfig {
    pub center_x: f32,
    pub center_y: f32,
    /// Scale multiplier applied to the selected font's native coordinate units.
    pub radius: f32,
    /// Clockwise radians in the positive-Y-down coordinate system.
    pub rotation_radians: f32,
}

impl Default for GlyphConfig {
    fn default() -> Self {
        Self {
            center_x: 0.0,
            center_y: 0.0,
            radius: 1.0,
            rotation_radians: 0.0,
        }
    }
}

/// One semantic stroke carried by an octal digit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlyphStroke {
    Left,
    Centre,
    Right,
}

impl GlyphStroke {
    #[must_use]
    pub const fn bit(self) -> u8 {
        match self {
            Self::Left => STROKE_LEFT,
            Self::Centre => STROKE_CENTRE,
            Self::Right => STROKE_RIGHT,
        }
    }

    #[must_use]
    pub const fn wire_id(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Centre => "centre",
            Self::Right => "right",
        }
    }
}

/// Fill rule for an emitted contour collection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlyphFillRule {
    NonZero,
    EvenOdd,
}

impl GlyphFillRule {
    #[must_use]
    pub const fn wire_id(self) -> &'static str {
        match self {
            Self::NonZero => "nonzero",
            Self::EvenOdd => "evenodd",
        }
    }
}

/// One semantic filled outline in a glyph plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlyphPrimitiveKind {
    /// A compound outer ring plus central hole.
    Core,
    /// One complete font outline for a non-zero octal digit.
    Arm,
}

impl GlyphPrimitiveKind {
    #[must_use]
    pub const fn wire_id(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Arm => "arm",
        }
    }
}

/// A temporary view of one contour. Its points are valid only for the callback
/// invocation that receives the enclosing [`GlyphPrimitive`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GlyphContour<'a> {
    pub points: &'a [GlyphPoint],
}

/// A temporary view of an emitted, fillable glyph outline.
///
/// Its contour slices are valid only for the callback invocation that receives
/// it. The core always has two contours and uses even-odd filling; each arm has
/// one contour and uses non-zero filling.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GlyphPrimitive<'a> {
    pub kind: GlyphPrimitiveKind,
    pub fill_rule: GlyphFillRule,
    pub socket_index: Option<u8>,
    pub digit_index: Option<u8>,
    pub digit: Option<u8>,
    pub contours: &'a [GlyphContour<'a>],
}

/// Result metadata for a completed or aborted outline emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlyphEmitResult {
    pub depth: u8,
    pub emitted_primitive_count: u16,
}

/// Input and rendering errors returned before mutable output is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GlyphError {
    InvalidDepth(u8),
    EmptyOctalText,
    InputTooLong { length: usize, depth: u8 },
    InvalidOctalDigit { index: usize, byte: u8 },
    OutputTooSmall { required: usize, actual: usize },
    InvalidRadius,
    InvalidRotation,
    InvalidFont,
    InvalidRasterDimensions { width: u16, height: u16 },
    InvalidRasterBufferLength { required: usize, actual: usize },
    CallbackAborted,
}

impl fmt::Display for GlyphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDepth(depth) => write!(
                formatter,
                "glyph depth must be between {MIN_DIGITS} and {MAX_DIGITS}, got {depth}"
            ),
            Self::EmptyOctalText => {
                formatter.write_str("glyph text must contain at least one octal digit")
            }
            Self::InputTooLong { length, depth } => {
                write!(
                    formatter,
                    "glyph text has {length} digits but depth is {depth}"
                )
            }
            Self::InvalidOctalDigit { index, byte } => write!(
                formatter,
                "glyph text byte {index} must be ASCII octal 0 through 7, got 0x{byte:02x}"
            ),
            Self::OutputTooSmall { required, actual } => write!(
                formatter,
                "glyph output buffer requires {required} bytes, received {actual}"
            ),
            Self::InvalidRadius => formatter
                .write_str("glyph font scale and centre must be finite; scale must be positive"),
            Self::InvalidRotation => formatter.write_str("glyph rotation must be finite"),
            Self::InvalidFont => formatter.write_str("glyph font data is invalid"),
            Self::InvalidRasterDimensions { width, height } => {
                write!(
                    formatter,
                    "glyph raster dimensions must be positive, got {width}x{height}"
                )
            }
            Self::InvalidRasterBufferLength { required, actual } => write!(
                formatter,
                "glyph raster buffer requires {required} bytes, received {actual}"
            ),
            Self::CallbackAborted => formatter.write_str("glyph emission callback aborted"),
        }
    }
}

impl core::error::Error for GlyphError {}

/// A validated, left-padded MSB-first octal glyph value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OctalGlyph {
    depth: u8,
    digits: [u8; MAX_DIGITS as usize],
}

impl OctalGlyph {
    /// Parses explicit ASCII octal text. Short values are left-padded with
    /// zeroes. Values longer than `depth` are rejected so no meaningful MSB
    /// address is silently lost.
    pub fn parse(depth: u8, octal_text: &str) -> Result<Self, GlyphError> {
        Self::from_ascii(depth, octal_text.as_bytes())
    }

    /// Parses explicit ASCII octal bytes. Useful at C/FFI boundaries where
    /// input is not necessarily a UTF-8 Rust string.
    pub fn from_ascii(depth: u8, octal_text: &[u8]) -> Result<Self, GlyphError> {
        validate_depth(depth)?;
        if octal_text.is_empty() {
            return Err(GlyphError::EmptyOctalText);
        }
        if octal_text.len() > depth as usize {
            return Err(GlyphError::InputTooLong {
                length: octal_text.len(),
                depth,
            });
        }

        let mut digits = [0_u8; MAX_DIGITS as usize];
        let padding = depth as usize - octal_text.len();
        for (index, byte) in octal_text.iter().copied().enumerate() {
            if !(b'0'..=b'7').contains(&byte) {
                return Err(GlyphError::InvalidOctalDigit { index, byte });
            }
            digits[padding + index] = byte - b'0';
        }
        Ok(Self { depth, digits })
    }

    /// Creates a glyph from numeric octal digits with the same strict length
    /// and left-padding contract as [`Self::from_ascii`].
    pub fn from_digits(depth: u8, input: &[u8]) -> Result<Self, GlyphError> {
        validate_depth(depth)?;
        if input.is_empty() {
            return Err(GlyphError::EmptyOctalText);
        }
        if input.len() > depth as usize {
            return Err(GlyphError::InputTooLong {
                length: input.len(),
                depth,
            });
        }

        let mut digits = [0_u8; MAX_DIGITS as usize];
        let padding = depth as usize - input.len();
        for (index, digit) in input.iter().copied().enumerate() {
            if digit >= RADIX {
                return Err(GlyphError::InvalidOctalDigit { index, byte: digit });
            }
            digits[padding + index] = digit;
        }
        Ok(Self { depth, digits })
    }

    #[must_use]
    pub const fn depth(self) -> u8 {
        self.depth
    }

    /// Digits in their normalized MSB-first order.
    #[must_use]
    pub fn digits(&self) -> &[u8] {
        &self.digits[..self.depth as usize]
    }

    #[must_use]
    pub const fn digit_at(self, index: u8) -> Option<u8> {
        if index < self.depth {
            Some(self.digits[index as usize])
        } else {
            None
        }
    }

    /// Writes the complete normalized value as ASCII octal. `output` can be
    /// longer than the depth; only the first depth bytes are written.
    pub fn write_normalized_ascii(self, output: &mut [u8]) -> Result<(), GlyphError> {
        let required = self.depth as usize;
        if output.len() < required {
            return Err(GlyphError::OutputTooSmall {
                required,
                actual: output.len(),
            });
        }
        for (index, destination) in output.iter_mut().take(required).enumerate() {
            *destination = b'0' + self.digits[index];
        }
        Ok(())
    }

    /// Returns which normalized MSB-first input digit belongs to a radial
    /// socket. Socket 0 holds the first digit, then sockets walk backwards
    /// from the least significant digit: `12345` becomes `1, 5, 4, 3, 2`.
    #[must_use]
    pub const fn digit_index_for_socket(depth: u8, socket_index: u8) -> Option<u8> {
        if depth < MIN_DIGITS || depth > MAX_DIGITS || socket_index >= depth {
            return None;
        }
        if socket_index == 0 {
            Some(0)
        } else {
            Some(depth - socket_index)
        }
    }

    /// Returns the semantic three-bit lattice-stroke mask for an octal digit.
    #[must_use]
    pub const fn stroke_mask(digit: u8) -> Option<u8> {
        if digit < RADIX { Some(digit) } else { None }
    }

    /// Emits the default font's compound core and complete arm outlines.
    pub fn emit(
        self,
        config: GlyphConfig,
        callback: impl FnMut(GlyphPrimitive<'_>) -> bool,
    ) -> Result<GlyphEmitResult, GlyphError> {
        self.emit_with_font(&DEFAULT_GLYPH_FONT, config, callback)
    }

    /// Emits deterministic, filled outlines using a caller-supplied font.
    ///
    /// The callback owns no memory: all contour slices are valid only for its
    /// duration. This keeps microcontroller use allocation-free.
    pub fn emit_with_font(
        self,
        font: &GlyphFont<'_>,
        config: GlyphConfig,
        mut callback: impl FnMut(GlyphPrimitive<'_>) -> bool,
    ) -> Result<GlyphEmitResult, GlyphError> {
        validate_config(config)?;
        validate_font(font)?;
        let mut result = GlyphEmitResult {
            depth: self.depth,
            emitted_primitive_count: 0,
        };

        let mut core_outer = [GlyphPoint::ZERO; MAX_POLYGON_POINTS];
        let core_outer_count = make_core_outer(self.depth, font, config, &mut core_outer);
        let mut core_hole = [GlyphPoint::ZERO; MAX_POLYGON_POINTS];
        let core_hole_count = make_core_hole(
            self.depth,
            font,
            config,
            &core_outer[..core_outer_count],
            &mut core_hole,
        );
        let core_contours = [
            GlyphContour {
                points: &core_outer[..core_outer_count],
            },
            GlyphContour {
                points: &core_hole[..core_hole_count],
            },
        ];
        emit_primitive(
            &mut callback,
            &mut result,
            GlyphPrimitive {
                kind: GlyphPrimitiveKind::Core,
                fill_rule: GlyphFillRule::EvenOdd,
                socket_index: None,
                digit_index: None,
                digit: None,
                contours: &core_contours,
            },
        )?;

        for socket_index in 0..self.depth {
            let digit_index = Self::digit_index_for_socket(self.depth, socket_index)
                .expect("validated glyph depth and socket index");
            let digit = self.digits[digit_index as usize];
            let mut arm = [GlyphPoint::ZERO; MAX_FONT_ARM_POINTS];
            let arm_count = transform_arm(font, config, self.depth, socket_index, digit, &mut arm);
            if arm_count < 3 {
                continue;
            }
            let arm_contours = [GlyphContour {
                points: &arm[..arm_count],
            }];
            emit_primitive(
                &mut callback,
                &mut result,
                GlyphPrimitive {
                    kind: GlyphPrimitiveKind::Arm,
                    fill_rule: GlyphFillRule::NonZero,
                    socket_index: Some(socket_index),
                    digit_index: Some(digit_index),
                    digit: Some(digit),
                    contours: &arm_contours,
                },
            )?;
        }

        Ok(result)
    }

    /// Calculates an invariant frame for this glyph's depth using the default
    /// font. It includes every digit outline, not only active arms.
    pub fn frame(self, config: GlyphConfig) -> Result<GlyphFrame, GlyphError> {
        self.frame_with_font(&DEFAULT_GLYPH_FONT, config)
    }

    /// Calculates a value-invariant, font-grid-snapped frame for this depth.
    pub fn frame_with_font(
        self,
        font: &GlyphFont<'_>,
        config: GlyphConfig,
    ) -> Result<GlyphFrame, GlyphError> {
        validate_config(config)?;
        validate_font(font)?;
        let mut core_outer = [GlyphPoint::ZERO; MAX_POLYGON_POINTS];
        let core_outer_count = make_core_outer(self.depth, font, config, &mut core_outer);
        let mut core_hole = [GlyphPoint::ZERO; MAX_POLYGON_POINTS];
        let core_hole_count = make_core_hole(
            self.depth,
            font,
            config,
            &core_outer[..core_outer_count],
            &mut core_hole,
        );
        let mut accumulator = FrameAccumulator::default();
        accumulator.include_all(&core_outer[..core_outer_count]);
        accumulator.include_all(&core_hole[..core_hole_count]);

        let mut arm = [GlyphPoint::ZERO; MAX_FONT_ARM_POINTS];
        for socket_index in 0..self.depth {
            for digit in 0..RADIX {
                let count = transform_arm(font, config, self.depth, socket_index, digit, &mut arm);
                accumulator.include_all(&arm[..count]);
            }
        }
        Ok(accumulator.finish(font, config))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct SocketFrame {
    centre: GlyphPoint,
    tangent: GlyphPoint,
    outward: GlyphPoint,
    length: f32,
}

impl SocketFrame {
    fn local_to_world(self, tangent_distance: f32, outward_distance: f32) -> GlyphPoint {
        add(
            add(self.centre, scale(self.tangent, tangent_distance)),
            scale(self.outward, outward_distance),
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct FrameAccumulator {
    min_x: f32,
    min_y: f32,
    max_x: f32,
    max_y: f32,
    initialized: bool,
}

impl Default for FrameAccumulator {
    fn default() -> Self {
        Self {
            min_x: 0.0,
            min_y: 0.0,
            max_x: 0.0,
            max_y: 0.0,
            initialized: false,
        }
    }
}

impl FrameAccumulator {
    fn include_all(&mut self, points: &[GlyphPoint]) {
        for point in points {
            if !self.initialized {
                self.min_x = point.x;
                self.max_x = point.x;
                self.min_y = point.y;
                self.max_y = point.y;
                self.initialized = true;
            } else {
                self.min_x = self.min_x.min(point.x);
                self.max_x = self.max_x.max(point.x);
                self.min_y = self.min_y.min(point.y);
                self.max_y = self.max_y.max(point.y);
            }
        }
    }

    fn finish(self, font: &GlyphFont<'_>, config: GlyphConfig) -> GlyphFrame {
        debug_assert!(self.initialized, "frame includes a core");
        let grid = font.grid_size * config.radius;
        let padding = grid * font.padding_cells;
        let max_x = absf(self.min_x - config.center_x).max(absf(self.max_x - config.center_x));
        let max_y = absf(self.min_y - config.center_y).max(absf(self.max_y - config.center_y));
        let half_width = ceilf(max_x / grid) * grid + padding;
        let half_height = ceilf(max_y / grid) * grid + padding;
        GlyphFrame {
            x: config.center_x - half_width,
            y: config.center_y - half_height,
            width: half_width * 2.0,
            height: half_height * 2.0,
        }
    }
}

fn validate_depth(depth: u8) -> Result<(), GlyphError> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&depth) {
        return Err(GlyphError::InvalidDepth(depth));
    }
    Ok(())
}

fn validate_config(config: GlyphConfig) -> Result<(), GlyphError> {
    if !config.radius.is_finite()
        || config.radius <= 0.0
        || !config.center_x.is_finite()
        || !config.center_y.is_finite()
    {
        return Err(GlyphError::InvalidRadius);
    }
    if !config.rotation_radians.is_finite() {
        return Err(GlyphError::InvalidRotation);
    }
    Ok(())
}

fn validate_font(font: &GlyphFont<'_>) -> Result<(), GlyphError> {
    let numeric_values = [
        font.units,
        font.socket_width,
        font.core_radius,
        font.inset_thickness,
        font.grid_size,
        font.padding_cells,
    ];
    if font.id.is_empty()
        || font.version.is_empty()
        || font.geometry_version.is_empty()
        || numeric_values
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
        || !(3..=MAX_POLYGON_POINTS).contains(&font.legacy_core_outer.len())
        || !(3..=MAX_POLYGON_POINTS).contains(&font.legacy_core_hole.len())
        || !(MIN_DIGITS..=MAX_DIGITS).contains(&font.legacy_core_outer_depth)
        || font.legacy_core_outer.len() != usize::from(font.legacy_core_outer_depth) * 2
        || !(MIN_DIGITS..=MAX_DIGITS).contains(&font.legacy_core_hole_depth)
        || font
            .arm_point_counts
            .iter()
            .enumerate()
            .any(|(digit, count)| {
                let count = usize::from(*count);
                count > MAX_FONT_ARM_POINTS || (digit > 0 && count < 3) || (digit == 0 && count < 2)
            })
        || font
            .source_sha256
            .is_some_and(|digest| !is_lower_hex_digest(digest))
    {
        return Err(GlyphError::InvalidFont);
    }
    Ok(())
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn emit_primitive(
    callback: &mut impl FnMut(GlyphPrimitive<'_>) -> bool,
    result: &mut GlyphEmitResult,
    primitive: GlyphPrimitive<'_>,
) -> Result<(), GlyphError> {
    if !callback(primitive) {
        return Err(GlyphError::CallbackAborted);
    }
    result.emitted_primitive_count += 1;
    Ok(())
}

fn make_socket_frame(
    depth: u8,
    font: &GlyphFont<'_>,
    config: GlyphConfig,
    socket_index: u8,
) -> SocketFrame {
    if depth == font.legacy_core_outer_depth {
        let start_index = usize::from(socket_index) * 2;
        if let (Some(start), Some(end)) = (
            font.legacy_core_outer.get(start_index),
            font.legacy_core_outer.get(start_index + 1),
        ) {
            // The authored Hex v2 core is rounded to two decimals while a
            // trigonometric rotation produces tiny residuals. Derive the
            // socket directly from its authored chord so every arm endpoint
            // lands exactly on the compound core in non-Boolean renderers.
            let start = transform_global_point(config, *start);
            let end = transform_global_point(config, *end);
            let delta = GlyphPoint::new(end.x - start.x, end.y - start.y);
            let length = sqrtf(delta.x * delta.x + delta.y * delta.y).max(0.001);
            let tangent = GlyphPoint::new(delta.x / length, delta.y / length);
            return SocketFrame {
                centre: GlyphPoint::new((start.x + end.x) * 0.5, (start.y + end.y) * 0.5),
                tangent,
                outward: GlyphPoint::new(tangent.y, -tangent.x),
                length,
            };
        }
    }
    let angle = config.rotation_radians + 2.0 * PI * socket_index as f32 / depth as f32;
    let tangent = GlyphPoint::new(cosf(angle), sinf(angle));
    // Rotate the source font's top-facing `(0, -1)` radial vector clockwise
    // in the positive-Y-down plane. This keeps socket 1 upper-right, exactly
    // as the historical Hex v2 SVG is authored.
    let outward = GlyphPoint::new(sinf(angle), -cosf(angle));
    let centre = add(
        GlyphPoint::new(config.center_x, config.center_y),
        scale(outward, font.core_radius * config.radius),
    );
    SocketFrame {
        centre,
        tangent,
        outward,
        length: font.socket_width * config.radius,
    }
}

fn make_core_outer(
    depth: u8,
    font: &GlyphFont<'_>,
    config: GlyphConfig,
    output: &mut [GlyphPoint; MAX_POLYGON_POINTS],
) -> usize {
    if depth == font.legacy_core_outer_depth {
        for (index, point) in font.legacy_core_outer.iter().copied().enumerate() {
            output[index] = transform_global_point(config, point);
        }
        return font.legacy_core_outer.len();
    }
    for socket_index in 0..depth {
        let frame = make_socket_frame(depth, font, config, socket_index);
        let index = usize::from(socket_index) * 2;
        output[index] = frame.local_to_world(-frame.length * 0.5, 0.0);
        output[index + 1] = frame.local_to_world(frame.length * 0.5, 0.0);
    }
    usize::from(depth) * 2
}

fn make_core_hole(
    depth: u8,
    font: &GlyphFont<'_>,
    config: GlyphConfig,
    outer: &[GlyphPoint],
    output: &mut [GlyphPoint; MAX_POLYGON_POINTS],
) -> usize {
    if depth == font.legacy_core_hole_depth {
        for (index, point) in font.legacy_core_hole.iter().copied().enumerate() {
            output[index] = transform_global_point(config, point);
        }
        return font.legacy_core_hole.len();
    }
    inset_convex_polygon(outer, font.inset_thickness * config.radius, output)
}

fn transform_arm(
    font: &GlyphFont<'_>,
    config: GlyphConfig,
    depth: u8,
    socket_index: u8,
    digit: u8,
    output: &mut [GlyphPoint; MAX_FONT_ARM_POINTS],
) -> usize {
    let Some(points) = font.arm(digit) else {
        return 0;
    };
    if points.len() < 2 {
        return points.len();
    }
    let frame = make_socket_frame(depth, font, config, socket_index);
    for (index, point) in points.iter().copied().enumerate() {
        output[index] = if index == 0 {
            frame.local_to_world(-frame.length * 0.5, 0.0)
        } else if index + 1 == points.len() {
            frame.local_to_world(frame.length * 0.5, 0.0)
        } else {
            frame.local_to_world(point.x * config.radius, point.y * config.radius)
        };
    }
    points.len()
}

fn transform_global_point(config: GlyphConfig, point: GlyphPoint) -> GlyphPoint {
    let x = point.x * config.radius;
    let y = point.y * config.radius;
    let cosine = cosf(config.rotation_radians);
    let sine = sinf(config.rotation_radians);
    GlyphPoint::new(
        config.center_x + x * cosine - y * sine,
        config.center_y + x * sine + y * cosine,
    )
}

fn inset_convex_polygon(
    points: &[GlyphPoint],
    thickness: f32,
    output: &mut [GlyphPoint; MAX_POLYGON_POINTS],
) -> usize {
    if points.len() < 3 || thickness <= 0.0 {
        for (index, point) in points.iter().copied().enumerate() {
            output[index] = point;
        }
        return points.len();
    }
    let inward_sign = if signed_area(points) >= 0.0 {
        1.0
    } else {
        -1.0
    };
    let mut line_points = [GlyphPoint::ZERO; MAX_POLYGON_POINTS];
    let mut line_directions = [GlyphPoint::ZERO; MAX_POLYGON_POINTS];
    for (index, point) in points.iter().copied().enumerate() {
        let next = points[(index + 1) % points.len()];
        let dx = next.x - point.x;
        let dy = next.y - point.y;
        let length = sqrtf(dx * dx + dy * dy).max(0.001);
        let normal = GlyphPoint::new((-dy / length) * inward_sign, (dx / length) * inward_sign);
        line_points[index] = add(point, scale(normal, thickness));
        line_directions[index] = GlyphPoint::new(dx, dy);
    }
    for index in 0..points.len() {
        let previous = (index + points.len() - 1) % points.len();
        output[index] = intersect_lines(
            line_points[previous],
            line_directions[previous],
            line_points[index],
            line_directions[index],
        )
        .unwrap_or(points[index]);
    }
    points.len()
}

fn signed_area(points: &[GlyphPoint]) -> f32 {
    points
        .iter()
        .enumerate()
        .map(|(index, point)| {
            let next = points[(index + 1) % points.len()];
            point.x * next.y - next.x * point.y
        })
        .sum()
}

fn intersect_lines(
    point_a: GlyphPoint,
    direction_a: GlyphPoint,
    point_b: GlyphPoint,
    direction_b: GlyphPoint,
) -> Option<GlyphPoint> {
    let cross = direction_a.x * direction_b.y - direction_a.y * direction_b.x;
    if absf(cross) < 0.000_001 {
        return None;
    }
    let delta = GlyphPoint::new(point_b.x - point_a.x, point_b.y - point_a.y);
    let t = (delta.x * direction_b.y - delta.y * direction_b.x) / cross;
    Some(GlyphPoint::new(
        point_a.x + direction_a.x * t,
        point_a.y + direction_a.y * t,
    ))
}

const fn add(left: GlyphPoint, right: GlyphPoint) -> GlyphPoint {
    GlyphPoint::new(left.x + right.x, left.y + right.y)
}

const fn scale(point: GlyphPoint, scalar: f32) -> GlyphPoint {
    GlyphPoint::new(point.x * scalar, point.y * scalar)
}

const fn absf(value: f32) -> f32 {
    if value < 0.0 { -value } else { value }
}

/// A straight-alpha RGBA colour. Raw raster bytes use this component order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rgba8 {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
    pub alpha: u8,
}

impl Rgba8 {
    pub const TRANSPARENT: Self = Self {
        red: 0,
        green: 0,
        blue: 0,
        alpha: 0,
    };
    pub const WHITE: Self = Self {
        red: 255,
        green: 255,
        blue: 255,
        alpha: 255,
    };
    pub const BLACK: Self = Self {
        red: 0,
        green: 0,
        blue: 0,
        alpha: 255,
    };

    #[must_use]
    pub const fn new(red: u8, green: u8, blue: u8, alpha: u8) -> Self {
        Self {
            red,
            green,
            blue,
            alpha,
        }
    }
}

/// Options for allocation-free RGBA8 rasterization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlyphRasterOptions {
    pub width: u16,
    pub height: u16,
    pub foreground: Rgba8,
    pub background: Rgba8,
}

impl Default for GlyphRasterOptions {
    fn default() -> Self {
        Self {
            width: 128,
            height: 128,
            foreground: Rgba8::WHITE,
            background: Rgba8::TRANSPARENT,
        }
    }
}

/// Metadata describing one caller-owned RGBA8 raster buffer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GlyphRasterInfo {
    pub width: u16,
    pub height: u16,
    pub stride_bytes: usize,
    pub byte_len: usize,
    pub frame: GlyphFrame,
}

#[derive(Clone, Copy)]
struct RasterContour {
    points: [GlyphPoint; MAX_POLYGON_POINTS],
    point_count: usize,
}

impl RasterContour {
    const EMPTY: Self = Self {
        points: [GlyphPoint::ZERO; MAX_POLYGON_POINTS],
        point_count: 0,
    };
}

#[derive(Clone, Copy)]
struct RasterPrimitive {
    fill_rule: GlyphFillRule,
    contours: [RasterContour; MAX_CONTOURS_PER_PRIMITIVE],
    contour_count: usize,
}

impl RasterPrimitive {
    const EMPTY: Self = Self {
        fill_rule: GlyphFillRule::NonZero,
        contours: [RasterContour::EMPTY; MAX_CONTOURS_PER_PRIMITIVE],
        contour_count: 0,
    };
}

impl OctalGlyph {
    /// Rasterizes this glyph with the default font into a caller-owned,
    /// row-major, straight-alpha `RGBA8` buffer.
    pub fn rasterize_rgba8(
        self,
        config: GlyphConfig,
        options: GlyphRasterOptions,
        output: &mut [u8],
    ) -> Result<GlyphRasterInfo, GlyphError> {
        self.rasterize_rgba8_with_font(&DEFAULT_GLYPH_FONT, config, options, output)
    }

    /// Rasterizes this glyph with an explicit font. The fixed 4×4 coverage
    /// grid is deterministic and needs neither an allocator nor a graphics
    /// dependency.
    pub fn rasterize_rgba8_with_font(
        self,
        font: &GlyphFont<'_>,
        config: GlyphConfig,
        options: GlyphRasterOptions,
        output: &mut [u8],
    ) -> Result<GlyphRasterInfo, GlyphError> {
        validate_config(config)?;
        validate_font(font)?;
        if options.width == 0 || options.height == 0 {
            return Err(GlyphError::InvalidRasterDimensions {
                width: options.width,
                height: options.height,
            });
        }
        let byte_len = options.width as usize * options.height as usize * 4;
        if output.len() != byte_len {
            return Err(GlyphError::InvalidRasterBufferLength {
                required: byte_len,
                actual: output.len(),
            });
        }

        let frame = self.frame_with_font(font, config)?;
        let mut primitives = [RasterPrimitive::EMPTY; MAX_PRIMITIVES];
        let mut primitive_count = 0_usize;
        self.emit_with_font(font, config, |primitive| {
            let Some(destination) = primitives.get_mut(primitive_count) else {
                return false;
            };
            destination.fill_rule = primitive.fill_rule;
            destination.contour_count = primitive.contours.len();
            for (index, contour) in primitive.contours.iter().enumerate() {
                destination.contours[index].point_count = contour.points.len();
                destination.contours[index].points[..contour.points.len()]
                    .copy_from_slice(contour.points);
            }
            primitive_count += 1;
            true
        })?;

        let scale = (options.width as f32 / frame.width).min(options.height as f32 / frame.height);
        let pad_x = (options.width as f32 - frame.width * scale) * 0.5;
        let pad_y = (options.height as f32 - frame.height * scale) * 0.5;
        let sample_count = (RASTER_SUBPIXEL_GRID * RASTER_SUBPIXEL_GRID) as u32;

        for pixel_y in 0..options.height as usize {
            for pixel_x in 0..options.width as usize {
                let mut alpha_sum = 0_u32;
                let mut red_premultiplied_sum = 0_u32;
                let mut green_premultiplied_sum = 0_u32;
                let mut blue_premultiplied_sum = 0_u32;

                for sub_y in 0..RASTER_SUBPIXEL_GRID {
                    for sub_x in 0..RASTER_SUBPIXEL_GRID {
                        let screen_x =
                            pixel_x as f32 + (sub_x as f32 + 0.5) / RASTER_SUBPIXEL_GRID as f32;
                        let screen_y =
                            pixel_y as f32 + (sub_y as f32 + 0.5) / RASTER_SUBPIXEL_GRID as f32;
                        let point = GlyphPoint::new(
                            frame.x + (screen_x - pad_x) / scale,
                            frame.y + (screen_y - pad_y) / scale,
                        );
                        let mut colour = options.background;
                        for primitive in primitives[..primitive_count].iter() {
                            if point_in_primitive(point, primitive) {
                                colour = options.foreground;
                            }
                        }
                        alpha_sum += u32::from(colour.alpha);
                        red_premultiplied_sum += u32::from(colour.red) * u32::from(colour.alpha);
                        green_premultiplied_sum +=
                            u32::from(colour.green) * u32::from(colour.alpha);
                        blue_premultiplied_sum += u32::from(colour.blue) * u32::from(colour.alpha);
                    }
                }

                let index = (pixel_y * options.width as usize + pixel_x) * 4;
                let averaged_alpha = (alpha_sum + sample_count / 2) / sample_count;
                let rounded_half = alpha_sum / 2;
                let red = (red_premultiplied_sum + rounded_half).checked_div(alpha_sum);
                let green = (green_premultiplied_sum + rounded_half).checked_div(alpha_sum);
                let blue = (blue_premultiplied_sum + rounded_half).checked_div(alpha_sum);
                if let (Some(red), Some(green), Some(blue)) = (red, green, blue) {
                    output[index] = red as u8;
                    output[index + 1] = green as u8;
                    output[index + 2] = blue as u8;
                    output[index + 3] = averaged_alpha as u8;
                } else {
                    output[index..index + 4].fill(0);
                }
            }
        }

        Ok(GlyphRasterInfo {
            width: options.width,
            height: options.height,
            stride_bytes: options.width as usize * 4,
            byte_len,
            frame,
        })
    }
}

fn point_in_primitive(point: GlyphPoint, primitive: &RasterPrimitive) -> bool {
    match primitive.fill_rule {
        GlyphFillRule::EvenOdd => {
            primitive.contours[..primitive.contour_count]
                .iter()
                .filter(|contour| point_in_polygon(point, &contour.points[..contour.point_count]))
                .count()
                % 2
                == 1
        }
        GlyphFillRule::NonZero => {
            primitive.contours[..primitive.contour_count]
                .iter()
                .map(|contour| winding_number(point, &contour.points[..contour.point_count]))
                .sum::<i32>()
                != 0
        }
    }
}

fn point_in_polygon(point: GlyphPoint, polygon: &[GlyphPoint]) -> bool {
    winding_number(point, polygon) != 0
}

fn winding_number(point: GlyphPoint, polygon: &[GlyphPoint]) -> i32 {
    if polygon.len() < 3 {
        return 0;
    }
    let mut winding = 0_i32;
    let mut previous = polygon[polygon.len() - 1];
    for current in polygon {
        if previous.y <= point.y {
            if current.y > point.y && is_left(previous, *current, point) > 0.0 {
                winding += 1;
            }
        } else if current.y <= point.y && is_left(previous, *current, point) < 0.0 {
            winding -= 1;
        }
        previous = *current;
    }
    winding
}

fn is_left(start: GlyphPoint, end: GlyphPoint, point: GlyphPoint) -> f32 {
    (end.x - start.x) * (point.y - start.y) - (point.x - start.x) * (end.y - start.y)
}

#[cfg(feature = "alloc")]
mod allocated {
    use alloc::vec::Vec;

    use super::*;

    /// An owned contour suitable for serialisation and retained renderer state.
    #[derive(Clone, Debug, PartialEq)]
    pub struct OwnedGlyphContour {
        pub points: Vec<GlyphPoint>,
    }

    /// An owned outline suitable for host transports such as JSON and SVG.
    #[derive(Clone, Debug, PartialEq)]
    pub struct OwnedGlyphPrimitive {
        pub kind: GlyphPrimitiveKind,
        pub fill_rule: GlyphFillRule,
        pub socket_index: Option<u8>,
        pub digit_index: Option<u8>,
        pub digit: Option<u8>,
        pub contours: Vec<OwnedGlyphContour>,
    }

    impl OctalGlyph {
        /// Materializes the default font's callback geometry into owned vectors.
        /// Embedded callers should use [`Self::emit`] instead.
        pub fn collect_primitives(
            self,
            config: GlyphConfig,
        ) -> Result<Vec<OwnedGlyphPrimitive>, GlyphError> {
            self.collect_primitives_with_font(&DEFAULT_GLYPH_FONT, config)
        }

        /// Materializes callback geometry from an explicit font.
        pub fn collect_primitives_with_font(
            self,
            font: &GlyphFont<'_>,
            config: GlyphConfig,
        ) -> Result<Vec<OwnedGlyphPrimitive>, GlyphError> {
            let mut primitives = Vec::with_capacity(MAX_PRIMITIVES);
            self.emit_with_font(font, config, |primitive| {
                primitives.push(OwnedGlyphPrimitive {
                    kind: primitive.kind,
                    fill_rule: primitive.fill_rule,
                    socket_index: primitive.socket_index,
                    digit_index: primitive.digit_index,
                    digit: primitive.digit,
                    contours: primitive
                        .contours
                        .iter()
                        .map(|contour| OwnedGlyphContour {
                            points: contour.points.to_vec(),
                        })
                        .collect(),
                });
                true
            })?;
            Ok(primitives)
        }
    }
}

#[cfg(feature = "alloc")]
pub use allocated::{OwnedGlyphContour, OwnedGlyphPrimitive};

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;

    fn primitives(glyph: OctalGlyph) -> Vec<GlyphPrimitiveKind> {
        let mut result = Vec::new();
        glyph
            .emit(GlyphConfig::default(), |primitive| {
                result.push(primitive.kind);
                true
            })
            .expect("valid glyph");
        result
    }

    #[test]
    fn retains_the_canonical_one_two_four_semantic_mask() {
        assert_eq!(OctalGlyph::stroke_mask(1), Some(STROKE_LEFT));
        assert_eq!(OctalGlyph::stroke_mask(2), Some(STROKE_CENTRE));
        assert_eq!(OctalGlyph::stroke_mask(4), Some(STROKE_RIGHT));
        assert_eq!(OctalGlyph::stroke_mask(7), Some(7));
        assert_eq!(OctalGlyph::stroke_mask(8), None);
        assert_eq!(
            primitives(OctalGlyph::parse(3, "7").expect("glyph")),
            [GlyphPrimitiveKind::Core, GlyphPrimitiveKind::Arm]
        );
    }

    #[test]
    fn normalizes_msb_first_and_uses_the_established_socket_order() {
        let glyph = OctalGlyph::parse(5, "12345").expect("glyph");
        let mut normalized = [0_u8; MAX_DIGITS as usize];
        glyph
            .write_normalized_ascii(&mut normalized)
            .expect("buffer is enough");
        assert_eq!(&normalized[..5], b"12345");
        assert_eq!(
            (0..5)
                .map(|socket| glyph.digit_at(OctalGlyph::digit_index_for_socket(5, socket).unwrap()))
                .collect::<Vec<_>>(),
            [Some(1), Some(5), Some(4), Some(3), Some(2)]
        );
    }

    #[test]
    fn custom_fonts_change_geometry_without_changing_octal_semantics() {
        let custom = GlyphFont {
            id: "example-outline",
            version: "0.1.0",
            geometry_version: "example-geometry-1",
            source_sha256: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            core_radius: 80.0,
            ..DEFAULT_GLYPH_FONT
        };
        let outlines = OctalGlyph::parse(3, "700")
            .expect("glyph")
            .collect_primitives_with_font(&custom, GlyphConfig::default())
            .expect("outlines");
        assert_eq!(OctalGlyph::stroke_mask(7), Some(7));
        assert_close(
            outlines[0].contours[0].points[0],
            GlyphPoint::new(-8.0, -80.0),
        );
        assert_eq!(outlines[1].digit, Some(7));
    }

    #[test]
    fn rejects_ambiguous_or_invalid_input_before_emission() {
        assert_eq!(OctalGlyph::parse(5, ""), Err(GlyphError::EmptyOctalText));
        assert_eq!(
            OctalGlyph::parse(5, "123456"),
            Err(GlyphError::InputTooLong {
                length: 6,
                depth: 5
            })
        );
        assert_eq!(
            OctalGlyph::parse(5, "18"),
            Err(GlyphError::InvalidOctalDigit {
                index: 1,
                byte: b'8'
            })
        );
    }

    #[test]
    fn hex_v2_font_matches_the_verified_depth_six_fixture() {
        let glyph = OctalGlyph::parse(6, "777777").expect("glyph");
        let frame = glyph.frame(GlyphConfig::default()).expect("frame");
        assert_eq!(
            frame,
            GlyphFrame {
                x: -176.0,
                y: -200.0,
                width: 352.0,
                height: 400.0
            }
        );

        let outlines = glyph
            .collect_primitives(GlyphConfig::default())
            .expect("outlines");
        assert_eq!(outlines.len(), 7);
        assert_eq!(outlines[0].kind, GlyphPrimitiveKind::Core);
        assert_eq!(outlines[0].fill_rule, GlyphFillRule::EvenOdd);
        assert_eq!(outlines[0].contours[0].points.len(), 12);
        assert_eq!(outlines[0].contours[1].points.len(), 7);
        let first_arm = &outlines[1];
        assert_eq!(first_arm.kind, GlyphPrimitiveKind::Arm);
        assert_eq!(first_arm.socket_index, Some(0));
        assert_eq!(first_arm.digit, Some(7));
        assert_close(
            first_arm.contours[0].points[0],
            GlyphPoint::new(-8.0, -41.57),
        );
        assert_close(
            first_arm.contours[0].points[1],
            GlyphPoint::new(-40.0, -96.99),
        );

        // The source font rotates its top arm clockwise: socket 1 is on the
        // upper-right, not mirrored to the upper-left.
        let uniform = OctalGlyph::parse(6, "111111")
            .expect("glyph")
            .collect_primitives(GlyphConfig::default())
            .expect("outlines");
        assert_close(
            uniform[2].contours[0].points[0],
            GlyphPoint::new(32.0, -27.71),
        );
    }

    #[test]
    fn hex_v2_frames_are_depth_stable_and_raster_is_deterministic() {
        for depth in MIN_DIGITS..=MAX_DIGITS {
            let zero = OctalGlyph::parse(depth, "0").expect("glyph");
            let all = OctalGlyph::parse(depth, "77777777".get(..usize::from(depth)).unwrap())
                .expect("glyph");
            assert_eq!(
                zero.frame(GlyphConfig::default()).unwrap(),
                all.frame(GlyphConfig::default()).unwrap()
            );
        }

        let all = OctalGlyph::parse(5, "77777").expect("glyph");
        let options = GlyphRasterOptions {
            width: 64,
            height: 64,
            foreground: Rgba8::new(0x12, 0xAB, 0xEF, 0xFF),
            background: Rgba8::TRANSPARENT,
        };
        let mut first = [0_u8; 64 * 64 * 4];
        let mut second = [0_u8; 64 * 64 * 4];
        let info = all
            .rasterize_rgba8(GlyphConfig::default(), options, &mut first)
            .expect("raster");
        all.rasterize_rgba8(GlyphConfig::default(), options, &mut second)
            .expect("raster");
        assert_eq!(first, second);
        assert_eq!(info.byte_len, first.len());
        assert!(first.chunks_exact(4).any(|pixel| pixel[3] > 0));
        assert_eq!(
            first[(32 * 64 + 32) * 4 + 3],
            0,
            "core aperture is transparent"
        );
    }

    fn assert_close(actual: GlyphPoint, expected: GlyphPoint) {
        assert!(
            (actual.x - expected.x).abs() < 0.001,
            "x: {:?} != {:?}",
            actual,
            expected
        );
        assert!(
            (actual.y - expected.y).abs() < 0.001,
            "y: {:?} != {:?}",
            actual,
            expected
        );
    }
}
