/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Fractonica portable octal glyph geometry API.
 *
 * This header intentionally has no display, allocator, operating-system, or
 * transport dependency. A display adapter supplies a callback that consumes
 * each compound outline while its contours are valid.
 */

#ifndef FRACTONICA_EMBEDDED_GLYPH_H
#define FRACTONICA_EMBEDDED_GLYPH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fractonica/embedded/glyph_spec.generated.h"

#ifdef __cplusplus
extern "C" {
#endif

/** ABI version for this standalone glyph component. */
#define FRACTONICA_GLYPH_ABI_VERSION 2u

/** The octal alphabet has exactly eight digits: 0 through 7. */
#define FRACTONICA_GLYPH_OCTAL_RADIX FRACTONICA_GLYPH_SPEC_RADIX

/** A glyph has between three and eight sockets. */
#define FRACTONICA_GLYPH_MIN_DIGITS_PER_GLYPH FRACTONICA_GLYPH_SPEC_MIN_DIGITS
#define FRACTONICA_GLYPH_MAX_DIGITS_PER_GLYPH FRACTONICA_GLYPH_SPEC_MAX_DIGITS

/** Five digits are the Fractonica pulse-glyph default. */
#define FRACTONICA_GLYPH_DEFAULT_DIGITS_PER_GLYPH FRACTONICA_GLYPH_SPEC_DEFAULT_DIGITS

/** Canonical one-bit stroke masks for every octal digit. */
#define FRACTONICA_GLYPH_STROKE_LEFT FRACTONICA_GLYPH_SPEC_STROKE_LEFT
#define FRACTONICA_GLYPH_STROKE_CENTRE FRACTONICA_GLYPH_SPEC_STROKE_CENTRE
#define FRACTONICA_GLYPH_STROKE_RIGHT FRACTONICA_GLYPH_SPEC_STROKE_RIGHT

/** Largest individual contour: two points per socket. */
#define FRACTONICA_GLYPH_MAX_POLYGON_POINTS \
    (FRACTONICA_GLYPH_MAX_DIGITS_PER_GLYPH * 2u)

/** The core ring is the only compound outline in the bundled font. */
#define FRACTONICA_GLYPH_MAX_CONTOURS_PER_POLYGON 2u

/** A marker used when a polygon does not belong to a socket or input digit. */
#define FRACTONICA_GLYPH_NO_INDEX UINT8_MAX

typedef struct fractonica_glyph_point {
    float x;
    float y;
} fractonica_glyph_point_t;

/** A complete semantic outline in a glyph plan. */
typedef enum fractonica_glyph_polygon_kind {
    FRACTONICA_GLYPH_POLYGON_CORE = 1,
    FRACTONICA_GLYPH_POLYGON_ARM = 2,
} fractonica_glyph_polygon_kind_t;

/** Fill rule required to render a compound outline faithfully. */
typedef enum fractonica_glyph_fill_rule {
    FRACTONICA_GLYPH_FILL_NONZERO = 1,
    FRACTONICA_GLYPH_FILL_EVENODD = 2,
} fractonica_glyph_fill_rule_t;

/**
 * One closed contour of a compound glyph outline.
 *
 * Points and the contour itself are valid only during the callback that
 * receives the containing polygon. Never retain either pointer.
 */
typedef struct fractonica_glyph_contour {
    uint8_t point_count;
    const fractonica_glyph_point_t *points;
} fractonica_glyph_contour_t;

typedef struct fractonica_glyph_polygon {
    fractonica_glyph_polygon_kind_t kind;
    fractonica_glyph_fill_rule_t fill_rule;
    /** 0..digits_per_glyph-1 for an arm, otherwise NO_INDEX. */
    uint8_t socket_index;
    /** Index in the left-padded, MSB-first glyph value for an arm. */
    uint8_t digit_index;
    /** Octal value (0..7) represented by an arm, otherwise 0. */
    uint8_t digit;
    /** Core: outer contour plus aperture; arm: one font outline. */
    uint8_t contour_count;
    /** Valid only for the duration of the callback. Never retain this pointer. */
    const fractonica_glyph_contour_t *contours;
} fractonica_glyph_polygon_t;

/**
 * Return true to continue emission.  Returning false stops immediately and
 * makes fractonica_glyph_emit_octal_text return CALLBACK_ABORTED.
 */
typedef bool (*fractonica_glyph_emit_callback_t)(
    void *context,
    const fractonica_glyph_polygon_t *polygon);

/**
 * `radius` is a scale multiplier applied to the selected font's native
 * coordinate units. Positive Y points down, which matches common display
 * APIs. The bundled Hex v2 font uses a native six-socket frame of
 * -176,-200,352,400 at radius 1.
 */
typedef struct fractonica_glyph_config {
    uint8_t digits_per_glyph;
    float center_x;
    float center_y;
    float radius;
    /** Clockwise rotation in a positive-Y-down coordinate system. */
    float rotation_radians;
} fractonica_glyph_config_t;

typedef struct fractonica_glyph_emit_result {
    uint8_t digits_per_glyph;
    uint8_t input_digit_count;
    uint16_t emitted_primitive_count;
} fractonica_glyph_emit_result_t;

typedef enum fractonica_glyph_status {
    FRACTONICA_GLYPH_STATUS_OK = 0,
    FRACTONICA_GLYPH_STATUS_INVALID_ARGUMENT = 1,
    FRACTONICA_GLYPH_STATUS_INVALID_DIGIT_COUNT = 2,
    FRACTONICA_GLYPH_STATUS_INVALID_RADIUS = 3,
    FRACTONICA_GLYPH_STATUS_INVALID_ROTATION = 4,
    FRACTONICA_GLYPH_STATUS_INPUT_TOO_LONG = 5,
    FRACTONICA_GLYPH_STATUS_INVALID_OCTAL_TEXT = 6,
    FRACTONICA_GLYPH_STATUS_CALLBACK_ABORTED = 7,
} fractonica_glyph_status_t;

/** Initializes a configuration for a five-digit glyph centered at (0, 0). */
void fractonica_glyph_config_init(fractonica_glyph_config_t *config);

/** Human-readable static string for diagnostics; never returns NULL. */
const char *fractonica_glyph_status_string(fractonica_glyph_status_t status);

/** Canonical generated grammar version shared with Rust, JS, and Swift. */
const char *fractonica_glyph_grammar_version(void);

/** Canonical generated filled-geometry version shared with Rust, JS, and Swift. */
const char *fractonica_glyph_geometry_version(void);

/** Canonical generated visual-font identity shared with Rust, JS, and Swift. */
const char *fractonica_glyph_font_id(void);

/** Canonical generated visual-font version shared with Rust, JS, and Swift. */
const char *fractonica_glyph_font_version(void);

/**
 * Returns the canonical 1/2/4 lattice-stroke bit mask for an octal digit.
 * Invalid digits return zero; valid zero also returns zero, so validate input
 * separately when that distinction matters.
 */
uint8_t fractonica_glyph_stroke_mask(uint8_t digit);

/**
 * Returns the input digit position for a socket in the canonical circular
 * order.  Socket zero carries the most significant digit; subsequent sockets
 * proceed around the glyph from least significant back toward most significant.
 *
 * For a five-digit value "12345", the socket order is: 1, 5, 4, 3, 2.
 * Returns FRACTONICA_GLYPH_NO_INDEX when digits_per_glyph or socket_index is
 * outside its supported range.
 */
uint8_t fractonica_glyph_digit_index_for_socket(
    uint8_t digits_per_glyph,
    uint8_t socket_index);

/**
 * Emits one glyph from an explicit-length, MSB-first octal string.
 *
 * `octal_text` must contain one through `digits_per_glyph` ASCII digits in
 * the inclusive range '0'..'7'.  Short values are left-padded with zeroes;
 * no implicit truncation or character filtering is performed.  All input and
 * configuration validation completes before the first callback.
 *
 * This function makes no heap allocations. It emits a core with an even-odd
 * aperture plus one non-zero-filled outline per nonzero digit. It uses only
 * fixed, bounded stack arrays sized for the generated font and the supported
 * maximum digit count.
 */
fractonica_glyph_status_t fractonica_glyph_emit_octal_text(
    const fractonica_glyph_config_t *config,
    const char *octal_text,
    size_t octal_text_length,
    fractonica_glyph_emit_callback_t callback,
    void *callback_context,
    fractonica_glyph_emit_result_t *out_result);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FRACTONICA_EMBEDDED_GLYPH_H */
