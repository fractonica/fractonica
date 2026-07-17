/* SPDX-License-Identifier: Apache-2.0 */

#include "fractonica/embedded/glyph.h"

#include <float.h>
#include <math.h>
#include <string.h>

/*
 * This is the allocation-free C port of the canonical outline construction.
 * The octal grammar (1 / 2 / 4) selects a font arm by its numeric mask. The
 * generated Hex v2 font then supplies the actual arbitrary outline, so the
 * visual typeface may evolve without changing the address semantics.
 */

static const float FRACTONICA_GLYPH_PI = 3.14159265358979323846f;

typedef struct fractonica_glyph_frame {
    fractonica_glyph_point_t center;
    fractonica_glyph_point_t tangent;
    fractonica_glyph_point_t outward;
    float length;
} fractonica_glyph_frame_t;

static bool fractonica_glyph_isfinite(float value) {
    return value == value && value <= FLT_MAX && value >= -FLT_MAX;
}

static fractonica_glyph_point_t fractonica_glyph_point_add(
    fractonica_glyph_point_t left,
    fractonica_glyph_point_t right) {
    fractonica_glyph_point_t result = {left.x + right.x, left.y + right.y};
    return result;
}

static fractonica_glyph_point_t fractonica_glyph_point_scale(
    fractonica_glyph_point_t point,
    float factor) {
    fractonica_glyph_point_t result = {point.x * factor, point.y * factor};
    return result;
}

static fractonica_glyph_point_t fractonica_glyph_local_to_world(
    const fractonica_glyph_frame_t *frame,
    float tangent_distance,
    float outward_distance) {
    fractonica_glyph_point_t result = frame->center;
    result = fractonica_glyph_point_add(
        result,
        fractonica_glyph_point_scale(frame->tangent, tangent_distance));
    result = fractonica_glyph_point_add(
        result,
        fractonica_glyph_point_scale(frame->outward, outward_distance));
    return result;
}

static fractonica_glyph_point_t fractonica_glyph_transform_global_point(
    const fractonica_glyph_config_t *config,
    fractonica_glyph_spec_point_t point);

static fractonica_glyph_frame_t fractonica_glyph_make_frame(
    const fractonica_glyph_config_t *config,
    uint8_t socket_index) {
    const float angle = config->rotation_radians +
                        (2.0f * FRACTONICA_GLYPH_PI * (float)socket_index /
                         (float)config->digits_per_glyph);
    fractonica_glyph_frame_t frame;

    /*
     * The rounded depth-six source contour is authoritative. Building its
     * socket frames from the emitted chord makes arm endpoints coincide with
     * it exactly, rather than leaving a sub-pixel trig-rounding gap.
     */
    if (config->digits_per_glyph == FRACTONICA_GLYPH_FONT_LEGACY_OUTER_DEPTH) {
        const uint8_t point_index = (uint8_t)(socket_index * 2u);
        const fractonica_glyph_point_t start = fractonica_glyph_transform_global_point(
            config,
            fractonica_glyph_font_legacy_outer[point_index]);
        const fractonica_glyph_point_t end = fractonica_glyph_transform_global_point(
            config,
            fractonica_glyph_font_legacy_outer[(uint8_t)(point_index + 1u)]);
        const float dx = end.x - start.x;
        const float dy = end.y - start.y;
        float length = sqrtf(dx * dx + dy * dy);
        const float radial_x = (start.x + end.x) * 0.5f - config->center_x;
        const float radial_y = (start.y + end.y) * 0.5f - config->center_y;

        if (length < 0.001f) {
            length = 0.001f;
        }
        frame.center.x = (start.x + end.x) * 0.5f;
        frame.center.y = (start.y + end.y) * 0.5f;
        frame.tangent.x = dx / length;
        frame.tangent.y = dy / length;
        frame.outward.x = frame.tangent.y;
        frame.outward.y = -frame.tangent.x;
        if (frame.outward.x * radial_x + frame.outward.y * radial_y < 0.0f) {
            frame.outward.x = -frame.outward.x;
            frame.outward.y = -frame.outward.y;
        }
        frame.length = length;
        return frame;
    }

    /*
     * In the canonical positive-Y-down plane this puts socket zero at twelve
     * o'clock. The outward vector is the +angle rotation of the default top
     * socket's upward normal. It is intentionally `(sin, -cos)`: this places
     * socket one on the upper-right side of the historical Hex v2 core.
     */
    frame.tangent.x = cosf(angle);
    frame.tangent.y = sinf(angle);
    frame.outward.x = sinf(angle);
    frame.outward.y = -cosf(angle);
    frame.center.x = config->center_x +
                     frame.outward.x * FRACTONICA_GLYPH_FONT_CORE_RADIUS * config->radius;
    frame.center.y = config->center_y +
                     frame.outward.y * FRACTONICA_GLYPH_FONT_CORE_RADIUS * config->radius;
    frame.length = FRACTONICA_GLYPH_FONT_SOCKET_WIDTH * config->radius;
    return frame;
}

static fractonica_glyph_point_t fractonica_glyph_transform_global_point(
    const fractonica_glyph_config_t *config,
    fractonica_glyph_spec_point_t point) {
    const float cosine = cosf(config->rotation_radians);
    const float sine = sinf(config->rotation_radians);
    const float x = point.x * config->radius;
    const float y = point.y * config->radius;
    fractonica_glyph_point_t result = {
        config->center_x + x * cosine - y * sine,
        config->center_y + x * sine + y * cosine,
    };
    return result;
}

static fractonica_glyph_status_t fractonica_glyph_validate(
    const fractonica_glyph_config_t *config,
    const char *octal_text,
    size_t octal_text_length,
    fractonica_glyph_emit_callback_t callback) {
    size_t index;

    if (config == NULL || octal_text == NULL || callback == NULL ||
        octal_text_length == 0u) {
        return FRACTONICA_GLYPH_STATUS_INVALID_ARGUMENT;
    }
    if (config->digits_per_glyph < FRACTONICA_GLYPH_MIN_DIGITS_PER_GLYPH ||
        config->digits_per_glyph > FRACTONICA_GLYPH_MAX_DIGITS_PER_GLYPH) {
        return FRACTONICA_GLYPH_STATUS_INVALID_DIGIT_COUNT;
    }
    if (!fractonica_glyph_isfinite(config->radius) || config->radius <= 0.0f ||
        !fractonica_glyph_isfinite(config->center_x) ||
        !fractonica_glyph_isfinite(config->center_y)) {
        return FRACTONICA_GLYPH_STATUS_INVALID_RADIUS;
    }
    if (!fractonica_glyph_isfinite(config->rotation_radians)) {
        return FRACTONICA_GLYPH_STATUS_INVALID_ROTATION;
    }
    if (octal_text_length > (size_t)config->digits_per_glyph) {
        return FRACTONICA_GLYPH_STATUS_INPUT_TOO_LONG;
    }
    for (index = 0u; index < octal_text_length; ++index) {
        if (octal_text[index] < '0' || octal_text[index] > '7') {
            return FRACTONICA_GLYPH_STATUS_INVALID_OCTAL_TEXT;
        }
    }
    return FRACTONICA_GLYPH_STATUS_OK;
}

static fractonica_glyph_status_t fractonica_glyph_emit_polygon(
    fractonica_glyph_emit_callback_t callback,
    void *context,
    fractonica_glyph_polygon_kind_t kind,
    fractonica_glyph_fill_rule_t fill_rule,
    uint8_t socket_index,
    uint8_t digit_index,
    uint8_t digit,
    const fractonica_glyph_contour_t *contours,
    uint8_t contour_count,
    fractonica_glyph_emit_result_t *result) {
    fractonica_glyph_polygon_t polygon;

    polygon.kind = kind;
    polygon.fill_rule = fill_rule;
    polygon.socket_index = socket_index;
    polygon.digit_index = digit_index;
    polygon.digit = digit;
    polygon.contour_count = contour_count;
    polygon.contours = contours;
    if (!callback(context, &polygon)) {
        return FRACTONICA_GLYPH_STATUS_CALLBACK_ABORTED;
    }
    result->emitted_primitive_count++;
    return FRACTONICA_GLYPH_STATUS_OK;
}

static uint8_t fractonica_glyph_make_core_outer(
    const fractonica_glyph_config_t *config,
    fractonica_glyph_point_t *output) {
    uint8_t socket_index;

    /*
     * The historical six-socket core contour is part of the bundled visual
     * font, not a lossy derivation. This is the contour used by the verified
     * 777777 reference SVG. Other supported depths derive the same radial
     * construction from the font metrics.
     */
    if (config->digits_per_glyph == FRACTONICA_GLYPH_FONT_LEGACY_OUTER_DEPTH) {
        for (socket_index = 0u;
             socket_index < FRACTONICA_GLYPH_FONT_LEGACY_OUTER_POINT_COUNT;
             ++socket_index) {
            output[socket_index] = fractonica_glyph_transform_global_point(
                config,
                fractonica_glyph_font_legacy_outer[socket_index]);
        }
        return FRACTONICA_GLYPH_FONT_LEGACY_OUTER_POINT_COUNT;
    }
    for (socket_index = 0u; socket_index < config->digits_per_glyph; ++socket_index) {
        const fractonica_glyph_frame_t frame =
            fractonica_glyph_make_frame(config, socket_index);
        const uint8_t point_index = (uint8_t)(socket_index * 2u);
        output[point_index] = fractonica_glyph_local_to_world(&frame, -frame.length * 0.5f, 0.0f);
        output[(uint8_t)(point_index + 1u)] =
            fractonica_glyph_local_to_world(&frame, frame.length * 0.5f, 0.0f);
    }
    return (uint8_t)(config->digits_per_glyph * 2u);
}

static float fractonica_glyph_signed_area(
    const fractonica_glyph_point_t *points,
    uint8_t point_count) {
    float area = 0.0f;
    uint8_t index;

    for (index = 0u; index < point_count; ++index) {
        const fractonica_glyph_point_t point = points[index];
        const fractonica_glyph_point_t next = points[(uint8_t)((index + 1u) % point_count)];
        area += point.x * next.y - next.x * point.y;
    }
    return area;
}

static bool fractonica_glyph_intersect_lines(
    fractonica_glyph_point_t point_a,
    fractonica_glyph_point_t direction_a,
    fractonica_glyph_point_t point_b,
    fractonica_glyph_point_t direction_b,
    fractonica_glyph_point_t *out_point) {
    const float cross = direction_a.x * direction_b.y - direction_a.y * direction_b.x;
    const float dx = point_b.x - point_a.x;
    const float dy = point_b.y - point_a.y;
    float distance;

    if (fabsf(cross) < 0.000001f) {
        return false;
    }
    distance = (dx * direction_b.y - dy * direction_b.x) / cross;
    out_point->x = point_a.x + direction_a.x * distance;
    out_point->y = point_a.y + direction_a.y * distance;
    return true;
}

/* Matches the canonical generic-depth core-hole construction exactly. */
static uint8_t fractonica_glyph_inset_convex_polygon(
    const fractonica_glyph_point_t *points,
    uint8_t point_count,
    float thickness,
    fractonica_glyph_point_t *output) {
    fractonica_glyph_point_t line_points[FRACTONICA_GLYPH_MAX_POLYGON_POINTS];
    fractonica_glyph_point_t line_directions[FRACTONICA_GLYPH_MAX_POLYGON_POINTS];
    const float inward_sign = fractonica_glyph_signed_area(points, point_count) >= 0.0f
                                  ? 1.0f
                                  : -1.0f;
    uint8_t index;

    if (point_count < 3u || thickness <= 0.0f) {
        memcpy(output, points, sizeof(*output) * point_count);
        return point_count;
    }
    for (index = 0u; index < point_count; ++index) {
        const fractonica_glyph_point_t point = points[index];
        const fractonica_glyph_point_t next = points[(uint8_t)((index + 1u) % point_count)];
        const float dx = next.x - point.x;
        const float dy = next.y - point.y;
        float length = sqrtf(dx * dx + dy * dy);
        fractonica_glyph_point_t normal;

        if (length < 0.001f) {
            length = 0.001f;
        }
        normal.x = (-dy / length) * inward_sign;
        normal.y = (dx / length) * inward_sign;
        line_points[index] = fractonica_glyph_point_add(
            point,
            fractonica_glyph_point_scale(normal, thickness));
        line_directions[index].x = dx;
        line_directions[index].y = dy;
    }
    for (index = 0u; index < point_count; ++index) {
        const uint8_t previous = (uint8_t)((index + point_count - 1u) % point_count);
        if (!fractonica_glyph_intersect_lines(
                line_points[previous],
                line_directions[previous],
                line_points[index],
                line_directions[index],
                &output[index])) {
            output[index] = points[index];
        }
    }
    return point_count;
}

static uint8_t fractonica_glyph_make_core_hole(
    const fractonica_glyph_config_t *config,
    const fractonica_glyph_point_t *outer,
    uint8_t outer_count,
    fractonica_glyph_point_t *output) {
    uint8_t index;

    if (config->digits_per_glyph == FRACTONICA_GLYPH_FONT_LEGACY_HOLE_DEPTH) {
        for (index = 0u; index < FRACTONICA_GLYPH_FONT_LEGACY_HOLE_POINT_COUNT; ++index) {
            output[index] = fractonica_glyph_transform_global_point(
                config,
                fractonica_glyph_font_legacy_hole[index]);
        }
        return FRACTONICA_GLYPH_FONT_LEGACY_HOLE_POINT_COUNT;
    }
    return fractonica_glyph_inset_convex_polygon(
        outer,
        outer_count,
        FRACTONICA_GLYPH_FONT_INSET_THICKNESS * config->radius,
        output);
}

static fractonica_glyph_status_t fractonica_glyph_emit_core(
    const fractonica_glyph_config_t *config,
    fractonica_glyph_emit_callback_t callback,
    void *context,
    fractonica_glyph_emit_result_t *result) {
    fractonica_glyph_point_t outer[FRACTONICA_GLYPH_MAX_POLYGON_POINTS];
    fractonica_glyph_point_t hole[FRACTONICA_GLYPH_MAX_POLYGON_POINTS];
    fractonica_glyph_contour_t contours[FRACTONICA_GLYPH_MAX_CONTOURS_PER_POLYGON];
    const uint8_t outer_count = fractonica_glyph_make_core_outer(config, outer);
    const uint8_t hole_count = fractonica_glyph_make_core_hole(config, outer, outer_count, hole);

    contours[0].point_count = outer_count;
    contours[0].points = outer;
    contours[1].point_count = hole_count;
    contours[1].points = hole;
    return fractonica_glyph_emit_polygon(
        callback,
        context,
        FRACTONICA_GLYPH_POLYGON_CORE,
        FRACTONICA_GLYPH_FILL_EVENODD,
        FRACTONICA_GLYPH_NO_INDEX,
        FRACTONICA_GLYPH_NO_INDEX,
        0u,
        contours,
        2u,
        result);
}

static fractonica_glyph_status_t fractonica_glyph_emit_arm(
    const fractonica_glyph_config_t *config,
    uint8_t socket_index,
    uint8_t digit_index,
    uint8_t digit,
    fractonica_glyph_emit_callback_t callback,
    void *context,
    fractonica_glyph_emit_result_t *result) {
    fractonica_glyph_point_t points[FRACTONICA_GLYPH_FONT_ARM_MAX_POINTS];
    fractonica_glyph_contour_t contour;
    const fractonica_glyph_frame_t frame =
        fractonica_glyph_make_frame(config, socket_index);
    const uint8_t point_count = fractonica_glyph_font_arm_point_counts[digit];
    uint8_t index;

    /* Digit zero is semantically and visually empty, despite its two anchors. */
    if (digit == 0u) {
        return FRACTONICA_GLYPH_STATUS_OK;
    }
    for (index = 0u; index < point_count; ++index) {
        if (index == 0u) {
            points[index] = fractonica_glyph_local_to_world(&frame, -frame.length * 0.5f, 0.0f);
        } else if ((uint8_t)(index + 1u) == point_count) {
            points[index] = fractonica_glyph_local_to_world(&frame, frame.length * 0.5f, 0.0f);
        } else {
            const fractonica_glyph_spec_point_t point = fractonica_glyph_font_arms[digit][index];
            points[index] = fractonica_glyph_local_to_world(
                &frame,
                point.x * config->radius,
                point.y * config->radius);
        }
    }
    contour.point_count = point_count;
    contour.points = points;
    return fractonica_glyph_emit_polygon(
        callback,
        context,
        FRACTONICA_GLYPH_POLYGON_ARM,
        FRACTONICA_GLYPH_FILL_NONZERO,
        socket_index,
        digit_index,
        digit,
        &contour,
        1u,
        result);
}

void fractonica_glyph_config_init(fractonica_glyph_config_t *config) {
    if (config == NULL) {
        return;
    }
    config->digits_per_glyph = FRACTONICA_GLYPH_DEFAULT_DIGITS_PER_GLYPH;
    config->center_x = 0.0f;
    config->center_y = 0.0f;
    config->radius = 1.0f;
    config->rotation_radians = 0.0f;
}

const char *fractonica_glyph_status_string(fractonica_glyph_status_t status) {
    switch (status) {
        case FRACTONICA_GLYPH_STATUS_OK:
            return "ok";
        case FRACTONICA_GLYPH_STATUS_INVALID_ARGUMENT:
            return "invalid argument";
        case FRACTONICA_GLYPH_STATUS_INVALID_DIGIT_COUNT:
            return "digits per glyph must be in the range 3..8";
        case FRACTONICA_GLYPH_STATUS_INVALID_RADIUS:
            return "glyph font scale and centre must be finite; scale must be positive";
        case FRACTONICA_GLYPH_STATUS_INVALID_ROTATION:
            return "glyph rotation must be finite";
        case FRACTONICA_GLYPH_STATUS_INPUT_TOO_LONG:
            return "octal text is longer than digits per glyph";
        case FRACTONICA_GLYPH_STATUS_INVALID_OCTAL_TEXT:
            return "octal text must contain only ASCII digits 0 through 7";
        case FRACTONICA_GLYPH_STATUS_CALLBACK_ABORTED:
            return "glyph emission callback aborted";
        default:
            return "unknown glyph status";
    }
}

const char *fractonica_glyph_grammar_version(void) {
    return FRACTONICA_GLYPH_GRAMMAR_VERSION;
}

const char *fractonica_glyph_geometry_version(void) {
    return FRACTONICA_GLYPH_GEOMETRY_VERSION;
}

const char *fractonica_glyph_font_id(void) {
    return FRACTONICA_GLYPH_FONT_ID;
}

const char *fractonica_glyph_font_version(void) {
    return FRACTONICA_GLYPH_FONT_VERSION;
}

uint8_t fractonica_glyph_stroke_mask(uint8_t digit) {
    return digit < FRACTONICA_GLYPH_OCTAL_RADIX ? digit : 0u;
}

uint8_t fractonica_glyph_digit_index_for_socket(
    uint8_t digits_per_glyph,
    uint8_t socket_index) {
    if (digits_per_glyph < FRACTONICA_GLYPH_MIN_DIGITS_PER_GLYPH ||
        digits_per_glyph > FRACTONICA_GLYPH_MAX_DIGITS_PER_GLYPH ||
        socket_index >= digits_per_glyph) {
        return FRACTONICA_GLYPH_NO_INDEX;
    }
    return socket_index == 0u ? 0u : (uint8_t)(digits_per_glyph - socket_index);
}

fractonica_glyph_status_t fractonica_glyph_emit_octal_text(
    const fractonica_glyph_config_t *config,
    const char *octal_text,
    size_t octal_text_length,
    fractonica_glyph_emit_callback_t callback,
    void *callback_context,
    fractonica_glyph_emit_result_t *out_result) {
    fractonica_glyph_emit_result_t result;
    fractonica_glyph_status_t status;
    size_t padding;
    uint8_t socket_index;

    memset(&result, 0, sizeof(result));
    status = fractonica_glyph_validate(config, octal_text, octal_text_length, callback);
    if (status != FRACTONICA_GLYPH_STATUS_OK) {
        if (out_result != NULL) {
            *out_result = result;
        }
        return status;
    }

    result.digits_per_glyph = config->digits_per_glyph;
    result.input_digit_count = (uint8_t)octal_text_length;
    padding = (size_t)config->digits_per_glyph - octal_text_length;

    status = fractonica_glyph_emit_core(config, callback, callback_context, &result);
    if (status != FRACTONICA_GLYPH_STATUS_OK) {
        goto finish;
    }

    for (socket_index = 0u; socket_index < config->digits_per_glyph; ++socket_index) {
        const uint8_t digit_index = fractonica_glyph_digit_index_for_socket(
            config->digits_per_glyph,
            socket_index);
        const uint8_t digit = digit_index < padding
                                  ? 0u
                                  : (uint8_t)(octal_text[digit_index - padding] - '0');

        status = fractonica_glyph_emit_arm(
            config,
            socket_index,
            digit_index,
            digit,
            callback,
            callback_context,
            &result);
        if (status != FRACTONICA_GLYPH_STATUS_OK) {
            goto finish;
        }
    }

finish:
    if (out_result != NULL) {
        *out_result = result;
    }
    return status;
}
