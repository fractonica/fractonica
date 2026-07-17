/* SPDX-License-Identifier: Apache-2.0 */

#include "fractonica/embedded/glyph.h"

#include <float.h>
#include <math.h>
#include <string.h>

/*
 * The geometry below is intentionally parametric rather than an imported asset
 * catalogue.  Octal bits map to a left branch, central spike, and right branch
 * respectively.  This keeps every digit distinct while making the component
 * small enough for microcontrollers and straightforward for display adapters.
 */

static const float FRACTONICA_GLYPH_PI = 3.14159265358979323846f;
static const float FRACTONICA_GLYPH_CORE_RADIUS_RATIO = 0.30f;
static const float FRACTONICA_GLYPH_CUTOUT_RADIUS_RATIO = 0.12f;
static const float FRACTONICA_GLYPH_SOCKET_WIDTH_RATIO = 0.82f;

typedef struct fractonica_glyph_frame {
    fractonica_glyph_point_t center;
    fractonica_glyph_point_t tangent;
    fractonica_glyph_point_t outward;
} fractonica_glyph_frame_t;

static bool fractonica_glyph_isfinite(float value) {
    return value == value && value <= FLT_MAX && value >= -FLT_MAX;
}

static fractonica_glyph_point_t fractonica_glyph_point_add(
    fractonica_glyph_point_t a,
    fractonica_glyph_point_t b) {
    fractonica_glyph_point_t result = {a.x + b.x, a.y + b.y};
    return result;
}

static fractonica_glyph_point_t fractonica_glyph_point_scale(
    fractonica_glyph_point_t point,
    float scalar) {
    fractonica_glyph_point_t result = {point.x * scalar, point.y * scalar};
    return result;
}

static fractonica_glyph_point_t fractonica_glyph_local_to_world(
    const fractonica_glyph_frame_t *frame,
    float tangent,
    float outward) {
    fractonica_glyph_point_t result = frame->center;
    result = fractonica_glyph_point_add(
        result,
        fractonica_glyph_point_scale(frame->tangent, tangent));
    result = fractonica_glyph_point_add(
        result,
        fractonica_glyph_point_scale(frame->outward, outward));
    return result;
}

static fractonica_glyph_frame_t fractonica_glyph_make_frame(
    const fractonica_glyph_config_t *config,
    uint8_t socket_index) {
    const float angle = config->rotation_radians - FRACTONICA_GLYPH_PI / 2.0f +
                        (2.0f * FRACTONICA_GLYPH_PI * (float)socket_index /
                         (float)config->digits_per_glyph);
    fractonica_glyph_frame_t frame;
    frame.center.x = config->center_x;
    frame.center.y = config->center_y;
    frame.outward.x = cosf(angle);
    frame.outward.y = sinf(angle);
    frame.tangent.x = -sinf(angle);
    frame.tangent.y = cosf(angle);
    return frame;
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
    uint8_t socket_index,
    uint8_t digit_index,
    uint8_t digit,
    const fractonica_glyph_point_t *points,
    uint8_t point_count,
    fractonica_glyph_emit_result_t *result) {
    fractonica_glyph_polygon_t polygon;

    polygon.kind = kind;
    polygon.socket_index = socket_index;
    polygon.digit_index = digit_index;
    polygon.digit = digit;
    polygon.point_count = point_count;
    polygon.points = points;
    if (!callback(context, &polygon)) {
        return FRACTONICA_GLYPH_STATUS_CALLBACK_ABORTED;
    }
    result->emitted_polygon_count++;
    return FRACTONICA_GLYPH_STATUS_OK;
}

static fractonica_glyph_status_t fractonica_glyph_emit_core(
    const fractonica_glyph_config_t *config,
    fractonica_glyph_emit_callback_t callback,
    void *context,
    fractonica_glyph_emit_result_t *result) {
    fractonica_glyph_point_t points[FRACTONICA_GLYPH_MAX_POLYGON_POINTS];
    const float core_radius = config->radius * FRACTONICA_GLYPH_CORE_RADIUS_RATIO;
    const float half_socket_width =
        core_radius * sinf(FRACTONICA_GLYPH_PI / (float)config->digits_per_glyph) *
        FRACTONICA_GLYPH_SOCKET_WIDTH_RATIO;
    uint8_t socket_index;

    for (socket_index = 0u; socket_index < config->digits_per_glyph; ++socket_index) {
        const fractonica_glyph_frame_t frame =
            fractonica_glyph_make_frame(config, socket_index);
        const fractonica_glyph_point_t socket_center =
            fractonica_glyph_local_to_world(&frame, 0.0f, core_radius);
        points[(uint8_t)(socket_index * 2u)] = fractonica_glyph_point_add(
            socket_center,
            fractonica_glyph_point_scale(frame.tangent, -half_socket_width));
        points[(uint8_t)(socket_index * 2u + 1u)] = fractonica_glyph_point_add(
            socket_center,
            fractonica_glyph_point_scale(frame.tangent, half_socket_width));
    }

    return fractonica_glyph_emit_polygon(
        callback,
        context,
        FRACTONICA_GLYPH_POLYGON_CORE,
        FRACTONICA_GLYPH_NO_INDEX,
        FRACTONICA_GLYPH_NO_INDEX,
        0u,
        points,
        (uint8_t)(config->digits_per_glyph * 2u),
        result);
}

static fractonica_glyph_status_t fractonica_glyph_emit_arm_piece(
    const fractonica_glyph_frame_t *frame,
    const float *local_coordinates,
    uint8_t point_count,
    uint8_t socket_index,
    uint8_t digit_index,
    uint8_t digit,
    fractonica_glyph_emit_callback_t callback,
    void *context,
    fractonica_glyph_emit_result_t *result) {
    fractonica_glyph_point_t points[4];
    uint8_t point_index;

    for (point_index = 0u; point_index < point_count; ++point_index) {
        points[point_index] = fractonica_glyph_local_to_world(
            frame,
            local_coordinates[(uint8_t)(point_index * 2u)],
            local_coordinates[(uint8_t)(point_index * 2u + 1u)]);
    }

    return fractonica_glyph_emit_polygon(
        callback,
        context,
        FRACTONICA_GLYPH_POLYGON_ARM,
        socket_index,
        digit_index,
        digit,
        points,
        point_count,
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
    const fractonica_glyph_frame_t frame =
        fractonica_glyph_make_frame(config, socket_index);
    const float radius = config->radius;
    const float shaft[] = {
        -0.070f * radius, 0.24f * radius,
         0.070f * radius, 0.24f * radius,
         0.095f * radius, 0.55f * radius,
        -0.095f * radius, 0.55f * radius,
    };
    const float left_branch[] = {
        -0.045f * radius, 0.36f * radius,
        -0.105f * radius, 0.51f * radius,
        -0.525f * radius, 0.72f * radius,
        -0.405f * radius, 0.53f * radius,
    };
    const float center_spike[] = {
        -0.095f * radius, 0.48f * radius,
         0.000f * radius, 1.00f * radius,
         0.095f * radius, 0.48f * radius,
    };
    const float right_branch[] = {
         0.045f * radius, 0.36f * radius,
         0.105f * radius, 0.51f * radius,
         0.525f * radius, 0.72f * radius,
         0.405f * radius, 0.53f * radius,
    };
    fractonica_glyph_status_t status;

    if (digit == 0u) {
        return FRACTONICA_GLYPH_STATUS_OK;
    }

    status = fractonica_glyph_emit_arm_piece(
        &frame, shaft, 4u, socket_index, digit_index, digit, callback, context, result);
    if (status != FRACTONICA_GLYPH_STATUS_OK) {
        return status;
    }
    if ((digit & 0x1u) != 0u) {
        status = fractonica_glyph_emit_arm_piece(
            &frame, left_branch, 4u, socket_index, digit_index, digit, callback, context, result);
        if (status != FRACTONICA_GLYPH_STATUS_OK) {
            return status;
        }
    }
    if ((digit & 0x2u) != 0u) {
        status = fractonica_glyph_emit_arm_piece(
            &frame, center_spike, 3u, socket_index, digit_index, digit, callback, context, result);
        if (status != FRACTONICA_GLYPH_STATUS_OK) {
            return status;
        }
    }
    if ((digit & 0x4u) != 0u) {
        status = fractonica_glyph_emit_arm_piece(
            &frame, right_branch, 4u, socket_index, digit_index, digit, callback, context, result);
    }
    return status;
}

static fractonica_glyph_status_t fractonica_glyph_emit_cutout(
    const fractonica_glyph_config_t *config,
    fractonica_glyph_emit_callback_t callback,
    void *context,
    fractonica_glyph_emit_result_t *result) {
    fractonica_glyph_point_t points[FRACTONICA_GLYPH_MAX_DIGITS_PER_GLYPH];
    const float cutout_radius =
        config->radius * FRACTONICA_GLYPH_CUTOUT_RADIUS_RATIO;
    uint8_t point_index;

    for (point_index = 0u; point_index < config->digits_per_glyph; ++point_index) {
        const fractonica_glyph_frame_t frame =
            fractonica_glyph_make_frame(config, point_index);
        points[point_index] = fractonica_glyph_local_to_world(
            &frame, 0.0f, cutout_radius);
    }

    return fractonica_glyph_emit_polygon(
        callback,
        context,
        FRACTONICA_GLYPH_POLYGON_CUTOUT,
        FRACTONICA_GLYPH_NO_INDEX,
        FRACTONICA_GLYPH_NO_INDEX,
        0u,
        points,
        config->digits_per_glyph,
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
            return "glyph center and radius must be finite; radius must be positive";
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
    size_t padding = 0u;
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
            config->digits_per_glyph, socket_index);
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

    status = fractonica_glyph_emit_cutout(config, callback, callback_context, &result);

finish:
    if (out_result != NULL) {
        *out_result = result;
    }
    return status;
}
