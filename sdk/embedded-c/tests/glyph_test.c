/* SPDX-License-Identifier: Apache-2.0 */

#include "fractonica/embedded/glyph.h"

#include <float.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct capture {
    uint16_t primitive_count;
    uint16_t core_count;
    uint16_t arm_count;
    uint8_t core_contour_count;
    uint8_t core_outer_count;
    uint8_t core_hole_count;
    fractonica_glyph_fill_rule_t core_fill_rule;
    fractonica_glyph_fill_rule_t arm_fill_rule;
    fractonica_glyph_point_t core_outer[FRACTONICA_GLYPH_MAX_POLYGON_POINTS];
    fractonica_glyph_point_t core_hole[FRACTONICA_GLYPH_MAX_POLYGON_POINTS];
    fractonica_glyph_point_t first_arm[FRACTONICA_GLYPH_FONT_ARM_MAX_POINTS];
    uint8_t first_arm_point_count;
    fractonica_glyph_point_t second_arm[FRACTONICA_GLYPH_FONT_ARM_MAX_POINTS];
    uint8_t second_arm_point_count;
    uint8_t socket_digit[FRACTONICA_GLYPH_MAX_DIGITS_PER_GLYPH];
    uint8_t socket_seen[FRACTONICA_GLYPH_MAX_DIGITS_PER_GLYPH];
    bool all_points_finite;
    uint16_t stop_after;
} capture_t;

static int failures = 0;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            failures++;                                                         \
        }                                                                       \
    } while (0)

static bool is_finite(float value) {
    return value == value && value <= FLT_MAX && value >= -FLT_MAX;
}

static bool near(float left, float right) {
    return fabsf(left - right) <= 0.001f;
}

static bool capture_polygon(void *context, const fractonica_glyph_polygon_t *polygon) {
    capture_t *capture = (capture_t *)context;
    uint8_t contour_index;

    capture->primitive_count++;
    if (capture->stop_after != 0u && capture->primitive_count >= capture->stop_after) {
        return false;
    }
    if (polygon->kind == FRACTONICA_GLYPH_POLYGON_CORE) {
        capture->core_count++;
        capture->core_fill_rule = polygon->fill_rule;
        capture->core_contour_count = polygon->contour_count;
        if (polygon->contour_count >= 2u) {
            capture->core_outer_count = polygon->contours[0].point_count;
            capture->core_hole_count = polygon->contours[1].point_count;
            memcpy(
                capture->core_outer,
                polygon->contours[0].points,
                sizeof(*capture->core_outer) * capture->core_outer_count);
            memcpy(
                capture->core_hole,
                polygon->contours[1].points,
                sizeof(*capture->core_hole) * capture->core_hole_count);
        }
    } else if (polygon->kind == FRACTONICA_GLYPH_POLYGON_ARM) {
        capture->arm_count++;
        capture->arm_fill_rule = polygon->fill_rule;
        if (polygon->socket_index < FRACTONICA_GLYPH_MAX_DIGITS_PER_GLYPH) {
            capture->socket_digit[polygon->socket_index] = polygon->digit;
            capture->socket_seen[polygon->socket_index] = 1u;
        }
        if (polygon->socket_index == 0u && polygon->contour_count == 1u) {
            capture->first_arm_point_count = polygon->contours[0].point_count;
            memcpy(
                capture->first_arm,
                polygon->contours[0].points,
                sizeof(*capture->first_arm) * capture->first_arm_point_count);
        }
        if (polygon->socket_index == 1u && polygon->contour_count == 1u) {
            capture->second_arm_point_count = polygon->contours[0].point_count;
            memcpy(
                capture->second_arm,
                polygon->contours[0].points,
                sizeof(*capture->second_arm) * capture->second_arm_point_count);
        }
    }

    for (contour_index = 0u; contour_index < polygon->contour_count; ++contour_index) {
        const fractonica_glyph_contour_t *contour = &polygon->contours[contour_index];
        uint8_t point_index;

        for (point_index = 0u; point_index < contour->point_count; ++point_index) {
            if (!is_finite(contour->points[point_index].x) ||
                !is_finite(contour->points[point_index].y)) {
                capture->all_points_finite = false;
            }
        }
    }
    return true;
}

static void test_defaults(void) {
    fractonica_glyph_config_t config;

    fractonica_glyph_config_init(&config);
    CHECK(config.digits_per_glyph == FRACTONICA_GLYPH_DEFAULT_DIGITS_PER_GLYPH);
    CHECK(config.radius == 1.0f);
    CHECK(strcmp(fractonica_glyph_grammar_version(), "1.0.0") == 0);
    CHECK(strcmp(fractonica_glyph_geometry_version(), "2.1.0") == 0);
    CHECK(strcmp(fractonica_glyph_font_id(), "fractonica-hex-v2") == 0);
    CHECK(strcmp(fractonica_glyph_font_version(), "1.0.0") == 0);
    CHECK(fractonica_glyph_stroke_mask(1u) == FRACTONICA_GLYPH_STROKE_LEFT);
    CHECK(fractonica_glyph_stroke_mask(2u) == FRACTONICA_GLYPH_STROKE_CENTRE);
    CHECK(fractonica_glyph_stroke_mask(4u) == FRACTONICA_GLYPH_STROKE_RIGHT);
    CHECK(fractonica_glyph_stroke_mask(7u) == 7u);
    CHECK(fractonica_glyph_stroke_mask(8u) == 0u);
    CHECK(fractonica_glyph_digit_index_for_socket(5u, 0u) == 0u);
    CHECK(fractonica_glyph_digit_index_for_socket(5u, 1u) == 4u);
    CHECK(fractonica_glyph_digit_index_for_socket(5u, 2u) == 3u);
    CHECK(fractonica_glyph_digit_index_for_socket(5u, 3u) == 2u);
    CHECK(fractonica_glyph_digit_index_for_socket(5u, 4u) == 1u);
    CHECK(fractonica_glyph_digit_index_for_socket(2u, 0u) == FRACTONICA_GLYPH_NO_INDEX);
}

static void test_msb_first_socket_mapping_and_compound_core(void) {
    fractonica_glyph_config_t config;
    fractonica_glyph_emit_result_t result;
    capture_t capture;
    fractonica_glyph_status_t status;

    memset(&capture, 0, sizeof(capture));
    capture.all_points_finite = true;
    fractonica_glyph_config_init(&config);
    config.radius = 100.0f;

    status = fractonica_glyph_emit_octal_text(
        &config, "12345", 5u, capture_polygon, &capture, &result);
    CHECK(status == FRACTONICA_GLYPH_STATUS_OK);
    CHECK(result.digits_per_glyph == 5u);
    CHECK(result.input_digit_count == 5u);
    CHECK(result.emitted_primitive_count == capture.primitive_count);
    CHECK(capture.core_count == 1u);
    CHECK(capture.arm_count == 5u);
    CHECK(capture.core_fill_rule == FRACTONICA_GLYPH_FILL_EVENODD);
    CHECK(capture.arm_fill_rule == FRACTONICA_GLYPH_FILL_NONZERO);
    CHECK(capture.core_contour_count == 2u);
    CHECK(capture.core_outer_count == 10u);
    CHECK(capture.core_hole_count == 10u);
    CHECK(capture.socket_seen[0] == 1u && capture.socket_digit[0] == 1u);
    CHECK(capture.socket_seen[1] == 1u && capture.socket_digit[1] == 5u);
    CHECK(capture.socket_seen[2] == 1u && capture.socket_digit[2] == 4u);
    CHECK(capture.socket_seen[3] == 1u && capture.socket_digit[3] == 3u);
    CHECK(capture.socket_seen[4] == 1u && capture.socket_digit[4] == 2u);
    CHECK(capture.all_points_finite);
}

static void test_hex_v2_six_digit_reference_geometry(void) {
    fractonica_glyph_config_t config;
    fractonica_glyph_emit_result_t result;
    capture_t capture;
    fractonica_glyph_status_t status;

    memset(&capture, 0, sizeof(capture));
    capture.all_points_finite = true;
    fractonica_glyph_config_init(&config);
    config.digits_per_glyph = 6u;

    status = fractonica_glyph_emit_octal_text(
        &config, "777777", 6u, capture_polygon, &capture, &result);
    CHECK(status == FRACTONICA_GLYPH_STATUS_OK);
    CHECK(result.emitted_primitive_count == 7u);
    CHECK(capture.core_contour_count == 2u);
    CHECK(capture.core_outer_count == 12u);
    CHECK(capture.core_hole_count == 7u);
    CHECK(near(capture.core_outer[0].x, -8.0f));
    CHECK(near(capture.core_outer[0].y, -41.57f));
    CHECK(near(capture.core_outer[1].x, 8.0f));
    CHECK(near(capture.core_outer[1].y, -41.57f));
    CHECK(near(capture.core_hole[0].x, 8.0f));
    CHECK(near(capture.core_hole[0].y, 0.0f));
    CHECK(near(capture.core_hole[3].x, 0.0f));
    CHECK(near(capture.core_hole[3].y, 27.71f));
    CHECK(capture.first_arm_point_count == 8u);
    CHECK(near(capture.first_arm[0].x, -8.0f));
    CHECK(near(capture.first_arm[0].y, -41.57f));
    CHECK(near(capture.first_arm[1].x, -40.0f));
    CHECK(near(capture.first_arm[1].y, -96.99f));
    CHECK(near(capture.first_arm[2].x, 0.0f));
    CHECK(near(capture.first_arm[2].y, -166.28f));
    CHECK(near(capture.first_arm[7].x, 8.0f));
    CHECK(near(capture.first_arm[7].y, -41.57f));
    /* Socket one shares the upper-right exact-core chord, not its mirror. */
    CHECK(capture.second_arm_point_count == 8u);
    CHECK(near(capture.second_arm[0].x, 32.0f));
    CHECK(near(capture.second_arm[0].y, -27.71f));
    CHECK(near(capture.second_arm[7].x, 40.0f));
    CHECK(near(capture.second_arm[7].y, -13.86f));
    CHECK(capture.all_points_finite);
}

static void test_left_padding_and_range(void) {
    fractonica_glyph_config_t config;
    fractonica_glyph_emit_result_t result;
    capture_t capture;
    fractonica_glyph_status_t status;
    uint8_t depth;

    for (depth = FRACTONICA_GLYPH_MIN_DIGITS_PER_GLYPH;
         depth <= FRACTONICA_GLYPH_MAX_DIGITS_PER_GLYPH;
         ++depth) {
        memset(&capture, 0, sizeof(capture));
        capture.all_points_finite = true;
        fractonica_glyph_config_init(&config);
        config.digits_per_glyph = depth;
        config.radius = 48.0f;

        status = fractonica_glyph_emit_octal_text(
            &config, "17", 2u, capture_polygon, &capture, &result);
        CHECK(status == FRACTONICA_GLYPH_STATUS_OK);
        CHECK(result.digits_per_glyph == depth);
        CHECK(capture.core_count == 1u);
        CHECK(capture.core_contour_count == 2u);
        CHECK(capture.all_points_finite);
        CHECK(capture.socket_seen[0] == 0u);
        CHECK(capture.socket_seen[1] == 1u && capture.socket_digit[1] == 7u);
        CHECK(capture.socket_seen[2] == 1u && capture.socket_digit[2] == 1u);
    }
}

static void test_invalid_input_has_no_emission(void) {
    fractonica_glyph_config_t config;
    capture_t capture;
    fractonica_glyph_status_t status;

    memset(&capture, 0, sizeof(capture));
    fractonica_glyph_config_init(&config);
    status = fractonica_glyph_emit_octal_text(
        &config, "128", 3u, capture_polygon, &capture, NULL);
    CHECK(status == FRACTONICA_GLYPH_STATUS_INVALID_OCTAL_TEXT);
    CHECK(capture.primitive_count == 0u);

    config.digits_per_glyph = 2u;
    status = fractonica_glyph_emit_octal_text(
        &config, "1", 1u, capture_polygon, &capture, NULL);
    CHECK(status == FRACTONICA_GLYPH_STATUS_INVALID_DIGIT_COUNT);
    CHECK(capture.primitive_count == 0u);

    fractonica_glyph_config_init(&config);
    status = fractonica_glyph_emit_octal_text(
        &config, "123456", 6u, capture_polygon, &capture, NULL);
    CHECK(status == FRACTONICA_GLYPH_STATUS_INPUT_TOO_LONG);
    CHECK(capture.primitive_count == 0u);
}

static void test_callback_abort(void) {
    fractonica_glyph_config_t config;
    fractonica_glyph_emit_result_t result;
    capture_t capture;
    fractonica_glyph_status_t status;

    memset(&capture, 0, sizeof(capture));
    capture.stop_after = 1u;
    fractonica_glyph_config_init(&config);
    status = fractonica_glyph_emit_octal_text(
        &config, "77777", 5u, capture_polygon, &capture, &result);
    CHECK(status == FRACTONICA_GLYPH_STATUS_CALLBACK_ABORTED);
    CHECK(capture.primitive_count == 1u);
    CHECK(result.emitted_primitive_count == 0u);
}

int main(void) {
    test_defaults();
    test_msb_first_socket_mapping_and_compound_core();
    test_hex_v2_six_digit_reference_geometry();
    test_left_padding_and_range();
    test_invalid_input_has_no_emission();
    test_callback_abort();

    if (failures != 0) {
        fprintf(stderr, "%d glyph test(s) failed\n", failures);
        return 1;
    }
    puts("fractonica embedded glyph tests passed");
    return 0;
}
