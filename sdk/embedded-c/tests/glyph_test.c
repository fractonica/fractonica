/* SPDX-License-Identifier: Apache-2.0 */

#include "fractonica/embedded/glyph.h"

#include <float.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct capture {
    uint16_t polygon_count;
    uint16_t core_count;
    uint16_t arm_count;
    uint16_t cutout_count;
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

static bool capture_polygon(void *context, const fractonica_glyph_polygon_t *polygon) {
    capture_t *capture = (capture_t *)context;
    uint8_t index;

    capture->polygon_count++;
    if (capture->stop_after != 0u && capture->polygon_count >= capture->stop_after) {
        return false;
    }
    if (polygon->kind == FRACTONICA_GLYPH_POLYGON_CORE) {
        capture->core_count++;
    } else if (polygon->kind == FRACTONICA_GLYPH_POLYGON_ARM) {
        capture->arm_count++;
        if (polygon->socket_index < FRACTONICA_GLYPH_MAX_DIGITS_PER_GLYPH) {
            capture->socket_digit[polygon->socket_index] = polygon->digit;
            capture->socket_seen[polygon->socket_index] = 1u;
        }
    } else if (polygon->kind == FRACTONICA_GLYPH_POLYGON_CUTOUT) {
        capture->cutout_count++;
    }

    for (index = 0u; index < polygon->point_count; ++index) {
        if (!is_finite(polygon->points[index].x) ||
            !is_finite(polygon->points[index].y)) {
            capture->all_points_finite = false;
        }
    }
    return true;
}

static void test_defaults(void) {
    fractonica_glyph_config_t config;

    fractonica_glyph_config_init(&config);
    CHECK(config.digits_per_glyph == FRACTONICA_GLYPH_DEFAULT_DIGITS_PER_GLYPH);
    CHECK(config.radius == 1.0f);
    CHECK(fractonica_glyph_digit_index_for_socket(5u, 0u) == 0u);
    CHECK(fractonica_glyph_digit_index_for_socket(5u, 1u) == 4u);
    CHECK(fractonica_glyph_digit_index_for_socket(5u, 2u) == 3u);
    CHECK(fractonica_glyph_digit_index_for_socket(5u, 3u) == 2u);
    CHECK(fractonica_glyph_digit_index_for_socket(5u, 4u) == 1u);
    CHECK(fractonica_glyph_digit_index_for_socket(2u, 0u) == FRACTONICA_GLYPH_NO_INDEX);
}

static void test_msb_first_socket_mapping(void) {
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
    CHECK(result.emitted_polygon_count == capture.polygon_count);
    CHECK(capture.core_count == 1u);
    CHECK(capture.cutout_count == 1u);
    CHECK(capture.arm_count == 12u); /* five shafts plus 1 + 1 + 2 + 1 + 2 bit branches */
    CHECK(capture.socket_seen[0] == 1u && capture.socket_digit[0] == 1u);
    CHECK(capture.socket_seen[1] == 1u && capture.socket_digit[1] == 5u);
    CHECK(capture.socket_seen[2] == 1u && capture.socket_digit[2] == 4u);
    CHECK(capture.socket_seen[3] == 1u && capture.socket_digit[3] == 3u);
    CHECK(capture.socket_seen[4] == 1u && capture.socket_digit[4] == 2u);
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
        CHECK(capture.cutout_count == 1u);
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
    CHECK(capture.polygon_count == 0u);

    config.digits_per_glyph = 2u;
    status = fractonica_glyph_emit_octal_text(
        &config, "1", 1u, capture_polygon, &capture, NULL);
    CHECK(status == FRACTONICA_GLYPH_STATUS_INVALID_DIGIT_COUNT);
    CHECK(capture.polygon_count == 0u);

    fractonica_glyph_config_init(&config);
    status = fractonica_glyph_emit_octal_text(
        &config, "123456", 6u, capture_polygon, &capture, NULL);
    CHECK(status == FRACTONICA_GLYPH_STATUS_INPUT_TOO_LONG);
    CHECK(capture.polygon_count == 0u);
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
    CHECK(capture.polygon_count == 1u);
    CHECK(result.emitted_polygon_count == 0u);
}

int main(void) {
    test_defaults();
    test_msb_first_socket_mapping();
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
