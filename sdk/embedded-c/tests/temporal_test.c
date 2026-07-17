/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Host check:
 * cc -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude src/temporal.c \
 *   tests/temporal_test.c -lm -o /tmp/fractonica-temporal-tests && \
 *   /tmp/fractonica-temporal-tests
 */

#include "fractonica/embedded/temporal.h"

#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int failures = 0;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            ++failures;                                                         \
        }                                                                       \
    } while (0)

static int is_finite(double value) {
    return value == value && value <= DBL_MAX && value >= -DBL_MAX;
}

static fractonica_temporal_address_t parse(const char *digits) {
    fractonica_temporal_address_t address = {0u, 0u};
    CHECK(fractonica_temporal_address_parse_octal(
              &address, digits, strlen(digits)) == FRACTONICA_TEMPORAL_OK);
    return address;
}

static fractonica_temporal_interval_t interval(void) {
    fractonica_temporal_interval_t value;
    value.previous_epoch_seconds = 0;
    value.next_epoch_seconds = 1024;
    return value;
}

static fractonica_temporal_eclipse_point_t eclipse(
    uint16_t index,
    int64_t epoch_seconds,
    uint8_t saros) {
    fractonica_temporal_eclipse_point_t point;
    point.index = index;
    point.epoch_seconds = epoch_seconds;
    point.saros = saros;
    point.sequence = (uint8_t)index;
    point.type_code = 0u;
    return point;
}

static void test_address_formatting(void) {
    fractonica_temporal_address_t address = {0u, 0u};
    char formatted[4] = {0};
    char undersized[3] = {0};

    CHECK(fractonica_temporal_address_init(&address, 256u, 3u) ==
          FRACTONICA_TEMPORAL_OK);
    CHECK(fractonica_temporal_address_format_msb(
              &address, formatted, sizeof(formatted)) == FRACTONICA_TEMPORAL_OK);
    CHECK(strcmp(formatted, "400") == 0);
    CHECK(fractonica_temporal_address_format_msb(
              &address, undersized, sizeof(undersized)) ==
          FRACTONICA_TEMPORAL_BUFFER_TOO_SMALL);
    CHECK(fractonica_temporal_address_init(&address, 8u, 1u) ==
          FRACTONICA_TEMPORAL_ADDRESS_OUT_OF_RANGE);
    CHECK(fractonica_temporal_address_parse_octal(&address, "8", 1u) ==
          FRACTONICA_TEMPORAL_INVALID_ADDRESS_DIGIT);
}

static void test_rarity(void) {
    fractonica_temporal_rarity_t rarity = {
        FRACTONICA_TEMPORAL_RARITY_COMMON,
        0u,
    };
    fractonica_temporal_address_t at_flip = parse("0001120");
    fractonica_temporal_address_t preceding = parse("0001117");
    const char *cases[] = {"0001111", "0011111", "0111111", "1111111"};
    const fractonica_temporal_rarity_family_t expected[] = {
        FRACTONICA_TEMPORAL_RARITY_TRIPLEX,
        FRACTONICA_TEMPORAL_RARITY_DUPLEX,
        FRACTONICA_TEMPORAL_RARITY_SIMPLEX,
        FRACTONICA_TEMPORAL_RARITY_NIHIL};
    size_t index;

    for (index = 0u; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        fractonica_temporal_address_t address = parse(cases[index]);
        CHECK(fractonica_temporal_classify_rarity(&address, &rarity) ==
              FRACTONICA_TEMPORAL_OK);
        CHECK(rarity.family == expected[index]);
        CHECK(rarity.digit == 1u);
    }
    {
        fractonica_temporal_address_t zero = parse("0000000");
        CHECK(fractonica_temporal_classify_rarity(&zero, &rarity) ==
              FRACTONICA_TEMPORAL_OK);
    }
    CHECK(rarity.family == FRACTONICA_TEMPORAL_RARITY_NIHIL);
    CHECK(rarity.digit == 7u);
    CHECK(strcmp(fractonica_temporal_rarity_digit_name(rarity.digit), "Omega") == 0);

    CHECK(fractonica_temporal_classify_rarity(&at_flip, &rarity) ==
          FRACTONICA_TEMPORAL_OK);
    {
        fractonica_temporal_rarity_t preceding_rarity = {
            FRACTONICA_TEMPORAL_RARITY_COMMON,
            0u,
        };
        CHECK(fractonica_temporal_classify_rarity(&preceding, &preceding_rarity) ==
              FRACTONICA_TEMPORAL_OK);
        CHECK(rarity.family == preceding_rarity.family);
        CHECK(rarity.digit == preceding_rarity.digit);
    }
}

static void test_clock_and_pulse(void) {
    fractonica_temporal_interval_t value = interval();
    fractonica_temporal_clock_reading_t reading = {0};
    fractonica_temporal_pulse10_t pulse = {0};
    fractonica_temporal_address_t target = parse("1234567012");
    const uint8_t expected_msb[5] = {1u, 2u, 3u, 4u, 5u};
    const uint8_t expected_lsb[5] = {6u, 7u, 0u, 1u, 2u};
    double now = (double)target.value / 1073741824.0 * 1024.0;

    CHECK(fractonica_temporal_clock_reading(&value, 512.0, 3u, &reading) ==
          FRACTONICA_TEMPORAL_OK);
    CHECK(reading.bin_count == 512u);
    CHECK(reading.bin_index == 256u);
    CHECK(reading.address.value == 256u);

    CHECK(fractonica_temporal_clock_reading(&value, -10.0, 1u, &reading) ==
          FRACTONICA_TEMPORAL_OK);
    CHECK(reading.bin_index == 0u);
    CHECK(fractonica_temporal_clock_reading(&value, 2000.0, 1u, &reading) ==
          FRACTONICA_TEMPORAL_OK);
    CHECK(reading.bin_index == 7u);
    CHECK(reading.next_flip_epoch_seconds == 1024.0);
    CHECK(reading.time_until_flip_seconds < 0.0);

    CHECK(fractonica_temporal_clock_reading(&value, NAN, 1u, &reading) ==
          FRACTONICA_TEMPORAL_NONFINITE_TIMESTAMP);
    CHECK(fractonica_temporal_clock_reading(&value, INFINITY, 1u, &reading) ==
          FRACTONICA_TEMPORAL_NONFINITE_TIMESTAMP);
    value.previous_epoch_seconds = INT64_MIN;
    value.next_epoch_seconds = INT64_MAX;
    CHECK(fractonica_temporal_clock_reading(&value, 0.0, 1u, &reading) ==
          FRACTONICA_TEMPORAL_OK);
    CHECK(is_finite(reading.phase));
    CHECK(fabs(reading.phase - 0.5) < 1e-12);

    value = interval();
    CHECK(fractonica_temporal_pulse_reading_10(&value, now, &pulse) ==
          FRACTONICA_TEMPORAL_OK);
    CHECK(memcmp(pulse.most_significant, expected_msb, sizeof(expected_msb)) == 0);
    CHECK(memcmp(pulse.least_significant, expected_lsb, sizeof(expected_lsb)) == 0);
}

static void test_series_bracket(void) {
    fractonica_temporal_eclipse_point_t eclipses[] = {
        eclipse(0u, 100, FRACTONICA_TEMPORAL_DEFAULT_PULSE_SAROS),
        eclipse(1u, 200, FRACTONICA_TEMPORAL_DEFAULT_PULSE_SAROS),
        eclipse(2u, 300, FRACTONICA_TEMPORAL_DEFAULT_PULSE_SAROS),
    };
    fractonica_temporal_series_interval_t bracket = {0};

    CHECK(fractonica_temporal_series_bracket(
              eclipses, 3u, 200, &bracket) == FRACTONICA_TEMPORAL_OK);
    CHECK(bracket.previous.epoch_seconds == 200);
    CHECK(bracket.next.epoch_seconds == 300);

    CHECK(fractonica_temporal_series_bracket(
              eclipses, 3u, 0, &bracket) == FRACTONICA_TEMPORAL_OK);
    CHECK(bracket.previous.index == 0u);
    CHECK(bracket.next.index == 1u);
    CHECK(fractonica_temporal_series_bracket(
              eclipses, 3u, 400, &bracket) == FRACTONICA_TEMPORAL_OK);
    CHECK(bracket.previous.index == 1u);
    CHECK(bracket.next.index == 2u);

    eclipses[2].saros = 140u;
    CHECK(fractonica_temporal_series_bracket(
              eclipses, 3u, 200, &bracket) ==
          FRACTONICA_TEMPORAL_MIXED_SAROS_SERIES);
    eclipses[2].saros = FRACTONICA_TEMPORAL_DEFAULT_PULSE_SAROS;
    eclipses[2].epoch_seconds = 200;
    CHECK(fractonica_temporal_series_bracket(
              eclipses, 3u, 200, &bracket) ==
          FRACTONICA_TEMPORAL_UNSORTED_ECLIPSES);
    CHECK(fractonica_temporal_series_bracket(
              eclipses, 1u, 200, &bracket) == FRACTONICA_TEMPORAL_TOO_FEW_ECLIPSES);
}

int main(void) {
    test_address_formatting();
    test_rarity();
    test_clock_and_pulse();
    test_series_bracket();
    if (failures != 0) {
        fprintf(stderr, "%d temporal test(s) failed\n", failures);
        return 1;
    }
    puts("fractonica embedded temporal tests passed");
    return 0;
}
