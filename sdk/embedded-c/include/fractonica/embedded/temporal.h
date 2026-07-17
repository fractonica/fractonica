/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) Fractonica contributors.
 *
 * A bounded, allocation-free C11 temporal API. All output storage belongs to
 * the caller and every function reports a status code.
 */

#ifndef FRACTONICA_EMBEDDED_TEMPORAL_H
#define FRACTONICA_EMBEDDED_TEMPORAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FRACTONICA_TEMPORAL_ABI_VERSION 1u
#define FRACTONICA_TEMPORAL_RADIX 8u
#define FRACTONICA_TEMPORAL_MIN_CALCULATION_DEPTH 1u
#define FRACTONICA_TEMPORAL_MAX_CALCULATION_DEPTH 8u
#define FRACTONICA_TEMPORAL_REALTIME_PULSE_DEPTH 10u
#define FRACTONICA_TEMPORAL_GLYPH_DIGITS 5u
#define FRACTONICA_TEMPORAL_MAX_ADDRESS_DEPTH \
    FRACTONICA_TEMPORAL_REALTIME_PULSE_DEPTH
#define FRACTONICA_TEMPORAL_DEFAULT_PULSE_SAROS 141u

typedef enum fractonica_temporal_status {
    FRACTONICA_TEMPORAL_OK = 0,
    FRACTONICA_TEMPORAL_INVALID_ARGUMENT = 1,
    FRACTONICA_TEMPORAL_INVALID_DEPTH = 2,
    FRACTONICA_TEMPORAL_ADDRESS_OUT_OF_RANGE = 3,
    FRACTONICA_TEMPORAL_INVALID_ADDRESS_DIGIT = 4,
    FRACTONICA_TEMPORAL_BUFFER_TOO_SMALL = 5,
    FRACTONICA_TEMPORAL_NONFINITE_TIMESTAMP = 6,
    FRACTONICA_TEMPORAL_INVALID_INTERVAL = 7,
    FRACTONICA_TEMPORAL_TOO_FEW_ECLIPSES = 8,
    FRACTONICA_TEMPORAL_UNSORTED_ECLIPSES = 9,
    FRACTONICA_TEMPORAL_MIXED_SAROS_SERIES = 10
} fractonica_temporal_status_t;

/* A fixed-width octal address. Digits are always interpreted MSB first. */
typedef struct fractonica_temporal_address {
    uint32_t value;
    uint8_t depth;
} fractonica_temporal_address_t;

typedef enum fractonica_temporal_rarity_family {
    FRACTONICA_TEMPORAL_RARITY_COMMON = 0,
    FRACTONICA_TEMPORAL_RARITY_TRIPLEX = 3,
    FRACTONICA_TEMPORAL_RARITY_DUPLEX = 4,
    FRACTONICA_TEMPORAL_RARITY_SIMPLEX = 5,
    FRACTONICA_TEMPORAL_RARITY_NIHIL = 6
} fractonica_temporal_rarity_family_t;

typedef struct fractonica_temporal_rarity {
    fractonica_temporal_rarity_family_t family;
    /* The repeated octal digit. It is zero for common values. */
    uint8_t digit;
} fractonica_temporal_rarity_t;

typedef struct fractonica_temporal_interval {
    int64_t previous_epoch_seconds;
    int64_t next_epoch_seconds;
} fractonica_temporal_interval_t;

/*
 * A single point from a separately-provenanced Saros-series catalogue. The
 * SDK never owns or loads such a catalogue; callers retain the storage.
 */
typedef struct fractonica_temporal_eclipse_point {
    uint16_t index;
    int64_t epoch_seconds;
    uint8_t saros;
    uint8_t sequence;
    uint8_t type_code;
} fractonica_temporal_eclipse_point_t;

typedef struct fractonica_temporal_series_interval {
    uint8_t saros;
    fractonica_temporal_eclipse_point_t previous;
    fractonica_temporal_eclipse_point_t next;
} fractonica_temporal_series_interval_t;

typedef struct fractonica_temporal_clock_reading {
    double phase;
    uint32_t bin_count;
    uint32_t bin_index;
    fractonica_temporal_address_t address;
    double progress_within_bin;
    double next_flip_epoch_seconds;
    double time_until_flip_seconds;
} fractonica_temporal_clock_reading_t;

typedef struct fractonica_temporal_pulse10 {
    fractonica_temporal_clock_reading_t clock;
    /* The first glyph: five most-significant octal digits. */
    uint8_t most_significant[FRACTONICA_TEMPORAL_GLYPH_DIGITS];
    /* The second glyph: five least-significant octal digits. */
    uint8_t least_significant[FRACTONICA_TEMPORAL_GLYPH_DIGITS];
} fractonica_temporal_pulse10_t;

/* Valid for depths 1 through FRACTONICA_TEMPORAL_MAX_ADDRESS_DEPTH. */
fractonica_temporal_status_t fractonica_temporal_address_init(
    fractonica_temporal_address_t *out_address,
    uint32_t value,
    uint8_t depth);

/* Parses exactly digit_count ASCII octal digits (without requiring a NUL). */
fractonica_temporal_status_t fractonica_temporal_address_parse_octal(
    fractonica_temporal_address_t *out_address,
    const char *digits,
    size_t digit_count);

/* Formats exactly depth MSB-first digits and a trailing NUL. */
fractonica_temporal_status_t fractonica_temporal_address_format_msb(
    const fractonica_temporal_address_t *address,
    char *output,
    size_t output_capacity);

fractonica_temporal_status_t fractonica_temporal_address_digit_msb(
    const fractonica_temporal_address_t *address,
    uint8_t index,
    uint8_t *out_digit);

/*
 * Applies the same exact-flip rule as the Rust core: a nonzero address ending
 * in zero is classified using the immediately preceding address. Zero itself
 * is Omega Nihil.
 */
fractonica_temporal_status_t fractonica_temporal_classify_rarity(
    const fractonica_temporal_address_t *address,
    fractonica_temporal_rarity_t *out_rarity);

/* Returns a static English label for a rarity digit; never allocates. */
const char *fractonica_temporal_rarity_digit_name(uint8_t digit);

/*
 * Validates a strictly time-ordered, single-Saros catalogue and returns the
 * surrounding pair. An exact interior timestamp treats that point as the
 * previous eclipse; dates outside coverage use the nearest edge interval.
 */
fractonica_temporal_status_t fractonica_temporal_series_bracket(
    const fractonica_temporal_eclipse_point_t *eclipses,
    size_t eclipse_count,
    int64_t at_epoch_seconds,
    fractonica_temporal_series_interval_t *out_interval);

/*
 * Computes a bounded clock at a regular calculation depth (1..8). Epochs are
 * seconds, and now_epoch_seconds must be finite. Time outside the interval is
 * clamped to its first/last address just as in the Rust temporal core.
 */
fractonica_temporal_status_t fractonica_temporal_clock_reading(
    const fractonica_temporal_interval_t *interval,
    double now_epoch_seconds,
    uint8_t depth,
    fractonica_temporal_clock_reading_t *out_reading);

/* Computes the fixed ten-digit pulse and splits it MSB [5] + LSB [5]. */
fractonica_temporal_status_t fractonica_temporal_pulse_reading_10(
    const fractonica_temporal_interval_t *interval,
    double now_epoch_seconds,
    fractonica_temporal_pulse10_t *out_pulse);

#ifdef __cplusplus
}
#endif

#endif /* FRACTONICA_EMBEDDED_TEMPORAL_H */
