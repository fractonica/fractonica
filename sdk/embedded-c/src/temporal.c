/* SPDX-License-Identifier: Apache-2.0 */

#include "fractonica/embedded/temporal.h"

#include <float.h>
#include <math.h>

static fractonica_temporal_status_t fractonica_temporal_octal_power(
    uint8_t exponent,
    uint32_t *out_power) {
    uint32_t result = 1u;
    uint8_t index;

    if (out_power == NULL) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }
    if (exponent > FRACTONICA_TEMPORAL_MAX_ADDRESS_DEPTH) {
        return FRACTONICA_TEMPORAL_INVALID_DEPTH;
    }

    for (index = 0u; index < exponent; ++index) {
        result *= FRACTONICA_TEMPORAL_RADIX;
    }
    *out_power = result;
    return FRACTONICA_TEMPORAL_OK;
}

static int fractonica_temporal_isfinite(double value) {
    return value == value && value <= DBL_MAX && value >= -DBL_MAX;
}

static fractonica_temporal_status_t fractonica_temporal_validate_address(
    const fractonica_temporal_address_t *address) {
    uint32_t bin_count;
    fractonica_temporal_status_t status;

    if (address == NULL) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }
    if (address->depth == 0u ||
        address->depth > FRACTONICA_TEMPORAL_MAX_ADDRESS_DEPTH) {
        return FRACTONICA_TEMPORAL_INVALID_DEPTH;
    }
    status = fractonica_temporal_octal_power(address->depth, &bin_count);
    if (status != FRACTONICA_TEMPORAL_OK) {
        return status;
    }
    if (address->value >= bin_count) {
        return FRACTONICA_TEMPORAL_ADDRESS_OUT_OF_RANGE;
    }
    return FRACTONICA_TEMPORAL_OK;
}

static uint64_t fractonica_temporal_positive_interval_seconds(
    int64_t previous_epoch_seconds,
    int64_t next_epoch_seconds) {
    if (previous_epoch_seconds < 0 && next_epoch_seconds >= 0) {
        /* Avoid negating INT64_MIN and preserve the full UINT64 range. */
        return (uint64_t)(-(previous_epoch_seconds + 1)) + 1u +
               (uint64_t)next_epoch_seconds;
    }
    return (uint64_t)(next_epoch_seconds - previous_epoch_seconds);
}

fractonica_temporal_status_t fractonica_temporal_address_init(
    fractonica_temporal_address_t *out_address,
    uint32_t value,
    uint8_t depth) {
    fractonica_temporal_address_t address;
    fractonica_temporal_status_t status;

    if (out_address == NULL) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }
    address.value = value;
    address.depth = depth;
    status = fractonica_temporal_validate_address(&address);
    if (status != FRACTONICA_TEMPORAL_OK) {
        return status;
    }
    *out_address = address;
    return FRACTONICA_TEMPORAL_OK;
}

fractonica_temporal_status_t fractonica_temporal_address_parse_octal(
    fractonica_temporal_address_t *out_address,
    const char *digits,
    size_t digit_count) {
    uint32_t value = 0u;
    size_t index;

    if (out_address == NULL || digits == NULL) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }
    if (digit_count == 0u ||
        digit_count > FRACTONICA_TEMPORAL_MAX_ADDRESS_DEPTH) {
        return FRACTONICA_TEMPORAL_INVALID_DEPTH;
    }

    for (index = 0u; index < digit_count; ++index) {
        unsigned char digit = (unsigned char)digits[index];
        if (digit < (unsigned char)'0' || digit > (unsigned char)'7') {
            return FRACTONICA_TEMPORAL_INVALID_ADDRESS_DIGIT;
        }
        value = value * FRACTONICA_TEMPORAL_RADIX +
                (uint32_t)(digit - (unsigned char)'0');
    }

    return fractonica_temporal_address_init(
        out_address, value, (uint8_t)digit_count);
}

fractonica_temporal_status_t fractonica_temporal_address_digit_msb(
    const fractonica_temporal_address_t *address,
    uint8_t index,
    uint8_t *out_digit) {
    uint8_t exponent;
    uint32_t divisor;
    fractonica_temporal_status_t status;

    if (out_digit == NULL) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }
    status = fractonica_temporal_validate_address(address);
    if (status != FRACTONICA_TEMPORAL_OK) {
        return status;
    }
    if (index >= address->depth) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }

    exponent = (uint8_t)(address->depth - index - 1u);
    status = fractonica_temporal_octal_power(exponent, &divisor);
    if (status != FRACTONICA_TEMPORAL_OK) {
        return status;
    }
    *out_digit = (uint8_t)((address->value / divisor) %
                           FRACTONICA_TEMPORAL_RADIX);
    return FRACTONICA_TEMPORAL_OK;
}

fractonica_temporal_status_t fractonica_temporal_address_format_msb(
    const fractonica_temporal_address_t *address,
    char *output,
    size_t output_capacity) {
    uint8_t index;
    fractonica_temporal_status_t status;

    if (output == NULL) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }
    status = fractonica_temporal_validate_address(address);
    if (status != FRACTONICA_TEMPORAL_OK) {
        return status;
    }
    if (output_capacity < (size_t)address->depth + 1u) {
        return FRACTONICA_TEMPORAL_BUFFER_TOO_SMALL;
    }

    for (index = 0u; index < address->depth; ++index) {
        uint8_t digit;
        status = fractonica_temporal_address_digit_msb(address, index, &digit);
        if (status != FRACTONICA_TEMPORAL_OK) {
            return status;
        }
        output[index] = (char)('0' + digit);
    }
    output[address->depth] = '\0';
    return FRACTONICA_TEMPORAL_OK;
}

fractonica_temporal_status_t fractonica_temporal_classify_rarity(
    const fractonica_temporal_address_t *address,
    fractonica_temporal_rarity_t *out_rarity) {
    fractonica_temporal_status_t status;
    uint32_t adjusted;
    uint32_t remaining;
    uint8_t repeated_digit;
    uint8_t suffix_length = 0u;
    uint8_t wildcard_prefix;

    if (out_rarity == NULL) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }
    status = fractonica_temporal_validate_address(address);
    if (status != FRACTONICA_TEMPORAL_OK) {
        return status;
    }

    if (address->value == 0u) {
        out_rarity->family = FRACTONICA_TEMPORAL_RARITY_NIHIL;
        out_rarity->digit = 7u;
        return FRACTONICA_TEMPORAL_OK;
    }

    adjusted = address->value;
    if (adjusted % FRACTONICA_TEMPORAL_RADIX == 0u) {
        --adjusted;
    }
    repeated_digit = (uint8_t)(adjusted % FRACTONICA_TEMPORAL_RADIX);
    remaining = adjusted;
    while (suffix_length < address->depth &&
           remaining % FRACTONICA_TEMPORAL_RADIX == repeated_digit) {
        ++suffix_length;
        remaining /= FRACTONICA_TEMPORAL_RADIX;
    }

    wildcard_prefix = (uint8_t)(address->depth - suffix_length);
    switch (wildcard_prefix) {
        case 3u:
            out_rarity->family = FRACTONICA_TEMPORAL_RARITY_TRIPLEX;
            break;
        case 2u:
            out_rarity->family = FRACTONICA_TEMPORAL_RARITY_DUPLEX;
            break;
        case 1u:
            out_rarity->family = FRACTONICA_TEMPORAL_RARITY_SIMPLEX;
            break;
        case 0u:
            out_rarity->family = FRACTONICA_TEMPORAL_RARITY_NIHIL;
            break;
        default:
            out_rarity->family = FRACTONICA_TEMPORAL_RARITY_COMMON;
            break;
    }
    out_rarity->digit = out_rarity->family == FRACTONICA_TEMPORAL_RARITY_COMMON
                             ? 0u
                             : repeated_digit;
    return FRACTONICA_TEMPORAL_OK;
}

const char *fractonica_temporal_rarity_digit_name(uint8_t digit) {
    switch (digit) {
        case 1u:
            return "Alpha";
        case 2u:
            return "Beta";
        case 3u:
            return "Gamma";
        case 4u:
            return "Delta";
        case 5u:
            return "Epsilon";
        case 6u:
            return "Digamma";
        case 7u:
            return "Omega";
        default:
            return "Common";
    }
}

fractonica_temporal_status_t fractonica_temporal_series_bracket(
    const fractonica_temporal_eclipse_point_t *eclipses,
    size_t eclipse_count,
    int64_t at_epoch_seconds,
    fractonica_temporal_series_interval_t *out_interval) {
    size_t previous_index;
    size_t next_index;
    size_t index;
    uint8_t saros;

    if (eclipses == NULL || out_interval == NULL) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }
    if (eclipse_count < 2u) {
        return FRACTONICA_TEMPORAL_TOO_FEW_ECLIPSES;
    }

    saros = eclipses[0].saros;
    for (index = 1u; index < eclipse_count; ++index) {
        if (eclipses[index].saros != saros) {
            return FRACTONICA_TEMPORAL_MIXED_SAROS_SERIES;
        }
        if (eclipses[index - 1u].epoch_seconds >= eclipses[index].epoch_seconds) {
            return FRACTONICA_TEMPORAL_UNSORTED_ECLIPSES;
        }
    }

    if (at_epoch_seconds <= eclipses[0].epoch_seconds) {
        previous_index = 0u;
        next_index = 1u;
    } else if (at_epoch_seconds >= eclipses[eclipse_count - 1u].epoch_seconds) {
        previous_index = eclipse_count - 2u;
        next_index = eclipse_count - 1u;
    } else {
        size_t low = 1u;
        size_t high = eclipse_count - 1u;
        while (low < high) {
            const size_t middle = low + (high - low) / 2u;
            if (eclipses[middle].epoch_seconds <= at_epoch_seconds) {
                low = middle + 1u;
            } else {
                high = middle;
            }
        }
        previous_index = low - 1u;
        next_index = low;
    }

    out_interval->saros = saros;
    out_interval->previous = eclipses[previous_index];
    out_interval->next = eclipses[next_index];
    return FRACTONICA_TEMPORAL_OK;
}

static fractonica_temporal_status_t fractonica_temporal_clock_reading_at_depth(
    const fractonica_temporal_interval_t *interval,
    double now_epoch_seconds,
    uint8_t depth,
    fractonica_temporal_clock_reading_t *out_reading) {
    uint64_t total_seconds;
    uint32_t bin_count;
    long double raw_phase;
    long double phase;
    long double scaled;
    uint32_t bin_index;
    uint32_t next_bin_index;
    fractonica_temporal_status_t status;

    if (interval == NULL || out_reading == NULL) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }
    if (depth == 0u || depth > FRACTONICA_TEMPORAL_MAX_ADDRESS_DEPTH) {
        return FRACTONICA_TEMPORAL_INVALID_DEPTH;
    }
    if (!fractonica_temporal_isfinite(now_epoch_seconds)) {
        return FRACTONICA_TEMPORAL_NONFINITE_TIMESTAMP;
    }
    if (interval->next_epoch_seconds <= interval->previous_epoch_seconds) {
        return FRACTONICA_TEMPORAL_INVALID_INTERVAL;
    }
    status = fractonica_temporal_octal_power(depth, &bin_count);
    if (status != FRACTONICA_TEMPORAL_OK) {
        return status;
    }

    total_seconds = fractonica_temporal_positive_interval_seconds(
        interval->previous_epoch_seconds, interval->next_epoch_seconds);
    raw_phase = ((long double)now_epoch_seconds -
                 (long double)interval->previous_epoch_seconds) /
                (long double)total_seconds;
    if (raw_phase < 0.0L) {
        phase = 0.0L;
    } else if (raw_phase >= 1.0L) {
        phase = 1.0L - (long double)DBL_EPSILON;
    } else {
        phase = raw_phase;
    }
    scaled = phase * (long double)bin_count;
    bin_index = (uint32_t)scaled;
    if (bin_index >= bin_count) {
        bin_index = bin_count - 1u;
    }
    next_bin_index = bin_index + 1u;

    out_reading->phase = (double)phase;
    out_reading->bin_count = bin_count;
    out_reading->bin_index = bin_index;
    status = fractonica_temporal_address_init(
        &out_reading->address, bin_index, depth);
    if (status != FRACTONICA_TEMPORAL_OK) {
        return status;
    }
    out_reading->progress_within_bin = (double)(
        scaled - (long double)bin_index);
    if (out_reading->progress_within_bin < 0.0) {
        out_reading->progress_within_bin = 0.0;
    } else if (out_reading->progress_within_bin > 1.0) {
        out_reading->progress_within_bin = 1.0;
    }
    out_reading->next_flip_epoch_seconds = (double)(
        (long double)interval->previous_epoch_seconds +
        ((long double)next_bin_index / (long double)bin_count) *
            (long double)total_seconds);
    out_reading->time_until_flip_seconds =
        out_reading->next_flip_epoch_seconds - now_epoch_seconds;
    return FRACTONICA_TEMPORAL_OK;
}

fractonica_temporal_status_t fractonica_temporal_clock_reading(
    const fractonica_temporal_interval_t *interval,
    double now_epoch_seconds,
    uint8_t depth,
    fractonica_temporal_clock_reading_t *out_reading) {
    if (depth < FRACTONICA_TEMPORAL_MIN_CALCULATION_DEPTH ||
        depth > FRACTONICA_TEMPORAL_MAX_CALCULATION_DEPTH) {
        return FRACTONICA_TEMPORAL_INVALID_DEPTH;
    }
    return fractonica_temporal_clock_reading_at_depth(
        interval, now_epoch_seconds, depth, out_reading);
}

fractonica_temporal_status_t fractonica_temporal_pulse_reading_10(
    const fractonica_temporal_interval_t *interval,
    double now_epoch_seconds,
    fractonica_temporal_pulse10_t *out_pulse) {
    uint8_t index;
    fractonica_temporal_status_t status;

    if (out_pulse == NULL) {
        return FRACTONICA_TEMPORAL_INVALID_ARGUMENT;
    }
    /* Pulse depth is intentionally above regular caller-selectable depth. */
    status = fractonica_temporal_clock_reading_at_depth(
        interval,
        now_epoch_seconds,
        FRACTONICA_TEMPORAL_REALTIME_PULSE_DEPTH,
        &out_pulse->clock);
    if (status != FRACTONICA_TEMPORAL_OK) {
        return status;
    }

    for (index = 0u; index < FRACTONICA_TEMPORAL_GLYPH_DIGITS; ++index) {
        status = fractonica_temporal_address_digit_msb(
            &out_pulse->clock.address, index, &out_pulse->most_significant[index]);
        if (status != FRACTONICA_TEMPORAL_OK) {
            return status;
        }
        status = fractonica_temporal_address_digit_msb(
            &out_pulse->clock.address,
            (uint8_t)(index + FRACTONICA_TEMPORAL_GLYPH_DIGITS),
            &out_pulse->least_significant[index]);
        if (status != FRACTONICA_TEMPORAL_OK) {
            return status;
        }
    }
    return FRACTONICA_TEMPORAL_OK;
}
