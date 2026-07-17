# Embedded C SDK

This SDK is licensed under Apache-2.0; see [LICENSE](LICENSE).

This directory exposes small, dependency-free C11 APIs usable from ESP-IDF C
and C++ for the parts of Fractonica that belong on constrained helpers:

- a portable temporal clock, MSB-first pulse addressing, and rarity rules;
- glyph geometry with renderer adapters for displays such as LVGL.

The ABI will use plain fixed-width values, caller-owned buffers, explicit
lengths, status codes, and an ABI version. Panics, exceptions, allocation
ownership, platform handles, and RTOS objects may not cross the boundary.

Pairing, authenticated communication, and device-message envelopes do **not**
have a published C ABI yet. Their security model and canonical bytes must be
defined before an embedded client is allowed to speak to a node.

## Portable temporal clock

`fractonica/embedded/temporal.h` is the C11 counterpart to the allocation-free
Rust temporal core. It provides fixed-width MSB-first octal addresses, the
same exact-flip rarity rule, regular clock readings at depths one through
eight, a bounded binary search over a caller-owned single-Saros timestamp
table, and the realtime ten-digit pulse split into two five-digit glyphs.

```c
#include "fractonica/embedded/temporal.h"

fractonica_temporal_interval_t interval = {
    .previous_epoch_seconds = previous_eclipse_epoch,
    .next_epoch_seconds = next_eclipse_epoch,
};
fractonica_temporal_pulse10_t pulse;

if (fractonica_temporal_pulse_reading_10(&interval, now_epoch, &pulse) ==
    FRACTONICA_TEMPORAL_OK) {
    /* pulse.most_significant and pulse.least_significant are 5 octal digits. */
}
```

The SDK contains no eclipse catalogue. A helper may carry a separately
provenanced, bounded timestamp table and pass its surrounding interval to the
clock. See [the data provenance policy](../../docs/data-provenance.md) before
shipping any temporal dataset.

## Portable octal glyph geometry

`fractonica/embedded/glyph.h` is an allocation-free C11 emitter. Caller-owned
code receives compound core and arm outlines through a callback, then decides
how to draw them. The component has no ESP-IDF, LVGL, heap, filesystem, or
network dependency. Its generated default is the versioned `fractonica-hex-v2`
font; the grammar remains the semantic `1 / 2 / 4` octal contract.

The default is a five-digit glyph. The depth is configurable from three to
eight sockets. Input is an explicit-length, MSB-first ASCII octal string, and
short values are left-padded with zeroes. It rejects non-octal input and values
longer than the configured depth rather than silently changing the value.

The socket ordering follows the established circular glyph convention: socket
zero holds the most significant digit, and the remaining sockets run from the
least significant digit back toward the most significant one. Therefore a
five-digit `"12345"` glyph has socket values `1, 5, 4, 3, 2`.

The callback's contour and point pointers are transient: render or copy them
before the callback returns. The core has two contours and requires
`FRACTONICA_GLYPH_FILL_EVENODD`, which produces its aperture without a special
erase polygon. Each arm has one contour and uses
`FRACTONICA_GLYPH_FILL_NONZERO`.

```c
#include "fractonica/embedded/glyph.h"

static bool draw_polygon(void *display, const fractonica_glyph_polygon_t *polygon) {
    for (uint8_t i = 0; i < polygon->contour_count; ++i) {
        const fractonica_glyph_contour_t *contour = &polygon->contours[i];
        /* Adapt contour->points / contour->point_count to your display API. */
    }
    /* Use polygon->fill_rule when filling a compound outline. */
    return true;
}

fractonica_glyph_config_t glyph;
fractonica_glyph_config_init(&glyph); /* five sockets, unit radius */
glyph.center_x = 120.0f;
glyph.center_y = 120.0f;
glyph.radius = 88.0f;

fractonica_glyph_emit_octal_text(
    &glyph, "72444", 5u, draw_polygon, display, NULL);
```

### Host validation

From this directory:

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

For a minimal compiler-only check (on toolchains where `-lm` is needed):

```sh
cc -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude \
  src/glyph.c tests/glyph_test.c -lm -o glyph_test
./glyph_test
cc -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude \
  src/temporal.c tests/temporal_test.c -lm -o temporal_test
./temporal_test
```

The CMake target `fractonica::embedded` links both stable components;
`fractonica::embedded_glyph` and `fractonica::embedded_temporal` are available
when a helper only needs one. The test suite also compiles a C++17 consumer
against the C API. The glyph component has ABI version `2` (compound contours);
the temporal component remains ABI version `1`. They are independently usable.

### ESP-IDF component use

Add this directory to an ESP-IDF project's `EXTRA_COMPONENT_DIRS`. Its
`CMakeLists.txt` detects `idf_component_register`, compiles the two C11 source
files as one component, and exports `include` to C and C++ consumers:

```cmake
set(EXTRA_COMPONENT_DIRS "/absolute/path/to/fractonica/sdk/embedded-c")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(my_fractonica_helper)
```

Keep display, audio, radio, storage, and network code in the helper's own
component. The SDK intentionally has no ESP-IDF dependency and should not be
modified to contain product-specific hardware policy.
