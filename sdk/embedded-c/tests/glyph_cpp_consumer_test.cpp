// SPDX-License-Identifier: Apache-2.0

#include "fractonica/embedded/glyph.h"
#include "fractonica/embedded/temporal.h"

#include <cstdint>

namespace {

struct Capture {
    std::uint16_t polygons = 0;
};

bool consume_polygon(void *context, const fractonica_glyph_polygon_t *polygon) {
    auto *capture = static_cast<Capture *>(context);
    if (capture == nullptr || polygon == nullptr || polygon->points == nullptr ||
        polygon->point_count < 3u) {
        return false;
    }
    ++capture->polygons;
    return true;
}

} // namespace

int main() {
    fractonica_glyph_config_t glyph;
    fractonica_glyph_emit_result_t result{};
    Capture capture{};

    fractonica_glyph_config_init(&glyph);
    glyph.radius = 64.0f;

    const auto status = fractonica_glyph_emit_octal_text(
        &glyph, "72444", 5u, consume_polygon, &capture, &result);
    fractonica_temporal_address_t address{};
    fractonica_temporal_rarity_t rarity{};
    const auto temporal_status = fractonica_temporal_address_parse_octal(
        &address, "72444", 5u);
    const auto rarity_status = fractonica_temporal_classify_rarity(&address, &rarity);

    return status == FRACTONICA_GLYPH_STATUS_OK &&
                   temporal_status == FRACTONICA_TEMPORAL_OK &&
                   rarity_status == FRACTONICA_TEMPORAL_OK &&
                   capture.polygons == result.emitted_polygon_count &&
                   capture.polygons >= 2u &&
                   rarity.family == FRACTONICA_TEMPORAL_RARITY_DUPLEX
               ? 0
               : 1;
}
