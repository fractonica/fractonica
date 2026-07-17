# Firmware

Embedded helpers are bounded publishers, not full Fractonica nodes. They may
capture sensor or audio data, retain an offline queue, pair with a node, and
upload commands or content-addressed media. They do not embed SQLite, graph
materialization, peer-to-peer replication, or node policy.

Production ESP32 helpers will use pinned ESP-IDF C/C++ for hardware-facing
I2S, DMA, radios, NVS, OTA, watchdogs, power management, and LVGL integration.
They can link the portable Apache-2.0 [Embedded C SDK](../sdk/embedded-c) for
exact local temporal behavior and allocation-free glyph geometry. The SDK does
not bundle eclipse data; any device catalogue must satisfy the
[provenance policy](../docs/data-provenance.md).

Firmware network implementation starts after the pairing threat model and
bounded message format are accepted. Until then, helpers cannot infer a device
protocol or expose a public port on their own.
