#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

case "$(uname -s)" in
  Darwin) HOST_LIBRARY="$ROOT/target/debug/libfractonica_mobile_ffi.dylib" ;;
  Linux) HOST_LIBRARY="$ROOT/target/debug/libfractonica_mobile_ffi.so" ;;
  *) echo "Unsupported host for UniFFI generation." >&2; exit 1 ;;
esac

cargo build --locked -p fractonica-mobile-ffi
mkdir -p \
  "$ROOT/packages/mobile-native/ios/Generated" \
  "$ROOT/packages/mobile-native/android/src/main/java"

cargo run --quiet --locked -p fractonica-uniffi-bindgen -- generate \
  --library "$HOST_LIBRARY" \
  --language swift \
  --out-dir "$ROOT/packages/mobile-native/ios/Generated" \
  --no-format

cargo run --quiet --locked -p fractonica-uniffi-bindgen -- generate \
  --library "$HOST_LIBRARY" \
  --language kotlin \
  --out-dir "$ROOT/packages/mobile-native/android/src/main/java" \
  --no-format

echo "Generated pinned UniFFI 0.32.0 Swift and Kotlin bindings."
