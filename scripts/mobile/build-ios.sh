#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SIMULATOR_TARGETS=("aarch64-apple-ios-sim" "x86_64-apple-ios")
DEVICE_TARGET="aarch64-apple-ios"
IOS_TARGET_DIR="$ROOT/target/mobile-ios-16.4"
DEVICE_LIBRARY="$IOS_TARGET_DIR/$DEVICE_TARGET/release/libfractonica_mobile_ffi.a"
DESTINATION="$ROOT/packages/mobile-native/ios/Rust/FractonicaMobileCoreFFI.xcframework"
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/fractonica-ios.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
SIMULATOR_LIBRARY="$STAGE/simulator/libfractonica_mobile_ffi.a"

"$ROOT/scripts/mobile/generate-bindings.sh"

for target in "${SIMULATOR_TARGETS[@]}" "$DEVICE_TARGET"; do
  if ! rustup target list --installed | grep -qx "$target"; then
    echo "Install the iOS Rust targets first: rustup target add ${SIMULATOR_TARGETS[*]} $DEVICE_TARGET" >&2
    exit 1
  fi
done

cd "$ROOT"
for target in "${SIMULATOR_TARGETS[@]}"; do
  IPHONEOS_DEPLOYMENT_TARGET=16.4 CARGO_TARGET_DIR="$IOS_TARGET_DIR" \
    cargo build --locked --release -p fractonica-mobile-ffi --target "$target"
done
IPHONEOS_DEPLOYMENT_TARGET=16.4 CARGO_TARGET_DIR="$IOS_TARGET_DIR" \
  cargo build --locked --release -p fractonica-mobile-ffi --target "$DEVICE_TARGET"
mkdir -p "$STAGE/headers" "$(dirname "$SIMULATOR_LIBRARY")" "$ROOT/packages/mobile-native/ios/Rust"
cp "$ROOT/packages/mobile-native/ios/Generated/FractonicaMobileCoreFFI.h" "$STAGE/headers/"
cp "$ROOT/packages/mobile-native/ios/Generated/FractonicaMobileCoreFFI.modulemap" "$STAGE/headers/module.modulemap"

lipo -create \
  "$IOS_TARGET_DIR/aarch64-apple-ios-sim/release/libfractonica_mobile_ffi.a" \
  "$IOS_TARGET_DIR/x86_64-apple-ios/release/libfractonica_mobile_ffi.a" \
  -output "$SIMULATOR_LIBRARY"

xcodebuild -create-xcframework \
  -library "$SIMULATOR_LIBRARY" \
  -headers "$STAGE/headers" \
  -library "$DEVICE_LIBRARY" \
  -headers "$STAGE/headers" \
  -output "$STAGE/FractonicaMobileCoreFFI.xcframework"

if [[ -e "$DESTINATION" ]]; then
  mv "$DESTINATION" "$STAGE/previous.xcframework"
fi
mv "$STAGE/FractonicaMobileCoreFFI.xcframework" "$DESTINATION"

echo "Built iOS device and simulator XCFramework at $DESTINATION"
