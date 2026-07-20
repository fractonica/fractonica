#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
API="${FRACTONICA_ANDROID_API:-24}"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Library/Android/sdk}}"
NDK_VERSION="${FRACTONICA_ANDROID_NDK_VERSION:-27.1.12297006}"

# Expo's generated Android project builds these four ABIs by default. Keep the
# Rust artifacts in lockstep so an APK can never install successfully and then
# fail only when JNA tries to load the Fractonica core.
TARGETS=(
  "aarch64-linux-android"
  "armv7-linux-androideabi"
  "i686-linux-android"
  "x86_64-linux-android"
)
ABIS=(
  "arm64-v8a"
  "armeabi-v7a"
  "x86"
  "x86_64"
)
COMPILERS=(
  "aarch64-linux-android${API}-clang"
  "armv7a-linux-androideabi${API}-clang"
  "i686-linux-android${API}-clang"
  "x86_64-linux-android${API}-clang"
)
ENV_TARGETS=(
  "aarch64_linux_android"
  "armv7_linux_androideabi"
  "i686_linux_android"
  "x86_64_linux_android"
)
CARGO_ENV_TARGETS=(
  "AARCH64_LINUX_ANDROID"
  "ARMV7_LINUX_ANDROIDEABI"
  "I686_LINUX_ANDROID"
  "X86_64_LINUX_ANDROID"
)

NDK_ROOT="${FRACTONICA_ANDROID_NDK_ROOT:-$SDK_ROOT/ndk/$NDK_VERSION}"
if [[ ! -d "$NDK_ROOT" ]]; then
  echo "Android NDK $NDK_VERSION not found at $NDK_ROOT." >&2
  echo "Install it with: sdkmanager \"ndk;$NDK_VERSION\"" >&2
  exit 1
fi
case "$(uname -s)-$(uname -m)" in
  Darwin-*) HOST_TAG="darwin-x86_64" ;;
  Linux-x86_64) HOST_TAG="linux-x86_64" ;;
  Linux-aarch64) HOST_TAG="linux-x86_64" ;;
  *) echo "Unsupported Android NDK host." >&2; exit 1 ;;
esac

TOOLCHAIN="$NDK_ROOT/toolchains/llvm/prebuilt/$HOST_TAG/bin"
MISSING_TARGETS=()
for target in "${TARGETS[@]}"; do
  if ! rustup target list --installed | grep -qx "$target"; then
    MISSING_TARGETS+=("$target")
  fi
done
if (( ${#MISSING_TARGETS[@]} > 0 )); then
  echo "Install the Android Rust targets first: rustup target add ${MISSING_TARGETS[*]}" >&2
  exit 1
fi

"$ROOT/scripts/mobile/generate-bindings.sh"
cd "$ROOT"
for index in "${!TARGETS[@]}"; do
  target="${TARGETS[$index]}"
  abi="${ABIS[$index]}"
  linker="$TOOLCHAIN/${COMPILERS[$index]}"
  env_target="${ENV_TARGETS[$index]}"
  cargo_env_target="${CARGO_ENV_TARGETS[$index]}"

  if [[ ! -x "$linker" ]]; then
    echo "Android $abi linker not found at $linker." >&2
    exit 1
  fi

  env \
    "CC_${env_target}=$linker" \
    "AR_${env_target}=$TOOLCHAIN/llvm-ar" \
    "CARGO_TARGET_${cargo_env_target}_LINKER=$linker" \
    cargo build --locked --release -p fractonica-mobile-ffi --target "$target"

  destination="$ROOT/packages/mobile-native/android/src/main/jniLibs/$abi"
  mkdir -p "$destination"
  install -m 0755 \
    "$ROOT/target/$target/release/libfractonica_mobile_ffi.so" \
    "$destination/libfractonica_mobile_ffi.so"
  echo "Built Android $abi library at $destination/libfractonica_mobile_ffi.so"
done
