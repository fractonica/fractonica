#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PLATFORM="${1:-all}"

case "$PLATFORM" in
  ios) "$ROOT/scripts/mobile/build-ios.sh" ;;
  android) "$ROOT/scripts/mobile/build-android.sh" ;;
  all)
    "$ROOT/scripts/mobile/build-ios.sh"
    "$ROOT/scripts/mobile/build-android.sh"
    ;;
  *) echo "Usage: $0 [ios|android|all]" >&2; exit 2 ;;
esac
