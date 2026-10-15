#!/usr/bin/env bash
# Exercise the same release binaries as guest-image CI, then a sparse copy of
# grund that retains its ELF bytes but needs more ext4 blocks than `du -sk` sees.
# GRUND_BINARY=... GRUND_GUEST_BINARY=... ./crates/grund-guest/test-build-image.sh
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
grund="$(realpath -e "${GRUND_BINARY:?set GRUND_BINARY to the release grund}")"
guest="$(realpath -e "${GRUND_GUEST_BINARY:?set GRUND_GUEST_BINARY to the release grund-guest}")"
scratch="${GRUND_GUEST_TEST_ROOT:-$repo/../scratch/guest-image}"
mkdir -p "$scratch"
work="$(mktemp -d "$scratch/image.XXXXXX")"
trap 'rm -rf "$work"' EXIT

check_image() {
  local name="$1" binary="$2" image="$work/$1.ext4"
  TMPDIR="$work" GRUND_BINARY="$binary" GRUND_GUEST_BINARY="$guest" \
    "$repo/crates/grund-guest/build-image.sh" "$image"
  debugfs -R "dump /usr/local/bin/grund $work/$name.grund" "$image" >"$work/$name.debugfs" 2>&1
  cmp "$binary" "$work/$name.grund"
  debugfs -R "dump /sbin/init $work/$name.init" "$image" >"$work/$name.debugfs" 2>&1
  cmp "$guest" "$work/$name.init"
}

check_image release "$grund"
cp --sparse=always "$grund" "$work/sparse-grund"
truncate -s "$(( $(stat -c '%s' "$grund") + 64 * 1048576 ))" "$work/sparse-grund"
check_image sparse "$work/sparse-grund"
echo "guest image smoke: release and sparse release binaries match their ext4 copies"
