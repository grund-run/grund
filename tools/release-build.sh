#!/bin/sh
set -eu

# Each architecture has its own target directory and a read-only cache restore.
# The library cache producer never stages a binary or release payload.
[ "$#" -eq 1 ] || { echo "usage: release-build.sh {amd64|arm64|cache-arm64}" >&2; exit 2; }
mode="$1"
case "$mode" in amd64|arm64|cache-arm64) ;; *) echo "unknown release build: $mode" >&2; exit 2;; esac
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
export GRUND_REVISION="$(git rev-parse "${CI_COMMIT_SHA}^{commit}")"
if [ "$mode" = cache-arm64 ]; then
    case "${CI_PIPELINE_EVENT:-}" in
        push|manual) ;;
        *) echo "cache production requires a push or manual event" >&2; exit 1;;
    esac
    [ -z "${CI_COMMIT_TAG:-}" ] && [ "$(git rev-parse HEAD)" = "$GRUND_REVISION" ] \
        || { echo "cache production requires an untagged matching checkout" >&2; exit 1; }
else
    python3 tools/release.py prepare
fi
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/scratch/tag-release/target-$mode}"
export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0
export RUSTC_WRAPPER=sccache SCCACHE_DIR="${SCCACHE_DIR:-$HOME/.cache/sccache}"
export SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-2G}"
export RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-musl
export GRUND_VERSION="${CI_COMMIT_TAG:-}"
# A rerun reproduces the same immutable package, including attribution.
export GRUND_BUILD_TIME="$(git show -s --format=%cI "$GRUND_REVISION")"

if [ "$mode" = amd64 ]; then
    # Match main's native musl build instead of changing its Cargo unit hashes
    # with an explicit native --target.
    cargo build --locked --release -p grund --bin grund
    cp "$CARGO_TARGET_DIR/release/grund" scratch/tag-release/dist/grund-linux-amd64
    python3 tools/release.py verify-amd64
    exit
fi

tooling="$root/scratch/tag-release/tooling"
mkdir -p "$tooling"
if [ ! -f "$tooling/zig.tar.xz" ]; then
    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz \
        -o "$tooling/zig.tar.xz"
fi
printf '%s  %s\n' d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea \
    "$tooling/zig.tar.xz" | sha256sum -c -
tar -xJf "$tooling/zig.tar.xz" -C "$tooling"
export PATH="$tooling/zig-linux-x86_64-0.13.0:$tooling/cargo/bin:$PATH"
host=$(rustc -vV | sed -n 's/^host: //p')
if ! "$tooling/cargo/bin/cargo-zigbuild" --version 2>/dev/null | grep -qx 'cargo-zigbuild 0.22.1'; then
    # Reuse the installed tool, not its otherwise unbounded build directory.
    CARGO_TARGET_DIR="$root/scratch/tag-release/tool-target" \
        cargo install --locked --target "$host" --version 0.22.1 --root "$tooling/cargo" cargo-zigbuild
    rm -rf "$root/scratch/tag-release/tool-target"
fi
rustup target add aarch64-unknown-linux-musl
# Rust's linker retains Cortex-A53's erratum fix, absent in Zig's driver.
linker="$(rustc --print sysroot)/lib/rustlib/$host/bin/rust-lld"
test -x "$linker"
if [ "$mode" = cache-arm64 ]; then
    # Real libraries contain the reusable linker-plugin-LTO bitcode. Building
    # --bin here would pay the tag's final ThinLTO link on every main push.
    RUSTFLAGS="-C linker=$linker" cargo zigbuild --locked --release -p grund --lib --target aarch64-unknown-linux-musl
else
    RUSTFLAGS="-C linker=$linker" cargo zigbuild --locked --release -p grund --bin grund --target aarch64-unknown-linux-musl
    cp "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/grund" scratch/tag-release/dist/grund-linux-arm64
    python3 tools/release.py verify-arm64
fi
