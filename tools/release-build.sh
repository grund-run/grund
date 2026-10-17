#!/bin/sh
set -eu

# Build one architecture for a parallel release, or both for a serial control.
# Benchmark staging cannot publish: every publishing command still checks a tag.
benchmark=false
if [ "${1:-}" = "--benchmark" ]; then
    benchmark=true
    shift
fi
arch="${1:-all}"
[ "$#" -le 1 ] || { echo "usage: release-build.sh [--benchmark] [amd64|arm64|all]" >&2; exit 2; }
case "$arch" in amd64|arm64|all) ;; *) echo "unknown release architecture: $arch" >&2; exit 2;; esac

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/scratch/tag-release/target}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" CARGO_INCREMENTAL=0
export RUSTC_WRAPPER=sccache SCCACHE_DIR="${SCCACHE_DIR:-$HOME/.cache/sccache}" SCCACHE_CACHE_SIZE=40G
export RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-musl
export GRUND_REVISION="$(git rev-parse "${CI_COMMIT_SHA}^{commit}")"
# A rerun reproduces the same attribution; benchmark labels force a new link.
export GRUND_BUILD_TIME="$(git show -s --format=%cI "$GRUND_REVISION")"
verify=verify
if "$benchmark"; then
    export GRUND_RELEASE_BENCHMARK_VERSION="${GRUND_RELEASE_BENCHMARK_VERSION:-ciperf-$GRUND_REVISION}"
    export GRUND_VERSION="$GRUND_RELEASE_BENCHMARK_VERSION"
    python3 tools/release.py prepare-benchmark
    verify=verify-benchmark
else
    python3 tools/release.py prepare
    export GRUND_VERSION="$CI_COMMIT_TAG"
fi

if "$benchmark" && [ -n "${GRUND_RELEASE_ROOT_CGU:-}" ]; then
    cargo() {
        command cargo --config "profile.release.package.grund.codegen-units=$GRUND_RELEASE_ROOT_CGU" "$@"
    }
fi

if [ "$arch" = amd64 ] || [ "$arch" = all ]; then
    # Match main's native musl build, so its dependency snapshot is reusable.
    cargo build --locked --release -p grund --bin grund
    cp "$CARGO_TARGET_DIR/release/grund" scratch/tag-release/dist/grund-linux-amd64
    python3 tools/release.py "$verify-amd64"
fi

if [ "$arch" = arm64 ] || [ "$arch" = all ]; then
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
        # Only the installed tool is reused; its own build artifacts are not.
        CARGO_TARGET_DIR="$root/scratch/tag-release/tool-target" \
            cargo install --locked --target "$host" --version 0.22.1 --root "$tooling/cargo" cargo-zigbuild
        rm -rf "$root/scratch/tag-release/tool-target"
    fi
    rustup target add aarch64-unknown-linux-musl
    # Rust's linker retains Cortex-A53's erratum fix, absent in Zig's driver.
    linker="$(rustc --print sysroot)/lib/rustlib/$host/bin/rust-lld"
    test -x "$linker"
    RUSTFLAGS="-C linker=$linker" cargo zigbuild --locked --release -p grund --bin grund --target aarch64-unknown-linux-musl
    cp "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/grund" scratch/tag-release/dist/grund-linux-arm64
    python3 tools/release.py "$verify-arm64"
fi
