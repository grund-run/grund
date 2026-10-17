#!/bin/sh
set -eu

# These directories are disposable; no normal developer target is overwritten.
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
export CARGO_TARGET_DIR="$root/scratch/tag-release/target"
export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0
export RUSTC_WRAPPER=sccache SCCACHE_DIR="${SCCACHE_DIR:-$HOME/.cache/sccache}" SCCACHE_CACHE_SIZE=40G
export RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-musl
python3 tools/release.py prepare
export GRUND_VERSION="$CI_COMMIT_TAG" GRUND_REVISION="$CI_COMMIT_SHA"
# A rerun must reproduce the same immutable package, including attribution.
export GRUND_BUILD_TIME="$(git show -s --format=%cI "$CI_COMMIT_SHA")"

mkdir -p scratch/tag-release/tooling
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz \
    -o scratch/tag-release/tooling/zig.tar.xz
printf '%s  %s\n' d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea \
    scratch/tag-release/tooling/zig.tar.xz | sha256sum -c -
tar -xJf scratch/tag-release/tooling/zig.tar.xz -C scratch/tag-release/tooling
export PATH="$root/scratch/tag-release/tooling/zig-linux-x86_64-0.13.0:$PATH"
cargo install --locked --version 0.22.1 --root "$root/scratch/tag-release/tooling/cargo" cargo-zigbuild
export PATH="$root/scratch/tag-release/tooling/cargo/bin:$PATH"
rustup target add aarch64-unknown-linux-musl

cargo build --locked --release -p grund --bin grund --target x86_64-unknown-linux-musl
cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/grund" scratch/tag-release/dist/grund-linux-amd64
# Zig compiles C dependencies; Rust's bundled LLVM linker retains the
# Cortex-A53 erratum fix that Zig's linker driver does not accept.
host=$(rustc -vV | sed -n 's/^host: //p')
linker="$(rustc --print sysroot)/lib/rustlib/$host/bin/rust-lld"
test -x "$linker"
RUSTFLAGS="-C linker=$linker" cargo zigbuild --locked --release -p grund --bin grund --target aarch64-unknown-linux-musl
cp "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/grund" scratch/tag-release/dist/grund-linux-arm64
python3 tools/release.py verify
