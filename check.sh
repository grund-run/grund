#!/usr/bin/env bash
# Verify grund exactly as it ships: the static musl binary built in the CI
# image, packaged by Dockerfile.prebuilt into a read-only scratch container,
# asserted with the same accepttests (crates/grund/tests/accepttest) CI runs.
#
# Needs docker, and the development infrastructure (compose.dev.yaml), which
# this script starts. A script because it is docker orchestration; every
# assertion lives in the Rust accepttests.
set -euo pipefail
cd "$(dirname "$0")"

img=grund:check
name=grund-check
port=${PORT:-8497}
rust_image=rust:1.98-alpine

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "infrastructure (compose.dev.yaml)"
docker compose -f compose.dev.yaml up -d --wait >/dev/null
network=grund-dev_default
echo "  ok   postgres, nats, mailpit"

echo "cargo (host)"
cargo fmt --all --check
cargo run --locked -q -p comment-policy
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
echo "  ok   fmt, comment policy, clippy and tests"

echo "static binary ($rust_image, as CI builds it)"
docker run --rm -v "$PWD":/src -w /src \
  -v grund-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/src/target/musl -e OWNER="$(id -u):$(id -g)" \
  "$rust_image" sh -c 'apk add --no-cache -q musl-dev binutils protobuf-dev \
    && cargo build --locked --release -p grund; status=$?; chown -R "$OWNER" target/musl; [ $status -eq 0 ] \
    && ! readelf -d target/musl/release/grund | grep -q NEEDED'
mkdir -p .image
cp target/musl/release/grund .image/grund
echo "  ok   statically linked ($(du -h .image/grund | cut -f1))"

echo "image"
docker build -q -f Dockerfile.prebuilt -t "$img" .image >/dev/null
echo "  ok   scratch image builds ($(docker images "$img" --format '{{.Size}}'))"

echo "runtime (read-only, as deployed)"
cleanup
docker run -d --name "$name" --read-only --cap-drop ALL --network "$network" \
  -p "127.0.0.1:$port:8080" \
  -e GRUND_PUBLIC_URL="http://127.0.0.1:$port" \
  -e DATABASE_URL=postgres://grund:grund@postgres:5432/grund \
  -e GRUND_SECRET_KEY="$(openssl rand -hex 32)" \
  -e GRUND_NATS_URL=nats://nats:4222 \
  -e GRUND_SMTP_URL=smtp://mailpit:1025 \
  -e GRUND_WORK_POLL_INTERVAL=1 -e GRUND_HEALTH_INTERVAL=1 \
  -e GRUND_LOGIN_ATTEMPTS_PER_ADDRESS=0 -e GRUND_MAIL_REQUESTS_PER_ADDRESS=0 \
  -e GRUND_ORGANISATIONS=multi \
  "$img" >/dev/null
if ! GRUND_ACCEPT_URL="http://127.0.0.1:$port" GRUND_ACCEPT_MAILPIT_URL=http://127.0.0.1:58410 \
  cargo test --locked -p grund --test tests; then
  docker logs "$name"
  exit 1
fi

echo
echo "all checks passed"
