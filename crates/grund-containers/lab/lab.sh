#!/usr/bin/env bash
# lab.sh: grund-containers on a throwaway lab machine (fleet's lab/lab.sh),
# from this host, with no host changes. Builds the lab driver
# (examples/lab.rs) as a static musl binary, boots a fresh Debian 13 machine
# (2 vCPU, 2 GiB, 8 GiB), installs Docker in it first, runs scenario.sh as
# root (run, then private), and destroys the machine (KEEP=1 keeps it).
#
#   crates/grund-containers/lab/lab.sh
#
# With LAB_LOCK set, every call into the fleet lab is serialised through
# flock -o on that file, for a host whose lab others share.
# The runtime downloads containerd and runc itself,
# inside the machine, from their GitHub releases (that is what is tested).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
fleet_lab="${FLEET_LAB:-$repo/../fleet/lab/lab.sh}"
lock="${LAB_LOCK:-}"
name="${LAB_NAME:-grund-containers}"
target="${CARGO_TARGET_DIR:-$repo/target}"

lab() { if [[ -n "$lock" ]]; then flock -o "$lock" "$fleet_lab" "$@"; else "$fleet_lab" "$@"; fi; }

(cd "$repo" && cargo build -j4 --release -q --target x86_64-unknown-linux-musl -p grund-containers --example lab)
driver="$target/x86_64-unknown-linux-musl/release/examples/lab"

lab fetch >/dev/null
lab up "$name" --cpus 2 --mem 2048 --disk 8 >/dev/null
cleanup() { [[ "${KEEP:-}" == 1 ]] || lab destroy "$name" >/dev/null; }
trap cleanup EXIT
for _ in $(seq 60); do lab ssh "$name" true 2>/dev/null && break; sleep 2; done
lab put "$name" "$driver" "$here/scenario.sh" /tmp/
lab ssh "$name" 'sudo mkdir -p /opt/grund-lab && sudo mv /tmp/lab /tmp/scenario.sh /opt/grund-lab/ && sudo chmod +x /opt/grund-lab/lab /opt/grund-lab/scenario.sh'
lab ssh "$name" 'sudo /opt/grund-lab/scenario.sh docker'
lab ssh "$name" 'sudo /opt/grund-lab/scenario.sh run'
lab ssh "$name" 'sudo /opt/grund-lab/scenario.sh private'
