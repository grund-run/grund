#!/usr/bin/env bash
# mesh.sh: grund-net's base layers end to end, in network namespaces.
#
#   crates/grund-net/lab/mesh.sh [path/to/grund-net-lab]
#
# No root and no host changes: it re-executes itself inside an unprivileged
# user, network and mount namespace (unshare -Urnm), and every namespace
# below is a child of that one, joined by veth pairs. Everything dies with it.
#
# The topology, as in grund/fleet network-verification.md:
#
#   node a (10.1.0.2) - NAT ra (198.51.100.11) -+
#                                               +- "internet" - lighthouse (198.51.100.1)
#   node b (10.2.0.2) - NAT rb (198.51.100.12) -+               relay on 443 (TLS),
#                                                               address discovery on 7842
#
# The NATs are home-router shaped: port-preserving masquerade, and
# unsolicited input on the WAN side dropped.
#
# Checks, each printed as "ok" or "FAIL", exit status 1 on any failure:
#   1. both nodes come up with their addresses from the signed list;
#   2. a reaches b's grund0 address, and the path turns direct (punched);
#   3. with direct UDP between the NATs dropped, traffic continues over the
#      relay; after it is restored, the path is direct again;
#   4. a member that sends a packet with another member's source is dropped
#      by the receiver's filter, and a correct packet from it is delivered;
#   5. a key that is not on the list is refused;
#   6. a new list without b cuts a off from b.
set -euo pipefail

if [ -z "${GRUND_NET_LAB_INSIDE:-}" ]; then
  here=$(cd "$(dirname "$0")" && pwd)
  bin=${1:-$here/../../../target/debug/grund-net-lab}
  [ -x "$bin" ] || { echo "build it first: cargo build -p grund-net --bins ($bin)" >&2; exit 2; }
  GRUND_NET_LAB_INSIDE=1 BIN=$(realpath "$bin") exec unshare -Urnm --fork bash "$0"
fi

: "${BIN:?}"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/grund-net-lab.XXXXXX")

declare -A NS=()
PIDS=()
FAILED=0
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  for p in "${NS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [ "$FAILED" = 0 ] && rm -rf "$WORK" || echo "logs kept in $WORK" >&2
}
trap cleanup EXIT

mkns() {
  unshare -n sleep infinity &
  NS[$1]=$!
  sleep 0.05
  nsx "$1" ip link set lo up
}
nsx() { local ns=$1; shift; nsenter -t "${NS[$ns]}" -n -- "$@"; }
bg() { local ns=$1; shift; nsenter -t "${NS[$ns]}" -n -- "$@" & PIDS+=($!); LAST=$!; }
link() {
  ip link add "$2" netns "${NS[$1]}" type veth peer name "$5" netns "${NS[$4]}"
  nsx "$1" ip addr add "$3" dev "$2"
  nsx "$4" ip addr add "$6" dev "$5"
  nsx "$1" ip link set "$2" up
  nsx "$4" ip link set "$5" up
}
plug() {
  ip link add wan netns "${NS[$1]}" type veth peer name "p-$1" netns "${NS[net]}"
  nsx "$1" ip addr add "$2" dev wan
  nsx "$1" ip link set wan up
  nsx net ip link set "p-$1" master br0 up
}
nat_router() {
  nsx "$1" sysctl -qw net.ipv4.ip_forward=1
  nsx "$1" nft -f - <<'EOF'
table ip nat {
  chain post { type nat hook postrouting priority 100; policy accept; oifname "wan" masquerade; }
}
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "wan" ct state established,related accept
    iifname "wan" drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    iifname "lan" oifname "wan" accept
    iifname "wan" ct state established,related accept
  }
}
EOF
}
check() {
  if eval "$2"; then echo "ok    $1"; else echo "FAIL  $1"; FAILED=1; fi
}
field() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2], {}, {"d": d}))' "$@" 2>/dev/null || true; }
wait_for() {
  local secs=$1 cond=$2
  for _ in $(seq 1 $((secs * 4))); do eval "$cond" && return 0; sleep 0.25; done
  return 1
}
path_to() { field "$WORK/status-$1.json" "[p['path'] for p in d['peers'] if p['endpoint_id']=='$2'][0]"; }
counter() { field "$WORK/status-$1.json" "d['counters']['$2']"; }
key() { "$BIN" keygen; }
jget() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$1" "$2"; }

mkns net
nsx net ip link add br0 type bridge
nsx net ip link set br0 up
mkns lh
plug lh 198.51.100.1/24
for side in a:1:11 b:2:12; do
  IFS=: read -r n i pub <<<"$side"
  mkns "r$n"
  mkns "$n"
  plug "r$n" "198.51.100.$pub/24"
  link "r$n" lan "10.$i.0.1/24" "$n" eth0 "10.$i.0.2/24"
  nsx "$n" ip route add default via "10.$i.0.1"
  nat_router "r$n"
done
mkns c
plug c 198.51.100.40/24

# A lab CA and the relay's certificate from it. The nodes trust the CA; a
# self-signed server certificate is refused (webpki: CaUsedAsEndEntity).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -keyout "$WORK/ca.key" -out "$WORK/ca.crt" -subj /CN=grund-net-lab-ca 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$WORK/relay.key" -out "$WORK/relay.csr" -subj /CN=grund-net-lab-relay 2>/dev/null
openssl x509 -req -in "$WORK/relay.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial -days 1 \
  -extfile <(printf 'subjectAltName=IP:198.51.100.1\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n') \
  -out "$WORK/relay.crt" 2>/dev/null
NETKEY=$(key)
A=$(key) B=$(key) C=$(key) D=$(key)
for n in A B C D; do eval "${n}_ID=\$(jget \"\$$n\" endpoint_id) ${n}_SEED=\$(jget \"\$$n\" seed)"; done
PREFIX=fd12:3456:789a
list() {
  local epoch=$1; shift
  python3 - "$epoch" "$@" >"$WORK/list.json" <<'PY'
import json, sys
epoch, members = int(sys.argv[1]), sys.argv[2:]
print(json.dumps({"network_id": "net_lab", "epoch": epoch, "prefix": "fd12:3456:789a::",
  "issued_at": 1790000000,
  "members": [{"machine_id": f"m_{i}", "endpoint_id": m.split(":")[0], "slot": int(m.split(":")[1])}
              for i, m in enumerate(members)]}))
PY
  "$BIN" sign --network-key "$(jget "$NETKEY" seed)" --list "$WORK/list.json" >"$WORK/signed.json.tmp"
  mv "$WORK/signed.json.tmp" "$WORK/signed.json"
}
list 1 "$A_ID:1" "$B_ID:2" "$D_ID:4"

RELAY=https://198.51.100.1/
bg lh "$BIN" lighthouse --https 198.51.100.1:443 --qad 198.51.100.1:7842 \
  --cert "$WORK/relay.crt" --key "$WORK/relay.key" \
  --allow "$A_ID" --allow "$B_ID" --allow "$C_ID" --allow "$D_ID" 2>"$WORK/lighthouse.log"
sleep 1
for n in a b; do
  seed=$([ $n = a ] && echo "$A_SEED" || echo "$B_SEED")
  bg "$n" env RUST_LOG="${LAB_LOG:-grund_net=info}" "$BIN" node --key "$seed" --relay "$RELAY" \
    --relay-root "$WORK/ca.crt" --network-pub "$(jget "$NETKEY" public)" \
    --list "$WORK/signed.json" --status "$WORK/status-$n.json" 2>"$WORK/node-$n.log"
  eval "PID_$n=\$LAST"
done

B_ADDR=$PREFIX:2::1
addr_of() { field "$WORK/status-$1.json" "d['address']"; }
epoch_of() { field "$WORK/status-$1.json" "d['epoch']"; }
both_up() { [ "$(addr_of a)" = "$PREFIX:1::1" ] && [ "$(addr_of b)" = "$B_ADDR" ]; }
direct() { nsx a ping -6 -c 1 -W 1 "$B_ADDR" >/dev/null 2>&1; path_to a "$B_ID" | grep -q ^direct; }
relayed() { path_to a "$B_ID" | grep -q ^relay; }
grew() { [ "$(counter "$1" "$2")" -gt "$3" ]; }
check "1. both nodes are up with their addresses from the list" 'wait_for 15 both_up'

nsx a ping -6 -c 3 -W 1 "$B_ADDR" >/dev/null 2>&1 || true
check "2a. a reaches b's grund0 address" 'nsx a ping -6 -c 10 -i 0.2 -W 1 "$B_ADDR" >"$WORK/ping2.txt" 2>&1'
check "2b. the path from a to b turns direct (hole punched through both NATs)" \
  'wait_for 20 direct'
echo "      path: $(path_to a "$B_ID")"

nsx net nft -f - <<'EOF'
table bridge cut {
  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr 198.51.100.11 ip daddr 198.51.100.12 udp dport != 443 drop
    ip saddr 198.51.100.12 ip daddr 198.51.100.11 udp dport != 443 drop
  }
}
EOF
bg a sh -c 'exec ping -6 -i 0.2 -W 1 "$0" >/dev/null 2>&1' "$B_ADDR"
PING_BG=$LAST
check "3a. with direct UDP dropped, traffic moves to the relay" \
  'wait_for 20 relayed'
sleep 2
check "3b. and flows over it" 'nsx a ping -6 -c 5 -i 0.2 -W 2 "$B_ADDR" >/dev/null 2>&1'
nsx net nft delete table bridge cut
check "3c. after direct UDP is restored, the path is direct again" \
  'wait_for 90 direct'
kill "$PING_BG" 2>/dev/null || true
echo "      path: $(path_to a "$B_ID")"

spoofed0=$(counter b dropped_spoofed_in)
received0=$(counter b received)
nsx c "$BIN" inject --key "$D_SEED" --relay "$RELAY" --relay-root "$WORK/ca.crt" --to "$B_ID" \
  --src "$PREFIX:1::1" --dst "$B_ADDR" >"$WORK/inject-spoof.json" 2>"$WORK/inject-spoof.log" || true
check "4a. a member sending with another member's source is dropped by the receiver" \
  'wait_for 5 "grew b dropped_spoofed_in $spoofed0"'
nsx c "$BIN" inject --key "$D_SEED" --relay "$RELAY" --relay-root "$WORK/ca.crt" --to "$B_ID" \
  --src "$PREFIX:4::1" --dst "$B_ADDR" >"$WORK/inject-ok.json" 2>"$WORK/inject-ok.log" || true
check "4b. the same member with its own source is delivered" \
  'wait_for 5 "grew b received $received0"'

refused0=$(counter b refused_non_members)
nsx c "$BIN" inject --key "$C_SEED" --relay "$RELAY" --relay-root "$WORK/ca.crt" --to "$B_ID" \
  --src "$PREFIX:3::1" --dst "$B_ADDR" >"$WORK/inject-nonmember.json" 2>"$WORK/inject-nonmember.log" || true
check "5. a key that is not on the list is refused" \
  'wait_for 5 "grew b refused_non_members $refused0"'

list 2 "$A_ID:1" "$D_ID:4"
kill -HUP "$PID_a" "$PID_b"
check "6a. the new list (epoch 2) is in force on a" 'wait_for 5 "[ \"\$(epoch_of a)\" = 2 ]"'
check "6b. a can no longer reach b" '! nsx a ping -6 -c 3 -i 0.2 -W 1 "$B_ADDR" >/dev/null 2>&1'

echo
[ "$FAILED" = 0 ] && echo "all checks passed" || { echo "some checks failed"; exit 1; }
