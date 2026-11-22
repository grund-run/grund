set -eu
: "${NATS_AUTH_TOKEN:?NATS_AUTH_TOKEN must be set}"
case "$NATS_AUTH_TOKEN" in *[!a-zA-Z0-9_-]*) echo 'NATS_AUTH_TOKEN must be URL-safe' >&2; exit 1;; esac
: "${NATS_MAX_MEM:?NATS_MAX_MEM must be set}"
: "${NATS_MAX_FILE:?NATS_MAX_FILE must be set}"
for bound in "$NATS_MAX_MEM" "$NATS_MAX_FILE"; do
    case "$bound" in ''|*[!0-9]*) echo 'JetStream store bounds must be positive bytes' >&2; exit 1;; esac
    [ "$bound" -gt 0 ] || exit 1
done
awk '$5 == "/data" { found=1 } END { exit !found }' /proc/self/mountinfo || {
    echo 'JetStream requires its owned /data volume' >&2
    exit 1
}
probe=$(mktemp /data/.grund-write-XXXXXX) || exit 1
rm "$probe"
umask 077
cat > /tmp/grund-nats.conf <<EOF
port: 4222
http: 8222
authorization { token: "$NATS_AUTH_TOKEN" }
jetstream {
    max_mem: $NATS_MAX_MEM
    max_file: $NATS_MAX_FILE
}
EOF
exec nats-server -c /tmp/grund-nats.conf -js -sd /data
