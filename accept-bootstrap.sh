#!/bin/sh
# Claim the operator before acceptance tests admit public sign-ups. Keep the
# one-time link and its form token in process memory, never in CI output.
set +x
set -eu

[ "$#" -gt 0 ] || { echo "missing grund command" >&2; exit 1; }
: "${GRUND_ACCEPT_URL:?set GRUND_ACCEPT_URL to the public origin}"
attempt=0
until curl -fsS -o /dev/null "$GRUND_ACCEPT_URL/health/live" 2>/dev/null; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 60 ] || { echo "grund did not become live" >&2; exit 1; }
    sleep 1
done
output=$("$@" setup-link) || { echo "setup-link failed" >&2; exit 1; }
link=
for field in $output; do
    case "$field" in
        http://*/signup/owner\?token=*|https://*/signup/owner\?token=*) link=$field ;;
    esac
done
[ -n "$link" ] || { echo "setup-link returned no owner URL" >&2; exit 1; }
origin=${link%%/signup/owner*}
token=${link##*token=}
cookies=$(mktemp)
trap 'rm -f "$cookies"' EXIT HUP INT TERM
html=$(printf 'url = "%s"\n' "$link" | curl -fsS -c "$cookies" --config -) || {
    echo "owner form unavailable" >&2; exit 1;
}
case "$html" in
    *'name="csrf" value="'*) csrf=${html#*'name="csrf" value="'}; csrf=${csrf%%\"*} ;;
    *) echo "owner form has no CSRF token" >&2; exit 1 ;;
esac
username=operator-$(openssl rand -hex 5)
password=accept-bootstrap-$(openssl rand -hex 16)
status=$(printf 'csrf=%s&token=%s&username=%s&email=%s%%40accept.test&password=%s' \
    "$csrf" "$token" "$username" "$username" "$password" |
    curl -sS -o /dev/null -w '%{http_code}' -b "$cookies" -c "$cookies" \
        --data-binary @- "$origin/signup/owner") || {
    echo "owner creation request failed" >&2; exit 1;
}
[ "$status" = 303 ] || { echo "owner creation refused (HTTP $status)" >&2; exit 1; }
echo "operator owner claimed for acceptance tests"
