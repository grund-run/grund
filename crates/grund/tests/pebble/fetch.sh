#!/bin/sh
# Fetches Pebble, Let's Encrypt's ACME test server, and pebble-challtestsrv
# (its DNS stand-in) for the certificate accepttests
# (tests/accepttest/certificates.rs), into target/pebble unless a directory
# is given. The tests spawn both per test; they never reach a real CA.
#
#   crates/grund/tests/pebble/fetch.sh [dir]
#
# Pinned by version and by the SHA-256 of each release archive. Pebble
# publishes no checksum file, so the digests are the archives' as downloaded
# on 2026-09-28; a different archive under the same name is refused.
set -eu
version=v2.10.1
dir=${1:-$(cd "$(dirname "$0")/../../../.." && pwd)/target/pebble}
mkdir -p "$dir"
fetch() {
  name=$1 sha=$2
  if [ -x "$dir/$name" ] && [ "$(cat "$dir/$name.version" 2>/dev/null)" = "$version" ]; then
    return 0
  fi
  url="https://github.com/letsencrypt/pebble/releases/download/$version/$name-linux-amd64.tar.gz"
  archive="$dir/$name.tar.gz"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$archive" "$url"
  else
    wget -q -O "$archive" "$url"
  fi
  echo "$sha  $archive" | sha256sum -c - >/dev/null || {
    echo "fetch.sh: $name $version does not match its pinned SHA-256" >&2
    rm -f "$archive"
    exit 1
  }
  tar -xzf "$archive" -C "$dir"
  mv "$dir/$name-linux-amd64/linux/amd64/$name" "$dir/$name"
  chmod 0755 "$dir/$name"
  rm -rf "$dir/$name-linux-amd64" "$archive"
  echo "$version" >"$dir/$name.version"
}
fetch pebble 4f2fcb5bca8c85c9cf73ad140fccfc0d2be40bd81ab99879c79b7b8a0b4f70ed
fetch pebble-challtestsrv e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92
echo "pebble $version in $dir"
