#!/bin/sh
# Fetches Pebble from a pinned upstream source commit and pebble-challtestsrv
# from the pinned release. The former is built locally with Go for the ACME
# accepttests, into target/pebble unless a directory is given.
#
#   crates/grund/tests/pebble/fetch.sh [dir]
#
# Pebble v2.10.1 intermittently refuses ARI replaces when a certificate's
# serial has DER sign padding (https://github.com/letsencrypt/pebble/issues/550).
# The source revision contains upstream's fix. Remove the pin when Pebble
# releases past v2.10.1, and use release archives for both binaries again.
set -eu
version=v2.10.1
revision=1fcb30cabf594e047cb92432b9392bc3dfa469f7
source_sha=d80d1c4cfe9697ba4072e24a5cfb13fa1dc17e7f6d5a0e72a3546b712fb03e42
dir=${1:-$(cd "$(dirname "$0")/../../../.." && pwd)/target/pebble}
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
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
if [ ! -x "$dir/pebble" ] || [ "$(cat "$dir/pebble.version" 2>/dev/null)" != "$revision" ]; then
  archive="$dir/pebble-$revision.tar.gz"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$archive" "https://github.com/letsencrypt/pebble/archive/$revision.tar.gz"
  else
    wget -q -O "$archive" "https://github.com/letsencrypt/pebble/archive/$revision.tar.gz"
  fi
  echo "$source_sha  $archive" | sha256sum -c - >/dev/null || {
    echo "fetch.sh: pebble $revision source does not match its pinned SHA-256" >&2
    rm -f "$archive"
    exit 1
  }
  tar -xzf "$archive" -C "$dir"
  (cd "$dir/pebble-$revision" && GOTOOLCHAIN=local go build -trimpath -o "$dir/pebble" ./cmd/pebble)
  rm -rf "$dir/pebble-$revision" "$archive"
  echo "$revision" >"$dir/pebble.version"
fi
fetch pebble-challtestsrv e93a5aa25ecdf3af2f9fbb2de32b0173e64a2eae81002a4ccfe35fa6f4f60b92
echo "pebble $revision in $dir"
