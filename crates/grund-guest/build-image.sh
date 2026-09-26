#!/usr/bin/env bash
# Build the root filesystem of a grund microVM: an ext4 image holding only
# grund-guest as /sbin/init and a static grund at /usr/local/bin/grund. No
# distribution, no shell, no certificate store: grund join trusts Mozilla's
# roots compiled into it when the machine has none.
#
#   crates/grund-guest/build-image.sh <out.ext4>
#   GRUND_BINARY=… GRUND_GUEST_BINARY=… crates/grund-guest/build-image.sh <out.ext4>
#
# With both binaries given (CI's release step built them), nothing is
# compiled. The image is small (GRUND_GUEST_SIZE_MIB, default 48): the VM's
# disk is this image grown to its size, and grund-guest grows / to fill it
# at boot. mkfs's default reserve (256 GDT blocks, 64-bit descriptors) lets
# it grow online to 2 TiB; a larger disk keeps a 2 TiB filesystem.
#
# Built without root: `mkfs.ext4 -d` fills the filesystem from a staging
# directory, then debugfs sets every inode to uid/gid 0 and one timestamp,
# so the image does not depend on who built it or when. The same toolchain
# (rust-toolchain.toml), checkout path and SOURCE_DATE_EPOCH give the same
# bytes; a different e2fsprogs may not.
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
image="${1:?usage: build-image.sh <out.ext4>}"
size_mib="${GRUND_GUEST_SIZE_MIB:-48}"
uuid=4b8f2a61-9c3e-4d7a-b5e0-2f6c8d1a3e97
target=x86_64-unknown-linux-musl
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$repo" log -1 --format=%ct 2>/dev/null || echo 0)}"

fail() { echo "build-image: $*" >&2; exit 1; }
for tool in mkfs.ext4 debugfs e2fsck readelf; do
  command -v "$tool" >/dev/null || fail "$tool is required (e2fsprogs, binutils)"
done

grund="${GRUND_BINARY:-}"
guest="${GRUND_GUEST_BINARY:-}"
if [[ -z "$grund" || -z "$guest" ]]; then
  (cd "$repo" && cargo build --locked --release --target "$target" -q -p grund-guest -p grund)
  grund="$repo/target/$target/release/grund"
  guest="$repo/target/$target/release/grund-guest"
fi
for binary in "$guest" "$grund"; do
  [[ -f "$binary" ]] || fail "no binary at $binary"
  if readelf -d "$binary" | grep -q NEEDED; then
    fail "$binary is dynamically linked; the guest has no libc to load"
  fi
done

stage="$(mktemp -d "${TMPDIR:-/tmp}/grund-guest-stage.XXXXXX")"
trap 'rm -rf "$stage" "$stage.debugfs" "$stage.err"' EXIT
mkdir -p "$stage"/{sbin,usr/local/bin,dev,proc,sys,run,tmp,etc,var/lib/grund}
install -m 0755 "$guest" "$stage/sbin/init"
install -m 0755 "$grund" "$stage/usr/local/bin/grund"
printf 'NAME="grund"\nID=grund\nPRETTY_NAME="grund microVM"\n' > "$stage/etc/os-release"
chmod 0644 "$stage/etc/os-release"
chmod 1777 "$stage/tmp"
find "$stage" -exec touch -h -d "@$epoch" {} +

rm -f "$image.part"
truncate -s "${size_mib}M" "$image.part"
E2FSPROGS_FAKE_TIME="$epoch" mkfs.ext4 -q -F -L grund-root -U "$uuid" \
  -E "hash_seed=$uuid,root_owner=0:0" -d "$stage" "$image.part" >/dev/null
{
  (cd "$stage" && find . -mindepth 1 | sed 's|^\.||'; echo /lost+found; echo /) | sort -u | while read -r path; do
    for field in uid gid; do echo "set_inode_field $path $field 0"; done
    for field in atime mtime ctime crtime; do echo "set_inode_field $path $field @$epoch"; done
  done
} > "$stage.debugfs"
E2FSPROGS_FAKE_TIME="$epoch" debugfs -w -f "$stage.debugfs" "$image.part" >/dev/null 2>"$stage.err" \
  || { cat "$stage.err" >&2; fail "debugfs could not normalise the image"; }
if grep -v '^debugfs' "$stage.err" | grep -q .; then
  cat "$stage.err" >&2
  fail "debugfs reported errors while normalising the image"
fi
e2fsck -fn "$image.part" >/dev/null 2>&1 || fail "the image does not pass e2fsck"
mv "$image.part" "$image"
echo "$image sha256 $(sha256sum "$image" | cut -d' ' -f1)"
