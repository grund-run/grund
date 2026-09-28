#!/bin/sh
# Install grund agent on a Linux device and add it to an organisation's pool.
#
#   curl -fsSL https://git.kjuulh.io/grund/grund/raw/branch/main/crates/grund-agent/install.sh |
#     sudo sh -s -- --url https://dev.app.grund.sh --code grund_join_...
#
# or, from an instance that serves its own installer (GRUND_SERVE_INSTALLER,
# on in compose.yaml):
#
#   curl -fsSL https://grund.example.com/install |
#     sudo sh -s -- --url https://grund.example.com --code grund_join_... --from-instance
#
#   --url URL        the grund instance (required)
#   --code CODE      the one-time setup code from its Machines page (required
#                    unless this device is already registered)
#   --name NAME      the name to ask for (default: the hostname)
#   --no-vms         install only the agent, never Firecracker
#   --from-instance  take grund from the instance itself, not from grund's
#                    package registry
#
# What it does, as root, each step checked:
#   1. grund: the build the instance itself runs, checked against a SHA-256,
#      to /usr/local/bin/grund. By default from grund's package registry, by
#      the full 40-character commit the instance's /health/ready names, so
#      the instance chooses only among builds grund's CI published; a build
#      from source names none and is refused. With --from-instance, the
#      instance's own executable, from <url>/install/grund-linux-<arch>:
#      any build works, and the bytes are as trustworthy as the instance's
#      TLS (nothing is signed yet)
#   2. with /dev/kvm: Firecracker and its jailer (a pinned release, checked
#      against a pinned SHA-256) to /usr/local/bin, and nftables from the
#      system's package manager if nft is missing
#   3. `grund join`, unless /var/lib/grund/agent/machine.json exists
#   4. grund-agent.service, enabled and started: `grund agent`, with
#      Firecracker VMs where step 2 ran. KillMode=process, so restarting
#      the agent leaves its VMs running; with systemd 254+, Delegate=yes
#      and DelegateSubgroup=agent, so each VM gets a cgroup with CPU and
#      memory limits and the agent still restarts (cgroup v2 lets no process
#      sit beside child cgroups that have controllers, so systemd must start
#      the agent in its own leaf).
#
# What it changes beyond those files: VMs get grund's bridge grundbr0, its
# nftables table `inet grund` and IPv4 forwarding when the agent first runs
# (grund-docs design/vm-runtime.md). Docker's FORWARD policy drops VM
# traffic; the device then shows no egress and gets no VMs.
set -eu

FIRECRACKER_VERSION=v1.17.0
FIRECRACKER_TGZ_SHA256=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558
PACKAGES=https://git.kjuulh.io/api/packages/grund/generic/grund

url="" code="" name="" vms=1 from_instance=
while [ $# -gt 0 ]; do
  case "$1" in
    --url) url="$2"; shift 2 ;;
    --code) code="$2"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    --no-vms) vms=""; shift ;;
    --from-instance) from_instance=1; shift ;;
    *) echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

fail() { echo "install.sh: $*" >&2; exit 1; }
step() { echo "==> $*"; }
[ -n "$url" ] || fail "give the instance: --url https://grund.example.com"
[ "$(id -u)" = 0 ] || fail "run as root (sudo sh -s -- ...): it installs to /usr/local/bin and a systemd unit"
[ "$(uname -s)" = Linux ] || fail "grund agent runs on Linux; this is $(uname -s)"
[ "$(uname -m)" = x86_64 ] || fail "grund publishes x86_64 builds only so far; this is $(uname -m)"
command -v systemctl >/dev/null || fail "this installer needs systemd to run the agent"
command -v curl >/dev/null || fail "curl is required"
command -v sha256sum >/dev/null || fail "sha256sum is required (coreutils)"
url="${url%/}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

verify() { # file sha256
  echo "$2  $1" | sha256sum -c --quiet >/dev/null 2>&1 || fail "$(basename "$1") does not match its SHA-256; nothing was installed from it"
}

step "grund, the build $url runs"
ready="$(curl -fsS "$url/health/ready")" ||
  fail "$url/health/ready did not answer 200; is the instance up and ready, and is this its address?"
revision="$(echo "$ready" | sed -n 's/.*"revision":"\([^"]*\)".*/\1/p')"
[ -n "$revision" ] || fail "$url/health/ready names no revision; is it a grund instance?"
if [ -n "$from_instance" ]; then
  base="$url/install"
  file="grund-linux-$(uname -m)"
  curl -fsSL -o "$work/grund" "$base/$file" ||
    fail "$url serves no $file: it does not serve its installer (GRUND_SERVE_INSTALLER), or runs grund for another architecture"
  sum="$(curl -fsSL "$base/$file.sha256")" || fail "$url serves no SHA-256 for $file"
else
  echo "$revision" | grep -qx '[0-9a-f]\{40\}' ||
    fail "$url runs a grund build that was not published (revision \"$revision\"; a build from source, such as compose from a clone, has none). Install from the instance itself: its Machines page offers the command when it serves its installer (GRUND_SERVE_INSTALLER=true, compose.yaml's default), or add --from-instance to this one. Or run a published image, git.kjuulh.io/grund/grund:main-<the full 40-character commit>"
  base="$PACKAGES/main-$revision"
  curl -fsSL -o "$work/grund" "$base/grund" || fail "no published grund for revision $revision ($base/grund)"
  sum="$(curl -fsSL "$base/grund.sha256")" || fail "no published SHA-256 for grund $revision"
fi
echo "$sum" | grep -qx '[0-9a-f]\{64\}' || fail "the SHA-256 from $base is not 64 hex characters"
verify "$work/grund" "$sum"
install -m 0755 "$work/grund" /usr/local/bin/grund
echo "    grund $revision from $base, sha256 $(echo "$sum" | cut -c1-12)"

runtime=none
if [ -n "$vms" ] && [ -c /dev/kvm ]; then
  step "Firecracker $FIRECRACKER_VERSION and its jailer (this device has /dev/kvm)"
  tgz="$work/firecracker.tgz"
  curl -fsSL -o "$tgz" "https://github.com/firecracker-microvm/firecracker/releases/download/$FIRECRACKER_VERSION/firecracker-$FIRECRACKER_VERSION-x86_64.tgz"
  verify "$tgz" "$FIRECRACKER_TGZ_SHA256"
  tar -xzf "$tgz" -C "$work"
  release="$work/release-$FIRECRACKER_VERSION-x86_64"
  install -m 0755 "$release/firecracker-$FIRECRACKER_VERSION-x86_64" /usr/local/bin/firecracker
  install -m 0755 "$release/jailer-$FIRECRACKER_VERSION-x86_64" /usr/local/bin/jailer
  if ! command -v nft >/dev/null && [ ! -x /usr/sbin/nft ]; then
    step "nftables, for the VMs' bridge"
    if command -v apt-get >/dev/null; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q nftables >/dev/null || { apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q nftables >/dev/null; }
    elif command -v dnf >/dev/null; then
      dnf install -y -q nftables
    elif command -v pacman >/dev/null; then
      pacman -S --noconfirm --needed nftables >/dev/null
    else
      fail "install nftables (nft) for VMs, or rerun with --no-vms"
    fi
  fi
  runtime=firecracker
elif [ -n "$vms" ]; then
  echo "    no /dev/kvm: the agent runs without VMs"
fi

if [ -f /var/lib/grund/agent/machine.json ]; then
  step "already registered; keeping this device's identity"
else
  [ -n "$code" ] || fail "give the setup code from $url's Machines page: --code grund_join_..."
  step "registering with $url"
  /usr/local/bin/grund join --url "$url" --name "${name:-$(uname -n)}" "$code"
fi

step "grund-agent.service"
delegate=""
systemd_version="$(systemctl --version | sed -n '1s/^systemd \([0-9]*\).*/\1/p')"
if [ "${systemd_version:-0}" -ge 254 ]; then
  delegate="Delegate=yes
DelegateSubgroup=agent"
else
  echo "    systemd ${systemd_version:-?} has no DelegateSubgroup (254+): VMs run without cgroup limits"
fi
cat > /etc/systemd/system/grund-agent.service <<UNIT
[Unit]
Description=grund agent: keeps this machine connected to its grund instance
Documentation=https://git.kjuulh.io/grund/grund
After=network-online.target
Wants=network-online.target
ConditionPathExists=/var/lib/grund/agent/machine.json

[Service]
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/local/bin/grund agent --vm-runtime $runtime --vm-firecracker /usr/local/bin/firecracker --vm-jailer /usr/local/bin/jailer
Restart=always
RestartSec=5
KillMode=process
$delegate

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable grund-agent.service >/dev/null 2>&1
systemctl restart grund-agent.service
sleep 3
systemctl is-active --quiet grund-agent.service || { journalctl -u grund-agent --no-pager -n 20; fail "grund-agent.service did not stay up"; }
echo "    running; logs: journalctl -u grund-agent -f"
echo "done: this device shows as connected on $url's Machines page"
