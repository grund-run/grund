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
#   --binary FILE    use an already SHA-256-verified local grund release
#   --prepare-only   install prerequisites and the unit without joining;
#                    an existing registered machine is still restarted
#
# What it does, as root, each step checked:
#   1. grund: the build this instance selects for a device, checked against a
#      SHA-256 and installed to /usr/local/lib/grund/agent/grund. The CLI
#      in /usr/local/bin/grund is never replaced. By default the full
#      40-character public commit from /health/ready names a build in grund's
#      package registry. For <server>+<public>, the second commit selects that
#      public build. A build from source names none and is refused. With
#      --from-instance, the instance's own executable is fetched from
#      <url>/install/grund-linux-<arch>: any build works, and the bytes are as
#      trustworthy as the instance's TLS (nothing is signed yet)
#   2. restic: pinned upstream encrypted backup executable, checked against
#      its release SHA-256 before installation to /usr/local/bin, and bzip2
#      from the system's package manager if it is missing, to unpack it
#   3. with /dev/kvm: Firecracker and its jailer (a pinned release, checked
#      against a pinned SHA-256) to /usr/local/bin, and nftables from the
#      system's package manager if nft is missing
#   4. `grund join`, unless /var/lib/grund/agent/machine.json exists
#   5. grund-agent.service, enabled and started: `grund agent`, with
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
umask 077

FIRECRACKER_VERSION=v1.17.0
FIRECRACKER_TGZ_SHA256=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558
RESTIC_VERSION=0.18.1
# https://github.com/restic/restic/releases/download/v0.18.1/SHA256SUMS
RESTIC_BZ2_SHA256=680838f19d67151adba227e1570cdd8af12c19cf1735783ed1ba928bc41f363d
PACKAGES=https://git.kjuulh.io/api/packages/grund/generic/grund

url="" code="" name="" vms=1 from_instance= binary= prepare_only=
while [ $# -gt 0 ]; do
  case "$1" in
    --url) url="$2"; shift 2 ;;
    --code) code="$2"; shift 2 ;;
    --name) name="$2"; shift 2 ;;
    --no-vms) vms=""; shift ;;
    --from-instance) from_instance=1; shift ;;
    --binary) [ $# -ge 2 ] || { echo "--binary needs a file" >&2; exit 2; }; binary="$2"; shift 2 ;;
    --prepare-only) prepare_only=1; shift ;;
    *) echo "install.sh: unknown argument: $1" >&2; exit 2 ;;
  esac
done

fail() { echo "install.sh: $*" >&2; exit 1; }
step() { echo "==> $*"; }
pkg() { # package, what to do without a known package manager
  if command -v apt-get >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$1" >/dev/null 2>&1 || { apt-get update -q >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$1" >/dev/null; }
  elif command -v dnf >/dev/null; then
    dnf install -y -q "$1"
  elif command -v pacman >/dev/null; then
    pacman -S --noconfirm --needed "$1" >/dev/null
  else
    fail "$2"
  fi
}
[ -n "$url" ] || fail "give the instance: --url https://grund.example.com"
[ "$(id -u)" = 0 ] || fail "run as root (sudo sh -s -- ...): it installs to /usr/local/bin and a systemd unit"
[ "$(uname -s)" = Linux ] || fail "grund agent runs on Linux; this is $(uname -s)"
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64)
    arch=arm64
    RESTIC_BZ2_SHA256=87f53fddde38764095e9c058a3b31834052c37e5826d2acf34e18923c006bd45
    [ -z "$vms" ] || echo "    arm64: container apps supported; this installer does not install Firecracker"
    vms=""
    ;;
  *) fail "grund publishes Linux amd64 and arm64 builds; this is $(uname -m)" ;;
esac
command -v systemctl >/dev/null || fail "this installer needs systemd to run the agent"
command -v curl >/dev/null || fail "curl is required"
command -v sha256sum >/dev/null || fail "sha256sum is required (coreutils)"
command -v flock >/dev/null || fail "flock is required (util-linux)"
command -v sync >/dev/null || fail "sync is required (coreutils)"
[ ! -L /etc/systemd/system/grund-agent.service ] || fail "the agent unit must not be a symbolic link"
previous_arguments="" legacy_unit=""
if [ -f /etc/systemd/system/grund-agent.service ]; then
  previous_exec="$(sed -n 's/^ExecStart=//p' /etc/systemd/system/grund-agent.service)"
  case "$previous_exec" in
    "/usr/local/bin/grund agent "*)
      previous_arguments="${previous_exec#'/usr/local/bin/grund agent '}"; legacy_unit=1 ;;
    "/usr/local/lib/grund/agent/grund agent "*)
      previous_arguments="${previous_exec#'/usr/local/lib/grund/agent/grund agent '}" ;;
    *) fail "existing grund-agent.service has an unmanaged ExecStart; preserve it manually before installing" ;;
  esac
  environment_files="$(systemctl show -p EnvironmentFiles --value grund-agent.service)" ||
    fail "cannot inspect the existing agent environment; nothing was changed"
  if [ -n "$environment_files" ] ||
    grep -Eq '^[[:space:]]*EnvironmentFile[[:space:]]*=' /etc/systemd/system/grund-agent.service; then
    fail "the existing agent uses EnvironmentFile; this installer cannot safely resolve that identity, so nothing was changed"
  fi
  case "$previous_arguments" in
    *--data-dir*) fail "this installer cannot migrate a custom agent data directory; nothing was changed" ;;
  esac
  environment_data="$(systemctl show -p Environment --value grund-agent.service | tr ' ' '\n' | sed -n 's/^GRUND_AGENT_DATA_DIR=//p')"
  if [ -n "$environment_data" ] && [ "$environment_data" != /var/lib/grund/agent ]; then
    fail "this installer cannot migrate a custom agent data directory; nothing was changed"
  fi
fi
for directory in /var/lib/grund /usr/local/lib/grund /usr/local/lib/grund/agent; do
  [ ! -L "$directory" ] || fail "$directory must not be a symbolic link"
  if [ -e "$directory" ]; then
    [ -d "$directory" ] && [ "$(stat -c %u "$directory")" = 0 ] ||
      fail "$directory must be a root-owned directory"
    [ -z "$(find "$directory" -maxdepth 0 -perm /022 -print)" ] ||
      fail "$directory must not be group- or world-writable"
  else
    install -d -m 0700 "$directory"
  fi
done
[ ! -L /var/lib/grund/.update.lock ] || fail "the update lock must not be a symbolic link"
exec 9>/var/lib/grund/.update.lock
flock -n 9 || fail "another agent installation or update is running"
runtime_binary=/usr/local/lib/grund/agent/grund
[ ! -L "$runtime_binary" ] || fail "the runtime must not be a symbolic link"
[ ! -e /var/lib/grund/agent/update-journal.json ] ||
  fail "an agent update is unresolved; let its supervisor finish before installing"
url="${url%/}"

work="$(mktemp -d)"
staged="" switched="" unit_written="" old_active="" old_enabled="" unit_staged="" legacy_repair="" snapshot=""
if systemctl is-active --quiet grund-agent.service; then old_active=1; fi
if systemctl is-enabled --quiet grund-agent.service; then old_enabled=1; fi
if [ -f /etc/systemd/system/grund-agent.service ]; then
  cp -p /etc/systemd/system/grund-agent.service "$work/previous.service"
fi
cleanup() {
  result=$?
  trap - EXIT
  if [ "$result" != 0 ] && { [ -n "$switched" ] || [ -n "$legacy_repair" ]; }; then
    echo "install.sh: installation failed; restoring the retained runtime and dedicated unit" >&2
    if [ -n "$unit_written" ] || [ -n "$legacy_repair" ]; then systemctl stop grund-agent.service || true; fi
    if [ -f /usr/local/lib/grund/agent/grund.install-previous ]; then
      mv -f /usr/local/lib/grund/agent/grund.install-previous "$runtime_binary"
      sync /usr/local/lib/grund/agent
    else
      rm -f "$runtime_binary"
    fi
    if [ -n "$unit_written" ] || [ -n "$legacy_repair" ]; then
      if [ -f "$work/previous.service" ]; then
        install -m 0644 "$work/previous.service" /etc/systemd/system/grund-agent.service
      else
        systemctl disable grund-agent.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/grund-agent.service
      fi
      systemctl daemon-reload || true
      if [ -z "$old_enabled" ]; then systemctl disable grund-agent.service >/dev/null 2>&1 || true; fi
    fi
    if [ -n "$old_active" ]; then
      systemctl restart grund-agent.service &&
        systemctl is-active --quiet grund-agent.service ||
        echo "install.sh: previous service could not restart; inspect journalctl -u grund-agent" >&2
    fi
  fi
  [ -z "$staged" ] || rm -f "$staged"
  [ -z "$unit_staged" ] || rm -f "$unit_staged"
  [ -z "$snapshot" ] || rm -f "$snapshot"
  rm -rf "$work"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

retain_running_runtime() {
  pid="$(systemctl show -p MainPID --value grund-agent.service)"
  case "$pid" in
    ""|0|*[!0-9]*) fail "the active agent has no trustworthy systemd MainPID; nothing was replaced" ;;
  esac
  [ "$(stat -c %u "/proc/$pid")" = 0 ] || fail "the agent MainPID is not root-owned"
  expected=/usr/local/lib/grund/agent/grund
  [ -z "$legacy_unit" ] || expected=/usr/local/bin/grund
  executable="$(readlink "/proc/$pid/exe")" || fail "cannot inspect the running agent executable"
  case "$executable" in
    "$expected"|"$expected (deleted)") ;;
    *) fail "the systemd MainPID is not running the validated agent executable" ;;
  esac
  identity="$(stat -Lc '%d:%i:%s' "/proc/$pid/exe")"
  exec 8<"/proc/$pid/exe"
  source="/proc/$$/fd/8"
  snapshot="$(mktemp /usr/local/lib/grund/agent/.known-good.XXXXXX)"
  install -m 0755 "$source" "$snapshot"
  [ -s "$snapshot" ] && cmp -s "$source" "$snapshot" ||
    fail "the complete running executable could not be retained"
  "$snapshot" --version >/dev/null || fail "the retained executable cannot report its version"
  [ "$(systemctl show -p MainPID --value grund-agent.service)" = "$pid" ] &&
    [ "$(stat -Lc '%d:%i:%s' "/proc/$pid/exe")" = "$identity" ] ||
    fail "the running agent changed while retaining it; rerun the installer"
  sync "$snapshot"
  mv -f "$snapshot" /usr/local/lib/grund/agent/grund.install-previous
  snapshot=""
  sync /usr/local/lib/grund/agent
  exec 8<&-
  if [ -n "$legacy_unit" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in
        ExecStart=*) printf 'ExecStart=%s agent %s\n' "$runtime_binary" "$previous_arguments" ;;
        *) printf '%s\n' "$line" ;;
      esac
    done < "$work/previous.service" > "$work/rollback.service"
    mv -f "$work/rollback.service" "$work/previous.service"
    legacy_repair=1
  fi
}
if [ -n "$legacy_unit" ] && [ -z "$old_active" ]; then
  fail "the legacy agent is not running; a trusted running executable is required before separating it from the CLI"
fi
if [ -n "$old_active" ]; then retain_running_runtime; fi

verify() { # file sha256
  echo "$2  $1" | sha256sum -c --quiet >/dev/null 2>&1 || fail "$(basename "$1") does not match its SHA-256; nothing was installed from it"
}
install_runtime() {
  source="$1"
  staged="$(mktemp /usr/local/lib/grund/agent/.grund.XXXXXX)"
  install -m 0755 "$source" "$staged"
  [ "$(sha256sum "$source" | cut -d ' ' -f 1)" = "$(sha256sum "$staged" | cut -d ' ' -f 1)" ] ||
    fail "the runtime source changed while copying"
  "$staged" --version >/dev/null || fail "the runtime does not report its version"
  sync "$staged"
}

switch_runtime() {
  previous=/usr/local/lib/grund/agent/grund.install-previous
  [ ! -L "$previous" ] || fail "the previous runtime must not be a symbolic link"
  if [ -n "$old_active" ]; then
    [ -f "$previous" ] || fail "the retained running executable is missing"
  elif [ -f "$runtime_binary" ]; then
    snapshot="$(mktemp /usr/local/lib/grund/agent/.known-good.XXXXXX)"
    install -m 0755 "$runtime_binary" "$snapshot"
    cmp -s "$runtime_binary" "$snapshot" || fail "the previous runtime changed while retaining it"
    sync "$snapshot"
    mv -f "$snapshot" "$previous"
    snapshot=""
    sync /usr/local/lib/grund/agent
  else
    rm -f "$previous"
  fi
  switched=1
  mv -f "$staged" "$runtime_binary"
  staged=""
  sync /usr/local/lib/grund/agent
}

if [ -n "$binary" ]; then
  [ -x "$binary" ] || fail "--binary must name the verified executable"
  [ -z "$from_instance" ] || fail "--binary and --from-instance cannot be combined"
  step "grund, the verified local release"
  "$binary" --version
  install_runtime "$binary"
else
  step "grund, the build $url selects"
  ready="$(curl -fsS "$url/health/ready")" ||
    fail "$url/health/ready did not answer 200; is the instance up and ready, and is this its address?"
  revision="$(echo "$ready" | sed -n 's/.*"revision":"\([^"]*\)".*/\1/p')"
  [ -n "$revision" ] || fail "$url/health/ready names no revision; is it a grund instance?"
  artifact_revision="$revision"
  if [ -n "$from_instance" ]; then
    base="$url/install"
    file="grund-linux-$(uname -m)"
    curl -fsSL -o "$work/grund" "$base/$file" ||
      fail "$url serves no $file: it does not serve its installer (GRUND_SERVE_INSTALLER), or runs grund for another architecture"
    sum="$(curl -fsSL "$base/$file.sha256")" || fail "$url serves no SHA-256 for $file"
  else
    case "$revision" in
      *+*)
        server_revision=${revision%%+*}
        artifact_revision=${revision#*+}
        echo "$server_revision" | grep -qx '[0-9a-f]\{40\}' ||
          fail "$url names an invalid server revision \"$revision\"; expected <server commit>+<public commit>"
        ;;
    esac
    echo "$artifact_revision" | grep -qx '[0-9a-f]\{40\}' ||
      fail "$url runs a grund build that was not published (revision \"$revision\"; a build from source, such as compose from a clone, has none). Install from the instance itself: its Machines page offers the command when it serves its installer (GRUND_SERVE_INSTALLER=true, compose.yaml's default), or add --from-instance to this one. Or run a published image, git.kjuulh.io/grund/grund:main-<the full 40-character commit>"
    [ "$arch" = amd64 ] || fail "main-commit packages contain amd64 only; use the versioned installer at https://grund.sh/install or --from-instance"
    base="$PACKAGES/main-$artifact_revision"
    curl -fsSL -o "$work/grund" "$base/grund" || fail "no published grund for revision $artifact_revision ($base/grund)"
    sum="$(curl -fsSL "$base/grund.sha256")" || fail "no published SHA-256 for grund $artifact_revision"
  fi
  echo "$sum" | grep -qx '[0-9a-f]\{64\}' || fail "the SHA-256 from $base is not 64 hex characters"
  verify "$work/grund" "$sum"
  install_runtime "$work/grund"
  echo "    grund $artifact_revision from $base, sha256 $(echo "$sum" | cut -c1-12)"
fi
step "restic $RESTIC_VERSION, encrypted backups"
if ! command -v bzip2 >/dev/null; then
  echo "    bzip2, to unpack it"
  pkg bzip2 "install bzip2: it unpacks the pinned backup engine"
fi
archive="$work/restic.bz2"
curl -fsSL -o "$archive" "https://github.com/restic/restic/releases/download/v$RESTIC_VERSION/restic_${RESTIC_VERSION}_linux_${arch}.bz2" ||
  fail "could not download pinned restic $RESTIC_VERSION"
verify "$archive" "$RESTIC_BZ2_SHA256"
bzip2 -dc "$archive" > "$work/restic" || fail "could not unpack verified restic"
install -m 0755 "$work/restic" /usr/local/bin/restic

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
    pkg nftables "install nftables (nft) for VMs, or rerun with --no-vms"
  fi
  runtime=firecracker
elif [ -n "$vms" ]; then
  echo "    no /dev/kvm: the agent runs without VMs"
fi

switch_runtime

if [ -f /var/lib/grund/agent/machine.json ]; then
  step "already registered; keeping this device's identity"
elif [ -n "$prepare_only" ]; then
  step "agent installed; enrollment waits for the owner's machine setup code"
else
  [ -n "$code" ] || fail "give the setup code from $url's Machines page: --code grund_join_..."
  step "registering with $url"
  "$runtime_binary" join --url "$url" --name "${name:-$(uname -n)}" "$code"
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
runtime_arguments="${previous_arguments:---vm-runtime $runtime --vm-firecracker /usr/local/bin/firecracker --vm-jailer /usr/local/bin/jailer}"
cat > "$work/grund-agent.service" <<UNIT
[Unit]
Description=grund agent: keeps this machine connected to its grund instance
Documentation=https://git.kjuulh.io/grund/grund
After=network-online.target
Wants=network-online.target
ConditionPathExists=/var/lib/grund/agent/machine.json

[Service]
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$runtime_binary agent $runtime_arguments
Restart=always
RestartSec=5
KillMode=process
$delegate

[Install]
WantedBy=multi-user.target
UNIT
if [ -f "$work/previous.service" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ExecStart=*) printf 'ExecStart=%s agent %s\n' "$runtime_binary" "$runtime_arguments" ;;
      *) printf '%s\n' "$line" ;;
    esac
  done < "$work/previous.service" > "$work/grund-agent.service"
fi
unit_staged="$(mktemp /etc/systemd/system/.grund-agent.service.XXXXXX)"
install -m 0644 "$work/grund-agent.service" "$unit_staged"
sync "$unit_staged"
unit_written=1
mv -f "$unit_staged" /etc/systemd/system/grund-agent.service
unit_staged=""
sync /etc/systemd/system
printf 'grund-agent-v1\n' > "$work/managed-agent"
systemctl daemon-reload
systemctl enable grund-agent.service >/dev/null 2>&1
if [ -f /var/lib/grund/agent/machine.json ]; then
  systemctl restart grund-agent.service
  sleep 3
  systemctl is-active --quiet grund-agent.service || { journalctl -u grund-agent --no-pager -n 20; fail "grund-agent.service did not stay up"; }
  echo "    service running; logs: journalctl -u grund-agent -f"
  echo "done: enrollment/control-link health is not established by this service check"
else
  echo "    enabled; not started until this machine is registered"
fi
install -m 0600 "$work/managed-agent" /var/lib/grund/.installer-agent
