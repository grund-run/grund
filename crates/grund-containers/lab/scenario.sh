#!/usr/bin/env bash
# scenario.sh: runs as root INSIDE a throwaway lab machine (lab.sh puts it
# there with the lab driver, /opt/grund-lab/lab). Every runtime step is a
# separate run of the driver, so nothing is kept in a process between steps:
# what the agent's runtime knows, it reads back from containerd.
#
#   scenario.sh docker   install Docker (docker.io) and start one container in it
#   scenario.sh run      the grund-containers scenario, beside Docker
set -euo pipefail
L=/opt/grund-lab/lab
SOCK=/run/grund/containerd.sock
WHOAMI=docker.io/traefik/whoami@sha256:200689790a0a0ea48ca45992e0450bc26ccab5307375b41c84dfc4f2475937ab

say() { echo "$(date +%s%3N) $*"; }
lab() { "$L" "$@"; }
pid_of() { lab list | awk -v id="$1" '$3 == "id="id { for (i = 1; i <= NF; i++) if ($i ~ /^pid=/) { sub("pid=", "", $i); print $i } }'; }
shim_pids() { pgrep -f "containerd-shim-runc-v2 -namespace grund" | tr '\n' ' '; }

docker_phase() {
  say "kernel $(uname -r), $(nproc) vCPU, $(awk '/MemTotal/ {print $2}' /proc/meminfo) kB"
  t=$(date +%s)
  if DEBIAN_FRONTEND=noninteractive apt-get -qq update >/dev/null 2>&1 &&
    DEBIAN_FRONTEND=noninteractive apt-get -qq install -y docker.io >/dev/null 2>&1; then
    say "docker_install=ok seconds=$(( $(date +%s) - t )) $(docker --version) containerd=$(containerd --version | awk '{print $3}')"
    docker run -d --name docker-whoami "$WHOAMI" >/dev/null
    say "docker container: $(docker inspect -f '{{.Name}} running={{.State.Running}} ip={{.NetworkSettings.IPAddress}}' docker-whoami)"
    say "docker's containerd: socket=$(ls /run/containerd/containerd.sock) namespaces=[$(ctr -a /run/containerd/containerd.sock namespaces ls -q | tr '\n' ' ')]"
  else
    say "docker_install=failed seconds=$(( $(date +%s) - t )) (apt): the run goes on without Docker"
  fi
}

run_phase() {
  touch /root/marker
  find /run/containerd /var/lib/containerd /opt -xdev 2>/dev/null | sort > /root/docker-paths-before || true

  say "== capabilities"
  lab caps

  say "== prepare: first use downloads containerd 2.4.1 and runc 1.5.1 from GitHub and starts containerd"
  lab prepare
  say "unit: $(systemctl show grund-containerd -p ActiveState -p KillMode -p Delegate -p LimitNOFILE -p Restart | tr '\n' ' ')"
  say "binaries: $(ls /var/lib/grund/bin/containerd-2.4.1 | tr '\n' ' ')"
  say "== prepare again (containerd answers)"
  lab prepare

  say "== pull $WHOAMI by digest through the Transfer service"
  lab pull
  say "== pull again"
  lab pull

  say "== create two containers: a (image entrypoint, port 80) and b (command /whoami --port 8080)"
  lab create a
  lab create b /whoami --port 8080
  lab create-again a
  lab ready a 80 /
  lab ready b 8080 /health
  lab list
  a_pid=$(pid_of a)
  say "container a: pid=$a_pid user=$(awk '/^Uid:/ {print $2}' /proc/$a_pid/status) NoNewPrivs=$(awk '/^NoNewPrivs:/ {print $2}' /proc/$a_pid/status) CapEff=$(awk '/^CapEff:/ {print $2}' /proc/$a_pid/status)"
  say "cgroup a: $(cat /proc/$a_pid/cgroup) memory.max=$(cat /sys/fs/cgroup/grund/a/memory.max) cpu.max=\"$(cat /sys/fs/cgroup/grund/a/cpu.max)\" pids.max=$(cat /sys/fs/cgroup/grund/a/pids.max)"
  say "netns a: $(nsenter --net=/run/grund/netns/a ip -br link | tr -s ' ' | tr '\n' ';') same as the process's: $([[ $(stat -L -c %i /run/grund/netns/a) == $(stat -L -c %i /proc/$a_pid/ns/net) ]] && echo yes || echo no)"
  say "host cannot reach a: $(curl -s -m 1 -o /dev/null -w '%{http_code}' http://127.0.0.1:80/ || true) (000 = nothing listens on the host)"
  say "log a: $(head -c 200 /var/lib/grund/agent/logs/a.log | tr '\n' ' ')"
  for p in $(shim_pids); do say "shim pid=$p exe=$(readlink /proc/$p/exe) $(tr '\0' ' ' < /proc/$p/cmdline | grep -o -- '-address [^ ]*')"; done
  say "runc state: $(ls /run/grund/runc/grund 2>/dev/null | tr '\n' ' ') shim sockets: $(ls /run/grund/s | wc -l)"

  say "== a third container from an image whose USER is a name (prom/node-exporter, USER nobody): resolved from the image's /etc/passwd"
  export LAB_IMAGE=docker.io/prom/node-exporter:v1.9.1 LAB_DIGEST=sha256:d00a542e409ee618a4edc67da14dd48c5da66726bbd5537ab2af9c1dfc442c8a
  lab pull
  lab create c
  lab ready c 9100 /metrics
  c_pid=$(pid_of c)
  say "container c: pid=$c_pid uid/gid=$(awk '/^Uid:/ {print $2}' /proc/$c_pid/status)/$(awk '/^Gid:/ {print $2}' /proc/$c_pid/status) groups=[$(awk '/^Groups:/ {$1=""; print}' /proc/$c_pid/status)]"
  lab remove c SIGTERM 5
  unset LAB_IMAGE LAB_DIGEST

  say "== a's process is killed from outside (SIGKILL to pid $a_pid)"
  kill -KILL "$a_pid"
  lab wait-exited a
  lab probe a 80
  lab list
  say "== restart a"
  lab restart a
  lab ready a 80 /
  lab list

  say "== containerd SIGKILLed: systemd restarts it (Restart=on-failure); the apps keep their pids"
  before="$(pid_of a) $(pid_of b)"
  systemctl kill -s KILL --kill-whom=main grund-containerd
  t=$(date +%s%3N)
  until lab list >/dev/null 2>&1; do sleep 0.1; done
  say "containerd answers again after $(( $(date +%s%3N) - t )) ms; pids before=[$before] now=[$(pid_of a) $(pid_of b)]"

  say "== containerd stopped cleanly; prepare starts it again under the same unit name"
  systemctl stop grund-containerd
  say "unit after stop: $(systemctl is-active grund-containerd || true); shims still running: [$(shim_pids)]"
  say "list while containerd is stopped (expected to fail): $(lab list 2>&1 | tail -1 || true)"
  lab prepare
  say "pids now=[$(pid_of a) $(pid_of b)]"
  lab ready a 80 /

  say "== remove b with SIGTERM and a 2 s grace"
  lab remove b SIGTERM 2
  lab list
  say "after removal: netns b=$([[ -e /run/grund/netns/b ]] && echo present || echo gone) cgroup b=$([[ -d /sys/fs/cgroup/grund/b ]] && echo present || echo gone) runc state=[$(ls /run/grund/runc/grund 2>/dev/null | tr '\n' ' ')]"
  say "== remove an unknown id"
  lab remove nosuch SIGTERM 1

  say "== isolation"
  if command -v ctr >/dev/null; then
    say "grund's containerd namespaces: [$(ctr -a $SOCK namespaces ls -q | tr '\n' ' ')]"
    say "docker's containerd namespaces: [$(ctr -a /run/containerd/containerd.sock namespaces ls -q | tr '\n' ' ')]; containers in its grund namespace: [$(ctr -a /run/containerd/containerd.sock -n grund containers ls -q | tr '\n' ' ')]"
  fi
  find /run/containerd /var/lib/containerd /opt -xdev 2>/dev/null | sort > /root/docker-paths-after || true
  say "paths under /run/containerd, /var/lib/containerd, /opt added or removed during the run: [$(comm -3 /root/docker-paths-before /root/docker-paths-after | tr -d '\t' | tr '\n' ' ')]"
  say "paths there changed since the run began: [$(find /run/containerd /var/lib/containerd /opt -xdev -newer /root/marker 2>/dev/null | tr '\n' ' ')]"
  say "paths there naming grund, besides this lab's /opt/grund-lab: [$(grep -v '^/opt/grund-lab' /root/docker-paths-after | grep -c grund || true)]"
  if command -v docker >/dev/null; then
    say "docker container still: $(docker inspect -f 'running={{.State.Running}} pid={{.State.Pid}}' docker-whoami); answers: $(curl -s -m 2 "http://$(docker inspect -f '{{.NetworkSettings.IPAddress}}' docker-whoami)/" | head -1)"
    docker restart docker-whoami >/dev/null && say "docker restart docker-whoami: $(docker inspect -f 'running={{.State.Running}}' docker-whoami)"
  fi
  say "resident memory (KiB): containerd=$(ps -o rss= -p "$(systemctl show -p MainPID --value grund-containerd)") shims=[$(for p in $(shim_pids); do ps -o rss= -p $p; done | tr -s ' \n' ' ')]"
  say "disk: bin=$(du -sh /var/lib/grund/bin | cut -f1) runtime=$(du -sh /var/lib/grund/runtime | cut -f1)"
  say "== remove a"
  lab remove a SIGTERM 2
  lab list
  say "done"
}

case "${1:-}" in
  docker) docker_phase ;;
  run) run_phase ;;
  *) echo "usage: scenario.sh docker|run" >&2; exit 2 ;;
esac
