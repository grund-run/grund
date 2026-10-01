use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;

use super::random_hex;

pub const LIGHTHOUSE: &str = "198.51.100.1";
pub const PUBLIC_URL: &str = "https://198.51.100.1";
pub const RELAY_URL: &str = "https://198.51.100.1:8443";
pub const NAT_A: &str = "198.51.100.11";
pub const RELAY_1: &str = "198.51.100.2";
pub const RELAY_2: &str = "198.51.100.3";
pub const NAT_B: &str = "198.51.100.12";

const TOPOLOGY: &str = r#"
set -euo pipefail
W=$1
T=$2
mkdir -p "$W/ns"
mk() {
  if [ "${2:-}" = own-mounts ]; then
    unshare -n -m --propagation private tail --pid=$$ -f /dev/null &
  else
    unshare -n tail --pid=$$ -f /dev/null &
  fi
  echo $! > "$W/ns/$1"
  sleep 0.05
  nsx "$1" ip link set lo up
}
pid() { cat "$W/ns/$1"; }
nsx() { local ns=$1; shift; nsenter -t "$(pid "$ns")" -n -- "$@"; }
link() {
  ip link add "$2" netns "$(pid "$1")" type veth peer name "$5" netns "$(pid "$4")"
  nsx "$1" ip addr add "$3" dev "$2"
  nsx "$4" ip addr add "$6" dev "$5"
  nsx "$1" ip link set "$2" up
  nsx "$4" ip link set "$5" up
}
plug() {
  ip link add wan netns "$(pid "$1")" type veth peer name "p-$1" netns "$(pid net)"
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
mk net
nsx net ip link add br0 type bridge
nsx net ip link set br0 up
mk lh
plug lh 198.51.100.1/24
for side in a:1:11 b:2:12; do
  IFS=: read -r n i pub <<<"$side"
  mk "r$n"
  mk "$n" own-mounts
  plug "r$n" "198.51.100.$pub/24"
  link "r$n" lan "10.$i.0.1/24" "$n" eth0 "10.$i.0.2/24"
  nsx "$n" ip route add default via "10.$i.0.1"
  nat_router "r$n"
done
mk rl1
plug rl1 198.51.100.2/24
mk rl2
plug rl2 198.51.100.3/24
mk c own-mounts
plug c 198.51.100.40/24
nsx c ip link set wan down
nsx c ip link set wan name eth0
nsx c ip link set eth0 up
nsx c ip route add default via 198.51.100.1 dev eth0
touch "$W/ready"
exec tail --pid="$T" -f /dev/null
"#;

pub struct Lab {
    pub work: PathBuf,
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    pids: HashMap<String, u32>,
    children: Mutex<Vec<(String, Child)>>,
    lab_bin: PathBuf,
    many_ids: bool,
}

impl Drop for Lab {
    fn drop(&mut self) {
        if let Ok(children) = self.children.get_mut() {
            for (_, child) in children.iter_mut().rev() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

fn which(program: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|path| path.is_file())
    })
}

pub fn lab_binary() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_grund")).with_file_name("grund-net-lab")
}

impl Lab {
    pub async fn start() -> anyhow::Result<Option<Arc<Self>>> {
        if std::env::var("GRUND_ACCEPT_NETLAB").ok().as_deref() != Some("1") {
            eprintln!("skipped: the network lab runs only with GRUND_ACCEPT_NETLAB=1");
            return Ok(None);
        }
        for tool in [
            "unshare", "nsenter", "ip", "nft", "setpriv", "openssl", "ping",
        ] {
            anyhow::ensure!(which(tool).is_some(), "the network lab needs {tool}");
        }
        let lab_bin = lab_binary();
        anyhow::ensure!(
            lab_bin.is_file(),
            "build it first: cargo build -p grund-net --bins ({})",
            lab_bin.display()
        );
        let work = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("nl-{}", random_hex(4)));
        std::fs::create_dir_all(work.join("pg"))?;
        let mut lab = Self {
            ca: work.join("ca.crt"),
            cert: work.join("server.crt"),
            key: work.join("server.key"),
            work,
            pids: HashMap::new(),
            children: Mutex::new(Vec::new()),
            lab_bin,
            many_ids: false,
        };
        lab.certificates()?;
        let log = std::fs::File::create(lab.work.join("topology.log"))?;
        let ids = subordinate_ids();
        lab.many_ids = ids.is_some();
        let mapping: Vec<String> = match ids {
            Some((uid, gid, count)) => vec![
                "--map-user=0".into(),
                "--map-group=0".into(),
                format!("--map-users=1:{uid}:{count}"),
                format!("--map-groups=1:{gid}:{count}"),
                "-nm".into(),
            ],
            None => vec!["-Urnm".into()],
        };
        let holder = Command::new("unshare")
            .args(&mapping)
            .args(["--fork", "--kill-child", "setpriv", "--pdeathsig", "KILL"])
            .args(["bash", "-c", TOPOLOGY, "topology"])
            .arg(&lab.work)
            .arg(std::process::id().to_string())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()
            .context("start the lab's user namespace")?;
        lab.children
            .lock()
            .unwrap()
            .push(("topology".into(), holder));
        let deadline = Instant::now() + Duration::from_secs(20);
        while !lab.work.join("ready").exists() {
            if Instant::now() > deadline {
                let log =
                    std::fs::read_to_string(lab.work.join("topology.log")).unwrap_or_default();
                anyhow::bail!("the lab's topology did not come up:\n{log}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        for entry in std::fs::read_dir(lab.work.join("ns"))? {
            let entry = entry?;
            let pid = std::fs::read_to_string(entry.path())?.trim().parse()?;
            lab.pids
                .insert(entry.file_name().to_string_lossy().into_owned(), pid);
        }
        for node in ["a", "b", "c"] {
            std::fs::write(
                lab.work.join(format!("nsswitch-{node}")),
                "hosts: files dns\n",
            )?;
            std::fs::write(lab.work.join(format!("resolv-{node}")), "")?;
            for (file, target) in [
                ("nsswitch", "/etc/nsswitch.conf"),
                ("resolv", "/etc/resolv.conf"),
            ] {
                let source = lab.work.join(format!("{file}-{node}"));
                let out = lab.run(
                    node,
                    &["mount", "--bind", &source.to_string_lossy(), target],
                )?;
                anyhow::ensure!(out.status.success(), "bind {target} in {node}: {out:?}");
            }
        }
        let lab = Arc::new(lab);
        lab.bridge_host_services()?;
        Ok(Some(lab))
    }

    fn certificates(&self) -> anyhow::Result<()> {
        let w = &self.work;
        let ext = w.join("ext.cnf");
        std::fs::write(
            &ext,
            format!(
                "subjectAltName=IP:{LIGHTHOUSE},IP:{RELAY_1},IP:{RELAY_2}\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n"
            ),
        )?;
        let steps: [Vec<String>; 3] = [
            vec![
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=grund-netlab-ca",
            ]
            .into_iter()
            .map(String::from)
            .chain([
                "-keyout".into(),
                path(w, "ca.key"),
                "-out".into(),
                path(w, "ca.crt"),
            ])
            .collect(),
            vec![
                "req",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-nodes",
                "-subj",
                "/CN=grund-netlab",
            ]
            .into_iter()
            .map(String::from)
            .chain([
                "-keyout".into(),
                path(w, "server.key"),
                "-out".into(),
                path(w, "server.csr"),
            ])
            .collect(),
            vec!["x509", "-req", "-days", "1", "-CAcreateserial"]
                .into_iter()
                .map(String::from)
                .chain([
                    "-in".into(),
                    path(w, "server.csr"),
                    "-CA".into(),
                    path(w, "ca.crt"),
                    "-CAkey".into(),
                    path(w, "ca.key"),
                    "-extfile".into(),
                    ext.to_string_lossy().into_owned(),
                    "-out".into(),
                    path(w, "server.crt"),
                ])
                .collect(),
        ];
        for step in steps {
            let out = Command::new("openssl").args(&step).output()?;
            anyhow::ensure!(out.status.success(), "openssl {step:?}: {out:?}");
        }
        Ok(())
    }

    fn enter(&self, ns: &str) -> Command {
        let mut command = Command::new(which("nsenter").expect("checked at start"));
        command.arg("-t").arg(self.pids[ns].to_string()).args([
            "-U",
            "--preserve-credentials",
            "-n",
            "-m",
            "--",
            "setpriv",
            "--pdeathsig",
            "KILL",
        ]);
        command
    }

    pub fn run(&self, ns: &str, args: &[&str]) -> anyhow::Result<Output> {
        self.enter(ns)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("run {args:?} in {ns}"))
    }

    pub async fn run_async(self: &Arc<Self>, ns: &str, args: &[&str]) -> anyhow::Result<Output> {
        let (lab, ns, args) = (
            self.clone(),
            ns.to_string(),
            args.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
        );
        tokio::task::spawn_blocking(move || {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            lab.run(&ns, &args)
        })
        .await?
    }

    pub async fn succeeds(self: &Arc<Self>, ns: &str, args: &[&str]) -> bool {
        self.run_async(ns, args)
            .await
            .is_ok_and(|out| out.status.success())
    }

    pub fn spawn(
        &self,
        ns: &str,
        args: &[&str],
        env: &[(&str, &str)],
        log: &str,
    ) -> anyhow::Result<()> {
        let log_name = log.to_string();
        let log = std::fs::File::create(self.work.join(log))?;
        let mut command = self.enter(ns);
        command
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        for (name, value) in env {
            command.env(name, value);
        }
        let child = command
            .spawn()
            .with_context(|| format!("spawn {args:?} in {ns}"))?;
        self.children.lock().unwrap().push((log_name, child));
        Ok(())
    }

    fn spawn_here(&self, args: &[&str], log: &str) -> anyhow::Result<()> {
        let log_name = log.to_string();
        let log = std::fs::File::create(self.work.join(log))?;
        let child = Command::new(&self.lab_bin)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        self.children.lock().unwrap().push((log_name, child));
        Ok(())
    }

    pub fn stop(&self, log: &str) -> bool {
        let mut children = self.children.lock().unwrap();
        let mut stopped = false;
        for (name, child) in children.iter_mut() {
            if name == log {
                let _ = child.kill();
                let _ = child.wait();
                stopped = true;
            }
        }
        stopped
    }

    pub fn spawn_relay(&self, ns: &str, address: &str, token: &str) -> anyhow::Result<String> {
        let (cert, key, ca) = (
            self.cert.to_string_lossy().into_owned(),
            self.key.to_string_lossy().into_owned(),
            self.ca.to_string_lossy().into_owned(),
        );
        let log = format!("relay-{ns}.log");
        self.spawn(
            ns,
            &[
                env!("CARGO_BIN_EXE_grund"),
                "relay",
                "--listen",
                &format!("{address}:443"),
                "--quic-listen",
                &format!("{address}:7842"),
                "--tls-cert-file",
                &cert,
                "--tls-key-file",
                &key,
                "--grund-url",
                PUBLIC_URL,
            ],
            &[
                ("GRUND_RELAY_ACCESS_TOKEN", token),
                ("SSL_CERT_FILE", &ca),
                ("RUST_LOG", "grund_server=debug,iroh_relay=info,warn"),
            ],
            &log,
        )?;
        Ok(log)
    }

    pub fn set_nsswitch(&self, node: &str, hosts: &str) -> anyhow::Result<()> {
        std::fs::write(
            self.work.join(format!("nsswitch-{node}")),
            format!("hosts: {hosts}\n"),
        )?;
        Ok(())
    }

    pub async fn start_resolved(self: &Arc<Self>, node: &str) -> anyhow::Result<Option<String>> {
        let resolved = Path::new("/usr/lib/systemd/systemd-resolved");
        if !self.many_ids || !resolved.is_file() || which("dbus-daemon").is_none() {
            return Ok(None);
        }
        let out = self
            .run_async(node, &["mount", "-t", "tmpfs", "tmpfs", "/run/systemd"])
            .await?;
        anyhow::ensure!(
            out.status.success(),
            "tmpfs on /run/systemd in {node}: {out:?}"
        );
        let bus = "/run/systemd/grund-lab-bus";
        let config = self.work.join(format!("bus-{node}.conf"));
        std::fs::write(
            &config,
            format!(
                "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\" \
                 \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n\
                 <busconfig><type>system</type><listen>unix:path={bus}</listen><auth>EXTERNAL</auth>\
                 <policy context=\"default\"><allow user=\"*\"/><allow own=\"*\"/>\
                 <allow send_destination=\"*\"/><allow receive_sender=\"*\"/></policy></busconfig>\n"
            ),
        )?;
        self.spawn(
            node,
            &[
                "dbus-daemon",
                "--nofork",
                "--nopidfile",
                "--config-file",
                &config.to_string_lossy(),
            ],
            &[],
            &format!("dbus-{node}.log"),
        )?;
        let address = format!("unix:path={bus}");
        for _ in 0..40 {
            if self.succeeds(node, &["test", "-S", bus]).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.spawn(
            node,
            &[&resolved.to_string_lossy()],
            &[("DBUS_SYSTEM_BUS_ADDRESS", &address)],
            &format!("resolved-{node}.log"),
        )?;
        for _ in 0..50 {
            if self
                .succeeds(
                    node,
                    &["test", "-S", "/run/systemd/resolve/io.systemd.Resolve"],
                )
                .await
            {
                return Ok(Some(address));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!(
            "systemd-resolved did not start in {node}:\n{}",
            std::fs::read_to_string(self.work.join(format!("resolved-{node}.log")))
                .unwrap_or_default()
        )
    }

    pub fn pid_of(&self, log: &str) -> Option<u32> {
        self.children
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(name, _)| name == log)
            .map(|(_, child)| child.id())
    }

    pub fn socket(&self, name: &str) -> String {
        self.work.join(name).to_string_lossy().into_owned()
    }

    fn bridge_host_services(&self) -> anyhow::Result<()> {
        let database = std::env::var("GRUND_ACCEPT_DATABASE_URL")
            .ok()
            .unwrap_or(super::DEFAULT_DATABASE_URL.into());
        let smtp = std::env::var("GRUND_ACCEPT_SMTP_URL")
            .ok()
            .unwrap_or(super::DEFAULT_SMTP_URL.into());
        let pg = self.work.join("pg/.s.PGSQL.5432");
        self.spawn_here(
            &[
                "forward",
                "--listen",
                &format!("unix:{}", pg.display()),
                "--to",
                &format!("tcp:{}", host_port(&database)?),
            ],
            "bridge-pg.log",
        )?;
        self.spawn_here(
            &[
                "forward",
                "--listen",
                &format!("unix:{}", self.socket("smtp.sock")),
                "--to",
                &format!("tcp:{}", host_port(&smtp)?),
            ],
            "bridge-smtp.log",
        )?;
        wait_for_path(&pg)?;
        wait_for_path(&self.work.join("smtp.sock"))
    }

    pub fn bridge_into(
        &self,
        ns: &str,
        listen: &str,
        host: &str,
        name: &str,
    ) -> anyhow::Result<()> {
        let socket = self.socket(&format!("{name}.sock"));
        self.spawn_here(
            &[
                "forward",
                "--listen",
                &format!("unix:{socket}"),
                "--to",
                &format!("tcp:{host}"),
            ],
            &format!("bridge-{name}.log"),
        )?;
        wait_for_path(&self.work.join(format!("{name}.sock")))?;
        self.spawn(
            ns,
            &[
                &self.lab_bin.to_string_lossy(),
                "forward",
                "--listen",
                &format!("tcp:{listen}"),
                "--to",
                &format!("unix:{socket}"),
            ],
            &[],
            &format!("front-{name}.log"),
        )
    }

    pub fn front_door(&self, grund_listen: &str) -> anyhow::Result<u16> {
        let (cert, key) = (self.cert.to_string_lossy(), self.key.to_string_lossy());
        self.spawn(
            "lh",
            &[
                &self.lab_bin.to_string_lossy(),
                "forward",
                "--listen",
                &format!("tcp:{LIGHTHOUSE}:443"),
                "--tls-cert",
                &cert,
                "--tls-key",
                &key,
                "--to",
                &format!("tcp:{grund_listen}"),
            ],
            &[],
            "front-tls.log",
        )?;
        self.spawn(
            "lh",
            &[
                &self.lab_bin.to_string_lossy(),
                "forward",
                "--listen",
                &format!("unix:{}", self.socket("front.sock")),
                "--to",
                &format!("tcp:{LIGHTHOUSE}:443"),
            ],
            &[],
            "front-sock.log",
        )?;
        self.spawn(
            "lh",
            &[
                &self.lab_bin.to_string_lossy(),
                "forward",
                "--listen",
                "tcp:127.0.0.1:1025",
                "--to",
                &format!("unix:{}", self.socket("smtp.sock")),
            ],
            &[],
            "front-smtp.log",
        )?;
        wait_for_path(&self.work.join("front.sock"))?;
        let port = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        self.spawn_here(
            &[
                "forward",
                "--listen",
                &format!("tcp:127.0.0.1:{port}"),
                "--to",
                &format!("unix:{}", self.socket("front.sock")),
            ],
            "bridge-front.log",
        )?;
        Ok(port)
    }

    pub fn roots(&self) -> anyhow::Result<rustls::RootCertStore> {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(&self.ca)? {
            roots.add(cert?)?;
        }
        Ok(roots)
    }

    pub async fn cut_direct_udp(self: &Arc<Self>) -> anyhow::Result<()> {
        let rules = format!(
            "table bridge cut {{\n  chain forward {{\n    type filter hook forward priority 0; policy accept;\n    \
             ip saddr {NAT_A} ip daddr {NAT_B} meta l4proto udp drop\n    \
             ip saddr {NAT_B} ip daddr {NAT_A} meta l4proto udp drop\n  }}\n}}\n"
        );
        let file = self.work.join("cut.nft");
        std::fs::write(&file, rules)?;
        let out = self
            .run_async("net", &["nft", "-f", &file.to_string_lossy()])
            .await?;
        anyhow::ensure!(out.status.success(), "{out:?}");
        Ok(())
    }

    pub async fn restore_direct_udp(self: &Arc<Self>) -> anyhow::Result<()> {
        let out = self
            .run_async("net", &["nft", "delete", "table", "bridge", "cut"])
            .await?;
        anyhow::ensure!(out.status.success(), "{out:?}");
        Ok(())
    }

    pub fn use_resolver(&self, node: &str, nameserver: &str) -> anyhow::Result<()> {
        std::fs::write(
            self.work.join(format!("resolv-{node}")),
            format!("nameserver {nameserver}\noptions timeout:2 attempts:2\n"),
        )?;
        Ok(())
    }
}

fn subordinate_ids() -> Option<(u64, u64, u64)> {
    which("newuidmap")?;
    which("newgidmap")?;
    let user = String::from_utf8(Command::new("id").arg("-un").output().ok()?.stdout).ok()?;
    let user = user.trim();
    let find = |file: &str| -> Option<(u64, u64)> {
        std::fs::read_to_string(file)
            .ok()?
            .lines()
            .find_map(|line| {
                let mut parts = line.split(':');
                (parts.next()? == user).then_some(())?;
                Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
            })
    };
    let (uid, uids) = find("/etc/subuid")?;
    let (gid, gids) = find("/etc/subgid")?;
    Some((uid, gid, uids.min(gids).min(65535)))
}

fn wait_for_path(path: &Path) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        anyhow::ensure!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn path(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

fn host_port(url: &str) -> anyhow::Result<String> {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    anyhow::ensure!(host_port.contains(':'), "{url} has no port");
    Ok(host_port.to_string())
}
