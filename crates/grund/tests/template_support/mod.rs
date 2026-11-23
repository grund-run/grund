use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

use grund_domain::app::templates::Template;
use uuid::Uuid;

pub enum Mount {
    Writable,
    ReadOnly,
}

pub struct Fixture {
    pub template: &'static Template,
    pub memory_mib: u64,
    pub address: String,
    directory: PathBuf,
    name: String,
    network: Option<String>,
    volume: Option<String>,
    container: Option<String>,
    credentials: Vec<(String, String)>,
}

impl Fixture {
    pub fn new(template: &'static Template, omitted_env: &[&str]) -> Self {
        checked(
            &["version", "--format", "{{.Server.Version}}"],
            "Docker must be available for this explicitly ignored acceptance test",
        );
        checked(
            &["image", "inspect", "--format", "{{.Id}}", template.image],
            "the catalogue's pinned image must already be provisioned locally; this test never pulls",
        );
        let spec = template.spec(false).expect("template is available");
        assert!(spec.ports.iter().all(|port| !port.public));
        assert!(spec.image.contains("@sha256:"));
        assert_eq!(spec.volumes.len(), 1, "template owns one persistent volume");
        assert!(
            spec.ports.iter().all(|port| !port.public),
            "the actual AppSpec must expose no public ports",
        );
        let name = format!("grund-{}-accept-{}", template.key, Uuid::new_v4().simple());
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cache = manifest
            .ancestors()
            .find(|path| path.join(".workspace-cache").is_dir())
            .unwrap_or_else(|| manifest.parent().unwrap().parent().unwrap())
            .join(".workspace-cache/template-acceptance");
        fs::create_dir_all(&cache).expect("create workspace test cache");
        let directory = cache.join(&name);
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .expect("create private template test directory");
        let mut fixture = Self {
            template,
            memory_mib: spec.memory_mib,
            address: String::new(),
            directory,
            name,
            network: None,
            volume: None,
            container: None,
            credentials: template
                .secret_variables
                .iter()
                .map(|name| {
                    let random = Uuid::new_v4().simple().to_string();
                    let value = if name.ends_with("_USER") {
                        format!("grund_{random}")
                    } else {
                        random
                    };
                    ((*name).to_owned(), value)
                })
                .collect(),
        };
        let mut env = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(fixture.directory.join("service.env"))
            .expect("create private environment file");
        for variable in &spec.env {
            if !omitted_env.contains(&variable.name.as_str()) && !variable.value.contains('\n') {
                writeln!(env, "{}={}", variable.name, variable.value)
                    .expect("write the actual AppSpec environment");
            }
        }
        for (name, value) in &fixture.credentials {
            writeln!(env, "{name}={value}").expect("write generated template credential");
        }
        drop(env);
        let random = Uuid::new_v4();
        let bytes = random.as_bytes();
        let subnet = format!("10.253.{}.{}/28", bytes[0], bytes[1] & 240);
        fixture.network = Some(checked(
            &[
                "network",
                "create",
                "--internal",
                "--subnet",
                &subnet,
                &fixture.name,
            ],
            "create uniquely named internal network",
        ));
        fixture.volume = Some(checked(
            &["volume", "create", &fixture.name],
            "create uniquely named owned data volume",
        ));
        fixture
    }

    pub fn credential(&self, name: &str) -> &str {
        &self
            .credentials
            .iter()
            .find(|(key, _)| key == name)
            .expect("template declares the required secret")
            .1
    }

    pub fn start(&mut self, mount: Option<Mount>) {
        let spec = self.template.spec(false).expect("template is available");
        let envfile = self.directory.join("service.env");
        let memory = format!("{}m", spec.memory_mib);
        let cpus = format!("{:.3}", f64::from(spec.cpu_millis) / 1000.0);
        let volume = format!(
            "type=volume,source={},target={}{}",
            self.volume.as_deref().expect("fixture owns a volume"),
            spec.volumes[0].path,
            if matches!(mount, Some(Mount::ReadOnly)) {
                ",readonly"
            } else {
                ""
            },
        );
        let mut args = vec![
            "create",
            "--pull=never",
            "--name",
            &self.name,
            "--network",
            self.network.as_deref().expect("fixture owns a network"),
            "--memory",
            &memory,
            "--memory-swap",
            &memory,
            "--cpus",
            &cpus,
            "--env-file",
            envfile.to_str().expect("environment path is UTF-8"),
            "--stop-signal",
            &spec.stop.signal,
        ];
        if mount.is_some() {
            args.extend_from_slice(&["--mount", &volume]);
        }
        for variable in &spec.env {
            if variable.value.contains('\n') {
                args.extend_from_slice(&["--env", &variable.name]);
            }
        }
        if let Some(entrypoint) = spec.command.first() {
            args.extend_from_slice(&["--entrypoint", entrypoint]);
        }
        args.push(&spec.image);
        args.extend(spec.command.iter().skip(1).map(String::as_str));
        let mut create = Command::new("docker");
        create.args(&args);
        for variable in &spec.env {
            if variable.value.contains('\n') {
                create.env(&variable.name, &variable.value);
            }
        }
        self.container = Some(self.successful(
            create.output().expect("create the actual template AppSpec"),
            "create the actual template AppSpec",
        ));
        checked(&["start", self.id()], "start the actual template AppSpec");
        self.address = checked(
            &[
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                self.id(),
            ],
            "read the container's private bridge address",
        );
        let bindings = checked(
            &[
                "inspect",
                "--format",
                "{{json .HostConfig.PortBindings}}",
                self.id(),
            ],
            "inspect host port bindings",
        );
        assert!(
            matches!(bindings.as_str(), "{}" | "null"),
            "template must never publish host ports",
        );
    }

    pub fn remove_copy(&mut self) {
        self.successful(
            docker(&["stop", "--time", "30", self.id()]),
            "stop the previous copy cleanly",
        );
        checked(
            &["rm", "--volumes", self.id()],
            "remove the previous copy without removing its named volume",
        );
        self.container = None;
        self.address.clear();
    }

    pub fn id(&self) -> &str {
        self.container.as_deref().expect("fixture owns a container")
    }

    pub fn exec(&self, args: &[&str]) -> Output {
        let mut command = vec!["exec", self.id()];
        command.extend_from_slice(args);
        docker(&command)
    }

    pub fn successful(&self, output: Output, context: &str) -> String {
        assert!(
            output.status.success(),
            "{context}: {}",
            self.redact(&String::from_utf8_lossy(&output.stderr)),
        );
        String::from_utf8(output.stdout)
            .expect("template client output is UTF-8")
            .trim()
            .to_owned()
    }

    pub fn redact(&self, value: &str) -> String {
        self.credentials
            .iter()
            .fold(value.to_owned(), |text, (name, _)| {
                text.replace(self.credential(name), "[redacted]")
            })
    }

    pub fn logs(&self) -> String {
        let output = docker(&["logs", "--tail", "80", self.id()]);
        self.redact(&format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ))
    }

    pub fn wait_until_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if self.ready() {
                let address: IpAddr = self.address.parse().expect("container has a bridge IP");
                assert!(!address.is_loopback() && !address.is_unspecified());
                return;
            }
            let running = checked(
                &["inspect", "--format", "{{.State.Running}}", self.id()],
                "inspect startup state",
            );
            assert!(
                running == "true" && Instant::now() < deadline,
                "template failed HTTP readiness: {}",
                self.logs(),
            );
            thread::sleep(Duration::from_millis(250));
        }
    }

    pub fn ready(&self) -> bool {
        let (name, path) = self.template.check.expect("template has HTTP readiness");
        let port = self
            .template
            .ports
            .iter()
            .find(|(candidate, _, _)| *candidate == name)
            .expect("readiness uses a declared port")
            .1;
        let url = format!("http://{}:{port}{path}", self.address);
        self.exec(&[
            "/bin/sh",
            "-ec",
            "if command -v curl >/dev/null 2>&1; then exec curl --noproxy '*' -fsS --max-time 2 \"$1\"; else exec wget -q -T 2 -O - \"$1\"; fi",
            "readiness",
            &url,
        ])
        .status
        .success()
    }

    pub fn assert_startup_refused(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(!self.ready(), "unsafe template reached HTTP readiness");
            let state = checked(
                &[
                    "inspect",
                    "--format",
                    "{{.State.Running}} {{.State.ExitCode}}",
                    self.id(),
                ],
                "inspect unsafe startup result",
            );
            if let Some(code) = state.strip_prefix("false ") {
                assert_ne!(code, "0", "unsafe startup must fail: {}", self.logs());
                return;
            }
            assert!(
                Instant::now() < deadline,
                "unsafe startup did not fail closed: {}",
                self.logs(),
            );
            thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn http_get(&self, port: u16, path: &str) -> String {
        let address: SocketAddr = format!("{}:{port}", self.address)
            .parse()
            .expect("private HTTP address");
        let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(3))
            .expect("connect to the private bridge HTTP endpoint");
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("bound HTTP read time");
        write!(
            socket,
            "GET {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .expect("send HTTP request");
        let mut response = String::new();
        socket
            .read_to_string(&mut response)
            .expect("read HTTP response");
        assert!(
            response.starts_with("HTTP/1.1 200 ") || response.starts_with("HTTP/1.0 200 "),
            "HTTP readiness request must succeed",
        );
        response
            .split_once("\r\n\r\n")
            .expect("HTTP response has a body separator")
            .1
            .to_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(id) = &self.container {
            let _ = Command::new("docker")
                .args(["rm", "--force", "--volumes", id])
                .output();
        }
        if let Some(id) = &self.volume {
            let _ = Command::new("docker").args(["volume", "rm", id]).output();
        }
        if let Some(id) = &self.network {
            let _ = Command::new("docker").args(["network", "rm", id]).output();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn docker(args: &[&str]) -> Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("execute Docker for this explicitly ignored acceptance test")
}

fn checked(args: &[&str], context: &str) -> String {
    let output = docker(args);
    assert!(
        output.status.success(),
        "{context}: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout)
        .expect("Docker output is UTF-8")
        .trim()
        .to_owned()
}
