use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::Write,
    net::IpAddr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use grund_domain::app::templates;
use uuid::Uuid;

#[test]
#[ignore = "requires Docker and the catalogue's pinned SeaweedFS image already provisioned locally"]
fn seaweedfs_auxiliary_apis_bind_only_to_loopback() {
    let template = templates::find("seaweedfs").expect("SeaweedFS template exists");
    checked(
        &["image", "inspect", "--format", "{{.Id}}", template.image],
        "the pinned SeaweedFS image must be provisioned before this opt-in test (never pulled here)",
    );
    let name = format!("grund-s3-bind-{}", Uuid::new_v4().simple());
    let directory = std::env::temp_dir().join(&name);
    DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .expect("create private SeaweedFS test directory");
    let mut fixture = Seaweedfs {
        name,
        directory,
        created: false,
    };
    let envfile = fixture.directory.join("s3.env");
    let mut credentials = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&envfile)
        .expect("create private SeaweedFS environment file");
    for variable in ["S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"] {
        writeln!(
            credentials,
            "{variable}={}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        )
        .expect("write generated SeaweedFS credential");
    }
    drop(credentials);
    let mut arguments = vec![
        "create",
        "--pull=never",
        "--name",
        &fixture.name,
        "--network",
        "none",
        "--memory",
        "512m",
        "--cpus",
        "0.5",
        "--tmpfs",
        "/data:rw,size=256m",
        "--env-file",
        envfile.to_str().expect("environment path is UTF-8"),
        "--entrypoint",
        template.command.first().expect("SeaweedFS has a command"),
        template.image,
    ];
    arguments.extend_from_slice(&template.command[1..]);
    checked(&arguments, "create the exact shipped SeaweedFS template");
    fixture.created = true;
    checked(&["start", &fixture.name], "start the SeaweedFS template");

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let probe = Command::new("docker")
            .args([
                "exec",
                &fixture.name,
                "/bin/busybox",
                "wget",
                "-S",
                "-O",
                "/dev/null",
                "-T",
                "1",
                "http://127.0.0.1:8333/",
            ])
            .output()
            .expect("probe the native S3 HTTP server");
        let response = String::from_utf8_lossy(&probe.stderr);
        let answered = response.lines().any(|line| {
            line.split_whitespace()
                .next()
                .is_some_and(|word| word.starts_with("HTTP/"))
        });
        if !answered {
            assert!(
                Instant::now() < deadline,
                "the native S3 HTTP server did not answer"
            );
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        let output = checked(
            &["exec", &fixture.name, "/bin/busybox", "netstat", "-lnt"],
            "inspect actual native TCP listener bindings",
        );
        for line in output.lines() {
            let mut fields = line.split_whitespace();
            if !matches!(fields.next(), Some("tcp" | "tcp6")) {
                continue;
            }
            let local = fields.nth(2).expect("listener endpoint");
            let (host, port) = local.rsplit_once(':').expect("listener address");
            let address: IpAddr = host.parse().expect("listener IP");
            let port: u16 = port.parse().expect("listener port");
            if port != 8333 {
                assert!(
                    address.is_loopback(),
                    "auxiliary API {port} binds non-loopback address {address}"
                );
            }
        }
        break;
    }
}

struct Seaweedfs {
    name: String,
    directory: PathBuf,
    created: bool,
}

impl Drop for Seaweedfs {
    fn drop(&mut self) {
        if self.created {
            let _ = Command::new("docker")
                .args(["rm", "-f", &self.name])
                .output();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn checked(arguments: &[&str], context: &str) -> String {
    let output = Command::new("docker")
        .args(arguments)
        .output()
        .unwrap_or_else(|_| panic!("{context}: Docker did not execute"));
    assert!(
        output.status.success(),
        "{context}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("Docker output is UTF-8")
}
