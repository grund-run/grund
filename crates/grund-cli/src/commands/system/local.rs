use std::{borrow::Cow, fs, net::IpAddr, path::Path, process::Stdio, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, process::Command};

use super::{atomic_write, compose, failed, io, read_managed, run};
use crate::{
    error::{CliError, CliResult, Code},
    progress::Progress,
};

pub(super) struct Target<'a> {
    pub server: bool,
    pub domain: Option<&'a str>,
    pub url: Cow<'a, str>,
    pub convert: bool,
}

pub(super) fn target<'a>(
    domain: Option<&'a str>,
    url: Option<&'a str>,
    existing_domain: Option<&'a str>,
) -> CliResult<Target<'a>> {
    if let Some(url) = url {
        if domain.is_some() {
            return Err(CliError::usage("choose either --domain or --url"));
        }
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| CliError::usage("--url needs an HTTPS address"))?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(CliError::usage(
                "--url needs an HTTPS address without a path or password",
            ));
        }
        return Ok(Target {
            server: false,
            domain: None,
            url: Cow::Borrowed(url.trim_end_matches('/')),
            convert: false,
        });
    }
    let named = domain.or(existing_domain.filter(|name| !name.is_empty()));
    if let Some(name) = named {
        if !super::domain_name(name) {
            return Err(CliError::usage("give a DNS name such as grund.example.com"));
        }
        if existing_domain.is_some_and(|old| !old.is_empty() && old != name) {
            return Err(CliError::new(
                Code::Conflict,
                "this installation already uses another domain",
            ));
        }
    }
    Ok(Target {
        server: true,
        domain: named,
        url: named.map_or(Cow::Borrowed("http://localhost:8080"), |name| {
            Cow::Owned(format!("https://{name}"))
        }),
        convert: domain.is_some() && existing_domain == Some(""),
    })
}

pub(super) fn tunnel(
    connection: Option<&str>,
    user: Option<&str>,
    hostname: &str,
) -> CliResult<String> {
    let user = user.unwrap_or("root");
    let safe = |value: &str| {
        !value.is_empty()
            && !value.starts_with('-')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    if !safe(user) {
        return Err(failed("cannot safely format the SSH login name"));
    }
    let (host, port) = if let Some(connection) = connection {
        let mut parts = connection.split_whitespace();
        let _client = parts.next();
        let _client_port = parts.next();
        let address = parts
            .next()
            .ok_or_else(|| failed("SSH_CONNECTION has no server address"))?;
        let port = parts
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| failed("SSH_CONNECTION has no valid server port"))?;
        if parts.next().is_some() || address.parse::<IpAddr>().is_err() {
            return Err(failed("SSH_CONNECTION has no valid server address"));
        }
        (address, port)
    } else {
        if !safe(hostname) {
            return Err(failed("cannot safely format this machine's hostname"));
        }
        (hostname, 22)
    };
    Ok(if port == 22 {
        format!("ssh -L 8080:localhost:8080 {user}@{host}")
    } else {
        format!("ssh -p {port} -L 8080:localhost:8080 {user}@{host}")
    })
}

pub(super) fn distribution(release: &str) -> CliResult<&'static str> {
    match release.lines().find_map(|line| line.strip_prefix("ID=")).map(|id| id.trim_matches('"')) {
        Some("debian") => Ok("Debian"),
        Some("ubuntu") => Ok("Ubuntu"),
        _ => Err(CliError::new(Code::Failed, "Automatic Docker setup is available only on Debian and Ubuntu.")
            .hint("Install Docker and its 'docker compose' command from your distribution's packages, then run the same command again.")),
    }
}

fn compose_v2(version: &str) -> bool {
    version
        .rsplit(':')
        .next()
        .unwrap_or(version)
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|major| major.parse::<u32>().ok())
        .is_some_and(|major| major >= 2)
}

async fn probe(command: &mut Command) -> Option<Vec<u8>> {
    command
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .ok()?
        .ok()
        .filter(|out| out.status.success())
        .map(|out| out.stdout)
}

pub(super) async fn docker(progress: &Progress) -> CliResult<()> {
    let engine =
        Path::new("/usr/sbin/dockerd").is_file() || Path::new("/usr/bin/dockerd").is_file();
    let client = Path::new("/usr/bin/docker").is_file();
    let compose_ready = if client {
        probe(Command::new("/usr/bin/docker").args(["compose", "version", "--short"]))
            .await
            .is_some_and(|version| compose_v2(String::from_utf8_lossy(&version).trim()))
    } else {
        false
    };
    if !engine || !client || !compose_ready {
        let os = fs::read_to_string("/etc/os-release").map_err(io)?;
        let distribution = distribution(&os)?;
        progress
            .step(
                &format!("Checking software from {distribution}"),
                "Check this machine can reach its package servers, then run the same command again.",
                async {
                    run(
                        Command::new("/usr/bin/apt-get")
                            .arg("update")
                            .env("DEBIAN_FRONTEND", "noninteractive"),
                        "refresh distribution package list",
                    )
                    .await
                    .map(|_| ())
                },
            )
            .await?;
        let compose_package = if compose_ready {
            None
        } else {
            let mut found = None;
            for package in ["docker-compose-v2", "docker-compose"] {
                if let Some(output) = probe(Command::new("/usr/bin/apt-cache").args([
                    "show",
                    "--no-all-versions",
                    package,
                ]))
                .await
                    && String::from_utf8_lossy(&output)
                        .lines()
                        .filter_map(|line| line.strip_prefix("Version: "))
                        .any(compose_v2)
                {
                    found = Some(package);
                    break;
                }
            }
            Some(found.ok_or_else(|| failed(format!("{distribution}'s configured packages do not provide Docker's compose tool version 2 or later."))
                .hint("Use a supported Debian or Ubuntu release with that package in its distribution repositories; no third-party install script is run."))?)
        };
        let client_package = if !client
            && probe(Command::new("/usr/bin/apt-cache").args([
                "show",
                "--no-all-versions",
                "docker-cli",
            ]))
            .await
            .is_some_and(|output| !output.is_empty())
        {
            Some("docker-cli")
        } else {
            None
        };
        let packages = [
            (!engine).then_some("docker.io"),
            client_package,
            compose_package,
        ];
        let mut label = String::with_capacity(96);
        label.push_str("Installing Docker (");
        label.push_str(distribution);
        label.push_str(" packages: ");
        let mut separator = "";
        for package in packages.into_iter().flatten() {
            label.push_str(separator);
            label.push_str(package);
            separator = ", ";
        }
        label.push(')');
        progress.step(
            &label,
            "Check the package manager's configuration and internet connection, then run the same command again.",
            async {
                run(Command::new("/usr/bin/apt-get")
                    .args(["install", "--yes", "--no-install-recommends"])
                    .args(packages.into_iter().flatten())
                    .env("DEBIAN_FRONTEND", "noninteractive"), "install distribution Docker packages").await.map(|_| ())
            },
        ).await?;
    }
    progress
        .step(
            "Starting Docker",
            "Run systemctl status docker.service to see why Docker could not start.",
            async {
                run(
                    Command::new("/usr/bin/systemctl").args(["enable", "--now", "docker.service"]),
                    "start Docker",
                )
                .await?;
                Ok(())
            },
        )
        .await?;
    progress
        .step(
            "Checking Docker tools",
            "Install Docker's command-line tools from this machine's package repositories, then run the same command again.",
            super::platform(true),
        )
        .await
}

pub(super) async fn input(
    command: &mut Command,
    bytes: &[u8],
    operation: &str,
) -> CliResult<Vec<u8>> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|_| failed(format!("could not execute {operation}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| failed("could not open local command input"))?;
    tokio::time::timeout(Duration::from_secs(1800), async move {
        stdin.write_all(bytes).await.map_err(io)?;
        drop(stdin);
        let output = child.wait_with_output().await.map_err(io)?;
        if !output.status.success() {
            return Err(failed(format!(
                "{operation} failed ({}); rerun with --verbose for the operation name",
                output.status
            )));
        }
        Ok(output.stdout)
    })
    .await
    .map_err(|_| failed(format!("{operation} exceeded its deadline")))?
}

const DOMAIN_JOURNAL: &str = ".domain-change.json";

#[derive(Serialize, Deserialize)]
struct DomainChange {
    domain: String,
    previous_env: String,
}

pub(super) fn domain(root: &Path, installed: bool) -> CliResult<Option<String>> {
    if !installed {
        return Ok(None);
    }
    if super::present(&root.join(DOMAIN_JOURNAL))? {
        return Ok(Some(String::new()));
    }
    Ok(Some(
        read_managed(&root.join(".installer-domain"))?
            .trim()
            .to_owned(),
    ))
}

async fn start(root: &Path) -> CliResult<()> {
    run(
        compose(root).args(["up", "--no-build", "-d", "--wait", "--wait-timeout", "180"]),
        "start managed server",
    )
    .await?;
    run(
        compose(root).args([
            "exec",
            "-T",
            "grund",
            "/grund",
            "probe",
            "--address",
            "127.0.0.1:8080",
        ]),
        "check managed server readiness",
    )
    .await
    .map(|_| ())
}

pub(super) async fn recover_domain(root: &Path) -> CliResult<()> {
    if !super::present(&root.join(DOMAIN_JOURNAL))? {
        return Ok(());
    }
    let change: DomainChange = serde_json::from_str(&read_managed(&root.join(DOMAIN_JOURNAL))?)
        .map_err(|_| {
            failed("domain change recovery file is invalid; inspect it before retrying")
        })?;
    atomic_write(&root.join(".env"), change.previous_env.as_bytes(), 0o600)?;
    atomic_write(&root.join(".installer-domain"), b"\n", 0o600)?;
    start(root).await.map_err(|error| {
        error.hint(
            "The prior local configuration is restored. Start the managed server before retrying.",
        )
    })?;
    fs::remove_file(root.join(DOMAIN_JOURNAL)).map_err(io)?;
    fs::File::open(root)
        .and_then(|file| file.sync_all())
        .map_err(io)
}

fn domain_env(env: &str, domain: &str) -> String {
    let mut changed = String::with_capacity(env.len() + domain.len() * 2 + 64);
    for line in env
        .lines()
        .filter(|line| !line.starts_with("GRUND_DOMAIN=") && !line.starts_with("GRUND_PUBLIC_URL="))
    {
        changed.push_str(line);
        changed.push('\n');
    }
    changed.push_str(&format!(
        "GRUND_DOMAIN={domain}\nGRUND_PUBLIC_URL=https://{domain}\n"
    ));
    changed
}

pub(super) async fn convert_domain(root: &Path, domain: &str) -> CliResult<()> {
    let previous_env = read_managed(&root.join(".env"))?;
    let change = DomainChange {
        domain: domain.to_owned(),
        previous_env,
    };
    atomic_write(
        &root.join(DOMAIN_JOURNAL),
        &serde_json::to_vec(&change).map_err(|_| failed("could not save domain recovery state"))?,
        0o600,
    )?;
    atomic_write(
        &root.join(".env"),
        domain_env(&change.previous_env, domain).as_bytes(),
        0o600,
    )?;
    let result = async {
        start(root).await?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .resolve(domain, ([127, 0, 0, 1], 443).into())
            .build()
            .map_err(|_| failed("could not configure the HTTPS check"))?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
        let url = format!("https://{domain}/health/ready");
        loop {
            if let Ok(response) = client.get(&url).send().await
                && response.status().is_success()
            {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(failed("HTTPS was not ready.").hint(
                    "Point the domain at this machine and allow incoming port 443, then retry.",
                ));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        atomic_write(
            &root.join(".installer-domain"),
            format!("{domain}\n").as_bytes(),
            0o600,
        )?;
        fs::remove_file(root.join(DOMAIN_JOURNAL)).map_err(io)?;
        fs::File::open(root)
            .and_then(|file| file.sync_all())
            .map_err(io)
    }
    .await;
    if let Err(error) = result {
        if !super::present(&root.join(DOMAIN_JOURNAL))? {
            atomic_write(
                &root.join(DOMAIN_JOURNAL),
                &serde_json::to_vec(&change)
                    .map_err(|_| failed("could not save domain recovery state"))?,
                0o600,
            )?;
        }
        recover_domain(root).await?;
        return Err(error.hint("The local installation was restored. Check the domain points at this machine and port 443 is reachable, then retry."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_default_is_local_and_never_exposes_unencrypted_login() {
        let target = target(None, None, None).unwrap();
        assert!(target.server);
        assert_eq!(target.url, "http://localhost:8080");
        assert_eq!(target.domain, None);
        assert!(!target.convert);
    }

    #[test]
    fn default_reinstall_keeps_tls_and_only_a_local_install_can_gain_a_domain() {
        let existing = target(None, None, Some("grund.example.com")).unwrap();
        assert_eq!(existing.url, "https://grund.example.com");
        assert!(!existing.convert);
        let conversion = target(Some("grund.example.com"), None, Some("")).unwrap();
        assert!(conversion.convert);
        assert!(target(Some("other.example.com"), None, Some("grund.example.com")).is_err());
    }

    #[test]
    fn an_explicit_machine_target_still_requires_https() {
        assert!(target(None, Some("http://192.0.2.1:8080"), None).is_err());
        assert!(target(None, Some("https://user:password@grund.example.com"), None).is_err());
        let machine = target(None, Some("https://grund.example.com/"), None).unwrap();
        assert!(!machine.server);
        assert_eq!(machine.url, "https://grund.example.com");
    }

    #[test]
    fn a_remote_tunnel_uses_the_actual_server_address_port_and_login() {
        assert_eq!(
            tunnel(
                Some("198.51.100.2 53127 192.0.2.4 2222"),
                Some("kasper"),
                "debian-box"
            )
            .unwrap(),
            "ssh -p 2222 -L 8080:localhost:8080 kasper@192.0.2.4"
        );
        assert_eq!(
            tunnel(None, Some("root"), "debian-box").unwrap(),
            "ssh -L 8080:localhost:8080 root@debian-box"
        );
    }

    #[test]
    fn tunnel_output_never_turns_environment_text_into_shell_arguments() {
        assert!(tunnel(None, Some("root;touch /tmp/pwned"), "debian-box").is_err());
        assert!(tunnel(None, Some("root"), "host; touch /tmp/pwned").is_err());
        assert!(tunnel(Some("client 22 $(hostname) 22"), Some("root"), "debian-box").is_err());
    }

    #[test]
    fn compose_package_selection_refuses_v1_and_understands_debian_epochs() {
        assert!(!compose_v2("1.29.2-3"));
        assert!(compose_v2("2.26.1-4"));
        assert!(compose_v2("1:2.26.1-4ubuntu1"));
        assert!(!compose_v2("(none)"));
    }

    #[test]
    fn only_debian_and_ubuntu_may_install_distribution_packages() {
        assert_eq!(
            distribution("ID=debian\nVERSION_ID=13\n").unwrap(),
            "Debian"
        );
        assert_eq!(distribution("ID=\"ubuntu\"\n").unwrap(), "Ubuntu");
        assert!(distribution("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n").is_err());
    }
}
