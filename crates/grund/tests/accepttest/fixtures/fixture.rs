use std::{
    fs::File,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Context;

use super::client::{self, Origin};

pub const DEFAULT_DATABASE_URL: &str = "postgres://grund:grund@127.0.0.1:55410/grund";
pub const DEFAULT_NATS_URL: &str = "nats://127.0.0.1:54210";
pub const DEFAULT_SMTP_URL: &str = "smtp://127.0.0.1:51410";
pub const DEFAULT_MAILPIT_URL: &str = "http://127.0.0.1:58410";

pub struct Fixture {
    pub origin: Origin,
    pub mailpit: Option<Origin>,
    child: Option<Child>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

pub fn external_target() -> Option<String> {
    env("GRUND_ACCEPT_URL")
}

impl Fixture {
    pub async fn start() -> anyhow::Result<Self> {
        match external_target() {
            Some(url) => Self::attach(&url).await,
            None => Self::spawn(&[]).await,
        }
    }

    async fn attach(url: &str) -> anyhow::Result<Self> {
        let fixture = Self {
            origin: Origin::parse(url)?,
            mailpit: env("GRUND_ACCEPT_MAILPIT_URL")
                .map(|url| Origin::parse(&url))
                .transpose()?,
            child: None,
        };
        fixture.wait_until_live(None).await?;
        Ok(fixture)
    }

    pub async fn spawn(extra: &[(&str, &str)]) -> anyhow::Result<Self> {
        let port = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let log_path =
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("grund-{port}.log"));
        let log = File::create(&log_path)?;

        let public_url = format!("http://127.0.0.1:{port}");
        let database_url = env("GRUND_ACCEPT_DATABASE_URL").unwrap_or(DEFAULT_DATABASE_URL.into());
        let smtp_url = env("GRUND_ACCEPT_SMTP_URL").unwrap_or(DEFAULT_SMTP_URL.into());
        let mailpit_url = env("GRUND_ACCEPT_MAILPIT_URL").unwrap_or(DEFAULT_MAILPIT_URL.into());
        let secret_key = random_hex(32);

        let mut settings: Vec<(String, String)> = vec![
            ("GRUND_LISTEN".into(), format!("127.0.0.1:{port}")),
            ("GRUND_PUBLIC_URL".into(), public_url.clone()),
            ("DATABASE_URL".into(), database_url),
            ("GRUND_SECRET_KEY".into(), secret_key),
            ("GRUND_SMTP_URL".into(), smtp_url),
            ("GRUND_MAIL_FROM".into(), "grund <grund@accept.test>".into()),
            ("GRUND_HEALTH_INTERVAL".into(), "1".into()),
            ("GRUND_DATABASE_MAX_CONNECTIONS".into(), "4".into()),
            ("GRUND_WORK_POLL_INTERVAL".into(), "1".into()),
            (
                "RUST_LOG".into(),
                "grund=debug,grund_server=debug,grund_store=debug,warn".into(),
            ),
        ];
        if env("GRUND_ACCEPT_NO_NATS").is_none() {
            let nats = env("GRUND_ACCEPT_NATS_URL").unwrap_or(DEFAULT_NATS_URL.into());
            settings.push(("GRUND_NATS_URL".into(), nats));
        }
        for (name, value) in extra {
            settings.retain(|(key, _)| key != name);
            settings.push((name.to_string(), value.to_string()));
        }

        let mut command = Command::new(env!("CARGO_BIN_EXE_grund"));
        command
            .arg("serve")
            .env_clear()
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        for (name, value) in &settings {
            command.env(name, value);
        }

        let fixture = Self {
            origin: Origin::parse(&public_url)?,
            mailpit: Some(Origin::parse(&mailpit_url)?),
            child: Some(command.spawn().context("spawn grund")?),
        };
        fixture.wait_until_live(Some(&log_path)).await?;
        Ok(fixture)
    }

    async fn wait_until_live(&self, log: Option<&std::path::Path>) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let error = match client::send(&self.origin, "GET", "/health/ready", &[], None).await {
                Ok(response) if response.status == 200 => return Ok(()),
                Ok(response) => anyhow::anyhow!("status {}: {}", response.status, response.text()),
                Err(error) => error,
            };
            if Instant::now() > deadline {
                let log = log
                    .and_then(|path| std::fs::read_to_string(path).ok())
                    .unwrap_or_default();
                anyhow::bail!(
                    "{}/health/ready never answered 200: {error:#}\n\
                     (spawned instances need PostgreSQL at GRUND_ACCEPT_DATABASE_URL, default \
                     {DEFAULT_DATABASE_URL}: `docker compose -f compose.yaml -f compose.dev.yaml \
                     up -d postgres nats mailpit`)\n--- server log\n{log}",
                    self.origin.authority()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

pub fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).expect("randomness");
    buffer.iter().map(|b| format!("{b:02x}")).collect()
}
