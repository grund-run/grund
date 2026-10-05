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
    child: std::sync::Mutex<Option<Child>>,
    database: Option<(String, String)>,
    settings: Vec<(String, String)>,
    log_path: Option<std::path::PathBuf>,
    lab: Option<std::sync::Arc<super::netlab::Lab>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = self.child.get_mut().ok().and_then(Option::as_mut) {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some((admin, name)) = self.database.take() {
            let _ = std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                runtime.block_on(async {
                    let mut connection =
                        <sqlx::PgConnection as sqlx::Connection>::connect(&admin).await?;
                    sqlx::Executor::execute(
                        &mut connection,
                        sqlx::AssertSqlSafe(format!(
                            "DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"
                        )),
                    )
                    .await?;
                    Ok::<_, anyhow::Error>(())
                })
            })
            .join();
        }
    }
}

async fn fresh_database(admin: &str) -> anyhow::Result<(String, String)> {
    let name = format!("grund_accept_{}", random_hex(8));
    let mut connection = <sqlx::PgConnection as sqlx::Connection>::connect(admin)
        .await
        .with_context(|| format!("connect to GRUND_ACCEPT_DATABASE_URL ({admin})"))?;
    sqlx::Executor::execute(
        &mut connection,
        sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")),
    )
    .await?;
    let (base, _) = admin
        .rsplit_once('/')
        .context("GRUND_ACCEPT_DATABASE_URL has no database name")?;
    Ok((format!("{base}/{name}"), name))
}

async fn allow_connections(admin: &str, name: &str, allow: bool) -> anyhow::Result<()> {
    let mut connection = <sqlx::PgConnection as sqlx::Connection>::connect(admin).await?;
    sqlx::Executor::execute(
        &mut connection,
        sqlx::AssertSqlSafe(format!(
            "ALTER DATABASE \"{name}\" WITH ALLOW_CONNECTIONS {allow}"
        )),
    )
    .await?;
    Ok(())
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
            child: std::sync::Mutex::new(None),
            database: None,
            settings: Vec::new(),
            log_path: None,
            lab: None,
        };
        fixture.wait_until_live(None).await?;
        Ok(fixture)
    }

    pub async fn spawn(extra: &[(&str, &str)]) -> anyhow::Result<Self> {
        let fixture = Self::spawn_unwaited(extra, false).await?;
        fixture
            .wait_until_live(fixture.log_path.clone().as_deref())
            .await?;
        Ok(fixture)
    }

    pub async fn spawn_while_its_database_refuses(extra: &[(&str, &str)]) -> anyhow::Result<Self> {
        Self::spawn_unwaited(extra, true).await
    }

    async fn spawn_unwaited(extra: &[(&str, &str)], refusing: bool) -> anyhow::Result<Self> {
        let port = free_port();
        let log_path =
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("grund-{port}.log"));
        let log = File::create(&log_path)?;

        let public_url = format!("http://127.0.0.1:{port}");
        let admin_url = env("GRUND_ACCEPT_DATABASE_URL").unwrap_or(DEFAULT_DATABASE_URL.into());
        let (database_url, database_name) = fresh_database(&admin_url).await?;
        if refusing {
            allow_connections(&admin_url, &database_name, false).await?;
        }
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
            ("GRUND_DATABASE_ACQUIRE_TIMEOUT".into(), "30".into()),
            ("GRUND_WORK_POLL_INTERVAL".into(), "1".into()),
            ("GRUND_ORGANISATIONS".into(), "multi".into()),
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

        let child = serve(&settings, log)?;
        let fixture = Self {
            origin: Origin::parse(&public_url)?,
            mailpit: Some(Origin::parse(&mailpit_url)?),
            child: std::sync::Mutex::new(Some(child)),
            database: Some((admin_url, database_name)),
            settings,
            log_path: Some(log_path),
            lab: None,
        };
        Ok(fixture)
    }

    pub async fn database_accepts_connections(&self) -> anyhow::Result<()> {
        let (admin, name) = self
            .database
            .as_ref()
            .context("only a spawned instance has a database")?;
        allow_connections(admin, name, true).await
    }

    pub async fn becomes_ready_within(&self, within: Duration) -> anyhow::Result<Duration> {
        let started = Instant::now();
        loop {
            if let Ok(response) =
                client::send(&self.origin, "GET", "/health/ready", &[], None).await
                && response.status == 200
            {
                return Ok(started.elapsed());
            }
            anyhow::ensure!(
                started.elapsed() < within,
                "not ready within {within:?}:\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn spawn_in_lab(
        lab: std::sync::Arc<super::netlab::Lab>,
        extra: &[(&str, &str)],
    ) -> anyhow::Result<Self> {
        use super::netlab::{LIGHTHOUSE, PUBLIC_URL, RELAY_URL};
        let listen = "127.0.0.1:8080";
        let port = lab.front_door(listen)?;
        let admin_url = env("GRUND_ACCEPT_DATABASE_URL").unwrap_or(DEFAULT_DATABASE_URL.into());
        let (_, database_name) = fresh_database(&admin_url).await?;
        let mailpit_url = env("GRUND_ACCEPT_MAILPIT_URL").unwrap_or(DEFAULT_MAILPIT_URL.into());
        let (user, _) = admin_url
            .split_once("://")
            .and_then(|(_, rest)| rest.rsplit_once('@'))
            .context("GRUND_ACCEPT_DATABASE_URL has no user")?;
        let database_url = format!(
            "postgres://{user}@localhost/{database_name}?host={}",
            lab.work.join("pg").display()
        );
        let mut settings: Vec<(String, String)> = vec![
            ("GRUND_LISTEN".into(), listen.into()),
            ("GRUND_PUBLIC_URL".into(), PUBLIC_URL.into()),
            ("DATABASE_URL".into(), database_url),
            ("GRUND_SECRET_KEY".into(), random_hex(32)),
            ("GRUND_SMTP_URL".into(), "smtp://127.0.0.1:1025".into()),
            ("GRUND_MAIL_FROM".into(), "grund <grund@accept.test>".into()),
            ("GRUND_HEALTH_INTERVAL".into(), "1".into()),
            ("GRUND_DATABASE_MAX_CONNECTIONS".into(), "8".into()),
            ("GRUND_DATABASE_ACQUIRE_TIMEOUT".into(), "30".into()),
            ("GRUND_WORK_POLL_INTERVAL".into(), "1".into()),
            ("GRUND_ORGANISATIONS".into(), "multi".into()),
            ("GRUND_RELAY_ADDRESS".into(), format!("{LIGHTHOUSE}:8443")),
            ("GRUND_RELAY_URL".into(), RELAY_URL.into()),
            (
                "GRUND_RELAY_TLS_CERT_FILE".into(),
                lab.cert.to_string_lossy().into_owned(),
            ),
            (
                "GRUND_RELAY_TLS_KEY_FILE".into(),
                lab.key.to_string_lossy().into_owned(),
            ),
            (
                "GRUND_RELAY_QUIC_ADDRESS".into(),
                format!("{LIGHTHOUSE}:7842"),
            ),
            (
                "RUST_LOG".into(),
                "grund=debug,grund_server=debug,grund_net=debug,warn".into(),
            ),
        ];
        for (name, value) in extra {
            settings.retain(|(key, _)| key != name);
            if !value.is_empty() {
                settings.push((name.to_string(), value.to_string()));
            }
        }
        let env: Vec<(&str, &str)> = settings
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        lab.spawn("lh", &[grund_binary(), "serve"], &env, "grund.log")?;
        let mut origin = Origin::parse(PUBLIC_URL)?;
        origin.connect = Some(("127.0.0.1".into(), port));
        origin.roots = Some(std::sync::Arc::new(lab.roots()?));
        let log_path = lab.work.join("grund.log");
        let fixture = Self {
            origin,
            mailpit: Some(Origin::parse(&mailpit_url)?),
            child: std::sync::Mutex::new(None),
            database: Some((admin_url, database_name)),
            settings,
            log_path: None,
            lab: Some(lab),
        };
        fixture.wait_until_live(Some(&log_path)).await?;
        Ok(fixture)
    }

    pub async fn restart_with(&self, extra: &[(&str, &str)]) -> anyhow::Result<()> {
        let log_path = self
            .log_path
            .clone()
            .context("only a spawned instance can restart")?;
        let mut settings = self.settings.clone();
        for (name, value) in extra {
            settings.retain(|(key, _)| key != name);
            settings.push((name.to_string(), value.to_string()));
        }
        {
            let mut child = self.child.lock().unwrap();
            if let Some(mut running) = child.take() {
                let _ = running.kill();
                let _ = running.wait();
            }
            let log = std::fs::OpenOptions::new().append(true).open(&log_path)?;
            *child = Some(serve(&settings, log)?);
        }
        self.wait_until_live(Some(&log_path)).await
    }

    pub async fn down_for(&self, outage: Duration) -> anyhow::Result<()> {
        let log_path = self
            .log_path
            .clone()
            .context("only a spawned instance can stop")?;
        if let Some(mut running) = self.child.lock().unwrap().take() {
            let _ = running.kill();
            let _ = running.wait();
        }
        tokio::time::sleep(outage).await;
        {
            let log = std::fs::OpenOptions::new().append(true).open(&log_path)?;
            *self.child.lock().unwrap() = Some(serve(&self.settings, log)?);
        }
        self.wait_until_live(Some(&log_path)).await
    }

    pub async fn restart_in_lab(&self, extra: &[(&str, &str)]) -> anyhow::Result<()> {
        let lab = self
            .lab
            .clone()
            .context("only a lab instance restarts in the lab")?;
        let mut settings = self.settings.clone();
        for (name, value) in extra {
            settings.retain(|(key, _)| key != name);
            if !value.is_empty() {
                settings.push((name.to_string(), value.to_string()));
            }
        }
        lab.stop("grund.log");
        let env: Vec<(&str, &str)> = settings
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        lab.spawn("lh", &[grund_binary(), "serve"], &env, "grund.log")?;
        self.wait_until_live(Some(&lab.work.join("grund.log")))
            .await
    }

    pub async fn spawn_replica(&self, extra: &[(&str, &str)]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            self.lab.is_none(),
            "a replica is spawned beside a local instance"
        );
        let port = free_port();
        let log_path =
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("grund-{port}.log"));
        let log = File::create(&log_path)?;
        let mut settings = self.settings.clone();
        settings.retain(|(key, _)| key != "GRUND_LISTEN");
        settings.push(("GRUND_LISTEN".into(), format!("127.0.0.1:{port}")));
        for (name, value) in extra {
            settings.retain(|(key, _)| key != name);
            settings.push((name.to_string(), value.to_string()));
        }
        let child = serve(&settings, log)?;
        let replica = Self {
            origin: Origin::parse(&format!("http://127.0.0.1:{port}"))?,
            mailpit: self.mailpit.clone(),
            child: std::sync::Mutex::new(Some(child)),
            database: None,
            settings,
            log_path: Some(log_path.clone()),
            lab: None,
        };
        replica.wait_until_live(Some(&log_path)).await?;
        Ok(replica)
    }

    pub async fn running(&self, args: &[&str]) -> anyhow::Result<Ran> {
        self.running_with(args, &[]).await
    }

    pub async fn running_with(&self, args: &[&str], extra: &[(&str, &str)]) -> anyhow::Result<Ran> {
        anyhow::ensure!(
            self.lab.is_none() && self.log_path.is_some(),
            "commands run beside a spawned local instance"
        );
        let mut command = Command::new(grund_binary());
        command.args(args).env_clear();
        for (name, value) in &self.settings {
            if !extra.iter().any(|(key, _)| key == name) {
                command.env(name, value);
            }
        }
        for (name, value) in extra {
            command.env(name, value);
        }
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::task::spawn_blocking(move || command.output()),
        )
        .await
        .with_context(|| format!("grund {args:?} did not finish within 30 s"))???;
        Ok(Ran {
            success: output.status.success(),
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    pub async fn setup_link(&self) -> anyhow::Result<String> {
        let ran = self.running(&["setup-link"]).await?;
        anyhow::ensure!(ran.success, "grund setup-link failed: {}", ran.stderr);
        ran.setup_link_path()
            .with_context(|| format!("grund setup-link printed no link:\n{}", ran.stdout))
    }

    pub async fn sql(&self, statement: &str) -> anyhow::Result<u64> {
        let url = self
            .database_url()
            .context("only a spawned instance has a database")?;
        let mut connection = <sqlx::PgConnection as sqlx::Connection>::connect(&url).await?;
        Ok(
            sqlx::Executor::execute(&mut connection, sqlx::AssertSqlSafe(statement.to_string()))
                .await?
                .rows_affected(),
        )
    }

    pub async fn count(&self, query: &str) -> anyhow::Result<i64> {
        let url = self
            .database_url()
            .context("only a spawned instance has a database")?;
        let mut connection = <sqlx::PgConnection as sqlx::Connection>::connect(&url).await?;
        Ok(
            sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(query.to_string()))
                .fetch_one(&mut connection)
                .await?,
        )
    }

    pub async fn database_away_for(&self, outage: Duration) -> anyhow::Result<()> {
        let (admin, name) = self
            .database
            .as_ref()
            .context("only a spawned instance has a database")?;
        let mut connection = <sqlx::PgConnection as sqlx::Connection>::connect(admin).await?;
        let mut run = async |statement: String| {
            sqlx::Executor::execute(&mut connection, sqlx::AssertSqlSafe(statement)).await
        };
        run(format!(
            "ALTER DATABASE \"{name}\" WITH ALLOW_CONNECTIONS false"
        ))
        .await?;
        let terminate = format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'"
        );
        let back = Instant::now() + outage;
        while Instant::now() < back {
            run(terminate.clone()).await?;
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        run(format!(
            "ALTER DATABASE \"{name}\" WITH ALLOW_CONNECTIONS true"
        ))
        .await?;
        Ok(())
    }

    pub fn log(&self) -> String {
        self.log_path
            .as_ref()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .unwrap_or_default()
    }

    pub fn is_running(&self) -> bool {
        self.child
            .lock()
            .unwrap()
            .as_mut()
            .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
    }

    pub fn database_url(&self) -> Option<String> {
        let (admin, name) = self.database.as_ref()?;
        let (base, _) = admin.rsplit_once('/')?;
        Some(format!("{base}/{name}"))
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

pub struct Ran {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Ran {
    pub fn line(&self, status: &str, check: &str) -> Option<String> {
        self.stdout
            .lines()
            .find(|line| {
                let mut words = line.split_whitespace();
                words.next() == Some(status) && words.next() == Some(check)
            })
            .map(str::to_string)
    }

    pub fn setup_link_path(&self) -> Option<String> {
        self.stdout
            .split_whitespace()
            .find(|word| word.contains("/signup/owner?token=grund_setup_"))
            .and_then(|url| url.find("/signup/owner").map(|at| url[at..].to_string()))
    }
}

fn serve(settings: &[(String, String)], log: File) -> anyhow::Result<Child> {
    let mut command = Command::new(grund_binary());
    command
        .arg("serve")
        .env_clear()
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    for (name, value) in settings {
        command.env(name, value);
    }
    command.spawn().context("spawn grund")
}

pub async fn refused_at_start(extra: &[(&str, &str)]) -> anyhow::Result<String> {
    let mut command = Command::new(grund_binary());
    command
        .arg("serve")
        .env_clear()
        .env("DATABASE_URL", "postgres://grund@127.0.0.1:1/unreachable")
        .env("GRUND_SECRET_KEY", random_hex(32))
        .env("GRUND_LISTEN", "127.0.0.1:0")
        .env("GRUND_DATABASE_WAIT", "0");
    for (name, value) in extra {
        command.env(name, value);
    }
    let output = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::task::spawn_blocking(move || command.output()),
    )
    .await
    .context("grund neither started nor refused within 20 s")???;
    anyhow::ensure!(
        !output.status.success(),
        "grund was expected to refuse {extra:?}, and exited successfully"
    );
    Ok(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

pub fn grund_binary() -> &'static str {
    static BINARY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    BINARY.get_or_init(|| {
        std::env::var("GRUND_ACCEPT_GRUND_BIN")
            .ok()
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_grund").to_string())
    })
}

fn port_block() -> u32 {
    static BLOCK: std::sync::OnceLock<(u32, std::net::TcpListener)> = std::sync::OnceLock::new();
    BLOCK
        .get_or_init(|| {
            let first = std::process::id() % 24;
            (0..24)
                .map(|step| (first + step) % 24)
                .find_map(|block| {
                    let base = u16::try_from(20_000 + block * 500).expect("below 32000");
                    std::net::TcpListener::bind(("127.0.0.1", base))
                        .ok()
                        .map(|claim| (block, claim))
                })
                .expect("every port block is claimed by another test binary")
        })
        .0
}

pub fn free_port() -> u16 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    let base = 20_000 + port_block() * 500;
    loop {
        let offset = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        assert!(offset < 500, "this test binary ran out of its 499 ports");
        let port = u16::try_from(base + offset).expect("below 32000");
        let free = ["127.0.0.1:", "0.0.0.0:"].iter().all(|host| {
            std::net::TcpListener::bind(format!("{host}{port}")).is_ok()
                && std::net::UdpSocket::bind(format!("{host}{port}")).is_ok()
        });
        if free {
            return port;
        }
    }
}

pub fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer).expect("randomness");
    buffer.iter().map(|b| format!("{b:02x}")).collect()
}
