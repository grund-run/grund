//! Configuration for `grund serve` and `grund migrate`.
//!
//! Every knob is a flag and an environment variable, and `--help` is the
//! reference. `validated()` refuses a configuration that would run insecurely
//! or not at all, and every refusal names the variable to fix.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::Args;

/// Where PostgreSQL is. Shared by `serve` and `migrate`.
#[derive(Clone, Debug, Args)]
pub struct DatabaseArgs {
    /// PostgreSQL connection URL. The password may be left out and read from
    /// GRUND_DATABASE_PASSWORD_FILE instead, which is what compose.yaml does.
    #[arg(long, env = "DATABASE_URL")]
    pub database_url: String,

    /// A file holding the database password (trailing newline ignored). Wins
    /// over a password in DATABASE_URL.
    #[arg(long, env = "GRUND_DATABASE_PASSWORD_FILE")]
    pub database_password_file: Option<PathBuf>,

    /// Pool size. Each request holds a connection only for its statements; the
    /// projection runner holds two. At least 4.
    #[arg(long, env = "GRUND_DATABASE_MAX_CONNECTIONS", default_value_t = 10)]
    pub database_max_connections: u32,

    /// How long a request waits for a pooled connection before failing with
    /// 503 instead of queueing without bound.
    #[arg(long, env = "GRUND_DATABASE_ACQUIRE_TIMEOUT", value_parser = secs, default_value = "5")]
    pub database_acquire_timeout: Duration,

    /// Upper bound on any one statement, set per connection. A statement near
    /// this is a bug or an outage, not a slow page.
    #[arg(long, env = "GRUND_DATABASE_STATEMENT_TIMEOUT", value_parser = secs, default_value = "10")]
    pub database_statement_timeout: Duration,
}

impl DatabaseArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.database_url.starts_with("postgres://")
                || self.database_url.starts_with("postgresql://"),
            "DATABASE_URL must be a postgres:// URL"
        );
        anyhow::ensure!(
            self.database_max_connections >= 4,
            "GRUND_DATABASE_MAX_CONNECTIONS must be at least 4: the projection runner alone holds 2"
        );
        anyhow::ensure!(
            !self.database_acquire_timeout.is_zero() && !self.database_statement_timeout.is_zero(),
            "GRUND_DATABASE_ACQUIRE_TIMEOUT and GRUND_DATABASE_STATEMENT_TIMEOUT must be positive"
        );
        Ok(())
    }
}

/// How an instance hands out organisations (GRUND_ORGANISATIONS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OrganisationMode {
    /// One organisation for the whole instance.
    Single,
    /// An organisation per sign-up, and more on request.
    Multi,
}

/// `grund serve`: the control plane (dashboard, API, background work).
#[derive(Clone, Debug, Args)]
pub struct ServeConfig {
    #[command(flatten)]
    pub database: DatabaseArgs,

    /// Where the HTTP server binds. The image sets 0.0.0.0:8080.
    #[arg(long, env = "GRUND_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,

    /// The origin people reach grund at, e.g. https://app.grund.sh. Links in
    /// mail point here, cookies are scoped to it, and a form posted from any
    /// other origin is refused. Plain http only for loopback, unless
    /// GRUND_DEV_MODE is on.
    #[arg(
        long,
        env = "GRUND_PUBLIC_URL",
        default_value = "http://localhost:8080"
    )]
    pub public_url: String,

    /// Development mode: allows plain http on a non-loopback public URL and
    /// generates a throwaway secret key when none is configured (every restart
    /// then signs everyone out). Never for an instance people depend on.
    #[arg(long, env = "GRUND_DEV_MODE", default_value_t = false, action = clap::ArgAction::Set)]
    pub dev_mode: bool,

    /// 32 random bytes as 64 hex characters. Keys CSRF tokens and the digests
    /// that keep raw addresses out of rate-limit tables. Prefer
    /// GRUND_SECRET_KEY_FILE, which `grund init` writes.
    #[arg(long, env = "GRUND_SECRET_KEY", hide_env_values = true)]
    pub secret_key: Option<String>,

    /// A file holding the secret key, as GRUND_SECRET_KEY.
    #[arg(long, env = "GRUND_SECRET_KEY_FILE")]
    pub secret_key_file: Option<PathBuf>,

    /// NATS server for wake-ups (e.g. nats://nats:4222). Optional: without it,
    /// background work is found by polling every GRUND_WORK_POLL_INTERVAL. When
    /// set, grund refuses to start if it cannot connect.
    #[arg(long, env = "GRUND_NATS_URL")]
    pub nats_url: Option<String>,

    /// A NATS credentials file (JWT + nkey), for servers that require one.
    #[arg(long, env = "GRUND_NATS_CREDS_FILE")]
    pub nats_creds_file: Option<PathBuf>,

    /// Prefix for every subject grund publishes. Unique per instance and
    /// environment, so two instances sharing one NATS never wake each other.
    #[arg(long, env = "GRUND_NATS_SUBJECT_PREFIX", default_value = "grund")]
    pub nats_subject_prefix: String,

    /// Backstop for background work (mail, cleanup) when no wake-up arrives.
    /// NATS makes work start sooner; this makes it start at all.
    #[arg(long, env = "GRUND_WORK_POLL_INTERVAL", value_parser = secs, default_value = "5")]
    pub work_poll_interval: Duration,

    /// SMTP server for mail, e.g. smtp://mailpit:1025 (plain, local only),
    /// smtp://user:pass@host:587?tls=required (STARTTLS) or
    /// smtps://user:pass@host:465. Unset: mail waits in the outbox and
    /// readiness says so.
    #[arg(long, env = "GRUND_SMTP_URL", hide_env_values = true)]
    pub smtp_url: Option<String>,

    /// The From address of every mail grund sends.
    #[arg(
        long,
        env = "GRUND_MAIL_FROM",
        default_value = "grund <grund@localhost>"
    )]
    pub mail_from: String,

    /// How the instance hands out organisations. `single` (the default, for
    /// self-hosting): one organisation, created with the first account, which
    /// owns it; everyone after that joins by invitation. `multi` (grund's
    /// hosted instance): every sign-up gets an organisation named after it,
    /// and anyone signed in may create more.
    #[arg(
        long,
        env = "GRUND_ORGANISATIONS",
        value_enum,
        default_value = "single"
    )]
    pub organisations: OrganisationMode,

    /// Whether sign-up without an invitation is open at all. Off, only
    /// invitations create accounts (and, in `single` mode, the first
    /// account cannot be created: leave it on until the admin exists).
    #[arg(long, env = "GRUND_SIGNUP_ENABLED", default_value_t = true, action = clap::ArgAction::Set)]
    pub signup_enabled: bool,

    /// How many reverse proxies in front of grund append to X-Forwarded-For.
    /// 0 trusts no header and uses the connecting address. Set it to exactly
    /// the number of proxies you run: one more lets any client choose the
    /// address its requests are limited under.
    #[arg(long, env = "GRUND_TRUSTED_PROXY_HOPS", default_value_t = 0)]
    pub trusted_proxy_hops: u8,

    /// Failed sign-ins allowed per account name per 15 minutes before that
    /// name is locked for the rest of the window. Counted for names that do
    /// not exist too, so a lockout tells nobody whether an account exists.
    #[arg(long, env = "GRUND_LOGIN_FAILURES_PER_ACCOUNT", default_value_t = 10)]
    pub login_failures_per_account: u32,

    /// Sign-in attempts allowed per client address per 15 minutes; 0 turns
    /// the per-address limit off. Only meaningful when the real client
    /// address reaches grund (see GRUND_TRUSTED_PROXY_HOPS).
    #[arg(long, env = "GRUND_LOGIN_ATTEMPTS_PER_ADDRESS", default_value_t = 100)]
    pub login_attempts_per_address: u32,

    /// Password-reset and verification mails allowed per address per hour.
    #[arg(long, env = "GRUND_MAIL_REQUESTS_PER_EMAIL", default_value_t = 3)]
    pub mail_requests_per_email: u32,

    /// Sign-up, reset and resend requests allowed per client address per hour;
    /// 0 turns the per-address limit off.
    #[arg(long, env = "GRUND_MAIL_REQUESTS_PER_ADDRESS", default_value_t = 20)]
    pub mail_requests_per_address: u32,

    /// A session ends after this long without a request.
    #[arg(long, env = "GRUND_SESSION_IDLE_TIMEOUT", value_parser = hours, default_value = "168")]
    pub session_idle_timeout: Duration,

    /// A session ends this long after sign-in, however active it is.
    #[arg(long, env = "GRUND_SESSION_MAX_AGE", value_parser = hours, default_value = "720")]
    pub session_max_age: Duration,

    /// A grund license key. Unlocks commercial features such as social
    /// sign-in. Without one grund runs every free feature.
    #[arg(long, env = "GRUND_LICENSE_KEY", hide_env_values = true)]
    pub license_key: Option<String>,

    /// A file holding the license key.
    #[arg(long, env = "GRUND_LICENSE_KEY_FILE")]
    pub license_key_file: Option<PathBuf>,

    #[command(flatten)]
    pub social: SocialArgs,

    #[command(flatten)]
    pub insights: InsightsArgs,

    /// Upper bound on one request. Sign-in hashes a password (~50 ms), so
    /// anything near this is a stuck dependency, not slow work.
    #[arg(long, env = "GRUND_REQUEST_TIMEOUT", value_parser = secs, default_value = "15")]
    pub request_timeout: Duration,

    /// How often readiness re-checks its dependencies.
    #[arg(long, env = "GRUND_HEALTH_INTERVAL", value_parser = secs, default_value = "5")]
    pub health_interval: Duration,

    /// How long in-flight work gets to finish after SIGTERM. Must stay inside
    /// the kubelet's terminationGracePeriodSeconds (30 s by default).
    #[arg(long, env = "GRUND_SHUTDOWN_GRACE", value_parser = secs, default_value = "10")]
    pub shutdown_grace: Duration,
}

/// Social sign-in providers. A commercial feature: configuring one does
/// nothing unless the license allows it (see `Entitlements`).
#[derive(Clone, Debug, Default, Args)]
pub struct SocialArgs {
    /// Offer social sign-in. Needs a license that includes it; without one
    /// grund starts, logs why, and offers password sign-in only.
    #[arg(long, env = "GRUND_SOCIAL_LOGIN", default_value_t = false, action = clap::ArgAction::Set)]
    pub social_login: bool,

    /// GitHub OAuth app client id. Set with GRUND_GITHUB_CLIENT_SECRET.
    #[arg(long, env = "GRUND_GITHUB_CLIENT_ID")]
    pub github_client_id: Option<String>,

    #[arg(long, env = "GRUND_GITHUB_CLIENT_SECRET", hide_env_values = true)]
    pub github_client_secret: Option<String>,

    /// Google OAuth client id. Set with GRUND_GOOGLE_CLIENT_SECRET.
    #[arg(long, env = "GRUND_GOOGLE_CLIENT_ID")]
    pub google_client_id: Option<String>,

    #[arg(long, env = "GRUND_GOOGLE_CLIENT_SECRET", hide_env_values = true)]
    pub google_client_secret: Option<String>,

    /// Any OpenID Connect provider, by issuer URL (discovery is read from
    /// <issuer>/.well-known/openid-configuration). Set with
    /// GRUND_OIDC_CLIENT_ID, GRUND_OIDC_CLIENT_SECRET and GRUND_OIDC_NAME.
    #[arg(long, env = "GRUND_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,

    #[arg(long, env = "GRUND_OIDC_CLIENT_ID")]
    pub oidc_client_id: Option<String>,

    #[arg(long, env = "GRUND_OIDC_CLIENT_SECRET", hide_env_values = true)]
    pub oidc_client_secret: Option<String>,

    /// The button label for the OIDC provider, e.g. "Company SSO".
    #[arg(long, env = "GRUND_OIDC_NAME", default_value = "Single sign-on")]
    pub oidc_name: String,
}

/// Reporting new accounts to a grund insights service, for the people who
/// operate this instance. Off unless both settings are present: an instance
/// without them sends nothing anywhere and queues nothing.
#[derive(Clone, Debug, Default, Args)]
pub struct InsightsArgs {
    /// The insights ingest endpoint, e.g. http://insights:8081. Once an
    /// account's address is confirmed, grund sends its username, address,
    /// sign-in method and the two times to `<url>/v1/accounts`, from the
    /// outbox, at least once. Set with GRUND_INSIGHTS_TOKEN.
    #[arg(long, env = "GRUND_INSIGHTS_URL")]
    pub insights_url: Option<String>,

    /// The bearer token that insights expects (its INSIGHTS_INGEST_TOKEN), at
    /// least 32 printable ASCII characters.
    #[arg(long, env = "GRUND_INSIGHTS_TOKEN", hide_env_values = true)]
    pub insights_token: Option<String>,
}

impl InsightsArgs {
    /// Whether accounts are reported.
    pub fn enabled(&self) -> bool {
        self.insights_url.is_some() && self.insights_token.is_some()
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.insights_url.is_some() == self.insights_token.is_some(),
            "GRUND_INSIGHTS_URL and GRUND_INSIGHTS_TOKEN must be set together"
        );
        if let Some(url) = &self.insights_url {
            anyhow::ensure!(
                (url.starts_with("http://") || url.starts_with("https://"))
                    && !url.ends_with('/')
                    && !url.contains(['?', '#']),
                "GRUND_INSIGHTS_URL must be an http or https URL without a trailing slash"
            );
        }
        if let Some(token) = &self.insights_token {
            anyhow::ensure!(
                token.len() >= 32 && token.bytes().all(|b| b.is_ascii_graphic()),
                "GRUND_INSIGHTS_TOKEN must be at least 32 printable ASCII characters"
            );
        }
        Ok(())
    }
}

const PLACEHOLDERS: &[&str] = &["change-me", "changeme", "replace-me"];

impl ServeConfig {
    /// Refuses configuration that would run insecurely or not at all. Every
    /// message names the variable to fix. An optional setting that is present
    /// but empty (an uncommented `GRUND_LICENSE_KEY=` in .env) counts as unset,
    /// and a secret containing a placeholder from the examples is refused
    /// outside dev mode.
    pub fn validate(&mut self) -> anyhow::Result<()> {
        for value in [
            &mut self.secret_key,
            &mut self.nats_url,
            &mut self.smtp_url,
            &mut self.license_key,
            &mut self.social.github_client_id,
            &mut self.social.github_client_secret,
            &mut self.social.google_client_id,
            &mut self.social.google_client_secret,
            &mut self.social.oidc_issuer,
            &mut self.social.oidc_client_id,
            &mut self.social.oidc_client_secret,
            &mut self.insights.insights_url,
            &mut self.insights.insights_token,
        ] {
            if value.as_deref().is_some_and(|v| v.trim().is_empty()) {
                *value = None;
            }
        }
        self.database.validate()?;

        let origin = PublicOrigin::parse(&self.public_url).ok_or_else(|| {
            anyhow::anyhow!(
                "GRUND_PUBLIC_URL must be an origin like https://app.example.com: a scheme and \
                 host, an optional port, no path or trailing slash; got {:?}",
                self.public_url
            )
        })?;
        anyhow::ensure!(
            origin.https || origin.is_loopback() || self.dev_mode,
            "GRUND_PUBLIC_URL is plain http on {:?}: session cookies would cross the network \
             unencrypted. Put TLS in front and use https, use localhost, or set GRUND_DEV_MODE=true",
            origin.host
        );

        anyhow::ensure!(
            !(self.secret_key.is_some() && self.secret_key_file.is_some()),
            "set GRUND_SECRET_KEY or GRUND_SECRET_KEY_FILE, not both"
        );
        anyhow::ensure!(
            self.secret_key.is_some() || self.secret_key_file.is_some() || self.dev_mode,
            "no secret key: set GRUND_SECRET_KEY_FILE (written by `grund init`) or \
             GRUND_SECRET_KEY (64 hex characters, e.g. `openssl rand -hex 32`)"
        );
        anyhow::ensure!(
            !(self.license_key.is_some() && self.license_key_file.is_some()),
            "set GRUND_LICENSE_KEY or GRUND_LICENSE_KEY_FILE, not both"
        );

        if !self.dev_mode {
            for (name, value) in [
                ("DATABASE_URL", Some(self.database.database_url.as_str())),
                ("GRUND_SECRET_KEY", self.secret_key.as_deref()),
                ("GRUND_SMTP_URL", self.smtp_url.as_deref()),
                (
                    "GRUND_GITHUB_CLIENT_SECRET",
                    self.social.github_client_secret.as_deref(),
                ),
                (
                    "GRUND_GOOGLE_CLIENT_SECRET",
                    self.social.google_client_secret.as_deref(),
                ),
                (
                    "GRUND_OIDC_CLIENT_SECRET",
                    self.social.oidc_client_secret.as_deref(),
                ),
                (
                    "GRUND_INSIGHTS_TOKEN",
                    self.insights.insights_token.as_deref(),
                ),
            ] {
                if let Some(value) = value {
                    let lower = value.to_ascii_lowercase();
                    anyhow::ensure!(
                        !PLACEHOLDERS.iter().any(|p| lower.contains(p)),
                        "{name} still holds a placeholder from the example configuration; \
                         generate a real value"
                    );
                }
            }
        }

        if let Some(url) = &self.smtp_url {
            anyhow::ensure!(
                url.starts_with("smtp://") || url.starts_with("smtps://"),
                "GRUND_SMTP_URL must start with smtp:// or smtps://"
            );
        }
        anyhow::ensure!(
            self.mail_from.contains('@'),
            "GRUND_MAIL_FROM must be a mail address, optionally with a name: \"grund <grund@example.com>\""
        );
        anyhow::ensure!(
            !self.nats_subject_prefix.is_empty()
                && self
                    .nats_subject_prefix
                    .split('.')
                    .all(|token| !token.is_empty()
                        && token
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')),
            "GRUND_NATS_SUBJECT_PREFIX must be dot-separated tokens of [A-Za-z0-9_-]"
        );
        anyhow::ensure!(
            self.nats_url.is_some() || self.nats_creds_file.is_none(),
            "GRUND_NATS_CREDS_FILE is set but GRUND_NATS_URL is not"
        );
        anyhow::ensure!(
            self.trusted_proxy_hops <= 5,
            "GRUND_TRUSTED_PROXY_HOPS must be at most 5"
        );
        anyhow::ensure!(
            self.login_failures_per_account >= 3,
            "GRUND_LOGIN_FAILURES_PER_ACCOUNT must be at least 3, or a typo locks its owner out"
        );
        anyhow::ensure!(
            self.mail_requests_per_email >= 1,
            "GRUND_MAIL_REQUESTS_PER_EMAIL must be at least 1"
        );
        anyhow::ensure!(
            self.session_idle_timeout <= self.session_max_age
                && self.session_idle_timeout >= Duration::from_secs(3600),
            "GRUND_SESSION_IDLE_TIMEOUT must be at least 1 hour and at most GRUND_SESSION_MAX_AGE"
        );
        anyhow::ensure!(
            self.session_max_age <= Duration::from_secs(90 * 24 * 3600),
            "GRUND_SESSION_MAX_AGE must be at most 2160 hours (90 days)"
        );
        anyhow::ensure!(
            !self.work_poll_interval.is_zero()
                && self.work_poll_interval <= Duration::from_secs(60),
            "GRUND_WORK_POLL_INTERVAL must be between 1 and 60 seconds"
        );
        anyhow::ensure!(
            !self.health_interval.is_zero() && self.health_interval <= Duration::from_secs(60),
            "GRUND_HEALTH_INTERVAL must be between 1 and 60 seconds"
        );
        anyhow::ensure!(
            !self.request_timeout.is_zero(),
            "GRUND_REQUEST_TIMEOUT must be positive"
        );
        anyhow::ensure!(
            self.shutdown_grace <= Duration::from_secs(30),
            "GRUND_SHUTDOWN_GRACE must be at most 30 s, the kubelet's default grace period"
        );
        self.social.validate()?;
        self.insights.validate()?;
        Ok(())
    }

    pub fn public_origin(&self) -> PublicOrigin {
        PublicOrigin::parse(&self.public_url).expect("validated at startup")
    }
}

impl SocialArgs {
    fn validate(&self) -> anyhow::Result<()> {
        for (id_name, id, secret_name, secret) in [
            (
                "GRUND_GITHUB_CLIENT_ID",
                &self.github_client_id,
                "GRUND_GITHUB_CLIENT_SECRET",
                &self.github_client_secret,
            ),
            (
                "GRUND_GOOGLE_CLIENT_ID",
                &self.google_client_id,
                "GRUND_GOOGLE_CLIENT_SECRET",
                &self.google_client_secret,
            ),
            (
                "GRUND_OIDC_CLIENT_ID",
                &self.oidc_client_id,
                "GRUND_OIDC_CLIENT_SECRET",
                &self.oidc_client_secret,
            ),
        ] {
            anyhow::ensure!(
                id.is_some() == secret.is_some(),
                "{id_name} and {secret_name} must be set together"
            );
        }
        anyhow::ensure!(
            self.oidc_issuer.is_some() == self.oidc_client_id.is_some(),
            "GRUND_OIDC_ISSUER and GRUND_OIDC_CLIENT_ID must be set together"
        );
        if let Some(issuer) = &self.oidc_issuer {
            anyhow::ensure!(
                issuer.starts_with("https://") && !issuer.ends_with('/'),
                "GRUND_OIDC_ISSUER must be an https URL without a trailing slash"
            );
        }
        anyhow::ensure!(
            !self.social_login
                || self.github_client_id.is_some()
                || self.google_client_id.is_some()
                || self.oidc_client_id.is_some(),
            "GRUND_SOCIAL_LOGIN is on but no provider is configured: set GRUND_GITHUB_CLIENT_ID, \
             GRUND_GOOGLE_CLIENT_ID or GRUND_OIDC_ISSUER"
        );
        Ok(())
    }
}

/// The validated public origin: scheme, host and port, nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicOrigin {
    pub https: bool,
    pub host: String,
    /// The origin exactly as a browser sends it in `Origin`.
    pub serialized: String,
}

impl PublicOrigin {
    pub fn parse(url: &str) -> Option<Self> {
        let (scheme, authority) = url.split_once("://")?;
        let https = match scheme {
            "https" => true,
            "http" => false,
            _ => return None,
        };
        if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
            return None;
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port.parse::<u16>().ok()?)),
            None => (authority, None),
        };
        let host = host.to_ascii_lowercase();
        if !is_hostname(&host) {
            return None;
        }
        let default_port = if https { 443 } else { 80 };
        let serialized = match port {
            Some(port) if port != default_port => format!("{scheme}://{host}:{port}"),
            _ => format!("{scheme}://{host}"),
        };
        Some(Self {
            https,
            host,
            serialized,
        })
    }

    pub fn is_loopback(&self) -> bool {
        self.host == "localhost" || self.host == "127.0.0.1" || self.host.ends_with(".localhost")
    }
}

fn is_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

pub fn secs(s: &str) -> Result<Duration, String> {
    s.parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|e| e.to_string())
}

fn hours(s: &str) -> Result<Duration, String> {
    s.parse::<u64>()
        .map(|h| Duration::from_secs(h * 3600))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::*;

    #[derive(Parser)]
    struct Harness {
        #[command(flatten)]
        serve: ServeConfig,
    }

    fn parse(args: &[&str]) -> anyhow::Result<ServeConfig> {
        let base = [
            "grund",
            "--database-url",
            "postgres://grund@localhost/grund",
            "--secret-key-file",
            "/tmp/key",
        ];
        let mut config = Harness::try_parse_from(base.iter().chain(args).copied())?.serve;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn the_command_definition_is_internally_consistent() {
        Harness::command().debug_assert();
    }

    #[test]
    fn defaults_with_a_database_and_a_key_are_a_valid_local_instance() {
        let config = parse(&[]).unwrap();
        assert_eq!(config.public_origin().serialized, "http://localhost:8080");
        assert!(config.signup_enabled);
        assert!(!config.social.social_login);
        assert!(!config.insights.enabled(), "nothing is reported by default");
    }

    #[test]
    fn plain_http_on_a_network_address_is_refused_outside_dev_mode() {
        let error = parse(&["--public-url", "http://192.168.1.10:8080"]).unwrap_err();
        assert!(error.to_string().contains("GRUND_PUBLIC_URL"), "{error}");
        assert!(
            parse(&[
                "--public-url",
                "http://192.168.1.10:8080",
                "--dev-mode",
                "true"
            ])
            .is_ok()
        );
        assert!(parse(&["--public-url", "https://app.example.com"]).is_ok());
    }

    #[test]
    fn a_public_url_with_a_path_or_trailing_slash_is_refused() {
        for url in [
            "https://app.example.com/",
            "https://app.example.com/x",
            "app.example.com",
            "ftp://x",
        ] {
            let error = parse(&["--public-url", url]).unwrap_err().to_string();
            assert!(error.contains("GRUND_PUBLIC_URL"), "{url}: {error}");
        }
    }

    #[test]
    fn the_default_port_is_left_out_of_the_origin_browsers_compare_against() {
        let origin = PublicOrigin::parse("https://app.example.com:443").unwrap();
        assert_eq!(origin.serialized, "https://app.example.com");
        let origin = PublicOrigin::parse("http://localhost:8080").unwrap();
        assert_eq!(origin.serialized, "http://localhost:8080");
    }

    #[test]
    fn starting_without_any_secret_key_is_refused_outside_dev_mode() {
        let mut config = Harness::try_parse_from([
            "grund",
            "--database-url",
            "postgres://grund@localhost/grund",
        ])
        .unwrap()
        .serve;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("GRUND_SECRET_KEY_FILE"), "{error}");
        config.dev_mode = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_placeholder_secret_is_refused_outside_dev_mode() {
        let error = parse(&["--smtp-url", "smtp://grund:change-me@mail.example.com:587"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("GRUND_SMTP_URL"), "{error}");
        let error = parse(&["--database-url", "postgres://grund:changeme@db/grund"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("DATABASE_URL"), "{error}");
    }

    #[test]
    fn an_empty_optional_setting_counts_as_unset() {
        let config = parse(&["--license-key", "", "--nats-url", " "]).unwrap();
        assert!(config.license_key.is_none());
        assert!(config.nats_url.is_none());
    }

    #[test]
    fn a_social_provider_needs_its_id_and_secret_together() {
        let error = parse(&["--github-client-id", "abc"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("GRUND_GITHUB_CLIENT_SECRET"), "{error}");
    }

    #[test]
    fn insights_needs_its_url_and_token_together_and_a_long_token() {
        let token = "0123456789abcdef0123456789abcdef";
        let error = parse(&["--insights-url", "http://insights:8081"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("GRUND_INSIGHTS_TOKEN"), "{error}");
        let error = parse(&["--insights-token", token]).unwrap_err().to_string();
        assert!(error.contains("GRUND_INSIGHTS_URL"), "{error}");
        let error = parse(&[
            "--insights-url",
            "http://insights:8081",
            "--insights-token",
            "short",
        ])
        .unwrap_err()
        .to_string();
        assert!(error.contains("at least 32"), "{error}");
        let error = parse(&[
            "--insights-url",
            "insights:8081/",
            "--insights-token",
            token,
        ])
        .unwrap_err()
        .to_string();
        assert!(error.contains("GRUND_INSIGHTS_URL"), "{error}");
        let config = parse(&[
            "--insights-url",
            "http://insights:8081",
            "--insights-token",
            token,
        ])
        .unwrap();
        assert!(config.insights.enabled());
    }

    #[test]
    fn empty_insights_settings_count_as_unset() {
        let config = parse(&["--insights-url", "", "--insights-token", " "]).unwrap();
        assert!(!config.insights.enabled());
    }

    #[test]
    fn social_login_without_a_provider_is_refused() {
        let error = parse(&["--social-login", "true"]).unwrap_err().to_string();
        assert!(error.contains("GRUND_SOCIAL_LOGIN"), "{error}");
    }

    #[test]
    fn a_small_pool_is_refused_because_the_projection_runner_needs_two() {
        let error = parse(&["--database-max-connections", "2"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("GRUND_DATABASE_MAX_CONNECTIONS"), "{error}");
    }

    #[test]
    fn a_grace_period_longer_than_the_kubelets_is_refused() {
        assert!(parse(&["--shutdown-grace", "31"]).is_err());
    }

    #[test]
    fn an_unknown_flag_is_an_error_not_a_server() {
        assert!(parse(&["--public-ur", "https://x.example.com"]).is_err());
    }
}
