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
    /// GRUND_DEV_MODE is on. Default: https://<GRUND_DOMAIN> when that is
    /// set, else http://localhost:8080.
    #[arg(long, env = "GRUND_PUBLIC_URL")]
    pub public_url: Option<String>,

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

    /// Image registries (host[:port], comma-separated) grund may speak to
    /// over plain HTTP when it resolves an app's image. For tests against a
    /// local registry; every other registry is HTTPS only.
    #[arg(long, env = "GRUND_INSECURE_REGISTRIES", value_delimiter = ',')]
    pub insecure_registries: Vec<String>,

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
    /// owns it and is made with `grund setup-link`; everyone after that joins
    /// by invitation. `multi` (grund's
    /// hosted instance): every sign-up gets an organisation named after it,
    /// and anyone signed in may create more.
    #[arg(
        long,
        env = "GRUND_ORGANISATIONS",
        value_enum,
        default_value = "single"
    )]
    pub organisations: OrganisationMode,

    /// The organisation whose owners and admins run the management pool: the
    /// instance's own machines, leased to organisations (grund-docs
    /// design/machines.md). Its id (a UUID), or its slug. Prefer the id on an
    /// instance with open sign-up: a slug names whoever holds it, so a slug
    /// set before its organisation exists could be taken by anyone signing
    /// up. Unset: the instance's organisation in `single` mode, and no
    /// management pool in `multi` mode.
    #[arg(long, env = "GRUND_OPERATOR_ORGANISATION")]
    pub operator_organisation: Option<String>,

    /// Whether sign-up without an invitation is open at all, in `multi`
    /// mode. Off, only invitations create accounts. A `single` instance's
    /// sign-up form is closed either way: its first account comes from
    /// `grund setup-link`, and later ones from invitations.
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

    /// Machine registrations allowed per client address per minute; 0 turns
    /// the per-address limit off. A real install makes one; probing for
    /// registration tokens needs many. Only meaningful when the real client
    /// address reaches grund (see GRUND_TRUSTED_PROXY_HOPS).
    #[arg(long, env = "GRUND_ENROLL_ATTEMPTS_PER_ADDRESS", default_value_t = 10)]
    pub enroll_attempts_per_address: u32,

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

    #[command(flatten)]
    pub billing: BillingArgs,

    #[command(flatten)]
    pub capacity: CapacityArgs,

    #[command(flatten)]
    pub relay: RelayArgs,

    #[command(flatten)]
    pub tls: TlsArgs,

    #[command(flatten)]
    pub machine_defaults: MachineDefaultsArgs,

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

/// A billing service for this instance (grund-docs design/billing.md). Only
/// grund's hosted service has one; without it every organisation is free and
/// nothing is charged.
#[derive(Clone, Debug, Default, Args)]
pub struct BillingArgs {
    /// The billing service, e.g. http://billing:8080, reached from grund's
    /// servers only. grund calls `grund.billing.v1.BillingService` on it. Set
    /// with GRUND_BILLING_TOKEN.
    #[arg(long, env = "GRUND_BILLING_URL")]
    pub billing_url: Option<String>,

    /// The bearer token the billing service expects, at least 32 printable
    /// ASCII characters.
    #[arg(long, env = "GRUND_BILLING_TOKEN", hide_env_values = true)]
    pub billing_token: Option<String>,
}

/// What the Machines page offers by default: the script that installs the
/// agent on a device, and the image a new VM boots. All optional; without
/// them the page shows `grund join` alone and an empty image form.
#[derive(Clone, Debug, Args)]
pub struct MachineDefaultsArgs {
    /// A script that installs grund and its agent service on a device, run as
    /// `curl -fsSL <url> | sudo sh -s -- --url <instance> --code <setup code>`
    /// (grund's own is crates/grund-agent/install.sh). Not with
    /// GRUND_SERVE_INSTALLER.
    #[arg(long, env = "GRUND_AGENT_INSTALL_URL")]
    pub agent_install_url: Option<String>,

    /// Serve this instance's own installer and binary: `GET /install` (the
    /// install.sh built into this binary) and `GET
    /// /install/grund-linux-<arch>` (this executable) with its `.sha256`. The
    /// Machines page then offers `curl -fsSL <instance>/install | sudo sh -s
    /// -- --url <instance> --code <setup code> --from-instance`, and a
    /// machine installs exactly the build the instance runs, published or
    /// built from source. compose.yaml turns it on. Off by default, so an
    /// instance that sets GRUND_AGENT_INSTALL_URL keeps its machines on
    /// builds from grund's package registry.
    #[arg(long, env = "GRUND_SERVE_INSTALLER", default_value_t = false, action = clap::ArgAction::Set)]
    pub serve_installer: bool,

    /// The kernel a new VM boots by default, with GRUND_VM_KERNEL_SHA256.
    #[arg(long, env = "GRUND_VM_KERNEL_URL")]
    pub vm_kernel_url: Option<String>,

    /// Lowercase hex SHA-256 of GRUND_VM_KERNEL_URL.
    #[arg(long, env = "GRUND_VM_KERNEL_SHA256")]
    pub vm_kernel_sha256: Option<String>,

    /// The root filesystem a new VM boots by default, with
    /// GRUND_VM_ROOTFS_SHA256.
    #[arg(long, env = "GRUND_VM_ROOTFS_URL")]
    pub vm_rootfs_url: Option<String>,

    /// Lowercase hex SHA-256 of GRUND_VM_ROOTFS_URL.
    #[arg(long, env = "GRUND_VM_ROOTFS_SHA256")]
    pub vm_rootfs_sha256: Option<String>,
}

impl MachineDefaultsArgs {
    fn validate(&self) -> anyhow::Result<()> {
        let url = |name: &str, value: &Option<String>, https_only: bool| -> anyhow::Result<()> {
            if let Some(value) = value {
                let ok =
                    value.starts_with("https://") || (!https_only && value.starts_with("http://"));
                anyhow::ensure!(
                    ok,
                    "{name} must be an {} URL, not {value:?}",
                    if https_only { "https" } else { "http or https" }
                );
            }
            Ok(())
        };
        anyhow::ensure!(
            !(self.serve_installer && self.agent_install_url.is_some()),
            "set GRUND_AGENT_INSTALL_URL or GRUND_SERVE_INSTALLER=true, not both: the Machines \
             page offers one installer. compose.yaml turns GRUND_SERVE_INSTALLER on (since \
             2026-09-28): drop GRUND_AGENT_INSTALL_URL to install the instance's own build, or \
             set GRUND_SERVE_INSTALLER=false to keep that installer"
        );
        url("GRUND_AGENT_INSTALL_URL", &self.agent_install_url, true)?;
        url("GRUND_VM_KERNEL_URL", &self.vm_kernel_url, false)?;
        url("GRUND_VM_ROOTFS_URL", &self.vm_rootfs_url, false)?;
        for (name, image, sha) in [
            (
                "GRUND_VM_KERNEL",
                &self.vm_kernel_url,
                &self.vm_kernel_sha256,
            ),
            (
                "GRUND_VM_ROOTFS",
                &self.vm_rootfs_url,
                &self.vm_rootfs_sha256,
            ),
        ] {
            anyhow::ensure!(
                image.is_some() == sha.is_some(),
                "{name}_URL and {name}_SHA256 must be set together: a VM image is pinned by its digest"
            );
            if let Some(sha) = sha {
                anyhow::ensure!(
                    sha.len() == 64 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                    "{name}_SHA256 must be 64 lowercase hex characters"
                );
            }
        }
        Ok(())
    }
}

/// grund's relay (grund-docs design/network.md §10): the lighthouse machines
/// reach from behind their NATs, and QUIC address discovery, which tells a
/// machine its public address. Off unless GRUND_RELAY_ADDRESS is set. Only
/// machines registered with this instance and not revoked are admitted.
#[derive(Clone, Debug, Args)]
pub struct RelayArgs {
    /// Where the relay listens (TCP), e.g. 0.0.0.0:8443. Its own listener,
    /// not GRUND_LISTEN: the relay's WebSocket upgrade needs an HTTP/1 loop
    /// that axum's server is not.
    #[arg(long, env = "GRUND_RELAY_ADDRESS")]
    pub relay_address: Option<std::net::SocketAddr>,

    /// The relay's URL as machines reach it, e.g. https://relay.example.com.
    /// Registration tells machines this URL. Plain http only for loopback.
    #[arg(long, env = "GRUND_RELAY_URL")]
    pub relay_url: Option<String>,

    /// The relay's certificate chain (PEM). Without it the relay listens in
    /// plain HTTP, for a proxy in front that terminates TLS and passes the
    /// WebSocket upgrade through.
    #[arg(long, env = "GRUND_RELAY_TLS_CERT_FILE")]
    pub relay_tls_cert_file: Option<std::path::PathBuf>,

    /// The private key of GRUND_RELAY_TLS_CERT_FILE (PEM).
    #[arg(long, env = "GRUND_RELAY_TLS_KEY_FILE")]
    pub relay_tls_key_file: Option<std::path::PathBuf>,

    /// Where QUIC address discovery listens (UDP), e.g. 0.0.0.0:7842. Needs
    /// the relay's certificate; without it machines behind NAT fall back to
    /// the relay more often.
    #[arg(long, env = "GRUND_RELAY_QUIC_ADDRESS")]
    pub relay_quic_address: Option<std::net::SocketAddr>,

    /// The relays machines use besides the one in this process: `grund
    /// relay`s elsewhere, comma-separated, each `https://relay.example.com`
    /// or `region=https://relay.example.com`. Machines get the list, signed,
    /// with their network's membership, so changing it reaches them at the
    /// next epoch, with no re-join.
    #[arg(long, env = "GRUND_RELAYS", value_delimiter = ',')]
    pub relays: Vec<RelaySpec>,

    /// The token `grund relay`s present to ask this instance which keys
    /// they may admit (POST /relay/v1/access). At least 32 characters.
    /// Unset: the access endpoint answers 404, and only the relay in this
    /// process admits anyone.
    #[arg(long, env = "GRUND_RELAY_ACCESS_TOKEN", hide_env_values = true)]
    pub relay_access_token: Option<String>,
}

/// One relay in GRUND_RELAYS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaySpec {
    pub url: String,
    pub region: Option<String>,
}

impl std::str::FromStr for RelaySpec {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        let (region, url) = match input.split_once('=') {
            Some((region, url)) if !region.contains("://") => (Some(region.trim()), url.trim()),
            _ => (None, input),
        };
        if let Some(region) = region
            && (region.is_empty()
                || !region
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
        {
            return Err(format!(
                "a relay's region is a-z, 0-9 and hyphens, not {region:?}"
            ));
        }
        let origin = PublicOrigin::parse(url.trim_end_matches('/')).ok_or_else(|| {
            format!("a relay is a URL like https://relay.example.com, not {url:?}")
        })?;
        if !(origin.https || origin.is_loopback()) {
            return Err(format!(
                "a relay must be https, except on loopback: {url:?}"
            ));
        }
        Ok(Self {
            url: url.trim_end_matches('/').to_string(),
            region: region.map(str::to_string),
        })
    }
}

impl RelayArgs {
    /// The relay URLs machines are told at registration and in every
    /// membership list: the relay in this process first, when it is on,
    /// then GRUND_RELAYS.
    pub fn urls(&self) -> Vec<String> {
        self.list().into_iter().map(|r| r.url).collect()
    }

    /// [`RelayArgs::urls`] with each relay's region.
    pub fn list(&self) -> Vec<RelaySpec> {
        let mut out: Vec<RelaySpec> = match (&self.relay_address, &self.relay_url) {
            (Some(_), Some(url)) => vec![RelaySpec {
                url: url.trim_end_matches('/').to_string(),
                region: None,
            }],
            _ => Vec::new(),
        };
        for relay in &self.relays {
            if !out.iter().any(|r| r.url == relay.url) {
                out.push(relay.clone());
            }
        }
        out
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.relay_address.is_some() == self.relay_url.is_some(),
            "GRUND_RELAY_ADDRESS and GRUND_RELAY_URL must be set together"
        );
        if let Some(url) = &self.relay_url {
            let origin = PublicOrigin::parse(url.trim_end_matches('/')).ok_or_else(|| {
                anyhow::anyhow!(
                    "GRUND_RELAY_URL must be a URL like https://relay.example.com, not {url:?}"
                )
            })?;
            anyhow::ensure!(
                origin.https || origin.is_loopback(),
                "GRUND_RELAY_URL must be https, except on loopback: machines trust the relay's \
                 certificate to know they reached grund's relay"
            );
        }
        anyhow::ensure!(
            self.relay_tls_cert_file.is_some() == self.relay_tls_key_file.is_some(),
            "GRUND_RELAY_TLS_CERT_FILE and GRUND_RELAY_TLS_KEY_FILE must be set together"
        );
        if let Some(token) = &self.relay_access_token {
            anyhow::ensure!(
                token.len() >= 32,
                "GRUND_RELAY_ACCESS_TOKEN must be at least 32 characters"
            );
        }
        Ok(())
    }
}

/// This instance's own HTTPS (grund-docs design/traffic.md §5): grund
/// terminates TLS itself for GRUND_DOMAIN, with a certificate it orders by
/// ACME, or with one supplied in files. Off unless GRUND_DOMAIN or
/// GRUND_TLS_CERT_FILE is set. Plain http on GRUND_LISTEN is served as
/// before either way, for the local health probe and a proxy in front.
#[derive(Clone, Debug, Args)]
pub struct TlsArgs {
    /// The name people reach this instance at, e.g. grund.example.com. Turns
    /// on HTTPS on GRUND_TLS_LISTEN, with a certificate ordered from
    /// GRUND_ACME_DIRECTORY unless GRUND_TLS_CERT_FILE supplies one.
    /// GRUND_PUBLIC_URL then defaults to https://<GRUND_DOMAIN>.
    #[arg(long, env = "GRUND_DOMAIN")]
    pub domain: Option<String>,

    /// Where HTTPS listens. ACME's TLS-ALPN-01 challenge is answered here,
    /// so for ACME this must be what port 443 of GRUND_DOMAIN reaches.
    #[arg(long, env = "GRUND_TLS_LISTEN", default_value = "0.0.0.0:443")]
    pub tls_listen: SocketAddr,

    /// A plain-http listener, e.g. 0.0.0.0:80, that redirects every request
    /// to GRUND_PUBLIC_URL and answers ACME's HTTP-01 challenge. Needed for
    /// GRUND_ACME_CHALLENGE=http-01. Off by default: TLS-ALPN-01 needs no
    /// port 80.
    #[arg(long, env = "GRUND_TLS_REDIRECT_LISTEN")]
    pub tls_redirect_listen: Option<SocketAddr>,

    /// A certificate chain (PEM, leaf first) to serve instead of ordering
    /// one. Re-read when the file changes, so a renewal by another tool is
    /// picked up. Set with GRUND_TLS_KEY_FILE.
    #[arg(long, env = "GRUND_TLS_CERT_FILE")]
    pub tls_cert_file: Option<PathBuf>,

    /// The private key of GRUND_TLS_CERT_FILE (PEM).
    #[arg(long, env = "GRUND_TLS_KEY_FILE")]
    pub tls_key_file: Option<PathBuf>,

    /// The ACME directory certificates are ordered from, e.g.
    /// https://acme-v02.api.letsencrypt.org/directory: GRUND_DOMAIN's, and
    /// those of `grund relay`s on other hosts (grund.certificates.v1), which
    /// is why it may be set without GRUND_DOMAIN. Setting it agrees to that
    /// CA's subscriber agreement. No default in the binary, so nothing talks
    /// to a CA unless told to; compose.yaml sets Let's Encrypt.
    #[arg(long, env = "GRUND_ACME_DIRECTORY")]
    pub acme_directory: Option<String>,

    /// A contact address for the ACME account, e.g. ops@example.com. Optional:
    /// Let's Encrypt no longer mails about expiry.
    #[arg(long, env = "GRUND_ACME_CONTACT")]
    pub acme_contact: Option<String>,

    /// A PEM file of extra roots to trust for GRUND_ACME_DIRECTORY's own
    /// HTTPS, for a private or test CA (step-ca, Pebble). Public CAs need
    /// none.
    #[arg(long, env = "GRUND_ACME_CA_FILE")]
    pub acme_ca_file: Option<PathBuf>,

    /// The ACME profile named on every order. Let's Encrypt's `classic` is
    /// 90 days today (64 from 2027-02-10, 45 from 2028-02-16); renewal
    /// follows the CA's renewal information, so a lifetime change needs no
    /// configuration change.
    #[arg(long, env = "GRUND_ACME_PROFILE", default_value = "classic")]
    pub acme_profile: String,

    /// How the CA checks this instance holds GRUND_DOMAIN: tls-alpn-01 on
    /// GRUND_TLS_LISTEN (no port 80 needed), or http-01 on
    /// GRUND_TLS_REDIRECT_LISTEN.
    #[arg(
        long,
        env = "GRUND_ACME_CHALLENGE",
        value_parser = ["tls-alpn-01", "http-01"],
        default_value = "tls-alpn-01"
    )]
    pub acme_challenge: String,

    /// The first wait after a failed order, in seconds; each further failure
    /// doubles it, up to 12 hours, and a CA's Retry-After is waited out when
    /// it asks for longer. 300 keeps a broken setup inside Let's Encrypt's 5
    /// failed validations per name per hour. Lower only against a test CA.
    #[arg(long, env = "GRUND_ACME_RETRY_BASE", value_parser = secs, default_value = "300")]
    pub acme_retry_base: Duration,

    /// How often each replica looks for a renewed certificate (in the
    /// database, or GRUND_TLS_CERT_FILE's modification time), and for due
    /// ACME work.
    #[arg(long, env = "GRUND_TLS_REFRESH_INTERVAL", value_parser = secs, default_value = "10")]
    pub tls_refresh_interval: Duration,
}

impl TlsArgs {
    /// Whether this instance serves HTTPS itself.
    pub fn enabled(&self) -> bool {
        self.domain.is_some() || self.tls_cert_file.is_some()
    }

    /// Whether this instance orders its certificate by ACME.
    pub fn acme(&self) -> bool {
        self.domain.is_some() && self.tls_cert_file.is_none()
    }

    /// Whether this instance orders certificates at all: its own, or those
    /// of terminators on other hosts.
    pub fn orders(&self) -> bool {
        self.acme_directory.is_some()
    }

    fn validate(&mut self) -> anyhow::Result<()> {
        if let Some(domain) = &mut self.domain {
            *domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            anyhow::ensure!(
                is_hostname(domain)
                    && domain.contains('.')
                    && !domain
                        .split('.')
                        .all(|l| l.bytes().all(|b| b.is_ascii_digit())),
                "GRUND_DOMAIN must be a DNS name like grund.example.com, not {domain:?}: no \
                 scheme, port, wildcard or IP address"
            );
        }
        anyhow::ensure!(
            self.tls_cert_file.is_some() == self.tls_key_file.is_some(),
            "GRUND_TLS_CERT_FILE and GRUND_TLS_KEY_FILE must be set together"
        );
        for (name, set) in [
            ("GRUND_ACME_CONTACT", self.acme_contact.is_some()),
            ("GRUND_ACME_CA_FILE", self.acme_ca_file.is_some()),
        ] {
            anyhow::ensure!(
                !set || self.acme_directory.is_some(),
                "{name} is set, but GRUND_ACME_DIRECTORY is not: it is a setting of the ACME \
                 account"
            );
        }
        anyhow::ensure!(
            !self.acme() || self.acme_directory.is_some(),
            "GRUND_DOMAIN is set, so HTTPS needs a certificate: set GRUND_ACME_DIRECTORY (for \
             Let's Encrypt, https://acme-v02.api.letsencrypt.org/directory), or supply one with \
             GRUND_TLS_CERT_FILE and GRUND_TLS_KEY_FILE"
        );
        if let Some(directory) = &self.acme_directory {
            anyhow::ensure!(
                directory.starts_with("https://") && !directory.contains(char::is_whitespace),
                "GRUND_ACME_DIRECTORY must be an https URL, not {directory:?}"
            );
        }
        if let Some(contact) = &mut self.acme_contact {
            let address = contact.trim().trim_start_matches("mailto:").to_string();
            anyhow::ensure!(
                address
                    .split_once('@')
                    .is_some_and(|(local, host)| !local.is_empty() && is_hostname(host))
                    && !address.contains([',', ' ', '<', '>']),
                "GRUND_ACME_CONTACT must be one mail address, like ops@example.com"
            );
            *contact = format!("mailto:{address}");
        }
        anyhow::ensure!(
            !self.acme_profile.is_empty()
                && self.acme_profile.len() <= 64
                && self
                    .acme_profile
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'),
            "GRUND_ACME_PROFILE must be a profile name like classic"
        );
        anyhow::ensure!(
            self.acme_challenge != "http-01" || self.tls_redirect_listen.is_some(),
            "GRUND_ACME_CHALLENGE=http-01 needs GRUND_TLS_REDIRECT_LISTEN (e.g. 0.0.0.0:80): \
             that is where the CA looks for the answer"
        );
        anyhow::ensure!(
            self.tls_redirect_listen.is_none() || self.enabled(),
            "GRUND_TLS_REDIRECT_LISTEN redirects to HTTPS, which is off: set GRUND_DOMAIN or \
             GRUND_TLS_CERT_FILE"
        );
        anyhow::ensure!(
            self.tls_redirect_listen
                .is_none_or(|redirect| redirect != self.tls_listen),
            "GRUND_TLS_REDIRECT_LISTEN and GRUND_TLS_LISTEN must differ"
        );
        anyhow::ensure!(
            !self.acme_retry_base.is_zero() && self.acme_retry_base <= Duration::from_secs(3600),
            "GRUND_ACME_RETRY_BASE must be between 1 and 3600 seconds"
        );
        anyhow::ensure!(
            !self.tls_refresh_interval.is_zero()
                && self.tls_refresh_interval <= Duration::from_secs(300),
            "GRUND_TLS_REFRESH_INTERVAL must be between 1 and 300 seconds"
        );
        Ok(())
    }
}

/// A capacity provider for the management pool (grund-docs
/// design/machines.md): where grund gets machines from. Only grund's hosted
/// service has one (fleet); a self-hosted instance adds machines to its pool
/// by hand.
#[derive(Clone, Debug, Args)]
pub struct CapacityArgs {
    /// The capacity provider, e.g. http://fleet:8080, reached from grund's
    /// servers only. grund calls `grund.capacity.v1.CapacityService` on it.
    /// Set with GRUND_CAPACITY_TOKEN.
    #[arg(long, env = "GRUND_CAPACITY_URL")]
    pub capacity_url: Option<String>,

    /// The bearer token the capacity provider expects, at least 32 printable
    /// ASCII characters.
    #[arg(long, env = "GRUND_CAPACITY_TOKEN", hide_env_values = true)]
    pub capacity_token: Option<String>,
}

impl CapacityArgs {
    /// Whether a capacity provider is configured.
    pub fn enabled(&self) -> bool {
        self.capacity_url.is_some() && self.capacity_token.is_some()
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.capacity_url.is_some() == self.capacity_token.is_some(),
            "GRUND_CAPACITY_URL and GRUND_CAPACITY_TOKEN must be set together"
        );
        if let Some(url) = &self.capacity_url {
            anyhow::ensure!(
                (url.starts_with("http://") || url.starts_with("https://"))
                    && !url.ends_with('/')
                    && !url.contains(['?', '#']),
                "GRUND_CAPACITY_URL must be an http or https URL without a trailing slash"
            );
        }
        if let Some(token) = &self.capacity_token {
            anyhow::ensure!(
                token.len() >= 32 && token.bytes().all(|b| b.is_ascii_graphic()),
                "GRUND_CAPACITY_TOKEN must be at least 32 printable ASCII characters"
            );
        }
        Ok(())
    }
}

impl BillingArgs {
    /// Whether a billing service is configured.
    pub fn enabled(&self) -> bool {
        self.billing_url.is_some() && self.billing_token.is_some()
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.billing_url.is_some() == self.billing_token.is_some(),
            "GRUND_BILLING_URL and GRUND_BILLING_TOKEN must be set together"
        );
        if let Some(url) = &self.billing_url {
            anyhow::ensure!(
                (url.starts_with("http://") || url.starts_with("https://"))
                    && !url.ends_with('/')
                    && !url.contains(['?', '#']),
                "GRUND_BILLING_URL must be an http or https URL without a trailing slash"
            );
        }
        if let Some(token) = &self.billing_token {
            anyhow::ensure!(
                token.len() >= 32 && token.bytes().all(|b| b.is_ascii_graphic()),
                "GRUND_BILLING_TOKEN must be at least 32 printable ASCII characters"
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
            &mut self.billing.billing_url,
            &mut self.billing.billing_token,
            &mut self.capacity.capacity_url,
            &mut self.capacity.capacity_token,
            &mut self.operator_organisation,
            &mut self.machine_defaults.agent_install_url,
            &mut self.public_url,
            &mut self.tls.domain,
            &mut self.tls.acme_directory,
            &mut self.tls.acme_contact,
        ] {
            if value.as_deref().is_some_and(|v| v.trim().is_empty()) {
                *value = None;
            }
        }
        self.database.validate()?;
        self.tls.validate()?;

        let public_url = self
            .public_url
            .get_or_insert_with(|| match &self.tls.domain {
                Some(domain) => format!("https://{domain}"),
                None => "http://localhost:8080".into(),
            })
            .clone();
        let origin = PublicOrigin::parse(&public_url).ok_or_else(|| {
            anyhow::anyhow!(
                "GRUND_PUBLIC_URL must be an origin like https://app.example.com: a scheme and \
                 host, an optional port, no path or trailing slash; got {public_url:?}"
            )
        })?;
        if let Some(domain) = &self.tls.domain {
            anyhow::ensure!(
                origin.https && &origin.host == domain,
                "GRUND_PUBLIC_URL is {public_url:?}, but GRUND_DOMAIN is {domain:?}: with \
                 GRUND_DOMAIN set, GRUND_PUBLIC_URL must be https://{domain} (a port may follow), \
                 or be left unset"
            );
        }
        anyhow::ensure!(
            !self.tls.enabled() || self.tls.tls_listen != self.listen,
            "GRUND_TLS_LISTEN and GRUND_LISTEN are both {}: HTTPS and plain http need their own \
             listeners",
            self.listen
        );
        anyhow::ensure!(
            self.tls
                .tls_redirect_listen
                .is_none_or(|redirect| redirect != self.listen),
            "GRUND_TLS_REDIRECT_LISTEN and GRUND_LISTEN are both {}: the redirect listener \
             answers nothing but redirects and ACME HTTP-01",
            self.listen
        );
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
                ("GRUND_BILLING_TOKEN", self.billing.billing_token.as_deref()),
                (
                    "GRUND_CAPACITY_TOKEN",
                    self.capacity.capacity_token.as_deref(),
                ),
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
        self.billing.validate()?;
        self.capacity.validate()?;
        self.relay.validate()?;
        anyhow::ensure!(
            self.relay.relay_quic_address.is_none()
                || (self.relay.relay_address.is_some()
                    && (self.relay.relay_tls_cert_file.is_some()
                        || self.relay_serves_instance_certificate())),
            "GRUND_RELAY_QUIC_ADDRESS needs the relay (GRUND_RELAY_ADDRESS) and its certificate \
             (GRUND_RELAY_TLS_CERT_FILE, or GRUND_DOMAIN's when GRUND_RELAY_URL is on it): QUIC \
             always speaks TLS"
        );
        self.machine_defaults.validate()?;
        Ok(())
    }

    fn colocated_relay_host(&self) -> Option<String> {
        if self.relay.relay_address.is_none() || self.relay.relay_tls_cert_file.is_some() {
            return None;
        }
        let origin = PublicOrigin::parse(self.relay.relay_url.as_deref()?.trim_end_matches('/'))?;
        origin.https.then_some(origin.host)
    }

    /// Whether the relay in this process serves the instance's own
    /// certificate (grund-docs design/traffic.md §5.7): it has no files of
    /// its own, and its URL is on GRUND_DOMAIN, or on a name the instance
    /// adds to its own certificate ([`Self::instance_certificate_names`]).
    pub fn relay_serves_instance_certificate(&self) -> bool {
        self.colocated_relay_host().is_some_and(|host| {
            self.tls.acme() || (self.tls.enabled() && self.tls.domain.as_deref() == Some(&host))
        })
    }

    /// The names of the instance's own certificate when it orders it:
    /// GRUND_DOMAIN, then the relay in this process's host when that is
    /// another name, so both are served from one certificate and one key.
    pub fn instance_certificate_names(&self) -> Vec<String> {
        let Some(domain) = self.tls.domain.clone().filter(|_| self.tls.acme()) else {
            return Vec::new();
        };
        let relay = self.colocated_relay_host().filter(|host| host != &domain);
        std::iter::once(domain).chain(relay).collect()
    }

    pub fn public_origin(&self) -> PublicOrigin {
        self.public_url
            .as_deref()
            .and_then(PublicOrigin::parse)
            .expect("validated at startup")
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
    fn machines_are_told_the_relay_in_this_process_first_then_grund_relays_once_each() {
        let config = parse(&[
            "--relay-address",
            "0.0.0.0:8443",
            "--relay-url",
            "https://relay.example.com/",
            "--relays",
            "eu-central=https://relay-eu.example.com, https://relay.example.com,https://relay-us.example.com",
        ])
        .unwrap();
        assert_eq!(
            config.relay.list(),
            vec![
                RelaySpec {
                    url: "https://relay.example.com".into(),
                    region: None
                },
                RelaySpec {
                    url: "https://relay-eu.example.com".into(),
                    region: Some("eu-central".into())
                },
                RelaySpec {
                    url: "https://relay-us.example.com".into(),
                    region: None
                },
            ]
        );
        assert!(parse(&[]).unwrap().relay.urls().is_empty());
    }

    #[test]
    fn a_plain_http_relay_a_bad_region_or_a_short_access_token_is_refused() {
        assert!(parse(&["--relays", "http://relay.example.com"]).is_err());
        assert!(parse(&["--relays", "http://127.0.0.1:3340"]).is_ok());
        assert!(parse(&["--relays", "EU=https://relay.example.com"]).is_err());
        assert!(parse(&["--relay-access-token", "short"]).is_err());
        assert!(parse(&["--relay-access-token", "0123456789abcdef0123456789abcdef"]).is_ok());
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
    fn an_instance_offers_one_installer_its_own_or_another() {
        let url = "https://example.com/install.sh";
        assert!(parse(&["--serve-installer", "true"]).is_ok());
        assert!(parse(&["--agent-install-url", url]).is_ok());
        assert!(parse(&["--serve-installer", "true", "--agent-install-url", url]).is_err());
        assert!(parse(&["--serve-installer", "true", "--agent-install-url", ""]).is_ok());
    }

    const LE: &str = "https://acme-v02.api.letsencrypt.org/directory";

    fn refused(args: &[&str], names: &str) {
        let error = parse(args).unwrap_err().to_string();
        assert!(error.contains(names), "{args:?}: {error}");
    }

    #[test]
    fn a_domain_with_acme_serves_https_at_that_name() {
        let config = parse(&["--domain", "Grund.Example.com.", "--acme-directory", LE]).unwrap();
        assert_eq!(config.tls.domain.as_deref(), Some("grund.example.com"));
        assert_eq!(
            config.public_origin().serialized,
            "https://grund.example.com"
        );
        assert!(config.tls.enabled() && config.tls.acme());
        assert_eq!(config.tls.acme_profile, "classic");
        assert_eq!(config.tls.acme_challenge, "tls-alpn-01");
    }

    #[test]
    fn a_domain_without_a_certificate_source_is_refused_naming_both() {
        let error = parse(&["--domain", "grund.example.com"])
            .unwrap_err()
            .to_string();
        assert!(error.contains("GRUND_ACME_DIRECTORY"), "{error}");
        assert!(error.contains("GRUND_TLS_CERT_FILE"), "{error}");
    }

    #[test]
    fn a_supplied_certificate_beside_an_acme_directory_leaves_acme_to_the_relays() {
        let config = parse(&[
            "--domain",
            "grund.example.com",
            "--acme-directory",
            LE,
            "--tls-cert-file",
            "/c",
            "--tls-key-file",
            "/k",
        ])
        .unwrap();
        assert!(config.tls.enabled() && !config.tls.acme() && config.tls.orders());
        refused(&["--tls-cert-file", "/c"], "GRUND_TLS_KEY_FILE");
    }

    #[test]
    fn a_supplied_certificate_needs_no_domain() {
        let config = parse(&["--tls-cert-file", "/c", "--tls-key-file", "/k"]).unwrap();
        assert!(config.tls.enabled() && !config.tls.acme());
    }

    #[test]
    fn an_acme_directory_without_a_domain_orders_for_relays_only() {
        let config = parse(&["--acme-directory", LE]).unwrap();
        assert!(!config.tls.enabled() && !config.tls.acme() && config.tls.orders());
        refused(
            &["--acme-contact", "ops@example.com"],
            "GRUND_ACME_DIRECTORY",
        );
        refused(&["--acme-ca-file", "/ca.pem"], "GRUND_ACME_DIRECTORY");
        refused(
            &["--acme-directory", "http://ca.example/dir"],
            "GRUND_ACME_DIRECTORY",
        );
    }

    #[test]
    fn a_domain_that_is_not_a_dns_name_is_refused() {
        for domain in [
            "https://grund.example.com",
            "*.example.com",
            "192.168.1.10",
            "localhost",
            "a:443",
        ] {
            refused(
                &["--domain", domain, "--acme-directory", LE],
                "GRUND_DOMAIN",
            );
        }
    }

    #[test]
    fn a_public_url_for_another_name_or_plain_http_is_refused_with_a_domain() {
        let domain = ["--domain", "grund.example.com", "--acme-directory", LE];
        let with = |url: &'static str| [&domain[..], &["--public-url", url]].concat();
        refused(&with("https://other.example.com"), "GRUND_PUBLIC_URL");
        refused(&with("http://grund.example.com"), "GRUND_PUBLIC_URL");
        assert!(parse(&with("https://grund.example.com:8443")).is_ok());
    }

    #[test]
    fn the_acme_directory_must_be_https() {
        refused(
            &[
                "--domain",
                "grund.example.com",
                "--acme-directory",
                "http://ca.example/dir",
            ],
            "GRUND_ACME_DIRECTORY",
        );
    }

    #[test]
    fn a_contact_becomes_a_mailto_uri_and_a_list_is_refused() {
        let config = parse(&[
            "--domain",
            "grund.example.com",
            "--acme-directory",
            LE,
            "--acme-contact",
            "ops@example.com",
        ])
        .unwrap();
        assert_eq!(
            config.tls.acme_contact.as_deref(),
            Some("mailto:ops@example.com")
        );
        refused(
            &[
                "--domain",
                "grund.example.com",
                "--acme-directory",
                LE,
                "--acme-contact",
                "a@example.com, b@example.com",
            ],
            "GRUND_ACME_CONTACT",
        );
    }

    #[test]
    fn http01_needs_the_redirect_listener_and_it_needs_https() {
        let domain = ["--domain", "grund.example.com", "--acme-directory", LE];
        refused(
            &[&domain[..], &["--acme-challenge", "http-01"]].concat(),
            "GRUND_TLS_REDIRECT_LISTEN",
        );
        assert!(
            parse(
                &[
                    &domain[..],
                    &[
                        "--acme-challenge",
                        "http-01",
                        "--tls-redirect-listen",
                        "0.0.0.0:80"
                    ]
                ]
                .concat()
            )
            .is_ok()
        );
        refused(
            &["--tls-redirect-listen", "0.0.0.0:80"],
            "GRUND_TLS_REDIRECT_LISTEN",
        );
    }

    #[test]
    fn https_and_plain_http_cannot_share_a_listener() {
        refused(
            &[
                "--domain",
                "grund.example.com",
                "--acme-directory",
                LE,
                "--listen",
                "0.0.0.0:443",
            ],
            "GRUND_TLS_LISTEN",
        );
    }

    #[test]
    fn a_retry_base_outside_its_range_is_refused() {
        let domain = ["--domain", "grund.example.com", "--acme-directory", LE];
        refused(
            &[&domain[..], &["--acme-retry-base", "0"]].concat(),
            "GRUND_ACME_RETRY_BASE",
        );
        refused(
            &[&domain[..], &["--acme-retry-base", "7200"]].concat(),
            "GRUND_ACME_RETRY_BASE",
        );
    }

    #[test]
    fn an_unknown_flag_is_an_error_not_a_server() {
        assert!(parse(&["--public-ur", "https://x.example.com"]).is_err());
    }
}
