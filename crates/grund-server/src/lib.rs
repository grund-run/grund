//! grund's control plane.
//!
//! ```text
//!   grund serve
//!     config ─► tracing ─► PostgreSQL ─► migrations ─► NATS (optional) ─► State
//!     notmad, drained in this order on SIGTERM:
//!       grund/http          pages and health                stops taking requests first
//!       grund/health        nostatus checks                 keeps readiness honest while draining
//!       grund/projections   read-model catch-up and rebuild
//!       grund/sweeper       expired sessions, links, windows
//!       grund/outbox        mail and reset requests         drains last, up to 5 s
//! ```
//!
//! PostgreSQL is the truth. NATS, when configured, only wakes background work
//! sooner; every worker also polls, so losing NATS costs latency, never work.

pub mod api;
pub mod config;
pub mod crypto;
pub mod db;
pub mod health;
pub mod license;
pub mod projections;
pub mod secrets;
pub mod server;
pub mod services;
pub mod state;
pub mod templates;
pub mod web;

use anyhow::Context;

use crate::{config::ServeConfig, state::State};

/// `grund serve`.
pub async fn serve(config: ServeConfig) -> anyhow::Result<()> {
    let secret = secrets::SecretKey::load(&config)?;
    let pool = db::connect(&config.database).await?;
    grund_store::migrate(&pool).await?;
    let events = mire::EventStore::new(pool.clone());
    let nats = connect_nats(&config).await?;

    let templates = templates::Templates::new()?;
    let mailer = services::mail::Mailer::new(&config, templates.clone())?;
    let health = health::registry(pool.clone(), nats.clone(), mailer.configured(), &config);
    let entitlements = entitlements(&config)?;
    let social = if config.social.social_login {
        services::social::providers(&config.social)
    } else {
        Vec::new()
    };
    let http = http_client()?;
    let grace = config.shutdown_grace;
    let state = State {
        config: std::sync::Arc::new(config),
        pool,
        events,
        nats,
        secret: std::sync::Arc::new(secret),
        health,
        passwords: services::passwords::Passwords::new()?,
        templates,
        entitlements: std::sync::Arc::new(entitlements),
        social: std::sync::Arc::new(social),
        http,
        started: health::started(),
    };

    tracing::info!(
        revision = health::REVISION,
        version = health::VERSION,
        "grund starting"
    );
    notmad::Mad::builder()
        .add(server::Http::new(state.clone()))
        .add(health::Checks::new(&state))
        .add(projections::Projections::new(&state))
        .add(services::maintenance::Sweeper::new(state.clone()))
        .add(services::outbox::OutboxDrain::new(state.clone(), mailer))
        .cancellation(Some(grace))
        .run()
        .await?;
    Ok(())
}

/// The HTTP client for calls to sign-in providers: rustls with the ring
/// provider (installed here, once per process), 10 s per request.
pub fn http_client() -> anyhow::Result<reqwest::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .user_agent("grund")
        .build()
        .context("build the HTTP client for sign-in providers")
}

fn entitlements(config: &ServeConfig) -> anyhow::Result<services::entitlements::Entitlements> {
    let key = match (&config.license_key, &config.license_key_file) {
        (Some(key), _) => Some(key.clone()),
        (None, Some(path)) => Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("read GRUND_LICENSE_KEY_FILE {}", path.display()))?,
        ),
        (None, None) => None,
    };
    let entitlements = services::entitlements::Entitlements::from_key(
        key.as_deref(),
        &license::Verifier::grund(),
        chrono::Utc::now(),
    );
    if config.social.social_login
        && let Err(refusal) = entitlements.allows(license::Feature::SocialLogin)
    {
        tracing::warn!(%refusal, "GRUND_SOCIAL_LOGIN is on, but social sign-in needs a license that includes it; offering password sign-in only");
    }
    Ok(entitlements)
}

/// `grund migrate`: applies every migration and exits. `serve` does the same
/// on start; this is for running it as its own step.
pub async fn migrate(args: config::DatabaseArgs) -> anyhow::Result<()> {
    args.validate()?;
    let pool = db::connect(&args).await?;
    grund_store::migrate(&pool).await?;
    tracing::info!("migrations applied");
    Ok(())
}

async fn connect_nats(config: &ServeConfig) -> anyhow::Result<Option<async_nats::Client>> {
    let Some(url) = &config.nats_url else {
        tracing::info!(
            poll_interval_seconds = config.work_poll_interval.as_secs(),
            "GRUND_NATS_URL not set; background work is found by polling"
        );
        return Ok(None);
    };
    let mut options = async_nats::ConnectOptions::new()
        .name("grund")
        .connection_timeout(std::time::Duration::from_secs(5));
    if let Some(path) = &config.nats_creds_file {
        options = options
            .credentials_file(path)
            .await
            .with_context(|| format!("read GRUND_NATS_CREDS_FILE {}", path.display()))?;
    }
    let client = options
        .connect(url.as_str())
        .await
        .context("connect to NATS (GRUND_NATS_URL)")?;
    tracing::info!("connected to NATS for wake-ups");
    Ok(Some(client))
}
