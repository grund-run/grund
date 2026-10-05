//! grund's control plane.
//!
//! ```text
//!   grund serve
//!     config ─► tracing ─► PostgreSQL (waited for up to GRUND_DATABASE_WAIT) ─► migrations ─► NATS (optional) ─► State
//!     notmad, drained in this order on SIGTERM:
//!       grund/http          pages and health                stops taking requests first
//!       grund/https         the same, over TLS               only with GRUND_DOMAIN or GRUND_TLS_CERT_FILE
//!       grund/redirect      http to https, ACME HTTP-01     only with GRUND_TLS_REDIRECT_LISTEN
//!       grund/relay         machines' relay (network.md)    only with GRUND_RELAY_ADDRESS
//!       grund/health        nostatus checks                 keeps readiness honest while draining
//!       grund/projections   read-model catch-up and rebuild
//!       grund/sweeper       expired sessions, links, windows
//!       grund/certificates  renewed certificates, ACME work  with HTTPS, or GRUND_ACME_DIRECTORY
//!       grund/outbox        mail, resets, insights reports  drains last, up to 5 s
//! ```
//!
//! PostgreSQL is the truth. NATS, when configured, only wakes background work
//! sooner; every worker also polls, so losing NATS costs latency, never work.

pub mod acme;
pub mod api;
pub mod apps_command;
pub mod certificates;
pub mod config;
pub mod crypto;
pub mod db;
pub mod doctor;
pub mod edge;
pub mod extension;
pub mod health;
pub mod hearing;
pub mod keys;
pub mod license;
pub mod projections;
pub mod registry;
pub mod relay;
pub mod relay_certificate;
pub mod relay_command;
pub mod relays_command;
pub mod restart;
pub mod sagas;
pub mod secrets;
pub mod server;
pub mod services;
pub mod setup_link;
pub mod state;
pub mod templates;
pub mod wakes;
pub mod web;

use anyhow::Context;

use crate::{config::ServeConfig, state::State};

/// `grund serve`, with the extensions this binary was built with (none for
/// the open-source-only build).
pub async fn serve(
    config: ServeConfig,
    extensions: Vec<std::sync::Arc<dyn extension::Extension>>,
) -> anyhow::Result<()> {
    if config.machine_defaults.serve_installer {
        web::install::check()?;
    }
    certificates::check_files(&config)?;
    let secret = secrets::SecretKey::load(&config)?;
    let pool = db::connect_waiting(&config.database, config.database_wait, config.listen).await?;
    grund_store::migrate(&pool).await?;
    if config.organisations == config::OrganisationMode::Single {
        use grund_store::organisations::{InstanceCheck, prepare_single_instance};
        match prepare_single_instance(&pool).await? {
            InstanceCheck::Ready => {}
            InstanceCheck::Adopted(organisation_id) => tracing::info!(
                %organisation_id,
                "GRUND_ORGANISATIONS=single: adopted the one organisation as the instance's"
            ),
            InstanceCheck::TooMany(count) => anyhow::bail!(
                "GRUND_ORGANISATIONS=single needs at most one organisation, and this database has \
                 {count}. Run with GRUND_ORGANISATIONS=multi, or delete organisations first"
            ),
        }
    }
    keys::check_at_start(
        &pool,
        &keys::Keys::new(std::sync::Arc::new(secret.clone())),
        config.dev_mode,
    )
    .await?;
    let events = mire::EventStore::new(pool.clone());
    mire_sagas::migrate(&events).await?;
    let nats = connect_nats(&config).await?;

    let extra: Vec<(&'static str, &'static str)> = extensions
        .iter()
        .flat_map(|e| e.templates().iter().copied())
        .collect();
    let templates = templates::Templates::new(&extra)?;
    let mailer = services::mail::Mailer::new(&config, templates.clone())?;
    let reporter = services::insights::Reporter::new(&config.insights)?;
    let secret = std::sync::Arc::new(secret);
    let certificates = certificates::Certificates::new(&config, pool.clone(), secret.clone());
    certificates.start().await?;
    let hearing = std::sync::Arc::new(hearing::Hearing::new(chrono::Utc::now()));
    let health = health::registry(
        pool.clone(),
        hearing.clone(),
        nats.clone(),
        mailer.configured(),
        &certificates,
        &config,
    );
    let entitlements = entitlements(&config)?;
    let grace = config.shutdown_grace;
    let config_billing = config.billing.clone();
    let capacity = services::capacity::Capacity::new(&config.capacity)?;
    let deletions = sagas::Deletions::new(events.clone());
    let state = State {
        config: std::sync::Arc::new(config),
        pool,
        events,
        nats,
        secret,
        certificates,
        health,
        passwords: services::passwords::Passwords::new()?,
        templates,
        entitlements: std::sync::Arc::new(entitlements),
        billing: services::billing::Billing::new(&config_billing)?,
        capacity,
        deletions,
        extensions: std::sync::Arc::new(extensions),
        started: health::started(),
        wakes: wakes::Wakes::default(),
        hearing,
    };

    if state.config.social.social_login && state.extensions.is_empty() {
        tracing::warn!(
            "GRUND_SOCIAL_LOGIN is on, but this build has no commercial features; offering password sign-in only"
        );
    }
    tracing::info!(
        insights = state.config.insights.enabled(),
        billing = state.billing.enabled(),
        capacity = state.capacity.enabled(),
        extensions = ?state.extensions.iter().map(|e| e.name()).collect::<Vec<_>>(),
        revision = health::revision(),
        version = health::VERSION,
        "grund starting"
    );
    notmad::Mad::builder()
        .add(server::Http::new(state.clone()))
        .add(certificates::Https::new(state.clone()))
        .add(certificates::Redirect::new(state.clone()))
        .add(relay::RelayServer::new(state.clone()))
        .add(health::Checks::new(&state))
        .add(projections::Projections::new(&state))
        .add(services::apps::AppReconciler::new(state.clone()))
        .add(services::entry::EntryKeys::new(state.clone()))
        .add(services::maintenance::Sweeper::new(state.clone()))
        .add(certificates::CertificateWork::new(&state))
        .add(sagas::DeletionWorker::new(&state))
        .add(services::outbox::OutboxDrain::new(
            state.clone(),
            mailer,
            reporter,
        ))
        .cancellation(Some(grace))
        .run()
        .await?;
    Ok(())
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
