//! Opening the PostgreSQL pool.

use std::{
    net::SocketAddr,
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::Context;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tokio_util::sync::CancellationToken;

use crate::config::DatabaseArgs;

/// The longest pause between two tries while waiting for PostgreSQL at start.
pub const LONGEST_PAUSE: Duration = Duration::from_secs(10);

/// Connects with the configured bounds: a pool that never waits longer than
/// `acquire_timeout` for a connection, and a `statement_timeout` on every
/// connection, so one stuck statement cannot hold a request forever.
pub async fn connect(args: &DatabaseArgs) -> anyhow::Result<PgPool> {
    let options = options(args)?;
    open(args, options).await
}

/// Connects as [`connect`] does, but when PostgreSQL does not answer, tries
/// again for up to `wait` (GRUND_DATABASE_WAIT) before failing with the
/// last error, which names DATABASE_URL. A configuration that cannot work
/// (a bad URL, an unreadable password file) fails at once.
///
/// While it waits, `listen` answers `/health/live` with 200 and everything
/// else, readiness included, with 503: an orchestrator's liveness probe
/// does not restart a process that is only waiting, and readiness says the
/// database is what is missing. The listener is closed before this returns,
/// so the HTTP server can bind the address.
pub async fn connect_waiting(
    args: &DatabaseArgs,
    wait: Duration,
    listen: SocketAddr,
) -> anyhow::Result<PgPool> {
    let options = options(args)?;
    let mut last = match open(args, options.clone()).await {
        Ok(pool) => return Ok(pool),
        Err(error) if wait.is_zero() => return Err(error),
        Err(error) => error,
    };
    tracing::warn!(
        error = format!("{last:#}"),
        wait_s = wait.as_secs(),
        "PostgreSQL does not answer; waiting for it (GRUND_DATABASE_WAIT)"
    );
    let stop = CancellationToken::new();
    let standin = tokio::spawn(stand_in(listen, stop.clone()));
    let deadline = Instant::now() + wait;
    let mut attempt = 0u32;
    let outcome = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break Err(last);
        }
        let pause = crate::restart::wait_after(attempt, crate::acme::unit_random())
            .min(LONGEST_PAUSE)
            .min(remaining);
        tokio::time::sleep(pause).await;
        attempt += 1;
        match open(args, options.clone()).await {
            Ok(pool) => break Ok(pool),
            Err(error) => {
                tracing::info!(
                    attempt,
                    left_s = deadline.saturating_duration_since(Instant::now()).as_secs(),
                    error = format!("{error:#}"),
                    "PostgreSQL still does not answer"
                );
                last = error;
            }
        }
    };
    stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), standin).await;
    match outcome {
        Ok(pool) => {
            tracing::info!(attempt, "PostgreSQL answers; starting");
            Ok(pool)
        }
        Err(error) => Err(error.context(format!(
            "PostgreSQL did not answer within GRUND_DATABASE_WAIT ({} s)",
            wait.as_secs()
        ))),
    }
}

fn options(args: &DatabaseArgs) -> anyhow::Result<PgConnectOptions> {
    let mut options = PgConnectOptions::from_str(&args.database_url)
        .context("DATABASE_URL is not a valid PostgreSQL URL")?
        .application_name("grund")
        .options([(
            "statement_timeout",
            format!("{}", args.database_statement_timeout.as_millis()),
        )]);
    if let Some(path) = &args.database_password_file {
        let password = std::fs::read_to_string(path)
            .with_context(|| format!("read GRUND_DATABASE_PASSWORD_FILE {}", path.display()))?;
        options = options.password(password.trim_end_matches(['\n', '\r']));
    }
    Ok(options)
}

async fn open(args: &DatabaseArgs, options: PgConnectOptions) -> anyhow::Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(args.database_max_connections)
        .acquire_timeout(args.database_acquire_timeout)
        .connect_with(options)
        .await
        .context("connect to PostgreSQL (DATABASE_URL)")
}

async fn stand_in(listen: SocketAddr, stop: CancellationToken) {
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::warn!(%listen, %error, "could not answer health checks while waiting for PostgreSQL");
            return;
        }
    };
    let app = axum::Router::new()
        .route("/health/live", axum::routing::get(crate::health::live))
        .fallback(crate::health::waiting_for_database);
    if let Err(error) = axum::serve(listener, app)
        .with_graceful_shutdown(async move { stop.cancelled().await })
        .await
    {
        tracing::warn!(%error, "the listener answering while waiting for PostgreSQL stopped");
    }
}
