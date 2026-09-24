//! Health, through nostatus (Kasper, 2026-09-24; skills DECISIONS D-4).
//!
//! nostatus owns the checks and the loop that runs them: a `StatusRegistry`
//! of named checks with a severity each, run every GRUND_HEALTH_INTERVAL by
//! the [`Checks`] component. The HTTP answers read the last results and never
//! run a check themselves, so probing readiness costs no database round trip
//! and a flood of probes cannot become load on PostgreSQL.
//!
//! We serve our own two routes rather than `nostatus::axum_routes`: its
//! readiness answer has no body (we report the revision there, which is how
//! a deployment is proven), and its `/health` runs every check on demand for
//! any caller and returns error text.

use std::time::Instant;

use axum::{
    Json,
    extract::State as AxumState,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use nostatus::{CheckInfo, CheckStatus, Severity, StatusError, StatusRegistry, StatusState};
use notmad::{Component, ComponentInfo, MadError};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::state::State;

/// The commit this binary was built from.
pub const REVISION: &str = env!("GRUND_BUILD_REVISION");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Builds the registry: what readiness depends on, and how much.
///
/// PostgreSQL is critical: without it no request can be served. NATS, when
/// configured, is major: it only makes background work start sooner and
/// polling is correct without it, so its loss degrades readiness but never
/// takes the instance out of rotation.
pub fn registry(
    pool: sqlx::PgPool,
    nats: Option<async_nats::Client>,
    config: &crate::config::ServeConfig,
) -> StatusState {
    let mut registry = StatusRegistry::builder();
    registry
        .interval(config.health_interval)
        .check_timeout(std::time::Duration::from_secs(2));

    registry.add_fn(
        CheckInfo::new("postgres")
            .description("SELECT 1 on the pool requests use")
            .severity(Severity::Critical),
        move || {
            let pool = pool.clone();
            async move {
                sqlx::query("SELECT 1")
                    .execute(&pool)
                    .await
                    .map_err(|error| StatusError::from(anyhow::Error::from(error)))?;
                Ok(CheckStatus::Healthy)
            }
        },
    );

    if let Some(client) = nats {
        registry.add_fn(
            CheckInfo::new("nats")
                .description("wake-ups for background work; polling covers an outage")
                .severity(Severity::Major),
            move || {
                let client = client.clone();
                async move {
                    Ok(match client.connection_state() {
                        async_nats::connection::State::Connected => CheckStatus::Healthy,
                        _ => CheckStatus::Unhealthy,
                    })
                }
            },
        );
    }
    registry.build()
}

/// Runs the checks on their interval. Added after the HTTP listener, so it
/// keeps readiness current while requests drain.
pub struct Checks {
    status: StatusState,
}

impl Checks {
    pub fn new(state: &State) -> Self {
        Self {
            status: state.health.clone(),
        }
    }
}

impl Component for Checks {
    fn info(&self) -> ComponentInfo {
        "grund/health".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        self.status.run(cancellation).await;
        Ok(())
    }
}

/// Liveness checks nothing: no dependency outage is fixed by restarting grund,
/// so none may restart it.
pub async fn live() -> Response {
    no_store(Json(serde_json::json!({ "status": "ok" })))
}

#[derive(Serialize)]
struct Readiness {
    status: CheckStatus,
    revision: &'static str,
    version: &'static str,
    uptime_seconds: u64,
    checks: Vec<ReadinessCheck>,
}

#[derive(Serialize)]
struct ReadinessCheck {
    name: String,
    severity: Severity,
    status: CheckStatus,
}

/// Readiness from the last completed checks: 503 when a critical dependency
/// is down (or before the first pass has finished), 200 otherwise. The body
/// says what is deployed and why the answer is what it is. Check names and
/// states only: error text can carry hostnames and stays in the log.
pub async fn ready(AxumState(state): AxumState<State>) -> Response {
    let snapshot = state.health.snapshot().await;
    let body = Readiness {
        status: snapshot.overall_status,
        revision: REVISION,
        version: VERSION,
        uptime_seconds: state.started.elapsed().as_secs(),
        checks: snapshot
            .checks
            .into_iter()
            .map(|check| ReadinessCheck {
                name: check.info.name,
                severity: check.info.severity,
                status: check.status,
            })
            .collect(),
    };
    let status = match body.status {
        CheckStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
        CheckStatus::Healthy | CheckStatus::Degraded => StatusCode::OK,
    };
    no_store((status, Json(body)))
}

fn no_store(body: impl IntoResponse) -> Response {
    let mut response = body.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// When the process started, for readiness.
pub fn started() -> Instant {
    Instant::now()
}
