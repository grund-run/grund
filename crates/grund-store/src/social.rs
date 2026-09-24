//! Social sign-in flows (migration 0002). Every read and transition checks
//! the stage and the expiry in the statement itself.

use std::time::Duration;

use sqlx::PgExecutor;
use uuid::Uuid;

/// A flow waiting for the provider's callback.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Authorizing {
    pub provider: String,
    pub state: String,
    pub pkce_verifier: String,
    pub nonce: String,
}

/// A verified identity waiting for the person's next step.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Pending {
    pub provider: String,
    pub stage: String,
    pub subject: String,
    pub email: String,
    pub suggested_name: Option<String>,
    pub account_id: Option<Uuid>,
}

/// Starts a flow.
pub async fn start(
    executor: impl PgExecutor<'_>,
    flow_digest: &[u8; 32],
    provider: &str,
    state: &str,
    pkce_verifier: &str,
    nonce: &str,
    ttl: Duration,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO grund_social_flows (flow_digest, provider, stage, state, pkce_verifier, nonce, expires_at) \
         VALUES ($1, $2, 'authorizing', $3, $4, $5, clock_timestamp() + make_interval(secs => $6))",
    )
    .bind(&flow_digest[..])
    .bind(provider)
    .bind(state)
    .bind(pkce_verifier)
    .bind(nonce)
    .bind(ttl.as_secs_f64())
    .execute(executor)
    .await?;
    Ok(())
}

/// Takes an authorizing flow for its callback, once: the flow is marked done
/// in the same statement, so a second callback finds nothing.
pub async fn take_authorizing(
    executor: impl PgExecutor<'_>,
    flow_digest: &[u8; 32],
    provider: &str,
) -> Result<Option<Authorizing>, sqlx::Error> {
    sqlx::query_as::<_, Authorizing>(
        "UPDATE grund_social_flows SET stage = 'done' \
         WHERE flow_digest = $1 AND provider = $2 AND stage = 'authorizing' AND expires_at > clock_timestamp() \
         RETURNING provider, state, pkce_verifier, nonce",
    )
    .bind(&flow_digest[..])
    .bind(provider)
    .fetch_optional(executor)
    .await
}

/// Parks a verified identity at `stage` (`choose_username` or `link`).
#[allow(clippy::too_many_arguments)]
pub async fn park(
    executor: impl PgExecutor<'_>,
    flow_digest: &[u8; 32],
    stage: &str,
    subject: &str,
    email: &str,
    suggested_name: Option<&str>,
    account_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE grund_social_flows SET stage = $2, subject = $3, email = $4, suggested_name = $5, account_id = $6 \
         WHERE flow_digest = $1 AND stage = 'done' AND expires_at > clock_timestamp()",
    )
    .bind(&flow_digest[..])
    .bind(stage)
    .bind(subject)
    .bind(email)
    .bind(suggested_name)
    .bind(account_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// The identity parked at `stage`, without using it.
pub async fn pending(
    executor: impl PgExecutor<'_>,
    flow_digest: &[u8; 32],
    stage: &str,
) -> Result<Option<Pending>, sqlx::Error> {
    sqlx::query_as::<_, Pending>(
        "SELECT provider, stage, subject, email, suggested_name, account_id FROM grund_social_flows \
         WHERE flow_digest = $1 AND stage = $2 AND expires_at > clock_timestamp()",
    )
    .bind(&flow_digest[..])
    .bind(stage)
    .fetch_optional(executor)
    .await
}

/// Uses the identity parked at `stage`, once.
pub async fn finish(
    executor: impl PgExecutor<'_>,
    flow_digest: &[u8; 32],
    stage: &str,
) -> Result<Option<Pending>, sqlx::Error> {
    sqlx::query_as::<_, Pending>(
        "UPDATE grund_social_flows SET stage = 'done' \
         WHERE flow_digest = $1 AND stage = $2 AND expires_at > clock_timestamp() \
         RETURNING provider, stage, subject, email, suggested_name, account_id",
    )
    .bind(&flow_digest[..])
    .bind(stage)
    .fetch_optional(executor)
    .await
}

/// Deletes flows that expired more than an hour ago. Bounded per pass.
pub async fn sweep(executor: impl PgExecutor<'_>) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM grund_social_flows WHERE flow_digest IN ( \
           SELECT flow_digest FROM grund_social_flows \
           WHERE expires_at < clock_timestamp() - interval '1 hour' LIMIT 1000)",
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}
