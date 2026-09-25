//! Reporting confirmed accounts to a grund insights service, for the people
//! who operate this instance (GRUND_INSIGHTS_URL and GRUND_INSIGHTS_TOKEN).
//!
//! Off unless both are set, and then nothing is queued, so an instance
//! without them sends nothing anywhere. When on, the unit of work that
//! confirms an address also queues one outbox row for that account, and the
//! outbox drain posts it to `<url>/v1/accounts` after commit, at least once.
//! insights records each account once, however many copies arrive.
//!
//! The report holds the username, the address, how the account signed up,
//! when it registered and when the address was confirmed. Nothing else: no
//! password, session, client address or organisation.

use std::time::Duration;

use anyhow::Context;
use grund_store::{
    accounts,
    outbox::{self, Claimed, Kind},
};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{config::InsightsArgs, state::State};

/// How the account was created: `password`, or the sign-in provider's id.
pub const PASSWORD: &str = "password";

/// Queues the report for an account whose address is confirmed, inside the
/// caller's transaction. Does nothing when reporting is off, or when the
/// account is not confirmed. One row per account: a second call for the same
/// account is ignored.
pub async fn queue_account(
    state: &State,
    connection: &mut PgConnection,
    account_id: Uuid,
    method: &str,
) -> Result<(), sqlx::Error> {
    if !state.config.insights.enabled() {
        return Ok(());
    }
    let Some(account) = accounts::confirmed(&mut *connection, account_id).await? else {
        return Ok(());
    };
    let payload = serde_json::json!({
        "instance": state.config.public_origin().host,
        "account_id": account.account_id,
        "username": account.username,
        "method": method,
        "registered_at": account.registered_at,
        "verified_at": account.verified_at,
    });
    outbox::enqueue(
        connection,
        Uuid::new_v5(&account_id, Kind::InsightsAccount.as_str().as_bytes()),
        Kind::InsightsAccount,
        &account.email,
        &payload,
    )
    .await
}

/// Why a report was not delivered.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// Reporting was turned off after the row was queued: drop it.
    #[error("insights is not configured")]
    NotConfigured,
    /// insights refused the report as invalid; retrying will not help.
    #[error("refused by insights")]
    Permanent,
    /// insights was unreachable, refused the token, or failed this time.
    #[error("delivery to insights failed; will retry")]
    Transient,
}

/// Posts reports to insights.
#[derive(Clone)]
pub struct Reporter {
    target: Option<(String, String)>,
    http: reqwest::Client,
}

impl Reporter {
    pub fn new(config: &InsightsArgs) -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .user_agent("grund")
            .build()
            .context("build the HTTP client for insights")?;
        let target = match (&config.insights_url, &config.insights_token) {
            (Some(url), Some(token)) => Some((format!("{url}/v1/accounts"), token.clone())),
            _ => None,
        };
        Ok(Self { target, http })
    }

    /// Delivers one claimed row. The address is the row's recipient.
    pub async fn send(&self, row: &Claimed) -> Result<(), ReportError> {
        let Some((url, token)) = &self.target else {
            return Err(ReportError::NotConfigured);
        };
        let mut body = row.payload.clone();
        body["email"] = row.recipient.clone().into();
        let response = self
            .http
            .post(url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|_| ReportError::Transient)?;
        match response.status().as_u16() {
            200 | 201 => Ok(()),
            400 | 413 | 415 => Err(ReportError::Permanent),
            status => {
                if status == 401 {
                    tracing::warn!(
                        "insights refused GRUND_INSIGHTS_TOKEN; reports wait until it matches INSIGHTS_INGEST_TOKEN"
                    );
                }
                Err(ReportError::Transient)
            }
        }
    }
}
