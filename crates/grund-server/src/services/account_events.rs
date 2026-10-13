//! Reports confirmed account events to an optional operator-owned HTTP
//! endpoint. The sign-up transaction queues one outbox row per confirmed
//! account; the drain delivers it after commit and retries failures.
//!
//! An instance without a configured endpoint queues and contacts nothing.
//! The report includes username, address, sign-in method and times, but no
//! password, session, client address or organisation.

use std::time::Duration;

use anyhow::Context;
use grund_store::{
    accounts,
    outbox::{self, Claimed, Kind},
};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{config::AccountEventArgs, state::State};

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
    if !state.config.account_events.enabled() {
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
        Uuid::new_v5(&account_id, Kind::AccountConfirmed.as_str().as_bytes()),
        Kind::AccountConfirmed,
        &account.email,
        &payload,
    )
    .await
}

/// Why a report was not delivered.
#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    /// Reporting was turned off after the row was queued: drop it.
    #[error("account event endpoint is not configured")]
    NotConfigured,
    /// The endpoint refused the report as invalid; retrying will not help.
    #[error("refused by the account event endpoint")]
    Permanent,
    /// The endpoint was unreachable, refused the token, or failed this time.
    #[error("account event delivery failed; will retry")]
    Transient,
}

/// Posts account events to the configured endpoint.
#[derive(Clone)]
pub struct Reporter {
    target: Option<(String, String)>,
    http: reqwest::Client,
}

impl Reporter {
    pub fn new(config: &AccountEventArgs) -> anyhow::Result<Self> {
        grund_tls::install_default();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .user_agent("grund")
            .build()
            .context("build the HTTP client for account events")?;
        let target = config
            .endpoint()
            .map(|(url, token)| (url.to_owned(), token.to_owned()));
        Ok(Self { target, http })
    }

    /// Delivers one claimed row. The address is the row's recipient.
    pub async fn send(&self, row: &Claimed) -> Result<(), ReportError> {
        let Some((url, token)) = &self.target else {
            return Err(ReportError::NotConfigured);
        };
        let mut body = row.payload.clone();
        body["email"] = row.recipient.clone().into();
        let response =
            crate::telemetry::propagate(self.http.post(url).bearer_auth(token).json(&body))
                .send()
                .await
                .map_err(|_| ReportError::Transient)?;
        match response.status().as_u16() {
            200 | 201 => Ok(()),
            400 | 413 | 415 => Err(ReportError::Permanent),
            status => {
                if status == 401 {
                    tracing::warn!(
                        "account event endpoint refused the configured token; reports will retry"
                    );
                }
                Err(ReportError::Transient)
            }
        }
    }
}
