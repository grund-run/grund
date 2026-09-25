//! The billing shim (grund-docs design/billing.md). Billing is a separate
//! service that only grund's hosted service runs; grund asks it about an
//! organisation (`GetAccount`, `CheckDeletion`) and tells it, through the
//! outbox, when organisations are created, renamed or deleted
//! (`RecordOrganisation`). The contract is `proto/grund/billing/v1`.
//!
//! Without GRUND_BILLING_URL (every self-hosted instance) the shim is
//! [`Billing::Free`]: every organisation is free, deleting is allowed, and
//! nothing is queued. grund never waits on billing to serve a page: a read
//! that fails or takes over 2 seconds says billing is unavailable and nothing
//! else changes. Only deleting fails closed, because it cannot be undone.

use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, Utc};
use grund_store::outbox::{self, Claimed, Kind};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{config::BillingArgs, state::State};

/// How long a read from the billing service may take before the page says
/// billing is unavailable.
pub const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// An organisation's billing, as its owners see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BillingView {
    /// No billing service: nothing is charged.
    Free,
    Account {
        plan: String,
        past_due: bool,
        manage_url: Option<String>,
    },
    /// The billing service did not answer in time, or answered an error.
    Unavailable,
}

/// Whether an organisation may be deleted, as far as billing is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deletion {
    Allowed,
    Refused(String),
    /// The billing service could not be asked; deletion is refused.
    Unavailable,
}

/// What happened to an organisation, for `RecordOrganisation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Created,
    Renamed,
    Deleted,
}

impl Change {
    fn as_proto(self) -> &'static str {
        match self {
            Change::Created => "ORGANISATION_CHANGE_CREATED",
            Change::Renamed => "ORGANISATION_CHANGE_RENAMED",
            Change::Deleted => "ORGANISATION_CHANGE_DELETED",
        }
    }
}

/// Why a queued change was not delivered.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("billing is not configured")]
    NotConfigured,
    #[error("the billing service refused the change for good")]
    Permanent,
    #[error("the billing service did not take the change; will retry")]
    Transient,
}

/// The billing seam: free, or a billing service.
#[derive(Clone)]
pub enum Billing {
    Free,
    Remote(Remote),
}

/// A configured billing service.
#[derive(Clone)]
pub struct Remote {
    url: String,
    token: String,
    http: reqwest::Client,
}

impl Billing {
    /// The shim this configuration asks for.
    pub fn new(config: &BillingArgs) -> anyhow::Result<Self> {
        let (Some(url), Some(token)) = (&config.billing_url, &config.billing_token) else {
            return Ok(Billing::Free);
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(2))
            .user_agent("grund")
            .build()
            .context("build the HTTP client for billing")?;
        Ok(Billing::Remote(Remote {
            url: url.clone(),
            token: token.clone(),
            http,
        }))
    }

    /// Whether a billing service is configured.
    pub fn enabled(&self) -> bool {
        matches!(self, Billing::Remote(_))
    }

    /// The organisation's billing account.
    pub async fn account(&self, organisation_id: Uuid) -> BillingView {
        let Billing::Remote(remote) = self else {
            return BillingView::Free;
        };
        let body = serde_json::json!({ "organisationId": organisation_id.to_string() });
        match remote.call("GetAccount", &body, Some(READ_TIMEOUT)).await {
            Ok(answer) => {
                let account = &answer["account"];
                BillingView::Account {
                    plan: account["plan"].as_str().unwrap_or("Free").to_string(),
                    past_due: account["status"].as_str() == Some("ACCOUNT_STATUS_PAST_DUE"),
                    manage_url: account["manageUrl"]
                        .as_str()
                        .filter(|url| url.starts_with("https://") || url.starts_with("http://"))
                        .map(str::to_string),
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, %organisation_id, "billing account unavailable");
                BillingView::Unavailable
            }
        }
    }

    /// Whether billing lets the organisation be deleted now.
    pub async fn check_deletion(&self, organisation_id: Uuid) -> Deletion {
        let Billing::Remote(remote) = self else {
            return Deletion::Allowed;
        };
        let body = serde_json::json!({ "organisationId": organisation_id.to_string() });
        match remote
            .call("CheckDeletion", &body, Some(READ_TIMEOUT))
            .await
        {
            Ok(answer) if answer["allowed"].as_bool() == Some(true) => Deletion::Allowed,
            Ok(answer) => Deletion::Refused(
                answer["reason"]
                    .as_str()
                    .filter(|r| !r.is_empty())
                    .unwrap_or("Billing does not allow deleting this organisation yet.")
                    .to_string(),
            ),
            Err(error) => {
                tracing::warn!(error = %error, %organisation_id, "billing could not be asked about a deletion");
                Deletion::Unavailable
            }
        }
    }

    /// Delivers one queued change, from the outbox drain.
    pub async fn record(&self, row: &Claimed) -> Result<(), RecordError> {
        let Billing::Remote(remote) = self else {
            return Err(RecordError::NotConfigured);
        };
        match remote.call("RecordOrganisation", &row.payload, None).await {
            Ok(_) => Ok(()),
            Err(CallError::Status(400 | 404 | 413 | 415)) => Err(RecordError::Permanent),
            Err(CallError::Status(401)) => {
                tracing::warn!(
                    "the billing service refused GRUND_BILLING_TOKEN; changes wait until it is accepted"
                );
                Err(RecordError::Transient)
            }
            Err(_) => Err(RecordError::Transient),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum CallError {
    #[error("unreachable or timed out")]
    Unreachable,
    #[error("answered status {0}")]
    Status(u16),
    #[error("answered something that is not JSON")]
    Body,
}

impl Remote {
    async fn call(
        &self,
        method: &str,
        body: &serde_json::Value,
        timeout: Option<Duration>,
    ) -> Result<serde_json::Value, CallError> {
        let mut request = self
            .http
            .post(format!(
                "{}/grund.billing.v1.BillingService/{method}",
                self.url
            ))
            .bearer_auth(&self.token)
            .header("Connect-Protocol-Version", "1")
            .json(body);
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = request.send().await.map_err(|_| CallError::Unreachable)?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(CallError::Status(status));
        }
        response.json().await.map_err(|_| CallError::Body)
    }
}

/// Queues `RecordOrganisation` for a change, inside the unit of work that
/// made it. Does nothing without a billing service.
pub async fn queue_change(
    state: &State,
    connection: &mut PgConnection,
    organisation_id: Uuid,
    slug: &str,
    change: Change,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    if !state.billing.enabled() {
        return Ok(());
    }
    let event_id = Uuid::now_v7();
    let payload = serde_json::json!({
        "eventId": event_id.to_string(),
        "organisationId": organisation_id.to_string(),
        "slug": slug,
        "change": change.as_proto(),
        "changedAt": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    outbox::enqueue(
        connection,
        event_id,
        Kind::BillingOrganisation,
        "",
        &payload,
    )
    .await
}
