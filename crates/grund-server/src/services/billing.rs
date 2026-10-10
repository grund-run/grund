//! The billing shim (grund-docs design/billing.md). Billing is a separate
//! service that only grund's hosted service runs; grund asks it about an
//! organisation (`GetAccount`, `CheckDeletion`) and tells it, through the
//! outbox, when organisations are created, renamed or deleted
//! (`RecordOrganisation`). The contract is `proto/grund/billing/v1`.
//!
//! Without GRUND_BILLING_URL (every self-hosted instance) the shim is
//! [`Billing::Free`]: every organisation is free, deleting is allowed, and
//! nothing is queued. Settings use a process-local billing account cache:
//! a missing or expired account refreshes in the background, never on the
//! page's critical path. Only deleting fails closed when billing is down.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use grund_store::outbox::{self, Claimed, Kind};
use parking_lot::Mutex;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{config::BillingArgs, state::State};

/// How long a background account read or a deletion check may take.
pub const READ_TIMEOUT: Duration = Duration::from_secs(2);

const ACCOUNT_REFRESH: Duration = Duration::from_secs(60);
const ACCOUNT_RETRY: Duration = Duration::from_secs(15);
const ACCOUNT_MAX_STALE: Duration = Duration::from_secs(300);

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
    /// No recent account is available from the billing service.
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
    Remote(Arc<Remote>),
}

/// A configured billing service.
pub struct Remote {
    url: String,
    token: String,
    http: reqwest::Client,
    accounts: Mutex<HashMap<Uuid, CachedAccount>>,
}

struct CachedAccount {
    view: Option<BillingView>,
    fetched_at: Option<Instant>,
    refresh_after: Instant,
    refreshing: bool,
}

impl Billing {
    /// The shim this configuration asks for.
    pub fn new(config: &BillingArgs) -> anyhow::Result<Self> {
        let (Some(url), Some(token)) = (&config.billing_url, &config.billing_token) else {
            return Ok(Billing::Free);
        };
        grund_tls::install_default();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(2))
            .user_agent("grund")
            .build()
            .context("build the HTTP client for billing")?;
        Ok(Billing::Remote(Arc::new(Remote {
            url: url.clone(),
            token: token.clone(),
            http,
            accounts: Mutex::new(HashMap::new()),
        })))
    }

    /// Whether a billing service is configured.
    pub fn enabled(&self) -> bool {
        matches!(self, Billing::Remote(_))
    }

    /// Returns the last recent account without waiting for the billing service.
    /// Missing or expired accounts trigger one background refresh per organisation.
    pub fn account(&self, organisation_id: Uuid) -> BillingView {
        let Billing::Remote(remote) = self else {
            return BillingView::Free;
        };
        let (view, refresh) = {
            let mut accounts = remote.accounts.lock();
            let now = Instant::now();
            let account = accounts
                .entry(organisation_id)
                .or_insert_with(|| CachedAccount {
                    view: None,
                    fetched_at: None,
                    refresh_after: now,
                    refreshing: false,
                });
            let view = account
                .fetched_at
                .filter(|fetched_at| now.duration_since(*fetched_at) <= ACCOUNT_MAX_STALE)
                .and_then(|_| account.view.clone())
                .unwrap_or(BillingView::Unavailable);
            let refresh = !account.refreshing && now >= account.refresh_after;
            if refresh {
                account.refreshing = true;
            }
            (view, refresh)
        };
        if refresh {
            let remote = remote.clone();
            tokio::spawn(async move {
                let body = serde_json::json!({ "organisationId": organisation_id.to_string() });
                let result = remote
                    .call("GetAccount", &body, Some(READ_TIMEOUT))
                    .await
                    .map(|answer| {
                        let billing_account = &answer["account"];
                        BillingView::Account {
                            plan: billing_account["plan"]
                                .as_str()
                                .unwrap_or("Free")
                                .to_string(),
                            past_due: billing_account["status"].as_str()
                                == Some("ACCOUNT_STATUS_PAST_DUE"),
                            manage_url: billing_account["manageUrl"]
                                .as_str()
                                .filter(|url| {
                                    url.starts_with("https://") || url.starts_with("http://")
                                })
                                .map(str::to_string),
                        }
                    });
                let now = Instant::now();
                if let Err(error) = &result {
                    tracing::warn!(error = %error, "billing account unavailable");
                }
                let mut accounts = remote.accounts.lock();
                let account = accounts
                    .get_mut(&organisation_id)
                    .expect("refreshing account exists");
                account.refreshing = false;
                match result {
                    Ok(view) => {
                        account.view = Some(view);
                        account.fetched_at = Some(now);
                        account.refresh_after = now + ACCOUNT_REFRESH;
                    }
                    Err(_) => {
                        account.refresh_after = now + ACCOUNT_RETRY;
                    }
                }
            });
        }
        view
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
        let response = crate::telemetry::propagate(request)
            .send()
            .await
            .map_err(|_| CallError::Unreachable)?;
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
