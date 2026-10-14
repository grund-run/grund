//! The optional billing service receives organisation lifecycle changes through
//! the durable outbox.
//! Extensions own customer actions and operator UI. The public contract is
//! `proto/grund/billing/v1`.
//!
//! Without GRUND_BILLING_URL (every self-hosted instance) the shim is
//! [`Billing::Free`]: every organisation is free, deleting is allowed, and
//! nothing is queued. Settings use a process-local billing account cache.
//! Ordinary settings refresh in the background; an extension-owned billing
//! page may wait up to two seconds. Actions and deletion fail closed.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use grund_store::outbox::{self, Claimed, Kind};
use parking_lot::Mutex;
use sqlx::{PgConnection, PgPool};
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
    Account(Arc<AccountDetails>),
    /// No recent account is available from the billing service.
    Unavailable,
}

/// A fetched account shared by cache readers without copying its strings.
#[derive(Debug, PartialEq, Eq)]
pub struct AccountDetails {
    pub plan: String,
    pub pending_plan: String,
    pub past_due: bool,
    pub cancelled: bool,
    pub complimentary: bool,
    pub complimentary_reason: String,
    pub complimentary_expires_at: Option<String>,
    pub complimentary_scheduled_plan: String,
    pub complimentary_scheduled: bool,
    pub complimentary_effective_at: Option<String>,
    pub operator_url: String,
    pub provider_subscription_id: String,
    pub total_amount_cents: i64,
    pub currency: String,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub cancel_at_period_end: bool,
    pub usage: Option<UsageDetails>,
    pub invoices: Vec<InvoiceDetails>,
}

/// Observed usage from delivered hourly provider samples in the current period.
#[derive(Debug, PartialEq, Eq)]
pub struct UsageDetails {
    pub machines_billed: i32,
    pub machine_hours: i64,
    pub sampled_hours: i64,
    pub expected_hours: i64,
    pub estimated_amount_cents: Option<i64>,
    pub first_machine_credit_cents: i64,
}

/// An observed provider order; a document exists only when reported available.
#[derive(Debug, PartialEq, Eq)]
pub struct InvoiceDetails {
    pub id: String,
    pub date: Option<String>,
    pub observed_at: Option<String>,
    pub amount_cents: i64,
    pub currency: String,
    pub status: String,
    pub document_available: bool,
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

#[derive(Debug, thiserror::Error)]
pub enum BillingError {
    #[error("billing is unavailable")]
    Unavailable,
    #[error("billing returned an invalid redirect")]
    InvalidRedirect,
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
    redirect_origins: Vec<String>,
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
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("grund")
            .build()
            .context("build the HTTP client for billing")?;
        Ok(Billing::Remote(Arc::new(Remote {
            url: url.clone(),
            token: token.clone(),
            redirect_origins: config
                .billing_redirect_origins
                .as_deref()
                .unwrap_or("")
                .split(',')
                .filter(|origin| !origin.is_empty())
                .map(str::to_owned)
                .collect(),
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
                    .map(|answer| view_from_response(&answer));
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
    pub async fn account_now(&self, organisation_id: Uuid) -> BillingView {
        let Billing::Remote(remote) = self else {
            return BillingView::Free;
        };
        let body = serde_json::json!({"organisationId": organisation_id.to_string()});
        match remote.call("GetAccount", &body, Some(READ_TIMEOUT)).await {
            Ok(answer) => {
                let view = view_from_response(&answer);
                remote.accounts.lock().remove(&organisation_id);
                view
            }
            Err(error) => {
                tracing::warn!(%error, "billing account unavailable");
                BillingView::Unavailable
            }
        }
    }

    /// Waits for one account read when a billing page has no usable cached value.
    /// Warm accounts keep the background-refresh behaviour of ordinary settings.
    pub async fn account_for_page(&self, organisation_id: Uuid) -> BillingView {
        let Billing::Remote(remote) = self else {
            return BillingView::Free;
        };
        let warm = remote
            .accounts
            .lock()
            .get(&organisation_id)
            .is_some_and(|account| {
                account
                    .fetched_at
                    .is_some_and(|at| at.elapsed() <= ACCOUNT_MAX_STALE)
                    && account
                        .view
                        .as_ref()
                        .is_some_and(|view| !matches!(view, BillingView::Unavailable))
            });
        if warm {
            return self.account(organisation_id);
        }
        let view = self.account_now(organisation_id).await;
        if !matches!(view, BillingView::Unavailable) {
            let now = Instant::now();
            remote.accounts.lock().insert(
                organisation_id,
                CachedAccount {
                    view: Some(view.clone()),
                    fetched_at: Some(now),
                    refresh_after: now + ACCOUNT_REFRESH,
                    refreshing: false,
                },
            );
        }
        view
    }

    /// Calls a method of the optional external billing service. Business
    /// actions and their payloads belong to the extension using this seam.
    pub async fn request(
        &self,
        method: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, BillingError> {
        let Billing::Remote(remote) = self else {
            return Err(BillingError::Unavailable);
        };
        remote.call(method, body, None).await.map_err(|error| {
            tracing::warn!(%error, method, "billing request unavailable");
            BillingError::Unavailable
        })
    }

    /// Accepts only redirects to a configured HTTPS origin.
    pub fn redirect(&self, value: &serde_json::Value) -> Result<String, BillingError> {
        let Billing::Remote(remote) = self else {
            return Err(BillingError::Unavailable);
        };
        remote.redirect(value)
    }

    /// Checks a link from the external billing service without following it.
    pub fn allows_redirect(&self, url: &str) -> bool {
        matches!(self, Billing::Remote(remote) if remote.allows_redirect(url))
    }

    /// Invalidates an account after an extension changes its billing state.
    pub fn invalidate_account(&self, organisation_id: Uuid) {
        if let Billing::Remote(remote) = self {
            remote.accounts.lock().remove(&organisation_id);
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
        let method = match Kind::parse(&row.kind) {
            Some(Kind::BillingMachineCount) => "RecordMachineCount",
            Some(Kind::BillingMachineChange) => "RecordMachineChange",
            _ => "RecordOrganisation",
        };
        match remote.call(method, &row.payload, None).await {
            Ok(_) => Ok(()),
            Err(CallError::Status(400 | 404 | 413 | 415)) if method == "RecordOrganisation" => {
                Err(RecordError::Permanent)
            }
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

impl Remote {
    fn allows_redirect(&self, url: &str) -> bool {
        let Ok(parsed) = reqwest::Url::parse(url) else {
            return false;
        };
        parsed.scheme() == "https"
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && self
                .redirect_origins
                .iter()
                .any(|origin| origin == &parsed.origin().ascii_serialization())
    }

    fn redirect(&self, value: &serde_json::Value) -> Result<String, BillingError> {
        let url = value.as_str().ok_or(BillingError::InvalidRedirect)?;
        if !self.allows_redirect(url) {
            tracing::warn!("billing returned a disallowed redirect");
            return Err(BillingError::InvalidRedirect);
        }
        Ok(url.to_owned())
    }
}

fn json_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_str()
        .and_then(|value| value.parse().ok())
        .or_else(|| value.as_i64())
}

fn view_from_response(answer: &serde_json::Value) -> BillingView {
    let account = &answer["account"];
    let Some(plan) = account["plan"].as_str().filter(|plan| !plan.is_empty()) else {
        return BillingView::Unavailable;
    };
    if !matches!(
        account["status"].as_str(),
        Some("ACCOUNT_STATUS_ACTIVE" | "ACCOUNT_STATUS_PAST_DUE" | "ACCOUNT_STATUS_CANCELLED")
    ) {
        return BillingView::Unavailable;
    }
    let period_start = account["periodStart"].as_str().map(str::to_owned);
    let period_end = account["periodEnd"].as_str().map(str::to_owned);
    let usage = (period_start.is_some() && period_end.is_some())
        .then(|| account.get("usage"))
        .flatten()
        .filter(|usage| usage.is_object())
        .map(|usage| UsageDetails {
            machines_billed: json_i64(&usage["machinesBilled"])
                .and_then(|count| i32::try_from(count).ok())
                .unwrap_or(0),
            machine_hours: json_i64(&usage["machineHours"]).unwrap_or(0),
            sampled_hours: json_i64(&usage["sampledHours"]).unwrap_or(0),
            expected_hours: json_i64(&usage["expectedHours"]).unwrap_or(0),
            estimated_amount_cents: json_i64(&usage["estimatedAmountCents"]),
            first_machine_credit_cents: json_i64(&usage["firstMachineCreditCents"]).unwrap_or(0),
        });
    let invoices = account["invoices"]
        .as_array()
        .into_iter()
        .flat_map(|invoices| invoices.iter().take(20))
        .filter_map(|invoice| {
            let id = invoice["id"].as_str().filter(|id| !id.is_empty())?;
            let currency = invoice["currency"]
                .as_str()
                .filter(|currency| !currency.is_empty())?;
            let status = invoice["status"]
                .as_str()
                .filter(|status| !status.is_empty())?;
            Some(InvoiceDetails {
                id: id.to_owned(),
                date: invoice["date"].as_str().map(str::to_owned),
                observed_at: invoice["observedAt"].as_str().map(str::to_owned),
                amount_cents: json_i64(&invoice["amountCents"])?,
                currency: currency.to_owned(),
                status: status.to_owned(),
                document_available: invoice["documentAvailable"].as_bool().unwrap_or(false),
            })
        })
        .collect();
    BillingView::Account(Arc::new(AccountDetails {
        plan: plan.to_owned(),
        pending_plan: account["pendingPlan"].as_str().unwrap_or("").to_owned(),
        past_due: account["status"].as_str() == Some("ACCOUNT_STATUS_PAST_DUE"),
        cancelled: account["status"].as_str() == Some("ACCOUNT_STATUS_CANCELLED"),
        complimentary: account["complimentary"].as_bool().unwrap_or(false),
        complimentary_reason: account["complimentaryReason"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
        complimentary_expires_at: account["complimentaryExpiresAt"]
            .as_str()
            .map(str::to_owned),
        complimentary_scheduled_plan: account["complimentaryScheduledPlan"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
        complimentary_scheduled: account["complimentaryScheduled"].as_bool().unwrap_or(false),
        complimentary_effective_at: account["complimentaryEffectiveAt"]
            .as_str()
            .map(str::to_owned),
        operator_url: account["operatorUrl"].as_str().unwrap_or("").to_owned(),
        provider_subscription_id: account["providerSubscriptionId"]
            .as_str()
            .unwrap_or("")
            .to_owned(),
        total_amount_cents: json_i64(&account["totalAmountCents"]).unwrap_or(0),
        currency: account["currency"].as_str().unwrap_or("EUR").to_owned(),
        period_start,
        period_end,
        cancel_at_period_end: account["cancelAtPeriodEnd"].as_bool().unwrap_or(false),
        usage,
        invoices,
    }))
}

/// Enqueues existing live organisations when billing is enabled on a populated
/// instance. The stable event ID makes restart retries safe, and the original
/// creation timestamp prevents a delayed seed from undoing a later rename.
pub async fn queue_existing(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let organisations: Vec<(Uuid, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT organisation_id,slug,created_at FROM grund_organisations WHERE deleted_at IS NULL",
    )
    .fetch_all(&mut *tx)
    .await?;
    for (id, slug, created_at) in organisations {
        let event_id = Uuid::new_v5(&id, b"billing-existing-organisation-v1");
        enqueue_change(&mut tx, event_id, id, &slug, Change::Created, created_at).await?;
    }
    tx.commit().await
}

async fn enqueue_change(
    connection: &mut PgConnection,
    event_id: Uuid,
    organisation_id: Uuid,
    slug: &str,
    change: Change,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
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
    enqueue_change(
        connection,
        Uuid::now_v7(),
        organisation_id,
        slug,
        change,
        at,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{BillingView, view_from_response};

    #[test]
    fn account_decoder_preserves_observed_usage_and_omits_missing_history() {
        let response = serde_json::json!({
            "account": {
                "plan": "Homelab",
                "status": "ACCOUNT_STATUS_ACTIVE",
                "periodStart": "2026-09-01T00:00:00Z",
                "periodEnd": "2026-10-01T00:00:00Z",
                "cancelAtPeriodEnd": true,
                "usage": {
                    "machinesBilled": 2,
                    "machineHours": "59",
                    "sampledHours": "30",
                    "expectedHours": "31",
                    "estimatedAmountCents": "0",
                    "firstMachineCreditCents": "300"
                },
                "invoices": [{
                    "id": "8d6c5ad1-8918-4d69-b8bd-884cae887fad",
                    "date": "2026-09-01T00:00:00Z",
                    "amountCents": "300",
                    "currency": "eur",
                    "status": "paid",
                    "documentAvailable": true
                }]
            }
        });
        let BillingView::Account(details) = view_from_response(&response) else {
            panic!("observed account should remain available");
        };
        assert!(details.cancel_at_period_end);
        let usage = details.usage.as_ref().expect("known period has usage");
        assert_eq!(usage.machine_hours, 59);
        assert_eq!(usage.sampled_hours, 30);
        assert_eq!(usage.expected_hours, 31);
        assert_eq!(usage.estimated_amount_cents, Some(0));
        assert_eq!(usage.first_machine_credit_cents, 300);
        assert_eq!(details.invoices[0].amount_cents, 300);
        assert!(details.invoices[0].document_available);

        let legacy = serde_json::json!({
            "account": {"plan": "Homelab", "status": "ACCOUNT_STATUS_ACTIVE"}
        });
        let BillingView::Account(details) = view_from_response(&legacy) else {
            panic!("older billing backend should still have an account");
        };
        assert!(details.usage.is_none());
        assert!(details.invoices.is_empty());
        assert!(details.period_end.is_none());
    }
}
