//! The optional billing service receives organisation lifecycle changes and
//! own-machine transitions and hourly counts through the durable outbox.
//! Account changes and redirects are requested only from owner or operator
//! handlers; the contract is `proto/grund/billing/v1`.
//!
//! Without GRUND_BILLING_URL (every self-hosted instance) the shim is
//! [`Billing::Free`]: every organisation is free, deleting is allowed, and
//! nothing is queued. Settings use a process-local billing account cache:
//! a missing or expired account refreshes in the background, never on an
//! ordinary page's critical path. Billing actions and deletion fail closed.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use chrono::{DateTime, Timelike, Utc};
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

pub struct Complimentary<'a> {
    pub organisation_id: Uuid,
    pub enabled: bool,
    pub plan: &'a str,
    pub reason: &'a str,
    pub expires_at: Option<&'a str>,
    pub actor_id: Uuid,
    pub key: Uuid,
}

pub struct HostedChange<'a> {
    pub organisation_id: Uuid,
    pub order_id: Uuid,
    pub machine_id: Uuid,
    pub size: &'a str,
    pub region: &'a str,
    pub change: &'a str,
    pub at: DateTime<Utc>,
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

    /// Only an exact configured HTTPS origin may be linked from operator UI.
    pub fn trusted_operator_url(&self, url: &str, subscription_id: &str) -> bool {
        matches!(self, Billing::Remote(remote)
            if Uuid::parse_str(subscription_id).is_ok() && remote.allows_redirect(url))
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

    pub async fn checkout(
        &self,
        organisation_id: Uuid,
        plan: &str,
        success_url: &str,
        key: Uuid,
    ) -> Result<String, BillingError> {
        let Billing::Remote(remote) = self else {
            return Err(BillingError::Unavailable);
        };
        let response = remote
            .call(
                "BeginCheckout",
                &serde_json::json!({
                    "organisationId": organisation_id.to_string(), "plan": plan,
                    "successUrl": success_url, "idempotencyKey": key.to_string(),
                }),
                None,
            )
            .await
            .map_err(|error| {
                tracing::warn!(%error, "billing checkout unavailable");
                BillingError::Unavailable
            })?;
        remote.redirect(&response["url"])
    }

    pub async fn change_plan(
        &self,
        organisation_id: Uuid,
        plan: &str,
        key: Uuid,
    ) -> Result<(), BillingError> {
        self.mutate("ChangePlan", serde_json::json!({
            "organisationId": organisation_id.to_string(), "plan": plan, "idempotencyKey": key.to_string()
        }), organisation_id).await
    }

    pub async fn cancel(&self, organisation_id: Uuid, key: Uuid) -> Result<(), BillingError> {
        self.mutate(
            "CancelSubscription",
            serde_json::json!({
                "organisationId": organisation_id.to_string(), "idempotencyKey": key.to_string()
            }),
            organisation_id,
        )
        .await
    }

    pub async fn portal(
        &self,
        organisation_id: Uuid,
        return_url: &str,
        key: Uuid,
    ) -> Result<String, BillingError> {
        let Billing::Remote(remote) = self else {
            return Err(BillingError::Unavailable);
        };
        let response = remote.call("OpenPortal", &serde_json::json!({
            "organisationId": organisation_id.to_string(), "returnUrl": return_url, "idempotencyKey": key.to_string()
        }), None).await.map_err(|error| {
            tracing::warn!(%error, "billing portal unavailable");
            BillingError::Unavailable
        })?;
        remote.redirect(&response["url"])
    }

    pub async fn complimentary(&self, params: Complimentary<'_>) -> Result<(), BillingError> {
        self.mutate(
            "SetComplimentary",
            serde_json::json!({
                "organisationId": params.organisation_id.to_string(),
                "enabled": params.enabled, "plan": params.plan,
                "reason": params.reason, "expiresAt": params.expires_at,
                "actorId": params.actor_id.to_string(), "idempotencyKey": params.key.to_string()
            }),
            params.organisation_id,
        )
        .await
    }

    async fn mutate(
        &self,
        method: &str,
        body: serde_json::Value,
        organisation_id: Uuid,
    ) -> Result<(), BillingError> {
        let Billing::Remote(remote) = self else {
            return Err(BillingError::Unavailable);
        };
        remote.call(method, &body, None).await.map_err(|error| {
            tracing::warn!(%error, method, "billing change unavailable");
            BillingError::Unavailable
        })?;
        remote.accounts.lock().remove(&organisation_id);
        Ok(())
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
    BillingView::Account(Arc::new(AccountDetails {
        plan: plan.to_owned(),
        pending_plan: account["pendingPlan"].as_str().unwrap_or("").to_owned(),
        past_due: account["status"].as_str() == Some("ACCOUNT_STATUS_PAST_DUE"),
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
        total_amount_cents: account["totalAmountCents"]
            .as_str()
            .and_then(|value| value.parse().ok())
            .or_else(|| account["totalAmountCents"].as_i64())
            .unwrap_or(0),
        currency: account["currency"].as_str().unwrap_or("EUR").to_owned(),
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

pub async fn sample_machine_counts(state: &State) -> Result<(), sqlx::Error> {
    if !state.billing.enabled() {
        return Ok(());
    }
    let sampled_at = (Utc::now() - chrono::Duration::hours(1))
        .with_minute(0)
        .and_then(|at| at.with_second(0))
        .and_then(|at| at.with_nanosecond(0))
        .expect("UTC hour");
    enqueue_completed_hour(&state.pool, sampled_at).await
}

/// Records own-machine inventory as of the end of a completed UTC hour.
/// Registration and revocation timestamps preserve historical inventory even
/// when machines change again before the sampler runs.
pub async fn enqueue_completed_hour(
    pool: &PgPool,
    sampled_at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    let boundary = sampled_at + chrono::Duration::hours(1);
    let counts: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT o.organisation_id, count(m.machine_id) \
         FROM grund_organisations o LEFT JOIN grund_machines m \
         ON m.home_organisation_id = o.organisation_id \
         AND m.pool = 'organisation' AND m.registered_at < $1 \
         AND (m.revoked_at IS NULL OR m.revoked_at >= $1) \
         WHERE o.created_at < $1 AND (o.deleted_at IS NULL OR o.deleted_at >= $1) \
         GROUP BY o.organisation_id",
    )
    .bind(boundary)
    .fetch_all(&mut *transaction)
    .await?;
    for (organisation_id, count) in counts {
        let event_id = Uuid::new_v5(&organisation_id, sampled_at.to_rfc3339().as_bytes());
        let payload = serde_json::json!({
            "eventId": event_id.to_string(), "idempotencyKey": event_id.to_string(),
            "organisationId": organisation_id.to_string(),
            "sampledAt": sampled_at.to_rfc3339(), "machines": count
        });
        outbox::enqueue(
            &mut transaction,
            event_id,
            Kind::BillingMachineCount,
            "",
            &payload,
        )
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn queue_machine_change(
    state: &State,
    connection: &mut PgConnection,
    machine_id: Uuid,
    change: &str,
    at: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    if !state.billing.enabled() {
        return Ok(());
    }
    let row: Option<(Uuid, i64)> = sqlx::query_as(
        "SELECT home_organisation_id, stream_version FROM grund_machines \
         WHERE machine_id = $1 AND pool = 'organisation'",
    )
    .bind(machine_id)
    .fetch_optional(&mut *connection)
    .await?;
    if let Some((organisation_id, version)) = row {
        let event_id = Uuid::new_v5(&machine_id, version.to_string().as_bytes());
        let payload = serde_json::json!({
            "eventId": event_id.to_string(), "idempotencyKey": event_id.to_string(),
            "organisationId": organisation_id.to_string(), "machineId": machine_id.to_string(),
            "change": change, "changedAt": at.to_rfc3339(), "machineKind": "MACHINE_KIND_OWN"
        });
        outbox::enqueue(
            connection,
            event_id,
            Kind::BillingMachineChange,
            "",
            &payload,
        )
        .await?;
    }
    Ok(())
}

/// Queue a hosted lease transition for rental reconciliation, never the
/// own-machine licence meter. A lease order has one start and one end.
pub async fn queue_hosted_change(
    state: &State,
    connection: &mut PgConnection,
    event: HostedChange<'_>,
) -> Result<(), sqlx::Error> {
    if !state.billing.enabled() {
        return Ok(());
    }
    let event_id = Uuid::new_v5(&event.order_id, event.change.as_bytes());
    let payload = serde_json::json!({
        "eventId": event_id.to_string(), "idempotencyKey": event_id.to_string(),
        "organisationId": event.organisation_id.to_string(), "machineId": event.machine_id.to_string(),
        "orderId": event.order_id.to_string(), "size": event.size, "region": event.region,
        "change": event.change, "changedAt": event.at.to_rfc3339(), "machineKind": "MACHINE_KIND_HOSTED"
    });
    outbox::enqueue(
        connection,
        event_id,
        Kind::BillingMachineChange,
        "",
        &payload,
    )
    .await
}

pub fn validate_complimentary(
    enabled: bool,
    plan: &str,
    reason: &str,
    expiry: &str,
) -> Result<(), &'static str> {
    if reason.trim().is_empty() || reason.len() > 500 {
        return Err("A reason of at most 500 characters is required.");
    }
    if enabled {
        if !matches!(plan, "Homelab" | "Pro" | "Business") {
            return Err("Choose an available plan.");
        }
        let at = expiry
            .parse::<DateTime<Utc>>()
            .map_err(|_| "Enter an expiry date and time.")?;
        if at <= Utc::now() {
            return Err("Expiry must be in the future.");
        }
    }
    Ok(())
}
