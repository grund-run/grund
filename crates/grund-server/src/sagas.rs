//! Work that needs another service's answer before it can finish, run as
//! mire sagas (mire-sagas): durable, retried, and resumable after a crash.
//!
//! `organisation-deletion` is the first. An owner asks to delete an
//! organisation (`DeletionRequested`); billing must agree before anything is
//! deleted (grund-docs design/billing.md). Two steps, both fulfilled by
//! [`DeletionPublisher`] from the saga outbox, so a billing outage retries
//! instead of failing:
//!
//! ```text
//!   DeletionRequested ─► billing: CheckDeletion (Free: allowed at once)
//!                     ─► conclude: Delete, or CancelDeletion with billing's reason
//! ```
//!
//! The saga starts from the organisation stream through the projection
//! runner ([`DeletionTrigger`], at least once), and the request path also
//! triggers it at once so nobody waits for the runner's next pass. A second
//! trigger for the same request is a no-op.

use std::{sync::Arc, time::Duration};

use chrono::Utc;
use grund_domain::organisation::{Organisation, OrganisationCommand, OrganisationEvent};
use grund_store::{organisations, work::Work};
use mire::{EventStore, HandledEvent};
use mire_sagas::{
    Emit, EmitPublisher, OutboxMessage, Output, PgSagaRunner, Saga, SagaBuilder, SagaWorker, Start,
    task,
};
use notmad::{Component, ComponentInfo, MadError};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    services::{
        billing::{self, Change, Deletion},
        outbox::wake,
    },
    state::State,
};

/// How long a step whose service did not answer waits before it is retried.
pub const RETRY_DELAY: Duration = Duration::from_secs(5);

/// The subscription that starts deletion sagas from organisation events.
pub const DELETION_TRIGGER_SUBSCRIPTION: &str = "grund-organisation-deletion-trigger-v1";

/// The `organisation-deletion` saga.
pub struct OrganisationDeletion;

/// What the saga remembers about the request it serves.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeletionState {
    pub organisation_id: String,
    pub request_id: String,
}

/// Asks billing whether the organisation may be deleted.
#[derive(Debug, Clone, Serialize, Deserialize, mire::EventData)]
#[mire(event_type = "grund.billing.check_deletion")]
pub struct CheckDeletion {
    pub organisation_id: String,
}

/// Billing's answer.
#[derive(Debug, Clone, Serialize, Deserialize, mire::EventData)]
#[mire(event_type = "grund.billing.deletion_checked")]
pub struct DeletionChecked {
    pub allowed: bool,
    pub reason: String,
}

/// Billing's answer, as the next step reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingDecision {
    pub allowed: bool,
    pub reason: String,
}

/// Deletes the organisation, or cancels the request, as billing decided.
#[derive(Debug, Clone, Serialize, Deserialize, mire::EventData)]
#[mire(event_type = "grund.organisation.conclude_deletion")]
pub struct ConcludeDeletion {
    pub organisation_id: String,
    pub request_id: String,
    pub allowed: bool,
    pub reason: String,
}

/// Whether the organisation is gone.
#[derive(Debug, Clone, Serialize, Deserialize, mire::EventData)]
#[mire(event_type = "grund.organisation.deletion_concluded")]
pub struct DeletionConcluded {
    pub deleted: bool,
}

fn ask_billing(mire_sagas::State(s): mire_sagas::State<DeletionState>) -> Emit {
    Emit::event(CheckDeletion {
        organisation_id: s.organisation_id.clone(),
    })
}

fn conclude(
    mire_sagas::State(s): mire_sagas::State<DeletionState>,
    Output(decision): Output<BillingDecision>,
) -> Emit {
    Emit::event(ConcludeDeletion {
        organisation_id: s.organisation_id.clone(),
        request_id: s.request_id.clone(),
        allowed: decision.allowed,
        reason: decision.reason,
    })
}

impl Saga for OrganisationDeletion {
    type State = DeletionState;

    fn name() -> &'static str {
        "organisation-deletion"
    }

    fn build(b: SagaBuilder<Self>) -> SagaBuilder<Self> {
        b.start_on::<Organisation, _>(|event: &OrganisationEvent| match event {
            OrganisationEvent::DeletionRequested {
                request_id,
                organisation_id,
                ..
            } => Some(Start {
                instance_id: request_id.to_string(),
                state: DeletionState {
                    organisation_id: organisation_id.to_string(),
                    request_id: request_id.to_string(),
                },
            }),
            _ => None,
        })
        .step(
            "billing",
            task(ask_billing).on_response(|answer: DeletionChecked| BillingDecision {
                allowed: answer.allowed,
                reason: answer.reason,
            }),
        )
        .step(
            "conclude",
            task(conclude)
                .after("billing")
                .on_response(|done: DeletionConcluded| done)
                .terminal_success(),
        )
    }
}

/// Starts deletion sagas and reports on them.
#[derive(Clone)]
pub struct Deletions {
    runner: Arc<PgSagaRunner<OrganisationDeletion>>,
}

impl Deletions {
    pub fn new(store: EventStore) -> Self {
        Self {
            runner: Arc::new(runner(store)),
        }
    }

    /// Starts the saga for a `DeletionRequested`. Any other event, or a second
    /// start for the same request, does nothing.
    pub async fn start(&self, event: &OrganisationEvent) -> anyhow::Result<()> {
        start(&self.runner, event).await
    }
}

fn runner(store: EventStore) -> PgSagaRunner<OrganisationDeletion> {
    PgSagaRunner::new(OrganisationDeletion::build(SagaBuilder::for_saga()), store)
}

async fn start(
    runner: &PgSagaRunner<OrganisationDeletion>,
    event: &OrganisationEvent,
) -> anyhow::Result<()> {
    if matches!(event, OrganisationEvent::DeletionRequested { .. }) {
        runner.trigger::<Organisation>(event).await?;
    }
    Ok(())
}

/// Starts deletion sagas from the organisation stream, at least once.
pub struct DeletionTrigger {
    runner: Arc<PgSagaRunner<OrganisationDeletion>>,
}

impl DeletionTrigger {
    pub fn new(deletions: &Deletions) -> Self {
        Self {
            runner: deletions.runner.clone(),
        }
    }
}

impl mire::EventHandler for DeletionTrigger {
    type Aggregate = Organisation;

    async fn handle(&self, event: HandledEvent<OrganisationEvent>) -> anyhow::Result<()> {
        start(&self.runner, &event.event).await
    }
}

/// Fulfils the saga's requests: asks billing, then deletes or cancels. An
/// error is retried after [`RETRY_DELAY`] from the saga outbox.
#[derive(Clone)]
pub struct DeletionPublisher {
    state: State,
    deliver: Arc<PgSagaRunner<OrganisationDeletion>>,
}

impl EmitPublisher for DeletionPublisher {
    fn publish(&self, msg: OutboxMessage<'_>) -> impl Future<Output = anyhow::Result<()>> + Send {
        let this = self.clone();
        let event_type = msg.event_type.to_string();
        let payload = msg.payload.clone();
        let instance = msg.instance_id.to_string();
        async move {
            match event_type.as_str() {
                "grund.billing.check_deletion" => {
                    let request: CheckDeletion = serde_json::from_value(payload)?;
                    let organisation_id = Uuid::parse_str(&request.organisation_id)?;
                    let answer = match this.state.billing.check_deletion(organisation_id).await {
                        Deletion::Allowed => DeletionChecked {
                            allowed: true,
                            reason: String::new(),
                        },
                        Deletion::Refused(reason) => DeletionChecked {
                            allowed: false,
                            reason,
                        },
                        Deletion::Unavailable => {
                            anyhow::bail!("billing could not be asked; retrying")
                        }
                    };
                    this.deliver.deliver(&instance, &answer).await?;
                }
                "grund.organisation.conclude_deletion" => {
                    let request: ConcludeDeletion = serde_json::from_value(payload)?;
                    let deleted = conclude_deletion(&this.state, &request).await?;
                    this.deliver
                        .deliver(&instance, &DeletionConcluded { deleted })
                        .await?;
                }
                other => anyhow::bail!("organisation-deletion emitted an unknown request {other}"),
            }
            Ok(())
        }
    }
}

async fn conclude_deletion(state: &State, request: &ConcludeDeletion) -> anyhow::Result<bool> {
    let organisation_id = Uuid::parse_str(&request.organisation_id)?;
    let request_id = Uuid::parse_str(&request.request_id)?;
    let now = Utc::now();
    let mut work = Work::begin(&state.events, request_id, "organisation-deletion").await?;
    let deleted = if request.allowed {
        let events = work
            .organisation(
                organisation_id,
                OrganisationCommand::Delete {
                    request_id,
                    at: now,
                },
            )
            .await?;
        if !events.is_empty() {
            organisations::withdraw_all(work.sql(), organisation_id).await?;
            let slug = organisations::slug_of(&mut **work.sql(), organisation_id)
                .await?
                .unwrap_or_default();
            billing::queue_change(
                state,
                work.sql(),
                organisation_id,
                &slug,
                Change::Deleted,
                now,
            )
            .await?;
        }
        !events.is_empty()
    } else {
        work.organisation(
            organisation_id,
            OrganisationCommand::CancelDeletion {
                request_id,
                actor: None,
                reason: request.reason.clone(),
                at: now,
            },
        )
        .await?;
        false
    };
    work.commit().await?;
    if deleted {
        tracing::info!(%organisation_id, %request_id, "organisation deleted");
        if state.billing.enabled() {
            wake(state).await;
        }
    } else {
        tracing::info!(%organisation_id, %request_id, "organisation deletion cancelled");
    }
    Ok(deleted)
}

/// The notmad component that drives deletion sagas: recovery, timeouts and
/// the saga outbox.
pub struct DeletionWorker {
    worker: std::sync::Mutex<Option<SagaWorker<OrganisationDeletion>>>,
}

impl DeletionWorker {
    pub fn new(state: &State) -> Self {
        let publisher = DeletionPublisher {
            state: state.clone(),
            deliver: Arc::new(runner(state.events.clone())),
        };
        let worker = SagaWorker::new(runner(state.events.clone()).with_publisher(publisher))
            .poll_interval(Duration::from_secs(1))
            .drain_interval(Duration::from_millis(250))
            .outbox_retry_delay(RETRY_DELAY);
        Self {
            worker: std::sync::Mutex::new(Some(worker)),
        }
    }
}

impl Component for DeletionWorker {
    fn info(&self) -> ComponentInfo {
        "grund/sagas".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let worker = self.worker.lock().expect("saga worker lock").take();
        let Some(worker) = worker else {
            return Ok(());
        };
        worker
            .run(cancellation)
            .await
            .map_err(|error| MadError::Inner(error.into()))
    }
}
