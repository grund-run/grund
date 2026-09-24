//! The outbox drain (skills `messaging` §2): delivers mail and resolves reset
//! requests after commit, at least once. Added last to notmad, so it drains
//! last.
//!
//! It wakes on a NATS hint (`<prefix>.outbox`) when one is configured, and
//! polls every GRUND_WORK_POLL_INTERVAL regardless: a lost hint costs latency,
//! never mail.

use std::time::Duration;

use futures_util::StreamExt;
use grund_store::{
    accounts::{self, Lookup},
    outbox::{self, Claimed, Kind},
    tokens::{self, Purpose},
};
use notmad::{Component, ComponentInfo, MadError};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    crypto,
    services::mail::{Mail, MailError, Mailer},
    state::State,
};

/// How long a claimed row is leased before another replica may retry it.
pub const LEASE: Duration = Duration::from_secs(60);
/// How long a password-reset link is valid.
pub const RESET_LINK_TTL: Duration = Duration::from_secs(30 * 60);
/// How long delivered rows are kept before deletion (skills D-11).
pub const RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);

const BATCH: i64 = 20;

/// The subject a commit that queued outbox work publishes to.
pub fn wake_subject(prefix: &str) -> String {
    format!("{prefix}.outbox")
}

/// Hints the drain that work is queued. Best-effort: the drain polls anyway.
pub async fn wake(state: &State) {
    if let Some(nats) = &state.nats {
        let subject = wake_subject(&state.config.nats_subject_prefix);
        if let Err(error) = nats.publish(subject, Default::default()).await {
            tracing::debug!(error = %error, "outbox wake-up not published; the poll picks the work up");
        }
    }
}

/// The notmad component.
pub struct OutboxDrain {
    state: State,
    mailer: Mailer,
}

impl OutboxDrain {
    pub fn new(state: State, mailer: Mailer) -> Self {
        Self { state, mailer }
    }

    async fn drain(&self) {
        for _ in 0..10 {
            let claimed = match outbox::claim(&self.state.pool, BATCH, LEASE).await {
                Ok(claimed) => claimed,
                Err(error) => {
                    tracing::warn!(error = %error, "outbox claim failed; retrying next tick");
                    return;
                }
            };
            if claimed.is_empty() {
                return;
            }
            for row in claimed {
                let id = row.outbox_id;
                if let Err(error) = self.process(row).await {
                    tracing::warn!(error = %error, outbox_id = %id, "outbox row failed; its lease expires and it is retried");
                }
            }
        }
    }

    async fn process(&self, row: Claimed) -> anyhow::Result<()> {
        let Some(kind) = Kind::parse(&row.kind) else {
            tracing::error!(kind = %row.kind, outbox_id = %row.outbox_id, "unknown outbox kind; dropped");
            outbox::delivered(&self.state.pool, row.outbox_id).await?;
            return Ok(());
        };
        let mail = match kind {
            Kind::PasswordResetRequested => return self.resolve_reset(row).await,
            Kind::VerifyEmailMail => Mail::VerifyEmail,
            Kind::PasswordResetMail => Mail::PasswordReset,
            Kind::SignupExistingMail => Mail::SignupExisting,
        };
        match self.mailer.send(mail, &row.recipient, &row.payload).await {
            Ok(()) => {
                outbox::delivered(&self.state.pool, row.outbox_id).await?;
                tracing::info!(outbox_id = %row.outbox_id, kind = kind.as_str(), "mail sent");
            }
            Err(MailError::Permanent) => {
                tracing::warn!(outbox_id = %row.outbox_id, kind = kind.as_str(), "mail undeliverable; dropped");
                outbox::delivered(&self.state.pool, row.outbox_id).await?;
            }
            Err(error @ (MailError::NotConfigured | MailError::Transient)) => {
                outbox::failed(
                    &self.state.pool,
                    row.outbox_id,
                    row.attempts,
                    &error.to_string(),
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn resolve_reset(&self, row: Claimed) -> anyhow::Result<()> {
        let mut tx = self.state.pool.begin().await?;
        if let Some(account) =
            accounts::login_record(&mut *tx, Lookup::Email(&row.recipient)).await?
        {
            let token = crypto::random_token();
            tokens::issue(
                &mut tx,
                &crypto::digest(&token),
                Purpose::ResetPassword,
                account.account_id,
                &account.email_normalized,
                RESET_LINK_TTL,
            )
            .await?;
            let payload = serde_json::json!({
                "username": account.username,
                "link": format!("{}/reset/confirm?token={token}", self.state.config.public_origin().serialized),
            });
            let mail_id = Uuid::new_v5(&row.outbox_id, b"password-reset-mail");
            outbox::enqueue(
                &mut tx,
                mail_id,
                Kind::PasswordResetMail,
                &account.email,
                &payload,
            )
            .await?;
        }
        outbox::delivered(&mut *tx, row.outbox_id).await?;
        tx.commit().await?;
        wake(&self.state).await;
        Ok(())
    }
}

impl Component for OutboxDrain {
    fn info(&self) -> ComponentInfo {
        "grund/outbox".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        let mut wakes = match &self.state.nats {
            Some(nats) => match nats
                .subscribe(wake_subject(&self.state.config.nats_subject_prefix))
                .await
            {
                Ok(subscriber) => Some(subscriber),
                Err(error) => {
                    tracing::warn!(error = %error, "outbox wake-ups unavailable; polling only");
                    None
                }
            },
            None => None,
        };
        let mut tick = tokio::time::interval(self.state.config.work_poll_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut prune = tokio::time::interval(Duration::from_secs(3600));
        prune.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let woken = async {
                match wakes.as_mut() {
                    Some(subscriber) => subscriber.next().await.is_some(),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = cancellation.cancelled() => {
                    let _ = tokio::time::timeout(Duration::from_secs(5), self.drain()).await;
                    return Ok(());
                }
                _ = tick.tick() => self.drain().await,
                alive = woken => {
                    if alive {
                        self.drain().await;
                    } else {
                        wakes = None;
                    }
                }
                _ = prune.tick() => {
                    if let Err(error) = outbox::prune(&self.state.pool, RETENTION).await {
                        tracing::warn!(error = %error, "outbox prune failed; retrying next hour");
                    }
                }
            }
        }
    }
}
