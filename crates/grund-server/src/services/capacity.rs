//! The capacity shim (grund-docs design/machines.md): where the management
//! pool gets machines from. The contract is `proto/grund/capacity/v1`; grund
//! calls it, and a provider (fleet, on grund's hosted service) implements it.
//!
//! Without GRUND_CAPACITY_URL (every self-hosted instance) the shim is
//! [`Capacity::None`]: machines join the pool by hand, with a registration
//! token an operator mints, and nothing is called.
//!
//! Calls are made from the operator's request, synchronously, never queued:
//! each carries a one-time registration token, and a queue would keep that
//! token in the database until it was delivered. A call that fails leaves
//! nothing half done that grund cannot see: the token expires unused, or the
//! machine stays returning or revoked, and the operator asks again.

use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, Utc};

use crate::{config::CapacityArgs, state::State};

/// How long one call to the provider may take.
pub const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// Why a call to the provider did not do what was asked.
#[derive(Debug, thiserror::Error)]
pub enum CapacityError {
    #[error("no capacity provider is configured")]
    NotConfigured,
    #[error("the capacity provider could not be reached or is unavailable")]
    Unavailable,
    #[error("the capacity provider refused: {0}")]
    Refused(String),
}

/// The capacity seam: none, or a provider.
#[derive(Clone)]
pub enum Capacity {
    None,
    Remote(Remote),
}

/// A configured provider.
#[derive(Clone)]
pub struct Remote {
    url: String,
    token: String,
    http: reqwest::Client,
}

impl Capacity {
    /// The shim this configuration asks for.
    pub fn new(config: &CapacityArgs) -> anyhow::Result<Self> {
        let (Some(url), Some(token)) = (&config.capacity_url, &config.capacity_token) else {
            return Ok(Capacity::None);
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(CALL_TIMEOUT)
            .connect_timeout(Duration::from_secs(2))
            .user_agent("grund")
            .build()
            .context("build the HTTP client for the capacity provider")?;
        Ok(Capacity::Remote(Remote {
            url: url.clone(),
            token: token.clone(),
            http,
        }))
    }

    /// Whether a provider is configured.
    pub fn enabled(&self) -> bool {
        matches!(self, Capacity::Remote(_))
    }

    /// Asks for a new machine that registers into the management pool with
    /// `token`. Returns the provider's id for it.
    pub async fn provision(
        &self,
        idempotency_key: &str,
        grund_url: &str,
        token: &str,
        expires_at: DateTime<Utc>,
        size: &str,
    ) -> Result<String, CapacityError> {
        let answer = self
            .call(
                "ProvisionMachine",
                &serde_json::json!({
                    "idempotencyKey": idempotency_key,
                    "grundUrl": grund_url,
                    "enrollmentToken": token,
                    "tokenExpiresAt": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    "size": size,
                }),
            )
            .await?;
        answer["providerMachineId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .ok_or_else(|| CapacityError::Refused("the provider answered no machine id".into()))
    }

    /// Asks for a machine to be wiped and booted with a re-registration token.
    pub async fn rebuild(
        &self,
        idempotency_key: &str,
        provider_machine_id: &str,
        grund_url: &str,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), CapacityError> {
        self.call(
            "RebuildMachine",
            &serde_json::json!({
                "idempotencyKey": idempotency_key,
                "providerMachineId": provider_machine_id,
                "grundUrl": grund_url,
                "enrollmentToken": token,
                "tokenExpiresAt": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            }),
        )
        .await
        .map(drop)
    }

    /// Gives a revoked machine back to the provider.
    pub async fn release(
        &self,
        idempotency_key: &str,
        provider_machine_id: &str,
    ) -> Result<(), CapacityError> {
        self.call(
            "ReleaseMachine",
            &serde_json::json!({
                "idempotencyKey": idempotency_key,
                "providerMachineId": provider_machine_id,
            }),
        )
        .await
        .map(drop)
    }

    async fn call(
        &self,
        method: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, CapacityError> {
        let Capacity::Remote(remote) = self else {
            return Err(CapacityError::NotConfigured);
        };
        let response = remote
            .http
            .post(format!(
                "{}/grund.capacity.v1.CapacityService/{method}",
                remote.url
            ))
            .bearer_auth(&remote.token)
            .header("Connect-Protocol-Version", "1")
            .json(body)
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(error = %error, method, "the capacity provider could not be reached");
                CapacityError::Unavailable
            })?;
        let status = response.status().as_u16();
        let answer: serde_json::Value = response.json().await.unwrap_or_default();
        match status {
            200 => Ok(answer),
            503 | 502 | 504 | 429 => Err(CapacityError::Unavailable),
            401 => {
                tracing::warn!("the capacity provider refused GRUND_CAPACITY_TOKEN");
                Err(CapacityError::Unavailable)
            }
            _ => Err(CapacityError::Refused(
                answer["message"]
                    .as_str()
                    .filter(|m| !m.is_empty())
                    .unwrap_or("no reason given")
                    .chars()
                    .take(300)
                    .collect(),
            )),
        }
    }
}

/// Access to [`Capacity`] from [`State`].
pub trait CapacityState {
    fn capacity(&self) -> Capacity;
}

impl CapacityState for State {
    fn capacity(&self) -> Capacity {
        self.capacity.clone()
    }
}
