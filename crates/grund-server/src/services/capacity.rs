//! The capacity shim (grund-docs design/machines.md): where the management
//! pool gets machines from. The contract is `proto/grund/capacity/v1`; grund
//! calls it, and a provider (fleet, on grund's hosted service) implements it.
//!
//! Without GRUND_CAPACITY_URL (every self-hosted instance) the shim is
//! [`Capacity::None`]: machines join the pool by hand, with a registration
//! token an operator mints, and nothing is called.
//!
//! Operator calls stay synchronous. Hosted customer orders persist before the
//! provider is called so uncertain outcomes can be reconciled with the
//! idempotency key; enrollment tokens are derived from a secret key rather
//! than stored as reusable plaintext.

use std::{any::Any, future::Future, pin::Pin, sync::Arc, time::Duration};

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

pub type CapacityFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Size, region and state reported by a provider's inventory.
pub type InventorySize = (String, String, String);

/// Provider operations supplied by an extension alongside the legacy remote provider.
pub trait CapacityProvider: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn offers(&self) -> CapacityFuture<'_, Result<Vec<Offer>, CapacityError>>;
    fn inventory_sizes(&self) -> CapacityFuture<'_, Result<Vec<InventorySize>, CapacityError>>;
    fn get_provision<'a>(
        &'a self,
        key: &'a str,
    ) -> CapacityFuture<'a, Result<Option<String>, CapacityError>>;
    fn provision<'a>(
        &'a self,
        key: &'a str,
        url: &'a str,
        token: &'a str,
        expiry: DateTime<Utc>,
        size: &'a str,
        region: &'a str,
    ) -> CapacityFuture<'a, Result<String, CapacityError>>;
    fn rebuild<'a>(
        &'a self,
        key: &'a str,
        provider_id: &'a str,
        url: &'a str,
        token: &'a str,
        expiry: DateTime<Utc>,
    ) -> CapacityFuture<'a, Result<(), CapacityError>>;
    fn release<'a>(
        &'a self,
        key: &'a str,
        provider_id: &'a str,
    ) -> CapacityFuture<'a, Result<(), CapacityError>>;
}

/// The capacity seam: none, or a provider.
#[derive(Clone)]
pub enum Capacity {
    None,
    Remote(Remote),
    Provider(Arc<dyn CapacityProvider>),
}

/// A configured provider.
#[derive(Clone)]
pub struct Remote {
    url: String,
    token: String,
    http: reqwest::Client,
}

/// A selectable size and region published by the configured provider.
#[derive(Debug, Clone)]
pub struct Offer {
    pub size: String,
    pub region: String,
    pub vcpus: i32,
    pub memory_mib: i64,
    pub disk_gib: i64,
    pub ready: i32,
    pub can_place: bool,
}

pub(crate) fn protobuf_i64(value: &serde_json::Value) -> i64 {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .unwrap_or_default()
}

fn parse_offers(response: &serde_json::Value) -> Result<Vec<Offer>, CapacityError> {
    let offers = response["offers"]
        .as_array()
        .ok_or_else(|| CapacityError::Refused("invalid offers response".into()))?;
    offers
        .iter()
        .map(|offer| {
            Ok(Offer {
                size: offer["size"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| CapacityError::Refused("invalid size".into()))?
                    .to_owned(),
                region: offer["region"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| CapacityError::Refused("invalid region".into()))?
                    .to_owned(),
                vcpus: protobuf_i64(&offer["vcpus"]) as i32,
                memory_mib: protobuf_i64(&offer["memoryMib"]),
                disk_gib: protobuf_i64(&offer["diskGib"]),
                ready: protobuf_i64(&offer["ready"]) as i32,
                can_place: offer["canPlace"].as_bool().unwrap_or(false),
            })
        })
        .collect()
}

impl Capacity {
    /// The shim this configuration asks for.
    pub fn new(config: &CapacityArgs) -> anyhow::Result<Self> {
        let (Some(url), Some(token)) = (&config.capacity_url, &config.capacity_token) else {
            return Ok(Capacity::None);
        };
        grund_tls::install_default();
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
        matches!(self, Capacity::Remote(_) | Capacity::Provider(_))
    }

    /// Lists actual selectable capacity; an unconfigured provider offers nothing.
    pub async fn offers(&self) -> Result<Vec<Offer>, CapacityError> {
        if let Self::Provider(provider) = self {
            return provider.offers().await;
        }
        if !self.enabled() {
            return Ok(Vec::new());
        }
        let response = self.call("ListOffers", &serde_json::json!({})).await?;
        parse_offers(&response)
    }

    /// Returns exact size and region of already assigned machines for migration
    /// from an older registration that did not record its selected offer.
    pub async fn inventory_sizes(&self) -> Result<Vec<(String, String, String)>, CapacityError> {
        if let Self::Provider(provider) = self {
            return provider.inventory_sizes().await;
        }
        if !self.enabled() {
            return Ok(Vec::new());
        }
        let mut page = String::new();
        let mut seen = std::collections::HashSet::new();
        let mut sizes = Vec::new();
        loop {
            let response = self
                .call(
                    "ListInventoryMachines",
                    &serde_json::json!({
                        "pageSize": 200,
                        "pageToken": page,
                    }),
                )
                .await?;
            let rows = response["machines"]
                .as_array()
                .ok_or_else(|| CapacityError::Refused("invalid inventory response".into()))?;
            for row in rows {
                if let (Some(id), Some(size), Some(region)) = (
                    row["id"].as_str().filter(|v| !v.is_empty()),
                    row["size"].as_str().filter(|v| !v.is_empty()),
                    row["region"].as_str().filter(|v| !v.is_empty()),
                ) {
                    sizes.push((id.to_owned(), size.to_owned(), region.to_owned()));
                }
            }
            let next = response["nextPageToken"].as_str().unwrap_or_default();
            if next.is_empty() {
                break;
            }
            if !seen.insert(next.to_owned()) {
                return Err(CapacityError::Refused(
                    "inventory pagination repeated".into(),
                ));
            }
            page = next.to_owned();
        }
        Ok(sizes)
    }

    /// Resolves an ambiguous provision by its idempotency key without replaying it.
    pub async fn get_provision(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<String>, CapacityError> {
        if let Self::Provider(provider) = self {
            return provider.get_provision(idempotency_key).await;
        }
        let answer = self
            .call(
                "GetProvision",
                &serde_json::json!({
                    "idempotencyKey": idempotency_key
                }),
            )
            .await?;
        if answer["found"].as_bool() != Some(true) {
            return Ok(None);
        }
        answer["providerMachineId"]
            .as_str()
            .filter(|id| !id.is_empty())
            .map(|id| Some(id.to_owned()))
            .ok_or_else(|| CapacityError::Refused("invalid provision lookup".into()))
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
        region: &str,
    ) -> Result<String, CapacityError> {
        if let Self::Provider(provider) = self {
            return provider
                .provision(idempotency_key, grund_url, token, expires_at, size, region)
                .await;
        }
        let answer = self
            .call(
                "ProvisionMachine",
                &serde_json::json!({
                    "idempotencyKey": idempotency_key,
                    "grundUrl": grund_url,
                    "enrollmentToken": token,
                    "tokenExpiresAt": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    "size": size,
                    "region": region,
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
        if let Self::Provider(provider) = self {
            return provider
                .rebuild(
                    idempotency_key,
                    provider_machine_id,
                    grund_url,
                    token,
                    expires_at,
                )
                .await;
        }
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
        if let Self::Provider(provider) = self {
            return provider.release(idempotency_key, provider_machine_id).await;
        }
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

    #[tracing::instrument(name = "capacity.call", skip(self, body))]
    pub(crate) async fn call(
        &self,
        method: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, CapacityError> {
        let Capacity::Remote(remote) = self else {
            return Err(CapacityError::NotConfigured);
        };
        let response = crate::telemetry::propagate(
            remote
                .http
                .post(format!(
                    "{}/grund.capacity.v1.CapacityService/{method}",
                    remote.url
                ))
                .bearer_auth(&remote.token)
                .header("Connect-Protocol-Version", "1")
                .json(body),
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_offer_keeps_the_memory_and_disk_advertised_in_protobuf_json() {
        let offers = parse_offers(&serde_json::json!({
            "offers": [{
                "size": "micro",
                "region": "own-lab",
                "vcpus": 1,
                "memoryMib": "512",
                "diskGib": "2",
                "ready": 1,
                "canPlace": true
            }]
        }))
        .unwrap();
        assert_eq!((offers[0].memory_mib, offers[0].disk_gib), (512, 2));
        assert!(offers[0].can_place);
    }
}
