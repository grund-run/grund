//! Generic capacity-provider contract for management pool machines.
//! A public instance has no provider; private extensions can install one.

use crate::state::State;
use chrono::{DateTime, Utc};
pub use grund_domain::agent_updates::ProviderUpdateFence;
use std::{any::Any, future::Future, pin::Pin, sync::Arc};

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

/// A provider machine's ID, size and region from its inventory.
pub type InventorySize = (String, String, String);

/// Provider operations used by the shared machine service.
pub trait CapacityProvider: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn acquire_machine_update_fence<'a>(
        &'a self,
        reservation: &'a ProviderUpdateFence,
    ) -> CapacityFuture<'a, Result<bool, CapacityError>>;
    fn release_machine_update_fence<'a>(
        &'a self,
        reservation: &'a ProviderUpdateFence,
    ) -> CapacityFuture<'a, Result<u64, CapacityError>>;
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
        accept_empty_volume_ids: &'a [uuid::Uuid],
        restored_volumes: &'a [(uuid::Uuid, uuid::Uuid)],
    ) -> CapacityFuture<'a, Result<(), CapacityError>>;
}

#[derive(Clone, Default)]
pub enum Capacity {
    #[default]
    None,
    Provider(Arc<dyn CapacityProvider>),
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

impl Capacity {
    pub fn enabled(&self) -> bool {
        matches!(self, Self::Provider(_))
    }

    pub async fn acquire_machine_update_fence(
        &self,
        reservation: &ProviderUpdateFence,
    ) -> Result<bool, CapacityError> {
        match self {
            Self::None => Err(CapacityError::NotConfigured),
            Self::Provider(provider) => provider.acquire_machine_update_fence(reservation).await,
        }
    }

    pub async fn release_machine_update_fence(
        &self,
        reservation: &ProviderUpdateFence,
    ) -> Result<u64, CapacityError> {
        match self {
            Self::None => Err(CapacityError::NotConfigured),
            Self::Provider(provider) => provider.release_machine_update_fence(reservation).await,
        }
    }

    pub async fn offers(&self) -> Result<Vec<Offer>, CapacityError> {
        match self {
            Self::None => Ok(Vec::new()),
            Self::Provider(provider) => provider.offers().await,
        }
    }

    pub async fn inventory_sizes(&self) -> Result<Vec<InventorySize>, CapacityError> {
        match self {
            Self::None => Ok(Vec::new()),
            Self::Provider(provider) => provider.inventory_sizes().await,
        }
    }

    pub async fn get_provision(&self, key: &str) -> Result<Option<String>, CapacityError> {
        match self {
            Self::None => Err(CapacityError::NotConfigured),
            Self::Provider(provider) => provider.get_provision(key).await,
        }
    }

    pub async fn provision(
        &self,
        key: &str,
        url: &str,
        token: &str,
        expiry: DateTime<Utc>,
        size: &str,
        region: &str,
    ) -> Result<String, CapacityError> {
        match self {
            Self::None => Err(CapacityError::NotConfigured),
            Self::Provider(provider) => {
                provider
                    .provision(key, url, token, expiry, size, region)
                    .await
            }
        }
    }

    pub async fn rebuild(
        &self,
        key: &str,
        provider_id: &str,
        url: &str,
        token: &str,
        expiry: DateTime<Utc>,
    ) -> Result<(), CapacityError> {
        match self {
            Self::None => Err(CapacityError::NotConfigured),
            Self::Provider(provider) => {
                provider.rebuild(key, provider_id, url, token, expiry).await
            }
        }
    }

    pub async fn release(
        &self,
        key: &str,
        provider_id: &str,
        accept_empty_volume_ids: &[uuid::Uuid],
        restored_volumes: &[(uuid::Uuid, uuid::Uuid)],
    ) -> Result<(), CapacityError> {
        match self {
            Self::None => Err(CapacityError::NotConfigured),
            Self::Provider(provider) => {
                provider
                    .release(key, provider_id, accept_empty_volume_ids, restored_volumes)
                    .await
            }
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
