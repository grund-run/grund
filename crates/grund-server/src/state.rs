//! What the process opens once, shared by every request and component.
//!
//! Handlers never reach into these fields for domain work: they ask for a
//! service through its extension trait (`state.accounts()`), defined at the
//! bottom of the file that defines the service.

use std::{sync::Arc, time::Instant};

use crate::{
    config::ServeConfig,
    secrets::SecretKey,
    services::{entitlements::Entitlements, passwords::Passwords, social::Provider},
    templates::Templates,
};

/// Cheap to clone: every field is an `Arc`, a pool or a handle.
#[derive(Clone)]
pub struct State {
    pub config: Arc<ServeConfig>,
    pub pool: sqlx::PgPool,
    pub events: mire::EventStore,
    pub nats: Option<async_nats::Client>,
    pub secret: Arc<SecretKey>,
    pub health: nostatus::StatusState,
    pub passwords: Passwords,
    pub templates: Templates,
    pub entitlements: Arc<Entitlements>,
    /// The social providers configured with GRUND_SOCIAL_LOGIN on. Offered
    /// only when `entitlements` allows social sign-in.
    pub social: Arc<Vec<Provider>>,
    /// For calls to social sign-in providers: 10 s per request.
    pub http: reqwest::Client,
    pub started: Instant,
}
