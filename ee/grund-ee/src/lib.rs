//! grund's commercial features. Licensed under the grund Commercial License
//! (`ee/LICENSE`), not the AGPL: the source is here to read, and using it
//! needs a grund license key that includes the feature.
//!
//! Each feature is an [`grund_server::extension::Extension`], and every one
//! asks [`grund_server::services::entitlements::Entitlements`] before it acts.

pub mod social;

use std::sync::Arc;

use grund_server::{config::ServeConfig, extension::Extension};

/// Every commercial extension, configured from `config`.
pub fn extensions(config: &ServeConfig) -> anyhow::Result<Vec<Arc<dyn Extension>>> {
    let social = Arc::new(social::SocialLogin::new(config)?);
    Ok(vec![Arc::new(social::Registered(social))])
}
