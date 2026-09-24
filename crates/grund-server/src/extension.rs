//! The seam between grund's open core and features built outside it (the
//! commercial `ee/` directory). An extension adds routes, templates and
//! sign-in providers; it never replaces anything the core does. Whether a
//! commercial extension may act is still decided by
//! [`crate::services::entitlements::Entitlements`], which every such
//! extension asks before serving.

use std::sync::Arc;

use crate::state::State;

/// A way to sign in that an extension offers on the sign-in page.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoginProvider {
    pub id: String,
    pub name: String,
    pub icon: &'static str,
}

/// A feature built outside the core.
pub trait Extension: Send + Sync + 'static {
    /// Its name, for logs.
    fn name(&self) -> &'static str;

    /// Templates to add to the environment, by name. They may extend the
    /// core's layouts.
    fn templates(&self) -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// Routes to merge into the page router, under the same middleware as
    /// the core's pages.
    fn routes(&self) -> axum::Router<State>;

    /// Providers to offer on the sign-in page, already filtered by what the
    /// instance is entitled to.
    fn login_providers(&self, _state: &State) -> Vec<LoginProvider> {
        Vec::new()
    }
}

/// The extensions this binary was built with.
pub type Extensions = Arc<Vec<Arc<dyn Extension>>>;
