//! Social sign-in as an extension of the core: its routes, its two pages,
//! and the providers it adds to the sign-in page when the license allows.

pub mod flows;
pub mod pages;

use std::sync::Arc;

use anyhow::Context;
use axum::routing::get;
use grund_server::{
    config::ServeConfig,
    extension::{Extension, LoginProvider},
    license::Feature,
    state::State,
};

use flows::{Provider, Social};

/// The social sign-in extension.
pub struct SocialLogin {
    providers: Arc<[Provider]>,
    http: reqwest::Client,
}

impl SocialLogin {
    /// The providers GRUND_SOCIAL_LOGIN and the provider settings name, and an
    /// HTTP client for them: rustls with the ring provider, 10 s per request.
    pub fn new(config: &ServeConfig) -> anyhow::Result<Self> {
        let providers = if config.social.social_login {
            flows::providers(&config.social)
        } else {
            Vec::new()
        };
        Ok(Self {
            providers: providers.into(),
            http: http_client()?,
        })
    }

    /// The same, for tests: these providers and this client.
    pub fn with(providers: Vec<Provider>, http: reqwest::Client) -> Self {
        Self {
            providers: providers.into(),
            http,
        }
    }

    /// The flows over this extension's providers.
    pub fn flows(&self, state: &State) -> Social {
        Social::new(state, self.providers.clone(), self.http.clone())
    }
}

/// The HTTP client for calls to sign-in providers.
pub fn http_client() -> anyhow::Result<reqwest::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .user_agent("grund")
        .build()
        .context("build the HTTP client for sign-in providers")
}

/// The templates this extension adds.
pub const TEMPLATES: &[(&str, &str)] = &[
    (
        "pages/social-username.html.jinja",
        include_str!("../../templates/pages/social-username.html.jinja"),
    ),
    (
        "pages/social-link.html.jinja",
        include_str!("../../templates/pages/social-link.html.jinja"),
    ),
];

/// Wraps the extension so its routes can reach it.
pub struct Registered(pub Arc<SocialLogin>);

impl Extension for Registered {
    fn name(&self) -> &'static str {
        "social-login"
    }

    fn templates(&self) -> &'static [(&'static str, &'static str)] {
        TEMPLATES
    }

    fn routes(&self) -> axum::Router<State> {
        axum::Router::new()
            .route("/auth/{provider}/start", get(pages::start))
            .route("/auth/{provider}/callback", get(pages::callback))
            .route(
                "/auth/complete",
                get(pages::complete_form).post(pages::complete),
            )
            .route("/auth/link", get(pages::link_form).post(pages::link))
            .layer(axum::Extension(self.0.clone()))
    }

    fn login_providers(&self, state: &State) -> Vec<LoginProvider> {
        if state.entitlements.allows(Feature::SocialLogin).is_err() {
            return Vec::new();
        }
        self.0
            .providers
            .iter()
            .map(|p| LoginProvider {
                id: p.id.to_string(),
                name: p.name.clone(),
                icon: p.icon,
            })
            .collect()
    }
}
