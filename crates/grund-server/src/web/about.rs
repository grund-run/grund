//! `/{org}/settings/about`: the grund instance an organisation lives on,
//! for anyone in it: which build it runs, where it answers and how apps
//! are reached. Nothing here is secret; `/health/ready` reports the
//! revision to anyone.

use axum::extract::State as AxumState;
use minijinja::context;

use crate::{
    config::OrganisationMode,
    health,
    state::State,
    web::{orgs::Member, pages::PageResult},
};

/// `GET /{org}/settings/about`.
pub async fn about_page(AxumState(state): AxumState<State>, member: Member) -> PageResult {
    let config = &state.config;
    let page = context! {
        revision => health::revision(),
        address => config.public_origin().serialized,
        app_domain => config.entry.app_domain.clone(),
        single => config.organisations == OrganisationMode::Single,
    };
    member
        .render(&state, "pages/about.html.jinja", "org-settings", page)
        .await
}
