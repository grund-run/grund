//! `/{org}/settings/about`: the grund instance an organisation lives on,
//! for anyone in it: which build it runs, where it answers and how apps
//! are reached. Nothing here is secret; `/health/ready` reports the
//! revision to anyone.

use crate::templates::compiled::pages;
use axum::extract::State as AxumState;

use crate::{
    config::OrganisationMode,
    health,
    state::State,
    web::{orgs::Member, pages::PageResult},
};
pub struct AboutPage<'a> {
    pub viewer: &'a crate::web::pages::TypedViewer,
    pub revision: &'a str,
    pub address: &'a str,
    pub app_addresses: std::borrow::Cow<'a, str>,
    pub single: bool,
}

/// `GET /{org}/settings/about`.
pub async fn about_page(AxumState(state): AxumState<State>, member: Member) -> PageResult {
    let config = &state.config;
    crate::web::pages::signed_in_typed(
        &state,
        &member.browser,
        &member.session,
        Some(&member.membership),
        axum::http::StatusCode::OK,
        "About",
        "org-settings",
        None,
        None,
        None,
        |viewer, _| {
            pages::about::render(&AboutPage {
                viewer,
                revision: health::revision(),
                address: &config.public_origin().serialized,
                app_addresses: config
                    .entry
                    .app_domain
                    .as_ref()
                    .filter(|domain| !domain.is_empty())
                    .map_or_else(
                        || std::borrow::Cow::Borrowed("None: apps answer only inside grund"),
                        |domain| {
                            std::borrow::Cow::Owned(format!(
                                "<app>-{}.{}",
                                member.membership.slug, domain
                            ))
                        },
                    ),
                single: config.organisations == OrganisationMode::Single,
            })
        },
    )
    .await
}
