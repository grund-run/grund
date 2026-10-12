use std::sync::Arc;

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{HeaderValue, StatusCode, Uri, header},
    response::Response,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::billing::{AccountDetails, Billing, BillingError, BillingView},
    state::State,
    templates::compiled::pages::billing as template,
    web::{
        browser::Browser,
        orgs::{Member, member_of},
        pages::{PageResult, forged, not_found_page, redirect, signed_in_typed},
    },
};

pub struct AccountView {
    pub details: Arc<AccountDetails>,
    pub operator_url_allowed: bool,
}

impl AccountView {
    pub fn from_billing(view: BillingView) -> Option<Self> {
        let BillingView::Account(details) = view else {
            return None;
        };
        Some(Self {
            details,
            operator_url_allowed: false,
        })
    }

    pub fn from_billing_operator(view: BillingView, billing: &Billing) -> Option<Self> {
        let mut account = Self::from_billing(view)?;
        account.operator_url_allowed = billing.trusted_operator_url(
            &account.details.operator_url,
            &account.details.provider_subscription_id,
        );
        Some(account)
    }
}

pub struct BillingPage<'a> {
    pub viewer: &'a crate::web::pages::TypedViewer,
    pub csrf: &'a str,
    pub account: Option<AccountView>,
    pub choice_key: String,
    pub portal_key: String,
    pub cancel_key: String,
    pub notice: &'static str,
    pub error: &'static str,
}

#[derive(Default, Deserialize)]
pub struct BillingQuery {
    #[serde(default)]
    done: String,
    #[serde(default)]
    error: String,
}

pub async fn page(
    AxumState(state): AxumState<State>,
    member: Member,
    Query(query): Query<BillingQuery>,
) -> PageResult {
    if !state.billing.enabled() || member.membership.role != "owner" {
        return not_found_page(&state, &member.browser);
    }
    let account = AccountView::from_billing(
        state
            .billing
            .account_for_page(member.membership.organisation_id)
            .await,
    );
    let notice = match query.done.as_str() {
        "changed" => "Plan change requested.",
        "cancelled" => "Cancellation requested for the end of the current period.",
        _ => "",
    };
    let error = if query.error == "unavailable" {
        "Billing is unavailable. Try again later."
    } else {
        ""
    };
    signed_in_typed(
        &state,
        &member.browser,
        &member.session,
        Some(&member.membership),
        StatusCode::OK,
        "Billing",
        "org-settings",
        None,
        None,
        None,
        |viewer, csrf| {
            template::render(&BillingPage {
                viewer,
                csrf,
                account,
                notice,
                error,
                choice_key: Uuid::now_v7().to_string(),
                portal_key: Uuid::now_v7().to_string(),
                cancel_key: Uuid::now_v7().to_string(),
            })
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct BillingForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    plan: String,
    #[serde(default)]
    idempotency_key: String,
}

fn billing_url(slug: &str, error: bool) -> String {
    format!(
        "/{slug}/settings/billing{}",
        if error { "?error=unavailable" } else { "" }
    )
}

fn external_redirect(url: &str) -> Response {
    let mut response = redirect(url);
    let origin = reqwest::Url::parse(url)
        .expect("redirect was validated by billing")
        .origin()
        .ascii_serialization();
    let csp = crate::web::CSP.replace(
        "form-action 'self'",
        &format!("form-action 'self' {origin}"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&csp).expect("valid policy"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

pub async fn choose(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<BillingForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (_, membership) = match member_of(&state, &browser, &uri, &slug).await {
        Ok(member) => member,
        Err(response) => return Ok(*response),
    };
    if !state.billing.enabled() || membership.role != "owner" {
        return not_found_page(&state, &browser);
    }
    if !matches!(form.plan.as_str(), "Homelab" | "Pro" | "Business") {
        return Ok(redirect(&billing_url(&slug, true)));
    }
    let Ok(key) = Uuid::parse_str(&form.idempotency_key) else {
        return Ok(redirect(&billing_url(&slug, true)));
    };
    let result = match state.billing.account_now(membership.organisation_id).await {
        BillingView::Account(details)
            if details.complimentary || details.complimentary_scheduled =>
        {
            Err(BillingError::Unavailable)
        }
        BillingView::Account(details) if details.plan != "Free" && !details.plan.is_empty() => {
            state
                .billing
                .change_plan(membership.organisation_id, &form.plan, key)
                .await
                .map(|()| None)
        }
        BillingView::Account(_) => {
            let success = format!(
                "{}/{}/settings/billing",
                state.config.public_origin().serialized,
                membership.slug
            );
            state
                .billing
                .checkout(membership.organisation_id, &form.plan, &success, key)
                .await
                .map(Some)
        }
        _ => Err(BillingError::Unavailable),
    };
    Ok(match result {
        Ok(Some(url)) => external_redirect(&url),
        Ok(None) => redirect(&format!("/{slug}/settings/billing?done=changed")),
        Err(_) => redirect(&billing_url(&slug, true)),
    })
}

pub async fn cancel(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<BillingForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (_, membership) = match member_of(&state, &browser, &uri, &slug).await {
        Ok(member) => member,
        Err(response) => return Ok(*response),
    };
    if !state.billing.enabled() || membership.role != "owner" {
        return not_found_page(&state, &browser);
    }
    let Ok(key) = Uuid::parse_str(&form.idempotency_key) else {
        return Ok(redirect(&billing_url(&slug, true)));
    };
    let result = state.billing.cancel(membership.organisation_id, key).await;
    Ok(redirect(&format!(
        "/{slug}/settings/billing?{}",
        if result.is_ok() {
            "done=cancelled"
        } else {
            "error=unavailable"
        }
    )))
}

pub async fn portal(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<BillingForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (_, membership) = match member_of(&state, &browser, &uri, &slug).await {
        Ok(member) => member,
        Err(response) => return Ok(*response),
    };
    if !state.billing.enabled() || membership.role != "owner" {
        return not_found_page(&state, &browser);
    }
    let Ok(key) = Uuid::parse_str(&form.idempotency_key) else {
        return Ok(redirect(&billing_url(&slug, true)));
    };
    let back = format!(
        "{}/{}/settings/billing",
        state.config.public_origin().serialized,
        membership.slug
    );
    Ok(
        match state
            .billing
            .portal(membership.organisation_id, &back, key)
            .await
        {
            Ok(url) => external_redirect(&url),
            Err(_) => redirect(&billing_url(&slug, true)),
        },
    )
}
