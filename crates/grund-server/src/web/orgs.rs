//! Organisation pages: `/` sends a signed-in person to one of their
//! organisations; `/{org}`, `/{org}/members` and `/{org}/settings` are about
//! one of them; `/orgs/new` creates one; `/invite` accepts an invitation.
//!
//! Every `/{org}` page first resolves the viewer's membership. A slug the
//! viewer is not a member of gets the same 404 as one that does not exist.

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{StatusCode, Uri},
    response::Response,
};
use grund_domain::organisation::Role;
use grund_store::organisations::Membership;
use minijinja::{Value, context};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::{
        accounts::{AccountsState, FieldErrors, InvitedSignupOutcome},
        billing::BillingView,
        organisations::{
            AcceptOutcome, ChangeOutcome, CreateOutcome, DeleteOutcome, InviteOutcome,
            OrganisationsState, RenameOutcome,
        },
        sessions::Session,
    },
    state::State,
    web::{
        browser::Browser,
        pages::{
            PageError, forged, message, not_found_page, redirect, render, require_session,
            start_session, viewer_context,
        },
    },
};

type PageResult = Result<Response, PageError>;

async fn member_of(
    state: &State,
    browser: &Browser,
    uri: &Uri,
    slug: &str,
) -> Result<(Session, Membership), Box<Response>> {
    let session = require_session(browser, uri)?;
    match state.organisations().open(slug, session.account_id).await {
        Ok(Some(membership)) => Ok((session, membership)),
        Ok(None) => match state
            .organisations()
            .renamed_to(slug, session.account_id)
            .await
        {
            Ok(Some(current)) => {
                let rest = uri.path().strip_prefix(&format!("/{slug}")).unwrap_or("");
                let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
                Err(Box::new(permanent_redirect(&format!(
                    "/{current}{rest}{query}"
                ))))
            }
            Ok(None) => Err(Box::new(
                not_found_page(state, browser).unwrap_or_else(error_response),
            )),
            Err(error) => Err(Box::new(error_response(PageError::from(error)))),
        },
        Err(error) => Err(Box::new(error_response(PageError::from(error)))),
    }
}

fn permanent_redirect(to: &str) -> Response {
    let mut response = axum::response::IntoResponse::into_response(StatusCode::PERMANENT_REDIRECT);
    if let Ok(location) = axum::http::HeaderValue::from_str(to) {
        response
            .headers_mut()
            .insert(axum::http::header::LOCATION, location);
    }
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

fn error_response(error: PageError) -> Response {
    axum::response::IntoResponse::into_response(error)
}

macro_rules! member_or_return {
    ($state:expr, $browser:expr, $uri:expr, $slug:expr) => {
        match member_of($state, $browser, $uri, $slug).await {
            Ok(found) => found,
            Err(response) => return Ok(*response),
        }
    };
}

/// `/`: the organisation used last, or the first; a page saying there is
/// none when the account belongs to no organisation.
pub async fn landing(AxumState(state): AxumState<State>, browser: Browser, uri: Uri) -> PageResult {
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(redirect) => return Ok(*redirect),
    };
    if let Some(slug) = state.organisations().landing(session.account_id).await? {
        return Ok(redirect(&format!("/{slug}")));
    }
    let viewer = viewer_context(&state, &session, None).await?;
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/no-organisation.html.jinja",
        context! { viewer, csrf => browser.csrf_token(), section => "overview" },
    )
}

/// `/{org}`: the organisation's overview.
pub async fn overview(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let viewer = viewer_context(&state, &session, Some(&membership)).await?;
    let members = state
        .organisations()
        .members(membership.organisation_id)
        .await?
        .len();
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/home.html.jinja",
        context! { viewer, members, csrf => browser.csrf_token(), section => "overview" },
    )
}

#[derive(Deserialize, Default)]
pub struct NoticeQuery {
    #[serde(default)]
    done: String,
    #[serde(default)]
    error: String,
}

/// `/{org}/members`: members, pending invitations, and (for owners and
/// admins) the forms that change them.
pub async fn members_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Query(query): Query<NoticeQuery>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let notice = match query.done.as_str() {
        "invited" => "Invitation sent. The link works for 7 days.",
        "revoked" => "Invitation withdrawn. Its link no longer works.",
        "role" => "Role changed.",
        "removed" => "Member removed.",
        _ => "",
    };
    let error = match query.error.as_str() {
        "not-allowed" => "Your role does not allow that.",
        "last-owner" => {
            "An organisation needs at least one owner. Make someone else an owner first."
        }
        "gone" => "That member or invitation is no longer there.",
        _ => "",
    };
    members_view(
        &state,
        &browser,
        &session,
        &membership,
        StatusCode::OK,
        MembersForm {
            notice,
            error,
            ..Default::default()
        },
    )
    .await
}

#[derive(Default)]
struct MembersForm<'a> {
    notice: &'a str,
    error: &'a str,
    invite_error: String,
    email: String,
    role: String,
}

async fn members_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    status: StatusCode,
    form: MembersForm<'_>,
) -> PageResult {
    let organisations = state.organisations();
    let viewer_role = Role::parse(&membership.role).unwrap_or(Role::Member);
    let members: Vec<Value> = organisations
        .members(membership.organisation_id)
        .await?
        .into_iter()
        .map(|m| {
            let role = Role::parse(&m.role).unwrap_or(Role::Member);
            let is_self = m.account_id == session.account_id;
            let manageable = !is_self
                && viewer_role.manages_members()
                && (role != Role::Owner || viewer_role == Role::Owner);
            context! {
                id => m.account_id.to_string(),
                username => m.username,
                email => m.email,
                role => m.role,
                joined => m.joined_at.map(|at| at.format("%-d %b %Y").to_string()).unwrap_or_default(),
                is_self,
                manageable,
            }
        })
        .collect();
    let pending: Vec<Value> = organisations
        .pending(membership.organisation_id)
        .await?
        .into_iter()
        .map(|i| {
            context! {
                id => i.invitation_id.to_string(),
                email => i.email,
                role => i.role,
                invited_by => i.invited_by,
                expires => i.expires_at.format("%-d %b %Y").to_string(),
            }
        })
        .collect();
    let roles: &[&str] = if viewer_role == Role::Owner {
        &["member", "admin", "owner"]
    } else {
        &["member", "admin"]
    };
    let viewer = viewer_context(state, session, Some(membership)).await?;
    render(
        state,
        browser,
        status,
        "pages/members.html.jinja",
        context! {
            viewer, members, pending, roles,
            notice => form.notice, error => form.error,
            invite_error => form.invite_error, email => form.email,
            role => if form.role.is_empty() { "member".to_string() } else { form.role },
            csrf => browser.csrf_token(), section => "members",
        },
    )
}

#[derive(Deserialize)]
pub struct InviteForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    role: String,
}

/// `POST /{org}/members/invite`.
pub async fn invite(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<InviteForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let actor_name = state
        .accounts()
        .viewer(session.account_id)
        .await?
        .map(|v| v.username)
        .unwrap_or_default();
    let outcome = state
        .organisations()
        .invite(
            session.account_id,
            &actor_name,
            &membership,
            &form.email,
            &form.role,
            &browser.meta(),
        )
        .await?;
    let (status, invite_error) = match outcome {
        InviteOutcome::Sent(_) => return Ok(redirect(&format!("/{slug}/members?done=invited"))),
        InviteOutcome::AlreadyMember => (
            StatusCode::OK,
            "That address already belongs to a member.".to_string(),
        ),
        InviteOutcome::Invalid(message) => (StatusCode::OK, message),
        InviteOutcome::NotAllowed => (
            StatusCode::FORBIDDEN,
            "Your role does not allow inviting.".to_string(),
        ),
        InviteOutcome::TooMany => (
            StatusCode::OK,
            "This organisation has 50 pending invitations. Withdraw some first.".to_string(),
        ),
        InviteOutcome::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many mails to that address lately. Try again in an hour.".to_string(),
        ),
    };
    members_view(
        &state,
        &browser,
        &session,
        &membership,
        status,
        MembersForm {
            invite_error,
            email: form.email,
            role: form.role,
            ..Default::default()
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

#[derive(Deserialize)]
pub struct RoleForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    role: String,
}

fn after_change(slug: &str, outcome: ChangeOutcome, done: &str) -> Response {
    let query = match outcome {
        ChangeOutcome::Done => format!("done={done}"),
        ChangeOutcome::NotAllowed => "error=not-allowed".into(),
        ChangeOutcome::LastOwner => "error=last-owner".into(),
        ChangeOutcome::NotFound => "error=gone".into(),
    };
    redirect(&format!("/{slug}/members?{query}"))
}

/// `POST /{org}/members/{account}/role`.
pub async fn change_role(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, account_id)): Path<(String, Uuid)>,
    Form(form): Form<RoleForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let outcome = state
        .organisations()
        .change_role(
            session.account_id,
            membership.organisation_id,
            account_id,
            &form.role,
            &browser.meta(),
        )
        .await?;
    Ok(after_change(&slug, outcome, "role"))
}

/// `POST /{org}/members/{account}/remove`. Removing yourself is leaving,
/// which lands on `/`.
pub async fn remove_member(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, account_id)): Path<(String, Uuid)>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let outcome = state
        .organisations()
        .remove(
            session.account_id,
            membership.organisation_id,
            account_id,
            &browser.meta(),
        )
        .await?;
    if outcome == ChangeOutcome::Done && account_id == session.account_id {
        return Ok(redirect("/"));
    }
    Ok(after_change(&slug, outcome, "removed"))
}

/// `POST /{org}/invitations/{invitation}/revoke`.
pub async fn revoke_invitation(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path((slug, invitation_id)): Path<(String, Uuid)>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let outcome = state
        .organisations()
        .revoke(
            session.account_id,
            membership.organisation_id,
            invitation_id,
            &browser.meta(),
        )
        .await?;
    Ok(after_change(&slug, outcome, "revoked"))
}

/// `/{org}/settings`: the organisation's name, its plan and who manages
/// billing, and for owners, renaming and deleting.
pub async fn settings_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Query(query): Query<NoticeQuery>,
) -> PageResult {
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let notice = match query.done.as_str() {
        "renamed" => "Renamed. The old name keeps working as a redirect for members.",
        _ => "",
    };
    settings_view(
        &state,
        &browser,
        &session,
        &membership,
        StatusCode::OK,
        SettingsForm {
            notice,
            ..Default::default()
        },
    )
    .await
}

#[derive(Default)]
struct SettingsForm<'a> {
    notice: &'a str,
    rename_error: String,
    rename_value: String,
    delete_error: String,
}

async fn settings_view(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: &Membership,
    status: StatusCode,
    form: SettingsForm<'_>,
) -> PageResult {
    let organisations = state.organisations();
    let owners: Vec<String> = organisations
        .members(membership.organisation_id)
        .await?
        .into_iter()
        .filter(|m| m.role == Role::Owner.as_str())
        .map(|m| m.username)
        .collect();
    let billing = match organisations.billing(membership.organisation_id).await {
        BillingView::Free => {
            context! { state => "free", plan => "Free", past_due => false, manage_url => () }
        }
        BillingView::Account {
            plan,
            past_due,
            manage_url,
        } => context! { state => "account", plan, past_due, manage_url },
        BillingView::Unavailable => {
            context! { state => "unavailable", plan => "", past_due => false, manage_url => () }
        }
    };
    let viewer = viewer_context(state, session, Some(membership)).await?;
    let rename_value = if form.rename_value.is_empty() {
        membership.slug.clone()
    } else {
        form.rename_value
    };
    render(
        state,
        browser,
        status,
        "pages/org-settings.html.jinja",
        context! {
            viewer, owners, billing, rename_value,
            deleting => membership.deletion_requested_at.is_some(),
            refusal => membership.deletion_refusal.clone().unwrap_or_default(),
            notice => form.notice,
            rename_error => form.rename_error,
            delete_error => form.delete_error,
            csrf => browser.csrf_token(), section => "org-settings",
        },
    )
}

#[derive(Deserialize)]
pub struct RenameForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    slug: String,
}

/// `POST /{org}/settings/rename`.
pub async fn rename(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<RenameForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let (status, rename_error) = match state
        .organisations()
        .rename(session.account_id, &membership, &form.slug, &browser.meta())
        .await?
    {
        RenameOutcome::Renamed(new) => {
            return Ok(redirect(&format!("/{new}/settings?done=renamed")));
        }
        RenameOutcome::Invalid(message) => (StatusCode::OK, message),
        RenameOutcome::NotAllowed => (
            StatusCode::FORBIDDEN,
            "Only owners rename an organisation.".to_string(),
        ),
    };
    settings_view(
        &state,
        &browser,
        &session,
        &membership,
        status,
        SettingsForm {
            rename_error,
            rename_value: form.slug,
            ..Default::default()
        },
    )
    .await
}

#[derive(Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    confirm: String,
}

/// `POST /{org}/settings/delete`: asks to delete; the settings page then
/// shows the request until billing has answered.
pub async fn delete(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<DeleteForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let (status, delete_error) = match state
        .organisations()
        .request_deletion(
            session.account_id,
            &membership,
            &form.confirm,
            &browser.meta(),
        )
        .await?
    {
        DeleteOutcome::Requested => return Ok(redirect(&format!("/{slug}/settings"))),
        DeleteOutcome::Unconfirmed => (
            StatusCode::OK,
            format!("Type {} exactly to delete it.", membership.slug),
        ),
        DeleteOutcome::NotAllowed => (
            StatusCode::FORBIDDEN,
            "Only owners delete an organisation.".to_string(),
        ),
        DeleteOutcome::Instance => (
            StatusCode::OK,
            "This is the instance's own organisation, and an instance needs it.".to_string(),
        ),
    };
    settings_view(
        &state,
        &browser,
        &session,
        &membership,
        status,
        SettingsForm {
            delete_error,
            ..Default::default()
        },
    )
    .await
}

/// `POST /{org}/settings/cancel-deletion`.
pub async fn cancel_deletion(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (session, membership) = member_or_return!(&state, &browser, &uri, &slug);
    state
        .organisations()
        .cancel_deletion(session.account_id, &membership, &browser.meta())
        .await?;
    Ok(redirect(&format!("/{slug}/settings")))
}

/// `/orgs/new`.
pub async fn new_form(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
) -> PageResult {
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(redirect) => return Ok(*redirect),
    };
    if !state.organisations().can_create() {
        return not_found_page(&state, &browser);
    }
    new_page(&state, &browser, &session, StatusCode::OK, "", "").await
}

async fn new_page(
    state: &State,
    browser: &Browser,
    session: &Session,
    status: StatusCode,
    slug: &str,
    error: &str,
) -> PageResult {
    let viewer = viewer_context(state, session, None).await?;
    render(
        state,
        browser,
        status,
        "pages/org-new.html.jinja",
        context! { viewer, slug, error, csrf => browser.csrf_token(), section => "new-organisation" },
    )
}

#[derive(Deserialize)]
pub struct NewForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    slug: String,
}

/// `POST /orgs/new`.
pub async fn create(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Form(form): Form<NewForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(redirect) => return Ok(*redirect),
    };
    match state
        .organisations()
        .create(session.account_id, &form.slug, &browser.meta())
        .await?
    {
        CreateOutcome::Created(slug) => Ok(redirect(&format!("/{slug}"))),
        CreateOutcome::Invalid(error) => {
            new_page(
                &state,
                &browser,
                &session,
                StatusCode::OK,
                &form.slug,
                &error,
            )
            .await
        }
        CreateOutcome::NotAvailable => not_found_page(&state, &browser),
    }
}

#[derive(Deserialize, Default)]
pub struct TokenQuery {
    #[serde(default)]
    token: String,
}

/// `/invite?token=`: what the invitation offers depends on who opens it
/// (grund-docs design/organisations.md, Invitations).
pub async fn invitation_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Query(query): Query<TokenQuery>,
) -> PageResult {
    invitation_view(
        &state,
        &browser,
        &query.token,
        StatusCode::OK,
        &FieldErrors::default(),
        "",
    )
    .await
}

async fn invitation_view(
    state: &State,
    browser: &Browser,
    token: &str,
    status: StatusCode,
    errors: &FieldErrors,
    username: &str,
) -> PageResult {
    let Some(invitation) = state.organisations().invitation(token).await? else {
        return expired(state, browser);
    };
    let signed_in = match &browser.session {
        Some(session) => state.accounts().viewer(session.account_id).await?,
        None => None,
    };
    let has_account = state
        .accounts()
        .has_account(&invitation.email_normalized)
        .await?;
    let mode = match &signed_in {
        Some(viewer) if viewer.email.to_lowercase() == invitation.email_normalized => "join",
        Some(_) => "other-account",
        None if has_account => "sign-in",
        None => "sign-up",
    };
    let return_to = serde_urlencoded::to_string([("return_to", format!("/invite?token={token}"))])
        .unwrap_or_default();
    let response = render(
        state,
        browser,
        status,
        "pages/invite.html.jinja",
        context! {
            mode, token, errors, username, return_to,
            organisation => invitation.slug,
            invited_by => invitation.invited_by,
            role => invitation.role,
            email => invitation.email,
            signed_in_as => signed_in.map(|v| v.username),
            csrf => browser.csrf_token(),
        },
    )?;
    Ok(super::pages::with_referrer_same_origin(response))
}

fn expired(state: &State, browser: &Browser) -> PageResult {
    message(
        state,
        browser,
        StatusCode::OK,
        "This invitation has expired",
        "Invitations work once, for 7 days, and stop working when they are withdrawn. Ask for a new one.",
        Some(("/", "Go to grund")),
    )
}

#[derive(Deserialize)]
pub struct InvitationForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
}

/// `POST /invite`: joins the signed-in account, or creates an account for
/// the invited address.
pub async fn accept_invitation(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Form(form): Form<InvitationForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    if let Some(session) = &browser.session {
        return match state
            .organisations()
            .accept(session.account_id, &form.token, &browser.meta())
            .await?
        {
            AcceptOutcome::Joined(slug) | AcceptOutcome::AlreadyMember(slug) => {
                Ok(redirect(&format!("/{slug}")))
            }
            AcceptOutcome::WrongAccount => {
                invitation_view(
                    &state,
                    &browser,
                    &form.token,
                    StatusCode::OK,
                    &FieldErrors::default(),
                    "",
                )
                .await
            }
            AcceptOutcome::Expired => expired(&state, &browser),
        };
    }
    match state
        .accounts()
        .sign_up_invited(&form.token, &form.username, &form.password, &browser.meta())
        .await?
    {
        InvitedSignupOutcome::SignedIn {
            account_id,
            organisation,
        } => start_session(&state, &browser, account_id, &format!("/{organisation}")).await,
        InvitedSignupOutcome::Invalid(errors) => {
            invitation_view(
                &state,
                &browser,
                &form.token,
                StatusCode::OK,
                &errors,
                &form.username,
            )
            .await
        }
        InvitedSignupOutcome::HasAccount => {
            invitation_view(
                &state,
                &browser,
                &form.token,
                StatusCode::OK,
                &FieldErrors::default(),
                "",
            )
            .await
        }
        InvitedSignupOutcome::Expired => expired(&state, &browser),
    }
}
