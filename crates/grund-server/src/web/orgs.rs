//! Organisation pages: `/` sends a signed-in person to one of their
//! organisations; `/{org}` (the Overview, with its first apps),
//! `/{org}/members` and `/{org}/settings` are about one of them; `/orgs/new` creates one; `/invite` accepts an invitation.
//!
//! Every `/{org}` page first resolves the viewer's membership. A slug the
//! viewer is not a member of gets the same 404 as one that does not exist.

use axum::{
    Form,
    extract::{FromRequestParts, Path, Query, RawPathParams, State as AxumState},
    http::{StatusCode, Uri, request::Parts},
    response::{IntoResponse, Response},
};
use grund_domain::organisation::Role;
use grund_store::organisations::Membership;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::{
        accounts::{AccountsState, FieldErrors, InvitedSignupOutcome},
        apps::{AppListing, AppsState},
        billing::BillingView,
        organisations::{
            AcceptOutcome, ChangeOutcome, CreateOutcome, DeleteOutcome, InviteOutcome,
            OrganisationsState, RenameOutcome,
        },
        sessions::Session,
    },
    state::State,
    web::{
        apps,
        browser::Browser,
        pages::{
            Notice, PageError, PageResult, forged, message, not_found_page, redirect,
            require_session, start_session,
        },
    },
};

const OVERVIEW_APPS: usize = 5;
pub fn role_title(role: &str) -> &'static str {
    match role {
        "owner" => "Owner",
        "admin" => "Admin",
        _ => "Member",
    }
}

pub struct HomePage<'a> {
    pub viewer: &'a super::pages::TypedViewer,
    pub members: usize,
    pub icons: Vec<&'static str>,
    pub apps: Vec<apps::ListingView>,
    pub app_count: usize,
}

pub struct MemberRow {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub joined: String,
    pub is_self: bool,
    pub manageable: bool,
}

pub struct InvitationRow {
    pub id: String,
    pub email: String,
    pub role: String,
    pub invited_by: String,
    pub expires: String,
}

pub struct MembersPage<'a> {
    pub viewer: &'a super::pages::TypedViewer,
    pub csrf: &'a str,
    pub members: Vec<MemberRow>,
    pub pending: Vec<InvitationRow>,
    pub roles: &'static [(&'static str, &'static str)],
    pub notice: &'a str,
    pub error: &'a str,
    pub invite_error: String,
    pub email: String,
    pub role: String,
}

pub struct BillingPage {
    pub state: &'static str,
    pub plan: String,
    pub past_due: bool,
    pub manage_url: Option<String>,
}

pub struct SettingsPage<'a> {
    pub viewer: &'a super::pages::TypedViewer,
    pub csrf: &'a str,
    pub owners: Vec<String>,
    pub billing: BillingPage,
    pub rename_value: String,
    pub deleting: bool,
    pub refusal: String,
    pub notice: &'a str,
    pub rename_error: String,
    pub delete_error: String,
}

pub struct NewOrganisationPage<'a> {
    pub csrf: &'a str,
    pub slug: &'a str,
    pub error: &'a str,
}

pub(super) async fn member_of(
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

/// A page handler's signed-in member of the organisation its `{org}` path
/// segment names, with the browser asking. Extracting it answers instead
/// of the handler when there is no session (sign-in, coming back here), the
/// organisation was renamed (a permanent redirect) or the viewer is not a
/// member (the 404 page). For pages that only read; a handler that takes a
/// form checks its CSRF token first and then calls `member_or_return!`.
pub struct Member {
    pub browser: Browser,
    pub session: Session,
    pub membership: Membership,
}

impl FromRequestParts<State> for Member {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &State) -> Result<Self, Response> {
        let Ok(browser) = Browser::from_request_parts(parts, state).await;
        let slug = RawPathParams::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?
            .iter()
            .find(|(name, _)| *name == "org")
            .map(|(_, value)| value.to_string())
            .unwrap_or_default();
        let (session, membership) = member_of(state, &browser, &parts.uri, &slug)
            .await
            .map_err(|response| *response)?;
        Ok(Self {
            browser,
            session,
            membership,
        })
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
    super::pages::signed_in_typed(
        &state,
        &browser,
        &session,
        None,
        StatusCode::OK,
        "",
        "overview",
        None,
        None,
        None,
        |viewer, _| {
            crate::templates::compiled::pages::no_organisation::render(
                &super::pages::NoOrganisationPage {
                    can_create: viewer.can_create,
                },
            )
        },
    )
    .await
}

/// `/{org}`: the organisation's overview.
pub async fn overview(AxumState(state): AxumState<State>, member: Member) -> PageResult {
    let membership = &member.membership;
    let members = state
        .organisations()
        .members(membership.organisation_id)
        .await?
        .len();
    let listings = state
        .apps()
        .listings(membership.organisation_id, &membership.slug)
        .await
        .map_err(|e| PageError::from(anyhow::anyhow!(e)))?;
    let shown: Vec<&AppListing> = listings.iter().take(OVERVIEW_APPS).collect();
    super::pages::signed_in_typed(
        &state,
        &member.browser,
        &member.session,
        Some(membership),
        StatusCode::OK,
        "",
        "overview",
        None,
        None,
        None,
        |viewer, _| {
            crate::templates::compiled::pages::home::render(&HomePage {
                viewer,
                members,
                icons: apps::icons_of(&shown),
                apps: shown.iter().map(|l| apps::listing_view(l)).collect(),
                app_count: listings.len(),
            })
        },
    )
    .await
}

/// `/{org}/settings/members`: members, pending invitations, and (for owners and
/// admins) the forms that change them.
pub async fn members_page(
    AxumState(state): AxumState<State>,
    member: Member,
    Query(query): Query<Notice>,
) -> PageResult {
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
        &member.browser,
        &member.session,
        &member.membership,
        StatusCode::OK,
        MembersForm {
            notice,
            error,
            ..Default::default()
        },
    )
    .await
}

/// `/{org}/members`, where the members page used to be: a permanent redirect
/// to `/{org}/settings/members`, for members only.
pub async fn members_moved(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(slug): Path<String>,
) -> PageResult {
    let (_, membership) = member_or_return!(&state, &browser, &uri, &slug);
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    Ok(permanent_redirect(&format!(
        "/{}/settings/members{query}",
        membership.slug
    )))
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
    let members: Vec<MemberRow> = organisations
        .members(membership.organisation_id)
        .await?
        .into_iter()
        .map(|m| {
            let role = Role::parse(&m.role).unwrap_or(Role::Member);
            let is_self = m.account_id == session.account_id;
            let manageable = !is_self
                && viewer_role.manages_members()
                && (role != Role::Owner || viewer_role == Role::Owner);
            MemberRow {
                id: m.account_id.to_string(),
                username: m.username,
                email: m.email,
                role: m.role,
                joined: m
                    .joined_at
                    .map(|at| at.format("%-d %b %Y").to_string())
                    .unwrap_or_default(),
                is_self,
                manageable,
            }
        })
        .collect();
    let pending: Vec<InvitationRow> = organisations
        .pending(membership.organisation_id)
        .await?
        .into_iter()
        .map(|i| InvitationRow {
            id: i.invitation_id.to_string(),
            email: i.email,
            role: i.role,
            invited_by: i.invited_by,
            expires: i.expires_at.format("%-d %b %Y").to_string(),
        })
        .collect();
    let roles: &[(&str, &str)] = if viewer_role == Role::Owner {
        &[("member", "Member"), ("admin", "Admin"), ("owner", "Owner")]
    } else {
        &[("member", "Member"), ("admin", "Admin")]
    };
    super::pages::signed_in_typed(
        state,
        browser,
        session,
        Some(membership),
        status,
        "Members",
        "members",
        None,
        None,
        None,
        |viewer, csrf| {
            crate::templates::compiled::pages::members::render(&MembersPage {
                viewer,
                csrf,
                members,
                pending,
                roles,
                notice: form.notice,
                error: form.error,
                invite_error: form.invite_error,
                email: form.email,
                role: if form.role.is_empty() {
                    "member".to_string()
                } else {
                    form.role
                },
            })
        },
    )
    .await
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

/// `POST /{org}/settings/members/invite`.
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
        InviteOutcome::Sent(_) => {
            return Ok(redirect(&format!("/{slug}/settings/members?done=invited")));
        }
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
    redirect(&format!("/{slug}/settings/members?{query}"))
}

/// `POST /{org}/settings/members/{account}/role`.
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

/// `POST /{org}/settings/members/{account}/remove`. Removing yourself is leaving,
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

/// `POST /{org}/settings/invitations/{invitation}/revoke`.
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
    member: Member,
    Query(query): Query<Notice>,
) -> PageResult {
    let notice = match query.done.as_str() {
        "renamed" => "Renamed. The old name keeps working as a redirect for members.",
        _ => "",
    };
    settings_view(
        &state,
        &member.browser,
        &member.session,
        &member.membership,
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
        BillingView::Free => BillingPage {
            state: "free",
            plan: "Free".into(),
            past_due: false,
            manage_url: None,
        },
        BillingView::Account {
            plan,
            past_due,
            manage_url,
        } => BillingPage {
            state: "account",
            plan,
            past_due,
            manage_url,
        },
        BillingView::Unavailable => BillingPage {
            state: "unavailable",
            plan: String::new(),
            past_due: false,
            manage_url: None,
        },
    };
    let rename_value = if form.rename_value.is_empty() {
        membership.slug.clone()
    } else {
        form.rename_value
    };
    super::pages::signed_in_typed(
        state,
        browser,
        session,
        Some(membership),
        status,
        "Organisation",
        "org-settings",
        None,
        membership.deletion_requested_at.as_ref().map(|_| 3),
        None,
        |viewer, csrf| {
            crate::templates::compiled::pages::org_settings::render(&SettingsPage {
                viewer,
                csrf,
                owners,
                billing,
                rename_value,
                deleting: membership.deletion_requested_at.is_some(),
                refusal: membership.deletion_refusal.clone().unwrap_or_default(),
                notice: form.notice,
                rename_error: form.rename_error,
                delete_error: form.delete_error,
            })
        },
    )
    .await
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
    super::pages::signed_in_typed(
        state,
        browser,
        session,
        None,
        status,
        "New organisation",
        "new-organisation",
        None,
        None,
        None,
        |_, csrf| {
            crate::templates::compiled::pages::org_new::render(&NewOrganisationPage {
                csrf,
                slug,
                error,
            })
        },
    )
    .await
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
    let csrf = browser.csrf_token();
    let response = super::pages::render_typed(
        browser,
        status,
        crate::templates::compiled::pages::invite::render(&super::pages::InvitePage {
            mode,
            token,
            errors,
            username,
            return_to: &return_to,
            organisation: &invitation.slug,
            invited_by: &invitation.invited_by,
            role: &invitation.role,
            email: &invitation.email,
            signed_in_as: signed_in.as_ref().map(|viewer| viewer.username.as_str()),
            csrf: &csrf,
        }),
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
