//! The server-rendered pages: sign-up, verification, sign-in, sign-out,
//! password reset, the signed-in home and the sessions page.

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use grund_domain::organisation::Role;
use grund_store::organisations::Membership;
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::{
        accounts::{
            AccountsState, FieldErrors, LoginOutcome, OwnerSignupOutcome, ResetOutcome,
            ResetRequestOutcome, SignupForm, SignupOutcome,
        },
        organisations::{Home, OrganisationsState},
        sessions::{Session, SessionsState},
    },
    state::State,
    web::browser::Browser,
};

/// A page, or why it could not be served.
pub enum PageError {
    /// Something broke; logged with the request id, shown generically.
    Internal(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for PageError {
    fn from(error: E) -> Self {
        PageError::Internal(error.into())
    }
}

impl IntoResponse for PageError {
    fn into_response(self) -> Response {
        let PageError::Internal(error) = self;
        let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();
        response
            .extensions_mut()
            .insert(Failed(std::sync::Arc::new(error)));
        response
    }
}

/// Marks a response as a failure for [`crate::web::request_context`] to
/// render and log.
#[derive(Clone)]
pub struct Failed(pub std::sync::Arc<anyhow::Error>);

/// What a page handler answers: the page, or why it could not be served.
pub type PageResult = Result<Response, PageError>;

pub fn render_typed(browser: &Browser, status: StatusCode, html: String) -> PageResult {
    let mut response = (status, axum::response::Html(html)).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for cookie in browser.cookies() {
        headers.append(header::SET_COOKIE, cookie);
    }
    Ok(response)
}

#[derive(Clone, serde::Serialize)]
pub struct TypedOrg {
    pub slug: String,
    pub role: String,
    pub kind: String,
    pub manages: bool,
    pub owner: bool,
    pub since: String,
    pub current: bool,
}

#[derive(Clone, serde::Serialize)]
pub struct TypedViewer {
    pub username: String,
    pub email: String,
    pub initials: String,
    pub orgs: Vec<TypedOrg>,
    pub current: Option<TypedOrg>,
    pub can_create: bool,
    pub registered_on: String,
}

#[derive(serde::Serialize)]
pub struct AppSearch {
    pub q: String,
    pub sort: String,
    pub view: String,
}

pub struct LoginPage<'a> {
    pub csrf: &'a str,
    pub login: &'a str,
    pub error: &'a str,
    pub notice: &'a str,
    pub return_to: &'a str,
    pub providers: &'a [crate::extension::LoginProvider],
    pub signup_enabled: bool,
}

pub struct SignupPage<'a> {
    pub csrf: &'a str,
    pub username: &'a str,
    pub email: &'a str,
    pub errors: &'a FieldErrors,
    pub error: &'a str,
}

pub struct SignupOwnerPage<'a> {
    pub csrf: &'a str,
    pub token: &'a str,
    pub username: &'a str,
    pub email: &'a str,
    pub errors: &'a FieldErrors,
}

pub struct MessagePage<'a> {
    pub title: &'a str,
    pub text: &'a str,
    pub link_href: &'a str,
    pub link_text: &'a str,
}

pub struct VerifyPage<'a> {
    pub csrf: &'a str,
    pub token: &'a str,
    pub valid: bool,
}

pub struct ResetPage<'a> {
    pub csrf: &'a str,
    pub email: &'a str,
    pub error: &'a str,
}

pub struct ResetConfirmPage<'a> {
    pub csrf: &'a str,
    pub token: &'a str,
    pub valid: bool,
    pub error: &'a str,
    pub password_error: &'a str,
}

pub struct SessionRow {
    pub id: String,
    pub device: String,
    pub address: String,
    pub created: String,
    pub last_seen: String,
    pub current: bool,
}

pub struct SessionsPage<'a> {
    pub csrf: &'a str,
    pub sessions: &'a [SessionRow],
    pub notice: &'a str,
}

pub struct NoOrganisationPage {
    pub can_create: bool,
}

pub struct ErrorPage<'a> {
    pub title: &'a str,
    pub text: &'a str,
    pub request_id: &'a str,
}

pub struct InvitePage<'a> {
    pub mode: &'a str,
    pub token: &'a str,
    pub errors: &'a FieldErrors,
    pub username: &'a str,
    pub return_to: &'a str,
    pub organisation: &'a str,
    pub invited_by: &'a str,
    pub role: &'a str,
    pub email: &'a str,
    pub signed_in_as: Option<&'a str>,
    pub csrf: &'a str,
}

pub struct LicensesPage<'a> {
    pub inter: &'a str,
    pub mono: &'a str,
}

pub fn redirect(to: &str) -> Response {
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(to).unwrap_or(HeaderValue::from_static("/")),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Sets `Referrer-Policy: same-origin`, for a page whose address carries a
/// token: other sites never see it, and the page's forms still post with
/// their real `Origin` (web/mod.rs).
pub fn with_referrer_same_origin(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    response
}

pub fn message(
    _state: &State,
    browser: &Browser,
    status: StatusCode,
    title: &str,
    text: &str,
    link: Option<(&str, &str)>,
) -> PageResult {
    let (link_href, link_text) = link.unwrap_or_default();
    render_typed(
        browser,
        status,
        crate::templates::compiled::pages::message::render(&MessagePage {
            title,
            text,
            link_href,
            link_text,
        }),
    )
}

pub fn forged(state: &State, browser: &Browser) -> PageResult {
    message(
        state,
        browser,
        StatusCode::FORBIDDEN,
        "This form has expired",
        "This form has expired. Reload the page and try again.",
        Some(("/", "Go to grund")),
    )
}

/// A path to return to after sign-in: same-origin paths only.
pub fn safe_return_to(value: Option<&str>) -> Option<String> {
    let value = value?;
    let ok = value.starts_with('/')
        && !value.starts_with("//")
        && !value.starts_with("/\\")
        && value.len() <= 512
        && !value.chars().any(|c| c.is_control());
    ok.then(|| value.to_string())
}

/// The signed-in session, or a redirect to sign-in that comes back here.
pub fn require_session(browser: &Browser, uri: &Uri) -> Result<Session, Box<Response>> {
    browser.session.clone().ok_or_else(|| {
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        let query = serde_urlencoded::to_string([("return_to", path)]).unwrap_or_default();
        Box::new(redirect(&format!("/login?{query}")))
    })
}

/// What every signed-in page's layout shows: the person, their
/// organisations for the switcher, and the organisation the page is about
/// (`current`). Account pages pass `None`, and the layout uses the
/// organisation `/` would open.
pub async fn typed_viewer_context(
    state: &State,
    session: &Session,
    current: Option<&Membership>,
) -> Result<TypedViewer, PageError> {
    let viewer = state
        .accounts()
        .viewer(session.account_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("session names an account that does not exist"))?;
    let organisations = state.organisations();
    let memberships = organisations.memberships_of(session.account_id).await?;
    let current = match current {
        Some(current) => Some(current.clone()),
        None => match organisations.landing(session.account_id).await? {
            Some(slug) => memberships.iter().find(|m| m.slug == slug).cloned(),
            None => None,
        },
    };
    let initials: String = viewer
        .username
        .split('-')
        .filter_map(|part| part.chars().next())
        .take(2)
        .collect();
    let orgs = memberships
        .iter()
        .map(|m| {
            let role = Role::parse(&m.role).unwrap_or(Role::Member);
            TypedOrg {
                slug: m.slug.clone(),
                role: m.role.clone(),
                kind: m.kind.clone(),
                manages: role.manages_members(),
                owner: role == Role::Owner,
                since: m.created_at.format("%-d %B %Y").to_string(),
                current: current
                    .as_ref()
                    .is_some_and(|c| c.organisation_id == m.organisation_id),
            }
        })
        .collect();
    let current = current.map(|c| {
        let role = Role::parse(&c.role).unwrap_or(Role::Member);
        TypedOrg {
            slug: c.slug,
            role: c.role,
            kind: c.kind,
            manages: role.manages_members(),
            owner: role == Role::Owner,
            since: c.created_at.format("%-d %B %Y").to_string(),
            current: true,
        }
    });
    Ok(TypedViewer {
        username: viewer.username,
        email: viewer.email,
        initials,
        orgs,
        current,
        can_create: organisations.can_create(),
        registered_on: viewer.registered_at.format("%-d %B %Y").to_string(),
    })
}

/// Renders a signed-in page in the typed app layout, using the viewer for
/// `membership` (or the organisation `/` would open) and the browser's CSRF token.
#[allow(clippy::too_many_arguments)]
pub async fn signed_in_typed(
    state: &State,
    browser: &Browser,
    session: &Session,
    membership: Option<&Membership>,
    status: StatusCode,
    title: &str,
    section: &str,
    list: Option<&AppSearch>,
    refresh: Option<u16>,
    title_org: Option<bool>,
    render: impl FnOnce(&TypedViewer, &str) -> String,
) -> PageResult {
    use sedge_rt::Render;

    let viewer = typed_viewer_context(state, session, membership).await?;
    let csrf = browser.csrf_token();
    let content = render(&viewer, &csrf);
    let html = crate::templates::compiled::layouts::App {
        title,
        viewer: &viewer,
        section,
        csrf: &csrf,
        list,
        refresh,
        title_org,
        children: &|out| out.push_str(&content),
    }
    .render_to_string();
    render_typed(browser, status, html)
}

/// The `?done=` and `?error=` a form's redirect leaves for the page it
/// lands on, which turns each into a sentence.
#[derive(Deserialize, Default)]
pub struct Notice {
    #[serde(default)]
    pub done: String,
    #[serde(default)]
    pub error: String,
}

#[derive(Deserialize, Default)]
pub struct LoginQuery {
    return_to: Option<String>,
}

pub async fn login_form(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Query(query): Query<LoginQuery>,
) -> PageResult {
    if browser.session.is_some() {
        return Ok(redirect("/"));
    }
    login_page(
        &state,
        &browser,
        StatusCode::OK,
        "",
        None,
        None,
        safe_return_to(query.return_to.as_deref()),
    )
}

fn login_page(
    state: &State,
    browser: &Browser,
    status: StatusCode,
    login: &str,
    error: Option<&str>,
    notice: Option<&str>,
    return_to: Option<String>,
) -> PageResult {
    let csrf = browser.csrf_token();
    let providers: Vec<_> = state
        .extensions
        .iter()
        .flat_map(|extension| extension.login_providers(state))
        .collect();
    render_typed(
        browser,
        status,
        crate::templates::compiled::pages::login::render(&LoginPage {
            csrf: &csrf,
            login,
            error: error.unwrap_or_default(),
            notice: notice.unwrap_or_default(),
            return_to: return_to.as_deref().unwrap_or_default(),
            providers: &providers,
            signup_enabled: state.config.signup_enabled,
        }),
    )
}

#[derive(Deserialize)]
pub struct LoginForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    login: String,
    #[serde(default)]
    password: String,
    return_to: Option<String>,
}

/// One answer for "no such account" and "wrong password".
pub const INVALID_LOGIN: &str = "That email, username or password is not right.";

pub async fn login(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Form(form): Form<LoginForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let return_to = safe_return_to(form.return_to.as_deref());
    match state
        .accounts()
        .log_in(&form.login, &form.password, &browser.meta())
        .await?
    {
        LoginOutcome::SignedIn { account_id } => {
            let response = start_session(
                &state,
                &browser,
                account_id,
                return_to.as_deref().unwrap_or("/"),
            )
            .await?;
            tracing::info!(%account_id, "signed in");
            Ok(response)
        }
        LoginOutcome::Invalid => login_page(
            &state,
            &browser,
            StatusCode::OK,
            &form.login,
            Some(INVALID_LOGIN),
            None,
            return_to,
        ),
        LoginOutcome::Locked => login_page(
            &state,
            &browser,
            StatusCode::TOO_MANY_REQUESTS,
            &form.login,
            Some(
                "Too many attempts for this account. Try again in 15 minutes, or reset your password.",
            ),
            None,
            return_to,
        ),
        LoginOutcome::RateLimited => login_page(
            &state,
            &browser,
            StatusCode::TOO_MANY_REQUESTS,
            &form.login,
            Some("Too many attempts from your network. Try again in a few minutes."),
            None,
            return_to,
        ),
        LoginOutcome::Unverified => message(
            &state,
            &browser,
            StatusCode::OK,
            "Confirm your email first",
            "We sent a new link to the address on your account. Open it, then sign in again.",
            Some(("/login", "Back to sign in")),
        ),
    }
}

/// Signs the browser in as `account_id` (a new session, replacing any it
/// had) and redirects to `to`.
pub async fn start_session(
    state: &State,
    browser: &Browser,
    account_id: Uuid,
    to: &str,
) -> PageResult {
    let (token, _) = state
        .sessions()
        .start(
            account_id,
            browser.session_token.as_deref(),
            &browser.client(),
        )
        .await?;
    let mut response = redirect(to);
    let jar = browser.jar();
    let headers = response.headers_mut();
    headers.append(
        header::SET_COOKIE,
        jar.set(
            jar.session_name(),
            &token,
            state.sessions().max_age().as_secs(),
        ),
    );
    headers.append(header::SET_COOKIE, jar.set(jar.csrf_name(), "", 0));
    Ok(response)
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

pub async fn logout(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    if let Some(token) = &browser.session_token {
        state.sessions().end(token).await?;
    }
    let mut response = redirect("/login");
    let jar = browser.jar();
    response
        .headers_mut()
        .append(header::SET_COOKIE, jar.set(jar.session_name(), "", 0));
    Ok(response)
}

pub async fn signup_form(AxumState(state): AxumState<State>, browser: Browser) -> PageResult {
    if browser.session.is_some() {
        return Ok(redirect("/"));
    }
    if !state.config.signup_enabled {
        return signup_closed(&state, &browser);
    }
    match crate::services::organisations::plan_home(&state).await? {
        Home::Closed => return signup_closed(&state, &browser),
        Home::Unclaimed => return no_owner(&state, &browser),
        Home::Personal(_) | Home::NewInstance(_) => {}
    }
    signup_page(
        &state,
        &browser,
        StatusCode::OK,
        &SignupForm::default(),
        &FieldErrors::default(),
        "",
    )
}

fn signup_closed(state: &State, browser: &Browser) -> PageResult {
    message(
        state,
        browser,
        StatusCode::FORBIDDEN,
        "Sign-up is closed",
        "This grund is invite-only. Ask its admin to invite your address, then open the link in the mail.",
        Some(("/login", "Sign in")),
    )
}

fn no_owner(state: &State, browser: &Browser) -> PageResult {
    message(
        state,
        browser,
        StatusCode::FORBIDDEN,
        "This grund has no owner yet",
        "Its first account is created with a one-time link made on the machine grund runs on. There, run: docker compose exec grund /grund setup-link",
        Some(("/login", "Sign in")),
    )
}

fn signup_page(
    _state: &State,
    browser: &Browser,
    status: StatusCode,
    form: &SignupForm,
    errors: &FieldErrors,
    error: &str,
) -> PageResult {
    let csrf = browser.csrf_token();
    render_typed(
        browser,
        status,
        crate::templates::compiled::pages::signup::render(&SignupPage {
            csrf: &csrf,
            username: &form.username,
            email: &form.email,
            errors,
            error,
        }),
    )
}

#[derive(Deserialize)]
pub struct SignupFields {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
}

pub async fn signup(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Form(fields): Form<SignupFields>,
) -> PageResult {
    if !browser.form_is_genuine(&fields.csrf) {
        return forged(&state, &browser);
    }
    let form = SignupForm {
        username: fields.username,
        email: fields.email,
        password: fields.password,
    };
    match state
        .accounts()
        .sign_up(form.clone(), &browser.meta())
        .await?
    {
        SignupOutcome::Sent { .. } => Ok(redirect("/signup/sent")),
        SignupOutcome::Invalid(errors) => signup_page(
            &state,
            &browser,
            StatusCode::UNPROCESSABLE_ENTITY,
            &form,
            &errors,
            "",
        ),
        SignupOutcome::Closed => signup_closed(&state, &browser),
        SignupOutcome::NoOwner => no_owner(&state, &browser),
        SignupOutcome::RateLimited => signup_page(
            &state,
            &browser,
            StatusCode::TOO_MANY_REQUESTS,
            &form,
            &FieldErrors::default(),
            "Too many requests from your network. Try again later.",
        ),
    }
}

/// `/signup/owner?token=`: the owner's setup link (grund-docs design/auth.md
/// §5). Opening it uses nothing.
pub async fn owner_form(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Query(query): Query<TokenQuery>,
) -> PageResult {
    if !state.accounts().setup_link_is_live(&query.token).await? {
        return owner_link_expired(&state, &browser);
    }
    owner_page(
        &state,
        &browser,
        StatusCode::OK,
        &query.token,
        &SignupForm::default(),
        &FieldErrors::default(),
    )
}

fn owner_page(
    _state: &State,
    browser: &Browser,
    status: StatusCode,
    token: &str,
    form: &SignupForm,
    errors: &FieldErrors,
) -> PageResult {
    let csrf = browser.csrf_token();
    let response = render_typed(
        browser,
        status,
        crate::templates::compiled::pages::signup_owner::render(&SignupOwnerPage {
            csrf: &csrf,
            token,
            username: &form.username,
            email: &form.email,
            errors,
        }),
    )?;
    Ok(with_referrer_same_origin(response))
}

fn owner_link_expired(state: &State, browser: &Browser) -> PageResult {
    message(
        state,
        browser,
        StatusCode::OK,
        "This setup link has expired",
        "A setup link works once, for an hour, and only while this grund has no account. If it has none yet, make a new link on its machine: docker compose exec grund /grund setup-link",
        Some(("/login", "Sign in")),
    )
}

#[derive(Deserialize)]
pub struct OwnerFields {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
}

pub async fn owner_signup(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Form(fields): Form<OwnerFields>,
) -> PageResult {
    if !browser.form_is_genuine(&fields.csrf) {
        return forged(&state, &browser);
    }
    let form = SignupForm {
        username: fields.username,
        email: fields.email,
        password: fields.password,
    };
    match state
        .accounts()
        .sign_up_owner(&fields.token, form.clone(), &browser.meta())
        .await?
    {
        OwnerSignupOutcome::SignedIn {
            account_id,
            organisation,
        } => start_session(&state, &browser, account_id, &format!("/{organisation}")).await,
        OwnerSignupOutcome::Invalid(errors) => owner_page(
            &state,
            &browser,
            StatusCode::UNPROCESSABLE_ENTITY,
            &fields.token,
            &form,
            &errors,
        ),
        OwnerSignupOutcome::Expired => owner_link_expired(&state, &browser),
    }
}

pub async fn signup_sent(AxumState(state): AxumState<State>, browser: Browser) -> PageResult {
    message(
        &state,
        &browser,
        StatusCode::OK,
        "Check your inbox",
        "We sent a link to the address you entered. Open it to confirm your email, then sign in. It works for 24 hours.",
        Some(("/login", "Sign in")),
    )
}

#[derive(Deserialize, Default)]
pub struct TokenQuery {
    #[serde(default)]
    token: String,
}

pub async fn verify_form(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Query(query): Query<TokenQuery>,
) -> PageResult {
    let valid =
        !query.token.is_empty() && state.accounts().verification_is_valid(&query.token).await?;
    let csrf = browser.csrf_token();
    let response = render_typed(
        &browser,
        StatusCode::OK,
        crate::templates::compiled::pages::verify::render(&VerifyPage {
            csrf: &csrf,
            token: &query.token,
            valid,
        }),
    )?;
    Ok(with_referrer_same_origin(response))
}

#[derive(Deserialize)]
pub struct TokenForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    password: String,
}

pub async fn verify(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Form(form): Form<TokenForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    if state
        .accounts()
        .verify_email(&form.token, &browser.meta())
        .await?
    {
        return login_page(
            &state,
            &browser,
            StatusCode::OK,
            "",
            None,
            Some("Your email is confirmed. Sign in to continue."),
            None,
        );
    }
    verify_page(&browser, StatusCode::GONE, "", false)
}

fn verify_page(browser: &Browser, status: StatusCode, token: &str, valid: bool) -> PageResult {
    let csrf = browser.csrf_token();
    render_typed(
        browser,
        status,
        crate::templates::compiled::pages::verify::render(&VerifyPage {
            csrf: &csrf,
            token,
            valid,
        }),
    )
}

pub async fn reset_form(AxumState(_state): AxumState<State>, browser: Browser) -> PageResult {
    reset_page(&browser, StatusCode::OK, "", "")
}

fn reset_page(browser: &Browser, status: StatusCode, email: &str, error: &str) -> PageResult {
    let csrf = browser.csrf_token();
    render_typed(
        browser,
        status,
        crate::templates::compiled::pages::reset::render(&ResetPage {
            csrf: &csrf,
            email,
            error,
        }),
    )
}

#[derive(Deserialize)]
pub struct ResetFields {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    email: String,
}

pub async fn reset(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Form(form): Form<ResetFields>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let (status, error) = match state
        .accounts()
        .request_reset(&form.email, &browser.meta())
        .await?
    {
        ResetRequestOutcome::Sent => return Ok(redirect("/reset/sent")),
        ResetRequestOutcome::Invalid(error) => (StatusCode::UNPROCESSABLE_ENTITY, error),
        ResetRequestOutcome::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests from your network. Try again later.".into(),
        ),
    };
    reset_page(&browser, status, &form.email, &error)
}

pub async fn reset_sent(AxumState(state): AxumState<State>, browser: Browser) -> PageResult {
    message(
        &state,
        &browser,
        StatusCode::OK,
        "Check your inbox",
        "If an account exists for that address, we sent it a link to choose a new password. It works for 30 minutes.",
        Some(("/login", "Back to sign in")),
    )
}

pub async fn reset_confirm_form(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Query(query): Query<TokenQuery>,
) -> PageResult {
    let valid = !query.token.is_empty() && state.accounts().reset_is_valid(&query.token).await?;
    let response = reset_confirmation(&browser, StatusCode::OK, &query.token, valid, "")?;
    Ok(with_referrer_same_origin(response))
}

fn reset_confirmation(
    browser: &Browser,
    status: StatusCode,
    token: &str,
    valid: bool,
    password_error: &str,
) -> PageResult {
    let csrf = browser.csrf_token();
    render_typed(
        browser,
        status,
        crate::templates::compiled::pages::reset_confirm::render(&ResetConfirmPage {
            csrf: &csrf,
            token,
            valid,
            error: "",
            password_error,
        }),
    )
}

pub async fn reset_confirm(
    AxumState(state): AxumState<State>,
    browser: Browser,
    Form(form): Form<TokenForm>,
) -> PageResult {
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    match state
        .accounts()
        .reset_password(&form.token, &form.password, &browser.meta())
        .await?
    {
        ResetOutcome::Done => {
            let mut response = login_page(
                &state,
                &browser,
                StatusCode::OK,
                "",
                None,
                Some("Your password is set. Sign in with it."),
                None,
            )?;
            let jar = browser.jar();
            response
                .headers_mut()
                .append(header::SET_COOKIE, jar.set(jar.session_name(), "", 0));
            Ok(response)
        }
        ResetOutcome::Expired => reset_confirmation(&browser, StatusCode::GONE, "", false, ""),
        ResetOutcome::Invalid(message) => reset_confirmation(
            &browser,
            StatusCode::UNPROCESSABLE_ENTITY,
            &form.token,
            true,
            &message,
        ),
    }
}

pub async fn sessions_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Query(query): Query<Notice>,
) -> PageResult {
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(redirect) => return Ok(*redirect),
    };
    let sessions: Vec<SessionRow> = state
        .sessions()
        .list(session.account_id)
        .await?
        .into_iter()
        .map(|s| SessionRow {
            id: s.session_id.to_string(),
            device: describe_user_agent(&s.user_agent),
            address: s.client_address,
            created: s.created_at.format("%-d %b %Y, %H:%M UTC").to_string(),
            last_seen: s.last_seen_at.format("%-d %b %Y, %H:%M UTC").to_string(),
            current: s.session_id == session.session_id,
        })
        .collect();
    let notice = match query.done.as_str() {
        "revoked" => "That device is signed out.",
        "others" => "Every other device is signed out.",
        _ => "",
    };
    signed_in_typed(
        &state,
        &browser,
        &session,
        None,
        StatusCode::OK,
        "Sessions",
        "settings",
        None,
        None,
        None,
        |_, csrf| {
            crate::templates::compiled::pages::sessions::render(&SessionsPage {
                csrf,
                sessions: &sessions,
                notice,
            })
        },
    )
    .await
}

pub async fn revoke_session(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Path(session_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(redirect) => return Ok(*redirect),
    };
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    let revoked = match Uuid::parse_str(&session_id) {
        Ok(id) => state.sessions().revoke(session.account_id, id).await?,
        Err(_) => false,
    };
    if !revoked {
        return not_found_page(&state, &browser);
    }
    Ok(redirect("/settings/sessions?done=revoked"))
}

pub async fn revoke_other_sessions(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Form(form): Form<CsrfForm>,
) -> PageResult {
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(redirect) => return Ok(*redirect),
    };
    if !browser.form_is_genuine(&form.csrf) {
        return forged(&state, &browser);
    }
    state
        .sessions()
        .revoke_others(session.account_id, session.session_id)
        .await?;
    Ok(redirect("/settings/sessions?done=others"))
}

/// A short, human name for a browser from its User-Agent.
pub fn describe_user_agent(user_agent: &str) -> String {
    if user_agent.starts_with("grund ") {
        return user_agent.chars().take(80).collect();
    }
    let browser = [
        ("Edg/", "Edge"),
        ("Firefox/", "Firefox"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
        ("curl/", "curl"),
    ]
    .into_iter()
    .find(|(needle, _)| user_agent.contains(needle))
    .map(|(_, name)| name);
    let system = [
        ("Android", "Android"),
        ("iPhone", "iOS"),
        ("iPad", "iPadOS"),
        ("Mac OS X", "macOS"),
        ("Windows", "Windows"),
        ("Linux", "Linux"),
    ]
    .into_iter()
    .find(|(needle, _)| user_agent.contains(needle))
    .map(|(_, name)| name);
    match (browser, system) {
        (Some(browser), Some(system)) => format!("{browser} on {system}"),
        (Some(browser), None) => browser.to_string(),
        (None, Some(system)) => format!("A browser on {system}"),
        (None, None) if user_agent.is_empty() => "Unknown device".to_string(),
        (None, None) => user_agent.chars().take(40).collect(),
    }
}

/// The 404 page: the same for "does not exist" and "not yours to see".
pub fn not_found_page(_state: &State, browser: &Browser) -> PageResult {
    render_typed(
        browser,
        StatusCode::NOT_FOUND,
        crate::templates::compiled::pages::error::render(&ErrorPage {
            title: "Not found",
            text: "There is nothing here, or it is not yours to see.",
            request_id: "",
        }),
    )
}

pub async fn not_found(AxumState(state): AxumState<State>, browser: Browser) -> PageResult {
    not_found_page(&state, &browser)
}

/// Renders the generic error page for a failed handler, logging the cause
/// with the request id. The page never shows the cause.
pub fn internal_error(_state: &State, request_id: Uuid, error: &anyhow::Error) -> Response {
    tracing::error!(%request_id, error = format!("{error:#}"), "request failed");
    let request_id = request_id.to_string();
    let html = crate::templates::compiled::pages::error::render(&ErrorPage {
        title: "Something went wrong",
        text: "grund could not finish that. Try again in a moment.",
        request_id: &request_id,
    });
    let mut response = (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::response::Html(html),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn licenses(AxumState(_state): AxumState<State>, browser: Browser) -> PageResult {
    render_typed(
        &browser,
        StatusCode::OK,
        crate::templates::compiled::pages::licenses::render(&LicensesPage {
            inter: crate::web::assets::INTER_LICENSE,
            mono: crate::web::assets::MONO_LICENSE,
        }),
    )
}

/// The swatches the style guide shows: token and role.
pub const SWATCHES: &[(&str, &str)] = &[
    ("bg", "page background"),
    ("bg-raised", "sidebar, inputs"),
    ("surface", "boxes of rows, cards, callouts, menus"),
    ("surface-hover", "hover on surfaces and nav items"),
    ("control", "boxed icon buttons"),
    (
        "active",
        "the selected nav item and view, marks, success banners",
    ),
    ("border", "dividers between rows"),
    ("border-strong", "tags, dashed boxes, menus"),
    ("border-control", "the edge of what you operate, 3:1"),
    ("text", "titles, names, body"),
    ("text-2", "secondary text"),
    ("muted", "counts, hints"),
    ("accent", "primary buttons, focus rings"),
    ("accent-hover", "primary buttons on hover"),
    ("accent-text", "links"),
    ("accent-ink", "text on the accent"),
    ("ok", "serving, success"),
    ("blue", "in progress"),
    ("orange", "updates, attention"),
    ("violet", "code, APIs, devices"),
    ("danger", "errors, destructive actions"),
    ("danger-surface", "behind errors and danger buttons"),
];

const KNOWN_IMAGE_ICONS: &[&str] = &[
    "nginx",
    "postgres",
    "redis",
    "nats",
    "clickhouse",
    "mongo",
    "node",
    "python",
    "prometheus",
    "rabbitmq",
];

/// The name of every icon in the sprite, in display order.
pub fn sprite_icons() -> Vec<&'static str> {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/templates/components/icons.html.sedge"
    ));
    source
        .split("<symbol id=\"i-")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .collect()
}

const DISCONNECTED_TAB: &str = "disconnected";
pub struct StyleGuidePage {
    pub viewer: TypedViewer,
    pub csrf: String,
    pub swatches: &'static [(&'static str, &'static str)],
    pub sprite_icons: Vec<&'static str>,
    pub gallery: &'static [&'static str],
    pub icons: Vec<&'static str>,
    pub apps: Vec<crate::web::apps::ListingView>,
    pub machines: Vec<crate::web::machines::MachineItem<'static>>,
}

fn style_guide_fixture(csrf: String) -> StyleGuidePage {
    let viewer = TypedViewer {
        username: "example".into(),
        initials: "EX".into(),
        email: String::new(),
        registered_on: String::new(),
        current: Some(TypedOrg {
            slug: "nord-studio".into(),
            role: "owner".into(),
            kind: "shared".into(),
            manages: true,
            owner: true,
            since: String::new(),
            current: true,
        }),
        orgs: vec![
            TypedOrg {
                slug: "nord-studio".into(),
                role: "owner".into(),
                kind: String::new(),
                manages: true,
                owner: true,
                since: String::new(),
                current: true,
            },
            TypedOrg {
                slug: "example".into(),
                role: "owner".into(),
                kind: String::new(),
                manages: true,
                owner: true,
                since: String::new(),
                current: false,
            },
        ],
        can_create: true,
    };
    let apps = [
        (
            "storefront",
            "nginx:1.27",
            Some("storefront-nord-studio.example.run"),
            None,
        ),
        ("db", "postgres:17", None, Some("db.grund.internal:5432")),
        ("cache", "redis:7", None, Some("cache.grund.internal:6379")),
        (
            "events",
            "clickhouse/clickhouse-server:24",
            None,
            Some("events.grund.internal:9000"),
        ),
        ("bus", "nats:2.10", None, Some("bus.grund.internal:4222")),
        ("worker", "acme/worker:3", None, None),
        (
            "api",
            "ghcr.io/nord/api:1.4.0",
            Some("api-nord-studio.example.run"),
            None,
        ),
    ]
    .into_iter()
    .map(
        |(name, image, address, internal)| crate::web::apps::ListingView {
            name: name.into(),
            tone: "muted",
            copies: 0,
            icon: crate::web::apps::image_icon(image),
            image: image.into(),
            address: address.map(str::to_owned),
            internal: internal.map(str::to_owned),
        },
    )
    .collect();
    let machines = [
        (
            "homelab-1",
            "Connected",
            "ok",
            "",
            false,
            vec!["zone=a"],
            "",
            16,
            "64 GB",
            Some("1.2 TB"),
        ),
        (
            "web-1",
            "Connected",
            "ok",
            "",
            true,
            vec![],
            "",
            4,
            "8 GB",
            Some("80 GB"),
        ),
        (
            "closet",
            "Disconnected",
            "orange",
            DISCONNECTED_TAB,
            false,
            vec!["zone=b", "gpu=yes"],
            "last seen 6 Oct 2026 22:14 UTC",
            8,
            "31 GB",
            None,
        ),
        (
            "spare",
            "Out of service",
            "muted",
            "",
            false,
            vec![],
            "2 copies",
            2,
            "3.8 GB",
            Some("120 GB"),
        ),
    ]
    .into_iter()
    .map(
        |(name, status, tone, tab, leased, labels, detail, vcpus, memory, disk)| {
            crate::web::machines::MachineItem {
                id: name.into(),
                name,
                labels: labels.into_iter().map(str::to_owned).collect(),
                status,
                tone,
                tab,
                search: name.into(),
                shown: true,
                detail: detail.into(),
                out_of_service: status == "Out of service",
                leased,
                facts: [
                    ("cpu", format!("{vcpus} vCPU")),
                    ("memory", format!("{memory} RAM")),
                    ("disk", disk.unwrap_or_default().into()),
                ],
                kvm: false,
                hosts_vms: false,
            }
        },
    )
    .collect();
    let mut icons = KNOWN_IMAGE_ICONS.to_vec();
    icons.push("docker");
    StyleGuidePage {
        viewer,
        csrf,
        swatches: SWATCHES,
        sprite_icons: sprite_icons(),
        gallery: KNOWN_IMAGE_ICONS,
        icons,
        apps,
        machines,
    }
}

pub async fn style_guide(AxumState(_state): AxumState<State>, browser: Browser) -> PageResult {
    let page = style_guide_fixture(browser.csrf_token());
    render_typed(
        &browser,
        StatusCode::OK,
        crate::templates::compiled::pages::style_guide::render(&page),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_same_origin_paths_are_returned_to() {
        assert_eq!(
            safe_return_to(Some("/settings/sessions")).as_deref(),
            Some("/settings/sessions")
        );
        for bad in [
            "//evil.example",
            "/\\evil.example",
            "https://evil.example",
            "settings",
            "/x\ny",
        ] {
            assert_eq!(safe_return_to(Some(bad)), None, "{bad:?}");
        }
    }

    #[test]
    fn user_agents_become_short_device_names() {
        let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
        assert_eq!(describe_user_agent(firefox), "Firefox on Linux");
        let chrome_mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36";
        assert_eq!(describe_user_agent(chrome_mac), "Chrome on macOS");
        assert_eq!(describe_user_agent(""), "Unknown device");
    }
}
