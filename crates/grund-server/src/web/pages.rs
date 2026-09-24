//! The server-rendered pages: sign-up, verification, sign-in, sign-out,
//! password reset, the signed-in home and the sessions page.

use axum::{
    Form,
    extract::{Path, Query, State as AxumState},
    http::{HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use minijinja::{Value, context};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    services::{
        accounts::{
            AccountsState, FieldErrors, LoginOutcome, ResetOutcome, ResetRequestOutcome,
            SignupForm, SignupOutcome,
        },
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

type PageResult = Result<Response, PageError>;

pub fn render(
    state: &State,
    browser: &Browser,
    status: StatusCode,
    template: &str,
    ctx: Value,
) -> PageResult {
    let html = state.templates.render(template, ctx)?;
    let mut response = (status, axum::response::Html(html)).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for cookie in browser.cookies() {
        headers.append(header::SET_COOKIE, cookie);
    }
    Ok(response)
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

fn with_referrer_off(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

pub fn message(
    state: &State,
    browser: &Browser,
    status: StatusCode,
    title: &str,
    text: &str,
    link: Option<(&str, &str)>,
) -> PageResult {
    let (link_href, link_text) = link.unwrap_or_default();
    render(
        state,
        browser,
        status,
        "pages/message.html.jinja",
        context! { title, text, link_href, link_text },
    )
}

pub fn forged(state: &State, browser: &Browser) -> PageResult {
    message(
        state,
        browser,
        StatusCode::FORBIDDEN,
        "This form has expired",
        "For your safety grund only accepts forms it just showed you. Go back, reload the page and try again.",
        Some(("/", "Go to grund")),
    )
}

/// A path to return to after sign-in: same-origin paths only.
/// The social providers the sign-in page offers: none unless the license
/// includes social sign-in.
pub fn offered_providers(state: &State) -> Vec<Value> {
    if state
        .entitlements
        .allows(crate::license::Feature::SocialLogin)
        .is_err()
    {
        return Vec::new();
    }
    state
        .social
        .iter()
        .map(|p| context! { id => p.id, name => p.name, icon => p.icon })
        .collect()
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

fn require_session(browser: &Browser, uri: &Uri) -> Result<Session, Box<Response>> {
    browser.session.clone().ok_or_else(|| {
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        let query = serde_urlencoded::to_string([("return_to", path)]).unwrap_or_default();
        Box::new(redirect(&format!("/login?{query}")))
    })
}

pub async fn home(AxumState(state): AxumState<State>, browser: Browser, uri: Uri) -> PageResult {
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(redirect) => return Ok(*redirect),
    };
    let viewer = viewer_context(&state, &session).await?;
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/home.html.jinja",
        context! {
            viewer, csrf => browser.csrf_token(), section => "overview",
        },
    )
}

async fn viewer_context(state: &State, session: &Session) -> Result<Value, PageError> {
    let viewer = state
        .accounts()
        .viewer(session.account_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("session names an account that does not exist"))?;
    let organisation = viewer
        .memberships
        .first()
        .map(|m| m.slug.clone())
        .unwrap_or_else(|| viewer.username.clone());
    let initials: String = viewer
        .username
        .split('-')
        .filter_map(|part| part.chars().next())
        .take(2)
        .collect();
    let memberships: Vec<Value> = viewer
        .memberships
        .iter()
        .map(|m| context! { slug => m.slug, role => m.role })
        .collect();
    Ok(context! {
        username => viewer.username,
        email => viewer.email,
        initials,
        organisation,
        memberships,
        registered_on => viewer.registered_at.format("%-d %B %Y").to_string(),
    })
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
    render(
        state,
        browser,
        status,
        "pages/login.html.jinja",
        context! {
            csrf => browser.csrf_token(),
            login,
            error => error.unwrap_or_default(),
            notice => notice.unwrap_or_default(),
            return_to => return_to.unwrap_or_default(),
            providers => offered_providers(state),
            signup_enabled => state.config.signup_enabled,
        },
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
            let (token, _) = state
                .sessions()
                .start(
                    account_id,
                    browser.session_token.as_deref(),
                    &browser.client(),
                )
                .await?;
            let mut response = redirect(return_to.as_deref().unwrap_or("/"));
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
        "This grund instance does not take new accounts. Ask whoever runs it for one.",
        Some(("/login", "Sign in")),
    )
}

fn signup_page(
    state: &State,
    browser: &Browser,
    status: StatusCode,
    form: &SignupForm,
    errors: &FieldErrors,
    error: &str,
) -> PageResult {
    render(
        state,
        browser,
        status,
        "pages/signup.html.jinja",
        context! {
            csrf => browser.csrf_token(),
            username => form.username,
            email => form.email,
            errors => Value::from_serialize(errors),
            error,
        },
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
    let response = render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/verify.html.jinja",
        context! {
            csrf => browser.csrf_token(), token => query.token, valid,
        },
    )?;
    Ok(with_referrer_off(response))
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
    render(
        &state,
        &browser,
        StatusCode::GONE,
        "pages/verify.html.jinja",
        context! {
            csrf => browser.csrf_token(), token => "", valid => false,
        },
    )
}

pub async fn reset_form(AxumState(state): AxumState<State>, browser: Browser) -> PageResult {
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/reset.html.jinja",
        context! {
            csrf => browser.csrf_token(), email => "", error => "",
        },
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
    render(
        &state,
        &browser,
        status,
        "pages/reset.html.jinja",
        context! {
            csrf => browser.csrf_token(), email => form.email, error,
        },
    )
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
    let response = render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/reset-confirm.html.jinja",
        context! {
            csrf => browser.csrf_token(), token => query.token, valid, error => "", password_error => "",
        },
    )?;
    Ok(with_referrer_off(response))
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
        ResetOutcome::Expired => render(
            &state,
            &browser,
            StatusCode::GONE,
            "pages/reset-confirm.html.jinja",
            context! {
                csrf => browser.csrf_token(), token => "", valid => false, error => "", password_error => "",
            },
        ),
        ResetOutcome::Invalid(message) => render(
            &state,
            &browser,
            StatusCode::UNPROCESSABLE_ENTITY,
            "pages/reset-confirm.html.jinja",
            context! { csrf => browser.csrf_token(), token => form.token, valid => true, error => "", password_error => message },
        ),
    }
}

#[derive(Deserialize, Default)]
pub struct NoticeQuery {
    #[serde(default)]
    done: String,
}

pub async fn sessions_page(
    AxumState(state): AxumState<State>,
    browser: Browser,
    uri: Uri,
    Query(query): Query<NoticeQuery>,
) -> PageResult {
    let session = match require_session(&browser, &uri) {
        Ok(session) => session,
        Err(redirect) => return Ok(*redirect),
    };
    let viewer = viewer_context(&state, &session).await?;
    let sessions: Vec<Value> = state
        .sessions()
        .list(session.account_id)
        .await?
        .into_iter()
        .map(|s| {
            context! {
                id => s.session_id.to_string(),
                device => describe_user_agent(&s.user_agent),
                address => s.client_address,
                created => s.created_at.format("%-d %b %Y, %H:%M UTC").to_string(),
                last_seen => s.last_seen_at.format("%-d %b %Y, %H:%M UTC").to_string(),
                current => s.session_id == session.session_id,
            }
        })
        .collect();
    let notice = match query.done.as_str() {
        "revoked" => "That device is signed out.",
        "others" => "Every other device is signed out.",
        _ => "",
    };
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/sessions.html.jinja",
        context! {
            viewer, sessions, notice, csrf => browser.csrf_token(), section => "settings",
        },
    )
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

fn not_found_page(state: &State, browser: &Browser) -> PageResult {
    render(
        state,
        browser,
        StatusCode::NOT_FOUND,
        "pages/error.html.jinja",
        context! {
            title => "Not found", text => "There is nothing here, or it is not yours to see.", request_id => "",
        },
    )
}

pub async fn not_found(AxumState(state): AxumState<State>, browser: Browser) -> PageResult {
    not_found_page(&state, &browser)
}

/// Renders the generic error page for a failed handler, logging the cause
/// with the request id. The page never shows the cause.
pub fn internal_error(state: &State, request_id: Uuid, error: &anyhow::Error) -> Response {
    tracing::error!(%request_id, error = format!("{error:#}"), "request failed");
    let html = state
        .templates
        .render(
            "pages/error.html.jinja",
            context! {
                title => "Something went wrong",
                text => "grund could not finish that. Try again in a moment.",
                request_id => request_id.to_string(),
            },
        )
        .unwrap_or_else(|_| "Something went wrong.".to_string());
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

pub async fn licenses(AxumState(state): AxumState<State>, browser: Browser) -> PageResult {
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/licenses.html.jinja",
        context! {
            inter => crate::web::assets::INTER_LICENSE,
            mono => crate::web::assets::MONO_LICENSE,
        },
    )
}

/// The swatches the style guide shows: token and role.
pub const SWATCHES: &[(&str, &str)] = &[
    ("bg", "page background"),
    ("bg-raised", "sidebar, inputs"),
    ("surface", "cards, callouts"),
    ("active", "selected nav item"),
    ("border", "dividers (strong shown)"),
    ("text", "primary text"),
    ("text-2", "secondary text"),
    ("muted", "counts, hints"),
    ("accent", "primary buttons, brand"),
    ("ok", "serving, success"),
    ("blue", "in progress"),
    ("orange", "updates, attention"),
    ("violet", "code, APIs"),
    ("danger", "errors, sign-out"),
];

pub async fn style_guide(AxumState(state): AxumState<State>, browser: Browser) -> PageResult {
    let viewer = context! {
        username => "example", initials => "EX", organisation => "nord-studio", email => "",
        memberships => Vec::<Value>::new(), registered_on => "",
    };
    render(
        &state,
        &browser,
        StatusCode::OK,
        "pages/style-guide.html.jinja",
        context! {
            viewer, csrf => browser.csrf_token(), section => "", swatches => SWATCHES,
        },
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
