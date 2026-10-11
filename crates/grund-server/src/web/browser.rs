//! What a page handler knows about the browser asking: its request id, its
//! address, its cookies, its session and its CSRF token.

use std::{net::SocketAddr, time::Instant};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, HeaderValue, header, request::Parts},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;

use crate::{
    config::PublicOrigin,
    crypto,
    services::{
        accounts::RequestMeta,
        sessions::{Client, Session, SessionsState},
    },
    state::State,
};

/// The request id minted by [`crate::web::request_context`].
#[derive(Debug, Clone, Copy)]
pub struct RequestId(pub Uuid);

/// The instant HTTP request handling began, carried in request extensions.
#[derive(Debug, Clone, Copy)]
pub struct RequestStart(pub Instant);

/// The cookie names and attributes for this instance's origin. On https the
/// cookies are `__Host-` prefixed and `Secure`; on plain-http loopback
/// browsers would refuse both, so neither is used there.
#[derive(Debug, Clone)]
pub struct CookieJar {
    secure: bool,
}

impl CookieJar {
    pub fn for_origin(origin: &PublicOrigin) -> Self {
        Self {
            secure: origin.https,
        }
    }

    pub fn session_name(&self) -> &'static str {
        if self.secure {
            "__Host-grund_session"
        } else {
            "grund_session"
        }
    }

    pub fn csrf_name(&self) -> &'static str {
        if self.secure {
            "__Host-grund_csrf"
        } else {
            "grund_csrf"
        }
    }

    /// A `Set-Cookie` value. `max_age` of zero deletes the cookie.
    pub fn set(&self, name: &str, value: &str, max_age: u64) -> HeaderValue {
        let secure = if self.secure { "; Secure" } else { "" };
        HeaderValue::from_str(&format!(
            "{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"
        ))
        .expect("cookie values are base64url")
    }
}

/// The browser behind a request.
#[derive(Debug, Clone)]
pub struct Browser {
    pub request_id: Uuid,
    pub request_started: Instant,
    pub address: String,
    pub user_agent: String,
    pub session_token: Option<String>,
    pub session: Option<Session>,
    csrf_nonce: Option<String>,
    fresh_nonce: Option<String>,
    same_origin: bool,
    jar: CookieJar,
    csrf_key: [u8; 32],
    csrf_mask: [u8; 32],
}

impl Browser {
    /// The masked token every form on the page carries. The mask is fresh for
    /// each browser request and shared by all forms rendered in that response.
    pub fn csrf_token(&self) -> String {
        let digest = self.csrf_digest();
        let mut masked = [0u8; 64];
        masked[..32].copy_from_slice(&self.csrf_mask);
        for (byte, (mask, digest)) in masked[32..]
            .iter_mut()
            .zip(self.csrf_mask.iter().zip(digest.iter()))
        {
            *byte = mask ^ digest;
        }
        URL_SAFE_NO_PAD.encode(masked)
    }

    fn csrf_digest(&self) -> [u8; 32] {
        match &self.session {
            Some(session) => {
                crypto::hmac(&self.csrf_key, &[b"session", session.session_id.as_bytes()])
            }
            None => {
                let nonce = self
                    .csrf_nonce
                    .as_deref()
                    .or(self.fresh_nonce.as_deref())
                    .unwrap_or_default();
                crypto::hmac(&self.csrf_key, &[b"anonymous", nonce.as_bytes()])
            }
        }
    }

    /// Whether a submitted form came from this origin with a valid token.
    /// A fresh nonce (no cookie arrived) never validates.
    pub fn form_is_genuine(&self, submitted: &str) -> bool {
        if !self.same_origin || (self.session.is_none() && self.csrf_nonce.is_none()) {
            return false;
        }
        if submitted.len() != 86 {
            return false;
        }
        let mut masked = [0u8; 64];
        if URL_SAFE_NO_PAD.decode_slice(submitted, &mut masked).ok() != Some(64) {
            return false;
        }
        let digest = self.csrf_digest();
        let mut unmasked = [0u8; 32];
        for (byte, (mask, value)) in unmasked
            .iter_mut()
            .zip(masked[..32].iter().zip(masked[32..].iter()))
        {
            *byte = mask ^ value;
        }
        crypto::constant_time_eq(&unmasked, &digest)
    }

    /// Cookies this response must set: a CSRF nonce when the browser had none.
    pub fn cookies(&self) -> Vec<HeaderValue> {
        self.fresh_nonce
            .iter()
            .map(|nonce| self.jar.set(self.jar.csrf_name(), nonce, 24 * 3600))
            .collect()
    }

    pub fn jar(&self) -> &CookieJar {
        &self.jar
    }

    pub fn meta(&self) -> RequestMeta {
        RequestMeta {
            request_id: self.request_id,
            address: self.address.clone(),
        }
    }

    pub fn client(&self) -> Client {
        Client {
            user_agent: self.user_agent.clone(),
            address: self.address.clone(),
        }
    }
}

impl FromRequestParts<State> for Browser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &State) -> Result<Self, Self::Rejection> {
        let origin = state.config.public_origin();
        let jar = CookieJar::for_origin(&origin);
        let request_id = parts
            .extensions
            .get::<RequestId>()
            .map_or_else(Uuid::now_v7, |id| id.0);
        let request_started = parts
            .extensions
            .get::<RequestStart>()
            .map_or_else(Instant::now, |start| start.0);
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip().to_string());
        let address = client_address(
            &parts.headers,
            peer.as_deref(),
            state.config.trusted_proxy_hops,
        );
        let user_agent = header_str(&parts.headers, header::USER_AGENT)
            .chars()
            .take(256)
            .collect();
        let session_token = cookie(&parts.headers, jar.session_name()).filter(|t| t.len() == 43);
        let csrf_nonce = cookie(&parts.headers, jar.csrf_name()).filter(|t| t.len() == 43);

        let session = match &session_token {
            Some(token) => match state.sessions().authenticate(token).await {
                Ok(session) => session,
                Err(error) => {
                    tracing::warn!(error = %error, "session lookup failed; treating the request as signed out");
                    None
                }
            },
            None => None,
        };
        let fresh_nonce = (session.is_none() && csrf_nonce.is_none()).then(crypto::random_token);
        let mut csrf_mask = [0u8; 32];
        getrandom::fill(&mut csrf_mask).expect("the operating system provides randomness");

        Ok(Browser {
            request_id,
            request_started,
            address,
            user_agent,
            session_token,
            session,
            csrf_nonce,
            fresh_nonce,
            same_origin: same_origin(&parts.headers, &origin),
            jar,
            csrf_key: state.secret.derive("csrf"),
            csrf_mask,
        })
    }
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> &str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

/// A cookie's value from the request's `Cookie` headers.
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_string())
}

/// The client address: the connecting peer, or with `hops` trusted proxies,
/// the entry that many places from the right of `X-Forwarded-For`.
pub fn client_address(headers: &HeaderMap, peer: Option<&str>, hops: u8) -> String {
    if hops > 0 {
        let forwarded: Vec<&str> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .collect();
        if let Some(address) = forwarded
            .len()
            .checked_sub(hops as usize)
            .and_then(|i| forwarded.get(i))
        {
            return address.chars().take(64).collect();
        }
    }
    peer.unwrap_or_default().to_string()
}

/// Whether a request's own headers say it came from this origin. A browser
/// sends `Sec-Fetch-Site` and `Origin` on form posts; clients that send
/// neither are judged by their CSRF token alone.
pub fn same_origin(headers: &HeaderMap, origin: &PublicOrigin) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok())
        && !matches!(site, "same-origin" | "none")
    {
        return false;
    }
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        Some(sent) => sent == origin.serialized,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    #[test]
    fn without_trusted_proxies_the_forwarded_header_is_ignored() {
        let h = headers(&[("x-forwarded-for", "6.6.6.6")]);
        assert_eq!(client_address(&h, Some("10.0.0.1"), 0), "10.0.0.1");
    }

    #[test]
    fn with_one_proxy_the_entry_it_appended_is_the_client_and_spoofed_ones_are_ignored() {
        let h = headers(&[("x-forwarded-for", "6.6.6.6, 203.0.113.9")]);
        assert_eq!(client_address(&h, Some("10.0.0.1"), 1), "203.0.113.9");
        assert_eq!(client_address(&h, Some("10.0.0.1"), 2), "6.6.6.6");
        assert_eq!(client_address(&h, Some("10.0.0.1"), 3), "10.0.0.1");
    }

    #[test]
    fn a_cross_site_or_foreign_origin_post_is_not_same_origin() {
        let origin = PublicOrigin::parse("https://app.grund.sh").unwrap();
        assert!(same_origin(
            &headers(&[
                ("origin", "https://app.grund.sh"),
                ("sec-fetch-site", "same-origin")
            ]),
            &origin
        ));
        assert!(!same_origin(
            &headers(&[("origin", "https://evil.example")]),
            &origin
        ));
        assert!(!same_origin(
            &headers(&[("sec-fetch-site", "cross-site")]),
            &origin
        ));
        assert!(!same_origin(
            &headers(&[("sec-fetch-site", "same-site")]),
            &origin
        ));
        assert!(same_origin(&headers(&[]), &origin));
    }

    #[test]
    fn cookies_are_host_prefixed_and_secure_only_on_https() {
        let https = CookieJar::for_origin(&PublicOrigin::parse("https://app.grund.sh").unwrap());
        let value = https.set(https.session_name(), "x", 60);
        assert_eq!(
            value,
            "__Host-grund_session=x; Path=/; HttpOnly; SameSite=Lax; Max-Age=60; Secure"
        );
        let http = CookieJar::for_origin(&PublicOrigin::parse("http://localhost:8080").unwrap());
        assert_eq!(
            http.set(http.session_name(), "x", 60),
            "grund_session=x; Path=/; HttpOnly; SameSite=Lax; Max-Age=60"
        );
    }

    #[test]
    fn a_cookie_is_found_among_several() {
        let h = headers(&[("cookie", "a=1; grund_session=abc"), ("cookie", "b=2")]);
        assert_eq!(cookie(&h, "grund_session").as_deref(), Some("abc"));
        assert_eq!(cookie(&h, "missing"), None);
    }
    fn anonymous_browser() -> Browser {
        Browser {
            request_id: Uuid::now_v7(),
            request_started: Instant::now(),
            address: String::new(),
            user_agent: String::new(),
            session_token: None,
            session: None,
            csrf_nonce: Some(crypto::random_token()),
            fresh_nonce: None,
            same_origin: true,
            jar: CookieJar { secure: false },
            csrf_key: [9; 32],
            csrf_mask: [4; 32],
        }
    }

    #[test]
    fn masked_forms_are_stable_within_a_page_and_independent_between_requests() {
        let browser = anonymous_browser();
        let first = browser.csrf_token();
        assert_eq!(first, browser.csrf_token());
        assert!(browser.form_is_genuine(&first));
        let mut next_response = browser.clone();
        next_response.csrf_mask = [5; 32];
        let second = next_response.csrf_token();
        assert_ne!(first, second);
        assert!(browser.form_is_genuine(&second));
    }

    #[test]
    fn malformed_cross_site_and_unbound_tokens_cannot_submit_a_form() {
        let browser = anonymous_browser();
        let token = browser.csrf_token();
        for wrong in [
            String::new(),
            crypto::encode(&browser.csrf_digest()),
            format!("{token}x"),
            "x".repeat(86),
        ] {
            assert!(!browser.form_is_genuine(&wrong), "{wrong}");
        }
        let mut altered = token.into_bytes();
        altered[0] = if altered[0] == b'A' { b'B' } else { b'A' };
        assert!(!browser.form_is_genuine(std::str::from_utf8(&altered).unwrap()));
        let mut cross_site = browser.clone();
        cross_site.same_origin = false;
        assert!(!cross_site.form_is_genuine(&browser.csrf_token()));
        let mut without_cookie = browser.clone();
        without_cookie.csrf_nonce = None;
        without_cookie.fresh_nonce = Some(crypto::random_token());
        assert!(!without_cookie.form_is_genuine(&browser.csrf_token()));
        let mut different_cookie = browser.clone();
        different_cookie.csrf_nonce = Some(crypto::random_token());
        assert!(!different_cookie.form_is_genuine(&browser.csrf_token()));
    }

    #[test]
    fn a_session_rotates_the_csrf_binding_without_accepting_the_old_token() {
        let mut browser = anonymous_browser();
        browser.session = Some(Session {
            session_id: Uuid::now_v7(),
            account_id: Uuid::now_v7(),
        });
        let token = browser.csrf_token();
        assert!(browser.form_is_genuine(&token));
        browser.session.as_mut().unwrap().session_id = Uuid::now_v7();
        assert!(!browser.form_is_genuine(&token));
        assert!(browser.form_is_genuine(&browser.csrf_token()));
    }
}
