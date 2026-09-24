//! What a page handler knows about the browser asking: its request id, its
//! address, its cookies, its session and its CSRF token.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, HeaderValue, header, request::Parts},
};
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
    pub address: String,
    pub user_agent: String,
    pub session_token: Option<String>,
    pub session: Option<Session>,
    csrf_nonce: Option<String>,
    fresh_nonce: Option<String>,
    same_origin: bool,
    jar: CookieJar,
    csrf_key: [u8; 32],
}

impl Browser {
    /// The token every form on the page must carry: bound to the session when
    /// there is one, else to this browser's CSRF cookie.
    pub fn csrf_token(&self) -> String {
        match &self.session {
            Some(session) => crypto::encode(&crypto::hmac(
                &self.csrf_key,
                &[b"session", session.session_id.as_bytes()],
            )),
            None => {
                let nonce = self
                    .csrf_nonce
                    .as_deref()
                    .or(self.fresh_nonce.as_deref())
                    .unwrap_or_default();
                crypto::encode(&crypto::hmac(
                    &self.csrf_key,
                    &[b"anonymous", nonce.as_bytes()],
                ))
            }
        }
    }

    /// Whether a submitted form may act: it came from this origin and carries
    /// the right token. A fresh nonce (no cookie arrived) never validates.
    pub fn form_is_genuine(&self, submitted: &str) -> bool {
        if !self.same_origin {
            return false;
        }
        if self.session.is_none() && self.csrf_nonce.is_none() {
            return false;
        }
        crypto::constant_time_eq(self.csrf_token().as_bytes(), submitted.as_bytes())
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

        Ok(Browser {
            request_id,
            address,
            user_agent,
            session_token,
            session,
            csrf_nonce,
            fresh_nonce,
            same_origin: same_origin(&parts.headers, &origin),
            jar,
            csrf_key: state.secret.derive("csrf"),
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
}
