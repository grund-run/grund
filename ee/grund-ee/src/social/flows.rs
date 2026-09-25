//! Social sign-in: GitHub, Google and any OpenID
//! Connect provider, behind [`grund_server::services::entitlements::Entitlements`].
//!
//! Every flow carries `state` (bound to a `__Host-` cookie), a PKCE S256
//! verifier and, for OIDC, a `nonce`, and is single-use for ten minutes. An
//! identity links to an existing account only after the person proves they
//! own it; an address match alone never links.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use grund_domain::{
    account::{AccountCommand, RegistrationMethod},
    names::{EmailAddress, Username},
    organisation::OrganisationCommand,
};
use grund_store::{
    accounts::{self, Lookup},
    social,
    work::{Work, WorkError},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use std::sync::Arc;

use grund_server::{
    config::{PublicOrigin, SocialArgs},
    crypto,
    services::{
        accounts::RequestMeta,
        insights,
        limits::{Limits, LimitsState},
        outbox::wake as outbox_wake,
        passwords::{Passwords, PasswordsState},
    },
    state::State,
};

/// How long a flow lives, from the redirect to the last step.
pub const FLOW_TTL: Duration = Duration::from_secs(600);

/// Which provider protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    /// GitHub's OAuth apps: the profile and verified addresses come from its API.
    GitHub,
    /// OpenID Connect: the ID token from the token endpoint carries the identity.
    Oidc { issuer: String },
}

/// A configured provider.
#[derive(Debug, Clone)]
pub struct Provider {
    pub id: &'static str,
    pub name: String,
    pub icon: &'static str,
    pub protocol: Protocol,
    pub client_id: String,
    pub client_secret: String,
}

/// The providers the configuration names, in the order they are offered.
pub fn providers(social: &SocialArgs) -> Vec<Provider> {
    let mut providers = Vec::new();
    if let (Some(id), Some(secret)) = (&social.github_client_id, &social.github_client_secret) {
        providers.push(Provider {
            id: "github",
            name: "GitHub".into(),
            icon: "github",
            protocol: Protocol::GitHub,
            client_id: id.clone(),
            client_secret: secret.clone(),
        });
    }
    if let (Some(id), Some(secret)) = (&social.google_client_id, &social.google_client_secret) {
        providers.push(Provider {
            id: "google",
            name: "Google".into(),
            icon: "globe",
            protocol: Protocol::Oidc {
                issuer: "https://accounts.google.com".into(),
            },
            client_id: id.clone(),
            client_secret: secret.clone(),
        });
    }
    if let (Some(issuer), Some(id), Some(secret)) = (
        &social.oidc_issuer,
        &social.oidc_client_id,
        &social.oidc_client_secret,
    ) {
        providers.push(Provider {
            id: "oidc",
            name: social.oidc_name.clone(),
            icon: "key",
            protocol: Protocol::Oidc {
                issuer: issuer.clone(),
            },
            client_id: id.clone(),
            client_secret: secret.clone(),
        });
    }
    providers
}

/// Who a provider says the person is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    pub email: String,
    pub email_verified: bool,
    pub suggested_name: Option<String>,
}

/// What to do with an identity after the callback: the linking rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// The identity is linked to this account already.
    SignIn(Uuid),
    /// The provider has not verified the address: create and link nothing.
    Refuse,
    /// No account has the address: offer a new account.
    ChooseUsername,
    /// This account has the address: link only after its password.
    ProveOwnership(Uuid),
}

/// The linking rule, as a pure function of what the store knows.
pub fn decide(
    linked_account: Option<Uuid>,
    email_verified: bool,
    account_with_email: Option<Uuid>,
) -> Next {
    match (linked_account, email_verified, account_with_email) {
        (Some(account), _, _) => Next::SignIn(account),
        (None, false, _) => Next::Refuse,
        (None, true, None) => Next::ChooseUsername,
        (None, true, Some(account)) => Next::ProveOwnership(account),
    }
}

/// The PKCE S256 challenge for a verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// The claims of an ID token that matter here.
#[derive(Debug, Deserialize)]
pub struct IdClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Audience,
    pub exp: i64,
    pub nonce: Option<String>,
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Verified,
    pub preferred_username: Option<String>,
    pub name: Option<String>,
}

/// `aud` is a string or a list of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

/// `email_verified` is a boolean, or (some providers) the string "true".
#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
pub enum Verified {
    Bool(bool),
    Text(String),
    #[default]
    Missing,
}

/// Why an ID token was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdTokenError {
    #[error("the ID token is malformed")]
    Malformed,
    #[error("the ID token is from another issuer")]
    Issuer,
    #[error("the ID token is for another client")]
    Audience,
    #[error("the ID token has expired")]
    Expired,
    #[error("the ID token does not carry this flow's nonce")]
    Nonce,
}

/// Reads and checks an ID token received directly from the token endpoint
/// over TLS. Its signature is not checked: OIDC Core §3.1.3.7 lets TLS
/// validation of the token endpoint stand in for it on this path. `iss`,
/// `aud`, `exp` and `nonce` are checked.
pub fn read_id_token(
    token: &str,
    issuer: &str,
    client_id: &str,
    nonce: &str,
    now: i64,
) -> Result<Identity, IdTokenError> {
    let payload = token.split('.').nth(1).ok_or(IdTokenError::Malformed)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| IdTokenError::Malformed)?;
    let claims: IdClaims = serde_json::from_slice(&bytes).map_err(|_| IdTokenError::Malformed)?;
    if claims.iss != issuer {
        return Err(IdTokenError::Issuer);
    }
    let audience_ok = match &claims.aud {
        Audience::One(aud) => aud == client_id,
        Audience::Many(auds) => auds.iter().any(|aud| aud == client_id),
    };
    if !audience_ok {
        return Err(IdTokenError::Audience);
    }
    if claims.exp <= now {
        return Err(IdTokenError::Expired);
    }
    let nonce_ok = claims
        .nonce
        .as_deref()
        .is_some_and(|sent| crypto::constant_time_eq(sent.as_bytes(), nonce.as_bytes()));
    if !nonce_ok {
        return Err(IdTokenError::Nonce);
    }
    let email_verified = match claims.email_verified {
        Verified::Bool(value) => value,
        Verified::Text(value) => value == "true",
        Verified::Missing => false,
    };
    Ok(Identity {
        subject: claims.sub,
        email: claims.email.unwrap_or_default(),
        email_verified,
        suggested_name: claims.preferred_username.or(claims.name),
    })
}

/// How a callback ended.
#[derive(Debug)]
pub enum CallbackOutcome {
    SignIn(Uuid),
    ChooseUsername,
    Link { email: String },
    Refused(&'static str),
}

/// How the choose-a-username step ended.
#[derive(Debug)]
pub enum CompleteOutcome {
    SignIn(Uuid),
    Invalid(String),
    Expired,
}

/// How the prove-ownership step ended.
#[derive(Debug)]
pub enum LinkOutcome {
    SignIn(Uuid),
    WrongPassword,
    Locked,
    Expired,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// Social sign-in flows.
#[derive(Clone)]
pub struct Social {
    state: State,
    passwords: Passwords,
    limits: Limits,
    http: reqwest::Client,
    providers: Arc<[Provider]>,
}

impl Social {
    /// The flows for `state`, over these providers and this client.
    pub fn new(state: &State, providers: Arc<[Provider]>, http: reqwest::Client) -> Self {
        Self {
            state: state.clone(),
            passwords: state.passwords(),
            limits: state.limits(),
            http,
            providers,
        }
    }

    fn origin(&self) -> PublicOrigin {
        self.state.config.public_origin()
    }

    /// The configured provider with this id.
    pub fn provider(&self, id: &str) -> Option<Provider> {
        self.providers.iter().find(|p| p.id == id).cloned()
    }

    fn redirect_uri(&self, provider: &Provider) -> String {
        format!("{}/auth/{}/callback", self.origin().serialized, provider.id)
    }

    async fn discover(&self, issuer: &str) -> anyhow::Result<Discovery> {
        let discovery: Discovery = self
            .http
            .get(format!("{issuer}/.well-known/openid-configuration"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        anyhow::ensure!(
            discovery.issuer == issuer,
            "the provider's discovery names another issuer"
        );
        Ok(discovery)
    }

    /// Starts a flow: returns the cookie token and where to send the browser.
    pub async fn start(&self, provider: &Provider) -> anyhow::Result<(String, String)> {
        let cookie = crypto::random_token();
        let state = crypto::random_token();
        let verifier = crypto::random_token();
        let nonce = crypto::random_token();
        social::start(
            &self.state.pool,
            &crypto::digest(&cookie),
            provider.id,
            &state,
            &verifier,
            &nonce,
            FLOW_TTL,
        )
        .await?;
        let (endpoint, scope) = match &provider.protocol {
            Protocol::GitHub => (
                "https://github.com/login/oauth/authorize".to_string(),
                "read:user user:email",
            ),
            Protocol::Oidc { issuer } => (
                self.discover(issuer).await?.authorization_endpoint,
                "openid email profile",
            ),
        };
        let query = serde_urlencoded::to_string([
            ("response_type", "code"),
            ("client_id", provider.client_id.as_str()),
            ("redirect_uri", self.redirect_uri(provider).as_str()),
            ("scope", scope),
            ("state", state.as_str()),
            ("nonce", nonce.as_str()),
            ("code_challenge", pkce_challenge(&verifier).as_str()),
            ("code_challenge_method", "S256"),
        ])?;
        let separator = if endpoint.contains('?') { '&' } else { '?' };
        Ok((cookie, format!("{endpoint}{separator}{query}")))
    }

    /// Handles the provider's callback: checks the flow, exchanges the code and
    /// applies the linking rule.
    pub async fn callback(
        &self,
        provider: &Provider,
        cookie: &str,
        state: &str,
        code: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<CallbackOutcome> {
        let digest = crypto::digest(cookie);
        let Some(flow) = social::take_authorizing(&self.state.pool, &digest, provider.id).await?
        else {
            return Ok(CallbackOutcome::Refused(
                "This sign-in has expired. Start again.",
            ));
        };
        if !crypto::constant_time_eq(flow.state.as_bytes(), state.as_bytes()) {
            return Ok(CallbackOutcome::Refused(
                "This sign-in did not start here. Start again.",
            ));
        }
        let identity = match self
            .exchange(provider, code, &flow.pkce_verifier, &flow.nonce)
            .await
        {
            Ok(identity) => identity,
            Err(error) => {
                tracing::warn!(provider = provider.id, error = %error, "social sign-in exchange failed");
                return Ok(CallbackOutcome::Refused(
                    "The provider did not confirm who you are. Try again.",
                ));
            }
        };
        let linked =
            accounts::identity_account(&self.state.pool, provider.id, &identity.subject).await?;
        let email = EmailAddress::parse(&identity.email).ok();
        let with_email = match &email {
            Some(email) => {
                accounts::login_record(&self.state.pool, Lookup::Email(email.normalized()))
                    .await?
                    .map(|r| r.account_id)
            }
            None => None,
        };
        let verified = identity.email_verified && email.is_some();
        match decide(linked, verified, with_email) {
            Next::SignIn(account_id) => {
                tracing::info!(%account_id, provider = provider.id, request_id = %meta.request_id, "social sign-in");
                Ok(CallbackOutcome::SignIn(account_id))
            }
            Next::Refuse => Ok(CallbackOutcome::Refused(
                "Your provider has not verified your email address. Verify it there, then try again.",
            )),
            Next::ChooseUsername => {
                let suggestion = identity
                    .suggested_name
                    .as_deref()
                    .and_then(Username::suggest)
                    .or_else(|| {
                        email
                            .as_ref()
                            .and_then(|e| Username::suggest(e.local_part()))
                    });
                social::park(
                    &self.state.pool,
                    &digest,
                    "choose_username",
                    &identity.subject,
                    &identity.email,
                    suggestion.as_ref().map(Username::as_str),
                    None,
                )
                .await?;
                Ok(CallbackOutcome::ChooseUsername)
            }
            Next::ProveOwnership(account_id) => {
                social::park(
                    &self.state.pool,
                    &digest,
                    "link",
                    &identity.subject,
                    &identity.email,
                    None,
                    Some(account_id),
                )
                .await?;
                Ok(CallbackOutcome::Link {
                    email: identity.email,
                })
            }
        }
    }

    async fn exchange(
        &self,
        provider: &Provider,
        code: &str,
        verifier: &str,
        nonce: &str,
    ) -> anyhow::Result<Identity> {
        match &provider.protocol {
            Protocol::GitHub => {
                let token: TokenResponse = self
                    .http
                    .post("https://github.com/login/oauth/access_token")
                    .header(reqwest::header::ACCEPT, "application/json")
                    .form(&[
                        ("client_id", provider.client_id.as_str()),
                        ("client_secret", provider.client_secret.as_str()),
                        ("code", code),
                        ("redirect_uri", self.redirect_uri(provider).as_str()),
                        ("code_verifier", verifier),
                    ])
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                let access = token
                    .access_token
                    .ok_or_else(|| anyhow::anyhow!("GitHub returned no access token"))?;
                let user: GitHubUser = self.github(&access, "https://api.github.com/user").await?;
                let emails: Vec<GitHubEmail> = self
                    .github(&access, "https://api.github.com/user/emails")
                    .await?;
                let primary = emails.into_iter().find(|e| e.primary);
                Ok(Identity {
                    subject: user.id.to_string(),
                    email_verified: primary.as_ref().is_some_and(|e| e.verified),
                    email: primary.map(|e| e.email).unwrap_or_default(),
                    suggested_name: Some(user.login),
                })
            }
            Protocol::Oidc { issuer } => {
                let discovery = self.discover(issuer).await?;
                let token: TokenResponse = self
                    .http
                    .post(&discovery.token_endpoint)
                    .form(&[
                        ("grant_type", "authorization_code"),
                        ("code", code),
                        ("redirect_uri", self.redirect_uri(provider).as_str()),
                        ("client_id", provider.client_id.as_str()),
                        ("client_secret", provider.client_secret.as_str()),
                        ("code_verifier", verifier),
                    ])
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                let id_token = token
                    .id_token
                    .ok_or_else(|| anyhow::anyhow!("the provider returned no ID token"))?;
                Ok(read_id_token(
                    &id_token,
                    issuer,
                    &provider.client_id,
                    nonce,
                    Utc::now().timestamp(),
                )?)
            }
        }
    }

    async fn github<T: serde::de::DeserializeOwned>(
        &self,
        access: &str,
        url: &str,
    ) -> anyhow::Result<T> {
        Ok(self
            .http
            .get(url)
            .bearer_auth(access)
            .header(reqwest::header::USER_AGENT, "grund")
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    /// The identity waiting at `stage` for this cookie, if any.
    pub async fn pending(
        &self,
        cookie: &str,
        stage: &str,
    ) -> anyhow::Result<Option<social::Pending>> {
        Ok(social::pending(&self.state.pool, &crypto::digest(cookie), stage).await?)
    }

    /// Creates an account for a verified identity that has none: no password,
    /// the address verified, the identity linked.
    pub async fn complete_signup(
        &self,
        cookie: &str,
        username: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<CompleteOutcome> {
        let digest = crypto::digest(cookie);
        let username = match Username::parse(username) {
            Ok(username) => username,
            Err(error) => return Ok(CompleteOutcome::Invalid(format!("{error}."))),
        };
        if accounts::username_taken(&self.state.pool, username.as_str()).await? {
            return Ok(CompleteOutcome::Invalid("That username is taken.".into()));
        }
        let Some(pending) = social::finish(&self.state.pool, &digest, "choose_username").await?
        else {
            return Ok(CompleteOutcome::Expired);
        };
        let Ok(email) = EmailAddress::parse(&pending.email) else {
            return Ok(CompleteOutcome::Expired);
        };
        let account_id = Uuid::now_v7();
        match self
            .create(account_id, &username, &email, &pending, meta)
            .await
        {
            Ok(()) => Ok(CompleteOutcome::SignIn(account_id)),
            Err(error) if error.unique_violation().is_some() => Ok(CompleteOutcome::Invalid(
                "That username or identity is already in use. Start again.".into(),
            )),
            Err(error) => Err(error.into()),
        }
    }

    async fn create(
        &self,
        account_id: Uuid,
        username: &Username,
        email: &EmailAddress,
        pending: &social::Pending,
        meta: &RequestMeta,
    ) -> Result<(), WorkError> {
        let organisation_id = Uuid::now_v7();
        let identity_id = Uuid::now_v7();
        let now = Utc::now();
        let mut work = Work::begin(&self.state.events, meta.request_id, "social-signup").await?;
        work.account(
            account_id,
            AccountCommand::Register {
                username: username.clone(),
                organisation_id,
                method: RegistrationMethod::Social {
                    provider: pending.provider.clone(),
                },
                at: now,
            },
        )
        .await?;
        work.account(
            account_id,
            AccountCommand::VerifyEmail {
                email_digest: crypto::email_digest(email.normalized()),
                at: now,
            },
        )
        .await?;
        work.account(
            account_id,
            AccountCommand::LinkIdentity {
                provider: pending.provider.clone(),
                identity_id,
                at: now,
            },
        )
        .await?;
        work.organisation(
            organisation_id,
            OrganisationCommand::CreatePersonal {
                slug: username.clone(),
                owner: account_id,
                at: now,
            },
        )
        .await?;
        accounts::insert_email(work.sql(), account_id, email.as_str(), email.normalized()).await?;
        accounts::insert_identity(
            work.sql(),
            identity_id,
            &pending.provider,
            &pending.subject,
            account_id,
        )
        .await?;
        insights::queue_account(&self.state, work.sql(), account_id, &pending.provider).await?;
        work.commit().await?;
        tracing::info!(%account_id, provider = %pending.provider, "account created by social sign-in");
        if self.state.config.insights.enabled() {
            outbox_wake(&self.state).await;
        }
        Ok(())
    }

    /// Links a verified identity to the account with its address, once the
    /// person has given that account's password. Throttled like sign-in.
    pub async fn link(
        &self,
        cookie: &str,
        password: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<LinkOutcome> {
        let digest = crypto::digest(cookie);
        let Some(pending) = social::pending(&self.state.pool, &digest, "link").await? else {
            return Ok(LinkOutcome::Expired);
        };
        let Some(account_id) = pending.account_id else {
            return Ok(LinkOutcome::Expired);
        };
        let name = pending.email.to_lowercase();
        if self.limits.login_locked(&name).await? {
            return Ok(LinkOutcome::Locked);
        }
        let record = accounts::login_record_by_id(&self.state.pool, account_id).await?;
        let verified = self
            .passwords
            .verify(password, record.as_ref().and_then(|r| r.phc.as_deref()))
            .await?;
        if !verified.matches {
            self.limits.login_failed(&name).await?;
            return Ok(LinkOutcome::WrongPassword);
        }
        let Some(pending) = social::finish(&self.state.pool, &digest, "link").await? else {
            return Ok(LinkOutcome::Expired);
        };
        let identity_id = Uuid::now_v7();
        let mut work = Work::begin(&self.state.events, meta.request_id, "social-link").await?;
        work.account(
            account_id,
            AccountCommand::LinkIdentity {
                provider: pending.provider.clone(),
                identity_id,
                at: Utc::now(),
            },
        )
        .await?;
        accounts::insert_identity(
            work.sql(),
            identity_id,
            &pending.provider,
            &pending.subject,
            account_id,
        )
        .await?;
        work.commit().await?;
        self.limits.login_succeeded(&name).await?;
        tracing::info!(%account_id, provider = %pending.provider, "identity linked");
        Ok(LinkOutcome::SignIn(account_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(claims: serde_json::Value) -> String {
        format!(
            "e30.{}.sig",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        )
    }

    fn claims() -> serde_json::Value {
        serde_json::json!({
            "iss": "https://sso.example.com", "sub": "abc", "aud": "client-1", "exp": 2_000_000_000,
            "nonce": "n0nce", "email": "a@example.com", "email_verified": true, "preferred_username": "Ada",
        })
    }

    #[test]
    fn a_linked_identity_signs_in_whatever_else_is_true() {
        let account = Uuid::now_v7();
        assert_eq!(decide(Some(account), false, None), Next::SignIn(account));
        assert_eq!(
            decide(Some(account), true, Some(Uuid::now_v7())),
            Next::SignIn(account)
        );
    }

    #[test]
    fn an_unverified_address_is_refused_even_when_it_matches_an_account() {
        assert_eq!(decide(None, false, Some(Uuid::now_v7())), Next::Refuse);
        assert_eq!(decide(None, false, None), Next::Refuse);
    }

    #[test]
    fn a_verified_address_that_matches_an_account_must_prove_ownership_first() {
        let account = Uuid::now_v7();
        assert_eq!(
            decide(None, true, Some(account)),
            Next::ProveOwnership(account)
        );
        assert_eq!(decide(None, true, None), Next::ChooseUsername);
    }

    #[test]
    fn the_pkce_challenge_is_the_rfc_7636_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn an_id_token_is_accepted_only_for_this_issuer_client_nonce_and_time() {
        let read = |c: serde_json::Value| {
            read_id_token(
                &token(c),
                "https://sso.example.com",
                "client-1",
                "n0nce",
                1_900_000_000,
            )
        };
        let identity = read(claims()).unwrap();
        assert_eq!(identity.subject, "abc");
        assert!(identity.email_verified);
        let mut c = claims();
        c["iss"] = "https://evil.example".into();
        assert_eq!(read(c).unwrap_err(), IdTokenError::Issuer);
        let mut c = claims();
        c["aud"] = serde_json::json!(["other", "client-1"]);
        assert!(read(c).is_ok());
        let mut c = claims();
        c["aud"] = "other".into();
        assert_eq!(read(c).unwrap_err(), IdTokenError::Audience);
        let mut c = claims();
        c["exp"] = 1_800_000_000.into();
        assert_eq!(read(c).unwrap_err(), IdTokenError::Expired);
        let mut c = claims();
        c["nonce"] = "replayed".into();
        assert_eq!(read(c).unwrap_err(), IdTokenError::Nonce);
        let mut c = claims();
        c.as_object_mut().unwrap().remove("nonce");
        assert_eq!(read(c).unwrap_err(), IdTokenError::Nonce);
        assert_eq!(
            read_id_token("garbage", "x", "y", "z", 0).unwrap_err(),
            IdTokenError::Malformed
        );
    }

    #[test]
    fn email_verified_as_the_string_true_counts_and_anything_else_does_not() {
        let read = |c: serde_json::Value| {
            read_id_token(
                &token(c),
                "https://sso.example.com",
                "client-1",
                "n0nce",
                1_900_000_000,
            )
        };
        let mut c = claims();
        c["email_verified"] = "true".into();
        assert!(read(c).unwrap().email_verified);
        let mut c = claims();
        c["email_verified"] = "yes".into();
        assert!(!read(c).unwrap().email_verified);
        let mut c = claims();
        c.as_object_mut().unwrap().remove("email_verified");
        assert!(!read(c).unwrap().email_verified);
    }
}
