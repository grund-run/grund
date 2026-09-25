use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use axum::{
    Json, Router,
    body::Body,
    extract::State as AxumState,
    http::{Request, StatusCode, header},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use grund_ee::social::{
    Registered, SocialLogin, TEMPLATES,
    flows::{Protocol, Provider},
};
use grund_server::{
    config::ServeConfig,
    license::{PREFIX, Verifier},
    services::{
        accounts::{AccountsState, RequestMeta, SignupForm, SignupOutcome},
        entitlements::Entitlements,
        passwords::Passwords,
    },
    state::State,
    templates::Templates,
};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Parser)]
struct Harness {
    #[command(flatten)]
    serve: ServeConfig,
}

#[derive(Default)]
struct MockProvider {
    nonce: Option<String>,
    subject: String,
    email: String,
    email_verified: bool,
    issuer: String,
}

async fn start_provider(mock: Arc<Mutex<MockProvider>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    mock.lock().unwrap().issuer = issuer.clone();
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(|AxumState(mock): AxumState<Arc<Mutex<MockProvider>>>| async move {
                let issuer = mock.lock().unwrap().issuer.clone();
                Json(serde_json::json!({
                    "issuer": issuer,
                    "authorization_endpoint": format!("{issuer}/authorize"),
                    "token_endpoint": format!("{issuer}/token"),
                }))
            }),
        )
        .route(
            "/token",
            post(|AxumState(mock): AxumState<Arc<Mutex<MockProvider>>>, body: String| async move {
                assert!(body.contains("code_verifier="), "the token request carries the PKCE verifier");
                assert!(body.contains("grant_type=authorization_code"));
                let mock = mock.lock().unwrap();
                let claims = serde_json::json!({
                    "iss": mock.issuer, "sub": mock.subject, "aud": "test-client", "exp": 4_000_000_000i64,
                    "nonce": mock.nonce, "email": mock.email, "email_verified": mock.email_verified,
                    "preferred_username": "Ada Lovelace",
                });
                let id_token = format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()));
                Json(serde_json::json!({ "access_token": "x", "id_token": id_token }))
            }),
        )
        .with_state(mock);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    issuer
}

fn license(key: &SigningKey) -> String {
    let claims = serde_json::json!({
        "v": 1, "kid": "test-only", "id": "lic_test", "customer": "cus_test", "plan": "pro",
        "features": ["social_login"], "issued_at": 0, "not_before": 0, "expires_at": 4_000_000_000i64,
    });
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signed = format!("{PREFIX}{payload}");
    format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(signed.as_bytes()).to_bytes())
    )
}

async fn state(pool: PgPool, issuer: &str) -> State {
    grund_store::migrate(&pool).await.unwrap();
    let mut serve = Harness::try_parse_from([
        "grund",
        "--database-url",
        "postgres://unused/grund",
        "--dev-mode",
        "true",
        "--public-url",
        "http://127.0.0.1:1",
    ])
    .unwrap()
    .serve;
    serve.validate().unwrap();
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let key = SigningKey::from_bytes(&seed);
    let verifier = Verifier::with_keys([("test-only".to_string(), key.verifying_key().to_bytes())]);
    let entitlements = Entitlements::from_key(Some(&license(&key)), &verifier, chrono::Utc::now());
    let provider = Provider {
        id: "oidc",
        name: "Test SSO".into(),
        icon: "key",
        protocol: Protocol::Oidc {
            issuer: issuer.to_string(),
        },
        client_id: "test-client".into(),
        client_secret: "test-secret".into(),
    };
    let events = mire::EventStore::new(pool.clone());
    State {
        config: Arc::new(serve),
        events: events.clone(),
        pool,
        nats: None,
        secret: Arc::new(grund_server::secrets::SecretKey::generate()),
        health: nostatus::StatusState::empty(),
        passwords: Passwords::new().unwrap(),
        templates: Templates::new(TEMPLATES).unwrap(),
        entitlements: Arc::new(entitlements),
        billing: grund_server::services::billing::Billing::Free,
        deletions: grund_server::sagas::Deletions::new(events.clone()),
        extensions: Arc::new(vec![Arc::new(Registered(Arc::new(SocialLogin::with(
            vec![provider],
            grund_ee::social::http_client().unwrap(),
        ))))]),
        started: Instant::now(),
    }
}

struct Browser {
    app: Router,
    cookies: Vec<(String, String)>,
}

struct Page {
    status: StatusCode,
    location: String,
    body: String,
}

impl Browser {
    async fn send(&mut self, method: &str, uri: &str, form: Option<String>) -> Page {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::ORIGIN, "http://127.0.0.1:1")
            .header(
                header::COOKIE,
                self.cookies
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        if form.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        }
        let mut request = request.body(Body::from(form.unwrap_or_default())).unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [127, 0, 0, 1],
                9,
            ))));
        let response = self.app.clone().oneshot(request).await.unwrap();
        for set in response.headers().get_all(header::SET_COOKIE) {
            let pair = set.to_str().unwrap().split(';').next().unwrap();
            let (name, value) = pair.split_once('=').unwrap();
            self.cookies.retain(|(k, _)| k != name);
            if !value.is_empty() {
                self.cookies.push((name.to_string(), value.to_string()));
            }
        }
        let status = response.status();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default();
        let body = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        Page {
            status,
            location,
            body,
        }
    }

    fn has_session(&self) -> bool {
        self.cookies.iter().any(|(k, _)| k == "grund_session")
    }
}

fn csrf(body: &str) -> String {
    let start = body.find("name=\"csrf\" value=\"").unwrap() + 19;
    body[start..start + body[start..].find('"').unwrap()].to_string()
}

fn query_param(url: &str, name: &str) -> String {
    let query = url.split_once('?').unwrap().1;
    serde_urlencoded::from_str::<Vec<(String, String)>>(query)
        .unwrap()
        .into_iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
        .unwrap_or_default()
}

async fn authorize(browser: &mut Browser, mock: &Arc<Mutex<MockProvider>>) -> Page {
    let start = browser.send("GET", "/auth/oidc/start", None).await;
    assert_eq!(start.status, StatusCode::SEE_OTHER);
    assert!(start.location.contains("/authorize?"), "{}", start.location);
    assert_eq!(
        query_param(&start.location, "code_challenge_method"),
        "S256"
    );
    assert_eq!(query_param(&start.location, "code_challenge").len(), 43);
    mock.lock().unwrap().nonce = Some(query_param(&start.location, "nonce"));
    let state = query_param(&start.location, "state");
    browser
        .send(
            "GET",
            &format!("/auth/oidc/callback?code=c0de&state={state}"),
            None,
        )
        .await
}

#[sqlx::test(migrations = false)]
async fn a_licensed_instance_offers_the_provider_and_a_new_identity_becomes_an_account(
    pool: PgPool,
) {
    let mock = Arc::new(Mutex::new(MockProvider {
        subject: Uuid::now_v7().to_string(),
        email: format!(
            "ada-{}@example.com",
            &Uuid::now_v7().simple().to_string()[24..]
        ),
        email_verified: true,
        ..Default::default()
    }));
    let issuer = start_provider(mock.clone()).await;
    let app = grund_server::web::router(state(pool, &issuer).await);
    let mut browser = Browser {
        app,
        cookies: Vec::new(),
    };

    let login = browser.send("GET", "/login", None).await;
    assert!(login.body.contains("Continue with Test SSO"));

    let callback = authorize(&mut browser, &mock).await;
    assert_eq!(
        (callback.status, callback.location.as_str()),
        (StatusCode::SEE_OTHER, "/auth/complete")
    );
    let complete = browser.send("GET", "/auth/complete", None).await;
    assert!(
        complete.body.contains("ada-lovelace"),
        "the provider's name is suggested"
    );
    let username = format!("ada-{}", &Uuid::now_v7().simple().to_string()[24..]);
    let done = browser
        .send(
            "POST",
            "/auth/complete",
            Some(format!("csrf={}&username={username}", csrf(&complete.body))),
        )
        .await;
    assert_eq!(
        (done.status, done.location.as_str()),
        (StatusCode::SEE_OTHER, "/")
    );
    assert!(browser.has_session());
    let landing = browser.send("GET", "/", None).await;
    assert_eq!(
        (landing.status, landing.location.as_str()),
        (StatusCode::SEE_OTHER, format!("/{username}").as_str()),
        "the first account on a single-organisation instance owns its organisation"
    );
    let home = browser.send("GET", &landing.location, None).await;
    assert!(
        home.body
            .contains(&format!("Signed in as {username}, owner of {username}"))
    );

    let mut again = Browser {
        app: browser.app.clone(),
        cookies: Vec::new(),
    };
    let callback = authorize(&mut again, &mock).await;
    assert_eq!(
        (callback.status, callback.location.as_str()),
        (StatusCode::SEE_OTHER, "/"),
        "a linked identity signs straight in"
    );
    assert!(again.has_session());
}

#[sqlx::test(migrations = false)]
async fn an_identity_whose_address_has_an_account_links_only_with_that_accounts_password(
    pool: PgPool,
) {
    let email = format!(
        "grace-{}@example.com",
        &Uuid::now_v7().simple().to_string()[24..]
    );
    let mock = Arc::new(Mutex::new(MockProvider {
        subject: Uuid::now_v7().to_string(),
        email: email.clone(),
        email_verified: true,
        ..Default::default()
    }));
    let issuer = start_provider(mock.clone()).await;
    let state = state(pool, &issuer).await;
    let meta = RequestMeta {
        request_id: Uuid::now_v7(),
        address: "127.0.0.1".into(),
    };
    let outcome = state
        .accounts()
        .sign_up(
            SignupForm {
                username: format!("grace-{}", &Uuid::now_v7().simple().to_string()[24..]),
                email: email.clone(),
                password: "graces own long password".into(),
            },
            &meta,
        )
        .await
        .unwrap();
    assert!(matches!(outcome, SignupOutcome::Sent { .. }));
    let mut browser = Browser {
        app: grund_server::web::router(state),
        cookies: Vec::new(),
    };

    let callback = authorize(&mut browser, &mock).await;
    assert_eq!(
        (callback.status, callback.location.as_str()),
        (StatusCode::SEE_OTHER, "/auth/link")
    );
    assert!(
        !browser.has_session(),
        "an address match alone never signs in"
    );
    let link = browser.send("GET", "/auth/link", None).await;
    assert!(link.body.contains(&email));

    let wrong = browser
        .send(
            "POST",
            "/auth/link",
            Some(format!(
                "csrf={}&password=not+her+password",
                csrf(&link.body)
            )),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::OK);
    assert!(wrong.body.contains("That password is not right."));
    assert!(!browser.has_session());

    let right = browser
        .send(
            "POST",
            "/auth/link",
            Some(format!(
                "csrf={}&password=graces+own+long+password",
                csrf(&wrong.body)
            )),
        )
        .await;
    assert_eq!(
        (right.status, right.location.as_str()),
        (StatusCode::SEE_OTHER, "/")
    );
    assert!(browser.has_session());

    let replay = browser
        .send(
            "POST",
            "/auth/link",
            Some(format!(
                "csrf={}&password=graces+own+long+password",
                csrf(&wrong.body)
            )),
        )
        .await;
    assert_ne!(
        replay.status,
        StatusCode::SEE_OTHER,
        "a used flow links nothing again"
    );
}

#[sqlx::test(migrations = false)]
async fn an_unverified_address_or_a_foreign_state_is_refused_and_creates_nothing(pool: PgPool) {
    let mock = Arc::new(Mutex::new(MockProvider {
        subject: Uuid::now_v7().to_string(),
        email: "mallory@example.com".into(),
        email_verified: false,
        ..Default::default()
    }));
    let issuer = start_provider(mock.clone()).await;
    let app = grund_server::web::router(state(pool.clone(), &issuer).await);
    let mut browser = Browser {
        app: app.clone(),
        cookies: Vec::new(),
    };

    let callback = authorize(&mut browser, &mock).await;
    assert_eq!(callback.status, StatusCode::FORBIDDEN);
    assert!(
        callback
            .body
            .contains("has not verified your email address")
    );
    let accounts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM grund_account_emails WHERE email = 'mallory@example.com'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(accounts, 0);

    let mut victim = Browser {
        app,
        cookies: Vec::new(),
    };
    victim.send("GET", "/auth/oidc/start", None).await;
    let forged = victim
        .send(
            "GET",
            "/auth/oidc/callback?code=c0de&state=attackers-own-state-value-0000000",
            None,
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert!(forged.body.contains("did not start here"));
}
