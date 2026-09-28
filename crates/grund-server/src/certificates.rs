//! The instance's certificates (grund-docs design/traffic.md §5.1, "the
//! certificates part"): what `grund serve` serves on GRUND_TLS_LISTEN, and
//! the ACME orders behind it.
//!
//! ```text
//!   every replica                               the replica holding the lease
//!   ─────────────                               ────────────────────────────
//!   Resolver ◄─ refresh (grund_certificates     claim (SKIP LOCKED, 10 min lease)
//!      │        version, every                    ├─ account (sealed, per directory)
//!      │        GRUND_TLS_REFRESH_INTERVAL)       ├─ order: resume by URL, or new with a
//!      ▼                                          │  fresh key (sealed) and its CSR
//!   grund/https ── acme-tls/1 ─► grund_acme_      ├─ challenges ─► grund_acme_challenges
//!   grund/redirect ─ HTTP-01 ─►  challenges       ├─ finalize, chain, ARI window
//!                                                 └─ record: chain + sealed key, version+1
//! ```
//!
//! PostgreSQL holds all of it, so any replica can serve the certificate and
//! answer a challenge while one replica orders. A failed attempt reschedules
//! with backoff (never sooner than the CA's Retry-After) and the stored
//! certificate keeps being served; with none stored yet, HTTPS refuses
//! handshakes and readiness says why, while plain http carries on.
//!
//! Keys are sealed with ChaCha20-Poly1305 under `GRUND_SECRET_KEY`'s
//! `tls/seal` subkey, bound to what they are (account, order key,
//! certificate key) as associated data.
//!
//! Only the instance's own domain is built. The relay, the gate and the edge
//! will hand in a CSR instead of having the instance make their key
//! (`grund_tls::KeyAndCsr`); that flow is designed in traffic.md §5.7, not
//! built.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, SystemTime},
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use grund_store::certificates::{self as store, Challenge, Claim, Desired, Issued};
use grund_tls::{KeyAndCsr, Resolver, Served};
use instant_acme::{
    Account, AuthorizationStatus, CertificateIdentifier, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use nostatus::CheckStatus;
use notmad::{Component, ComponentInfo, MadError};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    acme::{self, Failure, Http},
    config::ServeConfig,
    secrets::SecretKey,
    state::State,
};

/// The subject of the instance's own domain certificate.
pub const SUBJECT: &str = "instance";

/// How long a replica holds a subject while it works on it. Longer than
/// [`ATTEMPT_DEADLINE`], so a live holder is never overtaken.
pub const LEASE: Duration = Duration::from_secs(600);

/// The longest one attempt (account, order, challenges, certificate) runs.
/// An order still unfinished then is resumed by the next attempt.
pub const ATTEMPT_DEADLINE: Duration = Duration::from_secs(300);

/// How long a published challenge answer stays valid.
pub const CHALLENGE_TTL: Duration = Duration::from_secs(900);

/// A certificate with less than this left is reported as degraded, unless
/// its lifetime is so short that a third of it is less (traffic.md §5.6).
pub const EXPIRY_WARNING: Duration = Duration::from_secs(14 * 86400);

/// Refuses to start when GRUND_TLS_CERT_FILE or its key cannot be read, or
/// do not belong together, before anything else is opened.
pub fn check_files(config: &ServeConfig) -> anyhow::Result<()> {
    if let (Some(cert), Some(key)) = (&config.tls.tls_cert_file, &config.tls.tls_key_file) {
        grund_tls::Files::new(cert, key)
            .reload_if_changed(&Resolver::default())
            .context("GRUND_TLS_CERT_FILE and GRUND_TLS_KEY_FILE")?;
    }
    Ok(())
}

/// The instance's certificates. Cheap to clone; clones share the resolver
/// and what has been loaded.
#[derive(Clone)]
pub struct Certificates {
    resolver: Resolver,
    inner: Arc<Inner>,
}

struct Inner {
    source: Source,
    pool: sqlx::PgPool,
    secret: Arc<SecretKey>,
    dev_mode: bool,
    holder: Uuid,
    known_version: AtomicI64,
}

enum Source {
    Off,
    Files(Mutex<grund_tls::Files>),
    Acme(AcmeSettings),
}

struct AcmeSettings {
    desired: Desired,
    contact: Option<String>,
    ca_file: Option<PathBuf>,
    retry_base: Duration,
}

impl Certificates {
    /// From the validated configuration. Nothing is read yet: see [`Self::start`].
    pub fn new(config: &ServeConfig, pool: sqlx::PgPool, secret: Arc<SecretKey>) -> Self {
        let tls = &config.tls;
        let source = match (&tls.tls_cert_file, &tls.tls_key_file, &tls.domain) {
            (Some(cert), Some(key), _) => {
                Source::Files(Mutex::new(grund_tls::Files::new(cert, key)))
            }
            (_, _, Some(domain)) => Source::Acme(AcmeSettings {
                desired: Desired {
                    subject: SUBJECT.into(),
                    names: vec![domain.clone()],
                    directory: tls.acme_directory.clone().unwrap_or_default(),
                    profile: tls.acme_profile.clone(),
                    challenge: Challenge::parse(&tls.acme_challenge)
                        .unwrap_or(Challenge::TlsAlpn01),
                },
                contact: tls.acme_contact.clone(),
                ca_file: tls.acme_ca_file.clone(),
                retry_base: tls.acme_retry_base,
            }),
            _ => Source::Off,
        };
        Self {
            resolver: Resolver::default(),
            inner: Arc::new(Inner {
                source,
                pool,
                secret,
                dev_mode: config.dev_mode,
                holder: Uuid::now_v7(),
                known_version: AtomicI64::new(0),
            }),
        }
    }

    /// What HTTPS serves. The relay, when it runs beside the instance, can
    /// serve the same certificate through a clone of this.
    pub fn resolver(&self) -> Resolver {
        self.resolver.clone()
    }

    /// Whether this instance serves HTTPS itself.
    pub fn enabled(&self) -> bool {
        !matches!(self.inner.source, Source::Off)
    }

    /// Whether this instance orders its certificate by ACME.
    pub fn acme(&self) -> bool {
        matches!(self.inner.source, Source::Acme(_))
    }

    /// Before serving: loads GRUND_TLS_CERT_FILE (refusing to start when it
    /// cannot), or records what ACME should order and loads what was
    /// ordered before. A CA being unreachable never stops the start.
    pub async fn start(&self) -> anyhow::Result<()> {
        match &self.inner.source {
            Source::Off => Ok(()),
            Source::Files(files) => {
                files
                    .lock()
                    .expect("files lock")
                    .reload_if_changed(&self.resolver)
                    .context("GRUND_TLS_CERT_FILE and GRUND_TLS_KEY_FILE")?;
                let served = self
                    .resolver
                    .current()
                    .context("a certificate was loaded")?;
                tracing::info!(
                    names = ?served.names,
                    not_after = %DateTime::<Utc>::from(served.not_after),
                    "https: serving the certificate from GRUND_TLS_CERT_FILE"
                );
                Ok(())
            }
            Source::Acme(settings) => {
                Http::new(settings.ca_file.as_deref())?;
                store::desire(&self.inner.pool, &settings.desired)
                    .await
                    .context("record the certificate GRUND_DOMAIN needs")?;
                self.refresh().await?;
                match self.resolver.current() {
                    Some(served) => tracing::info!(
                        names = ?served.names,
                        not_after = %DateTime::<Utc>::from(served.not_after),
                        "https: serving the stored certificate; renewal is ACME's"
                    ),
                    None => tracing::info!(
                        domain = %settings.desired.names[0],
                        directory = %settings.desired.directory,
                        "https: no certificate yet; HTTPS refuses handshakes until the first order succeeds"
                    ),
                }
                Ok(())
            }
        }
    }

    /// Serves a renewed certificate if there is one: GRUND_TLS_CERT_FILE
    /// when it changed, or a newer version in the database.
    pub async fn refresh(&self) -> anyhow::Result<()> {
        match &self.inner.source {
            Source::Off => Ok(()),
            Source::Files(files) => {
                if files
                    .lock()
                    .expect("files lock")
                    .reload_if_changed(&self.resolver)
                    .context("GRUND_TLS_CERT_FILE and GRUND_TLS_KEY_FILE")?
                {
                    tracing::info!("https: GRUND_TLS_CERT_FILE changed; serving it");
                }
                Ok(())
            }
            Source::Acme(_) => {
                let known = self.inner.known_version.load(Ordering::Acquire);
                let Some(stored) =
                    store::stored_if_changed(&self.inner.pool, SUBJECT, known).await?
                else {
                    return Ok(());
                };
                self.inner
                    .known_version
                    .store(stored.version, Ordering::Release);
                let key = stored
                    .sealed_key
                    .as_deref()
                    .and_then(|sealed| self.unseal(&certificate_aad(SUBJECT), sealed));
                let Some(key) = key else {
                    return self.unreadable_key().await;
                };
                let served = Served::from_pkcs8(stored.chain_pem.as_bytes(), &key)
                    .context("the stored certificate")?;
                tracing::info!(
                    version = stored.version,
                    not_after = %DateTime::<Utc>::from(served.not_after),
                    "https: serving certificate version {}",
                    stored.version
                );
                self.resolver.set(served);
                Ok(())
            }
        }
    }

    async fn unreadable_key(&self) -> anyhow::Result<()> {
        if self.inner.dev_mode {
            tracing::warn!(
                "https: the stored certificate's key was sealed with another GRUND_SECRET_KEY \
                 (GRUND_DEV_MODE's throwaway one); ordering a new certificate"
            );
            store::order_now(&self.inner.pool, SUBJECT).await?;
            return Ok(());
        }
        anyhow::bail!(
            "the stored certificate's key does not open with GRUND_SECRET_KEY; it was sealed \
             with another secret key"
        )
    }

    /// Does the ACME work that is due, if this replica can claim it: an
    /// order, or a renewal-information check. Returns whether it claimed
    /// anything. Failures are recorded and rescheduled, not returned.
    pub async fn work_once(&self) -> anyhow::Result<bool> {
        let Source::Acme(settings) = &self.inner.source else {
            return Ok(false);
        };
        let Some(claim) =
            store::claim(&self.inner.pool, self.inner.holder, LEASE.as_secs_f64()).await?
        else {
            return Ok(false);
        };
        if claim.subject != SUBJECT {
            store::release(&self.inner.pool, &claim.subject, self.inner.holder).await?;
            return Ok(false);
        }
        let http = Http::new(settings.ca_file.as_deref())?;
        let attempt = tokio::time::timeout(ATTEMPT_DEADLINE, self.attempt(settings, &http, &claim));
        let failed = match attempt.await {
            Ok(Ok(())) => return Ok(true),
            Ok(Err(failed)) => failed,
            Err(_) => Attempt::failed(
                Failure::TimedOut,
                anyhow::anyhow!("the attempt ran out of time"),
            ),
        };
        let retry_after = http.take_retry_after();
        let delay = acme::backoff(
            u32::try_from(claim.attempts).unwrap_or(0),
            settings.retry_base,
            retry_after,
            acme::unit_random(),
        );
        let recorded = store::record_failure(
            &self.inner.pool,
            SUBJECT,
            self.inner.holder,
            delay.as_secs_f64(),
            failed.failure.code(),
        )
        .await?;
        let serving = self
            .resolver
            .current()
            .map(|served| DateTime::<Utc>::from(served.not_after).to_rfc3339());
        tracing::warn!(
            error = format!("{:#}", failed.error),
            code = failed.failure.code(),
            attempts = claim.attempts + 1,
            retry_in_seconds = delay.as_secs(),
            retry_after_seconds = retry_after.map(|d| d.as_secs()),
            serving_until = serving.as_deref().unwrap_or("nothing"),
            recorded,
            "https: certificate {} failed; the current certificate (if any) stays served and \
             grund tries again later",
            if claim.order_due {
                "order"
            } else {
                "renewal check"
            }
        );
        Ok(true)
    }

    async fn attempt(
        &self,
        settings: &AcmeSettings,
        http: &Http,
        claim: &Claim,
    ) -> Result<(), Attempt> {
        let account = self.account(settings, http, &claim.directory).await?;
        let current = match &claim.chain_pem {
            Some(chain) => Some(leaf(chain).map_err(Attempt::internal)?),
            None => None,
        };
        if !claim.order_due {
            let (leaf_der, not_before, not_after) = current.ok_or_else(|| {
                Attempt::internal(anyhow::anyhow!("a renewal check needs a certificate"))
            })?;
            let (renew_at, ari_check_at) =
                renewal(&account, &leaf_der, not_before, not_after).await;
            store::record_renewal_info(
                &self.inner.pool,
                SUBJECT,
                self.inner.holder,
                renew_at,
                ari_check_at,
            )
            .await
            .map_err(Attempt::store)?;
            tracing::info!(%renew_at, "https: renewal window checked");
            return Ok(());
        }
        let profiles: Vec<String> = account.profiles().map(|p| p.name.to_string()).collect();
        if !profiles.is_empty() && !profiles.iter().any(|p| p == &claim.profile) {
            return Err(Attempt::failed(
                Failure::Refused,
                anyhow::anyhow!(
                    "GRUND_ACME_PROFILE={} is not offered by {}; it offers {}",
                    claim.profile,
                    claim.directory,
                    profiles.join(", ")
                ),
            ));
        }
        let replaces = current
            .as_ref()
            .and_then(|(der, _, _)| CertificateIdentifier::try_from(der).ok())
            .map(CertificateIdentifier::into_owned);
        let (order_id, mut order, csr) = self.order(&account, claim, replaces).await?;
        let challenge = Challenge::parse(&claim.challenge).unwrap_or(Challenge::TlsAlpn01);
        let published = self.authorize(&mut order, challenge).await?;
        let result = self.finish(&mut order, order_id, claim, &csr).await;
        for (name, token) in &published {
            let _ = store::remove_challenge(&self.inner.pool, challenge, name, token).await;
        }
        let chain = result?;
        let served = Served::from_pkcs8(chain.as_bytes(), csr.key_pkcs8_der())
            .context("the issued certificate")
            .map_err(Attempt::internal)?;
        if let Some(missing) = claim.names.iter().find(|name| !served.covers(name)) {
            return Err(Attempt::failed(
                Failure::Refused,
                anyhow::anyhow!("the issued certificate does not name {missing}"),
            ));
        }
        let (leaf_der, not_before, not_after) = leaf(&chain).map_err(Attempt::internal)?;
        let (renew_at, ari_check_at) = renewal(&account, &leaf_der, not_before, not_after).await;
        let issued = Issued {
            chain_pem: chain,
            sealed_key: Some(self.seal(&certificate_aad(SUBJECT), csr.key_pkcs8_der())),
            not_before,
            not_after,
            renew_at,
            ari_check_at,
        };
        let recorded = store::record_issued(
            &self.inner.pool,
            SUBJECT,
            self.inner.holder,
            order_id,
            &issued,
        )
        .await
        .map_err(Attempt::store)?;
        if !recorded {
            tracing::warn!(
                "https: a certificate was issued after this replica lost its lease; discarded"
            );
            return Ok(());
        }
        tracing::info!(
            names = ?claim.names,
            %not_after,
            %renew_at,
            "https: certificate issued"
        );
        self.resolver.set(served);
        Ok(())
    }

    async fn order(
        &self,
        account: &Account,
        claim: &Claim,
        replaces: Option<CertificateIdentifier<'static>>,
    ) -> Result<(Uuid, instant_acme::Order, KeyAndCsr), Attempt> {
        let pool = &self.inner.pool;
        if let Some(pending) = store::pending_order(pool, SUBJECT)
            .await
            .map_err(Attempt::store)?
        {
            let key = pending
                .sealed_key
                .as_deref()
                .and_then(|sealed| self.unseal(&order_aad(pending.order_id), sealed));
            let resumed = match key {
                Some(key) => match account.order(pending.url.clone()).await {
                    Ok(mut order) => (!matches!(order_status(&mut order), OrderStatus::Invalid))
                        .then(|| KeyAndCsr::from_pkcs8(&key, &claim.names).ok())
                        .flatten()
                        .map(|csr| (order, csr)),
                    Err(error) if Failure::of(&error) == Failure::Unreachable => {
                        return Err(Attempt::acme(error));
                    }
                    Err(_) => None,
                },
                None => None,
            };
            if let Some((order, csr)) = resumed {
                tracing::info!(url = %pending.url, "https: resuming an order placed earlier");
                return Ok((pending.order_id, order, csr));
            }
            store::finish_order(pool, pending.order_id, "abandoned", "not_resumable")
                .await
                .map_err(Attempt::store)?;
        }
        let csr = KeyAndCsr::generate(&claim.names).map_err(Attempt::internal)?;
        let identifiers: Vec<Identifier> = claim
            .names
            .iter()
            .map(|name| Identifier::Dns(name.clone()))
            .collect();
        let placed = match replaces {
            Some(replaces) => {
                let new = NewOrder::new(&identifiers)
                    .profile(&claim.profile)
                    .replaces(replaces);
                match account.new_order(&new).await {
                    Ok(order) => Ok(order),
                    Err(error) if Failure::of(&error) == Failure::Refused => {
                        tracing::info!(error = %error, "https: the CA refused a renewal that names the certificate it replaces; ordering without");
                        account
                            .new_order(&NewOrder::new(&identifiers).profile(&claim.profile))
                            .await
                    }
                    Err(error) => Err(error),
                }
            }
            None => {
                account
                    .new_order(&NewOrder::new(&identifiers).profile(&claim.profile))
                    .await
            }
        };
        let order = placed.map_err(Attempt::acme)?;
        let order_id = Uuid::now_v7();
        store::insert_order(
            pool,
            order_id,
            SUBJECT,
            order.url(),
            Some(&self.seal(&order_aad(order_id), csr.key_pkcs8_der())),
        )
        .await
        .map_err(Attempt::store)?;
        tracing::info!(url = %order.url(), profile = %claim.profile, "https: order placed");
        Ok((order_id, order, csr))
    }

    async fn authorize(
        &self,
        order: &mut instant_acme::Order,
        challenge: Challenge,
    ) -> Result<Vec<(String, String)>, Attempt> {
        let kind = match challenge {
            Challenge::TlsAlpn01 => ChallengeType::TlsAlpn01,
            Challenge::Http01 => ChallengeType::Http01,
        };
        let mut published = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization = authorization.map_err(Attempt::acme)?;
            if authorization.status != AuthorizationStatus::Pending {
                continue;
            }
            let mut handle = authorization.challenge(kind.clone()).ok_or_else(|| {
                Attempt::failed(
                    Failure::Refused,
                    anyhow::anyhow!("the CA offers no {} challenge", challenge.as_str()),
                )
            })?;
            let name = match handle.identifier().identifier {
                Identifier::Dns(name) => name.to_ascii_lowercase(),
                _ => {
                    return Err(Attempt::internal(anyhow::anyhow!(
                        "an authorization for something other than a DNS name"
                    )));
                }
            };
            let token = handle.token.clone();
            store::put_challenge(
                &self.inner.pool,
                challenge,
                &name,
                &token,
                handle.key_authorization().as_str(),
                CHALLENGE_TTL.as_secs_f64(),
            )
            .await
            .map_err(Attempt::store)?;
            handle.set_ready().await.map_err(Attempt::acme)?;
            tracing::info!(%name, challenge = challenge.as_str(), "https: challenge ready");
            published.push((name, token));
        }
        Ok(published)
    }

    async fn finish(
        &self,
        order: &mut instant_acme::Order,
        order_id: Uuid,
        claim: &Claim,
        csr: &KeyAndCsr,
    ) -> Result<String, Attempt> {
        let policy = RetryPolicy::new()
            .initial_delay(Duration::from_millis(250))
            .backoff(2.0)
            .timeout(Duration::from_secs(120));
        if matches!(order_status(order), OrderStatus::Pending) {
            let status = order.poll_ready(&policy).await.map_err(Attempt::acme)?;
            if status == OrderStatus::Invalid {
                let detail = order
                    .state()
                    .error
                    .as_ref()
                    .map(|problem| problem.to_string())
                    .unwrap_or_else(|| "no detail".into());
                store::finish_order(
                    &self.inner.pool,
                    order_id,
                    "invalid",
                    "authorization_failed",
                )
                .await
                .map_err(Attempt::store)?;
                return Err(Attempt::failed(
                    Failure::AuthorizationFailed,
                    anyhow::anyhow!(
                        "the CA could not validate {} by {}: {detail}",
                        claim.names.join(", "),
                        claim.challenge
                    ),
                ));
            }
        }
        if matches!(order_status(order), OrderStatus::Ready) {
            order
                .finalize_csr(csr.csr_der())
                .await
                .map_err(Attempt::acme)?;
        }
        if matches!(order_status(order), OrderStatus::Invalid) {
            store::finish_order(&self.inner.pool, order_id, "invalid", "order_invalid")
                .await
                .map_err(Attempt::store)?;
            return Err(Attempt::failed(
                Failure::Refused,
                anyhow::anyhow!("the CA marked the order invalid"),
            ));
        }
        order.poll_certificate(&policy).await.map_err(Attempt::acme)
    }

    async fn account(
        &self,
        settings: &AcmeSettings,
        http: &Http,
        directory: &str,
    ) -> Result<Account, Attempt> {
        let pool = &self.inner.pool;
        let aad = account_aad(directory);
        if let Some(sealed) = store::account(pool, directory)
            .await
            .map_err(Attempt::store)?
        {
            match self.unseal(&aad, &sealed) {
                Some(json) => {
                    let credentials = serde_json::from_slice(&json)
                        .context("the stored ACME account")
                        .map_err(Attempt::internal)?;
                    return Account::builder_with_http(Box::new(http.clone()))
                        .from_credentials(credentials)
                        .await
                        .map_err(Attempt::acme);
                }
                None if self.inner.dev_mode => {
                    tracing::warn!(
                        "https: the stored ACME account was sealed with another GRUND_SECRET_KEY (GRUND_DEV_MODE); making a new one"
                    );
                    store::delete_account(pool, directory)
                        .await
                        .map_err(Attempt::store)?;
                }
                None => {
                    return Err(Attempt::internal(anyhow::anyhow!(
                        "the stored ACME account does not open with GRUND_SECRET_KEY"
                    )));
                }
            }
        }
        let contact: Vec<&str> = settings.contact.iter().map(String::as_str).collect();
        let (account, credentials) = Account::builder_with_http(Box::new(http.clone()))
            .create(
                &NewAccount {
                    contact: &contact,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory.to_string(),
                None,
            )
            .await
            .map_err(Attempt::acme)?;
        let json = serde_json::to_vec(&credentials)
            .context("the new ACME account")
            .map_err(Attempt::internal)?;
        let sealed = self.seal(&aad, &json);
        let stored = store::insert_account(pool, directory, &sealed)
            .await
            .map_err(Attempt::store)?;
        if stored == sealed {
            tracing::info!(id = %account.id(), %directory, "https: ACME account made");
            return Ok(account);
        }
        let json = self
            .unseal(&aad, &stored)
            .context("the ACME account another replica stored")
            .map_err(Attempt::internal)?;
        let credentials = serde_json::from_slice(&json)
            .context("the stored ACME account")
            .map_err(Attempt::internal)?;
        Account::builder_with_http(Box::new(http.clone()))
            .from_credentials(credentials)
            .await
            .map_err(Attempt::acme)
    }

    /// Answers TLS-ALPN-01 from the database, for the names this instance
    /// orders; nothing when it does not order by ACME.
    pub fn challenges(&self) -> StoredChallenges {
        match &self.inner.source {
            Source::Acme(settings) => StoredChallenges {
                pool: Some(self.inner.pool.clone()),
                names: settings.desired.names.clone().into(),
            },
            _ => StoredChallenges {
                pool: None,
                names: Arc::from(Vec::new()),
            },
        }
    }

    /// The HTTP-01 key authorization for `token`, if an order waits on it.
    pub async fn http01(&self, token: &str) -> Option<String> {
        if !self.acme() {
            return None;
        }
        store::http01(&self.inner.pool, token)
            .await
            .map_err(|error| tracing::warn!(error = %error, "https: HTTP-01 lookup failed"))
            .ok()
            .flatten()
    }

    /// Readiness for the served certificate: unhealthy with none or an
    /// expired one, degraded within [`EXPIRY_WARNING`] of expiry.
    pub fn health(&self) -> CheckStatus {
        match self.resolver.current() {
            None => CheckStatus::Unhealthy,
            Some(served) => expiry_status(served.not_before, served.not_after, SystemTime::now()),
        }
    }

    fn seal(&self, aad: &str, plaintext: &[u8]) -> Vec<u8> {
        seal(&self.inner.secret.derive("tls/seal"), aad, plaintext)
    }

    fn unseal(&self, aad: &str, sealed: &[u8]) -> Option<Vec<u8>> {
        unseal(&self.inner.secret.derive("tls/seal"), aad, sealed)
    }
}

/// TLS-ALPN-01 answers from `grund_acme_challenges`, for a
/// [`grund_tls::TlsListener`].
#[derive(Clone)]
pub struct StoredChallenges {
    pool: Option<sqlx::PgPool>,
    names: Arc<[String]>,
}

impl grund_tls::Challenges for StoredChallenges {
    async fn tls_alpn01(&self, name: &str) -> Option<Vec<u8>> {
        let pool = self.pool.as_ref()?;
        if !self.names.iter().any(|n| n == name) {
            return None;
        }
        let key_authorization = store::tls_alpn01(pool, name)
            .await
            .map_err(|error| tracing::warn!(error = %error, "https: TLS-ALPN-01 lookup failed"))
            .ok()
            .flatten()?;
        Some(Sha256::digest(key_authorization.as_bytes()).to_vec())
    }
}

struct Attempt {
    failure: Failure,
    error: anyhow::Error,
}

impl Attempt {
    fn failed(failure: Failure, error: anyhow::Error) -> Self {
        Self { failure, error }
    }

    fn acme(error: instant_acme::Error) -> Self {
        Self {
            failure: Failure::of(&error),
            error: anyhow::Error::from(error),
        }
    }

    fn store(error: sqlx::Error) -> Self {
        Self::failed(
            Failure::Internal,
            anyhow::Error::from(error).context("the database"),
        )
    }

    fn internal(error: anyhow::Error) -> Self {
        Self::failed(Failure::Internal, error)
    }
}

fn order_status(order: &mut instant_acme::Order) -> OrderStatus {
    order.state().status
}

fn leaf(
    chain_pem: &str,
) -> anyhow::Result<(
    rustls::pki_types::CertificateDer<'static>,
    DateTime<Utc>,
    DateTime<Utc>,
)> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .next()
        .context("the chain holds no certificate")?
        .context("parse the chain")?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der)
        .map_err(|error| anyhow::anyhow!("parse the certificate: {error}"))?;
    let at = |t: x509_parser::time::ASN1Time| {
        DateTime::from_timestamp(t.timestamp(), 0).context("a certificate time")
    };
    let validity = parsed.validity();
    let (not_before, not_after) = (at(validity.not_before)?, at(validity.not_after)?);
    Ok((der, not_before, not_after))
}

async fn renewal(
    account: &Account,
    leaf_der: &rustls::pki_types::CertificateDer<'_>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
) -> (DateTime<Utc>, Option<DateTime<Utc>>) {
    let fallback = acme::fallback_renewal_time(not_before, not_after);
    let now = Utc::now();
    let Ok(id) = CertificateIdentifier::try_from(leaf_der) else {
        return (fallback, None);
    };
    match account.renewal_info(&id).await {
        Ok((info, retry)) => {
            let convert = |t: time::OffsetDateTime| {
                DateTime::from_timestamp(t.unix_timestamp(), t.nanosecond()).unwrap_or(now)
            };
            let renew_at = acme::renewal_time(
                convert(info.suggested_window.start),
                convert(info.suggested_window.end),
                now,
                acme::unit_random(),
            );
            let wait = retry.clamp(Duration::from_secs(60), Duration::from_secs(24 * 3600));
            (renew_at, Some(now + wait))
        }
        Err(instant_acme::Error::Unsupported(_)) => (fallback, None),
        Err(error) => {
            tracing::info!(error = %error, "https: no renewal information from the CA; renewing two thirds in, asking again in an hour");
            (fallback, Some(now + Duration::from_secs(3600)))
        }
    }
}

/// Readiness for a certificate valid from `not_before` to `not_after`, at
/// `now`.
pub fn expiry_status(
    not_before: SystemTime,
    not_after: SystemTime,
    now: SystemTime,
) -> CheckStatus {
    let Ok(left) = not_after.duration_since(now) else {
        return CheckStatus::Unhealthy;
    };
    let lifetime = not_after.duration_since(not_before).unwrap_or_default();
    if left < EXPIRY_WARNING.min(lifetime / 3) {
        CheckStatus::Degraded
    } else {
        CheckStatus::Healthy
    }
}

fn certificate_aad(subject: &str) -> String {
    format!("grund/tls/certificate-key/{subject}")
}

fn order_aad(order_id: Uuid) -> String {
    format!("grund/tls/order-key/{order_id}")
}

fn account_aad(directory: &str) -> String {
    format!("grund/tls/acme-account/{directory}")
}

const SEAL_VERSION: u8 = 1;

fn seal(key: &[u8; 32], aad: &str, plaintext: &[u8]) -> Vec<u8> {
    use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).expect("a 32-byte key"));
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).expect("the operating system provides randomness");
    let mut buffer = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad.as_bytes()),
        &mut buffer,
    )
    .expect("sealing a buffer this size");
    let mut sealed = Vec::with_capacity(1 + NONCE_LEN + buffer.len());
    sealed.push(SEAL_VERSION);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&buffer);
    sealed
}

fn unseal(key: &[u8; 32], aad: &str, sealed: &[u8]) -> Option<Vec<u8>> {
    use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
    let (&version, rest) = sealed.split_first()?;
    if version != SEAL_VERSION || rest.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key).ok()?);
    let mut buffer = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).ok()?,
            Aad::from(aad.as_bytes()),
            &mut buffer,
        )
        .ok()?;
    Some(plaintext.to_vec())
}

/// The instance's certificates.
pub trait CertificatesState {
    fn certificates(&self) -> Certificates;
}

impl CertificatesState for State {
    fn certificates(&self) -> Certificates {
        self.certificates.clone()
    }
}

/// HTTPS on GRUND_TLS_LISTEN, serving the same router as plain http. Off
/// unless GRUND_DOMAIN or GRUND_TLS_CERT_FILE is set. Added right after the
/// plain listener, so both stop taking requests first.
pub struct Https {
    state: State,
}

impl Https {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

impl Component for Https {
    fn info(&self) -> ComponentInfo {
        "grund/https".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        use axum::serve::ListenerExt;
        let certificates = self.state.certificates();
        if !certificates.enabled() {
            cancellation.cancelled().await;
            return Ok(());
        }
        let address = self.state.config.tls.tls_listen;
        let tcp = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| format!("bind GRUND_TLS_LISTEN {address}"))?;
        let config = grund_tls::server_config(certificates.resolver(), &[b"http/1.1"])?;
        let listener =
            grund_tls::TlsListener::new(tcp, Arc::new(config), certificates.challenges())
                .map_err(anyhow::Error::from)?;
        tracing::info!(%address, public_url = %self.state.config.public_origin().serialized, "grund listening for https");
        let app = crate::web::router(self.state.clone())
            .into_make_service_with_connect_info::<SocketAddr>();
        axum::serve(listener.tap_io(|_| {}), app)
            .with_graceful_shutdown(async move { cancellation.cancelled().await })
            .await
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
}

/// Plain http on GRUND_TLS_REDIRECT_LISTEN: ACME's HTTP-01 answers, and a
/// permanent redirect to GRUND_PUBLIC_URL for everything else. The redirect
/// goes to the configured origin, never to the request's Host, so it cannot
/// be pointed elsewhere.
pub struct Redirect {
    state: State,
}

impl Redirect {
    pub fn new(state: State) -> Self {
        Self { state }
    }
}

impl Component for Redirect {
    fn info(&self) -> ComponentInfo {
        "grund/redirect".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        use axum::{
            extract::{Path, State as AxumState},
            http::{StatusCode, Uri, header},
            response::IntoResponse,
            routing::get,
        };
        let Some(address) = self.state.config.tls.tls_redirect_listen else {
            cancellation.cancelled().await;
            return Ok(());
        };
        let origin = self.state.config.public_origin().serialized;
        let router = axum::Router::new()
            .route(
                "/.well-known/acme-challenge/{token}",
                get(
                    |AxumState(state): AxumState<State>, Path(token): Path<String>| async move {
                        match state.certificates().http01(&token).await {
                            Some(answer) => {
                                ([(header::CONTENT_TYPE, "text/plain")], answer).into_response()
                            }
                            None => StatusCode::NOT_FOUND.into_response(),
                        }
                    },
                ),
            )
            .fallback(move |uri: Uri| {
                let origin = origin.clone();
                async move {
                    let path = uri.path_and_query().map_or("/", |p| p.as_str());
                    (
                        StatusCode::PERMANENT_REDIRECT,
                        [(header::LOCATION, format!("{origin}{path}"))],
                    )
                }
            })
            .with_state(self.state.clone());
        let listener = tokio::net::TcpListener::bind(address)
            .await
            .with_context(|| format!("bind GRUND_TLS_REDIRECT_LISTEN {address}"))?;
        tracing::info!(%address, "grund redirecting http to https");
        axum::serve(listener, router)
            .with_graceful_shutdown(async move { cancellation.cancelled().await })
            .await
            .map_err(anyhow::Error::from)?;
        Ok(())
    }
}

/// Picks up renewed certificates on every replica, and does due ACME work
/// on whichever replica claims it, every GRUND_TLS_REFRESH_INTERVAL. A
/// failure is logged and tried again next tick; it never stops grund.
pub struct CertificateWork {
    certificates: Certificates,
    interval: Duration,
}

impl CertificateWork {
    pub fn new(state: &State) -> Self {
        Self {
            certificates: state.certificates(),
            interval: state.config.tls.tls_refresh_interval,
        }
    }
}

impl Component for CertificateWork {
    fn info(&self) -> ComponentInfo {
        "grund/certificates".into()
    }

    async fn run(&self, cancellation: CancellationToken) -> Result<(), MadError> {
        if !self.certificates.enabled() {
            cancellation.cancelled().await;
            return Ok(());
        }
        let mut tick = tokio::time::interval(self.interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                _ = tick.tick() => {}
            }
            if let Err(error) = self.certificates.refresh().await {
                tracing::warn!(
                    error = format!("{error:#}"),
                    "https: could not load a renewed certificate; the current one stays served"
                );
            }
            let work = self.certificates.work_once();
            tokio::select! {
                () = cancellation.cancelled() => return Ok(()),
                done = work => if let Err(error) = done {
                    tracing::warn!(error = format!("{error:#}"), "https: certificate work failed; trying again next tick");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_key_opens_only_with_its_key_and_purpose() {
        let key = [7u8; 32];
        let sealed = seal(&key, "grund/tls/certificate-key/instance", b"secret");
        assert_eq!(
            unseal(&key, "grund/tls/certificate-key/instance", &sealed).as_deref(),
            Some(&b"secret"[..])
        );
        assert!(unseal(&[8u8; 32], "grund/tls/certificate-key/instance", &sealed).is_none());
        assert!(unseal(&key, "grund/tls/acme-account/x", &sealed).is_none());
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(unseal(&key, "grund/tls/certificate-key/instance", &tampered).is_none());
        assert!(unseal(&key, "grund/tls/certificate-key/instance", &[]).is_none());
    }

    #[test]
    fn two_seals_of_one_key_differ() {
        let key = [7u8; 32];
        assert_ne!(seal(&key, "a", b"secret"), seal(&key, "a", b"secret"));
    }

    #[test]
    fn a_certificate_is_degraded_near_expiry_and_unhealthy_after() {
        let day = Duration::from_secs(86400);
        let issued = SystemTime::UNIX_EPOCH + day * 1000;
        let expires = issued + day * 90;
        assert_eq!(expiry_status(issued, expires, issued), CheckStatus::Healthy);
        assert_eq!(
            expiry_status(issued, expires, expires - day * 15),
            CheckStatus::Healthy
        );
        assert_eq!(
            expiry_status(issued, expires, expires - day * 13),
            CheckStatus::Degraded
        );
        assert_eq!(
            expiry_status(issued, expires, expires + day),
            CheckStatus::Unhealthy
        );
    }

    #[test]
    fn a_short_lived_certificate_is_degraded_only_in_its_last_third() {
        let issued = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let expires = issued + Duration::from_secs(6 * 86400);
        assert_eq!(
            expiry_status(issued, expires, issued + Duration::from_secs(3 * 86400)),
            CheckStatus::Healthy
        );
        assert_eq!(
            expiry_status(issued, expires, issued + Duration::from_secs(5 * 86400)),
            CheckStatus::Degraded
        );
    }
}
