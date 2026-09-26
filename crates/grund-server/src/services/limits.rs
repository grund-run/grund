//! Rate limits and lockout, on `grund_throttle`.
//! Counted values (account names, addresses, client addresses) are keyed by
//! an HMAC with the instance's throttle subkey, so the table holds none of
//! them in the clear.

use std::time::Duration;

use grund_store::throttle::{self, Scope};

use crate::{crypto, state::State};

/// The sign-in window: failures and attempts are counted per 15 minutes.
pub const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);
/// The mail window: requests are counted per hour.
pub const MAIL_WINDOW: Duration = Duration::from_secs(3600);

/// The instance's limits.
#[derive(Clone)]
pub struct Limits {
    pool: sqlx::PgPool,
    key: [u8; 32],
    login_failures: u32,
    login_attempts_per_address: u32,
    mail_per_email: u32,
    mail_per_address: u32,
}

impl Limits {
    fn key(&self, scope: Scope, value: &str) -> [u8; 32] {
        crypto::hmac(&self.key, &[scope.as_str().as_bytes(), value.as_bytes()])
    }

    /// Whether this account name has failed too often in this window. Names
    /// that do not exist are counted like any other.
    pub async fn login_locked(&self, name: &str) -> Result<bool, sqlx::Error> {
        let key = self.key(Scope::LoginFailure, name);
        let failures = throttle::count(&self.pool, Scope::LoginFailure, &key, LOGIN_WINDOW).await?;
        Ok(failures >= self.login_failures as i32)
    }

    /// Counts a failed sign-in for this account name.
    pub async fn login_failed(&self, name: &str) -> Result<(), sqlx::Error> {
        let key = self.key(Scope::LoginFailure, name);
        throttle::hit(&self.pool, Scope::LoginFailure, &key, LOGIN_WINDOW).await?;
        Ok(())
    }

    /// Forgets the failures of a name that just signed in.
    pub async fn login_succeeded(&self, name: &str) -> Result<(), sqlx::Error> {
        throttle::clear(
            &self.pool,
            Scope::LoginFailure,
            &self.key(Scope::LoginFailure, name),
        )
        .await
    }

    /// Counts a sign-in attempt from `address`; `false` when over the limit.
    /// Always `true` when the per-address limit is off.
    pub async fn admit_login_address(&self, address: &str) -> Result<bool, sqlx::Error> {
        self.admit(
            Scope::LoginAddress,
            address,
            self.login_attempts_per_address,
            LOGIN_WINDOW,
        )
        .await
    }

    /// Counts a sign-up, reset or resend request from `address`.
    pub async fn admit_mail_address(&self, address: &str) -> Result<bool, sqlx::Error> {
        self.admit(
            Scope::MailAddress,
            address,
            self.mail_per_address,
            MAIL_WINDOW,
        )
        .await
    }

    /// Counts a mail to `email` (normalised); `false` when this address has had
    /// its share this hour, in which case nothing is sent.
    pub async fn admit_mail_to(&self, email: &str) -> Result<bool, sqlx::Error> {
        self.admit(Scope::MailEmail, email, self.mail_per_email, MAIL_WINDOW)
            .await
    }

    async fn admit(
        &self,
        scope: Scope,
        value: &str,
        limit: u32,
        window: Duration,
    ) -> Result<bool, sqlx::Error> {
        if limit == 0 {
            return Ok(true);
        }
        let hits = throttle::hit(&self.pool, scope, &self.key(scope, value), window).await?;
        Ok(hits <= limit as i32)
    }
}

/// Access to [`Limits`] from [`State`].
pub trait LimitsState {
    fn limits(&self) -> Limits;
}

impl LimitsState for State {
    fn limits(&self) -> Limits {
        Limits {
            pool: self.pool.clone(),
            key: self.secret.derive("throttle"),
            login_failures: self.config.login_failures_per_account,
            login_attempts_per_address: self.config.login_attempts_per_address,
            mail_per_email: self.config.mail_requests_per_email,
            mail_per_address: self.config.mail_requests_per_address,
        }
    }
}
