//! Accounts: sign-up, email verification, sign-in and password reset. Every
//! decision that could reveal whether an account exists costs the same
//! either way, or is made later by the outbox drain, off the request path.

use std::time::Duration;

use chrono::Utc;
use grund_domain::{
    account::{AccountCommand, PasswordChangeReason, RegistrationMethod},
    names::{self, EmailAddress, Username},
    organisation::OrganisationCommand,
};
use grund_store::{
    accounts::{self, LoginRecord, Lookup, Viewer},
    outbox::{self, Kind},
    sessions,
    tokens::{self, Purpose},
    work::{Work, WorkError},
};
use uuid::Uuid;

use crate::{
    crypto,
    services::{
        limits::{Limits, LimitsState},
        outbox::wake,
        passwords::{Passwords, PasswordsState},
    },
    state::State,
};

/// How long an email-verification link is valid.
pub const VERIFY_LINK_TTL: Duration = Duration::from_secs(24 * 3600);

/// Who is asking, for limits, logs and event metadata.
#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub request_id: Uuid,
    pub address: String,
}

/// A sign-up form as submitted.
#[derive(Debug, Clone, Default)]
pub struct SignupForm {
    pub username: String,
    pub email: String,
    pub password: String,
}

/// Messages for the fields of a form, shown next to them.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FieldErrors {
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
}

impl FieldErrors {
    pub fn is_empty(&self) -> bool {
        self.username.is_none() && self.email.is_none() && self.password.is_none()
    }
}

/// How a sign-up ended.
#[derive(Debug)]
pub enum SignupOutcome {
    /// A link was sent to this address, or (when it already has an account)
    /// a note saying so. The two are answered identically.
    Sent {
        email: String,
    },
    Invalid(FieldErrors),
    Closed,
    RateLimited,
}

/// How a sign-in ended.
#[derive(Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    SignedIn {
        account_id: Uuid,
    },
    /// Unknown account and wrong password: one outcome.
    Invalid,
    Locked,
    /// The password was right but the address is not confirmed; a new link
    /// was sent (if the mail limit allows).
    Unverified,
    RateLimited,
}

/// How a reset request ended. `Sent` whether or not an account exists.
#[derive(Debug, PartialEq, Eq)]
pub enum ResetRequestOutcome {
    Sent,
    Invalid(String),
    RateLimited,
}

/// How setting a new password through a reset link ended.
#[derive(Debug, PartialEq, Eq)]
pub enum ResetOutcome {
    Done,
    Expired,
    Invalid(String),
}

/// Account flows.
#[derive(Clone)]
pub struct Accounts {
    state: State,
    passwords: Passwords,
    limits: Limits,
}

impl Accounts {
    fn link(&self, path_and_query: &str) -> String {
        format!(
            "{}{path_and_query}",
            self.state.config.public_origin().serialized
        )
    }

    /// Creates an account, its personal organisation and a verification link.
    pub async fn sign_up(
        &self,
        form: SignupForm,
        meta: &RequestMeta,
    ) -> anyhow::Result<SignupOutcome> {
        if !self.state.config.signup_enabled {
            return Ok(SignupOutcome::Closed);
        }
        if !self.limits.admit_mail_address(&meta.address).await? {
            return Ok(SignupOutcome::RateLimited);
        }
        let mut errors = FieldErrors::default();
        let username = Username::parse(&form.username)
            .map_err(|e| errors.username = Some(sentence(e)))
            .ok();
        let email = EmailAddress::parse(&form.email)
            .map_err(|e| errors.email = Some(sentence(e)))
            .ok();
        if let Err(error) =
            names::check_new_password(&form.password, username.as_ref(), email.as_ref())
        {
            errors.password = Some(sentence(error));
        }
        if let Some(name) = &username
            && accounts::username_taken(&self.state.pool, name.as_str()).await?
        {
            errors.username = Some(TAKEN.into());
        }
        let (Some(username), Some(email)) = (username, email) else {
            return Ok(SignupOutcome::Invalid(errors));
        };
        if !errors.is_empty() {
            return Ok(SignupOutcome::Invalid(errors));
        }

        let phc = self.passwords.hash(&form.password).await?;
        let sent = SignupOutcome::Sent {
            email: email.as_str().to_string(),
        };

        if accounts::login_record(&self.state.pool, Lookup::Email(email.normalized()))
            .await?
            .is_some()
        {
            self.note_existing(&email).await?;
            return Ok(sent);
        }

        match self.create(&username, &email, &phc, meta).await {
            Ok(()) => Ok(sent),
            Err(error) => match error.unique_violation().as_deref() {
                Some("grund_accounts_username_idx" | "grund_organisations_slug_idx") => {
                    Ok(SignupOutcome::Invalid(FieldErrors {
                        username: Some(TAKEN.into()),
                        ..Default::default()
                    }))
                }
                Some("grund_account_emails_normalized_idx") => {
                    self.note_existing(&email).await?;
                    Ok(sent)
                }
                _ => Err(error.into()),
            },
        }
    }

    async fn create(
        &self,
        username: &Username,
        email: &EmailAddress,
        phc: &str,
        meta: &RequestMeta,
    ) -> Result<(), WorkError> {
        let account_id = Uuid::now_v7();
        let organisation_id = Uuid::now_v7();
        let now = Utc::now();
        let mail_allowed = self.limits.admit_mail_to(email.normalized()).await?;
        let mut work = Work::begin(&self.state.events, meta.request_id, "signup").await?;
        work.account(
            account_id,
            AccountCommand::Register {
                username: username.clone(),
                organisation_id,
                method: RegistrationMethod::Password,
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
        accounts::set_password(work.sql(), account_id, phc).await?;
        if mail_allowed {
            self.queue_verification(
                work.sql(),
                account_id,
                username.as_str(),
                email.as_str(),
                email.normalized(),
            )
            .await?;
        }
        work.commit().await?;
        tracing::info!(%account_id, "account created");
        wake(&self.state).await;
        Ok(())
    }

    async fn queue_verification(
        &self,
        connection: &mut sqlx::PgConnection,
        account_id: Uuid,
        username: &str,
        email: &str,
        normalized: &str,
    ) -> Result<(), sqlx::Error> {
        let token = crypto::random_token();
        tokens::issue(
            connection,
            &crypto::digest(&token),
            Purpose::VerifyEmail,
            account_id,
            normalized,
            VERIFY_LINK_TTL,
        )
        .await?;
        let payload = serde_json::json!({ "username": username, "link": self.link(&format!("/verify?token={token}")) });
        outbox::enqueue(
            connection,
            Uuid::now_v7(),
            Kind::VerifyEmailMail,
            email,
            &payload,
        )
        .await
    }

    async fn note_existing(&self, email: &EmailAddress) -> anyhow::Result<()> {
        if !self.limits.admit_mail_to(email.normalized()).await? {
            return Ok(());
        }
        let payload = serde_json::json!({ "login_link": self.link("/login"), "reset_link": self.link("/reset") });
        let mut tx = self.state.pool.begin().await?;
        outbox::enqueue(
            &mut tx,
            Uuid::now_v7(),
            Kind::SignupExistingMail,
            email.as_str(),
            &payload,
        )
        .await?;
        tx.commit().await?;
        wake(&self.state).await;
        Ok(())
    }

    /// Whether a verification link is still good (for the page it opens).
    pub async fn verification_is_valid(&self, token: &str) -> anyhow::Result<bool> {
        Ok(tokens::peek(
            &self.state.pool,
            &crypto::digest(token),
            Purpose::VerifyEmail,
        )
        .await?
        .is_some())
    }

    /// Uses a verification link. `false` when it is unknown, used or expired.
    pub async fn verify_email(&self, token: &str, meta: &RequestMeta) -> anyhow::Result<bool> {
        let mut work = Work::begin(&self.state.events, meta.request_id, "verify-email").await?;
        let Some(redeemed) =
            tokens::redeem(work.sql(), &crypto::digest(token), Purpose::VerifyEmail).await?
        else {
            return Ok(false);
        };
        work.account(
            redeemed.account_id,
            AccountCommand::VerifyEmail {
                email_digest: crypto::email_digest(&redeemed.email_normalized),
                at: Utc::now(),
            },
        )
        .await?;
        work.commit().await?;
        tracing::info!(account_id = %redeemed.account_id, "email verified");
        Ok(true)
    }

    /// Checks a sign-in. Unknown account and wrong password do the same work
    /// and give the same answer.
    pub async fn log_in(
        &self,
        login: &str,
        password: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<LoginOutcome> {
        let name = login.trim().to_lowercase();
        if !self.limits.admit_login_address(&meta.address).await? {
            return Ok(LoginOutcome::RateLimited);
        }
        if self.limits.login_locked(&name).await? {
            return Ok(LoginOutcome::Locked);
        }
        if name.is_empty() || password.is_empty() || password.len() > names::PASSWORD_MAX_BYTES {
            self.limits.login_failed(&name).await?;
            return Ok(LoginOutcome::Invalid);
        }
        let lookup = if name.contains('@') {
            Lookup::Email(&name)
        } else {
            Lookup::Username(&name)
        };
        let record = accounts::login_record(&self.state.pool, lookup).await?;
        let verified = self
            .passwords
            .verify(password, record.as_ref().and_then(|r| r.phc.as_deref()))
            .await?;
        let (true, Some(record)) = (verified.matches, record) else {
            self.limits.login_failed(&name).await?;
            return Ok(LoginOutcome::Invalid);
        };
        self.limits.login_succeeded(&name).await?;
        if verified.needs_rehash
            && let Some(old) = &record.phc
        {
            let new = self.passwords.hash(password).await?;
            accounts::upgrade_password(&self.state.pool, record.account_id, old, &new).await?;
        }
        if !record.email_verified {
            self.resend_verification(&record).await?;
            return Ok(LoginOutcome::Unverified);
        }
        Ok(LoginOutcome::SignedIn {
            account_id: record.account_id,
        })
    }

    async fn resend_verification(&self, record: &LoginRecord) -> anyhow::Result<()> {
        if !self.limits.admit_mail_to(&record.email_normalized).await? {
            return Ok(());
        }
        let mut tx = self.state.pool.begin().await?;
        self.queue_verification(
            &mut tx,
            record.account_id,
            &record.username,
            &record.email,
            &record.email_normalized,
        )
        .await?;
        tx.commit().await?;
        wake(&self.state).await;
        Ok(())
    }

    /// Records that someone asked for a reset link. Never looks the address
    /// up: the drain does that later, and sends nothing if no account has it.
    pub async fn request_reset(
        &self,
        email: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<ResetRequestOutcome> {
        if !self.limits.admit_mail_address(&meta.address).await? {
            return Ok(ResetRequestOutcome::RateLimited);
        }
        let email = match EmailAddress::parse(email) {
            Ok(email) => email,
            Err(error) => return Ok(ResetRequestOutcome::Invalid(sentence(error))),
        };
        if self.limits.admit_mail_to(email.normalized()).await? {
            let mut tx = self.state.pool.begin().await?;
            outbox::enqueue(
                &mut tx,
                Uuid::now_v7(),
                Kind::PasswordResetRequested,
                email.normalized(),
                &serde_json::json!({}),
            )
            .await?;
            tx.commit().await?;
            wake(&self.state).await;
        }
        Ok(ResetRequestOutcome::Sent)
    }

    /// Whether a reset link is still good (for the page it opens).
    pub async fn reset_is_valid(&self, token: &str) -> anyhow::Result<bool> {
        Ok(tokens::peek(
            &self.state.pool,
            &crypto::digest(token),
            Purpose::ResetPassword,
        )
        .await?
        .is_some())
    }

    /// Sets a new password through a reset link: the link is used, the address
    /// counts as verified (the link proved the mailbox), and every session of
    /// the account ends.
    pub async fn reset_password(
        &self,
        token: &str,
        password: &str,
        meta: &RequestMeta,
    ) -> anyhow::Result<ResetOutcome> {
        let digest = crypto::digest(token);
        let Some(pending) = tokens::peek(&self.state.pool, &digest, Purpose::ResetPassword).await?
        else {
            return Ok(ResetOutcome::Expired);
        };
        let Some(record) =
            accounts::login_record_by_id(&self.state.pool, pending.account_id).await?
        else {
            return Ok(ResetOutcome::Expired);
        };
        let username = Username::parse(&record.username).ok();
        let email = EmailAddress::parse(&record.email).ok();
        if let Err(error) = names::check_new_password(password, username.as_ref(), email.as_ref()) {
            return Ok(ResetOutcome::Invalid(sentence(error)));
        }
        let phc = self.passwords.hash(password).await?;

        let mut work = Work::begin(&self.state.events, meta.request_id, "password-reset").await?;
        let Some(redeemed) = tokens::redeem(work.sql(), &digest, Purpose::ResetPassword).await?
        else {
            return Ok(ResetOutcome::Expired);
        };
        accounts::set_password(work.sql(), redeemed.account_id, &phc).await?;
        let now = Utc::now();
        work.account(
            redeemed.account_id,
            AccountCommand::VerifyEmail {
                email_digest: crypto::email_digest(&redeemed.email_normalized),
                at: now,
            },
        )
        .await?;
        work.account(
            redeemed.account_id,
            AccountCommand::ChangePassword {
                reason: PasswordChangeReason::Reset,
                at: now,
            },
        )
        .await?;
        let ended =
            sessions::revoke_all_except(&mut **work.sql(), redeemed.account_id, None).await?;
        work.commit().await?;
        tracing::info!(account_id = %redeemed.account_id, sessions_ended = ended, "password reset");
        Ok(ResetOutcome::Done)
    }

    /// The signed-in person.
    pub async fn viewer(&self, account_id: Uuid) -> anyhow::Result<Option<Viewer>> {
        let mut connection = self.state.pool.acquire().await?;
        Ok(accounts::viewer(&mut connection, account_id).await?)
    }
}

const TAKEN: &str = "That username is taken.";

fn sentence(error: impl std::fmt::Display) -> String {
    let text = error.to_string();
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str()),
        None => text,
    }
}

/// Access to [`Accounts`] from [`State`].
pub trait AccountsState {
    fn accounts(&self) -> Accounts;
}

impl AccountsState for State {
    fn accounts(&self) -> Accounts {
        Accounts {
            state: self.clone(),
            passwords: self.passwords(),
            limits: self.limits(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_messages_read_as_sentences() {
        assert_eq!(
            sentence("use at least 12 characters"),
            "Use at least 12 characters."
        );
    }
}
