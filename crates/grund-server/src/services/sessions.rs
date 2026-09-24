//! Dashboard sessions (docs/design/auth.md §3): an opaque token in the
//! cookie, only its SHA-256 in PostgreSQL, rotated at every sign-in.

use std::time::Duration;

use grund_store::sessions::{self, LiveSession, NewSession, SessionView};
use uuid::Uuid;

use crate::{crypto, state::State};

/// A signed-in request's session.
#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: Uuid,
    pub account_id: Uuid,
}

/// Where a sign-in came from, as shown on the sessions page.
#[derive(Debug, Clone, Default)]
pub struct Client {
    pub user_agent: String,
    pub address: String,
}

/// Starts, finds, lists and ends sessions.
#[derive(Clone)]
pub struct Sessions {
    pool: sqlx::PgPool,
    idle: Duration,
    max_age: Duration,
}

impl Sessions {
    /// Mints a session for `account_id` and returns its token (for the
    /// cookie). The session the browser presented before, if any, is revoked:
    /// a sign-in never keeps a token that existed before it.
    pub async fn start(
        &self,
        account_id: Uuid,
        previous_token: Option<&str>,
        client: &Client,
    ) -> Result<(String, Session), sqlx::Error> {
        let token = crypto::random_token();
        let digest = crypto::digest(&token);
        let session_id = Uuid::now_v7();
        let mut tx = self.pool.begin().await?;
        if let Some(previous) = previous_token {
            sessions::revoke_by_token(&mut *tx, &crypto::digest(previous)).await?;
        }
        sessions::insert(
            &mut tx,
            NewSession {
                session_id,
                token_digest: &digest,
                account_id,
                max_age: self.max_age,
                user_agent: &client.user_agent,
                client_address: &client.address,
            },
        )
        .await?;
        tx.commit().await?;
        Ok((
            token,
            Session {
                session_id,
                account_id,
            },
        ))
    }

    /// The live session a cookie token names, noting the activity.
    pub async fn authenticate(&self, token: &str) -> Result<Option<Session>, sqlx::Error> {
        let Some(LiveSession {
            session_id,
            account_id,
            ..
        }) = sessions::find(&self.pool, &crypto::digest(token), self.idle).await?
        else {
            return Ok(None);
        };
        sessions::touch(&self.pool, session_id).await?;
        Ok(Some(Session {
            session_id,
            account_id,
        }))
    }

    /// The account's live sessions, newest first.
    pub async fn list(&self, account_id: Uuid) -> Result<Vec<SessionView>, sqlx::Error> {
        sessions::list(&self.pool, account_id, self.idle).await
    }

    /// Ends one of the account's sessions; `false` if it has no such session.
    pub async fn revoke(&self, account_id: Uuid, session_id: Uuid) -> Result<bool, sqlx::Error> {
        sessions::revoke(&self.pool, account_id, session_id).await
    }

    /// Ends every session of the account except `keep`.
    pub async fn revoke_others(&self, account_id: Uuid, keep: Uuid) -> Result<u64, sqlx::Error> {
        sessions::revoke_all_except(&self.pool, account_id, Some(keep)).await
    }

    /// Ends the session a token names (sign-out).
    pub async fn end(&self, token: &str) -> Result<(), sqlx::Error> {
        sessions::revoke_by_token(&self.pool, &crypto::digest(token)).await
    }

    /// How long a session may live, for the cookie's Max-Age.
    pub fn max_age(&self) -> Duration {
        self.max_age
    }
}

/// Access to [`Sessions`] from [`State`].
pub trait SessionsState {
    fn sessions(&self) -> Sessions;
}

impl SessionsState for State {
    fn sessions(&self) -> Sessions {
        Sessions {
            pool: self.pool.clone(),
            idle: self.config.session_idle_timeout,
            max_age: self.config.session_max_age,
        }
    }
}
