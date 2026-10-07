//! Device logins (grund-docs design/cli.md §2): `grund login` asks for one,
//! the person approves it on `/device` with their browser session, and the
//! CLI's next poll turns it into a CLI session, once.
//!
//! The device code is the CLI's secret and only its SHA-256 is stored. The
//! user code is eight consonants, for the person to compare with what their
//! terminal shows; it is not a credential (approving needs a session, and a
//! code only names a login that the CLI already holds the device code of).

use std::time::Duration;

use grund_store::device_logins::{self, NewLogin, PendingLogin};
use uuid::Uuid;

use crate::{
    crypto,
    services::sessions::{Client, SessionsState},
    state::State,
};

/// How long a login waits for approval.
pub const TTL: Duration = Duration::from_secs(600);

/// How often the CLI may poll.
pub const INTERVAL: Duration = Duration::from_secs(5);

/// The longest client or host description accepted, in characters.
pub const MAX_LABEL_CHARS: usize = 100;

const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

/// A login just started: what the CLI shows and keeps.
#[derive(Debug)]
pub struct Started {
    pub device_code: String,
    pub user_code: String,
}

/// What a poll found.
#[derive(Debug)]
pub enum Polled {
    Pending,
    SlowDown,
    Approved { token: String, account_id: Uuid },
    Denied,
    Expired,
    NotFound,
}

/// A user code as typed: letters only, upper case, so `bcdf-ghjk` and
/// `BCDFGHJK` name the same login. `None` when it cannot be one.
pub fn normalize_user_code(text: &str) -> Option<String> {
    let code: String = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (code.len() == 8 && code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b))).then_some(code)
}

/// A user code as shown: `XXXX-XXXX`.
pub fn display_user_code(code: &str) -> String {
    if code.len() == 8 {
        format!("{}-{}", &code[..4], &code[4..])
    } else {
        code.to_string()
    }
}

fn label(text: &str) -> String {
    let text: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_LABEL_CHARS)
        .collect();
    let text = text.trim().to_string();
    if text.is_empty() {
        "unknown".into()
    } else {
        text
    }
}

fn random_user_code() -> String {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    bytes
        .iter()
        .map(|b| USER_CODE_ALPHABET[usize::from(*b) % USER_CODE_ALPHABET.len()] as char)
        .collect()
}

/// Starts, finds, approves and polls device logins.
#[derive(Clone)]
pub struct DeviceLogins {
    state: State,
}

impl DeviceLogins {
    /// Starts a login for `client` on `host`, asked from `address`.
    pub async fn start(&self, client: &str, host: &str, address: &str) -> anyhow::Result<Started> {
        let (client, host) = (label(client), label(host));
        let device_code = crypto::random_base62();
        let digest = crypto::digest(&device_code);
        for _ in 0..5 {
            let user_code = random_user_code();
            let stored = device_logins::insert(
                &self.state.pool,
                NewLogin {
                    login_id: Uuid::now_v7(),
                    device_code_digest: &digest,
                    user_code: &user_code,
                    client: &client,
                    host: &host,
                    client_address: &address.chars().take(64).collect::<String>(),
                    ttl: TTL,
                },
            )
            .await?;
            if stored {
                tracing::info!(client = %client, host = %host, "device login started");
                return Ok(Started {
                    device_code,
                    user_code,
                });
            }
        }
        anyhow::bail!("no free user code after five draws")
    }

    /// The pending login a user code names, for the approval page.
    pub async fn pending(&self, user_code: &str) -> anyhow::Result<Option<PendingLogin>> {
        let Some(code) = normalize_user_code(user_code) else {
            return Ok(None);
        };
        Ok(device_logins::pending(&self.state.pool, &code).await?)
    }

    /// Approves a pending login for the signed-in `account_id`.
    pub async fn approve(&self, login_id: Uuid, account_id: Uuid) -> anyhow::Result<bool> {
        let approved = device_logins::approve(&self.state.pool, login_id, account_id).await?;
        if approved {
            tracing::info!(login = %login_id, account = %account_id, "device login approved");
        }
        Ok(approved)
    }

    /// Denies a pending login.
    pub async fn deny(&self, login_id: Uuid) -> anyhow::Result<bool> {
        Ok(device_logins::deny(&self.state.pool, login_id).await?)
    }

    /// Polls a login by its device code. The first poll after approval
    /// mints the CLI session in the same transaction that uses the login
    /// up, so its secret is handed out once.
    pub async fn poll(&self, device_code: &str, address: &str) -> anyhow::Result<Polled> {
        if device_code.len() != crypto::BASE62_32_BYTES
            || !device_code.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Ok(Polled::NotFound);
        }
        let mut tx = self.state.pool.begin().await?;
        let Some(login) =
            device_logins::poll(&mut tx, &crypto::digest(device_code), INTERVAL.mul_f32(0.8))
                .await?
        else {
            return Ok(Polled::NotFound);
        };
        let outcome = if login.used || login.expired {
            Polled::Expired
        } else if login.denied {
            Polled::Denied
        } else if let Some(account_id) = login.approved_by {
            let (token, session) = self
                .state
                .sessions()
                .start_cli(
                    &mut tx,
                    account_id,
                    &Client {
                        user_agent: format!("{} on {}", login.client, login.host),
                        address: address.to_string(),
                    },
                )
                .await?;
            device_logins::use_up(&mut tx, login.login_id, session.session_id).await?;
            tracing::info!(
                login = %login.login_id,
                session = %session.session_id,
                account = %account_id,
                "device login became a CLI session"
            );
            Polled::Approved { token, account_id }
        } else if login.polled_within {
            Polled::SlowDown
        } else {
            Polled::Pending
        };
        tx.commit().await?;
        Ok(outcome)
    }
}

/// Access to [`DeviceLogins`] from [`State`].
pub trait DeviceLoginsState {
    fn device_logins(&self) -> DeviceLogins;
}

impl DeviceLoginsState for State {
    fn device_logins(&self) -> DeviceLogins {
        DeviceLogins {
            state: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_user_code_is_read_however_it_is_typed_and_shown_in_two_halves() {
        assert_eq!(
            normalize_user_code("bcdf-ghjk").as_deref(),
            Some("BCDFGHJK")
        );
        assert_eq!(
            normalize_user_code(" BCDF GHJK ").as_deref(),
            Some("BCDFGHJK")
        );
        assert_eq!(normalize_user_code("BCDFGHJ"), None);
        assert_eq!(normalize_user_code("ABCDEFGH"), None);
        assert_eq!(display_user_code("BCDFGHJK"), "BCDF-GHJK");
    }

    #[test]
    fn user_codes_use_only_the_alphabet() {
        for _ in 0..100 {
            let code = random_user_code();
            assert!(normalize_user_code(&code).is_some(), "{code}");
        }
    }
}
