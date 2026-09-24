//! What handlers and components ask for, through extension traits on
//! [`crate::state::State`] (skills D-1): `state.accounts()`,
//! `state.sessions()`, `state.limits()`, `state.passwords()`.

pub mod accounts;
pub mod entitlements;
pub mod limits;
pub mod mail;
pub mod maintenance;
pub mod outbox;
pub mod passwords;
pub mod sessions;

pub use accounts::AccountsState;
pub use entitlements::EntitlementsState;
pub use limits::LimitsState;
pub use passwords::PasswordsState;
pub use sessions::SessionsState;
