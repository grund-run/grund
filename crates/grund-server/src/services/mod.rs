//! What handlers and components ask for, through extension traits on
//! [`crate::state::State`] (skills D-1): `state.accounts()`,
//! `state.sessions()`, `state.limits()`, `state.passwords()`,
//! `state.organisations()`, `state.machines()`.

pub mod accounts;
pub mod billing;
pub mod capacity;
pub mod entitlements;
pub mod insights;
pub mod limits;
pub mod machines;
pub mod mail;
pub mod maintenance;
pub mod organisations;
pub mod outbox;
pub mod passwords;
pub mod sessions;

pub use accounts::AccountsState;
pub use entitlements::EntitlementsState;
pub use limits::LimitsState;
pub use machines::MachinesState;
pub use organisations::OrganisationsState;
pub use passwords::PasswordsState;
pub use sessions::SessionsState;
