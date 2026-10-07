//! What handlers and components ask for, through extension traits on
//! [`crate::state::State`] (skills D-1): `state.accounts()`,
//! `state.sessions()`, `state.limits()`, `state.passwords()`,
//! `state.organisations()`, `state.machines()`.

pub mod accounts;
pub mod agents;
pub mod apps;
pub mod billing;
pub mod capacity;
pub mod device_logins;
pub mod domains;
pub mod entitlements;
pub mod entry;
pub mod insights;
pub mod limits;
pub mod machines;
pub mod mail;
pub mod maintenance;
pub mod networks;
pub mod organisations;
pub mod outbox;
pub mod passwords;
pub mod registry_credentials;
pub mod relays;
pub mod sessions;
pub mod terminators;
pub mod tokens;

pub use accounts::AccountsState;
pub use device_logins::DeviceLoginsState;
pub use domains::DomainsState;
pub use entitlements::EntitlementsState;
pub use limits::LimitsState;
pub use machines::MachinesState;
pub use organisations::OrganisationsState;
pub use passwords::PasswordsState;
pub use registry_credentials::RegistryCredentialsState;
pub use relays::RelaysState;
pub use sessions::SessionsState;
pub use tokens::TokensState;
