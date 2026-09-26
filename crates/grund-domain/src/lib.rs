//! grund's domain: what an account, an organisation and (later) an app,
//! a machine and a release are, and the pure decisions about them.
//!
//! Nothing in this crate does I/O or reads a clock. Aggregates fold events
//! (`mire::Aggregate::apply`), commands decide (`mire::Command::handle`), and
//! timestamps arrive as fields. The orchestrator and the agent will share
//! these types, which is why they live apart from the server.

pub mod account;
pub mod names;

pub mod organisation;
