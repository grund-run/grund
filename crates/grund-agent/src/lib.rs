//! grund's machine agent: what runs on every machine grund manages, a
//! customer's own hardware and a grund machine alike.
//!
//! `grund join` registers the machine (grund-docs design/machines.md §5): it
//! makes the machine key, calls the instance's `EnrollMachine` with a
//! one-time token, and keeps the identity it is given. `grund agent` then
//! keeps it connected (§7b): heartbeats, its signed desired state, and the
//! VMs that state asks for, through a [`vm::VmRuntime`].

pub mod agent;
pub mod apps;
pub mod backups;
pub mod capture;
pub mod doctor;
pub mod forward;
pub mod gate;
pub mod guest_boot;
pub mod join;
pub mod lease;
pub mod local_bootstrap;
pub mod net;
pub mod policy;
pub mod probe;
pub mod registry_login;
pub mod resolved;
pub mod runtime;
pub mod secrets;
pub mod simulated;
pub mod supervisor;
mod telemetry;
mod telemetry_final;
mod telemetry_spool;
mod telemetry_tail;
mod usage;
pub mod vm;
mod vm_updates;
pub mod volume;
