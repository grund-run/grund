//! grund's machine agent: what runs on every machine grund manages, a
//! customer's own hardware and a grund machine alike.
//!
//! `grund join` registers the machine (grund-docs design/machines.md §5): it
//! makes the machine key, calls the instance's `EnrollMachine` with a
//! one-time token, and keeps the identity it is given. `grund agent` then
//! keeps it connected (§7b): heartbeats, its signed desired state, and the
//! VMs that state asks for, through a [`vm::VmRuntime`].

pub mod agent;
pub mod join;
pub mod net;
pub mod vm;
