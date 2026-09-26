//! grund's machine agent: what runs on every machine grund manages, a
//! customer's own hardware and a grund machine alike.
//!
//! Today it registers the machine (`grund join`, grund-docs
//! design/machines.md §5): it makes the machine key, calls the instance's
//! `EnrollMachine` with a one-time token, and keeps the identity it is given.
//! The control link, desired state and the runtime come later.

pub mod join;
pub mod vm;
