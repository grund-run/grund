//! grund's API descriptors, shared by code generation and CLI self-description.
#![forbid(unsafe_code)]

pub mod files;

/// Every API message and service, including source comments, as a protobuf
/// `FileDescriptorSet`, without compiling generated messages or services.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/grund.desc"));
