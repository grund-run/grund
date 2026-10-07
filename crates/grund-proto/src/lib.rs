//! grund's API contract, generated from `proto/` at build time: message
//! types, the service traits servers implement, and (with the `client`
//! feature) clients for the CLI and agent.
#![forbid(unsafe_code)]

connectrpc::include_generated!();

/// Every message and service above, with their comments, as a protobuf
/// `FileDescriptorSet`: what the CLI generates its JSON Schemas and
/// self-description from.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/grund.desc"));
