//! grund's network layer: the base of network.md (grund/fleet
//! `docs/design/network.md`, §14.1).
//!
//! - [`key`]: the machine key `grund join` makes is the machine's iroh key,
//!   so one Ed25519 key proves who a machine is to grund, to the relay and to
//!   its peers.
//! - [`endpoint`]: grund's policy for an iroh endpoint: grund's own relays
//!   and no n0 service, the short path timeouts that make a moved machine
//!   recover in seconds, and only uplink addresses offered to peers.
//! - [`relay`]: the relay (the "lighthouse" every machine reaches from behind
//!   its NAT), served inside an HTTP server beside other routes, with an
//!   access check, plus QUIC address discovery, which hole punching needs.
//! - [`membership`]: the signed list of a private network's members. grund
//!   signs it; machines verify it and never allocate anything themselves.
//! - [`mesh`]: the private network itself: IPv6 packets from the `grund0`
//!   TUN device to members, one QUIC datagram each, or two when a packet does
//!   not fit the path, with the inbound filter that refuses non-members and
//!   spoofed sources.
//!
//! How membership lists reach a machine is not this crate's concern: the
//! mesh takes a stream of verified lists, today from the HTTPS control link.

pub mod endpoint;
pub mod frame;
pub mod key;
pub mod membership;
pub mod mesh;
pub mod relay;
pub mod tun;

/// The ALPN of the private network's connections between members.
pub const NET_ALPN: &[u8] = b"grund/net/1";
