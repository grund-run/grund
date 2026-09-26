//! The membership list of one private network (network.md §5).
//!
//! grund is the only authority on who is a member. It signs each version of
//! the list with the network's Ed25519 key, and a machine accepts a list only
//! if the signature verifies and its epoch is newer than the one it holds.
//! The signature covers the exact bytes grund sent (`SignedList::body`), so
//! no canonical encoding has to agree between the two ends.
//!
//! Addresses come from the list, never from a key or the machine: the
//! network's prefix is a /48 from `fd00::/8`, each member owns
//! `prefix:slot::/64`, and the machine itself is `prefix:slot::1`. Slot 0 is
//! never a member's (network.md §6.1: reserved for app addresses).

use std::{collections::HashSet, net::Ipv6Addr, str::FromStr};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

/// One version of a private network's membership, as grund signs it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipList {
    /// grund's id of the private network.
    pub network_id: String,
    /// Increases with every change. A machine refuses a list whose epoch is
    /// not newer than the one it holds.
    pub epoch: u64,
    /// The network's /48, written as its first address (`fd12:3456:789a::`).
    pub prefix: Ipv6Addr,
    /// When grund signed this version, in seconds since the Unix epoch.
    pub issued_at: i64,
    /// Every member, in no particular order.
    pub members: Vec<Member>,
}

/// One machine on a private network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// grund's id of the machine.
    pub machine_id: String,
    /// The machine's key, as iroh prints an endpoint id.
    pub endpoint_id: String,
    /// The member's /64 within the network's prefix. Never 0.
    pub slot: u16,
}

/// A membership list as it travels: the bytes grund signed, and the
/// signature over exactly those bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedList {
    /// The list, JSON-encoded, base64 on the wire.
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    /// Ed25519 over `body` by the network's key, base64 on the wire.
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

/// Why a membership list was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MembershipError {
    /// The signature does not verify with the network's key.
    #[error("the signature does not verify with the network's key")]
    BadSignature,
    /// The signed bytes are not a membership list.
    #[error("the signed body is not a membership list: {0}")]
    Malformed(String),
    /// The prefix is not a /48 inside `fd00::/8`.
    #[error("the prefix {0} is not a /48 in fd00::/8")]
    BadPrefix(Ipv6Addr),
    /// A member has slot 0, which is reserved.
    #[error("member {0} has slot 0, which is reserved")]
    ReservedSlot(String),
    /// Two members share a slot.
    #[error("slot {0} is given to two members")]
    DuplicateSlot(u16),
    /// A member's endpoint id does not parse.
    #[error("member {0} has an endpoint id that does not parse")]
    BadEndpointId(String),
    /// Two members share a key.
    #[error("endpoint id {0} is listed twice")]
    DuplicateEndpointId(String),
}

impl SignedList {
    /// Signs `list` with the network's key. grund-server calls this, or
    /// [`SignedList::sign_bytes`] with bytes it encoded itself.
    pub fn sign(list: &MembershipList, network_key: &SigningKey) -> Self {
        let body = serde_json::to_vec(list).expect("a membership list always encodes");
        Self::sign_bytes(body, network_key)
    }

    /// Signs already-encoded list bytes with the network's key.
    pub fn sign_bytes(body: Vec<u8>, network_key: &SigningKey) -> Self {
        let signature = network_key.sign(&body).to_bytes().to_vec();
        Self { body, signature }
    }

    /// Verifies the signature and the list's own rules, and returns the list.
    pub fn verify(&self, network_key: &VerifyingKey) -> Result<MembershipList, MembershipError> {
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| MembershipError::BadSignature)?;
        network_key
            .verify(&self.body, &signature)
            .map_err(|_| MembershipError::BadSignature)?;
        let list: MembershipList = serde_json::from_slice(&self.body)
            .map_err(|e| MembershipError::Malformed(e.to_string()))?;
        list.validate()?;
        Ok(list)
    }
}

impl MembershipList {
    /// Checks the rules every list keeps: a ULA /48 prefix, no slot 0, and no
    /// slot or key given twice.
    pub fn validate(&self) -> Result<(), MembershipError> {
        let p = self.prefix.octets();
        if p[0] != 0xfd || p[6..].iter().any(|b| *b != 0) {
            return Err(MembershipError::BadPrefix(self.prefix));
        }
        let mut slots = HashSet::new();
        let mut keys = HashSet::new();
        for m in &self.members {
            if m.slot == 0 {
                return Err(MembershipError::ReservedSlot(m.machine_id.clone()));
            }
            if !slots.insert(m.slot) {
                return Err(MembershipError::DuplicateSlot(m.slot));
            }
            let id = EndpointId::from_str(&m.endpoint_id)
                .map_err(|_| MembershipError::BadEndpointId(m.machine_id.clone()))?;
            if !keys.insert(id) {
                return Err(MembershipError::DuplicateEndpointId(m.endpoint_id.clone()));
            }
        }
        Ok(())
    }

    /// The machine address of a slot: `prefix:slot::1`.
    pub fn address(&self, slot: u16) -> Ipv6Addr {
        let mut o = self.prefix.octets();
        o[6..8].copy_from_slice(&slot.to_be_bytes());
        o[15] = 1;
        Ipv6Addr::from(o)
    }

    /// The member whose /64 holds `addr`, if any.
    pub fn member_for(&self, addr: Ipv6Addr) -> Option<&Member> {
        let o = addr.octets();
        if o[..6] != self.prefix.octets()[..6] {
            return None;
        }
        let slot = u16::from_be_bytes([o[6], o[7]]);
        self.members.iter().find(|m| m.slot == slot)
    }

    /// The member with this key, if any.
    pub fn member_by_id(&self, id: &EndpointId) -> Option<&Member> {
        self.members
            .iter()
            .find(|m| EndpointId::from_str(&m.endpoint_id).is_ok_and(|e| &e == id))
    }
}

mod b64 {
    use super::*;

    pub fn serialize<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> String {
        crate::key::endpoint_id(&[seed; 32]).to_string()
    }

    fn list() -> MembershipList {
        MembershipList {
            network_id: "net_test".into(),
            epoch: 3,
            prefix: "fd12:3456:789a::".parse().unwrap(),
            issued_at: 1_790_000_000,
            members: vec![
                Member {
                    machine_id: "m_a".into(),
                    endpoint_id: id(1),
                    slot: 1,
                },
                Member {
                    machine_id: "m_b".into(),
                    endpoint_id: id(2),
                    slot: 2,
                },
            ],
        }
    }

    #[test]
    fn a_signed_list_verifies_and_round_trips_through_json() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let signed = SignedList::sign(&list(), &key);
        let wire = serde_json::to_string(&signed).unwrap();
        let back: SignedList = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.verify(&key.verifying_key()), Ok(list()));
    }

    #[test]
    fn another_networks_key_is_refused() {
        let signed = SignedList::sign(&list(), &SigningKey::from_bytes(&[9; 32]));
        let other = SigningKey::from_bytes(&[10; 32]).verifying_key();
        assert_eq!(signed.verify(&other), Err(MembershipError::BadSignature));
    }

    #[test]
    fn a_changed_byte_is_refused() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let mut signed = SignedList::sign(&list(), &key);
        let at = signed.body.len() / 2;
        signed.body[at] ^= 1;
        assert_eq!(
            signed.verify(&key.verifying_key()),
            Err(MembershipError::BadSignature)
        );
    }

    #[test]
    fn slot_zero_and_shared_slots_or_keys_are_refused() {
        let mut l = list();
        l.members[0].slot = 0;
        assert_eq!(
            l.validate(),
            Err(MembershipError::ReservedSlot("m_a".into()))
        );
        let mut l = list();
        l.members[1].slot = 1;
        assert_eq!(l.validate(), Err(MembershipError::DuplicateSlot(1)));
        let mut l = list();
        l.members[1].endpoint_id = id(1);
        assert_eq!(
            l.validate(),
            Err(MembershipError::DuplicateEndpointId(id(1)))
        );
    }

    #[test]
    fn a_prefix_outside_fd00_or_longer_than_48_bits_is_refused() {
        let mut l = list();
        l.prefix = "2001:db8::".parse().unwrap();
        assert!(matches!(l.validate(), Err(MembershipError::BadPrefix(_))));
        l.prefix = "fd12:3456:789a:1::".parse().unwrap();
        assert!(matches!(l.validate(), Err(MembershipError::BadPrefix(_))));
    }

    #[test]
    fn addresses_come_from_the_slot() {
        let l = list();
        assert_eq!(
            l.address(2),
            "fd12:3456:789a:2::1".parse::<Ipv6Addr>().unwrap()
        );
        let inside: Ipv6Addr = "fd12:3456:789a:2::abcd".parse().unwrap();
        assert_eq!(l.member_for(inside).map(|m| m.slot), Some(2));
        let unassigned: Ipv6Addr = "fd12:3456:789a:9::1".parse().unwrap();
        assert!(l.member_for(unassigned).is_none());
        let elsewhere: Ipv6Addr = "fd12:3456:789b:2::1".parse().unwrap();
        assert!(l.member_for(elsewhere).is_none());
    }
}
