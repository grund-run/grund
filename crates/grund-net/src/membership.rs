//! The membership list of one private network (network.md §5).
//!
//! grund is the only authority on who is a member. It signs each version of
//! the list with the network's Ed25519 key, and a machine accepts a list only
//! if the signature verifies and its epoch is newer than the one it holds.
//! The signature covers [`SIGNING_PREFIX`] followed by the exact bytes grund
//! sent (`SignedList::body`), so no canonical encoding has to agree between
//! the two ends, and nothing else the network key might ever sign can be
//! read as a membership list. The body is `serde_json` of
//! [`MembershipList`] ([`MembershipList::encode`]).
//!
//! Addresses come from the list, never from a key or the machine: the
//! network's prefix is a /48 from `fd00::/8`, each member owns
//! `prefix:slot::/64`, and the machine itself is `prefix:slot::1`. Slot 0 is
//! never a member's (network.md §6.1: reserved for app addresses).
//!
//! Each member also lists the app replicas grund placed on it
//! ([`Member::apps`]): each has its own address in the member's /64
//! ([`replica_address`]) and the ports its app declares, which are all a
//! peer may reach on it ([`crate::filter`]).

use std::{collections::HashSet, net::Ipv6Addr, str::FromStr};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What every membership signature covers before the body: grund's domain
/// separation for this kind of message (grund-server `keys.rs`,
/// `sign(key_id, prefix, payload)`; grund-docs machines.md §4).
pub const SIGNING_PREFIX: &[u8] = b"grund-net-membership-v1\n";

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
    /// grund's relays, every one a member may use. It travels in the list,
    /// signed, so adding a relay (a region) reaches every machine at its
    /// next epoch, with no re-join. Lists signed before relays were carried
    /// have none; a machine then uses the relays it was told at join.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relays: Vec<Relay>,
}

/// One of grund's relays, as the list names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relay {
    /// Where machines reach it: `https://relay.example.com`.
    pub url: String,
    /// Where it runs, for choosing among relays later. Not used yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
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
    /// The machine's name in its pool, a DNS label: it answers as
    /// `<name>.machines.grund.internal` ([`crate::dns`]). Lists signed
    /// before names were carried have none, and encode as they did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What the machine accepts from the other members: nothing else gets
    /// in ([`crate::filter`]). Empty, or absent in older lists, is closed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<Port>,
    /// The relay the member is homed on, one of [`MembershipList::relays`],
    /// as its agent last reported it: peers dial it through this one relay
    /// rather than all of them. Absent when it reported none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// The app replicas grund placed on the machine that are running (not
    /// draining). Lists signed before apps had networks have none, and encode
    /// as they did.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub apps: Vec<AppReplica>,
}

/// One replica of an app, as the list names it on its member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppReplica {
    /// The app's name, a DNS label: `<app>.grund.internal` answers with the
    /// addresses of its ready replicas ([`crate::dns`]).
    pub app: String,
    /// grund's id of the replica, as it prints it (lowercase, hyphenated).
    pub replica_id: String,
    /// The replica's own address: [`replica_address`] of its member's slot.
    pub address: Ipv6Addr,
    /// What other members and replicas may reach on it; nothing else gets
    /// in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<Port>,
    /// Whether its machine last reported it ready.
    #[serde(default)]
    pub ready: bool,
}

/// The most ports one replica may accept, as apps.md §15 allows an app.
pub const MAX_APP_PORTS: usize = 16;

/// What a replica address's interface identifier is hashed under.
pub const REPLICA_ADDRESS_PREFIX: &[u8] = b"grund-replica-address-v1\n";

/// The address of replica `replica_id` on the member at `slot` of the
/// network `prefix`: `prefix:slot:` and the first 64 bits of SHA-256 of
/// [`REPLICA_ADDRESS_PREFIX`] and the id (apps.md §12.2). It depends only on
/// the replica, so the instance knows it without asking and a restart keeps
/// it. An identifier at or below `0xffff` would land beside the machine's
/// `::1` and the stub's `::53`, so it is moved above them.
pub fn replica_address(prefix: Ipv6Addr, slot: u16, replica_id: &str) -> Ipv6Addr {
    let digest = Sha256::new()
        .chain_update(REPLICA_ADDRESS_PREFIX)
        .chain_update(replica_id.as_bytes())
        .finalize();
    let mut iid = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes"));
    if iid <= 0xffff {
        iid |= 0x8000_0000_0000_0000;
    }
    let mut o = prefix.octets();
    o[6..8].copy_from_slice(&slot.to_be_bytes());
    o[8..].copy_from_slice(&iid.to_be_bytes());
    Ipv6Addr::from(o)
}

/// A transport of a declared port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

/// A port a member accepts connections on from the other members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Port {
    pub transport: Transport,
    pub port: u16,
}

/// The most ports a member may declare, as grund allows.
pub const MAX_PORTS: usize = 64;

/// A membership list as it travels: the list's bytes, and the signature over
/// [`SIGNING_PREFIX`] followed by exactly those bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedList {
    /// The list, JSON-encoded, base64 on the wire.
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    /// Ed25519 over `SIGNING_PREFIX || body` by the network's key, base64 on
    /// the wire.
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
    /// A member's name is not a DNS label of `a-z 0-9` and inner hyphens.
    #[error("member {0} has a name that is not a DNS label")]
    BadName(String),
    /// Two members share a name.
    #[error("the name {0} is given to two members")]
    DuplicateName(String),
    /// A member declares port 0, or more than [`MAX_PORTS`].
    #[error("member {0} declares port 0 or more than 64 ports")]
    BadPorts(String),
    /// A relay's URL is not an https URL (http only on loopback).
    #[error("the relay URL {0} is not an https URL")]
    BadRelay(String),
    /// An app replica's address is outside its member's /64, is the
    /// member's own or another replica's, or its app or ports are invalid.
    #[error("member {0} lists an app replica with a bad address, name or ports")]
    BadApp(String),
}

impl SignedList {
    /// Signs `list` with the network's key. grund-server calls this, or
    /// [`SignedList::sign_bytes`] with bytes it encoded itself.
    pub fn sign(list: &MembershipList, network_key: &SigningKey) -> Self {
        Self::sign_bytes(list.encode(), network_key)
    }

    /// Signs already-encoded list bytes with the network's key.
    pub fn sign_bytes(body: Vec<u8>, network_key: &SigningKey) -> Self {
        let signature = network_key
            .sign(&Self::signed_message(&body))
            .to_bytes()
            .to_vec();
        Self { body, signature }
    }

    /// The exact bytes the signature covers: [`SIGNING_PREFIX`] then `body`.
    /// A signer that holds the key elsewhere (grund-server's `keys.rs`) signs
    /// these, or signs `body` under the same prefix.
    pub fn signed_message(body: &[u8]) -> Vec<u8> {
        [SIGNING_PREFIX, body].concat()
    }

    /// Verifies the signature and the list's own rules, and returns the list.
    pub fn verify(&self, network_key: &VerifyingKey) -> Result<MembershipList, MembershipError> {
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| MembershipError::BadSignature)?;
        network_key
            .verify(&Self::signed_message(&self.body), &signature)
            .map_err(|_| MembershipError::BadSignature)?;
        let list: MembershipList = serde_json::from_slice(&self.body)
            .map_err(|e| MembershipError::Malformed(e.to_string()))?;
        list.validate()?;
        Ok(list)
    }
}

impl MembershipList {
    /// The body grund signs: `serde_json` of the list, fields in declaration
    /// order.
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a membership list always encodes")
    }

    /// Checks the rules every list keeps: a ULA /48 prefix, no slot 0, and no
    /// slot or key given twice.
    pub fn validate(&self) -> Result<(), MembershipError> {
        let p = self.prefix.octets();
        if p[0] != 0xfd || p[6..].iter().any(|b| *b != 0) {
            return Err(MembershipError::BadPrefix(self.prefix));
        }
        let mut slots = HashSet::new();
        let mut keys = HashSet::new();
        let mut names = HashSet::new();
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
            if m.ports.len() > MAX_PORTS || m.ports.iter().any(|p| p.port == 0) {
                return Err(MembershipError::BadPorts(m.machine_id.clone()));
            }
            if let Some(name) = &m.name {
                if !is_label(name) {
                    return Err(MembershipError::BadName(m.machine_id.clone()));
                }
                if !names.insert(name.as_str()) {
                    return Err(MembershipError::DuplicateName(name.clone()));
                }
            }
        }
        let mut addresses = HashSet::new();
        for m in &self.members {
            for r in &m.apps {
                let o = r.address.octets();
                let in_own = o[..6] == p[..6] && u16::from_be_bytes([o[6], o[7]]) == m.slot;
                let iid = u64::from_be_bytes(o[8..].try_into().expect("8 bytes"));
                if !in_own
                    || iid <= 0xffff
                    || !addresses.insert(r.address)
                    || !is_label(&r.app)
                    || r.ports.len() > MAX_APP_PORTS
                    || r.ports.iter().any(|p| p.port == 0)
                {
                    return Err(MembershipError::BadApp(m.machine_id.clone()));
                }
            }
        }
        for relay in &self.relays {
            if !is_relay_url(&relay.url) {
                return Err(MembershipError::BadRelay(relay.url.clone()));
            }
        }
        for m in &self.members {
            if let Some(url) = &m.relay_url
                && !self.relays.iter().any(|r| &r.url == url)
            {
                return Err(MembershipError::BadRelay(url.clone()));
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

    /// The member with this name, compared as DNS does, ignoring ASCII case.
    pub fn member_by_name(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| {
            m.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
        })
    }

    /// The app replica whose address is `addr`, and its member.
    pub fn replica_at(&self, addr: Ipv6Addr) -> Option<(&Member, &AppReplica)> {
        let member = self.member_for(addr)?;
        member
            .apps
            .iter()
            .find(|r| r.address == addr)
            .map(|r| (member, r))
    }

    /// The addresses of `app`'s ready replicas on every member, compared as
    /// DNS does, ignoring ASCII case.
    pub fn ready_addresses(&self, app: &str) -> Vec<Ipv6Addr> {
        let mut out: Vec<Ipv6Addr> = self
            .members
            .iter()
            .flat_map(|m| m.apps.iter())
            .filter(|r| r.ready && r.app.eq_ignore_ascii_case(app))
            .map(|r| r.address)
            .collect();
        out.sort();
        out
    }

    /// The member with this key, if any.
    pub fn member_by_id(&self, id: &EndpointId) -> Option<&Member> {
        self.members
            .iter()
            .find(|m| EndpointId::from_str(&m.endpoint_id).is_ok_and(|e| &e == id))
    }
}

fn is_relay_url(url: &str) -> bool {
    let Ok(parsed) = iroh::RelayUrl::from_str(url) else {
        return false;
    };
    let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback)
}

fn is_label(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
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
            relays: vec![],
            members: vec![
                Member {
                    machine_id: "m_a".into(),
                    endpoint_id: id(1),
                    slot: 1,
                    name: Some("a".into()),
                    ports: vec![],
                    relay_url: None,
                    apps: Vec::new(),
                },
                Member {
                    machine_id: "m_b".into(),
                    endpoint_id: id(2),
                    slot: 2,
                    name: Some("b".into()),
                    ports: vec![],
                    relay_url: None,
                    apps: Vec::new(),
                },
            ],
        }
    }

    #[test]
    fn a_replica_address_is_stable_in_its_members_slash_64_and_never_a_reserved_host() {
        let prefix: Ipv6Addr = "fd12:3456:789a::".parse().unwrap();
        let a = replica_address(prefix, 7, "0199b2c4-0000-7000-8000-000000000001");
        assert_eq!(
            a,
            replica_address(prefix, 7, "0199b2c4-0000-7000-8000-000000000001")
        );
        assert_ne!(
            a,
            replica_address(prefix, 7, "0199b2c4-0000-7000-8000-000000000002")
        );
        assert_eq!(&a.segments()[..4], &[0xfd12, 0x3456, 0x789a, 7]);
        for n in 0..2000 {
            let iid = u64::from_be_bytes(
                replica_address(prefix, 1, &n.to_string()).octets()[8..]
                    .try_into()
                    .unwrap(),
            );
            assert!(iid > 0xffff);
        }
    }

    #[test]
    fn a_replica_outside_its_members_slash_64_or_on_a_reserved_host_is_refused() {
        let mut l = list();
        let good = AppReplica {
            app: "shop".into(),
            replica_id: "r-1".into(),
            address: replica_address(l.prefix, l.members[0].slot, "r-1"),
            ports: vec![Port {
                transport: Transport::Tcp,
                port: 80,
            }],
            ready: true,
        };
        l.members[0].apps = vec![good.clone()];
        assert_eq!(l.validate(), Ok(()));
        let in_others = replica_address(l.prefix, l.members[1].slot, "r-1");
        let host = l.address(l.members[0].slot);
        for address in [in_others, host] {
            l.members[0].apps = vec![AppReplica {
                address,
                ..good.clone()
            }];
            assert!(
                matches!(l.validate(), Err(MembershipError::BadApp(_))),
                "{address}"
            );
        }
        l.members[0].apps = vec![good.clone(), good.clone()];
        assert!(matches!(l.validate(), Err(MembershipError::BadApp(_))));
        l.members[0].apps = vec![AppReplica {
            app: "Shop".into(),
            ..good
        }];
        assert!(matches!(l.validate(), Err(MembershipError::BadApp(_))));
    }

    #[test]
    fn the_body_format_is_pinned() {
        let l = MembershipList {
            network_id: "net_test".into(),
            epoch: 3,
            prefix: "fd12:3456:789a::".parse().unwrap(),
            issued_at: 1_790_000_000,
            relays: vec![],
            members: vec![Member {
                machine_id: "m_a".into(),
                endpoint_id: "e".into(),
                slot: 1,
                name: None,
                ports: vec![],
                relay_url: None,
                apps: Vec::new(),
            }],
        };
        assert_eq!(
            String::from_utf8(l.encode()).unwrap(),
            r#"{"network_id":"net_test","epoch":3,"prefix":"fd12:3456:789a::","issued_at":1790000000,"members":[{"machine_id":"m_a","endpoint_id":"e","slot":1}]}"#
        );
    }

    #[test]
    fn a_named_member_carries_its_name_after_its_slot() {
        let mut l = list();
        l.members.truncate(1);
        l.members[0].endpoint_id = "e".into();
        assert_eq!(
            String::from_utf8(l.encode()).unwrap(),
            r#"{"network_id":"net_test","epoch":3,"prefix":"fd12:3456:789a::","issued_at":1790000000,"members":[{"machine_id":"m_a","endpoint_id":"e","slot":1,"name":"a"}]}"#
        );
    }

    #[test]
    fn relays_travel_after_the_members_and_must_be_https() {
        let mut l = list();
        l.members.truncate(1);
        l.members[0].endpoint_id = "e".into();
        l.members[0].name = None;
        l.relays = vec![Relay {
            url: "https://relay.example.com/".into(),
            region: Some("eu".into()),
        }];
        assert_eq!(
            String::from_utf8(l.encode()).unwrap(),
            r#"{"network_id":"net_test","epoch":3,"prefix":"fd12:3456:789a::","issued_at":1790000000,"members":[{"machine_id":"m_a","endpoint_id":"e","slot":1}],"relays":[{"url":"https://relay.example.com/","region":"eu"}]}"#
        );
        let mut l = list();
        for (url, ok) in [
            ("https://relay.example.com", true),
            ("http://127.0.0.1:3340", true),
            ("http://relay.example.com", false),
            ("not a url", false),
        ] {
            l.relays = vec![Relay {
                url: url.into(),
                region: None,
            }];
            assert_eq!(l.validate().is_ok(), ok, "{url}");
        }
    }

    #[test]
    fn a_members_home_relay_is_one_of_the_lists_relays() {
        let mut l = list();
        l.relays = vec![Relay {
            url: "https://relay.example.com".into(),
            region: None,
        }];
        l.members[0].relay_url = Some("https://relay.example.com".into());
        assert_eq!(l.validate(), Ok(()));
        l.members[0].relay_url = Some("https://elsewhere.example.com".into());
        assert_eq!(
            l.validate(),
            Err(MembershipError::BadRelay(
                "https://elsewhere.example.com".into()
            ))
        );
    }

    #[test]
    fn names_are_dns_labels_given_once_and_found_in_any_case() {
        let l = list();
        assert_eq!(l.member_by_name("B").map(|m| m.slot), Some(2));
        assert!(l.member_by_name("c").is_none());
        let mut twice = list();
        twice.members[1].name = Some("a".into());
        assert_eq!(
            twice.validate(),
            Err(MembershipError::DuplicateName("a".into()))
        );
        for bad in ["", "-a", "a-", "A", "a.b", "a_b"] {
            let mut l = list();
            l.members[0].name = Some(bad.into());
            assert_eq!(
                l.validate(),
                Err(MembershipError::BadName("m_a".into())),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_signature_covers_the_domain_prefix_not_the_bare_body() {
        let key = SigningKey::from_bytes(&[9; 32]);
        let body = list().encode();
        let bare = SignedList {
            body: body.clone(),
            signature: key.sign(&body).to_bytes().to_vec(),
        };
        assert_eq!(
            bare.verify(&key.verifying_key()),
            Err(MembershipError::BadSignature)
        );
        let mut prefixed = SIGNING_PREFIX.to_vec();
        prefixed.extend_from_slice(&body);
        let external = SignedList {
            body,
            signature: key.sign(&prefixed).to_bytes().to_vec(),
        };
        assert_eq!(external.verify(&key.verifying_key()), Ok(list()));
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
