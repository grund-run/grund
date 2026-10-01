//! Certificates for TLS terminators on other hosts (grund-docs
//! design/traffic.md §5.7): what `grund.certificates.v1.CertificateService`
//! decides. The terminator is the caller, proven by its own key; which
//! certificate it may ask for, and see, follows from who it is and nothing
//! else. A name it may not have is refused exactly as a certificate that
//! does not exist.
//!
//! The ordering is `certificates.rs`'s, on the same rows: a request records
//! the CSR (`grund_store::certificates::request_remote`) and the instance's
//! lease holder orders it with its account and backoff.

use std::collections::BTreeSet;

use grund_store::certificates::{self as store, Challenge, PendingChallenge, RemoteRequest};
use x509_parser::prelude::FromDer;

use crate::{
    certificates::CertificatesState,
    services::{agents::MachineCaller, relays::RelayCaller},
    state::State,
};

/// The largest CSR accepted, DER.
pub const MAX_CSR_BYTES: usize = 4096;

/// A TLS terminator on another host, as its own key's signature proved: a
/// `grund relay` or a `grund edge` enrolled with this instance, or a
/// registered machine (whose gate will terminate TLS for direct names; not
/// built).
#[derive(Debug, Clone)]
pub enum Terminator {
    Relay(RelayCaller),
    Edge(RelayCaller),
    Machine(MachineCaller),
}

fn short(text: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(text.as_bytes())[..8])
}

impl Terminator {
    /// Who the certificate belongs to: the instance, for its relays and
    /// edges.
    pub fn owner(&self) -> String {
        match self {
            Terminator::Relay(_) | Terminator::Edge(_) => "instance".into(),
            Terminator::Machine(machine) => machine
                .organisation_id
                .map_or_else(|| "instance".into(), |id| format!("organisation:{id}")),
        }
    }

    /// The subject a relay's one certificate is kept under.
    pub fn subject(&self) -> Option<String> {
        match self {
            Terminator::Relay(relay) => Some(format!("relay:{}", relay.host)),
            Terminator::Edge(_) | Terminator::Machine(_) => None,
        }
    }

    /// The subject of the certificate for exactly `names`, when the caller
    /// keeps one there: a relay's for its host (and `names` empty means
    /// that one); an edge's for one name, under a digest of its host and the
    /// name, so every subject fits the store's 128 characters.
    pub fn subject_for(&self, names: &[String]) -> Option<String> {
        match self {
            Terminator::Relay(relay) => (names.is_empty() || names == [relay.host.clone()])
                .then(|| format!("relay:{}", relay.host)),
            Terminator::Edge(edge) => match names {
                [name] => Some(format!(
                    "{}{}",
                    self.subject_prefix()?,
                    short(&format!("{}:{name}", edge.host))
                )),
                _ => None,
            },
            Terminator::Machine(_) => None,
        }
    }

    /// What every subject of the caller starts with.
    pub fn subject_prefix(&self) -> Option<String> {
        match self {
            Terminator::Relay(relay) => Some(format!("relay:{}", relay.host)),
            Terminator::Edge(edge) => Some(format!("edge:{}:", short(&edge.host))),
            Terminator::Machine(_) => None,
        }
    }

    /// The names a relay may ask a certificate for: exactly its host. An
    /// edge may also ask for every address in the route table, one at a
    /// time ([`Terminators::request`]).
    pub fn names(&self) -> Vec<String> {
        match self {
            Terminator::Relay(relay) | Terminator::Edge(relay) => vec![relay.host.clone()],
            Terminator::Machine(_) => Vec::new(),
        }
    }
}

/// How a request ended.
#[derive(Debug)]
pub enum RequestOutcome {
    Recorded(Box<store::RemoteStatus>),
    /// Names the caller may not have: the same answer as no certificate.
    NotFound,
    Invalid(String),
    /// This instance orders no certificates (GRUND_ACME_DIRECTORY unset).
    AcmeOff,
}

/// What a watch sends next, for one of the caller's certificates.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pending {
    pub subject: String,
    pub challenges: Vec<PendingChallenge>,
    pub wants_csr: bool,
    pub version: i64,
    pub names: Vec<String>,
}

/// Checks that `csr` (DER) is a self-signed PKCS#10 request naming exactly
/// `names` as DNS subjectAltNames.
pub fn check_csr(csr: &[u8], names: &[String]) -> Result<(), String> {
    if csr.is_empty() || csr.len() > MAX_CSR_BYTES {
        return Err(format!("the CSR must be 1 to {MAX_CSR_BYTES} bytes of DER"));
    }
    let (rest, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(csr)
            .map_err(|_| "the CSR is not PKCS#10 DER".to_string())?;
    if !rest.is_empty() {
        return Err("the CSR has bytes after it".into());
    }
    request
        .verify_signature()
        .map_err(|_| "the CSR is not signed by the key it names".to_string())?;
    let mut named = BTreeSet::new();
    for extension in request.requested_extensions().into_iter().flatten() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = extension {
            for name in &san.general_names {
                match name {
                    x509_parser::extensions::GeneralName::DNSName(dns) => {
                        named.insert(dns.to_ascii_lowercase());
                    }
                    _ => return Err("the CSR names something other than DNS names".into()),
                }
            }
        }
    }
    let wanted: BTreeSet<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
    if named != wanted {
        return Err("the CSR must name exactly the requested names".into());
    }
    Ok(())
}

/// Certificates for remote terminators.
#[derive(Clone)]
pub struct Terminators {
    state: State,
}

impl Terminators {
    async fn may_have(
        &self,
        caller: &Terminator,
        names: &BTreeSet<String>,
    ) -> anyhow::Result<bool> {
        use crate::services::entry::EntryState;
        match caller {
            Terminator::Edge(edge) => match names.iter().next() {
                Some(name) if names.len() == 1 => {
                    Ok(*name == edge.host || self.state.entry().routes_name(name).await?)
                }
                _ => Ok(false),
            },
            _ => {
                let allowed: BTreeSet<String> = caller.names().into_iter().collect();
                Ok(!names.is_empty() && *names == allowed)
            }
        }
    }

    /// Records `csr` for `names` as the caller's certificate request.
    pub async fn request(
        &self,
        caller: &Terminator,
        names: &[String],
        csr: &[u8],
    ) -> anyhow::Result<RequestOutcome> {
        let requested: BTreeSet<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
        let names: Vec<String> = requested.iter().cloned().collect();
        let Some(subject) = caller.subject_for(&names) else {
            return Ok(RequestOutcome::NotFound);
        };
        if !self.may_have(caller, &requested).await? {
            return Ok(RequestOutcome::NotFound);
        }
        if let Err(message) = check_csr(csr, &names) {
            return Ok(RequestOutcome::Invalid(message));
        }
        let Some((directory, profile)) = self.state.certificates().ordering() else {
            return Ok(RequestOutcome::AcmeOff);
        };
        let owner = caller.owner();
        let recorded = store::request_remote(
            &self.state.pool,
            &RemoteRequest {
                owner: owner.clone(),
                subject: subject.clone(),
                names,
                csr: csr.to_vec(),
                directory,
                profile,
                challenge: Challenge::TlsAlpn01,
            },
        )
        .await?;
        if !recorded {
            return Ok(RequestOutcome::NotFound);
        }
        match store::remote_status(&self.state.pool, &owner, &subject).await? {
            Some(status) => Ok(RequestOutcome::Recorded(Box::new(status))),
            None => Ok(RequestOutcome::NotFound),
        }
    }

    /// The caller's certificate for `names` (a relay: empty for its one),
    /// if it asked for one.
    pub async fn status(
        &self,
        caller: &Terminator,
        names: &[String],
    ) -> anyhow::Result<Option<store::RemoteStatus>> {
        let names: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
        let Some(subject) = caller.subject_for(&names) else {
            return Ok(None);
        };
        Ok(store::remote_status(&self.state.pool, &caller.owner(), &subject).await?)
    }

    /// What is pending now for each of the caller's certificates; empty
    /// when it has none.
    pub async fn pending(&self, caller: &Terminator) -> anyhow::Result<Vec<Pending>> {
        let Some(prefix) = caller.subject_prefix() else {
            return Ok(Vec::new());
        };
        let statuses = match caller {
            Terminator::Relay(_) => {
                store::remote_status(&self.state.pool, &caller.owner(), &prefix)
                    .await?
                    .map(|status| vec![(prefix.clone(), status)])
                    .unwrap_or_default()
            }
            _ => store::remote_statuses(&self.state.pool, &caller.owner(), &prefix).await?,
        };
        let mut out = Vec::with_capacity(statuses.len());
        for (subject, status) in statuses {
            let challenges = store::challenges_of(&self.state.pool, &subject).await?;
            out.push(Pending {
                subject,
                challenges,
                wants_csr: status.wants_csr,
                version: status.version,
                names: status.names,
            });
        }
        Ok(out)
    }

    /// Records that the caller answers its challenge with `token`. False
    /// when it has no such challenge.
    pub async fn answering(&self, caller: &Terminator, token: &str) -> anyhow::Result<bool> {
        for pending in self.pending(caller).await? {
            if pending.challenges.iter().any(|c| c.token == token) {
                return Ok(store::mark_answering(&self.state.pool, &pending.subject, token).await?);
            }
        }
        Ok(false)
    }
}

/// Certificates for remote terminators.
pub trait TerminatorsState {
    fn terminators(&self) -> Terminators;
}

impl TerminatorsState for State {
    fn terminators(&self) -> Terminators {
        Terminators {
            state: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[test]
    fn a_csr_must_name_exactly_what_is_asked_for() {
        let made = grund_tls::KeyAndCsr::generate(&names(&["relay.example.com"])).unwrap();
        check_csr(made.csr_der(), &names(&["relay.example.com"])).unwrap();
        assert!(check_csr(made.csr_der(), &names(&["other.example.com"])).is_err());
        assert!(
            check_csr(
                made.csr_der(),
                &names(&["relay.example.com", "other.example.com"])
            )
            .is_err()
        );
    }

    #[test]
    fn a_tampered_or_oversized_csr_is_refused() {
        let made = grund_tls::KeyAndCsr::generate(&names(&["relay.example.com"])).unwrap();
        let mut tampered = made.csr_der().to_vec();
        let at = tampered.len() / 2;
        tampered[at] ^= 1;
        assert!(check_csr(&tampered, &names(&["relay.example.com"])).is_err());
        assert!(check_csr(&[], &names(&["relay.example.com"])).is_err());
        assert!(
            check_csr(
                &vec![0u8; MAX_CSR_BYTES + 1],
                &names(&["relay.example.com"])
            )
            .is_err()
        );
    }

    #[test]
    fn a_relay_may_ask_for_its_own_host_only_and_a_machine_for_nothing_yet() {
        let relay = Terminator::Relay(RelayCaller {
            relay_id: uuid::Uuid::now_v7(),
            host: "relay.example.com".into(),
        });
        assert_eq!(relay.names(), names(&["relay.example.com"]));
        assert_eq!(relay.subject().as_deref(), Some("relay:relay.example.com"));
        assert_eq!(relay.owner(), "instance");
        let machine = Terminator::Machine(MachineCaller {
            machine_id: uuid::Uuid::now_v7(),
            organisation_id: None,
        });
        assert!(machine.names().is_empty() && machine.subject().is_none());
        assert!(machine.subject_for(&names(&["a.example.com"])).is_none());
    }

    #[test]
    fn an_edge_keeps_one_certificate_per_name_under_its_own_prefix() {
        let edge = Terminator::Edge(RelayCaller {
            relay_id: uuid::Uuid::now_v7(),
            host: "edge-1.grund.run".into(),
        });
        let prefix = edge.subject_prefix().unwrap();
        let photos = edge
            .subject_for(&names(&["photos-kasper.grund.run"]))
            .unwrap();
        let blog = edge.subject_for(&names(&["blog-bob.grund.run"])).unwrap();
        assert!(photos.starts_with(&prefix) && blog.starts_with(&prefix) && photos != blog);
        assert!(photos.len() <= 128);
        assert!(
            edge.subject_for(&names(&["a.grund.run", "b.grund.run"]))
                .is_none()
        );
        assert!(edge.subject_for(&[]).is_none());
        let other = Terminator::Edge(RelayCaller {
            relay_id: uuid::Uuid::now_v7(),
            host: "edge-2.grund.run".into(),
        });
        assert!(
            !other
                .subject_for(&names(&["photos-kasper.grund.run"]))
                .unwrap()
                .starts_with(&prefix)
        );
        let relay = Terminator::Relay(RelayCaller {
            relay_id: uuid::Uuid::now_v7(),
            host: "relay.example.com".into(),
        });
        assert_eq!(
            relay.subject_for(&[]).as_deref(),
            Some("relay:relay.example.com")
        );
        assert!(
            relay
                .subject_for(&names(&["photos-kasper.grund.run"]))
                .is_none()
        );
    }
}
