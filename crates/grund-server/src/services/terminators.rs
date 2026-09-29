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
/// `grund relay` enrolled with this instance, or a registered machine (whose
/// gate will terminate TLS; not built).
#[derive(Debug, Clone)]
pub enum Terminator {
    Relay(RelayCaller),
    Machine(MachineCaller),
}

impl Terminator {
    /// Who the certificate belongs to: the instance, for its relays.
    pub fn owner(&self) -> String {
        match self {
            Terminator::Relay(_) => "instance".into(),
            Terminator::Machine(machine) => machine
                .organisation_id
                .map_or_else(|| "instance".into(), |id| format!("organisation:{id}")),
        }
    }

    /// The subject its certificate is kept under, when it may have one. A
    /// machine may not yet: the gate is not built.
    pub fn subject(&self) -> Option<String> {
        match self {
            Terminator::Relay(relay) => Some(format!("relay:{}", relay.host)),
            Terminator::Machine(_) => None,
        }
    }

    /// The names it may ask a certificate for: a relay, exactly its host.
    pub fn names(&self) -> Vec<String> {
        match self {
            Terminator::Relay(relay) => vec![relay.host.clone()],
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

/// What a watch sends next.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pending {
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
    /// Records `csr` for `names` as the caller's certificate request.
    pub async fn request(
        &self,
        caller: &Terminator,
        names: &[String],
        csr: &[u8],
    ) -> anyhow::Result<RequestOutcome> {
        let Some(subject) = caller.subject() else {
            return Ok(RequestOutcome::NotFound);
        };
        let requested: BTreeSet<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
        let allowed: BTreeSet<String> = caller.names().into_iter().collect();
        if requested.is_empty() || requested != allowed {
            return Ok(RequestOutcome::NotFound);
        }
        let names: Vec<String> = requested.into_iter().collect();
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

    /// The caller's certificate, if it asked for one.
    pub async fn status(&self, caller: &Terminator) -> anyhow::Result<Option<store::RemoteStatus>> {
        let Some(subject) = caller.subject() else {
            return Ok(None);
        };
        Ok(store::remote_status(&self.state.pool, &caller.owner(), &subject).await?)
    }

    /// What is pending for the caller now, or none when it has no
    /// certificate.
    pub async fn pending(&self, caller: &Terminator) -> anyhow::Result<Option<Pending>> {
        let Some(status) = self.status(caller).await? else {
            return Ok(None);
        };
        let subject = caller.subject().unwrap_or_default();
        let challenges = store::challenges_of(&self.state.pool, &subject).await?;
        Ok(Some(Pending {
            challenges,
            wants_csr: status.wants_csr,
            version: status.version,
            names: status.names,
        }))
    }

    /// Records that the caller answers its challenge with `token`. False
    /// when it has no such challenge.
    pub async fn answering(&self, caller: &Terminator, token: &str) -> anyhow::Result<bool> {
        let Some(subject) = caller.subject() else {
            return Ok(false);
        };
        if self.status(caller).await?.is_none() {
            return Ok(false);
        }
        Ok(store::mark_answering(&self.state.pool, &subject, token).await?)
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
    }
}
