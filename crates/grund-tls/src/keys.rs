use anyhow::Context;

/// A fresh private key and a CSR for it, made where TLS will terminate. The
/// CSR goes to whoever runs the ACME order; the key never leaves the
/// terminator (for the instance's own domain, the instance is both, and
/// stores the key sealed).
pub struct KeyAndCsr {
    key_pkcs8_der: Vec<u8>,
    csr_der: Vec<u8>,
}

impl std::fmt::Debug for KeyAndCsr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyAndCsr(..)")
    }
}

impl KeyAndCsr {
    /// An ECDSA P-256 key and a CSR naming exactly `names` as DNS names.
    pub fn generate(names: &[String]) -> anyhow::Result<Self> {
        anyhow::ensure!(!names.is_empty(), "a CSR needs at least one name");
        let key = rcgen::KeyPair::generate().context("generate the certificate key")?;
        Self::request(key, names)
    }

    /// A CSR naming `names` for a key made earlier (PKCS#8 DER), so an order
    /// interrupted after its key was made can be finalized with that key.
    pub fn from_pkcs8(key_pkcs8_der: &[u8], names: &[String]) -> anyhow::Result<Self> {
        anyhow::ensure!(!names.is_empty(), "a CSR needs at least one name");
        let key = rcgen::KeyPair::try_from(key_pkcs8_der).context("load the certificate key")?;
        Self::request(key, names)
    }

    fn request(key: rcgen::KeyPair, names: &[String]) -> anyhow::Result<Self> {
        let mut params =
            rcgen::CertificateParams::new(names.to_vec()).context("the certificate's names")?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params
            .serialize_request(&key)
            .context("sign the certificate request")?;
        Ok(Self {
            key_pkcs8_der: key.serialize_der(),
            csr_der: csr.der().to_vec(),
        })
    }

    /// The CSR, DER, as ACME's finalize takes it.
    pub fn csr_der(&self) -> &[u8] {
        &self.csr_der
    }

    /// The private key, PKCS#8 DER. Only the terminator reads this.
    pub fn key_pkcs8_der(&self) -> &[u8] {
        &self.key_pkcs8_der
    }
}

#[cfg(test)]
mod tests {
    use rcgen::PublicKeyData;
    use x509_parser::prelude::FromDer;

    use super::*;

    #[test]
    fn a_csr_names_the_key_that_stays_behind() {
        let made = KeyAndCsr::generate(&["grund.example.com".into()]).unwrap();
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(made.csr_der())
                .unwrap();
        let key = rcgen::KeyPair::try_from(made.key_pkcs8_der()).unwrap();
        assert_eq!(
            csr.certification_request_info.subject_pki.raw,
            key.subject_public_key_info().as_slice()
        );
        assert_eq!(format!("{made:?}"), "KeyAndCsr(..)");
    }

    #[test]
    fn a_resumed_order_signs_its_csr_with_the_key_it_made_first() {
        let names = vec!["grund.example.com".to_string()];
        let first = KeyAndCsr::generate(&names).unwrap();
        let again = KeyAndCsr::from_pkcs8(first.key_pkcs8_der(), &names).unwrap();
        let spki = |csr: &[u8]| {
            let (_, csr) =
                x509_parser::certification_request::X509CertificationRequest::from_der(csr)
                    .unwrap();
            csr.certification_request_info.subject_pki.raw.to_vec()
        };
        assert_eq!(spki(first.csr_der()), spki(again.csr_der()));
    }

    #[test]
    fn a_csr_without_names_is_refused() {
        assert!(KeyAndCsr::generate(&[]).is_err());
    }
}
