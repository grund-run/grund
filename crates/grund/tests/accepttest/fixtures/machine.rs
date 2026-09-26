use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use super::{Given, Then, When};

pub const MACHINES: &str = "/grund.machine.v1.MachineService";
pub const ENROLL: &str = "/grund.agent.v1.MachineEnrollmentService/EnrollMachine";

pub struct MachineKey(SigningKey);

impl MachineKey {
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("randomness");
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn public_base64(&self) -> String {
        STANDARD.encode(self.0.verifying_key().to_bytes())
    }

    pub fn public_base64url(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0.verifying_key().to_bytes())
    }

    pub fn sign(&self, origin: &str, signed_at: i64, token: &str) -> String {
        let mut message = format!("grund-enroll-v1\n{origin}\n{signed_at}\n").into_bytes();
        message.extend_from_slice(&Sha256::digest(token.as_bytes()));
        STANDARD.encode(self.0.sign(&message).to_bytes())
    }
}

pub struct Enroll<'a> {
    pub token: &'a str,
    pub key: &'a MachineKey,
    pub hostname: &'a str,
    pub requested_name: &'a str,
    pub signed_for: Option<&'a str>,
    pub clock_offset_seconds: i64,
}

impl<'a> Enroll<'a> {
    pub fn new(token: &'a str, key: &'a MachineKey) -> Self {
        Self {
            token,
            key,
            hostname: "Kasper's NUC.local",
            requested_name: "",
            signed_for: None,
            clock_offset_seconds: 0,
        }
    }
}

impl Given {
    pub async fn an_enrollment_token(
        &self,
        when: &When,
        then: &Then,
        slug: &str,
        machine_name: &str,
        ttl_seconds: i32,
    ) -> anyhow::Result<String> {
        when.calling(
            &format!("{MACHINES}/CreateEnrollmentToken"),
            &serde_json::json!({ "slug": slug, "machineName": machine_name, "ttlSeconds": ttl_seconds })
                .to_string(),
        )
        .await?;
        then.status(200)?;
        let token = then.json()?["token"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        anyhow::ensure!(
            token.starts_with("grund_enr_") && token.len() == 62,
            "{token}"
        );
        Ok(token)
    }
}

impl When {
    pub async fn enrolling(&self, enroll: &Enroll<'_>) -> anyhow::Result<&Self> {
        let origin = self.testcase.fixture.origin.serialized();
        let signed_at = chrono::Utc::now().timestamp() + enroll.clock_offset_seconds;
        let signature = enroll.key.sign(
            enroll.signed_for.unwrap_or(&origin),
            signed_at,
            enroll.token,
        );
        let body = serde_json::json!({
            "token": enroll.token,
            "machinePublicKey": enroll.key.public_base64(),
            "signedAtUnix": signed_at.to_string(),
            "signature": signature,
            "facts": { "hostname": enroll.hostname, "arch": "x86_64", "cpus": 4 },
            "requestedName": enroll.requested_name,
        });
        self.calling(ENROLL, &body.to_string()).await
    }
}

impl Then {
    pub fn error_reason(&self, code: &str, reason: &str) -> anyhow::Result<&Self> {
        self.connect_code(code)?;
        let json = self.json()?;
        anyhow::ensure!(
            json["details"][0]["debug"]["reason"] == reason,
            "wanted reason {reason:?}: {json}"
        );
        Ok(self)
    }
}
