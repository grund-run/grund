//! Privileged first-owner machine registration and durable local enrollment recovery.

use std::{
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Arc,
};

use anyhow::Context;
use chrono::{DateTime, Utc};
use grund_domain::machine::{
    KeyPurpose, LocalMachineBootstrap, MachineCommand, MachineError, Pool, TOKEN_TTL, TokenKind,
};
use grund_proto::grund::agent::v1::EnrollMachineResponse;
use grund_store::{
    machines::{self, NewToken},
    setup_links,
    work::{Work, WorkError},
};
use uuid::Uuid;

use crate::{
    config::ServeConfig,
    keys::Keys,
    secrets::SecretKey,
    services::{
        machines::Enrollment,
        networks::{Networks, network_message},
    },
};

/// A permanent local identity/configuration refusal, distinguished from an unavailable database.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Refused(pub &'static str);

pub(crate) fn decode(bytes: &[u8]) -> anyhow::Result<LocalMachineBootstrap> {
    let descriptor: LocalMachineBootstrap = serde_json::from_slice(bytes).map_err(|_| {
        Refused("GRUND_LOCAL_MACHINE_FILE must contain a valid local machine descriptor")
    })?;
    anyhow::ensure!(
        !descriptor.machine_id.is_nil(),
        Refused("local machine ID must not be nil")
    );
    anyhow::ensure!(
        grund_config::names::MachineName::parse(descriptor.name.as_str())
            .ok()
            .as_ref()
            == Some(&descriptor.name),
        Refused("local machine name is invalid")
    );
    let bytes: [u8; 32] = hex::decode(descriptor.key.as_hex())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Refused(
            "local machine key must be a valid Ed25519 public key",
        ))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| Refused("local machine key must be a valid Ed25519 public key"))?;
    anyhow::ensure!(
        !key.is_weak() && hex::encode(bytes) == descriptor.key.as_hex(),
        Refused("local machine key must be a canonical strong Ed25519 public key")
    );
    Ok(descriptor)
}

/// Loads and validates bounded privileged configuration without exposing its contents in errors.
pub fn load(path: &Path) -> anyhow::Result<LocalMachineBootstrap> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Refused("cannot open GRUND_LOCAL_MACHINE_FILE"))?;
    let metadata = file
        .metadata()
        .map_err(|_| Refused("cannot inspect GRUND_LOCAL_MACHINE_FILE"))?;
    anyhow::ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o022 == 0,
        Refused("GRUND_LOCAL_MACHINE_FILE must be a regular file not writable by group or others")
    );
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| Refused("cannot read GRUND_LOCAL_MACHINE_FILE"))?;
    anyhow::ensure!(
        bytes.len() <= 65536,
        Refused("GRUND_LOCAL_MACHINE_FILE exceeds 65536 bytes")
    );
    decode(&bytes)
}

pub(crate) async fn register(
    work: &mut Work<'_>,
    descriptor: &LocalMachineBootstrap,
    account_id: Uuid,
    organisation_id: Uuid,
    at: DateTime<Utc>,
) -> Result<(), WorkError> {
    if machines::machine(&mut **work.sql(), descriptor.machine_id)
        .await?
        .is_some()
    {
        return Err(MachineError::AlreadyExists.into());
    }
    let token_id = Uuid::now_v7();
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).expect("the operating system provides randomness");
    let token = format!(
        "{}{}",
        TokenKind::Organisation.prefix(),
        crate::services::machines::base32(&secret)
    );
    let actor = format!("account:{account_id}");
    machines::insert_token(
        &mut **work.sql(),
        &NewToken {
            token_id,
            digest: crate::crypto::digest(&token),
            kind: TokenKind::Organisation.as_str(),
            organisation_id: Some(organisation_id),
            machine_id: None,
            name: Some(descriptor.name.as_str()),
            minted_by: &actor,
            expires_at: at + TOKEN_TTL,
            vm_id: None,
        },
    )
    .await?;
    work.machine(
        descriptor.machine_id,
        MachineCommand::Register {
            pool: Pool::Organisation { organisation_id },
            name: descriptor.name.clone(),
            key: descriptor.key.clone(),
            token_id,
            minted_by: actor,
            facts: descriptor.facts.clone(),
            provider_machine_id: None,
            at,
        },
    )
    .await?;
    let row = machines::machine(&mut **work.sql(), descriptor.machine_id).await?;
    if !row.as_ref().is_some_and(|row| {
        row.home_organisation_id == Some(organisation_id)
            && row.public_key.as_deref() == Some(descriptor.key.as_hex())
            && row.minted_by == format!("account:{account_id}")
    }) {
        return Err(MachineError::AlreadyExists.into());
    }
    machines::consume_token(
        work.sql(),
        token_id,
        descriptor.key.as_hex(),
        descriptor.machine_id,
        at,
    )
    .await?;
    Ok(())
}

async fn recover(config: ServeConfig) -> anyhow::Result<Option<EnrollMachineResponse>> {
    let descriptor = config
        .local_machine
        .as_ref()
        .ok_or(Refused("GRUND_LOCAL_MACHINE_FILE is not configured"))?;
    let secret = SecretKey::load(&config)
        .map_err(|_| Refused("local recovery requires the configured production secret key"))?;
    let keys = Keys::new(Arc::new(secret));
    let pool = crate::db::connect(&config.database)
        .await
        .context("local enrollment database is unavailable")?;
    anyhow::ensure!(
        keys.mismatched(&pool).await?.is_empty(),
        Refused("local recovery secret does not match the instance keys")
    );
    let mut tx = pool.begin().await?;
    let owner = setup_links::claimed_owner(&mut *tx).await?;
    let Some((account_id, organisation_id)) = owner else {
        anyhow::ensure!(
            !setup_links::any_account(&mut *tx).await?
                && machines::machine(&mut *tx, descriptor.machine_id)
                    .await?
                    .is_none(),
            Refused("local machine is not bound to a setup-created owner")
        );
        return Ok(None);
    };
    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT machine_id FROM grund_machines WHERE machine_id = $1 FOR SHARE")
            .bind(descriptor.machine_id)
            .fetch_optional(&mut *tx)
            .await?;
    anyhow::ensure!(
        exists.is_some(),
        Refused("the owner's local machine no longer exists")
    );
    let row = machines::machine(&mut *tx, descriptor.machine_id)
        .await?
        .ok_or(Refused("the owner's local machine no longer exists"))?;
    anyhow::ensure!(
        row.state == "active"
            && row.pool == "organisation"
            && row.home_organisation_id == Some(organisation_id)
            && row.pool_organisation_id == Some(organisation_id)
            && row.public_key.as_deref() == Some(descriptor.key.as_hex())
            && row.minted_by == format!("account:{account_id}"),
        Refused("local machine was revoked, changed key, or belongs to another identity")
    );
    let enrollment = Enrollment {
        machine_id: descriptor.machine_id,
        name: row.name,
        pool: Pool::Organisation { organisation_id },
        instance_key: keys.ensure(&mut tx, KeyPurpose::Instance, None).await?,
        trust_key: keys
            .ensure(&mut tx, KeyPurpose::Organisation, Some(organisation_id))
            .await?,
    };
    let machine_id = descriptor.machine_id;
    let relay_urls = config.relay.urls();
    let network = Networks::new(pool.clone(), keys, Arc::new(config))
        .reconcile(organisation_id)
        .await?;
    let network = network_message(&network, machine_id, relay_urls).ok_or(Refused(
        "the local machine has no current organisation network slot",
    ))?;
    tx.commit().await?;
    Ok(Some(crate::api::enrollment::enrollment_response(
        enrollment,
        Some(network),
    )))
}

/// Prints null before owner claim, otherwise the real current enrollment as protobuf JSON.
pub async fn run(mut config: ServeConfig) -> anyhow::Result<()> {
    config
        .validate()
        .map_err(|_| Refused("local enrollment configuration is invalid"))?;
    let response = recover(config).await?;
    println!("{}", serde_json::to_string(&response)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> serde_json::Value {
        let key = ed25519_dalek::SigningKey::from_bytes(&[23; 32]);
        serde_json::json!({
            "machine_id": Uuid::now_v7(),
            "name": "local-host",
            "key": hex::encode(key.verifying_key().as_bytes()),
            "facts": grund_domain::machine::MachineFacts::default()
        })
    }

    #[test]
    fn privileged_descriptors_refuse_invalid_identities_and_unknown_fields() {
        let valid = descriptor();
        assert!(decode(&serde_json::to_vec(&valid).unwrap()).is_ok());
        for (field, value) in [
            ("machine_id", serde_json::json!(Uuid::nil())),
            ("name", serde_json::json!("not a machine name")),
            ("key", serde_json::json!("not a key")),
            ("key", serde_json::json!("00".repeat(32))),
            ("organisation_id", serde_json::json!(Uuid::now_v7())),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(decode(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
    }

    #[test]
    fn privileged_descriptors_cannot_enable_development_mode() {
        #[derive(clap::Parser)]
        struct Harness {
            #[command(flatten)]
            config: ServeConfig,
        }
        use clap::Parser;
        let path = std::env::temp_dir().join(format!("grund-local-config-{}.json", Uuid::now_v7()));
        std::fs::write(&path, serde_json::to_vec(&descriptor()).unwrap()).unwrap();
        let mut config = Harness::try_parse_from([
            "grund",
            "--database-url",
            "postgres://localhost/grund",
            "--dev-mode=true",
            "--local-machine-file",
            path.to_str().unwrap(),
        ])
        .unwrap()
        .config;
        assert!(config.validate().is_err());
        std::fs::remove_file(path).unwrap();
    }
}
