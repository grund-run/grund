use super::*;
use clap::Parser;
use serde_json::Value;

#[allow(dead_code)]
#[path = "../../../grund/tests/accepttest/fixtures/registry.rs"]
mod registry;

fn random_hex(bytes: usize) -> String {
    let mut value = vec![0; bytes];
    getrandom::fill(&mut value).unwrap();
    hex::encode(value)
}

#[derive(Parser)]
struct TestConfig {
    #[command(flatten)]
    config: crate::config::ServeConfig,
}

async fn state(pool: sqlx::PgPool, registry: &registry::FakeRegistry) -> anyhow::Result<State> {
    grund_store::migrate(&pool).await?;
    let mut config =
        TestConfig::try_parse_from(["test", "--database-url", "postgres://unused/test"])?.config;
    config.insecure_registries = vec![registry.host.clone()];
    config.license_key = None;
    config.license_key_file = None;
    let secret = Arc::new(crate::secrets::SecretKey::generate());
    let events = mire::EventStore::new(pool.clone());
    let certificates =
        crate::certificates::Certificates::new(&config, pool.clone(), secret.clone());
    let hearing = Arc::new(crate::hearing::Hearing::new(Utc::now()));
    let health = crate::health::registry(
        pool.clone(),
        hearing.clone(),
        None,
        false,
        &certificates,
        &config,
    );
    let entitlements = Arc::new(crate::entitlements(&config)?);
    Ok(State {
        config: Arc::new(config),
        pool,
        events: events.clone(),
        nats: None,
        secret,
        certificates,
        health,
        passwords: crate::services::passwords::Passwords::new()?,
        entitlements,
        billing: crate::services::billing::Billing::Free,
        capacity: crate::services::capacity::Capacity::None,
        deletions: crate::sagas::Deletions::new(events),
        extensions: Arc::new(Vec::new()),
        started: std::time::Instant::now(),
        wakes: crate::wakes::Wakes::default(),
        hearing,
    })
}

async fn membership(state: &State, org: Uuid, actor: Uuid, role: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO grund_memberships \
         (organisation_id,account_id,role,stream_version,joined_at) \
         VALUES ($1,$2,$3,1,clock_timestamp())",
    )
    .bind(org)
    .bind(actor)
    .bind(role)
    .execute(&state.pool)
    .await?;
    Ok(())
}

async fn launch(
    state: &State,
    registry: &registry::FakeRegistry,
    actor: Uuid,
    org: Uuid,
    name: &str,
    template: &'static str,
) -> anyhow::Result<ReleaseRow> {
    registry.publish(template, "test");
    let mut spec = grund_domain::app::templates::find(template)
        .unwrap()
        .spec(false)
        .unwrap();
    spec.image = registry.image(template, "test");
    let (_, release) = state
        .apps()
        .launch(
            actor,
            org,
            Launch {
                name: name.into(),
                settings: SettingsInput::default(),
                spec,
                detect_port: None,
                secrets: Vec::new(),
                generated_template: Some(template),
            },
        )
        .await?;
    Ok(release)
}

fn value(result: CredentialReveal) -> anyhow::Result<String> {
    match result {
        CredentialReveal::Value(value) => Ok(value),
        _ => anyhow::bail!("an authorised generated credential must be available"),
    }
}

async fn audit_count(state: &State) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT count(*) FROM grund_template_credential_reveals")
            .fetch_one(&state.pool)
            .await?,
    )
}

#[sqlx::test(migrations = false)]
async fn generated_credentials_require_current_owner_or_admin_and_commit_value_free_audit(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    let registry = registry::FakeRegistry::start().await?;
    let state = state(pool, &registry).await?;
    let org = Uuid::now_v7();
    let foreign_org = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let admin = Uuid::now_v7();
    let member = Uuid::now_v7();
    let outsider = Uuid::now_v7();
    membership(&state, org, owner, "owner").await?;
    membership(&state, org, admin, "admin").await?;
    membership(&state, org, member, "member").await?;
    membership(&state, foreign_org, outsider, "owner").await?;
    let release = launch(&state, &registry, owner, org, "database", "postgres").await?;
    let apps = state.apps();
    let key = "postgres-password";
    for (actor, tenant, name, secret) in [
        (member, org, "database", key),
        (outsider, org, "database", key),
        (owner, foreign_org, "database", key),
        (owner, org, "missing", key),
        (owner, org, "database", "missing"),
    ] {
        assert!(matches!(
            apps.reveal_template_credential(actor, tenant, name, secret)
                .await?,
            CredentialReveal::Unavailable
        ));
    }
    assert_eq!(audit_count(&state).await?, 0);
    let before: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&state.pool)
        .await?;
    let credential = value(
        apps.reveal_template_credential(owner, org, "database", key)
            .await?,
    )?;
    let admin_credential = value(
        apps.reveal_template_credential(admin, org, "database", key)
            .await?,
    )?;
    anyhow::ensure!(
        credential == admin_credential,
        "owner and admin read the same credential"
    );
    let after: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&state.pool)
        .await?;
    let audits: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(a) FROM grund_template_credential_reveals a ORDER BY actor",
    )
    .fetch_all(&state.pool)
    .await?;
    assert_eq!(audits.len(), 2);
    for audit in &audits {
        assert_eq!(audit["organisation_id"], org.to_string());
        assert_eq!(audit["app_id"], release.app_id.to_string());
        assert_eq!(audit["name"], key);
        assert_eq!(audit["version"], 1);
        let actor = audit["actor"].as_str().unwrap();
        assert!(actor == owner.to_string() || actor == admin.to_string());
        let at = DateTime::parse_from_rfc3339(audit["revealed_at"].as_str().unwrap())?;
        assert!(at >= before && at <= after);
        assert!(audit.as_object().unwrap().keys().all(|key| matches!(
            key.as_str(),
            "organisation_id"
                | "reveal_id"
                | "app_id"
                | "actor"
                | "name"
                | "version"
                | "revealed_at"
        )));
        anyhow::ensure!(
            !audit.to_string().contains(&credential),
            "audit is value-free"
        );
    }
    let mut audited_actors: Vec<_> = audits
        .iter()
        .map(|audit| audit["actor"].as_str().unwrap().to_string())
        .collect();
    audited_actors.sort();
    let mut expected_actors = vec![owner.to_string(), admin.to_string()];
    expected_actors.sort();
    assert_eq!(audited_actors, expected_actors);
    let sealed: Vec<u8> = sqlx::query_scalar(
        "SELECT sealed FROM grund_app_secrets WHERE app_id=$1 AND name=$2 AND version=1",
    )
    .bind(release.app_id)
    .bind(key)
    .fetch_one(&state.pool)
    .await?;
    anyhow::ensure!(
        !sealed
            .windows(credential.len())
            .any(|bytes| bytes == credential.as_bytes()),
        "credential is sealed at rest"
    );
    anyhow::ensure!(
        !serde_json::to_string(&release.spec.0)?.contains(&credential),
        "release specs carry references, not credential values"
    );
    sqlx::query(
        "UPDATE grund_memberships SET role='member' WHERE organisation_id=$1 AND account_id=$2",
    )
    .bind(org)
    .bind(admin)
    .execute(&state.pool)
    .await?;
    assert!(matches!(
        apps.reveal_template_credential(admin, org, "database", key)
            .await?,
        CredentialReveal::Unavailable
    ));
    assert_eq!(audit_count(&state).await?, 2);
    Ok(())
}

#[sqlx::test(migrations = false)]
async fn template_redeploy_keeps_credential_versions_and_owned_volume_identity(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    let registry = registry::FakeRegistry::start().await?;
    let state = state(pool, &registry).await?;
    let org = Uuid::now_v7();
    let owner = Uuid::now_v7();
    membership(&state, org, owner, "owner").await?;
    let apps = state.apps();
    for (template, secret) in [
        ("postgres", "postgres-password"),
        ("redis", "redis-password"),
    ] {
        let initial = launch(&state, &registry, owner, org, template, template).await?;
        let credential = value(
            apps.reveal_template_credential(owner, org, template, secret)
                .await?,
        )?;
        let volumes = apps.volumes(org, template).await?;
        assert_eq!(volumes.len(), 1);
        assert_eq!(initial.secret_versions.0.len(), 1);
        assert_eq!(initial.secret_versions.0[0].name, secret);
        assert_eq!(initial.secret_versions.0[0].version, 1);
        let redeployed = apps
            .change(
                owner,
                org,
                template,
                Change {
                    copies: None,
                    spec: initial.spec.0.clone(),
                    detect_port: None,
                    secrets: Vec::new(),
                    same_image: true,
                },
            )
            .await?;
        assert_eq!(redeployed.number, initial.number + 1);
        assert_eq!(redeployed.secret_versions.0, initial.secret_versions.0);
        let retained = apps.volumes(org, template).await?;
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].volume_id, volumes[0].volume_id);
        assert_eq!(retained[0].path, volumes[0].path);
        let revealed = value(
            apps.reveal_template_credential(owner, org, template, secret)
                .await?,
        )?;
        anyhow::ensure!(
            credential == revealed,
            "redeploy does not rotate the credential"
        );
        let versions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM grund_app_secrets WHERE app_id=$1 AND name=$2",
        )
        .bind(initial.app_id)
        .bind(secret)
        .fetch_one(&state.pool)
        .await?;
        assert_eq!(versions, 1);
    }
    Ok(())
}

#[sqlx::test(migrations = false)]
async fn user_entered_secrets_stay_write_only_even_when_replacing_a_generated_value(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    let registry = registry::FakeRegistry::start().await?;
    let state = state(pool, &registry).await?;
    let org = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let admin = Uuid::now_v7();
    membership(&state, org, owner, "owner").await?;
    membership(&state, org, admin, "admin").await?;
    let initial = launch(&state, &registry, owner, org, "database", "postgres").await?;
    let apps = state.apps();
    let key = "postgres-password";
    let generated = value(
        apps.reveal_template_credential(owner, org, "database", key)
            .await?,
    )?;
    let mut custom_spec = grund_domain::app::templates::find("postgres")
        .unwrap()
        .spec(false)
        .unwrap();
    custom_spec.image = registry.image("postgres", "test");
    let (_, custom) = apps
        .launch(
            owner,
            org,
            Launch {
                name: "custom".into(),
                settings: SettingsInput::default(),
                spec: custom_spec,
                detect_port: None,
                secrets: vec![(
                    "POSTGRES_PASSWORD".into(),
                    "user-entered-test-password".into(),
                )],
                generated_template: None,
            },
        )
        .await?;
    for actor in [owner, admin] {
        assert!(matches!(
            apps.reveal_template_credential(actor, org, "custom", key)
                .await?,
            CredentialReveal::Unavailable
        ));
    }
    assert!(
        apps.generated_credentials(org, custom.app_id)
            .await?
            .is_empty()
    );
    apps.set_secret(
        owner,
        org,
        "database",
        "user-password",
        b"user-entered-test-password",
    )
    .await?;
    let (_, version, _) = apps
        .set_secret(owner, org, "database", key, generated.as_bytes())
        .await?;
    assert_eq!(version, 2);
    for actor in [owner, admin] {
        for secret in [key, "user-password"] {
            assert!(matches!(
                apps.reveal_template_credential(actor, org, "database", secret)
                    .await?,
                CredentialReveal::Unavailable
            ));
        }
    }
    assert!(
        apps.generated_credentials(org, initial.app_id)
            .await?
            .is_empty()
    );
    assert_eq!(audit_count(&state).await?, 1);
    let pinned: Vec<i32> = sqlx::query_scalar(
        "SELECT version FROM grund_template_credentials WHERE organisation_id=$1 AND app_id=$2 AND name=$3",
    )
    .bind(org)
    .bind(initial.app_id)
    .bind(key)
    .fetch_all(&state.pool)
    .await?;
    assert_eq!(pinned, vec![1]);
    Ok(())
}

#[sqlx::test(migrations = false)]
async fn concurrent_credential_reveals_allow_five_per_actor_and_organisation_not_per_app(
    pool: sqlx::PgPool,
) -> anyhow::Result<()> {
    let registry = registry::FakeRegistry::start().await?;
    let state = state(pool, &registry).await?;
    let org = Uuid::now_v7();
    let foreign_org = Uuid::now_v7();
    let owner = Uuid::now_v7();
    let admin = Uuid::now_v7();
    membership(&state, org, owner, "owner").await?;
    membership(&state, org, admin, "admin").await?;
    membership(&state, foreign_org, owner, "owner").await?;
    launch(&state, &registry, owner, org, "first", "postgres").await?;
    launch(&state, &registry, owner, org, "second", "postgres").await?;
    launch(&state, &registry, owner, foreign_org, "first", "postgres").await?;
    let apps = state.apps();
    let results = futures_util::future::join_all((0..6).map(|index| {
        apps.reveal_template_credential(
            owner,
            org,
            if index % 2 == 0 { "first" } else { "second" },
            "postgres-password",
        )
    }))
    .await;
    let mut allowed = 0;
    let mut limited = 0;
    for result in results {
        match result? {
            CredentialReveal::Value(_) => allowed += 1,
            CredentialReveal::RateLimited => limited += 1,
            CredentialReveal::Unavailable => anyhow::bail!("an authorised credential disappeared"),
        }
    }
    assert_eq!((allowed, limited), (5, 1));
    assert_eq!(audit_count(&state).await?, 5);
    value(
        apps.reveal_template_credential(admin, org, "first", "postgres-password")
            .await?,
    )?;
    value(
        apps.reveal_template_credential(owner, foreign_org, "first", "postgres-password")
            .await?,
    )?;
    assert_eq!(audit_count(&state).await?, 7);
    assert!(matches!(
        apps.reveal_template_credential(owner, org, "second", "postgres-password")
            .await?,
        CredentialReveal::RateLimited
    ));
    assert_eq!(audit_count(&state).await?, 7);
    sqlx::query(
        "UPDATE grund_template_credential_reveals SET revealed_at=clock_timestamp()-interval '2 minutes' \
         WHERE organisation_id=$1 AND actor=$2",
    )
    .bind(org)
    .bind(owner)
    .execute(&state.pool)
    .await?;
    value(
        apps.reveal_template_credential(owner, org, "first", "postgres-password")
            .await?,
    )?;
    assert_eq!(audit_count(&state).await?, 8);
    Ok(())
}
