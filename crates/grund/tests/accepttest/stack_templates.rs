use anyhow::{Context, ensure};
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::accepttest::fixtures::{FakeRegistry, Then, When, testcase_configured};

const STACKS: &str = "/grund.stack.v1.StackService";

async fn call(when: &When, then: &Then, method: &str, body: Value) -> anyhow::Result<Value> {
    when.calling(&format!("{STACKS}/{method}"), &body.to_string())
        .await?;
    then.json()
}

async fn resources(pool: &PgPool) -> anyhow::Result<Value> {
    Ok(sqlx::query_scalar(
        "SELECT jsonb_build_object(\
         'stacks',(SELECT count(*) FROM grund_stacks),\
         'members',(SELECT count(*) FROM grund_stack_members),\
         'apps',(SELECT count(*) FROM grund_apps),\
         'volumes',(SELECT count(*) FROM grund_volumes),\
         'secrets',(SELECT count(*) FROM grund_app_secrets),\
         'credentials',(SELECT count(*) FROM grund_template_credentials),\
         'requests',(SELECT count(*) FROM grund_stack_requests))",
    )
    .fetch_one(pool)
    .await?)
}

#[tokio::test]
async fn a_disabled_catalogue_service_rejects_the_entire_plan_without_creating_children()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let database = given
        .testcase
        .fixture
        .database_url()
        .context("spawned database")?;
    let pool = PgPool::connect(&database).await?;
    registry.publish("acme/web", "1");
    let yaml = format!(
        "stack:\n  name: disabled\n  services:\n    app:\n      image: {}\n    object-store:\n      template: minio\n",
        registry.image("acme/web", "1"),
    );
    let before = resources(&pool).await?;
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM es_events")
        .fetch_one(&pool)
        .await?;
    for method in ["PreviewStack", "DeployStack"] {
        let mut request = json!({"organisation":owner.username,"yaml":yaml});
        if method == "DeployStack" {
            request["idempotencyKey"] = json!("disabled-template");
        }
        call(&when, &then, method, request).await?;
        then.status(400)?.connect_code("invalid_argument")?;
        ensure!(
            resources(&pool).await? == before,
            "a rejected catalogue plan created durable resources"
        );
        let after: i64 = sqlx::query_scalar("SELECT count(*) FROM es_events")
            .fetch_one(&pool)
            .await?;
        ensure!(after == events, "a rejected catalogue plan appended events");
    }
    call(
        &when,
        &then,
        "GetStack",
        json!({"organisation":owner.username,"name":"disabled"}),
    )
    .await?;
    then.status(404)?.connect_code("not_found")?;
    Ok(())
}

#[tokio::test]
async fn an_existing_writer_cannot_become_a_template_or_gain_copies_by_omitting_mounts()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let database = given
        .testcase
        .fixture
        .database_url()
        .context("spawned database")?;
    let pool = PgPool::connect(&database).await?;
    registry.publish("acme/writer", "1");
    let image = registry.image("acme/writer", "1");
    let yaml = format!(
        "stack:\n  name: retained\n  services:\n    writer:\n      image: {image}\n      volumes:\n        data:\n          path: /data\n",
    );
    let created = call(
        &when,
        &then,
        "DeployStack",
        json!({"organisation":owner.username,"yaml":yaml,"idempotencyKey":"writer-created"}),
    )
    .await?;
    then.status(200)?;
    let id = created["stack"]["services"][0]["appId"]
        .as_str()
        .context("stable writer identity")?
        .parse::<uuid::Uuid>()?;
    let volumes: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT volume_id FROM grund_volumes WHERE app_id=$1 ORDER BY volume_id",
    )
    .bind(id)
    .fetch_all(&pool)
    .await?;
    ensure!(volumes.len() == 1, "the writer owns exactly one volume");
    let before = resources(&pool).await?;
    for (key, replacement) in [
        (
            "writer-template-conversion",
            "      template: postgres\n".to_string(),
        ),
        (
            "writer-copy-expansion",
            format!("      image: {image}\n      copies: 2\n"),
        ),
    ] {
        let changed = format!("stack:\n  name: retained\n  services:\n    writer:\n{replacement}");
        for method in ["PreviewStack", "DeployStack"] {
            let mut request = json!({"organisation":owner.username,"yaml":changed});
            if method == "DeployStack" {
                request["expectedVersion"] = created["stack"]["version"].clone();
                request["idempotencyKey"] = json!(key);
            }
            call(&when, &then, method, request).await?;
            then.status(400)?.connect_code("invalid_argument")?;
            ensure!(
                resources(&pool).await? == before,
                "a rejected writer conversion changed durable resources"
            );
        }
    }
    let state: Value = sqlx::query_scalar("SELECT state FROM grund_stacks WHERE stack_id=$1")
        .bind(
            created["stack"]["id"]
                .as_str()
                .context("stack identity")?
                .parse::<uuid::Uuid>()?,
        )
        .fetch_one(&pool)
        .await?;
    ensure!(state["revisions"]["1"]["services"]["writer"]["app_id"] == id.to_string());
    ensure!(state["revisions"]["1"]["services"]["writer"]["settings"]["copies"] == 1);
    let after: Vec<uuid::Uuid> = sqlx::query_scalar(
        "SELECT volume_id FROM grund_volumes WHERE app_id=$1 ORDER BY volume_id",
    )
    .bind(id)
    .fetch_all(&pool)
    .await?;
    ensure!(
        after == volumes,
        "rejection retains the original data volume identity"
    );
    Ok(())
}
