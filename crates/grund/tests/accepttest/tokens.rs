use serde_json::{Value, json};

use crate::accepttest::fixtures::{FakeRegistry, Given, Then, When, testcase_configured};

const APPS: &str = "/grund.app.v1.AppService";
const GET_VIEWER: &str = "/grund.account.v1.AccountService/GetViewer";

async fn a_token(when: &When, then: &Then, org: &str, name: &str) -> anyhow::Result<String> {
    let page = format!("/{org}/settings/tokens");
    when.submitting(&page, &page, &[("name", name), ("days", "30")])
        .await?;
    then.status(200)?
        .header("cache-control", "no-store")?
        .body_contains("the only time grund shows it")?;
    let html = then.body()?;
    let start = html
        .find("grund_pat_")
        .ok_or_else(|| anyhow::anyhow!("the page that answers the form shows no token: {html}"))?;
    Ok(html[start..start + "grund_pat_".len() + 43].to_string())
}

async fn calling_with_token(
    when: &When,
    token: &str,
    procedure: &str,
    body: Value,
) -> anyhow::Result<()> {
    let bearer = format!("Bearer {token}");
    when.calling_with(
        &format!("{APPS}/{procedure}"),
        &body.to_string(),
        &[("Authorization", &bearer)],
    )
    .await?;
    Ok(())
}

fn ci(given: &Given) -> (When, Then) {
    let (_, when, then) = given.testcase.another_browser();
    (when, then)
}

fn spec(image: &str) -> Value {
    json!({
        "image": image,
        "ports": [{"name": "http", "port": 80}],
        "resources": {"memoryMib": "64", "cpuMillis": 100},
    })
}

#[tokio::test]
async fn ci_deploys_with_a_token_and_no_session_in_the_tokens_organisation_only()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let other_org = given.a_fresh_name("team");
    when.submitting("/orgs/new", "/orgs/new", &[("slug", &other_org)])
        .await?;
    then.status(303)?;
    let token = a_token(&when, &then, org, "github actions").await?;
    let digest = registry.publish("acme/shop", "1");

    let (ci_when, ci_then) = ci(&given);
    calling_with_token(
        &ci_when,
        &token,
        "CreateApp",
        json!({"organisation": org, "name": "shop"}),
    )
    .await?;
    ci_then.status(200)?.header("cache-control", "no-store")?;
    calling_with_token(
        &ci_when,
        &token,
        "Deploy",
        json!({"organisation": org, "name": "shop", "spec": spec(&registry.image("acme/shop", "1")), "note": "from CI"}),
    )
    .await?;
    ci_then.status(200)?;
    let release = ci_then.json()?["release"].clone();
    anyhow::ensure!(release["number"] == 1, "{release}");
    anyhow::ensure!(release["imageDigest"] == digest.as_str(), "{release}");
    anyhow::ensure!(release["source"] == "RELEASE_SOURCE_API", "{release}");
    anyhow::ensure!(
        release["createdBy"] == owner.username.as_str(),
        "a token's release is its maker's: {release}"
    );
    anyhow::ensure!(
        ci_when.testcase.data().cookies.is_empty(),
        "a token call set a cookie"
    );
    let second = registry.publish("acme/shop", "2");
    let file = format!(
        "[apps.shop]\nimage = \"{}\"\n\n[[apps.shop.ports]]\nname = \"http\"\nport = 80\n",
        registry.image("acme/shop", "2")
    );
    calling_with_token(
        &ci_when,
        &token,
        "Deploy",
        json!({"organisation": org, "name": "shop", "grundToml": file}),
    )
    .await?;
    ci_then.status(200)?;
    let release = ci_then.json()?["release"].clone();
    anyhow::ensure!(release["number"] == 2, "{release}");
    anyhow::ensure!(release["imageDigest"] == second.as_str(), "{release}");
    anyhow::ensure!(release["source"] == "RELEASE_SOURCE_FILE", "{release}");

    calling_with_token(
        &ci_when,
        &token,
        "ListApps",
        json!({"organisation": other_org}),
    )
    .await?;
    ci_then.status(404)?.connect_code("not_found")?;
    calling_with_token(
        &ci_when,
        &token,
        "CreateApp",
        json!({"organisation": other_org, "name": "shop"}),
    )
    .await?;
    ci_then.status(404)?.connect_code("not_found")?;
    when.calling(
        &format!("{APPS}/ListApps"),
        &json!({"organisation": other_org}).to_string(),
    )
    .await?;
    then.status(200)?;
    anyhow::ensure!(
        then.json()?["apps"].as_array().is_none_or(Vec::is_empty),
        "the token's call made an app in the other organisation"
    );

    calling_with_token(
        &ci_when,
        &token,
        "DeleteApp",
        json!({"organisation": org, "name": "shop"}),
    )
    .await?;
    ci_then.status(403)?.connect_code("permission_denied")?;
    let bearer = format!("Bearer {token}");
    ci_when
        .calling_with(GET_VIEWER, "{}", &[("Authorization", &bearer)])
        .await?;
    ci_then.status(403)?.connect_code("permission_denied")?;

    let fixture = &given.testcase.fixture;
    anyhow::ensure!(
        fixture.count(&format!(
            "SELECT count(*) FROM grund_api_tokens WHERE token_digest = sha256('{token}'::bytea)"
        ))
        .await?
            == 1,
        "the token's SHA-256 is what is stored"
    );
    anyhow::ensure!(
        !fixture.log().contains(&token),
        "grund's log carries the token"
    );
    when.visiting(&format!("/{org}/settings/tokens")).await?;
    then.status(200)?
        .body_contains("github actions")?
        .body_lacks(&token)?;
    Ok(())
}

#[tokio::test]
async fn a_revoked_or_expired_token_is_refused_and_another_account_cannot_see_or_revoke_one()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.as_str();
    let kept = a_token(&when, &then, org, "kept").await?;
    let revoked = a_token(&when, &then, org, "to revoke").await?;
    let expired = a_token(&when, &then, org, "to expire").await?;
    let (ci_when, ci_then) = ci(&given);
    let list = json!({"organisation": org});
    for token in [&kept, &revoked, &expired] {
        calling_with_token(&ci_when, token, "ListApps", list.clone()).await?;
        ci_then.status(200)?;
    }
    let fixture = &given.testcase.fixture;
    let id_of = |name: &str| {
        format!(
            "SELECT token_id::text FROM grund_api_tokens WHERE name = '{name}' AND organisation_id = \
             (SELECT organisation_id FROM grund_organisations WHERE slug = '{org}')"
        )
    };
    let revoked_id = scalar(fixture, &id_of("to revoke")).await?;

    let (stranger_given, stranger, stranger_then) = given.testcase.another_browser();
    let stranger_account = stranger_given.a_signed_in_account().await?;
    stranger
        .visiting(&format!("/{org}/settings/tokens"))
        .await?;
    stranger_then.status(404)?.body_lacks("to revoke")?;
    let stranger_page = format!("/{}/settings/tokens", stranger_account.username);
    stranger.visiting(&stranger_page).await?;
    stranger_then.status(200)?.body_lacks("to revoke")?;
    stranger
        .submitting_on_current_page(
            &format!(
                "/{}/settings/tokens/{revoked_id}/revoke",
                stranger_account.username
            ),
            &[],
        )
        .await?;
    stranger_then.redirects_to(&format!("{stranger_page}?error=gone"))?;
    stranger.visiting(&stranger_page).await?;
    stranger
        .submitting_on_current_page(&format!("/{org}/settings/tokens/{revoked_id}/revoke"), &[])
        .await?;
    stranger_then.status(404)?;
    stranger.visiting(&stranger_page).await?;
    stranger
        .submitting_on_current_page(&format!("/{org}/settings/tokens"), &[("name", "mine")])
        .await?;
    stranger_then.status(404)?;
    calling_with_token(&ci_when, &revoked, "ListApps", list.clone()).await?;
    ci_then.status(200)?;

    when.visiting(&format!("/{org}/settings/tokens")).await?;
    when.submitting_on_current_page(&format!("/{org}/settings/tokens/{revoked_id}/revoke"), &[])
        .await?;
    then.redirects_to(&format!("/{org}/settings/tokens?done=revoked"))?;
    fixture
        .sql(
            "UPDATE grund_api_tokens SET created_at = clock_timestamp() - interval '2 days', \
             expires_at = clock_timestamp() - interval '1 second' WHERE name = 'to expire'",
        )
        .await?;

    for token in [&revoked, &expired] {
        calling_with_token(&ci_when, token, "ListApps", list.clone()).await?;
        ci_then.status(401)?.connect_code("unauthenticated")?;
    }
    calling_with_token(&ci_when, &kept, "ListApps", list.clone()).await?;
    ci_then.status(200)?;
    let forged = format!("grund_pat_{}", "A".repeat(43));
    calling_with_token(&ci_when, &forged, "ListApps", list.clone()).await?;
    ci_then.status(401)?.connect_code("unauthenticated")?;
    ci_when
        .calling_with(
            &format!("{APPS}/ListApps"),
            &list.to_string(),
            &[("Authorization", "Basic Zm9vOmJhcg==")],
        )
        .await?;
    ci_then.status(401)?.connect_code("unauthenticated")?;

    when.visiting(&format!("/{org}/settings/tokens")).await?;
    then.status(200)?
        .body_contains("kept")?
        .body_lacks("to revoke")?
        .body_lacks("to expire")?;
    Ok(())
}

#[tokio::test]
async fn a_token_cannot_borrow_a_session_cookie_sent_beside_it() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    given.a_signed_in_account().await?;
    when.calling_with(
        GET_VIEWER,
        "{}",
        &[("Authorization", "Bearer grund_pat_nope")],
    )
    .await?;
    then.status(401)?.connect_code("unauthenticated")?;
    when.calling(GET_VIEWER, "{}").await?;
    then.status(200)?;
    Ok(())
}

async fn scalar(
    fixture: &crate::accepttest::fixtures::Fixture,
    query: &str,
) -> anyhow::Result<String> {
    let url = fixture
        .database_url()
        .ok_or_else(|| anyhow::anyhow!("only a spawned instance has a database"))?;
    let mut connection = <sqlx::PgConnection as sqlx::Connection>::connect(&url).await?;
    Ok(
        sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(query.to_string()))
            .fetch_one(&mut connection)
            .await?,
    )
}
