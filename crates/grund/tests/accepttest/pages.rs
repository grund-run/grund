use crate::accepttest::fixtures::testcase;

const PAGES: &[&str] = &[
    "/login",
    "/signup",
    "/reset",
    "/reset/sent",
    "/signup/sent",
    "/verify?token=x",
    "/reset/confirm?token=x",
    "/licenses",
    "/style-guide",
    "/no/such/page",
];

#[tokio::test]
async fn every_page_is_html_that_needs_nothing_the_csp_forbids_and_is_never_cached()
-> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;

    for path in PAGES {
        when.visiting(path).await?;
        then.carries_the_security_headers()
            .and_then(|t| t.header_contains("content-type", "text/html"))
            .and_then(|t| t.header("cache-control", "no-store"))
            .and_then(|t| t.body_lacks(" style="))
            .and_then(|t| t.body_lacks("<style"))
            .and_then(|t| t.body_lacks(" onclick="))
            .map_err(|error| error.context(*path))?;
        only_the_script_file(&then.body()?).map_err(|error| error.context(*path))?;
    }
    Ok(())
}

fn only_the_script_file(body: &str) -> anyhow::Result<()> {
    let scripts = body.matches("<script").count();
    let linked = body.matches("<script src=\"/static/grund.js?v=").count();
    anyhow::ensure!(
        scripts == linked && linked <= 1,
        "a page loads only /static/grund.js, and no inline script"
    );
    Ok(())
}

const ORG_PAGES: &[&str] = &[
    "",
    "/apps",
    "/apps?view=grid&sort=deployed&q=x",
    "/deploy",
    "/deploy?mode=premade",
    "/deploy?template=nginx",
    "/domains",
    "/templates",
    "/machines",
    "/machines?tab=disconnected&q=x",
    "/machines/add",
    "/settings",
    "/settings/members",
    "/settings/tokens",
    "/settings/registries",
    "/settings/about",
];

#[tokio::test]
async fn every_signed_in_page_renders_in_the_shell_with_nothing_the_csp_forbids()
-> anyhow::Result<()> {
    let (given, when, then) = testcase().await?;
    let account = given.a_signed_in_account().await?;
    let org = account.username.clone();
    let pages = ORG_PAGES
        .iter()
        .map(|page| format!("/{org}{page}"))
        .chain(["/settings/sessions".to_string(), "/orgs/new".to_string()]);
    let mut script = None;
    for path in &pages.collect::<Vec<_>>() {
        when.visiting(path).await?;
        then.status(200)
            .and_then(|t| t.carries_the_security_headers())
            .and_then(|t| t.header("cache-control", "no-store"))
            .and_then(|t| t.body_contains("class=\"shell\""))
            .and_then(|t| t.body_contains("Sign out</button>"))
            .and_then(|t| t.body_lacks(" style="))
            .and_then(|t| t.body_lacks("<style"))
            .and_then(|t| t.body_lacks(" onclick="))
            .map_err(|error| error.context(path.clone()))?;
        let body = then.body()?;
        only_the_script_file(&body).map_err(|error| error.context(path.clone()))?;
        if path.starts_with(&format!("/{org}")) {
            let own_search = path.contains("/machines");
            anyhow::ensure!(
                body.contains("placeholder=\"Search apps…\"") != own_search,
                "{path} has the app search unless it has its own"
            );
            let action = match path.split('?').next().unwrap_or_default() {
                p if p.ends_with("/deploy") || p.ends_with("/machines/add") => None,
                p if p.ends_with("/machines") => Some("Add machine"),
                _ => Some("Deploy app"),
            };
            let buttons = body.matches("<span class=\"btn-label\">").count();
            anyhow::ensure!(
                action.map_or(buttons == 0, |action| {
                    buttons == 1
                        && body.contains(&format!("<span class=\"btn-label\">{action}</span>"))
                }),
                "{path} has its section's one top bar action, {action:?}"
            );
        }
        let start = body.find("/static/grund.js?v=");
        script = start.map(|start| {
            body[start..]
                .chars()
                .take_while(|c| *c != '"')
                .collect::<String>()
        });
    }
    when.visiting(&format!("/{org}/templates")).await?;
    then.body_contains("Needs storage")?
        .body_contains("aria-current=\"page\">")?;

    let script = script.expect("signed-in pages load the script");
    when.visiting(&script).await?;
    then.status(200)?
        .header_contains("content-type", "text/javascript")?
        .header("cache-control", "public, max-age=31536000, immutable")?
        .body_contains("data-copy")?;
    Ok(())
}

#[tokio::test]
async fn every_organisation_page_is_a_404_to_someone_outside_it() -> anyhow::Result<()> {
    let (given, _when, _then) = testcase().await?;
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    for page in ORG_PAGES {
        outsider_when.visiting(&format!("/{org}{page}")).await?;
        outsider_then
            .status(404)
            .map_err(|error| error.context(*page))?;
    }
    Ok(())
}

#[tokio::test]
async fn an_unknown_page_is_a_404_page() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;
    when.visiting("/no/such/page").await?;
    then.status(404)?.body_contains("Not found")?;
    Ok(())
}

#[tokio::test]
async fn the_stylesheet_each_page_links_is_served_and_cached_for_a_year() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;
    let page = when.send("GET", "/login", &[], None).await?.text();
    let start = page
        .find("/static/grund.css?v=")
        .expect("the page links its stylesheet");
    let href: String = page[start..].chars().take_while(|c| *c != '"').collect();

    when.visiting(&href).await?;
    then.status(200)?
        .header_contains("content-type", "text/css")?
        .header("cache-control", "public, max-age=31536000, immutable")?
        .body_contains("--accent")?;
    for font in [
        "/static/fonts/inter-latin.woff2",
        "/static/fonts/jetbrains-mono-latin.woff2",
        "/static/favicon.svg",
        "/static/mark.svg",
    ] {
        when.visiting(font).await?;
        then.status(200).map_err(|e| e.context(font))?;
    }
    when.visiting("/static/../Cargo.toml").await?;
    then.status_in(&[400, 404])?;
    Ok(())
}

#[tokio::test]
async fn the_grund_yaml_schema_is_served_to_anyone_and_describes_the_file() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;
    when.visiting("/schema/grund.json").await?;
    then.status(200)?
        .header("content-type", "application/schema+json")?
        .header("cache-control", "public, max-age=3600")?
        .header("access-control-allow-origin", "*")?;
    let schema = then.json()?;
    anyhow::ensure!(
        schema["$schema"] == "http://json-schema.org/draft-07/schema#",
        "{schema}"
    );
    anyhow::ensure!(schema["title"] == "grund.yaml", "{schema}");
    anyhow::ensure!(
        schema
            == serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../../schema/grund.json"
            ))?,
        "the instance serves the schema the repository keeps"
    );
    Ok(())
}

#[tokio::test]
async fn pages_whose_address_carries_a_token_send_referrers_only_to_this_origin()
-> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;
    for path in ["/verify?token=abc", "/reset/confirm?token=abc"] {
        when.visiting(path).await?;
        then.status(200)?
            .header("referrer-policy", "same-origin")
            .map_err(|e| e.context(path))?;
    }
    Ok(())
}

#[tokio::test]
async fn every_response_says_which_request_it_was() -> anyhow::Result<()> {
    let (_given, when, then) = testcase().await?;
    when.requesting_with("GET", "/login", &[("X-Request-Id", "caller-chosen")], None)
        .await?;
    then.header_lacks("x-request-id", "caller-chosen")?;
    let id = when
        .send("GET", "/login", &[], None)
        .await?
        .header("x-request-id")
        .map(str::to_string);
    anyhow::ensure!(id.is_some_and(|id| id.len() == 36), "no request id");
    Ok(())
}

#[tokio::test]
async fn the_about_page_names_the_revision_readiness_reports() -> anyhow::Result<()> {
    let (given, when, then) = testcase().await?;
    let account = given.a_signed_in_account().await?;
    when.requesting("GET", "/health/ready").await?;
    let revision = then.json()?["revision"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    when.visiting(&format!("/{}/settings/about", account.username))
        .await?;
    then.status(200)?
        .body_contains(&revision)?
        .body_contains("aria-current=\"page\">About")?;
    Ok(())
}
