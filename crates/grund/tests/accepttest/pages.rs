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

#[tokio::test]
async fn every_signed_in_page_renders_in_the_shell_with_nothing_the_csp_forbids()
-> anyhow::Result<()> {
    let (given, when, then) = testcase().await?;
    let account = given.a_signed_in_account().await?;
    let org = account.username.clone();
    let pages = [
        format!("/{org}"),
        format!("/{org}/apps"),
        format!("/{org}/apps?view=grid&sort=deployed&q=x"),
        format!("/{org}/deploy"),
        format!("/{org}/domains"),
        format!("/{org}/templates"),
        format!("/{org}/machines"),
        format!("/{org}/settings"),
        format!("/{org}/settings/members"),
        "/settings/sessions".to_string(),
        "/orgs/new".to_string(),
    ];
    let mut script = None;
    for path in &pages {
        when.visiting(path).await?;
        then.status(200)
            .and_then(|t| t.carries_the_security_headers())
            .and_then(|t| t.header("cache-control", "no-store"))
            .and_then(|t| t.body_contains("class=\"shell\""))
            .and_then(|t| t.body_contains("action=\"/logout\""))
            .and_then(|t| t.body_lacks(" style="))
            .and_then(|t| t.body_lacks("<style"))
            .and_then(|t| t.body_lacks(" onclick="))
            .map_err(|error| error.context(path.clone()))?;
        let body = then.body()?;
        only_the_script_file(&body).map_err(|error| error.context(path.clone()))?;
        if path.starts_with(&format!("/{org}")) {
            anyhow::ensure!(
                body.contains("placeholder=\"Search apps…\""),
                "{path} has the search"
            );
            anyhow::ensure!(
                path.ends_with("/deploy")
                    || body.contains("<span class=\"btn-label\">Deploy app</span>"),
                "{path} has the deploy button"
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
    then.body_contains("Templates are in development")?
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
async fn the_new_organisation_pages_are_a_404_to_someone_outside_it() -> anyhow::Result<()> {
    let (given, _when, _then) = testcase().await?;
    let owner = given.a_signed_in_account().await?;
    let org = owner.username.clone();
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    for path in ["deploy", "domains", "templates"] {
        outsider_when.visiting(&format!("/{org}/{path}")).await?;
        outsider_then
            .status(404)
            .map_err(|error| error.context(path))?;
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
