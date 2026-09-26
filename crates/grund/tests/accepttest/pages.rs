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
            .and_then(|t| t.body_lacks("<script"))
            .and_then(|t| t.body_lacks(" style="))
            .and_then(|t| t.body_lacks("<style"))
            .and_then(|t| t.body_lacks(" onclick="))
            .map_err(|error| error.context(*path))?;
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
