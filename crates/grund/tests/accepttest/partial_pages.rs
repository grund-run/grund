use crate::accepttest::fixtures::{csrf_of, form_encode, testcase, testcase_with_mail};

fn layout_of(html: &str) -> anyhow::Result<String> {
    let start = html
        .find("<html lang=\"en\" sedx-layout=\"")
        .map(|at| at + "<html lang=\"en\" sedx-layout=\"".len())
        .ok_or_else(|| anyhow::anyhow!("the page names no sedx layout"))?;
    Ok(html[start..].chars().take_while(|c| *c != '"').collect())
}

#[tokio::test]
async fn a_signed_in_page_the_browser_already_shows_is_answered_with_its_regions()
-> anyhow::Result<()> {
    let (given, when, then) = testcase().await?;
    let account = given.a_signed_in_account().await?;
    let org = account.username.clone();

    when.visiting(&format!("/{org}/apps")).await?;
    then.status(200)?.header_contains("vary", "sedx-layout")?;
    let full = then.body()?;
    let layout = layout_of(&full)?;
    anyhow::ensure!(layout.len() == 16, "{layout}");
    anyhow::ensure!(
        full.contains("<head sedx-region=\"0\">") && full.contains("<body sedx-region=\"1\">"),
        "the head and the body are the layout's regions"
    );

    when.requesting_with(
        "GET",
        &format!("/{org}/machines"),
        &[("Sedx-Layout", &layout)],
        None,
    )
    .await?;
    then.status(200)?
        .carries_the_security_headers()?
        .header("cache-control", "no-store")?
        .header("sedx-layout", &layout)?
        .header_contains("vary", "sedx-layout")?
        .body_contains("<body sedx-region=\"1\">")?
        .body_contains("class=\"shell\"")?
        .body_contains("Add machine")?;
    let partial = then.body()?;
    anyhow::ensure!(
        partial.len() < full.len() + 4096,
        "a partial page is not larger than a page"
    );
    Ok(())
}

#[tokio::test]
async fn a_page_from_another_build_of_the_layout_gets_the_whole_page() -> anyhow::Result<()> {
    let (given, when, _then) = testcase().await?;
    let account = given.a_signed_in_account().await?;
    let response = when
        .send(
            "GET",
            &format!("/{}/apps", account.username),
            &[("Sedx-Layout", "0123456789abcdef")],
            None,
        )
        .await?;
    anyhow::ensure!(response.status == 200, "status {}", response.status);
    anyhow::ensure!(
        response.header("sedx-layout").is_none(),
        "no partial render for an id this build does not have"
    );
    let body = response.text();
    anyhow::ensure!(body.starts_with("<!doctype html>") && body.contains("class=\"shell\""));
    Ok(())
}

#[tokio::test]
async fn signing_in_from_the_script_answers_with_sedx_location_and_the_session_cookie()
-> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.an_account().await?;
    let page = when.send("GET", "/login", &[], None).await?.text();
    let csrf = csrf_of(&page).ok_or_else(|| anyhow::anyhow!("no csrf field"))?;
    let layout = layout_of(&page)?;
    let origin = when.form_origin();
    let body = form_encode(&[
        ("csrf", &csrf),
        ("login", &account.username),
        ("password", &account.password),
    ]);
    when.requesting_with(
        "POST",
        "/login",
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Origin", &origin),
            ("Sec-Fetch-Site", "same-origin"),
            ("Sedx-Layout", &layout),
        ],
        Some(body.as_bytes()),
    )
    .await?;
    then.status(204)?
        .header("sedx-location", "/")?
        .header_lacks("location", "/")?;
    then.sets_cookie("grund_session")?;
    Ok(())
}

#[tokio::test]
async fn a_form_posted_without_the_script_still_redirects() -> anyhow::Result<()> {
    let Some((given, when, then)) = testcase_with_mail().await? else {
        return Ok(());
    };
    let account = given.an_account().await?;
    when.signing_in(&account.username, &account.password)
        .await?;
    then.status(303)?.redirects_to("/")?;
    Ok(())
}

#[tokio::test]
async fn signed_in_pages_load_sedx_before_grund_js_and_both_are_cached_for_a_year()
-> anyhow::Result<()> {
    let (given, when, then) = testcase().await?;
    let account = given.a_signed_in_account().await?;
    when.visiting(&format!("/{}/apps", account.username))
        .await?;
    let page = then.body()?;
    let sedx = page
        .find("/static/sedx.js?v=")
        .ok_or_else(|| anyhow::anyhow!("signed-in pages load sedx.js"))?;
    let grund = page
        .find("/static/grund.js?v=")
        .ok_or_else(|| anyhow::anyhow!("signed-in pages load grund.js"))?;
    anyhow::ensure!(
        sedx < grund,
        "sedx.js runs before grund.js, which listens for sedx:load"
    );
    let href: String = page[sedx..].chars().take_while(|c| *c != '"').collect();
    when.visiting(&href).await?;
    then.status(200)?
        .header_contains("content-type", "text/javascript")?
        .header("cache-control", "public, max-age=31536000, immutable")?
        .body_contains("sedx-layout")?;

    when.visiting("/login").await?;
    then.body_lacks("/static/sedx.js")?;
    Ok(())
}
