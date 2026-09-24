use crate::accepttest::fixtures::testcase_configured;

const CONFIGURED: &[(&str, &str)] = &[
    ("GRUND_SOCIAL_LOGIN", "true"),
    ("GRUND_GITHUB_CLIENT_ID", "accept-test-client"),
    ("GRUND_GITHUB_CLIENT_SECRET", "accept-test-secret-not-real"),
    ("GRUND_OIDC_ISSUER", "https://sso.accept.test"),
    ("GRUND_OIDC_CLIENT_ID", "accept-test-client"),
    ("GRUND_OIDC_CLIENT_SECRET", "accept-test-secret-not-real"),
];

async fn assert_refused(
    when: &crate::accepttest::fixtures::When,
    then: &crate::accepttest::fixtures::Then,
) -> anyhow::Result<()> {
    when.visiting("/health/ready").await?;
    then.status(200)?;
    when.visiting("/login").await?;
    then.status(200)?
        .body_lacks("Continue with")?
        .body_lacks("/auth/github/start")?;
    for path in [
        "/auth/github/start",
        "/auth/oidc/start",
        "/auth/google/start",
        "/auth/github/callback?code=anything&state=anything",
        "/auth/complete",
        "/auth/link",
    ] {
        when.visiting(path).await?;
        then.status(403)
            .and_then(|t| t.body_contains("Social sign-in needs a grund license"))
            .and_then(|t| t.header_lacks("location", "github.com"))
            .map_err(|error| error.context(path))?;
    }
    when.posting_raw("/auth/complete", &[("username", "someone")], None)
        .await?;
    then.status(403)?;
    Ok(())
}

#[tokio::test]
async fn social_sign_in_configured_without_a_license_starts_offers_no_provider_and_refuses_every_route()
-> anyhow::Result<()> {
    let Some((_given, when, then)) = testcase_configured(CONFIGURED).await? else {
        return Ok(());
    };
    assert_refused(&when, &then).await
}

#[tokio::test]
async fn a_license_key_this_build_does_not_trust_is_the_same_as_none() -> anyhow::Result<()> {
    let forged = "grund-license-v1.eyJ2IjoxLCJraWQiOiJmb3JnZWQiLCJpZCI6IngiLCJwbGFuIjoicHJvIiwiZmVhdHVyZXMiOlsic29jaWFsX2xvZ2luIl0sIm5vdF9iZWZvcmUiOjAsImV4cGlyZXNfYXQiOjQwMDAwMDAwMDB9.AAAA";
    let mut env = CONFIGURED.to_vec();
    env.push(("GRUND_LICENSE_KEY", forged));
    let Some((_given, when, then)) = testcase_configured(&env).await? else {
        return Ok(());
    };
    assert_refused(&when, &then).await
}
