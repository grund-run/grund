use std::time::{Duration, Instant};

use crate::accepttest::fixtures::{
    AccountAnswer, BILLING_TOKEN, DeletionAnswer, FakeBilling, testcase_configured,
};

#[tokio::test]
async fn enabling_billing_backfills_organisations_created_while_billing_was_off()
-> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let billing =
        FakeBilling::start_with_account(DeletionAnswer::Allow, AccountAnswer::Free).await?;
    given
        .testcase
        .fixture
        .restart_with(&[
            ("GRUND_BILLING_URL", &billing.url),
            ("GRUND_BILLING_TOKEN", BILLING_TOKEN),
        ])
        .await?;

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if billing.calls("RecordOrganisation").iter().any(|call| {
            call.body["slug"] == owner.username
                && call.body["change"] == "ORGANISATION_CHANGE_CREATED"
        }) {
            break;
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "existing organisation was not seeded as a creation"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}
