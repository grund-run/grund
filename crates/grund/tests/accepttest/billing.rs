use std::time::{Duration, Instant};

use serde_json::json;

use crate::accepttest::fixtures::{
    AccountAnswer, BILLING_TOKEN, DeletionAnswer, FakeBilling, testcase_configured,
};

fn form_key(when: &crate::accepttest::fixtures::When, index: usize) -> anyhow::Result<String> {
    let data = when.testcase.data();
    let page = data
        .last
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("billing page not loaded"))?
        .text();
    let marker = "name=\"idempotency_key\" value=\"";
    let key = page
        .split(marker)
        .nth(index + 1)
        .and_then(|part| part.split('\"').next())
        .ok_or_else(|| anyhow::anyhow!("billing form key missing"))?;
    Ok(key.to_owned())
}

async fn eventually_account(
    when: &crate::accepttest::fixtures::When,
    then: &crate::accepttest::fixtures::Then,
    path: &str,
    expected: &str,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        when.visiting(path).await?;
        then.status(200)?;
        if then.body_contains(expected).is_ok() {
            return Ok(());
        }
        anyhow::ensure!(Instant::now() < deadline, "{path} never showed {expected}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn configured(
    billing: &FakeBilling,
    operator: &str,
) -> anyhow::Result<
    Option<(
        crate::accepttest::fixtures::Given,
        crate::accepttest::fixtures::When,
        crate::accepttest::fixtures::Then,
    )>,
> {
    testcase_configured(&[
        ("GRUND_BILLING_URL", &billing.url),
        ("GRUND_BILLING_TOKEN", BILLING_TOKEN),
        (
            "GRUND_BILLING_REDIRECT_ORIGINS",
            "https://billing.accept.test",
        ),
        ("GRUND_OPERATOR_ORGANISATION", operator),
    ])
    .await
}

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
            (
                "GRUND_BILLING_REDIRECT_ORIGINS",
                "https://billing.accept.test",
            ),
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

#[tokio::test]
async fn an_owner_can_begin_checkout_without_a_payment_return_marking_the_plan_paid()
-> anyhow::Result<()> {
    let billing =
        FakeBilling::start_with_account(DeletionAnswer::Allow, AccountAnswer::Free).await?;
    let Some((given, when, then)) = configured(&billing, "ops-accept").await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let path = format!("/{}/settings/billing", owner.username);
    when.visiting(&path).await?;
    then.status(200)?
        .body_contains("First own machine free")?
        .body_contains("€49 per month")?;
    let key = form_key(&when, 0)?;
    when.submitting_on_current_page(
        &format!("{path}/choose"),
        &[("plan", "Pro"), ("idempotency_key", &key)],
    )
    .await?;
    then.redirects_to("https://billing.accept.test/checkout")?
        .header_contains(
            "content-security-policy",
            "form-action 'self' https://billing.accept.test",
        )?
        .header("referrer-policy", "no-referrer")?;
    let calls = billing
        .wait_for("BeginCheckout", 1, Duration::from_secs(5))
        .await?;
    anyhow::ensure!(
        calls[0].authorization.as_deref() == Some(format!("Bearer {BILLING_TOKEN}").as_str()),
        "authenticated billing call required"
    );
    eventually_account(&when, &then, &path, "Continue to checkout").await?;
    then.status(200)?
        .body_contains("Free")?
        .body_contains("Continue to checkout")?;
    Ok(())
}

#[tokio::test]
async fn owners_change_cancel_and_open_the_portal_but_outsiders_and_forged_forms_cannot()
-> anyhow::Result<()> {
    let billing = FakeBilling::start(DeletionAnswer::Allow).await?;
    let Some((given, when, then)) = configured(&billing, "ops-accept").await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let path = format!("/{}/settings/billing", owner.username);
    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    outsider_when.visiting(&path).await?;
    outsider_then.status(404)?;
    outsider_when.visiting_home().await?;
    outsider_when
        .submitting_on_current_page(&format!("{path}/choose"), &[("plan", "Business")])
        .await?;
    outsider_then.status(404)?;
    eventually_account(&when, &then, &path, "Change plan").await?;
    then.status(200)?.body_contains("Pro")?;
    let origin = when.testcase.fixture.origin.serialized();
    when.posting_raw(
        &format!("{path}/choose"),
        &[("plan", "Business")],
        Some(&origin),
    )
    .await?;
    then.status(403)?;
    anyhow::ensure!(
        billing.calls("ChangePlan").is_empty(),
        "forgery reached billing"
    );
    eventually_account(&when, &then, &path, "Change plan").await?;
    let key = form_key(&when, 0)?;
    when.submitting_on_current_page(
        &format!("{path}/choose"),
        &[("plan", "Business"), ("idempotency_key", &key)],
    )
    .await?;
    then.redirects_to(&format!("{path}?done=changed"))?;
    eventually_account(&when, &then, &path, "Change plan").await?;
    let key = form_key(&when, 1)?;
    when.submitting_on_current_page(&format!("{path}/portal"), &[("idempotency_key", &key)])
        .await?;
    then.redirects_to("https://billing.accept.test/portal")?
        .header_contains(
            "content-security-policy",
            "form-action 'self' https://billing.accept.test",
        )?;
    eventually_account(&when, &then, &path, "Change plan").await?;
    let key = form_key(&when, 2)?;
    when.submitting_on_current_page(&format!("{path}/cancel"), &[("idempotency_key", &key)])
        .await?;
    then.redirects_to(&format!("{path}?done=cancelled"))?;
    anyhow::ensure!(
        billing.calls("ChangePlan").len() == 1 && billing.calls("CancelSubscription").len() == 1,
        "owner actions did not reach billing exactly once"
    );
    Ok(())
}

#[tokio::test]
async fn only_operator_managers_can_grant_complimentary_billing() -> anyhow::Result<()> {
    let billing =
        FakeBilling::start_with_account(DeletionAnswer::Allow, AccountAnswer::Free).await?;
    let operator = format!("ops-{}", crate::accepttest::fixtures::random_hex(4));
    let Some((given, when, then)) = configured(&billing, &operator).await? else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;
    let (other, other_when, other_then) = given.testcase.another_browser();
    let target = other.a_signed_in_account().await?;
    other_when.calling("/grund.operator.v1.OperatorService/SetComplimentary", &json!({
        "organisation": target.username, "enabled": true, "reason": "fixture",
        "expiresAt": "2099-01-01T00:00:00Z", "idempotencyKey": uuid::Uuid::now_v7().to_string()
    }).to_string()).await?;
    other_then.status(404)?.connect_code("not_found")?;
    anyhow::ensure!(
        billing.calls("SetComplimentary").is_empty(),
        "non-operator reached billing"
    );
    let admin = format!(
        "/{operator}/admin?tab=organisations&organisation={}",
        target.username
    );
    when.visiting(&admin).await?;
    then.status(200)?
        .body_contains("Grant complimentary billing")?;
    then.status(200)?.body_contains("Complimentary")?;
    let key = form_key(&when, 0)?;
    when.submitting_on_current_page(
        &format!("/{operator}/admin/organisations/complimentary"),
        &[
            ("organisation", &target.username),
            ("billing_action", "grant"),
            ("plan", "Pro"),
            ("reason", "test account"),
            ("expires_at", "2099-01-01T00:00:00Z"),
            ("idempotency_key", &key),
        ],
    )
    .await?;
    then.status(303)?;
    billing
        .wait_for("SetComplimentary", 1, Duration::from_secs(5))
        .await?;
    when.calling(
        "/grund.operator.v1.OperatorService/GetBillingAccount",
        &json!({"organisation": target.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    let granted = then.json()?;
    anyhow::ensure!(
        granted["complimentary"] == true
            && granted["complimentaryScheduled"] != true
            && granted["totalAmountCents"].as_str().unwrap_or("0") == "0"
            && granted["providerSubscriptionId"].is_null(),
        "a new organisation has an immediately free plan without a subscription: {granted}"
    );
    let owner_page = format!("/{}/settings/billing", target.username);
    eventually_account(&other_when, &other_then, &owner_page, "€0").await?;
    other_then.body_lacks("Provider subscription ID")?;
    Ok(())
}

#[tokio::test]
async fn paid_complimentary_grant_is_scheduled_until_provider_confirms_it() -> anyhow::Result<()> {
    let billing = FakeBilling::start(DeletionAnswer::Allow).await?;
    let operator = format!("ops-{}", crate::accepttest::fixtures::random_hex(4));
    let Some((given, when, then)) = configured(&billing, &operator).await? else {
        return Ok(());
    };
    given.a_signed_in_account_named(&operator).await?;
    let (customer, customer_when, customer_then) = given.testcase.another_browser();
    let target = customer.a_signed_in_account().await?;
    let admin = format!(
        "/{operator}/admin?tab=organisations&organisation={}",
        target.username
    );
    eventually_account(&when, &then, &admin, "Grant complimentary billing").await?;
    then.body_contains("Open payment provider")?
        .body_contains("11111111-1111-4111-8111-111111111111")?;
    let key = form_key(&when, 0)?;
    when.submitting_on_current_page(
        &format!("/{operator}/admin/organisations/complimentary"),
        &[
            ("organisation", &target.username),
            ("billing_action", "grant"),
            ("plan", "Business"),
            ("reason", "operator grant"),
            ("expires_at", "2099-12-01T00:00:00Z"),
            ("idempotency_key", &key),
        ],
    )
    .await?;
    then.status(303)?;
    let calls = billing
        .wait_for("SetComplimentary", 1, Duration::from_secs(5))
        .await?;
    anyhow::ensure!(
        calls[0].body["plan"] == "Business",
        "the scheduled grant did not preserve the requested plan"
    );
    when.calling(
        "/grund.operator.v1.OperatorService/GetBillingAccount",
        &json!({"organisation": target.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    let scheduled = then.json()?;
    anyhow::ensure!(
        scheduled["complimentary"] != true
            && scheduled["complimentaryScheduled"] == true
            && scheduled["complimentaryScheduledPlan"] == "Business"
            && scheduled["totalAmountCents"] == "1000",
        "the pending grant must not mark the current paid cycle free: {scheduled}"
    );
    eventually_account(&when, &then, &admin, "Complimentary from").await?;
    then.body_contains("2099-02-01")?.body_lacks("€0")?;
    let owner_page = format!("/{}/settings/billing", target.username);
    eventually_account(
        &customer_when,
        &customer_then,
        &owner_page,
        "Complimentary from",
    )
    .await?;
    customer_then
        .body_contains("current billing cycle is charged normally")?
        .body_lacks("€0")?
        .body_lacks("Open payment provider")?
        .body_lacks("11111111-1111-4111-8111-111111111111")?;
    billing.confirm_scheduled_discount();
    when.calling(
        "/grund.operator.v1.OperatorService/GetBillingAccount",
        &json!({"organisation": target.username}).to_string(),
    )
    .await?;
    then.status(200)?;
    let active = then.json()?;
    anyhow::ensure!(
        active["complimentary"] == true
            && active["complimentaryScheduled"] != true
            && active["totalAmountCents"].as_str().unwrap_or("0") == "0",
        "only provider-confirmed complimentary billing may show €0: {active}"
    );
    eventually_account(&customer_when, &customer_then, &owner_page, "€0").await?;
    customer_then.body_lacks("Complimentary from")?;
    Ok(())
}

#[tokio::test]
async fn billing_outage_blocks_payment_actions_without_blocking_organisation_settings()
-> anyhow::Result<()> {
    let billing =
        FakeBilling::start_with_account(DeletionAnswer::Allow, AccountAnswer::Unavailable).await?;
    let Some((given, when, then)) = configured(&billing, "ops-accept").await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let settings = format!("/{}/settings", owner.username);
    when.visiting(&settings).await?;
    then.status(200)?;
    let page = format!("{settings}/billing");
    when.visiting(&page).await?;
    then.status(200)?
        .body_contains("Billing is unavailable")?
        .body_lacks("Continue to checkout")?;
    let key = uuid::Uuid::now_v7().to_string();
    when.submitting_on_current_page(
        &format!("{page}/choose"),
        &[("plan", "Pro"), ("idempotency_key", &key)],
    )
    .await?;
    then.redirects_to(&format!("{page}?error=unavailable"))?;
    anyhow::ensure!(
        billing.calls("BeginCheckout").is_empty(),
        "outage must not start checkout"
    );
    Ok(())
}

#[tokio::test]
async fn checkout_refuses_a_billing_redirect_outside_the_allowed_origin() -> anyhow::Result<()> {
    let billing =
        FakeBilling::start_with_account(DeletionAnswer::Allow, AccountAnswer::Free).await?;
    billing.checkout_redirect("https://untrusted.example/checkout");
    let Some((given, when, then)) = configured(&billing, "ops-accept").await? else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let page = format!("/{}/settings/billing", owner.username);
    eventually_account(&when, &then, &page, "First own machine free").await?;
    then.status(200)?;
    let key = form_key(&when, 0)?;
    when.submitting_on_current_page(
        &format!("{page}/choose"),
        &[("plan", "Pro"), ("idempotency_key", &key)],
    )
    .await?;
    then.redirects_to(&format!("{page}?error=unavailable"))?
        .header_lacks("location", "untrusted.example")?;
    Ok(())
}
