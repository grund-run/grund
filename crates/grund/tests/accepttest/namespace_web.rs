use serde_json::json;

use crate::accepttest::{
    domains::{a_custom_name, domain_call, status_of, verified},
    traffic::a_stack_with,
};

#[tokio::test]
async fn app_address_forms_preserve_refusals_and_require_explicit_restoration_after_unbinding()
-> anyhow::Result<()> {
    let Some(stack) = a_stack_with(&[]).await? else {
        return Ok(());
    };
    let owner = stack.given.a_signed_in_account().await?;
    let org = owner.username;
    stack.deploy(&org, "hello", "1", 1).await?;
    let (when, then) = (&stack.when, &stack.then);
    stack.deploy(&org, "other", "1", 1).await?;
    let parent = a_custom_name();
    verified(&stack, when, then, &org, &parent).await?;
    let bound = domain_call(
        when,
        then,
        "BindDomain",
        json!({"organisation": org, "name": parent, "app": "hello"}),
    )
    .await?;
    anyhow::ensure!(bound.0 == 200, "could not bind parent apex: {}", bound.1);
    let domains = format!("/{org}/domains");
    let configure = format!("/{org}/domains/app-domain");
    let settings = format!("/{org}/apps/hello/settings?edit=domains");
    let save = format!("/{org}/apps/hello/settings/domains");
    when.posting_raw(&configure, &[("name", &parent)], Some(&when.form_origin()))
        .await?;
    then.status(403)?;
    anyhow::ensure!(
        status_of(when, then, &org, &parent).await?["isAppDomain"] != true,
        "a forged form enabled an app domain"
    );
    when.visiting(&domains).await?;
    when.submitting_on_current_page(&configure, &[("name", &parent)])
        .await?;
    then.redirects_to(&format!("/{org}/domains?done=app-domain#custom"))?;
    let parent_view = status_of(when, then, &org, &parent).await?;
    anyhow::ensure!(
        parent_view["isAppDomain"] == true && parent_view["app"] == "hello",
        "enabling the namespace changed its independent apex binding: {parent_view}"
    );
    let original = format!("hello.{parent}");
    let chosen = format!("api.{parent}");
    when.visiting(&domains).await?;
    then.body_contains(&format!("*.{parent}"))?
        .body_contains(&original)?
        .body_lacks(&format!("_grund.{original}"))?;
    when.visiting(&settings).await?;
    then.body_contains("value=\"hello\"")?;
    when.submitting_on_current_page(
        &save,
        &[("operation", "subdomain"), ("subdomain", "bad.label")],
    )
    .await?;
    then.status(422)?
        .body_contains("value=\"bad.label\"")?
        .body_contains("aria-invalid=\"true\"")?;
    anyhow::ensure!(
        status_of(when, then, &org, &original).await?["app"] == "hello",
        "a refused label replaced the current app address"
    );
    when.visiting(&settings).await?;
    when.submitting_on_current_page(&save, &[("operation", "subdomain"), ("subdomain", "api")])
        .await?;
    then.redirects_to(&settings)?;
    anyhow::ensure!(
        status_of(when, then, &org, &chosen).await?["parentDomain"] == parent,
        "the chosen app address lost verified-parent provenance"
    );
    let other = format!("other.{parent}");
    let unbound = domain_call(
        when,
        then,
        "UnbindDomain",
        json!({"organisation": org, "name": other}),
    )
    .await?;
    anyhow::ensure!(
        unbound.0 == 200,
        "could not unbind another app address: {}",
        unbound.1
    );
    when.visiting(&settings).await?;
    then.body_contains("value=\"api\"")?.body_lacks(&other)?;
    when.submitting_on_current_page(&save, &[("operation", "unbind"), ("domain", &chosen)])
        .await?;
    then.redirects_to(&settings)?;
    when.visiting(&domains).await?;
    when.visiting(&settings).await?;
    then.body_contains("value=\"api\"")?.body_lacks(&other)?;
    when.submitting_on_current_page(&save, &[("operation", "check"), ("domain", &chosen)])
        .await?;
    then.redirects_to(&settings)?;
    anyhow::ensure!(
        status_of(when, then, &org, &chosen).await?["status"] == "DOMAIN_STATUS_VERIFIED",
        "a page read or setup check recreated an explicitly unbound app address"
    );
    when.visiting(&settings).await?;
    when.submitting_on_current_page(&save, &[("operation", "subdomain"), ("subdomain", "api")])
        .await?;
    then.redirects_to(&settings)?;
    let (outsider, outsider_when, outsider_then) = stack.given.testcase.another_browser();
    let foreign = outsider.a_signed_in_account().await?;
    outsider_when
        .visiting(&format!("/{}/domains", foreign.username))
        .await?;
    outsider_when
        .submitting_on_current_page(
            &save,
            &[("operation", "subdomain"), ("subdomain", "stolen")],
        )
        .await?;
    outsider_then.status(404)?;
    anyhow::ensure!(
        status_of(when, then, &org, &chosen).await?["app"] == "hello",
        "another organisation changed the restored app address"
    );
    Ok(())
}
