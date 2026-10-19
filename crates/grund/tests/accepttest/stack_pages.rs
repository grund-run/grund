use anyhow::{Context, ensure};
use serde_json::{Value, json};

use crate::accepttest::fixtures::{FakeRegistry, Then, When, csrf_of, testcase_configured};

const SERVICE: &str = "/grund.stack.v1.StackService";
const REFUSED_SECRET: &str = "stack-form-secret-must-not-be-returned";

async fn call(when: &When, then: &Then, method: &str, body: Value) -> anyhow::Result<Value> {
    when.calling(&format!("{SERVICE}/{method}"), &body.to_string())
        .await?;
    then.status(200)?.json()
}

fn file(name: &str, image: &str, greeting: &str) -> String {
    format!(
        "stack:\n  name: {name}\n  services:\n    web:\n      image: {image}\n      env:\n        GREETING: {greeting}\n"
    )
}

fn decoded(value: &str) -> String {
    let mut result = String::new();
    let mut rest = value;
    while let Some(start) = rest.find('&') {
        result.push_str(&rest[..start]);
        rest = &rest[start..];
        let Some(end) = rest.find(';') else {
            break;
        };
        let entity = &rest[1..end];
        let character = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|digits| u32::from_str_radix(digits, 16).ok())
                .or_else(|| {
                    entity
                        .strip_prefix('#')
                        .and_then(|digits| digits.parse().ok())
                })
                .and_then(char::from_u32),
        };
        if let Some(character) = character {
            result.push(character);
        } else {
            result.push_str(&rest[..=end]);
        }
        rest = &rest[end + 1..];
    }
    result.push_str(rest);
    result
}

fn control<'a>(html: &'a str, tag: &str, name: &str) -> Option<&'a str> {
    html.split(&format!("<{tag}"))
        .skip(1)
        .filter_map(|rest| rest.split_once('>').map(|(attributes, _)| attributes))
        .find(|attributes| attributes.contains(&format!("name=\"{name}\"")))
}

fn hidden(html: &str, name: &str) -> Option<String> {
    let attributes = control(html, "input", name)?;
    if !attributes.contains("type=\"hidden\"") {
        return None;
    }
    let (_, rest) = attributes.split_once("value=\"")?;
    Some(decoded(rest.split_once('"')?.0))
}

fn editor_file(html: &str) -> anyhow::Result<String> {
    let attributes = control(html, "textarea", "file").context("no editable stack file")?;
    let (_, rest) = html
        .split_once(&format!("<textarea{attributes}>"))
        .context("stack editor opening tag absent")?;
    Ok(decoded(
        rest.split_once("</textarea>")
            .context("stack editor closing tag absent")?
            .0,
    ))
}

struct StackForm {
    csrf: String,
    key: String,
    stack: String,
    expected_version: String,
    file: String,
}

impl StackForm {
    fn from_page(html: &str, file: String) -> anyhow::Result<Self> {
        Ok(Self {
            csrf: csrf_of(html).context("stack form has no CSRF token")?,
            key: hidden(html, "key").context("stack form has no request key")?,
            stack: hidden(html, "stack").unwrap_or_default(),
            expected_version: hidden(html, "expected_version").unwrap_or_default(),
            file,
        })
    }

    async fn post(&self, when: &When, path: &str, extra: &[(&str, &str)]) -> anyhow::Result<()> {
        let mut fields = vec![
            ("csrf", self.csrf.as_str()),
            ("key", self.key.as_str()),
            ("stack", self.stack.as_str()),
            ("expected_version", self.expected_version.as_str()),
            ("file", self.file.as_str()),
        ];
        fields.extend_from_slice(extra);
        when.posting_raw(
            path,
            &fields,
            Some(&when.testcase.fixture.origin.serialized()),
        )
        .await?;
        Ok(())
    }
}

async fn stacks(when: &When, then: &Then, org: &str) -> anyhow::Result<Vec<Value>> {
    let listed = call(when, then, "ListStacks", json!({"organisation":org})).await?;
    Ok(listed["stacks"].as_array().cloned().unwrap_or_default())
}

async fn stack(when: &When, then: &Then, org: &str, name: &str) -> anyhow::Result<Value> {
    let found = call(
        when,
        then,
        "GetStack",
        json!({"organisation":org,"name":name}),
    )
    .await?;
    Ok(found["stack"].clone())
}

fn unchanged(before: &Value, after: &Value) -> anyhow::Result<()> {
    for field in ["id", "yaml", "version", "revision", "services"] {
        ensure!(
            before[field] == after[field],
            "refused browser operation changed stack {field}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_stack_file_is_reviewed_without_writes_then_created_from_the_reviewed_form()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = &owner.username;
    let name = given.a_fresh_name("reviewed");
    registry.publish("acme/stack-pages", "1");
    let image = registry.image("acme/stack-pages", "1");
    let deploy = format!("/{org}/stacks/deploy");
    let preview = format!("{deploy}/preview");
    let yaml = file(&name, &image, "reviewed-value");

    let (outsider, outsider_when, outsider_then) = given.testcase.another_browser();
    outsider.a_signed_in_account().await?;
    outsider_when.visiting(&deploy).await?;
    outsider_then.status(404)?;

    when.visiting(&deploy).await?;
    then.status(200)?.carries_the_security_headers()?;
    let initial = then.body()?;
    let mut form = StackForm::from_page(&initial, yaml.clone())?;
    let inspections = registry.manifest_calls();
    for path in [&preview, &deploy] {
        when.posting_raw(
            path,
            &[("file", &yaml), ("key", &form.key), ("stack", "")],
            Some(&when.testcase.fixture.origin.serialized()),
        )
        .await?;
        then.status(403)?;
    }
    ensure!(
        registry.manifest_calls() == inspections,
        "CSRF refusal resolved an image"
    );
    ensure!(stacks(&when, &then, org).await?.is_empty());

    let invalid = format!("stack:\n  name: {name}\n  services: [\n");
    form.file = invalid.clone();
    form.post(
        &when,
        &preview,
        &[
            ("secrets_key", "web.PASSWORD"),
            ("secrets_value", REFUSED_SECRET),
        ],
    )
    .await?;
    then.status(422)?
        .carries_the_security_headers()?
        .body_lacks(REFUSED_SECRET)?;
    let refused = then.body()?;
    ensure!(
        control(&refused, "textarea", "file")
            .is_some_and(|attributes| attributes.contains("aria-invalid=\"true\"")),
        "invalid stack file is not marked invalid"
    );
    ensure!(editor_file(&refused)? == invalid, "refusal lost the file");
    ensure!(stacks(&when, &then, org).await?.is_empty());

    form.file = yaml.clone();
    form.post(&when, &preview, &[]).await?;
    then.status(200)?.carries_the_security_headers()?;
    let reviewed = then.body()?;
    ensure!(
        hidden(&reviewed, "file").as_deref() == Some(yaml.as_str())
            && control(&reviewed, "textarea", "file").is_none(),
        "review did not freeze the submitted file"
    );
    ensure!(
        reviewed
            .split("<pre")
            .skip(1)
            .filter_map(|rest| rest.split_once('>').map(|(_, body)| body))
            .filter_map(|body| body.split_once("</pre>").map(|(text, _)| text))
            .any(|text| decoded(text) == yaml),
        "reviewed file is not visible as read-only code"
    );
    let review_form = StackForm::from_page(
        &reviewed,
        hidden(&reviewed, "file").context("review has no submitted file")?,
    )?;
    ensure!(
        review_form.expected_version.is_empty() && review_form.stack.is_empty(),
        "new preview acquired an update precondition"
    );
    ensure!(stacks(&when, &then, org).await?.is_empty());

    review_form
        .post(&when, &preview, &[("intent", "edit")])
        .await?;
    then.status(200)?;
    let editing = then.body()?;
    ensure!(
        editor_file(&editing)? == yaml,
        "return to edit lost the reviewed file"
    );
    let form = StackForm::from_page(&editing, editor_file(&editing)?)?;
    ensure!(
        form.key == review_form.key,
        "return to edit lost the request key"
    );
    form.post(&when, &preview, &[]).await?;
    then.status(200)?;
    let reviewed = then.body()?;
    let form = StackForm::from_page(
        &reviewed,
        hidden(&reviewed, "file").context("review has no submitted file")?,
    )?;
    form.post(&when, &deploy, &[]).await?;
    then.status(303)?
        .header_contains("location", &format!("/{org}/stacks/{name}"))?;
    let created = stack(&when, &then, org, &name).await?;
    ensure!(
        created["yaml"] == yaml,
        "created stack differs from reviewed file"
    );
    ensure!(
        created["services"]
            .as_array()
            .is_some_and(|services| { services.len() == 1 && services[0]["name"] == "web" }),
        "created stack is missing its actual service"
    );
    let listed = stacks(&when, &then, org).await?;
    ensure!(listed.len() == 1 && listed[0]["name"] == name);
    Ok(())
}

#[tokio::test]
async fn a_new_stack_cannot_acquire_update_authority_by_preview_or_a_forged_version()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = &owner.username;
    let name = given.a_fresh_name("collision");
    registry.publish("acme/stack-pages", "1");
    let image = registry.image("acme/stack-pages", "1");
    let original = file(&name, &image, "original-value");
    call(
        &when,
        &then,
        "DeployStack",
        json!({"organisation":org,"yaml":original,"idempotencyKey":given.a_fresh_name("seed")}),
    )
    .await?;
    let before = stack(&when, &then, org, &name).await?;
    let deploy = format!("/{org}/stacks/deploy");
    let preview = format!("{deploy}/preview");
    when.visiting(&deploy).await?;
    then.status(200)?;
    let replacement = file(&name, &image, "must-not-replace-existing");
    let mut form = StackForm::from_page(&then.body()?, replacement.clone())?;
    form.post(
        &when,
        &preview,
        &[
            ("secrets_key", "web.PASSWORD"),
            ("secrets_value", REFUSED_SECRET),
        ],
    )
    .await?;
    then.status(422)?.body_lacks(REFUSED_SECRET)?;
    let refused = then.body()?;
    ensure!(editor_file(&refused)? == replacement);
    ensure!(
        control(&refused, "textarea", "file")
            .is_some_and(|attributes| attributes.contains("aria-invalid=\"true\"")),
        "create collision is not attached to the stack file"
    );
    ensure!(
        hidden(&refused, "expected_version")
            .unwrap_or_default()
            .is_empty()
            && hidden(&refused, "stack").unwrap_or_default().is_empty(),
        "create collision acquired authority to update the existing stack"
    );
    unchanged(&before, &stack(&when, &then, org, &name).await?)?;

    form.expected_version = before["version"]
        .as_str()
        .context("stack version absent")?
        .to_string();
    ensure!(form.expected_version.parse::<u64>()? > 0);
    form.post(&when, &deploy, &[]).await?;
    then.status(422)?;
    ensure!(
        control(&then.body()?, "textarea", "file")
            .is_some_and(|attributes| attributes.contains("aria-invalid=\"true\"")),
        "forged create version was not refused as a file collision"
    );
    unchanged(&before, &stack(&when, &then, org, &name).await?)?;
    let listed = stacks(&when, &then, org).await?;
    ensure!(listed.len() == 1 && listed[0]["name"] == name);
    Ok(())
}

#[tokio::test]
async fn editing_preserves_stack_identity_and_never_refreshes_a_stale_review_precondition()
-> anyhow::Result<()> {
    let registry = FakeRegistry::start().await?;
    let Some((given, when, then)) =
        testcase_configured(&[("GRUND_INSECURE_REGISTRIES", &registry.host)]).await?
    else {
        return Ok(());
    };
    let owner = given.a_signed_in_account().await?;
    let org = &owner.username;
    let name = given.a_fresh_name("editing");
    let renamed = given.a_fresh_name("renamed");
    registry.publish("acme/stack-pages", "1");
    let image = registry.image("acme/stack-pages", "1");
    let original = file(&name, &image, "original-value");
    call(
        &when,
        &then,
        "DeployStack",
        json!({"organisation":org,"yaml":original,"idempotencyKey":given.a_fresh_name("seed")}),
    )
    .await?;
    let before = stack(&when, &then, org, &name).await?;
    let deploy = format!("/{org}/stacks/deploy");
    let preview = format!("{deploy}/preview");
    let edit = format!("{deploy}?stack={name}");
    when.visiting(&edit).await?;
    then.status(200)?;
    let mut form = StackForm::from_page(&then.body()?, file(&renamed, &image, "renamed-value"))?;
    ensure!(form.stack == name, "edit form lost original stack identity");
    ensure!(form.expected_version.parse::<u64>()? > 0);
    for path in [&preview, &deploy] {
        form.post(
            &when,
            path,
            &[
                ("secrets_key", "web.PASSWORD"),
                ("secrets_value", REFUSED_SECRET),
            ],
        )
        .await?;
        then.status(422)?.body_lacks(REFUSED_SECRET)?;
        ensure!(editor_file(&then.body()?)? == form.file);
        unchanged(&before, &stack(&when, &then, org, &name).await?)?;
        let listed = stacks(&when, &then, org).await?;
        ensure!(
            listed.len() == 1 && listed[0]["name"] == name,
            "renamed edit created a second stack"
        );
    }

    let current = stack(&when, &then, org, &name).await?;
    let current_version = current["version"]
        .as_str()
        .context("stack version absent")?
        .parse::<u64>()?;
    ensure!(
        current_version > 1,
        "created stack has no older positive version"
    );
    let old_version = (current_version - 1).to_string();
    form.expected_version = old_version.clone();
    form.file = file(&name, &image, "stale-editor-value");
    form.post(
        &when,
        &preview,
        &[
            ("secrets_key", "web.PASSWORD"),
            ("secrets_value", REFUSED_SECRET),
        ],
    )
    .await?;
    then.status(422)?.body_lacks(REFUSED_SECRET)?;
    let refused = then.body()?;
    ensure!(editor_file(&refused)? == form.file);
    ensure!(
        hidden(&refused, "expected_version").as_deref() == Some(old_version.as_str()),
        "stale preview silently refreshed the editor's update precondition"
    );
    let refused_form = StackForm::from_page(&refused, editor_file(&refused)?)?;
    refused_form.post(&when, &deploy, &[]).await?;
    then.status(422)?;
    unchanged(&current, &stack(&when, &then, org, &name).await?)?;
    Ok(())
}
