use crate::accepttest::fixtures::{Ran, free_port, random_hex, testcase_configured};

const SINGLE: &[(&str, &str)] = &[("GRUND_ORGANISATIONS", "single")];

fn has(ran: &Ran, status: &str, check: &str) -> anyhow::Result<String> {
    ran.line(status, check).ok_or_else(|| {
        anyhow::anyhow!(
            "no `{status} {check}` line in:\n{}\n--- stderr\n{}",
            ran.stdout,
            ran.stderr
        )
    })
}

#[tokio::test]
async fn doctor_passes_a_running_instance_and_names_what_is_left_to_do() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let fixture = &given.testcase.fixture;
    let ran = fixture.running(&["doctor", "instance"]).await?;
    anyhow::ensure!(ran.code == Some(0), "{}\n{}", ran.stdout, ran.stderr);
    for check in [
        "config",
        "secret-key",
        "database",
        "migrations",
        "instance-keys",
        "mail",
        "nats",
        "disk",
    ] {
        has(&ran, "ok", check)?;
    }
    has(&ran, "skip", "certificate")?;
    has(&ran, "warn", "public-url")?;
    anyhow::ensure!(has(&ran, "warn", "owner")?.contains("no account yet"));
    anyhow::ensure!(
        ran.stdout
            .contains("fix: docker compose exec grund /grund setup-link")
    );
    anyhow::ensure!(
        ran.stdout
            .lines()
            .last()
            .is_some_and(|l| l.starts_with("summary: 0 fail"))
    );

    given.the_owner().await?;
    let ran = fixture.running(&["doctor", "instance", "--json"]).await?;
    anyhow::ensure!(ran.code == Some(0), "{}", ran.stderr);
    let report: serde_json::Value = serde_json::from_str(ran.stdout.trim())?;
    anyhow::ensure!(
        report["target"] == "instance" && report["status"] == "warn",
        "{report}"
    );
    let owner = report["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|c| c["name"] == "owner"))
        .cloned()
        .unwrap_or_default();
    anyhow::ensure!(owner["status"] == "ok", "{owner}");
    anyhow::ensure!(ran.stderr.trim().is_empty() || !ran.stderr.contains("grund doctor"));
    Ok(())
}

#[tokio::test]
async fn doctor_fails_naming_the_cause_and_exits_one() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let fixture = &given.testcase.fixture;
    let closed = format!("127.0.0.1:{}", free_port());

    let ran = fixture
        .running_with(
            &["doctor", "instance"],
            &[("DATABASE_URL", &format!("postgres://grund@{closed}/grund"))],
        )
        .await?;
    anyhow::ensure!(ran.code == Some(1), "exit {:?}", ran.code);
    has(&ran, "fail", "database")?;
    has(&ran, "skip", "migrations")?;

    let ran = fixture
        .running_with(
            &["doctor", "instance"],
            &[("GRUND_SECRET_KEY", &random_hex(32))],
        )
        .await?;
    anyhow::ensure!(ran.code == Some(1));
    anyhow::ensure!(has(&ran, "fail", "instance-keys")?.contains("do not match"));

    let ran = fixture
        .running_with(
            &["doctor", "instance"],
            &[("GRUND_SMTP_URL", &format!("smtp://{closed}"))],
        )
        .await?;
    anyhow::ensure!(ran.code == Some(1));
    has(&ran, "fail", "mail")?;
    anyhow::ensure!(!ran.stdout.contains(&closed) || ran.stdout.contains("GRUND_SMTP_URL"));

    let ran = fixture
        .running_with(
            &["doctor", "instance"],
            &[("GRUND_PUBLIC_URL", "http://grund.example.com")],
        )
        .await?;
    anyhow::ensure!(ran.code == Some(1));
    anyhow::ensure!(has(&ran, "fail", "config")?.contains("GRUND_PUBLIC_URL"));
    anyhow::ensure!(
        ran.stdout.lines().count() == 4,
        "config failing stops the run:\n{}",
        ran.stdout
    );
    Ok(())
}

#[tokio::test]
async fn doctor_refuses_a_database_a_newer_grund_migrated() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(SINGLE).await? else {
        return Ok(());
    };
    let fixture = &given.testcase.fixture;
    let ran = fixture.running(&["doctor", "instance"]).await?;
    has(&ran, "ok", "migrations")?;
    fixture
        .sql(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
             VALUES (9999, 'from the future', true, '\\x00', 0)",
        )
        .await?;
    let ran = fixture.running(&["doctor", "instance"]).await?;
    anyhow::ensure!(ran.code == Some(1));
    anyhow::ensure!(has(&ran, "fail", "migrations")?.contains("9999"));
    anyhow::ensure!(ran.stdout.contains("forward-only"));
    Ok(())
}

#[tokio::test]
async fn doctor_on_a_machine_reaches_the_instance_and_compares_clocks() -> anyhow::Result<()> {
    let Some((given, _when, _then)) = testcase_configured(&[]).await? else {
        return Ok(());
    };
    let fixture = &given.testcase.fixture;
    let data =
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("doctor-{}", random_hex(4)));
    let url = fixture.origin.serialized();
    let data_dir = data.display().to_string();
    let ran = fixture
        .running(&["doctor", "machine", "--data-dir", &data_dir, "--url", &url])
        .await?;
    for check in ["arch", "kernel", "memory", "systemd", "cgroup", "disk"] {
        anyhow::ensure!(
            ran.stdout
                .lines()
                .any(|line| line.split_whitespace().nth(1) == Some(check)),
            "no {check} line:\n{}",
            ran.stdout
        );
    }
    anyhow::ensure!(has(&ran, "ok", "instance")?.contains(&url));
    has(&ran, "ok", "clock")?;

    let closed = format!("http://127.0.0.1:{}", free_port());
    let ran = fixture
        .running(&[
            "doctor",
            "machine",
            "--data-dir",
            &data_dir,
            "--url",
            &closed,
            "--json",
        ])
        .await?;
    anyhow::ensure!(ran.code == Some(1), "exit {:?}: {}", ran.code, ran.stdout);
    let report: serde_json::Value = serde_json::from_str(ran.stdout.trim())?;
    anyhow::ensure!(
        report["status"] == "fail" && report["target"] == "machine",
        "{report}"
    );
    Ok(())
}
