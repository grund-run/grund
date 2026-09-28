use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::accepttest::fixtures::{
    Fixture,
    client::{self, Origin},
    external_target,
    pebble::{Pebble, SHORT_PROFILE_SECONDS, a_domain, free_port},
    random_hex, refused_at_start,
};

fn settings(pairs: &[(String, String)]) -> Vec<(&str, &str)> {
    pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

fn https(domain: &str, port: u16, roots: Arc<rustls::RootCertStore>) -> anyhow::Result<Origin> {
    let mut origin = Origin::parse(&format!("https://{domain}:{port}"))?;
    origin.connect = Some(("127.0.0.1".into(), port));
    origin.roots = Some(roots);
    Ok(origin)
}

async fn eventually<T, F, Fut>(what: &str, within: Duration, mut probe: F) -> anyhow::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let deadline = Instant::now() + within;
    loop {
        match probe().await {
            Ok(value) => return Ok(value),
            Err(error) if Instant::now() > deadline => {
                return Err(error.context(format!("{what} within {within:?}")));
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

async fn served_over_https(origin: &Origin) -> anyhow::Result<Vec<u8>> {
    let response = client::send(origin, "GET", "/health/ready", &[], None).await?;
    anyhow::ensure!(response.status == 200, "status {}", response.status);
    client::leaf_certificate(origin).await
}

async fn certificate_check(fixture: &Fixture) -> anyhow::Result<String> {
    let response = client::send(&fixture.origin, "GET", "/health/ready", &[], None).await?;
    let body: serde_json::Value = serde_json::from_slice(&response.body)?;
    let check = body["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|c| c["name"] == "certificate"))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no certificate check in {body}"))?;
    anyhow::ensure!(check["severity"] == "minor", "{check}");
    Ok(check["status"].as_str().unwrap_or_default().to_string())
}

async fn reports_certificate(fixture: &Fixture, status: &str) -> anyhow::Result<()> {
    eventually(
        &format!("readiness reporting the certificate {status}"),
        Duration::from_secs(5),
        || async {
            let now = certificate_check(fixture).await?;
            anyhow::ensure!(now == status, "the certificate check is {now}");
            Ok(())
        },
    )
    .await
}

async fn orders(fixture: &Fixture) -> anyhow::Result<i64> {
    let url = fixture
        .database_url()
        .expect("a spawned instance has a database");
    let mut connection = <sqlx::PgConnection as sqlx::Connection>::connect(&url).await?;
    Ok(sqlx::query_scalar("SELECT count(*) FROM grund_acme_orders")
        .fetch_one(&mut connection)
        .await?)
}

async fn acme_instance(
    extra: &[(&str, &str)],
) -> anyhow::Result<Option<(Pebble, Fixture, String)>> {
    if external_target().is_some() {
        eprintln!("skipped: spawns its own instance and ACME server");
        return Ok(None);
    }
    let Some(pebble) = Pebble::start(free_port()).await? else {
        return Ok(None);
    };
    let domain = a_domain();
    let mut env = pebble.grund_settings(&domain);
    for (name, value) in extra {
        env.retain(|(key, _)| key != name);
        env.push((name.to_string(), value.to_string()));
    }
    let fixture = Fixture::spawn(&settings(&env)).await?;
    Ok(Some((pebble, fixture, domain)))
}

#[tokio::test]
async fn a_domain_gets_its_certificate_by_tls_alpn01_and_is_served_over_https() -> anyhow::Result<()>
{
    let Some((pebble, fixture, domain)) = acme_instance(&[]).await? else {
        return Ok(());
    };
    let origin = https(&domain, pebble.tls_port, pebble.roots().await?)?;

    eventually(
        "https with Pebble's certificate",
        Duration::from_secs(60),
        || served_over_https(&origin),
    )
    .await
    .map_err(|error| error.context(fixture.log()))?;

    reports_certificate(&fixture, "healthy").await?;
    anyhow::ensure!(
        orders(&fixture).await? == 1,
        "one order for one certificate"
    );
    anyhow::ensure!(
        fixture.log().contains("answered a TLS-ALPN-01 challenge"),
        "the challenge was answered on the instance's own TLS listener"
    );
    let plain = client::send(&fixture.origin, "GET", "/health/live", &[], None).await?;
    anyhow::ensure!(plain.status == 200, "plain http keeps working beside https");
    Ok(())
}

#[tokio::test]
async fn a_short_lived_certificate_is_renewed_and_served_without_a_restart() -> anyhow::Result<()> {
    let Some((pebble, fixture, domain)) = acme_instance(&[("GRUND_ACME_PROFILE", "short")]).await?
    else {
        return Ok(());
    };
    let origin = https(&domain, pebble.tls_port, pebble.roots().await?)?;
    let first = eventually("a first certificate", Duration::from_secs(60), || {
        served_over_https(&origin)
    })
    .await
    .map_err(|error| error.context(fixture.log()))?;

    let renewed = eventually(
        "a renewed certificate",
        Duration::from_secs(SHORT_PROFILE_SECONDS * 3),
        || async {
            let now = served_over_https(&origin).await?;
            anyhow::ensure!(now != first, "still the first certificate");
            Ok(now)
        },
    )
    .await
    .map_err(|error| error.context(fixture.log()))?;

    anyhow::ensure!(renewed != first);
    anyhow::ensure!(fixture.is_running(), "renewed in place, not by a restart");
    anyhow::ensure!(orders(&fixture).await? >= 2);
    anyhow::ensure!(
        fixture.log().contains("renewal window checked") || pebble.issued_count() >= 2,
        "the renewal followed the CA's renewal information"
    );
    Ok(())
}

#[tokio::test]
async fn two_replicas_place_one_order_and_serve_the_same_certificate() -> anyhow::Result<()> {
    let Some((pebble, first, domain)) = acme_instance(&[]).await? else {
        return Ok(());
    };
    let other_port = free_port();
    let second = first
        .spawn_replica(&[("GRUND_TLS_LISTEN", &format!("127.0.0.1:{other_port}"))])
        .await?;
    let roots = pebble.roots().await?;
    let at_first = https(&domain, pebble.tls_port, roots.clone())?;
    let at_second = https(&domain, other_port, roots)?;

    let one = eventually("the first replica serving", Duration::from_secs(60), || {
        served_over_https(&at_first)
    })
    .await
    .map_err(|error| error.context(format!("{}\n--- second\n{}", first.log(), second.log())))?;
    let two = eventually(
        "the second replica serving",
        Duration::from_secs(20),
        || served_over_https(&at_second),
    )
    .await
    .map_err(|error| error.context(second.log()))?;

    anyhow::ensure!(one == two, "both replicas serve the one certificate");
    anyhow::ensure!(orders(&first).await? == 1, "exactly one order between them");
    anyhow::ensure!(
        pebble.issued_count() == 1,
        "Pebble issued once:\n{}",
        pebble.log()
    );
    Ok(())
}

#[tokio::test]
async fn an_unreachable_ca_degrades_instead_of_stopping_grund_and_the_stored_certificate_outlives_it()
-> anyhow::Result<()> {
    if external_target().is_some() {
        return Ok(());
    }
    let Some(mut pebble) = Pebble::prepare(free_port())? else {
        return Ok(());
    };
    let domain = a_domain();
    let fixture = Fixture::spawn(&settings(&pebble.grund_settings(&domain))).await?;

    eventually("a failed order", Duration::from_secs(20), || async {
        anyhow::ensure!(fixture.log().contains("acme_unreachable"));
        Ok(())
    })
    .await?;
    anyhow::ensure!(
        fixture.is_running(),
        "an unreachable CA does not stop grund"
    );
    reports_certificate(&fixture, "unhealthy").await?;
    let ready = client::send(&fixture.origin, "GET", "/health/ready", &[], None).await?;
    anyhow::ensure!(
        ready.status == 200,
        "a minor check never takes grund out of rotation"
    );

    pebble.run().await?;
    let origin = https(&domain, pebble.tls_port, pebble.roots().await?)?;
    let issued = eventually("https once the CA is back", Duration::from_secs(60), || {
        served_over_https(&origin)
    })
    .await
    .map_err(|error| error.context(fixture.log()))?;

    let roots = pebble.roots().await?;
    pebble.stop();
    fixture.restart_with(&[]).await?;
    let origin = https(&domain, pebble.tls_port, roots)?;
    let after_restart = eventually(
        "the stored certificate after a restart with the CA down",
        Duration::from_secs(10),
        || served_over_https(&origin),
    )
    .await
    .map_err(|error| error.context(fixture.log()))?;
    anyhow::ensure!(after_restart == issued);
    reports_certificate(&fixture, "healthy").await?;
    Ok(())
}

#[tokio::test]
async fn http01_is_answered_on_the_redirect_listener_which_sends_everything_else_to_https()
-> anyhow::Result<()> {
    if external_target().is_some() {
        return Ok(());
    }
    let Some(mut pebble) = Pebble::prepare(free_port())? else {
        return Ok(());
    };
    pebble.run().await?;
    let domain = a_domain();
    let redirect = format!("127.0.0.1:{}", pebble.http_port);
    let mut env = pebble.grund_settings(&domain);
    env.push(("GRUND_ACME_CHALLENGE".into(), "http-01".into()));
    env.push(("GRUND_TLS_REDIRECT_LISTEN".into(), redirect.clone()));
    let fixture = Fixture::spawn(&settings(&env)).await?;
    let origin = https(&domain, pebble.tls_port, pebble.roots().await?)?;

    eventually("https by HTTP-01", Duration::from_secs(60), || {
        served_over_https(&origin)
    })
    .await
    .map_err(|error| error.context(fixture.log()))?;
    anyhow::ensure!(!fixture.log().contains("answered a TLS-ALPN-01 challenge"));

    let mut plain = Origin::parse(&format!("http://{domain}"))?;
    plain.connect = Some(("127.0.0.1".into(), pebble.http_port));
    let response = client::send(&plain, "GET", "/orgs/new?x=1", &[], None).await?;
    anyhow::ensure!(response.status == 308, "status {}", response.status);
    anyhow::ensure!(
        response.header("location")
            == Some(format!("https://{domain}:{}/orgs/new?x=1", pebble.tls_port).as_str()),
        "{:?}",
        response.header("location")
    );
    let unknown =
        client::send(&plain, "GET", "/.well-known/acme-challenge/nope", &[], None).await?;
    anyhow::ensure!(unknown.status == 404);
    Ok(())
}

fn self_signed(domain: &str) -> anyhow::Result<(String, String, Arc<rustls::RootCertStore>)> {
    let key = rcgen::KeyPair::generate()?;
    let cert = rcgen::CertificateParams::new(vec![domain.to_string()])?.self_signed(&key)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone())?;
    Ok((cert.pem(), key.serialize_pem(), Arc::new(roots)))
}

#[tokio::test]
async fn a_supplied_certificate_is_served_and_replaced_when_its_files_change() -> anyhow::Result<()>
{
    if external_target().is_some() {
        return Ok(());
    }
    let domain = a_domain();
    let dir =
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("tls-{}", random_hex(6)));
    std::fs::create_dir_all(&dir)?;
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    let (cert, key, roots) = self_signed(&domain)?;
    std::fs::write(&cert_path, cert)?;
    std::fs::write(&key_path, key)?;
    let port = free_port();
    let fixture = Fixture::spawn(&[
        ("GRUND_DOMAIN", &domain),
        ("GRUND_PUBLIC_URL", &format!("https://{domain}:{port}")),
        ("GRUND_TLS_LISTEN", &format!("127.0.0.1:{port}")),
        ("GRUND_TLS_CERT_FILE", &cert_path.to_string_lossy()),
        ("GRUND_TLS_KEY_FILE", &key_path.to_string_lossy()),
        ("GRUND_TLS_REFRESH_INTERVAL", "1"),
    ])
    .await?;

    let first = served_over_https(&https(&domain, port, roots)?).await?;
    reports_certificate(&fixture, "healthy").await?;

    let (cert, key, roots) = self_signed(&domain)?;
    std::fs::write(&key_path, key)?;
    std::fs::write(&cert_path, cert)?;
    let origin = https(&domain, port, roots)?;
    let second = eventually("the replaced certificate", Duration::from_secs(15), || {
        served_over_https(&origin)
    })
    .await
    .map_err(|error| error.context(fixture.log()))?;
    anyhow::ensure!(first != second);
    anyhow::ensure!(
        orders(&fixture).await? == 0,
        "a supplied certificate orders nothing"
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

#[tokio::test]
async fn a_bad_certificate_setup_is_refused_at_start_naming_the_variable() -> anyhow::Result<()> {
    if external_target().is_some() {
        return Ok(());
    }
    let output = refused_at_start(&[("GRUND_DOMAIN", "grund.example.com")]).await?;
    anyhow::ensure!(output.contains("GRUND_ACME_DIRECTORY"), "{output}");

    let output = refused_at_start(&[
        ("GRUND_DOMAIN", "grund.example.com"),
        ("GRUND_TLS_CERT_FILE", "/nonexistent/cert.pem"),
        ("GRUND_TLS_KEY_FILE", "/nonexistent/key.pem"),
        ("GRUND_TLS_LISTEN", "127.0.0.1:1"),
    ])
    .await?;
    anyhow::ensure!(output.contains("GRUND_TLS_CERT_FILE"), "{output}");
    Ok(())
}
