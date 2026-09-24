use std::time::{Duration, Instant};

use anyhow::Context;

use super::client::{self, Origin};

pub async fn messages_to(mailpit: &Origin, to: &str) -> anyhow::Result<Vec<serde_json::Value>> {
    let query = format!(
        "/api/v1/search?query=to:%22{}%22&limit=50",
        to.replace('@', "%40").replace('+', "%2B")
    );
    let response = client::send(mailpit, "GET", &query, &[], None).await?;
    anyhow::ensure!(
        response.status == 200,
        "mailpit search answered {}",
        response.status
    );
    let json: serde_json::Value = serde_json::from_slice(&response.body)?;
    Ok(json["messages"].as_array().cloned().unwrap_or_default())
}

pub async fn wait_for(
    mailpit: &Origin,
    to: &str,
    subject: &str,
    at_least: usize,
) -> anyhow::Result<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let mut found: Vec<serde_json::Value> = messages_to(mailpit, to)
            .await?
            .into_iter()
            .filter(|m| m["Subject"].as_str().is_some_and(|s| s.contains(subject)))
            .collect();
        found.sort_by(|a, b| b["Created"].as_str().cmp(&a["Created"].as_str()));
        if found.len() >= at_least
            && let Some(message) = found.first()
        {
            let id = message["ID"].as_str().context("message without ID")?;
            let response =
                client::send(mailpit, "GET", &format!("/api/v1/message/{id}"), &[], None).await?;
            return Ok(serde_json::from_slice(&response.body)?);
        }
        anyhow::ensure!(
            Instant::now() < deadline,
            "no {at_least} mail(s) {subject:?} to {to} within 20 s"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

pub async fn link(
    mailpit: &Origin,
    to: &str,
    subject: &str,
    path: &str,
    at_least: usize,
) -> anyhow::Result<String> {
    let message = wait_for(mailpit, to, subject, at_least).await?;
    let text = message["Text"].as_str().context("mail without text")?;
    let start = text
        .find(path)
        .with_context(|| format!("no {path} link in {text}"))?;
    let link: String = text[start..]
        .chars()
        .take_while(|c| !c.is_whitespace())
        .collect();
    Ok(link)
}

pub async fn count_to(mailpit: &Origin, to: &str) -> anyhow::Result<usize> {
    Ok(messages_to(mailpit, to).await?.len())
}
