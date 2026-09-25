use std::time::{Duration, Instant};

use anyhow::Context;

use super::{When, client, mail};

impl When {
    pub async fn requesting(&self, method: &str, path: &str) -> anyhow::Result<&Self> {
        self.requesting_with(method, path, &[], None).await
    }

    pub async fn requesting_with(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> anyhow::Result<&Self> {
        let response = self.send(method, path, headers, body).await?;
        self.testcase.data().last = Some(response);
        Ok(self)
    }

    pub async fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> anyhow::Result<client::Response> {
        let fixture = &self.testcase.fixture;
        let cookie = {
            let data = self.testcase.data();
            data.cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ")
        };
        let mut all: Vec<(&str, &str)> = headers.to_vec();
        if !cookie.is_empty() {
            all.push(("Cookie", &cookie));
        }
        let response = client::send(&fixture.origin, method, path, &all, body).await?;
        let mut data = self.testcase.data();
        for set in response.headers_named("set-cookie") {
            let pair = set.split(';').next().unwrap_or_default();
            if let Some((name, value)) = pair.split_once('=') {
                let expired = set.to_ascii_lowercase().contains("max-age=0");
                if expired || value.is_empty() {
                    data.cookies.remove(name);
                } else {
                    data.cookies.insert(name.to_string(), value.to_string());
                }
            }
        }
        Ok(response)
    }

    pub async fn calling(&self, procedure: &str, json: &str) -> anyhow::Result<&Self> {
        self.calling_with(procedure, json, &[]).await
    }

    pub async fn calling_with(
        &self,
        procedure: &str,
        json: &str,
        extra: &[(&str, &str)],
    ) -> anyhow::Result<&Self> {
        let mut headers = vec![
            ("Content-Type", "application/json"),
            ("Connect-Protocol-Version", "1"),
        ];
        headers.extend_from_slice(extra);
        self.requesting_with("POST", procedure, &headers, Some(json.as_bytes()))
            .await
    }

    pub async fn visiting(&self, path: &str) -> anyhow::Result<&Self> {
        self.requesting("GET", path).await
    }

    pub async fn posting_raw(
        &self,
        path: &str,
        fields: &[(&str, &str)],
        origin: Option<&str>,
    ) -> anyhow::Result<&Self> {
        let body = form_encode(fields);
        let mut headers = vec![("Content-Type", "application/x-www-form-urlencoded")];
        if let Some(origin) = origin {
            headers.push(("Origin", origin));
        }
        self.requesting_with("POST", path, &headers, Some(body.as_bytes()))
            .await
    }

    pub async fn submitting(
        &self,
        page: &str,
        action: &str,
        fields: &[(&str, &str)],
    ) -> anyhow::Result<&Self> {
        let form = self.send("GET", page, &[], None).await?;
        anyhow::ensure!(form.status == 200, "GET {page}: status {}", form.status);
        let csrf = csrf_of(&form.text()).with_context(|| format!("{page} has no csrf field"))?;
        let origin = self.origin_a_browser_sends(form.header("referrer-policy"));
        let mut all = vec![("csrf", csrf.as_str())];
        all.extend_from_slice(fields);
        self.posting_raw(action, &all, Some(&origin)).await
    }

    pub fn form_origin(&self) -> String {
        let policy = self
            .testcase
            .data()
            .last
            .as_ref()
            .and_then(|page| page.header("referrer-policy").map(str::to_string));
        self.origin_a_browser_sends(policy.as_deref())
    }

    pub fn origin_a_browser_sends(&self, referrer_policy: Option<&str>) -> String {
        let effective = referrer_policy
            .and_then(|policy| policy.split(',').next_back())
            .map(|policy| policy.trim().to_ascii_lowercase());
        if effective.as_deref() == Some("no-referrer") {
            "null".to_string()
        } else {
            self.testcase.fixture.origin.serialized()
        }
    }

    pub async fn submitting_with_token(
        &self,
        action: &str,
        csrf: &str,
        fields: &[(&str, &str)],
    ) -> anyhow::Result<&Self> {
        let origin = self.form_origin();
        let mut all = vec![("csrf", csrf)];
        all.extend_from_slice(fields);
        self.posting_raw(action, &all, Some(&origin)).await
    }

    pub async fn submitting_on_current_page(
        &self,
        action: &str,
        fields: &[(&str, &str)],
    ) -> anyhow::Result<&Self> {
        let html = self
            .testcase
            .data()
            .last
            .as_ref()
            .map(|r| r.text())
            .context("no page loaded")?;
        let csrf = csrf_of(&html).context("the current page has no csrf field")?;
        self.submitting_with_token(action, &csrf, fields).await
    }

    pub async fn signing_up(
        &self,
        username: &str,
        email: &str,
        password: &str,
    ) -> anyhow::Result<&Self> {
        self.submitting(
            "/signup",
            "/signup",
            &[
                ("username", username),
                ("email", email),
                ("password", password),
            ],
        )
        .await
    }

    pub async fn signing_in(&self, login: &str, password: &str) -> anyhow::Result<&Self> {
        let mut form = self.send("GET", "/login", &[], None).await?;
        if form.status == 303 {
            form = self.send("GET", "/", &[], None).await?;
        }
        let csrf = csrf_of(&form.text()).context("no csrf field to sign in with")?;
        self.submitting_with_token("/login", &csrf, &[("login", login), ("password", password)])
            .await
    }

    pub async fn signing_in_as_the_account(&self) -> anyhow::Result<&Self> {
        let account = self.testcase.data().account.clone().context("no account")?;
        self.signing_in(&account.username, &account.password).await
    }

    pub async fn following_the_mailed_link(
        &self,
        to: &str,
        subject: &str,
        path: &str,
    ) -> anyhow::Result<&Self> {
        let link = self.the_mailed_link(to, subject, path).await?;
        self.visiting(&link).await
    }

    pub async fn the_mailed_link(
        &self,
        to: &str,
        subject: &str,
        path: &str,
    ) -> anyhow::Result<String> {
        let mailpit = self
            .testcase
            .fixture
            .mailpit
            .clone()
            .context("no mailpit")?;
        mail::link(&mailpit, to, subject, path, 1, mail::Pick::Newest).await
    }

    pub async fn the_newest_of_mailed_links(
        &self,
        to: &str,
        subject: &str,
        path: &str,
        count: usize,
    ) -> anyhow::Result<String> {
        let mailpit = self
            .testcase
            .fixture
            .mailpit
            .clone()
            .context("no mailpit")?;
        mail::link(&mailpit, to, subject, path, count, mail::Pick::Newest).await
    }

    pub async fn the_oldest_of_mailed_links(
        &self,
        to: &str,
        subject: &str,
        path: &str,
        count: usize,
    ) -> anyhow::Result<String> {
        let mailpit = self
            .testcase
            .fixture
            .mailpit
            .clone()
            .context("no mailpit")?;
        mail::link(&mailpit, to, subject, path, count, mail::Pick::Oldest).await
    }

    pub async fn timing_sign_ins_alternately(
        &self,
        first: (&str, &str),
        second: (&str, &str),
        rounds: usize,
    ) -> anyhow::Result<(Duration, Duration)> {
        let mut firsts = Vec::with_capacity(rounds);
        let mut seconds = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            firsts.push(self.time_one_sign_in(first.0, first.1).await?);
            seconds.push(self.time_one_sign_in(second.0, second.1).await?);
        }
        firsts.sort();
        seconds.sort();
        Ok((firsts[rounds / 2], seconds[rounds / 2]))
    }

    async fn time_one_sign_in(&self, login: &str, password: &str) -> anyhow::Result<Duration> {
        let form = self.send("GET", "/login", &[], None).await?;
        let csrf = csrf_of(&form.text()).context("no csrf")?;
        let origin = self.testcase.fixture.origin.serialized();
        let body = form_encode(&[("csrf", &csrf), ("login", login), ("password", password)]);
        let started = Instant::now();
        let response = self
            .send(
                "POST",
                "/login",
                &[
                    ("Content-Type", "application/x-www-form-urlencoded"),
                    ("Origin", &origin),
                ],
                Some(body.as_bytes()),
            )
            .await?;
        let elapsed = started.elapsed();
        anyhow::ensure!(
            response.status == 200,
            "a timed sign-in answered {}",
            response.status
        );
        Ok(elapsed)
    }
}

pub fn csrf_of(html: &str) -> Option<String> {
    let start = html.find("name=\"csrf\" value=\"")? + "name=\"csrf\" value=\"".len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_string())
}

pub fn form_encode(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "+".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}
