use anyhow::{Context, ensure};

use super::{Then, client::Response};

impl Then {
    fn last(&self) -> anyhow::Result<Response> {
        self.testcase
            .data()
            .last
            .clone()
            .context("no request was made")
    }

    pub fn status(&self, expected: u16) -> anyhow::Result<&Self> {
        let response = self.last()?;
        ensure!(
            response.status == expected,
            "status: got {}, wanted {expected}\n{}",
            response.status,
            response.text().chars().take(2000).collect::<String>()
        );
        Ok(self)
    }

    pub fn status_in(&self, allowed: &[u16]) -> anyhow::Result<&Self> {
        let status = self.last()?.status;
        ensure!(
            allowed.contains(&status),
            "status: got {status}, wanted one of {allowed:?}"
        );
        Ok(self)
    }

    pub fn header(&self, name: &str, expected: &str) -> anyhow::Result<&Self> {
        let response = self.last()?;
        let value = response.header(name);
        ensure!(
            value == Some(expected),
            "{name}: got {value:?}, wanted {expected:?}"
        );
        Ok(self)
    }

    pub fn header_contains(&self, name: &str, needle: &str) -> anyhow::Result<&Self> {
        let response = self.last()?;
        let value = response.header(name).unwrap_or_default();
        ensure!(value.contains(needle), "{name}: {value:?} lacks {needle:?}");
        Ok(self)
    }

    pub fn header_lacks(&self, name: &str, needle: &str) -> anyhow::Result<&Self> {
        let response = self.last()?;
        let value = response.header(name).unwrap_or_default();
        ensure!(
            !value.contains(needle),
            "{name}: {value:?} contains {needle:?}"
        );
        Ok(self)
    }

    pub fn json(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::from_slice(&self.last()?.body).context("body is not JSON")
    }

    pub fn json_field_is_set(&self, field: &str) -> anyhow::Result<&Self> {
        let json = self.json()?;
        let value = json[field].as_str().unwrap_or_default();
        ensure!(!value.is_empty(), "{field} is missing or empty in {json}");
        Ok(self)
    }

    pub fn carries_the_security_headers(&self) -> anyhow::Result<&Self> {
        self.header_contains("content-security-policy", "default-src 'none'")?
            .header_contains("content-security-policy", "script-src 'self'")?
            .header_contains("content-security-policy", "frame-ancestors 'none'")?
            .header_contains("content-security-policy", "form-action 'self'")?
            .header_lacks("content-security-policy", "unsafe-inline")?
            .header_lacks("content-security-policy", "unsafe-eval")?
            .header("x-content-type-options", "nosniff")?
            .header("x-frame-options", "DENY")
    }

    pub fn redirects_to(&self, location: &str) -> anyhow::Result<&Self> {
        self.status(303)?.header("location", location)
    }

    pub fn body_contains(&self, needle: &str) -> anyhow::Result<&Self> {
        let text = self.last()?.text();
        ensure!(
            text.contains(needle),
            "body lacks {needle:?}:\n{}",
            text.chars().take(3000).collect::<String>()
        );
        Ok(self)
    }

    pub fn body_lacks(&self, needle: &str) -> anyhow::Result<&Self> {
        let text = self.last()?.text();
        ensure!(!text.contains(needle), "body contains {needle:?}");
        Ok(self)
    }

    pub fn sets_cookie(&self, name_suffix: &str) -> anyhow::Result<String> {
        let response = self.last()?;
        response
            .headers_named("set-cookie")
            .into_iter()
            .find(|c| {
                c.split('=')
                    .next()
                    .is_some_and(|n| n.ends_with(name_suffix))
                    && !c.contains("Max-Age=0")
            })
            .map(str::to_string)
            .with_context(|| format!("no Set-Cookie for {name_suffix}"))
    }

    pub fn sets_no_session_cookie(&self) -> anyhow::Result<&Self> {
        let response = self.last()?;
        let set = response.headers_named("set-cookie").into_iter().any(|c| {
            c.split('=')
                .next()
                .is_some_and(|n| n.ends_with("grund_session"))
                && !c.contains("Max-Age=0")
        });
        ensure!(!set, "a session cookie was set");
        Ok(self)
    }

    pub fn page_without_its_token(&self) -> anyhow::Result<String> {
        let text = self.last()?.text();
        let mut out = String::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find("value=\"") {
            out.push_str(&rest[..at]);
            let after = &rest[at + 7..];
            let end = after.find('"').unwrap_or(0);
            out.push_str("value=\"…\"");
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(out)
    }

    pub fn is_the_page(&self, other: &str) -> anyhow::Result<&Self> {
        let this = self.page_without_its_token()?;
        ensure!(this == other, "the two answers differ");
        Ok(self)
    }
}
