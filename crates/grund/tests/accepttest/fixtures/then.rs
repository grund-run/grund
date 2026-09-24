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
}
