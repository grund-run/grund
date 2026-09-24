use anyhow::Context;

use super::{Account, Given, When, fixture::random_hex};

impl Given {
    pub fn a_fresh_name(&self, prefix: &str) -> String {
        format!("{prefix}-{}", random_hex(5))
    }

    pub async fn an_unconfirmed_account(&self) -> anyhow::Result<Account> {
        let username = self.a_fresh_name("acc");
        let account = Account {
            email: format!("{username}@accept.test"),
            username,
            password: format!("pw {} correct horse", random_hex(6)),
        };
        let when = When {
            testcase: self.testcase.clone(),
        };
        when.signing_up(&account.username, &account.email, &account.password)
            .await?;
        let status = self.testcase.data().last.as_ref().map(|r| r.status);
        anyhow::ensure!(status == Some(303), "sign-up answered {status:?}");
        self.testcase.data().account = Some(account.clone());
        Ok(account)
    }

    pub async fn an_account(&self) -> anyhow::Result<Account> {
        let account = self.an_unconfirmed_account().await?;
        let when = When {
            testcase: self.testcase.clone(),
        };
        when.following_the_mailed_link(&account.email, "Confirm your email", "/verify?token=")
            .await?;
        when.submitting_on_current_page("/verify", &[("token", &self.last_token()?)])
            .await?;
        let status = self.testcase.data().last.as_ref().map(|r| r.status);
        anyhow::ensure!(status == Some(200), "verification answered {status:?}");
        Ok(account)
    }

    pub async fn a_signed_in_account(&self) -> anyhow::Result<Account> {
        let account = self.an_account().await?;
        let when = When {
            testcase: self.testcase.clone(),
        };
        when.signing_in(&account.username, &account.password)
            .await?;
        let status = self.testcase.data().last.as_ref().map(|r| r.status);
        anyhow::ensure!(status == Some(303), "sign-in answered {status:?}");
        Ok(account)
    }

    pub fn last_token(&self) -> anyhow::Result<String> {
        let html = self
            .testcase
            .data()
            .last
            .as_ref()
            .map(|r| r.text())
            .context("no page")?;
        let start = html
            .find("name=\"token\" value=\"")
            .context("no token field")?
            + "name=\"token\" value=\"".len();
        let end = html[start..].find('"').context("unterminated")? + start;
        Ok(html[start..end].to_string())
    }

    pub fn the_session_cookie(&self) -> Option<String> {
        self.testcase
            .data()
            .cookies
            .iter()
            .find(|(name, _)| name.ends_with("grund_session"))
            .map(|(_, value)| value.clone())
    }

    pub fn remember(&self, key: &str, value: &str) {
        self.testcase
            .data()
            .remembered
            .insert(key.to_string(), value.to_string());
    }

    pub fn recall(&self, key: &str) -> Option<String> {
        self.testcase.data().remembered.get(key).cloned()
    }
}

pub async fn mail_count(given: &Given, to: &str) -> anyhow::Result<usize> {
    let mailpit = given
        .testcase
        .fixture
        .mailpit
        .clone()
        .context("no mailpit")?;
    super::mail::count_to(&mailpit, to).await
}
