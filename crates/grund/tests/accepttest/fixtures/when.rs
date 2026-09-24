use super::{When, client};

impl When {
    pub async fn requesting(&self, method: &str, path: &str) -> anyhow::Result<&Self> {
        self.requesting_with(method, path, &[]).await
    }

    pub async fn requesting_with(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> anyhow::Result<&Self> {
        let fixture = &self.testcase.fixture;
        let response = client::send(&fixture.origin, method, path, headers, None).await?;
        self.testcase.data().last = Some(response);
        Ok(self)
    }
}
