use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

use super::{Fixture, client::Response, fixture::external_target};

#[derive(Default)]
pub struct Exchange {
    pub last: Option<Response>,
    pub cookies: BTreeMap<String, String>,
    pub account: Option<Account>,
    pub remembered: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct Account {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Clone)]
pub struct TestCase {
    pub fixture: Arc<Fixture>,
    pub data: Arc<Mutex<Exchange>>,
}

impl TestCase {
    pub fn data(&self) -> MutexGuard<'_, Exchange> {
        self.data.lock().unwrap()
    }

    pub fn another_browser(&self) -> (Given, When, Then) {
        split(TestCase {
            fixture: self.fixture.clone(),
            data: Arc::default(),
        })
    }
}

pub struct Given {
    pub testcase: TestCase,
}
pub struct When {
    pub testcase: TestCase,
}
pub struct Then {
    pub testcase: TestCase,
}

fn split(testcase: TestCase) -> (Given, When, Then) {
    (
        Given {
            testcase: testcase.clone(),
        },
        When {
            testcase: testcase.clone(),
        },
        Then { testcase },
    )
}

pub async fn testcase() -> anyhow::Result<(Given, When, Then)> {
    Ok(split(TestCase {
        fixture: Arc::new(Fixture::start().await?),
        data: Arc::default(),
    }))
}

pub async fn testcase_with_mail() -> anyhow::Result<Option<(Given, When, Then)>> {
    let fixture = Fixture::start().await?;
    if fixture.mailpit.is_none() {
        eprintln!("skipped: needs the target's mail (GRUND_ACCEPT_MAILPIT_URL)");
        return Ok(None);
    }
    Ok(Some(split(TestCase {
        fixture: Arc::new(fixture),
        data: Arc::default(),
    })))
}

pub async fn testcase_configured(
    env: &[(&str, &str)],
) -> anyhow::Result<Option<(Given, When, Then)>> {
    if external_target().is_some() {
        eprintln!("skipped: needs a spawned binary with {env:?}");
        return Ok(None);
    }
    Ok(Some(split(TestCase {
        fixture: Arc::new(Fixture::spawn(env).await?),
        data: Arc::default(),
    })))
}
