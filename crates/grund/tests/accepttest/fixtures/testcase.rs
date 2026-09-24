use std::sync::{Arc, Mutex, MutexGuard};

use super::{Fixture, client::Response, fixture::external_target};

/// What a test carries from one step to the next.
#[derive(Default)]
pub struct Exchange {
    /// The response the When step produced; Then asserts on it.
    pub last: Option<Response>,
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

fn split(fixture: Fixture) -> (Given, When, Then) {
    let testcase = TestCase {
        fixture: Arc::new(fixture),
        data: Arc::default(),
    };
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

/// A test against whatever target this run is pointed at.
pub async fn testcase() -> anyhow::Result<(Given, When, Then)> {
    Ok(split(Fixture::start().await?))
}

/// A test that needs the binary started with specific configuration. `None`
/// against an external target, whose configuration is not ours to choose; the
/// unit tests and the default `cargo test` run cover it there.
pub async fn testcase_configured(
    env: &[(&str, &str)],
) -> anyhow::Result<Option<(Given, When, Then)>> {
    if external_target().is_some() {
        eprintln!("skipped: needs a spawned binary with {env:?}");
        return Ok(None);
    }
    Ok(Some(split(Fixture::spawn(env).await?)))
}
