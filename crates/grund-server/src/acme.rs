//! The ACME client side of the instance's certificates (grund-docs
//! design/traffic.md §5): the account, orders, challenges and renewal
//! information, through instant-acme.
//!
//! instant-acme speaks ACME; this module gives it an HTTP client with
//! deadlines and a memory for the CA's Retry-After, which instant-acme's own
//! errors do not carry. The decisions (when to renew, how long to back off)
//! are pure functions at the bottom, tested on their own.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use anyhow::Context;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};

/// Each request to the CA must finish within this.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest a CA's Retry-After is honoured for; beyond it the next
/// attempt waits this long instead.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(24 * 3600);

/// The longest the backoff between failed orders grows to (traffic.md §5.5).
pub const MAX_BACKOFF: Duration = Duration::from_secs(12 * 3600);

/// An HTTP client for instant-acme: reqwest with a per-request deadline,
/// optional extra roots, and the Retry-After of the last refused response.
#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
    retry_after: Arc<Mutex<Option<SystemTime>>>,
}

impl Http {
    /// A client trusting the system roots and, when given, the PEM roots in
    /// `extra_roots` (GRUND_ACME_CA_FILE).
    pub fn new(extra_roots: Option<&std::path::Path>) -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("grund/", env!("CARGO_PKG_VERSION")));
        if let Some(path) = extra_roots {
            let pem = std::fs::read(path)
                .with_context(|| format!("read GRUND_ACME_CA_FILE {}", path.display()))?;
            let roots = reqwest::Certificate::from_pem_bundle(&pem).with_context(|| {
                format!(
                    "GRUND_ACME_CA_FILE {} holds no PEM certificate",
                    path.display()
                )
            })?;
            anyhow::ensure!(
                !roots.is_empty(),
                "GRUND_ACME_CA_FILE {} holds no PEM certificate",
                path.display()
            );
            builder = builder.tls_certs_merge(roots);
        }
        Ok(Self {
            client: builder.build().context("the ACME HTTP client")?,
            retry_after: Arc::default(),
        })
    }

    /// The Retry-After of the last response the CA refused, if it sent one,
    /// and forgets it.
    pub fn take_retry_after(&self) -> Option<Duration> {
        let at = self.retry_after.lock().expect("retry-after lock").take()?;
        Some(
            at.duration_since(SystemTime::now())
                .unwrap_or(Duration::ZERO),
        )
    }
}

impl HttpClient for Http {
    fn request(
        &self,
        request: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let client = self.client.clone();
        let slot = self.retry_after.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let body = http_body_util::BodyExt::collect(body)
                .await
                .map(http_body_util::Collected::to_bytes)
                .unwrap_or_else(|never| match never {});
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .send()
                .await
                .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
            if !response.status().is_success()
                && let Some(at) = response
                    .headers()
                    .get(http::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_retry_after)
            {
                *slot.lock().expect("retry-after lock") = Some(at);
            }
            let mut head = http::Response::builder().status(response.status());
            for (name, value) in response.headers() {
                head = head.header(name, value);
            }
            let bytes = response
                .bytes()
                .await
                .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
            let (parts, ()) = head
                .body(())
                .map_err(instant_acme::Error::Http)?
                .into_parts();
            Ok(BytesResponse {
                parts,
                body: Box::new(bytes),
            })
        })
    }
}

fn parse_retry_after(value: &str) -> Option<SystemTime> {
    let value = value.trim();
    match value.parse::<u64>() {
        Ok(seconds) => Some(SystemTime::now() + Duration::from_secs(seconds)),
        Err(_) => httpdate::parse_http_date(value).ok(),
    }
}

/// Why an attempt failed, as a stable code for the database and readiness,
/// and whether the order behind it may be resumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The CA could not be reached, or did not answer in time.
    Unreachable,
    /// The CA refused for rate limits (it may have said until when).
    RateLimited,
    /// The CA could not validate a name: the challenge failed.
    AuthorizationFailed,
    /// The CA refused the request otherwise.
    Refused,
    /// The order did not finish within the attempt's deadline; it is
    /// resumed next time.
    TimedOut,
    /// A remote terminator did not say it answers its challenge in time.
    TerminatorUnreachable,
    /// Anything on this side: the database, sealing, a bad chain.
    Internal,
}

impl Failure {
    /// The code stored in `last_error`.
    pub fn code(self) -> &'static str {
        match self {
            Failure::Unreachable => "acme_unreachable",
            Failure::RateLimited => "acme_rate_limited",
            Failure::AuthorizationFailed => "authorization_failed",
            Failure::Refused => "acme_refused",
            Failure::TimedOut => "order_timed_out",
            Failure::TerminatorUnreachable => "terminator_unreachable",
            Failure::Internal => "internal",
        }
    }

    /// What instant-acme's error means here.
    pub fn of(error: &instant_acme::Error) -> Self {
        match error {
            instant_acme::Error::Api(problem) => match problem.r#type.as_deref() {
                Some(t) if t.ends_with(":rateLimited") => Failure::RateLimited,
                Some(t) if t.ends_with(":badNonce") => Failure::Unreachable,
                _ if problem.status.is_some_and(|s| s >= 500) => Failure::Unreachable,
                _ => Failure::Refused,
            },
            instant_acme::Error::Other(_) => Failure::Unreachable,
            instant_acme::Error::Timeout(_) => Failure::TimedOut,
            _ => Failure::Internal,
        }
    }
}

/// When to start renewing, given the CA's suggested window (RFC 9773 §4.2):
/// a uniformly random point in it (`unit` in [0, 1)), not before `now`, and
/// `now` itself once the window has passed.
pub fn renewal_time(
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    now: DateTime<Utc>,
    unit: f64,
) -> DateTime<Utc> {
    let start = start.max(now);
    if end <= start {
        return now;
    }
    let span = (end - start).num_milliseconds() as f64;
    start + chrono::Duration::milliseconds((span * unit.clamp(0.0, 1.0)) as i64)
}

/// When to renew without renewal information: two thirds into the lifetime,
/// as traffic.md §5.6 falls back to.
pub fn fallback_renewal_time(not_before: DateTime<Utc>, not_after: DateTime<Utc>) -> DateTime<Utc> {
    not_before + (not_after - not_before) * 2 / 3
}

/// How long to wait after the `failures`-th consecutive failure (0 for the
/// first): `base`, doubling each time, stretched by up to half again as
/// jitter (`unit` in [0, 1)) so instances spread out, at most
/// [`MAX_BACKOFF`], and never less than the CA's `retry_after` (capped at
/// [`MAX_RETRY_AFTER`]). The jitter only lengthens a wait, so the base alone
/// bounds how often a broken setup fails.
pub fn backoff(
    failures: u32,
    base: Duration,
    retry_after: Option<Duration>,
    unit: f64,
) -> Duration {
    let doubled = base
        .checked_mul(1u32 << failures.min(20))
        .unwrap_or(MAX_BACKOFF)
        .min(MAX_BACKOFF);
    let jittered = doubled
        .mul_f64(1.0 + 0.5 * unit.clamp(0.0, 1.0))
        .min(MAX_BACKOFF);
    match retry_after {
        Some(asked) => jittered.max(asked.min(MAX_RETRY_AFTER)),
        None => jittered,
    }
}

/// A uniform random number in [0, 1), for jitter and renewal times.
pub fn unit_random() -> f64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("the operating system provides randomness");
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(seconds, 0).unwrap()
    }

    #[test]
    fn renewal_falls_inside_the_window_and_never_before_now() {
        let (start, end) = (at(1000), at(2000));
        assert_eq!(renewal_time(start, end, at(0), 0.0), start);
        assert_eq!(renewal_time(start, end, at(0), 0.5), at(1500));
        assert_eq!(renewal_time(start, end, at(1500), 0.0), at(1500));
        assert!(renewal_time(start, end, at(0), 0.999_999) < end);
    }

    #[test]
    fn a_window_that_has_passed_renews_now() {
        assert_eq!(renewal_time(at(1000), at(2000), at(5000), 0.7), at(5000));
    }

    #[test]
    fn without_renewal_information_renewal_is_two_thirds_in() {
        assert_eq!(fallback_renewal_time(at(0), at(90 * 86400)), at(60 * 86400));
    }

    #[test]
    fn backoff_doubles_from_its_base_and_stops_at_twelve_hours() {
        let base = Duration::from_secs(300);
        assert_eq!(backoff(0, base, None, 0.0), base);
        assert_eq!(backoff(1, base, None, 0.0), base * 2);
        assert_eq!(backoff(0, base, None, 0.5), base * 5 / 4);
        assert_eq!(backoff(30, base, None, 0.0), MAX_BACKOFF);
    }

    #[test]
    fn five_failed_validations_take_more_than_an_hour_at_the_default_base() {
        let base = Duration::from_secs(300);
        let waited: Duration = (0..4).map(|n| backoff(n, base, None, 0.0)).sum();
        assert!(waited >= Duration::from_secs(3600), "{waited:?}");
    }

    #[test]
    fn a_longer_retry_after_is_waited_out_but_not_forever() {
        let base = Duration::from_secs(60);
        let asked = Duration::from_secs(7200);
        assert_eq!(backoff(0, base, Some(asked), 0.0), asked);
        assert_eq!(
            backoff(3, base, Some(Duration::from_secs(1)), 0.0),
            base * 8
        );
        assert_eq!(
            backoff(0, base, Some(Duration::from_secs(10 * 86400)), 0.0),
            MAX_RETRY_AFTER
        );
    }

    #[test]
    fn retry_after_is_read_as_seconds_or_an_http_date() {
        let soon = parse_retry_after("120").unwrap();
        let wait = soon.duration_since(SystemTime::now()).unwrap();
        assert!(wait > Duration::from_secs(110) && wait <= Duration::from_secs(120));
        assert!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT").is_some());
        assert!(parse_retry_after("soon").is_none());
    }

    #[test]
    fn a_rate_limit_and_an_outage_are_told_apart() {
        let problem = |t: &str, status: u16| {
            instant_acme::Error::Api(instant_acme::Problem {
                r#type: Some(t.into()),
                detail: None,
                status: Some(status),
                subproblems: Vec::new(),
            })
        };
        assert_eq!(
            Failure::of(&problem("urn:ietf:params:acme:error:rateLimited", 429)),
            Failure::RateLimited
        );
        assert_eq!(
            Failure::of(&problem("urn:ietf:params:acme:error:serverInternal", 500)),
            Failure::Unreachable
        );
        assert_eq!(
            Failure::of(&problem(
                "urn:ietf:params:acme:error:rejectedIdentifier",
                400
            )),
            Failure::Refused
        );
        assert_eq!(
            Failure::of(&instant_acme::Error::Timeout(None)),
            Failure::TimedOut
        );
    }

    #[test]
    fn random_units_stay_in_range() {
        for _ in 0..1000 {
            let unit = unit_random();
            assert!((0.0..1.0).contains(&unit));
        }
    }
}
