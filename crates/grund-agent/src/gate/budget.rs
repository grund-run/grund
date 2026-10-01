//! The gate's retry budget (grund-docs design/traffic.md §8.4, §13): at
//! most 2 attempts beyond the first per request, and retries at most 20 %
//! of an app's requests in any 10 s on this gate, so a failing app is not
//! hit with a retry storm.
//!
//! A floor of [`MIN_RETRIES`] per window keeps the rule from refusing the
//! one retry a quiet app needs when a copy dies under it: with two requests
//! in a window, 20 % would allow none. The budget never refuses the first
//! attempt.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Retries beyond the first attempt, per request.
pub const MAX_RETRIES_PER_REQUEST: usize = 2;

/// The share of an app's requests that may be retries.
pub const RETRY_SHARE: f64 = 0.2;

/// The window the share is counted over.
pub const WINDOW: Duration = Duration::from_secs(10);

/// Retries always allowed in a window, whatever the share.
pub const MIN_RETRIES: u64 = 10;

#[derive(Debug, Clone, Copy)]
struct Window {
    started: Instant,
    requests: u64,
    retries: u64,
    previous_requests: u64,
    previous_retries: u64,
}

impl Window {
    fn roll(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.started);
        if elapsed >= WINDOW * 2 {
            *self = Window::new(now);
        } else if elapsed >= WINDOW {
            self.previous_requests = self.requests;
            self.previous_retries = self.retries;
            self.requests = 0;
            self.retries = 0;
            self.started += WINDOW;
        }
    }

    fn new(now: Instant) -> Self {
        Self {
            started: now,
            requests: 0,
            retries: 0,
            previous_requests: 0,
            previous_retries: 0,
        }
    }

    fn sliding(&self, now: Instant) -> (f64, f64) {
        let into = now.duration_since(self.started).as_secs_f64() / WINDOW.as_secs_f64();
        let weight = (1.0 - into).clamp(0.0, 1.0);
        (
            self.requests as f64 + self.previous_requests as f64 * weight,
            self.retries as f64 + self.previous_retries as f64 * weight,
        )
    }
}

/// Per app, on this gate.
#[derive(Debug, Default)]
pub struct Budget {
    apps: Mutex<HashMap<String, Window>>,
}

impl Budget {
    /// Counts a request of `app`.
    pub fn request(&self, app: &str, now: Instant) {
        let mut apps = self.apps.lock().expect("budget lock");
        let window = apps
            .entry(app.to_string())
            .or_insert_with(|| Window::new(now));
        window.roll(now);
        window.requests += 1;
    }

    /// Whether `app` may retry now; counts the retry when it may.
    pub fn retry(&self, app: &str, now: Instant) -> bool {
        let mut apps = self.apps.lock().expect("budget lock");
        let window = apps
            .entry(app.to_string())
            .or_insert_with(|| Window::new(now));
        window.roll(now);
        let (requests, retries) = window.sliding(now);
        let allowed = (requests * RETRY_SHARE).max(MIN_RETRIES as f64);
        if retries + 1.0 > allowed {
            return false;
        }
        window.retries += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retries_stop_at_a_fifth_of_an_apps_requests_above_the_floor() {
        let budget = Budget::default();
        let now = Instant::now();
        for _ in 0..1000 {
            budget.request("shop", now);
        }
        let allowed = (0..400).filter(|_| budget.retry("shop", now)).count();
        assert_eq!(allowed, 200);
        assert!(budget.retry("blog", now), "another app has its own budget");
    }

    #[test]
    fn a_quiet_app_still_gets_the_floor_and_the_budget_refills_with_time() {
        let budget = Budget::default();
        let now = Instant::now();
        budget.request("shop", now);
        let allowed = (0..50).filter(|_| budget.retry("shop", now)).count();
        assert_eq!(allowed, MIN_RETRIES as usize);
        assert!(budget.retry("shop", now + WINDOW * 3));
    }
}
