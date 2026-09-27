//! Bounded retry for the patch API's JSON calls on HTTP 429 / 503.
//!
//! `scan` keeps up to 32 patch-API requests in flight, so a throttling
//! server (or a proxy / WAF in front of it) answering `429 Too Many
//! Requests` or `503 Service Unavailable` is expected, not exotic. Each
//! such answer is retried a bounded number of times before it becomes the
//! request's error:
//!
//! - at most [`ApiRetryPolicy::max_retries`] retries per request (3 by
//!   default, [`API_MAX_RETRIES_ENV`] overrides, `0` disables);
//! - the wait honors the server's `Retry-After` (delta-seconds or an
//!   HTTP-date), capped at [`ApiRetryPolicy::max_retry_after`] (30 s);
//!   without one it is exponential from [`ApiRetryPolicy::base_delay`]
//!   (500 ms, 1 s, 2 s, ... capped at [`ApiRetryPolicy::max_backoff`]) with
//!   "equal jitter" — each wait lands in `[d/2, d)`, the sample derived
//!   deterministically from a seed, the request and the retry number;
//! - every wait is drawn from one run-wide budget
//!   ([`ApiRetryPolicy::run_wait_budget`], 60 s of summed waiting): once it
//!   is spent, the next throttled answer is final at once, so a throttled
//!   run adds at most that much waiting however many requests it makes.
//!
//! Nothing else is retried here: other 4xx (401/403 keep driving the proxy
//! fallback), other 5xx and transport errors surface on the first answer,
//! exactly as before. Retries happen inside each request's future, so the
//! callers' ordered folds (`ordered_concurrent`) see the same sequence of
//! results a clean run produces.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::StatusCode;

/// Env override for [`ApiRetryPolicy::max_retries`]: a non-negative
/// integer, clamped to [`MAX_RETRIES_CEILING`]; `0` turns retries off. An
/// unset, empty or unparsable value keeps the default.
pub const API_MAX_RETRIES_ENV: &str = "SOCKET_API_MAX_RETRIES";

/// The most retries [`API_MAX_RETRIES_ENV`] can ask for per request.
pub const MAX_RETRIES_CEILING: u32 = 10;

/// Retry policy for the patch API's JSON calls (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiRetryPolicy {
    /// Retries per request after the first attempt (`0` = never retry).
    pub max_retries: u32,
    /// First backoff step without a `Retry-After`; doubles per retry.
    pub base_delay: Duration,
    /// Cap on one backoff step (before jitter halves its lower bound).
    pub max_backoff: Duration,
    /// Cap on one wait taken from a server's `Retry-After`.
    pub max_retry_after: Duration,
    /// Summed waiting all requests sharing the budget may spend.
    pub run_wait_budget: Duration,
}

impl Default for ApiRetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_backoff: Duration::from_secs(8),
            max_retry_after: Duration::from_secs(30),
            run_wait_budget: Duration::from_secs(60),
        }
    }
}

impl ApiRetryPolicy {
    /// No retries: every 429 / 503 is final on the first answer (the
    /// behavior before retries existed).
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Self::default()
        }
    }

    /// The default policy with [`API_MAX_RETRIES_ENV`] applied.
    pub fn from_env() -> Self {
        let mut policy = Self::default();
        if let Some(n) = max_retries_override(std::env::var(API_MAX_RETRIES_ENV).ok().as_deref()) {
            policy.max_retries = n;
        }
        policy
    }

    /// The pause before retry number `retry` (1-based): the server's
    /// `Retry-After` under [`Self::max_retry_after`] when it sent one,
    /// otherwise the jittered exponential step (`jitter` in `[0, 1)`).
    pub fn delay(&self, retry: u32, retry_after: Option<Duration>, jitter: f64) -> Duration {
        if let Some(after) = retry_after {
            return after.min(self.max_retry_after);
        }
        let step = self
            .base_delay
            .saturating_mul(1u32 << retry.saturating_sub(1).min(16))
            .min(self.max_backoff);
        // Equal jitter: [step/2, step).
        let half = step / 2;
        half + half.mul_f64(jitter.clamp(0.0, 1.0))
    }
}

/// [`API_MAX_RETRIES_ENV`]'s value as a retry count, or `None` to keep the
/// default (unset, empty, or not a non-negative integer).
fn max_retries_override(raw: Option<&str>) -> Option<u32> {
    let n = raw?.trim().parse::<u64>().ok()?;
    Some(n.min(u64::from(MAX_RETRIES_CEILING)) as u32)
}

/// Is this answer one the retry loop may repeat? (429 and 503 only.)
pub fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE
    )
}

/// A `Retry-After` header as a wait from `now_unix_secs`: delta-seconds
/// (`Retry-After: 7`) or an HTTP-date (`Retry-After: Fri, 27 Mar 2026
/// 19:12:42 GMT`; a date already past waits zero). `None` when absent or
/// unreadable — the caller then backs off exponentially.
pub fn parse_retry_after(headers: &HeaderMap, now_unix_secs: u64) -> Option<Duration> {
    let raw = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if raw.bytes().all(|b| b.is_ascii_digit()) {
        return raw.parse::<u64>().ok().map(Duration::from_secs);
    }
    // Only the date forms: a signed or fractional number is malformed.
    if raw.starts_with(['-', '+']) || raw.parse::<f64>().is_ok() {
        return None;
    }
    let at = crate::api::date::parse_timestamp_secs(raw)?;
    Some(Duration::from_secs(at.saturating_sub(now_unix_secs)))
}

/// The jitter sample in `[0, 1)` for retry `retry` of the request `key`
/// under `seed`: a SplitMix64 mix, so a given seed replays the same waits
/// (tests) while distinct requests and processes stay desynchronized.
pub fn jitter_sample(seed: u64, key: &str, retry: u32) -> f64 {
    // FNV-1a over the key, folded with the seed and the retry number.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut z = seed ^ h ^ u64::from(retry).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    (z >> 11) as f64 / (1u64 << 53) as f64
}

/// The retry loop's sleep, injectable so tests run on a virtual clock.
pub type RetrySleep =
    Arc<dyn Fn(Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// The retry loop's view of time and randomness. [`Default`] is the real
/// thing (tokio's sleep, the system clock, a per-process random seed);
/// tests substitute a recorder and fixed values.
#[derive(Clone)]
pub struct RetryHooks {
    /// Waits out one retry delay.
    pub sleep: RetrySleep,
    /// Now, as UNIX seconds (resolves an HTTP-date `Retry-After`).
    pub now_unix_secs: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Seed for [`jitter_sample`].
    pub jitter_seed: u64,
}

impl Default for RetryHooks {
    fn default() -> Self {
        Self {
            sleep: Arc::new(|d| Box::pin(tokio::time::sleep(d))),
            now_unix_secs: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs())
            }),
            jitter_seed: process_seed(),
        }
    }
}

impl std::fmt::Debug for RetryHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetryHooks")
            .field("jitter_seed", &self.jitter_seed)
            .finish_non_exhaustive()
    }
}

/// One random seed per process (std's randomly keyed hasher; no RNG
/// dependency).
fn process_seed() -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _};
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(0x5eed);
        hasher.finish()
    })
}

/// The run-wide wait budget every default client draws from: one CLI run
/// is one process, and a run builds several clients (discovery, download,
/// the proxy fallback), so the budget is process-wide rather than
/// per-client.
fn process_budget() -> Arc<AtomicU64> {
    static BUDGET: OnceLock<Arc<AtomicU64>> = OnceLock::new();
    Arc::clone(BUDGET.get_or_init(|| {
        Arc::new(AtomicU64::new(millis(
            ApiRetryPolicy::default().run_wait_budget,
        )))
    }))
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// A client's retry state: the policy, the shared wait budget, the hooks.
#[derive(Debug, Clone)]
pub(crate) struct ApiRetry {
    pub(crate) policy: ApiRetryPolicy,
    /// Milliseconds of waiting left, shared by every client holding it.
    budget_ms: Arc<AtomicU64>,
    pub(crate) hooks: RetryHooks,
}

impl ApiRetry {
    /// The default: [`ApiRetryPolicy::from_env`] on the process budget.
    pub(crate) fn from_env() -> Self {
        Self {
            policy: ApiRetryPolicy::from_env(),
            budget_ms: process_budget(),
            hooks: RetryHooks::default(),
        }
    }

    /// `policy` on a FRESH budget of its own `run_wait_budget` (tests, or a
    /// caller that wants isolation from the process budget).
    pub(crate) fn with_policy(policy: ApiRetryPolicy, hooks: RetryHooks) -> Self {
        Self {
            policy,
            budget_ms: Arc::new(AtomicU64::new(millis(policy.run_wait_budget))),
            hooks,
        }
    }

    /// Take `delay` from the budget; `false` (nothing taken) when too
    /// little is left.
    pub(crate) fn reserve(&self, delay: Duration) -> bool {
        let want = millis(delay);
        self.budget_ms
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(want)
            })
            .is_ok()
    }

    /// Milliseconds of waiting left (tests).
    #[cfg(test)]
    pub(crate) fn budget_left_ms(&self) -> u64 {
        self.budget_ms.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::HeaderValue;

    fn headers(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(RETRY_AFTER, HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn retry_after_delta_seconds() {
        assert_eq!(
            parse_retry_after(&headers("7"), 0),
            Some(Duration::from_secs(7))
        );
        assert_eq!(parse_retry_after(&headers(" 0 "), 0), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_http_date_is_relative_to_now() {
        // Fri, 27 Mar 2026 19:12:42 GMT = 1774638762.
        let at = 1_774_638_762u64;
        let h = headers("Fri, 27 Mar 2026 19:12:42 GMT");
        assert_eq!(
            parse_retry_after(&h, at - 12),
            Some(Duration::from_secs(12))
        );
        // A date in the past waits zero.
        assert_eq!(parse_retry_after(&h, at + 100), Some(Duration::ZERO));
    }

    #[test]
    fn retry_after_malformed_or_absent_is_none() {
        assert_eq!(parse_retry_after(&HeaderMap::new(), 0), None);
        for bad in ["-3", "+3", "1.5", "soon", ""] {
            assert_eq!(parse_retry_after(&headers(bad), 0), None, "{bad:?}");
        }
    }

    #[test]
    fn delay_caps_retry_after_and_jitters_backoff_into_the_upper_half() {
        let p = ApiRetryPolicy::default();
        assert_eq!(
            p.delay(1, Some(Duration::from_secs(120)), 0.9),
            Duration::from_secs(30),
            "Retry-After is capped"
        );
        assert_eq!(
            p.delay(2, Some(Duration::from_secs(3)), 0.9),
            Duration::from_secs(3),
            "Retry-After ignores jitter and the backoff step"
        );
        // Steps 500 ms, 1 s, 2 s, 4 s, 8 s, 8 s: each wait in [step/2, step).
        for (retry, step_ms) in [(1u32, 500u64), (2, 1000), (3, 2000), (5, 8000), (9, 8000)] {
            let lo = p.delay(retry, None, 0.0);
            let hi = p.delay(retry, None, 0.999_999);
            assert_eq!(lo, Duration::from_millis(step_ms / 2), "retry {retry}");
            assert!(hi < Duration::from_millis(step_ms), "retry {retry}: {hi:?}");
            assert!(hi > lo);
        }
    }

    #[test]
    fn jitter_is_deterministic_per_seed_key_and_retry() {
        let a = jitter_sample(42, "GET /x", 1);
        assert_eq!(a, jitter_sample(42, "GET /x", 1));
        assert_ne!(a, jitter_sample(43, "GET /x", 1));
        assert_ne!(a, jitter_sample(42, "GET /y", 1));
        assert_ne!(a, jitter_sample(42, "GET /x", 2));
        for i in 0..1000u32 {
            let j = jitter_sample(u64::from(i), "k", i % 4);
            assert!((0.0..1.0).contains(&j), "{j}");
        }
    }

    #[test]
    fn max_retries_env_parsing() {
        assert_eq!(max_retries_override(None), None);
        assert_eq!(max_retries_override(Some("")), None);
        assert_eq!(max_retries_override(Some("x")), None);
        assert_eq!(max_retries_override(Some("-1")), None);
        assert_eq!(max_retries_override(Some("0")), Some(0));
        assert_eq!(max_retries_override(Some(" 5 ")), Some(5));
        assert_eq!(
            max_retries_override(Some("1000")),
            Some(MAX_RETRIES_CEILING)
        );
    }

    #[test]
    fn budget_reserves_until_spent_and_never_goes_negative() {
        let retry = ApiRetry::with_policy(
            ApiRetryPolicy {
                run_wait_budget: Duration::from_secs(3),
                ..ApiRetryPolicy::default()
            },
            RetryHooks::default(),
        );
        assert!(retry.reserve(Duration::from_secs(2)));
        assert!(!retry.reserve(Duration::from_secs(2)), "only 1 s left");
        assert_eq!(retry.budget_left_ms(), 1000);
        assert!(retry.reserve(Duration::from_secs(1)));
        assert!(retry.reserve(Duration::ZERO), "a zero wait is always free");
        assert!(!retry.reserve(Duration::from_millis(1)));
        // Clones share the budget.
        let clone = retry.clone();
        assert!(!clone.reserve(Duration::from_millis(1)));
    }

    #[test]
    fn only_429_and_503_are_retryable() {
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE));
        for s in [400u16, 401, 403, 404, 408, 500, 502, 504] {
            assert!(
                !is_retryable_status(StatusCode::from_u16(s).unwrap()),
                "{s}"
            );
        }
    }
}
