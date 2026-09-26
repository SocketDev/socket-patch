//! Ordered, bounded concurrency for independent network requests.
//!
//! The CLI's patch-API loops (batch discovery, per-package detail GETs,
//! hosted record views) used to await one request at a time, so a run
//! paid one round trip per request. Every consumer here must keep its
//! output byte-identical to the serial loop, so the only primitive on
//! offer is the ORDERED one: at most `limit` futures run at once, and
//! results come back in input order no matter which request finishes
//! first. Callers fold them exactly as the serial loop did (warnings,
//! failure lists, first-error rules), so nothing downstream can tell the
//! difference. Never swap in `buffer_unordered`.
//!
//! Everything runs on the caller's task (no `spawn`), so the futures may
//! borrow (`&ApiClient`) and need not be `Send`.
//!
//! `--debug` is part of that output. Every window here wraps its request in
//! [`crate::api::client::hold_back_debug`] and releases it at the fold, so
//! each request's lines print where the serial loop's would have and a
//! window the caller drops (the batch fallback) announces nothing the
//! serial loop would not have announced. Relying on the order the futures
//! happen to be first-polled in would work today and is exactly what
//! `hold_back_debug` exists to stop depending on.

use std::future::Future;

use futures_util::stream::{self, Stream, StreamExt};

use crate::utils::env_compat::is_debug_enabled;

/// In-flight request cap for the authenticated patch API. Measured with
/// no 429s up to 32 in flight; 8 already makes the loops latency-flat.
pub const API_CONCURRENCY: usize = 8;

/// In-flight request cap on the public patch proxy, which serializes
/// anonymous callers behind one shared server-side semaphore — stay
/// polite there.
pub const PROXY_API_CONCURRENCY: usize = 4;

/// Operator override for the caps above: the escape hatch for an endpoint
/// that caps in-flight requests per client (a self-hosted `--api-url`, a
/// corporate reverse proxy, a WAF or CDN). `1` restores the old strictly
/// serial loops exactly.
pub const API_CONCURRENCY_ENV: &str = "SOCKET_API_CONCURRENCY";

/// Largest value [`API_CONCURRENCY_ENV`] can ask for — the most in-flight
/// requests the patch API was measured to answer without a 429.
const MAX_API_CONCURRENCY: usize = 32;

/// In-flight cap for pristine downloads from the PUBLIC package registries
/// (npmjs.org, PyPI, crates.io, RubyGems, the Go proxy, Maven Central).
/// Deliberately its own number, not [`API_CONCURRENCY`]: those hosts are
/// not the patch API, they have their own rate limits, the fetcher has no
/// 429/`Retry-After` handling, and [`API_CONCURRENCY_ENV`] is the escape
/// hatch for an operator's *patch API* — turning it up must not turn a
/// public registry up with it. 4 keeps the lockfile-only ladder latency-
/// flat without bursting at anyone.
pub const REGISTRY_CONCURRENCY: usize = 4;

/// The in-flight cap for pristine registry downloads; see
/// [`REGISTRY_CONCURRENCY`]. No env override — a tight `RLIMIT_NOFILE`
/// still forces one at a time, for the reason [`api_concurrency`] gives.
pub fn registry_concurrency() -> usize {
    if crate::crawlers::walk_pool::fd_limit_is_tight() {
        return 1;
    }
    REGISTRY_CONCURRENCY
}

/// The in-flight cap for a client on the public proxy (`true`) or the
/// authenticated API (`false`).
///
/// [`API_CONCURRENCY_ENV`] overrides it, clamped to
/// `1..=MAX_API_CONCURRENCY`; an unset, empty or unparsable value leaves
/// the default in place. On the public proxy the override can only LOWER
/// the cap: that server's semaphore is shared across anonymous callers, so
/// widening it is not one client's call to make.
///
/// Under a tight `RLIMIT_NOFILE`
/// ([`crate::crawlers::walk_pool::fd_limit_is_tight`]) the cap is 1 whatever
/// the override asks for: each in-flight request holds its own socket, and
/// the serial loop never held more than one, so extra connections could fail
/// with `EMFILE` where the serial loop's single connection succeeded (or
/// failed differently).
pub fn api_concurrency(use_public_proxy: bool) -> usize {
    api_concurrency_under(
        use_public_proxy,
        crate::crawlers::walk_pool::fd_limit_is_tight(),
    )
}

fn api_concurrency_under(use_public_proxy: bool, fd_limit_is_tight: bool) -> usize {
    if fd_limit_is_tight {
        return 1;
    }
    let default = if use_public_proxy {
        PROXY_API_CONCURRENCY
    } else {
        API_CONCURRENCY
    };
    match api_concurrency_override() {
        Some(limit) if use_public_proxy => limit.min(default),
        Some(limit) => limit,
        None => default,
    }
}

/// [`API_CONCURRENCY_ENV`] as a usable limit, or `None` when it is unset,
/// empty or not a positive integer. A set-but-unusable value is reported
/// under `--debug` rather than failing the command: telling a scan to stop
/// because of a stray export would be worse than scanning at the default.
fn api_concurrency_override() -> Option<usize> {
    let raw = std::env::var(API_CONCURRENCY_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<usize>() {
        Ok(limit) if limit > 0 => Some(limit.min(MAX_API_CONCURRENCY)),
        _ => {
            if is_debug_enabled() {
                eprintln!(
                    "[socket-patch debug] ignoring {API_CONCURRENCY_ENV}={raw:?}: \
                     expected an integer of 1 or more"
                );
            }
            None
        }
    }
}

/// Run `f` over `items` with at most `limit` futures in flight, yielding
/// results in INPUT order (item `i`'s result is always the `i`-th item,
/// even when a later request finishes first). A `limit` of 0 is treated
/// as 1. Futures are only started as the stream is polled, so dropping
/// the stream early cancels whatever is still in flight and never starts
/// the rest — the property a caller relies on to abandon a window and
/// replay it elsewhere.
pub fn ordered_concurrent<I, F, Fut>(
    items: I,
    limit: usize,
    f: F,
) -> impl Stream<Item = Fut::Output>
where
    I: IntoIterator,
    F: FnMut(I::Item) -> Fut,
    Fut: Future,
{
    stream::iter(items).map(f).buffered(limit.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Duration;

    /// Serial with its env sibling below: the default arms read
    /// [`API_CONCURRENCY_ENV`], which that test sets and restores.
    #[test]
    #[serial_test::serial]
    fn a_tight_descriptor_limit_runs_requests_one_at_a_time() {
        assert_eq!(api_concurrency_under(false, false), API_CONCURRENCY);
        assert_eq!(api_concurrency_under(true, false), PROXY_API_CONCURRENCY);
        assert_eq!(api_concurrency_under(false, true), 1);
        assert_eq!(api_concurrency_under(true, true), 1);
    }

    /// [`ordered_concurrent`], collected: every result, in input order.
    async fn map_ordered_concurrent<I, F, Fut>(items: I, limit: usize, f: F) -> Vec<Fut::Output>
    where
        I: IntoIterator,
        F: FnMut(I::Item) -> Fut,
        Fut: Future,
    {
        ordered_concurrent(items, limit, f).collect().await
    }

    /// Later items finish first (reversed latencies); results still come
    /// back in input order.
    #[tokio::test(start_paused = true)]
    async fn results_keep_input_order_under_reversed_latencies() {
        let items: Vec<u64> = (0..10).collect();
        let out = map_ordered_concurrent(items.clone(), 4, |i| async move {
            tokio::time::sleep(Duration::from_millis(100 * (10 - i))).await;
            i * 2
        })
        .await;
        assert_eq!(out, items.iter().map(|i| i * 2).collect::<Vec<_>>());
    }

    /// Never more than `limit` futures in flight, and the limit is
    /// actually reached (the loop is concurrent, not serial).
    #[tokio::test(start_paused = true)]
    async fn in_flight_count_never_exceeds_limit() {
        let live = Cell::new(0usize);
        let peak = Cell::new(0usize);
        let out = map_ordered_concurrent(0..20u64, 3, |i| {
            let (live, peak) = (&live, &peak);
            async move {
                live.set(live.get() + 1);
                peak.set(peak.get().max(live.get()));
                tokio::time::sleep(Duration::from_millis(10 + (i % 4) * 7)).await;
                live.set(live.get() - 1);
                i
            }
        })
        .await;
        assert_eq!(out, (0..20).collect::<Vec<_>>());
        assert_eq!(peak.get(), 3);
        assert_eq!(live.get(), 0);
    }

    /// Wall time is ~ceil(n/limit) round trips, not n.
    #[tokio::test(start_paused = true)]
    async fn runs_requests_concurrently() {
        let start = tokio::time::Instant::now();
        map_ordered_concurrent(0..8u32, 4, |_| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        })
        .await;
        assert_eq!(start.elapsed(), Duration::from_millis(200));
    }

    #[tokio::test]
    async fn empty_input_yields_nothing_and_starts_nothing() {
        let started = Cell::new(0usize);
        let out: Vec<u8> = map_ordered_concurrent(Vec::<u8>::new(), 8, |x| {
            started.set(started.get() + 1);
            async move { x }
        })
        .await;
        assert!(out.is_empty());
        assert_eq!(started.get(), 0);
    }

    /// A zero limit degrades to serial instead of stalling forever.
    #[tokio::test(start_paused = true)]
    async fn zero_limit_is_serial() {
        let live = Cell::new(0usize);
        let peak = Cell::new(0usize);
        let out = map_ordered_concurrent(0..5u8, 0, |i| {
            let (live, peak) = (&live, &peak);
            async move {
                live.set(live.get() + 1);
                peak.set(peak.get().max(live.get()));
                tokio::time::sleep(Duration::from_millis(5)).await;
                live.set(live.get() - 1);
                i
            }
        })
        .await;
        assert_eq!(out, vec![0, 1, 2, 3, 4]);
        assert_eq!(peak.get(), 1);
    }

    /// Dropping the stream after item `k` never starts the items past the
    /// window: at most `limit` futures were ever created beyond `k`.
    #[tokio::test(start_paused = true)]
    async fn dropping_the_stream_stops_starting_new_work() {
        let started = Cell::new(0usize);
        {
            let mut s = Box::pin(ordered_concurrent(0..100u32, 4, |i| {
                started.set(started.get() + 1);
                async move {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    i
                }
            }));
            assert_eq!(s.next().await, Some(0));
            assert_eq!(s.next().await, Some(1));
        }
        // Items 0..=1 consumed, window of 4 refilled once per consumption.
        assert!(started.get() <= 6, "started {}", started.get());
    }

    /// Both caps, and everything [`API_CONCURRENCY_ENV`] can do to them.
    /// One test: SOCKET_* env is process-global, so each case restores the
    /// variable before the next.
    #[test]
    #[serial_test::serial]
    fn concurrency_caps_per_client_kind_and_env_override() {
        let orig = std::env::var(API_CONCURRENCY_ENV).ok();
        std::env::remove_var(API_CONCURRENCY_ENV);
        assert_eq!(api_concurrency(false), API_CONCURRENCY);
        assert_eq!(api_concurrency(true), PROXY_API_CONCURRENCY);

        // 1 is the escape hatch: `buffered(1)` is the old serial loop.
        std::env::set_var(API_CONCURRENCY_ENV, "1");
        assert_eq!(api_concurrency(false), 1);
        assert_eq!(api_concurrency(true), 1);

        // Whitespace is a shell artifact, not a value.
        std::env::set_var(API_CONCURRENCY_ENV, " 2 ");
        assert_eq!(api_concurrency(false), 2);

        // Raising the authenticated cap is allowed up to the measured
        // ceiling; the proxy's shared semaphore is never widened.
        std::env::set_var(API_CONCURRENCY_ENV, "16");
        assert_eq!(api_concurrency(false), 16);
        assert_eq!(api_concurrency(true), PROXY_API_CONCURRENCY);
        std::env::set_var(API_CONCURRENCY_ENV, "9999");
        assert_eq!(api_concurrency(false), MAX_API_CONCURRENCY);
        assert_eq!(api_concurrency(true), PROXY_API_CONCURRENCY);

        // Unusable values leave the defaults alone rather than failing the
        // command ("" is the shell idiom for "unset").
        for bad in ["", "   ", "0", "-1", "eight", "4.5"] {
            std::env::set_var(API_CONCURRENCY_ENV, bad);
            assert_eq!(api_concurrency(false), API_CONCURRENCY, "{bad:?}");
            assert_eq!(api_concurrency(true), PROXY_API_CONCURRENCY, "{bad:?}");
        }

        match orig {
            Some(v) => std::env::set_var(API_CONCURRENCY_ENV, v),
            None => std::env::remove_var(API_CONCURRENCY_ENV),
        }
    }
}
