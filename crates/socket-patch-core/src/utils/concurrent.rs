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

use std::future::Future;

use futures_util::stream::{self, Stream, StreamExt};

/// In-flight request cap for the authenticated patch API. Measured with
/// no 429s up to 32 in flight; 8 already makes the loops latency-flat.
pub const API_CONCURRENCY: usize = 8;

/// In-flight request cap on the public patch proxy, which serializes
/// anonymous callers behind one shared server-side semaphore — stay
/// polite there.
pub const PROXY_API_CONCURRENCY: usize = 4;

/// The in-flight cap for a client on the public proxy (`true`) or the
/// authenticated API (`false`).
pub fn api_concurrency(use_public_proxy: bool) -> usize {
    if use_public_proxy {
        PROXY_API_CONCURRENCY
    } else {
        API_CONCURRENCY
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

/// [`ordered_concurrent`], collected: every result, in input order.
pub async fn map_ordered_concurrent<I, F, Fut>(items: I, limit: usize, f: F) -> Vec<Fut::Output>
where
    I: IntoIterator,
    F: FnMut(I::Item) -> Fut,
    Fut: Future,
{
    ordered_concurrent(items, limit, f).collect().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Duration;

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

    #[test]
    fn concurrency_caps_per_client_kind() {
        assert_eq!(api_concurrency(false), API_CONCURRENCY);
        assert_eq!(api_concurrency(true), PROXY_API_CONCURRENCY);
    }
}
