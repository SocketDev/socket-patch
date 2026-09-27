//! Bounded 429 / 503 retry on the patch API's JSON calls
//! (`socket_patch_core::api::retry`), end to end against a mock server.
//!
//! Every client here runs on a virtual clock: the retry sleep is a
//! recorder that returns at once, so the tests assert the exact waits the
//! policy chose without sleeping them.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt as _;
use serde_json::json;
use socket_patch_core::api::client::{
    is_fallback_candidate, ApiClient, ApiClientOptions, ApiError,
};
use socket_patch_core::api::retry::{jitter_sample, ApiRetryPolicy, RetryHooks};
use socket_patch_core::utils::concurrent::ordered_concurrent;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "org";
const SEED: u64 = 0x5eed_1234;

/// A recording virtual clock: every retry wait lands in the returned log.
fn virtual_clock(now_unix_secs: u64) -> (RetryHooks, Arc<Mutex<Vec<Duration>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    let hooks = RetryHooks {
        sleep: Arc::new(move |d| {
            sink.lock().unwrap().push(d);
            Box::pin(async {})
        }),
        now_unix_secs: Arc::new(move || now_unix_secs),
        // A frozen monotonic clock: the retry window never closes (the
        // window tests drive the clock themselves).
        monotonic_now: Arc::new(|| Duration::ZERO),
        jitter_seed: SEED,
    };
    (hooks, log)
}

/// A virtual clock for ONE request's retries: each recorded wait also
/// advances the monotonic clock by its length, as a real sleep would.
/// (Only meaningful sequentially: parallel waits would add up here.)
fn advancing_clock() -> (RetryHooks, Arc<Mutex<Vec<Duration>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let now = Arc::new(Mutex::new(Duration::from_secs(1)));
    let (sink, tick, read) = (Arc::clone(&log), Arc::clone(&now), Arc::clone(&now));
    let hooks = RetryHooks {
        sleep: Arc::new(move |d| {
            sink.lock().unwrap().push(d);
            *tick.lock().unwrap() += d;
            Box::pin(async {})
        }),
        now_unix_secs: Arc::new(|| 0),
        monotonic_now: Arc::new(move || *read.lock().unwrap()),
        jitter_seed: SEED,
    };
    (hooks, log)
}

fn options(uri: &str, proxy: bool) -> ApiClientOptions {
    ApiClientOptions {
        api_url: uri.to_string(),
        api_token: (!proxy).then(|| "tok".to_string()),
        use_public_proxy: proxy,
        org_slug: (!proxy).then(|| ORG.to_string()),
    }
}

/// An authenticated client with `policy` on the virtual clock.
fn client(uri: &str, policy: ApiRetryPolicy) -> (ApiClient, Arc<Mutex<Vec<Duration>>>) {
    let (hooks, log) = virtual_clock(0);
    (
        ApiClient::new(options(uri, false)).with_api_retry(policy, hooks),
        log,
    )
}

fn waits(log: &Arc<Mutex<Vec<Duration>>>) -> Vec<Duration> {
    log.lock().unwrap().clone()
}

fn purl(i: usize) -> String {
    format!("pkg:npm/retry-pkg-{i:03}@1.0.0")
}

fn by_package_route(purl: &str) -> String {
    let enc = purl
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40");
    format!("/v0/orgs/{ORG}/patches/by-package/{enc}")
}

fn search_body(purl: &str, i: usize) -> serde_json::Value {
    json!({
        "patches": [{
            "uuid": format!("00000000-0000-4000-8000-{i:012x}"),
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "description": format!("patch {i}"),
            "license": "MIT",
            "tier": "free",
            "vulnerabilities": {}
        }],
        "canAccessPaidPatches": false
    })
}

/// `template` for the first `n` requests to `route` (GET), then 200 with
/// `body`.
async fn mount_get_then_ok(
    server: &MockServer,
    route: &str,
    template: Option<(ResponseTemplate, u64)>,
    body: serde_json::Value,
) {
    if let Some((template, n)) = template {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(template)
            .up_to_n_times(n)
            .with_priority(1)
            .mount(server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn requests_to(server: &MockServer, route: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == route)
        .count()
}

/// The serialized search result — what `scan` folds into its output.
fn rendered(r: &socket_patch_core::api::types::SearchResponse) -> String {
    serde_json::to_string(r).unwrap()
}

/// 429 then 200: the call succeeds with exactly the clean run's result,
/// after one jittered backoff wait (500 ms step → [250, 500) ms, the exact
/// value fixed by the seed).
#[tokio::test]
async fn a_429_then_200_matches_a_clean_run() {
    let p = purl(1);
    let route = by_package_route(&p);

    let clean = MockServer::start().await;
    mount_get_then_ok(&clean, &route, None, search_body(&p, 1)).await;
    let (c, log) = client(&clean.uri(), ApiRetryPolicy::default());
    let want = c.search_patches_by_package(&p).await.expect("clean run");
    assert!(waits(&log).is_empty());

    let throttled = MockServer::start().await;
    mount_get_then_ok(
        &throttled,
        &route,
        Some((ResponseTemplate::new(429), 1)),
        search_body(&p, 1),
    )
    .await;
    let (c, log) = client(&throttled.uri(), ApiRetryPolicy::default());
    let got = c
        .search_patches_by_package(&p)
        .await
        .expect("retried to 200");
    assert_eq!(rendered(&got), rendered(&want));
    assert_eq!(requests_to(&throttled, &route).await, 2);

    let label = format!("GET {}{route}", throttled.uri());
    let expected = ApiRetryPolicy::default()
        .delay(1, None, jitter_sample(SEED, &label, 1))
        .expect("no Retry-After");
    assert_eq!(waits(&log), vec![expected]);
    assert!(expected >= Duration::from_millis(250) && expected < Duration::from_millis(500));
}

/// `Retry-After` wins over the backoff: delta-seconds as sent (30 s, the
/// cap, included), an HTTP-date resolved against the (virtual) clock, and
/// a `0` or past date floored at the jittered first backoff step.
#[tokio::test]
async fn retry_after_is_honored_and_floored() {
    let p = purl(2);
    let route = by_package_route(&p);
    // Fri, 27 Mar 2026 19:12:42 GMT.
    let date_at = 1_774_638_762u64;
    for (header, now, want) in [
        ("7", 0, Some(Duration::from_secs(7))),
        ("30", 0, Some(Duration::from_secs(30))),
        (
            "Fri, 27 Mar 2026 19:12:42 GMT",
            date_at - 12,
            Some(Duration::from_secs(12)),
        ),
        // Floored: computed from the request's jitter below.
        ("Fri, 27 Mar 2026 19:12:42 GMT", date_at + 5, None),
        ("0", 0, None),
    ] {
        let server = MockServer::start().await;
        mount_get_then_ok(
            &server,
            &route,
            Some((
                ResponseTemplate::new(429).insert_header("Retry-After", header),
                1,
            )),
            search_body(&p, 2),
        )
        .await;
        let (hooks, log) = virtual_clock(now);
        let c = ApiClient::new(options(&server.uri(), false))
            .with_api_retry(ApiRetryPolicy::default(), hooks);
        c.search_patches_by_package(&p)
            .await
            .unwrap_or_else(|e| panic!("Retry-After {header:?}: {e}"));
        let want = want.unwrap_or_else(|| {
            let label = format!("GET {}{route}", server.uri());
            let floor = ApiRetryPolicy::default()
                .delay(1, None, jitter_sample(SEED, &label, 1))
                .expect("backoff");
            assert!(floor >= Duration::from_millis(250) && floor < Duration::from_millis(500));
            floor
        });
        assert_eq!(waits(&log), vec![want], "Retry-After {header:?}");
    }
}

/// A `Retry-After` beyond the 30 s cap is not waited out (nor retried
/// early, which the server would only refuse again): the answer is final
/// on the first request, naming why.
#[tokio::test]
async fn a_retry_after_over_the_cap_gives_up_at_once() {
    let p = purl(7);
    let route = by_package_route(&p);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "120"))
        .mount(&server)
        .await;
    let (c, log) = client(&server.uri(), ApiRetryPolicy::default());
    let err = c.search_patches_by_package(&p).await.expect_err("429");
    assert!(matches!(err, ApiError::RateLimited(_)), "{err:?}");
    assert_eq!(
        err.to_string(),
        "Rate limit exceeded (HTTP 429, Retry-After 120 s exceeds the 30 s retry cap). \
         Please try again later."
    );
    assert_eq!(requests_to(&server, &route).await, 1);
    assert!(waits(&log).is_empty());
}

/// A 429 that never clears: 1 + 3 requests, three waits, then the
/// request's error — still `RateLimited` (never a fallback candidate),
/// naming the retries.
#[tokio::test]
async fn exhausted_429_is_rate_limited_after_three_retries() {
    let p = purl(3);
    let route = by_package_route(&p);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;
    let (c, log) = client(&server.uri(), ApiRetryPolicy::default());
    let err = c
        .search_patches_by_package(&p)
        .await
        .expect_err("throttled throughout");
    assert!(matches!(err, ApiError::RateLimited(_)), "{err:?}");
    assert!(!is_fallback_candidate(&err));
    assert_eq!(
        err.to_string(),
        "Rate limit exceeded (HTTP 429, gave up after 3 retries). Please try again later."
    );
    assert_eq!(requests_to(&server, &route).await, 4);
    assert_eq!(waits(&log).len(), 3);
}

/// 503 on the authenticated batch POST: retried like a 429; exhausted, it
/// is a `ServiceUnavailable` status error with the body, plus the retry
/// note.
#[tokio::test]
async fn batch_post_503_retries_then_succeeds_or_reports() {
    let route = format!("/v0/orgs/{ORG}/patches/batch");
    let body = json!({
        "packages": [{ "purl": purl(4), "patches": [{
            "uuid": "00000000-0000-4000-8000-000000000004", "purl": purl(4),
            "tier": "free", "cveIds": [], "ghsaIds": [], "severity": "high",
            "title": "t"
        }]}],
        "canAccessPaidPatches": false
    });

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "2"))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
        .mount(&server)
        .await;
    let (c, log) = client(&server.uri(), ApiRetryPolicy::default());
    let got = c
        .search_patches_batch(&[purl(4)])
        .await
        .expect("503 twice, then 200");
    assert_eq!(got.packages.len(), 1);
    assert_eq!(waits(&log), vec![Duration::from_secs(2); 2]);

    let down = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(503).set_body_string("over capacity"))
        .mount(&down)
        .await;
    let (c, log) = client(&down.uri(), ApiRetryPolicy::default());
    let err = c
        .search_patches_batch(&[purl(4)])
        .await
        .expect_err("503 throughout");
    assert_eq!(
        err.to_string(),
        "API request failed with status 503: over capacity (gave up after 3 retries)"
    );
    assert!(matches!(err, ApiError::ServiceUnavailable(_)), "{err:?}");
    assert_eq!(requests_to(&down, &route).await, 4);
    assert_eq!(waits(&log).len(), 3);
}

/// 401, 403, 404, 400 and 500 are answered once: never retried, and 401 /
/// 403 still classify as the proxy-fallback candidates they were.
#[tokio::test]
async fn other_statuses_are_not_retried() {
    for status in [401u16, 403, 404, 400, 500, 502] {
        let p = purl(5);
        let route = by_package_route(&p);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(&route))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let (c, log) = client(&server.uri(), ApiRetryPolicy::default());
        let result = c.search_patches_by_package(&p).await;
        match status {
            401 | 403 => assert!(
                is_fallback_candidate(result.as_ref().expect_err("auth error")),
                "{status}"
            ),
            // 404 on by-package is "no patches" (unchanged).
            404 => assert!(result.expect("404 is empty").patches.is_empty()),
            _ => assert!(result.is_err(), "{status}"),
        }
        assert_eq!(requests_to(&server, &route).await, 1, "{status}");
        assert!(waits(&log).is_empty(), "{status}");
    }
}

/// `ApiRetryPolicy::none()` (`SOCKET_API_MAX_RETRIES=0`): one request, and
/// the error text is the pre-retry one.
#[tokio::test]
async fn retries_off_answers_once_with_the_original_message() {
    let p = purl(6);
    let route = by_package_route(&p);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(&route))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;
    let (c, log) = client(&server.uri(), ApiRetryPolicy::none());
    let err = c.search_patches_by_package(&p).await.expect_err("429");
    assert_eq!(
        err.to_string(),
        "Rate limit exceeded. Please try again later."
    );
    assert_eq!(requests_to(&server, &route).await, 1);
    assert!(waits(&log).is_empty());
}

/// The run-wide retry window is wall-clock: it opens with the first retry,
/// and a retry whose wait would end after it closes is refused — across
/// clones and requests.
#[tokio::test]
async fn the_retry_window_bounds_wall_clock_waiting() {
    let server = MockServer::start().await;
    for i in 0..3 {
        Mock::given(method("GET"))
            .and(path(by_package_route(&purl(10 + i))))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "2"))
            .mount(&server)
            .await;
    }
    let policy = ApiRetryPolicy {
        retry_window: Duration::from_secs(5),
        ..ApiRetryPolicy::default()
    };
    let (hooks, log) = advancing_clock();
    let c = ApiClient::new(options(&server.uri(), false)).with_api_retry(policy, hooks);
    // Request A: waits 2 s + 2 s (4 s into the window), then its 3rd
    // retry would end at 6 s: refused.
    let a = c.search_patches_by_package(&purl(10)).await.expect_err("A");
    assert_eq!(
        a.to_string(),
        "Rate limit exceeded (HTTP 429, the run's 5 s retry window has closed). \
         Please try again later."
    );
    // Request B on a clone, 4 s in: no 2 s wait fits.
    let b = c
        .clone()
        .search_patches_by_package(&purl(11))
        .await
        .expect_err("B");
    assert!(b.to_string().contains("retry window has closed"), "{b}");
    assert_eq!(waits(&log), vec![Duration::from_secs(2); 2]);
    assert_eq!(requests_to(&server, &by_package_route(&purl(10))).await, 3);
    assert_eq!(requests_to(&server, &by_package_route(&purl(11))).await, 1);
}

/// 32 requests throttled at once, all persistently: parallel waits do not
/// add up against the window, so EVERY request gets its 3 retries (the
/// window only bounds wall-clock time) before its `RateLimited` error.
#[tokio::test]
async fn thirty_two_concurrent_throttled_requests_each_get_their_retries() {
    const N: usize = 32;
    let purls: Vec<String> = (0..N).map(|i| purl(100 + i)).collect();
    let server = MockServer::start().await;
    for p in &purls {
        Mock::given(method("GET"))
            .and(path(by_package_route(p)))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "20"))
            .mount(&server)
            .await;
    }
    // A clock that stands still while all 32 wait in parallel: each wait
    // (20 s) ends inside the 60 s window even though they sum to 640 s.
    let (c, log) = client(&server.uri(), ApiRetryPolicy::default());
    let c = &c;
    let errors: Vec<String> = ordered_concurrent(purls.iter(), N, |p| async move {
        c.search_patches_by_package(p)
            .await
            .expect_err("throttled throughout")
            .to_string()
    })
    .collect()
    .await;
    for (p, e) in purls.iter().zip(&errors) {
        assert_eq!(
            e, "Rate limit exceeded (HTTP 429, gave up after 3 retries). Please try again later.",
            "{p}"
        );
        assert_eq!(requests_to(&server, &by_package_route(p)).await, 4, "{p}");
    }
    assert_eq!(waits(&log).len(), N * 3);
}

/// A 32-wide `ordered_concurrent` window over 96 packages where every
/// third answers 429 (with jittered backoff, some twice) before its 200:
/// the folded sequence is identical to a clean run's.
#[tokio::test]
async fn a_32_wide_window_with_scattered_429s_folds_like_a_clean_run() {
    const N: usize = 96;
    let purls: Vec<String> = (0..N).map(purl).collect();

    let run = |throttle: bool| {
        let purls = purls.clone();
        async move {
            let server = MockServer::start().await;
            for (i, p) in purls.iter().enumerate() {
                let template = (throttle && i % 3 == 0).then(|| {
                    (
                        ResponseTemplate::new(429)
                            .set_delay(Duration::from_millis((N - i) as u64 % 7)),
                        1 + (i % 2) as u64,
                    )
                });
                mount_get_then_ok(&server, &by_package_route(p), template, search_body(p, i)).await;
            }
            let (c, log) = client(&server.uri(), ApiRetryPolicy::default());
            let c = &c;
            let folded: Vec<String> = ordered_concurrent(purls.iter(), 32, |p| async move {
                match c.search_patches_by_package(p).await {
                    Ok(r) => rendered(&r),
                    Err(e) => format!("ERR {e}"),
                }
            })
            .collect()
            .await;
            (folded, waits(&log).len())
        }
    };
    let (clean, clean_waits) = run(false).await;
    let (throttled, throttled_waits) = run(true).await;
    assert_eq!(clean_waits, 0);
    // 32 throttled packages, half of them twice.
    assert_eq!(throttled_waits, 16 + 16 * 2);
    assert_eq!(throttled, clean);
    assert!(clean.iter().all(|r| !r.starts_with("ERR")));
}

/// Public proxy batch: an over-capacity 503 is retried; the permanent
/// "Patch API is not configured" 503 degrades to the per-package path on
/// the first answer, with no wait.
#[tokio::test]
async fn proxy_batch_retries_over_capacity_but_not_unconfigured() {
    let p = purl(20);
    let batch = json!({
        "packages": [{ "purl": p, "patches": [{
            "uuid": "00000000-0000-4000-8000-000000000020", "purl": p,
            "tier": "free", "cveIds": [], "ghsaIds": [], "severity": "high",
            "title": "t"
        }]}],
        "canAccessPaidPatches": false
    });
    let proxy_client = |uri: &str| {
        let (hooks, log) = virtual_clock(0);
        (
            ApiClient::new(options(uri, true)).with_api_retry(ApiRetryPolicy::default(), hooks),
            log,
        )
    };

    let busy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(
            ResponseTemplate::new(503).set_body_string("Service temporarily over capacity"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&busy)
        .await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(batch))
        .mount(&busy)
        .await;
    let (c, log) = proxy_client(&busy.uri());
    let got = c
        .search_patches_batch(std::slice::from_ref(&p))
        .await
        .expect("retried");
    assert_eq!(got.packages.len(), 1);
    assert_eq!(waits(&log).len(), 1);

    let unconfigured = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": "Service Unavailable",
            "message": "Patch API is not configured on this server"
        })))
        .expect(1)
        .mount(&unconfigured)
        .await;
    let enc = p
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40");
    Mock::given(method("GET"))
        .and(path(format!("/patch/by-package/{enc}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(search_body(&p, 20)))
        .expect(1)
        .mount(&unconfigured)
        .await;
    let (c, log) = proxy_client(&unconfigured.uri());
    let got = c
        .search_patches_batch(std::slice::from_ref(&p))
        .await
        .expect("degraded to per-package");
    assert_eq!(got.packages.len(), 1);
    assert!(waits(&log).is_empty());
}

/// The legacy per-package proxy path swallows an unresolvable PURL, but a
/// package still throttled after its retries fails the call — it must not
/// vanish from the result.
#[tokio::test]
async fn legacy_proxy_path_surfaces_an_exhausted_throttle() {
    let ok = purl(30);
    let stuck = purl(31);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    let enc = |p: &str| {
        p.replace(':', "%3A")
            .replace('/', "%2F")
            .replace('@', "%40")
    };
    Mock::given(method("GET"))
        .and(path(format!("/patch/by-package/{}", enc(&ok))))
        .respond_with(ResponseTemplate::new(200).set_body_json(search_body(&ok, 30)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/by-package/{}", enc(&stuck))))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;
    let (hooks, log) = virtual_clock(0);
    let c = ApiClient::new(options(&server.uri(), true))
        .with_api_retry(ApiRetryPolicy::default(), hooks);
    let err = c
        .search_patches_batch(&[ok.clone(), stuck.clone()])
        .await
        .expect_err("a throttled package fails the call");
    assert!(matches!(err, ApiError::RateLimited(_)), "{err:?}");
    assert_eq!(waits(&log).len(), 3);
}

/// `fetch_registry_references` (hosted's package references POST) and
/// `fetch_patch` (patch view / VEX record) share the retry.
#[tokio::test]
async fn package_references_and_patch_view_retry_too() {
    let server = MockServer::start().await;
    let refs = format!("/v0/orgs/{ORG}/patches/package");
    Mock::given(method("POST"))
        .and(path(&refs))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(&refs))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": { "u-1": { "status": "granted", "url": "https://x/y.tgz" } }
        })))
        .mount(&server)
        .await;
    let uuid = "00000000-0000-4000-8000-0000000000aa";
    let view = format!("/v0/orgs/{ORG}/patches/view/{uuid}");
    mount_get_then_ok(
        &server,
        &view,
        Some((ResponseTemplate::new(503), 1)),
        json!({
            "uuid": uuid, "purl": purl(40), "publishedAt": "2024-01-01T00:00:00Z",
            "files": {}, "vulnerabilities": {}, "description": "d", "license": "MIT",
            "tier": "free"
        }),
    )
    .await;
    let (c, log) = client(&server.uri(), ApiRetryPolicy::default());
    let got = c
        .fetch_registry_references(&["u-1".to_string()])
        .await
        .expect("references after one 429");
    assert_eq!(got["u-1"].status, "granted");
    let patch = c.fetch_patch(uuid).await.expect("view after one 503");
    assert_eq!(patch.expect("found").uuid, uuid);
    let w = waits(&log);
    assert_eq!(w.len(), 2);
    assert_eq!(w[0], Duration::from_secs(1));
}

/// The proxy's permanent `503 "Patch API is not configured"` is not
/// throttling on ANY JSON path: the per-package lookups and the patch view
/// answer it once, with no wait, as the plain `Other` status error — so
/// the legacy per-package path still skips such packages (an empty result,
/// not a failed batch), exactly as before retries existed.
#[tokio::test]
async fn unconfigured_503_is_never_retried_on_per_package_or_view_calls() {
    let unconfigured = || {
        ResponseTemplate::new(503).set_body_json(json!({
            "error": "Service Unavailable",
            "message": "Patch API is not configured on this server"
        }))
    };
    let enc = |p: &str| {
        p.replace(':', "%3A")
            .replace('/', "%2F")
            .replace('@', "%40")
    };
    let purls = [purl(50), purl(51)];
    let server = MockServer::start().await;
    // The batch endpoint is missing, so the legacy per-package path runs.
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;
    for p in &purls {
        Mock::given(method("GET"))
            .and(path(format!("/patch/by-package/{}", enc(p))))
            .respond_with(unconfigured())
            .expect(1)
            .mount(&server)
            .await;
    }
    let uuid = "00000000-0000-4000-8000-0000000000bb";
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{uuid}")))
        .respond_with(unconfigured())
        .expect(1)
        .mount(&server)
        .await;
    let (hooks, log) = virtual_clock(0);
    let c = ApiClient::new(options(&server.uri(), true))
        .with_api_retry(ApiRetryPolicy::default(), hooks);

    let got = c
        .search_patches_batch(&purls)
        .await
        .expect("unconfigured packages are skipped, not a failed batch");
    assert!(got.packages.is_empty(), "{:?}", got.packages);

    let err = c.fetch_patch(uuid).await.expect_err("503");
    assert!(matches!(err, ApiError::Other(_)), "{err:?}");
    assert!(
        err.to_string()
            .starts_with("API request failed with status 503")
            && !err.to_string().contains("retr"),
        "the pre-retry text: {err}"
    );
    assert!(waits(&log).is_empty());
}

/// Default retry policy on the proxy `/patch/batch`: an over-capacity 503
/// or a 429 that never clears is retried, then errors — and NEVER degrades
/// to the per-package path (that would multiply the load on a server that
/// is already refusing it).
#[tokio::test]
async fn persistent_proxy_batch_throttle_errors_without_per_package_fallback() {
    let p = purl(60);
    let enc = p
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40");
    for (status, body) in [(503u16, "Service temporarily over capacity"), (429, "")] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/patch/batch"))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .expect(4)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/patch/by-package/{enc}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(search_body(&p, 60)))
            .expect(0)
            .mount(&server)
            .await;
        let (hooks, log) = virtual_clock(0);
        let c = ApiClient::new(options(&server.uri(), true))
            .with_api_retry(ApiRetryPolicy::default(), hooks);
        let err = c
            .search_patches_batch(std::slice::from_ref(&p))
            .await
            .expect_err("persistent throttle surfaces");
        match status {
            503 => {
                assert!(matches!(err, ApiError::ServiceUnavailable(_)), "{err:?}");
                assert_eq!(
                    err.to_string(),
                    "API request failed with status 503: Service temporarily over capacity \
                     (gave up after 3 retries)"
                );
            }
            _ => assert!(matches!(err, ApiError::RateLimited(_)), "{err:?}"),
        }
        assert!(!is_fallback_candidate(&err));
        assert_eq!(waits(&log).len(), 3, "{status}");
        // `expect(4)` / `expect(0)` are verified when `server` drops.
    }
}
