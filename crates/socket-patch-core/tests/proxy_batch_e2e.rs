//! Proxy-mode batch search: `search_patches_batch` must POST
//! `/patch/batch` against the public proxy and only degrade to the legacy
//! per-package GET path when the deployed proxy predates the endpoint.
//!
//! The decision table lives in `is_batch_unsupported` (unit-tested in
//! `client.rs`); these tests pin the end-to-end wiring against a mock
//! server — which HTTP calls actually fire for each proxy response. The
//! `.expect(0)` mounts on the GET route are the teeth: they fail the test
//! (on `MockServer` drop) if the fallback fires when it must not, and
//! vice versa.

use serde_json::json;
use socket_patch_core::api::client::{ApiClient, ApiClientOptions, ApiError};
use socket_patch_core::api::retry::{ApiRetryPolicy, RetryHooks};
use wiremock::matchers::{body_json, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PURL: &str = "pkg:npm/left-pad@1.3.0";

fn proxy_client(api_url: &str) -> ApiClient {
    ApiClient::new(ApiClientOptions {
        api_url: api_url.to_string(),
        api_token: None,
        route: socket_patch_core::api::client::ApiRoute::Proxy,
    })
}

/// A minimal proxy-shaped batch response with one free patch.
fn batch_response_body() -> serde_json::Value {
    json!({
        "packages": [{
            "purl": PURL,
            "patches": [{
                "uuid": "11111111-2222-3333-4444-555555555555",
                "purl": PURL,
                "tier": "free",
                "cveIds": ["CVE-2024-0001"],
                "ghsaIds": ["GHSA-aaaa-bbbb-cccc"],
                "severity": "high",
                "title": "Fixes prototype pollution"
            }]
        }],
        "canAccessPaidPatches": false
    })
}

/// A minimal per-package (`SearchResponse`) body for the legacy GET path.
fn by_package_response_body() -> serde_json::Value {
    json!({
        "patches": [{
            "uuid": "11111111-2222-3333-4444-555555555555",
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "description": "Fixes prototype pollution",
            "license": "MIT",
            "tier": "free",
            "vulnerabilities": {}
        }],
        "canAccessPaidPatches": false
    })
}

/// Mount a `GET /patch/by-package/*` mock with the given expected hit count.
async fn mount_by_package(server: &MockServer, body: serde_json::Value, expected_hits: u64) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/patch/by-package/.*$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .expect(expected_hits)
        .mount(server)
        .await;
}

#[tokio::test]
async fn proxy_batch_posts_components_and_skips_per_package_gets() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        // Wire-contract pin: the proxy receives the CycloneDX-style body.
        .and(body_json(json!({ "components": [{ "purl": PURL }] })))
        .respond_with(ResponseTemplate::new(200).set_body_json(batch_response_body()))
        .expect(1)
        .mount(&server)
        .await;
    mount_by_package(&server, by_package_response_body(), 0).await;

    let client = proxy_client(&server.uri());
    let resp = client
        .search_patches_batch(&[PURL.to_string()])
        .await
        .expect("proxy batch POST must succeed");

    assert_eq!(resp.packages.len(), 1);
    assert_eq!(resp.packages[0].purl, PURL);
    assert_eq!(resp.packages[0].patches.len(), 1);
    assert_eq!(resp.packages[0].patches[0].tier, "free");
    assert!(!resp.can_access_paid_patches);
}

#[tokio::test]
async fn proxy_batch_degrades_to_per_package_gets_on_legacy_catch_all_400() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "Unsupported endpoint",
            "message": "Endpoint POST /patch/batch is not supported."
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_by_package(&server, by_package_response_body(), 1).await;

    let client = proxy_client(&server.uri());
    let resp = client
        .search_patches_batch(&[PURL.to_string()])
        .await
        .expect("legacy proxy must degrade to per-package GETs, not error");

    assert_eq!(resp.packages.len(), 1, "fallback results must be assembled");
    assert_eq!(resp.packages[0].purl, PURL);
    assert_eq!(resp.packages[0].patches.len(), 1);
}

#[tokio::test]
async fn proxy_batch_degrades_when_patch_api_unconfigured_503() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({
            "error": "Service Unavailable",
            "message": "Patch API is not configured on this server"
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_by_package(&server, by_package_response_body(), 1).await;

    let client = proxy_client(&server.uri());
    client
        .search_patches_batch(&[PURL.to_string()])
        .await
        .expect("unconfigured patch API must degrade to the GET path");
}

#[tokio::test]
async fn proxy_batch_validation_400_degrades_to_per_package_gets() {
    // The batch endpoint validates the component list all-or-nothing, so a
    // chunk mixing a supported PURL with one the server doesn't recognize
    // (e.g. pkg:jsr/… from the Deno crawler) is rejected wholesale. The
    // valid subset must still resolve via the per-package path instead of
    // failing the scan.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "message": "Invalid PURL format. Must include ecosystem type and package name.",
                "details": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_by_package(&server, by_package_response_body(), 1).await;

    let client = proxy_client(&server.uri());
    let resp = client
        .search_patches_batch(&[PURL.to_string()])
        .await
        .expect("validation 400 must degrade to per-package GETs, not error");

    assert_eq!(resp.packages.len(), 1, "fallback results must be assembled");
    assert_eq!(resp.packages[0].purl, PURL);
}

#[tokio::test]
async fn proxy_batch_validation_400_with_failing_gets_yields_empty_ok() {
    // Regression shape of the Deno JSR docker e2e: every crawled PURL is a
    // type the server rejects (pkg:jsr/…), so the batch 400s AND each
    // per-package GET 400s. The per-package path swallows those individual
    // failures, so the scan-level result is an empty success — not an
    // error that flips the whole scan's exit code.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "message": "Invalid PURL format. Must include ecosystem type and package name.",
                "details": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/patch/by-package/.*$"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": {
                "message": "Invalid PURL format. Must include ecosystem type and package name.",
                "details": null
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = proxy_client(&server.uri());
    let resp = client
        .search_patches_batch(&["pkg:jsr/@std/path@0.220.0".to_string()])
        .await
        .expect("per-purl failures are swallowed; the batch call must not error");

    assert!(
        resp.packages.is_empty(),
        "an unresolvable PURL yields no packages, not an error"
    );
    assert!(!resp.can_access_paid_patches);
}

#[tokio::test]
async fn proxy_batch_over_capacity_503_surfaces_without_fallback() {
    // Deliberate: degrading on an over-capacity 503 would amplify load
    // tenfold via the concurrent per-package fallback.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(
            ResponseTemplate::new(503).set_body_string("Service temporarily over capacity"),
        )
        .expect(1)
        .mount(&server)
        .await;
    mount_by_package(&server, by_package_response_body(), 0).await;

    // Single-answer classification: retries off (the bounded 429 / 503
    // retry is pinned in api_retry_e2e.rs).
    let client =
        proxy_client(&server.uri()).with_api_retry(ApiRetryPolicy::none(), RetryHooks::default());
    let err = client
        .search_patches_batch(&[PURL.to_string()])
        .await
        .expect_err("over-capacity 503 must surface");
    assert!(
        matches!(&err, ApiError::ServiceUnavailable(msg) if msg.contains("503")),
        "over-capacity 503 must be ServiceUnavailable with the status embedded; got: {err:?}"
    );
}

#[tokio::test]
async fn proxy_batch_429_surfaces_as_rate_limited_without_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(429))
        .expect(1)
        .mount(&server)
        .await;
    mount_by_package(&server, by_package_response_body(), 0).await;

    // Single-answer classification: retries off (the bounded 429 / 503
    // retry is pinned in api_retry_e2e.rs).
    let client =
        proxy_client(&server.uri()).with_api_retry(ApiRetryPolicy::none(), RetryHooks::default());
    let err = client
        .search_patches_batch(&[PURL.to_string()])
        .await
        .expect_err("429 must surface");
    assert!(
        matches!(err, ApiError::RateLimited(_)),
        "429 must be RateLimited; got: {err:?}"
    );
}

#[tokio::test]
async fn proxy_batch_fallback_preserves_requested_purl_order() {
    // The per-package fallback runs each chunk's GETs concurrently; the
    // assembled `packages` list must not follow *completion* order. That
    // order is user-visible — `scan --json` emits `packages` verbatim and the
    // human table indexes it — so two identical scans of an unchanged project
    // could disagree. The order must follow the requested PURLs, matching
    // what the batch endpoint returns.
    //
    // The mock makes the race deterministic: the FIRST requested PURL is
    // served with a delay, so completion order is the exact reverse of
    // request order.
    let first = "pkg:npm/alpha@1.0.0";
    let second = "pkg:npm/omega@1.0.0";

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(405))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/patch/by-package/.*alpha.*$"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(by_package_response_body())
                .set_delay(std::time::Duration::from_millis(400)),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/patch/by-package/.*omega.*$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(by_package_response_body()))
        .expect(1)
        .mount(&server)
        .await;

    let client = proxy_client(&server.uri());
    let resp = client
        .search_patches_batch(&[first.to_string(), second.to_string()])
        .await
        .expect("legacy proxy must degrade to per-package GETs");

    let order: Vec<&str> = resp.packages.iter().map(|p| p.purl.as_str()).collect();
    assert_eq!(
        order,
        vec![first, second],
        "assembled packages must follow the requested PURL order, not response-completion order"
    );
}

// ── A fallback that was not answered must not read as "no patches" ──────

/// What a host that is not the patch service answers: a web server's own
/// error page.
fn html_page(status: u16) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(
        "<!doctype html><html><head><title>Error</title></head><body>nginx</body></html>",
        "text/html",
    )
}

/// The proxy's catch-all for a route it does not serve.
fn unsupported_endpoint() -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(json!({
        "error": "Unsupported endpoint",
        "message": "Endpoint POST /patch/batch is not supported."
    }))
}

fn by_package_path(purl: &str) -> String {
    format!(
        "/patch/by-package/{}",
        purl.replace(':', "%3A")
            .replace('/', "%2F")
            .replace('@', "%40")
    )
}

async fn mount_package(server: &MockServer, purl: &str, answer: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(by_package_path(purl)))
        .respond_with(answer)
        .expect(1)
        .mount(server)
        .await;
}

#[tokio::test]
async fn fallback_no_patch_answers_are_a_success_with_nothing_unanswered() {
    // Every way the service says "nothing for this package" on the legacy
    // path: an empty list, its refusal of a PURL it does not serve, and
    // its own 404 body. All three are answers.
    let empty = "pkg:npm/empty@1.0.0";
    let refused = "pkg:jsr/@std/path@0.220.0";
    let missing = "pkg:npm/missing@1.0.0";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(unsupported_endpoint())
        .expect(1)
        .mount(&server)
        .await;
    mount_package(
        &server,
        empty,
        ResponseTemplate::new(200)
            .set_body_json(json!({ "patches": [], "canAccessPaidPatches": false })),
    )
    .await;
    mount_package(
        &server,
        refused,
        ResponseTemplate::new(400).set_body_json(json!({
            "error": "Invalid PURL format",
            "message": "Expected a valid PURL starting with \"pkg:\""
        })),
    )
    .await;
    mount_package(
        &server,
        missing,
        ResponseTemplate::new(404).set_body_json(json!({
            "error": { "message": "Not found", "details": null }
        })),
    )
    .await;

    let resp = proxy_client(&server.uri())
        .search_patches_batch(&[empty.to_string(), refused.to_string(), missing.to_string()])
        .await
        .expect("the service answered for every package");
    assert!(resp.packages.is_empty(), "{:?}", resp.packages);
    assert!(resp.unanswered.is_empty(), "{:?}", resp.unanswered);
}

#[tokio::test]
async fn fallback_returns_the_answered_packages_and_names_the_rest() {
    // Some lookups answered, others did not: the answered packages are
    // used, and each one that got no answer is listed with its error, in
    // the order asked — never dropped as if it had no patches.
    let patched = PURL;
    let clean = "pkg:npm/clean@1.0.0";
    let broken = "pkg:npm/broken@1.0.0";
    let foreign = "pkg:npm/foreign@1.0.0";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(unsupported_endpoint())
        .expect(1)
        .mount(&server)
        .await;
    mount_package(
        &server,
        patched,
        ResponseTemplate::new(200).set_body_json(by_package_response_body()),
    )
    .await;
    mount_package(
        &server,
        clean,
        ResponseTemplate::new(200)
            .set_body_json(json!({ "patches": [], "canAccessPaidPatches": false })),
    )
    .await;
    mount_package(
        &server,
        broken,
        ResponseTemplate::new(500).set_body_string("upstream exploded"),
    )
    .await;
    mount_package(&server, foreign, html_page(404)).await;

    let resp = proxy_client(&server.uri())
        .search_patches_batch(&[
            broken.to_string(),
            patched.to_string(),
            foreign.to_string(),
            clean.to_string(),
        ])
        .await
        .expect("two packages were answered");
    assert_eq!(resp.packages.len(), 1, "{:?}", resp.packages);
    assert_eq!(resp.packages[0].purl, patched);
    let unanswered: Vec<(&str, &str)> = resp
        .unanswered
        .iter()
        .map(|u| (u.purl.as_str(), u.error.as_str()))
        .collect();
    assert_eq!(unanswered.len(), 2, "{unanswered:?}");
    assert_eq!(
        unanswered[0],
        (
            broken,
            "API request failed with status 500: upstream exploded"
        )
    );
    assert_eq!(unanswered[1].0, foreign);
    assert!(
        unanswered[1]
            .1
            .contains("did not answer like the Socket patch API"),
        "{unanswered:?}"
    );
}

#[tokio::test]
async fn fallback_with_every_lookup_failing_is_an_error_not_an_empty_result() {
    // The batch POST is refused, and every per-package GET then fails
    // with a 500: the service said nothing about any package, so the call
    // must fail instead of reporting an empty (patch-free) result.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(unsupported_endpoint())
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/patch/by-package/.*$"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream exploded"))
        .expect(2)
        .mount(&server)
        .await;

    let err = proxy_client(&server.uri())
        .search_patches_batch(&[
            "pkg:npm/alpha@1.0.0".to_string(),
            "pkg:npm/omega@1.0.0".to_string(),
        ])
        .await
        .expect_err("no package was answered: the call must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("500") && msg.contains("upstream exploded"),
        "the error must carry the cause: {msg}"
    );
}

#[tokio::test]
async fn a_host_that_is_not_the_patch_service_is_an_error_naming_it() {
    // A mistyped proxy URL: the host 404s the batch POST and every
    // per-package GET with its own HTML page. A 404 that is not the patch
    // service's answer says nothing about patches.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(html_page(404))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/patch/by-package/.*$"))
        .respond_with(html_page(404))
        .mount(&server)
        .await;

    let err = proxy_client(&server.uri())
        .search_patches_batch(&[PURL.to_string()])
        .await
        .expect_err("a foreign 404 page must not read as \"no patches\"");
    let msg = err.to_string();
    assert!(
        msg.contains(&server.address().to_string()),
        "the error must name the host that answered: {msg}"
    );
    assert!(
        msg.contains("--proxy-url") && msg.contains("SOCKET_PROXY_URL"),
        "the error must say which setting to check: {msg}"
    );
}

#[tokio::test]
async fn a_batch_400_that_is_not_the_services_is_an_error_without_fallback() {
    // What a forward proxy or WAF answers for anything: a 400 with its own
    // page. That is not the batch endpoint rejecting a chunk, so it must
    // not fan out into one GET per package against the same wrong host.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(html_page(400))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/patch/by-package/.*$"))
        .respond_with(html_page(400))
        .expect(0)
        .mount(&server)
        .await;

    let err = proxy_client(&server.uri())
        .search_patches_batch(&[PURL.to_string()])
        .await
        .expect_err("a foreign 400 page must not read as \"no patches\"");
    let msg = err.to_string();
    assert!(
        msg.contains("400") && msg.contains(&server.address().to_string()),
        "{msg}"
    );
    assert!(msg.contains("--proxy-url"), "{msg}");
}

#[tokio::test]
async fn a_200_that_is_not_json_fails_the_lookup() {
    // A captive portal answers every GET with a 200 login page.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(405))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/patch/by-package/.*$"))
        .respond_with(html_page(200))
        .mount(&server)
        .await;

    let err = proxy_client(&server.uri())
        .search_patches_batch(&[PURL.to_string()])
        .await
        .expect_err("a login page is not an answer");
    assert!(matches!(err, ApiError::Parse(_)), "{err:?}");
    assert!(
        err.to_string().contains("--proxy-url"),
        "the error must say which setting to check: {err}"
    );
}

#[tokio::test]
async fn a_proxy_without_the_per_package_route_fails_the_lookup() {
    // Both routes answer the proxy's "Unsupported endpoint" catch-all: a
    // Socket proxy that does not serve patches at this URL.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(unsupported_endpoint())
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/patch/by-package/.*$"))
        .respond_with(unsupported_endpoint())
        .mount(&server)
        .await;

    let err = proxy_client(&server.uri())
        .search_patches_batch(&[PURL.to_string()])
        .await
        .expect_err("a missing route is not \"no patches\"");
    assert!(
        err.to_string().contains("Unsupported endpoint"),
        "the error must carry the cause: {err}"
    );
}
