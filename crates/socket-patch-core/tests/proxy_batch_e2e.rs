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
use wiremock::matchers::{body_json, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const PURL: &str = "pkg:npm/left-pad@1.3.0";

fn proxy_client(api_url: &str) -> ApiClient {
    ApiClient::new(ApiClientOptions {
        api_url: api_url.to_string(),
        api_token: None,
        use_public_proxy: true,
        org_slug: None,
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
        .search_patches_batch(None, &[PURL.to_string()])
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
        .search_patches_batch(None, &[PURL.to_string()])
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
        .search_patches_batch(None, &[PURL.to_string()])
        .await
        .expect("unconfigured patch API must degrade to the GET path");
}

#[tokio::test]
async fn proxy_batch_validation_400_surfaces_without_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(json!({ "error": "Invalid PURL format" })),
        )
        .expect(1)
        .mount(&server)
        .await;
    mount_by_package(&server, by_package_response_body(), 0).await;

    let client = proxy_client(&server.uri());
    let err = client
        .search_patches_batch(None, &[PURL.to_string()])
        .await
        .expect_err("a genuine validation 400 must surface, not silently degrade");

    match &err {
        ApiError::Other(msg) => {
            assert!(msg.contains("400"), "must embed the status; got: {msg}");
            assert!(
                msg.contains("Invalid PURL format"),
                "must embed the body; got: {msg}"
            );
        }
        other => panic!("validation 400 must be Other; got: {other:?}"),
    }
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

    let client = proxy_client(&server.uri());
    let err = client
        .search_patches_batch(None, &[PURL.to_string()])
        .await
        .expect_err("over-capacity 503 must surface");
    assert!(
        matches!(&err, ApiError::Other(msg) if msg.contains("503")),
        "over-capacity 503 must be Other with the status embedded; got: {err:?}"
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

    let client = proxy_client(&server.uri());
    let err = client
        .search_patches_batch(None, &[PURL.to_string()])
        .await
        .expect_err("429 must surface");
    assert!(
        matches!(err, ApiError::RateLimited(_)),
        "429 must be RateLimited; got: {err:?}"
    );
}
