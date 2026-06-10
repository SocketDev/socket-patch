//! Regression: the binary transport path (`fetch_blob` / `fetch_diff` /
//! `fetch_package`, all sharing `fetch_binary`) must classify authenticated
//! 401 / 403 / 429 responses the same way the JSON path does.
//!
//! Before the fix, `fetch_binary` collapsed every non-OK/404 status into
//! `ApiError::Other`. That defeated `is_fallback_candidate` (which keys on
//! `Unauthorized` / `Forbidden`) so a stale/revoked token blocked binary
//! downloads instead of rerouting to the public proxy, and the tailored
//! 401/403/429 operator messages were lost.
//!
//! These tests drive the *authenticated* `fetch_binary` branch (token + org
//! slug, not public-proxy) against a mock server, so they exercise exactly the
//! endpoint that can legitimately return those statuses.

use socket_patch_core::api::client::{
    is_fallback_candidate, ApiClient, ApiClientOptions, ApiError,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A 64-hex SHA-256 the validator accepts, so the request actually reaches the
/// transport (and the mock) rather than short-circuiting on bad input.
const VALID_HASH: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

fn authed_client(api_url: &str) -> ApiClient {
    ApiClient::new(ApiClientOptions {
        api_url: api_url.to_string(),
        api_token: Some("sktsec_token_placeholder_api".to_string()),
        use_public_proxy: false,
        org_slug: Some("my-org".to_string()),
    })
}

#[tokio::test]
async fn fetch_blob_401_classifies_as_unauthorized_and_is_fallback_candidate() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/my-org/patches/blob/{VALID_HASH}")))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let client = authed_client(&server.uri());
    let err = client
        .fetch_blob(VALID_HASH)
        .await
        .expect_err("401 must surface as an error");

    assert!(
        matches!(err, ApiError::Unauthorized(_)),
        "binary 401 must be Unauthorized, not Other; got: {err:?}"
    );
    assert!(
        is_fallback_candidate(&err),
        "a binary 401 must be eligible for the auth→proxy fallback"
    );
}

#[tokio::test]
async fn fetch_blob_403_classifies_as_forbidden_and_is_fallback_candidate() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/my-org/patches/blob/{VALID_HASH}")))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = authed_client(&server.uri());
    let err = client
        .fetch_blob(VALID_HASH)
        .await
        .expect_err("403 must surface as an error");

    assert!(
        matches!(err, ApiError::Forbidden(_)),
        "binary 403 must be Forbidden, not Other; got: {err:?}"
    );
    assert!(
        is_fallback_candidate(&err),
        "a binary 403 must be eligible for the auth→proxy fallback"
    );
    // Authenticated path → org-access wording, not the proxy paid-subscriber hint.
    assert!(
        err.to_string().contains("organization"),
        "authenticated 403 must carry the org-access message; got: {err}"
    );
}

#[tokio::test]
async fn fetch_blob_429_classifies_as_rate_limited_and_not_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/my-org/patches/blob/{VALID_HASH}")))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;

    let client = authed_client(&server.uri());
    let err = client
        .fetch_blob(VALID_HASH)
        .await
        .expect_err("429 must surface as an error");

    assert!(
        matches!(err, ApiError::RateLimited(_)),
        "binary 429 must be RateLimited, not Other; got: {err:?}"
    );
    // Rate limits surface as-is — never rerouted to the proxy.
    assert!(!is_fallback_candidate(&err));
}

#[tokio::test]
async fn fetch_blob_500_still_classifies_as_other() {
    // Genuine server errors must keep flowing through to `Other` with the
    // status code embedded — the fix must not over-classify.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/my-org/patches/blob/{VALID_HASH}")))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let client = authed_client(&server.uri());
    let err = client
        .fetch_blob(VALID_HASH)
        .await
        .expect_err("500 must surface as an error");

    match &err {
        ApiError::Other(msg) => {
            assert!(
                msg.contains("500"),
                "Other must embed the status; got: {msg}"
            );
            assert!(
                msg.contains("boom"),
                "Other must embed the body; got: {msg}"
            );
        }
        other => panic!("500 must be Other; got: {other:?}"),
    }
    // An unclassified server error is never rerouted to the proxy.
    assert!(!is_fallback_candidate(&err));
}
