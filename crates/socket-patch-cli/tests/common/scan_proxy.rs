//! The mock Socket public proxy the hermetic `scan` suites (`e2e_cargo`,
//! `e2e_composer`, `e2e_maven`, `e2e_nuget`) pin with `--proxy-url`.

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Start a mock Socket public proxy answering the scan's `POST /patch/batch`
/// with an empty (no-patch) result, so no scan ever leaves localhost.
pub async fn start_proxy() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    server
}

/// Hermeticity guard: every scan in a test must have routed its patch lookup
/// through the in-test proxy. Fewer recorded requests than scans means at
/// least one binary invocation talked to the live API (or skipped the lookup
/// outright) despite the pinning.
pub async fn assert_proxy_served_scans(server: &MockServer, scans: usize) {
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(
        requests.len() >= scans,
        "expected all {scans} scan invocations to hit the in-test proxy; \
         recorded only {} request(s)",
        requests.len()
    );
}
