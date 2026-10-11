//! `socket-patch --update` reports its outcome to the telemetry endpoint:
//! `cli_updated` after a swap, `cli_update_failed` (with the envelope's
//! error code) on a failure. Each run drives a staged COPY of the binary
//! (`update_fixture::staged_install`) and points the anonymous proxy
//! telemetry route at a local wiremock; the workspace-wide
//! `SOCKET_TELEMETRY_DISABLED=1` (`.cargo/config.toml`) is overridden for
//! the child only.

use crate::update_fixture;

use update_fixture::{make_served_binary, run_installed, staged_install, FakeReleaseBuilder};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// A telemetry recorder on the public proxy's `/patch/telemetry` route.
async fn telemetry_mock() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/telemetry"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&server)
        .await;
    server
}

/// The telemetry bodies `server` received, in order.
async fn telemetry_events(server: &MockServer) -> Vec<serde_json::Value> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|req| {
            assert!(
                req.headers.get("authorization").is_none(),
                "the anonymous proxy route never carries a bearer"
            );
            serde_json::from_slice(&req.body).expect("telemetry body is JSON")
        })
        .collect()
}

#[tokio::test]
async fn successful_update_reports_cli_updated() {
    let install = staged_install();
    let (served, _) = make_served_binary();
    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .mount()
        .await;
    let telemetry = telemetry_mock().await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--force", "--yes"],
        &[
            ("SOCKET_UPDATE_BASE_URL", &release.base_url),
            ("SOCKET_PROXY_URL", &telemetry.uri()),
            ("SOCKET_TELEMETRY_DISABLED", "0"),
        ],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let events = telemetry_events(&telemetry).await;
    assert_eq!(events.len(), 1, "exactly one event: {events:#?}");
    let event = &events[0];
    assert_eq!(event["event_type"], "cli_updated");
    assert_eq!(event["context"]["command"], "update");
    assert_eq!(event["context"]["version"], CURRENT);
    assert_eq!(event["metadata"]["from_version"], CURRENT);
    assert_eq!(event["metadata"]["to_version"], CURRENT);
    assert_eq!(event["metadata"]["channel"], "standalone");
    assert_eq!(event["metadata"]["forced"], true);
    assert_eq!(event["metadata"]["pinned"], false);
    assert!(event.get("error").is_none());

    release.verify_request_hygiene().await;
}

#[tokio::test]
async fn failed_update_reports_cli_update_failed_with_its_code() {
    let install = staged_install();
    let (served, _) = make_served_binary();
    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .omit_sums_file()
        .expect_asset_downloads(0)
        .mount()
        .await;
    let telemetry = telemetry_mock().await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes", "--json"],
        &[
            ("SOCKET_UPDATE_BASE_URL", &release.base_url),
            ("SOCKET_PROXY_URL", &telemetry.uri()),
            ("SOCKET_TELEMETRY_DISABLED", "0"),
        ],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");
    let envelope_code = envelope["error"]["code"]
        .as_str()
        .expect("the failure envelope carries a code");

    let events = telemetry_events(&telemetry).await;
    assert_eq!(events.len(), 1, "exactly one event: {events:#?}");
    let event = &events[0];
    assert_eq!(event["event_type"], "cli_update_failed");
    assert_eq!(event["context"]["command"], "update");
    assert_eq!(event["metadata"]["error_code"], envelope_code);
    assert!(
        event["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("SHA256SUMS")),
        "the error message rides along: {event:#}"
    );

    install.assert_binary_intact();
}

/// `--offline` refuses before any network, telemetry included.
#[tokio::test]
async fn offline_update_sends_nothing() {
    let install = staged_install();
    let telemetry = telemetry_mock().await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes", "--offline"],
        &[
            ("SOCKET_PROXY_URL", &telemetry.uri()),
            ("SOCKET_TELEMETRY_DISABLED", "0"),
        ],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(telemetry_events(&telemetry).await.is_empty());
}
