//! Coverage-gap e2e for `update::download::fetch_archive`'s non-404 HTTP
//! failure branch (2026-09 coverage audit): a server error on the asset
//! download must surface as `download_failed` — not `asset_not_found`,
//! which is reserved for 404 ("no prebuilt binary for your target").
//!
//! Same discipline as `self_update_failures_e2e.rs`: every test runs a
//! staged COPY of the built binary (`update_fixture::staged_install`) —
//! `CARGO_BIN_EXE_socket-patch` itself must never be a swap target — and
//! a failed update must leave the install byte-identical with no stage
//! droppings.

#[path = "common/mod.rs"]
mod common;
#[path = "common/update_fixture.rs"]
mod update_fixture;

use wiremock::matchers::{method, path as urlpath};
use wiremock::{Mock, ResponseTemplate};

use update_fixture::{
    asset_name_for_current_target, make_served_binary, run_installed, staged_install,
    FakeReleaseBuilder,
};

/// A CDN that answers the archive GET with a 500 (outage, half-published
/// release, WAF tantrum) aborts the update as `download_failed`, names the
/// HTTP status, and leaves the install pristine.
#[tokio::test]
async fn asset_server_error_is_download_failed() {
    let install = staged_install();
    let (served, _) = make_served_binary();
    let asset = asset_name_for_current_target();

    // SHA256SUMS vouches for the asset (so the pipeline gets past the
    // sums fetch and reaches the archive GET), but the download route
    // answers 500 instead of the bytes: `omit_asset` keeps the sums entry
    // while skipping the fixture's 200 mock, and the explicit mock below
    // owns the asset path.
    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .omit_asset(&asset)
        .mount()
        .await;
    Mock::given(method("GET"))
        .and(urlpath(format!(
            "/SocketDev/socket-patch/releases/download/v9.9.9/{asset}"
        )))
        .respond_with(ResponseTemplate::new(500))
        .mount(&release.server)
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(
        common::envelope_error_code(&env),
        Some("download_failed"),
        "a non-404 asset error is download_failed, not asset_not_found"
    );
    let message = common::envelope_error_message(&env).unwrap_or_default();
    assert!(
        message.contains("returned 500"),
        "download_failed must carry the HTTP status: {message}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}
