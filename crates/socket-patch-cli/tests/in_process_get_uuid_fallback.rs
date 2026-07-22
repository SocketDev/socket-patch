//! In-process regression test for the `get <uuid>` auth→proxy fallback.
//!
//! Regression guard: `run()` correctly retried a 401/403 from the
//! authenticated patch-view endpoint against the public proxy — but then
//! `save_and_apply_patch` RE-FETCHED the patch with a freshly-built
//! authenticated client, hitting the same 401 and exiting 1. The
//! already-fetched `PatchResponse` must be carried through to the save
//! step so a stale token still yields free patches end to end (the whole
//! point of the fallback).

use serial_test::serial;
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::commands::get::{run, GetArgs};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "22222222-2222-4222-8222-222222222222";
const PURL: &str = "pkg:npm/fallback-pkg@1.0.0";
const AFTER_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[tokio::test]
#[serial]
async fn stale_token_uuid_get_falls_back_to_proxy_end_to_end() {
    let server = MockServer::start().await;

    // The authenticated endpoint rejects the stale token.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    // The public proxy serves the free patch.
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-06-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash": AFTER_HASH,
                    "blobContent": "cGF0Y2hlZAo=",
                    "beforeBlobContent": "b3JpZ2luYWwK",
                }
            },
            "vulnerabilities": {},
            "description": "fallback test patch", "license": "MIT", "tier": "free",
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let args = GetArgs {
        identifier: UUID.to_string(),
        common: GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            api_url: Some(server.uri()),
            api_token: Some("stale-token".to_string()),
            org: Some(ORG.to_string()),
            proxy_url: Some(server.uri()),
            json: true,
            no_telemetry: true,
            ..GlobalArgs::default()
        },
        id: true,
        cve: false,
        ghsa: false,
        package: false,
        // save_only isolates the fallback/save path from the apply step.
        save_only: true,
        one_off: false,
        all_releases: false,
    };

    let code = run(args).await;
    assert_eq!(
        code, 0,
        "a stale token must fall back to the proxy and still save the free patch"
    );

    // The patch made it into the manifest...
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).expect("manifest");
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        manifest["patches"][PURL]["uuid"], UUID,
        "manifest must carry the proxy-fetched patch; manifest={manifest}"
    );
    // ...and its blob was written.
    assert!(
        tmp.path().join(".socket/blobs").join(AFTER_HASH).exists(),
        "after-blob must be written to .socket/blobs"
    );
}
