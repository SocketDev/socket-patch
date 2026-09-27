//! The human-readable `get` summary must not report one patch twice.
//!
//! `download_and_apply_patches` prints an `Added: / Skipped: / Failed: /
//! Updated:` block after writing the manifest. Regression guard: the "added"
//! tally was bumped for EVERY record it wrote — including the ones classified
//! `Updated` — so replacing an existing manifest entry printed both
//! `Added: 1` and `Updated: 1` for the single patch it had just swapped.
//!
//! The JSON `downloaded` count deliberately covers adds + updates (pinned by
//! `in_process_get_update_count.rs`); only the human `Added:` line is the
//! true-adds count.
//!
//! Runs `--save-only` so the apply step never fires: this is purely about the
//! download bookkeeping.

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const OLD_UUID: &str = "00000000-0000-4000-8000-000000000000";
const NEW_UUID: &str = "11111111-1111-4111-8111-111111111111";
const PURL: &str = "pkg:npm/summary-pkg@1.0.0";
const PURL_ENCODED: &str = "pkg%3Anpm%2Fsummary-pkg%401.0.0";

fn seed_manifest(root: &std::path::Path, uuid: &str) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "patches": {
                PURL: {
                    "uuid": uuid,
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "previously recorded",
                    "license": "MIT",
                    "tier": "free",
                }
            }
        }))
        .unwrap(),
    )
    .expect("write manifest");
}

async fn mount_mocks(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/by-package/{PURL_ENCODED}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": NEW_UUID,
                "purl": PURL,
                "publishedAt": "2024-06-01T00:00:00Z",
                "description": "replacement patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {},
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{NEW_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": NEW_UUID,
            "purl": PURL,
            "publishedAt": "2024-06-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111",
                    "blobContent": "cGF0Y2hlZAo=",
                }
            },
            "vulnerabilities": {},
            "description": "replacement patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// Run `get <PURL> --save-only` against `mock`, returning `(code, stdout, stderr)`.
fn run_get(cwd: &std::path::Path, uri: &str) -> (i32, String, String) {
    common::run(
        cwd,
        &[
            "get",
            PURL,
            "--yes",
            "--save-only",
            "--api-url",
            uri,
            "--api-token",
            "fake-token-for-tests",
            "--org",
            ORG,
        ],
    )
}

#[tokio::test]
async fn replacing_a_manifest_entry_is_reported_as_updated_only() {
    let mock = MockServer::start().await;
    mount_mocks(&mock).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    // The PURL is already recorded under a DIFFERENT uuid → `Updated`.
    seed_manifest(tmp.path(), OLD_UUID);

    let (code, stdout, stderr) = run_get(tmp.path(), &mock.uri());
    assert_eq!(code, 0, "save-only update must succeed; stderr={stderr}");

    assert!(
        stderr.contains("Updated: 1"),
        "the replacement must be reported as an update; stderr={stderr}"
    );
    assert!(
        !stderr.contains("Added: 1"),
        "a replaced entry must NOT also be counted as an add — one patch, one \
         line; stdout={stdout}\nstderr={stderr}"
    );

    // The manifest really was swapped (so the assertions above aren't
    // describing a run that did nothing).
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let m: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(m["patches"][PURL]["uuid"], NEW_UUID, "manifest={body}");
}

#[tokio::test]
async fn a_brand_new_entry_is_still_reported_as_added() {
    // Positive control: the `Added:` line must still count real adds, so a
    // fix that simply stopped counting can't pass.
    let mock = MockServer::start().await;
    mount_mocks(&mock).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    // No manifest at all → `Added`.
    let (code, stdout, stderr) = run_get(tmp.path(), &mock.uri());
    assert_eq!(code, 0, "save-only add must succeed; stderr={stderr}");

    assert!(
        stderr.contains("Added: 1"),
        "a new entry must be reported as an add; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        !stderr.contains("Updated:"),
        "a new entry must not report an update; stderr={stderr}"
    );

    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let m: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(m["patches"][PURL]["uuid"], NEW_UUID, "manifest={body}");
}
