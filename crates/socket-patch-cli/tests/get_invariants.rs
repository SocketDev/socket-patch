//! End-to-end tests for `get` against a wiremock-driven mock API.
//! Exercises every identifier-type branch (UUID, PURL, CVE, GHSA,
//! package-name search) plus the save-and-apply / paid / not-found
//! error paths. Real-API integration stays in `e2e_npm.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
/// The `afterHash` embedded in `patch_response_json`; also the blob filename.
const AFTER_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
/// base64 "cGF0Y2hlZAo=" decodes to exactly these bytes.
const BLOB_BYTES: &[u8] = b"patched\n";

fn run_get(cwd: &Path, api_url: &str, identifier: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec![
        "get",
        identifier,
        "--json",
        "--save-only",
        "--yes",
        "--api-url",
        api_url,
        "--api-token",
        "fake-token-for-test",
        "--org",
        ORG_SLUG,
    ];
    args.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&args)
        .current_dir(cwd)
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// PatchResponse JSON suitable as a `view/{uuid}` response. All fields
/// are camelCase as the binary expects.
fn patch_response_json(purl: &str, uuid: &str) -> serde_json::Value {
    // base64 of "patched\n" — content is arbitrary, the save path
    // doesn't verify content hash. The afterHash value is what gets
    // used as the blob filename.
    serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "2024-01-01T00:00:00Z",
        "files": {
            "package/index.js": {
                "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111",
                "blobContent": "cGF0Y2hlZAo=",
            }
        },
        "vulnerabilities": {
            "GHSA-test-1234": {
                "cves": ["CVE-2024-12345"],
                "summary": "Test vulnerability",
                "severity": "high",
                "description": "Synthetic test patch",
            }
        },
        "description": "Test patch",
        "license": "MIT",
        "tier": "free",
    })
}

// ---------------------------------------------------------------------------
// UUID identifier — direct fetch via /patches/view/{uuid}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_by_uuid_save_only_writes_manifest_and_blob() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(patch_response_json(purl, UUID)))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run_get(tmp.path(), &mock.uri(), UUID, &[]);
    assert_eq!(
        code, 0,
        "get must succeed; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_single_save_only_success(&v, purl, UUID);

    // Manifest written under .socket/manifest.json with the resolved entry.
    assert_manifest_has_patch(tmp.path(), purl, UUID);

    // Blob written under .socket/blobs/<afterHash> with the decoded payload.
    assert_blob_written(tmp.path(), AFTER_HASH, BLOB_BYTES);
}

#[tokio::test]
async fn get_by_uuid_not_found_emits_envelope() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run_get(tmp.path(), &mock.uri(), UUID, &[]);
    assert_eq!(
        code, 0,
        "not_found is a clean (non-error) outcome; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "not_found");
    assert_eq!(v["found"], 0);
    assert_eq!(v["downloaded"], 0);
    assert_eq!(v["applied"], 0);
    assert_eq!(v["patches"].as_array().expect("patches array").len(), 0);
    // A 404 must never leave a manifest behind.
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "not_found must not write a manifest"
    );
}

// ---------------------------------------------------------------------------
// CVE identifier — fetch via /patches/by-cve/{cve}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_by_cve_returns_matching_patches() {
    let mock = MockServer::start().await;
    let cve = "CVE-2021-44906";
    let purl = "pkg:npm/minimist@1.2.2";

    // by-cve returns SearchResponse shape (lightweight patch metadata).
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "Fixes CVE",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    // After selecting a search result, get fetches the full patch.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(patch_response_json(purl, UUID)))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run_get(tmp.path(), &mock.uri(), cve, &[]);
    assert_eq!(
        code, 0,
        "get by CVE must succeed; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_single_save_only_success(&v, purl, UUID);
    assert_manifest_has_patch(tmp.path(), purl, UUID);
    assert_blob_written(tmp.path(), AFTER_HASH, BLOB_BYTES);
}

/// Read `.socket/manifest.json` and assert it records the given PURL with
/// the expected UUID. Merely checking the file exists would let a broken
/// save path (empty/garbage manifest) pass.
fn assert_manifest_has_patch(root: &Path, purl: &str, uuid: &str) {
    let manifest_path = root.join(".socket/manifest.json");
    assert!(manifest_path.exists(), "manifest must be written");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let patches = manifest["patches"].as_object().expect("patches object");
    assert!(
        patches.contains_key(purl),
        "manifest must contain PURL key {purl}; got {manifest}"
    );
    assert_eq!(
        patches[purl]["uuid"], uuid,
        "manifest PURL entry must record the resolved UUID; got {manifest}"
    );
}

/// Assert the patch blob was actually downloaded to disk with the exact
/// expected bytes. A manifest entry alone proves only that metadata was
/// recorded; without this a regression that skips the content download (or
/// writes the wrong/empty bytes) would still report `success`.
fn assert_blob_written(root: &Path, after_hash: &str, expected: &[u8]) {
    let blob_path = root.join(".socket/blobs").join(after_hash);
    assert!(
        blob_path.exists(),
        "blob file must be written at .socket/blobs/{after_hash}"
    );
    let blob = std::fs::read(&blob_path).unwrap();
    assert_eq!(
        blob, expected,
        "blob content must be the decoded patch payload, not a stub/wrong bytes"
    );
}

/// Assert the JSON success envelope for a single saved-but-not-applied
/// (`--save-only`) patch: exactly one found, one downloaded, none applied,
/// and the lone patch record echoes the resolved purl/uuid as `added`.
/// Pinning these counts stops a broken save path (e.g. found-but-not-
/// downloaded, or a silent auto-apply) from masquerading as success.
fn assert_single_save_only_success(v: &serde_json::Value, purl: &str, uuid: &str) {
    assert_eq!(v["status"], "success", "expected success envelope; got {v}");
    assert_eq!(v["found"], 1, "exactly one patch must be found; got {v}");
    assert_eq!(v["downloaded"], 1, "the patch must be downloaded; got {v}");
    assert_eq!(
        v["applied"], 0,
        "--save-only must not apply the patch; got {v}"
    );
    let patches = v["patches"].as_array().expect("patches array");
    assert_eq!(patches.len(), 1, "exactly one patch record; got {v}");
    assert_eq!(patches[0]["purl"], purl, "record must echo purl; got {v}");
    assert_eq!(patches[0]["uuid"], uuid, "record must echo uuid; got {v}");
    assert_eq!(
        patches[0]["action"], "added",
        "a freshly saved patch must be reported as added; got {v}"
    );
}

#[tokio::test]
async fn get_by_cve_no_match_emits_not_found() {
    let mock = MockServer::start().await;
    let cve = "CVE-2099-99999";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run_get(tmp.path(), &mock.uri(), cve, &[]);
    assert_eq!(code, 0, "empty CVE search is not an error; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "not_found");
    assert_eq!(v["found"], 0);
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "empty CVE search must not write a manifest"
    );
}

// ---------------------------------------------------------------------------
// GHSA identifier — fetch via /patches/by-ghsa/{ghsa}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_by_ghsa_returns_matching_patches() {
    let mock = MockServer::start().await;
    let ghsa = "GHSA-xvch-5gv4-984h";
    let purl = "pkg:npm/minimist@1.2.2";

    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/by-ghsa/{ghsa}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "Fixes GHSA",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(patch_response_json(purl, UUID)))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, _) = run_get(tmp.path(), &mock.uri(), ghsa, &[]);
    assert_eq!(code, 0, "get by GHSA must succeed; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_single_save_only_success(&v, purl, UUID);
    assert_manifest_has_patch(tmp.path(), purl, UUID);
    assert_blob_written(tmp.path(), AFTER_HASH, BLOB_BYTES);
}

// ---------------------------------------------------------------------------
// PURL identifier — fetch via /patches/by-package/{purl}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_by_purl_returns_matching_patches() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    // URL-encoded form of the PURL (`:` → `%3A`, `/` → `%2F`, `@` → `%40`).
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";

    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "Patch for purl",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(patch_response_json(purl, UUID)))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, _) = run_get(tmp.path(), &mock.uri(), purl, &[]);
    assert_eq!(code, 0, "get by PURL must succeed; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_single_save_only_success(&v, purl, UUID);
    assert_manifest_has_patch(tmp.path(), purl, UUID);
    assert_blob_written(tmp.path(), AFTER_HASH, BLOB_BYTES);
}

// ---------------------------------------------------------------------------
// Multiple patches available — JSON mode returns selection_required
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_multiple_patches_in_json_mode_returns_selection_required() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/foo@1.0.0";
    let encoded = "pkg%3Anpm%2Ffoo%401.0.0";
    let uuid_a = "11111111-1111-4111-8111-111111111111";
    let uuid_b = "22222222-2222-4222-8222-222222222222";

    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                {
                    "uuid": uuid_a,
                    "purl": purl,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "First patch",
                    "license": "MIT",
                    "tier": "free",
                    "vulnerabilities": {}
                },
                {
                    "uuid": uuid_b,
                    "purl": purl,
                    "publishedAt": "2024-02-01T00:00:00Z",
                    "description": "Second patch",
                    "license": "MIT",
                    "tier": "free",
                    "vulnerabilities": {}
                }
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run_get(tmp.path(), &mock.uri(), purl, &[]);
    // With multiple free patches and --json, get must NOT prompt
    // interactively and must NOT silently auto-pick one (which would
    // emit `success`). It must emit a `selection_required` envelope and
    // exit 1 so the caller can pick one via --id.
    assert_eq!(
        code, 1,
        "multi-patch JSON path must exit 1 (selection required); stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["status"], "selection_required",
        "multi-patch JSON path must emit selection_required, never success/auto-pick; got {v}"
    );
    assert_eq!(v["purl"], purl, "envelope must echo the queried purl");
    let options = v["options"].as_array().expect("options array");
    assert_eq!(
        options.len(),
        2,
        "both available patches must be offered as options; got {v}"
    );
    let offered: Vec<&str> = options
        .iter()
        .map(|o| o["uuid"].as_str().expect("option uuid"))
        .collect();
    assert!(
        offered.contains(&uuid_a) && offered.contains(&uuid_b),
        "options must list both patch UUIDs; got {offered:?}"
    );
    // No manifest may be written when selection is still required —
    // nothing has been chosen or downloaded yet.
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "selection_required must not write a manifest"
    );
}

// ---------------------------------------------------------------------------
// Paid patch path
// ---------------------------------------------------------------------------

/// UUID-by-UUID fetch via public proxy when the patch is paid:
/// the binary recognises the identifier as a UUID, hits the
/// `/patch/view/<uuid>` endpoint on the proxy, sees `tier: "paid"`
/// in the response, and emits a `paid_required` JSON envelope.
/// Covers the UUID-specific branch of the paid path in
/// `commands::get::run`.
#[tokio::test]
async fn get_uuid_paid_patch_via_public_proxy_emits_paid_required_envelope() {
    let mock = MockServer::start().await;

    // Public-proxy view-by-UUID endpoint.
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": "pkg:npm/paid-by-uuid@1.0.0",
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "Paid patch fetched by UUID",
            "license": "MIT",
            "tier": "paid",
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(binary())
        .args([
            "get",
            UUID,
            "--json",
            "--save-only",
            "--yes",
            "--api-url",
            &mock.uri(),
        ])
        .current_dir(tmp.path())
        .env("SOCKET_PATCH_PROXY_URL", mock.uri())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "invalid JSON envelope: {e}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(
        v["status"], "paid_required",
        "UUID-fetched paid patch via public proxy must emit paid_required; got {v}"
    );
    assert_eq!(v["found"], 1);
    assert_eq!(v["downloaded"], 0);
    assert_eq!(v["applied"], 0);
    let patches = v["patches"].as_array().expect("patches array");
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0]["uuid"], UUID);
    assert_eq!(patches[0]["tier"], "paid");
    // A paid patch is never downloaded, so no manifest may be written.
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "paid_required must not write a manifest"
    );
}

#[tokio::test]
async fn get_paid_patch_via_public_proxy_returns_paid_required() {
    // When using the public proxy (no api-token + no org), a paid patch
    // returns a `paid_required` status. To simulate this we DON'T pass
    // --api-token / --org so the binary falls back to the public proxy.
    // We also have to point SOCKET_PATCH_PROXY_URL at the mock.
    let mock = MockServer::start().await;
    let purl = "pkg:npm/paidpkg@1.0.0";
    let encoded = "pkg%3Anpm%2Fpaidpkg%401.0.0";

    // Public-proxy by-package path: /patch/by-package/...
    Mock::given(method("GET"))
        .and(path(format!("/patch/by-package/{encoded}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "Paid patch",
                "license": "MIT",
                "tier": "paid",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(binary())
        .args([
            "get",
            purl,
            "--json",
            "--save-only",
            "--yes",
            "--api-url",
            &mock.uri(),
        ])
        .current_dir(tmp.path())
        .env("SOCKET_PATCH_PROXY_URL", mock.uri())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    // A single paid patch with no paid access must emit `paid_required`
    // with zero downloads/applies and the patch echoed back as paid.
    // Asserting merely `!= success` would let a generic error envelope
    // (or any other status) pass and mask a broken paid-path branch.
    assert_eq!(
        v["status"], "paid_required",
        "paid patch without token must emit paid_required; got: {v}"
    );
    assert_eq!(
        v["found"], 1,
        "the one paid patch must be counted as found; got {v}"
    );
    assert_eq!(
        v["downloaded"], 0,
        "paid patch must not be downloaded; got {v}"
    );
    assert_eq!(v["applied"], 0, "paid patch must not be applied; got {v}");
    let patches = v["patches"].as_array().expect("patches array");
    assert_eq!(
        patches.len(),
        1,
        "exactly the one paid patch must be reported; got {v}"
    );
    assert_eq!(patches[0]["purl"], purl);
    assert_eq!(patches[0]["uuid"], UUID);
    assert_eq!(
        patches[0]["tier"], "paid",
        "reported patch must be flagged paid; got {v}"
    );
    // Nothing was downloaded, so no manifest may be written.
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "paid_required must not write a manifest"
    );
}
