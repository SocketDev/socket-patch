//! Additional e2e tests for `get` edge cases — exercises the
//! validation branches (--one-off + --save-only conflict, --id flag,
//! multi-patch selection via --id, auto-select for single free patch
//! match) and a few error paths the main get_invariants suite doesn't
//! reach.

use std::path::PathBuf;
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID_A: &str = "11111111-1111-4111-8111-111111111111";
const UUID_B: &str = "22222222-2222-4222-8222-222222222222";

/// Collect the paths of every request the mock actually received. Used to
/// prove which code path the binary really took (vs. fabricating the right
/// envelope without touching the network it claims to touch).
async fn received_paths(mock: &MockServer) -> Vec<String> {
    mock.received_requests()
        .await
        .expect("wiremock must record received requests")
        .iter()
        .map(|r| r.url.path().to_string())
        .collect()
}

#[test]
fn get_one_off_and_save_only_together_errors() {
    // The two flags are mutually exclusive — using both must fail.
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            UUID_A,
            "--one-off",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "error");
    let err = v["error"].as_str().expect("error message");
    assert!(
        err.contains("one-off") && err.contains("save-only"),
        "error must mention both flags: {err}"
    );
}

#[tokio::test]
async fn get_with_id_flag_selects_specific_patch() {
    // Multiple patches available for a PURL, `--id <UUID>` picks one.
    let mock = MockServer::start().await;
    let purl = "pkg:npm/multi@1.0.0";
    let encoded = "pkg%3Anpm%2Fmulti%401.0.0";

    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                {
                    "uuid": UUID_A, "purl": purl,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "first", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                },
                {
                    "uuid": UUID_B, "purl": purl,
                    "publishedAt": "2024-02-01T00:00:00Z",
                    "description": "second", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    // Mock the view endpoint for the SELECTED UUID.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID_B}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID_B,
            "purl": purl,
            "publishedAt": "2024-02-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "Second patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&mock)
        .await;

    // --id is a boolean type-tag: it tells the binary that the
    // positional identifier is a UUID, bypassing the auto-detection
    // step. Pair it with the UUID as the positional. With --id the
    // by-package endpoint must NOT be consulted — the fetch goes
    // straight to view/{UUID_B}, so we must observe UUID_B (the
    // selected patch) coming back, never UUID_A.
    let tmp = tempfile::tempdir().unwrap();
    let _ = purl;
    let _ = encoded;
    let out = Command::new(binary())
        .args([
            "get",
            UUID_B,
            "--id",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code, 0,
        "--id fetch-by-UUID of a free patch must succeed; stdout={stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["found"], 1, "exactly one patch fetched; stdout={stdout}");
    assert_eq!(
        v["downloaded"], 1,
        "the patch must be downloaded; stdout={stdout}"
    );
    let patches = v["patches"].as_array().expect("patches array");
    assert_eq!(
        patches.len(),
        1,
        "exactly one patch record; stdout={stdout}"
    );
    // The crux: --id <UUID_B> must select UUID_B specifically, not the
    // first patch (UUID_A) that the by-package listing would surface.
    assert_eq!(
        patches[0]["uuid"], UUID_B,
        "--id must select the requested UUID, not the listing's first entry; stdout={stdout}"
    );
    assert_ne!(
        patches[0]["uuid"], UUID_A,
        "must not have fallen back to the by-package first match; stdout={stdout}"
    );
    assert_eq!(patches[0]["action"], "added", "stdout={stdout}");

    // Prove the route, not just the payload: --id must fetch view/{UUID_B}
    // directly and must NEVER consult the by-package listing (which is mounted
    // as a trap returning BOTH UUIDs). Asserting only patches[0].uuid==UUID_B
    // is satisfiable by a broken impl that lists by-package and happens to
    // dedup/sort to UUID_B; the request log is what makes this airtight.
    let paths = received_paths(&mock).await;
    assert!(
        paths
            .iter()
            .any(|p| p.ends_with(&format!("/patches/view/{UUID_B}"))),
        "--id must fetch view/{UUID_B} directly; recorded paths={paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.contains("/by-package/")),
        "--id must NOT consult the by-package listing; recorded paths={paths:?}"
    );
    assert!(
        !paths
            .iter()
            .any(|p| p.ends_with(&format!("/patches/view/{UUID_A}"))),
        "--id must not fetch the non-selected UUID_A; recorded paths={paths:?}"
    );
}

#[tokio::test]
async fn get_with_no_matching_purl_emits_not_found() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/empty-result@1.0.0";
    let encoded = "pkg%3Anpm%2Fempty-result%401.0.0";

    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            purl,
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(0),
        "an empty (but successful) lookup is exit 0, not an error"
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "not_found", "stdout={stdout}");
    assert_eq!(v["found"], 0, "stdout={stdout}");
    assert_eq!(v["downloaded"], 0, "stdout={stdout}");
    assert_eq!(
        v["patches"].as_array().expect("patches array").len(),
        0,
        "no patches on not_found; stdout={stdout}"
    );
    // not_found must come from a real (empty) by-package lookup, not from a
    // short-circuit that never queried the API at all.
    let paths = received_paths(&mock).await;
    assert!(
        paths
            .iter()
            .any(|p| p.contains(&format!("/by-package/{encoded}"))),
        "the by-package endpoint must actually be queried; recorded paths={paths:?}"
    );
}

#[tokio::test]
async fn get_by_package_with_single_paid_patch_emits_paid_required() {
    // Single paid patch for free user via public proxy → paid_required.
    let mock = MockServer::start().await;
    let purl = "pkg:npm/paid-single@1.0.0";
    let encoded = "pkg%3Anpm%2Fpaid-single%401.0.0";

    Mock::given(method("GET"))
        .and(path(format!("/patch/by-package/{encoded}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID_A, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "paid", "license": "MIT", "tier": "paid",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            purl,
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
        ])
        .current_dir(tmp.path())
        .env("SOCKET_PATCH_PROXY_URL", mock.uri())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a recognized-but-paywalled patch is not an error exit"
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    // The mock returned exactly one paid patch and canAccessPaidPatches=false,
    // so the deterministic outcome is paid_required — not a vague "anything
    // but success". The patch must NOT have been downloaded.
    assert_eq!(v["status"], "paid_required", "stdout={stdout}");
    assert_eq!(v["found"], 1, "the paid patch was found; stdout={stdout}");
    assert_eq!(
        v["downloaded"], 0,
        "must not download a paid patch; stdout={stdout}"
    );
    assert_eq!(
        v["applied"], 0,
        "must not apply a paid patch; stdout={stdout}"
    );
    let patches = v["patches"].as_array().expect("patches array");
    assert_eq!(patches.len(), 1, "stdout={stdout}");
    assert_eq!(patches[0]["uuid"], UUID_A, "stdout={stdout}");
    assert_eq!(patches[0]["tier"], "paid", "stdout={stdout}");
    // paid_required must be the verdict of a real proxy lookup, and the binary
    // must NOT have attempted to download the paid blob via any view endpoint.
    let paths = received_paths(&mock).await;
    assert!(
        paths
            .iter()
            .any(|p| p.contains(&format!("/patch/by-package/{encoded}"))),
        "the public proxy by-package endpoint must be queried; recorded paths={paths:?}"
    );
    assert!(
        !paths.iter().any(|p| p.contains("/view/")),
        "a paywalled patch must not be downloaded via a view endpoint; recorded paths={paths:?}"
    );
}

#[tokio::test]
async fn get_with_invalid_search_purl_falls_through() {
    // A bare string that doesn't match UUID/CVE/GHSA/PURL is treated as a
    // package-name search (IdentifierType::Package). That path first
    // enumerates installed packages in the cwd; with an empty working dir
    // there are no packages to match, so the binary must short-circuit to
    // a `no_packages` envelope (exit 0) BEFORE it ever queries the API.
    // We mount the by-package mock to fail the test loudly if the binary
    // ever reaches the network on an empty workspace.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(format!(
            "^/v0/orgs/{ORG_SLUG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(500).set_body_string("network must not be reached"))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            "just-a-package-name",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(
        out.status.code(),
        Some(0),
        "package-name fallback over an empty workspace is a clean exit 0"
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    // Deterministic outcome: the un-typed identifier fell through to the
    // package search, which found nothing installed.
    assert_eq!(v["status"], "no_packages", "stdout={stdout}");
    assert_eq!(
        v["patches"].as_array().expect("patches array").len(),
        0,
        "stdout={stdout}"
    );
    // It must NOT have been misrouted to e.g. a successful download or a
    // not_found from an unintended API call.
    assert_ne!(v["status"], "success", "stdout={stdout}");
    // The mock returns 500; if the binary had queried it the run would have
    // surfaced an error status instead of no_packages.
    assert_ne!(
        v["status"], "error",
        "should not have reached the API; stdout={stdout}"
    );
    // The strongest guarantee: the binary must short-circuit BEFORE any
    // network call on an empty workspace. Inspecting the status alone is a
    // disjoint-outcome loophole (a broken impl could hit the 500 mock and
    // still coerce the result to no_packages). The request log makes "never
    // touched the network" non-negotiable.
    let paths = received_paths(&mock).await;
    assert!(
        paths.is_empty(),
        "package-name fallback over an empty workspace must not hit the API; recorded paths={paths:?}"
    );
}

#[tokio::test]
async fn get_uuid_returns_paid_patch_with_token_succeeds() {
    // Authenticated user (has token + org) requesting a paid patch
    // bypasses the proxy and gets the full PatchResponse.
    let mock = MockServer::start().await;
    let purl = "pkg:npm/paid-with-token@1.0.0";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID_A}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID_A,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "Paid patch with token access",
            "license": "MIT",
            "tier": "paid",
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            UUID_A,
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "real-token-but-not-validated-by-mock",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code, 0,
        "paid patch via authenticated path must succeed; stdout={stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["found"], 1, "stdout={stdout}");
    assert_eq!(
        v["downloaded"], 1,
        "authenticated paid fetch must actually download; stdout={stdout}"
    );
    let patches = v["patches"].as_array().expect("patches array");
    assert_eq!(patches.len(), 1, "stdout={stdout}");
    assert_eq!(
        patches[0]["uuid"], UUID_A,
        "must return the requested UUID; stdout={stdout}"
    );
    assert_eq!(patches[0]["action"], "added", "stdout={stdout}");
    // The authenticated path must reach the org-scoped view endpoint directly
    // (bypassing the public proxy), proving the download was a real fetch.
    let paths = received_paths(&mock).await;
    assert!(
        paths
            .iter()
            .any(|p| p.ends_with(&format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID_A}"))),
        "authenticated paid fetch must hit the org-scoped view endpoint; recorded paths={paths:?}"
    );
}

#[test]
fn get_help_lists_all_identifier_flags() {
    let out = Command::new(binary())
        .args(["get", "--help"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--id",
        "--cve",
        "--ghsa",
        "--package",
        "--save-only",
        "--one-off",
    ] {
        assert!(
            stdout.contains(flag),
            "get --help missing flag {flag}; got: {stdout}"
        );
    }
}

#[tokio::test]
async fn get_on_vendored_purl_warns_about_uuid_drift() {
    // An explicit `get --id <newer-uuid>` is allowed to move the manifest
    // past the uuid the vendor ledger still wires — but it must SAY so:
    // until a `vendor` run refreshes the artifact, VEX verification fails
    // closed with `vendor_uuid_mismatch`. The warning rides the JSON
    // `warnings` array (and stderr in human mode).
    let mock = MockServer::start().await;
    let purl = "pkg:npm/vendored-drift@1.0.0";

    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID_B}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID_B,
            "purl": purl,
            "publishedAt": "2024-02-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "Newer patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    // The vendor ledger wires the purl at UUID_A.
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { purl: {
                "ecosystem": "npm",
                "basePurl": purl,
                "uuid": UUID_A,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{UUID_A}/vendored-drift-1.0.0.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();

    let out = Command::new(binary())
        .args([
            "get",
            UUID_B,
            "--id",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 0, "explicit get still succeeds; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["patches"][0]["action"], "added", "stdout={stdout}");

    let warnings = v["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("uuid drift must surface a warning; stdout={stdout}"));
    assert_eq!(warnings.len(), 1, "stdout={stdout}");
    let w = warnings[0].as_str().expect("warning string");
    assert!(
        w.contains("is vendored at patch") && w.contains(UUID_A) && w.contains(UUID_B),
        "warning must name both uuids; got: {w}"
    );
    assert!(
        w.contains("socket-patch vendor"),
        "warning must point at the remedy; got: {w}"
    );
}
