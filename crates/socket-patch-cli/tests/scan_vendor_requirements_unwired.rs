//! #786: a vendored requirements.txt entry whose pin the user removed or
//! bumped is unwired. A vendored rescan must not rediscover it from the
//! vendor ledger — before, it re-added a removed package as a
//! `(transitive)` line (exit 0) or refused a bumped one with
//! `pypi_requirement_not_pinned` (exit 1, on every run) — and must warn
//! `vendor_ledger_entry_unwired` instead; `--prune` reverts the entry and
//! exits 0.
//!
//! Driven through the built binary against a mock patch API that has no
//! patches, so the only way the stale entry can reach the vendor step is
//! the ledger supplement. The ledger is seeded in the exact shape the
//! requirements backend records (a rewritten `requirements_line`). The
//! package name is a fixture no interpreter on the machine has installed
//! (a crawled install would bypass the supplement).

use std::path::Path;
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "test-org";
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const PURL: &str = "pkg:pypi/sp-fixture-six@1.16.0";
const WHEEL: &str = "sp_fixture_six-1.16.0-py3-none-any.whl";

fn vendor_line() -> String {
    format!("./.socket/vendor/pypi/{UUID}/{WHEEL}  # socket-patch vendor: sp-fixture-six==1.16.0")
}

/// A project vendored by `scan --mode vendored` from `sp-fixture-six==1.16.0` on
/// line 1 of requirements.txt: the committed wheel, and the ledger entry
/// recording the rewritten pin.
fn seed_vendored(root: &Path) {
    let dir = root.join(format!(".socket/vendor/pypi/{UUID}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(WHEEL), b"not a real wheel").unwrap();
    let state = serde_json::json!({
        "version": 1,
        "entries": {
            PURL: {
                "ecosystem": "pypi",
                "basePurl": PURL,
                "uuid": UUID,
                "artifact": {
                    "path": format!(".socket/vendor/pypi/{UUID}/{WHEEL}"),
                    "sha256": "",
                },
                "wiring": [{
                    "file": "requirements.txt",
                    "kind": "requirements_line",
                    "action": "rewritten",
                    "key": "requirements.txt:1",
                    "original": ["sp-fixture-six==1.16.0"],
                    "new": vendor_line(),
                }],
                "flavor": "requirements",
                "detached": true,
            }
        }
    });
    std::fs::write(
        root.join(".socket/vendor/state.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
}

async fn empty_patch_api() -> MockServer {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    mock
}

fn run_scan_vendored(root: &Path, mock_uri: &str, extra: &[&str]) -> (i32, serde_json::Value) {
    let mut argv = vec![
        "scan",
        "--mode",
        "vendored",
        "--json",
        "--yes",
        "--api-url",
        mock_uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
        "--vendor-url",
        mock_uri,
        "--patch-server-url",
        mock_uri,
    ];
    argv.extend_from_slice(extra);
    let out = Command::new(env!("CARGO_BIN_EXE_socket-patch"))
        .args(&argv)
        .current_dir(root)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env_remove("VIRTUAL_ENV")
        .env_remove("CONDA_PREFIX")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON ({e}): stdout={stdout}; stderr={stderr}"));
    (out.status.code().unwrap_or(-1), v)
}

fn unwired_warnings(v: &serde_json::Value) -> usize {
    v["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|w| w["code"] == "vendor_ledger_entry_unwired")
        .count()
}

/// Every purl the scan sent to the batch endpoint.
async fn batch_purls(mock: &MockServer) -> Vec<String> {
    let mut purls = Vec::new();
    for req in mock.received_requests().await.unwrap_or_default() {
        if !req.url.path().ends_with("/patches/batch") {
            continue;
        }
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
        for c in body["components"]
            .as_array()
            .or_else(|| body["purls"].as_array())
            .cloned()
            .unwrap_or_default()
        {
            if let Some(p) = c["purl"].as_str().or_else(|| c.as_str()) {
                purls.push(p.to_string());
            }
        }
    }
    purls
}

/// The user's edit of the vendored line, run through a plain rescan and
/// then `--prune`.
async fn assert_unwired_and_pruned(edited: &str) {
    let mock = empty_patch_api().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    seed_vendored(root);
    std::fs::write(root.join("requirements.txt"), edited).unwrap();

    let (code, v) = run_scan_vendored(root, &mock.uri(), &[]);
    assert_eq!(code, 0, "edited={edited:?}: {v}");
    assert_eq!(unwired_warnings(&v), 1, "edited={edited:?}: {v}");
    assert!(
        !batch_purls(&mock).await.iter().any(|p| p == PURL),
        "edited={edited:?}: the unwired ledger entry must not be rediscovered: {v}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("requirements.txt")).unwrap(),
        edited,
        "a plain rescan must not touch requirements.txt"
    );

    let (code, v) = run_scan_vendored(root, &mock.uri(), &["--prune"]);
    assert_eq!(code, 0, "edited={edited:?}: {v}");
    assert_eq!(
        reverted_purls(&v),
        serde_json::json!([PURL]),
        "edited={edited:?}: {v}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("requirements.txt")).unwrap(),
        edited,
        "the user's own pin must survive the prune"
    );
    assert!(
        !root.join(format!(".socket/vendor/pypi/{UUID}")).exists(),
        "edited={edited:?}: the dead uuid dir is reclaimed"
    );
    let state = std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap_or_default();
    assert!(!state.contains(PURL), "edited={edited:?}: {state}");
}

/// #786 case A: the user deleted the vendored line.
#[tokio::test]
async fn removed_vendored_pin_is_unwired_and_pruned() {
    assert_unwired_and_pruned("idna==3.7\n").await;
}

/// #786 case B: the user bumped the pin to another release.
#[tokio::test]
async fn bumped_vendored_pin_is_unwired_and_pruned() {
    assert_unwired_and_pruned("sp-fixture-six==1.17.0\nidna==3.7\n").await;
}

/// The fresh-clone case the ledger supplement exists for: the vendored
/// line is still there and nothing is installed, so the entry stays
/// discoverable and no unwired warning is raised.
#[tokio::test]
async fn wired_vendored_pin_stays_discoverable() {
    let mock = empty_patch_api().await;
    let tmp = tempfile::tempdir().unwrap();
    seed_vendored(tmp.path());
    let wired = format!("{}\nidna==3.7\n", vendor_line());
    std::fs::write(tmp.path().join("requirements.txt"), &wired).unwrap();

    let (code, v) = run_scan_vendored(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(unwired_warnings(&v), 0, "{v}");
    assert!(
        batch_purls(&mock).await.iter().any(|p| p == PURL),
        "the wired entry stays discoverable: {v}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap(),
        wired
    );
}

/// The purls the prune GC reverted: its `vendor_reverted` events (v5.0's
/// `gc.revertedVendoredEntries`).
fn reverted_purls(envelope: &serde_json::Value) -> serde_json::Value {
    envelope["events"]
        .as_array()
        .expect("events array")
        .iter()
        .filter(|e| e["errorCode"] == "vendor_reverted")
        .map(|e| e["purl"].clone())
        .collect()
}

/// #1127: the human `--prune` run reverts an unwired entry too, when the
/// crawl found packages but none of them has a patch. Its early "No patches
/// available" exit used to skip the GC in vendored mode, while `--json`
/// ran it. The installed npm package makes sure the crawl is non-empty
/// (an empty crawl takes the vendored-only GC, which already worked).
#[tokio::test]
async fn human_prune_reverts_unwired_entry_when_no_package_is_patched() {
    let mock = empty_patch_api().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    seed_vendored(root);
    std::fs::write(root.join("requirements.txt"), "idna==3.7\n").unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "p", "version": "1.0.0", "dependencies": { "ms": "2.1.3" } }"#,
    )
    .unwrap();
    let ms = root.join("node_modules/ms");
    std::fs::create_dir_all(&ms).unwrap();
    std::fs::write(
        ms.join("package.json"),
        r#"{ "name": "ms", "version": "2.1.3" }"#,
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_socket-patch"))
        .args([
            "scan",
            "--mode",
            "vendored",
            "--prune",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
            "--vendor-url",
            &mock.uri(),
            "--patch-server-url",
            &mock.uri(),
        ])
        .current_dir(root)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env_remove("VIRTUAL_ENV")
        .env_remove("CONDA_PREFIX")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stdout.contains("No patches available for installed packages."),
        "the run must take the found-but-unpatched exit: stdout={stdout}"
    );
    assert!(
        stdout.contains("GC: reverted 1 vendored entry"),
        "the human run must report the vendored GC: stdout={stdout}; stderr={stderr}"
    );
    assert!(
        !root.join(format!(".socket/vendor/pypi/{UUID}")).exists(),
        "the dead uuid dir is reclaimed: stdout={stdout}"
    );
    let state = std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap_or_default();
    assert!(!state.contains(PURL), "{state}");
}
