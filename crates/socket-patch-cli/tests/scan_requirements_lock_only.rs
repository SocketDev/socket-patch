//! Lock-only `scan` over a pip `requirements.txt` (a fresh checkout: no
//! virtualenv yet, the usual CI case). Discovery must read the pins the
//! way pip does, or the package never reaches the patch API and `scan`
//! reports "No patches available" while pip installs the unpatched
//! release:
//!
//! * #523: whitespace around `==` and the legacy `name (==X)` form;
//! * #412: pins reached through in-root `-r` includes;
//! * #721: a UTF-16 file with a BOM (Windows PowerShell 5.1's
//!   `pip freeze >` output), which pip decodes.
//!
//! Driven through the built binary against a mock patch API; the
//! assertion is what discovery sends to the batch endpoint and the
//! `lockfileOnlyPackages` count in the JSON envelope, in both hosted and
//! vendored mode. The package names are fixtures no interpreter on the
//! machine has installed, so every hit is a lock-only one.

use std::path::Path;
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "test-org";

async fn mount_empty_batch(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
}

fn run_scan(root: &Path, mock_uri: &str, extra: &[&str]) -> (i32, serde_json::Value) {
    let mut argv = vec![
        "scan",
        "--json",
        "--yes",
        "--api-url",
        mock_uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
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

/// Every purl the scan sent to the batch endpoint.
async fn batch_purls(mock: &MockServer) -> Vec<String> {
    let mut purls: Vec<String> = Vec::new();
    for req in mock.received_requests().await.unwrap_or_default() {
        if !req.url.path().ends_with("/patches/batch") {
            continue;
        }
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
        let found = body["components"]
            .as_array()
            .or_else(|| body["purls"].as_array())
            .cloned()
            .unwrap_or_default();
        for c in found {
            let purl = c["purl"]
                .as_str()
                .or_else(|| c.as_str())
                .map(str::to_string);
            purls.extend(purl);
        }
    }
    purls.sort();
    purls.dedup();
    purls
}

async fn assert_lock_only_discovers(files: &[(&str, &str)], expected: &[&str]) {
    let files: Vec<(&str, &[u8])> = files.iter().map(|(r, c)| (*r, c.as_bytes())).collect();
    assert_lock_only_discovers_bytes(&files, expected).await;
}

async fn assert_lock_only_discovers_bytes(files: &[(&str, &[u8])], expected: &[&str]) {
    for mode in [&[][..], &["--vendor"][..]] {
        let mock = MockServer::start().await;
        mount_empty_batch(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        for (rel, content) in files {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }
        let (code, v) = run_scan(tmp.path(), &mock.uri(), mode);
        assert_eq!(code, 0, "mode={mode:?}: {v}");
        assert_eq!(
            v["lockfileOnlyPackages"].as_u64(),
            Some(expected.len() as u64),
            "mode={mode:?}: {v}"
        );
        let purls = batch_purls(&mock).await;
        for want in expected {
            assert!(
                purls.iter().any(|p| p == want),
                "mode={mode:?}: {want} must reach the patch API; sent {purls:?}; {v}"
            );
        }
    }
}

/// #523: spaced and parenthesised exact pins are discovered.
#[tokio::test]
async fn lock_only_scan_discovers_spaced_pins() {
    assert_lock_only_discovers(
        &[(
            "requirements.txt",
            "sp-fixture-a == 1.15.0\n\
             sp-fixture-b ==1.15.0\n\
             sp-fixture-c== 1.15.0\n\
             sp-fixture-d[x] == 1.15.0\n\
             sp-fixture-e (==1.15.0)\n",
        )],
        &[
            "pkg:pypi/sp-fixture-a@1.15.0",
            "pkg:pypi/sp-fixture-b@1.15.0",
            "pkg:pypi/sp-fixture-c@1.15.0",
            "pkg:pypi/sp-fixture-d@1.15.0",
            "pkg:pypi/sp-fixture-e@1.15.0",
        ],
    )
    .await;
}

/// #412: pins in an in-root `-r` include are discovered.
#[tokio::test]
async fn lock_only_scan_discovers_included_pins() {
    assert_lock_only_discovers(
        &[
            ("requirements.txt", "-r requirements/base.txt\n"),
            ("requirements/base.txt", "sp-fixture-six==1.16.0\n"),
        ],
        &["pkg:pypi/sp-fixture-six@1.16.0"],
    )
    .await;
}

/// #721: pip decodes a requirements file by its BOM, so a UTF-16 file
/// (what Windows PowerShell 5.1's `pip freeze >` writes) is discovered,
/// in either byte order, instead of reading as "No packages found".
#[tokio::test]
async fn lock_only_scan_discovers_utf16_pins() {
    let text = "sp-fixture-idna==3.7\r\nsp-fixture-six==1.16.0\r\n";
    let le: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let be: Vec<u8> = [0xFE, 0xFF]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_be_bytes))
        .collect();
    for bytes in [le, be] {
        assert_lock_only_discovers_bytes(
            &[("requirements.txt", &bytes)],
            &[
                "pkg:pypi/sp-fixture-idna@3.7",
                "pkg:pypi/sp-fixture-six@1.16.0",
            ],
        )
        .await;
    }
}
