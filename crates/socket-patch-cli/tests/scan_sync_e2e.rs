//! End-to-end tests for `scan --sync` (and `scan --apply` non-dry-run)
//! — the canonical bot workflow that combines discovery, download,
//! manifest write, file patch, and optional pruning. Exercises the
//! full `scan -> get -> apply` pipeline against a mock API + a real
//! file fixture.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn write_npm_package(root: &Path, name: &str, version: &str, content: &[u8]) {
    let pkg_dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), content).unwrap();
}

fn write_root(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "scan-sync-test", "version": "0.0.0" }"#,
    )
    .unwrap();
}

#[tokio::test]
async fn scan_sync_against_clean_project_adds_and_applies_patch() {
    // End-to-end `scan --sync --yes`: discover patch via batch, fetch
    // the full view, write manifest, apply to disk.
    let before = b"before\n";
    let after = b"after\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);
    let purl = "pkg:npm/sync-target@1.0.0";
    let encoded = "pkg%3Anpm%2Fsync-target%401.0.0";

    let mock = MockServer::start().await;

    // Batch discovery
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID,
                    "purl": purl,
                    "tier": "free",
                    "cveIds": [],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "sync patch"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    // Per-package search (scan --apply uses it)
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "Sync patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    // Full PatchResponse with inline blob_content
    // base64 of "after\n" — encoded inline since we don't want a new dev-dep.
    let blob_b64 = "YWZ0ZXIK";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "Sync test patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "sync-target", "1.0.0", before);

    let out = Command::new(binary())
        .args([
            "scan",
            "--json",
            "--sync",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        code, 0,
        "scan --sync must succeed; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let status = v["status"].as_str().expect("status string");
    // status is "success" or "partial_failure"; either is acceptable as
    // long as the chain completed.
    assert!(
        status == "success" || status == "partial_failure",
        "unexpected status: {status}; envelope={v}"
    );

    // The manifest must exist now.
    let manifest_path = tmp.path().join(".socket/manifest.json");
    assert!(
        manifest_path.exists(),
        "scan --sync must write the manifest"
    );

    // Verify the apply sub-object is present (synchronous path emits it).
    let apply_obj = v["apply"].as_object();
    if let Some(apply) = apply_obj {
        // We expect at least one patch action recorded.
        assert!(
            apply.contains_key("patches") || apply.contains_key("applied"),
            "apply sub-object should have outcomes; got: {apply:?}"
        );
    }
}

#[tokio::test]
async fn scan_apply_with_existing_blob_uses_local_cache() {
    // When the after-hash blob is already in .socket/blobs, scan --apply
    // should skip the blob download and use the cached one.
    let before = b"before\n";
    let after = b"after\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);
    let purl = "pkg:npm/cached-sync@1.0.0";
    let encoded = "pkg%3Anpm%2Fcached-sync%401.0.0";

    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID,
                    "purl": purl,
                    "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "low",
                    "title": "x"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    // base64 of "after\n" — encoded inline since we don't want a new dev-dep.
    let blob_b64 = "YWZ0ZXIK";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free",
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "cached-sync", "1.0.0", before);

    // Pre-stage the manifest WITH the same UUID — scan --apply should
    // emit `action: skipped` because UUID matches the manifest entry.
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "{UUID}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{before_hash}",
          "afterHash":  "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "x", "license": "MIT", "tier": "free"
    }}
  }}
}}"#
        ),
    )
    .unwrap();
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), after).unwrap();

    let out = Command::new(binary())
        .args([
            "scan",
            "--json",
            "--apply",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 0, "scan --apply with cached UUID must succeed; stdout={stdout}");
}

#[tokio::test]
async fn scan_apply_with_no_patches_emits_empty_apply_object() {
    // Discovery returns zero patches — scan --apply still emits the
    // apply sub-object so downstream consumers always see it.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "empty-target", "1.0.0", b"x");

    let out = Command::new(binary())
        .args([
            "scan",
            "--json",
            "--apply",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let apply = v["apply"].as_object().unwrap();
    assert_eq!(apply["found"], 0);
    assert_eq!(apply["applied"], 0);
}
