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
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
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
    // A clean apply against a pristine fixture MUST fully succeed. Accepting
    // "partial_failure" here would mask the apply step silently failing
    // (`scan.rs` flips status to partial_failure exactly when apply_code != 0).
    assert_eq!(
        status, "success",
        "scan --sync against a clean project must fully succeed; envelope={v}"
    );

    // The apply sub-object MUST be present and report exactly one patch
    // discovered, downloaded, and applied with no failures. Guarding this
    // behind `if let Some(..)` (as before) let a missing apply object pass.
    let apply = v["apply"]
        .as_object()
        .unwrap_or_else(|| panic!("scan --sync must emit an apply sub-object; envelope={v}"));
    assert_eq!(apply["found"], 1, "apply.found; apply={apply:?}");
    assert_eq!(apply["applied"], 1, "apply.applied; apply={apply:?}");
    assert_eq!(apply["failed"], 0, "apply.failed; apply={apply:?}");
    // A fresh add against an empty manifest MUST download the blob exactly once
    // and classify it as new (not skipped/updated). Without these a regression
    // that double-counts, re-uses a stale cache, or mislabels the action stays
    // green on `applied == 1` alone.
    assert_eq!(
        apply["downloaded"], 1,
        "the new patch must be downloaded; apply={apply:?}"
    );
    assert_eq!(
        apply["skipped"], 0,
        "nothing to skip on a fresh add; apply={apply:?}"
    );
    assert_eq!(
        apply["updated"], 0,
        "no manifest entry existed to update; apply={apply:?}"
    );
    let patches = apply["patches"].as_array().expect("apply.patches array");
    assert_eq!(
        patches.len(),
        1,
        "exactly one patch record; apply={apply:?}"
    );
    assert_eq!(patches[0]["purl"], purl);
    assert_eq!(patches[0]["uuid"], UUID);
    assert_eq!(
        patches[0]["action"], "added",
        "patch must be newly added; record={:?}",
        patches[0]
    );

    // The manifest must exist AND record this exact patch/uuid.
    let manifest_path = tmp.path().join(".socket/manifest.json");
    assert!(
        manifest_path.exists(),
        "scan --sync must write the manifest"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap())
            .expect("valid manifest JSON");
    assert_eq!(
        manifest["patches"][purl]["uuid"], UUID,
        "manifest must record the applied patch under its purl; manifest={manifest}"
    );
    // The manifest must record the independently-computed before/after hashes,
    // not just the UUID — otherwise a manifest that drops or corrupts the file
    // records would pass on the UUID check alone.
    let file_entry = &manifest["patches"][purl]["files"]["package/index.js"];
    assert_eq!(
        file_entry["beforeHash"], before_hash,
        "manifest must record the original-content hash; manifest={manifest}"
    );
    assert_eq!(
        file_entry["afterHash"], after_hash,
        "manifest must record the patched-content hash; manifest={manifest}"
    );

    // The whole point of `--sync`: the on-disk file is rewritten to the
    // patched ("after") content and its hash matches the API's afterHash.
    let patched = tmp
        .path()
        .join("node_modules")
        .join("sync-target")
        .join("index.js");
    let on_disk = std::fs::read(&patched).expect("patched index.js must exist");
    assert_eq!(
        on_disk, after,
        "index.js must contain the patched bytes after scan --sync"
    );
    assert_eq!(
        git_sha256(&on_disk),
        after_hash,
        "on-disk content hash must equal the API's afterHash"
    );

    // Confirm the real pipeline ran end-to-end: batch discovery + the full
    // patch view were both fetched from the mock (not short-circuited).
    let reqs = mock.received_requests().await.expect("recorded requests");
    let hit = |needle: &str| reqs.iter().any(|r| r.url.path().contains(needle));
    assert!(hit("/patches/batch"), "batch discovery must be called");
    assert!(
        hit(&format!("/patches/view/{UUID}")),
        "full patch view must be fetched"
    );
    assert!(
        hit(&format!("/patches/by-package/{encoded}")),
        "per-package patch search must be queried during scan --sync"
    );
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
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
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
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        code, 0,
        "scan --apply with cached UUID must succeed; stdout={stdout}; stderr={stderr}"
    );

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "envelope={v}");

    // The pre-staged manifest already carries this exact UUID, so the patch
    // MUST be classified `skipped` (not re-applied / re-added). Nothing in
    // the original test verified this — exit 0 alone would also hold if the
    // patch were wrongly re-applied.
    let apply = v["apply"]
        .as_object()
        .unwrap_or_else(|| panic!("scan --apply must emit an apply sub-object; envelope={v}"));
    assert_eq!(apply["found"], 1, "apply.found; apply={apply:?}");
    assert_eq!(
        apply["skipped"], 1,
        "patch must be skipped; apply={apply:?}"
    );
    assert_eq!(
        apply["applied"], 0,
        "nothing applied on a skip; apply={apply:?}"
    );
    assert_eq!(apply["failed"], 0, "apply.failed; apply={apply:?}");
    // The defining claim of this test ("skip the blob download / use the cached
    // one"): a known UUID with a cached blob must NOT trigger a blob download
    // and must NOT update the manifest. The original test asserted neither, so
    // a regression that re-downloads/re-writes on every run stayed green on
    // `skipped == 1` alone.
    assert_eq!(
        apply["downloaded"], 0,
        "a cached/known patch must not be downloaded; apply={apply:?}"
    );
    assert_eq!(
        apply["updated"], 0,
        "a skipped patch must not update the manifest; apply={apply:?}"
    );
    let patches = apply["patches"].as_array().expect("apply.patches array");
    assert_eq!(patches.len(), 1, "apply={apply:?}");
    assert_eq!(patches[0]["uuid"], UUID);
    assert_eq!(
        patches[0]["action"], "skipped",
        "cached/known UUID must yield action=skipped; record={:?}",
        patches[0]
    );

    // A skip must NOT touch the file: index.js stays at its original
    // ("before") content (the patch was never re-applied).
    let on_disk = std::fs::read(
        tmp.path()
            .join("node_modules")
            .join("cached-sync")
            .join("index.js"),
    )
    .expect("index.js must exist");
    assert_eq!(
        on_disk, before,
        "skipped patch must leave the file untouched"
    );

    // The pre-staged cached blob must still be present and unchanged.
    let cached = std::fs::read(blobs.join(&after_hash)).expect("cached blob must remain");
    assert_eq!(cached, after, "cached blob must be untouched");

    // A skip must leave the manifest byte-identical: exactly the one pre-staged
    // entry under its purl with the same UUID — not duplicated, replaced, or
    // augmented with a second record.
    let manifest_after: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .expect("valid manifest JSON after skip");
    let entries = manifest_after["patches"]
        .as_object()
        .expect("manifest patches object");
    assert_eq!(
        entries.len(),
        1,
        "skip must not add/duplicate manifest entries; manifest={manifest_after}"
    );
    assert_eq!(
        manifest_after["patches"][purl]["uuid"], UUID,
        "skip must preserve the original manifest UUID; manifest={manifest_after}"
    );
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
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v["status"], "success", "envelope={v}");
    let apply = v["apply"].as_object().unwrap();
    assert_eq!(apply["found"], 0, "apply={apply:?}");
    assert_eq!(apply["applied"], 0, "apply={apply:?}");
    assert_eq!(apply["skipped"], 0, "apply={apply:?}");
    assert_eq!(apply["failed"], 0, "apply={apply:?}");
    assert_eq!(apply["downloaded"], 0, "apply={apply:?}");
    // No patches discovered => the patches list must be empty, not just absent.
    assert_eq!(
        apply["patches"].as_array().expect("patches array").len(),
        0,
        "apply.patches must be empty; apply={apply:?}"
    );

    // Discovery (batch) must have actually been queried.
    let reqs = mock.received_requests().await.expect("recorded requests");
    assert!(
        reqs.iter().any(|r| r.url.path().contains("/patches/batch")),
        "batch discovery must be called"
    );
}

#[tokio::test]
async fn scan_apply_skips_vendored_purl_without_downloading() {
    // A purl recorded in the vendor ledger is skipped BEFORE download —
    // even when a NEWER patch uuid is available. The manifest must stay at
    // the vendored uuid (moving past it would break VEX verification with
    // `vendor_uuid_mismatch`), the patch view must never be fetched, and
    // the newer uuid still surfaces in `updates[]` as the operator's
    // signal to run `scan --vendor` / `vendor`.
    const NEW_UUID: &str = "22222222-2222-4222-8222-222222222222";
    let before = b"before\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(b"after\n");
    let purl = "pkg:npm/sync-target@1.0.0";
    let encoded = "pkg%3Anpm%2Fsync-target%401.0.0";

    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": NEW_UUID,
                    "purl": purl,
                    "tier": "free",
                    "cveIds": [],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "newer patch"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": NEW_UUID,
                "purl": purl,
                "publishedAt": "2024-06-01T00:00:00Z",
                "description": "Newer patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    // The full view endpoint exists but MUST NOT be hit for a vendored purl.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{NEW_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "sync-target", "1.0.0", before);

    // Manifest already records the patch at the VENDORED uuid…
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(socket.join("vendor")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "patches": { purl: {
                "uuid": UUID,
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": before_hash, "afterHash": after_hash } },
                "vulnerabilities": {},
                "description": "vendored patch", "license": "MIT", "tier": "free"
            }}
        }))
        .unwrap(),
    )
    .unwrap();
    // …and the vendor ledger owns it.
    std::fs::write(
        socket.join("vendor/state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { purl: {
                "ecosystem": "npm",
                "basePurl": purl,
                "uuid": UUID,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{UUID}/sync-target-1.0.0.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();

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
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "envelope={v}");

    let apply = v["apply"].as_object().expect("apply sub-object");
    assert_eq!(apply["found"], 1, "apply={apply:?}");
    assert_eq!(apply["skipped"], 1, "apply={apply:?}");
    assert_eq!(apply["downloaded"], 0, "vendored purl must not download; apply={apply:?}");
    assert_eq!(apply["applied"], 0, "apply={apply:?}");
    assert_eq!(apply["failed"], 0, "apply={apply:?}");
    let patches = apply["patches"].as_array().expect("patches array");
    assert_eq!(patches.len(), 1, "apply={apply:?}");
    assert_eq!(patches[0]["purl"], purl);
    assert_eq!(patches[0]["action"], "skipped", "record={:?}", patches[0]);
    assert_eq!(patches[0]["errorCode"], "vendored", "record={:?}", patches[0]);

    // The newer uuid still surfaces as an available update.
    let updates = v["updates"].as_array().expect("updates array");
    assert_eq!(updates.len(), 1, "envelope={v}");
    assert_eq!(updates[0]["purl"], purl);
    assert_eq!(updates[0]["oldUuid"], UUID);
    assert_eq!(updates[0]["newUuid"], NEW_UUID);

    // The manifest must STILL record the vendored uuid.
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(socket.join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["patches"][purl]["uuid"], UUID,
        "manifest must not move past the vendored uuid; manifest={manifest}"
    );
    // And the installed tree is untouched (no in-place apply happened).
    let on_disk =
        std::fs::read(tmp.path().join("node_modules/sync-target/index.js")).unwrap();
    assert_eq!(on_disk, before, "installed tree must stay untouched");

    // Load-bearing: the full patch view was NEVER fetched.
    let reqs = mock.received_requests().await.expect("recorded requests");
    assert!(
        !reqs.iter().any(|r| r.url.path().contains("/patches/view/")),
        "no patch view fetch for a vendored purl"
    );
}
