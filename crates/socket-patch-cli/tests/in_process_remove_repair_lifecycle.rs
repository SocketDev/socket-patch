//! Full-lifecycle tests for `remove` and `repair`.
//!
//! `remove` exercises the rollback → manifest delete → blob cleanup
//! chain. `repair` exercises blob fetching + GC across all three
//! download modes (file/diff/package). Both are run in-process so
//! coverage is captured.

use std::path::Path;

use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::commands::remove::{run as remove_run, RemoveArgs};
use socket_patch_cli::commands::repair::{run as repair_run, RepairArgs};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn write_root(cwd: &Path) {
    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
}

fn write_npm_pkg(cwd: &Path, name: &str, version: &str, file: &str, content: &[u8]) {
    let pkg = cwd.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    let p = pkg.join(file);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, content).unwrap();
}

// ---------------------------------------------------------------------------
// remove full lifecycle: rollback first, then drop from manifest, then GC
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn remove_with_rollback_full_chain() {
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());

    let original = b"original\n";
    let patched = b"patched\n";
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(patched);

    // Installed package — currently in the PATCHED state, so remove
    // should roll it back to original via the beforeHash blob.
    write_npm_pkg(tmp.path(), "remove-target", "1.0.0", "index.js", patched);

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "pkg:npm/remove-target@1.0.0": {{
                    "uuid": "11111111-1111-4111-8111-111111111111",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/index.js": {{
                        "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), original).unwrap();
    std::fs::write(blobs.join(&after_hash), patched).unwrap();

    let args = RemoveArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            yes: true,
            global: false,
            global_prefix: None,
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: "pkg:npm/remove-target@1.0.0".to_string(),
        skip_rollback: false,
    };
    let code = remove_run(args).await;
    assert_eq!(code, 0, "remove with rollback must succeed");

    // 1. File restored to original.
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/remove-target/index.js")).unwrap(),
        original
    );
    // 2. Manifest no longer has the entry.
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(m["patches"].as_object().unwrap().len(), 0);
    // 3. Blobs no longer referenced — cleanup should have removed them.
    let blobs_remaining: Vec<_> = std::fs::read_dir(&blobs).unwrap().flatten().collect();
    assert!(
        blobs_remaining.is_empty(),
        "blob cleanup must remove orphaned blobs after remove; still present: {:?}",
        blobs_remaining
    );
}

#[tokio::test]
#[serial]
async fn remove_by_uuid_finds_correct_purl() {
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    let uuid = "abcdef01-2345-4789-8abc-def012345678";
    // A decoy with a DIFFERENT uuid that must be left untouched. Without it,
    // a single-entry manifest can't distinguish "removed the entry matching
    // the uuid" from "removed every entry" — both leave 0 patches.
    let decoy_uuid = "99999999-9999-4999-8999-999999999999";

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "pkg:npm/uuid-remove@1.0.0": {{
                    "uuid": "{uuid}",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{}}, "vulnerabilities": {{}},
                    "description": "x", "license": "MIT", "tier": "free"
                }},
                "pkg:npm/decoy-keep@2.0.0": {{
                    "uuid": "{decoy_uuid}",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{}}, "vulnerabilities": {{}},
                    "description": "x", "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();

    let args = RemoveArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            yes: true,
            global: false,
            global_prefix: None,
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: uuid.to_string(),
        skip_rollback: true,
    };
    assert_eq!(remove_run(args).await, 0);
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    let patches = m["patches"].as_object().unwrap();
    // Exactly the uuid-matched purl is gone; the decoy survives intact.
    assert_eq!(
        patches.len(),
        1,
        "only the uuid-matched entry must be removed"
    );
    assert!(
        !patches.contains_key("pkg:npm/uuid-remove@1.0.0"),
        "the entry whose uuid matched the identifier must be removed"
    );
    assert!(
        patches.contains_key("pkg:npm/decoy-keep@2.0.0"),
        "the non-matching decoy must be left untouched"
    );
    assert_eq!(
        patches["pkg:npm/decoy-keep@2.0.0"]["uuid"], decoy_uuid,
        "the surviving entry must still be the decoy"
    );
}

#[tokio::test]
#[serial]
async fn remove_no_matching_purl_exits_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    // A real entry that does NOT match the identifier. Removing nothing must
    // be a true no-op: not-found exits 1 AND must not delete the bystander.
    let manifest_json = r#"{ "patches": {
        "pkg:npm/bystander@1.0.0": {
            "uuid": "22222222-2222-4222-8222-222222222222",
            "exportedAt": "2024-01-01T00:00:00Z",
            "files": {}, "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free"
        }
    } }"#;
    std::fs::write(socket.join("manifest.json"), manifest_json).unwrap();

    let args = RemoveArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            yes: true,
            global: false,
            global_prefix: None,
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: "pkg:npm/does-not-exist@9.9.9".to_string(),
        skip_rollback: true,
    };
    assert_eq!(remove_run(args).await, 1);
    // The bystander entry must remain — a non-match deletes nothing.
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    let patches = m["patches"].as_object().unwrap();
    assert_eq!(
        patches.len(),
        1,
        "a non-matching identifier must remove nothing"
    );
    assert!(patches.contains_key("pkg:npm/bystander@1.0.0"));
}

#[tokio::test]
#[serial]
async fn remove_invalid_manifest_emits_error() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let original = "{ not json";
    std::fs::write(socket.join("manifest.json"), original).unwrap();

    let args = RemoveArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            yes: true,
            global: false,
            global_prefix: None,
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: "pkg:npm/anything@1.0.0".to_string(),
        skip_rollback: true,
    };
    assert_eq!(remove_run(args).await, 1);
    // A manifest it could not parse must be left byte-for-byte intact — remove
    // must never silently overwrite/truncate it into a valid empty manifest.
    assert_eq!(
        std::fs::read_to_string(socket.join("manifest.json")).unwrap(),
        original,
        "unparseable manifest must not be clobbered on error"
    );
}

#[tokio::test]
#[serial]
async fn remove_no_manifest_emits_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let args = RemoveArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            yes: true,
            global: false,
            global_prefix: None,
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: "pkg:npm/anything@1.0.0".to_string(),
        skip_rollback: true,
    };
    assert_eq!(remove_run(args).await, 1);
    // Removing from a non-existent manifest must not conjure one into being.
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "remove against a missing manifest must not create one"
    );
}

// ---------------------------------------------------------------------------
// repair: download in all three modes (file/diff/package)
// ---------------------------------------------------------------------------

fn make_repair_args(cwd: &Path, mode: &str) -> RepairArgs {
    RepairArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            dry_run: false,
            offline: false,
            json: true,
            download_mode: mode.to_string(),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        download_only: false,
    }
}

#[tokio::test]
#[serial]
async fn repair_diff_mode_downloads_diff_archives() {
    let tmp = tempfile::tempdir().unwrap();
    let uuid = "12121212-1212-4121-8121-121212121212";
    let _after_hash = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1";

    let server = MockServer::start().await;
    // Diff mode fetches /v0/orgs/<org>/patches/diff/<uuid> → tar.gz body.
    let fake_archive = b"fake diff archive";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/diff/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(fake_archive.to_vec()))
        .mount(&server)
        .await;
    // Fallback blob endpoint should also be available.
    let real_blob = b"real blob content";
    let real_hash = git_sha256(real_blob);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/blob/{real_hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(real_blob.to_vec()))
        .mount(&server)
        .await;

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "pkg:npm/diff-test@1.0.0": {{
                    "uuid": "{uuid}",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/x.js": {{
                        "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                        "afterHash": "{real_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();

    std::env::set_var("SOCKET_API_URL", server.uri());
    std::env::set_var("SOCKET_API_TOKEN", "fake");
    std::env::set_var("SOCKET_ORG_SLUG", ORG);
    let code = repair_run(make_repair_args(tmp.path(), "diff")).await;
    std::env::remove_var("SOCKET_API_URL");
    std::env::remove_var("SOCKET_API_TOKEN");
    std::env::remove_var("SOCKET_ORG_SLUG");
    assert_eq!(code, 0, "repair --download-mode diff must succeed");

    // The diff archive should be on disk at .socket/diffs/<uuid>.tar.gz, and
    // its bytes must be exactly what the server served — a corrupt/empty
    // write would otherwise still satisfy a bare `exists()` check.
    let archive_path = socket.join(format!("diffs/{uuid}.tar.gz"));
    assert!(
        archive_path.exists(),
        "diff archive must be persisted to {}",
        archive_path.display()
    );
    assert_eq!(
        std::fs::read(&archive_path).unwrap(),
        fake_archive,
        "persisted diff archive bytes must match the served body"
    );
    // Prove the real download path ran (not a short-circuit): the diff
    // endpoint must have actually been requested.
    let hits = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == format!("/v0/orgs/{ORG}/patches/diff/{uuid}"))
        .count();
    assert_eq!(hits, 1, "diff endpoint must be fetched exactly once");
}

#[tokio::test]
#[serial]
async fn repair_package_mode_downloads_package_archives() {
    let tmp = tempfile::tempdir().unwrap();
    let uuid = "13131313-1313-4131-8131-131313131313";
    let _after_hash = "def456def456def456def456def456def456def456def456def456def456def4";

    let server = MockServer::start().await;
    let archive_bytes = b"fake package archive bytes";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(archive_bytes.to_vec()))
        .mount(&server)
        .await;
    let real_blob = b"real blob";
    let real_hash = git_sha256(real_blob);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/blob/{real_hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(real_blob.to_vec()))
        .mount(&server)
        .await;

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "pkg:npm/pkg-test@1.0.0": {{
                    "uuid": "{uuid}",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/x.js": {{
                        "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                        "afterHash": "{real_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();

    std::env::set_var("SOCKET_API_URL", server.uri());
    std::env::set_var("SOCKET_API_TOKEN", "fake");
    std::env::set_var("SOCKET_ORG_SLUG", ORG);
    let code = repair_run(make_repair_args(tmp.path(), "package")).await;
    std::env::remove_var("SOCKET_API_URL");
    std::env::remove_var("SOCKET_API_TOKEN");
    std::env::remove_var("SOCKET_ORG_SLUG");
    assert_eq!(code, 0);
    let archive_path = socket.join(format!("packages/{uuid}.tar.gz"));
    assert!(archive_path.exists());
    assert_eq!(
        std::fs::read(&archive_path).unwrap(),
        archive_bytes,
        "persisted package archive bytes must match the served body"
    );
    let hits = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == format!("/v0/orgs/{ORG}/patches/package/{uuid}"))
        .count();
    assert_eq!(hits, 1, "package endpoint must be fetched exactly once");
}

#[tokio::test]
#[serial]
async fn repair_file_mode_downloads_individual_blobs() {
    let tmp = tempfile::tempdir().unwrap();
    let blob_content = b"some patched content\n";
    let after_hash = git_sha256(blob_content);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/blob/{after_hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(blob_content.to_vec()))
        .mount(&server)
        .await;

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "pkg:npm/file-test@1.0.0": {{
                    "uuid": "14141414-1414-4141-8141-141414141414",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/x.js": {{
                        "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                        "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();

    std::env::set_var("SOCKET_API_URL", server.uri());
    std::env::set_var("SOCKET_API_TOKEN", "fake");
    std::env::set_var("SOCKET_ORG_SLUG", ORG);
    let code = repair_run(make_repair_args(tmp.path(), "file")).await;
    std::env::remove_var("SOCKET_API_URL");
    std::env::remove_var("SOCKET_API_TOKEN");
    std::env::remove_var("SOCKET_ORG_SLUG");
    assert_eq!(code, 0);
    let blob_path = socket.join("blobs").join(&after_hash);
    assert!(blob_path.exists());
    // Content-addressed: the stored blob must contain exactly the served
    // bytes, and re-hashing it must reproduce the manifest's afterHash.
    let stored = std::fs::read(&blob_path).unwrap();
    assert_eq!(
        stored, blob_content,
        "stored blob bytes must match served body"
    );
    assert_eq!(
        git_sha256(&stored),
        after_hash,
        "stored blob must hash back to its content-addressed name"
    );
    let hits = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == format!("/v0/orgs/{ORG}/patches/blob/{after_hash}"))
        .count();
    assert_eq!(hits, 1, "blob endpoint must be fetched exactly once");
}

#[tokio::test]
#[serial]
async fn repair_dry_run_does_not_download() {
    let tmp = tempfile::tempdir().unwrap();

    // Critically: run dry-run while ONLINE (offline = false) and with a mock
    // server that WOULD happily serve the missing blob. The only thing that
    // can stop the download is the dry_run flag being honoured. The previous
    // version of this test also set offline = true and had no server, so a
    // `dry_run` that was silently ignored would still pass vacuously (network
    // blocked by airgap, not by dry-run logic).
    let blob_content = b"would-be-downloaded blob\n";
    let after_hash = git_sha256(blob_content);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/blob/{after_hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(blob_content.to_vec()))
        .mount(&server)
        .await;

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
            "pkg:npm/dryrun@1.0.0": {{
                "uuid": "15151515-1515-4151-8151-151515151515",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {{ "package/x.js": {{
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  "{after_hash}"
                }}}},
                "vulnerabilities": {{}}, "description": "x",
                "license": "MIT", "tier": "free"
            }}
        }}}}"#
        ),
    )
    .unwrap();

    let mut args = make_repair_args(tmp.path(), "file");
    args.common.dry_run = true;
    args.common.offline = false;

    std::env::set_var("SOCKET_API_URL", server.uri());
    std::env::set_var("SOCKET_API_TOKEN", "fake");
    std::env::set_var("SOCKET_ORG_SLUG", ORG);
    let code = repair_run(args).await;
    std::env::remove_var("SOCKET_API_URL");
    std::env::remove_var("SOCKET_API_TOKEN");
    std::env::remove_var("SOCKET_ORG_SLUG");
    assert_eq!(code, 0, "dry-run repair must succeed");

    // The blob the server offered must NOT be on disk.
    assert!(
        !socket.join("blobs").join(&after_hash).exists(),
        "dry-run must not write the missing blob to disk"
    );
    assert!(
        !socket.join("blobs").exists() || socket.join("blobs").read_dir().unwrap().count() == 0,
        "dry-run must not download blobs"
    );
    // The decisive check: the blob endpoint must never have been requested.
    // If dry_run were ignored, fetch_missing_sources would have hit it.
    let hits = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| {
            r.url
                .path()
                .starts_with(&format!("/v0/orgs/{ORG}/patches/"))
        })
        .count();
    assert_eq!(
        hits, 0,
        "dry-run must not issue any patch-artifact download requests"
    );
}

#[tokio::test]
#[serial]
async fn repair_with_no_manifest_emits_error() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(repair_run(make_repair_args(tmp.path(), "file")).await, 1);
}

/// Regression: a repair where a missing artifact fails to download must
/// exit non-zero. The blob the manifest references is absent from disk AND
/// the mock server has no route for it (→ 404 / not found), so the fetch
/// fails. Before the fix `run()` reported success (exit 0) even though it
/// had marked the run a partial failure and emitted a `Failed` event —
/// hiding the failure from any CI guarding on the exit code.
#[tokio::test]
#[serial]
async fn repair_download_failure_exits_nonzero() {
    let tmp = tempfile::tempdir().unwrap();
    // A valid-format (64 hex) afterHash the server will never serve.
    let after_hash = git_sha256(b"never served by the mock\n");

    // Mock server with NO blob route → every fetch 404s.
    let server = MockServer::start().await;

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "pkg:npm/fetch-fail@1.0.0": {{
                    "uuid": "17171717-1717-4171-8171-171717171717",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/x.js": {{
                        "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                        "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();

    std::env::set_var("SOCKET_API_URL", server.uri());
    std::env::set_var("SOCKET_API_TOKEN", "fake");
    std::env::set_var("SOCKET_ORG_SLUG", ORG);
    let code = repair_run(make_repair_args(tmp.path(), "file")).await;
    std::env::remove_var("SOCKET_API_URL");
    std::env::remove_var("SOCKET_API_TOKEN");
    std::env::remove_var("SOCKET_ORG_SLUG");

    assert_eq!(
        code, 1,
        "a failed artifact download must surface as a non-zero exit"
    );
    // The blob must not have been written.
    assert!(!socket.join("blobs").join(&after_hash).exists());
}

#[tokio::test]
#[serial]
async fn repair_offline_with_present_blobs_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let blob = b"already present\n";
    let hash = git_sha256(blob);

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "pkg:npm/present@1.0.0": {{
                    "uuid": "16161616-1616-4161-8161-161616161616",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/x.js": {{
                        "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                        "afterHash": "{hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&hash), blob).unwrap();

    let mut args = make_repair_args(tmp.path(), "file");
    args.common.offline = true;
    assert_eq!(repair_run(args).await, 0);
    // The referenced blob is in use, so offline cleanup must leave it intact.
    let kept = blobs.join(&hash);
    assert!(kept.exists(), "a referenced blob must survive repair");
    assert_eq!(
        std::fs::read(&kept).unwrap(),
        blob,
        "the surviving blob's content must be unchanged"
    );
}
