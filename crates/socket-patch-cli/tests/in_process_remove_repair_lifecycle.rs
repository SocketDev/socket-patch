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
    std::fs::write(cwd.join("package.json"), r#"{"name":"r","version":"0.0.0"}"#).unwrap();
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
    assert_eq!(m["patches"].as_object().unwrap().len(), 0);
}

#[tokio::test]
#[serial]
async fn remove_no_matching_purl_exits_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), r#"{ "patches": {} }"#).unwrap();

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
}

#[tokio::test]
#[serial]
async fn remove_invalid_manifest_emits_error() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), "{ not json").unwrap();

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
    let after_hash = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1";

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

    // The diff archive should be on disk at .socket/diffs/<uuid>.tar.gz.
    let archive_path = socket.join(format!("diffs/{uuid}.tar.gz"));
    assert!(
        archive_path.exists(),
        "diff archive must be persisted to {}",
        archive_path.display()
    );
}

#[tokio::test]
#[serial]
async fn repair_package_mode_downloads_package_archives() {
    let tmp = tempfile::tempdir().unwrap();
    let uuid = "13131313-1313-4131-8131-131313131313";
    let after_hash = "def456def456def456def456def456def456def456def456def456def456def4";

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
    assert!(socket.join(format!("packages/{uuid}.tar.gz")).exists());
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
    assert!(socket.join("blobs").join(&after_hash).exists());
}

#[tokio::test]
#[serial]
async fn repair_dry_run_does_not_download() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{ "patches": {
            "pkg:npm/dryrun@1.0.0": {
                "uuid": "15151515-1515-4151-8151-151515151515",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": { "package/x.js": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
                }},
                "vulnerabilities": {}, "description": "x",
                "license": "MIT", "tier": "free"
            }
        }}"#,
    )
    .unwrap();

    let mut args = make_repair_args(tmp.path(), "file");
    args.common.dry_run = true;
    args.common.offline = true;
    assert_eq!(repair_run(args).await, 0);
    // Nothing should be downloaded.
    assert!(
        !socket.join("blobs").exists() || socket.join("blobs").read_dir().unwrap().count() == 0,
        "dry-run must not download blobs"
    );
}

#[tokio::test]
#[serial]
async fn repair_with_no_manifest_emits_error() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(repair_run(make_repair_args(tmp.path(), "file")).await, 1);
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
}
