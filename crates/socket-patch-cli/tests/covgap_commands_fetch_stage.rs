//! Coverage-gap tests for `commands/fetch_stage.rs` — the user-facing
//! diagnostics and server-shaped failure arms no existing suite drives:
//!
//!   - the non-quiet offline "no local source" report: the count header,
//!     the 5-PURL cap, the "... and N more" continuation, and the
//!     `repair` hint (`report_offline_missing`);
//!   - the non-quiet online staging progress: the download announcement
//!     and the diff→per-file-blob fallback messages;
//!   - the vendor mem-stager's per-file failure arms for malformed patch
//!     view responses (missing `blobContent`, invalid `afterHash`,
//!     undecodable base64) and the non-quiet "could not fetch patch
//!     content" stderr block listing the failed PURLs.
//!
//! The `--silent` variants of the offline / download-failure diagnostics
//! (errors only, never nothing) are pinned by
//! `coverage_fix_apply_silent_mute_exit.rs`; this suite covers the
//! human-mode (non-quiet) output shape and the mem-stager arms.

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
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";
/// base64 of AFTER, the shape the view response's `blobContent` carries.
const AFTER_B64: &str = "YWZ0ZXIK";

/// Git-SHA256: SHA256("blob <len>\0" ++ content). Computed independently
/// of the code under test.
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Spawn the built binary in `root` with a scrubbed `SOCKET_*` surface
/// (prefix scrub — fixed lists rot), the telemetry kill-switch forced,
/// and `extra_env` injected last so deliberate seeds survive the scrub.
/// Mirrors `scan_vendor_e2e.rs::run_cli_env`.
fn run_cli_env(root: &Path, argv: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(argv).current_dir(root);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_")
            && key.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// report_offline_missing: header count, 5-PURL cap, "... and N more",
// repair hint — the full non-quiet body.
// ---------------------------------------------------------------------------

/// SEVEN sourceless npm patches under `--offline` in human mode: the
/// error header carries the total, at most FIVE PURLs are listed, the
/// remainder is summarized as "... and 2 more", and the `repair` hint
/// closes the report.
#[test]
fn apply_offline_nonquiet_lists_capped_missing_purls_and_repair_hint() {
    let tmp = tempfile::tempdir().unwrap();
    // Root project marker + empty node_modules (the same shape
    // `apply_invariants.rs::write_project` uses to reach the offline gate).
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"covgap-offline","version":"0.0.0"}"#,
    )
    .unwrap();
    std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();

    // Manifest with 7 patches and NO blobs/diffs/packages dirs anywhere:
    // every patch is sourceless. Distinct purls, hashes, and v4 uuids.
    let mut patches = serde_json::Map::new();
    for i in 0..7u32 {
        let purl = format!("pkg:npm/miss-{i}@1.0.0");
        let uuid = format!("{i}{i}{i}{i}{i}{i}{i}{i}-{i}{i}{i}{i}-4{i}{i}{i}-8{i}{i}{i}-{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}{i}");
        let before_hash = format!("{:064}", i * 2 + 1);
        let after_hash = format!("{:064}", i * 2 + 2);
        patches.insert(
            purl,
            serde_json::json!({
                "uuid": uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": before_hash,
                        "afterHash": after_hash,
                    }
                },
                "vulnerabilities": {},
                "description": "sourceless",
                "license": "MIT",
                "tier": "free",
            }),
        );
    }
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
    )
    .unwrap();

    let (code, _stdout, stderr) = run_cli_env(tmp.path(), &["apply", "--offline"], &[]);
    assert_eq!(
        code, 1,
        "offline + 7 sourceless patches must fail; stderr={stderr}"
    );
    assert!(
        stderr.contains("Error: 7 patch(es) have no local source and --offline is set:"),
        "the header must carry the TOTAL count, not the listed count; stderr={stderr}"
    );
    let listed: Vec<&str> = stderr
        .lines()
        .filter(|l| l.starts_with("  - pkg:npm/miss-"))
        .collect();
    assert_eq!(
        listed.len(),
        5,
        "exactly five PURLs are listed (the cap); got {listed:?}\nstderr={stderr}"
    );
    assert!(
        stderr.contains("  ... and 2 more"),
        "the 2 unlisted patches are summarized; stderr={stderr}"
    );
    assert!(
        stderr.contains("Run \"socket-patch repair\" to download missing artifacts."),
        "the repair hint closes the report; stderr={stderr}"
    );
}

// ---------------------------------------------------------------------------
// Non-quiet online staging: download announcement + diff→blob fallback.
// ---------------------------------------------------------------------------

/// A human-mode (no `--json`/`--silent`) online apply in the default
/// `diff` download mode, where the server has no diff archive but serves
/// the per-file blob: the run announces the primary download (with the
/// mode tag), reports the diff failure, announces the per-file blob
/// fallback, reports its success — and applies. `.socket/` stays
/// untouched (downloads land in the overlay tempdir).
#[tokio::test]
async fn apply_online_nonquiet_prints_download_progress_and_diff_fallback() {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);

    let mock = MockServer::start().await;
    // Only the per-file blob endpoint is mounted; the diff/package archive
    // endpoints 404 (wiremock's default for unmounted routes), so the
    // default diff-mode fetch fails and the blob fallback closes the gap.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(AFTER.to_vec()))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"covgap-fallback-root","version":"0.0.0"}"#,
    )
    .unwrap();
    let pkg = tmp.path().join("node_modules").join("fallback-test");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        r#"{"name":"fallback-test","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "patches": {
                "pkg:npm/fallback-test@1.0.0": {
                    "uuid": UUID,
                    "exportedAt": "2026-01-01T00:00:00Z",
                    "files": {
                        "package/index.js": {
                            "beforeHash": before_hash,
                            "afterHash": after_hash,
                        }
                    },
                    "vulnerabilities": {},
                    "description": "diff fallback target",
                    "license": "MIT",
                    "tier": "free",
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();

    // apply rejects --api-url/--api-token/--org flags — env is its channel.
    let mock_uri = mock.uri();
    let (code, stdout, stderr) = run_cli_env(
        tmp.path(),
        &["apply"],
        &[
            ("SOCKET_API_URL", mock_uri.as_str()),
            ("SOCKET_API_TOKEN", "fake-token-for-test"),
            ("SOCKET_ORG_SLUG", ORG_SLUG),
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");

    // The four progress lines of the staging flow, in the shapes users see.
    assert!(
        stdout.contains("Downloading missing patch artifacts (mode: diff)..."),
        "the primary download is announced with its mode tag; stdout={stdout}"
    );
    assert!(
        stdout.contains("Failed to download 1 blob(s)")
            && stdout.contains("Diff archive not found on server"),
        "the diff fetch failure is reported before the fallback; stdout={stdout}"
    );
    assert!(
        stdout.contains("Falling back to per-file blob downloads for 1 blob(s)..."),
        "the per-file blob fallback is announced with the gap size; stdout={stdout}"
    );
    assert!(
        stdout.contains("Downloaded 1 blob(s)"),
        "the fallback's own result line is printed; stdout={stdout}"
    );

    // The fallback actually applied the patch…
    assert_eq!(
        std::fs::read(pkg.join("index.js")).unwrap(),
        AFTER,
        "node_modules must carry the after-content"
    );
    // …and the downloaded blob never landed in the persistent cache.
    let blobs_dir = socket.join("blobs");
    if blobs_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&blobs_dir).unwrap().collect();
        assert!(
            entries.is_empty(),
            "downloads land in the overlay tempdir, never .socket/blobs/; found {entries:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Vendor mem-stager: malformed patch view responses fail closed, with the
// non-quiet per-file / summary diagnostics.
// ---------------------------------------------------------------------------

/// Committed manifest with NO local artifacts (no blobs/diffs/packages):
/// the vendor mem-stager must fetch the patch view for its content.
fn seed_sourceless_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "patches": {
                PURL: {
                    "uuid": UUID,
                    "exportedAt": "2026-01-01T00:00:00Z",
                    "files": {
                        "package/index.js": {
                            "beforeHash": git_sha256(BEFORE),
                            "afterHash": git_sha256(AFTER),
                        }
                    },
                    "vulnerabilities": {},
                    "description": "Vendor patch",
                    "license": "MIT",
                    "tier": "free",
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
}

/// Mount `/patches/view/{UUID}` whose single file entry carries
/// `file_fields` — the knob each malformed-response variant turns.
async fn mount_view(mock: &MockServer, file_fields: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": file_fields },
            "vulnerabilities": {},
            "description": "Vendor patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// Human-mode standalone `vendor` (staging runs before any package
/// matching, so no lockfile or installed tree is needed).
fn run_vendor_human(root: &Path, mock_uri: &str) -> (i32, String, String) {
    run_cli_env(
        root,
        &["vendor"],
        &[
            ("SOCKET_API_URL", mock_uri),
            ("SOCKET_API_TOKEN", "fake-token"),
            ("SOCKET_ORG_SLUG", ORG_SLUG),
        ],
    )
}

/// Shared postconditions for every malformed-view variant: exit 1, the
/// fetch was really attempted (announcement on stdout), the non-quiet
/// summary block names the failed purl on stderr, and the fail-closed run
/// wrote nothing (no blobs — mem staging is disk-free — and no vendor
/// tree).
fn assert_failed_closed(root: &Path, code: i32, stdout: &str, stderr: &str) {
    assert_eq!(
        code, 1,
        "a malformed view response must fail the run; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("Fetching 1 patch(es)' content (kept in memory)..."),
        "the run must have reached the view fetch (not bailed earlier); stdout={stdout}"
    );
    assert!(
        stderr.contains("Error: could not fetch patch content for 1 patch(es):"),
        "the summary block carries the failed count; stderr={stderr}"
    );
    assert!(
        stderr.contains(&format!("  - {PURL}")),
        "the failed purl is listed; stderr={stderr}"
    );
    assert!(
        !root.join(".socket/blobs").exists(),
        "mem staging must write no blobs"
    );
    assert!(
        !root.join(".socket/vendor").exists(),
        "a failed staging must write no vendor tree"
    );
}

/// Variant (a): the view entry has a valid `afterHash` but a null
/// `blobContent`. The per-file arm names the file on stderr, and the
/// summary block follows.
#[tokio::test]
async fn vendor_view_without_blob_content_reports_per_file_and_summary_errors() {
    let mock = MockServer::start().await;
    mount_view(
        &mock,
        serde_json::json!({
            "beforeHash": git_sha256(BEFORE),
            "afterHash": git_sha256(AFTER),
            "blobContent": null,
        }),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    seed_sourceless_manifest(tmp.path());

    let (code, stdout, stderr) = run_vendor_human(tmp.path(), &mock.uri());
    assert_failed_closed(tmp.path(), code, &stdout, &stderr);
    assert!(
        stderr.contains(&format!(
            "  [error] {PURL}: no blob content served for package/index.js"
        )),
        "the missing-content arm names patch AND file; stderr={stderr}"
    );
}

/// Variant (b): valid `blobContent` but an `afterHash` that is 64 chars
/// of non-hex — rejected by the blob-hash key guard. The guard arm breaks
/// without a per-file line; only the summary block reports the failure.
#[tokio::test]
async fn vendor_view_with_invalid_after_hash_fails_closed_without_per_file_line() {
    let mock = MockServer::start().await;
    mount_view(
        &mock,
        serde_json::json!({
            "beforeHash": git_sha256(BEFORE),
            "afterHash": "z".repeat(64),
            "blobContent": AFTER_B64,
        }),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    seed_sourceless_manifest(tmp.path());

    let (code, stdout, stderr) = run_vendor_human(tmp.path(), &mock.uri());
    assert_failed_closed(tmp.path(), code, &stdout, &stderr);
    assert!(
        !stderr.contains("[error]"),
        "the hash-guard arm breaks silently (no per-file line today); stderr={stderr}"
    );
}

/// Variant (c): valid `afterHash` but a `blobContent` that is not
/// base64 — the decode arm fails closed, again with only the summary
/// block on stderr.
#[tokio::test]
async fn vendor_view_with_undecodable_blob_content_fails_closed() {
    let mock = MockServer::start().await;
    mount_view(
        &mock,
        serde_json::json!({
            "beforeHash": git_sha256(BEFORE),
            "afterHash": git_sha256(AFTER),
            "blobContent": "%%%not-base64%%%",
        }),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    seed_sourceless_manifest(tmp.path());

    let (code, stdout, stderr) = run_vendor_human(tmp.path(), &mock.uri());
    assert_failed_closed(tmp.path(), code, &stdout, &stderr);
    assert!(
        !stderr.contains("[error]"),
        "the decode arm breaks silently (no per-file line today); stderr={stderr}"
    );
}
