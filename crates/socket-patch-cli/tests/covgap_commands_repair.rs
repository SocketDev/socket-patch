//! Coverage-gap tests for `commands/repair.rs`: the human-mode (non-`--json`)
//! output arms that every existing suite drove through `--json`, plus the
//! warn-and-continue housekeeping contracts.
//!
//! Ranges pinned (audited at d5e1815, file unchanged since):
//!   * the loud `manifest_not_found` / `repair_failed` stderr prints,
//!   * the loud "All {mode} artifacts are present locally." summary,
//!   * the `... and N more` truncation of the offline warning (>5 missing)
//!     and the dry-run preview (>10 missing),
//!   * the loud orphan-archive removal print, including the
//!     `.replace("blob(s)", "{label} archive(s)")` coupling to
//!     `format_cleanup_result`'s exact wording,
//!   * the archive-cleanup failure arm (stderr warning + `cleanup_failed`
//!     skip event, exit stays 0, loop continues to the packages pass),
//!   * the lock-file unlink-failure warning (exit stays 0),
//!   * the loud "Rebuilt N vendored artifact(s)." summary after the
//!     vendored-repair phase.
//!
//! Everything runs offline or against a wiremock server — no real hosts.
//! Fixtures mirror `repair_invariants.rs` / `repair_vendor_e2e.rs` (this
//! suite owns its own copies; those files are owned by other agents).

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "test-org";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// A `socket-patch` command rooted at `cwd` with every ambient `SOCKET_*`
/// env var scrubbed (same rationale as `repair_invariants.rs`: an ambient
/// `SOCKET_OFFLINE`/`SOCKET_JSON`/`SOCKET_SILENT` would flip the very
/// loud-vs-quiet branches this suite exists to pin). Tests re-seed only
/// what they deliberately control via `.env()` after this scrub.
fn socket_cmd(cwd: &Path) -> Command {
    let mut cmd = Command::new(binary());
    cmd.current_dir(cwd);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SOCKET_")
            && name.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(name);
        }
    }
    cmd
}

/// Git-SHA256: SHA256("blob <len>\0" ++ content).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// A manifest with one patch referencing one blob — the baseline
/// `.socket/manifest.json` (mirrors `repair_invariants.rs`).
const MANIFEST_JSON: &str = r#"{
  "patches": {
    "pkg:npm/__covgap_repair__@1.0.0": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {
        "package/index.js": {
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
        }
      },
      "vulnerabilities": {},
      "description": "covgap repair fixture",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

const REFERENCED_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REFERENCED_UUID: &str = "11111111-1111-4111-8111-111111111111";

fn make_socket_dir(root: &Path) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), MANIFEST_JSON).expect("write manifest");
    socket
}

fn write_blob(socket: &Path, hash: &str, content: &[u8]) {
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(hash), content).expect("write blob");
}

/// Write an archive (`<name>.tar.gz`) under `socket/<subdir>`.
fn write_archive(socket: &Path, subdir: &str, name: &str, content: &[u8]) {
    let dir = socket.join(subdir);
    std::fs::create_dir_all(&dir).expect("create archive dir");
    std::fs::write(dir.join(format!("{name}.tar.gz")), content).expect("write archive");
}

/// A manifest whose single patch carries 12 files with 12 DISTINCT
/// 64-hex afterHashes — enough missing artifacts to overflow both the
/// offline warning's take(5) and the dry-run preview's take(10).
fn write_twelve_file_manifest(root: &Path) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let mut files = serde_json::Map::new();
    for i in 1..=12u32 {
        files.insert(
            format!("package/f{i:02}.js"),
            serde_json::json!({
                "beforeHash": "0".repeat(64),
                "afterHash": format!("{i:02}").repeat(32),
            }),
        );
    }
    let manifest = serde_json::json!({
        "patches": {
            "pkg:npm/__covgap_many__@1.0.0": {
                "uuid": "33333333-3333-4333-8333-333333333333",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": files,
                "vulnerabilities": {},
                "description": "covgap 12-file fixture",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .expect("write manifest");
    socket
}

/// Lines of `s` that carry a truncated missing-artifact id ("  - <12>...").
fn item_lines(s: &str) -> Vec<&str> {
    s.lines().filter(|l| l.starts_with("  - ")).collect()
}

// ---------------------------------------------------------------------------
// Human-mode error prints (loud twins of the covered --json envelopes)
// ---------------------------------------------------------------------------

/// Loud twin of `repair_with_no_manifest_emits_manifest_not_found_envelope`:
/// human mode reports the missing manifest on STDERR (no JSON envelope on
/// stdout) and exits 1, without conjuring a `.socket/` directory.
#[test]
fn repair_manifest_not_found_human_mode_prints_to_stderr() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = socket_cmd(tmp.path())
        .args(["repair", "--offline"])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Manifest not found at"),
        "human mode must report the missing manifest on stderr; stderr=\n{stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "human mode must not emit a JSON envelope on stdout; stdout=\n{stdout}"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "repair on a bare directory must not create .socket/"
    );
}

/// Loud twin of `repair_with_invalid_manifest_emits_repair_failed_envelope`:
/// a `repair_inner` failure (unparseable manifest) prints "Error: {e}" to
/// STDERR in human mode and exits 1, with nothing on stdout.
#[test]
fn repair_failed_human_mode_prints_error_to_stderr() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), "{ not valid json").unwrap();

    let out = socket_cmd(tmp.path())
        .args(["repair", "--offline"])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Error:"),
        "human mode must print the repair failure as 'Error: ...'; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("manifest"),
        "the error must name the manifest parse failure; stderr=\n{stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "the failure path must not print a JSON envelope or progress on \
         stdout; stdout=\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// Human-mode summaries
// ---------------------------------------------------------------------------

/// The loud "All {mode} artifacts are present locally." summary. Every
/// existing loud run used the default diff mode with no `<uuid>.tar.gz`
/// present (always "missing"), and every all-present run was `--json` —
/// so the print never executed. `--download-mode file` with the referenced
/// blob on disk is the all-present shape.
#[test]
fn repair_all_present_human_mode_prints_summary() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    write_blob(&socket, REFERENCED_HASH, b"patched content");

    let out = socket_cmd(tmp.path())
        .args(["repair", "--offline", "--download-mode", "file"])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("All file artifacts are present locally."),
        "the all-present summary must name the requested mode; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Repair complete."),
        "the run must finish with the completion line; stdout=\n{stdout}"
    );
    assert!(
        socket.join("blobs").join(REFERENCED_HASH).exists(),
        "the referenced blob must survive a no-op repair"
    );
}

/// The offline warning lists at most 5 missing ids and folds the rest into
/// "  ... and N more". With 12 missing file artifacts that's 5 items + 7.
#[test]
fn repair_offline_warning_truncates_missing_list_after_five() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_twelve_file_manifest(tmp.path());
    // No blobs on disk → all 12 afterHashes are missing.

    let out = socket_cmd(tmp.path())
        .args(["repair", "--offline", "--download-mode", "file"])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "offline missing artifacts are a warning, not a failure; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Warning: 12 file artifact(s) are missing (offline mode - not downloading)"),
        "the warning header must carry the full missing count; stdout=\n{stdout}"
    );
    let items = item_lines(&stdout);
    assert_eq!(
        items.len(),
        5,
        "the offline warning must list exactly 5 missing ids; stdout=\n{stdout}"
    );
    for item in &items {
        // "  - " + 12 truncated chars + "..." — the ids are 64-hex here.
        assert_eq!(
            item.len(),
            "  - ".len() + 12 + 3,
            "each listed id must be truncated to 12 chars + ellipsis; got {item:?}"
        );
    }
    assert!(
        stdout.contains("  ... and 7 more"),
        "the overflow line must report the remaining 12 - 5 = 7 ids; stdout=\n{stdout}"
    );
}

/// The dry-run preview lists at most 10 missing ids and folds the rest into
/// "  ... and N more". With 12 missing that's 10 items + 2. (No `--offline`:
/// the dry-run branch returns before any download I/O, so the run stays
/// hermetic; telemetry is pinned off explicitly since the run is not
/// airgapped by flag.)
#[test]
fn repair_dry_run_preview_truncates_missing_list_after_ten() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = write_twelve_file_manifest(tmp.path());

    let out = socket_cmd(tmp.path())
        .args(["repair", "--dry-run", "--download-mode", "file"])
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "dry-run preview must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Found 12 missing file artifact(s)"),
        "the online header must carry the full missing count; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Dry run - would download:"),
        "the dry-run preview header must print; stdout=\n{stdout}"
    );
    let items = item_lines(&stdout);
    assert_eq!(
        items.len(),
        10,
        "the dry-run preview must list exactly 10 missing ids; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("  ... and 2 more"),
        "the overflow line must report the remaining 12 - 10 = 2 ids; stdout=\n{stdout}"
    );
    // Dry run downloads nothing: no blobs directory appears.
    assert!(
        !socket.join("blobs").exists(),
        "dry-run must not create or populate .socket/blobs"
    );
}

/// The loud orphan-archive removal print — including the
/// `.replace("blob(s)", "{label} archive(s)")` rewrite of
/// `format_cleanup_result`'s wording, a cross-crate string coupling only a
/// test can pin. One orphan in `diffs/` and one in `packages/`, each next
/// to the referenced `<uuid>.tar.gz` that must survive.
#[test]
fn repair_removes_orphan_archives_human_mode_prints_relabeled_summary() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    write_blob(&socket, REFERENCED_HASH, b"kept");
    // Referenced archives keep the default diff mode's missing-check happy
    // AND must survive the sweep.
    write_archive(&socket, "diffs", REFERENCED_UUID, b"kept-diff");
    write_archive(&socket, "packages", REFERENCED_UUID, b"kept-package");
    const ORPHAN_DIFF: &str = "99999999-9999-4999-8999-999999999999";
    const ORPHAN_PKG: &str = "88888888-8888-4888-8888-888888888888";
    write_archive(&socket, "diffs", ORPHAN_DIFF, b"orphan diff bytes");
    write_archive(&socket, "packages", ORPHAN_PKG, b"orphan pkg bytes");

    let out = socket_cmd(tmp.path())
        .args(["repair", "--offline"])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    // The relabeled summaries: `format_cleanup_result` says
    // "Removed 1 unused blob(s) (...)"; the archive arms must rewrite the
    // noun per directory.
    assert!(
        stdout.contains("Removed 1 unused diff archive(s)"),
        "the diffs sweep must print the relabeled summary; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Removed 1 unused package archive(s)"),
        "the packages sweep must print the relabeled summary; stdout=\n{stdout}"
    );
    assert!(
        !stdout.contains("unused blob(s)"),
        "no archive line may leak the unrelabeled 'blob(s)' wording; stdout=\n{stdout}"
    );
    // Bonus pin: with the referenced diff archive present, the default diff
    // mode takes the all-present branch too.
    assert!(
        stdout.contains("All diff artifacts are present locally."),
        "diff mode with the referenced archive present is all-present; stdout=\n{stdout}"
    );
    // Disk effects: orphans gone, referenced archives intact.
    assert!(
        !socket
            .join("diffs")
            .join(format!("{ORPHAN_DIFF}.tar.gz"))
            .exists(),
        "the orphan diff archive must be swept"
    );
    assert!(
        !socket
            .join("packages")
            .join(format!("{ORPHAN_PKG}.tar.gz"))
            .exists(),
        "the orphan package archive must be swept"
    );
    assert!(socket
        .join("diffs")
        .join(format!("{REFERENCED_UUID}.tar.gz"))
        .exists());
    assert!(socket
        .join("packages")
        .join(format!("{REFERENCED_UUID}.tar.gz"))
        .exists());
}

// ---------------------------------------------------------------------------
// Archive-cleanup failure arm (warn-and-continue)
// ---------------------------------------------------------------------------

/// Archive twin of `repair_cleanup_failure_is_reported_in_json_and_silent_modes`
/// (which only trips the BLOB arm): a failing archive-cleanup pass must warn
/// on stderr in human mode, ride the JSON envelope as a `cleanup_failed`
/// skip, keep exit 0 / status success, and NOT abort the loop — the packages
/// pass still sweeps its orphan after the diffs pass failed.
///
/// Deterministic cross-platform fixture: `.socket/diffs` is a regular FILE,
/// so `cleanup_dir`'s metadata() succeeds (no early return) and read_dir()
/// fails with ENOTDIR.
#[test]
fn repair_archive_cleanup_failure_warns_and_continues() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    write_blob(&socket, REFERENCED_HASH, b"kept");
    std::fs::write(socket.join("diffs"), b"not a dir").expect("stage diffs-as-file");
    const ORPHAN_PKG: &str = "77777777-7777-4777-8777-777777777777";
    write_archive(&socket, "packages", ORPHAN_PKG, b"orphan pkg bytes");
    let orphan_pkg_path = socket.join("packages").join(format!("{ORPHAN_PKG}.tar.gz"));

    // Loud human mode: stderr warning, exit 0, packages pass still ran.
    let loud = socket_cmd(tmp.path())
        .args(["repair", "--offline", "--download-mode", "file"])
        .output()
        .expect("run socket-patch");
    let loud_stdout = String::from_utf8_lossy(&loud.stdout);
    let loud_stderr = String::from_utf8_lossy(&loud.stderr);
    assert_eq!(
        loud.status.code(),
        Some(0),
        "archive-cleanup failure must stay non-fatal; stdout=\n{loud_stdout}\nstderr=\n{loud_stderr}"
    );
    assert!(
        loud_stderr.contains("Warning: diff cleanup failed"),
        "human mode must warn about the failed diff cleanup on stderr; stderr=\n{loud_stderr}"
    );
    assert!(
        stdout_reports_package_sweep(&loud_stdout),
        "the loop must continue to the packages pass after the diffs failure; stdout=\n{loud_stdout}"
    );
    assert!(
        !orphan_pkg_path.exists(),
        "the packages orphan must be swept despite the diffs failure"
    );
    assert!(
        socket.join("diffs").is_file(),
        "the failing cleanup must leave the diffs path untouched"
    );

    // JSON mode: same fixture (re-stage the swept orphan), the failure rides
    // the envelope as an informational skip while status stays success.
    write_archive(&socket, "packages", ORPHAN_PKG, b"orphan pkg bytes");
    let json = socket_cmd(tmp.path())
        .args(["repair", "--json", "--offline", "--download-mode", "file"])
        .output()
        .expect("run socket-patch");
    let json_stdout = String::from_utf8_lossy(&json.stdout);
    assert_eq!(
        json.status.code(),
        Some(0),
        "json: archive-cleanup failure stays non-fatal; stdout=\n{json_stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(json_stdout.trim()).expect("envelope JSON");
    assert_eq!(v["status"], "success");
    let events = v["events"].as_array().expect("events array");
    let skip = events
        .iter()
        .find(|e| e["action"] == "skipped" && e["errorCode"] == "cleanup_failed")
        .unwrap_or_else(|| {
            panic!("json: envelope must record the failed archive cleanup; got events={events:?}")
        });
    assert!(
        skip["reason"].as_str().unwrap_or("").contains("diff cleanup failed"),
        "the skip reason must name the failing archive pass; got {skip}"
    );
    // The packages pass still swept its orphan: one batched removal event.
    assert_eq!(
        v["summary"]["removed"], 1,
        "the packages sweep must still be recorded; envelope={v}"
    );
    assert!(
        !orphan_pkg_path.exists(),
        "json: the packages orphan must be swept despite the diffs failure"
    );
}

/// True when the loud stdout carries the packages sweep summary.
fn stdout_reports_package_sweep(stdout: &str) -> bool {
    stdout.contains("Removed 1 unused package archive(s)")
}

// ---------------------------------------------------------------------------
// Lock-file unlink failure (housekeeping stays non-fatal)
// ---------------------------------------------------------------------------

/// A failed `apply.lock` unlink at the tail of a finished repair is
/// housekeeping: human mode warns on stderr WITHOUT flipping the exit code.
/// Unix-only: unlink needs write on the parent dir, so a 0o555 `.socket`
/// makes the delete fail deterministically while opening the pre-created
/// lock file (no dir write needed) and reading the manifest still work.
/// Same chmod choreography as `repair_cleanup_failure_is_reported_in_json_
/// and_silent_modes` in `repair_invariants.rs` (running as root would let
/// the unlink through and fail this test loudly, not vacuously).
#[cfg(unix)]
#[test]
fn repair_warns_but_exits_zero_when_lock_file_unremovable() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    write_blob(&socket, REFERENCED_HASH, b"kept");
    std::fs::write(socket.join("apply.lock"), b"leftover").expect("stage stale lock");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555))
        .expect("chmod .socket read-only");

    let out = socket_cmd(tmp.path())
        .args(["repair", "--offline", "--download-mode", "file"])
        .output()
        .expect("run socket-patch");

    // Restore write permission FIRST so the tempdir can always be dropped
    // (and the existence probe below runs against a sane dir).
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755))
        .expect("restore .socket permissions");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a failed lock-file delete must not flip the exit code of a \
         finished repair; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Warning: could not remove lock file"),
        "human mode must warn about the undeletable lock file; stderr=\n{stderr}"
    );
    assert!(
        socket.join("apply.lock").exists(),
        "the lock file survives the failed delete"
    );
    assert!(
        stdout.contains("Repair complete."),
        "the repair itself must have finished normally; stdout=\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// Loud vendored-repair summary — "Rebuilt N vendored artifact(s)."
// ---------------------------------------------------------------------------

const UUID: &str = "11111111-1111-4111-8111-111111111111";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";
const AFTER_B64: &str = "YWZ0ZXIK";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ENCODED: &str = "pkg%3Anpm%2Fleft-pad%401.3.0";

/// Vendorable npm project (mirrors `repair_vendor_e2e.rs::write_fixture`).
fn write_vendor_fixture(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-repair-vendor", "version": "0.0.0" }"#,
    )
    .unwrap();
    let lock = serde_json::json!({
        "name": "covgap-repair-vendor",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "covgap-repair-vendor",
                "version": "0.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig==",
                "license": "WTFPL"
            }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), lock_bytes).unwrap();

    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

/// Mount discovery + view for `UUID` (mirrors `repair_vendor_e2e.rs`).
async fn mount_patch_api(mock: &MockServer) {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID,
                    "purl": PURL,
                    "tier": "free",
                    "cveIds": ["CVE-2026-0001"],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "vendor target"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{ENCODED}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "Vendor patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": AFTER_B64,
                }
            },
            "vulnerabilities": {
                "GHSA-aaaa-bbbb-cccc": {
                    "cves": ["CVE-2026-0001"],
                    "summary": "test vuln",
                    "severity": "high",
                    "description": "details"
                }
            },
            "description": "Vendor patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// Run the CLI against the mock API. `json` toggles the `--json` flag —
/// the loud variant is exactly what `repair_vendor_e2e.rs`'s hardcoded
/// `--json` helper could never produce.
fn run_cli(root: &Path, mock_uri: &str, argv: &[&str], json: bool) -> (i32, String, String) {
    let mut cmd = socket_cmd(root);
    cmd.args(argv);
    if json {
        cmd.arg("--json");
    }
    cmd.args(["--api-url", mock_uri, "--api-token", "fake-token", "--org", ORG_SLUG]);
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The loud "Rebuilt N vendored artifact(s)." summary after the
/// vendored-repair phase — uncovered only because the sibling e2e suite
/// drives every repair through `--json`. Reuses the hermetic
/// offline-rebuild fixture (installed copy + seeded after-blob), so the
/// repair itself makes zero network requests.
#[tokio::test]
async fn repair_offline_rebuild_human_mode_prints_rebuilt_summary() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vendor_fixture(tmp.path());

    // Establish the vendored project (network allowed for setup only).
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["scan", "--vendor", "--yes"],
        true,
    );
    assert_eq!(code, 0, "vendor setup failed: stdout={stdout} stderr={stderr}");
    let tgz = tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
    assert!(tgz.is_file(), "setup must vendor the tarball");

    std::fs::remove_file(&tgz).unwrap();
    // Patch content available locally: the after-blob on disk.
    let blobs = tmp.path().join(".socket/blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(git_sha256(AFTER)), AFTER).unwrap();

    let before_reqs = mock.received_requests().await.unwrap().len();
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"], false);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert!(
        stdout.contains("Rebuilt 1 vendored artifact(s)."),
        "the loud run must print the vendored-rebuild summary; stdout=\n{stdout}"
    );
    assert!(tgz.is_file(), "the tarball was rebuilt offline");
    let after_reqs = mock.received_requests().await.unwrap().len();
    assert_eq!(
        before_reqs, after_reqs,
        "--offline repair must make no network requests"
    );
}
