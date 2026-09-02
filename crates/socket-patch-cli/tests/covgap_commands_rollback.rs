//! Coverage-gap tests for `commands/rollback.rs` (2026-09 audit).
//!
//! Five themes the existing rollback suites never exercised:
//!
//!   1. HUMAN-mode output — nearly every prior rollback test runs `--json`
//!      or `--silent`, so the dry-run summary, wet-run messages, verbose
//!      per-file details, preserve-state closing message, and the
//!      error-class stderr notices had never rendered;
//!   2. failure legs of the vendored and hosted rollback (unknown-backend
//!      revert failure, ledger save/persist failure, replay refusal,
//!      per-purl revert I/O failure, corrupt ledgers);
//!   3. scope plumbing gaps (path globs selecting vendored/hosted entries,
//!      `--ecosystems` narrowing both non-manifest legs, the multi-copy
//!      out-of-scope warning);
//!   4. the interactive confirm DECLINE (PTY-driven, like
//!      `interactive_prompts_e2e.rs`);
//!   5. boundary error envelopes (corrupt manifest, blobs-path-is-a-file
//!      legacy error shape, lock contention).
//!
//! Binary-driven throughout (the `rollback_duality_invariants.rs` shape):
//! `SOCKET_*`-scrubbed child processes via `common::run`, hand-written
//! camelCase manifests, git-sha256 oracle, `--offline` everywhere. Hosted
//! ledgers are serialized through the real `RedirectState`/`FileEdit`
//! types so fixtures can never drift from the on-disk schema (the
//! `in_process_rollback_hosted.rs` convention).

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord};
use socket_patch_core::patch::redirect::{FileEdit, RedirectState};

#[path = "common/mod.rs"]
mod common;

use common::{envelope_error_code, git_sha256, json_string, run};

// ───────────────────────── shared fixture helpers ─────────────────────────

/// One hand-written camelCase manifest entry (single `package/index.js`
/// file row), matching the TS-compatible on-disk schema.
fn manifest_entry(purl: &str, uuid: &str, before_hash: &str, after_hash: &str) -> String {
    format!(
        r#""{purl}": {{
      "uuid": "{uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{before_hash}",
          "afterHash": "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "synthetic covgap test patch",
      "license": "MIT",
      "tier": "free"
    }}"#
    )
}

/// Write `.socket/manifest.json` from pre-rendered entries; returns the
/// `.socket` dir.
fn write_socket_manifest(root: &Path, entries: &[String]) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let patches = entries.join(",\n    ");
    std::fs::write(
        socket.join("manifest.json"),
        format!("{{\n  \"patches\": {{\n    {patches}\n  }}\n}}"),
    )
    .expect("write manifest");
    socket
}

/// Install a fake npm package at `<root>/<nm_rel>/<name>` with the given
/// `index.js` bytes and version.
fn install_npm_pkg(root: &Path, nm_rel: &str, name: &str, version: &str, index_js: &[u8]) -> PathBuf {
    let pkg_dir = root.join(nm_rel).join(name);
    std::fs::create_dir_all(&pkg_dir).expect("create package dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .expect("write package.json");
    std::fs::write(pkg_dir.join("index.js"), index_js).expect("write index.js");
    pkg_dir
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-rollback-root", "version": "0.0.0" }"#,
    )
    .expect("write root package.json");
}

fn stage_blob(socket: &Path, hash: &str, content: &[u8]) {
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(hash), content).expect("stage blob");
}

/// Stage `<uuid>.tar.gz` in both archive stores so the GC has something
/// sweepable to preview/free.
fn stage_archives(socket: &Path, uuid: &str) {
    for dir in ["diffs", "packages"] {
        let path = socket.join(dir).join(format!("{uuid}.tar.gz"));
        std::fs::create_dir_all(path.parent().expect("archive path has a parent"))
            .expect("create archive dir");
        std::fs::write(path, b"synthetic-archive-bytes").expect("stage archive");
    }
}

/// The `code` field of every run-level warning in a rollback envelope.
fn warning_codes(envelope: &Value) -> Vec<String> {
    envelope["warnings"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|w| w["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_envelope(stdout: &str, stderr: &str) -> Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| {
        panic!("rollback --json must emit a JSON envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    })
}

/// The default single-package patched fixture: an installed npm package
/// whose `index.js` holds the PATCHED bytes, one manifest entry, both
/// blobs staged, both archives staged.
struct PatchedFixture {
    root: tempfile::TempDir,
    socket: PathBuf,
    pkg_dir: PathBuf,
    purl: &'static str,
    before: &'static [u8],
    after: &'static [u8],
    before_hash: String,
    after_hash: String,
}

fn patched_fixture() -> PatchedFixture {
    let before: &[u8] = b"covgap-original-content\n";
    let after: &[u8] = b"covgap-patched-content\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);
    let purl = "pkg:npm/covgap-target@1.0.0";
    let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    let root = tempfile::tempdir().expect("tempdir");
    write_root_package_json(root.path());
    let pkg_dir = install_npm_pkg(root.path(), "node_modules", "covgap-target", "1.0.0", after);
    let socket = write_socket_manifest(
        root.path(),
        &[manifest_entry(purl, uuid, &before_hash, &after_hash)],
    );
    stage_blob(&socket, &before_hash, before);
    stage_blob(&socket, &after_hash, after);
    stage_archives(&socket, uuid);

    PatchedFixture {
        root,
        socket,
        pkg_dir,
        purl,
        before,
        after,
        before_hash,
        after_hash,
    }
}

/// Restore a directory's mode on drop, so a failed assertion never leaks a
/// read-only tree into TMPDIR.
#[cfg(unix)]
struct DirModeGuard {
    path: PathBuf,
    restore_mode: u32,
}

#[cfg(unix)]
impl DirModeGuard {
    fn chmod(path: &Path, mode: u32, restore_mode: u32) -> Self {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("chmod fixture dir");
        Self {
            path: path.to_path_buf(),
            restore_mode,
        }
    }
    fn restore(&self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &self.path,
            std::fs::Permissions::from_mode(self.restore_mode),
        );
    }
}

#[cfg(unix)]
impl Drop for DirModeGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Probe whether permission bits are enforced for this process; root (or
/// CAP_DAC_OVERRIDE containers) bypasses them, making read-only-dir tests
/// fail spuriously. Returns false (and logs a skip) when they are not.
#[cfg(unix)]
fn readonly_dir_enforced(dir: &Path) -> bool {
    let probe = dir.join(".covgap-write-probe");
    if std::fs::write(&probe, b"x").is_ok() {
        let _ = std::fs::remove_file(&probe);
        eprintln!("skipping: permission bits not enforced (running as root?)");
        return false;
    }
    true
}

/// Spawn the binary WITHOUT waiting (the lock-choreography tests mutate
/// the fixture while the child is blocked on the apply lock), with the
/// exact same seed-then-scrub environment as `common::run`.
fn spawn_scrubbed(cwd: &Path, args: &[&str]) -> std::process::Child {
    let mut cmd = std::process::Command::new(common::binary());
    cmd.args(args).current_dir(cwd);
    cmd.env("SOCKET_GLOBAL", "true")
        .env("SOCKET_GLOBAL_PREFIX", "/nonexistent")
        .env("SOCKET_DRY_RUN", "true")
        .env("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json")
        .env("SOCKET_JSON", "true")
        .env("SOCKET_SILENT", "true")
        .env("SOCKET_VERBOSE", "true")
        .env_remove("SOCKET_GLOBAL")
        .env_remove("SOCKET_GLOBAL_PREFIX")
        .env_remove("SOCKET_DRY_RUN")
        .env_remove("SOCKET_MANIFEST_PATH")
        .env_remove("SOCKET_JSON")
        .env_remove("SOCKET_SILENT")
        .env_remove("SOCKET_VERBOSE")
        .env_remove("SOCKET_API_TOKEN");
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_")
            && !name.contains("TELEMETRY")
            && name != "SOCKET_NO_CONFIG"
            && name != "SOCKET_NO_UPDATE_CHECK"
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_NO_CONFIG", "1");
    cmd.env("SOCKET_NO_UPDATE_CHECK", "1");
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd.spawn().expect("spawn socket-patch binary")
}

// ═══════════════════════ 1. human-mode output pass ════════════════════════

/// The HUMAN dry-run summary (`--dry-run` with no `--json`): the
/// verification header, the can-rollback count, the would-be manifest
/// removal block, and the "Would free" GC preview — none of which any
/// `--json` dry-run test renders. Nothing may be mutated.
#[test]
fn human_dry_run_summary_lists_counts_and_would_free() {
    let fx = patched_fixture();
    let manifest_before =
        std::fs::read(fx.socket.join("manifest.json")).expect("read manifest bytes");

    let (code, stdout, stderr) = run(fx.root.path(), &["rollback", "--dry-run", "--offline"]);
    assert_eq!(
        code, 0,
        "human dry run must exit 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Rollback verification complete:"),
        "the dry-run header must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 package(s) can be rolled back"),
        "the can-rollback count must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Would remove 1 patch(es) from manifest:")
            && stdout.contains(&format!("  - {}", fx.purl)),
        "the would-be manifest removal must be previewed; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Would free") && stdout.contains("bytes of unused blobs/archives"),
        "the GC preview must print its would-free line; stdout=\n{stdout}"
    );

    // Disk untouched.
    assert_eq!(
        std::fs::read(fx.pkg_dir.join("index.js")).expect("read installed file"),
        fx.after,
        "dry run must not restore the file"
    );
    assert_eq!(
        std::fs::read(fx.socket.join("manifest.json")).expect("manifest exists"),
        manifest_before,
        "dry run must leave the manifest byte-identical"
    );
}

/// Wet human run over one already-original entry plus one not-installed
/// entry: the "(already original)" line prints on stdout and the
/// not-installed warning block prints on stderr — and the run still
/// exits 0 (per-package semantics).
#[test]
fn human_wet_reports_already_original_and_not_installed() {
    let before: &[u8] = b"already-orig-original\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(b"already-orig-patched\n");
    let purl = "pkg:npm/already-orig@1.0.0";
    let ghost_purl = "pkg:npm/covgap-ghost@2.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // Installed at the BEFORE bytes: rollback is a no-op for it.
    install_npm_pkg(tmp.path(), "node_modules", "already-orig", "1.0.0", before);
    write_socket_manifest(
        tmp.path(),
        &[
            manifest_entry(
                purl,
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                &before_hash,
                &after_hash,
            ),
            manifest_entry(
                ghost_purl,
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                &git_sha256(b"ghost-original\n"),
                &git_sha256(b"ghost-patched\n"),
            ),
        ],
    );

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes"]);
    assert_eq!(
        code, 0,
        "already-original + not-installed exits 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Rolled back packages:")
            && stdout.contains(&format!("  {purl} (already original)")),
        "the no-op must print its '(already original)' line; stdout=\n{stdout}"
    );
    assert!(
        stderr.contains("Warning: 1 manifest patch(es) had no matching installed package:")
            && stderr.contains(&format!("  - {ghost_purl}")),
        "the not-installed warning block must print on stderr; stderr=\n{stderr}"
    );
}

/// `--verbose` per-file details on a hash-mismatch failure: the humanized
/// `[hash mismatch]` label plus the `message:` and `expected:` lines
/// (populated exactly on this status) — and the wet "Failed to rollback:"
/// section with exit 1.
#[test]
fn human_verbose_hash_mismatch_details() {
    let before: &[u8] = b"mismatch-original\n";
    let after: &[u8] = b"mismatch-patched\n";
    let drifted: &[u8] = b"locally drifted content\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);
    let purl = "pkg:npm/covgap-drifted@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    let pkg_dir = install_npm_pkg(tmp.path(), "node_modules", "covgap-drifted", "1.0.0", drifted);
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            purl,
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            &before_hash,
            &after_hash,
        )],
    );
    // Before-blob staged so the missing-blob gate never trips: the failure
    // under test is the engine's hash-mismatch verification.
    stage_blob(&socket, &before_hash, before);

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["rollback", "--offline", "--yes", "--verbose"],
    );
    assert_eq!(
        code, 1,
        "a hash mismatch must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Failed to rollback:") && stdout.contains(purl),
        "the wet failure section must name the package; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Detailed verification:"),
        "--verbose must print the details header; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("[hash mismatch]"),
        "the humanized status label must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("message: File has been modified after patching"),
        "the verbose message line must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("expected: {after_hash}")),
        "the verbose expected-hash line must print; stdout=\n{stdout}"
    );

    // Fail-closed: file untouched, manifest entry retained.
    assert_eq!(
        std::fs::read(pkg_dir.join("index.js")).expect("read file"),
        drifted,
        "a mismatched file must never be overwritten"
    );
    let m: Value = serde_json::from_str(
        &std::fs::read_to_string(socket.join("manifest.json")).expect("manifest exists"),
    )
    .expect("valid manifest JSON");
    assert!(
        m["patches"].get(purl).is_some(),
        "a failed entry must stay in the manifest; manifest={m}"
    );
}

/// The human `--preserve-state` closing message — every prior
/// preserve-state test runs `--json`.
#[test]
fn human_preserve_state_closing_message() {
    let fx = patched_fixture();
    let manifest_before =
        std::fs::read(fx.socket.join("manifest.json")).expect("read manifest bytes");

    let (code, stdout, stderr) = run(
        fx.root.path(),
        &["rollback", "--offline", "--preserve-state"],
    );
    assert_eq!(
        code, 0,
        "preserve-state rollback exits 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Manifest entries and vendored artifacts preserved"),
        "the preserve-state closing message must print; stdout=\n{stdout}"
    );
    // The system IS restored, the state is NOT.
    assert_eq!(
        std::fs::read(fx.pkg_dir.join("index.js")).expect("read restored file"),
        fx.before,
        "the file restore still happens under --preserve-state"
    );
    assert_eq!(
        std::fs::read(fx.socket.join("manifest.json")).expect("manifest exists"),
        manifest_before,
        "--preserve-state must not rewrite the manifest"
    );
}

/// A syntactically-invalid manifest drives the legacy top-level error in
/// BOTH output modes: `{status: "error", error}` on `--json` and an
/// `Error:` stderr line otherwise, exit 1 either way.
#[test]
fn corrupt_manifest_json_errors_in_both_modes() {
    // ── --json ──
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), b"{ not json").expect("write corrupt manifest");

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline"]);
    assert_eq!(
        code, 1,
        "a corrupt manifest must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "error", "stdout=\n{stdout}");
    assert!(
        v["error"]
            .as_str()
            .is_some_and(|e| e.contains("Failed to parse manifest JSON")),
        "the error must name the parse failure; stdout=\n{stdout}"
    );

    // ── human ──
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), b"{ not json").expect("write corrupt manifest");

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline"]);
    assert_eq!(
        code, 1,
        "human mode exits 1 too; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Error:") && stderr.contains("Failed to parse manifest JSON"),
        "the human error must print on stderr; stderr=\n{stderr}"
    );
}

/// `.socket/blobs` existing as a regular FILE makes the inner pipeline's
/// `create_dir_all` fail — the boundary maps that to the legacy
/// `{status: "error", rolledBack: 0, vendored: [], results: []}` envelope
/// (and a bare `Error:` stderr line in human mode), exit 1.
#[test]
fn blobs_path_as_file_yields_legacy_error_envelope() {
    let build = || {
        let before_hash = git_sha256(b"blobfile-original\n");
        let after_hash = git_sha256(b"blobfile-patched\n");
        let tmp = tempfile::tempdir().expect("tempdir");
        let socket = write_socket_manifest(
            tmp.path(),
            &[manifest_entry(
                "pkg:npm/covgap-blobfile@1.0.0",
                "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
                &before_hash,
                &after_hash,
            )],
        );
        // The blobs path is a regular FILE, so create_dir_all must fail.
        std::fs::write(socket.join("blobs"), b"not a directory").expect("write blobs file");
        tmp
    };

    // ── --json: legacy error envelope shape ──
    let tmp = build();
    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "the inner Err must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "error", "stdout=\n{stdout}");
    assert!(
        v["error"].as_str().is_some_and(|e| !e.is_empty()),
        "the envelope carries the io error; stdout=\n{stdout}"
    );
    assert_eq!(v["rolledBack"], 0, "stdout=\n{stdout}");
    assert_eq!(v["failed"], 0, "stdout=\n{stdout}");
    assert_eq!(v["vendored"], json!([]), "stdout=\n{stdout}");
    assert_eq!(v["results"], json!([]), "stdout=\n{stdout}");

    // ── human: bare Error line ──
    let tmp = build();
    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes"]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("Error:"),
        "the human boundary error must print on stderr; stderr=\n{stderr}"
    );
}

/// Multi-copy contract meets path scoping: rollback restores EVERY
/// installed copy of a selected patch, and when some restored copy lives
/// outside the given paths the run says so via the
/// `out_of_scope_copies_restored` warning (singular grammar pinned).
#[test]
fn path_scope_warns_about_out_of_scope_restored_copies() {
    let before: &[u8] = b"dup-original\n";
    let after: &[u8] = b"dup-patched\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);
    let purl = "pkg:npm/covgap-dup@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // The SAME name@version installed twice: root + nested workspace copy.
    let root_copy = install_npm_pkg(tmp.path(), "node_modules", "covgap-dup", "1.0.0", after);
    let nested_copy = install_npm_pkg(
        tmp.path(),
        "packages/app/node_modules",
        "covgap-dup",
        "1.0.0",
        after,
    );
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            purl,
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            &before_hash,
            &after_hash,
        )],
    );
    stage_blob(&socket, &before_hash, before);
    stage_blob(&socket, &after_hash, after);

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["rollback", "--json", "--offline", "--yes", "packages/app"],
    );
    assert_eq!(
        code, 0,
        "the path-scoped multi-copy rollback succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");

    // BOTH copies are restored (patches are per-package, not per-path)...
    assert_eq!(
        std::fs::read(nested_copy.join("index.js")).expect("read nested copy"),
        before,
        "the in-scope copy must be restored"
    );
    assert_eq!(
        std::fs::read(root_copy.join("index.js")).expect("read root copy"),
        before,
        "the out-of-scope copy must be restored too (multi-copy contract)"
    );

    // ...and the out-of-scope restore is surfaced, singular grammar intact.
    let warning = v["warnings"]
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|w| w["code"] == "out_of_scope_copies_restored")
        })
        .unwrap_or_else(|| panic!("out_of_scope_copies_restored must be warned; stdout=\n{stdout}"))
        .clone();
    assert!(
        warning["detail"]
            .as_str()
            .is_some_and(|d| d.contains("1 restored copy lives")),
        "the singular grammar must hold; stdout=\n{stdout}"
    );
    assert_eq!(
        v["manifest"]["removedEntries"],
        json!([purl]),
        "the fully-restored patch leaves the manifest; stdout=\n{stdout}"
    );
}

/// Ledger-less but still WIRED: a lockfile that consumes `.socket/vendor/`
/// artifacts with NO ledger and NO manifest is a supported recovery state —
/// rollback must refuse with the `socket-patch repair` guidance (exit 1),
/// never fall through to the bare "Manifest not found" error, and must not
/// touch the wired lock.
#[test]
fn ledgerless_wired_lock_errors_with_repair_guidance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // A v3 package-lock whose resolution points into `.socket/vendor/` —
    // exactly what a deleted/uncommitted state.json leaves behind.
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": { "name": "fixture", "version": "1.0.0" },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": format!("file:.socket/vendor/npm/{V_UUID}/left-pad-1.3.0.tgz")
            }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(tmp.path().join("package-lock.json"), &lock_bytes).unwrap();

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "the recovery state must refuse; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "error", "stdout=\n{stdout}");
    assert!(
        v["error"].as_str().is_some_and(|e| {
            e.contains("lockfiles still reference .socket/vendor/ artifacts")
                && e.contains("socket-patch repair")
        }),
        "the error must carry the repair guidance, not 'Manifest not found'; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_bytes,
        "the wired lock must be untouched"
    );
}

/// Lock contention: rollback against an externally-held `.socket/apply.lock`
/// exits 1 with the shared `lock_held` error envelope (command `rollback`).
#[test]
fn lock_contention_exits_with_lock_held_envelope() {
    use fs2::FileExt;

    let before_hash = git_sha256(b"lock-original\n");
    let after_hash = git_sha256(b"lock-patched\n");
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            "pkg:npm/covgap-locked@1.0.0",
            "11111111-1111-4111-8111-111111111111",
            &before_hash,
            &after_hash,
        )],
    );

    // Hold the binary's lock for the duration of the test (the
    // e2e_safety_lock.rs pattern: same crate, same path, real flock).
    let lock_path = socket.join("apply.lock");
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open lock file");
    lock_file
        .try_lock_exclusive()
        .expect("test could not take the initial lock");

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "lock contention must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(
        envelope_error_code(&v),
        Some("lock_held"),
        "expected errorCode=lock_held; stdout=\n{stdout}"
    );
    assert_eq!(json_string(&v, "status"), Some("error"), "stdout=\n{stdout}");
    assert_eq!(
        json_string(&v, "command"),
        Some("rollback"),
        "the envelope must name the rollback command; stdout=\n{stdout}"
    );
    drop(lock_file);
}

// ═════════════════════════ 2. vendored-leg gaps ════════════════════════════

const V_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const V_PURL: &str = "pkg:npm/left-pad@1.3.0";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

/// One self-contained npm project ready to `vendor`: root package.json, a
/// v3 package-lock with a registry-resolved `left-pad`, the installed
/// package, and a `.socket/` manifest + after-hash blob (offline source) —
/// the `in_process_rollback_vendored.rs` fixture, subprocess-driven.
struct VendorFixture {
    tmp: tempfile::TempDir,
    original_lock: Vec<u8>,
}

impl VendorFixture {
    fn root(&self) -> &Path {
        self.tmp.path()
    }
    fn lock_bytes(&self) -> Vec<u8> {
        std::fs::read(self.root().join("package-lock.json")).expect("read package-lock.json")
    }
    fn state_path(&self) -> PathBuf {
        self.root().join(".socket/vendor/state.json")
    }
    fn tgz_path(&self) -> PathBuf {
        self.root()
            .join(format!(".socket/vendor/npm/{V_UUID}/left-pad-1.3.0.tgz"))
    }
    fn manifest_json(&self) -> Value {
        serde_json::from_slice(
            &std::fs::read(self.root().join(".socket/manifest.json")).expect("read manifest"),
        )
        .expect("manifest is JSON")
    }
}

fn vendor_fixture() -> VendorFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();

    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "fixture",
                "version": "1.0.0",
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
    let mut original_lock = serde_json::to_vec_pretty(&lock).unwrap();
    original_lock.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &original_lock).unwrap();

    let before_hash = git_sha256(ORIG_INDEX);
    let after_hash = git_sha256(PATCHED_INDEX);
    let manifest = json!({
        "patches": {
            V_PURL: {
                "uuid": V_UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "package/index.js": { "beforeHash": before_hash, "afterHash": after_hash }
                },
                "vulnerabilities": {},
                "description": "synthetic vendored covgap patch",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    manifest_bytes.push(b'\n');
    std::fs::write(socket.join("manifest.json"), &manifest_bytes).unwrap();
    std::fs::write(socket.join("blobs").join(&after_hash), PATCHED_INDEX).unwrap();

    VendorFixture { tmp, original_lock }
}

/// Vendor the fixture through the binary (offline, staged blob source).
fn vendor(fx: &VendorFixture) {
    let (code, stdout, stderr) = run(
        fx.root(),
        &["vendor", "--json", "--silent", "--offline", "--lock-timeout", "5"],
    );
    assert_eq!(
        code, 0,
        "fixture vendor must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert_ne!(
        fx.lock_bytes(),
        fx.original_lock,
        "sanity: vendor must rewire the lock"
    );
    assert!(fx.tgz_path().is_file(), "sanity: artifact written");
}

/// A ledger entry whose ecosystem has no vendor backend in this build
/// fails the vendored leg: exit 1, the purl + error in `vendoredFailed`
/// (JSON), the "Failed to revert vendoring" stderr line (human), and the
/// manifest entry retained (fail-closed cleanup).
#[test]
fn vendored_unknown_ecosystem_fails_leg_in_both_modes() {
    let rewrite_ecosystem = |fx: &VendorFixture| {
        let mut state: Value =
            serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap()).unwrap();
        state["entries"][V_PURL]["ecosystem"] = json!("brew");
        std::fs::write(fx.state_path(), serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    };

    // ── --json ──
    let fx = vendor_fixture();
    vendor(&fx);
    rewrite_ecosystem(&fx);
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "an unknown-backend entry must fail the run; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "partial_failure", "stdout=\n{stdout}");
    let failed = v["vendoredFailed"]
        .as_array()
        .expect("vendoredFailed array");
    assert_eq!(failed.len(), 1, "stdout=\n{stdout}");
    assert_eq!(failed[0]["purl"], V_PURL, "stdout=\n{stdout}");
    assert!(
        failed[0]["error"]
            .as_str()
            .is_some_and(|e| e.contains("no vendor backend for ecosystem `brew`")),
        "the error must name the missing backend; stdout=\n{stdout}"
    );
    assert!(
        fx.manifest_json()["patches"].get(V_PURL).is_some(),
        "a failed vendored purl's manifest entry must be retained"
    );

    // ── human ──
    let fx = vendor_fixture();
    vendor(&fx);
    rewrite_ecosystem(&fx);
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--offline", "--yes"]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains(&format!("Failed to revert vendoring for {V_PURL}")),
        "the human failure line must print on stderr; stderr=\n{stderr}"
    );
}

/// Human dry-run previews of the vendored leg: "Would revert vendoring"
/// (default) and "Would unwire … (artifact preserved)" (--preserve-state),
/// with lock, ledger, and artifact all untouched.
#[test]
fn vendored_dry_run_previews_in_human_mode() {
    let fx = vendor_fixture();
    vendor(&fx);
    let wired_lock = fx.lock_bytes();
    let state_before = std::fs::read(fx.state_path()).unwrap();

    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--offline", "--dry-run"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!("Would revert vendoring for {V_PURL}")),
        "the default preview line must print; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), wired_lock, "dry run must not touch the lock");
    assert_eq!(
        std::fs::read(fx.state_path()).unwrap(),
        state_before,
        "dry run must not touch the ledger"
    );
    assert!(fx.tgz_path().is_file(), "dry run must keep the artifact");

    let (code, stdout, stderr) = run(
        fx.root(),
        &["rollback", "--offline", "--dry-run", "--preserve-state"],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "Would unwire vendoring for {V_PURL} (artifact preserved)"
        )),
        "the preserve-state preview line must print; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), wired_lock, "still untouched");
    assert!(fx.tgz_path().is_file(), "still kept");
}

/// Wet human-mode vendored messages: "Reverted vendoring for {key}" plus
/// the reinstall note on the default run, and "Unwired vendoring for {key}
/// (artifact preserved)" under --preserve-state.
#[test]
fn vendored_wet_human_messages() {
    // ── default: revert ──
    let fx = vendor_fixture();
    vendor(&fx);
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--offline", "--yes"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!("Reverted vendoring for {V_PURL}")),
        "the wet revert line must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("unwired packages keep their patched bytes"),
        "the reinstall note must print; stdout=\n{stdout}"
    );
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "the lock must be restored byte-for-byte"
    );
    assert!(!fx.tgz_path().exists(), "the artifact must be deleted");

    // ── --preserve-state: unwire ──
    let fx = vendor_fixture();
    vendor(&fx);
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--offline", "--preserve-state"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "Unwired vendoring for {V_PURL} (artifact preserved)"
        )),
        "the preserve-state wet line must print; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
    assert!(fx.tgz_path().is_file(), "artifact kept");
    assert!(fx.state_path().is_file(), "ledger entry kept");
}

/// `--ecosystems` narrows the vendored leg: a pypi-scoped run leaves the
/// npm entry (wiring, ledger, artifact all intact), an npm-scoped run
/// reverts it.
#[test]
fn ecosystems_filter_narrows_vendored_scope() {
    let fx = vendor_fixture();
    vendor(&fx);
    let wired_lock = fx.lock_bytes();

    let (code, stdout, stderr) = run(
        fx.root(),
        &["rollback", "--json", "--offline", "--yes", "--ecosystems", "pypi"],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(
        v["vendoredReverted"],
        json!([]),
        "a pypi-scoped run must not revert the npm entry; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), wired_lock, "the wiring must survive");
    assert!(fx.tgz_path().is_file(), "the artifact must survive");
    assert!(fx.state_path().is_file(), "the ledger must survive");

    let (code, stdout, stderr) = run(
        fx.root(),
        &["rollback", "--json", "--offline", "--yes", "--ecosystems", "npm"],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(
        v["vendoredReverted"],
        json!([V_PURL]),
        "the npm-scoped run must revert it; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
}

/// A corrupt vendor ledger fails ONLY the legs that need it: the run exits
/// 1 with the `vendor_state_unreadable` warning (JSON) / `Error
/// (vendor_state_unreadable):` stderr notice (human), manifest cleanup and
/// GC are skipped fail-closed, and the garbage ledger is left in place.
#[test]
fn corrupt_vendor_ledger_warns_and_fails_in_both_modes() {
    let corrupt = |fx: &VendorFixture| {
        std::fs::create_dir_all(fx.root().join(".socket/vendor")).unwrap();
        std::fs::write(fx.state_path(), b"garbage not json").unwrap();
    };

    // ── --json ── (NOT vendored: the installed tree is already original,
    // so the agent leg is a clean no-op and the exit-1 is the corrupt
    // ledger alone.)
    let fx = vendor_fixture();
    corrupt(&fx);
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "a corrupt vendor ledger must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "partial_failure", "stdout=\n{stdout}");
    assert!(
        warning_codes(&v).contains(&"vendor_state_unreadable".to_string()),
        "the warning must be surfaced; stdout=\n{stdout}"
    );
    assert_eq!(
        v["gc"],
        json!({ "skipped": true }),
        "GC must be skipped fail-closed; stdout=\n{stdout}"
    );
    assert_eq!(
        v["manifest"]["removedEntries"],
        json!([]),
        "manifest cleanup must be skipped fail-closed; stdout=\n{stdout}"
    );
    assert!(
        fx.manifest_json()["patches"].get(V_PURL).is_some(),
        "the manifest entry must survive"
    );
    assert_eq!(
        std::fs::read(fx.state_path()).unwrap(),
        b"garbage not json",
        "the corrupt ledger must be left in place for quarantine"
    );

    // ── human ──
    let fx = vendor_fixture();
    corrupt(&fx);
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--offline", "--yes"]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("Error (vendor_state_unreadable):"),
        "the error-class notice must print on stderr; stderr=\n{stderr}"
    );
}

/// A path-shaped target selects a VENDORED entry through its installed
/// copy: `rollback node_modules/left-pad` reverts the vendored state.
#[test]
fn path_glob_selects_vendored_entry() {
    let fx = vendor_fixture();
    vendor(&fx);

    let (code, stdout, stderr) = run(
        fx.root(),
        &["rollback", "--json", "--offline", "--yes", "node_modules/left-pad"],
    );
    assert_eq!(
        code, 0,
        "the path-scoped vendored rollback succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(
        v["vendoredReverted"],
        json!([V_PURL]),
        "the path target must select the vendored entry; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
    assert!(!fx.tgz_path().exists(), "artifact deleted");
}

/// The human drift-keep notice: a vendored entry whose wiring matches
/// nothing in the live lock is kept, and the error-class "Kept vendored
/// state for …" line prints on stderr with exit 1.
#[test]
fn drift_keep_prints_human_notice() {
    const DRIFT_PURL: &str = "pkg:npm/__covgap_drift_kept__@1.0.0";
    const DRIFT_UUID: &str = "33333333-3333-4333-8333-333333333333";

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": { "": { "name": "fixture", "version": "1.0.0" } }
    });
    let mut original_lock = serde_json::to_vec_pretty(&lock).unwrap();
    original_lock.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &original_lock).unwrap();

    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let original_manifest = format!(
        r#"{{
  "patches": {{
    "{DRIFT_PURL}": {{
      "uuid": "{DRIFT_UUID}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "synthetic drift-keep fixture",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), &original_manifest).unwrap();

    // Ledger wired with a fragment the lock does not contain (the
    // in_process_rollback_vendored.rs drift shape).
    let artifact_dir = socket.join("vendor/npm").join(DRIFT_UUID);
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join("package.tgz"), b"tgz").unwrap();
    let original_state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{DRIFT_PURL}": {{
      "ecosystem": "npm",
      "basePurl": "{DRIFT_PURL}",
      "uuid": "{DRIFT_UUID}",
      "artifact": {{ "path": ".socket/vendor/npm/{DRIFT_UUID}/package.tgz" }},
      "wiring": [{{ "file": "weird.txt", "kind": "npm_lock_entry", "action": "added", "key": "node_modules/x" }}]
    }}
  }}
}}"#
    );
    let state_path = socket.join("vendor/state.json");
    std::fs::write(&state_path, &original_state).unwrap();

    let (code, stdout, stderr) = run(root, &["rollback", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "a drift-keep exits partial_failure; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("Kept vendored state for {DRIFT_PURL}"))
            && stderr.contains("drifted"),
        "the drift-keep notice must print on stderr; stderr=\n{stderr}"
    );
    assert_eq!(
        std::fs::read(&state_path).unwrap(),
        original_state.as_bytes(),
        "the drift-kept ledger must survive byte-identical"
    );
    assert_eq!(
        std::fs::read(socket.join("manifest.json")).unwrap(),
        original_manifest.as_bytes(),
        "the manifest entry must survive a drift-keep"
    );
}

/// A vendor-ledger SAVE failure after a successful revert (the artifact is
/// already gone, the entry already removed in memory): the purl lands in
/// `vendoredFailed` with the "vendor ledger write failed" error, the run
/// exits 1, and the manifest entry is retained.
#[cfg(unix)]
#[test]
fn vendored_ledger_save_failure_fails_closed() {
    let fx = vendor_fixture();
    vendor(&fx);

    // Read-only `.socket/vendor`: the revert itself succeeds (the lock is
    // at the project root and the artifact lives in a writable uuid dir),
    // but `save_state`'s emptied-ledger unlink of state.json fails.
    let vendor_dir = fx.root().join(".socket/vendor");
    let guard = DirModeGuard::chmod(&vendor_dir, 0o555, 0o755);
    if !readonly_dir_enforced(&vendor_dir) {
        return;
    }

    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--json", "--offline", "--yes"]);
    guard.restore();

    assert_eq!(
        code, 1,
        "a ledger save failure must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "partial_failure", "stdout=\n{stdout}");
    let failed = v["vendoredFailed"]
        .as_array()
        .expect("vendoredFailed array");
    assert_eq!(failed.len(), 1, "stdout=\n{stdout}");
    assert_eq!(failed[0]["purl"], V_PURL, "stdout=\n{stdout}");
    assert!(
        failed[0]["error"]
            .as_str()
            .is_some_and(|e| e.contains("vendor ledger write failed")),
        "the error must name the ledger write; stdout=\n{stdout}"
    );
    assert!(
        fx.manifest_json()["patches"].get(V_PURL).is_some(),
        "the manifest entry must be retained when the ledger save failed"
    );
}

/// Manifest-cleanup qualifier bridging: a manifest purl spelled WITH a
/// qualifier still leaves the manifest after its (bare-keyed) ledger entry
/// is cleanly reverted — the qualifier-stripped match arm.
#[test]
fn qualified_manifest_purl_removed_after_vendored_revert() {
    const QUALIFIED: &str = "pkg:npm/left-pad@1.3.0?foo=bar";

    let fx = vendor_fixture();
    vendor(&fx);

    // Re-key the manifest entry with a qualifier the ledger key lacks.
    let mut manifest = fx.manifest_json();
    let record = manifest["patches"][V_PURL].take();
    manifest["patches"]
        .as_object_mut()
        .unwrap()
        .remove(V_PURL);
    manifest["patches"][QUALIFIED] = record;
    std::fs::write(
        fx.root().join(".socket/manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(
        v["vendoredReverted"],
        json!([V_PURL]),
        "the ledger revert reports the LEDGER key; stdout=\n{stdout}"
    );
    assert_eq!(
        v["manifest"]["removedEntries"],
        json!([QUALIFIED]),
        "the qualified manifest spelling must still be removed; stdout=\n{stdout}"
    );
    assert_eq!(
        fx.manifest_json()["patches"],
        json!({}),
        "the qualified entry must be gone from disk"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
}

// ═════════════════════════ 3. hosted-leg gaps ══════════════════════════════

const LP_PURL: &str = "pkg:npm/left-pad@1.2.3";
const LP_UUID: &str = "55555555-5555-4555-8555-555555555555";
const LP_HOSTED_URL: &str = "http://patch.test/patch/npm/left-pad/1.2.3/66666666-6666-4666-8666-666666666666/55555555-5555-4555-8555-555555555555/left-pad-1.2.3.tgz";
const GEM_PURL: &str = "pkg:gem/rex@1.0.0";
const GEM_UUID: &str = "77777777-7777-4777-8777-777777777777";
const GEM_UPSTREAM_REMOTE: &str = "https://rubygems.org/";
const GEM_PATCH_REMOTE: &str = "http://patch.test/gems/t0k3nt0k3n/";

/// A full camelCase patch record for hand-written ledgers.
fn hosted_record(uuid: &str) -> PatchRecord {
    let mut files = std::collections::HashMap::new();
    files.insert(
        "package/index.js".to_string(),
        PatchFileInfo {
            before_hash: "a".repeat(64),
            after_hash: "b".repeat(64),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2024-01-01T00:00:00Z".to_string(),
        files,
        vulnerabilities: std::collections::HashMap::new(),
        description: "x".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// Serialize a hand-written ledger through the real core types (real
/// schema: version, mode "hosted", edits[FileEdit], records{purl:record}).
fn write_hosted_ledger(root: &Path, records: Vec<(&str, PatchRecord)>, edits: Vec<FileEdit>) {
    let mut state = RedirectState::new();
    state.edits = edits;
    for (purl, record) in records {
        state.records.insert(purl.to_string(), record);
    }
    let vendor_dir = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).expect("create .socket/vendor");
    let mut bytes = serde_json::to_vec_pretty(&state).expect("serialize ledger");
    bytes.push(b'\n');
    std::fs::write(vendor_dir.join("redirect-state.json"), bytes).expect("write ledger");
}

fn ledger_path(root: &Path) -> PathBuf {
    root.join(".socket/vendor/redirect-state.json")
}

// yarn-classic fragments — `redirect_yarn_classic_entry` is a text kind the
// per-purl npm revert claims by `<name>@<version>` key.

fn yarn_block(resolved: &str, integrity: &str) -> String {
    format!(
        "left-pad@1.2.3:\n  version \"1.2.3\"\n  resolved \"{resolved}\"\n  integrity {integrity}"
    )
}

fn yarn_original_block() -> String {
    yarn_block(
        "https://registry.yarnpkg.com/left-pad/-/left-pad-1.2.3.tgz#aaaa",
        "sha512-UPSTREAMupstream==",
    )
}

fn yarn_redirected_block() -> String {
    yarn_block(LP_HOSTED_URL, "sha512-PATCHEDpatched==")
}

fn yarn_lock_content(block: &str) -> String {
    format!(
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\n{block}\n"
    )
}

fn yarn_classic_edit() -> FileEdit {
    FileEdit {
        path: "yarn.lock".to_string(),
        kind: "redirect_yarn_classic_entry".to_string(),
        action: "rewritten".to_string(),
        key: Some("left-pad@1.2.3".to_string()),
        original: Some(Value::String(yarn_original_block())),
        new: Some(Value::String(yarn_redirected_block())),
    }
}

// gem fragments — `redirect_gemfile_lock_source_url` has NO per-purl revert.

fn gemfile_lock_content(remote: &str) -> String {
    format!(
        "GEM\n  remote: {remote}\n  specs:\n    rex (1.0.0)\n\n\
         PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rex\n\nBUNDLED WITH\n   2.5.9\n"
    )
}

fn gem_source_edit() -> FileEdit {
    FileEdit {
        path: "Gemfile.lock".to_string(),
        kind: "redirect_gemfile_lock_source_url".to_string(),
        action: "rewritten".to_string(),
        key: Some("rex".to_string()),
        original: Some(Value::String(GEM_UPSTREAM_REMOTE.to_string())),
        new: Some(Value::String(GEM_PATCH_REMOTE.to_string())),
    }
}

/// Single-record npm fixture (yarn-classic wiring, redirected on disk).
fn write_single_npm_fixture(root: &Path) {
    std::fs::write(
        root.join("yarn.lock"),
        yarn_lock_content(&yarn_redirected_block()),
    )
    .unwrap();
    write_hosted_ledger(
        root,
        vec![(LP_PURL, hosted_record(LP_UUID))],
        vec![yarn_classic_edit()],
    );
}

/// Two-record fixture: npm (per-purl revertable) + gem (replay-only).
fn write_two_record_fixture(root: &Path) {
    std::fs::write(
        root.join("yarn.lock"),
        yarn_lock_content(&yarn_redirected_block()),
    )
    .unwrap();
    std::fs::write(
        root.join("Gemfile.lock"),
        gemfile_lock_content(GEM_PATCH_REMOTE),
    )
    .unwrap();
    write_hosted_ledger(
        root,
        vec![
            (LP_PURL, hosted_record(LP_UUID)),
            (GEM_PURL, hosted_record(GEM_UUID)),
        ],
        vec![yarn_classic_edit(), gem_source_edit()],
    );
}

/// Human wet run over a hosted-only (manifest-less) project: the unscoped
/// "No patches found in manifest" announce, the wet "Unwound hosted
/// redirect for {purl}" line, and the reinstall note — with the wiring
/// actually unwound and the emptied ledger deleted.
#[test]
fn hosted_human_wet_announces_and_unwinds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes"]);
    assert_eq!(
        code, 0,
        "the hosted-only rollback succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("No patches found in manifest"),
        "the unscoped empty-manifest announce must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("Unwound hosted redirect for {LP_PURL}")),
        "the wet unwind line must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("unwired packages keep their patched bytes"),
        "the reinstall note must print; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the wiring must be unwound on disk"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "the emptied ledger must be deleted"
    );
}

/// Human dry-run twin: "Would unwind hosted redirect for {purl}", nothing
/// mutated.
#[test]
fn hosted_human_dry_run_previews() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--dry-run"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!("Would unwind hosted redirect for {LP_PURL}")),
        "the dry-run unwind preview must print; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_redirected_block()),
        "dry run must not touch the wired lock"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "dry run must not touch the ledger"
    );
}

/// Human notice for a SCOPED hosted target with no per-purl revert (gem,
/// with an out-of-scope npm record blocking the replay): the "Cannot
/// unwind hosted redirect for …" stderr guidance, exit 1, nothing touched.
#[test]
fn scoped_unsupported_ecosystem_prints_human_notice() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_two_record_fixture(tmp.path());
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes", GEM_PURL]);
    assert_eq!(
        code, 1,
        "a scoped unsupported hosted purl fails closed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("Cannot unwind hosted redirect for {GEM_PURL}"))
            && stderr.contains("no per-purl revert exists"),
        "the human guidance must print on stderr; stderr=\n{stderr}"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "the ledger must be untouched"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("Gemfile.lock")).unwrap(),
        gemfile_lock_content(GEM_PATCH_REMOTE),
        "the refused gem wiring must be untouched"
    );
}

/// Per-purl hosted revert FAILURE: the wired lockfile is unreadable
/// (yarn.lock is a directory), so the scoped npm revert errors — the purl
/// + error land in `hosted.failed`, exit 1, everything else untouched.
#[test]
fn per_purl_revert_failure_lands_in_hosted_failed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Two records so the scoped npm run is NOT replay-eligible: the
    // failure under test is the per-purl revert alone.
    std::fs::create_dir(tmp.path().join("yarn.lock")).unwrap(); // a DIRECTORY
    std::fs::write(
        tmp.path().join("Gemfile.lock"),
        gemfile_lock_content(GEM_PATCH_REMOTE),
    )
    .unwrap();
    write_hosted_ledger(
        tmp.path(),
        vec![
            (LP_PURL, hosted_record(LP_UUID)),
            (GEM_PURL, hosted_record(GEM_UUID)),
        ],
        vec![yarn_classic_edit(), gem_source_edit()],
    );
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["rollback", "--json", "--offline", "--yes", LP_PURL],
    );
    assert_eq!(
        code, 1,
        "a failed per-purl revert must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "partial_failure", "stdout=\n{stdout}");
    let failed = v["hosted"]["failed"].as_array().expect("failed array");
    assert_eq!(failed.len(), 1, "stdout=\n{stdout}");
    assert_eq!(failed[0]["purl"], LP_PURL, "stdout=\n{stdout}");
    assert!(
        failed[0]["error"]
            .as_str()
            .is_some_and(|e| e.contains("read yarn.lock")),
        "the error must name the unreadable lockfile; stdout=\n{stdout}"
    );
    assert_eq!(
        v["hosted"]["reverted"],
        json!([]),
        "nothing may be reported reverted; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "a failed revert must leave the ledger byte-identical"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("Gemfile.lock")).unwrap(),
        gemfile_lock_content(GEM_PATCH_REMOTE),
        "the out-of-scope gem wiring must be untouched"
    );
}

/// The whole-ledger replay REFUSAL loop: a leftover edit with an unsafe
/// path refuses its group — `group:<name>` failure entries in the JSON,
/// the "Cannot unwind hosted redirect edits" stderr line in human mode,
/// exit 1, ledger intact.
#[test]
fn replay_refusal_reports_group_failures_in_both_modes() {
    let evil_edit = || FileEdit {
        path: "../evil.lock".to_string(),
        kind: "redirect_yarn_classic_entry".to_string(),
        action: "rewritten".to_string(),
        key: Some("left-pad@1.2.3".to_string()),
        original: Some(Value::String(yarn_original_block())),
        new: Some(Value::String(yarn_redirected_block())),
    };

    // ── --json ──
    let tmp = tempfile::tempdir().expect("tempdir");
    write_hosted_ledger(tmp.path(), vec![], vec![evil_edit()]);
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "a replay refusal must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "partial_failure", "stdout=\n{stdout}");
    let failed = v["hosted"]["failed"].as_array().expect("failed array");
    assert_eq!(failed.len(), 1, "stdout=\n{stdout}");
    assert_eq!(
        failed[0]["purl"], "group:yarn",
        "the refusal is reported per group; stdout=\n{stdout}"
    );
    assert!(
        failed[0]["error"]
            .as_str()
            .is_some_and(|e| e.contains("unsafe path") && e.contains("../evil.lock")),
        "the refusal must name the reason and the file; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "a refused replay must leave the ledger byte-identical"
    );

    // ── human ──
    let tmp = tempfile::tempdir().expect("tempdir");
    write_hosted_ledger(tmp.path(), vec![], vec![evil_edit()]);
    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes"]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("Cannot unwind hosted redirect edits (yarn)"),
        "the human refusal line must print on stderr; stderr=\n{stderr}"
    );
}

/// A records-EMPTY ledger with leftover edits (the degraded
/// record-fetch-failed shape): an unscoped wet run replays the edits —
/// the confirm clause for leftover edits composes on the way — restoring
/// the wired file and deleting the emptied ledger.
#[test]
fn leftover_edits_only_ledger_replays_unscoped() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("yarn.lock"),
        yarn_lock_content(&yarn_redirected_block()),
    )
    .unwrap();
    write_hosted_ledger(tmp.path(), vec![], vec![yarn_classic_edit()]);

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 0,
        "the leftover-edits replay succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert!(
        v["hosted"]["editedFiles"].as_u64().unwrap_or(0) >= 1,
        "the replay rewrote the lock; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the leftover edit must be replayed"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "the emptied ledger must be deleted"
    );
}

/// A corrupt redirect ledger skips ONLY the hosted leg: exit 1 with the
/// `redirect_state_unreadable` warning (JSON) / `Error
/// (redirect_state_unreadable):` notice (human), and the garbage file is
/// left in place for quarantine.
#[test]
fn corrupt_redirect_ledger_warns_and_fails_in_both_modes() {
    let corrupt = || {
        let tmp = tempfile::tempdir().expect("tempdir");
        let vendor_dir = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor_dir).unwrap();
        std::fs::write(vendor_dir.join("redirect-state.json"), b"garbage not json").unwrap();
        tmp
    };

    // ── --json ──
    let tmp = corrupt();
    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "a corrupt redirect ledger must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "partial_failure", "stdout=\n{stdout}");
    assert!(
        warning_codes(&v).contains(&"redirect_state_unreadable".to_string()),
        "the warning must be surfaced; stdout=\n{stdout}"
    );
    assert_eq!(
        v["hosted"]["reverted"],
        json!([]),
        "the hosted leg must be skipped; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        b"garbage not json",
        "the corrupt ledger must be left in place for quarantine"
    );

    // ── human ──
    let tmp = corrupt();
    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes"]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("Error (redirect_state_unreadable):"),
        "the error-class notice must print on stderr; stderr=\n{stderr}"
    );
}

/// `--ecosystems` narrows the hosted leg: a pypi-scoped run leaves the npm
/// record (and, being a scope, blocks the whole-ledger replay); an
/// npm-scoped run unwinds it.
#[test]
fn ecosystems_filter_narrows_hosted_scope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["rollback", "--json", "--offline", "--yes", "--ecosystems", "pypi"],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(
        v["hosted"]["reverted"],
        json!([]),
        "a pypi-scoped run must not unwind the npm record; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "the record must survive the eco-narrowed run"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_redirected_block()),
        "the wiring must survive too"
    );

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["rollback", "--json", "--offline", "--yes", "--ecosystems", "npm"],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(
        v["hosted"]["reverted"],
        json!([LP_PURL]),
        "the npm-scoped run must unwind it; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the wiring must be unwound"
    );
    assert!(!ledger_path(tmp.path()).exists(), "ledger deleted");
}

/// A path-shaped target selects a HOSTED record through its installed
/// copy: `rollback node_modules/left-pad` unwinds the redirect.
#[test]
fn path_glob_selects_hosted_record() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());
    // An installed copy for the path-scope crawler to discover.
    write_root_package_json(tmp.path());
    install_npm_pkg(
        tmp.path(),
        "node_modules",
        "left-pad",
        "1.2.3",
        b"installed bytes\n",
    );

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["rollback", "--json", "--offline", "--yes", "node_modules/left-pad"],
    );
    assert_eq!(
        code, 0,
        "the path-scoped hosted rollback succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(
        v["hosted"]["reverted"],
        json!([LP_PURL]),
        "the path target must select the hosted record; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the wiring must be unwound"
    );
    assert!(!ledger_path(tmp.path()).exists(), "ledger deleted");
}

/// `persist_redirect_state` FAILURE after the hosted leg mutated the
/// ledger in memory: the replay rewrote the wired file, but the emptied
/// ledger cannot be removed (read-only `.socket/vendor`) — the failure
/// lands in `hosted.failed` as the `ledger` entry and the run exits 1.
#[cfg(unix)]
#[test]
fn hosted_persist_failure_lands_in_hosted_failed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("yarn.lock"),
        yarn_lock_content(&yarn_redirected_block()),
    )
    .unwrap();
    write_hosted_ledger(tmp.path(), vec![], vec![yarn_classic_edit()]);

    let vendor_dir = tmp.path().join(".socket/vendor");
    let guard = DirModeGuard::chmod(&vendor_dir, 0o555, 0o755);
    if !readonly_dir_enforced(&vendor_dir) {
        return;
    }

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    guard.restore();

    assert_eq!(
        code, 1,
        "a ledger persist failure must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "partial_failure", "stdout=\n{stdout}");
    let failed = v["hosted"]["failed"].as_array().expect("failed array");
    assert!(
        failed.iter().any(|f| f["purl"] == "ledger"
            && f["error"]
                .as_str()
                .is_some_and(|e| e.contains("failed to persist the hosted redirect ledger"))),
        "the persist failure must be reported under the 'ledger' key; stdout=\n{stdout}"
    );
    // The replay itself ran before the persist: the wired file is restored.
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the replay's file writes land before the persist failure"
    );
    assert!(
        ledger_path(tmp.path()).exists(),
        "the un-removable ledger file must still be on disk"
    );
}

/// bun-deferred npm purls: bun.lock edits hard-refuse the per-purl npm
/// revert, so on a replay-eligible run the purl DEFERS to the whole-ledger
/// replay and succeeds through it — the wet human "Unwound hosted redirect
/// for {purl}" line prints from the deferred path.
#[test]
fn bun_deferred_purl_unwinds_via_replay() {
    let bun_original = r#"    "left-pad": ["left-pad@1.2.3", "", {}, "sha512-UPSTREAMupstream=="],"#;
    let bun_redirected = format!(r#"    "left-pad": ["{LP_HOSTED_URL}", "", {{}}, "sha512-PATCHEDpatched=="],"#);
    let bun_lock = |block: &str| {
        format!("{{\n  \"lockfileVersion\": 1,\n  \"packages\": {{\n{block}\n  }}\n}}\n")
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("bun.lock"), bun_lock(&bun_redirected)).unwrap();
    write_hosted_ledger(
        tmp.path(),
        vec![(LP_PURL, hosted_record(LP_UUID))],
        vec![FileEdit {
            path: "bun.lock".to_string(),
            kind: "redirect_bun_lock_package".to_string(),
            action: "rewritten".to_string(),
            key: Some("left-pad".to_string()),
            original: Some(Value::String(bun_original.to_string())),
            new: Some(Value::String(bun_redirected.clone())),
        }],
    );

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes"]);
    assert_eq!(
        code, 0,
        "the bun-deferred unwind succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains(&format!("Unwound hosted redirect for {LP_PURL}")),
        "the deferred purl's wet unwind line must print; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap(),
        bun_lock(bun_original),
        "the bun.lock fragment must be replayed back to the original"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "record and edit both unwound: the ledger must be deleted"
    );
}

// ═══════════════ 4. GC-failure warnings (unix permissions) ═════════════════

/// GC failures WARN, never fail the rollback: with the blob and diff
/// stores unreadable (mode 000) on an already-original fixture, the run
/// still exits 0 carrying `cleanup_failed` warnings for both sweeps.
#[cfg(unix)]
#[test]
fn gc_failure_warns_but_run_still_succeeds() {
    let before: &[u8] = b"gc-original\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(b"gc-patched\n");
    let purl = "pkg:npm/covgap-gc@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // Installed at BEFORE bytes: the engine never reads a blob.
    install_npm_pkg(tmp.path(), "node_modules", "covgap-gc", "1.0.0", before);
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            purl,
            "22222222-2222-4222-8222-222222222222",
            &before_hash,
            &after_hash,
        )],
    );
    let blobs = socket.join("blobs");
    let diffs = socket.join("diffs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::create_dir_all(&diffs).unwrap();
    let blob_guard = DirModeGuard::chmod(&blobs, 0o000, 0o755);
    let diff_guard = DirModeGuard::chmod(&diffs, 0o000, 0o755);
    // The sweeps READ these dirs, so probe the denial with a read: root (or
    // CAP_DAC_OVERRIDE) opens a mode-000 dir fine and the GC would succeed.
    if std::fs::read_dir(&blobs).is_ok() {
        eprintln!("skipping: permission bits not enforced (running as root?)");
        return;
    }

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    blob_guard.restore();
    diff_guard.restore();

    assert_eq!(
        code, 0,
        "GC failures must not fail the rollback; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    let warnings = v["warnings"].as_array().expect("warnings array");
    assert!(
        warnings.iter().any(|w| w["code"] == "cleanup_failed"
            && w["detail"]
                .as_str()
                .is_some_and(|d| d.contains("blob cleanup failed"))),
        "the blob sweep failure must be warned; stdout=\n{stdout}"
    );
    assert!(
        warnings.iter().any(|w| w["code"] == "cleanup_failed"
            && w["detail"]
                .as_str()
                .is_some_and(|d| d.contains("diffs cleanup failed"))),
        "the diffs sweep failure must be warned; stdout=\n{stdout}"
    );
    assert_eq!(
        v["manifest"]["removedEntries"],
        json!([purl]),
        "the already-original entry still leaves the manifest; stdout=\n{stdout}"
    );
}

// ═══════════ 5. manifest-write failure (macOS immutable flag) ═══════════════

/// `write_manifest` failure AFTER a successful restore: the files are
/// rolled back, but the entry removal cannot land — `removedEntries` comes
/// back empty, the `manifest_write_failed` warning is carried, the run
/// exits 1, and the on-disk manifest is byte-identical.
#[cfg(target_os = "macos")]
#[test]
fn manifest_write_failure_warns_and_exits_one() {
    struct ChflagsGuard(PathBuf);
    impl ChflagsGuard {
        fn set(path: &Path) -> Self {
            let status = std::process::Command::new("chflags")
                .arg("uchg")
                .arg(path)
                .status()
                .expect("run chflags uchg");
            assert!(status.success(), "chflags uchg must succeed");
            Self(path.to_path_buf())
        }
        fn release(&self) {
            let _ = std::process::Command::new("chflags")
                .arg("nouchg")
                .arg(&self.0)
                .status();
        }
    }
    impl Drop for ChflagsGuard {
        fn drop(&mut self) {
            self.release();
        }
    }

    let fx = patched_fixture();
    let manifest_path = fx.socket.join("manifest.json");
    let manifest_before = std::fs::read(&manifest_path).expect("read manifest bytes");
    let guard = ChflagsGuard::set(&manifest_path);

    let (code, stdout, stderr) = run(fx.root.path(), &["rollback", "--json", "--offline", "--yes"]);
    guard.release();

    assert_eq!(
        code, 1,
        "a manifest write failure must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], "partial_failure", "stdout=\n{stdout}");
    assert!(
        warning_codes(&v).contains(&"manifest_write_failed".to_string()),
        "the write failure must be warned; stdout=\n{stdout}"
    );
    assert_eq!(
        v["manifest"]["removedEntries"],
        json!([]),
        "nothing may be reported removed when the write failed; stdout=\n{stdout}"
    );
    // The restore itself DID land...
    assert_eq!(
        std::fs::read(fx.pkg_dir.join("index.js")).expect("read restored file"),
        fx.before,
        "the file restore happens before the manifest write"
    );
    // ...but the manifest is untouched.
    assert_eq!(
        std::fs::read(&manifest_path).expect("manifest exists"),
        manifest_before,
        "a failed manifest write must leave the file byte-identical"
    );
    // And the entry's blobs must survive for a retry (the failed-write
    // fallback restores the in-memory reference before the GC).
    assert!(
        fx.socket.join("blobs").join(&fx.before_hash).exists()
            && fx.socket.join("blobs").join(&fx.after_hash).exists(),
        "the failed-cleanup entry's blobs must be pinned"
    );
}

// ═══════════════ 6. interactive confirm decline (PTY) ═══════════════════════

#[cfg(unix)]
mod interactive {
    use super::*;
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::{Read, Write};
    use std::time::Duration;

    /// Spawn the binary inside a PTY, send `input`, collect all output —
    /// the `interactive_prompts_e2e.rs` harness (same env scrubbing).
    fn run_in_pty(args: &[&str], cwd: &Path, input: &str, timeout: Duration) -> (i32, String) {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");

        let mut cmd = CommandBuilder::new(common::binary());
        for a in args {
            cmd.arg(a);
        }
        cmd.cwd(cwd);
        // Seed-then-scrub the highest-risk vars (SOCKET_YES would skip the
        // very prompt under test), then prefix-scrub the rest.
        cmd.env("SOCKET_YES", "true");
        cmd.env("SOCKET_JSON", "true");
        cmd.env("SOCKET_DRY_RUN", "true");
        cmd.env("SOCKET_SILENT", "true");
        cmd.env_remove("SOCKET_YES");
        cmd.env_remove("SOCKET_JSON");
        cmd.env_remove("SOCKET_DRY_RUN");
        cmd.env_remove("SOCKET_SILENT");
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("SOCKET_")
                && !name.contains("TELEMETRY")
                && name != "SOCKET_NO_CONFIG"
                && name != "SOCKET_NO_UPDATE_CHECK"
            {
                cmd.env_remove(&key);
            }
        }
        cmd.env("SOCKET_NO_UPDATE_CHECK", "1");

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .expect("spawn socket-patch in PTY");
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().expect("clone reader");
        let reader_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = reader.read_to_end(&mut buf);
            buf
        });

        let mut killer = child.clone_killer();
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            let _ = killer.kill();
        });

        let mut writer = pair.master.take_writer().expect("take writer");
        let _ = writer.write_all(input.as_bytes());
        let _ = writer.flush();
        drop(writer);

        let status = child.wait().expect("child.wait");
        drop(pair.master);

        let output = reader_handle.join().expect("reader thread join");
        (
            status.exit_code() as i32,
            String::from_utf8_lossy(&output).to_string(),
        )
    }

    /// Declining the rollback confirm prompt cancels cleanly: the composed
    /// manifest clause renders with the `[Y/n]` hint, "Rollback cancelled."
    /// prints, the run exits 0, and nothing is mutated.
    #[test]
    fn rollback_interactive_decline_cancels() {
        let before_hash = git_sha256(b"pty-original\n");
        let after_hash = git_sha256(b"pty-patched\n");
        let tmp = tempfile::tempdir().expect("tempdir");
        let socket = write_socket_manifest(
            tmp.path(),
            &[manifest_entry(
                "pkg:npm/covgap-pty@1.0.0",
                "44444444-4444-4444-8444-444444444444",
                &before_hash,
                &after_hash,
            )],
        );
        let manifest_before =
            std::fs::read(socket.join("manifest.json")).expect("read manifest bytes");

        let (code, output) = run_in_pty(
            &["rollback", "--offline"],
            tmp.path(),
            "n\n",
            Duration::from_secs(15),
        );
        assert_eq!(code, 0, "declining must exit 0; got: {output}");
        assert!(
            output.contains(
                "Roll back 1 patch(es) and remove them from the local manifest? [Y/n]"
            ),
            "the composed confirm prompt must render verbatim; got: {output}"
        );
        assert!(
            !output.contains("Non-interactive mode"),
            "the PTY run must take the interactive branch; got: {output}"
        );
        assert!(
            output.contains("Rollback cancelled."),
            "the decline must be acknowledged; got: {output}"
        );
        assert_eq!(
            std::fs::read(socket.join("manifest.json")).expect("manifest exists"),
            manifest_before,
            "a declined rollback must leave the manifest byte-identical"
        );
    }
}

// ══════════════════ 7. mop-up: remaining uncovered arms ════════════════════

/// JSON dry-run of the vendored leg: the human preview print is skipped
/// (the mode gate's false branch) while the envelope still previews the
/// revert — `dryRun: true`, `vendoredReverted` names the key — and lock,
/// ledger, and artifact are all untouched.
#[test]
fn vendored_dry_run_json_previews_without_human_print() {
    let fx = vendor_fixture();
    vendor(&fx);
    let wired_lock = fx.lock_bytes();
    let state_before = std::fs::read(fx.state_path()).unwrap();

    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--json", "--offline", "--dry-run"]);
    assert_eq!(
        code, 0,
        "the JSON dry run must exit 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["dryRun"], json!(true), "stdout=\n{stdout}");
    assert_eq!(
        v["vendoredReverted"],
        json!([V_PURL]),
        "the envelope must preview the revert; stdout=\n{stdout}"
    );
    assert!(
        !stdout.contains("Would revert vendoring"),
        "--json must mute the human preview line; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), wired_lock, "dry run must not touch the lock");
    assert_eq!(
        std::fs::read(fx.state_path()).unwrap(),
        state_before,
        "dry run must not touch the ledger"
    );
    assert!(fx.tgz_path().is_file(), "dry run must keep the artifact");
}

/// Human twin of `per_purl_revert_failure_lands_in_hosted_failed`: the
/// failed per-purl npm revert prints the "Failed to unwind hosted
/// redirect for {purl}: {e}" stderr line (errors print even without
/// `--json`), exit 1, ledger untouched.
#[test]
fn per_purl_revert_failure_prints_human_stderr_line() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // yarn.lock is a DIRECTORY so the scoped npm revert fails on read;
    // the second (gem) record keeps the scoped run replay-ineligible.
    std::fs::create_dir(tmp.path().join("yarn.lock")).unwrap();
    std::fs::write(
        tmp.path().join("Gemfile.lock"),
        gemfile_lock_content(GEM_PATCH_REMOTE),
    )
    .unwrap();
    write_hosted_ledger(
        tmp.path(),
        vec![
            (LP_PURL, hosted_record(LP_UUID)),
            (GEM_PURL, hosted_record(GEM_UUID)),
        ],
        vec![yarn_classic_edit(), gem_source_edit()],
    );
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes", LP_PURL]);
    assert_eq!(
        code, 1,
        "a failed per-purl revert must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("Failed to unwind hosted redirect for {LP_PURL}:")),
        "the human failure line must print on stderr; stderr=\n{stderr}"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "a failed revert must leave the ledger byte-identical"
    );
}

/// Dry-run twin of `bun_deferred_purl_unwinds_via_replay`: the bun-lock
/// edits hard-refuse the per-purl npm revert, so the deferred purl's
/// PREVIEW routes through the replay's dropped-records probe and prints
/// "Would unwind hosted redirect for {purl}" — with bun.lock and the
/// ledger byte-identical afterwards.
#[test]
fn bun_deferred_purl_dry_run_previews_via_replay() {
    let bun_original = r#"    "left-pad": ["left-pad@1.2.3", "", {}, "sha512-UPSTREAMupstream=="],"#;
    let bun_redirected = format!(r#"    "left-pad": ["{LP_HOSTED_URL}", "", {{}}, "sha512-PATCHEDpatched=="],"#);
    let bun_lock = |block: &str| {
        format!("{{\n  \"lockfileVersion\": 1,\n  \"packages\": {{\n{block}\n  }}\n}}\n")
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("bun.lock"), bun_lock(&bun_redirected)).unwrap();
    write_hosted_ledger(
        tmp.path(),
        vec![(LP_PURL, hosted_record(LP_UUID))],
        vec![FileEdit {
            path: "bun.lock".to_string(),
            kind: "redirect_bun_lock_package".to_string(),
            action: "rewritten".to_string(),
            key: Some("left-pad".to_string()),
            original: Some(Value::String(bun_original.to_string())),
            new: Some(Value::String(bun_redirected.clone())),
        }],
    );
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--dry-run"]);
    assert_eq!(
        code, 0,
        "the bun-deferred dry run succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains(&format!("Would unwind hosted redirect for {LP_PURL}")),
        "the deferred purl's dry-run preview line must print; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap(),
        bun_lock(&bun_redirected),
        "dry run must not touch the wired bun.lock"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "dry run must not touch the ledger"
    );
}

/// The manifest vanishing while another process holds the apply lock: the
/// pre-lock existence probe saw the file, but the under-lock read finds
/// it gone — rollback fails closed with the "Invalid manifest" error
/// (exit 1) rather than silently treating the run as empty.
///
/// Choreography: hold the lock, let the CLI pass its probe and block,
/// delete the manifest, release. If the CLI was slow enough to probe
/// AFTER the delete it takes the pre-lock "Manifest not found" path
/// instead — that alternative is detected and retried with a longer
/// pre-delete grace (bounded; the first attempt lands in practice).
#[test]
fn manifest_deleted_under_held_lock_fails_with_invalid_manifest() {
    use fs2::FileExt;

    for attempt in 1..=8u64 {
        let tmp = tempfile::tempdir().expect("tempdir");
        let socket = write_socket_manifest(
            tmp.path(),
            &[manifest_entry(
                "pkg:npm/covgap-toctou@1.0.0",
                "33333333-3333-4333-8333-333333333333",
                &git_sha256(b"toctou-original\n"),
                &git_sha256(b"toctou-patched\n"),
            )],
        );
        let lock_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(socket.join("apply.lock"))
            .expect("open lock file");
        lock_file
            .try_lock_exclusive()
            .expect("test could not take the initial lock");

        let child = spawn_scrubbed(
            tmp.path(),
            &["rollback", "--json", "--offline", "--yes", "--lock-timeout", "30"],
        );
        // Grace for the child to pass its (fast) pre-lock probe and block
        // on the lock; escalates across retries.
        std::thread::sleep(std::time::Duration::from_millis(200 * attempt));
        std::fs::remove_file(socket.join("manifest.json")).expect("delete manifest");
        FileExt::unlock(&lock_file).expect("release the lock");

        let out = child.wait_with_output().expect("wait for socket-patch");
        let code = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert_eq!(
            code, 1,
            "both interleavings exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
        );
        let v = parse_envelope(&stdout, &stderr);
        assert_eq!(v["status"], "error", "stdout=\n{stdout}");
        match v["error"].as_str() {
            Some("Invalid manifest") => return, // target interleaving reached
            Some("Manifest not found") => continue, // probed after the delete — retry
            other => panic!(
                "unexpected error for the vanished manifest: {other:?}\nstdout=\n{stdout}\nstderr=\n{stderr}"
            ),
        }
    }
    panic!("the probe-then-delete interleaving never landed in 8 attempts");
}

/// Human twin of `hosted_persist_failure_lands_in_hosted_failed`: the
/// wet-run ledger persist failure prints the "Error: failed to persist
/// the hosted redirect ledger" stderr line, exit 1 — after the replay
/// already restored the wired file.
#[cfg(unix)]
#[test]
fn hosted_persist_failure_prints_human_error_line() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("yarn.lock"),
        yarn_lock_content(&yarn_redirected_block()),
    )
    .unwrap();
    write_hosted_ledger(tmp.path(), vec![], vec![yarn_classic_edit()]);

    let vendor_dir = tmp.path().join(".socket/vendor");
    let guard = DirModeGuard::chmod(&vendor_dir, 0o555, 0o755);
    if !readonly_dir_enforced(&vendor_dir) {
        return;
    }

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes"]);
    guard.restore();

    assert_eq!(
        code, 1,
        "a ledger persist failure must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Error: failed to persist the hosted redirect ledger"),
        "the human persist-failure line must print on stderr; stderr=\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the replay's file writes land before the persist failure"
    );
}

/// Human twin of `manifest_write_failure_warns_and_exits_one`: the failed
/// manifest update prints the "Error: failed to update the manifest:"
/// stderr line, exit 1, manifest byte-identical — after the file restore
/// already landed.
#[cfg(target_os = "macos")]
#[test]
fn manifest_write_failure_prints_human_error_line() {
    struct ChflagsGuard(PathBuf);
    impl ChflagsGuard {
        fn set(path: &Path) -> Self {
            let status = std::process::Command::new("chflags")
                .arg("uchg")
                .arg(path)
                .status()
                .expect("run chflags uchg");
            assert!(status.success(), "chflags uchg must succeed");
            Self(path.to_path_buf())
        }
        fn release(&self) {
            let _ = std::process::Command::new("chflags")
                .arg("nouchg")
                .arg(&self.0)
                .status();
        }
    }
    impl Drop for ChflagsGuard {
        fn drop(&mut self) {
            self.release();
        }
    }

    let fx = patched_fixture();
    let manifest_path = fx.socket.join("manifest.json");
    let manifest_before = std::fs::read(&manifest_path).expect("read manifest bytes");
    let guard = ChflagsGuard::set(&manifest_path);

    let (code, stdout, stderr) = run(fx.root.path(), &["rollback", "--offline", "--yes"]);
    guard.release();

    assert_eq!(
        code, 1,
        "a manifest write failure must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Error: failed to update the manifest:"),
        "the human write-failure line must print on stderr; stderr=\n{stderr}"
    );
    // The restore itself DID land...
    assert_eq!(
        std::fs::read(fx.pkg_dir.join("index.js")).expect("read restored file"),
        fx.before,
        "the file restore happens before the manifest write"
    );
    // ...but the manifest is untouched.
    assert_eq!(
        std::fs::read(&manifest_path).expect("manifest exists"),
        manifest_before,
        "a failed manifest write must leave the file byte-identical"
    );
}

/// The dry-run human summary's two conditional lines: "N package(s)
/// already in original state" and "N package(s) cannot be rolled back" —
/// one no-op entry plus one drifted entry render both, the can-rollback
/// count excludes them, and nothing is mutated.
#[test]
fn human_dry_run_summary_reports_already_original_and_failed() {
    let noop_before: &[u8] = b"dryboth-noop-original\n";
    let noop_purl = "pkg:npm/covgap-dry-noop@1.0.0";
    let drift_before: &[u8] = b"dryboth-drift-original\n";
    let drifted: &[u8] = b"dryboth-locally-drifted\n";
    let drift_purl = "pkg:npm/covgap-dry-drift@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // Installed at the BEFORE bytes: verification says already-original.
    install_npm_pkg(tmp.path(), "node_modules", "covgap-dry-noop", "1.0.0", noop_before);
    // Installed at DRIFTED bytes: verification says hash-mismatch.
    let drift_dir = install_npm_pkg(tmp.path(), "node_modules", "covgap-dry-drift", "1.0.0", drifted);
    let socket = write_socket_manifest(
        tmp.path(),
        &[
            manifest_entry(
                noop_purl,
                "88888888-8888-4888-8888-888888888888",
                &git_sha256(noop_before),
                &git_sha256(b"dryboth-noop-patched\n"),
            ),
            manifest_entry(
                drift_purl,
                "99999999-9999-4999-8999-999999999999",
                &git_sha256(drift_before),
                &git_sha256(b"dryboth-drift-patched\n"),
            ),
        ],
    );
    // Both before-blobs staged so the missing-blob gate never downloads:
    // the statuses under test are already_original and hash_mismatch.
    stage_blob(&socket, &git_sha256(noop_before), noop_before);
    stage_blob(&socket, &git_sha256(drift_before), drift_before);
    let manifest_bytes = std::fs::read(socket.join("manifest.json")).unwrap();

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--dry-run", "--offline"]);
    assert_eq!(
        code, 1,
        "the drifted entry cannot roll back, so the preview exits 1; \
         stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Rollback verification complete:"),
        "the dry-run header must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("0 package(s) can be rolled back"),
        "a no-op and a failure leave nothing rollback-able; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 package(s) already in original state"),
        "the already-original summary line must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 package(s) cannot be rolled back"),
        "the cannot-rollback summary line must print; stdout=\n{stdout}"
    );
    // Preview, no mutations.
    assert_eq!(
        std::fs::read(drift_dir.join("index.js")).unwrap(),
        drifted,
        "dry run must not touch the drifted file"
    );
    assert_eq!(
        std::fs::read(socket.join("manifest.json")).unwrap(),
        manifest_bytes,
        "dry run must leave the manifest byte-identical"
    );
}

/// A DIRECTORY squatting a before-blob's path in `.socket/blobs`: the
/// dry-run stage's hard-link fails and the copy fallback is attempted
/// (and swallowed) — the preview still completes because the
/// already-original file never reads the blob, and the squatter itself is
/// untouched.
#[test]
fn dry_run_blob_stage_survives_directory_squatting_blob_hash() {
    let before: &[u8] = b"squat-original\n";
    let before_hash = git_sha256(before);
    let purl = "pkg:npm/covgap-squat@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    install_npm_pkg(tmp.path(), "node_modules", "covgap-squat", "1.0.0", before);
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            purl,
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            &before_hash,
            &git_sha256(b"squat-patched\n"),
        )],
    );
    let squatter = socket.join("blobs").join(&before_hash);
    std::fs::create_dir_all(&squatter).unwrap();
    std::fs::write(squatter.join("marker"), b"keep").unwrap();

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--dry-run", "--offline"]);
    assert_eq!(
        code, 0,
        "the already-original preview must survive the squatter; \
         stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("1 package(s) already in original state"),
        "the entry must still verify as already original; stdout=\n{stdout}"
    );
    assert!(
        squatter.is_dir() && squatter.join("marker").exists(),
        "the squatting directory must be untouched by the dry run"
    );
}

// ═══════════ 8. mop-up: scope isolation, variant + redirect routing ════════

/// One camelCase manifest patch entry as a JSON value (the string helper
/// above pins `package/index.js`; these fixtures pick their own file key).
fn patch_entry_value(uuid: &str, file: &str, before_hash: &str, after_hash: &str) -> Value {
    json!({
        "uuid": uuid,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": {
            file: { "beforeHash": before_hash, "afterHash": after_hash }
        },
        "vulnerabilities": {},
        "description": "synthetic covgap test patch",
        "license": "MIT",
        "tier": "free"
    })
}

/// An identifier that matches only a MANIFEST entry is still probed
/// against every vendor-ledger entry — by ledger key AND by the entry's
/// `base_purl` — and must match neither: the unrelated vendored package
/// keeps its ledger record, lock wiring, and artifact while the named
/// in-place patch rolls back and leaves the manifest.
#[test]
fn identifier_scope_leaves_unrelated_vendored_entry_untouched() {
    const IO_PURL: &str = "pkg:npm/is-odd@1.0.0";
    const IO_UUID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    let io_before: &[u8] = b"module.exports = n => n % 2 === 1; // orig\n";
    let io_patched: &[u8] = b"module.exports = n => Math.abs(n) % 2 === 1; // patched\n";

    let fx = vendor_fixture();
    vendor(&fx);
    let wired_lock = fx.lock_bytes();
    let state_before = std::fs::read(fx.state_path()).expect("read vendor ledger");

    // The in-place patch arrives AFTER vendoring so `vendor` never saw it:
    // installed at the PATCHED bytes, before-blob staged for the restore.
    install_npm_pkg(fx.root(), "node_modules", "is-odd", "1.0.0", io_patched);
    let socket = fx.root().join(".socket");
    stage_blob(&socket, &git_sha256(io_before), io_before);
    let mut manifest = fx.manifest_json();
    manifest["patches"][IO_PURL] = patch_entry_value(
        IO_UUID,
        "package/index.js",
        &git_sha256(io_before),
        &git_sha256(io_patched),
    );
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let (code, stdout, stderr) = run(
        fx.root(),
        &["rollback", "--json", "--yes", "--offline", "--lock-timeout", "5", IO_PURL],
    );
    assert_eq!(
        code, 0,
        "the identifier-scoped rollback must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["rolledBack"], json!(1), "stdout=\n{stdout}");
    assert_eq!(
        v["results"][0]["purl"],
        json!(IO_PURL),
        "only the named patch may be acted on; stdout=\n{stdout}"
    );
    for leg in ["vendoredReverted", "vendoredPreserved", "vendoredKept", "vendoredFailed"] {
        assert_eq!(
            v[leg],
            json!([]),
            "the identifier must not leak into the vendored leg ({leg}); stdout=\n{stdout}"
        );
    }
    assert_eq!(
        v["manifest"]["removedEntries"],
        json!([IO_PURL]),
        "only the named entry leaves the manifest; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(fx.root().join("node_modules/is-odd/index.js")).expect("read restored file"),
        io_before,
        "the named patch must be restored in place"
    );
    // Every vendored surface survives byte-identically.
    assert_eq!(fx.lock_bytes(), wired_lock, "the vendored lock wiring must survive");
    assert_eq!(
        std::fs::read(fx.state_path()).expect("vendor ledger still present"),
        state_before,
        "the vendor ledger must be byte-identical"
    );
    assert!(fx.tgz_path().is_file(), "the vendored artifact must survive");
    let m = fx.manifest_json();
    assert!(
        m["patches"].get(V_PURL).is_some(),
        "the vendored manifest entry must be retained; manifest={m}"
    );
    assert!(
        m["patches"].get(IO_PURL).is_none(),
        "the rolled-back entry must be removed; manifest={m}"
    );
}

/// TWO vendored entries reverted in one run: the manifest-cleanup matcher
/// walks EVERY reverted ledger key for each vendor-owned purl — the
/// non-matching sibling key falls through key equality, qualifier
/// stripping, and the ledger `base_purl` probe — and each entry is still
/// keyed to ITS OWN revert: both manifest records drop, both artifacts
/// and ledger entries go, and the lock returns to its pre-vendor bytes.
#[test]
fn two_vendored_entries_each_cleanup_via_their_own_revert() {
    const RP_PURL: &str = "pkg:npm/right-pad@1.0.1";
    const RP_UUID: &str = "5b8c0d2e-3f4a-4b5c-8d6e-9f0a1b2c3d4e";
    let rp_orig: &[u8] = b"module.exports = (s, n) => s + ' '.repeat(n); // orig\n";
    let rp_patched: &[u8] = b"module.exports = (s, n) => s + ' '.repeat(n < 0 ? 0 : n); // patched\n";

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    install_npm_pkg(root, "node_modules", "left-pad", "1.3.0", ORIG_INDEX);
    install_npm_pkg(root, "node_modules", "right-pad", "1.0.1", rp_orig);
    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .expect("write root package.json");
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": { "left-pad": "^1.3.0", "right-pad": "^1.0.1" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig==",
                "license": "WTFPL"
            },
            "node_modules/right-pad": {
                "version": "1.0.1",
                "resolved": "https://registry.npmjs.org/right-pad/-/right-pad-1.0.1.tgz",
                "integrity": "sha512-origrp==",
                "license": "MIT"
            }
        }
    });
    let mut original_lock = serde_json::to_vec_pretty(&lock).expect("serialize lock");
    original_lock.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &original_lock).expect("write lock");

    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let mut patches = serde_json::Map::new();
    patches.insert(
        V_PURL.to_string(),
        patch_entry_value(
            V_UUID,
            "package/index.js",
            &git_sha256(ORIG_INDEX),
            &git_sha256(PATCHED_INDEX),
        ),
    );
    patches.insert(
        RP_PURL.to_string(),
        patch_entry_value(
            RP_UUID,
            "package/index.js",
            &git_sha256(rp_orig),
            &git_sha256(rp_patched),
        ),
    );
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).expect("serialize manifest"),
    )
    .expect("write manifest");
    // After-hash blobs are the offline vendor source for both packages.
    stage_blob(&socket, &git_sha256(PATCHED_INDEX), PATCHED_INDEX);
    stage_blob(&socket, &git_sha256(rp_patched), rp_patched);

    let (code, stdout, stderr) = run(
        root,
        &["vendor", "--json", "--silent", "--offline", "--lock-timeout", "5"],
    );
    assert_eq!(
        code, 0,
        "fixture vendor of both packages must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let lp_tgz = root.join(format!(".socket/vendor/npm/{V_UUID}/left-pad-1.3.0.tgz"));
    let rp_tgz = root.join(format!(".socket/vendor/npm/{RP_UUID}/right-pad-1.0.1.tgz"));
    assert!(lp_tgz.is_file() && rp_tgz.is_file(), "sanity: both artifacts written");

    let (code, stdout, stderr) = run(
        root,
        &["rollback", "--json", "--yes", "--offline", "--lock-timeout", "5"],
    );
    assert_eq!(
        code, 0,
        "the two-entry revert must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    let mut reverted: Vec<String> = v["vendoredReverted"]
        .as_array()
        .expect("vendoredReverted array")
        .iter()
        .map(|p| p.as_str().expect("purl string").to_string())
        .collect();
    reverted.sort();
    assert_eq!(
        reverted,
        vec![V_PURL.to_string(), RP_PURL.to_string()],
        "both entries must revert; stdout=\n{stdout}"
    );
    let mut removed: Vec<String> = v["manifest"]["removedEntries"]
        .as_array()
        .expect("removedEntries array")
        .iter()
        .map(|p| p.as_str().expect("purl string").to_string())
        .collect();
    removed.sort();
    assert_eq!(
        removed,
        vec![V_PURL.to_string(), RP_PURL.to_string()],
        "each manifest entry must be keyed to its own revert; stdout=\n{stdout}"
    );
    let m: Value = serde_json::from_slice(
        &std::fs::read(socket.join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest is JSON");
    assert_eq!(
        m["patches"],
        json!({}),
        "no manifest entry may survive its own clean revert; manifest={m}"
    );
    assert!(
        !lp_tgz.exists() && !rp_tgz.exists(),
        "both artifacts must be deleted"
    );
    let state_path = root.join(".socket/vendor/state.json");
    if state_path.exists() {
        let state: Value = serde_json::from_slice(
            &std::fs::read(&state_path).expect("read vendor ledger"),
        )
        .expect("ledger is JSON");
        assert_eq!(
            state["entries"],
            json!({}),
            "no ledger entry may survive; state={state}"
        );
    }
    assert_eq!(
        std::fs::read(root.join("package-lock.json")).expect("read lock"),
        original_lock,
        "the lock must return to its pre-vendor bytes"
    );
}

/// PyPI release-variant fallback when NO variant matches the installed
/// distribution (a locally-modified file): rollback attempts EVERY
/// variant instead of silently skipping the package, so the per-file
/// verification surfaces the drift — both qualified purls land in
/// `results` as hash-mismatch failures, exit 1, the file keeps its
/// drifted bytes, and the manifest keeps both entries.
#[test]
fn pypi_variant_group_with_no_installed_match_attempts_every_variant() {
    const WHEEL: &str = "pkg:pypi/covgapkit@1.0.0?artifact_id=covgapkit-1.0.0-py3-none-any.whl";
    const SDIST: &str = "pkg:pypi/covgapkit@1.0.0?artifact_id=covgapkit-1.0.0.tar.gz";
    let drifted: &[u8] = b"VERSION = 'locally-drifted'\n";
    let wheel_before: &[u8] = b"VERSION = 'wheel-original'\n";
    let wheel_after: &[u8] = b"VERSION = 'wheel-patched'\n";
    let sdist_before: &[u8] = b"VERSION = 'sdist-original'\n";
    let sdist_after: &[u8] = b"VERSION = 'sdist-patched'\n";

    // Hand-built venv layout (the shape the python crawler probes);
    // `VIRTUAL_ENV` is injected child-only, so discovery is deterministic
    // and parallel-safe regardless of the ambient shell.
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    let venv = root.join(".venv");
    #[cfg(windows)]
    let site_packages = venv.join("Lib").join("site-packages");
    #[cfg(not(windows))]
    let site_packages = venv.join("lib").join("python3.12").join("site-packages");
    let dist_info = site_packages.join("covgapkit-1.0.0.dist-info");
    std::fs::create_dir_all(&dist_info).expect("create dist-info");
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: covgapkit\nVersion: 1.0.0\n",
    )
    .expect("write METADATA");
    let pkg = site_packages.join("covgapkit");
    std::fs::create_dir_all(&pkg).expect("create package dir");
    std::fs::write(pkg.join("__init__.py"), drifted).expect("write module");

    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let mut patches = serde_json::Map::new();
    patches.insert(
        WHEEL.to_string(),
        patch_entry_value(
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "covgapkit/__init__.py",
            &git_sha256(wheel_before),
            &git_sha256(wheel_after),
        ),
    );
    patches.insert(
        SDIST.to_string(),
        patch_entry_value(
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "covgapkit/__init__.py",
            &git_sha256(sdist_before),
            &git_sha256(sdist_after),
        ),
    );
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).expect("serialize manifest"),
    )
    .expect("write manifest");
    // Both before-blobs staged: verification must reach the drift
    // comparison (hash_mismatch), not stop at a missing-blob gate.
    stage_blob(&socket, &git_sha256(wheel_before), wheel_before);
    stage_blob(&socket, &git_sha256(sdist_before), sdist_before);

    let (code, stdout, stderr) = common::run_with_env(
        root,
        &["rollback", "--json", "--yes", "--offline", "--lock-timeout", "5"],
        &[("VIRTUAL_ENV", venv.to_str().expect("utf8 venv path"))],
    );
    assert_eq!(
        code, 1,
        "a drifted install cannot roll back; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["status"], json!("partial_failure"), "stdout=\n{stdout}");
    assert_eq!(v["failed"], json!(2), "stdout=\n{stdout}");
    let results = v["results"].as_array().expect("results array");
    let mut result_purls: Vec<&str> = results
        .iter()
        .map(|r| r["purl"].as_str().expect("purl string"))
        .collect();
    result_purls.sort_unstable();
    assert_eq!(
        result_purls,
        vec![WHEEL, SDIST],
        "EVERY variant must be attempted when none matches the installed \
         distribution — silent skipping is the bug this guards; stdout=\n{stdout}"
    );
    for r in results {
        assert_eq!(r["success"], json!(false), "stdout=\n{stdout}");
        assert_eq!(
            r["filesVerified"][0]["status"],
            json!("hash_mismatch"),
            "the per-file verification must surface the drift; stdout=\n{stdout}"
        );
    }
    assert_eq!(
        std::fs::read(pkg.join("__init__.py")).expect("read module"),
        drifted,
        "a failed verification must leave the drifted bytes alone"
    );
    let m: Value = serde_json::from_slice(
        &std::fs::read(socket.join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest is JSON");
    assert!(
        m["patches"].get(WHEEL).is_some() && m["patches"].get(SDIST).is_some(),
        "failed variants must both stay in the manifest; manifest={m}"
    );
}

/// A DISCOVERED local-go redirect target: the module lives in the module
/// cache (child-only `GOMODCACHE` injection), so the crawler resolves it
/// and the rollback loop routes the discovered target through the
/// local-go redirect teardown — dropping the socket-owned `replace` and
/// the `.socket/go-patches/` copy while the CACHE copy stays
/// byte-identical (a redirect never patches the cache in place).
#[test]
fn discovered_local_go_redirect_drops_wiring_not_cache_copy() {
    use socket_patch_core::vendor::go_mod_edit::{
        ensure_replace_entry, read_replace_entries, GO_PATCHES_DIR,
    };

    const MODULE: &str = "github.com/covgap/discovered";
    const VERSION: &str = "v1.2.3";
    const PURL: &str = "pkg:golang/github.com/covgap/discovered@v1.2.3";
    let original: &[u8] = b"package discovered\n\nfunc V() string { return \"orig\" }\n";
    let patched: &[u8] = b"package discovered\n\nfunc V() string { return \"patched\" }\n";

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(
        root.join("go.mod"),
        format!("module covgapproj\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n"),
    )
    .expect("write go.mod");
    assert!(
        rt.block_on(ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false))
            .expect("install replace directive"),
        "fixture must install the socket-owned replace"
    );
    let copy_dir = root.join(GO_PATCHES_DIR).join(format!("{MODULE}@{VERSION}"));
    std::fs::create_dir_all(&copy_dir).expect("create go-patches copy");
    std::fs::write(copy_dir.join("discovered.go"), patched).expect("write patched copy");

    // The module cache the crawler discovers. All-lowercase coordinates:
    // no case-escaping in the on-disk directory name.
    let cache = tempfile::tempdir().expect("cache tempdir");
    let cache_mod_dir = cache.path().join(format!("{MODULE}@{VERSION}"));
    std::fs::create_dir_all(&cache_mod_dir).expect("create cache module dir");
    std::fs::write(cache_mod_dir.join("discovered.go"), original).expect("write cache copy");

    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let mut patches = serde_json::Map::new();
    patches.insert(
        PURL.to_string(),
        patch_entry_value(
            "abababab-abab-4bab-8bab-abababababab",
            "package/discovered.go",
            &git_sha256(original),
            &git_sha256(patched),
        ),
    );
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).expect("serialize manifest"),
    )
    .expect("write manifest");

    let (code, stdout, stderr) = common::run_with_env(
        root,
        &["rollback", "--json", "--yes", "--offline", "--lock-timeout", "5"],
        &[("GOMODCACHE", cache.path().to_str().expect("utf8 cache path"))],
    );
    assert_eq!(
        code, 0,
        "the discovered redirect rollback must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout, &stderr);
    assert_eq!(v["rolledBack"], json!(1), "stdout=\n{stdout}");
    let result = &v["results"][0];
    assert_eq!(result["purl"], json!(PURL), "stdout=\n{stdout}");
    // The DISCOVERED route: the result names the module-cache copy — the
    // undiscovered fallback reports the project root instead, so this
    // pins which path ran.
    let path = result["path"].as_str().expect("path string");
    assert!(
        path.ends_with("discovered@v1.2.3") && path != root.display().to_string(),
        "the target must be the discovered cache dir; path={path}"
    );
    assert!(
        result["filesRolledBack"]
            .as_array()
            .expect("filesRolledBack array")
            .iter()
            .any(|f| f == "package/discovered.go"),
        "the redirect teardown reports the patch's files; stdout=\n{stdout}"
    );
    assert!(
        rt.block_on(read_replace_entries(root))
            .iter()
            .all(|e| !(e.module == MODULE && e.socket_owned())),
        "the socket-owned replace directive must be dropped"
    );
    let go_mod = std::fs::read_to_string(root.join("go.mod")).expect("read go.mod");
    assert!(
        go_mod.contains(&format!("require {MODULE} {VERSION}")),
        "the require directive must survive; go.mod=\n{go_mod}"
    );
    assert!(!copy_dir.exists(), "the go-patches copy must be removed");
    assert_eq!(
        std::fs::read(cache_mod_dir.join("discovered.go")).expect("read cache copy"),
        original,
        "the module-cache copy must stay byte-identical"
    );
    let m: Value = serde_json::from_slice(
        &std::fs::read(socket.join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest is JSON");
    assert!(
        m["patches"].get(PURL).is_none(),
        "the rolled-back entry must leave the manifest; manifest={m}"
    );
}
