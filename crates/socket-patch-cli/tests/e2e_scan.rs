//! End-to-end tests for the `scan` subcommand against the real Socket API.
//!
//! Exercises the `scan --apply` + GC pipeline introduced in v3.0:
//!
//! * `scan --json --apply --yes` adds, updates, and skips patches based on
//!   the existing manifest, emitting the `apply.patches[]` action vocabulary
//!   (`"added"`, `"updated"`, `"skipped"`).
//! * Read-only `scan --json` emits the `updates` array (PURLs whose UUID
//!   would change) and a non-mutating `gc` preview.
//! * GC runs by default after apply — prunes manifest entries for
//!   uninstalled packages, sweeps orphan blob files.
//! * `--no-prune` opts out of all GC.
//!
//! Uses the same minimist@1.2.2 patch fixture as `e2e_npm.rs`. Tests are
//! marked `#[ignore]` so they only run with `--ignored`, matching the
//! existing e2e gating in `.github/workflows/ci.yml`.
//!
//! # Prerequisites
//! - `npm` on PATH
//! - Network access to `patches-api.socket.dev` and `registry.npmjs.org`
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --test e2e_scan -- --ignored
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants (shared with e2e_npm; duplicated here because Rust integration
// test binaries don't share modules without `tests/common/mod.rs` tricks
// that the existing suite explicitly avoided).
// ---------------------------------------------------------------------------

const NPM_PURL: &str = "pkg:npm/minimist@1.2.2";

/// Git SHA-256 of the *unpatched* `index.js` shipped with minimist 1.2.2.
/// Used to assert "file was patched" (no longer matches BEFORE_HASH).
/// The specific `AFTER_HASH` isn't pinned here because the upstream API
/// can serve multiple free patches over time with different fix bytes.
const BEFORE_HASH: &str = "311f1e893e6eac502693fad8617dcf5353a043ccc0f7b4ba9fe385e838b67a10";

/// 64-hex-char placeholder used for orphan-blob fixtures. Not a real
/// blob hash — picked so it can't accidentally collide with anything
/// the API would return.
const FAKE_ORPHAN_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Fake UUID we plant in the manifest to force `scan --apply` into the
/// `"updated"` branch.
const FAKE_OLD_UUID: &str = "11111111-1111-4111-8111-111111111111";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn git_sha256_file(path: &Path) -> String {
    let content = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    git_sha256(&content)
}

fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let out: Output = Command::new(binary())
        .args(args)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_API_URL")
        .output()
        .expect("failed to execute socket-patch binary");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

fn assert_run_ok(cwd: &Path, args: &[&str], context: &str) -> (String, String) {
    let (code, stdout, stderr) = run(cwd, args);
    assert_eq!(
        code, 0,
        "{context} failed (exit {code}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    (stdout, stderr)
}

fn npm_run(cwd: &Path, args: &[&str]) {
    let out = Command::new("npm")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to run npm");
    assert!(
        out.status.success(),
        "npm {args:?} failed (exit {:?}).\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn write_package_json(cwd: &Path) {
    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"e2e-scan-test","version":"0.0.0","private":true}"#,
    )
    .expect("write package.json");
}

fn parse_scan_json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("scan emitted invalid JSON: {e}\nstdout:\n{stdout}"))
}

/// Parse the persisted `.socket/manifest.json`. Panics with a useful
/// message if it doesn't exist or is malformed.
fn read_manifest_file(cwd: &Path) -> serde_json::Value {
    let path = cwd.join(".socket/manifest.json");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("manifest is not valid JSON: {e}\n{content}"))
}

/// Write a manifest with the given (PURL → UUID) entries. Used to seed
/// the "updated" and "prune" test scenarios. Mimics the shape produced
/// by `download_and_apply_patches` — only the keys we care about.
fn write_seed_manifest(cwd: &Path, purl: &str, uuid: &str) {
    let socket_dir = cwd.join(".socket");
    std::fs::create_dir_all(&socket_dir).expect("create .socket");
    let manifest = serde_json::json!({
        "version": 1,
        "patches": {
            purl: {
                "uuid": uuid,
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {},
                "vulnerabilities": {},
                "description": "",
                "license": "",
                "tier": "free",
            }
        }
    });
    std::fs::write(
        socket_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write seed manifest");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `scan --json --apply --yes` against a fresh install should report a
/// single `action: "added"` entry for the minimist patch, write the
/// manifest, and patch the file on disk. The specific UUID/afterHash
/// the upstream API serves can change over time (multiple free patches
/// may exist for the same PURL), so the test asserts the contract
/// shape rather than exact bytes — action vocabulary, PURL match, and
/// "file was patched" (i.e. no longer matches BEFORE_HASH).
#[test]
#[ignore]
fn test_scan_apply_json_adds_new_patch() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    let index_js = cwd.join("node_modules/minimist/index.js");
    assert_eq!(git_sha256_file(&index_js), BEFORE_HASH);

    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--apply", "--yes"],
        "scan --json --apply --yes (fresh)",
    );
    let v = parse_scan_json(&stdout);

    assert_eq!(v["status"], "success");
    let patches = v["apply"]["patches"].as_array().expect("apply.patches array");
    let minimist = patches
        .iter()
        .find(|p| p["purl"] == NPM_PURL)
        .expect("apply.patches should include minimist");
    assert_eq!(minimist["action"], "added");
    assert!(minimist["uuid"].is_string(), "uuid must be present");

    assert_ne!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "file should have been patched (no longer BEFORE_HASH)",
    );
    let manifest = read_manifest_file(cwd);
    assert!(
        manifest["patches"][NPM_PURL].is_object(),
        "manifest must record an entry for {NPM_PURL}"
    );
}

/// Re-running `scan --json --apply --yes` after the patch is already in
/// the manifest reports `action: "skipped"` and leaves the file alone.
#[test]
#[ignore]
fn test_scan_apply_json_skips_existing() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    assert_run_ok(cwd, &["scan", "--json", "--apply", "--yes"], "first run");
    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--apply", "--yes"],
        "second run",
    );
    let v = parse_scan_json(&stdout);

    let patches = v["apply"]["patches"].as_array().expect("apply.patches array");
    let minimist = patches
        .iter()
        .find(|p| p["purl"] == NPM_PURL)
        .expect("apply.patches should include minimist on re-run");
    assert_eq!(minimist["action"], "skipped");
    // The first run already patched the file — second run shouldn't
    // touch it, so the hash should still differ from BEFORE_HASH.
    assert_ne!(
        git_sha256_file(&cwd.join("node_modules/minimist/index.js")),
        BEFORE_HASH,
        "file should still be patched after a no-op re-run",
    );
}

/// Seeding a manifest with a fake old UUID for the minimist PURL forces
/// `scan --apply` into the `"updated"` branch — the per-patch record
/// carries `oldUuid` matching the fake.
#[test]
#[ignore]
fn test_scan_apply_json_updates_existing() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);
    write_seed_manifest(cwd, NPM_PURL, FAKE_OLD_UUID);

    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--apply", "--yes"],
        "scan with seeded fake UUID",
    );
    let v = parse_scan_json(&stdout);

    let patches = v["apply"]["patches"].as_array().expect("apply.patches array");
    let minimist = patches
        .iter()
        .find(|p| p["purl"] == NPM_PURL)
        .expect("apply.patches should include minimist");
    assert_eq!(minimist["action"], "updated");
    assert_eq!(minimist["oldUuid"], FAKE_OLD_UUID);
    assert!(
        minimist["uuid"].is_string(),
        "uuid must be present (specific value can drift as API serves multiple patches)",
    );
    assert_ne!(
        minimist["uuid"], FAKE_OLD_UUID,
        "new uuid must differ from the seeded fake oldUuid",
    );

    let manifest = read_manifest_file(cwd);
    let new_uuid = manifest["patches"][NPM_PURL]["uuid"]
        .as_str()
        .expect("manifest must record a new uuid");
    assert_ne!(new_uuid, FAKE_OLD_UUID, "manifest must reflect the update");
}

/// `scan --json` (without `--apply`) is read-only: it lists available
/// patches and an `updates` array reflecting manifest-vs-API drift, but
/// does not mutate `.socket/manifest.json` or the file on disk.
#[test]
#[ignore]
fn test_scan_json_read_only_emits_updates_array() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);
    write_seed_manifest(cwd, NPM_PURL, FAKE_OLD_UUID);

    let index_js = cwd.join("node_modules/minimist/index.js");
    assert_eq!(git_sha256_file(&index_js), BEFORE_HASH);

    let (stdout, _) = assert_run_ok(cwd, &["scan", "--json"], "scan --json (read-only)");
    let v = parse_scan_json(&stdout);

    let updates = v["updates"].as_array().expect("updates array");
    assert_eq!(updates.len(), 1, "expected exactly one update for minimist");
    assert_eq!(updates[0]["purl"], NPM_PURL);
    assert_eq!(updates[0]["oldUuid"], FAKE_OLD_UUID);
    assert!(updates[0]["newUuid"].is_string(), "newUuid must be present");
    assert_ne!(
        updates[0]["newUuid"], FAKE_OLD_UUID,
        "newUuid must differ from the seeded oldUuid",
    );

    // No mutation: seeded manifest UUID stays put, file stays unpatched.
    let manifest = read_manifest_file(cwd);
    assert_eq!(manifest["patches"][NPM_PURL]["uuid"], FAKE_OLD_UUID);
    assert_eq!(git_sha256_file(&index_js), BEFORE_HASH);
}

/// `scan --json` against a project with no existing manifest does NOT
/// create one — read-only is read-only.
#[test]
#[ignore]
fn test_scan_json_read_only_no_mutation() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    let index_js = cwd.join("node_modules/minimist/index.js");
    let (_, _) = assert_run_ok(cwd, &["scan", "--json"], "scan --json (no manifest)");

    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "scan --json must not create a manifest"
    );
    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "scan --json must not patch files"
    );
}

/// When a previously-patched package is uninstalled, the next
/// `scan --apply --yes` should prune its manifest entry and sweep the
/// orphan blobs. JSON output reports it in `gc.prunedManifestEntries`.
#[test]
#[ignore]
fn test_scan_apply_prunes_uninstalled_package_by_default() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    // First run — patch is added.
    assert_run_ok(cwd, &["scan", "--json", "--apply", "--yes"], "initial apply");
    assert!(cwd.join(".socket/manifest.json").exists());

    // Simulate uninstall: drop minimist from package.json + node_modules.
    npm_run(cwd, &["uninstall", "minimist"]);
    // Reinstall a placeholder package so the crawl still finds *something*
    // (`scan` with zero scanned packages skips GC entirely).
    npm_run(cwd, &["install", "left-pad@1.3.0"]);

    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--apply", "--yes"],
        "scan after uninstall",
    );
    let v = parse_scan_json(&stdout);

    let pruned = v["gc"]["prunedManifestEntries"]
        .as_array()
        .expect("gc.prunedManifestEntries array");
    assert!(
        pruned.iter().any(|p| p == NPM_PURL),
        "minimist should be pruned from manifest after uninstall; got {pruned:?}"
    );

    let manifest = read_manifest_file(cwd);
    assert!(
        manifest["patches"][NPM_PURL].is_null(),
        "minimist entry should be removed from manifest"
    );
}

/// `--no-prune` opts out of GC entirely: manifest entries for
/// uninstalled packages survive, and the `gc` sub-object reports
/// `skipped: true`.
#[test]
#[ignore]
fn test_scan_apply_no_prune_keeps_uninstalled_entries() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    assert_run_ok(cwd, &["scan", "--json", "--apply", "--yes"], "initial apply");
    npm_run(cwd, &["uninstall", "minimist"]);
    npm_run(cwd, &["install", "left-pad@1.3.0"]);

    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--apply", "--yes", "--no-prune"],
        "scan with --no-prune",
    );
    let v = parse_scan_json(&stdout);

    assert_eq!(v["gc"]["skipped"], true, "gc should report skipped: true");

    let manifest = read_manifest_file(cwd);
    assert!(
        !manifest["patches"][NPM_PURL].is_null(),
        "minimist entry should survive when --no-prune is set"
    );
}

/// Even without manifest changes, a stray orphan blob file in
/// `.socket/blobs/` is removed by the next `scan --apply --yes`.
#[test]
#[ignore]
fn test_scan_apply_cleans_orphan_blobs() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);
    assert_run_ok(cwd, &["scan", "--json", "--apply", "--yes"], "initial apply");

    // Plant an orphan blob. Not referenced by any manifest entry, so the
    // GC pass must reap it.
    let blobs_dir = cwd.join(".socket/blobs");
    std::fs::create_dir_all(&blobs_dir).expect("create blobs dir");
    let orphan = blobs_dir.join(FAKE_ORPHAN_HASH);
    std::fs::write(&orphan, b"junk").expect("plant orphan");
    assert!(orphan.exists());

    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--apply", "--yes"],
        "scan with orphan blob present",
    );
    let v = parse_scan_json(&stdout);

    let removed = v["gc"]["removedBlobs"]
        .as_u64()
        .expect("gc.removedBlobs should be a number");
    assert!(
        removed >= 1,
        "gc should report at least 1 removed blob, got {removed}"
    );
    assert!(!orphan.exists(), "orphan blob should be deleted");
}

/// Read-only `scan --json` previews GC actions without performing them:
/// the `gc.prunableManifestEntries` lists what *would* be pruned, and
/// `gc.orphanBlobs` counts what *would* be reaped. Nothing changes on
/// disk afterward.
#[test]
#[ignore]
fn test_scan_json_read_only_gc_preview() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);
    assert_run_ok(cwd, &["scan", "--json", "--apply", "--yes"], "initial apply");

    npm_run(cwd, &["uninstall", "minimist"]);
    npm_run(cwd, &["install", "left-pad@1.3.0"]);

    let blobs_dir = cwd.join(".socket/blobs");
    let orphan = blobs_dir.join(FAKE_ORPHAN_HASH);
    std::fs::write(&orphan, b"junk").expect("plant orphan");

    let (stdout, _) = assert_run_ok(cwd, &["scan", "--json"], "scan --json (preview)");
    let v = parse_scan_json(&stdout);

    let prunable = v["gc"]["prunableManifestEntries"]
        .as_array()
        .expect("gc.prunableManifestEntries array");
    assert!(
        prunable.iter().any(|p| p == NPM_PURL),
        "preview should list minimist as prunable; got {prunable:?}"
    );

    let orphan_blobs = v["gc"]["orphanBlobs"]
        .as_u64()
        .expect("gc.orphanBlobs is a count");
    assert!(
        orphan_blobs >= 1,
        "preview should count at least 1 orphan blob, got {orphan_blobs}"
    );

    // Preview is non-mutating: orphan + manifest entry must still be there.
    assert!(orphan.exists(), "preview must not delete orphan blob");
    let manifest = read_manifest_file(cwd);
    assert!(
        !manifest["patches"][NPM_PURL].is_null(),
        "preview must not prune the manifest"
    );
}
