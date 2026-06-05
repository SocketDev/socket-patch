//! End-to-end tests for the `scan` subcommand against the real Socket API.
//!
//! Exercises the `scan --apply` + opt-in GC pipeline introduced in v3.0:
//!
//! * `scan --json --apply --yes` adds, updates, and skips patches based on
//!   the existing manifest, emitting the `apply.patches[]` action vocabulary
//!   (`"added"`, `"updated"`, `"skipped"`).
//! * Read-only `scan --json` emits the `updates` array (PURLs whose UUID
//!   would change) and does NOT emit a `gc` field by default.
//! * `--prune` opts into garbage collection (manifest pruning + orphan
//!   file cleanup). Without it, scan leaves the manifest alone.
//! * `--sync` is sugar for `--apply --prune` — the canonical bot mode.
//! * `--dry-run` previews `--apply` / `--prune` / `--sync` actions
//!   without mutating disk.
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

/// These e2e tests are `#[ignore]`d and only execute when explicitly
/// requested (`--ignored`) — at which point npm is a hard prerequisite, not
/// an optional one. A silent `return` on missing npm would let the entire
/// e2e suite report green without exercising a single assertion, which is
/// exactly the failure mode this audit guards against. Fail loudly instead.
fn require_npm() {
    assert!(
        has_command("npm"),
        "npm not found on PATH; the e2e_scan suite requires npm. \
         Install npm before running with --ignored."
    );
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
    require_npm();

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
    // Guard against the "scan did nothing but still said success" failure
    // mode (e.g. crawler found 0 packages, or every API batch errored and
    // the command still reported success): a real apply must have scanned
    // minimist and found at least one free patch for it.
    assert!(
        v["scannedPackages"].as_u64().unwrap_or(0) >= 1,
        "scan must have crawled at least one package; got {}",
        v["scannedPackages"]
    );
    assert!(
        v["freePatches"].as_u64().unwrap_or(0) >= 1,
        "API must have returned at least one free patch; got {}",
        v["freePatches"]
    );
    let patches = v["apply"]["patches"].as_array().expect("apply.patches array");
    let minimist = patches
        .iter()
        .find(|p| p["purl"] == NPM_PURL)
        .expect("apply.patches should include minimist");
    assert_eq!(minimist["action"], "added");
    let reported_uuid = minimist["uuid"].as_str().expect("uuid must be present");
    assert!(!reported_uuid.is_empty(), "uuid must be non-empty");

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
    // The persisted manifest must record the *same* UUID the apply output
    // reported — not some other patch, and not a stale/empty value.
    assert_eq!(
        manifest["patches"][NPM_PURL]["uuid"].as_str(),
        Some(reported_uuid),
        "manifest uuid must match the uuid reported in apply.patches",
    );
}

/// Re-running `scan --json --apply --yes` after the patch is already in
/// the manifest reports `action: "skipped"` and leaves the file alone.
#[test]
#[ignore]
fn test_scan_apply_json_skips_existing() {
    require_npm();
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    let index_js = cwd.join("node_modules/minimist/index.js");
    assert_run_ok(cwd, &["scan", "--json", "--apply", "--yes"], "first run");
    // Capture the exact patched bytes after the first run. A correct
    // "skipped" re-run must leave the file *byte-for-byte identical*; merely
    // checking `!= BEFORE_HASH` would also pass if the second run re-applied
    // the patch or corrupted the file into some other non-pristine state.
    let hash_after_first = git_sha256_file(&index_js);
    assert_ne!(
        hash_after_first, BEFORE_HASH,
        "first run should have patched the file",
    );

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
    // The re-run is a no-op: the file must be exactly what the first run
    // produced.
    assert_eq!(
        git_sha256_file(&index_js),
        hash_after_first,
        "a skipped re-run must leave the patched file byte-for-byte identical",
    );
}

/// Seeding a manifest with a fake old UUID for the minimist PURL forces
/// `scan --apply` into the `"updated"` branch — the per-patch record
/// carries `oldUuid` matching the fake.
#[test]
#[ignore]
fn test_scan_apply_json_updates_existing() {
    require_npm();
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
    require_npm();
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
    require_npm();
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    let index_js = cwd.join("node_modules/minimist/index.js");
    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "precondition: file must be unpatched before read-only scan",
    );
    let (stdout, _) = assert_run_ok(cwd, &["scan", "--json"], "scan --json (no manifest)");
    let v = parse_scan_json(&stdout);

    // Positive proof the read-only scan actually *did the read* — without
    // this, a scan that crawled 0 packages or whose API batches all failed
    // would still trivially satisfy the "no mutation" assertions below and
    // falsely pass. A real read-only scan of an installed minimist must
    // report it as scanned with a free patch available.
    assert_eq!(v["status"], "success");
    assert!(
        v["scannedPackages"].as_u64().unwrap_or(0) >= 1,
        "read-only scan must crawl at least one package; got {}",
        v["scannedPackages"]
    );
    assert!(
        v["freePatches"].as_u64().unwrap_or(0) >= 1,
        "read-only scan must surface at least one free patch; got {}",
        v["freePatches"]
    );
    let packages = v["packages"].as_array().expect("packages array");
    assert!(
        packages.iter().any(|p| p["purl"] == NPM_PURL),
        "read-only scan must list minimist among discovered packages; got {packages:?}"
    );

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

/// When a previously-patched package is uninstalled, passing `--prune`
/// (or `--sync`) on the next `scan --apply --yes` prunes its manifest
/// entry and sweeps the orphan blobs. JSON output reports it in
/// `gc.prunedManifestEntries`.
#[test]
#[ignore]
fn test_scan_apply_prune_prunes_uninstalled_package() {
    require_npm();
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    // First run — patch is added (no --prune needed for the apply step).
    assert_run_ok(cwd, &["scan", "--json", "--apply", "--yes"], "initial apply");
    assert!(cwd.join(".socket/manifest.json").exists());

    npm_run(cwd, &["uninstall", "minimist"]);
    // Reinstall a placeholder package so the crawl still finds *something*
    // (scan with zero scanned packages skips GC entirely).
    npm_run(cwd, &["install", "left-pad@1.3.0"]);

    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--apply", "--yes", "--prune"],
        "scan with --prune after uninstall",
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

/// Default `scan --apply --yes` (no `--prune`) leaves manifest entries
/// for uninstalled packages alone. The `gc` field is omitted entirely
/// from JSON output — users wanting cleanup must opt in.
#[test]
#[ignore]
fn test_scan_apply_default_keeps_uninstalled_entries() {
    require_npm();
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    assert_run_ok(cwd, &["scan", "--json", "--apply", "--yes"], "initial apply");
    npm_run(cwd, &["uninstall", "minimist"]);
    npm_run(cwd, &["install", "left-pad@1.3.0"]);

    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--apply", "--yes"],
        "scan without --prune",
    );
    let v = parse_scan_json(&stdout);

    // Positive proof the scan actually executed an apply pass — otherwise a
    // scan that crawled 0 packages (or whose API batches all failed) would
    // emit no `gc` field and leave the manifest untouched, trivially passing
    // the negative assertions below for entirely the wrong reason.
    assert_eq!(v["status"], "success");
    assert!(
        v["scannedPackages"].as_u64().unwrap_or(0) >= 1,
        "scan must have crawled at least one (installed) package; got {}",
        v["scannedPackages"]
    );
    assert!(
        v["apply"]["patches"].is_array(),
        "an apply run must emit the apply.patches array; got {}",
        v["apply"]
    );

    assert!(
        v.get("gc").is_none() || v["gc"].is_null(),
        "gc field must be omitted when --prune is not set; got {}",
        v["gc"]
    );

    let manifest = read_manifest_file(cwd);
    assert!(
        !manifest["patches"][NPM_PURL].is_null(),
        "minimist entry must survive when --prune is not set"
    );
}

/// Even without manifest changes, a stray orphan blob file in
/// `.socket/blobs/` is removed by the next `scan --apply --yes --prune`
/// (GC must be opt-in via `--prune` or `--sync`).
#[test]
#[ignore]
fn test_scan_apply_prune_cleans_orphan_blobs() {
    require_npm();
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);
    assert_run_ok(cwd, &["scan", "--json", "--apply", "--yes"], "initial apply");

    let index_js = cwd.join("node_modules/minimist/index.js");
    let patched_hash = git_sha256_file(&index_js);
    assert_ne!(
        patched_hash, BEFORE_HASH,
        "precondition: initial apply must have patched the file",
    );

    // Plant an orphan blob. Not referenced by any manifest entry, so the
    // GC pass must reap it.
    let blobs_dir = cwd.join(".socket/blobs");
    std::fs::create_dir_all(&blobs_dir).expect("create blobs dir");
    // Snapshot the legitimate (manifest-referenced) blobs that exist *before*
    // we plant the orphan. A correct GC reaps ONLY the orphan; a buggy GC
    // that nukes the whole blob store would also satisfy `removedBlobs >= 1`
    // and `!orphan.exists()`, so we assert every pre-existing blob survives.
    let legit_blobs_before: Vec<std::ffi::OsString> = std::fs::read_dir(&blobs_dir)
        .expect("read blobs dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    let orphan = blobs_dir.join(FAKE_ORPHAN_HASH);
    std::fs::write(&orphan, b"junk").expect("plant orphan");
    assert!(orphan.exists());

    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--apply", "--yes", "--prune"],
        "scan --prune with orphan blob present",
    );
    let v = parse_scan_json(&stdout);
    assert_eq!(v["status"], "success");

    let removed = v["gc"]["removedBlobs"]
        .as_u64()
        .expect("gc.removedBlobs should be a number");
    assert!(
        removed >= 1,
        "gc should report at least 1 removed blob, got {removed}"
    );
    assert!(!orphan.exists(), "orphan blob should be deleted");

    // The orphan was the only unreferenced blob: GC must not have touched any
    // legitimate, manifest-referenced blob.
    for name in &legit_blobs_before {
        assert!(
            blobs_dir.join(name).exists(),
            "GC must not delete the referenced blob {name:?}; over-broad cleanup detected",
        );
    }

    // minimist is still installed, so its manifest entry must survive the
    // prune, and the patched file on disk must not have been reverted.
    let manifest = read_manifest_file(cwd);
    assert!(
        manifest["patches"][NPM_PURL].is_object(),
        "still-installed minimist must NOT be pruned by GC"
    );
    assert_eq!(
        git_sha256_file(&index_js),
        patched_hash,
        "GC must not revert the patched file of a still-installed package",
    );
}

/// `scan --json --dry-run --sync --yes` previews the full sync action:
/// `apply.patches[]` is populated with would-be actions and `gc`
/// reports `prunable*`/`orphan*` counts, but nothing on disk changes.
#[test]
#[ignore]
fn test_scan_dry_run_sync_previews_apply_and_gc() {
    require_npm();
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);
    // Set up: apply once to create a manifest, then uninstall + plant
    // an orphan so there's prune + cleanup work to preview.
    assert_run_ok(cwd, &["scan", "--json", "--apply", "--yes"], "initial apply");

    npm_run(cwd, &["uninstall", "minimist"]);
    npm_run(cwd, &["install", "left-pad@1.3.0"]);

    let blobs_dir = cwd.join(".socket/blobs");
    let orphan = blobs_dir.join(FAKE_ORPHAN_HASH);
    std::fs::write(&orphan, b"junk").expect("plant orphan");

    // Capture pre-state to verify dry-run is non-mutating.
    let pre_manifest = read_manifest_file(cwd);

    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--dry-run", "--sync", "--yes"],
        "scan --dry-run --sync",
    );
    let v = parse_scan_json(&stdout);

    // Preview output present.
    let prunable = v["gc"]["prunableManifestEntries"]
        .as_array()
        .expect("gc.prunableManifestEntries array");
    assert!(
        prunable.iter().any(|p| p == NPM_PURL),
        "preview should list minimist as prunable; got {prunable:?}"
    );
    assert!(
        v["gc"]["orphanBlobs"].as_u64().unwrap_or(0) >= 1,
        "preview should count at least 1 orphan blob"
    );
    assert_eq!(v["apply"]["dryRun"], true);
    // The apply preview must still emit the stable `patches[]` shape even
    // when nothing is selectable, so a bot can parse it unconditionally.
    assert!(
        v["apply"]["patches"].is_array(),
        "dry-run apply must emit a patches array; got {}",
        v["apply"]
    );

    // Verify non-mutation.
    assert!(orphan.exists(), "dry-run must not delete orphan blob");
    let post_manifest = read_manifest_file(cwd);
    assert_eq!(
        pre_manifest, post_manifest,
        "dry-run must leave manifest exactly as it was"
    );
}

/// `scan --json` (no `--prune`/`--sync`) emits NO `gc` field, even when
/// the manifest has prunable entries and there are orphan files on
/// disk. GC information is opt-in per the v3.0 contract.
#[test]
#[ignore]
fn test_scan_json_no_gc_field_without_prune() {
    require_npm();
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

    let (stdout, _) = assert_run_ok(cwd, &["scan", "--json"], "scan --json (no prune)");
    let v = parse_scan_json(&stdout);

    // Positive proof the read-only scan actually ran a discovery pass — a
    // scan that crawled nothing would emit no gc field and pass the negative
    // assertion below for the wrong reason. left-pad is the installed package
    // here (minimist was uninstalled), so at minimum one package is scanned.
    assert_eq!(v["status"], "success");
    assert!(
        v["scannedPackages"].as_u64().unwrap_or(0) >= 1,
        "read-only scan must crawl at least one package; got {}",
        v["scannedPackages"]
    );

    assert!(
        v.get("gc").is_none() || v["gc"].is_null(),
        "scan --json must NOT emit gc when --prune is not set; got {}",
        v["gc"]
    );
}

/// `scan --json --sync --yes` does the full sync — discover + apply +
/// prune + sweep — in one invocation. Mirrors what an auto-update bot
/// would run as the single command.
#[test]
#[ignore]
fn test_scan_sync_yes_full_lifecycle() {
    require_npm();
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    // Run 1: --sync adds the patch (no prior state to prune).
    let (stdout1, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--sync", "--yes"],
        "first --sync apply",
    );
    let v1 = parse_scan_json(&stdout1);
    let patches = v1["apply"]["patches"]
        .as_array()
        .expect("first sync should populate apply.patches");
    assert!(
        patches.iter().any(|p| p["purl"] == NPM_PURL && p["action"] == "added"),
        "first sync should add the minimist patch"
    );
    assert_eq!(v1["status"], "success");
    // gc field should be present (--sync implies --prune). It must be a real GC
    // result, not the `{"skipped": true}` short-circuit (which `is_object()`
    // would also accept), and on this first run there is nothing installed-then-
    // uninstalled, so it must prune nothing.
    let gc1 = v1["gc"].as_object().expect("gc must be emitted under --sync");
    assert!(
        gc1.get("skipped") != Some(&serde_json::Value::Bool(true)),
        "GC must not be skipped on a --sync run that scanned packages; got {:?}",
        gc1
    );
    let pruned1 = gc1["prunedManifestEntries"]
        .as_array()
        .expect("first-run gc must report prunedManifestEntries");
    assert!(
        pruned1.is_empty(),
        "first --sync run must prune nothing (minimist is still installed); got {pruned1:?}"
    );

    // Uninstall + plant orphan, then run --sync again.
    npm_run(cwd, &["uninstall", "minimist"]);
    npm_run(cwd, &["install", "left-pad@1.3.0"]);
    let blobs_dir = cwd.join(".socket/blobs");
    let orphan = blobs_dir.join(FAKE_ORPHAN_HASH);
    std::fs::write(&orphan, b"junk").expect("plant orphan");

    // Run 2: --sync prunes minimist + sweeps the orphan.
    let (stdout2, _) = assert_run_ok(
        cwd,
        &["scan", "--json", "--sync", "--yes"],
        "second --sync after uninstall",
    );
    let v2 = parse_scan_json(&stdout2);
    let pruned = v2["gc"]["prunedManifestEntries"]
        .as_array()
        .expect("gc.prunedManifestEntries array");
    assert!(
        pruned.iter().any(|p| p == NPM_PURL),
        "minimist should be pruned by --sync after uninstall; got {pruned:?}"
    );
    assert!(!orphan.exists(), "orphan should be reaped");
    let manifest = read_manifest_file(cwd);
    assert!(
        manifest["patches"][NPM_PURL].is_null(),
        "manifest must not retain minimist after --sync prune"
    );
}
