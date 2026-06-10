//! Real-yarn-classic capstone e2e for `socket-patch vendor` — the
//! committability proof for the yarn classic (v1 lockfile) flavor.
//!
//! Drives the REAL `corepack yarn@1.22.22` (network used for fixture setup
//! only):
//!   1. `yarn install` of a single dep (left-pad@1.3.0) into a tempdir.
//!   2. Hand-stage a `.socket/` manifest + blob whose before/after Git-blob
//!      hashes are computed from the ACTUAL installed bytes (a marker comment
//!      prepended to `index.js`).
//!   3. `socket-patch vendor --json --offline` (the real binary) — assert the
//!      deterministic tarball lands at `.socket/vendor/npm/<uuid>/…` and the
//!      `yarn.lock` block is rewired to
//!      `resolved "file:./.socket/vendor/npm/<uuid>/left-pad-1.3.0.tgz#<sha1>"`
//!      plus a recomputed `integrity sha512-…` line (spike Y2/Y6).
//!   4. **Fresh-checkout proof**: copy ONLY the committable files
//!      (package.json + yarn.lock + .socket/) to a new dir, point
//!      `YARN_CACHE_FOLDER` at an EMPTY dir, and run
//!      `corepack yarn install --frozen-lockfile --offline` — the patched
//!      bytes MUST be what yarn installs.
//!   5. Idempotency: re-running vendor leaves yarn.lock byte-identical.
//!   6. **Revert proof**: `vendor --revert` restores yarn.lock byte-for-byte
//!      to the pre-vendor snapshot and removes `.socket/vendor/` entirely.
//!
//! LOCAL capstone (not behind docker-e2e): skips with a `println` + return
//! when `corepack` (yarn classic) is unavailable or the fixture install
//! cannot reach the registry; every assertion after that is HARD.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

/// Canonical lowercase patch uuid (a dedicated path level under
/// `.socket/vendor/npm/`).
const UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab";
/// Marker prepended to the dep's entry point by the synthetic patch.
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
/// Pinned yarn classic via corepack (matches the spike).
const YARN_CLASSIC: &str = "yarn@1.22.22";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// `corepack <pm> --version` succeeds — the only liveness probe that
/// distinguishes "corepack present" from "this yarn flavor is fetchable".
fn has_corepack_pm(pm: &str) -> bool {
    Command::new("corepack")
        .args([pm, "--version"])
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `corepack <pm> <args>` in `cwd` with the given extra env, the download
/// prompt disabled, and every `SOCKET_*` var scrubbed.
fn corepack(cwd: &Path, pm: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm)
        .args(args)
        .current_dir(cwd)
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    scrub_socket_env(&mut cmd);
    cmd.output().expect("failed to run corepack")
}

/// Remove every ambient `SOCKET_*` var (so a developer's `SOCKET_DRY_RUN=1`
/// etc. can't flip behavior) and the PM cache var the harness controls.
fn scrub_socket_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy();
        if k.starts_with("SOCKET_") {
            cmd.env_remove(k.as_ref());
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("YARN_CACHE_FOLDER");
}

/// Run the socket-patch binary with a scrubbed environment.
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    scrub_socket_env(&mut cmd);
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Git-blob SHA-256 (`sha256("blob <len>\0" ++ bytes)`).
fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Write `.socket/manifest.json` + the after-hash blob so vendor runs fully
/// offline.
fn stage_patch(proj: &Path, purl: &str, file_key: &str, before: &[u8], after: &[u8]) {
    let socket = proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": { purl: {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { file_key: {
                "beforeHash": git_sha256(before),
                "afterHash": git_sha256(after),
            }},
            "vulnerabilities": {},
            "description": "capstone marker patch",
            "license": "MIT",
            "tier": "free",
        }}
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(after)), after).unwrap();
}

fn parse_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("vendor --json output is not JSON: {e}\nstdout:\n{stdout}"))
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

// ── the capstone ──────────────────────────────────────────────────────

#[test]
fn yarn_classic_vendor_fresh_checkout_frozen_offline_install_and_revert() {
    if !has_corepack_pm(YARN_CLASSIC) {
        println!(
            "SKIP e2e_vendor_yarn_classic_build: `corepack {YARN_CLASSIC}` unavailable \
             (corepack not installed or yarn classic not fetchable)"
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    // A registry dependency spec — vendoring leaves package.json untouched
    // and rewires only the lock block (spike Y2).
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"yarn-classic-capstone","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();

    // 1. REAL fixture: yarn classic install (network allowed here, private
    //    cache via YARN_CACHE_FOLDER).
    let cache = tmp.path().join("yarn-cache");
    let install = corepack(
        &proj,
        YARN_CLASSIC,
        &["install", "--no-progress"],
        &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_vendor_yarn_classic_build: fixture `yarn install` failed (registry \
             unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }

    let installed_index = proj.join("node_modules").join(DEP).join("index.js");
    let orig = std::fs::read(&installed_index).expect("installed index.js");
    assert!(
        !orig.starts_with(MARKER.as_bytes()),
        "pristine install must not carry the marker"
    );
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    let purl = format!("pkg:npm/{DEP}@{DEP_VERSION}");

    // 2. Manifest + blob from the ACTUAL installed bytes (npm-family file
    //    keys carry the `package/` prefix).
    stage_patch(&proj, &purl, "package/index.js", &orig, &patched);

    let lock_path = proj.join("yarn.lock");
    let lock_before = std::fs::read(&lock_path).expect("yarn.lock after yarn install");
    let lock_before_str = String::from_utf8(lock_before.clone()).unwrap();
    assert!(
        lock_before_str.contains("# yarn lockfile v1"),
        "fixture must be a yarn classic v1 lock:\n{lock_before_str}"
    );
    assert!(
        lock_before_str.contains("https://registry.yarnpkg.com/"),
        "pre-vendor block must resolve to the registry"
    );

    // 3. Vendor (offline: blob staged locally → zero network).
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");
    let applied = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "applied" && e["purl"] == purl.as_str())
        .unwrap_or_else(|| panic!("expected an applied event for {purl}: {env}"));
    assert!(
        applied.get("errorCode").is_none(),
        "clean apply event: {applied}"
    );

    // Artifact: deterministic tarball + informational marker in the uuid dir.
    let tgz_rel = format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}.tgz");
    assert!(
        proj.join(&tgz_rel).is_file(),
        "vendored tarball missing at {tgz_rel}"
    );
    assert!(
        proj.join(format!(
            ".socket/vendor/npm/{UUID}/socket-patch.vendor.json"
        ))
        .is_file(),
        "informational vendor marker missing"
    );
    assert!(
        proj.join(".socket/vendor/state.json").is_file(),
        "vendor ledger missing"
    );

    // Lock rewiring: `resolved "file:./<rel-tgz>#<sha1>"` + a recomputed
    // `integrity sha512-…` line (spike Y2: the `file:./` prefix and BOTH
    // hashes are load-bearing; a bare path 404s and the integrity is never
    // the inherited registry one).
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    let expected_resolved = format!("  resolved \"file:./{tgz_rel}#");
    assert!(
        lock_after.contains(&expected_resolved),
        "yarn.lock must resolve to the vendored tarball with a `file:./` prefix and #sha1 \
         fragment; got:\n{lock_after}"
    );
    assert!(
        !lock_after.contains("https://registry.yarnpkg.com/"),
        "the registry resolution must be gone from the rewired block:\n{lock_after}"
    );
    // The integrity line is the recomputed sha512 of OUR tarball — verify it
    // matches the bytes on disk (never inherited from the registry).
    let tgz_bytes = std::fs::read(proj.join(&tgz_rel)).unwrap();
    let our_sha512 = format!("sha512-{}", sha512_sri_b64(&tgz_bytes));
    assert!(
        lock_after.contains(&format!("integrity {our_sha512}")),
        "integrity must be the recomputed sha512 of the vendored tarball ({our_sha512}); \
         got:\n{lock_after}"
    );
    assert!(
        !lock_after.contains(
            "integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
        ),
        "the inherited registry integrity must NOT survive the rewrite"
    );
    // package.json is never touched by the lock-only yarn-classic wiring.
    let pkg_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join("package.json")).unwrap()).unwrap();
    assert_eq!(
        pkg_json["dependencies"][DEP].as_str(),
        Some(DEP_VERSION),
        "package.json dependency spec must stay registry-form"
    );
    eprintln!("VENDOR OK");

    // 4. FRESH-CHECKOUT PROOF: only the committable files, EMPTY yarn cache,
    //    spike-proven strictest invocation `--frozen-lockfile --offline`.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(&lock_path, fresh.join("yarn.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_cache = tmp.path().join("fresh-yarn-cache");
    let ci = corepack(
        &fresh,
        YARN_CLASSIC,
        &["install", "--frozen-lockfile", "--offline", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --frozen-lockfile --offline` must succeed from the \
         vendored tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let fresh_installed =
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        fresh_installed.starts_with(MARKER.as_bytes()),
        "yarn must install the PATCHED bytes from the vendored tarball; got:\n{}",
        String::from_utf8_lossy(&fresh_installed[..fresh_installed.len().min(120)])
    );
    assert_eq!(
        fresh_installed, patched,
        "fresh install must be byte-identical to the patched content"
    );
    eprintln!("FRESH INSTALL OK");

    // 5. Idempotency: a re-run exits 0 and leaves the lock byte-stable.
    let lock_wired = std::fs::read(&lock_path).unwrap();
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env2 = parse_envelope(&stdout);
    assert_eq!(env2["summary"]["failed"], 0, "re-run must not fail: {env2}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_wired,
        "re-vendor must leave yarn.lock byte-identical"
    );

    // 6. REVERT PROOF: lock restored byte-for-byte, artifacts gone.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "revert envelope: {renv}");
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "revert must restore yarn.lock byte-identical to the pre-vendor snapshot"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
    eprintln!("REVERT OK");
}

// ── tiny crypto shim (kept local so the file stays self-contained) ─────

/// Standard-base64-encoded sha512 of `bytes` — the body of the npm-family
/// `sha512-…` SRI integrity string.
fn sha512_sri_b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Sha512;
    let digest = Sha512::digest(bytes);
    base64::engine::general_purpose::STANDARD.encode(digest)
}
