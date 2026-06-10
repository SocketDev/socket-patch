//! Real-bun capstone e2e for `socket-patch vendor` — the committability
//! proof for the bun (text `bun.lock`) flavor.
//!
//! Drives the REAL `bun` (network used for fixture setup only):
//!   1. `bun install` of left-pad@1.3.0 into a tempdir (private
//!      `BUN_INSTALL_CACHE_DIR`). bun 1.3.x writes the text `bun.lock` by
//!      default; `--save-text-lockfile` is passed as a belt-and-braces guard
//!      against a future binary-lockfile default.
//!   2. Hand-stage a `.socket/` manifest + blob from the ACTUAL installed
//!      bytes (a marker comment prepended to `index.js`).
//!   3. `socket-patch vendor --json --offline` — assert the deterministic
//!      tarball lands at `.socket/vendor/npm/<uuid>/…` and the bun.lock
//!      `packages` entry is rewritten from the registry 4-tuple to the
//!      local-tarball 3-tuple `["<name>@<rel-path>", {deps}, "sha512-<ours>"]`
//!      (spike BN1/BN3). package.json is left UNTOUCHED.
//!   4. **Fresh-checkout proof**: copy ONLY the committable files
//!      (package.json + bun.lock + .socket/) to a new dir, an EMPTY
//!      `BUN_INSTALL_CACHE_DIR`, and run the spike's strictest invocation
//!      `bun install --frozen-lockfile` — the patched bytes MUST be what bun
//!      installs (BN7).
//!   5. Idempotency: re-running vendor leaves bun.lock byte-identical.
//!   6. **Revert proof**: `vendor --revert` restores bun.lock byte-for-byte
//!      and removes `.socket/vendor/` entirely.
//!
//! LOCAL capstone (not behind docker-e2e): skips with a `println` + return
//! when `bun` is unavailable or the fixture install cannot reach the
//! registry; every assertion after that is HARD.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

const UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `bun <args>` in `cwd` with the given private cache dir and every
/// `SOCKET_*` var scrubbed.
fn bun(cwd: &Path, args: &[&str], cache_dir: &Path) -> Output {
    let mut cmd = Command::new("bun");
    cmd.args(args)
        .current_dir(cwd)
        .env("BUN_INSTALL_CACHE_DIR", cache_dir);
    scrub_socket_env(&mut cmd);
    cmd.output().expect("failed to run bun")
}

/// Remove ambient `SOCKET_*` vars and the bun cache env the harness controls
/// (always passed explicitly).
fn scrub_socket_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy();
        if k.starts_with("SOCKET_") {
            cmd.env_remove(k.as_ref());
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("BUN_INSTALL_CACHE_DIR");
}

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

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

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
fn bun_vendor_fresh_checkout_frozen_install_and_revert() {
    if !has_command("bun") {
        println!("SKIP e2e_vendor_bun_build: `bun` not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"bun-capstone","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();

    // 1. REAL fixture: bun install (network allowed here, private cache).
    //    `--save-text-lockfile` guarantees the text bun.lock vendor wires
    //    (bun 1.3.x already defaults to it; the flag future-proofs the test).
    let cache = tmp.path().join("bun-cache");
    let install = bun(
        &proj,
        &["install", "--save-text-lockfile"],
        &cache,
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_vendor_bun_build: fixture `bun install` failed (registry \
             unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }
    let lock_path = proj.join("bun.lock");
    if !lock_path.is_file() {
        println!(
            "SKIP e2e_vendor_bun_build: bun produced no text bun.lock (binary lockfile?) — \
             this bun version's default lockfile is not the wirable text form"
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

    stage_patch(&proj, &purl, "package/index.js", &orig, &patched);

    let pkg_path = proj.join("package.json");
    let lock_before = std::fs::read(&lock_path).expect("bun.lock after bun install");
    let pkg_before = std::fs::read(&pkg_path).expect("package.json");
    let lock_before_str = String::from_utf8(lock_before.clone()).unwrap();
    assert!(
        lock_before_str.contains("\"lockfileVersion\": 1"),
        "fixture must be a bun text lockfileVersion 1:\n{lock_before_str}"
    );
    // Pre-vendor: the registry 4-tuple `["left-pad@1.3.0", "", {}, "sha512-…"]`.
    assert!(
        lock_before_str.contains(&format!("\"{DEP}@{DEP_VERSION}\", \"\"")),
        "pre-vendor packages entry must be the registry 4-tuple:\n{lock_before_str}"
    );

    // 3. Vendor (offline).
    let (code, stdout, stderr) = run_socket(
        &proj,
        &["vendor", "--json", "--offline", "--cwd", proj.to_str().unwrap()],
    );
    assert_eq!(code, 0, "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
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
    assert!(applied.get("errorCode").is_none(), "clean apply event: {applied}");

    let tgz_rel = format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}.tgz");
    assert!(proj.join(&tgz_rel).is_file(), "vendored tarball missing at {tgz_rel}");
    assert!(
        proj.join(format!(".socket/vendor/npm/{UUID}/socket-patch.vendor.json"))
            .is_file(),
        "informational vendor marker missing"
    );
    assert!(
        proj.join(".socket/vendor/state.json").is_file(),
        "vendor ledger missing"
    );

    // bun.lock packages entry rewritten to the local-tarball 3-tuple:
    // element 0 = `<name>@<bare-rel-path>` (no `file:`/`./`), the deps object
    // shifts to index 1, integrity is the recomputed sha512 of OUR tarball.
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock_after.contains(&format!("\"{DEP}@{tgz_rel}\", {{}}, \"sha512-")),
        "bun.lock packages entry must be the local-tarball 3-tuple; got:\n{lock_after}"
    );
    assert!(
        !lock_after.contains(&format!("\"{DEP}@{DEP_VERSION}\", \"\"")),
        "the registry 4-tuple must be gone after the rewrite:\n{lock_after}"
    );
    assert!(
        !lock_after.contains(
            "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
        ),
        "the inherited registry integrity must NOT survive the rewrite:\n{lock_after}"
    );
    // package.json is left untouched by the lock-only bun wiring.
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        pkg_before,
        "bun vendoring is lock-only; package.json must stay byte-identical"
    );
    eprintln!("VENDOR OK");

    // 4. FRESH-CHECKOUT PROOF: committable files only, EMPTY cache,
    //    spike-proven `--frozen-lockfile`.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&pkg_path, fresh.join("package.json")).unwrap();
    std::fs::copy(&lock_path, fresh.join("bun.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_cache = tmp.path().join("fresh-bun-cache");
    let ci = bun(&fresh, &["install", "--frozen-lockfile"], &fresh_cache);
    assert!(
        ci.status.success(),
        "fresh-checkout `bun install --frozen-lockfile` must succeed from the vendored \
         tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let fresh_installed =
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        fresh_installed.starts_with(MARKER.as_bytes()),
        "bun must install the PATCHED bytes from the vendored tarball; got:\n{}",
        String::from_utf8_lossy(&fresh_installed[..fresh_installed.len().min(120)])
    );
    assert_eq!(
        fresh_installed, patched,
        "fresh install must be byte-identical to the patched content"
    );
    // --frozen-lockfile would have errored if the lock drifted; prove it
    // left the committed lock byte-stable.
    assert_eq!(
        std::fs::read(fresh.join("bun.lock")).unwrap(),
        std::fs::read(&lock_path).unwrap(),
        "--frozen-lockfile install must leave bun.lock byte-identical"
    );
    eprintln!("FRESH INSTALL OK");

    // 5. Idempotency: a re-run exits 0 and leaves bun.lock byte-stable.
    let lock_wired = std::fs::read(&lock_path).unwrap();
    let (code, stdout, stderr) = run_socket(
        &proj,
        &["vendor", "--json", "--offline", "--cwd", proj.to_str().unwrap()],
    );
    assert_eq!(code, 0, "re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let env2 = parse_envelope(&stdout);
    assert_eq!(env2["summary"]["failed"], 0, "re-run must not fail: {env2}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_wired,
        "re-vendor must leave bun.lock byte-identical"
    );

    // 6. REVERT PROOF: bun.lock restored byte-for-byte, artifacts gone.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &["vendor", "--revert", "--json", "--offline", "--cwd", proj.to_str().unwrap()],
    );
    assert_eq!(code, 0, "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "revert envelope: {renv}");
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "revert must restore bun.lock byte-identical to the pre-vendor snapshot"
    );
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        pkg_before,
        "revert must leave package.json byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
    eprintln!("REVERT OK");
}
