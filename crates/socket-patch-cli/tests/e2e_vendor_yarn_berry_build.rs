//! Real-yarn-berry capstone e2e for `socket-patch vendor` — the
//! committability proof for the yarn berry 4.x (node-modules linker) flavor.
//!
//! Drives the REAL `corepack yarn@4.x` (network used for fixture setup only):
//!   1. `yarn install` of left-pad@1.3.0 into a tempdir whose `.yarnrc.yml`
//!      pins `nodeLinker: node-modules` + `enableGlobalCache: false` (the
//!      cacheKey-10c0 / compressionLevel-0 default the spike B2/B4 proved is
//!      offline-reproducible).
//!   2. Hand-stage a `.socket/` manifest + blob from the ACTUAL installed
//!      bytes (a marker comment prepended to `index.js`).
//!   3. `socket-patch vendor --json --offline` — assert the deterministic
//!      tarball lands at `.socket/vendor/npm/<uuid>/…`, the root package.json
//!      gains a `resolutions` entry, and yarn.lock has the `file:` resolution
//!      entry with a `checksum: 10c0/<hex>` (spike B3 — the checksum is the
//!      sha512 of the reproduced cache zip).
//!   4. **Fresh-checkout proof**: copy ONLY the committable files
//!      (package.json + yarn.lock + .yarnrc.yml + .socket/) to a new dir, an
//!      EMPTY global cache, and run the spike's strictest invocation
//!      `corepack yarn install --immutable --check-cache` — the patched bytes
//!      MUST be what yarn installs (B5).
//!   5. Idempotency: re-running vendor leaves both files byte-identical.
//!   6. **Revert proof**: `vendor --revert` restores package.json AND
//!      yarn.lock byte-for-byte and removes `.socket/vendor/` entirely.
//!
//! LOCAL capstone (not behind docker-e2e): skips with a `println` + return
//! when `corepack` (yarn berry) is unavailable or the fixture install cannot
//! reach the registry; every assertion after that is HARD.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

const UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
/// Pinned yarn berry via corepack (matches the spike's 4.x).
const YARN_BERRY: &str = "yarn@4.12.0";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

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

fn corepack(cwd: &Path, pm: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
    // Scrub FIRST (it removes YARN_* / SOCKET_* from the inherited env), then
    // seed the hermetic flags so they survive (Command: last env call wins).
    scrub_socket_env(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run corepack")
}

/// Remove ambient `SOCKET_*` and `YARN_*` vars (so a developer's settings
/// can't leak into the child).
fn scrub_socket_env(cmd: &mut Command) {
    // Seed-then-scrub (mirrors e2e_redirect_yarn_berry_build.rs): yarn berry
    // lets EVERY `.yarnrc.yml` setting be overridden by a `YARN_*` env var
    // (env outranks the project yarnrc), so an ambient `YARN_NODE_LINKER=pnp`
    // was verified to turn this test red — the fixture install builds a PnP
    // tree and node_modules/left-pad never exists. The explicit env_remove
    // below clears the seed too, but if the scrub is ever dropped the seed
    // (rather than a developer's ambient shell, which this suite can't rely
    // on) turns the test red immediately.
    cmd.env("YARN_NODE_LINKER", "pnp");
    for (k, _) in std::env::vars_os() {
        let key = k.to_string_lossy();
        if key.starts_with("SOCKET_") || key.starts_with("YARN_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("YARN_NODE_LINKER");
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
fn yarn_berry_vendor_fresh_checkout_immutable_check_cache_and_revert() {
    if !has_corepack_pm(YARN_BERRY) {
        println!(
            "SKIP e2e_vendor_yarn_berry_build: `corepack {YARN_BERRY}` unavailable \
             (corepack not installed or yarn berry not fetchable)"
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"yarn-berry-capstone","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();
    // node-modules linker + the cacheKey-10c0 / compressionLevel-0 default
    // (the only checksum recipe vendor reproduces offline — spike B4).
    std::fs::write(
        proj.join(".yarnrc.yml"),
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
    )
    .unwrap();

    // 1. REAL fixture: yarn berry install (network allowed here, private
    //    global cache).
    let global = tmp.path().join("yarn-global");
    // RED guard (e2e_vendor_bun_build bug class): the seeded YARN_GLOBAL_FOLDER
    // must actually reach the corepack child — a scrub that runs AFTER the
    // extra_env seed silently wipes it (Command: last env call wins) and every
    // install below quietly uses the developer's real `~/.yarn/berry`.
    let probe = corepack(
        &proj,
        YARN_BERRY,
        &["config", "get", "globalFolder"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    let reported = String::from_utf8_lossy(&probe.stdout);
    assert!(
        probe.status.success() && reported.trim().ends_with("yarn-global"),
        "seeded YARN_GLOBAL_FOLDER must survive the env scrub (scrub must run \
         before the seed); yarn reports globalFolder = `{}`",
        reported.trim()
    );
    let install = corepack(
        &proj,
        YARN_BERRY,
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_vendor_yarn_berry_build: fixture `yarn install` failed (registry \
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

    stage_patch(&proj, &purl, "package/index.js", &orig, &patched);

    // Snapshot the COMMITTABLE files exactly as they sit post-install. Note
    // berry rewrites package.json (compact → pretty) during install, so the
    // pre-vendor truth is the on-disk bytes, not what we authored.
    let lock_path = proj.join("yarn.lock");
    let pkg_path = proj.join("package.json");
    let lock_before = std::fs::read(&lock_path).expect("yarn.lock after yarn install");
    let pkg_before = std::fs::read(&pkg_path).expect("package.json after yarn install");
    let lock_before_str = String::from_utf8(lock_before.clone()).unwrap();
    assert!(
        lock_before_str.contains("__metadata:") && lock_before_str.contains("cacheKey: 10c0"),
        "fixture must be a berry cacheKey-10c0 lock:\n{lock_before_str}"
    );
    assert!(
        lock_before_str.contains("\"left-pad@npm:1.3.0\""),
        "pre-vendor lock must carry the registry `npm:` resolution"
    );

    // 3. Vendor (offline).
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

    // package.json gained a `resolutions` entry pointing at the vendored
    // tarball (the dependency range is left untouched — spike B3).
    let pkg_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pkg_path).unwrap()).unwrap();
    assert_eq!(
        pkg_json["resolutions"][DEP].as_str(),
        Some(format!("file:./{tgz_rel}").as_str()),
        "package.json must gain the resolutions entry: {pkg_json}"
    );
    assert_eq!(
        pkg_json["dependencies"][DEP].as_str(),
        Some(DEP_VERSION),
        "the dependency range must stay registry-form"
    );

    // yarn.lock has the file: resolution entry with a `checksum: 10c0/<hex>`
    // (the reproduced cache-zip sha512) and the registry `npm:` entry gone.
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock_after.contains(&format!("left-pad@file:./{tgz_rel}::locator=")),
        "yarn.lock must carry the file: locator entry; got:\n{lock_after}"
    );
    let checksum_line = lock_after
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("checksum: 10c0/"))
        .unwrap_or_else(|| {
            panic!("yarn.lock must carry a `checksum: 10c0/<hex>` line:\n{lock_after}")
        });
    let checksum_hex = checksum_line.trim_start_matches("checksum: 10c0/");
    assert_eq!(
        checksum_hex.len(),
        128,
        "sha512 hex is 128 chars: {checksum_line}"
    );
    assert!(
        checksum_hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "checksum body must be hex: {checksum_line}"
    );
    assert!(
        !lock_after.contains("\"left-pad@npm:1.3.0\""),
        "the registry `npm:` resolution must be replaced by the file: entry:\n{lock_after}"
    );
    eprintln!("VENDOR OK");

    // 4. FRESH-CHECKOUT PROOF: only the committable files, EMPTY global cache,
    //    spike-proven strictest invocation `--immutable --check-cache`.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&pkg_path, fresh.join("package.json")).unwrap();
    std::fs::copy(&lock_path, fresh.join("yarn.lock")).unwrap();
    std::fs::copy(proj.join(".yarnrc.yml"), fresh.join(".yarnrc.yml")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_global = tmp.path().join("fresh-yarn-global");
    let ci = corepack(
        &fresh,
        YARN_BERRY,
        &["install", "--immutable", "--check-cache"],
        &[
            ("YARN_GLOBAL_FOLDER", fresh_global.to_str().unwrap()),
            ("YARN_ENABLE_GLOBAL_CACHE", "false"),
        ],
    );
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --immutable --check-cache` must succeed from the \
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
    // --immutable would have errored if our checksum diverged from the
    // reproduced cache zip; prove it left the committed lock byte-stable.
    assert_eq!(
        std::fs::read(fresh.join("yarn.lock")).unwrap(),
        std::fs::read(&lock_path).unwrap(),
        "--immutable install must leave yarn.lock byte-identical"
    );
    eprintln!("FRESH INSTALL OK");

    // 5. Idempotency: a re-run exits 0 and leaves BOTH files byte-stable.
    let lock_wired = std::fs::read(&lock_path).unwrap();
    let pkg_wired = std::fs::read(&pkg_path).unwrap();
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
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        pkg_wired,
        "re-vendor must leave package.json byte-identical"
    );

    // 6. REVERT PROOF: package.json AND yarn.lock restored byte-for-byte.
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
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        pkg_before,
        "revert must restore package.json byte-identical to the pre-vendor snapshot"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
    eprintln!("REVERT OK");
}
