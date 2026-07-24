//! Real-yarn-classic developer-flow e2e for `socket-patch vendor` — proves
//! yarn 1 stays a first-class installer for vendored wiring across the flows
//! the fresh-checkout capstone (`e2e_vendor_yarn_classic_build.rs`) does not
//! exercise:
//!
//!   1. **Re-save survival**: a plain `yarn install` (no `--frozen-lockfile`,
//!      no `--offline`) must keep the vendored
//!      `resolved "file:./.socket/vendor/…"` block intact, and a `yarn add`
//!      — which re-serializes the ENTIRE lockfile from yarn's in-memory
//!      model (`Saved lockfile.` is asserted as proof) — must round-trip the
//!      vendored block byte-intact. A further plain install must be a
//!      lockfile fixpoint. Otherwise the everyday dev flow silently drops
//!      patches on the next install.
//!   2. **Unpatched-neighbor coexistence**: a dependency that yarn berry
//!      builtin-patches (`resolve` — the package at the center of the strapi
//!      incident) rides along UNvendored; its lock block must stay
//!      byte-identical through vendor + installs, and it must install
//!      unpatched.
//!   3. **No `patch:` protocol leakage**: the wired lockfile must never
//!      contain a `patch:` resolution — yarn classic has no such protocol,
//!      and a berry migration of the lockfile must not inherit one from us.
//!   4. **Frozen re-entry**: after the re-save, `yarn install
//!      --frozen-lockfile` must pass — the re-saved lockfile and our wiring
//!      agree, so CI-style installs keep working downstream of dev installs.
//!
//! LOCAL capstone (not behind docker-e2e): skips with a `println` + return
//! when `corepack` (yarn classic) is unavailable or the fixture install
//! cannot reach the registry; every assertion after that is HARD.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

/// Canonical lowercase patch uuid (a dedicated path level under
/// `.socket/vendor/npm/`).
const UUID: &str = "2b3c4d5e-6f7a-4b2c-9d3e-123456789abc";
/// Marker prepended to the dep's entry point by the synthetic patch.
const MARKER: &str = "/* SOCKET-PATCHED */\n";
/// The dependency that gets vendored.
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
/// The unpatched neighbor: yarn berry applies a builtin compat patch to
/// `resolve`, which made it the noisiest package in the strapi incident.
/// Pure JS, no install scripts, tiny.
const NEIGHBOR: &str = "resolve";
const NEIGHBOR_VERSION: &str = "1.20.0";
/// Pinned yarn classic via corepack (matches the fresh-checkout capstone).
const YARN_CLASSIC: &str = "yarn@1.22.22";

// ── self-contained helpers (convention: e2e test files stay standalone) ─

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
            "vulnerabilities": { "GHSA-vend-yarn-dev": {
                "cves": ["CVE-2024-99999"],
                "summary": "dev-flow capstone vuln",
                "severity": "high",
                "description": "d",
            }},
            "description": "dev-flow marker patch",
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

/// The contiguous lockfile block (header line through the following blank
/// line) whose header starts with `"<name>@`. Yarn classic writes one block
/// per resolution with headers like `resolve@^1.20.0:` or
/// `"resolve@1.20.0", "resolve@^1.x":` — matching on the leading
/// `<name>@` is stable for the single-version fixtures used here.
fn lock_block<'a>(lock: &'a str, name: &str) -> &'a str {
    let mut start = None;
    for (idx, line) in lock.lines().enumerate() {
        let header =
            line.starts_with(&format!("{name}@")) || line.starts_with(&format!("\"{name}@"));
        if header {
            start = Some(idx);
            break;
        }
    }
    let start = start.unwrap_or_else(|| panic!("no lock block for {name}:\n{lock}"));
    let lines: Vec<&str> = lock.lines().collect();
    let mut end = lines.len();
    for (idx, line) in lines.iter().enumerate().skip(start + 1) {
        if line.is_empty() {
            end = idx;
            break;
        }
    }
    // Slice out of the original str so the caller compares real bytes.
    let head_offset: usize = lines[..start].iter().map(|l| l.len() + 1).sum();
    let block_len: usize = lines[start..end].iter().map(|l| l.len() + 1).sum();
    &lock[head_offset..head_offset + block_len]
}

// ── the dev-flow capstone ─────────────────────────────────────────────

#[test]
fn yarn_classic_vendored_lock_survives_dev_install_resave() {
    if !has_corepack_pm(YARN_CLASSIC) {
        println!(
            "SKIP e2e_vendor_yarn_classic_dev_flow: `corepack {YARN_CLASSIC}` unavailable \
             (corepack not installed or yarn classic not fetchable)"
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"yarn-classic-dev-flow","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}","{NEIGHBOR}":"{NEIGHBOR_VERSION}"}}}}"#
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
            "SKIP e2e_vendor_yarn_classic_dev_flow: fixture `yarn install` failed (registry \
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
    let neighbor_index = proj.join("node_modules").join(NEIGHBOR).join("index.js");
    let neighbor_orig = std::fs::read(&neighbor_index).expect("installed neighbor index.js");
    let purl = format!("pkg:npm/{DEP}@{DEP_VERSION}");

    // 2. Manifest + blob from the ACTUAL installed bytes (npm-family file
    //    keys carry the `package/` prefix). Only DEP is patched — NEIGHBOR
    //    deliberately has no manifest entry.
    stage_patch(&proj, &purl, "package/index.js", &orig, &patched);

    let lock_path = proj.join("yarn.lock");
    let lock_before = std::fs::read_to_string(&lock_path).expect("yarn.lock after yarn install");
    let neighbor_block_before = lock_block(&lock_before, NEIGHBOR).to_owned();
    assert!(
        neighbor_block_before.contains("https://registry.yarnpkg.com/"),
        "neighbor block must resolve to the registry pre-vendor:\n{neighbor_block_before}"
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
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("vendor --json output is not JSON: {e}\nstdout:\n{stdout}"));
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");

    let tgz_rel = format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}.tgz");
    assert!(
        proj.join(&tgz_rel).is_file(),
        "vendored tarball missing at {tgz_rel}"
    );

    let lock_wired = std::fs::read_to_string(&lock_path).unwrap();
    let wired_resolved_prefix = format!("  resolved \"file:./{tgz_rel}#");
    assert!(
        lock_wired.contains(&wired_resolved_prefix),
        "yarn.lock must resolve to the vendored tarball:\n{lock_wired}"
    );
    // The exact wired block — the byte sequence that must survive re-saves.
    let dep_block_wired = lock_block(&lock_wired, DEP).to_owned();
    assert!(
        dep_block_wired.contains(&wired_resolved_prefix)
            && dep_block_wired.contains("integrity sha512-"),
        "wired block must carry file: resolved + recomputed integrity:\n{dep_block_wired}"
    );

    // Unpatched-neighbor proof: the resolve block is byte-identical.
    assert_eq!(
        lock_block(&lock_wired, NEIGHBOR),
        neighbor_block_before,
        "vendor must leave the unpatched neighbor's lock block byte-identical"
    );
    // No `patch:` protocol leakage anywhere (a berry migration of this file
    // must never inherit a patch: resolution from our wiring).
    assert!(
        !lock_wired.contains("patch:"),
        "vendored yarn.lock must not contain a `patch:` resolution:\n{lock_wired}"
    );
    eprintln!("VENDOR OK");

    // 4. DEV-FLOW PROOF: fresh checkout, then a PLAIN `yarn install` — no
    //    --frozen-lockfile, no --offline. Yarn re-saves yarn.lock in this
    //    mode; the vendored block must survive the re-save byte-intact.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(&lock_path, fresh.join("yarn.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_cache = tmp.path().join("fresh-yarn-cache");
    let dev = corepack(
        &fresh,
        YARN_CLASSIC,
        &["install", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    assert!(
        dev.status.success(),
        "fresh-checkout plain `yarn install` must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&dev.stdout),
        String::from_utf8_lossy(&dev.stderr),
    );
    let fresh_installed =
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert_eq!(
        fresh_installed, patched,
        "plain install must deliver the PATCHED bytes from the vendored tarball"
    );
    let fresh_neighbor =
        std::fs::read(fresh.join("node_modules").join(NEIGHBOR).join("index.js")).unwrap();
    assert_eq!(
        fresh_neighbor, neighbor_orig,
        "the unpatched neighbor must install pristine registry bytes"
    );

    let lock_resaved = std::fs::read_to_string(fresh.join("yarn.lock")).unwrap();
    assert_eq!(
        lock_block(&lock_resaved, DEP),
        dep_block_wired,
        "yarn's lockfile re-save must preserve the vendored block byte-intact"
    );
    assert_eq!(
        lock_block(&lock_resaved, NEIGHBOR),
        neighbor_block_before,
        "yarn's lockfile re-save must preserve the neighbor block byte-intact"
    );
    assert!(
        !lock_resaved.contains("patch:"),
        "re-saved yarn.lock must not contain a `patch:` resolution:\n{lock_resaved}"
    );
    eprintln!("DEV INSTALL OK");

    // 5. FULL RE-SERIALIZATION PROOF: `yarn add` rebuilds yarn.lock from
    //    yarn's in-memory model — every block is re-emitted, so a lossy
    //    parse of our vendored block would surface here. `Saved lockfile.`
    //    in the output is the non-vacuousness guard: it proves the file
    //    really was rewritten rather than left untouched.
    let add = corepack(
        &fresh,
        YARN_CLASSIC,
        &["add", "isarray@2.0.5", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    assert!(
        add.status.success(),
        "`yarn add` must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr),
    );
    assert!(
        String::from_utf8_lossy(&add.stdout).contains("Saved lockfile"),
        "`yarn add` must actually re-serialize yarn.lock (`Saved lockfile.`):\nstdout:\n{}",
        String::from_utf8_lossy(&add.stdout),
    );
    let lock_readded = std::fs::read_to_string(fresh.join("yarn.lock")).unwrap();
    assert_eq!(
        lock_block(&lock_readded, DEP),
        dep_block_wired,
        "a full lockfile re-serialization (`yarn add`) must round-trip the vendored block \
         byte-intact"
    );
    assert_eq!(
        lock_block(&lock_readded, NEIGHBOR),
        neighbor_block_before,
        "a full lockfile re-serialization must round-trip the neighbor block byte-intact"
    );
    assert!(
        !lock_readded.contains("patch:"),
        "re-serialized yarn.lock must not contain a `patch:` resolution:\n{lock_readded}"
    );
    let still_patched =
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert_eq!(
        still_patched, patched,
        "patched bytes must survive the `yarn add` re-link"
    );
    eprintln!("YARN ADD RE-SERIALIZATION OK");

    // 6. FIXPOINT: another plain install leaves yarn.lock byte-identical —
    //    the wiring never oscillates under repeated dev installs.
    let dev2 = corepack(
        &fresh,
        YARN_CLASSIC,
        &["install", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    assert!(
        dev2.status.success(),
        "second plain `yarn install` must succeed.\nstderr:\n{}",
        String::from_utf8_lossy(&dev2.stderr),
    );
    assert_eq!(
        std::fs::read_to_string(fresh.join("yarn.lock")).unwrap(),
        lock_readded,
        "plain install after `yarn add` must be a lockfile fixpoint"
    );
    eprintln!("FIXPOINT OK");

    // 7. FROZEN RE-ENTRY: the re-saved lockfile passes `--frozen-lockfile`
    //    (online) — dev installs don't wedge the CI flow downstream.
    let frozen = corepack(
        &fresh,
        YARN_CLASSIC,
        &["install", "--frozen-lockfile", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    assert!(
        frozen.status.success(),
        "`yarn install --frozen-lockfile` must pass on the re-saved lockfile.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&frozen.stdout),
        String::from_utf8_lossy(&frozen.stderr),
    );
    eprintln!("FROZEN RE-ENTRY OK");
}
