//! Real-pnpm capstone e2e for `socket-patch vendor` — the committability
//! proof for the pnpm (lockfileVersion 9.0) flavor.
//!
//! Drives the REAL `corepack pnpm@10` (and pnpm@9 when fetchable — both emit
//! byte-identical 9.0 locks, spike P1/P2):
//!   1. `pnpm install` of left-pad@1.3.0 into a tempdir (private `--store-dir`).
//!   2. Hand-stage a `.socket/` manifest + blob from the ACTUAL installed
//!      bytes (a marker comment prepended to `index.js`).
//!   3. `socket-patch vendor --json --offline` — assert the deterministic
//!      tarball lands at `.socket/vendor/npm/<uuid>/…`, the root package.json
//!      gains `pnpm.overrides`, and pnpm-lock.yaml carries the file:
//!      resolution (spike P1: importer specifier+version rewritten, packages
//!      entry rekeyed with the recomputed integrity).
//!   4. **Fresh-checkout proof**: copy ONLY the committable files
//!      (package.json + pnpm-lock.yaml + .socket/) to a new dir, an EMPTY
//!      `--store-dir`, and run the spike's strictest invocation
//!      `pnpm install --frozen-lockfile --offline` — the patched bytes MUST
//!      be what pnpm installs (P4).
//!   5. Idempotency: re-running vendor leaves both files byte-identical.
//!   6. **Revert proof**: `vendor --revert` restores package.json AND
//!      pnpm-lock.yaml byte-for-byte and removes `.socket/vendor/`.
//!
//! LOCAL capstone (not behind docker-e2e): skips with a `println` + return
//! when `corepack pnpm@10` is unavailable or the fixture install cannot reach
//! the registry; every assertion after that is HARD.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

const UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
/// Pinned pnpm majors via corepack — @10 is required, @9 is run too when
/// fetchable (the spike proved both emit byte-identical 9.0 locks).
const PNPM_PRIMARY: &str = "pnpm@10";
const PNPM_SECONDARY: &str = "pnpm@9";

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

fn corepack(cwd: &Path, pm: &str, args: &[&str]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm)
        .args(args)
        .current_dir(cwd)
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    scrub_socket_env(&mut cmd);
    cmd.output().expect("failed to run corepack")
}

/// Remove ambient `SOCKET_*` vars and the pnpm store env the harness controls
/// (the `--store-dir` flag is always passed explicitly).
fn scrub_socket_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy();
        if k.starts_with("SOCKET_") {
            cmd.env_remove(k.as_ref());
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("PNPM_HOME");
    cmd.env_remove("npm_config_store_dir");
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
            "vulnerabilities": { "GHSA-vend-pnpm-real": {
                "cves": ["CVE-2024-88888"],
                "summary": "capstone vex vuln",
                "severity": "high",
                "description": "d",
            }},
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
fn pnpm_vendor_fresh_checkout_frozen_offline_install_and_revert() {
    if !has_corepack_pm(PNPM_PRIMARY) {
        println!(
            "SKIP e2e_vendor_pnpm_build: `corepack {PNPM_PRIMARY}` unavailable \
             (corepack not installed or pnpm not fetchable)"
        );
        return;
    }
    run_pnpm_capstone(PNPM_PRIMARY);

    // Cheap bonus coverage: pnpm 9 emits a byte-identical 9.0 lock (spike P1),
    // so run the whole lifecycle again on it when it is fetchable. Never a
    // skip-failure — @10 already carried the hard assertions.
    if has_corepack_pm(PNPM_SECONDARY) {
        eprintln!("--- also exercising {PNPM_SECONDARY} ---");
        run_pnpm_capstone(PNPM_SECONDARY);
    } else {
        eprintln!("note: {PNPM_SECONDARY} not fetchable; ran {PNPM_PRIMARY} only");
    }
}

fn run_pnpm_capstone(pm: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    // Author package.json in the SAME shape pnpm's vendor edit reserializes
    // (serde_json pretty, 2-space, trailing newline) so the vendor→revert
    // round trip is byte-identical (pnpm — unlike yarn berry — does not
    // rewrite package.json on install).
    let pkg_doc = serde_json::json!({
        "name": "pnpm-capstone",
        "version": "0.0.0",
        "private": true,
        "dependencies": { DEP: DEP_VERSION },
    });
    std::fs::write(
        proj.join("package.json"),
        format!("{}\n", serde_json::to_string_pretty(&pkg_doc).unwrap()),
    )
    .unwrap();

    // 1. REAL fixture: pnpm install (network allowed here, private store).
    let store = tmp.path().join("pnpm-store");
    let install = corepack(
        &proj,
        pm,
        &["install", "--store-dir", store.to_str().unwrap()],
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_vendor_pnpm_build ({pm}): fixture `pnpm install` failed (registry \
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

    let lock_path = proj.join("pnpm-lock.yaml");
    let pkg_path = proj.join("package.json");
    let lock_before = std::fs::read(&lock_path).expect("pnpm-lock.yaml after pnpm install");
    let pkg_before = std::fs::read(&pkg_path).expect("package.json");
    let lock_before_str = String::from_utf8(lock_before.clone()).unwrap();
    assert!(
        lock_before_str.contains("lockfileVersion: '9.0'"),
        "fixture must be a lockfileVersion 9.0 lock:\n{lock_before_str}"
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
        "vendor failed ({pm}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
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

    // Real-toolchain VEX: attest the vendored patch against the vendored
    // tarball (`(vendored)` marker), proving the pnpm install → vendor → vex
    // chain end to end.
    let vex_path = proj.join("out.vex.json");
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vex",
            "--cwd",
            proj.to_str().unwrap(),
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ],
    );
    assert_eq!(code, 0, "vex failed ({pm}).\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let vex_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    let vex_stmts = vex_doc["statements"].as_array().unwrap();
    assert_eq!(vex_stmts.len(), 1, "vendored patch must be attested: {vex_doc}");
    assert_eq!(vex_stmts[0]["vulnerability"]["name"], "GHSA-vend-pnpm-real");
    assert_eq!(vex_stmts[0]["products"][0]["subcomponents"][0]["@id"], purl);
    assert!(
        vex_stmts[0]["impact_statement"]
            .as_str()
            .unwrap()
            .contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {vex_doc}"
    );

    // package.json gained `pnpm.overrides` with a VERSIONED selector pointing
    // at the vendored tarball (spike P1; pnpm spells the target `file:<root-
    // relative>` with no `./`).
    let pkg_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pkg_path).unwrap()).unwrap();
    assert_eq!(
        pkg_json["pnpm"]["overrides"][format!("{DEP}@{DEP_VERSION}")].as_str(),
        Some(format!("file:{tgz_rel}").as_str()),
        "package.json must gain pnpm.overrides: {pkg_json}"
    );

    // pnpm-lock.yaml carries the file: resolution (overrides section +
    // rekeyed packages entry).
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock_after.contains(&format!("{DEP}@{DEP_VERSION}: file:{tgz_rel}")),
        "lock `overrides:` must point at the vendored tarball; got:\n{lock_after}"
    );
    assert!(
        lock_after.contains(&format!("{DEP}@file:{tgz_rel}:")),
        "lock packages entry must be rekeyed to the file: tarball; got:\n{lock_after}"
    );
    assert!(
        lock_after.contains(&format!("tarball: file:{tgz_rel}")),
        "lock resolution must carry the file: tarball key; got:\n{lock_after}"
    );
    // The recomputed integrity is OUR tarball's sha512, never the inherited
    // registry one.
    assert!(
        !lock_after.contains(
            "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
        ),
        "the inherited registry integrity must NOT survive the rewrite:\n{lock_after}"
    );
    eprintln!("VENDOR OK ({pm})");

    // 4. FRESH-CHECKOUT PROOF: committable files only, EMPTY store,
    //    spike-proven `--frozen-lockfile --offline`.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&pkg_path, fresh.join("package.json")).unwrap();
    std::fs::copy(&lock_path, fresh.join("pnpm-lock.yaml")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_store = tmp.path().join("fresh-pnpm-store");
    let ci = corepack(
        &fresh,
        pm,
        &[
            "install",
            "--frozen-lockfile",
            "--offline",
            "--store-dir",
            fresh_store.to_str().unwrap(),
        ],
    );
    assert!(
        ci.status.success(),
        "fresh-checkout `pnpm install --frozen-lockfile --offline` must succeed from the \
         vendored tarball ({pm}).\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let fresh_installed =
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        fresh_installed.starts_with(MARKER.as_bytes()),
        "pnpm must install the PATCHED bytes from the vendored tarball; got:\n{}",
        String::from_utf8_lossy(&fresh_installed[..fresh_installed.len().min(120)])
    );
    assert_eq!(
        fresh_installed, patched,
        "fresh install must be byte-identical to the patched content"
    );
    eprintln!("FRESH INSTALL OK ({pm})");

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
        "re-vendor failed ({pm}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env2 = parse_envelope(&stdout);
    assert_eq!(env2["summary"]["failed"], 0, "re-run must not fail: {env2}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_wired,
        "re-vendor must leave pnpm-lock.yaml byte-identical"
    );
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        pkg_wired,
        "re-vendor must leave package.json byte-identical"
    );

    // 6. REVERT PROOF: package.json AND pnpm-lock.yaml restored byte-for-byte.
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
        "revert failed ({pm}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "revert envelope: {renv}");
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "revert must restore pnpm-lock.yaml byte-identical to the pre-vendor snapshot"
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
    eprintln!("REVERT OK ({pm})");
}
