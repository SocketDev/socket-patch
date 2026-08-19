//! Real-pnpm capstone e2e for `socket-patch vendor` — the committability
//! proof for the pnpm (lockfileVersion 9.0) flavor.
//!
//! Drives the REAL `corepack pnpm@10` (and pnpm@9 / pnpm@11 when fetchable —
//! all three emit byte-identical single-document 9.0 locks, spike P1/P2 +
//! matrix leg vendor-pnpm11):
//!   1. `pnpm install` of left-pad@1.3.0 into a tempdir (private `--store-dir`).
//!   2. Hand-stage a `.socket/` manifest + blob from the ACTUAL installed
//!      bytes (a marker comment prepended to `index.js`).
//!   3. `socket-patch vendor --json --offline` — assert the deterministic
//!      tarball lands at `.socket/vendor/npm/<uuid>/…`, the root package.json
//!      gains `pnpm.overrides`, a `pnpm-workspace.yaml` is created carrying
//!      the same `overrides:` (where pnpm >= 11 reads them) plus a root-only
//!      `packages:` list, and pnpm-lock.yaml carries the file: resolution
//!      (spike P1: importer specifier+version rewritten, packages entry
//!      rekeyed with the recomputed integrity).
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
//!
//! Below the capstone: the LEGACY grammars — pnpm 7 (`lockfileVersion: 5.4`)
//! and pnpm 8 (`'6.0'`), wired by the pnpm-legacy backend. HERMETIC legs
//! (no corepack, no network, always run) prove the splice reproduces the
//! pnpm-captured end state byte-for-byte, is idempotent, and reverts
//! byte-identical; gated `pnpm7_real_*`/`pnpm8_real_*` legs run the full
//! lifecycle against the real pinned pnpm, including the SAME-PATH
//! frozen+offline empty-store proof and the MOVED-CHECKOUT `--offline`
//! proof (pnpm <= 8 absolutizes file: override specifiers, so frozen
//! installs are path-bound — the moved-checkout frozen FAILURE is asserted
//! as the documented limitation).

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

#[path = "common/cache_env.rs"]
mod cache_env;

const UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
/// Pinned pnpm majors via corepack — @10 is required, @9 and @11 are run too
/// when fetchable (the spike proved @9/@10 emit byte-identical 9.0 locks; the
/// matrix proved @11 (11.22.0) does as well — single-document, same grammar).
const PNPM_PRIMARY: &str = "pnpm@10";
const PNPM_SECONDARY: &str = "pnpm@9";
const PNPM_TERTIARY: &str = "pnpm@11";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn has_corepack_pm(pm: &str) -> bool {
    // Isolated too: this probe is what actually downloads the package manager
    // the first time, and corepack stores it under `COREPACK_HOME`.
    let mut cmd = Command::new("corepack");
    cmd.args([pm, "--version"])
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    cache_env::isolate(&mut cmd);
    cmd.stdout(Stdio::null())
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
    // After the scrub: it strips ambient `PNPM_*` and `npm_config_*`, which
    // would otherwise take the sandbox values back out again.
    cache_env::isolate(&mut cmd);
    cmd.output().expect("failed to run corepack")
}

/// Remove ambient `SOCKET_*` / `PNPM_*` / `npm_config_*` vars (the
/// `--store-dir` flag is always passed explicitly).
///
/// Seed-then-scrub (mirrors e2e_redirect_yarn_berry_build.rs): pnpm lets
/// EVERY `.npmrc` setting be overridden by an `npm_config_*` env var (env
/// outranks the project npmrc), so an ambient `npm_config_node_linker=pnp`
/// was verified to turn the capstone red — pnpm emits a `.pnp.cjs` and
/// `vendor` refuses the project as unsupported Plug'n'Play. The explicit
/// env_remove below clears the seed too, but if the prefix scrub is ever
/// dropped the seed (rather than a developer's ambient shell, which this
/// suite can't rely on) turns the test red immediately.
fn scrub_socket_env(cmd: &mut Command) {
    cmd.env("npm_config_node_linker", "pnp");
    for (k, _) in std::env::vars_os() {
        let key = k.to_string_lossy();
        if (key.starts_with("SOCKET_")
            || key.starts_with("PNPM_")
            || key.to_ascii_lowercase().starts_with("npm_config_"))
            && key != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("npm_config_node_linker");
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

    // Ladder top: pnpm 11 (matrix leg vendor-pnpm11, 11.22.0) emits the same
    // single-document 9.0 lock as 10 and its supply-chain verification accepts
    // the vendored file: tarball, so the whole lifecycle carries hard
    // assertions here too. pnpm >= 11 reads `overrides` ONLY from
    // pnpm-workspace.yaml (the package.json `pnpm` table is ignored), which
    // makes the workspace-file assertions inside run_pnpm_capstone the
    // load-bearing wiring surface on this leg — the fresh-checkout
    // frozen+offline install below would resolve the unpatched registry
    // tarball without it.
    if has_corepack_pm(PNPM_TERTIARY) {
        eprintln!("--- also exercising {PNPM_TERTIARY} ---");
        run_pnpm_capstone(PNPM_TERTIARY);
    } else {
        eprintln!("note: {PNPM_TERTIARY} not fetchable; skipped");
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
    assert_eq!(
        code, 0,
        "vex failed ({pm}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let vex_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    let vex_stmts = vex_doc["statements"].as_array().unwrap();
    assert_eq!(
        vex_stmts.len(),
        1,
        "vendored patch must be attested: {vex_doc}"
    );
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

    // pnpm >= 11 reads `overrides` only from pnpm-workspace.yaml, so vendoring
    // mirrors the same versioned selector there. When the project had none
    // (this fixture), it is CREATED with a root-only `packages:` list — pnpm 9
    // refuses a workspace file whose `packages` field is missing/empty, and
    // `.` cannot glob a stray subtree into the workspace the way `packages/*`
    // could. That makes the committable set install on pnpm 9/10/11 alike.
    let ws_path = proj.join("pnpm-workspace.yaml");
    let ws_after =
        std::fs::read_to_string(&ws_path).expect("vendoring must create pnpm-workspace.yaml");
    assert!(
        ws_after.contains(&format!("{DEP}@{DEP_VERSION}: file:{tgz_rel}")),
        "pnpm-workspace.yaml `overrides:` must point at the vendored tarball; got:\n{ws_after}"
    );
    assert!(
        ws_after.contains("packages:") && ws_after.contains("- '.'"),
        "created pnpm-workspace.yaml must carry a root-only packages list; got:\n{ws_after}"
    );
    eprintln!("VENDOR OK ({pm})");

    // 4. FRESH-CHECKOUT PROOF: committable files only, EMPTY store,
    //    spike-proven `--frozen-lockfile --offline`.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&pkg_path, fresh.join("package.json")).unwrap();
    std::fs::copy(&lock_path, fresh.join("pnpm-lock.yaml")).unwrap();
    std::fs::copy(&ws_path, fresh.join("pnpm-workspace.yaml")).unwrap();
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

    // 5. Idempotency: a re-run exits 0 and leaves ALL THREE files byte-stable.
    let lock_wired = std::fs::read(&lock_path).unwrap();
    let pkg_wired = std::fs::read(&pkg_path).unwrap();
    let ws_wired = std::fs::read(&ws_path).unwrap();
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
    assert_eq!(
        std::fs::read(&ws_path).unwrap(),
        ws_wired,
        "re-vendor must leave pnpm-workspace.yaml byte-identical"
    );

    // 6. REVERT PROOF: package.json AND pnpm-lock.yaml restored byte-for-byte,
    //    and the pnpm-workspace.yaml vendoring created is deleted.
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
    assert!(
        !ws_path.exists(),
        "revert must delete the pnpm-workspace.yaml vendoring created"
    );
    eprintln!("REVERT OK ({pm})");
}

// ── pre-9.0 LEGACY lock legs (hermetic splice-shape + gated real-pnpm) ────
//
// pnpm 7 (lockfileVersion 5.4) and pnpm 8 ('6.0') are wired by the
// pnpm-legacy vendor backend since 2026-08-18 (they used to refuse). The
// hermetic legs below prove the splice reproduces the captured pnpm-emitted
// shape byte-for-byte with no corepack/network; the `pnpm7_real_*` /
// `pnpm8_real_*` legs run the full lifecycle against the REAL pinned pnpm
// when corepack can fetch it (mirroring the @9/@11 opportunistic pattern —
// @10 stays the primary capstone above).

/// Pinned legacy majors (the exact versions the vendor-legacy spike
/// captured the lock grammars from).
const PNPM_LEGACY_7: &str = "pnpm@7.33.5";
const PNPM_LEGACY_8: &str = "pnpm@8.15.9";

/// Byte-accurate lock captured from a REAL `pnpm@7.33.5 install` of
/// left-pad@1.3.0 (matrix leg vendor-pnpm7): unquoted `lockfileVersion: 5.4`,
/// `specifiers:` section, `/left-pad/1.3.0:` packages key.
const PNPM7_LOCK: &str = "lockfileVersion: 5.4

specifiers:
  left-pad: 1.3.0

dependencies:
  left-pad: 1.3.0

packages:

  /left-pad/1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()
    dev: false
";

/// Byte-accurate lock captured from a REAL `pnpm@8.15.9 install` of the same
/// fixture (matrix leg vendor-pnpm8): quoted `lockfileVersion: '6.0'`,
/// `settings:` section, `/left-pad@1.3.0:` packages key (the `@` rekeying
/// pnpm 8 introduced).
const PNPM8_LOCK: &str = "lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  left-pad:
    specifier: 1.3.0
    version: 1.3.0

packages:

  /left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}
    deprecated: use String.prototype.padStart()
    dev: false
";

/// Expected pnpm-7-shaped lock AFTER vendoring, exactly as `pnpm@7.33.5
/// install` itself serialized the same end state (spike p7): `overrides:`
/// at the ROOT_KEYS_ORDER slot, the SPECIFIER absolutized against the
/// project root (pnpm <= 8 absolutizes file: overrides itself — the
/// documented portability caveat), the dep value + rekeyed packages entry
/// relative, `name:`/`version:` spelled out, `deprecated:` dropped.
/// `{ABS}` / `{INT}` are substituted per run.
const PNPM7_AFTER_TEMPLATE: &str = "lockfileVersion: 5.4

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz

specifiers:
  left-pad: file:{ABS}/.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz

dependencies:
  left-pad: file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz

packages:

  file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz:
    resolution: {integrity: {INT}, tarball: file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz}
    name: left-pad
    version: 1.3.0
    dev: false
";

/// Expected pnpm-8-shaped lock AFTER vendoring (spike p8) — the nested
/// specifier/version grammar, same override/rekey shape.
const PNPM8_AFTER_TEMPLATE: &str = "lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

overrides:
  left-pad@1.3.0: file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz

dependencies:
  left-pad:
    specifier: file:{ABS}/.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz
    version: file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz

packages:

  file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz:
    resolution: {integrity: {INT}, tarball: file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz}
    name: left-pad
    version: 1.3.0
    dev: false
";

#[test]
fn pnpm7_lock_v54_hermetic_splice_idempotency_and_revert() {
    run_legacy_hermetic(PNPM7_LOCK, PNPM7_AFTER_TEMPLATE, "5.4");
}

#[test]
fn pnpm8_lock_v60_hermetic_splice_idempotency_and_revert() {
    run_legacy_hermetic(PNPM8_LOCK, PNPM8_AFTER_TEMPLATE, "6.0");
}

/// The tarball's SRI (`sha512-<base64>`), the integrity spelling pnpm locks
/// record.
fn tarball_integrity(tgz: &Path) -> String {
    use base64::Engine as _;
    use sha2::Sha512;
    let bytes = std::fs::read(tgz).expect("vendored tarball");
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes))
    )
}

/// Hermetic (no corepack, no network) proof that the legacy splice
/// reproduces the pnpm-captured end state byte-for-byte, is idempotent
/// (`skipped`/`already_vendored`, byte-stable), and reverts byte-identical.
/// The absolute-specifier portability caveat must be surfaced as the
/// `vendor_pnpm_legacy_absolute_specifier` run warning, and NO
/// pnpm-workspace.yaml may appear (pnpm <= 8 reads overrides only from
/// package.json).
fn run_legacy_hermetic(lock_text: &str, after_template: &str, version: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    let dep_dir = proj.join("node_modules").join(DEP);
    std::fs::create_dir_all(&dep_dir).unwrap();
    std::fs::write(
        dep_dir.join("package.json"),
        format!("{{\"name\":\"{DEP}\",\"version\":\"{DEP_VERSION}\"}}\n"),
    )
    .unwrap();
    let orig = b"module.exports = function leftPad(str) { return str; };\n".to_vec();
    std::fs::write(dep_dir.join("index.js"), &orig).unwrap();
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    let purl = format!("pkg:npm/{DEP}@{DEP_VERSION}");
    stage_patch(&proj, &purl, "package/index.js", &orig, &patched);

    let pkg_doc = serde_json::json!({
        "name": "pnpm-legacy-hermetic",
        "version": "0.0.0",
        "private": true,
        "dependencies": { DEP: DEP_VERSION },
    });
    let pkg_path = proj.join("package.json");
    let lock_path = proj.join("pnpm-lock.yaml");
    std::fs::write(
        &pkg_path,
        format!("{}\n", serde_json::to_string_pretty(&pkg_doc).unwrap()),
    )
    .unwrap();
    std::fs::write(&lock_path, lock_text).unwrap();
    let pkg_before = std::fs::read(&pkg_path).unwrap();
    let lock_before = std::fs::read(&lock_path).unwrap();

    // 1. Vendor: exits 0 and wires both surfaces.
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
        "vendor must wire a {version} lock.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");
    // The path-bound frozen-install caveat is machine-readable (vendor
    // warnings surface as non-counting skipped events carrying the code).
    assert!(
        env["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["errorCode"] == "vendor_pnpm_legacy_absolute_specifier"),
        "the absolute-specifier caveat must be surfaced: {env}"
    );

    let tgz_rel = format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}.tgz");
    assert!(
        proj.join(&tgz_rel).is_file(),
        "tarball missing at {tgz_rel}"
    );

    // package.json gained the versioned override.
    let pkg_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pkg_path).unwrap()).unwrap();
    assert_eq!(
        pkg_json["pnpm"]["overrides"][format!("{DEP}@{DEP_VERSION}")].as_str(),
        Some(format!("file:{tgz_rel}").as_str()),
        "package.json must gain pnpm.overrides: {pkg_json}"
    );

    // The lock is byte-identical to what the REAL pnpm serialized for this
    // end state (spike p7/p8), with the live absolute root + integrity.
    let abs = std::fs::canonicalize(&proj).unwrap();
    let expected = after_template
        .replace("{UUID}", UUID)
        .replace("{ABS}", &abs.display().to_string())
        .replace("{INT}", &tarball_integrity(&proj.join(&tgz_rel)));
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    assert_eq!(
        lock_after, expected,
        "{version} lock must match the pnpm-captured after shape byte-for-byte"
    );

    // pnpm <= 8 reads overrides only from package.json — creating a
    // workspace file would flip the project into workspace mode.
    assert!(
        !proj.join("pnpm-workspace.yaml").exists(),
        "legacy wiring must not create pnpm-workspace.yaml"
    );

    // 2. Idempotency: re-run skips (`already_vendored`), all bytes stable.
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
    assert_eq!(code, 0, "re-vendor.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let env2 = parse_envelope(&stdout);
    assert!(
        env2["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "skipped" && e["errorCode"] == "already_vendored"),
        "in-sync rerun must report already_vendored: {env2}"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        lock_after,
        "re-vendor must leave the lock byte-identical"
    );
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        pkg_wired,
        "re-vendor must leave package.json byte-identical"
    );

    // 3. Revert: both files byte-restored, artifact gone.
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
    assert_eq!(code, 0, "revert.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        pkg_before,
        "revert must restore package.json byte-identical"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "revert must restore pnpm-lock.yaml byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
}

// ── gated real-pnpm legacy lifecycle legs ─────────────────────────────

#[test]
fn pnpm7_real_lifecycle_same_path_frozen_and_moved_checkout_offline() {
    if !has_corepack_pm(PNPM_LEGACY_7) {
        println!("SKIP: `corepack {PNPM_LEGACY_7}` unavailable");
        return;
    }
    run_legacy_capstone(PNPM_LEGACY_7, "lockfileVersion: 5.4");
}

#[test]
fn pnpm8_real_lifecycle_same_path_frozen_and_moved_checkout_offline() {
    if !has_corepack_pm(PNPM_LEGACY_8) {
        println!("SKIP: `corepack {PNPM_LEGACY_8}` unavailable");
        return;
    }
    run_legacy_capstone(PNPM_LEGACY_8, "lockfileVersion: '6.0'");
}

/// Full lifecycle against the REAL pinned legacy pnpm, spike-proven flags:
///
/// 1. online fixture install (skip when the registry is unreachable);
/// 2. vendor --json --offline wires package.json + the legacy lock (no
///    pnpm-workspace.yaml);
/// 3. SAME-PATH strict proof: wipe node_modules, EMPTY store,
///    `install --frozen-lockfile --offline` → marker bytes (the absolute
///    specifier matches this checkout, spike probe A);
/// 4. MOVED-CHECKOUT proof: committables copied to a different dir with a
///    dead-registry .npmrc and an EMPTY store — `--frozen-lockfile` MUST
///    fail (pnpm <= 8's path-bound frozen check, spike probe B pins the
///    documented limitation) and plain `install --offline` MUST land the
///    marker bytes (probe C);
/// 5. idempotent re-vendor (byte-stable, already_vendored);
/// 6. revert restores both files byte-identical and removes .socket/vendor.
fn run_legacy_capstone(pm: &str, lock_head: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let pkg_doc = serde_json::json!({
        "name": "pnpm-legacy-capstone",
        "version": "0.0.0",
        "private": true,
        "dependencies": { DEP: DEP_VERSION },
    });
    std::fs::write(
        proj.join("package.json"),
        format!("{}\n", serde_json::to_string_pretty(&pkg_doc).unwrap()),
    )
    .unwrap();

    // 1. REAL fixture install (network allowed here, private store).
    let store = tmp.path().join("pnpm-store");
    let install = corepack(
        &proj,
        pm,
        &["install", "--store-dir", store.to_str().unwrap()],
    );
    if !install.status.success() {
        println!(
            "SKIP legacy capstone ({pm}): fixture `pnpm install` failed (registry \
             unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }

    let installed_index = proj.join("node_modules").join(DEP).join("index.js");
    let orig = std::fs::read(&installed_index).expect("installed index.js");
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    let purl = format!("pkg:npm/{DEP}@{DEP_VERSION}");
    stage_patch(&proj, &purl, "package/index.js", &orig, &patched);

    let lock_path = proj.join("pnpm-lock.yaml");
    let pkg_path = proj.join("package.json");
    let lock_before = std::fs::read(&lock_path).expect("lock after pnpm install");
    let pkg_before = std::fs::read(&pkg_path).unwrap();
    let lock_before_str = String::from_utf8(lock_before.clone()).unwrap();
    assert!(
        lock_before_str.starts_with(lock_head),
        "fixture must be a {lock_head} lock:\n{lock_before_str}"
    );

    // 2. Vendor (offline).
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
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let tgz_rel = format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}.tgz");
    assert!(proj.join(&tgz_rel).is_file());
    assert!(
        !proj.join("pnpm-workspace.yaml").exists(),
        "legacy wiring must not create pnpm-workspace.yaml ({pm})"
    );
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    let abs = std::fs::canonicalize(&proj).unwrap();
    assert!(
        lock_after.contains(&format!("{DEP}@{DEP_VERSION}: file:{tgz_rel}")),
        "lock overrides must point at the vendored tarball ({pm}):\n{lock_after}"
    );
    assert!(
        lock_after.contains(&format!("file:{}/{tgz_rel}", abs.display())),
        "lock specifier must carry pnpm <= 8's absolutized spelling ({pm}):\n{lock_after}"
    );
    eprintln!("VENDOR OK ({pm})");

    // 3. SAME-PATH strict proof: wipe node_modules, EMPTY store, the
    //    spike-proven strictest invocation.
    std::fs::remove_dir_all(proj.join("node_modules")).unwrap();
    let same_store = tmp.path().join("store-same");
    let ci = corepack(
        &proj,
        pm,
        &[
            "install",
            "--frozen-lockfile",
            "--offline",
            "--store-dir",
            same_store.to_str().unwrap(),
        ],
    );
    assert!(
        ci.status.success(),
        "same-path `install --frozen-lockfile --offline` must succeed from the vendored \
         tarball ({pm}).\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let same_installed = std::fs::read(&installed_index).unwrap();
    assert_eq!(
        same_installed, patched,
        "same-path frozen+offline install must land the patched bytes ({pm})"
    );
    eprintln!("SAME-PATH FROZEN INSTALL OK ({pm})");

    // The lock must be byte-stable under pnpm's own re-serialization.
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        lock_after,
        "pnpm's own install must leave the spliced lock byte-identical ({pm})"
    );

    // 4. MOVED-CHECKOUT proof (different absolute path, dead registry,
    //    EMPTY store): frozen fails — the documented pnpm <= 8 limitation —
    //    and plain --offline lands the marker.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&pkg_path, fresh.join("package.json")).unwrap();
    std::fs::copy(&lock_path, fresh.join("pnpm-lock.yaml")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    std::fs::write(fresh.join(".npmrc"), "registry=http://127.0.0.1:1/\n").unwrap();

    let fresh_store = tmp.path().join("store-fresh");
    let frozen = corepack(
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
        !frozen.status.success(),
        "pnpm <= 8's frozen check is path-bound (absolute specifier): a moved checkout \
         passing --frozen-lockfile would invalidate the documented caveat ({pm})"
    );

    // `--no-frozen-lockfile` is load-bearing, not belt-and-braces: pnpm
    // defaults --frozen-lockfile ON when CI=true, and the moved-checkout
    // recovery WORKS by re-resolving the path-bound absolute specifier —
    // frozen semantics skip that re-resolution and fail (observed on CI:
    // ERR_PNPM_OUTDATED_LOCKFILE on pnpm 8, stale-path install on pnpm 7).
    let plain = corepack(
        &fresh,
        pm,
        &[
            "install",
            "--offline",
            "--no-frozen-lockfile",
            "--store-dir",
            fresh_store.to_str().unwrap(),
        ],
    );
    assert!(
        plain.status.success(),
        "moved-checkout `install --offline --no-frozen-lockfile` must succeed from the \
         vendored tarball ({pm}).\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&plain.stdout),
        String::from_utf8_lossy(&plain.stderr),
    );
    let fresh_installed =
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert_eq!(
        fresh_installed, patched,
        "moved-checkout install must land the patched bytes ({pm})"
    );
    eprintln!("MOVED-CHECKOUT OFFLINE INSTALL OK ({pm})");

    // 5. Idempotency in the original project.
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
    assert!(
        env2["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "skipped" && e["errorCode"] == "already_vendored"),
        "in-sync rerun must report already_vendored ({pm}): {env2}"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        lock_after,
        "re-vendor must be byte-stable ({pm})"
    );

    // 6. Revert restores the pair byte-identical.
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
    assert_eq!(renv["summary"]["removed"], 1, "{renv}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "revert must restore pnpm-lock.yaml byte-identical ({pm})"
    );
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        pkg_before,
        "revert must restore package.json byte-identical ({pm})"
    );
    assert!(!proj.join(".socket/vendor").exists());
    eprintln!("REVERT OK ({pm})");
}
