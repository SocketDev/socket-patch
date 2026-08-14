//! Real-composer capstone e2e for `socket-patch vendor` — the composer
//! committability proof on the HOST toolchain (the docker twin is
//! `docker_e2e_vendor_composer.rs`; this suite adds coverage on developer/CI
//! hosts that carry composer 2 — hosts without it compile the test and
//! soft-skip).
//!
//! Drives the REAL composer (network used for fixture setup only):
//!   1. `composer update` resolves a real psr/log 3.0.x into `vendor/`
//!      (private COMPOSER_HOME + cache).
//!   2. Hand-stage a `.socket/` manifest + blob whose before/after Git-blob
//!      hashes are computed from the ACTUAL installed bytes (a trailing
//!      marker comment on `src/LoggerInterface.php` — still valid php).
//!   3. `socket-patch vendor --json --offline` — assert the vendored copy at
//!      `.socket/vendor/composer/<uuid>/psr/log@<ver>` and the lock-only
//!      wiring: the psr/log entry's `dist` becomes `{type: path, url: <copy>,
//!      reference: <patch-uuid>}` with `transport-options.symlink === false`
//!      (forces a real copy) and `source` REMOVED; composer.json stays
//!      byte-untouched.
//!   4. **VEX (vendored) leg**: `socket-patch vex` attests the patch against
//!      the committed copy with the `(vendored)` impact marker.
//!   5. **Fresh-checkout proof**: ONLY the committable files (composer.json,
//!      composer.lock, `.socket/`) travel to a new dir; `composer install`
//!      with a cold COMPOSER_HOME/cache materializes `vendor/psr/log` as a
//!      REAL directory (not a symlink) holding the patched bytes, and the
//!      patch uuid survives into `vendor/composer/installed.json`
//!      (`dist.reference`).
//!   6. Idempotency: a re-vendor leaves composer.lock byte-identical.
//!   7. **Revert proof**: `vendor --revert` restores composer.lock
//!      byte-for-byte and removes `.socket/vendor/` entirely.
//!
//! Skips (with a println) when `composer` is not installed (this host) or
//! the fixture install cannot reach packagist; every assertion after that is
//! hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

#[path = "common/cache_env.rs"]
mod cache_env;

/// Canonical lowercase patch uuid (a dedicated path level under
/// `.socket/vendor/composer/`) — also what `dist.reference` must carry.
const UUID: &str = "4d5e6f7a-8b9c-4a1b-8c2d-0123456789ab";
const GHSA: &str = "GHSA-vend-composer-host";
/// The dependency under test — dep-free, tiny, and the same fixture the
/// docker twin uses.
const DEP: &str = "psr/log";
/// Version the hand-written (composer-free) revert fixtures below pin.
const FIXTURE_VERSION: &str = "3.0.2";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn has_command(cmd: &str) -> bool {
    let mut probe = Command::new(cmd);
    probe.arg("--version");
    cache_env::isolate(&mut probe);
    probe
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Run the socket-patch binary with a scrubbed environment: every ambient
/// `SOCKET_*` var is removed (so a developer's `SOCKET_DRY_RUN=1` etc. can't
/// flip behavior) along with `VIRTUAL_ENV` (crawler discovery input).
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") && k.to_string_lossy() != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run `composer <args>` in `cwd` with a PRIVATE home + cache (the host's
/// composer state must neither leak in nor be polluted).
fn composer(cwd: &Path, args: &[&str], home: &Path, cache: &Path) -> Output {
    std::fs::create_dir_all(home).unwrap();
    std::fs::create_dir_all(cache).unwrap();
    let mut cmd = Command::new("composer");
    cmd.args(args).arg("--no-interaction").current_dir(cwd);
    cache_env::isolate(&mut cmd);
    cmd.env("COMPOSER_HOME", home)
        .env("COMPOSER_CACHE_DIR", cache)
        .output()
        .expect("failed to run composer")
}

/// Git-blob SHA-256 (`sha256("blob <len>\0" ++ bytes)`) — the hash format
/// socket-patch records in manifests.
fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Write `.socket/manifest.json` + the after-hash blob (with a vulnerability
/// so the VEX leg has a statement to emit) so vendor runs fully offline.
fn stage_patch_with_vuln(proj: &Path, purl: &str, file_key: &str, before: &[u8], after: &[u8]) {
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
            "vulnerabilities": { GHSA: {
                "cves": ["CVE-2026-44444"],
                "summary": "composer capstone vex vuln",
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

/// The resolved (leading-`v`-stripped) version of `name` from composer.lock's
/// `packages[]`.
fn locked_composer_version(lock_path: &Path, name: &str) -> Option<String> {
    let lock: serde_json::Value = serde_json::from_slice(&std::fs::read(lock_path).ok()?).ok()?;
    lock["packages"].as_array()?.iter().find_map(|p| {
        if p["name"] == name {
            Some(p["version"].as_str()?.trim_start_matches('v').to_string())
        } else {
            None
        }
    })
}

/// The psr/log entry from a composer.lock's `packages[]` (owned clone, for
/// assertion messages).
fn lock_entry(lock_path: &Path, name: &str) -> serde_json::Value {
    let lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(lock_path).expect("read composer.lock"))
            .expect("composer.lock parses");
    lock["packages"]
        .as_array()
        .expect("packages[]")
        .iter()
        .find(|p| p["name"] == name)
        .unwrap_or_else(|| panic!("{name} entry missing from composer.lock"))
        .clone()
}

// ── the capstone ──────────────────────────────────────────────────────

#[test]
#[ignore = "host capstone: shells out to a real composer 2; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn composer_vendor_fresh_checkout_install_and_revert() {
    if !has_command("composer") {
        println!("SKIP e2e_vendor_composer_build: `composer` not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("composer.json"),
        r#"{
    "name": "socket/vendor-capstone",
    "description": "socket-patch vendor host capstone fixture",
    "require": {
        "psr/log": "3.0.*"
    }
}
"#,
    )
    .unwrap();

    // 1. REAL fixture: composer update resolves + installs psr/log from
    //    packagist (network allowed here only, private home + cache).
    let home = tmp.path().join("composer-home");
    let cache = tmp.path().join("composer-cache");
    let update = composer(&proj, &["update"], &home, &cache);
    if !update.status.success() {
        println!(
            "SKIP e2e_vendor_composer_build: `composer update` failed (packagist \
             unreachable?):\n{}",
            String::from_utf8_lossy(&update.stderr)
        );
        return;
    }

    let lock_path = proj.join("composer.lock");
    let version = locked_composer_version(&lock_path, DEP)
        .unwrap_or_else(|| panic!("{DEP} not present in composer.lock after update"));

    let installed_php = proj.join("vendor/psr/log/src/LoggerInterface.php");
    let orig = std::fs::read(&installed_php).expect("installed LoggerInterface.php");
    assert!(
        !String::from_utf8_lossy(&orig).contains("SOCKET-PATCH-VENDOR-E2E-MARKER"),
        "pristine install must not carry the marker"
    );

    // 2. Marker patch = the ACTUAL installed bytes + a trailing marker
    //    comment (still valid php).
    let marker = format!("\n// SOCKET-PATCH-VENDOR-E2E-MARKER patch={UUID}\n");
    let patched: Vec<u8> = [orig.as_slice(), marker.as_bytes()].concat();
    let purl = format!("pkg:composer/{DEP}@{version}");
    stage_patch_with_vuln(&proj, &purl, "src/LoggerInterface.php", &orig, &patched);

    let json_before = std::fs::read(proj.join("composer.json")).unwrap();
    let lock_before = std::fs::read(&lock_path).unwrap();

    // 3. Vendor (offline: the blob is staged locally → zero network).
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

    // Artifact under the stable path convention, patched byte-for-byte, plus
    // the informational marker and the committed ledger.
    let copy_rel = format!(".socket/vendor/composer/{UUID}/{DEP}@{version}");
    assert_eq!(
        std::fs::read(proj.join(&copy_rel).join("src/LoggerInterface.php")).unwrap(),
        patched,
        "vendored LoggerInterface.php must hold the patched bytes"
    );
    assert!(
        proj.join(format!(
            ".socket/vendor/composer/{UUID}/socket-patch.vendor.json"
        ))
        .is_file(),
        "informational vendor marker missing"
    );
    assert!(
        proj.join(".socket/vendor/state.json").is_file(),
        "vendor ledger missing"
    );

    // Lock wiring (the composer contract row): dist → {type: path, url,
    // reference: <patch-uuid>}, transport-options.symlink === false (forces a
    // real copy at install), source REMOVED; composer.json byte-untouched.
    let entry = lock_entry(&lock_path, DEP);
    assert_eq!(entry["dist"]["type"], "path", "dist.type: {entry}");
    assert_eq!(entry["dist"]["url"], copy_rel, "dist.url: {entry}");
    assert_eq!(entry["dist"]["reference"], UUID, "dist.reference: {entry}");
    assert_eq!(
        entry["transport-options"]["symlink"],
        serde_json::Value::Bool(false),
        "transport-options.symlink: {entry}"
    );
    assert!(
        entry.get("source").is_none(),
        "source must be removed from the wired entry: {entry}"
    );
    assert_eq!(
        std::fs::read(proj.join("composer.json")).unwrap(),
        json_before,
        "vendor must NOT touch composer.json (lock-only wiring)"
    );

    // 4. VEX (vendored) leg: attest the patch against the committed copy
    //    (composer has no product auto-detect, so `--product` is explicit).
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
            "pkg:composer/app@1.0.0",
        ],
    );
    assert_eq!(code, 0, "vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "the vendored composer patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], purl);
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    assert!(
        impact.contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {impact}"
    );

    // 5. FRESH-CHECKOUT PROOF: ONLY the committable files, cold composer
    //    home + cache — the vendored path dist is the only possible source
    //    of psr/log.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("composer.json"), fresh.join("composer.json")).unwrap();
    std::fs::copy(&lock_path, fresh.join("composer.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    assert!(
        !fresh.join("vendor").exists(),
        "fresh checkout must not carry an installed tree (test bug)"
    );

    let fresh_home = tmp.path().join("cold-composer-home");
    let fresh_cache = tmp.path().join("cold-composer-cache");
    let install = composer(&fresh, &["install"], &fresh_home, &fresh_cache);
    assert!(
        install.status.success(),
        "cold-cache `composer install` must succeed from the vendored path dist.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    // Real COPY, not a symlink (transport-options symlink:false is
    // load-bearing — a symlink would dangle in any other checkout).
    let installed_dir = fresh.join("vendor/psr/log");
    assert!(
        installed_dir.is_dir(),
        "vendor/psr/log missing after install"
    );
    assert!(
        !std::fs::symlink_metadata(&installed_dir)
            .unwrap()
            .file_type()
            .is_symlink(),
        "vendor/psr/log is a SYMLINK — symlink:false not honored"
    );
    assert_eq!(
        std::fs::read(installed_dir.join("src/LoggerInterface.php")).unwrap(),
        patched,
        "installed LoggerInterface.php must be byte-identical to the patched content"
    );

    // In-tree traceability: composer preserves dist.reference verbatim into
    // vendor/composer/installed.json — the patch uuid must survive there.
    let installed_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fresh.join("vendor/composer/installed.json")).unwrap(),
    )
    .unwrap();
    // composer 2 wraps the list in {"packages": [...]}; composer 1 wrote a
    // bare array — accept both like the docker twin's php oracle.
    let installed_pkgs = installed_json
        .get("packages")
        .and_then(|p| p.as_array())
        .or_else(|| installed_json.as_array())
        .expect("installed.json package list");
    let installed_entry = installed_pkgs
        .iter()
        .find(|p| p["name"] == DEP)
        .unwrap_or_else(|| panic!("{DEP} missing from installed.json"));
    assert_eq!(
        installed_entry["dist"]["reference"], UUID,
        "installed.json must carry dist.reference == patch uuid: {installed_entry}"
    );

    // 6. Idempotency: a re-run exits 0 and leaves the lock byte-stable.
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
        "re-vendor must leave composer.lock byte-identical"
    );

    // 7. REVERT PROOF: lock restored byte-for-byte, artifacts gone,
    //    composer.json still untouched.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
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
        "revert must restore composer.lock byte-identical to the pre-vendor snapshot"
    );
    assert_eq!(
        std::fs::read(proj.join("composer.json")).unwrap(),
        json_before,
        "composer.json must stay untouched through revert"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
}

// ── revert against ledger state the capstone above never produces ─────
//
// Both regressions below are about `.socket/vendor/` state that outlived (or
// was rebuilt without) its wiring record, which the capstone's clean
// vendor→revert round trip cannot reach. They hand-write the wired lock +
// artifact instead of driving composer, so they need neither the toolchain
// nor the network and run in the normal `test` job (no `#[ignore]`).

/// `repair`-reconstructed ledger entry: recovered from the lockfile path, so
/// it owns the artifact but records NO pre-vendor wiring (see
/// `repair_vendor.rs`'s `synth_entry`).
const UUID_RECONSTRUCTED: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
/// Un-ledgered artifact dir that composer.lock still points at.
const UUID_ORPHAN_WIRED: &str = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
/// Un-ledgered artifact dir nothing references.
const UUID_ORPHAN_DEAD: &str = "3c4d5e6f-7a8b-4c9d-8e0f-2a3b4c5d6e7f";

const FIXTURE_PHP: &[u8] =
    b"<?php\n// SOCKET-PATCH-VENDOR-E2E-MARKER\ninterface LoggerInterface {}\n";

/// Write the vendored copy for `uuid` (dir-shaped, as the composer backend
/// materializes it) and return its project-relative path.
fn write_vendored_copy(proj: &Path, uuid: &str) -> String {
    let copy_rel = format!(".socket/vendor/composer/{uuid}/{DEP}@{FIXTURE_VERSION}");
    let src = proj.join(&copy_rel).join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("LoggerInterface.php"), FIXTURE_PHP).unwrap();
    copy_rel
}

/// composer.json + a composer.lock ALREADY wired to `uuid`'s copy — the
/// exact surgery `vendor` writes (path dist, uuid `reference`, `symlink:
/// false`, `source` gone) and what a fresh clone of a vendored project has.
fn write_wired_project(proj: &Path, uuid: &str) -> String {
    let copy_rel = write_vendored_copy(proj, uuid);
    std::fs::write(
        proj.join("composer.json"),
        r#"{
    "name": "socket/vendor-revert-fixture",
    "require": {
        "psr/log": "3.0.*"
    }
}
"#,
    )
    .unwrap();
    let lock = serde_json::json!({
        "_readme": ["This file locks the dependencies of your project to a known state"],
        "content-hash": "7a59d114f58e9b02546b21d7e57430d3",
        "packages": [{
            "name": DEP,
            "version": FIXTURE_VERSION,
            "dist": { "type": "path", "url": copy_rel, "reference": uuid },
            "transport-options": { "symlink": false },
            "type": "library",
        }],
        "packages-dev": [],
        "minimum-stability": "stable",
        "plugin-api-version": "2.6.0",
    });
    std::fs::write(
        proj.join("composer.lock"),
        format!("{}\n", serde_json::to_string_pretty(&lock).unwrap()),
    )
    .unwrap();
    copy_rel
}

/// The `.socket/vendor/state.json` a `repair` reconstruction leaves: artifact
/// + uuid recovered from the lock path, `wiring` empty.
fn write_reconstructed_ledger(proj: &Path, uuid: &str, copy_rel: &str) {
    let purl = format!("pkg:composer/{DEP}@{FIXTURE_VERSION}");
    let state = serde_json::json!({
        "version": 1,
        "entries": { purl.clone(): {
            "ecosystem": "composer",
            "basePurl": purl,
            "uuid": uuid,
            "artifact": { "path": copy_rel },
            "wiring": [],
        }}
    });
    std::fs::write(
        proj.join(".socket/vendor/state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

fn events(env: &serde_json::Value) -> &Vec<serde_json::Value> {
    env["events"].as_array().expect("events[]")
}

/// REGRESSION: reverting a `repair`-reconstructed entry must not strand
/// composer.lock. There is no recorded registry `dist` to put back, so the
/// revert has to REFUSE and keep the artifacts — deleting them while the lock
/// still points at them made the next `composer install` fail with "Source
/// path … is not found", and the run reported success.
#[test]
fn revert_of_reconstructed_entry_refuses_and_keeps_artifacts() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let copy_rel = write_wired_project(&proj, UUID_RECONSTRUCTED);
    write_reconstructed_ledger(&proj, UUID_RECONSTRUCTED, &copy_rel);

    let lock_path = proj.join("composer.lock");
    let lock_before = std::fs::read(&lock_path).unwrap();
    let state_before = std::fs::read(proj.join(".socket/vendor/state.json")).unwrap();

    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 1,
        "an unrestorable entry must fail the revert.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "partialFailure", "envelope: {env}");
    assert_eq!(env["summary"]["removed"], 0, "nothing reverted: {env}");
    let failed = events(&env)
        .iter()
        .find(|e| e["action"] == "failed")
        .unwrap_or_else(|| panic!("expected a failed event: {env}"));
    assert_eq!(failed["errorCode"], "revert_failed", "{failed}");
    let detail = failed["error"].as_str().expect("error detail");
    assert!(
        detail.contains(DEP) && detail.contains("composer update"),
        "the refusal must name the package and the re-resolve escape hatch: {detail}"
    );

    assert!(
        proj.join(&copy_rel)
            .join("src/LoggerInterface.php")
            .exists(),
        "a refused revert must NOT delete the artifacts the lock still consumes"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "composer.lock must be left exactly as it was"
    );
    assert_eq!(
        std::fs::read(proj.join(".socket/vendor/state.json")).unwrap(),
        state_before,
        "the entry must stay in the ledger so a later repair/revert can retry"
    );
}

/// REGRESSION: with state.json gone, the orphan sweep must not delete a uuid
/// dir composer.lock still points at — un-ledgered does not mean un-wired
/// (that is exactly the state `repair` reconstructs from). A genuinely
/// unreferenced dir in the same run must still be swept.
#[test]
fn orphan_sweep_keeps_lock_referenced_dir_when_ledger_is_gone() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let wired_rel = write_wired_project(&proj, UUID_ORPHAN_WIRED);
    let dead_rel = write_vendored_copy(&proj, UUID_ORPHAN_DEAD);
    assert!(
        !proj.join(".socket/vendor/state.json").exists(),
        "fixture models a project whose ledger was deleted"
    );

    let lock_before = std::fs::read(proj.join("composer.lock")).unwrap();
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "sweeping is not a failure.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);

    assert!(
        proj.join(&wired_rel)
            .join("src/LoggerInterface.php")
            .exists(),
        "the lock-referenced artifact must survive the sweep: {env}"
    );
    assert!(
        !proj
            .join(format!(".socket/vendor/composer/{UUID_ORPHAN_DEAD}"))
            .exists(),
        "the unreferenced orphan must still be swept: {env}"
    );
    assert_eq!(
        std::fs::read(proj.join("composer.lock")).unwrap(),
        lock_before,
        "the sweep must not touch composer.lock"
    );
    assert!(
        events(&env)
            .iter()
            .any(|e| e["errorCode"] == "vendor_orphan_still_wired"
                && e["reason"]
                    .as_str()
                    .is_some_and(|r| r.contains(UUID_ORPHAN_WIRED))),
        "the kept dir must be surfaced as an advisory: {env}"
    );
    assert!(
        events(&env).iter().any(|e| e["action"] == "removed"
            && e["errorCode"] == "vendor_orphan_removed"
            && e["purl"]
                .as_str()
                .is_some_and(|p| p.contains(&format!("{DEP}@{FIXTURE_VERSION}"))
                    || p.contains(UUID_ORPHAN_DEAD))),
        "the swept dir must be reported: {env}"
    );
    assert_eq!(
        dead_rel,
        format!(".socket/vendor/composer/{UUID_ORPHAN_DEAD}/{DEP}@{FIXTURE_VERSION}"),
        "fixture path convention"
    );
}
