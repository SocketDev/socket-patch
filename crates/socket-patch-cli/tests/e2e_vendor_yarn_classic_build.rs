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
//!   7. **Manifest-less VEX** on the fresh checkout (`ManifestlessVex`):
//!      with `.socket/manifest.json` deleted, then the vendor ledger too, the
//!      patch is still attested `(vendored)` from the `yarn.lock` wiring +
//!      committed tarball (record from the patch API); `--offline` is
//!      `record_unavailable` with zero API requests; a lock reverted to the
//!      registry (and really re-installed) is NOT attested even though the
//!      ledger and tarball remain — plus embedded `apply --vex` /
//!      `vendor --vex`.
//!
//! The detached twin (`yarn_classic_detached_scan_vendored_…`) produces the
//! state with `scan --mode vendored --detached` against a wiremock Socket
//! API instead — the vendored shape that never has a manifest — and runs the
//! same fresh-checkout install + manifest-less VEX matrix (plus the embedded
//! re-scan).
//!
//! The yarn release is `yarn@1.22.22` unless
//! `SOCKET_PATCH_YARN_CLASSIC_E2E_VERSION` names another 1.x (see
//! `common/yarn_classic_vex.rs`).
//!
//! LOCAL capstone (not behind docker-e2e): skips with a `println` + return
//! when `corepack` (yarn classic) is unavailable or the fixture install
//! cannot reach the registry — unless `SOCKET_PATCH_YARN_E2E_REQUIRED=1`;
//! every assertion after that is HARD.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

/// Canonical lowercase patch uuid (a dedicated path level under
/// `.socket/vendor/npm/`).
const UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab";
/// Marker prepended to the dep's entry point by the synthetic patch.
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const GHSA: &str = "GHSA-vend-yarn-real";
const CVE: &str = "CVE-2024-88888";

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[path = "common/yarn_classic_vex.rs"]
mod yarn_classic_vex;

use yarn_classic_vex::{
    require_yarn_classic, via_apply, via_vendor, yarn_classic, ManifestlessVex, Wiring,
};

/// Print a SKIP line — or, under `SOCKET_PATCH_YARN_E2E_REQUIRED=1` (a leg
/// that provisioned corepack yarn on purpose), FAIL: a required leg must
/// never report green on an unexercised toolchain or an unreachable fixture
/// registry.
macro_rules! skip {
    ($($arg:tt)*) => {{
        yarn_classic_vex::skip("e2e_vendor_yarn_classic_build", &format!($($arg)*));
    }};
}

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Run `corepack <pm> <args>` in `cwd` with the given extra env, the download
/// prompt disabled, and every `SOCKET_*` var scrubbed.
fn corepack(cwd: &Path, pm: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
    // Scrub FIRST (it removes YARN_CACHE_FOLDER / SOCKET_* from the inherited
    // env), then seed the hermetic flags so they survive (Command: last env
    // call wins). Scrubbing last wiped the caller's private cache override,
    // so the fixture install silently used the developer's global cache.
    scrub_socket_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run corepack")
}

/// Remove every ambient `SOCKET_*` var (so a developer's `SOCKET_DRY_RUN=1`
/// etc. can't flip behavior) and the PM cache var the harness controls.
fn scrub_socket_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy();
        if k.starts_with("SOCKET_") && k != "SOCKET_NO_CONFIG" {
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
            "vulnerabilities": { GHSA: {
                "cves": [CVE],
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
fn yarn_classic_vendor_fresh_checkout_frozen_offline_install_and_revert() {
    if !require_yarn_classic("e2e_vendor_yarn_classic_build", |c| {
        cache_env::isolate(c);
    }) {
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
        &yarn_classic(),
        &["install", "--no-progress"],
        &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
    );
    if !install.status.success() {
        skip!(
            "fixture `yarn install` failed (registry unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }

    // Hermeticity guard: the install must have gone through the PRIVATE cache.
    // If YARN_CACHE_FOLDER never reached the child, yarn silently used the
    // user's global cache and the fresh-checkout "empty cache" premise is
    // void (a leaked run even parks the PATCHED tarball in the global cache).
    assert!(
        cache.is_dir() && std::fs::read_dir(&cache).unwrap().next().is_some(),
        "fixture install did not populate the private YARN_CACHE_FOLDER at {}",
        cache.display()
    );

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
    // Run-level advisory: the fixture has no `packageManager` pin, so the
    // wired classic lockfile is one stray `yarn@2+ install` away from being
    // silently de-patched — the envelope must say so.
    let run_warnings = env["warnings"].as_array().unwrap_or_else(|| {
        panic!("wired classic project without a yarn@1 pin must carry run-level warnings: {env}")
    });
    assert!(
        run_warnings
            .iter()
            .any(|w| w["code"] == "yarn_classic_berry_migration_risk"),
        "expected yarn_classic_berry_migration_risk: {env}"
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

    // Real-toolchain VEX: attest the vendored patch (`(vendored)` marker).
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
    assert_eq!(code, 0, "vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let vex_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    let vex_stmts = vex_doc["statements"].as_array().unwrap();
    assert_eq!(
        vex_stmts.len(),
        1,
        "vendored patch must be attested: {vex_doc}"
    );
    assert_eq!(vex_stmts[0]["vulnerability"]["name"], "GHSA-vend-yarn-real");
    assert_eq!(vex_stmts[0]["products"][0]["subcomponents"][0]["@id"], purl);
    assert!(
        vex_stmts[0]["impact_statement"]
            .as_str()
            .unwrap()
            .contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {vex_doc}"
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
        &yarn_classic(),
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
    let tarball_capable =
        yarn_classic_vex::installs_file_tarballs(&yarn_classic_vex::yarn_classic_version());
    if !tarball_capable {
        // KNOWN yarn < 1.7 LIMITATION (see `installs_file_tarballs`): the
        // install "succeeds" having installed nothing for the vendored
        // entry. Pin the shape so a behavior change is noticed; the
        // manifest-less VEX below still runs (it verifies the committed
        // artifact, not the installed tree).
        assert!(
            !fresh.join("node_modules").join(DEP).exists(),
            "yarn {} unexpectedly installed a `file:` tarball entry — the \
             installs_file_tarballs boundary moved",
            yarn_classic()
        );
        println!(
            "KNOWN LIMITATION {}: a vendored `file:` tarball lock entry installs nothing",
            yarn_classic()
        );
    }
    // Same guard for the fresh install: yarn unpacks even `file:` tarballs
    // through its cache, so an untouched fresh_cache means the GLOBAL cache
    // served the install and the offline-from-vendored-tarball proof is
    // vacuous.
    if tarball_capable {
        assert!(
            fresh_cache.is_dir() && std::fs::read_dir(&fresh_cache).unwrap().next().is_some(),
            "fresh install did not populate the private YARN_CACHE_FOLDER at {}",
            fresh_cache.display()
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
    }

    // 7. MANIFEST-LESS VEX over the really-installed fresh checkout (a copy,
    //    so the idempotency/revert legs below still see the vendored proj).
    let vex_dir = tmp.path().join("fresh-vex");
    copy_dir_recursive(&fresh, &vex_dir);
    let api = vex_e2e_common::PatchApi::start(vec![(
        UUID.to_string(),
        vex_e2e_common::patch_view(
            UUID,
            &purl,
            &[("package/index.js", &vex_e2e_common::git_sha256(&patched))],
            &[(GHSA, &[CVE])],
        ),
    )]);
    let reverted_cache = tmp.path().join("reverted-yarn-cache");
    ManifestlessVex {
        leg: "vendor-build",
        wiring: Wiring::Vendored,
        purl: &purl,
        uuid: UUID,
        vulns: &[(GHSA, &[CVE])],
        api: &api,
        proxy_override: None,
        patch_server_url: None,
        registry_lock: lock_before.clone(),
        // A real `yarn install --frozen-lockfile` of the reverted lock (from
        // the registry): pristine bytes, the committed tarball unused.
        reinstall: Some(Box::new(|dir: &Path| {
            // (Absent on yarn < 1.7, which installed nothing above.)
            let _ = std::fs::remove_dir_all(dir.join("node_modules"));
            let out = corepack(
                dir,
                &yarn_classic(),
                &["install", "--frozen-lockfile", "--no-progress"],
                &[("YARN_CACHE_FOLDER", reverted_cache.to_str().unwrap())],
            );
            assert!(
                out.status.success(),
                "reverted-lock `yarn install --frozen-lockfile` failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                std::fs::read(dir.join("node_modules").join(DEP).join("index.js")).unwrap(),
                orig,
                "the reverted lock installs pristine bytes"
            );
        })),
        embedded: vec![("apply --vex", via_apply()), ("vendor --vex", via_vendor())],
    }
    .run(&vex_dir);
    eprintln!("MANIFEST-LESS VEX OK");

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
    // The advisory is state-based: an in-sync re-run (wiring still on disk)
    // must warn again…
    assert!(
        env2["warnings"].as_array().is_some_and(|ws| ws
            .iter()
            .any(|w| w["code"] == "yarn_classic_berry_migration_risk")),
        "in-sync re-run must still carry the migration-risk advisory: {env2}"
    );
    // …and a `packageManager: yarn@1…` pin must silence it (corepack makes
    // stray berry installs refuse instead of migrate).
    let pkg_path = proj.join("package.json");
    let mut pkg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pkg_path).unwrap()).unwrap();
    pkg["packageManager"] = serde_json::Value::String("yarn@1.22.22".to_string());
    std::fs::write(&pkg_path, serde_json::to_string_pretty(&pkg).unwrap()).unwrap();
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
        "pinned re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env3 = parse_envelope(&stdout);
    assert!(
        env3.get("warnings").is_none(),
        "a yarn@1 packageManager pin must suppress the advisory (and empty \
         warnings must be omitted from JSON entirely): {env3}"
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
    assert!(
        renv.get("warnings").is_none(),
        "after revert the wiring is gone — the state-based advisory must fall \
         silent: {renv}"
    );
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

// ── detached vendoring from the patch API (the manifest-less shape) ────

/// `scan --mode vendored --detached` against a wiremock Socket API: the
/// vendored posture that NEVER has a `.socket/manifest.json` (the vendor
/// ledger embeds the record) — the shape a depscan-opened PR commits. The
/// scan discovers the dep (batch search), the record (with `blobContent`)
/// comes from the mocked `view/<uuid>` and the tarball is built locally
/// (`--vendor-source build`). A fresh checkout of
/// only the committable files installs the patched bytes with the real yarn
/// (`--frozen-lockfile --offline`, empty cache), then the manifest-less VEX
/// matrix runs over it.
#[test]
fn yarn_classic_detached_scan_vendored_fresh_checkout_manifestless_vex() {
    const LEG: &str = "vendor-detached-scan";
    if !require_yarn_classic(LEG, |c| {
        cache_env::isolate(c);
    }) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"yarn-classic-detached","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();
    let cache = tmp.path().join("yarn-cache");
    let install = corepack(
        &proj,
        &yarn_classic(),
        &["install", "--no-progress"],
        &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
    );
    if !install.status.success() {
        skip!(
            "{LEG}: fixture `yarn install` failed (registry unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }
    let orig = std::fs::read(proj.join("node_modules").join(DEP).join("index.js")).unwrap();
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    let purl = format!("pkg:npm/{DEP}@{DEP_VERSION}");
    let lock_before = std::fs::read(proj.join("yarn.lock")).unwrap();

    let mut view = vex_e2e_common::patch_view(
        UUID,
        &purl,
        &[("package/index.js", &git_sha256(&patched))],
        &[(GHSA, &[CVE])],
    );
    view["files"]["package/index.js"]["beforeHash"] = git_sha256(&orig).into();
    view["files"]["package/index.js"]["blobContent"] = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .encode(&patched)
            .into()
    };
    // The Socket API the scan drives: discovery + the patch view.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let summary = serde_json::json!({
            "uuid": UUID, "purl": purl, "tier": "free", "cveIds": [CVE],
            "ghsaIds": [GHSA], "severity": "high", "title": "detached capstone",
        });
        Mock::given(method("POST"))
            .and(path("/v0/orgs/test-org/patches/batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": [{ "purl": purl, "patches": [summary] }],
                "canAccessPaidPatches": false,
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("^/v0/orgs/test-org/patches/by-package/.+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": UUID, "purl": purl, "publishedAt": "2026-01-01T00:00:00Z",
                    "description": "x", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/test-org/patches/view/{UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(view.clone()))
            .mount(&server)
            .await;
        server
    });
    // The record source for VEX once the ledger is gone (counted apart).
    let api = vex_e2e_common::PatchApi::start(vec![(UUID.to_string(), view)]);

    let api_url = server.uri();
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "vendored",
            "--detached",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &api_url,
            "--api-token",
            "fake",
            "--org",
            "test-org",
            "--vendor-source",
            "build",
        ],
    );
    assert_eq!(
        code, 0,
        "scan --mode vendored --detached failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["vendor"]["summary"]["applied"], 1,
        "one package vendored: {env}"
    );
    assert!(
        !proj.join(".socket/manifest.json").exists(),
        "--detached must never write the manifest"
    );
    let tgz_rel = format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}.tgz");
    assert!(proj.join(&tgz_rel).is_file(), "vendored tarball missing");
    let lock = std::fs::read_to_string(proj.join("yarn.lock")).unwrap();
    assert!(
        lock.contains(&format!("  resolved \"file:./{tgz_rel}#")),
        "yarn.lock must be wired to the vendored tarball:\n{lock}"
    );

    // Fresh checkout: only the committable files, empty cache, offline.
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(proj.join("yarn.lock"), fresh.join("yarn.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    let fresh_cache = tmp.path().join("fresh-yarn-cache");
    let ci = corepack(
        &fresh,
        &yarn_classic(),
        &["install", "--frozen-lockfile", "--offline", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    assert!(
        ci.status.success(),
        "fresh-checkout install failed:\n{}",
        String::from_utf8_lossy(&ci.stderr)
    );
    let installed = fresh.join("node_modules").join(DEP).join("index.js");
    if yarn_classic_vex::installs_file_tarballs(&yarn_classic_vex::yarn_classic_version()) {
        assert_eq!(
            std::fs::read(&installed).unwrap(),
            patched,
            "the fresh install must deliver the patched bytes"
        );
    } else {
        assert!(!installed.exists(), "yarn < 1.7 installs no `file:` entry");
    }

    let reverted_cache = tmp.path().join("reverted-yarn-cache");
    ManifestlessVex {
        leg: LEG,
        wiring: Wiring::Vendored,
        purl: &purl,
        uuid: UUID,
        vulns: &[(GHSA, &[CVE])],
        api: &api,
        proxy_override: None,
        patch_server_url: None,
        registry_lock: lock_before,
        reinstall: Some(Box::new(|dir: &Path| {
            let _ = std::fs::remove_dir_all(dir.join("node_modules"));
            let out = corepack(
                dir,
                &yarn_classic(),
                &["install", "--frozen-lockfile", "--no-progress"],
                &[("YARN_CACHE_FOLDER", reverted_cache.to_str().unwrap())],
            );
            assert!(
                out.status.success(),
                "reverted-lock install failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                std::fs::read(dir.join("node_modules").join(DEP).join("index.js")).unwrap(),
                orig,
                "the reverted lock installs pristine bytes"
            );
        })),
        embedded: vec![
            ("apply --vex", via_apply()),
            ("vendor --vex", via_vendor()),
            // The command that produced the state, re-run manifest-less.
            (
                "scan --mode vendored --detached --vex",
                Box::new(|run: vex_e2e_common::VexRun| {
                    let mut run = run
                        .via(vex_e2e_common::VexVia::Scan)
                        .arg("--mode")
                        .arg("vendored")
                        .arg("--detached")
                        .arg("--vendor-source")
                        .arg("build")
                        .arg("--yes");
                    run.proxy_url = None;
                    run.api_url = Some(api_url.clone());
                    run.api_token = Some("fake".to_string());
                    run.org = Some("test-org".to_string());
                    run
                }),
            ),
        ],
    }
    .run(&fresh);
    drop(server);
}
