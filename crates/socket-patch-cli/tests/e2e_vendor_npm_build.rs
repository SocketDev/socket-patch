//! Real-npm capstone e2e for `socket-patch vendor` — the committability proof.
//!
//! Drives the REAL npm (network used for fixture setup only):
//!   1. `npm install left-pad@1.3.0` into a tempdir project (private cache).
//!   2. Hand-stage a `.socket/` manifest + blob whose before/after Git-blob
//!      hashes are computed from the ACTUAL installed bytes (a marker comment
//!      prepended to `index.js`).
//!   3. `socket-patch vendor --json --offline` (the real binary) — assert the
//!      deterministic tarball lands at `.socket/vendor/npm/<uuid>/…` and the
//!      package-lock entry is rewired to `file:` + a recomputed sha512.
//!   4. **Fresh-checkout proof**: copy ONLY the committable files
//!      (package.json + package-lock.json + .socket/) to a new dir and run
//!      `npm ci --cache <empty tmp>` — the patched bytes MUST be what npm
//!      installs (the recomputed `integrity` means the registry tarball can
//!      never satisfy the lock; the spike proved plain `npm ci` exits 0 with
//!      only the vendored dep).
//!   5. Idempotency: re-running vendor leaves the lock byte-identical.
//!   6. **Revert proof**: `vendor --revert` restores the lock byte-for-byte
//!      and removes `.socket/vendor/` entirely.
//!
//! Skips (with a println) when `npm` is not installed or the fixture install
//! cannot reach the registry; every assertion after that is hard.

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

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
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
        if k.to_string_lossy().starts_with("SOCKET_") {
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

/// Run npm with ambient `npm_config_*` env scrubbed. npm reads any
/// `npm_config_<key>` variable (case-insensitive) as config wherever the
/// invocation doesn't pin a flag: an ambient `npm_config_dry_run=true` turns
/// the fixture install into a no-op that still exits 0 (so the skip-gate
/// passes and the marker asserts panic), and `npm_config_save=false`
/// suppresses the package-lock.json every later oracle reads. Both verified
/// hostile values are seeded and then scrubbed — `env_remove` clears the seed
/// too, so the child never sees it, but if a scrub line is ever dropped the
/// seed (not a developer's shell) turns the suite red immediately.
fn npm(cwd: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new("npm");
    cmd.args(args)
        .current_dir(cwd)
        .env("npm_config_dry_run", "true")
        .env("npm_config_save", "false")
        .env_remove("npm_config_dry_run")
        .env_remove("npm_config_save");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy()
            .to_ascii_lowercase()
            .starts_with("npm_config_")
        {
            cmd.env_remove(&k);
        }
    }
    cmd.output().expect("failed to run npm")
}

/// Git-blob SHA-256 (`sha256("blob <len>\0" ++ bytes)`) — the hash format
/// socket-patch records in manifests.
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

/// Like [`stage_patch`] but records a vulnerability so a generated VEX
/// document has a statement to emit.
fn stage_patch_with_vuln(
    proj: &Path,
    purl: &str,
    file_key: &str,
    before: &[u8],
    after: &[u8],
    ghsa: &str,
) {
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
            "vulnerabilities": { ghsa: {
                "cves": ["CVE-2024-99999"],
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
fn npm_vendor_fresh_checkout_npm_ci_and_revert() {
    if !has_command("npm") {
        println!("SKIP e2e_vendor_npm_build: `npm` not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"vendor-capstone","version":"0.0.0","private":true}"#,
    )
    .unwrap();

    // 1. REAL fixture: npm install (network allowed here, private cache).
    let cache = tmp.path().join("npm-cache");
    let install = npm(
        &proj,
        &[
            "install",
            &format!("{DEP}@{DEP_VERSION}"),
            "--no-audit",
            "--no-fund",
            "--cache",
            cache.to_str().unwrap(),
        ],
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_vendor_npm_build: `npm install {DEP}@{DEP_VERSION}` failed (registry \
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

    // 2. Manifest + blob from the ACTUAL installed bytes (npm file keys carry
    //    the `package/` prefix).
    stage_patch(&proj, &purl, "package/index.js", &orig, &patched);

    let lock_path = proj.join("package-lock.json");
    let lock_before = std::fs::read(&lock_path).expect("package-lock.json after npm install");
    let pre_lock: serde_json::Value = serde_json::from_slice(&lock_before).unwrap();
    let registry_integrity = pre_lock["packages"][format!("node_modules/{DEP}")]["integrity"]
        .as_str()
        .expect("registry lock entry has integrity")
        .to_string();

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

    // Lock rewiring: `resolved` → relative file: spec, `integrity` recomputed
    // (NEVER the inherited registry sha512 — a warm cache would otherwise
    // silently install unpatched bytes).
    let post_lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&lock_path).unwrap()).unwrap();
    let entry = &post_lock["packages"][format!("node_modules/{DEP}")];
    assert_eq!(
        entry["resolved"],
        format!("file:{tgz_rel}"),
        "lock entry must resolve to the vendored tarball: {entry}"
    );
    let new_integrity = entry["integrity"].as_str().expect("rewired integrity");
    assert!(
        new_integrity.starts_with("sha512-"),
        "recomputed integrity must be sha512: {new_integrity}"
    );
    assert_ne!(
        new_integrity, registry_integrity,
        "integrity must be recomputed from the PATCHED tarball, not inherited"
    );
    // package.json is never touched by npm vendoring (lock-only wiring).
    let pkg_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join("package.json")).unwrap()).unwrap();
    assert_eq!(
        pkg_json["dependencies"][DEP]
            .as_str()
            .map(|s| s.contains("file:")),
        Some(false),
        "package.json dependency spec must stay registry-form"
    );

    // 4. FRESH-CHECKOUT PROOF: only the committable files, empty npm cache.
    //    (Spike-proven invocation: plain `npm ci --cache <fresh>`;
    //    --no-audit/--no-fund only silence unrelated registry chatter.)
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(&lock_path, fresh.join("package-lock.json")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_cache = tmp.path().join("fresh-npm-cache");
    let ci = npm(
        &fresh,
        &[
            "ci",
            "--cache",
            fresh_cache.to_str().unwrap(),
            "--no-audit",
            "--no-fund",
        ],
    );
    assert!(
        ci.status.success(),
        "fresh-checkout `npm ci` must succeed from the vendored tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let fresh_installed =
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        fresh_installed.starts_with(MARKER.as_bytes()),
        "npm ci must install the PATCHED bytes from the vendored tarball; got:\n{}",
        String::from_utf8_lossy(&fresh_installed[..fresh_installed.len().min(120)])
    );
    assert_eq!(
        fresh_installed, patched,
        "fresh install must be byte-identical to the patched content"
    );

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
        "re-vendor must leave package-lock.json byte-identical"
    );

    // 6. REVERT PROOF: lock restored byte-for-byte, artifacts gone.
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
        "revert must restore package-lock.json byte-identical to the pre-vendor snapshot"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
}

/// Real-toolchain VEX capstone for npm: after a REAL install + `vendor`, the
/// vendored `.tgz` is the on-disk evidence. `socket-patch vex` must attest the
/// patch against that vendored tarball with the `(vendored)` marker — proving
/// the vendored-artifact verification path works for a real npm tarball (not
/// just the synthetic cargo-dir fixtures).
#[test]
fn npm_vendor_vex_attests_against_vendored_tarball() {
    if !has_command("npm") {
        println!("SKIP e2e_vendor_npm_build (vex): `npm` not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"vex-vendor","version":"0.0.0","private":true}"#,
    )
    .unwrap();

    let cache = tmp.path().join("npm-cache");
    let install = npm(
        &proj,
        &[
            "install",
            &format!("{DEP}@{DEP_VERSION}"),
            "--no-audit",
            "--no-fund",
            "--cache",
            cache.to_str().unwrap(),
        ],
    );
    if !install.status.success() {
        println!("SKIP e2e_vendor_npm_build (vex): npm install failed (registry unreachable?)");
        return;
    }

    let installed_index = proj.join("node_modules").join(DEP).join("index.js");
    let orig = std::fs::read(&installed_index).expect("installed index.js");
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    let purl = format!("pkg:npm/{DEP}@{DEP_VERSION}");
    const GHSA: &str = "GHSA-vend-npm-real";
    stage_patch_with_vuln(&proj, &purl, "package/index.js", &orig, &patched, GHSA);

    // Vendor (offline: blob staged locally).
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

    // VEX against the vendored tarball (default verify mode).
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

    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "the vendored npm patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], purl);
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    assert!(
        impact.contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {impact}"
    );
}
