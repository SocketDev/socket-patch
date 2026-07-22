//! Real-bun redirect capstone e2e — the hosted-mode full-chain proof for the
//! bun (text `bun.lock`) flavor, mirroring `e2e_redirect_npm_build.rs`.
//!
//! `scan --mode hosted` rewrites `bun.lock` so the patched dependency's
//! `packages` entry moves from the registry 4-tuple to the URL 3-tuple
//! `["<name>@<hosted-url>", {deps}, "sha512-<patched>"]`, and records the
//! patch in the redirect ledger. This test proves every link against REAL
//! `bun`:
//!
//!   1. `bun install` of left-pad@1.3.0 (network for fixture setup only,
//!      private `BUN_INSTALL_CACHE_DIR`, text lockfile).
//!   2. Build a PATCHED tarball from the installed bytes; its sha512 is what
//!      the redirect mock hands back (bun verifies the downloaded tarball's
//!      sha512 directly — no cache-zip conversion like yarn berry, so no
//!      bootstrap is needed).
//!   3. `scan --mode hosted --json --vex` (the real binary): bun.lock now
//!      pins the hosted URL + the patched sha512, the ledger embeds the
//!      record, the in-run VEX is the `(redirected)` attestation.
//!   4. FRESH-CHECKOUT PROOF: only package.json + bun.lock + .socket/ travel;
//!      `bun install --frozen-lockfile` with a fresh `BUN_INSTALL_CACHE_DIR`
//!      MUST install the patched bytes from the hosted tarball.
//!
//! The negative twin serves TAMPERED tarball bytes while the lock keeps the
//! real sha512: the fresh frozen install MUST fail with an integrity error.
//!
//! `bun.lockb` (bun's legacy binary lockfile) auto-migration is NOT exercised
//! here: bun 1.3.x writes the text `bun.lock` by default and offers no flag to
//! emit the binary form, so a real lockb fixture cannot be generated on this
//! toolchain. That migration branch is covered by the in-process shim test
//! `scan_redirect_migrates_bun_lockb_then_redirects` in
//! `tests/in_process_redirect.rs`.
//!
//! Skips (with a println) when `bun`/`tar` are missing or the fixture install
//! cannot reach the registry; every assertion after is hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d";
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const GHSA: &str = "GHSA-redirect-bun-real";
const PRODUCT: &str = "pkg:npm/app@1.0.0";

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

fn scrub_socket_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") && k.to_string_lossy() != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("BUN_INSTALL_CACHE_DIR");
}

fn bun(cwd: &Path, args: &[&str], cache_dir: &Path) -> Output {
    let mut cmd = Command::new("bun");
    cmd.args(args).current_dir(cwd);
    scrub_socket_env(&mut cmd);
    cmd.env("BUN_INSTALL_CACHE_DIR", cache_dir);
    cmd.output().expect("failed to run bun")
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

fn sha512_sri_b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
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

struct BunRedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    patched: Vec<u8>,
    _server: MockServer,
}

/// Steps 1–3: real install, patched tarball + API mocks, `scan --mode hosted
/// --vex`, and the envelope/lockfile/ledger assertions. `tamper_served_tarball`
/// serves DIFFERENT bytes than the sha512 pinned into the lock. `None` = skip.
async fn bun_hosted_project(tag: &str, tamper_served_tarball: bool) -> Option<BunRedirectFixture> {
    if !has_command("bun") {
        println!("SKIP e2e_redirect_bun_build ({tag}): `bun` not installed");
        return None;
    }
    if !has_command("tar") {
        println!("SKIP e2e_redirect_bun_build ({tag}): `tar` not installed");
        return None;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"redirect-bun-capstone","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();

    // 1. REAL fixture: bun install (network here, private cache). Text lockfile.
    let cache = tmp.path().join("bun-cache");
    let install = bun(&proj, &["install", "--save-text-lockfile"], &cache);
    if !install.status.success() {
        println!(
            "SKIP e2e_redirect_bun_build ({tag}): fixture `bun install` failed (registry \
             unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return None;
    }
    if !proj.join("bun.lock").is_file() {
        println!(
            "SKIP e2e_redirect_bun_build ({tag}): bun produced no text bun.lock (binary \
             lockfile?)"
        );
        return None;
    }

    let installed_dir = proj.join("node_modules").join(DEP);
    let orig = std::fs::read(installed_dir.join("index.js")).expect("installed index.js");
    assert!(
        !orig.starts_with(MARKER.as_bytes()),
        "pristine install must not carry the marker"
    );
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();

    // 2. Patched tarball from the installed package; its sha512 is the pin.
    let stage = tmp.path().join("tarstage");
    copy_dir_recursive(&installed_dir, &stage.join("package"));
    std::fs::write(stage.join("package").join("index.js"), &patched).unwrap();
    let tgz_path = tmp.path().join(format!("{DEP}-{DEP_VERSION}.tgz"));
    let tar = Command::new("tar")
        .args(["-czf", tgz_path.to_str().unwrap(), "package"])
        .current_dir(&stage)
        .output()
        .expect("failed to run tar");
    assert!(
        tar.status.success(),
        "tar failed: {}",
        String::from_utf8_lossy(&tar.stderr)
    );
    let tgz = std::fs::read(&tgz_path).unwrap();
    let sri = format!("sha512-{}", sha512_sri_b64(&tgz));
    let served: Vec<u8> = if tamper_served_tarball {
        [tgz.as_slice(), &[0u8][..]].concat()
    } else {
        tgz.clone()
    };

    // 3. API mocks + the hosted tarball route bun will hit at install time.
    let server = MockServer::start().await;
    let hosted_url = format!(
        "{}/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz",
        server.uri()
    );
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "redirect bun capstone fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": hosted_url,
                    "purl": PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": hosted_url,
                        "integrity": { "sha512": sri }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": compute_git_sha256_from_bytes(&orig),
                    "afterHash": compute_git_sha256_from_bytes(&patched),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-1111"], "summary": "redirect bun capstone vuln",
                    "severity": "high", "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_raw(served, "application/octet-stream"))
        .mount(&server)
        .await;

    // scan --mode hosted --vex.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--vex",
            "out.vex.json",
            "--vex-product",
            PRODUCT,
        ],
    );
    assert_eq!(
        code, 0,
        "scan --mode hosted failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("scan --mode hosted --json output is not JSON: {e}\nstdout:\n{stdout}")
    });
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "one dep redirected: {env}"
    );
    // In-run VEX (step 3 of the module doc): the envelope's vex block plus the
    // document's unverified `(redirected)` attestation. Without these, a scan
    // that silently skips the VEX write (or emits the wrong statement) stays
    // green — the exit code only catches a HARD vex failure.
    assert_eq!(env["vex"]["path"], "out.vex.json", "vex block: {env}");
    assert_eq!(env["vex"]["statements"], 1, "vex block: {env}");
    assert_eq!(env["vex"]["format"], "openvex-0.2.0", "vex block: {env}");
    assert_eq!(
        env["vex"]["verified"], false,
        "in-run redirect VEX is attested from the ledger, not hash-verified: {env}"
    );
    let vex_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join("out.vex.json")).unwrap()).unwrap();
    let stmts = vex_doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "exactly the redirected patch attested: {vex_doc}"
    );
    assert_eq!(
        stmts[0]["vulnerability"]["name"], GHSA,
        "vex doc: {vex_doc}"
    );
    assert_eq!(stmts[0]["status"], "not_affected", "vex doc: {vex_doc}");
    assert_eq!(
        stmts[0]["products"][0]["subcomponents"][0]["@id"], PURL,
        "vex doc: {vex_doc}"
    );
    assert_eq!(
        stmts[0]["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (redirected)"),
        "the in-run attestation must carry the (redirected) marker: {vex_doc}"
    );

    // Lockfile pin: the hosted URL (as the tuple spec) + the patched sha512.
    let lock = std::fs::read_to_string(proj.join("bun.lock")).unwrap();
    assert!(
        lock.contains(&format!("\"{DEP}@{hosted_url}\"")),
        "bun.lock tuple spec must be name@<hosted url>; got:\n{lock}"
    );
    assert!(
        lock.contains(&sri),
        "bun.lock integrity must be the patched sha512 ({sri}); got:\n{lock}"
    );

    let ledger = std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("\"records\"") && ledger.contains(GHSA),
        "redirect ledger must embed the patch record + vulnerability: {ledger}"
    );

    Some(BunRedirectFixture {
        tmp,
        proj,
        patched,
        _server: server,
    })
}

/// Fresh dir with only the committable files, then `bun install
/// --frozen-lockfile` against an empty cache.
fn fresh_checkout_bun_install(fx: &BunRedirectFixture) -> (PathBuf, Output) {
    let fresh = fx.tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(fx.proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(fx.proj.join("bun.lock"), fresh.join("bun.lock")).unwrap();
    copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
    let fresh_cache = fx.tmp.path().join("fresh-bun-cache");
    let ci = bun(&fresh, &["install", "--frozen-lockfile"], &fresh_cache);
    (fresh, ci)
}

// ── the capstone ──────────────────────────────────────────────────────

// #[serial]: bun shares an on-disk cache/registry-metadata directory across
// installs of the same URL; serializing keeps the tampered twin from reusing
// the main leg's honest bytes (each leg also uses its own cache dir).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_redirect_fresh_checkout_installs_patched_bytes() {
    let Some(fx) = bun_hosted_project("main", false).await else {
        return;
    };

    let (fresh, ci) = fresh_checkout_bun_install(&fx);
    assert!(
        ci.status.success(),
        "fresh-checkout `bun install --frozen-lockfile` must succeed from the hosted patch \
         tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "bun must install the PATCHED bytes from the hosted patch; got:\n{}",
        String::from_utf8_lossy(&installed[..installed.len().min(120)])
    );
    assert_eq!(
        installed, fx.patched,
        "fresh install must be byte-identical to the patched content"
    );
}

/// Negative twin: the hosted route serves TAMPERED bytes while the lock pins
/// the real sha512 — the fresh frozen install must refuse.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn bun_redirect_tampered_hosted_tarball_fails_frozen_install() {
    let Some(fx) = bun_hosted_project("tampered", true).await else {
        return;
    };

    let (_fresh, ci) = fresh_checkout_bun_install(&fx);
    assert!(
        !ci.status.success(),
        "bun install MUST fail when the served tarball does not match the pinned sha512.\n\
         stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let chatter = format!(
        "{}\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr)
    );
    assert!(
        chatter.to_lowercase().contains("integrity")
            || chatter.to_lowercase().contains("checksum")
            || chatter.to_lowercase().contains("hash")
            || chatter.contains("IntegrityCheckFailed"),
        "the failure must be the integrity check, not something incidental:\n{chatter}"
    );
}
