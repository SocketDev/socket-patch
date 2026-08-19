//! Real-yarn version-matrix refusal pins — yarn 2 and yarn 3 (berry legacy
//! cacheKeys) against BOTH lockfile-touching modes.
//!
//! Only cacheKey `10c0` (yarn 4 with `compressionLevel: 0`, the default) has
//! an offline-reproducible cache-zip checksum, so hosted redirect and
//! vendored wiring must REFUSE yarn 2/3 locks — cleanly, per-file/per-package,
//! and without touching a byte of `yarn.lock` or `package.json`. The 36-cell
//! yarn matrix sweep (2026-08-18, real production data) proved this contract
//! holds today, but until now the cacheKey gates were only unit-tested
//! against synthetic lock strings: a regression against a REAL yarn 2/3 lock
//! (e.g. a partial rewrite before the refusal fires) would ship unseen.
//!
//! Each test generates the lock with the REAL corepack-pinned yarn
//! (`yarn@2.4.3` / `yarn@3.8.7`, network for fixture setup only), pins the
//! cacheKey those versions actually emit (empirical, matching the sweep):
//!
//!   * yarn 2.4.3 — `cacheKey: 7` (default compression), `7c0` with
//!     `compressionLevel: 0`
//!   * yarn 3.8.7 — `cacheKey: 8` (default compression), `8c0` with
//!     `compressionLevel: 0`
//!
//! and then asserts the FULL refusal contract against the built binary:
//!
//!   * `scan --mode hosted`: exit 0, envelope `status: success`,
//!     `redirect.redirected == 0`, no rewritten files, a per-file warning with
//!     code `redirect_yarn_berry_cache_unsupported` (the CODE, not human
//!     text), and `yarn.lock` + `package.json` byte-identical.
//!   * `scan --mode vendored`: exit 1, envelope `status: partial_failure`,
//!     a per-package failed event with errorCode
//!     `vendor_yarn_berry_cache_unsupported` (download succeeded — the
//!     refusal is at the wiring step, not discovery), zero mutations to
//!     `yarn.lock` / `package.json`, and no `.socket/vendor` artifacts.
//!
//! If a future corepack pin emits a different cacheKey, the pin assertion
//! fails first with a message saying exactly that, so the refusal-contract
//! assertions below it never run against a lock this test no longer
//! generates.
//!
//! LOCAL capstones (not behind docker-e2e): each skips with a `println` +
//! return when the corepack-pinned yarn is unavailable or the fixture
//! install cannot reach the registry; every assertion after that is HARD.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use base64::Engine as _;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
/// `encode_uri_component(PURL)` — the by-package route segment.
const PURL_ENCODED: &str = "pkg%3Anpm%2Fleft-pad%401.3.0";
const UUID: &str = "3c4d5e6f-7a8b-4c3d-9e4f-23456789abcd";
const TOKEN: &str = "33333333-3333-4333-8333-333333333333";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const GHSA: &str = "GHSA-yarn-legacy-refusal";

// ── self-contained helpers (convention: e2e test files stay standalone) ─

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Probe corepack from a NEUTRAL temp dir: a `packageManager` field in an
/// ancestor `package.json` makes corepack refuse to run a different package
/// manager, which would spuriously fail the gate (mirrors
/// e2e_redirect_yarn_berry_build.rs).
fn has_corepack_pm(pm: &str) -> bool {
    let Ok(probe) = tempfile::tempdir() else {
        return false;
    };
    let mut cmd = Command::new("corepack");
    cmd.args([pm, "--version"])
        .current_dir(probe.path())
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    cache_env::isolate(&mut cmd);
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn scrub_socket_env(cmd: &mut Command) {
    // Seed-then-scrub (mirrors e2e_redirect_yarn_berry_build.rs): yarn berry
    // lets EVERY `.yarnrc.yml` setting be overridden by a `YARN_*` env var,
    // so an ambient `YARN_NODE_LINKER=pnp` would build a PnP tree and
    // node_modules/left-pad would never exist. The env_remove below clears
    // the seed too, but if the scrub is ever dropped the seed turns these
    // tests red immediately rather than relying on a developer's shell.
    cmd.env("YARN_NODE_LINKER", "pnp");
    for (k, _) in std::env::vars_os() {
        let key = k.to_string_lossy();
        if (key.starts_with("SOCKET_") || key.starts_with("YARN_")) && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("YARN_NODE_LINKER");
}

fn corepack(cwd: &Path, pm: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
    // Scrub FIRST (it removes YARN_* / SOCKET_* from the inherited env), then
    // set the hermetic flags so they survive (Command: last env call wins).
    scrub_socket_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        .env("YARN_ENABLE_GLOBAL_CACHE", "false");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run corepack")
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

/// Mount the full patch API for `left-pad` on the mock: discovery (batch),
/// per-package search, the full view (blobContent inline so the vendored
/// download needs no extra route), and the hosted reference. The hosted
/// reference carries a syntactically-valid dummy `yarnBerry10c0` checksum —
/// the refusal must fire BEFORE any checksum is consumed, so nothing in
/// these tests ever validates it.
async fn mount_patch_api(server: &MockServer, orig: &[u8], patched: &[u8]) {
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
                    "cveIds": ["CVE-2026-2222"], "ghsaIds": [GHSA],
                    "severity": "high",
                    "title": "yarn legacy refusal fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/by-package/{PURL_ENCODED}"
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
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": compute_git_sha256_from_bytes(orig),
                    "afterHash": compute_git_sha256_from_bytes(patched),
                    "blobContent": base64::engine::general_purpose::STANDARD.encode(patched),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-2222"], "summary": "yarn legacy refusal vuln",
                    "severity": "high", "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
    let dummy_10c0 = format!("10c0/{}", "0".repeat(128));
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": hosted_url,
                    "purl": PURL,
                    "artifacts": [
                        { "kind": "tarball", "url": hosted_url,
                          "integrity": { "sha512": "sha512-unused-by-refusal==" } },
                        { "kind": "yarn-berry-zip", "url": hosted_url,
                          "integrity": { "yarnBerry10c0": dummy_10c0 } }
                    ],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
}

/// One version-matrix refusal cell: real install with the pinned yarn, the
/// cacheKey pin, then the hosted + vendored refusal contracts.
async fn refusal_case(tag: &str, yarn_pm: &str, compression_zero: bool, expected_cache_key: &str) {
    if !has_corepack_pm(yarn_pm) {
        println!(
            "SKIP e2e_yarn_legacy_cachekey_refusal_build ({tag}): `corepack {yarn_pm}` unavailable"
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"yarn-legacy-refusal","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();
    let mut yarnrc = String::from("nodeLinker: node-modules\nenableTelemetry: false\n");
    if compression_zero {
        yarnrc.push_str("compressionLevel: 0\n");
    }
    std::fs::write(proj.join(".yarnrc.yml"), yarnrc).unwrap();

    // 1. REAL fixture: the pinned yarn's install (network here, private
    //    global folder).
    let global = tmp.path().join("yarn-global");
    let install = corepack(
        &proj,
        yarn_pm,
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_yarn_legacy_cachekey_refusal_build ({tag}): fixture `yarn install` \
             failed (registry unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }

    // 2. The cacheKey pin — the empirical fact the refusal contract below is
    //    conditioned on. Fails FIRST, with a self-describing message, if a
    //    future corepack pin emits something else.
    let lock_path = proj.join("yarn.lock");
    let lock = std::fs::read_to_string(&lock_path).expect("yarn.lock after yarn install");
    assert!(
        lock.lines()
            .any(|l| l.trim() == format!("cacheKey: {expected_cache_key}")),
        "({tag}) `corepack {yarn_pm}` no longer emits `cacheKey: {expected_cache_key}` \
         (compressionLevel-0 yarnrc: {compression_zero}) — the refusal contract this test \
         pins was verified against that cacheKey; re-verify the contract against the new \
         lock before updating the pin. Lock header:\n{}",
        lock.lines().take(8).collect::<Vec<_>>().join("\n")
    );
    assert!(
        !lock.contains("cacheKey: 10c0"),
        "({tag}) a legacy-yarn lock must not carry the supported 10c0 cacheKey:\n{lock}"
    );

    let orig = std::fs::read(proj.join("node_modules").join(DEP).join("index.js"))
        .expect("installed index.js");
    assert!(
        !orig.starts_with(MARKER.as_bytes()),
        "({tag}) pristine install must not carry the marker"
    );
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();

    let server = MockServer::start().await;
    mount_patch_api(&server, &orig, &patched).await;

    // Byte-level baseline AFTER the install (berry rewrites package.json
    // compact → pretty during install, so the on-disk bytes are the truth).
    let lock_before = std::fs::read(&lock_path).unwrap();
    let pkg_path = proj.join("package.json");
    let pkg_before = std::fs::read(&pkg_path).unwrap();

    let api_args = |mode: &'static str| {
        vec![
            "scan".to_string(),
            "--mode".into(),
            mode.into(),
            "--json".into(),
            "--yes".into(),
            "--cwd".into(),
            proj.to_str().unwrap().into(),
            "--api-url".into(),
            server.uri(),
            "--org".into(),
            ORG.into(),
            "--api-token".into(),
            "fake".into(),
        ]
    };

    // 3. HOSTED refusal: clean per-file warning, exit 0, zero mutations.
    let hosted_args: Vec<String> = api_args("hosted");
    let hosted_argv: Vec<&str> = hosted_args.iter().map(String::as_str).collect();
    let (code, stdout, stderr) = run_socket(&proj, &hosted_argv);
    assert_eq!(
        code, 0,
        "({tag}) hosted refusal must exit 0 (a clean refusal, not an error).\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("({tag}) scan --mode hosted --json output is not JSON: {e}\nstdout:\n{stdout}")
    });
    assert_eq!(env["status"], "success", "({tag}) envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 0,
        "({tag}) nothing may be redirected on a legacy-cacheKey lock: {env}"
    );
    assert_eq!(
        env["redirect"]["rewrittenFiles"].as_array().map(Vec::len),
        Some(0),
        "({tag}) no file may be rewritten: {env}"
    );
    let warnings = env["redirect"]["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("({tag}) redirect.warnings must be an array: {env}"));
    let warning = warnings
        .iter()
        .find(|w| w["code"] == "redirect_yarn_berry_cache_unsupported")
        .unwrap_or_else(|| {
            panic!(
                "({tag}) hosted refusal must carry the warning CODE \
                 `redirect_yarn_berry_cache_unsupported`: {env}"
            )
        });
    assert!(
        warning["detail"]
            .as_str()
            .unwrap_or_default()
            .contains(&format!("`{expected_cache_key}`")),
        "({tag}) the warning detail should name the observed cacheKey \
         `{expected_cache_key}`: {warning}"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "({tag}) hosted refusal must leave yarn.lock byte-identical"
    );
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        pkg_before,
        "({tag}) hosted refusal must leave package.json byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "({tag}) hosted refusal must not create .socket/vendor"
    );
    eprintln!("({tag}) HOSTED REFUSAL OK");

    // 4. VENDORED refusal: per-package failed event, exit 1, partial_failure,
    //    zero mutations, no vendor artifacts. The download block proves the
    //    refusal fires at the WIRING step, not by failing discovery.
    let vendored_args: Vec<String> = api_args("vendored");
    let vendored_argv: Vec<&str> = vendored_args.iter().map(String::as_str).collect();
    let (code, stdout, stderr) = run_socket(&proj, &vendored_argv);
    assert_eq!(
        code, 1,
        "({tag}) vendored refusal must exit 1 (partial failure).\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("({tag}) scan --mode vendored --json output is not JSON: {e}\nstdout:\n{stdout}")
    });
    assert_eq!(env["status"], "partial_failure", "({tag}) envelope: {env}");
    assert_eq!(
        env["download"]["downloaded"], 1,
        "({tag}) the patch must download fine — the refusal is at the wiring step: {env}"
    );
    let events = env["vendor"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("({tag}) vendor.events must be an array: {env}"));
    let failed = events
        .iter()
        .find(|e| e["action"] == "failed" && e["purl"] == PURL)
        .unwrap_or_else(|| panic!("({tag}) expected a per-package failed event for {PURL}: {env}"));
    assert_eq!(
        failed["errorCode"], "vendor_yarn_berry_cache_unsupported",
        "({tag}) the refusal must be the CODE, not human text: {failed}"
    );
    assert_eq!(
        env["vendor"]["summary"]["failed"], 1,
        "({tag}) vendor summary: {env}"
    );
    assert_eq!(
        env["vendor"]["summary"]["applied"], 0,
        "({tag}) nothing may be vendored: {env}"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "({tag}) vendored refusal must leave yarn.lock byte-identical"
    );
    assert_eq!(
        std::fs::read(&pkg_path).unwrap(),
        pkg_before,
        "({tag}) vendored refusal must leave package.json byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        "({tag}) vendored refusal must not create .socket/vendor"
    );
    assert!(
        !proj.join(".socket/blobs").exists(),
        "({tag}) vendored refusal must not spill blobs to disk"
    );
    eprintln!("({tag}) VENDORED REFUSAL OK");
}

// ── the version-matrix cells ──────────────────────────────────────────
//
// No #[serial]: unlike the redirect-berry capstone there is no tampered twin
// whose correctness depends on cache isolation between tests — every cell
// installs registry bytes into its own tempdir with a private global folder.

#[tokio::test(flavor = "multi_thread")]
async fn yarn2_default_compression_cachekey7_refused_by_hosted_and_vendored() {
    refusal_case("yarn2-default", "yarn@2.4.3", false, "7").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn yarn2_compression0_cachekey7c0_refused_by_hosted_and_vendored() {
    refusal_case("yarn2-c0", "yarn@2.4.3", true, "7c0").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn yarn3_default_compression_cachekey8_refused_by_hosted_and_vendored() {
    refusal_case("yarn3-default", "yarn@3.8.7", false, "8").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn yarn3_compression0_cachekey8c0_refused_by_hosted_and_vendored() {
    refusal_case("yarn3-c0", "yarn@3.8.7", true, "8c0").await;
}
