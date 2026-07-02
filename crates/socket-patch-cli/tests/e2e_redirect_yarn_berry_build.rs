//! Real-yarn-berry redirect capstone e2e — the hosted-mode full-chain proof
//! for the yarn berry 4.x (node-modules linker) flavor, mirroring
//! `e2e_redirect_npm_build.rs`.
//!
//! `scan --mode hosted` never lands patched bytes in the repo: it rewrites
//! `yarn.lock` so the patched dependency resolves via
//! `npm:<v>::__archiveUrl=<hosted-tgz>` with `checksum: 10c0/<hex>` (yarn's
//! cache-zip sha512), and records the patch in the redirect ledger. This test
//! proves every link against the REAL `corepack yarn@4.12.0`:
//!
//!   1. `yarn install` of left-pad@1.3.0 (network for fixture setup only,
//!      private global cache, node-modules linker).
//!   2. Build a PATCHED tarball from the installed bytes, then run a BOOTSTRAP
//!      real-yarn resolution against it (`resolutions: file:./patched.tgz`) to
//!      extract the EXACT `10c0/<hex>` checksum yarn computes for that
//!      tarball's cache zip — the value the redirect mock must hand back
//!      (yarn recomputes the same zip checksum whether the locator is `file:`
//!      or `::__archiveUrl=`, so `--check-cache` will accept it).
//!   3. `scan --mode hosted --json --vex` (the real binary): yarn.lock now
//!      pins the hosted `__archiveUrl` + the `10c0` checksum, the ledger
//!      embeds the record, the in-run VEX is the `(redirected)` attestation.
//!   4. FRESH-CHECKOUT PROOF: only package.json + yarn.lock + .yarnrc.yml +
//!      .socket/ travel; `yarn install --immutable --check-cache` (offline
//!      from the registry, `unsafeHttpWhitelist` for the wiremock host) MUST
//!      install the patched bytes from the hosted tarball.
//!
//! The negative twin serves a DIFFERENT tarball at the archiveUrl while the
//! lock keeps the real `10c0` checksum: the fresh `--check-cache` install MUST
//! fail with a YN0018 checksum error — the lock pin is enforcement.
//!
//! Skips (with a println) when `corepack yarn@4.12.0` is unavailable or the
//! fixture install cannot reach the registry; every assertion after is hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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
const GHSA: &str = "GHSA-redirect-berry-real";
const PRODUCT: &str = "pkg:npm/app@1.0.0";
const YARN_BERRY: &str = "yarn@4.12.0";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Probe corepack from a NEUTRAL temp dir: a `packageManager` field in an
/// ancestor `package.json` (e.g. this monorepo's root) makes corepack refuse
/// to run a different package manager, which would spuriously fail the gate.
/// The real installs below all run in their own tempdirs, so the probe must
/// too.
fn has_corepack_pm(pm: &str) -> bool {
    let Ok(probe) = tempfile::tempdir() else {
        return false;
    };
    Command::new("corepack")
        .args([pm, "--version"])
        .current_dir(probe.path())
        .env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn scrub_socket_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    for v in [
        "YARN_CACHE_FOLDER",
        "YARN_GLOBAL_FOLDER",
        "YARN_ENABLE_GLOBAL_CACHE",
    ] {
        cmd.env_remove(v);
    }
}

fn corepack(cwd: &Path, pm: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
    // Scrub FIRST (it removes YARN_* / SOCKET_* from the inherited env), then
    // set the hermetic flags so they survive.
    scrub_socket_env(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        // Hermetic: no global mirror/cache. Without this, yarn's persistent
        // `~/.yarn/berry` global cache serves a previously-fetched archive
        // keyed by the (shared) resolution locator, so the tampered twin can
        // reuse the main leg's honest bytes and never hit YN0018 (flaky pass).
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

/// Build a patched npm tarball (`package/` prefix, marker-prepended index.js)
/// from the installed dep directory.
fn build_patched_tgz(installed_dir: &Path, patched_index: &[u8], out_tgz: &Path) {
    let stage = out_tgz.parent().unwrap().join("tarstage");
    copy_dir_recursive(installed_dir, &stage.join("package"));
    std::fs::write(stage.join("package").join("index.js"), patched_index).unwrap();
    let tar = Command::new("tar")
        .args(["-czf", out_tgz.to_str().unwrap(), "package"])
        .current_dir(&stage)
        .output()
        .expect("failed to run tar");
    assert!(
        tar.status.success(),
        "tar failed: {}",
        String::from_utf8_lossy(&tar.stderr)
    );
}

/// BOOTSTRAP: resolve the patched tarball with a real yarn (`resolutions`
/// pointing at `file:./patched.tgz`) so yarn writes the exact
/// `checksum: 10c0/<hex>` for that tarball's cache zip. Returns that
/// `10c0/<hex>` value — the checksum `--check-cache` will recompute and the
/// redirect mock must therefore hand back. `None` if the bootstrap install
/// could not run (skip signal).
fn bootstrap_berry_checksum(tmp: &Path, patched_tgz: &Path) -> Option<String> {
    let boot = tmp.join("berry-bootstrap");
    std::fs::create_dir_all(&boot).unwrap();
    let tgz_local = boot.join("patched.tgz");
    std::fs::copy(patched_tgz, &tgz_local).unwrap();
    std::fs::write(
        boot.join("package.json"),
        format!(
            r#"{{"name":"berry-bootstrap","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}},"resolutions":{{"{DEP}":"file:./patched.tgz"}}}}"#
        ),
    )
    .unwrap();
    std::fs::write(
        boot.join(".yarnrc.yml"),
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
    )
    .unwrap();
    let global = tmp.join("berry-bootstrap-global");
    let out = corepack(
        &boot,
        YARN_BERRY,
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !out.status.success() {
        println!(
            "SKIP e2e_redirect_yarn_berry_build: bootstrap yarn install failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    let lock = std::fs::read_to_string(boot.join("yarn.lock")).ok()?;
    let checksum = lock
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("checksum: 10c0/"))?
        .trim_start_matches("checksum: ")
        .to_string();
    Some(checksum)
}

/// Everything the fresh-checkout leg needs. `tmp` owns the tree; `_server`
/// keeps the hosted-tarball route alive through the fresh install.
struct BerryRedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    patched: Vec<u8>,
    host: String,
    _server: MockServer,
}

/// Steps 1–3: real install, patched tarball + bootstrap checksum + API mocks,
/// `scan --mode hosted --vex`, and the envelope/lockfile/ledger assertions.
/// `tamper_served_tarball` serves DIFFERENT bytes at the archiveUrl than the
/// checksum pins. `None` = skip (message printed).
async fn berry_hosted_project(
    tag: &str,
    tamper_served_tarball: bool,
) -> Option<BerryRedirectFixture> {
    if !has_corepack_pm(YARN_BERRY) {
        println!("SKIP e2e_redirect_yarn_berry_build ({tag}): `corepack {YARN_BERRY}` unavailable");
        return None;
    }
    if !has_command("tar") {
        println!("SKIP e2e_redirect_yarn_berry_build ({tag}): `tar` not installed");
        return None;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"redirect-berry-capstone","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();
    std::fs::write(
        proj.join(".yarnrc.yml"),
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
    )
    .unwrap();

    // 1. REAL fixture: yarn berry install (network here, private global cache).
    let global = tmp.path().join("yarn-global");
    let install = corepack(
        &proj,
        YARN_BERRY,
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_redirect_yarn_berry_build ({tag}): fixture `yarn install` failed \
             (registry unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
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

    // 2. Patched tarball + the exact `10c0` checksum yarn computes for it.
    let tgz_path = tmp.path().join(format!("{DEP}-{DEP_VERSION}.tgz"));
    build_patched_tgz(&installed_dir, &patched, &tgz_path);
    let tgz = std::fs::read(&tgz_path).unwrap();
    // `None` (bootstrap install couldn't run) propagates as a skip.
    let checksum = bootstrap_berry_checksum(tmp.path(), &tgz_path)?;
    let served: Vec<u8> = if tamper_served_tarball {
        // A DIFFERENT but still-valid tarball: rebuild with different patched
        // bytes so yarn's recomputed cache-zip checksum won't match the pin.
        let other: Vec<u8> = [b"/* SOCKET-TAMPERED */\n".as_slice(), orig.as_slice()].concat();
        let other_path = tmp.path().join("tampered.tgz");
        build_patched_tgz(&installed_dir, &other, &other_path);
        std::fs::read(&other_path).unwrap()
    } else {
        tgz.clone()
    };

    // 3. API mocks + the hosted tarball route yarn will hit at install time.
    let server = MockServer::start().await;
    let host = server.uri().replace("http://", "").replace("https://", "");
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
                    "title": "redirect berry capstone fixture"
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
    // Reference: granted, carrying BOTH a tarball (sha512, opaque here) and the
    // yarn-berry-zip artifact whose yarnBerry10c0 is the bootstrap checksum.
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
                          "integrity": { "sha512": "sha512-unused-by-berry==" } },
                        { "kind": "yarn-berry-zip", "url": hosted_url,
                          "integrity": { "yarnBerry10c0": checksum } }
                    ],
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
                    "cves": ["CVE-2026-1111"], "summary": "redirect berry capstone vuln",
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

    // Lockfile pin: the encoded __archiveUrl + the 10c0 checksum.
    let lock = std::fs::read_to_string(proj.join("yarn.lock")).unwrap();
    let encoded = socket_patch_core::utils::uri::encode_uri_component(&hosted_url);
    assert!(
        lock.contains("::__archiveUrl=") && lock.contains(&encoded),
        "yarn.lock must carry the encoded __archiveUrl; got:\n{lock}"
    );
    assert!(
        lock.contains(&checksum),
        "yarn.lock must carry the 10c0 checksum ({checksum}); got:\n{lock}"
    );

    let ledger = std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("\"records\"") && ledger.contains(GHSA),
        "redirect ledger must embed the patch record + vulnerability: {ledger}"
    );

    Some(BerryRedirectFixture {
        tmp,
        proj,
        patched,
        host,
        _server: server,
    })
}

/// Fresh dir with only the committable files, then `yarn install --immutable
/// --check-cache` offline-from-registry (the wiremock host is whitelisted for
/// http). Returns the fresh dir + the install output.
fn fresh_checkout_yarn_install(fx: &BerryRedirectFixture) -> (PathBuf, Output) {
    let fresh = fx.tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(fx.proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(fx.proj.join("yarn.lock"), fresh.join("yarn.lock")).unwrap();
    // A fresh .yarnrc.yml: node-modules linker, no global cache, and the
    // wiremock host whitelisted for plain http (yarn refuses http otherwise).
    std::fs::write(
        fresh.join(".yarnrc.yml"),
        format!(
            "nodeLinker: node-modules\nenableGlobalCache: false\n\
             unsafeHttpWhitelist:\n  - \"{}\"\n\
             npmRegistryServer: \"http://127.0.0.1:1\"\n",
            fx.host.split(':').next().unwrap_or("127.0.0.1")
        ),
    )
    .unwrap();
    copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
    let fresh_global = fx.tmp.path().join("fresh-yarn-global");
    let ci = corepack(
        &fresh,
        YARN_BERRY,
        &["install", "--immutable", "--check-cache"],
        &[
            ("YARN_GLOBAL_FOLDER", fresh_global.to_str().unwrap()),
            ("YARN_ENABLE_GLOBAL_CACHE", "false"),
        ],
    );
    (fresh, ci)
}

// ── the capstone ──────────────────────────────────────────────────────

// #[serial]: real yarn shares content-addressed cache state across concurrent
// installs of the same tarball; serializing keeps the tampered twin from
// reusing a cache entry the main leg populated (which would mask the YN0018).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn berry_redirect_fresh_checkout_installs_patched_bytes() {
    let Some(fx) = berry_hosted_project("main", false).await else {
        return;
    };

    let (fresh, ci) = fresh_checkout_yarn_install(&fx);
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --immutable --check-cache` must succeed from the \
         hosted patch tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "yarn must install the PATCHED bytes from the hosted patch; got:\n{}",
        String::from_utf8_lossy(&installed[..installed.len().min(120)])
    );
    assert_eq!(
        installed, fx.patched,
        "fresh install must be byte-identical to the patched content"
    );
}

/// Negative twin: the archiveUrl serves a DIFFERENT tarball while the lock
/// pins the real `10c0` checksum — the fresh `--check-cache` install must fail
/// with YN0018.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn berry_redirect_tampered_hosted_tarball_fails_check_cache() {
    let Some(fx) = berry_hosted_project("tampered", true).await else {
        return;
    };

    let (_fresh, ci) = fresh_checkout_yarn_install(&fx);
    assert!(
        !ci.status.success(),
        "yarn --check-cache MUST fail when the served tarball's cache-zip checksum does not \
         match the pinned 10c0.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let chatter = format!(
        "{}\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr)
    );
    assert!(
        chatter.contains("YN0018") || chatter.to_lowercase().contains("checksum"),
        "the failure must be the checksum check, not something incidental:\n{chatter}"
    );
}
