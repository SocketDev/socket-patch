//! Real-yarn-berry `nodeLinker: pnpm` capstones — hosted redirect + vendored
//! wiring for yarn 4's pnpm-style install layout.
//!
//! With `nodeLinker: pnpm`, berry materializes packages under
//! `node_modules/.store/<name>-<protocol>-<hash>/package/` and exposes them
//! through symlinks at `node_modules/<name>` — the same shape pnpm uses.
//! The 36-cell yarn matrix sweep (2026-08-18, real production data) proved
//! discovery crawls that layout fine and both lockfile-touching modes work
//! end-to-end, but the layout is completely unmentioned in code or tests: a
//! regression (e.g. a crawler that stops following the top-level symlinks,
//! or a wiring step confused by the `.store` path) would ship unseen. These
//! capstones pin it against the REAL `corepack yarn@4.12.0` (network for
//! fixture setup only), mirroring the node-modules-linker siblings
//! (`e2e_redirect_yarn_berry_build.rs` / `e2e_vendor_yarn_berry_build.rs`):
//!
//!   * hosted — `scan --mode hosted` rewires `yarn.lock` to the hosted
//!     `__archiveUrl` + `10c0` checksum (bootstrap-resolution trick, see the
//!     redirect sibling); a fresh checkout of only the committable files
//!     passes `yarn install --immutable --check-cache` offline-from-registry
//!     and serves the patched bytes THROUGH the `.store` symlink layout.
//!   * vendored — `vendor --offline` wires `resolutions` + the `file:`
//!     locator; the fresh `--immutable --check-cache` install lands the
//!     patched bytes in a `left-pad-file-<hash>` store entry, and
//!     `--revert` restores package.json AND yarn.lock byte-for-byte.
//!
//! Both fresh installs additionally prove resolution through `yarn node`
//! (`require.resolve` traverses the symlink into `.store`).
//!
//! LOCAL capstones (not behind docker-e2e): each skips with a `println` +
//! return when `corepack yarn@4.12.0` is unavailable or the fixture install
//! cannot reach the registry; every assertion after that is HARD.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "5e6f7a8b-9c0d-4e5f-8a6b-456789abcdef";
const TOKEN: &str = "55555555-5555-4555-8555-555555555555";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const GHSA: &str = "GHSA-yarn4-pnpm-linker";
const YARN_BERRY: &str = "yarn@4.12.0";
/// The project yarnrc for every leg: berry's pnpm-style store layout.
const YARNRC_PNPM: &str = "nodeLinker: pnpm\nenableGlobalCache: false\n";

// ── self-contained helpers (convention: e2e test files stay standalone) ─

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Probe corepack from a NEUTRAL temp dir (see the redirect sibling: an
/// ancestor `packageManager` field would make corepack refuse other PMs).
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

fn has_command(cmd: &str) -> bool {
    let mut probe = Command::new(cmd);
    probe.arg("--version");
    cache_env::isolate(&mut probe);
    probe
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn scrub_socket_env(cmd: &mut Command) {
    // Seed-then-scrub (mirrors e2e_redirect_yarn_berry_build.rs): an ambient
    // `YARN_NODE_LINKER` outranks the project yarnrc — here it would silently
    // flip the very layout this suite exists to pin, so the seed keeps the
    // scrub honest. (`pnp` rather than `node-modules` as the seed: a PnP tree
    // has no node_modules at all, so a dropped scrub fails loudly.)
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
    // Scrub FIRST, then the hermetic flags so they survive (last env wins).
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

/// The pnpm-linker layout invariant: `node_modules/<dep>` is a symlink and
/// the backing store entry lives under `node_modules/.store/<dep>-…`. This
/// is the assertion that makes these capstones about the LAYOUT rather than
/// a rerun of the node-modules siblings.
fn assert_pnpm_store_layout(root: &Path, ctx: &str) {
    let link = root.join("node_modules").join(DEP);
    let meta = std::fs::symlink_metadata(&link)
        .unwrap_or_else(|e| panic!("({ctx}) node_modules/{DEP} missing: {e}"));
    assert!(
        meta.file_type().is_symlink(),
        "({ctx}) nodeLinker: pnpm must expose {DEP} as a symlink into .store"
    );
    let store = root.join("node_modules").join(".store");
    let entries: Vec<String> = std::fs::read_dir(&store)
        .unwrap_or_else(|e| panic!("({ctx}) node_modules/.store missing: {e}"))
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries.iter().any(|n| n.starts_with(DEP)),
        "({ctx}) .store must hold a {DEP} entry; found: {entries:?}"
    );
}

/// RESOLUTION PROOF: `yarn node`'s `require.resolve` must traverse the
/// pnpm-linker symlinks to the PATCHED bytes, and the resolved real path
/// must live inside `.store`.
fn assert_yarn_node_resolves_patched(root: &Path, patched: &[u8]) {
    let out = corepack(
        root,
        YARN_BERRY,
        &["node", "-p", &format!("require.resolve('{DEP}')")],
        &[],
    );
    assert!(
        out.status.success(),
        "`yarn node` must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let resolved = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let bytes = std::fs::read(&resolved)
        .unwrap_or_else(|e| panic!("cannot read resolved path {resolved}: {e}"));
    assert_eq!(
        bytes, patched,
        "yarn node must resolve the PATCHED bytes (via {resolved})"
    );
}

/// Git-blob SHA-256 for the offline vendor manifest.
fn git_sha256(content: &[u8]) -> String {
    compute_git_sha256_from_bytes(content)
}

/// Write `.socket/manifest.json` + the after-hash blob so vendor runs fully
/// offline.
fn stage_patch(proj: &Path, purl: &str, before: &[u8], after: &[u8]) {
    let socket = proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": { purl: {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": git_sha256(before),
                "afterHash": git_sha256(after),
            }},
            "vulnerabilities": {},
            "description": "pnpm-linker capstone marker patch",
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

/// Build a patched npm tarball (`package/` prefix, marker-prepended index.js)
/// from the installed dep directory (read through the store symlink —
/// copy_dir_recursive reads file contents, so the layout is flattened into a
/// regular `package/` tree exactly as a registry tarball would carry it).
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

/// BOOTSTRAP: resolve the patched tarball with a real yarn to extract the
/// exact `10c0/<hex>` checksum for its cache zip (see the redirect sibling's
/// module docs — the checksum is linker-independent, so the bootstrap runs
/// with the default node-modules linker). `None` = skip (message printed).
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
            "SKIP e2e_yarn4_pnpm_linker_build: bootstrap yarn install failed:\n{}",
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

/// Install the single-package pnpm-linker fixture; `None` = skip printed.
fn install_pnpm_fixture(tag: &str, tmp: &Path, proj: &Path) -> Option<Vec<u8>> {
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"yarn4-pnpm-linker-capstone","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();
    std::fs::write(proj.join(".yarnrc.yml"), YARNRC_PNPM).unwrap();
    let global = tmp.join("yarn-global");
    let install = corepack(
        proj,
        YARN_BERRY,
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_yarn4_pnpm_linker_build ({tag}): fixture `yarn install` failed \
             (registry unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return None;
    }
    assert_pnpm_store_layout(proj, tag);
    // Read THROUGH the symlink — the same path discovery crawls.
    let orig = std::fs::read(proj.join("node_modules").join(DEP).join("index.js"))
        .expect("installed index.js (through the .store symlink)");
    assert!(
        !orig.starts_with(MARKER.as_bytes()),
        "({tag}) pristine install must not carry the marker"
    );
    Some(orig)
}

/// Fresh dir with only the committable files, then `yarn install --immutable
/// --check-cache` with an empty global cache under the pnpm linker.
fn fresh_checkout_install(tmp: &Path, proj: &Path, yarnrc: &str) -> (PathBuf, Output) {
    let fresh = tmp.join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(proj.join("yarn.lock"), fresh.join("yarn.lock")).unwrap();
    std::fs::write(fresh.join(".yarnrc.yml"), yarnrc).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    let fresh_global = tmp.join("fresh-yarn-global");
    let ci = corepack(
        &fresh,
        YARN_BERRY,
        &["install", "--immutable", "--check-cache"],
        &[("YARN_GLOBAL_FOLDER", fresh_global.to_str().unwrap())],
    );
    (fresh, ci)
}

// ── hosted capstone ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn yarn4_pnpm_linker_hosted_redirect_fresh_checkout_installs_patched_bytes() {
    if !has_corepack_pm(YARN_BERRY) {
        println!("SKIP e2e_yarn4_pnpm_linker_build (hosted): `corepack {YARN_BERRY}` unavailable");
        return;
    }
    if !has_command("tar") {
        println!("SKIP e2e_yarn4_pnpm_linker_build (hosted): `tar` not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let Some(orig) = install_pnpm_fixture("hosted", tmp.path(), &proj) else {
        return;
    };
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();

    // Patched tarball + the exact `10c0` checksum yarn computes for it.
    let tgz_path = tmp.path().join(format!("{DEP}-{DEP_VERSION}.tgz"));
    build_patched_tgz(&proj.join("node_modules").join(DEP), &patched, &tgz_path);
    let tgz = std::fs::read(&tgz_path).unwrap();
    let Some(checksum) = bootstrap_berry_checksum(tmp.path(), &tgz_path) else {
        return;
    };

    // API mocks + the hosted tarball route yarn will hit at install time.
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
                    "title": "pnpm-linker hosted capstone fixture"
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
                    "cves": ["CVE-2026-4444"], "summary": "pnpm-linker capstone vuln",
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
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(tgz.clone(), "application/octet-stream"),
        )
        .mount(&server)
        .await;

    let pkg_before = std::fs::read(proj.join("package.json")).unwrap();

    // scan --mode hosted — discovery must crawl the .store layout to even
    // find the installed package.
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
    assert!(
        env["packagesWithPatches"].as_u64() >= Some(1),
        "discovery must find the dep through the pnpm-linker layout: {env}"
    );
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "one dep redirected: {env}"
    );

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
    assert_eq!(
        std::fs::read(proj.join("package.json")).unwrap(),
        pkg_before,
        "hosted redirect must not touch package.json"
    );
    eprintln!("HOSTED REWIRE OK");

    // FRESH-CHECKOUT PROOF: committable files only, offline from the
    // registry, pnpm linker — the patched bytes must land in .store and be
    // served through the symlink.
    let yarnrc = format!(
        "{YARNRC_PNPM}unsafeHttpWhitelist:\n  - \"{}\"\nnpmRegistryServer: \"http://127.0.0.1:1\"\n",
        host.split(':').next().unwrap_or("127.0.0.1")
    );
    let (fresh, ci) = fresh_checkout_install(tmp.path(), &proj, &yarnrc);
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --immutable --check-cache` must succeed from the \
         hosted patch tarball under nodeLinker: pnpm.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    assert_pnpm_store_layout(&fresh, "hosted-fresh");
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert_eq!(
        installed, patched,
        "fresh install must serve the patched bytes through the .store symlink"
    );
    assert_yarn_node_resolves_patched(&fresh, &patched);
    eprintln!("FRESH INSTALL + YARN NODE RESOLUTION OK");
}

// ── vendored capstone ─────────────────────────────────────────────────

#[test]
fn yarn4_pnpm_linker_vendor_fresh_checkout_installs_patched_bytes_and_reverts() {
    if !has_corepack_pm(YARN_BERRY) {
        println!(
            "SKIP e2e_yarn4_pnpm_linker_build (vendored): `corepack {YARN_BERRY}` unavailable"
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let Some(orig) = install_pnpm_fixture("vendored", tmp.path(), &proj) else {
        return;
    };
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    stage_patch(&proj, PURL, &orig, &patched);

    // Committable baseline AFTER install (berry pretty-prints package.json).
    let lock_path = proj.join("yarn.lock");
    let pkg_path = proj.join("package.json");
    let lock_before = std::fs::read(&lock_path).unwrap();
    let pkg_before = std::fs::read(&pkg_path).unwrap();

    // Vendor (offline) — discovery must crawl the .store layout.
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
    let pkg_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&pkg_path).unwrap()).unwrap();
    assert_eq!(
        pkg_json["resolutions"][DEP].as_str(),
        Some(format!("file:./{tgz_rel}").as_str()),
        "package.json must gain the resolutions entry: {pkg_json}"
    );
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock_after.contains(&format!("left-pad@file:./{tgz_rel}::locator=")),
        "yarn.lock must carry the file: locator entry; got:\n{lock_after}"
    );
    eprintln!("VENDOR OK");

    // FRESH-CHECKOUT PROOF under the pnpm linker: the patched bytes land in
    // a file-protocol store entry and serve through the symlink.
    let (fresh, ci) = fresh_checkout_install(tmp.path(), &proj, YARNRC_PNPM);
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --immutable --check-cache` must succeed from the \
         vendored tarball under nodeLinker: pnpm.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    assert_pnpm_store_layout(&fresh, "vendored-fresh");
    // The store entry for a file:-resolved package is `<name>-file-<hash>` —
    // the observable difference from the registry (`<name>-npm-<version>-…`)
    // entry, proving the vendored tarball (not the registry) fed the store.
    let store_entries: Vec<String> = std::fs::read_dir(fresh.join("node_modules/.store"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        store_entries
            .iter()
            .any(|n| n.starts_with(&format!("{DEP}-file-"))),
        "the store must hold a file-protocol entry for {DEP}; found: {store_entries:?}"
    );
    let fresh_installed =
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert_eq!(
        fresh_installed, patched,
        "fresh install must serve the patched bytes through the .store symlink"
    );
    assert_yarn_node_resolves_patched(&fresh, &patched);
    eprintln!("FRESH INSTALL + YARN NODE RESOLUTION OK");

    // REVERT PROOF: package.json AND yarn.lock restored byte-for-byte.
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
    let renv: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("revert --json output is not JSON: {e}\nstdout:\n{stdout}"));
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
