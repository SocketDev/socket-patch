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
//!     tarball-URL locator + `10c0` checksum (bootstrap-resolution trick, see the
//!     redirect sibling); a fresh checkout of only the committable files
//!     passes `yarn install --immutable --check-cache` offline-from-registry
//!     and serves the patched bytes THROUGH the `.store` symlink layout.
//!   * vendored — `vendor` wires `resolutions` + the `file:`
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
//!
//! Every capstone ends with the manifest-less VEX matrix
//! (`yarn_berry_common::run_manifestless_vex_matrix`): fresh checkouts of the
//! wired state without the manifest, without the ledgers, `--offline`,
//! tampered, reverted to the registry and installed under PnP — each
//! installed by the REAL yarn and attested (or refused) by standalone and
//! embedded VEX against a mock patch API. The yarn 4 release is
//! `SOCKET_PATCH_YARN_BERRY_VERSION` (default 4.12.0; loop:
//! `scripts/yarn-berry-vex-matrix.sh`); `SOCKET_PATCH_YARN_E2E_REQUIRED=1`
//! turns every soft-skip into a failure.

#[path = "common/mod.rs"]
mod common;
use common::{binary, git_sha256};

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "5e6f7a8b-9c0d-4e5f-8a6b-456789abcdef";
const TOKEN: &str = "55555555-5555-4555-8555-555555555555";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const CVE: &str = "CVE-2026-4444";
const GHSA: &str = "GHSA-yarn4-pnpm-linker";
// The yarn 4 release under test is `yarn_berry()` (`yarn@4.12.0` unless
// `SOCKET_PATCH_YARN_BERRY_VERSION` pins another 4.x — see yarn_berry_common).
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[path = "yarn_berry_common/mod.rs"]
mod yarn_berry_common;
use yarn_berry_common::{yarn_berry, yarn_e2e_required};

/// Print a SKIP line — or, under `SOCKET_PATCH_YARN_E2E_REQUIRED=1` (a leg
/// that provisioned corepack yarn on purpose), FAIL: a required leg must
/// never report green on an unexercised toolchain or an unreachable fixture
/// registry.
macro_rules! skip {
    ($($arg:tt)*) => {{
        let msg = format!($($arg)*);
        if yarn_e2e_required() {
            panic!("{msg} (SOCKET_PATCH_YARN_E2E_REQUIRED=1 forbids skipping)");
        }
        println!("{msg}");
    }};
}
/// The project yarnrc for every leg: berry's pnpm-style store layout.
const YARNRC_PNPM: &str = "nodeLinker: pnpm\nenableGlobalCache: false\n";

// ── self-contained helpers (convention: e2e test files stay standalone) ─

/// Probe corepack from a NEUTRAL temp dir (see the redirect sibling: an
/// ancestor `packageManager` field would make corepack refuse other PMs).
fn has_corepack_pm(pm: &str) -> bool {
    let Ok(probe) = tempfile::tempdir() else {
        return false;
    };
    let mut cmd = yarn_berry_common::corepack_command();
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
    let mut cmd = yarn_berry_common::corepack_command();
    cmd.arg(pm).args(args).current_dir(cwd);
    // Scrub FIRST, then the hermetic flags so they survive (last env wins).
    scrub_socket_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    yarn_berry_common::pin_berry_ci_defaults(&mut cmd, pm);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        .env("YARN_ENABLE_GLOBAL_CACHE", "false");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    yarn_berry_common::berry_spawn_output(&mut cmd).expect("failed to run corepack")
}

fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.current_dir(cwd);
    scrub_socket_env(&mut cmd);
    let _fixture = prebuilt_common::prepare_command(&mut cmd, cwd, args, &[]);
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
        yarn_berry(),
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
            "vulnerabilities": { GHSA: {
                "cves": [CVE], "summary": "capstone vuln",
                "severity": "high", "description": "d",
            }},
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
        yarn_berry(),
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !out.status.success() {
        skip!(
            "SKIP e2e_yarn4_pnpm_linker_build: bootstrap yarn install failed:\n{}",
            yarn_berry_common::yarn_output(&out)
        );
        return None;
    }
    let lock = std::fs::read_to_string(boot.join("yarn.lock")).ok()?;
    // yarn 4.0.x writes the bare hex, 4.1+ `10c0/<hex>`: the API form is the
    // prefixed one. A lock with neither is a harness failure, never a
    // silent pass.
    let checksum = yarn_berry_common::yarn_written_checksum(&lock);
    if checksum.is_none() {
        skip!(
            "SKIP: bootstrap `{} install` wrote no 10c0 cache checksum:\n{lock}",
            yarn_berry()
        );
    }
    checksum
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
        yarn_berry(),
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !install.status.success() {
        skip!(
            "SKIP e2e_yarn4_pnpm_linker_build ({tag}): fixture `yarn install` failed \
             (registry unreachable?):\n{}",
            yarn_berry_common::yarn_output(&install)
        );
        return None;
    }
    // Windows line endings (yarn writes CRLF there): see yarn_berry_common.
    yarn_berry_common::adopt_yarn_line_endings(
        proj,
        yarn_berry(),
        &format!("pnpm-linker-{tag}"),
        &["package.json", "yarn.lock"],
    );
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
    // v5 hosted mode may leave no `.socket/` at all (no ledger, no manifest).
    if proj.join(".socket").is_dir() {
        copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
    }
    let fresh_global = tmp.join("fresh-yarn-global");
    let ci = corepack(
        &fresh,
        yarn_berry(),
        &["install", "--immutable", "--check-cache"],
        &[("YARN_GLOBAL_FOLDER", fresh_global.to_str().unwrap())],
    );
    (fresh, ci)
}

// ── hosted capstone ───────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn yarn4_pnpm_linker_hosted_redirect_fresh_checkout_installs_patched_bytes() {
    if !has_corepack_pm(yarn_berry()) {
        skip!(
            "SKIP e2e_yarn4_pnpm_linker_build (hosted): `corepack {}` unavailable",
            yarn_berry()
        );
        return;
    }
    if !has_command("tar") {
        skip!("SKIP e2e_yarn4_pnpm_linker_build (hosted): `tar` not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let Some(orig) = install_pnpm_fixture("hosted", tmp.path(), &proj) else {
        return;
    };
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    let registry_lock = std::fs::read(proj.join("yarn.lock")).unwrap();

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
                    "cves": [CVE], "summary": "pnpm-linker capstone vuln",
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
        env["packages"].as_array().map(Vec::len) >= Some(1),
        "discovery must find the dep through the pnpm-linker layout: {env}"
    );
    assert_eq!(env["summary"]["applied"], 1, "one dep redirected: {env}");

    let lock = std::fs::read_to_string(proj.join("yarn.lock")).unwrap();
    assert!(
        lock.contains(&format!("\n  resolution: \"{DEP}@{hosted_url}\"")),
        "yarn.lock must pin the hosted tarball locator; got:\n{lock}"
    );
    // #404 option C: the entry is keyed by the tarball descriptor, and the
    // root package.json routes the locked descriptor there.
    assert!(
        lock.lines()
            .any(|l| l.trim_end_matches('\r') == format!("\"{DEP}@{hosted_url}\":")),
        "yarn.lock entry must be keyed by the tarball descriptor; got:\n{lock}"
    );
    let root_pkg = std::fs::read_to_string(proj.join("package.json")).unwrap();
    let root_pkg: serde_json::Value = serde_json::from_str(&root_pkg).unwrap();
    assert!(
        root_pkg["resolutions"].as_object().is_some_and(|r| r
            .iter()
            .any(|(sel, v)| sel.starts_with(&format!("{DEP}@npm:"))
                && v.as_str() == Some(hosted_url.as_str()))),
        "package.json must route {DEP} to the hosted tarball: {root_pkg}"
    );
    assert!(
        !lock.contains("__archiveUrl"),
        "the hosted pin must not be an npm: locator (#404); got:\n{lock}"
    );
    let checksum_line = yarn_berry_common::expected_checksum_line(
        &String::from_utf8_lossy(&registry_lock),
        &checksum,
    );
    assert!(
        lock.lines().any(|l| l == checksum_line),
        "yarn.lock must carry the cache checksum in yarn's own spelling \
         ({checksum_line:?}); got:\n{lock}"
    );
    // #404 option C: the only package.json change is the `resolutions` pin.
    {
        let mut after: serde_json::Value =
            serde_json::from_slice(&std::fs::read(proj.join("package.json")).unwrap()).unwrap();
        let before: serde_json::Value = serde_json::from_slice(&pkg_before).unwrap();
        after.as_object_mut().unwrap().shift_remove("resolutions");
        assert_eq!(
            after, before,
            "the hosted pin only adds `resolutions` to package.json"
        );
    }
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

    // MANIFEST-LESS VEX over the hosted wiring (see `yarn_berry_common`).
    let registry_state = [
        ("yarn.lock", registry_lock),
        ("package.json", pkg_before.clone()),
    ];
    let yarn =
        |cwd: &Path, args: &[&str], env: &[(&str, &str)]| corepack(cwd, yarn_berry(), args, env);
    let api_url = server.uri();
    let flow = yarn_berry_common::BerryVexFlow {
        yarn_spec: yarn_berry(),
        flow: "pnpm-linker",
        wiring: yarn_berry_common::BerryWiring::Hosted {
            patch_server: api_url.clone(),
        },
        proj: &proj,
        scratch: tmp.path(),
        committable: &["package.json", "yarn.lock"],
        yarnrc: &yarnrc,
        registry_state: &registry_state,
        purl: PURL,
        uuid: UUID,
        vulns: &[(GHSA, &[CVE])],
        patched: &patched,
        pristine: &orig,
        installed: "node_modules/left-pad/index.js",
        registry_cache: proj.join(".yarn/cache"),
        yarn: &yarn,
        flow_api: Some(yarn_berry_common::FlowApi {
            api_url,
            org: ORG.to_string(),
        }),
        pnp_cell: true,
    };
    yarn_berry_common::off_runtime(|| yarn_berry_common::run_manifestless_vex_matrix(&flow));
}

// ── vendored capstone ─────────────────────────────────────────────────

#[test]
fn yarn4_pnpm_linker_vendor_fresh_checkout_installs_patched_bytes_and_reverts() {
    if !has_corepack_pm(yarn_berry()) {
        skip!(
            "SKIP e2e_yarn4_pnpm_linker_build (vendored): `corepack {}` unavailable",
            yarn_berry()
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

    // Download the vendored artifact — discovery must crawl the .store layout.
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

    // MANIFEST-LESS VEX over the vendored wiring (see `yarn_berry_common`),
    // BEFORE the revert below consumes the project's wiring.
    let registry_state = [
        ("yarn.lock", lock_before.clone()),
        ("package.json", pkg_before.clone()),
    ];
    let yarn =
        |cwd: &Path, args: &[&str], env: &[(&str, &str)]| corepack(cwd, yarn_berry(), args, env);
    let flow = yarn_berry_common::BerryVexFlow {
        yarn_spec: yarn_berry(),
        flow: "pnpm-linker",
        wiring: yarn_berry_common::BerryWiring::Vendored {
            artifact_rel: tgz_rel.clone(),
        },
        proj: &proj,
        scratch: tmp.path(),
        committable: &["package.json", "yarn.lock"],
        yarnrc: YARNRC_PNPM,
        registry_state: &registry_state,
        purl: PURL,
        uuid: UUID,
        vulns: &[(GHSA, &[CVE])],
        patched: &patched,
        pristine: &orig,
        installed: "node_modules/left-pad/index.js",
        registry_cache: proj.join(".yarn/cache"),
        yarn: &yarn,
        flow_api: None,
        pnp_cell: true,
    };
    yarn_berry_common::off_runtime(|| yarn_berry_common::run_manifestless_vex_matrix(&flow));

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

// ── agent-mode transitive capstone (#495) ─────────────────────────────

/// #495: under the pnpm linker a TRANSITIVE dependency exists only at
/// `node_modules/.store/<slug>-npm-<v>-<hash>/package`, reachable through
/// the entry's own `node_modules/<name> -> ../package` link (yarn 4; yarn 3
/// wrote a real dir there). Agent-mode `apply` must find and patch that
/// copy, the code yarn's runtime loads must carry the patch, and
/// `rollback` must restore it.
#[test]
fn yarn4_pnpm_linker_agent_apply_patches_transitive_store_copy() {
    if !has_corepack_pm(yarn_berry()) {
        skip!(
            "SKIP e2e_yarn4_pnpm_linker_build (agent transitive): `corepack {}` unavailable",
            yarn_berry()
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"yarn4-pnpm-linker-transitive","version":"0.0.0","private":true,"dependencies":{"is-odd":"3.0.1"}}"#,
    )
    .unwrap();
    std::fs::write(proj.join(".yarnrc.yml"), YARNRC_PNPM).unwrap();
    let global = tmp.path().join("yarn-global");
    let install = corepack(
        &proj,
        yarn_berry(),
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !install.status.success() {
        skip!(
            "SKIP e2e_yarn4_pnpm_linker_build (agent transitive): fixture `yarn install` \
             failed (registry unreachable?):\n{}",
            yarn_berry_common::yarn_output(&install)
        );
        return;
    }

    // The layout under test: no importer-level `is-number`, one store
    // entry whose package dir is the only physical copy.
    let nm = proj.join("node_modules");
    assert!(
        std::fs::symlink_metadata(nm.join("is-number")).is_err(),
        "is-number must be transitive-only (not linked at the importer root)"
    );
    let entry = std::fs::read_dir(nm.join(".store"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("is-number-npm-6.0.0-"))
        })
        .expect(".store must hold an is-number-npm-6.0.0 entry");
    let index = entry.join("package").join("index.js");
    let orig = std::fs::read(&index).expect("store copy of is-number/index.js");
    assert!(!orig.starts_with(MARKER.as_bytes()));
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    stage_patch(&proj, "pkg:npm/is-number@6.0.0", &orig, &patched);
    // The before blob too, so the offline rollback can restore.
    std::fs::write(proj.join(".socket/blobs").join(git_sha256(&orig)), &orig).unwrap();

    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "apply",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "apply failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("apply --json output is not JSON: {e}\nstdout:\n{stdout}"));
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["summary"]["applied"], 1,
        "transitive copy applied: {env}"
    );
    assert_eq!(
        std::fs::read(&index).unwrap(),
        patched,
        "store copy patched"
    );

    // RUNTIME PROOF: is-odd's own require of is-number loads the patch.
    let resolve = "process.stdout.write(require('fs').readFileSync(require.resolve('is-number', \
                   {paths: [require('path').dirname(require.resolve('is-odd'))]})))";
    let out = corepack(&proj, yarn_berry(), &["node", "-e", resolve], &[]);
    assert!(
        out.status.success(),
        "`yarn node` failed:\n{}",
        yarn_berry_common::yarn_output(&out)
    );
    assert_eq!(
        out.stdout, patched,
        "is-odd must load the patched is-number"
    );

    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "rollback",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "rollback failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read(&index).unwrap(),
        orig,
        "rollback restores the store copy"
    );
}

/// #496 review: a package bundling is-number@7.0.0 lands in the pnpm
/// linker's store as `.store/parent-…/package/node_modules/is-number`,
/// beside the regular `.store/is-number-npm-7.0.0-…/package`, and Node
/// loads the BUNDLED copy for `parent`. That copy is reachable only
/// through the entry's `node_modules/parent -> ../package` link, so apply
/// must still find it: both copies get patched, `parent` loads the patch,
/// and rollback restores both.
#[test]
fn yarn4_pnpm_linker_agent_apply_patches_bundled_copy_inside_store_package() {
    if !has_corepack_pm(yarn_berry()) || !has_command("tar") {
        skip!(
            "SKIP e2e_yarn4_pnpm_linker_build (agent bundled): `corepack {}` or `tar` unavailable",
            yarn_berry()
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join(".yarnrc.yml"), YARNRC_PNPM).unwrap();
    let global = tmp.path().join("yarn-global");
    let install = |manifest: &str| {
        std::fs::write(proj.join("package.json"), manifest).unwrap();
        corepack(
            &proj,
            yarn_berry(),
            &["install"],
            &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
        )
    };

    // The registry copy first, so the bundled one can be byte-identical:
    // one patch's before-hashes then fit both.
    let out = install(
        r#"{"name":"yarn4-pnpm-linker-bundled","version":"0.0.0","private":true,"dependencies":{"is-number":"7.0.0"}}"#,
    );
    if !out.status.success() {
        skip!(
            "SKIP e2e_yarn4_pnpm_linker_build (agent bundled): fixture `yarn install` \
             failed (registry unreachable?):\n{}",
            yarn_berry_common::yarn_output(&out)
        );
        return;
    }
    let nm = proj.join("node_modules");
    let registry_copy = nm.join("is-number");

    let stage = tmp.path().join("parent-stage").join("package");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(
        stage.join("package.json"),
        r#"{"name":"parent","version":"1.0.0","main":"index.js","bundleDependencies":["is-number"],"dependencies":{"is-number":"7.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        stage.join("index.js"),
        "module.exports = require.resolve('is-number');\n",
    )
    .unwrap();
    copy_dir_recursive(
        &registry_copy,
        &stage.join("node_modules").join("is-number"),
    );
    let tgz = proj.join("parent-1.0.0.tgz");
    let tar = Command::new("tar")
        .args(["-czf", tgz.to_str().unwrap(), "package"])
        .current_dir(stage.parent().unwrap())
        .output()
        .expect("failed to run tar");
    assert!(
        tar.status.success(),
        "tar: {}",
        String::from_utf8_lossy(&tar.stderr)
    );

    let out = install(
        r#"{"name":"yarn4-pnpm-linker-bundled","version":"0.0.0","private":true,"dependencies":{"is-number":"7.0.0","parent":"file:./parent-1.0.0.tgz"}}"#,
    );
    assert!(
        out.status.success(),
        "`yarn install` with the bundling tarball failed:\n{}",
        yarn_berry_common::yarn_output(&out)
    );

    // The layout under test: two physical is-number@7.0.0 copies in the
    // store, the bundled one inside parent's `package` dir.
    let store_entry = |prefix: &str| {
        std::fs::read_dir(nm.join(".store"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(prefix))
            })
            .unwrap_or_else(|| panic!(".store must hold a {prefix}* entry"))
    };
    let regular_index = store_entry("is-number-npm-7.0.0-").join("package/index.js");
    let bundled_index = store_entry("parent-").join("package/node_modules/is-number/index.js");
    let orig = std::fs::read(&regular_index).expect("regular store copy of is-number/index.js");
    assert_eq!(
        std::fs::read(&bundled_index).expect("bundled copy inside parent's package dir"),
        orig,
        "the bundled copy is byte-identical to the registry copy"
    );

    // Which copy Node loads for `parent`: the bundled one.
    let load = "process.stdout.write(require('fs').readFileSync(require('parent')))";
    let loaded_path = corepack(
        &proj,
        yarn_berry(),
        &["node", "-p", "require('parent')"],
        &[],
    );
    // Compared as canonical paths: Node prints the platform's separators.
    let loaded = PathBuf::from(String::from_utf8_lossy(&loaded_path.stdout).trim());
    assert_eq!(
        std::fs::canonicalize(&loaded).ok(),
        std::fs::canonicalize(&bundled_index).ok(),
        "parent must load its bundled is-number:\n{}",
        yarn_berry_common::yarn_output(&loaded_path)
    );

    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    stage_patch(&proj, "pkg:npm/is-number@7.0.0", &orig, &patched);
    std::fs::write(proj.join(".socket/blobs").join(git_sha256(&orig)), &orig).unwrap();

    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "apply",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "apply failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("apply --json output is not JSON: {e}\nstdout:\n{stdout}"));
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        std::fs::read(&regular_index).unwrap(),
        patched,
        "regular copy patched"
    );
    assert_eq!(
        std::fs::read(&bundled_index).unwrap(),
        patched,
        "bundled copy patched"
    );

    // RUNTIME PROOF: the copy `parent` actually loads carries the patch.
    let out = corepack(&proj, yarn_berry(), &["node", "-e", load], &[]);
    assert!(
        out.status.success(),
        "`yarn node` failed:\n{}",
        yarn_berry_common::yarn_output(&out)
    );
    assert_eq!(
        out.stdout, patched,
        "parent must load the patched is-number"
    );

    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "rollback",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "rollback failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read(&regular_index).unwrap(),
        orig,
        "rollback restores the regular copy"
    );
    assert_eq!(
        std::fs::read(&bundled_index).unwrap(),
        orig,
        "rollback restores the bundled copy"
    );
}
