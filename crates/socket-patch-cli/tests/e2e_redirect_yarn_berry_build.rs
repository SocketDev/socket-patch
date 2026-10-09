//! Real-yarn-berry redirect capstone e2e — the hosted-mode full-chain proof
//! for the yarn berry 4.x (node-modules linker) flavor, mirroring
//! `e2e_redirect_npm_build.rs`.
//!
//! `scan --mode hosted` never lands patched bytes in the repo: it rewrites
//! `yarn.lock` so the patched dependency resolves via the tarball-URL
//! locator `<name>@<hosted-tgz>` with `checksum: 10c0/<hex>` (yarn's
//! cache-zip sha512); v5 keeps no redirect ledger — the lock pin is the
//! whole hosted state. This test proves every link against the REAL
//! `corepack yarn@4.12.0`:
//!
//!   1. `yarn install` of left-pad@1.3.0 (network for fixture setup only,
//!      private global cache, node-modules linker).
//!   2. Build a PATCHED tarball from the installed bytes, then run a BOOTSTRAP
//!      real-yarn resolution against it (`resolutions: file:./patched.tgz`) to
//!      extract the EXACT `10c0/<hex>` checksum yarn computes for that
//!      tarball's cache zip — the value the redirect mock must hand back
//!      (yarn recomputes the same zip checksum whether the locator is `file:`
//!      or a tarball URL, so `--check-cache` will accept it).
//!   3. `scan --mode hosted --json --vex` (the real binary): yarn.lock now
//!      pins the hosted tarball URL + the `10c0` checksum, NO ledger is
//!      written, the in-run VEX is the `(redirected)` attestation.
//!   4. FRESH-CHECKOUT PROOF: only package.json + yarn.lock + .yarnrc.yml +
//!      .socket/ travel; `yarn install --immutable --check-cache` (offline
//!      from the registry, `unsafeHttpWhitelist` for the wiremock host) MUST
//!      install the patched bytes from the hosted tarball — with an npm
//!      registry token configured (`YARN_NPM_AUTH_TOKEN` + `npmAlwaysAuth`)
//!      that the patch host must never receive (#404: an `npm:` locator made
//!      yarn's npm fetcher send it).
//!
//! The negative twin serves a DIFFERENT tarball at the hosted URL while the
//! lock keeps the real `10c0` checksum: the fresh `--check-cache` install MUST
//! fail with a YN0018 checksum error — the lock pin is enforcement.
//!
//! Skips (with a println) when `corepack yarn@4.12.0` is unavailable or the
//! fixture install cannot reach the registry; every assertion after is hard.
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
use common::binary;

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
const UUID: &str = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d";
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const GHSA: &str = "GHSA-redirect-berry-real";
const PRODUCT: &str = "pkg:npm/app@1.0.0";
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

// ── self-contained helpers ────────────────────────────────────────────

/// Probe corepack from a NEUTRAL temp dir: a `packageManager` field in an
/// ancestor `package.json` (e.g. this monorepo's root) makes corepack refuse
/// to run a different package manager, which would spuriously fail the gate.
/// The real installs below all run in their own tempdirs, so the probe must
/// too.
fn has_corepack_pm(pm: &str) -> bool {
    let Ok(probe) = tempfile::tempdir() else {
        return false;
    };
    // Isolated too: this probe is what actually downloads the package manager
    // the first time, and corepack stores it under `COREPACK_HOME`.
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
    // Seed-then-scrub (mirrors e2e_golang_redirect.rs): yarn berry lets EVERY
    // `.yarnrc.yml` setting be overridden by a `YARN_*` env var (env outranks
    // the project yarnrc), so an ambient `YARN_NODE_LINKER=pnp` was verified
    // to turn both tests red — the fixture install builds a PnP tree and
    // node_modules/left-pad never exists. The explicit env_remove below
    // clears the seed too, but if the scrub is ever dropped the seed (rather
    // than a developer's ambient shell, which this suite can't rely on) turns
    // the tests red immediately.
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
    // Scrub FIRST (it removes YARN_* / SOCKET_* from the inherited env), then
    // set the hermetic flags so they survive.
    scrub_socket_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    yarn_berry_common::pin_berry_ci_defaults(&mut cmd, pm);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0")
        // Hermetic: no global mirror/cache. Without this, yarn's persistent
        // `~/.yarn/berry` global cache serves a previously-fetched archive
        // keyed by the (shared) resolution locator, so the tampered twin can
        // reuse the main leg's honest bytes and never hit YN0018 (flaky pass).
        .env("YARN_ENABLE_GLOBAL_CACHE", "false");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    yarn_berry_common::berry_spawn_output(&mut cmd).expect("failed to run corepack")
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
        yarn_berry(),
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !out.status.success() {
        skip!(
            "SKIP e2e_redirect_yarn_berry_build: bootstrap yarn install failed:\n{}",
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

/// Everything the fresh-checkout leg needs. `tmp` owns the tree; `_server`
/// keeps the hosted-tarball route alive through the fresh install.
struct BerryRedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    orig: Vec<u8>,
    patched: Vec<u8>,
    host: String,
    /// `yarn.lock` as the real yarn wrote it, BEFORE the hosted rewrite.
    registry_lock: Vec<u8>,
    /// The root `package.json` BEFORE the hosted rewrite (#404 option C
    /// pins through its `resolutions`, so a revert restores both files).
    registry_pkg: Vec<u8>,
    /// The dependency is declared `"catalog:"` (#632): `.yarnrc.yml` keeps
    /// the catalog in every checkout.
    catalog: bool,
    _server: MockServer,
}

/// Which CLI front door drives the hosted engine. Both consume the SAME
/// engine by construction (v4.0): `scan --mode hosted` discovers the dep,
/// while `get <uuid> --mode hosted` names the patch explicitly (the uuid
/// identifier path is exempt from installed narrowing and needs only the
/// view + reference mocks, which the fixture mounts anyway). get has no
/// `--vex`, so the get driver drops the vex flags + assertions; the `10c0`
/// cacheKey bootstrap is engine-side and runs identically for both.
#[derive(Clone, Copy, PartialEq, Debug)]
enum HostedDriver {
    Scan,
    GetUuid,
}

/// Steps 1–3: real install, patched tarball + bootstrap checksum + API mocks,
/// the hosted rewrite (per `driver`: `scan --mode hosted --vex` or
/// `get <uuid> --mode hosted`), and the envelope/lockfile/ledger assertions.
/// `tamper_served_tarball` serves DIFFERENT bytes at the hosted URL than the
/// checksum pins. `None` = skip (message printed).
async fn berry_hosted_project(
    tag: &str,
    tamper_served_tarball: bool,
    driver: HostedDriver,
) -> Option<BerryRedirectFixture> {
    berry_hosted_project_with(tag, tamper_served_tarball, driver, false).await
}

/// [`berry_hosted_project`], with the dependency declared through the
/// default yarn catalog when `catalog` is set (#632).
async fn berry_hosted_project_with(
    tag: &str,
    tamper_served_tarball: bool,
    driver: HostedDriver,
    catalog: bool,
) -> Option<BerryRedirectFixture> {
    if !has_corepack_pm(yarn_berry()) {
        skip!(
            "SKIP e2e_redirect_yarn_berry_build ({tag}): `corepack {}` unavailable",
            yarn_berry()
        );
        return None;
    }
    if !has_command("tar") {
        skip!("SKIP e2e_redirect_yarn_berry_build ({tag}): `tar` not installed");
        return None;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"redirect-berry-capstone","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{}"}}}}"#,
            if catalog { "catalog:" } else { DEP_VERSION }
        ),
    )
    .unwrap();
    std::fs::write(
        proj.join(".yarnrc.yml"),
        format!(
            "nodeLinker: node-modules\nenableGlobalCache: false\n{}",
            catalog_yarnrc(catalog)
        ),
    )
    .unwrap();

    // 1. REAL fixture: yarn berry install (network here, private global cache).
    let global = tmp.path().join("yarn-global");
    let install = corepack(
        &proj,
        yarn_berry(),
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !install.status.success() {
        skip!(
            "SKIP e2e_redirect_yarn_berry_build ({tag}): fixture `yarn install` failed \
             (registry unreachable?):\n{}",
            yarn_berry_common::yarn_output(&install)
        );
        return None;
    }
    // Windows line endings (yarn writes CRLF there): see yarn_berry_common.
    yarn_berry_common::adopt_yarn_line_endings(
        &proj,
        yarn_berry(),
        &format!("redirect-{tag}"),
        &["package.json", "yarn.lock"],
    );
    let installed_dir = proj.join("node_modules").join(DEP);
    let orig = std::fs::read(installed_dir.join("index.js")).expect("installed index.js");
    let registry_lock = std::fs::read(proj.join("yarn.lock")).expect("registry yarn.lock");
    let registry_pkg = std::fs::read(proj.join("package.json")).expect("registry package.json");
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

    // The hosted rewrite: scan (with --vex) or get <uuid> (no --vex — get
    // has none by contract), same engine either way.
    let api_url = server.uri();
    let argv: Vec<&str> = match driver {
        HostedDriver::Scan => vec![
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &api_url,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--vex",
            "out.vex.json",
            "--vex-product",
            PRODUCT,
        ],
        HostedDriver::GetUuid => vec![
            "get",
            UUID,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            &api_url,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    };
    let (code, stdout, stderr) = run_socket(&proj, &argv);
    assert_eq!(
        code, 0,
        "{driver:?} --mode hosted failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("{driver:?} --mode hosted --json output is not JSON: {e}\nstdout:\n{stdout}")
    });
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 1, "one dep redirected: {env}");
    if driver == HostedDriver::Scan {
        // In-run VEX (step 3 of the module doc): the envelope's vex block plus
        // the document's unverified `(redirected)` attestation. Without these,
        // a scan that silently skips the VEX write (or emits the wrong
        // statement) stays green — the exit code only catches a HARD vex
        // failure. (Scan driver only: get has no --vex by contract.)
        assert_eq!(env["vex"]["path"], "out.vex.json", "vex block: {env}");
        assert_eq!(env["vex"]["statements"], 1, "vex block: {env}");
        assert_eq!(env["vex"]["format"], "openvex-0.2.0", "vex block: {env}");
        assert!(
            env["vex"]["warnings"]
                .as_array()
                .is_some_and(|w| w.iter().any(|w| w["code"] == "vex_hosted_unverified")),
            "in-run redirect VEX is attested from this run's fetched record, not hash-verified: {env}"
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
    }

    // Lockfile pin: the tarball-URL locator + the 10c0 checksum. Never an
    // `npm:` locator (`::__archiveUrl=`): yarn's npm fetcher sends registry
    // auth to whatever host that locator names (#404).
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
    if catalog {
        assert_eq!(
            root_pkg["resolutions"][format!("{DEP}@catalog:")],
            hosted_url.as_str(),
            "#632: the catalog descriptor yarn matches is routed too: {root_pkg}"
        );
    }
    assert!(
        !lock.contains("__archiveUrl"),
        "the hosted pin must not be an npm: locator; got:\n{lock}"
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

    // v5: hosted mode writes no ledger — the yarn.lock pin is the state.
    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "hosted mode must not write the redirect ledger"
    );

    Some(BerryRedirectFixture {
        tmp,
        proj,
        orig,
        patched,
        host,
        registry_lock,
        registry_pkg,
        catalog,
        _server: server,
    })
}

/// The `.yarnrc.yml` of a fresh checkout: node-modules linker, no global
/// cache, the wiremock host whitelisted for plain http (yarn refuses http
/// otherwise) and the registry poisoned (the install must come from the
/// hosted tarball alone).
fn fresh_yarnrc(fx: &BerryRedirectFixture) -> String {
    format!(
        "nodeLinker: node-modules\nenableGlobalCache: false\n\
         unsafeHttpWhitelist:\n  - \"{}\"\n\
         npmRegistryServer: \"http://127.0.0.1:1\"\n{}",
        fx.host.split(':').next().unwrap_or("127.0.0.1"),
        catalog_yarnrc(fx.catalog)
    )
}

/// The `.yarnrc.yml` default catalog of a `"catalog:"` fixture (#632).
fn catalog_yarnrc(catalog: bool) -> String {
    if catalog {
        format!("catalog:\n  {DEP}: {DEP_VERSION}\n")
    } else {
        String::new()
    }
}

/// Fresh dir with only the committable files, then `yarn install --immutable
/// --check-cache` offline-from-registry (the wiremock host is whitelisted for
/// http). The install runs with an npm registry token that yarn must apply to
/// every registry request (`YARN_NPM_AUTH_TOKEN` + `YARN_NPM_ALWAYS_AUTH`),
/// the CI shape #404 leaked to the patch host: [`assert_patch_host_got_no_auth`]
/// checks the hosted tarball request carried none. Returns the fresh dir +
/// the install output.
fn fresh_checkout_yarn_install(fx: &BerryRedirectFixture) -> (PathBuf, Output) {
    let fresh = fx.tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(fx.proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(fx.proj.join("yarn.lock"), fresh.join("yarn.lock")).unwrap();
    // A fresh .yarnrc.yml: node-modules linker, no global cache, and the
    // wiremock host whitelisted for plain http (yarn refuses http otherwise).
    std::fs::write(fresh.join(".yarnrc.yml"), fresh_yarnrc(fx)).unwrap();
    // v5 hosted mode may leave no `.socket/` at all (no ledger, no manifest).
    if fx.proj.join(".socket").is_dir() {
        copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
    }
    let fresh_global = fx.tmp.path().join("fresh-yarn-global");
    let ci = corepack(
        &fresh,
        yarn_berry(),
        &["install", "--immutable", "--check-cache"],
        &[
            ("YARN_GLOBAL_FOLDER", fresh_global.to_str().unwrap()),
            ("YARN_ENABLE_GLOBAL_CACHE", "false"),
            ("YARN_NPM_AUTH_TOKEN", REGISTRY_TOKEN),
            ("YARN_NPM_ALWAYS_AUTH", "true"),
            // Hardened mode (yarn enables it on its own for public-PR CI)
            // re-validates every lock resolution against its descriptor; a
            // tarball locator under an `npm:` key fails it with YN0078 —
            // why the pin routes through `resolutions` (#404).
            ("YARN_ENABLE_HARDENED_MODE", "true"),
        ],
    );
    (fresh, ci)
}

/// The npm registry token the fresh install is configured with.
const REGISTRY_TOKEN: &str = "SOCKET-E2E-REGISTRY-TOKEN";

/// #404: the patch host fetched the hosted tarball, and no request it
/// received carried an `Authorization` header (or the registry token in any
/// header) — the hosted pin must never hand registry credentials to it.
async fn assert_patch_host_got_no_auth(fx: &BerryRedirectFixture) {
    let requests = fx
        ._server
        .received_requests()
        .await
        .expect("wiremock request recording is on");
    let tarball_gets: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path().ends_with(".tgz"))
        .collect();
    assert!(
        !tarball_gets.is_empty(),
        "the fresh install must fetch the hosted tarball from the patch host"
    );
    // The same wiremock also plays the Socket API, whose requests carry the
    // CLI's own API token — only the yarn-made tarball fetches are judged
    // for an Authorization header; the registry token must appear nowhere.
    for r in &tarball_gets {
        assert!(
            !r.headers.contains_key("authorization"),
            "{} {} carried an Authorization header to the patch host: {:?}",
            r.method,
            r.url,
            r.headers.get("authorization")
        );
    }
    for r in &requests {
        for (name, value) in r.headers.iter() {
            assert!(
                !value.to_str().unwrap_or("").contains(REGISTRY_TOKEN),
                "{} {} leaked the registry token in header {name}",
                r.method,
                r.url
            );
        }
    }
}

/// The manifest-less VEX matrix over the hosted rewrite `driver` produced
/// (see `yarn_berry_common`): fresh checkouts without the manifest, without
/// the ledgers, offline, tampered, reverted to the registry and installed
/// under PnP — each installed by the REAL yarn and attested (or refused) by
/// the REAL binary against a mock patch API.
fn hosted_manifestless_vex_matrix(fx: &BerryRedirectFixture, driver: HostedDriver) {
    let yarnrc = fresh_yarnrc(fx);
    let registry_state = [
        ("yarn.lock", fx.registry_lock.clone()),
        ("package.json", fx.registry_pkg.clone()),
    ];
    let yarn =
        |cwd: &Path, args: &[&str], env: &[(&str, &str)]| corepack(cwd, yarn_berry(), args, env);
    let api_url = fx._server.uri();
    let flow = yarn_berry_common::BerryVexFlow {
        yarn_spec: yarn_berry(),
        flow: match driver {
            HostedDriver::Scan => "node-modules(scan)",
            HostedDriver::GetUuid => "node-modules(get)",
        },
        wiring: yarn_berry_common::BerryWiring::Hosted {
            patch_server: api_url.clone(),
        },
        proj: &fx.proj,
        scratch: fx.tmp.path(),
        committable: &["package.json", "yarn.lock"],
        yarnrc: &yarnrc,
        registry_state: &registry_state,
        purl: PURL,
        uuid: UUID,
        vulns: &[(GHSA, &["CVE-2026-1111"])],
        patched: &fx.patched,
        pristine: &fx.orig,
        installed: "node_modules/left-pad/index.js",
        registry_cache: fx.proj.join(".yarn/cache"),
        yarn: &yarn,
        // Re-run the flow's own `scan --mode hosted --vex` manifest-less
        // (the get driver has no `--vex` by contract).
        flow_api: (driver == HostedDriver::Scan).then(|| yarn_berry_common::FlowApi {
            api_url,
            org: ORG.to_string(),
        }),
        pnp_cell: true,
    };
    yarn_berry_common::off_runtime(|| yarn_berry_common::run_manifestless_vex_matrix(&flow));
}

// ── the capstone ──────────────────────────────────────────────────────

// #[serial]: real yarn shares content-addressed cache state across concurrent
// installs of the same tarball; serializing keeps the tampered twin from
// reusing a cache entry the main leg populated (which would mask the YN0018).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn berry_redirect_fresh_checkout_installs_patched_bytes() {
    let Some(fx) = berry_hosted_project("main", false, HostedDriver::Scan).await else {
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
    assert_patch_host_got_no_auth(&fx).await;

    hosted_manifestless_vex_matrix(&fx, HostedDriver::Scan);
}

/// #632: a dependency declared through a yarn catalog (`"catalog:"`, yarn
/// >= 4.10). Yarn matches `resolutions` before it expands the catalog, so a
/// pin routing only the expanded `npm:` descriptor left the fresh
/// `--immutable` install failing YN0028 (and a mutable one unpatched). The
/// fresh checkout must install the patched bytes from the hosted tarball.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn berry_redirect_catalog_dependency_fresh_checkout_installs() {
    let release = yarn_berry().strip_prefix("yarn@").unwrap_or(yarn_berry());
    let minor: Vec<u32> = release
        .split('.')
        .take(2)
        .filter_map(|p| p.parse().ok())
        .collect();
    if minor.as_slice() < [4, 10].as_slice() {
        // Not a skip of an available toolchain: catalogs do not exist before
        // yarn 4.10, so there is nothing to exercise.
        println!("SKIP berry catalog e2e: {release} predates yarn catalogs (4.10)");
        return;
    }
    let Some(fx) = berry_hosted_project_with("catalog", false, HostedDriver::Scan, true).await
    else {
        return;
    };

    let (fresh, ci) = fresh_checkout_yarn_install(&fx);
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --immutable --check-cache` of a catalog dependency \
         must succeed from the hosted patch tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert_eq!(
        installed, fx.patched,
        "fresh install of the catalog dependency must be the patched content"
    );
    assert_patch_host_got_no_auth(&fx).await;
}

/// get-driven hosted twin (v4.0): `get <uuid> --mode hosted --json --yes`
/// routes through the SAME hosted engine as `scan --mode hosted`, so the
/// berry chain must hold unchanged — including the `10c0` cacheKey bootstrap
/// (the fixture still resolves the patched tarball with a real yarn to pin
/// the exact cache-zip checksum) and the lock's tarball-URL locator +
/// `checksum: 10c0/<hex>` splice — and the fresh `yarn install --immutable
/// --check-cache` pulls the patched bytes from the hosted tarball. The uuid
/// identifier path is exempt from installed narrowing, so only the view +
/// reference mocks matter (the fixture mounts them anyway).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn berry_get_uuid_hosted_fresh_checkout_installs() {
    let Some(fx) = berry_hosted_project("get-uuid", false, HostedDriver::GetUuid).await else {
        return;
    };

    let (fresh, ci) = fresh_checkout_yarn_install(&fx);
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --immutable --check-cache` must succeed from the \
         hosted patch tarball (get-driven redirect).\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "yarn must install the PATCHED bytes from the hosted patch (get-driven); got:\n{}",
        String::from_utf8_lossy(&installed[..installed.len().min(120)])
    );
    assert_eq!(
        installed, fx.patched,
        "fresh install must be byte-identical to the patched content (get-driven)"
    );

    hosted_manifestless_vex_matrix(&fx, HostedDriver::GetUuid);
}

/// Negative twin: the hosted URL serves a DIFFERENT tarball while the lock
/// pins the real `10c0` checksum — the fresh `--check-cache` install must fail
/// with YN0018.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn berry_redirect_tampered_hosted_tarball_fails_check_cache() {
    let Some(fx) = berry_hosted_project("tampered", true, HostedDriver::Scan).await else {
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
