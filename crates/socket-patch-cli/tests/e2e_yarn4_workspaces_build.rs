//! Real-yarn-berry WORKSPACES capstones — hosted redirect + vendored wiring
//! for a yarn 4 monorepo (nodeLinker: node-modules), where the patched
//! dependency belongs to a workspace MEMBER, not the root.
//!
//! The single-package flavors are pinned by `e2e_redirect_yarn_berry_build.rs`
//! and `e2e_vendor_yarn_berry_build.rs`; the 36-cell yarn matrix sweep
//! (2026-08-18, real production data) proved the workspace flavor also works
//! end-to-end — a scan from the ROOT rewires the member's dep in the single
//! root `yarn.lock`, and a fresh `--immutable --check-cache` install serves
//! the patched bytes — but nothing pinned it. Workspaces are the layout most
//! real berry repos use, so a regression here (e.g. member deps skipped
//! because discovery or the rewriter only considers root dependencies) would
//! ship unseen.
//!
//! Fixture: root (`ws-root`, no dependencies of its own) + `packages/app`
//! depending on left-pad@1.3.0. Both capstones drive the REAL
//! `corepack yarn@4.12.0` (network for fixture setup only) and prove:
//!
//!   * hosted — `scan --mode hosted` from the root rewires the member's
//!     `left-pad@npm:1.3.0` lock entry to the hosted `__archiveUrl` + `10c0`
//!     checksum (bootstrap-resolution trick, see the redirect sibling)
//!     without touching either package.json; a fresh checkout of only the
//!     committable files installs the patched bytes offline-from-registry,
//!     and the member resolves them through `yarn node`.
//!   * vendored — `vendor --offline` wires the ROOT package.json
//!     `resolutions` + the root lock `file:` locator (member package.json
//!     byte-identical); fresh `--immutable --check-cache` installs the
//!     patched bytes, the member resolves them, and `--revert` restores
//!     root package.json AND yarn.lock byte-for-byte.
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
const UUID: &str = "4d5e6f7a-8b9c-4d4e-8f5a-3456789abcde";
const TOKEN: &str = "44444444-4444-4444-8444-444444444444";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const CVE: &str = "CVE-2026-3333";
const GHSA: &str = "GHSA-yarn4-workspaces";
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
    // `YARN_NODE_LINKER=pnp` outranks the project yarnrc and would build a
    // PnP tree with no node_modules; the seed keeps the scrub honest.
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
    yarn_berry_common::pin_berry_ci_defaults(&mut cmd);
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

/// Write the workspace fixture: root (no deps) + packages/app (left-pad).
fn write_workspace_fixture(proj: &Path) {
    std::fs::create_dir_all(proj.join("packages/app")).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"ws-root","version":"0.0.0","private":true,"workspaces":["packages/app"]}"#,
    )
    .unwrap();
    std::fs::write(
        proj.join("packages/app/package.json"),
        format!(r#"{{"name":"app","version":"1.0.0","dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#),
    )
    .unwrap();
    std::fs::write(
        proj.join(".yarnrc.yml"),
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
    )
    .unwrap();
}

/// MEMBER RESOLUTION PROOF: from the workspace member's directory, `yarn
/// node` must resolve the dep to the PATCHED bytes.
fn assert_member_resolves_patched(root: &Path, patched: &[u8]) {
    let member = root.join("packages/app");
    let out = corepack(
        &member,
        yarn_berry(),
        &["node", "-p", &format!("require.resolve('{DEP}')")],
        &[],
    );
    assert!(
        out.status.success(),
        "`yarn node` from the member must succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let resolved = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let bytes = std::fs::read(&resolved)
        .unwrap_or_else(|e| panic!("cannot read member-resolved path {resolved}: {e}"));
    assert!(
        bytes.starts_with(MARKER.as_bytes()),
        "the member must resolve the PATCHED bytes (via {resolved}); got:\n{}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(120)])
    );
    assert_eq!(
        bytes, patched,
        "member-resolved bytes must be byte-identical to the patched content"
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
            "vulnerabilities": { GHSA: {
                "cves": [CVE], "summary": "capstone vuln",
                "severity": "high", "description": "d",
            }},
            "description": "workspaces capstone marker patch",
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
/// pointing at `file:./patched.tgz`) to extract the exact `10c0/<hex>`
/// checksum yarn computes for that tarball's cache zip (see the redirect
/// sibling's module docs). `None` = skip (message printed).
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
            "SKIP e2e_yarn4_workspaces_build: bootstrap yarn install failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return None;
    }
    let lock = std::fs::read_to_string(boot.join("yarn.lock")).ok()?;
    // yarn 4.0.x writes the bare hex, 4.1+ `10c0/<hex>`: the API form is the
    // prefixed one. A lock with neither is a harness failure, never a
    // silent pass (the old `?` here returned before any assertion ran).
    let checksum = yarn_berry_common::yarn_written_checksum(&lock);
    if checksum.is_none() {
        skip!(
            "SKIP: bootstrap `{} install` wrote no 10c0 cache checksum:\n{lock}",
            yarn_berry()
        );
    }
    checksum
}

/// Install the workspace fixture with the real yarn; `None` = skip printed.
fn install_workspace_fixture(tag: &str, tmp: &Path, proj: &Path) -> Option<Vec<u8>> {
    write_workspace_fixture(proj);
    let global = tmp.join("yarn-global");
    let install = corepack(
        proj,
        yarn_berry(),
        &["install"],
        &[("YARN_GLOBAL_FOLDER", global.to_str().unwrap())],
    );
    if !install.status.success() {
        skip!(
            "SKIP e2e_yarn4_workspaces_build ({tag}): fixture `yarn install` failed \
             (registry unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return None;
    }
    // The member's dep hoists to the ROOT node_modules — the single-lock,
    // single-store berry layout this capstone exists to pin.
    let orig = std::fs::read(proj.join("node_modules").join(DEP).join("index.js"))
        .expect("installed index.js (hoisted to root node_modules)");
    assert!(
        !orig.starts_with(MARKER.as_bytes()),
        "({tag}) pristine install must not carry the marker"
    );
    Some(orig)
}

/// Fresh dir with only the committable files (root + member package.json,
/// yarn.lock, the given .yarnrc.yml body, .socket/), then `yarn install
/// --immutable --check-cache` with an empty global cache.
fn fresh_checkout_install(tmp: &Path, proj: &Path, yarnrc: &str) -> (PathBuf, Output) {
    let fresh = tmp.join("fresh");
    std::fs::create_dir_all(fresh.join("packages/app")).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(
        proj.join("packages/app/package.json"),
        fresh.join("packages/app/package.json"),
    )
    .unwrap();
    std::fs::copy(proj.join("yarn.lock"), fresh.join("yarn.lock")).unwrap();
    std::fs::write(fresh.join(".yarnrc.yml"), yarnrc).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));
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
async fn yarn4_workspaces_hosted_redirect_rewires_member_dep_from_root_scan() {
    if !has_corepack_pm(yarn_berry()) {
        skip!(
            "SKIP e2e_yarn4_workspaces_build (hosted): `corepack {}` unavailable",
            yarn_berry()
        );
        return;
    }
    if !has_command("tar") {
        skip!("SKIP e2e_yarn4_workspaces_build (hosted): `tar` not installed");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let Some(orig) = install_workspace_fixture("hosted", tmp.path(), &proj) else {
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
                    "title": "workspaces hosted capstone fixture"
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
                    "cves": [CVE], "summary": "workspaces capstone vuln",
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

    let root_pkg_before = std::fs::read(proj.join("package.json")).unwrap();
    let member_pkg_before = std::fs::read(proj.join("packages/app/package.json")).unwrap();

    // scan --mode hosted from the WORKSPACE ROOT.
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
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "the member's dep must be redirected from a root scan: {env}"
    );

    // The single root lock carries the member dep's hosted pin; the
    // workspace entries stay workspace-resolved and no package.json moved.
    let lock = std::fs::read_to_string(proj.join("yarn.lock")).unwrap();
    let encoded = socket_patch_core::utils::uri::encode_uri_component(&hosted_url);
    assert!(
        lock.contains("::__archiveUrl=") && lock.contains(&encoded),
        "yarn.lock must carry the encoded __archiveUrl; got:\n{lock}"
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
    assert!(
        lock.contains("\"app@workspace:packages/app\""),
        "the workspace member entry must stay workspace-resolved:\n{lock}"
    );
    assert_eq!(
        std::fs::read(proj.join("package.json")).unwrap(),
        root_pkg_before,
        "hosted redirect must not touch the root package.json"
    );
    assert_eq!(
        std::fs::read(proj.join("packages/app/package.json")).unwrap(),
        member_pkg_before,
        "hosted redirect must not touch the member package.json"
    );
    eprintln!("HOSTED REWIRE OK");

    // FRESH-CHECKOUT PROOF: committable files only, offline from the
    // registry (poisoned npmRegistryServer, wiremock host whitelisted).
    let yarnrc = format!(
        "nodeLinker: node-modules\nenableGlobalCache: false\n\
         unsafeHttpWhitelist:\n  - \"{}\"\n\
         npmRegistryServer: \"http://127.0.0.1:1\"\n",
        host.split(':').next().unwrap_or("127.0.0.1")
    );
    let (fresh, ci) = fresh_checkout_install(tmp.path(), &proj, &yarnrc);
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --immutable --check-cache` must succeed from the \
         hosted patch tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert_eq!(
        installed, patched,
        "fresh install must be byte-identical to the patched content"
    );
    assert_member_resolves_patched(&fresh, &patched);
    eprintln!("FRESH INSTALL + MEMBER RESOLUTION OK");

    // MANIFEST-LESS VEX over the hosted wiring (see `yarn_berry_common`).
    let registry_state = [("yarn.lock", registry_lock)];
    let yarn =
        |cwd: &Path, args: &[&str], env: &[(&str, &str)]| corepack(cwd, yarn_berry(), args, env);
    let api_url = server.uri();
    let flow = yarn_berry_common::BerryVexFlow {
        yarn_spec: yarn_berry(),
        flow: "workspaces",
        wiring: yarn_berry_common::BerryWiring::Hosted {
            patch_server: api_url.clone(),
        },
        proj: &proj,
        scratch: tmp.path(),
        committable: &["package.json", "packages/app/package.json", "yarn.lock"],
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
fn yarn4_workspaces_vendor_wires_root_and_member_installs_patched_bytes() {
    if !has_corepack_pm(yarn_berry()) {
        skip!(
            "SKIP e2e_yarn4_workspaces_build (vendored): `corepack {}` unavailable",
            yarn_berry()
        );
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let Some(orig) = install_workspace_fixture("vendored", tmp.path(), &proj) else {
        return;
    };
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    stage_patch(&proj, PURL, &orig, &patched);

    // Committable baseline AFTER install (berry pretty-prints package.json).
    let lock_path = proj.join("yarn.lock");
    let root_pkg_path = proj.join("package.json");
    let member_pkg_path = proj.join("packages/app/package.json");
    let lock_before = std::fs::read(&lock_path).unwrap();
    let root_pkg_before = std::fs::read(&root_pkg_path).unwrap();
    let member_pkg_before = std::fs::read(&member_pkg_path).unwrap();

    // Vendor (offline) from the WORKSPACE ROOT.
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
    assert_eq!(
        env["summary"]["applied"], 1,
        "the member's dep must be vendored: {env}"
    );
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");

    let tgz_rel = format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}.tgz");
    assert!(
        proj.join(&tgz_rel).is_file(),
        "vendored tarball missing at {tgz_rel}"
    );

    // The `resolutions` wiring lands on the ROOT package.json (the only
    // place berry honors it); the member package.json stays byte-identical.
    let root_pkg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&root_pkg_path).unwrap()).unwrap();
    assert_eq!(
        root_pkg["resolutions"][DEP].as_str(),
        Some(format!("file:./{tgz_rel}").as_str()),
        "ROOT package.json must gain the resolutions entry: {root_pkg}"
    );
    assert_eq!(
        std::fs::read(&member_pkg_path).unwrap(),
        member_pkg_before,
        "the member package.json must stay byte-identical"
    );
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock_after.contains(&format!("left-pad@file:./{tgz_rel}::locator=")),
        "yarn.lock must carry the file: locator entry; got:\n{lock_after}"
    );
    assert!(
        lock_after.contains("\"app@workspace:packages/app\""),
        "the workspace member entry must stay workspace-resolved:\n{lock_after}"
    );
    eprintln!("VENDOR OK");

    // FRESH-CHECKOUT PROOF + member resolution.
    let (fresh, ci) = fresh_checkout_install(
        tmp.path(),
        &proj,
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
    );
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --immutable --check-cache` must succeed from the \
         vendored tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let fresh_installed =
        std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert_eq!(
        fresh_installed, patched,
        "fresh install must be byte-identical to the patched content"
    );
    assert_member_resolves_patched(&fresh, &patched);
    eprintln!("FRESH INSTALL + MEMBER RESOLUTION OK");

    // MANIFEST-LESS VEX over the vendored wiring (see `yarn_berry_common`),
    // BEFORE the revert below consumes the project's wiring.
    let registry_state = [
        ("yarn.lock", lock_before.clone()),
        ("package.json", root_pkg_before.clone()),
    ];
    let yarn =
        |cwd: &Path, args: &[&str], env: &[(&str, &str)]| corepack(cwd, yarn_berry(), args, env);
    let flow = yarn_berry_common::BerryVexFlow {
        yarn_spec: yarn_berry(),
        flow: "workspaces",
        wiring: yarn_berry_common::BerryWiring::Vendored {
            artifact_rel: tgz_rel.clone(),
        },
        proj: &proj,
        scratch: tmp.path(),
        committable: &["package.json", "packages/app/package.json", "yarn.lock"],
        yarnrc: "nodeLinker: node-modules\nenableGlobalCache: false\n",
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

    // REVERT PROOF: root package.json AND yarn.lock restored byte-for-byte,
    // vendor artifacts gone, member untouched throughout.
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
        std::fs::read(&root_pkg_path).unwrap(),
        root_pkg_before,
        "revert must restore the root package.json byte-identical"
    );
    assert_eq!(
        std::fs::read(&member_pkg_path).unwrap(),
        member_pkg_before,
        "the member package.json must stay byte-identical through revert"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
    eprintln!("REVERT OK");
}
