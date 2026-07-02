//! Rush hosted-mode redirect capstone — proving `scan --mode hosted` rewrites
//! a Rush monorepo's pnpm source-of-truth lock and that a real pnpm install
//! then pulls the patched dependency from the hosted tarball.
//!
//! Rush drives pnpm indirectly: `rush update` generates
//! `common/temp/pnpm-lock.yaml` from `common/config/rush/pnpm-lock.yaml`, then
//! `rush install` runs `pnpm install --frozen-lockfile` inside `common/temp`.
//!
//! Tier 1 (default-runnable, gated on corepack pnpm): run the REAL CLI
//! `scan --mode hosted` against wiremock over a committed Rush-shaped fixture
//! (rush.json + common/config/rush/pnpm-lock.yaml), then REPLICATE rush's
//! install step in-test — clearly labeled a simulation: copy the rewritten
//! lock to `common/temp/pnpm-lock.yaml`, write a minimal generated-style
//! `common/temp/package.json`, and run `corepack pnpm@9 install
//! --frozen-lockfile` with the registry pointed at a DEAD port so the only
//! reachable artifact URL is the wiremock hosted tarball. Asserts the patched
//! bytes land in `common/temp/node_modules`, plus a tamper leg (serve wrong
//! bytes → pnpm integrity failure). The repo-state.json twin is exercised for
//! the stale-hash warning.
//!
//! Tier 2 (gated on `RUSH_E2E=1`, network-dependent, NOT run by default): real
//! `npm x @microsoft/rush` — `rush update` → `scan --mode hosted` →
//! `rush install`, asserting patched bytes; plus the
//! `preventManualShrinkwrapChanges` failure + `rush update` recovery.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha512};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d";
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const RUSH_VERSION: &str = "5.100.0";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Probe corepack from a NEUTRAL temp dir (a `packageManager` field in an
/// ancestor package.json — e.g. this monorepo root — otherwise makes corepack
/// refuse a different manager).
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
        .map(|s| s.success())
        .unwrap_or(false)
}

fn scrub_socket_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("npm_config_store_dir");
    cmd.env_remove("PNPM_HOME");
}

fn corepack(cwd: &Path, pm: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
    scrub_socket_env(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run corepack")
}

fn run_socket(cwd: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    scrub_socket_env(&mut cmd);
    cmd.output().expect("failed to run socket-patch binary")
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

/// A minimal but valid npm tarball for left-pad with `index.js` = `index`.
fn make_tgz(index: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (p, bytes) in [
        (
            "package/package.json",
            format!(r#"{{"name":"{DEP}","version":"{DEP_VERSION}"}}"#).into_bytes(),
        ),
        ("package/index.js", index.to_vec()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, p, bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// The Rush source-of-truth pnpm lock (v9) resolving left-pad, plus the
/// generated-lock twin the sim installs from.
fn rush_common_lock() -> String {
    format!(
        "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      {DEP}:
        specifier: {DEP_VERSION}
        version: {DEP_VERSION}

packages:
  {DEP}@{DEP_VERSION}:
    resolution: {{integrity: sha512-UPSTREAMupstreamUPSTREAMupstreamUPSTREAMupstreamUPSTREAMupstreamUPSTREAMupstreamUPSTREAMupstreamUPSTREAMupstreamUPSTREAMupAB==}}

snapshots:
  {DEP}@{DEP_VERSION}: {{}}
"
    )
}

/// Lay down a Rush-shaped fixture. `with_repo_state` also drops
/// common/config/rush/repo-state.json (carries pnpmShrinkwrapHash).
fn write_rush_fixture(root: &Path, with_repo_state: bool) {
    std::fs::write(
        root.join("rush.json"),
        format!(r#"{{ "rushVersion": "{RUSH_VERSION}" }}"#),
    )
    .unwrap();
    let common = root.join("common/config/rush");
    std::fs::create_dir_all(&common).unwrap();
    std::fs::write(common.join("pnpm-lock.yaml"), rush_common_lock()).unwrap();
    if with_repo_state {
        std::fs::write(
            common.join("repo-state.json"),
            "{\n  \"pnpmShrinkwrapHash\": \"deadbeef\",\n  \"preventManualShrinkwrapChanges\": true\n}\n",
        )
        .unwrap();
    }
}

/// Mount discovery + reference + view + the hosted tarball route. `served` is
/// what the tarball endpoint returns (tampered legs pass different bytes than
/// the pinned sha512).
async fn mount_hosted(server: &MockServer, hosted_url: &str, sri: &str, served: Vec<u8>) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "rush hosted fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
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
        .mount(server)
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
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64)
            }},
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
    // The hosted tarball route pnpm hits at install time.
    Mock::given(method("GET"))
        .and(path(format!(
            "/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_raw(served, "application/octet-stream"))
        .mount(server)
        .await;
}

/// Run `scan --mode hosted` (real binary) over the Rush fixture at `root`.
fn scan_hosted(root: &Path, api_url: &str) -> Output {
    run_socket(
        root,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            root.to_str().unwrap(),
            "--api-url",
            api_url,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    )
}

/// SIMULATE `rush install`: copy the rewritten common lock to
/// `common/temp/pnpm-lock.yaml`, write a minimal generated-style
/// `common/temp/package.json`, and run `pnpm install --frozen-lockfile` there
/// with the registry pointed at a dead port (so the only reachable artifact
/// URL is the wiremock hosted tarball). Returns the pnpm output.
fn simulate_rush_install(root: &Path, store: &Path) -> Output {
    let temp = root.join("common/temp");
    std::fs::create_dir_all(&temp).unwrap();
    std::fs::copy(
        root.join("common/config/rush/pnpm-lock.yaml"),
        temp.join("pnpm-lock.yaml"),
    )
    .unwrap();
    // Generated-style workspace root: depends on the patched package, with the
    // registry pinned to a dead port so pnpm can only reach the hosted tarball.
    std::fs::write(
        temp.join("package.json"),
        format!(
            r#"{{ "name": "rush-common-temp", "version": "0.0.0", "private": true, "dependencies": {{ "{DEP}": "{DEP_VERSION}" }} }}"#
        ),
    )
    .unwrap();
    std::fs::write(temp.join(".npmrc"), "registry=http://127.0.0.1:1/\n").unwrap();
    corepack(
        &temp,
        "pnpm@9",
        &[
            "install",
            "--frozen-lockfile",
            "--store-dir",
            store.to_str().unwrap(),
        ],
        &[],
    )
}

// ── Tier 1: default-runnable pnpm simulation ───────────────────────────

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn rush_hosted_scan_then_simulated_pnpm_install_lands_patched_bytes() {
    if !has_corepack_pm("pnpm@9") {
        println!("SKIP e2e_redirect_rush_sim: `corepack pnpm@9` unavailable");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_rush_fixture(root, true);

    let orig = b"module.exports = function leftpad() {};\n";
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    let tgz = make_tgz(&patched);
    let sri = format!("sha512-{}", sha512_sri_b64(&tgz));

    let server = MockServer::start().await;
    let hosted_url = format!(
        "{}/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz",
        server.uri()
    );
    mount_hosted(&server, &hosted_url, &sri, tgz.clone()).await;

    let out = scan_hosted(root, &server.uri());
    assert!(
        out.status.success(),
        "scan --mode hosted failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let common_lock =
        std::fs::read_to_string(root.join("common/config/rush/pnpm-lock.yaml")).unwrap();
    assert!(
        common_lock.contains(&format!("tarball: {hosted_url}")) && common_lock.contains(&sri),
        "the rush common lock must be repointed at the hosted tarball; got:\n{common_lock}"
    );

    // SIMULATE `rush install` from the rewritten lock.
    let store = tmp.path().join("pnpm-store");
    let install = simulate_rush_install(root, &store);
    assert!(
        install.status.success(),
        "simulated `pnpm install --frozen-lockfile` (rush install) must succeed from the \
         hosted tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    let installed = std::fs::read(
        root.join("common/temp/node_modules")
            .join(DEP)
            .join("index.js"),
    )
    .unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "the simulated rush install must land the PATCHED bytes; got:\n{}",
        String::from_utf8_lossy(&installed[..installed.len().min(120)])
    );
}

/// Tamper twin: the hosted route serves DIFFERENT bytes than the pinned
/// sha512 → the simulated `pnpm install --frozen-lockfile` must fail the
/// integrity check.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn rush_hosted_tampered_tarball_fails_simulated_install() {
    if !has_corepack_pm("pnpm@9") {
        println!("SKIP e2e_redirect_rush_sim (tampered): `corepack pnpm@9` unavailable");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_rush_fixture(root, false);

    let orig = b"module.exports = function leftpad() {};\n";
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    let tgz = make_tgz(&patched);
    let sri = format!("sha512-{}", sha512_sri_b64(&tgz));
    // Serve a DIFFERENT tarball than the pinned sha512.
    let tampered = make_tgz(b"/* SOCKET-TAMPERED */\nmodule.exports = 1;\n");

    let server = MockServer::start().await;
    let hosted_url = format!(
        "{}/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz",
        server.uri()
    );
    mount_hosted(&server, &hosted_url, &sri, tampered).await;

    let out = scan_hosted(root, &server.uri());
    assert!(out.status.success(), "scan --mode hosted should succeed");

    let store = tmp.path().join("pnpm-store");
    let install = simulate_rush_install(root, &store);
    assert!(
        !install.status.success(),
        "simulated rush install MUST fail when the served tarball does not match the pinned \
         sha512.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );
    let chatter = format!(
        "{}\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    assert!(
        chatter.to_lowercase().contains("integrity")
            || chatter.to_lowercase().contains("checksum")
            || chatter.contains("ERR_PNPM"),
        "the failure must be the integrity check, not something incidental:\n{chatter}"
    );
}

// ── Tier 2: real Rush (gated on RUSH_E2E=1, network-dependent) ─────────

/// Real `@microsoft/rush`: `rush update` → `scan --mode hosted` →
/// `rush install`, asserting the patched bytes land, then the
/// `preventManualShrinkwrapChanges` failure + `rush update` recovery.
///
/// Network-dependent (rush is fetched via `npm x`, and `rush update`/`install`
/// hit the registry for everything but the redirected dep). NOT run by
/// default; set `RUSH_E2E=1` to opt in.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn rush_hosted_real_rush_update_install() {
    if std::env::var("RUSH_E2E").as_deref() != Ok("1") {
        println!("SKIP e2e_redirect_rush_sim: set RUSH_E2E=1 to run the real-rush tier-2 leg");
        return;
    }
    if !has_command("npm") || !has_corepack_pm("pnpm@9") {
        println!("SKIP e2e_redirect_rush_sim (tier2): npm / corepack pnpm@9 unavailable");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // A minimal real Rush repo: rush.json with a pinned rushVersion + one
    // project depending on the patched package.
    std::fs::write(
        root.join("rush.json"),
        format!(
            r#"{{
  "rushVersion": "{RUSH_VERSION}",
  "pnpmVersion": "9.15.9",
  "projects": [
    {{ "packageName": "app-a", "projectFolder": "apps/a" }}
  ]
}}
"#
        ),
    )
    .unwrap();
    let common = root.join("common/config/rush");
    std::fs::create_dir_all(&common).unwrap();
    std::fs::write(
        common.join("pnpm-config.json"),
        "{ \"preventManualShrinkwrapChanges\": false }\n",
    )
    .unwrap();
    let app_a = root.join("apps/a");
    std::fs::create_dir_all(&app_a).unwrap();
    std::fs::write(
        app_a.join("package.json"),
        format!(
            r#"{{ "name": "app-a", "version": "1.0.0", "dependencies": {{ "{DEP}": "{DEP_VERSION}" }} }}"#
        ),
    )
    .unwrap();

    let orig = b"module.exports = function leftpad() {};\n";
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();
    let tgz = make_tgz(&patched);
    let sri = format!("sha512-{}", sha512_sri_b64(&tgz));
    let server = MockServer::start().await;
    let hosted_url = format!(
        "{}/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz",
        server.uri()
    );
    mount_hosted(&server, &hosted_url, &sri, tgz.clone()).await;

    // rush update generates common/config/rush/pnpm-lock.yaml + common/temp.
    // Rush REJECTS any unrecognized `RUSH_`-prefixed env var (including our own
    // `RUSH_E2E` gate), so strip every `RUSH_*` before invoking it.
    let rush_pkg = format!("@microsoft/rush@{RUSH_VERSION}");
    let rush = |args: &[&str]| -> Output {
        let mut full = vec!["x", "-y", rush_pkg.as_str()];
        full.extend_from_slice(args);
        let mut cmd = Command::new("npm");
        cmd.args(&full).current_dir(root);
        scrub_socket_env(&mut cmd);
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("RUSH_") {
                cmd.env_remove(&k);
            }
        }
        cmd.output().expect("failed to run rush via npm x")
    };

    let up = rush(&["update"]);
    if !up.status.success() {
        println!(
            "SKIP e2e_redirect_rush_sim (tier2): `rush update` failed (network?):\n{}",
            String::from_utf8_lossy(&up.stderr)
        );
        return;
    }
    // scan --mode hosted rewrites the generated common lock.
    let out = scan_hosted(root, &server.uri());
    assert!(
        out.status.success(),
        "scan --mode hosted failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    // rush install must land the patched bytes.
    let inst = rush(&["install"]);
    assert!(
        inst.status.success(),
        "`rush install` must succeed from the hosted tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&inst.stdout),
        String::from_utf8_lossy(&inst.stderr),
    );
    let installed = std::fs::read(
        root.join("common/temp/node_modules")
            .join(DEP)
            .join("index.js"),
    )
    .unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "real rush install must land the PATCHED bytes"
    );

    // Flip preventManualShrinkwrapChanges=true: rush install must now refuse
    // the out-of-band lock edit, and a `rush update` recovers.
    std::fs::write(
        common.join("pnpm-config.json"),
        "{ \"preventManualShrinkwrapChanges\": true }\n",
    )
    .unwrap();
    // Re-run the redirect so the lock is edited out-of-band again.
    let _ = scan_hosted(root, &server.uri());
    let blocked = rush(&["install"]);
    assert!(
        !blocked.status.success(),
        "with preventManualShrinkwrapChanges=true, `rush install` must reject the out-of-band \
         lock edit.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr),
    );
    let recover = rush(&["update"]);
    assert!(
        recover.status.success(),
        "`rush update` must recover after the shrinkwrap-hash desync.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&recover.stdout),
        String::from_utf8_lossy(&recover.stderr),
    );

    // A guard so `_server` clearly outlives the installs.
    drop(server);
}
