//! Real-install redirect capstone e2e for pnpm — the pnpm counterpart of
//! `tests/e2e_redirect_npm_build.rs`.
//!
//! `scan --mode hosted` never lands patched bytes in the repo: it splices the
//! patched package's `resolution:` in pnpm-lock.yaml to `{integrity:
//! <patched sha512>, tarball: <hosted url>}` (a wiremock standing in for
//! patch.socket.dev) and writes nothing else but the pnpm >=11 trust setting
//! (v5: no redirect ledger; the lock IS the hosted state). The corepack legs
//! prove every link of that chain against the REAL pnpm:
//!
//!   1. `corepack pnpm@<major> install left-pad@1.3.0` into a tempdir project
//!      (network used for fixture setup only, private `--store-dir`).
//!   2. Build a PATCHED tarball from the actually-installed bytes (marker
//!      comment prepended to `index.js`) and serve it from wiremock, alongside
//!      the discovery / reference / view API mocks.
//!   3. `scan --mode hosted --json --yes` (the real binary): the lock's
//!      `resolution:` now pins the wiremock tarball URL + the patched
//!      tarball's sha512, no ledger is written, and a second scan is
//!      idempotent (lock and workspace file byte-stable).
//!   4. FRESH-CHECKOUT PROOF: only package.json + pnpm-lock.yaml (+ `.socket/`
//!      when present) travel, the `.npmrc` registry points at a DEAD port, the store is
//!      empty — `pnpm install --frozen-lockfile` MUST land the marker bytes,
//!      because the only reachable artifact URL is the hosted tarball.
//!
//! The tamper twin serves DIFFERENT bytes under the honest sha512 pin: the
//! fresh install must FAIL on the integrity check — the lockfile pin is
//! enforcement, not decoration.
//!
//! The required CI matrix provisions exact pnpm versions across majors 1–12
//! and runs `pnpm_pinned_matrix_*` with setup failures treated as failures.
//! It covers warm-cache verification, clean reinstall, fresh frozen install,
//! ordinary install, lock-only discovery, rollback and tamper rejection. A
//! second fixture covers scoped aliases and peer variants in workspaces on
//! pnpm >=6. The older named corepack capstones remain opt-in conveniences.
//!
//! MANIFEST-LESS VEX: every positive leg (matrix and named) ends in
//! `assert_manifestless_hosted_vex` over its real fresh install — the
//! ledger record, then the lockfile alone + the patch API record, then
//! `--offline` (`record_unavailable`, zero requests), then embedded
//! `scan --mode hosted --vex`, then the lock reverted with the ledger kept
//! (`redirect_unwired`, `--no-verify` too). The hermetic evidence edges
//! (tampered / pristine installs, spoofed hosts, record mismatches) live in
//! `e2e_vex_lockfile/pnpm.rs`.
//!
//! TRUST AUTO-CONFIG: a scan that rewrites a ROOT v9 lock also ensures
//! `trustLockfile: true` in pnpm-workspace.yaml (the workspace file joins
//! `rewrittenFiles`), because pnpm >=11's lockfile supply-chain policy
//! rejects the rewritten lock otherwise. Legacy locks need no trust setting
//! or flag. The auto-config gate is lock-major >=9. Two
//! pnpm@11 legs pin both sides empirically: the ZERO-TOUCH leg commits the
//! scan-written workspace file and the plain dead-registry frozen install
//! succeeds with NO flags; the `--no-trust-lockfile-config` control pins the
//! opt-out (no workspace write) plus the old behavior it restores — the
//! plain frozen install fails against a dead registry
//! (ERR_PNPM_META_FETCH_FAIL there — ERR_PNPM_TARBALL_URL_MISMATCH needs
//! reachable registry metadata) and the manual `--trust-lockfile` flag
//! recovers.
//!
//! THE REGISTRY ROUTE: when every grant carries a registry address and the
//! project's pnpm pins prove pnpm >= 11.20, the scan routes each patched
//! package through the named registry of its patch (`namedRegistries` plus
//! `overrides` in pnpm-workspace.yaml, and the lock in the shape pnpm
//! writes for them) instead of trusting the lock. The pnpm@12 and pnpm@11
//! legs prove it against the real pnpm with no network beyond two loopback
//! servers: pnpm re-locks the scan's files without changing a byte, a
//! fresh checkout frozen-installs the patched bytes with lockfile
//! verification on, `pnpm add` / `update` / `dedupe` keep a peer-dependent
//! hosted package, and after each cleanup (a rollback of one package, a
//! re-scan, the fall back to `trustLockfile`, a full rollback) the
//! workspace file and the lock still agree, which a frozen install proves.
//!
//! Two synthetic legs need no pnpm at all (hermetic wiremock, never ignored),
//! pinning the rewrite grammar against byte-accurate locks captured from the
//! 2026-08-18 pnpm matrix sweep: a v5.4 lock (`/name/version:` key) and a v6
//! plain key (`/name@version:`) each splice in place with sibling lines
//! byte-preserved.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[allow(clippy::duplicate_mod)]
#[path = "common/fs_tree.rs"]
mod fs_tree;

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
use vex_e2e_common::{
    assert_absent, assert_attested, assert_not_attested, installed_pnpm_pre_10_5, patch_view,
    run_vex, strip_ledgers, strip_manifest, Marker, PatchApi, VexRun, VexVia,
};

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
/// Canonical lowercase patch uuid (a dedicated path level of the hosted URL).
const UUID: &str = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d";
/// Access-token uuid segment of the hosted download URL (opaque to the CLI —
/// it just writes the URL the reference endpoint hands back).
const TOKEN: &str = "22222222-2222-4222-8222-222222222222";
/// Marker prepended to the dep's entry point by the synthetic patch.
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const GHSA: &str = "GHSA-redirect-pnpm";
/// Pinned pnpm majors via corepack. Locally a leg whose major corepack can't
/// provide skips; under `SOCKET_PATCH_PNPM_E2E_REQUIRED` (the Linux CI row)
/// every leg is required. @7 and @8 are the legacy-lock legs: they emit
/// lockfileVersion 5.4 / 6.0, proving the v5/v6 rewrite installs for real.
const PNPM_PRIMARY: &str = "pnpm@10";
const PNPM_SECONDARY: &str = "pnpm@9";
const PNPM_TERTIARY: &str = "pnpm@11";
/// The first major hosted mode declares named registries for.
const PNPM_NAMED_REGISTRY: &str = "pnpm@12";
const PNPM_LEGACY_V5: &str = "pnpm@7";
const PNPM_LEGACY_V6: &str = "pnpm@8";
/// left-pad@1.3.0's registry integrity, byte-accurate from the matrix legs'
/// pnpm-emitted locks — the synthetic legs' pristine `resolution:` value.
const UPSTREAM_SHA512: &str = "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==";
/// Synthetic patched integrity for the no-install legs (nothing downloads it,
/// so it only has to be distinct from the upstream value).
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";

// ── self-contained helpers ────────────────────────────────────────────

fn socket_bin() -> PathBuf {
    std::env::var_os("SOCKET_PATCH_PNPM_E2E_SOCKET_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_socket-patch")))
}

/// Probe corepack from a NEUTRAL temp dir (a `packageManager` field in an
/// ancestor package.json — e.g. this monorepo root — otherwise makes corepack
/// refuse a different manager).
fn pnpm_command(pm: &str) -> Command {
    if let Some(bin) = std::env::var_os("SOCKET_PATCH_PNPM_E2E_BIN") {
        Command::new(bin)
    } else {
        let mut cmd = hermetic::tool_command("corepack");
        cmd.arg(pm);
        cmd
    }
}

/// Set by every CI leg that runs this suite: a missing toolchain or a
/// failed fixture install is then a failure, never a skip. The workflow
/// passes an EMPTY value on legs that run other suites, so empty = unset.
fn pnpm_required() -> bool {
    std::env::var_os("SOCKET_PATCH_PNPM_E2E_REQUIRED").is_some_and(|v| !v.is_empty())
}

fn has_corepack_pm(pm: &str) -> bool {
    let probe = tempfile::tempdir().unwrap();
    let mut cmd = pnpm_command(pm);
    cmd.arg("--version").current_dir(probe.path());
    cache_env::isolate(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    let output = cmd.output();
    let ok = output.as_ref().is_ok_and(|o| o.status.success());
    if pnpm_required() {
        assert!(ok, "required pnpm toolchain unavailable: {output:?}");
        if let Ok(output) = output {
            // An exact pin (the pinned matrix) must match exactly; a bare
            // major (`pnpm@10`, the e2e legs) must resolve inside it.
            let got = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let want = pm.strip_prefix("pnpm@").unwrap();
            assert!(
                got == want || got.starts_with(&format!("{want}.")),
                "matrix must run the pinned version: want {want}, got {got}"
            );
        }
    }
    ok
}

/// `dir` as the operating system spells it: every link resolved and, on
/// Windows, every 8.3 short name expanded, without the verbatim `\\?\`
/// prefix `canonicalize` adds there. A directory that cannot be resolved
/// is returned as given, so a child started in it fails as it would have.
fn os_spelling(dir: &Path) -> PathBuf {
    std::fs::canonicalize(dir).map_or_else(
        |_| dir.to_path_buf(),
        socket_patch_core::utils::pnpm_workspace::without_verbatim_prefix,
    )
}

fn corepack(cwd: &Path, pm: &str, args: &[&str]) -> Output {
    corepack_with_retries(cwd, pm, args, false)
}

/// [`corepack`], except that an `install` keeps pnpm's own fetch retries
/// when `registry_retries` is set. Every other install clamps them so the
/// negative legs fail fast against the dead port or the tampered wiremock
/// tarball; the fixture install is the one step that reaches
/// registry.npmjs.org, where a clamp turned a single `read ECONNRESET`
/// into a failed required leg.
fn corepack_with_retries(cwd: &Path, pm: &str, args: &[&str], registry_retries: bool) -> Output {
    corepack_command(cwd, pm, args, registry_retries)
        .output()
        .expect("failed to run corepack")
}

/// The command [`corepack_with_retries`] runs, for a caller that adds
/// environment after the hermetic scrub.
fn corepack_command(cwd: &Path, pm: &str, args: &[&str], registry_retries: bool) -> Command {
    let mut cmd = pnpm_command(pm);
    let legacy = pm
        .strip_prefix("pnpm@")
        .and_then(|v| v.split('.').next())
        .and_then(|v| v.parse::<u32>().ok())
        .is_some_and(|major| major <= 4);
    // pnpm <=4 accepts `store`; 1–3 silently ignore `store-dir` and early 4
    // rejects it. Ignoring the option lets a warm store fake cold coverage.
    let args: Vec<String> = args
        .iter()
        .map(|arg| {
            if legacy {
                arg.replacen("--store-dir=", "--store=", 1)
            } else {
                arg.to_string()
            }
        })
        .collect();
    // pnpm gets its working directory in the operating system's spelling.
    // pnpm 11 keeps the project directory as the process was given it and
    // resolves the workspace root (the directory of a pnpm-workspace.yaml,
    // where the lock is) through the operating system. The temp directory
    // of a hosted Windows runner is under an 8.3 short name
    // (`C:\Users\RUNNER~1\...`), so the two spelled one directory
    // differently: `pnpm remove` and `pnpm add` then recorded the project
    // as a second importer (`../../RUNNER~1/.../proj`) and left the root
    // importer `.`, with the dependency they were to change, as it was.
    cmd.args(&args).current_dir(os_spelling(cwd));
    if !registry_retries
        && args.first().is_some_and(|arg| arg == "install")
        && pm
            .strip_prefix("pnpm@")
            .and_then(|v| v.split('.').next())
            .and_then(|v| v.parse::<u32>().ok())
            .is_some_and(|major| (6..=11).contains(&major))
    {
        cmd.args([
            "--fetch-retries=0",
            "--fetch-retry-mintimeout=100",
            "--fetch-retry-maxtimeout=500",
        ]);
    }
    hermetic::scrub_socket_vars(&mut cmd);
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv, hermetic::Extra::Pnpm]);
    // After the scrub: it strips ambient `PNPM_*` / `npm_config_*`, which
    // would otherwise take the sandbox values back out again.
    cache_env::isolate(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    cmd
}

fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    run_socket_env(cwd, args, &[])
}

/// [`run_socket`] with extra env applied after the scrub.
fn run_socket_env(cwd: &Path, args: &[&str], env: &[(String, String)]) -> (i32, String, String) {
    let mut cmd = hermetic::command(&socket_bin());
    cmd.args(args).current_dir(cwd);
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv, hermetic::Extra::Pnpm]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Which CLI front door drives the hosted engine. Both consume the SAME
/// engine by construction (v4.0): `scan --mode hosted` discovers the dep,
/// while `get <uuid> --mode hosted` names the patch explicitly (the uuid
/// identifier path is exempt from installed narrowing and needs no
/// discovery mocks beyond view + reference, which the fixture mounts
/// anyway).
#[derive(Clone, Copy, PartialEq, Debug)]
enum HostedDriver {
    Scan,
    GetUuid,
}

/// `scan --mode hosted` / `get <uuid> --mode hosted` (the real binary) over
/// the project at `root`, per `driver`. `extra_args` rides at the end (e.g.
/// `--no-trust-lockfile-config` — a global flag both subcommands accept).
fn run_hosted(
    driver: HostedDriver,
    root: &Path,
    api_url: &str,
    extra_args: &[&str],
) -> (i32, String, String) {
    let mut args = match driver {
        HostedDriver::Scan => vec!["scan"],
        HostedDriver::GetUuid => vec!["get", UUID],
    };
    args.extend_from_slice(&[
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
    ]);
    args.extend_from_slice(extra_args);
    run_socket(root, &args)
}

fn parse_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| {
        panic!("scan --mode hosted --json output is not JSON: {e}\nstdout:\n{stdout}")
    })
}

fn warning_codes(env: &serde_json::Value) -> Vec<String> {
    env["warnings"]
        .as_array()
        .map(|ws| {
            ws.iter()
                .map(|w| w["code"].as_str().unwrap_or("").to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Standard-base64-encoded sha512 of `bytes` — the body of the npm-family
/// `sha512-…` SRI integrity string.
fn sha512_sri_b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
}

fn hosted_url_for(base: &str) -> String {
    format!("{base}/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz")
}

/// A patched npm tarball built from the ACTUALLY-installed package: every
/// installed file travels under the `package/` prefix, with the entry point
/// swapped for `patched_index`. Built with the tar crate rather than a system
/// `tar` so the suite has no external-binary dependency (pnpm installs from
/// tar-crate output fine — `e2e_redirect_rush_sim.rs` proved it).
fn make_tgz_from_installed(pkg_dir: &Path, patched_index: &[u8]) -> Vec<u8> {
    // node_modules/<dep> is a symlink into .pnpm under pnpm's layout, and a
    // symlinked dir must be walked through its real path.
    let pkg_dir = pkg_dir
        .canonicalize()
        .expect("installed package dir must resolve");
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack = vec![pkg_dir.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                files.push(p);
            }
        }
    }
    files.sort();
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for p in &files {
        let rel = p.strip_prefix(&pkg_dir).unwrap();
        // Tar entry names always use `/` regardless of host separator.
        let name = format!(
            "package/{}",
            rel.components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
        );
        let bytes = if rel == Path::new("index.js") {
            patched_index.to_vec()
        } else {
            std::fs::read(p).unwrap()
        };
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, &name, bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// Mount discovery + by-package + reference + view (same contract as
/// `tests/in_process_redirect_pnpm.rs` / `e2e_redirect_npm_build.rs`).
/// `before_hash`/`after_hash` are the view record's file hashes.
async fn mount_api_mocks(
    server: &MockServer,
    hosted_url: &str,
    sri: &str,
    before_hash: &str,
    after_hash: &str,
) {
    mount_target_api_mocks(server, hosted_url, sri, before_hash, after_hash, PURL).await;
}

async fn mount_target_api_mocks(
    server: &MockServer,
    hosted_url: &str,
    sri: &str,
    before_hash: &str,
    after_hash: &str,
    purl: &str,
) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID, "purl": purl, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "pnpm redirect capstone fixture"
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
                "uuid": UUID, "purl": purl,
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
                    "purl": purl,
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
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash": after_hash,
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-2222"],
                    "summary": "pnpm redirect capstone vuln",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// The hosted tarball route pnpm hits at install time. Separate from the API
/// mocks because the tamper twin serves different bytes than the pinned sri.
async fn mount_tarball_route(server: &MockServer, served: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_raw(served, "application/octet-stream"))
        .mount(server)
        .await;
}

/// Everything the post-redirect legs need. `tmp` owns the whole tree;
/// `_server` keeps the hosted-tarball route alive through the fresh installs.
struct PnpmRedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    patched: Vec<u8>,
    _server: MockServer,
    lock_name: String,
    lock_before: String,
}

/// Steps 1–3 of the module doc against the REAL `corepack <pm>`: fixture
/// install, patched tarball + API mocks, the hosted rewrite (via `driver`:
/// `scan --mode hosted` or `get <uuid> --mode hosted` — same engine, same
/// on-disk contract), and the envelope/lockfile/ledger/idempotency
/// assertions. When `tamper_served_tarball` is set, the tarball route serves
/// DIFFERENT bytes than the sha512 pinned into the lockfile — the negative
/// twin's premise. `no_trust_config` runs every rewrite with
/// `--no-trust-lockfile-config` and flips the trust-auto-config expectations
/// to the opted-out contract. `None` = skip (message already printed).
async fn redirect_scanned_pnpm_project(
    pm: &str,
    tag: &str,
    tamper_served_tarball: bool,
    no_trust_config: bool,
    driver: HostedDriver,
) -> Option<PnpmRedirectFixture> {
    if !has_corepack_pm(pm) {
        println!("SKIP e2e_redirect_pnpm_build ({tag}): `corepack {pm}` unavailable");
        return None;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{ "name": "pnpm-redirect-capstone", "version": "0.0.0", "private": true, "dependencies": {{ "{DEP}": "{DEP_VERSION}" }} }}"#
        ),
    )
    .unwrap();

    // 1. REAL fixture: pnpm install (network allowed here, private store).
    let store = tmp.path().join("pnpm-store");
    let install = corepack_with_retries(
        &proj,
        pm,
        &["install", &format!("--store-dir={}", store.display())],
        true,
    );
    if !install.status.success() {
        assert!(
            !pnpm_required(),
            "required {pm} fixture install failed: {:?}",
            install
        );
        println!(
            "SKIP e2e_redirect_pnpm_build ({tag}): fixture `{pm} install` failed \
             (registry unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return None;
    }

    let orig = std::fs::read(proj.join("node_modules").join(DEP).join("index.js"))
        .expect("installed index.js");
    assert!(
        !orig.starts_with(MARKER.as_bytes()),
        "pristine install must not carry the marker"
    );
    let patched: Vec<u8> = [MARKER.as_bytes(), orig.as_slice()].concat();

    // 2. Patched tarball from the ACTUAL installed bytes. The lockfile pin is
    //    ALWAYS the real tarball's sha512; the negative twin only tampers
    //    what the route SERVES, so the pin is what catches the swap.
    let tgz = make_tgz_from_installed(&proj.join("node_modules").join(DEP), &patched);
    let sri = format!("sha512-{}", sha512_sri_b64(&tgz));
    let served: Vec<u8> = if tamper_served_tarball {
        let tampered: Vec<u8> = [b"/* SOCKET-TAMPERED */\n", orig.as_slice()].concat();
        make_tgz_from_installed(&proj.join("node_modules").join(DEP), &tampered)
    } else {
        tgz.clone()
    };

    // 3. API mocks + the hosted tarball route the fresh installs will hit.
    let server = MockServer::start().await;
    let hosted_url = hosted_url_for(&server.uri());
    mount_api_mocks(
        &server,
        &hosted_url,
        &sri,
        &compute_git_sha256_from_bytes(&orig),
        &compute_git_sha256_from_bytes(&patched),
    )
    .await;
    mount_tarball_route(&server, served).await;

    let lock_name = if proj.join("pnpm-lock.yaml").exists() {
        "pnpm-lock.yaml"
    } else {
        "shrinkwrap.yaml"
    };
    let lock_path = proj.join(lock_name);
    let lock_before = std::fs::read_to_string(&lock_path).expect("pnpm-lock.yaml after install");
    let pkg_before = std::fs::read(proj.join("package.json")).unwrap();
    // Whether the fixture install left a workspace file behind decides the
    // trust edit's action: "created" (new file) vs "added" (line appended).
    let ws_path = proj.join("pnpm-workspace.yaml");
    let ws_existed_before = ws_path.exists();
    // The pristine resolution line — captured (not hardcoded) so "the upstream
    // integrity is gone" can be asserted against whatever the registry served.
    let upstream_resolution = lock_before
        .lines()
        .find(|l| l.contains("integrity:"))
        .expect("pristine lock must carry an inline resolution")
        .to_string();

    let scan_extra: &[&str] = if no_trust_config {
        &["--no-trust-lockfile-config"]
    } else {
        &[]
    };
    let (code, stdout, stderr) = run_hosted(driver, &proj, &server.uri(), scan_extra);
    assert_eq!(
        code, 0,
        "{driver:?} --mode hosted failed ({tag}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    if pm == "pnpm@1.0.0" {
        assert_eq!(
            env["summary"]["applied"], 0,
            "unsafe legacy lock must be refused: {env}"
        );
        assert!(
            warning_codes(&env).contains(&"redirect_pnpm_legacy_lockfile_unsupported".to_string())
        );
        assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), lock_before);
        assert!(!proj.join(".socket/vendor/redirect-state.json").exists());
        // Nothing was wired, so a manifest-less VEX finds nothing to attest
        // (the pristine lock names no Socket patch) and never goes online.
        off_runtime(|| {
            let api = hosted_patch_api(PURL, &patched);
            let out = run_vex(
                &socket_bin(),
                &proj,
                &VexRun {
                    patch_server_url: Some(server.uri()),
                    ..VexRun::online(&api)
                },
            );
            assert_eq!(out.code, Some(2), "refused legacy lock vex: {out}");
            assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
            assert_absent(out.doc.as_ref(), PURL);
            api.assert_no_requests();
        });
        println!(
            "EXPECTED REFUSAL: pnpm 1.0.0 discards hosted URLs; lock unchanged, no patch confirmed"
        );
        return None;
    }

    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["summary"]["applied"], 1,
        "exactly one dep redirected: {env}"
    );
    // The zero-touch trustLockfile auto-config fires only for root v9 locks
    // (and not under `--no-trust-lockfile-config`): pnpm 7/8 (5.x/6.0) have
    // neither the lockfile policy nor the setting, so legacy runs rewrite
    // ONLY the lock and keep the manual flag guidance.
    let v9_lock = lock_before.starts_with("lockfileVersion: '9.0'");
    // pnpm 9.0–10.4 (as the install recorded it) get no pnpm-workspace.yaml:
    // a root-only workspace breaks `pnpm add` there and they never read
    // `trustLockfile` (#734).
    let pre_10_5 = installed_pnpm_pre_10_5(&proj);
    let auto_trust = v9_lock && !no_trust_config && !pre_10_5;
    let expected_rewrites = if auto_trust {
        serde_json::json!(["pnpm-lock.yaml", "pnpm-workspace.yaml"])
    } else {
        serde_json::json!([lock_name])
    };
    assert_eq!(
        env["redirect"]["rewrittenFiles"], expected_rewrites,
        "the rewritten set must match the lock's grammar + trust config ({tag}): {env}"
    );
    // The install-guidance warning: assert the CODE and the recovery's stable
    // spelling only — the detail prose is not part of the contract.
    assert!(
        warning_codes(&env).contains(&"redirect_pnpm_trust_lockfile".to_string()),
        "a landed pnpm rewrite must warn about pnpm >=11 installs: {env}"
    );
    let trust_detail = env["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "redirect_pnpm_trust_lockfile")
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_default()
        .to_string();
    if auto_trust {
        assert!(
            trust_detail.contains("trustLockfile: true"),
            "the v9 warning must name the auto-configured trustLockfile key; got: {trust_detail}"
        );
    } else if v9_lock && !no_trust_config {
        assert!(
            trust_detail.contains("ERR_PNPM_ADDING_TO_ROOT"),
            "the pnpm 9.0–10.4 warning must say why no workspace file was created; \
             got: {trust_detail}"
        );
    } else if v9_lock {
        // Opted out on a v9 lock: the manual two-recovery guidance stands.
        assert!(
            trust_detail.contains("trust-lockfile"),
            "the opted-out v9 warning must name the manual trust-lockfile recovery; \
             got: {trust_detail}"
        );
    } else {
        // Legacy (5.x/6.0) lock: pnpm 7/8 reject `--trust-lockfile` as an
        // unknown option, so the guidance must never mention it — installs
        // work unchanged and no trust step exists on those majors.
        assert!(
            !trust_detail.contains("trust-lockfile"),
            "the legacy-lock warning must not recommend --trust-lockfile (pnpm 7/8 \
             reject the flag); got: {trust_detail}"
        );
        assert!(
            trust_detail.contains("pnpm") && trust_detail.contains("no trust step"),
            "the legacy-lock warning must say installs work unchanged on pnpm 7/8; \
             got: {trust_detail}"
        );
    }

    // Trust auto-config surface: the workspace file itself. Auto runs write
    // `trustLockfile: true`; legacy / opted-out runs must leave the file
    // exactly as the fixture install left it (absent, for these fixtures).
    let ws_after_scan = if auto_trust {
        let ws = std::fs::read_to_string(&ws_path)
            .expect("a v9 rewrite must auto-write pnpm-workspace.yaml");
        assert!(
            ws.contains("trustLockfile: true"),
            "the scan-written workspace file must carry the trust key ({tag}); got:\n{ws}"
        );
        Some(ws)
    } else {
        assert_eq!(
            ws_path.exists(),
            ws_existed_before,
            "a legacy-lock, pnpm 9.0–10.4 or --no-trust-lockfile-config run must not \
             create pnpm-workspace.yaml ({tag})"
        );
        None
    };

    // Lock splice: `{integrity: <patched sri>, tarball: <hosted url>}` with
    // the upstream resolution line fully replaced; package.json untouched
    // (hosted mode edits only the lock).
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock_after.contains(&format!("integrity: {sri}"))
            && lock_after.contains(&format!("tarball: {hosted_url}")),
        "resolution must be spliced to the patched sri + hosted tarball; got:\n{lock_after}"
    );
    assert!(
        !lock_after.contains(&upstream_resolution),
        "the upstream resolution line must be replaced; got:\n{lock_after}"
    );
    assert_eq!(
        std::fs::read(proj.join("package.json")).unwrap(),
        pkg_before,
        "hosted mode must not edit package.json"
    );

    // v5 hosted mode keeps no ledger: the lock (+ the trust setting) is the
    // whole hosted state.
    let ledger_path = proj.join(".socket/vendor/redirect-state.json");
    assert!(
        !ledger_path.exists(),
        "hosted mode writes no redirect ledger ({tag})"
    );

    // Idempotency: the second scan still counts the dep as redirected (the
    // hosted URL is already in the lock) but rewrites nothing — lock AND
    // workspace file byte-stable — and still writes no ledger.
    let (code, stdout, stderr) = run_hosted(driver, &proj, &server.uri(), scan_extra);
    assert_eq!(
        code, 0,
        "second {driver:?} --mode hosted failed ({tag}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env2 = parse_envelope(&stdout);
    assert_eq!(
        env2["summary"]["applied"], 1,
        "an already-redirected dep still counts: {env2}"
    );
    assert_eq!(
        env2["redirect"]["rewrittenFiles"],
        serde_json::json!([]),
        "the re-run must rewrite nothing: {env2}"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        lock_after,
        "the re-run must leave the lock byte-stable"
    );
    if let Some(ws) = &ws_after_scan {
        assert_eq!(
            &std::fs::read_to_string(&ws_path).unwrap(),
            ws,
            "the re-run must leave pnpm-workspace.yaml byte-stable"
        );
    }
    assert!(!ledger_path.exists(), "the re-run writes no ledger ({tag})");

    Some(PnpmRedirectFixture {
        tmp,
        proj,
        patched,
        _server: server,
        lock_name: lock_name.to_string(),
        lock_before,
    })
}

/// New dir holding ONLY what a git checkout would carry — package.json,
/// pnpm-lock.yaml, `.socket/` (plus, when `with_workspace_yaml`, the
/// `trustLockfile: true` pnpm-workspace.yaml the scan wrote — the zero-touch
/// committed checkout) — with the registry pointed at a DEAD port and an
/// EMPTY store, then `corepack <pm> install --frozen-lockfile` (+
/// `extra_args`). Returns the fresh dir and the pnpm output (asserted by each
/// leg: success for the real tarball, integrity failure for the tampered
/// one, policy failure for pnpm 11 without the trust config or flag).
fn fresh_checkout_install(
    fx: &PnpmRedirectFixture,
    pm: &str,
    label: &str,
    extra_args: &[&str],
    with_workspace_yaml: bool,
) -> (PathBuf, Output) {
    fresh_checkout_install_env(fx, pm, label, extra_args, with_workspace_yaml, &[])
}

/// [`fresh_checkout_install`] with `env` set on the install, after the
/// hermetic scrub.
fn fresh_checkout_install_env(
    fx: &PnpmRedirectFixture,
    pm: &str,
    label: &str,
    extra_args: &[&str],
    with_workspace_yaml: bool,
    env: &[(&str, &str)],
) -> (PathBuf, Output) {
    let fresh = fx.tmp.path().join(format!("fresh-{label}"));
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(fx.proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(fx.proj.join(&fx.lock_name), fresh.join(&fx.lock_name)).unwrap();
    if with_workspace_yaml {
        std::fs::copy(
            fx.proj.join("pnpm-workspace.yaml"),
            fresh.join("pnpm-workspace.yaml"),
        )
        .expect("the v9 scan must have written pnpm-workspace.yaml");
    }
    // v5 hosted mode writes nothing under `.socket/`; carry it when present.
    if fx.proj.join(".socket").is_dir() {
        fs_tree::copy_tree(&fx.proj.join(".socket"), &fresh.join(".socket"));
    }
    // Dead registry: the only reachable artifact URL is the wiremock hosted
    // tarball, so a successful install can only have come from it. The retry
    // clamps keep the negative legs from pnpm's default 10s + 60s retry
    // ladder against the dead port (the max/min timeouts back the retry
    // count up, should a pnpm major ever treat 0 as unset).
    std::fs::write(
        fresh.join(".npmrc"),
        "registry=http://127.0.0.1:1/\n\
         fetch-retries=0\n\
         fetch-retry-mintimeout=100\n\
         fetch-retry-maxtimeout=500\n",
    )
    .unwrap();
    let fresh_store = fx.tmp.path().join(format!("fresh-store-{label}"));
    let store_flag = format!("--store-dir={}", fresh_store.display());
    let mut args = vec!["install", "--frozen-lockfile", &store_flag];
    args.extend_from_slice(extra_args);
    let mut cmd = corepack_command(&fresh, pm, &args, false);
    cmd.envs(env.iter().copied());
    let out = cmd.output().expect("failed to run corepack");
    (fresh, out)
}

fn assert_marker_landed(fresh: &Path, patched: &[u8], ci: &Output, tag: &str) {
    assert!(
        ci.status.success(),
        "fresh-checkout `pnpm install --frozen-lockfile` must succeed from the hosted \
         patch tarball ({tag}).\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "pnpm must install the PATCHED bytes from the hosted patch ({tag}); got:\n{}",
        String::from_utf8_lossy(&installed[..installed.len().min(120)])
    );
    assert_eq!(
        installed, patched,
        "fresh install must be byte-identical to the patched content ({tag})"
    );
}

// ── manifest-less VEX (lockfile discovery) ─────────────────────────────

/// Run `f` on a scoped OS thread outside the test's tokio runtime:
/// [`PatchApi`] owns its own runtime, which can be neither started nor
/// dropped from inside an async context. A panic in `f` fails the test
/// with its original message.
fn off_runtime<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|s| {
        s.spawn(f)
            .join()
            .unwrap_or_else(|p| std::panic::resume_unwind(p))
    })
}

/// The vulnerability set every hosted fixture's view record carries.
const HOSTED_VULNS: &[(&str, &[&str])] = &[(GHSA, &["CVE-2026-2222"])];

/// A patch API stand-in serving `purl`'s patch view with the REAL patched
/// bytes' hash — the record a manifest-less, ledger-less checkout recovers
/// from the API.
fn hosted_patch_api(purl: &str, patched: &[u8]) -> PatchApi {
    PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(
            UUID,
            purl,
            &[("package/index.js", &compute_git_sha256_from_bytes(patched))],
            HOSTED_VULNS,
        ),
    )])
}

/// Manifest-less VEX over a checkout `fresh` that the real pnpm installed
/// from the redirected lock (the marker bytes have landed). `patch_server`
/// is the wiremock origin the lock's hosted URLs point at (a Socket host in
/// production; here it must be named via `--patch-server-url`). Proves, in
/// order:
///
/// 1. no `.socket/manifest.json` (hosted mode never writes one): the ledger
///    record + the hash-verified installed tree attest `(redirected)`;
/// 2. ledgers deleted too: the lockfile reference alone, with the record
///    fetched from the patch API, still attests;
/// 3. `--offline` with no ledgers: `record_unavailable`, zero API traffic;
/// 4. the lock reverted to the registry resolution while the ledger (and
///    the patched installed bytes) stay: NOT attested, `--no-verify` too;
/// 5. embedded `scan --mode hosted --vex` over the ledger-less checkout
///    (`api_url` = the flow's discovery/reference mock) attests as well.
///
/// `lock_name` / `lock_before` are the committed lock and its pristine
/// registry bytes.
fn assert_manifestless_hosted_vex(
    fresh: &Path,
    patch_server: &str,
    lock_name: &str,
    lock_before: &str,
    patched: &[u8],
    purl: &str,
    tag: &str,
) {
    off_runtime(|| {
        let bin = socket_bin();
        let api = hosted_patch_api(purl, patched);
        let with_origin = |run: VexRun| VexRun {
            patch_server_url: Some(patch_server.to_string()),
            ..run
        };
        let ledger = fresh.join(".socket/vendor/redirect-state.json");
        let lock = fresh.join(lock_name);
        let lock_wired = std::fs::read(&lock).expect("fresh checkout lock");

        // 1. Manifest deleted (hosted checkouts carry none): ledger record.
        strip_manifest(fresh);
        if ledger.exists() {
            let out = run_vex(&bin, fresh, &with_origin(VexRun::online(&api)));
            assert_eq!(out.code, Some(0), "[{tag}] manifest-less vex: {out}");
            assert_attested(out.doc(), purl, UUID, Marker::Redirected, HOSTED_VULNS);
            eprintln!("VEX-CELL hosted [{tag}] manifest-deleted: attested");
        }
        let ledger_bytes = std::fs::read(&ledger).ok();

        // 2. Ledgers deleted: lockfile discovery + the API record.
        strip_ledgers(fresh);
        let views = api.view_requests(UUID);
        let out = run_vex(&bin, fresh, &with_origin(VexRun::online(&api)));
        assert_eq!(out.code, Some(0), "[{tag}] ledger-less vex: {out}");
        assert_attested(out.doc(), purl, UUID, Marker::Redirected, HOSTED_VULNS);
        assert!(
            api.view_requests(UUID) > views,
            "[{tag}] the record must come from the patch API: {:?}",
            api.requests()
        );
        eprintln!("VEX-CELL hosted [{tag}] ledgers-deleted: attested");

        // 3. Offline, no ledgers: the record is unavailable, zero network.
        let seen = api.request_count();
        let out = run_vex(&bin, fresh, &with_origin(VexRun::offline()));
        assert_eq!(out.code, Some(1), "[{tag}] offline ledger-less vex: {out}");
        assert_not_attested(&out.envelope, purl, "record_unavailable");
        assert_absent(out.doc.as_ref(), purl);
        assert_eq!(api.request_count(), seen, "[{tag}] --offline hit the API");
        eprintln!("VEX-CELL hosted [{tag}] offline: record_unavailable");

        // 5. Embedded: `scan --mode hosted --vex`, manifest- and ledger-less.
        let scan = VexRun {
            via: VexVia::Scan,
            api_url: Some(patch_server.to_string()),
            api_token: Some("fake".to_string()),
            org: Some(ORG.to_string()),
            patch_server_url: Some(patch_server.to_string()),
            extra_args: vec!["--mode".into(), "hosted".into(), "--yes".into()],
            ..VexRun::default()
        };
        let out = run_vex(&bin, fresh, &scan);
        assert_eq!(out.code, Some(0), "[{tag}] scan --mode hosted --vex: {out}");
        assert_attested(out.doc(), purl, UUID, Marker::Redirected, HOSTED_VULNS);
        assert_eq!(
            std::fs::read(&lock).unwrap(),
            lock_wired,
            "[{tag}] the embedded re-scan must leave the redirected lock byte-stable"
        );
        eprintln!("VEX-CELL hosted [{tag}] embedded-scan: attested");
        strip_ledgers(fresh);

        // 4. Lock reverted to the registry resolution, ledger restored, the
        //    patched bytes still installed: nothing wires the patch any more.
        if let Some(bytes) = &ledger_bytes {
            std::fs::write(&ledger, bytes).unwrap();
        }
        std::fs::write(&lock, lock_before).unwrap();
        for no_verify in [false, true] {
            let out = run_vex(
                &bin,
                fresh,
                &with_origin(VexRun {
                    no_verify,
                    ..VexRun::online(&api)
                }),
            );
            assert_ne!(
                out.code,
                Some(0),
                "[{tag}] reverted lock (no_verify={no_verify}): {out}"
            );
            assert_absent(out.doc.as_ref(), purl);
            if ledger_bytes.is_some() {
                assert_not_attested(&out.envelope, purl, "redirect_unwired");
            }
            eprintln!("VEX-CELL hosted [{tag}] reverted(no_verify={no_verify}): not attested");
        }
        std::fs::write(&lock, &lock_wired).unwrap();
        if let Some(bytes) = &ledger_bytes {
            std::fs::write(&ledger, bytes).unwrap();
        }
    });
    eprintln!("MANIFEST-LESS HOSTED VEX OK ({tag})");
}

/// [`assert_manifestless_hosted_vex`] over a fixture's fresh checkout.
fn assert_fixture_manifestless_vex(fx: &PnpmRedirectFixture, fresh: &Path, tag: &str) {
    assert_manifestless_hosted_vex(
        fresh,
        &fx._server.uri(),
        &fx.lock_name,
        &fx.lock_before,
        &fx.patched,
        PURL,
        tag,
    );
}

// ── corepack legs (gating mirrors e2e_redirect_rush_sim.rs) ───────────

// multi_thread: the CLI/pnpm subprocesses block a worker thread while
// wiremock keeps serving the API + tarball routes on the others.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm10_redirect_fresh_checkout_frozen_install_lands_patched_bytes() {
    let Some(fx) =
        redirect_scanned_pnpm_project(PNPM_PRIMARY, "pnpm10", false, false, HostedDriver::Scan)
            .await
    else {
        return;
    };

    // 4. FRESH-CHECKOUT PROOF: pnpm pulls the patched bytes from the hosted
    //    patch server because the committed lockfile says so.
    let (fresh, ci) = fresh_checkout_install(&fx, PNPM_PRIMARY, "pnpm10", &[], false);
    assert_marker_landed(&fresh, &fx.patched, &ci, "pnpm10");
    assert_fixture_manifestless_vex(&fx, &fresh, "pnpm10");
}

/// Negative twin: the hosted route serves TAMPERED bytes while the lockfile
/// pins the REAL tarball's sha512 — the fresh frozen install must refuse to
/// install and must not land the marker. This is what makes the redirect
/// safe to commit: a compromised or swapped hosted artifact cannot slip past
/// the pin.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm10_redirect_tampered_hosted_tarball_fails_fresh_frozen_install() {
    let Some(fx) = redirect_scanned_pnpm_project(
        PNPM_PRIMARY,
        "pnpm10-tampered",
        true,
        false,
        HostedDriver::Scan,
    )
    .await
    else {
        return;
    };

    let (fresh, ci) = fresh_checkout_install(&fx, PNPM_PRIMARY, "pnpm10-tampered", &[], false);
    assert!(
        !ci.status.success(),
        "pnpm MUST fail when the served tarball does not match the pinned sha512.\nstdout:\n{}\nstderr:\n{}",
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
            || chatter.contains("ERR_PNPM"),
        "the failure must be the integrity check, not something incidental:\n{chatter}"
    );
    // The marker bytes must not have landed anywhere pnpm links from.
    if let Ok(bytes) = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")) {
        assert!(
            !bytes.starts_with(MARKER.as_bytes()),
            "no marker bytes may land from a tampered tarball"
        );
    }
}

/// get-driven hosted twin (v4.0): `get <uuid> --mode hosted --json --yes`
/// routes through the SAME hosted engine as `scan --mode hosted`, so the
/// full pnpm@10 chain must hold unchanged — the fixture's lock splice,
/// trustLockfile auto-config (pnpm-workspace.yaml gains `trustLockfile:
/// true`, the workspace file joins `rewrittenFiles`), ledger, and
/// idempotency assertions all run against the get front door, and the fresh
/// dead-registry `pnpm install --frozen-lockfile` lands the marker bytes.
/// The uuid identifier path is exempt from installed narrowing, so no
/// search-endpoint mocks are needed beyond the view + reference routes the
/// fixture already mounts.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm_get_uuid_hosted_fresh_checkout_frozen_install() {
    let Some(fx) = redirect_scanned_pnpm_project(
        PNPM_PRIMARY,
        "pnpm10-get",
        false,
        false,
        HostedDriver::GetUuid,
    )
    .await
    else {
        return;
    };

    let (fresh, ci) = fresh_checkout_install(&fx, PNPM_PRIMARY, "pnpm10-get", &[], false);
    assert_marker_landed(&fresh, &fx.patched, &ci, "pnpm10 get-uuid");
    assert_fixture_manifestless_vex(&fx, &fresh, "pnpm10 get-uuid");
}

/// pnpm@9 leg (the vendor capstone's secondary convention):
/// same positive chain, no tamper twin needed — @10 already carries it.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm9_redirect_fresh_checkout_frozen_install_lands_patched_bytes() {
    let Some(fx) =
        redirect_scanned_pnpm_project(PNPM_SECONDARY, "pnpm9", false, false, HostedDriver::Scan)
            .await
    else {
        return;
    };
    let (fresh, ci) = fresh_checkout_install(&fx, PNPM_SECONDARY, "pnpm9", &[], false);
    assert_marker_landed(&fresh, &fx.patched, &ci, "pnpm9");
    assert_fixture_manifestless_vex(&fx, &fresh, "pnpm9");
    // #734: the scan left the project a plain single package, so pnpm 9's
    // everyday `pnpm add` still works (a root-only workspace fails it with
    // ERR_PNPM_ADDING_TO_ROOT).
    assert!(!fx.proj.join("pnpm-workspace.yaml").exists());
    let store = fx.tmp.path().join("pnpm-store");
    let add = corepack(
        &fx.proj,
        PNPM_SECONDARY,
        &[
            "add",
            "is-number@7.0.0",
            &format!("--store-dir={}", store.display()),
        ],
    );
    let stderr = String::from_utf8_lossy(&add.stderr);
    let stdout = String::from_utf8_lossy(&add.stdout);
    assert!(
        !stdout.contains("ADDING_TO_ROOT") && !stderr.contains("ADDING_TO_ROOT"),
        "pnpm 9 `pnpm add` must not hit ERR_PNPM_ADDING_TO_ROOT:\n{stdout}\n{stderr}"
    );
}

/// pnpm@11 ZERO-TOUCH leg: pnpm 11's lockfile supply-chain policy verifies
/// each resolution's tarball URL against registry metadata and would reject
/// the rewritten lock, but the scan auto-writes `trustLockfile: true` into
/// pnpm-workspace.yaml — so a fresh checkout that carries the scan's outputs
/// (the workspace file is scan-written and commit-intended, exactly like the
/// lock) frozen-installs against the DEAD registry with NO FLAGS and lands
/// the marker bytes. This is the shipped headline: CI needs no modification.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm11_zero_touch_frozen_install_lands_patched_bytes_via_auto_trust_config() {
    let Some(fx) =
        redirect_scanned_pnpm_project(PNPM_TERTIARY, "pnpm11", false, false, HostedDriver::Scan)
            .await
    else {
        return;
    };
    let (fresh, ci) = fresh_checkout_install(&fx, PNPM_TERTIARY, "pnpm11-zero-touch", &[], true);
    assert_marker_landed(&fresh, &fx.patched, &ci, "pnpm11 zero-touch");
    assert_fixture_manifestless_vex(&fx, &fresh, "pnpm11 zero-touch");
}

// ── the registry route, against a real pnpm ─────────────────────────────

/// A synthetic package of the registry-route legs: its name, and the
/// manifest fields beyond `name` and `version` (every one at 1.0.0).
struct RoutePackage {
    name: &'static str,
    fields: serde_json::Value,
}

/// The packages the default registry of the registry-route legs serves:
/// `peer-user` has a peer dependency and a dependency of its own (the
/// shape a bare registry declaration loses on `pnpm add`), `leaf` is
/// reached only through other packages, `extra` is there to be added.
fn route_packages() -> Vec<RoutePackage> {
    let package = |name, fields| RoutePackage { name, fields };
    vec![
        package("leaf", serde_json::json!({})),
        package(
            "mid",
            serde_json::json!({"dependencies": {"leaf": "^1.0.0"}}),
        ),
        package("host", serde_json::json!({})),
        package(
            "peer-user",
            serde_json::json!({
                "peerDependencies": {"host": "^1.0.0"},
                "dependencies": {"leaf": "^1.0.0"}
            }),
        ),
        package("extra", serde_json::json!({})),
    ]
}

const ROUTE_VERSION: &str = "1.0.0";

/// One hosted patch of the registry-route legs.
struct RoutePatch {
    name: &'static str,
    uuid: &'static str,
    /// The grant the patched tarball is served under.
    token: &'static str,
}

const ROUTE_PATCHES: [RoutePatch; 2] = [
    RoutePatch {
        name: "leaf",
        uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        token: "1eaf1eaf-1eaf-41ea-8f1e-af1eaf1eaf1e",
    },
    RoutePatch {
        name: "peer-user",
        uuid: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        token: "9ee29ee2-9ee2-49ee-829e-e29ee29ee29e",
    },
];

impl RoutePatch {
    fn purl(&self) -> String {
        format!("pkg:npm/{}@{ROUTE_VERSION}", self.name)
    }

    /// The directory the patch is served from, which is its registry.
    fn registry_path(&self) -> String {
        format!(
            "/patch/npm/{}/{ROUTE_VERSION}/{}/{}/",
            self.name, self.token, self.uuid
        )
    }

    fn tarball_path(&self) -> String {
        format!("{}{}-{ROUTE_VERSION}.tgz", self.registry_path(), self.name)
    }

    /// The name of the patch's registry: `socket-` and the first eight
    /// digits of the patch UUID.
    fn alias(&self) -> String {
        format!("socket-{}", &self.uuid[..8])
    }

    /// The `namedRegistries` line of the patch on `server`.
    fn registry_line(&self, server: &MockServer) -> String {
        format!(
            "  {}: {}{}\n",
            self.alias(),
            server.uri(),
            self.registry_path()
        )
    }

    /// The workspace file's `overrides` line of the patch.
    fn override_line(&self) -> String {
        format!(
            "  '{}@{ROUTE_VERSION}': '{}:{ROUTE_VERSION}'\n",
            self.name,
            self.alias()
        )
    }

    /// The lock's record of that override.
    fn lock_override(&self) -> String {
        format!(
            "  {}@{ROUTE_VERSION}: {}:{ROUTE_VERSION}\n",
            self.name,
            self.alias()
        )
    }

    /// How the lock spells the patched release once routed.
    fn routed_version(&self) -> String {
        format!("{}:{ROUTE_VERSION}", self.alias())
    }

    /// The advisory the patch fixes.
    fn advisory(&self) -> String {
        format!("GHSA-route-{}", self.name)
    }
}

fn route_index(name: &str, patched: bool) -> String {
    let marker = if patched { MARKER } else { "" };
    format!("{marker}module.exports = '{name}'\n")
}

/// The tarball of a synthetic package at [`ROUTE_VERSION`].
fn route_tgz(package: &RoutePackage, patched: bool) -> Vec<u8> {
    route_tgz_of(package, ROUTE_VERSION, patched)
}

/// The tarball of `version` of a synthetic package.
fn route_tgz_of(package: &RoutePackage, version: &str, patched: bool) -> Vec<u8> {
    let mut manifest = serde_json::json!({"name": package.name, "version": version});
    for (key, value) in package.fields.as_object().into_iter().flatten() {
        manifest[key] = value.clone();
    }
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (name, bytes) in [
        (
            "package/package.json",
            serde_json::to_vec_pretty(&manifest).unwrap(),
        ),
        (
            "package/index.js",
            route_index(package.name, patched).into_bytes(),
        ),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// The fields a registry lists for [`ROUTE_VERSION`] of a synthetic
/// package.
fn route_version_document(
    package: &RoutePackage,
    tarball: &str,
    bytes: &[u8],
) -> serde_json::Value {
    route_version_document_of(package, ROUTE_VERSION, tarball, bytes)
}

/// The fields a registry lists for `version` of a synthetic package.
fn route_version_document_of(
    package: &RoutePackage,
    version: &str,
    tarball: &str,
    bytes: &[u8],
) -> serde_json::Value {
    let mut document = serde_json::json!({
        "name": package.name,
        "version": version,
        "dist": {
            "tarball": tarball,
            "integrity": format!("sha512-{}", sha512_sri_b64(bytes)),
        }
    });
    for (key, value) in package.fields.as_object().into_iter().flatten() {
        document[key] = value.clone();
    }
    document
}

/// The release of `peer-user` past the patched one: the default registry
/// lists it too (never as `latest`), and no patch is hosted for it.
const ROUTE_NEXT_VERSION: &str = "2.0.0";

/// The default registry: every synthetic package, as npm serves one (the
/// packument, the tarball, and the version document the upstream restore
/// reads).
async fn mount_route_registry(registry: &MockServer) {
    for package in route_packages() {
        let releases: &[&str] = match package.name {
            "peer-user" => &[ROUTE_VERSION, ROUTE_NEXT_VERSION],
            _ => &[ROUTE_VERSION],
        };
        mount_registry_package(registry, &package, releases, ROUTE_VERSION).await;
    }
}

/// One package of a default registry: `releases` of it, `latest` its
/// `latest` dist-tag.
async fn mount_registry_package(
    registry: &MockServer,
    package: &RoutePackage,
    releases: &[&str],
    latest: &str,
) {
    let name = package.name;
    let published = "2020-01-01T00:00:00.000Z";
    let mut versions = serde_json::Map::new();
    let mut time = serde_json::json!({"created": published, "modified": published});
    for version in releases {
        let bytes = route_tgz_of(package, version, false);
        let tarball = format!("{}/{name}/-/{name}-{version}.tgz", registry.uri());
        let document = route_version_document_of(package, version, &tarball, &bytes);
        versions.insert(version.to_string(), document.clone());
        time[*version] = published.into();
        Mock::given(method("GET"))
            .and(path(format!("/{name}/{version}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(document))
            .mount(registry)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/{name}/-/{name}-{version}.tgz")))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(bytes, "application/octet-stream"),
            )
            .mount(registry)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("/{name}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name,
            "dist-tags": {"latest": latest},
            "versions": versions,
            "time": time,
        })))
        .mount(registry)
        .await;
}

/// pnpm for one registry-route leg, with a metadata cache of the leg's own
/// (`cache`). The mock servers of this file come from a pool, so a later
/// leg can be served on a port an earlier leg's registry had, and pnpm
/// keeps what a registry answered by host and port and trusts it for an
/// exact version: on the shared cache a leg would resolve packages from
/// another leg's registry and never ask its own.
fn route_pnpm(cache: &Path, cwd: &Path, pm: &str, args: &[&str]) -> Output {
    let mut cmd = corepack_command(cwd, pm, args, false);
    cmd.env("XDG_CACHE_HOME", cache);
    cmd.output().expect("failed to run corepack")
}

/// The reference result of the route patches; each of `addressed` carries
/// its registry address, the others none.
fn route_reference(server: &MockServer, addressed: &[&str]) -> serde_json::Value {
    let packages = route_packages();
    let mut results = serde_json::Map::new();
    for patch in &ROUTE_PATCHES {
        let package = packages.iter().find(|p| p.name == patch.name).unwrap();
        let url = format!("{}{}", server.uri(), patch.tarball_path());
        let sri = format!("sha512-{}", sha512_sri_b64(&route_tgz(package, true)));
        let registry = addressed
            .contains(&patch.name)
            .then(|| format!("{}{}", server.uri(), patch.registry_path()));
        results.insert(
            patch.uuid.to_string(),
            serde_json::json!({
                "status": "granted",
                "url": url,
                "purl": patch.purl(),
                "artifacts": [{"kind": "tarball", "url": url, "integrity": {"sha512": sri}}],
                "registryOverride": null,
                "npmRegistryUrl": registry,
            }),
        );
    }
    serde_json::json!({ "results": results })
}

/// The patch server, on its own origin as in production: the Socket API
/// for the two patches, each patched tarball at its granted URL, and in
/// the same directory the document of the patched package, with the
/// package's own dependency fields; any other name there is a 404.
async fn mount_route_patch_server(server: &MockServer) {
    let packages = route_packages();
    let listed: Vec<serde_json::Value> = ROUTE_PATCHES
        .iter()
        .map(|patch| {
            serde_json::json!({
                "purl": patch.purl(),
                "patches": [{
                    "uuid": patch.uuid, "purl": patch.purl(), "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "registry route fixture"
                }]
            })
        })
        .collect();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": listed,
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(route_reference(server, &["leaf", "peer-user"])),
        )
        .mount(server)
        .await;
    for patch in &ROUTE_PATCHES {
        let package = packages.iter().find(|p| p.name == patch.name).unwrap();
        let patched = route_tgz(package, true);
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*{}.*$",
                patch.name
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": patch.uuid, "purl": patch.purl(),
                    "publishedAt": "2026-01-01T00:00:00Z",
                    "description": "x", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{}", patch.uuid)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": patch.uuid,
                "purl": patch.purl(),
                "publishedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": compute_git_sha256_from_bytes(
                            route_index(patch.name, false).as_bytes()
                        ),
                        "afterHash": compute_git_sha256_from_bytes(
                            route_index(patch.name, true).as_bytes()
                        ),
                    }
                },
                "vulnerabilities": {
                    patch.advisory(): {
                        "cves": [],
                        "summary": "registry route fixture",
                        "severity": "high",
                        "description": "d"
                    }
                },
                "description": "x", "license": "MIT", "tier": "free"
            })))
            .mount(server)
            .await;
        let tarball = format!("{}{}", server.uri(), patch.tarball_path());
        Mock::given(method("GET"))
            .and(path(patch.tarball_path()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(patched.clone(), "application/octet-stream"),
            )
            .mount(server)
            .await;
        // The patch's own registry: the one document, beside the tarball.
        Mock::given(method("GET"))
            .and(path(format!("{}{}", patch.registry_path(), patch.name)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": patch.name,
                "dist-tags": {"latest": ROUTE_VERSION},
                "versions": {
                    ROUTE_VERSION: route_version_document(package, &tarball, &patched)
                },
            })))
            .mount(server)
            .await;
    }
}

/// The index.js a pnpm install left for `name`, reached through
/// `through` (a direct dependency of the project that depends on it), or
/// directly when `through` is `name` itself.
fn installed_index(root: &Path, through: &str, name: &str) -> String {
    let direct = root.join("node_modules").join(through);
    let dir = if through == name {
        direct
    } else {
        // pnpm links a package's dependencies beside it in the store.
        direct
            .canonicalize()
            .expect("an installed dependency")
            .parent()
            .unwrap()
            .join(name)
    };
    std::fs::read_to_string(dir.join("index.js"))
        .unwrap_or_else(|e| panic!("{name} via {through}: {e}"))
}

/// THE REGISTRY ROUTE against a real pnpm, with no network beyond two
/// loopback servers (a default registry of synthetic packages, and the
/// patch server on its own origin).
///
/// The scan routes a package with a peer dependency and a transitive
/// leaf, each through the named registry of its patch. Then, with the
/// real pnpm:
///
/// * `pnpm install --lockfile-only` over the scan's files changes not a
///   byte of the lock: it is the lock pnpm writes for that workspace file;
/// * a fresh checkout frozen-installs from an empty store with no flags
///   and no `trustLockfile`, and lands the patched bytes of both;
/// * `vex` attests both patches from that install: lockfile discovery
///   reads the lock's registry keys, and the installed files verify;
/// * `pnpm add`, `pnpm update`, `pnpm dedupe` and `pnpm install
///   --fix-lockfile` keep both packages routed and patched (a bare
///   registry declaration loses the peer-dependent one on pnpm 12.19+);
/// * after each cleanup, pnpm-workspace.yaml and the lock still agree,
///   which a frozen install from an empty store proves: `rollback` of one
///   package; the re-scan that routes it again; the fall back to
///   `trustLockfile` when a grant loses its registry address; and
///   `rollback` of everything, which leaves the pristine lock and no
///   workspace file.
async fn registry_route_survives_resolution_and_cleans_up(pm: &str, tag: &str) {
    if !has_corepack_pm(pm) {
        println!("SKIP {tag}: `corepack {pm}` unavailable");
        return;
    }
    let registry = MockServer::start().await;
    mount_route_registry(&registry).await;
    let server = MockServer::start().await;
    mount_route_patch_server(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("pnpm-cache");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"app","version":"1.0.0","private":true,"dependencies":{"host":"1.0.0","mid":"1.0.0","peer-user":"1.0.0"}}"#,
    )
    .unwrap();
    let npmrc = format!("registry={}/\n", registry.uri());
    std::fs::write(proj.join(".npmrc"), &npmrc).unwrap();
    let store = |label: &str| format!("--store-dir={}", tmp.path().join(label).display());
    let chatter = |out: &Output| {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    let install = route_pnpm(&cache, &proj, pm, &["install", &store("store-fixture")]);
    if !install.status.success() {
        assert!(
            !pnpm_required(),
            "fixture install failed:\n{}",
            chatter(&install)
        );
        println!("SKIP {tag}: fixture install failed:\n{}", chatter(&install));
        return;
    }
    let lock_path = proj.join("pnpm-lock.yaml");
    let ws_path = proj.join("pnpm-workspace.yaml");
    let read = |path: &Path| std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
    let lock_before = read(&lock_path);
    assert!(!ws_path.exists(), "the fixture has no workspace file");

    let scan = || {
        let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &proj, &server.uri(), &[]);
        assert_eq!(
            code, 0,
            "scan failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        parse_envelope(&stdout)
    };
    let [leaf, peer_user] = &ROUTE_PATCHES;
    // The workspace file a scan leaves, with the patches in that order.
    let workspace_of = |patches: &[&RoutePatch]| {
        let registries: String = patches.iter().map(|p| p.registry_line(&server)).collect();
        let overrides: String = patches.iter().map(|p| p.override_line()).collect();
        format!("packages:\n  - '.'\nnamedRegistries:\n{registries}overrides:\n{overrides}")
    };
    let routed_workspace = workspace_of(&[leaf, peer_user]);
    let assert_routed = |lock: &str, names: &[&str], when: &str| {
        for patch in &ROUTE_PATCHES {
            // The `packages:` entry: its key, then its resolution.
            let entry = |key: String| lock.contains(&format!("\n  {key}:\n    resolution: "));
            let routed = entry(format!("{}@{}", patch.name, patch.routed_version()));
            let plain = entry(format!("{}@1.0.0", patch.name));
            let want = names.contains(&patch.name);
            assert_eq!(
                (routed, plain),
                (want, !want),
                "{tag} {when}: {} must be {}:\n{lock}",
                patch.name,
                if want {
                    "routed"
                } else {
                    "on the default registry"
                }
            );
        }
    };
    // A fresh checkout of what is committed, installed frozen from an
    // empty store; `patched` are the packages whose bytes must be the
    // patch's.
    let frozen_install = |label: &str, patched: &[&str]| {
        let fresh = tmp.path().join(format!("fresh-{label}"));
        std::fs::create_dir_all(&fresh).unwrap();
        for file in ["package.json", "pnpm-lock.yaml", ".npmrc"] {
            std::fs::copy(proj.join(file), fresh.join(file)).unwrap();
        }
        if ws_path.exists() {
            std::fs::copy(&ws_path, fresh.join("pnpm-workspace.yaml")).unwrap();
        }
        let out = route_pnpm(
            &cache,
            &fresh,
            pm,
            &[
                "install",
                "--frozen-lockfile",
                &store(&format!("store-{label}")),
            ],
        );
        assert!(
            out.status.success(),
            "{tag} {label}: the frozen install must accept the lock and the workspace \
             file as they are.\n{}",
            chatter(&out)
        );
        for (through, name) in [("peer-user", "peer-user"), ("mid", "leaf")] {
            let index = installed_index(&fresh, through, name);
            assert_eq!(
                index.starts_with(MARKER),
                patched.contains(&name),
                "{tag} {label}: {name} installed as:\n{index}"
            );
        }
        fresh
    };

    // ── the scan routes both packages ──
    let env = scan();
    assert!(
        !warning_codes(&env).contains(&"redirect_pnpm_entry_not_found".to_string()),
        "{env}"
    );
    assert_eq!(read(&ws_path), routed_workspace, "{tag}");
    let routed_lock = read(&lock_path);
    assert_routed(&routed_lock, &["leaf", "peer-user"], "after the scan");
    for said in [
        format!(
            "overrides:\n{}{}\n",
            leaf.lock_override(),
            peer_user.lock_override()
        ),
        format!(
            "specifier: {routed}\n        version: {routed}(host@1.0.0)\n",
            routed = peer_user.routed_version()
        ),
        format!("      leaf: {}\n", leaf.routed_version()),
    ] {
        assert!(routed_lock.contains(&said), "{tag}: {said}\n{routed_lock}");
    }

    // ── pnpm writes the same lock for that workspace file ──
    // A copy of what is committed, re-locked by pnpm itself: not a byte of
    // the scan's lock changes.
    let pnpm_agrees = |label: &str| {
        let agree = tmp.path().join(format!("agree-{label}"));
        std::fs::create_dir_all(&agree).unwrap();
        for file in [
            "package.json",
            "pnpm-lock.yaml",
            "pnpm-workspace.yaml",
            ".npmrc",
        ] {
            std::fs::copy(proj.join(file), agree.join(file)).unwrap();
        }
        let relock = route_pnpm(
            &cache,
            &agree,
            pm,
            &[
                "install",
                "--lockfile-only",
                &store(&format!("store-agree-{label}")),
            ],
        );
        assert!(
            relock.status.success(),
            "{tag} {label}:\n{}",
            chatter(&relock)
        );
        assert_eq!(
            read(&agree.join("pnpm-lock.yaml")),
            read(&lock_path),
            "{tag} {label}: the scan's lock is the one pnpm resolves from the workspace file"
        );
    };
    pnpm_agrees("routed");

    // ── a fresh checkout installs it, and resolving again keeps it ──
    let fresh = frozen_install("routed", &["leaf", "peer-user"]);
    let asked = server.received_requests().await.unwrap_or_default();
    for patch in &ROUTE_PATCHES {
        let document = format!("{}{}", patch.registry_path(), patch.name);
        assert!(
            asked.iter().any(|request| request.url.path() == document),
            "{tag}: pnpm must have verified {} against its named registry",
            patch.name
        );
    }
    let (code, stdout, stderr) = run_socket(
        &fresh,
        &[
            "vex",
            "--product",
            "pkg:npm/app@1.0.0",
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            &server.uri(),
        ],
    );
    assert_eq!(code, 0, "{tag}: verified VEX failed: {stdout}\n{stderr}");
    let vex: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let attested: Vec<(&str, &str)> = vex["statements"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|statement| {
            Some((
                statement["vulnerability"]["name"].as_str()?,
                statement["status"].as_str()?,
            ))
        })
        .collect();
    for patch in &ROUTE_PATCHES {
        assert!(
            attested.contains(&(patch.advisory().as_str(), "not_affected")),
            "{tag}: {} must be attested from the routed lock: {vex}",
            patch.name
        );
    }
    for (step, args) in [
        ("add", vec!["add", "extra@1.0.0"]),
        ("update", vec!["update"]),
        ("dedupe", vec!["dedupe"]),
        ("install --fix-lockfile", vec!["install", "--fix-lockfile"]),
    ] {
        let mut args = args;
        let flag = store("store-routed");
        args.push(&flag);
        let out = route_pnpm(&cache, &fresh, pm, &args);
        // The first pnpm 12 releases have no `--fix-lockfile`.
        if step == "install --fix-lockfile"
            && !out.status.success()
            && chatter(&out).contains("unexpected argument '--fix-lockfile'")
        {
            println!("SKIP {tag} pnpm {step}: this pnpm has no such flag");
            continue;
        }
        assert!(
            out.status.success(),
            "{tag} pnpm {step}:\n{}",
            chatter(&out)
        );
        let lock = read(&fresh.join("pnpm-lock.yaml"));
        assert_routed(
            &lock,
            &["leaf", "peer-user"],
            &format!("after `pnpm {step}`"),
        );
        assert!(
            lock.contains(&format!(
                "{}{}",
                server.uri(),
                ROUTE_PATCHES[1].tarball_path()
            )),
            "{tag} pnpm {step}: the peer-dependent package keeps its patched tarball:\n{lock}"
        );
        for (through, name) in [("peer-user", "peer-user"), ("mid", "leaf")] {
            assert!(
                installed_index(&fresh, through, name).starts_with(MARKER),
                "{tag} pnpm {step}: {name} must stay patched"
            );
        }
    }
    assert!(
        read(&fresh.join("pnpm-lock.yaml")).contains("\n  extra@1.0.0:"),
        "{tag}: `pnpm add` added its package"
    );

    // ── every cleanup leaves the two files agreeing ──
    let unwind = vec![
        ("SOCKET_PATCH_SERVER_URL".to_string(), server.uri()),
        ("SOCKET_NPM_REGISTRY".to_string(), registry.uri()),
    ];
    let rollback = |targets: &[&str]| {
        let mut args = vec!["rollback"];
        args.extend_from_slice(targets);
        args.extend_from_slice(&["--yes", "--json", "--cwd", proj.to_str().unwrap()]);
        let (code, stdout, stderr) = run_socket_env(&proj, &args, &unwind);
        assert_eq!(
            code, 0,
            "{tag} rollback {targets:?} failed: {stdout}\n{stderr}"
        );
    };

    // One package rolled back: its registry and its override leave both
    // files at once.
    rollback(&[&leaf.purl()]);
    let lock = read(&lock_path);
    assert_routed(&lock, &["peer-user"], "after the rollback of leaf");
    assert!(
        lock.contains(&format!("overrides:\n{}\n", peer_user.lock_override())),
        "{tag}:\n{lock}"
    );
    assert_eq!(
        read(&ws_path),
        workspace_of(&[peer_user]),
        "{tag}: after the rollback of leaf"
    );
    frozen_install("one-rolled-back", &["peer-user"]);

    // The re-scan routes it again, its registry and its override after
    // the ones that stayed, in the file and in the lock's record alike:
    // pnpm re-locks that without changing a byte either.
    scan();
    assert_routed(
        &read(&lock_path),
        &["leaf", "peer-user"],
        "after the re-scan",
    );
    assert_eq!(
        read(&ws_path),
        workspace_of(&[peer_user, leaf]),
        "{tag}: re-scan"
    );
    pnpm_agrees("rescanned");
    frozen_install("rescanned", &["leaf", "peer-user"]);

    // A grant loses its registry address: the whole project goes back to
    // `trustLockfile`, with nothing of the route left, and the warning
    // names the package.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(route_reference(&server, &["peer-user"])),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    let env = scan();
    assert_eq!(
        read(&ws_path),
        "packages:\n  - '.'\ntrustLockfile: true\n",
        "{tag}: the fall back to trust"
    );
    let lock = read(&lock_path);
    assert_routed(&lock, &[], "after the fall back to trust");
    assert!(
        !lock.contains("@socket-") && !lock.contains("overrides:"),
        "{tag}:\n{lock}"
    );
    assert!(
        env.to_string()
            .contains("the patch service gave no registry address for leaf@1.0.0"),
        "{tag}: {env}"
    );
    frozen_install("trust", &["leaf", "peer-user"]);

    // Everything rolled back: the pristine lock, and no workspace file.
    rollback(&[]);
    assert_eq!(read(&lock_path), lock_before, "{tag}: rollback");
    assert!(
        !ws_path.exists(),
        "{tag}: the file the scan created is gone"
    );
    frozen_install("rolled-back", &[]);
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm installs (~90s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm12_registry_route_survives_resolution_and_cleans_up() {
    registry_route_survives_resolution_and_cleans_up(PNPM_NAMED_REGISTRY, "pnpm12-route").await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm installs (~90s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm11_registry_route_survives_resolution_and_cleans_up() {
    registry_route_survives_resolution_and_cleans_up(PNPM_TERTIARY, "pnpm11-route").await;
}

/// CLEANUP OF THE REGISTRY ROUTE against a real pnpm: once a hosted patch
/// is no longer needed, `scan` and `repair` take every unused entry of the
/// route out, and what they leave is a project pnpm installs frozen.
///
/// A project a hosted scan routed (a peer-dependent package and a
/// transitive leaf, both patched) is checked out once per case, changed
/// with the real pnpm the way a user would, and cleaned:
///
/// * the dependency is removed (`pnpm remove`), then `scan`, `repair
///   --offline` and `scan --prune` each;
/// * the dependency is upgraded past the patched release (`pnpm add
///   <name>@2.0.0`), then `scan` and `repair --offline` each;
/// * every patched dependency is removed while an unpatched one stays,
///   then `scan` and `repair --offline` each: no alias, no override of
///   ours and no registry key is left, and the workspace file the routed
///   scan created is deleted;
/// * the patch of one package is withdrawn, then of both, then `scan`.
///
/// Every command first runs with `--dry-run`, which must leave both files
/// byte for byte. After every wet run pnpm-workspace.yaml and the lock are
/// compared with what is expected, pnpm re-locks them without changing a
/// byte (the lock is the one pnpm writes for that workspace file), and a
/// fresh checkout installs with `--frozen-lockfile` from an empty store.
/// `scan` and `repair` must leave the same bytes: `repair` reads the files
/// alone, with no patch service to reach.
async fn registry_route_is_cleaned_up_when_a_patch_is_not_needed(pm: &str, tag: &str) {
    if !has_corepack_pm(pm) {
        println!("SKIP {tag}: `corepack {pm}` unavailable");
        return;
    }
    let registry = MockServer::start().await;
    mount_route_registry(&registry).await;
    let server = MockServer::start().await;
    mount_route_patch_server(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("pnpm-cache");
    let chatter = |out: &Output| {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    let store = |label: &str| format!("--store-dir={}", tmp.path().join(label).display());
    let read = |path: &Path| std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
    const FILES: [&str; 4] = [
        "package.json",
        "pnpm-lock.yaml",
        "pnpm-workspace.yaml",
        ".npmrc",
    ];
    // The committed files of `from`, in a new directory.
    let copy_of = |from: &Path, label: &str| {
        let to = tmp.path().join(label);
        std::fs::create_dir_all(&to).unwrap();
        for file in FILES {
            if from.join(file).exists() {
                std::fs::copy(from.join(file), to.join(file)).unwrap();
            }
        }
        to
    };
    // The lock and the workspace file (`None` when there is none).
    let state = |dir: &Path| {
        let ws = dir.join("pnpm-workspace.yaml");
        (
            read(&dir.join("pnpm-lock.yaml")),
            ws.exists().then(|| read(&ws)),
        )
    };
    let pnpm = |dir: &Path, label: &str, args: &[&str]| {
        let flag = store(&format!("store-{label}"));
        let mut args = args.to_vec();
        args.push(&flag);
        let out = route_pnpm(&cache, dir, pm, &args);
        assert!(
            out.status.success(),
            "{tag} {label}: pnpm {args:?}:\n{}",
            chatter(&out)
        );
    };

    // ── the routed project ──
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"app","version":"1.0.0","private":true,"dependencies":{"host":"1.0.0","mid":"1.0.0","peer-user":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        proj.join(".npmrc"),
        format!("registry={}/\n", registry.uri()),
    )
    .unwrap();
    let install = route_pnpm(&cache, &proj, pm, &["install", &store("store-fixture")]);
    if !install.status.success() {
        assert!(
            !pnpm_required(),
            "fixture install failed:\n{}",
            chatter(&install)
        );
        println!("SKIP {tag}: fixture install failed:\n{}", chatter(&install));
        return;
    }
    let pristine_lock = read(&proj.join("pnpm-lock.yaml"));
    let env = vec![
        ("SOCKET_PATCH_SERVER_URL".to_string(), server.uri()),
        ("SOCKET_NPM_REGISTRY".to_string(), registry.uri()),
    ];
    let api = server.uri();
    // `scan --mode hosted --json [extra]`, and `repair --offline --json
    // [extra]` pointed at an API address nothing listens on.
    let scan = |dir: &Path, extra: &[&str]| {
        let mut args = vec![
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            dir.to_str().unwrap(),
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ];
        args.extend_from_slice(extra);
        let (code, stdout, stderr) = run_socket_env(dir, &args, &env);
        assert_eq!(
            code, 0,
            "{tag}: scan {extra:?} failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        parse_envelope(&stdout)
    };
    let repair = |dir: &Path, extra: &[&str]| {
        let mut args = vec![
            "repair",
            "--offline",
            "--json",
            "--cwd",
            dir.to_str().unwrap(),
            "--api-url",
            "http://127.0.0.1:9",
        ];
        args.extend_from_slice(extra);
        let (code, stdout, stderr) = run_socket_env(dir, &args, &env);
        assert_eq!(
            code, 0,
            "{tag}: repair {extra:?} failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        parse_envelope(&stdout)
    };
    // How many registry entries the envelope reports as `action`.
    let reported = |doc: &serde_json::Value, action: &str| {
        doc["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|e| e["errorCode"] == "registry_entry_unused" && e["action"] == action)
            .count()
    };
    scan(&proj, &[]);
    let (routed_lock, routed_ws) = state(&proj);
    let [leaf, peer_user] = &ROUTE_PATCHES;
    let workspace_of = |patches: &[&RoutePatch]| {
        let registries: String = patches.iter().map(|p| p.registry_line(&server)).collect();
        let overrides: String = patches.iter().map(|p| p.override_line()).collect();
        format!("packages:\n  - '.'\nnamedRegistries:\n{registries}overrides:\n{overrides}")
    };
    assert_eq!(
        routed_ws.as_deref(),
        Some(workspace_of(&[leaf, peer_user]).as_str()),
        "{tag}: the routed project"
    );
    let leaf_only = workspace_of(&[leaf]);
    // What the lock says of each patch once only leaf is routed.
    let leaf_routed = format!("\n  leaf@{}:\n    resolution: ", leaf.routed_version());
    let leaf_recorded = format!("overrides:\n{}\n", leaf.lock_override());
    let peer_user_key = format!("peer-user@{}", peer_user.routed_version());
    let peer_user_recorded = peer_user.lock_override();

    // A checkout of the routed project with its dependencies installed,
    // then changed by `change` (pnpm arguments) as a user would.
    let checkout = |label: &str, change: &[&str]| {
        let dir = copy_of(&proj, label);
        pnpm(&dir, label, &["install", "--frozen-lockfile"]);
        if !change.is_empty() {
            pnpm(&dir, label, change);
        }
        dir
    };
    // What a cleanup must leave: pnpm re-locks it without changing a byte,
    // and a fresh checkout installs frozen from an empty store, with the
    // patched bytes exactly where `patched` says (`(through, name, patched)`).
    let verified_by_pnpm = |dir: &Path, label: &str, installed: &[(&str, &str, bool)]| {
        let agree = copy_of(dir, &format!("agree-{label}"));
        pnpm(
            &agree,
            &format!("agree-{label}"),
            &["install", "--lockfile-only"],
        );
        assert_eq!(
            read(&agree.join("pnpm-lock.yaml")),
            read(&dir.join("pnpm-lock.yaml")),
            "{tag} {label}: the cleaned lock is the one pnpm resolves from the workspace file"
        );
        let fresh = copy_of(dir, &format!("fresh-{label}"));
        pnpm(
            &fresh,
            &format!("fresh-{label}"),
            &["install", "--frozen-lockfile"],
        );
        for (through, name, patched) in installed {
            let index = installed_index(&fresh, through, name);
            assert_eq!(
                index.starts_with(MARKER),
                *patched,
                "{tag} {label}: {name} installed as:\n{index}"
            );
        }
    };
    // A dry run of `command` lists `entries` removals and leaves both
    // files byte for byte; the wet run lists the same and returns what it
    // left.
    let cleaned = |dir: &Path,
                   label: &str,
                   command: &dyn Fn(&Path, &[&str]) -> serde_json::Value,
                   extra: &[&str],
                   entries: usize| {
        let before = state(dir);
        let mut dry = extra.to_vec();
        dry.push("--dry-run");
        let doc = command(dir, &dry);
        assert_eq!(reported(&doc, "verified"), entries, "{tag} {label}: {doc}");
        assert_eq!(
            state(dir),
            before,
            "{tag} {label}: a dry run writes nothing"
        );
        let doc = command(dir, extra);
        assert_eq!(reported(&doc, "removed"), entries, "{tag} {label}: {doc}");
        assert!(!dir.join(".socket").exists(), "{tag} {label}: no residue");
        (state(dir), doc)
    };

    // ── the dependency was removed ──
    // peer-user is gone from the lock; leaf is still there through mid.
    type Cleaner<'a> = &'a dyn Fn(&Path, &[&str]) -> serde_json::Value;
    let removed_installs = [("mid", "leaf", true)];
    let mut removed_states = Vec::new();
    let removed_cases: [(&str, Cleaner, &[&str]); 3] = [
        ("removed-scan", &scan, &[]),
        ("removed-repair", &repair, &[]),
        ("removed-prune", &scan, &["--prune"]),
    ];
    for (label, command, extra) in removed_cases {
        let dir = checkout(label, &["remove", "peer-user"]);
        let (lock, ws) = state(&dir);
        assert_eq!(
            ws, routed_ws,
            "{tag} {label}: pnpm leaves the workspace file"
        );
        assert!(
            !lock.contains(&peer_user_key) && lock.contains(&peer_user_recorded),
            "{tag} {label}: pnpm dropped the release and still records its override:\n{lock}"
        );
        // The patch's registry, its override, and the lock's record of it.
        let ((lock, ws), doc) = cleaned(&dir, label, command, extra, 3);
        assert_eq!(ws.as_deref(), Some(leaf_only.as_str()), "{tag} {label}");
        assert!(
            lock.contains(&leaf_recorded)
                && !lock.contains("peer-user")
                && lock.contains(&leaf_routed),
            "{tag} {label}:\n{lock}"
        );
        // `repair` and `--prune` count what they removed in `gc`; a plain
        // hosted scan reports no `gc`.
        match label {
            "removed-scan" => assert!(doc.get("gc").is_none(), "{tag}: {doc}"),
            _ => assert_eq!(doc["gc"]["removedRegistryEntries"], 3, "{tag}: {doc}"),
        }
        verified_by_pnpm(&dir, label, &removed_installs);
        removed_states.push((lock, ws));
    }
    assert!(
        removed_states
            .iter()
            .all(|state| *state == removed_states[0]),
        "{tag}: scan, repair and scan --prune leave the same bytes"
    );

    // ── the dependency was upgraded past the patched release ──
    let upgrade = format!("peer-user@{ROUTE_NEXT_VERSION}");
    let upgraded_installs = [("peer-user", "peer-user", false), ("mid", "leaf", true)];
    let mut upgraded_states = Vec::new();
    let upgraded_cases: [(&str, Cleaner); 2] =
        [("upgraded-scan", &scan), ("upgraded-repair", &repair)];
    for (label, command) in upgraded_cases {
        let dir = checkout(label, &["add", &upgrade]);
        let (lock, _) = state(&dir);
        assert!(
            lock.contains(&format!("\n  peer-user@{ROUTE_NEXT_VERSION}:\n"))
                && !lock.contains(&peer_user_key)
                && lock.contains(&peer_user_recorded),
            "{tag} {label}: pnpm resolved the later release from the default registry:\n{lock}"
        );
        let ((lock, ws), _) = cleaned(&dir, label, command, &[], 3);
        assert_eq!(ws.as_deref(), Some(leaf_only.as_str()), "{tag} {label}");
        assert!(
            lock.contains(&leaf_recorded)
                && !lock.contains("peer-user@1.0.0")
                && lock.contains(&format!("\n  peer-user@{ROUTE_NEXT_VERSION}:\n")),
            "{tag} {label}:\n{lock}"
        );
        verified_by_pnpm(&dir, label, &upgraded_installs);
        upgraded_states.push((lock, ws));
    }
    assert_eq!(
        upgraded_states[0], upgraded_states[1],
        "{tag}: scan and repair leave the same bytes"
    );

    // ── no patched dependency is left ──
    // `host`, which has no patch, is still installed and crawled. The file
    // the routed scan created goes with the last of the route, whichever
    // command takes it out.
    let none_cases: [(&str, Cleaner); 2] = [("none-scan", &scan), ("none-repair", &repair)];
    for (label, command) in none_cases {
        let dir = checkout(label, &["remove", "peer-user", "mid"]);
        // Two registries, two overrides, and the lock's record of both.
        let ((lock, ws), _) = cleaned(&dir, label, command, &[], 6);
        assert_eq!(
            ws, None,
            "{tag} {label}: the workspace file the route created is gone"
        );
        assert!(
            !lock.contains("socket") && !lock.contains("overrides:"),
            "{tag} {label}: no registry key and no override record is left:\n{lock}"
        );
        verified_by_pnpm(&dir, label, &[]);
    }

    // ── the patch of one package was withdrawn ──
    // The search no longer lists it, and the reference endpoint says so.
    let listed = |patches: &[&RoutePatch]| -> Vec<serde_json::Value> {
        patches
            .iter()
            .map(|patch| {
                serde_json::json!({
                    "purl": patch.purl(),
                    "patches": [{
                        "uuid": patch.uuid, "purl": patch.purl(), "tier": "free",
                        "cveIds": [], "ghsaIds": [], "severity": "high",
                        "title": "registry route fixture"
                    }]
                })
            })
            .collect()
    };
    let withdraw = |granted: Vec<&'static RoutePatch>, priority: u8| {
        let mut results = route_reference(&server, &["leaf", "peer-user"]);
        for patch in &ROUTE_PATCHES {
            if !granted.iter().any(|kept| kept.uuid == patch.uuid) {
                results["results"][patch.uuid] = serde_json::json!({"status": "withdrawn"});
            }
        }
        let batch = serde_json::json!({
            "packages": listed(&granted),
            "canAccessPaidPatches": false,
        });
        let server = &server;
        async move {
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(ResponseTemplate::new(200).set_body_json(results))
                .with_priority(priority)
                .mount(server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(batch))
                .with_priority(priority)
                .mount(server)
                .await;
        }
    };
    withdraw(vec![leaf], 2).await;
    let dir = checkout("withdrawn-one", &[]);
    let before = state(&dir);
    assert_eq!(before, (routed_lock.clone(), routed_ws.clone()));
    scan(&dir, &["--dry-run"]);
    assert_eq!(state(&dir), before, "{tag}: a dry run writes nothing");
    scan(&dir, &[]);
    let (lock, ws) = state(&dir);
    assert_eq!(
        ws.as_deref(),
        Some(leaf_only.as_str()),
        "{tag} withdrawn-one"
    );
    assert!(
        lock.contains(&leaf_recorded)
            && !lock.contains(&peer_user_key)
            && lock.contains("\n  peer-user@1.0.0:\n    resolution: ")
            && lock.contains(&leaf_routed),
        "{tag} withdrawn-one: the withdrawn release is back on the registry:\n{lock}"
    );
    verified_by_pnpm(
        &dir,
        "withdrawn-one",
        &[("peer-user", "peer-user", false), ("mid", "leaf", true)],
    );

    // ── every patch was withdrawn ──
    withdraw(Vec::new(), 1).await;
    let dir = checkout("withdrawn-all", &[]);
    let before = state(&dir);
    scan(&dir, &["--dry-run"]);
    assert_eq!(state(&dir), before, "{tag}: a dry run writes nothing");
    scan(&dir, &[]);
    assert_eq!(
        state(&dir),
        (pristine_lock.clone(), None),
        "{tag} withdrawn-all: the pristine lock, and no workspace file"
    );
    verified_by_pnpm(
        &dir,
        "withdrawn-all",
        &[("peer-user", "peer-user", false), ("mid", "leaf", false)],
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm installs (~3min); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm12_registry_route_is_cleaned_up_when_a_patch_is_not_needed() {
    registry_route_is_cleaned_up_when_a_patch_is_not_needed(PNPM_NAMED_REGISTRY, "pnpm12-cleanup")
        .await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm installs (~3min); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm11_registry_route_is_cleaned_up_when_a_patch_is_not_needed() {
    registry_route_is_cleaned_up_when_a_patch_is_not_needed(PNPM_TERTIARY, "pnpm11-cleanup").await;
}

/// WHAT PNPM DOES WITH A NEWER RELEASE IN RANGE of a routed one, measured
/// with a real pnpm (the transitive half of the override's reach).
///
/// Two packages depend on `leaf`: one asks for exactly 1.0.0, the other
/// for `^1.0.0` and is locked on 1.5.0. Only 1.0.0 has a patch. The scan
/// routes leaf@1.0.0 and leaves the dependent on 1.5.0 as locked (a lock
/// does not record the range a transitive dependent asked through), and
/// notes that pnpm may move it. Then, with the real pnpm:
///
/// * a frozen install, a plain `pnpm install` and `pnpm install
///   --lockfile-only` take the scan's lock as it is, byte for byte: the
///   dependent keeps 1.5.0;
/// * `pnpm update` and `pnpm dedupe` apply the override to the `^1.0.0`
///   range: leaf@1.5.0 leaves the lock and the dependent installs the
///   patched 1.0.0;
/// * `pnpm add <another package>` does the same on pnpm 11.20 to 11.28 and
///   leaves the dependent on 1.5.0 on pnpm 12.
///
/// The routed release itself is kept by every one of them.
///
/// The leg also pins why an override of the user's cannot hide outside
/// pnpm-workspace.yaml on these releases: `pnpm.overrides` and
/// `resolutions` in package.json are not read (no `overrides:` reaches
/// the lock, and the dependency resolves as without them).
async fn registry_route_reaches_a_newer_release_in_range(pm: &str, tag: &str) {
    if !has_corepack_pm(pm) {
        println!("SKIP {tag}: `corepack {pm}` unavailable");
        return;
    }
    let registry = MockServer::start().await;
    let package = |name, fields| RoutePackage { name, fields };
    mount_registry_package(
        &registry,
        &package("leaf", serde_json::json!({})),
        &[ROUTE_VERSION, "1.5.0"],
        "1.5.0",
    )
    .await;
    for (name, range) in [("pinned-user", "1.0.0"), ("ranged-user", "^1.0.0")] {
        mount_registry_package(
            &registry,
            &package(name, serde_json::json!({"dependencies": {"leaf": range}})),
            &[ROUTE_VERSION],
            ROUTE_VERSION,
        )
        .await;
    }
    mount_registry_package(
        &registry,
        &package("extra", serde_json::json!({})),
        &[ROUTE_VERSION],
        ROUTE_VERSION,
    )
    .await;
    let server = MockServer::start().await;
    mount_route_patch_server(&server).await;
    let leaf = &ROUTE_PATCHES[0];

    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("pnpm-cache");
    let store = |label: &str| format!("--store-dir={}", tmp.path().join(label).display());
    let chatter = |out: &Output| {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    let read = |path: &Path| std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
    let npmrc = format!("registry={}/\n", registry.uri());
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"app","version":"1.0.0","private":true,"dependencies":{"pinned-user":"1.0.0","ranged-user":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(proj.join(".npmrc"), &npmrc).unwrap();
    let install = route_pnpm(&cache, &proj, pm, &["install", &store("store-fixture")]);
    if !install.status.success() {
        assert!(
            !pnpm_required(),
            "fixture install failed:\n{}",
            chatter(&install)
        );
        println!("SKIP {tag}: fixture install failed:\n{}", chatter(&install));
        return;
    }
    let lock_path = proj.join("pnpm-lock.yaml");
    let entry = |lock: &str, key: &str| lock.contains(&format!("\n  {key}:\n    resolution: "));
    let plain = read(&lock_path);
    assert!(
        entry(&plain, "leaf@1.0.0") && entry(&plain, "leaf@1.5.0"),
        "{tag}: the fixture locks both releases:\n{plain}"
    );

    // ── the scan routes 1.0.0 and leaves 1.5.0 as locked, with a note ──
    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &proj, &server.uri(), &[]);
    assert_eq!(code, 0, "{tag}: scan failed.\n{stdout}\n{stderr}");
    let env = parse_envelope(&stdout);
    let routed = read(&lock_path);
    let routed_key = format!("leaf@{}", leaf.routed_version());
    assert!(
        entry(&routed, &routed_key)
            && entry(&routed, "leaf@1.5.0")
            && !entry(&routed, "leaf@1.0.0"),
        "{tag}: after the scan:\n{routed}"
    );
    assert!(
        env.to_string().contains(
            "pnpm-lock.yaml also locks leaf at 1.5.0, which a range that admits 1.0.0 may admit too"
        ),
        "{tag}: the scan notes the release in range: {env}"
    );

    // A person who scans again, with nothing to change, is given the
    // one-line reminder and the note with it: it is the project's state.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--mode",
            "hosted",
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
    assert_eq!(code, 0, "{tag}: re-scan failed.\n{stdout}\n{stderr}");
    let said = stderr.replace('\n', " ");
    let said = said.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        said.contains("already routes them through a named registry")
            && said.contains("also locks leaf at 1.5.0"),
        "{tag}: the reminder carries the note:\n{stderr}"
    );
    assert_eq!(
        read(&lock_path),
        routed,
        "{tag}: the re-scan changes nothing"
    );

    // A copy of what is committed, with real pnpm run over it.
    let checkout = |label: &str| {
        let dir = tmp.path().join(label);
        std::fs::create_dir_all(&dir).unwrap();
        for file in [
            "package.json",
            "pnpm-lock.yaml",
            "pnpm-workspace.yaml",
            ".npmrc",
        ] {
            std::fs::copy(proj.join(file), dir.join(file)).unwrap();
        }
        dir
    };
    let pnpm = |dir: &Path, label: &str, args: &[&str]| {
        let flag = store(&format!("store-{label}"));
        let mut args = args.to_vec();
        args.push(&flag);
        let out = route_pnpm(&cache, dir, pm, &args);
        assert!(
            out.status.success(),
            "{tag} {label}: pnpm {args:?}:\n{}",
            chatter(&out)
        );
    };

    // ── a frozen install takes the lock as it is ──
    let frozen = checkout("frozen");
    pnpm(&frozen, "frozen", &["install", "--frozen-lockfile"]);
    assert!(
        installed_index(&frozen, "pinned-user", "leaf").starts_with(MARKER),
        "{tag}: the dependent on 1.0.0 gets the patched bytes"
    );
    assert_eq!(
        installed_index(&frozen, "ranged-user", "leaf"),
        route_index("leaf", false),
        "{tag}: the dependent locked on 1.5.0 gets 1.5.0"
    );
    assert_eq!(
        read(&frozen.join("pnpm-lock.yaml")),
        routed,
        "{tag}: frozen"
    );

    // ── what each resolving command does with the release in range ──
    // `Some(true)`: the dependent on `^1.0.0` moves to the patched release;
    // `None`: the scan's lock is taken byte for byte. `pnpm add` of another
    // package moves it on pnpm 11 and was measured to leave it on pnpm
    // 12.0.0 through 12.22.0, which a later pnpm 12 may change: there the
    // outcome is printed, not asserted.
    let add = (pm == PNPM_TERTIARY).then_some(true);
    for (label, args, moves) in [
        ("relock", vec!["install", "--lockfile-only"], None),
        ("install", vec!["install"], None),
        ("add", vec!["add", "extra@1.0.0"], add),
        ("update", vec!["update"], Some(true)),
        ("dedupe", vec!["dedupe"], Some(true)),
    ] {
        let dir = checkout(label);
        if label != "relock" {
            pnpm(&dir, label, &["install", "--frozen-lockfile"]);
        }
        pnpm(&dir, label, &args);
        let lock = read(&dir.join("pnpm-lock.yaml"));
        let command = args.join(" ");
        println!(
            "MEASURED {tag} `pnpm {command}`: leaf@1.5.0 {}; lock {}",
            if entry(&lock, "leaf@1.5.0") {
                "kept"
            } else {
                "gone"
            },
            if lock == routed {
                "unchanged"
            } else {
                "changed"
            },
        );
        assert!(
            entry(&lock, &routed_key),
            "{tag} `pnpm {command}`: the routed release stays routed:\n{lock}"
        );
        match moves {
            None if label == "add" => {}
            None => assert_eq!(
                lock, routed,
                "{tag} `pnpm {command}`: the scan's lock is taken as it is"
            ),
            Some(moved) => {
                assert_eq!(
                    !entry(&lock, "leaf@1.5.0"),
                    moved,
                    "{tag} `pnpm {command}`: leaf@1.5.0 must be {}:\n{lock}",
                    if moved { "gone" } else { "kept" }
                );
                assert_eq!(
                    installed_index(&dir, "ranged-user", "leaf").starts_with(MARKER),
                    moved,
                    "{tag} `pnpm {command}`: what the dependent on ^1.0.0 installs"
                );
            }
        }
        assert!(
            installed_index_or_none(&dir, "pinned-user", "leaf")
                .is_none_or(|index| index.starts_with(MARKER)),
            "{tag} `pnpm {command}`: the dependent on 1.0.0 stays patched"
        );
    }

    // ── pnpm no longer reads overrides from package.json ──
    let manifest_overrides = tmp.path().join("manifest-overrides");
    std::fs::create_dir_all(&manifest_overrides).unwrap();
    std::fs::write(
        manifest_overrides.join("package.json"),
        r#"{"name":"app","version":"1.0.0","private":true,"dependencies":{"ranged-user":"1.0.0"},"pnpm":{"overrides":{"leaf":"1.0.0"}},"resolutions":{"leaf":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(manifest_overrides.join(".npmrc"), &npmrc).unwrap();
    pnpm(
        &manifest_overrides,
        "manifest-overrides",
        &["install", "--lockfile-only"],
    );
    let lock = read(&manifest_overrides.join("pnpm-lock.yaml"));
    assert!(
        !lock.contains("\noverrides:\n")
            && entry(&lock, "leaf@1.5.0")
            && !entry(&lock, "leaf@1.0.0"),
        "{tag}: package.json `pnpm.overrides` and `resolutions` are not read, so the lock \
         records no override and the range resolves as without them:\n{lock}"
    );
}

/// [`installed_index`], or `None` where nothing is installed (a
/// lockfile-only run).
fn installed_index_or_none(root: &Path, through: &str, name: &str) -> Option<String> {
    root.join("node_modules")
        .join(through)
        .exists()
        .then(|| installed_index(root, through, name))
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm installs (~1min); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm12_registry_route_reaches_a_newer_release_in_range() {
    registry_route_reaches_a_newer_release_in_range(PNPM_NAMED_REGISTRY, "pnpm12-in-range").await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm installs (~1min); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm11_registry_route_reaches_a_newer_release_in_range() {
    registry_route_reaches_a_newer_release_in_range(PNPM_TERTIARY, "pnpm11-in-range").await;
}

/// A PROJECT ROUTED BEFORE ITS BAZEL WORKSPACE GOT A RULES_JS HUB, with a
/// real pnpm. Hosted mode does not route a lock that a hub reads, so the
/// next scan has to settle the project one of two ways, and a frozen
/// install has to pass afterwards wherever pnpm reads the workspace file:
///
/// * the hub keeps the lock up to date with a pnpm 11 that does not see
///   pnpm-workspace.yaml: the scan leaves the lock to the hub
///   (`redirect_pnpm_bazel_workspace_hidden`) and the route with it, every
///   byte of the lock and of the workspace file as it was, so pnpm still
///   installs the patched release through its registry;
/// * the hub only reads the lock: the scan leaves the route whole, the
///   registry and the override out of the workspace file, the `overrides:`
///   record and the registry keys out of the lock, in one run, and pins the
///   release on `trustLockfile`, which pnpm installs frozen and patched.
async fn registry_route_is_left_for_a_bazel_hub_added_later(pm: &str, tag: &str) {
    if !has_corepack_pm(pm) {
        println!("SKIP {tag}: `corepack {pm}` unavailable");
        return;
    }
    let registry = MockServer::start().await;
    let package = |name, fields| RoutePackage { name, fields };
    mount_registry_package(
        &registry,
        &package("leaf", serde_json::json!({})),
        &[ROUTE_VERSION],
        ROUTE_VERSION,
    )
    .await;
    mount_registry_package(
        &registry,
        &package(
            "pinned-user",
            serde_json::json!({"dependencies": {"leaf": "1.0.0"}}),
        ),
        &[ROUTE_VERSION],
        ROUTE_VERSION,
    )
    .await;
    let server = MockServer::start().await;
    mount_route_patch_server(&server).await;
    let leaf = &ROUTE_PATCHES[0];

    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("pnpm-cache");
    let store = |label: &str| format!("--store-dir={}", tmp.path().join(label).display());
    let chatter = |out: &Output| {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    };
    let read = |path: &Path| std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"app","version":"1.0.0","private":true,"dependencies":{"pinned-user":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        proj.join(".npmrc"),
        format!("registry={}/\n", registry.uri()),
    )
    .unwrap();
    let install = route_pnpm(&cache, &proj, pm, &["install", &store("store-fixture")]);
    if !install.status.success() {
        assert!(
            !pnpm_required(),
            "fixture install failed:\n{}",
            chatter(&install)
        );
        println!("SKIP {tag}: fixture install failed:\n{}", chatter(&install));
        return;
    }
    let entry = |lock: &str, key: &str| lock.contains(&format!("\n  {key}:\n    resolution: "));
    let routed_key = format!("leaf@{}", leaf.routed_version());
    let files = |dir: &Path| {
        (
            read(&dir.join("pnpm-lock.yaml")),
            read(&dir.join("pnpm-workspace.yaml")),
        )
    };

    // ── an earlier run routed the project ──
    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &proj, &server.uri(), &[]);
    assert_eq!(code, 0, "{tag}: scan failed.\n{stdout}\n{stderr}");
    let (routed_lock, routed_workspace) = files(&proj);
    assert!(
        entry(&routed_lock, &routed_key)
            && routed_lock.contains("\noverrides:\n")
            && routed_workspace.contains("namedRegistries:")
            && !routed_workspace.contains("trustLockfile"),
        "{tag}: the first scan routes the release:\n{routed_lock}\n{routed_workspace}"
    );

    let checkout = |from: &Path, label: &str| {
        let dir = tmp.path().join(label);
        std::fs::create_dir_all(&dir).unwrap();
        for file in [
            "package.json",
            "pnpm-lock.yaml",
            "pnpm-workspace.yaml",
            ".npmrc",
        ] {
            std::fs::copy(from.join(file), dir.join(file)).unwrap();
        }
        dir
    };
    let frozen = |dir: &Path, label: &str| {
        let flag = store(&format!("store-{label}"));
        let out = route_pnpm(&cache, dir, pm, &["install", "--frozen-lockfile", &flag]);
        assert!(
            out.status.success(),
            "{tag} {label}: a frozen install:\n{}",
            chatter(&out)
        );
    };
    // The hub of the Bazel workspace, its `npm.npm_translate_lock` on line 3.
    let hub = |more: &str| {
        format!(
            "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
             npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
             npm.npm_translate_lock(pnpm_lock = \"//:pnpm-lock.yaml\"{more})\n\
             pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
             pnpm.pnpm(name = \"pnpm\", pnpm_version = \"11.28.10\")\n"
        )
    };

    // ── a hub that hides the workspace file from its pnpm 11 ──
    let hidden = checkout(&proj, "hidden");
    frozen(&hidden, "hidden");
    std::fs::write(
        hidden.join("MODULE.bazel"),
        hub(", update_pnpm_lock = True"),
    )
    .unwrap();
    let before = files(&hidden);
    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &hidden, &server.uri(), &[]);
    assert_eq!(code, 0, "{tag}: scan failed.\n{stdout}\n{stderr}");
    let env = parse_envelope(&stdout);
    assert!(
        env.to_string()
            .contains("redirect_pnpm_bazel_workspace_hidden"),
        "{tag}: the scan leaves the lock to the hub: {env}"
    );
    assert_eq!(
        files(&hidden),
        before,
        "{tag}: the route stays as it was, the lock and the workspace file alike"
    );
    assert!(entry(&before.0, &routed_key), "{tag}:\n{}", before.0);
    let hidden_fresh = checkout(&hidden, "hidden-fresh");
    frozen(&hidden_fresh, "hidden-fresh");
    assert!(
        installed_index(&hidden_fresh, "pinned-user", "leaf").starts_with(MARKER),
        "{tag}: the routed release still installs patched"
    );

    // ── a hub that reads the lock ──
    std::fs::write(proj.join("MODULE.bazel"), hub("")).unwrap();
    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &proj, &server.uri(), &[]);
    assert_eq!(code, 0, "{tag}: scan failed.\n{stdout}\n{stderr}");
    let env = parse_envelope(&stdout);
    let (lock, workspace) = files(&proj);
    assert!(
        entry(&lock, "leaf@1.0.0")
            && !lock.contains("@socket-")
            && !lock.contains("\noverrides:\n")
            && lock.contains(&leaf.tarball_path()),
        "{tag}: the lock is back in the plain shape, pinned:\n{lock}"
    );
    assert_eq!(
        workspace, "packages:\n  - '.'\ntrustLockfile: true\n",
        "{tag}: the route's entries leave the workspace file with the lock's"
    );
    assert!(
        env.to_string()
            .contains("a Bazel hub reads the pnpm lock (MODULE.bazel:3)"),
        "{tag}: the warning names the call: {env}"
    );
    let left = checkout(&proj, "left");
    frozen(&left, "left");
    assert!(
        installed_index(&left, "pinned-user", "leaf").starts_with(MARKER),
        "{tag}: the pinned release installs patched"
    );
    assert_eq!(
        read(&left.join("pnpm-lock.yaml")),
        lock,
        "{tag}: pnpm takes the lock as the scan left it"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm installs (~1min); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm12_registry_route_is_left_for_a_bazel_hub_added_later() {
    registry_route_is_left_for_a_bazel_hub_added_later(PNPM_NAMED_REGISTRY, "pnpm12-bazel-hub")
        .await;
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm installs (~1min); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm11_registry_route_is_left_for_a_bazel_hub_added_later() {
    registry_route_is_left_for_a_bazel_hub_added_later(PNPM_TERTIARY, "pnpm11-bazel-hub").await;
}

/// #1074: with pnpm's `lockfile` setting off, pnpm neither reads nor
/// writes `pnpm-lock.yaml` and installs the upstream package from the
/// registry, so a hosted pin in the committed lock patches nothing. Over a
/// lock the real pnpm 11 scan pinned, once `lockfile: false` lands in
/// `pnpm-workspace.yaml`:
///
/// * a re-run of `scan --mode hosted` refuses with
///   `redirect_pnpm_lockfile_disabled` and leaves the lock and the
///   workspace file byte-for-byte;
/// * lock-only `vex` (no node_modules, no manifest, no ledgers: the CI/SBOM
///   case) no longer attests the patch from the lock pin.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm11_disabled_lockfile_is_neither_pinned_nor_attested() {
    let Some(fx) = redirect_scanned_pnpm_project(
        PNPM_TERTIARY,
        "pnpm11-lockfile-off",
        false,
        false,
        HostedDriver::Scan,
    )
    .await
    else {
        return;
    };
    let ws_path = fx.proj.join("pnpm-workspace.yaml");
    let mut workspace = std::fs::read_to_string(&ws_path).unwrap_or_default();
    if !workspace.is_empty() && !workspace.ends_with('\n') {
        workspace.push('\n');
    }
    workspace.push_str("lockfile: false\n");
    std::fs::write(&ws_path, &workspace).unwrap();
    let lock_path = fx.proj.join(&fx.lock_name);
    let lock_wired = std::fs::read_to_string(&lock_path).unwrap();
    assert_ne!(
        lock_wired, fx.lock_before,
        "the fixture scan pinned the lock"
    );

    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &fx.proj, &fx._server.uri(), &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = parse_envelope(&stdout);
    assert_eq!(env["summary"]["applied"], 0, "{env}");
    let codes = warning_codes(&env);
    assert!(
        codes.contains(&"redirect_pnpm_lockfile_disabled".to_string())
            && !codes.contains(&"redirect_pnpm_trust_lockfile".to_string()),
        "{codes:?}\n{env}"
    );
    assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), lock_wired);
    assert_eq!(std::fs::read_to_string(&ws_path).unwrap(), workspace);

    // A lock-only checkout: package.json, the pinned lock and the workspace
    // file pnpm reads the setting from, nothing installed.
    let fresh = fx.tmp.path().join("fresh-lockfile-off");
    std::fs::create_dir_all(&fresh).unwrap();
    for file in ["package.json", fx.lock_name.as_str(), "pnpm-workspace.yaml"] {
        std::fs::copy(fx.proj.join(file), fresh.join(file)).unwrap();
    }
    let patch_server = fx._server.uri();
    off_runtime(|| {
        let api = hosted_patch_api(PURL, &fx.patched);
        let out = run_vex(
            &socket_bin(),
            &fresh,
            &VexRun {
                patch_server_url: Some(patch_server.clone()),
                ..VexRun::online(&api)
            },
        );
        assert_ne!(out.code, Some(0), "lock-only vex must not attest: {out}");
        assert_absent(out.doc.as_ref(), PURL);

        // Control: the same checkout with the setting removed attests.
        std::fs::remove_file(fresh.join("pnpm-workspace.yaml")).unwrap();
        let out = run_vex(
            &socket_bin(),
            &fresh,
            &VexRun {
                patch_server_url: Some(patch_server.clone()),
                ..VexRun::online(&api)
            },
        );
        assert_eq!(out.code, Some(0), "control: {out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, HOSTED_VULNS);
    });
}

/// `--no-trust-lockfile-config` control: pins the opt-out (the scan writes
/// no pnpm-workspace.yaml — asserted inside the fixture helper) AND the old
/// behavior it restores. Without the trust config the PLAIN frozen install
/// fails against the dead registry — with ERR_PNPM_META_FETCH_FAIL, not the
/// live-registry-only ERR_PNPM_TARBALL_URL_MISMATCH, so only the ERR_PNPM
/// family and the non-zero exit are asserted (and no claim is made about the
/// marker: pnpm downloads the hosted tarball before the policy check fails).
/// The manual `--trust-lockfile` flag recovery must then succeed against the
/// same dead registry and land the marker bytes.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm11_no_trust_config_opt_out_frozen_install_needs_manual_trust_lockfile() {
    let Some(fx) = redirect_scanned_pnpm_project(
        PNPM_TERTIARY,
        "pnpm11-opt-out",
        false,
        true,
        HostedDriver::Scan,
    )
    .await
    else {
        return;
    };

    let (_fresh, plain) =
        fresh_checkout_install(&fx, PNPM_TERTIARY, "pnpm11-opt-out-plain", &[], false);
    assert!(
        !plain.status.success(),
        "pnpm 11's lockfile policy must reject the plain frozen install against a dead \
         registry when the scan was opted out of the trustLockfile config.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&plain.stdout),
        String::from_utf8_lossy(&plain.stderr),
    );
    let chatter = format!(
        "{}\n{}",
        String::from_utf8_lossy(&plain.stdout),
        String::from_utf8_lossy(&plain.stderr)
    );
    assert!(
        chatter.contains("ERR_PNPM"),
        "the plain-install failure must be a pnpm error, not something incidental:\n{chatter}"
    );

    // Manual recovery: the per-run flag, exactly as the warning detail says.
    let (fresh, trusted) = fresh_checkout_install(
        &fx,
        PNPM_TERTIARY,
        "pnpm11-opt-out-trust",
        &["--trust-lockfile"],
        false,
    );
    assert_marker_landed(&fresh, &fx.patched, &trusted, "pnpm11 --trust-lockfile");
    assert_fixture_manifestless_vex(&fx, &fresh, "pnpm11 --trust-lockfile");
}

/// #1514: pnpm 11+ read `pnpm_config_trust_lockfile` ahead of
/// pnpm-workspace.yaml, so a scan whose environment sets it to `false` must
/// not write a `trustLockfile: true` that installs there ignore, nor claim
/// they need no extra flags. Over a lock the real pnpm 11 scan pinned
/// without the trust config, a re-run in that environment (the heal path,
/// which would otherwise write the key) writes no workspace file and names
/// the variable in the trust warning.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm11_trust_lockfile_env_override_is_respected() {
    let Some(fx) = redirect_scanned_pnpm_project(
        PNPM_TERTIARY,
        "pnpm11-trust-env",
        false,
        true,
        HostedDriver::Scan,
    )
    .await
    else {
        return;
    };
    let ws_path = fx.proj.join("pnpm-workspace.yaml");
    assert!(
        !ws_path.exists(),
        "the opted-out fixture scan wrote no workspace file"
    );
    let lock_path = fx.proj.join(&fx.lock_name);
    let lock_wired = std::fs::read_to_string(&lock_path).unwrap();

    let api_url = fx._server.uri();
    let args = [
        "scan",
        "--mode",
        "hosted",
        "--json",
        "--yes",
        "--cwd",
        fx.proj.to_str().unwrap(),
        "--api-url",
        &api_url,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    let env = [(
        "pnpm_config_trust_lockfile".to_string(),
        "false".to_string(),
    )];
    let (code, stdout, stderr) = run_socket_env(&fx.proj, &args, &env);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope = parse_envelope(&stdout);
    assert!(
        !ws_path.exists(),
        "a trustLockfile key the environment overrides must not be written:\n{envelope}"
    );
    assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), lock_wired);
    let detail = envelope["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|w| w["code"] == "redirect_pnpm_trust_lockfile")
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_else(|| panic!("redirect_pnpm_trust_lockfile:\n{envelope}"))
        .to_string();
    assert!(
        detail.contains("`pnpm_config_trust_lockfile=false`") && !detail.contains("no extra flags"),
        "{detail}"
    );

    // Control: the same re-run without the variable heals the config.
    let (code, stdout, stderr) = run_socket_env(&fx.proj, &args, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let workspace = std::fs::read_to_string(&ws_path).unwrap_or_default();
    assert!(workspace.contains("trustLockfile: true"), "{workspace}");
}

/// #1557: pnpm 11+ ignore a `pnpm_config_trust_lockfile` that is not
/// exactly `true` or `false`, such as the empty string `${{ vars.X }}`
/// exports when the repo variable is unset, and read pnpm-workspace.yaml
/// instead. A scan whose
/// environment sets it so must heal the trust config as if it were unset,
/// and a fresh frozen install in that same environment then lands the
/// patched bytes from the written key.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm11_empty_trust_lockfile_env_is_ignored() {
    let Some(fx) = redirect_scanned_pnpm_project(
        PNPM_TERTIARY,
        "pnpm11-trust-env-empty",
        false,
        true,
        HostedDriver::Scan,
    )
    .await
    else {
        return;
    };
    let ws_path = fx.proj.join("pnpm-workspace.yaml");
    assert!(
        !ws_path.exists(),
        "the opted-out fixture scan wrote no workspace file"
    );

    let api_url = fx._server.uri();
    let args = [
        "scan",
        "--mode",
        "hosted",
        "--json",
        "--yes",
        "--cwd",
        fx.proj.to_str().unwrap(),
        "--api-url",
        &api_url,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    let env = [("pnpm_config_trust_lockfile".to_string(), String::new())];
    let (code, stdout, stderr) = run_socket_env(&fx.proj, &args, &env);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let envelope = parse_envelope(&stdout);
    let workspace = std::fs::read_to_string(&ws_path).unwrap_or_default();
    assert!(
        workspace.contains("trustLockfile: true"),
        "an empty variable pnpm ignores must not stop the write:\n{envelope}"
    );
    let detail = envelope["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|w| w["code"] == "redirect_pnpm_trust_lockfile")
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_else(|| panic!("redirect_pnpm_trust_lockfile:\n{envelope}"))
        .to_string();
    assert!(
        detail.contains("no extra flags") && !detail.contains("in the environment"),
        "the warning must not claim the empty variable was respected:\n{detail}"
    );

    // pnpm itself, run with the same empty variable, honours the key.
    let (fresh, ci) = fresh_checkout_install_env(
        &fx,
        PNPM_TERTIARY,
        "pnpm11-trust-env-empty",
        &[],
        true,
        &[("pnpm_config_trust_lockfile", "")],
    );
    assert_marker_landed(&fresh, &fx.patched, &ci, "pnpm11 empty trust env");
}

/// Legacy pnpm@7 leg: the fixture install emits a lockfileVersion 5.4 lock
/// (`/name/version:` path-style key), the scan splices its resolution like
/// any other grammar, and the fresh dead-registry frozen install proves
/// pnpm 7 fetches the hosted tarball from the spliced entry and enforces the
/// sha512 pin (empty store, marker bytes land).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm7_v5_lock_redirect_fresh_checkout_frozen_install_lands_patched_bytes() {
    let Some(fx) =
        redirect_scanned_pnpm_project(PNPM_LEGACY_V5, "pnpm7", false, false, HostedDriver::Scan)
            .await
    else {
        return;
    };
    let lock = std::fs::read_to_string(fx.proj.join("pnpm-lock.yaml")).unwrap();
    assert!(
        lock.starts_with("lockfileVersion: 5.4")
            && lock.contains(&format!("/{DEP}/{DEP_VERSION}:")),
        "anchor: pnpm@7 must have emitted a v5.4 path-style lock; got:\n{lock}"
    );
    let (fresh, ci) = fresh_checkout_install(&fx, PNPM_LEGACY_V5, "pnpm7", &[], false);
    assert_marker_landed(&fresh, &fx.patched, &ci, "pnpm7");
    assert_fixture_manifestless_vex(&fx, &fresh, "pnpm7");
}

/// Legacy pnpm@8 leg: same chain over the lockfileVersion 6.0 grammar
/// (`/name@version:` key). pnpm 8 has no lockfile supply-chain policy, so the
/// plain frozen install must succeed against the dead registry.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm8_v6_lock_redirect_fresh_checkout_frozen_install_lands_patched_bytes() {
    let Some(fx) =
        redirect_scanned_pnpm_project(PNPM_LEGACY_V6, "pnpm8", false, false, HostedDriver::Scan)
            .await
    else {
        return;
    };
    let lock = std::fs::read_to_string(fx.proj.join("pnpm-lock.yaml")).unwrap();
    assert!(
        lock.starts_with("lockfileVersion: '6.0'")
            && lock.contains(&format!("/{DEP}@{DEP_VERSION}:")),
        "anchor: pnpm@8 must have emitted a v6 lock; got:\n{lock}"
    );
    let (fresh, ci) = fresh_checkout_install(&fx, PNPM_LEGACY_V6, "pnpm8", &[], false);
    assert_marker_landed(&fresh, &fx.patched, &ci, "pnpm8");
    assert_fixture_manifestless_vex(&fx, &fresh, "pnpm8");
}

// ── synthetic legs (hermetic — no pnpm binary, never ignored) ─────────

/// Required CI matrix: unlike the opportunistic capstones above, a missing
/// toolchain or failed fixture is a failure. The job provisions each pnpm
/// major with a compatible Node version and passes its absolute executable.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "requires the pinned pnpm matrix toolchain"]
async fn pnpm_pinned_matrix_install_verify_revert_and_tamper() {
    let version = std::env::var("SOCKET_PATCH_PNPM_E2E_VERSION")
        .expect("set SOCKET_PATCH_PNPM_E2E_VERSION to the exact pnpm version");
    let pm = format!("pnpm@{version}");
    let fx = redirect_scanned_pnpm_project(&pm, &version, false, false, HostedDriver::Scan).await;
    if version == "1.0.0" {
        assert!(fx.is_none(), "the unsafe legacy format must be refused");
        return;
    }
    let fx = fx.expect("required matrix fixture must not skip");
    let warm_store = format!("--store-dir={}", fx.tmp.path().join("pnpm-store").display());
    let warm = corepack(
        &fx.proj,
        &pm,
        &["install", "--frozen-lockfile", &warm_store],
    );
    assert!(warm.status.success(), "warm install failed: {warm:?}");
    let installed = std::fs::read(fx.proj.join("node_modules").join(DEP).join("index.js")).unwrap();
    let (vex_code, _, _) = vex_online(&fx.proj, &fx._server.uri());
    assert_eq!(
        vex_code == 0,
        installed == fx.patched,
        "a successful pnpm install must not cause VEX to attest stale files"
    );
    // A lock-only edit does not invalidate every pnpm major's warm cache.
    // The cross-version recovery is a clean tree AND a new empty store;
    // --force alone is not sufficient (and pnpm 12 re-resolves upstream).
    std::fs::remove_dir_all(fx.proj.join("node_modules")).unwrap();
    let clean_store = format!(
        "--store-dir={}",
        fx.tmp.path().join("clean-store").display()
    );
    let clean = corepack(
        &fx.proj,
        &pm,
        &["install", "--frozen-lockfile", &clean_store],
    );
    assert_marker_landed(
        &fx.proj,
        &fx.patched,
        &clean,
        &format!("{version} clean reinstall"),
    );
    let with_workspace = fx.proj.join("pnpm-workspace.yaml").exists();
    let (fresh, install) = fresh_checkout_install(&fx, &pm, "matrix", &[], with_workspace);
    assert_marker_landed(&fresh, &fx.patched, &install, &version);

    // Local evidence of remediation: the default VEX path verifies installed
    // hashes. This deliberately makes no assertion about dashboard alerts.
    let (code, stdout, stderr) = vex_online(&fresh, &fx._server.uri());
    assert_eq!(code, 0, "verified VEX failed: {stdout}\n{stderr}");
    let vex: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(vex["statements"][0]["status"], "not_affected", "{vex}");
    assert_eq!(vex["statements"][0]["vulnerability"]["name"], GHSA, "{vex}");
    // Manifest-less VEX: ledger kept / ledgers deleted / offline / reverted
    // lock / embedded `scan --mode hosted --vex`, over this real install.
    assert_fixture_manifestless_vex(&fx, &fresh, &version);

    // An ordinary install must also preserve the patch. Use a new store so
    // a warm cache cannot disguise an upstream re-resolution.
    let store_flag = format!(
        "--store-dir={}",
        fx.tmp.path().join("ordinary-store").display()
    );
    std::fs::remove_dir_all(fresh.join("node_modules")).unwrap();
    let ordinary = corepack(&fresh, &pm, &["install", &store_flag]);
    assert_marker_landed(&fresh, &fx.patched, &ordinary, &version);

    // Revert committed wiring without an installed tree: no in-place patch
    // reversal or blob fetching can hide a lock/trust-setting rollback bug.
    // v5: the upstream restore re-resolves the registry integrity (a mirror
    // of the pristine lock's), with the mock origin named the patch server.
    std::fs::remove_dir_all(fx.proj.join("node_modules")).unwrap();
    let unwind = unwind_env(&fx._server, &fx.lock_before).await;
    let (code, stdout, stderr) =
        run_socket_env(&fx.proj, &["rollback", "--yes", "--json"], &unwind);
    assert_eq!(code, 0, "rollback failed: {stdout}\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(fx.proj.join(&fx.lock_name)).unwrap(),
        fx.lock_before
    );
    // The same project must be discoverable from just its lockfile in a
    // fresh checkout, including the legacy shrinkwrap filename.
    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &fx.proj, &fx._server.uri(), &[]);
    assert_eq!(code, 0, "lock-only scan failed: {stdout}\n{stderr}");
    assert_eq!(parse_envelope(&stdout)["summary"]["applied"], 1);

    // Every major must reject a hosted tarball whose bytes disagree with its
    // lockfile pin, even when pnpm >=11 uses trustLockfile.
    let tampered = redirect_scanned_pnpm_project(&pm, &version, true, false, HostedDriver::GetUuid)
        .await
        .expect("required tamper fixture must not skip");
    let with_workspace = tampered.proj.join("pnpm-workspace.yaml").exists();
    let (fresh, install) = fresh_checkout_install(&tampered, &pm, "tampered", &[], with_workspace);
    assert!(
        !install.status.success(),
        "{version} accepted a tampered tarball"
    );
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    assert!(
        ["integrity", "checksum"]
            .iter()
            .any(|word| output.to_ascii_lowercase().contains(word)),
        "unexpected failure: {output}"
    );
    assert!(
        !fresh
            .join("node_modules")
            .join(DEP)
            .join("index.js")
            .exists(),
        "tampered bytes were linked"
    );
}

/// The env an unwind of a hosted pnpm pin runs with: `server` named the
/// patch server (so its tarball URL counts as a hosted pin — v5 keeps no
/// ledger) and an npm registry mirror under `<server>/registry` serving
/// `left-pad@1.3.0`'s version document with the integrity `lock_before`
/// (the pristine lock) recorded — all the v5 upstream restore reads.
async fn unwind_env(server: &MockServer, lock_before: &str) -> Vec<(String, String)> {
    unwind_env_for(server, &server.uri(), lock_before).await
}

/// [`unwind_env`] with the hosted origin given explicitly (the synthetic
/// legs pin `https://patch.test`, not the mock server's own origin).
async fn unwind_env_for(
    server: &MockServer,
    patch_origin: &str,
    lock_before: &str,
) -> Vec<(String, String)> {
    let integrity = regex::Regex::new(r"integrity: (sha512-[A-Za-z0-9+/=]+)")
        .unwrap()
        .captures(lock_before)
        .map(|c| c[1].to_string())
        .unwrap_or_else(|| panic!("no integrity in the pristine lock:\n{lock_before}"));
    Mock::given(method("GET"))
        .and(path(format!("/registry/{DEP}/{DEP_VERSION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": DEP,
            "version": DEP_VERSION,
            "dist": {
                "tarball": format!("https://registry.npmjs.org/{DEP}/-/{DEP}-{DEP_VERSION}.tgz"),
                "integrity": integrity
            }
        })))
        .mount(server)
        .await;
    vec![
        (
            "SOCKET_PATCH_SERVER_URL".to_string(),
            patch_origin.to_string(),
        ),
        (
            "SOCKET_NPM_REGISTRY".to_string(),
            format!("{}/registry", server.uri()),
        ),
    ]
}

/// v5 unwind of a synthetic-leg hosted pin: `rollback` restores the
/// upstream resolution from the registry mirror — the lock lands back on
/// `pristine` byte for byte — and no ledger appears at any point.
async fn assert_rollback_restores_pristine(server: &MockServer, root: &Path, pristine: &str) {
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "hosted mode writes no redirect ledger"
    );
    let unwind = unwind_env_for(server, "https://patch.test", pristine).await;
    let (code, stdout, stderr) = run_socket_env(
        root,
        &[
            "rollback",
            "--yes",
            "--json",
            "--cwd",
            root.to_str().unwrap(),
        ],
        &unwind,
    );
    assert_eq!(
        code, 0,
        "rollback failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap(),
        pristine,
        "rollback restores the upstream resolution byte for byte"
    );
    assert!(!root.join(".socket/vendor/redirect-state.json").exists());
}

/// `vex` over `cwd`, ONLINE: v5 keeps no hosted ledger, so the patch record
/// comes from the patch API (`server_uri`, which is also the patch-server
/// origin the lock's hosted URL lives on). The installed tree is still
/// hash-verified.
fn vex_online(cwd: &Path, server_uri: &str) -> (i32, String, String) {
    run_socket(
        cwd,
        &[
            "vex",
            "--product",
            "pkg:npm/consumer@0.0.0",
            "--api-url",
            server_uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            server_uri,
        ],
    )
}

/// A project whose only lockfile is the synthesized `lock`, with an installed
/// node_modules stub so the crawler discovers the dep (a real pnpm project
/// always has one).
fn write_synthetic_project(root: &Path, lock: &str) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{DEP}": "{DEP_VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(DEP);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{DEP}", "version": "{DEP_VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(root.join("pnpm-lock.yaml"), lock).unwrap();
}

/// Byte-accurate pnpm 7 (lockfileVersion 5.4) lock, copied from the matrix
/// sweep's hosted-pnpm7 fixture: unquoted `5.4`, `/name/version:` package
/// key, `specifiers:` section, `dev: false` flag.
fn v5_lock() -> String {
    format!(
        "lockfileVersion: 5.4

specifiers:
  {DEP}: {DEP_VERSION}

dependencies:
  {DEP}: {DEP_VERSION}

packages:

  /{DEP}/{DEP_VERSION}:
    resolution: {{integrity: {UPSTREAM_SHA512}}}
    deprecated: use String.prototype.padStart()
    dev: false
"
    )
}

/// Byte-accurate pnpm 8 (lockfileVersion '6.0') lock from the matrix sweep's
/// hosted-pnpm8 fixture: quoted `'6.0'`, `/name@version:` package key.
fn v6_lock() -> String {
    format!(
        "lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  {DEP}:
    specifier: {DEP_VERSION}
    version: {DEP_VERSION}

packages:

  /{DEP}@{DEP_VERSION}:
    resolution: {{integrity: {UPSTREAM_SHA512}}}
    deprecated: use String.prototype.padStart()
    dev: false
"
    )
}

/// pnpm v5.x lock keys (`/name/version:`) are inside the redirect grammar:
/// the resolution is spliced in place with the path-style key and every
/// sibling line (`deprecated:`, `dev:`) byte-preserved — proven installable
/// by the gated pnpm@7 leg above (matrix: hosted-pnpm7, live splice-install
/// verification 2026-08-18).
#[tokio::test(flavor = "multi_thread")]
async fn pnpm_v5_lock_key_rewrite_splices_in_place() {
    let server = MockServer::start().await;
    let hosted_url = hosted_url_for("https://patch.test");
    mount_api_mocks(
        &server,
        &hosted_url,
        PATCHED_SHA512,
        &"a".repeat(64),
        &"b".repeat(64),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_synthetic_project(tmp.path(), &v5_lock());
    let lock_path = tmp.path().join("pnpm-lock.yaml");

    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, tmp.path(), &server.uri(), &[]);
    assert_eq!(
        code, 0,
        "scan --mode hosted failed on the v5 lock.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["summary"]["applied"], 1,
        "the v5 path-style key must be redirectable: {env}"
    );
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        serde_json::json!(["pnpm-lock.yaml"]),
        "the v5 lock must be the rewritten file: {env}"
    );
    assert!(
        warning_codes(&env).contains(&"redirect_pnpm_trust_lockfile".to_string()),
        "a landed v5 rewrite must still carry the install guidance: {env}"
    );

    // The spliced block, byte-exact: the `/name/version:` key keeps its
    // path-style shape, the resolution carries {integrity, tarball}, and the
    // sibling lines survive untouched.
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    let spliced = format!(
        "  /{DEP}/{DEP_VERSION}:\n    resolution: {{integrity: {PATCHED_SHA512}, tarball: {hosted_url}}}\n    deprecated: use String.prototype.padStart()\n    dev: false\n"
    );
    assert!(
        lock_after.contains(&spliced),
        "the v5 packages entry must be spliced in place; want:\n{spliced}\ngot:\n{lock_after}"
    );
    assert!(
        !lock_after.contains(UPSTREAM_SHA512),
        "the upstream integrity must be replaced; got:\n{lock_after}"
    );

    // The unwind: no ledger preserves the original — rollback re-resolves
    // the upstream integrity and splices it back in place.
    assert_rollback_restores_pristine(&server, tmp.path(), &v5_lock()).await;
}

/// pnpm v6 PLAIN lock keys (`/name@version:` with no peer suffix) stay inside
/// the redirect grammar — verified against a real pnpm 8 install in the
/// matrix sweep (hosted-pnpm8): the resolution is spliced in place with its
/// sibling lines (`deprecated:`, `dev:`) byte-preserved.
#[tokio::test(flavor = "multi_thread")]
async fn pnpm_v6_plain_lock_key_rewrite_stays_supported() {
    let server = MockServer::start().await;
    let hosted_url = hosted_url_for("https://patch.test");
    mount_api_mocks(
        &server,
        &hosted_url,
        PATCHED_SHA512,
        &"a".repeat(64),
        &"b".repeat(64),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_synthetic_project(tmp.path(), &v6_lock());
    let lock_path = tmp.path().join("pnpm-lock.yaml");

    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, tmp.path(), &server.uri(), &[]);
    assert_eq!(
        code, 0,
        "scan --mode hosted failed on the v6 lock.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["summary"]["applied"], 1,
        "the plain v6 key must stay redirectable: {env}"
    );
    assert_eq!(
        env["redirect"]["rewrittenFiles"],
        serde_json::json!(["pnpm-lock.yaml"]),
        "the v6 lock must be the rewritten file: {env}"
    );
    assert!(
        warning_codes(&env).contains(&"redirect_pnpm_trust_lockfile".to_string()),
        "a landed v6 rewrite must still carry the install guidance: {env}"
    );

    // The trust AUTO-CONFIG must NOT fire for a legacy lock: the gate is
    // lock-major >= 9, and a 6.0 lock means pnpm 8 — no lockfile policy, no
    // trustLockfile setting (pnpm 7/8 reject the flag spelling too, so the
    // warning must NOT recommend `--trust-lockfile`: it gets the legacy
    // installs-work-unchanged guidance instead). No workspace file appears.
    assert!(
        !tmp.path().join("pnpm-workspace.yaml").exists(),
        "a v6-lock scan must not auto-write pnpm-workspace.yaml: {env}"
    );
    let v6_detail = env["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "redirect_pnpm_trust_lockfile")
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_default();
    assert!(
        !v6_detail.contains("trust-lockfile"),
        "the legacy-lock warning must not recommend --trust-lockfile (pnpm 7/8 \
         reject the flag as unknown); got: {v6_detail}"
    );
    assert!(
        v6_detail.contains("pnpm 1–8") && v6_detail.contains("no trust step"),
        "the legacy-lock warning must say installs work unchanged on pnpm 7/8; \
         got: {v6_detail}"
    );

    // The spliced block, byte-exact: the `/name@version:` key keeps its
    // shape, the resolution carries {integrity, tarball}, and the sibling
    // lines survive untouched.
    let lock_after = std::fs::read_to_string(&lock_path).unwrap();
    let spliced = format!(
        "  /{DEP}@{DEP_VERSION}:\n    resolution: {{integrity: {PATCHED_SHA512}, tarball: {hosted_url}}}\n    deprecated: use String.prototype.padStart()\n    dev: false\n"
    );
    assert!(
        lock_after.contains(&spliced),
        "the v6 packages entry must be spliced in place; want:\n{spliced}\ngot:\n{lock_after}"
    );
    assert!(
        !lock_after.contains(UPSTREAM_SHA512),
        "the upstream integrity must be replaced; got:\n{lock_after}"
    );

    // The unwind: no ledger preserves the original — rollback re-resolves
    // the upstream integrity and splices it back in place.
    assert_rollback_restores_pristine(&server, tmp.path(), &v6_lock()).await;
}

/// Real pnpm workspace graph with a scoped target, an npm alias, two peer
/// contexts and peers-of-peers. Registry/API/tarballs are local so this test
/// validates graph handling without depending on upstream package metadata.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "requires the pinned pnpm matrix toolchain"]
async fn pnpm_pinned_matrix_workspace_peer_instances() {
    let version = std::env::var("SOCKET_PATCH_PNPM_E2E_VERSION").unwrap();
    let major: u32 = version.split('.').next().unwrap().parse().unwrap();
    if major < 6 {
        // The required single-package test above covers these older majors;
        // this fixture exercises the three modern workspace lock grammars.
        return;
    }
    let pm = format!("pnpm@{version}");
    assert!(has_corepack_pm(&pm));
    const TARGET: &str = "@fixture/left-pad";
    const TARGET_PURL: &str = "pkg:npm/@fixture/left-pad@1.3.0";
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("workspace");
    std::fs::create_dir_all(&proj).unwrap();
    let original = b"module.exports = 'original';\n";
    let patched = [MARKER.as_bytes(), original.as_slice()].concat();
    let mut patched_tarball = Vec::new();
    for (name, versions, peers) in [
        (
            TARGET,
            vec!["1.3.0"],
            serde_json::json!({"e2e-middle": "*", "e2e-leaf": "*"}),
        ),
        (
            "e2e-middle",
            vec!["1.0.0"],
            serde_json::json!({"e2e-leaf": "*"}),
        ),
        ("e2e-leaf", vec!["1.0.0", "2.0.0"], serde_json::json!({})),
    ] {
        let mut metadata = serde_json::json!({"name":name,"dist-tags":{"latest": versions.last().unwrap()},"versions":{}});
        for version in versions {
            let package = tmp.path().join("pack");
            std::fs::create_dir_all(&package).unwrap();
            let manifest = serde_json::json!({"name":name,"version":version,"main":"index.js","peerDependencies":peers});
            std::fs::write(package.join("package.json"), manifest.to_string()).unwrap();
            std::fs::write(package.join("index.js"), original).unwrap();
            let tgz = make_tgz_from_installed(&package, original);
            if name == TARGET {
                patched_tarball = make_tgz_from_installed(&package, &patched);
            }
            let route = format!(
                "/{name}/-/{}-{version}.tgz",
                name.rsplit('/').next().unwrap()
            );
            let mut record = manifest;
            record["dist"] = serde_json::json!({"tarball":format!("{}{route}",server.uri()),"integrity":format!("sha512-{}",sha512_sri_b64(&tgz))});
            metadata["versions"][version] = record;
            Mock::given(method("GET"))
                .and(path(&route))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz))
                .mount(&server)
                .await;
        }
        let route = if name == TARGET {
            "(?i)^/(?:@|%40)fixture(?:/|%2f)left-pad$".to_string()
        } else {
            format!("^/{name}$")
        };
        Mock::given(method("GET"))
            .and(path_regex(route))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(&server)
            .await;
    }
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"workspace-fixture","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let registry = format!("{}/", server.uri());
    std::fs::write(
        proj.join(".npmrc"),
        format!("registry={registry}\nfetch-retries=0\n"),
    )
    .unwrap();
    std::fs::write(
        proj.join("pnpm-workspace.yaml"),
        format!("packages:\n  - 'packages/*'\nregistry: '{registry}'\nminimumReleaseAge: 0\n"),
    )
    .unwrap();
    for (app, leaf, alias) in [("a", "1.0.0", false), ("b", "2.0.0", true)] {
        let dir = proj.join("packages").join(app);
        std::fs::create_dir_all(&dir).unwrap();
        let name = if alias { "alias" } else { TARGET };
        let spec = if alias {
            "npm:@fixture/left-pad@1.3.0"
        } else {
            "1.3.0"
        };
        std::fs::write(dir.join("package.json"), serde_json::json!({"name":app,"version":"1.0.0","private":true,"dependencies":{name:spec,"e2e-middle":"1.0.0","e2e-leaf":leaf}}).to_string()).unwrap();
    }
    let store = format!("--store-dir={}", tmp.path().join("initial-store").display());
    let install = corepack(&proj, &pm, &["install", &store]);
    assert!(install.status.success(), "workspace fixture: {install:?}");
    let lock_before = std::fs::read_to_string(proj.join("pnpm-lock.yaml")).unwrap();
    let url = hosted_url_for(&server.uri());
    let sri = format!("sha512-{}", sha512_sri_b64(&patched_tarball));
    mount_target_api_mocks(
        &server,
        &url,
        &sri,
        &compute_git_sha256_from_bytes(original),
        &compute_git_sha256_from_bytes(&patched),
        TARGET_PURL,
    )
    .await;
    mount_tarball_route(&server, patched_tarball).await;
    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &proj, &server.uri(), &[]);
    assert_eq!(code, 0, "workspace redirect: {stdout}\n{stderr}");
    assert_eq!(parse_envelope(&stdout)["summary"]["applied"], 1, "{stdout}");
    let lock_after = std::fs::read_to_string(proj.join("pnpm-lock.yaml")).unwrap();
    // Both peer contexts must be represented before the rewrite; v9 factors
    // their common resolution into packages and keeps contexts in snapshots.
    assert!(lock_before.contains("e2e-leaf@1.0.0") || lock_before.contains("e2e-leaf/1.0.0"));
    assert!(lock_before.contains("e2e-leaf@2.0.0") || lock_before.contains("e2e-leaf/2.0.0"));
    if major < 9 {
        assert_eq!(
            lock_after.matches(&url).count(),
            2,
            "both legacy peer resolutions: {lock_after}"
        );
    }
    let fresh = tmp.path().join("fresh-workspace");
    std::fs::create_dir_all(&fresh).unwrap();
    for file in [
        "package.json",
        "pnpm-workspace.yaml",
        "pnpm-lock.yaml",
        ".npmrc",
    ] {
        std::fs::copy(proj.join(file), fresh.join(file)).unwrap();
    }
    // Copy only manifests, never node_modules or a warm store.
    for app in ["a", "b"] {
        let dir = fresh.join("packages").join(app);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(
            proj.join("packages").join(app).join("package.json"),
            dir.join("package.json"),
        )
        .unwrap();
    }
    let store = format!("--store-dir={}", tmp.path().join("fresh-store").display());
    let install = corepack(&fresh, &pm, &["install", "--frozen-lockfile", &store]);
    assert!(
        install.status.success(),
        "workspace frozen install: {install:?}"
    );
    for (app, target) in [("a", TARGET), ("b", "alias")] {
        let bytes = std::fs::read(
            fresh
                .join("packages")
                .join(app)
                .join("node_modules")
                .join(target)
                .join("index.js"),
        )
        .unwrap();
        assert_eq!(
            bytes, patched,
            "{version}: {app}/{target} must install the patched peer instance"
        );
    }
    // Manifest-less VEX over the fresh workspace: both peer instances are
    // hash-verified, from the ledger and then from the lockfile alone.
    if proj.join(".socket").is_dir() {
        fs_tree::copy_tree(&proj.join(".socket"), &fresh.join(".socket"));
    }
    assert_manifestless_hosted_vex(
        &fresh,
        &server.uri(),
        "pnpm-lock.yaml",
        &lock_before,
        &patched,
        TARGET_PURL,
        &format!("{version} workspace"),
    );
    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &proj, &server.uri(), &[]);
    assert_eq!(code, 0, "workspace rerun: {stdout}\n{stderr}");
    assert_eq!(
        parse_envelope(&stdout)["redirect"]["rewrittenFiles"],
        serde_json::json!([])
    );
}
