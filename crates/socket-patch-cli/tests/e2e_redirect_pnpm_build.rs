//! Real-install redirect capstone e2e for pnpm — the pnpm counterpart of
//! `tests/e2e_redirect_npm_build.rs`.
//!
//! `scan --mode hosted` never lands patched bytes in the repo: it splices the
//! patched package's `resolution:` in pnpm-lock.yaml to `{integrity:
//! <patched sha512>, tarball: <hosted url>}` (a wiremock standing in for
//! patch.socket.dev) and records the patch in the redirect ledger. The
//! corepack legs prove every link of that chain against the REAL pnpm:
//!
//!   1. `corepack pnpm@<major> install left-pad@1.3.0` into a tempdir project
//!      (network used for fixture setup only, private `--store-dir`).
//!   2. Build a PATCHED tarball from the actually-installed bytes (marker
//!      comment prepended to `index.js`) and serve it from wiremock, alongside
//!      the discovery / reference / view API mocks.
//!   3. `scan --mode hosted --json --yes` (the real binary): the lock's
//!      `resolution:` now pins the wiremock tarball URL + the patched
//!      tarball's sha512, the ledger holds the `redirect_pnpm_resolution`
//!      edit + the patch record, and a second scan is idempotent (lock
//!      byte-stable, no duplicate ledger edits).
//!   4. FRESH-CHECKOUT PROOF: only package.json + pnpm-lock.yaml + `.socket/`
//!      travel, the `.npmrc` registry points at a DEAD port, the store is
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
//! TRUST AUTO-CONFIG: a scan that rewrites a ROOT v9 lock also ensures
//! `trustLockfile: true` in pnpm-workspace.yaml (ledger edit kind
//! `redirect_pnpm_workspace_trust`; the workspace file joins
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

#[path = "common/cache_env.rs"]
mod cache_env;

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
/// Pinned pnpm majors via corepack — @10 is the required leg, the others are
/// opportunistic (the vendor capstone's ladder convention). @7 and @8 are the
/// legacy-lock legs: they emit lockfileVersion 5.4 / 6.0, proving the v5/v6
/// rewrite installs for real.
const PNPM_PRIMARY: &str = "pnpm@10";
const PNPM_SECONDARY: &str = "pnpm@9";
const PNPM_TERTIARY: &str = "pnpm@11";
const PNPM_LEGACY_V5: &str = "pnpm@7";
const PNPM_LEGACY_V6: &str = "pnpm@8";
/// left-pad@1.3.0's registry integrity, byte-accurate from the matrix legs'
/// pnpm-emitted locks — the synthetic legs' pristine `resolution:` value.
const UPSTREAM_SHA512: &str = "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==";
/// Synthetic patched integrity for the no-install legs (nothing downloads it,
/// so it only has to be distinct from the upstream value).
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
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
        let mut cmd = Command::new("corepack");
        cmd.arg(pm);
        cmd
    }
}

fn has_corepack_pm(pm: &str) -> bool {
    let probe = tempfile::tempdir().unwrap();
    let mut cmd = pnpm_command(pm);
    cmd.arg("--version").current_dir(probe.path());
    cache_env::isolate(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    let output = cmd.output();
    let ok = output.as_ref().is_ok_and(|o| o.status.success());
    if std::env::var_os("SOCKET_PATCH_PNPM_E2E_REQUIRED").is_some() {
        assert!(ok, "required pnpm toolchain unavailable: {output:?}");
        if let Ok(output) = output {
            assert_eq!(
                String::from_utf8_lossy(&output.stdout).trim(),
                pm.strip_prefix("pnpm@").unwrap(),
                "matrix must run the pinned version"
            );
        }
    }
    ok
}

/// Remove ambient `SOCKET_*` / `PNPM_*` / `npm_config_*` vars.
///
/// Seed-then-scrub (mirrors e2e_vendor_pnpm_build.rs): pnpm lets EVERY
/// `.npmrc` setting be overridden by an `npm_config_*` env var (env outranks
/// the project npmrc), so an ambient `npm_config_node_linker=pnp` alone can
/// turn a capstone red. The explicit env_remove below clears the seed too,
/// but if the prefix scrub is ever dropped the seed (rather than a
/// developer's ambient shell, which this suite can't rely on) turns the test
/// red immediately.
fn scrub_socket_env(cmd: &mut Command) {
    cmd.env("npm_config_node_linker", "pnp");
    for (k, _) in std::env::vars_os() {
        let key = k.to_string_lossy();
        if (key.starts_with("SOCKET_")
            || key.starts_with("PNPM_")
            || key.to_ascii_lowercase().starts_with("npm_config_"))
            && key != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("npm_config_node_linker");
}

fn corepack(cwd: &Path, pm: &str, args: &[&str]) -> Output {
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
    cmd.args(&args).current_dir(cwd);
    if args.first().is_some_and(|arg| arg == "install")
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
    scrub_socket_env(&mut cmd);
    // After the scrub: it strips ambient `PNPM_*` / `npm_config_*`, which
    // would otherwise take the sandbox values back out again.
    cache_env::isolate(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
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

/// Which CLI front door drives the hosted engine. Both consume the SAME
/// engine by construction (v3.6): `scan --mode hosted` discovers the dep,
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
    env["redirect"]["warnings"]
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
    let install = corepack(
        &proj,
        pm,
        &["install", &format!("--store-dir={}", store.display())],
    );
    if !install.status.success() {
        assert!(
            std::env::var_os("SOCKET_PATCH_PNPM_E2E_REQUIRED").is_none(),
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
            env["redirect"]["redirected"], 0,
            "unsafe legacy lock must be refused: {env}"
        );
        assert!(
            warning_codes(&env).contains(&"redirect_pnpm_legacy_lockfile_unsupported".to_string())
        );
        assert_eq!(std::fs::read_to_string(&lock_path).unwrap(), lock_before);
        assert!(!proj.join(".socket/vendor/redirect-state.json").exists());
        println!(
            "EXPECTED REFUSAL: pnpm 1.0.0 discards hosted URLs; lock unchanged, no patch confirmed"
        );
        return None;
    }

    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "exactly one dep redirected: {env}"
    );
    // The zero-touch trustLockfile auto-config fires only for root v9 locks
    // (and not under `--no-trust-lockfile-config`): pnpm 7/8 (5.x/6.0) have
    // neither the lockfile policy nor the setting, so legacy runs rewrite
    // ONLY the lock and keep the manual flag guidance.
    let v9_lock = lock_before.starts_with("lockfileVersion: '9.0'");
    let auto_trust = v9_lock && !no_trust_config;
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
    let trust_detail = env["redirect"]["warnings"]
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
            "a legacy-lock or --no-trust-lockfile-config run must not create \
             pnpm-workspace.yaml ({tag})"
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

    // Ledger: the lock edit (with the original resolution preserved for
    // revert) + the embedded patch record a post-install `vex` verifies.
    let ledger_path = proj.join(".socket/vendor/redirect-state.json");
    let ledger: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    let edits = ledger["edits"].as_array().unwrap().clone();
    assert!(
        edits.iter().any(|e| e["kind"] == "redirect_pnpm_resolution"
            && e["key"] == format!("{DEP}@{DEP_VERSION}")
            && e["path"] == lock_name),
        "the ledger must record the redirect_pnpm_resolution edit: {ledger}"
    );
    let trust_edits: Vec<&serde_json::Value> = edits
        .iter()
        .filter(|e| e["kind"] == "redirect_pnpm_workspace_trust")
        .collect();
    if auto_trust {
        // Exactly one trust edit, so `--revert` unwinds exactly one write.
        assert_eq!(
            trust_edits.len(),
            1,
            "a v9 rewrite must record exactly one workspace trust edit: {ledger}"
        );
        let edit = trust_edits[0];
        assert_eq!(edit["path"], "pnpm-workspace.yaml", "trust edit: {edit}");
        assert_eq!(edit["key"], "trustLockfile", "trust edit: {edit}");
        // "created" = new file (revert deletes it); "added" = line appended
        // to a pre-existing file (revert removes only that line).
        let expected_action = if ws_existed_before {
            "added"
        } else {
            "created"
        };
        assert_eq!(edit["action"], expected_action, "trust edit: {edit}");
    } else {
        assert!(
            trust_edits.is_empty(),
            "legacy-lock / --no-trust-lockfile-config runs must record no workspace \
             trust edit: {ledger}"
        );
    }
    assert!(
        ledger["records"][PURL]["vulnerabilities"][GHSA].is_object(),
        "the ledger must embed the patch record + vulnerability: {ledger}"
    );

    // Idempotency: the second scan still counts the dep as redirected (the
    // hosted URL is already in the lock) but rewrites nothing — lock AND
    // workspace file byte-stable — and appends no duplicate edits (which
    // would poison a revert).
    let (code, stdout, stderr) = run_hosted(driver, &proj, &server.uri(), scan_extra);
    assert_eq!(
        code, 0,
        "second {driver:?} --mode hosted failed ({tag}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env2 = parse_envelope(&stdout);
    assert_eq!(
        env2["redirect"]["redirected"], 1,
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
    let ledger2: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    assert_eq!(
        edits.len(),
        ledger2["edits"].as_array().unwrap().len(),
        "a re-run must not append duplicate ledger edits: {ledger2}"
    );

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
    copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
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
    let out = corepack(&fresh, pm, &args);
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

/// get-driven hosted twin (v3.6): `get <uuid> --mode hosted --json --yes`
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
}

/// Opportunistic pnpm@9 leg (the vendor capstone's secondary convention):
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
    let (vex_code, _, _) = run_socket(
        &fx.proj,
        &["vex", "--offline", "--product", "pkg:npm/consumer@0.0.0"],
    );
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
    let (code, stdout, stderr) = run_socket(
        &fresh,
        &["vex", "--offline", "--product", "pkg:npm/consumer@0.0.0"],
    );
    assert_eq!(code, 0, "verified VEX failed: {stdout}\n{stderr}");
    let vex: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(vex["statements"][0]["status"], "not_affected", "{vex}");
    assert_eq!(vex["statements"][0]["vulnerability"]["name"], GHSA, "{vex}");

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
    std::fs::remove_dir_all(fx.proj.join("node_modules")).unwrap();
    let (code, stdout, stderr) =
        run_socket(&fx.proj, &["rollback", "--offline", "--yes", "--json"]);
    assert_eq!(code, 0, "rollback failed: {stdout}\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(fx.proj.join(&fx.lock_name)).unwrap(),
        fx.lock_before
    );
    // The same project must be discoverable from just its lockfile in a
    // fresh checkout, including the legacy shrinkwrap filename.
    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &fx.proj, &fx._server.uri(), &[]);
    assert_eq!(code, 0, "lock-only scan failed: {stdout}\n{stderr}");
    assert_eq!(parse_envelope(&stdout)["redirect"]["redirected"], 1);

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
    let hosted_url = hosted_url_for("http://patch.test");
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
        env["redirect"]["redirected"], 1,
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

    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    let edit = ledger["edits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| {
            e["kind"] == "redirect_pnpm_resolution" && e["key"] == format!("{DEP}@{DEP_VERSION}")
        })
        .unwrap_or_else(|| panic!("the ledger must record the v5 redirect edit: {ledger}"));
    assert!(
        edit["original"]
            .as_str()
            .unwrap_or_default()
            .contains(UPSTREAM_SHA512),
        "the ledger must preserve the original upstream integrity for revert: {edit}"
    );
}

/// pnpm v6 PLAIN lock keys (`/name@version:` with no peer suffix) stay inside
/// the redirect grammar — verified against a real pnpm 8 install in the
/// matrix sweep (hosted-pnpm8): the resolution is spliced in place with its
/// sibling lines (`deprecated:`, `dev:`) byte-preserved.
#[tokio::test(flavor = "multi_thread")]
async fn pnpm_v6_plain_lock_key_rewrite_stays_supported() {
    let server = MockServer::start().await;
    let hosted_url = hosted_url_for("http://patch.test");
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
        env["redirect"]["redirected"], 1,
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
    let v6_detail = env["redirect"]["warnings"]
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

    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    let edit = ledger["edits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| {
            e["kind"] == "redirect_pnpm_resolution" && e["key"] == format!("{DEP}@{DEP_VERSION}")
        })
        .unwrap_or_else(|| panic!("the ledger must record the v6 redirect edit: {ledger}"));
    assert!(
        edit["original"]
            .as_str()
            .unwrap_or_default()
            .contains(UPSTREAM_SHA512),
        "the ledger must preserve the original upstream integrity for revert: {edit}"
    );
    assert!(
        !ledger["edits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "redirect_pnpm_workspace_trust"),
        "a v6-lock scan must record no workspace trust edit: {ledger}"
    );
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
    assert_eq!(
        parse_envelope(&stdout)["redirect"]["redirected"],
        1,
        "{stdout}"
    );
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
    let (code, stdout, stderr) = run_hosted(HostedDriver::Scan, &proj, &server.uri(), &[]);
    assert_eq!(code, 0, "workspace rerun: {stdout}\n{stderr}");
    assert_eq!(
        parse_envelope(&stdout)["redirect"]["rewrittenFiles"],
        serde_json::json!([])
    );
}
