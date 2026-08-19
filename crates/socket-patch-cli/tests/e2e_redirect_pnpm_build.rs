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
//! Version ladder (the `e2e_vendor_pnpm_build.rs` convention): pnpm@10 is the
//! PRIMARY leg (skips only when corepack/pnpm is unfetchable or the fixture
//! install cannot reach the registry); pnpm@7, pnpm@8, pnpm@9 and pnpm@11 are
//! opportunistic. The pnpm@7/@8 legs prove the LEGACY lock grammars end to
//! end: their pnpm-emitted v5.4 / v6 locks are spliced by the same rewrite
//! and both majors frozen-install the hosted tarball from an empty store
//! (verified live 2026-08-18, corepack pnpm@7.33.5 / pnpm@8.15.9).
//!
//! TRUST AUTO-CONFIG: a scan that rewrites a ROOT v9 lock also ensures
//! `trustLockfile: true` in pnpm-workspace.yaml (ledger edit kind
//! `redirect_pnpm_workspace_trust`; the workspace file joins
//! `rewrittenFiles`), because pnpm >=11's lockfile supply-chain policy
//! rejects the rewritten lock otherwise. Legacy 5.x/6.0 locks mean pnpm 7/8
//! — no policy, no setting — so they rewrite ONLY the lock and keep the
//! manual `--trust-lockfile` guidance (the gate is lock-major >= 9). Two
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
use std::process::{Command, Output, Stdio};

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
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Probe corepack from a NEUTRAL temp dir (a `packageManager` field in an
/// ancestor package.json — e.g. this monorepo root — otherwise makes corepack
/// refuse a different manager).
fn has_corepack_pm(pm: &str) -> bool {
    let Ok(probe) = tempfile::tempdir() else {
        return false;
    };
    // Isolated too: this probe is what actually downloads the package manager
    // the first time, and corepack stores it under `COREPACK_HOME`.
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
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
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

/// `scan --mode hosted` (the real binary) over the project at `root`.
/// `extra_args` rides at the end (e.g. `--no-trust-lockfile-config`).
fn scan_hosted(root: &Path, api_url: &str, extra_args: &[&str]) -> (i32, String, String) {
    let mut args = vec![
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
    ];
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
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
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
            "uuid": UUID,
            "purl": PURL,
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
}

/// Steps 1–3 of the module doc against the REAL `corepack <pm>`: fixture
/// install, patched tarball + API mocks, `scan --mode hosted`, and the
/// envelope/lockfile/ledger/idempotency assertions. When
/// `tamper_served_tarball` is set, the tarball route serves DIFFERENT bytes
/// than the sha512 pinned into the lockfile — the negative twin's premise.
/// `no_trust_config` runs every scan with `--no-trust-lockfile-config` and
/// flips the trust-auto-config expectations to the opted-out contract.
/// `None` = skip (message already printed).
async fn redirect_scanned_pnpm_project(
    pm: &str,
    tag: &str,
    tamper_served_tarball: bool,
    no_trust_config: bool,
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
        &["install", "--store-dir", store.to_str().unwrap()],
    );
    if !install.status.success() {
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

    let lock_path = proj.join("pnpm-lock.yaml");
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
        .find(|l| l.trim_start().starts_with("resolution: {integrity:"))
        .expect("pristine lock must carry an inline resolution")
        .to_string();

    let scan_extra: &[&str] = if no_trust_config {
        &["--no-trust-lockfile-config"]
    } else {
        &[]
    };
    let (code, stdout, stderr) = scan_hosted(&proj, &server.uri(), scan_extra);
    assert_eq!(
        code, 0,
        "scan --mode hosted failed ({tag}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
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
        serde_json::json!(["pnpm-lock.yaml"])
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
            trust_detail.contains("pnpm 7/8") && trust_detail.contains("installs work unchanged"),
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
        lock_after.contains(&format!(
            "resolution: {{integrity: {sri}, tarball: {hosted_url}}}"
        )),
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
            && e["path"] == "pnpm-lock.yaml"),
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
    let (code, stdout, stderr) = scan_hosted(&proj, &server.uri(), scan_extra);
    assert_eq!(
        code, 0,
        "second scan --mode hosted failed ({tag}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
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
    std::fs::copy(fx.proj.join("pnpm-lock.yaml"), fresh.join("pnpm-lock.yaml")).unwrap();
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
    let mut args = vec![
        "install",
        "--frozen-lockfile",
        "--store-dir",
        fresh_store.to_str().unwrap(),
    ];
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
    let Some(fx) = redirect_scanned_pnpm_project(PNPM_PRIMARY, "pnpm10", false, false).await else {
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
    let Some(fx) =
        redirect_scanned_pnpm_project(PNPM_PRIMARY, "pnpm10-tampered", true, false).await
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

/// Opportunistic pnpm@9 leg (the vendor capstone's secondary convention):
/// same positive chain, no tamper twin needed — @10 already carries it.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
#[ignore = "wall-bound real-pnpm install (~60s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn pnpm9_redirect_fresh_checkout_frozen_install_lands_patched_bytes() {
    let Some(fx) = redirect_scanned_pnpm_project(PNPM_SECONDARY, "pnpm9", false, false).await
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
    let Some(fx) = redirect_scanned_pnpm_project(PNPM_TERTIARY, "pnpm11", false, false).await
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
    let Some(fx) =
        redirect_scanned_pnpm_project(PNPM_TERTIARY, "pnpm11-opt-out", false, true).await
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
    let Some(fx) = redirect_scanned_pnpm_project(PNPM_LEGACY_V5, "pnpm7", false, false).await
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
    let Some(fx) = redirect_scanned_pnpm_project(PNPM_LEGACY_V6, "pnpm8", false, false).await
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

    let (code, stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &[]);
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

    let (code, stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &[]);
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
        v6_detail.contains("pnpm 7/8") && v6_detail.contains("installs work unchanged"),
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
