//! Real-composer capstone e2e for `socket-patch vendor` — the composer
//! committability proof on the HOST toolchain (the docker twin is
//! `docker_e2e_vendor_composer.rs`; this suite adds coverage on developer/CI
//! hosts that carry composer 2 — hosts without it compile the test and
//! soft-skip).
//!
//! Drives the REAL composer (network used for fixture setup only):
//!   1. `composer update` resolves a real psr/log 3.0.x into `vendor/`
//!      (private COMPOSER_HOME + cache).
//!   2. Hand-stage a `.socket/` manifest + blob whose before/after Git-blob
//!      hashes are computed from the ACTUAL installed bytes (a trailing
//!      marker comment on `src/LoggerInterface.php` — still valid php).
//!   3. `socket-patch vendor --json --offline` — assert the vendored copy at
//!      `.socket/vendor/composer/<uuid>/psr/log@<ver>` and the lock-only
//!      wiring: the psr/log entry's `dist` becomes `{type: path, url: <copy>,
//!      reference: <patch-uuid>}` with `transport-options.symlink === false`
//!      (forces a real copy) and `source` REMOVED; composer.json stays
//!      byte-untouched.
//!   4. **VEX (vendored) leg**: `socket-patch vex` attests the patch against
//!      the committed copy with the `(vendored)` impact marker.
//!   5. **Fresh-checkout proof**: ONLY the committable files (composer.json,
//!      composer.lock, `.socket/`) travel to a new dir; `composer install`
//!      with a cold COMPOSER_HOME/cache materializes `vendor/psr/log` as a
//!      REAL directory (not a symlink) holding the patched bytes, and the
//!      patch uuid survives into `vendor/composer/installed.json`
//!      (`dist.reference`).
//!      Then the **manifest-less VEX legs** run on that fresh checkout (the shape a
//!      depscan PR / a `vendor --detached` checkout has): with
//!      `.socket/manifest.json` deleted, standalone `vex` (and embedded
//!      `vendor --vex` / `apply --vex`) still attests `(vendored)` from the
//!      ledger; with both ledgers deleted too it attests from the
//!      composer.lock path dist + the mock patch API's record; `--offline`
//!      with no ledgers is `record_unavailable` with zero requests; and once
//!      composer.lock is reverted to the registry dist (ledger + artifact
//!      left behind, a real `composer install` re-run) nothing attests —
//!      `--no-verify` included.
//!   6. Idempotency: a re-vendor leaves composer.lock byte-identical.
//!   7. **Revert proof**: `vendor --revert` restores composer.lock
//!      byte-for-byte and removes `.socket/vendor/` entirely.
//!
//! A third twin drives `scan --vendor --detached --vex` (the depscan-style
//! front door: batch discovery → vendored copy + lock wiring, NO manifest,
//! embedded VEX in the same run) against the same mocked API, then the same
//! fresh-checkout install and manifest-less VEX legs.
//!
//! The capstone also has a `get <uuid> --mode vendored` twin (v3.6): the
//! SAME vendor engine driven through get's uuid path against a wiremock
//! `view/{uuid}` (record + inline blob content served by the API instead of
//! a locally staged manifest/blob), ending in the same fresh-checkout
//! `composer install` proof.
//!
//! Both composer majors: the capstones drive whatever `composer` is on
//! PATH (composer 1 resolves the fixture from an inline package repository,
//! since packagist no longer serves composer 1 — see
//! `composer_e2e_common`). Skips (with a println) when `composer` is not
//! installed or the fixture install cannot reach its registry, unless
//! `SOCKET_PATCH_COMPOSER_E2E_REQUIRED` is set (then those fail); every
//! assertion after that is hard. `SOCKET_PATCH_COMPOSER_E2E_VERSION` pins
//! the release a CI leg expects.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "composer_e2e_common/mod.rs"]
mod composer_e2e_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use vex_e2e_common::{
    assert_absent, assert_attested, assert_not_attested, run_vex, strip_ledgers, strip_manifest,
    Marker, PatchApi, VexOutcome, VexRun, VexVia,
};

/// Canonical lowercase patch uuid (a dedicated path level under
/// `.socket/vendor/composer/`) — also what `dist.reference` must carry.
const UUID: &str = "4d5e6f7a-8b9c-4a1b-8c2d-0123456789ab";
const GHSA: &str = "GHSA-vend-composer-host";
/// Org slug the get twin passes on the argv (and the view mock's path).
const ORG: &str = "test-org";
/// The dependency under test — dep-free, tiny, and the same fixture the
/// docker twin uses.
const DEP: &str = "psr/log";
/// Version the hand-written (composer-free) revert fixtures below pin.
const FIXTURE_VERSION: &str = "3.0.2";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Run the socket-patch binary with a scrubbed environment: every ambient
/// `SOCKET_*` var is removed (so a developer's `SOCKET_DRY_RUN=1` etc. can't
/// flip behavior) along with `VIRTUAL_ENV` (crawler discovery input).
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") && k.to_string_lossy() != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run `composer <args>` in `cwd` with a PRIVATE home + cache (the host's
/// composer state must neither leak in nor be polluted).
fn composer(cwd: &Path, args: &[&str], home: &Path, cache: &Path) -> Output {
    composer_e2e_common::composer(cwd, args, home, cache)
}

/// Git-blob SHA-256 (`sha256("blob <len>\0" ++ bytes)`) — the hash format
/// socket-patch records in manifests.
fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Write `.socket/manifest.json` + the after-hash blob (with a vulnerability
/// so the VEX leg has a statement to emit) so vendor runs fully offline.
fn stage_patch_with_vuln(proj: &Path, purl: &str, file_key: &str, before: &[u8], after: &[u8]) {
    let socket = proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": { purl: {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { file_key: {
                "beforeHash": git_sha256(before),
                "afterHash": git_sha256(after),
            }},
            "vulnerabilities": { GHSA: {
                "cves": ["CVE-2026-44444"],
                "summary": "composer capstone vex vuln",
                "severity": "high",
                "description": "d",
            }},
            "description": "capstone marker patch",
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

fn parse_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("vendor --json output is not JSON: {e}\nstdout:\n{stdout}"))
}

/// The resolved (leading-`v`-stripped) version of `name` from composer.lock's
/// `packages[]`.
fn locked_composer_version(lock_path: &Path, name: &str) -> Option<String> {
    let lock: serde_json::Value = serde_json::from_slice(&std::fs::read(lock_path).ok()?).ok()?;
    lock["packages"].as_array()?.iter().find_map(|p| {
        if p["name"] == name {
            Some(p["version"].as_str()?.trim_start_matches('v').to_string())
        } else {
            None
        }
    })
}

/// The psr/log entry from a composer.lock's `packages[]` (owned clone, for
/// assertion messages).
fn lock_entry(lock_path: &Path, name: &str) -> serde_json::Value {
    let lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(lock_path).expect("read composer.lock"))
            .expect("composer.lock parses");
    lock["packages"]
        .as_array()
        .expect("packages[]")
        .iter()
        .find(|p| p["name"] == name)
        .unwrap_or_else(|| panic!("{name} entry missing from composer.lock"))
        .clone()
}

/// Which CLI front door vendors the patch. Both land on the SAME vendor
/// engine by construction (v3.6): `vendor` consumes the locally staged
/// `.socket/` manifest + blob fully offline, while `get <uuid> --mode
/// vendored` fetches the record from the mocked API (the uuid path is
/// exempt from installed narrowing, so only the `view/{uuid}` route is
/// needed), writes the manifest itself, and stages patch content in memory
/// — `.socket/blobs` must stay absent. `--vendor-source build` keeps the
/// get flow off the vendoring service (no grant/tarball mocks needed).
enum VendorDriver<'a> {
    VendorOffline,
    GetUuidVendored { api_url: &'a str },
}

/// The vendoring invocation of the capstone, parameterized by `driver`.
fn run_vendored(driver: &VendorDriver<'_>, proj: &Path) -> (i32, String, String) {
    match driver {
        VendorDriver::VendorOffline => run_socket(
            proj,
            &[
                "vendor",
                "--json",
                "--offline",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        ),
        VendorDriver::GetUuidVendored { api_url } => run_socket(
            proj,
            &[
                "get",
                UUID,
                "--mode",
                "vendored",
                "--json",
                "--yes",
                "--api-url",
                api_url,
                "--api-token",
                "fake",
                "--org",
                ORG,
                "--vendor-source",
                "build",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        ),
    }
}

/// The discovery routes `scan --vendor` walks before the view fetch: batch
/// search (the installed psr/log has one free patch) + the per-package
/// search its selection consults.
async fn mount_scan_mocks(server: &MockServer, purl: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID, "purl": purl, "tier": "free",
                    "cveIds": [VEX_CVE], "ghsaIds": [GHSA], "severity": "high",
                    "title": "composer vendor capstone"
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
                "description": "capstone marker patch", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// Mount `view/{UUID}` on the mock API: the patch record with REAL git-blob
/// hashes over the ACTUAL installed bytes plus inline base64 `blobContent`,
/// so `get --mode vendored` both saves the manifest record and stages the
/// after-bytes in memory (nothing is staged locally). Mirrors
/// [`stage_patch_with_vuln`]'s record shape — same bare composer purl
/// (leading `v` stripped, no qualifiers), same vendor-relative file key.
async fn mount_view_mock(
    server: &MockServer,
    purl: &str,
    file_key: &str,
    before: &[u8],
    after: &[u8],
) {
    use base64::Engine as _;
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(after);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { file_key: {
                "beforeHash": git_sha256(before),
                "afterHash": git_sha256(after),
                "blobContent": blob_b64,
            }},
            "vulnerabilities": { GHSA: {
                "cves": ["CVE-2026-44444"],
                "summary": "composer capstone vex vuln",
                "severity": "high",
                "description": "d",
            }},
            "description": "capstone marker patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

/// REAL fixture: write the psr/log composer.json, then `composer update`
/// resolves + installs it (packagist on composer 2, the inline package
/// repository on composer 1; network allowed here only, private home +
/// cache). Returns false after printing the suite's SKIP line — `tag` names
/// the calling test — when the registry is unreachable (a failure instead
/// when the leg requires composer).
fn setup_composer_project(proj: &Path, home: &Path, cache: &Path, tag: &str, major: u32) -> bool {
    composer_e2e_common::setup_psr_log_project(
        &format!("e2e_vendor_composer_build{tag}"),
        proj,
        home,
        cache,
        major,
    )
    .is_some()
}

/// FRESH-CHECKOUT PROOF: ONLY the committable files (composer.json,
/// composer.lock, `.socket/`) travel to a new dir; a cold-home/cache
/// `composer install` must materialize vendor/psr/log as a REAL directory
/// (not a symlink — `transport-options.symlink: false` is load-bearing)
/// holding the `patched` bytes, with the patch uuid surviving into
/// `vendor/composer/installed.json` (`dist.reference`).
fn assert_fresh_checkout_installs_patched(tmp: &Path, proj: &Path, patched: &[u8]) -> PathBuf {
    let fresh = tmp.join("fresh");
    composer_e2e_common::fresh_checkout(proj, &fresh);

    let fresh_home = tmp.join("cold-composer-home");
    let fresh_cache = tmp.join("cold-composer-cache");
    let install = composer(&fresh, &["install"], &fresh_home, &fresh_cache);
    assert!(
        install.status.success(),
        "cold-cache `composer install` must succeed from the vendored path dist.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    // Real COPY, not a symlink (transport-options symlink:false is
    // load-bearing — a symlink would dangle in any other checkout).
    let installed_dir = fresh.join("vendor/psr/log");
    assert!(
        installed_dir.is_dir(),
        "vendor/psr/log missing after install"
    );
    assert!(
        !std::fs::symlink_metadata(&installed_dir)
            .unwrap()
            .file_type()
            .is_symlink(),
        "vendor/psr/log is a SYMLINK — symlink:false not honored"
    );
    assert_eq!(
        std::fs::read(installed_dir.join("src/LoggerInterface.php")).unwrap(),
        patched,
        "installed LoggerInterface.php must be byte-identical to the patched content"
    );

    // In-tree traceability: composer preserves dist.reference verbatim into
    // vendor/composer/installed.json — the patch uuid must survive there.
    // composer 2 wraps the list in {"packages": [...]}; composer 1 writes a
    // bare array — accept both like the docker twin's php oracle.
    let installed_pkgs = composer_e2e_common::installed_packages(&fresh);
    let installed_entry = installed_pkgs
        .iter()
        .find(|p| p["name"] == DEP)
        .unwrap_or_else(|| panic!("{DEP} missing from installed.json"));
    assert_eq!(
        installed_entry["dist"]["reference"], UUID,
        "installed.json must carry dist.reference == patch uuid: {installed_entry}"
    );
    fresh
}

// ── manifest-less VEX legs ────────────────────────────────────────────

/// Product purl every VEX leg of this suite passes (composer has no product
/// auto-detect from a bare fixture composer.json with no version).
const VEX_PRODUCT: &str = "pkg:composer/app@1.0.0";
const VEX_CVE: &str = "CVE-2026-44444";

/// Step 5b over a fresh `composer install`ed checkout of the vendored
/// project (`registry_lock` = the pre-vendor composer.lock the real composer
/// wrote): the four manifest-less legs plus the embedded `vendor --vex` /
/// `apply --vex` twins. The record comes from a mock patch API whose view
/// carries the REAL after-hash of the patched file.
fn assert_manifestless_vendored_vex(
    tmp: &Path,
    fresh: &Path,
    purl: &str,
    patched: &[u8],
    registry_lock: &[u8],
    tag: &str,
) {
    let vulns: &[(&str, &[&str])] = &[(GHSA, &[VEX_CVE])];
    let api = PatchApi::start(vec![(
        UUID.to_string(),
        vex_e2e_common::patch_view(
            UUID,
            purl,
            &[("src/LoggerInterface.php", &git_sha256(patched))],
            vulns,
        ),
    )]);
    let product = |run: VexRun| VexRun {
        product: Some(VEX_PRODUCT.to_string()),
        ..run
    };
    let vex_in = |dir: &Path, run: VexRun| -> VexOutcome { run_vex(&binary(), dir, &product(run)) };
    let lock_wired = std::fs::read(fresh.join("composer.lock")).unwrap();
    let artifact = fresh.join(format!(
        ".socket/vendor/composer/{UUID}/{DEP}@{}",
        purl.rsplit('@').next().unwrap()
    ));
    assert!(
        artifact.is_dir(),
        "[{tag}] the committed artifact travelled"
    );

    // (1) manifest deleted, ledgers kept: standalone + embedded attest.
    strip_manifest(fresh);
    let out = vex_in(fresh, VexRun::online(&api));
    assert_eq!(out.code, Some(0), "[{tag}] manifest deleted:\n{out}");
    assert_attested(out.doc(), purl, UUID, Marker::Vendored, vulns);
    for via in [VexVia::Vendor, VexVia::Apply] {
        let out = vex_in(fresh, VexRun::online(&api).via(via));
        assert_eq!(out.code, Some(0), "[{tag}] embedded {via:?}:\n{out}");
        assert_eq!(
            out.envelope["status"], "noManifest",
            "[{tag}] {via:?}:\n{out}"
        );
        assert_eq!(
            out.envelope["vex"]["statements"], 1,
            "[{tag}] {via:?}:\n{out}"
        );
        assert_attested(out.doc(), purl, UUID, Marker::Vendored, vulns);
    }
    assert_eq!(
        std::fs::read(fresh.join("composer.lock")).unwrap(),
        lock_wired,
        "[{tag}] manifest-less vendor/apply must not touch composer.lock"
    );
    assert!(
        !fresh.join(".socket/manifest.json").exists(),
        "[{tag}] no VEX leg may write a manifest"
    );

    // (4) (prepared before the ledgers go) composer.lock reverted to the
    // registry dist while the ledger + artifact stay committed, then a REAL
    // re-install: composer now consumes the pristine registry package, so
    // nothing may attest — --no-verify and --offline included.
    let reverted = tmp.join(format!("{tag}-reverted"));
    std::fs::create_dir_all(&reverted).unwrap();
    std::fs::copy(fresh.join("composer.json"), reverted.join("composer.json")).unwrap();
    std::fs::write(reverted.join("composer.lock"), registry_lock).unwrap();
    composer_e2e_common::copy_dir_recursive(&fresh.join(".socket"), &reverted.join(".socket"));
    let install = composer(
        &reverted,
        &["install"],
        &tmp.join(format!("{tag}-reverted-home")),
        &tmp.join(format!("{tag}-reverted-cache")),
    );
    assert!(
        install.status.success(),
        "[{tag}] re-install from the reverted lock:\n{}\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    assert_ne!(
        std::fs::read(reverted.join("vendor/psr/log/src/LoggerInterface.php")).unwrap(),
        patched,
        "[{tag}] the reverted install is the registry package"
    );
    assert!(reverted.join(".socket/vendor/state.json").is_file());
    for (label, run) in [
        ("online", VexRun::online(&api)),
        (
            "online --no-verify",
            VexRun {
                no_verify: true,
                ..VexRun::online(&api)
            },
        ),
        (
            "offline",
            VexRun {
                proxy_url: Some(api.uri()),
                ..VexRun::offline()
            },
        ),
        (
            "offline --no-verify",
            VexRun {
                proxy_url: Some(api.uri()),
                no_verify: true,
                ..VexRun::offline()
            },
        ),
    ] {
        let out = vex_in(&reverted, run);
        assert_eq!(out.code, Some(1), "[{tag}] reverted {label}:\n{out}");
        assert_not_attested(&out.envelope, purl, "vendor_unwired");
        assert_absent(out.doc.as_ref(), purl);
    }
    let out = vex_in(&reverted, VexRun::online(&api).via(VexVia::Apply));
    assert_eq!(out.code, Some(1), "[{tag}] reverted apply --vex:\n{out}");
    assert_absent(out.doc.as_ref(), purl);

    // (2) ledgers deleted too: the composer.lock path dist + the API record
    // are the only evidence left, and still attest.
    strip_ledgers(fresh);
    let fetched = api.view_requests(UUID);
    let out = vex_in(fresh, VexRun::online(&api));
    assert_eq!(out.code, Some(0), "[{tag}] ledgers deleted:\n{out}");
    assert_attested(out.doc(), purl, UUID, Marker::Vendored, vulns);
    assert!(
        api.view_requests(UUID) > fetched,
        "[{tag}] with no ledger the record must come from the API: {:?}",
        api.requests()
    );
    let out = vex_in(fresh, VexRun::online(&api).via(VexVia::Vendor));
    assert_eq!(
        out.code,
        Some(0),
        "[{tag}] ledger-less vendor --vex:\n{out}"
    );
    assert_attested(out.doc(), purl, UUID, Marker::Vendored, vulns);

    // (3) --offline with no ledgers: record_unavailable, zero requests.
    let seen = api.request_count();
    for no_verify in [false, true] {
        let out = vex_in(
            fresh,
            VexRun {
                proxy_url: Some(api.uri()),
                no_verify,
                ..VexRun::offline()
            },
        );
        assert_eq!(out.code, Some(1), "[{tag}] offline no ledgers:\n{out}");
        assert_not_attested(&out.envelope, purl, "record_unavailable");
        assert!(out.doc.is_none(), "[{tag}] offline:\n{out}");
    }
    assert_eq!(
        api.request_count(),
        seen,
        "[{tag}] --offline must make zero requests: {:?}",
        api.requests()
    );
}

// ── the capstone ──────────────────────────────────────────────────────

#[test]
#[ignore = "host capstone: shells out to a real composer 2; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn composer_vendor_fresh_checkout_install_and_revert() {
    let Some(major) = composer_e2e_common::composer_major("e2e_vendor_composer_build") else {
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();

    // 1. REAL fixture: composer update resolves + installs psr/log from
    //    packagist (network allowed here only, private home + cache).
    let home = tmp.path().join("composer-home");
    let cache = tmp.path().join("composer-cache");
    if !setup_composer_project(&proj, &home, &cache, "", major) {
        return;
    }

    let lock_path = proj.join("composer.lock");
    let version = locked_composer_version(&lock_path, DEP)
        .unwrap_or_else(|| panic!("{DEP} not present in composer.lock after update"));

    let installed_php = proj.join("vendor/psr/log/src/LoggerInterface.php");
    let orig = std::fs::read(&installed_php).expect("installed LoggerInterface.php");
    assert!(
        !String::from_utf8_lossy(&orig).contains("SOCKET-PATCH-VENDOR-E2E-MARKER"),
        "pristine install must not carry the marker"
    );

    // 2. Marker patch = the ACTUAL installed bytes + a trailing marker
    //    comment (still valid php).
    let marker = format!("\n// SOCKET-PATCH-VENDOR-E2E-MARKER patch={UUID}\n");
    let patched: Vec<u8> = [orig.as_slice(), marker.as_bytes()].concat();
    let purl = format!("pkg:composer/{DEP}@{version}");
    stage_patch_with_vuln(&proj, &purl, "src/LoggerInterface.php", &orig, &patched);

    let json_before = std::fs::read(proj.join("composer.json")).unwrap();
    let lock_before = std::fs::read(&lock_path).unwrap();

    // 3. Vendor (offline: the blob is staged locally → zero network).
    let (code, stdout, stderr) = run_vendored(&VendorDriver::VendorOffline, &proj);
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");
    let applied = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "applied" && e["purl"] == purl.as_str())
        .unwrap_or_else(|| panic!("expected an applied event for {purl}: {env}"));
    assert!(
        applied.get("errorCode").is_none(),
        "clean apply event: {applied}"
    );

    // Artifact under the stable path convention, patched byte-for-byte, plus
    // the informational marker and the committed ledger.
    let copy_rel = format!(".socket/vendor/composer/{UUID}/{DEP}@{version}");
    assert_eq!(
        std::fs::read(proj.join(&copy_rel).join("src/LoggerInterface.php")).unwrap(),
        patched,
        "vendored LoggerInterface.php must hold the patched bytes"
    );
    assert!(
        proj.join(format!(
            ".socket/vendor/composer/{UUID}/socket-patch.vendor.json"
        ))
        .is_file(),
        "informational vendor marker missing"
    );
    assert!(
        proj.join(".socket/vendor/state.json").is_file(),
        "vendor ledger missing"
    );

    // Lock wiring (the composer contract row): dist → {type: path, url,
    // reference: <patch-uuid>}, transport-options.symlink === false (forces a
    // real copy at install), source REMOVED; composer.json byte-untouched.
    let entry = lock_entry(&lock_path, DEP);
    assert_eq!(entry["dist"]["type"], "path", "dist.type: {entry}");
    assert_eq!(entry["dist"]["url"], copy_rel, "dist.url: {entry}");
    assert_eq!(entry["dist"]["reference"], UUID, "dist.reference: {entry}");
    assert_eq!(
        entry["transport-options"]["symlink"],
        serde_json::Value::Bool(false),
        "transport-options.symlink: {entry}"
    );
    assert!(
        entry.get("source").is_none(),
        "source must be removed from the wired entry: {entry}"
    );
    assert_eq!(
        std::fs::read(proj.join("composer.json")).unwrap(),
        json_before,
        "vendor must NOT touch composer.json (lock-only wiring)"
    );

    // 4. VEX (vendored) leg: attest the patch against the committed copy
    //    (composer has no product auto-detect, so `--product` is explicit).
    let vex_path = proj.join("out.vex.json");
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vex",
            "--cwd",
            proj.to_str().unwrap(),
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            "pkg:composer/app@1.0.0",
        ],
    );
    assert_eq!(code, 0, "vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "the vendored composer patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], purl);
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    assert!(
        impact.contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {impact}"
    );

    // 5. FRESH-CHECKOUT PROOF: ONLY the committable files, cold composer
    //    home + cache — the vendored path dist is the only possible source
    //    of psr/log.
    let fresh = assert_fresh_checkout_installs_patched(tmp.path(), &proj, &patched);

    // 5b. Manifest-less VEX legs on the fresh checkout.
    assert_manifestless_vendored_vex(tmp.path(), &fresh, &purl, &patched, &lock_before, "vendor");

    // 6. Idempotency: a re-run exits 0 and leaves the lock byte-stable.
    let lock_wired = std::fs::read(&lock_path).unwrap();
    let (code, stdout, stderr) = run_vendored(&VendorDriver::VendorOffline, &proj);
    assert_eq!(
        code, 0,
        "re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env2 = parse_envelope(&stdout);
    assert_eq!(env2["summary"]["failed"], 0, "re-run must not fail: {env2}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_wired,
        "re-vendor must leave composer.lock byte-identical"
    );

    // 7. REVERT PROOF: lock restored byte-for-byte, artifacts gone,
    //    composer.json still untouched.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "revert envelope: {renv}");
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "revert must restore composer.lock byte-identical to the pre-vendor snapshot"
    );
    assert_eq!(
        std::fs::read(proj.join("composer.json")).unwrap(),
        json_before,
        "composer.json must stay untouched through revert"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
}

/// `get <uuid> --mode vendored` twin of the capstone above (v3.6): the SAME
/// vendor engine, artifact convention, and lock-only wiring, driven through
/// get's uuid path — exempt from installed narrowing, so only the mocked
/// `view/{uuid}` route is needed. Unlike the capstone, NOTHING is staged
/// locally: the record and the patched content come from the API mock, get
/// writes `.socket/manifest.json` itself, and `.socket/blobs` must stay
/// absent (vendored downloads live in memory). Ends with the same
/// fresh-checkout `composer install` proof; the revert half stays with the
/// vendor capstone (same engine, same ledger).
// multi_thread: the CLI/composer subprocesses block a worker thread while
// wiremock keeps serving the view route on the others.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real composer 2; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
async fn composer_get_uuid_vendored_fresh_checkout_install() {
    let Some(major) = composer_e2e_common::composer_major("e2e_vendor_composer_build(get)") else {
        return;
    };

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();

    // REAL fixture: composer update resolves + installs psr/log from
    // packagist (network allowed here only, private home + cache).
    let home = tmp.path().join("composer-home");
    let cache = tmp.path().join("composer-cache");
    if !setup_composer_project(&proj, &home, &cache, "(get)", major) {
        return;
    }

    let lock_path = proj.join("composer.lock");
    let version = locked_composer_version(&lock_path, DEP)
        .unwrap_or_else(|| panic!("{DEP} not present in composer.lock after update"));

    let installed_php = proj.join("vendor/psr/log/src/LoggerInterface.php");
    let orig = std::fs::read(&installed_php).expect("installed LoggerInterface.php");
    assert!(
        !String::from_utf8_lossy(&orig).contains("SOCKET-PATCH-VENDOR-E2E-MARKER"),
        "pristine install must not carry the marker"
    );
    let marker = format!("\n// SOCKET-PATCH-VENDOR-E2E-MARKER patch={UUID}\n");
    let patched: Vec<u8> = [orig.as_slice(), marker.as_bytes()].concat();
    let purl = format!("pkg:composer/{DEP}@{version}");

    let json_before = std::fs::read(proj.join("composer.json")).unwrap();
    let lock_before = std::fs::read(&lock_path).unwrap();

    // The API serves the record: view/{uuid} with REAL git-blob hashes over
    // the ACTUAL installed bytes + inline blob content.
    let server = MockServer::start().await;
    mount_view_mock(&server, &purl, "src/LoggerInterface.php", &orig, &patched).await;

    let (code, stdout, stderr) = run_vendored(
        &VendorDriver::GetUuidVendored {
            api_url: &server.uri(),
        },
        &proj,
    );
    assert_eq!(
        code, 0,
        "get --mode vendored failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // get's envelope nests the vendor Envelope under "vendor" and drops
    // "applied" (structurally zero — the nested apply never runs).
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["found"], 1, "envelope: {env}");
    assert_eq!(env["downloaded"], 1, "envelope: {env}");
    assert!(
        env.get("applied").is_none(),
        "vendored get must drop 'applied': {env}"
    );
    assert_eq!(
        env["vendor"]["summary"]["applied"], 1,
        "one package vendored: {env}"
    );
    assert_eq!(env["vendor"]["summary"]["failed"], 0, "no failures: {env}");
    assert!(
        env["vendor"]["events"]
            .as_array()
            .expect("vendor.events[]")
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == purl.as_str()),
        "expected an applied vendor event for {purl}: {env}"
    );

    // get wrote NO manifest and NO blobs: the ledger's detached entry, keyed
    // by the bare composer purl, is the record.
    assert!(
        !proj.join(".socket/manifest.json").exists(),
        "get --mode vendored must NOT write the manifest (the ledger is the record)"
    );
    let state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(proj.join(".socket/vendor/state.json")).expect("vendor ledger missing"),
    )
    .unwrap();
    assert_eq!(
        state["entries"][purl.as_str()]["uuid"],
        UUID,
        "the ledger must record the vendored patch under the bare purl: {state}"
    );
    assert_eq!(
        state["entries"][purl.as_str()]["detached"],
        true,
        "a get --mode vendored entry is detached: {state}"
    );
    assert!(
        !proj.join(".socket/blobs").exists(),
        "get --mode vendored must NOT persist blobs"
    );

    // Anti-vacuity: the record + blob content really came from the API.
    let view_hits = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().contains(&format!("/patches/view/{UUID}")))
        .count();
    assert!(view_hits >= 1, "the view route must have been consulted");

    // Same artifact + lock-only wiring contract as the vendor capstone.
    let copy_rel = format!(".socket/vendor/composer/{UUID}/{DEP}@{version}");
    assert_eq!(
        std::fs::read(proj.join(&copy_rel).join("src/LoggerInterface.php")).unwrap(),
        patched,
        "vendored LoggerInterface.php must hold the patched bytes"
    );
    assert!(
        proj.join(".socket/vendor/state.json").is_file(),
        "vendor ledger missing"
    );
    let entry = lock_entry(&lock_path, DEP);
    assert_eq!(entry["dist"]["type"], "path", "dist.type: {entry}");
    assert_eq!(entry["dist"]["url"], copy_rel, "dist.url: {entry}");
    assert_eq!(entry["dist"]["reference"], UUID, "dist.reference: {entry}");
    assert_eq!(
        entry["transport-options"]["symlink"],
        serde_json::Value::Bool(false),
        "transport-options.symlink: {entry}"
    );
    assert!(
        entry.get("source").is_none(),
        "source must be removed from the wired entry: {entry}"
    );
    assert_eq!(
        std::fs::read(proj.join("composer.json")).unwrap(),
        json_before,
        "get --mode vendored must NOT touch composer.json (lock-only wiring)"
    );

    // FRESH-CHECKOUT PROOF: identical committability contract to the
    // capstone — cold home + cache, path dist the only source.
    let fresh = assert_fresh_checkout_installs_patched(tmp.path(), &proj, &patched);

    // Manifest-less VEX legs on the get-produced checkout: `get` wrote the
    // manifest, so deleting it is exactly the depscan / detached shape.
    tokio::task::block_in_place(|| {
        assert_manifestless_vendored_vex(tmp.path(), &fresh, &purl, &patched, &lock_before, "get")
    });
}

/// `scan --vendor --detached --vex` twin: batch discovery over the REAL
/// install → the vendored copy + composer.lock wiring with NO manifest
/// (detached), the in-run embedded VEX attesting `(vendored)`, then the same
/// fresh-checkout install and manifest-less VEX legs.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: shells out to a real composer; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
async fn composer_scan_vendor_detached_vex_fresh_checkout_install() {
    let Some(major) = composer_e2e_common::composer_major("e2e_vendor_composer_build(scan)") else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let home = tmp.path().join("composer-home");
    let cache = tmp.path().join("composer-cache");
    if !setup_composer_project(&proj, &home, &cache, "(scan)", major) {
        return;
    }
    let lock_path = proj.join("composer.lock");
    let version = locked_composer_version(&lock_path, DEP)
        .unwrap_or_else(|| panic!("{DEP} not present in composer.lock after update"));
    let orig = std::fs::read(proj.join("vendor/psr/log/src/LoggerInterface.php")).unwrap();
    let marker = format!("\n// SOCKET-PATCH-VENDOR-E2E-MARKER patch={UUID}\n");
    let patched: Vec<u8> = [orig.as_slice(), marker.as_bytes()].concat();
    let purl = format!("pkg:composer/{DEP}@{version}");
    let lock_before = std::fs::read(&lock_path).unwrap();

    let server = MockServer::start().await;
    mount_scan_mocks(&server, &purl).await;
    mount_view_mock(&server, &purl, "src/LoggerInterface.php", &orig, &patched).await;

    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--vendor",
            "--detached",
            "--vendor-source",
            "build",
            "--vex",
            "out.vex.json",
            "--vex-product",
            VEX_PRODUCT,
            "--json",
            "--yes",
            "--api-url",
            &server.uri(),
            "--api-token",
            "fake",
            "--org",
            ORG,
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "scan --vendor --detached --vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["vex"]["statements"], 1, "in-run vex block: {env}");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proj.join("out.vex.json")).unwrap()).unwrap();
    assert_attested(&doc, &purl, UUID, Marker::Vendored, &[(GHSA, &[VEX_CVE])]);
    assert!(
        !proj.join(".socket/manifest.json").exists(),
        "--detached must not write a manifest: {env}"
    );
    let copy_rel = format!(".socket/vendor/composer/{UUID}/{DEP}@{version}");
    let entry = lock_entry(&lock_path, DEP);
    assert_eq!(entry["dist"]["type"], "path", "dist.type: {entry}");
    assert_eq!(entry["dist"]["url"], copy_rel, "dist.url: {entry}");
    assert_eq!(entry["dist"]["reference"], UUID, "dist.reference: {entry}");
    assert!(entry.get("source").is_none(), "source removed: {entry}");

    let fresh = assert_fresh_checkout_installs_patched(tmp.path(), &proj, &patched);
    tokio::task::block_in_place(|| {
        assert_manifestless_vendored_vex(tmp.path(), &fresh, &purl, &patched, &lock_before, "scan")
    });
}

// ── revert against ledger state the capstone above never produces ─────
//
// Both regressions below are about `.socket/vendor/` state that outlived (or
// was rebuilt without) its wiring record, which the capstone's clean
// vendor→revert round trip cannot reach. They hand-write the wired lock +
// artifact instead of driving composer, so they need neither the toolchain
// nor the network and run in the normal `test` job (no `#[ignore]`).

/// `repair`-reconstructed ledger entry: recovered from the lockfile path, so
/// it owns the artifact but records NO pre-vendor wiring (see
/// `repair_vendor.rs`'s `synth_entry`).
const UUID_RECONSTRUCTED: &str = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d";
/// Un-ledgered artifact dir that composer.lock still points at.
const UUID_ORPHAN_WIRED: &str = "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e";
/// Un-ledgered artifact dir nothing references.
const UUID_ORPHAN_DEAD: &str = "3c4d5e6f-7a8b-4c9d-8e0f-2a3b4c5d6e7f";

const FIXTURE_PHP: &[u8] =
    b"<?php\n// SOCKET-PATCH-VENDOR-E2E-MARKER\ninterface LoggerInterface {}\n";

/// Write the vendored copy for `uuid` (dir-shaped, as the composer backend
/// materializes it) and return its project-relative path.
fn write_vendored_copy(proj: &Path, uuid: &str) -> String {
    let copy_rel = format!(".socket/vendor/composer/{uuid}/{DEP}@{FIXTURE_VERSION}");
    let src = proj.join(&copy_rel).join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("LoggerInterface.php"), FIXTURE_PHP).unwrap();
    copy_rel
}

/// composer.json + a composer.lock ALREADY wired to `uuid`'s copy — the
/// exact surgery `vendor` writes (path dist, uuid `reference`, `symlink:
/// false`, `source` gone) and what a fresh clone of a vendored project has.
fn write_wired_project(proj: &Path, uuid: &str) -> String {
    let copy_rel = write_vendored_copy(proj, uuid);
    std::fs::write(
        proj.join("composer.json"),
        r#"{
    "name": "socket/vendor-revert-fixture",
    "require": {
        "psr/log": "3.0.*"
    }
}
"#,
    )
    .unwrap();
    let lock = serde_json::json!({
        "_readme": ["This file locks the dependencies of your project to a known state"],
        "content-hash": "7a59d114f58e9b02546b21d7e57430d3",
        "packages": [{
            "name": DEP,
            "version": FIXTURE_VERSION,
            "dist": { "type": "path", "url": copy_rel, "reference": uuid },
            "transport-options": { "symlink": false },
            "type": "library",
        }],
        "packages-dev": [],
        "minimum-stability": "stable",
        "plugin-api-version": "2.6.0",
    });
    std::fs::write(
        proj.join("composer.lock"),
        format!("{}\n", serde_json::to_string_pretty(&lock).unwrap()),
    )
    .unwrap();
    copy_rel
}

/// The `.socket/vendor/state.json` a `repair` reconstruction leaves: artifact
/// + uuid recovered from the lock path, `wiring` empty.
fn write_reconstructed_ledger(proj: &Path, uuid: &str, copy_rel: &str) {
    let purl = format!("pkg:composer/{DEP}@{FIXTURE_VERSION}");
    let state = serde_json::json!({
        "version": 1,
        "entries": { purl.clone(): {
            "ecosystem": "composer",
            "basePurl": purl,
            "uuid": uuid,
            "artifact": { "path": copy_rel },
            "wiring": [],
        }}
    });
    std::fs::write(
        proj.join(".socket/vendor/state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

fn events(env: &serde_json::Value) -> &Vec<serde_json::Value> {
    env["events"].as_array().expect("events[]")
}

/// REGRESSION: reverting a `repair`-reconstructed entry must not strand
/// composer.lock. There is no recorded registry `dist` to put back, so the
/// revert has to REFUSE and keep the artifacts — deleting them while the lock
/// still points at them made the next `composer install` fail with "Source
/// path … is not found", and the run reported success.
#[test]
fn revert_of_reconstructed_entry_refuses_and_keeps_artifacts() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let copy_rel = write_wired_project(&proj, UUID_RECONSTRUCTED);
    write_reconstructed_ledger(&proj, UUID_RECONSTRUCTED, &copy_rel);

    let lock_path = proj.join("composer.lock");
    let lock_before = std::fs::read(&lock_path).unwrap();
    let state_before = std::fs::read(proj.join(".socket/vendor/state.json")).unwrap();

    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 1,
        "an unrestorable entry must fail the revert.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "partialFailure", "envelope: {env}");
    assert_eq!(env["summary"]["removed"], 0, "nothing reverted: {env}");
    let failed = events(&env)
        .iter()
        .find(|e| e["action"] == "failed")
        .unwrap_or_else(|| panic!("expected a failed event: {env}"));
    assert_eq!(failed["errorCode"], "revert_failed", "{failed}");
    let detail = failed["error"].as_str().expect("error detail");
    assert!(
        detail.contains(DEP) && detail.contains("composer update"),
        "the refusal must name the package and the re-resolve escape hatch: {detail}"
    );

    assert!(
        proj.join(&copy_rel)
            .join("src/LoggerInterface.php")
            .exists(),
        "a refused revert must NOT delete the artifacts the lock still consumes"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "composer.lock must be left exactly as it was"
    );
    assert_eq!(
        std::fs::read(proj.join(".socket/vendor/state.json")).unwrap(),
        state_before,
        "the entry must stay in the ledger so a later repair/revert can retry"
    );
}

/// REGRESSION: with state.json gone, the orphan sweep must not delete a uuid
/// dir composer.lock still points at — un-ledgered does not mean un-wired
/// (that is exactly the state `repair` reconstructs from). A genuinely
/// unreferenced dir in the same run must still be swept.
#[test]
fn orphan_sweep_keeps_lock_referenced_dir_when_ledger_is_gone() {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let wired_rel = write_wired_project(&proj, UUID_ORPHAN_WIRED);
    let dead_rel = write_vendored_copy(&proj, UUID_ORPHAN_DEAD);
    assert!(
        !proj.join(".socket/vendor/state.json").exists(),
        "fixture models a project whose ledger was deleted"
    );

    let lock_before = std::fs::read(proj.join("composer.lock")).unwrap();
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "sweeping is not a failure.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);

    assert!(
        proj.join(&wired_rel)
            .join("src/LoggerInterface.php")
            .exists(),
        "the lock-referenced artifact must survive the sweep: {env}"
    );
    assert!(
        !proj
            .join(format!(".socket/vendor/composer/{UUID_ORPHAN_DEAD}"))
            .exists(),
        "the unreferenced orphan must still be swept: {env}"
    );
    assert_eq!(
        std::fs::read(proj.join("composer.lock")).unwrap(),
        lock_before,
        "the sweep must not touch composer.lock"
    );
    assert!(
        events(&env)
            .iter()
            .any(|e| e["errorCode"] == "vendor_orphan_still_wired"
                && e["reason"]
                    .as_str()
                    .is_some_and(|r| r.contains(UUID_ORPHAN_WIRED))),
        "the kept dir must be surfaced as an advisory: {env}"
    );
    assert!(
        events(&env).iter().any(|e| e["action"] == "removed"
            && e["errorCode"] == "vendor_orphan_removed"
            && e["purl"]
                .as_str()
                .is_some_and(|p| p.contains(&format!("{DEP}@{FIXTURE_VERSION}"))
                    || p.contains(UUID_ORPHAN_DEAD))),
        "the swept dir must be reported: {env}"
    );
    assert_eq!(
        dead_rel,
        format!(".socket/vendor/composer/{UUID_ORPHAN_DEAD}/{DEP}@{FIXTURE_VERSION}"),
        "fixture path convention"
    );
}

// ── S1: Composer's path-mirror filters ─────────────────────────────────

/// Every regular file under `root`, relative, `/`-separated, sorted.
fn tree_files(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, rel: &str, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            let child = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &child, out);
            } else {
                out.push(child);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", &mut out);
    out.sort();
    out
}

/// Filter files that make Composer's path mirror skip real psr/log files
/// (the patched one included): `.gitignore` (Composer ≤ 2.1),
/// `.gitattributes` export-ignore (every version), `.hgignore` (Composer 1).
fn plant_mirror_filters(dir: &Path) {
    std::fs::write(
        dir.join(".gitignore"),
        "/src/LoggerInterface.php\n/src/NullLogger.php\n",
    )
    .unwrap();
    std::fs::write(
        dir.join(".gitattributes"),
        "* text=auto\n/src/LoggerTrait.php export-ignore\n",
    )
    .unwrap();
    std::fs::write(
        dir.join(".hgignore"),
        "syntax: glob\nsrc/AbstractLogger.php\n",
    )
    .unwrap();
}

/// A fresh checkout of `proj` installs every file of the vendored copy
/// byte-for-byte (the patched `src/LoggerInterface.php` included).
fn assert_fresh_install_mirrors_whole_copy(
    tmp: &Path,
    proj: &Path,
    copy_rel: &str,
    patched: &[u8],
) {
    let fresh = assert_fresh_checkout_installs_patched(tmp, proj, patched);
    let copy = proj.join(copy_rel);
    let installed = fresh.join("vendor/psr/log");
    let copied = tree_files(&copy);
    for rel in [
        "src/NullLogger.php",
        "src/LoggerTrait.php",
        "src/AbstractLogger.php",
    ] {
        assert!(
            copied.iter().any(|f| f == rel),
            "fixture lost {rel}: {copied:?}"
        );
    }
    for rel in &copied {
        assert_eq!(
            std::fs::read(installed.join(rel)).ok(),
            Some(std::fs::read(copy.join(rel)).unwrap()),
            "composer's path mirror dropped or changed {rel} (installed: {:?})",
            tree_files(&installed)
        );
    }
}

/// A package whose own `.gitignore` / `.gitattributes` / `.hgignore` match
/// real files still installs every file from the vendored copy: the filters
/// are neutralized in the copy (warned, human mode), and the human output
/// names the composer reinstall steps.
#[test]
#[ignore = "host capstone: shells out to a real composer; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn composer_vendor_keeps_files_mirror_filters_would_drop() {
    let suite = "e2e_vendor_composer_build(mirror-filters)";
    let Some(major) = composer_e2e_common::composer_major(suite) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let home = tmp.path().join("composer-home");
    let cache = tmp.path().join("composer-cache");
    if !setup_composer_project(&proj, &home, &cache, "(mirror-filters)", major) {
        return;
    }
    let lock_path = proj.join("composer.lock");
    let version = locked_composer_version(&lock_path, DEP).expect("psr/log locked");
    let installed = proj.join("vendor/psr/log");
    plant_mirror_filters(&installed);
    let orig = std::fs::read(installed.join("src/LoggerInterface.php")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), b"\n// SOCKET-PATCH-MIRROR-FILTER-MARKER\n"].concat();
    let purl = format!("pkg:composer/{DEP}@{version}");
    stage_patch_with_vuln(&proj, &purl, "src/LoggerInterface.php", &orig, &patched);

    let (code, stdout, stderr) = run_socket(
        &proj,
        &["vendor", "--offline", "--cwd", proj.to_str().unwrap()],
    );
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Warning (vendor_composer_mirror_filters_neutralized)"),
        "the neutralization is surfaced:\n{stderr}"
    );
    assert!(
        stdout.contains("Run `composer install` to update vendor/"),
        "the composer reinstall hint is printed:\n{stdout}"
    );
    assert!(
        stdout.contains("Composer 1 does not reinstall")
            && stdout.contains("remove vendor/psr/log first"),
        "the Composer 1 hint names the package dir:\n{stdout}"
    );

    let copy_rel = format!(".socket/vendor/composer/{UUID}/{DEP}@{version}");
    let copy = proj.join(&copy_rel);
    assert_eq!(std::fs::read(copy.join(".gitignore")).unwrap(), b"");
    assert_eq!(std::fs::read(copy.join(".hgignore")).unwrap(), b"");
    assert_eq!(
        std::fs::read(copy.join(".gitattributes")).unwrap(),
        b"* text=auto\n"
    );
    assert_eq!(
        std::fs::read(installed.join(".gitignore")).unwrap(),
        b"/src/LoggerInterface.php\n/src/NullLogger.php\n",
        "the installed tree is never touched"
    );
    assert_fresh_install_mirrors_whole_copy(tmp.path(), &proj, &copy_rel, &patched);
}

/// A copy vendored by a CLI that predates the neutralization (filter files
/// intact in the committed copy) is healed by the idempotent re-run: the
/// lock stays byte-identical, the heal is warned, and a fresh checkout then
/// installs every file.
#[test]
#[ignore = "host capstone: shells out to a real composer; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn composer_vendor_fast_path_heals_legacy_copy() {
    let suite = "e2e_vendor_composer_build(legacy-copy)";
    let Some(major) = composer_e2e_common::composer_major(suite) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let home = tmp.path().join("composer-home");
    let cache = tmp.path().join("composer-cache");
    if !setup_composer_project(&proj, &home, &cache, "(legacy-copy)", major) {
        return;
    }
    let lock_path = proj.join("composer.lock");
    let version = locked_composer_version(&lock_path, DEP).expect("psr/log locked");
    let orig = std::fs::read(proj.join("vendor/psr/log/src/LoggerInterface.php")).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), b"\n// SOCKET-PATCH-LEGACY-COPY-MARKER\n"].concat();
    let purl = format!("pkg:composer/{DEP}@{version}");
    stage_patch_with_vuln(&proj, &purl, "src/LoggerInterface.php", &orig, &patched);
    let (code, stdout, stderr) = run_vendored(&VendorDriver::VendorOffline, &proj);
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let copy_rel = format!(".socket/vendor/composer/{UUID}/{DEP}@{version}");
    let copy = proj.join(&copy_rel);
    plant_mirror_filters(&copy);
    let lock_wired = std::fs::read(&lock_path).unwrap();

    let (code, stdout, stderr) = run_vendored(&VendorDriver::VendorOffline, &proj);
    assert_eq!(
        code, 0,
        "re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    assert!(
        env["events"].as_array().unwrap().iter().any(|e| {
            e["errorCode"] == "vendor_composer_mirror_filters_neutralized"
                && e["purl"] == purl.as_str()
        }),
        "the heal is surfaced: {env}"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_wired,
        "composer.lock untouched"
    );
    assert_eq!(std::fs::read(copy.join(".gitignore")).unwrap(), b"");
    assert_eq!(
        std::fs::read(copy.join("src/LoggerInterface.php")).unwrap(),
        patched,
        "the patched file is untouched by the heal"
    );

    let (code, stdout, stderr) = run_vendored(&VendorDriver::VendorOffline, &proj);
    assert_eq!(
        code, 0,
        "second re-vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert!(
        !env["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["errorCode"] == "vendor_composer_mirror_filters_neutralized"),
        "a healed copy has nothing left to neutralize: {env}"
    );
    assert_fresh_install_mirrors_whole_copy(tmp.path(), &proj, &copy_rel, &patched);
}

// ── S8: a `v`-tagged release ───────────────────────────────────────────

/// symfony/deprecation-contracts `v3.5.1` (PHP ≥ 8.1) or `v2.5.4` (older
/// PHP): a release whose lock version carries the `v` tag. Composer picks
/// the one its PHP can run; Composer 1 resolves it from an inline package
/// repository (packagist no longer serves Composer 1).
const VTAG_DEP: &str = "symfony/deprecation-contracts";
const VTAG_FILE: &str = "function.php";

fn vtag_composer_json(major: u32) -> String {
    let release = |version: &str, reference: &str, php: &str| {
        serde_json::json!({
            "name": VTAG_DEP,
            "version": version,
            "type": "library",
            "dist": {
                "type": "zip",
                "url": format!("https://api.github.com/repos/symfony/deprecation-contracts/zipball/{reference}"),
                "reference": reference,
            },
            "source": {
                "type": "git",
                "url": "https://github.com/symfony/deprecation-contracts.git",
                "reference": reference,
            },
            "require": { "php": php },
            "autoload": { "files": ["function.php"] },
        })
    };
    let mut doc = serde_json::json!({
        "name": "socket/composer-vtag-capstone",
        "require": { VTAG_DEP: "3.5.1 || 2.5.4" },
    });
    if major < 2 {
        doc["repositories"] = serde_json::json!([
            { "packagist.org": false },
            { "type": "package", "package": release("v3.5.1", "74c71c939a79f7d5bf3c1ce9f5ea37ba0114c6f6", ">=8.1") },
            { "type": "package", "package": release("v2.5.4", "605389f2a7e5625f273b53960dc46aeaf9c62918", ">=7.1") },
        ]);
    }
    format!("{}\n", serde_json::to_string_pretty(&doc).unwrap())
}

/// `vendor` of a `v`-tagged release: the lock keeps its `v3.5.1` spelling,
/// the copy's leaf carries the bare purl version, and a fresh checkout
/// installs the patched bytes with the uuid in installed.json.
#[test]
#[ignore = "host capstone: shells out to a real composer; the unpinned `test` job \
            skips it, the e2e job runs it with a pinned toolchain via --ignored"]
fn composer_vendor_v_tagged_fresh_checkout_install() {
    let suite = "e2e_vendor_composer_build(v-tagged)";
    let Some(major) = composer_e2e_common::composer_major(suite) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let home = tmp.path().join("composer-home");
    let cache = tmp.path().join("composer-cache");
    std::fs::write(proj.join("composer.json"), vtag_composer_json(major)).unwrap();
    let update = composer(&proj, &["update"], &home, &cache);
    if !update.status.success() {
        composer_e2e_common::skip::<()>(
            suite,
            &format!(
                "`composer update` failed:\n{}\n{}",
                String::from_utf8_lossy(&update.stdout),
                String::from_utf8_lossy(&update.stderr)
            ),
        );
        return;
    }
    let lock_path = proj.join("composer.lock");
    let pretty = lock_entry(&lock_path, VTAG_DEP)["version"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(pretty == "v3.5.1" || pretty == "v2.5.4", "locked {pretty}");
    let version = pretty.trim_start_matches('v').to_string();
    let installed = proj.join("vendor").join(VTAG_DEP).join(VTAG_FILE);
    let orig = std::fs::read(&installed).unwrap();
    let patched: Vec<u8> = [orig.as_slice(), b"\n// SOCKET-PATCH-VTAG-MARKER\n"].concat();
    let purl = format!("pkg:composer/{VTAG_DEP}@{version}");
    stage_patch_with_vuln(&proj, &purl, VTAG_FILE, &orig, &patched);

    let (code, stdout, stderr) = run_vendored(&VendorDriver::VendorOffline, &proj);
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_envelope(&stdout);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let entry = lock_entry(&lock_path, VTAG_DEP);
    let copy_rel = format!(".socket/vendor/composer/{UUID}/{VTAG_DEP}@{version}");
    assert_eq!(
        entry["version"],
        pretty.as_str(),
        "the lock keeps its tag: {entry}"
    );
    assert_eq!(entry["dist"]["url"], copy_rel.as_str(), "{entry}");
    assert_eq!(entry["dist"]["reference"], UUID, "{entry}");
    assert!(entry.get("source").is_none(), "{entry}");

    let vex_path = proj.join("out.vex.json");
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vex",
            "--cwd",
            proj.to_str().unwrap(),
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            VEX_PRODUCT,
        ],
    );
    assert_eq!(code, 0, "vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    assert_eq!(doc["statements"].as_array().unwrap().len(), 1, "{doc}");
    assert_eq!(
        doc["statements"][0]["products"][0]["subcomponents"][0]["@id"],
        purl.as_str()
    );

    let fresh = tmp.path().join("fresh");
    composer_e2e_common::fresh_checkout(&proj, &fresh);
    let install = composer(
        &fresh,
        &["install"],
        &tmp.path().join("cold-home"),
        &tmp.path().join("cold-cache"),
    );
    assert!(
        install.status.success(),
        "cold install from the vendored path dist:\n{}\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    assert_eq!(
        std::fs::read(fresh.join("vendor").join(VTAG_DEP).join(VTAG_FILE)).unwrap(),
        patched
    );
    let installed_entry = composer_e2e_common::installed_packages(&fresh)
        .into_iter()
        .find(|p| p["name"] == VTAG_DEP)
        .expect("installed.json names the package");
    assert_eq!(
        installed_entry["dist"]["reference"], UUID,
        "{installed_entry}"
    );
    assert_eq!(
        installed_entry["version"],
        pretty.as_str(),
        "{installed_entry}"
    );
}
