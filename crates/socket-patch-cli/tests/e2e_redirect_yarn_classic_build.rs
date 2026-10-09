//! Real-yarn-classic redirect capstone e2e — the hosted-mode full-chain proof
//! for the yarn v1 (classic lockfile) flavor, mirroring
//! `e2e_redirect_yarn_berry_build.rs` / `e2e_redirect_npm_build.rs`.
//!
//! `scan --mode hosted` never lands patched bytes in the repo: it rewrites the
//! classic `yarn.lock` block to
//! `resolved "<hosted-tgz-url>#<sha1>"` + a recomputed `integrity sha512-…`
//! line — and writes nothing else (v5: no redirect ledger; the lock IS the
//! hosted state). This test proves every
//! link against the REAL `corepack yarn@1.22.22` — the gap the 2026-07 strapi
//! incident exposed: hosted wiring for a classic lock had never been
//! install-proven with the installer that actually honors the v1 format
//! (a berry install migrates the lockfile; yarn 2.4.3 additionally crashes on
//! Node 23+ in its own builtin `patch:` fetcher).
//!
//!   1. `yarn install` of left-pad@1.3.0 (network for fixture setup only,
//!      private cache via `YARN_CACHE_FOLDER`).
//!   2. Build a PATCHED tarball from the installed bytes; its sha1 (the
//!      `resolved` URL fragment classic verifies) and sha512 SRI (the
//!      `integrity` line) are computed in-test — classic hashes the tarball
//!      bytes directly, so no bootstrap resolution is needed (unlike berry's
//!      cache-zip `10c0` checksum).
//!   3. `scan --mode hosted --json --vex` (the real binary) against a wiremock
//!      Socket API: yarn.lock now pins the hosted URL + `#sha1` + recomputed
//!      integrity, no ledger is written, the in-run VEX is the
//!      `(redirected)` attestation.
//!   4. FRESH-CHECKOUT PROOF: only package.json + yarn.lock + .socket/ travel;
//!      `yarn install --frozen-lockfile` (empty private cache; the only dep
//!      resolves from the mock host, so the registry is never contacted) MUST
//!      install the patched bytes from the hosted tarball.
//!
//! The negative twin serves a DIFFERENT tarball at the hosted URL while the
//! lock keeps the real sha1/integrity pins: the fresh install MUST fail on
//! the integrity/hash check — the lock pin is enforcement.
//!
//! Manifest-less VEX (the depscan / never-committed-manifest shape): once the
//! fresh checkout has installed the hosted bytes, `ManifestlessVex` deletes
//! `.socket/manifest.json` (and any ledger), and proves the patch is
//! still attested `(redirected)` from the `yarn.lock` wiring alone (record
//! from the patch API), is `record_unavailable` `--offline` with zero API
//! requests, and is NOT attested once the lock is reverted to the registry
//! and really re-installed — plus the same through embedded `apply --vex`
//! and `scan --mode hosted --vex`. A dev-flow twin re-serializes the hosted
//! lock with `yarn add` (pre-1.10 releases drop the `integrity` line) and
//! attests from that yarn-written lock, installed and lockfile-only.
//!
//! The yarn release is `yarn@1.22.22` unless
//! `SOCKET_PATCH_YARN_CLASSIC_E2E_VERSION` names another 1.x (see
//! `common/yarn_classic_vex.rs`). Skips (with a println) when that yarn is
//! unavailable or the fixture install cannot reach the registry — unless
//! `SOCKET_PATCH_YARN_E2E_REQUIRED=1`; every assertion after is hard.

#[path = "common/mod.rs"]
mod common;
use common::binary;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[path = "common/yarn_classic_vex.rs"]
mod yarn_classic_vex;

use yarn_classic_vex::{
    installs_file_tarballs, require_yarn_classic, via_apply, yarn_classic, yarn_classic_version,
    Embedded, ManifestlessVex, Wiring,
};

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "7c8d9e0f-1a2b-4c3d-8e4f-5a6b7c8d9e0f";
const TOKEN: &str = "33333333-3333-4333-8333-333333333333";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const GHSA: &str = "GHSA-redirect-classic-real";
const PRODUCT: &str = "pkg:npm/app@1.0.0";
const CVE: &str = "CVE-2026-2222";

/// Print a SKIP line — or, under `SOCKET_PATCH_YARN_E2E_REQUIRED=1` (a leg
/// that provisioned corepack yarn on purpose), FAIL: a required leg must
/// never report green on an unexercised toolchain or an unreachable fixture
/// registry.
macro_rules! skip {
    ($($arg:tt)*) => {{
        yarn_classic_vex::skip("e2e_redirect_yarn_classic_build", &format!($($arg)*));
    }};
}

// ── self-contained helpers ────────────────────────────────────────────

fn scrub_socket_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("YARN_CACHE_FOLDER");
    // An ambient yarn 1 mirror setting, or a redirected rc file, would make
    // both yarn and the hosted scan see a mirror the leg did not set up.
    for (k, _) in std::env::vars_os() {
        let lower = k.to_string_lossy().to_ascii_lowercase();
        let config = lower.starts_with("yarn_") || lower.starts_with("npm_config_");
        if config && (lower.contains("offline_mirror") || lower.ends_with("userconfig")) {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("PREFIX");
}

fn corepack(cwd: &Path, pm: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
    // Scrub FIRST (it removes SOCKET_* and YARN_CACHE_FOLDER), then
    // set the hermetic flags so they survive.
    scrub_socket_env(&mut cmd);
    cache_env::isolate(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run corepack")
}

fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    run_socket_env(cwd, args, &[])
}

fn run_socket_env(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    scrub_socket_env(&mut cmd);
    // The hosted scan reads yarn 1's user rc files, so it must see the same
    // sandboxed HOME the fixture's `yarn install` ran under.
    cache_env::isolate(&mut cmd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
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
/// from the installed dep directory. Built in-process with tar+flate2 and
/// ONLY regular-file entries — yarn classic extracts the tarball directly and
/// rejects the directory/AppleDouble entries a system `tar -czf` emits
/// ("… is not a valid path"), while real npm tarballs never carry them.
fn build_patched_tgz(installed_dir: &Path, patched_index: &[u8], out_tgz: &Path) {
    fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let ft = entry.file_type().unwrap();
            if ft.is_dir() {
                collect_files(root, &entry.path(), out);
            } else if ft.is_file() {
                out.push(entry.path().strip_prefix(root).unwrap().to_path_buf());
            }
        }
    }
    let mut files = Vec::new();
    collect_files(installed_dir, installed_dir, &mut files);
    files.sort();

    let gz = flate2::write::GzEncoder::new(
        std::fs::File::create(out_tgz).unwrap(),
        flate2::Compression::default(),
    );
    let mut builder = tar::Builder::new(gz);
    for rel in files {
        let bytes = if rel == Path::new("index.js") {
            patched_index.to_vec()
        } else {
            std::fs::read(installed_dir.join(&rel)).unwrap()
        };
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        let entry_path = Path::new("package").join(&rel);
        builder
            .append_data(&mut header, entry_path, bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap();
}

/// Hex sha1 of `bytes` — the `resolved "…#<sha1>"` fragment yarn classic
/// verifies against the fetched tarball.
fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::Digest as _;
    hex::encode(sha1::Sha1::digest(bytes))
}

/// `sha512-<b64>` SRI of `bytes` — the classic `integrity` line.
fn sha512_sri(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
    )
}

/// Everything the fresh-checkout leg needs. `tmp` owns the tree; `_server`
/// keeps the hosted-tarball route alive through the fresh install.
struct ClassicRedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    orig: Vec<u8>,
    patched: Vec<u8>,
    /// The registry `yarn.lock` the real install wrote, before the rewrite.
    lock_pristine: Vec<u8>,
    server: MockServer,
}

/// Which CLI front door drives the hosted engine. Both consume the SAME
/// engine by construction (v4.0): `scan --mode hosted` discovers the dep,
/// while `get <uuid> --mode hosted` names the patch explicitly (the uuid
/// identifier path is exempt from installed narrowing and needs only the
/// view + reference mocks, which the fixture mounts anyway). get has no
/// `--vex`, so the get driver drops the vex flags + assertions.
#[derive(Clone, Copy, PartialEq, Debug)]
enum HostedDriver {
    Scan,
    GetUuid,
}

/// Where the fixture configures `yarn-offline-mirror`.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Mirror {
    None,
    /// The project's `.yarnrc` (#364).
    ProjectRc,
    /// The project's `.yarnrc`, saved with a UTF-8 BOM and CRLF (#1078).
    ProjectRcBom,
    /// The `.yarnrc` of the project's parent directory (#1013).
    ParentRc,
    /// `YARN_YARN_OFFLINE_MIRROR` (#1013).
    Env,
}

/// Steps 1–3: real install, patched tarball + API mocks, the hosted rewrite
/// (per `driver`: `scan --mode hosted --vex` or `get <uuid> --mode hosted`),
/// and the envelope/lockfile/ledger assertions.
/// `tamper_served_tarball` serves DIFFERENT bytes at the hosted URL than the
/// sha1/integrity pins. `mirror` configures `yarn-offline-mirror` (at
/// `<proj>/mirror`) where [`Mirror`] says before the fixture install, so the
/// mirror holds the upstream tarball, and asserts the hosted rewrite
/// REFUSES (#364) instead of pinning. `None` = skip (message printed).
async fn classic_hosted_project(
    tag: &str,
    tamper_served_tarball: bool,
    mirror: Mirror,
    driver: HostedDriver,
) -> Option<ClassicRedirectFixture> {
    let offline_mirror = mirror != Mirror::None;
    if !require_yarn_classic(&format!("e2e_redirect_yarn_classic_build ({tag})"), |c| {
        cache_env::isolate(c);
    }) {
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"redirect-classic-capstone","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}"}}}}"#
        ),
    )
    .unwrap();
    let mirror_dir = proj.join("mirror");
    let mirror_dir = mirror_dir.to_str().unwrap();
    // Where yarn reads the mirror from; the env leg sets it for yarn AND
    // the scan (the same shell would).
    let mut mirror_env: Vec<(&str, &str)> = Vec::new();
    match mirror {
        Mirror::None => {}
        Mirror::ProjectRc => {
            std::fs::write(proj.join(".yarnrc"), "yarn-offline-mirror \"./mirror\"\n").unwrap();
        }
        Mirror::ProjectRcBom => {
            std::fs::write(
                proj.join(".yarnrc"),
                "\u{feff}yarn-offline-mirror \"./mirror\"\r\n",
            )
            .unwrap();
        }
        Mirror::ParentRc => {
            std::fs::write(
                tmp.path().join(".yarnrc"),
                format!("yarn-offline-mirror {mirror_dir:?}\n"),
            )
            .unwrap();
        }
        Mirror::Env => {
            // yarn creates a mirror dir named in an rc file, never one
            // named in env.
            std::fs::create_dir_all(proj.join("mirror")).unwrap();
            mirror_env.push(("YARN_YARN_OFFLINE_MIRROR", mirror_dir));
        }
    }

    // 1. REAL fixture: yarn classic install (network here, private cache).
    let cache = tmp.path().join("yarn-cache");
    let mut install_env = vec![("YARN_CACHE_FOLDER", cache.to_str().unwrap())];
    install_env.extend_from_slice(&mirror_env);
    let install = corepack(
        &proj,
        &yarn_classic(),
        &["install", "--no-progress"],
        &install_env,
    );
    if !install.status.success() {
        skip!(
            "({tag}): fixture `yarn install` failed (registry unreachable?):\n{}",
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
    let lock_pristine = std::fs::read_to_string(proj.join("yarn.lock")).unwrap();
    assert!(
        lock_pristine.contains("# yarn lockfile v1"),
        "fixture must be a yarn classic v1 lock:\n{lock_pristine}"
    );

    // 2. Patched tarball + the exact hashes classic will verify at install.
    let tgz_path = tmp.path().join(format!("{DEP}-{DEP_VERSION}.tgz"));
    build_patched_tgz(&installed_dir, &patched, &tgz_path);
    let tgz = std::fs::read(&tgz_path).unwrap();
    let tgz_sha1 = sha1_hex(&tgz);
    let tgz_sri = sha512_sri(&tgz);
    let served: Vec<u8> = if tamper_served_tarball {
        // A DIFFERENT but still-valid tarball: rebuild with different patched
        // bytes so the fetched tarball can't satisfy the pinned hashes.
        let other: Vec<u8> = [b"/* SOCKET-TAMPERED */\n".as_slice(), orig.as_slice()].concat();
        let other_path = tmp.path().join("tampered.tgz");
        build_patched_tgz(&installed_dir, &other, &other_path);
        std::fs::read(&other_path).unwrap()
    } else {
        tgz.clone()
    };

    // 3. API mocks + the hosted tarball route yarn will hit at install time.
    let server = MockServer::start().await;
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
                    "title": "redirect classic capstone fixture"
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
    // Reference: granted, with the tarball artifact carrying BOTH hashes the
    // classic rewrite pins (sha1 fragment + sha512 SRI).
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
                          "integrity": { "sha512": tgz_sri, "sha1": tgz_sha1 } }
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
                    "cves": ["CVE-2026-2222"], "summary": "redirect classic capstone vuln",
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
    let (code, stdout, stderr) = run_socket_env(&proj, &argv, &mirror_env);
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("{driver:?} --mode hosted --json output is not JSON: {e}\nstdout:\n{stdout}")
    });
    if offline_mirror {
        // With nothing redirected, `--vex` has nothing to attest: the scan
        // fails closed on that rather than reporting a success.
        if driver == HostedDriver::Scan {
            assert_ne!(code, 0, "nothing attested must not exit 0: {env}");
            assert_eq!(env["error"]["code"], "manifest_not_found", "{env}");
        }
        // #364: the mirror would serve the upstream tarball under the hosted
        // URL's basename, so nothing is pinned, counted or attested.
        assert_eq!(
            env["summary"]["applied"], 0,
            "a mirrored project must not count a redirect: {env}"
        );
        assert!(
            env.to_string()
                .contains("redirect_yarn_classic_offline_mirror"),
            "the refusal must be reported: {env}"
        );
        assert_eq!(
            std::fs::read_to_string(proj.join("yarn.lock")).unwrap(),
            lock_pristine,
            "the refused lock must stay byte-identical"
        );
        if driver == HostedDriver::Scan {
            let vex = std::fs::read_to_string(proj.join("out.vex.json")).unwrap_or_default();
            assert!(
                !vex.contains("not_affected"),
                "a refused redirect must not be attested: {vex}"
            );
        }
        return Some(ClassicRedirectFixture {
            tmp,
            proj,
            orig,
            patched,
            lock_pristine: lock_pristine.into_bytes(),
            server,
        });
    }
    assert_eq!(
        code, 0,
        "{driver:?} --mode hosted failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 1, "one dep redirected: {env}");

    // Lockfile pin: hosted URL + #sha1 fragment + the recomputed integrity.
    let lock = std::fs::read_to_string(proj.join("yarn.lock")).unwrap();
    assert!(
        lock.contains(&format!("  resolved \"{hosted_url}#{tgz_sha1}\"")),
        "yarn.lock must resolve to the hosted tarball with the #sha1 fragment; got:\n{lock}"
    );
    assert!(
        lock.contains(&format!("  integrity {tgz_sri}")),
        "yarn.lock must carry the recomputed sha512 SRI of the patched tarball; got:\n{lock}"
    );
    assert!(
        !lock.contains("https://registry.yarnpkg.com/"),
        "the registry resolution must be gone from the rewired block:\n{lock}"
    );

    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "v5 hosted mode writes no redirect ledger — the lock is the hosted state"
    );

    Some(ClassicRedirectFixture {
        tmp,
        proj,
        orig,
        patched,
        lock_pristine: lock_pristine.into_bytes(),
        server,
    })
}

/// Fresh dir with only the committable files, then `yarn install
/// --frozen-lockfile` with an EMPTY private cache. The single dep resolves
/// from the mock host, so the registry is never needed.
fn fresh_checkout_yarn_install(fx: &ClassicRedirectFixture) -> (PathBuf, Output) {
    let fresh = fx.tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(fx.proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(fx.proj.join("yarn.lock"), fresh.join("yarn.lock")).unwrap();
    // v5 hosted mode writes nothing under `.socket/`; carry it when present.
    if fx.proj.join(".socket").is_dir() {
        copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
    }
    let fresh_cache = fx.tmp.path().join("fresh-yarn-cache");
    let ci = corepack(
        &fresh,
        &yarn_classic(),
        &["install", "--frozen-lockfile", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    (fresh, ci)
}

/// Manifest-less VEX over the fresh checkout `fresh` (hosted bytes
/// installed by the real yarn): see `ManifestlessVex::run` for the cells.
/// The record's afterHash is the patched `index.js`; the lock references the
/// fixture's mock host, so it is passed as `--patch-server-url`. `scan`
/// adds the embedded `scan --mode hosted --vex` re-resolution against the
/// fixture API (the command the flow itself ran).
fn manifestless_vex(fx: &ClassicRedirectFixture, fresh: &Path, leg: &str, scan: bool) {
    use vex_e2e_common::{git_sha256, patch_view, PatchApi, VexVia};
    let api = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(
            UUID,
            PURL,
            &[("package/index.js", &git_sha256(&fx.patched))],
            &[(GHSA, &[CVE])],
        ),
    )]);
    let server = fx.server.uri();
    let mut embedded: Vec<(&str, Embedded)> = vec![("apply --vex", via_apply())];
    if scan {
        embedded.push((
            "scan --mode hosted --vex",
            Box::new(|run| {
                let mut run = run
                    .via(VexVia::Scan)
                    .arg("--mode")
                    .arg("hosted")
                    .arg("--yes");
                run.proxy_url = None;
                run.api_url = Some(server.clone());
                run.api_token = Some("fake".to_string());
                run.org = Some(ORG.to_string());
                run
            }),
        ));
    }
    let tmp = fx.tmp.path().to_path_buf();
    let orig = fx.orig.clone();
    ManifestlessVex {
        leg,
        wiring: Wiring::Hosted,
        purl: PURL,
        uuid: UUID,
        vulns: &[(GHSA, &[CVE])],
        api: &api,
        proxy_override: None,
        patch_server_url: Some(fx.server.uri()),
        registry_lock: fx.lock_pristine.clone(),
        // A real `yarn install --frozen-lockfile` of the reverted lock (from
        // the registry): the installed tree is pristine again.
        reinstall: Some(Box::new(move |dir: &Path| {
            std::fs::remove_dir_all(dir.join("node_modules")).expect("rm node_modules");
            let cache = tmp.join(format!("{leg}-reverted-cache"));
            let out = corepack(
                dir,
                &yarn_classic(),
                &["install", "--frozen-lockfile", "--no-progress"],
                &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
            );
            assert!(
                out.status.success(),
                "{leg}: reverted-lock `yarn install --frozen-lockfile` failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let installed = std::fs::read(dir.join("node_modules").join(DEP).join("index.js"))
                .expect("reinstalled index.js");
            assert_eq!(
                installed, orig,
                "{leg}: the reverted lock installs pristine bytes"
            );
        })),
        embedded,
    }
    .run(fresh);
}

/// Dev flow over the hosted lock: `yarn add` re-serializes the WHOLE lock
/// from yarn's in-memory model (a release < 1.10 drops every `integrity`
/// line, leaving the `#sha1` fragment as the pin). The hosted block must
/// survive with its Socket URL, and a manifest-less, ledger-less checkout of
/// that yarn-written lock must still attest — installed, and lockfile-only
/// (nothing installed: the surviving pin is the evidence).
fn hosted_dev_resave_vex(fx: &ClassicRedirectFixture) {
    use vex_e2e_common::{
        assert_attested, binary, git_sha256, patch_view, run_vex, strip_ledgers, strip_manifest,
        Marker, PatchApi, VexRun,
    };
    let dev = fx.tmp.path().join("dev-resave");
    std::fs::create_dir_all(&dev).unwrap();
    std::fs::copy(fx.proj.join("package.json"), dev.join("package.json")).unwrap();
    std::fs::copy(fx.proj.join("yarn.lock"), dev.join("yarn.lock")).unwrap();
    let cache = fx.tmp.path().join("dev-resave-cache");
    let add = corepack(
        &dev,
        &yarn_classic(),
        &["add", "isarray@2.0.5", "--no-progress"],
        &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
    );
    assert!(
        add.status.success() && String::from_utf8_lossy(&add.stdout).contains("Saved lockfile"),
        "`yarn add` must re-serialize the hosted lock:\n{}\n{}",
        String::from_utf8_lossy(&add.stdout),
        String::from_utf8_lossy(&add.stderr)
    );
    let lock = std::fs::read_to_string(dev.join("yarn.lock")).unwrap();
    let hosted = format!("/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/");
    assert!(
        lock.contains(&hosted),
        "hosted block lost by `yarn add`:\n{lock}"
    );
    if !yarn_classic_vex::writes_integrity(&yarn_classic_vex::yarn_classic_version()) {
        // The attestations below then rest on the `#sha1` pin alone.
        assert!(
            !lock.contains("integrity "),
            "a pre-1.10 re-save drops every `integrity` line:\n{lock}"
        );
    }
    assert_eq!(
        std::fs::read(dev.join("node_modules").join(DEP).join("index.js")).unwrap(),
        fx.patched,
        "the re-linked tree carries the hosted (patched) bytes"
    );
    strip_manifest(&dev);
    strip_ledgers(&dev);
    let api = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(
            UUID,
            PURL,
            &[("package/index.js", &git_sha256(&fx.patched))],
            &[(GHSA, &[CVE])],
        ),
    )]);
    let run = VexRun {
        patch_server_url: Some(fx.server.uri()),
        ..VexRun::online(&api)
    };
    for installed in [true, false] {
        if !installed {
            std::fs::remove_dir_all(dev.join("node_modules")).unwrap();
        }
        let out = run_vex(&binary(), &dev, &run);
        assert_eq!(
            out.code,
            Some(0),
            "re-saved hosted lock (installed={installed}):\n{out}"
        );
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, &[(GHSA, &[CVE])]);
        println!(
            "VEXCELL leg=redirect-dev-resave yarn={} mode=hosted cell={} PASS",
            yarn_classic_vex::yarn_classic_version(),
            if installed {
                "resaved-installed"
            } else {
                "resaved-lockfile-only"
            }
        );
    }
}

// ── the capstone ──────────────────────────────────────────────────────

// #[serial]: real yarn classic keeps a process-wide mutex on its cache dirs
// and the twin legs build tarballs from the same fixture; serializing keeps
// the tampered twin from ever observing the main leg's cache state.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_redirect_fresh_checkout_installs_patched_bytes() {
    let Some(fx) = classic_hosted_project("main", false, Mirror::None, HostedDriver::Scan).await
    else {
        return;
    };

    let (fresh, ci) = fresh_checkout_yarn_install(&fx);
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --frozen-lockfile` must succeed from the hosted patch \
         tarball.\nstdout:\n{}\nstderr:\n{}",
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

    // Off the async executor: the patch-API stand-in runs its own runtime.
    tokio::task::block_in_place(|| manifestless_vex(&fx, &fresh, "redirect-scan", true));
    tokio::task::block_in_place(|| hosted_dev_resave_vex(&fx));
}

/// get-driven hosted twin (v4.0): `get <uuid> --mode hosted --json --yes`
/// routes through the SAME hosted engine as `scan --mode hosted`, so the
/// classic chain must hold unchanged — the fixture's lock pin (hosted URL +
/// `#sha1` + recomputed integrity) and ledger assertions run against the get
/// front door, and the fresh `yarn install --frozen-lockfile` (empty cache,
/// dead registry) installs the patched bytes from the hosted tarball. The
/// uuid identifier path is exempt from installed narrowing, so only the
/// view + reference mocks matter (the fixture mounts them anyway).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_get_uuid_hosted_fresh_checkout_installs() {
    let Some(fx) =
        classic_hosted_project("get-uuid", false, Mirror::None, HostedDriver::GetUuid).await
    else {
        return;
    };

    let (fresh, ci) = fresh_checkout_yarn_install(&fx);
    assert!(
        ci.status.success(),
        "fresh-checkout `yarn install --frozen-lockfile` must succeed from the hosted patch \
         tarball (get-driven redirect).\nstdout:\n{}\nstderr:\n{}",
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

    tokio::task::block_in_place(|| manifestless_vex(&fx, &fresh, "redirect-get-uuid", false));
}

/// Negative twin: the hosted URL serves a DIFFERENT tarball while the lock
/// pins the real sha1/integrity — the fresh install must fail on the
/// integrity/hash check, proving the lock pin is enforcement.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_redirect_tampered_hosted_tarball_fails_integrity() {
    let Some(fx) = classic_hosted_project("tampered", true, Mirror::None, HostedDriver::Scan).await
    else {
        return;
    };

    let (fresh, ci) = fresh_checkout_yarn_install(&fx);
    assert!(
        !ci.status.success(),
        "yarn classic MUST fail when the served tarball does not match the pinned \
         sha1/integrity.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let chatter = format!(
        "{}\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr)
    )
    .to_lowercase();
    assert!(
        chatter.contains("integrity") || chatter.contains("hash"),
        "the failure must be the integrity/hash check, not something incidental:\n{chatter}"
    );
    // The tampered bytes must never land in node_modules.
    let index = fresh.join("node_modules").join(DEP).join("index.js");
    if let Ok(installed) = std::fs::read(&index) {
        assert!(
            !installed.starts_with(b"/* SOCKET-TAMPERED */"),
            "tampered bytes must not be installed"
        );
    }
}

/// #364: with `yarn-offline-mirror` set, yarn 1 looks the tarball up in the
/// mirror by the basename of `resolved`, which the hosted URL shares with
/// the upstream tarball already there, so a hosted pin would make every
/// install fail its integrity check. The hosted rewrite refuses instead
/// (the fixture asserts no redirect, no attestation, an untouched lock),
/// and the fresh checkout still installs offline from the mirror.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_offline_mirror_refuses_hosted_and_keeps_installs_working() {
    let Some(fx) = classic_hosted_project(
        "offline-mirror",
        false,
        Mirror::ProjectRc,
        HostedDriver::Scan,
    )
    .await
    else {
        return;
    };
    assert!(
        fx.proj
            .join("mirror")
            .join(format!("{DEP}-{DEP_VERSION}.tgz"))
            .is_file(),
        "the fixture install must populate the offline mirror"
    );
    let fresh = fx.tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    for f in ["package.json", "yarn.lock", ".yarnrc"] {
        std::fs::copy(fx.proj.join(f), fresh.join(f)).unwrap();
    }
    copy_dir_recursive(&fx.proj.join("mirror"), &fresh.join("mirror"));
    let fresh_cache = fx.tmp.path().join("fresh-yarn-cache");
    // yarn 1.0–1.6 install nothing from a mirror (a local tarball), with or
    // without socket-patch: the control the issue measured. Pin that
    // limitation there instead of the upstream bytes.
    if !installs_file_tarballs(&yarn_classic_version()) {
        let ci = corepack(
            &fresh,
            &yarn_classic(),
            &["install", "--frozen-lockfile", "--no-progress"],
            &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
        );
        assert!(
            ci.status.success(),
            "stderr:\n{}",
            String::from_utf8_lossy(&ci.stderr)
        );
        assert!(
            !fresh
                .join("node_modules")
                .join(DEP)
                .join("index.js")
                .exists(),
            "yarn < 1.7 is expected to install nothing from the mirror"
        );
        return;
    }
    for extra in [&[][..], &["--offline"][..]] {
        let mut args = vec!["install", "--frozen-lockfile", "--no-progress"];
        args.extend_from_slice(extra);
        let ci = corepack(
            &fresh,
            &yarn_classic(),
            &args,
            &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
        );
        assert!(
            ci.status.success(),
            "`yarn {args:?}` must still install from the mirror.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&ci.stdout),
            String::from_utf8_lossy(&ci.stderr),
        );
        let installed =
            std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
        assert_eq!(
            installed, fx.orig,
            "the untouched lock installs the upstream bytes"
        );
        std::fs::remove_dir_all(fresh.join("node_modules")).unwrap();
    }
}

/// #1078 / #1013: yarn 1 also takes the mirror from a BOM-prefixed project
/// `.yarnrc`, an ancestor directory's `.yarnrc` and a `YARN_*` env var, so
/// each refuses the hosted rewrite like the plain project rc above (the
/// fixture asserts no redirect, no attestation, an untouched lock).
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_offline_mirror_outside_project_rc_refuses_hosted() {
    for (tag, mirror) in [
        ("offline-mirror-bom", Mirror::ProjectRcBom),
        ("offline-mirror-parent", Mirror::ParentRc),
        ("offline-mirror-env", Mirror::Env),
    ] {
        let Some(fx) = classic_hosted_project(tag, false, mirror, HostedDriver::Scan).await else {
            continue;
        };
        assert!(
            fx.proj
                .join("mirror")
                .join(format!("{DEP}-{DEP_VERSION}.tgz"))
                .is_file(),
            "{tag}: yarn must read this mirror config (the fixture install populates it)"
        );
    }
}

/// #363: a git-sourced dependency (`git+file://…#v1.3.0`) locks as a block
/// yarn 1 fetches with GIT, from its `resolved`. `scan --mode hosted` must
/// leave that block byte-identical (rewriting `resolved` to the hosted
/// tarball made every later install fail with `git ls-remote` on a `.tgz`),
/// say so with `redirect_yarn_classic_git_skipped`, and attest nothing in
/// its in-run VEX. The fresh-checkout `yarn install --frozen-lockfile` still
/// succeeds. The git repo is local, so no registry is needed.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_git_sourced_dependency_is_left_unrewired() {
    if cfg!(windows) {
        // `git+file:` urls over a drive-letter path are not a shape yarn 1
        // parses reliably; the rewriter logic is OS-independent and unit
        // tested.
        println!("SKIP classic_git_sourced_dependency_is_left_unrewired: not on Windows");
        return;
    }
    if !require_yarn_classic("e2e_redirect_yarn_classic_build (git)", |c| {
        cache_env::isolate(c);
    }) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    // A local git source of left-pad@1.3.0, tagged v1.3.0.
    let repo = tmp.path().join("lpgit");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join("package.json"),
        format!(r#"{{"name":"{DEP}","version":"{DEP_VERSION}","main":"index.js"}}"#),
    )
    .unwrap();
    let orig: &[u8] = b"module.exports = function leftPad(s) { return s; };\n";
    std::fs::write(repo.join("index.js"), orig).unwrap();
    for args in [
        &["init", "-q"][..],
        &["add", "-A"],
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "v",
        ],
        &["tag", "v1.3.0"],
    ] {
        let st = Command::new("git")
            .args(args)
            .current_dir(&repo)
            .status()
            .expect("git");
        assert!(st.success(), "git {args:?}");
    }

    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"git-classic","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"git+file://{}#v1.3.0"}}}}"#,
            repo.display()
        ),
    )
    .unwrap();
    let cache = tmp.path().join("yarn-cache");
    let install = corepack(
        &proj,
        &yarn_classic(),
        &["install", "--no-progress"],
        &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
    );
    if !install.status.success() {
        skip!(
            "(git): fixture `yarn install` of the git source failed:\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }
    let lock_pristine = std::fs::read_to_string(proj.join("yarn.lock")).unwrap();
    assert!(
        lock_pristine.contains("resolved \"git+file://"),
        "fixture must lock a git block:\n{lock_pristine}"
    );

    // A granted hosted patch for the same name@version.
    let installed_dir = proj.join("node_modules").join(DEP);
    let patched: Vec<u8> = [MARKER.as_bytes(), orig].concat();
    let tgz_path = tmp.path().join("patched.tgz");
    build_patched_tgz(&installed_dir, &patched, &tgz_path);
    let tgz = std::fs::read(&tgz_path).unwrap();
    let server = mock_hosted_grant(&tgz, orig, &patched, "git classic fixture").await;
    let api_url = server.uri();
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
    );
    println!("scan exit {code}\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scan --json output is not JSON: {e}\n{stdout}\n{stderr}"));
    assert_eq!(
        std::fs::read_to_string(proj.join("yarn.lock")).unwrap(),
        lock_pristine,
        "the git block must stay byte-identical: {env}"
    );
    assert!(
        env.to_string()
            .contains("redirect_yarn_classic_git_skipped"),
        "the skip must be named: {env}"
    );
    let vex = std::fs::read_to_string(proj.join("out.vex.json")).unwrap_or_default();
    assert!(
        !vex.contains("not_affected"),
        "nothing may be attested for the git copy:\n{vex}\n{env}"
    );

    // A fresh checkout still installs (from git, unpatched).
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(proj.join("yarn.lock"), fresh.join("yarn.lock")).unwrap();
    let fresh_cache = tmp.path().join("fresh-yarn-cache");
    let ci = corepack(
        &fresh,
        &yarn_classic(),
        &["install", "--frozen-lockfile", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    assert!(
        ci.status.success(),
        "fresh `yarn install --frozen-lockfile` must still succeed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
}

/// #921: a `file:` directory dependency locks as a block with no
/// `resolved`; yarn 1 COPIES the directory into node_modules, so no lock
/// rewrite reaches it. `scan --mode hosted --json` must say so with
/// `redirect_yarn_classic_directory_skipped` (it used to report success
/// with no warning at all), leave the lock byte-identical and attest
/// nothing in its in-run VEX. The fork is local, so no registry is needed.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_file_directory_dependency_is_named_and_not_attested() {
    if !require_yarn_classic("e2e_redirect_yarn_classic_build (file:)", |c| {
        cache_env::isolate(c);
    }) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    let fork = proj.join("forks").join(DEP);
    std::fs::create_dir_all(&fork).unwrap();
    std::fs::write(
        fork.join("package.json"),
        format!(r#"{{"name":"{DEP}","version":"{DEP_VERSION}","main":"index.js"}}"#),
    )
    .unwrap();
    let orig: &[u8] = b"module.exports = function leftPad(s) { return s; };\n";
    std::fs::write(fork.join("index.js"), orig).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"file-classic","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"file:./forks/{DEP}"}}}}"#
        ),
    )
    .unwrap();
    let cache = tmp.path().join("yarn-cache");
    let install = corepack(
        &proj,
        &yarn_classic(),
        &["install", "--no-progress"],
        &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
    );
    if !install.status.success() {
        skip!(
            "(file:): fixture `yarn install` of the file: directory failed:\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }
    let lock_pristine = std::fs::read_to_string(proj.join("yarn.lock")).unwrap();
    assert!(
        lock_pristine.contains(&format!("{DEP}@file:./forks/{DEP}"))
            && !lock_pristine.contains("resolved"),
        "fixture must lock a file: directory block:\n{lock_pristine}"
    );

    let installed_dir = proj.join("node_modules").join(DEP);
    let patched: Vec<u8> = [MARKER.as_bytes(), orig].concat();
    let tgz_path = tmp.path().join("patched.tgz");
    build_patched_tgz(&installed_dir, &patched, &tgz_path);
    let tgz = std::fs::read(&tgz_path).unwrap();
    let server = mock_hosted_grant(&tgz, orig, &patched, "file: classic fixture").await;

    let api_url = server.uri();
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
    );
    println!("scan exit {code}\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scan --json output is not JSON: {e}\n{stdout}\n{stderr}"));
    assert_eq!(
        std::fs::read_to_string(proj.join("yarn.lock")).unwrap(),
        lock_pristine,
        "the file: block must stay byte-identical: {env}"
    );
    assert!(
        env.to_string()
            .contains("redirect_yarn_classic_directory_skipped"),
        "the skip must be named: {env}"
    );
    let vex = std::fs::read_to_string(proj.join("out.vex.json")).unwrap_or_default();
    assert!(
        !vex.contains("not_affected"),
        "nothing may be attested for the file: copy:\n{vex}\n{env}"
    );
}

/// #1236: the same `file:` directory declared under ANOTHER dependency
/// name (`"lp2": "file:./lpdir"`, lpdir being left-pad@1.3.0) locks as
/// `"lp2@file:./lpdir"`, beside the registry left-pad. yarn 1 copies it
/// into `node_modules/lp2`, so it stays unpatched whatever the pin does.
/// `scan --mode hosted` must still pin the registry block, name the copy
/// (`redirect_yarn_classic_directory_skipped`), and neither its in-run VEX
/// nor a lock-only `vex` may attest left-pad not_affected.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_file_directory_copy_under_another_name_is_named_and_not_attested() {
    if !require_yarn_classic("e2e_redirect_yarn_classic_build (other-name file:)", |c| {
        cache_env::isolate(c);
    }) {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    let copy = proj.join("lpdir");
    std::fs::create_dir_all(&copy).unwrap();
    std::fs::write(
        copy.join("package.json"),
        format!(r#"{{"name":"{DEP}","version":"{DEP_VERSION}","main":"index.js"}}"#),
    )
    .unwrap();
    let orig: &[u8] = b"module.exports = function leftPad(s) { return s; };\n";
    std::fs::write(copy.join("index.js"), orig).unwrap();
    std::fs::write(
        proj.join("package.json"),
        format!(
            r#"{{"name":"other-name-classic","version":"0.0.0","private":true,"dependencies":{{"{DEP}":"{DEP_VERSION}","lp2":"file:./lpdir"}}}}"#
        ),
    )
    .unwrap();
    let cache = tmp.path().join("yarn-cache");
    let install = corepack(
        &proj,
        &yarn_classic(),
        &["install", "--no-progress"],
        &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
    );
    if !install.status.success() {
        skip!(
            "(other-name file:): fixture `yarn install` failed:\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }
    let lock_pristine = std::fs::read_to_string(proj.join("yarn.lock")).unwrap();
    assert!(
        lock_pristine.contains("lp2@file:./lpdir"),
        "fixture must lock the copy under its dependency name:\n{lock_pristine}"
    );

    let installed_dir = proj.join("node_modules").join(DEP);
    let installed_orig = std::fs::read(installed_dir.join("index.js")).unwrap();
    let patched: Vec<u8> = [MARKER.as_bytes(), &installed_orig].concat();
    let tgz_path = tmp.path().join("patched.tgz");
    build_patched_tgz(&installed_dir, &patched, &tgz_path);
    let tgz = std::fs::read(&tgz_path).unwrap();
    let server = mock_hosted_grant(&tgz, &installed_orig, &patched, "other-name fixture").await;

    let api_url = server.uri();
    let api = [
        "--api-url",
        api_url.as_str(),
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    let mut args = vec![
        "scan",
        "--mode",
        "hosted",
        "--json",
        "--yes",
        "--cwd",
        proj.to_str().unwrap(),
        "--vex",
        "out.vex.json",
        "--vex-product",
        PRODUCT,
    ];
    args.extend(api);
    let (code, stdout, stderr) = run_socket(&proj, &args);
    println!("scan exit {code}\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scan --json output is not JSON: {e}\n{stdout}\n{stderr}"));
    let lock = std::fs::read_to_string(proj.join("yarn.lock")).unwrap();
    assert!(
        lock.contains(&format!("{UUID}/{DEP}-{DEP_VERSION}.tgz")),
        "the registry left-pad block must still be pinned:\n{lock}"
    );
    assert!(
        env.to_string()
            .contains("redirect_yarn_classic_directory_skipped"),
        "the other-name copy must be named: {env}"
    );
    assert!(env.to_string().contains("lp2@file:./lpdir"), "{env}");
    let vex = std::fs::read_to_string(proj.join("out.vex.json")).unwrap_or_default();
    assert!(
        !vex.contains("not_affected"),
        "the in-run VEX must not attest left-pad:\n{vex}\n{env}"
    );

    // Lock-only: with node_modules gone, `vex` reads only the lock.
    std::fs::remove_dir_all(proj.join("node_modules")).unwrap();
    let mut args = vec![
        "vex",
        "--cwd",
        proj.to_str().unwrap(),
        "--output",
        "lock-only.vex.json",
        "--product",
        PRODUCT,
        "--patch-server-url",
        api_url.as_str(),
    ];
    args.extend(api);
    let (code, stdout, stderr) = run_socket(&proj, &args);
    println!("vex exit {code}\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let vex = std::fs::read_to_string(proj.join("lock-only.vex.json")).unwrap_or_default();
    assert!(
        !vex.contains("not_affected"),
        "lock-only vex must not attest left-pad:\n{vex}\n{stdout}\n{stderr}"
    );
}

/// A mock patch API granting one hosted patch of `DEP@DEP_VERSION` whose
/// tarball is `tgz` (`index.js` from `orig` to `patched`).
async fn mock_hosted_grant(tgz: &[u8], orig: &[u8], patched: &[u8], title: &str) -> MockServer {
    let server = MockServer::start().await;
    let hosted_url = format!(
        "{}/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz",
        server.uri()
    );
    let summary = serde_json::json!({
        "uuid": UUID, "purl": PURL, "tier": "free",
        "cveIds": [], "ghsaIds": [], "severity": "high", "title": title
    });
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{ "purl": PURL, "patches": [summary] }],
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
                "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free", "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { UUID: {
                "status": "granted", "url": hosted_url, "purl": PURL,
                "artifacts": [{ "kind": "tarball", "url": hosted_url,
                    "integrity": { "sha512": sha512_sri(tgz), "sha1": sha1_hex(tgz) } }],
                "registryOverride": null
            } }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": compute_git_sha256_from_bytes(orig),
                "afterHash": compute_git_sha256_from_bytes(patched),
            } },
            "vulnerabilities": { GHSA: {
                "cves": [CVE], "summary": "s", "severity": "high", "description": "d"
            } },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(&server)
        .await;

    server
}
