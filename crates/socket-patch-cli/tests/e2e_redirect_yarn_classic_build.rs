//! Real-yarn-classic redirect capstone e2e — the hosted-mode full-chain proof
//! for the yarn v1 (classic lockfile) flavor, mirroring
//! `e2e_redirect_yarn_berry_build.rs` / `e2e_redirect_npm_build.rs`.
//!
//! `scan --mode hosted` never lands patched bytes in the repo: it rewrites the
//! classic `yarn.lock` block to
//! `resolved "<hosted-tgz-url>#<sha1>"` + a recomputed `integrity sha512-…`
//! line, and records the patch in the redirect ledger. This test proves every
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
//!      integrity, the ledger embeds the record, the in-run VEX is the
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
//! Skips (with a println) when `corepack yarn@1.22.22` is unavailable or the
//! fixture install cannot reach the registry; every assertion after is hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const DEP: &str = "left-pad";
const DEP_VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "7c8d9e0f-1a2b-4c3d-8e4f-5a6b7c8d9e0f";
const TOKEN: &str = "33333333-3333-4333-8333-333333333333";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const GHSA: &str = "GHSA-redirect-classic-real";
const PRODUCT: &str = "pkg:npm/app@1.0.0";
const YARN_CLASSIC: &str = "yarn@1.22.22";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Probe corepack from a NEUTRAL temp dir: a `packageManager` field in an
/// ancestor `package.json` (e.g. this monorepo's root) makes corepack refuse
/// to run a different package manager, which would spuriously fail the gate.
/// The real installs below all run in their own tempdirs, so the probe must
/// too.
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

fn scrub_socket_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env_remove("YARN_CACHE_FOLDER");
}

fn corepack(cwd: &Path, pm: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("corepack");
    cmd.arg(pm).args(args).current_dir(cwd);
    // Scrub FIRST (it removes YARN_* / SOCKET_* from the inherited env), then
    // set the hermetic flags so they survive.
    scrub_socket_env(&mut cmd);
    cmd.env("COREPACK_ENABLE_DOWNLOAD_PROMPT", "0");
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
    patched: Vec<u8>,
    _server: MockServer,
}

/// Steps 1–3: real install, patched tarball + API mocks, `scan --mode hosted
/// --vex`, and the envelope/lockfile/ledger assertions.
/// `tamper_served_tarball` serves DIFFERENT bytes at the hosted URL than the
/// sha1/integrity pins. `None` = skip (message printed).
async fn classic_hosted_project(
    tag: &str,
    tamper_served_tarball: bool,
) -> Option<ClassicRedirectFixture> {
    if !has_corepack_pm(YARN_CLASSIC) {
        println!(
            "SKIP e2e_redirect_yarn_classic_build ({tag}): `corepack {YARN_CLASSIC}` unavailable"
        );
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

    // 1. REAL fixture: yarn classic install (network here, private cache).
    let cache = tmp.path().join("yarn-cache");
    let install = corepack(
        &proj,
        YARN_CLASSIC,
        &["install", "--no-progress"],
        &[("YARN_CACHE_FOLDER", cache.to_str().unwrap())],
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_redirect_yarn_classic_build ({tag}): fixture `yarn install` failed \
             (registry unreachable?):\n{}",
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

    // scan --mode hosted --vex.
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
            "--vex",
            "out.vex.json",
            "--vex-product",
            PRODUCT,
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
        "one dep redirected: {env}"
    );

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

    let ledger = std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("\"records\"") && ledger.contains(GHSA),
        "redirect ledger must embed the patch record + vulnerability: {ledger}"
    );

    Some(ClassicRedirectFixture {
        tmp,
        proj,
        patched,
        _server: server,
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
    copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
    let fresh_cache = fx.tmp.path().join("fresh-yarn-cache");
    let ci = corepack(
        &fresh,
        YARN_CLASSIC,
        &["install", "--frozen-lockfile", "--no-progress"],
        &[("YARN_CACHE_FOLDER", fresh_cache.to_str().unwrap())],
    );
    (fresh, ci)
}

// ── the capstone ──────────────────────────────────────────────────────

// #[serial]: real yarn classic keeps a process-wide mutex on its cache dirs
// and the twin legs build tarballs from the same fixture; serializing keeps
// the tampered twin from ever observing the main leg's cache state.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_redirect_fresh_checkout_installs_patched_bytes() {
    let Some(fx) = classic_hosted_project("main", false).await else {
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
}

/// Negative twin: the hosted URL serves a DIFFERENT tarball while the lock
/// pins the real sha1/integrity — the fresh install must fail on the
/// integrity/hash check, proving the lock pin is enforcement.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn classic_redirect_tampered_hosted_tarball_fails_integrity() {
    let Some(fx) = classic_hosted_project("tampered", true).await else {
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
