//! Real-install redirect→VEX capstone e2e for npm — the full-chain proof.
//!
//! `scan --redirect` never lands patched bytes in the repo: it rewrites the
//! lockfile so the patched dependency RESOLVES from Socket's hosted vendored
//! patch (here: a wiremock standing in for patch.socket.dev) and records the
//! patch (file hashes + vulnerabilities) in the redirect ledger. This test
//! proves every link of that chain against the REAL npm:
//!
//!   1. `npm install left-pad@1.3.0` into a tempdir project (network used for
//!      fixture setup only, private cache).
//!   2. Build a PATCHED tarball from the actually-installed bytes (marker
//!      comment prepended to `index.js`) and serve it from wiremock, alongside
//!      the discovery / reference / view API mocks.
//!   3. `scan --redirect --json --vex …` (the real binary): the lockfile now
//!      pins the wiremock tarball URL + the patched tarball's sha512, the
//!      ledger embeds the patch record, and the in-run VEX is the unverified
//!      `(redirected)` attestation (`verified: false`).
//!   4. FRESH-CHECKOUT PROOF: only package.json + package-lock.json +
//!      `.socket/` travel; `npm ci --cache <empty>` MUST install the patched
//!      bytes — npm pulls them from the hosted patch server because the
//!      lockfile says so.
//!   5. POST-INSTALL VERIFIED VEX: `socket-patch vex` (default verify mode)
//!      hash-verifies the installed tree against the ledger records and emits
//!      the `(redirected)` statement.
//!
//! The negative twin serves TAMPERED tarball bytes while the lockfile keeps
//! the real sha512: the fresh `npm ci` must FAIL with an integrity error —
//! the lockfile pin is enforcement, not decoration.
//!
//! Skips (with a println) when `npm`/`tar` are missing or the fixture install
//! cannot reach the registry; every assertion after that is hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
const GHSA: &str = "GHSA-redirect-real";
const PRODUCT: &str = "pkg:npm/app@1.0.0";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
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

fn npm(cwd: &Path, args: &[&str]) -> Output {
    Command::new("npm")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to run npm")
}

/// Standard-base64-encoded sha512 of `bytes` — the body of the npm-family
/// `sha512-…` SRI integrity string.
fn sha512_sri_b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    let digest = Sha512::digest(bytes);
    base64::engine::general_purpose::STANDARD.encode(digest)
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

/// Everything the post-redirect legs need. `tmp` owns the whole tree;
/// `_server` keeps the hosted-tarball route alive through the fresh `npm ci`.
struct RedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    patched: Vec<u8>,
    _server: MockServer,
}

/// Steps 1–3 of the module doc: real install, patched tarball + API mocks
/// (same contract as `tests/in_process_redirect.rs`), `scan --redirect
/// --vex`, and the envelope/lockfile/ledger assertions. When
/// `tamper_served_tarball` is set, the tarball route serves DIFFERENT bytes
/// than the sha512 pinned into the lockfile — the negative twin's premise.
/// `None` = skip (message already printed).
async fn redirect_scanned_project(
    tag: &str,
    tamper_served_tarball: bool,
) -> Option<RedirectFixture> {
    if !has_command("npm") {
        println!("SKIP e2e_redirect_npm_build ({tag}): `npm` not installed");
        return None;
    }
    if !has_command("tar") {
        println!("SKIP e2e_redirect_npm_build ({tag}): `tar` not installed");
        return None;
    }

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"redirect-capstone","version":"0.0.0","private":true}"#,
    )
    .unwrap();

    // 1. REAL fixture: npm install (network allowed here, private cache).
    let cache = tmp.path().join("npm-cache");
    let install = npm(
        &proj,
        &[
            "install",
            &format!("{DEP}@{DEP_VERSION}"),
            "--no-audit",
            "--no-fund",
            "--cache",
            cache.to_str().unwrap(),
        ],
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_redirect_npm_build ({tag}): `npm install {DEP}@{DEP_VERSION}` failed \
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

    // 2. Patched npm tarball from the ACTUAL installed package: copy the
    //    installed dir under the `package/` prefix npm expects, swap in the
    //    patched entry point, tar it up (bsdtar or GNU tar — npm only needs
    //    the prefix). The lockfile pin is ALWAYS the real tarball's sha512;
    //    the negative twin only tampers what the route SERVES, so the pin is
    //    what catches the swap.
    let stage = tmp.path().join("tarstage");
    copy_dir_recursive(&proj.join("node_modules").join(DEP), &stage.join("package"));
    std::fs::write(stage.join("package").join("index.js"), &patched).unwrap();
    let tgz_path = tmp.path().join(format!("{DEP}-{DEP_VERSION}.tgz"));
    let tar = Command::new("tar")
        .args(["-czf", tgz_path.to_str().unwrap(), "package"])
        .current_dir(&stage)
        .output()
        .expect("failed to run tar");
    assert!(
        tar.status.success(),
        "tar failed: {}",
        String::from_utf8_lossy(&tar.stderr)
    );
    let tgz = std::fs::read(&tgz_path).unwrap();
    let sri = format!("sha512-{}", sha512_sri_b64(&tgz));
    let served: Vec<u8> = if tamper_served_tarball {
        [tgz.as_slice(), &[0u8][..]].concat()
    } else {
        tgz.clone()
    };

    // 3. API mocks + the hosted tarball route `npm ci` will hit.
    let server = MockServer::start().await;
    let hosted_url = format!(
        "{}/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz",
        server.uri()
    );
    // Batch discovery: the installed package has one free patch.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "redirect capstone fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    // Per-package search used by the redirect selection.
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
    // Reference endpoint: granted, pointing at the hosted tarball with the
    // real tarball's sha512 (what gets pinned into the lockfile).
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
        .mount(&server)
        .await;
    // View endpoint: the patch record (REAL before/after hashes of the
    // installed vs patched bytes) the redirect run persists for VEX.
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
                    "cves": ["CVE-2026-1111"],
                    "summary": "redirect capstone vuln",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(&server)
        .await;
    // The hosted tarball itself — what npm downloads at install time.
    Mock::given(method("GET"))
        .and(path(format!(
            "/patch/npm/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.tgz"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_raw(served, "application/octet-stream"))
        .mount(&server)
        .await;

    // scan --redirect --vex: rewrite the lockfile + emit the in-run
    // (unverified) attestation.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "scan",
            "--redirect",
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
        "scan --redirect failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("scan --redirect --json output is not JSON: {e}\nstdout:\n{stdout}")
    });
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "exactly one dep redirected: {env}"
    );
    assert_eq!(env["vex"]["path"], "out.vex.json", "vex block: {env}");
    assert_eq!(env["vex"]["statements"], 1, "vex block: {env}");
    assert_eq!(env["vex"]["format"], "openvex-0.2.0", "vex block: {env}");
    assert_eq!(
        env["vex"]["verified"], false,
        "in-run redirect VEX is attested from the ledger, not hash-verified: {env}"
    );

    // Lockfile pin: hosted URL + the PATCHED tarball's sha512.
    let lock = std::fs::read_to_string(proj.join("package-lock.json")).unwrap();
    assert!(
        lock.contains(&hosted_url),
        "lockfile resolved must point at the hosted patch tarball; got:\n{lock}"
    );
    assert!(
        lock.contains(&sri),
        "lockfile integrity must be the patched tarball's sha512 ({sri}); got:\n{lock}"
    );

    // Ledger embeds the patch record so a post-install `vex` can verify.
    let ledger = std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("\"records\"") && ledger.contains(GHSA),
        "redirect ledger must embed the patch record + vulnerability: {ledger}"
    );

    Some(RedirectFixture {
        tmp,
        proj,
        patched,
        _server: server,
    })
}

/// New dir holding ONLY what a git checkout would carry — package.json,
/// package-lock.json, `.socket/` — then `npm ci` against an empty cache.
/// Returns the fresh dir and the `npm ci` output (asserted by each test:
/// success for the real tarball, integrity failure for the tampered one).
fn fresh_checkout_npm_ci(fx: &RedirectFixture) -> (PathBuf, Output) {
    let fresh = fx.tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(fx.proj.join("package.json"), fresh.join("package.json")).unwrap();
    std::fs::copy(
        fx.proj.join("package-lock.json"),
        fresh.join("package-lock.json"),
    )
    .unwrap();
    copy_dir_recursive(&fx.proj.join(".socket"), &fresh.join(".socket"));
    let fresh_cache = fx.tmp.path().join("fresh-npm-cache");
    let ci = npm(
        &fresh,
        &[
            "ci",
            "--cache",
            fresh_cache.to_str().unwrap(),
            "--no-audit",
            "--no-fund",
        ],
    );
    (fresh, ci)
}

// ── the capstone ──────────────────────────────────────────────────────

// multi_thread: the CLI/npm subprocesses block a worker thread while wiremock
// keeps serving the API + tarball routes on the others.
#[tokio::test(flavor = "multi_thread")]
async fn npm_redirect_fresh_checkout_npm_ci_installs_patched_bytes_and_vex_verifies() {
    let Some(fx) = redirect_scanned_project("main", false).await else {
        return;
    };

    // 4. FRESH-CHECKOUT PROOF: npm pulls the patched bytes from the hosted
    //    patch server because the committed lockfile says so.
    let (fresh, ci) = fresh_checkout_npm_ci(&fx);
    assert!(
        ci.status.success(),
        "fresh-checkout `npm ci` must succeed from the hosted patch tarball.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let installed = std::fs::read(fresh.join("node_modules").join(DEP).join("index.js")).unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "npm ci must install the PATCHED bytes from the hosted patch; got:\n{}",
        String::from_utf8_lossy(&installed[..installed.len().min(120)])
    );
    assert_eq!(
        installed, fx.patched,
        "fresh install must be byte-identical to the patched content"
    );

    // 5. POST-INSTALL VERIFIED VEX: default verify mode hash-verifies the
    //    installed tree against the ledger's patch record.
    let doc_path = fresh.join("doc.json");
    let (code, stdout, stderr) = run_socket(
        &fresh,
        &[
            "vex",
            "--output",
            doc_path.to_str().unwrap(),
            "--product",
            PRODUCT,
            "--cwd",
            fresh.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "post-install vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&doc_path).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "exactly the redirected patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], PURL);
    assert_eq!(
        stmts[0]["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (redirected)"),
        "the post-install (hash-verified) attestation must carry the (redirected) marker"
    );
}

/// Negative twin: the hosted route serves TAMPERED bytes while the lockfile
/// pins the REAL tarball's sha512 — the fresh `npm ci` must refuse to
/// install. This is what makes the redirect safe to commit: a compromised or
/// swapped hosted artifact cannot slip past the pin.
#[tokio::test(flavor = "multi_thread")]
async fn npm_redirect_tampered_hosted_tarball_fails_fresh_npm_ci() {
    let Some(fx) = redirect_scanned_project("tampered", true).await else {
        return;
    };

    let (_fresh, ci) = fresh_checkout_npm_ci(&fx);
    assert!(
        !ci.status.success(),
        "npm ci MUST fail when the served tarball does not match the pinned sha512.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr),
    );
    let chatter = format!(
        "{}\n{}",
        String::from_utf8_lossy(&ci.stdout),
        String::from_utf8_lossy(&ci.stderr)
    );
    assert!(
        chatter.contains("EINTEGRITY") || chatter.to_lowercase().contains("integrity"),
        "the failure must be the integrity check, not something incidental:\n{chatter}"
    );
}
