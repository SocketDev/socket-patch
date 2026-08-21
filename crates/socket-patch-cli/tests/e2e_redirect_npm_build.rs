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
//! v3.6 adds get-driven twins through the SAME fixture: `get <uuid> --mode
//! hosted` must land the identical redirect (no manifest, no blobs — the
//! ledger is the persistence), and `get <GHSA> --mode hosted` must narrow a
//! two-version fan-out to the installed version BEFORE the grant request.
//!
//! Skips (with a println) when `npm`/`tar` are missing or the fixture install
//! cannot reach the registry; every assertion after that is hard.

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
const GHSA: &str = "GHSA-redirect-real";
const PRODUCT: &str = "pkg:npm/app@1.0.0";
/// GHSA identifier the get-narrowing twin searches by. Must match get's
/// auto-detect shape (`GHSA-xxxx-xxxx-xxxx`) — the free-form `GHSA` above
/// only keys the view record's vulnerabilities map, which get never parses
/// as an identifier.
const SEARCH_GHSA: &str = "GHSA-gett-hstd-narw";
/// Fabricated second fan-out patch: a version this project does NOT have
/// installed (nor lock-resolved). Its uuid reaching the reference endpoint
/// means the installed-version narrowing regressed.
const UUID_UNINSTALLED: &str = "9f8e7d6c-5b4a-4c3d-8e2f-1a0b9c8d7e6f";
const PURL_UNINSTALLED: &str = "pkg:npm/left-pad@9.9.9";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn has_command(cmd: &str) -> bool {
    let mut probe = Command::new(cmd);
    probe.arg("--version");
    cache_env::isolate(&mut probe);
    probe
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
    let mut cmd = Command::new("npm");
    cmd.args(args).current_dir(cwd);
    cache_env::isolate(&mut cmd);
    cmd.output().expect("failed to run npm")
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
/// `server` keeps the hosted-tarball route alive through the fresh `npm ci`
/// and is queried by the narrowing twin's received-request oracles.
struct RedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    patched: Vec<u8>,
    server: MockServer,
}

/// Which CLI invocation drives step 3 (the redirect itself). The scan
/// variant is the original capstone; the get variants prove `get … --mode
/// hosted` parity through the same fixture — a (purl, uuid)-identical
/// selection must produce the identical on-disk redirect.
#[derive(Clone, Copy, PartialEq, Debug)]
enum RedirectCli {
    /// `scan --redirect --json --yes --vex …` (embedded VEX asserted).
    ScanRedirectVex,
    /// `get <UUID> --mode hosted --json --yes` — get has no `--vex`.
    GetUuidHosted,
    /// `get <SEARCH_GHSA> --mode hosted --json --yes`, with a two-version
    /// by-ghsa fan-out mounted: the real patch for the installed version +
    /// a fabricated one for an uninstalled version that MUST be narrowed
    /// out before the grant request.
    GetGhsaHosted,
}

/// Steps 1–3 of the module doc: real install, patched tarball + API mocks
/// (same contract as `tests/in_process_redirect.rs`), the `cli`-selected
/// redirect invocation, and the envelope/lockfile/ledger assertions. When
/// `tamper_served_tarball` is set, the tarball route serves DIFFERENT bytes
/// than the sha512 pinned into the lockfile — the negative twin's premise.
/// `None` = skip (message already printed).
async fn redirect_scanned_project(
    tag: &str,
    tamper_served_tarball: bool,
    cli: RedirectCli,
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
    // The GHSA fan-out the narrowing twin resolves through: the real patch
    // for the installed 1.3.0 plus a fabricated one for the uninstalled
    // 9.9.9 (listed first, with a NEWER publishedAt, so any regression that
    // skips the narrowing has every chance to pick it up).
    if cli == RedirectCli::GetGhsaHosted {
        let fanout_patch = |uuid: &str, purl: &str, published: &str| {
            serde_json::json!({
                "uuid": uuid, "purl": purl,
                "publishedAt": published,
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            })
        };
        Mock::given(method("GET"))
            .and(path(format!(
                "/v0/orgs/{ORG}/patches/by-ghsa/{SEARCH_GHSA}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [
                    fanout_patch(UUID_UNINSTALLED, PURL_UNINSTALLED, "2026-02-01T00:00:00Z"),
                    fanout_patch(UUID, PURL, "2026-01-01T00:00:00Z"),
                ],
                "canAccessPaidPatches": false,
            })))
            .mount(&server)
            .await;
    }

    // The redirect invocation itself: `scan --redirect --vex` (the original
    // capstone, in-run unverified attestation included) or one of the
    // `get … --mode hosted` twins (get has no --vex).
    let uri = server.uri();
    let proj_str = proj.to_str().unwrap();
    let argv: Vec<&str> = match cli {
        RedirectCli::ScanRedirectVex => vec![
            "scan",
            "--redirect",
            "--json",
            "--yes",
            "--cwd",
            proj_str,
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--vex",
            "out.vex.json",
            "--vex-product",
            PRODUCT,
        ],
        RedirectCli::GetUuidHosted => vec![
            "get",
            UUID,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj_str,
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        RedirectCli::GetGhsaHosted => vec![
            "get",
            SEARCH_GHSA,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj_str,
            "--api-url",
            &uri,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    };
    let (code, stdout, stderr) = run_socket(&proj, &argv);
    assert_eq!(
        code,
        0,
        "`{}` failed.\nstdout:\n{stdout}\nstderr:\n{stderr}",
        argv.join(" ")
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "--json output of `{}` is not JSON: {e}\nstdout:\n{stdout}",
            argv.join(" ")
        )
    });
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["redirect"]["mode"], "hosted",
        "redirect sub-object is mode-tagged: {env}"
    );
    assert_eq!(
        env["redirect"]["redirected"], 1,
        "exactly one dep redirected: {env}"
    );
    match cli {
        RedirectCli::ScanRedirectVex => {
            assert_eq!(env["vex"]["path"], "out.vex.json", "vex block: {env}");
            assert_eq!(env["vex"]["statements"], 1, "vex block: {env}");
            assert_eq!(env["vex"]["format"], "openvex-0.2.0", "vex block: {env}");
            assert_eq!(
                env["vex"]["verified"], false,
                "in-run redirect VEX is attested from the ledger, not hash-verified: {env}"
            );
        }
        RedirectCli::GetUuidHosted => {
            assert_eq!(
                env["found"], 1,
                "uuid get resolves exactly one patch: {env}"
            );
            assert_eq!(
                env["patches"],
                serde_json::json!([]),
                "the UUID path is exempt from narrowing — no skip records: {env}"
            );
        }
        RedirectCli::GetGhsaHosted => {
            assert_eq!(env["found"], 2, "both fan-out versions were found: {env}");
            let skips = env["patches"].as_array().expect("patches array");
            assert_eq!(
                skips.len(),
                1,
                "exactly the uninstalled version is skipped: {env}"
            );
            assert_eq!(skips[0]["purl"], PURL_UNINSTALLED, "skip record: {env}");
            assert_eq!(skips[0]["uuid"], UUID_UNINSTALLED, "skip record: {env}");
            assert_eq!(
                skips[0]["errorCode"], "package_not_installed",
                "calm narrowing skip, never an error: {env}"
            );
        }
    }
    if cli != RedirectCli::ScanRedirectVex {
        assert!(
            env.get("vex").is_none(),
            "get has no --vex — no vex block may appear: {env}"
        );
        assert!(
            env.get("downloaded").is_none() && env.get("applied").is_none(),
            "hosted get drops downloaded/applied (nothing lands in .socket/): {env}"
        );
        assert!(
            !proj.join(".socket/manifest.json").exists(),
            "get --mode hosted must NOT write the manifest (scan parity)"
        );
        assert!(
            !proj.join(".socket/blobs").exists(),
            "get --mode hosted must NOT persist blobs"
        );
    }

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
        server,
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
#[ignore = "wall-bound real-npm install (~150s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn npm_redirect_fresh_checkout_npm_ci_installs_patched_bytes_and_vex_verifies() {
    let Some(fx) = redirect_scanned_project("main", false, RedirectCli::ScanRedirectVex).await
    else {
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
#[ignore = "wall-bound real-npm install (~150s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn npm_redirect_tampered_hosted_tarball_fails_fresh_npm_ci() {
    let Some(fx) = redirect_scanned_project("tampered", true, RedirectCli::ScanRedirectVex).await
    else {
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

// ── get --mode hosted twins (v3.6) ────────────────────────────────────

/// `get <uuid> --mode hosted` twin of the capstone: the same fixture (real
/// npm install, patched hosted tarball, API mocks) driven by get's UUID path
/// must land the identical redirect — lockfile pinned to the hosted tarball,
/// ledger written, NO manifest/blobs (all asserted inside the fixture) — and
/// a fresh checkout's `npm ci` must install the patched bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-bound real-npm install (~150s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn npm_get_uuid_hosted_fresh_checkout_npm_ci_installs_patched_bytes() {
    let Some(fx) = redirect_scanned_project("get-uuid", false, RedirectCli::GetUuidHosted).await
    else {
        return;
    };

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
}

/// `get <GHSA> --mode hosted` narrowing twin: the by-ghsa fan-out returns
/// TWO patches — the installed 1.3.0's and a fabricated one for an
/// uninstalled 9.9.9. The coarse installed-version narrowing must drop the
/// latter BEFORE the grant request (the reference body is the oracle — the
/// lockfile rewriter could never catch a granted-but-unmatchable version),
/// only the installed purl may land in the ledger, and the fresh-checkout
/// install must still land the patched bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-bound real-npm install (~150s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn npm_get_ghsa_hosted_narrows_and_installs() {
    let Some(fx) = redirect_scanned_project("get-ghsa", false, RedirectCli::GetGhsaHosted).await
    else {
        return;
    };

    // The reference request must carry ONLY the installed version's uuid —
    // requesting the uninstalled version's grant means the fan-out was not
    // narrowed before the hosted engine ran.
    let requests = fx.server.received_requests().await.unwrap_or_default();
    let reference_bodies: Vec<String> = requests
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/package"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert_eq!(reference_bodies.len(), 1, "exactly one reference request");
    assert!(
        reference_bodies[0].contains(UUID),
        "the installed version's uuid must be requested; body: {}",
        reference_bodies[0]
    );
    assert!(
        !reference_bodies[0].contains(UUID_UNINSTALLED),
        "the uninstalled version's uuid must be narrowed out BEFORE the grant \
         request; body: {}",
        reference_bodies[0]
    );
    let uninstalled_views = requests
        .iter()
        .filter(|r| {
            r.url
                .path()
                .contains(&format!("/patches/view/{UUID_UNINSTALLED}"))
        })
        .count();
    assert_eq!(
        uninstalled_views, 0,
        "the uninstalled version's view must never be fetched"
    );

    // Ledger: only the installed purl's record.
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fx.proj.join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    assert!(
        ledger["records"][PURL].is_object(),
        "the installed purl must be recorded in the ledger: {ledger}"
    );
    assert!(
        ledger["records"][PURL_UNINSTALLED].is_null(),
        "no ledger record for the uninstalled version: {ledger}"
    );

    // Fresh-checkout proof: the narrowed redirect still installs the
    // patched bytes.
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
}
