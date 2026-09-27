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
//! v5 adds the MANIFEST-LESS VEX tail to every flow that installs
//! (`npm_e2e_common::manifestless_vex_matrix`): with the fresh checkout's
//! ledger present, then deleted (lockfile discovery + a mock patch API),
//! then `--offline` (`record_unavailable`, zero requests), then with the
//! lock reverted to its registry bytes (`redirect_unwired`, `--no-verify`
//! too) — plus the embedded `apply --vex` twin. And it runs against EVERY
//! npm major: `SOCKET_PATCH_NPM_E2E_BIN` / `_VERSION` / `_REQUIRED` select
//! and pin the npm (see `npm_e2e_common`), npm 6's lockfileVersion 1
//! included, and the shrinkwrap flavor (`npm shrinkwrap` on <= 11, npm 12's
//! shrinkwrap + package-lock twin) has its own capstone. npm >= 12 refuses
//! the redirected lock (EALLOWREMOTE) unless `.npmrc` sets
//! `allow-remote=all`, so the hosted run AUTO-CONFIGURES it: every flow
//! asserts the run wrote `allow-remote=all` to a new project `.npmrc`
//! (ledger-recorded, `redirect_npm_allow_remote` warned), the fresh checkout
//! carries that committed `.npmrc` and installs with a PLAIN `npm ci` on
//! every major — npm >= 12 additionally proves the setting is load-bearing
//! (a checkout WITHOUT it is refused EALLOWREMOTE) — and the main capstone
//! ends with `rollback` removing exactly the `.npmrc` it created.
//!
//! Skips (with a println) when `npm` is missing or the fixture install
//! cannot reach the registry — unless `SOCKET_PATCH_NPM_E2E_REQUIRED` is set;
//! every assertion after that is hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha512};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "npm_e2e_common/mod.rs"]
mod npm_e2e_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use npm_e2e_common::{LockFlavor, ManifestlessCase};
use vex_e2e_common::{git_sha256, patch_view, Marker, PatchApi, VexVia};

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

/// Standard-base64-encoded sha512 of `bytes` — the body of the npm-family
/// `sha512-…` SRI integrity string.
fn sha512_sri_b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    let digest = Sha512::digest(bytes);
    base64::engine::general_purpose::STANDARD.encode(digest)
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    npm_e2e_common::copy_dir_recursive(src, dst)
}

/// Everything the post-redirect legs need. `tmp` owns the whole tree;
/// `server` keeps the hosted-tarball route alive through the fresh `npm ci`
/// and is queried by the narrowing twin's received-request oracles.
struct RedirectFixture {
    tmp: tempfile::TempDir,
    proj: PathBuf,
    patched: Vec<u8>,
    server: MockServer,
    /// The npm under test (major) and the committed lock files, with their
    /// pre-redirect (registry) bytes for the manifest-less revert cell.
    major: u32,
    flavor: LockFlavor,
    locks: Vec<&'static str>,
    pristine_locks: Vec<(&'static str, Vec<u8>)>,
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
    flavor: LockFlavor,
) -> Option<RedirectFixture> {
    let suite = format!("e2e_redirect_npm_build ({tag})");
    let Some(major) = npm_e2e_common::npm_major() else {
        npm_e2e_common::skip(&suite, "`npm` not installed");
        return None;
    };

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
    if !npm_e2e_common::install_fixture(&suite, &proj, &cache, &format!("{DEP}@{DEP_VERSION}")) {
        return None;
    }
    let expected_lock_version = match major {
        ..=6 => 1,
        7 | 8 => 2,
        _ => 3,
    };
    assert_eq!(
        npm_e2e_common::lockfile_version(&proj),
        Some(expected_lock_version),
        "npm {major} writes lockfileVersion {expected_lock_version}"
    );
    let locks = npm_e2e_common::commit_lock_flavor(&proj, flavor, major);
    let pristine_locks: Vec<(&'static str, Vec<u8>)> = locks
        .iter()
        .map(|lock| (*lock, std::fs::read(proj.join(lock)).unwrap()))
        .collect();

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
    // Packed like `npm pack` (regular-file members only): npm 7.0.x's
    // extractor fails ENOTDIR on the directory entries system tar adds.
    let tgz = npm_e2e_common::npm_pack_like(&stage.join("package"));
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

    // Lockfile pin: hosted URL + the PATCHED tarball's sha512, in EVERY
    // committed npm lock (npm 12 installs from the package-lock.json twin of
    // a shrinkwrap).
    for lock_name in &locks {
        let lock = std::fs::read_to_string(proj.join(lock_name)).unwrap();
        assert!(
            lock.contains(&hosted_url),
            "{lock_name} resolved must point at the hosted patch tarball; got:\n{lock}"
        );
        assert!(
            lock.contains(&sri),
            "{lock_name} integrity must be the patched tarball's sha512 ({sri}); got:\n{lock}"
        );
    }
    // A lockfileVersion 1 lock (npm <= 6) gets the npm 6 install caveat.
    let legacy_warned = env["redirect"]["warnings"]
        .as_array()
        .is_some_and(|w| w.iter().any(|w| w["code"] == "redirect_npm_legacy_client"));
    assert_eq!(
        legacy_warned,
        major <= 6,
        "redirect_npm_legacy_client iff the lock is v1: {env}"
    );
    // Every npm major gets the npm >= 12 install caveat (the run cannot know
    // which npm the project's CI uses).
    assert!(
        env["redirect"]["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w["code"] == "redirect_npm_allow_remote")),
        "the npm >= 12 allow-remote caveat must be emitted: {env}"
    );

    // ...and the run AUTO-CONFIGURED it: a new project `.npmrc` holding
    // exactly `allow-remote=all`, said so in the warning, ledger-recorded
    // (so `rollback` can remove exactly what it added).
    let allow_remote = env["redirect"]["warnings"]
        .as_array()
        .and_then(|w| w.iter().find(|w| w["code"] == "redirect_npm_allow_remote"))
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_default();
    assert!(
        allow_remote.contains("`allow-remote=all` was written to a new project .npmrc")
            && allow_remote.contains("lets npm install ANY url-resolved"),
        "the allow-remote auto-config must be reported with its tradeoff: {env}"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join(".npmrc")).unwrap(),
        "allow-remote=all\n",
        "the hosted run must write allow-remote=all to the project .npmrc"
    );

    // Ledger embeds the patch record so a post-install `vex` can verify.
    let ledger = std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("\"records\"") && ledger.contains(GHSA),
        "redirect ledger must embed the patch record + vulnerability: {ledger}"
    );
    assert!(
        ledger.contains("\"redirect_npmrc_allow_remote\""),
        "the .npmrc auto-config must be ledger-recorded: {ledger}"
    );

    Some(RedirectFixture {
        tmp,
        proj,
        patched,
        server,
        major,
        flavor,
        locks,
        pristine_locks,
    })
}

/// New dir holding ONLY what a git checkout would carry — package.json, the
/// committed npm lock(s), the committed `.npmrc` the hosted run wrote,
/// `.socket/` — then a PLAIN `npm ci` (no `--allow-remote` flag) against an
/// empty cache. Returns the fresh dir and the `npm ci` output (asserted by
/// each test: success for the real tarball, integrity failure for the
/// tampered one).
///
/// npm >= 12 first proves the auto-configured `.npmrc` is LOAD-BEARING: a
/// twin checkout without it is refused EALLOWREMOTE and installs nothing.
fn fresh_checkout_npm_ci(fx: &RedirectFixture) -> (PathBuf, Output) {
    let fresh = fx.tmp.path().join("fresh");
    npm_e2e_common::fresh_checkout(&fx.proj, &fresh, &fx.locks);
    assert_eq!(
        std::fs::read_to_string(fresh.join(".npmrc")).unwrap(),
        "allow-remote=all\n",
        "the fresh checkout carries the committed, auto-configured .npmrc"
    );
    if npm_e2e_common::needs_allow_remote(fx.major) {
        let bare = fx.tmp.path().join("fresh-without-npmrc");
        npm_e2e_common::fresh_checkout(&fx.proj, &bare, &fx.locks);
        std::fs::remove_file(bare.join(".npmrc")).unwrap();
        let refused = npm_e2e_common::npm_ci(&bare, &fx.tmp.path().join("refused-npm-cache"));
        let text = npm_e2e_common::output_text(&refused);
        assert!(
            !refused.status.success() && text.contains("EALLOWREMOTE"),
            "npm {} must refuse the redirected lock without allow-remote=all:\n{text}",
            fx.major
        );
        assert!(
            !bare.join("node_modules").join(DEP).exists(),
            "the refused install must not have installed anything"
        );
    }
    let fresh_cache = fx.tmp.path().join("fresh-npm-cache");
    let ci = npm_e2e_common::npm_ci(&fresh, &fresh_cache);
    (fresh, ci)
}

/// The capstone's last step: `rollback` in the redirected project unwinds
/// the lock redirect AND removes exactly the `.npmrc` the hosted run created
/// (the ledger's `redirect_npmrc_allow_remote` `created` edit), leaving the
/// committed lock(s) at their registry resolution and no ledger behind.
fn rollback_removes_npmrc(fx: &RedirectFixture) {
    let proj = fx.proj.to_str().unwrap();
    let (code, stdout, stderr) = run_socket(&fx.proj, &["rollback", "--json", "--cwd", proj]);
    assert_eq!(
        code, 0,
        "rollback failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !fx.proj.join(".npmrc").exists(),
        "rollback must remove the .npmrc the hosted run created:\n{stdout}"
    );
    let json = |b: &[u8]| serde_json::from_slice::<serde_json::Value>(b).unwrap();
    for (lock, pristine) in &fx.pristine_locks {
        let now = std::fs::read(fx.proj.join(lock)).unwrap();
        assert_eq!(
            json(&now),
            json(pristine),
            "rollback must restore {lock} to its registry resolution"
        );
    }
    assert!(
        !fx.proj.join(".socket/vendor/redirect-state.json").exists(),
        "the emptied redirect ledger is deleted"
    );
}

/// [`fresh_checkout_npm_ci`] + the install oracle every non-tampered flow
/// shares: npm >= 7 must install the PATCHED bytes byte-for-byte. npm <= 6
/// ignores `resolved` for a registry dependency (it fetches the registry
/// tarball — verified against 6.14.18), so its install must FAIL CLOSED with
/// EINTEGRITY against the patched sha512 pin and leave nothing installed
/// (the tail then exercises the lockfile basis). Returns `(fresh, installed)`.
fn fresh_install_patched(fx: &RedirectFixture) -> (PathBuf, bool) {
    let (fresh, ci) = fresh_checkout_npm_ci(fx);
    let text = npm_e2e_common::output_text(&ci);
    let index = fresh.join("node_modules").join(DEP).join("index.js");
    if fx.major <= 6 {
        assert!(
            !ci.status.success() && text.contains("EINTEGRITY"),
            "npm {} must refuse (EINTEGRITY) the registry bytes it fetches instead:\n{text}",
            fx.major
        );
        assert!(
            std::fs::read(&index).map_or(true, |b| b != fx.patched),
            "npm <= 6 cannot have installed the patched bytes"
        );
        let _ = std::fs::remove_dir_all(fresh.join("node_modules"));
        return (fresh, false);
    }
    assert!(
        ci.status.success(),
        "fresh-checkout `npm ci` must succeed from the hosted patch tarball.\n{text}"
    );
    let installed = std::fs::read(&index).unwrap();
    assert!(
        installed.starts_with(MARKER.as_bytes()),
        "npm ci must install the PATCHED bytes from the hosted patch; got:\n{}",
        String::from_utf8_lossy(&installed[..installed.len().min(120)])
    );
    assert_eq!(
        installed, fx.patched,
        "fresh install must be byte-identical to the patched content"
    );
    (fresh, true)
}

/// A patch API (public-proxy view route) serving the capstone's record
/// with the REAL patched hash — what manifest-less VEX fetches once the
/// ledger is gone. Built on its own runtime thread (the test's own runtime
/// cannot host a nested one).
fn manifestless_tail(fx: &RedirectFixture, fresh: &Path, installed: bool, embedded: &[VexVia]) {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let api = PatchApi::start(vec![(
                    UUID.to_string(),
                    patch_view(
                        UUID,
                        PURL,
                        &[("package/index.js", &git_sha256(&fx.patched))],
                        &[(GHSA, &["CVE-2026-1111"])],
                    ),
                )]);
                let case = ManifestlessCase {
                    label: format!("npm {} hosted {}", fx.major, fx.flavor.tag()),
                    project: fresh,
                    purl: PURL,
                    uuid: UUID,
                    marker: Marker::Redirected,
                    vulns: &[(GHSA, &["CVE-2026-1111"])],
                    api: &api,
                    patch_server_url: Some(fx.server.uri()),
                    registry_locks: fx.pristine_locks.clone(),
                    embedded,
                };
                let report = npm_e2e_common::manifestless_vex_matrix(&case);
                npm_e2e_common::record_results(&format!(
                    "npm={} mode=hosted flavor={} install={} {report}",
                    npm_e2e_common::npm_version().unwrap_or_default(),
                    fx.flavor.tag(),
                    if installed {
                        "patched"
                    } else {
                        "refused-EINTEGRITY"
                    }
                ));
            })
            .join()
            .expect("manifest-less VEX tail panicked");
    });
}

// ── the capstone ──────────────────────────────────────────────────────

// multi_thread: the CLI/npm subprocesses block a worker thread while wiremock
// keeps serving the API + tarball routes on the others.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-bound real-npm install (~150s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn npm_redirect_fresh_checkout_npm_ci_installs_patched_bytes_and_vex_verifies() {
    let Some(fx) = redirect_scanned_project(
        "main",
        false,
        RedirectCli::ScanRedirectVex,
        LockFlavor::PackageLock,
    )
    .await
    else {
        return;
    };

    // 4. FRESH-CHECKOUT PROOF: npm pulls the patched bytes from the hosted
    //    patch server because the committed lockfile says so.
    let (fresh, installed) = fresh_install_patched(&fx);

    // 5. POST-INSTALL VERIFIED VEX: default verify mode hash-verifies the
    //    installed tree against the ledger's patch record (npm <= 6 installed
    //    nothing — the manifest-less tail below covers its lockfile basis).
    if installed {
        post_install_ledger_vex(&fresh);
    }

    // 6. MANIFEST-LESS VEX over the fresh checkout: ledger present, ledger
    //    deleted (lockfile + API), offline, reverted — standalone and via
    //    the embedded `apply --vex`.
    manifestless_tail(&fx, &fresh, installed, &[VexVia::Apply]);

    // 7. ROLLBACK: the lock redirect AND the auto-configured .npmrc go.
    rollback_removes_npmrc(&fx);
}

/// Step 5 of the capstone: the ledger-backed, hash-verified `vex`.
fn post_install_ledger_vex(fresh: &Path) {
    let doc_path = fresh.join("doc.json");
    let (code, stdout, stderr) = run_socket(
        fresh,
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

/// Shrinkwrap flavor of the capstone: the committed lock is
/// npm-shrinkwrap.json — npm <= 11's `npm shrinkwrap` output (the lock is
/// renamed), npm 12's shrinkwrap + package-lock.json twin (the command is
/// gone and installs read the twin). The redirect must land in EVERY
/// committed lock, the fresh `npm ci` must install the patched bytes, and
/// the manifest-less VEX tail must attest them (and stop once reverted).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-bound real-npm install (~150s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn npm_redirect_shrinkwrap_fresh_checkout_and_manifestless_vex() {
    let Some(fx) = redirect_scanned_project(
        "shrinkwrap",
        false,
        RedirectCli::ScanRedirectVex,
        LockFlavor::Shrinkwrap,
    )
    .await
    else {
        return;
    };
    assert!(fx.locks.contains(&"npm-shrinkwrap.json"), "{:?}", fx.locks);
    let (fresh, installed) = fresh_install_patched(&fx);
    manifestless_tail(&fx, &fresh, installed, &[VexVia::Apply]);
}

/// Negative twin: the hosted route serves TAMPERED bytes while the lockfile
/// pins the REAL tarball's sha512 — the fresh `npm ci` must refuse to
/// install. This is what makes the redirect safe to commit: a compromised or
/// swapped hosted artifact cannot slip past the pin.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-bound real-npm install (~150s); runs on all 3 OSes as an e2e CI matrix leg"]
async fn npm_redirect_tampered_hosted_tarball_fails_fresh_npm_ci() {
    let Some(fx) = redirect_scanned_project(
        "tampered",
        true,
        RedirectCli::ScanRedirectVex,
        LockFlavor::PackageLock,
    )
    .await
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
    let Some(fx) = redirect_scanned_project(
        "get-uuid",
        false,
        RedirectCli::GetUuidHosted,
        LockFlavor::PackageLock,
    )
    .await
    else {
        return;
    };

    let (fresh, installed) = fresh_install_patched(&fx);
    manifestless_tail(&fx, &fresh, installed, &[VexVia::Apply]);
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
    let Some(fx) = redirect_scanned_project(
        "get-ghsa",
        false,
        RedirectCli::GetGhsaHosted,
        LockFlavor::PackageLock,
    )
    .await
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
    let (fresh, installed) = fresh_install_patched(&fx);
    manifestless_tail(&fx, &fresh, installed, &[]);
}
