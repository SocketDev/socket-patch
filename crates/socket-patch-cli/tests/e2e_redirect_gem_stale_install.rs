//! Hermetic e2e for the gem hosted-mode STALE-INSTALL warning
//! (`redirect_gem_stale_install`).
//!
//! Live-verified defect (2026-08-19 gem matrix, bundler 1.17.3 / 2.7.2 /
//! 4.0.18, fresh containers): `scan --mode hosted` for gems is a pure
//! Gemfile/Gemfile.lock text rewrite. On the natural warm path — `bundle
//! install` first (the gem materialized under BUNDLE_PATH), hosted redirect
//! second — the NEXT `bundle install` exits 0, reports `Using <gem>`, and
//! never refetches: the installed files and the cached `.gem` stay UPSTREAM
//! while the Gemfile + lock claim the patch registry. Silent on every
//! bundler major (bundler 4's CHECKSUMS verify at download time only, and
//! nothing is downloaded). `bundle install --force`/`--redownload` do NOT
//! heal it either — verified: they reinstall from the stale cached `.gem`
//! (bundler 1 silently, bundler 4 with an exit-37 checksum refusal). The
//! only verified remedy is removing the stale materialization (gems dir +
//! cache `.gem` + specifications entry) and re-running `bundle install`.
//!
//! These tests pin the CLI-side guard: after the rewrite, the hosted flow
//! probes the project's bundle paths (the ruby crawler's discovery — the
//! same APIs `apply` uses) for a materialization of each redirected gem and
//! hash-compares it against the patch record's afterHash file map:
//!
//!   1. STALE materialization (upstream bytes on disk) → LOUD
//!      `redirect_gem_stale_install` warning in the JSON envelope naming the
//!      installed dir, the cache `.gem`, the specifications entry, and the
//!      verified remedy — and the same detail on stderr in human mode.
//!   2. ALREADY-PATCHED materialization (all files at afterHash — e.g. an
//!      agent-mode apply preceded the mode switch) → NO warning: the check
//!      must never false-positive on a patched install.
//!   3. FRESH CHECKOUT (no materialization at all) → NO warning: the
//!      redirect's normal `bundle install` flow fetches the patched gem.
//!
//! Fully hermetic: the "installed" gem is laid down by hand in bundler's
//! deployment layout (`vendor/bundle/ruby/<ver>/{gems,cache,specifications}`),
//! one wiremock plays the whole patches API, and no ruby/gem/bundler is
//! shelled anywhere on the stale/patched arms.

use std::path::{Path, PathBuf};
use std::process::Command;

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const DEP: &str = "stale-probe-gem";
const DEP_VERSION: &str = "1.0.0";
const PURL: &str = "pkg:gem/stale-probe-gem@1.0.0";
const UUID: &str = "8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d";
const TOKEN: &str = "66666666-6666-4666-8666-666666666666";
const GHSA: &str = "GHSA-gem-stale-e2e";

const UPSTREAM_LIB: &str =
    "module StaleProbeGem\n  def self.status\n    \"VULNERABLE\"\n  end\nend\n";
const PATCHED_LIB: &str = "module StaleProbeGem\n  def self.status\n    \"PATCHED\"\n  end\nend\n";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// Run the socket-patch binary with the ambient `SOCKET_*` surface scrubbed
/// (a developer's env must not steer the assertions) and config reads off.
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env("SOCKET_NO_CONFIG", "1");
    cmd.env_remove("VIRTUAL_ENV");
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Mount the whole patches API: batch discovery, by-package selection, the
/// granted reference (rubygems-compact-index override, the identifier shape
/// the TS reference builder emits), and the patch view whose file map carries
/// the REAL before/after hashes of the fixture lib.
async fn mount_api(server: &MockServer) {
    let hosted_url = format!(
        "{}/patch/gem/{DEP}/{DEP_VERSION}/{TOKEN}/{UUID}/{DEP}-{DEP_VERSION}.gem",
        server.uri()
    );
    let index_url = format!("{}/patch-registry/gem/{TOKEN}/{UUID}/", server.uri());
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "gem stale-install fixture"
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
                        "integrity": { "sha256": "c0ffee".repeat(10) + "abcd" }
                    }],
                    "registryOverride": {
                        "kind": "rubygems-compact-index",
                        "indexUrl": index_url,
                        "identifiers": {
                            "name": DEP,
                            "version": DEP_VERSION,
                            "gemChecksumSha256": "c0ffee".repeat(10) + "abcd",
                        }
                    }
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
                "lib/stale_probe_gem.rb": {
                    "beforeHash": compute_git_sha256_from_bytes(UPSTREAM_LIB.as_bytes()),
                    "afterHash": compute_git_sha256_from_bytes(PATCHED_LIB.as_bytes()),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-4444"],
                    "summary": "gem stale-install fixture vuln",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// The committable pair: a plain Gemfile + a pre-CHECKSUMS Gemfile.lock (the
/// bundler 1/2 shape the live repro used — the warning must not depend on the
/// CHECKSUMS-era lock grammar).
fn write_manifest_pair(proj: &Path) {
    std::fs::write(
        proj.join("Gemfile"),
        format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n"),
    )
    .unwrap();
    std::fs::write(
        proj.join("Gemfile.lock"),
        format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    {DEP} ({DEP_VERSION})\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  {DEP} (= {DEP_VERSION})\n\n\
             BUNDLED WITH\n   1.17.3\n"
        ),
    )
    .unwrap();
}

/// Materialize the gem in bundler's deployment layout under the project —
/// installed dir + cached `.gem` + specifications entry, exactly what a real
/// `bundle install` leaves behind (verified layout on bundler 1.17/2.7/4.0).
/// Returns (installed gem dir, cache .gem path, specifications path).
fn materialize_installed_gem(proj: &Path, lib_content: &str) -> (PathBuf, PathBuf, PathBuf) {
    let home = proj.join("vendor/bundle/ruby/3.3.0");
    let gem_dir = home.join("gems").join(format!("{DEP}-{DEP_VERSION}"));
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join("lib/stale_probe_gem.rb"), lib_content).unwrap();
    let cache = home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem"));
    std::fs::create_dir_all(cache.parent().unwrap()).unwrap();
    std::fs::write(&cache, b"upstream-gem-archive-bytes").unwrap();
    let spec = home
        .join("specifications")
        .join(format!("{DEP}-{DEP_VERSION}.gemspec"));
    std::fs::create_dir_all(spec.parent().unwrap()).unwrap();
    std::fs::write(&spec, "# stub gemspec\n").unwrap();
    (gem_dir, cache, spec)
}

fn hosted_scan_json(proj: &Path, api: &str) -> (i32, String, String) {
    run_socket(
        proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().expect("utf8 tmp path"),
            "--api-url",
            api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
    )
}

fn stale_warnings(env: &serde_json::Value) -> Vec<String> {
    env["redirect"]["warnings"]
        .as_array()
        .expect("redirect.warnings")
        .iter()
        .filter(|w| w["code"] == "redirect_gem_stale_install")
        .map(|w| w["detail"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// STALE materialization: the redirect succeeds AND the envelope carries the
/// loud machine-readable warning naming every stale path plus the verified
/// remedy. The human path mirrors the same detail to stderr.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_redirect_over_stale_install_warns_loudly() {
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let (gem_dir, cache, spec) = materialize_installed_gem(&proj, UPSTREAM_LIB);

    let (code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(
        code, 0,
        "hosted scan must succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout not JSON: {e}\n{stdout}"));
    assert_eq!(env["redirect"]["redirected"], 1, "envelope: {env}");
    let gemfile = std::fs::read_to_string(proj.join("Gemfile")).unwrap();
    assert!(
        gemfile.contains("/patch-registry/gem/"),
        "Gemfile must gain the patch-registry source block:\n{gemfile}"
    );

    let details = stale_warnings(&env);
    assert_eq!(
        details.len(),
        1,
        "exactly one stale-install warning for the one stale materialization: {env}"
    );
    let detail = &details[0];
    // The detail must name the dep, every stale path, and the VERIFIED remedy.
    assert!(detail.contains(PURL), "detail must name the purl: {detail}");
    for p in [&gem_dir, &cache, &spec] {
        assert!(
            detail.contains(&p.display().to_string()),
            "detail must name the stale path {}: {detail}",
            p.display()
        );
    }
    assert!(
        detail.contains("bundle install"),
        "detail must prescribe the re-install: {detail}"
    );
    // The empirically DISPROVEN remedies must be called out as non-remedies —
    // `--force`/`--redownload` reinstall from the stale cache (verified on
    // bundler 1.17/2.7/4.0), so the detail must steer users away from them.
    assert!(
        detail.contains("--redownload") && detail.contains("--force"),
        "detail must warn that --force/--redownload reinstall from the stale cache: {detail}"
    );

    // The installed tree was NOT touched — detection is read-only (no
    // destructive deletion by default).
    assert_eq!(
        std::fs::read_to_string(gem_dir.join("lib/stale_probe_gem.rb")).unwrap(),
        UPSTREAM_LIB,
        "detection must never modify the installed tree"
    );
    assert!(
        cache.is_file() && spec.is_file(),
        "detection must not delete"
    );

    // Human-mode re-scan (idempotent) re-detects and mirrors the SAME detail
    // to stderr — a re-run keeps warning until the stale install is gone.
    let (code, _stdout, stderr) = run_socket(
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
    assert_eq!(code, 0, "human re-scan must succeed:\n{stderr}");
    assert!(
        stderr.contains("redirect_gem_stale_install")
            || stderr.contains(&gem_dir.display().to_string()),
        "human mode must mirror the stale-install warning to stderr:\n{stderr}"
    );
}

/// ALREADY-PATCHED materialization (every record file at afterHash): the
/// warning must NOT fire — the check may never false-positive on a patched
/// install (e.g. agent-mode apply preceded the mode switch).
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_redirect_over_patched_install_stays_quiet() {
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    materialize_installed_gem(&proj, PATCHED_LIB);

    let (code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(
        code, 0,
        "hosted scan must succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout not JSON: {e}\n{stdout}"));
    assert_eq!(env["redirect"]["redirected"], 1, "envelope: {env}");
    assert!(
        stale_warnings(&env).is_empty(),
        "an already-patched materialization must never trip the stale warning: {env}"
    );
}

/// FRESH CHECKOUT (no materialization): quiet — the redirect's normal
/// `bundle install` flow fetches the patched gem; there is nothing stale.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_redirect_fresh_checkout_stays_quiet() {
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    // No vendor/bundle at all — the lockfile supplement carries discovery.

    let (code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(
        code, 0,
        "hosted scan must succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout not JSON: {e}\n{stdout}"));
    assert_eq!(env["redirect"]["redirected"], 1, "envelope: {env}");
    assert!(
        stale_warnings(&env).is_empty(),
        "a fresh checkout must not trip the stale warning: {env}"
    );
}
