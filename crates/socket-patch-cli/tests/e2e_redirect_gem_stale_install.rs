//! Hermetic e2e for the gem hosted-mode stale-install guard
//! (`redirect_gem_stale_install`) — the live-verified warm-path defect where
//! `bundle install` never refetches an already-materialized gem after the
//! redirect, and neither do `--force`/`--redownload` (they reinstall from
//! the stale cached `.gem`). Full narrative + verified remedies: the "Gem
//! stale-install guard" section of CLI_CONTRACT.md.
//!
//! Coverage (real binary + wiremock; the "installed" gems are laid down by
//! hand in bundler's deployment layout, so no ruby/gem/bundler is needed):
//!
//!   1. STALE materialization → loud warning in the JSON envelope naming
//!      the installed dir, cache `.gem`, and specifications entry, plus the
//!      code-tagged stderr mirror in human mode.
//!   2. ALREADY-PATCHED materialization → quiet (never false-positive).
//!   3. FRESH checkout (no materialization) → quiet.
//!   4. TWO gem homes both stale → one warning per home, each naming its
//!      own paths.
//!   5. RE-FIRE: a re-scan whose /patches/view fetch fails transiently
//!      still warns, judged from the redirect ledger's persisted record.
//!   6. Same-run `--vex`: the stale purl is excluded from the ledger-based
//!      attestation — the envelope must never attest a CVE its own warning
//!      says is live.
//!   7. Manifest-less standalone `vex` over the same committed state follows
//!      the installed tree: stale → `not_applied` (ledger kept) / nothing
//!      discoverable (ledgers deleted, lock not yet converged); after the
//!      prescribed re-install (the lock bundler then writes — separate
//!      patch-registry `GEM` section on bundler >= 2.2, the merged
//!      multi-remote section on <= 2.1) it attests from the lock + patch API
//!      with no ledger; offline → `record_unavailable`; tampered →
//!      `hash_mismatch`; reverted pair → `redirect_unwired`.

use std::path::{Path, PathBuf};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

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

/// Mount the whole patches API: batch discovery, by-package selection, the
/// granted reference (rubygems-compact-index override), and — unless
/// `view_budget` caps it — the patch view whose file map carries the REAL
/// before/after hashes of the fixture lib. With `view_budget: Some(n)` the
/// view answers 200 exactly n times and 500 afterwards (the transient-fetch
/// re-fire arm).
async fn mount_api(server: &MockServer, view_budget: Option<u64>) {
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
    let view = Mock::given(method("GET"))
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
        })));
    match view_budget {
        Some(n) => {
            view.up_to_n_times(n).mount(server).await;
            // After the budget: transient server failure — the re-fire arm.
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
                .respond_with(ResponseTemplate::new(500))
                .mount(server)
                .await;
        }
        None => view.mount(server).await,
    }
}

/// The committable pair: a plain Gemfile + a pre-CHECKSUMS Gemfile.lock (the
/// bundler 1/2 lock shape — the guard must not depend on the CHECKSUMS-era
/// grammar).
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

/// Materialize the gem in bundler's deployment layout under one ruby-version
/// home — installed dir + cached `.gem` + specifications entry, exactly what
/// a real `bundle install` leaves. Paths are built COMPONENT-WISE (the same
/// join operations the crawler uses) so their `display()` matches the
/// production warning text byte-for-byte on every platform.
/// Returns (installed gem dir, cache .gem path, specifications path).
fn materialize_installed_gem(
    proj: &Path,
    ruby_version: &str,
    lib_content: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let home = proj
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join(ruby_version);
    let gem_dir = home.join("gems").join(format!("{DEP}-{DEP_VERSION}"));
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), lib_content).unwrap();
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
    common::run_with_env(
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
        &[],
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
/// remedy. The human path mirrors the same code-tagged detail to stderr.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_redirect_over_stale_install_warns_loudly() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let (gem_dir, cache, spec) = materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);

    let (code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(
        code, 0,
        "hosted scan must succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = common::parse_json_envelope(&stdout);
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
        detail.contains("`bundle install`"),
        "detail must prescribe the re-install: {detail}"
    );
    // The empirically DISPROVEN remedies are steered away from, never
    // prescribed (they reinstall from the stale cache).
    assert!(
        detail.contains("--redownload") && detail.contains("--force"),
        "detail must steer away from --force/--redownload: {detail}"
    );

    // The installed tree was NOT touched — detection is read-only (no
    // destructive deletion by default).
    assert_eq!(
        std::fs::read_to_string(gem_dir.join("lib").join("stale_probe_gem.rb")).unwrap(),
        UPSTREAM_LIB,
        "detection must never modify the installed tree"
    );
    assert!(
        cache.is_file() && spec.is_file(),
        "detection must not delete"
    );

    // Human-mode re-scan (idempotent) re-detects and mirrors the SAME detail
    // to stderr — a re-run keeps warning until the stale install is gone.
    let (code, _stdout, stderr) = common::run_with_env(
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
        &[],
    );
    assert_eq!(code, 0, "human re-scan must succeed:\n{stderr}");
    assert!(
        stderr.contains("redirect_gem_stale_install"),
        "human mode must carry the greppable code tag on stderr:\n{stderr}"
    );
    assert!(
        stderr.contains(&gem_dir.display().to_string()),
        "human mode must name the stale gem dir on stderr:\n{stderr}"
    );
}

/// ALREADY-PATCHED materialization (every record file at afterHash): the
/// warning must NOT fire — the check may never false-positive on a patched
/// install (e.g. agent-mode apply preceded the mode switch).
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_redirect_over_patched_install_stays_quiet() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    materialize_installed_gem(&proj, "3.3.0", PATCHED_LIB);

    let (code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(
        code, 0,
        "hosted scan must succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = common::parse_json_envelope(&stdout);
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
    mount_api(&server, None).await;
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
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(env["redirect"]["redirected"], 1, "envelope: {env}");
    assert!(
        stale_warnings(&env).is_empty(),
        "a fresh checkout must not trip the stale warning: {env}"
    );
}

/// TWO gem homes (two ruby versions under vendor/bundle) both stale: one
/// warning per home, each naming its own home's paths — multiplicity is
/// per materialization, not per purl.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_redirect_warns_once_per_stale_gem_home() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let (dir_a, cache_a, _) = materialize_installed_gem(&proj, "3.2.0", UPSTREAM_LIB);
    let (dir_b, cache_b, _) = materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);

    let (code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = common::parse_json_envelope(&stdout);
    let details = stale_warnings(&env);
    assert_eq!(details.len(), 2, "one warning per stale gem home: {env}");
    let a = details
        .iter()
        .find(|d| d.contains(&dir_a.display().to_string()))
        .unwrap_or_else(|| panic!("no warning names {}: {details:?}", dir_a.display()));
    assert!(a.contains(&cache_a.display().to_string()), "{a}");
    let b = details
        .iter()
        .find(|d| d.contains(&dir_b.display().to_string()))
        .unwrap_or_else(|| panic!("no warning names {}: {details:?}", dir_b.display()));
    assert!(b.contains(&cache_b.display().to_string()), "{b}");
}

/// RE-FIRE guarantee: scan 1 warns and persists the patch record in the
/// redirect ledger; scan 2's /patches/view fetch fails transiently (500) —
/// the warning must STILL fire, judged from the ledger's persisted record,
/// alongside the record_fetch_failed warning for the fetch itself.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_stale_warning_refires_when_record_fetch_fails() {
    let server = MockServer::start().await;
    mount_api(&server, Some(1)).await; // view answers 200 exactly once
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let (gem_dir, ..) = materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);

    // Scan 1: fresh record, warning fires, ledger persists the record.
    let (code, stdout, _) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(code, 0);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(stale_warnings(&env).len(), 1, "scan 1 must warn: {env}");
    let ledger = std::fs::read_to_string(proj.join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains(UUID),
        "the ledger must persist the record scan 2 falls back to: {ledger}"
    );

    // Scan 2: view 500s → record_fetch_failed, but the stale warning
    // re-fires from the ledger record.
    let (code, stdout, _) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(code, 0);
    let env = common::parse_json_envelope(&stdout);
    let codes: Vec<&str> = env["redirect"]["warnings"]
        .as_array()
        .expect("warnings")
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"record_fetch_failed"),
        "the transient fetch failure itself is surfaced: {env}"
    );
    let details = stale_warnings(&env);
    assert_eq!(
        details.len(),
        1,
        "a flaky record fetch must not retire the stale warning: {env}"
    );
    assert!(details[0].contains(&gem_dir.display().to_string()), "{env}");
}

/// Same-run `--vex` consistency: a stale-flagged purl is EXCLUDED from the
/// ledger-based `assume_applied` attestation — the envelope must never
/// attest a CVE its own warning says is live. With the only patch stale,
/// verification finds nothing attestable, so the run fails the VEX step
/// (the embedded-VEX fail-the-command contract) and no document attests
/// the purl.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_stale_purl_is_not_vex_attested_in_the_same_run() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);

    let vex_path = proj.join("out.vex.json");
    let (code, stdout, stderr) = common::run_with_env(
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
            vex_path.to_str().unwrap(),
            "--vex-product",
            "pkg:gem/app@1.0.0",
        ],
        &[],
    );
    let env = common::parse_json_envelope(&stdout);
    // The warning fired…
    assert_eq!(
        stale_warnings(&env).len(),
        1,
        "the stale warning must be in the same envelope: {env}"
    );
    // …so the purl must NOT be attested by any written document.
    if let Ok(doc) = std::fs::read_to_string(&vex_path) {
        assert!(
            !doc.contains(PURL),
            "a stale purl must never be attested by the same run's VEX:\n{doc}"
        );
    }
    // With the only patch stale-excluded there is nothing to attest — the
    // embedded-VEX contract fails the command rather than writing an
    // evidence-free document.
    assert_ne!(
        code, 0,
        "an all-stale --vex run must fail, not attest.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(env["status"], "error", "envelope: {env}");
}

/// 7. Manifest-less VEX (no `.socket/manifest.json` — hosted never writes
/// one) over the stale-install scenario, before and after the prescribed
/// fix. The two post-install lock shapes are the ones REAL bundler writes
/// (captured in e2e_redirect_gem_build's version matrix).
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_manifest_less_vex_follows_the_installed_tree() {
    use vex_e2e_common::{
        assert_absent, assert_attested, assert_not_attested, run_vex, strip_ledgers,
        strip_manifest, Marker, VexRun,
    };
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let bin = vex_e2e_common::binary();
    let vulns: &[(&str, &[&str])] = &[(GHSA, &["CVE-2026-4444"])];
    let base = VexRun {
        api_url: Some(server.uri()),
        api_token: Some("fake".into()),
        org: Some(ORG.into()),
        // The fixture's hosted URLs are on the mock origin, not the Socket
        // patch host discovery allowlists by default.
        patch_server_url: Some(server.uri()),
        product: Some("pkg:gem/app@1.0.0".into()),
        ..VexRun::default()
    };
    let requests = || async {
        server
            .received_requests()
            .await
            .map(|r| r.len())
            .unwrap_or(0)
    };

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let pristine_gemfile = std::fs::read(proj.join("Gemfile")).unwrap();
    let pristine_lock = std::fs::read(proj.join("Gemfile.lock")).unwrap();
    let (gem_dir, _, _) = materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);
    let (code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(code, 0, "hosted scan:\n{stdout}\n{stderr}");
    assert_eq!(
        stale_warnings(&common::parse_json_envelope(&stdout)).len(),
        1
    );
    strip_manifest(&proj);
    let ledger = std::fs::read(proj.join(".socket/vendor/redirect-state.json")).unwrap();

    // Stale, ledger kept: the Gemfile block keeps the claim live, the
    // pristine installed tree decides.
    let out = run_vex(&bin, &proj, &base);
    assert_eq!(out.code, Some(1), "stale install: {out}");
    assert_not_attested(&out.envelope, PURL, "not_applied");

    // Stale, no ledgers: the lock is not converged yet (bundler < 2.6 mixed
    // pair) and the Gemfile is not a discovery input — nothing to attest.
    strip_ledgers(&proj);
    let out = run_vex(&bin, &proj, &base);
    assert_eq!(out.code, Some(2), "nothing discoverable: {out}");
    assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
    assert_absent(out.doc.as_ref(), PURL);

    // The prescribed re-install: patched tree + the lock bundler writes.
    let index_url = format!("{}/patch-registry/gem/{TOKEN}/{UUID}/", server.uri());
    let separate = format!(
        "GEM\n  remote: {index_url}\n  specs:\n    {DEP} ({DEP_VERSION})\n\n\
         GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
         PLATFORMS\n  ruby\n\nDEPENDENCIES\n  {DEP} (= {DEP_VERSION})!\n\n\
         BUNDLED WITH\n   2.6.9\n"
    );
    let merged = format!(
        "GEM\n  remote: https://rubygems.org/\n  remote: {index_url}\n  specs:\n    \
         {DEP} ({DEP_VERSION})\n\nPLATFORMS\n  ruby\n\n\
         DEPENDENCIES\n  {DEP} (= {DEP_VERSION})!\n\nBUNDLED WITH\n   1.17.3\n"
    );
    std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), PATCHED_LIB).unwrap();
    for (shape, lock) in [
        ("bundler >= 2.2", &separate),
        ("bundler <= 2.1 merged", &merged),
    ] {
        std::fs::write(proj.join("Gemfile.lock"), lock).unwrap();
        let out = run_vex(&bin, &proj, &base);
        assert_eq!(out.code, Some(0), "{shape}, ledger-less: {out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);

        let before = requests().await;
        let mut offline = base.clone();
        offline.offline = true;
        let out = run_vex(&bin, &proj, &offline);
        assert_eq!(out.code, Some(1), "{shape}, offline: {out}");
        assert_not_attested(&out.envelope, PURL, "record_unavailable");
        assert_eq!(requests().await, before, "{shape}: --offline made requests");
    }

    // Tampered installed tree: installed evidence wins over the wiring.
    std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), "tampered\n").unwrap();
    let out = run_vex(&bin, &proj, &base);
    assert_eq!(out.code, Some(1), "tampered: {out}");
    assert_not_attested(&out.envelope, PURL, "hash_mismatch");
    std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), PATCHED_LIB).unwrap();

    // Reverted pair, ledger (and the patched install) kept.
    std::fs::write(proj.join(".socket/vendor/redirect-state.json"), &ledger).unwrap();
    std::fs::write(proj.join("Gemfile"), &pristine_gemfile).unwrap();
    std::fs::write(proj.join("Gemfile.lock"), &pristine_lock).unwrap();
    for no_verify in [false, true] {
        let mut run = base.clone();
        run.no_verify = no_verify;
        let out = run_vex(&bin, &proj, &run);
        assert_eq!(out.code, Some(1), "reverted no_verify={no_verify}: {out}");
        assert_not_attested(&out.envelope, PURL, "redirect_unwired");
    }
}
