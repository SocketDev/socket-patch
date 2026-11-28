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
//!   0. REFRESH (the `refresh` tests at the end): a stale project-local
//!      install and a committed cache-dir archive are replaced with the
//!      sha256-verified patched gem, and by the upstream gem after a
//!      rollback; a shared gem home is left alone under one human warning;
//!      a dry run only says what it would do; an unverified or unreachable
//!      archive changes nothing. Arms 1-7 run where the patched archive
//!      cannot be fetched, so they pin the warning the refresh falls back
//!      to.
//!   1. STALE materialization → loud warning in the JSON envelope naming
//!      the installed dir, cache `.gem`, and specifications entry, plus the
//!      one-warning summary on stderr in human mode.
//!   2. ALREADY-PATCHED materialization → quiet (never false-positive).
//!   3. FRESH checkout (no materialization) → quiet.
//!   4. TWO gem homes both stale → one warning per home, each naming its
//!      own paths.
//!   5. RE-SCAN: a hosted scan fetches no patch record — the installed
//!      gem is judged by the archive RubyGems cached when installing it, so
//!      the warning re-fires on every re-scan while the committed wiring is
//!      left untouched.
//!   6. Same-run `--vex`: the stale purl is excluded from the attestation
//!      — the envelope must never attest a CVE its own warning says is
//!      live.
//!   7. Manifest-less standalone `vex` over the same committed state follows
//!      the installed tree: stale → nothing discoverable (no ledger, lock not
//!      yet converged); after the prescribed re-install (the lock bundler
//!      then writes — separate patch-registry `GEM` section on bundler >=
//!      2.2, the merged multi-remote section on <= 2.1) it attests from the
//!      lock + patch API; offline → `record_unavailable`; tampered →
//!      `hash_mismatch`; reverted pair → not attested (nothing wires it).

use std::path::{Path, PathBuf};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{body_string_contains, method, path, path_regex};
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
/// The `.gem` archives a real install leaves in the home's `cache/`: the
/// patched one is the artifact the grant names (its sha256 below).
const UPSTREAM_ARCHIVE: &[u8] = b"upstream-gem-archive-bytes";
const PATCHED_ARCHIVE: &[u8] = b"patched-gem-archive-bytes";

/// `path` as the CLI prints it in a suggested shell command: unquoted when
/// every character is safe, else single-quoted (mirrors `gem_refresh`'s
/// `shell_word`), so the expectations hold on Windows and in a temp dir
/// whose path has a space.
fn shell_word(path: &Path) -> String {
    let text = path.display().to_string();
    let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if !text.is_empty() && text.chars().all(safe) {
        text
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

fn patched_archive_sha256() -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(PATCHED_ARCHIVE))
}

/// Mount the whole patches API: batch discovery, by-package selection, the
/// granted reference (rubygems-compact-index override, carrying the patched
/// archive's sha256), and — unless `view_budget` caps it — the patch view
/// whose file map carries the REAL before/after hashes of the fixture lib
/// (the standalone `vex` reads it). With `view_budget: Some(n)` the
/// view answers 200 exactly n times and 500 afterwards (the transient-fetch
/// re-fire arm).
async fn mount_api(server: &MockServer, view_budget: Option<u64>) {
    mount_api_for(server, view_budget, &patched_archive_sha256()).await;
}

/// [`mount_api`] with the grant naming `patched_sha` as the patched
/// archive's sha256.
async fn mount_api_for(server: &MockServer, view_budget: Option<u64>, patched_sha: &str) {
    mount_api_with(server, view_budget, patched_sha, &[]).await;
}

/// One platform gem of the fixture gem's version as the grant lists it
/// (`gemBuilds`): its platform, the sha256 the patch registry serves for
/// it, and the patch of its patched build (`None`: the registry serves
/// upstream's own gem for that platform).
type ListedBuild<'a> = (&'a str, String, Option<&'a str>);

/// The snapshot the registry URL of a grant that lists platform gems names.
const SNAPSHOT: u32 = 4;

/// The patches of the fixture gem's patched platform builds.
const ARM_UUID: &str = "a1b2c3d4-0000-4000-8000-00000000000a";
const LINUX_UUID: &str = "a1b2c3d4-0000-4000-8000-00000000000b";

/// [`mount_api_for`] with the grant also listing `builds`, every platform
/// gem of the version (`gemBuilds`; absent from a grant with none, as the
/// service sends a patch of the ruby gem alone), under a registry URL that
/// names [`SNAPSHOT`].
async fn mount_api_with(
    server: &MockServer,
    view_budget: Option<u64>,
    patched_sha: &str,
    builds: &[ListedBuild<'_>],
) {
    mount_patch_api_with(
        server,
        UUID,
        PATCHED_LIB,
        view_budget,
        patched_sha,
        builds,
        SNAPSHOT,
    )
    .await;
}

/// The path of the patch registry of the fixture gem's patch as a grant
/// that lists platform gems names it (no trailing slash).
fn snapshot_registry_path() -> String {
    format!("/patch-registry/gem/{TOKEN}/{UUID}/s/{SNAPSHOT}")
}

/// [`mount_api_for`] for the patch `uuid`, whose patched lib is
/// `patched_lib`.
async fn mount_patch_api(
    server: &MockServer,
    uuid: &str,
    patched_lib: &str,
    view_budget: Option<u64>,
    patched_sha: &str,
) {
    mount_patch_api_with(server, uuid, patched_lib, view_budget, patched_sha, &[], 0).await;
}

/// The grant of the patch `uuid` on `api`, whose patched ruby gem has the
/// sha256 `patched_sha` and which lists `builds` under the registry
/// snapshot `snapshot` (a grant with no list names the registry without
/// one).
fn granted_reference(
    api: &str,
    uuid: &str,
    patched_sha: &str,
    builds: &[ListedBuild<'_>],
    snapshot: u32,
) -> serde_json::Value {
    let mut identifiers = serde_json::json!({
        "name": DEP,
        "version": DEP_VERSION,
        "gemChecksumSha256": patched_sha,
    });
    let hosted_url =
        format!("{api}/patch/gem/{DEP}/{DEP_VERSION}/{TOKEN}/{uuid}/{DEP}-{DEP_VERSION}.gem");
    let mut index_url = format!("{api}/patch-registry/gem/{TOKEN}/{uuid}/");
    if !builds.is_empty() {
        identifiers["gemBuilds"] = builds
            .iter()
            .map(|(platform, sha, patch)| {
                serde_json::json!({
                    "platform": platform, "gemChecksumSha256": sha, "patchUuid": patch,
                })
            })
            .collect();
        index_url = format!("{index_url}s/{snapshot}");
    }
    serde_json::json!({
        "status": "granted",
        "url": hosted_url,
        "purl": PURL,
        "artifacts": [{
            "kind": "tarball",
            "url": hosted_url,
            "integrity": { "sha256": patched_sha }
        }],
        "registryOverride": {
            "kind": "rubygems-compact-index",
            "indexUrl": index_url,
            "identifiers": identifiers,
        }
    })
}

/// The API of the patch `uuid`, whose patched lib is `patched_lib` and
/// whose grant lists `builds` under the registry snapshot `snapshot`
/// ([`granted_reference`]).
async fn mount_patch_api_with(
    server: &MockServer,
    uuid: &str,
    patched_lib: &str,
    view_budget: Option<u64>,
    patched_sha: &str,
    builds: &[ListedBuild<'_>],
    snapshot: u32,
) {
    let reference = granted_reference(&server.uri(), uuid, patched_sha, builds, snapshot);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": uuid, "purl": PURL, "tier": "free",
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
                "uuid": uuid, "purl": PURL,
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
            "results": { uuid: reference }
        })))
        .mount(server)
        .await;
    let view = Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "lib/stale_probe_gem.rb": {
                    "beforeHash": compute_git_sha256_from_bytes(UPSTREAM_LIB.as_bytes()),
                    "afterHash": compute_git_sha256_from_bytes(patched_lib.as_bytes()),
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
            if n > 0 {
                view.up_to_n_times(n).mount(server).await;
            }
            // After the budget: transient server failure — the re-fire arm.
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
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
/// a real `bundle install` leaves (the cached archive is the patched one
/// exactly when the lib is). Paths are built COMPONENT-WISE (the same
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
    let archive = if lib_content == PATCHED_LIB {
        PATCHED_ARCHIVE
    } else {
        UPSTREAM_ARCHIVE
    };
    std::fs::write(&cache, archive).unwrap();
    let spec = home
        .join("specifications")
        .join(format!("{DEP}-{DEP_VERSION}.gemspec"));
    std::fs::create_dir_all(spec.parent().unwrap()).unwrap();
    std::fs::write(&spec, "# stub gemspec\n").unwrap();
    (gem_dir, cache, spec)
}

/// The archive RubyGems leaves in `home/cache/` for the gem it installed.
fn cache_archive(home: &Path, archive: &[u8]) {
    let cache = home.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join(format!("{DEP}-{DEP_VERSION}.gem")), archive).unwrap();
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

/// How many hosted pins the run wrote (v5.0: the `applied` / `verified`
/// events with `details.mode: "hosted"`, formerly `redirect.redirected`).
fn hosted_pinned(env: &serde_json::Value) -> u64 {
    env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| {
            e["details"]["mode"] == "hosted"
                && (e["action"] == "applied" || e["action"] == "verified")
        })
        .count() as u64
}

/// `(purl, uuid)` of each hosted pin the run reports, in event order.
fn hosted_pins(env: &serde_json::Value) -> Vec<(String, String)> {
    env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| {
            e["details"]["mode"] == "hosted"
                && (e["action"] == "applied" || e["action"] == "verified")
        })
        .map(|e| {
            let text = |key: &str| e[key].as_str().unwrap_or_default().to_string();
            (text("purl"), text("uuid"))
        })
        .collect()
}

fn stale_warnings(env: &serde_json::Value) -> Vec<String> {
    env["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|w| w["code"] == "redirect_gem_stale_install")
        .map(|w| w["detail"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// STALE materialization the refresh cannot fix (the patch registry does
/// not serve the archive): the redirect succeeds, nothing of the install is
/// changed, AND the envelope carries the machine-readable warning naming
/// the stale install, why it was not refreshed, and the verified remedy.
/// The human path prints one summary warning with the same facts.
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
    assert_eq!(hosted_pinned(&env), 1, "envelope: {env}");
    let gemfile = std::fs::read_to_string(proj.join("Gemfile")).unwrap();
    assert!(
        gemfile.contains("/patch-registry/gem/"),
        "Gemfile must gain the patch-registry source:\n{gemfile}"
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
    assert!(
        detail.contains("was not refreshed (the patched gem could not be downloaded"),
        "detail must say why the refresh did not happen: {detail}"
    );

    // The installed tree was NOT touched: without the verified patched
    // archive in hand nothing is changed, and nothing is ever deleted.
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
        stderr.contains(
            "Warning: 1 gem is still unpatched on disk after the switch to hosted patches."
        ),
        "human mode must print the stale-install summary on stderr:\n{stderr}"
    );
    assert_eq!(
        stderr.matches("still unpatched on disk").count(),
        1,
        "one stale-install warning for the run:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("stale-probe-gem {DEP_VERSION}"))
            && stderr.contains(&spec.display().to_string())
            && stderr.contains(&cache.display().to_string()),
        "human mode must name the gem and the files to remove:\n{stderr}"
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
    assert_eq!(hosted_pinned(&env), 1, "envelope: {env}");
    assert!(
        stale_warnings(&env).is_empty(),
        "an already-patched materialization must never trip the stale warning: {env}"
    );
    assert_eq!(
        view_requests(&server).await,
        0,
        "the cached archive judges the install: no patch view is fetched"
    );
}

async fn view_requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().contains("/patches/view/"))
        .count()
}

/// A gem home whose `cache/` was pruned after install (`rm -rf
/// $BUNDLE_PATH/cache` in an image, `gem cleanup`) has no archive to judge
/// the installed copy by: the scan fetches that patch's view record and
/// judges the copy from it.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_pruned_cache_is_judged_by_the_patch_view() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let (_, cache, _) = materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);
    std::fs::remove_file(&cache).unwrap();

    let (code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(hosted_pinned(&env), 1, "envelope: {env}");
    assert_eq!(
        stale_warnings(&env).len(),
        1,
        "judged stale by the view: {env}"
    );
    assert_eq!(view_requests(&server).await, 1, "one view, for that purl");
}

/// Pruned cache and a failing view fetch: nothing can judge the installed
/// copy, so the same run's `--vex` withholds the purl instead of assuming
/// it patched.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_unjudgeable_install_is_not_vex_attested() {
    let server = MockServer::start().await;
    mount_api(&server, Some(0)).await; // every view fetch fails
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let (_, cache, _) = materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);
    std::fs::remove_file(&cache).unwrap();

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
    assert_eq!(hosted_pinned(&env), 1, "envelope: {env}");
    assert!(
        stale_warnings(&env).is_empty(),
        "no evidence, no warning: {env}"
    );
    if let Ok(doc) = std::fs::read_to_string(&vex_path) {
        assert!(
            !doc.contains(PURL),
            "an unjudged purl is never attested:\n{doc}"
        );
    }
    assert_ne!(
        code, 0,
        "nothing attestable fails the --vex run.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        view_requests(&server).await >= 1,
        "the probe asked for the view"
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
    assert_eq!(hosted_pinned(&env), 1, "envelope: {env}");
    assert!(
        stale_warnings(&env).is_empty(),
        "a fresh checkout must not trip the stale warning: {env}"
    );
}

/// #1055: the installed copy is a version the project's lock doesn't
/// resolve (another project put it in the gem home; here the lock resolves
/// 2.0.0 under `~> 2.0` while only 1.0.0 is installed). Hosted mode must
/// skip it with `redirect_gem_version_not_locked` and leave the Gemfile and
/// lock byte-identical, never rewrite the declaration to the older version.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_scan_never_pins_a_version_the_lock_does_not_resolve() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let gemfile = format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"~> 2.0\"\n");
    let lock = format!(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    {DEP} (2.0.0)\n\n\
         PLATFORMS\n  ruby\n\nDEPENDENCIES\n  {DEP} (~> 2.0)\n\n\
         BUNDLED WITH\n   2.6.9\n"
    );
    std::fs::write(proj.join("Gemfile"), &gemfile).unwrap();
    std::fs::write(proj.join("Gemfile.lock"), &lock).unwrap();
    materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);

    let (_code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(
        hosted_pinned(&env),
        0,
        "nothing may be redirected: {env}\nstderr:\n{stderr}"
    );
    let codes: Vec<&str> = env["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"redirect_gem_version_not_locked"),
        "the unlocked version must be reported: {env}"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
        gemfile,
        "the user's `~> 2.0` constraint must survive"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
        lock,
        "the lock must stay byte-identical"
    );
}

/// #1125: the same shared-home copy, but the project has no lock at all
/// (a fresh library clone before `bundle install`). Nothing says which
/// version the project resolves, so hosted mode must neither rewrite the
/// user's `~> 2.0` down to the installed 1.0.0 nor append the gem to a
/// Gemfile that never declared it: it skips with `redirect_gem_no_lockfile`
/// (whose detail names `bundle lock`) and writes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_scan_without_a_lock_pins_nothing() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    for gemfile in [
        format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"~> 2.0\"\n"),
        "source \"https://rubygems.org\"\ngem \"tiny-dep\"\n".to_string(),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("Gemfile"), &gemfile).unwrap();
        materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);

        let (code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
        assert!(
            common::envelope::hosted_pins(&env).is_empty(),
            "nothing may be redirected: {env}\nstderr:\n{stderr}"
        );
        let hit: Vec<&serde_json::Value> = env["warnings"]
            .as_array()
            .expect("warnings")
            .iter()
            .filter(|w| w["code"] == "redirect_gem_no_lockfile")
            .collect();
        assert_eq!(hit.len(), 1, "the missing lock must be reported: {env}");
        assert!(
            hit[0]["detail"].as_str().unwrap().contains("bundle lock"),
            "the remedy names `bundle lock`: {env}"
        );
        assert_eq!(
            std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
            gemfile,
            "the Gemfile must stay byte-identical"
        );
        assert!(!proj.join("Gemfile.lock").exists());
    }
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

/// v5 hosted mode keeps no ledger and fetches no record: scan 1 warns
/// (from the installed gem's cached archive) and persists nothing but the
/// Gemfile/lock edits; scan 2 asks for no patch view either, warns again,
/// exits 0, and leaves the committed wiring byte-identical (the re-run is
/// idempotent) — still with no ledger.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_rescan_rewarns_without_fetching_records_and_keeps_the_wiring() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let (gem_dir, ..) = materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);

    let (code, stdout, _) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(code, 0);
    let env = common::parse_json_envelope(&stdout);
    let details = stale_warnings(&env);
    assert_eq!(details.len(), 1, "scan 1 must warn: {env}");
    assert!(details[0].contains(&gem_dir.display().to_string()), "{env}");
    let ledger = proj.join(".socket/vendor/redirect-state.json");
    assert!(!ledger.exists(), "hosted mode writes no redirect ledger");
    let gemfile = std::fs::read(proj.join("Gemfile")).unwrap();
    let lock = std::fs::read(proj.join("Gemfile.lock")).unwrap();

    let (code, stdout, _) = hosted_scan_json(&proj, &server.uri());
    assert_eq!(code, 0, "{stdout}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(stale_warnings(&env).len(), 1, "scan 2 warns again: {env}");
    assert!(!stdout.contains("record_fetch_failed"), "{env}");
    let views = server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.url.path().contains("/patches/view/"))
        .count();
    assert_eq!(views, 0, "a hosted scan never fetches a patch view");
    assert_eq!(
        std::fs::read(proj.join("Gemfile")).unwrap(),
        gemfile,
        "the re-run leaves the Gemfile as the first run wrote it"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile.lock")).unwrap(),
        lock,
        "the re-run leaves the lock as the first run wrote it"
    );
    assert!(!ledger.exists(), "still no ledger");
}

/// Same-run `--vex` consistency: a stale-flagged purl is EXCLUDED from the
/// run's `assume_applied` attestation — the envelope must never
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

/// #796: Bundler 4's `bundle install --standalone` installs into
/// `<proj>/bundle/ruby/<abi>/` and writes `bundle/bundler/setup.rb`, but no
/// `.bundle/config` (bundler 4 no longer remembers CLI flags). That tree is
/// what the app loads, so a stale UNPATCHED copy there must trip the guard
/// with the project-local remedy, and the same run's `--vex` must not
/// attest the purl.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_stale_bundler4_standalone_install_warns_and_is_not_attested() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = proj.join("bundle").join("ruby").join("3.3.0");
    let gem_dir = home.join("gems").join(format!("{DEP}-{DEP_VERSION}"));
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), UPSTREAM_LIB).unwrap();
    cache_archive(&home, UPSTREAM_ARCHIVE);
    std::fs::create_dir_all(proj.join("bundle").join("bundler")).unwrap();
    std::fs::write(
        proj.join("bundle").join("bundler").join("setup.rb"),
        "require 'rbconfig'\n",
    )
    .unwrap();
    assert!(!proj.join(".bundle").exists(), "bundler 4 writes no config");

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
    assert_eq!(hosted_pinned(&env), 1, "envelope: {env}");
    let details = stale_warnings(&env);
    assert_eq!(
        details.len(),
        1,
        "the stale standalone copy must trip the guard: {env}\nstderr:\n{stderr}"
    );
    assert!(
        details[0].contains(&gem_dir.display().to_string())
            && !details[0].contains("shared gem home"),
        "the warning must name the standalone copy as project-local: {}",
        details[0]
    );
    if let Ok(doc) = std::fs::read_to_string(&vex_path) {
        assert!(
            !doc.contains(PURL),
            "a stale standalone copy must never be attested:\n{doc}"
        );
    }
    assert_ne!(
        code, 0,
        "an all-stale --vex run must fail, not attest.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// #967: with `simulate_version 5` (Bundler 4.x) or
/// `default_install_uses_path` (2.x) and no path in any tier, Bundler
/// installs into `<root>/.bundle/<engine>/<abi>/gems`. A stale copy there is
/// what `bundle exec` loads, so the guard must name it and the same run's
/// `--vex` must not attest the purl.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_stale_dot_bundle_install_warns_and_is_not_attested() {
    for config in [
        "---\nBUNDLE_SIMULATE_VERSION: \"5\"\n",
        "---\nBUNDLE_DEFAULT_INSTALL_USES_PATH: \"true\"\n",
    ] {
        let server = MockServer::start().await;
        mount_api(&server, None).await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        let home = proj.join(".bundle").join("ruby").join("3.3.0");
        let gem_dir = home.join("gems").join(format!("{DEP}-{DEP_VERSION}"));
        std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
        std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), UPSTREAM_LIB).unwrap();
        cache_archive(&home, UPSTREAM_ARCHIVE);
        std::fs::write(proj.join(".bundle").join("config"), config).unwrap();

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
        assert_eq!(hosted_pinned(&env), 1, "{config}: envelope: {env}");
        let details = stale_warnings(&env);
        assert_eq!(
            details.len(),
            1,
            "{config}: the stale .bundle copy must trip the guard: {env}\nstderr:\n{stderr}"
        );
        assert!(
            details[0].contains(&gem_dir.display().to_string())
                && !details[0].contains("shared gem home"),
            "{config}: the warning must name the .bundle copy as project-local: {}",
            details[0]
        );
        if let Ok(doc) = std::fs::read_to_string(&vex_path) {
            assert!(
                !doc.contains(PURL),
                "{config}: a stale .bundle copy must never be attested:\n{doc}"
            );
        }
        assert_ne!(
            code, 0,
            "{config}: an all-stale --vex run must fail, not attest.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}

/// #483: bundler's cache dir is the `cache_path` setting — `bundle config
/// set --local cache_path vendor/gems` (a committed `.bundle/config`) or a
/// `BUNDLE_CACHE_PATH` export. A fresh checkout whose committed archive at
/// that path is the UNPATCHED upstream `.gem` installs those bytes, so the
/// standalone cache warning must name it and the same run's `--vex` must
/// not attest the purl — exactly as for the default `vendor/cache`. Under
/// `BUNDLE_IGNORE_CONFIG` the committed setting is ignored, by bundler and
/// by the guard alike, so the default `vendor/cache` archive still counts.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_stale_archive_at_configured_cache_path_warns_and_is_not_attested() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let moved = "---\nBUNDLE_CACHE_PATH: \"vendor/gems\"\n";
    // #951: Bundler drops a trailing `# comment` from the value.
    let commented = "---\nBUNDLE_CACHE_PATH: vendor/gems # committed gem cache\n";
    for (label, config, env, cache_dir) in [
        ("app-config", Some(moved), &[][..], "gems"),
        ("app-config-commented", Some(commented), &[][..], "gems"),
        (
            "env",
            None,
            &[("BUNDLE_CACHE_PATH", "vendor/gems")][..],
            "gems",
        ),
        // BUNDLE_IGNORE_CONFIG: bundler skips the file, so the ignored
        // `cache_path` moves nothing and `vendor/cache` is still installed.
        (
            "ignore-config",
            Some(moved),
            &[("BUNDLE_IGNORE_CONFIG", "1")][..],
            "cache",
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        if let Some(config) = config {
            std::fs::create_dir_all(proj.join(".bundle")).unwrap();
            std::fs::write(proj.join(".bundle").join("config"), config).unwrap();
        }
        let archive = proj
            .join("vendor")
            .join(cache_dir)
            .join(format!("{DEP}-{DEP_VERSION}.gem"));
        std::fs::create_dir_all(archive.parent().unwrap()).unwrap();
        std::fs::write(&archive, UPSTREAM_ARCHIVE).unwrap();

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
            env,
        );
        let env = common::parse_json_envelope(&stdout);
        let warnings = stale_warnings(&env);
        assert_eq!(
            warnings.len(),
            1,
            "{label}: the configured cache archive must warn: {env}\nstderr:\n{stderr}"
        );
        assert!(
            warnings[0].contains(&archive.display().to_string()),
            "{label}: the warning must name the configured archive: {}",
            warnings[0]
        );
        if let Ok(doc) = std::fs::read_to_string(&vex_path) {
            assert!(
                !doc.contains(PURL),
                "{label}: a stale purl must never be attested by the same run's VEX:\n{doc}"
            );
        }
        assert_ne!(
            code, 0,
            "{label}: an all-stale --vex run must fail, not attest.\nstdout:\n{stdout}"
        );
    }
}

/// #577: Bundler reads settings local → env → GLOBAL → default, and the
/// global tier is the file `bundle config set --global …` writes:
/// `$BUNDLE_CONFIG`, else `$BUNDLE_USER_CONFIG`, else
/// `$BUNDLE_USER_HOME/config`, else `~/.bundle/config`. A global
/// `cache_path` moves bundler's install-from cache exactly like a local
/// one, so the stale archive there must warn and must not be attested.
/// A local `cache_path` still beats the global one, and under
/// `BUNDLE_IGNORE_CONFIG` neither file counts.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_stale_archive_at_global_cache_path_warns_and_is_not_attested() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let moved = "---\nBUNDLE_CACHE_PATH: \"vendor/gems\"\n";
    // (label, env var naming the global file or its dir, local config,
    // extra env, cache dir the archive sits in)
    for (label, global_var, local, extra, cache_dir) in [
        ("home", "HOME", None, None, "gems"),
        ("user-config", "BUNDLE_USER_CONFIG", None, None, "gems"),
        ("user-home", "BUNDLE_USER_HOME", None, None, "gems"),
        ("bundle-config", "BUNDLE_CONFIG", None, None, "gems"),
        // The local tier beats the global one: the global `vendor/gems`
        // is shadowed by the local `vendor/other`.
        (
            "local-wins",
            "HOME",
            Some("---\nBUNDLE_CACHE_PATH: \"vendor/other\"\n"),
            None,
            "other",
        ),
        // Bundler skips every config file: `vendor/cache` stays in force.
        (
            "ignore-config",
            "HOME",
            None,
            Some(("BUNDLE_IGNORE_CONFIG", "1")),
            "cache",
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        if let Some(local) = local {
            std::fs::create_dir_all(proj.join(".bundle")).unwrap();
            std::fs::write(proj.join(".bundle").join("config"), local).unwrap();
        }
        // Lay the global config down where `global_var` points bundler.
        let user = tmp.path().join("user");
        let (global_value, global_file) = match global_var {
            "HOME" => (user.clone(), user.join(".bundle").join("config")),
            "BUNDLE_USER_HOME" => (user.clone(), user.join("config")),
            _ => (user.join("bundle-config"), user.join("bundle-config")),
        };
        std::fs::create_dir_all(global_file.parent().unwrap()).unwrap();
        std::fs::write(&global_file, moved).unwrap();
        let archive = proj
            .join("vendor")
            .join(cache_dir)
            .join(format!("{DEP}-{DEP_VERSION}.gem"));
        std::fs::create_dir_all(archive.parent().unwrap()).unwrap();
        std::fs::write(&archive, UPSTREAM_ARCHIVE).unwrap();

        let global_value = global_value.to_str().unwrap().to_string();
        let mut env: Vec<(&str, &str)> = vec![(global_var, &global_value)];
        // HOME keeps pointing somewhere empty for the non-HOME rows, so an
        // ambient ~/.bundle/config cannot leak in.
        let empty_home = tmp.path().join("empty-home");
        let empty_home = empty_home.to_str().unwrap().to_string();
        if global_var != "HOME" {
            env.push(("HOME", &empty_home));
        }
        env.extend(extra);

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
            &env,
        );
        let envelope = common::parse_json_envelope(&stdout);
        let warnings = stale_warnings(&envelope);
        assert_eq!(
            warnings.len(),
            1,
            "{label}: the globally configured cache archive must warn: {envelope}\nstderr:\n{stderr}"
        );
        assert!(
            warnings[0].contains(&archive.display().to_string()),
            "{label}: the warning must name the archive bundler installs from: {}",
            warnings[0]
        );
        if let Ok(doc) = std::fs::read_to_string(&vex_path) {
            assert!(
                !doc.contains(PURL),
                "{label}: a stale purl must never be attested by the same run's VEX:\n{doc}"
            );
        }
        assert_ne!(
            code, 0,
            "{label}: an all-stale --vex run must fail, not attest.\nstdout:\n{stdout}"
        );
    }
}

/// #577: a global `gemfile` setting (`bundle config set --global gemfile
/// Gemfile.next`) makes bundler load `Gemfile.next`, exactly like the local
/// one #507 covers. The hosted scan must refuse with
/// `redirect_gem_bundle_gemfile_unsupported`, leave the `Gemfile` pair
/// untouched, and attest nothing.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_global_gemfile_setting_is_refused() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    // The refused lock contributes no packages, so the scan only reaches
    // the redirect (and its refusal) through an installed copy of the gem.
    // Lay one down in the project rather than leaning on whatever `gem env`
    // reports for the host: on Windows that probe can outlive its 10s
    // budget, the scan then finds nothing, and the refusal never runs.
    materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);
    std::fs::write(
        proj.join("Gemfile.next"),
        format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n"),
    )
    .unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(home.join(".bundle")).unwrap();
    std::fs::write(
        home.join(".bundle").join("config"),
        "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n",
    )
    .unwrap();
    let pristine_gemfile = std::fs::read(proj.join("Gemfile")).unwrap();
    let pristine_lock = std::fs::read(proj.join("Gemfile.lock")).unwrap();

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
        &[("HOME", home.to_str().unwrap())],
    );
    let envelope = common::parse_json_envelope(&stdout);
    let warnings: Vec<&serde_json::Value> = envelope["warnings"]
        .as_array()
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let refusal = warnings
        .iter()
        .find(|w| w["code"] == "redirect_gem_bundle_gemfile_unsupported")
        .unwrap_or_else(|| {
            panic!("the global gemfile setting must be refused: {envelope}\nstderr:\n{stderr}")
        });
    let detail = refusal["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("global bundler config") && detail.contains("--global"),
        "the refusal must name the global setting and its remedy: {detail}"
    );
    assert_eq!(
        hosted_pinned(&envelope),
        0,
        "nothing redirected: {envelope}"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile")).unwrap(),
        pristine_gemfile,
        "the Gemfile bundler ignores must be byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("Gemfile.lock")).unwrap(),
        pristine_lock,
        "the lock must be byte-identical"
    );
    if let Ok(doc) = std::fs::read_to_string(&vex_path) {
        assert!(
            !doc.contains(PURL),
            "nothing may be attested for a gem bundler installs unpatched:\n{doc}"
        );
    }
    assert_ne!(code, 0, "nothing was patched or attested: {envelope}");
}

/// Empty higher-tier gemfile settings shadow the global alternative but
/// leave Bundler's default manifest (or an existing nonempty env value)
/// active. A valid project must not be refused because of that unused file.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_empty_gemfile_setting_shadows_global_alternative() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    for (label, local, env_gemfile) in [
        ("empty-env", false, Some("")),
        ("empty-local", true, None),
        ("empty-local-with-env", true, Some("Gemfile")),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        let alternate = proj.join("Gemfile.next");
        std::fs::write(&alternate, "source 'https://rubygems.org'\n").unwrap();
        let original_alternate = std::fs::read(&alternate).unwrap();
        if local {
            std::fs::create_dir(proj.join(".bundle")).unwrap();
            std::fs::write(proj.join(".bundle/config"), "---\nBUNDLE_GEMFILE: \"\"\n").unwrap();
        }
        let global = tmp.path().join("global-config");
        std::fs::write(&global, "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n").unwrap();
        let mut env = vec![("BUNDLE_USER_CONFIG", global.to_str().unwrap())];
        if let Some(value) = env_gemfile {
            env.push(("BUNDLE_GEMFILE", value));
        }
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
            ],
            &env,
        );
        assert_eq!(code, 0, "{label}: stdout:\n{stdout}\nstderr:\n{stderr}");
        let envelope = common::parse_json_envelope(&stdout);
        assert_eq!(hosted_pinned(&envelope), 1, "{label}: {envelope}");
        assert!(
            std::fs::read_to_string(proj.join("Gemfile"))
                .unwrap()
                .contains("/patch-registry/gem/"),
            "{label}: the active Gemfile must receive the patch source"
        );
        assert_eq!(std::fs::read(&alternate).unwrap(), original_alternate);
    }
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
    assert!(
        !proj.join(".socket/vendor/redirect-state.json").exists(),
        "hosted mode writes no redirect ledger"
    );

    // Stale: the scan converged the lock with the Gemfile, so the pin is
    // discovered from the lock — and judged against the installed tree,
    // which still holds the upstream copy. Nothing is attested, and the
    // run says why.
    strip_ledgers(&proj);
    let out = run_vex(&bin, &proj, &base);
    assert_eq!(out.code, Some(1), "stale install: {out}");
    assert_not_attested(&out.envelope, PURL, "not_applied");
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

    // Reverted pair (the patched install kept): nothing wires the patch any
    // more, so nothing attests it — verified or not.
    std::fs::write(proj.join("Gemfile"), &pristine_gemfile).unwrap();
    std::fs::write(proj.join("Gemfile.lock"), &pristine_lock).unwrap();
    for no_verify in [false, true] {
        let mut run = base.clone();
        run.no_verify = no_verify;
        let out = run_vex(&bin, &proj, &run);
        assert_ne!(out.code, Some(0), "reverted no_verify={no_verify}: {out}");
        assert_absent(out.doc.as_ref(), PURL);
    }
}

/// #709: `bundle config set --local path <dir>` with `<dir>` OUTSIDE the
/// project. The crawler refuses that root as an apply write target (a
/// committed `.bundle/config` is untrusted), but bundler installs into and
/// loads from it, so the read-only guard must still look there: the stale
/// copy warns with the project-local remedy, and the same run's `--vex`
/// does not attest the purl.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_stale_install_under_out_of_tree_config_path_is_not_attested() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    let bundle = tmp.path().join("outside bundle");
    std::fs::create_dir_all(proj.join(".bundle")).unwrap();
    write_manifest_pair(&proj);
    std::fs::write(
        proj.join(".bundle").join("config"),
        format!("---\nBUNDLE_PATH: \"{}\"\n", bundle.display()),
    )
    .unwrap();
    let gem_dir = bundle
        .join("ruby")
        .join("3.3.0")
        .join("gems")
        .join(format!("{DEP}-{DEP_VERSION}"));
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), UPSTREAM_LIB).unwrap();
    cache_archive(&bundle.join("ruby").join("3.3.0"), UPSTREAM_ARCHIVE);

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
    let warnings = stale_warnings(&env);
    assert_eq!(warnings.len(), 1, "{env}");
    assert!(
        warnings[0].contains(&gem_dir.display().to_string()),
        "the warning must name the configured install: {}",
        warnings[0]
    );
    assert!(
        warnings[0].contains("or remove ") && !warnings[0].contains("shared gem home"),
        "the project's own bundle path takes the project-local remedy: {}",
        warnings[0]
    );
    if let Ok(doc) = std::fs::read_to_string(&vex_path) {
        assert!(!doc.contains(PURL), "stale purl attested:\n{doc}");
    }
    assert_ne!(
        code, 0,
        "an all-stale --vex run must fail, not attest.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Read-only: the refused root is never written.
    assert_eq!(
        std::fs::read_to_string(gem_dir.join("lib").join("stale_probe_gem.rb")).unwrap(),
        UPSTREAM_LIB
    );
}

/// Lay down a stale UNPATCHED copy in a machine gem home (`<home>/gems/…`,
/// plus its cache `.gem` and specifications entry) and a fake `gem` on
/// `<bin_dir>` whose `gem env gemdir` answers that home (and whose
/// `gempath` fails), so the crawler's `gem env` fallback resolves to
/// exactly this one home. Returns the installed gem dir.
#[cfg(unix)]
fn stage_system_home_copy(home: &Path, bin_dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let gem_dir = home.join("gems").join(format!("{DEP}-{DEP_VERSION}"));
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), UPSTREAM_LIB).unwrap();
    std::fs::create_dir_all(home.join("cache")).unwrap();
    std::fs::write(
        home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem")),
        UPSTREAM_ARCHIVE,
    )
    .unwrap();
    std::fs::create_dir_all(home.join("specifications")).unwrap();
    std::fs::write(
        home.join("specifications")
            .join(format!("{DEP}-{DEP_VERSION}.gemspec")),
        "# stub gemspec\n",
    )
    .unwrap();
    std::fs::create_dir_all(bin_dir).unwrap();
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = env ] && [ \"$2\" = gemdir ]; then\n  printf '%s\\n' \"{}\"\n  exit 0\nfi\nexit 1\n",
        home.display()
    );
    let bin = bin_dir.join("gem");
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    gem_dir
}

/// One `scan --mode hosted --json --vex` run over `proj` with `PATH`
/// narrowed to `bin_dir` (the fake `gem`) plus `extra_env`.
#[cfg(unix)]
fn hosted_vex_scan_with_gem_on_path(
    proj: &Path,
    api: &str,
    bin_dir: &Path,
    extra_env: &[(&str, &str)],
) -> (i32, serde_json::Value, String, PathBuf) {
    let vex_path = proj.join("out.vex.json");
    let path_env = bin_dir.to_str().unwrap().to_string();
    let mut env: Vec<(&str, &str)> = vec![("PATH", path_env.as_str())];
    env.extend_from_slice(extra_env);
    let (code, stdout, stderr) = common::run_with_env(
        proj,
        &[
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            api,
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-product",
            "pkg:gem/app@1.0.0",
        ],
        &env,
    );
    let env = common::parse_json_envelope(&stdout);
    (code, env, stderr, vex_path)
}

/// #1001: the project sets an explicit Bundler install `path` (local config
/// or env `BUNDLE_PATH`) that isn't installed yet, as on every fresh clone
/// or cold CI cache. Bundler then fetches non-default gems into that path
/// and never reuses a copy in the machine's `gem env` home, so an unpatched
/// copy there is not stale for this project: no warning, and the same
/// run's `--vex` attests the purl (exit 0).
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_explicit_bundle_path_ignores_system_home_copy() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    for via_env in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        let extra: &[(&str, &str)] = if via_env {
            &[("BUNDLE_PATH", "vendor/bundle")]
        } else {
            std::fs::create_dir_all(proj.join(".bundle")).unwrap();
            std::fs::write(
                proj.join(".bundle").join("config"),
                "---\nBUNDLE_PATH: \"vendor/bundle\"\n",
            )
            .unwrap();
            &[]
        };
        let bin_dir = tmp.path().join("fake-bin");
        let system_copy = stage_system_home_copy(&tmp.path().join("system-home"), &bin_dir);

        let (code, env, stderr, vex_path) =
            hosted_vex_scan_with_gem_on_path(&proj, &server.uri(), &bin_dir, extra);
        assert!(
            stale_warnings(&env).is_empty(),
            "via_env={via_env}: bundler never reuses {} under an explicit path: {env}",
            system_copy.display()
        );
        assert_eq!(
            code, 0,
            "via_env={via_env}: the run must attest, not fail.\nenvelope: {env}\nstderr:\n{stderr}"
        );
        let doc = std::fs::read_to_string(&vex_path).expect("VEX written");
        assert!(
            doc.contains(PURL),
            "via_env={via_env}: purl not attested:\n{doc}"
        );
    }
}

/// #1001 control: with no Bundler `path` setting, `bundle install` installs
/// into and reuses the `gem env` home, so a stale copy there still warns
/// (shared-home flavor) and stays out of the same run's VEX. The same holds
/// when a local `path.system: true` outranks an env `BUNDLE_PATH`: Bundler's
/// first deciding tier turns system gems back on.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_system_install_still_flags_system_home_copy() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    for local_system_over_env_path in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        let extra: &[(&str, &str)] = if local_system_over_env_path {
            std::fs::create_dir_all(proj.join(".bundle")).unwrap();
            std::fs::write(
                proj.join(".bundle").join("config"),
                "---\nBUNDLE_PATH__SYSTEM: \"true\"\n",
            )
            .unwrap();
            &[("BUNDLE_PATH", "vendor/bundle")]
        } else {
            &[]
        };
        let bin_dir = tmp.path().join("fake-bin");
        let system_copy = stage_system_home_copy(&tmp.path().join("system-home"), &bin_dir);

        let (code, env, stderr, vex_path) =
            hosted_vex_scan_with_gem_on_path(&proj, &server.uri(), &bin_dir, extra);
        let case = format!("local_system_over_env_path={local_system_over_env_path}");
        let warnings = stale_warnings(&env);
        assert_eq!(warnings.len(), 1, "{case}: {env}");
        assert!(
            warnings[0].contains(&system_copy.display().to_string())
                && warnings[0].contains("shared gem home"),
            "{case}: {}",
            warnings[0]
        );
        if let Ok(doc) = std::fs::read_to_string(&vex_path) {
            assert!(!doc.contains(PURL), "{case}: stale purl attested:\n{doc}");
        }
        assert_ne!(
            code, 0,
            "{case}: an all-stale --vex run must fail.\nstderr:\n{stderr}"
        );
    }
}

/// #729: run from the project root with `--cwd` left at its default (`.`).
/// The project's own `vendor/bundle` is project-local whatever spelling
/// `--cwd` has, so the stale copy there takes the delete-list remedy (not
/// the "shared gem home" caveat), and the committed `vendor/cache`
/// archive is folded into that warning instead of warning separately.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_default_cwd_keeps_project_local_remedy() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    materialize_installed_gem(&proj, "3.3.0", UPSTREAM_LIB);
    std::fs::create_dir_all(proj.join("vendor").join("cache")).unwrap();
    std::fs::write(
        proj.join("vendor")
            .join("cache")
            .join(format!("{DEP}-{DEP_VERSION}.gem")),
        UPSTREAM_ARCHIVE,
    )
    .unwrap();

    for cwd_args in [&[][..], &["--cwd", "."][..]] {
        let mut args = vec!["scan", "--mode", "hosted", "--json", "--yes", "--api-url"];
        let uri = server.uri();
        args.push(&uri);
        args.extend_from_slice(&["--org", ORG, "--api-token", "fake"]);
        args.extend_from_slice(cwd_args);
        let (code, stdout, stderr) = common::run_with_env(&proj, &args, &[]);
        assert_eq!(
            code, 0,
            "args={args:?}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        let env = common::parse_json_envelope(&stdout);
        let warnings = stale_warnings(&env);
        assert_eq!(
            warnings.len(),
            1,
            "args={args:?}: one project-local warning with the cache archive folded in: {env}"
        );
        let detail = &warnings[0];
        assert!(
            detail.contains("or remove ") && !detail.contains("shared gem home"),
            "args={args:?}: the project's own vendor/bundle is project-local: {detail}"
        );
        let cache_archive = Path::new("vendor")
            .join("cache")
            .join(format!("{DEP}-{DEP_VERSION}.gem"));
        assert!(
            detail.contains(&cache_archive.display().to_string()),
            "args={args:?}: the committed cache archive belongs in the delete list: {detail}"
        );
    }
}

/// #1109: `deployment` (local config, env or global config) stops Bundler
/// using system gems without an explicit `path`: it installs into
/// `vendor/bundle`. On a fresh checkout that store doesn't exist yet, but
/// `bundle install` still fetches into it and never reuses the `gem env`
/// copy, so it is not stale: no warning, and the same run's `--vex`
/// attests the purl.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_deployment_ignores_system_home_copy() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let cases: &[(&str, Option<&str>, &[(&str, &str)])] = &[
        ("local deployment", Some("BUNDLE_DEPLOYMENT: \"true\""), &[]),
        ("env deployment", None, &[("BUNDLE_DEPLOYMENT", "true")]),
        (
            "global deployment",
            None,
            &[("BUNDLE_USER_CONFIG", "../user-bundle-config")],
        ),
    ];
    for (case, local, extra) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        if let Some(line) = local {
            std::fs::create_dir_all(proj.join(".bundle")).unwrap();
            std::fs::write(
                proj.join(".bundle").join("config"),
                format!("---\n{line}\n"),
            )
            .unwrap();
        }
        std::fs::write(
            tmp.path().join("user-bundle-config"),
            "---\nBUNDLE_DEPLOYMENT: \"true\"\n",
        )
        .unwrap();
        let bin_dir = tmp.path().join("fake-bin");
        let system_copy = stage_system_home_copy(&tmp.path().join("system-home"), &bin_dir);

        let (code, env, stderr, vex_path) =
            hosted_vex_scan_with_gem_on_path(&proj, &server.uri(), &bin_dir, extra);
        assert!(
            stale_warnings(&env).is_empty(),
            "{case}: bundler never reuses {}: {env}",
            system_copy.display()
        );
        assert_eq!(
            code, 0,
            "{case}: the run must attest, not fail.\nenvelope: {env}\nstderr:\n{stderr}"
        );
        let doc = std::fs::read_to_string(&vex_path).expect("VEX written");
        assert!(doc.contains(PURL), "{case}: purl not attested:\n{doc}");
    }
}

/// #1109 controls: a falsy `deployment`, or a higher tier that decides
/// the path with system gems on (`path.system`, or a falsy
/// `disable_shared_gems`), leaves Bundler on the system gems, so the stale
/// `gem env` copy still warns and stays out of the VEX. So do the
/// `.bundle`-default flags: Bundler 2.x honors only
/// `default_install_uses_path` and Bundler 4.x only `simulate_version 5`,
/// and a scan can't tell which Bundler runs, so it keeps judging the
/// system home rather than risk skipping a copy Bundler loads.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_system_gems_settings_still_flag_system_home_copy() {
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let cases: &[(&str, Option<&str>, &[(&str, &str)])] = &[
        (
            "local deployment false over env deployment",
            Some("BUNDLE_DEPLOYMENT: \"false\""),
            &[("BUNDLE_DEPLOYMENT", "true")],
        ),
        (
            "local path.system over env deployment",
            Some("BUNDLE_PATH__SYSTEM: \"true\""),
            &[("BUNDLE_DEPLOYMENT", "true")],
        ),
        (
            "local disable_shared_gems false over env deployment",
            Some("BUNDLE_DISABLE_SHARED_GEMS: \"false\""),
            &[("BUNDLE_DEPLOYMENT", "true")],
        ),
        (
            "local simulate_version 5",
            Some("BUNDLE_SIMULATE_VERSION: \"5\""),
            &[],
        ),
        (
            "local default_install_uses_path",
            Some("BUNDLE_DEFAULT_INSTALL_USES_PATH: \"true\""),
            &[],
        ),
    ];
    for (case, local, extra) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        if let Some(line) = local {
            std::fs::create_dir_all(proj.join(".bundle")).unwrap();
            std::fs::write(
                proj.join(".bundle").join("config"),
                format!("---\n{line}\n"),
            )
            .unwrap();
        }
        let bin_dir = tmp.path().join("fake-bin");
        let system_copy = stage_system_home_copy(&tmp.path().join("system-home"), &bin_dir);

        let (code, env, stderr, vex_path) =
            hosted_vex_scan_with_gem_on_path(&proj, &server.uri(), &bin_dir, extra);
        let warnings = stale_warnings(&env);
        assert_eq!(warnings.len(), 1, "{case}: {env}");
        assert!(
            warnings[0].contains(&system_copy.display().to_string()),
            "{case}: {}",
            warnings[0]
        );
        if let Ok(doc) = std::fs::read_to_string(&vex_path) {
            assert!(!doc.contains(PURL), "{case}: stale purl attested:\n{doc}");
        }
        assert_ne!(code, 0, "{case}: stderr:\n{stderr}");
    }
}

/// The lock `bundle install` writes once the hosted pin is installed
/// (bundler >= 2.2: a separate patch-registry `GEM` section).
fn converged_lock(api: &str) -> String {
    let index_url = format!("{api}/patch-registry/gem/{TOKEN}/{UUID}/");
    format!(
        "GEM\n  remote: {index_url}\n  specs:\n    {DEP} ({DEP_VERSION})\n\n\
         GEM\n  remote: https://rubygems.org/\n  specs:\n\n\
         PLATFORMS\n  ruby\n\nDEPENDENCIES\n  {DEP} (= {DEP_VERSION})!\n\n\
         BUNDLED WITH\n   2.6.9\n"
    )
}

/// #1098 (and #1109 for standalone `vex`): when Bundler doesn't use system
/// gems for the project, standalone `vex` must not judge the unused,
/// unpatched copy in the `gem env` home. Each case scans, converges the
/// lock the way `bundle install` would, then runs a manifest-less `vex`
/// with the same fake `gem` on `PATH`:
///
/// - a fresh checkout under an explicit `path` (env, local or global
///   config) or `deployment`, nothing installed yet: attested from the
///   lock;
/// - an installed `BUNDLE_PATH: gems` holding the PATCHED copy: verified.
///
/// The control, where Bundler does use system gems, still refuses the
/// unpatched system copy with `not_applied`.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_standalone_vex_ignores_unused_system_home_copy() {
    use vex_e2e_common::{
        assert_attested, assert_not_attested, run_vex, strip_ledgers, strip_manifest, Marker,
        VexRun,
    };
    let server = MockServer::start().await;
    mount_api(&server, None).await;
    let bin = vex_e2e_common::binary();
    let vulns: &[(&str, &[&str])] = &[(GHSA, &["CVE-2026-4444"])];

    enum Config {
        None,
        Local(&'static str),
        Env(&'static str, &'static str),
        Global(&'static str),
    }
    let cases: &[(&str, Config, bool, bool)] = &[
        // (case, config, install the patched copy under `gems/`, attests)
        (
            "fresh, local path",
            Config::Local("BUNDLE_PATH: \"vendor/bundle\""),
            false,
            true,
        ),
        (
            "fresh, env path",
            Config::Env("BUNDLE_PATH", "vendor/bundle"),
            false,
            true,
        ),
        (
            "fresh, global path",
            Config::Global("BUNDLE_PATH: \"vendor/bundle\""),
            false,
            true,
        ),
        (
            "fresh, local deployment",
            Config::Local("BUNDLE_DEPLOYMENT: \"true\""),
            false,
            true,
        ),
        (
            "installed, local path gems",
            Config::Local("BUNDLE_PATH: \"gems\""),
            true,
            true,
        ),
        ("control, system gems", Config::None, false, false),
    ];
    for (case, config, install, attests) in cases {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        let bin_dir = tmp.path().join("fake-bin");
        stage_system_home_copy(&tmp.path().join("system-home"), &bin_dir);
        let global_config = tmp.path().join("user-bundle-config");
        let mut envs: Vec<(String, std::ffi::OsString)> =
            vec![("PATH".into(), bin_dir.clone().into_os_string())];
        match config {
            Config::None => {}
            Config::Local(line) => {
                std::fs::create_dir_all(proj.join(".bundle")).unwrap();
                std::fs::write(
                    proj.join(".bundle").join("config"),
                    format!("---\n{line}\n"),
                )
                .unwrap();
            }
            Config::Env(k, v) => envs.push(((*k).into(), (*v).into())),
            Config::Global(line) => {
                std::fs::write(&global_config, format!("---\n{line}\n")).unwrap();
                envs.push(("BUNDLE_USER_CONFIG".into(), global_config.clone().into()));
            }
        }
        let scan_env: Vec<(&str, &str)> = envs
            .iter()
            .filter(|(k, _)| k != "PATH")
            .map(|(k, v)| (k.as_str(), v.to_str().unwrap()))
            .collect();
        let (code, env, stderr, _) =
            hosted_vex_scan_with_gem_on_path(&proj, &server.uri(), &bin_dir, &scan_env);
        assert_eq!(
            code == 0,
            *attests,
            "{case}: hosted scan --vex.\nenvelope: {env}\nstderr:\n{stderr}"
        );
        strip_manifest(&proj);
        strip_ledgers(&proj);
        std::fs::write(proj.join("Gemfile.lock"), converged_lock(&server.uri())).unwrap();
        if *install {
            let gem_dir = proj
                .join("gems")
                .join("ruby")
                .join("3.3.0")
                .join("gems")
                .join(format!("{DEP}-{DEP_VERSION}"));
            std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
            std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), PATCHED_LIB).unwrap();
        }

        let run = VexRun {
            api_url: Some(server.uri()),
            api_token: Some("fake".into()),
            org: Some(ORG.into()),
            patch_server_url: Some(server.uri()),
            product: Some("pkg:gem/app@1.0.0".into()),
            envs,
            ..VexRun::default()
        };
        let out = run_vex(&bin, &proj, &run);
        if *attests {
            assert_eq!(out.code, Some(0), "{case}: {out}");
            assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
        } else {
            assert_eq!(out.code, Some(1), "{case}: {out}");
            assert_not_attested(&out.envelope, PURL, "not_applied");
        }
    }
}

// ── refresh ───────────────────────────────────────────────────────────

/// A real `.gem` of the fixture gem whose `lib/stale_probe_gem.rb` is
/// `lib`: the outer tar RubyGems reads, with the gemspec YAML
/// (`metadata.gz`, the same bytes for every build, as the patch service
/// keeps it) and the package tree (`data.tar.gz`).
fn real_gem(lib: &str) -> Vec<u8> {
    real_gem_for(lib, "ruby")
}

/// [`real_gem`] built for `platform`: `ruby`, or the platform of a
/// precompiled gem (`<name>-<version>-<platform>.gem`).
fn real_gem_for(lib: &str, platform: &str) -> Vec<u8> {
    use std::io::Write as _;
    fn gz(bytes: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }
    fn tar_of(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        for (name, bytes) in members {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, *bytes).unwrap();
        }
        tar.into_inner().unwrap()
    }
    let metadata = format!(
        "--- !ruby/object:Gem::Specification\nname: {DEP}\nversion: \
         !ruby/object:Gem::Version\n  version: {DEP_VERSION}\nplatform: {platform}\nauthors:\n- \
         e2e\nbindir: bin\ndependencies: []\nexecutables: []\nextensions: []\nfiles:\n- \
         lib/stale_probe_gem.rb\nrequire_paths:\n- lib\nrubygems_version: 3.6.9\n"
    );
    tar_of(&[
        ("metadata.gz", &gz(metadata.as_bytes())),
        (
            "data.tar.gz",
            &gz(&tar_of(&[("lib/stale_probe_gem.rb", lib.as_bytes())])),
        ),
    ])
}

fn sha256_of(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The patch registry's download route for the fixture gem, serving `body`.
async fn serve_patched_gem(server: &MockServer, body: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/patch-registry/gem/{TOKEN}/{UUID}/gems/{DEP}-{DEP_VERSION}.gem"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/octet-stream"))
        .mount(server)
        .await;
}

/// A real install of the fixture gem under `home`: the gem dir, the
/// archive RubyGems installed it from, and a gemspec that builds nothing.
fn install_real_gem(home: &Path, lib: &str) -> PathBuf {
    install_real_gem_for(home, lib, "ruby")
}

/// [`install_real_gem`] of the build for `platform`: RubyGems names a
/// platform gem's dir, archive and gemspec `<name>-<version>-<platform>`.
fn install_real_gem_for(home: &Path, lib: &str, platform: &str) -> PathBuf {
    let leaf = match platform {
        "ruby" => format!("{DEP}-{DEP_VERSION}"),
        platform => format!("{DEP}-{DEP_VERSION}-{platform}"),
    };
    let gem_dir = home.join("gems").join(&leaf);
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), lib).unwrap();
    std::fs::create_dir_all(home.join("cache")).unwrap();
    std::fs::write(
        home.join("cache").join(format!("{leaf}.gem")),
        real_gem_for(lib, platform),
    )
    .unwrap();
    std::fs::create_dir_all(home.join("specifications")).unwrap();
    std::fs::write(
        home.join("specifications").join(format!("{leaf}.gemspec")),
        format!(
            "Gem::Specification.new do |s|\n  s.name = \"{DEP}\".freeze\n  s.version = \
             \"{DEP_VERSION}\".freeze\n  s.require_paths = [\"lib\".freeze]\nend\n"
        ),
    )
    .unwrap();
    gem_dir
}

fn project_home(proj: &Path) -> PathBuf {
    proj.join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.3.0")
}

fn warnings_with_code(env: &serde_json::Value, code: &str) -> Vec<String> {
    env["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|w| w["code"] == code)
        .map(|w| w["detail"].as_str().unwrap_or_default().to_string())
        .collect()
}

fn installed_lib(gem_dir: &Path) -> String {
    std::fs::read_to_string(gem_dir.join("lib").join("stale_probe_gem.rb")).unwrap()
}

fn scan_args<'a>(proj: &'a Path, api: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--cwd",
        proj.to_str().expect("utf8 tmp path"),
        "--api-url",
        api,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    args.extend_from_slice(extra);
    args
}

/// The whole point: after `scan`, with no further command, the project's
/// installed gem and both archives ARE the patched gem (so `bundle exec`
/// loads it, and every reinstall flavor reinstalls it), the same run's
/// `--vex` attests it once the probe re-verified it, and a re-scan has
/// nothing left to say.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_replaces_a_stale_project_install_and_its_archives() {
    let server = MockServer::start().await;
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = project_home(&proj);
    let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
    let leaf = format!("{DEP}-{DEP_VERSION}");
    let spec = home.join("specifications").join(format!("{leaf}.gemspec"));
    let spec_before = std::fs::read(&spec).unwrap();
    // A committed `bundle cache` of the upstream gem.
    let committed = proj
        .join("vendor")
        .join("cache")
        .join(format!("{leaf}.gem"));
    std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
    std::fs::write(&committed, real_gem(UPSTREAM_LIB)).unwrap();

    let vex_path = proj.join("out.vex.json");
    let uri = server.uri();
    let args = scan_args(
        &proj,
        &uri,
        &[
            "--json",
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-product",
            "pkg:gem/app@1.0.0",
        ],
    );
    let (code, stdout, stderr) = common::run_with_env(&proj, &args, &[]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert_eq!(hosted_pinned(&env), 1, "{env}");
    assert!(
        stale_warnings(&env).is_empty(),
        "nothing is left stale: {env}"
    );
    let notes = warnings_with_code(&env, "redirect_gem_install_refreshed");
    assert_eq!(
        notes.len(),
        2,
        "the install and the committed archive: {env}"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.contains(&gem_dir.display().to_string()))
            && notes
                .iter()
                .any(|n| n.contains(&committed.display().to_string())),
        "{notes:?}"
    );

    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB);
    assert_eq!(
        std::fs::read(home.join("cache").join(format!("{leaf}.gem"))).unwrap(),
        patched,
        "the archive RubyGems reinstalls from is the patched one"
    );
    assert_eq!(std::fs::read(&committed).unwrap(), patched);
    assert_eq!(std::fs::read(&spec).unwrap(), spec_before);
    assert!(
        !home.join(".socket-patch-refresh").exists(),
        "no stage left"
    );
    let doc = std::fs::read_to_string(&vex_path).expect("VEX written");
    assert!(doc.contains(PURL), "the refreshed copy is attested:\n{doc}");

    // Human re-scan: nothing to refresh, nothing to warn about.
    let args = scan_args(&proj, &uri, &[]);
    let (code, _, stderr) = common::run_with_env(&proj, &args, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        !stderr.contains("still unpatched") && !stderr.contains("Replaced"),
        "a re-scan has nothing to refresh or to warn about:\n{stderr}"
    );
}

/// #2242: what the `rm -f <gemspec> <archive> && bundle install` remedy
/// left in the tree of an earlier Ruby (`vendor/bundle/ruby/3.2.0` beside
/// the `ruby/3.3.0` the project now installs into): the unpatched gem dir,
/// with no gemspec and no archive. `bundle install` never replaces it, and
/// a re-scan cannot refresh it. The scan's remedy is then the directory
/// itself, and following it leaves nothing to warn about.
#[tokio::test(flavor = "multi_thread")]
async fn a_gem_dir_left_without_its_gemspec_is_named_as_the_thing_to_remove() {
    let server = MockServer::start().await;
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    // The running Ruby's tree holds the patched gem already.
    let home = project_home(&proj);
    let current = install_real_gem(&home, PATCHED_LIB);
    // The earlier Ruby's tree, after the old remedy.
    let old_home = home.with_file_name("3.2.0");
    let leftover = install_real_gem(&old_home, UPSTREAM_LIB);
    let leaf = format!("{DEP}-{DEP_VERSION}");
    std::fs::remove_file(
        old_home
            .join("specifications")
            .join(format!("{leaf}.gemspec")),
    )
    .unwrap();
    std::fs::remove_file(old_home.join("cache").join(format!("{leaf}.gem"))).unwrap();

    let uri = server.uri();
    let args = scan_args(&proj, &uri, &[]);
    let (code, _, stderr) = common::run_with_env(&proj, &args, &[]);
    assert_eq!(code, 0, "{stderr}");
    let command = format!("Run `rm -rf {} && bundle install`", shell_word(&leftover));
    assert!(stderr.contains(&command), "{stderr}");
    assert!(
        !stderr.contains("Re-run `socket-patch scan`") && !stderr.contains("rm -f "),
        "no retry that fails the same way, no file that is not there:\n{stderr}"
    );
    assert_eq!(installed_lib(&leftover), UPSTREAM_LIB, "left as it was");

    let args = scan_args(&proj, &uri, &["--json"]);
    let (code, stdout, stderr) = common::run_with_env(&proj, &args, &[]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    let stale = stale_warnings(&env);
    assert_eq!(stale.len(), 1, "{env}");
    assert!(
        stale[0].contains(&format!(
            "Remove {} and run `bundle install`",
            leftover.display()
        )),
        "{stale:?}"
    );

    // The remedy's `rm -rf` (its `bundle install` has nothing to install:
    // the running Ruby's tree is complete).
    std::fs::remove_dir_all(&leftover).unwrap();
    let args = scan_args(&proj, &uri, &[]);
    let (code, _, stderr) = common::run_with_env(&proj, &args, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(!stderr.contains("still unpatched"), "{stderr}");
    assert_eq!(installed_lib(&current), PATCHED_LIB);
}

/// #2219: the machine that did not run the scan. A teammate pulls the
/// hosted `Gemfile` / `Gemfile.lock` onto a checkout whose gems are already
/// installed (or CI restores a `vendor/bundle` cache): Bundler keeps the
/// upstream copy, and standalone `vex` is the one command that notices.
/// Its remedy must be one that works. "Reinstall from the lockfile" does
/// not: `bundle install` changes nothing, and `bundle pristine` on Bundler
/// 2.6+ removes the gems and then fails on the lock's checksum. So `vex`
/// names the scan, and the scan it names, with no `--mode`, replaces the
/// installed copy without touching the committed pair, after which `vex`
/// attests the gem.
#[tokio::test(flavor = "multi_thread")]
async fn standalone_vex_sends_a_stale_hosted_gem_to_the_scan_that_replaces_it() {
    use vex_e2e_common::{assert_attested, assert_not_attested, run_vex, Marker, VexRun};
    let server = MockServer::start().await;
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    let uri = server.uri();
    let tmp = tempfile::tempdir().unwrap();

    // Machine A: scan and commit the pair.
    let a = tmp.path().join("a");
    std::fs::create_dir_all(&a).unwrap();
    write_manifest_pair(&a);
    let (code, _, stderr) = common::run_with_env(&a, &scan_args(&a, &uri, &[]), &[]);
    assert_eq!(code, 0, "{stderr}");

    // Machine B: the same commit over gems installed before it.
    let proj = tmp.path().join("b");
    std::fs::create_dir_all(&proj).unwrap();
    for file in ["Gemfile", "Gemfile.lock"] {
        std::fs::copy(a.join(file), proj.join(file)).unwrap();
    }
    let pair = |proj: &Path| {
        ["Gemfile", "Gemfile.lock"].map(|file| std::fs::read_to_string(proj.join(file)).unwrap())
    };
    let committed = pair(&proj);
    assert!(
        committed[1].contains("/patch-registry/gem/"),
        "the lock pulled onto machine B names the patch registry:\n{}",
        committed[1]
    );
    let home = project_home(&proj);
    let gem_dir = install_real_gem(&home, UPSTREAM_LIB);

    let bin = vex_e2e_common::binary();
    let run = |human: bool| VexRun {
        api_url: Some(uri.clone()),
        api_token: Some("fake".into()),
        org: Some(ORG.into()),
        patch_server_url: Some(uri.clone()),
        product: Some("pkg:gem/app@1.0.0".into()),
        human,
        ..VexRun::default()
    };
    let out = run_vex(&bin, &proj, &run(false));
    assert_eq!(out.code, Some(1), "{out}");
    assert_not_attested(&out.envelope, PURL, "not_applied");

    let out = run_vex(&bin, &proj, &run(true));
    assert_eq!(out.code, Some(1), "{out}");
    assert!(
        out.stderr
            .contains("Run `socket-patch scan` to replace the installed copies")
            && out.stderr.contains("`bundle pristine`")
            && out.stderr.contains("--gem-refresh-shared"),
        "the remedy for an installed hosted gem is the scan:\n{}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("Reinstall from the lockfile")
            && !out.stderr.contains("socket-patch apply"),
        "no remedy that leaves or breaks the install:\n{}",
        out.stderr
    );
    assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB, "vex writes nothing");

    // The same checkout with an agent-mode patch of another package: a
    // scan with no `--mode` keeps agent mode there and replaces no gem, so
    // the hint names the files to remove, not a scan.
    let mixed = tmp.path().join("mixed");
    std::fs::create_dir_all(&mixed).unwrap();
    for file in ["Gemfile", "Gemfile.lock"] {
        std::fs::copy(a.join(file), mixed.join(file)).unwrap();
    }
    install_real_gem(&project_home(&mixed), UPSTREAM_LIB);
    common::write_minimal_manifest(
        &mixed.join(".socket"),
        "pkg:npm/left-pad@1.3.0",
        "22222222-2222-4222-8222-222222222222",
        &[],
    );
    let out = run_vex(&bin, &mixed, &run(true));
    assert_eq!(out.code, Some(1), "{out}");
    assert!(
        out.stderr
            .contains("Remove each gem's `specifications/<name>-<version>.gemspec`")
            && out.stderr.contains(
                "Other projects may load a gem home outside the project, so for one run \
                 `bundle config set --local path vendor/bundle && bundle install` instead",
            ),
        "a mixed-mode project is told which files to remove:\n{}",
        out.stderr
    );
    assert!(
        !out.stderr.contains("Run `socket-patch scan`")
            && !out.stderr.contains("Reinstall from the lockfile"),
        "no scan that would keep agent mode, and no reinstall:\n{}",
        out.stderr
    );

    // The scan the hint names: no `--mode`, the project's own.
    let args = [
        "scan",
        "--yes",
        "--cwd",
        proj.to_str().expect("utf8 tmp path"),
        "--api-url",
        &uri,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    let (code, stdout, stderr) = common::run_with_env(&proj, &args, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "{stdout}\n{stderr}");
    assert_eq!(
        std::fs::read(home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem"))).unwrap(),
        patched,
        "the archive every reinstall uses is the patched one"
    );
    assert_eq!(pair(&proj), committed, "the committed pair is untouched");

    let out = run_vex(&bin, &proj, &run(false));
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(
        out.doc(),
        PURL,
        UUID,
        Marker::Redirected,
        &[(GHSA, &["CVE-2026-4444"])],
    );
}

/// The machine's platform in the platform-build arm, and one the lock also
/// names (another machine's).
const PLATFORM: &str = "arm64-darwin";
const OTHER_PLATFORM: &str = "x86_64-linux-gnu";

/// A gem bundler locks as precompiled platform builds, each pinned to its
/// upstream archive: one entry per platform, no ruby-platform one.
fn platform_lock(arm_sha: &str, linux_sha: &str) -> String {
    format!(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    {DEP} ({DEP_VERSION}-{PLATFORM})\n    \
         {DEP} ({DEP_VERSION}-{OTHER_PLATFORM})\n\nPLATFORMS\n  {PLATFORM}\n  {OTHER_PLATFORM}\n\n\
         DEPENDENCIES\n  {DEP} (= {DEP_VERSION})\n\nCHECKSUMS\n  {DEP} ({DEP_VERSION}-{PLATFORM}) \
         sha256={arm_sha}\n  {DEP} ({DEP_VERSION}-{OTHER_PLATFORM}) sha256={linux_sha}\n\n\
         BUNDLED WITH\n  4.0.15\n"
    )
}

/// A gem locked as precompiled platform builds, with a prebuild for every
/// one: the scan moves both lock entries to the patch registry, each
/// pinned to its own prebuild, and the platform copy this machine
/// installed (`gems/<name>-<version>-<platform>`) is replaced with the
/// patched platform gem the registry serves under that name, verified
/// against that platform's sha256 — as is the committed `bundle cache`
/// archive. A platform gem declares no extensions, so nothing is built.
/// The same run's `--vex` attests the gem, a re-scan has nothing left to
/// do, and `rollback` hands back the pre-scan pair byte for byte and puts
/// the installed copy and the archive back on the upstream platform gem.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_replaces_a_stale_platform_install_with_its_prebuild() {
    let server = MockServer::start().await;
    let build = |lib: &str, platform: &str| real_gem_for(lib, platform);
    let (prebuilt, other_prebuilt) = (
        build(PATCHED_LIB, PLATFORM),
        build(PATCHED_LIB, OTHER_PLATFORM),
    );
    let (upstream, other_upstream) = (
        build(UPSTREAM_LIB, PLATFORM),
        build(UPSTREAM_LIB, OTHER_PLATFORM),
    );
    mount_api_with(
        &server,
        None,
        &sha256_of(&real_gem(PATCHED_LIB)),
        &[
            (PLATFORM, sha256_of(&prebuilt), Some(ARM_UUID)),
            (OTHER_PLATFORM, sha256_of(&other_prebuilt), Some(LINUX_UUID)),
        ],
    )
    .await;
    let leaf = format!("{DEP}-{DEP_VERSION}-{PLATFORM}");
    // The patch registry serves the prebuild under the platform gem's name.
    Mock::given(method("GET"))
        .and(path(format!(
            "{}/gems/{leaf}.gem",
            snapshot_registry_path()
        )))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(prebuilt.clone(), "application/octet-stream"),
        )
        .mount(&server)
        .await;
    // rubygems.org's stand-in: the index lists each build under its own
    // `<version>-<platform>` token.
    Mock::given(method("GET"))
        .and(path(format!("/upstream/info/{DEP}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "---\n{DEP_VERSION} |checksum:{}\n{DEP_VERSION}-{PLATFORM} |checksum:{}\n\
             {DEP_VERSION}-{OTHER_PLATFORM} |checksum:{}\n",
            sha256_of(&real_gem(UPSTREAM_LIB)),
            sha256_of(&upstream),
            sha256_of(&other_upstream),
        )))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/upstream/gems/{leaf}.gem")))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(upstream.clone(), "application/octet-stream"),
        )
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let gemfile = format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n");
    let lock = platform_lock(&sha256_of(&upstream), &sha256_of(&other_upstream));
    std::fs::write(proj.join("Gemfile"), &gemfile).unwrap();
    std::fs::write(proj.join("Gemfile.lock"), &lock).unwrap();
    let home = project_home(&proj);
    let gem_dir = install_real_gem_for(&home, UPSTREAM_LIB, PLATFORM);
    assert!(gem_dir.ends_with(&leaf));
    // A committed `bundle cache` of the upstream platform gem.
    let committed = proj
        .join("vendor")
        .join("cache")
        .join(format!("{leaf}.gem"));
    std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
    std::fs::write(&committed, &upstream).unwrap();

    let vex_path = proj.join("out.vex.json");
    let uri = server.uri();
    let args = scan_args(
        &proj,
        &uri,
        &[
            "--json",
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-product",
            "pkg:gem/app@1.0.0",
        ],
    );
    let (code, stdout, stderr) = common::run_with_env(&proj, &args, &[]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    // One pin, reported per locked build, each under its own patch.
    assert_eq!(
        hosted_pins(&env),
        [
            (format!("{PURL}?platform={PLATFORM}"), ARM_UUID.to_string()),
            (
                format!("{PURL}?platform={OTHER_PLATFORM}"),
                LINUX_UUID.to_string()
            ),
        ],
        "{env}"
    );
    assert!(
        !stdout.contains("redirect_gem_platform_unsupported"),
        "every locked platform has a prebuild: {env}"
    );

    // The lock: both builds under the patch registry, each on its own
    // prebuild's sha256.
    let index = format!("{uri}{}/", snapshot_registry_path());
    let hosted_lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
    assert!(
        hosted_lock.contains(&format!(
            "GEM\n  remote: {index}\n  specs:\n    {DEP} ({DEP_VERSION}-{PLATFORM})\n    {DEP} \
             ({DEP_VERSION}-{OTHER_PLATFORM})\n\n"
        )),
        "{hosted_lock}"
    );
    assert!(
        hosted_lock.contains(&format!(
            "DEPENDENCIES\n  {DEP} (= {DEP_VERSION})!\n\nCHECKSUMS\n  {DEP} \
             ({DEP_VERSION}-{PLATFORM}) sha256={}\n  {DEP} ({DEP_VERSION}-{OTHER_PLATFORM}) \
             sha256={}\n",
            sha256_of(&prebuilt),
            sha256_of(&other_prebuilt)
        )),
        "{hosted_lock}"
    );

    // The installed platform copy and both archives are the prebuild.
    assert!(
        stale_warnings(&env).is_empty(),
        "nothing is left stale: {env}"
    );
    let notes = warnings_with_code(&env, "redirect_gem_install_refreshed");
    assert_eq!(
        notes.len(),
        2,
        "the install and the committed archive: {env}"
    );
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB);
    assert_eq!(
        std::fs::read(home.join("cache").join(format!("{leaf}.gem"))).unwrap(),
        prebuilt,
        "the archive RubyGems reinstalls from is the prebuild"
    );
    assert_eq!(std::fs::read(&committed).unwrap(), prebuilt);
    assert!(
        !home.join(".socket-patch-refresh").exists(),
        "no stage left"
    );
    let doc = std::fs::read_to_string(&vex_path).expect("VEX written");
    assert!(doc.contains(PURL), "the refreshed copy is attested:\n{doc}");

    // A re-scan: the pair is as the scan wants it, the install is patched.
    let (code, stdout, stderr) =
        common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert!(
        stale_warnings(&env).is_empty()
            && warnings_with_code(&env, "redirect_gem_install_refreshed").is_empty(),
        "a re-scan has nothing to refresh or to warn about: {env}"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
        hosted_lock,
        "a re-scan leaves the lock byte-identical"
    );

    // Rollback: every platform entry back upstream, each `CHECKSUMS` entry
    // back on its upstream sha256, the Gemfile as it was.
    let rubygems = format!("{uri}/upstream");
    let (code, stdout, stderr) = common::run_with_env(
        &proj,
        &[
            "rollback",
            PURL,
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            uri.as_str(),
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            uri.as_str(),
        ],
        &[("SOCKET_RUBYGEMS_URL", rubygems.as_str())],
    );
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON: {e}\n{stdout}\n{stderr}"));
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
        lock,
        "rollback restores the lock byte for byte"
    );
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
        gemfile
    );
    // The lock pins the upstream platform gem again, so what Bundler holds
    // goes back to it too: a patched archive left in its cache dir would
    // fail every install on the restored checksum.
    assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB);
    assert_eq!(
        std::fs::read(home.join("cache").join(format!("{leaf}.gem"))).unwrap(),
        upstream
    );
    assert_eq!(std::fs::read(&committed).unwrap(), upstream);
    assert_eq!(
        warnings_with_code(&env, "upstream_gem_install_refreshed").len(),
        2,
        "the install and the committed archive: {env}"
    );
    assert!(
        warnings_with_code(&env, "upstream_gem_stale_cache").is_empty()
            && warnings_with_code(&env, "upstream_gem_stale_install").is_empty(),
        "nothing is left on the patched build: {env}"
    );
}

/// A shared gem home that holds BOTH builds of the gem's version: another
/// project's ruby-platform copy (`gems/<name>-<version>`, patched in place
/// there, its archive pruned) and the platform build this project's lock
/// names. Which copy is this project's is the lock's to say, by leaf:
///
/// * the scan reports the stale PLATFORM build (the one Bundler loads here)
///   and refreshes it on request. Judging the first dir of the version, the
///   ruby-platform one, would call the gem patched and leave the loaded
///   build unpatched and unreported;
/// * `rollback` puts that platform build back on the upstream gem, and
///   neither run judges, reports or replaces the ruby-platform copy the
///   lock does not name.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn stale_guard_follows_the_builds_the_lock_names_in_a_home_with_both() {
    let server = MockServer::start().await;
    let (prebuilt, other_prebuilt) = (
        real_gem_for(PATCHED_LIB, PLATFORM),
        real_gem_for(PATCHED_LIB, OTHER_PLATFORM),
    );
    let (upstream, other_upstream) = (
        real_gem_for(UPSTREAM_LIB, PLATFORM),
        real_gem_for(UPSTREAM_LIB, OTHER_PLATFORM),
    );
    mount_api_with(
        &server,
        None,
        &sha256_of(&real_gem(PATCHED_LIB)),
        &[
            (PLATFORM, sha256_of(&prebuilt), Some(ARM_UUID)),
            (OTHER_PLATFORM, sha256_of(&other_prebuilt), Some(LINUX_UUID)),
        ],
    )
    .await;
    let leaf = format!("{DEP}-{DEP_VERSION}-{PLATFORM}");
    for (route, body) in [
        (
            format!("{}/gems/{leaf}.gem", snapshot_registry_path()),
            prebuilt.clone(),
        ),
        (format!("/upstream/gems/{leaf}.gem"), upstream.clone()),
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, "application/octet-stream"))
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(format!("/upstream/info/{DEP}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "---\n{DEP_VERSION}-{PLATFORM} |checksum:{}\n{DEP_VERSION}-{OTHER_PLATFORM} \
             |checksum:{}\n",
            sha256_of(&upstream),
            sha256_of(&other_upstream),
        )))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let lock = platform_lock(&sha256_of(&upstream), &sha256_of(&other_upstream));
    std::fs::write(
        proj.join("Gemfile"),
        format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n"),
    )
    .unwrap();
    std::fs::write(proj.join("Gemfile.lock"), &lock).unwrap();
    // The shared home: the other project's ruby-platform copy first, then
    // this project's platform build beside it.
    let home = tmp.path().join("system-home");
    let bin_dir = tmp.path().join("fake-bin");
    let ruby_dir = stage_system_home_copy(&home, &bin_dir);
    let ruby_archive = home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem"));
    std::fs::write(ruby_dir.join("lib").join("stale_probe_gem.rb"), PATCHED_LIB).unwrap();
    std::fs::remove_file(&ruby_archive).unwrap();
    let platform_dir = install_real_gem_for(&home, UPSTREAM_LIB, PLATFORM);
    let path_env = [("PATH", bin_dir.to_str().unwrap())];
    let ruby_copy_untouched = || {
        assert_eq!(
            installed_lib(&ruby_dir),
            PATCHED_LIB,
            "the ruby-platform copy is not this project's"
        );
        assert!(!ruby_archive.exists(), "no archive is added beside it");
    };

    // The scan: the stale copy is the platform build, and a shared home is
    // left alone.
    let uri = server.uri();
    let (code, stdout, stderr) =
        common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &path_env);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert_eq!(hosted_pinned(&env), 2, "both locked builds: {env}");
    let stale = stale_warnings(&env);
    assert_eq!(stale.len(), 1, "one stale copy, the platform build: {env}");
    assert!(
        stale[0].contains(&format!("install at {}, and", platform_dir.display())),
        "{stale:?}"
    );
    assert_eq!(installed_lib(&platform_dir), UPSTREAM_LIB);
    ruby_copy_untouched();

    // On request the platform build is refreshed; the other copy is not.
    let (code, stdout, stderr) = common::run_with_env(
        &proj,
        &scan_args(&proj, &uri, &["--json", "--gem-refresh-shared"]),
        &path_env,
    );
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert!(stale_warnings(&env).is_empty(), "{env}");
    let notes = warnings_with_code(&env, "redirect_gem_install_refreshed");
    assert_eq!(notes.len(), 1, "{env}");
    assert!(
        notes[0].contains(&platform_dir.display().to_string()),
        "{notes:?}"
    );
    assert_eq!(installed_lib(&platform_dir), PATCHED_LIB);
    assert_eq!(
        std::fs::read(home.join("cache").join(format!("{leaf}.gem"))).unwrap(),
        prebuilt
    );
    ruby_copy_untouched();

    // Rollback: the platform build goes back to the upstream gem. The
    // ruby-platform copy holds the patch and has no archive, and is still
    // none of this project's builds: it is neither reported nor replaced.
    let rubygems = format!("{uri}/upstream");
    let (code, stdout, stderr) = common::run_with_env(
        &proj,
        &[
            "rollback",
            PURL,
            "--json",
            "--gem-refresh-shared",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            uri.as_str(),
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            uri.as_str(),
        ],
        &[
            ("PATH", bin_dir.to_str().unwrap()),
            ("SOCKET_RUBYGEMS_URL", rubygems.as_str()),
        ],
    );
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON: {e}\n{stdout}\n{stderr}"));
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
        lock,
        "rollback restores the lock byte for byte"
    );
    assert_eq!(installed_lib(&platform_dir), UPSTREAM_LIB);
    assert_eq!(
        std::fs::read(home.join("cache").join(format!("{leaf}.gem"))).unwrap(),
        upstream
    );
    assert_eq!(
        warnings_with_code(&env, "upstream_gem_install_refreshed").len(),
        1,
        "{env}"
    );
    assert!(
        warnings_with_code(&env, "upstream_gem_stale_install").is_empty(),
        "the copy the lock does not name is not reported: {env}"
    );
    ruby_copy_untouched();
}

/// A lock of two platform builds where the patch registry has a patched
/// build for the other platform only: this machine's platform is served
/// as upstream's own gem, and its lock entry keeps upstream's sha256. The
/// copy this machine installed and the committed `bundle cache` archive
/// are upstream's gem, which is right. The scan moves the gem, reports no
/// stale install, refreshes nothing and downloads no gem: with the gem
/// home's cached archive beside the install, and with it pruned, where
/// only the patch's file hashes could judge the copy (they would call
/// upstream's files stale).
#[tokio::test(flavor = "multi_thread")]
async fn a_platform_served_as_upstreams_gem_is_no_stale_install() {
    let upstream = real_gem_for(UPSTREAM_LIB, PLATFORM);
    let other_upstream = real_gem_for(UPSTREAM_LIB, OTHER_PLATFORM);
    let other_patched = real_gem_for(PATCHED_LIB, OTHER_PLATFORM);
    let leaf = format!("{DEP}-{DEP_VERSION}-{PLATFORM}");
    for cached in [true, false] {
        let server = MockServer::start().await;
        mount_api_with(
            &server,
            None,
            &sha256_of(&real_gem(PATCHED_LIB)),
            &[
                (PLATFORM, sha256_of(&upstream), None),
                (OTHER_PLATFORM, sha256_of(&other_patched), Some(LINUX_UUID)),
            ],
        )
        .await;
        // The registry hands this platform's gem on unchanged: a refresh
        // that asked for it would be served, and would show below.
        let gem_route = format!("{}/gems/{leaf}.gem", snapshot_registry_path());
        Mock::given(method("GET"))
            .and(path(gem_route.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(upstream.clone(), "application/octet-stream"),
            )
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("Gemfile"),
            format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n"),
        )
        .unwrap();
        let lock = platform_lock(&sha256_of(&upstream), &sha256_of(&other_upstream));
        std::fs::write(proj.join("Gemfile.lock"), &lock).unwrap();
        let home = project_home(&proj);
        let gem_dir = install_real_gem_for(&home, UPSTREAM_LIB, PLATFORM);
        let home_archive = home.join("cache").join(format!("{leaf}.gem"));
        if !cached {
            std::fs::remove_file(&home_archive).unwrap();
        }
        let committed = proj
            .join("vendor")
            .join("cache")
            .join(format!("{leaf}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        std::fs::write(&committed, &upstream).unwrap();

        let uri = server.uri();
        let (code, stdout, stderr) =
            common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "cached={cached}: {env}\nstderr:\n{stderr}");
        // The gem moved: the other platform is patched, this one is not.
        assert_eq!(
            hosted_pins(&env),
            [(
                format!("{PURL}?platform={OTHER_PLATFORM}"),
                LINUX_UUID.to_string()
            )],
            "cached={cached}: {env}"
        );
        let hosted_lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
        assert!(
            hosted_lock.contains(&format!(
                "CHECKSUMS\n  {DEP} ({DEP_VERSION}-{PLATFORM}) sha256={}\n  {DEP} \
                 ({DEP_VERSION}-{OTHER_PLATFORM}) sha256={}\n",
                sha256_of(&upstream),
                sha256_of(&other_patched)
            )),
            "cached={cached}: this platform keeps upstream's sha256:\n{hosted_lock}"
        );

        // Nothing about this machine's copy: it is the gem the lock pins.
        assert!(
            stale_warnings(&env).is_empty()
                && warnings_with_code(&env, "redirect_gem_install_refreshed").is_empty(),
            "cached={cached}: {env}"
        );
        assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB, "cached={cached}");
        assert_eq!(std::fs::read(&committed).unwrap(), upstream);
        match cached {
            true => assert_eq!(std::fs::read(&home_archive).unwrap(), upstream),
            false => assert!(!home_archive.exists(), "no archive is added"),
        }
        let asked: Vec<String> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|request| request.url.path().to_string())
            .filter(|route| route.contains("/gems/") || route.contains("/patches/view/"))
            .collect();
        assert_eq!(
            asked,
            Vec::<String>::new(),
            "cached={cached}: no gem is downloaded, no record is fetched to judge the copy"
        );

        // For a person: the one line about the gem's builds, and no warning.
        let (code, stdout, stderr) = common::run_with_env(&proj, &scan_args(&proj, &uri, &[]), &[]);
        assert_eq!(code, 0, "cached={cached}:\n{stdout}\n{stderr}");
        assert!(
            stdout.contains(&format!(
                "{DEP} {DEP_VERSION}: patched for {OTHER_PLATFORM}; upstream gem kept for \
                 {PLATFORM} (no patched build yet)\n"
            )),
            "cached={cached}:\n{stdout}"
        );
        assert!(
            !stderr.contains("stale") && !stderr.contains("unpatched install"),
            "cached={cached}:\n{stderr}"
        );
        assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB, "cached={cached}");

        // The VEX of this machine, from the run itself and from a later
        // `vex`: the other platform's build is attested under its own
        // patch, and this machine's build is said affected. The installed
        // copy is upstream's gem, as its lock entry names it, and is no
        // evidence against the build the lock installs patched.
        let patched_part = format!("Patched via Socket patch {LINUX_UUID} (redirected)");
        let expected = [
            (
                "not_affected".to_string(),
                format!("{PURL}?platform={OTHER_PLATFORM}"),
                patched_part,
            ),
            (
                "affected".to_string(),
                format!("{PURL}?platform={PLATFORM}"),
                String::new(),
            ),
        ];
        let said = |doc: &serde_json::Value| -> Vec<(String, String, String)> {
            let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_string();
            let statements = doc["statements"].as_array().expect("statements");
            statements
                .iter()
                .map(|st| {
                    let packages = st["products"][0]["subcomponents"].as_array();
                    assert_eq!(packages.map(Vec::len), Some(1), "{st}");
                    (
                        text(&st["status"]),
                        text(&st["products"][0]["subcomponents"][0]["@id"]),
                        text(&st["impact_statement"]),
                    )
                })
                .collect()
        };
        let vex_path = proj.join("run.vex.json");
        let with_vex = [
            "--json",
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-product",
            "pkg:gem/app@1.0.0",
        ];
        let (code, stdout, stderr) =
            common::run_with_env(&proj, &scan_args(&proj, &uri, &with_vex), &[]);
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "cached={cached}: {env}\nstderr:\n{stderr}");
        assert_eq!(env["vex"]["affected"], 1, "cached={cached}: {env}");
        let doc = vex_e2e_common::read_doc(&vex_path).expect("the run's document");
        assert_eq!(said(&doc), expected, "cached={cached}: {doc}");

        let later = vex_e2e_common::VexRun {
            api_url: Some(uri.clone()),
            api_token: Some("fake".into()),
            org: Some(ORG.into()),
            patch_server_url: Some(uri.clone()),
            product: Some("pkg:gem/app@1.0.0".into()),
            ..vex_e2e_common::VexRun::default()
        };
        let out = vex_e2e_common::run_vex(&vex_e2e_common::binary(), &proj, &later);
        assert_eq!(out.code, Some(0), "cached={cached}: {out}");
        assert_eq!(said(out.doc()), expected, "cached={cached}: {out}");
        assert_eq!(out.envelope["status"], "success", "cached={cached}: {out}");
    }
}

/// The snapshot the registry URL names once the patched build of
/// [`PLATFORM`] was withdrawn.
const LATER_SNAPSHOT: u32 = 5;

/// A machine of the platform [`PLATFORM`] that holds a patched build which
/// was withdrawn since. The lock was moved while both locked platforms had
/// a patched build, and the hosted scan put this machine's patched build
/// in place: the installed copy, the archive RubyGems keeps beside it and
/// the committed `bundle cache` archive are that build. After the
/// withdrawal the reference lists upstream's own gem for this platform (no
/// patch), under a later snapshot, beside the other platform's patched
/// build.
struct WithdrawnBuild {
    _tmp: tempfile::TempDir,
    proj: PathBuf,
    home: PathBuf,
    gem_dir: PathBuf,
    home_archive: PathBuf,
    committed: PathBuf,
    /// Upstream's gem for this platform, and the build that was withdrawn.
    upstream: Vec<u8>,
    withdrawn: Vec<u8>,
    /// The sha256 of the other platform's patched build.
    other_patched: String,
    /// The path the registry serves this platform's gem at after the
    /// withdrawal.
    file_route: String,
}

impl WithdrawnBuild {
    /// Stage the machine against `server`, which answers as the patch
    /// service does after the withdrawal, except for this platform's gem
    /// file: each case serves that its own way.
    async fn stage(server: &MockServer) -> WithdrawnBuild {
        let upstream = real_gem_for(UPSTREAM_LIB, PLATFORM);
        let other_upstream = real_gem_for(UPSTREAM_LIB, OTHER_PLATFORM);
        let withdrawn = real_gem_for(PATCHED_LIB, PLATFORM);
        let other_patched = sha256_of(&real_gem_for(PATCHED_LIB, OTHER_PLATFORM));
        let ruby_sha = sha256_of(&real_gem(PATCHED_LIB));
        let leaf = format!("{DEP}-{DEP_VERSION}-{PLATFORM}");

        // While both platforms had a patched build.
        mount_api_with(
            server,
            None,
            &ruby_sha,
            &[
                (PLATFORM, sha256_of(&withdrawn), Some(ARM_UUID)),
                (OTHER_PLATFORM, other_patched.clone(), Some(LINUX_UUID)),
            ],
        )
        .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "{}/gems/{leaf}.gem",
                snapshot_registry_path()
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(withdrawn.clone(), "application/octet-stream"),
            )
            .mount(server)
            .await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("Gemfile"),
            format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n"),
        )
        .unwrap();
        std::fs::write(
            proj.join("Gemfile.lock"),
            platform_lock(&sha256_of(&upstream), &sha256_of(&other_upstream)),
        )
        .unwrap();
        let home = project_home(&proj);
        let gem_dir = install_real_gem_for(&home, UPSTREAM_LIB, PLATFORM);
        let home_archive = home.join("cache").join(format!("{leaf}.gem"));
        let committed = proj
            .join("vendor")
            .join("cache")
            .join(format!("{leaf}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        std::fs::write(&committed, &upstream).unwrap();
        let uri = server.uri();
        let (code, stdout, stderr) =
            common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
        assert_eq!(code, 0, "premise: the first scan\n{stdout}\n{stderr}");
        assert_eq!(
            installed_lib(&gem_dir),
            PATCHED_LIB,
            "premise: this machine holds the patched build"
        );
        for archive in [&home_archive, &committed] {
            assert_eq!(std::fs::read(archive).unwrap(), withdrawn, "premise");
        }

        // The patched build of this platform is withdrawn.
        server.reset().await;
        mount_patch_api_with(
            server,
            UUID,
            PATCHED_LIB,
            None,
            &ruby_sha,
            &[
                (PLATFORM, sha256_of(&upstream), None),
                (OTHER_PLATFORM, other_patched.clone(), Some(LINUX_UUID)),
            ],
            LATER_SNAPSHOT,
        )
        .await;
        let file_route =
            format!("/patch-registry/gem/{TOKEN}/{UUID}/s/{LATER_SNAPSHOT}/gems/{leaf}.gem");
        WithdrawnBuild {
            _tmp: tmp,
            proj,
            home,
            gem_dir,
            home_archive,
            committed,
            upstream,
            withdrawn,
            other_patched,
            file_route,
        }
    }

    /// The registry hands this platform's gem on as `body`.
    async fn relay(&self, server: &MockServer, body: &[u8]) {
        Mock::given(method("GET"))
            .and(path(self.file_route.clone()))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(body.to_vec(), "application/octet-stream"),
            )
            .mount(server)
            .await;
    }

    /// `socket-patch scan --mode hosted` with `extra`: exit code, stdout
    /// and stderr.
    fn scan(&self, server: &MockServer, extra: &[&str]) -> (i32, String, String) {
        let uri = server.uri();
        common::run_with_env(&self.proj, &scan_args(&self.proj, &uri, extra), &[])
    }

    /// A `--json` scan with `extra`, which must exit 0: its envelope.
    fn scan_json(&self, server: &MockServer, extra: &[&str]) -> serde_json::Value {
        let mut args = vec!["--json"];
        args.extend_from_slice(extra);
        let (code, stdout, stderr) = self.scan(server, &args);
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
        env
    }

    /// The lock follows the reference: the registry at the later snapshot,
    /// upstream's sha256 for this platform, the other platform's patched
    /// build as it was.
    fn assert_lock_is_back_on_upstreams_gem(&self, server: &MockServer) {
        let lock = std::fs::read_to_string(self.proj.join("Gemfile.lock")).unwrap();
        assert!(
            lock.contains(&format!(
                "  remote: {}/patch-registry/gem/{TOKEN}/{UUID}/s/{LATER_SNAPSHOT}/\n",
                server.uri()
            )) && lock.contains(&format!(
                "CHECKSUMS\n  {DEP} ({DEP_VERSION}-{PLATFORM}) sha256={}\n  {DEP} \
                 ({DEP_VERSION}-{OTHER_PLATFORM}) sha256={}\n",
                sha256_of(&self.upstream),
                self.other_patched
            )),
            "{lock}"
        );
    }

    /// The copy, the archive beside it and the committed archive are all
    /// `gem`, whose `lib` Ruby loads.
    fn assert_holds(&self, gem: &[u8], lib: &str) {
        assert_eq!(installed_lib(&self.gem_dir), lib);
        assert_eq!(std::fs::read(&self.home_archive).unwrap(), gem);
        assert_eq!(std::fs::read(&self.committed).unwrap(), gem);
        assert!(
            !self.home.join(".socket-patch-refresh").exists(),
            "no stage left"
        );
    }

    /// What a VEX document says of the gem whatever this machine holds:
    /// the other platform's build is attested under its own patch, and
    /// this platform's build is affected.
    fn assert_vex(&self, doc: &serde_json::Value) {
        let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_string();
        let said: Vec<(String, String, String)> = doc["statements"]
            .as_array()
            .expect("statements")
            .iter()
            .map(|st| {
                let packages = st["products"][0]["subcomponents"].as_array();
                assert_eq!(packages.map(Vec::len), Some(1), "{st}");
                (
                    text(&st["status"]),
                    text(&st["products"][0]["subcomponents"][0]["@id"]),
                    text(&st["impact_statement"]),
                )
            })
            .collect();
        assert_eq!(
            said,
            [
                (
                    "not_affected".to_string(),
                    format!("{PURL}?platform={OTHER_PLATFORM}"),
                    format!("Patched via Socket patch {LINUX_UUID} (redirected)"),
                ),
                (
                    "affected".to_string(),
                    format!("{PURL}?platform={PLATFORM}"),
                    String::new(),
                ),
            ],
            "{doc}"
        );
        assert!(
            !doc.to_string().contains(ARM_UUID),
            "the withdrawn build's patch is named nowhere: {doc}"
        );
    }

    /// A later `socket-patch vex` over the project: its outcome.
    fn later_vex(&self, server: &MockServer) -> vex_e2e_common::VexOutcome {
        let later = vex_e2e_common::VexRun {
            api_url: Some(server.uri()),
            api_token: Some("fake".into()),
            org: Some(ORG.into()),
            patch_server_url: Some(server.uri()),
            product: Some("pkg:gem/app@1.0.0".into()),
            ..vex_e2e_common::VexRun::default()
        };
        vex_e2e_common::run_vex(&vex_e2e_common::binary(), &self.proj, &later)
    }
}

/// The paths of the gem files and patch records `server` was asked for
/// after its first `skip` requests.
async fn gems_and_views_since(server: &MockServer, skip: usize) -> Vec<String> {
    let requests = server.received_requests().await.unwrap_or_default();
    let routes = requests.iter().skip(skip).map(|r| r.url.path().to_string());
    routes
        .filter(|route| route.contains("/gems/") || route.contains("/patches/view/"))
        .collect()
}

/// A patched build that was withdrawn must not stay installed. The next
/// scan puts upstream's sha256 back into the lock, and the guard judges
/// this machine's copy by the archive it was installed from: it is not
/// upstream's gem, so it is replaced, with the committed archive, by the
/// file the patch registry serves for the platform, verified against the
/// sha256 the reference lists. Whether the registry relays that file
/// (200) or redirects to the upstream registry (302), in which case the
/// other host learns nothing of the grant. One download, no patch record.
/// The run's VEX and a later one say `affected` of this platform's build
/// and still attest the other; a further scan changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_build_is_replaced_with_upstreams_gem_through_the_registry() {
    for redirects in [false, true] {
        let server = MockServer::start().await;
        let elsewhere = MockServer::start().await;
        let w = WithdrawnBuild::stage(&server).await;
        let leaf = format!("{DEP}-{DEP_VERSION}-{PLATFORM}");
        if redirects {
            let location = format!("{}/gems/{leaf}.gem", elsewhere.uri());
            Mock::given(method("GET"))
                .and(path(w.file_route.clone()))
                .respond_with(
                    ResponseTemplate::new(302)
                        .insert_header("Location", location.as_str())
                        .insert_header("Cache-Control", "no-store"),
                )
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/gems/{leaf}.gem")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_raw(w.upstream.clone(), "application/octet-stream"),
                )
                .mount(&elsewhere)
                .await;
        } else {
            w.relay(&server, &w.upstream).await;
        }

        let env = w.scan_json(&server, &[]);
        assert_eq!(
            hosted_pins(&env),
            [(
                format!("{PURL}?platform={OTHER_PLATFORM}"),
                LINUX_UUID.to_string()
            )],
            "redirects={redirects}: {env}"
        );
        w.assert_lock_is_back_on_upstreams_gem(&server);
        assert!(stale_warnings(&env).is_empty(), "nothing is left: {env}");
        let mut notes = warnings_with_code(&env, "redirect_gem_install_refreshed");
        notes.sort();
        assert_eq!(
            notes,
            [
                format!(
                    "{PURL}: replaced the withdrawn archive at {} with the upstream gem",
                    w.committed.display()
                ),
                format!(
                    "{PURL}: replaced the withdrawn install at {} with the upstream gem",
                    w.gem_dir.display()
                ),
            ],
            "redirects={redirects}: {env}"
        );
        w.assert_holds(&w.upstream, UPSTREAM_LIB);
        assert_eq!(
            gems_and_views_since(&server, 0).await,
            [w.file_route.clone()],
            "redirects={redirects}: one download for both, and no patch record"
        );
        let handed_on = elsewhere.received_requests().await.unwrap_or_default();
        assert_eq!(handed_on.len(), usize::from(redirects));
        for request in &handed_on {
            let sent = format!("{:?}", request.headers);
            assert!(
                request.headers.get("referer").is_none() && !sent.contains(TOKEN),
                "the other host learns nothing of the grant: {sent}"
            );
        }

        // A further scan changes nothing and downloads nothing.
        let lock = std::fs::read(w.proj.join("Gemfile.lock")).unwrap();
        let before = server.received_requests().await.unwrap_or_default().len();
        let vex_path = w.proj.join("run.vex.json");
        let with_vex = [
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-product",
            "pkg:gem/app@1.0.0",
        ];
        let env = w.scan_json(&server, &with_vex);
        assert!(
            stale_warnings(&env).is_empty()
                && warnings_with_code(&env, "redirect_gem_install_refreshed").is_empty(),
            "redirects={redirects}: {env}"
        );
        assert_eq!(std::fs::read(w.proj.join("Gemfile.lock")).unwrap(), lock);
        w.assert_holds(&w.upstream, UPSTREAM_LIB);
        let asked = gems_and_views_since(&server, before).await;
        assert!(
            asked.iter().all(|route| !route.contains("/gems/")),
            "redirects={redirects}: {asked:?}"
        );

        // VEX, from that run and from a later `vex`.
        assert_eq!(env["vex"]["affected"], 1, "{env}");
        w.assert_vex(&vex_e2e_common::read_doc(&vex_path).expect("the run's document"));
        let out = w.later_vex(&server);
        assert_eq!(out.code, Some(0), "redirects={redirects}: {out}");
        w.assert_vex(out.doc());
        assert_eq!(out.envelope["status"], "success", "{out}");
    }
}

/// For a person, the run that replaces the copy of a withdrawn build says
/// so in one line per kind, each naming the upstream gem and why, never a
/// patched one, and has nothing left to reinstall.
#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_build_refresh_says_what_took_its_place() {
    let server = MockServer::start().await;
    let w = WithdrawnBuild::stage(&server).await;
    w.relay(&server, &w.upstream).await;

    let (code, stdout, stderr) = w.scan(&server, &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    for line in [
        format!(
            "Replaced the installed copy of 1 gem with the upstream build (its patched build \
             was withdrawn): {DEP} {DEP_VERSION}.\n"
        ),
        format!(
            "Replaced 1 archive in Bundler's cache dir with the upstream gem (its patched build \
             was withdrawn): {DEP} {DEP_VERSION}.\n"
        ),
    ] {
        assert!(stderr.contains(&line), "missing {line:?}:\n{stderr}");
    }
    assert!(
        !stderr.contains("still holds") && !stderr.contains("patched build:"),
        "nothing is left to warn about, and nothing is called patched:\n{stderr}"
    );
    assert!(
        stdout.contains(
            "  2. Run `socket-patch vex` to verify the installed patches (the installed gems \
             already hold the builds the lockfile pins, so there is nothing to reinstall).\n"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("vendor/cache/{DEP}-{DEP_VERSION}-{PLATFORM}.gem")),
        "the replaced archive is a file to commit:\n{stdout}"
    );
    w.assert_holds(&w.upstream, UPSTREAM_LIB);
}

/// The withdrawn build is one of an earlier patch of the gem, and the
/// patch on offer is a newer one with no patched build for this machine's
/// platform. The earlier patch's registry, under the snapshot the lock
/// names, no longer lists the build and refuses its file, so the lock is
/// not held there: the scan asks that registry once, moves the pair to
/// the newer patch with upstream's sha256 for this platform, says that
/// the build is back on upstream's gem, and the guard replaces the copy
/// and the committed archive with the file the newer patch's registry
/// serves. One download, no patch record; a further scan changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_build_of_an_earlier_patch_is_replaced_through_the_newer_patchs_registry() {
    let server = MockServer::start().await;
    let w = WithdrawnBuild::stage(&server).await;
    let leaf = format!("{DEP}-{DEP_VERSION}-{PLATFORM}");
    let api = server.uri();
    let lock_before = std::fs::read_to_string(w.proj.join("Gemfile.lock")).unwrap();
    assert!(
        lock_before.contains(&format!("  remote: {api}{}/\n", snapshot_registry_path())),
        "premise: the lock is on the earlier patch at its first snapshot:\n{lock_before}"
    );

    // The service offers the newer patch, with a patched build for the
    // other platform alone. The earlier patch is still granted: only its
    // build for this platform is gone.
    server.reset().await;
    let ruby_sha = sha256_of(&real_gem(NEWER_PATCHED_LIB));
    let newer_other = sha256_of(&real_gem_for(NEWER_PATCHED_LIB, OTHER_PLATFORM));
    let newer_other_uuid = "a1b2c3d4-0000-4000-8000-00000000000c";
    let offered = [
        (PLATFORM, sha256_of(&w.upstream), None),
        (OTHER_PLATFORM, newer_other.clone(), Some(newer_other_uuid)),
    ];
    let earlier_now = [
        (PLATFORM, sha256_of(&w.upstream), None),
        (OTHER_PLATFORM, w.other_patched.clone(), Some(LINUX_UUID)),
    ];
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                NEWER_UUID: granted_reference(&api, NEWER_UUID, &ruby_sha, &offered, LATER_SNAPSHOT),
                UUID: granted_reference(
                    &api,
                    UUID,
                    &sha256_of(&real_gem(PATCHED_LIB)),
                    &earlier_now,
                    LATER_SNAPSHOT,
                ),
            }
        })))
        .with_priority(1)
        .mount(&server)
        .await;
    mount_patch_api_with(
        &server,
        NEWER_UUID,
        NEWER_PATCHED_LIB,
        None,
        &ruby_sha,
        &offered,
        LATER_SNAPSHOT,
    )
    .await;
    // The earlier patch's registry as the lock names it: the build of
    // this platform is not listed, and its file is not served.
    let earlier_index = format!("{}/info/{DEP}", snapshot_registry_path());
    Mock::given(method("GET"))
        .and(path(earlier_index.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "---\n{DEP_VERSION} |checksum:{}\n{DEP_VERSION}-{OTHER_PLATFORM} |checksum:{}\n",
            sha256_of(&real_gem(PATCHED_LIB)),
            w.other_patched
        )))
        .mount(&server)
        .await;
    // The newer patch's registry relays upstream's gem for this platform.
    let newer_registry = format!("/patch-registry/gem/{TOKEN}/{NEWER_UUID}/s/{LATER_SNAPSHOT}");
    let file_route = format!("{newer_registry}/gems/{leaf}.gem");
    Mock::given(method("GET"))
        .and(path(file_route.clone()))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(w.upstream.clone(), "application/octet-stream"),
        )
        .mount(&server)
        .await;

    let known = ["--patch-server-url", api.as_str()];
    let env = w.scan_json(&server, &known);
    let lock = std::fs::read_to_string(w.proj.join("Gemfile.lock")).unwrap();
    assert!(
        lock.contains(&format!("  remote: {api}{newer_registry}/\n"))
            && !lock.contains(UUID)
            && lock.contains(&format!(
                "CHECKSUMS\n  {DEP} ({DEP_VERSION}-{PLATFORM}) sha256={}\n  {DEP} \
                 ({DEP_VERSION}-{OTHER_PLATFORM}) sha256={newer_other}\n",
                sha256_of(&w.upstream),
            )),
        "the lock is on the newer patch, upstream's sha256 back for this platform:\n{lock}\n{env}"
    );
    assert_eq!(
        hosted_pins(&env),
        [(
            format!("{PURL}?platform={OTHER_PLATFORM}"),
            newer_other_uuid.to_string()
        )],
        "{env}"
    );
    let back: Vec<&serde_json::Value> = env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| event["errorCode"] == "gem_upstream_build_kept")
        .collect();
    assert_eq!(
        back,
        [&serde_json::json!({
            "action": "skipped",
            "purl": format!("{PURL}?platform={PLATFORM}"),
            "errorCode": "gem_upstream_build_kept",
            "reason": format!(
                "the patch registry serves upstream's own gem for {PLATFORM}: its patched build \
                 was withdrawn"
            ),
            "details": {
                "gemFix": NEWER_UUID, "platform": PLATFORM, "withdrawn": true, "mode": "hosted",
            },
        })],
        "{env}"
    );
    assert!(stale_warnings(&env).is_empty(), "nothing is left: {env}");
    let mut notes = warnings_with_code(&env, "redirect_gem_install_refreshed");
    notes.sort();
    assert_eq!(
        notes,
        [
            format!(
                "{PURL}: replaced the withdrawn archive at {} with the upstream gem",
                w.committed.display()
            ),
            format!(
                "{PURL}: replaced the withdrawn install at {} with the upstream gem",
                w.gem_dir.display()
            ),
        ],
        "{env}"
    );
    w.assert_holds(&w.upstream, UPSTREAM_LIB);
    let asked = server.received_requests().await.unwrap_or_default();
    let asked: Vec<&str> = asked
        .iter()
        .map(|request| request.url.path())
        .filter(|route| route.starts_with("/patch-registry/") || route.contains("/patches/view/"))
        .collect();
    assert_eq!(
        asked,
        [earlier_index.as_str(), file_route.as_str()],
        "the registry the lock was on is asked once, upstream's gem is downloaded once from the \
         newer patch's registry, and no patch record is fetched"
    );

    // A further scan changes nothing and downloads nothing.
    let before = server.received_requests().await.unwrap_or_default().len();
    let env = w.scan_json(&server, &known);
    assert!(
        stale_warnings(&env).is_empty()
            && warnings_with_code(&env, "redirect_gem_install_refreshed").is_empty(),
        "{env}"
    );
    assert_eq!(
        std::fs::read_to_string(w.proj.join("Gemfile.lock")).unwrap(),
        lock
    );
    w.assert_holds(&w.upstream, UPSTREAM_LIB);
    let asked = server.received_requests().await.unwrap_or_default();
    let asked: Vec<&str> = asked
        .iter()
        .skip(before)
        .map(|request| request.url.path())
        .filter(|route| route.starts_with("/patch-registry/"))
        .collect();
    assert_eq!(asked, Vec::<&str>::new(), "no registry request");
}

/// The lock stays on the patch it is on: the patch on offer serves
/// upstream's gem for the other platform, which the lock's patch still
/// serves patched. That patch withdrew this machine's build, so its
/// registry no longer lists it under the snapshot the lock names. The
/// scan asks that registry once, brings the pair to the same patch's
/// current snapshot with upstream's sha256 for this platform (the other
/// platform's patched sha256 as it was), skips the patch on offer quietly,
/// and the guard replaces the copy and the committed archive with the file
/// that patch's registry serves under its current snapshot. One download,
/// no patch record; a further scan changes nothing and downloads nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_build_of_the_patch_a_lock_stays_on_is_replaced_through_its_current_registry() {
    let server = MockServer::start().await;
    let w = WithdrawnBuild::stage(&server).await;
    let api = server.uri();
    let lock_before = std::fs::read_to_string(w.proj.join("Gemfile.lock")).unwrap();
    assert!(
        lock_before.contains(&format!("  remote: {api}{}/\n", snapshot_registry_path())),
        "premise: the lock is on the patch at its first snapshot:\n{lock_before}"
    );

    // The service offers a newer patch with no patched build for either
    // platform, and answers each reference request with the patches it was
    // asked for: the newer one, and the lock's own as it stands.
    server.reset().await;
    let ruby_sha = sha256_of(&real_gem(PATCHED_LIB));
    let newer_ruby_sha = sha256_of(&real_gem(NEWER_PATCHED_LIB));
    let other_upstream = sha256_of(&real_gem_for(UPSTREAM_LIB, OTHER_PLATFORM));
    let offered = [
        (PLATFORM, sha256_of(&w.upstream), None),
        (OTHER_PLATFORM, other_upstream, None),
    ];
    let own_now = [
        (PLATFORM, sha256_of(&w.upstream), None),
        (OTHER_PLATFORM, w.other_patched.clone(), Some(LINUX_UUID)),
    ];
    let on_offer = granted_reference(&api, NEWER_UUID, &newer_ruby_sha, &offered, LATER_SNAPSHOT);
    let own = granted_reference(&api, UUID, &ruby_sha, &own_now, LATER_SNAPSHOT);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(move |request: &wiremock::Request| {
            let asked: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or_default();
            let mut results = serde_json::Map::new();
            for uuid in asked["uuids"].as_array().into_iter().flatten() {
                match uuid.as_str() {
                    Some(NEWER_UUID) => results.insert(NEWER_UUID.to_string(), on_offer.clone()),
                    Some(UUID) => results.insert(UUID.to_string(), own.clone()),
                    _ => None,
                };
            }
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
        })
        .with_priority(1)
        .mount(&server)
        .await;
    mount_patch_api_with(
        &server,
        NEWER_UUID,
        NEWER_PATCHED_LIB,
        None,
        &newer_ruby_sha,
        &offered,
        LATER_SNAPSHOT,
    )
    .await;
    // The lock's registry as the lock names it: the build of this platform
    // is not listed. Under its current snapshot it lists upstream's gem
    // for it, and relays that file.
    let index_before = format!("{}/info/{DEP}", snapshot_registry_path());
    let index_now = format!("/patch-registry/gem/{TOKEN}/{UUID}/s/{LATER_SNAPSHOT}/info/{DEP}");
    for (route, listing) in [
        (
            &index_before,
            format!(
                "---\n{DEP_VERSION} |checksum:{ruby_sha}\n{DEP_VERSION}-{OTHER_PLATFORM} \
                 |checksum:{}\n",
                w.other_patched
            ),
        ),
        (
            &index_now,
            format!(
                "---\n{DEP_VERSION} |checksum:{ruby_sha}\n{DEP_VERSION}-{PLATFORM} \
                 |checksum:{}\n{DEP_VERSION}-{OTHER_PLATFORM} |checksum:{}\n",
                sha256_of(&w.upstream),
                w.other_patched
            ),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(route.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_string(listing))
            .mount(&server)
            .await;
    }
    w.relay(&server, &w.upstream).await;

    let known = ["--patch-server-url", api.as_str()];
    let env = w.scan_json(&server, &known);
    w.assert_lock_is_back_on_upstreams_gem(&server);
    assert!(
        !std::fs::read_to_string(w.proj.join("Gemfile.lock"))
            .unwrap()
            .contains(NEWER_UUID),
        "the lock stays on its patch"
    );
    let events: Vec<(String, String, String)> = env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| event["details"]["mode"] == "hosted")
        .map(|event| {
            let text = |key: &str| event[key].as_str().unwrap_or_default().to_string();
            (text("action"), text("purl"), text("errorCode"))
        })
        .collect();
    assert_eq!(
        events,
        [
            (
                "skipped".to_string(),
                PURL.to_string(),
                "redirect_gem_newer_fix_waits".to_string()
            ),
            (
                "skipped".to_string(),
                format!("{PURL}?platform={PLATFORM}"),
                "gem_upstream_build_kept".to_string()
            ),
            (
                "applied".to_string(),
                format!("{PURL}?platform={OTHER_PLATFORM}"),
                String::new()
            ),
        ],
        "{env}"
    );
    assert_eq!(
        hosted_pins(&env),
        [(
            format!("{PURL}?platform={OTHER_PLATFORM}"),
            LINUX_UUID.to_string()
        )],
        "{env}"
    );
    assert!(stale_warnings(&env).is_empty(), "nothing is left: {env}");
    let mut notes = warnings_with_code(&env, "redirect_gem_install_refreshed");
    notes.sort();
    assert_eq!(
        notes,
        [
            format!(
                "{PURL}: replaced the withdrawn archive at {} with the upstream gem",
                w.committed.display()
            ),
            format!(
                "{PURL}: replaced the withdrawn install at {} with the upstream gem",
                w.gem_dir.display()
            ),
        ],
        "{env}"
    );
    w.assert_holds(&w.upstream, UPSTREAM_LIB);
    let asked = server.received_requests().await.unwrap_or_default();
    let routes: Vec<&str> = asked
        .iter()
        .map(|request| request.url.path())
        .filter(|route| route.starts_with("/patch-registry/") || route.contains("/patches/view/"))
        .collect();
    assert_eq!(
        routes,
        [index_before.as_str(), w.file_route.as_str()],
        "the registry the lock is on is asked once, upstream's gem is downloaded once under \
         its current snapshot, and no patch record is fetched"
    );
    let references: Vec<serde_json::Value> = asked
        .iter()
        .filter(|request| request.url.path().ends_with("/patches/package"))
        .map(|request| {
            serde_json::from_slice::<serde_json::Value>(&request.body).unwrap_or_default()["uuids"]
                .clone()
        })
        .collect();
    assert_eq!(
        references,
        [serde_json::json!([UUID]), serde_json::json!([NEWER_UUID])],
        "the scan's check of the pin and the patch on offer: no further reference request"
    );

    // A further scan changes nothing and downloads nothing.
    let lock = std::fs::read_to_string(w.proj.join("Gemfile.lock")).unwrap();
    let before = server.received_requests().await.unwrap_or_default().len();
    let env = w.scan_json(&server, &known);
    assert!(
        stale_warnings(&env).is_empty()
            && warnings_with_code(&env, "redirect_gem_install_refreshed").is_empty(),
        "{env}"
    );
    assert_eq!(
        std::fs::read_to_string(w.proj.join("Gemfile.lock")).unwrap(),
        lock
    );
    w.assert_holds(&w.upstream, UPSTREAM_LIB);
    let asked = server.received_requests().await.unwrap_or_default();
    let routes: Vec<&str> = asked
        .iter()
        .skip(before)
        .map(|request| request.url.path())
        .filter(|route| route.starts_with("/patch-registry/"))
        .collect();
    assert_eq!(routes, [index_now.as_str()], "one listing, no download");
}

/// The registry relays bytes that are not the gem the reference lists for
/// the platform: no byte of them is used. The withdrawn build stays, the
/// lock still goes back to upstream's sha256, and the run says, as a
/// warning and never as a failure, that a withdrawn build is still
/// installed and how to remove it. That copy keeps nothing of the gem out
/// of the VEX: the other platform's build is attested, this one affected.
#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_build_is_not_replaced_with_a_gem_the_reference_does_not_list() {
    let server = MockServer::start().await;
    let w = WithdrawnBuild::stage(&server).await;
    // The same gem with other bytes.
    w.relay(
        &server,
        &real_gem_for("module StaleProbeGem\n  EVIL = true\nend\n", PLATFORM),
    )
    .await;
    let spec = w
        .home
        .join("specifications")
        .join(format!("{DEP}-{DEP_VERSION}-{PLATFORM}.gemspec"));
    let files = [&spec, &w.home_archive, &w.committed];

    // For a person: one warning, and what to run.
    let (code, stdout, stderr) = w.scan(&server, &[]);
    assert_eq!(code, 0, "a failed refresh never fails the scan:\n{stderr}");
    w.assert_lock_is_back_on_upstreams_gem(&server);
    w.assert_holds(&w.withdrawn, PATCHED_LIB);
    let words: Vec<String> = files.iter().map(|path| shell_word(path)).collect();
    let warning = format!(
        "Warning: 1 gem still holds a patched build on disk that was withdrawn.\n  - Not \
         refreshed (the upstream gem the server sent does not have the pinned sha256): {DEP} \
         {DEP_VERSION}. Re-run `socket-patch scan` to retry, or run `rm -f {} && bundle \
         install`.\n",
        words.join(" ")
    );
    assert!(stderr.contains(&warning), "missing {warning:?}:\n{stderr}");
    assert_eq!(stderr.matches("still holds").count(), 1, "{stderr}");
    assert!(!stderr.contains("Replaced"), "{stderr}");
    assert!(
        stdout.contains(
            "  2. Replace the withdrawn gem build with the command in the warning above (a \
             plain `bundle install` keeps the gems it already has), then run `socket-patch vex` \
             to verify the installed patches.\n"
        ),
        "{stdout}"
    );

    // The same in `--json`, on every later run, with the run's own VEX.
    let vex_path = w.proj.join("run.vex.json");
    let with_vex = [
        "--vex",
        vex_path.to_str().unwrap(),
        "--vex-product",
        "pkg:gem/app@1.0.0",
    ];
    let env = w.scan_json(&server, &with_vex);
    let listed: Vec<String> = files.iter().map(|p| p.display().to_string()).collect();
    assert_eq!(
        stale_warnings(&env),
        [format!(
            "{PURL} is back on upstream's own gem for {PLATFORM}, whose patched build was \
             withdrawn, but its withdrawn install at {} was not refreshed (the upstream gem the \
             server sent does not have the pinned sha256), and `bundle install` reuses an \
             installed gem instead of fetching the upstream one. Re-run `socket-patch scan` to \
             retry, or remove {} and run `bundle install`",
            w.gem_dir.display(),
            listed.join(", ")
        )],
        "{env}"
    );
    assert!(
        warnings_with_code(&env, "redirect_gem_install_refreshed").is_empty(),
        "{env}"
    );
    w.assert_holds(&w.withdrawn, PATCHED_LIB);
    assert_eq!(env["vex"]["statements"], 2, "{env}");
    assert_eq!(env["vex"]["affected"], 1, "{env}");
    w.assert_vex(&vex_e2e_common::read_doc(&vex_path).expect("the run's document"));
    let out = w.later_vex(&server);
    assert_eq!(out.code, Some(0), "{out}");
    w.assert_vex(out.doc());
    assert_eq!(out.envelope["status"], "success", "{out}");
}

/// The refresh is switched off, or only previewed: nothing is downloaded
/// and nothing replaced. A dry run says what a wet run would replace, and
/// `--no-gem-install-refresh` warns that the withdrawn build is still
/// installed, with the run that replaces it. That run then does.
#[tokio::test(flavor = "multi_thread")]
async fn a_withdrawn_build_is_left_with_a_warning_when_the_refresh_is_off() {
    let server = MockServer::start().await;
    let w = WithdrawnBuild::stage(&server).await;
    w.relay(&server, &w.upstream).await;

    let env = w.scan_json(&server, &["--dry-run"]);
    let mut would = warnings_with_code(&env, "redirect_gem_install_would_refresh");
    would.sort();
    assert_eq!(
        would,
        [
            format!(
                "{PURL}: would replace the withdrawn archive at {} with the upstream gem",
                w.committed.display()
            ),
            format!(
                "{PURL}: would replace the withdrawn install at {} with the upstream gem",
                w.gem_dir.display()
            ),
        ],
        "{env}"
    );
    assert!(stale_warnings(&env).is_empty(), "{env}");
    w.assert_holds(&w.withdrawn, PATCHED_LIB);

    let env = w.scan_json(&server, &["--no-gem-install-refresh"]);
    w.assert_lock_is_back_on_upstreams_gem(&server);
    let stale = stale_warnings(&env);
    assert_eq!(stale.len(), 1, "{env}");
    assert!(
        stale[0].starts_with(&format!(
            "{PURL} is back on upstream's own gem for {PLATFORM}, whose patched build was \
             withdrawn, but its withdrawn install at {} was not refreshed \
             (`--no-gem-install-refresh` is set), and `bundle install` reuses an installed gem \
             instead of fetching the upstream one. Re-run without `--no-gem-install-refresh`, \
             or remove ",
            w.gem_dir.display()
        )) && stale[0].ends_with(" and run `bundle install`"),
        "{}",
        stale[0]
    );
    w.assert_holds(&w.withdrawn, PATCHED_LIB);
    assert_eq!(
        gems_and_views_since(&server, 0).await,
        Vec::<String>::new(),
        "neither run downloads a gem or fetches a record"
    );

    // The run the warning names.
    let env = w.scan_json(&server, &[]);
    assert!(stale_warnings(&env).is_empty(), "{env}");
    assert_eq!(
        warnings_with_code(&env, "redirect_gem_install_refreshed").len(),
        2,
        "{env}"
    );
    w.assert_holds(&w.upstream, UPSTREAM_LIB);
}

/// A fresh checkout: nothing is installed, and the lock names the gem only
/// as platform builds. The hosted scan reads the gem from the lock alone
/// and pins every build to its patched build. Where the patch registry
/// does not list one locked platform it pins nothing, says which, and
/// leaves both files as they were.
#[tokio::test(flavor = "multi_thread")]
async fn gem_hosted_scan_pins_platform_builds_from_the_lock_alone() {
    let ruby_sha = sha256_of(&real_gem(PATCHED_LIB));
    let (arm_sha, linux_sha) = (
        sha256_of(&real_gem_for(PATCHED_LIB, PLATFORM)),
        sha256_of(&real_gem_for(PATCHED_LIB, OTHER_PLATFORM)),
    );
    for complete in [true, false] {
        let server = MockServer::start().await;
        let mut builds = vec![(PLATFORM, arm_sha.clone(), Some(ARM_UUID))];
        if complete {
            builds.push((OTHER_PLATFORM, linux_sha.clone(), Some(LINUX_UUID)));
        }
        mount_api_with(&server, None, &ruby_sha, &builds).await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let gemfile =
            format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n");
        let lock = platform_lock(&"1".repeat(64), &"2".repeat(64));
        std::fs::write(proj.join("Gemfile"), &gemfile).unwrap();
        std::fs::write(proj.join("Gemfile.lock"), &lock).unwrap();

        let (code, stdout, stderr) = hosted_scan_json(&proj, &server.uri());
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
        let after = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
        let skipped = warnings_with_code(&env, "redirect_gem_platform_unsupported");
        if complete {
            assert_eq!(hosted_pinned(&env), 2, "one per locked build: {env}");
            assert!(skipped.is_empty(), "{env}");
            assert!(
                after.contains(&format!(
                    "{}/\n  specs:\n    {DEP} ({DEP_VERSION}-{PLATFORM})\n    {DEP} \
                     ({DEP_VERSION}-{OTHER_PLATFORM})\n",
                    snapshot_registry_path()
                )),
                "{after}"
            );
            assert!(
                after.contains(&format!(
                    "  {DEP} ({DEP_VERSION}-{PLATFORM}) sha256={arm_sha}\n  {DEP} \
                     ({DEP_VERSION}-{OTHER_PLATFORM}) sha256={linux_sha}\n"
                )),
                "{after}"
            );
            assert!(
                stale_warnings(&env).is_empty(),
                "nothing is installed: {env}"
            );
        } else {
            assert_eq!(hosted_pinned(&env), 0, "{env}");
            // A platform the list leaves out: the gem is left as it is,
            // and nothing is warned about.
            assert!(skipped.is_empty(), "{env}");
            let unlisted: Vec<&str> = env["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|event| event["errorCode"] == "redirect_gem_platform_unlisted")
                .filter_map(|event| event["reason"].as_str())
                .collect();
            let [detail] = unlisted.as_slice() else {
                panic!("one quiet skip: {env}");
            };
            assert_eq!(
                *detail,
                format!(
                    "{DEP} {DEP_VERSION}: the patch registry does not list {OTHER_PLATFORM}, so \
                     the gem is left as it is"
                )
            );
            assert_eq!(after, lock, "the lock is untouched");
            assert_eq!(
                std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
                gemfile,
                "the Gemfile is untouched"
            );
        }
    }
}

/// A lock that names the gem only as platform builds, beside a plain
/// gem, and a patch whose registry does not list every locked platform:
/// the run refuses the gem. The lock still resolves it, so the closing
/// totals count its advisory as left to patch, in hosted mode (which
/// reads the gem from the lock alone) and in vendored mode (which reads
/// the installed platform copy).
#[tokio::test(flavor = "multi_thread")]
async fn refused_platform_gem_is_counted_as_left_to_patch() {
    const LEFT: &str =
        "\n1 vulnerability left to patch: 1 is in packages this run did not patch.\n";
    let arm_sha = sha256_of(&real_gem_for(PATCHED_LIB, PLATFORM));
    for mode in ["hosted", "vendored"] {
        let server = MockServer::start().await;
        // The lookup names the advisory the patch fixes, as the service
        // does (the totals count advisories), and only for a run that
        // asks about the gem.
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": [],
                "canAccessPaidPatches": false,
            })))
            .with_priority(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
            .and(body_string_contains(DEP))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": [{
                    "purl": PURL,
                    "patches": [{
                        "uuid": UUID, "purl": PURL, "tier": "free",
                        "cveIds": [], "ghsaIds": [GHSA], "severity": "high",
                        "title": "gem stale-install fixture"
                    }]
                }],
                "canAccessPaidPatches": false,
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        mount_api_with(
            &server,
            None,
            &sha256_of(&real_gem(PATCHED_LIB)),
            &[(PLATFORM, arm_sha.clone(), Some(ARM_UUID))],
        )
        .await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        let gemfile = format!(
            "source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\ngem \
             \"plain-probe-gem\", \"1.0.0\"\n"
        );
        // The plain gem makes the lock one that lists ruby-platform gems
        // too, as every real lock does (nokogiri beside racc).
        let lock = platform_lock(&"1".repeat(64), &"2".repeat(64))
            .replace("  specs:\n", "  specs:\n    plain-probe-gem (1.0.0)\n")
            .replace(
                "DEPENDENCIES\n",
                "DEPENDENCIES\n  plain-probe-gem (= 1.0.0)\n",
            );
        assert!(
            lock.contains("    plain-probe-gem (1.0.0)\n")
                && !lock.contains(&format!("    {DEP} ({DEP_VERSION})\n")),
            "the lock holds a plain gem, and {DEP} as platform builds only:\n{lock}"
        );
        std::fs::write(proj.join("Gemfile"), &gemfile).unwrap();
        std::fs::write(proj.join("Gemfile.lock"), &lock).unwrap();
        if mode == "vendored" {
            install_real_gem_for(&project_home(&proj), UPSTREAM_LIB, PLATFORM);
        }

        let uri = server.uri();
        let (code, stdout, stderr) = common::run_with_env(
            &proj,
            &[
                "scan",
                "--mode",
                mode,
                "--yes",
                "--cwd",
                proj.to_str().unwrap(),
                "--api-url",
                uri.as_str(),
                "--patch-server-url",
                uri.as_str(),
                "--org",
                ORG,
                "--api-token",
                "fake",
            ],
            &[],
        );
        assert_eq!(code, 0, "{mode}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        // The premise: the run left the gem alone for a platform the
        // patch registry does not serve.
        let (refusal, said) = match mode {
            "hosted" => (
                format!(
                    "{DEP} {DEP_VERSION}: the patch registry does not list {OTHER_PLATFORM}, so \
                     the gem is left as it is"
                ),
                &stdout,
            ),
            _ => (
                format!(
                    "{DEP}@{DEP_VERSION} is not vendored: no patched build yet for \
                     {OTHER_PLATFORM}"
                ),
                &stderr,
            ),
        };
        assert!(
            said.contains(&refusal),
            "{mode}: the run leaves the gem alone\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert_eq!(
            std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
            lock,
            "{mode}: the lock is untouched"
        );
        assert!(
            stdout.ends_with(LEFT),
            "{mode}: the refused gem is left to patch\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}

/// Human output of the run that refreshes: one progress line per kind,
/// no warning, and the committed archive in the files to commit.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_reports_progress_lines_and_the_archive_to_commit() {
    let server = MockServer::start().await;
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    install_real_gem(&project_home(&proj), UPSTREAM_LIB);
    let leaf = format!("{DEP}-{DEP_VERSION}");
    let committed = proj
        .join("vendor")
        .join("cache")
        .join(format!("{leaf}.gem"));
    std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
    std::fs::write(&committed, real_gem(UPSTREAM_LIB)).unwrap();

    let uri = server.uri();
    let (code, stdout, stderr) = common::run_with_env(&proj, &scan_args(&proj, &uri, &[]), &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains(&format!(
            "Replaced the installed copy of 1 gem with the patched build: {DEP} {DEP_VERSION}."
        )) && stderr.contains(&format!(
            "Replaced 1 archive in Bundler's cache dir with the patched gem: {DEP} {DEP_VERSION}."
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("still unpatched"), "{stderr}");
    assert!(
        stdout.contains(&format!("vendor/cache/{leaf}.gem")),
        "the replaced archive is a file to commit:\n{stdout}"
    );
}

/// `--dry-run` writes nothing and says what a wet run would refresh.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_dry_run_only_says_what_it_would_replace() {
    let server = MockServer::start().await;
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = project_home(&proj);
    let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
    let upstream = real_gem(UPSTREAM_LIB);
    let gemfile = std::fs::read(proj.join("Gemfile")).unwrap();

    let uri = server.uri();
    let (code, stdout, stderr) = common::run_with_env(
        &proj,
        &scan_args(&proj, &uri, &["--json", "--dry-run"]),
        &[],
    );
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    let would = warnings_with_code(&env, "redirect_gem_install_would_refresh");
    assert_eq!(would.len(), 1, "{env}");
    assert!(
        would[0].contains(&gem_dir.display().to_string()),
        "{would:?}"
    );
    assert!(stale_warnings(&env).is_empty(), "{env}");

    let (code, _, stderr) =
        common::run_with_env(&proj, &scan_args(&proj, &uri, &["--dry-run"]), &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains(&format!(
            "Would replace the installed copy of 1 gem with the patched build: {DEP} {DEP_VERSION}."
        )),
        "{stderr}"
    );

    assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB);
    assert_eq!(
        std::fs::read(home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem"))).unwrap(),
        upstream
    );
    assert_eq!(std::fs::read(proj.join("Gemfile")).unwrap(), gemfile);
    assert!(
        !server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .any(|r| r.url.path().ends_with(".gem")),
        "a dry run downloads no archive"
    );
}

/// The archive the server sends is not the one the grant pins: nothing of
/// it is used, the install stays as it was, the warning says why, and the
/// run still exits 0. `--no-gem-install-refresh` does not even ask.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_uses_no_byte_of_an_unverified_archive() {
    let server = MockServer::start().await;
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    // Same gem, other bytes.
    serve_patched_gem(
        &server,
        real_gem("module StaleProbeGem\n  EVIL = true\nend\n"),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = project_home(&proj);
    let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
    let cache = home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem"));

    let uri = server.uri();
    let (code, stdout, stderr) =
        common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(
        code, 0,
        "a failed refresh never fails the scan: {env}\n{stderr}"
    );
    let details = stale_warnings(&env);
    assert_eq!(details.len(), 1, "{env}");
    assert!(
        details[0].contains("does not have the pinned sha256"),
        "{}",
        details[0]
    );
    assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB);
    assert_eq!(std::fs::read(&cache).unwrap(), real_gem(UPSTREAM_LIB));
    assert!(!home.join(".socket-patch-refresh").exists());

    let before = server.received_requests().await.unwrap_or_default().len();
    let (code, stdout, _) = common::run_with_env(
        &proj,
        &scan_args(&proj, &uri, &["--json", "--no-gem-install-refresh"]),
        &[],
    );
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}");
    let details = stale_warnings(&env);
    assert!(
        details.len() == 1 && details[0].contains("`--no-gem-install-refresh` is set"),
        "{env}"
    );
    let asked_for_gem = server.received_requests().await.unwrap_or_default()[before..]
        .iter()
        .any(|r| r.url.path().ends_with(".gem"));
    assert!(!asked_for_gem, "an opted-out run downloads no archive");
}

/// A gem home outside the project is left exactly as it was, under ONE
/// human warning that names the gem, the home, and the remedy as a
/// command; `--gem-refresh-shared` refreshes it like a project-local one.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn refresh_leaves_a_shared_gem_home_alone_unless_asked() {
    let server = MockServer::start().await;
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = tmp.path().join("system-home");
    let bin_dir = tmp.path().join("fake-bin");
    stage_system_home_copy(&home, &bin_dir);
    let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
    let cache = home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem"));
    let path_env = [("PATH", bin_dir.to_str().unwrap())];

    let uri = server.uri();
    let (code, _, stderr) = common::run_with_env(&proj, &scan_args(&proj, &uri, &[]), &path_env);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(
        installed_lib(&gem_dir),
        UPSTREAM_LIB,
        "the shared home is not touched"
    );
    assert_eq!(std::fs::read(&cache).unwrap(), real_gem(UPSTREAM_LIB));
    assert_eq!(
        stderr.matches("still unpatched on disk").count(),
        1,
        "one stale-install warning:\n{stderr}"
    );
    for needle in [
        "Warning: 1 gem is still unpatched on disk after the switch to hosted patches.",
        &format!(
            "  - Shared gem home {} (left alone, other projects may load it): {DEP} {DEP_VERSION}.",
            home.display()
        ),
        "run `bundle config set --local path vendor/bundle && bundle install`",
        "`--gem-refresh-shared`",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?}:\n{stderr}");
    }

    let (code, stdout, stderr) = common::run_with_env(
        &proj,
        &scan_args(&proj, &uri, &["--json", "--gem-refresh-shared"]),
        &path_env,
    );
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert!(stale_warnings(&env).is_empty(), "{env}");
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB);
    assert_eq!(std::fs::read(&cache).unwrap(), patched);
}

/// rubygems.org's stand-in under `/upstream` (`SOCKET_RUBYGEMS_URL`): the
/// compact index entry naming the upstream archive's sha256, and its
/// download.
async fn serve_upstream_gem(server: &MockServer, upstream: &[u8]) {
    Mock::given(method("GET"))
        .and(path(format!("/upstream/info/{DEP}")))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "---\n{DEP_VERSION} |checksum:{}\n",
            sha256_of(upstream)
        )))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/upstream/gems/{DEP}-{DEP_VERSION}.gem")))
        .respond_with(
            ResponseTemplate::new(200).set_body_raw(upstream.to_vec(), "application/octet-stream"),
        )
        .mount(server)
        .await;
}

/// The unwind direction: `rollback` puts the lock back on rubygems.org and
/// the project's installed gem and archives back on the upstream gem,
/// verified against the sha256 the compact index names.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_after_rollback_restores_the_upstream_gem() {
    let server = MockServer::start().await;
    let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    serve_upstream_gem(&server, &upstream).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = project_home(&proj);
    let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
    let leaf = format!("{DEP}-{DEP_VERSION}");
    let cache = home.join("cache").join(format!("{leaf}.gem"));
    let committed = proj
        .join("vendor")
        .join("cache")
        .join(format!("{leaf}.gem"));
    std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
    std::fs::write(&committed, &upstream).unwrap();

    let uri = server.uri();
    let (code, _, stderr) = common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "scan refreshed it");
    // The lock as `bundle install` leaves it once the pin is installed.
    std::fs::write(proj.join("Gemfile.lock"), converged_lock(&uri)).unwrap();

    let rubygems = format!("{uri}/upstream");
    let rollback = |extra: &[&'static str]| {
        let mut args = vec![
            "rollback",
            PURL,
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            uri.as_str(),
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            uri.as_str(),
        ];
        args.extend_from_slice(extra);
        common::run_with_env(&proj, &args, &[("SOCKET_RUBYGEMS_URL", rubygems.as_str())])
    };

    // A dry run says what it would do and changes nothing.
    let (code, stdout, stderr) = rollback(&["--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "Would replace the installed copy of 1 gem with the upstream build: {DEP} {DEP_VERSION}."
        )),
        "{stdout}"
    );
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB);

    let (code, stdout, stderr) = rollback(&["--json"]);
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON: {e}\n{stdout}\n{stderr}"));
    assert_eq!(code, 0, "{env}\n{stderr}");
    let lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
    assert!(
        !lock.contains("/patch-registry/"),
        "the lock is back on upstream:\n{lock}"
    );
    assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB);
    assert_eq!(std::fs::read(&cache).unwrap(), upstream);
    assert_eq!(std::fs::read(&committed).unwrap(), upstream);
    assert_eq!(
        warnings_with_code(&env, "upstream_gem_install_refreshed").len(),
        2,
        "the install and the committed archive: {env}"
    );
    assert!(
        warnings_with_code(&env, "upstream_gem_stale_cache").is_empty()
            && warnings_with_code(&env, "upstream_gem_stale_install").is_empty(),
        "nothing is left on the patched build: {env}"
    );
}

/// #2086: `rollback` / `remove` of a hosted gem whose patched copy sits in
/// a shared gem home leave that copy alone and warn about it. The warning
/// names no re-run with `--gem-refresh-shared`: the first run removed the
/// wiring, so a second one has nothing to unwind. It names the
/// project-local path, and the files whose removal makes `bundle install`
/// fetch the upstream gem into the shared home. The generic reinstall note
/// does not claim that the next install replaces the copy.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn hosted_unwind_names_no_rerun_for_a_shared_gem_home() {
    const UNWINDS: [&[&str]; 2] = [&["rollback", "--yes"], &["remove", PURL, "--yes"]];
    for (unwind, json) in UNWINDS
        .into_iter()
        .flat_map(|unwind| [(unwind, false), (unwind, true)])
    {
        let case = format!("{unwind:?} json={json}");
        let server = MockServer::start().await;
        let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
        mount_api_for(&server, None, &sha256_of(&patched)).await;
        serve_patched_gem(&server, patched.clone()).await;
        serve_upstream_gem(&server, &upstream).await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        let home = tmp.path().join("system-home");
        let bin_dir = tmp.path().join("fake-bin");
        stage_system_home_copy(&home, &bin_dir);
        let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
        let leaf = format!("{DEP}-{DEP_VERSION}");
        let cache = home.join("cache").join(format!("{leaf}.gem"));
        let spec = home.join("specifications").join(format!("{leaf}.gemspec"));

        // The shared copy becomes the patched build.
        let uri = server.uri();
        let rubygems = format!("{uri}/upstream");
        let env = [
            ("PATH", bin_dir.to_str().unwrap()),
            ("SOCKET_RUBYGEMS_URL", rubygems.as_str()),
        ];
        let (code, _, stderr) = common::run_with_env(
            &proj,
            &scan_args(&proj, &uri, &["--json", "--gem-refresh-shared"]),
            &env,
        );
        assert_eq!(code, 0, "{case}: {stderr}");
        assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "{case}: premise");
        std::fs::write(proj.join("Gemfile.lock"), converged_lock(&uri)).unwrap();
        let held_before = snapshot(&home);

        let mut args = unwind.to_vec();
        args.extend([
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            uri.as_str(),
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            uri.as_str(),
        ]);
        if json {
            args.push("--json");
        }
        let (code, stdout, stderr) = common::run_with_env(&proj, &args, &env);
        assert_eq!(code, 0, "{case}:\n{stdout}\n{stderr}");
        let lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
        assert!(!lock.contains("/patch-registry/"), "{case}:\n{lock}");
        assert!(
            snapshot(&home) == held_before,
            "{case}: the shared gem home is left alone"
        );

        let remove_files = format!("{} {}", shell_word(&spec), shell_word(&cache));
        let warning = if json {
            let env = common::parse_json_envelope(&stdout);
            let details = details_with_code(&env, "upstream_gem_stale_install");
            assert_eq!(details.len(), 1, "{case}: {env}");
            // rollback's run-level advisory defers to the gem warning.
            if unwind[0] == "rollback" {
                let reinstall = details_with_code(&env, "reinstall_required");
                assert_eq!(reinstall.len(), 1, "{case}: {env}");
                assert!(
                    reinstall[0].contains("`bundle install` keeps an installed gem"),
                    "{case}: {}",
                    reinstall[0]
                );
            }
            assert!(
                details[0].contains(&format!(
                    "remove {}, {} and run `bundle install`",
                    spec.display(),
                    cache.display()
                )),
                "{case}: {}",
                details[0]
            );
            details[0].clone()
        } else {
            assert_eq!(
                stderr.matches("still holds the patched build").count(),
                1,
                "{case}: one warning:\n{stderr}"
            );
            assert!(
                stderr.contains(&format!("run `rm -f {remove_files} && bundle install`")),
                "{case}: the remedy as a command:\n{stderr}"
            );
            if unwind[0] == "rollback" {
                assert!(
                    stdout.contains("1 unwired package keeps its patched bytes")
                        && stdout.contains("`bundle install` keeps")
                        && !stdout.contains("package-manager install."),
                    "{case}: the note defers to the gem warning:\n{stdout}"
                );
            }
            stderr.clone()
        };
        assert!(
            warning.contains("bundle config set --local path vendor/bundle && bundle install"),
            "{case}: {warning}"
        );
        assert!(
            !warning.contains("--gem-refresh-shared") && !warning.to_lowercase().contains("re-run"),
            "{case}: a second unwind has nothing to unwind: {warning}"
        );

        // Why no re-run is named: the wiring is gone.
        let mut again = args.clone();
        again.push("--gem-refresh-shared");
        let (code, stdout, stderr) = common::run_with_env(&proj, &again, &env);
        assert_eq!(code, 1, "{case}: premise:\n{stdout}\n{stderr}");
        let nothing = match (json, unwind[0]) {
            (true, _) => "\"status\": \"error\"",
            (false, "rollback") => "nothing to roll back",
            (false, _) => "nothing to remove",
        };
        assert!(
            format!("{stdout}{stderr}").contains(nothing),
            "{case}: premise: a second unwind finds nothing:\n{stdout}\n{stderr}"
        );
        assert!(snapshot(&home) == held_before, "{case}");
    }
}

/// A registry that is refused (plain http, and not this machine) is not
/// asked what the upstream gem is. `rollback` still puts the lock back,
/// leaves the installed copy as it is, and says so: the copy is reported as
/// one it could not check, with the reason, not passed over in silence
/// while it still holds the patched build.
#[tokio::test(flavor = "multi_thread")]
async fn rollback_reports_the_copy_a_refused_registry_left_unchecked() {
    refused_registry_leaves_the_copy_reported(true).await;
}

/// The same with the copy's archive gone from the home's cache (a pruned
/// `cache/`, as slim images have). With nothing to judge the copy by it is
/// still reported, not passed over.
#[tokio::test(flavor = "multi_thread")]
async fn rollback_reports_an_unchecked_copy_whose_cached_archive_is_gone() {
    refused_registry_leaves_the_copy_reported(false).await;
}

async fn refused_registry_leaves_the_copy_reported(cached_archive: bool) {
    let server = MockServer::start().await;
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = project_home(&proj);
    let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
    let leaf = format!("{DEP}-{DEP_VERSION}");
    let cache = home.join("cache").join(format!("{leaf}.gem"));

    let uri = server.uri();
    let (code, _, stderr) = common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "scan refreshed it");
    std::fs::write(proj.join("Gemfile.lock"), converged_lock(&uri)).unwrap();
    let asked_before = server.received_requests().await.unwrap().len();
    if !cached_archive {
        std::fs::remove_file(&cache).unwrap();
    }

    // Refused before any request: nothing is looked up or sent.
    const REFUSED: &str = "http://gemstash.example.test:9292";
    let args = [
        "rollback",
        PURL,
        "--cwd",
        proj.to_str().unwrap(),
        "--api-url",
        uri.as_str(),
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--patch-server-url",
        uri.as_str(),
        "--json",
    ];
    let (code, stdout, stderr) =
        common::run_with_env(&proj, &args, &[("SOCKET_RUBYGEMS_URL", REFUSED)]);
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON: {e}\n{stdout}\n{stderr}"));
    assert_eq!(code, 0, "{env}\n{stderr}");
    let lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
    assert!(
        !lock.contains("/patch-registry/"),
        "the lock is back on upstream:\n{lock}"
    );
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "left as it is");
    if cached_archive {
        assert_eq!(std::fs::read(&cache).unwrap(), patched);
    }
    assert!(
        warnings_with_code(&env, "upstream_gem_install_refreshed").is_empty(),
        "{env}"
    );
    let unchecked = warnings_with_code(&env, "upstream_gem_stale_install");
    assert_eq!(unchecked.len(), 1, "the copy is reported: {env}");
    for needle in [
        PURL,
        "could not be checked against the upstream gem",
        "`http://gemstash.example.test:9292` is not an https URL",
        "set it to an https URL",
        "it still holds the patched build",
        "run `bundle install`",
        gem_dir.to_str().unwrap(),
    ] {
        assert!(
            unchecked[0].contains(needle),
            "missing {needle:?}: {}",
            unchecked[0]
        );
    }
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        asked_before,
        "the rollback asked a registry"
    );
}

/// The commands that unwind a hosted gem.
const HOSTED_UNWINDS: [&[&str]; 2] = [&["rollback", "--yes"], &["remove", PURL, "--yes"]];

/// A project whose gem a hosted scan pinned, with the lock as `bundle
/// install` leaves it, in a gem home that has no `cache/` dir (Bundler
/// 4.1's `prune` setting, the `rm -rf "${BUNDLE_PATH}"/ruby/*/cache` of the
/// Dockerfile Rails generates, `gem cleanup`). With `refreshed` the scan
/// replaced the installed copy with the patched build; without, it was told
/// not to (`--no-gem-install-refresh`) and the copy is still the upstream
/// one. Returns the installed gem dir and the gem home.
async fn hosted_with_pruned_home_cache(
    server: &MockServer,
    proj: &Path,
    refreshed: bool,
) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(proj).unwrap();
    write_manifest_pair(proj);
    let home = project_home(proj);
    let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
    let uri = server.uri();
    let flags: &[&str] = if refreshed {
        &["--json"]
    } else {
        &["--json", "--no-gem-install-refresh"]
    };
    let (code, _, stderr) = common::run_with_env(proj, &scan_args(proj, &uri, flags), &[]);
    assert_eq!(code, 0, "{stderr}");
    let expected = if refreshed { PATCHED_LIB } else { UPSTREAM_LIB };
    assert_eq!(installed_lib(&gem_dir), expected, "premise");
    std::fs::write(proj.join("Gemfile.lock"), converged_lock(&uri)).unwrap();
    std::fs::remove_dir_all(home.join("cache")).unwrap();
    (gem_dir, home)
}

/// Every `detail` (a warning's) or `reason` (an event's) that `--json`
/// output carries under `code`, wherever the command puts it.
fn details_with_code(env: &serde_json::Value, code: &str) -> Vec<String> {
    fn walk(value: &serde_json::Value, code: &str, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                if map
                    .get("code")
                    .or(map.get("errorCode"))
                    .and_then(|c| c.as_str())
                    == Some(code)
                {
                    let detail = map.get("detail").or(map.get("reason"));
                    out.push(
                        detail
                            .and_then(|d| d.as_str())
                            .unwrap_or_default()
                            .to_string(),
                    );
                }
                map.values().for_each(|v| walk(v, code, out));
            }
            serde_json::Value::Array(items) => items.iter().for_each(|v| walk(v, code, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(env, code, &mut out);
    out
}

/// #2092: a gem home with no `cache/` dir has no archive to judge the
/// installed copy by. The hosted unwind judges it by the pin's patch record
/// instead, as the scan does in that home, and puts the upstream gem back:
/// otherwise the app keeps loading the patch under the restored lock, and
/// no later `bundle install` changes that.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_unwind_restores_an_install_whose_home_cache_was_pruned() {
    for command in HOSTED_UNWINDS {
        let server = MockServer::start().await;
        let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
        mount_api_for(&server, None, &sha256_of(&patched)).await;
        serve_patched_gem(&server, patched.clone()).await;
        serve_upstream_gem(&server, &upstream).await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, home) = hosted_with_pruned_home_cache(&server, &proj, true).await;
        let views_before = view_requests(&server).await;

        let mut args = command.to_vec();
        args.push("--json");
        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &args);
        let env: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("{command:?}: not JSON: {e}\n{stdout}\n{stderr}"));
        assert_eq!(code, 0, "{command:?}: {env}\n{stderr}");
        let lock = std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap();
        assert!(!lock.contains("/patch-registry/"), "{command:?}:\n{lock}");
        assert_eq!(
            installed_lib(&gem_dir),
            UPSTREAM_LIB,
            "{command:?}: the upstream gem is back: {env}"
        );
        assert_eq!(
            details_with_code(&env, "upstream_gem_install_refreshed").len(),
            1,
            "{command:?}: {env}"
        );
        assert!(
            details_with_code(&env, "upstream_gem_stale_install").is_empty(),
            "{command:?}: nothing is left on the patched build: {env}"
        );
        assert!(
            !home.join("cache").exists(),
            "{command:?}: a pruned cache dir is not created"
        );
        assert_eq!(
            view_requests(&server).await - views_before,
            1,
            "{command:?}: one patch record, for that pin"
        );
    }
}

/// The same in a human run: the refresh is a progress line, and the gem is
/// not counted among the packages that keep their patched bytes.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_unwind_reports_the_pruned_home_refresh_in_a_human_run() {
    let server = MockServer::start().await;
    let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    serve_upstream_gem(&server, &upstream).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    let (gem_dir, _) = hosted_with_pruned_home_cache(&server, &proj, true).await;

    // A dry run says what it would do and changes nothing.
    let would = format!(
        "Would replace the installed copy of 1 gem with the upstream build: {DEP} {DEP_VERSION}."
    );
    let (code, stdout, stderr) =
        unwind_run(&proj, &server.uri(), &["rollback", "--yes", "--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains(&would), "{stdout}\n{stderr}");
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB);

    let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &["rollback", "--yes"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB, "{stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "Replaced the installed copy of 1 gem with the upstream build: {DEP} {DEP_VERSION}."
        )),
        "{stdout}\n{stderr}"
    );
    assert!(
        !stdout.contains("patched bytes") && !stderr.contains("still"),
        "nothing is left to reinstall:\n{stdout}\n{stderr}"
    );
}

/// #2092: when no patch record can be had for such a copy (the API fails),
/// nothing tells it from the patched build. It is left as it is and named
/// as a copy that could not be checked, with the reason and the files to
/// remove: never passed over in silence.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_unwind_names_a_pruned_home_install_no_record_can_judge() {
    let server = MockServer::start().await;
    let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
    // The view answers 500.
    mount_api_for(&server, Some(0), &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    serve_upstream_gem(&server, &upstream).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    let (gem_dir, home) = hosted_with_pruned_home_cache(&server, &proj, true).await;
    let before = snapshot(&home);
    let asked_before = server.received_requests().await.unwrap().len();

    let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &["rollback", "--yes", "--json"]);
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON: {e}\n{stdout}\n{stderr}"));
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(snapshot(&home), before, "left as it is");
    assert!(
        details_with_code(&env, "upstream_gem_install_refreshed").is_empty(),
        "{env}"
    );
    assert!(
        gem_downloads_since(&server, asked_before).await.is_empty(),
        "no gem was downloaded for a copy nothing judged"
    );
    let unchecked = details_with_code(&env, "upstream_gem_stale_install");
    assert_eq!(unchecked.len(), 1, "the copy is reported: {env}");
    let spec = home
        .join("specifications")
        .join(format!("{DEP}-{DEP_VERSION}.gemspec"));
    for needle in [
        PURL,
        "could not be checked against the upstream gem",
        "its gem home has no archive of it and its patch record could not be fetched",
        "it still holds the patched build",
        "run `bundle install`",
        gem_dir.to_str().unwrap(),
        spec.to_str().unwrap(),
    ] {
        assert!(
            unchecked[0].contains(needle),
            "missing {needle:?}: {}",
            unchecked[0]
        );
    }

    // A human run counts it apart, in one warning.
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    hosted_with_pruned_home_cache(&server, &proj, true).await;
    let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &["rollback", "--yes"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stderr.contains("1 gem on disk could not be checked")
            && stderr.contains("its patch record could not be fetched"),
        "{stdout}\n{stderr}"
    );
}

/// #2092 where nothing proves the upstream gem's sha256 (a lock without
/// `CHECKSUMS`, with `--offline` or a registry that does not answer): the
/// copy cannot be replaced, but it is not passed over. Offline no record is
/// fetched and the copy is named as one that could not be checked; with the
/// API in reach the record proves it patched and it is named as stale.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_unwind_names_a_pruned_home_install_with_no_upstream_sha256() {
    for (offline, needles) in [
        (
            true,
            [
                "could not be checked against the upstream gem",
                "`--offline` is set, so its patch record was not fetched",
            ],
        ),
        (
            false,
            [
                "its patched install at",
                "nothing pins the sha256 of the upstream gem",
            ],
        ),
    ] {
        let server = MockServer::start().await;
        let patched = real_gem(PATCHED_LIB);
        mount_api_for(&server, None, &sha256_of(&patched)).await;
        serve_patched_gem(&server, patched.clone()).await;
        // No rubygems.org stand-in: the compact index is a 404.
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, home) = hosted_with_pruned_home_cache(&server, &proj, true).await;
        let before = snapshot(&home);
        let views_before = view_requests(&server).await;

        let mut args = vec!["rollback", "--yes", "--json"];
        if offline {
            args.push("--offline");
        }
        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &args);
        let env: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("offline={offline}: not JSON: {e}\n{stdout}\n{stderr}"));
        assert_eq!(code, 0, "offline={offline}: {env}\n{stderr}");
        assert_eq!(snapshot(&home), before, "offline={offline}: left as it is");
        let left = details_with_code(&env, "upstream_gem_stale_install");
        assert_eq!(left.len(), 1, "offline={offline}: reported: {env}");
        for needle in
            needles
                .into_iter()
                .chain([PURL, "run `bundle install`", gem_dir.to_str().unwrap()])
        {
            assert!(
                left[0].contains(needle),
                "offline={offline}: missing {needle:?}: {}",
                left[0]
            );
        }
        assert_eq!(
            view_requests(&server).await - views_before,
            usize::from(!offline),
            "offline={offline}: an offline run fetches no record"
        );
    }
}

/// The record judges, it does not assume: an installed copy that is still
/// the upstream gem (the scan was told not to refresh it) is left alone in
/// a home with no `cache/` dir too, with no warning and no gem download.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_unwind_leaves_an_upstream_install_in_a_pruned_home_alone() {
    let server = MockServer::start().await;
    let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    serve_upstream_gem(&server, &upstream).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    let (_, home) = hosted_with_pruned_home_cache(&server, &proj, false).await;
    let before = snapshot(&home);
    let asked_before = server.received_requests().await.unwrap().len();

    let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &["rollback", "--yes", "--json"]);
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON: {e}\n{stdout}\n{stderr}"));
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert_eq!(snapshot(&home), before, "nothing changed");
    assert!(
        details_with_code(&env, "upstream_gem_install_refreshed").is_empty()
            && details_with_code(&env, "upstream_gem_stale_install").is_empty(),
        "{env}"
    );
    assert!(
        gem_downloads_since(&server, asked_before).await.is_empty(),
        "no gem was downloaded"
    );
}

/// A project whose `Gemfile` names a private gem mirror as its source
/// (`source "<mirror>"`), so the lock resolves the gem from that remote,
/// with the gem installed from it. `checksum` is the sha256 the lock's
/// `CHECKSUMS` section pins for the gem (Bundler 2.6 and later); `None`
/// writes a lock without the section. Returns the installed gem dir.
fn mirror_project(proj: &Path, mirror: &str, checksum: Option<&str>) -> PathBuf {
    std::fs::create_dir_all(proj).unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        format!("source \"{mirror}\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n"),
    )
    .unwrap();
    let checksums = checksum
        .map(|sha| format!("CHECKSUMS\n  {DEP} ({DEP_VERSION}) sha256={sha}\n\n"))
        .unwrap_or_default();
    std::fs::write(
        proj.join("Gemfile.lock"),
        format!(
            "GEM\n  remote: {mirror}/\n  specs:\n    {DEP} ({DEP_VERSION})\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  {DEP} (= {DEP_VERSION})\n\n\
             {checksums}BUNDLED WITH\n   2.6.9\n"
        ),
    )
    .unwrap();
    install_real_gem(&project_home(proj), UPSTREAM_LIB)
}

/// #2230: a hosted gem the lock resolves from a private mirror, under a
/// lock without `CHECKSUMS`. The unwind restores the pair, and nothing
/// gives the upstream gem's sha256, so the patched archive in the gem home
/// says nothing about the installed copy. The copy is judged by the pin's
/// patch record like one with no archive: the patched build the scan put
/// there is named with the files to remove (`bundle install` and `bundle
/// pristine` keep it otherwise), and offline it is named as a copy that
/// could not be checked. Neither is passed over in silence.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_unwind_names_a_patched_install_from_a_mirror_without_checksums() {
    const MIRROR: &str = "https://gems.example.test";
    for (offline, needles) in [
        (false, ["its patched install at", "run `bundle install`"]),
        (
            true,
            [
                "could not be checked against the upstream gem",
                "nothing gives the sha256 of its upstream gem and `--offline` is set, so its \
                 patch record was not fetched",
            ],
        ),
    ] {
        let server = MockServer::start().await;
        let patched = real_gem(PATCHED_LIB);
        mount_api_for(&server, None, &sha256_of(&patched)).await;
        serve_patched_gem(&server, patched.clone()).await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let gem_dir = mirror_project(&proj, MIRROR, None);
        // The project commits its bundler cache.
        let committed = proj
            .join("vendor")
            .join("cache")
            .join(format!("{DEP}-{DEP_VERSION}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        std::fs::write(&committed, real_gem(UPSTREAM_LIB)).unwrap();
        let pair = |name: &str| std::fs::read_to_string(proj.join(name)).unwrap();
        let (gemfile, lock) = (pair("Gemfile"), pair("Gemfile.lock"));
        let uri = server.uri();
        let (code, _, stderr) =
            common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
        assert_eq!(code, 0, "{stderr}");
        assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "premise: refreshed");
        let home = project_home(&proj);
        let before = snapshot(&home);
        let asked_before = server.received_requests().await.unwrap().len();

        let mut args = vec!["rollback", "--yes", "--json"];
        if offline {
            args.push("--offline");
        }
        let (code, stdout, stderr) = unwind_run(&proj, &uri, &args);
        let env: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("offline={offline}: not JSON: {e}\n{stdout}\n{stderr}"));
        assert_eq!(code, 0, "offline={offline}: {env}\n{stderr}");
        assert_eq!(pair("Gemfile"), gemfile, "offline={offline}");
        assert_eq!(pair("Gemfile.lock"), lock, "offline={offline}");
        assert_eq!(snapshot(&home), before, "offline={offline}: left as it is");
        let left = details_with_code(&env, "upstream_gem_stale_install");
        assert_eq!(left.len(), 1, "offline={offline}: reported: {env}");
        for needle in needles.into_iter().chain([PURL, gem_dir.to_str().unwrap()]) {
            assert!(
                left[0].contains(needle),
                "offline={offline}: missing {needle:?}: {}",
                left[0]
            );
        }
        // The archive in Bundler's cache dir is named too, as one nothing
        // could check: the registry is not asked about another remote's gem.
        let cached = details_with_code(&env, "upstream_gem_stale_cache");
        assert_eq!(cached.len(), 1, "offline={offline}: {env}");
        assert!(
            cached[0].contains(committed.to_str().unwrap())
                && cached[0].contains("could not be checked against the upstream sha256"),
            "offline={offline}: {}",
            cached[0]
        );
        let asked_registry = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .skip(asked_before)
            .any(|request| request.url.path().starts_with("/upstream/"));
        assert!(
            !asked_registry,
            "offline={offline}: rubygems.org is not asked about another remote's gem"
        );
    }
}

/// The record judges, it does not assume (#2230): an installed copy from a
/// private mirror that is still the upstream gem (the scan was told not to
/// refresh it) gets no warning after the unwind.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_unwind_leaves_an_upstream_install_from_a_mirror_alone() {
    let server = MockServer::start().await;
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    let gem_dir = mirror_project(&proj, "https://gems.example.test", None);
    let uri = server.uri();
    let flags = ["--json", "--no-gem-install-refresh"];
    let (code, _, stderr) = common::run_with_env(&proj, &scan_args(&proj, &uri, &flags), &[]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB, "premise");

    let (code, stdout, stderr) = unwind_run(&proj, &uri, &["rollback", "--yes", "--json"]);
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("not JSON: {e}\n{stdout}\n{stderr}"));
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert!(
        details_with_code(&env, "upstream_gem_stale_install").is_empty(),
        "{env}"
    );
}

/// #2230: on a lock with `CHECKSUMS`, a hosted gem from a private mirror
/// can be unwound. The restore reads the gem's upstream sha256 from the
/// mirror's own compact index when `SOCKET_RUBYGEMS_URL` names that
/// server: the pair is the pre-scan pair byte for byte and the installed
/// copy is the upstream gem again. Without the setting the unwind refuses,
/// changes nothing and names the setting.
#[tokio::test(flavor = "multi_thread")]
async fn hosted_unwind_restores_a_mirror_gem_when_the_registry_setting_names_the_mirror() {
    for command in HOSTED_UNWINDS {
        let server = MockServer::start().await;
        let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
        mount_api_for(&server, None, &sha256_of(&patched)).await;
        serve_patched_gem(&server, patched.clone()).await;
        // The mirror: the mock's `/upstream` tree.
        serve_upstream_gem(&server, &upstream).await;
        let uri = server.uri();
        let mirror = format!("{uri}/upstream");
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let gem_dir = mirror_project(&proj, &mirror, Some(&sha256_of(&upstream)));
        let pair = |name: &str| std::fs::read_to_string(proj.join(name)).unwrap();
        let (gemfile, lock) = (pair("Gemfile"), pair("Gemfile.lock"));
        let (code, _, stderr) =
            common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
        assert_eq!(code, 0, "{stderr}");
        assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "premise: refreshed");
        let (hosted_gemfile, hosted_lock) = (pair("Gemfile"), pair("Gemfile.lock"));
        assert!(hosted_lock.contains("/patch-registry/"), "{hosted_lock}");

        // rubygems.org (here: another stand-in) is not the lock's remote.
        let mut args = command.to_vec();
        args.push("--json");
        let elsewhere = format!("{uri}/elsewhere");
        let (code, stdout, stderr) = unwind_run_with_registry(&proj, &uri, &args, &elsewhere);
        assert_ne!(code, 0, "{command:?}: {stdout}\n{stderr}");
        let said = format!("{stdout}\n{stderr}");
        for needle in [
            "is not rubygems.org",
            &format!("`SOCKET_RUBYGEMS_URL={mirror}`"),
            "git checkout -- Gemfile Gemfile.lock",
        ] {
            assert!(
                said.contains(needle),
                "{command:?}: missing {needle:?}: {said}"
            );
        }
        assert_eq!(pair("Gemfile"), hosted_gemfile, "{command:?}: refused");
        assert_eq!(pair("Gemfile.lock"), hosted_lock, "{command:?}: refused");
        assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "{command:?}: refused");

        // The setting names the mirror: the remedy the refusal gave.
        let (code, stdout, stderr) = unwind_run_with_registry(&proj, &uri, &args, &mirror);
        let env: serde_json::Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("{command:?}: not JSON: {e}\n{stdout}\n{stderr}"));
        assert_eq!(code, 0, "{command:?}: {env}\n{stderr}");
        assert_eq!(pair("Gemfile"), gemfile, "{command:?}");
        assert_eq!(pair("Gemfile.lock"), lock, "{command:?}");
        assert_eq!(
            installed_lib(&gem_dir),
            UPSTREAM_LIB,
            "{command:?}: the upstream gem is back: {env}"
        );
        assert!(
            details_with_code(&env, "upstream_gem_stale_install").is_empty(),
            "{command:?}: nothing is left on the patched build: {env}"
        );
    }
}

/// The vendored half of the patch API for the fixture's patch: the grant
/// names the patched `.gem` and the stub gemspec a path source loads, each
/// with its sha512, beside the hosted registry override. Priority 1, so it
/// answers `patches/package` in place of [`mount_api_for`]'s hosted-only
/// grant.
async fn mount_vendored_grant(server: &MockServer, patched: &[u8]) {
    mount_vendored_grant_of(server, UUID, patched).await;
}

/// [`mount_vendored_grant`] for the patch `uuid`.
async fn mount_vendored_grant_of(server: &MockServer, uuid: &str, patched: &[u8]) {
    use base64::Engine as _;
    use sha2::Digest as _;
    let sri = |bytes: &[u8]| {
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
        )
    };
    let stub = format!(
        "Gem::Specification.new do |s|\n  s.name = \"{DEP}\".freeze\n  s.version = \
         \"{DEP_VERSION}\".freeze\n  s.authors = [\"e2e\".freeze]\n  s.summary = \
         \"fixture\".freeze\n  s.files = [\"lib/stale_probe_gem.rb\".freeze]\n  s.require_paths \
         = [\"lib\".freeze]\nend\n"
    )
    .into_bytes();
    let leaf = format!("{DEP}-{DEP_VERSION}");
    let base = format!("/artifacts/{uuid}");
    let gem_url = format!("{}{base}/{leaf}.gem", server.uri());
    let stub_url = format!("{}{base}/{leaf}.gemspec", server.uri());
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                uuid: {
                    "status": "granted",
                    "url": gem_url,
                    "purl": PURL,
                    "artifacts": [
                        { "kind": "tarball", "url": gem_url,
                          "integrity": { "sha512": sri(patched), "sha256": sha256_of(patched) } },
                        { "kind": "gem-stub-gemspec", "url": stub_url,
                          "integrity": { "sha512": sri(&stub) } }
                    ],
                    "registryOverride": {
                        "kind": "rubygems-compact-index",
                        "indexUrl": format!("{}/patch-registry/gem/{TOKEN}/{uuid}/", server.uri()),
                        "identifiers": {
                            "name": DEP,
                            "version": DEP_VERSION,
                            "gemChecksumSha256": sha256_of(patched),
                        }
                    }
                }
            }
        })))
        .with_priority(1)
        .mount(server)
        .await;
    for (file, bytes) in [
        (format!("{leaf}.gem"), patched.to_vec()),
        (format!("{leaf}.gemspec"), stub),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("{base}/{file}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
            .mount(server)
            .await;
    }
}

/// Every regular file under `dir`, relative, with its bytes.
fn snapshot(dir: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

/// A hosted → vendored takeover (`get --mode vendored`, `scan --mode
/// vendored`, and plain `vendor`, which ejects the lock's hosted pins) puts
/// the gem back on its upstream entry only on its way to the `path:`
/// source, which is what Bundler loads from then on. The gems
/// Bundler already holds are unused leftovers: the takeover must not
/// refresh them (the patched installed copy would become an unpatched one
/// that `vex` then reports against the vendored artifact) and must download
/// no gem for them (vendored mode needs no registry). The installed gem,
/// its cached archive and the cache-dir archive stay byte-identical, and
/// the takeover's own advisory about the cache-dir archive is unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_is_not_run_by_a_hosted_to_vendored_takeover() {
    let takeovers: [&[&str]; 3] = [
        &["get", UUID, "--mode", "vendored"],
        &["scan", "--mode", "vendored"],
        &["vendor"],
    ];
    for takeover in takeovers {
        let server = MockServer::start().await;
        let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
        mount_api_for(&server, None, &sha256_of(&patched)).await;
        serve_patched_gem(&server, patched.clone()).await;
        // Everything a refresh back to upstream would need is there to use.
        serve_upstream_gem(&server, &upstream).await;
        mount_vendored_grant(&server, &patched).await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        let home = project_home(&proj);
        let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
        let leaf = format!("{DEP}-{DEP_VERSION}");
        let committed = proj
            .join("vendor")
            .join("cache")
            .join(format!("{leaf}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        std::fs::write(&committed, &upstream).unwrap();

        // The hosted state: the scan pins the gem and refreshes the
        // project's copies; the lock is then as `bundle install` leaves it.
        let uri = server.uri();
        let (code, _, stderr) =
            common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
        assert_eq!(code, 0, "{takeover:?}: hosted scan:\n{stderr}");
        std::fs::write(proj.join("Gemfile.lock"), converged_lock(&uri)).unwrap();
        assert_eq!(
            installed_lib(&gem_dir),
            PATCHED_LIB,
            "{takeover:?}: premise"
        );
        assert_eq!(
            std::fs::read(&committed).unwrap(),
            patched,
            "{takeover:?}: premise"
        );
        let held_before = (snapshot(&home), snapshot(committed.parent().unwrap()));
        let requests_before = server.received_requests().await.unwrap_or_default().len();

        let rubygems = format!("{uri}/upstream");
        let mut args = takeover.to_vec();
        args.extend([
            "--yes",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            uri.as_str(),
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            uri.as_str(),
        ]);
        let (code, stdout, stderr) =
            common::run_with_env(&proj, &args, &[("SOCKET_RUBYGEMS_URL", rubygems.as_str())]);
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "{takeover:?}: {env}\nstderr:\n{stderr}");
        let gemfile = std::fs::read_to_string(proj.join("Gemfile")).unwrap();
        assert!(
            gemfile.contains(".socket/vendor/gem/") && !gemfile.contains("/patch-registry/"),
            "{takeover:?}: the takeover vendored the gem:\n{gemfile}"
        );

        assert!(
            (snapshot(&home), snapshot(committed.parent().unwrap())) == held_before,
            "{takeover:?}: the takeover changed a gem Bundler already held: {env}"
        );
        let fetched: Vec<String> = server.received_requests().await.unwrap_or_default()
            [requests_before..]
            .iter()
            .map(|r| r.url.path().to_string())
            .filter(|path| path.contains("/gems/"))
            .collect();
        assert!(
            fetched.is_empty(),
            "{takeover:?}: the takeover downloaded a gem for the installed copies: {fetched:?}"
        );
        let text = env.to_string();
        for code in [
            "upstream_gem_install_refreshed",
            "upstream_gem_stale_install",
            "redirect_gem_install_refreshed",
            "redirect_gem_stale_install",
        ] {
            assert!(!text.contains(code), "{takeover:?}: {code} in {env}");
        }
        // The takeover's own advisory about the patched cache-dir archive,
        // as it always was: the per-package takeover's event says the
        // vendored copy shadows it for now, the eject passes on its
        // restore's warning.
        let archive = committed.display().to_string();
        if takeover == ["vendor"] {
            let details = warnings_with_code(&env, "upstream_gem_stale_cache");
            assert!(
                details.len() == 1 && details[0].contains(&archive),
                "{takeover:?}: the eject names the archive: {env}"
            );
        } else {
            let notice = env["events"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|e| e["errorCode"] == "upstream_gem_stale_cache")
                .unwrap_or_else(|| panic!("{takeover:?}: the takeover names the archive: {env}"));
            assert!(
                notice["reason"].as_str().is_some_and(|r| {
                    r.contains("while the gem stays vendored") && r.contains(&archive)
                }),
                "{takeover:?}: {notice}"
            );
        }
    }
}

/// A project whose gem went hosted, then vendored: the hosted scan
/// replaced the project's installed copy and its gem-home archive with the
/// patched build, and the takeover (`scan --mode vendored`) left them
/// alone. Returns the installed gem dir and that archive.
async fn hosted_then_vendored(server: &MockServer, proj: &Path) -> (PathBuf, PathBuf) {
    let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
    mount_api_for(server, None, &sha256_of(&patched)).await;
    serve_patched_gem(server, patched.clone()).await;
    serve_upstream_gem(server, &upstream).await;
    mount_vendored_grant(server, &patched).await;
    std::fs::create_dir_all(proj).unwrap();
    write_manifest_pair(proj);
    let home = project_home(proj);
    let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
    let archive = home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem"));

    let uri = server.uri();
    let (code, _, stderr) = common::run_with_env(proj, &scan_args(proj, &uri, &["--json"]), &[]);
    assert_eq!(code, 0, "hosted scan:\n{stderr}");
    std::fs::write(proj.join("Gemfile.lock"), converged_lock(&uri)).unwrap();
    let (code, stdout, stderr) = unwind_run(
        proj,
        &uri,
        &["scan", "--mode", "vendored", "--yes", "--json"],
    );
    assert_eq!(code, 0, "takeover:\n{stdout}\n{stderr}");
    let gemfile = std::fs::read_to_string(proj.join("Gemfile")).unwrap();
    assert!(
        gemfile.contains(".socket/vendor/gem/"),
        "premise:\n{gemfile}"
    );
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "premise");
    assert_eq!(std::fs::read(&archive).unwrap(), patched, "premise");
    (gem_dir, archive)
}

/// Run `args` in `proj` against the mock API, with rubygems.org's stand-in.
fn unwind_run(proj: &Path, uri: &str, args: &[&str]) -> (i32, String, String) {
    unwind_run_with_registry(proj, uri, args, &format!("{uri}/upstream"))
}

/// [`unwind_run`], with `rubygems` as the gem registry (`SOCKET_RUBYGEMS_URL`).
fn unwind_run_with_registry(
    proj: &Path,
    uri: &str,
    args: &[&str],
    rubygems: &str,
) -> (i32, String, String) {
    let mut args = args.to_vec();
    args.extend([
        "--cwd",
        proj.to_str().unwrap(),
        "--api-url",
        uri,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--patch-server-url",
        uri,
    ]);
    common::run_with_env(proj, &args, &[("SOCKET_RUBYGEMS_URL", rubygems)])
}

/// The commands that unwind a vendored gem.
const VENDORED_UNWINDS: [&[&str]; 3] = [
    &["rollback", "--yes"],
    &["remove", PURL, "--yes"],
    &["vendor", "--revert", "--yes"],
];

/// #2083: once a vendored gem is unwound, Bundler loads the installed copy
/// again. If a hosted scan made that copy the patched build before the
/// gem was vendored, the unwind puts the upstream gem back, as the hosted
/// unwind does: otherwise the app keeps running the patch under an
/// upstream lock, and `bundle pristine` fails on the upstream checksum.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_restores_an_install_a_hosted_scan_patched() {
    for unwind in VENDORED_UNWINDS {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, archive) = hosted_then_vendored(&server, &proj).await;

        let mut args = unwind.to_vec();
        args.push("--json");
        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &args);
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "{unwind:?}: {env}\nstderr:\n{stderr}");
        let pair = format!(
            "{}{}",
            std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
            std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap()
        );
        assert!(
            !pair.contains(".socket/vendor/") && !pair.contains("/patch-registry/"),
            "{unwind:?}: the gem is back on its upstream entry:\n{pair}"
        );
        assert_eq!(
            installed_lib(&gem_dir),
            UPSTREAM_LIB,
            "{unwind:?}: the installed copy is the upstream build again: {env}"
        );
        assert_eq!(
            std::fs::read(&archive).unwrap(),
            real_gem(UPSTREAM_LIB),
            "{unwind:?}: so is the archive `bundle pristine` reinstalls from: {env}"
        );
        let text = env.to_string();
        assert!(
            text.contains("upstream_gem_install_refreshed")
                && !text.contains("upstream_gem_stale_install"),
            "{unwind:?}: {env}"
        );
        // Nothing of the gem is left on its patched build (#2214).
        assert!(
            details_with_code(&env, "reinstall_required").is_empty(),
            "{unwind:?}: {env}"
        );
    }
}

/// The human run says what it replaced, after its own line for the gem,
/// and rollback's "keeps its patched bytes" note no longer counts the gem.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_reports_the_refresh_in_a_human_run() {
    let own_lines = [
        format!("Reverted vendoring for {PURL}"),
        format!("Reverted vendoring for {PURL}"),
        "Reverted 1 vendored package".to_string(),
    ];
    for (unwind, own_line) in VENDORED_UNWINDS.into_iter().zip(own_lines) {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, _) = hosted_then_vendored(&server, &proj).await;

        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), unwind);
        assert_eq!(code, 0, "{unwind:?}: {stdout}\n{stderr}");
        assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB, "{unwind:?}");
        let replaced = format!(
            "Replaced the installed copy of 1 gem with the upstream build: {DEP} {DEP_VERSION}."
        );
        assert_eq!(stdout.matches(&replaced).count(), 1, "{unwind:?}: {stdout}");
        assert!(stdout.contains(&own_line), "{unwind:?}: {stdout}");
        if unwind[0] != "vendor" {
            assert!(
                stdout.find(&own_line) < stdout.find(&replaced),
                "{unwind:?}: {stdout}"
            );
        }
        assert!(
            !stdout.contains("patched bytes in installed trees")
                && !stderr.contains("upstream_gem")
                && !stderr.contains("Warning:"),
            "{unwind:?}: nothing is left to warn about:\n{stdout}\n{stderr}"
        );
    }
}

/// A copy the unwind may not or cannot refresh is left exactly as it was
/// and named with a remedy that works: `--no-gem-install-refresh`, and an
/// upstream gem that cannot be downloaded.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_names_an_install_it_leaves_on_the_patched_build() {
    for (unwind, opt_out) in VENDORED_UNWINDS
        .into_iter()
        .flat_map(|unwind| [(unwind, true), (unwind, false)])
    {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, archive) = hosted_then_vendored(&server, &proj).await;
        let home = project_home(&proj);
        let held_before = snapshot(&home);
        if !opt_out {
            // rubygems.org names the upstream sha256 but its download fails.
            Mock::given(method("GET"))
                .and(path(format!("/upstream/gems/{DEP}-{DEP_VERSION}.gem")))
                .respond_with(ResponseTemplate::new(503))
                .with_priority(1)
                .mount(&server)
                .await;
        }

        let mut args = unwind.to_vec();
        args.push("--json");
        if opt_out {
            args.push("--no-gem-install-refresh");
        }
        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &args);
        let env = common::parse_json_envelope(&stdout);
        let case = format!("{unwind:?} opt_out={opt_out}");
        assert_eq!(code, 0, "{case}: {env}\nstderr:\n{stderr}");
        assert!(
            snapshot(&home) == held_before,
            "{case}: the gem home changed: {env}"
        );
        let text = env.to_string();
        let spec = home
            .join("specifications")
            .join(format!("{DEP}-{DEP_VERSION}.gemspec"));
        for needle in [
            "upstream_gem_stale_install",
            gem_dir.to_str().unwrap(),
            spec.to_str().unwrap(),
            archive.to_str().unwrap(),
            "bundle install",
        ] {
            // The envelope JSON-escapes a Windows path's backslashes.
            let needle = needle.replace('\\', "\\\\");
            assert!(text.contains(&needle), "{case}: no {needle:?} in {env}");
        }
        assert!(
            !text.contains("upstream_gem_install_refreshed"),
            "{case}: {env}"
        );
    }
}

/// The human run of the same: one warning with the remedy as a command,
/// and rollback's reinstall note still counts the gem.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_warns_once_in_a_human_run() {
    for unwind in VENDORED_UNWINDS {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, archive) = hosted_then_vendored(&server, &proj).await;

        let mut args = unwind.to_vec();
        args.push("--no-gem-install-refresh");
        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &args);
        assert_eq!(code, 0, "{unwind:?}: {stdout}\n{stderr}");
        assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "{unwind:?}");
        let warning = "Warning: 1 gem still holds the patched build on disk after the switch \
                       back to the upstream registry";
        assert_eq!(stderr.matches(warning).count(), 1, "{unwind:?}: {stderr}");
        assert!(
            stderr.contains(&format!(
                "rm -f {}",
                shell_word(
                    &project_home(&proj)
                        .join("specifications")
                        .join(format!("{DEP}-{DEP_VERSION}.gemspec"))
                )
            )) && stderr.contains(&format!("{} && bundle install", shell_word(&archive))),
            "{unwind:?}: {stderr}"
        );
        assert!(
            !stderr.contains("Re-run"),
            "{unwind:?}: a second unwind has nothing to unwind: {stderr}"
        );
        assert!(!stdout.contains("Replaced the installed copy"), "{stdout}");
        if unwind[0] == "rollback" {
            assert!(
                stdout.contains("1 unwired package keeps its patched bytes"),
                "{stdout}"
            );
        }
    }
}

/// A registry that is refused (plain http, and not this machine) is not
/// asked what the upstream gem is, in a vendored unwind as in a hosted one:
/// the installed copy is left exactly as it was and reported as one that
/// could not be checked, with the reason, not passed over while it still
/// holds the patched build.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_reports_the_copy_a_refused_registry_left_unchecked() {
    for unwind in VENDORED_UNWINDS {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, _) = hosted_then_vendored(&server, &proj).await;
        let home = project_home(&proj);
        let held_before = snapshot(&home);
        let asked_before = server.received_requests().await.unwrap().len();

        let mut args = unwind.to_vec();
        args.push("--json");
        // Refused before any request: nothing is looked up or sent.
        let (code, stdout, stderr) = unwind_run_with_registry(
            &proj,
            &server.uri(),
            &args,
            "http://gemstash.example.test:9292",
        );
        let env = common::parse_json_envelope(&stdout);
        let case = format!("{unwind:?}");
        assert_eq!(code, 0, "{case}: {env}\nstderr:\n{stderr}");
        assert!(
            snapshot(&home) == held_before,
            "{case}: the gem home changed: {env}"
        );
        let text = env.to_string();
        for needle in [
            "upstream_gem_stale_install",
            "could not be checked against the upstream gem",
            "`http://gemstash.example.test:9292` is not an https URL",
            "set it to an https URL",
            gem_dir.to_str().unwrap(),
        ] {
            // The envelope JSON-escapes a Windows path's backslashes.
            let needle = needle.replace('\\', "\\\\");
            assert!(text.contains(&needle), "{case}: no {needle:?} in {env}");
        }
        assert!(
            !text.contains("upstream_gem_install_refreshed"),
            "{case}: {env}"
        );
        let upstream_asked = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .skip(asked_before)
            .any(|request| request.url.path().starts_with("/upstream/"));
        assert!(!upstream_asked, "{case}: the unwind asked a registry");
    }
}

/// A gem that was only ever vendored still has the upstream build
/// installed: its unwind changes nothing in the gem home, downloads no
/// gem and raises nothing about it.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_leaves_an_upstream_install_alone() {
    for unwind in VENDORED_UNWINDS {
        let server = MockServer::start().await;
        let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
        mount_api_for(&server, None, &sha256_of(&patched)).await;
        serve_upstream_gem(&server, &upstream).await;
        mount_vendored_grant(&server, &patched).await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        let home = project_home(&proj);
        install_real_gem(&home, UPSTREAM_LIB);
        let uri = server.uri();
        let (code, stdout, stderr) = unwind_run(
            &proj,
            &uri,
            &["scan", "--mode", "vendored", "--yes", "--json"],
        );
        assert_eq!(code, 0, "vendored scan:\n{stdout}\n{stderr}");
        let held_before = snapshot(&home);
        let requests_before = server.received_requests().await.unwrap_or_default().len();

        let mut args = unwind.to_vec();
        args.push("--json");
        let (code, stdout, stderr) = unwind_run(&proj, &uri, &args);
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "{unwind:?}: {env}\nstderr:\n{stderr}");
        assert!(
            snapshot(&home) == held_before,
            "{unwind:?}: the gem home changed: {env}"
        );
        let fetched: Vec<String> = server.received_requests().await.unwrap_or_default()
            [requests_before..]
            .iter()
            .map(|r| r.url.path().to_string())
            .filter(|path| path.contains("/gems/"))
            .collect();
        assert!(fetched.is_empty(), "{unwind:?}: downloaded {fetched:?}");
        let text = env.to_string();
        for code in [
            "upstream_gem_install_refreshed",
            "upstream_gem_stale_install",
        ] {
            assert!(!text.contains(code), "{unwind:?}: {code} in {env}");
        }
    }
}

/// #2214: rollback's "keeps its patched bytes" note, and the
/// `reinstall_required` warning `--json` carries for it, are about the
/// installed trees. Vendored mode never touches a gem home, so a gem that
/// was only ever vendored has nothing patched there once its pair is
/// restored: its installed copy is the upstream build, which its archive
/// in the gem home and the ledger record's pre-patch hashes prove.
#[tokio::test(flavor = "multi_thread")]
async fn rollback_of_an_only_vendored_gem_names_no_reinstall() {
    for json in [true, false] {
        let case = format!("json={json}");
        let server = MockServer::start().await;
        let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
        mount_api_for(&server, None, &sha256_of(&patched)).await;
        serve_upstream_gem(&server, &upstream).await;
        mount_vendored_grant(&server, &patched).await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        write_manifest_pair(&proj);
        let pair_before = (
            std::fs::read(proj.join("Gemfile")).unwrap(),
            std::fs::read(proj.join("Gemfile.lock")).unwrap(),
        );
        let home = project_home(&proj);
        install_real_gem(&home, UPSTREAM_LIB);
        let uri = server.uri();
        let (code, stdout, stderr) = unwind_run(
            &proj,
            &uri,
            &["scan", "--mode", "vendored", "--yes", "--json"],
        );
        assert_eq!(code, 0, "{case}: vendored scan:\n{stdout}\n{stderr}");
        assert!(
            std::fs::read_to_string(proj.join("Gemfile"))
                .unwrap()
                .contains(".socket/vendor/gem/"),
            "{case}: premise: the gem is vendored"
        );
        let held_before = snapshot(&home);

        let mut args = vec!["rollback", "--yes"];
        if json {
            args.push("--json");
        }
        let (code, stdout, stderr) = unwind_run(&proj, &uri, &args);
        assert_eq!(code, 0, "{case}:\n{stdout}\n{stderr}");
        let pair_after = (
            std::fs::read(proj.join("Gemfile")).unwrap(),
            std::fs::read(proj.join("Gemfile.lock")).unwrap(),
        );
        assert!(pair_after == pair_before, "{case}: the pair is restored");
        assert!(
            snapshot(&home) == held_before,
            "{case}: the gem home is untouched"
        );
        if json {
            let env = common::parse_json_envelope(&stdout);
            assert_eq!(env["status"], "success", "{case}: {env}");
            assert!(
                details_with_code(&env, "reinstall_required").is_empty(),
                "{case}: no installed tree holds patched bytes: {env}"
            );
        } else {
            assert!(
                stdout.contains(&format!("Reverted vendoring for {PURL}")),
                "{case}:\n{stdout}"
            );
            assert!(
                !stdout.contains("patched bytes in installed trees")
                    && !stderr.contains("Warning:"),
                "{case}: nothing is left to reinstall:\n{stdout}\n{stderr}"
            );
        }
    }
}

/// The other side of #2214: an installed copy the unwind could not prove
/// to be the upstream build is still counted. Here agent mode patched the
/// copy before the gem was vendored, and the gem comes from a remote the
/// unwind does not judge, so the patched files stay.
#[tokio::test(flavor = "multi_thread")]
async fn rollback_still_names_a_reinstall_for_an_install_it_could_not_judge() {
    for json in [true, false] {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, _) =
            agent_then_vendored_from(&server, &proj, "https://gems.example.test").await;

        let mut args = vec!["rollback", "--yes"];
        if json {
            args.push("--json");
        }
        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &args);
        assert_eq!(code, 0, "json={json}:\n{stdout}\n{stderr}");
        assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "json={json}: premise");
        if json {
            let env = common::parse_json_envelope(&stdout);
            assert_eq!(
                details_with_code(&env, "reinstall_required").len(),
                1,
                "{env}"
            );
        } else {
            assert!(
                stdout.contains("1 unwired package keeps its patched bytes in installed trees"),
                "{stdout}\n{stderr}"
            );
        }
    }
}

/// #2214, a copy the gem home's archive alone would call upstream: agent
/// mode patched it in place, beside the upstream archive, and standalone
/// `vendor` then vendored the gem from the manifest. Rollback may only
/// drop its reinstall warning when the installed copy no longer holds the
/// patched file.
#[tokio::test(flavor = "multi_thread")]
async fn rollback_never_calls_an_agent_patched_install_upstream() {
    let server = MockServer::start().await;
    let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_upstream_gem(&server, &upstream).await;
    mount_vendored_grant(&server, &patched).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = project_home(&proj);
    let gem_dir = agent_patched_install(&proj, &home);
    let uri = server.uri();
    let (code, stdout, stderr) = unwind_run(&proj, &uri, &["vendor", "--yes", "--json"]);
    assert_eq!(code, 0, "vendor:\n{stdout}\n{stderr}");
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "premise");
    assert_eq!(
        std::fs::read(home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem"))).unwrap(),
        upstream,
        "premise: the archive beside it is the upstream one"
    );

    let (code, stdout, stderr) = unwind_run(&proj, &uri, &["rollback", "--yes", "--json"]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert_eq!(
        installed_lib(&gem_dir),
        PATCHED_LIB,
        "premise: this rollback leaves the installed copy patched: {env}"
    );
    assert_eq!(
        details_with_code(&env, "reinstall_required").len(),
        1,
        "the copy is left patched, so the warning stays: {env}"
    );
}

/// A project whose gem agent mode patched in place and a vendored scan
/// then took over: the takeover moved the manifest record into the vendor
/// ledger and left the installed copy (patched files, upstream archive in
/// the gem home's `cache/`) alone. Returns the installed gem dir and that
/// archive.
async fn agent_then_vendored(server: &MockServer, proj: &Path) -> (PathBuf, PathBuf) {
    agent_then_vendored_from(server, proj, "https://rubygems.org").await
}

/// [`agent_then_vendored`], with `remote` as the pair's gem source.
async fn agent_then_vendored_from(
    server: &MockServer,
    proj: &Path,
    remote: &str,
) -> (PathBuf, PathBuf) {
    let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
    mount_api_for(server, None, &sha256_of(&patched)).await;
    serve_upstream_gem(server, &upstream).await;
    mount_vendored_grant(server, &patched).await;
    std::fs::create_dir_all(proj).unwrap();
    write_manifest_pair(proj);
    for file in ["Gemfile", "Gemfile.lock"] {
        let text = std::fs::read_to_string(proj.join(file)).unwrap();
        assert!(text.contains("https://rubygems.org"), "premise: {text}");
        std::fs::write(
            proj.join(file),
            text.replace("https://rubygems.org", remote),
        )
        .unwrap();
    }
    let home = project_home(proj);
    let gem_dir = agent_patched_install(proj, &home);
    let archive = home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem"));

    let uri = server.uri();
    let (code, stdout, stderr) = unwind_run(
        proj,
        &uri,
        &["scan", "--mode", "vendored", "--yes", "--json"],
    );
    assert_eq!(code, 0, "takeover:\n{stdout}\n{stderr}");
    let gemfile = std::fs::read_to_string(proj.join("Gemfile")).unwrap();
    assert!(
        gemfile.contains(".socket/vendor/gem/"),
        "premise:\n{gemfile}"
    );
    let manifest = std::fs::read_to_string(proj.join(".socket").join("manifest.json")).unwrap();
    assert!(
        stdout.contains("vendor_manifest_record_migrated") && !manifest.contains(PURL),
        "premise: the takeover owns the record now:\n{stdout}\n{manifest}"
    );
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "premise");
    assert_eq!(std::fs::read(&archive).unwrap(), upstream, "premise");
    (gem_dir, archive)
}

/// The gem downloads (`/gems/<leaf>.gem`, from any registry) among the
/// requests `server` received after the first `skip`.
async fn gem_downloads_since(server: &MockServer, skip: usize) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .skip(skip)
        .map(|request| request.url.path().to_string())
        .filter(|path| path.contains("/gems/"))
        .collect()
}

/// #2093: a vendored takeover of a gem agent mode patched in place drops
/// the manifest record and keeps the patched files in the installed copy.
/// Once the vendored gem is unwound Bundler loads that copy again, and no
/// record is left that could undo the patch. The unwind therefore puts
/// the upstream gem back, from the upstream archive RubyGems kept in the
/// gem home (nothing is downloaded), and leaves nothing of agent mode's
/// in the gem dir.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_restores_an_install_agent_mode_patched() {
    for unwind in VENDORED_UNWINDS {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, archive) = agent_then_vendored(&server, &proj).await;
        let asked_before = server.received_requests().await.unwrap().len();

        let mut args = unwind.to_vec();
        args.push("--json");
        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &args);
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "{unwind:?}: {env}\nstderr:\n{stderr}");
        let pair = format!(
            "{}{}",
            std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
            std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap()
        );
        assert!(
            !pair.contains(".socket/vendor/"),
            "{unwind:?}: the gem is back on its upstream entry:\n{pair}"
        );
        assert_eq!(
            installed_lib(&gem_dir),
            UPSTREAM_LIB,
            "{unwind:?}: the installed copy is the upstream build again: {env}"
        );
        assert!(
            !gem_dir.join(".socket-patch-kept").exists(),
            "{unwind:?}: the copy is a fresh install of the upstream gem: {env}"
        );
        assert_eq!(
            std::fs::read(&archive).unwrap(),
            real_gem(UPSTREAM_LIB),
            "{unwind:?}: the upstream archive is untouched: {env}"
        );
        let fetched = gem_downloads_since(&server, asked_before).await;
        assert!(fetched.is_empty(), "{unwind:?}: downloaded {fetched:?}");
        let text = env.to_string();
        assert!(
            text.contains("upstream_gem_install_refreshed")
                && !text.contains("upstream_gem_stale_install"),
            "{unwind:?}: {env}"
        );
    }
}

/// The same with the gem home's `cache/` pruned (Bundler 4.1 `prune`, a
/// Docker image's `rm -rf ruby/*/cache`): the ledger's record still proves
/// the installed files are the patched ones, so the upstream gem is
/// downloaded and installed over them.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_restores_an_agent_patched_install_without_its_archive() {
    for unwind in VENDORED_UNWINDS {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, archive) = agent_then_vendored(&server, &proj).await;
        std::fs::remove_dir_all(archive.parent().unwrap()).unwrap();
        let asked_before = server.received_requests().await.unwrap().len();

        let mut args = unwind.to_vec();
        args.push("--json");
        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &args);
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "{unwind:?}: {env}\nstderr:\n{stderr}");
        assert_eq!(
            installed_lib(&gem_dir),
            UPSTREAM_LIB,
            "{unwind:?}: the installed copy is the upstream build again: {env}"
        );
        assert_eq!(
            gem_downloads_since(&server, asked_before).await,
            [format!("/upstream/gems/{DEP}-{DEP_VERSION}.gem")],
            "{unwind:?}: one download, of the upstream gem"
        );
        let text = env.to_string();
        assert!(
            text.contains("upstream_gem_install_refreshed")
                && !text.contains("upstream_gem_stale_install"),
            "{unwind:?}: {env}"
        );
    }
}

/// An agent-patched copy the unwind may not replace
/// (`--no-gem-install-refresh`) or cannot (`--offline` with the archive
/// pruned) is left exactly as it was and named with the files to remove,
/// not passed over as if it were the upstream build.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_names_an_agent_patched_install_it_leaves() {
    for (unwind, opt_out) in VENDORED_UNWINDS
        .into_iter()
        .flat_map(|unwind| [(unwind, true), (unwind, false)])
    {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, archive) = agent_then_vendored(&server, &proj).await;
        let home = project_home(&proj);
        if !opt_out {
            std::fs::remove_dir_all(archive.parent().unwrap()).unwrap();
        }
        let held_before = snapshot(&home);

        let mut args = unwind.to_vec();
        args.push("--json");
        args.push(if opt_out {
            "--no-gem-install-refresh"
        } else {
            "--offline"
        });
        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &args);
        let env = common::parse_json_envelope(&stdout);
        let case = format!("{unwind:?} opt_out={opt_out}");
        assert_eq!(code, 0, "{case}: {env}\nstderr:\n{stderr}");
        assert!(
            snapshot(&home) == held_before,
            "{case}: the gem home changed: {env}"
        );
        let text = env.to_string();
        let spec = home
            .join("specifications")
            .join(format!("{DEP}-{DEP_VERSION}.gemspec"));
        for needle in [
            "upstream_gem_stale_install",
            gem_dir.to_str().unwrap(),
            spec.to_str().unwrap(),
            "bundle install",
        ] {
            // The envelope JSON-escapes a Windows path's backslashes.
            let needle = needle.replace('\\', "\\\\");
            assert!(text.contains(&needle), "{case}: no {needle:?} in {env}");
        }
        assert!(
            !text.contains("upstream_gem_install_refreshed"),
            "{case}: {env}"
        );
    }
}

/// A manifest record for the gem means its in-place patch is agent mode's
/// and still on record, so a vendored unwind does not end it:
/// `vendor --revert` undoes the vendoring only and leaves the installed
/// copy as it is. Two ways there: standalone `vendor`, which works from
/// the manifest and keeps the record in it, and an agent-mode record
/// written again after a vendored takeover.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_leaves_an_install_the_manifest_still_records() {
    for standalone in [true, false] {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let home = project_home(&proj);
        let uri = server.uri();
        let gem_dir = if standalone {
            let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
            mount_api_for(&server, None, &sha256_of(&patched)).await;
            serve_upstream_gem(&server, &upstream).await;
            mount_vendored_grant(&server, &patched).await;
            std::fs::create_dir_all(&proj).unwrap();
            write_manifest_pair(&proj);
            let gem_dir = agent_patched_install(&proj, &home);
            let (code, stdout, stderr) = unwind_run(&proj, &uri, &["vendor", "--yes", "--json"]);
            assert_eq!(code, 0, "vendor:\n{stdout}\n{stderr}");
            gem_dir
        } else {
            let (gem_dir, _) = agent_then_vendored(&server, &proj).await;
            common::write_in_place_patch_record(
                &proj.join(".socket"),
                PURL,
                UUID,
                "lib/stale_probe_gem.rb",
                UPSTREAM_LIB.as_bytes(),
                PATCHED_LIB.as_bytes(),
            );
            gem_dir
        };
        let case = format!("standalone={standalone}");
        let manifest_path = proj.join(".socket").join("manifest.json");
        assert!(
            std::fs::read_to_string(proj.join("Gemfile"))
                .unwrap()
                .contains(".socket/vendor/gem/")
                && std::fs::read_to_string(&manifest_path)
                    .unwrap()
                    .contains(PURL),
            "{case}: premise: vendored, with the record in the manifest"
        );
        let held_before = snapshot(&home);

        let (code, stdout, stderr) =
            unwind_run(&proj, &uri, &["vendor", "--revert", "--yes", "--json"]);
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "{case}: {env}\nstderr:\n{stderr}");
        assert!(
            !std::fs::read_to_string(proj.join("Gemfile"))
                .unwrap()
                .contains(".socket/vendor/"),
            "{case}: the vendoring is undone: {env}"
        );
        assert!(
            snapshot(&home) == held_before,
            "{case}: the gem home changed: {env}"
        );
        assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "{case}");
        assert!(
            std::fs::read_to_string(&manifest_path)
                .unwrap()
                .contains(PURL),
            "{case}: the manifest keeps the record: {env}"
        );
        let text = env.to_string();
        for code in [
            "upstream_gem_install_refreshed",
            "upstream_gem_stale_install",
        ] {
            assert!(!text.contains(code), "{case}: {code} in {env}");
        }
    }
}

/// A gem the lock resolves from another remote is not judged, as in every
/// unwind refresh: nothing proves its restored entry is the upstream one,
/// and rubygems.org is not asked about a gem that is not its own.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_does_not_judge_an_agent_patched_gem_from_another_remote() {
    for unwind in VENDORED_UNWINDS {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, _) =
            agent_then_vendored_from(&server, &proj, "https://gems.example.test").await;
        let home = project_home(&proj);
        let held_before = snapshot(&home);
        let asked_before = server.received_requests().await.unwrap().len();

        let mut args = unwind.to_vec();
        args.push("--json");
        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), &args);
        let env = common::parse_json_envelope(&stdout);
        assert_eq!(code, 0, "{unwind:?}: {env}\nstderr:\n{stderr}");
        assert!(
            std::fs::read_to_string(proj.join("Gemfile.lock"))
                .unwrap()
                .contains("remote: https://gems.example.test/"),
            "{unwind:?}: premise: back on the other remote"
        );
        assert!(
            snapshot(&home) == held_before,
            "{unwind:?}: the gem home changed: {env}"
        );
        assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "{unwind:?}");
        let upstream_asked = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .skip(asked_before)
            .any(|request| request.url.path().starts_with("/upstream/"));
        assert!(!upstream_asked, "{unwind:?}: the unwind asked rubygems.org");
        let text = env.to_string();
        for code in [
            "upstream_gem_install_refreshed",
            "upstream_gem_stale_install",
        ] {
            assert!(!text.contains(code), "{unwind:?}: {code} in {env}");
        }
    }
}

/// The human run says what it replaced, and rollback's "keeps its patched
/// bytes" note no longer counts the gem.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_unwind_reports_the_agent_patched_refresh_in_a_human_run() {
    for unwind in VENDORED_UNWINDS {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let (gem_dir, _) = agent_then_vendored(&server, &proj).await;

        let (code, stdout, stderr) = unwind_run(&proj, &server.uri(), unwind);
        assert_eq!(code, 0, "{unwind:?}: {stdout}\n{stderr}");
        assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB, "{unwind:?}");
        assert!(
            stdout.contains(&format!(
                "Replaced the installed copy of 1 gem with the upstream build: {DEP} \
                 {DEP_VERSION}."
            )),
            "{unwind:?}: {stdout}\n{stderr}"
        );
        assert!(
            !stdout.contains("keeps its patched bytes") && !stderr.contains("still holds"),
            "{unwind:?}: {stdout}\n{stderr}"
        );
    }
}

/// What `scan --mode agent` leaves of the fixture gem under `home`: the
/// upstream install with its lib patched in place, the upstream archive
/// still in the home's `cache/`, and the manifest record (with both blobs)
/// that proves the patch. Returns the gem dir.
fn agent_patched_install(proj: &Path, home: &Path) -> PathBuf {
    let gem_dir = install_real_gem(home, UPSTREAM_LIB);
    std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), PATCHED_LIB).unwrap();
    common::write_in_place_patch_record(
        &proj.join(".socket"),
        PURL,
        UUID,
        "lib/stale_probe_gem.rb",
        UPSTREAM_LIB.as_bytes(),
        PATCHED_LIB.as_bytes(),
    );
    // A file of agent mode's own inside the gem dir (a native gem keeps its
    // original build there).
    std::fs::write(gem_dir.join(".socket-patch-kept"), "kept").unwrap();
    gem_dir
}

/// #2089: a gem agent mode patched in place keeps the upstream archive in
/// the gem home's `cache/`. Once the hosted scan pins the patched gem's
/// checksum in the lock, `bundle pristine` and `bundle install
/// --redownload` reinstall from that archive: Bundler 2.6 and later remove
/// the gem and fail on the checksum, older ones bring the unpatched gem
/// back. So the scan replaces that archive with the patched gem and leaves
/// the gem dir, whose files are patched already, exactly as it is;
/// `rollback` still gives the upstream gem back.
#[tokio::test(flavor = "multi_thread")]
async fn refresh_replaces_the_upstream_archive_beside_an_agent_patched_install() {
    let server = MockServer::start().await;
    let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    serve_upstream_gem(&server, &upstream).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = project_home(&proj);
    let gem_dir = agent_patched_install(&proj, &home);
    let cache = home.join("cache").join(format!("{DEP}-{DEP_VERSION}.gem"));
    assert_eq!(std::fs::read(&cache).unwrap(), upstream, "fixture");

    // A dry run says the copy would be replaced and changes nothing.
    let uri = server.uri();
    let (code, stdout, stderr) = common::run_with_env(
        &proj,
        &scan_args(&proj, &uri, &["--json", "--dry-run"]),
        &[],
    );
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert_eq!(
        warnings_with_code(&env, "redirect_gem_install_would_refresh").len(),
        1,
        "{env}"
    );
    assert_eq!(std::fs::read(&cache).unwrap(), upstream);

    let (code, stdout, stderr) =
        common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert_eq!(hosted_pinned(&env), 1, "{env}");
    assert!(
        stale_warnings(&env).is_empty(),
        "nothing is left stale: {env}"
    );
    let notes = warnings_with_code(&env, "redirect_gem_install_refreshed");
    assert!(
        notes.len() == 1
            && notes[0].contains(&cache.display().to_string())
            && notes[0].contains("patched in place"),
        "the archive, and only it: {env}"
    );
    assert!(
        gem_dir.join(".socket-patch-kept").is_file(),
        "the gem dir is not replaced"
    );
    assert_eq!(
        std::fs::read(&cache).unwrap(),
        patched,
        "the archive RubyGems reinstalls from is the one the lock pins"
    );
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB);
    assert!(
        !home.join(".socket-patch-refresh").exists(),
        "no stage left"
    );

    // A re-scan has nothing to refresh and nothing to warn about.
    let (code, _, stderr) = common::run_with_env(&proj, &scan_args(&proj, &uri, &[]), &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        !stderr.contains("Replaced")
            && !stderr.contains("upstream archive")
            && !stderr.contains("still unpatched"),
        "{stderr}"
    );

    // `rollback` undoes both the hosted pin and the agent record: the
    // upstream files and the upstream archive are back.
    std::fs::write(proj.join("Gemfile.lock"), converged_lock(&uri)).unwrap();
    let rubygems = format!("{uri}/upstream");
    let (code, stdout, stderr) = common::run_with_env(
        &proj,
        &[
            "rollback",
            "--yes",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
            "--api-url",
            uri.as_str(),
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--patch-server-url",
            uri.as_str(),
        ],
        &[("SOCKET_RUBYGEMS_URL", rubygems.as_str())],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB);
    assert_eq!(std::fs::read(&cache).unwrap(), upstream);
}

/// The same copy where the run may not replace it: it is left byte for
/// byte as it was, and the warning says what is wrong with it (the archive,
/// not the files, which are patched) and how to fix it. A shared gem home
/// gets the project-local path or `--gem-refresh-shared`;
/// `--no-gem-install-refresh` gets the files to remove.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn an_agent_patched_install_the_run_may_not_replace_is_warned_about() {
    let server = MockServer::start().await;
    let (patched, upstream) = (real_gem(PATCHED_LIB), real_gem(UPSTREAM_LIB));
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched.clone()).await;
    let uri = server.uri();
    let leaf = format!("{DEP}-{DEP_VERSION}");

    // Project-local, refresh turned off.
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = project_home(&proj);
    let gem_dir = agent_patched_install(&proj, &home);
    let cache = home.join("cache").join(format!("{leaf}.gem"));
    let spec = home.join("specifications").join(format!("{leaf}.gemspec"));
    let (code, stdout, stderr) = common::run_with_env(
        &proj,
        &scan_args(&proj, &uri, &["--json", "--no-gem-install-refresh"]),
        &[],
    );
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\n{stderr}");
    let details = stale_warnings(&env);
    assert_eq!(details.len(), 1, "{env}");
    for needle in [
        "patched in place",
        "`--no-gem-install-refresh` is set",
        &format!("emove {} and run `bundle install`", cache.display()),
    ] {
        assert!(
            details[0].contains(needle),
            "missing {needle:?}: {details:?}"
        );
    }
    assert!(
        !details[0].contains("unpatched install")
            && !details[0].contains(&spec.display().to_string()),
        "the installed files are patched, and stay installed: {details:?}"
    );
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB);
    assert_eq!(std::fs::read(&cache).unwrap(), upstream);

    // A shared gem home.
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = tmp.path().join("system-home");
    let bin_dir = tmp.path().join("fake-bin");
    stage_system_home_copy(&home, &bin_dir);
    let gem_dir = agent_patched_install(&proj, &home);
    let cache = home.join("cache").join(format!("{leaf}.gem"));
    let path_env = [("PATH", bin_dir.to_str().unwrap())];
    let (code, _, stderr) = common::run_with_env(&proj, &scan_args(&proj, &uri, &[]), &path_env);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB);
    assert_eq!(
        std::fs::read(&cache).unwrap(),
        upstream,
        "the shared home is not touched"
    );
    for needle in [
        "Warning: 1 gem patched in place still has its upstream archive on disk after the \
         switch to hosted patches.",
        &format!(
            "  - Shared gem home {} (left alone, other projects may load it): {DEP} {DEP_VERSION}.",
            home.display()
        ),
        "run `bundle config set --local path vendor/bundle && bundle install`",
        "`--gem-refresh-shared`",
    ] {
        assert!(stderr.contains(needle), "missing {needle:?}:\n{stderr}");
    }
    assert!(!stderr.contains("still unpatched on disk"), "{stderr}");

    let (code, stdout, stderr) = common::run_with_env(
        &proj,
        &scan_args(&proj, &uri, &["--json", "--gem-refresh-shared"]),
        &path_env,
    );
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\n{stderr}");
    assert!(stale_warnings(&env).is_empty(), "{env}");
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB);
    assert_eq!(std::fs::read(&cache).unwrap(), patched);
    assert!(gem_dir.join(".socket-patch-kept").is_file());
}

// ── a hosted gem whose patch was superseded, taken over by vendored ───

/// The newer patch the service publishes for the fixture gem once the
/// project is hosted on [`UUID`].
const NEWER_UUID: &str = "9b0c1d2e-3f4a-4b5c-8d7e-8f9a0b1c2d3e";
const NEWER_PATCHED_LIB: &str =
    "module StaleProbeGem\n  def self.status\n    \"PATCHED AGAIN\"\n  end\nend\n";

/// The patch API once [`NEWER_UUID`] supersedes [`UUID`] (mount it on a
/// reset server): discovery, selection and the view name only the newer
/// patch, and its grant carries the vendored artifacts beside the hosted
/// override.
async fn mount_newer_patch(server: &MockServer) {
    let patched = real_gem(NEWER_PATCHED_LIB);
    mount_patch_api(
        server,
        NEWER_UUID,
        NEWER_PATCHED_LIB,
        None,
        &sha256_of(&patched),
    )
    .await;
    mount_vendored_grant_of(server, NEWER_UUID, &patched).await;
    serve_upstream_gem(server, &real_gem(UPSTREAM_LIB)).await;
}

/// A project hosted on [`UUID`], with the lock as `bundle install` leaves
/// it and the installed copy holding that patch's bytes, after the service
/// replaced the patch with [`NEWER_UUID`]. Returns the gem home.
async fn hosted_on_a_superseded_patch(server: &MockServer, proj: &Path) -> PathBuf {
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(server, None, &sha256_of(&patched)).await;
    serve_patched_gem(server, patched).await;
    std::fs::create_dir_all(proj).unwrap();
    write_manifest_pair(proj);
    let home = project_home(proj);
    let gem_dir = install_real_gem(&home, UPSTREAM_LIB);
    let uri = server.uri();
    let (code, _, stderr) = common::run_with_env(proj, &scan_args(proj, &uri, &["--json"]), &[]);
    assert_eq!(code, 0, "hosted scan:\n{stderr}");
    std::fs::write(proj.join("Gemfile.lock"), converged_lock(&uri)).unwrap();
    assert_eq!(installed_lib(&gem_dir), PATCHED_LIB, "premise");
    server.reset().await;
    mount_newer_patch(server).await;
    home
}

/// The events of `env` that name the fixture gem, as `action/errorCode`.
fn gem_events(env: &serde_json::Value) -> Vec<String> {
    env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["purl"].as_str().is_some_and(|p| p.starts_with(PURL)))
        .map(|e| {
            format!(
                "{}/{}",
                e["action"].as_str().unwrap_or_default(),
                e["errorCode"].as_str().unwrap_or_default()
            )
        })
        .collect()
}

/// #2129: a gem on a hosted patch whose installed copy holds that patch's
/// bytes, after a newer patch was published for the same version. The
/// installed copy matches neither side of the newer patch, but the gem is
/// installed and its lock entry is ours: `scan --mode vendored` vendors
/// the newer patch, as it does on a checkout with no gems installed, and
/// leaves the installed copy alone. The dry run previews the same, and a
/// second run finds nothing left to do. `get --mode vendored` takes the
/// same path.
#[tokio::test(flavor = "multi_thread")]
async fn vendored_takeover_of_a_hosted_gem_whose_patch_was_superseded() {
    let takeovers: [&[&str]; 2] = [
        &["scan", "--mode", "vendored"],
        &["get", NEWER_UUID, "--mode", "vendored"],
    ];
    for takeover in takeovers {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        let home = hosted_on_a_superseded_patch(&server, &proj).await;
        let uri = server.uri();
        let held_before = snapshot(&home);
        let read_pair = || {
            format!(
                "{}{}",
                std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
                std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap()
            )
        };
        let pair_before = read_pair();
        let run = |extra: &[&str]| {
            let mut args = takeover.to_vec();
            args.extend(["--yes", "--json"]);
            args.extend(extra);
            let (code, stdout, stderr) = unwind_run(&proj, &uri, &args);
            let env = common::parse_json_envelope(&stdout);
            assert_eq!(code, 0, "{takeover:?} {extra:?}: {env}\nstderr:\n{stderr}");
            assert!(
                !env.to_string().contains("package_not_installed"),
                "{takeover:?} {extra:?}: the gem is installed: {env}"
            );
            env
        };

        run(&["--dry-run"]);
        assert_eq!(
            read_pair(),
            pair_before,
            "{takeover:?}: the dry run wrote nothing"
        );
        assert!(
            !proj.join(".socket").join("vendor").exists(),
            "{takeover:?}"
        );

        let env = run(&[]);
        let copy_rel = format!(".socket/vendor/gem/{NEWER_UUID}/{DEP}-{DEP_VERSION}");
        let pair = read_pair();
        assert!(
            pair.matches(&copy_rel).count() >= 2 && !pair.contains("/patch-registry/"),
            "{takeover:?}: the pair names the newer patch's copy and no hosted pin:\n{pair}\n{env}"
        );
        assert_eq!(
            installed_lib(&proj.join(&copy_rel)),
            NEWER_PATCHED_LIB,
            "{takeover:?}: the vendored copy is the newer patch"
        );
        assert!(
            snapshot(&home) == held_before,
            "{takeover:?}: the takeover left the installed copy alone: {env}"
        );

        let env = run(&[]);
        assert_eq!(
            read_pair(),
            pair,
            "{takeover:?}: the re-run changed the pair: {env}"
        );
        assert!(
            snapshot(&home) == held_before,
            "{takeover:?}: the re-run changed the installed copy: {env}"
        );
    }
}

/// #2129, the native-extension half: a hosted gem that builds an
/// extension cannot be vendored, superseded patch or not. The refusal
/// names that (`native_extensions_unsupported`), not a gem that is "not
/// installed", and the hosted pin stays. (A dry run of the scan previews
/// no native-extension refusal for any hosted gem, so only the real run is
/// held to this.)
#[tokio::test(flavor = "multi_thread")]
async fn vendored_takeover_of_a_superseded_native_gem_names_the_extension() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    let home = hosted_on_a_superseded_patch(&server, &proj).await;
    let spec = home
        .join("specifications")
        .join(format!("{DEP}-{DEP_VERSION}.gemspec"));
    let text = std::fs::read_to_string(&spec).unwrap();
    std::fs::write(
        &spec,
        text.replace(
            "  s.require_paths",
            "  s.extensions = [\"ext/probe/extconf.rb\".freeze]\n  s.require_paths",
        ),
    )
    .unwrap();
    let pair_before = (
        std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
        std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
    );

    let (code, stdout, stderr) = unwind_run(
        &proj,
        &server.uri(),
        &["scan", "--mode", "vendored", "--yes", "--json"],
    );
    let env = common::parse_json_envelope(&stdout);
    let events = gem_events(&env);
    assert!(
        events
            .iter()
            .any(|e| e.ends_with("/native_extensions_unsupported")),
        "{events:?}\n{env}\nstderr:\n{stderr}"
    );
    assert!(!env.to_string().contains("package_not_installed"), "{env}");
    assert_ne!(code, 0, "{env}");
    assert_eq!(
        (
            std::fs::read_to_string(proj.join("Gemfile")).unwrap(),
            std::fs::read_to_string(proj.join("Gemfile.lock")).unwrap(),
        ),
        pair_before,
        "the hosted pin stays"
    );
    assert!(!proj.join(".socket").join("vendor").exists());
}

/// A lock whose `PLATFORMS` names `ruby` alone names every gem as its
/// ruby-platform gem, and for such a lock Bundler loads an installed
/// precompiled build of the locked version in its place: the copy an
/// install from the upstream registry left behind. After the switch that
/// copy is what Ruby runs, and `bundle install` keeps it.
///
/// * The scan reports it and does not replace it: the patched gem of this
///   lock is the ruby-platform gem, which only an install builds. It asks
///   the patch registry for no gem, names the command, offers no retry
///   that would do the same, and does not say that nothing is left.
/// * `vex` exits 0 and says `affected` of the gem, with what to do.
/// * A lock that names another platform as well loads the gems it lists,
///   so the copy is not this project's, and a gem dir no gemspec lists is
///   no gem: neither is reported.
#[tokio::test(flavor = "multi_thread")]
async fn a_precompiled_copy_under_a_ruby_only_lock_is_reported_and_attested_affected() {
    use vex_e2e_common::{run_vex, statements_for, VexRun};
    let server = MockServer::start().await;
    let patched = real_gem(PATCHED_LIB);
    mount_api_for(&server, None, &sha256_of(&patched)).await;
    serve_patched_gem(&server, patched).await;
    let uri = server.uri();
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_manifest_pair(&proj);
    let home = project_home(&proj);
    let gem_dir = install_real_gem_for(&home, UPSTREAM_LIB, PLATFORM);
    let leaf = format!("{DEP}-{DEP_VERSION}-{PLATFORM}");
    let spec = home.join("specifications").join(format!("{leaf}.gemspec"));

    let (code, stdout, stderr) = common::run_with_env(&proj, &scan_args(&proj, &uri, &[]), &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("1 gem is still unpatched on disk after the switch to hosted patches")
            && stderr.contains(&format!(
                "Not refreshed (it is a precompiled {PLATFORM} gem, which Bundler loads in \
                 place of the ruby gem the lock names"
            )),
        "the copy Bundler loads is reported with what it is:\n{stderr}"
    );
    assert!(
        stderr.contains("Run `rm -f ")
            && stderr.contains(&format!("{leaf}.gemspec"))
            && stderr.contains(&format!("{leaf}.gem && bundle install`")),
        "the command names the copy's gemspec and archive:\n{stderr}"
    );
    assert!(!stderr.contains("to retry"), "{stderr}");
    assert!(
        stdout.contains(
            "1 gem is still unpatched on disk: the warning names the command that installs the \
             patched gem."
        ) && !stdout.contains("Nothing left to patch"),
        "the closing lines do not say that nothing is left:\n{stdout}"
    );
    assert_eq!(installed_lib(&gem_dir), UPSTREAM_LIB, "the copy is left");
    let gems: Vec<String> = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|request| request.url.path().to_string())
        .filter(|path| path.contains("/gems/"))
        .collect();
    assert!(gems.is_empty(), "no gem is asked for: {gems:?}");

    // `vex`: a document, exit 0, and the gem's actual state.
    let run = VexRun {
        api_url: Some(uri.clone()),
        api_token: Some("fake".into()),
        org: Some(ORG.into()),
        patch_server_url: Some(uri.clone()),
        product: Some("pkg:gem/app@1.0.0".into()),
        ..VexRun::default()
    };
    let out = run_vex(&vex_e2e_common::binary(), &proj, &run);
    assert_eq!(out.code, Some(0), "{out}");
    let statements = statements_for(out.doc(), PURL);
    assert_eq!(statements.len(), 1, "{out}");
    assert_eq!(statements[0]["status"], "affected", "{out}");
    let action = statements[0]["action_statement"]
        .as_str()
        .unwrap_or_default();
    assert!(action.contains("Run `socket-patch scan`"), "{action}");
    let skipped: Vec<&serde_json::Value> = out.envelope["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|event| event["action"] == "skipped")
        .collect();
    assert_eq!(skipped.len(), 1, "{out}");
    assert_eq!(
        skipped[0]["errorCode"], "vex_gem_install_unpatched",
        "{out}"
    );
    assert!(
        warnings_with_code(&out.envelope, "vex_gem_install_unpatched")
            .iter()
            .any(|detail| detail.contains("the VEX document says affected")),
        "{out}"
    );

    // A lock that names another platform too loads exactly what it lists.
    let lock_path = proj.join("Gemfile.lock");
    let hosted_lock = std::fs::read_to_string(&lock_path).unwrap();
    let both = hosted_lock.replace("PLATFORMS\n  ruby\n", "PLATFORMS\n  ruby\n  x86_64-linux\n");
    assert_ne!(both, hosted_lock);
    std::fs::write(&lock_path, &both).unwrap();
    let (code, stdout, stderr) =
        common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert!(stale_warnings(&env).is_empty(), "{env}");

    // Back on the ruby-only lock, with the copy's gemspec removed: the dir
    // is what an install left behind, and nothing loads it.
    std::fs::write(&lock_path, &hosted_lock).unwrap();
    std::fs::remove_file(&spec).unwrap();
    let (code, stdout, stderr) =
        common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert!(stale_warnings(&env).is_empty(), "{env}");
}

/// A patched platform build in a gem home whose `cache/` was pruned (a
/// slim image, `gem cleanup`): no archive says which gem the copy was
/// installed from. A platform gem is a patch of its own, whose files carry
/// that patch's header, so they never hash to what the gem patch's record
/// lists.
///
/// * The copy is judged by the record of its own patch: the healthy one is
///   left alone and nothing is said, run after run. Judged by the gem
///   patch's record it was called stale and replaced, or warned about,
///   every time.
/// * Where that build's record cannot be read, nothing judges the copy: it
///   is not called stale and is not replaced.
/// * An upstream copy in the same place is still stale, by the build's
///   record.
#[tokio::test(flavor = "multi_thread")]
async fn a_patched_platform_copy_with_a_pruned_cache_is_judged_by_its_own_patch() {
    // What the platform build's own patch makes of the file.
    let stamped = format!("# Socket Community Patch: {ARM_UUID}\n{PATCHED_LIB}");
    let build_record = |served: bool| {
        let template = match served {
            true => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": ARM_UUID,
                "purl": format!("{PURL}?platform={PLATFORM}"),
                "publishedAt": "2026-01-01T00:00:00Z",
                "files": { "lib/stale_probe_gem.rb": {
                    "beforeHash": compute_git_sha256_from_bytes(UPSTREAM_LIB.as_bytes()),
                    "afterHash": compute_git_sha256_from_bytes(stamped.as_bytes()),
                } },
                "vulnerabilities": {},
                "description": "x", "license": "MIT", "tier": "free"
            })),
            false => ResponseTemplate::new(404),
        };
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{ARM_UUID}")))
            .respond_with(template)
    };
    for (served, installed, stale) in [
        (true, stamped.as_str(), false),
        (false, stamped.as_str(), false),
        (true, UPSTREAM_LIB, true),
    ] {
        let server = MockServer::start().await;
        let prebuilt = real_gem_for(&stamped, PLATFORM);
        let other = real_gem_for(PATCHED_LIB, OTHER_PLATFORM);
        mount_api_with(
            &server,
            None,
            &sha256_of(&real_gem(PATCHED_LIB)),
            &[
                (PLATFORM, sha256_of(&prebuilt), Some(ARM_UUID)),
                (OTHER_PLATFORM, sha256_of(&other), Some(LINUX_UUID)),
            ],
        )
        .await;
        build_record(served).mount(&server).await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(
            proj.join("Gemfile"),
            format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n"),
        )
        .unwrap();
        let upstream = |platform: &str| sha256_of(&real_gem_for(UPSTREAM_LIB, platform));
        std::fs::write(
            proj.join("Gemfile.lock"),
            platform_lock(&upstream(PLATFORM), &upstream(OTHER_PLATFORM)),
        )
        .unwrap();
        let home = project_home(&proj);
        let gem_dir = install_real_gem_for(&home, installed, PLATFORM);
        std::fs::remove_dir_all(home.join("cache")).unwrap();

        let uri = server.uri();
        let label = format!("record served: {served}, stale: {stale}");
        for run in ["first", "second"] {
            let (code, stdout, stderr) =
                common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
            let env = common::parse_json_envelope(&stdout);
            assert_eq!(code, 0, "{label}, {run} scan: {env}\nstderr:\n{stderr}");
            assert_eq!(
                stale_warnings(&env).len(),
                usize::from(stale),
                "{label}, {run} scan: {env}"
            );
            assert!(
                warnings_with_code(&env, "redirect_gem_install_refreshed").is_empty(),
                "{label}, {run} scan: nothing is replaced without the archive: {env}"
            );
            assert_eq!(installed_lib(&gem_dir), installed, "{label}, {run} scan");
        }
        let fix_records = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| {
                request
                    .url
                    .path()
                    .ends_with(&format!("/patches/view/{UUID}"))
            })
            .count();
        assert_eq!(
            fix_records, 0,
            "{label}: the gem patch's record is not what judges it"
        );
        // The build's own record is asked for without its file contents.
        let own: Vec<Option<String>> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| {
                request
                    .url
                    .path()
                    .ends_with(&format!("/patches/view/{ARM_UUID}"))
            })
            .map(|request| request.url.query().map(str::to_string))
            .collect();
        assert!(
            !own.is_empty()
                && own
                    .iter()
                    .all(|query| query.as_deref() == Some("include_blobs=false")),
            "{label}: {own:?}"
        );
    }
}

/// What `vex` attests of a platform build is what Ruby loads. The archive
/// RubyGems installed the copy from says which gem it was, with no
/// request, and the installed tree is then held to that archive's own
/// files: a copy whose archive is the patched gem while a file under
/// `gems/<leaf>` has other bytes is not attested, and the scan replaces it
/// from the archive.
#[tokio::test(flavor = "multi_thread")]
async fn a_platform_copy_is_attested_by_its_archive_only_while_its_tree_is_the_archives() {
    use vex_e2e_common::{assert_not_attested, run_vex, statements_for, VexRun};
    let stamped = format!("# Socket Community Patch: {ARM_UUID}\n{PATCHED_LIB}");
    let server = MockServer::start().await;
    let prebuilt = real_gem_for(&stamped, PLATFORM);
    let other = real_gem_for(PATCHED_LIB, OTHER_PLATFORM);
    mount_api_with(
        &server,
        None,
        &sha256_of(&real_gem(PATCHED_LIB)),
        &[
            (PLATFORM, sha256_of(&prebuilt), Some(ARM_UUID)),
            (OTHER_PLATFORM, sha256_of(&other), Some(LINUX_UUID)),
        ],
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n"),
    )
    .unwrap();
    let upstream = |platform: &str| sha256_of(&real_gem_for(UPSTREAM_LIB, platform));
    std::fs::write(
        proj.join("Gemfile.lock"),
        platform_lock(&upstream(PLATFORM), &upstream(OTHER_PLATFORM)),
    )
    .unwrap();
    let home = project_home(&proj);
    let gem_dir = install_real_gem_for(&home, &stamped, PLATFORM);
    let uri = server.uri();
    let (code, stdout, stderr) =
        common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert!(stale_warnings(&env).is_empty(), "{env}");

    let run = VexRun {
        api_url: Some(uri.clone()),
        api_token: Some("fake".into()),
        org: Some(ORG.into()),
        patch_server_url: Some(uri.clone()),
        product: Some("pkg:gem/app@1.0.0".into()),
        ..VexRun::default()
    };
    let build = format!("{PURL}?platform={PLATFORM}");
    let out = run_vex(&vex_e2e_common::binary(), &proj, &run);
    assert_eq!(out.code, Some(0), "{out}");
    let attested = statements_for(out.doc(), &build);
    assert!(
        attested
            .iter()
            .any(|statement| statement["status"] == "not_affected"),
        "the build is attested by its archive and its tree: {out}"
    );
    let records = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|request| {
            request
                .url
                .path()
                .ends_with(&format!("/patches/view/{ARM_UUID}"))
        })
        .count();
    assert_eq!(records, 0, "with no record of its patch read");

    // The same archive, and a file of the gem with other bytes.
    std::fs::write(gem_dir.join("lib").join("stale_probe_gem.rb"), UPSTREAM_LIB).unwrap();
    let out = run_vex(&vex_e2e_common::binary(), &proj, &run);
    assert_not_attested(&out.envelope, &build, "hash_mismatch");

    // The scan sees the same, and puts the archive's files back.
    let (code, stdout, stderr) =
        common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(code, 0, "{env}\nstderr:\n{stderr}");
    assert_eq!(
        warnings_with_code(&env, "redirect_gem_install_refreshed").len(),
        1,
        "{env}"
    );
    assert_eq!(installed_lib(&gem_dir), stamped);
}

/// A project locked on the two platform builds of the fixture gem, against
/// a service that lists a patched build for both, the one for [`PLATFORM`]
/// being `prebuilt`. Returns the project dir.
async fn platform_project(server: &MockServer, tmp: &Path, prebuilt: &[u8]) -> PathBuf {
    let other = real_gem_for(PATCHED_LIB, OTHER_PLATFORM);
    mount_api_with(
        server,
        None,
        &sha256_of(&real_gem(PATCHED_LIB)),
        &[
            (PLATFORM, sha256_of(prebuilt), Some(ARM_UUID)),
            (OTHER_PLATFORM, sha256_of(&other), Some(LINUX_UUID)),
        ],
    )
    .await;
    let proj = tmp.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        format!("source \"https://rubygems.org\"\ngem \"{DEP}\", \"{DEP_VERSION}\"\n"),
    )
    .unwrap();
    let upstream = |platform: &str| sha256_of(&real_gem_for(UPSTREAM_LIB, platform));
    std::fs::write(
        proj.join("Gemfile.lock"),
        platform_lock(&upstream(PLATFORM), &upstream(OTHER_PLATFORM)),
    )
    .unwrap();
    proj
}

/// How many requests `server` got for the record of the [`PLATFORM`]
/// build's own patch.
async fn build_record_requests(server: &MockServer) -> usize {
    let requests = server.received_requests().await.unwrap_or_default();
    let record = format!("/patches/view/{ARM_UUID}");
    requests
        .iter()
        .filter(|request| request.url.path().ends_with(&record))
        .count()
}

/// The `--vex` of the run that moved the lock judges an installed platform
/// copy by the digest that run's own reference listed: the archive says
/// the copy is the patched build, and no record is read. Where the gem
/// home keeps no archive and the build's record cannot be read, the build
/// the run just confirmed is not stated `affected`: the run's own gate
/// withholds the gem as a copy nothing judged, as it does for any gem.
#[tokio::test(flavor = "multi_thread")]
async fn the_vex_of_the_run_that_moved_the_lock_goes_by_that_runs_digest() {
    let stamped = format!("# Socket Community Patch: {ARM_UUID}\n{PATCHED_LIB}");
    let build = format!("{PURL}?platform={PLATFORM}");
    for pruned in [false, true] {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = platform_project(&server, tmp.path(), &real_gem_for(&stamped, PLATFORM)).await;
        let home = project_home(&proj);
        install_real_gem_for(&home, &stamped, PLATFORM);
        if pruned {
            std::fs::remove_dir_all(home.join("cache")).unwrap();
        }
        let vex_path = proj.join("out.vex.json");
        let uri = server.uri();
        let args = scan_args(
            &proj,
            &uri,
            &[
                "--json",
                "--vex",
                vex_path.to_str().unwrap(),
                "--vex-product",
                "pkg:gem/app@1.0.0",
            ],
        );
        let (code, stdout, stderr) = common::run_with_env(&proj, &args, &[]);
        let env = common::parse_json_envelope(&stdout);
        // With nothing to judge the copy by, the run's gate withholds the
        // gem, and an embedded document with nothing in it fails the run.
        assert_eq!(
            code == 0,
            !pruned,
            "pruned: {pruned}: {env}\nstderr:\n{stderr}"
        );
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&vex_path).unwrap_or_default())
                .unwrap_or_default();
        let statuses: Vec<&str> = vex_e2e_common::statements_for(&doc, &build)
            .iter()
            .filter_map(|statement| statement["status"].as_str())
            .collect();
        match pruned {
            false => {
                assert_eq!(statuses, ["not_affected"], "{env}\n{doc}");
                assert_eq!(build_record_requests(&server).await, 0, "no record is read");
            }
            true => assert!(
                !statuses.contains(&"affected")
                    && !env.to_string().contains("vex_gem_build_unknown"),
                "a build the run confirmed is not stated affected for a read that failed: \
                 {env}\n{doc}"
            ),
        }
    }
}

/// A platform build has one `vex` outcome, from all of its installed
/// copies, and is attested only when every copy is shown to be the patched
/// build.
///
/// * The same build installed from another gem in two gem homes is left
///   out once, not once per home.
/// * One copy proven by its archive beside one that nothing can judge (no
///   archive, and the build's record cannot be read) is not attested: the
///   build is stated `affected` once, under the unknown-build warning, and
///   is in no other list.
#[tokio::test(flavor = "multi_thread")]
async fn a_platform_build_in_two_gem_homes_has_one_vex_outcome() {
    use vex_e2e_common::{run_vex, statements_for, VexRun};
    let stamped = format!("# Socket Community Patch: {ARM_UUID}\n{PATCHED_LIB}");
    let build = format!("{PURL}?platform={PLATFORM}");
    for proven_beside_unjudged in [false, true] {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let proj = platform_project(&server, tmp.path(), &real_gem_for(&stamped, PLATFORM)).await;
        let uri = server.uri();
        let (code, stdout, stderr) =
            common::run_with_env(&proj, &scan_args(&proj, &uri, &["--json"]), &[]);
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        // Two gem homes of the project: the trees of two Rubies.
        let first = project_home(&proj);
        let second = first.with_file_name("3.4.0");
        match proven_beside_unjudged {
            false => {
                // Both copies were installed from upstream's gem.
                install_real_gem_for(&first, UPSTREAM_LIB, PLATFORM);
                install_real_gem_for(&second, UPSTREAM_LIB, PLATFORM);
            }
            true => {
                install_real_gem_for(&first, &stamped, PLATFORM);
                install_real_gem_for(&second, &stamped, PLATFORM);
                std::fs::remove_dir_all(second.join("cache")).unwrap();
            }
        }
        let run = VexRun {
            api_url: Some(uri.clone()),
            api_token: Some("fake".into()),
            org: Some(ORG.into()),
            patch_server_url: Some(uri.clone()),
            product: Some("pkg:gem/app@1.0.0".into()),
            ..VexRun::default()
        };
        let out = run_vex(&vex_e2e_common::binary(), &proj, &run);
        let label = format!("proven beside unjudged: {proven_beside_unjudged}: {out}");
        let events: Vec<(&str, &str)> = out.envelope["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|event| event["purl"] == build.as_str())
            .map(|event| {
                let text = |key: &str| event[key].as_str().unwrap_or_default();
                (text("action"), text("errorCode"))
            })
            .collect();
        let statuses: Vec<&str> = statements_for(out.doc(), &build)
            .iter()
            .filter_map(|statement| statement["status"].as_str())
            .collect();
        match proven_beside_unjudged {
            false => {
                assert_eq!(events, [("skipped", "not_applied")], "{label}");
                assert!(statuses.is_empty(), "{label}");
            }
            true => {
                assert_eq!(events, [("skipped", "vex_gem_build_unknown")], "{label}");
                assert_eq!(statuses, ["affected"], "{label}");
            }
        }
    }
}
