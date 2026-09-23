//! Coverage-gap tests for `commands/scan/mod.rs` (2026-09 audit).
//!
//! Pins the audited-but-untested surfaces of `scan`:
//!
//! * the remaining `resolve_mode_flags` cross-mode conflict arms (and
//!   `ScanMode::Agent.cli_name()` reaching an error message);
//! * human (non-JSON) terminals: `--offline`, the `--mode hosted --prune`
//!   no-GC warning, the empty `--global-prefix` hint, the `--vex` success
//!   line, and the PnP layout refusal riding a NON-empty scan;
//! * the `redirect_prune_ignored` warning inside the zero-package hosted
//!   JSON envelope;
//! * the paid-tier rendering surface (no fixture anywhere else sends
//!   `tier: "paid"` in the batch response): the `N+M` table column, the
//!   paid-subscription nudge + pricing URL, the paid-access summary, and
//!   the "No downloadable patches" terminal;
//! * the human `[UPDATE]` marker + newer-patches summary, the `(+N)` vuln
//!   overflow, and the per-package detail-fetch warning;
//! * the human `[skip] … (vendored …)` lines;
//! * per-patch vulnerability rendering in the "Patches to apply" preview;
//! * the human post-apply GC line (both pluralization arms) and the
//!   `hosted_wiring_retained` stderr warning after an in-place apply;
//! * non-TTY human runs: a mode-less scan is report-only (no download, no
//!   `.socket/`), while `--mode agent` / `--apply` / `--prune` auto-proceed;
//! * the hosted human arm's results table, `[UPDATE]` detection and
//!   confirm prompt (parity with the agent/vendored arms);
//! * the declined download / redirect confirm via a PTY (exit 0, hint, no
//!   mutation).
//!
//! Subprocess runs scrub the `SOCKET_*` flag environment (the
//! `cli_scan_silent.rs` pattern) so ambient developer/CI configuration
//! cannot reroute the branch under test. Network tests use wiremock.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use socket_patch_cli::args::{GLOBAL_ARG_ENV_VARS, LOCAL_ARG_ENV_VARS};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const OLD_UUID: &str = "99999999-9999-4999-8999-999999999999";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-scan-root", "version": "0.0.0" }"#,
    )
    .unwrap();
}

fn write_npm_package(root: &Path, name: &str, version: &str, content: &[u8]) {
    let pkg_dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), content).unwrap();
}

/// Run `socket-patch scan` in `cwd` with the whole flag-bound `SOCKET_*`
/// environment scrubbed, so the CLI arguments are the sole source of truth
/// (telemetry stays disabled so no run phones home).
fn run_scan(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("scan").args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS.iter().chain(LOCAL_ARG_ENV_VARS.iter()) {
        cmd.env_remove(var);
    }
    // The unconditional python crawl consults VIRTUAL_ENV first, so an
    // activated host virtualenv would make "empty project" scans non-empty.
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Human-path (no `--json`) run against a mock API.
fn run_scan_human(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec![
        "--api-url",
        api_url,
        "--api-token",
        "fake-token-for-test",
        "--org",
        ORG_SLUG,
    ];
    args.extend_from_slice(extra);
    run_scan(cwd, &args)
}

async fn recorded(mock: &MockServer) -> Vec<wiremock::Request> {
    mock.received_requests()
        .await
        .expect("wiremock records requests by default")
}

fn by_package_gets(reqs: &[wiremock::Request]) -> usize {
    reqs.iter()
        .filter(|r| {
            format!("{}", r.method) == "GET" && r.url.path().contains("/patches/by-package/")
        })
        .count()
}

fn view_gets(reqs: &[wiremock::Request]) -> usize {
    reqs.iter()
        .filter(|r| format!("{}", r.method) == "GET" && r.url.path().contains("/patches/view/"))
        .count()
}

fn batch_bodies(reqs: &[wiremock::Request]) -> Vec<String> {
    reqs.iter()
        .filter(|r| format!("{}", r.method) == "POST" && r.url.path().ends_with("/patches/batch"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

/// Mount the batch endpoint returning one package with one patch of the
/// given tier and vuln ids.
async fn mount_batch_one(
    mock: &MockServer,
    purl: &str,
    uuid: &str,
    tier: &str,
    cve_ids: &[&str],
    can_access_paid: bool,
) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": uuid,
                    "purl": purl,
                    "tier": tier,
                    "cveIds": cve_ids,
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "covgap test patch"
                }]
            }],
            "canAccessPaidPatches": can_access_paid,
        })))
        .mount(mock)
        .await;
}

fn encode_purl(purl: &str) -> String {
    purl.replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40")
}

/// Mount the by-package detail endpoint for `purl` with the given
/// vulnerabilities object.
async fn mount_by_package(
    mock: &MockServer,
    purl: &str,
    uuid: &str,
    vulnerabilities: serde_json::Value,
) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{}",
            encode_purl(purl)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": uuid,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "Covgap test patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": vulnerabilities,
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
}

/// Mount the three endpoints the full human apply flow hits — batch,
/// by-package, and the patch view with an inline blob (fixture shape
/// mirrors `cli_scan_silent.rs` / `scan_sync_e2e.rs`).
async fn mount_one_patch_api(mock: &MockServer, purl: &str, before: &[u8]) {
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(b"after\n");
    mount_batch_one(mock, purl, UUID, "free", &[], false).await;
    mount_by_package(mock, purl, UUID, serde_json::json!({})).await;
    // base64 of "after\n" — inline so the apply step needs no blob endpoint.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash": after_hash,
                    "blobContent": "YWZ0ZXIK",
                }
            },
            "vulnerabilities": {},
            "description": "Covgap test patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// Seed `.socket/manifest.json` with one entry per `(purl, uuid)` pair
/// (camelCase wire shape, mirroring `scan_invariants.rs`).
fn seed_manifest(root: &Path, entries: &[(&str, &str)]) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let patches: serde_json::Map<String, serde_json::Value> = entries
        .iter()
        .map(|(purl, uuid)| {
            (
                (*purl).to_string(),
                serde_json::json!({
                    "uuid": uuid,
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "seed",
                    "license": "MIT",
                    "tier": "free",
                }),
            )
        })
        .collect();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// resolve_mode_flags — the remaining cross-mode conflict arms
// ---------------------------------------------------------------------------
// Only the `--mode hosted --vendor` arm is pinned in cli_parse_scan.rs;
// these cover the --redirect / --apply / --sync booleans against a
// different --mode, plus ScanMode::Agent.cli_name() rendering into the
// message. Clap parses each combination fine (no value-dependent conflict
// is expressible); the fold is what rejects them.

mod mode_fold {
    use clap::Parser;
    use socket_patch_cli::commands::scan::{resolve_mode_flags, ScanArgs};
    use socket_patch_cli::{Cli, Commands};

    /// Every env var that could reroute the parse or the fold (superset:
    /// the shared scrub lists from `args.rs`).
    fn with_clean_env<T>(f: impl FnOnce() -> T) -> T {
        let vars: Vec<&str> = socket_patch_cli::args::GLOBAL_ARG_ENV_VARS
            .iter()
            .chain(socket_patch_cli::args::LOCAL_ARG_ENV_VARS.iter())
            .copied()
            .collect();
        let saved: Vec<(&str, Option<String>)> =
            vars.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for k in &vars {
            std::env::remove_var(k);
        }
        let result = f();
        for (k, orig) in saved {
            match orig {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        result
    }

    fn parse_scan(extra: &[&str]) -> ScanArgs {
        let mut argv = vec!["socket-patch", "scan"];
        argv.extend_from_slice(extra);
        let cli = with_clean_env(|| Cli::try_parse_from(&argv)).expect("parse");
        match cli.command {
            Commands::Scan(a) => a,
            _ => panic!("expected Scan"),
        }
    }

    fn fold_err(extra: &[&str]) -> String {
        let mut args = parse_scan(extra);
        resolve_mode_flags(&mut args).expect_err("cross-mode contradiction must error")
    }

    #[test]
    #[serial_test::serial]
    fn mode_vendored_with_redirect_boolean_errors() {
        let err = fold_err(&["--mode", "vendored", "--redirect"]);
        assert!(
            err.contains("--mode vendored cannot be used with --redirect"),
            "clap-style 'cannot be used with' phrasing naming both spellings: {err}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn mode_vendored_with_apply_boolean_errors() {
        let err = fold_err(&["--mode", "vendored", "--apply"]);
        assert!(
            err.contains("--mode vendored cannot be used with --apply"),
            "the --apply arm must name the conflicting boolean: {err}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn mode_hosted_with_sync_boolean_errors() {
        // --sync counts as an agent-mode spelling, so it contradicts hosted.
        let err = fold_err(&["--mode", "hosted", "--sync"]);
        assert!(
            err.contains("--mode hosted cannot be used with --sync"),
            "the --sync arm must name the conflicting boolean: {err}"
        );
    }

    #[test]
    #[serial_test::serial]
    fn mode_agent_with_vendor_boolean_errors_naming_agent() {
        // Pins ScanMode::Agent.cli_name(): "agent" must render into the
        // message (the only user-visible spelling of the variant).
        let err = fold_err(&["--mode", "agent", "--vendor"]);
        assert!(
            err.contains("--mode agent cannot be used with --vendor"),
            "the agent arm must render cli_name() and the boolean: {err}"
        );
    }
}

// ---------------------------------------------------------------------------
// Human terminals reachable without a network: --offline, hosted --prune,
// empty --global-prefix
// ---------------------------------------------------------------------------

/// `scan --offline` on the human path: hard error on stderr, exit 1,
/// nothing on stdout (the JSON twin is covered elsewhere).
#[test]
fn scan_offline_human_path_errors_on_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_scan(tmp.path(), &["--offline"]);
    assert_eq!(code, 1, "offline scan must fail; stderr={stderr:?}");
    assert!(
        stderr.contains("scan requires network access"),
        "the strict-airgap refusal must reach stderr; got {stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "the human offline error must not print a JSON envelope; got {stdout:?}"
    );
}

/// `scan --mode hosted --prune` (human path): the no-GC warning fires
/// BEFORE the crawl, so an empty project suffices — no network at all.
#[test]
fn scan_hosted_prune_human_warns_prune_is_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, _stdout, stderr) = run_scan(tmp.path(), &["--mode", "hosted", "--prune"]);
    assert_eq!(
        code, 0,
        "hosted --prune stays accepted (never a usage error)"
    );
    assert!(
        stderr.contains("Warning (redirect_prune_ignored):"),
        "the ignored-prune warning must reach stderr; got {stderr:?}"
    );
    assert!(
        stderr.contains("runs no GC sweep"),
        "the warning must explain hosted mode runs no GC; got {stderr:?}"
    );
}

/// `--global-prefix <empty dir>`: the global-flavored empty-scan hint.
#[test]
fn scan_empty_global_prefix_prints_global_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let prefix = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &["--global-prefix", prefix.path().to_str().unwrap()],
    );
    assert_eq!(code, 0, "an empty global scan succeeds; stderr={stderr:?}");
    assert!(
        stdout.contains("No global packages found."),
        "the global empty-scan hint must print; got {stdout:?}"
    );
    assert!(
        !stdout.contains("No packages found. Run"),
        "the local-flavored hint must not print on a global scan; got {stdout:?}"
    );
}

// ---------------------------------------------------------------------------
// Zero-package hosted JSON envelope: redirect_prune_ignored rides
// redirect.warnings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_hosted_prune_zero_package_json_carries_the_warning() {
    let mock = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run_scan_human(
        tmp.path(),
        &mock.uri(),
        &["--json", "--mode", "hosted", "--prune"],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(
        v["scannedPackages"], 0,
        "classic keys stay schema-consistent"
    );
    assert_eq!(v["redirect"]["mode"], "hosted");
    assert_eq!(v["redirect"]["redirected"], 0);
    let warnings = v["redirect"]["warnings"]
        .as_array()
        .expect("redirect.warnings array");
    let prune_warning = warnings
        .iter()
        .find(|w| w["code"] == "redirect_prune_ignored")
        .unwrap_or_else(|| panic!("redirect_prune_ignored must ride the envelope: {v}"));
    assert!(
        prune_warning["detail"]
            .as_str()
            .is_some_and(|d| d.contains("runs no GC sweep")),
        "the warning detail must explain the no-op: {prune_warning}"
    );

    // The empty crawl never queries the API.
    let reqs = recorded(&mock).await;
    assert!(
        batch_bodies(&reqs).is_empty(),
        "empty project must not query"
    );
}

// ---------------------------------------------------------------------------
// Paid-tier surface — no other fixture sends tier: "paid"
// ---------------------------------------------------------------------------

/// Paid patch, NO paid access: the `free+paid` table column, the
/// paid-subscription nudge + pricing URL, and the "No downloadable
/// patches" terminal (exit 0, and no detail fetch is even attempted).
#[tokio::test]
async fn scan_paid_patch_without_access_nudges_and_downloads_nothing() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_batch_one(&mock, purl, UUID, "paid", &["CVE-2024-0001"], false).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("0+1"),
        "the table column must render free+paid counts; got {stdout:?}"
    );
    assert!(
        stdout.contains("Summary: 1 package(s) with 0 free patch(es)"),
        "the no-access summary counts FREE patches only; got {stdout:?}"
    );
    assert!(
        stdout.contains("+ 1 additional patch(es) available with paid subscription"),
        "the paid nudge must print; got {stdout:?}"
    );
    assert!(
        stdout.contains("https://socket.dev/pricing"),
        "the pricing URL must print; got {stdout:?}"
    );
    assert!(
        stdout.contains("No downloadable patches (paid subscription required)."),
        "the gated-catalog terminal must print; got {stdout:?}"
    );

    // Returned before the detail-fetch loop: nothing was downloadable.
    let reqs = recorded(&mock).await;
    assert_eq!(
        by_package_gets(&reqs),
        0,
        "no detail fetch may happen when nothing is downloadable"
    );
}

/// Paid patch WITH paid access: the summary counts ALL patches (the
/// can-access arm) and no nudge prints. The deliberately-failing detail
/// fetch (500) then pins the per-package warning and the terminal error.
#[tokio::test]
async fn scan_paid_patch_with_access_counts_all_and_reports_detail_failure() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_batch_one(&mock, purl, UUID, "paid", &[], true).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{}",
            encode_purl(purl)
        )))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &[]);
    assert_eq!(
        code, 1,
        "a failed detail fetch fails the scan; stdout={stdout}"
    );
    assert!(
        stdout.contains("Summary: 1 package(s) with 1 available patch(es)"),
        "the can-access summary counts all patches; got {stdout:?}"
    );
    assert!(
        stdout.contains("0+1"),
        "the free+paid column renders for paid-access users too; got {stdout:?}"
    );
    assert!(
        !stdout.contains("paid subscription"),
        "no nudge for a subscriber; got {stdout:?}"
    );
    assert!(
        stderr.contains("Could not fetch patch details."),
        "the terminal detail-failure must reach stderr; got {stderr:?}"
    );
}

/// The JSON twin pinning the paid counter itself: `paidPatches` counts
/// every non-free tier, `freePatches` stays 0.
#[tokio::test]
async fn scan_json_counts_paid_patches_separately() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_batch_one(&mock, purl, UUID, "paid", &[], false).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &["--json"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["totalPatches"], 1);
    assert_eq!(v["freePatches"], 0);
    assert_eq!(v["paidPatches"], 1, "{v}");
    assert_eq!(v["canAccessPaidPatches"], false);
}

// ---------------------------------------------------------------------------
// Human table: [UPDATE] marker, newer-patches summary, (+N) vuln overflow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_human_table_renders_update_marker_and_vuln_overflow() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    // Three CVEs force the `(+N)` truncation; the manifest's OLD uuid
    // against the batch's NEW uuid drives the update marker.
    mount_batch_one(
        &mock,
        purl,
        UUID,
        "free",
        &["CVE-2024-0003", "CVE-2024-0001", "CVE-2024-0002"],
        false,
    )
    .await;
    mount_by_package(&mock, purl, UUID, serde_json::json!({})).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");
    seed_manifest(tmp.path(), &[(purl, OLD_UUID)]);

    // --dry-run keeps the run read-only past the table (the confirm and
    // apply never run), so no view/blob mocks are needed.
    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &["--dry-run", "--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("[UPDATE]"),
        "the human update marker must render; got {stdout:?}"
    );
    assert!(
        stdout.contains("1 package(s) have newer patches available."),
        "the newer-patches summary must print; got {stdout:?}"
    );
    // Deterministic order: collect_vuln_ids sorts CVEs, so the first two
    // sorted ids show and the third folds into (+1).
    assert!(
        stdout.contains("CVE-2024-0001, CVE-2024-0002 (+1)"),
        "3+ vuln ids must truncate to two plus (+N); got {stdout:?}"
    );
    assert!(
        stdout.contains("[dry-run] Would download and apply 1 patch(es). No changes made."),
        "dry-run must stop before the confirm; got {stdout:?}"
    );
}

/// The per-package detail-fetch warning on the non-silent human path (the
/// terminal "Could not fetch patch details." was previously reached only
/// via --silent runs, skipping the warning line).
#[tokio::test]
async fn scan_human_detail_fetch_failure_warns_per_package() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_batch_one(&mock, purl, UUID, "free", &[], false).await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{}",
            encode_purl(purl)
        )))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 1, "stdout={stdout}; stderr={stderr}");
    assert!(
        stderr.contains(&format!("Warning: could not fetch details for {purl}")),
        "the per-package warning must name the purl on stderr; got {stderr:?}"
    );
    assert!(
        stderr.contains("Could not fetch patch details."),
        "the terminal error follows the warning; got {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// Vendor-owned purls on the human path: the [skip] lines
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_human_skips_vendored_purls_without_downloading() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_batch_one(&mock, purl, UUID, "free", &[], false).await;
    mount_by_package(&mock, purl, UUID, serde_json::json!({})).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");
    // Vendored state ledger claiming the purl (camelCase wire shape).
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("state.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "version": 1,
            "entries": {
                purl: {
                    "ecosystem": "npm",
                    "basePurl": purl,
                    "uuid": UUID,
                    "artifact": {
                        "path": format!(".socket/vendor/npm/{UUID}/minimist-1.2.2.tgz"),
                    },
                    "wiring": [],
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &["--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains(&format!(
            "[skip] {purl} (vendored — run scan --vendor to update)"
        )),
        "the vendored skip line must name the purl and the remedy; got {stdout:?}"
    );
    assert!(
        stdout.contains("No patches selected."),
        "with everything vendor-owned nothing is selected; got {stdout:?}"
    );

    // The vendor-owned purl never downloads: no /view/ fetch happened.
    let reqs = recorded(&mock).await;
    assert_eq!(view_gets(&reqs), 0, "vendor-owned purls must not download");
    // …and no manifest write happened (the skip is calm, not a mutation).
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "a fully-skipped run must not create the manifest"
    );
}

// ---------------------------------------------------------------------------
// "Patches to apply" preview: per-patch vulnerability rendering
// ---------------------------------------------------------------------------
// Every other human-path fixture ships `vulnerabilities: {}`, so the
// CVE/GHSA fold, the "Fixes:" line, and the per-vuln summary lines had
// never executed.

#[tokio::test]
async fn scan_human_preview_renders_vulnerability_details() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_batch_one(&mock, purl, UUID, "free", &[], false).await;
    mount_by_package(
        &mock,
        purl,
        UUID,
        serde_json::json!({
            "GHSA-aaaa-bbbb-cccc": {
                "cves": ["CVE-2024-9999"],
                "summary": "heap overflow in parse",
                "severity": "HIGH",
                "description": "d"
            },
            "GHSA-dddd-eeee-ffff": {
                "cves": [],
                "summary": "no-cve issue",
                "severity": "LOW",
                "description": "d"
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &["--dry-run", "--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("Fixes: "),
        "the Fixes line must print; got {stdout:?}"
    );
    assert!(
        stdout.contains("CVE-2024-9999"),
        "a vuln WITH CVEs contributes its CVE ids; got {stdout:?}"
    );
    assert!(
        stdout.contains("GHSA-dddd-eeee-ffff"),
        "a CVE-less vuln falls back to its GHSA id in Fixes; got {stdout:?}"
    );
    assert!(
        stdout.contains("- CVE-2024-9999: heap overflow in parse"),
        "the per-vuln summary line carries its CVE label; got {stdout:?}"
    );
    assert!(
        stdout.contains("- no-cve issue"),
        "a CVE-less vuln's summary prints without a label; got {stdout:?}"
    );
    assert!(
        stdout.contains("[dry-run] Would download and apply 1 patch(es). No changes made."),
        "dry-run stops before any mutation; got {stdout:?}"
    );
}

// ---------------------------------------------------------------------------
// Human post-apply GC line (`--sync`) — both pluralization arms — and the
// hosted_wiring_retained warning after an in-place apply
// ---------------------------------------------------------------------------

/// Run the full human apply pipeline with `flags` (e.g. `--sync --yes`)
/// and `orphans` pre-seeded manifest entries (plus one orphan blob file
/// each), and return `(code, stdout, stderr, root)`.
async fn run_apply_with_orphans(
    mock: &MockServer,
    orphans: &[(&str, &str, char)],
    flags: &[&str],
) -> (i32, String, String, tempfile::TempDir) {
    let purl = "pkg:npm/silent-target@1.0.0";
    let before = b"before\n";
    mount_one_patch_api(mock, purl, before).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", before);
    let entries: Vec<(&str, &str)> = orphans.iter().map(|(p, u, _)| (*p, *u)).collect();
    seed_manifest(tmp.path(), &entries);
    let blobs = tmp.path().join(".socket/blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    for (_, _, fill) in orphans {
        std::fs::write(blobs.join(fill.to_string().repeat(64)), b"orphan").unwrap();
    }

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), flags);
    (code, stdout, stderr, tmp)
}

#[tokio::test]
async fn scan_sync_human_gc_line_singular_arms() {
    let mock = MockServer::start().await;
    let (code, stdout, stderr, tmp) = run_apply_with_orphans(
        &mock,
        &[("pkg:npm/gone@1.0.0", OLD_UUID, 'c')],
        &["--sync", "--yes"],
    )
    .await;
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("GC: pruned 1 manifest entry and removed 1 orphan file ("),
        "the singular GC line must print; got {stdout:?}"
    );
    // The line reports real work: the orphan entry and blob are gone.
    let manifest =
        std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).expect("manifest");
    let v: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert!(
        v["patches"]["pkg:npm/gone@1.0.0"].is_null(),
        "the orphan entry must be pruned: {v}"
    );
    assert_eq!(
        v["patches"]["pkg:npm/silent-target@1.0.0"]["uuid"], UUID,
        "the applied patch must be recorded: {v}"
    );
    assert!(
        !tmp.path()
            .join(".socket/blobs")
            .join("c".repeat(64))
            .exists(),
        "the orphan blob must be swept"
    );
}

#[tokio::test]
async fn scan_sync_human_gc_line_plural_arms() {
    let mock = MockServer::start().await;
    let (code, stdout, stderr, _tmp) = run_apply_with_orphans(
        &mock,
        &[
            ("pkg:npm/gone@1.0.0", OLD_UUID, 'c'),
            (
                "pkg:npm/also-gone@2.0.0",
                "88888888-8888-4888-8888-888888888888",
                'd',
            ),
        ],
        &["--sync", "--yes"],
    )
    .await;
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("GC: pruned 2 manifest entries and removed 2 orphan files ("),
        "the plural GC line must print; got {stdout:?}"
    );
}

/// After an in-place apply over LIVE hosted wiring (redirect ledger record
/// + a lockfile still resolving the purl to the hosted patch server), the
/// human path must warn that the conversion did not complete.
#[tokio::test]
async fn scan_human_apply_over_live_hosted_wiring_warns_retained() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/silent-target@1.0.0";
    let before = b"before\n";
    mount_one_patch_api(&mock, purl, before).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", before);

    // The live lock: resolves the purl to the hosted patch server (the
    // inventory proof fires on the patch.socket.dev host).
    let lock = serde_json::json!({
        "name": "covgap-scan-root",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "covgap-scan-root",
                "version": "0.0.0",
                "dependencies": { "silent-target": "^1.0.0" }
            },
            "node_modules/silent-target": {
                "version": "1.0.0",
                "resolved": format!(
                    "https://patch.socket.dev/patch/npm/tok/{UUID}/silent-target-1.0.0.tgz"
                ),
                "integrity": "sha512-orig==",
            }
        }
    });
    std::fs::write(
        tmp.path().join("package-lock.json"),
        serde_json::to_string_pretty(&lock).unwrap(),
    )
    .unwrap();

    // The redirect ledger recording that hosted redirect.
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::patch::redirect::RedirectState;
    let mut state = RedirectState::new();
    state.records.insert(
        purl.to_string(),
        PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files: std::collections::HashMap::new(),
            vulnerabilities: std::collections::HashMap::new(),
            description: String::new(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        },
    );
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("redirect-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &["--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stderr.contains("Warning (hosted_wiring_retained):"),
        "the retained-wiring warning must reach stderr; got {stderr:?}"
    );
    assert!(
        stderr.contains(purl),
        "the warning must name the package; got {stderr:?}"
    );
    // The apply itself still happened (warning, not a refusal).
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/silent-target/index.js")).unwrap(),
        b"after\n",
        "the in-place apply proceeds despite the warning"
    );
}

// ---------------------------------------------------------------------------
// embed_vex_human success line
// ---------------------------------------------------------------------------

#[test]
fn scan_human_vex_success_prints_wrote_line() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    // Manifest with one vulnerable record; nothing installed. With
    // --vex-no-verify the manifest is trusted, so the empty-crawl early
    // return still generates the document (no network at all).
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            // npm declared `manual` so VEX generation does not omit the
            // patch (ecosystem_not_setup) and fail the run.
            "setup": { "exclude": [], "manual": ["npm"] },
            "patches": {
                "pkg:npm/vuln-pkg@1.0.0": {
                    "uuid": UUID,
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {
                        "package/index.js": {
                            "beforeHash": "a".repeat(64),
                            "afterHash": "b".repeat(64),
                        }
                    },
                    "vulnerabilities": {
                        "GHSA-aaaa-bbbb-cccc": {
                            "cves": ["CVE-2024-0001"],
                            "summary": "s",
                            "severity": "high",
                            "description": "d"
                        }
                    },
                    "description": "seed",
                    "license": "MIT",
                    "tier": "free",
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let vex_path = tmp.path().join("scan.vex.json");

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &[
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-no-verify",
            "--vex-product",
            "pkg:npm/my-app@1.0.0",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("Wrote OpenVEX document with 1 statement(s) to"),
        "the human VEX success line must print; got {stdout:?}"
    );
    assert!(
        stdout.contains(vex_path.to_str().unwrap()),
        "the success line must name the output path; got {stdout:?}"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vex_path).expect("VEX doc written"))
            .expect("valid OpenVEX JSON");
    assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
    assert_eq!(doc["statements"].as_array().map(|s| s.len()), Some(1));
}

// ---------------------------------------------------------------------------
// PnP layout refusal rides the NON-empty human scan (polyglot repo)
// ---------------------------------------------------------------------------
// The zero-package twin is covered; this pins that another ecosystem's
// discovery does not silently bless the structurally-invisible npm half.

#[tokio::test]
async fn scan_human_pnp_refusal_prints_alongside_other_ecosystems() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    // yarn-berry PnP shape: yarn.lock + .pnp.cjs, no node_modules.
    write_root_package_json(tmp.path());
    std::fs::write(tmp.path().join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
    std::fs::write(tmp.path().join(".pnp.cjs"), "// stub PnP loader\n").unwrap();
    // …plus one installed gem so the scan is NON-empty.
    std::fs::create_dir_all(
        tmp.path()
            .join("vendor/bundle/ruby/3.0.0/gems/rack-2.2.0/lib"),
    )
    .unwrap();

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &[]);
    assert_eq!(
        code, 0,
        "refusals never flip the exit; stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains("Found 1 packages"),
        "the gem must be discovered (non-empty path); got {stderr:?}"
    );
    assert!(
        stderr.contains("Warning (yarn_pnp_unsupported):"),
        "the PnP refusal must print on the non-empty path; got {stderr:?}"
    );
    assert!(
        stderr.contains("Plug'n'Play"),
        "the refusal must name the layout; got {stderr:?}"
    );

    // The scan genuinely queried for the gem — the other ecosystem's
    // discovery ran while the npm half was refused.
    let reqs = recorded(&mock).await;
    let bodies = batch_bodies(&reqs);
    assert_eq!(bodies.len(), 1, "one batch POST for the gem");
    assert!(
        bodies[0].contains("pkg:gem/rack@2.2.0"),
        "the batch body must carry the crawled gem purl; got {}",
        bodies[0]
    );
}

// ---------------------------------------------------------------------------
// Non-TTY human scans: the mode-less scan is report-only, explicit intent
// auto-proceeds
// ---------------------------------------------------------------------------
// Every `Command::output()` child here has a non-TTY stdin. A bare `scan`
// (no `--mode`/`--apply`/`--sync`/`--vendor`/`--redirect`, no `--prune`,
// no `--yes`) must stop BEFORE the download with exit 0 and the get-hint,
// creating nothing under `.socket/`; any intent flag keeps `confirm()`'s
// non-TTY auto-accept and applies.

/// Bare `scan` piped: the discovery, table and per-patch preview print
/// (the report IS the value), then the run stops — no view fetch, no
/// `.socket/`, the installed file untouched — and `confirm()` was never
/// consulted (no "Non-interactive mode" line).
#[tokio::test]
async fn scan_bare_human_non_tty_is_report_only() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_one_patch_api(&mock, purl, b"x\n").await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &[]);
    assert_eq!(
        code, 0,
        "report-only is a success; stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stdout.contains("Patches to apply:") && stdout.contains(purl),
        "the per-patch preview still prints; got {stdout:?}"
    );
    assert!(
        stdout.contains("To apply a patch, run:") && stdout.contains("socket-patch get <CVE-ID>"),
        "the get-hint must print; got {stdout:?}"
    );
    assert!(
        !stderr.contains("Non-interactive mode detected"),
        "confirm() must not be consulted on the report-only path; got {stderr:?}"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "a report-only scan must not create .socket/"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/minimist/index.js")).unwrap(),
        b"x\n",
        "a report-only scan must not patch the installed file"
    );
    let reqs = recorded(&mock).await;
    assert_eq!(
        view_gets(&reqs),
        0,
        "a report-only scan must not download the patch"
    );
}

/// The same piped run with an explicit intent flag (each spelling that
/// folds to `--mode agent`) auto-proceeds through `confirm()`'s non-TTY
/// default and applies.
#[tokio::test]
async fn scan_human_non_tty_explicit_intent_auto_proceeds() {
    for flags in [&["--mode", "agent"][..], &["--apply"][..]] {
        let mock = MockServer::start().await;
        let purl = "pkg:npm/silent-target@1.0.0";
        let before = b"before\n";
        mount_one_patch_api(&mock, purl, before).await;

        let tmp = tempfile::tempdir().unwrap();
        write_root_package_json(tmp.path());
        write_npm_package(tmp.path(), "silent-target", "1.0.0", before);

        let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), flags);
        assert_eq!(code, 0, "flags={flags:?}: stdout={stdout}; stderr={stderr}");
        assert!(
            stderr.contains("Non-interactive mode detected, proceeding with default."),
            "flags={flags:?}: explicit intent keeps confirm()'s non-TTY auto-accept; got {stderr:?}"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("node_modules/silent-target/index.js")).unwrap(),
            b"after\n",
            "flags={flags:?}: the apply must proceed"
        );
        let manifest =
            std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).expect("manifest");
        let v: serde_json::Value = serde_json::from_str(&manifest).unwrap();
        assert_eq!(v["patches"][purl]["uuid"], UUID, "flags={flags:?}: {v}");
    }
}

/// `--prune` alone is explicit intent too (it asks for a `.socket/`
/// mutation): the piped run applies AND garbage-collects.
#[tokio::test]
async fn scan_human_non_tty_prune_counts_as_intent() {
    let mock = MockServer::start().await;
    let (code, stdout, stderr, tmp) = run_apply_with_orphans(
        &mock,
        &[("pkg:npm/gone@1.0.0", OLD_UUID, 'c')],
        &["--prune"],
    )
    .await;
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stderr.contains("Non-interactive mode detected, proceeding with default."),
        "--prune auto-proceeds through confirm(); got {stderr:?}"
    );
    assert!(
        stdout.contains("GC: pruned 1 manifest entry and removed 1 orphan file ("),
        "the GC still runs; got {stdout:?}"
    );
    let manifest =
        std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).expect("manifest");
    let v: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert!(v["patches"]["pkg:npm/gone@1.0.0"].is_null(), "{v}");
    assert_eq!(
        v["patches"]["pkg:npm/silent-target@1.0.0"]["uuid"], UUID,
        "{v}"
    );
}

/// An empty discovery stops every human mode at "No patches available"
/// with exit 0 and no `.socket/`: vendored mode no longer falls through to
/// its vendor step to re-vendor a committed manifest (scan vendors what
/// discovery selects), and hosted mode no longer enters its engine for a
/// zero-package redirect.
#[tokio::test]
async fn scan_human_empty_discovery_stops_in_every_mode() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    for flags in [
        &[][..],
        &["--mode", "vendored"][..],
        &["--mode", "hosted"][..],
        &["--mode", "agent"][..],
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_root_package_json(tmp.path());
        write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");
        let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), flags);
        assert_eq!(code, 0, "flags={flags:?}: stdout={stdout}; stderr={stderr}");
        assert!(
            stdout.contains("No patches available for installed packages."),
            "flags={flags:?}: got {stdout:?}"
        );
        assert!(
            !tmp.path().join(".socket").exists(),
            "flags={flags:?}: an empty discovery must create nothing"
        );
    }
}

// ---------------------------------------------------------------------------
// Human `--mode hosted`: table + update detection parity and the confirm
// ---------------------------------------------------------------------------
// The hosted human arm used to return straight into the redirect engine —
// no results table, no `[UPDATE]` marker, and no prompt (while `get --mode
// hosted` and scan's agent/vendored arms all confirm). It now shares the
// table/update block and confirms before the engine runs.

/// Reference endpoint denying the grant: the engine runs (proving the
/// prompt was accepted) but rewrites nothing, so no lockfile fixture is
/// needed.
async fn mount_forbidden_reference(mock: &MockServer, purl: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { UUID: {
                "status": "forbidden", "url": null, "purl": purl,
                "artifacts": [], "registryOverride": null
            } }
        })))
        .mount(mock)
        .await;
}

fn reference_posts(reqs: &[wiremock::Request]) -> usize {
    reqs.iter()
        .filter(|r| format!("{}", r.method) == "POST" && r.url.path().ends_with("/patches/package"))
        .count()
}

/// Seed a redirect ledger recording `uuid` for `purl` (hosted mode's only
/// patch store), so update detection has an "old" side to compare. Written
/// through the real ledger type so the hosted engine's strict loader
/// accepts it.
fn seed_redirect_ledger(root: &Path, purl: &str, uuid: &str) {
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::patch::redirect::RedirectState;
    let mut state = RedirectState::new();
    state.records.insert(
        purl.to_string(),
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files: std::collections::HashMap::new(),
            vulnerabilities: std::collections::HashMap::new(),
            description: "seed".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        },
    );
    let vendor_dir = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("redirect-state.json"),
        serde_json::to_string_pretty(&state).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn scan_hosted_human_prints_table_updates_and_confirms() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_batch_one(&mock, purl, UUID, "free", &["CVE-2024-0001"], false).await;
    mount_by_package(&mock, purl, UUID, serde_json::json!({})).await;
    mount_forbidden_reference(&mock, purl).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");
    // The ledger records an OLDER patch: the shared update detection must
    // flag the newer offer in hosted mode too.
    seed_redirect_ledger(tmp.path(), purl, OLD_UUID);

    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &["--mode", "hosted"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("VULNERABILITIES") && stdout.contains("CVE-2024-0001"),
        "the results table must print in hosted mode; got {stdout:?}"
    );
    assert!(
        stdout.contains("Summary: 1 package(s) with 1 free patch(es)"),
        "the summary must print in hosted mode; got {stdout:?}"
    );
    assert!(
        stdout.contains("[UPDATE]")
            && stdout.contains("1 package(s) have newer patches available."),
        "update detection must run in hosted mode; got {stdout:?}"
    );
    // `--mode hosted` is explicit intent: the new prompt auto-accepts on a
    // non-TTY stdin and the engine runs.
    assert!(
        stderr.contains("Non-interactive mode detected, proceeding with default."),
        "the hosted confirm must run (and auto-accept) on a non-TTY; got {stderr:?}"
    );
    assert!(
        stdout.contains("Redirected 0 package(s)"),
        "the engine must run after the prompt; got {stdout:?}"
    );
    let reqs = recorded(&mock).await;
    assert_eq!(
        reference_posts(&reqs),
        1,
        "the engine resolved the reference"
    );

    // `--dry-run` previews without confirming (the engine honors it itself).
    let (code, _stdout, stderr) =
        run_scan_human(tmp.path(), &mock.uri(), &["--mode", "hosted", "--dry-run"]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        !stderr.contains("Non-interactive mode detected"),
        "a hosted dry run never prompts; got {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// Declined download confirm via PTY (unix only)
// ---------------------------------------------------------------------------
// A non-TTY mode-less scan never reaches `confirm()` (report-only above),
// and every explicit-intent run auto-accepts there, so only a PTY reaches
// the decline arm: exit 0, the get-hint, and no mutation.

#[cfg(unix)]
mod pty {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Duration;

    use portable_pty::{native_pty_system, CommandBuilder, PtySize};

    /// Spawn the binary in a PTY, send `input`, and collect all output
    /// until exit (the `interactive_prompts_e2e.rs` harness pattern:
    /// reader thread + kill-after-timeout watchdog, no polling).
    fn run_in_pty(args: &[&str], cwd: &Path, input: &str, timeout: Duration) -> (i32, String) {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");

        let mut cmd = CommandBuilder::new(binary());
        for a in args {
            cmd.arg(a);
        }
        cmd.cwd(cwd);
        // Scrub the flag-bound SOCKET_* surface (SOCKET_YES=true would skip
        // the very prompt under test); keep telemetry disabled and the
        // update notifier off — this child gets a REAL terminal, so the
        // stderr-TTY guard does not protect it.
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("SOCKET_") {
                cmd.env_remove(&key);
            }
        }
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
        cmd.env("SOCKET_NO_UPDATE_CHECK", "1");

        let mut child = pair.slave.spawn_command(cmd).expect("spawn in PTY");
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().expect("clone reader");
        let reader_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = reader.read_to_end(&mut buf);
            buf
        });

        let mut killer = child.clone_killer();
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            let _ = killer.kill();
        });

        let mut writer = pair.master.take_writer().expect("take writer");
        let _ = writer.write_all(input.as_bytes());
        let _ = writer.flush();
        drop(writer);

        let status = child.wait().expect("child.wait");
        drop(pair.master);

        let output = reader_handle.join().expect("reader thread join");
        (
            status.exit_code() as i32,
            String::from_utf8_lossy(&output).to_string(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scan_decline_at_download_prompt_exits_zero_without_mutation() {
        let mock = MockServer::start().await;
        let purl = "pkg:npm/minimist@1.2.2";
        mount_batch_one(&mock, purl, UUID, "free", &[], false).await;
        mount_by_package(&mock, purl, UUID, serde_json::json!({})).await;

        let tmp = tempfile::tempdir().unwrap();
        write_root_package_json(tmp.path());
        write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");

        let uri = mock.uri();
        let cwd = tmp.path().to_path_buf();
        let (code, output) = tokio::task::spawn_blocking(move || {
            run_in_pty(
                &[
                    "scan",
                    "--api-url",
                    &uri,
                    "--api-token",
                    "fake-token-for-test",
                    "--org",
                    ORG_SLUG,
                ],
                &cwd,
                "n\n",
                Duration::from_secs(60),
            )
        })
        .await
        .expect("spawn_blocking join");

        assert_eq!(code, 0, "declining is not an error; output:\n{output}");
        // The prompt genuinely ran (a regression auto-proceeding in a TTY
        // would skip it — and would mutate, failing below too).
        assert!(
            output.contains("Download and apply 1 patch(es)?"),
            "the confirm prompt must have shown; got:\n{output}"
        );
        assert!(
            output.contains("To apply a patch, run:"),
            "the decline hint must print; got:\n{output}"
        );
        assert!(
            output.contains("socket-patch get <CVE-ID>"),
            "the decline hint names the get command; got:\n{output}"
        );

        // Decline mutates nothing: no manifest, untouched file, no download.
        assert!(
            !tmp.path().join(".socket/manifest.json").exists(),
            "declining must not create the manifest"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("node_modules/minimist/index.js")).unwrap(),
            b"x\n",
            "declining must not patch the installed file"
        );
        let reqs = recorded(&mock).await;
        assert_eq!(view_gets(&reqs), 0, "declining must not download the patch");
    }

    /// The hosted twin: declining "Redirect N package(s) …?" exits 0 with
    /// the hosted get-hint and never enters the engine (no reference
    /// resolve, no `.socket/`).
    #[tokio::test(flavor = "multi_thread")]
    async fn scan_hosted_decline_at_redirect_prompt_exits_zero_without_mutation() {
        let mock = MockServer::start().await;
        let purl = "pkg:npm/minimist@1.2.2";
        mount_batch_one(&mock, purl, UUID, "free", &[], false).await;
        mount_by_package(&mock, purl, UUID, serde_json::json!({})).await;
        mount_forbidden_reference(&mock, purl).await;

        let tmp = tempfile::tempdir().unwrap();
        write_root_package_json(tmp.path());
        write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");

        let uri = mock.uri();
        let cwd = tmp.path().to_path_buf();
        let (code, output) = tokio::task::spawn_blocking(move || {
            run_in_pty(
                &[
                    "scan",
                    "--mode",
                    "hosted",
                    "--api-url",
                    &uri,
                    "--api-token",
                    "fake-token-for-test",
                    "--org",
                    ORG_SLUG,
                ],
                &cwd,
                "n\n",
                Duration::from_secs(60),
            )
        })
        .await
        .expect("spawn_blocking join");

        assert_eq!(code, 0, "declining is not an error; output:\n{output}");
        assert!(
            output.contains("Redirect 1 package(s) to the hosted patch server?"),
            "the hosted confirm prompt must have shown; got:\n{output}"
        );
        assert!(
            output.contains("To redirect a package, run:")
                && output.contains("socket-patch get <CVE-ID> --mode hosted"),
            "the hosted decline hint must print; got:\n{output}"
        );
        assert!(
            !output.contains("Redirected"),
            "declining must not enter the redirect engine; got:\n{output}"
        );
        assert!(
            !tmp.path().join(".socket").exists(),
            "declining must create nothing under .socket/"
        );
        let reqs = recorded(&mock).await;
        assert_eq!(
            reference_posts(&reqs),
            0,
            "declining must not resolve the hosted reference"
        );
    }
}

// ---------------------------------------------------------------------------
// Invalid binary lockfiles must report a format error in every scan mode.
// ---------------------------------------------------------------------------

fn write_invalid_bun_lockb_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-lockb-only", "version": "0.0.0", "dependencies": { "minimist": "1.2.2" } }"#,
    )
    .unwrap();
    std::fs::write(root.join("bun.lockb"), b"\0binary bun lockfile").unwrap();
}

fn bun_lockb_warning(v: &serde_json::Value) -> Option<&serde_json::Value> {
    v["warnings"]
        .as_array()
        .and_then(|ws| ws.iter().find(|w| w["code"] == "bun_lockb_invalid"))
}

/// A corrupt binary lock must remain visible as a format error on the
/// zero-package path, including when hosted mode has nothing to redirect.
#[test]
fn scan_invalid_bun_lockb_warns_instead_of_silent_success() {
    for mode in [None, Some("vendored"), Some("hosted")] {
        let tmp = tempfile::tempdir().unwrap();
        write_invalid_bun_lockb_project(tmp.path());
        let mut args = vec!["--json"];
        if let Some(mode) = mode {
            args.extend(["--mode", mode]);
        }
        let (code, stdout, stderr) = run_scan(tmp.path(), &args);
        assert_eq!(
            code, 0,
            "mode={mode:?}: refusals never flip the exit; stdout={stdout}; stderr={stderr}"
        );
        let v: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("bad JSON ({e}): {stdout}"));
        assert_eq!(v["status"], "success", "mode={mode:?}: {v}");
        assert_eq!(v["scannedPackages"], 0, "mode={mode:?}: {v}");
        assert_eq!(v["lockfileOnlyPackages"], 0, "mode={mode:?}: {v}");
        let warning = bun_lockb_warning(&v).unwrap_or_else(|| {
            panic!("mode={mode:?}: warnings[] must carry bun_lockb_invalid: {v}")
        });
        let detail = warning["detail"].as_str().unwrap_or_default();
        assert!(
            detail.contains("cannot inventory bun.lockb"),
            "mode={mode:?}: the binary format error must name its file: {detail}"
        );
        assert!(
            !stdout.contains("Warning ("),
            "mode={mode:?}: the human warning line must not leak into the JSON stream: {stdout}"
        );
    }

    // Human path: the same diagnosis as a stderr `Warning (code): detail`
    // line, exit 0, and the generic "No packages found" hint still prints.
    let tmp = tempfile::tempdir().unwrap();
    write_invalid_bun_lockb_project(tmp.path());
    let (code, stdout, stderr) = run_scan(tmp.path(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stderr.contains("Warning (bun_lockb_invalid): cannot inventory bun.lockb"),
        "the human path must name the layout and the code; got {stderr:?}"
    );
    assert!(
        stderr.contains("cannot inventory bun.lockb"),
        "the human path must carry the remedy; got {stderr:?}"
    );
    assert!(stdout.contains("No packages found"), "{stdout:?}");
}

/// Installed dependencies do not suppress binary format diagnoses in any
/// mode, including when hosted mode finds no patches to redirect.
#[tokio::test]
async fn scan_nonempty_keeps_the_bun_lockb_discovery_warning_in_every_mode() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    for mode in [None, Some("vendored"), Some("hosted")] {
        let tmp = tempfile::tempdir().unwrap();
        write_invalid_bun_lockb_project(tmp.path());
        write_npm_package(tmp.path(), "minimist", "1.2.2", b"module.exports = 1;\n");
        let uri = mock.uri();
        let mut args = vec![
            "--json",
            "--api-url",
            uri.as_str(),
            "--api-token",
            "fake-token-for-test",
            "--org",
            ORG_SLUG,
        ];
        if let Some(mode) = mode {
            args.extend(["--mode", mode]);
        }
        let (code, stdout, stderr) = run_scan(tmp.path(), &args);
        assert_eq!(code, 0, "mode={mode:?}: stdout={stdout}; stderr={stderr}");
        let v: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("bad JSON ({e}): {stdout}"));
        assert_eq!(v["scannedPackages"], 1, "mode={mode:?}: {v}");
        assert_eq!(v["status"], "success", "mode={mode:?}: {v}");
        let warning = bun_lockb_warning(&v).unwrap_or_else(|| {
            panic!("mode={mode:?}: the non-empty envelope must keep bun_lockb_invalid: {v}")
        });
        assert!(
            warning["detail"]
                .as_str()
                .is_some_and(|d| d.contains("cannot inventory bun.lockb")),
            "mode={mode:?}: {v}"
        );
    }

    // Human hosted path: the same warning line on stderr before the driver
    // runs (exit 0; nothing to redirect).
    let tmp = tempfile::tempdir().unwrap();
    write_invalid_bun_lockb_project(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"module.exports = 1;\n");
    let (code, stdout, stderr) = run_scan_human(tmp.path(), &mock.uri(), &["--mode", "hosted"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stderr.contains("Warning (bun_lockb_invalid):"),
        "the human hosted path must keep the warning; got {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// Human `--mode vendored --dry-run`: the `[would-refuse]` lines
// ---------------------------------------------------------------------------
// The contract promises the human vendored preview names what the wet run
// would refuse. Only `get --mode vendored --dry-run` printed the lines; a
// human `scan --mode vendored --dry-run` on a refused Bun project said
// "Would download and vendor 1 patch(es). No changes made." for a run that
// exits 1. Both commands now share the printer.

/// A real bun 1.3.14 lockfileVersion-1 workspace lock resolving minimist
/// from the registry: the shape the vendored preflight refuses.
fn write_bun_v1_workspace_lock(root: &Path) {
    std::fs::write(
        root.join("bun.lock"),
        "{\n  \"lockfileVersion\": 1,\n  \"configVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"covgap-scan-root\",\n      \"dependencies\": {\n        \"consumer\": \"workspace:*\",\n      },\n    },\n    \"packages/consumer\": {\n      \"name\": \"consumer\",\n      \"version\": \"1.0.0\",\n      \"dependencies\": {\n        \"minimist\": \"1.2.2\",\n      },\n    },\n  },\n  \"packages\": {\n    \"consumer\": [\"consumer@workspace:packages/consumer\"],\n\n    \"minimist\": [\"minimist@1.2.2\", \"\", {}, \"sha512-AAAA==\"],\n  }\n}\n",
    )
    .unwrap();
}

#[tokio::test]
async fn scan_human_vendored_dry_run_names_would_refuse_records() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_batch_one(&mock, purl, UUID, "free", &[], false).await;
    mount_by_package(&mock, purl, UUID, serde_json::json!({})).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2", b"x\n");
    write_bun_v1_workspace_lock(tmp.path());

    let (code, stdout, stderr) = run_scan_human(
        tmp.path(),
        &mock.uri(),
        &["--mode", "vendored", "--dry-run"],
    );
    assert_eq!(
        code, 0,
        "a preview never flips the exit; stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stdout.contains("[dry-run] Would download and vendor 1 patch(es). No changes made."),
        "the count line stays; got {stdout:?}"
    );
    assert!(
        stdout.contains(&format!(
            "  [would-refuse] {purl} (vendor_bun_workspace_unsupported): "
        )),
        "the human scan preview must name the refusal like get's does; got {stdout:?}"
    );
    assert!(
        stdout.contains("lockfileVersion-1 lock") && stdout.contains("--mode hosted"),
        "the engine's detail rides along; got {stdout:?}"
    );
    // Nothing written: no manifest, no blobs, no vendor ledger. (The dry-run
    // return precedes the human arm's baseline pre-verify, so this preview
    // fetches no patch view either; the on-disk state is the oracle here.)
    assert!(
        !tmp.path().join(".socket").exists(),
        "a dry run writes nothing"
    );

    // `--silent`: informational, so nothing at all on stdout.
    let (code, stdout, _) = run_scan_human(
        tmp.path(),
        &mock.uri(),
        &["--mode", "vendored", "--dry-run", "--silent"],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.trim().is_empty(),
        "silent dry run prints nothing:\n{stdout}"
    );
}
