//! Coverage-gap tests for `commands/scan/hosted.rs` (coverage audit 2026-09).
//!
//! Targets the audited never-executed branches of `run_redirect_selected`:
//! the `bad_purl` / `no_url` reference skips, the WET takeover refusal
//! (vendored revert fails closed) and its refused-purl cleanup, the cargo
//! socket-owned-wiring-without-ledger refusal, the bun.lockb dry-run /
//! failed-migration / unrestorable-backup arms, the live
//! present-but-unreadable pnpm-workspace.yaml fallback, the hosted-direction
//! `redirect_supersedes_vendored` warning, and the human-output lines
//! (dry-run verb, migration/rush/pnpm/takeover warning loops, the VEX
//! summary and dry-run VEX skip).
//!
//! Everything runs the built binary as a subprocess via
//! `common::run_with_env` (hermetic `SOCKET_*` scrub, child-only env
//! injection) so both the `--json` envelope and the human stdout/stderr can
//! be read back; no parent-process env is ever mutated, so no
//! serialization is needed.

use std::path::Path;

use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const NAME: &str = "covgap-hosted";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:npm/covgap-hosted@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const HOSTED_URL: &str = "http://patch.test/patch/npm/covgap-hosted/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/covgap-hosted-1.0.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const UPSTREAM_SHA512: &str = "sha512-UPSTREAMupstream==";
const GHSA: &str = "GHSA-cvgp-hstd-aaaa";

// ───────────────────────────── API mocks ─────────────────────────────

/// Batch discovery + per-package search for one `(purl, uuid)` pair.
async fn mock_discovery(server: &MockServer, purl: &str, uuid: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": uuid, "purl": purl, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "covgap hosted fixture"
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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [{
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// The reference endpoint with an arbitrary `results` object — the seam the
/// bad-purl / no-url server shapes are injected through.
async fn mock_reference_results(server: &MockServer, results: Value) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": results })))
        .mount(server)
        .await;
}

/// The standard granted tarball reference for `(uuid, purl, url)`.
async fn mock_granted_reference(server: &MockServer, uuid: &str, purl: &str, url: &str) {
    mock_reference_results(
        server,
        json!({
            uuid: {
                "status": "granted",
                "url": url,
                "purl": purl,
                "artifacts": [{
                    "kind": "tarball",
                    "url": url,
                    "integrity": { "sha512": PATCHED_SHA512 }
                }],
                "registryOverride": null
            }
        }),
    )
    .await;
}

/// `view/{uuid}` — the record a confirmed redirect persists for VEX.
async fn mock_view(server: &MockServer, uuid: &str, purl: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "a".repeat(64),
                    "afterHash": "b".repeat(64),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-9"],
                    "summary": "covgap hosted vex fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

// ─────────────────────────── project fixtures ───────────────────────────

/// npm project: package.json + installed node_modules copy + a
/// lockfileVersion-3 package-lock.json resolving `name` upstream (the
/// `in_process_redirect.rs` `write_project` shape).
fn write_npm_project(root: &Path, name: &str) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{name}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{name}": "{VERSION}" }} }},
    "node_modules/{name}": {{
      "version": "{VERSION}",
      "resolved": "https://registry.npmjs.org/{name}/-/{name}-{VERSION}.tgz",
      "integrity": "{UPSTREAM_SHA512}"
    }}
  }}
}}
"#
        ),
    )
    .unwrap();
}

/// pnpm project whose only lockfile is a v9 root pnpm-lock.yaml (the
/// `in_process_redirect_pnpm.rs` shape).
fn write_pnpm_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(
        root.join("pnpm-lock.yaml"),
        format!(
            "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      {NAME}:
        specifier: {VERSION}
        version: {VERSION}

packages:
  {NAME}@{VERSION}:
    resolution: {{integrity: {UPSTREAM_SHA512}}}

snapshots:
  {NAME}@{VERSION}: {{}}
"
        ),
    )
    .unwrap();
}

/// bun project locked to a BINARY bun.lockb (never parsed): package.json +
/// installed copy + placeholder lockb bytes.
fn write_bun_lockb_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "^{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(root.join("bun.lockb"), b"BUN-BINARY-PLACEHOLDER").unwrap();
}

/// Install a fake `bun` shim into `<root>/fakebin` and return the PATH value
/// that puts it first (child-env only — the parent PATH is never touched).
#[cfg(unix)]
fn install_bun_shim(root: &Path, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let bin_dir = root.join("fakebin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let shim = bin_dir.join("bun");
    std::fs::write(&shim, body).unwrap();
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
    format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

/// Rush monorepo: rush.json + the common source-of-truth lock resolving the
/// patched package + repo-state.json (the pnpmShrinkwrapHash carrier). No
/// root package.json/lock pair.
fn write_rush_project(root: &Path) {
    std::fs::write(root.join("rush.json"), r#"{ "rushVersion": "5.100.0" }"#).unwrap();
    let common_dir = root.join("common/config/rush");
    std::fs::create_dir_all(&common_dir).unwrap();
    std::fs::write(
        common_dir.join("pnpm-lock.yaml"),
        format!(
            "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      {NAME}:
        specifier: {VERSION}
        version: {VERSION}

packages:
  {NAME}@{VERSION}:
    resolution: {{integrity: {UPSTREAM_SHA512}}}

snapshots:
  {NAME}@{VERSION}: {{}}
"
        ),
    )
    .unwrap();
    std::fs::write(
        common_dir.join("repo-state.json"),
        "{\n  \"pnpmShrinkwrapHash\": \"deadbeef\",\n  \"preventManualShrinkwrapChanges\": true\n}\n",
    )
    .unwrap();
}

/// A hand-written vendored ledger (`.socket/vendor/state.json`) claiming
/// `purl` with the given uuid and npm flavor (camelCase, the serde shape
/// `vendor::load_state` parses). Empty wiring — the classifiers and reverts
/// under test never need recorded lock fragments.
fn write_vendor_state(root: &Path, purl: &str, uuid: &str, flavor: &str) {
    let state = json!({
        "version": 1,
        "entries": {
            purl: {
                "ecosystem": "npm",
                "basePurl": purl,
                "uuid": uuid,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{uuid}/{NAME}-{VERSION}.tgz")
                },
                "wiring": [],
                "flavor": flavor
            }
        }
    });
    let dir = root.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    let mut bytes = serde_json::to_vec_pretty(&state).unwrap();
    bytes.push(b'\n');
    std::fs::write(dir.join("state.json"), bytes).unwrap();
}

// ───────────────────────────── runners ─────────────────────────────

/// `scan --mode hosted` (human output) via the hermetic subprocess runner.
fn scan_hosted(
    cwd: &Path,
    api_url: &str,
    extra: &[&str],
    env: &[(&str, &str)],
) -> (i32, String, String) {
    let cwd_s = cwd.to_str().unwrap().to_string();
    let mut args = vec![
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--cwd",
        &cwd_s,
        "--api-url",
        api_url,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    args.extend_from_slice(extra);
    common::run_with_env(cwd, &args, env)
}

/// `scan --mode hosted --json` → `(exit code, parsed envelope)`.
fn scan_hosted_json(
    cwd: &Path,
    api_url: &str,
    extra: &[&str],
    env: &[(&str, &str)],
) -> (i32, Value) {
    let mut args = vec!["--json"];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = scan_hosted(cwd, api_url, &args, env);
    let doc = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be the JSON envelope ({e});\nstdout=\n{stdout}\nstderr=\n{stderr}")
    });
    (code, doc)
}

/// The `code` of every warning in the redirect envelope.
fn warning_codes(doc: &Value) -> Vec<String> {
    doc["redirect"]["warnings"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|w| w["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The `detail` of the first warning carrying `code` (panics when absent).
fn warning_detail<'a>(doc: &'a Value, code: &str) -> &'a str {
    doc["redirect"]["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|w| w["code"] == code)
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_else(|| panic!("expected a `{code}` warning: {doc:#}"))
}

// ───────────────────── reference-skip reasons (835-844) ─────────────────────

/// A granted reference whose purl fails `parse_purl_simple` is skipped with
/// reason `bad_purl` — never redirected, never recorded — and the project is
/// left byte-untouched.
#[tokio::test]
async fn granted_reference_with_unparseable_purl_is_skipped_as_bad_purl() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_reference_results(
        &server,
        json!({
            UUID: {
                "status": "granted",
                "url": HOSTED_URL,
                "purl": "not-a-purl",
                "artifacts": [{
                    "kind": "tarball",
                    "url": HOSTED_URL,
                    "integrity": { "sha512": PATCHED_SHA512 }
                }],
                "registryOverride": null
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "a fully-skipped redirect still exits 0: {doc:#}");
    assert_eq!(
        doc["redirect"]["skipped"],
        json!([{ "purl": "not-a-purl", "uuid": UUID, "reason": "bad_purl" }]),
        "the skipped entry must carry the SERVED purl and the bad_purl reason: {doc:#}"
    );
    assert_eq!(doc["redirect"]["redirected"], 0, "envelope: {doc:#}");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "a bad-purl grant must leave the lockfile byte-identical"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "a zero-redirect run must not write a redirect ledger"
    );
}

/// A granted reference with `url: null` is skipped with reason `no_url` —
/// a grant without an artifact URL must never be redirected with an empty
/// URL.
#[tokio::test]
async fn granted_reference_without_url_is_skipped_as_no_url() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_reference_results(
        &server,
        json!({
            UUID: {
                "status": "granted",
                "url": null,
                "purl": PURL,
                "artifacts": [],
                "registryOverride": null
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "a fully-skipped redirect still exits 0: {doc:#}");
    assert_eq!(
        doc["redirect"]["skipped"],
        json!([{ "purl": PURL, "uuid": UUID, "reason": "no_url" }]),
        "the skipped entry must carry the no_url reason: {doc:#}"
    );
    assert_eq!(doc["redirect"]["redirected"], 0, "envelope: {doc:#}");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "a url-less grant must leave the lockfile byte-identical"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "a zero-redirect run must not write a redirect ledger"
    );
}

// ──────────────── wet takeover refusal + refused-purl cleanup ────────────────

/// WET-run takeover refusal (the fail-closed half of the takeover contract):
/// a vendored ledger entry whose flavor names a backend this build lacks
/// makes `dispatch_revert_one` fail closed, so the purl is refused —
/// `redirect_vendored_revert_failed` warning, a `vendored_revert_failed`
/// skip, `redirected: 0` — and the refused-purl cleanup drops its override
/// so the rewrite can never land. The vendored ledger and the lockfile stay
/// byte-identical. The human re-run prints the same refusal through the
/// takeover pre-warning loop.
#[tokio::test]
async fn wet_takeover_refuses_unrevertable_vendored_flavor_fail_closed() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    write_vendor_state(
        tmp.path(),
        PURL,
        "33333333-3333-4333-8333-333333333333",
        "no-such-flavor",
    );
    let state_before = std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap();
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "a refused takeover still exits 0: {doc:#}");
    let detail = warning_detail(&doc, "redirect_vendored_revert_failed");
    assert!(
        detail.contains("NOT redirected") && detail.contains("vendor --revert"),
        "the refusal must name the fail-closed outcome and the manual path: {detail}"
    );
    assert!(
        doc["redirect"]["skipped"]
            .as_array()
            .is_some_and(|s| s.iter().any(|e| e["purl"] == PURL
                && e["uuid"] == UUID
                && e["reason"] == "vendored_revert_failed")),
        "the refusal must be accounted as skipped: {doc:#}"
    );
    assert_eq!(
        doc["redirect"]["redirected"], 0,
        "a refused purl is never counted redirected: {doc:#}"
    );
    // The refused-purl cleanup dropped the override: the rewrite landed
    // nothing, so the lock is byte-identical and hosted-URL-free.
    let lock_after = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(
        lock_after, lock_before,
        "the retained-out override must never reach the rewriters"
    );
    assert!(
        !String::from_utf8_lossy(&lock_after).contains(HOSTED_URL),
        "the hosted URL must never appear in a refused lock"
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap(),
        state_before,
        "a failed revert must leave the vendored ledger byte-identical"
    );

    // Human re-run (idempotent — nothing was touched): the takeover
    // pre-warning loop prints the refusal to stderr, and the skipped line
    // prints the bare purl/reason.
    let (code, stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "human refusal run exits 0; stderr=\n{stderr}");
    assert!(
        stdout.contains("Redirected 0 package(s)"),
        "anchor: the human redirect branch ran; stdout=\n{stdout}"
    );
    assert!(
        stderr.contains(&format!("skipped {PURL} (vendored_revert_failed)")),
        "the human skipped line must name purl + reason; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("  warning: ") && stderr.contains("could not be reverted"),
        "the takeover pre-warning must reach human stderr; stderr=\n{stderr}"
    );
}

// ───────────── cargo wiring-without-ledger refusal (1104-1114) ─────────────

/// A cargo purl with SOCKET-OWNED `[patch.crates-io]` wiring in
/// .cargo/config.toml but NO vendored ledger must be refused: the originals
/// needed to revert are unrecoverable, so redirecting on top would wedge the
/// project. The refusal happens before any rewrite — config and lock stay
/// byte-identical.
#[tokio::test]
async fn cargo_socket_owned_wiring_without_ledger_refuses_the_redirect() {
    const CNAME: &str = "covgap-cargo-dep";
    const CPURL: &str = "pkg:cargo/covgap-cargo-dep@1.0.0";
    const CUUID: &str = "44444444-4444-4444-8444-444444444444";
    let server = MockServer::start().await;
    mock_discovery(&server, CPURL, CUUID).await;
    let hosted_url = format!(
        "{}/patch/cargo/{CNAME}/1.0.0/55555555-5555-4555-8555-555555555555/{CUUID}/{CNAME}-1.0.0.crate",
        server.uri()
    );
    let cksum = "a".repeat(64);
    mock_reference_results(
        &server,
        json!({
            CUUID: {
                "status": "granted",
                "url": hosted_url,
                "purl": CPURL,
                "artifacts": [{
                    "kind": "tarball",
                    "url": hosted_url,
                    "integrity": { "sha256": cksum }
                }],
                "registryOverride": {
                    "kind": "cargo-sparse",
                    "indexUrl": format!("sparse+{}/index/", server.uri()),
                    "identifiers": {
                        "name": CNAME,
                        "version": "1.0.0",
                        "cargoCksumSha256": cksum,
                    }
                }
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{CNAME} = \"1.0.0\"\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        format!(
            "version = 3\n\n[[package]]\nname = \"consumer\"\nversion = \"0.1.0\"\ndependencies = [\n \"{CNAME}\",\n]\n\n[[package]]\nname = \"{CNAME}\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{cksum}\"\n"
        ),
    )
    .unwrap();
    // Socket-owned [patch.crates-io] wiring — but NO .socket/vendor/state.json.
    std::fs::create_dir_all(root.join(".cargo")).unwrap();
    std::fs::write(
        root.join(".cargo/config.toml"),
        format!(
            "[patch.crates-io]\n{CNAME} = {{ path = \".socket/vendor/cargo/{CUUID}/{CNAME}-1.0.0\" }}\n"
        ),
    )
    .unwrap();
    let config_before = std::fs::read(root.join(".cargo/config.toml")).unwrap();
    let lock_before = std::fs::read(root.join("Cargo.lock")).unwrap();
    let manifest_before = std::fs::read(root.join("Cargo.toml")).unwrap();

    // Hermetic CARGO_HOME so the cargo crawler never scans the host's real
    // registry cache.
    let cargo_home = root.join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();
    let cargo_home_s = cargo_home.to_str().unwrap().to_string();
    let (code, doc) = scan_hosted_json(
        root,
        &server.uri(),
        &[],
        &[("CARGO_HOME", cargo_home_s.as_str())],
    );

    assert_eq!(code, 0, "a refused cargo takeover still exits 0: {doc:#}");
    let detail = warning_detail(&doc, "redirect_vendored_revert_failed");
    assert!(
        detail.contains("no usable vendored ledger entry"),
        "the refusal must name the missing ledger: {detail}"
    );
    assert!(
        doc["redirect"]["skipped"]
            .as_array()
            .is_some_and(|s| s.iter().any(|e| e["purl"] == CPURL
                && e["reason"] == "vendored_revert_failed")),
        "the refusal must be accounted as skipped: {doc:#}"
    );
    assert_eq!(doc["redirect"]["redirected"], 0, "envelope: {doc:#}");
    assert_eq!(
        std::fs::read(root.join(".cargo/config.toml")).unwrap(),
        config_before,
        "the socket-owned wiring must be left for manual recovery"
    );
    assert_eq!(
        std::fs::read(root.join("Cargo.lock")).unwrap(),
        lock_before,
        "the lock must stay byte-identical"
    );
    assert_eq!(
        std::fs::read(root.join("Cargo.toml")).unwrap(),
        manifest_before,
        "the manifest must stay byte-identical"
    );
}

// ───────────────────────── bun.lockb arms ─────────────────────────

/// `--dry-run` over a bun.lockb project warns `redirect_bun_lockb_would_migrate`
/// WITHOUT spawning bun: no shim is installed and PATH is untouched, so any
/// spawn would either fail (emitting the unsupported warning instead) or —
/// on a bun-equipped host — actually migrate; neither may happen. The human
/// leg prints the same detail through the migration warning loop.
#[tokio::test]
async fn bun_lockb_dry_run_warns_would_migrate_without_spawning_bun() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_bun_lockb_project(tmp.path());
    let lockb_before = std::fs::read(tmp.path().join("bun.lockb")).unwrap();

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &["--dry-run"], &[]);
    assert_eq!(code, 0, "dry-run over a lockb project exits 0: {doc:#}");
    assert_eq!(doc["redirect"]["dryRun"], true, "envelope: {doc:#}");
    let detail = warning_detail(&doc, "redirect_bun_lockb_would_migrate");
    assert!(
        detail.contains("re-run without --dry-run"),
        "the preview must say how to apply: {detail}"
    );
    assert!(
        !warning_codes(&doc).contains(&"redirect_bun_lockb_unsupported".to_string()),
        "a dry-run must never report a migration ATTEMPT (proof no bun was \
         spawned): {doc:#}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("bun.lockb")).unwrap(),
        lockb_before,
        "dry-run must leave bun.lockb byte-identical"
    );
    assert!(
        !tmp.path().join("bun.lock").exists(),
        "dry-run must not create a text lock"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "dry-run must not write a redirect ledger"
    );

    // Human leg: the migration-warning loop prints the bare detail string.
    let (code, _stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &["--dry-run"], &[]);
    assert_eq!(code, 0, "human dry-run exits 0; stderr=\n{stderr}");
    assert!(
        stderr.contains("  warning: bun.lockb would be migrated"),
        "the would-migrate detail must reach human stderr; stderr=\n{stderr}"
    );
}

/// A FAILED bun.lockb migration (bun exits 1) degrades to
/// `redirect_bun_lockb_unsupported` — the redirect cannot pin a binary
/// lockfile — with bun.lockb left in place as the rewriter's presence-only
/// refusal target. Deterministic via a PATH shim: relying on bun being
/// absent from the runner would flake the day bun lands on it.
#[cfg(unix)]
#[tokio::test]
async fn failed_bun_lockb_migration_warns_unsupported_and_keeps_the_binary_lock() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_bun_lockb_project(tmp.path());
    let lockb_before = std::fs::read(tmp.path().join("bun.lockb")).unwrap();
    let path_value = install_bun_shim(tmp.path(), "#!/bin/sh\nexit 1\n");

    let (code, doc) = scan_hosted_json(
        tmp.path(),
        &server.uri(),
        &[],
        &[("PATH", path_value.as_str())],
    );
    assert_eq!(code, 0, "a failed migration is a warning, not an error: {doc:#}");
    let detail = warning_detail(&doc, "redirect_bun_lockb_unsupported");
    assert!(
        detail.contains("cannot pin a binary lockfile"),
        "the unsupported warning must explain the refusal: {detail}"
    );
    assert_eq!(doc["redirect"]["redirected"], 0, "envelope: {doc:#}");
    assert_eq!(
        std::fs::read(tmp.path().join("bun.lockb")).unwrap(),
        lockb_before,
        "the binary lock must survive the failed migration byte-identically"
    );
    assert!(
        !tmp.path().join("bun.lock").exists(),
        "no text lock may appear after a failed migration"
    );

    // Human leg: the migration-warning loop prints the bare detail.
    let (code, _stdout, stderr) = scan_hosted(
        tmp.path(),
        &server.uri(),
        &[],
        &[("PATH", path_value.as_str())],
    );
    assert_eq!(code, 0, "human run exits 0; stderr=\n{stderr}");
    assert!(
        stderr.contains("  warning: bun.lockb could not be migrated"),
        "the unsupported detail must reach human stderr; stderr=\n{stderr}"
    );
}

/// Zero-redirect migration whose bun.lockb RESTORE cannot run (the
/// pre-migration read failed — chmod 000, exists() still true): the run must
/// KEEP the ledger's removal record and warn
/// `redirect_bun_lockb_migrated_without_redirect` (git history is the
/// restore path) instead of silently converting the lockfile format with no
/// record. The restored-successfully sibling branch is pinned by
/// `zero_redirect_restores_bun_lockb_after_migration` in
/// in_process_redirect.rs.
#[cfg(unix)]
#[tokio::test]
async fn unreadable_bun_lockb_backup_keeps_the_migration_and_warns_loudly() {
    use std::os::unix::fs::PermissionsExt;
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_bun_lockb_project(tmp.path());
    // The shim re-locks to a DIFFERENT version so no redirect lands in the
    // migrated bun.lock (the zero-redirect shape).
    let bun_lock_body = format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"packages\": {{\n    \
         \"{NAME}\": [\"{NAME}@2.0.0\", \"\", {{}}, \"{UPSTREAM_SHA512}\"],\n  \
         }}\n}}\n"
    );
    let path_value = install_bun_shim(
        tmp.path(),
        &format!(
            "#!/bin/sh\n\
             cat > bun.lock <<'LOCK'\n{bun_lock_body}LOCK\n\
             rm -f bun.lockb\n\
             exit 0\n"
        ),
    );
    // exists() stays true, std::fs::read fails → no backup to restore from.
    let lockb = tmp.path().join("bun.lockb");
    std::fs::set_permissions(&lockb, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&lockb).is_ok() {
        // Running as root: mode bits don't apply, the backup read succeeds
        // and the restore branch (already covered elsewhere) runs instead.
        println!("SKIP: running as root — chmod 000 cannot make the backup unreadable");
        return;
    }

    let (code, doc) = scan_hosted_json(
        tmp.path(),
        &server.uri(),
        &[],
        &[("PATH", path_value.as_str())],
    );
    assert_eq!(code, 0, "the kept migration is a warning, not an error: {doc:#}");
    let detail = warning_detail(&doc, "redirect_bun_lockb_migrated_without_redirect");
    assert!(
        detail.contains("git history is the restore path"),
        "the loud warning must point at the only recovery: {detail}"
    );
    assert_eq!(doc["redirect"]["redirected"], 0, "envelope: {doc:#}");
    assert!(
        tmp.path().join("bun.lock").exists(),
        "the migrated text lock is kept when the restore cannot run"
    );
    assert!(
        !lockb.exists(),
        "bun deleted the binary lock and no backup could restore it"
    );
    // The kept migration's removal record reaches the ledger so a future
    // `--revert` knows the file was replaced.
    let ledger =
        std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("redirect_bun_lockb_migrated") && ledger.contains("\"removed\""),
        "the ledger must keep the migration's removal record: {ledger}"
    );
}

// ───────────── live unreadable pnpm-workspace.yaml fallback (1450) ─────────────

/// Production wiring of the present-but-unreadable pnpm-workspace.yaml arm
/// (the exact seam where a Create once overwrote the user's workspace file):
/// a LIVE hosted run over a v9 pnpm lock with an unreadable workspace file
/// must still rewrite the lock, fall back to warning-only guidance naming
/// the file and the error, and leave the user's workspace bytes untouched.
#[cfg(unix)]
#[tokio::test]
async fn unreadable_pnpm_workspace_gets_warning_only_guidance_in_a_live_run() {
    use std::os::unix::fs::PermissionsExt;
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let ws = tmp.path().join("pnpm-workspace.yaml");
    let user_bytes = "packages:\n  - 'apps/*'\n";
    std::fs::write(&ws, user_bytes).unwrap();
    std::fs::set_permissions(&ws, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&ws).is_ok() {
        println!("SKIP: running as root — chmod 000 cannot make the workspace unreadable");
        return;
    }

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);
    // Restore before asserting so the tempdir cleans up and the bytes can
    // be read back.
    std::fs::set_permissions(&ws, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(code, 0, "the fallback is warning-only, never an error: {doc:#}");
    let detail = warning_detail(&doc, "redirect_pnpm_trust_lockfile");
    assert!(
        detail.contains("exists but could not be read") && detail.contains("left untouched"),
        "the fallback must name the unreadable file and the hands-off \
         decision: {detail}"
    );
    // The lock rewrite itself still landed.
    let lock = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    assert!(
        lock.contains(&format!("tarball: {HOSTED_URL}")),
        "the redirect must land despite the workspace fallback:\n{lock}"
    );
    assert_eq!(doc["redirect"]["redirected"], 1, "envelope: {doc:#}");
    // FINDING-5 seam: the user's workspace file was NOT overwritten with the
    // root-only scaffold.
    assert_eq!(
        std::fs::read_to_string(&ws).unwrap(),
        user_bytes,
        "the unreadable workspace file must be left byte-identical"
    );
    let ledger =
        std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        !ledger.contains("redirect_pnpm_workspace_trust"),
        "no workspace-trust edit may be recorded when the file was unreadable: {ledger}"
    );
}

// ──────────── redirect_supersedes_vendored (1723-1726 + human) ────────────

/// The hosted-direction takeover warning: a LIVE lock routing package X to
/// its hosted artifact while BOTH ledgers still claim X (redirect records +
/// vendored state) must fire `redirect_supersedes_vendored` naming X — the
/// only signal that X's vendored ledger entry and committed tarball are now
/// orphaned. A DIFFERENT package Y is granted this run so the takeover
/// pre-revert never consumes X's vendored entry. The human re-run prints
/// the same warning through the takeover loop.
#[tokio::test]
async fn live_hosted_overlap_fires_redirect_supersedes_vendored() {
    const XNAME: &str = "covgap-super-x";
    const XPURL: &str = "pkg:npm/covgap-super-x@1.0.0";
    const XUUID: &str = "66666666-6666-4666-8666-666666666666";
    let x_hosted = format!(
        "http://patch.test/patch/npm/{XNAME}/1.0.0/77777777-7777-4777-8777-777777777777/{XUUID}/{XNAME}-1.0.0.tgz"
    );

    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await; // grants Y (= NAME) only
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // Lock: X already hosted-wired (an earlier run), Y still upstream.
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}", "{XNAME}": "1.0.0" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}", "{XNAME}": "1.0.0" }} }},
    "node_modules/{NAME}": {{
      "version": "{VERSION}",
      "resolved": "https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz",
      "integrity": "{UPSTREAM_SHA512}"
    }},
    "node_modules/{XNAME}": {{
      "version": "1.0.0",
      "resolved": "{x_hosted}",
      "integrity": "{PATCHED_SHA512}"
    }}
  }}
}}
"#
        ),
    )
    .unwrap();
    // Redirect ledger: records X (the record uuid the live-lock proof keys on).
    let socket_vendor = root.join(".socket/vendor");
    std::fs::create_dir_all(&socket_vendor).unwrap();
    let redirect_ledger = json!({
        "version": 1,
        "mode": "hosted",
        "records": {
            XPURL: {
                "uuid": XUUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "package/index.js": { "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64) }
                },
                "vulnerabilities": {},
                "description": "x",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    std::fs::write(
        socket_vendor.join("redirect-state.json"),
        serde_json::to_vec_pretty(&redirect_ledger).unwrap(),
    )
    .unwrap();
    // Vendored ledger ALSO claims X (stale — the lock routes X hosted).
    write_vendor_state(
        root,
        XPURL,
        "88888888-8888-4888-8888-888888888888",
        "package-lock",
    );

    let (code, doc) = scan_hosted_json(root, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "the overlap warning never flips the exit code: {doc:#}");
    assert_eq!(
        doc["redirect"]["redirected"], 1,
        "anchor: Y must redirect normally: {doc:#}"
    );
    let detail = warning_detail(&doc, "redirect_supersedes_vendored");
    assert!(
        detail.contains(XPURL),
        "the superseded package must be named: {detail}"
    );
    assert!(
        detail.contains("socket-patch remove"),
        "the per-package remediation must be prescribed: {detail}"
    );
    // Warn-only contract: the stale vendored ledger is NOT deleted.
    let state =
        std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap();
    assert!(
        state.contains(XPURL),
        "the takeover warning must not delete the other mode's ledger: {state}"
    );

    // Human re-run (idempotent): the takeover-warning loop prints the detail.
    let (code, _stdout, stderr) = scan_hosted(root, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "human overlap run exits 0; stderr=\n{stderr}");
    assert!(
        stderr.contains("  warning: hosted redirect superseded the vendored ledger for:")
            && stderr.contains(XPURL),
        "the supersedes warning must reach human stderr; stderr=\n{stderr}"
    );
}

// ───────────────────────── human-output lines ─────────────────────────

/// Human `--dry-run` output: the summary uses the "would rewrite" verb, the
/// requested VEX is skipped with the explicit `--dry-run` notice (and no
/// document is written), and the pnpm trust guidance reaches stderr through
/// the pnpm warning loop.
#[tokio::test]
async fn human_dry_run_prints_would_rewrite_pnpm_guidance_and_vex_skip() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let lock_before = std::fs::read(tmp.path().join("pnpm-lock.yaml")).unwrap();

    let (code, stdout, stderr) = scan_hosted(
        tmp.path(),
        &server.uri(),
        &[
            "--dry-run",
            "--vex",
            "out.vex.json",
            "--vex-product",
            "pkg:npm/consumer@0.0.0",
        ],
        &[],
    );
    assert_eq!(code, 0, "dry-run exits 0; stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains("Redirected 1 package(s)") && stdout.contains("; would rewrite"),
        "the dry-run summary must use the preview verb; stdout=\n{stdout}"
    );
    assert!(
        stderr.contains("Skipping VEX generation (--dry-run)."),
        "the requested-but-skipped VEX must be announced; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("  warning: ") && stderr.contains("trustLockfile"),
        "the pnpm trust guidance must reach human stderr; stderr=\n{stderr}"
    );
    assert!(
        !tmp.path().join("out.vex.json").exists(),
        "dry-run must not write the VEX document"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("pnpm-lock.yaml")).unwrap(),
        lock_before,
        "dry-run must leave the lock byte-identical"
    );
}

/// Human `--vex` success summary: statement count, the document path, and
/// the attested-from-the-ledger caveat all reach stderr, and the document
/// itself parses with the one redirected statement — a live execution of
/// the `vex_statements Some ⇒ vex path Some` invariant.
#[tokio::test]
async fn human_vex_success_summary_names_statements_path_and_ledger_caveat() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);

    let (code, stdout, stderr) = scan_hosted(
        tmp.path(),
        &server.uri(),
        &[
            "--vex",
            "out.vex.json",
            "--vex-product",
            "pkg:npm/consumer@0.0.0",
        ],
        &[],
    );
    assert_eq!(code, 0, "scan --vex exits 0; stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains("Redirected 1 package(s); rewrote"),
        "anchor: the wet-run summary verb; stdout=\n{stdout}"
    );
    assert!(
        stderr.contains("Wrote OpenVEX document with 1 statement(s) to")
            && stderr.contains("out.vex.json"),
        "the VEX summary must name the count and the path; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("attested from the ledger"),
        "the no-verify caveat is load-bearing; stderr=\n{stderr}"
    );
    let doc: Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join("out.vex.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        doc["statements"].as_array().map(Vec::len),
        Some(1),
        "the summary's count must match the document: {doc}"
    );
    assert_eq!(doc["statements"][0]["vulnerability"]["name"], GHSA);
}

/// Human Rush run: the `redirect_rush_repo_state_stale` detail reaches
/// stderr through the rush warning loop (the JSON twin is pinned in
/// in_process_redirect.rs).
#[tokio::test]
async fn human_rush_run_prints_the_repo_state_stale_warning_line() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_rush_project(tmp.path());

    let (code, stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "rush run exits 0; stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains("Redirected 1 package(s); rewrote"),
        "anchor: the rush lock must be rewritten; stdout=\n{stdout}"
    );
    assert!(
        stderr.contains("  warning: pnpm-lock.yaml was edited outside `rush update`"),
        "the rush repo-state warning must reach human stderr; stderr=\n{stderr}"
    );
}

// ───────── ledger save failure after a successful revert (1065-1079) ─────────

/// save_state failure AFTER a successful takeover revert: the wiring is gone
/// but the vendored ledger still claims it, so the purl must fail CLOSED —
/// `redirect_vendored_revert_failed` with the could-not-be-updated detail, a
/// `vendored_revert_failed` skip, and no redirect. Reached by making
/// `.socket/vendor` itself read-only (0o555): the entry's empty wiring
/// reverts trivially and its artifact dir under the still-writable
/// `.socket/vendor/npm/` is removed, but persisting the now-empty ledger
/// needs a write in `.socket/vendor` and fails.
#[cfg(unix)]
#[tokio::test]
async fn ledger_save_failure_after_successful_revert_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    /// Restore the vendor dir's mode even on assertion panic, so the
    /// tempdir can clean up.
    struct ModeGuard(std::path::PathBuf);
    impl Drop for ModeGuard {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }

    const VUUID: &str = "99999999-9999-4999-8999-999999999999";
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    write_vendor_state(root, PURL, VUUID, "package-lock");
    // The artifact dir the successful revert removes (its parent
    // `.socket/vendor/npm` stays writable).
    let artifact_dir = root.join(".socket/vendor/npm").join(VUUID);
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join(format!("{NAME}-{VERSION}.tgz")), b"tgz").unwrap();
    let lock_before = std::fs::read(root.join("package-lock.json")).unwrap();

    let vendor_dir = root.join(".socket/vendor");
    std::fs::set_permissions(&vendor_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let _guard = ModeGuard(vendor_dir.clone());
    // Root ignores mode bits: probe with a real write attempt.
    if std::fs::write(vendor_dir.join(".covgap-write-probe"), b"x").is_ok() {
        let _ = std::fs::remove_file(vendor_dir.join(".covgap-write-probe"));
        println!("SKIP: running as root — chmod 555 cannot make the ledger unwritable");
        return;
    }

    let (code, doc) = scan_hosted_json(root, &server.uri(), &[], &[]);

    assert_eq!(code, 0, "the fail-closed refusal still exits 0: {doc:#}");
    let detail = warning_detail(&doc, "redirect_vendored_revert_failed");
    assert!(
        detail.contains("could not be updated"),
        "the post-revert ledger-save failure must be named: {detail}"
    );
    assert!(
        doc["redirect"]["skipped"]
            .as_array()
            .is_some_and(|s| s.iter().any(|e| e["purl"] == PURL
                && e["reason"] == "vendored_revert_failed")),
        "the refusal must be accounted as skipped: {doc:#}"
    );
    assert_eq!(doc["redirect"]["redirected"], 0, "envelope: {doc:#}");
    let lock_after = std::fs::read(root.join("package-lock.json")).unwrap();
    assert_eq!(
        lock_after, lock_before,
        "no redirect may land when the ledger cannot record the takeover"
    );
    // Fail-closed residue this warning exists to explain: the wiring/artifact
    // are reverted but the ledger still claims the entry.
    assert!(
        root.join(".socket/vendor/state.json").exists(),
        "the stale ledger survives (the warning tells the user to fix it)"
    );
}
