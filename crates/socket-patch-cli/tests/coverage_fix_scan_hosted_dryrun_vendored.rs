//! Coverage-audit regression: `scan --mode hosted --dry-run` over a VENDORED
//! project must preview the WET run's takeover outcome.
//!
//! Pre-fix, the takeover pre-revert loop's dry-run branch pushed the
//! `redirect_would_revert_vendored` warning ("will revert … then redirect")
//! and `continue`d — skipping the revert but LEAVING the purl in the
//! candidates/overrides handed to the rewriters. The pnpm/berry rewriters
//! then previewed against the still-vendored lock, fail-closed refused its
//! `file:.socket/vendor/…` resolution (`redirect_pnpm_entry_vendored`,
//! "run `vendor --revert` first"), and the envelope reported `redirected: 0`
//! with BOTH contradictory prescriptions — while the same command WITHOUT
//! `--dry-run` reverted first and reported `redirected: 1`. A CI gate keying
//! on the dry-run count concluded the migration would fail when it succeeds.
//!
//! Fixture: a real offline `vendor` run (the `in_process_vendor.rs` harness
//! shapes) produces the vendored lock + `.socket/vendor/state.json` entry;
//! the hosted API is wiremock (`in_process_redirect_pnpm.rs` shapes).

use std::path::Path;

#[path = "vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;

use serde_json::{json, Value};
use serial_test::serial;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NAME: &str = "dryrun-vendored-takeover";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:npm/dryrun-vendored-takeover@1.0.0";
const UUID: &str = "44444444-4444-4444-8444-444444444444";
const HOSTED_URL: &str = "http://patch.test/patch/npm/dryrun-vendored-takeover/1.0.0/55555555-5555-4555-8555-555555555555/44444444-4444-4444-8444-444444444444/dryrun-vendored-takeover-1.0.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const UPSTREAM_SHA512: &str = "sha512-UPSTREAMupstream==";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

async fn mock_hosted_api(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "dry-run takeover fixture"
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
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": HOSTED_URL,
                    "purl": PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": HOSTED_URL,
                        "integrity": { "sha512": PATCHED_SHA512 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
    // `view/{uuid}` — the record the wet run persists into the redirect
    // ledger after a confirmed redirect.
    let before_hash = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash": after_hash,
                }
            },
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// The `in_process_redirect_pnpm.rs` project shape: v9 root pnpm lock
/// resolving the package under `packages:`, plus the installed node_modules
/// copy (with the real patch-target file, so the vendor run can pack the
/// artifact).
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
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();
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

/// The manifest + staged blob the offline vendor run needs.
fn seed_manifest_and_blob(root: &Path) {
    let before_hash = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    let manifest = json!({
        "patches": {
            PURL: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": before_hash,
                        "afterHash": after_hash
                    }
                },
                "vulnerabilities": {},
                "description": "dry-run takeover fixture",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    bytes.push(b'\n');
    std::fs::write(socket.join("manifest.json"), &bytes).unwrap();
    std::fs::write(socket.join("blobs").join(after_hash), PATCHED_INDEX).unwrap();
}

/// Run the built binary with ambient `SOCKET_*` scrubbed; `(code, stdout,
/// stderr)`.
fn run_cli(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args(args).current_dir(cwd);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    // Isolate the npm config layers the hosted `.npmrc` auto-config
    // consults (an ambient explicit `allow-remote` would change the plan).
    let absent = cwd.join(".absent-npm-config");
    for var in [
        "NPM_CONFIG_USERCONFIG",
        "npm_config_userconfig",
        "NPM_CONFIG_GLOBALCONFIG",
        "npm_config_globalconfig",
        "PREFIX",
    ] {
        cmd.env(var, &absent);
    }
    cmd.env("NPM_CONFIG_ALLOW_REMOTE", "")
        .env("npm_config_allow_remote", "");
    let out = cmd.output().expect("spawn socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `vendor --json --offline` through the binary → `(code, envelope)`.
fn vendor_cli(cwd: &Path) -> (i32, Value) {
    let (code, stdout, stderr) = run_cli(
        cwd,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            cwd.to_str().unwrap(),
        ],
    );
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("vendor --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, env)
}

/// `scan --mode hosted --json [--dry-run]` through the binary → `(code,
/// envelope)`.
fn scan_hosted_json(cwd: &Path, api_url: &str, dry_run: bool) -> (i32, Value) {
    let mut args = vec![
        "scan",
        "--mode",
        "hosted",
        "--json",
        "--yes",
        "--cwd",
        cwd.to_str().unwrap(),
        "--api-url",
        api_url,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    if dry_run {
        args.push("--dry-run");
    }
    let (code, stdout, stderr) = run_cli(cwd, &args);
    let doc: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be the JSON envelope ({e});\nstdout=\n{stdout}\nstderr=\n{stderr}")
    });
    (code, doc)
}

/// Vendor the fixture project for real (offline) so the lock carries the
/// `file:.socket/vendor/…` wiring and `.socket/vendor/state.json` owns the
/// entry — the exact state the takeover pre-revert keys on.
fn vendored_project(root: &Path) {
    write_pnpm_project(root);
    seed_manifest_and_blob(root);
    let (code, env) = vendor_cli(root);
    assert_eq!(code, 0, "fixture vendor run must succeed: {env:#}");
    let lock = std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap();
    assert!(
        lock.contains(".socket/vendor/"),
        "fixture must be vendored:\n{lock}"
    );
    let state: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert!(
        state["entries"].get(PURL).is_some(),
        "fixture vendored ledger must own the purl: {state:#}"
    );
}

fn warning_detail<'a>(doc: &'a Value, code: &str) -> Option<&'a str> {
    doc["redirect"]["warnings"]
        .as_array()?
        .iter()
        .find(|w| w["code"] == code)
        .and_then(|w| w["detail"].as_str())
}

fn rewritten_files(doc: &Value) -> Vec<&str> {
    doc["redirect"]["rewrittenFiles"]
        .as_array()
        .map(|f| f.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn warning_codes(doc: &Value) -> Vec<&str> {
    doc["redirect"]["warnings"]
        .as_array()
        .map(|w| w.iter().filter_map(|e| e["code"].as_str()).collect())
        .unwrap_or_default()
}

/// The dry-run preview must match the wet run's takeover outcome: the
/// vendored purl counts as `redirected` (the wet run reverts its vendored
/// state, then redirects), the `redirect_would_revert_vendored` warning
/// explains the plan, and the contradictory rewriter refusal
/// (`redirect_pnpm_entry_vendored`, "run `vendor --revert` first") never
/// appears — the run itself performs that revert. Nothing lands on disk.
#[tokio::test]
#[serial]
async fn dry_run_over_vendored_project_previews_the_wet_takeover() {
    let server = MockServer::start().await;
    mock_hosted_api(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendored_project(root);
    let vendored_lock = std::fs::read(root.join("pnpm-lock.yaml")).unwrap();
    let vendored_state = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();

    let (code, doc) = scan_hosted_json(root, &server.uri(), /*dry_run=*/ true);
    assert_eq!(code, 0, "dry-run scan --mode hosted must succeed: {doc:#}");
    assert_eq!(doc["redirect"]["dryRun"], true, "envelope: {doc:#}");

    let codes = warning_codes(&doc);
    assert!(
        codes.contains(&"redirect_would_revert_vendored"),
        "the takeover plan must be announced: {doc:#}"
    );
    // THE BUG: the rewriters previewed against the still-vendored lock and
    // refused it, contradicting the takeover warning above.
    assert!(
        !codes.contains(&"redirect_pnpm_entry_vendored"),
        "the dry-run must not also tell the user to run `vendor --revert` \
         for a purl this run just promised to revert itself: {doc:#}"
    );
    // THE BUG: the preview reported `redirected: 0` for a migration the wet
    // run lands (below) — the CI-gate signal this envelope exists for.
    assert_eq!(
        doc["redirect"]["redirected"], 1,
        "the dry-run must preview the wet outcome: {doc:#}"
    );
    assert_eq!(
        doc["redirect"]["skipped"].as_array().map(Vec::len),
        Some(0),
        "a revertable vendored purl is not skipped: {doc:#}"
    );
    // Review finding: the pnpm trustLockfile auto-config the wet run
    // writes (the takeover splices the root v9 lock) must be previewed too.
    let trust = warning_detail(&doc, "redirect_pnpm_trust_lockfile")
        .unwrap_or_else(|| panic!("the trust config must be previewed: {doc:#}"));
    // (The vendor run already created pnpm-workspace.yaml for its own
    // wiring, so the wet run MERGES the key into it.)
    assert!(
        trust.contains("would be merged into the existing pnpm-workspace.yaml"),
        "{trust}"
    );
    assert!(
        rewritten_files(&doc).contains(&"pnpm-workspace.yaml"),
        "the preview must list the workspace file the wet run writes: {doc:#}"
    );
    let workspace = |root: &Path| std::fs::read_to_string(root.join("pnpm-workspace.yaml")).ok();
    let vendored_workspace = workspace(root);
    assert!(
        !vendored_workspace
            .as_deref()
            .unwrap_or_default()
            .contains("trustLockfile"),
        "dry run writes nothing"
    );

    // Dry-run invariants: nothing on disk moved.
    assert_eq!(
        std::fs::read(root.join("pnpm-lock.yaml")).unwrap(),
        vendored_lock,
        "dry-run must leave the vendored lock byte-identical"
    );
    assert_eq!(
        std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
        vendored_state,
        "dry-run must leave the vendored ledger byte-identical"
    );
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "dry-run must not write the redirect ledger"
    );

    // The SAME command without --dry-run: reverts the vendored state, then
    // redirects — `redirected: 1`. This is the outcome the preview above
    // must agree with.
    let (code, wet) = scan_hosted_json(root, &server.uri(), /*dry_run=*/ false);
    assert_eq!(code, 0, "wet scan --mode hosted must succeed: {wet:#}");
    assert_eq!(
        wet["redirect"]["redirected"], 1,
        "the wet takeover must land: {wet:#}"
    );
    let lock = std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap();
    assert!(
        lock.contains(&format!("tarball: {HOSTED_URL}")),
        "the wet run must leave the lock hosted:\n{lock}"
    );
    assert!(
        workspace(root).is_some_and(|w| w.contains("trustLockfile: true")),
        "the wet run writes what the preview promised: {wet:#}"
    );
}

/// Refusal parity: a vendored purl whose revert the wet run would REFUSE
/// (here: a ledger entry whose uuid fails the revert's fail-closed grammar
/// guard) must be refused by the dry-run too — `redirect_vendored_revert_failed`
/// + a `vendored_revert_failed` skip, `redirected: 0` — never previewed as a
/// clean takeover, and never handed to the rewriters for a second,
/// contradictory diagnosis.
#[tokio::test]
#[serial]
async fn dry_run_refuses_unrevertable_vendored_state_like_the_wet_run() {
    let server = MockServer::start().await;
    mock_hosted_api(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendored_project(root);
    // Corrupt the entry's uuid: revert (wet or preview) fail-closes on the
    // uuid-dir grammar guard before touching anything.
    let state_path = root.join(".socket/vendor/state.json");
    let mut state: Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["entries"][PURL]["uuid"] = json!("not-a-uuid");
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    let vendored_lock = std::fs::read(root.join("pnpm-lock.yaml")).unwrap();

    let (code, doc) = scan_hosted_json(root, &server.uri(), /*dry_run=*/ true);
    assert_eq!(code, 0, "dry-run scan --mode hosted must succeed: {doc:#}");

    let codes = warning_codes(&doc);
    assert!(
        codes.contains(&"redirect_vendored_revert_failed"),
        "the unrevertable state must be refused in the preview too: {doc:#}"
    );
    assert!(
        !codes.contains(&"redirect_would_revert_vendored"),
        "a refused purl must not also be promised a takeover: {doc:#}"
    );
    assert!(
        doc["redirect"]["skipped"].as_array().is_some_and(|s| s
            .iter()
            .any(|e| e["purl"] == PURL && e["reason"] == "vendored_revert_failed")),
        "the refusal must be accounted as skipped: {doc:#}"
    );
    assert_eq!(
        doc["redirect"]["redirected"], 0,
        "a refused takeover previews as not redirected: {doc:#}"
    );
    assert_eq!(
        std::fs::read(root.join("pnpm-lock.yaml")).unwrap(),
        vendored_lock,
        "dry-run must leave the vendored lock byte-identical"
    );
}

/// `scan --mode hosted [--dry-run]` in HUMAN mode → `(code, stdout,
/// stderr)`.
fn scan_hosted_human(cwd: &Path, api_url: &str, dry_run: bool) -> (i32, String, String) {
    let mut args = vec![
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--cwd",
        cwd.to_str().unwrap(),
        "--api-url",
        api_url,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    if dry_run {
        args.push("--dry-run");
    }
    run_cli(cwd, &args)
}

/// The first line of `stdout` (the summary).
/// The engine's one-line summary. Human hosted `scan` prints the results
/// table and discovery summary above it, so find it by its lead words.
fn summary_line(stdout: &str) -> &str {
    stdout
        .lines()
        .find(|l| l.starts_with("Would redirect ") || l.starts_with("Redirected "))
        .unwrap_or_default()
}

/// Human takeover output: the dry run announces the planned migration and
/// the wet run the landed one, each as its own line on stderr, and both
/// summaries count the same 3 files — the lock and workspace the hosted
/// rewriter touches plus the package.json `pnpm.overrides` wiring only the
/// vendored revert touches (the wet count used to omit it: "rewrote 2
/// files"). The wet run's next steps name `.socket/vendor/` and
/// package.json, so the deleted vendored ledger entry and artifact and the
/// reverted wiring are committed too.
#[tokio::test]
#[serial]
async fn human_takeover_prints_migration_lines_and_matching_file_counts() {
    let server = MockServer::start().await;
    mock_hosted_api(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendored_project(root);

    let (code, dry_out, dry_err) = scan_hosted_human(root, &server.uri(), true);
    assert_eq!(code, 0, "stdout=\n{dry_out}\nstderr=\n{dry_err}");
    assert!(
        dry_err.lines().any(|l| l
            == format!(
                "Would migrate {PURL} from vendored to hosted (its vendored wiring, ledger \
                 entry, and committed artifact would be reverted first)."
            )),
        "stderr=\n{dry_err}"
    );
    assert!(
        !dry_err.contains("redirect_would_revert_vendored"),
        "the planned takeover is a progress line, not a warning; stderr=\n{dry_err}"
    );
    assert_eq!(
        summary_line(&dry_out),
        "Would redirect 1 package and rewrite 3 files (--dry-run: nothing was changed).",
        "stdout=\n{dry_out}"
    );

    let (code, wet_out, wet_err) = scan_hosted_human(root, &server.uri(), false);
    assert_eq!(code, 0, "stdout=\n{wet_out}\nstderr=\n{wet_err}");
    assert!(
        wet_err.lines().any(|l| l
            == format!(
                "Migrated {PURL} from vendored to hosted (reverted its vendored wiring, ledger \
                 entry, and committed artifact)."
            )),
        "stderr=\n{wet_err}"
    );
    assert_eq!(
        summary_line(&wet_out),
        "Redirected 1 package; rewrote 3 files.",
        "the wet count must equal the dry-run preview; stdout=\n{wet_out}"
    );
    assert!(
        wet_out.contains(
            "Commit .socket/vendor/ (the redirect ledger, plus the removed vendored ledger \
             entries and artifacts), package.json, pnpm-lock.yaml, and pnpm-workspace.yaml \
             to keep the redirect."
        ),
        "stdout=\n{wet_out}"
    );
}

/// The package-lock twin of [`write_pnpm_project`]: a lockfileVersion 3
/// root lock resolving the package from the registry.
fn write_package_lock_project(root: &Path) {
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
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();
    let lock = json!({
        "name": "consumer", "version": "0.0.0", "lockfileVersion": 3, "requires": true,
        "packages": {
            "": { "name": "consumer", "version": "0.0.0", "dependencies": { NAME: VERSION } },
            format!("node_modules/{NAME}"): {
                "version": VERSION,
                "resolved": format!("https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz"),
                "integrity": UPSTREAM_SHA512,
            }
        }
    });
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_string_pretty(&lock).unwrap(),
    )
    .unwrap();
}

/// Review finding: a dry-run vendored→hosted takeover of a package-lock
/// purl withheld the purl from the rewriters, so the npm 12 `.npmrc`
/// `allow-remote=all` write the wet run makes was neither warned about
/// ("would be written to a new project .npmrc") nor listed in `rewrittenFiles`.
#[tokio::test]
#[serial]
async fn dry_run_package_lock_takeover_previews_the_npmrc_write() {
    let server = MockServer::start().await;
    mock_hosted_api(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_package_lock_project(root);
    seed_manifest_and_blob(root);
    let (code, env) = vendor_cli(root);
    assert_eq!(code, 0, "fixture vendor run must succeed: {env:#}");
    let vendored_lock = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    assert!(vendored_lock.contains(".socket/vendor/"), "{vendored_lock}");

    let (code, doc) = scan_hosted_json(root, &server.uri(), /*dry_run=*/ true);
    assert_eq!(code, 0, "{doc:#}");
    assert!(
        warning_codes(&doc).contains(&"redirect_would_revert_vendored"),
        "{doc:#}"
    );
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    let detail = warning_detail(&doc, "redirect_npm_allow_remote")
        .unwrap_or_else(|| panic!("the .npmrc write must be previewed: {doc:#}"));
    assert!(
        detail.contains("would be written to a new project .npmrc")
            && detail.contains("patch.test"),
        "{detail}"
    );
    assert!(rewritten_files(&doc).contains(&".npmrc"), "{doc:#}");
    assert!(!root.join(".npmrc").exists(), "dry run writes nothing");
    assert_eq!(
        std::fs::read_to_string(root.join("package-lock.json")).unwrap(),
        vendored_lock
    );

    let (code, wet) = scan_hosted_json(root, &server.uri(), /*dry_run=*/ false);
    assert_eq!(code, 0, "{wet:#}");
    assert_eq!(wet["redirect"]["redirected"], 1, "{wet:#}");
    assert_eq!(
        std::fs::read_to_string(root.join(".npmrc")).unwrap(),
        "allow-remote=all\n",
        "the wet run writes what the preview promised"
    );
}

/// vlt twin: the vendored `file` node and its edges are reverted to the
/// registry node before the rewrite, so the dry run previews
/// `redirected: 1` (never `redirect_vlt_entry_vendored`) and writes
/// nothing; the wet run lands the same outcome.
#[tokio::test]
#[serial]
async fn vlt_dry_run_over_vendored_project_previews_the_wet_takeover() {
    use vlt_hosted_common as hosted;
    let server = MockServer::start().await;
    hosted::mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let registry_lock = format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n    {}\n  }},\n  \
         \"edges\": {{\n    \"file~_d left-pad\": \"prod 1.3.0 {}\"\n  }}\n}}\n",
        hosted::registry_node(hosted::TILDE_ID),
        hosted::TILDE_ID
    );
    std::fs::write(root.join("vlt-lock.json"), &registry_lock).unwrap();
    hosted::write_package_json(root);
    hosted::install_importer(root, hosted::PRISTINE);
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut record = hosted::view_body();
    record.as_object_mut().unwrap().remove("purl");
    record["exportedAt"] = json!("2026-01-01T00:00:00Z");
    std::fs::write(
        socket.join("manifest.json"),
        json!({ "patches": { hosted::PURL: record } }).to_string(),
    )
    .unwrap();
    std::fs::write(
        socket
            .join("blobs")
            .join(hosted::git_sha256(hosted::PATCHED)),
        hosted::PATCHED,
    )
    .unwrap();
    let cwd = root.to_str().unwrap().to_string();
    let (code, env, stderr) = hosted::run_json(root, &["vendor", "--offline", "--cwd", &cwd], &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    std::fs::remove_file(socket.join("manifest.json")).unwrap();
    let vendored_lock = std::fs::read(root.join("vlt-lock.json")).unwrap();
    let vendored_state = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();
    let vendored_pkg = std::fs::read(root.join("package.json")).unwrap();

    let (_, doc) = hosted::scan_hosted(root, &server, &["--dry-run"], &[]);
    let codes = hosted::warning_codes(&doc);
    assert!(
        codes.contains(&"redirect_would_revert_vendored".to_string()),
        "{doc:#}"
    );
    assert!(
        !codes.contains(&"redirect_vlt_entry_vendored".to_string()),
        "{doc:#}"
    );
    assert_eq!(hosted::redirected(&doc), 1, "{doc:#}");
    assert_eq!(
        std::fs::read(root.join("vlt-lock.json")).unwrap(),
        vendored_lock
    );
    assert_eq!(
        std::fs::read(root.join("package.json")).unwrap(),
        vendored_pkg
    );
    assert_eq!(
        std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
        vendored_state
    );
    assert!(!hosted::ledger_path(root).exists());

    let (_, wet) = hosted::scan_hosted(root, &server, &[], &[]);
    assert_eq!(hosted::redirected(&wet), 1, "{wet:#}");
    let lock = hosted::read(root, "vlt-lock.json");
    assert!(lock.contains(&hosted::artifact_url(&server)), "{lock}");
    assert!(!lock.contains(".socket/vendor"), "{lock}");
}
