//! Hermetic bun mode-takeover contract tests through the built binary.
//!
//! Twin of the yarn legs in `mode_migration_npm.rs` and the pnpm
//! `hosted_to_vendor_conversion` module in `in_process_vendor.rs`, for the
//! one npm-family lock flavor whose hosted→vendored takeover used to be a
//! hard refusal (`redirect_revert_failed`, "cannot replay yet"): the bun
//! hosted rewrite REPLACES the registry 4-tuple's `name@version` spec with
//! a URL 3-tuple, so without the per-purl pre-revert the bun vendor backend
//! cannot even find the entry. The API is wiremock; no `bun` binary is
//! needed (the lock grammar is the real bun 1.4.2 lockfileVersion-2 shape
//! from the compatibility matrix captures, and the packages tuple grammar
//! is identical on versions 0/1/2).
//!
//! Scenarios:
//!   1. `scan --mode hosted` → `scan --mode vendored`: the takeover reverts
//!      the hosted line, drops the redirect-ledger record, vendors from the
//!      pristine registry line (the vendor ledger's `original` is the
//!      REGISTRY tuple, never the hosted URL), and `vendor --revert`
//!      restores the pristine bytes.
//!   2. `vendor --dry-run` over the live hosted redirect previews the
//!      takeover (`vendor_would_revert_redirect`) with no false
//!      `vendor_lock_entry_not_found` follow-up and no writes; the wet
//!      `vendor` then completes it.
//!   3. Two hosted records: a SCOPED `rollback <purl>` (per-purl path, the
//!      whole-ledger replay is not eligible) unwinds only the targeted line
//!      and record; the sibling stays hosted.
//!   4. Same ledger, `remove <purl>`.
//!   5. A hosted-wired lockfileVersion-1 WORKSPACE lock (hosted accepts it,
//!      the vendored backend refuses it): `vendor` — dry and wet — refuses
//!      `vendor_bun_workspace_unsupported` BEFORE the takeover reverts
//!      anything, so the hosted wiring survives byte-for-byte; the v2 twin
//!      still takes over.
//!
//! Every child process gets the ambient `SOCKET_*` vars scrubbed and
//! telemetry hard-disabled; each test runs in its own tempdir.

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NAME: &str = "left-pad";
const VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
/// Canonical-grammar patch uuid (the vendor path layer validates the uuid
/// path level fail-closed).
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const HOSTED_URL: &str = "http://patch.test/patch/npm/left-pad/1.3.0/55555555-5555-4555-8555-555555555555/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

/// The second hosted record of the scoped-unwind scenarios.
const OTHER_NAME: &str = "other";
const OTHER_PURL: &str = "pkg:npm/other@1.0.0";
const OTHER_UUID: &str = "0a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d";
const OTHER_HOSTED_URL: &str = "http://patch.test/patch/npm/other/1.0.0/55555555-5555-4555-8555-555555555555/0a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d/other-1.0.0.tgz";

/// The registry 4-tuple lines exactly as bun 1.4.2 emits them (matrix
/// capture grammar; the `""` registry field is the default registry).
const LEFT_PAD_REGISTRY_LINE: &str = r#"    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="],"#;
const OTHER_REGISTRY_LINE: &str =
    r#"    "other": ["other@1.0.0", "", {}, "sha512-otherOTHERother0123456789=="],"#;

/// Pristine lockfileVersion-2 bun.lock for a root-only project depending on
/// `left-pad@1.3.0` (real bun 1.4.2 shape: `configVersion`, the root
/// workspace block with trailing commas, one packages entry per line).
fn pristine_lock() -> String {
    format!(
        "{{\n  \"lockfileVersion\": 2,\n  \"configVersion\": 1,\n  \"workspaces\": {{\n    \"\": {{\n      \"name\": \"bun-takeover-fixture\",\n      \"dependencies\": {{\n        \"left-pad\": \"1.3.0\",\n      }},\n    }},\n  }},\n  \"packages\": {{\n{LEFT_PAD_REGISTRY_LINE}\n  }}\n}}\n"
    )
}

/// Pristine lock with TWO registry entries (`left-pad@1.3.0`, `other@1.0.0`).
fn pristine_lock_two() -> String {
    format!(
        "{{\n  \"lockfileVersion\": 2,\n  \"configVersion\": 1,\n  \"workspaces\": {{\n    \"\": {{\n      \"name\": \"bun-takeover-fixture\",\n      \"dependencies\": {{\n        \"left-pad\": \"1.3.0\",\n        \"other\": \"1.0.0\",\n      }},\n    }},\n  }},\n  \"packages\": {{\n{LEFT_PAD_REGISTRY_LINE}\n\n{OTHER_REGISTRY_LINE}\n  }}\n}}\n"
    )
}

/// The URL 3-tuple line the hosted rewriter writes for `key`.
fn hosted_line(key: &str, name: &str, url: &str, sha512: &str) -> String {
    format!("    \"{key}\": [\"{name}@{url}\", {{}}, \"{sha512}\"],")
}

/// The packages-entry line keyed `key` (verbatim, no line terminator).
fn lock_line(lock: &str, key: &str) -> String {
    let prefix = format!("    \"{key}\": [");
    lock.split('\n')
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no `{key}` entry in:\n{lock}"))
        .trim_end_matches('\r')
        .to_string()
}

fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

// ───────────────────────────── fixture ─────────────────────────────

/// package.json + the installed (unpatched) copy under node_modules + the
/// given bun.lock.
fn write_bun_project(root: &Path, lock: &str, deps: &[(&str, &str)]) {
    let dep_map: serde_json::Map<String, Value> = deps
        .iter()
        .map(|(n, v)| (n.to_string(), Value::String(v.to_string())))
        .collect();
    std::fs::write(
        root.join("package.json"),
        serde_json::to_vec_pretty(&json!({
            "name": "bun-takeover-fixture",
            "version": "1.0.0",
            "private": true,
            "dependencies": Value::Object(dep_map),
        }))
        .unwrap(),
    )
    .unwrap();
    for (name, version) in deps {
        let pkg = root.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();
    }
    std::fs::write(root.join("bun.lock"), lock).unwrap();
}

fn patch_record(uuid: &str) -> Value {
    json!({
        "uuid": uuid,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": {
            "package/index.js": {
                "beforeHash": compute_git_sha256_from_bytes(ORIG_INDEX),
                "afterHash": compute_git_sha256_from_bytes(PATCHED_INDEX),
            }
        },
        "vulnerabilities": {},
        "description": "bun takeover fixture",
        "license": "MIT",
        "tier": "free"
    })
}

/// `.socket/manifest.json` + the after-hash blob, so `vendor --offline`
/// runs fully offline (hosted mode writes no manifest — its ledger is its
/// store).
fn seed_manifest_and_blob(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut bytes =
        serde_json::to_vec_pretty(&json!({ "patches": { PURL: patch_record(UUID) } })).unwrap();
    bytes.push(b'\n');
    std::fs::write(socket.join("manifest.json"), &bytes).unwrap();
    std::fs::write(
        socket
            .join("blobs")
            .join(compute_git_sha256_from_bytes(PATCHED_INDEX)),
        PATCHED_INDEX,
    )
    .unwrap();
}

/// The full hosted-mode API mock set for the one patch over `PURL`
/// (discovery + by-package + grant + view). The view carries the patched
/// file's `blobContent`, so `scan --mode vendored`'s download phase can
/// stage the blob it vendors from.
async fn mock_api(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "bun takeover fixture"
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
    let mut view = patch_record(UUID);
    view["purl"] = json!(PURL);
    view["publishedAt"] = json!("2024-01-01T00:00:00Z");
    view["files"]["package/index.js"]["blobContent"] =
        json!(base64::engine::general_purpose::STANDARD.encode(PATCHED_INDEX));
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view))
        .mount(server)
        .await;
}

// ───────────────────────── subprocess runner ─────────────────────────

/// Run the built `socket-patch` binary with every ambient `SOCKET_*` var
/// scrubbed (except the hermetic `SOCKET_NO_CONFIG`) and telemetry
/// hard-disabled. Returns `(exit_code, stdout, stderr)`.
fn run_cli(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args(args).current_dir(cwd);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("spawn socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `--json` invocation returning the parsed envelope.
fn run_json(cwd: &Path, args: &[&str]) -> (i32, Value) {
    let (code, stdout, stderr) = run_cli(cwd, args);
    // The child's stderr rides the harness's captured output so a failing
    // assertion downstream shows the CLI's own diagnostics.
    if !stderr.trim().is_empty() {
        println!("[{}] stderr:\n{stderr}", args.first().unwrap_or(&"?"));
    }
    let env: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("{args:?} must emit a JSON envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, env)
}

fn scan_mode(cwd: &Path, api_url: &str, mode: &str, extra: &[&str]) -> (i32, Value) {
    let mut args = vec![
        "scan",
        "--mode",
        mode,
        "--json",
        "--yes",
        "--api-url",
        api_url,
        "--api-token",
        "fake",
        "--org",
        ORG,
        "--cwd",
        cwd.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run_json(cwd, &args)
}

fn vendor_cli(cwd: &Path, extra: &[&str]) -> (i32, Value) {
    let mut args = vec![
        "vendor",
        "--json",
        "--offline",
        "--cwd",
        cwd.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    run_json(cwd, &args)
}

fn events(envelope: &Value) -> &Vec<Value> {
    envelope["events"].as_array().expect("events array")
}

/// The first event matching `action` (+ `errorCode` when given; a plain
/// `applied` carries `errorCode: null`).
fn find_event<'a>(envelope: &'a Value, action: &str, error_code: Option<&str>) -> &'a Value {
    events(envelope)
        .iter()
        .find(|e| e["action"] == action && error_code.is_none_or(|c| e["errorCode"] == c))
        .unwrap_or_else(|| panic!("expected a `{action}`/`{error_code:?}` event in:\n{envelope:#}"))
}

fn assert_no_event_code(envelope: &Value, error_code: &str) {
    assert!(
        events(envelope)
            .iter()
            .all(|e| e["errorCode"] != error_code),
        "unexpected `{error_code}` event in:\n{envelope:#}"
    );
}

/// The vendored local-tarball 3-tuple bun must end up with.
fn vendored_rel_tgz() -> String {
    format!(".socket/vendor/npm/{UUID}/{NAME}-{VERSION}.tgz")
}

/// Assertions shared by the takeover scenarios once the wet vendored run
/// has happened: the redirect ledger no longer claims the purl, bun.lock
/// carries the local tuple and no hosted residue, and the vendor ledger's
/// recorded `original` is the PRISTINE registry line.
fn assert_pure_vendored(root: &Path) {
    match std::fs::read_to_string(root.join(".socket/vendor/redirect-state.json")) {
        Ok(text) => {
            let ledger: Value = serde_json::from_str(&text).unwrap();
            assert!(
                ledger["records"].get(PURL).is_none(),
                "the superseded redirect record must be dropped: {ledger:#}"
            );
            assert!(
                ledger["edits"]
                    .as_array()
                    .is_none_or(|edits| edits.iter().all(|e| e["key"] != NAME)),
                "the superseded bun.lock edit must be dropped: {ledger:#}"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // An emptied ledger is deleted — the expected outcome here.
        }
        Err(e) => panic!("unreadable redirect ledger: {e}"),
    }

    let lock = read(root, "bun.lock");
    assert!(
        !lock.contains(HOSTED_URL) && !lock.contains("patch.test"),
        "the hosted URL must be gone from bun.lock:\n{lock}"
    );
    let line = lock_line(&lock, NAME);
    assert!(
        line.contains(&format!("\"{NAME}@{}\"", vendored_rel_tgz())),
        "bun.lock must carry the local vendored 3-tuple:\n{line}"
    );
    assert!(
        root.join(vendored_rel_tgz()).is_file(),
        "the committed artifact must exist"
    );

    let state: Value = serde_json::from_str(&read(root, ".socket/vendor/state.json")).unwrap();
    let wiring = state["entries"][PURL]["wiring"]
        .as_array()
        .unwrap_or_else(|| panic!("wiring array: {state:#}"));
    let lock_wiring = wiring
        .iter()
        .find(|w| w["kind"] == "bun_lock_package")
        .unwrap_or_else(|| panic!("bun_lock_package wiring record: {state:#}"));
    assert_eq!(
        lock_wiring["original"],
        json!(LEFT_PAD_REGISTRY_LINE),
        "the vendor ledger must record the PRISTINE registry line as its original \
         (never the grant-tokenized hosted URL line): {state:#}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 1. scan --mode hosted → scan --mode vendored → vendor --revert
// ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn bun_hosted_then_scan_vendored_takeover_round_trips_to_registry() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_bun_project(root, &pristine_lock(), &[(NAME, VERSION)]);
    let pristine = std::fs::read(root.join("bun.lock")).unwrap();

    // A: hosted redirect — registry 4-tuple → URL 3-tuple, ledger claims
    //    the purl with one `redirect_bun_lock_package` edit whose original
    //    is the registry line.
    let (code, env) = scan_mode(root, &server.uri(), "hosted", &[]);
    assert_eq!(code, 0, "scan --mode hosted must succeed: {env:#}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let hosted_lock = read(root, "bun.lock");
    assert_eq!(
        lock_line(&hosted_lock, NAME),
        hosted_line(NAME, NAME, HOSTED_URL, PATCHED_SHA512),
        "hosted URL 3-tuple written:\n{hosted_lock}"
    );
    let ledger: Value =
        serde_json::from_str(&read(root, ".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger["records"].get(PURL).is_some(),
        "hosted run must record the purl: {ledger:#}\nhosted envelope: {env:#}"
    );
    let edit = &ledger["edits"][0];
    assert_eq!(edit["kind"], "redirect_bun_lock_package", "{ledger:#}");
    assert_eq!(
        edit["original"],
        json!(LEFT_PAD_REGISTRY_LINE),
        "{ledger:#}"
    );

    // The scan-side vendored preview is ledger-only by contract
    // (`would_vendor` / `already_vendored` / `would_revendor`, CLI_CONTRACT
    // "scan --vendor"): it must at least not fail and not write anything.
    let (code, preview) = scan_mode(root, &server.uri(), "vendored", &["--dry-run"]);
    assert_eq!(code, 0, "vendored preview must succeed: {preview:#}");
    assert_eq!(
        read(root, "bun.lock"),
        hosted_lock,
        "a dry run must not touch bun.lock"
    );
    assert!(
        !root.join(".socket/vendor/state.json").exists(),
        "a dry run must not create the vendor ledger"
    );

    // B: vendored scan over the LIVE hosted redirect — the takeover. Used
    //    to exit 1 with `redirect_revert_failed` ("cannot replay yet").
    let (code, env) = scan_mode(root, &server.uri(), "vendored", &[]);
    assert_eq!(
        code, 0,
        "scan --mode vendored over the hosted bun project must succeed: {env:#}"
    );
    assert_eq!(env["status"], "success", "{env:#}");
    let vendor = &env["vendor"];
    assert_eq!(vendor["summary"]["applied"], 1, "{env:#}");
    assert_eq!(vendor["summary"]["failed"], 0, "{env:#}");
    find_event(vendor, "skipped", Some("vendor_takeover_reverted_redirect"));
    find_event(vendor, "applied", None);
    assert_no_event_code(vendor, "redirect_revert_failed");
    assert_pure_vendored(root);
    // Vendored mode is manifest-free: the ledger entry (with its embedded
    // record) is the only record of the vendored patch.
    let state: Value = serde_json::from_str(&read(root, ".socket/vendor/state.json")).unwrap();
    assert_eq!(state["entries"][PURL]["uuid"], UUID, "{state:#}");
    assert_eq!(state["entries"][PURL]["record"]["uuid"], UUID, "{state:#}");
    assert!(
        !root.join(".socket/manifest.json").exists(),
        "a vendored scan must not write a manifest"
    );

    // C: a re-run is an in-sync no-op with no second takeover.
    let (code, env) = scan_mode(root, &server.uri(), "vendored", &[]);
    assert_eq!(code, 0, "{env:#}");
    find_event(&env["vendor"], "skipped", Some("already_vendored"));
    assert_no_event_code(&env["vendor"], "vendor_takeover_reverted_redirect");

    // D: `vendor --revert` restores the REGISTRY lock byte-exactly — the
    //    pre-redirect resolution the takeover carried forward, not the
    //    hosted splice.
    let (code, env) = vendor_cli(root, &["--revert"]);
    assert_eq!(code, 0, "revert must succeed: {env:#}");
    assert_eq!(
        std::fs::read(root.join("bun.lock")).unwrap(),
        pristine,
        "bun.lock must be restored byte-identical to the pristine registry lock; got:\n{}",
        read(root, "bun.lock")
    );
    assert!(
        !root.join(".socket/vendor").exists(),
        ".socket/vendor must be fully pruned after the revert"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 1b. Digest-less re-saves (Bun 1.1.39–1.3.9) across the conversions
// ─────────────────────────────────────────────────────────────────────
// Every text-lock release below 1.3.10 re-saves a URL or local-tarball
// 3-tuple WITHOUT its sha512 on any later lock re-save (`bun add`, `bun
// install` after a manifest change; measured on real 1.1.45, 1.2.23 and
// 1.3.9). The 2-tuple is still the recorded wiring (same key, spec and
// meta): the per-purl claim must not refuse it as drift, or the
// hosted→vendored takeover, `rollback <purl>` and `remove <purl>` all fail
// `redirect_revert_failed`; the vendored revert must claim it by path, or
// the vendored→hosted takeover fails `redirect_vendored_revert_failed`.

/// The line as Bun < 1.3.10 re-saves it: trailing `"sha512-…"` dropped.
fn drop_bun_digest(line: &str) -> String {
    let cut = line
        .rfind(", \"sha512-")
        .unwrap_or_else(|| panic!("no sha512 element in {line}"));
    let tail = if line.ends_with("],") { "]," } else { "]" };
    format!("{}{tail}", &line[..cut])
}

/// Re-spell the `key` packages line of the live bun.lock digest-less.
fn drop_digest_in_lock(root: &Path, key: &str) -> String {
    let lock = read(root, "bun.lock");
    let line = lock_line(&lock, key);
    let digestless = drop_bun_digest(&line);
    assert!(
        !digestless.contains("sha512") && digestless.ends_with("],"),
        "{digestless}"
    );
    std::fs::write(root.join("bun.lock"), lock.replace(&line, &digestless)).unwrap();
    digestless
}

fn redirect_warning_codes(env: &Value) -> Vec<String> {
    env["redirect"]["warnings"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|w| w["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn bun_digestless_hosted_line_is_taken_over_by_scan_vendored_and_reverts_to_registry() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_bun_project(root, &pristine_lock(), &[(NAME, VERSION)]);
    let pristine = std::fs::read(root.join("bun.lock")).unwrap();

    let (code, env) = scan_mode(root, &server.uri(), "hosted", &[]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(
        lock_line(&read(root, "bun.lock"), NAME),
        hosted_line(NAME, NAME, HOSTED_URL, PATCHED_SHA512)
    );
    let digestless = drop_digest_in_lock(root, NAME);
    assert!(digestless.contains(HOSTED_URL), "{digestless}");

    // The takeover over the digest-less hosted line: used to refuse
    // `redirect_revert_failed` ("has drifted from the recorded hosted
    // redirect") and vendor nothing.
    let (code, env) = scan_mode(root, &server.uri(), "vendored", &[]);
    assert_eq!(code, 0, "takeover over a digest-less hosted line: {env:#}");
    assert_eq!(env["status"], "success", "{env:#}");
    let vendor = &env["vendor"];
    assert_eq!(vendor["summary"]["applied"], 1, "{env:#}");
    assert_eq!(vendor["summary"]["failed"], 0, "{env:#}");
    find_event(vendor, "skipped", Some("vendor_takeover_reverted_redirect"));
    find_event(vendor, "applied", None);
    assert_no_event_code(vendor, "redirect_revert_failed");
    assert_pure_vendored(root);

    // And the vendored wiring, re-saved digest-less again, still reverts
    // to the pristine registry lock.
    drop_digest_in_lock(root, NAME);
    let (code, env) = vendor_cli(root, &["--revert"]);
    assert_eq!(code, 0, "revert over a digest-less vendored line: {env:#}");
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(
        std::fs::read(root.join("bun.lock")).unwrap(),
        pristine,
        "bun.lock restored byte-identical to the pristine registry lock; got:\n{}",
        read(root, "bun.lock")
    );
    assert!(
        !root.join(".socket/vendor").exists(),
        ".socket/vendor pruned"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bun_digestless_vendored_line_is_taken_over_by_scan_hosted_and_rolls_back_to_registry() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_bun_project(root, &pristine_lock(), &[(NAME, VERSION)]);
    let pristine = std::fs::read(root.join("bun.lock")).unwrap();

    let (code, env) = scan_mode(root, &server.uri(), "vendored", &[]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(env["vendor"]["summary"]["applied"], 1, "{env:#}");
    let digestless = drop_digest_in_lock(root, NAME);
    assert!(
        digestless.contains(&vendored_rel_tgz()),
        "the vendored spec survives the re-save: {digestless}"
    );

    // vendored → hosted over the digest-less local tuple: the vendored
    // revert claims the line by its `.socket/vendor/npm/<uuid>/` path.
    let (code, env) = scan_mode(root, &server.uri(), "hosted", &[]);
    assert_eq!(
        code, 0,
        "takeover over a digest-less vendored line: {env:#}"
    );
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let codes = redirect_warning_codes(&env);
    assert!(
        codes
            .iter()
            .any(|c| c == "redirect_takeover_reverted_vendored"),
        "the takeover must be announced: {codes:?}\n{env:#}"
    );
    assert!(
        !codes.iter().any(|c| c == "redirect_vendored_revert_failed"),
        "the vendored revert must not be refused: {env:#}"
    );
    let lock = read(root, "bun.lock");
    assert_eq!(
        lock_line(&lock, NAME),
        hosted_line(NAME, NAME, HOSTED_URL, PATCHED_SHA512),
        "hosted URL 3-tuple written:\n{lock}"
    );
    assert!(
        !lock.contains(".socket/vendor/npm/"),
        "the local tuple must be gone:\n{lock}"
    );
    assert!(
        !root.join(vendored_rel_tgz()).exists(),
        "the vendored artifact must be removed by the takeover"
    );
    let ledger: Value =
        serde_json::from_str(&read(root, ".socket/vendor/redirect-state.json")).unwrap();
    assert_eq!(
        ledger["edits"][0]["original"],
        json!(LEFT_PAD_REGISTRY_LINE),
        "the hosted ledger records the PRISTINE registry line as its original: {ledger:#}"
    );

    // Unscoped rollback of the hosted wiring lands on the pristine lock.
    let (code, env) = run_json(
        root,
        &[
            "rollback",
            "--yes",
            "--json",
            "--cwd",
            root.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(
        std::fs::read(root.join("bun.lock")).unwrap(),
        pristine,
        "pristine lock restored; got:\n{}",
        read(root, "bun.lock")
    );
}

#[test]
fn bun_scoped_rollback_and_remove_of_a_digestless_hosted_record_unwind_only_that_purl() {
    for verb in ["rollback", "remove"] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let pristine = write_two_record_hosted_project(root);
        let digestless = drop_digest_in_lock(root, NAME);
        assert!(digestless.contains(HOSTED_URL), "{digestless}");

        let (code, env) = run_json(
            root,
            &[
                verb,
                PURL,
                "--yes",
                "--json",
                "--cwd",
                root.to_str().unwrap(),
            ],
        );
        assert_eq!(
            code, 0,
            "scoped {verb} over a digest-less hosted line must succeed: {env:#}"
        );
        if verb == "rollback" {
            assert_eq!(env["hosted"]["reverted"], json!([PURL]), "{env:#}");
            assert_eq!(env["hosted"]["failed"], json!([]), "{env:#}");
        } else {
            assert!(env["error"].is_null(), "{env:#}");
        }
        assert_only_left_pad_unwound(root, &pristine);
    }
}

// ─────────────────────────────────────────────────────────────────────
// 2. vendor --dry-run over the live hosted redirect, then the wet vendor
// ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn bun_vendor_dry_run_previews_the_takeover_then_wet_vendor_completes_it() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_bun_project(root, &pristine_lock(), &[(NAME, VERSION)]);

    let (code, env) = scan_mode(root, &server.uri(), "hosted", &[]);
    assert_eq!(code, 0, "{env:#}");
    let hosted_lock = std::fs::read(root.join("bun.lock")).unwrap();
    let ledger_path = root.join(".socket/vendor/redirect-state.json");
    let hosted_ledger = std::fs::read(&ledger_path).unwrap();

    // The manifest record `vendor` acts on (offline: the staged blob).
    seed_manifest_and_blob(root);

    // Dry run: the takeover is PROBED (write-free) and previewed; the
    // backend preview does not run against the still-hosted lock, so no
    // false `vendor_lock_entry_not_found` and no refusal. Nothing written.
    let (code, env) = vendor_cli(root, &["--dry-run"]);
    assert_eq!(code, 0, "vendor --dry-run must succeed: {env:#}");
    let advisory = find_event(&env, "skipped", Some("vendor_would_revert_redirect"));
    assert_eq!(advisory["purl"], PURL, "{env:#}");
    assert_no_event_code(&env, "vendor_lock_entry_not_found");
    assert_no_event_code(&env, "redirect_revert_failed");
    assert_eq!(
        env["summary"]["failed"], 0,
        "the preview must not report a failure: {env:#}"
    );
    assert_eq!(
        std::fs::read(root.join("bun.lock")).unwrap(),
        hosted_lock,
        "a dry run must not touch bun.lock"
    );
    assert_eq!(
        std::fs::read(&ledger_path).unwrap(),
        hosted_ledger,
        "a dry run must not touch the redirect ledger"
    );
    assert!(
        !root.join(".socket/vendor/state.json").exists(),
        "a dry run must not create the vendor ledger"
    );

    // Wet `vendor`: the takeover the preview promised.
    let (code, env) = vendor_cli(root, &[]);
    assert_eq!(code, 0, "vendor must succeed: {env:#}");
    assert_eq!(env["summary"]["applied"], 1, "{env:#}");
    find_event(&env, "skipped", Some("vendor_takeover_reverted_redirect"));
    find_event(&env, "applied", None);
    assert_pure_vendored(root);
}

// ─────────────────────────────────────────────────────────────────────
// 3./4. scoped rollback / remove of ONE of two hosted bun records
// ─────────────────────────────────────────────────────────────────────

/// A hosted-live bun project with TWO redirect records, written exactly as
/// the hosted flow leaves them (ledger edits = verbatim lines, lock = the
/// URL 3-tuples). Two records make a scoped unwind of one purl ineligible
/// for the whole-ledger replay, so it takes the per-purl revert — the path
/// that used to refuse for bun.
fn write_two_record_hosted_project(root: &Path) -> String {
    let pristine = pristine_lock_two();
    write_bun_project(root, &pristine, &[(NAME, VERSION), (OTHER_NAME, "1.0.0")]);
    let left_pad_hosted = hosted_line(NAME, NAME, HOSTED_URL, PATCHED_SHA512);
    let other_hosted = hosted_line(
        OTHER_NAME,
        OTHER_NAME,
        OTHER_HOSTED_URL,
        "sha512-otherPATCHED==",
    );
    let hosted = pristine
        .replace(LEFT_PAD_REGISTRY_LINE, &left_pad_hosted)
        .replace(OTHER_REGISTRY_LINE, &other_hosted);
    assert_ne!(hosted, pristine);
    std::fs::write(root.join("bun.lock"), &hosted).unwrap();
    let ledger = json!({
        "version": 1,
        "mode": "hosted",
        "edits": [
            {
                "path": "bun.lock",
                "kind": "redirect_bun_lock_package",
                "action": "rewritten",
                "key": NAME,
                "original": LEFT_PAD_REGISTRY_LINE,
                "new": left_pad_hosted,
            },
            {
                "path": "bun.lock",
                "kind": "redirect_bun_lock_package",
                "action": "rewritten",
                "key": OTHER_NAME,
                "original": OTHER_REGISTRY_LINE,
                "new": other_hosted,
            }
        ],
        "records": {
            PURL: patch_record(UUID),
            OTHER_PURL: patch_record(OTHER_UUID),
        }
    });
    std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
    std::fs::write(
        root.join(".socket/vendor/redirect-state.json"),
        serde_json::to_vec_pretty(&ledger).unwrap(),
    )
    .unwrap();
    pristine
}

/// After unwinding ONLY `left-pad`: its line is the registry tuple, `other`
/// is still hosted, and the ledger keeps exactly `other`'s record + edit.
fn assert_only_left_pad_unwound(root: &Path, pristine: &str) {
    let lock = read(root, "bun.lock");
    assert_eq!(
        lock_line(&lock, NAME),
        lock_line(pristine, NAME),
        "left-pad back to its registry tuple:\n{lock}"
    );
    assert!(
        lock_line(&lock, OTHER_NAME).contains(OTHER_HOSTED_URL),
        "other must stay hosted:\n{lock}"
    );
    let ledger: Value =
        serde_json::from_str(&read(root, ".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger["records"].get(PURL).is_none() && ledger["records"].get(OTHER_PURL).is_some(),
        "{ledger:#}"
    );
    let edits = ledger["edits"].as_array().unwrap();
    assert_eq!(edits.len(), 1, "{ledger:#}");
    assert_eq!(edits[0]["key"], OTHER_NAME, "{ledger:#}");
}

#[test]
fn bun_scoped_rollback_of_one_of_two_hosted_records_unwinds_only_that_purl() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pristine = write_two_record_hosted_project(root);

    // Scoped rollback: per-purl path (two records ⇒ the replay is not
    // eligible). Used to exit 1 with hosted.failed = ["cannot replay yet"].
    let (code, env) = run_json(
        root,
        &[
            "rollback",
            PURL,
            "--yes",
            "--json",
            "--cwd",
            root.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "scoped rollback must succeed: {env:#}");
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(env["hosted"]["reverted"], json!([PURL]), "{env:#}");
    assert_eq!(env["hosted"]["failed"], json!([]), "{env:#}");
    assert_only_left_pad_unwound(root, &pristine);

    // The last record out: covers every record ⇒ whole-ledger replay;
    // pristine lock, ledger deleted.
    let (code, env) = run_json(
        root,
        &[
            "rollback",
            OTHER_PURL,
            "--yes",
            "--json",
            "--cwd",
            root.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(read(root, "bun.lock"), pristine, "pristine lock restored");
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "emptied ledger deleted"
    );
}

#[test]
fn bun_scoped_remove_of_one_of_two_hosted_records_unwinds_only_that_purl() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pristine = write_two_record_hosted_project(root);

    // `remove <purl>` takes the same per-purl hosted leg; used to exit 1
    // with `hosted_revert_failed`.
    let (code, env) = run_json(
        root,
        &[
            "remove",
            PURL,
            "--yes",
            "--json",
            "--cwd",
            root.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "scoped remove must succeed: {env:#}");
    assert!(
        env["error"].is_null(),
        "no top-level error expected: {env:#}"
    );
    assert_only_left_pad_unwound(root, &pristine);
}

// ─────────────────────────────────────────────────────────────────────
// 5. hosted-wired pre-v2 WORKSPACE lock: `vendor` refuses BEFORE un-hosting
// ─────────────────────────────────────────────────────────────────────
// Hosted mode accepts a lockfileVersion-1 workspace lock (a URL tuple has
// no path to resolve); the vendored backend refuses every pre-v2 workspace
// lock (`vendor_bun_workspace_unsupported`). The plain `vendor` command
// used to run the takeover FIRST — revert the hosted line, persist the
// redirect-ledger drop — and only then hear the engine's refusal, leaving
// the project unpatched in BOTH modes while the refusal's remedy pointed
// at the hosted mode it had just destroyed; its dry run promised the
// takeover (`vendor_would_revert_redirect`, status success) outright. The
// Bun preflight now runs inside the engine loop before the takeover block.

const WS_CODE: &str = "vendor_bun_workspace_unsupported";

#[tokio::test]
async fn bun_hosted_refusal_preserves_vendored_v0_workspace() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let direct = pristine_lock()
        .replace("\"lockfileVersion\": 2", "\"lockfileVersion\": 0")
        .replace("  \"configVersion\": 1,\n", "");
    write_bun_project(root, &direct, &[(NAME, VERSION)]);
    seed_manifest_and_blob(root);
    let (code, env) = vendor_cli(root, &["--vendor-source", "build"]);
    assert_eq!(code, 0, "{env:#}");

    // Bun 1.1.45 preserves the local tuple when a direct project grows an
    // unrelated workspace. Its old lock remains consumable and patched.
    let lock = read(root, "bun.lock").replace(
        "  \"packages\": {\n",
        "  \"packages\": {\n    \"consumer\": [\"consumer@workspace:packages/consumer\", {}],\n\n",
    );
    std::fs::write(root.join("bun.lock"), &lock).unwrap();
    let state = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();
    let artifact = std::fs::read(root.join(vendored_rel_tgz())).unwrap();
    let manifest = std::fs::read(root.join(".socket/manifest.json")).unwrap();

    for extra in [&["--dry-run"][..], &[][..]] {
        let (code, env) = scan_mode(root, &server.uri(), "hosted", extra);
        assert_eq!(code, 0, "{env:#}");
        assert_eq!(env["redirect"]["redirected"], 0, "{env:#}");
        let warnings = env["redirect"]["warnings"].as_array().unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w["code"] == "redirect_bun_workspace_unsupported"),
            "{env:#}"
        );
        assert!(
            warnings
                .iter()
                .all(|w| w["code"] != "redirect_would_revert_vendored"
                    && w["code"] != "redirect_takeover_reverted_vendored"),
            "{env:#}"
        );
        assert_eq!(read(root, "bun.lock"), lock);
        assert_eq!(
            std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
            state
        );
        assert_eq!(
            std::fs::read(root.join(vendored_rel_tgz())).unwrap(),
            artifact
        );
        assert_eq!(
            std::fs::read(root.join(".socket/manifest.json")).unwrap(),
            manifest
        );
        assert!(!root.join(".socket/vendor/redirect-state.json").exists());
    }
}

#[test]
fn bun_vendor_silent_refusal_keeps_error_diagnosis() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let lock = write_hosted_workspace_project(root, 1);
    let ledger = std::fs::read(root.join(".socket/vendor/redirect-state.json")).unwrap();
    for dry_run in [true, false] {
        let mut args = vec![
            "vendor",
            "--offline",
            "--silent",
            "--cwd",
            root.to_str().unwrap(),
        ];
        if dry_run {
            args.push("--dry-run");
        }
        let (code, stdout, stderr) = run_cli(root, &args);
        assert_eq!(code, 1);
        assert!(stdout.is_empty(), "{stdout}");
        assert!(
            stderr.contains("Cannot vendor") && stderr.contains("lockfileVersion-1"),
            "{stderr}"
        );
        assert_hosted_wiring_intact(root, &lock, &ledger);
    }
}

/// Pristine `lockfileVersion` workspace lock — root + a `packages/consumer`
/// member declaring left-pad — in the real bun 1.3.14 (v1) / 1.4.2 (v2)
/// grammar: `configVersion`, the member's 1-tuple `workspace:` entry, a
/// blank line between entries, trailing commas.
fn pristine_workspace_lock(version: u64) -> String {
    format!(
        "{{\n  \"lockfileVersion\": {version},\n  \"configVersion\": 1,\n  \"workspaces\": {{\n    \"\": {{\n      \"name\": \"bun-takeover-fixture\",\n      \"dependencies\": {{\n        \"consumer\": \"workspace:*\",\n      }},\n    }},\n    \"packages/consumer\": {{\n      \"name\": \"consumer\",\n      \"version\": \"1.0.0\",\n      \"dependencies\": {{\n        \"left-pad\": \"1.3.0\",\n      }},\n    }},\n  }},\n  \"packages\": {{\n    \"consumer\": [\"consumer@workspace:packages/consumer\"],\n\n{LEFT_PAD_REGISTRY_LINE}\n  }}\n}}\n"
    )
}

/// A hosted-live WORKSPACE bun project with ONE redirect record, written
/// exactly as `scan --mode hosted` leaves it, plus the manifest record and
/// blob a default-mode `get`/`scan` adds — the shape the plain `vendor`
/// command acts on (a hosted-only project is a `noManifest` no-op).
/// Returns the hosted lock text.
fn write_hosted_workspace_project(root: &Path, version: u64) -> String {
    let pristine = pristine_workspace_lock(version);
    write_bun_project(root, &pristine, &[(NAME, VERSION)]);
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"bun-takeover-fixture","version":"1.0.0","private":true,"workspaces":["packages/*"],"dependencies":{"consumer":"workspace:*"}}"#,
    )
    .unwrap();
    let consumer = root.join("packages/consumer");
    std::fs::create_dir_all(&consumer).unwrap();
    std::fs::write(
        consumer.join("package.json"),
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    let left_pad_hosted = hosted_line(NAME, NAME, HOSTED_URL, PATCHED_SHA512);
    let hosted = pristine.replace(LEFT_PAD_REGISTRY_LINE, &left_pad_hosted);
    assert_ne!(hosted, pristine, "the hosted splice must hit");
    std::fs::write(root.join("bun.lock"), &hosted).unwrap();
    let ledger = json!({
        "version": 1,
        "mode": "hosted",
        "edits": [{
            "path": "bun.lock",
            "kind": "redirect_bun_lock_package",
            "action": "rewritten",
            "key": NAME,
            "original": LEFT_PAD_REGISTRY_LINE,
            "new": left_pad_hosted,
        }],
        "records": { PURL: patch_record(UUID) },
    });
    std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
    std::fs::write(
        root.join(".socket/vendor/redirect-state.json"),
        serde_json::to_vec_pretty(&ledger).unwrap(),
    )
    .unwrap();
    seed_manifest_and_blob(root);
    hosted
}

/// Every byte of the hosted wiring must survive a refused run: the lock,
/// the redirect ledger (record + edit), and no vendor ledger or artifact.
fn assert_hosted_wiring_intact(root: &Path, hosted_lock: &str, hosted_ledger: &[u8]) {
    assert_eq!(
        read(root, "bun.lock"),
        hosted_lock,
        "bun.lock must stay byte-identical to the hosted lock"
    );
    let ledger_path = root.join(".socket/vendor/redirect-state.json");
    assert_eq!(
        std::fs::read(&ledger_path).unwrap(),
        hosted_ledger,
        "the redirect ledger must stay byte-identical"
    );
    let ledger: Value =
        serde_json::from_str(&read(root, ".socket/vendor/redirect-state.json")).unwrap();
    assert!(ledger["records"].get(PURL).is_some(), "{ledger:#}");
    let edits = ledger["edits"].as_array().unwrap();
    assert_eq!(edits.len(), 1, "{ledger:#}");
    assert_eq!(edits[0]["key"], NAME, "{ledger:#}");
    assert!(
        !root.join(".socket/vendor/state.json").exists(),
        "a refused run must not create the vendor ledger"
    );
    assert!(
        !root.join(".socket/vendor/npm").exists(),
        "a refused run must not stage or pack an artifact"
    );
}

#[test]
fn bun_vendor_over_hosted_v1_workspace_lock_refuses_before_unhosting() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let hosted_lock = write_hosted_workspace_project(root, 1);
    let hosted_ledger = std::fs::read(root.join(".socket/vendor/redirect-state.json")).unwrap();

    // Dry run: previews the REFUSAL, not the takeover, with the wet run's
    // exit code — and writes nothing.
    let (code, env) = vendor_cli(root, &["--dry-run"]);
    assert_eq!(
        code, 1,
        "the preview must exit like the wet run it predicts: {env:#}"
    );
    assert_eq!(env["status"], "partialFailure", "{env:#}");
    assert_eq!(env["dryRun"], true, "{env:#}");
    let failed = find_event(&env, "failed", Some(WS_CODE));
    assert_eq!(failed["purl"], PURL, "{env:#}");
    assert_eq!(env["summary"]["failed"], 1, "{env:#}");
    assert_no_event_code(&env, "vendor_would_revert_redirect");
    assert_no_event_code(&env, "vendor_takeover_reverted_redirect");
    assert_no_event_code(&env, "redirect_revert_failed");
    assert_hosted_wiring_intact(root, &hosted_lock, &hosted_ledger);

    // Wet run: the same refusal, BEFORE any revert — hosted wiring intact.
    // Used to: `skipped vendor_takeover_reverted_redirect` then `failed
    // vendor_bun_workspace_unsupported`, registry tuple back in the lock,
    // redirect-state.json deleted, `.socket/vendor/` empty.
    let (code, env) = vendor_cli(root, &[]);
    assert_eq!(code, 1, "the wet run refuses: {env:#}");
    assert_eq!(env["status"], "partialFailure", "{env:#}");
    let failed = find_event(&env, "failed", Some(WS_CODE));
    assert_eq!(failed["purl"], PURL, "{env:#}");
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|d| d.contains("lockfileVersion-1 lock") && d.contains("--mode hosted")),
        "the detail names the version and the hosted alternative this run left in place: {env:#}"
    );
    assert_eq!(env["summary"]["applied"], 0, "{env:#}");
    assert_eq!(env["summary"]["failed"], 1, "{env:#}");
    assert_no_event_code(&env, "vendor_takeover_reverted_redirect");
    assert_no_event_code(&env, "vendor_would_revert_redirect");
    assert_no_event_code(&env, "redirect_revert_failed");
    assert_hosted_wiring_intact(root, &hosted_lock, &hosted_ledger);

    // The manifest record survives too (the recovery path — a networked
    // `scan --mode hosted` — needs nothing this run could have dropped).
    let manifest: Value = serde_json::from_str(&read(root, ".socket/manifest.json")).unwrap();
    assert_eq!(manifest["patches"][PURL]["uuid"], UUID, "{manifest:#}");
}

/// The lockfileVersion-2 twin: hosted mode and the vendored backend both
/// accept it, so the takeover still completes — the preflight must not
/// over-refuse the supported workspace shape.
#[test]
fn bun_vendor_over_hosted_v2_workspace_lock_still_takes_over() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_hosted_workspace_project(root, 2);

    let (code, env) = vendor_cli(root, &["--dry-run"]);
    assert_eq!(code, 0, "{env:#}");
    find_event(&env, "skipped", Some("vendor_would_revert_redirect"));
    assert_no_event_code(&env, WS_CODE);

    let (code, env) = vendor_cli(root, &[]);
    assert_eq!(code, 0, "the v2 takeover must succeed: {env:#}");
    assert_eq!(env["summary"]["applied"], 1, "{env:#}");
    find_event(&env, "skipped", Some("vendor_takeover_reverted_redirect"));
    find_event(&env, "applied", None);
    assert_no_event_code(&env, WS_CODE);
    assert_pure_vendored(root);
    let lock = read(root, "bun.lock");
    assert!(
        lock.contains("    \"consumer\": [\"consumer@workspace:packages/consumer\"],\n"),
        "the workspace entry survives the takeover:\n{lock}"
    );
    assert!(lock.starts_with("{\n  \"lockfileVersion\": 2,\n"), "{lock}");
}
