//! Hermetic npm-family mode-takeover contract tests through the built
//! binary: bun below, vlt in `in_process_vendor_bun_takeover/vlt.rs`.
//!
//! Twin of the yarn legs in `mode_migration_npm.rs` and the pnpm
//! `hosted_to_vendor_conversion` module in `in_process_vendor.rs`, for the
//! bun lock flavor: the bun hosted rewrite REPLACES the registry 4-tuple's `name@version` spec with
//! a URL 3-tuple, so without the per-purl pre-revert the bun vendor backend
//! cannot even find the entry. The API is wiremock; no `bun` binary is
//! needed (the lock grammar is the real bun 1.4.2 lockfileVersion-2 shape
//! from the compatibility matrix captures, and the packages tuple grammar
//! is identical on versions 0/1/2).
//!
//! v5: hosted mode keeps no ledger — the hosted state is the lock's URL
//! 3-tuple alone. Every unwind of a hosted pin (the vendor takeover,
//! `rollback`, `remove`) restores the registry 4-tuple, re-resolving the
//! integrity from the npm registry: here one shared wiremock mirror
//! ([`registry_uri`], `SOCKET_NPM_REGISTRY`) serving the pristine
//! integrities, with the `https://patch.socket.dev` origin named hosted via
//! `SOCKET_PATCH_SERVER_URL`.
//!
//! Scenarios:
//!   1. `scan --mode hosted` → `scan --mode vendored`: the takeover restores
//!      the registry line, vendors from it (the vendor ledger's `original`
//!      is the REGISTRY tuple, never the hosted URL), and `vendor --revert`
//!      restores the pristine bytes.
//!   2. `vendor --dry-run` over the live hosted pin previews the takeover
//!      (`vendor_would_revert_redirect`) with no false
//!      `vendor_lock_entry_not_found` follow-up and no writes; the wet
//!      `vendor` then completes it.
//!   3. Two hosted pins: a SCOPED `rollback <purl>` restores only the
//!      targeted line; the sibling stays hosted.
//!   4. Same project, `remove <purl>`.
//!   5. A hosted-wired lockfileVersion-1 WORKSPACE lock (hosted accepts it,
//!      the vendored backend refuses it): `vendor` — dry and wet — refuses
//!      `vendor_bun_workspace_unsupported` BEFORE the takeover restores
//!      anything, so the hosted wiring survives byte-for-byte; the v2 twin
//!      still takes over.
//!
//! Every child process gets the ambient `SOCKET_*` vars scrubbed and
//! telemetry hard-disabled; each test runs in its own tempdir.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "vex_e2e_common/bun.rs"]
mod bun_vex;
#[path = "in_process_vendor_bun_takeover/vlt.rs"]
mod vlt;
#[path = "vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;

const ORG: &str = "test-org";
const NAME: &str = "left-pad";
const VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
/// Canonical-grammar patch uuid (the vendor path layer validates the uuid
/// path level fail-closed).
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const HOSTED_URL: &str = "https://patch.socket.dev/patch/npm/left-pad/1.3.0/55555555-5555-4555-8555-555555555555/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";
/// The vulnerability the patch record carries — what manifest-less VEX must
/// attest after each mode lands.
const GHSA: &str = "GHSA-bunt-akeo-0001";
const CVE: &str = "CVE-2026-5555";

/// The second hosted record of the scoped-unwind scenarios.
const OTHER_NAME: &str = "other";
const OTHER_PURL: &str = "pkg:npm/other@1.0.0";
const OTHER_HOSTED_URL: &str = "https://patch.socket.dev/patch/npm/other/1.0.0/55555555-5555-4555-8555-555555555555/0a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d/other-1.0.0.tgz";

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
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "bun takeover vuln",
            "severity": "high", "description": "d"
        }},
        "description": "bun takeover fixture",
        "license": "MIT",
        "tier": "free"
    })
}

/// `.socket/manifest.json` + the after-hash blob, so `vendor` needs no API
/// (hosted mode writes no manifest).
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

/// The manifest-less VEX step ([`bun_vex::run_bun_vex_matrix`]) on a
/// lockfile-only checkout of `root` (no bun here: nothing is installed, so
/// a hosted ref is judged by the lock's sha512 pin and a vendored one by
/// the committed artifact): attested with `mode`'s marker from the ledger
/// and from the lock + patch API; offline → `record_unavailable`; the
/// pristine lock back → NOT attested.
fn manifestless_vex(
    root: &Path,
    scratch: &Path,
    mode: bun_vex::BunMode,
    pristine: &[u8],
    tag: &str,
) {
    let case = bun_vex::BunVexCase {
        tag,
        mode,
        purl: PURL,
        uuid: UUID,
        files: vec![(
            "package/index.js".to_string(),
            compute_git_sha256_from_bytes(PATCHED_INDEX),
        )],
        vulns: &[(GHSA, &[CVE])],
        lock: "bun.lock",
        registry_lock: pristine.to_vec(),
        patch_server_url: Some("https://patch.socket.dev".to_string()),
    };
    bun_vex::run_bun_vex_matrix(root, scratch, &case, |_| {});
}

// ───────────────────────── subprocess runner ─────────────────────────

/// The `sha512-…` integrity of a registry 4-tuple line (its last string).
fn line_integrity(line: &str) -> String {
    line.rsplit('"')
        .nth(1)
        .filter(|s| s.starts_with("sha512-"))
        .unwrap_or_else(|| panic!("no integrity in {line}"))
        .to_string()
}

/// One npm registry mirror shared by every test in this binary: the
/// version documents of `left-pad@1.3.0` and `other@1.0.0` carrying the
/// integrities of the pristine registry lines, which is all the v5 upstream
/// restore of a bun.lock entry reads. It runs on its own thread + runtime
/// for the life of the process (the per-test runtimes come and go).
fn registry_uri() -> &'static str {
    static URI: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URI.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("registry mirror runtime");
            rt.block_on(async move {
                let server = MockServer::start().await;
                for (name, version, line) in [
                    (NAME, VERSION, LEFT_PAD_REGISTRY_LINE),
                    (OTHER_NAME, "1.0.0", OTHER_REGISTRY_LINE),
                ] {
                    Mock::given(method("GET"))
                        .and(path(format!("/{name}/{version}")))
                        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                            "name": name,
                            "version": version,
                            "dist": {
                                "tarball": format!(
                                    "https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"
                                ),
                                "integrity": line_integrity(line)
                            }
                        })))
                        .mount(&server)
                        .await;
                }
                tx.send(server.uri()).expect("hand back the mirror uri");
                std::future::pending::<()>().await;
            });
        });
        rx.recv().expect("registry mirror started")
    })
}

/// Run the built `socket-patch` binary with every ambient `SOCKET_*` var
/// scrubbed (except the hermetic `SOCKET_NO_CONFIG`) and telemetry
/// hard-disabled; `https://patch.socket.dev` counts as the patch server
/// (`SOCKET_PATCH_SERVER_URL`) and the registry is the shared mirror
/// (`SOCKET_NPM_REGISTRY`). Returns `(exit_code, stdout, stderr)`.
fn run_cli(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.current_dir(cwd);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NPM_REGISTRY", registry_uri());
    let _fixture = prebuilt_common::prepare_command(&mut cmd, cwd, args, &[]);
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
    let fixture = (mode == "vendored").then(|| {
        let mut view = patch_record(UUID);
        view["purl"] = json!(PURL);
        view["publishedAt"] = json!("2024-01-01T00:00:00Z");
        view["files"]["package/index.js"]["blobContent"] =
            json!(base64::engine::general_purpose::STANDARD.encode(PATCHED_INDEX));
        prebuilt_common::Server::view(view)
    });
    if let Some(fixture) = &fixture {
        args.extend(["--vendor-url", &fixture.uri]);
    }
    args.extend_from_slice(extra);
    run_json(cwd, &args)
}

/// `vendor --json` — online: a takeover's upstream restore reads the
/// registry mirror.
fn vendor_cli(cwd: &Path, extra: &[&str]) -> (i32, Value) {
    let mut args = vec!["vendor", "--json", "--cwd", cwd.to_str().unwrap()];
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
/// has happened: no hosted ledger exists, bun.lock carries the local tuple
/// and no hosted residue, and the vendor ledger's recorded `original` is
/// the PRISTINE registry line (the takeover's upstream restore).
fn assert_pure_vendored(root: &Path) {
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "no hosted ledger may exist"
    );

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

    // A: hosted redirect — registry 4-tuple → URL 3-tuple; no ledger.
    let (code, env) = scan_mode(root, &server.uri(), "hosted", &[]);
    assert_eq!(code, 0, "scan --mode hosted must succeed: {env:#}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let hosted_lock = read(root, "bun.lock");
    assert_eq!(
        lock_line(&hosted_lock, NAME),
        hosted_line(NAME, NAME, HOSTED_URL, PATCHED_SHA512),
        "hosted URL 3-tuple written:\n{hosted_lock}"
    );
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "hosted mode writes no ledger: {env:#}"
    );
    let scratch = tempfile::tempdir().unwrap();
    manifestless_vex(
        root,
        scratch.path(),
        bun_vex::BunMode::Hosted,
        &pristine,
        "hosted",
    );

    // The scan-side vendored preview is ledger-only by contract
    // (`would_vendor` / `already_vendored` / `would_revendor`, CLI_CONTRACT
    // "scan --mode vendored"): it must at least not fail and not write anything.
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

    // B: vendored scan over the LIVE hosted pin — the takeover restores the
    //    registry line first, then vendors.
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
    manifestless_vex(
        root,
        scratch.path(),
        bun_vex::BunMode::Vendored,
        &pristine,
        "vendored",
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
// 1a. Lockfile-only checkouts (no node_modules) see the hosted pin (#720)
// ─────────────────────────────────────────────────────────────────────
// The usual CI shape: a committed hosted bun.lock and no install. The
// lockfile inventory must still name the hosted-pinned package, or a
// hosted re-run never moves to a superseding patch and `scan --mode
// vendored` never takes the pin over — both "success" with 0 packages.

/// A superseded patch's uuid: the hosted pin an earlier scan committed.
const SUPERSEDED_UUID: &str = "1e2d3c4b-5a69-4788-9a6b-5c4d3e2f1a0b";

/// A lockfile-only bun project whose lock pins `left-pad` to `url`.
fn write_lockfile_only_hosted_project(root: &Path, url: &str) -> String {
    write_bun_project(root, &pristine_lock(), &[(NAME, VERSION)]);
    let lock = pristine_lock().replace(
        LEFT_PAD_REGISTRY_LINE,
        &hosted_line(NAME, NAME, url, PATCHED_SHA512),
    );
    assert_ne!(lock, pristine_lock(), "replacement must hit");
    std::fs::write(root.join("bun.lock"), &lock).unwrap();
    std::fs::remove_dir_all(root.join("node_modules")).unwrap();
    lock
}

#[tokio::test(flavor = "multi_thread")]
async fn bun_lockfile_only_hosted_rerun_moves_to_a_superseding_patch() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let superseded_url = HOSTED_URL.replace(UUID, SUPERSEDED_UUID);
    write_lockfile_only_hosted_project(root, &superseded_url);

    let (code, env) = scan_mode(root, &server.uri(), "hosted", &[]);
    assert_eq!(code, 0, "hosted re-run must succeed: {env:#}");
    assert_eq!(
        env["scannedPackages"], 1,
        "the hosted pin must be seen: {env:#}"
    );
    let lock = read(root, "bun.lock");
    assert_eq!(
        lock_line(&lock, NAME),
        hosted_line(NAME, NAME, HOSTED_URL, PATCHED_SHA512),
        "the re-run must re-pin to the superseding patch:\n{lock}"
    );
    assert!(!lock.contains(SUPERSEDED_UUID), "{lock}");
    assert!(!root.join("node_modules").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn bun_lockfile_only_scan_vendored_takes_over_the_hosted_pin() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let hosted_lock = write_lockfile_only_hosted_project(root, HOSTED_URL);

    let (code, env) = scan_mode(root, &server.uri(), "vendored", &[]);
    assert_eq!(code, 0, "vendored takeover must succeed: {env:#}");
    assert_eq!(
        env["scannedPackages"], 1,
        "the hosted pin must be seen: {env:#}"
    );
    let vendor = &env["vendor"];
    assert_eq!(vendor["summary"]["applied"], 1, "{env:#}");
    assert_eq!(vendor["summary"]["failed"], 0, "{env:#}");
    find_event(vendor, "skipped", Some("vendor_takeover_reverted_redirect"));
    assert_ne!(read(root, "bun.lock"), hosted_lock, "bun.lock must change");
    assert_pure_vendored(root);
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

    // The takeover over the digest-less hosted line must not refuse
    // `redirect_revert_failed` ("has drifted from the recorded hosted
    // redirect").
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
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "hosted mode writes no ledger"
    );

    // Unscoped rollback of the hosted pin restores its upstream entry: the
    // pristine lock.
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
    assert!(!ledger_path.exists(), "hosted mode writes no ledger");

    // The manifest record `vendor` acts on (the staged blob).
    seed_manifest_and_blob(root);

    // Dry run: the takeover's upstream restore is resolved write-free and
    // previewed; the backend preview does not run against the still-hosted
    // lock, so no false `vendor_lock_entry_not_found` and no refusal.
    // Nothing written.
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
    assert!(!ledger_path.exists(), "a dry run writes no hosted ledger");
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

/// A hosted-live bun project with TWO hosted pins, written exactly as the
/// v5 hosted flow leaves it: the lock's URL 3-tuples and nothing else (no
/// ledger).
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
    pristine
}

/// After unwinding ONLY `left-pad`: its line is the registry tuple, `other`
/// is still hosted, and no ledger exists.
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
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "no hosted ledger may exist"
    );
}

#[test]
fn bun_scoped_rollback_of_one_of_two_hosted_records_unwinds_only_that_purl() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pristine = write_two_record_hosted_project(root);

    // Scoped rollback: only left-pad's pin is restored to its upstream
    // registry line; `other` stays hosted.
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

    // The last pin out: pristine lock, no ledger anywhere.
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
        "no hosted ledger"
    );
}

#[test]
fn bun_scoped_remove_of_one_of_two_hosted_records_unwinds_only_that_purl() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pristine = write_two_record_hosted_project(root);

    // `remove <purl>` takes the same per-purl hosted leg.
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
// lock (`vendor_bun_workspace_unsupported`). The Bun preflight runs inside
// the engine loop before the takeover block, so a refused `vendor` (and its
// dry run) never restores the hosted line to upstream first — which would
// leave the project unpatched in BOTH modes.

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
    let (code, env) = vendor_cli(root, &["--vendor-source", "service"]);
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
        assert_hosted_wiring_intact(root, &lock);
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

/// A hosted-live WORKSPACE bun project with ONE hosted pin, written
/// exactly as `scan --mode hosted` leaves it (no ledger), plus the manifest
/// record and
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
    seed_manifest_and_blob(root);
    hosted
}

/// Every byte of the hosted wiring must survive a refused run: the lock
/// (the only hosted state), and no vendor ledger or artifact.
fn assert_hosted_wiring_intact(root: &Path, hosted_lock: &str) {
    assert_eq!(
        read(root, "bun.lock"),
        hosted_lock,
        "bun.lock must stay byte-identical to the hosted lock"
    );
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "no hosted ledger may appear"
    );
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
    assert_hosted_wiring_intact(root, &hosted_lock);

    // Wet run: the same refusal, BEFORE any restore — hosted wiring intact.
    // Used to: `skipped vendor_takeover_reverted_redirect` then `failed
    // vendor_bun_workspace_unsupported`, registry tuple back in the lock,
    // `.socket/vendor/` empty.
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
    assert_hosted_wiring_intact(root, &hosted_lock);

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
