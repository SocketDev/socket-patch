//! Shared fixture for the `scan --mode hosted` suites (#1089): the API
//! mocks, project writers and runners `hosted_failure_paths.rs` (the
//! `--json` contracts) and `hosted_render.rs` (the human output) build on.
//!
//! Everything runs the built binary as a subprocess via
//! `common::run_with_env` (hermetic `SOCKET_*` scrub, child-only env
//! injection) so both the `--json` envelope and the human stdout/stderr can
//! be read back; no parent-process env is ever mutated, so no
//! serialization is needed.

// Each suite uses a different subset, and some re-exports only from
// `cfg(unix)` tests.
#![allow(dead_code, unused_imports)]

use std::path::Path;

pub(crate) use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common;
pub(crate) use crate::common::envelope::{
    all_codes, codes_in, envelope_error_code, envelope_error_message, hosted_pins,
};

/// The hosted `skipped` events as the pre-v5.0 `redirect.skipped[]` rows
/// (`{purl, uuid, reason: <errorCode>, detail?: <reason>}`).
pub(crate) fn hosted_skipped(doc: &Value) -> Vec<Value> {
    doc["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["details"]["mode"] == "hosted" && e["action"] == "skipped")
        .map(|e| {
            let mut row = json!({"purl": e["purl"], "uuid": e["uuid"], "reason": e["errorCode"]});
            if e["reason"].is_string() {
                row["detail"] = e["reason"].clone();
            }
            row
        })
        .collect()
}

pub(crate) const ORG: &str = "test-org";
pub(crate) const NAME: &str = "covgap-hosted";
pub(crate) const VERSION: &str = "1.0.0";
pub(crate) const PURL: &str = "pkg:npm/covgap-hosted@1.0.0";
pub(crate) const UUID: &str = "11111111-1111-4111-8111-111111111111";
pub(crate) const HOSTED_URL: &str = "http://patch.test/patch/npm/covgap-hosted/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/covgap-hosted-1.0.0.tgz";
pub(crate) const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
/// The grant's sha1: yarn classic pins it as `resolved`'s `#` fragment (#558).
pub(crate) const PATCHED_SHA1: &str = "5ba15ba15ba15ba15ba15ba15ba15ba15ba15ba1";
pub(crate) const UPSTREAM_SHA512: &str = "sha512-UPSTREAMupstream==";
pub(crate) const GHSA: &str = "GHSA-cvgp-hstd-aaaa";

// ───────────────────────────── API mocks ─────────────────────────────

/// Batch discovery + per-package search for one `(purl, uuid)` pair.
pub(crate) async fn mock_discovery(server: &MockServer, purl: &str, uuid: &str) {
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
pub(crate) async fn mock_reference_results(server: &MockServer, results: Value) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": results })))
        .mount(server)
        .await;
}

/// The standard granted tarball reference for `(uuid, purl, url)`.
pub(crate) async fn mock_granted_reference(server: &MockServer, uuid: &str, purl: &str, url: &str) {
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
                    "integrity": { "sha512": PATCHED_SHA512, "sha1": PATCHED_SHA1 }
                }],
                "registryOverride": null
            }
        }),
    )
    .await;
}

/// `view/{uuid}` — the record a confirmed redirect persists for VEX.
pub(crate) async fn mock_view(server: &MockServer, uuid: &str, purl: &str) {
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
pub(crate) fn write_npm_project(root: &Path, name: &str) {
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
pub(crate) fn write_pnpm_project(root: &Path) {
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

/// Malformed binary Bun project with an installed package, to exercise
/// preflight and hosted format diagnostics without a valid binary fixture.
pub(crate) fn write_bun_lockb_project(root: &Path) {
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
pub(crate) fn install_bun_shim(root: &Path, body: &str) -> String {
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
pub(crate) fn write_rush_project(root: &Path) {
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
pub(crate) fn write_vendor_state(root: &Path, purl: &str, uuid: &str, flavor: &str) {
    write_vendor_state_wired(root, purl, uuid, flavor, json!([]));
}

/// [`write_vendor_state`] with explicit `wiring` records (the camelCase
/// `WiringRecord` shape) — for the takeover tests whose revert must have a
/// lock fragment to restore.
pub(crate) fn write_vendor_state_wired(
    root: &Path,
    purl: &str,
    uuid: &str,
    flavor: &str,
    wiring: Value,
) {
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
                "wiring": wiring,
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
pub(crate) fn scan_hosted(
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
pub(crate) fn scan_hosted_json(
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

/// The `detail` of the first warning carrying `code` (panics when absent).
pub(crate) fn warning_detail<'a>(doc: &'a Value, code: &str) -> &'a str {
    doc["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|w| w["code"] == code)
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_else(|| panic!("expected a `{code}` warning: {doc:#}"))
}

/// A fake `bun` that records the spawn in `marker` (an absolute path, so the
/// child's cwd is irrelevant) and then fails. Every test using it asserts
/// the marker is ABSENT: the gate under test must refuse before any spawn.
#[cfg(unix)]
pub(crate) fn install_marker_bun_shim(root: &Path) -> (String, std::path::PathBuf) {
    let marker = root.join("bun-was-spawned");
    let path_value = install_bun_shim(
        root,
        &format!("#!/bin/sh\ntouch \"{}\"\nexit 1\n", marker.display()),
    );
    (path_value, marker)
}

#[cfg(unix)]
pub(crate) fn mkfifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt as _;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
    assert_eq!(rc, 0, "mkfifo(2): {}", std::io::Error::last_os_error());
}

/// `scan_hosted_json` on a worker thread with a deadline: a wedged run never
/// returns, so on timeout a writer is connected to `fifo` (releasing any
/// reader blocked in open(2)) and the test FAILS instead of hanging the
/// suite. The deadline is generous on purpose — a healthy run finishes in
/// seconds, the regression under test never finishes — so a slow CI box
/// (first-launch dyld stall, parallel test load) cannot turn into a flake.
#[cfg(unix)]
pub(crate) fn scan_hosted_json_or_release_fifo(
    cwd: &Path,
    api_url: &str,
    extra: &[&str],
    env: &[(&str, &str)],
    fifo: &Path,
) -> (i32, Value) {
    let cwd = cwd.to_path_buf();
    let api_url = api_url.to_string();
    let extra: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
    let env: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let extra: Vec<&str> = extra.iter().map(String::as_str).collect();
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let _ = tx.send(scan_hosted_json(&cwd, &api_url, &extra, &env));
    });
    let deadline = std::time::Duration::from_secs(60);
    match rx.recv_timeout(deadline) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            use std::os::unix::fs::OpenOptionsExt as _;
            let released = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(fifo)
                .is_ok();
            panic!(
                "scan --mode hosted wedged on a FIFO bun.lockb for {deadline:?} (a reader \
                 was blocked in open(2): {released})"
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the scan thread panicked before reporting (see the output above)")
        }
    }
}

/// Stdout below the discovery report: human hosted `scan` prints the
/// results table and its `Summary:` block (plus any indented continuation
/// lines) before the engine's own output.
pub(crate) fn engine_stdout(stdout: &str) -> String {
    let mut lines = stdout.lines().peekable();
    let mut seen_summary = false;
    let mut out = Vec::new();
    while let Some(line) = lines.next() {
        if !seen_summary {
            if line.starts_with("Summary: ") {
                seen_summary = true;
                while lines.peek().is_some_and(|l| l.starts_with(' ')) {
                    lines.next();
                }
            }
            continue;
        }
        out.push(line);
    }
    if !seen_summary {
        return stdout.to_string();
    }
    let mut joined = out.join("\n");
    if !out.is_empty() {
        joined.push('\n');
    }
    joined
}

/// Yarn classic project: package.json (with `package_manager` when given) +
/// installed node_modules copy + a v1 yarn.lock resolving NAME upstream.
pub(crate) fn write_yarn_classic_project(root: &Path, package_manager: Option<&str>) {
    let pm = package_manager
        .map(|pm| format!(r#", "packageManager": "{pm}""#))
        .unwrap_or_default();
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0"{pm}, "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
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
        root.join("yarn.lock"),
        format!(
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
             # yarn lockfile v1\n\n\n\
             {NAME}@{VERSION}:\n  version \"{VERSION}\"\n  \
             resolved \"https://registry.yarnpkg.com/{NAME}/-/{NAME}-{VERSION}.tgz#bbbb\"\n  \
             integrity {UPSTREAM_SHA512}\n"
        ),
    )
    .unwrap();
}

/// A granted reference whose tarball the mock serves (a yarn classic pin
/// reads it, #558 / #591), with the grant's hashes matching it; returns its
/// URL.
pub(crate) async fn mock_served_classic_reference(server: &MockServer) -> String {
    use base64::Engine as _;
    use sha1::Digest as _;
    let manifest = format!(r#"{{"name":"{NAME}","version":"{VERSION}"}}"#);
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "package/package.json", manifest.as_bytes())
        .unwrap();
    let tgz = builder.into_inner().unwrap().finish().unwrap();
    let artifact = format!("/patch/npm/{NAME}/{VERSION}/22222222-2222-4222-8222-222222222222/{UUID}/{NAME}-{VERSION}.tgz");
    let url = format!("{}{artifact}", server.uri());
    mock_reference_results(
        server,
        json!({
            UUID: {
                "status": "granted",
                "url": url,
                "purl": PURL,
                "artifacts": [{
                    "kind": "tarball",
                    "url": url,
                    "integrity": {
                        "sha512": format!(
                            "sha512-{}",
                            base64::engine::general_purpose::STANDARD
                                .encode(sha2::Sha512::digest(&tgz))
                        ),
                        "sha1": hex::encode(sha1::Sha1::digest(&tgz)),
                    }
                }],
                "registryOverride": null
            }
        }),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(artifact))
        .respond_with(ResponseTemplate::new(200).set_body_raw(tgz, "application/octet-stream"))
        .mount(server)
        .await;
    url
}

/// The superseded package X of the `redirect_supersedes_vendored` tests.
pub(crate) const SUPER_X_PURL: &str = "pkg:npm/covgap-super-x@1.0.0";

/// A project whose lock routes X (`SUPER_X_PURL`) to its hosted artifact (a
/// lockfile hosted pin: v5 hosted state, recognized as such under
/// `--patch-server-url http://patch.test`) while the vendored ledger still
/// claims X, and whose Y (= `NAME`) is still upstream.
pub(crate) fn write_superseded_vendored_project(root: &Path) {
    const XNAME: &str = "covgap-super-x";
    const XPURL: &str = SUPER_X_PURL;
    const XUUID: &str = "66666666-6666-4666-8666-666666666666";
    let x_hosted = format!(
        "http://patch.test/patch/npm/{XNAME}/1.0.0/77777777-7777-4777-8777-777777777777/{XUUID}/{XNAME}-1.0.0.tgz"
    );
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
    // No redirect ledger (v5): X's hosted pin in the lock is the whole
    // hosted state. The mock host is recognized as a patch server only via
    // `--patch-server-url` below.
    // Vendored ledger ALSO claims X (stale — the lock routes X hosted).
    write_vendor_state(
        root,
        XPURL,
        "88888888-8888-4888-8888-888888888888",
        "package-lock",
    );
}
