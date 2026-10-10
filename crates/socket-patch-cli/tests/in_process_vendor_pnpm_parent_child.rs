//! A vendored pnpm package whose own dependency is vendored too (#830):
//! `debug@4.3.4 → ms@2.1.2`, both patched. Vendoring `ms` after `debug`
//! rewrites the `ms` ref INSIDE debug's rekeyed snapshot, so unwinding
//! `debug` alone used to splice its pre-vendor block back over that ref:
//!
//! - `remove pkg:npm/debug@4.3.4` exited 0 with a lock pnpm rejects
//!   (`ERR_PNPM_LOCKFILE_MISSING_DEPENDENCY`: debug → `ms@2.1.2`, which no
//!   longer exists while `ms` stays vendored);
//! - `rollback` exited 1 forever (ms's ref record, keyed by debug's gone
//!   `file:` key, never matched again) with the artifact and ledger entry
//!   stranded;
//! - the vendored → hosted takeover skipped `ms` as
//!   `vendored_revert_failed` after its wiring was already gone, so the
//!   run succeeded with `ms` unpatched.
//!
//! The API is wiremock; no pnpm binary is needed. Every child process gets
//! the ambient `SOCKET_*` vars scrubbed; each test runs in its own tempdir.

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::collections::HashSet;
use std::path::Path;

use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const DEBUG: &str = "pkg:npm/debug@4.3.4";
const MS: &str = "pkg:npm/ms@2.1.2";
const DEBUG_UUID: &str = "55555555-5555-4555-8555-555555555555";
const MS_UUID: &str = "66666666-6666-4666-8666-666666666666";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

const PKG: &str = r#"{
  "name": "c",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "debug": "4.3.4"
  }
}
"#;

const LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      debug:
        specifier: 4.3.4
        version: 4.3.4

packages:

  debug@4.3.4:
    resolution: {integrity: sha512-3NN8vD3qzN8YtsF8Mxz4wHinpTcRP71BdOdGhzQk7dVDwXhUjS7O9BXaHGhn7m7Y1hB+L4szF+XwoAhBc2upBw==}
    engines: {node: '>=6.0'}
    peerDependencies:
      supports-color: '*'
    peerDependenciesMeta:
      supports-color:
        optional: true

  ms@2.1.2:
    resolution: {integrity: sha512-sGkPx+VjMtmA6MX27oA4FBFELFCZZ4S4XqeGOXCv68tT+jb3vk/RyaKWP0PTKyWtmLSM0b+adUTEvbs1PEaH2w==}

snapshots:

  debug@4.3.4:
    dependencies:
      ms: 2.1.2

  ms@2.1.2: {}
";

fn parts(purl: &str) -> (&'static str, &'static str, &'static str) {
    match purl {
        DEBUG => ("debug", "4.3.4", DEBUG_UUID),
        MS => ("ms", "2.1.2", MS_UUID),
        other => panic!("unknown purl {other}"),
    }
}

fn hosted_url(purl: &str) -> String {
    let (name, version, uuid) = parts(purl);
    format!(
        "https://patch.socket.dev/patch/npm/{name}/{version}/44444444-4444-4444-8444-444444444444/{uuid}/{name}-{version}.tgz"
    )
}

fn patch_record(purl: &str) -> Value {
    json!({
        "uuid": parts(purl).2,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": {
            "package/index.js": {
                "beforeHash": compute_git_sha256_from_bytes(ORIG_INDEX),
                "afterHash": compute_git_sha256_from_bytes(PATCHED_INDEX),
            }
        },
        "vulnerabilities": {},
        "description": "pnpm parent/child fixture",
        "license": "MIT",
        "tier": "free"
    })
}

/// The project (installed copies, lock, manifest + blob) with nothing
/// vendored yet.
fn write_project(root: &Path) {
    std::fs::write(root.join("package.json"), PKG).unwrap();
    std::fs::write(root.join("pnpm-lock.yaml"), LOCK).unwrap();
    for purl in [DEBUG, MS] {
        let (name, version, _) = parts(purl);
        let dir = root.join("node_modules").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
        std::fs::write(dir.join("index.js"), ORIG_INDEX).unwrap();
    }
    let manifest = json!({ "patches": { DEBUG: patch_record(DEBUG), MS: patch_record(MS) } });
    std::fs::create_dir_all(root.join(".socket/blobs")).unwrap();
    std::fs::write(
        root.join(".socket/manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join(".socket/blobs")
            .join(compute_git_sha256_from_bytes(PATCHED_INDEX)),
        PATCHED_INDEX,
    )
    .unwrap();
}

/// Run the built binary hermetically. Returns `(exit_code, envelope)`.
fn run_json(cwd: &Path, args: &[&str]) -> (i32, Value) {
    let mut cmd = hermetic::binary_command();
    cmd.current_dir(cwd).env("SOCKET_TELEMETRY_DISABLED", "1");
    let _fixture = prebuilt_common::prepare_command(&mut cmd, cwd, args, &[]);
    let out = cmd.output().expect("spawn socket-patch binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let env: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("{args:?} must emit a JSON envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (out.status.code().unwrap_or(-1), env)
}

/// A vendored project: `vendor` processes the purl-sorted manifest, so the
/// parent (`debug`) is vendored before its dependency (`ms`).
fn vendored_project(root: &Path) {
    write_project(root);
    let (code, env) = run_json(root, &["vendor", "--json", "--cwd", root.to_str().unwrap()]);
    assert_eq!(code, 0, "vendor: {env:#}");
    let lock = read_lock(root);
    for purl in [DEBUG, MS] {
        let (name, version, uuid) = parts(purl);
        assert!(
            lock.contains(&format!(
                "  {name}@file:.socket/vendor/npm/{uuid}/{name}-{version}.tgz:"
            )),
            "{purl} vendored:\n{lock}"
        );
    }
}

fn read_lock(root: &Path) -> String {
    std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap()
}

fn vendored_uuids(root: &Path) -> Vec<String> {
    std::fs::read_dir(root.join(".socket/vendor/npm"))
        .map(|dir| {
            let mut uuids: Vec<String> = dir
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            uuids.sort();
            uuids
        })
        .unwrap_or_default()
}

/// Every snapshot dependency ref names an existing snapshots key: what a
/// frozen pnpm install checks (`ERR_PNPM_LOCKFILE_MISSING_DEPENDENCY`).
fn assert_snapshot_refs_resolve(lock: &str) {
    let snapshots = lock
        .split("\nsnapshots:\n")
        .nth(1)
        .expect("snapshots section");
    let mut keys = HashSet::new();
    let mut refs = Vec::new();
    for line in snapshots.lines() {
        if let Some(key) = line.strip_prefix("  ").filter(|l| !l.starts_with(' ')) {
            let key = key.strip_suffix(": {}").or_else(|| key.strip_suffix(':'));
            keys.insert(key.unwrap().to_string());
        } else if let Some(dep) = line.strip_prefix("      ") {
            let (name, value) = dep.split_once(": ").unwrap();
            refs.push(format!("{name}@{value}"));
        }
    }
    for r in refs {
        assert!(keys.contains(&r), "dangling snapshot ref `{r}`:\n{lock}");
    }
}

/// No recorded lock entry was reported missing or drifted, and no artifact
/// kept: every record found its live fragment.
fn assert_clean_unwind(env: &Value) {
    let text = env.to_string();
    for code in [
        "vendor_lock_entry_removed",
        "vendor_lock_entry_drifted",
        "vendor_artifact_kept",
    ] {
        assert!(!text.contains(code), "{code}: {env:#}");
    }
}

/// #830: `remove <parent>` keeps the vendored child wired and the lock
/// resolvable; `remove <child>` afterwards lands on the pre-vendor lock.
#[test]
fn remove_parent_keeps_the_vendored_child_wired() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendored_project(root);
    let cwd = root.to_str().unwrap();

    let (code, env) = run_json(
        root,
        &[
            "remove",
            DEBUG,
            "--json",
            "--offline",
            "--yes",
            "--cwd",
            cwd,
        ],
    );
    assert_eq!(code, 0, "remove debug: {env:#}");
    assert_clean_unwind(&env);
    let lock = read_lock(root);
    assert_snapshot_refs_resolve(&lock);
    let ms_spec = format!("file:.socket/vendor/npm/{MS_UUID}/ms-2.1.2.tgz");
    assert!(
        lock.contains(&format!(
            "  debug@4.3.4:\n    dependencies:\n      ms: {ms_spec}\n"
        )),
        "debug's restored snapshot keeps the vendored ms ref:\n{lock}"
    );
    assert_eq!(vendored_uuids(root), [MS_UUID]);

    let (code, env) = run_json(
        root,
        &["remove", MS, "--json", "--offline", "--yes", "--cwd", cwd],
    );
    assert_eq!(code, 0, "remove ms: {env:#}");
    assert_eq!(read_lock(root), LOCK, "lock byte-restored");
    assert!(vendored_uuids(root).is_empty());
}

/// #830: `rollback` unwinds both in one run, exits 0 and strands nothing;
/// a second run is a clean no-op.
#[test]
fn rollback_unwinds_parent_and_child_in_one_run() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendored_project(root);
    let cwd = root.to_str().unwrap();
    for run in 0..2 {
        let (code, env) = run_json(
            root,
            &["rollback", "--json", "--yes", "--offline", "--cwd", cwd],
        );
        assert_eq!(code, 0, "rollback #{run}: {env:#}");
        assert_clean_unwind(&env);
        assert_eq!(read_lock(root), LOCK, "rollback #{run}: lock byte-restored");
        assert_eq!(
            std::fs::read_to_string(root.join("package.json")).unwrap(),
            PKG
        );
        assert!(vendored_uuids(root).is_empty(), "rollback #{run}");
        let state =
            std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap_or_default();
        assert!(!state.contains("pkg:npm/"), "no ledger entry left: {state}");
    }
}

/// #830: `vendor --revert` likewise leaves no residue.
#[test]
fn vendor_revert_unwinds_parent_and_child() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendored_project(root);
    let (code, env) = run_json(
        root,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            root.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{env:#}");
    assert_clean_unwind(&env);
    assert_eq!(read_lock(root), LOCK, "lock byte-restored");
    assert!(vendored_uuids(root).is_empty());
}

/// The hosted API for both patches.
async fn mock_api(server: &MockServer) {
    let offer = |purl: &str| {
        json!({
            "uuid": parts(purl).2, "purl": purl, "tier": "free",
            "cveIds": [], "ghsaIds": [], "severity": "high", "title": "fixture"
        })
    };
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [
                { "purl": DEBUG, "patches": [offer(DEBUG)] },
                { "purl": MS, "patches": [offer(MS)] },
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    for purl in [DEBUG, MS] {
        let (name, _, uuid) = parts(purl);
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*{name}.*$"
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
        let mut view = patch_record(purl);
        view["purl"] = json!(purl);
        view["publishedAt"] = json!("2024-01-01T00:00:00Z");
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(view))
            .mount(server)
            .await;
    }
    let grant = |purl: &str| {
        json!({
            "status": "granted",
            "url": hosted_url(purl),
            "purl": purl,
            "artifacts": [{
                "kind": "tarball",
                "url": hosted_url(purl),
                "integrity": { "sha512": "sha512-PATCHEDpatchedPATCHEDpatched0123456789==" }
            }],
            "registryOverride": null
        })
    };
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": { DEBUG_UUID: grant(DEBUG), MS_UUID: grant(MS) }
        })))
        .mount(server)
        .await;
}

/// #830: the vendored → hosted takeover reverts and pins BOTH packages; it
/// never skips the child as `vendored_revert_failed` after its wiring is
/// gone, and the `--dry-run` preview predicts no refusal either. (A guard:
/// since #689 a missing ref record is no longer drift, so this variant
/// already converged; the lock-entry warnings it still raised are what the
/// core fix removes.)
#[tokio::test(flavor = "multi_thread")]
async fn hosted_takeover_migrates_parent_and_child() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendored_project(root);
    let scan = |extra: &[&str]| {
        let mut args = vec![
            "scan",
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--api-url",
            &server.uri(),
            "--api-token",
            "fake",
            "--org",
            ORG,
            "--cwd",
            root.to_str().unwrap(),
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        args.extend(extra.iter().map(|s| s.to_string()));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        run_json(root, &args)
    };

    let vendored_lock = read_lock(root);
    let (code, env) = scan(&["--dry-run"]);
    assert_eq!(code, 0, "{env:#}");
    assert!(
        !env.to_string().contains("vendored_revert_failed"),
        "{env:#}"
    );
    assert_eq!(read_lock(root), vendored_lock, "the dry run writes nothing");

    let (code, env) = scan(&[]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(env["status"], "success", "{env:#}");
    let text = env.to_string();
    for code in ["vendored_revert_failed", "redirect_takeover_unpatched"] {
        assert!(!text.contains(code), "{code}: {env:#}");
    }
    assert_clean_unwind(&env);
    assert_eq!(hosted_pin_count(&env), 2, "{env:#}");
    let lock = read_lock(root);
    assert!(
        !lock.contains(".socket/vendor/"),
        "nothing stays vendored:\n{lock}"
    );
    for purl in [DEBUG, MS] {
        assert!(lock.contains(&hosted_url(purl)), "{purl} pinned:\n{lock}");
    }
    assert!(vendored_uuids(root).is_empty());
}

/// How many hosted pins the run wrote (`applied`) or, on a dry run, would
/// write (`verified`): the `details.mode: "hosted"` events (v5.0's
/// `redirect.redirected`).
fn hosted_pin_count(envelope: &serde_json::Value) -> usize {
    envelope["events"]
        .as_array()
        .expect("events array")
        .iter()
        .filter(|e| {
            e["details"]["mode"] == "hosted"
                && (e["action"] == "applied" || e["action"] == "verified")
        })
        .count()
}
