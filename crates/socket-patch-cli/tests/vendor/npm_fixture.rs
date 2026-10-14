//! The offline npm fixture and runners `vendor_failure_paths.rs` and
//! `vendor_render.rs` share: a self-contained npm project with a staged
//! patch blob, driven either in-process (`vendor_run`) or through the built
//! binary with a scrubbed child environment (`run_cli` / `vendor_cli`). No
//! test mutates this process's environment.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::commands::vendor::{run as actual_vendor_run, VendorArgs};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::vendor::state::VendorArtifact;
use socket_patch_core::vendor::{save_state, VendorEntry, VendorState};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::hermetic;
use crate::prebuilt_common;

pub(crate) async fn vendor_run(mut args: VendorArgs) -> i32 {
    let server = prebuilt_common::Server::project(&args.common.cwd);
    server.configure(&mut args.common);
    actual_vendor_run(args).await
}

/// Canonical-grammar patch UUID (the vendor path layer validates it).
pub(crate) const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
pub(crate) const PURL: &str = "pkg:npm/left-pad@1.3.0";
pub(crate) const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
pub(crate) const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";
pub(crate) const REG_RESOLVED: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
pub(crate) const REG_INTEGRITY: &str = "sha512-orig==";

pub(crate) fn rel_tgz() -> String {
    format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
}

// ───────────────────────────── fixture ─────────────────────────────

pub(crate) struct NpmFixture {
    pub(crate) tmp: tempfile::TempDir,
    pub(crate) original_lock: Vec<u8>,
}

impl NpmFixture {
    pub(crate) fn root(&self) -> &Path {
        self.tmp.path()
    }
    pub(crate) fn lock_path(&self) -> PathBuf {
        self.root().join("package-lock.json")
    }
    pub(crate) fn lock_bytes(&self) -> Vec<u8> {
        std::fs::read(self.lock_path()).expect("read package-lock.json")
    }
    pub(crate) fn manifest_path(&self) -> PathBuf {
        self.root().join(".socket/manifest.json")
    }
    pub(crate) fn vendor_dir(&self) -> PathBuf {
        self.root().join(".socket/vendor")
    }
    pub(crate) fn tgz_path(&self) -> PathBuf {
        self.root().join(rel_tgz())
    }
    pub(crate) fn state_path(&self) -> PathBuf {
        self.root().join(".socket/vendor/state.json")
    }
    pub(crate) fn redirect_state_path(&self) -> PathBuf {
        self.root().join(".socket/vendor/redirect-state.json")
    }
}

/// One manifest patch record (camelCase, the TS-compatible manifest shape).
pub(crate) fn patch_record(before_hash: &str, after_hash: &str) -> Value {
    json!({
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": {
            "package/index.js": { "beforeHash": before_hash, "afterHash": after_hash }
        },
        "vulnerabilities": {},
        "description": "synthetic covgap vendor test patch",
        "license": "MIT",
        "tier": "free"
    })
}

pub(crate) fn npm_fixture_with_purls(manifest_purls: &[&str]) -> NpmFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();

    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": REG_RESOLVED,
                "integrity": REG_INTEGRITY,
                "license": "WTFPL"
            }
        }
    });
    let mut original_lock = serde_json::to_vec_pretty(&lock).unwrap();
    original_lock.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &original_lock).unwrap();

    let before_hash = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    let mut patches = serde_json::Map::new();
    for purl in manifest_purls {
        patches.insert(purl.to_string(), patch_record(&before_hash, &after_hash));
    }
    let manifest = json!({ "patches": patches });
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    manifest_bytes.push(b'\n');
    std::fs::write(socket.join("manifest.json"), &manifest_bytes).unwrap();
    std::fs::write(socket.join("blobs").join(&after_hash), PATCHED_INDEX).unwrap();

    NpmFixture { tmp, original_lock }
}

pub(crate) fn npm_fixture() -> NpmFixture {
    npm_fixture_with_purls(&[PURL])
}

/// In-process `VendorArgs` (json+silent+offline), for staging a vendored
/// state a subsequent subprocess run asserts against.
pub(crate) fn vendor_args(cwd: &Path) -> VendorArgs {
    VendorArgs {
        common: GlobalArgs {
            cwd: cwd.to_path_buf(),
            json: true,
            silent: true,
            offline: false,
            // See in_process_vendor.rs: absorbs the fork→exec fd window of
            // concurrent tests in this binary.
            lock_timeout: Some(5),
            ..GlobalArgs::default()
        },
        force: false,
        revert: false,
        check: false,
        local_repo: None,
        vex: Default::default(),
    }
}

// ───────────────────────── subprocess runner ─────────────────────────

/// Run the built `socket-patch` binary in the hermetic env (every ambient
/// `SOCKET_*` env var scrubbed from the child, telemetry hard-disabled).
pub(crate) fn run_cli(
    cwd: &Path,
    args: &[&str],
    extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut cmd = hermetic::binary_command();
    let fixture = (!args
        .iter()
        .any(|a| matches!(*a, "--api-url" | "--vendor-url"))
        && !extra_env
            .iter()
            .any(|(k, _)| matches!(*k, "SOCKET_API_URL" | "SOCKET_VENDOR_URL")))
    .then(|| prebuilt_common::Server::project(cwd));
    let mut filtered = Vec::new();
    let mut args_iter = args.iter().copied();
    while let Some(arg) = args_iter.next() {
        if fixture.is_some() && arg == "--patch-server-url" {
            args_iter.next();
        } else {
            filtered.push(arg);
        }
    }
    cmd.args(&filtered).current_dir(cwd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if let Some(fixture) = &fixture {
        fixture.command(&mut cmd);
    }
    let out = cmd.output().expect("spawn socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `vendor --json --offline --cwd <cwd> <extra...>` through the binary.
pub(crate) fn vendor_cli(cwd: &Path, extra: &[&str]) -> (i32, Value) {
    let mut args = vec!["vendor", "--json", "--cwd", cwd.to_str().unwrap()];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_cli(cwd, &args, &[]);
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("vendor --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, env)
}

/// A synthetic ledger with one entry of `eco` for [`PURL`], written via the
/// real `save_state` serializer (what a tampered-but-parseable state.json
/// deserializes into).
pub(crate) async fn write_ledger_entry(root: &Path, eco: &str) {
    let mut state = VendorState::default();
    state.entries.insert(
        PURL.to_string(),
        VendorEntry::new(
            eco.into(),
            PURL.into(),
            UUID.into(),
            VendorArtifact {
                yarn_berry10c0: None,
                path: format!(".socket/vendor/{eco}/{UUID}/left-pad-1.3.0.tgz"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            Vec::new(),
        ),
    );
    save_state(root, &state).await.unwrap();
}

/// The mock patch-server origin the hosted pins below live on. Only
/// `https://patch.socket.dev` and the `--patch-server-url` origin count as
/// hosted, so every run over these pins passes that flag.
pub(crate) const HOSTED_ORIGIN: &str = "https://patch.socket.dev";
pub(crate) const HOSTED_INTEGRITY: &str = "sha512-HOSTEDpatchedHOSTEDpatched==";
/// What the mock npm registry's version document hands back for the
/// upstream restore.
pub(crate) const UPSTREAM_INTEGRITY: &str = "sha512-UPSTREAMupstreamUPSTREAM==";

pub(crate) fn hosted_url() -> String {
    format!(
        "{HOSTED_ORIGIN}/patch/npm/left-pad/1.3.0/55555555-5555-4555-8555-555555555555/{UUID}/left-pad-1.3.0.tgz"
    )
}

/// Pin the fixture's left-pad entry to the hosted tarball (what `scan
/// --mode hosted` leaves in package-lock.json) and return the lock bytes.
pub(crate) fn pin_hosted(fx: &NpmFixture) -> Vec<u8> {
    let mut lock: Value = serde_json::from_slice(&fx.lock_bytes()).unwrap();
    lock["packages"]["node_modules/left-pad"]["resolved"] = Value::String(hosted_url());
    lock["packages"]["node_modules/left-pad"]["integrity"] =
        Value::String(HOSTED_INTEGRITY.to_string());
    let mut bytes = serde_json::to_vec_pretty(&lock).unwrap();
    bytes.push(b'\n');
    std::fs::write(fx.lock_path(), &bytes).unwrap();
    bytes
}

/// A wiremock npm registry answering left-pad@1.3.0's version document.
pub(crate) async fn mock_npm_registry() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/left-pad/1.3.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "left-pad",
            "version": "1.3.0",
            "dist": {
                "tarball": format!("{}/left-pad/-/left-pad-1.3.0.tgz", server.uri()),
                "integrity": UPSTREAM_INTEGRITY,
                "shasum": "0000000000000000000000000000000000000000"
            }
        })))
        .mount(&server)
        .await;
    server
}

/// `vendor --json --patch-server-url <mock origin>` through the binary,
/// ONLINE against the mock registry (the upstream restore needs it) but
/// anonymous, so no other network path opens.
pub(crate) fn vendor_online(fx: &NpmFixture, registry: &str, extra: &[&str]) -> (i32, Value) {
    let root = fx.root().to_str().unwrap();
    let mut args = vec![
        "vendor",
        "--json",
        "--patch-server-url",
        HOSTED_ORIGIN,
        "--cwd",
        root,
    ];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_cli(
        fx.root(),
        &args,
        &[
            ("SOCKET_NO_API_TOKEN", "1"),
            ("SOCKET_NPM_REGISTRY", registry),
        ],
    );
    let env: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}"));
    (code, env)
}

pub(crate) fn human_vendor(fx: &NpmFixture, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["vendor", "--cwd", fx.root().to_str().unwrap()];
    args.extend_from_slice(extra);
    run_cli(fx.root(), &args, &[])
}

/// `sha512-…` SRI of `bytes` (same helper shape as the sibling repair and
/// scan-vendor suites): a syntactically VALID integrity so the pristine
/// ladder proceeds past the no-integrity `Unverifiable` refusal and
/// actually attempts the fetch.
pub(crate) fn sri_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha512};
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}
