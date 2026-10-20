//! Shared fixtures for the `remove` suite's failure-path and render
//! files: the binary runner, hand-written camelCase manifests and vendor
//! ledgers, the hosted-redirect lockfile pair with its mock npm registry,
//! and the mixed drift-keep fixture.

use std::path::{Path, PathBuf};

use crate::common;

/// Spawn `socket-patch remove` with the scrubbed env plus telemetry
/// disabled; `env` entries land last so per-test injections survive.
pub(crate) fn run_remove(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut full = vec!["remove"];
    full.extend_from_slice(args);
    let mut env_full = vec![("SOCKET_TELEMETRY_DISABLED", "1")];
    env_full.extend_from_slice(env);
    common::run_with_env(cwd, &full, &env_full)
}

pub(crate) fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// One hand-written camelCase manifest with a single `files: {}` patch —
/// the internal rollback needs no before-blobs, keeping wet runs offline.
pub(crate) fn write_manifest_files_empty(root: &Path, purl: &str, uuid: &str) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let manifest = format!(
        r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "{uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "covgap remove test patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
    socket
}

/// Two-entry `files: {}` manifest (purl1/uuid1, purl2/uuid2).
pub(crate) fn write_two_entry_manifest(
    root: &Path,
    purl1: &str,
    uuid1: &str,
    purl2: &str,
    uuid2: &str,
) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let manifest = format!(
        r#"{{
  "patches": {{
    "{purl1}": {{
      "uuid": "{uuid1}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "covgap remove test patch 1",
      "license": "MIT",
      "tier": "free"
    }},
    "{purl2}": {{
      "uuid": "{uuid2}",
      "exportedAt": "2024-01-02T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "covgap remove test patch 2",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
    socket
}

/// Vendor ledger with one npm entry keyed `key` (extra: raw JSON fields
/// appended to the entry — e.g. `"flavor": "...",` or `"detached": true,`),
/// plus the artifact dir it names. Fixture shape copied from
/// remove_invariants.rs::write_vendored_ledger.
pub(crate) fn write_vendor_ledger_entry(
    root: &Path,
    key: &str,
    base_purl: &str,
    uuid: &str,
    wiring: &str,
    extra: &str,
) -> PathBuf {
    let vendor = root.join(".socket/vendor");
    let artifact_dir = vendor.join("npm").join(uuid);
    std::fs::create_dir_all(&artifact_dir).expect("create artifact dir");
    std::fs::write(artifact_dir.join("package.tgz"), b"tgz").expect("write artifact");
    let state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{key}": {{
      "ecosystem": "npm",
      "basePurl": "{base_purl}",
      "uuid": "{uuid}",
      {extra}"artifact": {{ "path": ".socket/vendor/npm/{uuid}/package.tgz" }},
      "wiring": {wiring}
    }}
  }}
}}"#
    );
    std::fs::write(vendor.join("state.json"), state).expect("write vendor state");
    artifact_dir
}

/// A wiring record naming a file the npm revert backend does not edit: the
/// revert drift-keeps (`kept_artifact`) — fixture copied from
/// remove_duality_invariants.rs.
pub(crate) const DRIFTED_WIRING: &str = r#"[{ "file": "weird.txt", "kind": "npm_lock_entry", "action": "added", "key": "node_modules/x" }]"#;

pub(crate) const NPM_PURL: &str = "pkg:npm/left-pad@1.3.0";

pub(crate) const NPM_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

pub(crate) const ORIG_RESOLVED: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";

pub(crate) const ORIG_INTEGRITY: &str = "sha512-UPSTREAM==";

pub(crate) const HOSTED_RESOLVED: &str = "https://patch.socket.dev/patch/npm/left-pad/1.3.0/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz";

pub(crate) const HOSTED_INTEGRITY: &str = "sha512-PATCHED==";

/// A lockfileVersion-3 package-lock.json whose left-pad entry currently
/// holds the HOSTED (redirected) resolved/integrity pair.
pub(crate) fn redirected_lock_text() -> String {
    format!(
        r#"{{
  "name": "hosted-fixture",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "packages": {{
    "": {{ "name": "hosted-fixture", "version": "0.0.0" }},
    "node_modules/left-pad": {{
      "name": "left-pad",
      "version": "1.3.0",
      "resolved": "{HOSTED_RESOLVED}",
      "integrity": "{HOSTED_INTEGRITY}"
    }}
  }}
}}
"#
    )
}

/// A PRE-V5 redirect ledger (v5 never writes one) with ONE npm record and
/// its recorded `redirect_npm_lock_entry` edit matching
/// [`redirected_lock_text`].
pub(crate) fn npm_redirect_ledger_text() -> String {
    format!(
        r#"{{
  "version": 1,
  "mode": "hosted",
  "edits": [
    {{
      "path": "package-lock.json",
      "kind": "redirect_npm_lock_entry",
      "action": "rewritten",
      "key": "node_modules/left-pad",
      "original": {{ "resolved": "{ORIG_RESOLVED}", "integrity": "{ORIG_INTEGRITY}" }},
      "new": {{ "resolved": "{HOSTED_RESOLVED}", "integrity": "{HOSTED_INTEGRITY}" }}
    }}
  ],
  "records": {{
    "{NPM_PURL}": {{
      "uuid": "{NPM_UUID}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "covgap hosted npm patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    )
}

pub(crate) fn write_redirect_ledger_text(root: &Path, text: &str) -> PathBuf {
    let vendor = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor).expect("create .socket/vendor");
    let path = vendor.join("redirect-state.json");
    std::fs::write(&path, text).expect("write redirect ledger");
    path
}

/// The exact bytes the upstream restore writes when it puts
/// [`redirected_lock_text`] back on the registry entry the mock registry
/// serves (`ORIG_RESOLVED` / `ORIG_INTEGRITY`; same whole-file derivation
/// the remove_duality_invariants.rs twins use).
pub(crate) fn expected_reverted_lock_text() -> String {
    let mut expected: serde_json::Value =
        serde_json::from_str(&redirected_lock_text()).expect("parse fixture lock");
    let entry = expected["packages"]["node_modules/left-pad"]
        .as_object_mut()
        .expect("lock entry object");
    entry.insert("resolved".into(), serde_json::json!(ORIG_RESOLVED));
    entry.insert("integrity".into(), serde_json::json!(ORIG_INTEGRITY));
    format!("{}\n", serde_json::to_string_pretty(&expected).unwrap())
}

#[cfg(unix)]
pub(crate) fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
}

/// Restore the dir's mode even on assertion panic (or a panic inside the
/// binary runner), so the tempdir can clean up.
#[cfg(unix)]
pub(crate) struct ModeGuard(pub(crate) PathBuf);

#[cfg(unix)]
impl Drop for ModeGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

/// Probe whether permission bits are enforced for this process; root (or
/// CAP_DAC_OVERRIDE containers) bypasses them, making read-only-dir tests
/// fail spuriously. Returns false (and logs a skip) when they are not.
#[cfg(unix)]
pub(crate) fn readonly_dir_enforced(dir: &Path) -> bool {
    let probe = dir.join(".covgap-write-probe");
    if std::fs::write(&probe, b"x").is_ok() {
        let _ = std::fs::remove_file(&probe);
        eprintln!("skipping: permission bits not enforced (running as root?)");
        return false;
    }
    true
}

/// A mock npm registry serving left-pad@1.3.0's version document with the
/// fixture's upstream tarball + integrity (or nothing: every lookup 404s).
/// wiremock serves from its own thread; the runtime only owns the server.
pub(crate) struct NpmRegistry {
    server: wiremock::MockServer,
    _rt: tokio::runtime::Runtime,
}

impl NpmRegistry {
    pub(crate) fn start(serve_left_pad: bool) -> Self {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let server = rt.block_on(async {
            let server = MockServer::start().await;
            if serve_left_pad {
                Mock::given(method("GET"))
                    .and(path("/npm/left-pad/1.3.0"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                        "name": "left-pad",
                        "version": "1.3.0",
                        "dist": { "tarball": ORIG_RESOLVED, "integrity": ORIG_INTEGRITY }
                    })))
                    .mount(&server)
                    .await;
            }
            server
        });
        Self { server, _rt: rt }
    }

    pub(crate) fn base(&self) -> String {
        format!("{}/npm", self.server.uri())
    }
}

/// `run_remove` with the npm registry pointed at `registry`.
pub(crate) fn run_remove_online(
    cwd: &Path,
    args: &[&str],
    registry: &NpmRegistry,
) -> (i32, String, String) {
    let base = registry.base();
    run_remove(cwd, args, &[("SOCKET_NPM_REGISTRY", base.as_str())])
}

pub(crate) fn legacy_ledger_path(root: &Path) -> PathBuf {
    root.join(".socket/vendor/redirect-state.json")
}

pub(crate) const MIXED_UUID: &str = "88888888-8888-4888-8888-888888888888";

pub(crate) const MIXED_KEPT_PURL: &str = "pkg:npm/__covgap_dk_kept__@1.0.0";

pub(crate) const MIXED_REMOVED_PURL: &str = "pkg:npm/__covgap_dk_removed__@2.0.0";

/// Two manifest entries sharing one patch uuid — the only identifier shape
/// that matches BOTH while the drift-keep exclusion set covers only one —
/// plus a drift-keeping vendored ledger entry for the first.
pub(crate) fn make_mixed_drift_fixture(root: &Path) -> PathBuf {
    let socket = write_two_entry_manifest(
        root,
        MIXED_KEPT_PURL,
        MIXED_UUID,
        MIXED_REMOVED_PURL,
        MIXED_UUID,
    );
    write_vendor_ledger_entry(
        root,
        MIXED_KEPT_PURL,
        MIXED_KEPT_PURL,
        MIXED_UUID,
        DRIFTED_WIRING,
        "",
    );
    socket
}
