//! Hermetic vlt hosted-mode fixtures shared by the redirect, rollback,
//! symlink, get and covgap suites: a vlt project (`vlt-lock.json`, an
//! installed importer copy, optionally vlt's store and hidden lock), the
//! wiremock API (discovery, the grant, the patch view) plus the artifact
//! route the vlt preflight fetches, and a scrubbed subprocess runner that
//! reads the `--json` envelope back.
//!
//! Include with `#[path = "vlt_hosted_common/mod.rs"] mod vlt_hosted_common;`.

#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const ORG: &str = "test-org";
pub const NAME: &str = "left-pad";
pub const VERSION: &str = "1.3.0";
pub const PURL: &str = "pkg:npm/left-pad@1.3.0";
pub const UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub const TOKEN: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
pub const GHSA: &str = "GHSA-vlth-aaaa-bbbb";
pub const UPSTREAM_SHA512: &str = "sha512-UPSTREAMupstreamUPSTREAMupstream==";
pub const REGISTRY_URL: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
pub const PRISTINE: &[u8] = b"module.exports = 'pristine'\n";
pub const PATCHED: &[u8] = b"module.exports = 'patched'\n";
pub const PACKAGE_JSON: &[u8] = b"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}\n";
pub const TILDE_ID: &str = "~npm~left-pad@1.3.0";
pub const LEGACY_ID: &str = "·npm·left-pad@1.3.0";
pub const EMPTY_SEGMENT_ID: &str = "··left-pad@1.3.0";

pub const ADVISORY: &str = "redirect_vlt_reinstall_required";
pub const UNVERIFIABLE: &str = "redirect_vlt_artifact_unverifiable";

pub const ADVISORY_NOTHING_STALE: &str = "vlt-lock.json pins Socket-patched packages; fresh \
     checkouts install them with `vlt ci` or `vlt install --frozen-lockfile`. Note: `vlt update` \
     re-resolves from the registry and drops these redirects.";

pub fn advisory_invalidated(n: usize) -> String {
    format!(
        "vlt-lock.json pins Socket-patched packages; socket-patch removed {n} stale installed \
         copies (node_modules/.vlt-lock.json and node_modules/.vlt entries), so node_modules is \
         incomplete until you run `vlt install` (or `vlt ci`), which installs the patched \
         packages. Note: `vlt update` re-resolves from the registry and drops these redirects."
    )
}

pub fn advisory_cleanup_skipped(n: usize) -> String {
    format!(
        "vlt-lock.json pins Socket-patched packages, but node_modules still holds {n} unpatched \
         copies and `vlt install` will not refresh them; run `vlt ci` (or re-run without \
         --no-vlt-install-cleanup)."
    )
}

pub fn advisory_undeterminable(n: usize) -> String {
    format!(
        "vlt-lock.json pins Socket-patched packages, but socket-patch could not check {n} \
         installed copies (node_modules is a link, or no patch record or artifact was \
         available); run `vlt ci` to be sure the patched packages are installed."
    )
}

/// Why the heal keeps stale optional copies, shared by every heal's detail.
pub const OPTIONAL_KEPT: &str = "socket-patch does not remove them because `vlt install` does \
     not reinstall a removed optional dependency. Run `vlt ci` (or delete node_modules and run \
     `vlt install`). vlt releases before 1.0.5 install no optional dependency from the lock of a \
     project that declares only optional dependencies, so there both commands remove the \
     installed copy: upgrade vlt to 1.0.5 or later first.";

pub fn advisory_optional_kept(n: usize) -> String {
    format!(
        "vlt-lock.json pins Socket-patched packages, but node_modules still holds {n} unpatched \
         copies of optional dependencies; {OPTIONAL_KEPT}"
    )
}

/// The sentence a heal's detail gains for `n` kept optional copies
/// (`held` names them).
pub fn also_optional_kept(n: usize, held: &str) -> String {
    format!("node_modules also still holds {n} {held}; {OPTIONAL_KEPT}")
}

/// `line` (a [`node`]) with slot [0] set to `flags`.
pub fn with_flags(line: &str, flags: u8) -> String {
    line.replacen("[0,", &format!("[{flags},"), 1)
}

pub fn git_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn sha512_sri(bytes: &[u8]) -> String {
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

/// The patched npm tarball the hosted artifact route serves.
pub fn patched_tarball() -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    for (name, data) in [
        ("package/package.json", PACKAGE_JSON),
        ("package/index.js", PATCHED),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(bytes).unwrap();
    enc.finish().unwrap()
}

pub fn artifact_path() -> String {
    format!("/patch/npm/{NAME}/{VERSION}/{TOKEN}/{UUID}/{NAME}-{VERSION}.tgz")
}

pub fn artifact_url(server: &MockServer) -> String {
    format!("{}{}", server.uri(), artifact_path())
}

pub async fn mock_discovery(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "vlt hosted fixture"
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
}

/// The grant for [`UUID`], pointing at `url` with `sha512`.
pub async fn mock_reference_at(server: &MockServer, url: &str, sha512: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": url,
                    "purl": PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": url,
                        "integrity": { "sha512": sha512 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
}

/// The grant for the served [`patched_tarball`].
pub async fn mock_reference(server: &MockServer) {
    mock_reference_at(
        server,
        &artifact_url(server),
        &sha512_sri(&patched_tarball()),
    )
    .await;
}

pub fn view_body() -> Value {
    json!({
        "uuid": UUID,
        "purl": PURL,
        "publishedAt": "2024-01-01T00:00:00Z",
        "files": {
            "package/index.js": {
                "beforeHash": git_sha256(PRISTINE),
                "afterHash": git_sha256(PATCHED),
            }
        },
        "vulnerabilities": {
            GHSA: {
                "cves": ["CVE-2026-4242"],
                "summary": "vlt hosted fixture",
                "severity": "high",
                "description": "d"
            }
        },
        "description": "x", "license": "MIT", "tier": "free"
    })
}

pub async fn mock_view(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view_body()))
        .mount(server)
        .await;
}

/// The artifact route with an arbitrary response.
pub async fn mock_artifact_with(server: &MockServer, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(artifact_path()))
        .respond_with(response)
        .mount(server)
        .await;
}

pub async fn mock_artifact(server: &MockServer) {
    mock_artifact_with(
        server,
        ResponseTemplate::new(200).set_body_bytes(patched_tarball()),
    )
    .await;
}

/// Discovery, grant, view and a passing artifact.
pub async fn mock_all(server: &MockServer) {
    mock_discovery(server).await;
    mock_reference(server).await;
    mock_view(server).await;
    mock_artifact(server).await;
}

/// How many requests reached the artifact route.
pub async fn artifact_requests(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == artifact_path())
        .count()
}

/// Which `vlt-lock.json` era to write.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Era {
    /// `lockfileVersion: 1`, tilde ids.
    V1,
    /// `lockfileVersion: 0`, `·npm·` ids.
    V0,
    /// No `lockfileVersion`, `··` ids.
    A0,
}

impl Era {
    pub fn dep_id(self) -> &'static str {
        match self {
            Era::V1 => TILDE_ID,
            Era::V0 => LEGACY_ID,
            Era::A0 => EMPTY_SEGMENT_ID,
        }
    }
}

/// A canonical vlt lock with the given node entries (`"<id>": <tuple>`).
pub fn vlt_lock(era: Era, nodes: &[String]) -> String {
    let version = match era {
        Era::V1 => "  \"lockfileVersion\": 1,\n",
        Era::V0 => "  \"lockfileVersion\": 0,\n",
        Era::A0 => "",
    };
    let body = nodes
        .iter()
        .map(|n| format!("    {n}"))
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        "{{\n{version}  \"options\": {{}},\n  \"nodes\": {{\n{body}\n  }},\n  \"edges\": {{}}\n}}\n"
    )
}

/// `"<id>": [0,"left-pad","<sha512>","<url>"]`.
pub fn node(id: &str, sha512: &str, url: &str) -> String {
    format!("\"{id}\": [0,\"{NAME}\",\"{sha512}\",\"{url}\"]")
}

pub fn registry_node(id: &str) -> String {
    node(id, UPSTREAM_SHA512, REGISTRY_URL)
}

/// The same line after a hosted splice.
pub fn pinned_node(id: &str, server: &MockServer) -> String {
    node(id, &sha512_sri(&patched_tarball()), &artifact_url(server))
}

pub fn write_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
}

/// The importer copy the crawler discovers, `node_modules/left-pad`.
pub fn install_importer(root: &Path, index: &[u8]) {
    let dir = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("package.json"), PACKAGE_JSON).unwrap();
    std::fs::write(dir.join("index.js"), index).unwrap();
}

/// vlt's store entry `node_modules/.vlt/<id>/node_modules/left-pad`.
pub fn store_dir(root: &Path, id: &str) -> PathBuf {
    root.join("node_modules/.vlt")
        .join(id)
        .join("node_modules")
        .join(NAME)
}

pub fn install_store(root: &Path, id: &str, index: &[u8]) {
    let dir = store_dir(root, id);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("package.json"), PACKAGE_JSON).unwrap();
    std::fs::write(dir.join("index.js"), index).unwrap();
}

/// `node_modules/.vlt-lock.json` holding `nodes` verbatim.
pub fn write_hidden_lock(root: &Path, nodes: &[String]) {
    std::fs::create_dir_all(root.join("node_modules")).unwrap();
    std::fs::write(
        root.join("node_modules/.vlt-lock.json"),
        vlt_lock(Era::V1, nodes),
    )
    .unwrap();
}

/// A vlt project: package.json, `vlt-lock.json` with one registry node,
/// and the importer copy (no store).
pub fn write_vlt_project(root: &Path, era: Era) {
    write_package_json(root);
    std::fs::write(
        root.join("vlt-lock.json"),
        vlt_lock(era, &[registry_node(era.dep_id())]),
    )
    .unwrap();
    install_importer(root, PRISTINE);
}

/// [`write_vlt_project`] (v1) plus a warm install: the store entry with
/// `index` and a hidden lock recording the registry integrity.
pub fn write_installed_vlt_project(root: &Path, index: &[u8]) {
    write_vlt_project(root, Era::V1);
    install_store(root, TILDE_ID, index);
    write_hidden_lock(root, &[registry_node(TILDE_ID)]);
}

pub fn package_lock() -> String {
    format!(
        r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }},
    "node_modules/{NAME}": {{
      "version": "{VERSION}",
      "resolved": "{REGISTRY_URL}",
      "integrity": "{UPSTREAM_SHA512}"
    }}
  }}
}}
"#
    )
}

pub fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

pub fn ledger_path(root: &Path) -> PathBuf {
    root.join(".socket/vendor/redirect-state.json")
}

/// The `socket-patch` binary with the ambient `SOCKET_*` and proxy
/// environment scrubbed (telemetry opt-outs kept).
pub fn scrubbed_cli() -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.env("SOCKET_DRY_RUN", "true")
        .env("SOCKET_OFFLINE", "true")
        .env("SOCKET_NO_VLT_INSTALL_CLEANUP", "true")
        .env_remove("SOCKET_DRY_RUN")
        .env_remove("SOCKET_OFFLINE")
        .env_remove("SOCKET_NO_VLT_INSTALL_CLEANUP");
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        let proxy = name.eq_ignore_ascii_case("http_proxy")
            || name.eq_ignore_ascii_case("https_proxy")
            || name.eq_ignore_ascii_case("all_proxy")
            || name.eq_ignore_ascii_case("no_proxy");
        if proxy
            || (name.starts_with("SOCKET_")
                && !name.contains("TELEMETRY")
                && name != "SOCKET_NO_CONFIG")
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_UPDATE_CHECK", "1");
    cmd
}

/// Run `<args> --json` in `cwd` with `env`; `(exit code, envelope, stderr)`.
pub fn run_json(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, Value, String) {
    let mut cmd = scrubbed_cli();
    cmd.args(args).arg("--json").current_dir(cwd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let doc = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be the JSON envelope ({e});\nstdout=\n{stdout}\nstderr=\n{stderr}")
    });
    (out.status.code().unwrap_or(-1), doc, stderr)
}

/// `scan --mode hosted --json --yes` against `server`, plus `extra`.
pub fn scan_hosted(
    cwd: &Path,
    server: &MockServer,
    extra: &[&str],
    env: &[(&str, &str)],
) -> (i32, Value) {
    let cwd_s = cwd.to_str().unwrap().to_string();
    let uri = server.uri();
    let mut args = vec![
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--cwd",
        &cwd_s,
        "--api-url",
        &uri,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    args.extend_from_slice(extra);
    let (code, doc, stderr) = run_json(cwd, &args, env);
    assert!(
        code == 0 || extra.contains(&"--vex"),
        "scan --mode hosted must exit 0: {doc:#}\nstderr=\n{stderr}"
    );
    (code, doc)
}

pub fn warning_codes(doc: &Value) -> Vec<String> {
    doc["redirect"]["warnings"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|w| w["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub fn warning_detail(doc: &Value, code: &str) -> String {
    doc["redirect"]["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|w| w["code"] == code)
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_else(|| panic!("expected a `{code}` warning: {doc:#}"))
        .to_string()
}

pub fn redirected(doc: &Value) -> u64 {
    doc["redirect"]["redirected"]
        .as_u64()
        .unwrap_or_else(|| panic!("{doc:#}"))
}

/// Whether the VEX document at `path` attests [`PURL`].
pub fn vex_attests(path: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(path) else {
        return false;
    };
    let doc: Value = serde_json::from_str(&text).unwrap();
    doc["statements"].as_array().into_iter().flatten().any(|s| {
        s["products"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|p| p["subcomponents"].as_array().into_iter().flatten())
            .any(|c| c["@id"] == PURL)
    })
}
