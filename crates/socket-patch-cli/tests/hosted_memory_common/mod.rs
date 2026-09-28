//! Shared harness for the in-memory hosted engine tests: a wiremock patch
//! API that serves every patch a fixture's `overrides.json` describes, the
//! engine run over that API, and a disk `scan --mode hosted --json` run of
//! the same files through the real binary under a scrubbed environment.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use socket_patch_cli::hosted_memory::{
    run_in_memory, HostedScanOptions, HostedScanOutput, MarkKind, PresentKind, SessionBuilder,
};
use socket_patch_core::api::client::{ApiClient, ApiClientOptions, PatchApi};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

pub const ORG: &str = "test-org";

pub fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../socket-patch-core/tests/fixtures")
}

/// One patch the fake API serves.
#[derive(Debug, Clone)]
pub struct Patch {
    pub purl: String,
    pub uuid: String,
    pub reference: Value,
}

fn percent_decode(s: &str) -> String {
    socket_patch_core::utils::purl::percent_decode_purl_component(s).into_owned()
}

fn purl_key(purl: &str) -> String {
    let decoded = socket_patch_core::utils::purl::normalize_purl(
        socket_patch_core::utils::purl::strip_purl_qualifiers(purl),
    )
    .into_owned();
    if decoded.starts_with("pkg:pypi/") {
        decoded.to_ascii_lowercase().replace(['_', '.'], "-")
    } else {
        decoded
    }
}

/// Patches from a golden fixture's `overrides.json` (one `DepOverride`
/// each). `rewrite_host` replaces `https://patch.socket.dev` in the served
/// URLs (so a wheel-metadata download hits the mock, never the network).
pub fn patches_from_overrides(overrides: &Path, rewrite_host: Option<&str>) -> Vec<Patch> {
    let text = std::fs::read_to_string(overrides).expect("read overrides.json");
    let list: Vec<Value> = serde_json::from_str(&text).expect("overrides.json is a list");
    list.into_iter()
        .map(|o| {
            let eco = o["ecosystem"].as_str().unwrap().to_string();
            let name = o["name"].as_str().unwrap().to_string();
            let full = match o["namespace"].as_str() {
                Some(ns) if !ns.is_empty() => format!("{ns}/{name}"),
                _ => name,
            };
            let version = o["version"].as_str().unwrap();
            let purl = format!("pkg:{eco}/{full}@{version}");
            let uuid = o["patchUuid"].as_str().unwrap().to_string();
            let fix = |v: &Value| -> Value {
                match (v.as_str(), rewrite_host) {
                    (Some(s), Some(host)) => {
                        Value::String(s.replace("https://patch.socket.dev", host))
                    }
                    _ => v.clone(),
                }
            };
            let url = fix(&o["artifactUrl"]);
            let mut artifacts = vec![serde_json::json!({
                "kind": "tarball",
                "url": url,
                "integrity": o["integrity"].clone(),
            })];
            if let Some(zip) = o["berryZipUrl"].as_str() {
                artifacts.push(serde_json::json!({
                    "kind": "yarn-berry-zip",
                    "url": fix(&Value::String(zip.to_string())),
                    "integrity": {"yarnBerry10c0": o["integrity"]["yarnBerry10c0"].clone()},
                }));
            }
            let mut registry_override = o.get("registryOverride").cloned().unwrap_or(Value::Null);
            if let Some(index) = registry_override.get("indexUrl").cloned() {
                registry_override["indexUrl"] = fix(&index);
            }
            Patch {
                purl,
                uuid,
                reference: serde_json::json!({
                    "status": "granted",
                    "url": url,
                    "purl": null,
                    "artifacts": artifacts,
                    "registryOverride": registry_override,
                }),
            }
        })
        .collect()
}

struct Batch(Vec<Patch>);
impl Respond for Batch {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let mut packages = Vec::new();
        for component in body["components"].as_array().into_iter().flatten() {
            let Some(purl) = component["purl"].as_str() else {
                continue;
            };
            let patches: Vec<Value> = self
                .0
                .iter()
                .filter(|p| purl_key(&p.purl) == purl_key(purl))
                .map(|p| {
                    serde_json::json!({
                        "uuid": p.uuid, "purl": purl, "tier": "free", "cveIds": [],
                        "ghsaIds": ["GHSA-test-aaaa-bbbb"], "severity": "high", "title": "fixture"
                    })
                })
                .collect();
            if !patches.is_empty() {
                packages.push(serde_json::json!({ "purl": purl, "patches": patches }));
            }
        }
        ResponseTemplate::new(200).set_body_json(
            serde_json::json!({ "packages": packages, "canAccessPaidPatches": false }),
        )
    }
}

struct ByPackage(Vec<Patch>);
impl Respond for ByPackage {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let raw = request
            .url
            .path()
            .rsplit_once("/by-package/")
            .map(|(_, p)| p)
            .unwrap_or("");
        let purl = percent_decode(raw);
        let patches: Vec<Value> = self
            .0
            .iter()
            .filter(|p| purl_key(&p.purl) == purl_key(&purl))
            .map(|p| {
                serde_json::json!({
                    "uuid": p.uuid, "purl": purl, "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "fixture", "license": "MIT", "tier": "free",
                    "vulnerabilities": {"GHSA-test-aaaa-bbbb": {
                        "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d"
                    }}
                })
            })
            .collect();
        ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({ "patches": patches, "canAccessPaidPatches": false }))
    }
}

struct References(Vec<Patch>);
impl Respond for References {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        let mut results = serde_json::Map::new();
        for uuid in body["uuids"].as_array().into_iter().flatten() {
            let Some(uuid) = uuid.as_str() else { continue };
            if let Some(p) = self.0.iter().find(|p| p.uuid == uuid) {
                results.insert(uuid.to_string(), p.reference.clone());
            }
        }
        ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
    }
}

struct View(Vec<Patch>);
impl Respond for View {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let uuid = request.url.path().rsplit('/').next().unwrap_or("");
        match self.0.iter().find(|p| p.uuid == uuid) {
            Some(p) => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": p.uuid, "purl": p.purl, "publishedAt": "2024-01-01T00:00:00Z",
                "files": {"package/index.js": {"beforeHash": "a".repeat(64), "afterHash": "b".repeat(64)}},
                "vulnerabilities": {"GHSA-test-aaaa-bbbb": {
                    "cves": ["CVE-2024-0001"], "summary": "s", "severity": "high", "description": "d"
                }},
                "description": "fixture", "license": "MIT", "tier": "free"
            })),
            None => ResponseTemplate::new(404),
        }
    }
}

/// Mount the fake patch API for `patches`.
pub async fn mount_api(server: &MockServer, patches: &[Patch]) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(Batch(patches.to_vec()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ByPackage(patches.to_vec()))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(References(patches.to_vec()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!("^/v0/orgs/{ORG}/patches/view/.+$")))
        .respond_with(View(patches.to_vec()))
        .mount(server)
        .await;
}

pub fn client(server: &MockServer) -> Arc<dyn PatchApi> {
    Arc::new(ApiClient::new(ApiClientOptions {
        api_url: server.uri(),
        api_token: Some("fake-token".to_string()),
        use_public_proxy: false,
        org_slug: Some(ORG.to_string()),
    }))
}

/// Every regular file under `dir`, keyed by `/`-separated relative path.
pub fn read_tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, at: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(at) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                walk(base, &path, out);
            } else if meta.is_file() {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

/// `files` added to a session (`bun.lockb` as bytes, the rest as text)
/// plus presence-only markers.
pub fn build_input(
    files: &BTreeMap<String, Vec<u8>>,
    present: &[&str],
    options: HostedScanOptions,
) -> socket_patch_cli::hosted_memory::HostedScanInput {
    let mut builder = SessionBuilder::new(options).expect("valid options");
    for (path, bytes) in files {
        if path.ends_with("bun.lockb") {
            builder.add_binary(path, bytes).unwrap();
        } else {
            builder.push_chunk(path, bytes).unwrap();
            builder.end_file(path).unwrap();
        }
    }
    for path in present {
        builder
            .mark_present(path, MarkKind::Present(PresentKind::Present))
            .unwrap();
    }
    builder.finish().unwrap()
}

pub fn options(dry_run: bool) -> HostedScanOptions {
    HostedScanOptions {
        org_slug: ORG.to_string(),
        dry_run,
        ..HostedScanOptions::default()
    }
}

pub async fn run_engine(
    server: &MockServer,
    input: socket_patch_cli::hosted_memory::HostedScanInput,
) -> HostedScanOutput {
    run_in_memory(input, client(server), CancellationToken::new())
        .await
        .expect("engine run")
}

/// The disk run's outcome: the `--json` envelope and the files it changed
/// (new or byte-changed, relative to the input).
pub struct DiskRun {
    pub envelope: Value,
    pub changed: BTreeMap<String, Vec<u8>>,
    pub stderr: String,
}

/// `socket-patch scan --mode hosted --json` over a copy of `files`, through
/// the real binary, with every ambient input scrubbed: an empty `PATH` (no
/// node / pipenv / gem subprocesses), `HOME` and the language caches at
/// empty directories, no socket-cli config, no telemetry.
pub fn run_disk(server: &MockServer, files: &BTreeMap<String, Vec<u8>>, dry_run: bool) -> DiskRun {
    run_disk_with(server, files, dry_run, &[])
}

/// A human (non-`--json`) disk scan with `args`: exit code, stdout, and the
/// files it changed.
pub fn run_disk_args(
    server: &MockServer,
    files: &BTreeMap<String, Vec<u8>>,
    args: &[&str],
) -> (i32, String, BTreeMap<String, Vec<u8>>) {
    let (project, _home, mut cmd) = disk_command(server, files);
    cmd.args(args);
    let output = cmd.output().expect("spawn socket-patch");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let after = read_tree(project.path());
    let changed = after
        .into_iter()
        .filter(|(rel, bytes)| files.get(rel) != Some(bytes))
        .collect();
    (output.status.code().unwrap_or(-1), stdout, changed)
}

/// [`run_disk`] with extra `scan --json` arguments.
pub fn run_disk_with(
    server: &MockServer,
    files: &BTreeMap<String, Vec<u8>>,
    dry_run: bool,
    extra: &[&str],
) -> DiskRun {
    let (project, _home, mut cmd) = disk_command(server, files);
    cmd.arg("--json");
    if dry_run {
        cmd.arg("--dry-run");
    }
    cmd.args(extra);
    let output = cmd.output().expect("spawn socket-patch");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let envelope: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("disk --json output is not JSON ({e}):\n{stdout}\n{stderr}"));
    let after = read_tree(project.path());
    let changed = after
        .into_iter()
        .filter(|(rel, bytes)| files.get(rel) != Some(bytes))
        .collect();
    DiskRun {
        envelope,
        changed,
        stderr,
    }
}

/// The scrubbed `scan --mode hosted` command over a copy of `files` (the
/// returned tempdirs, the project and `HOME`, must outlive the run).
fn disk_command(
    server: &MockServer,
    files: &BTreeMap<String, Vec<u8>>,
) -> (tempfile::TempDir, tempfile::TempDir, std::process::Command) {
    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    for (rel, bytes) in files {
        let path = project.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
    }
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.env_clear();
    for keep in [
        "SYSTEMROOT",
        "SystemRoot",
        "windir",
        "TMPDIR",
        "TEMP",
        "TMP",
    ] {
        if let Some(v) = std::env::var_os(keep) {
            cmd.env(keep, v);
        }
    }
    let empty = |name: &str| {
        let dir = home.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    };
    cmd.env("PATH", "")
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("CARGO_HOME", empty("cargo"))
        .env("GOPATH", empty("go"))
        .env("GOMODCACHE", empty("gomodcache"))
        .env("GEM_HOME", empty("gem"))
        .env("XDG_CONFIG_HOME", empty("xdg"))
        .env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_UPDATE_CHECK", "1");
    cmd.args([
        "scan",
        "--mode",
        "hosted",
        "--yes",
        "--cwd",
        project.path().to_str().unwrap(),
        "--org",
        ORG,
        "--api-token",
        "fake-token",
        "--api-url",
        &server.uri(),
    ]);
    (project, home, cmd)
}

/// The engine's changed files (text and binary) as bytes.
pub fn engine_changed(output: &HostedScanOutput) -> BTreeMap<String, Vec<u8>> {
    output
        .changed_files
        .iter()
        .map(|f| (f.path.clone(), f.content.as_bytes().to_vec()))
        .chain(
            output
                .changed_binary_files
                .iter()
                .map(|f| (f.path.clone(), f.content.clone())),
        )
        .collect()
}

/// Every file under `dir` (a golden fixture's `input/`).
pub fn fixture_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    read_tree(dir)
}

/// Show a readable diff of two changed-file maps.
pub fn describe(map: &BTreeMap<String, Vec<u8>>) -> String {
    map.iter()
        .map(|(k, v)| format!("--- {k}\n{}", String::from_utf8_lossy(v)))
        .collect::<Vec<_>>()
        .join("\n")
}
