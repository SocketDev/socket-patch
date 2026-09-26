//! Hermetic vlt vendored-mode fixtures shared by the vendor, takeover,
//! repair, scan/get, VEX and lifecycle suites.
//!
//! Two project sources:
//! * the committed real-vlt captures under
//!   `socket-patch-core/tests/fixtures/vendor/npm/vlt/<vlt version>/`
//!   (projects plus the expected lock and package.json files real vlt kept
//!   byte-stable through `vlt ci`), used as byte oracles;
//! * a small synthetic `left-pad` project ([`Lock`], [`project`]) for the
//!   shapes no capture has.
//!
//! The installed copy is staged as vlt's store entry
//! `node_modules/.vlt/<DepID>/node_modules/<name>` (a real dir, so the
//! suites run on every OS), and every run is `--offline` against a staged
//! manifest record plus its after-hash blob, unless a test says otherwise.
//!
//! Include with `#[path = "vlt_vendor_common/mod.rs"] mod vlt_vendor;`.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
pub const UUID2: &str = "0a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d";
/// The uuid the real-vlt captures were taken with.
pub const FIXTURE_UUID: &str = "11111111-2222-4333-8444-555555555555";
pub const NAME: &str = "left-pad";
pub const VERSION: &str = "1.3.0";
pub const PURL: &str = "pkg:npm/left-pad@1.3.0";
pub const PRISTINE: &[u8] = b"module.exports = 'pristine';\n";
pub const PATCHED: &[u8] = b"module.exports = 'patched';\n";
pub const REG_SHA: &str = "sha512-REGISTRYregistryREGISTRYregistry==";
pub const REG_URL: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
pub const VLT_LOCK: &str = "vlt-lock.json";

/// The real-vlt versions whose captures are committed.
pub const CAPTURED: &[&str] = &["1.2.0", "1.0.10", "1.0.4", "1.0.0-rc.32", "1.0.0-rc.14"];

pub fn git_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../socket-patch-core/tests/fixtures/vendor/npm/vlt")
}

/// `.socket/vendor/npm/<uuid>/<leaf>/node_modules/<name>` (DESIGN §4.2).
pub fn rel_dir(uuid: &str, name: &str, version: &str) -> String {
    let (scope, bare) = match name.split_once('/') {
        Some((scope, bare)) => (format!("{scope}/"), bare),
        None => (String::new(), name),
    };
    format!(".socket/vendor/npm/{uuid}/{scope}{bare}-{version}/node_modules/{name}")
}

pub fn uuid_dir(root: &Path, uuid: &str) -> PathBuf {
    root.join(format!(".socket/vendor/npm/{uuid}"))
}

/// The file DepID of `rel` in a `lockfileVersion: 1` lock.
pub fn file_id_v1(rel: &str) -> String {
    format!("file~{}", rel.replace('_', "__").replace('/', "+"))
}

pub fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Every file under `dir` (relative, forward-slashed) with its bytes.
pub fn snapshot(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap();
                let rel = rel.to_string_lossy().replace('\\', "/");
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

// ── lock builder ─────────────────────────────────────────────────────────

/// A canonical `vlt-lock.json` (one entry per line, vlt's layout).
#[derive(Clone)]
pub struct Lock {
    pub version: Option<u8>,
    pub options: String,
    pub nodes: Vec<String>,
    pub edges: Vec<String>,
    pub crlf: bool,
}

impl Lock {
    pub fn v1(nodes: &[&str], edges: &[&str]) -> Self {
        Lock {
            version: Some(1),
            options: "{}".into(),
            nodes: nodes.iter().map(|s| s.to_string()).collect(),
            edges: edges.iter().map(|s| s.to_string()).collect(),
            crlf: false,
        }
    }

    pub fn v0(nodes: &[&str], edges: &[&str]) -> Self {
        Lock {
            version: Some(0),
            ..Lock::v1(nodes, edges)
        }
    }

    pub fn render(&self) -> String {
        let block = |entries: &[String]| {
            if entries.is_empty() {
                return "{}".to_string();
            }
            let lines: Vec<String> = entries
                .iter()
                .enumerate()
                .map(|(i, e)| format!("    {e}{}", if i + 1 < entries.len() { "," } else { "" }))
                .collect();
            format!("{{\n{}\n  }}", lines.join("\n"))
        };
        let version = self
            .version
            .map(|v| format!("  \"lockfileVersion\": {v},\n"))
            .unwrap_or_default();
        let text = format!(
            "{{\n{version}  \"options\": {},\n  \"nodes\": {},\n  \"edges\": {}\n}}\n",
            self.options,
            block(&self.nodes),
            block(&self.edges)
        );
        if self.crlf {
            text.replace('\n', "\r\n")
        } else {
            text
        }
    }
}

pub fn reg_node(id: &str) -> String {
    format!("\"{id}\": [0,\"{NAME}\",\"{REG_SHA}\",\"{REG_URL}\"]")
}

/// The one-dependency project: `left-pad` direct from the root.
pub fn direct_lock() -> Lock {
    Lock::v1(
        &[&reg_node("~npm~left-pad@1.3.0")],
        &["\"file~_d left-pad\": \"prod 1.3.0 ~npm~left-pad@1.3.0\""],
    )
}

pub fn direct_lock_v0() -> Lock {
    Lock::v0(
        &[&reg_node("·npm·left-pad@1.3.0")],
        &["\"file·. left-pad\": \"prod 1.3.0 ·npm·left-pad@1.3.0\""],
    )
}

pub const ROOT_PKG: &str =
    "{\n  \"name\": \"consumer\",\n  \"version\": \"0.0.0\",\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";

pub fn store_dir(root: &Path, dep_id: &str, name: &str) -> PathBuf {
    root.join("node_modules/.vlt")
        .join(dep_id)
        .join("node_modules")
        .join(name)
}

/// vlt's installed store copy of `name@version` under `dep_id`, holding
/// `index` and `package_json` (default: name and version only).
pub fn install_store(
    root: &Path,
    dep_id: &str,
    name: &str,
    version: &str,
    index: &[u8],
    package_json: Option<&str>,
) -> PathBuf {
    let dir = store_dir(root, dep_id, name);
    std::fs::create_dir_all(&dir).unwrap();
    let pkg = package_json
        .map(str::to_string)
        .unwrap_or_else(|| format!("{{\"name\":\"{name}\",\"version\":\"{version}\"}}\n"));
    std::fs::write(dir.join("package.json"), pkg).unwrap();
    std::fs::write(dir.join("index.js"), index).unwrap();
    dir
}

/// A manifest record for `uuid` patching `index.js` (and optionally
/// `package.json`), plus the after-hash blobs, so `vendor --offline` runs.
pub fn stage_patch(root: &Path, purls: &[&str], uuid: &str, extra: &[(&str, &[u8], &[u8])]) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut files = serde_json::Map::new();
    let mut all: Vec<(&str, &[u8], &[u8])> = vec![("package/index.js", PRISTINE, PATCHED)];
    all.extend_from_slice(extra);
    for (file, before, after) in all {
        files.insert(
            file.to_string(),
            json!({ "beforeHash": git_sha256(before), "afterHash": git_sha256(after) }),
        );
        std::fs::write(socket.join("blobs").join(git_sha256(after)), after).unwrap();
    }
    let record = json!({
        "uuid": uuid,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": files,
        "vulnerabilities": {},
        "description": "vlt vendor fixture",
        "license": "MIT",
        "tier": "free"
    });
    let mut patches = serde_json::Map::new();
    for purl in purls {
        patches.insert(purl.to_string(), record.clone());
    }
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).unwrap(),
    )
    .unwrap();
}

/// The synthetic project: `lock`, root package.json `pkg`, the left-pad
/// store copy under `store_id`, and a staged patch at [`UUID`].
pub fn project(root: &Path, lock: &Lock, pkg: &str, store_id: &str) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join(VLT_LOCK), lock.render()).unwrap();
    std::fs::write(root.join("package.json"), pkg).unwrap();
    install_store(root, store_id, NAME, VERSION, PRISTINE, None);
    stage_patch(root, &[PURL], UUID, &[]);
}

pub fn direct_project(root: &Path) {
    project(root, &direct_lock(), ROOT_PKG, "~npm~left-pad@1.3.0");
}

/// A capture's case, read from its `case.json`.
pub struct Case {
    pub vlt: String,
    pub name: String,
    pub project: String,
    pub purl: String,
    pub refusal: Option<String>,
}

impl Case {
    pub fn dir(&self) -> PathBuf {
        fixtures().join(&self.vlt).join("cases").join(&self.name)
    }

    pub fn project_dir(&self) -> PathBuf {
        fixtures()
            .join(&self.vlt)
            .join("projects")
            .join(&self.project)
    }

    pub fn coords(&self) -> (String, String) {
        let rest = self.purl.strip_prefix("pkg:npm/").unwrap();
        let (name, version) = rest.rsplit_once('@').unwrap();
        (name.to_string(), version.to_string())
    }
}

pub fn cases(vlt: &str) -> Vec<Case> {
    let mut out = Vec::new();
    let dir = fixtures().join(vlt).join("cases");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in names {
        let case: Value =
            serde_json::from_slice(&std::fs::read(dir.join(&name).join("case.json")).unwrap())
                .unwrap();
        out.push(Case {
            vlt: vlt.to_string(),
            name,
            project: case["project"].as_str().unwrap().to_string(),
            purl: case["purl"].as_str().unwrap().to_string(),
            refusal: case["refusal"].as_str().map(str::to_string),
        });
    }
    out
}

/// The node keys of `lock` whose tuple names `name` at `version`.
pub fn dep_ids(lock: &str, name: &str, version: &str) -> Vec<String> {
    let doc: Value = serde_json::from_str(lock).unwrap();
    doc["nodes"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(key, tuple)| {
            tuple[1] == name
                && (key.ends_with(&format!("@{version}")) || key.contains(&format!("@{version}~")))
                && !key.starts_with("file")
        })
        .map(|(key, _)| key.clone())
        .collect()
}

/// A capture's project copied to `root`, the target installed in vlt's
/// store (every instance) and its patch staged at [`FIXTURE_UUID`].
pub fn capture_project(root: &Path, case: &Case) {
    copy_dir(&case.project_dir(), root);
    let lock = std::fs::read_to_string(root.join(VLT_LOCK)).unwrap();
    let (name, version) = case.coords();
    for id in dep_ids(&lock, &name, &version) {
        install_store(root, &id, &name, &version, PRISTINE, None);
    }
    stage_patch(root, &[&case.purl], FIXTURE_UUID, &[]);
}

// ── CLI ──────────────────────────────────────────────────────────────────

/// The `socket-patch` binary with the ambient `SOCKET_*`, `VLT_*` and proxy
/// environment scrubbed (telemetry disabled).
pub fn cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().to_string();
        let proxy = ["http_proxy", "https_proxy", "all_proxy", "no_proxy"]
            .iter()
            .any(|p| name.eq_ignore_ascii_case(p));
        if proxy
            || name.starts_with("VLT_")
            || (name.starts_with("SOCKET_") && name != "SOCKET_NO_CONFIG")
        {
            cmd.env_remove(&key);
        }
    }
    for key in [
        "SOCKET_OFFLINE",
        "SOCKET_DRY_RUN",
        "SOCKET_API_URL",
        "SOCKET_PROXY_URL",
        "SOCKET_NO_VLT_INSTALL_CLEANUP",
    ] {
        cmd.env_remove(key);
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_UPDATE_CHECK", "1");
    cmd
}

/// `socket-patch <args>` in `cwd`: `(exit code, stdout JSON, stderr)`.
pub fn socket(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, Value, String) {
    let mut cmd = cli();
    cmd.args(args).current_dir(cwd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let doc = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be one JSON document ({e});\nstdout=\n{stdout}\nstderr=\n{stderr}")
    });
    (out.status.code().unwrap_or(-1), doc, stderr)
}

/// `socket-patch <args>` in `cwd`, human output: `(exit code, stdout,
/// stderr)`.
pub fn socket_human(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let out = cli()
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// `vendor --json --offline` plus `extra`.
pub fn vendor(root: &Path, extra: &[&str]) -> (i32, Value, String) {
    let cwd = root.to_str().unwrap().to_string();
    let mut args = vec!["vendor", "--json", "--offline", "--cwd", &cwd];
    args.extend_from_slice(extra);
    socket(root, &args, &[])
}

pub fn events(env: &Value) -> Vec<Value> {
    env["events"].as_array().cloned().unwrap_or_default()
}

/// Every event `errorCode` of the envelope, in order.
pub fn codes(env: &Value) -> Vec<String> {
    events(env)
        .iter()
        .filter_map(|e| e["errorCode"].as_str().map(str::to_string))
        .collect()
}

/// The `failed` event's `(errorCode, error)` for `purl`.
pub fn failure(env: &Value, purl: &str) -> (String, String) {
    events(env)
        .iter()
        .find(|e| e["action"] == "failed" && e["purl"] == purl)
        .map(|e| {
            (
                e["errorCode"].as_str().unwrap_or_default().to_string(),
                e["error"].as_str().unwrap_or_default().to_string(),
            )
        })
        .unwrap_or_else(|| panic!("expected a failed event for {purl}: {env:#}"))
}

pub fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

pub fn ledger(root: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(root.join(".socket/vendor/state.json")).unwrap()).unwrap()
}

/// The ledger entry for `purl`.
pub fn ledger_entry(root: &Path, purl: &str) -> Value {
    ledger(root)["entries"][purl].clone()
}

/// The exact `<uuid>/.gitignore` and `.gitattributes` bytes (DESIGN §4.2).
pub const UUID_GITIGNORE: &str =
    "!*\n**/node_modules/*/node_modules/\n**/node_modules/@*/*/node_modules/\n";
pub const UUID_GITATTRIBUTES: &str = "* -text\n";

pub fn git() -> Option<PathBuf> {
    socket_patch_core::utils::process::resolve_tool("git")
}

pub fn git_init(root: &Path) -> bool {
    let Some(git) = git() else {
        return false;
    };
    Command::new(git)
        .args(["init", "-q"])
        .current_dir(root)
        .status()
        .is_ok_and(|s| s.success())
}
