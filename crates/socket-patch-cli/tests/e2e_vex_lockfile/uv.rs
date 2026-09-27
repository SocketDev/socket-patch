//! Manifest-less VEX for uv: `uv.lock` (with and without its
//! `pyproject.toml`), PEP 723 script locks (`<script>.py.lock` + the
//! script's metadata block) and PEP 751 `pylock.toml` (`uv export --format
//! pylock.toml` / `uv pip compile -o pylock.toml` / `pip lock`) — HOSTED and
//! VENDORED, with NO `.socket/manifest.json` and (unless a cell says
//! otherwise) NO `.socket/vendor/{state,redirect-state}.json` ledgers.
//!
//! Hermetic: no real package manager, runs on every OS. Every wiring file is
//! produced by the SAME writers the product uses: the cells run the core
//! rewriters (`rewrite_python_lock`, `rewrite_project_metadata`,
//! `rewrite_script_metadata`) over real uv output (uv 0.11 `uv lock` /
//! `uv lock --script` / `uv export --format pylock.toml` grammar), and the
//! writer-driven cells run the real `scan --redirect --vex` / `scan --vendor
//! --vex` binaries against a wiremock patch API. The package is a made-up
//! `vexfixture`, so no interpreter's global site-packages on the test host
//! can hold a copy (a no-venv python project falls back to the global
//! interpreters). The real-uv capstones (every uv 0.N line) live in
//! `e2e_redirect_uv_build` (hosted) and `e2e_vendor_pypi_build` (vendored).
//!
//! The matrix, per flavor × {hosted, vendored} (see the section headers):
//!
//!   a. no manifest / no ledgers, online → attested with the right
//!      subcomponent purl, vulnerability id + CVE alias, `(redirected)` /
//!      `(vendored)` marker, exit 0, envelope `verified` events;
//!   b. `--offline` (and an API that 404s) → `record_unavailable`, exit 1,
//!      and under `--offline` NO request reaches the API;
//!   c. ledger present, manifest absent → attests offline from the ledger's
//!      record (no API request);
//!   d. lockfile reverted to the registry while the ledger (+ artifact)
//!      remain → `redirect_unwired` / `vendor_unwired`, `--no-verify` too;
//!   e. tampered installed tree (hosted) → `hash_mismatch`; tampered
//!      vendored wheel member → `vendor_hash_mismatch`;
//!   f. spoofs: a uuid on a non-Socket host is no reference; a record whose
//!      purl or uuid differs from the lock → `record_mismatch`;
//!   g. hosted not installed → attests from the lock's sha256 pin (D5);
//!      installed + patched → attests after hashing; installed pristine →
//!      `not_applied`; a pin-less hosted entry needs an installed tree.
//!
//! Plus the embedded entry points (`scan --redirect --vex`, `scan --vendor
//! --vex`, `apply --vex`).

use crate::vex_e2e_common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
use socket_patch_core::patch::redirect::{FileEdit, RedirectState};
use socket_patch_core::utils::python_lock::{rewrite_python_lock, ArtifactSource};
use socket_patch_core::utils::python_script::{rewrite_project_metadata, rewrite_script_metadata};
use socket_patch_core::vendor::state::{
    VendorArtifact, VendorEntry, VendorState, WiringAction, WiringRecord,
};
use vex_e2e_common::{assert_omitted_parts, skipped_reason};

// ── fixture identity ────────────────────────────────────────────────────

const PKG: &str = "vexfixture";
/// Every fixture locks this version (the real uv 0.11 output for
/// `six==1.16.0`, renamed).
const VER: &str = "1.16.0";
const HOSTED_UUID: &str = "4a7c1e2b-3d4f-4a5b-8c6d-7e8f9a0b1c2d";
const VENDORED_UUID: &str = "5b8d2f3c-4e5a-4b6c-9d7e-8f9a0b1c2d3e";
/// A uuid-SHAPED grant token: hosted urls carry it BEFORE the patch uuid.
const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
const PRODUCT: &str = "pkg:pypi/app@0.1.0";
const GHSA: &str = "GHSA-pya1-vexl-ock1";
const CVE: &str = "CVE-2026-7001";
/// The patched module, site-packages relative (pypi record keys are).
const MODULE: &str = "vexfixture/__init__.py";
const PRISTINE: &[u8] = b"# vexfixture pristine\n";
const PATCHED: &[u8] = b"# vexfixture pristine\nSOCKET_PATCHED = 1\n";
/// Org slug for the writer-driven (`scan`) cells.
const ORG: &str = "test-org";
/// The PEP 723 script a script lock belongs to.
const SCRIPT: &str = "tool.py";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn base_purl(version: &str) -> String {
    format!("pkg:pypi/{PKG}@{version}")
}

/// The artifact-qualified purl the patch API files pypi patches under.
fn api_purl(version: &str) -> String {
    format!("pkg:pypi/{PKG}@{version}?artifact_id=py3-none-any-whl")
}

// ── package-manager output (real grammars, renamed to `vexfixture`) ────

/// `pyproject.toml` of the uv project.
fn uv_pyproject() -> String {
    format!(
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\n\
         dependencies = [\"{PKG}=={VER}\"]\n"
    )
}

/// The registry `[[package]]` entry every uv lock shape carries.
fn uv_registry_package() -> String {
    format!(
        r#"[[package]]
name = "{PKG}"
version = "{VER}"
source = {{ registry = "https://pypi.org/simple" }}
sdist = {{ url = "https://files.pythonhosted.org/packages/71/39/{PKG}-{VER}.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926", size = 34041, upload-time = "2021-05-05T14:18:18.379Z" }}
wheels = [
    {{ url = "https://files.pythonhosted.org/packages/d9/5a/{PKG}-{VER}-py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254", size = 11053, upload-time = "2021-05-05T14:18:17.237Z" }},
]
"#
    )
}

/// `uv lock` (uv 0.11.19, lock `version = 1`, `revision = 3`) for the uv
/// project, byte-for-byte except the rename.
fn uv_native_lock() -> String {
    format!(
        r#"version = 1
revision = 3
requires-python = ">=3.9"

[[package]]
name = "app"
version = "0.1.0"
source = {{ virtual = "." }}
dependencies = [
    {{ name = "{PKG}" }},
]

[package.metadata]
requires-dist = [{{ name = "{PKG}", specifier = "=={VER}" }}]

{}"#,
        uv_registry_package()
    )
}

/// The PEP 723 script (`tool.py`) a script lock belongs to.
fn script_native() -> String {
    format!(
        "# /// script\n# requires-python = \">=3.9\"\n# dependencies = [\"{PKG}=={VER}\"]\n# ///\n\
         import vexfixture\n"
    )
}

/// `uv lock --script tool.py` (uv 0.11.19) — the `[manifest]` requirements
/// stand in for the project's root package.
fn script_native_lock() -> String {
    format!(
        r#"version = 1
revision = 3
requires-python = ">=3.9"

[manifest]
requirements = [{{ name = "{PKG}", specifier = "=={VER}" }}]

{}"#,
        uv_registry_package()
    )
}

/// `uv export --format pylock.toml` (uv 0.11.19) for the same project.
fn pylock_native() -> String {
    format!(
        r#"# This file was autogenerated by uv via the following command:
#    uv export --format pylock.toml
lock-version = "1.0"
created-by = "uv"
requires-python = ">=3.9"

[[packages]]
name = "{PKG}"
version = "{VER}"
index = "https://pypi.org/simple"
sdist = {{ url = "https://files.pythonhosted.org/packages/71/39/{PKG}-{VER}.tar.gz", upload-time = 2021-05-05T14:18:18Z, size = 34041, hashes = {{ sha256 = "1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926" }} }}
wheels = [{{ url = "https://files.pythonhosted.org/packages/d9/5a/{PKG}-{VER}-py3-none-any.whl", upload-time = 2021-05-05T14:18:17Z, size = 11053, hashes = {{ sha256 = "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254" }} }}]
"#
    )
}

/// `pip lock` (pip 25.x) — a `pylock.toml` WITHOUT uv's header or
/// `index`, and wheel-only.
fn pip_lock_native() -> String {
    format!(
        r#"lock-version = "1.0"
created-by = "pip"

[[packages]]
name = "{PKG}"
version = "{VER}"

[[packages.wheels]]
name = "{PKG}-{VER}-py3-none-any.whl"
url = "https://files.pythonhosted.org/packages/d9/5a/{PKG}-{VER}-py3-none-any.whl"

[packages.wheels.hashes]
sha256 = "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"
"#
    )
}

// ── flavors ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Hosted,
    Vendored,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    /// `pyproject.toml` + `uv.lock` (both edited by the writers).
    UvProject,
    /// `uv.lock` alone (a lock-only checkout: the hosted rewriter edits the
    /// lock alone, discovery needs no pyproject confirmation).
    UvLockOnly,
    /// `tool.py` + `tool.py.lock` (PEP 723 script lock, both edited).
    Script,
    /// `pylock.toml` (uv export) beside a source-less `pyproject.toml`.
    Pylock,
    /// `pylock.toml` as `pip lock` writes it (no pyproject).
    PipLock,
}

impl Flavor {
    fn version(self) -> &'static str {
        VER
    }

    fn wheel(self) -> String {
        format!("{PKG}-{VER}-py3-none-any.whl")
    }

    fn lock_file(self) -> &'static str {
        match self {
            Flavor::UvProject | Flavor::UvLockOnly => "uv.lock",
            Flavor::Script => "tool.py.lock",
            Flavor::Pylock | Flavor::PipLock => "pylock.toml",
        }
    }

    /// Vendor-ledger `flavor` the pypi backend records.
    fn ledger_flavor(self) -> &'static str {
        match self {
            Flavor::UvProject | Flavor::UvLockOnly => "uv",
            Flavor::Script | Flavor::Pylock | Flavor::PipLock => "python-lock",
        }
    }

    fn purl(self) -> String {
        base_purl(self.version())
    }

    fn api_purl(self) -> String {
        api_purl(self.version())
    }

    fn label(self) -> String {
        format!("{self:?}")
    }

    fn hosted_url(self, uuid: &str) -> String {
        hosted_url_on("https://patch.socket.dev", self, uuid)
    }

    fn vendored_rel(self, uuid: &str) -> String {
        format!(".socket/vendor/pypi/{uuid}/{}", self.wheel())
    }

    /// The registry (pre-patch / reverted) project files.
    fn native_files(self) -> Vec<(&'static str, String)> {
        match self {
            Flavor::UvProject => vec![
                ("pyproject.toml", uv_pyproject()),
                ("uv.lock", uv_native_lock()),
            ],
            Flavor::UvLockOnly => vec![("uv.lock", uv_native_lock())],
            Flavor::Script => vec![
                (SCRIPT, script_native()),
                ("tool.py.lock", script_native_lock()),
            ],
            Flavor::Pylock => vec![
                ("pyproject.toml", uv_pyproject()),
                ("pylock.toml", pylock_native()),
            ],
            Flavor::PipLock => vec![("pylock.toml", pip_lock_native())],
        }
    }

    /// The project files after the writer wired `location` (a hosted url or
    /// a `.socket/vendor/...` path) pinned to `sha256`.
    fn wired_files(self, mode: Mode, location: &str, sha256: &str) -> Vec<(&'static str, String)> {
        let artifact = match mode {
            Mode::Hosted => ArtifactSource::Url(location),
            Mode::Vendored => ArtifactSource::Path(location),
        };
        let mut files = self.native_files();
        for (name, text) in files.iter_mut() {
            let rewritten = match (self, *name) {
                (_, "uv.lock" | "tool.py.lock" | "pylock.toml") => {
                    rewrite_python_lock(text, PKG, self.version(), artifact, sha256)
                        .expect("rewrite python lock")
                        .expect("lock has the entry")
                }
                (Flavor::UvProject, "pyproject.toml") => {
                    rewrite_project_metadata(text, PKG, self.version(), artifact)
                        .expect("rewrite pyproject")
                        .expect("pyproject changed")
                }
                (Flavor::Script, SCRIPT) => {
                    rewrite_script_metadata(text, PKG, self.version(), artifact)
                        .expect("rewrite script metadata")
                        .expect("script changed")
                }
                _ => continue,
            };
            *text = rewritten;
        }
        files
    }
}

fn hosted_url_on(origin: &str, flavor: Flavor, uuid: &str) -> String {
    format!(
        "{origin}/patch/pypi/{PKG}/{}/{TOKEN}/{uuid}/{}",
        flavor.version(),
        flavor.wheel()
    )
}

/// Every flavor (each uv lock grammar the writers wire).
fn flavors(_mode: Mode) -> Vec<Flavor> {
    vec![
        Flavor::UvProject,
        Flavor::UvLockOnly,
        Flavor::Script,
        Flavor::Pylock,
        Flavor::PipLock,
    ]
}

/// The heavier cells run every flavor too: there are only five.
fn representative(mode: Mode) -> Vec<Flavor> {
    flavors(mode)
}

// ── project scaffolding ─────────────────────────────────────────────────

/// A temp dir holding the project (`proj/`) and an isolated scratch home
/// (`home/`) for the child's per-user tool state.
struct Proj {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}

impl Proj {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        Proj {
            _tmp: tmp,
            root,
            home,
        }
    }

    fn write(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let path = self.root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn write_files(&self, files: &[(&str, String)]) {
        for (name, text) in files {
            self.write(name, text);
        }
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.root.join(rel)).unwrap()
    }

    fn exists(&self, rel: &str) -> bool {
        self.root.join(rel).exists()
    }

    /// Site-packages of the in-project `.venv` (PEP 405 layout per OS).
    fn site(&self) -> PathBuf {
        if cfg!(windows) {
            self.root.join(".venv/Lib/site-packages")
        } else {
            self.root.join(".venv/lib/python3.12/site-packages")
        }
    }

    /// Install `vexfixture==version` into `.venv` with `module` bytes.
    fn install(&self, version: &str, module: &[u8]) {
        let site = self.site();
        let dist = site.join(format!("{PKG}-{version}.dist-info"));
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::create_dir_all(site.join(PKG)).unwrap();
        std::fs::write(site.join(MODULE), module).unwrap();
        std::fs::write(
            dist.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: {PKG}\nVersion: {version}\n"),
        )
        .unwrap();
        std::fs::write(
            dist.join("WHEEL"),
            "Wheel-Version: 1.0\nGenerator: socket-patch-tests\nRoot-Is-Purelib: true\n\
             Tag: py3-none-any\n",
        )
        .unwrap();
        let rec = |rel: &str, bytes: &[u8]| {
            use base64::Engine as _;
            let digest =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
            format!("{rel},sha256={digest},{}\n", bytes.len())
        };
        let metadata = std::fs::read(dist.join("METADATA")).unwrap();
        let wheel = std::fs::read(dist.join("WHEEL")).unwrap();
        let record = format!(
            "{}{}{}{PKG}-{version}.dist-info/RECORD,,\n",
            rec(MODULE, module),
            rec(&format!("{PKG}-{version}.dist-info/METADATA"), &metadata),
            rec(&format!("{PKG}-{version}.dist-info/WHEEL"), &wheel),
        );
        std::fs::write(dist.join("RECORD"), record).unwrap();
    }
}

/// A wheel (zip) holding `vexfixture/__init__.py` = `module` plus its
/// dist-info. Returns the bytes.
fn build_wheel(version: &str, module: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let dist = format!("{PKG}-{version}.dist-info");
        let members: Vec<(String, Vec<u8>)> = vec![
            (MODULE.to_string(), module.to_vec()),
            (
                format!("{dist}/METADATA"),
                format!("Metadata-Version: 2.1\nName: {PKG}\nVersion: {version}\n\n").into_bytes(),
            ),
            (
                format!("{dist}/WHEEL"),
                b"Wheel-Version: 1.0\nGenerator: socket-patch-tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                    .to_vec(),
            ),
            (format!("{dist}/RECORD"), Vec::new()),
        ];
        for (name, bytes) in members {
            writer.start_file(name, opts).unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap();
    }
    buf.into_inner()
}

// ── records, views, ledgers ─────────────────────────────────────────────

fn record(uuid: &str) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        MODULE.to_string(),
        PatchFileInfo {
            before_hash: compute_git_sha256_from_bytes(PRISTINE),
            after_hash: compute_git_sha256_from_bytes(PATCHED),
        },
    );
    let mut vulnerabilities = HashMap::new();
    vulnerabilities.insert(
        GHSA.to_string(),
        VulnerabilityInfo {
            cves: vec![CVE.to_string()],
            summary: "vexfixture advisory".to_string(),
            severity: "high".to_string(),
            description: "d".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2026-09-01T00:00:00Z".to_string(),
        files,
        vulnerabilities,
        description: "vexfixture patch".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// The patch API's view of `uuid` (the `GET …/patch/view/<uuid>` body).
fn view(uuid: &str, purl: &str) -> Value {
    json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "Tue, 01 Sep 2026 00:00:00 GMT",
        "files": { MODULE: {
            "beforeHash": compute_git_sha256_from_bytes(PRISTINE),
            "afterHash": compute_git_sha256_from_bytes(PATCHED),
        } },
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "vexfixture advisory", "severity": "high",
            "description": "d"
        } },
        "description": "vexfixture patch",
        "license": "MIT",
        "tier": "free",
    })
}

/// `.socket/vendor/redirect-state.json` with `record` filed under
/// `ledger_purl` and an edit for every wiring `file`.
fn write_redirect_ledger(p: &Proj, ledger_purl: &str, record: PatchRecord, files: &[&str]) {
    let mut state = RedirectState::new();
    state.records.insert(ledger_purl.to_string(), record);
    for file in files {
        state.edits.push(FileEdit {
            path: file.to_string(),
            kind: "redirect_uv_lock_wheel".to_string(),
            action: "rewritten".to_string(),
            key: Some(format!("{PKG}@ver")),
            original: None,
            new: None,
        });
    }
    p.write(
        ".socket/vendor/redirect-state.json",
        serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// `.socket/vendor/state.json` with one pypi entry embedding `record` (the
/// shape every current vendor writer persists).
fn write_vendor_ledger(p: &Proj, flavor: Flavor, rel: &str, sha: &str, record: PatchRecord) {
    let mut state = VendorState::new();
    state.entries.insert(
        flavor.api_purl(),
        VendorEntry {
            ecosystem: "pypi".to_string(),
            base_purl: flavor.purl(),
            uuid: record.uuid.clone(),
            artifact: VendorArtifact {
                path: rel.to_string(),
                sha256: sha.to_string(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: flavor
                .native_files()
                .iter()
                .map(|(file, _)| WiringRecord {
                    file: file.to_string(),
                    kind: "pypi_lock_entry".to_string(),
                    action: WiringAction::Rewritten,
                    key: None,
                    original: None,
                    new: None,
                })
                .collect(),
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: Some(record),
            flavor: Some(flavor.ledger_flavor().to_string()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        },
    );
    p.write(
        ".socket/vendor/state.json",
        serde_json::to_string_pretty(&state).unwrap(),
    );
}

/// Wire `flavor` in `mode` into `p` exactly as the writers leave it:
/// hosted → the Socket url pinned to the patched wheel's sha256; vendored →
/// the committed `.socket/vendor/pypi/<uuid>/<wheel>` (holding `artifact`
/// module bytes) pinned to its sha256. Returns the pin.
fn wire(p: &Proj, flavor: Flavor, mode: Mode, artifact: &[u8]) -> String {
    let wheel = build_wheel(flavor.version(), artifact);
    let sha = sha256_hex(&wheel);
    let location = match mode {
        Mode::Hosted => flavor.hosted_url(HOSTED_UUID),
        Mode::Vendored => {
            let rel = flavor.vendored_rel(VENDORED_UUID);
            p.write(&rel, &wheel);
            rel
        }
    };
    p.write_files(&flavor.wired_files(mode, &location, &sha));
    sha
}

fn uuid_of(mode: Mode) -> &'static str {
    match mode {
        Mode::Hosted => HOSTED_UUID,
        Mode::Vendored => VENDORED_UUID,
    }
}

fn marker(mode: Mode) -> &'static str {
    match mode {
        Mode::Hosted => "redirected",
        Mode::Vendored => "vendored",
    }
}

// ── the mock patch API ──────────────────────────────────────────────────

/// A wiremock patch API on its own runtime (kept alive for the CLI runs).
struct Api {
    rt: tokio::runtime::Runtime,
    server: wiremock::MockServer,
}

impl Api {
    fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(wiremock::MockServer::start());
        Api { rt, server }
    }

    /// Serve `body` at the public-proxy `GET /patch/view/<uuid>` route an
    /// unauthenticated `vex` fetches a missing record from.
    fn serve_view(&self, uuid: &str, body: Value) -> &Self {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        self.rt.block_on(
            Mock::given(method("GET"))
                .and(path(format!("/patch/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&self.server),
        );
        self
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    fn requests(&self) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .map(|r| r.len())
            .unwrap_or(0)
    }
}

// ── running the CLI ─────────────────────────────────────────────────────

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

/// The CLI with the ambient `SOCKET_*` / python / uv discovery environment
/// scrubbed and uv's cache pointed into `p.home`.
fn cli(p: &Proj) -> Command {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars() {
        if (key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG") || key.starts_with("UV_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env_remove("VIRTUAL_ENV")
        .env("UV_CACHE_DIR", p.home.join("uv-cache"));
    cmd
}

/// `vex --json --output <proj>/out.vex.json` (unauthenticated) → (exit,
/// envelope, the written document when one was written).
fn vex(p: &Proj, extra: &[&str]) -> (Option<i32>, Value, Option<Value>) {
    let out_path = p.root.join("out.vex.json");
    let _ = std::fs::remove_file(&out_path);
    let mut args: Vec<String> = vec![
        "vex".into(),
        "--cwd".into(),
        p.root.to_str().unwrap().into(),
        "--json".into(),
        "--output".into(),
        out_path.to_str().unwrap().into(),
        "--product".into(),
        PRODUCT.into(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    let out = cli(p)
        .env("SOCKET_NO_API_TOKEN", "1")
        .args(&args)
        .output()
        .expect("invoke vex");
    let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "envelope JSON on stdout ({e}). stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let doc = std::fs::read(&out_path)
        .ok()
        .map(|b| serde_json::from_slice(&b).expect("VEX document JSON"));
    (out.status.code(), env, doc)
}

/// `vex` online against `api` (records fetched through the public proxy).
fn vex_online(p: &Proj, api: &Api, extra: &[&str]) -> (Option<i32>, Value, Option<Value>) {
    let uri = api.uri();
    let mut args = vec!["--proxy-url", uri.as_str()];
    args.extend_from_slice(extra);
    vex(p, &args)
}

/// `vex --offline`, with `api` configured anyway so a stray request would
/// be observed.
fn vex_offline(p: &Proj, api: &Api, extra: &[&str]) -> (Option<i32>, Value, Option<Value>) {
    let uri = api.uri();
    let mut args = vec!["--offline", "--proxy-url", uri.as_str()];
    args.extend_from_slice(extra);
    vex(p, &args)
}

/// Assert exactly one attested statement for `subcomponent` from `uuid`
/// with the `mode` marker, and the matching envelope `verified` event.
fn assert_attested(
    what: &str,
    code: Option<i32>,
    env: &Value,
    doc: &Option<Value>,
    subcomponent: &str,
    uuid: &str,
    mode: Mode,
) {
    assert_eq!(code, Some(0), "{what}: {env}");
    assert_eq!(env["status"], "success", "{what}: {env}");
    let doc = doc.as_ref().unwrap_or_else(|| panic!("{what}: no VEX doc"));
    let stmts = doc["statements"].as_array().expect("statements");
    assert_eq!(stmts.len(), 1, "{what}: {doc}");
    let st = &stmts[0];
    assert_eq!(st["status"], "not_affected", "{what}");
    assert_eq!(st["vulnerability"]["name"], GHSA, "{what}");
    assert_eq!(st["vulnerability"]["aliases"], json!([CVE]), "{what}");
    assert_eq!(st["products"][0]["@id"], PRODUCT, "{what}");
    let subs = st["products"][0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs.len(), 1, "{what}: {doc}");
    assert_eq!(subs[0]["@id"], subcomponent, "{what}: {doc}");
    assert_eq!(
        st["impact_statement"],
        format!("Patched via Socket patch {uuid} ({})", marker(mode)),
        "{what}"
    );
    let events = env["events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "{what}: {env}");
    assert_eq!(events[0]["action"], "verified", "{what}: {env}");
    assert_eq!(events[0]["purl"], subcomponent, "{what}: {env}");
    assert_eq!(events[0]["details"]["vulnerability"], GHSA, "{what}: {env}");
    assert_eq!(events[0]["details"]["aliases"], json!([CVE]), "{what}");
}

/// Assert the run attested nothing: exit 1 `no_applicable_patches` and the
/// purl skipped with `reason`; no VEX document was written.
fn assert_omitted(
    what: &str,
    code: Option<i32>,
    env: &Value,
    doc: &Option<Value>,
    purl: &str,
    reason: &str,
) {
    assert_omitted_parts(code, env, doc.as_ref(), purl, reason, what);
}

fn assert_no_manifest_written(p: &Proj, what: &str) {
    assert!(
        !p.exists(".socket/manifest.json"),
        "{what}: vex must never write the manifest"
    );
}

// ════════════════════════════════════════════════════════════════════════
// a + b + g(not installed): lockfile alone, no manifest, no ledgers
// ════════════════════════════════════════════════════════════════════════

/// (a) online → attested from the API record; (b) `--offline` →
/// `record_unavailable` with zero requests; (b') an API that has no view
/// for the uuid (404) → `record_unavailable`. Hosted cells are not
/// installed, so they attest from the lock's sha256 pin (g). Every flavor,
/// every uv lock grammar.
#[test]
fn lockfile_only_attests_online_and_is_unavailable_offline() {
    for mode in [Mode::Hosted, Mode::Vendored] {
        for flavor in flavors(mode) {
            let what = format!("{} {mode:?}", flavor.label());
            let p = Proj::new();
            wire(&p, flavor, mode, PATCHED);
            assert!(!p.exists(".socket/manifest.json"));
            assert!(!p.exists(".socket/vendor/state.json"));
            assert!(!p.exists(".socket/vendor/redirect-state.json"));
            let uuid = uuid_of(mode);

            // (b) offline: the wiring is found but no record is available,
            // and nothing is fetched.
            let api = Api::start();
            api.serve_view(uuid, view(uuid, &flavor.api_purl()));
            let (code, env, doc) = vex_offline(&p, &api, &[]);
            assert_omitted(
                &format!("{what} offline"),
                code,
                &env,
                &doc,
                &flavor.purl(),
                "record_unavailable",
            );
            assert_eq!(api.requests(), 0, "{what}: --offline made an API request");

            // (b') online, but the API has no record for the uuid.
            let empty = Api::start();
            let (code, env, doc) = vex_online(&p, &empty, &[]);
            assert_omitted(
                &format!("{what} 404"),
                code,
                &env,
                &doc,
                &flavor.purl(),
                "record_unavailable",
            );

            // (a) online.
            let (code, env, doc) = vex_online(&p, &api, &[]);
            assert_attested(&what, code, &env, &doc, &flavor.api_purl(), uuid, mode);
            assert!(api.requests() >= 1, "{what}: the record came from the API");
            assert_no_manifest_written(&p, &what);
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// c: ledger present, manifest absent → offline attestation from the ledger
// ════════════════════════════════════════════════════════════════════════

/// Write the ledger `mode`'s writer persists next to the wiring `wire`
/// left (record embedded, filed under the API's qualified purl).
fn write_ledger(p: &Proj, flavor: Flavor, mode: Mode, sha: &str, record: PatchRecord) {
    match mode {
        Mode::Hosted => {
            let files: Vec<&str> = flavor.native_files().iter().map(|(f, _)| *f).collect();
            write_redirect_ledger(p, &flavor.api_purl(), record, &files)
        }
        Mode::Vendored => {
            write_vendor_ledger(p, flavor, &flavor.vendored_rel(VENDORED_UUID), sha, record)
        }
    }
}

#[test]
fn ledger_without_manifest_attests_offline() {
    for mode in [Mode::Hosted, Mode::Vendored] {
        for flavor in representative(mode) {
            let what = format!("{} {mode:?} ledger", flavor.label());
            let p = Proj::new();
            let sha = wire(&p, flavor, mode, PATCHED);
            write_ledger(&p, flavor, mode, &sha, record(uuid_of(mode)));
            let api = Api::start();
            for extra in [&[][..], &["--no-verify"][..]] {
                let (code, env, doc) = vex_offline(&p, &api, extra);
                assert_attested(
                    &format!("{what} {extra:?}"),
                    code,
                    &env,
                    &doc,
                    &flavor.api_purl(),
                    uuid_of(mode),
                    mode,
                );
            }
            assert_eq!(api.requests(), 0, "{what}: the ledger record needs no API");
            assert_no_manifest_written(&p, &what);
        }
    }
}

/// The lockfile wires a NEWER patch than the ledger records for the same
/// package: the wired uuid wins, so the stale ledger record cannot stand in
/// for it — offline there is no record for the wired patch.
#[test]
fn ledger_record_for_a_superseded_patch_does_not_attest_the_wired_one() {
    const OLD: &str = "6c9e3a4d-5f6b-4c7d-8e8f-9a0b1c2d3e4f";
    for mode in [Mode::Hosted, Mode::Vendored] {
        for flavor in representative(mode) {
            let what = format!("{} {mode:?} superseded", flavor.label());
            let p = Proj::new();
            let sha = wire(&p, flavor, mode, PATCHED);
            write_ledger(&p, flavor, mode, &sha, record(OLD));
            let api = Api::start();
            let (code, env, doc) = vex_offline(&p, &api, &[]);
            assert_eq!(code, Some(1), "{what}: {env}");
            assert!(doc.is_none(), "{what}");
            assert_eq!(
                skipped_reason(&env, &flavor.purl()),
                "record_unavailable",
                "{what}: {env}"
            );
            // Online, the WIRED patch's record attests.
            api.serve_view(uuid_of(mode), view(uuid_of(mode), &flavor.api_purl()));
            let (code, env, doc) = vex_online(&p, &api, &[]);
            assert_attested(
                &what,
                code,
                &env,
                &doc,
                &flavor.api_purl(),
                uuid_of(mode),
                mode,
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// d: lockfile reverted while the ledger (and artifact) remain
// ════════════════════════════════════════════════════════════════════════

fn unwired_reason(mode: Mode) -> &'static str {
    match mode {
        Mode::Hosted => "redirect_unwired",
        Mode::Vendored => "vendor_unwired",
    }
}

/// Every flavor: after the writer's wiring is reverted to the registry
/// lock (the committed artifact and the ledger left behind), the ledger
/// record must not attest — with or without `--no-verify`, offline or
/// online. Without the ledger, the leftover artifact alone names nothing:
/// `manifest_not_found` (exit 2).
#[test]
fn reverted_lockfile_never_attests_a_leftover_ledger() {
    for mode in [Mode::Hosted, Mode::Vendored] {
        for flavor in flavors(mode) {
            let what = format!("{} {mode:?} reverted", flavor.label());
            let p = Proj::new();
            let sha = wire(&p, flavor, mode, PATCHED);
            write_ledger(&p, flavor, mode, &sha, record(uuid_of(mode)));
            // Sanity: live before the revert.
            let api = Api::start();
            let (code, env, _) = vex_offline(&p, &api, &[]);
            assert_eq!(code, Some(0), "{what} (live): {env}");

            p.write_files(&flavor.native_files());
            api.serve_view(uuid_of(mode), view(uuid_of(mode), &flavor.api_purl()));
            for extra in [&[][..], &["--no-verify"][..]] {
                let (code, env, doc) = vex_offline(&p, &api, extra);
                assert_omitted(
                    &format!("{what} {extra:?}"),
                    code,
                    &env,
                    &doc,
                    &flavor.purl(),
                    unwired_reason(mode),
                );
                let (code, env, doc) = vex_online(&p, &api, extra);
                assert_omitted(
                    &format!("{what} online {extra:?}"),
                    code,
                    &env,
                    &doc,
                    &flavor.purl(),
                    unwired_reason(mode),
                );
            }

            // No ledger: the reverted lock (and any leftover artifact)
            // wires nothing at all.
            for ledger in ["state.json", "redirect-state.json"] {
                let _ = std::fs::remove_file(p.root.join(".socket/vendor").join(ledger));
            }
            if mode == Mode::Vendored {
                // The committed artifact stays behind: it alone is not wiring.
                assert!(p.exists(&flavor.vendored_rel(VENDORED_UUID)), "{what}");
            }
            let (code, env, doc) = vex_online(&p, &api, &[]);
            assert_eq!(code, Some(2), "{what} (no ledger): {env}");
            assert_eq!(env["error"]["code"], "manifest_not_found", "{what}: {env}");
            assert!(doc.is_none());
        }
    }
}

/// uv writes (and uv re-resolves against) the metadata/lock PAIR — the
/// project's `pyproject.toml` + `uv.lock`, a script's PEP 723 block +
/// `<script>.py.lock`: a pair with only one half still wired is reverted as
/// far as uv is concerned (`uv sync` / `uv run` re-lock from the metadata),
/// so neither half keeps a ledger record alive, and neither half attests
/// from the lockfile alone.
#[test]
fn half_reverted_uv_pair_never_attests() {
    for mode in [Mode::Hosted, Mode::Vendored] {
        for (flavor, halves) in [
            (Flavor::UvProject, ["pyproject.toml", "uv.lock"]),
            (Flavor::Script, [SCRIPT, "tool.py.lock"]),
        ] {
            let native = flavor.native_files();
            for keep in halves {
                let what = format!("{} {mode:?} only {keep} still wired", flavor.label());
                let p = Proj::new();
                let sha = wire(&p, flavor, mode, PATCHED);
                for (name, text) in &native {
                    if *name != keep {
                        p.write(name, text);
                    }
                }
                let api = Api::start();
                api.serve_view(uuid_of(mode), view(uuid_of(mode), &flavor.api_purl()));
                // Ledger-less: the half pair is not a reference.
                let (code, env, _) = vex_online(&p, &api, &[]);
                assert_ne!(code, Some(0), "{what} (no ledger): {env}");
                assert!(
                    env["events"]
                        .as_array()
                        .is_none_or(|events| events.iter().all(|e| e["action"] != "verified")),
                    "{what}: {env}"
                );
                // With the ledger: dead, --no-verify or not.
                write_ledger(&p, flavor, mode, &sha, record(uuid_of(mode)));
                for extra in [&[][..], &["--no-verify"][..]] {
                    let (code, env, doc) = vex_offline(&p, &api, extra);
                    assert_omitted(
                        &format!("{what} {extra:?}"),
                        code,
                        &env,
                        &doc,
                        &flavor.purl(),
                        unwired_reason(mode),
                    );
                }
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// e: tampered installed tree (hosted) / tampered vendored wheel member
// ════════════════════════════════════════════════════════════════════════

const TAMPERED: &[u8] = b"# vexfixture tampered\n";

#[test]
fn tampered_evidence_is_omitted() {
    for flavor in representative(Mode::Hosted) {
        let what = format!("{} hosted tampered install", flavor.label());
        let p = Proj::new();
        let sha = wire(&p, flavor, Mode::Hosted, PATCHED);
        p.install(flavor.version(), TAMPERED);
        let api = Api::start();
        api.serve_view(HOSTED_UUID, view(HOSTED_UUID, &flavor.api_purl()));
        let (code, env, doc) = vex_online(&p, &api, &[]);
        assert_omitted(&what, code, &env, &doc, &flavor.purl(), "hash_mismatch");
        // The ledger's record is judged by the same installed evidence.
        write_ledger(&p, flavor, Mode::Hosted, &sha, record(HOSTED_UUID));
        let (code, env, doc) = vex_offline(&p, &api, &[]);
        assert_omitted(
            &format!("{what} + ledger"),
            code,
            &env,
            &doc,
            &flavor.purl(),
            "hash_mismatch",
        );
    }
    for flavor in representative(Mode::Vendored) {
        let what = format!("{} vendored tampered wheel", flavor.label());
        let p = Proj::new();
        // The committed wheel's member does not hash to the record's
        // afterHash (the lock pin matches the tampered wheel — a hand-edit
        // that re-pinned it).
        let sha = wire(&p, flavor, Mode::Vendored, TAMPERED);
        let api = Api::start();
        api.serve_view(VENDORED_UUID, view(VENDORED_UUID, &flavor.api_purl()));
        let (code, env, doc) = vex_online(&p, &api, &[]);
        assert_omitted(
            &what,
            code,
            &env,
            &doc,
            &flavor.purl(),
            "vendor_hash_mismatch",
        );
        write_ledger(&p, flavor, Mode::Vendored, &sha, record(VENDORED_UUID));
        let (code, env, doc) = vex_offline(&p, &api, &[]);
        assert_omitted(
            &format!("{what} + ledger"),
            code,
            &env,
            &doc,
            &flavor.purl(),
            "vendor_hash_mismatch",
        );
        // A deleted artifact is no evidence either.
        std::fs::remove_file(p.root.join(flavor.vendored_rel(VENDORED_UUID))).unwrap();
        let (code, env, doc) = vex_offline(&p, &api, &[]);
        assert_eq!(code, Some(1), "{what} (artifact deleted): {env}");
        assert!(doc.is_none(), "{what} (artifact deleted)");
        let reason = skipped_reason(&env, &flavor.purl());
        assert!(
            reason.starts_with("vendor_"),
            "{what} (artifact deleted): {reason}"
        );
    }
}

// ════════════════════════════════════════════════════════════════════════
// f: spoofed references and mismatched records
// ════════════════════════════════════════════════════════════════════════

/// A patch uuid in a url on a host that is not Socket's patch server —
/// including look-alike hosts — is the user's own dependency source, never
/// a patch reference: with no manifest and no ledgers the run finds nothing
/// (`manifest_not_found`, exit 2) and asks the API for nothing.
#[test]
fn uuid_on_a_non_socket_host_is_not_a_reference() {
    for flavor in representative(Mode::Hosted) {
        for origin in [
            "https://evil.example",
            "https://patch.socket.dev.evil.example",
            "https://patch.socket.dev@evil.example",
            "https://evil.example/https://patch.socket.dev",
        ] {
            let what = format!("{} {origin}", flavor.label());
            let p = Proj::new();
            let wheel = build_wheel(flavor.version(), PATCHED);
            p.write_files(&flavor.wired_files(
                Mode::Hosted,
                &hosted_url_on(origin, flavor, HOSTED_UUID),
                &sha256_hex(&wheel),
            ));
            let api = Api::start();
            api.serve_view(HOSTED_UUID, view(HOSTED_UUID, &flavor.api_purl()));
            let (code, env, doc) = vex_online(&p, &api, &[]);
            assert_eq!(code, Some(2), "{what}: {env}");
            assert_eq!(env["error"]["code"], "manifest_not_found", "{what}: {env}");
            assert!(doc.is_none(), "{what}");
            assert_eq!(api.requests(), 0, "{what}: nothing to fetch");
        }
    }
}

/// A `.socket/vendor`-LOOKING path that is not this project's committed
/// artifact dir (outside the root, under another directory) is no vendored
/// reference.
#[test]
fn vendor_shaped_path_outside_the_project_vendor_dir_is_not_a_reference() {
    for flavor in representative(Mode::Vendored) {
        for rel in [
            format!("vendor/pypi/{VENDORED_UUID}/{}", flavor.wheel()),
            format!(
                "wheels/.socket/vendor/pypi/{VENDORED_UUID}/{}",
                flavor.wheel()
            ),
            format!("../.socket/vendor/pypi/{VENDORED_UUID}/{}", flavor.wheel()),
        ] {
            let what = format!("{} {rel}", flavor.label());
            let p = Proj::new();
            let wheel = build_wheel(flavor.version(), PATCHED);
            if !rel.starts_with("..") {
                p.write(&rel, &wheel);
            }
            p.write_files(&flavor.wired_files(Mode::Vendored, &rel, &sha256_hex(&wheel)));
            let api = Api::start();
            api.serve_view(VENDORED_UUID, view(VENDORED_UUID, &flavor.api_purl()));
            let (code, env, doc) = vex_online(&p, &api, &[]);
            assert_ne!(code, Some(0), "{what}: {env}");
            assert!(doc.is_none(), "{what}: {env}");
            assert_eq!(api.requests(), 0, "{what}: nothing to fetch");
        }
    }
}

/// The record fetched for the WIRED uuid must name the lock's package AND
/// carry that uuid; otherwise the lock and the record disagree about what
/// was patched → `record_mismatch`, never attested.
#[test]
fn record_naming_another_package_or_patch_is_a_mismatch() {
    const OTHER_UUID: &str = "7d0f4b5e-6a7c-4d8e-9f0a-1b2c3d4e5f60";
    for mode in [Mode::Hosted, Mode::Vendored] {
        for flavor in representative(mode) {
            let uuid = uuid_of(mode);
            let bodies = [
                ("other package", view(uuid, "pkg:pypi/other-package@1.0.0")),
                ("other version", view(uuid, &api_purl("9.9.9"))),
                ("other uuid", view(OTHER_UUID, &flavor.api_purl())),
            ];
            for (label, body) in bodies {
                let what = format!("{} {mode:?} {label}", flavor.label());
                let p = Proj::new();
                wire(&p, flavor, mode, PATCHED);
                let api = Api::start();
                api.serve_view(uuid, body);
                let (code, env, doc) = vex_online(&p, &api, &[]);
                assert_omitted(&what, code, &env, &doc, &flavor.purl(), "record_mismatch");
            }

            // A LOCAL record for the wired uuid filed under another
            // package (a hand-edited ledger) is a mismatch too.
            let what = format!("{} {mode:?} ledger names another package", flavor.label());
            let p = Proj::new();
            wire(&p, flavor, mode, PATCHED);
            write_redirect_ledger(
                &p,
                "pkg:pypi/other-package@1.0.0",
                record(uuid),
                &[flavor.lock_file()],
            );
            let api = Api::start();
            let (code, env, doc) = vex_offline(&p, &api, &[]);
            assert_omitted(&what, code, &env, &doc, &flavor.purl(), "record_mismatch");
        }
    }
}

/// Two locks that wire ONE package to DIFFERENT patches attest neither.
#[test]
fn locks_wiring_different_patches_attest_neither() {
    let p = Proj::new();
    let uv = Flavor::UvLockOnly;
    wire(&p, uv, Mode::Hosted, PATCHED);
    // pylock.toml for the same package wired to the VENDORED patch.
    wire(&p, Flavor::Pylock, Mode::Vendored, PATCHED);
    std::fs::remove_file(p.root.join("pyproject.toml")).unwrap();
    let api = Api::start();
    api.serve_view(HOSTED_UUID, view(HOSTED_UUID, &uv.api_purl()));
    api.serve_view(VENDORED_UUID, view(VENDORED_UUID, &uv.api_purl()));
    let (code, env, doc) = vex_online(&p, &api, &[]);
    assert_omitted(
        "uv.lock vs pylock.toml",
        code,
        &env,
        &doc,
        &uv.purl(),
        "wiring_conflict",
    );
}

// ════════════════════════════════════════════════════════════════════════
// g: hosted installed evidence
// ════════════════════════════════════════════════════════════════════════

/// Once installed, the installed tree is the evidence: patched attests
/// after hashing (online and from the ledger offline), pristine is
/// `not_applied` even though the pinned wiring alone would have attested a
/// not-yet-installed checkout.
#[test]
fn hosted_installed_tree_is_hash_verified() {
    for flavor in representative(Mode::Hosted) {
        let what = format!("{} hosted installed", flavor.label());
        let p = Proj::new();
        let sha = wire(&p, flavor, Mode::Hosted, PATCHED);
        let api = Api::start();
        api.serve_view(HOSTED_UUID, view(HOSTED_UUID, &flavor.api_purl()));

        p.install(flavor.version(), PATCHED);
        let (code, env, doc) = vex_online(&p, &api, &[]);
        assert_attested(
            &what,
            code,
            &env,
            &doc,
            &flavor.api_purl(),
            HOSTED_UUID,
            Mode::Hosted,
        );

        p.install(flavor.version(), PRISTINE);
        let (code, env, doc) = vex_online(&p, &api, &[]);
        assert_omitted(
            &format!("{what} pristine"),
            code,
            &env,
            &doc,
            &flavor.purl(),
            "not_applied",
        );

        write_ledger(&p, flavor, Mode::Hosted, &sha, record(HOSTED_UUID));
        let (code, env, doc) = vex_offline(&p, &api, &[]);
        assert_omitted(
            &format!("{what} pristine + ledger"),
            code,
            &env,
            &doc,
            &flavor.purl(),
            "not_applied",
        );
        p.install(flavor.version(), PATCHED);
        let (code, env, doc) = vex_offline(&p, &api, &[]);
        assert_attested(
            &format!("{what} + ledger"),
            code,
            &env,
            &doc,
            &flavor.api_purl(),
            HOSTED_UUID,
            Mode::Hosted,
        );
    }
}

/// Every pypi hosted writer pins the patched wheel's sha256; an entry
/// without the pin was not written by socket-patch, so it cannot attest
/// from the lockfile alone (`package_not_found` until installed) — only a
/// verifying installed tree can.
#[test]
fn pinless_hosted_entry_needs_an_installed_tree() {
    for flavor in [
        Flavor::UvProject,
        Flavor::UvLockOnly,
        Flavor::Script,
        Flavor::Pylock,
        Flavor::PipLock,
    ] {
        let what = format!("{} pin-less", flavor.label());
        let p = Proj::new();
        let sha = wire(&p, flavor, Mode::Hosted, PATCHED);
        let lock = p.read(flavor.lock_file());
        let stripped = lock
            .replace(&format!(", hash = \"sha256:{sha}\""), "")
            .replace(&format!(", hashes = {{ sha256 = \"{sha}\" }}"), "");
        assert_ne!(stripped, lock, "{what}: the pin was stripped");
        assert!(!stripped.contains(&sha), "{what}: {stripped}");
        p.write(flavor.lock_file(), &stripped);
        let api = Api::start();
        api.serve_view(HOSTED_UUID, view(HOSTED_UUID, &flavor.api_purl()));
        let (code, env, doc) = vex_online(&p, &api, &[]);
        assert_omitted(&what, code, &env, &doc, &flavor.purl(), "package_not_found");
        p.install(flavor.version(), PATCHED);
        let (code, env, doc) = vex_online(&p, &api, &[]);
        assert_attested(
            &what,
            code,
            &env,
            &doc,
            &flavor.api_purl(),
            HOSTED_UUID,
            Mode::Hosted,
        );
    }
}

// ════════════════════════════════════════════════════════════════════════
// Writer-driven: the REAL `scan --redirect --vex` / `scan --vendor --vex`
// write the wiring and the ledgers; then the manifest (and the ledgers) are
// deleted and standalone `vex` must still attest — and stop attesting once
// the real revert unwinds the wiring with the ledger left behind.
// ════════════════════════════════════════════════════════════════════════

impl Api {
    /// The authenticated discovery + fetch routes `scan` uses for one pypi
    /// patch: batch discovery (base purl → the qualified record purl), the
    /// per-package search, the hosted grant (`artifact_url` pinned to
    /// `sha256`), the authenticated view with inline blob content, plus the
    /// public-proxy view `vex` falls back to and the hosted wheel itself
    /// (`scan --redirect` reads a uv lock's wheel METADATA from it).
    fn serve_scan_routes(
        &self,
        flavor: Flavor,
        uuid: &str,
        artifact_url: &str,
        wheel: Vec<u8>,
    ) -> &Self {
        use base64::Engine as _;
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        let purl = flavor.purl();
        let qualified = flavor.api_purl();
        let sha = sha256_hex(&wheel);
        let mut full_view = view(uuid, &qualified);
        full_view["files"][MODULE]["blobContent"] =
            Value::String(base64::engine::general_purpose::STANDARD.encode(PATCHED));
        let artifact_path = artifact_url.strip_prefix(&self.uri()).map(str::to_string);
        self.rt.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "packages": [{
                        "purl": purl,
                        "patches": [{
                            "uuid": uuid, "purl": qualified, "tier": "free",
                            "cveIds": [CVE], "ghsaIds": [GHSA], "severity": "HIGH",
                            "title": "vexfixture patch"
                        }]
                    }],
                    "canAccessPaidPatches": false,
                })))
                .mount(&self.server)
                .await;
            Mock::given(method("GET"))
                .and(path_regex(format!(
                    "^/v0/orgs/{ORG}/patches/by-package/.+$"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "patches": [{
                        "uuid": uuid, "purl": qualified,
                        "publishedAt": "2026-09-01T00:00:00Z",
                        "description": "vexfixture patch", "license": "MIT", "tier": "free",
                        "vulnerabilities": {}
                    }],
                    "canAccessPaidPatches": false,
                })))
                .mount(&self.server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": { uuid: {
                        "status": "granted",
                        "url": artifact_url,
                        "purl": purl,
                        "artifacts": [{
                            "kind": "tarball",
                            "url": artifact_url,
                            "integrity": { "sha256": sha }
                        }],
                        "registryOverride": null
                    } }
                })))
                .mount(&self.server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(full_view))
                .mount(&self.server)
                .await;
            if let Some(artifact_path) = artifact_path {
                Mock::given(method("GET"))
                    .and(path(artifact_path))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel))
                    .mount(&self.server)
                    .await;
            }
        });
        self.serve_view(uuid, view(uuid, &qualified))
    }
}

/// Run an authenticated `socket-patch <args> --json --yes` in `p` against
/// `api` → (exit, envelope).
fn run_authed(p: &Proj, api: &Api, args: &[&str]) -> (Option<i32>, Value) {
    let uri = api.uri();
    let out = cli(p)
        .current_dir(&p.root)
        .args(args)
        .args([
            "--json",
            "--yes",
            "--cwd",
            p.root.to_str().unwrap(),
            "--api-url",
            &uri,
            "--api-token",
            "fake-token",
            "--org",
            ORG,
        ])
        .output()
        .expect("invoke socket-patch");
    let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?}: envelope JSON on stdout ({e}). stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code(), env)
}

/// The embedded `--vex` document `scan` wrote, with its one statement
/// asserted.
fn assert_embedded_doc(what: &str, path: &Path, uuid: &str, mode: Mode) {
    let doc: Value = serde_json::from_slice(
        &std::fs::read(path).unwrap_or_else(|e| panic!("{what}: embedded VEX doc: {e}")),
    )
    .unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "{what}: {doc}");
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA, "{what}");
    assert_eq!(
        stmts[0]["impact_statement"],
        format!("Patched via Socket patch {uuid} ({})", marker(mode)),
        "{what}"
    );
}

/// Every flavor the writers produce from a registry checkout.
fn writer_flavors() -> Vec<Flavor> {
    flavors(Mode::Hosted)
}

/// `scan --redirect --vex` on a lock-only checkout (nothing installed; an
/// empty in-project venv keeps the crawl off the host interpreters) writes
/// the hosted wiring + the redirect ledger and attests in-run; afterwards,
/// with no manifest:
///   c. the ledger alone attests offline;
///   b. without the ledger, offline is `record_unavailable` with no request;
///   a. without the ledger, online (public-proxy view) attests;
///   d. `rollback` unwinds the wiring; with the ledger put back, it is dead.
///
/// uv locks are wired to the mock's origin (the writer fetches the hosted
/// wheel's METADATA for them), so `vex` is told that origin is the patch
/// server; script locks / pylock are wired to production `patch.socket.dev` urls
/// (nothing is fetched from them).
#[test]
fn scan_redirect_wiring_attests_without_manifest_or_ledger() {
    for flavor in writer_flavors() {
        let what = format!("{} scan --redirect", flavor.label());
        let p = Proj::new();
        p.write_files(&flavor.native_files());
        std::fs::create_dir_all(p.site()).unwrap();
        let api = Api::start();
        // uv locks (project + script) are wired to the mock's origin: the
        // writer fetches the hosted wheel's METADATA for them.
        let uv = matches!(
            flavor,
            Flavor::UvProject | Flavor::UvLockOnly | Flavor::Script
        );
        let artifact_url = if uv {
            hosted_url_on(&api.uri(), flavor, HOSTED_UUID)
        } else {
            flavor.hosted_url(HOSTED_UUID)
        };
        let wheel = build_wheel(flavor.version(), PATCHED);
        api.serve_scan_routes(flavor, HOSTED_UUID, &artifact_url, wheel);
        let embedded = p.root.join("embedded.vex.json");
        let (code, env) = run_authed(
            &p,
            &api,
            &[
                "scan",
                "--redirect",
                "--vex",
                embedded.to_str().unwrap(),
                "--vex-product",
                PRODUCT,
            ],
        );
        assert_eq!(code, Some(0), "{what}: {env}");
        let lock = p.read(flavor.lock_file());
        assert!(
            lock.contains(&artifact_url),
            "{what}: lock not wired:\n{lock}"
        );
        assert!(p.exists(".socket/vendor/redirect-state.json"), "{what}");
        assert!(
            !p.exists(".socket/manifest.json"),
            "{what}: hosted writes no manifest"
        );
        assert_embedded_doc(&what, &embedded, HOSTED_UUID, Mode::Hosted);

        let server_origin = api.uri();
        let origin: Vec<&str> = if uv {
            vec!["--patch-server-url", server_origin.as_str()]
        } else {
            Vec::new()
        };

        // c. the writer's ledger attests offline.
        let before = api.requests();
        let (code, env, doc) = vex_offline(&p, &api, &origin);
        assert_attested(
            &format!("{what} ledger"),
            code,
            &env,
            &doc,
            &flavor.api_purl(),
            HOSTED_UUID,
            Mode::Hosted,
        );
        assert_eq!(api.requests(), before, "{what}: offline made a request");

        // b / a. no ledger.
        let ledger_path = p.root.join(".socket/vendor/redirect-state.json");
        let ledger = std::fs::read(&ledger_path).unwrap();
        std::fs::remove_file(&ledger_path).unwrap();
        let (code, env, doc) = vex_offline(&p, &api, &origin);
        assert_omitted(
            &format!("{what} no ledger offline"),
            code,
            &env,
            &doc,
            &flavor.purl(),
            "record_unavailable",
        );
        assert_eq!(api.requests(), before, "{what}: offline made a request");
        let (code, env, doc) = vex_online(&p, &api, &origin);
        assert_attested(
            &format!("{what} no ledger online"),
            code,
            &env,
            &doc,
            &flavor.api_purl(),
            HOSTED_UUID,
            Mode::Hosted,
        );
        assert_no_manifest_written(&p, &what);

        // d. the real revert, then the ledger restored behind its back.
        std::fs::write(&ledger_path, &ledger).unwrap();
        let (code, env) = run_authed(&p, &api, &["rollback"]);
        assert_eq!(code, Some(0), "{what} rollback: {env}");
        for (name, text) in flavor.native_files() {
            assert_eq!(p.read(name), text, "{what}: rollback restores {name}");
        }
        // A fully reverted project keeps no `.socket/` at all: recreate the
        // directory the stale ledger is planted back into.
        std::fs::create_dir_all(ledger_path.parent().unwrap()).unwrap();
        std::fs::write(&ledger_path, &ledger).unwrap();
        for extra in [&[][..], &["--no-verify"][..]] {
            let mut args = origin.clone();
            args.extend_from_slice(extra);
            let (code, env, doc) = vex_offline(&p, &api, &args);
            assert_omitted(
                &format!("{what} reverted {extra:?}"),
                code,
                &env,
                &doc,
                &flavor.purl(),
                "redirect_unwired",
            );
        }
    }
}

/// `scan --vendor --vex --vendor-source build` over the installed (pristine)
/// dist rebuilds the patched wheel into `.socket/vendor/pypi/<uuid>/`, wires
/// the lock, writes the ledger (never a manifest: vendored mode is
/// manifest-free) and attests in-run. A legacy manifest seeded beside the
/// ledger attests the same way; then, with no manifest:
///   c. the vendor ledger alone attests offline;
///   b. without the ledger, offline is `record_unavailable`, no request;
///   a. without the ledger, online attests (the committed wheel is hashed);
///   d. `vendor --revert` unwinds the wiring; with the ledger put back (and
///      the artifact re-committed) it is `vendor_unwired`.
/// The `--detached` twin (a hidden compatibility no-op) behaves the same.
#[test]
fn scan_vendor_wiring_attests_without_manifest_or_ledger() {
    for detached in [false, true] {
        for flavor in writer_flavors() {
            if matches!(flavor, Flavor::UvLockOnly) {
                // uv vendoring always edits the pyproject/lock pair.
                continue;
            }
            let what = format!(
                "{} scan --vendor{}",
                flavor.label(),
                if detached { " --detached" } else { "" }
            );
            let p = Proj::new();
            p.write_files(&flavor.native_files());
            p.install(flavor.version(), PRISTINE);
            let api = Api::start();
            api.serve_scan_routes(
                flavor,
                VENDORED_UUID,
                &flavor.hosted_url(VENDORED_UUID),
                build_wheel(flavor.version(), PATCHED),
            );
            let embedded = p.root.join("embedded.vex.json");
            let mut args = vec![
                "scan",
                "--vendor",
                "--vendor-source",
                "build",
                "--vex",
                embedded.to_str().unwrap(),
                "--vex-product",
                PRODUCT,
            ];
            if detached {
                args.push("--detached");
            }
            let (code, env) = run_authed(&p, &api, &args);
            assert_eq!(code, Some(0), "{what}: {env}");
            assert_embedded_doc(&what, &embedded, VENDORED_UUID, Mode::Vendored);
            let lock = p.read(flavor.lock_file());
            assert!(
                lock.contains(&format!(".socket/vendor/pypi/{VENDORED_UUID}/")),
                "{what}: lock not wired:\n{lock}"
            );
            assert!(
                !p.exists(".socket/manifest.json"),
                "{what}: vendored mode is manifest-free (--detached is a no-op)"
            );
            // The installed tree stays pristine: vendoring never patches it.
            assert_eq!(std::fs::read(p.site().join(MODULE)).unwrap(), PRISTINE);
            // A legacy (pre-5.0) checkout also carries the manifest record
            // beside the ledger: same uuid, so it attests the same way.
            assert!(vex_e2e_common::seed_legacy_manifest(&p.root) > 0, "{what}");
            let (code, env, doc) = vex_offline(&p, &api, &[]);
            assert_attested(
                &format!("{what} legacy manifest"),
                code,
                &env,
                &doc,
                &flavor.api_purl(),
                VENDORED_UUID,
                Mode::Vendored,
            );
            vex_e2e_common::strip_manifest(&p.root);

            // c. the ledger alone.
            let before = api.requests();
            let (code, env, doc) = vex_offline(&p, &api, &[]);
            assert_attested(
                &format!("{what} ledger"),
                code,
                &env,
                &doc,
                &flavor.api_purl(),
                VENDORED_UUID,
                Mode::Vendored,
            );
            assert_eq!(api.requests(), before, "{what}: offline made a request");

            // b / a. no ledger.
            let ledger_path = p.root.join(".socket/vendor/state.json");
            let ledger = std::fs::read(&ledger_path).unwrap();
            std::fs::remove_file(&ledger_path).unwrap();
            let (code, env, doc) = vex_offline(&p, &api, &[]);
            assert_omitted(
                &format!("{what} no ledger offline"),
                code,
                &env,
                &doc,
                &flavor.purl(),
                "record_unavailable",
            );
            assert_eq!(api.requests(), before, "{what}: offline made a request");
            let (code, env, doc) = vex_online(&p, &api, &[]);
            assert_attested(
                &format!("{what} no ledger online"),
                code,
                &env,
                &doc,
                &flavor.api_purl(),
                VENDORED_UUID,
                Mode::Vendored,
            );
            assert_no_manifest_written(&p, &what);

            // d. the real revert, then the ledger + artifact put back.
            std::fs::write(&ledger_path, &ledger).unwrap();
            let artifact_dir = p.root.join(format!(".socket/vendor/pypi/{VENDORED_UUID}"));
            let artifacts: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(&artifact_dir)
                .unwrap()
                .flatten()
                .map(|e| (e.path(), std::fs::read(e.path()).unwrap()))
                .collect();
            let (code, env) = run_authed(&p, &api, &["vendor", "--revert"]);
            assert_eq!(code, Some(0), "{what} revert: {env}");
            for (name, text) in flavor.native_files() {
                assert_eq!(p.read(name), text, "{what}: revert restores {name}");
            }
            std::fs::create_dir_all(&artifact_dir).unwrap();
            for (path, bytes) in &artifacts {
                std::fs::write(path, bytes).unwrap();
            }
            std::fs::write(&ledger_path, &ledger).unwrap();
            for extra in [&[][..], &["--no-verify"][..]] {
                let (code, env, doc) = vex_offline(&p, &api, extra);
                assert_omitted(
                    &format!("{what} reverted {extra:?}"),
                    code,
                    &env,
                    &doc,
                    &flavor.purl(),
                    "vendor_unwired",
                );
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════════════
// Embedded: `apply --vex` / `vendor --vex` in a manifest-less checkout
// ════════════════════════════════════════════════════════════════════════

/// Run `socket-patch <command> --json --offline --vex <doc>` (unauthenticated)
/// in `p` → (exit, envelope, the document when one was written).
fn embedded_vex(p: &Proj, command: &str, extra: &[&str]) -> (Option<i32>, Value, Option<Value>) {
    let doc_path = p.root.join("embedded.vex.json");
    let _ = std::fs::remove_file(&doc_path);
    let out = cli(p)
        .env("SOCKET_NO_API_TOKEN", "1")
        .args([
            command,
            "--json",
            "--offline",
            "--cwd",
            p.root.to_str().unwrap(),
            "--vex",
            doc_path.to_str().unwrap(),
            "--vex-product",
            PRODUCT,
        ])
        .args(extra)
        .output()
        .expect("invoke socket-patch");
    let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{command}: envelope JSON on stdout ({e}). stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let doc = std::fs::read(&doc_path)
        .ok()
        .map(|b| serde_json::from_slice(&b).expect("VEX document JSON"));
    (out.status.code(), env, doc)
}

/// REGRESSION (fixed on the feature branch, `generate_vex_without_manifest`):
/// `apply --vex` / `vendor --vex` in a manifest-less uv checkout used to
/// return `noManifest` / exit 0 BEFORE the embedded VEX ran, so the
/// requested document was silently never written. Every flavor × mode, with
/// the writer's ledger and fully offline: the document is written (exit 0,
/// envelope `vex` summary) with the right marker; `--dry-run` writes none;
/// the lock reverted with the ledger left behind fails the command (exit 1,
/// `no_applicable_patches`) and leaves no stale document; and a project with
/// NOTHING wired keeps the calm no-op.
#[test]
fn embedded_apply_and_vendor_vex_attest_manifest_less_checkouts() {
    for command in ["apply", "vendor"] {
        // Nothing anywhere: the calm no-op is unchanged.
        let p = Proj::new();
        p.write_files(&Flavor::UvProject.native_files());
        let (code, env, doc) = embedded_vex(&p, command, &[]);
        assert_eq!(code, Some(0), "{command} (nothing wired): {env}");
        assert_eq!(env["status"], "noManifest", "{command}: {env}");
        assert!(env.get("vex").is_none(), "{command}: {env}");
        assert!(doc.is_none(), "{command}: nothing to attest, no document");

        for mode in [Mode::Hosted, Mode::Vendored] {
            for flavor in flavors(mode) {
                let what = format!("{command} --vex {} {mode:?}", flavor.label());
                let p = Proj::new();
                let sha = wire(&p, flavor, mode, PATCHED);
                write_ledger(&p, flavor, mode, &sha, record(uuid_of(mode)));

                let (code, env, doc) = embedded_vex(&p, command, &["--dry-run"]);
                assert_eq!(code, Some(0), "{what} --dry-run: {env}");
                assert!(doc.is_none(), "{what}: a dry run writes no VEX document");

                let (code, env, doc) = embedded_vex(&p, command, &[]);
                assert_eq!(code, Some(0), "{what}: {env}");
                assert_eq!(env["status"], "noManifest", "{what}: {env}");
                assert_eq!(env["vex"]["statements"], 1, "{what}: {env}");
                let doc = doc.unwrap_or_else(|| panic!("{what}: no document"));
                assert_eq!(doc["statements"][0]["vulnerability"]["name"], GHSA);
                assert_eq!(
                    doc["statements"][0]["impact_statement"],
                    format!(
                        "Patched via Socket patch {} ({})",
                        uuid_of(mode),
                        marker(mode)
                    ),
                    "{what}"
                );
                assert_no_manifest_written(&p, &what);

                // The lock reverted with the ledger left behind.
                p.write_files(&flavor.native_files());
                let (code, env, doc) = embedded_vex(&p, command, &[]);
                assert_eq!(code, Some(1), "{what} (reverted): {env}");
                assert_eq!(
                    env["error"]["code"], "no_applicable_patches",
                    "{what}: {env}"
                );
                assert!(doc.is_none(), "{what}: a failed run leaves no VEX document");
            }
        }
    }
}
