//! Real-uv hosted / vendored flows that end in manifest-less VEX, shared by
//! `e2e_redirect_uv_build` (hosted) and `e2e_vendor_pypi_build` (vendored).
//!
//! Pull it in NEXT TO the generic helper and the cache sandbox:
//!
//! ```ignore
//! #[path = "common/cache_env.rs"]
//! mod cache_env;
//! #[path = "vex_e2e_common/mod.rs"]
//! mod vex_e2e_common;
//! #[path = "vex_e2e_common/uv.rs"]
//! mod uv_vex;
//! ```
//!
//! # Which uv
//!
//! uv is pre-1.0, so every `0.N` line is a major. The binary under test is
//! chosen the way the bun suites choose theirs:
//!
//! * `SOCKET_PATCH_UV_E2E_BIN` — the uv executable (default: `uv` on PATH,
//!   then `~/.local/bin/uv`);
//! * `SOCKET_PATCH_UV_E2E_VERSION` — the release it must report (`uv
//!   --version`); a mismatch is a skip, or a failure under REQUIRED;
//! * `SOCKET_PATCH_UV_E2E_PYTHON` — the interpreter passed as `--python` (old
//!   uv releases cannot drive the newest CPython);
//! * `SOCKET_PATCH_UV_E2E_REQUIRED=1` — every "tool missing / PyPI
//!   unreachable" soft skip becomes a hard failure, so a CI leg cannot pass
//!   on an unexercised toolchain. Lanes a release genuinely lacks (no `uv
//!   lock --script` before 0.5.17, no pylock install before 0.7, …) are
//!   reported `n/a` either way.
//!
//! `scripts/uv-vex-matrix.sh` loops every `0.N` line (plus the 0.5.6
//! override / constraints boundary) through both suites.
//!
//! # A lane
//!
//! [`run_lane`] drives one `(mode, lane)` flow end to end with the REAL uv:
//!
//! 1. build the project with uv from PyPI (`uv lock` + `uv sync`, `uv lock
//!    --script`, `uv export --format pylock.toml`, `uv pip compile -o
//!    pylock.toml` or `pip lock`) and install the PRISTINE package;
//! 2. produce the committed state with our CLI — hosted: `scan --redirect
//!    --vex` against a wiremock patch API that also serves the patched
//!    wheel; vendored: `vendor --offline --vex` over a staged manifest +
//!    blob — asserting the in-run document;
//! 3. copy ONLY the committable files into a fresh checkout, delete
//!    `.socket/manifest.json`, install with uv from an EMPTY cache (hosted:
//!    uv downloads the patched wheel from the mock and checks its pin;
//!    vendored: `--offline` where the release allows) and prove the PATCHED
//!    bytes are what Python imports;
//! 4. manifest-less VEX there: (a) standalone `vex` attests the purl with
//!    the right marker and vulnerability ids; (b) with both ledgers deleted
//!    it still attests from lockfile discovery + the API record; (c)
//!    `--offline` without ledgers is `record_unavailable` with ZERO requests;
//!    (d) the embedded `apply --vex` (+ `vendor --vex` / `scan --redirect
//!    --vex`) attest too; (e) the wiring reverted to the registry files with
//!    the ledgers and artifacts left behind, reinstalled pristine by uv, is
//!    NOT attested — verified or `--no-verify`, online or offline;
//! 5. the lanes with project metadata also run a plain (re-resolving) `uv
//!    sync` — for a transitive target this is the 0.5.6 boundary: older uv
//!    re-resolves the override against the registry, reinstalls the
//!    pristine wheel and rewrites the lock, and VEX must follow it;
//! 6. the real revert (`rollback` / `vendor --revert`) restores every wiring
//!    file byte for byte.
//!
//! Every step prints one `UV-VEX uv=<ver> mode=<m> lane=<l> step=<s>
//! result=<r>` line, which the matrix script tabulates.

#![allow(dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::vex_e2e_common::{
    assert_attested, assert_not_attested, binary, git_sha256, patch_view, run_vex, statements_for,
    strip_ledgers, strip_manifest, Marker, PatchApi, VexOutcome, VexRun, VexVia,
};

/// Appended to the installed module by the synthetic patch.
pub const PATCH_SUFFIX: &str = "\n# SOCKET-PATCHED\nSOCKET_PATCHED = 1\n";
pub const ORG: &str = "test-org";
pub const GHSA: &str = "GHSA-uvbu-ildv-ex01";
pub const CVE: &str = "CVE-2026-7101";
/// A uuid-SHAPED grant token in front of the patch uuid (production shape).
pub const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
pub const PRODUCT: &str = "pkg:pypi/app@1.0.0";
pub const HOSTED_UUID: &str = "6e7f8091-a2b3-4c4d-8e5f-60718293a4b5";
pub const VENDORED_UUID: &str = "7f8091a2-b3c4-4d5e-9f60-718293a4b5c6";
const SCRIPT: &str = "tool.py";
/// Prints `1` iff the patched `six` is the one imported.
const ORACLE: &str = "import six; print(getattr(six, 'SOCKET_PATCHED', 0))";

// ── the uv under test ──────────────────────────────────────────────────

/// `SOCKET_PATCH_UV_E2E_REQUIRED` is set: skips are failures.
pub fn required() -> bool {
    std::env::var("SOCKET_PATCH_UV_E2E_REQUIRED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Report a soft skip: a panic under [`required`], else a `SKIP` line.
pub fn skip(suite: &str, why: &str) {
    if required() {
        panic!(
            "SOCKET_PATCH_UV_E2E_REQUIRED: {suite} cannot run: {why}\n\
             A required leg must never pass on an unexercised uv."
        );
    }
    println!("SKIP {suite}: {why}");
}

/// The uv binary a suite drives.
pub struct Uv {
    pub exe: PathBuf,
    /// `uv --version`'s release (`0.5.6`).
    pub version: String,
    parts: (u64, u64, u64),
    /// `--python` for the project-level commands.
    pub python: Option<PathBuf>,
}

/// Resolve the uv under test (see the module docs). `Err` is a skip reason.
pub fn uv_under_test() -> Result<Uv, String> {
    let exe = match std::env::var_os("SOCKET_PATCH_UV_E2E_BIN") {
        Some(bin) => PathBuf::from(bin),
        None => {
            let on_path = Command::new("uv")
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success());
            if on_path {
                PathBuf::from("uv")
            } else {
                let home = std::env::var_os("HOME").ok_or("`uv` not on PATH")?;
                let candidate = Path::new(&home).join(".local/bin/uv");
                if !candidate.is_file() {
                    return Err("`uv` not on PATH or at ~/.local/bin/uv".into());
                }
                candidate
            }
        }
    };
    let out = Command::new(&exe)
        .arg("--version")
        .output()
        .map_err(|e| format!("{}: {e}", exe.display()))?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let version = text
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("unparseable `uv --version`: {text:?}"))?
        .to_string();
    let mut nums = version.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    let parts = (
        nums.next().unwrap_or(0),
        nums.next().unwrap_or(0),
        nums.next().unwrap_or(0),
    );
    if let Ok(want) = std::env::var("SOCKET_PATCH_UV_E2E_VERSION") {
        if !want.is_empty() && want != version {
            return Err(format!(
                "{} is uv {version}, SOCKET_PATCH_UV_E2E_VERSION wants {want}",
                exe.display()
            ));
        }
    }
    let python = std::env::var_os("SOCKET_PATCH_UV_E2E_PYTHON")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from);
    Ok(Uv {
        exe,
        version,
        parts,
        python,
    })
}

impl Uv {
    pub fn at_least(&self, v: (u64, u64, u64)) -> bool {
        self.parts >= v
    }

    /// A uv child with the ambient python / uv / pip environment scrubbed
    /// (`UV_PROJECT_ENVIRONMENT` moves the venv, `PYTHONPATH` shadows the
    /// oracle), the cache sandbox applied, then `cache` as `UV_CACHE_DIR`.
    fn command(&self, cwd: &Path, args: &[OsString], cache: &Path) -> Command {
        let mut cmd = Command::new(&self.exe);
        scrub_python_env(&mut cmd);
        cmd.args(args).current_dir(cwd);
        crate::cache_env::isolate(&mut cmd);
        cmd.env("UV_CACHE_DIR", cache);
        cmd
    }

    pub fn run(&self, cwd: &Path, args: &[&str], cache: &Path) -> Output {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        self.command(cwd, &args, cache)
            .output()
            .unwrap_or_else(|e| panic!("spawning {}: {e}", self.exe.display()))
    }

    /// `args` plus `--python <interpreter>` when one is configured.
    pub fn run_py(&self, cwd: &Path, args: &[&str], cache: &Path) -> Output {
        let mut all: Vec<OsString> = args.iter().map(OsString::from).collect();
        if let Some(py) = &self.python {
            all.push("--python".into());
            all.push(py.into());
        }
        self.command(cwd, &all, cache)
            .output()
            .unwrap_or_else(|e| panic!("spawning {}: {e}", self.exe.display()))
    }

    /// Whether `uv <sub> --help` documents `needle`.
    pub fn help_has(&self, sub: &[&str], needle: &str) -> bool {
        let mut args = sub.to_vec();
        args.push("--help");
        let out = Command::new(&self.exe).args(&args).output();
        out.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains(needle))
    }
}

fn scrub_python_env(cmd: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("PYTHON")
            || name.starts_with("UV_")
            || name.starts_with("PIP_")
            || name.starts_with("SOCKET_")
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
}

pub fn ok(out: &Output) -> bool {
    out.status.success()
}

pub fn dump(out: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ── lanes ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Hosted,
    Vendored,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Hosted => "hosted",
            Mode::Vendored => "vendored",
        }
    }
    fn marker(self) -> Marker {
        match self {
            Mode::Hosted => Marker::Redirected,
            Mode::Vendored => Marker::Vendored,
        }
    }
    fn uuid(self) -> &'static str {
        match self {
            Mode::Hosted => HOSTED_UUID,
            Mode::Vendored => VENDORED_UUID,
        }
    }
    fn unwired(self) -> &'static str {
        match self {
            Mode::Hosted => "redirect_unwired",
            Mode::Vendored => "vendor_unwired",
        }
    }
}

/// One uv-produced lock shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// `pyproject.toml` + `uv.lock` pinning `six==1.16.0` directly.
    Project,
    /// `six` direct AND in `[tool.uv] constraint-dependencies`: the writers
    /// repoint the lock's `[manifest] constraints` entry too (the 0.5.6
    /// constraints boundary: older uv rejects it under `--locked`).
    Constraints,
    /// `six` only as `python-dateutil`'s dependency: wired through `[tool.uv]
    /// override-dependencies` + `[tool.uv.sources]` (the 0.5.6 boundary).
    Transitive,
    /// PEP 723 `tool.py` + `uv lock --script` → `tool.py.lock`.
    Script,
    /// `uv export --format pylock.toml` (a pylock-only consumer checkout).
    ExportPylock,
    /// `uv pip compile requirements.in -o pylock.toml`.
    CompilePylock,
    /// `pip lock` (pip ≥ 25.1), installed with the uv under test.
    PipLock,
}

impl Lane {
    pub const ALL: [Lane; 7] = [
        Lane::Project,
        Lane::Constraints,
        Lane::Transitive,
        Lane::Script,
        Lane::ExportPylock,
        Lane::CompilePylock,
        Lane::PipLock,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Lane::Project => "project",
            Lane::Constraints => "constraints",
            Lane::Transitive => "transitive",
            Lane::Script => "script",
            Lane::ExportPylock => "export-pylock",
            Lane::CompilePylock => "compile-pylock",
            Lane::PipLock => "pip-lock",
        }
    }

    /// The files the writers wire (and the fresh checkout commits).
    fn wiring(self) -> &'static [&'static str] {
        match self {
            Lane::Project | Lane::Constraints | Lane::Transitive => &["pyproject.toml", "uv.lock"],
            Lane::Script => &[SCRIPT, "tool.py.lock"],
            _ => &["pylock.toml"],
        }
    }

    /// The lock file among [`Self::wiring`].
    fn lock(self) -> &'static str {
        match self {
            Lane::Project | Lane::Constraints | Lane::Transitive => "uv.lock",
            Lane::Script => "tool.py.lock",
            _ => "pylock.toml",
        }
    }

    /// A `pyproject.toml` + `uv.lock` project lane.
    fn has_project(self) -> bool {
        matches!(self, Lane::Project | Lane::Constraints | Lane::Transitive)
    }

    /// `Err(why)` when this uv release has no such flow (reported `n/a`).
    fn available(self, uv: &Uv, mode: Mode) -> Result<(), String> {
        let pylock_install = || {
            if uv.help_has(&["pip", "sync"], "pylock") {
                Ok(())
            } else {
                Err("`uv pip sync` installs no pylock.toml before uv 0.7".to_string())
            }
        };
        match self {
            Lane::Project if mode == Mode::Vendored && !uv.at_least((0, 2, 35)) => {
                // Checked separately: the vendored writer must REFUSE the
                // `[[distribution]]` grammar (asserted in `run_lane`).
                Ok(())
            }
            Lane::Project => Ok(()),
            Lane::Constraints if !uv.at_least((0, 2, 37)) => {
                Err("no `[manifest] constraints` in uv.lock before uv 0.2.37".into())
            }
            Lane::Constraints => Ok(()),
            Lane::Transitive if !uv.at_least((0, 2, 35)) => {
                Err("no `[tool.uv] override-dependencies` + sources before uv 0.2.35".into())
            }
            Lane::Transitive => Ok(()),
            Lane::Script if !uv.help_has(&["lock"], "--script") => {
                Err("no `uv lock --script` before uv 0.5.17".into())
            }
            Lane::Script => Ok(()),
            Lane::ExportPylock => {
                if !uv.help_has(&["export"], "pylock") {
                    return Err("no `uv export --format pylock.toml` before uv 0.6.15".into());
                }
                pylock_install()
            }
            Lane::CompilePylock => {
                if !uv.help_has(&["pip", "compile"], "pylock") {
                    return Err("no PEP 751 `uv pip compile` before uv 0.6.15".into());
                }
                pylock_install()
            }
            Lane::PipLock => {
                let pip = Command::new(host_python())
                    .args(["-m", "pip", "lock", "--help"])
                    .output();
                if !pip.is_ok_and(|o| o.status.success()) {
                    return Err("host `python3 -m pip` has no `pip lock` (pip < 25.1)".into());
                }
                pylock_install()
            }
        }
    }
}

/// The interpreter `pip lock` runs under (the host's `python3`).
fn host_python() -> PathBuf {
    std::env::var_os("SOCKET_PATCH_UV_E2E_PIP_PYTHON")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("python3"))
}

// ── results ────────────────────────────────────────────────────────────

/// Collects one lane's `UV-VEX` result lines.
struct Report<'a> {
    uv: &'a Uv,
    mode: Mode,
    lane: Lane,
}

impl Report<'_> {
    fn row(&self, step: &str, result: &str) {
        let line = format!(
            "UV-VEX uv={} mode={} lane={} step={step} result={result}",
            self.uv.version,
            self.mode.name(),
            self.lane.name()
        );
        println!("{line}");
    }

    fn what(&self, step: &str) -> String {
        format!(
            "uv {} {} {} [{step}]",
            self.uv.version,
            self.mode.name(),
            self.lane.name()
        )
    }
}

// ── filesystem ─────────────────────────────────────────────────────────

pub fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// `<venv>/lib/python3.X/site-packages` (or `Lib/site-packages`).
pub fn site_packages(venv: &Path) -> Option<PathBuf> {
    if cfg!(windows) {
        let p = venv.join("Lib/site-packages");
        return p.is_dir().then_some(p);
    }
    std::fs::read_dir(venv.join("lib"))
        .ok()?
        .flatten()
        .map(|e| e.path().join("site-packages"))
        .find(|p| p.is_dir())
}

fn venv_python(dir: &Path) -> PathBuf {
    if cfg!(windows) {
        dir.join(".venv/Scripts/python.exe")
    } else {
        dir.join(".venv/bin/python")
    }
}

/// `six`'s installed version (its dist-info directory name).
fn installed_six_version(site: &Path) -> Option<String> {
    std::fs::read_dir(site).ok()?.flatten().find_map(|e| {
        let name = e.file_name().to_string_lossy().to_string();
        name.strip_prefix("six-")
            .and_then(|rest| rest.strip_suffix(".dist-info"))
            .map(str::to_string)
    })
}

/// Rebuild the installed `six` distribution as a wheel whose `six.py` is
/// `module` — the patched wheel the hosted mock serves. Members are the
/// installed RECORD's files minus installer bookkeeping; RECORD is
/// regenerated. Returns (filename, bytes).
fn wheel_from_installed(site: &Path, version: &str, module: &[u8]) -> (String, Vec<u8>) {
    use base64::Engine as _;
    use std::io::Write as _;
    let dist = format!("six-{version}.dist-info");
    let record = std::fs::read_to_string(site.join(&dist).join("RECORD")).expect("six RECORD");
    let skip = [
        "INSTALLER",
        "REQUESTED",
        "direct_url.json",
        "uv_cache.json",
        "RECORD",
    ];
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    for line in record.lines() {
        let rel = line.split(',').next().unwrap_or_default();
        if rel.is_empty()
            || rel.contains("__pycache__")
            || rel.starts_with("..")
            || skip.iter().any(|s| rel == format!("{dist}/{s}"))
        {
            continue;
        }
        let bytes = if rel == "six.py" {
            module.to_vec()
        } else {
            std::fs::read(site.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
        };
        members.push((rel.to_string(), bytes));
    }
    let mut new_record = String::new();
    for (rel, bytes) in &members {
        let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
        new_record.push_str(&format!("{rel},sha256={digest},{}\n", bytes.len()));
    }
    new_record.push_str(&format!("{dist}/RECORD,,\n"));
    members.push((format!("{dist}/RECORD"), new_record.into_bytes()));
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (rel, bytes) in &members {
            zip.start_file(rel.as_str(), opts).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
    }
    (
        format!("six-{version}-py2.py3-none-any.whl"),
        buf.into_inner(),
    )
}

// ── the scan-side mock (hosted) ────────────────────────────────────────

/// The authenticated routes `scan --redirect` uses for one pypi patch, plus
/// the patched wheel itself at its hosted url.
pub struct ScanApi {
    server: wiremock::MockServer,
    rt: tokio::runtime::Runtime,
}

impl ScanApi {
    fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(wiremock::MockServer::start());
        ScanApi { server, rt }
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    fn mount(&self, purl: &str, uuid: &str, artifact_url: &str, wheel: Vec<u8>, view: Value) {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        let sha = hex::encode(Sha256::digest(&wheel));
        let artifact_path = artifact_url
            .strip_prefix(&self.uri())
            .expect("artifact on the mock")
            .to_string();
        self.rt.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "packages": [{ "purl": purl, "patches": [{
                        "uuid": uuid, "purl": purl, "tier": "free",
                        "cveIds": [CVE], "ghsaIds": [GHSA], "severity": "HIGH",
                        "title": "uv capstone patch"
                    }] }],
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
                        "uuid": uuid, "purl": purl, "publishedAt": "2026-09-01T00:00:00Z",
                        "description": "uv capstone patch", "license": "MIT", "tier": "free",
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
                        "status": "granted", "url": artifact_url, "purl": purl,
                        "artifacts": [{ "kind": "tarball", "url": artifact_url,
                                        "integrity": { "sha256": sha } }],
                        "registryOverride": null
                    } }
                })))
                .mount(&self.server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(view))
                .mount(&self.server)
                .await;
            Mock::given(method("GET"))
                .and(path(artifact_path))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel))
                .mount(&self.server)
                .await;
        });
    }

    /// Requests for the hosted wheel (a real install fetched it).
    fn wheel_fetches(&self, leaf: &str) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path().ends_with(leaf))
            .count()
    }
}

/// Run `socket-patch <args>` with the ambient `SOCKET_*` / python env
/// scrubbed.
fn socket_patch(cwd: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(binary());
    scrub_python_env(&mut cmd);
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn socket-patch")
}

fn envelope(out: &Output, what: &str) -> Value {
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{what}: --json output is not JSON ({e}):\n{}", dump(out)))
}

// ── one lane ───────────────────────────────────────────────────────────

/// Everything a lane's project setup produced.
struct Built {
    /// The project the CLI wires (has the pristine `.venv`).
    proj: PathBuf,
    /// Pre-patch bytes of every [`Lane::wiring`] file.
    registry: Vec<(String, Vec<u8>)>,
    purl: String,
    version: String,
    /// The installed (pristine) `six.py` bytes.
    orig: Vec<u8>,
    site: PathBuf,
}

/// Build the lane's project with the real uv (network: PyPI). `Err` is a
/// skip reason (PyPI unreachable, fixture command failed).
fn build(uv: &Uv, lane: Lane, tmp: &Path) -> Result<Built, String> {
    let proj = tmp.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let cache = tmp.join("uv-cache");
    let need = |out: Output, what: &str| -> Result<Output, String> {
        if ok(&out) {
            Ok(out)
        } else {
            Err(format!("fixture `{what}` failed:\n{}", dump(&out)))
        }
    };
    let project_deps = |deps: &str| {
        std::fs::write(
            proj.join("pyproject.toml"),
            format!(
                "[project]\nname = \"uv-vex-capstone\"\nversion = \"0.1.0\"\n\
                 requires-python = \">=3.9\"\ndependencies = [{deps}]\n"
            ),
        )
        .unwrap();
    };
    let venv_install = |spec: &[&str]| -> Result<(), String> {
        need(uv.run_py(&proj, &["venv", ".venv"], &cache), "uv venv")?;
        let py = venv_python(&proj);
        let mut args = vec!["pip", "install", "--python", py.to_str().unwrap()];
        args.extend_from_slice(spec);
        need(uv.run(&proj, &args, &cache), "uv pip install")?;
        Ok(())
    };
    match lane {
        Lane::Project | Lane::Constraints | Lane::Transitive => {
            project_deps(match lane {
                Lane::Transitive => "\"python-dateutil==2.9.0.post0\"",
                _ => "\"six==1.16.0\"",
            });
            if lane == Lane::Constraints {
                let path = proj.join("pyproject.toml");
                let mut text = std::fs::read_to_string(&path).unwrap();
                text.push_str("\n[tool.uv]\nconstraint-dependencies = [\"six==1.16.0\"]\n");
                std::fs::write(&path, text).unwrap();
            }
            need(uv.run_py(&proj, &["lock"], &cache), "uv lock")?;
            let mut sync = vec!["sync"];
            no_install_project(uv, &proj, &mut sync);
            need(uv.run_py(&proj, &sync, &cache), "uv sync")?;
        }
        Lane::Script => {
            std::fs::write(
                proj.join(SCRIPT),
                format!(
                    "# /// script\n# requires-python = \">=3.9\"\n# dependencies = [\"six==1.16.0\"]\n\
                     # ///\n{ORACLE}\n"
                ),
            )
            .unwrap();
            need(
                uv.run_py(&proj, &["lock", "--script", SCRIPT], &cache),
                "uv lock --script",
            )?;
            // uv runs a script in a cache env the crawlers cannot see; the
            // developer's in-project venv holds the copy the writers read.
            venv_install(&["six==1.16.0"])?;
        }
        Lane::ExportPylock => {
            let src = tmp.join("export-src");
            std::fs::create_dir_all(&src).unwrap();
            std::fs::write(
                src.join("pyproject.toml"),
                "[project]\nname = \"uv-vex-capstone\"\nversion = \"0.1.0\"\n\
                 requires-python = \">=3.9\"\ndependencies = [\"six==1.16.0\"]\n",
            )
            .unwrap();
            need(uv.run_py(&src, &["lock"], &cache), "uv lock")?;
            let out = need(
                uv.run(
                    &src,
                    &["export", "--frozen", "--format", "pylock.toml"],
                    &cache,
                ),
                "uv export --format pylock.toml",
            )?;
            std::fs::write(proj.join("pylock.toml"), &out.stdout).unwrap();
            pylock_sync(uv, &proj, &cache)?;
        }
        Lane::CompilePylock => {
            std::fs::write(proj.join("requirements.in"), "six==1.16.0\n").unwrap();
            need(
                uv.run_py(
                    &proj,
                    &["pip", "compile", "requirements.in", "-o", "pylock.toml"],
                    &cache,
                ),
                "uv pip compile -o pylock.toml",
            )?;
            std::fs::remove_file(proj.join("requirements.in")).unwrap();
            pylock_sync(uv, &proj, &cache)?;
        }
        Lane::PipLock => {
            let mut cmd = Command::new(host_python());
            scrub_python_env(&mut cmd);
            crate::cache_env::isolate(&mut cmd);
            let out = cmd
                .args(["-m", "pip", "lock", "six==1.16.0", "-o", "pylock.toml"])
                .current_dir(&proj)
                .output()
                .expect("spawn pip lock");
            need(out, "pip lock")?;
            pylock_sync(uv, &proj, &cache)?;
        }
    }
    let lock = std::fs::read_to_string(proj.join(lane.lock())).unwrap();
    if lane.lock() == "pylock.toml" && !lock.contains("lock-version") {
        return Err(format!("{} wrote no PEP 751 lock:\n{lock}", lane.name()));
    }
    let site = site_packages(&proj.join(".venv")).ok_or("no site-packages in .venv")?;
    let version = installed_six_version(&site).ok_or("six is not installed in .venv")?;
    let orig = std::fs::read(site.join("six.py")).map_err(|e| format!("six.py: {e}"))?;
    assert!(
        !orig.ends_with(PATCH_SUFFIX.as_bytes()),
        "the pristine install already carries the marker"
    );
    let registry = lane
        .wiring()
        .iter()
        .map(|f| (f.to_string(), std::fs::read(proj.join(f)).unwrap()))
        .collect();
    Ok(Built {
        proj,
        registry,
        purl: format!("pkg:pypi/six@{version}"),
        version,
        orig,
        site,
    })
}

/// The `source = …` value of the lock's `six` `[[package]]` entry.
fn six_entry_source(lock: &str) -> String {
    let mut in_six = false;
    for line in lock.lines() {
        if line.starts_with("[[") {
            in_six = false;
        } else if line.trim() == "name = \"six\"" {
            in_six = true;
        } else if in_six {
            if let Some(source) = line.strip_prefix("source = ") {
                return source.trim().to_string();
            }
        }
    }
    String::new()
}

/// `--no-install-project` where the release has it; older releases build
/// and install the root project, so give it a package to build.
fn no_install_project(uv: &Uv, proj: &Path, args: &mut Vec<&str>) {
    if uv.help_has(&["sync"], "--no-install-project") {
        args.push("--no-install-project");
    } else {
        let pkg = proj.join("uv_vex_capstone");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(pkg.join("__init__.py"), "").unwrap();
    }
}

/// `uv venv` + `uv pip sync pylock.toml` in `dir`.
fn pylock_sync(uv: &Uv, dir: &Path, cache: &Path) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(dir.join(".venv"));
    let venv = uv.run_py(dir, &["venv", ".venv"], cache);
    if !ok(&venv) {
        return Err(format!("uv venv: {}", dump(&venv)));
    }
    let py = venv_python(dir);
    let sync = uv.run(
        dir,
        &[
            "pip",
            "sync",
            "--python",
            py.to_str().unwrap(),
            "pylock.toml",
        ],
        cache,
    );
    if ok(&sync) {
        Ok(())
    } else {
        Err(format!("uv pip sync pylock.toml: {}", dump(&sync)))
    }
}

/// Stage the vendored flow's manifest + blob (pypi keys are
/// site-packages-relative).
fn stage_manifest(proj: &Path, purl: &str, uuid: &str, orig: &[u8], patched: &[u8]) {
    let socket = proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = json!({ "patches": { purl: {
        "uuid": uuid,
        "exportedAt": "2026-09-01T00:00:00Z",
        "files": { "six.py": {
            "beforeHash": git_sha256(orig),
            "afterHash": git_sha256(patched),
        } },
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "uv capstone vex vuln", "severity": "high",
            "description": "d"
        } },
        "description": "uv capstone patch",
        "license": "MIT",
        "tier": "free",
    } } });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(patched)), patched).unwrap();
}

/// Install the committed `dir` with the uv under test from `cache`, the
/// way a CI checkout would; returns what the oracle printed (`1` =
/// patched, `0` = pristine). `offline` asks for `--offline` where the
/// release supports it for this lane.
fn install(uv: &Uv, lane: Lane, dir: &Path, cache: &Path, offline: bool, frozen: bool) -> String {
    let mut args: Vec<&str> = Vec::new();
    match lane {
        Lane::Project | Lane::Constraints | Lane::Transitive => {
            args.push("sync");
            if frozen && uv.help_has(&["sync"], "--frozen") {
                args.push("--frozen");
            }
            let before = uv.help_has(&["sync"], "--no-install-project");
            no_install_project(uv, dir, &mut args);
            // Without --no-install-project the root build needs setuptools
            // from the network even when every dependency is local.
            if offline && before && uv.help_has(&["sync"], "--offline") {
                args.push("--offline");
            }
            let out = uv.run_py(dir, &args, cache);
            assert!(
                ok(&out),
                "`uv {}` in {}:\n{}",
                args.join(" "),
                dir.display(),
                dump(&out)
            );
            oracle(uv, dir, cache)
        }
        Lane::Script => {
            // An EMPTY in-project venv keeps the crawlers off the host's
            // global interpreters; uv runs the script in its own env.
            if !dir.join(".venv").exists() {
                let venv = uv.run_py(dir, &["venv", ".venv"], cache);
                assert!(ok(&venv), "uv venv: {}", dump(&venv));
            }
            args.extend(["run"]);
            if frozen {
                args.push("--frozen");
            }
            if offline {
                args.push("--offline");
            }
            args.extend(["--script", SCRIPT]);
            let out = uv.run_py(dir, &args, cache);
            assert!(ok(&out), "`uv {}`:\n{}", args.join(" "), dump(&out));
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .last()
                .unwrap_or_default()
                .trim()
                .to_string()
        }
        _ => {
            let _ = std::fs::remove_dir_all(dir.join(".venv"));
            let venv = uv.run_py(dir, &["venv", ".venv"], cache);
            assert!(ok(&venv), "uv venv: {}", dump(&venv));
            let py = venv_python(dir);
            let mut args = vec!["pip", "sync", "--python", py.to_str().unwrap()];
            if offline {
                args.push("--offline");
            }
            args.push("pylock.toml");
            let out = uv.run(dir, &args, cache);
            assert!(ok(&out), "`uv {}`:\n{}", args.join(" "), dump(&out));
            oracle(uv, dir, cache)
        }
    }
}

fn oracle(_uv: &Uv, dir: &Path, _cache: &Path) -> String {
    let mut cmd = Command::new(venv_python(dir));
    scrub_python_env(&mut cmd);
    let out = cmd
        .args(["-c", ORACLE])
        .current_dir(dir)
        .output()
        .expect("spawn venv python");
    assert!(ok(&out), "oracle: {}", dump(&out));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn snapshot(dir: &Path, files: &[&str]) -> Vec<(String, Vec<u8>)> {
    files
        .iter()
        .filter_map(|f| std::fs::read(dir.join(f)).ok().map(|b| (f.to_string(), b)))
        .collect()
}

fn restore(dir: &Path, files: &[(String, Vec<u8>)]) {
    for (f, bytes) in files {
        let path = dir.join(f);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
}

/// One manifest-less VEX matrix over a fresh checkout that a real uv
/// install just proved patched (see the module docs, step 4).
pub struct Matrix<'a> {
    /// The fresh checkout: committed files only, manifest deleted, ledgers
    /// and artifacts present, installed patched.
    pub fresh: &'a Path,
    /// Base purl of the patched package.
    pub purl: &'a str,
    pub uuid: &'a str,
    pub mode: Mode,
    /// Exactly the vulnerability ids (+ aliases) the record lists.
    pub vulns: &'a [(&'a str, &'a [&'a str])],
    /// Serves the record's patch view (public-proxy + org routes).
    pub api: &'a PatchApi,
    /// `--patch-server-url` for a hosted mock origin (`None`: production).
    pub patch_server: Option<String>,
    /// Embedded entry points to run manifest-less (ledgers present).
    pub embedded: Vec<(&'a str, VexRun)>,
    /// Pre-patch bytes of the wiring files (the revert target).
    pub registry: &'a [(String, Vec<u8>)],
    /// Reinstall `dir` from its (reverted) files with the real package
    /// manager; returns the oracle (`0` = pristine).
    pub reinstall_registry: &'a dyn Fn(&Path) -> String,
}

/// Steps (a)–(e) of the module docs; `row(step, result)` reports each.
pub fn manifestless_matrix(m: &Matrix<'_>, row: &dyn Fn(&str, &str)) {
    let fresh = m.fresh;
    let marker = m.mode.marker();
    let vex = |run: VexRun| -> VexOutcome {
        let run = VexRun {
            patch_server_url: m.patch_server.clone(),
            product: Some(PRODUCT.to_string()),
            ..run
        };
        run_vex(&binary(), fresh, &run)
    };
    let attested = |out: &VexOutcome, step: &str| {
        assert_eq!(out.code, Some(0), "[{step}]:\n{out}");
        assert_attested(out.doc(), m.purl, m.uuid, marker, m.vulns);
        row(step, "attested");
    };
    assert!(
        !fresh.join(".socket/manifest.json").exists(),
        "the matrix runs manifest-less"
    );

    // (a) manifest deleted, ledgers kept.
    attested(&vex(VexRun::online(m.api)), "manifest-deleted");
    // (b) ledgers deleted too: lockfile discovery + the API record.
    let ledgers = snapshot(fresh, &LEDGERS);
    assert!(!ledgers.is_empty(), "the flow left no ledger");
    strip_ledgers(fresh);
    let before = m.api.view_requests(m.uuid);
    let out = vex(VexRun::online(m.api));
    attested(&out, "ledgers-deleted");
    assert!(
        m.api.view_requests(m.uuid) > before,
        "[ledgers-deleted]: the record was not fetched from the API"
    );
    // (c) offline without ledgers: nothing to attest from, zero network.
    let silent = PatchApi::empty();
    let out = vex(VexRun {
        proxy_url: Some(silent.uri()),
        ..VexRun::offline()
    });
    assert_eq!(out.code, Some(1), "[offline]:\n{out}");
    assert_not_attested(&out.envelope, m.purl, "record_unavailable");
    silent.assert_no_requests();
    row("offline", "record_unavailable (0 requests)");
    // (d) embedded entry points, manifest-less, ledgers back.
    restore(fresh, &ledgers);
    for (label, run) in &m.embedded {
        let out = vex(run.clone());
        assert_eq!(out.code, Some(0), "[{label}]:\n{out}");
        assert_attested(out.doc(), m.purl, m.uuid, marker, m.vulns);
        row(label, "attested");
        if run.via == VexVia::Scan && m.mode == Mode::Vendored {
            // `scan --mode vendored` is a WRITER: it records the vendored
            // patch in the manifest it (re)creates — the checkout goes back
            // to the manifest-less shape for the next steps.
            strip_manifest(fresh);
        }
        assert!(
            !fresh.join(".socket/manifest.json").exists(),
            "[{label}]: a manifest-less run wrote a manifest"
        );
    }
    // (e) wiring reverted to the registry, ledgers + artifacts kept,
    // reinstalled pristine by the real package manager.
    let wired = snapshot(
        fresh,
        &m.registry
            .iter()
            .map(|(f, _)| f.as_str())
            .collect::<Vec<_>>(),
    );
    restore(fresh, m.registry);
    let reinstalled = (m.reinstall_registry)(fresh);
    assert_eq!(
        reinstalled, "0",
        "[reverted]: the registry reinstall is patched"
    );
    for no_verify in [false, true] {
        for online in [false, true] {
            let run = if online {
                VexRun::online(m.api)
            } else {
                VexRun::offline()
            };
            let out = vex(VexRun { no_verify, ..run });
            let step = format!(
                "reverted{}{}",
                if no_verify { " --no-verify" } else { "" },
                if online { " online" } else { " offline" }
            );
            assert_eq!(out.code, Some(1), "[{step}]:\n{out}");
            assert_not_attested(&out.envelope, m.purl, m.mode.unwired());
        }
    }
    row(
        "reverted",
        &format!(
            "not attested ({}; verified + --no-verify)",
            m.mode.unwired()
        ),
    );
    restore(fresh, &wired);
}

const LEDGERS: [&str; 2] = [
    ".socket/vendor/state.json",
    ".socket/vendor/redirect-state.json",
];

/// Drive one `(mode, lane)` flow (see the module docs). Skips (or, under
/// REQUIRED, fails) when PyPI or a fixture command is unavailable; prints
/// `n/a` for flows the release lacks.
pub fn run_lane(suite: &str, uv: &Uv, mode: Mode, lane: Lane) {
    let report = Report { uv, mode, lane };
    if let Err(why) = lane.available(uv, mode) {
        report.row("all", &format!("n/a ({why})"));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let built = match build(uv, lane, tmp.path()) {
        Ok(b) => b,
        Err(why) => {
            skip(suite, &format!("{}: {why}", report.what("setup")));
            return;
        }
    };
    let uuid = mode.uuid();
    let patched: Vec<u8> = [built.orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    let proj = built.proj.clone();
    let embedded_doc = proj.join("embedded.vex.json");
    let vulns: &[(&str, &[&str])] = &[(GHSA, &[CVE])];

    // ── 2. produce the committed state ────────────────────────────────
    let mut scan_api: Option<ScanApi> = None;
    let mut wheel_leaf = String::new();
    match mode {
        Mode::Hosted => {
            let (leaf, wheel) = wheel_from_installed(&built.site, &built.version, &patched);
            let api = ScanApi::start();
            let artifact_url = format!(
                "{}/patch/pypi/six/{}/{TOKEN}/{uuid}/{leaf}",
                api.uri(),
                built.version
            );
            let mut view = patch_view(
                uuid,
                &built.purl,
                &[("six.py", &git_sha256(&patched))],
                vulns,
            );
            use base64::Engine as _;
            view["files"]["six.py"]["beforeHash"] = Value::String(git_sha256(&built.orig));
            view["files"]["six.py"]["blobContent"] =
                Value::String(base64::engine::general_purpose::STANDARD.encode(&patched));
            api.mount(&built.purl, uuid, &artifact_url, wheel, view);
            let uri = api.uri();
            let out = socket_patch(
                &proj,
                &[
                    "scan",
                    "--redirect",
                    "--json",
                    "--yes",
                    "--cwd",
                    proj.to_str().unwrap(),
                    "--api-url",
                    &uri,
                    "--api-token",
                    "fake-token",
                    "--org",
                    ORG,
                    "--vex",
                    embedded_doc.to_str().unwrap(),
                    "--vex-product",
                    PRODUCT,
                ],
            );
            let env = envelope(&out, &report.what("scan --redirect"));
            assert!(
                env["redirect"]["redirected"].as_u64().unwrap_or(0) >= 1,
                "{}: nothing redirected: {env:#}",
                report.what("scan --redirect")
            );
            // The in-run `--vex` judges the INSTALLED tree, which is still
            // the pristine wheel until uv reinstalls from the rewritten lock
            // ("installed evidence wins"): the redirect lands, the stale
            // install is reported, and nothing is attested (exit 1, no
            // document). The manifest-less matrix below re-runs `scan
            // --redirect --vex` over the reinstalled fresh checkout.
            assert_eq!(
                out.status.code(),
                Some(1),
                "{}: {env:#}",
                report.what("scan --redirect")
            );
            assert_eq!(
                env["error"]["code"],
                "no_applicable_patches",
                "{}: {env:#}",
                report.what("scan --redirect")
            );
            assert!(
                env.to_string().contains("redirect_pypi_stale_install"),
                "{}: the stale pristine install is not reported: {env:#}",
                report.what("scan --redirect")
            );
            assert!(
                !embedded_doc.exists(),
                "a failed in-run --vex wrote a document"
            );
            report.row(
                "in-run --vex (pristine installed)",
                "not attested (stale install)",
            );
            wheel_leaf = leaf;
            scan_api = Some(api);
        }
        Mode::Vendored => {
            stage_manifest(&proj, &built.purl, uuid, &built.orig, &patched);
            let out = socket_patch(
                &proj,
                &[
                    "vendor",
                    "--json",
                    "--offline",
                    "--cwd",
                    proj.to_str().unwrap(),
                    "--vex",
                    embedded_doc.to_str().unwrap(),
                    "--vex-product",
                    PRODUCT,
                ],
            );
            let env = envelope(&out, &report.what("vendor"));
            if lane == Lane::Project && !uv.at_least((0, 2, 35)) {
                // uv < 0.2.35 writes the experimental `[[distribution]]`
                // grammar, which cannot carry a portable local wheel: the
                // vendored writer refuses it (documented) and touches nothing.
                let text = env.to_string();
                assert!(
                    text.contains("pypi_uv_legacy_lock_unsupported"),
                    "{}: expected the legacy-grammar refusal: {env:#}",
                    report.what("vendor")
                );
                for (f, bytes) in &built.registry {
                    assert_eq!(&std::fs::read(proj.join(f)).unwrap(), bytes, "{f} touched");
                }
                report.row(
                    "all",
                    "refused (pypi_uv_legacy_lock_unsupported, documented)",
                );
                return;
            }
            assert_eq!(
                out.status.code(),
                Some(0),
                "{}: {env:#}",
                report.what("vendor")
            );
            assert_eq!(
                env["summary"]["applied"],
                1,
                "{}: {env:#}",
                report.what("vendor")
            );
        }
    }
    let lock_text = std::fs::read_to_string(proj.join(lane.lock())).unwrap();
    assert!(
        lock_text.contains(uuid),
        "{}: {} is not wired:\n{lock_text}",
        report.what("wire"),
        lane.lock()
    );
    if mode == Mode::Vendored {
        // Vendored attestation hashes the committed wheel, not the
        // (still pristine) installed tree.
        let doc: Value = serde_json::from_slice(
            &std::fs::read(&embedded_doc)
                .unwrap_or_else(|e| panic!("{}: in-run --vex document: {e}", report.what("wire"))),
        )
        .unwrap();
        assert_attested(&doc, &built.purl, uuid, mode.marker(), vulns);
        report.row("in-run --vex", "attested");
    }
    let wired = snapshot(&proj, lane.wiring());
    let patch_server = scan_api.as_ref().map(ScanApi::uri);

    // ── 3. fresh checkout + real install from an empty cache ──────────
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    restore(&fresh, &wired);
    copy_tree(&proj.join(".socket"), &fresh.join(".socket"));
    let _ = std::fs::remove_dir_all(fresh.join(".socket/blobs"));
    let _ = std::fs::remove_file(fresh.join("embedded.vex.json"));
    strip_manifest(&fresh);
    let fresh_cache = tmp.path().join("fresh-cache");
    // Vendored installs run `--offline` when every dependency is the
    // committed wheel; the transitive lane's other packages come from PyPI.
    let offline = mode == Mode::Vendored && lane != Lane::Transitive;
    let installed = install(uv, lane, &fresh, &fresh_cache, offline, true);
    assert_eq!(
        installed,
        "1",
        "{}: the fresh install is not patched",
        report.what("install")
    );
    if let Some(api) = &scan_api {
        assert!(
            api.wheel_fetches(&wheel_leaf) >= 1,
            "{}: uv never fetched the hosted wheel",
            report.what("install")
        );
    }
    for (f, bytes) in &wired {
        assert_eq!(
            &std::fs::read(fresh.join(f)).unwrap(),
            bytes,
            "{}: the install rewrote {f}",
            report.what("install")
        );
    }
    report.row("fresh-install", "patched");

    // ── 5. plain (re-resolving) sync — the 0.5.6 boundary ─────────────
    let api = PatchApi::start(vec![(
        uuid.to_string(),
        patch_view(
            uuid,
            &built.purl,
            &[("six.py", &git_sha256(&patched))],
            vulns,
        ),
    )]);
    if lane.has_project() && uv.help_has(&["sync"], "--frozen") {
        let resolved = install(uv, lane, &fresh, &fresh_cache, false, false);
        let lock_after = std::fs::read(fresh.join("uv.lock")).unwrap();
        let lock_text = String::from_utf8_lossy(&lock_after).to_string();
        let lock_kept = wired
            .iter()
            .any(|(f, b)| f == "uv.lock" && *b == lock_after);
        let still_wired = !six_entry_source(&lock_text).starts_with("{ registry");
        let run = VexRun {
            patch_server_url: patch_server.clone(),
            product: Some(PRODUCT.to_string()),
            ..VexRun::online(&api)
        };
        let out = run_vex(&binary(), &fresh, &run);
        // What uv does is the release's business; VEX must FOLLOW it. The
        // measured boundaries are asserted as facts: a direct dependency and
        // every uv >= 0.5.5 keep the patch; a transitive override on uv
        // <= 0.5.4 re-resolves to the registry (sources were not applied to
        // overrides — the advisory `pypi_uv_override_requires_uv_0_5_6`;
        // measured with real binaries: 0.5.4 re-resolves, 0.5.5 keeps).
        if lane != Lane::Transitive || uv.at_least((0, 5, 5)) {
            assert!(
                still_wired,
                "{}: plain `uv sync` dropped the patch:\n{lock_text}",
                report.what("plain-sync")
            );
        } else {
            assert!(
                !still_wired,
                "{}: expected the registry re-lock:\n{lock_text}",
                report.what("plain-sync")
            );
        }
        if still_wired {
            assert_eq!(
                resolved,
                "1",
                "{}: plain sync reinstalled pristine",
                report.what("plain-sync")
            );
            assert_eq!(out.code, Some(0), "{}:\n{out}", report.what("plain-sync"));
            assert_attested(out.doc(), &built.purl, uuid, mode.marker(), vulns);
            report.row(
                "plain-sync",
                if lock_kept {
                    "lock kept, patched, attested"
                } else {
                    "lock re-serialized, patch kept, patched, attested"
                },
            );
        } else {
            // The re-resolve went back to the registry and the lock lost the
            // patch (a `[manifest] overrides` echo may keep naming it; what
            // installs is the package entry). Measured on 0.2.37 / 0.3.5 /
            // 0.4.30 / 0.5.3: the plain sync itself leaves the same-version
            // install in place (still patched), but every install FROM the
            // re-resolved lock is pristine — so VEX, which attests what the
            // committed wiring delivers, must stop attesting.
            assert_ne!(out.code, Some(0), "{}:\n{out}", report.what("plain-sync"));
            assert!(
                out.doc
                    .as_ref()
                    .is_none_or(|d| statements_for(d, &built.purl).is_empty()),
                "{}: attested a re-resolved registry lock:\n{out}",
                report.what("plain-sync")
            );
            let _ = std::fs::remove_dir_all(fresh.join(".venv"));
            let from_relock = install(
                uv,
                lane,
                &fresh,
                &tmp.path().join("relock-cache"),
                false,
                true,
            );
            assert_eq!(
                from_relock,
                "0",
                "{}: a frozen install of the re-resolved lock is patched",
                report.what("plain-sync")
            );
            report.row(
                "plain-sync",
                &format!(
                    "lock re-resolved to the registry (plain sync left the {} install; \
                     frozen reinstall pristine), not attested",
                    if resolved == "1" {
                        "stale patched"
                    } else {
                        "pristine"
                    }
                ),
            );
        }
        let _ = std::fs::remove_dir_all(fresh.join(".venv"));
        restore(&fresh, &wired);
        let again = install(uv, lane, &fresh, &fresh_cache, offline, true);
        assert_eq!(
            again,
            "1",
            "{}: frozen reinstall",
            report.what("plain-sync")
        );
        if lane == Lane::Constraints {
            // `--locked` accepts the repointed `[manifest] constraints` entry
            // only where uv serializes constraints with their source
            // (advisory `pypi_uv_constraints_require_uv_0_5_6`; measured:
            // 0.5.4 rejects, 0.5.5 accepts).
            let mut args = vec!["sync", "--locked"];
            no_install_project(uv, &fresh, &mut args);
            let locked = ok(&uv.run_py(&fresh, &args, &fresh_cache));
            if uv.at_least((0, 5, 5)) {
                assert!(
                    locked,
                    "{}: `uv sync --locked` failed",
                    report.what("locked")
                );
            } else {
                assert!(
                    !locked,
                    "{}: expected the --locked rejection",
                    report.what("locked")
                );
            }
            report.row(
                "uv sync --locked",
                if locked {
                    "accepted"
                } else {
                    "rejected (uv serializes constraints without sources)"
                },
            );
            restore(&fresh, &wired);
        }
    }

    // ── 4. manifest-less VEX ──────────────────────────────────────────
    let mut embedded: Vec<(&str, VexRun)> =
        vec![("apply --vex", VexRun::offline().via(VexVia::Apply))];
    match mode {
        Mode::Vendored => embedded.push(("vendor --vex", VexRun::offline().via(VexVia::Vendor))),
        Mode::Hosted => embedded.push((
            "scan --redirect --vex",
            VexRun {
                api_url: patch_server.clone(),
                api_token: Some("fake-token".into()),
                org: Some(ORG.into()),
                ..VexRun::default()
            }
            .via(VexVia::Scan)
            .arg("--redirect")
            .arg("--yes"),
        )),
    }
    let reinstall_cache = tmp.path().join("revert-cache");
    manifestless_matrix(
        &Matrix {
            fresh: &fresh,
            purl: &built.purl,
            uuid,
            mode,
            vulns,
            api: &api,
            patch_server: patch_server.clone(),
            embedded,
            registry: &built.registry,
            reinstall_registry: &|dir: &Path| {
                let _ = std::fs::remove_dir_all(dir.join(".venv"));
                install(uv, lane, dir, &reinstall_cache, false, true)
            },
        },
        &|step, result| report.row(step, result),
    );

    // ── 6. the real revert restores every wiring file ─────────────────
    let out = match mode {
        Mode::Hosted => {
            let uri = patch_server.clone().unwrap();
            socket_patch(
                &proj,
                &[
                    "rollback",
                    "--json",
                    "--yes",
                    "--cwd",
                    proj.to_str().unwrap(),
                    "--api-url",
                    &uri,
                    "--api-token",
                    "fake-token",
                    "--org",
                    ORG,
                ],
            )
        }
        Mode::Vendored => socket_patch(
            &proj,
            &[
                "vendor",
                "--revert",
                "--json",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        ),
    };
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}:\n{}",
        report.what("revert"),
        dump(&out)
    );
    for (f, bytes) in &built.registry {
        assert_eq!(
            &std::fs::read(proj.join(f)).unwrap(),
            bytes,
            "{}: {f} not byte-restored",
            report.what("revert")
        );
    }
    report.row("revert", "byte-identical");
}

// ── production legs ────────────────────────────────────────────────────

/// The uv program a production leg drives: `SOCKET_PATCH_UV_E2E_BIN`, else
/// `uv` on PATH.
pub fn uv_program() -> String {
    std::env::var("SOCKET_PATCH_UV_E2E_BIN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "uv".to_string())
}

/// The patch API's view body for a locally recorded `record` (a manifest /
/// ledger `PatchRecord` JSON): what `GET …/patch/view/<uuid>` returns for
/// it, so a hermetic stand-in can serve a PRODUCTION record.
pub fn record_view(record: &Value, purl: &str) -> Value {
    json!({
        "uuid": record["uuid"],
        "purl": purl,
        "publishedAt": "Tue, 01 Sep 2026 00:00:00 GMT",
        "files": record["files"],
        "vulnerabilities": record["vulnerabilities"],
        "description": record["description"],
        "license": record["license"],
        "tier": record["tier"],
    })
}

/// `uv --version`'s release for the program `uv` (`?` when unknown).
pub fn version_of(uv: &str) -> String {
    Command::new(uv)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .nth(1)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "?".to_string())
}

/// Whether the production legs' own flow runs on `uv` (they are written for
/// current uv: `uv sync --frozen`, and — vendored — a root-less
/// `--offline` sync, which needs `--no-install-project`-era virtual
/// projects). `Err` is the `n/a` reason; the hermetic lanes cover older
/// releases.
pub fn production_supported(uv: &str, mode: Mode) -> Result<(), String> {
    let help = Command::new(uv)
        .args(["sync", "--help"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    if !help.contains("--frozen") {
        return Err("no `uv sync --frozen` (uv < 0.2); covered by the hermetic lanes".into());
    }
    let v = version_of(uv);
    let mut parts = v.split('.').map(|p| p.parse::<u64>().unwrap_or(0));
    let parsed = (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    );
    // A project with no build-system is VIRTUAL only from uv 0.4: before
    // that the leg's `uv sync --frozen --offline` builds the root project
    // and needs setuptools from the network.
    if mode == Mode::Vendored && parsed < (0, 4, 0) {
        return Err(
            "no virtual-project `uv sync --offline` (uv < 0.4); covered by the hermetic lanes"
                .into(),
        );
    }
    Ok(())
}

/// A production uv leg's committed state, for [`production_manifestless`].
pub struct Production<'a> {
    pub leg: &'a str,
    /// The project the leg wired (and installed patched).
    pub proj: &'a Path,
    pub tmp: &'a Path,
    pub mode: Mode,
    /// Base purl of the patched package.
    pub purl: &'a str,
    /// The production patch uuids the leg accepts.
    pub uuids: &'a [&'a str],
    /// Pre-patch `pyproject.toml` + `uv.lock`.
    pub registry: &'a [(String, Vec<u8>)],
    pub uv: &'a str,
    /// Whether `dir/.venv` imports the patched bytes.
    pub patched: &'a dyn Fn(&Path) -> bool,
    /// Extra embedded entry points (the leg's own `scan --vex`).
    pub embedded: Vec<(&'a str, VexRun)>,
}

/// The first production record for one of `p.uuids`, from the ledgers or
/// the manifest `p.proj` holds.
fn production_record(p: &Production<'_>) -> Value {
    let read = |rel: &str| -> Value {
        std::fs::read(p.proj.join(rel))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null)
    };
    let mut candidates: Vec<Value> = Vec::new();
    for (rel, pointer) in [
        (".socket/vendor/redirect-state.json", "/records"),
        (".socket/manifest.json", "/patches"),
    ] {
        if let Some(map) = read(rel).pointer(pointer).and_then(Value::as_object) {
            candidates.extend(map.values().cloned());
        }
    }
    if let Some(entries) = read(".socket/vendor/state.json")
        .pointer("/entries")
        .and_then(Value::as_object)
    {
        candidates.extend(entries.values().map(|e| e["record"].clone()));
    }
    candidates
        .into_iter()
        .find(|r| r["uuid"].as_str().is_some_and(|u| p.uuids.contains(&u)))
        .unwrap_or_else(|| {
            panic!(
                "{}: no production record for the leg's pinned patches in the ledgers",
                p.leg
            )
        })
}

/// Manifest-less VEX over a FRESH checkout of a production uv leg: copy
/// pyproject + uv.lock + `.socket/` (minus the manifest), install with the
/// real uv from an empty cache (`--offline` for vendored), prove the patched
/// bytes, then [`manifestless_matrix`] with a stand-in API serving the leg's
/// own production record (so the ledger-less step is hermetic). The embedded
/// steps add `apply --vex` (+ `vendor --vex` for vendored) to `p.embedded`.
pub fn production_manifestless(p: &Production<'_>) {
    let record = production_record(p);
    let uuid = record["uuid"].as_str().unwrap().to_string();
    let vulns_owned: Vec<(String, Vec<String>)> = record["vulnerabilities"]
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(id, v)| {
                    let cves = v["cves"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|c| c.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    (id.clone(), cves)
                })
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !vulns_owned.is_empty(),
        "{}: the record lists no vulnerability",
        p.leg
    );
    let cve_refs: Vec<Vec<&str>> = vulns_owned
        .iter()
        .map(|(_, c)| c.iter().map(String::as_str).collect())
        .collect();
    let vulns: Vec<(&str, &[&str])> = vulns_owned
        .iter()
        .zip(&cve_refs)
        .map(|((id, _), cves)| (id.as_str(), cves.as_slice()))
        .collect();

    let fresh = p.tmp.join("vex-fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    for f in ["pyproject.toml", "uv.lock"] {
        std::fs::copy(p.proj.join(f), fresh.join(f)).unwrap();
    }
    copy_tree(&p.proj.join(".socket"), &fresh.join(".socket"));
    strip_manifest(&fresh);
    let sync = |dir: &Path, cache: &Path, offline: bool| {
        let mut cmd = Command::new(p.uv);
        scrub_python_env(&mut cmd);
        crate::cache_env::isolate(&mut cmd);
        if let Some(py) = std::env::var_os("SOCKET_PATCH_UV_E2E_PYTHON").filter(|p| !p.is_empty()) {
            cmd.env("UV_PYTHON", py);
        }
        cmd.env("UV_CACHE_DIR", cache)
            .current_dir(dir)
            .args(["sync", "--frozen", "--quiet"]);
        if offline {
            cmd.arg("--offline");
        }
        let out = cmd.output().expect("spawn uv");
        assert!(
            ok(&out),
            "{}: `uv sync --frozen` in {}:\n{}",
            p.leg,
            dir.display(),
            dump(&out)
        );
    };
    sync(
        &fresh,
        &p.tmp.join("vex-fresh-cache"),
        p.mode == Mode::Vendored,
    );
    assert!(
        (p.patched)(&fresh),
        "{}: the fresh checkout is not patched",
        p.leg
    );

    let api = PatchApi::start(vec![(uuid.clone(), record_view(&record, p.purl))]);
    let mut embedded = vec![("apply --vex", VexRun::offline().via(VexVia::Apply))];
    if p.mode == Mode::Vendored {
        embedded.push(("vendor --vex", VexRun::offline().via(VexVia::Vendor)));
    }
    embedded.extend(p.embedded.iter().cloned());
    let reinstall_cache = p.tmp.join("vex-revert-cache");
    let version = String::from_utf8_lossy(
        &Command::new(p.uv)
            .arg("--version")
            .output()
            .expect("uv --version")
            .stdout,
    )
    .split_whitespace()
    .nth(1)
    .unwrap_or("?")
    .to_string();
    manifestless_matrix(
        &Matrix {
            fresh: &fresh,
            purl: p.purl,
            uuid: &uuid,
            mode: p.mode,
            vulns: &vulns,
            api: &api,
            patch_server: None,
            embedded,
            registry: p.registry,
            reinstall_registry: &|dir: &Path| {
                let _ = std::fs::remove_dir_all(dir.join(".venv"));
                sync(dir, &reinstall_cache, false);
                if (p.patched)(dir) { "1" } else { "0" }.to_string()
            },
        },
        &|step, result| {
            println!(
                "UV-VEX uv={version} mode={} lane=production({}) step={step} result={result}",
                p.mode.name(),
                p.leg
            )
        },
    );
}
