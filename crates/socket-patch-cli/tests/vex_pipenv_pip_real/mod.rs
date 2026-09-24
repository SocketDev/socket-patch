//! Shared plumbing for the REAL-package-manager manifest-less VEX
//! capstones `e2e_vex_build/pipenv.rs` (one Pipenv release per calendar
//! major) and `e2e_vex_build/pip.rs` (one pip release per major): the real
//! `six==1.16.0` from PyPI for the pristine install, a wiremock Socket API
//! that serves discovery, the hosted grant, the patch view AND the patched
//! wheel itself (so the package manager's own install of the hosted
//! artifact is real too), and [`manifestless_vex_matrix`] — the
//! `vex_pipenv_pip_steps` manifest-less VEX steps every flow ends with.
//!
//! Pull it in after `vex_e2e_common`:
//!
//! ```ignore
//! #[path = "vex_e2e_common/mod.rs"]
//! mod vex_e2e_common;
//! #[path = "vex_pipenv_pip_steps/mod.rs"]
//! mod vex_pipenv_pip_steps;
//! #[path = "vex_pipenv_pip_real/mod.rs"]
//! mod vex_pipenv_pip_real;
//! ```
//!
//! Gates. Without `uv`, or when PyPI / the release bootstrap is
//! unreachable, a test prints `SKIP` and passes — unless its
//! `SOCKET_PATCH_<PM>_E2E_REQUIRED` variable is set (non-empty), which CI
//! sets so a leg can never report green on an unexercised toolchain.
//! Bootstrapped tool venvs and the pip / uv caches live under
//! `$SOCKET_PATCH_PYPI_E2E_TOOLS` (default: the cargo target tmp dir) and
//! are reused across runs.
//!
//! Every step's verdict is also appended as one JSON line to
//! `$SOCKET_PATCH_VEX_E2E_RESULTS` when set (the local per-version matrix
//! loop collects them into its results table).

#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

use crate::vex_e2e_common::{assert_attested, binary, git_sha256, Marker};
use crate::vex_pipenv_pip_steps::{run_manifestless_steps, Records, Steps};

pub const ORG: &str = "test-org";
pub const PURL: &str = "pkg:pypi/six@1.16.0";
pub const PRODUCT: &str = "pkg:pypi/app@0.1.0";
pub const HOSTED_UUID: &str = "7b8c9d0e-1f2a-4b3c-8d4e-5f6a7b8c9d0e";
pub const VENDORED_UUID: &str = "0e9d8c7b-6a5f-4e4d-9c3b-2a1f0e9d8c7b";
/// A uuid-SHAPED grant token: the patch uuid is the LAST uuid segment.
pub const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
pub const GHSA: &str = "GHSA-real-ppip-0001";
pub const CVE: &str = "CVE-2026-7401";
pub const VULNS: &[(&str, &[&str])] = &[(GHSA, &[CVE])];
/// The registry wheel's filename (the hosted artifact keeps it).
pub const WHEEL: &str = "six-1.16.0-py2.py3-none-any.whl";
/// Appended to the installed `six.py` by the synthetic patch.
pub const PATCH_SUFFIX: &[u8] = b"\n# SOCKET-PATCHED\nSOCKET_PATCHED = 1\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Hosted,
    Vendored,
}

impl Mode {
    pub fn uuid(self) -> &'static str {
        match self {
            Mode::Hosted => HOSTED_UUID,
            Mode::Vendored => VENDORED_UUID,
        }
    }

    pub fn marker(self) -> Marker {
        match self {
            Mode::Hosted => Marker::Redirected,
            Mode::Vendored => Marker::Vendored,
        }
    }

    pub fn unwired(self) -> &'static str {
        match self {
            Mode::Hosted => "redirect_unwired",
            Mode::Vendored => "vendor_unwired",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Mode::Hosted => "hosted",
            Mode::Vendored => "vendored",
        }
    }

    /// The `scan` flags that produce this mode's wiring.
    pub fn scan_flags(self) -> &'static [&'static str] {
        match self {
            Mode::Hosted => &["--redirect"],
            Mode::Vendored => &["--vendor", "--vendor-source", "build"],
        }
    }
}

// ── gates + results ───────────────────────────────────────────────────

pub fn required(var: &str) -> bool {
    std::env::var_os(var).is_some_and(|v| !v.is_empty())
}

/// Skip (or, under `required_var`, fail) with `why`.
pub fn skip_or_fail(required_var: &str, why: &str) {
    if required(required_var) {
        panic!("{required_var} is set but {why}");
    }
    eprintln!("SKIP: {why}");
}

/// The versions a suite runs: `$<var>` (whitespace/comma separated) when
/// set and non-empty, else `default` (every major, the local loop).
pub fn versions(var: &str, default: &[&str]) -> Vec<String> {
    match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => v
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        _ => default.iter().map(|s| s.to_string()).collect(),
    }
}

/// Append one step verdict to `$SOCKET_PATCH_VEX_E2E_RESULTS`.
pub fn record(pm: &str, version: &str, cell: &str, step: &str, outcome: &str) {
    eprintln!("RESULT {pm} {version} {cell} {step}: {outcome}");
    let Some(path) = std::env::var_os("SOCKET_PATCH_VEX_E2E_RESULTS") else {
        return;
    };
    let line = serde_json::json!({
        "pm": pm, "version": version, "cell": cell, "step": step, "outcome": outcome,
    });
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("results file");
    writeln!(file, "{line}").unwrap();
}

// ── tools ─────────────────────────────────────────────────────────────

/// `uv`: PATH first, then `~/.local/bin/uv`.
pub fn find_uv() -> Option<PathBuf> {
    let on_path = Command::new("uv")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if on_path {
        return Some(PathBuf::from("uv"));
    }
    let home = std::env::var_os("HOME")?;
    let candidate = Path::new(&home).join(".local/bin/uv");
    candidate.is_file().then_some(candidate)
}

/// Bootstrapped tool venvs + caches (reused across runs).
pub fn tools_root() -> PathBuf {
    std::env::var_os("SOCKET_PATCH_PYPI_E2E_TOOLS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("pypi-pm-tools"))
}

pub fn venv_bin(venv: &Path, exe: &str) -> PathBuf {
    if cfg!(windows) {
        venv.join("Scripts").join(format!("{exe}.exe"))
    } else {
        venv.join("bin").join(exe)
    }
}

/// Run `exe` with the ambient Python / package-manager / Socket config
/// scrubbed, then `envs` (last wins).
pub fn tool(exe: &Path, cwd: &Path, args: &[&str], envs: &[(String, String)]) -> Output {
    let mut cmd = Command::new(exe);
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        let name = k.to_string_lossy();
        if [
            "PYTHON",
            "UV_",
            "PIP_",
            "PIPENV_",
            "SOCKET_",
            "VIRTUAL_ENV",
            "CONDA_",
            "WORKON_HOME",
        ]
        .iter()
        .any(|p| name.starts_with(p))
        {
            cmd.env_remove(&k);
        }
    }
    let root = tools_root();
    cmd.env(
        "PIP_CONFIG_FILE",
        if cfg!(windows) { "NUL" } else { "/dev/null" },
    )
    .env("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    .env("PIP_CACHE_DIR", root.join("pip-cache"))
    .env("PYTHONDONTWRITEBYTECODE", "1")
    .env("NO_COLOR", "1")
    .env("UV_CACHE_DIR", root.join("uv-cache"));
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", exe.display()))
}

pub fn out_text(out: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

pub fn assert_ok(out: &Output, what: &str) {
    assert!(out.status.success(), "{what} failed: {}", out_text(out));
}

/// A venv at `venv` for `python` (a uv python request or an interpreter
/// path) holding `pins` (installed with uv from PyPI).
pub fn make_venv(uv: &Path, python: &str, venv: &Path, pins: &[&str]) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(venv);
    std::fs::create_dir_all(venv.parent().unwrap()).map_err(|e| e.to_string())?;
    let cwd = venv.parent().unwrap();
    let out = tool(
        uv,
        cwd,
        &[
            "venv",
            "--quiet",
            "--python",
            python,
            venv.to_str().unwrap(),
        ],
        &[],
    );
    if !out.status.success() {
        return Err(format!("uv venv --python {python}: {}", out_text(&out)));
    }
    if !pins.is_empty() {
        let py = venv_bin(venv, "python");
        let mut args = vec![
            "pip",
            "install",
            "--quiet",
            "--python",
            py.to_str().unwrap(),
        ];
        args.extend_from_slice(pins);
        let out = tool(uv, cwd, &args, &[]);
        if !out.status.success() {
            return Err(format!("uv pip install {pins:?}: {}", out_text(&out)));
        }
    }
    Ok(())
}

/// `<tools_root>/<name>` made by [`make_venv`] unless `probe` already runs
/// there (bootstraps are reused across runs).
pub fn bootstrap_tool(
    uv: &Path,
    name: &str,
    python: &str,
    pins: &[&str],
    probe: &str,
) -> Result<PathBuf, String> {
    let venv = tools_root().join(name);
    let exe = venv_bin(&venv, probe);
    let healthy = |exe: &Path| {
        exe.is_file()
            && tool(exe, &tools_root(), &["--version"], &[])
                .status
                .success()
    };
    if healthy(&exe) {
        return Ok(venv);
    }
    make_venv(uv, python, &venv, pins)?;
    if !healthy(&exe) {
        return Err(format!("{name}: `{probe} --version` fails after bootstrap"));
    }
    Ok(venv)
}

/// What `import six` resolves to under `python`: the module bytes and
/// whether the synthetic patch marker is live.
pub fn six_oracle(python: &Path, cwd: &Path) -> Option<(PathBuf, Vec<u8>, bool)> {
    let out = tool(
        python,
        cwd,
        &[
            "-c",
            "import six; print(six.__file__); print(getattr(six, 'SOCKET_PATCHED', 0))",
        ],
        &[],
    );
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut lines = stdout.lines();
    let file = PathBuf::from(lines.next()?.trim());
    let patched = lines.next()?.trim() == "1";
    let bytes = std::fs::read(&file).ok()?;
    Some((file, bytes, patched))
}

/// Copy `from` into `to` recursively, skipping every path whose root-
/// relative spelling is in `skip` (a fresh checkout of the committed
/// state: no venv).
pub fn copy_tree(from: &Path, to: &Path, skip: &[&str]) {
    fn walk(root: &Path, dir: &Path, to: &Path, skip: &[&str]) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if skip.contains(&rel.as_str()) {
                continue;
            }
            let target = to.join(&rel);
            if path.is_dir() {
                std::fs::create_dir_all(&target).unwrap();
                walk(root, &path, to, skip);
            } else {
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::copy(&path, &target).unwrap();
            }
        }
    }
    std::fs::create_dir_all(to).unwrap();
    walk(from, from, to, skip);
}

// ── the patched artifact + the mock Socket API ────────────────────────

/// A PEP 427 wheel for six 1.16.0 whose `six.py` is `module` (RECORD
/// digests computed, so pip / Pipenv install it cleanly).
pub fn build_wheel(module: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    use sha2::Digest as _;
    let digest =
        |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(b));
    let meta = b"Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\nSummary: Python 2 and 3 compatibility utilities\n".to_vec();
    let wheel = b"Wheel-Version: 1.0\nGenerator: socket-patch-test\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-none-any\n".to_vec();
    let members: Vec<(&str, Vec<u8>)> = vec![
        ("six.py", module.to_vec()),
        ("six-1.16.0.dist-info/METADATA", meta),
        ("six-1.16.0.dist-info/WHEEL", wheel),
    ];
    let mut record = String::new();
    for (name, bytes) in &members {
        record.push_str(&format!(
            "{name},sha256={},{}\n",
            digest(bytes),
            bytes.len()
        ));
    }
    record.push_str("six-1.16.0.dist-info/RECORD,,\n");
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes) in members
        .iter()
        .map(|(n, b)| (*n, b.as_slice()))
        .chain(std::iter::once((
            "six-1.16.0.dist-info/RECORD",
            record.as_bytes(),
        )))
    {
        zip.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The patch view for `uuid`: `six.py` pristine → patched (with the inline
/// blob the vendored build consumes) and [`GHSA`] / [`CVE`].
pub fn view(uuid: &str, pristine: &[u8], patched: &[u8]) -> Value {
    use base64::Engine as _;
    serde_json::json!({
        "uuid": uuid,
        "purl": PURL,
        "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": { "six.py": {
            "beforeHash": git_sha256(pristine),
            "afterHash": git_sha256(patched),
            "blobContent": base64::engine::general_purpose::STANDARD.encode(patched),
        } },
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "real-pm fixture", "severity": "high", "description": "d"
        } },
        "description": "real package-manager vex fixture",
        "license": "MIT",
        "tier": "free",
    })
}

/// The Socket API + patch server stand-in for one patch: discovery, the
/// hosted grant (pointing at this server's own artifact route), the view on
/// both routes, and the patched wheel.
pub struct RealApi {
    rt: tokio::runtime::Runtime,
    server: wiremock::MockServer,
    pub uuid: String,
    pub wheel: Vec<u8>,
    pub wheel_sha256: String,
}

impl RealApi {
    pub fn start(uuid: &str, pristine: &[u8], patched: &[u8]) -> Self {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(wiremock::MockServer::start());
        let wheel = build_wheel(patched);
        let api = RealApi {
            rt,
            server,
            uuid: uuid.to_string(),
            wheel_sha256: sha256_hex(&wheel),
            wheel: wheel.clone(),
        };
        let url = api.artifact_url();
        let mounts = vec![
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "packages": [{ "purl": PURL, "patches": [{
                        "uuid": uuid, "purl": PURL, "tier": "free",
                        "cveIds": [CVE], "ghsaIds": [GHSA], "severity": "high",
                        "title": "real-pm fixture"
                    }] }],
                    "canAccessPaidPatches": false,
                }))),
            Mock::given(method("GET"))
                .and(path_regex(format!(
                    "^/v0/orgs/{ORG}/patches/by-package/.+$"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "patches": [{
                        "uuid": uuid, "purl": PURL, "publishedAt": "2026-03-27T00:00:00Z",
                        "description": "x", "license": "MIT", "tier": "free",
                        "vulnerabilities": {}
                    }],
                    "canAccessPaidPatches": false,
                }))),
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "results": { uuid: {
                        "status": "granted", "url": url, "purl": PURL,
                        "artifacts": [{ "kind": "tarball", "url": url,
                                        "integrity": { "sha256": api.wheel_sha256 } }],
                        "registryOverride": null
                    } }
                }))),
            Mock::given(method("GET"))
                .and(path(format!("/patch/view/{uuid}")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(view(uuid, pristine, patched)),
                ),
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(view(uuid, pristine, patched)),
                ),
            Mock::given(method("GET"))
                .and(path(api.artifact_path()))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", "application/octet-stream")
                        .set_body_bytes(wheel),
                ),
        ];
        for mock in mounts {
            api.rt.block_on(mock.mount(&api.server));
        }
        api
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    fn artifact_path(&self) -> String {
        format!("/patch/pypi/six/1.16.0/{TOKEN}/{}/{WHEEL}", self.uuid)
    }

    /// The hosted artifact url the grant hands out (on this server, which
    /// is why every VEX run passes `--patch-server-url` = [`Self::uri`]).
    pub fn artifact_url(&self) -> String {
        format!("{}{}", self.uri(), self.artifact_path())
    }

    /// How many times the patched wheel was downloaded.
    pub fn artifact_downloads(&self) -> usize {
        let wanted = self.artifact_path();
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == wanted)
            .count()
    }
}

/// `socket-patch scan --json --yes` in `cwd` against `api` (org route,
/// fake token, `--patch-server-url` = the mock), with `extra` flags and
/// child `envs` (PATH for the `pipenv --version` probe, …).
pub fn socket_scan(
    cwd: &Path,
    api: &RealApi,
    extra: &[&str],
    envs: &[(String, String)],
) -> (Option<i32>, Value, String) {
    let bin = binary();
    let uri = api.uri();
    let mut args = vec![
        "scan",
        "--json",
        "--yes",
        "--api-url",
        &uri,
        "--api-token",
        "fake",
        "--org",
        ORG,
        "--patch-server-url",
        &uri,
        "--cwd",
        cwd.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let mut envs = envs.to_vec();
    envs.push(("SOCKET_TELEMETRY_DISABLED".into(), "1".into()));
    envs.push(("SOCKET_NO_CONFIG".into(), "1".into()));
    let out = tool(&bin, cwd, &args, &envs);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let env: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "scan --json stdout ({e}):\n{}\n--- stderr\n{stderr}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    (out.status.code(), env, stderr)
}

/// The document attests six via `mode`'s patch for [`PRODUCT`] only.
pub fn assert_six_attested(doc: &Value, mode: Mode, what: &str) {
    let stmts = doc["statements"]
        .as_array()
        .unwrap_or_else(|| panic!("{what}: {doc}"));
    assert_eq!(stmts.len(), 1, "{what}: {doc}");
    assert_eq!(stmts[0]["products"][0]["@id"], PRODUCT, "{what}: {doc}");
    assert_attested(doc, PURL, mode.uuid(), mode.marker(), VULNS);
}

// ── the manifest-less VEX matrix every flow ends with ─────────────────

/// Inputs for [`manifestless_vex_matrix`].
pub struct VexMatrix<'a> {
    /// Result-row coordinates.
    pub pm: &'a str,
    pub version: &'a str,
    pub cell: &'a str,
    pub mode: Mode,
    /// The fresh checkout, INSTALLED with the real package manager, with
    /// the committed `.socket/` (manifest + ledgers) as the flow left it.
    pub project: &'a Path,
    /// The mock patch server the wiring points at (hosted references on
    /// its origin count: `--patch-server-url`).
    pub patch_server: &'a str,
    pub pristine: &'a [u8],
    pub patched: &'a [u8],
    /// Put the project's wiring files back to their registry bytes.
    pub revert: &'a (dyn Fn(&Path) + Sync),
    /// Extra child env for VEX runs (crawler inputs such as WORKON_HOME).
    pub envs: Vec<(String, String)>,
}

/// The `vex_pipenv_pip_steps` manifest-less steps over the installed
/// fresh checkout (records from a mock patch API serving six's view), each
/// verdict recorded as a results row.
pub fn manifestless_vex_matrix(m: &VexMatrix<'_>) {
    let row = format!("{}/{}", m.cell, m.mode.label());
    let sink = |step: &str, ok: bool| {
        record(
            m.pm,
            m.version,
            &row,
            step,
            if ok { "pass" } else { "FAIL" },
        );
    };
    run_manifestless_steps(&Steps {
        what: format!("{} {} {row}", m.pm, m.version),
        project: m.project,
        purl: PURL,
        uuid: m.mode.uuid(),
        marker: m.mode.marker(),
        vulns: Some(VULNS),
        records: Records::Mock(vec![(
            m.mode.uuid().to_string(),
            view(m.mode.uuid(), m.pristine, m.patched),
        )]),
        patch_server_url: Some(m.patch_server.to_string()),
        product: PRODUCT,
        revert: m.revert,
        envs: m.envs.clone(),
        on_step: Some(&sink),
        expect_verified: true,
    });
}
