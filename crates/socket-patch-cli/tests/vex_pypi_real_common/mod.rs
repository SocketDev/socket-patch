//! Shared plumbing for the REAL-package-manager manifest-less VEX capstones
//! (`e2e_vex_build/pdm.rs`, `e2e_vex_build/hatch.rs`): a pinned PDM / Hatch
//! release bootstrapped with `uv`, the real `six==1.16.0` from PyPI for the
//! pristine install, and a wiremock Socket API that serves the discovery,
//! the hosted grant, the patch view AND the patched wheel itself, so the
//! package manager's own install of the hosted artifact is real too.
//!
//! Pull it in after `vex_e2e_common`:
//!
//! ```ignore
//! #[path = "vex_e2e_common/mod.rs"]
//! mod vex_e2e_common;
//! #[path = "vex_pypi_real_common/mod.rs"]
//! mod vex_pypi_real_common;
//! ```
//!
//! Gates. Without `uv`, or when PyPI / the release bootstrap is
//! unreachable, a test prints `SKIP` and passes — unless its
//! `SOCKET_PATCH_<PM>_E2E_REQUIRED` variable is set (non-empty), which CI
//! sets so a leg can never report green on an unexercised toolchain.
//!
//! Every step's verdict is also appended as one JSON line to
//! `$SOCKET_PATCH_VEX_E2E_RESULTS` when that is set (the local per-version
//! matrix loop collects them into its results table).

#![allow(dead_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

use crate::vex_e2e_common::git_sha256;

pub const ORG: &str = "test-org";
pub const PURL: &str = "pkg:pypi/six@1.16.0";
pub const HOSTED_UUID: &str = "5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d";
pub const VENDORED_UUID: &str = "8d7c6b5a-4f3e-4d2c-9b1a-0f9e8d7c6b5a";
/// A uuid-SHAPED grant token: the patch uuid is the LAST uuid segment.
pub const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
pub const GHSA: &str = "GHSA-real-pypi-0001";
pub const CVE: &str = "CVE-2026-7201";
pub const VULNS: &[(&str, &[&str])] = &[(GHSA, &[CVE])];
/// The registry wheel's filename (the hosted artifact keeps it: the lock's
/// `files` entry and PEP 427 identity both name it).
pub const WHEEL: &str = "six-1.16.0-py2.py3-none-any.whl";
/// Appended to the installed `six.py` by the synthetic patch.
pub const PATCH_SUFFIX: &[u8] = b"\n# SOCKET-PATCHED\nSOCKET_PATCHED = 1\n";

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

/// Append one step verdict to `$SOCKET_PATCH_VEX_E2E_RESULTS`.
pub fn record(pm: &str, version: &str, cell: &str, step: &str, outcome: &str) {
    let Some(path) = std::env::var_os("SOCKET_PATCH_VEX_E2E_RESULTS") else {
        return;
    };
    let line = serde_json::json!({
        "pm": pm, "version": version, "cell": cell, "step": step, "outcome": outcome,
    });
    // One `write_all` of the whole line under a lock: the tests of a binary
    // run in parallel, and `writeln!` may split a line across syscalls.
    static WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = WRITE.lock().unwrap_or_else(|p| p.into_inner());
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("results file");
    file.write_all(format!("{line}\n").as_bytes()).unwrap();
}

// ── tools ─────────────────────────────────────────────────────────────

/// `uv`: PATH first, then `~/.local/bin/uv` (the standalone installer's
/// default location).
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

/// Where bootstrapped tool venvs (and uv's cache) live: reused across runs
/// (`$SOCKET_PATCH_PYPI_E2E_TOOLS`, else the cargo target tmp dir).
pub fn tools_root() -> PathBuf {
    std::env::var_os("SOCKET_PATCH_PYPI_E2E_TOOLS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("pypi-pm-tools"))
}

pub fn venv_bin(venv: &Path, exe: &str) -> PathBuf {
    venv.join("bin").join(exe)
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
            "PDM_",
            "HATCH_",
            "SOCKET_",
            "VIRTUAL_ENV",
            "CONDA_",
        ]
        .iter()
        .any(|p| name.starts_with(p))
        {
            cmd.env_remove(&k);
        }
    }
    cmd.env(
        "PIP_CONFIG_FILE",
        if cfg!(windows) { "NUL" } else { "/dev/null" },
    )
    .env("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    .env("PYTHONDONTWRITEBYTECODE", "1")
    .env("NO_COLOR", "1")
    .env("UV_CACHE_DIR", tools_root().join("uv-cache"));
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

/// A venv at `<tools_root>/<name>-<version>` holding `pins` for `python`,
/// reused when `<exe> --version` already works there.
pub fn bootstrap_tool(
    uv: &Path,
    name: &str,
    version: &str,
    python: &str,
    pins: &[String],
) -> Result<PathBuf, String> {
    // One bootstrap at a time: the tests of a binary run in parallel and
    // would otherwise race on the same cached venv.
    static BOOTSTRAP: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = BOOTSTRAP.lock().unwrap_or_else(|p| p.into_inner());
    let root = tools_root();
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let venv = root.join(format!("{name}-{version}"));
    let exe = venv_bin(&venv, name);
    let healthy =
        |exe: &Path| exe.is_file() && tool(exe, &root, &["--version"], &[]).status.success();
    if healthy(&exe) {
        return Ok(venv);
    }
    let _ = std::fs::remove_dir_all(&venv);
    let out = tool(
        uv,
        &root,
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
    let py = venv_bin(&venv, "python");
    let mut args = vec![
        "pip",
        "install",
        "--quiet",
        "--python",
        py.to_str().unwrap(),
    ];
    args.extend(pins.iter().map(String::as_str));
    let out = tool(uv, &root, &args, &[]);
    if !out.status.success() {
        return Err(format!("uv pip install {pins:?}: {}", out_text(&out)));
    }
    if !healthy(&exe) {
        return Err(format!("{name} {version} does not run after bootstrap"));
    }
    Ok(venv)
}

/// A venv at `venv` for `python` (the tool's own interpreter, so the
/// project runs on the release's supported Python), optionally seeded with
/// `packages` from PyPI.
pub fn make_venv(uv: &Path, python: &Path, venv: &Path, packages: &[&str]) -> Result<(), String> {
    let cwd = venv.parent().unwrap();
    let out = tool(
        uv,
        cwd,
        &[
            "venv",
            "--quiet",
            "--python",
            python.to_str().unwrap(),
            venv.to_str().unwrap(),
        ],
        &[],
    );
    if !out.status.success() {
        return Err(format!("uv venv: {}", out_text(&out)));
    }
    if !packages.is_empty() {
        let py = venv_bin(venv, "python");
        let mut args = vec![
            "pip",
            "install",
            "--quiet",
            "--python",
            py.to_str().unwrap(),
        ];
        args.extend_from_slice(packages);
        let out = tool(uv, cwd, &args, &[]);
        if !out.status.success() {
            return Err(format!("uv pip install {packages:?}: {}", out_text(&out)));
        }
    }
    Ok(())
}

/// What `import six` resolves to in `python`: the module bytes and whether
/// the synthetic patch marker is live.
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

// ── the patched artifact ──────────────────────────────────────────────

/// A PEP 427 wheel for six 1.16.0 whose `six.py` is `module` (RECORD
/// digests computed, so pip / PDM install it cleanly).
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
}

/// `socket-patch scan --json` in `cwd` against `api`, with `extra` flags and
/// child `envs` (PATH for tool probes).
pub fn socket_scan(
    cwd: &Path,
    api: &RealApi,
    extra: &[&str],
    envs: &[(String, String)],
) -> (Option<i32>, Value, String) {
    let bin = crate::vex_e2e_common::binary();
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

/// Copy `from` into `to` recursively, skipping every path whose root-
/// relative spelling is in `skip`.
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

// ── the manifest-less VEX matrix over a fresh, installed checkout ─────

/// Which patch mode produced the checkout.
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

    pub fn marker(self) -> crate::vex_e2e_common::Marker {
        match self {
            Mode::Hosted => crate::vex_e2e_common::Marker::Redirected,
            Mode::Vendored => crate::vex_e2e_common::Marker::Vendored,
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
}

/// The manifest-less VEX steps for one fresh checkout a real package
/// manager installed from the committed wiring.
pub struct VexMatrix<'a> {
    pub pm: &'a str,
    pub version: &'a str,
    /// Flavor label (results + assertion context).
    pub cell: String,
    pub mode: Mode,
    pub pristine: &'a [u8],
    pub patched: &'a [u8],
    /// `--patch-server-url` (the [`RealApi`] that served the artifact).
    pub patch_server: String,
    /// Child env for every VEX run (e.g. `VIRTUAL_ENV` naming the env the
    /// package manager installed into, when it lives outside the project).
    pub envs: Vec<(String, std::ffi::OsString)>,
    /// The installed `six.py` the package manager put in a location the
    /// crawler sees (hosted: tampering it must flip the verdict).
    pub installed_module: Option<PathBuf>,
}

impl VexMatrix<'_> {
    fn what(&self, step: &str) -> String {
        format!(
            "{} {} {} {} [{step}]",
            self.pm,
            self.version,
            self.cell,
            self.mode.label()
        )
    }

    fn run_for(&self, api: &crate::vex_e2e_common::PatchApi) -> crate::vex_e2e_common::VexRun {
        crate::vex_e2e_common::VexRun {
            patch_server_url: Some(self.patch_server.clone()),
            product: Some("pkg:pypi/app@0.1.0".into()),
            envs: self.envs.clone(),
            ..crate::vex_e2e_common::VexRun::online(api)
        }
    }

    fn api(&self) -> crate::vex_e2e_common::PatchApi {
        crate::vex_e2e_common::PatchApi::start(vec![(
            self.mode.uuid().to_string(),
            view(self.mode.uuid(), self.pristine, self.patched),
        )])
    }

    fn done(&self, step: &str) {
        record(
            self.pm,
            self.version,
            &format!("{}/{}", self.cell, self.mode.label()),
            step,
            "pass",
        );
    }

    /// Run every step in `checkout` (no manifest; ledgers + artifacts as
    /// committed). `ledgers_from` is the wiring run's project (the ledgers
    /// are restored from it for the revert step); `revert` puts the project
    /// files back to their registry wiring.
    pub fn run(&self, checkout: &Path, ledgers_from: &Path, revert: &dyn Fn(&Path)) {
        use crate::vex_e2e_common::*;
        let bin = binary();
        assert!(
            !checkout.join(".socket/manifest.json").exists(),
            "the checkout under test must be manifest-less"
        );
        let uuid = self.mode.uuid();

        // (1) manifest deleted, ledgers kept: offline from the ledger
        // record (zero network), then online.
        let api = self.api();
        let offline = VexRun {
            offline: true,
            ..self.run_for(&api)
        };
        let out = run_vex(&bin, checkout, &offline);
        assert_eq!(out.code, Some(0), "{}: {out}", self.what("ledger offline"));
        assert_attested(out.doc(), PURL, uuid, self.mode.marker(), VULNS);
        api.assert_no_requests();
        let out = run_vex(&bin, checkout, &self.run_for(&api));
        assert_eq!(
            out.code,
            Some(0),
            "{}: {out}",
            self.what("manifest-deleted")
        );
        assert_attested(out.doc(), PURL, uuid, self.mode.marker(), VULNS);
        self.done("manifest-deleted");

        // Hosted with the install visible to the crawler: the installed
        // bytes ARE the evidence — tampering them omits the patch.
        if let (Mode::Hosted, Some(module)) = (self.mode, &self.installed_module) {
            let good = std::fs::read(module).unwrap();
            assert_eq!(git_sha256(&good), git_sha256(self.patched), "{module:?}");
            std::fs::write(module, b"tampered = 1\n").unwrap();
            let out = run_vex(&bin, checkout, &self.run_for(&api));
            std::fs::write(module, &good).unwrap();
            assert_eq!(
                out.code,
                Some(1),
                "{}: {out}",
                self.what("tampered install")
            );
            assert_not_attested(&out.envelope, PURL, "hash_mismatch");
            self.done("tampered-install");
        }

        // (2) ledgers deleted too: lockfile / project-file discovery + API.
        let saved = tempfile::tempdir().unwrap();
        for rel in [
            socket_patch_core::vendor::VENDOR_STATE_REL,
            socket_patch_core::patch::redirect::REDIRECT_STATE_REL,
        ] {
            if checkout.join(rel).exists() {
                let to = saved.path().join(rel);
                std::fs::create_dir_all(to.parent().unwrap()).unwrap();
                std::fs::copy(checkout.join(rel), to).unwrap();
            }
        }
        strip_ledgers(checkout);
        let api = self.api();
        let out = run_vex(&bin, checkout, &self.run_for(&api));
        assert_eq!(out.code, Some(0), "{}: {out}", self.what("ledgers-deleted"));
        assert_attested(out.doc(), PURL, uuid, self.mode.marker(), VULNS);
        assert!(api.view_requests(uuid) >= 1, "{:?}", api.requests());
        assert!(
            !checkout.join(".socket/manifest.json").exists(),
            "vex writes no manifest"
        );
        self.done("ledgers-deleted");

        // Embedded forms on the same manifest-less, ledgerless checkout.
        for via in [VexVia::Apply, VexVia::Vendor] {
            let out = run_vex(&bin, checkout, &self.run_for(&api).via(via));
            assert_eq!(
                out.code,
                Some(0),
                "{}: {out}",
                self.what(&format!("{via:?} --vex"))
            );
            assert_eq!(out.envelope["vex"]["statements"], 1, "{out}");
            assert_attested(out.doc(), PURL, uuid, self.mode.marker(), VULNS);
        }
        self.done("embedded-apply-vendor-vex");

        // (3) offline, no ledgers: no local record → record_unavailable,
        // and not one request.
        let quiet = crate::vex_e2e_common::PatchApi::empty();
        for no_verify in [false, true] {
            let run = VexRun {
                offline: true,
                no_verify,
                ..self.run_for(&quiet)
            };
            let out = run_vex(&bin, checkout, &run);
            assert_eq!(out.code, Some(1), "{}: {out}", self.what("offline"));
            assert_not_attested(&out.envelope, PURL, "record_unavailable");
        }
        quiet.assert_no_requests();
        self.done("offline");

        // (4) wiring reverted to the registry, ledgers + artifacts kept (and
        // the patched install still in place): the dead claim never
        // attests — `--no-verify` and online included.
        for rel in [
            socket_patch_core::vendor::VENDOR_STATE_REL,
            socket_patch_core::patch::redirect::REDIRECT_STATE_REL,
        ] {
            let from = saved.path().join(rel);
            if from.exists() {
                std::fs::copy(&from, checkout.join(rel)).unwrap();
            } else if ledgers_from.join(rel).exists() {
                std::fs::copy(ledgers_from.join(rel), checkout.join(rel)).unwrap();
            }
        }
        revert(checkout);
        let api = self.api();
        for (offline, no_verify) in [(true, false), (true, true), (false, true)] {
            let run = VexRun {
                offline,
                no_verify,
                ..self.run_for(&api)
            };
            let out = run_vex(&bin, checkout, &run);
            let what = self.what(&format!("reverted offline={offline} no_verify={no_verify}"));
            assert_eq!(out.code, Some(1), "{what}: {out}");
            assert_not_attested(&out.envelope, PURL, self.mode.unwired());
            assert!(out.doc.is_none(), "{what}: {out}");
        }
        self.done("reverted");
    }
}
