//! Real-Poetry capstones for HOSTED and VENDORED patches that end in
//! manifest-less VEX — one full flow per mode against a real Poetry release:
//!
//! 1. a real project on `six==1.16.0`, locked by the real `poetry lock`
//!    (PyPI is used for fixture setup only);
//! 2. OUR CLI produces the committed state against a wiremock patch service:
//!    hosted = `scan --redirect --vex` on the lock-only checkout (the lock is
//!    repointed at a patched wheel the mock serves, the redirect ledger is
//!    written, the same-run VEX attests from the lock's sha256 pin); vendored
//!    = `scan --vendor --vendor-source build --vex` over the pristine
//!    install (the patched wheel is committed under
//!    `.socket/vendor/pypi/<uuid>/`, the lock is rewired to it, manifest +
//!    ledger are written);
//! 3. a FRESH checkout of only the committable files (`pyproject.toml`,
//!    `poetry.lock`, `.socket/`) is installed by the real `poetry install`
//!    and the imported `six` is proven to be the PATCHED bytes (vendored
//!    also red-probes: without `.socket/vendor` the install must fail);
//! 4. manifest-less VEX over that installed checkout, with standalone
//!    `socket-patch vex --json --output` against a separate records API:
//!    - (1) `.socket/manifest.json` deleted → attested with the right
//!      `(redirected)` / `(vendored)` marker and vulnerability ids, and also
//!      offline from the committed ledger;
//!    - (2) the ledgers deleted too → still attested, via lockfile discovery
//!      and the API record (installed tree / committed wheel hash-verified);
//!      embedded `apply --vex` (and vendored `vendor --vex`) agree;
//!    - (3) `--offline` with no ledgers → `record_unavailable`, zero API
//!      requests;
//!    - (4) the lock reverted to the registry version with the ledgers and
//!      artifacts kept → NOT attested (`redirect_unwired` /
//!      `vendor_unwired`), under `--no-verify` too;
//!
//!    then the real `rollback` / `vendor --revert` in the original project
//!    restores the pristine lock byte for byte.
//!
//! Poetry selection: `SOCKET_PATCH_POETRY_BIN` (a Poetry executable, e.g.
//! `<venv>/bin/poetry` of a pinned release) or `poetry` on `PATH`. With
//! `SOCKET_PATCH_POETRY_E2E_VERSION` set, `poetry --version` must report it.
//! Both tests soft-skip (println) when Poetry is missing or PyPI is
//! unreachable, unless `SOCKET_PATCH_POETRY_E2E_REQUIRED=1`, under which
//! every such skip is a hard failure (CI). `#[ignore]`-gated: the CI `e2e`
//! matrix runs one leg per Poetry major/lock-format boundary with
//! `--ignored`; locally:
//!
//! ```text
//! SOCKET_PATCH_POETRY_BIN=/path/to/poetry-1.8.5/bin/poetry \
//!   cargo test -p socket-patch-cli --test e2e_vex_build -- poetry:: --ignored
//! ```
//!
//! Every Poetry spawn gets its own `HOME` / cache / config (Poetry ≤ 1.1
//! shares one HTTP-cache lock under the home directory and wedges parallel
//! runs) and an in-project `.venv`.

use crate::vex_e2e_common;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use vex_e2e_common::{
    assert_absent, assert_attested, assert_not_attested, binary, git_sha256, run_vex,
    strip_ledgers, strip_manifest, Marker, PatchApi, VexOutcome, VexRun, VexVia,
};

const PKG: &str = "six";
const VER: &str = "1.16.0";
const PURL: &str = "pkg:pypi/six@1.16.0";
/// What the patch API files pypi patches under (artifact-qualified).
const API_PURL: &str = "pkg:pypi/six@1.16.0?artifact_id=py2-py3-none-any-whl";
const WHEEL: &str = "six-1.16.0-py2.py3-none-any.whl";
const HOSTED_UUID: &str = "3c5e7a9b-1d3f-4b5d-8f7a-9b1d3f5a7c9e";
const VENDORED_UUID: &str = "4d6f8b0c-2e4a-4c6e-9a8b-0c2e4a6c8e0f";
const TOKEN: &str = "11111111-2222-4333-8444-555555555555";
const ORG: &str = "test-org";
const PRODUCT: &str = "pkg:pypi/vex-poetry-e2e@0.1.0";
const GHSA: &str = "GHSA-poet-ryre-al01";
const CVE: &str = "CVE-2026-7201";
const MARKER: &[u8] = b"\n# SOCKET-PATCHED\nSOCKET_PATCHED = 1\n";
const ORACLE: &str = "import six; print(six.SOCKET_PATCHED)";

const PYPROJECT: &str = r#"[tool.poetry]
name = "vex-poetry-e2e"
version = "0.1.0"
description = ""
authors = ["Socket <engineering@socket.dev>"]

[tool.poetry.dependencies]
python = ">=3.8"
six = "1.16.0"
"#;

// ── gating ──────────────────────────────────────────────────────────────

fn required() -> bool {
    std::env::var("SOCKET_PATCH_POETRY_E2E_REQUIRED").is_ok_and(|v| v == "1" || v == "true")
}

/// Skip (or, under `SOCKET_PATCH_POETRY_E2E_REQUIRED=1`, fail) the test.
fn skip(why: &str) {
    assert!(!required(), "SOCKET_PATCH_POETRY_E2E_REQUIRED: {why}");
    println!("SKIP e2e_vex_build::poetry: {why}");
}

fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// A real Poetry, isolated per test.
struct Poetry {
    bin: PathBuf,
    version: String,
    home: PathBuf,
}

impl Poetry {
    /// Resolve and version-check Poetry; `None` (after [`skip`]) when absent.
    fn find(home: &Path) -> Option<Self> {
        let bin = match std::env::var_os("SOCKET_PATCH_POETRY_BIN") {
            Some(p) if !p.is_empty() => PathBuf::from(p),
            _ => match on_path("poetry") {
                Some(p) => p,
                None => {
                    skip("poetry is not installed (set SOCKET_PATCH_POETRY_BIN)");
                    return None;
                }
            },
        };
        let mut poetry = Poetry {
            bin,
            version: String::new(),
            home: home.to_path_buf(),
        };
        let out = poetry.run(home, &["--version"]);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if !out.status.success() {
            skip(&format!(
                "{} --version failed: {text}",
                poetry.bin.display()
            ));
            return None;
        }
        // "Poetry (version 1.8.5)" / "Poetry version 1.1.15".
        poetry.version = text
            .split_whitespace()
            .map(|w| w.trim_matches(|c| c == '(' || c == ')'))
            .find(|w| w.starts_with(|c: char| c.is_ascii_digit()) && w.contains('.'))
            .unwrap_or_default()
            .to_string();
        if let Ok(want) = std::env::var("SOCKET_PATCH_POETRY_E2E_VERSION") {
            if !want.is_empty() {
                assert_eq!(
                    poetry.version,
                    want,
                    "SOCKET_PATCH_POETRY_E2E_VERSION: {} reports {text:?}",
                    poetry.bin.display()
                );
            }
        }
        println!("poetry {} at {}", poetry.version, poetry.bin.display());
        Some(poetry)
    }

    fn major_minor(&self) -> (u32, u32) {
        let mut parts = self.version.split('.').map(|p| p.parse().unwrap_or(0));
        (parts.next().unwrap_or(0), parts.next().unwrap_or(0))
    }

    fn run(&self, cwd: &Path, args: &[&str]) -> Output {
        let mut cmd = Command::new(&self.bin);
        for (key, _) in std::env::vars_os() {
            let k = key.to_string_lossy();
            if k.starts_with("POETRY_")
                || k.starts_with("PIP_")
                || k.starts_with("SOCKET_")
                || k == "VIRTUAL_ENV"
                || k == "PYTHONPATH"
                || k == "PYTHONHOME"
            {
                cmd.env_remove(&key);
            }
        }
        cmd.current_dir(cwd)
            .args(args)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_CACHE_HOME", self.home.join(".cache"))
            .env("XDG_DATA_HOME", self.home.join(".local/share"))
            .env("POETRY_CACHE_DIR", self.home.join("poetry-cache"))
            .env("POETRY_CONFIG_DIR", self.home.join("poetry-config"))
            .env("POETRY_DATA_DIR", self.home.join("poetry-data"))
            .env("POETRY_VIRTUALENVS_IN_PROJECT", "true")
            .env("POETRY_VIRTUALENVS_PATH", self.home.join("poetry-venvs"))
            .env("POETRY_NO_INTERACTION", "1")
            .env("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
            .env("PIP_DISABLE_PIP_VERSION_CHECK", "1")
            .env("PIP_CONFIG_FILE", "/dev/null")
            .env("PYTHONDONTWRITEBYTECODE", "1");
        cmd.output()
            .unwrap_or_else(|e| panic!("spawning {}: {e}", self.bin.display()))
    }

    /// `poetry install` of the lock alone (no root package).
    fn install(&self, cwd: &Path) -> Output {
        self.run(cwd, &["install", "--no-root", "-n"])
    }

    /// The env the CLI's crawler gets: Poetry's configuration (never an
    /// activation — `VIRTUAL_ENV` stays unset).
    fn cli_envs(&self) -> Vec<(String, OsString)> {
        vec![
            ("HOME".into(), self.home.clone().into()),
            (
                "POETRY_VIRTUALENVS_PATH".into(),
                self.home.join("poetry-venvs").into(),
            ),
            (
                "POETRY_CONFIG_DIR".into(),
                self.home.join("poetry-config").into(),
            ),
            (
                "POETRY_CACHE_DIR".into(),
                self.home.join("poetry-cache").into(),
            ),
        ]
    }
}

fn text(out: &Output) -> String {
    format!(
        "exit {:?}\n--- stdout\n{}\n--- stderr\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

// ── project helpers ─────────────────────────────────────────────────────

/// `six.py` inside the in-project venv, if installed.
fn installed_six(project: &Path) -> Option<PathBuf> {
    let lib = project.join(".venv/lib");
    std::fs::read_dir(lib)
        .ok()?
        .flatten()
        .map(|e| e.path().join("site-packages/six.py"))
        .find(|p| p.is_file())
}

fn python_oracle(project: &Path) -> String {
    let out = Command::new(project.join(".venv/bin/python"))
        .args(["-c", ORACLE])
        .current_dir(project)
        .env_remove("PYTHONPATH")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("venv python");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Copy only what a commit carries: `pyproject.toml`, `poetry.lock` and
/// `.socket/` (never the venv or caches).
fn fresh_checkout(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for file in ["pyproject.toml", "poetry.lock"] {
        std::fs::copy(from.join(file), to.join(file)).unwrap();
    }
    if from.join(".socket").is_dir() {
        copy_dir(&from.join(".socket"), &to.join(".socket"));
    }
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap().flatten() {
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Create `project/.venv` with the interpreter Poetry runs on (the
/// venv next to `SOCKET_PATCH_POETRY_BIN`, else `python3`) and pip 24.0 —
/// what Poetry 1.0 then installs into (see the pip-window note at the call
/// site). Needs PyPI, like the fixture lock.
fn seed_venv_with_modern_pip(poetry: &Poetry, project: &Path) {
    let beside = poetry.bin.with_file_name("python");
    let python = if beside.is_file() {
        beside
    } else {
        on_path("python3").expect("python3")
    };
    let venv = project.join(".venv");
    let out = Command::new(&python)
        .args(["-m", "venv"])
        .arg(&venv)
        .output()
        .unwrap();
    assert!(out.status.success(), "python -m venv: {}", text(&out));
    let out = Command::new(venv.join("bin/python"))
        .args([
            "-m",
            "pip",
            "install",
            "-q",
            "--disable-pip-version-check",
            "pip==24.0",
        ])
        .env("PIP_CONFIG_FILE", "/dev/null")
        .output()
        .unwrap();
    assert!(out.status.success(), "seeding pip 24.0: {}", text(&out));
}

/// An EMPTY in-project venv: keeps a lock-only crawl off the host's global
/// interpreters.
fn empty_venv(project: &Path) {
    std::fs::create_dir_all(project.join(".venv/lib/python3.12/site-packages")).unwrap();
}

/// A real `poetry lock` of [`PYPROJECT`] in `project`, plus the upstream
/// `six.py` bytes from a pristine install in a scratch sibling. `None`
/// (after [`skip`]) when PyPI is unreachable.
fn locked_project(poetry: &Poetry, project: &Path, probe: &Path) -> Option<(Vec<u8>, String)> {
    std::fs::create_dir_all(project).unwrap();
    std::fs::write(project.join("pyproject.toml"), PYPROJECT).unwrap();
    let out = poetry.run(project, &["lock", "-n"]);
    if !out.status.success() {
        skip(&format!("poetry lock (needs PyPI): {}", text(&out)));
        return None;
    }
    let lock = std::fs::read_to_string(project.join("poetry.lock")).unwrap();
    assert!(lock.contains("name = \"six\""), "{lock}");
    fresh_checkout(project, probe);
    let out = poetry.install(probe);
    if !out.status.success() {
        skip(&format!(
            "pristine poetry install (needs PyPI): {}",
            text(&out)
        ));
        return None;
    }
    let six = installed_six(probe).unwrap_or_else(|| panic!("six.py not installed in {probe:?}"));
    Some((std::fs::read(six).unwrap(), lock))
}

// ── the patched wheel ───────────────────────────────────────────────────

/// A valid `six-1.16.0-py2.py3-none-any.whl` whose `six.py` is `module`
/// (RECORD carries every member's hash, as installers expect).
fn build_wheel(module: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    use std::io::Write as _;
    let dist = format!("{PKG}-{VER}.dist-info");
    let mut members: Vec<(String, Vec<u8>)> = vec![
        ("six.py".into(), module.to_vec()),
        (
            format!("{dist}/METADATA"),
            format!("Metadata-Version: 2.1\nName: {PKG}\nVersion: {VER}\nSummary: six\n\n")
                .into_bytes(),
        ),
        (
            format!("{dist}/WHEEL"),
            b"Wheel-Version: 1.0\nGenerator: socket-patch-tests\nRoot-Is-Purelib: true\n\
              Tag: py2-none-any\nTag: py3-none-any\n"
                .to_vec(),
        ),
        (format!("{dist}/top_level.txt"), b"six\n".to_vec()),
    ];
    let mut record = String::new();
    for (name, bytes) in &members {
        let digest = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes));
        record.push_str(&format!("{name},sha256={digest},{}\n", bytes.len()));
    }
    record.push_str(&format!("{dist}/RECORD,,\n"));
    members.push((format!("{dist}/RECORD"), record.into_bytes()));
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, bytes) in members {
            writer.start_file(name, opts).unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap();
    }
    buf.into_inner()
}

// ── the patch service the CLI writes against ────────────────────────────

/// The authenticated routes `scan` uses for the one six patch — batch
/// discovery, per-package search, the hosted grant, the view with inline
/// blob content — plus the hosted wheel itself (what `poetry install`
/// downloads for a redirected lock). Records for the VEX runs come from a
/// separate [`PatchApi`], so its request counts are the VEX runs' alone.
struct PatchService {
    rt: tokio::runtime::Runtime,
    server: wiremock::MockServer,
}

impl PatchService {
    fn start(uuid: &str, pristine: &[u8], patched: &[u8], wheel: &[u8]) -> Self {
        use base64::Engine as _;
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, ResponseTemplate};
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(wiremock::MockServer::start());
        let artifact_path = format!("/patch/pypi/{PKG}/{VER}/{TOKEN}/{uuid}/{WHEEL}");
        let artifact_url = format!("{}{artifact_path}", server.uri());
        let mut full_view = record_view(uuid, pristine, patched);
        full_view["files"]["six.py"]["blobContent"] =
            Value::String(base64::engine::general_purpose::STANDARD.encode(patched));
        let sha = hex::encode(Sha256::digest(wheel));
        rt.block_on(async {
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "packages": [{
                        "purl": PURL,
                        "patches": [{
                            "uuid": uuid, "purl": API_PURL, "tier": "free",
                            "cveIds": [CVE], "ghsaIds": [GHSA], "severity": "HIGH",
                            "title": "six poetry e2e patch"
                        }]
                    }],
                    "canAccessPaidPatches": false,
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path_regex(format!(
                    "^/v0/orgs/{ORG}/patches/by-package/.+$"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "patches": [{
                        "uuid": uuid, "purl": API_PURL,
                        "publishedAt": "2026-09-01T00:00:00Z",
                        "description": "six poetry e2e patch", "license": "MIT",
                        "tier": "free", "vulnerabilities": {}
                    }],
                    "canAccessPaidPatches": false,
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/v0/orgs/{ORG}/patches/package")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "results": { uuid: {
                        "status": "granted",
                        "url": artifact_url,
                        "purl": PURL,
                        "artifacts": [{
                            "kind": "tarball",
                            "url": artifact_url,
                            "integrity": { "sha256": sha }
                        }],
                        "registryOverride": null
                    } }
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(full_view))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path(artifact_path))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(wheel.to_vec()))
                .mount(&server)
                .await;
        });
        PatchService { rt, server }
    }

    fn uri(&self) -> String {
        self.server.uri()
    }

    /// Requests for the hosted wheel (what proves Poetry downloaded it).
    fn wheel_downloads(&self) -> usize {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path().ends_with(".whl"))
            .count()
    }
}

/// The patch view (record) for `uuid`: `six.py` pristine → patched.
fn record_view(uuid: &str, pristine: &[u8], patched: &[u8]) -> Value {
    json!({
        "uuid": uuid,
        "purl": API_PURL,
        "publishedAt": "Tue, 01 Sep 2026 00:00:00 GMT",
        "files": { "six.py": {
            "beforeHash": git_sha256(pristine),
            "afterHash": git_sha256(patched),
        } },
        "vulnerabilities": { GHSA: {
            "cves": [CVE], "summary": "six advisory", "severity": "high", "description": "d"
        } },
        "description": "six poetry e2e patch",
        "license": "MIT",
        "tier": "free",
    })
}

/// `socket-patch <args> --json --yes` in `project`, authenticated against
/// `service` → (exit, envelope).
fn socket_patch(
    project: &Path,
    poetry: &Poetry,
    service: &PatchService,
    args: &[&str],
) -> (Option<i32>, Value) {
    let mut cmd = Command::new(binary());
    for (key, _) in std::env::vars_os() {
        let k = key.to_string_lossy();
        if k.starts_with("SOCKET_") || k.starts_with("POETRY_") || k == "VIRTUAL_ENV" {
            cmd.env_remove(&key);
        }
    }
    for (key, value) in poetry.cli_envs() {
        cmd.env(key, value);
    }
    let out = cmd
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .current_dir(project)
        .args(args)
        .args(["--json", "--yes", "--cwd"])
        .arg(project)
        .args([
            "--api-url",
            &service.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG,
        ])
        .output()
        .expect("invoke socket-patch");
    let env = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{args:?}: stdout is not JSON ({e}): {}", text(&out)));
    (out.status.code(), env)
}

// ── VEX steps ───────────────────────────────────────────────────────────

struct VexCtx<'a> {
    project: &'a Path,
    poetry: &'a Poetry,
    /// `--patch-server-url` (hosted: the mock service's origin).
    patch_server: Option<String>,
}

impl VexCtx<'_> {
    fn run(&self, api: &PatchApi, via: VexVia, offline: bool, extra: &[&str]) -> VexOutcome {
        let output = self.project.join("out.vex.json");
        let _ = std::fs::remove_file(&output);
        let mut run = VexRun {
            offline,
            proxy_url: Some(api.uri()),
            patch_server_url: self.patch_server.clone(),
            product: Some(PRODUCT.to_string()),
            envs: self.poetry.cli_envs(),
            ..VexRun::default()
        }
        .via(via);
        for arg in extra {
            run = run.arg(*arg);
        }
        run_vex(&binary(), self.project, &run)
    }

    fn standalone(&self, api: &PatchApi, offline: bool, extra: &[&str]) -> VexOutcome {
        self.run(api, VexVia::Vex, offline, extra)
    }
}

fn attested(what: &str, out: &VexOutcome, uuid: &str, marker: Marker) {
    assert_eq!(out.code, Some(0), "{what}: {out}");
    let stmts = assert_attested(out.doc(), PURL, uuid, marker, &[(GHSA, &[CVE])]);
    assert_eq!(stmts.len(), 1, "{what}: {out}");
    assert_eq!(
        out.doc()["statements"].as_array().map(Vec::len),
        Some(1),
        "{what}: {out}"
    );
}

fn omitted(what: &str, out: &VexOutcome, reason: &str) {
    assert_eq!(out.code, Some(1), "{what}: {out}");
    assert_eq!(
        out.envelope["error"]["code"], "no_applicable_patches",
        "{what}: {out}"
    );
    assert_not_attested(&out.envelope, PURL, reason);
    assert_absent(out.doc.as_ref(), PURL);
}

/// Steps (1)–(4) over an installed manifest-less checkout `ctx.project`
/// whose committed wiring is the patch `uuid`; `pristine_lock` is the
/// registry lock the revert step writes back.
fn manifestless_vex_matrix(
    ctx: &VexCtx<'_>,
    uuid: &str,
    marker: Marker,
    pristine_lock: &str,
    pristine: &[u8],
    patched: &[u8],
) {
    let label = format!("poetry {} {marker:?}", ctx.poetry.version);
    let api = PatchApi::start(vec![(uuid.into(), record_view(uuid, pristine, patched))]);
    let unwired = match marker {
        Marker::Redirected => "redirect_unwired",
        _ => "vendor_unwired",
    };

    // (1) manifest deleted, ledger kept: offline from the ledger, online.
    strip_manifest(ctx.project);
    let out = ctx.standalone(&api, true, &[]);
    attested(&format!("{label} (1) ledger offline"), &out, uuid, marker);
    api.assert_no_requests();
    let out = ctx.standalone(&api, false, &[]);
    attested(&format!("{label} (1) online"), &out, uuid, marker);

    // (2) ledgers deleted too: lockfile discovery + the API record.
    let socket_vendor = ctx.project.join(".socket/vendor");
    let ledgers: Vec<(PathBuf, Vec<u8>)> = ["state.json", "redirect-state.json"]
        .iter()
        .map(|f| socket_vendor.join(f))
        .filter(|p| p.is_file())
        .map(|p| {
            let bytes = std::fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect();
    assert!(!ledgers.is_empty(), "{label}: the writer left a ledger");
    strip_ledgers(ctx.project);
    let before = api.view_requests(uuid);
    let out = ctx.standalone(&api, false, &[]);
    attested(&format!("{label} (2) no ledgers"), &out, uuid, marker);
    assert!(
        api.view_requests(uuid) > before,
        "{label} (2): the record came from the API"
    );
    let out = ctx.standalone(&api, false, &["--no-verify"]);
    attested(&format!("{label} (2) --no-verify"), &out, uuid, marker);
    let mut embedded = vec![VexVia::Apply];
    if marker == Marker::Vendored {
        embedded.push(VexVia::Vendor);
    }
    for via in embedded {
        let out = ctx.run(&api, via, false, &[]);
        assert_eq!(out.code, Some(0), "{label} (2) {via:?} --vex: {out}");
        assert_eq!(out.envelope["status"], "noManifest", "{label}: {out}");
        assert_attested(out.doc(), PURL, uuid, marker, &[(GHSA, &[CVE])]);
    }
    assert!(
        !ctx.project.join(".socket/manifest.json").exists(),
        "{label}: VEX never writes the manifest"
    );

    // (3) offline with no ledgers: the record is unavailable, zero network.
    let seen = api.request_count();
    let out = ctx.standalone(&api, true, &[]);
    omitted(&format!("{label} (3) offline"), &out, "record_unavailable");
    assert_eq!(
        api.request_count(),
        seen,
        "{label} (3): --offline made a request"
    );

    // (4) the lock reverted to the registry, ledgers + artifacts kept.
    for (path, bytes) in &ledgers {
        std::fs::write(path, bytes).unwrap();
    }
    std::fs::write(ctx.project.join("poetry.lock"), pristine_lock).unwrap();
    for extra in [&[][..], &["--no-verify"][..]] {
        for offline in [true, false] {
            let out = ctx.standalone(&api, offline, extra);
            omitted(
                &format!("{label} (4) reverted offline={offline} {extra:?}"),
                &out,
                unwired,
            );
        }
    }
    let out = ctx.run(&api, VexVia::Apply, false, &["--vex-no-verify"]);
    assert_eq!(out.code, Some(1), "{label} (4) apply --vex: {out}");
    assert_eq!(
        out.envelope["error"]["code"], "no_applicable_patches",
        "{label} (4) apply --vex: {out}"
    );
    assert!(out.doc.is_none(), "{label} (4) apply --vex: {out}");
}

// ════════════════════════════════════════════════════════════════════════
// HOSTED
// ════════════════════════════════════════════════════════════════════════

#[test]
#[ignore = "real Poetry + PyPI; run by the CI e2e matrix per Poetry release"]
fn poetry_hosted_fresh_install_then_manifestless_vex() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let Some(poetry) = Poetry::find(&home) else {
        return;
    };
    let project = tmp.path().join("proj");
    let Some((pristine, pristine_lock)) =
        locked_project(&poetry, &project, &tmp.path().join("probe"))
    else {
        return;
    };
    let mut patched = pristine.clone();
    patched.extend_from_slice(MARKER);
    let wheel = build_wheel(&patched);
    let service = PatchService::start(HOSTED_UUID, &pristine, &patched, &wheel);
    empty_venv(&project);

    // Our CLI writes the hosted wiring on the lock-only checkout; the
    // same-run VEX attests from the lock's sha256 pin.
    let embedded = project.join("embedded.vex.json");
    let (code, env) = socket_patch(
        &project,
        &poetry,
        &service,
        &[
            "scan",
            "--redirect",
            "--vex",
            embedded.to_str().unwrap(),
            "--vex-product",
            PRODUCT,
        ],
    );
    assert_eq!(code, Some(0), "scan --redirect: {env}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env}");
    let lock = std::fs::read_to_string(project.join("poetry.lock")).unwrap();
    let sha = hex::encode(Sha256::digest(&wheel));
    assert!(
        lock.contains(&format!("{}/patch/pypi/six/", service.uri())),
        "{lock}"
    );
    assert!(lock.contains("type = \"url\""), "{lock}");
    assert!(lock.contains(&sha), "{lock}");
    assert_eq!(
        std::fs::read_to_string(project.join("pyproject.toml")).unwrap(),
        PYPROJECT
    );
    assert!(!project.join(".socket/manifest.json").exists());
    let doc: Value = serde_json::from_slice(&std::fs::read(&embedded).unwrap()).unwrap();
    assert_attested(
        &doc,
        PURL,
        HOSTED_UUID,
        Marker::Redirected,
        &[(GHSA, &[CVE])],
    );

    // Poetry < 1.4 keeps an already-installed same-version package; the
    // writer says so (and, for lock 1.0, names the pip window below).
    let stale_risk = env["redirect"]["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|w| w["code"] == "redirect_poetry_stale_install_risk");
    assert_eq!(
        stale_risk.is_some(),
        poetry.major_minor() < (1, 4),
        "stale-install advisory iff Poetry < 1.4: {env}"
    );

    // A fresh checkout installs the PATCHED wheel from the patch service.
    let fresh = tmp.path().join("fresh");
    fresh_checkout(&project, &fresh);
    if poetry.major_minor() == (1, 0) {
        // Poetry 1.0 installs url sources through the venv's pip, and pip
        // 22.3–23.0 (the ensurepip pip of Python 3.8.20) misparse the lock's
        // `#sha256=<hex>&` fragment and refuse the install — the documented,
        // fail-closed window the advisory names. Seed the venv with a pip
        // outside it, as the advisory tells users to.
        let note = stale_risk.map(|w| w.to_string()).unwrap_or_default();
        assert!(
            note.contains("pip 22.3"),
            "lock-1.0 pip window advisory: {env}"
        );
        seed_venv_with_modern_pip(&poetry, &fresh);
    }
    let before = service.wheel_downloads();
    let out = poetry.install(&fresh);
    assert!(
        out.status.success(),
        "poetry install (hosted): {}",
        text(&out)
    );
    assert!(
        service.wheel_downloads() > before,
        "the hosted wheel was downloaded"
    );
    let installed = installed_six(&fresh).expect("six installed");
    assert_eq!(
        std::fs::read(&installed).unwrap(),
        patched,
        "patched bytes installed"
    );
    assert_eq!(python_oracle(&fresh), "1");
    assert_eq!(
        std::fs::read_to_string(fresh.join("poetry.lock")).unwrap(),
        lock,
        "poetry install leaves the redirected lock alone"
    );

    let ctx = VexCtx {
        project: &fresh,
        poetry: &poetry,
        patch_server: Some(service.uri()),
    };
    manifestless_vex_matrix(
        &ctx,
        HOSTED_UUID,
        Marker::Redirected,
        &pristine_lock,
        &pristine,
        &patched,
    );
    // The installed tree is the evidence: once it is pristine again, the
    // live wiring no longer attests.
    std::fs::write(fresh.join("poetry.lock"), &lock).unwrap();
    std::fs::write(&installed, &pristine).unwrap();
    let api = PatchApi::start(vec![(
        HOSTED_UUID.into(),
        record_view(HOSTED_UUID, &pristine, &patched),
    )]);
    strip_ledgers(&fresh);
    let out = ctx.standalone(&api, false, &[]);
    omitted("hosted pristine install", &out, "not_applied");

    // The real rollback in the writer's project restores every byte.
    let (code, env) = socket_patch(&project, &poetry, &service, &["rollback"]);
    assert_eq!(code, Some(0), "rollback: {env}");
    assert_eq!(
        std::fs::read_to_string(project.join("poetry.lock")).unwrap(),
        pristine_lock,
        "rollback restores the pristine lock"
    );
}

// ════════════════════════════════════════════════════════════════════════
// VENDORED
// ════════════════════════════════════════════════════════════════════════

#[test]
#[ignore = "real Poetry + PyPI; run by the CI e2e matrix per Poetry release"]
fn poetry_vendored_fresh_install_then_manifestless_vex() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let Some(poetry) = Poetry::find(&home) else {
        return;
    };
    let project = tmp.path().join("proj");
    let Some((pristine, pristine_lock)) =
        locked_project(&poetry, &project, &tmp.path().join("probe"))
    else {
        return;
    };
    let mut patched = pristine.clone();
    patched.extend_from_slice(MARKER);
    let service = PatchService::start(VENDORED_UUID, &pristine, &patched, &build_wheel(&patched));

    // The vendored writer rebuilds the wheel from the installed dist.
    let out = poetry.install(&project);
    assert!(out.status.success(), "pristine install: {}", text(&out));
    let embedded = project.join("embedded.vex.json");
    let (code, env) = socket_patch(
        &project,
        &poetry,
        &service,
        &[
            "scan",
            "--vendor",
            "--vendor-source",
            "build",
            "--vex",
            embedded.to_str().unwrap(),
            "--vex-product",
            PRODUCT,
        ],
    );
    assert_eq!(code, Some(0), "scan --vendor: {env}");
    let rel = format!(".socket/vendor/pypi/{VENDORED_UUID}/{WHEEL}");
    assert!(
        project.join(&rel).is_file(),
        "vendored wheel committed: {env}"
    );
    let lock = std::fs::read_to_string(project.join("poetry.lock")).unwrap();
    assert!(lock.contains("type = \"file\""), "{lock}");
    assert!(lock.contains(&rel), "{lock}");
    let wheel_sha = hex::encode(Sha256::digest(std::fs::read(project.join(&rel)).unwrap()));
    assert!(
        lock.contains(&wheel_sha),
        "the lock pins the committed wheel:\n{lock}"
    );
    assert!(project.join(".socket/manifest.json").is_file());
    assert!(project.join(".socket/vendor/state.json").is_file());
    let doc: Value = serde_json::from_slice(&std::fs::read(&embedded).unwrap()).unwrap();
    assert_attested(
        &doc,
        PURL,
        VENDORED_UUID,
        Marker::Vendored,
        &[(GHSA, &[CVE])],
    );

    // Red probe: the fresh install genuinely depends on the committed wheel.
    let red = tmp.path().join("red");
    fresh_checkout(&project, &red);
    std::fs::remove_dir_all(red.join(".socket/vendor")).unwrap();
    let out = poetry.install(&red);
    assert!(
        !out.status.success() || installed_six(&red).is_none(),
        "RED PROBE VACUOUS: install succeeded without .socket/vendor: {}",
        text(&out)
    );

    // A fresh checkout installs the PATCHED wheel from `.socket/vendor`.
    let fresh = tmp.path().join("fresh");
    fresh_checkout(&project, &fresh);
    let out = poetry.install(&fresh);
    assert!(
        out.status.success(),
        "poetry install (vendored): {}",
        text(&out)
    );
    let installed = installed_six(&fresh).expect("six installed");
    assert_eq!(
        std::fs::read(&installed).unwrap(),
        patched,
        "patched bytes installed"
    );
    assert_eq!(python_oracle(&fresh), "1");
    if poetry.major_minor() >= (1, 6) {
        let out = poetry.run(&fresh, &["check", "--lock"]);
        assert!(out.status.success(), "poetry check --lock: {}", text(&out));
    }

    let ctx = VexCtx {
        project: &fresh,
        poetry: &poetry,
        patch_server: None,
    };
    manifestless_vex_matrix(
        &ctx,
        VENDORED_UUID,
        Marker::Vendored,
        &pristine_lock,
        &pristine,
        &patched,
    );
    // A tampered committed wheel member is never attested.
    std::fs::write(fresh.join("poetry.lock"), &lock).unwrap();
    std::fs::write(fresh.join(&rel), build_wheel(b"tampered = 1\n")).unwrap();
    let api = PatchApi::start(vec![(
        VENDORED_UUID.into(),
        record_view(VENDORED_UUID, &pristine, &patched),
    )]);
    strip_ledgers(&fresh);
    let out = ctx.standalone(&api, false, &[]);
    omitted("tampered wheel", &out, "vendor_hash_mismatch");

    // The real revert in the writer's project restores every byte.
    let (code, env) = socket_patch(&project, &poetry, &service, &["vendor", "--revert"]);
    assert_eq!(code, Some(0), "vendor --revert: {env}");
    assert_eq!(
        std::fs::read_to_string(project.join("poetry.lock")).unwrap(),
        pristine_lock,
        "revert restores the pristine lock"
    );
    assert!(!project
        .join(".socket/vendor/pypi")
        .join(VENDORED_UUID)
        .exists());
}
