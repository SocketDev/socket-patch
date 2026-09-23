#![cfg(unix)]
//! Real-Python capstone e2e for `socket-patch vendor` — the committability
//! proofs for BOTH pypi wiring flavors:
//!
//! * **uv project** (`uv.lock` present): paired `[tool.uv.sources]` pyproject
//!   entry + surgical uv.lock rewrite. Proofs: `uv lock --check` passes,
//!   plain `uv sync` leaves the lock byte-identical AND installs the patched
//!   wheel, and a fresh checkout (pyproject + uv.lock + .socket only) with an
//!   EMPTY UV_CACHE_DIR installs via `uv sync --frozen --offline`.
//! * **requirements.txt** (pip / `uv pip`): the exact pin line becomes
//!   `./<wheel> --hash=sha256:<hex>  # socket-patch vendor: …`. Proofs: a
//!   fresh checkout (requirements.txt + .socket only) installs with
//!   `pip install --no-index -r requirements.txt` FROM THE PROJECT ROOT
//!   (both tools resolve bare paths against the CWD — spike claim 3), and
//!   the same wheel installs via `uv pip install --no-index -r`.
//!
//! The requirements flavor also ends with the manifest-less VEX steps
//! (`vex_pipenv_pip_steps`) over the installed fresh checkout: manifest
//! deleted, ledgers deleted, `--offline` (`record_unavailable`, zero
//! requests), the pin reverted to the registry (`vendor_unwired`,
//! `--no-verify` too) and `apply --vex`.
//!
//! Both flavors finish with the revert proof: pyproject/uv.lock/
//! requirements.txt byte-identical to the pre-vendor snapshots and
//! `.socket/vendor/` gone.
//!
//! The uv flavor also has a `get <uuid> --mode vendored` twin (v3.6): the
//! SAME vendor engine driven through get's uuid path against a wiremock
//! `view/{uuid}` (record + inline blob content served by the API instead of
//! a locally staged manifest/blob), ending in the same fresh-checkout
//! frozen-offline proof.
//!
//! Network is used for fixture setup only (installing six==1.16.0); the
//! vendor runs are `--offline` against a locally staged blob, and the
//! fresh-checkout installs are `--no-index` / `--offline` with empty caches.
//!
//! Skips (println) when python3/uv are missing or the fixture install cannot
//! reach PyPI; all assertions after that are hard. uv discovery tries PATH
//! then `~/.local/bin/uv`.
//!
//! Manifest-less VEX: both uv capstones end in the shared matrix
//! (`vex_e2e_common/uv.rs` [`uv_vex::manifestless_matrix`]) over their fresh
//! checkout — `.socket/manifest.json` deleted, `vex` attests `(vendored)`
//! with and without the ledgers, `record_unavailable` offline with zero
//! requests, embedded `apply --vex` / `vendor --vex`, and NOT attested once
//! the pair is reverted with the ledger + wheel left behind. The `#[ignore]`d
//! `vendored_uv_*` lanes drive every other uv lock shape (constraints,
//! transitive override, script lock, pylock via `uv export` / `uv pip
//! compile` / `pip lock`) end to end with the uv under test.
//!
//! uv release for the uv tests: `SOCKET_PATCH_UV_E2E_BIN` / `_VERSION` /
//! `_PYTHON` / `_REQUIRED` (`scripts/uv-vex-matrix.sh` runs every uv 0.N
//! line); the two capstones need `uv lock --check` and report `n/a` on
//! older releases, whose lanes run in the `vendored_uv_*` tests. The pip
//! capstones below keep their own `uv` discovery.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "vex_e2e_common/uv.rs"]
mod uv_vex;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[path = "vex_pipenv_pip_steps/mod.rs"]
mod vex_pipenv_pip_steps;

const UUID: &str = "4d5e6f70-8192-4a1b-8c2d-0123456789ab";
const PURL: &str = "pkg:pypi/six@1.16.0";
/// Org slug the get twin passes on the argv (and the view mock's path).
const ORG: &str = "test-org";
/// Appended to the installed `six.py` by the synthetic patch.
const PATCH_SUFFIX: &str = "\n# SOCKET-PATCHED\nSOCKET_PATCHED = 1\n";
/// The staged record's advisory (what the manifest-less VEX must attest).
const VEX_VULNS: &[(&str, &[&str])] = &[("GHSA-vend-pypi-real", &["CVE-2024-88888"])];

/// The manifest-less VEX steps over the installed fresh checkout `fresh`
/// of the vendored requirements project (records served by a mock patch
/// API: the staged patch's `six.py` afterHash + advisory), `original`
/// being the registry requirements the revert step restores.
fn manifestless_vex(fresh: &Path, what: &str, patched: &[u8], original: &[u8]) {
    let view =
        vex_e2e_common::patch_view(UUID, PURL, &[("six.py", &git_sha256(patched))], VEX_VULNS);
    vex_pipenv_pip_steps::run_manifestless_steps(&vex_pipenv_pip_steps::Steps {
        what: what.to_string(),
        project: fresh,
        purl: PURL,
        uuid: UUID,
        marker: vex_e2e_common::Marker::Vendored,
        vulns: Some(VEX_VULNS),
        records: vex_pipenv_pip_steps::Records::Mock(vec![(UUID.to_string(), view)]),
        patch_server_url: None,
        product: "pkg:pypi/app@0.1.0",
        revert: &|p: &Path| std::fs::write(p.join("requirements.txt"), original).unwrap(),
        envs: Vec::new(),
        on_step: None,
        expect_verified: true,
    });
}

/// Oracle: prints `1` iff the patched module is the one imported.
const ORACLE: &str = "import six; print(six.SOCKET_PATCHED)";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

/// Run socket-patch with ambient `SOCKET_*` + `VIRTUAL_ENV` scrubbed
/// (`VIRTUAL_ENV` is a python-crawler discovery input and must not leak from
/// the developer's shell).
fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") && k.to_string_lossy() != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Resolve a Python interpreter (mirrors the core crawler's probe order).
fn find_python() -> Option<&'static str> {
    for cmd in ["python3", "python"] {
        let mut probe = Command::new(cmd);
        probe
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // Isolated so a pyenv shim resolves the same way here as in the
        // fixture installs below (probe and install must not disagree).
        cache_env::isolate(&mut probe);
        let ok = probe.status().map(|s| s.success()).unwrap_or(false);
        if ok {
            return Some(cmd);
        }
    }
    None
}

/// The uv under test for the two uv capstones (`SOCKET_PATCH_UV_E2E_*`,
/// else PATH / `~/.local/bin/uv`), plus the `UV_PYTHON` pin to pass it.
/// `None` after printing why (a skip, or `n/a` for a release without `uv
/// lock --check`); panics under `SOCKET_PATCH_UV_E2E_REQUIRED` when uv is
/// missing.
fn capstone_uv(tag: &str) -> Option<(PathBuf, Option<String>)> {
    let uv = match uv_vex::uv_under_test() {
        Ok(uv) => uv,
        Err(why) => {
            uv_vex::skip(&format!("e2e_vendor_pypi_build({tag})"), &why);
            return None;
        }
    };
    if !uv.help_has(&["lock"], "--check") {
        println!(
            "UV-VEX uv={} mode=vendored lane=project({}) step=all result=n/a (no `uv lock \
             --check`; the vendored_uv_project lane covers this release)",
            uv.version,
            if tag == "uv" { "vendor" } else { "get-uuid" }
        );
        return None;
    }
    let python = uv.python.as_ref().map(|p| p.display().to_string());
    Some((uv.exe, python))
}

/// Resolve `uv`: PATH first, then `~/.local/bin/uv` (the standalone
/// installer's default location).
fn find_uv() -> Option<PathBuf> {
    let mut probe = Command::new("uv");
    probe
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    cache_env::isolate(&mut probe);
    let on_path = probe.status().map(|s| s.success()).unwrap_or(false);
    if on_path {
        return Some(PathBuf::from("uv"));
    }
    let home = std::env::var_os("HOME")?;
    let candidate = Path::new(&home).join(".local/bin/uv");
    candidate.is_file().then_some(candidate)
}

/// Run a toolchain command with ambient python/uv/pip env scrubbed —
/// `PYTHON*` (a `PYTHONPATH` shadow hijacks the marker oracle), `UV_*`
/// (`UV_PROJECT_ENVIRONMENT` moves the venv away from `.venv`), `PIP_*`,
/// and `VIRTUAL_ENV` are all toolchain behavior inputs and must not leak
/// from the developer's shell. Scrub BEFORE seeding the explicit env — the
/// last env call wins.
///
/// Cache isolation goes in the middle. The uv half of this file always passed
/// an explicit `UV_CACHE_DIR`; the pip half passed an empty env slice, so pip
/// used the developer's own cache. [`cache_env::isolate`] gives both halves a
/// sandboxed default, and the explicit per-test `UV_CACHE_DIR` — including
/// the deliberately EMPTY one the fresh-checkout proof relies on — still wins
/// because it is applied last.
fn tool(exe: &Path, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(exe);
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        let name = k.to_string_lossy();
        if name.starts_with("PYTHON") || name.starts_with("UV_") || name.starts_with("PIP_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cache_env::isolate(&mut cmd);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", exe.display()))
}

fn assert_tool_ok(out: &Output, context: &str) {
    assert!(
        out.status.success(),
        "{context} failed (exit {:?}).\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Locate `<venv>/lib/python3.X/site-packages` (PEP-405 Unix layout).
fn site_packages(venv: &Path) -> PathBuf {
    let lib = venv.join("lib");
    for entry in std::fs::read_dir(&lib)
        .unwrap_or_else(|e| panic!("venv lib dir at {}: {e}", lib.display()))
        .flatten()
    {
        let sp = entry.path().join("site-packages");
        if sp.is_dir() {
            return sp;
        }
    }
    panic!("no site-packages under {}", lib.display());
}

/// Stage the synthetic patch (manifest + blob) for the installed `six.py`,
/// returning the patched bytes. pypi manifest file keys are
/// site-packages-relative.
fn stage_patch(proj: &Path, installed_six: &Path) -> Vec<u8> {
    let orig = std::fs::read(installed_six).expect("installed six.py");
    assert!(
        !orig.ends_with(PATCH_SUFFIX.as_bytes()),
        "pristine install must not carry the marker"
    );
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    let socket = proj.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": { PURL: {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "six.py": {
                "beforeHash": git_sha256(&orig),
                "afterHash": git_sha256(&patched),
            }},
            "vulnerabilities": { "GHSA-vend-pypi-real": {
                "cves": ["CVE-2024-88888"],
                "summary": "capstone vex vuln",
                "severity": "high",
                "description": "d",
            }},
            "description": "capstone marker patch",
            "license": "MIT",
            "tier": "free",
        }}
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(&patched)), &patched).unwrap();
    patched
}

fn parse_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("vendor --json output is not JSON: {e}\nstdout:\n{stdout}"))
}

/// Assert the envelope reports exactly one applied vendor for [`PURL`].
fn assert_vendored_applied(env: &serde_json::Value) {
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["applied"], 1, "one package vendored: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");
    assert!(
        env["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == PURL),
        "expected an applied event for {PURL}: {env}"
    );
}

/// Which CLI front door vendors the patch. Both land on the SAME vendor
/// engine by construction (v3.6): `vendor` consumes the locally staged
/// `.socket/` manifest + blob fully offline, while `get <uuid> --mode
/// vendored` fetches the record from the mocked API (the uuid path is
/// exempt from installed narrowing, so only the `view/{uuid}` route is
/// needed), writes the manifest itself, and stages patch content in memory
/// — `.socket/blobs` must stay absent. `--vendor-source build` keeps the
/// get flow off the vendoring service (no grant/tarball mocks needed).
enum VendorDriver<'a> {
    VendorOffline,
    GetUuidVendored { api_url: &'a str },
}

/// The vendoring invocation of the capstones, parameterized by `driver`.
fn run_vendored(driver: &VendorDriver<'_>, proj: &Path) -> (i32, String, String) {
    match driver {
        VendorDriver::VendorOffline => run_socket(
            proj,
            &[
                "vendor",
                "--json",
                "--offline",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        ),
        VendorDriver::GetUuidVendored { api_url } => run_socket(
            proj,
            &[
                "get",
                UUID,
                "--mode",
                "vendored",
                "--json",
                "--yes",
                "--api-url",
                api_url,
                "--api-token",
                "fake",
                "--org",
                ORG,
                "--vendor-source",
                "build",
                "--cwd",
                proj.to_str().unwrap(),
            ],
        ),
    }
}

/// Mount `view/{UUID}` on the mock API: the patch record with REAL git-blob
/// hashes over the ACTUAL installed bytes plus inline base64 `blobContent`,
/// so `get --mode vendored` both saves the manifest record and stages the
/// after-bytes in memory (nothing is staged locally). The purl is the
/// suite's bare (unqualified) spelling and the file key is
/// site-packages-relative — exactly what [`stage_patch`]'s manifest carries.
async fn mount_view_mock(server: &MockServer, before: &[u8], after: &[u8]) {
    use base64::Engine as _;
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(after);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "six.py": {
                "beforeHash": git_sha256(before),
                "afterHash": git_sha256(after),
                "blobContent": blob_b64,
            }},
            "vulnerabilities": { "GHSA-vend-pypi-real": {
                "cves": ["CVE-2024-88888"],
                "summary": "capstone vex vuln",
                "severity": "high",
                "description": "d",
            }},
            "description": "capstone marker patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

/// REAL uv fixture: write the six==1.16.0 pyproject, `uv lock`, `uv sync`
/// (network allowed here only). Returns false after printing the suite's
/// SKIP line — `tag` names the calling test — when PyPI is unreachable.
fn setup_uv_six_project(uv: &Path, proj: &Path, cache_env: &[(&str, &str)], tag: &str) -> bool {
    std::fs::write(
        proj.join("pyproject.toml"),
        "[project]\nname = \"vendor-capstone\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"six==1.16.0\"]\n",
    )
    .unwrap();
    let lock = tool(uv, proj, &["lock", "-q"], cache_env);
    if !lock.status.success() {
        println!(
            "SKIP e2e_vendor_pypi_build({tag}): `uv lock` failed (PyPI unreachable?):\n{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        return false;
    }
    let sync = tool(uv, proj, &["sync", "-q"], cache_env);
    if !sync.status.success() {
        println!(
            "SKIP e2e_vendor_pypi_build({tag}): `uv sync` failed (PyPI unreachable?):\n{}",
            String::from_utf8_lossy(&sync.stderr)
        );
        return false;
    }
    true
}

/// FRESH-CHECKOUT PROOF: pyproject + uv.lock + `.socket/` only travel to a
/// new dir; with an EMPTY UV_CACHE_DIR, `uv sync --frozen --offline` must
/// install the PATCHED six and leave uv.lock byte-identical to `lock_wired`
/// (spike claim 3).
fn assert_fresh_checkout_frozen_offline(
    uv: &Path,
    tmp: &Path,
    proj: &Path,
    lock_wired: &[u8],
    python: Option<&str>,
) {
    let fresh = tmp.join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("pyproject.toml"), fresh.join("pyproject.toml")).unwrap();
    std::fs::copy(proj.join("uv.lock"), fresh.join("uv.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_cache = tmp.join("fresh-uv-cache");
    let mut fresh_env: Vec<(&str, &str)> = vec![("UV_CACHE_DIR", fresh_cache.to_str().unwrap())];
    if let Some(py) = python {
        fresh_env.push(("UV_PYTHON", py));
    }
    let frozen = tool(
        uv,
        &fresh,
        &["sync", "--frozen", "--offline", "-q"],
        &fresh_env,
    );
    assert_tool_ok(
        &frozen,
        "fresh-checkout `uv sync --frozen --offline` (empty cache)",
    );
    assert_eq!(
        python_oracle(&fresh.join(".venv"), &fresh),
        "1",
        "fresh checkout must import the PATCHED six"
    );
    assert_eq!(
        std::fs::read(fresh.join("uv.lock")).unwrap(),
        lock_wired,
        "the frozen offline sync must leave uv.lock byte-identical"
    );
}

/// The single `.whl` inside the uuid dir (PEP 427 name derived from the
/// installed dist's WHEEL tags — don't hardcode the tag compression).
fn vendored_wheel(proj: &Path) -> PathBuf {
    let uuid_dir = proj.join(format!(".socket/vendor/pypi/{UUID}"));
    let wheels: Vec<PathBuf> = std::fs::read_dir(&uuid_dir)
        .unwrap_or_else(|e| panic!("uuid dir {}: {e}", uuid_dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "whl"))
        .collect();
    assert_eq!(
        wheels.len(),
        1,
        "exactly one vendored wheel expected in {}: {wheels:?}",
        uuid_dir.display()
    );
    wheels[0].clone()
}

/// Run the venv python against the marker oracle; returns trimmed stdout.
fn python_oracle(venv: &Path, cwd: &Path) -> String {
    let out = tool(&venv.join("bin/python"), cwd, &["-c", ORACLE], &[]);
    assert_tool_ok(&out, "python marker oracle");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// RED guards for the `tool()` hermeticity scrub: bake the hostile ambient
/// values in so this suite fails deterministically if the leak returns.
/// `UV_PROJECT_ENVIRONMENT` must be scrubbed (or `uv sync` builds the venv
/// away from `.venv` and `site_packages` panics) and the `PYTHONPATH` shadow
/// `six` must be scrubbed (or the marker oracle imports the shadow and every
/// patched-wheel assert dies on AttributeError). Constant paths only — both
/// tests share this process's environment.
fn bake_leak_guards() {
    let shadow = std::env::temp_dir().join("socket-e2e-pypi-shadow");
    std::fs::create_dir_all(&shadow).unwrap();
    std::fs::write(
        shadow.join("six.py"),
        "# ambient shadow module - no SOCKET_PATCHED attr\n",
    )
    .unwrap();
    std::env::set_var("PYTHONPATH", &shadow);
    std::env::set_var(
        "UV_PROJECT_ENVIRONMENT",
        std::env::temp_dir().join("socket-e2e-uv-env-leak"),
    );
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// The shared manifest-less VEX matrix (`uv_vex::manifestless_matrix`) over
/// `<tmp>/fresh`, the fresh checkout [`assert_fresh_checkout_frozen_offline`]
/// just installed PATCHED: manifest deleted → attested `(vendored)`; ledgers
/// deleted → attested from the lock + the API record; `--offline` →
/// `record_unavailable`, zero requests; `apply --vex` / `vendor --vex`
/// manifest-less → attested; the pair reverted to `registry` (ledger + wheel
/// kept) and reinstalled pristine by uv → `vendor_unwired`, `--no-verify` too.
fn manifestless_vex_tail(
    uv: &Path,
    tmp: &Path,
    patched: &[u8],
    registry: &[(&str, &[u8])],
    python: Option<&str>,
    tag: &str,
) {
    use vex_e2e_common::{git_sha256, patch_view, strip_manifest, PatchApi, VexRun, VexVia};
    let fresh = tmp.join("fresh");
    strip_manifest(&fresh);
    let vulns: &[(&str, &[&str])] = &[("GHSA-vend-pypi-real", &["CVE-2024-88888"])];
    let api = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(UUID, PURL, &[("six.py", &git_sha256(patched))], vulns),
    )]);
    let registry: Vec<(String, Vec<u8>)> = registry
        .iter()
        .map(|(f, b)| (f.to_string(), b.to_vec()))
        .collect();
    let reinstall_cache = tmp.join("reinstall-uv-cache");
    let version = String::from_utf8_lossy(&tool(uv, tmp, &["--version"], &[]).stdout)
        .split_whitespace()
        .nth(1)
        .unwrap_or("?")
        .to_string();
    uv_vex::manifestless_matrix(
        &uv_vex::Matrix {
            fresh: &fresh,
            purl: PURL,
            uuid: UUID,
            mode: uv_vex::Mode::Vendored,
            vulns,
            api: &api,
            patch_server: None,
            embedded: vec![
                ("apply --vex", VexRun::offline().via(VexVia::Apply)),
                ("vendor --vex", VexRun::offline().via(VexVia::Vendor)),
            ],
            registry: &registry,
            reinstall_registry: &|dir: &Path| {
                let _ = std::fs::remove_dir_all(dir.join(".venv"));
                let mut env: Vec<(&str, &str)> =
                    vec![("UV_CACHE_DIR", reinstall_cache.to_str().unwrap())];
                if let Some(py) = python {
                    env.push(("UV_PYTHON", py));
                }
                let out = tool(uv, dir, &["sync", "--frozen", "-q"], &env);
                assert_tool_ok(&out, "registry reinstall of the reverted pair");
                let probe = tool(
                    &dir.join(".venv/bin/python"),
                    dir,
                    &["-c", "import six; print(getattr(six, 'SOCKET_PATCHED', 0))"],
                    &[],
                );
                assert_tool_ok(&probe, "pristine oracle");
                String::from_utf8_lossy(&probe.stdout).trim().to_string()
            },
        },
        &|step, result| {
            println!(
                "UV-VEX uv={version} mode=vendored lane=project({tag}) step={step} result={result}"
            )
        },
    );
}

// ── the uv lanes (every lock shape, uv under test) ─────────────────────

fn vendored_lane(lane: uv_vex::Lane) {
    const SUITE: &str = "e2e_vendor_pypi_build";
    match uv_vex::uv_under_test() {
        Ok(uv) => uv_vex::run_lane(SUITE, &uv, uv_vex::Mode::Vendored, lane),
        Err(why) => uv_vex::skip(SUITE, &why),
    }
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn vendored_uv_project_manifestless_vex() {
    vendored_lane(uv_vex::Lane::Project);
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn vendored_uv_constraints_manifestless_vex() {
    vendored_lane(uv_vex::Lane::Constraints);
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn vendored_uv_transitive_override_manifestless_vex() {
    vendored_lane(uv_vex::Lane::Transitive);
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn vendored_uv_script_lock_manifestless_vex() {
    vendored_lane(uv_vex::Lane::Script);
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn vendored_uv_export_pylock_manifestless_vex() {
    vendored_lane(uv_vex::Lane::ExportPylock);
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn vendored_uv_pip_compile_pylock_manifestless_vex() {
    vendored_lane(uv_vex::Lane::CompilePylock);
}

#[test]
#[ignore = "real uv + pip + PyPI; run with --ignored"]
fn vendored_pip_lock_pylock_manifestless_vex() {
    vendored_lane(uv_vex::Lane::PipLock);
}

// ── capstone 1: uv project flavor ─────────────────────────────────────

#[test]
#[serial_test::serial]
fn uv_vendor_fresh_checkout_frozen_offline_and_revert() {
    let Some((uv, python)) = capstone_uv("uv") else {
        return;
    };
    bake_leak_guards();
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let cache = tmp.path().join("uv-cache");
    let mut cache_env: Vec<(&str, &str)> = vec![("UV_CACHE_DIR", cache.to_str().unwrap())];
    if let Some(py) = python.as_deref() {
        cache_env.push(("UV_PYTHON", py));
    }

    // REAL fixture: pyproject + uv lock + uv sync (network allowed here).
    if !setup_uv_six_project(&uv, &proj, &cache_env, "uv") {
        return;
    }

    let venv = proj.join(".venv");
    let installed_six = site_packages(&venv).join("six.py");
    let patched = stage_patch(&proj, &installed_six);

    let pyproject_before = std::fs::read(proj.join("pyproject.toml")).unwrap();
    let uvlock_before = std::fs::read(proj.join("uv.lock")).unwrap();

    // Vendor (offline; blob staged locally).
    let (code, stdout, stderr) = run_vendored(&VendorDriver::VendorOffline, &proj);
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_vendored_applied(&parse_envelope(&stdout));

    // Artifact + PAIRED wiring (pyproject AND lock — either half alone is a
    // silent no-op / silent revert, spike claims 7/9).
    let wheel = vendored_wheel(&proj);
    let wheel_rel = format!(
        ".socket/vendor/pypi/{UUID}/{}",
        wheel.file_name().unwrap().to_string_lossy()
    );
    let pyproject = std::fs::read_to_string(proj.join("pyproject.toml")).unwrap();
    assert!(
        pyproject.contains("[tool.uv.sources]") && pyproject.contains(&wheel_rel),
        "pyproject must gain the [tool.uv.sources] path entry:\n{pyproject}"
    );
    let uvlock = std::fs::read_to_string(proj.join("uv.lock")).unwrap();
    assert!(
        uvlock.contains(&wheel_rel),
        "uv.lock must resolve six from the vendored wheel path:\n{uvlock}"
    );

    // Real-toolchain VEX: attest the vendored patch against the vendored WHEEL
    // (the distinct pypi vendored-artifact verification path), `(vendored)`.
    let vex_path = proj.join("out.vex.json");
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vex",
            "--cwd",
            proj.to_str().unwrap(),
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            "pkg:pypi/app@1.0.0",
        ],
    );
    assert_eq!(code, 0, "vex failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let vex_doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
    let vex_stmts = vex_doc["statements"].as_array().unwrap();
    assert_eq!(
        vex_stmts.len(),
        1,
        "vendored pypi patch must be attested: {vex_doc}"
    );
    assert_eq!(vex_stmts[0]["vulnerability"]["name"], "GHSA-vend-pypi-real");
    assert_eq!(vex_stmts[0]["products"][0]["subcomponents"][0]["@id"], PURL);
    assert!(
        vex_stmts[0]["impact_statement"]
            .as_str()
            .unwrap()
            .contains("(vendored)"),
        "vendored attestation must carry the (vendored) marker: {vex_doc}"
    );

    // `uv lock --check` accepts the wired pair, and a plain `uv sync` both
    // leaves the lock byte-identical AND installs the patched wheel.
    let check = tool(&uv, &proj, &["lock", "--check"], &cache_env);
    assert_tool_ok(&check, "`uv lock --check` on the wired pair");
    let lock_wired = std::fs::read(proj.join("uv.lock")).unwrap();
    let resync = tool(&uv, &proj, &["sync", "-q"], &cache_env);
    assert_tool_ok(&resync, "plain `uv sync` on the wired pair");
    assert_eq!(
        std::fs::read(proj.join("uv.lock")).unwrap(),
        lock_wired,
        "plain `uv sync` must leave uv.lock byte-identical"
    );
    assert_eq!(
        python_oracle(&venv, &proj),
        "1",
        "uv sync must install the PATCHED vendored wheel"
    );

    // FRESH-CHECKOUT PROOF: pyproject + uv.lock + .socket only, EMPTY cache,
    // `uv sync --frozen --offline` (spike claim 3).
    assert_fresh_checkout_frozen_offline(&uv, tmp.path(), &proj, &lock_wired, python.as_deref());

    // Manifest-less VEX over that fresh checkout (a `vendor --detached` /
    // depscan checkout's shape once the manifest is gone).
    manifestless_vex_tail(
        &uv,
        tmp.path(),
        &patched,
        &[
            ("pyproject.toml", &pyproject_before),
            ("uv.lock", &uvlock_before),
        ],
        python.as_deref(),
        "vendor",
    );

    // REVERT PROOF: both halves of the pair restored byte-for-byte.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "revert envelope: {renv}");
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(proj.join("pyproject.toml")).unwrap(),
        pyproject_before,
        "revert must restore pyproject.toml byte-identical"
    );
    assert_eq!(
        std::fs::read(proj.join("uv.lock")).unwrap(),
        uvlock_before,
        "revert must restore uv.lock byte-identical"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
}

/// `get <uuid> --mode vendored` twin of the uv capstone above (v3.6): the
/// SAME vendor engine and wiring, driven through get's uuid path — exempt
/// from installed narrowing, so only the mocked `view/{uuid}` route is
/// needed. Unlike the capstone, NOTHING is staged locally: the record and
/// the patched content come from the API mock, get writes
/// `.socket/manifest.json` itself, and `.socket/blobs` must stay absent
/// (vendored downloads live in memory). Ends with the same fresh-checkout
/// `uv sync --frozen --offline` committability proof; the revert half stays
/// with the vendor capstone (same engine, same ledger).
// multi_thread: the CLI/uv subprocesses block a worker thread while wiremock
// keeps serving the view route on the others.
#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn uv_get_uuid_vendored_fresh_checkout_frozen_offline() {
    let Some((uv, python)) = capstone_uv("uv-get") else {
        return;
    };
    bake_leak_guards();
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let cache = tmp.path().join("uv-cache");
    let mut cache_env: Vec<(&str, &str)> = vec![("UV_CACHE_DIR", cache.to_str().unwrap())];
    if let Some(py) = python.as_deref() {
        cache_env.push(("UV_PYTHON", py));
    }

    // REAL fixture: pyproject + uv lock + uv sync (network allowed here).
    if !setup_uv_six_project(&uv, &proj, &cache_env, "uv-get") {
        return;
    }

    let venv = proj.join(".venv");
    let installed_six = site_packages(&venv).join("six.py");
    let orig = std::fs::read(&installed_six).expect("installed six.py");
    assert!(
        !orig.ends_with(PATCH_SUFFIX.as_bytes()),
        "pristine install must not carry the marker"
    );
    let patched: Vec<u8> = [orig.as_slice(), PATCH_SUFFIX.as_bytes()].concat();
    let pyproject_before = std::fs::read(proj.join("pyproject.toml")).unwrap();
    let uvlock_before = std::fs::read(proj.join("uv.lock")).unwrap();

    // The API serves the record: view/{uuid} with REAL git-blob hashes over
    // the ACTUAL installed bytes + inline blob content.
    let server = MockServer::start().await;
    mount_view_mock(&server, &orig, &patched).await;

    let (code, stdout, stderr) = run_vendored(
        &VendorDriver::GetUuidVendored {
            api_url: &server.uri(),
        },
        &proj,
    );
    assert_eq!(
        code, 0,
        "get --mode vendored failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // get's envelope nests the vendor Envelope under "vendor" and drops
    // "applied" (structurally zero — the nested apply never runs).
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["found"], 1, "envelope: {env}");
    assert_eq!(env["downloaded"], 1, "envelope: {env}");
    assert!(
        env.get("applied").is_none(),
        "vendored get must drop 'applied': {env}"
    );
    assert_vendored_applied(&env["vendor"]);

    // get wrote NO manifest and NO blobs: the ledger's detached entry, keyed
    // by the suite's bare pypi purl, is the record.
    assert!(
        !proj.join(".socket/manifest.json").exists(),
        "get --mode vendored must NOT write the manifest (the ledger is the record)"
    );
    let state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(proj.join(".socket/vendor/state.json")).expect("vendor ledger missing"),
    )
    .unwrap();
    assert_eq!(
        state["entries"][PURL]["uuid"], UUID,
        "the ledger must record the vendored patch under the bare purl: {state}"
    );
    assert_eq!(
        state["entries"][PURL]["detached"], true,
        "a get --mode vendored entry is detached: {state}"
    );
    assert!(
        !proj.join(".socket/blobs").exists(),
        "get --mode vendored must NOT persist blobs"
    );

    // Anti-vacuity: the record + blob content really came from the API.
    let view_hits = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().contains(&format!("/patches/view/{UUID}")))
        .count();
    assert!(view_hits >= 1, "the view route must have been consulted");

    // Same artifact + PAIRED wiring contract as the vendor capstone.
    let wheel = vendored_wheel(&proj);
    let wheel_rel = format!(
        ".socket/vendor/pypi/{UUID}/{}",
        wheel.file_name().unwrap().to_string_lossy()
    );
    let pyproject = std::fs::read_to_string(proj.join("pyproject.toml")).unwrap();
    assert!(
        pyproject.contains("[tool.uv.sources]") && pyproject.contains(&wheel_rel),
        "pyproject must gain the [tool.uv.sources] path entry:\n{pyproject}"
    );
    let uvlock = std::fs::read_to_string(proj.join("uv.lock")).unwrap();
    assert!(
        uvlock.contains(&wheel_rel),
        "uv.lock must resolve six from the vendored wheel path:\n{uvlock}"
    );

    // The wired pair is coherent, then the committability proof.
    let check = tool(&uv, &proj, &["lock", "--check"], &cache_env);
    assert_tool_ok(&check, "`uv lock --check` on the wired pair");
    let lock_wired = std::fs::read(proj.join("uv.lock")).unwrap();
    assert_fresh_checkout_frozen_offline(&uv, tmp.path(), &proj, &lock_wired, python.as_deref());

    // Manifest-less VEX over the fresh checkout: get wrote the manifest, the
    // checkout deletes it; the vendor ledger (+ wheel) and the pair remain.
    // Off the async runtime: the matrix's patch API owns its own runtime.
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                manifestless_vex_tail(
                    &uv,
                    tmp.path(),
                    &patched,
                    &[
                        ("pyproject.toml", &pyproject_before),
                        ("uv.lock", &uvlock_before),
                    ],
                    python.as_deref(),
                    "get-uuid",
                )
            })
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e))
    });
}

// ── capstone 2: requirements.txt flavor (pip + `uv pip`) ──────────────

#[test]
#[serial_test::serial]
fn pip_requirements_vendor_fresh_checkout_no_index_and_revert() {
    let Some(python) = find_python() else {
        println!("SKIP e2e_vendor_pypi_build(pip): no python3/python on PATH");
        return;
    };
    bake_leak_guards();
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("requirements.txt"), "six==1.16.0\n").unwrap();

    // REAL fixture: venv + pip install (network allowed here).
    let venv = proj.join(".venv");
    let mkvenv = tool(Path::new(python), &proj, &["-m", "venv", ".venv"], &[]);
    assert_tool_ok(&mkvenv, "python -m venv");
    let pip = venv.join("bin/pip");
    let install = tool(
        &pip,
        &proj,
        &[
            "install",
            "--disable-pip-version-check",
            "--quiet",
            "--no-cache-dir",
            "-r",
            "requirements.txt",
        ],
        &[],
    );
    if !install.status.success() {
        println!(
            "SKIP e2e_vendor_pypi_build(pip): `pip install six==1.16.0` failed (PyPI \
             unreachable?):\n{}",
            String::from_utf8_lossy(&install.stderr)
        );
        return;
    }

    let installed_six = site_packages(&venv).join("six.py");
    let patched = stage_patch(&proj, &installed_six);
    let requirements_before = std::fs::read(proj.join("requirements.txt")).unwrap();

    // Vendor (offline; blob staged locally).
    let (code, stdout, stderr) = run_vendored(&VendorDriver::VendorOffline, &proj);
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_vendored_applied(&parse_envelope(&stdout));

    // Artifact + the rewritten pin line (the exact spike-tested shape:
    // `./<wheel> --hash=sha256:<hex>  # socket-patch vendor: six==1.16.0`).
    let wheel = vendored_wheel(&proj);
    let wheel_rel = format!(
        ".socket/vendor/pypi/{UUID}/{}",
        wheel.file_name().unwrap().to_string_lossy()
    );
    let requirements = std::fs::read_to_string(proj.join("requirements.txt")).unwrap();
    let vendor_line = requirements
        .lines()
        .find(|l| l.contains(&wheel_rel))
        .unwrap_or_else(|| {
            panic!("requirements.txt must carry the vendored wheel line:\n{requirements}")
        });
    assert!(
        vendor_line.starts_with(&format!("./{wheel_rel}")),
        "the path line must be ./-prefixed and project-relative: {vendor_line}"
    );
    assert!(
        vendor_line.contains("--hash=sha256:"),
        "the path line must pin the wheel hash (hardens every install): {vendor_line}"
    );
    assert!(
        !requirements
            .lines()
            .any(|l| l.trim_start().starts_with("six==")),
        "the original registry pin must be gone:\n{requirements}"
    );

    // FRESH-CHECKOUT PROOF (pip): requirements.txt + .socket only; install
    // with --no-index FROM THE PROJECT ROOT (bare relative paths resolve
    // against the CWD in both pip and uv — spike claim 3).
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(
        proj.join("requirements.txt"),
        fresh.join("requirements.txt"),
    )
    .unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_venv = fresh.join(".venv");
    let mkvenv = tool(Path::new(python), &fresh, &["-m", "venv", ".venv"], &[]);
    assert_tool_ok(&mkvenv, "fresh python -m venv");
    let fresh_install = tool(
        &fresh_venv.join("bin/pip"),
        &fresh,
        &[
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "-r",
            "requirements.txt",
        ],
        &[],
    );
    assert_tool_ok(
        &fresh_install,
        "fresh-checkout `pip install --no-index -r requirements.txt` (project root)",
    );
    assert_eq!(
        python_oracle(&fresh_venv, &fresh),
        "1",
        "pip must install the PATCHED vendored wheel"
    );

    // `uv pip` variant against the same fresh checkout (hash-checked too).
    if let Some(uv) = find_uv() {
        let uv_cache = tmp.path().join("uv-pip-cache");
        let uv_venv = fresh.join(".venv-uv");
        let envs: Vec<(&str, &str)> = vec![("UV_CACHE_DIR", uv_cache.to_str().unwrap())];
        let mk = tool(&uv, &fresh, &["venv", "-q", ".venv-uv"], &envs);
        assert_tool_ok(&mk, "uv venv");
        let uv_venv_str = uv_venv.to_str().unwrap().to_string();
        let mut envs2: Vec<(&str, &str)> = vec![("UV_CACHE_DIR", uv_cache.to_str().unwrap())];
        envs2.push(("VIRTUAL_ENV", uv_venv_str.as_str()));
        let uv_install = tool(
            &uv,
            &fresh,
            &[
                "pip",
                "install",
                "-q",
                "--no-index",
                "-r",
                "requirements.txt",
            ],
            &envs2,
        );
        assert_tool_ok(
            &uv_install,
            "fresh-checkout `uv pip install --no-index -r requirements.txt` (project root)",
        );
        assert_eq!(
            python_oracle(&uv_venv, &fresh),
            "1",
            "uv pip must install the PATCHED vendored wheel"
        );
    } else {
        println!(
            "NOTE e2e_vendor_pypi_build(pip): `uv` not found, skipping the uv-pip variant \
             (pip half already proven)"
        );
    }

    // MANIFEST-LESS VEX over the installed fresh checkout.
    manifestless_vex(
        &fresh,
        "pip vendored fresh checkout",
        &patched,
        &requirements_before,
    );

    // REVERT PROOF.
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--revert",
            "--json",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code, 0,
        "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "revert envelope: {renv}");
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(proj.join("requirements.txt")).unwrap(),
        requirements_before,
        "revert must restore requirements.txt byte-identical to the pre-vendor snapshot"
    );
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
}

#[test]
#[serial_test::serial]
fn pip_vendored_requirements_evaluate_environment_markers() {
    let python = find_python().expect("Python is required for the pip marker regression");
    let tmp = tempfile::tempdir().unwrap();
    for (label, marker, installed) in [
        ("excluded", "python_version < '2'", false),
        ("included", "python_version >= '2'", true),
    ] {
        let project = tmp.path().join(label);
        std::fs::create_dir_all(&project).unwrap();
        assert_tool_ok(
            &tool(Path::new(python), &project, &["-m", "venv", ".venv"], &[]),
            "create source venv",
        );
        let venv = project.join(".venv");
        assert_tool_ok(
            &tool(
                &venv.join("bin/pip"),
                &project,
                &["install", "--disable-pip-version-check", "six==1.16.0"],
                &[],
            ),
            "install upstream six",
        );
        let patched = stage_patch(&project, &site_packages(&venv).join("six.py"));
        let original = format!("six==1.16.0 ; {marker}\n");
        std::fs::write(project.join("requirements.txt"), &original).unwrap();
        let (code, stdout, stderr) = run_vendored(&VendorDriver::VendorOffline, &project);
        assert_eq!(code, 0, "vendor failed: {stdout}\n{stderr}");
        assert_vendored_applied(&parse_envelope(&stdout));

        let fresh = project.join("fresh");
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::copy(
            project.join("requirements.txt"),
            fresh.join("requirements.txt"),
        )
        .unwrap();
        copy_dir_recursive(&project.join(".socket"), &fresh.join(".socket"));
        assert_tool_ok(
            &tool(Path::new(python), &fresh, &["-m", "venv", ".venv"], &[]),
            "create fresh venv",
        );
        let fresh_venv = fresh.join(".venv");
        assert_tool_ok(
            &tool(
                &fresh_venv.join("bin/pip"),
                &fresh,
                &[
                    "install",
                    "--disable-pip-version-check",
                    "--no-index",
                    "--require-hashes",
                    "-r",
                    "requirements.txt",
                ],
                &[],
            ),
            "install vendored marker requirement",
        );
        let probe = tool(
            &fresh_venv.join("bin/python"),
            &fresh,
            &[
                "-c",
                "import importlib.util; print(importlib.util.find_spec('six') is not None)",
            ],
            &[],
        );
        assert_tool_ok(&probe, "inspect installed package");
        assert_eq!(
            String::from_utf8_lossy(&probe.stdout).trim(),
            if installed { "True" } else { "False" }
        );
        if installed {
            assert_eq!(python_oracle(&fresh_venv, &fresh), "1");
            // The marker-carrying vendored line attests manifest-less too.
            manifestless_vex(
                &fresh,
                &format!("pip vendored marker {label}"),
                &patched,
                original.as_bytes(),
            );
        }
        let (code, stdout, stderr) =
            run_socket(&project, &["vendor", "--revert", "--offline", "--json"]);
        assert_eq!(code, 0, "revert failed: {stdout}\n{stderr}");
        assert_eq!(
            std::fs::read_to_string(project.join("requirements.txt")).unwrap(),
            original
        );
    }
}
