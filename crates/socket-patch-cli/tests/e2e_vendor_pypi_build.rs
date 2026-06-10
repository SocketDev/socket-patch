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
//! Both flavors finish with the revert proof: pyproject/uv.lock/
//! requirements.txt byte-identical to the pre-vendor snapshots and
//! `.socket/vendor/` gone.
//!
//! Network is used for fixture setup only (installing six==1.16.0); the
//! vendor runs are `--offline` against a locally staged blob, and the
//! fresh-checkout installs are `--no-index` / `--offline` with empty caches.
//!
//! Skips (println) when python3/uv are missing or the fixture install cannot
//! reach PyPI; all assertions after that are hard. uv discovery tries PATH
//! then `~/.local/bin/uv`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

const UUID: &str = "4d5e6f70-8192-4a1b-8c2d-0123456789ab";
const PURL: &str = "pkg:pypi/six@1.16.0";
/// Appended to the installed `six.py` by the synthetic patch.
const PATCH_SUFFIX: &str = "\n# SOCKET-PATCHED\nSOCKET_PATCHED = 1\n";
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
        if k.to_string_lossy().starts_with("SOCKET_") {
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
        let ok = Command::new(cmd)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            return Some(cmd);
        }
    }
    None
}

/// Resolve `uv`: PATH first, then `~/.local/bin/uv` (the standalone
/// installer's default location).
fn find_uv() -> Option<PathBuf> {
    let on_path = Command::new("uv")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if on_path {
        return Some(PathBuf::from("uv"));
    }
    let home = std::env::var_os("HOME")?;
    let candidate = Path::new(&home).join(".local/bin/uv");
    candidate.is_file().then_some(candidate)
}

/// Run a toolchain command with a scrubbed VIRTUAL_ENV + explicit env.
fn tool(exe: &Path, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(exe);
    cmd.args(args).current_dir(cwd);
    cmd.env_remove("VIRTUAL_ENV");
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
            "vulnerabilities": {},
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

// ── capstone 1: uv project flavor ─────────────────────────────────────

#[test]
fn uv_vendor_fresh_checkout_frozen_offline_and_revert() {
    let Some(uv) = find_uv() else {
        println!("SKIP e2e_vendor_pypi_build(uv): `uv` not on PATH or at ~/.local/bin/uv");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let cache = tmp.path().join("uv-cache");
    let cache_env: Vec<(&str, &str)> = vec![("UV_CACHE_DIR", cache.to_str().unwrap())];

    std::fs::write(
        proj.join("pyproject.toml"),
        "[project]\nname = \"vendor-capstone\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"six==1.16.0\"]\n",
    )
    .unwrap();

    // REAL fixture: uv lock + uv sync (network allowed here).
    let lock = tool(&uv, &proj, &["lock", "-q"], &cache_env);
    if !lock.status.success() {
        println!(
            "SKIP e2e_vendor_pypi_build(uv): `uv lock` failed (PyPI unreachable?):\n{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        return;
    }
    let sync = tool(&uv, &proj, &["sync", "-q"], &cache_env);
    if !sync.status.success() {
        println!(
            "SKIP e2e_vendor_pypi_build(uv): `uv sync` failed (PyPI unreachable?):\n{}",
            String::from_utf8_lossy(&sync.stderr)
        );
        return;
    }

    let venv = proj.join(".venv");
    let installed_six = site_packages(&venv).join("six.py");
    let _patched = stage_patch(&proj, &installed_six);

    let pyproject_before = std::fs::read(proj.join("pyproject.toml")).unwrap();
    let uvlock_before = std::fs::read(proj.join("uv.lock")).unwrap();

    // Vendor (offline; blob staged locally).
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
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
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(proj.join("pyproject.toml"), fresh.join("pyproject.toml")).unwrap();
    std::fs::copy(proj.join("uv.lock"), fresh.join("uv.lock")).unwrap();
    copy_dir_recursive(&proj.join(".socket"), &fresh.join(".socket"));

    let fresh_cache = tmp.path().join("fresh-uv-cache");
    let fresh_env: Vec<(&str, &str)> = vec![("UV_CACHE_DIR", fresh_cache.to_str().unwrap())];
    let frozen = tool(
        &uv,
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

// ── capstone 2: requirements.txt flavor (pip + `uv pip`) ──────────────

#[test]
fn pip_requirements_vendor_fresh_checkout_no_index_and_revert() {
    let Some(python) = find_python() else {
        println!("SKIP e2e_vendor_pypi_build(pip): no python3/python on PATH");
        return;
    };
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
    let _patched = stage_patch(&proj, &installed_six);
    let requirements_before = std::fs::read(proj.join("requirements.txt")).unwrap();

    // Vendor (offline; blob staged locally).
    let (code, stdout, stderr) = run_socket(
        &proj,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
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
