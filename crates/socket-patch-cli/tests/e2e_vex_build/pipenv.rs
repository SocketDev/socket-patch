//! Real-Pipenv capstone for manifest-less VEX: for every Pipenv calendar
//! major (one release per year line 2022..2026, the same releases
//! `pipenv-compatibility.yml` / `scripts/backtest-pipenv.py` pin), HOSTED
//! and VENDORED:
//!
//! 1. `pipenv install six==1.16.0` from PyPI (in-project venv) — the native
//!    Pipfile.lock that release writes;
//! 2. `socket-patch scan --mode hosted --vex` (hosted, on the lock-only
//!    checkout: the CI shape) / `scan --mode vendored --vendor-source build --vex`
//!    (vendored, from the pristine install) against a wiremock Socket API
//!    that also serves the patched wheel — the same-run document attests;
//! 3. a FRESH checkout of the committed state (Pipfile, Pipfile.lock,
//!    `.socket/`) installed with `pipenv install --deploy` — the release
//!    itself downloads the hosted wheel from the mock patch server /
//!    installs the committed vendored wheel, and `import six` proves the
//!    PATCHED bytes are what got installed;
//! 4. the manifest-less VEX matrix (`vex_pipenv_pip_real`): manifest
//!    deleted, ledgers deleted, `--offline` (zero requests), lock reverted
//!    to the registry (also `--no-verify`), `apply --vex`; plus the
//!    embedded `scan --mode hosted --vex` / `scan --mode vendored --vex` re-run on the
//!    manifest-less checkout.
//!
//! Versions: `SOCKET_PATCH_PIPENV_E2E_VERSIONS` (space / comma separated),
//! default every major below — the local loop. `#[ignore]`d (network:
//! PyPI) — run with `--ignored`; CI sets `SOCKET_PATCH_PIPENV_E2E_REQUIRED=1`
//! so a missing uv / failed bootstrap fails instead of skipping. Python:
//! 3.8 for Pipenv <= 2022 (its vendored pip predates 3.12), 3.12 after —
//! the backtest's interpreter split.

use crate::vex_e2e_common;
use crate::vex_pipenv_pip_real;

use std::path::{Path, PathBuf};
use std::process::Output;

use serde_json::Value;
use vex_pipenv_pip_real::*;

const REQUIRED: &str = "SOCKET_PATCH_PIPENV_E2E_REQUIRED";
const VERSIONS_VAR: &str = "SOCKET_PATCH_PIPENV_E2E_VERSIONS";
/// The last release of every calendar major 2022..2026.
const VERSIONS: &[&str] = &[
    "2022.12.19",
    "2023.12.1",
    "2024.4.1",
    "2025.1.3",
    "2026.8.0",
];

const PIPFILE: &str = "[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n[packages]\nsix = \"==1.16.0\"\n\n[dev-packages]\n";

fn year(version: &str) -> u32 {
    version.split('.').next().unwrap().parse().unwrap()
}

fn python_for(version: &str) -> &'static str {
    if year(version) <= 2022 {
        "3.8"
    } else {
        "3.12"
    }
}

/// A bootstrapped Pipenv release and the env every call runs under.
struct Pipenv {
    version: String,
    venv: PathBuf,
    envs: Vec<(String, String)>,
    uv: PathBuf,
    /// The project-venv seed pins (the tool venv's own: a newer setuptools
    /// breaks Pipenv <= 2021's vendored packaging).
    seed: Vec<String>,
}

impl Pipenv {
    fn bootstrap(uv: &Path, version: &str, scratch: &Path) -> Result<Self, String> {
        let pin = format!("pipenv=={version}");
        let setuptools = if year(version) >= 2023 {
            "setuptools==69.5.1"
        } else {
            "setuptools==57.5.0"
        };
        let venv = bootstrap_tool(
            uv,
            &format!("pipenv-{version}"),
            python_for(version),
            &[&pin, "pip==24.0", setuptools],
            "pipenv",
        )?;
        // Only `pipenv` on PATH (not the tool venv's python): the CLI
        // probes `pipenv --version` for the installer generation.
        let shim = scratch.join("pipenv-bin");
        std::fs::create_dir_all(&shim).unwrap();
        let _ = std::fs::remove_file(shim.join("pipenv"));
        std::os::unix::fs::symlink(venv_bin(&venv, "pipenv"), shim.join("pipenv")).unwrap();
        let workon = scratch.join("workon");
        std::fs::create_dir_all(&workon).unwrap();
        let path = format!(
            "{}:{}",
            shim.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let envs = vec![
            ("PATH".into(), path),
            ("PIPENV_VENV_IN_PROJECT".into(), "1".into()),
            (
                "PIPENV_PYTHON".into(),
                venv_bin(&venv, "python").display().to_string(),
            ),
            ("PIPENV_YES".into(), "1".into()),
            ("PIPENV_NOSPIN".into(), "1".into()),
            ("PIPENV_IGNORE_VIRTUALENVS".into(), "1".into()),
            (
                "PIPENV_CACHE_DIR".into(),
                tools_root().join("pipenv-cache").display().to_string(),
            ),
            ("WORKON_HOME".into(), workon.display().to_string()),
        ];
        Ok(Pipenv {
            version: version.to_string(),
            venv,
            envs,
            uv: uv.to_path_buf(),
            seed: vec!["pip==24.0".into(), setuptools.into()],
        })
    }

    /// Pre-create `<project>/.venv` on the tool's interpreter with the seed
    /// pins (what the backtest's `make_venv` does): Pipenv then installs
    /// into it instead of seeding its own with whatever virtualenv ships.
    fn project_venv(&self, project: &Path) {
        let python = venv_bin(&self.venv, "python");
        let seed: Vec<&str> = self.seed.iter().map(String::as_str).collect();
        make_venv(
            &self.uv,
            python.to_str().unwrap(),
            &project.join(".venv"),
            &seed,
        )
        .unwrap_or_else(|e| panic!("pipenv {}: project venv: {e}", self.version));
    }

    fn run(&self, cwd: &Path, args: &[&str]) -> std::process::Output {
        tool(&venv_bin(&self.venv, "pipenv"), cwd, args, &self.envs)
    }
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// One (release, mode) flow, end to end.
fn flow(pipenv: &Pipenv, mode: Mode, root: &Path) {
    let v = pipenv.version.as_str();
    let what = format!("pipenv {v} {}", mode.label());
    let proj = root.join(mode.label()).join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("Pipfile"), PIPFILE).unwrap();

    // 1. the native lock + pristine install. `--python` explicitly: Pipenv
    //    <= 2022 ignores PIPENV_PYTHON and picks the newest python3 on PATH
    //    (whose pkgutil no longer suits its vendored pip).
    let python = venv_bin(&pipenv.venv, "python");
    pipenv.project_venv(&proj);
    let out = pipenv.run(&proj, &["install", "--python", python.to_str().unwrap()]);
    assert_ok(&out, &format!("{what}: pipenv install"));
    let pristine_lock = read(&proj.join("Pipfile.lock"));
    let pristine_pipfile = read(&proj.join("Pipfile"));
    let py = venv_bin(&proj.join(".venv"), "python");
    let (_, pristine, patched_now) =
        six_oracle(&py, &proj).unwrap_or_else(|| panic!("{what}: six not importable"));
    assert!(!patched_now, "{what}: the registry six is already patched");
    let patched = [pristine.as_slice(), PATCH_SUFFIX].concat();
    let api = RealApi::start(mode.uuid(), &pristine, &patched);

    // 2. wire it with the real CLI, embedded VEX on the same run.
    if mode == Mode::Hosted {
        // The CI shape: the lock-only checkout (a warm venv holding the
        // registry release is reported stale and kept out of the same-run
        // attestation — see in_process_redirect_pipenv).
        std::fs::remove_dir_all(proj.join(".venv")).unwrap();
    }
    let embedded = proj.join("scan.vex.json");
    let mut args: Vec<&str> = mode.scan_flags().to_vec();
    args.extend([
        "--vex",
        embedded.to_str().unwrap(),
        "--vex-product",
        PRODUCT,
    ]);
    let (code, env, stderr) = socket_scan(&proj, &api, &args, &pipenv.envs);
    let ok = code == Some(0);
    record(
        "pipenv",
        v,
        &format!("default/{}", mode.label()),
        "wire",
        if ok { "pass" } else { "FAIL" },
    );
    assert!(ok, "{what}: scan failed: {env}\n{stderr}");
    let doc: Value = serde_json::from_slice(&read(&embedded)).unwrap();
    assert_six_attested(&doc, mode, &format!("{what} embedded scan --vex"));
    record(
        "pipenv",
        v,
        &format!("default/{}", mode.label()),
        "embedded-scan-vex",
        "pass",
    );
    std::fs::remove_file(&embedded).unwrap();
    let lock = String::from_utf8(read(&proj.join("Pipfile.lock"))).unwrap();
    match mode {
        Mode::Hosted => assert!(
            lock.contains(&api.artifact_url()) && lock.contains("#sha256="),
            "{what}: the lock must point at the hosted wheel: {lock}"
        ),
        Mode::Vendored => assert!(
            lock.contains(&format!(".socket/vendor/pypi/{}/", mode.uuid())),
            "{what}: the lock must point at the vendored wheel: {lock}"
        ),
    }
    assert_eq!(
        read(&proj.join("Pipfile")),
        pristine_pipfile,
        "{what}: Pipfile untouched"
    );

    // 3. fresh checkout of the committed state, installed by Pipenv itself.
    let fresh = root.join(mode.label()).join("fresh");
    copy_tree(&proj, &fresh, &[".venv"]);
    pipenv.project_venv(&fresh);
    let downloads = api.artifact_downloads();
    let out = pipenv.run(
        &fresh,
        &["install", "--deploy", "--python", python.to_str().unwrap()],
    );
    assert_ok(&out, &format!("{what}: fresh `pipenv install --deploy`"));
    let (_, bytes, is_patched) = six_oracle(&venv_bin(&fresh.join(".venv"), "python"), &fresh)
        .unwrap_or_else(|| panic!("{what}: six not importable in the fresh checkout"));
    let ok = is_patched && bytes == patched;
    record(
        "pipenv",
        v,
        &format!("default/{}", mode.label()),
        "install-patched",
        if ok { "pass" } else { "FAIL" },
    );
    assert!(ok, "{what}: the fresh install must carry the PATCHED six");
    if mode == Mode::Hosted {
        assert!(
            api.artifact_downloads() > downloads,
            "{what}: Pipenv must have downloaded the hosted wheel"
        );
    }
    assert_eq!(
        read(&fresh.join("Pipfile.lock")),
        lock.as_bytes(),
        "{what}: the install must not relock"
    );

    // 4. manifest-less VEX over the installed fresh checkout.
    let revert = |p: &Path| {
        std::fs::write(p.join("Pipfile.lock"), &pristine_lock).unwrap();
        std::fs::write(p.join("Pipfile"), &pristine_pipfile).unwrap();
    };
    let workon = pipenv
        .envs
        .iter()
        .find(|(k, _)| k == "WORKON_HOME")
        .unwrap()
        .clone();
    manifestless_vex_matrix(&VexMatrix {
        pm: "pipenv",
        version: v,
        cell: "default",
        mode,
        project: &fresh,
        patch_server: &api.uri(),
        pristine: &pristine,
        patched: &patched,
        revert: &revert,
        envs: vec![workon],
    });

    // Embedded re-scan of the manifest-less checkout (a CI re-run).
    let rescan = root.join(mode.label()).join("rescan");
    copy_tree(&fresh, &rescan, &[]);
    vex_e2e_common::strip_manifest(&rescan);
    let embedded = rescan.join("rescan.vex.json");
    let mut args: Vec<&str> = mode.scan_flags().to_vec();
    args.extend([
        "--vex",
        embedded.to_str().unwrap(),
        "--vex-product",
        PRODUCT,
    ]);
    let (code, env, stderr) = socket_scan(&rescan, &api, &args, &pipenv.envs);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(code, Some(0), "{what} re-scan: {env}\n{stderr}");
        let doc: Value = serde_json::from_slice(&read(&embedded)).unwrap();
        assert_six_attested(&doc, mode, &format!("{what} re-scan --vex"));
        assert_eq!(
            read(&rescan.join("Pipfile.lock")),
            lock.as_bytes(),
            "{what}: the re-scan keeps the lock byte-stable"
        );
    }));
    record(
        "pipenv",
        v,
        &format!("default/{}", mode.label()),
        "rescan-vex",
        if result.is_ok() { "pass" } else { "FAIL" },
    );
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[test]
#[ignore = "real Pipenv releases + PyPI (network). Run with --ignored."]
fn pipenv_every_major_hosted_and_vendored_end_in_manifest_less_vex() {
    let Some(uv) = find_uv() else {
        return skip_or_fail(REQUIRED, "uv is not installed");
    };
    let mut failures = Vec::new();
    for version in versions(VERSIONS_VAR, VERSIONS) {
        let scratch = tempfile::tempdir().unwrap();
        let pipenv = match Pipenv::bootstrap(&uv, &version, scratch.path()) {
            Ok(p) => p,
            Err(e) => {
                record("pipenv", &version, "default", "bootstrap", "SKIP");
                skip_or_fail(REQUIRED, &format!("pipenv {version} bootstrap: {e}"));
                continue;
            }
        };
        for mode in [Mode::Hosted, Mode::Vendored] {
            let root = scratch.path().join("run");
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                flow(&pipenv, mode, &root)
            }));
            if let Err(e) = result {
                let msg = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                failures.push(format!("pipenv {version} {}: {msg}", mode.label()));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

const PYLOCK_PIPFILE: &str = "[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n[packages]\nsix = \"==1.16.0\"\n\n[dev-packages]\n\n[pipenv]\nuse_pylock = true\n";

/// #912 / #1122 on a real Pipenv 2026 `use_pylock = true` project, whose
/// `pipenv lock` writes both `Pipfile.lock` and `pylock.toml`:
///
/// * #1122: vendored wires `Pipfile.lock` (what Pipenv installs from when
///   both exist), and a fresh `pipenv install --deploy` gets the PATCHED
///   six.
/// * #1368: the pylock, which PEP 751 installers (`uv pip install -r
///   pylock.toml`, pip) read, is wired to the same vendored wheel.
/// * #912: the pylock-only checkout (no `Pipfile.lock`) is refused in both
///   modes — Pipenv would drop the `archive` entry and install the upstream
///   release — and the pylock is left byte-identical.
fn pylock_flow(pipenv: &Pipenv, root: &Path) {
    let v = pipenv.version.as_str();
    let what = format!("pipenv {v} use_pylock");
    let proj = root.join("pylock").join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("Pipfile"), PYLOCK_PIPFILE).unwrap();
    let python = venv_bin(&pipenv.venv, "python");
    pipenv.project_venv(&proj);
    let out = pipenv.run(&proj, &["install", "--python", python.to_str().unwrap()]);
    assert_ok(&out, &format!("{what}: pipenv install"));
    if !proj.join("pylock.toml").is_file() {
        assert_ok(
            &pipenv.run(&proj, &["lock"]),
            &format!("{what}: pipenv lock"),
        );
    }
    let pristine_pylock = read(&proj.join("pylock.toml"));
    let py = venv_bin(&proj.join(".venv"), "python");
    let (_, pristine, _) =
        six_oracle(&py, &proj).unwrap_or_else(|| panic!("{what}: six not importable"));
    let patched = [pristine.as_slice(), PATCH_SUFFIX].concat();

    // #912: the pylock-only checkout, both modes.
    for mode in [Mode::Hosted, Mode::Vendored] {
        let only = root.join("pylock").join(format!("only-{}", mode.label()));
        copy_tree(&proj, &only, &[".venv"]);
        std::fs::remove_file(only.join("Pipfile.lock")).unwrap();
        let api = RealApi::start(mode.uuid(), &pristine, &patched);
        let (_, env, stderr) = socket_scan(&only, &api, mode.scan_flags(), &pipenv.envs);
        let code = match mode {
            Mode::Hosted => "redirect_pipenv_pylock_unsupported",
            Mode::Vendored => "pypi_pipenv_pylock_unsupported",
        };
        let ok = env.to_string().contains(code)
            && read(&only.join("pylock.toml")) == pristine_pylock
            && !only.join("Pipfile.lock").exists();
        record(
            "pipenv",
            v,
            &format!("pylock-only/{}", mode.label()),
            "refused",
            if ok { "pass" } else { "FAIL" },
        );
        assert!(
            ok,
            "{what} pylock-only {}: expected {code}, pylock untouched: {env}\n{stderr}",
            mode.label()
        );
    }

    // #1122: both locks, vendored.
    let mode = Mode::Vendored;
    let api = RealApi::start(mode.uuid(), &pristine, &patched);
    let (code, env, stderr) = socket_scan(&proj, &api, mode.scan_flags(), &pipenv.envs);
    assert_eq!(code, Some(0), "{what}: vendored scan: {env}\n{stderr}");
    let lock = String::from_utf8(read(&proj.join("Pipfile.lock"))).unwrap();
    assert!(
        lock.contains(&format!(".socket/vendor/pypi/{}/", mode.uuid())),
        "{what}: Pipfile.lock must point at the vendored wheel: {lock}"
    );
    let pylock = String::from_utf8(read(&proj.join("pylock.toml"))).unwrap();
    assert!(
        pylock.contains(&format!(".socket/vendor/pypi/{}/", mode.uuid())),
        "{what}: pylock.toml must point at the vendored wheel too: {pylock}"
    );
    let fresh = root.join("pylock").join("fresh");
    copy_tree(&proj, &fresh, &[".venv"]);
    pipenv.project_venv(&fresh);
    let out = pipenv.run(
        &fresh,
        &["install", "--deploy", "--python", python.to_str().unwrap()],
    );
    assert_ok(&out, &format!("{what}: fresh `pipenv install --deploy`"));
    let (_, bytes, is_patched) = six_oracle(&venv_bin(&fresh.join(".venv"), "python"), &fresh)
        .unwrap_or_else(|| panic!("{what}: six not importable in the fresh checkout"));
    let ok = is_patched && bytes == patched;
    record(
        "pipenv",
        v,
        "use_pylock/vendored",
        "install-patched",
        if ok { "pass" } else { "FAIL" },
    );
    assert!(ok, "{what}: the fresh install must carry the PATCHED six");

    // #1368: a PEP 751 installer reading the wired pylock gets the PATCHED
    // six too, from the committed wheel. pip must install it. uv must too,
    // unless it refuses Pipenv's own untouched pylock the same way: uv
    // 0.13.2+ reads the `environments = []` Pipenv writes as "no supported
    // environment", which is upstream's call, not the wiring's.
    let pep751 = root.join("pylock").join("pep751");
    let python = python.to_str().unwrap();
    let (out, py) = pylock_install(&pipenv.uv, python, &proj, &pep751.join("pip"), true);
    assert_ok(&out, &format!("{what}: `pip install -r pylock.toml`"));
    let (_, bytes, is_patched) = six_oracle(&py, &pep751.join("pip"))
        .unwrap_or_else(|| panic!("{what}: six not importable from the pylock install"));
    let ok = is_patched && bytes == patched;
    record(
        "pipenv",
        v,
        "use_pylock/vendored",
        "pylock-install-patched",
        if ok { "pass" } else { "FAIL" },
    );
    assert!(ok, "{what}: the pylock install must carry the PATCHED six");

    let (out, py) = pylock_install(&pipenv.uv, python, &proj, &pep751.join("uv"), false);
    let verdict = if out.status.success() {
        let (_, bytes, is_patched) = six_oracle(&py, &pep751.join("uv"))
            .unwrap_or_else(|| panic!("{what}: six not importable from the uv pylock install"));
        assert!(
            is_patched && bytes == patched,
            "{what}: the uv pylock install must carry the PATCHED six"
        );
        "pass"
    } else {
        let pristine_dir = pep751.join("uv-pristine");
        copy_tree(&proj, &pristine_dir, &[".venv"]);
        std::fs::write(pristine_dir.join("pylock.toml"), &pristine_pylock).unwrap();
        let (pristine_out, _) = pylock_install(
            &pipenv.uv,
            python,
            &pristine_dir,
            &pep751.join("uv-p"),
            false,
        );
        let wired_err = error_lines(&out);
        assert!(
            !pristine_out.status.success()
                && !wired_err.is_empty()
                && wired_err == error_lines(&pristine_out),
            "{what}: uv refuses the wired pylock but not Pipenv's own: {}\n--- pristine\n{}",
            out_text(&out),
            out_text(&pristine_out)
        );
        "upstream-refused"
    };
    record(
        "pipenv",
        v,
        "use_pylock/vendored",
        "pylock-uv-install",
        verdict,
    );
}

/// Installs `src`'s `pylock.toml` into a fresh venv in a copy of `src` at
/// `dir`, with pip (`-r pylock.toml` needs pip 26.1+; pinned exactly like
/// every other oracle here) or uv. Returns the installer's output and the
/// venv's python.
fn pylock_install(
    uv: &Path,
    python: &str,
    src: &Path,
    dir: &Path,
    with_pip: bool,
) -> (Output, PathBuf) {
    copy_tree(src, dir, &[".venv"]);
    let venv = dir.join(".venv");
    let pins: &[&str] = if with_pip { &["pip==26.2.2"] } else { &[] };
    make_venv(uv, python, &venv, pins).unwrap_or_else(|e| panic!("pylock venv: {e}"));
    let py = venv_bin(&venv, "python");
    let out = if with_pip {
        tool(
            &py,
            dir,
            &["-m", "pip", "install", "-r", "pylock.toml"],
            &[],
        )
    } else {
        let args = [
            "pip",
            "install",
            "--python",
            py.to_str().unwrap(),
            "-r",
            "pylock.toml",
        ];
        tool(uv, dir, &args, &[])
    };
    (out, py)
}

/// The `error:` lines of an installer's stderr: what it refused, without
/// the paths it printed around it.
fn error_lines(out: &Output) -> Vec<String> {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|l| l.starts_with("error:"))
        .map(str::to_owned)
        .collect()
}

#[test]
#[ignore = "real Pipenv releases + PyPI (network). Run with --ignored."]
fn pipenv_pylock_projects_wire_what_pipenv_installs() {
    let Some(uv) = find_uv() else {
        return skip_or_fail(REQUIRED, "uv is not installed");
    };
    let mut failures = Vec::new();
    // `[pipenv] use_pylock` is a Pipenv 2026 setting.
    for version in versions(VERSIONS_VAR, VERSIONS)
        .into_iter()
        .filter(|v| year(v) >= 2026)
    {
        let scratch = tempfile::tempdir().unwrap();
        let pipenv = match Pipenv::bootstrap(&uv, &version, scratch.path()) {
            Ok(p) => p,
            Err(e) => {
                record("pipenv", &version, "use_pylock", "bootstrap", "SKIP");
                skip_or_fail(REQUIRED, &format!("pipenv {version} bootstrap: {e}"));
                continue;
            }
        };
        let root = scratch.path().join("run");
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pylock_flow(&pipenv, &root)));
        if let Err(e) = result {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            failures.push(format!("pipenv {version} use_pylock: {msg}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

const SPLIT_PIPFILE: &str = "[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n[packages]\n\n[dev-packages]\n\n[docs]\nsix = \"==1.15.0\"\n\n[tests]\nsix = \"==1.16.0\"\n";

/// #1616: Pipenv 2023+ resolves each category on its own, so `[docs]` can
/// lock six 1.15.0 while `[tests]` locks the patched 1.16.0. Both modes
/// rewire only `tests.six`, leave `docs.six` as Pipenv wrote it, and a
/// fresh `pipenv sync --categories tests` installs the PATCHED six.
fn split_categories_flow(pipenv: &Pipenv, mode: Mode, root: &Path) {
    let v = pipenv.version.as_str();
    let what = format!("pipenv {v} split categories {}", mode.label());
    let proj = root.join("split").join(mode.label()).join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(proj.join("Pipfile"), SPLIT_PIPFILE).unwrap();
    let python = venv_bin(&pipenv.venv, "python");
    pipenv.project_venv(&proj);
    let out = pipenv.run(&proj, &["lock", "--python", python.to_str().unwrap()]);
    assert_ok(&out, &format!("{what}: pipenv lock"));
    let out = pipenv.run(&proj, &["sync", "--categories", "tests"]);
    assert_ok(&out, &format!("{what}: pipenv sync --categories tests"));
    let pristine_lock: Value = serde_json::from_slice(&read(&proj.join("Pipfile.lock"))).unwrap();
    assert_eq!(pristine_lock["docs"]["six"]["version"], "==1.15.0");
    assert_eq!(pristine_lock["tests"]["six"]["version"], "==1.16.0");
    let py = venv_bin(&proj.join(".venv"), "python");
    let (_, pristine, _) =
        six_oracle(&py, &proj).unwrap_or_else(|| panic!("{what}: six not importable"));
    let patched = [pristine.as_slice(), PATCH_SUFFIX].concat();
    let api = RealApi::start(mode.uuid(), &pristine, &patched);
    if mode == Mode::Hosted {
        std::fs::remove_dir_all(proj.join(".venv")).unwrap();
    }

    let (code, env, stderr) = socket_scan(&proj, &api, mode.scan_flags(), &pipenv.envs);
    assert_eq!(code, Some(0), "{what}: scan: {env}\n{stderr}");
    let lock: Value = serde_json::from_slice(&read(&proj.join("Pipfile.lock"))).unwrap();
    let wired = lock["tests"]["six"].to_string();
    let ok = lock["docs"]["six"] == pristine_lock["docs"]["six"]
        && match mode {
            Mode::Hosted => wired.contains(&api.artifact_url()),
            Mode::Vendored => wired.contains(&format!(".socket/vendor/pypi/{}/", mode.uuid())),
        };
    record(
        "pipenv",
        v,
        &format!("split-categories/{}", mode.label()),
        "wire",
        if ok { "pass" } else { "FAIL" },
    );
    assert!(
        ok,
        "{what}: only tests.six is rewired: {lock}\n{env}\n{stderr}"
    );

    let fresh = root.join("split").join(mode.label()).join("fresh");
    copy_tree(&proj, &fresh, &[".venv"]);
    pipenv.project_venv(&fresh);
    let out = pipenv.run(
        &fresh,
        &[
            "sync",
            "--categories",
            "tests",
            "--python",
            python.to_str().unwrap(),
        ],
    );
    assert_ok(
        &out,
        &format!("{what}: fresh `pipenv sync --categories tests`"),
    );
    let (_, bytes, is_patched) = six_oracle(&venv_bin(&fresh.join(".venv"), "python"), &fresh)
        .unwrap_or_else(|| panic!("{what}: six not importable in the fresh checkout"));
    let ok = is_patched && bytes == patched;
    record(
        "pipenv",
        v,
        &format!("split-categories/{}", mode.label()),
        "install-patched",
        if ok { "pass" } else { "FAIL" },
    );
    assert!(ok, "{what}: the fresh install must carry the PATCHED six");
}

#[test]
#[ignore = "real Pipenv releases + PyPI (network). Run with --ignored."]
fn pipenv_split_category_versions_wire_the_patched_category() {
    let Some(uv) = find_uv() else {
        return skip_or_fail(REQUIRED, "uv is not installed");
    };
    let mut failures = Vec::new();
    // Per-category resolution (and so a version split) is Pipenv 2023+.
    for version in versions(VERSIONS_VAR, VERSIONS)
        .into_iter()
        .filter(|v| year(v) >= 2023)
    {
        let scratch = tempfile::tempdir().unwrap();
        let pipenv = match Pipenv::bootstrap(&uv, &version, scratch.path()) {
            Ok(p) => p,
            Err(e) => {
                record("pipenv", &version, "split-categories", "bootstrap", "SKIP");
                skip_or_fail(REQUIRED, &format!("pipenv {version} bootstrap: {e}"));
                continue;
            }
        };
        for mode in [Mode::Hosted, Mode::Vendored] {
            let root = scratch.path().join("run");
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                split_categories_flow(&pipenv, mode, &root)
            }));
            if let Err(e) = result {
                let msg = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                failures.push(format!("pipenv {version} split {}: {msg}", mode.label()));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
