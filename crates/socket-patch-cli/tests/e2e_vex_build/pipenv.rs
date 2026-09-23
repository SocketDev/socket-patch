//! Real-Pipenv capstone for manifest-less VEX: for every Pipenv calendar
//! major (one release per year line 2022..2026, the same releases
//! `pipenv-compatibility.yml` / `scripts/backtest-pipenv.py` pin), HOSTED
//! and VENDORED:
//!
//! 1. `pipenv install six==1.16.0` from PyPI (in-project venv) — the native
//!    Pipfile.lock that release writes;
//! 2. `socket-patch scan --redirect --vex` (hosted, on the lock-only
//!    checkout: the CI shape) / `scan --vendor --vendor-source build --vex`
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
//!    embedded `scan --redirect --vex` / `scan --vendor --vex` re-run on the
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
