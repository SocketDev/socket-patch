//! Real-pip capstone for manifest-less VEX over `requirements.txt`: for
//! every pip major (latest release of each, `SOCKET_PATCH_PIP_E2E_VERSIONS`
//! overrides), HOSTED and VENDORED, three project shapes:
//!
//! | cell | requirements | hosted | vendored |
//! | --- | --- | --- | --- |
//! | `root` | `six==1.16.0` | yes | yes |
//! | `hashes` | `pip-compile --generate-hashes` style (`\` continued `--hash`, hash-checking mode) | yes | yes |
//! | `include` | `-r requirements/base.txt` | root-only rewriter: stays on the registry, nothing attested | yes |
//!
//! Each flow:
//!
//! 1. `python -m pip install -r requirements.txt` with the real pip major
//!    from PyPI (the pristine install);
//! 2. `socket-patch scan --redirect --vex` (hosted, on the lock-only
//!    checkout) / `scan --vendor --vendor-source build --vex` (vendored,
//!    from the pristine install) against a wiremock Socket API that also
//!    serves the patched wheel — the same-run document attests;
//! 3. a FRESH checkout (requirements files + `.socket/`) into a new venv
//!    with `pip install --no-index -r requirements.txt` — pip itself
//!    downloads the hosted wheel from the mock patch server (hash-checked)
//!    or installs the committed vendored wheel, and `import six` proves the
//!    PATCHED bytes are installed;
//! 4. the manifest-less VEX matrix (`vex_pipenv_pip_real`): manifest
//!    deleted, ledgers deleted, `--offline` (zero requests), requirements
//!    reverted to the registry pin (also `--no-verify`), `apply --vex`;
//!    plus the embedded `scan --redirect --vex` / `scan --vendor --vex`
//!    re-run on the manifest-less checkout.
//!
//! `#[ignore]`d (network: PyPI) — run with `--ignored`; CI sets
//! `SOCKET_PATCH_PIP_E2E_REQUIRED=1` so a missing uv / failed bootstrap
//! fails instead of skipping. Python 3.11 for every major (the newest
//! interpreter pip 22 supports).

use crate::vex_e2e_common;
use crate::vex_pipenv_pip_real;

use std::path::{Path, PathBuf};

use serde_json::Value;
use vex_e2e_common::{assert_absent, VexRun};
use vex_pipenv_pip_real::*;

const REQUIRED: &str = "SOCKET_PATCH_PIP_E2E_REQUIRED";
const VERSIONS_VAR: &str = "SOCKET_PATCH_PIP_E2E_VERSIONS";
/// pip majors (each resolves to its latest `N.*` release).
const VERSIONS: &[&str] = &["22", "23", "24", "25", "26"];
const PYTHON: &str = "3.11";

/// PyPI's sha256 of `six-1.16.0-py2.py3-none-any.whl` / `six-1.16.0.tar.gz`
/// (what `pip-compile --generate-hashes` writes).
const SIX_WHEEL_SHA256: &str = "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254";
const SIX_SDIST_SHA256: &str = "1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cell {
    Root,
    Hashes,
    Include,
}

impl Cell {
    fn label(self) -> &'static str {
        match self {
            Cell::Root => "root",
            Cell::Hashes => "hashes",
            Cell::Include => "include",
        }
    }

    /// The native (registry) requirements files.
    fn files(self) -> Vec<(&'static str, String)> {
        match self {
            Cell::Root => vec![("requirements.txt", "six==1.16.0\n".into())],
            Cell::Hashes => vec![(
                "requirements.txt",
                format!(
                    "six==1.16.0 \\\n    --hash=sha256:{SIX_WHEEL_SHA256} \\\n    --hash=sha256:{SIX_SDIST_SHA256}\n"
                ),
            )],
            Cell::Include => vec![
                ("requirements.txt", "-r requirements/base.txt\n".into()),
                ("requirements/base.txt", "six==1.16.0\n".into()),
            ],
        }
    }
}

/// A venv at `venv` holding the latest pip `major`.
fn pip_venv(uv: &Path, major: &str, venv: &Path) -> Result<String, String> {
    let pin = format!("pip=={major}.*");
    make_venv(uv, PYTHON, venv, &[&pin])?;
    let out = tool(
        &venv_bin(venv, "python"),
        venv.parent().unwrap(),
        &["-m", "pip", "--version"],
        &[],
    );
    if !out.status.success() {
        return Err(out_text(&out));
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let version = text
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    if version.split('.').next() != Some(major) {
        return Err(format!("wanted pip {major}.*, got {text}"));
    }
    Ok(version)
}

fn pip(venv: &Path, cwd: &Path, args: &[&str]) -> std::process::Output {
    let mut full = vec!["-m", "pip"];
    full.extend_from_slice(args);
    tool(&venv_bin(venv, "python"), cwd, &full, &[])
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn wiring_text(proj: &Path, cell: Cell) -> String {
    cell.files()
        .iter()
        .map(|(rel, _)| String::from_utf8(read(&proj.join(rel))).unwrap())
        .collect()
}

/// One (pip major, cell, mode) flow, end to end.
fn flow(uv: &Path, major: &str, pip_version: &str, cell: Cell, mode: Mode, root: &Path) {
    let what = format!("pip {pip_version} {} {}", cell.label(), mode.label());
    let row = format!("{}/{}", cell.label(), mode.label());
    let base = root.join(format!("{}-{}", cell.label(), mode.label()));
    let proj = base.join("proj");
    for (rel, body) in cell.files() {
        let path = proj.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    // 1. pristine install with the real pip.
    let venv = proj.join(".venv");
    pip_venv(uv, major, &venv).unwrap_or_else(|e| panic!("{what}: venv: {e}"));
    let out = pip(&venv, &proj, &["install", "-r", "requirements.txt"]);
    assert_ok(&out, &format!("{what}: pip install -r (registry)"));
    let (_, pristine, patched_now) = six_oracle(&venv_bin(&venv, "python"), &proj)
        .unwrap_or_else(|| panic!("{what}: six not importable"));
    assert!(!patched_now, "{what}: the registry six is already patched");
    let patched = [pristine.as_slice(), PATCH_SUFFIX].concat();
    let api = RealApi::start(mode.uuid(), &pristine, &patched);

    // 2. wire it with the real CLI, embedded VEX on the same run.
    if mode == Mode::Hosted {
        std::fs::remove_dir_all(&venv).unwrap();
    }
    let embedded = proj.join("scan.vex.json");
    let mut args: Vec<&str> = mode.scan_flags().to_vec();
    args.extend([
        "--vex",
        embedded.to_str().unwrap(),
        "--vex-product",
        PRODUCT,
    ]);
    let (code, env, stderr) = socket_scan(&proj, &api, &args, &[]);

    if cell == Cell::Include && mode == Mode::Hosted {
        // Documented limit: the hosted requirements rewriter edits only the
        // ROOT file, so the include pin stays on the registry — and VEX
        // must not claim a patch nothing installs.
        let native: String = cell.files().iter().map(|(_, b)| b.clone()).collect();
        let untouched = wiring_text(&proj, cell) == native;
        let doc = std::fs::read(&embedded)
            .ok()
            .map(|b| serde_json::from_slice::<Value>(&b).unwrap());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(untouched, "{what}: the include must stay on the registry");
            assert_absent(doc.as_ref(), PURL);
            let patch_api = vex_e2e_common::PatchApi::start(vec![(
                mode.uuid().to_string(),
                view(mode.uuid(), &pristine, &patched),
            )]);
            let out = vex_e2e_common::run_vex(
                &vex_e2e_common::binary(),
                &proj,
                &VexRun {
                    product: Some(PRODUCT.into()),
                    patch_server_url: Some(api.uri()),
                    ..VexRun::online(&patch_api)
                },
            );
            assert_ne!(out.code, Some(0), "{what}: {out}");
            assert_absent(out.doc.as_ref(), PURL);
        }));
        record(
            "pip",
            pip_version,
            &row,
            "root-only-limit",
            if result.is_ok() { "pass" } else { "FAIL" },
        );
        let _ = (code, env, stderr);
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
        return;
    }

    let ok = code == Some(0);
    record(
        "pip",
        pip_version,
        &row,
        "wire",
        if ok { "pass" } else { "FAIL" },
    );
    assert!(ok, "{what}: scan failed: {env}\n{stderr}");
    let doc: Value = serde_json::from_slice(&read(&embedded)).unwrap();
    assert_six_attested(&doc, mode, &format!("{what} embedded scan --vex"));
    record("pip", pip_version, &row, "embedded-scan-vex", "pass");
    std::fs::remove_file(&embedded).unwrap();
    let wired = wiring_text(&proj, cell);
    match mode {
        Mode::Hosted => assert!(
            wired.contains(&api.artifact_url()) && wired.contains("--hash=sha256:"),
            "{what}: requirements must point at the hosted wheel: {wired}"
        ),
        Mode::Vendored => assert!(
            wired.contains(&format!(".socket/vendor/pypi/{}/", mode.uuid())),
            "{what}: requirements must point at the vendored wheel: {wired}"
        ),
    }

    // 3. fresh checkout into a new venv, installed by pip itself with no
    //    index (the only source is the wiring).
    let fresh = base.join("fresh");
    copy_tree(&proj, &fresh, &[".venv"]);
    let fresh_venv = fresh.join(".venv");
    pip_venv(uv, major, &fresh_venv).unwrap_or_else(|e| panic!("{what}: fresh venv: {e}"));
    let downloads = api.artifact_downloads();
    let out = pip(
        &fresh_venv,
        &fresh,
        &["install", "--no-index", "-r", "requirements.txt"],
    );
    assert_ok(&out, &format!("{what}: fresh `pip install --no-index -r`"));
    let (_, bytes, is_patched) = six_oracle(&venv_bin(&fresh_venv, "python"), &fresh)
        .unwrap_or_else(|| panic!("{what}: six not importable in the fresh checkout"));
    let ok = is_patched && bytes == patched;
    record(
        "pip",
        pip_version,
        &row,
        "install-patched",
        if ok { "pass" } else { "FAIL" },
    );
    assert!(ok, "{what}: the fresh install must carry the PATCHED six");
    if mode == Mode::Hosted {
        assert!(
            api.artifact_downloads() > downloads,
            "{what}: pip must have downloaded the hosted wheel"
        );
    }

    // 4. manifest-less VEX over the installed fresh checkout.
    let revert = |p: &Path| {
        for (rel, body) in cell.files() {
            std::fs::write(p.join(rel), body).unwrap();
        }
    };
    manifestless_vex_matrix(&VexMatrix {
        pm: "pip",
        version: pip_version,
        cell: cell.label(),
        mode,
        project: &fresh,
        patch_server: &api.uri(),
        pristine: &pristine,
        patched: &patched,
        revert: &revert,
        envs: Vec::new(),
    });

    // Embedded re-scan of the manifest-less checkout (a CI re-run).
    let rescan = base.join("rescan");
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
    let (code, env, stderr) = socket_scan(&rescan, &api, &args, &[]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_eq!(code, Some(0), "{what} re-scan: {env}\n{stderr}");
        let doc: Value = serde_json::from_slice(&read(&embedded)).unwrap();
        assert_six_attested(&doc, mode, &format!("{what} re-scan --vex"));
        assert_eq!(
            wiring_text(&rescan, cell),
            wired,
            "{what}: the re-scan keeps the wiring byte-stable"
        );
    }));
    record(
        "pip",
        pip_version,
        &row,
        "rescan-vex",
        if result.is_ok() { "pass" } else { "FAIL" },
    );
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[test]
#[ignore = "real pip releases + PyPI (network). Run with --ignored."]
fn pip_every_major_hosted_and_vendored_end_in_manifest_less_vex() {
    let Some(uv) = find_uv() else {
        return skip_or_fail(REQUIRED, "uv is not installed");
    };
    let mut failures = Vec::new();
    for major in versions(VERSIONS_VAR, VERSIONS) {
        let scratch = tempfile::tempdir().unwrap();
        let probe: PathBuf = scratch.path().join("probe-venv");
        let pip_version = match pip_venv(&uv, &major, &probe) {
            Ok(v) => v,
            Err(e) => {
                record("pip", &major, "-", "bootstrap", "SKIP");
                skip_or_fail(REQUIRED, &format!("pip {major}.* bootstrap: {e}"));
                continue;
            }
        };
        for cell in [Cell::Root, Cell::Hashes, Cell::Include] {
            for mode in [Mode::Hosted, Mode::Vendored] {
                let root = scratch.path().join("run");
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    flow(&uv, &major, &pip_version, cell, mode, &root)
                }));
                if let Err(e) = result {
                    let msg = e
                        .downcast_ref::<String>()
                        .cloned()
                        .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                        .unwrap_or_default();
                    failures.push(format!(
                        "pip {pip_version} {} {}: {msg}",
                        cell.label(),
                        mode.label()
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}
