//! Real-PDM capstone: HOSTED and VENDORED patches end to end with a pinned
//! PDM release, finishing in manifest-less `socket-patch vex`.
//!
//! Per PDM release (`SOCKET_PATCH_PDM_E2E_VERSION`, default
//! [`DEFAULT_VERSION`]; the local matrix loop and the pdm-compatibility CI
//! workflow run one release per invocation):
//!
//! 1. bootstrap that exact PDM with `uv` (per-era pins, as
//!    `scripts/backtest-pdm.py` does) and `pdm lock` a one-dependency
//!    project on the real `six==1.16.0`, then `pdm sync` it (pristine);
//! 2. the synthetic patch appends a marker to the INSTALLED `six.py`; a
//!    wiremock Socket API serves discovery, the grant, the view and the
//!    patched wheel itself;
//! 3. hosted: `scan --redirect --vex` (same-run VEX attests); vendored:
//!    `scan --vendor --vendor-source build --vex`;
//! 4. a FRESH checkout of only the committable files (pyproject, pdm.lock,
//!    `.socket/` minus the manifest) is installed by the real `pdm sync` —
//!    from the mock patch server (hosted) or the committed wheel (vendored)
//!    — and `import six` must see the patched bytes;
//! 5. manifest-less VEX there (`vex_pypi_real_common::VexMatrix`): manifest
//!    deleted (ledger offline + online), tampered install → `hash_mismatch`
//!    (hosted), ledgers deleted (lockfile discovery + API), embedded
//!    `apply --vex` / `vendor --vex`, `--offline` with no ledger →
//!    `record_unavailable` with zero requests, and the lock reverted to the
//!    registry (ledgers + artifacts kept) → `redirect_unwired` /
//!    `vendor_unwired`, `--no-verify` included; plus a manifest-less
//!    `scan --redirect|--vendor --vex` re-run.
//!
//! Releases whose lock format loses url/path identity (PDM 1.8 – 1.15 =
//! 3.1, 2.0 – 2.7 = 4.0 – 4.2) must REFUSE both scans with the lock
//! untouched, attest nothing, and still install natively.
//!
//! `#[ignore]`d (network + minutes per release): run with `--ignored`. Gate:
//! without `uv` / PyPI it SKIPs, unless `SOCKET_PATCH_PDM_E2E_REQUIRED` is
//! set (CI), which turns every skip into a failure. Tool venvs are cached
//! under `$SOCKET_PATCH_PYPI_E2E_TOOLS` (default: the cargo target tmp dir).
//!
//! Local per-release loop (set `SOCKET_PATCH_VEX_E2E_RESULTS=<file>` to
//! collect every step's verdict as JSON lines):
//!
//! ```sh
//! for v in 0.12.3 1.0.0 1.4.5 1.8.5 1.15.5 2.0.3 2.7.4 2.8.2 2.10.4 2.11.2 2.17.3 2.20.1 2.22.4 2.25.9 2.29.2; do
//!   SOCKET_PATCH_PDM_E2E_REQUIRED=1 SOCKET_PATCH_PDM_E2E_VERSION=$v \
//!     cargo test -p socket-patch-cli --test e2e_vex_build -- pdm:: --ignored || break
//! done
//! ```

use crate::vex_e2e_common;
use crate::vex_pypi_real_common;

use std::path::{Path, PathBuf};

use vex_e2e_common::{assert_attested, git_sha256};
use vex_pypi_real_common::*;

const REQUIRED: &str = "SOCKET_PATCH_PDM_E2E_REQUIRED";
const DEFAULT_VERSION: &str = "2.29.2";
/// `pdm.lock` formats the rewriters refuse (identity-losing).
const REFUSED_LOCK_VERSIONS: [&str; 4] = ["3.1", "4.0", "4.1", "4.2"];

fn pdm_version() -> String {
    std::env::var("SOCKET_PATCH_PDM_E2E_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_VERSION.to_string())
}

fn vtuple(v: &str) -> (u32, u32, u32) {
    let mut it = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
        it.next().unwrap_or(0),
    )
}

/// The interpreter each PDM era runs on (`backtest-pdm.py::python_for`).
fn python_for(v: &str) -> &'static str {
    let t = vtuple(v);
    if t < (2, 0, 0) {
        "3.8"
    } else if t < (2, 21, 0) {
        "3.11"
    } else if t < (2, 27, 0) {
        "3.12"
    } else {
        "3.13"
    }
}

/// Per-era bootstrap pins (`backtest-pdm.py::pins_for`): 0.x/1.x carry
/// unpinned upper bounds modern PyPI resolves to incompatible releases.
fn pins_for(v: &str) -> Vec<String> {
    let t = vtuple(v);
    let mut pins: Vec<&str> = vec!["setuptools==57.5.0", "wheel==0.37.1"];
    if t < (1, 0, 0) {
        pins.extend([
            if t < (0, 9, 0) {
                "pip==20.2.4"
            } else {
                "pip==20.3.4"
            },
            "six==1.17.0",
            "toml==0.10.2",
            "tomlkit==0.7.2",
            "click==7.1.2",
            "pythonfinder==1.2.10",
            "resolvelib==0.5.5",
            "packaging==20.9",
            "requests==2.27.1",
        ]);
    } else if t < (1, 15, 0) {
        if t < (1, 5, 0) {
            pins.extend(["pip==20.3.4", "requests==2.27.1"]);
        } else if t < (1, 12, 0) {
            pins.extend(["pip==21.3.1", "requests==2.31.0"]);
        } else {
            pins.extend(["pip==22.0.4", "requests==2.31.0"]);
        }
        pins.extend([
            "six==1.17.0",
            "toml==0.10.2",
            "pythonfinder==1.2.10",
            "packaging==20.9",
        ]);
        if t < (1, 1, 0) {
            pins.push("resolvelib==0.5.5");
        }
    } else if t < (2, 0, 0) {
        pins.extend(["pip==22.0.4", "requests==2.31.0"]);
    } else {
        pins.push("pip==24.0");
        // 2.21 – 2.26.0 declare an unbounded `hishel>=0.0.32` but import
        // `hishel._serializers`, which hishel 1.0 removed (2.26.1 bounds it,
        // 2.26.9+ require 1.x).
        if ((2, 21, 0)..(2, 26, 1)).contains(&t) {
            pins.push("hishel<1");
        }
    }
    let mut out = vec![format!("pdm=={v}")];
    out.extend(pins.into_iter().map(String::from));
    out
}

/// A PDM release, bootstrapped, with a per-case isolated config.
struct Pdm {
    version: String,
    uv: PathBuf,
    venv: PathBuf,
}

impl Pdm {
    fn exe(&self) -> PathBuf {
        venv_bin(&self.venv, "pdm")
    }

    fn python(&self) -> PathBuf {
        venv_bin(&self.venv, "python")
    }

    /// `PDM_CONFIG_FILE` is honoured from 1.15; older releases read only
    /// `~/.pdm/config.toml`, so each case gets its own HOME with both.
    /// `use_venv` makes every release install into the project `.venv`
    /// (selected through `VIRTUAL_ENV`, which all of 0.12 – 2.29 honour).
    fn case_env(&self, case: &Path, project: &Path) -> Vec<(String, String)> {
        let home = case.join("home");
        let cache = case.join("pdm-cache");
        std::fs::create_dir_all(home.join(".pdm")).unwrap();
        std::fs::create_dir_all(&cache).unwrap();
        let t = vtuple(&self.version);
        let mut lines = vec![format!("cache_dir = {:?}", cache.to_str().unwrap())];
        if t >= (1, 15, 0) {
            lines.push("check_update = false".into());
            lines.push("python.use_venv = true".into());
        } else {
            if t >= (1, 5, 0) {
                lines.push("check_update = false".into());
            }
            lines.push("use_venv = true".into());
        }
        let config = lines.join("\n") + "\n";
        let config_file = case.join("pdm-config.toml");
        std::fs::write(&config_file, &config).unwrap();
        std::fs::write(home.join(".pdm/config.toml"), &config).unwrap();
        let path = format!(
            "{}:{}",
            self.venv.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        vec![
            ("HOME".into(), home.display().to_string()),
            ("PATH".into(), path),
            ("PDM_CONFIG_FILE".into(), config_file.display().to_string()),
            ("PDM_CACHE_DIR".into(), cache.display().to_string()),
            ("PDM_CHECK_UPDATE".into(), "false".into()),
            ("PDM_PYPI_URL".into(), "https://pypi.org/simple".into()),
            (
                "VIRTUAL_ENV".into(),
                project.join(".venv").display().to_string(),
            ),
        ]
    }

    fn run(
        &self,
        project: &Path,
        envs: &[(String, String)],
        args: &[&str],
    ) -> std::process::Output {
        tool(&self.exe(), project, args, envs)
    }

    /// `pdm sync` (with `--no-self` where the release has it). PDM < 1.5
    /// cannot skip the project itself; its self-install is incidental.
    fn sync(&self, project: &Path, envs: &[(String, String)]) -> std::process::Output {
        let help = self.run(project, envs, &["sync", "--help"]);
        let mut args = vec!["sync"];
        if String::from_utf8_lossy(&help.stdout).contains("--no-self") {
            args.push("--no-self");
        }
        self.run(project, envs, &args)
    }
}

/// Bootstrap the release under test, or `None` after SKIP.
fn pdm() -> Option<Pdm> {
    let version = pdm_version();
    let Some(uv) = find_uv() else {
        skip_or_fail(REQUIRED, "uv is not installed");
        return None;
    };
    match bootstrap_tool(
        &uv,
        "pdm",
        &version,
        python_for(&version),
        &pins_for(&version),
    ) {
        Ok(venv) => Some(Pdm { version, uv, venv }),
        Err(e) => {
            skip_or_fail(REQUIRED, &format!("PDM {version} bootstrap failed: {e}"));
            None
        }
    }
}

const PYPROJECT: &str = "[project]\nname = \"app\"\nversion = \"0.1.0\"\nrequires-python = \">=3.8\"\ndependencies = [\"six==1.16.0\"]\n\n[tool.pdm]\ndistribution = false\n";
/// PDM 0.x reads only the legacy `[tool.pdm]` metadata (1.0 – 1.4 accept
/// PEP 621 and migrate the legacy form into it on lock).
const LEGACY_PYPROJECT: &str = "[tool.pdm]\nname = \"app\"\nversion = \"0.1.0\"\npython_requires = \">=3.8\"\n\n[tool.pdm.dependencies]\nsix = \"==1.16.0\"\n";

fn pyproject_for(version: &str) -> &'static str {
    if vtuple(version) < (1, 0, 0) {
        LEGACY_PYPROJECT
    } else {
        PYPROJECT
    }
}

/// The registry-locked, pristine-installed project, or `None` after SKIP.
struct Locked {
    project: PathBuf,
    lock: String,
    lock_version: String,
    pristine: Vec<u8>,
}

fn lock_project(pdm: &Pdm, case: &Path) -> Option<Locked> {
    let project = case.join("proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("pyproject.toml"), pyproject_for(&pdm.version)).unwrap();
    let envs = pdm.case_env(case, &project);
    make_venv(&pdm.uv, &pdm.python(), &project.join(".venv"), &[]).expect("project venv");
    let out = pdm.run(&project, &envs, &["lock"]);
    if !out.status.success() {
        skip_or_fail(
            REQUIRED,
            &format!("pdm lock (PyPI) failed: {}", out_text(&out)),
        );
        return None;
    }
    let lock = std::fs::read_to_string(project.join("pdm.lock")).unwrap();
    let lock_version = lock
        .lines()
        .find_map(|l| l.strip_prefix("lock_version = \""))
        .map(|v| v.trim_end_matches('"').to_string())
        .unwrap_or_default();
    assert!(lock.contains("six-1.16.0-py2.py3-none-any.whl"), "{lock}");
    let out = pdm.sync(&project, &envs);
    let (_, pristine, patched) = six_oracle(&venv_bin(&project.join(".venv"), "python"), &project)
        .unwrap_or_else(|| {
            panic!(
                "pristine `pdm sync` did not install six: {}",
                out_text(&out)
            )
        });
    assert!(!patched);
    Some(Locked {
        project,
        lock,
        lock_version,
        pristine,
    })
}

fn patched_of(pristine: &[u8]) -> Vec<u8> {
    [pristine, PATCH_SUFFIX].concat()
}

fn scan_mode_args(mode: Mode) -> Vec<&'static str> {
    match mode {
        Mode::Hosted => vec!["--redirect"],
        Mode::Vendored => vec!["--vendor", "--vendor-source", "build"],
    }
}

fn flow(mode: Mode) {
    let Some(pdm) = pdm() else { return };
    let version = pdm.version.clone();
    let tmp = tempfile::tempdir().unwrap();
    let Some(locked) = lock_project(&pdm, tmp.path()) else {
        return;
    };
    let what = format!("pdm {version} {}", mode.label());
    let patched = patched_of(&locked.pristine);
    let api = RealApi::start(mode.uuid(), &locked.pristine, &patched);
    let project = &locked.project;
    let pyproject = std::fs::read_to_string(project.join("pyproject.toml")).unwrap();
    // Hosted is lock-only: nothing installed when the scan runs. Vendored
    // rebuilds the wheel from the installed release — installed by uv (as
    // `backtest-pdm.py` does): PDM <= 1.4's distlib installer writes no
    // `.dist-info/WHEEL`, which the build refuses as
    // `pypi_missing_wheel_metadata` (tags unknown).
    std::fs::remove_dir_all(project.join(".venv")).unwrap();
    let seed: &[&str] = match mode {
        Mode::Hosted => &[],
        Mode::Vendored => &["six==1.16.0"],
    };
    make_venv(&pdm.uv, &pdm.python(), &project.join(".venv"), seed).unwrap();
    let vex_out = project.join("scan.vex.json");
    let mut args = scan_mode_args(mode);
    args.extend([
        "--vex",
        vex_out.to_str().unwrap(),
        "--vex-product",
        "pkg:pypi/app@0.1.0",
    ]);
    let (code, env, stderr) = socket_scan(project, &api, &args, &[]);

    if REFUSED_LOCK_VERSIONS.contains(&locked.lock_version.as_str()) {
        // Identity-losing format: refused before any write, nothing
        // attested, and the native install still works.
        assert_eq!(
            std::fs::read_to_string(project.join("pdm.lock")).unwrap(),
            locked.lock,
            "{what}: a refused lock is never rewritten: {env}\n{stderr}"
        );
        let doc = std::fs::read(&vex_out)
            .ok()
            .map(|b| serde_json::from_slice::<serde_json::Value>(&b).unwrap());
        vex_e2e_common::assert_absent(doc.as_ref(), PURL);
        let patch_api = vex_e2e_common::PatchApi::start(vec![(
            mode.uuid().to_string(),
            view(mode.uuid(), &locked.pristine, &patched),
        )]);
        let run = vex_e2e_common::VexRun {
            patch_server_url: Some(api.uri()),
            ..vex_e2e_common::VexRun::online(&patch_api)
        };
        let fresh = tmp.path().join("fresh");
        copy_tree(
            project,
            &fresh,
            &[".venv", ".socket/manifest.json", "scan.vex.json"],
        );
        let out = vex_e2e_common::run_vex(&vex_e2e_common::binary(), &fresh, &run);
        // The refused lock was never rewritten, so nothing wires the patch:
        // `manifest_not_found` (exit 2) with no ledger, or — if the scan left
        // a ledger record behind — `no_applicable_patches` (exit 1). Either
        // way no statement and no verified event; anything else (a crash, a
        // product_undetected, a record fetch failure) is a broken gate.
        let error = out.envelope["error"]["code"].as_str().unwrap_or_default();
        match error {
            "manifest_not_found" => assert_eq!(out.code, Some(2), "{what}: {out}"),
            "no_applicable_patches" => assert_eq!(out.code, Some(1), "{what}: {out}"),
            other => panic!("{what}: unexpected outcome {other:?}: {out}"),
        }
        assert!(
            !out.envelope["events"]
                .as_array()
                .is_some_and(|events| events.iter().any(|e| e["action"] == "verified")),
            "{what}: nothing may be verified: {out}"
        );
        assert!(out.doc.is_none(), "{what}: {out}");
        make_venv(&pdm.uv, &pdm.python(), &fresh.join(".venv"), &[]).unwrap();
        let fresh_envs = pdm.case_env(tmp.path(), &fresh);
        let _ = pdm.sync(&fresh, &fresh_envs);
        let (_, bytes, marked) = six_oracle(&venv_bin(&fresh.join(".venv"), "python"), &fresh)
            .unwrap_or_else(|| panic!("{what}: native install of the refused lock failed"));
        assert!(!marked && bytes == locked.pristine, "{what}");
        record(
            "pdm",
            &version,
            &format!("lock {}/{}", locked.lock_version, mode.label()),
            "refused",
            "pass",
        );
        return;
    }

    // ── supported format: the wiring run ──────────────────────────────
    assert_eq!(code, Some(0), "{what}: scan failed: {env}\n{stderr}");
    let doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&vex_out).unwrap_or_else(|e| panic!("{what}: no same-run VEX ({e}): {env}")),
    )
    .unwrap();
    assert_attested(&doc, PURL, mode.uuid(), mode.marker(), VULNS);
    std::fs::remove_file(&vex_out).unwrap();
    let wired_lock = std::fs::read_to_string(project.join("pdm.lock")).unwrap();
    match mode {
        Mode::Hosted => assert!(
            wired_lock.contains(&api.artifact_url()),
            "{what}: {wired_lock}"
        ),
        Mode::Vendored => assert!(
            wired_lock.contains(&format!(".socket/vendor/pypi/{}/", mode.uuid())),
            "{what}: {wired_lock}"
        ),
    }
    assert_eq!(
        std::fs::read_to_string(project.join("pyproject.toml")).unwrap(),
        pyproject,
        "{what}: pyproject untouched"
    );
    record(
        "pdm",
        &version,
        &format!("lock {}/{}", locked.lock_version, mode.label()),
        "wired",
        "pass",
    );

    // ── fresh checkout, real install ──────────────────────────────────
    let fresh = tmp.path().join("fresh");
    copy_tree(
        project,
        &fresh,
        &[".venv", ".socket/manifest.json", ".pdm-python"],
    );
    assert!(!fresh.join(".socket/manifest.json").exists());
    make_venv(&pdm.uv, &pdm.python(), &fresh.join(".venv"), &[]).unwrap();
    let fresh_envs = pdm.case_env(&tmp.path().join("fresh-case"), &fresh);
    let out = pdm.sync(&fresh, &fresh_envs);
    let (module, bytes, marked) = six_oracle(&venv_bin(&fresh.join(".venv"), "python"), &fresh)
        .unwrap_or_else(|| {
            panic!(
                "{what}: fresh `pdm sync` did not install six: {}",
                out_text(&out)
            )
        });
    assert!(
        marked,
        "{what}: the patched module must be imported: {}",
        out_text(&out)
    );
    assert_eq!(git_sha256(&bytes), git_sha256(&patched), "{what}");
    assert_eq!(
        std::fs::read_to_string(fresh.join("pdm.lock")).unwrap(),
        wired_lock,
        "{what}: pdm sync keeps the wired lock"
    );
    record(
        "pdm",
        &version,
        &format!("lock {}/{}", locked.lock_version, mode.label()),
        "installed-patched",
        "pass",
    );

    // ── manifest-less VEX ─────────────────────────────────────────────
    // Embedded re-scan on the manifest-less checkout first (ledgers intact).
    let rescan_vex = fresh.join("rescan.vex.json");
    let mut args = scan_mode_args(mode);
    args.extend([
        "--vex",
        rescan_vex.to_str().unwrap(),
        "--vex-product",
        "pkg:pypi/app@0.1.0",
    ]);
    let (code, env, stderr) = socket_scan(&fresh, &api, &args, &[]);
    assert_eq!(
        code,
        Some(0),
        "{what}: manifest-less re-scan: {env}\n{stderr}"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&rescan_vex).unwrap()).unwrap();
    assert_attested(&doc, PURL, mode.uuid(), mode.marker(), VULNS);
    std::fs::remove_file(&rescan_vex).unwrap();
    let _ = std::fs::remove_file(fresh.join(".socket/manifest.json"));
    assert_eq!(
        std::fs::read_to_string(fresh.join("pdm.lock")).unwrap(),
        wired_lock,
        "{what}: re-scan idempotent"
    );
    record(
        "pdm",
        &version,
        &format!("lock {}/{}", locked.lock_version, mode.label()),
        "embedded-rescan-vex",
        "pass",
    );

    let pristine_lock = locked.lock.clone();
    let matrix = VexMatrix {
        pm: "pdm",
        version: &version,
        cell: format!("lock {}", locked.lock_version),
        mode,
        pristine: &locked.pristine,
        patched: &patched,
        patch_server: api.uri(),
        envs: Vec::new(),
        installed_module: Some(module),
    };
    matrix.run(&fresh, project, &|dir: &Path| {
        std::fs::write(dir.join("pdm.lock"), &pristine_lock).unwrap();
    });
}

#[test]
#[ignore = "real PDM + PyPI; run with --ignored (CI: SOCKET_PATCH_PDM_E2E_REQUIRED=1)"]
fn pdm_hosted_install_then_manifest_less_vex() {
    flow(Mode::Hosted);
}

#[test]
#[ignore = "real PDM + PyPI; run with --ignored (CI: SOCKET_PATCH_PDM_E2E_REQUIRED=1)"]
fn pdm_vendored_install_then_manifest_less_vex() {
    flow(Mode::Vendored);
}
