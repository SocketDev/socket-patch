//! Real-Hatch capstone: HOSTED and VENDORED patches end to end with a pinned
//! Hatch 1.x release, finishing in manifest-less `socket-patch vex`. Before
//! this suite no real-Hatch e2e existed in this repo (the depscan companion
//! PR's `hatch-patch-backtest.py` was the only native coverage).
//!
//! Per Hatch release (`SOCKET_PATCH_HATCH_E2E_VERSION`, default
//! [`DEFAULT_VERSION`]) and per declaration flavor — `[project]
//! dependencies` (hatchling backend) and a `hatch.toml` `[envs.default]`
//! environment dependency:
//!
//! 1. bootstrap that Hatch with `uv`; the real `six==1.16.0` from PyPI is
//!    the pristine release (vendored: installed in the project venv the
//!    build rebuilds the wheel from; hosted: outside the project — the
//!    hosted rewriter reads the exact pin from the declaration);
//! 2. the synthetic patch appends a marker to `six.py`; a wiremock Socket
//!    API serves discovery, the grant, the view and the patched wheel;
//! 3. hosted: `scan --redirect --vex`; vendored: `scan --vendor
//!    --vendor-source build --vex` — the same-run VEX attests, and the
//!    declaration becomes `six @ <url>#sha256=…` /
//!    `six @ {root:uri}/.socket/vendor/pypi/<uuid>/<wheel>#sha256=…`;
//! 4. a FRESH checkout of the committable files (pyproject / hatch.toml,
//!    the package, `.socket/` minus the manifest) is installed by the real
//!    `hatch env create` (pip installer) and `import six` in that
//!    environment must see the patched bytes;
//! 5. manifest-less VEX there (`vex_pypi_real_common::VexMatrix`, with
//!    `VIRTUAL_ENV` naming Hatch's out-of-tree environment so the crawler
//!    hashes the real install): manifest deleted, tampered install (hosted),
//!    ledgers deleted, embedded `apply --vex` / `vendor --vex`, offline with
//!    no ledger → `record_unavailable`, declaration reverted →
//!    `redirect_unwired` / `vendor_unwired` (`--no-verify` too); plus the
//!    manifest-less `scan --vex` re-run and, hosted, the not-installed
//!    (pin) basis.
//!
//! Hatch 1.0 / 1.1 do not expand `{root:uri}` in environment
//! dependencies: the vendored ENV flavor must be refused
//! (`pypi_hatch_unsupported`) with the files untouched and nothing
//! attested.
//!
//! `#[ignore]`d (network + minutes per release): run with `--ignored`. Gate:
//! without `uv` / PyPI it SKIPs, unless `SOCKET_PATCH_HATCH_E2E_REQUIRED` is
//! set (CI). Tool venvs are cached under `$SOCKET_PATCH_PYPI_E2E_TOOLS`.
//!
//! Local per-release loop (set `SOCKET_PATCH_VEX_E2E_RESULTS=<file>` to
//! collect every step's verdict as JSON lines):
//!
//! ```sh
//! for v in 1.0.0 1.1.2 1.2.1 1.4.2 1.6.3 1.7.0 1.9.7 1.12.0 1.13.0 1.14.2 1.16.5 1.18.1; do
//!   SOCKET_PATCH_HATCH_E2E_REQUIRED=1 SOCKET_PATCH_HATCH_E2E_VERSION=$v \
//!     cargo test -p socket-patch-cli --test e2e_vex_build -- hatch:: --ignored || break
//! done
//! ```

use crate::vex_e2e_common;
use crate::vex_pypi_real_common;

use std::path::{Path, PathBuf};

use vex_e2e_common::{assert_attested, git_sha256};
use vex_pypi_real_common::*;

const REQUIRED: &str = "SOCKET_PATCH_HATCH_E2E_REQUIRED";
const DEFAULT_VERSION: &str = "1.16.5";
const PRODUCT: &str = "pkg:pypi/app@0.1.0";
const BUILD: &str =
    "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n";

fn hatch_version() -> String {
    std::env::var("SOCKET_PATCH_HATCH_E2E_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_VERSION.to_string())
}

fn vtuple(v: &str) -> (u32, u32) {
    let mut it = v.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    /// `[project].dependencies`.
    Project,
    /// `hatch.toml` `[envs.default].dependencies`.
    HatchTomlEnv,
}

impl Flavor {
    fn label(self) -> &'static str {
        match self {
            Flavor::Project => "project-deps",
            Flavor::HatchTomlEnv => "hatch.toml-env",
        }
    }

    fn native(self) -> Vec<(&'static str, String)> {
        let project = |deps: &str| {
            format!(
                "{BUILD}[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = {deps}\n"
            )
        };
        match self {
            Flavor::Project => vec![("pyproject.toml", project("[\"six==1.16.0\"]"))],
            Flavor::HatchTomlEnv => vec![
                ("pyproject.toml", project("[]")),
                (
                    "hatch.toml",
                    "[envs.default]\ndependencies = [\"six==1.16.0\"]\n".into(),
                ),
            ],
        }
    }
}

struct Hatch {
    version: String,
    uv: PathBuf,
    venv: PathBuf,
}

impl Hatch {
    fn exe(&self) -> PathBuf {
        venv_bin(&self.venv, "hatch")
    }

    fn python(&self) -> PathBuf {
        venv_bin(&self.venv, "python")
    }

    fn bin_path(&self) -> String {
        format!(
            "{}:{}",
            self.venv.join("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        )
    }

    /// Isolated Hatch state for one case: HOME, data (environments),
    /// cache and config all under `case`.
    fn case_env(&self, case: &Path) -> Vec<(String, String)> {
        for dir in ["home", "hatch-data", "hatch-cache"] {
            std::fs::create_dir_all(case.join(dir)).unwrap();
        }
        let config = case.join("hatch-config.toml");
        if !config.exists() {
            std::fs::write(&config, "").unwrap();
        }
        vec![
            ("HOME".into(), case.join("home").display().to_string()),
            ("PATH".into(), self.bin_path()),
            (
                "HATCH_DATA_DIR".into(),
                case.join("hatch-data").display().to_string(),
            ),
            (
                "HATCH_CACHE_DIR".into(),
                case.join("hatch-cache").display().to_string(),
            ),
            ("HATCH_CONFIG".into(), config.display().to_string()),
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
}

/// Hatch 1.10 – 1.14 declare an unbounded `virtualenv` but call
/// `virtualenv.discovery.builtin.propose_interpreters`, which virtualenv 21
/// removed (every `hatch env create` then fails "Environment `default` is
/// incompatible"); 1.15+ work with 21.
fn pins_for(version: &str) -> Vec<String> {
    let mut pins = vec![format!("hatch=={version}")];
    let t = vtuple(version);
    if ((1, 10)..(1, 15)).contains(&t) {
        pins.push("virtualenv<21".into());
    }
    pins
}

fn hatch() -> Option<Hatch> {
    let version = hatch_version();
    let Some(uv) = find_uv() else {
        skip_or_fail(REQUIRED, "uv is not installed");
        return None;
    };
    match bootstrap_tool(&uv, "hatch", &version, "3.12", &pins_for(&version)) {
        Ok(venv) => Some(Hatch { version, uv, venv }),
        Err(e) => {
            skip_or_fail(REQUIRED, &format!("Hatch {version} bootstrap failed: {e}"));
            None
        }
    }
}

fn scan_mode_args(mode: Mode) -> Vec<&'static str> {
    match mode {
        Mode::Hosted => vec!["--redirect"],
        Mode::Vendored => vec!["--vendor", "--vendor-source", "build"],
    }
}

fn write_native(dir: &Path, flavor: Flavor) {
    for (rel, text) in flavor.native() {
        std::fs::write(dir.join(rel), text).unwrap();
    }
}

fn flow(flavor: Flavor, mode: Mode) {
    let Some(hatch) = hatch() else { return };
    let version = hatch.version.clone();
    let cell = flavor.label();
    let what = format!("hatch {version} {cell} {}", mode.label());
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("proj");
    std::fs::create_dir_all(project.join("app")).unwrap();
    std::fs::write(project.join("app/__init__.py"), "").unwrap();
    write_native(&project, flavor);

    // The pristine release from PyPI. Vendored: inside the project, where
    // the build rebuilds the wheel from it. Hosted: OUTSIDE it — the hosted
    // rewriter reads the exact pin from the declaration itself, and a stale
    // pristine copy the crawler could see would (correctly) make the
    // same-run VEX omit the patch as `not_applied`.
    let pristine_venv = match mode {
        Mode::Vendored => project.join(".venv"),
        Mode::Hosted => tmp.path().join("pristine-venv"),
    };
    if let Err(e) = make_venv(&hatch.uv, &hatch.python(), &pristine_venv, &["six==1.16.0"]) {
        skip_or_fail(REQUIRED, &format!("{what}: six==1.16.0 from PyPI: {e}"));
        return;
    }
    let (_, pristine, _) =
        six_oracle(&venv_bin(&pristine_venv, "python"), &project).expect("pristine six");
    let patched = [pristine.as_slice(), PATCH_SUFFIX].concat();
    let api = RealApi::start(mode.uuid(), &pristine, &patched);
    let vex_out = project.join("scan.vex.json");
    let mut args = scan_mode_args(mode);
    args.extend(["--vex", vex_out.to_str().unwrap(), "--vex-product", PRODUCT]);
    let scan_envs = vec![("PATH".to_string(), hatch.bin_path())];
    let (code, env, stderr) = socket_scan(&project, &api, &args, &scan_envs);

    if mode == Mode::Vendored && flavor == Flavor::HatchTomlEnv && vtuple(&version) < (1, 2) {
        assert_ne!(code, Some(0), "{what}: must refuse: {env}");
        let codes: Vec<&str> = env["vendor"]["events"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e["errorCode"].as_str())
            .collect();
        assert!(
            codes.contains(&"pypi_hatch_unsupported"),
            "{what}: {env}\n{stderr}"
        );
        for (rel, text) in flavor.native() {
            assert_eq!(
                std::fs::read_to_string(project.join(rel)).unwrap(),
                text,
                "{what}: {rel}"
            );
        }
        let doc = std::fs::read(&vex_out)
            .ok()
            .map(|b| serde_json::from_slice::<serde_json::Value>(&b).unwrap());
        vex_e2e_common::assert_absent(doc.as_ref(), PURL);
        record(
            "hatch",
            &version,
            &format!("{cell}/{}", mode.label()),
            "refused",
            "pass",
        );
        return;
    }

    // ── the wiring run ────────────────────────────────────────────────
    assert_eq!(code, Some(0), "{what}: scan failed: {env}\n{stderr}");
    let doc: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&vex_out).unwrap_or_else(|e| panic!("{what}: no same-run VEX ({e}): {env}")),
    )
    .unwrap();
    assert_attested(&doc, PURL, mode.uuid(), mode.marker(), VULNS);
    std::fs::remove_file(&vex_out).unwrap();
    let wired_file = match flavor {
        Flavor::Project => "pyproject.toml",
        Flavor::HatchTomlEnv => "hatch.toml",
    };
    let wired = std::fs::read_to_string(project.join(wired_file)).unwrap();
    match mode {
        Mode::Hosted => assert!(
            wired.contains(&format!(
                "six @ {}#sha256={}",
                api.artifact_url(),
                api.wheel_sha256
            )),
            "{what}: {wired}"
        ),
        Mode::Vendored => assert!(
            wired.contains(&format!(
                "six @ {{root:uri}}/.socket/vendor/pypi/{}/",
                mode.uuid()
            )),
            "{what}: {wired}"
        ),
    }
    let _ = std::fs::remove_dir_all(project.join(".venv"));
    record(
        "hatch",
        &version,
        &format!("{cell}/{}", mode.label()),
        "wired",
        "pass",
    );

    // ── fresh checkout, real `hatch env create` ───────────────────────
    let fresh = tmp.path().join("fresh");
    copy_tree(&project, &fresh, &[".socket/manifest.json"]);
    let case_envs = hatch.case_env(&tmp.path().join("fresh-case"));
    let out = hatch.run(&fresh, &case_envs, &["env", "create"]);
    assert_ok(&out, &format!("{what}: hatch env create"));
    let found = hatch.run(&fresh, &case_envs, &["env", "find"]);
    assert_ok(&found, &format!("{what}: hatch env find"));
    let env_dir = PathBuf::from(
        String::from_utf8_lossy(&found.stdout)
            .trim()
            .lines()
            .last()
            .unwrap()
            .trim(),
    );
    let (module, bytes, marked) =
        six_oracle(&venv_bin(&env_dir, "python"), &fresh).unwrap_or_else(|| {
            panic!(
                "{what}: six not installed in {env_dir:?}: {}",
                out_text(&out)
            )
        });
    assert!(
        marked,
        "{what}: the patched module must be imported: {}",
        out_text(&out)
    );
    assert_eq!(git_sha256(&bytes), git_sha256(&patched), "{what}");
    assert!(
        module.starts_with(&env_dir),
        "{what}: {module:?} outside {env_dir:?}"
    );
    record(
        "hatch",
        &version,
        &format!("{cell}/{}", mode.label()),
        "installed-patched",
        "pass",
    );

    // ── manifest-less VEX ─────────────────────────────────────────────
    let virtual_env = ("VIRTUAL_ENV".to_string(), env_dir.display().to_string());
    // Embedded re-scan on the manifest-less checkout (ledgers intact),
    // with the Hatch environment visible to the crawler.
    let rescan_vex = fresh.join("rescan.vex.json");
    let mut args = scan_mode_args(mode);
    args.extend([
        "--vex",
        rescan_vex.to_str().unwrap(),
        "--vex-product",
        PRODUCT,
    ]);
    let (code, env, stderr) = socket_scan(
        &fresh,
        &api,
        &args,
        &[scan_envs[0].clone(), virtual_env.clone()],
    );
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
        std::fs::read_to_string(fresh.join(wired_file)).unwrap(),
        wired,
        "{what}: re-scan idempotent"
    );
    record(
        "hatch",
        &version,
        &format!("{cell}/{}", mode.label()),
        "embedded-rescan-vex",
        "pass",
    );

    if mode == Mode::Hosted {
        // Not installed as far as the crawler knows (no VIRTUAL_ENV, no
        // in-project venv): the declaration's sha256 pin is the basis.
        let patch_api = vex_e2e_common::PatchApi::start(vec![(
            mode.uuid().to_string(),
            view(mode.uuid(), &pristine, &patched),
        )]);
        let run = vex_e2e_common::VexRun {
            patch_server_url: Some(api.uri()),
            product: Some(PRODUCT.into()),
            ..vex_e2e_common::VexRun::online(&patch_api)
        };
        let out = vex_e2e_common::run_vex(&vex_e2e_common::binary(), &fresh, &run);
        assert_eq!(out.code, Some(0), "{what}: pin basis: {out}");
        assert_attested(out.doc(), PURL, mode.uuid(), mode.marker(), VULNS);
        record(
            "hatch",
            &version,
            &format!("{cell}/{}", mode.label()),
            "pin-basis-not-installed",
            "pass",
        );
    }

    let matrix = VexMatrix {
        pm: "hatch",
        version: &version,
        cell: cell.to_string(),
        mode,
        pristine: &pristine,
        patched: &patched,
        patch_server: api.uri(),
        envs: vec![(virtual_env.0.clone(), virtual_env.1.clone().into())],
        installed_module: Some(module),
    };
    matrix.run(&fresh, &project, &|dir: &Path| write_native(dir, flavor));
}

#[test]
#[ignore = "real Hatch + PyPI; run with --ignored (CI: SOCKET_PATCH_HATCH_E2E_REQUIRED=1)"]
fn hatch_project_dependency_hosted() {
    flow(Flavor::Project, Mode::Hosted);
}

#[test]
#[ignore = "real Hatch + PyPI; run with --ignored (CI: SOCKET_PATCH_HATCH_E2E_REQUIRED=1)"]
fn hatch_project_dependency_vendored() {
    flow(Flavor::Project, Mode::Vendored);
}

#[test]
#[ignore = "real Hatch + PyPI; run with --ignored (CI: SOCKET_PATCH_HATCH_E2E_REQUIRED=1)"]
fn hatch_toml_environment_dependency_hosted() {
    flow(Flavor::HatchTomlEnv, Mode::Hosted);
}

#[test]
#[ignore = "real Hatch + PyPI; run with --ignored (CI: SOCKET_PATCH_HATCH_E2E_REQUIRED=1)"]
fn hatch_toml_environment_dependency_vendored() {
    flow(Flavor::HatchTomlEnv, Mode::Vendored);
}
