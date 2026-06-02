//! Shared harness for the experimental `socket-patch setup` end-to-end
//! test matrix (`tests/setup_matrix_*.rs`, gated by the `setup-e2e`
//! feature).
//!
//! Each `setup_matrix_<eco>.rs` wrapper pulls this in with
//! `#[path = "setup_matrix_common/mod.rs"] mod smc;` and calls
//! [`run_pm`] for each package manager it covers. The wrappers are
//! thin; ALL the flow logic lives in the single bash driver
//! `tests/setup_matrix/run-case.sh`, which this module invokes either
//! inside a Docker container (default) or on the host
//! (`SOCKET_PATCH_TEST_HOST=1`). The declarative case list comes from
//! `tests/setup_matrix/matrix.json` — the same spec the
//! `scripts/setup-matrix.sh` orchestrator consumes.
//!
//! ASPIRATIONAL assertion: each case asserts the *ideal* — that after
//! `setup` + a native install, the patch is (or isn't) applied as the
//! scenario expects. For ecosystems whose install hooks `setup` does
//! not yet configure, the `baseline_with_setup` / `alt_content_patchset`
//! cases are EXPECTED to fail; the failure message tags them
//! `BASELINE GAP` so the red is understood as a TODO, not a surprise.
//!
//! `#![allow(dead_code)]` — wrappers use different subsets of this API.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Path to the built binary under test (host mode passes this to the
/// driver via `SOCKET_PATCH_BIN`).
fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Workspace root = two levels up from this crate's manifest dir.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn driver_path() -> PathBuf {
    workspace_root().join("tests/setup_matrix/run-case.sh")
}

fn matrix_path() -> PathBuf {
    workspace_root().join("tests/setup_matrix/matrix.json")
}

/// Host mode runs the driver against host-installed toolchains instead
/// of a container. Mirrors the `docker_e2e_*` convention.
fn host_mode() -> bool {
    std::env::var("SOCKET_PATCH_TEST_HOST").map(|v| v == "1").unwrap_or(false)
}

fn docker_on_path() -> bool {
    Command::new("docker")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn image_present(image: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", &format!("socket-patch-test-{image}:latest")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// One concrete case = a (target, scenario) pair from matrix.json.
#[derive(Clone)]
struct Case {
    id: String,
    ecosystem: String,
    pm: String,
    image: String,
    scenario: String,
    patchset: String,
    run_setup: bool,
    expect_applied: bool,
    baseline_supported: bool,
    package: String,
    version: String,
    purl: String,
    manifest_key: String,
    apply_ecosystems: String,
    marker: String,
    alt_marker: String,
}

impl Case {
    /// Baseline (currently-known) outcome under today's code:
    /// `setup` only wires npm-family hooks, so applied is expected only
    /// when the target advertises `baseline_supported` AND the scenario
    /// aspires to apply.
    fn baseline_applied(&self) -> bool {
        self.expect_applied && self.baseline_supported
    }

    fn sm_env(&self) -> Vec<(String, String)> {
        vec![
            ("SM_ID".into(), self.id.clone()),
            ("SM_ECOSYSTEM".into(), self.ecosystem.clone()),
            ("SM_PM".into(), self.pm.clone()),
            ("SM_SCENARIO".into(), self.scenario.clone()),
            ("SM_PATCHSET".into(), self.patchset.clone()),
            ("SM_RUN_SETUP".into(), if self.run_setup { "1" } else { "0" }.into()),
            ("SM_EXPECT_APPLIED".into(), if self.expect_applied { "1" } else { "0" }.into()),
            ("SM_PACKAGE".into(), self.package.clone()),
            ("SM_VERSION".into(), self.version.clone()),
            ("SM_PURL".into(), self.purl.clone()),
            ("SM_MANIFEST_KEY".into(), self.manifest_key.clone()),
            ("SM_APPLY_ECOSYSTEMS".into(), self.apply_ecosystems.clone()),
            ("SM_MARKER".into(), self.marker.clone()),
            ("SM_ALT_MARKER".into(), self.alt_marker.clone()),
        ]
    }
}

/// Load every case for a given (ecosystem, pm) by crossing that target
/// with all scenarios in the spec.
fn load_cases(ecosystem: &str, pm: &str) -> Vec<Case> {
    let text = std::fs::read_to_string(matrix_path())
        .unwrap_or_else(|e| panic!("read matrix.json: {e}"));
    let spec: serde_json::Value =
        serde_json::from_str(&text).expect("parse matrix.json");
    let marker = spec["marker"].as_str().unwrap_or("").to_string();
    let alt_marker = spec["alt_marker"].as_str().unwrap_or("").to_string();

    let target = spec["targets"]
        .as_array()
        .expect("targets array")
        .iter()
        .find(|t| t["ecosystem"] == ecosystem && t["pm"] == pm)
        .unwrap_or_else(|| panic!("no target for {ecosystem}/{pm} in matrix.json"));

    let mut cases = Vec::new();
    for s in spec["scenarios"].as_array().expect("scenarios array") {
        let scenario = s["id"].as_str().unwrap().to_string();
        cases.push(Case {
            id: format!("{ecosystem}/{pm}/{scenario}"),
            ecosystem: ecosystem.to_string(),
            pm: pm.to_string(),
            image: target["image"].as_str().unwrap().to_string(),
            scenario,
            patchset: s["patchset"].as_str().unwrap().to_string(),
            run_setup: s["run_setup"].as_bool().unwrap(),
            expect_applied: s["expect_applied"].as_bool().unwrap(),
            baseline_supported: target["baseline_supported"].as_bool().unwrap(),
            package: target["package"].as_str().unwrap().to_string(),
            version: target["version"].as_str().unwrap().to_string(),
            purl: target["purl"].as_str().unwrap().to_string(),
            manifest_key: target["manifest_key"].as_str().unwrap().to_string(),
            apply_ecosystems: target["apply_ecosystems"].as_str().unwrap().to_string(),
            marker: marker.clone(),
            alt_marker: alt_marker.clone(),
        });
    }
    cases
}

struct RunResult {
    actual_applied: bool,
    raw: String,
    parsed: Option<serde_json::Value>,
}

/// Execute one case via the bash driver (container or host) and parse
/// its JSON result line.
fn run_case(case: &Case) -> RunResult {
    let driver = driver_path();
    let env = case.sm_env();

    let output = if host_mode() {
        let mut cmd = Command::new("bash");
        cmd.arg(&driver);
        for (k, v) in &env {
            cmd.env(k, v);
        }
        cmd.env("SOCKET_PATCH_BIN", binary());
        cmd.output().expect("spawn bash driver")
    } else {
        let script = std::fs::read_to_string(&driver)
            .unwrap_or_else(|e| panic!("read driver: {e}"));
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm"]);
        for (k, v) in &env {
            cmd.args(["-e", &format!("{k}={v}")]);
        }
        cmd.arg(format!("socket-patch-test-{}:latest", case.image));
        cmd.args(["bash", "-c", &script]);
        cmd.output().expect("spawn docker run")
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // The driver prints its result JSON as the last matching stdout line.
    let line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{') && l.contains("actual_applied"));

    let parsed = line.and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok());
    let actual_applied = parsed
        .as_ref()
        .and_then(|v| v["actual_applied"].as_bool())
        .unwrap_or(false);

    RunResult {
        actual_applied,
        raw: format!("stdout:\n{stdout}\nstderr:\n{stderr}"),
        parsed,
    }
}

/// Run every scenario for one (ecosystem, pm) and assert each meets the
/// ASPIRATIONAL expectation. Soft-skips when Docker / the ecosystem
/// image is unavailable (container mode) — matching the `docker_e2e_*`
/// convention where Rust integration tests have no native "skipped".
pub fn run_pm(ecosystem: &str, pm: &str) {
    if !host_mode() && !docker_on_path() {
        eprintln!("skip {ecosystem}/{pm}: docker not on PATH (set SOCKET_PATCH_TEST_HOST=1 to run on host)");
        return;
    }

    let cases = load_cases(ecosystem, pm);
    if !host_mode() {
        if let Some(c) = cases.first() {
            if !image_present(&c.image) {
                eprintln!(
                    "skip {ecosystem}/{pm}: image socket-patch-test-{}:latest not present \
                     (build it: scripts/setup-matrix.sh build --ecosystem {})",
                    c.image, c.image
                );
                return;
            }
        }
    }

    let mut failures = Vec::new();
    for case in &cases {
        let res = run_case(case);
        if res.actual_applied != case.expect_applied {
            let tag = if case.baseline_applied() {
                // We recorded this as working; failing now is a real regression.
                "REGRESSION (baseline says this should apply)"
            } else if case.expect_applied {
                "BASELINE GAP (setup does not yet wire this package manager)"
            } else {
                "LEAK (patch applied without the hook configuring it)"
            };
            failures.push(format!(
                "  - {}: expected applied={}, got {} [{}]\n{}",
                case.id, case.expect_applied, res.actual_applied, tag, indent(&res.raw)
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{}/{}: {} of {} setup-matrix case(s) did not meet the aspirational \
         expectation. BASELINE GAP entries are the experimental TODO list \
         (this suite is non-blocking in CI); REGRESSION / LEAK entries are \
         real problems:\n{}",
        ecosystem,
        pm,
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("      {l}")).collect::<Vec<_>>().join("\n")
}
