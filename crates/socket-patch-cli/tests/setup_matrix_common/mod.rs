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
use std::sync::OnceLock;

/// Path to the built binary under test (host mode passes this to the
/// driver via `SOCKET_PATCH_BIN`).
fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Build the pure-python `socket-patch-hook` wheel once and cache the path.
/// The pypi cases need it to exercise the `.pth` post-install hook; returns
/// `None` if the build fails (those cases then degrade to a gap). Requires
/// `python3` on PATH (always present in the pypi image / host pypi runs).
fn hook_wheel() -> Option<PathBuf> {
    static CELL: OnceLock<Option<PathBuf>> = OnceLock::new();
    CELL.get_or_init(|| {
        let root = workspace_root();
        let dist = root.join("target/setup-matrix-hook");
        std::fs::create_dir_all(&dist).ok()?;
        let version = env!("CARGO_PKG_VERSION");
        let ok = Command::new("python3")
            .arg(root.join("scripts/build-pypi-wheels.py"))
            .args(["--version", version, "--hook-only", "--dist"])
            .arg(&dist)
            .stdout(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            return None;
        }
        let wheel = dist.join(format!("socket_patch_hook-{version}-py3-none-any.whl"));
        wheel.exists().then_some(wheel)
    })
    .clone()
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
    /// On the temporary `known_regressions` allowlist in matrix.json: a case the
    /// baseline says should work but currently doesn't — tracked + tolerated
    /// (non-blocking), not a hard failure, until the underlying hook is fixed.
    known_regression: bool,
    package: String,
    version: String,
    purl: String,
    manifest_key: String,
    apply_ecosystems: String,
    marker: String,
    alt_marker: String,
    layout: String,
}

impl Case {
    /// Baseline (currently-known) outcome under today's code:
    /// `setup` only wires npm-family hooks, so applied is expected only
    /// when the target advertises `baseline_supported` AND the scenario
    /// aspires to apply.
    fn baseline_applied(&self) -> bool {
        self.expect_applied && self.baseline_supported
    }

    /// npm-family package managers (plus the polyglot monorepo's npm slice)
    /// are the surface `setup` actually configures today — the only cases
    /// where the check/remove round-trip is expected to do real work.
    fn is_npm_family(&self) -> bool {
        matches!(self.pm.as_str(), "npm" | "yarn" | "pnpm" | "bun") || self.layout == "monorepo"
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
            ("SM_LAYOUT".into(), self.layout.clone()),
        ]
    }
}

/// Load every case for a given (ecosystem, pm) by crossing the matching
/// target in `targets_key` with every scenario in `scenarios_key`,
/// tagging each with `layout`. `targets_key`/`scenarios_key` select the
/// spec section: ("targets","scenarios") for single projects,
/// ("workspace_targets","workspace_scenarios") for nested workspaces,
/// ("monorepo_targets","monorepo_scenarios") for the polyglot monorepo.
fn load_section(
    targets_key: &str,
    scenarios_key: &str,
    layout: &str,
    ecosystem: &str,
    pm: &str,
) -> Vec<Case> {
    let text = std::fs::read_to_string(matrix_path())
        .unwrap_or_else(|e| panic!("read matrix.json: {e}"));
    let spec: serde_json::Value =
        serde_json::from_str(&text).expect("parse matrix.json");
    let marker = spec["marker"].as_str().unwrap_or("").to_string();
    let alt_marker = spec["alt_marker"].as_str().unwrap_or("").to_string();
    let known_regressions: std::collections::HashSet<String> = spec["known_regressions"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let target = spec[targets_key]
        .as_array()
        .unwrap_or_else(|| panic!("{targets_key} array missing"))
        .iter()
        .find(|t| t["ecosystem"] == ecosystem && t["pm"] == pm)
        .unwrap_or_else(|| panic!("no {targets_key} entry for {ecosystem}/{pm}"));

    let mut cases = Vec::new();
    for s in spec[scenarios_key].as_array().expect("scenarios array") {
        let scenario = s["id"].as_str().unwrap().to_string();
        let case_id = format!("{ecosystem}/{pm}/{scenario}");
        cases.push(Case {
            id: case_id.clone(),
            ecosystem: ecosystem.to_string(),
            pm: pm.to_string(),
            image: target["image"].as_str().unwrap().to_string(),
            scenario,
            patchset: s["patchset"].as_str().unwrap().to_string(),
            run_setup: s["run_setup"].as_bool().unwrap(),
            expect_applied: s["expect_applied"].as_bool().unwrap(),
            baseline_supported: target["baseline_supported"].as_bool().unwrap(),
            known_regression: known_regressions.contains(&case_id),
            package: target["package"].as_str().unwrap().to_string(),
            version: target["version"].as_str().unwrap().to_string(),
            purl: target["purl"].as_str().unwrap().to_string(),
            manifest_key: target["manifest_key"].as_str().unwrap().to_string(),
            apply_ecosystems: target["apply_ecosystems"].as_str().unwrap().to_string(),
            marker: marker.clone(),
            alt_marker: alt_marker.clone(),
            layout: layout.to_string(),
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

    // The pypi cases need the prebuilt hook wheel to exercise the `.pth`
    // post-install hook; other ecosystems ignore it.
    let wheel = if case.ecosystem == "pypi" {
        hook_wheel()
    } else {
        None
    };

    let output = if host_mode() {
        let mut cmd = Command::new("bash");
        cmd.arg(&driver);
        for (k, v) in &env {
            cmd.env(k, v);
        }
        cmd.env("SOCKET_PATCH_BIN", binary());
        if let Some(w) = &wheel {
            cmd.env("SOCKET_PATCH_HOOK_WHEEL", w);
        }
        cmd.output().expect("spawn bash driver")
    } else {
        let script = std::fs::read_to_string(&driver)
            .unwrap_or_else(|e| panic!("read driver: {e}"));
        let mut cmd = Command::new("docker");
        cmd.args(["run", "--rm"]);
        for (k, v) in &env {
            cmd.args(["-e", &format!("{k}={v}")]);
        }
        // Mount the hook wheel into the container, PRESERVING its PEP 427
        // filename (pip/uv/pdm reject a wheel whose filename isn't a valid
        // `{name}-{ver}-{tags}.whl`, so we must not rename it on mount).
        if let Some(w) = &wheel {
            let name = w
                .file_name()
                .and_then(|n| n.to_str())
                .expect("hook wheel filename");
            let dest = format!("/tmp/{name}");
            cmd.args([
                "-v",
                &format!("{}:{}:ro", w.display(), dest),
                "-e",
                &format!("SOCKET_PATCH_HOOK_WHEEL={dest}"),
            ]);
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

/// Run the single-project scenarios for one (ecosystem, pm).
pub fn run_pm(ecosystem: &str, pm: &str) {
    run_cases(
        &format!("{ecosystem}/{pm}"),
        load_section("targets", "scenarios", "single", ecosystem, pm),
    );
}

/// Run the nested-workspace scenarios for one (ecosystem, pm).
pub fn run_workspace_pm(ecosystem: &str, pm: &str) {
    run_cases(
        &format!("{ecosystem}/{pm} [workspace]"),
        load_section("workspace_targets", "workspace_scenarios", "workspace", ecosystem, pm),
    );
}

/// Run the polyglot all-ecosystem monorepo scenarios.
pub fn run_monorepo() {
    run_cases(
        "monorepo",
        load_section("monorepo_targets", "monorepo_scenarios", "monorepo", "monorepo", "mono"),
    );
}

/// Execute a set of cases and assert each meets the ASPIRATIONAL
/// expectation. Soft-skips when Docker / the ecosystem image is
/// unavailable (container mode) — matching the `docker_e2e_*` convention
/// where Rust integration tests have no native "skipped".
fn run_cases(label: &str, cases: Vec<Case>) {
    if !host_mode() && !docker_on_path() {
        eprintln!("skip {label}: docker not on PATH (set SOCKET_PATCH_TEST_HOST=1 to run on host)");
        return;
    }
    if !host_mode() {
        if let Some(c) = cases.first() {
            if !image_present(&c.image) {
                eprintln!(
                    "skip {label}: image socket-patch-test-{}:latest not present \
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

        // The bash driver MUST emit exactly one parseable result line carrying
        // a real boolean `actual_applied`. If it does not (binary crashed,
        // docker error, script aborted before `emit_result`, malformed JSON),
        // the case never actually exercised setup+install. Without this guard
        // `run_case` falls back to `actual_applied = false`, which silently
        // satisfies EVERY `expect_applied == false` case — and makes the
        // round-trip `?` no-op — turning a broken harness fully green for the
        // wrong reason. Treat a missing/garbled result as a hard failure
        // regardless of the aspirational expectation (allowlist included).
        let applied = match res
            .parsed
            .as_ref()
            .and_then(|v| v.get("actual_applied"))
            .and_then(|v| v.as_bool())
        {
            Some(b) => b,
            None => {
                failures.push(format!(
                    "  - {}: driver emitted no parseable result line with a boolean \
                     `actual_applied` — the case did not run to completion (this is a \
                     harness/binary failure, NOT a baseline gap)\n{}",
                    case.id,
                    indent(&res.raw)
                ));
                continue;
            }
        };

        if applied != case.expect_applied {
            if case.known_regression {
                // On the temporary allowlist (matrix.json `known_regressions`):
                // a tracked, non-blocking regression — report it but don't fail.
                eprintln!(
                    "  - {}: expected applied={}, got {} [KNOWN REGRESSION (allowlisted in \
                     matrix.json; non-blocking — fix the hook + remove from the list)]",
                    case.id, case.expect_applied, applied
                );
            } else {
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
                    case.id, case.expect_applied, applied, tag, indent(&res.raw)
                ));
            }
        }

        // check/remove round-trip — only asserted for npm-family cases that
        // ran setup (the surface setup configures today). For other
        // ecosystems setup writes nothing, so the round-trip is a no-op and
        // we leave it untagged, consistent with the BASELINE GAP convention.
        if case.run_setup && case.is_npm_family() && !case.known_regression {
            if let Some(msg) = round_trip_failure(case, &res) {
                failures.push(msg);
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{}: {} of {} setup-matrix case(s) did not meet the aspirational \
         expectation. BASELINE GAP entries are the experimental TODO list \
         (this suite is non-blocking in CI); REGRESSION / LEAK entries are \
         real problems:\n{}",
        label,
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

/// Validate the behavioral `(setup)·(install)` round-trip emitted by the driver.
/// Verifies — through real install cycles, not by reading package.json — that:
///
/// 1. `setup --check` fails before setup, passes after setup, fails after
///    `setup --remove` (and remove itself succeeds);
/// 2. the patch is NOT applied before setup and NOT applied after remove
///    (the after-setup application is covered separately by the main
///    `actual_applied == expect_applied` assertion).
///
/// Returns a failure message describing any violation, or `None` on success.
fn round_trip_failure(case: &Case, res: &RunResult) -> Option<String> {
    // The main loop already turns a missing result line into a hard failure
    // and `continue`s before reaching here, so this branch is defensive: never
    // silently treat an absent result as a passing round-trip.
    let parsed = match res.parsed.as_ref() {
        Some(p) => p,
        None => {
            return Some(format!(
                "  - {}: setup/install behavioral round-trip could not be evaluated \
                 — driver produced no parseable result JSON\n{}",
                case.id,
                indent(&res.raw)
            ))
        }
    };
    let int = |k: &str| parsed.get(k).and_then(|v| v.as_i64());
    let boolean = |k: &str| parsed.get(k).and_then(|v| v.as_bool());

    let mut problems = Vec::new();

    // This branch runs ONLY for npm-family cases that ran setup, i.e. exactly
    // the driver's full (install)·(setup)·(install)·(remove)·(install) path,
    // which records every field below as a real value (never null). So every
    // probe must be PRESENT with the right value; a missing/null field means
    // the stage never ran and must be flagged, not tolerated.

    // (2) patch-application bookends must be present AND false: the patch must
    // NOT apply before any hook exists, and must NOT apply once it is removed.
    let applied_before = boolean("applied_before_setup");
    if applied_before != Some(false) {
        problems.push(format!(
            "applied_before_setup={applied_before:?} (want false: patch must NOT apply \
             before a hook is configured)"
        ));
    }
    let applied_after_remove = boolean("applied_after_remove");
    if applied_after_remove != Some(false) {
        problems.push(format!(
            "applied_after_remove={applied_after_remove:?} (want false: patch must NOT \
             apply once the hook is removed)"
        ));
    }

    // The native install of the patched package must itself have succeeded,
    // and the canonical after-setup verification must have found a real
    // on-disk copy to inspect (`primary_marker_present` is null only when NO
    // candidate file was found — which would make every "not applied" verdict
    // vacuous). Both guard against a green round-trip that inspected nothing.
    let install = int("install_exit");
    if install != Some(0) {
        problems.push(format!(
            "install_exit={install:?} (want 0: the native install must succeed for the \
             before/after probes to mean anything)"
        ));
    }
    if boolean("primary_marker_present").is_none() {
        problems.push(
            "primary_marker_present null/missing: no installed file was found to verify \
             (vacuous round-trip)"
                .to_string(),
        );
    }

    // (1) `setup --check` exit code must track the configured state:
    // non-zero before setup → 0 after setup → non-zero after remove. Each
    // must be present; a null exit means the check step never ran.
    let check_before = int("check_before_setup_exit");
    let check_setup = int("check_after_setup_exit");
    let remove = int("remove_exit");
    let check_remove = int("check_after_remove_exit");

    if !matches!(check_before, Some(n) if n != 0) {
        problems.push(format!(
            "check-before-setup exit={check_before:?} (want present & non-zero; not configured yet)"
        ));
    }
    if check_setup != Some(0) {
        problems.push(format!("check-after-setup exit={check_setup:?} (want 0; configured)"));
    }
    if remove != Some(0) {
        problems.push(format!("remove exit={remove:?} (want 0; remove must succeed)"));
    }
    if !matches!(check_remove, Some(n) if n != 0) {
        problems.push(format!(
            "check-after-remove exit={check_remove:?} (want present & non-zero; hook still present)"
        ));
    }

    if problems.is_empty() {
        return None;
    }
    Some(format!(
        "  - {}: setup/install behavioral round-trip failed [{}]\n{}",
        case.id,
        problems.join("; "),
        indent(&res.raw)
    ))
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("      {l}")).collect::<Vec<_>>().join("\n")
}
