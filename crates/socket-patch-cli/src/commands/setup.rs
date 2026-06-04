use clap::Args;
#[cfg(feature = "cargo")]
use socket_patch_core::cargo_setup::{
    add_guard_dep, discover_cargo_project, is_guard_dep_present, remove_guard_dep, CargoEditResult,
    CargoSetupStatus,
};
use socket_patch_core::crawlers::python_crawler::is_python_project;
use socket_patch_core::package_json::detect::{is_setup_configured_str, PackageManager};
use socket_patch_core::package_json::find::{
    detect_package_manager, find_package_json_files, PackageJsonLocation, WorkspaceType,
};
use socket_patch_core::package_json::update::{
    remove_package_json, update_package_json, RemoveResult, RemoveStatus, UpdateResult,
    UpdateStatus,
};
use socket_patch_core::pth_hook::{
    add_hook_dependency, deps_contain_hook, detect_python_pm, remove_hook_dependency, ManifestKind,
    PthEditResult, PthStatus, PythonPackageManager,
};
use socket_patch_core::utils::telemetry::track_patch_setup;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::args::GlobalArgs;
use crate::output::stdin_is_tty;

/// Stringify the detected npm-family manager for telemetry.
fn manager_name(pm: PackageManager) -> &'static str {
    match pm {
        PackageManager::Npm => "npm",
        PackageManager::Pnpm => "pnpm",
    }
}

/// Compose the `+`-joined telemetry manager tag across the ecosystems in scope
/// (e.g. `npm+pypi+cargo`), or `none`.
fn telemetry_manager_str(npm: bool, py: bool, cargo: bool, npm_pm: PackageManager) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if npm {
        parts.push(manager_name(npm_pm));
    }
    if py {
        parts.push("pypi");
    }
    if cargo {
        parts.push("cargo");
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join("+")
    }
}

#[derive(Args)]
pub struct SetupArgs {
    /// Verify the project is configured for socket-patch without changing
    /// anything. Exits non-zero if any manifest still needs setup.
    #[arg(
        long = "check",
        conflicts_with = "remove",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new(),
    )]
    pub check: bool,

    /// Revert the install hooks that `setup` added (npm `package.json` scripts
    /// and the Python `socket-patch-hook` dependency).
    #[arg(
        long = "remove",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new(),
    )]
    pub remove: bool,

    #[command(flatten)]
    pub common: GlobalArgs,
}

pub async fn run(args: SetupArgs) -> i32 {
    if args.check {
        run_check(&args).await
    } else if args.remove {
        run_remove(&args).await
    } else {
        run_setup(&args).await
    }
}

/// Discover the package.json files `setup`/`check`/`remove` should act on,
/// applying the pnpm "root-only" filtering. Returns an empty vec when none are
/// found (callers also consider Python before reporting `no_files`).
async fn discover(args: &SetupArgs) -> Vec<PackageJsonLocation> {
    let find_result = find_package_json_files(&args.common.cwd).await;

    // For pnpm monorepos, only update root package.json. pnpm runs root
    // postinstall on `pnpm install`, so workspace-level postinstall scripts are
    // unnecessary and would fail under pnpm's strict module isolation.
    match find_result.workspace_type {
        WorkspaceType::Pnpm => find_result
            .files
            .into_iter()
            .filter(|loc| loc.is_root)
            .collect(),
        _ => find_result.files,
    }
}

/// Emit the shared "nothing found" result and exit code.
fn report_no_files(args: &SetupArgs, status: &str) -> i32 {
    if args.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": status,
                "files": [],
            }))
            .unwrap()
        );
    } else {
        println!("No package.json or Python project found");
    }
    0
}

fn pathdiff(path: &str, base: &Path) -> String {
    let p = Path::new(path);
    p.strip_prefix(base)
        .map(|r| r.display().to_string())
        .unwrap_or_else(|_| path.to_string())
}

// ─────────────────────────────────────────────────────────────────────────
// Python (.pth hook) helpers
// ─────────────────────────────────────────────────────────────────────────

/// A Python manifest `setup` will edit, plus the resolved package manager.
struct PythonPlan {
    pm: PythonPackageManager,
    manifests: Vec<(PathBuf, ManifestKind)>,
}

/// Decide which Python manifest(s) to edit for the detected package manager.
///
/// pyproject-based managers (uv/poetry/pdm/hatch) edit `pyproject.toml`; pip
/// prefers an existing `requirements.txt`, then a PEP 621 `pyproject.toml`, and
/// otherwise creates `requirements.txt`.
async fn choose_python_manifests(
    cwd: &Path,
    pm: PythonPackageManager,
) -> Vec<(PathBuf, ManifestKind)> {
    let pyproject = cwd.join("pyproject.toml");
    let requirements = cwd.join("requirements.txt");
    let pyproject_exists = tokio::fs::metadata(&pyproject).await.is_ok();
    let requirements_exists = tokio::fs::metadata(&requirements).await.is_ok();

    match pm {
        PythonPackageManager::Uv
        | PythonPackageManager::Poetry
        | PythonPackageManager::Pdm
        | PythonPackageManager::Hatch => {
            if pyproject_exists {
                vec![(pyproject, ManifestKind::Pyproject)]
            } else {
                vec![]
            }
        }
        PythonPackageManager::Pip => {
            if requirements_exists {
                vec![(requirements, ManifestKind::Requirements)]
            } else if pyproject_exists {
                vec![(pyproject, ManifestKind::Pyproject)]
            } else {
                // Nothing to edit yet: create requirements.txt so a CI
                // `pip install -r requirements.txt` installs the hook.
                vec![(requirements, ManifestKind::Requirements)]
            }
        }
    }
}

async fn plan_python(common: &GlobalArgs) -> Option<PythonPlan> {
    if !is_python_project(&common.cwd).await {
        return None;
    }
    let pm = detect_python_pm(&common.cwd).await;
    let manifests = choose_python_manifests(&common.cwd, pm).await;
    if manifests.is_empty() {
        return None;
    }
    Some(PythonPlan { pm, manifests })
}

/// Run the hook-dependency edits for a plan (add or remove) at the given
/// dry-run setting. Returns per-manifest results.
async fn edit_python_manifests(
    plan: &PythonPlan,
    remove: bool,
    dry_run: bool,
) -> Vec<PthEditResult> {
    let mut out = Vec::new();
    for (path, kind) in &plan.manifests {
        let res = if remove {
            remove_hook_dependency(path, *kind, dry_run).await
        } else {
            add_hook_dependency(path, *kind, dry_run).await
        };
        out.push(res);
    }
    out
}

/// After a real (non-dry-run) edit that changed a manifest, refresh the
/// lockfile. Returns any warnings to surface. (There is no separate marker /
/// audit file: the committed dependency line is the source of truth.)
async fn finalize_python(plan: &PythonPlan, edits: &[PthEditResult], cwd: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    let any_changed = edits.iter().any(|e| e.status == PthStatus::Updated);
    if !any_changed {
        return warnings;
    }
    // Lockfile refresh (broad auto-edit): only when the manager uses a lockfile
    // that exists. Best-effort — never fatal.
    if let Some((program, args)) = plan.pm.lock_command() {
        let lockfile = match plan.pm {
            PythonPackageManager::Uv => Some("uv.lock"),
            PythonPackageManager::Poetry => Some("poetry.lock"),
            PythonPackageManager::Pdm => Some("pdm.lock"),
            _ => None,
        };
        let lock_present = match lockfile {
            Some(name) => tokio::fs::metadata(cwd.join(name)).await.is_ok(),
            None => false,
        };
        if lock_present {
            match tokio::process::Command::new(program)
                .args(args)
                .current_dir(cwd)
                .output()
                .await
            {
                Ok(o) if o.status.success() => {}
                Ok(o) => warnings.push(format!(
                    "`{program} {}` failed ({}); update the lockfile manually",
                    args.join(" "),
                    o.status
                )),
                Err(e) => warnings.push(format!(
                    "could not run `{program} {}`: {e}; update the lockfile manually",
                    args.join(" ")
                )),
            }
        }
    }
    warnings
}

fn pth_status_str(s: &PthStatus) -> &'static str {
    match s {
        PthStatus::Updated => "updated",
        PthStatus::AlreadyConfigured => "already_configured",
        PthStatus::Error => "error",
    }
}

fn update_status_str(s: &UpdateStatus) -> &'static str {
    match s {
        UpdateStatus::Updated => "updated",
        UpdateStatus::AlreadyConfigured => "already_configured",
        UpdateStatus::Error => "error",
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Cargo (project-local [patch]-redirect guard) helpers
// ─────────────────────────────────────────────────────────────────────────

/// Feature-agnostic summary of the cargo branch's contribution to a
/// setup/remove run. Built by [`build_cargo_outcome`] (a no-op `Default` when
/// the `cargo` feature is off), so the shared reporting code never has to name
/// the cargo-only types.
#[derive(Default)]
struct CargoOutcome {
    /// A cargo project was discovered (gates the `no_files` decision).
    present: bool,
    /// Items changed (guard dep added/removed + `[env]` written/removed).
    changed: usize,
    already: usize,
    errors: usize,
    /// Envelope `files[]` entries (kind = `cargo` / `cargo_env`).
    json_files: Vec<serde_json::Value>,
    /// Human-readable preview lines (already formatted).
    preview: Vec<String>,
}

/// Build the cargo outcome for a setup (`remove=false`) or remove
/// (`remove=true`) run at the given `dry_run` setting.
#[cfg(feature = "cargo")]
async fn build_cargo_outcome(common: &GlobalArgs, remove: bool, dry_run: bool) -> CargoOutcome {
    use socket_patch_core::patch::cargo_config;

    let project = match discover_cargo_project(&common.cwd).await {
        Some(p) => p,
        None => return CargoOutcome::default(),
    };

    let mut out = CargoOutcome {
        present: true,
        ..Default::default()
    };

    // Per-member guard dependency edits.
    let version = guard_version();
    let mut results: Vec<(String, CargoEditResult)> = Vec::new();
    for member in &project.members {
        let res = if remove {
            remove_guard_dep(member, dry_run).await
        } else {
            add_guard_dep(member, &version, dry_run).await
        };
        results.push(("cargo".to_string(), res));
    }

    // The shared `[env] SOCKET_PATCH_ROOT` at the workspace root.
    let config_path = project.root.join(".cargo/config.toml");
    let env_change = if remove {
        cargo_config::drop_env_root(&project.root, dry_run).await
    } else {
        cargo_config::ensure_env_root(&project.root, dry_run).await
    };
    results.push(("cargo_env".to_string(), env_result(&config_path, env_change)));

    // Aggregate counts + render envelope entries / preview lines.
    let mut added_paths: Vec<String> = Vec::new();
    for (kind, r) in &results {
        match r.status {
            CargoSetupStatus::Updated => {
                out.changed += 1;
                added_paths.push(r.path.clone());
            }
            CargoSetupStatus::AlreadyConfigured => out.already += 1,
            CargoSetupStatus::Error => out.errors += 1,
        }
        out.json_files.push(serde_json::json!({
            "kind": kind,
            "path": r.path,
            "status": cargo_status_str(&r.status, remove),
            "error": r.error,
        }));
    }

    if !added_paths.is_empty() {
        let header = if remove {
            "Cargo: remove socket-patch-guard + [env] SOCKET_PATCH_ROOT from:"
        } else {
            "Cargo: add socket-patch-guard + [env] SOCKET_PATCH_ROOT to:"
        };
        out.preview.push(header.to_string());
        for p in &added_paths {
            out.preview.push(format!("  + {}", pathdiff(p, &common.cwd)));
        }
    }

    out
}

#[cfg(not(feature = "cargo"))]
async fn build_cargo_outcome(_common: &GlobalArgs, _remove: bool, _dry_run: bool) -> CargoOutcome {
    CargoOutcome::default()
}

/// The guard version string `setup` writes — major.minor of this CLI, so the
/// committed dep tracks the installed `socket-patch`.
#[cfg(feature = "cargo")]
fn guard_version() -> String {
    let v = env!("CARGO_PKG_VERSION");
    let mut parts = v.split('.');
    match (parts.next(), parts.next()) {
        (Some(major), Some(minor)) => format!("{major}.{minor}"),
        _ => v.to_string(),
    }
}

#[cfg(feature = "cargo")]
fn cargo_status_str(s: &CargoSetupStatus, for_remove: bool) -> &'static str {
    match (s, for_remove) {
        (CargoSetupStatus::Updated, false) => "updated",
        (CargoSetupStatus::Updated, true) => "removed",
        (CargoSetupStatus::AlreadyConfigured, false) => "already_configured",
        (CargoSetupStatus::AlreadyConfigured, true) => "not_configured",
        (CargoSetupStatus::Error, _) => "error",
    }
}

#[cfg(feature = "cargo")]
fn env_result(config_path: &Path, change: Result<bool, String>) -> CargoEditResult {
    match change {
        Ok(true) => CargoEditResult {
            path: config_path.display().to_string(),
            status: CargoSetupStatus::Updated,
            error: None,
        },
        Ok(false) => CargoEditResult {
            path: config_path.display().to_string(),
            status: CargoSetupStatus::AlreadyConfigured,
            error: None,
        },
        Err(e) => CargoEditResult {
            path: config_path.display().to_string(),
            status: CargoSetupStatus::Error,
            error: Some(e),
        },
    }
}

/// Append cargo check entries (one per member + one for `[env]`) to the shared
/// `run_check` entries list. Returns whether a cargo project was found.
#[cfg(feature = "cargo")]
async fn append_cargo_check_entries(
    common: &GlobalArgs,
    entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) -> bool {
    use socket_patch_core::patch::cargo_config;

    let project = match discover_cargo_project(&common.cwd).await {
        Some(p) => p,
        None => return false,
    };
    for member in &project.members {
        let (state, err) = match tokio::fs::read_to_string(member).await {
            Ok(content) => {
                if is_guard_dep_present(&content) {
                    (CheckState::Configured, None)
                } else {
                    (CheckState::NeedsConfiguration, None)
                }
            }
            Err(e) => (CheckState::Error, Some(e.to_string())),
        };
        entries.push(("cargo", member.display().to_string(), state, err));
    }
    let env_ok = cargo_config::env_root_present(&project.root).await;
    entries.push((
        "cargo_env",
        project.root.join(".cargo/config.toml").display().to_string(),
        if env_ok {
            CheckState::Configured
        } else {
            CheckState::NeedsConfiguration
        },
        None,
    ));
    true
}

#[cfg(not(feature = "cargo"))]
async fn append_cargo_check_entries(
    _common: &GlobalArgs,
    _entries: &mut Vec<(&'static str, String, CheckState, Option<String>)>,
) -> bool {
    false
}

// ─────────────────────────────────────────────────────────────────────────
// check
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum CheckState {
    Configured,
    NeedsConfiguration,
    Error,
}

/// Read-only verification that every discovered manifest (npm package.json and
/// the Python dependency manifest) is configured for socket-patch. Never writes
/// (so `--dry-run` is a harmless no-op here). Exits 0 only when all are
/// configured and none failed to parse.
async fn run_check(args: &SetupArgs) -> i32 {
    if !args.common.json {
        println!("Searching for package.json / Python / Cargo manifests...");
    }

    let npm_files = discover(args).await;
    let py_plan = plan_python(&args.common).await;

    // (kind, path, state, error)
    let mut entries: Vec<(&'static str, String, CheckState, Option<String>)> = Vec::new();

    for loc in &npm_files {
        let (state, err) = match tokio::fs::read_to_string(&loc.path).await {
            Ok(content) => {
                if serde_json::from_str::<serde_json::Value>(&content).is_err() {
                    (CheckState::Error, Some("Invalid package.json".to_string()))
                } else if is_setup_configured_str(&content).needs_update {
                    (CheckState::NeedsConfiguration, None)
                } else {
                    (CheckState::Configured, None)
                }
            }
            Err(e) => (CheckState::Error, Some(e.to_string())),
        };
        entries.push(("package_json", loc.path.display().to_string(), state, err));
    }

    if let Some(plan) = &py_plan {
        for (path, kind) in &plan.manifests {
            let (state, err) = match tokio::fs::read_to_string(path).await {
                Ok(content) => {
                    if deps_contain_hook(&content) {
                        (CheckState::Configured, None)
                    } else {
                        (CheckState::NeedsConfiguration, None)
                    }
                }
                // A not-yet-created requirements.txt simply needs setup; a
                // missing pyproject we'd have to edit is an error.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => match kind {
                    ManifestKind::Requirements => (CheckState::NeedsConfiguration, None),
                    ManifestKind::Pyproject => (CheckState::Error, Some(e.to_string())),
                },
                Err(e) => (CheckState::Error, Some(e.to_string())),
            };
            entries.push(("pth", path.display().to_string(), state, err));
        }
    }

    append_cargo_check_entries(&args.common, &mut entries).await;

    if entries.is_empty() {
        return report_no_files(args, "no_files");
    }

    let configured = entries.iter().filter(|(_, _, s, _)| *s == CheckState::Configured).count();
    let needs = entries.iter().filter(|(_, _, s, _)| *s == CheckState::NeedsConfiguration).count();
    let errs = entries.iter().filter(|(_, _, s, _)| *s == CheckState::Error).count();

    let all_ok = needs == 0 && errs == 0;
    let status = if errs > 0 {
        "error"
    } else if all_ok {
        "configured"
    } else {
        "needs_configuration"
    };

    if args.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": status,
                "configured": configured,
                "needsConfiguration": needs,
                "errors": errs,
                "files": entries.iter().map(|(kind, path, state, err)| {
                    serde_json::json!({
                        "kind": kind,
                        "path": path,
                        "status": match state {
                            CheckState::Configured => "configured",
                            CheckState::NeedsConfiguration => "needs_configuration",
                            CheckState::Error => "error",
                        },
                        "error": err,
                    })
                }).collect::<Vec<_>>(),
            }))
            .unwrap()
        );
    } else {
        println!("\nConfiguration status:\n");
        for (_, path, state, err) in &entries {
            let rel = pathdiff(path, &args.common.cwd);
            match state {
                CheckState::Configured => println!("  ✓ {rel} (configured)"),
                CheckState::NeedsConfiguration => println!("  ✗ {rel} (needs setup)"),
                CheckState::Error => {
                    println!("  ! {rel}: {}", err.as_deref().unwrap_or("unknown error"))
                }
            }
        }
        println!();
        if all_ok {
            println!("All manifests are configured with socket-patch.");
        } else {
            println!(
                "{needs} manifest(s) need configuration, {errs} error(s). Run `socket-patch setup` to fix."
            );
        }
    }

    if all_ok {
        0
    } else {
        1
    }
}

// ─────────────────────────────────────────────────────────────────────────
// remove
// ─────────────────────────────────────────────────────────────────────────

/// Render a removed script value: `None` means the key is being deleted.
fn render_removed(new: &Option<String>) -> String {
    match new {
        Some(s) if !s.is_empty() => format!("\"{s}\""),
        _ => "(removed)".to_string(),
    }
}

/// Revert the install hooks `setup` added (npm package.json scripts + the
/// Python `socket-patch-hook` dependency). Honors `--dry-run`, `--yes`, `--json`.
async fn run_remove(args: &SetupArgs) -> i32 {
    let common = &args.common;
    if !common.json {
        println!("Searching for package.json / Python / Cargo manifests...");
    }

    let npm_files = discover(args).await;
    let py_plan = plan_python(common).await;
    let cargo_preview = build_cargo_outcome(common, true, true).await;
    if npm_files.is_empty() && py_plan.is_none() && !cargo_preview.present {
        return report_no_files(args, "no_files");
    }

    // Preview (dry_run=true never writes).
    let mut npm_preview = Vec::new();
    for loc in &npm_files {
        npm_preview.push(remove_package_json(&loc.path, true).await);
    }
    let py_preview = match &py_plan {
        Some(p) => edit_python_manifests(p, true, true).await,
        None => Vec::new(),
    };

    if !common.json {
        print_remove_preview(&npm_preview, &py_preview, &cargo_preview, common);
    }

    let n_remove = npm_preview.iter().filter(|r| r.status == RemoveStatus::Removed).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Updated).count()
        + cargo_preview.changed;
    let preview_errs = npm_preview.iter().filter(|r| r.status == RemoveStatus::Error).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo_preview.errors;

    // Nothing to remove: clean (exit 0) or some file errored (exit 1).
    if n_remove == 0 {
        if common.json {
            print_remove_envelope(
                if preview_errs > 0 { "error" } else { "not_configured" },
                &npm_preview,
                &py_preview,
                &cargo_preview,
                &[],
            );
        } else if preview_errs > 0 {
            println!("Nothing removed; {preview_errs} item(s) could not be processed (see errors above).");
        } else {
            println!("No socket-patch install hooks found to remove.");
        }
        return if preview_errs > 0 { 1 } else { 0 };
    }

    // Dry-run: preview already shown; report and exit without writing.
    if common.dry_run {
        if common.json {
            print_remove_envelope("dry_run", &npm_preview, &py_preview, &cargo_preview, &[]);
        } else {
            println!("\nSummary:");
            println!("  {n_remove} item(s) would have socket-patch removed");
        }
        return if preview_errs > 0 { 1 } else { 0 };
    }

    // Confirm before mutating.
    if !common.yes && !common.json {
        if !stdin_is_tty() {
            eprintln!("Non-interactive mode detected, proceeding automatically.");
        } else {
            print!("Remove these install hooks? (y/N): ");
            io::stdout().flush().unwrap();
            let mut answer = String::new();
            io::stdin().read_line(&mut answer).unwrap();
            let answer = answer.trim().to_lowercase();
            if answer != "y" && answer != "yes" {
                println!("Aborted");
                return 0;
            }
        }
    }

    if !common.json {
        println!("\nRemoving changes...");
    }
    let mut npm_results = Vec::new();
    for loc in &npm_files {
        npm_results.push(remove_package_json(&loc.path, false).await);
    }
    let mut py_results = Vec::new();
    let mut warnings = Vec::new();
    if let Some(plan) = &py_plan {
        py_results = edit_python_manifests(plan, true, false).await;
        warnings = finalize_python(plan, &py_results, &common.cwd).await;
    }
    // Real cargo removal (guard dep + [env] root).
    let cargo_results = build_cargo_outcome(common, true, false).await;

    let errs = npm_results.iter().filter(|r| r.status == RemoveStatus::Error).count()
        + py_results.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo_results.errors;

    if common.json {
        print_remove_envelope(
            if errs > 0 { "partial_failure" } else { "success" },
            &npm_results,
            &py_results,
            &cargo_results,
            &warnings,
        );
    } else {
        let removed = npm_results.iter().filter(|r| r.status == RemoveStatus::Removed).count()
            + py_results.iter().filter(|r| r.status == PthStatus::Updated).count()
            + cargo_results.changed;
        println!("\nSummary:");
        println!("  {removed} item(s) had socket-patch removed");
        if errs > 0 {
            println!("  {errs} error(s)");
        }
        for w in &warnings {
            println!("  warning: {w}");
        }
        if py_plan.is_some() {
            println!("\nAlso run `pip uninstall socket-patch-hook` to remove the installed .pth.");
        }
        if cargo_results.present {
            println!(
                "\nNote: existing patched-crate copies under .socket/cargo-patches/ and any \
                 managed [patch.crates-io] entries are removed on `socket-patch rollback`."
            );
        }
    }

    if errs > 0 {
        1
    } else {
        0
    }
}

fn print_remove_preview(
    npm: &[RemoveResult],
    py: &[PthEditResult],
    cargo: &CargoOutcome,
    common: &GlobalArgs,
) {
    let to_remove: Vec<_> = npm.iter().filter(|r| r.status == RemoveStatus::Removed).collect();
    let py_remove: Vec<_> = py.iter().filter(|r| r.status == PthStatus::Updated).collect();
    println!("\nProposed changes:\n");
    if !to_remove.is_empty() {
        println!("Will remove socket-patch from:");
        for r in &to_remove {
            let rel = pathdiff(&r.path, &common.cwd);
            println!("  - {rel}");
            println!("    postinstall:   \"{}\"", r.old_script);
            println!("    -> postinstall: {}", render_removed(&r.new_script));
            println!("    dependencies:  \"{}\"", r.old_dependencies_script);
            println!("    -> dependencies: {}", render_removed(&r.new_dependencies_script));
        }
        println!();
    }
    if !py_remove.is_empty() {
        println!("Will remove the socket-patch-hook dependency from:");
        for r in &py_remove {
            println!("  - {}", pathdiff(&r.path, &common.cwd));
        }
        println!();
    }
    if !cargo.preview.is_empty() {
        for line in &cargo.preview {
            println!("{line}");
        }
        println!();
    }
}

fn print_remove_envelope(
    status: &str,
    npm: &[RemoveResult],
    py: &[PthEditResult],
    cargo: &CargoOutcome,
    warnings: &[String],
) {
    let removed = npm.iter().filter(|r| r.status == RemoveStatus::Removed).count()
        + py.iter().filter(|r| r.status == PthStatus::Updated).count()
        + cargo.changed;
    let not_cfg = npm.iter().filter(|r| r.status == RemoveStatus::NotConfigured).count()
        + py.iter().filter(|r| r.status == PthStatus::AlreadyConfigured).count()
        + cargo.already;
    let errors = npm.iter().filter(|r| r.status == RemoveStatus::Error).count()
        + py.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo.errors;

    let mut files: Vec<serde_json::Value> = npm
        .iter()
        .map(|r| {
            serde_json::json!({
                "kind": "package_json",
                "path": r.path,
                "status": match r.status {
                    RemoveStatus::Removed => "removed",
                    RemoveStatus::NotConfigured => "not_configured",
                    RemoveStatus::Error => "error",
                },
                "error": r.error,
            })
        })
        .collect();
    files.extend(py.iter().map(|r| {
        serde_json::json!({
            "kind": "pth",
            "path": r.path,
            "status": match r.status {
                PthStatus::Updated => "removed",
                PthStatus::AlreadyConfigured => "not_configured",
                PthStatus::Error => "error",
            },
            "error": r.error,
        })
    }));
    // cargo.json_files already use the remove vocabulary
    // (removed/not_configured/error), built by `build_cargo_outcome`.
    files.extend(cargo.json_files.iter().cloned());

    let mut obj = serde_json::json!({
        "status": status,
        "removed": removed,
        "notConfigured": not_cfg,
        "errors": errors,
        "files": files,
    });
    if status == "dry_run" {
        obj["dryRun"] = serde_json::json!(true);
        obj["wouldRemove"] = serde_json::json!(removed);
    }
    if !warnings.is_empty() {
        obj["warnings"] = serde_json::json!(warnings);
    }
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}

// ─────────────────────────────────────────────────────────────────────────
// setup (npm package.json + Python .pth hook, combined)
// ─────────────────────────────────────────────────────────────────────────

async fn run_setup(args: &SetupArgs) -> i32 {
    let common = &args.common;
    if !common.json {
        println!("Configuring socket-patch install hooks...");
    }

    let npm_files = discover(args).await;
    let py_plan = plan_python(common).await;
    // Cargo preview (dry-run); `.present` also tells us a cargo project exists.
    let cargo_preview = build_cargo_outcome(common, false, true).await;

    if npm_files.is_empty() && py_plan.is_none() && !cargo_preview.present {
        if common.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "no_files",
                    "updated": 0,
                    "alreadyConfigured": 0,
                    "errors": 0,
                    "files": [],
                }))
                .unwrap()
            );
        } else {
            println!("No package.json, Python, or Cargo project found");
        }
        return 0;
    }

    let npm_pm = detect_package_manager(&common.cwd).await;

    let telemetry_manager = telemetry_manager_str(
        !npm_files.is_empty(),
        py_plan.is_some(),
        cargo_preview.present,
        npm_pm,
    );
    track_patch_setup(
        &telemetry_manager,
        common.api_token.as_deref(),
        common.org.as_deref(),
    )
    .await;

    // Preview (always dry-run first).
    let mut npm_preview = Vec::new();
    for loc in &npm_files {
        npm_preview.push(update_package_json(&loc.path, true, npm_pm).await);
    }
    let py_preview = match &py_plan {
        Some(plan) => edit_python_manifests(plan, false, true).await,
        None => Vec::new(),
    };

    if !common.json {
        print_setup_preview(&npm_preview, &py_preview, &cargo_preview, common);
    }

    let n_changes = npm_preview.iter().filter(|r| r.status == UpdateStatus::Updated).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Updated).count()
        + cargo_preview.changed;
    let preview_errors = npm_preview.iter().filter(|r| r.status == UpdateStatus::Error).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo_preview.errors;

    if n_changes == 0 {
        if common.json {
            print_setup_envelope(
                if preview_errors > 0 { "error" } else { "already_configured" },
                &npm_preview,
                &py_preview,
                &cargo_preview,
                npm_pm,
                py_plan.as_ref(),
                &[],
            );
        } else if preview_errors > 0 {
            println!("No hooks were changed; {preview_errors} item(s) could not be processed (see errors above).");
        } else {
            println!("All install hooks are already configured with socket-patch!");
        }
        return if preview_errors > 0 { 1 } else { 0 };
    }

    if common.dry_run {
        if common.json {
            print_setup_envelope(
                "dry_run",
                &npm_preview,
                &py_preview,
                &cargo_preview,
                npm_pm,
                py_plan.as_ref(),
                &[],
            );
        } else {
            println!("\nSummary (dry run):");
            println!("  {n_changes} item(s) would be updated");
        }
        return if preview_errors > 0 { 1 } else { 0 };
    }

    if !common.yes && !common.json {
        if !stdin_is_tty() {
            eprintln!("Non-interactive mode detected, proceeding automatically.");
        } else {
            print!("Proceed with these changes? (y/N): ");
            io::stdout().flush().unwrap();
            let mut answer = String::new();
            io::stdin().read_line(&mut answer).unwrap();
            let answer = answer.trim().to_lowercase();
            if answer != "y" && answer != "yes" {
                println!("Aborted");
                return 0;
            }
        }
    }

    if !common.json {
        println!("\nApplying changes...");
    }

    let mut npm_results = Vec::new();
    for loc in &npm_files {
        npm_results.push(update_package_json(&loc.path, false, npm_pm).await);
    }
    let mut py_results = Vec::new();
    let mut warnings = Vec::new();
    if let Some(plan) = &py_plan {
        py_results = edit_python_manifests(plan, false, false).await;
        warnings = finalize_python(plan, &py_results, &common.cwd).await;
    }
    // Real cargo edit (guard dep + [env] root).
    let cargo_results = build_cargo_outcome(common, false, false).await;

    let errors = npm_results.iter().filter(|r| r.status == UpdateStatus::Error).count()
        + py_results.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo_results.errors;

    if common.json {
        print_setup_envelope(
            if errors > 0 { "partial_failure" } else { "success" },
            &npm_results,
            &py_results,
            &cargo_results,
            npm_pm,
            py_plan.as_ref(),
            &warnings,
        );
    } else {
        let updated = npm_results.iter().filter(|r| r.status == UpdateStatus::Updated).count()
            + py_results.iter().filter(|r| r.status == PthStatus::Updated).count()
            + cargo_results.changed;
        println!("\nSummary:");
        println!("  {updated} item(s) updated");
        if errors > 0 {
            println!("  {errors} error(s)");
        }
        for w in &warnings {
            println!("  warning: {w}");
        }
        if let Some(plan) = &py_plan {
            println!(
                "\nCommit the {} dependency change (and your .socket/ patches) so \
                 the hook re-applies in CI after install.",
                plan.pm.as_str()
            );
        }
        if cargo_results.present {
            println!(
                "\nCommit Cargo.toml (socket-patch-guard), .cargo/config.toml, and your \
                 .socket/ patches so the guard re-applies cargo patches in CI."
            );
        }
    }

    if errors > 0 {
        1
    } else {
        0
    }
}

fn print_setup_preview(
    npm: &[UpdateResult],
    py: &[PthEditResult],
    cargo: &CargoOutcome,
    common: &GlobalArgs,
) {
    let npm_changes: Vec<_> = npm.iter().filter(|r| r.status == UpdateStatus::Updated).collect();
    let py_changes: Vec<_> = py.iter().filter(|r| r.status == PthStatus::Updated).collect();

    if !npm_changes.is_empty() {
        println!("\npackage.json files to update:");
        for r in &npm_changes {
            println!("  + {}", pathdiff(&r.path, &common.cwd));
            println!("    -> postinstall: \"{}\"", r.new_script);
        }
    }
    if !py_changes.is_empty() {
        println!("\nPython manifests to update (socket-patch-hook):");
        for r in &py_changes {
            println!("  + {}", pathdiff(&r.path, &common.cwd));
        }
    }
    if !cargo.preview.is_empty() {
        println!();
        for line in &cargo.preview {
            println!("{line}");
        }
    }

    let npm_already = npm.iter().filter(|r| r.status == UpdateStatus::AlreadyConfigured).count();
    let py_already = py.iter().filter(|r| r.status == PthStatus::AlreadyConfigured).count();
    if npm_already + py_already + cargo.already > 0 {
        println!(
            "\nAlready configured (will skip): {}",
            npm_already + py_already + cargo.already
        );
    }

    let errs: Vec<&str> = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::Error)
        .filter_map(|r| r.error.as_deref())
        .chain(
            py.iter()
                .filter(|r| r.status == PthStatus::Error)
                .filter_map(|r| r.error.as_deref()),
        )
        .collect();
    if !errs.is_empty() {
        println!("\nErrors:");
        for e in errs {
            println!("  ! {e}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn print_setup_envelope(
    status: &str,
    npm: &[UpdateResult],
    py: &[PthEditResult],
    cargo: &CargoOutcome,
    npm_pm: PackageManager,
    py_plan: Option<&PythonPlan>,
    warnings: &[String],
) {
    let updated = npm.iter().filter(|r| r.status == UpdateStatus::Updated).count()
        + py.iter().filter(|r| r.status == PthStatus::Updated).count()
        + cargo.changed;
    let already = npm.iter().filter(|r| r.status == UpdateStatus::AlreadyConfigured).count()
        + py.iter().filter(|r| r.status == PthStatus::AlreadyConfigured).count()
        + cargo.already;
    let errors = npm.iter().filter(|r| r.status == UpdateStatus::Error).count()
        + py.iter().filter(|r| r.status == PthStatus::Error).count()
        + cargo.errors;

    let mut files: Vec<serde_json::Value> = npm
        .iter()
        .map(|r| {
            serde_json::json!({
                "kind": "package_json",
                "path": r.path,
                "status": update_status_str(&r.status),
                "error": r.error,
            })
        })
        .collect();
    files.extend(py.iter().map(|r| {
        serde_json::json!({
            "kind": "pth",
            "path": r.path,
            "status": pth_status_str(&r.status),
            "error": r.error,
        })
    }));
    files.extend(cargo.json_files.iter().cloned());

    let mut obj = serde_json::json!({
        "status": status,
        "updated": updated,
        "alreadyConfigured": already,
        "errors": errors,
        "packageManager": manager_name(npm_pm),
        "files": files,
    });
    if status == "dry_run" {
        obj["dryRun"] = serde_json::json!(true);
        obj["wouldUpdate"] = serde_json::json!(updated);
    }
    if let Some(plan) = py_plan {
        obj["pythonPackageManager"] = serde_json::json!(plan.pm.as_str());
    }
    if !warnings.is_empty() {
        obj["warnings"] = serde_json::json!(warnings);
    }
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}
