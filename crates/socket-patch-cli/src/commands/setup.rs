use clap::Args;
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
        println!("Searching for package.json / Python manifests...");
    }

    let npm_files = discover(args).await;
    let py_plan = plan_python(&args.common).await;
    if npm_files.is_empty() && py_plan.is_none() {
        return report_no_files(args, "no_files");
    }

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
        println!("Searching for package.json / Python manifests...");
    }

    let npm_files = discover(args).await;
    let py_plan = plan_python(common).await;
    if npm_files.is_empty() && py_plan.is_none() {
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
        print_remove_preview(&npm_preview, &py_preview, common);
    }

    let n_remove = npm_preview.iter().filter(|r| r.status == RemoveStatus::Removed).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Updated).count();
    let preview_errs = npm_preview.iter().filter(|r| r.status == RemoveStatus::Error).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Error).count();

    // Nothing to remove: clean (exit 0) or some file errored (exit 1).
    if n_remove == 0 {
        if common.json {
            print_remove_envelope(
                if preview_errs > 0 { "error" } else { "not_configured" },
                &npm_preview,
                &py_preview,
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
            print_remove_envelope("dry_run", &npm_preview, &py_preview, &[]);
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

    let errs = npm_results.iter().filter(|r| r.status == RemoveStatus::Error).count()
        + py_results.iter().filter(|r| r.status == PthStatus::Error).count();

    if common.json {
        print_remove_envelope(
            if errs > 0 { "partial_failure" } else { "success" },
            &npm_results,
            &py_results,
            &warnings,
        );
    } else {
        let removed = npm_results.iter().filter(|r| r.status == RemoveStatus::Removed).count()
            + py_results.iter().filter(|r| r.status == PthStatus::Updated).count();
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
    }

    if errs > 0 {
        1
    } else {
        0
    }
}

fn print_remove_preview(npm: &[RemoveResult], py: &[PthEditResult], common: &GlobalArgs) {
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
}

fn print_remove_envelope(
    status: &str,
    npm: &[RemoveResult],
    py: &[PthEditResult],
    warnings: &[String],
) {
    let removed = npm.iter().filter(|r| r.status == RemoveStatus::Removed).count()
        + py.iter().filter(|r| r.status == PthStatus::Updated).count();
    let not_cfg = npm.iter().filter(|r| r.status == RemoveStatus::NotConfigured).count()
        + py.iter().filter(|r| r.status == PthStatus::AlreadyConfigured).count();
    let errors = npm.iter().filter(|r| r.status == RemoveStatus::Error).count()
        + py.iter().filter(|r| r.status == PthStatus::Error).count();

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

    if npm_files.is_empty() && py_plan.is_none() {
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
            println!("No package.json or Python project found");
        }
        return 0;
    }

    let npm_pm = detect_package_manager(&common.cwd).await;

    let telemetry_manager = match (!npm_files.is_empty(), py_plan.is_some()) {
        (true, true) => format!("{}+pypi", manager_name(npm_pm)),
        (true, false) => manager_name(npm_pm).to_string(),
        (false, true) => "pypi".to_string(),
        (false, false) => "none".to_string(),
    };
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
        print_setup_preview(&npm_preview, &py_preview, common);
    }

    let n_changes = npm_preview.iter().filter(|r| r.status == UpdateStatus::Updated).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Updated).count();
    let preview_errors = npm_preview.iter().filter(|r| r.status == UpdateStatus::Error).count()
        + py_preview.iter().filter(|r| r.status == PthStatus::Error).count();

    if n_changes == 0 {
        if common.json {
            print_setup_envelope(
                if preview_errors > 0 { "error" } else { "already_configured" },
                &npm_preview,
                &py_preview,
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

    let errors = npm_results.iter().filter(|r| r.status == UpdateStatus::Error).count()
        + py_results.iter().filter(|r| r.status == PthStatus::Error).count();

    if common.json {
        print_setup_envelope(
            if errors > 0 { "partial_failure" } else { "success" },
            &npm_results,
            &py_results,
            npm_pm,
            py_plan.as_ref(),
            &warnings,
        );
    } else {
        let updated = npm_results.iter().filter(|r| r.status == UpdateStatus::Updated).count()
            + py_results.iter().filter(|r| r.status == PthStatus::Updated).count();
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
    }

    if errors > 0 {
        1
    } else {
        0
    }
}

fn print_setup_preview(npm: &[UpdateResult], py: &[PthEditResult], common: &GlobalArgs) {
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

    let npm_already = npm.iter().filter(|r| r.status == UpdateStatus::AlreadyConfigured).count();
    let py_already = py.iter().filter(|r| r.status == PthStatus::AlreadyConfigured).count();
    if npm_already + py_already > 0 {
        println!("\nAlready configured (will skip): {}", npm_already + py_already);
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
    npm_pm: PackageManager,
    py_plan: Option<&PythonPlan>,
    warnings: &[String],
) {
    let updated = npm.iter().filter(|r| r.status == UpdateStatus::Updated).count()
        + py.iter().filter(|r| r.status == PthStatus::Updated).count();
    let already = npm.iter().filter(|r| r.status == UpdateStatus::AlreadyConfigured).count()
        + py.iter().filter(|r| r.status == PthStatus::AlreadyConfigured).count();
    let errors = npm.iter().filter(|r| r.status == UpdateStatus::Error).count()
        + py.iter().filter(|r| r.status == PthStatus::Error).count();

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
