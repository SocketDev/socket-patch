use clap::Args;
use socket_patch_core::crawlers::python_crawler::is_python_project;
use socket_patch_core::package_json::detect::PackageManager;
use socket_patch_core::package_json::find::{
    detect_package_manager, find_package_json_files, WorkspaceType,
};
use socket_patch_core::package_json::update::{update_package_json, UpdateResult, UpdateStatus};
use socket_patch_core::pth_hook::{
    add_hook_dependency, detect_python_pm, remove_hook_dependency, ManifestKind, PthEditResult,
    PthStatus, PythonPackageManager,
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
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Remove the socket-patch install hook instead of adding it. For Python
    /// this drops the `socket-patch-hook` dependency from the manifest (then run
    /// `pip uninstall socket-patch-hook`).
    #[arg(long, env = "SOCKET_SETUP_REMOVE", default_value_t = false)]
    pub remove: bool,
}

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

fn rel(path: &str, base: &Path) -> String {
    Path::new(path)
        .strip_prefix(base)
        .map(|r| r.display().to_string())
        .unwrap_or_else(|_| path.to_string())
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

    // Lockfile refresh (broad auto-edit): only when we changed a manifest and
    // the manager uses a lockfile that exists. Best-effort — never fatal.
    if any_changed {
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
    }
    warnings
}

pub async fn run(args: SetupArgs) -> i32 {
    let common = &args.common;
    let remove = args.remove;

    if !common.json {
        if remove {
            println!("Removing socket-patch install hooks...");
        } else {
            println!("Configuring socket-patch install hooks...");
        }
    }

    // ── discover both ecosystems ────────────────────────────────────────
    let find_result = find_package_json_files(&common.cwd).await;
    // pnpm monorepos: only the root package.json (see the original rationale).
    let npm_files = match find_result.workspace_type {
        WorkspaceType::Pnpm => find_result
            .files
            .into_iter()
            .filter(|loc| loc.is_root)
            .collect::<Vec<_>>(),
        _ => find_result.files,
    };
    // `--remove` only reverses the Python hook today; npm postinstall removal
    // is left to the user, so we don't touch package.json on remove.
    let npm_files = if remove { Vec::new() } else { npm_files };
    let npm_pm = detect_package_manager(&common.cwd).await;

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
        } else if remove {
            println!("No socket-patch install hooks found to remove.");
        } else {
            println!("No package.json or Python project found");
        }
        return 0;
    }

    // Telemetry: which install-hook surfaces are being exercised.
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

    // ── preview (always dry-run first) ──────────────────────────────────
    let mut npm_preview = Vec::new();
    for loc in &npm_files {
        npm_preview.push(update_package_json(&loc.path, true, npm_pm).await);
    }
    let py_preview = match &py_plan {
        Some(plan) => edit_python_manifests(plan, remove, true).await,
        None => Vec::new(),
    };

    if !common.json {
        print_preview(&npm_preview, &py_preview, common, remove);
    }

    let n_changes = npm_preview
        .iter()
        .filter(|r| r.status == UpdateStatus::Updated)
        .count()
        + py_preview
            .iter()
            .filter(|r| r.status == PthStatus::Updated)
            .count();
    let preview_errors = npm_preview
        .iter()
        .filter(|r| r.status == UpdateStatus::Error)
        .count()
        + py_preview
            .iter()
            .filter(|r| r.status == PthStatus::Error)
            .count();

    // Nothing to change: report already-configured (or surface errors).
    if n_changes == 0 {
        if common.json {
            print_envelope(
                if preview_errors > 0 { "error" } else { "already_configured" },
                &npm_preview,
                &py_preview,
                npm_pm,
                py_plan.as_ref(),
                &[],
                common,
            );
        } else if preview_errors > 0 {
            println!("No hooks were changed; {preview_errors} item(s) could not be processed (see errors above).");
        } else if remove {
            println!("No socket-patch install hooks were configured.");
        } else {
            println!("All install hooks are already configured with socket-patch!");
        }
        return if preview_errors > 0 { 1 } else { 0 };
    }

    // Dry-run: report the preview and stop.
    if common.dry_run {
        if common.json {
            print_envelope(
                "dry_run",
                &npm_preview,
                &py_preview,
                npm_pm,
                py_plan.as_ref(),
                &[],
                common,
            );
        } else {
            println!("\nSummary (dry run):");
            println!("  {n_changes} item(s) would be {}", if remove { "removed" } else { "updated" });
        }
        return if preview_errors > 0 { 1 } else { 0 };
    }

    // Confirm once (interactive only).
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

    // ── apply for real ──────────────────────────────────────────────────
    let mut npm_results = Vec::new();
    for loc in &npm_files {
        npm_results.push(update_package_json(&loc.path, false, npm_pm).await);
    }
    let mut py_results = Vec::new();
    let mut warnings = Vec::new();
    if let Some(plan) = &py_plan {
        py_results = edit_python_manifests(plan, remove, false).await;
        warnings = finalize_python(plan, &py_results, &common.cwd).await;
    }

    let errors = npm_results
        .iter()
        .filter(|r| r.status == UpdateStatus::Error)
        .count()
        + py_results
            .iter()
            .filter(|r| r.status == PthStatus::Error)
            .count();

    if common.json {
        print_envelope(
            if errors > 0 { "partial_failure" } else { "success" },
            &npm_results,
            &py_results,
            npm_pm,
            py_plan.as_ref(),
            &warnings,
            common,
        );
    } else {
        let updated = npm_results
            .iter()
            .filter(|r| r.status == UpdateStatus::Updated)
            .count()
            + py_results
                .iter()
                .filter(|r| r.status == PthStatus::Updated)
                .count();
        println!("\nSummary:");
        println!("  {updated} item(s) {}", if remove { "removed" } else { "updated" });
        if errors > 0 {
            println!("  {errors} error(s)");
        }
        for w in &warnings {
            println!("  warning: {w}");
        }
        if let Some(plan) = &py_plan {
            if remove {
                println!(
                    "\nAlso run `pip uninstall socket-patch-hook` to remove the installed .pth."
                );
            } else {
                println!(
                    "\nCommit the {} dependency change (and your .socket/ patches) so \
                     the hook re-applies in CI after install.",
                    plan.pm.as_str()
                );
            }
        }
    }

    if errors > 0 {
        1
    } else {
        0
    }
}

fn print_preview(
    npm: &[UpdateResult],
    py: &[PthEditResult],
    common: &GlobalArgs,
    remove: bool,
) {
    let verb = if remove { "remove" } else { "update" };
    let npm_changes: Vec<_> = npm.iter().filter(|r| r.status == UpdateStatus::Updated).collect();
    let py_changes: Vec<_> = py.iter().filter(|r| r.status == PthStatus::Updated).collect();

    if !npm_changes.is_empty() {
        println!("\npackage.json files to {verb}:");
        for r in &npm_changes {
            println!("  + {}", rel(&r.path, &common.cwd));
            println!("    postinstall -> \"{}\"", r.new_script);
        }
    }
    if !py_changes.is_empty() {
        println!("\nPython manifests to {verb} (socket-patch[hook]):");
        for r in &py_changes {
            println!("  + {}", rel(&r.path, &common.cwd));
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
fn print_envelope(
    status: &str,
    npm: &[UpdateResult],
    py: &[PthEditResult],
    npm_pm: PackageManager,
    py_plan: Option<&PythonPlan>,
    warnings: &[String],
    _common: &GlobalArgs,
) {
    let updated = npm.iter().filter(|r| r.status == UpdateStatus::Updated).count()
        + py.iter().filter(|r| r.status == PthStatus::Updated).count();
    let already = npm
        .iter()
        .filter(|r| r.status == UpdateStatus::AlreadyConfigured)
        .count()
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
    // Preserve the dry-run envelope schema consumers rely on.
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
