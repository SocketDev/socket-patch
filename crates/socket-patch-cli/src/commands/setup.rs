use clap::Args;
use socket_patch_core::package_json::detect::{is_setup_configured_str, PackageManager};
use socket_patch_core::package_json::find::{
    detect_package_manager, find_package_json_files, PackageJsonLocation, WorkspaceType,
};
use socket_patch_core::package_json::update::{
    remove_package_json, update_package_json, RemoveStatus, UpdateStatus,
};
use socket_patch_core::utils::telemetry::track_patch_setup;
use std::io::{self, Write};
use std::path::Path;

use crate::args::GlobalArgs;
use crate::output::stdin_is_tty;

/// Stringify the detected manager for telemetry.
fn manager_name(pm: PackageManager) -> &'static str {
    match pm {
        PackageManager::Npm => "npm",
        PackageManager::Pnpm => "pnpm",
    }
}

#[derive(Args)]
pub struct SetupArgs {
    /// Verify the project is configured for socket-patch without changing
    /// anything. Exits non-zero if any package.json still needs setup.
    #[arg(
        long = "check",
        conflicts_with = "remove",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new(),
    )]
    pub check: bool,

    /// Revert the install hooks that `setup` added to package.json.
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
/// applying the pnpm "root-only" filtering. Returns `None` when no files are
/// found (the caller emits the `no_files` result).
async fn discover(args: &SetupArgs) -> Option<Vec<PackageJsonLocation>> {
    let find_result = find_package_json_files(&args.common.cwd).await;

    // For pnpm monorepos, only update root package.json. pnpm runs root
    // postinstall on `pnpm install`, so workspace-level postinstall scripts are
    // unnecessary and would fail under pnpm's strict module isolation.
    let files = match find_result.workspace_type {
        WorkspaceType::Pnpm => find_result
            .files
            .into_iter()
            .filter(|loc| loc.is_root)
            .collect(),
        _ => find_result.files,
    };

    if files.is_empty() {
        None
    } else {
        Some(files)
    }
}

/// Emit the shared "no package.json files found" result and exit code.
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
        println!("No package.json files found");
    }
    0
}

// ─────────────────────────────────────────────────────────────────────────
// check
// ─────────────────────────────────────────────────────────────────────────

/// Read-only verification that every discovered package.json is configured for
/// socket-patch. Never writes (so `--dry-run` is a harmless no-op here). Exits
/// 0 only when all files are configured and none failed to parse.
async fn run_check(args: &SetupArgs) -> i32 {
    if !args.common.json {
        println!("Searching for package.json files...");
    }

    let files = match discover(args).await {
        Some(f) => f,
        None => return report_no_files(args, "no_files"),
    };

    #[derive(Clone, Copy, PartialEq)]
    enum CheckState {
        Configured,
        NeedsConfiguration,
        Error,
    }

    let mut entries = Vec::new();
    for loc in &files {
        let (state, err) = match tokio::fs::read_to_string(&loc.path).await {
            Ok(content) => {
                // A malformed package.json cannot be verified; surface it as an
                // error rather than silently "needs configuration".
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
        entries.push((loc.path.display().to_string(), state, err));
    }

    let configured = entries.iter().filter(|(_, s, _)| *s == CheckState::Configured).count();
    let needs = entries.iter().filter(|(_, s, _)| *s == CheckState::NeedsConfiguration).count();
    let errs = entries.iter().filter(|(_, s, _)| *s == CheckState::Error).count();

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
                "files": entries.iter().map(|(path, state, err)| {
                    serde_json::json!({
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
        for (path, state, err) in &entries {
            let rel = pathdiff(path, &args.common.cwd);
            match state {
                CheckState::Configured => println!("  ✓ {rel} (configured)"),
                CheckState::NeedsConfiguration => println!("  ✗ {rel} (needs setup)"),
                CheckState::Error => println!(
                    "  ! {rel}: {}",
                    err.as_deref().unwrap_or("unknown error")
                ),
            }
        }
        println!();
        if all_ok {
            println!("All package.json files are configured with socket-patch.");
        } else {
            println!(
                "{needs} file(s) need configuration, {errs} error(s). Run `socket-patch setup` to fix."
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

/// Revert the install hooks `setup` added. Honors `--dry-run` (preview only),
/// `--yes` (skip confirmation), and `--json`.
async fn run_remove(args: &SetupArgs) -> i32 {
    if !args.common.json {
        println!("Searching for package.json files...");
    }

    let files = match discover(args).await {
        Some(f) => f,
        None => return report_no_files(args, "no_files"),
    };

    if !args.common.json {
        println!("Found {} package.json file(s)", files.len());
    }

    // Preview every file (dry_run=true never writes).
    let mut preview = Vec::new();
    for loc in &files {
        preview.push(remove_package_json(&loc.path, true).await);
    }

    let to_remove: Vec<_> = preview.iter().filter(|r| r.status == RemoveStatus::Removed).collect();
    let not_configured: Vec<_> =
        preview.iter().filter(|r| r.status == RemoveStatus::NotConfigured).collect();
    let errors: Vec<_> = preview.iter().filter(|r| r.status == RemoveStatus::Error).collect();

    // Display proposed edits (human mode).
    if !args.common.json {
        println!("\nProposed changes:\n");
        if !to_remove.is_empty() {
            println!("Will remove socket-patch from:");
            for r in &to_remove {
                let rel = pathdiff(&r.path, &args.common.cwd);
                println!("  - {rel}");
                println!("    postinstall:   \"{}\"", r.old_script);
                println!("    -> postinstall: {}", render_removed(&r.new_script));
                println!("    dependencies:  \"{}\"", r.old_dependencies_script);
                println!(
                    "    -> dependencies: {}",
                    render_removed(&r.new_dependencies_script)
                );
            }
            println!();
        }
        if !not_configured.is_empty() {
            println!("Nothing to remove (will skip):");
            for r in &not_configured {
                println!("  = {}", pathdiff(&r.path, &args.common.cwd));
            }
            println!();
        }
        if !errors.is_empty() {
            println!("Errors:");
            for r in &errors {
                println!(
                    "  ! {}: {}",
                    pathdiff(&r.path, &args.common.cwd),
                    r.error.as_deref().unwrap_or("unknown error")
                );
            }
            println!();
        }
    }

    let json_files = |results: &[&socket_patch_core::package_json::update::RemoveResult]| {
        results
            .iter()
            .map(|r| {
                serde_json::json!({
                    "path": r.path,
                    "status": match r.status {
                        RemoveStatus::Removed => "removed",
                        RemoveStatus::NotConfigured => "not_configured",
                        RemoveStatus::Error => "error",
                    },
                    "error": r.error,
                })
            })
            .collect::<Vec<_>>()
    };

    // Nothing to remove: either everything is already clean (exit 0) or some
    // file errored (exit 1). Mirrors the setup flow's honest error handling.
    if to_remove.is_empty() {
        let errs = errors.len();
        if args.common.json {
            let all: Vec<_> = preview.iter().collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": if errs > 0 { "error" } else { "not_configured" },
                    "removed": 0,
                    "notConfigured": not_configured.len(),
                    "errors": errs,
                    "files": json_files(&all),
                }))
                .unwrap()
            );
        } else if errs > 0 {
            println!("Nothing removed; {errs} file(s) could not be processed (see errors above).");
        } else {
            println!("No socket-patch install hooks found to remove.");
        }
        return if errs > 0 { 1 } else { 0 };
    }

    // Dry-run: preview already shown; report and exit without writing.
    if args.common.dry_run {
        if args.common.json {
            let all: Vec<_> = preview.iter().collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "dry_run",
                    "wouldRemove": to_remove.len(),
                    "notConfigured": not_configured.len(),
                    "errors": errors.len(),
                    "dryRun": true,
                    "files": json_files(&all),
                }))
                .unwrap()
            );
        } else {
            println!("\nSummary:");
            println!("  {} file(s) would have socket-patch removed", to_remove.len());
            println!("  {} file(s) have nothing to remove", not_configured.len());
            if !errors.is_empty() {
                println!("  {} error(s)", errors.len());
            }
        }
        return if errors.is_empty() { 0 } else { 1 };
    }

    // Confirm before mutating.
    if !args.common.yes && !args.common.json {
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

    if !args.common.json {
        println!("\nRemoving changes...");
    }
    let mut results = Vec::new();
    for loc in &files {
        results.push(remove_package_json(&loc.path, false).await);
    }

    let removed = results.iter().filter(|r| r.status == RemoveStatus::Removed).count();
    let not_cfg = results.iter().filter(|r| r.status == RemoveStatus::NotConfigured).count();
    let errs = results.iter().filter(|r| r.status == RemoveStatus::Error).count();

    if args.common.json {
        let all: Vec<_> = results.iter().collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": if errs > 0 { "partial_failure" } else { "success" },
                "removed": removed,
                "notConfigured": not_cfg,
                "errors": errs,
                "files": json_files(&all),
            }))
            .unwrap()
        );
    } else {
        println!("\nSummary:");
        println!("  {removed} file(s) had socket-patch removed");
        println!("  {not_cfg} file(s) had nothing to remove");
        if errs > 0 {
            println!("  {errs} error(s)");
        }
    }

    if errs > 0 {
        1
    } else {
        0
    }
}

// ─────────────────────────────────────────────────────────────────────────
// setup (unchanged behavior)
// ─────────────────────────────────────────────────────────────────────────

async fn run_setup(args: &SetupArgs) -> i32 {
    if !args.common.json {
        println!("Searching for package.json files...");
    }

    let package_json_files = match discover(args).await {
        Some(f) => f,
        None => {
            if args.common.json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": "no_files",
                    "updated": 0,
                    "alreadyConfigured": 0,
                    "errors": 0,
                    "files": [],
                })).unwrap());
            } else {
                println!("No package.json files found");
            }
            return 0;
        }
    };

    // Detect package manager from lockfiles in the project root.
    let pm = detect_package_manager(&args.common.cwd).await;

    // Setup telemetry: emit once we know a real setup is being attempted
    // (past the "no files found" early exit) and the package manager is
    // resolved. Carries the detected manager so we can see which install
    // hooks are exercised in the wild.
    track_patch_setup(
        manager_name(pm),
        args.common.api_token.as_deref(),
        args.common.org.as_deref(),
    )
    .await;

    if !args.common.json {
        println!("Found {} package.json file(s)", package_json_files.len());
        if pm == PackageManager::Pnpm {
            println!("Detected pnpm project (using pnpm dlx)");
        }
    }

    // Preview changes (always preview first)
    let mut preview_results = Vec::new();
    for loc in &package_json_files {
        let result = update_package_json(&loc.path, true, pm).await;
        preview_results.push(result);
    }

    // Display preview
    let to_update: Vec<_> = preview_results
        .iter()
        .filter(|r| r.status == UpdateStatus::Updated)
        .collect();
    let already_configured: Vec<_> = preview_results
        .iter()
        .filter(|r| r.status == UpdateStatus::AlreadyConfigured)
        .collect();
    let errors: Vec<_> = preview_results
        .iter()
        .filter(|r| r.status == UpdateStatus::Error)
        .collect();

    if !args.common.json {
        println!("\nPackage.json files to be updated:\n");

        if !to_update.is_empty() {
            println!("Will update:");
            for result in &to_update {
                let rel_path = pathdiff(&result.path, &args.common.cwd);
                println!("  + {rel_path}");
                if result.old_script.is_empty() {
                    println!("    postinstall:   (no script)");
                } else {
                    println!("    postinstall:   \"{}\"", result.old_script);
                }
                println!("    -> postinstall: \"{}\"", result.new_script);
                if result.old_dependencies_script.is_empty() {
                    println!("    dependencies:  (no script)");
                } else {
                    println!("    dependencies:  \"{}\"", result.old_dependencies_script);
                }
                println!(
                    "    -> dependencies: \"{}\"",
                    result.new_dependencies_script
                );
            }
            println!();
        }

        if !already_configured.is_empty() {
            println!("Already configured (will skip):");
            for result in &already_configured {
                let rel_path = pathdiff(&result.path, &args.common.cwd);
                println!("  = {rel_path}");
            }
            println!();
        }

        if !errors.is_empty() {
            println!("Errors:");
            for result in &errors {
                let rel_path = pathdiff(&result.path, &args.common.cwd);
                println!(
                    "  ! {}: {}",
                    rel_path,
                    result.error.as_deref().unwrap_or("unknown error")
                );
            }
            println!();
        }
    }

    if to_update.is_empty() {
        // Nothing to update — but that can mean two very different things:
        // every file is already configured (a clean exit 0), or some files
        // failed to process (e.g. malformed JSON). Errors must surface with
        // an honest status and a non-zero exit; otherwise a parse failure is
        // silently reported as "already configured" and CI reads it as success.
        let errs = errors.len();
        if args.common.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": if errs > 0 { "error" } else { "already_configured" },
                "updated": 0,
                "alreadyConfigured": already_configured.len(),
                "errors": errs,
                "files": preview_results.iter().map(|r| {
                    serde_json::json!({
                        "path": r.path,
                        "status": match r.status {
                            UpdateStatus::Updated => "updated",
                            UpdateStatus::AlreadyConfigured => "already_configured",
                            UpdateStatus::Error => "error",
                        },
                        "error": r.error,
                    })
                }).collect::<Vec<_>>(),
            })).unwrap());
        } else if errs > 0 {
            // Individual errors were already listed in the preview above.
            println!(
                "No files were updated; {errs} file(s) could not be processed (see errors above)."
            );
        } else {
            println!("All package.json files are already configured with socket-patch!");
        }
        return if errs > 0 { 1 } else { 0 };
    }

    // If not dry-run, ask for confirmation
    if !args.common.dry_run {
        if !args.common.yes && !args.common.json {
            if !stdin_is_tty() {
                // Non-interactive: default to yes with warning
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

        if !args.common.json {
            println!("\nApplying changes...");
        }
        let mut results = Vec::new();
        for loc in &package_json_files {
            let result = update_package_json(&loc.path, false, pm).await;
            results.push(result);
        }

        let updated = results.iter().filter(|r| r.status == UpdateStatus::Updated).count();
        let already = results.iter().filter(|r| r.status == UpdateStatus::AlreadyConfigured).count();
        let errs = results.iter().filter(|r| r.status == UpdateStatus::Error).count();

        if args.common.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": if errs > 0 { "partial_failure" } else { "success" },
                "updated": updated,
                "alreadyConfigured": already,
                "errors": errs,
                "packageManager": match pm {
                    PackageManager::Npm => "npm",
                    PackageManager::Pnpm => "pnpm",
                },
                "files": results.iter().map(|r| {
                    serde_json::json!({
                        "path": r.path,
                        "status": match r.status {
                            UpdateStatus::Updated => "updated",
                            UpdateStatus::AlreadyConfigured => "already_configured",
                            UpdateStatus::Error => "error",
                        },
                        "error": r.error,
                    })
                }).collect::<Vec<_>>(),
            })).unwrap());
        } else {
            println!("\nSummary:");
            println!("  {updated} file(s) updated");
            println!("  {already} file(s) already configured");
            if errs > 0 {
                println!("  {errs} error(s)");
            }
        }

        if errs > 0 { 1 } else { 0 }
    } else {
        let updated = preview_results.iter().filter(|r| r.status == UpdateStatus::Updated).count();
        let already = preview_results.iter().filter(|r| r.status == UpdateStatus::AlreadyConfigured).count();
        let errs = preview_results.iter().filter(|r| r.status == UpdateStatus::Error).count();

        if args.common.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "dry_run",
                "wouldUpdate": updated,
                "alreadyConfigured": already,
                "errors": errs,
                "dryRun": true,
                "packageManager": match pm {
                    PackageManager::Npm => "npm",
                    PackageManager::Pnpm => "pnpm",
                },
                "files": preview_results.iter().map(|r| {
                    serde_json::json!({
                        "path": r.path,
                        "status": match r.status {
                            UpdateStatus::Updated => "updated",
                            UpdateStatus::AlreadyConfigured => "already_configured",
                            UpdateStatus::Error => "error",
                        },
                        "oldScript": r.old_script,
                        "newScript": r.new_script,
                        "oldDependenciesScript": r.old_dependencies_script,
                        "newDependenciesScript": r.new_dependencies_script,
                        "error": r.error,
                    })
                }).collect::<Vec<_>>(),
            })).unwrap());
        } else {
            println!("\nSummary:");
            println!("  {updated} file(s) would be updated");
            println!("  {already} file(s) already configured");
            if errs > 0 {
                println!("  {errs} error(s)");
            }
        }
        // Mirror the non-dry-run path: an unprocessable package.json is a
        // failure regardless of dry-run, so it must yield a non-zero exit.
        if errs > 0 { 1 } else { 0 }
    }
}

fn pathdiff(path: &str, base: &Path) -> String {
    let p = Path::new(path);
    p.strip_prefix(base)
        .map(|r| r.display().to_string())
        .unwrap_or_else(|_| path.to_string())
}
