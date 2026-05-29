use clap::Args;
use socket_patch_core::package_json::detect::PackageManager;
use socket_patch_core::package_json::find::{
    detect_package_manager, find_package_json_files, WorkspaceType,
};
use socket_patch_core::package_json::update::{update_package_json, UpdateStatus};
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
    #[command(flatten)]
    pub common: GlobalArgs,
}

pub async fn run(args: SetupArgs) -> i32 {
    if !args.common.json {
        println!("Searching for package.json files...");
    }

    let find_result = find_package_json_files(&args.common.cwd).await;

    // For pnpm monorepos, only update root package.json.
    // pnpm runs root postinstall on `pnpm install`, so workspace-level
    // postinstall scripts are unnecessary. Individual workspaces may not
    // have `@socketsecurity/socket-patch` as a dependency, causing
    // `npx @socketsecurity/socket-patch apply` to fail due to pnpm's
    // strict module isolation.
    let package_json_files = match find_result.workspace_type {
        WorkspaceType::Pnpm => find_result
            .files
            .into_iter()
            .filter(|loc| loc.is_root)
            .collect(),
        _ => find_result.files,
    };

    if package_json_files.is_empty() {
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
