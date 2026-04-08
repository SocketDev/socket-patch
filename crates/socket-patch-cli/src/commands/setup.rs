use clap::Args;
use socket_patch_core::package_json::detect::PackageManager;
use socket_patch_core::package_json::find::{detect_package_manager, find_package_json_files};
use socket_patch_core::package_json::update::{update_package_json, UpdateStatus};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::output::stdin_is_tty;

#[derive(Args)]
pub struct SetupArgs {
    /// Working directory
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Preview changes without modifying files
    #[arg(short = 'd', long = "dry-run", default_value_t = false)]
    pub dry_run: bool,

    /// Skip confirmation prompt
    #[arg(short = 'y', long, default_value_t = false)]
    pub yes: bool,

    /// Output results as JSON
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub async fn run(args: SetupArgs) -> i32 {
    if !args.json {
        println!("Searching for package.json files...");
    }

    let package_json_files = find_package_json_files(&args.cwd).await;

    if package_json_files.is_empty() {
        if args.json {
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
    let pm = detect_package_manager(&args.cwd).await;

    if !args.json {
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

    if !args.json {
        println!("\nPackage.json files to be updated:\n");

        if !to_update.is_empty() {
            println!("Will update:");
            for result in &to_update {
                let rel_path = pathdiff(&result.path, &args.cwd);
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
                let rel_path = pathdiff(&result.path, &args.cwd);
                println!("  = {rel_path}");
            }
            println!();
        }

        if !errors.is_empty() {
            println!("Errors:");
            for result in &errors {
                let rel_path = pathdiff(&result.path, &args.cwd);
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
        if args.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "already_configured",
                "updated": 0,
                "alreadyConfigured": already_configured.len(),
                "errors": errors.len(),
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
        } else {
            println!("All package.json files are already configured with socket-patch!");
        }
        return 0;
    }

    // If not dry-run, ask for confirmation
    if !args.dry_run {
        if !args.yes && !args.json {
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

        if !args.json {
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

        if args.json {
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

        if args.json {
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
        0
    }
}

fn pathdiff(path: &str, base: &Path) -> String {
    let p = Path::new(path);
    p.strip_prefix(base)
        .map(|r| r.display().to_string())
        .unwrap_or_else(|_| path.to_string())
}
