use clap::Args;
use socket_patch_core::package_json::find::find_package_json_files;
use socket_patch_core::package_json::update::{update_package_json, UpdateStatus};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

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
}

pub async fn run(args: SetupArgs) -> i32 {
    println!("Searching for package.json files...");

    let package_json_files = find_package_json_files(&args.cwd).await;

    if package_json_files.is_empty() {
        println!("No package.json files found");
        return 0;
    }

    println!("Found {} package.json file(s)", package_json_files.len());

    // Preview changes (always preview first)
    let mut preview_results = Vec::new();
    for loc in &package_json_files {
        let result = update_package_json(&loc.path, true).await;
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

    println!("\nPackage.json files to be updated:\n");

    if !to_update.is_empty() {
        println!("Will update:");
        for result in &to_update {
            let rel_path = pathdiff(&result.path, &args.cwd);
            println!("  + {rel_path}");
            if result.old_script.is_empty() {
                println!("    Current:  (no postinstall script)");
            } else {
                println!("    Current:  \"{}\"", result.old_script);
            }
            println!("    New:      \"{}\"", result.new_script);
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

    if to_update.is_empty() {
        println!("All package.json files are already configured with socket-patch!");
        return 0;
    }

    // If not dry-run, ask for confirmation
    if !args.dry_run {
        if !args.yes {
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

        println!("\nApplying changes...");
        let mut results = Vec::new();
        for loc in &package_json_files {
            let result = update_package_json(&loc.path, false).await;
            results.push(result);
        }

        let updated = results.iter().filter(|r| r.status == UpdateStatus::Updated).count();
        let already = results.iter().filter(|r| r.status == UpdateStatus::AlreadyConfigured).count();
        let errs = results.iter().filter(|r| r.status == UpdateStatus::Error).count();

        println!("\nSummary:");
        println!("  {updated} file(s) updated");
        println!("  {already} file(s) already configured");
        if errs > 0 {
            println!("  {errs} error(s)");
        }

        if errs > 0 { 1 } else { 0 }
    } else {
        let updated = preview_results.iter().filter(|r| r.status == UpdateStatus::Updated).count();
        let already = preview_results.iter().filter(|r| r.status == UpdateStatus::AlreadyConfigured).count();
        let errs = preview_results.iter().filter(|r| r.status == UpdateStatus::Error).count();

        println!("\nSummary:");
        println!("  {updated} file(s) would be updated");
        println!("  {already} file(s) already configured");
        if errs > 0 {
            println!("  {errs} error(s)");
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
