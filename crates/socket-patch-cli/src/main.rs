mod commands;
mod ecosystem_dispatch;
mod output;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "socket-patch",
    about = "CLI tool for applying security patches to dependencies",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Apply security patches to dependencies
    Apply(commands::apply::ApplyArgs),

    /// Rollback patches to restore original files
    Rollback(commands::rollback::RollbackArgs),

    /// Get security patches from Socket API and apply them
    #[command(visible_alias = "download")]
    Get(commands::get::GetArgs),

    /// Scan installed packages for available security patches
    Scan(commands::scan::ScanArgs),

    /// List all patches in the local manifest
    List(commands::list::ListArgs),

    /// Remove a patch from the manifest by PURL or UUID (rolls back files first)
    Remove(commands::remove::RemoveArgs),

    /// Configure package.json postinstall scripts to apply patches
    Setup(commands::setup::SetupArgs),

    /// Download missing blobs and clean up unused blobs
    #[command(visible_alias = "gc")]
    Repair(commands::repair::RepairArgs),
}

/// Check whether `s` looks like a UUID (8-4-4-4-12 hex pattern).
fn looks_like_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(expected.iter())
        .all(|(p, &len)| p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()))
}

#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            // If parsing failed, check whether the user passed a bare UUID
            // (e.g. `socket-patch 80630680-...`) and retry as `get <UUID> ...`.
            let args: Vec<String> = std::env::args().collect();
            if args.len() >= 2 && looks_like_uuid(&args[1]) {
                let mut new_args = vec![args[0].clone(), "get".into()];
                new_args.extend_from_slice(&args[1..]);
                match Cli::try_parse_from(&new_args) {
                    Ok(cli) => cli,
                    Err(_) => err.exit(),
                }
            } else {
                err.exit()
            }
        }
    };

    let exit_code = match cli.command {
        Commands::Apply(args) => commands::apply::run(args).await,
        Commands::Rollback(args) => commands::rollback::run(args).await,
        Commands::Get(args) => commands::get::run(args).await,
        Commands::Scan(args) => commands::scan::run(args).await,
        Commands::List(args) => commands::list::run(args).await,
        Commands::Remove(args) => commands::remove::run(args).await,
        Commands::Setup(args) => commands::setup::run(args).await,
        Commands::Repair(args) => commands::repair::run(args).await,
    };

    std::process::exit(exit_code);
}
