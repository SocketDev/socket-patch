mod commands;

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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

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
