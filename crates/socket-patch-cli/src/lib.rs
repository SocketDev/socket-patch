//! socket-patch CLI library crate.
//!
//! Exposes the clap parser types so integration tests can verify the public
//! CLI contract without invoking the binary. The `main.rs` binary entry point
//! is a thin wrapper that delegates to [`parse_with_uuid_fallback`] and the
//! `run` function on each command's `Args`.

pub mod commands;
pub mod ecosystem_dispatch;
pub mod output;

use clap::{Parser, Subcommand};

// CLI contract surface — subcommand names, visible_alias values, flag names,
// defaults, JSON shapes, and exit codes are PUBLIC and SEMVER-SIGNIFICANT.
// Changes here require a MAJOR bump + `scripts/version-sync.sh`.
// See crates/socket-patch-cli/CLI_CONTRACT.md.
#[derive(Parser)]
#[command(
    name = "socket-patch",
    about = "CLI tool for applying security patches to dependencies",
    version,
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
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
///
/// Used by [`parse_with_uuid_fallback`] to detect the convenience form
/// `socket-patch <UUID>` and rewrite it to `socket-patch get <UUID>`.
pub fn looks_like_uuid(s: &str) -> bool {
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

/// Parse a full argv vector, falling back to `get <UUID>` when the user
/// invoked `socket-patch <UUID> [...]` directly. Returns the original clap
/// error if the fallback also fails or if the first arg isn't a UUID.
///
/// Pulled out of `main.rs` so the fallback path is unit-testable.
pub fn parse_with_uuid_fallback(argv: Vec<String>) -> Result<Cli, clap::Error> {
    match Cli::try_parse_from(&argv) {
        Ok(cli) => Ok(cli),
        Err(err) => {
            if argv.len() >= 2 && looks_like_uuid(&argv[1]) {
                let mut new_args = vec![argv[0].clone(), "get".into()];
                new_args.extend_from_slice(&argv[1..]);
                match Cli::try_parse_from(&new_args) {
                    Ok(cli) => Ok(cli),
                    Err(_) => Err(err),
                }
            } else {
                Err(err)
            }
        }
    }
}
