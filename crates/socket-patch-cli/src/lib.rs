//! socket-patch CLI library crate.
//!
//! Exposes the clap parser types so integration tests can verify the public
//! CLI contract without invoking the binary. The `main.rs` binary entry point
//! is a thin wrapper that delegates to [`parse_with_uuid_fallback`] and the
//! `run` function on each command's `Args`.

pub mod args;
pub mod commands;
pub mod ecosystem_dispatch;
pub mod json_envelope;
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

    /// Download missing blobs and clean up unused blobs.
    ///
    /// `repair` (alias `gc`) is a first-class command for cleaning up
    /// the `.socket/` directory without running a scan. For the
    /// combined workflow (discover + apply + GC), use
    /// `scan --sync --json --yes`. `repair`/`gc` remain useful on
    /// their own when the user wants to clean up without an apply pass.
    #[command(visible_alias = "gc")]
    Repair(commands::repair::RepairArgs),

    /// Inspect (and optionally release) the `<.socket>/apply.lock`
    /// advisory file lock used by mutating subcommands. Exits 0
    /// when free, 1 when held. Pass `--release` to also delete the
    /// lock file when it is free.
    Unlock(commands::unlock::UnlockArgs),

    /// Generate an OpenVEX 0.2.0 attestation describing the
    /// vulnerabilities mitigated by the applied patches.
    Vex(commands::vex::VexArgs),
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

#[cfg(test)]
mod tests {
    //! Unit tests for the bare-UUID fallback. These tests lock in the
    //! `socket-patch <UUID>` rewrite shortcut and the shape predicate it
    //! uses — both of which are part of the CLI contract (see
    //! `CLI_CONTRACT.md`).
    use super::*;

    // ---------- looks_like_uuid ----------

    #[test]
    fn looks_like_uuid_accepts_canonical_lowercase() {
        assert!(looks_like_uuid("80630680-4da6-45f9-bba8-b888e0ffd58c"));
    }

    #[test]
    fn looks_like_uuid_accepts_uppercase() {
        // `is_ascii_hexdigit` accepts A-F as well as a-f, so all-uppercase
        // UUIDs must still pass the shape check.
        assert!(looks_like_uuid("80630680-4DA6-45F9-BBA8-B888E0FFD58C"));
    }

    #[test]
    fn looks_like_uuid_accepts_mixed_case() {
        assert!(looks_like_uuid("80630680-4Da6-45F9-bBa8-B888e0FfD58c"));
    }

    #[test]
    fn looks_like_uuid_rejects_four_groups() {
        // 8-4-4-4 — missing the final 12-char group.
        assert!(!looks_like_uuid("80630680-4da6-45f9-bba8"));
    }

    #[test]
    fn looks_like_uuid_rejects_six_groups() {
        // One too many groups — the split count must be exactly 5.
        assert!(!looks_like_uuid(
            "80630680-4da6-45f9-bba8-b888e0ffd58c-extra"
        ));
    }

    #[test]
    fn looks_like_uuid_rejects_8_4_4_4_13_group_lengths() {
        // Final group has 13 chars instead of 12.
        assert!(!looks_like_uuid("80630680-4da6-45f9-bba8-b888e0ffd58cc"));
    }

    #[test]
    fn looks_like_uuid_rejects_7_4_4_4_12_group_lengths() {
        // First group has 7 chars instead of 8.
        assert!(!looks_like_uuid("8063068-4da6-45f9-bba8-b888e0ffd58c0"));
    }

    #[test]
    fn looks_like_uuid_rejects_non_hex_chars() {
        // `g` is not a hex digit — must fail even though the shape is right.
        assert!(!looks_like_uuid("g0630680-4da6-45f9-bba8-b888e0ffd58c"));
        assert!(!looks_like_uuid("80630680-4dz6-45f9-bba8-b888e0ffd58c"));
        assert!(!looks_like_uuid("80630680-4da6-45f9-bba8-b888e0ffd58z"));
    }

    #[test]
    fn looks_like_uuid_rejects_empty_string() {
        assert!(!looks_like_uuid(""));
    }

    #[test]
    fn looks_like_uuid_rejects_string_with_no_dashes() {
        // 32 hex chars, no dashes — close to a UUID but not the right shape.
        assert!(!looks_like_uuid("806306804da645f9bba8b888e0ffd58c"));
    }

    #[test]
    fn looks_like_uuid_rejects_bare_dashes() {
        // Five empty groups — split count is right, group lengths aren't.
        assert!(!looks_like_uuid("----"));
    }

    #[test]
    fn looks_like_uuid_accepts_nil_uuid() {
        // The all-zeros nil UUID is correctly shaped and all-hex.
        assert!(looks_like_uuid("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn looks_like_uuid_rejects_surrounding_whitespace() {
        // The predicate must not trim: a leading/trailing space makes the
        // first/last group the wrong length (and the space is non-hex).
        assert!(!looks_like_uuid(" 80630680-4da6-45f9-bba8-b888e0ffd58c"));
        assert!(!looks_like_uuid("80630680-4da6-45f9-bba8-b888e0ffd58c "));
    }

    #[test]
    fn looks_like_uuid_rejects_internal_space() {
        // A space inside a group keeps the byte length right in one spot but
        // fails the hex check — guards against byte-length-only acceptance.
        assert!(!looks_like_uuid("8063068 -4da6-45f9-bba8-b888e0ffd58c"));
    }

    // ---------- parse_with_uuid_fallback ----------

    const UUID: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn fallback_rewrites_bare_uuid_to_get() {
        let cli = parse_with_uuid_fallback(argv(&["socket-patch", UUID])).unwrap();
        match cli.command {
            Commands::Get(args) => assert_eq!(args.identifier, UUID),
            _ => panic!("expected Commands::Get"),
        }
    }

    #[test]
    fn fallback_preserves_trailing_flags() {
        // Flags after the UUID must be forwarded to the synthesized `get`.
        let cli = parse_with_uuid_fallback(argv(&["socket-patch", UUID, "--json"])).unwrap();
        match cli.command {
            Commands::Get(args) => {
                assert_eq!(args.identifier, UUID);
                assert!(args.common.json, "--json should be forwarded to get");
            }
            _ => panic!("expected Commands::Get"),
        }
    }

    #[test]
    fn fallback_returns_original_error_when_first_arg_is_not_uuid() {
        // No rewrite should happen; the original clap error must surface.
        // `Cli` doesn't derive `Debug`, so `unwrap_err()` doesn't compile —
        // pull the error out via `match` instead.
        let err = match parse_with_uuid_fallback(argv(&["socket-patch", "not-a-uuid"])) {
            Ok(_) => panic!("expected parse to fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn fallback_is_skipped_when_normal_parse_succeeds() {
        // `list` parses normally — fallback should not engage.
        let cli = parse_with_uuid_fallback(argv(&["socket-patch", "list"])).unwrap();
        assert!(matches!(cli.command, Commands::List(_)));
    }

    #[test]
    fn fallback_does_not_double_rewrite_explicit_get() {
        // `socket-patch get <UUID>` already parses; fallback never runs.
        let cli = parse_with_uuid_fallback(argv(&["socket-patch", "get", UUID])).unwrap();
        match cli.command {
            Commands::Get(args) => assert_eq!(args.identifier, UUID),
            _ => panic!("expected Commands::Get"),
        }
    }

    #[test]
    fn fallback_forwards_multiple_flags_in_order() {
        // Every arg after the program name (UUID included) must be forwarded
        // after the synthesized `get`, preserving order, so multiple flags
        // all reach the rewritten command.
        let cli = parse_with_uuid_fallback(argv(&["socket-patch", UUID, "--id", "--json"]))
            .unwrap();
        match cli.command {
            Commands::Get(args) => {
                assert_eq!(args.identifier, UUID);
                assert!(args.id, "--id should be forwarded to get");
                assert!(args.common.json, "--json should be forwarded to get");
            }
            _ => panic!("expected Commands::Get"),
        }
    }

    #[test]
    fn fallback_handles_no_args_without_panicking() {
        // Only the program name is present (argv.len() == 1). The
        // `argv.len() >= 2` guard must short-circuit before indexing argv[1],
        // so this returns the original clap error rather than panicking.
        let err = match parse_with_uuid_fallback(argv(&["socket-patch"])) {
            Ok(_) => panic!("expected parse to fail without a subcommand"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand,
            "bare invocation should surface clap's missing-subcommand help, not panic"
        );
    }

    #[test]
    fn fallback_rewrites_uppercase_uuid_end_to_end() {
        // The shape check accepts uppercase; confirm the full fallback path
        // (not just `looks_like_uuid`) rewrites an uppercase bare UUID to get.
        const UPPER: &str = "80630680-4DA6-45F9-BBA8-B888E0FFD58C";
        let cli = parse_with_uuid_fallback(argv(&["socket-patch", UPPER])).unwrap();
        match cli.command {
            Commands::Get(args) => assert_eq!(args.identifier, UPPER),
            _ => panic!("expected Commands::Get"),
        }
    }

    #[test]
    fn fallback_surfaces_original_error_when_rewrite_also_fails() {
        // UUID is valid-shaped so a rewrite is attempted, but `get` doesn't
        // accept this flag — the rewrite parse fails and we must return the
        // ORIGINAL error (the one from the un-rewritten parse), not the
        // rewrite's error.
        let err = match parse_with_uuid_fallback(argv(&[
            "socket-patch",
            UUID,
            "--invalid-flag-that-get-does-not-accept",
        ])) {
            Ok(_) => panic!("expected parse to fail"),
            Err(e) => e,
        };
        // The original parse failed because `<UUID>` isn't a known
        // subcommand, so the surfaced error must be InvalidSubcommand —
        // NOT UnknownArgument (which is what the rewrite parse would have
        // produced).
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }
}
