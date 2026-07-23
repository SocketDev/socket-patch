//! socket-patch CLI library crate.
//!
//! Exposes the clap parser types so integration tests can verify the public
//! CLI contract without invoking the binary. The `main.rs` binary entry point
//! is a thin wrapper that delegates to [`parse_with_uuid_fallback`] and the
//! `run` function on each command's `Args`.

pub mod args;
pub mod commands;
pub(crate) mod ecosystem_dispatch;
pub mod json_envelope;
pub mod output;
pub mod update_notifier;

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

    /// Update socket-patch itself to the latest release (or
    /// `--update <VERSION>` for a specific one). Standalone installs
    /// only; package-manager installs are pointed at their own
    /// upgrade command.
    //
    // This root flag is the public surface; parsing-wise it is rewritten
    // to the hidden `self-update` subcommand by `parse_with_uuid_fallback`
    // (`command` stays required, so `--update` alone never parses `Ok`
    // here). The field itself exists for `--help` discoverability and to
    // reject the contradictory `socket-patch --update <subcommand>` form
    // in `main`. Deliberately no env binding: an ambient "always
    // self-update" toggle would poison every parse. (Plain `//` comments:
    // doc comments here would leak internals into `--help`.)
    #[arg(long)]
    pub update: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan installed packages for available security patches
    Scan(commands::scan::ScanArgs),

    /// Apply security patches to dependencies
    Apply(commands::apply::ApplyArgs),

    /// Generate an OpenVEX 0.2.0 attestation describing the
    /// vulnerabilities mitigated by the applied patches.
    Vex(commands::vex::VexArgs),

    /// Eject patched dependencies into committable `.socket/vendor/`
    /// and rewire lockfiles so fresh checkouts build with the patches
    /// (no socket-patch or Socket API needed). `--revert` undoes it.
    Vendor(commands::vendor::VendorArgs),

    /// Configure package.json postinstall scripts to apply patches
    Setup(commands::setup::SetupArgs),

    /// Rollback patches to restore original files
    Rollback(commands::rollback::RollbackArgs),

    /// Get security patches from Socket API and apply them
    #[command(visible_alias = "download")]
    Get(commands::get::GetArgs),

    /// List all patches in the local manifest
    List(commands::list::ListArgs),

    /// Remove a patch from the manifest by PURL or UUID (rolls back files first)
    Remove(commands::remove::RemoveArgs),

    /// Download missing blobs, clean up unused blobs, and reset the
    /// advisory lock state.
    ///
    /// `repair` (alias `gc`) is a first-class command for cleaning up
    /// the `.socket/` directory without running a scan. For the
    /// combined workflow (discover + apply + GC), use
    /// `scan --sync --json --yes`. `repair`/`gc` remain useful on
    /// their own when the user wants to clean up without an apply pass.
    #[command(visible_alias = "gc")]
    Repair(commands::repair::RepairArgs),

    /// Internal parse target of the root `--update` flag (see the rewrite
    /// in [`parse_with_uuid_fallback`]). Hidden: the public contract
    /// surface is `socket-patch --update`, and this name carries no
    /// stability guarantee (documented as internal in CLI_CONTRACT.md).
    #[command(hide = true, name = "self-update")]
    SelfUpdate(commands::update::UpdateArgs),
}

impl Commands {
    /// The flattened [`args::GlobalArgs`] every subcommand carries. Lets
    /// cross-cutting hooks (the update notifier) read `--json`/`--silent`/
    /// `--offline`/`--debug` before the dispatch match consumes `self`.
    pub fn global_args(&self) -> &args::GlobalArgs {
        match self {
            Commands::Scan(a) => &a.common,
            Commands::Apply(a) => &a.common,
            Commands::Vex(a) => &a.common,
            Commands::Vendor(a) => &a.common,
            Commands::Setup(a) => &a.common,
            Commands::Rollback(a) => &a.common,
            Commands::Get(a) => &a.common,
            Commands::List(a) => &a.common,
            Commands::Remove(a) => &a.common,
            Commands::Repair(a) => &a.common,
            Commands::SelfUpdate(a) => &a.common,
        }
    }
}

/// Check whether `s` looks like a UUID (8-4-4-4-12 hex pattern).
///
/// Used by [`parse_with_uuid_fallback`] to detect the convenience form
/// `socket-patch <UUID>` and rewrite it to `socket-patch get <UUID>`.
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

/// Parse a full argv vector with two convenience rewrites on failure:
/// `--update [...]` becomes the hidden `self-update` subcommand, and a
/// bare `<UUID>` becomes `get <UUID>`. Returns the original clap error if
/// no rewrite applies or the applicable rewrite also genuinely fails.
///
/// Pulled out of `main.rs` so the fallback paths are unit-testable.
pub fn parse_with_uuid_fallback(argv: Vec<String>) -> Result<Cli, clap::Error> {
    match Cli::try_parse_from(&argv) {
        Ok(cli) => Ok(cli),
        Err(err) => {
            // Root `--update` never parses Ok on its own (the subcommand
            // is required), so rewrite it to `self-update`, dropping the
            // flag token and keeping every other arg in order — this way
            // `--update 3.4.0`, `--json --update`, and `--update --help`
            // all reach the real parser. When `--update` is the FIRST
            // argument the intent is unambiguous, so the rewrite's outcome
            // (including its errors) is surfaced; anywhere else a genuine
            // rewrite failure falls back to the original error, mirroring
            // the UUID shortcut below.
            if let Some(pos) = argv.iter().skip(1).position(|a| a == "--update") {
                let pos = pos + 1; // undo the skip(1) offset
                let mut new_args = Vec::with_capacity(argv.len() + 1);
                new_args.push(argv[0].clone());
                new_args.push("self-update".to_string());
                new_args.extend_from_slice(&argv[1..pos]);
                new_args.extend_from_slice(&argv[pos + 1..]);
                return match Cli::try_parse_from(&new_args) {
                    Ok(cli) => Ok(cli),
                    Err(rewrite_err) if pos == 1 || !rewrite_err.use_stderr() => Err(rewrite_err),
                    Err(_) => Err(err),
                };
            }
            if argv.len() >= 2 && looks_like_uuid(&argv[1]) {
                let mut new_args = vec![argv[0].clone(), "get".into()];
                new_args.extend_from_slice(&argv[1..]);
                match Cli::try_parse_from(&new_args) {
                    Ok(cli) => Ok(cli),
                    // clap models `--help`/`--version` as `Err`, but they are
                    // display requests, not parse failures. For those the
                    // rewritten `get` form is the correct thing to show, so
                    // surface the rewrite's error (which clap exits 0 on).
                    // Only genuine failures (those clap prints to stderr) fall
                    // back to the original un-rewritten error.
                    Err(rewrite_err) if !rewrite_err.use_stderr() => Err(rewrite_err),
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
        let cli =
            parse_with_uuid_fallback(argv(&["socket-patch", UUID, "--id", "--json"])).unwrap();
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
    fn fallback_forwards_value_bearing_flag_in_order() {
        // The existing forwarding tests only use boolean flags, which don't
        // consume the following token. A value-bearing flag (`--manifest-path
        // <value>`) exercises the splice ordering differently: an off-by-one in
        // `extend_from_slice(&argv[1..])` would either drop the flag's value or
        // shift it onto the wrong token. Passing the flag explicitly wins over
        // its `SOCKET_MANIFEST_PATH` env fallback, so this holds regardless of
        // ambient env.
        let cli = parse_with_uuid_fallback(argv(&[
            "socket-patch",
            UUID,
            "--manifest-path",
            "custom/forwarded.json",
        ]))
        .unwrap();
        match cli.command {
            Commands::Get(args) => {
                assert_eq!(args.identifier, UUID);
                assert_eq!(
                    args.common.manifest_path, "custom/forwarded.json",
                    "the value-bearing flag and its argument must survive the rewrite in order"
                );
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

    #[test]
    fn fallback_forwards_help_to_rewritten_get() {
        // `socket-patch <UUID> --help` must display the rewritten `get`
        // command's help rather than swallowing it and surfacing the original
        // "invalid subcommand" error. clap models `--help` as an `Err`, but it
        // is a display request (exit 0), so the fallback must surface THAT
        // error, not the original InvalidSubcommand (which would exit 2).
        let err = match parse_with_uuid_fallback(argv(&["socket-patch", UUID, "--help"])) {
            Ok(_) => panic!("clap surfaces --help as an Err"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::DisplayHelp,
            "bare-UUID + --help should show get's help, not the original error"
        );
        // Display requests exit 0 and print to stdout, not stderr.
        assert!(!err.use_stderr());
        assert_eq!(err.exit_code(), 0);
        // The rendered help is for the rewritten `get` command, proving the
        // rewrite's error (not the original) was surfaced.
        assert!(err.to_string().contains("socket-patch get"));
    }

    #[test]
    fn fallback_forwards_version_to_rewritten_get() {
        // `--version` is likewise a display request that propagates to
        // subcommands (propagate_version = true); it must not be swallowed.
        let err = match parse_with_uuid_fallback(argv(&["socket-patch", UUID, "--version"])) {
            Ok(_) => panic!("clap surfaces --version as an Err"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(!err.use_stderr());
        assert_eq!(err.exit_code(), 0);
    }

    // ---------- --update rewrite ----------

    #[test]
    fn update_flag_alone_rewrites_to_self_update() {
        let cli = parse_with_uuid_fallback(argv(&["socket-patch", "--update"])).unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => {
                assert_eq!(args.pin_version, None);
                assert!(!args.force);
            }
            _ => panic!("expected Commands::SelfUpdate"),
        }
    }

    #[test]
    fn update_flag_takes_a_version_pin() {
        let cli = parse_with_uuid_fallback(argv(&["socket-patch", "--update", "3.4.0"])).unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => assert_eq!(args.pin_version.as_deref(), Some("3.4.0")),
            _ => panic!("expected Commands::SelfUpdate"),
        }
    }

    #[test]
    fn update_version_pin_normalizes_v_prefix() {
        let cli = parse_with_uuid_fallback(argv(&["socket-patch", "--update", "v3.4.0"])).unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => assert_eq!(args.pin_version.as_deref(), Some("3.4.0")),
            _ => panic!("expected Commands::SelfUpdate"),
        }
    }

    #[test]
    fn update_flag_is_position_independent() {
        // The flag needn't come first: every other arg is preserved in
        // order around the dropped `--update` token.
        let cli =
            parse_with_uuid_fallback(argv(&["socket-patch", "--json", "--update"])).unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => assert!(args.common.json),
            _ => panic!("expected Commands::SelfUpdate"),
        }
        let cli = parse_with_uuid_fallback(argv(&[
            "socket-patch",
            "--update",
            "--force",
            "--silent",
        ]))
        .unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => {
                assert!(args.force);
                assert!(args.common.silent);
            }
            _ => panic!("expected Commands::SelfUpdate"),
        }
    }

    #[test]
    fn update_with_garbage_version_is_a_usage_error() {
        let err = match parse_with_uuid_fallback(argv(&["socket-patch", "--update", "latest"])) {
            Ok(_) => panic!("expected parse to fail"),
            Err(e) => e,
        };
        // --update first ⇒ the rewrite's error surfaces (a value-validation
        // usage error, exit 2), not the original missing-subcommand help.
        assert!(err.use_stderr());
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("not a valid version"), "{err}");
    }

    #[test]
    fn update_before_subcommand_parses_as_root_flag() {
        // `socket-patch --update scan` parses Ok at the clap layer (root
        // flag + subcommand); main.rs rejects the combination with exit 2.
        // Pinned here so the rewrite never fires for it.
        let cli = parse_with_uuid_fallback(argv(&["socket-patch", "--update", "scan"]));
        // "scan" is not valid semver, so if the rewrite HAD fired this
        // would be an error — instead the plain parse wins.
        let cli = cli.unwrap();
        assert!(cli.update);
        assert!(matches!(cli.command, Commands::Scan(_)));
    }

    #[test]
    fn update_after_subcommand_surfaces_the_original_error() {
        // `socket-patch scan --update`: scan owns no --update flag, and the
        // rewrite (`self-update scan`) also fails on the VERSION value. The
        // flag was not argv[1], so the ORIGINAL unknown-argument error must
        // surface — pointing at scan, not at self-update.
        let err = match parse_with_uuid_fallback(argv(&["socket-patch", "scan", "--update"])) {
            Ok(_) => panic!("expected parse to fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn update_help_shows_self_update_help() {
        let err = match parse_with_uuid_fallback(argv(&["socket-patch", "--update", "--help"])) {
            Ok(_) => panic!("clap surfaces --help as an Err"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(!err.use_stderr());
        assert_eq!(err.exit_code(), 0);
        assert!(err.to_string().contains("self-update"), "{err}");
    }

    #[test]
    fn root_help_documents_the_update_flag() {
        let err = match parse_with_uuid_fallback(argv(&["socket-patch", "--help"])) {
            Ok(_) => panic!("clap surfaces --help as an Err"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let help = err.to_string();
        assert!(help.contains("--update"), "root help must advertise --update");
        assert!(
            !help.contains("self-update"),
            "the internal subcommand stays hidden from root help"
        );
    }

    #[test]
    fn fallback_genuine_rewrite_failure_still_uses_original_error() {
        // Regression guard for the fix: a *real* rewrite failure (one clap
        // prints to stderr) must still fall back to the original error, so the
        // help/version carve-out doesn't accidentally swallow legitimate
        // failures. An unknown flag makes the rewrite fail with UnknownArgument
        // (use_stderr == true), so the original InvalidSubcommand wins.
        let err = match parse_with_uuid_fallback(argv(&[
            "socket-patch",
            UUID,
            "--definitely-not-a-real-flag",
        ])) {
            Ok(_) => panic!("expected parse to fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
        assert!(err.use_stderr());
    }
}
