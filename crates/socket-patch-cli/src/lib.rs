//! socket-patch CLI library crate.
//!
//! Exposes the clap parser types so integration tests can verify the public
//! CLI contract without invoking the binary. The `main.rs` binary entry point
//! is a thin wrapper that delegates to [`parse_argv_with_shortcuts`] and the
//! `run` function on each command's `Args`.

pub mod args;
pub mod commands;
pub(crate) mod ecosystem_dispatch;
pub mod interrupt;
/// The in-memory hosted engine, which lives in core
/// ([`socket_patch_core::hosted::memory`]); re-exported under its old path
/// for the `hosted-bundle` harness and the integration tests.
pub use socket_patch_core::hosted::memory as hosted_memory;
pub mod json_envelope;
pub mod path_scope;
pub mod ui;
pub mod update_notifier;

use clap::{Parser, Subcommand};
use socket_patch_core::utils::target::is_uuid_shaped;

// CLI contract surface — subcommand names, visible_alias values, flag names,
// defaults, JSON shapes, and exit codes are PUBLIC and SEMVER-SIGNIFICANT.
// Changes here require a MAJOR bump + `scripts/version-sync.sh`.
// See crates/socket-patch-cli/CLI_CONTRACT.md.
#[derive(Parser)]
#[command(
    name = "socket-patch",
    about = "Apply security fixes to the dependency versions you already use",
    version,
    propagate_version = true,
    after_help = "Quick start:\n  \
        socket-patch scan --dry-run   Preview patches and dependency-file changes\n  \
        socket-patch scan             Apply patches, then run your package manager's install\n  \
        socket-patch vex -O vex.json  Generate OpenVEX after installing\n\n\
        Use 'socket-patch <command> -h' for common options, or '--help' for all options."
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
    // to the hidden `self-update` subcommand by `parse_argv_with_shortcuts`
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
    /// Find and apply available patches (preview with --dry-run)
    ///
    /// Rewrites lockfiles and related dependency files to use Socket-hosted
    /// patched packages without prompting. Use `scan --dry-run` to preview
    /// changes without writing them.
    ///
    /// Supported lockfiles can be scanned from a fresh checkout before
    /// installing dependencies. Some workflows require installed packages or
    /// build-tool resolution records first: agent mode patches installed
    /// files, and sbt / scala-cli need their build tool's resolution records.
    Scan(commands::scan::ScanArgs),

    /// Apply patches for a package, advisory, or patch UUID
    Get(commands::get::GetArgs),

    /// Show this project's patches in every mode
    List(commands::list::ListArgs),

    /// Restore and remove patches matching a package, PURL, or UUID
    Remove(commands::remove::RemoveArgs),

    /// Restore selected patches, or all patches when no target is given
    Rollback(commands::rollback::RollbackArgs),

    /// Generate OpenVEX for vulnerabilities addressed by verified patches
    Vex(commands::vex::VexArgs),

    /// Store patched dependencies in .socket/vendor/ for offline installs
    ///
    /// Rewire dependency files to use the committed artifacts. Unpatched
    /// dependencies still need their normal registry or cache. Use --revert
    /// to undo vendoring.
    Vendor(commands::vendor::VendorArgs),

    /// Reapply agent-mode patches after installing dependencies
    Apply(commands::apply::ApplyArgs),

    /// Restore agent or vendored patch artifacts and clean up unused ones
    ///
    /// Downloads missing agent patch data and redownloads missing or corrupt
    /// vendored artifacts using the existing vendor ledger, then deletes
    /// unreferenced artifacts. A lost `.socket/vendor/state.json` cannot be
    /// reconstructed; restore it from version control.
    Repair(commands::repair::RepairArgs),

    // Internal parse target of the root `--update` flag (see the rewrite
    // in `parse_argv_with_shortcuts`). Hidden: the public contract
    // surface is `socket-patch --update`, and this name carries no
    // stability guarantee (documented as internal in CLI_CONTRACT.md).
    // Plain `//` comments plus an explicit `about`/`override_usage`/
    // `display_name`: a doc comment here would become
    // `socket-patch --update --help` text, and the derived usage and
    // `--update --version` lines would name the hidden subcommand.
    #[command(
        hide = true,
        name = "self-update",
        display_name = "socket-patch",
        about = "Update socket-patch itself to the latest (or a pinned) release",
        override_usage = "socket-patch --update [VERSION] [OPTIONS]"
    )]
    SelfUpdate(commands::update::UpdateArgs),

    // Internal parity/debug harness for the in-memory hosted engine: reads a
    // JSON file bundle on stdin, prints the engine result. Hidden and
    // documented as internal in CLI_CONTRACT.md (no stability guarantee).
    #[command(hide = true, name = "hosted-bundle")]
    HostedBundle(commands::hosted_bundle::HostedBundleArgs),
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
            Commands::Rollback(a) => &a.common,
            Commands::Get(a) => &a.common,
            Commands::List(a) => &a.common,
            Commands::Remove(a) => &a.common,
            Commands::Repair(a) => &a.common,
            Commands::SelfUpdate(a) => &a.common,
            Commands::HostedBundle(a) => &a.common,
        }
    }

    /// Validate the run's path flags ([`args::GlobalArgs::validate_paths`])
    /// for every command that reads the project. `self-update` and the
    /// internal `hosted-bundle` harness (stdin in, stdout out) never touch
    /// `--cwd`, so an ambient `SOCKET_CWD` must not fail them. `get` and
    /// `scan` create the manifest, so a `--manifest-path` into a directory
    /// that does not exist yet stays legal for them.
    pub fn validate_paths(&self) -> Result<(), String> {
        match self {
            Commands::SelfUpdate(_) | Commands::HostedBundle(_) => Ok(()),
            Commands::Get(_) | Commands::Scan(_) => self.global_args().validate_paths(true),
            other => other.global_args().validate_paths(false),
        }
    }
}

/// Global options every subcommand's short help (`-h`) still lists; the
/// rest move to `--help` only.
const SHORT_HELP_GLOBALS: &[&str] = &["json", "dry_run", "cwd", "ecosystems", "offline"];

/// Per-subcommand arguments shown in `-h` on top of its own (non-global)
/// ones: the commands that prompt keep `--yes`.
fn short_help_extra_globals(sub: &str) -> &'static [&'static str] {
    match sub {
        "get" | "rollback" | "remove" | "self-update" => &["yes"],
        _ => &[],
    }
}

/// Command-specific arguments left out of a subcommand's `-h` (still in
/// `--help`), so each short help stays at about eight options.
fn short_help_hidden_own(sub: &str) -> &'static [&'static str] {
    match sub {
        "scan" => &[
            "batch_size",
            "prune",
            "sync",
            "all_releases",
            "vex_product",
            "vex_no_verify",
            "vex_doc_id",
            "vex_compact",
            "no_socket_yml",
            "min_severity",
            "max_new_patches",
        ],
        "get" => &["id", "cve", "ghsa", "package", "save_only", "all_releases"],
        "vex" => &["doc_id", "compact"],
        "apply" => &["vex_product", "vex_no_verify", "vex_doc_id", "vex_compact"],
        "vendor" => &["vex_product", "vex_no_verify", "vex_doc_id", "vex_compact"],
        _ => &[],
    }
}

/// The `socket-patch` command as it parses and renders: [`Cli`]'s derived
/// command with the short help (`-h`) trimmed to the common options. Every
/// argument stays in `--help` and parses exactly as before.
pub fn cli_command() -> clap::Command {
    use clap::CommandFactory;
    Cli::command().mut_subcommands(|sub| {
        let hidden_own = short_help_hidden_own(sub.get_name());
        let extra = short_help_extra_globals(sub.get_name());
        sub.mut_args(|arg| {
            let id = arg.get_id().as_str();
            let keep = if arg.get_help_heading() == Some(args::GLOBAL_OPTIONS) {
                SHORT_HELP_GLOBALS.contains(&id) || extra.contains(&id)
            } else {
                !hidden_own.contains(&id)
            };
            if keep {
                arg
            } else {
                arg.hide_short_help(true)
            }
        })
    })
}

/// Parse `argv` against [`cli_command`].
pub fn try_parse_cli(argv: &[String]) -> Result<Cli, clap::Error> {
    use clap::FromArgMatches;
    let mut matches = cli_command().try_get_matches_from(argv)?;
    Cli::from_arg_matches_mut(&mut matches).map_err(|e| e.format(&mut cli_command()))
}

/// Is there a UUID-shaped operand among `args` (argv without argv[0])
/// before the first subcommand name? A value-taking flag's value
/// (`--org <UUID>`, `-o<v>`) is not an operand, so a UUID-shaped org slug
/// or token never turns `socket-patch --org <UUID> scan --help` into
/// `get`. After `--` every token is an operand.
fn first_operand_is_uuid(args: &[String], subcommands: &[String]) -> bool {
    // The rewrite parses `args` as `get`'s, so `get`'s value-taking flags
    // (the shared global options included) decide what is a flag value.
    let cmd = cli_command();
    let get = cmd.find_subcommand("get").expect("get subcommand");
    let mut longs: Vec<&str> = Vec::new();
    let mut shorts: Vec<char> = Vec::new();
    for arg in cmd.get_arguments().chain(get.get_arguments()) {
        if !arg.get_action().takes_values() || arg.is_positional() {
            continue;
        }
        longs.extend(arg.get_long());
        longs.extend(arg.get_all_aliases().unwrap_or_default());
        shorts.extend(arg.get_short());
        shorts.extend(arg.get_all_short_aliases().unwrap_or_default());
    }
    let mut options_ended = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if !options_ended {
            if a == "--" {
                options_ended = true;
                continue;
            }
            if subcommands.iter().any(|s| s == a) {
                return false;
            }
            if let Some(long) = a.strip_prefix("--") {
                if !long.contains('=') && longs.contains(&long) {
                    i += 1;
                }
                continue;
            }
            if let Some(cluster) = a.strip_prefix('-').filter(|c| !c.is_empty()) {
                // `-xo VALUE` or `-xoVALUE`: the first value-taking short
                // consumes the rest of the cluster, or the next token
                // when it ends the cluster.
                let chars: Vec<char> = cluster.chars().collect();
                if let Some(at) = chars.iter().position(|c| shorts.contains(c)) {
                    if at + 1 == chars.len() {
                        i += 1;
                    }
                }
                continue;
            }
        }
        if is_uuid_shaped(a) {
            return true;
        }
    }
    false
}

/// Parse a full argv vector with two convenience rewrites on failure:
/// `--update [...]` becomes the hidden `self-update` subcommand, and a
/// bare `<UUID>` becomes `get <UUID>`. Returns the original clap error if
/// no rewrite applies or the applicable rewrite also genuinely fails.
///
/// Pulled out of `main.rs` so the fallback paths are unit-testable.
///
/// An unknown subcommand that names a retired one (`setup`, `unlock`), or
/// whose clap typo tip would point at a hidden internal subcommand
/// (`self-update`, `hosted-bundle`), gets a precise usage error instead of
/// the misleading tip (B76). Still a usage error: exit 2.
pub fn parse_argv_with_shortcuts(argv: Vec<String>) -> Result<Cli, clap::Error> {
    parse_with_rewrites(argv).map_err(explain_unknown_subcommand)
}

/// Subcommands earlier majors had, with what to do instead.
const RETIRED_SUBCOMMANDS: &[(&str, &str)] = &[
    (
        "setup",
        "was removed in v5.0, together with the install hooks it wired. In CI, run \
         `socket-patch apply` after each install (agent mode), or switch to \
         `socket-patch scan --mode hosted` or `--mode vendored`, whose lockfile edits \
         need no hook. To remove the old Bundler plugin, delete the Gemfile \
         `plugin \"socket-patch\"` block and `.socket/bundler-plugin/`, then run \
         `bundle plugin uninstall socket-patch` in every checkout that ran \
         `bundle install` with it",
    ),
    (
        "unlock",
        "was removed in v4.0: a lock left by a crashed run never blocks the next run, \
         so there is nothing to unlock",
    ),
];

const SELF_UPDATE_TIP: &str = "to update socket-patch itself, run `socket-patch --update`";

/// Hidden subcommands clap may still suggest as a typo fix, with the tip
/// that replaces the suggestion (`None`: no tip).
const HIDDEN_SUBCOMMAND_TIPS: &[(&str, Option<&str>)] = &[
    ("self-update", Some(SELF_UPDATE_TIP)),
    ("hosted-bundle", None),
];

/// Replace clap's tip for an unknown subcommand when it would mislead: a
/// retired v4 spelling (`setup` suggests the hidden `self-update`) or any
/// suggestion naming a hidden internal subcommand.
fn explain_unknown_subcommand(err: clap::Error) -> clap::Error {
    use clap::error::{ContextKind, ContextValue, ErrorKind};
    if err.kind() != ErrorKind::InvalidSubcommand {
        return err;
    }
    let Some(ContextValue::String(name)) = err.get(ContextKind::InvalidSubcommand) else {
        return err;
    };
    let message = if let Some((_, why)) = RETIRED_SUBCOMMANDS.iter().find(|(n, _)| n == name) {
        format!("the `{name}` subcommand {why}")
    } else if name == "update" {
        // Self-update is the root `--update` flag, not a subcommand.
        format!("unrecognized subcommand '{name}'\n\n  tip: {SELF_UPDATE_TIP}")
    } else {
        let suggested: Vec<&str> = match err.get(ContextKind::SuggestedSubcommand) {
            Some(ContextValue::String(s)) => vec![s.as_str()],
            Some(ContextValue::Strings(s)) => s.iter().map(String::as_str).collect(),
            _ => Vec::new(),
        };
        let Some((_, tip)) = HIDDEN_SUBCOMMAND_TIPS
            .iter()
            .find(|(hidden, _)| suggested.contains(hidden))
        else {
            return err;
        };
        match tip {
            Some(tip) => format!("unrecognized subcommand '{name}'\n\n  tip: {tip}"),
            None => format!("unrecognized subcommand '{name}'"),
        }
    };
    clap::Error::raw(ErrorKind::InvalidSubcommand, format!("{message}\n"))
        .format(&mut cli_command())
}

fn parse_with_rewrites(argv: Vec<String>) -> Result<Cli, clap::Error> {
    match try_parse_cli(&argv) {
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
            //
            // `--` ends the option list, so only a `--update` before it is
            // the flag — after it the token is an escaped operand and the
            // original error stands.
            let opts_end = argv
                .iter()
                .skip(1)
                .position(|a| a == "--")
                .map_or(argv.len(), |i| i + 1);
            // Both spellings clap gives a value-taking long flag are
            // recognized: the space form (`--update 3.4.0`, whose VERSION
            // reaches the synthesized subcommand as its positional) and the
            // inline `--update=3.4.0`, whose value is spliced in where the
            // flag token was. Without the inline arm clap rejects it as
            // "unexpected value '3.4.0' for '--update'" — the root flag is a
            // bool, so the `=` form never reaches the VERSION at all.
            let update_flag = argv
                .iter()
                .enumerate()
                .take(opts_end)
                .skip(1)
                .find_map(|(i, a)| match a.strip_prefix("--update") {
                    Some("") => Some((i, None)),
                    Some(rest) => rest.strip_prefix('=').map(|v| (i, Some(v))),
                    None => None,
                });
            if let Some((pos, inline_version)) = update_flag {
                let mut new_args = Vec::with_capacity(argv.len() + 1);
                new_args.push(argv[0].clone());
                new_args.push("self-update".to_string());
                new_args.extend_from_slice(&argv[1..pos]);
                if let Some(version) = inline_version {
                    new_args.push(version.to_string());
                }
                new_args.extend_from_slice(&argv[pos + 1..]);
                return match try_parse_cli(&new_args) {
                    Ok(cli) => Ok(cli),
                    Err(rewrite_err) if pos == 1 || !rewrite_err.use_stderr() => Err(rewrite_err),
                    Err(_) => Err(err),
                };
            }
            // The UUID shortcut keys on the first UUID-shaped token before
            // any subcommand name, not just argv[1], so root-position flags
            // are fine: `socket-patch --json <UUID>` is `get --json <UUID>`.
            // The shape is the shared target grammar's
            // ([`is_uuid_shaped`]), the same one `get` classifies with.
            let subcommands: Vec<String> = cli_command()
                .get_subcommands()
                .flat_map(|c| std::iter::once(c.get_name()).chain(c.get_all_aliases()))
                .map(str::to_string)
                .collect();
            let uuid_operand = first_operand_is_uuid(&argv[1..], &subcommands);
            if uuid_operand {
                let mut new_args = vec![argv[0].clone(), "get".into()];
                new_args.extend_from_slice(&argv[1..]);
                match try_parse_cli(&new_args) {
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
    use socket_patch_core::utils::target::is_uuid_shaped as looks_like_uuid;

    // ---------- looks_like_uuid (the shared core UUID shape) ----------

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

    // ---------- parse_argv_with_shortcuts ----------

    const UUID: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn fallback_rewrites_bare_uuid_to_get() {
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", UUID])).unwrap();
        match cli.command {
            Commands::Get(args) => assert_eq!(args.identifier, UUID),
            _ => panic!("expected Commands::Get"),
        }
    }

    #[test]
    fn fallback_preserves_trailing_flags() {
        // Flags after the UUID must be forwarded to the synthesized `get`.
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", UUID, "--json"])).unwrap();
        match cli.command {
            Commands::Get(args) => {
                assert_eq!(args.identifier, UUID);
                assert!(args.common.json, "--json should be forwarded to get");
            }
            _ => panic!("expected Commands::Get"),
        }
    }

    /// The shortcut keys on the first UUID-shaped operand, not just
    /// argv[1]: `socket-patch --json <UUID>` used to fail with
    /// "unexpected argument '--json'".
    #[test]
    fn fallback_rewrites_a_uuid_after_leading_flags() {
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", "--json", UUID])).unwrap();
        match cli.command {
            Commands::Get(args) => {
                assert_eq!(args.identifier, UUID);
                assert!(args.common.json);
            }
            _ => panic!("expected the get subcommand"),
        }
        // A UUID after a real subcommand is that subcommand's operand.
        assert!(parse_argv_with_shortcuts(argv(&["socket-patch", "list", UUID])).is_err());
    }

    #[test]
    fn fallback_skips_a_uuid_shaped_flag_value() {
        // A UUID-shaped flag value is the flag's value, not the shortcut
        // operand: `--org <UUID> scan` must fail exactly as `--org acme
        // scan` does, never parse as `get scan` (which would run `get`
        // with `scan` as its identifier).
        for flags in [
            vec!["--org", UUID],
            vec!["-o", UUID],
            vec!["--api-token", UUID],
        ] {
            for tail in [vec!["scan"], vec!["scan", "--help"]] {
                let mut args = vec!["socket-patch"];
                args.extend(flags.iter().copied());
                args.extend(tail.iter().copied());
                let err = match parse_argv_with_shortcuts(argv(&args)) {
                    Ok(cli) => panic!(
                        "{args:?} was rewritten to {:?}",
                        std::mem::discriminant(&cli.command)
                    ),
                    Err(e) => e,
                };
                assert_eq!(
                    err.kind(),
                    clap::error::ErrorKind::UnknownArgument,
                    "{args:?}"
                );
            }
        }
        assert!(!first_operand_is_uuid(
            &argv(&["--org", UUID, "-o", UUID, "--org=x"]),
            &[]
        ));
        assert!(first_operand_is_uuid(&argv(&["--org", "acme", UUID]), &[]));
        assert!(first_operand_is_uuid(&argv(&["-oacme", UUID]), &[]));
        assert!(first_operand_is_uuid(&argv(&["--org=acme", UUID]), &[]));
        assert!(first_operand_is_uuid(&argv(&["--", UUID]), &[]));
    }

    #[test]
    fn fallback_returns_original_error_when_first_arg_is_not_uuid() {
        // No rewrite should happen; the original clap error must surface.
        // `Cli` doesn't derive `Debug`, so `unwrap_err()` doesn't compile —
        // pull the error out via `match` instead.
        let err = match parse_argv_with_shortcuts(argv(&["socket-patch", "not-a-uuid"])) {
            Ok(_) => panic!("expected parse to fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn fallback_is_skipped_when_normal_parse_succeeds() {
        // `list` parses normally — fallback should not engage.
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", "list"])).unwrap();
        assert!(matches!(cli.command, Commands::List(_)));
    }

    #[test]
    fn fallback_does_not_double_rewrite_explicit_get() {
        // `socket-patch get <UUID>` already parses; fallback never runs.
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", "get", UUID])).unwrap();
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
            parse_argv_with_shortcuts(argv(&["socket-patch", UUID, "--id", "--json"])).unwrap();
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
        let cli = parse_argv_with_shortcuts(argv(&[
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
        let err = match parse_argv_with_shortcuts(argv(&["socket-patch"])) {
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
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", UPPER])).unwrap();
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
        let err = match parse_argv_with_shortcuts(argv(&[
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
        let err = match parse_argv_with_shortcuts(argv(&["socket-patch", UUID, "--help"])) {
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
        let err = match parse_argv_with_shortcuts(argv(&["socket-patch", UUID, "--version"])) {
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
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", "--update"])).unwrap();
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
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", "--update", "3.4.0"])).unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => assert_eq!(args.pin_version.as_deref(), Some("3.4.0")),
            _ => panic!("expected Commands::SelfUpdate"),
        }
    }

    #[test]
    fn update_version_pin_normalizes_v_prefix() {
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", "--update", "v3.4.0"])).unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => assert_eq!(args.pin_version.as_deref(), Some("3.4.0")),
            _ => panic!("expected Commands::SelfUpdate"),
        }
    }

    #[test]
    fn update_flag_is_position_independent() {
        // The flag needn't come first: every other arg is preserved in
        // order around the dropped `--update` token.
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", "--json", "--update"])).unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => assert!(args.common.json),
            _ => panic!("expected Commands::SelfUpdate"),
        }
        let cli =
            parse_argv_with_shortcuts(argv(&["socket-patch", "--update", "--force", "--silent"]))
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
        let err = match parse_argv_with_shortcuts(argv(&["socket-patch", "--update", "latest"])) {
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
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", "--update", "scan"]));
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
        let err = match parse_argv_with_shortcuts(argv(&["socket-patch", "scan", "--update"])) {
            Ok(_) => panic!("expected parse to fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn update_help_shows_self_update_help() {
        let err = match parse_argv_with_shortcuts(argv(&["socket-patch", "--update", "--help"])) {
            Ok(_) => panic!("clap surfaces --help as an Err"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(!err.use_stderr());
        assert_eq!(err.exit_code(), 0);
        // The page is self-update's, but spelled the public way: the hidden
        // subcommand name must not leak into its usage line.
        let text = err.to_string();
        assert!(
            text.contains("Usage: socket-patch --update [VERSION]"),
            "{text}"
        );
        assert!(!text.contains("self-update"), "{text}");
    }

    #[test]
    fn update_flag_accepts_the_inline_equals_version() {
        // `--update <VERSION>` is what the flag's own help advertises, and
        // clap accepts `--flag=value` for every value-taking long flag. But
        // the root `--update` is a `bool`, so clap rejects the `=` spelling
        // outright — "unexpected value '3.4.0' for '--update' found; no more
        // were expected", i.e. "this flag takes no value at all". The VERSION
        // only exists on the synthesized subcommand, so the rewrite has to
        // recognize `--update=<VERSION>` itself.
        let cli = parse_argv_with_shortcuts(argv(&["socket-patch", "--update=3.4.0"])).unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => assert_eq!(args.pin_version.as_deref(), Some("3.4.0")),
            _ => panic!("expected Commands::SelfUpdate"),
        }
    }

    #[test]
    fn update_inline_equals_version_normalizes_and_keeps_neighbours() {
        // Same leading-`v` normalization as the space form, and the inline
        // value is spliced in where the flag token was, so the args on either
        // side keep both their order and their meaning.
        let cli = parse_argv_with_shortcuts(argv(&[
            "socket-patch",
            "--json",
            "--update=v3.4.0",
            "--force",
        ]))
        .unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => {
                assert_eq!(args.pin_version.as_deref(), Some("3.4.0"));
                assert!(args.common.json, "--json before the flag must survive");
                assert!(args.force, "--force after the flag must survive");
            }
            _ => panic!("expected Commands::SelfUpdate"),
        }
    }

    #[test]
    fn update_inline_equals_garbage_version_is_a_usage_error() {
        // The inline form validates its VERSION exactly like the space form:
        // a usage error naming the bad value (exit 2), never a silent
        // fall-through to a latest-release install.
        let err = match parse_argv_with_shortcuts(argv(&["socket-patch", "--update=latest"])) {
            Ok(_) => panic!("expected parse to fail"),
            Err(e) => e,
        };
        assert!(err.use_stderr());
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("not a valid version"), "{err}");
    }

    #[test]
    fn update_after_a_double_dash_is_an_operand_not_the_flag() {
        // `--` ends the option list, so a following `--update` is an escaped
        // operand. The root command takes no positional, so this is a usage
        // error — it must NOT be rewritten into a binary-replacing
        // self-update. (`socket-patch list -- --update` already errors, only
        // because the rewrite happens to fail there; the root form has to
        // fail for the right reason.)
        let err = match parse_argv_with_shortcuts(argv(&["socket-patch", "--", "--update"])) {
            Ok(_) => panic!("`--update` after `--` is an operand, not the flag"),
            Err(e) => e,
        };
        assert!(err.use_stderr(), "a usage error, not a display request");
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn double_dash_after_the_update_flag_still_rewrites() {
        // Counter-guard for the test above: only a `--` that PRECEDES the
        // flag ends the option list, so `--update -- 3.4.0` still pins.
        let cli =
            parse_argv_with_shortcuts(argv(&["socket-patch", "--update", "--", "3.4.0"])).unwrap();
        match cli.command {
            Commands::SelfUpdate(args) => assert_eq!(args.pin_version.as_deref(), Some("3.4.0")),
            _ => panic!("expected Commands::SelfUpdate"),
        }
    }

    #[test]
    fn root_help_documents_the_update_flag() {
        let err = match parse_argv_with_shortcuts(argv(&["socket-patch", "--help"])) {
            Ok(_) => panic!("clap surfaces --help as an Err"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let help = err.to_string();
        assert!(
            help.contains("--update"),
            "root help must advertise --update"
        );
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
        let err = match parse_argv_with_shortcuts(argv(&[
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
