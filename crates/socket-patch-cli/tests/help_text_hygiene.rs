//! `--help` is user-facing text: implementation notes (clap internals,
//! function names, contract cross-references) belong in `//` comments, and
//! a hyphenated word must not be split across doc-comment lines (clap joins
//! the lines with a space: "lock- contending").

use clap::CommandFactory;
use socket_patch_cli::Cli;

/// Tokens that only make sense to someone reading the source.
const DEV_TOKENS: &[&str] = &[
    "clap",
    "`None`",
    "value_parser",
    "GlobalArgs",
    "GLOBAL_ARG_ENV_VARS",
    "resolve_mode_flags",
    "get_api_client",
    "parse_argv_with_shortcuts",
    "DEFAULT_SOCKET_API_URL",
    "CLI_CONTRACT",
    "Internal parse target",
    "#[command",
    "step-1",
    "step-2",
    "pre-service",
];

fn leaks(text: &str) -> Vec<String> {
    let mut found: Vec<String> = DEV_TOKENS
        .iter()
        .filter(|t| text.contains(**t))
        .map(|t| t.to_string())
        .collect();
    // A line-wrap-split hyphenated word: "lock- contending".
    let chars: Vec<char> = text.chars().collect();
    for w in chars.windows(4) {
        if w[0].is_ascii_lowercase() && w[1] == '-' && w[2] == ' ' && w[3].is_ascii_lowercase() {
            found.push(format!("split hyphen {:?}", w.iter().collect::<String>()));
        }
    }
    found
}

fn long_help(path: &[&str]) -> String {
    let mut cmd = Cli::command();
    cmd.build();
    let mut cur = &mut cmd;
    for name in path {
        cur = cur
            .find_subcommand_mut(name)
            .unwrap_or_else(|| panic!("no subcommand {name}"));
    }
    cur.render_long_help().to_string()
}

#[test]
fn every_help_page_has_no_developer_notes() {
    let mut cmd = Cli::command();
    cmd.build();
    let mut names: Vec<String> = vec![String::new()];
    names.extend(cmd.get_subcommands().map(|s| s.get_name().to_string()));
    let mut failures = Vec::new();
    for name in &names {
        let path: Vec<&str> = if name.is_empty() {
            vec![]
        } else {
            vec![name.as_str()]
        };
        let text = long_help(&path);
        let found = leaks(&text);
        if !found.is_empty() {
            failures.push(format!("{path:?} --help leaks {found:?}:\n{text}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
}

#[test]
fn global_options_help_has_no_developer_notes_on_any_subcommand() {
    let mut cmd = Cli::command();
    cmd.build();
    for sub in cmd.get_subcommands() {
        for arg in sub.get_arguments() {
            if arg.get_help_heading() != Some("Global options") {
                continue;
            }
            let text = format!(
                "{} {}",
                arg.get_help().map(|h| h.to_string()).unwrap_or_default(),
                arg.get_long_help()
                    .map(|h| h.to_string())
                    .unwrap_or_default()
            );
            let found = leaks(&text);
            assert!(
                found.is_empty(),
                "{} --{}: {found:?}: {text}",
                sub.get_name(),
                arg.get_id()
            );
        }
    }
}

#[test]
fn global_flags_are_grouped_after_command_flags() {
    let text = long_help(&["vex"]);
    let options = text.find("Options:").expect("Options heading");
    let global = text
        .find("Global options:")
        .expect("Global options heading");
    let output = text.find("-O, --output <OUTPUT>").expect("--output listed");
    let cwd = text.find("--cwd <CWD>").expect("--cwd listed");
    assert!(
        options < output && output < global && global < cwd,
        "{text}"
    );
}

#[test]
fn self_update_help_shows_the_public_spelling() {
    let text = long_help(&["self-update"]);
    assert!(
        text.starts_with("Update socket-patch itself to the latest release (or to VERSION)."),
        "{text}"
    );
    assert!(
        text.contains("Usage: socket-patch --update [VERSION] [OPTIONS]"),
        "{text}"
    );
    assert!(!text.contains("socket-patch self-update"), "{text}");
}

#[test]
fn vex_product_list_renders_one_item_per_line() {
    let text = long_help(&["vex"]);
    for item in [
        "1. the git `origin` remote",
        "2. package.json:",
        "3. pyproject.toml:",
        "4. Cargo.toml:",
    ] {
        assert!(
            text.lines().any(|l| l.trim_start().starts_with(item)),
            "{item:?} must start its own line:\n{text}"
        );
    }
}

#[test]
fn root_command_list_uses_the_verb_form() {
    let text = long_help(&[]);
    assert!(
        text.contains(
            "Undo patches: restore original files and unwind hosted or vendored lockfile wiring"
        ),
        "{text}"
    );
    assert!(!text.contains("Rollback patches"), "{text}");
    // v5 removed `setup`; its install-hook summary must not come back.
    assert!(!text.contains("install hooks"), "{text}");
    assert!(
        !text.lines().any(|l| l.trim_start().starts_with("setup ")),
        "{text}"
    );
}

/// v5 leads with scan, vex, vendor and list; the agent-mode commands follow.
#[test]
fn root_command_list_leads_with_the_v5_workflow() {
    let text = long_help(&[]);
    let order: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("  "))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|w| {
            [
                "scan", "vex", "vendor", "list", "get", "apply", "rollback", "remove", "repair",
            ]
            .contains(w)
        })
        .collect();
    assert_eq!(
        &order[..9],
        ["scan", "get", "list", "remove", "rollback", "vex", "vendor", "apply", "repair"],
        "{text}"
    );
    assert!(
        text.contains("Patch a project:") && text.contains("Agent mode ("),
        "{text}"
    );
    assert!(!text.contains("older agent-mode"), "{text}");
}

#[test]
fn vendor_and_repair_summaries_read_as_one_line() {
    let text = long_help(&[]);
    assert!(
        text.lines().any(|l| l
            == "  vendor    Eject patched dependencies into committable `.socket/vendor/` and rewire lockfiles to use them (`--revert` undoes it)"),
        "{text}"
    );
    assert!(
        text.lines().any(|l| l
            == "  repair    Restore agent or vendored patch artifacts and clean up unused ones"),
        "{text}"
    );
    let repair = long_help(&["repair"]);
    assert!(
        repair.starts_with(
            "Restore agent or vendored patch artifacts and clean up unused ones\n\n\
             Downloads missing agent patch data and redownloads missing or corrupt \
             vendored artifacts using the existing vendor ledger, then deletes \
             unreferenced artifacts. A lost `.socket/vendor/state.json` cannot be \
             reconstructed; restore it from version control.\n"
        ),
        "{repair}"
    );
}

/// `socket-patch --update --version` names the public binary, not the
/// hidden `self-update` parse target.
#[test]
fn self_update_version_line_names_the_binary() {
    let mut cmd = Cli::command();
    cmd.build();
    let sub = cmd
        .find_subcommand_mut("self-update")
        .expect("self-update subcommand");
    assert_eq!(
        sub.render_version(),
        format!("socket-patch {}\n", env!("CARGO_PKG_VERSION"))
    );
}

/// `--lock-timeout`'s help names every command that takes the lock,
/// agent-mode `get`/`scan` included.
#[test]
fn lock_timeout_help_names_get_and_scan() {
    let text = long_help(&["list"]);
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        flat.contains("`get` and `scan` when they record, apply, vendor or host patches"),
        "{flat}"
    );
}

/// `-h` stays short (about eight options per page); `--help` still lists
/// every option, and the removed `scan --apply`/`--vendor` spellings
/// are in neither.
#[test]
fn short_help_lists_about_eight_options_and_long_help_lists_all() {
    let mut cmd = socket_patch_cli::cli_command();
    cmd.build();
    for sub in cmd.get_subcommands_mut() {
        if sub.is_hide_set() || sub.get_name() == "help" {
            continue;
        }
        let name = sub.get_name().to_string();
        let short = sub.render_help().to_string();
        let long = sub.render_long_help().to_string();
        // Options only: `-h`/`-V` are on every command.
        let count = |t: &str| {
            t.lines()
                .map(str::trim_start)
                .filter(|l| l.starts_with('-') && !l.starts_with("-h,") && !l.starts_with("-V,"))
                .count()
        };
        assert!(
            count(&short) <= 9,
            "{name} -h lists {} options:\n{short}",
            count(&short)
        );
        assert!(
            count(&long) > count(&short),
            "{name} --help must list more than -h"
        );
        assert!(
            short.contains("--json") && short.contains("--cwd"),
            "{name}"
        );
    }
    let scan = cmd.find_subcommand_mut("scan").expect("scan");
    let long = scan.render_long_help().to_string();
    assert!(
        !long.contains("--apply") && !long.contains("--vendor "),
        "{long}"
    );
}
