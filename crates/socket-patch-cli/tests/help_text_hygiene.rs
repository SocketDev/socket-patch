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
        let path: Vec<&str> = if name.is_empty() { vec![] } else { vec![name.as_str()] };
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
        text.contains("Roll back patches to restore original files"),
        "{text}"
    );
    assert!(!text.contains("Rollback patches"), "{text}");
    assert!(
        text.contains("Wire install hooks (npm, Python, Bundler, Composer)"),
        "{text}"
    );
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
            == "  repair    Download missing patch artifacts and clean up unused ones [aliases: gc]"),
        "{text}"
    );
    let repair = long_help(&["repair"]);
    assert!(
        repair.starts_with(
            "Download missing patch artifacts and clean up unused ones\n\n\
             Restores missing blobs and diff/package archives, rebuilds missing or corrupt \
             vendored artifacts, then deletes the artifacts nothing references. It needs no \
             scan; for the combined workflow (discover, apply, clean up) use \
             `scan --sync --json --yes`.\n"
        ),
        "{repair}"
    );
}
