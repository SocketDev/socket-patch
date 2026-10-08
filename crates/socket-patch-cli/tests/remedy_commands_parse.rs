//! Every command a user-facing remedy prescribes must be one the CLI
//! actually accepts (B80).
//!
//! Scans the production string literals of the CLI and core crates for
//! backticked commands (`` `socket-patch vendor --revert` ``, or the bare
//! `` `scan --mode hosted` `` form) and parses each one with the real clap
//! definition. A remedy that names a retired subcommand, a misspelled flag
//! or a per-package argument a command does not take fails here instead
//! of in front of a user.
//!
//! The separate prose check catches the one wrong shape argv parsing
//! cannot: `vendor --revert` takes no package argument, so "run
//! `vendor --revert` for <purl>" promises a per-package undo that does
//! not exist.

use std::path::{Path, PathBuf};

use regex::Regex;

/// Subcommands (and their visible aliases) a remedy may name.
const SUBCOMMANDS: &str = "scan|get|download|list|remove|rollback|vex|vendor|apply|repair|gc";

fn crate_src(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .join(name)
        .join("src")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The production text of a source file: everything before its
/// `#[cfg(test)] mod …` test module, minus `//` comment lines, with Rust's
/// `\`-newline string continuations joined the way the compiler joins
/// them. A `#[cfg(test)]` on a single item (a test-only helper) does not
/// end the production text.
fn production_text(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    if name.contains("test") {
        return None;
    }
    let src = std::fs::read_to_string(path).expect("read source");
    let all: Vec<&str> = src.lines().collect();
    let mut lines = Vec::new();
    for (i, line) in all.iter().enumerate() {
        let trimmed = line.trim_start();
        let opens_test_module = trimmed.starts_with("#[cfg(test)]")
            && all[i + 1..]
                .iter()
                .map(|l| l.trim_start())
                .find(|l| !l.is_empty() && !l.starts_with("#["))
                .is_some_and(|l| l.starts_with("mod ") || l.starts_with("pub(crate) mod "));
        if opens_test_module {
            break;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        lines.push(*line);
    }
    let joined = lines.join("\n");
    Some(
        Regex::new(r"\\\n\s*")
            .expect("continuation regex")
            .replace_all(&joined, "")
            .into_owned(),
    )
}

/// `(file, command)` for every backticked remedy command in production
/// code.
fn remedy_commands() -> Vec<(String, String)> {
    let mut files = Vec::new();
    rust_files(&crate_src("socket-patch-core"), &mut files);
    rust_files(&crate_src("socket-patch-cli"), &mut files);
    files.sort();
    // `socket-patch <anything>` is a full command line, retired names
    // included; a bare `<subcommand> <args>` span is one too, but a bare
    // name alone (`` `get` ``) is prose naming the command, not a remedy.
    let span = Regex::new(&format!(
        r"`(?:socket-patch ([a-z-][^`\n]*)|((?:{SUBCOMMANDS}) [^`\n]+))`"
    ))
    .expect("span regex");
    let mut out = Vec::new();
    for file in files {
        let Some(text) = production_text(&file) else {
            continue;
        };
        for cap in span.captures_iter(&text) {
            let command = cap.get(1).or_else(|| cap.get(2)).expect("one arm matched");
            out.push((file.display().to_string(), command.as_str().to_string()));
        }
    }
    out
}

/// The argv a remedy stands for: format arguments (`{purl}`, `{}`) and
/// placeholders (`<purl>`) become one concrete token.
fn argv_of(command: &str) -> Vec<String> {
    let placeholder = Regex::new(r"\{[^}]*\}|<[^>]*>").expect("placeholder regex");
    let concrete = placeholder.replace_all(command, "pkg:npm/x@1.0.0");
    std::iter::once("socket-patch".to_string())
        .chain(concrete.split_whitespace().map(str::to_string))
        .collect()
}

#[test]
fn every_remedy_command_parses_with_the_real_cli() {
    let commands = remedy_commands();
    assert!(
        commands.len() > 50,
        "the scan must find the remedy corpus (found {}); did the source layout move?",
        commands.len()
    );
    let mut failures = Vec::new();
    for (file, command) in &commands {
        let argv = argv_of(command);
        if let Err(err) = socket_patch_cli::parse_argv_with_shortcuts(argv.clone()) {
            // `--help` / `--version` are display requests, not failures,
            // and prose that names a command without its required operand
            // (`` `socket-patch get` `` first) leaves the user to fill it
            // in. Everything else — an unknown subcommand or flag, a bad
            // value, an operand the command does not take — is a remedy
            // the CLI would reject.
            let incomplete = err.kind() == clap::error::ErrorKind::MissingRequiredArgument;
            if err.use_stderr() && !incomplete {
                failures.push(format!("{file}: `{command}` -> {}", err.kind()));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "remedies prescribe commands the CLI rejects:\n{}",
        failures.join("\n")
    );
}

#[test]
fn no_remedy_promises_a_per_package_vendor_revert() {
    let per_package = Regex::new(r"vendor --revert` for ").expect("prose regex");
    let mut files = Vec::new();
    rust_files(&crate_src("socket-patch-core"), &mut files);
    rust_files(&crate_src("socket-patch-cli"), &mut files);
    let offenders: Vec<String> = files
        .iter()
        .filter_map(|f| {
            let text = production_text(f)?;
            per_package.is_match(&text).then(|| f.display().to_string())
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "`vendor --revert` takes no package argument; these remedies imply one:\n{}",
        offenders.join("\n")
    );
}
