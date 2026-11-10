//! Architecture guard: child processes are made and bounded in
//! `utils::process`.
//!
//! `utils::process::output_within` is the one bounded spawn: it nulls stdin
//! and stderr, kills and reaps the child at the deadline, and never waits on
//! a grandchild that still holds the pipe. A production `kill_on_drop` spawn
//! (a `tokio::time::timeout` around a child) is a second deadline policy that
//! drifts from it (#845, #1067).
//!
//! `utils::process::command_for` is the one place a `Command` is made: it
//! takes the Socket credentials out of the child's environment. A production
//! `Command::new` elsewhere hands the ambient `SOCKET_API_TOKEN` to whatever
//! it runs.

use std::path::{Path, PathBuf};

/// Production files that still keep a hand-rolled deadline, relative to
/// `src/`. Migrate a file, then drop it here: a stale entry fails too.
const PENDING: &[&str] = &["vendor/npm_dir.rs"];

/// The production part of a source file: everything above its first
/// `#[cfg(test)]` module.
fn production(source: &str) -> &str {
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        if line.trim() == "#[cfg(test)]" {
            let next = source[offset + line.len()..].trim_start();
            if next.starts_with("mod ") || next.starts_with("pub(crate) mod ") {
                return &source[..offset];
            }
        }
        offset += line.len();
    }
    source
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Files under `src` whose production code spawns a `kill_on_drop` child.
fn hand_rolled_deadlines(src: &Path) -> Vec<String> {
    production_files_with(src, |production| production.contains("kill_on_drop("))
}

/// Files under `src` whose production code makes a `Command` itself: a
/// `Command::new(` outside a comment, in a file that is not a test-only
/// module ([`test_only_modules`]).
fn hand_made_commands(src: &Path) -> Vec<String> {
    let test_only = test_only_modules(src);
    production_files_with(src, |production| {
        production
            .lines()
            .any(|line| !line.trim_start().starts_with("//") && line.contains("Command::new("))
    })
    .into_iter()
    .filter(|relative| {
        !test_only.iter().any(|module| {
            relative == &format!("{module}.rs") || relative.starts_with(&format!("{module}/"))
        })
    })
    .collect()
}

/// The modules under `src` declared in a file of their own behind
/// `#[cfg(test)]` or `#[cfg(any(test, ..))]` (test support the
/// `test-fixtures` feature also exports), as paths relative to `src`
/// without the `.rs`.
fn test_only_modules(src: &Path) -> Vec<String> {
    let mut files = Vec::new();
    rust_files(src, &mut files);
    let mut modules = Vec::new();
    for path in &files {
        let source = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
        let lines: Vec<&str> = source.lines().map(str::trim).collect();
        // `a/mod.rs` and `lib.rs` declare modules beside themselves, `a.rs`
        // under `a/`.
        let stem = path.file_stem().unwrap().to_string_lossy();
        let parent = path.parent().unwrap().strip_prefix(src).unwrap();
        let dir = if matches!(stem.as_ref(), "mod" | "lib" | "main") {
            parent.to_path_buf()
        } else {
            parent.join(stem.as_ref())
        };
        for (at, line) in lines.iter().enumerate() {
            let declared = ["pub(crate) mod ", "pub mod ", "mod "]
                .iter()
                .find_map(|keyword| line.strip_prefix(keyword))
                .and_then(|rest| rest.strip_suffix(';'));
            let Some(name) = declared else {
                continue;
            };
            let behind_test_cfg = lines[..at]
                .iter()
                .rev()
                .take_while(|attr| attr.starts_with("#["))
                .any(|attr| *attr == "#[cfg(test)]" || attr.starts_with("#[cfg(any(test,"));
            if behind_test_cfg {
                modules.push(dir.join(name).to_string_lossy().replace('\\', "/"));
            }
        }
    }
    modules
}

/// Files under `src`, other than `utils/process.rs`, whose production code
/// `matches`.
fn production_files_with(src: &Path, matches: impl Fn(&str) -> bool) -> Vec<String> {
    let mut files = Vec::new();
    rust_files(src, &mut files);
    let mut found: Vec<String> = files
        .iter()
        .filter(|path| {
            let source = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
            matches(production(&source))
        })
        .map(|path| {
            path.strip_prefix(src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .filter(|relative| relative != "utils/process.rs")
        .collect();
    found.sort();
    found
}

#[test]
fn child_deadlines_go_through_utils_process() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let found = hand_rolled_deadlines(&src);
    let new: Vec<_> = found
        .iter()
        .filter(|file| !PENDING.contains(&file.as_str()))
        .collect();
    assert!(
        new.is_empty(),
        "spawn these children through utils::process::output_within, not a \
         local kill_on_drop deadline: {new:?}"
    );
    let stale: Vec<_> = PENDING
        .iter()
        .filter(|file| !found.iter().any(|found| found == *file))
        .collect();
    assert!(
        stale.is_empty(),
        "these files no longer keep a local deadline; drop them from PENDING: {stale:?}"
    );
}

#[test]
fn child_commands_are_made_by_utils_process() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let found = hand_made_commands(&src);
    assert!(
        found.is_empty(),
        "make these commands with utils::process::command_for, which keeps the Socket \
         credentials out of the child's environment, not Command::new: {found:?}"
    );
}

#[test]
fn the_guard_sees_a_planted_site_and_ignores_test_modules() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path();
    std::fs::create_dir_all(src.join("utils")).unwrap();
    std::fs::create_dir_all(src.join("crawlers")).unwrap();
    let spawn = "fn probe() { tokio::process::Command::new(\"x\").kill_on_drop(true); }\n";
    std::fs::write(src.join("utils/process.rs"), spawn).unwrap();
    std::fs::write(src.join("crawlers/planted.rs"), spawn).unwrap();
    std::fs::write(
        src.join("crawlers/tested.rs"),
        format!("fn probe() {{}}\n\n#[cfg(test)]\nmod tests {{\n    {spawn}}}\n"),
    )
    .unwrap();
    std::fs::write(
        src.join("crawlers/crlf.rs"),
        format!("fn a() {{}}\r\n#[cfg(test)]\r\nmod tests {{}}\r\n{spawn}"),
    )
    .unwrap();
    assert_eq!(hand_rolled_deadlines(src), ["crawlers/planted.rs"]);

    // A comment naming `Command::new(` and a test-only module file are not
    // production commands.
    std::fs::write(
        src.join("crawlers/commented.rs"),
        "/// Never a bare `Command::new(\"hatch\")`.\nfn probe() {}\n",
    )
    .unwrap();
    std::fs::write(
        src.join("crawlers/mod.rs"),
        "mod planted;\n#[cfg(test)]\npub(crate) mod support;\n\
         #[cfg(any(test, feature = \"test-fixtures\"))]\n#[doc(hidden)]\npub mod fixtures;\n",
    )
    .unwrap();
    std::fs::write(src.join("crawlers/support.rs"), spawn).unwrap();
    std::fs::write(src.join("crawlers/fixtures.rs"), spawn).unwrap();
    assert_eq!(hand_made_commands(src), ["crawlers/planted.rs"]);
}
