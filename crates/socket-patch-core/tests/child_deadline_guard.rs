//! Architecture guard: child-process deadlines live in `utils::process`.
//!
//! `utils::process::output_within` is the one bounded spawn: it nulls stdin
//! and stderr, kills and reaps the child at the deadline, and never waits on
//! a grandchild that still holds the pipe. A production `kill_on_drop` spawn
//! (a `tokio::time::timeout` around a child) is a second deadline policy that
//! drifts from it (#845, #1067).

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
    let mut files = Vec::new();
    rust_files(src, &mut files);
    let mut found: Vec<String> = files
        .iter()
        .filter(|path| {
            let source = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
            production(&source).contains("kill_on_drop(")
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
}
