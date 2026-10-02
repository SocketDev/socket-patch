//! Gradle dependency-lock files.
//!
//! Gradle 6+ keeps one `gradle.lockfile` per project (plus
//! `buildscript-gradle.lockfile` and, from 7.x, `settings-gradle.lockfile`
//! for the build-logic classpaths), each line `group:name:version=conf,…`
//! and an `empty=` line naming configurations that resolved nothing. The
//! legacy (pre-6.0 format) layout keeps one file per configuration under
//! `gradle/dependency-locks/<conf>.lockfile`, each line a bare
//! `group:name:version`.
//!
//! Locks never filter scan; hosted mode rewrites the base version to the
//! suffixed one in every lock file, and discovery reports lock membership.

use super::{join_rel, ListFn};

/// Per-project lock file names.
pub const LOCKFILE_NAMES: &[&str] = &[
    "gradle.lockfile",
    "buildscript-gradle.lockfile",
    "settings-gradle.lockfile",
];

/// The legacy per-configuration lock directory, relative to a project.
pub const LEGACY_LOCK_DIR: &str = "gradle/dependency-locks";

/// Directories never searched for lock files.
const PRUNED: &[&str] = &["build", ".gradle", "node_modules", ".socket", ".git"];
/// How deep below the root the search goes.
const MAX_DEPTH: usize = 8;
/// A bound on directories listed, so a huge checkout cannot stall.
const MAX_DIRS: usize = 20_000;

/// Every lock file in the tree under `root` (in `list`'s path space, so
/// the results join `root`), whichever build it belongs to: the
/// per-project files and every legacy `gradle/dependency-locks/*.lockfile`.
/// `build/`, `.gradle/`, `node_modules/`, `.socket/` and `.git/` are not
/// searched, nor anything deeper than eight directories. Sorted.
///
/// This is an inventory (discovery, reports): it also finds the lock files
/// of nested builds the root build does not include (samples, test
/// fixtures). Anything that rewrites lock files for a build uses
/// [`lockfile_paths_in`] with that build's project directories
/// (`ScriptGraph::lockfile_paths`).
pub fn lockfile_paths(list: ListFn<'_>, root: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_string(), 0usize)];
    let mut listed = 0usize;
    while let Some((dir, depth)) = stack.pop() {
        listed += 1;
        if listed > MAX_DIRS {
            break;
        }
        for child in list(&dir) {
            if let Some(name) = child.strip_suffix('/') {
                if name.is_empty() || PRUNED.contains(&name) {
                    continue;
                }
                let sub = join_rel(&dir, name);
                if name == "gradle" {
                    let legacy = join_rel(&sub, "dependency-locks");
                    for f in list(&legacy) {
                        if !f.ends_with('/') && f.ends_with(".lockfile") {
                            out.push(join_rel(&legacy, &f));
                        }
                    }
                }
                if depth < MAX_DEPTH {
                    stack.push((sub, depth + 1));
                }
            } else if LOCKFILE_NAMES.contains(&child.as_str()) {
                out.push(join_rel(&dir, &child));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The lock files of the given project directories (in `list`'s path
/// space): each one's per-project files and its legacy
/// `gradle/dependency-locks/*.lockfile`. Sorted.
pub fn lockfile_paths_in(list: ListFn<'_>, project_dirs: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for dir in project_dirs {
        for child in list(dir) {
            if LOCKFILE_NAMES.contains(&child.as_str()) {
                out.push(join_rel(dir, &child));
            }
        }
        let legacy = join_rel(dir, LEGACY_LOCK_DIR);
        for f in list(&legacy) {
            if !f.ends_with('/') && f.ends_with(".lockfile") {
                out.push(join_rel(&legacy, &f));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// One locked module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockEntry {
    pub group: String,
    pub artifact: String,
    pub version: String,
    /// The configurations it is locked for; empty in a legacy file.
    pub confs: Vec<String>,
    /// 1-based line.
    pub line: usize,
}

/// The parsed content of one lock file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockState {
    pub entries: Vec<LockEntry>,
    /// Configurations named on the `empty=` line.
    pub empty_confs: Vec<String>,
    /// 1-based lines that are neither an entry, a comment nor `empty=`.
    pub malformed: Vec<usize>,
}

impl LockState {
    /// The entries for `group:artifact`.
    pub fn entries_of<'a>(
        &'a self,
        group: &'a str,
        artifact: &'a str,
    ) -> impl Iterator<Item = &'a LockEntry> + 'a {
        self.entries
            .iter()
            .filter(move |e| e.group == group && e.artifact == artifact)
    }
}

fn split_coords(coords: &str) -> Option<(&str, &str, &str)> {
    let mut it = coords.split(':');
    let (g, a, v) = (it.next()?, it.next()?, it.next()?);
    (it.next().is_none() && !g.is_empty() && !a.is_empty() && !v.is_empty()).then_some((g, a, v))
}

fn split_confs(confs: &str) -> Vec<String> {
    confs
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect()
}

/// Parse a lock file (either format; CRLF and a BOM are fine).
pub fn parse(text: &str) -> LockState {
    let mut state = LockState::default();
    for (idx, raw) in super::dsl::strip_bom(text).lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (coords, confs) = match line.split_once('=') {
            Some((c, rest)) => (c.trim(), Some(rest)),
            None => (line, None),
        };
        if coords == "empty" {
            state
                .empty_confs
                .extend(split_confs(confs.unwrap_or_default()));
            continue;
        }
        match split_coords(coords) {
            Some((g, a, v)) => state.entries.push(LockEntry {
                group: g.to_string(),
                artifact: a.to_string(),
                version: v.to_string(),
                confs: confs.map(split_confs).unwrap_or_default(),
                line: idx + 1,
            }),
            None => state.malformed.push(idx + 1),
        }
    }
    state
}

/// `line` without its terminator, and the terminator.
fn split_eol(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = line.strip_suffix('\n') {
        (body, "\n")
    } else {
        (line, "")
    }
}

/// The coordinates and the `=…` tail of an entry line.
fn entry_parts(body: &str) -> (&str, &str) {
    match body.find('=') {
        Some(i) => (&body[..i], &body[i..]),
        None => (body, ""),
    }
}

/// `text` with the entry `group:artifact:from_v` locked at `to_v` instead.
/// Each line keeps its own line ending and its configuration tail, and the
/// file keeps its final newline (or lack of one). When `to_v` is already
/// locked, the configurations of both lines merge into the `to_v` line and
/// the `from_v` line goes. `None` when `from_v` is not locked.
pub fn rewrite_entry(
    text: &str,
    group: &str,
    artifact: &str,
    from_v: &str,
    to_v: &str,
) -> Option<String> {
    let from = format!("{group}:{artifact}:{from_v}");
    let to = format!("{group}:{artifact}:{to_v}");
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let coord_of = |line: &str| entry_parts(split_eol(line).0).0.trim().to_string();
    if !lines.iter().any(|l| coord_of(l) == from) {
        return None;
    }
    let existing = lines.iter().position(|l| coord_of(l) == to);
    let mut out = String::with_capacity(text.len() + to_v.len());
    match existing {
        None => {
            for line in &lines {
                let (body, eol) = split_eol(line);
                let (coords, tail) = entry_parts(body);
                if coords.trim() == from {
                    let lead = &coords[..coords.len() - coords.trim_start().len()];
                    out.push_str(lead);
                    out.push_str(&to);
                    out.push_str(tail);
                    out.push_str(eol);
                } else {
                    out.push_str(line);
                }
            }
        }
        Some(keep) => {
            // Merge the configurations of every `from` line into `to`.
            let mut confs: Vec<String> = Vec::new();
            let mut any_tail = false;
            for line in &lines {
                let (body, _) = split_eol(line);
                let (coords, tail) = entry_parts(body);
                let c = coords.trim();
                if c == from || c == to {
                    if let Some(rest) = tail.strip_prefix('=') {
                        any_tail = true;
                        for conf in split_confs(rest) {
                            if !confs.contains(&conf) {
                                confs.push(conf);
                            }
                        }
                    }
                }
            }
            confs.sort();
            for (i, line) in lines.iter().enumerate() {
                let (body, eol) = split_eol(line);
                let c = entry_parts(body).0.trim().to_string();
                if c == from {
                    continue;
                }
                if i == keep {
                    out.push_str(&to);
                    if any_tail {
                        out.push('=');
                        out.push_str(&confs.join(","));
                    }
                    out.push_str(eol);
                } else {
                    out.push_str(line);
                }
            }
            // Dropping the last line must not drop the file's final newline.
            let last_eol = lines.last().map_or("", |l| split_eol(l).1);
            if !last_eol.is_empty() && !out.is_empty() && !out.ends_with('\n') {
                out.push_str(last_eol);
            }
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::super::test_fs::MemFs;
    use super::*;

    const SINGLE: &str = "\
# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.socketfixture:consumer:2.0=compileClasspath,runtimeClasspath
com.socketfixture:victim:1.10.0=compileClasspath,runtimeClasspath
empty=annotationProcessor,testAnnotationProcessor
";

    #[test]
    fn parses_single_file_format() {
        let s = parse(SINGLE);
        assert_eq!(s.entries.len(), 2);
        let v = &s.entries[1];
        assert_eq!(
            (v.group.as_str(), v.artifact.as_str(), v.version.as_str()),
            ("com.socketfixture", "victim", "1.10.0")
        );
        assert_eq!(v.confs, ["compileClasspath", "runtimeClasspath"]);
        assert_eq!(v.line, 5);
        assert_eq!(
            s.empty_confs,
            ["annotationProcessor", "testAnnotationProcessor"]
        );
        assert!(s.malformed.is_empty());
        assert_eq!(s.entries_of("com.socketfixture", "victim").count(), 1);
    }

    #[test]
    fn parses_legacy_buildscript_and_settings_files() {
        let legacy = "# comment\r\ncom.socketfixture:victim:1.10.0\r\norg.x:y:1\r\n";
        let s = parse(legacy);
        assert_eq!(s.entries.len(), 2);
        assert!(s.entries[0].confs.is_empty());
        let buildscript = "com.socketfixture:victim:1.10.0=classpath\nempty=\n";
        let s = parse(buildscript);
        assert_eq!(s.entries[0].confs, ["classpath"]);
        assert!(s.empty_confs.is_empty());
        let settings = "\u{feff}com.socketfixture:victim:1.10.0=incomingCatalogForLibs0\nempty=\n";
        assert_eq!(parse(settings).entries.len(), 1);
        let bad = "g:a\ng:a:1:x=c\n=x\n";
        assert_eq!(parse(bad).malformed, [1, 2, 3]);
    }

    #[test]
    fn rewrite_preserves_tail_and_eol() {
        let crlf = SINGLE.replace('\n', "\r\n");
        let out = rewrite_entry(
            &crlf,
            "com.socketfixture",
            "victim",
            "1.10.0",
            "1.10.0-socket.4d5e6f70",
        )
        .unwrap();
        assert_eq!(
            out,
            crlf.replace("victim:1.10.0=", "victim:1.10.0-socket.4d5e6f70=")
        );
        assert!(out.ends_with("testAnnotationProcessor\r\n"));
        assert_eq!(parse(&out).entries[1].version, "1.10.0-socket.4d5e6f70");

        // No final newline stays that way; legacy bare entries rewrite too.
        let bare = "com.socketfixture:victim:1.10.0";
        assert_eq!(
            rewrite_entry(
                bare,
                "com.socketfixture",
                "victim",
                "1.10.0",
                "1.10.0-socket.1"
            )
            .unwrap(),
            "com.socketfixture:victim:1.10.0-socket.1"
        );
        // Prefix matches are not entries.
        assert_eq!(
            rewrite_entry(SINGLE, "com.socketfixture", "victim", "1.10", "x"),
            None
        );
        assert_eq!(
            rewrite_entry(SINGLE, "com.socketfixture", "victi", "1.10.0", "x"),
            None
        );
    }

    #[test]
    fn rewrite_merges_into_an_existing_target() {
        let text = "g:a:1.0-socket.1=compileClasspath\ng:a:1.0=runtimeClasspath,compileClasspath\nempty=\n";
        let out = rewrite_entry(text, "g", "a", "1.0", "1.0-socket.1").unwrap();
        assert_eq!(
            out,
            "g:a:1.0-socket.1=compileClasspath,runtimeClasspath\nempty=\n"
        );
        let text = "g:a:1.0-socket.1\r\ng:a:1.0\r\n";
        assert_eq!(
            rewrite_entry(text, "g", "a", "1.0", "1.0-socket.1").unwrap(),
            "g:a:1.0-socket.1\r\n"
        );
    }

    #[test]
    fn lists_every_lockfile_location() {
        let fs = MemFs::new(&[
            ("settings.gradle", ""),
            ("gradle.lockfile", ""),
            ("buildscript-gradle.lockfile", ""),
            ("settings-gradle.lockfile", ""),
            ("app/gradle.lockfile", ""),
            ("libs/core/gradle.lockfile", ""),
            ("buildSrc/gradle.lockfile", ""),
            ("buildSrc/buildscript-gradle.lockfile", ""),
            ("build-logic/gradle.lockfile", ""),
            ("build-logic/convention/gradle.lockfile", ""),
            ("gradle/dependency-locks/compileClasspath.lockfile", ""),
            ("gradle/dependency-locks/readme.txt", ""),
            ("app/gradle/dependency-locks/runtimeClasspath.lockfile", ""),
            ("build/gradle.lockfile", ""),
            ("app/build/gradle.lockfile", ""),
            (".gradle/gradle.lockfile", ""),
            ("node_modules/x/gradle.lockfile", ""),
            (".socket/gradle.lockfile", ""),
            (".git/gradle.lockfile", ""),
            ("a/b/c/d/e/f/g/h/gradle.lockfile", ""),
            ("a/b/c/d/e/f/g/h/i/gradle.lockfile", ""),
            ("other.lockfile", ""),
        ]);
        let got = lockfile_paths(&|d: &str| fs.list(d), "");
        assert_eq!(
            got,
            [
                "a/b/c/d/e/f/g/h/gradle.lockfile",
                "app/gradle.lockfile",
                "app/gradle/dependency-locks/runtimeClasspath.lockfile",
                "build-logic/convention/gradle.lockfile",
                "build-logic/gradle.lockfile",
                "buildSrc/buildscript-gradle.lockfile",
                "buildSrc/gradle.lockfile",
                "buildscript-gradle.lockfile",
                "gradle.lockfile",
                "gradle/dependency-locks/compileClasspath.lockfile",
                "libs/core/gradle.lockfile",
                "settings-gradle.lockfile",
            ]
        );
        // A sub-root keeps its prefix.
        let fs = MemFs::new(&[("w/gradle.lockfile", ""), ("w/x/gradle.lockfile", "")]);
        assert_eq!(
            lockfile_paths(&|d: &str| fs.list(d), "w"),
            ["w/gradle.lockfile", "w/x/gradle.lockfile"]
        );
    }
}
