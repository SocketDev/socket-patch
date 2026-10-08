//! A pure model of a Gradle build, shared by discovery, agent, vendored and
//! hosted mode.
//!
//! Nothing here touches the filesystem, the process environment or the
//! network. Project files come in through a [`TextReadFn`] and directory
//! listings through a [`ListFn`]; environment variables through an [`Env`].
//! The filesystem and process-env adapters live with their callers
//! (`crawlers::gradle_cache`), so every function here is testable against
//! in-memory fixtures on every OS.
//!
//! - [`dsl`]: a comment- and string-aware Groovy/Kotlin tokenizer.
//! - [`graph`]: the script graph of a checkout (settings, build scripts,
//!   `buildSrc`, included builds, convention plugins, `apply from` targets,
//!   the version catalog, init scripts) and the queries over it.
//! - [`locks`]: dependency-lock files: where they are, what they hold and a
//!   one-entry rewrite.
//! - [`home`]: the Gradle user home and the caches inside it.
//! - [`eol`]: line-ending sniffing and line-ending-blind comparison.
//! - [`selector`]: Gradle version ordering and version selectors.

pub mod dsl;
pub mod eol;
pub mod graph;
pub mod home;
pub mod locks;
pub mod selector;

use std::collections::{BTreeMap, HashMap};

/// Reads a forward-slash path (relative to the root the caller chose) as
/// text. `None` = missing or unreadable. Adapters strip a UTF-8 BOM and
/// return `None` for bytes that are not UTF-8; text is never decoded
/// lossily (see [`dsl::decode`]).
pub type TextReadFn<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Lists the children of a forward-slash directory path (`""` = the root):
/// bare names, with directories ending in `/`. A missing directory lists
/// as empty.
pub type ListFn<'a> = &'a dyn Fn(&str) -> Vec<String>;

/// Environment variable lookup.
pub trait Env {
    fn var(&self, k: &str) -> Option<String>;
}

impl Env for HashMap<String, String> {
    fn var(&self, k: &str) -> Option<String> {
        self.get(k).cloned()
    }
}

impl Env for BTreeMap<String, String> {
    fn var(&self, k: &str) -> Option<String> {
        self.get(k).cloned()
    }
}

impl Env for [(&str, &str)] {
    fn var(&self, k: &str) -> Option<String> {
        self.iter()
            .rev()
            .find(|(name, _)| *name == k)
            .map(|(_, v)| v.to_string())
    }
}

/// The host family a path or environment convention belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    Windows,
    Unix,
}

impl Os {
    /// The OS this binary runs on.
    pub fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

/// `dir` joined with `name` in forward-slash form (`""` is the root).
pub(crate) fn join_rel(dir: &str, name: &str) -> String {
    match (dir.is_empty(), name.is_empty()) {
        (true, _) => name.to_string(),
        (_, true) => dir.to_string(),
        _ => format!("{}/{name}", dir.trim_end_matches('/')),
    }
}

/// The directory part of a forward-slash path (`""` for a root-level file).
pub(crate) fn parent_rel(rel: &str) -> &str {
    rel.rfind('/').map_or("", |i| &rel[..i])
}

/// `base` joined with the relative path `p`, normalised. `None` when `p`
/// is absolute (POSIX, drive, UNC or a URL), uses backslashes, or climbs
/// above `floor` (a prefix directory of `base`, `""` = the read root).
pub(crate) fn resolve_rel(floor: &str, base: &str, p: &str) -> Option<String> {
    if p.is_empty()
        || p.starts_with('/')
        || p.contains('\\')
        || p.contains(':')
        || p.starts_with('~')
    {
        return None;
    }
    let floor_len = floor.split('/').filter(|s| !s.is_empty()).count();
    crate::utils::relpath::resolve_rel(base, p, floor_len)
}

/// 1-based line number of byte offset `at` in `text`.
pub(crate) fn line_of(text: &str, at: usize) -> usize {
    1 + text.as_bytes()[..at.min(text.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
}

#[cfg(test)]
pub(crate) mod test_fs {
    //! An in-memory tree behind [`TextReadFn`] / [`ListFn`] for the tests.

    use std::collections::BTreeMap;

    #[derive(Default)]
    pub struct MemFs {
        pub files: BTreeMap<String, String>,
    }

    impl MemFs {
        pub fn new(files: &[(&str, &str)]) -> Self {
            Self {
                files: files
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }
        }

        pub fn read(&self, rel: &str) -> Option<String> {
            self.files.get(rel).cloned()
        }

        pub fn list(&self, dir: &str) -> Vec<String> {
            let prefix = if dir.is_empty() {
                String::new()
            } else {
                format!("{}/", dir.trim_end_matches('/'))
            };
            let mut out: Vec<String> = Vec::new();
            for key in self.files.keys() {
                let Some(rest) = key.strip_prefix(&prefix) else {
                    continue;
                };
                let child = match rest.find('/') {
                    Some(i) => format!("{}/", &rest[..i]),
                    None => rest.to_string(),
                };
                if !out.contains(&child) {
                    out.push(child);
                }
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rel_normalises_and_rejects_escapes() {
        assert_eq!(
            resolve_rel("", "a/b", "../c.gradle").as_deref(),
            Some("a/c.gradle")
        );
        assert_eq!(resolve_rel("", "", "./x/./y").as_deref(), Some("x/y"));
        assert_eq!(resolve_rel("", "a", "../.."), None);
        assert_eq!(resolve_rel("root", "root/a", "../../x"), None);
        assert_eq!(resolve_rel("", "", "/etc/x"), None);
        assert_eq!(resolve_rel("", "", "C:/x"), None);
        assert_eq!(resolve_rel("", "", "a\\b"), None);
        assert_eq!(resolve_rel("", "", "https://h/x.gradle"), None);
        assert_eq!(resolve_rel("", "", "~/x"), None);
    }

    #[test]
    fn env_slice_last_wins() {
        let env: &[(&str, &str)] = &[("A", "1"), ("A", "2")];
        assert_eq!(env.var("A").as_deref(), Some("2"));
        assert_eq!(env.var("B"), None);
    }

    /// The module stays pure: no filesystem, process-environment or
    /// network access in any of its files (adapters live with callers).
    #[test]
    fn module_uses_no_fs_env_or_network() {
        let sources = [
            ("mod.rs", include_str!("mod.rs")),
            ("dsl.rs", include_str!("dsl.rs")),
            ("eol.rs", include_str!("eol.rs")),
            ("graph.rs", include_str!("graph.rs")),
            ("home.rs", include_str!("home.rs")),
            ("locks.rs", include_str!("locks.rs")),
            ("selector.rs", include_str!("selector.rs")),
        ];
        // Spelled in pieces so this test does not match itself.
        let banned = [
            ["std", "::fs"].concat(),
            ["std", "::env"].concat(),
            ["std", "::net"].concat(),
            ["std", "::process"].concat(),
            ["tokio", "::fs"].concat(),
            ["reqwest", "::"].concat(),
            ["use std", "::{"].concat(),
        ];
        for (name, src) in sources {
            for needle in &banned {
                assert!(
                    !src.contains(needle.as_str()),
                    "gradle/{name} uses {needle}"
                );
            }
        }
    }

    #[test]
    fn line_of_counts_newlines() {
        assert_eq!(line_of("a\nb\r\nc", 0), 1);
        assert_eq!(line_of("a\nb\r\nc", 2), 2);
        assert_eq!(line_of("a\nb\r\nc", 5), 3);
    }
}
