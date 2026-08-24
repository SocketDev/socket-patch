//! Path-glob scoping shared by `scan` and `rollback`.
//!
//! A [`PathScope`] holds the user's positional PATH patterns and answers
//! "is this installed-package directory in scope?". Matching rules
//! (documented in CLI_CONTRACT.md):
//!
//! * Patterns use Unix-shell glob syntax (`*`, `?`, `[...]`, `**`) with
//!   `require_literal_separator` — `*` never crosses a `/`, `**` spans
//!   directories.
//! * Relative patterns match the package path relative to `--cwd`;
//!   absolute patterns match the absolute path (the only way to scope
//!   packages outside the project tree, e.g. `--global` stores).
//! * A pattern that matches any ANCESTOR directory of the package path
//!   also matches, so `scan packages/foo` scopes the whole subtree
//!   without needing an explicit `packages/foo/**`.
//! * Matching is purely textual on `/`-normalized paths — no filesystem
//!   access, no symlink resolution.
//!
//! Scoping is PURL-level at the call sites: a package is in scope when
//! any of its discovered copies matches, and scoped operations then act
//! on every copy of the selected package.

use glob::{MatchOptions, Pattern};
use std::path::Path;

/// `*` and `?` stay within one path component; `**` is the only way to
/// cross directories. Case-sensitive on Unix; case-insensitive on Windows,
/// whose filesystems are case-insensitive (a drive-letter case mismatch
/// must not silently empty a scope).
const MATCH_OPTIONS: MatchOptions = MatchOptions {
    case_sensitive: cfg!(not(windows)),
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// Parsed positional PATH patterns.
#[derive(Debug)]
pub struct PathScope {
    patterns: Vec<(Pattern, bool)>, // (compiled, is_absolute)
    raw: Vec<String>,
}

/// Normalize a pattern for matching: strip a leading `./`, trailing `/`s,
/// and convert `\` to `/` so Windows-style input still compiles to the
/// separator the match side uses.
fn normalize_pattern(raw: &str) -> String {
    let mut p = raw.replace('\\', "/");
    while let Some(stripped) = p.strip_prefix("./") {
        p = stripped.to_string();
    }
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

/// `/`-normalized string form of a path for textual glob matching.
fn slashed(path: &Path) -> String {
    let s = path.to_string_lossy();
    if std::path::MAIN_SEPARATOR == '/' {
        s.into_owned()
    } else {
        s.replace(std::path::MAIN_SEPARATOR, "/")
    }
}

impl PathScope {
    /// Compile the user's patterns. An unparseable glob is a usage error —
    /// the caller maps `Err` to exit 2 like any other invalid argument.
    pub fn parse(raw_patterns: &[String]) -> Result<Self, String> {
        let mut patterns = Vec::with_capacity(raw_patterns.len());
        let mut raw = Vec::with_capacity(raw_patterns.len());
        for r in raw_patterns {
            let normalized = normalize_pattern(r);
            if normalized.is_empty() {
                return Err(format!("invalid path pattern {r:?}: empty pattern"));
            }
            let compiled = Pattern::new(&normalized)
                .map_err(|e| format!("invalid path pattern {r:?}: {e}"))?;
            let is_absolute = Path::new(&normalized).is_absolute();
            patterns.push((compiled, is_absolute));
            raw.push(r.clone());
        }
        Ok(Self { patterns, raw })
    }

    /// No patterns given — scoping is inactive and every path matches.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// The patterns exactly as the user typed them (for envelopes/errors).
    pub fn raw(&self) -> &[String] {
        &self.raw
    }

    /// Is `candidate` (an absolute package directory from a crawler) in
    /// scope? An empty scope matches everything.
    pub fn matches(&self, cwd: &Path, candidate: &Path) -> bool {
        if self.patterns.is_empty() {
            return true;
        }
        // Textual prefix-strip against the absolutized cwd; crawler paths
        // are already absolute, so this stays a pure string operation.
        let abs_cwd = std::path::absolute(cwd).unwrap_or_else(|_| cwd.to_path_buf());
        let abs = slashed(candidate);
        let rel = candidate
            .strip_prefix(&abs_cwd)
            .ok()
            .or_else(|| candidate.strip_prefix(cwd).ok())
            .map(slashed);
        self.patterns.iter().any(|(pattern, is_absolute)| {
            let target = if *is_absolute {
                Some(abs.as_str())
            } else {
                rel.as_deref()
            };
            match target {
                Some(t) => matches_path_or_ancestor(pattern, t),
                // A relative pattern can never match a path outside cwd.
                None => false,
            }
        })
    }
}

/// True when `pattern` matches `path` or any of its ancestor prefixes
/// (successively dropping trailing `/`-components), so a plain directory
/// pattern scopes its whole subtree.
fn matches_path_or_ancestor(pattern: &Pattern, path: &str) -> bool {
    let mut current = path;
    loop {
        if pattern.matches_with(current, MATCH_OPTIONS) {
            return true;
        }
        match current.rfind('/') {
            // Root ancestor of an absolute path is "/" — test it too, then stop.
            Some(0) if current.len() > 1 => current = "/",
            Some(idx) => current = &current[..idx],
            None => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scope(patterns: &[&str]) -> PathScope {
        PathScope::parse(&patterns.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("test patterns are valid")
    }

    fn cwd() -> PathBuf {
        PathBuf::from("/proj")
    }

    #[test]
    fn empty_scope_matches_everything() {
        let s = scope(&[]);
        assert!(s.is_empty());
        assert!(s.matches(&cwd(), Path::new("/anywhere/at/all")));
    }

    #[test]
    fn exact_relative_path_matches() {
        let s = scope(&["node_modules/lodash"]);
        assert!(s.matches(&cwd(), Path::new("/proj/node_modules/lodash")));
        assert!(!s.matches(&cwd(), Path::new("/proj/node_modules/left-pad")));
    }

    #[test]
    fn directory_pattern_scopes_its_subtree() {
        // No `/**` needed: matching an ancestor is enough.
        let s = scope(&["packages/foo"]);
        assert!(s.matches(
            &cwd(),
            Path::new("/proj/packages/foo/node_modules/lodash")
        ));
        assert!(!s.matches(
            &cwd(),
            Path::new("/proj/packages/bar/node_modules/lodash")
        ));
    }

    #[test]
    fn star_does_not_cross_separators() {
        let s = scope(&["packages/*"]);
        // `packages/*` matches the ancestor `packages/foo`, scoping its tree…
        assert!(s.matches(
            &cwd(),
            Path::new("/proj/packages/foo/node_modules/lodash")
        ));
        // …but `nested/*` must not match a deeper path component-wise.
        let s2 = scope(&["*"]);
        assert!(s2.matches(&cwd(), Path::new("/proj/anything")));
        let s3 = scope(&["src/*.js"]);
        assert!(!s3.matches(&cwd(), Path::new("/proj/src/deep/file.js")));
    }

    #[test]
    fn double_star_spans_directories() {
        let s = scope(&["packages/**/lodash"]);
        assert!(s.matches(
            &cwd(),
            Path::new("/proj/packages/foo/node_modules/lodash")
        ));
        assert!(!s.matches(&cwd(), Path::new("/proj/apps/foo/node_modules/lodash")));
    }

    #[test]
    fn absolute_pattern_matches_paths_outside_cwd() {
        let s = scope(&["/global/store"]);
        assert!(s.matches(&cwd(), Path::new("/global/store/lib/node_modules/x")));
        assert!(!s.matches(&cwd(), Path::new("/other/store/lib")));
    }

    #[test]
    fn relative_pattern_never_matches_outside_cwd() {
        let s = scope(&["store"]);
        assert!(!s.matches(&cwd(), Path::new("/global/store")));
    }

    #[test]
    fn leading_dot_slash_and_trailing_slash_are_normalized() {
        let s = scope(&["./packages/foo/"]);
        assert!(s.matches(&cwd(), Path::new("/proj/packages/foo/nested")));
    }

    #[test]
    fn invalid_pattern_is_a_parse_error() {
        let err = PathScope::parse(&["packages/[".to_string()]).unwrap_err();
        assert!(err.contains("invalid path pattern"), "{err}");
        let err = PathScope::parse(&["".to_string()]).unwrap_err();
        assert!(err.contains("empty pattern"), "{err}");
    }

    #[test]
    fn case_is_sensitive_on_every_platform() {
        let s = scope(&["Packages/foo"]);
        assert!(!s.matches(&cwd(), Path::new("/proj/packages/foo/x")));
    }

    #[test]
    fn matching_is_purely_textual() {
        // Paths that do not exist on disk still match — no fs access.
        let s = scope(&["no/such/dir"]);
        assert!(s.matches(&cwd(), Path::new("/proj/no/such/dir/pkg")));
    }
}
