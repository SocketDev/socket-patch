//! Path lists of the `socket.yml` patch policy: gitignore patterns matched
//! the way the npm `ignore` package (the backend's `projectIgnorePaths`
//! matcher) matches them.
//!
//! Evaluation walks top-down: for `a/b/c.lock` the matcher tests `a/`,
//! then `a/b/`, then the file, and the first ignored ancestor decides. A
//! negation can therefore never re-include anything under an ignored
//! directory, as in git and npm `ignore`. `ignore::gitignore`'s
//! `matched_path_or_any_parents` walks bottom-up and would re-include, so
//! it is not used.

use std::path::PathBuf;

use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::Match;

/// Longest accepted pattern, in bytes.
pub(crate) const MAX_PATTERN_BYTES: usize = 1024;

/// Why a pattern is refused before it reaches the glob compiler.
pub(crate) fn pattern_hygiene_error(pattern: &str) -> Option<String> {
    if pattern.len() > MAX_PATTERN_BYTES {
        return Some(format!("pattern is longer than {MAX_PATTERN_BYTES} bytes"));
    }
    if pattern.contains('\0') {
        return Some("pattern contains a NUL byte".to_string());
    }
    if pattern.trim().is_empty() {
        return Some("pattern is empty".to_string());
    }
    let body = pattern.strip_prefix('!').unwrap_or(pattern);
    let body_no_slash = body.strip_prefix('/').unwrap_or(body);
    let bytes = body_no_slash.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Some("pattern starts with a drive letter; paths are repo-relative".to_string());
    }
    if body.split('/').any(|segment| segment == "..") {
        return Some("pattern contains a `..` segment; paths are repo-relative".to_string());
    }
    None
}

/// One compiled, ordered pattern list (several named source lists joined;
/// the last matching pattern wins within a path).
#[derive(Clone, Debug)]
pub(crate) struct PathMatcher {
    gitignore: Gitignore,
    list_names: Vec<&'static str>,
}

/// The pattern that decided a path, and the list it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathHit {
    pub pattern: String,
    pub list: &'static str,
}

impl PathMatcher {
    /// Compile `lists` in order. The error names the list and the pattern.
    pub(crate) fn new(
        lists: &[(&'static str, &[String])],
    ) -> Result<Self, (&'static str, String, String)> {
        let mut builder = GitignoreBuilder::new("");
        // Never fails in ignore 0.4 (the Result is historical).
        let _ = builder.case_insensitive(true);
        builder.allow_unclosed_class(false);
        let mut list_names = Vec::with_capacity(lists.len());
        for (name, patterns) in lists {
            list_names.push(*name);
            for pattern in patterns.iter() {
                if let Some(message) = pattern_hygiene_error(pattern) {
                    return Err((name, pattern.clone(), message));
                }
                if let Err(e) = builder.add_line(Some(PathBuf::from(*name)), pattern) {
                    return Err((name, pattern.clone(), format!("invalid pattern: {e}")));
                }
            }
        }
        let gitignore = builder.build().map_err(|e| {
            (
                lists.last().map_or("", |l| l.0),
                String::new(),
                e.to_string(),
            )
        })?;
        Ok(Self {
            gitignore,
            list_names,
        })
    }

    fn hit(&self, glob: &ignore::gitignore::Glob) -> PathHit {
        let list = glob
            .from()
            .and_then(|from| {
                self.list_names
                    .iter()
                    .copied()
                    .find(|name| from == std::path::Path::new(name))
            })
            .unwrap_or("");
        PathHit {
            pattern: glob.original().to_string(),
            list,
        }
    }

    /// The pattern that matches the repo-relative `path` (`/` separators,
    /// no leading `/`), walking its ancestors top-down; `None` when nothing
    /// matches or a negation has the last word.
    pub(crate) fn check(&self, path: &str, is_dir: bool) -> Option<PathHit> {
        let path = path.trim_matches('/');
        if path.is_empty() || self.gitignore.is_empty() {
            return None;
        }
        let segments: Vec<&str> = path.split('/').collect();
        for end in 1..segments.len() {
            let ancestor = segments[..end].join("/");
            if let Match::Ignore(glob) = self.gitignore.matched(&ancestor, true) {
                return Some(self.hit(glob));
            }
        }
        match self.gitignore.matched(path, is_dir) {
            Match::Ignore(glob) => Some(self.hit(glob)),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(patterns: &[&str]) -> PathMatcher {
        let owned: Vec<String> = patterns.iter().map(|p| p.to_string()).collect();
        PathMatcher::new(&[("test", &owned)]).expect("patterns compile")
    }

    #[derive(serde::Deserialize)]
    struct GoldenCase {
        patterns: Vec<String>,
        path: String,
        ignored: bool,
    }

    #[derive(serde::Deserialize)]
    struct Golden {
        generator: String,
        cases: Vec<GoldenCase>,
    }

    #[test]
    fn agrees_with_npm_ignore_golden_fixture() {
        let text = include_str!("../../tests/fixtures/ignore_golden.json");
        let golden: Golden = serde_json::from_str(text).expect("golden fixture parses");
        assert!(golden.generator.starts_with("ignore@"));
        assert!(golden.cases.len() > 1000);
        let mut mismatches = Vec::new();
        for case in &golden.cases {
            let m = PathMatcher::new(&[("test", &case.patterns)]).expect("golden patterns compile");
            let got = m.check(&case.path, false).is_some();
            if got != case.ignored {
                mismatches.push(format!(
                    "{:?} on {:?}: npm ignore says {}, we say {}",
                    case.patterns, case.path, case.ignored, got
                ));
            }
        }
        assert!(
            mismatches.is_empty(),
            "{} mismatches:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }

    #[test]
    fn excluded_parent_cannot_be_reincluded() {
        let m = matcher(&["fixtures/", "!/a/fixtures/keep/"]);
        let hit = m
            .check("a/fixtures/keep/yarn.lock", false)
            .expect("still ignored");
        assert_eq!(hit.pattern, "fixtures/");
        assert_eq!(hit.list, "test");
    }

    #[test]
    fn negation_of_the_directory_itself_reincludes() {
        let m = matcher(&["tests/", "!/e2e/tests/"]);
        assert!(m.check("e2e/tests/package-lock.json", false).is_none());
        assert!(m.check("x/tests/package-lock.json", false).is_some());
    }

    #[test]
    fn case_insensitive_and_anchoring() {
        let m = matcher(&["/legacy/"]);
        assert!(m.check("Legacy/requirements.txt", false).is_some());
        assert!(m.check("x/legacy/requirements.txt", false).is_none());
        let bare = matcher(&["legacy/"]);
        assert!(bare.check("x/legacy/requirements.txt", false).is_some());
    }

    #[test]
    fn trailing_slash_only_matches_directories() {
        let m = matcher(&["package-lock.json/"]);
        assert!(m.check("package-lock.json", false).is_none());
        assert!(m.check("package-lock.json/x", false).is_some());
    }

    #[test]
    fn reports_the_list_of_the_deciding_pattern() {
        let a = vec!["tests/".to_string()];
        let b = vec!["/legacy/".to_string()];
        let m = PathMatcher::new(&[("defaults", &a), ("patches.ignorePaths", &b)]).unwrap();
        assert_eq!(
            m.check("legacy/x.lock", false).unwrap().list,
            "patches.ignorePaths"
        );
        assert_eq!(m.check("a/tests/x.lock", false).unwrap().list, "defaults");
    }

    #[test]
    fn hygiene_rejects_unsafe_patterns() {
        for bad in [
            "../x", "a/../b", "!../x", "C:/x", "/c:/x", "a\0b", "", "   ",
        ] {
            assert!(
                pattern_hygiene_error(bad).is_some(),
                "{bad:?} must be rejected"
            );
        }
        let long = "a".repeat(MAX_PATTERN_BYTES + 1);
        assert!(pattern_hygiene_error(&long).is_some());
        for good in ["/a/", "..a/", "a..b/", "**/x", "!/e2e/tests/", "ab:c"] {
            assert!(
                pattern_hygiene_error(good).is_none(),
                "{good:?} must be accepted"
            );
        }
    }

    #[test]
    fn bad_glob_is_an_error_naming_the_pattern() {
        let bad = vec!["a/[b".to_string()];
        let err = PathMatcher::new(&[("patches.ignorePaths", &bad)])
            .expect_err("unclosed class rejected");
        assert_eq!(err.0, "patches.ignorePaths");
        assert_eq!(err.1, "a/[b");
    }
}
