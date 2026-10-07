//! The workspace glob subset both workspace-membership checks read: npm,
//! yarn and Bun `package.json` `workspaces` (#884) and pnpm's
//! `pnpm-workspace.yaml` `packages:` (#1006). A pattern is a `/`-separated
//! glob: `*` and `?` match within one component, `**` matches any number
//! of components; a leading `./`, empty components and a trailing `/` are
//! ignored. A leading `!` negates; each caller applies negations the way
//! its package manager does. pnpm's globber also never lets a wildcard
//! match a component that starts with `.` ([`glob_matches_no_dot`]).

/// Whether the member path (`rel`, relative to the workspace root, one
/// entry per component) matches a `workspaces` pattern and no later
/// `!`-negated one (npm and yarn: the last matching pattern wins).
pub(crate) fn workspaces_include(patterns: &[String], rel: &[String]) -> bool {
    if rel.is_empty() {
        return false;
    }
    let mut included = false;
    for pattern in patterns {
        let (negated, pattern) = split_negation(pattern);
        if glob_matches(pattern, rel) {
            included = !negated;
        }
    }
    included
}

/// `(true, rest)` for a `!`-negated pattern, `(false, pattern)` otherwise.
pub(crate) fn split_negation(pattern: &str) -> (bool, &str) {
    match pattern.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, pattern),
    }
}

/// Whether one (un-negated) pattern matches `rel`. A pattern with no
/// components left (`""`, `.`, `./`) matches nothing.
pub(crate) fn glob_matches(pattern: &str, rel: &[String]) -> bool {
    pattern_matches(pattern, rel, true)
}

/// [`glob_matches`] the way pnpm's globber reads `packages:` (`dot: false`,
/// probed on pnpm 12.10.1): `*`, `?` and `**` never match a component that
/// starts with `.`, so `**` does not list `.github/actions/demo` and
/// `packages/*` does not list `packages/.hidden`. A pattern component that
/// itself starts with `.` (`.github/**`) still matches it.
pub(crate) fn glob_matches_no_dot(pattern: &str, rel: &[String]) -> bool {
    pattern_matches(pattern, rel, false)
}

fn pattern_matches(pattern: &str, rel: &[String], dot: bool) -> bool {
    let segments: Vec<&str> = pattern
        .trim()
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != ".")
        .collect();
    !segments.is_empty() && path_glob_matches(&segments, rel, dot)
}

/// `dot: false` keeps wildcards off components starting with `.`.
fn path_glob_matches(pattern: &[&str], path: &[String], dot: bool) -> bool {
    let hidden = |component: &String| !dot && component.starts_with('.');
    match pattern.split_first() {
        None => path.is_empty(),
        Some((&"**", rest)) => (0..=path.len())
            .take_while(|&skip| skip == 0 || !hidden(&path[skip - 1]))
            .any(|skip| path_glob_matches(rest, &path[skip..], dot)),
        Some((first, rest)) => path.split_first().is_some_and(|(head, tail)| {
            (!hidden(head) || first.starts_with('.'))
                && segment_glob_matches(first.as_bytes(), head.as_bytes())
                && path_glob_matches(rest, tail, dot)
        }),
    }
}

fn segment_glob_matches(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some((b'*', rest)) => {
            (0..=name.len()).any(|skip| segment_glob_matches(rest, &name[skip..]))
        }
        Some((b'?', rest)) => !name.is_empty() && segment_glob_matches(rest, &name[1..]),
        Some((c, rest)) => name.first() == Some(c) && segment_glob_matches(rest, &name[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspaces_patterns_match_like_npm_and_yarn() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(workspaces_include(
            &pats(&["packages/*"]),
            &rel("packages/a")
        ));
        assert!(!workspaces_include(
            &pats(&["packages/*"]),
            &rel("packages/a/b")
        ));
        assert!(workspaces_include(
            &pats(&["./packages/*/"]),
            &rel("packages/a")
        ));
        assert!(workspaces_include(
            &pats(&["packages/**"]),
            &rel("packages/a/b")
        ));
        assert!(workspaces_include(
            &pats(&["**/pkg-*"]),
            &rel("x/y/pkg-one")
        ));
        assert!(workspaces_include(&pats(&["app"]), &rel("app")));
        assert!(!workspaces_include(&pats(&["app"]), &rel("apps")));
        assert!(workspaces_include(&pats(&["app?"]), &rel("apps")));
        assert!(!workspaces_include(
            &pats(&["packages/*", "!packages/b"]),
            &rel("packages/b")
        ));
        assert!(!workspaces_include(&pats(&["*"]), &[]));
        assert!(!glob_matches("./", &rel("a")));
        // npm and yarn callers keep matching dot components.
        assert!(glob_matches("packages/*", &rel("packages/.hidden")));
    }

    #[test]
    fn pnpm_wildcards_skip_dot_components() {
        let rel = |p: &str| p.split('/').map(str::to_string).collect::<Vec<_>>();
        assert!(!glob_matches_no_dot("**", &rel(".github/actions/demo")));
        assert!(!glob_matches_no_dot(
            "packages/**",
            &rel("packages/.x/demo")
        ));
        assert!(!glob_matches_no_dot("packages/*", &rel("packages/.hidden")));
        assert!(!glob_matches_no_dot(
            "packages/?hidden",
            &rel("packages/.hidden")
        ));
        assert!(!glob_matches_no_dot("**/demo", &rel("a/.b/demo")));
        // An explicit dot component still matches, and below it wildcards
        // match ordinary names.
        assert!(glob_matches_no_dot(
            ".github/**",
            &rel(".github/actions/demo")
        ));
        assert!(glob_matches_no_dot(
            "packages/.hidden",
            &rel("packages/.hidden")
        ));
        assert!(glob_matches_no_dot("packages/.*", &rel("packages/.hidden")));
        assert!(glob_matches_no_dot("**", &rel("examples/demo")));
        assert!(glob_matches_no_dot("packages/**", &rel("packages/x/demo")));
    }
}
