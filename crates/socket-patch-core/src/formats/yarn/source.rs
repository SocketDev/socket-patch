//! Where yarn 1 installs a classic lock block's copy from, decided once for
//! every mode that reads or rewrites the block.

use super::patterns::split_pattern;

/// Where yarn 1 installs a lock block's copy from, as far as a lock
/// rewrite is concerned. Hosted, vendored and `vex` all classify a block of
/// the patched `name@version` through this one rule (#857, #921), so a copy
/// one of them cannot rewire is never silently counted as wired by another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClassicBlockSource {
    /// A tarball `resolved` (registry, URL or `file:` tarball): rewritable.
    Tarball,
    /// A `link:` range: a symlink into the working tree.
    Link,
    /// A `file:` directory range: yarn COPIES the directory into
    /// `node_modules`, so that copy keeps its own bytes.
    Directory,
    /// Fetched by yarn's git fetcher ([`classic_block_is_git`]).
    Git,
    /// Any other range with no `resolved`: not something yarn writes for a
    /// locked package, so the lock is stale and `yarn install` re-locks it.
    Unresolved,
}

/// [`ClassicBlockSource`] of a block from its key patterns and `resolved`.
pub(crate) fn classic_block_source(
    patterns: &[String],
    resolved: Option<&str>,
) -> ClassicBlockSource {
    for pattern in patterns {
        let range = split_pattern(pattern).map(|(_, r)| r).unwrap_or("");
        if range.starts_with("link:") {
            return ClassicBlockSource::Link;
        }
        if let Some(path) = range.strip_prefix("file:") {
            if !is_tarball_path(path) {
                return ClassicBlockSource::Directory;
            }
        }
    }
    if classic_block_is_git(patterns, resolved) {
        return ClassicBlockSource::Git;
    }
    match resolved {
        Some(_) => ClassicBlockSource::Tarball,
        None => ClassicBlockSource::Unresolved,
    }
}

/// Whether yarn 1 fetches a lock block with its GIT fetcher (#363): when any
/// key pattern's range (an `npm:` alias's target range included) is one
/// yarn's `GitResolver.isVersion` accepts, or the block's `resolved` is
/// itself a git remote. Yarn picks the fetcher from the PATTERN and hands it
/// the `resolved` value as a git remote, so rewriting that `resolved` to a
/// tarball breaks every later install (`git ls-remote` on a `.tgz`). The
/// hosted-git shorthands (`owner/repo`, `github:owner/repo`) are not git
/// here: yarn locks them to a codeload tarball and fetches that as one.
pub(crate) fn classic_block_is_git(patterns: &[String], resolved: Option<&str>) -> bool {
    patterns.iter().any(|p| {
        split_pattern(p).is_some_and(|(_, range)| {
            let range = match range.strip_prefix("npm:") {
                Some(aliased) => split_pattern(aliased).map_or("", |(_, r)| r),
                None => range,
            };
            yarn_classic_range_is_git(range)
        })
    }) || resolved.is_some_and(yarn_classic_range_is_git)
}

/// yarn 1's `GitResolver.isVersion` over node's legacy `url.parse`: a url
/// with a scheme whose path ends in `.git`, a `git+<x>:` / `git:` / `ssh:`
/// scheme, or a `github.com` / `gitlab.com` / `bitbucket.{com,org}` url
/// naming exactly `<owner>/<repo>` (not a file inside the repo, such as an
/// `/archive/v1.tar.gz`).
pub(crate) fn yarn_classic_range_is_git(range: &str) -> bool {
    let range = range.trim();
    let scheme_len = range
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-')))
        .unwrap_or(range.len());
    if scheme_len == 0 || !range[scheme_len..].starts_with(':') {
        return false;
    }
    let scheme = range[..scheme_len].to_ascii_lowercase();
    let rest = &range[scheme_len + 1..];
    let rest = rest.split('#').next().unwrap_or(rest);
    let (host, path) = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find(['/', '?']).unwrap_or(after.len());
            let authority = &after[..end];
            let host = authority.rsplit('@').next().unwrap_or(authority);
            let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
            (Some(host), &after[end..])
        }
        None => (None, rest),
    };
    let pathname = path.split('?').next().unwrap_or(path);
    if pathname.ends_with(".git") {
        return true;
    }
    if (scheme.starts_with("git+") && scheme.len() > 4) || scheme == "git" || scheme == "ssh" {
        return true;
    }
    match host {
        Some(host)
            if matches!(
                host.as_str(),
                "github.com" | "gitlab.com" | "bitbucket.com" | "bitbucket.org"
            ) =>
        {
            path.split('/').filter(|s| !s.is_empty()).count() == 2
        }
        _ => false,
    }
}

/// `file:` path → tarball or directory? Directories cannot be rewired.
fn is_tarball_path(path: &str) -> bool {
    let path = path.split('#').next().unwrap_or(path).trim_end_matches('/');
    path.ends_with(".tgz") || path.ends_with(".tar.gz")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// yarn 1's `GitResolver.isVersion`, case by case (#363).
    #[test]
    fn yarn_classic_git_ranges_are_recognized() {
        for range in [
            "git+https://github.com/stevemao/left-pad.git#v1.3.0",
            "git+ssh://git@github.com/stevemao/left-pad.git#ff8e7ba",
            "git+file:///tmp/lpgit#v1.3.0",
            "git://github.com/stevemao/left-pad.git",
            "ssh://git@example.com/left-pad",
            "https://example.com/left-pad.git",
            "https://example.com/left-pad.git#v1.3.0",
            "https://github.com/stevemao/left-pad",
            "https://github.com/stevemao/left-pad#v1.3.0",
            "https://gitlab.com/stevemao/left-pad/",
            "http://bitbucket.org/stevemao/left-pad",
            "GIT+HTTPS://github.com/stevemao/left-pad.git",
        ] {
            assert!(yarn_classic_range_is_git(range), "{range:?} is a git range");
        }
        for range in [
            "^1.3.0",
            "1.3.0",
            "latest",
            "stevemao/left-pad#v1.3.0",
            "github:stevemao/left-pad#v1.3.0",
            "https://codeload.github.com/stevemao/left-pad/tar.gz/ff8e7ba",
            "https://github.com/stevemao/left-pad/archive/v1.3.0.tar.gz",
            "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7",
            "file:./old/left-pad-1.3.0.tgz",
            "file:./.socket/vendor/npm/x/left-pad-1.3.0.tgz",
            "link:../left-pad",
            "",
        ] {
            assert!(
                !yarn_classic_range_is_git(range),
                "{range:?} is not a git range"
            );
        }
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(classic_block_is_git(
            &pats(&["left-pad@git+https://h/x.git#v1"]),
            Some("https://p.test/lp.tgz")
        ));
        assert!(classic_block_is_git(
            &pats(&["pad@npm:left-pad@git+https://h/x.git"]),
            None
        ));
        assert!(
            classic_block_is_git(&pats(&["left-pad@^1.3.0"]), Some("git+ssh://h/x.git#abc")),
            "a git `resolved` alone decides it too"
        );
        assert!(!classic_block_is_git(
            &pats(&["left-pad@stevemao/left-pad#v1.3.0"]),
            Some("https://codeload.github.com/stevemao/left-pad/tar.gz/ff8e7ba")
        ));
    }
}
