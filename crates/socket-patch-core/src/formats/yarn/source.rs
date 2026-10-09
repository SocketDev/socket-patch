//! Where yarn 1 installs a classic lock block's copy from, decided once for
//! every mode that reads or rewrites the block.

use super::patterns::split_pattern;
use crate::vendor::npm_origin::npm_spec_is_registry;

/// Where yarn 1 installs a lock block's copy from: the ONE classifier every
/// mode routes a classic block of the patched `name@version` through
/// (#857, #921, B16), so a copy one of them cannot rewire is never silently
/// counted as wired by another. What each mode then does with it:
///
/// | source          | hosted rewrite | hosted restore | vendored | inventory verifiers |
/// |-----------------|----------------|----------------|----------|---------------------|
/// | `Registry`      | pinned         | restored       | wired    | kept                |
/// | `RemoteTarball` | skipped, named | refused        | skipped  | dropped             |
/// | `Directory`     | skipped, named | n/a            | skipped  | n/a                 |
/// | `Git`           | skipped, named | refused        | skipped  | dropped             |
/// | `Link`          | not ours       | n/a            | skipped  | n/a                 |
/// | `Unresolved`    | left untouched | n/a            | skipped  | n/a                 |
///
/// Both writing modes pin a copy to Socket's build of the REGISTRY package
/// (the hosted artifact, the service-built vendored tarball), so a remote
/// tarball — a fork, a local build — would be replaced by registry bytes it
/// never was. `vex` reads every tarball copy by what its `resolved` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopySource {
    /// A registry tarball: every key pattern is a registry range (a
    /// version, semver range, dist-tag, or an `npm:` alias of one) and the
    /// block has a `resolved`.
    Registry,
    /// A tarball yarn fetches from somewhere other than the registry: a
    /// `file:` tarball, a URL range, or a hosted-git shorthand
    /// (`owner/repo`, `github:owner/repo`) that yarn locks to a GitHub
    /// codeload tarball. The user's own artifact, not the registry package.
    RemoteTarball,
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

/// [`CopySource`] of a classic block from its key patterns and `resolved`.
pub(crate) fn classic_copy_source(patterns: &[String], resolved: Option<&str>) -> CopySource {
    for pattern in patterns {
        let range = split_pattern(pattern).map(|(_, r)| r).unwrap_or("");
        if range.starts_with("link:") {
            return CopySource::Link;
        }
        if let Some(path) = range.strip_prefix("file:") {
            if !is_tarball_path(path) {
                return CopySource::Directory;
            }
        }
    }
    if classic_block_is_git(patterns, resolved) {
        return CopySource::Git;
    }
    let Some(resolved) = resolved else {
        return CopySource::Unresolved;
    };
    let registry_ranges = patterns
        .iter()
        .all(|p| split_pattern(p).is_some_and(|(_, range)| npm_spec_is_registry(range)));
    if registry_ranges && !is_codeload_tarball(resolved) {
        CopySource::Registry
    } else {
        CopySource::RemoteTarball
    }
}

/// The root-relative `file:` directory a classic block's key names, if
/// any: yarn 1 COPIES it into node_modules under the DEPENDENCY name
/// (`"lp2@file:./lpdir"`), so which package that copy is comes from the
/// directory's own `package.json` (#1236). `None` for a `file:` tarball or
/// a path that leaves the root.
pub(crate) fn classic_file_directory(patterns: &[String]) -> Option<String> {
    patterns.iter().find_map(|p| {
        let path = split_pattern(p)?.1.strip_prefix("file:")?;
        let path = path.split('#').next().unwrap_or_default();
        if is_tarball_path(path) {
            return None;
        }
        crate::utils::cargo_workspace::normalize_rel("", path)
    })
}

/// The package a classic `file:` directory or url copy really installs,
/// whatever dependency name its key carries (#1236): the directory's
/// `package.json` `name` (read through `read_text`, given the
/// root-relative manifest path), or the registry package a url tarball's
/// path names. `None` when neither says (a `file:` tarball, a
/// non-registry url, an unreadable manifest).
pub(crate) fn classic_copy_real_name(
    patterns: &[String],
    resolved: Option<&str>,
    version: &str,
    read_text: impl Fn(&str) -> Option<String>,
) -> Option<(String, CopySource)> {
    match classic_copy_source(patterns, resolved) {
        CopySource::Directory => {
            let dir = classic_file_directory(patterns)?;
            let manifest = if dir.is_empty() {
                "package.json".to_string()
            } else {
                format!("{dir}/package.json")
            };
            let name = manifest_name(read_text(&manifest)?.as_bytes())?;
            Some((name, CopySource::Directory))
        }
        CopySource::RemoteTarball => {
            let url = resolved?.split('#').next().unwrap_or_default();
            if !url.starts_with("http") {
                return None;
            }
            Some((
                registry_tarball_name(url, version)?,
                CopySource::RemoteTarball,
            ))
        }
        _ => None,
    }
}

/// `name` of a `package.json`.
pub(crate) fn manifest_name(bytes: &[u8]) -> Option<String> {
    let bytes = crate::formats::text::strip_bom_bytes(bytes);
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

/// The package an npm registry tarball url serves, from its
/// `/<name>/-/<leaf>-<version>.tgz` path (`<name>` may be `@scope/leaf`,
/// its `@` / `/` possibly percent-encoded); `None` for any other shape.
pub(crate) fn registry_tarball_name(url: &str, version: &str) -> Option<String> {
    let path = url.split_once("://").map_or(url, |(_, rest)| rest);
    let path = path.split(['?']).next()?;
    let (before, file) = path.rsplit_once("/-/")?;
    let mut segs: Vec<String> = before
        .split('/')
        .skip(1) // the host
        .map(|seg| crate::utils::purl::percent_decode_purl_component(seg).into_owned())
        .collect();
    let leaf_name = segs.pop()?;
    let (scope, leaf_name) = match leaf_name.split_once('/') {
        Some((scope, leaf)) => (Some(scope.to_string()), leaf.to_string()),
        None => (segs.pop().filter(|s| s.starts_with('@')), leaf_name),
    };
    if file != format!("{leaf_name}-{version}.tgz") {
        return None;
    }
    Some(match scope {
        Some(scope) => format!("{scope}/{leaf_name}"),
        None => leaf_name,
    })
}

/// A GitHub codeload tarball: what yarn 1 locks a hosted-git shorthand to.
fn is_codeload_tarball(resolved: &str) -> bool {
    resolved
        .split_once("://")
        .is_some_and(|(_, rest)| rest.starts_with("codeload.github.com/"))
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

    /// B16: which classic copies are the registry package. A hosted pin
    /// replaces the copy with Socket's patched registry artifact, so only
    /// a registry copy may be pinned.
    #[test]
    fn copy_sources_split_registry_from_remote_tarballs() {
        let pats = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let registry = Some("https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#aa");
        for key in [
            &["left-pad@^1.3.0"][..],
            &["left-pad@^1.3.0", "left-pad@~1.3.0"],
            &["left-pad@latest"],
            &["pad@npm:left-pad@^1.3.0"],
        ] {
            assert_eq!(
                classic_copy_source(&pats(key), registry),
                CopySource::Registry,
                "{key:?}"
            );
        }
        for (key, resolved) in [
            (
                "left-pad@file:./old/left-pad-1.3.0.tgz",
                "file:./old/left-pad-1.3.0.tgz#aa",
            ),
            ("left-pad@https://host/fork.tgz", "https://host/fork.tgz"),
            (
                "left-pad@stevemao/left-pad#v1.3.0",
                "https://codeload.github.com/stevemao/left-pad/tar.gz/ff8e7ba",
            ),
            (
                "left-pad@github:stevemao/left-pad",
                "https://codeload.github.com/stevemao/left-pad/tar.gz/ff8e7ba",
            ),
            (
                "pad@npm:left-pad@https://host/fork.tgz",
                "https://host/fork.tgz",
            ),
        ] {
            assert_eq!(
                classic_copy_source(&pats(&[key]), Some(resolved)),
                CopySource::RemoteTarball,
                "{key}"
            );
        }
        assert_eq!(
            classic_copy_source(&pats(&["left-pad@^1.3.0"]), None),
            CopySource::Unresolved
        );
        assert_eq!(
            classic_copy_source(&pats(&["left-pad@file:../left-pad"]), None),
            CopySource::Directory
        );
    }
}
