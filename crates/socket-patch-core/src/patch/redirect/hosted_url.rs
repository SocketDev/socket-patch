//! Hosted-artifact URL leaf ownership: whether a hosted tarball URL names a
//! given npm package version. Shared by the bun binary lock rewriter and the
//! manifest-less VEX discovery of bun / vlt hosted refs.

/// True when `url` is an http(s) artifact URL whose last path segment is
/// `<bare>-<version>.tgz` — the leaf every hosted artifact URL for this
/// `name@version` ends in. `<bare>` is the name without its `@scope/`: the
/// vendor path layer (`tgz_rel_leaf`) keeps a scope as a directory level
/// (`@scope/pkg-1.0.0.tgz`), and the hosted rewriter's prior-URL match
/// (`is_prior_hosted_bun_spec`) compares the same last path segment, so
/// `pkg-1.0.0.tgz` is the one spelling both agree on. Anything that fails
/// to parse fails the match (closed). The exact-leaf comparison is the
/// version discriminator: `pkg-1.3.0.tgz` never equals `pkg-11.3.0.tgz`
/// or `pkg-1.3.0-rc1.tgz`.
pub(crate) fn hosted_url_names(url: &str, name: &str, version: &str) -> bool {
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return false;
    }
    let scheme_end = url
        .find("://")
        .expect("url starts with http(s):// — checked above")
        + 3;
    let Some(path_start) = url[scheme_end..].find('/').map(|i| i + scheme_end) else {
        return false;
    };
    let leaf = url[path_start..].rsplit('/').next().unwrap_or_default();
    let bare = name.rsplit('/').next().unwrap_or(name);
    !leaf.is_empty() && leaf == format!("{bare}-{version}.tgz")
}

/// The version a hosted artifact `url` names for `name`: its last path
/// segment is `<bare>-<version>.tgz` with a semver `<version>`, confirmed by
/// [`hosted_url_names`]. How a hosted bun binary redirect's version is
/// recovered (`bun_binary::names`) and how lockfile discovery reads a bun
/// hosted ref's version.
pub(crate) fn hosted_url_version<'u>(url: &'u str, name: &str) -> Option<&'u str> {
    let bare = name.rsplit('/').next().unwrap_or(name);
    let version = url
        .rsplit('/')
        .next()?
        .strip_prefix(bare)?
        .strip_prefix('-')?
        .strip_suffix(".tgz")?;
    (semver::Version::parse(version).is_ok() && hosted_url_names(url, name, version))
        .then_some(version)
}
