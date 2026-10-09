//! The `packageManager` field of package.json (Corepack's pin) and the same
//! `<tool>@<version>[+<hash>]` spelling pnpm records in
//! `node_modules/.modules.yaml`.

/// The version `spec` pins for `tool`: `pnpm@9.15.9+sha512.…` gives
/// `9.15.9` for `pnpm`. `None` when `spec` names another tool.
pub(crate) fn pinned_version<'a>(spec: &'a str, tool: &str) -> Option<&'a str> {
    let rest = spec.trim().strip_prefix(tool)?.strip_prefix('@')?;
    Some(
        rest.split_once('+')
            .map_or(rest, |(version, _hash)| version),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_version_strips_the_hash_and_checks_the_tool() {
        assert_eq!(pinned_version("pnpm@9.15.9", "pnpm"), Some("9.15.9"));
        assert_eq!(
            pinned_version(" pnpm@10.4.1+sha512.abc== ", "pnpm"),
            Some("10.4.1")
        );
        assert_eq!(pinned_version("yarn@1.22.22", "yarn"), Some("1.22.22"));
        assert_eq!(pinned_version("yarn@1.22.22", "pnpm"), None);
        assert_eq!(pinned_version("pnpmx@9.0.0", "pnpm"), None);
        assert_eq!(pinned_version("pnpm", "pnpm"), None);
    }
}
