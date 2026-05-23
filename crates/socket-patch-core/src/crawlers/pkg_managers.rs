//! Detect which Node.js package manager produced the layout in a
//! project root (`npm`, `pnpm`, `yarn` classic, or yarn-berry PnP).
//!
//! The apply pipeline cares about this for two reasons:
//!
//! 1. **pnpm**: `node_modules/<pkg>` is typically a symlink into the
//!    content-addressed global store. Patching the link target would
//!    corrupt every other project on the machine that points at the
//!    same store entry. The CoW guard in
//!    [`crate::patch::cow::break_hardlink_if_needed`] is what
//!    actually fixes this; this detector just lets the CLI surface a
//!    one-line "we detected pnpm, applied with CoW" notice so users
//!    understand the layout was handled.
//!
//! 2. **yarn-berry / Plug'n'Play**: packages do not live on disk at
//!    all — they're inside `.yarn/cache/<pkg>.zip` and resolved via
//!    a custom Node loader (`.pnp.cjs`). The npm crawler can't reach
//!    them, and rewriting bytes inside a zip is a totally different
//!    operation than rewriting bytes in `node_modules/`. The right
//!    move is to refuse with a clear error and point the user at
//!    `yarn patch <pkg>`.
//!
//! Classic yarn (`yarn.lock` + a real `node_modules/`) behaves like
//! npm at the filesystem level, so no special handling is needed.

use std::path::Path;

/// Identified Node.js package manager / layout flavor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpmPkgManager {
    /// `node_modules/` present, no other markers. Default assumption.
    Npm,
    /// pnpm content-store layout (`node_modules/.modules.yaml` or
    /// `node_modules/.pnpm/`). Patching is safe via CoW; the operator
    /// gets a heads-up event.
    Pnpm,
    /// yarn classic — `yarn.lock` present, real `node_modules/`, no
    /// PnP loader. Behaves like npm at the FS level.
    YarnClassic,
    /// yarn-berry with Plug'n'Play (`.pnp.cjs` present). Packages
    /// live inside `.yarn/cache/*.zip`. Apply must refuse.
    YarnBerryPnP,
    /// No discernible package manager — empty or non-Node project.
    Unknown,
}

/// Detect the package manager that produced the layout under
/// `project_root`. Inspection is purely path-based — no shell-outs,
/// no parsing — so the detector is fast and side-effect-free.
///
/// Precedence (first match wins):
///
/// 1. `.pnp.cjs` or `.pnp.loader.mjs` → yarn-berry PnP.
/// 2. `node_modules/.modules.yaml` or `node_modules/.pnpm/` → pnpm.
/// 3. `yarn.lock` (without PnP markers) + `node_modules/` → yarn classic.
/// 4. `node_modules/` exists → npm.
/// 5. Otherwise → unknown.
pub fn detect_npm_pkg_manager(project_root: &Path) -> NpmPkgManager {
    // 1. yarn-berry PnP — highest priority because it determines
    //    whether the npm crawler can find anything at all.
    if project_root.join(".pnp.cjs").is_file()
        || project_root.join(".pnp.loader.mjs").is_file()
    {
        return NpmPkgManager::YarnBerryPnP;
    }

    // 2. pnpm — markers live inside node_modules/.
    let node_modules = project_root.join("node_modules");
    if node_modules.join(".modules.yaml").is_file()
        || node_modules.join(".pnpm").is_dir()
    {
        return NpmPkgManager::Pnpm;
    }

    // 3. yarn classic — yarn.lock + node_modules. We only return
    //    YarnClassic if node_modules actually exists, because a bare
    //    yarn.lock without node_modules is a fresh checkout where
    //    nothing has been installed yet.
    if project_root.join("yarn.lock").is_file() && node_modules.is_dir() {
        return NpmPkgManager::YarnClassic;
    }

    // 4. npm — any node_modules/ at all.
    if node_modules.is_dir() {
        return NpmPkgManager::Npm;
    }

    NpmPkgManager::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_for_empty_dir() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Unknown);
    }

    #[test]
    fn npm_for_bare_node_modules() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Npm);
    }

    #[test]
    fn pnpm_via_modules_yaml() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        std::fs::write(d.path().join("node_modules/.modules.yaml"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Pnpm);
    }

    #[test]
    fn pnpm_via_pnpm_dir() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.pnpm")).unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Pnpm);
    }

    #[test]
    fn yarn_classic_via_lockfile() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        std::fs::write(d.path().join("yarn.lock"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::YarnClassic);
    }

    /// yarn.lock without an installed node_modules is "fresh
    /// checkout, nothing installed yet" — don't claim yarn classic.
    #[test]
    fn yarn_classic_requires_installed_node_modules() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("yarn.lock"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Unknown);
    }

    #[test]
    fn yarn_berry_pnp_via_pnp_cjs() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.cjs"), "").unwrap();
        assert_eq!(
            detect_npm_pkg_manager(d.path()),
            NpmPkgManager::YarnBerryPnP
        );
    }

    /// yarn-berry takes priority over pnpm even if both sets of
    /// markers exist (defensive — shouldn't happen in real projects).
    #[test]
    fn yarn_berry_pnp_priority_over_pnpm() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.cjs"), "").unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.pnpm")).unwrap();
        assert_eq!(
            detect_npm_pkg_manager(d.path()),
            NpmPkgManager::YarnBerryPnP
        );
    }

}
