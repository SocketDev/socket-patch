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
    /// yarn-berry with Plug'n'Play (`.pnp.cjs`, `.pnp.js`, or
    /// `.pnp.loader.mjs` present). Packages live inside
    /// `.yarn/cache/*.zip`. Apply must refuse.
    YarnBerryPnP,
    /// bun-managed project — `bun.lock` (text, current default) or
    /// `bun.lockb` (binary, legacy) at the project root. Bun
    /// hard-links from `~/.bun/install/cache/` into `node_modules/`
    /// by default on Linux/macOS, so apply must CoW the link before
    /// rewriting (handled generically by `break_hardlink_if_needed`).
    /// The operator gets a heads-up event so it's clear which package
    /// manager the patch landed against.
    Bun,
    /// No discernible package manager — empty or non-Node project.
    Unknown,
}

/// Detect the package manager that produced the layout under
/// `project_root`. Inspection is purely path-based — no shell-outs,
/// no parsing — so the detector is fast and side-effect-free.
///
/// Precedence (first match wins):
///
/// 1. `.pnp.cjs`, `.pnp.js`, or `.pnp.loader.mjs` → yarn-berry PnP.
/// 2. `bun.lock` or `bun.lockb` (+ `node_modules/`) → bun.
/// 3. `node_modules/.modules.yaml` or `node_modules/.pnpm/` → pnpm.
/// 4. `yarn.lock` (without PnP markers) + `node_modules/` → yarn classic.
/// 5. `node_modules/` exists → npm.
/// 6. Otherwise → unknown.
///
/// Bun comes before pnpm in the precedence because bun's isolated
/// linker (v1.3.2+ default) populates `node_modules/.bun/` which
/// superficially resembles pnpm's `.pnpm/` content store. The
/// lockfile filename disambiguates cleanly.
pub fn detect_npm_pkg_manager(project_root: &Path) -> NpmPkgManager {
    // 1. yarn-berry PnP — highest priority because it determines
    //    whether the npm crawler can find anything at all. Yarn 3+
    //    emits `.pnp.cjs`; Yarn 2.x emitted `.pnp.js` (renamed to
    //    `.cjs` in 3.0 to dodge `"type": "module"` resolution); newer
    //    installs may also ship the ESM `.pnp.loader.mjs`. All three
    //    mean "packages aren't on disk" — refuse rather than silently
    //    fall through to Unknown (a Yarn 2 PnP tree has no
    //    `node_modules/`, so it would otherwise escape the refusal).
    if project_root.join(".pnp.cjs").is_file()
        || project_root.join(".pnp.js").is_file()
        || project_root.join(".pnp.loader.mjs").is_file()
    {
        return NpmPkgManager::YarnBerryPnP;
    }

    // 2. bun — `bun.lock` (text, current default in v1.2+) or
    //    `bun.lockb` (binary, legacy). Like the yarn-classic check
    //    below, we require `node_modules/` to actually exist —
    //    a bare lockfile without an install is a fresh checkout.
    let node_modules = project_root.join("node_modules");
    if (project_root.join("bun.lock").is_file() || project_root.join("bun.lockb").is_file())
        && node_modules.is_dir()
    {
        return NpmPkgManager::Bun;
    }

    // 3. pnpm — markers live inside node_modules/.
    if node_modules.join(".modules.yaml").is_file() || node_modules.join(".pnpm").is_dir() {
        return NpmPkgManager::Pnpm;
    }

    // 4. yarn classic — yarn.lock + node_modules. We only return
    //    YarnClassic if node_modules actually exists, because a bare
    //    yarn.lock without node_modules is a fresh checkout where
    //    nothing has been installed yet.
    if project_root.join("yarn.lock").is_file() && node_modules.is_dir() {
        return NpmPkgManager::YarnClassic;
    }

    // 5. npm — any node_modules/ at all.
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

    #[test]
    fn bun_via_text_lockfile() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        std::fs::write(d.path().join("bun.lock"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Bun);
    }

    #[test]
    fn bun_via_binary_lockfile() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        std::fs::write(d.path().join("bun.lockb"), b"").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Bun);
    }

    /// `bun.lock` without an installed `node_modules/` is a fresh
    /// checkout — same pattern as `yarn.lock` alone.
    #[test]
    fn bun_requires_installed_node_modules() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("bun.lock"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Unknown);
    }

    /// Bun's isolated linker (v1.3.2+ default) creates
    /// `node_modules/.bun/` which superficially resembles pnpm's
    /// `.pnpm/`. The lockfile filename disambiguates — `bun.lock`
    /// wins over the `.pnpm/` heuristic.
    #[test]
    fn bun_priority_over_pnpm_when_both_markers_present() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.pnpm")).unwrap();
        std::fs::write(d.path().join("bun.lock"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Bun);
    }

    /// yarn-berry beats bun (PnP is a structural override of
    /// everything — packages aren't on disk).
    #[test]
    fn yarn_berry_pnp_priority_over_bun() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.cjs"), "").unwrap();
        std::fs::write(d.path().join("bun.lock"), "").unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        assert_eq!(
            detect_npm_pkg_manager(d.path()),
            NpmPkgManager::YarnBerryPnP
        );
    }

    /// The ESM PnP loader variant (`.pnp.loader.mjs`) is sufficient on
    /// its own — newer yarn-berry installs ship it instead of (or
    /// alongside) `.pnp.cjs`. The end-to-end refusal test pins this at
    /// the CLI layer; pin it here at the detector layer too so a unit
    /// regression is caught without standing up the whole apply path.
    #[test]
    fn yarn_berry_pnp_via_loader_mjs() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.loader.mjs"), "").unwrap();
        assert_eq!(
            detect_npm_pkg_manager(d.path()),
            NpmPkgManager::YarnBerryPnP
        );
    }

    /// PnP wins even when a real `node_modules/` is also present (a
    /// yarn-berry checkout can carry both an installed tree and the
    /// loader). The refusal is the safety-critical branch — it must not
    /// be masked by the npm fallthrough.
    #[test]
    fn yarn_berry_pnp_priority_over_node_modules() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.cjs"), "").unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        assert_eq!(
            detect_npm_pkg_manager(d.path()),
            NpmPkgManager::YarnBerryPnP
        );
    }

    /// pnpm is checked before yarn-classic: a project with both a
    /// `yarn.lock` and pnpm's `.pnpm/` store (e.g. a repo migrating
    /// package managers without a clean reinstall) classifies as pnpm,
    /// matching the documented precedence table.
    #[test]
    fn pnpm_priority_over_yarn_classic() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.pnpm")).unwrap();
        std::fs::write(d.path().join("yarn.lock"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Pnpm);
    }

    /// bun is checked before yarn-classic too: a `bun.lock` plus a
    /// stray `yarn.lock` (multi-PM repo) classifies as bun.
    #[test]
    fn bun_priority_over_yarn_classic() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        std::fs::write(d.path().join("bun.lock"), "").unwrap();
        std::fs::write(d.path().join("yarn.lock"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Bun);
    }

    /// Robustness: a malformed layout where `node_modules` is a regular
    /// *file* rather than a directory must not be misclassified. Every
    /// non-PnP branch gates on `node_modules.is_dir()` (directly or via
    /// a child `join`), so a bun lockfile next to a `node_modules` file
    /// falls through to Unknown rather than claiming bun.
    #[test]
    fn node_modules_as_file_is_not_misclassified() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("node_modules"), "not a dir").unwrap();
        std::fs::write(d.path().join("bun.lock"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Unknown);
    }

    /// The bun-before-pnpm precedence must hold for the *binary* legacy
    /// lockfile too, not just the text one. `bun_priority_over_pnpm_*`
    /// only exercises `bun.lock`; pin `bun.lockb` against a `.pnpm/`
    /// store so a regression that special-cases only the text lockfile
    /// in the precedence is caught.
    #[test]
    fn bun_lockb_priority_over_pnpm() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.pnpm")).unwrap();
        std::fs::write(d.path().join("bun.lockb"), b"").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Bun);
    }

    /// yarn-berry PnP outranks bun via the ESM loader marker as well as
    /// `.pnp.cjs`. The existing `yarn_berry_pnp_priority_over_bun` only
    /// covers `.pnp.cjs`; pin the `.pnp.loader.mjs` path so the
    /// safety-critical refusal branch can't be masked by bun when an
    /// install ships only the loader variant.
    #[test]
    fn yarn_berry_loader_mjs_priority_over_bun() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.loader.mjs"), "").unwrap();
        std::fs::write(d.path().join("bun.lock"), "").unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        assert_eq!(
            detect_npm_pkg_manager(d.path()),
            NpmPkgManager::YarnBerryPnP
        );
    }

    /// Yarn 2.x (berry) emitted the PnP loader as `.pnp.js` — Yarn 3.0
    /// renamed it to `.pnp.cjs`. A Yarn 2 PnP tree has no
    /// `node_modules/` on disk, so if `.pnp.js` isn't recognized the
    /// project escapes the safety-critical refusal and silently
    /// classifies as Unknown. Pin the legacy marker so the refusal
    /// fires for Yarn 2 installs too.
    #[test]
    fn yarn_berry_pnp_via_legacy_pnp_js() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.js"), "").unwrap();
        assert_eq!(
            detect_npm_pkg_manager(d.path()),
            NpmPkgManager::YarnBerryPnP
        );
    }

    /// The legacy `.pnp.js` marker must outrank bun as well — same
    /// structural override as `.pnp.cjs`/`.pnp.loader.mjs`: packages
    /// aren't on disk, so refuse regardless of a stray lockfile or an
    /// installed `node_modules/`.
    #[test]
    fn yarn_berry_legacy_pnp_js_priority_over_bun() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.js"), "").unwrap();
        std::fs::write(d.path().join("bun.lock"), "").unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        assert_eq!(
            detect_npm_pkg_manager(d.path()),
            NpmPkgManager::YarnBerryPnP
        );
    }

    /// Robustness: `.pnp.js` as a *directory* (not a regular file) must
    /// not trip the PnP branch — the check is `.is_file()`. With no
    /// other markers it falls through to Unknown.
    #[test]
    fn pnp_js_as_dir_does_not_trigger_pnp() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join(".pnp.js")).unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Unknown);
    }

    /// Layout assumption: detection is *install*-based, not
    /// lockfile-based, for npm. A lone `package-lock.json` with no
    /// installed `node_modules/` is a fresh checkout — there's nothing
    /// on disk to patch — so it must classify as Unknown, not Npm.
    /// (The npm branch deliberately ignores `package-lock.json`.)
    #[test]
    fn npm_lockfile_without_node_modules_is_unknown() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("package-lock.json"), "{}").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Unknown);
    }

    /// Robustness: a malformed pnpm marker where `.modules.yaml` is a
    /// *directory* rather than a file must not trip the pnpm branch
    /// (the check is `.is_file()`). With no real `.pnpm/` store either,
    /// a bare `node_modules/` falls through to the npm default.
    #[test]
    fn modules_yaml_as_dir_does_not_trigger_pnpm() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.modules.yaml")).unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Npm);
    }

    /// Layout assumption: `node_modules` reached through a symlink to a
    /// real directory is a valid install (npm/yarn workspaces and some
    /// CI caches symlink it). `is_dir()` follows symlinks, so a
    /// `yarn.lock` beside a symlinked `node_modules/` still classifies
    /// as yarn-classic rather than falling through to Unknown.
    #[test]
    #[cfg(unix)]
    fn symlinked_node_modules_is_followed() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real_modules");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, d.path().join("node_modules")).unwrap();
        std::fs::write(d.path().join("yarn.lock"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::YarnClassic);
    }
}
