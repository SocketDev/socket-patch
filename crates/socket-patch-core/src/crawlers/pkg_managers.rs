//! Detect which Node.js package manager produced the layout in a
//! project root (`npm`, `pnpm`, `vlt`, `bun`, `yarn` classic, or yarn-berry
//! PnP).
//!
//! The apply pipeline cares about this for two reasons:
//!
//! 1. **pnpm**: `node_modules/<pkg>` is typically a symlink into the
//!    content-addressed global store. Patching the link target would
//!    corrupt every other project on the machine that points at the
//!    same store entry. The rename-over write in
//!    [`crate::utils::fs::atomic_write_bytes`] is what actually fixes
//!    this (the rename replaces only the directory entry, so the shared
//!    inode is never written through); this detector just lets the CLI
//!    surface a one-line "we detected pnpm, applied with CoW" notice so
//!    users understand the layout was handled.
//!
//! 2. **yarn-berry / Plug'n'Play**: packages do not live on disk at
//!    all — they're inside `.yarn/cache/<pkg>.zip` and resolved via
//!    a custom Node loader (`.pnp.cjs`). The npm crawler can't reach
//!    them, and rewriting bytes inside a zip is a totally different
//!    operation than rewriting bytes in `node_modules/`. The right
//!    move is to refuse with a clear error and point the user at
//!    `yarn patch <pkg>`.
//!
//! vlt keeps every installed package in a per-project store
//! (`node_modules/.vlt/<DepID>/node_modules/<name>`, hardlinked from vlt's
//! machine-wide cache on Linux) and links importers into it, which is the
//! pnpm situation again: the rename-over write keeps the shared cache
//! untouched and the detector only drives the CLI's notice.
//!
//! Classic yarn (`yarn.lock` + a real `node_modules/`) behaves like
//! npm at the filesystem level, so no special handling is needed.

use std::path::{Path, PathBuf};

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
    /// by default on Linux/macOS, so apply must never write through the
    /// shared inode (handled generically by the rename-over write in
    /// `utils::fs::atomic_write_bytes`).
    /// The operator gets a heads-up event so it's clear which package
    /// manager the patch landed against.
    Bun,
    /// vlt install state: the `node_modules/.vlt/` store directory or the
    /// hidden `node_modules/.vlt-lock.json`. Every package lives in the
    /// store, one real copy per DepID; a committed `vlt-lock.json` alone
    /// does not count, since another manager may have installed the tree.
    Vlt,
    /// No discernible package manager — empty or non-Node project.
    Unknown,
}

/// Detect the package manager that produced the layout under
/// `project_root`. Inspection is purely path-based — no shell-outs,
/// no parsing — so the detector is fast and side-effect-free.
///
/// Precedence (first match wins):
///
/// 1. `.pnp.cjs`, `.pnp.js`, or `.pnp.loader.mjs`, while the configured
///    yarn `nodeLinker` is `pnp` or unset ([`live_pnp_marker`]) → yarn-berry PnP —
///    unless the tree is pnpm's own `node-linker=pnp` layout (see
///    [`pnpm_pnp_layout`]), which also writes a `.pnp.cjs` but keeps
///    real package dirs in the pnpm virtual store → pnpm.
/// 2. `node_modules/.vlt/` is a directory, or `node_modules/.vlt-lock.json`
///    is a file → vlt.
/// 3. `bun.lock` or `bun.lockb` (+ `node_modules/`) → bun.
/// 4. `node_modules/.modules.yaml` or `node_modules/.pnpm/` → pnpm.
/// 5. `yarn.lock` (without PnP markers) + `node_modules/` → yarn classic.
/// 6. `node_modules/` exists → npm.
/// 7. Otherwise → unknown.
///
/// vlt wins over every other lockfile or store marker: its install state
/// only exists after a vlt install, while a sibling `bun.lock`,
/// `pnpm-lock.yaml` or `yarn.lock` may be stale.
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
    if live_pnp_marker(project_root, |m| project_root.join(m).is_file()).is_some() {
        // Carve-out: pnpm has its OWN PnP mode (`node-linker=pnp` in
        // `.npmrc`) which also writes a `.pnp.cjs` loader at the root
        // — but unlike yarn-berry the packages are real directories in
        // the pnpm virtual store, exactly the layout the CoW guard
        // patches natively. Reclassify as pnpm only on strong
        // evidence; anything ambiguous stays the fail-closed
        // yarn-berry refusal.
        if pnpm_pnp_layout(project_root) {
            return NpmPkgManager::Pnpm;
        }
        return NpmPkgManager::YarnBerryPnP;
    }

    // 2. vlt — its store or hidden lock exists only after a vlt install,
    //    so a stale sibling lockfile never outranks it.
    if project_root
        .join(crate::constants::npm_family::VLT_STORE_DIR)
        .is_dir()
        || project_root
            .join(crate::constants::npm_family::VLT_HIDDEN_LOCK_REL)
            .is_file()
    {
        return NpmPkgManager::Vlt;
    }

    // 3. bun — `bun.lock` (text, current default in v1.2+) or
    //    `bun.lockb` (binary, legacy). Like the yarn-classic check
    //    below, we require `node_modules/` to actually exist —
    //    a bare lockfile without an install is a fresh checkout.
    let node_modules = project_root.join("node_modules");
    if (project_root.join("bun.lock").is_file() || project_root.join("bun.lockb").is_file())
        && node_modules.is_dir()
    {
        return NpmPkgManager::Bun;
    }

    // 4. pnpm — markers live inside node_modules/.
    if node_modules.join(".modules.yaml").is_file() || node_modules.join(".pnpm").is_dir() {
        return NpmPkgManager::Pnpm;
    }

    // 5. yarn classic — yarn.lock + node_modules. We only return
    //    YarnClassic if node_modules actually exists, because a bare
    //    yarn.lock without node_modules is a fresh checkout where
    //    nothing has been installed yet.
    if project_root.join("yarn.lock").is_file() && node_modules.is_dir() {
        return NpmPkgManager::YarnClassic;
    }

    // 6. npm — any node_modules/ at all.
    if node_modules.is_dir() {
        return NpmPkgManager::Npm;
    }

    NpmPkgManager::Unknown
}

/// The yarn environment that decides which rc files yarn berry reads:
/// `YARN_NODE_LINKER`, `YARN_RC_FILENAME` (the rc file name yarn looks for
/// in every folder, `.yarnrc.yml` by default) and the home folder, whose
/// rc file yarn reads last.
#[derive(Debug, Clone)]
pub(crate) struct YarnEnv {
    pub node_linker: Option<String>,
    pub rc_filename: String,
    pub home: Option<PathBuf>,
}

impl YarnEnv {
    pub(crate) fn current() -> Self {
        let set = |k: &str| {
            std::env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        Self {
            node_linker: set("YARN_NODE_LINKER"),
            rc_filename: set("YARN_RC_FILENAME").unwrap_or_else(|| ".yarnrc.yml".to_string()),
            home: crate::utils::fs::home_dir(),
        }
    }

    /// The `nodeLinker` the home folder's rc file sets: yarn reads it after
    /// every project-side rc file, so it applies only when none of those
    /// sets the key.
    fn home_node_linker(&self) -> Option<String> {
        let rc = crate::utils::fs::read_regular_to_string_sync(
            &self.home.as_ref()?.join(&self.rc_filename),
        )
        .ok()?;
        rc_node_linker(&rc)
    }
}

/// The `nodeLinker` the rc file text `rc` sets, if any.
fn rc_node_linker(rc: &str) -> Option<String> {
    crate::formats::yarn::berry_gates::yarnrc_scalar(rc, "nodeLinker")
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// The `nodeLinker` yarn berry resolves for `project_root`:
/// `YARN_NODE_LINKER` when set (yarn lets every setting be overridden from
/// the environment), else the nearest rc file at or above the project that
/// sets `nodeLinker` (yarn merges every rc file up to the filesystem root,
/// the closest winning), else the home folder's rc file. The rc file name
/// is `YARN_RC_FILENAME` when set. `None` when nothing sets it: yarn berry
/// then uses its default linker, `pnp`.
pub fn yarn_node_linker(project_root: &Path) -> Option<String> {
    yarn_node_linker_in(project_root, &YarnEnv::current())
}

pub(crate) fn yarn_node_linker_in(project_root: &Path, env: &YarnEnv) -> Option<String> {
    if let Some(linker) = env.node_linker.clone() {
        return Some(linker);
    }
    let start = std::path::absolute(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    start
        .ancestors()
        .find_map(|dir| {
            let rc =
                crate::utils::fs::read_regular_to_string_sync(&dir.join(&env.rc_filename)).ok()?;
            rc_node_linker(&rc)
        })
        .or_else(|| env.home_node_linker())
}

/// The linker that decides whether a PnP loader is live: yarn 1 has no
/// `nodeLinker` (its PnP mode is `installConfig.pnp` in package.json, and
/// it reads neither `.yarnrc.yml` nor `YARN_NODE_LINKER`), so a loader
/// beside a classic `yarn.lock` is always live and reports `pnp`. Any
/// other project asks `linker` for yarn berry's configured `nodeLinker`.
pub(crate) fn effective_yarn_linker(
    yarn_lock: Option<&str>,
    linker: impl FnOnce() -> Option<String>,
) -> Option<String> {
    match yarn_lock.and_then(crate::formats::yarn::sniff_grammar) {
        Some(crate::formats::yarn::YarnLockGrammar::Classic) => Some("pnp".to_string()),
        _ => linker(),
    }
}

/// Whether a yarn `nodeLinker` setting (`None` = unset) is Plug'n'Play:
/// `pnp` itself, or nothing set at all (berry's default).
pub fn yarn_linker_is_pnp(linker: Option<&str>) -> bool {
    linker.is_none_or(|l| l == "pnp")
}

/// The PnP loader file that makes `project_root` a live yarn Plug'n'Play
/// tree, as `exists` sees the files, or `None`. A loader only counts while
/// the configured linker is still `pnp` (or unset): a Yarn 2 → Yarn 4
/// migration that switched `nodeLinker` to `node-modules` or `pnpm` keeps
/// the old `.pnp.js`, which yarn ignores, and so must every caller (#975).
/// Yarn 1 PnP (a classic `yarn.lock`) has no `nodeLinker`, so its loader
/// always counts ([`effective_yarn_linker`]).
/// Every `PNP_MARKERS` decision goes through here or
/// [`live_pnp_marker_with`].
pub fn live_pnp_marker(project_root: &Path, exists: impl Fn(&str) -> bool) -> Option<&'static str> {
    live_pnp_marker_with(
        || {
            let lock =
                crate::utils::fs::read_regular_to_string_sync(&project_root.join("yarn.lock"));
            effective_yarn_linker(lock.ok().as_deref(), || yarn_node_linker(project_root))
        },
        exists,
    )
}

/// [`live_pnp_marker`] over any file view: `linker` supplies the configured
/// `nodeLinker`, only asked for when a loader file exists.
pub fn live_pnp_marker_with(
    linker: impl FnOnce() -> Option<String>,
    exists: impl Fn(&str) -> bool,
) -> Option<&'static str> {
    let marker = crate::constants::npm_family::PNP_MARKERS
        .into_iter()
        .find(|m| exists(m))?;
    yarn_linker_is_pnp(linker().as_deref()).then_some(marker)
}

/// Is a PnP-marker-bearing project root actually pnpm's own PnP mode
/// (`node-linker=pnp` in `.npmrc`) rather than yarn-berry?
///
/// pnpm's PnP mode writes a `.pnp.cjs` loader at the root just like
/// yarn-berry does, but keeps real package directories in the pnpm
/// virtual store (`node_modules/.pnpm/<name>@<ver>/node_modules/<name>`,
/// verified against a real `pnpm install` with pnpm 10.28.2). The
/// reclassification requires ALL of:
///
/// * an installed pnpm store (`node_modules/.modules.yaml` or
///   `node_modules/.pnpm/`) — a bare `pnpm-lock.yaml` left behind in a
///   yarn-berry repo must not escape the refusal;
/// * `pnpm-lock.yaml` at the root — an installed store without pnpm's
///   lockfile is not attributable to pnpm's PnP mode;
/// * NO `yarn.lock` — a tree carrying both lockfiles alongside the
///   loader is ambiguous (mid-migration multi-PM repo), so the
///   safety-critical yarn-berry refusal still wins.
///
/// Shared with the vendor-side flavor probe
/// (`crate::vendor::npm_flavor::detect_npm_lock_flavor`) so both
/// detection sites agree on what counts as a pnpm-PnP tree.
pub(crate) fn pnpm_pnp_layout(project_root: &Path) -> bool {
    let node_modules = project_root.join("node_modules");
    (node_modules.join(".modules.yaml").is_file() || node_modules.join(".pnpm").is_dir())
        && project_root.join("pnpm-lock.yaml").is_file()
        && !project_root.join("yarn.lock").is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #975: yarn 4 keeps a Yarn 2 `.pnp.js` after a switch to the
    /// node-modules or pnpm linker; yarn ignores it, so must detection.
    #[test]
    fn stale_pnp_loader_under_non_pnp_linker_is_not_pnp() {
        for linker in ["node-modules", "pnpm", "'node-modules' # migrated"] {
            let d = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
            std::fs::write(d.path().join("yarn.lock"), "__metadata:\n").unwrap();
            std::fs::write(d.path().join(".pnp.js"), "").unwrap();
            std::fs::write(
                d.path().join(".yarnrc.yml"),
                format!("nodeLinker: {linker}\n"),
            )
            .unwrap();
            assert_eq!(
                live_pnp_marker_with(
                    || yarn_node_linker_in(d.path(), &bare_env(None)),
                    |m| d.path().join(m).is_file()
                ),
                None,
                "{linker}"
            );
        }
    }

    #[test]
    fn pnp_loader_counts_under_pnp_or_unset_linker() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.cjs"), "").unwrap();
        let exists = |m: &str| d.path().join(m).is_file();
        assert_eq!(
            live_pnp_marker_with(|| yarn_node_linker_in(d.path(), &bare_env(None)), exists),
            Some(".pnp.cjs")
        );
        std::fs::write(d.path().join(".yarnrc.yml"), "nodeLinker: \"pnp\"\n").unwrap();
        assert_eq!(
            live_pnp_marker_with(|| yarn_node_linker_in(d.path(), &bare_env(None)), exists),
            Some(".pnp.cjs")
        );
    }

    /// yarn's own precedence: the env var, then the nearest rc file that
    /// sets the key, walking up past rc files that don't.
    #[test]
    fn yarn_node_linker_follows_yarn_precedence() {
        let d = tempfile::tempdir().unwrap();
        let member = d.path().join("packages/a");
        std::fs::create_dir_all(&member).unwrap();
        assert_eq!(yarn_node_linker_in(&member, &bare_env(None)), None);
        std::fs::write(d.path().join(".yarnrc.yml"), "nodeLinker: node-modules\n").unwrap();
        std::fs::write(member.join(".yarnrc.yml"), "enableGlobalCache: false\n").unwrap();
        assert_eq!(
            yarn_node_linker_in(&member, &bare_env(None)).as_deref(),
            Some("node-modules")
        );
        std::fs::write(member.join(".yarnrc.yml"), "nodeLinker: pnp\n").unwrap();
        assert_eq!(
            yarn_node_linker_in(&member, &bare_env(None)).as_deref(),
            Some("pnp")
        );
        assert_eq!(
            yarn_node_linker_in(&member, &bare_env(Some("pnpm"))).as_deref(),
            Some("pnpm")
        );
        // `YarnEnv::current` drops an empty `YARN_NODE_LINKER`.
        assert_eq!(
            yarn_node_linker_in(&member, &bare_env(None)).as_deref(),
            Some("pnp")
        );
    }

    /// A [`YarnEnv`] with no home folder and the default rc file name.
    fn bare_env(node_linker: Option<&str>) -> YarnEnv {
        YarnEnv {
            node_linker: node_linker.map(str::to_string),
            rc_filename: ".yarnrc.yml".into(),
            home: None,
        }
    }

    /// yarn reads the home folder's rc file after every project-side one,
    /// and `YARN_RC_FILENAME` renames the rc file it looks for everywhere.
    #[test]
    fn yarn_node_linker_reads_home_rc_and_rc_filename() {
        let home = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();
        let mut env = bare_env(None);
        env.home = Some(home.path().to_path_buf());
        assert_eq!(yarn_node_linker_in(project.path(), &env), None);
        std::fs::write(
            home.path().join(".yarnrc.yml"),
            "nodeLinker: node-modules\n",
        )
        .unwrap();
        assert_eq!(
            yarn_node_linker_in(project.path(), &env).as_deref(),
            Some("node-modules"),
            "home rc applies to a project outside the home folder"
        );
        std::fs::write(project.path().join(".yarnrc.yml"), "nodeLinker: pnp\n").unwrap();
        assert_eq!(
            yarn_node_linker_in(project.path(), &env).as_deref(),
            Some("pnp"),
            "a project rc wins over the home rc"
        );

        env.rc_filename = ".yarnrc.ci.yml".into();
        assert_eq!(
            yarn_node_linker_in(project.path(), &env),
            None,
            "a renamed rc file skips .yarnrc.yml everywhere"
        );
        std::fs::write(home.path().join(".yarnrc.ci.yml"), "nodeLinker: pnpm\n").unwrap();
        assert_eq!(
            yarn_node_linker_in(project.path(), &env).as_deref(),
            Some("pnpm")
        );
        std::fs::write(
            project.path().join(".yarnrc.ci.yml"),
            "nodeLinker: node-modules\n",
        )
        .unwrap();
        assert_eq!(
            yarn_node_linker_in(project.path(), &env).as_deref(),
            Some("node-modules")
        );
    }

    /// Yarn 1 PnP (`installConfig.pnp`) has no `nodeLinker`, and yarn 1
    /// reads neither `.yarnrc.yml` nor `YARN_NODE_LINKER`: a loader beside
    /// a classic lock stays live whatever a berry setting says. The same
    /// setting still disowns a loader beside a berry lock (#975).
    #[test]
    fn yarn1_pnp_loader_ignores_berry_linker_settings() {
        let w = tempfile::tempdir().unwrap();
        let proj = w.path().join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(w.path().join(".yarnrc.yml"), "nodeLinker: node-modules\n").unwrap();
        std::fs::write(proj.join(".pnp.js"), "").unwrap();
        let exists = |m: &str| proj.join(m).is_file();
        for env in [bare_env(None), bare_env(Some("node-modules"))] {
            let probe = |lock: &str| {
                live_pnp_marker_with(
                    || effective_yarn_linker(Some(lock), || yarn_node_linker_in(&proj, &env)),
                    exists,
                )
            };
            assert_eq!(
                probe("# THIS IS AN AUTOGENERATED FILE.\n# yarn lockfile v1\n"),
                Some(".pnp.js"),
                "{env:?}"
            );
            assert_eq!(probe("__metadata:\n  version: 8\n"), None, "{env:?}");
        }
    }

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

    /// pnpm has its *own* PnP mode (`node-linker=pnp` in `.npmrc`),
    /// which writes a `.pnp.cjs` loader at the project root just like
    /// yarn-berry does. Unlike yarn-berry, the packages are real
    /// directories in the pnpm virtual store
    /// (`node_modules/.pnpm/<name>@<ver>/node_modules/<name>`), reached
    /// through the usual `node_modules/<name>` symlink — exactly the
    /// layout the CoW guard was built for. Classifying it as
    /// yarn-berry PnP makes `apply` refuse outright (exit 1, "use
    /// `yarn patch`" — a yarn command in a pnpm repo) on a tree
    /// socket-patch patches natively.
    ///
    /// Layout verified against a real `pnpm install` (pnpm 10.28.2).
    #[test]
    fn pnpm_pnp_mode_is_pnpm_not_yarn_berry() {
        let d = tempfile::tempdir().unwrap();
        // Root markers emitted by `pnpm install` with node-linker=pnp.
        std::fs::write(d.path().join(".pnp.cjs"), "").unwrap();
        std::fs::write(d.path().join("pnpm-lock.yaml"), "").unwrap();
        // Virtual store with a real package dir, the per-project pnpm
        // marker, and the top-level symlink into the store.
        std::fs::create_dir_all(
            d.path()
                .join("node_modules/.pnpm/flatted@3.3.1/node_modules/flatted"),
        )
        .unwrap();
        std::fs::write(d.path().join("node_modules/.modules.yaml"), "").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Pnpm);
    }

    /// The pnpm-PnP carve-out must stay fail-closed: a project carrying
    /// a `yarn.lock` *and* a `pnpm-lock.yaml` alongside the loader is
    /// ambiguous (mid-migration multi-PM repo), so the safety-critical
    /// yarn-berry refusal still wins.
    #[test]
    fn pnp_with_both_lockfiles_stays_yarn_berry() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.cjs"), "").unwrap();
        std::fs::write(d.path().join("pnpm-lock.yaml"), "").unwrap();
        std::fs::write(d.path().join("yarn.lock"), "").unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.pnpm")).unwrap();
        assert_eq!(
            detect_npm_pkg_manager(d.path()),
            NpmPkgManager::YarnBerryPnP
        );
    }

    /// The carve-out is install-based like every other branch: a
    /// `pnpm-lock.yaml` with no installed pnpm markers (a stale lockfile
    /// left behind in a yarn-berry repo) does not buy an escape from the
    /// refusal.
    #[test]
    fn pnp_with_stale_pnpm_lockfile_only_stays_yarn_berry() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.cjs"), "").unwrap();
        std::fs::write(d.path().join("pnpm-lock.yaml"), "").unwrap();
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

    #[test]
    fn vlt_via_store_dir() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.vlt")).unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Vlt);
    }

    #[test]
    fn vlt_via_hidden_lock() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        std::fs::write(d.path().join("node_modules/.vlt-lock.json"), "{}").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Vlt);
    }

    /// A committed `vlt-lock.json` is not install state: the tree beside it
    /// was installed by something else (here npm), or not at all.
    #[test]
    fn vlt_lockfile_without_vlt_install_state_falls_through() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("vlt-lock.json"), "{}").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Unknown);

        std::fs::create_dir_all(d.path().join("node_modules")).unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Npm);

        std::fs::create_dir_all(d.path().join("node_modules/.pnpm")).unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Pnpm);
    }

    #[test]
    fn yarn_berry_pnp_priority_over_vlt() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join(".pnp.cjs"), "").unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.vlt")).unwrap();
        std::fs::write(d.path().join("node_modules/.vlt-lock.json"), "{}").unwrap();
        assert_eq!(
            detect_npm_pkg_manager(d.path()),
            NpmPkgManager::YarnBerryPnP
        );
    }

    /// vlt install state outranks every sibling lockfile and store marker,
    /// each of which may be left over from another manager.
    #[test]
    fn vlt_priority_over_bun_pnpm_yarn_npm() {
        for marker in ["node_modules/.vlt", "node_modules/.vlt-lock.json"] {
            let d = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(d.path().join("node_modules/.pnpm")).unwrap();
            std::fs::write(d.path().join("node_modules/.modules.yaml"), "").unwrap();
            for lock in ["bun.lock", "bun.lockb", "yarn.lock", "package-lock.json"] {
                std::fs::write(d.path().join(lock), "").unwrap();
            }
            if marker.ends_with(".json") {
                std::fs::write(d.path().join(marker), "{}").unwrap();
            } else {
                std::fs::create_dir_all(d.path().join(marker)).unwrap();
            }
            assert_eq!(
                detect_npm_pkg_manager(d.path()),
                NpmPkgManager::Vlt,
                "{marker}"
            );
        }
    }

    #[test]
    fn node_modules_as_file_is_not_misclassified_vlt() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("node_modules"), "not a dir").unwrap();
        std::fs::write(d.path().join("vlt-lock.json"), "{}").unwrap();
        std::fs::write(d.path().join("vlt.json"), "{}").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Unknown);
    }

    /// Robustness: `.vlt` as a regular file, and the hidden lock as a
    /// directory, are not vlt install state.
    #[test]
    fn store_dir_as_file_is_not_vlt() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("node_modules/.vlt-lock.json")).unwrap();
        std::fs::write(d.path().join("node_modules/.vlt"), "not a dir").unwrap();
        assert_eq!(detect_npm_pkg_manager(d.path()), NpmPkgManager::Npm);
    }
}
