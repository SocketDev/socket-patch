//! Which lockfile governs a project's installs, per ecosystem: the ONE
//! precedence table every mode reads.
//!
//! Before this table the npm-family order lived in the vendored router, its
//! in-memory copy, the inventory's migration-leftover fallback, the hosted
//! vlt `SIBLING_LOCKS` list, the hosted vlt preflight inputs and the hosted
//! npm rewriter's "another lock owns it" check; the PyPI order lived in the
//! vendored router, the hosted `pdm_drives` gate and the agent-mode PDM
//! crawler. Each was a hand copy, and a precedence change had to land in all
//! of them.
//!
//! The table is presence-only and PURE: callers stat the files (on disk, in
//! a snapshot or in a memory project) and pass a predicate. Content
//! decisions that refine a family (pnpm v9 vs legacy, yarn classic vs berry,
//! a vlt lock's version) stay with the router that reads the bytes.
//!
//! What each mode DOES with the answer is deliberately different, and stays
//! with the mode: vendored wires the governing lock only and warns about
//! every other present lock ([`npm_locks_outside`],
//! [`pypi_locks_outside`]); hosted rewrites every present lock and asks the
//! table only to decide which lock confirms a pin or may veto its siblings
//! ([`pypi_tool_lock_governs`], and vlt's `vlt_drives`).

use crate::constants::npm_family::{BUN_LOCK, BUN_LOCKB, NPM_LOCKS, PNPM_LOCK, VLT_LOCK};

/// One npm-family wiring family: the locks one package manager installs
/// from. The family that governs wires (or supersedes) every file in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpmLockFamily {
    /// `vlt-lock.json`.
    Vlt,
    /// `bun.lock` and the binary `bun.lockb` (Bun reads the text lock when
    /// both exist).
    Bun,
    /// The root `pnpm-lock.yaml`.
    Pnpm,
    /// `yarn.lock`, classic or berry.
    Yarn,
    /// `npm-shrinkwrap.json` and `package-lock.json` (npm prefers the
    /// shrinkwrap; npm 12 installs from the package-lock beside it).
    Npm,
}

impl NpmLockFamily {
    /// The root-relative lock files of this family, in its own preference
    /// order.
    pub const fn files(self) -> &'static [&'static str] {
        match self {
            NpmLockFamily::Vlt => &[VLT_LOCK],
            NpmLockFamily::Bun => &[BUN_LOCK, BUN_LOCKB],
            NpmLockFamily::Pnpm => &[PNPM_LOCK],
            NpmLockFamily::Yarn => &["yarn.lock"],
            NpmLockFamily::Npm => &NPM_LOCKS,
        }
    }
}

/// The npm-family precedence, first present family wins. A Plug'n'Play
/// loader is checked before any of these (it refuses or reclassifies the
/// project whatever locks are present), and Rush's common lock only after
/// none matched; both stay with the router.
///
/// vlt first: a committed `vlt-lock.json` is only ever written by vlt. Bun
/// before pnpm: Bun's isolated linker leaves a `node_modules/.bun/` store
/// that looks like pnpm's, so the lock name decides.
pub const NPM_PRECEDENCE: [NpmLockFamily; 5] = [
    NpmLockFamily::Vlt,
    NpmLockFamily::Bun,
    NpmLockFamily::Pnpm,
    NpmLockFamily::Yarn,
    NpmLockFamily::Npm,
];

/// Every root npm-family lock file, in precedence order.
pub fn npm_lock_files() -> impl Iterator<Item = &'static str> {
    NPM_PRECEDENCE
        .into_iter()
        .flat_map(|family| family.files().iter().copied())
}

/// The family whose lock governs installs: the first in
/// [`NPM_PRECEDENCE`] with any file present, skipping `skip` (the inventory
/// asks what a version-refused pnpm lock was shadowing).
pub fn npm_governing_family(
    present: impl Fn(&str) -> bool,
    skip: Option<NpmLockFamily>,
) -> Option<NpmLockFamily> {
    NPM_PRECEDENCE
        .into_iter()
        .filter(|family| Some(*family) != skip)
        .find(|family| family.files().iter().any(|file| present(file)))
}

/// The present lock files OUTSIDE `family`, in precedence order: the locks
/// a single-lock wiring leaves untouched.
pub fn npm_locks_outside(
    family: NpmLockFamily,
    present: impl Fn(&str) -> bool,
) -> Vec<&'static str> {
    NPM_PRECEDENCE
        .into_iter()
        .filter(|other| *other != family)
        .flat_map(|other| other.files().iter().copied())
        .filter(|file| present(file))
        .collect()
}

/// The PyPI tool lockfiles, in precedence order (migration direction and
/// ecosystem currency: uv > Poetry > PDM > Pipenv). Standalone PEP 751 /
/// PEP 723 locks rank between uv and Poetry, but only when they pin the
/// package being wired, so the vendored router decides them with the
/// content in hand. `requirements.txt` and Hatch rank below every tool
/// lock.
pub const PYPI_TOOL_LOCKS: [&str; 4] = ["uv.lock", "poetry.lock", "pdm.lock", "Pipfile.lock"];

/// The PyPI requirements file the vendored router falls back to.
pub const PYPI_REQUIREMENTS: &str = "requirements.txt";

/// The governing tool lock: the first of [`PYPI_TOOL_LOCKS`] present.
pub fn pypi_governing_tool_lock(present: impl Fn(&str) -> bool) -> Option<&'static str> {
    PYPI_TOOL_LOCKS.into_iter().find(|lock| present(lock))
}

/// Whether a tool lock of higher precedence than `lock` (one of
/// [`PYPI_TOOL_LOCKS`]) is present: `lock`'s tool does not drive installs,
/// whether or not `lock` itself exists yet.
pub fn pypi_tool_lock_shadowed(lock: &str, present: impl Fn(&str) -> bool) -> bool {
    PYPI_TOOL_LOCKS
        .into_iter()
        .take_while(|higher| *higher != lock)
        .any(present)
}

/// Whether `lock` (one of [`PYPI_TOOL_LOCKS`]) is present and no tool lock
/// of higher precedence is: a leftover lower-ranked lock neither drives
/// installs nor may veto the governing one.
pub fn pypi_tool_lock_governs(lock: &str, present: impl Fn(&str) -> bool) -> bool {
    present(lock) && !pypi_tool_lock_shadowed(lock, present)
}

/// The present tool locks other than the governing one, in precedence
/// order.
pub fn pypi_locks_outside(governing: &str, present: impl Fn(&str) -> bool) -> Vec<&'static str> {
    PYPI_TOOL_LOCKS
        .into_iter()
        .filter(|lock| *lock != governing && present(lock))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set<'a>(files: &'a [&'a str]) -> impl Fn(&str) -> bool + 'a {
        move |name| files.contains(&name)
    }

    #[test]
    fn npm_precedence_is_vlt_bun_pnpm_yarn_npm() {
        let all = [
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lockb",
            "bun.lock",
            "vlt-lock.json",
        ];
        let expected = [
            (NpmLockFamily::Vlt, 6),
            (NpmLockFamily::Bun, 4),
            (NpmLockFamily::Pnpm, 3),
            (NpmLockFamily::Yarn, 2),
            (NpmLockFamily::Npm, 0),
        ];
        for (family, from) in expected {
            assert_eq!(
                npm_governing_family(set(&all[..=from]), None),
                Some(family),
                "{:?}",
                &all[..=from]
            );
        }
        assert_eq!(npm_governing_family(set(&[]), None), None);
        assert_eq!(
            npm_governing_family(set(&["bun.lockb"]), None),
            Some(NpmLockFamily::Bun)
        );
        assert_eq!(
            npm_governing_family(set(&["package-lock.json"]), None),
            Some(NpmLockFamily::Npm)
        );
    }

    #[test]
    fn skip_reports_what_a_family_shadows() {
        let files = ["pnpm-lock.yaml", "yarn.lock", "package-lock.json"];
        assert_eq!(
            npm_governing_family(set(&files), Some(NpmLockFamily::Pnpm)),
            Some(NpmLockFamily::Yarn)
        );
        assert_eq!(
            npm_governing_family(set(&["pnpm-lock.yaml"]), Some(NpmLockFamily::Pnpm)),
            None
        );
    }

    #[test]
    fn locks_outside_a_family_never_include_its_own_files() {
        let files = [
            "vlt-lock.json",
            "bun.lock",
            "bun.lockb",
            "pnpm-lock.yaml",
            "yarn.lock",
            "npm-shrinkwrap.json",
            "package-lock.json",
        ];
        assert_eq!(npm_lock_files().collect::<Vec<_>>(), files);
        assert_eq!(
            npm_locks_outside(NpmLockFamily::Vlt, set(&files)),
            files[1..]
        );
        assert_eq!(
            npm_locks_outside(NpmLockFamily::Npm, set(&files)),
            files[..5]
        );
        assert!(npm_locks_outside(NpmLockFamily::Bun, set(&["bun.lock", "bun.lockb"])).is_empty());
    }

    #[test]
    fn pypi_tool_lock_precedence() {
        assert_eq!(
            pypi_governing_tool_lock(set(&["Pipfile.lock", "pdm.lock", "uv.lock"])),
            Some("uv.lock")
        );
        assert!(pypi_tool_lock_governs(
            "pdm.lock",
            set(&["pdm.lock", "Pipfile.lock"])
        ));
        assert!(!pypi_tool_lock_governs(
            "pdm.lock",
            set(&["pdm.lock", "poetry.lock"])
        ));
        assert!(!pypi_tool_lock_governs(
            "pdm.lock",
            set(&["pdm.lock", "uv.lock"])
        ));
        assert!(!pypi_tool_lock_governs("pdm.lock", set(&[])));
        assert!(pypi_tool_lock_shadowed("pdm.lock", set(&["poetry.lock"])));
        assert!(!pypi_tool_lock_shadowed("pdm.lock", set(&["Pipfile.lock"])));
        assert!(!pypi_tool_lock_shadowed(
            "uv.lock",
            set(&["uv.lock", "poetry.lock"])
        ));
        assert_eq!(
            pypi_locks_outside(
                "poetry.lock",
                set(&["uv.lock", "poetry.lock", "Pipfile.lock"])
            ),
            ["uv.lock", "Pipfile.lock"]
        );
    }
}
