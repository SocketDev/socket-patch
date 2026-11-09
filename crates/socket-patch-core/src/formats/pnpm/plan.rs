//! The pnpm planning core both modes share. Hosted ([`super::hosted`]) and
//! vendored (`vendor::pnpm_lock`, `vendor::pnpm_lock_legacy`) mode differ
//! only in where a rewired entry points ([`Target`]); this module owns what
//! they agree on:
//!
//! * which lock versions each target's edit has fixtures for
//!   ([`hosted_refuses_lock`]; vendored takes the grammars its rekey was
//!   captured against, [`super::sniff_lock_grammar`], and refuses the rest,
//!   target-specifically: divergences N16);
//! * how a lock key names a patched `name@version` ([`match_key`]): the
//!   registry entry with its peer suffix, or the entry a vendored rewire
//!   already rekeyed;
//! * the all-or-nothing gate: an instance the target's edit cannot repoint
//!   ([`Target::repoints`]) refuses the release in every lock, so no lock
//!   is left half-rewired.
//!
//! The edits themselves stay with the targets: hosted splices each
//! instance's `resolution:`; vendored rekeys the entry to its `file:`
//! artifact and mirrors the override pnpm cross-checks.

use super::grammar;

use std::collections::BTreeMap;

use crate::constants::npm_family::{PNPM_LOCK, PNPM_SHRINKWRAP_LEGACY};
use crate::formats::text::strip_bom;
use crate::utils::pnpm_workspace::pinned_pnpm_major;
use crate::vendor::npm_common::tgz_rel_leaf;

/// Where a rewired entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    /// A Socket-hosted tarball URL (`scan --mode hosted`): the instance's
    /// `resolution:` is spliced in place.
    Hosted,
    /// A committed `.socket/vendor/npm/<uuid>/<leaf>` tarball (`vendor`):
    /// the entry is rekeyed to `file:<artifact>`.
    Vendored,
}

/// Whether the hosted splice refuses a lock: pnpm 1's early shrinkwrap
/// (shrinkwrapVersion 3 without a minor version), whose installers drop
/// registry tarball URLs whatever the frozen flag says (verified with pnpm
/// 1.0.0). Hosted takes every other lock version (divergences N16).
pub(crate) fn hosted_refuses_lock(text: &str) -> bool {
    let field = |name: &str| strip_bom(text).lines().find_map(|l| l.strip_prefix(name));
    field("shrinkwrapVersion:").is_some_and(|v| v.trim().trim_matches(['\'', '"']) == "3")
        && !field("shrinkwrapMinorVersion:")
            .is_some_and(|v| v.trim().parse::<u32>().is_ok_and(|v| v > 0))
}

impl Target {
    /// Whether this target's edit repoints a registry instance whose key
    /// carries `suffix` after `name@version`.
    pub(crate) fn repoints(self, suffix: &str) -> bool {
        match self {
            // The rekey moves the plain entry only: a peer-suffixed rekey
            // has no fixture and would dangle.
            Target::Vendored => suffix.is_empty(),
            // The splice repoints every peer context it can parse: none,
            // pnpm 5's `_peer@1`, or balanced `(peer@1)` groups.
            Target::Hosted if suffix.is_empty() || suffix.starts_with('_') => true,
            Target::Hosted => {
                let mut depth = 0usize;
                for c in suffix.chars() {
                    match c {
                        '(' => depth += 1,
                        ')' if depth > 0 => depth -= 1,
                        _ if depth == 0 => return false,
                        _ => {}
                    }
                }
                depth == 0
            }
        }
    }
}

/// The lock pnpm reads in a directory holding `pnpm-lock.yaml` (`lock`)
/// and/or a pnpm <= 2 `shrinkwrap.yaml` (`shrinkwrap`), given the pnpm major
/// the project pins ([`pinned_pnpm_major`]); the other one is SHADOWED
/// (owner decision on divergence N11): never rewritten, never part of the
/// all-or-nothing gate (debris in it cannot refuse a dependency), only swept
/// for stale Socket identities by lockfile discovery. pnpm 1 / 2 read only
/// `shrinkwrap.yaml`; pnpm >= 3 read only `pnpm-lock.yaml`. With no pin,
/// `pnpm-lock.yaml` governs (pnpm <= 2 never writes one).
pub(crate) fn governing_pnpm_lock(
    lock: bool,
    shrinkwrap: bool,
    pinned_major: Option<u32>,
) -> Option<&'static str> {
    let pnpm_1_or_2 = pinned_major.is_some_and(|major| major <= 2);
    let governs = shrinkwrap && (!lock || pnpm_1_or_2);
    (governs.then_some(PNPM_SHRINKWRAP_LEGACY)).or(lock.then_some(PNPM_LOCK))
}

/// The pnpm locks of a hosted run's `files` (root-relative paths) a planner
/// rewrites, in key order: per directory, the [`governing_pnpm_lock`], read
/// with the evidence `files` holds for that directory.
pub(crate) fn planned_locks(files: &BTreeMap<String, String>) -> Vec<&String> {
    let planned = |key: &&String| {
        let leaf = key.rsplit('/').next().unwrap_or(key);
        if !matches!(leaf, PNPM_LOCK | PNPM_SHRINKWRAP_LEGACY) {
            return false;
        }
        // `dir` keeps its trailing `/` (empty at the root).
        let in_dir = |rel: &str| format!("{}{rel}", &key[..key.len() - leaf.len()]);
        let has = |rel: &str| files.contains_key(&in_dir(rel));
        let both = (has(PNPM_LOCK), has(PNPM_SHRINKWRAP_LEGACY));
        // The pin decides only between the two, so it is read only then.
        let pinned = match both {
            (true, true) => pinned_pnpm_major(|rel| files.get(&in_dir(rel)).cloned()),
            _ => None,
        };
        governing_pnpm_lock(both.0, both.1, pinned) == Some(leaf)
    };
    files.keys().filter(planned).collect()
}

/// How one `packages:` / `snapshots:` key names a patched release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyMatch<'k> {
    /// The registry entry, with whatever follows `name@version` (empty, or
    /// a peer suffix such as `(react@18.2.0)` / `_react@18.2.0`).
    Registry { suffix: &'k str },
    /// The entry a vendored rewire rekeyed: v9's `name@file:<artifact>` or
    /// legacy's bare `file:<artifact>`, where the artifact is this
    /// project's vendored tarball of this release
    /// ([`crate::origin::vendor_ref`]: root-anchored, so a sibling
    /// checkout's `../.socket/vendor/…` is not ours; any uuid).
    Rekeyed,
}

/// How `key` names `name@version`, if it does (see [`KeyMatch`]). Keys in
/// every grammar's spelling (`name@1.0.0`, `/name@1.0.0`, `/name/1.0.0`,
/// quoted) read alike.
pub(crate) fn match_key<'k>(key: &'k str, name: &str, version: &str) -> Option<KeyMatch<'k>> {
    if let Some(suffix) = grammar::suffix(key, name, version) {
        return Some(KeyMatch::Registry { suffix });
    }
    let key = grammar::unquote(key);
    let path = key
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix("@file:"))
        .or_else(|| key.strip_prefix("file:"))?;
    // The leaf binding matters: a project can vendor one package at several
    // versions, and an edit must never take a sibling version's entry.
    crate::origin::vendor_ref(path)
        .filter(|v| v.eco == "npm" && v.leaf == tgz_rel_leaf(name, version))
        .map(|_| KeyMatch::Rekeyed)
}

#[cfg(test)]
mod tests {
    use super::super::{sniff_lock_grammar, PnpmLockGrammar};
    use super::*;

    const ART: &str = ".socket/vendor/npm/0b8d2c3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e/left-pad-1.3.0.tgz";

    #[test]
    fn keys_of_every_grammar_name_the_release() {
        for key in [
            "left-pad@1.3.0",
            "/left-pad@1.3.0",
            "/left-pad/1.3.0",
            "'left-pad@1.3.0'",
        ] {
            assert_eq!(
                match_key(key, "left-pad", "1.3.0"),
                Some(KeyMatch::Registry { suffix: "" }),
                "{key}"
            );
        }
        assert_eq!(
            match_key("left-pad@1.3.0(react@18.2.0)", "left-pad", "1.3.0"),
            Some(KeyMatch::Registry {
                suffix: "(react@18.2.0)"
            })
        );
        assert_eq!(match_key("left-pad@1.3.01", "left-pad", "1.3.0"), None);
        assert_eq!(
            match_key(&format!("left-pad@file:{ART}"), "left-pad", "1.3.0"),
            Some(KeyMatch::Rekeyed)
        );
        assert_eq!(
            match_key(&format!("file:{ART}"), "left-pad", "1.3.0"),
            Some(KeyMatch::Rekeyed)
        );
        // A sibling version's artifact, another package's key, and a
        // sibling checkout's path are not this release's rekey.
        assert_eq!(match_key(&format!("file:{ART}"), "left-pad", "1.3.1"), None);
        assert_eq!(
            match_key(&format!("is-odd@file:{ART}"), "left-pad", "1.3.0"),
            None
        );
        assert_eq!(
            match_key(&format!("left-pad@file:../{ART}"), "left-pad", "1.3.0"),
            None
        );
    }

    /// N11 (owner decision): of a directory's `pnpm-lock.yaml` and
    /// `shrinkwrap.yaml`, the one the pinned pnpm major reads governs and
    /// the other is shadowed (review finding: pnpm 1 / 2 read only the
    /// shrinkwrap).
    #[test]
    fn the_pinned_pnpm_major_picks_the_governing_lock() {
        // No pin: `pnpm-lock.yaml` governs a pair, and each lone lock itself.
        assert_eq!(governing_pnpm_lock(true, true, None), Some(PNPM_LOCK));
        assert_eq!(
            governing_pnpm_lock(false, true, None),
            Some(PNPM_SHRINKWRAP_LEGACY)
        );
        assert_eq!(governing_pnpm_lock(false, false, Some(2)), None);
        // pnpm 1 / 2 read only `shrinkwrap.yaml`; pnpm >= 3 only the lock.
        assert_eq!(
            governing_pnpm_lock(true, true, Some(2)),
            Some(PNPM_SHRINKWRAP_LEGACY)
        );
        assert_eq!(governing_pnpm_lock(true, true, Some(3)), Some(PNPM_LOCK));
        assert_eq!(governing_pnpm_lock(true, false, Some(1)), Some(PNPM_LOCK));

        let files = |pin: Option<&str>| {
            let mut files: BTreeMap<String, String> = [
                "a/pnpm-lock.yaml",
                "a/shrinkwrap.yaml",
                "b/shrinkwrap.yaml",
                "pnpm-lock.yaml",
                "shrinkwrap.yaml",
            ]
            .into_iter()
            .map(|k| (k.to_string(), String::new()))
            .collect();
            if let Some(pin) = pin {
                let pkg = format!(r#"{{"packageManager": "pnpm@{pin}"}}"#);
                files.insert("package.json".into(), pkg);
            }
            files
        };
        let planned = |files: &BTreeMap<String, String>| {
            planned_locks(files)
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        // No evidence, or pnpm >= 3: each `pnpm-lock.yaml` shadows its
        // sibling shrinkwrap.
        for pin in [None, Some("9.15.0")] {
            assert_eq!(
                planned(&files(pin)),
                ["a/pnpm-lock.yaml", "b/shrinkwrap.yaml", "pnpm-lock.yaml"],
                "{pin:?}"
            );
        }
        // pnpm 2 pinned at the root: there `shrinkwrap.yaml` governs and the
        // stray `pnpm-lock.yaml` is shadowed; `a/` has no evidence of its own.
        assert_eq!(
            planned(&files(Some("2.25.7"))),
            ["a/pnpm-lock.yaml", "b/shrinkwrap.yaml", "shrinkwrap.yaml"]
        );
        // The install record outranks package.json.
        let mut record = files(Some("9.15.0"));
        record.insert(
            "node_modules/.modules.yaml".into(),
            "packageManager: pnpm@2.25.7\n".into(),
        );
        assert_eq!(
            planned(&record).last().map(String::as_str),
            Some("shrinkwrap.yaml")
        );
    }

    #[test]
    fn each_target_repoints_what_its_edit_has_fixtures_for() {
        assert!(Target::Hosted.repoints(""));
        assert!(Target::Hosted.repoints("(react@18.2.0)"));
        assert!(Target::Hosted.repoints("_react@18.2.0"));
        assert!(!Target::Hosted.repoints("(react@18.2.0"));
        assert!(Target::Vendored.repoints(""));
        assert!(!Target::Vendored.repoints("(react@18.2.0)"));
        assert!(!Target::Vendored.repoints("_react@18.2.0"));
    }

    /// Divergence N16: hosted reads every lock but early shrinkwrap, while
    /// vendored keeps its refusal for every version its rekey was not
    /// captured against (target-specific).
    #[test]
    fn lock_versions_each_target_rewrites() {
        for (head, vendored) in [
            ("lockfileVersion: '9.0'\n", Some(PnpmLockGrammar::V9)),
            ("lockfileVersion: '6.0'\n", Some(PnpmLockGrammar::V60)),
            ("lockfileVersion: 5.4\n", Some(PnpmLockGrammar::V54)),
            ("lockfileVersion: 5.3\n", None),
            ("lockfileVersion: 5.1\n", None),
            ("lockfileVersion: '6.1'\n", None),
            ("lockfileVersion: '10.0'\n", None),
            ("shrinkwrapVersion: 3\nshrinkwrapMinorVersion: 9\n", None),
        ] {
            assert!(!hosted_refuses_lock(head), "{head}");
            assert_eq!(sniff_lock_grammar(head).ok(), vendored, "{head}");
        }
        assert!(hosted_refuses_lock("shrinkwrapVersion: 3\n"));
    }
}
