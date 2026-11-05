//! The pnpm planning core both modes share. Hosted ([`super::hosted`]) and
//! vendored (`vendor::pnpm_lock`, `vendor::pnpm_lock_legacy`) mode differ
//! only in where a rewired entry points ([`Target`]); this module owns what
//! they agree on:
//!
//! * which lock versions each target's edit has fixtures for
//!   ([`Target::check_lock`]);
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
use super::{sniff_lock_grammar, PnpmLockGrammar};
use crate::constants::npm_family::PNPM_LOCK;
use crate::formats::text::strip_bom;
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

impl Target {
    /// Whether this target's edit can rewrite a lock with `text`'s head,
    /// and in which grammar (`None`: the hosted splice reads every
    /// grammar the same way). Hosted takes every lock but pnpm 1's early
    /// shrinkwrap (shrinkwrapVersion 3 without a minor version), whose
    /// installers drop registry tarball URLs whatever the frozen flag says
    /// (verified with pnpm 1.0.0). Vendored takes the grammars its rekey was
    /// captured against (5.4, 6.0, 9.0): another version's `file:` override
    /// shape has no pnpm-blessed fixture, so it is refused,
    /// target-specifically (divergences N16).
    pub(crate) fn check_lock(self, text: &str) -> Result<Option<PnpmLockGrammar>, String> {
        if self == Target::Vendored {
            return sniff_lock_grammar(text).map(Some);
        }
        let field = |name: &str| strip_bom(text).lines().find_map(|l| l.strip_prefix(name));
        let early = field("shrinkwrapVersion:")
            .is_some_and(|v| v.trim().trim_matches(['\'', '"']) == "3")
            && !field("shrinkwrapMinorVersion:")
                .is_some_and(|v| v.trim().parse::<u32>().is_ok_and(|v| v > 0));
        match early {
            true => Err(format!(
                "{PNPM_LOCK} uses early pnpm 1 shrinkwrapVersion 3 without a supported \
                 minor version"
            )),
            false => Ok(None),
        }
    }

    /// Whether this target's edit repoints a registry instance whose key
    /// carries `suffix` after `name@version`. Hosted splices every peer
    /// context it can parse (pnpm 5's `_peer@1` or balanced `(peer@1)`
    /// groups); vendored rekeys the plain entry only, since a peer-suffixed
    /// rekey has no fixture and would dangle.
    pub(crate) fn repoints(self, suffix: &str) -> bool {
        if self == Target::Vendored || suffix.is_empty() || suffix.starts_with('_') {
            return suffix.is_empty() || self == Target::Hosted;
        }
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
            assert_eq!(Target::Hosted.check_lock(head), Ok(None), "{head}");
            assert_eq!(
                Target::Vendored.check_lock(head).ok().flatten(),
                vendored,
                "{head}"
            );
        }
        assert!(Target::Hosted.check_lock("shrinkwrapVersion: 3\n").is_err());
    }
}
