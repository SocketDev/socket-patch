//! `yarn.lock`, classic (v1) and berry (v2+): the one grammar every
//! reader and writer of the file shares.
//!
//! * which grammar a lock is ([`sniff_grammar`], [`is_berry_lock`]);
//! * the block walk and field reads ([`blocks`]);
//! * a classic block's dependency sub-maps against a patched manifest
//!   ([`classic_deps`]);
//! * key, descriptor and locator patterns ([`patterns`]);
//! * where yarn 1 installs a block's copy from ([`source`]);
//! * the stanza view the hosted berry writers re-key and re-order
//!   entries in ([`stanzas`]);
//! * the berry pinned-entry renderer ([`berry_entry`]) and the walk that
//!   drops the entries a pin leaves unreachable ([`berry_prune`]).
//!
//! The vendored backends (`vendor::yarn_classic_lock`,
//! `vendor::yarn_berry_lock`), the hosted rewriters and restorers
//! (`patch::redirect`), the lock inventory and lockfile discovery all read
//! the lock through these, so they cannot disagree on it.

pub(crate) mod berry_entry;
pub mod berry_gates;
pub(crate) mod berry_prune;
pub(crate) mod blocks;
pub(crate) mod classic_deps;
pub(crate) mod patterns;
pub(crate) mod source;
pub(crate) mod stanzas;

use super::text::strip_bom;

/// Which grammar a `yarn.lock` head declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YarnLockGrammar {
    /// A column-0 `__metadata:` key (yarn >= 2).
    Berry,
    /// The `# yarn lockfile v1` comment header.
    Classic,
}

/// Why [`sniff_grammar`] found neither grammar, for the refusal detail.
pub const UNIDENTIFIED_DETAIL: &str = "yarn.lock carries neither the `# yarn lockfile v1` \
     header nor a berry `__metadata:` key; cannot identify the lockfile version";

/// The ONE grammar decision: berry when any line is a column-0
/// `__metadata:` key, else classic when any line is the `# yarn lockfile v1`
/// header, else `None` (a header-less lock). Berry wins — a berry lock must
/// never be read as classic. CRLF lines split like LF ones; a leading BOM
/// is not key text (yarn's parsers drop it).
///
/// What a header-less lock is depends on what the caller does with it:
/// the vendored router, which must know the grammar it writes, refuses
/// `None` (`vendor_lockfile_version_unsupported`); every reader takes
/// [`grammar`]'s answer, classic — what yarn 1 parses it as, and what yarn
/// berry migrates it from.
pub fn sniff_grammar(text: &str) -> Option<YarnLockGrammar> {
    let mut classic = false;
    for line in strip_bom(text).lines() {
        if line.starts_with("__metadata:") {
            return Some(YarnLockGrammar::Berry);
        }
        classic |= line.trim() == "# yarn lockfile v1";
    }
    classic.then_some(YarnLockGrammar::Classic)
}

/// [`sniff_grammar`] with a header-less lock read as classic.
pub fn grammar(text: &str) -> YarnLockGrammar {
    sniff_grammar(text).unwrap_or(YarnLockGrammar::Classic)
}

/// Whether [`grammar`] says berry: the check both hosted rewriters, the
/// hosted restore, lockfile discovery and the classic vendored backend's
/// refusal gate share.
pub fn is_berry_lock(content: &str) -> bool {
    grammar(content) == YarnLockGrammar::Berry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniff_prefers_berry_and_skips_a_bom() {
        assert_eq!(
            sniff_grammar("__metadata:\n  version: 8\n"),
            Some(YarnLockGrammar::Berry)
        );
        assert_eq!(
            sniff_grammar("\u{feff}# yarn lockfile v1\r\n"),
            Some(YarnLockGrammar::Classic)
        );
        assert_eq!(
            sniff_grammar("# yarn lockfile v1\n__metadata:\n"),
            Some(YarnLockGrammar::Berry)
        );
        assert_eq!(sniff_grammar("a@1:\n  version \"1\"\n"), None);
        assert_eq!(grammar("a@1:\n  version \"1\"\n"), YarnLockGrammar::Classic);
    }

    /// B60: the vendored router (`sniff_grammar`) and every reader
    /// (`is_berry_lock`) take one decision, wherever in the file the marker
    /// sits. They used to disagree: the router read only the first 30 lines,
    /// so a classic header above a hand-merged `__metadata:` key was classic
    /// to vendor and berry to hosted, restore and VEX.
    #[test]
    fn the_router_and_the_readers_agree_on_a_deep_marker() {
        let padding = "\n".repeat(40);
        let merged = format!("# yarn lockfile v1\n{padding}__metadata:\n  version: 8\n");
        assert_eq!(sniff_grammar(&merged), Some(YarnLockGrammar::Berry));
        assert!(is_berry_lock(&merged));
        let deep_header = format!("{padding}# yarn lockfile v1\n");
        assert_eq!(sniff_grammar(&deep_header), Some(YarnLockGrammar::Classic));
        assert!(!is_berry_lock(&deep_header));
    }

    #[test]
    fn is_berry_lock_reads_the_whole_file_and_skips_a_bom() {
        assert!(is_berry_lock("\u{feff}__metadata:\n"));
        let deep = format!("{}__metadata:\n", "\n".repeat(100));
        assert!(is_berry_lock(&deep));
        assert!(!is_berry_lock("# yarn lockfile v1\n  __metadata:\n"));
    }
}
