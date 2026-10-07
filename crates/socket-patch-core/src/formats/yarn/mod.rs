//! `yarn.lock`, classic (v1) and berry (v2+): the one grammar every
//! reader and writer of the file shares.
//!
//! * which grammar a lock is ([`sniff_grammar`], [`is_berry_lock`]);
//! * the block walk and field reads ([`blocks`]);
//! * key, descriptor and locator patterns ([`patterns`]);
//! * where yarn 1 installs a block's copy from ([`source`]);
//! * the berry pinned-entry renderer ([`berry_entry`]).
//!
//! The vendored backends (`vendor::yarn_classic_lock`,
//! `vendor::yarn_berry_lock`), the hosted rewriters and restorers
//! (`patch::redirect`), the lock inventory and lockfile discovery all read
//! the lock through these, so they cannot disagree on it.

pub(crate) mod berry_entry;
pub mod berry_gates;
pub(crate) mod blocks;
pub(crate) mod patterns;
pub(crate) mod source;

use super::text::strip_bom;

/// Which grammar a `yarn.lock` head declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YarnLockGrammar {
    /// A column-0 `__metadata:` key (yarn >= 2).
    Berry,
    /// The `# yarn lockfile v1` comment header.
    Classic,
}

/// How many head lines [`sniff_grammar`] reads.
const SNIFF_HEAD_LINES: usize = 30;

/// Why [`sniff_grammar`] found neither grammar, for the refusal detail.
pub const UNIDENTIFIED_DETAIL: &str = "yarn.lock carries neither the `# yarn lockfile v1` \
     header nor a berry `__metadata:` key; cannot identify the lockfile version";

/// The head sniff: berry when one of the first lines is a column-0
/// `__metadata:` key, else classic when one is the `# yarn lockfile v1`
/// header, else `None`. Berry wins the check — a berry lock must never be
/// mistaken for classic. CRLF lines split like LF ones; a leading BOM is
/// not key text.
pub fn sniff_grammar(text: &str) -> Option<YarnLockGrammar> {
    let head: Vec<&str> = strip_bom(text).lines().take(SNIFF_HEAD_LINES).collect();
    if head.iter().any(|l| l.starts_with("__metadata:")) {
        Some(YarnLockGrammar::Berry)
    } else if head.iter().any(|l| l.trim() == "# yarn lockfile v1") {
        Some(YarnLockGrammar::Classic)
    } else {
        None
    }
}

/// A yarn.lock is berry (v2+) when ANY line carries the `__metadata:`
/// header key; anything else is a classic v1 lock. The whole-file check
/// both hosted rewriters, lockfile discovery and the classic vendored
/// backend's refusal gate share. A leading BOM is encoding, not key text
/// (yarn's YAML parser drops it), so a header-less lock opening with
/// `\u{feff}__metadata:` is berry too.
pub fn is_berry_lock(content: &str) -> bool {
    strip_bom(content)
        .lines()
        .any(|line| line.starts_with("__metadata:"))
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
        let deep = format!("{}# yarn lockfile v1\n", "\n".repeat(SNIFF_HEAD_LINES));
        assert_eq!(sniff_grammar(&deep), None);
    }

    #[test]
    fn is_berry_lock_reads_the_whole_file_and_skips_a_bom() {
        assert!(is_berry_lock("\u{feff}__metadata:\n"));
        let deep = format!("{}__metadata:\n", "\n".repeat(100));
        assert!(is_berry_lock(&deep));
        assert!(!is_berry_lock("# yarn lockfile v1\n  __metadata:\n"));
    }
}
