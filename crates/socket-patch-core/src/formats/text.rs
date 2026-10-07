//! The one rule every text reader shares: a leading UTF-8 byte-order mark
//! is encoding, not content (#905).
//!
//! The package managers whose files socket-patch reads strip it before they
//! parse (npm and Node for package.json, pnpm's and yarn's YAML parsers,
//! cargo, Bundler, Gradle), and Windows editors that save "UTF-8 with
//! signature" add it. A reader that matches a column-0 literal
//! (`lockfileVersion:`, a top-level YAML key) or hands the text to a strict
//! parser (serde_json) must therefore skip it first, and an editor that
//! rewrites the file must put it back. Exactly one BOM is encoding; a
//! second one is content, as for every tool above.

/// `(bom, rest)`: a leading UTF-8 BOM split off (`""` when there is none),
/// so an edit can read `rest` and restore `bom` byte-exact on write.
pub fn split_bom(text: &str) -> (&str, &str) {
    match text.strip_prefix('\u{feff}') {
        Some(rest) => ("\u{feff}", rest),
        None => ("", text),
    }
}

/// `text` without a leading UTF-8 BOM.
pub fn strip_bom(text: &str) -> &str {
    split_bom(text).1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_bom_splits_exactly_one_bom() {
        assert_eq!(split_bom("\u{feff}a: 1\n"), ("\u{feff}", "a: 1\n"));
        assert_eq!(split_bom("a: 1\n"), ("", "a: 1\n"));
        assert_eq!(split_bom("\u{feff}\u{feff}a"), ("\u{feff}", "\u{feff}a"));
        assert_eq!(split_bom(""), ("", ""));
    }

    #[test]
    fn strip_bom_drops_one_leading_bom_only() {
        assert_eq!(strip_bom("\u{feff}x"), "x");
        assert_eq!(strip_bom("x\u{feff}"), "x\u{feff}");
        assert_eq!(strip_bom("\u{feff}\u{feff}x"), "\u{feff}x");
    }
}
