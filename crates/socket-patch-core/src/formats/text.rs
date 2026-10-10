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

/// U+FEFF, the character a UTF-8 BOM decodes to.
pub const BOM: char = '\u{feff}';

/// `(bom, rest)`: a leading UTF-8 BOM split off (`""` when there is none),
/// so an edit can read `rest` and restore `bom` byte-exact on write.
pub fn split_bom(text: &str) -> (&'static str, &str) {
    match text.strip_prefix(BOM) {
        Some(rest) => ("\u{feff}", rest),
        None => ("", text),
    }
}

/// `text` without a leading UTF-8 BOM.
pub fn strip_bom(text: &str) -> &str {
    split_bom(text).1
}

/// [`strip_bom`] for bytes not yet decoded: drops one leading `EF BB BF`.
pub fn strip_bom_bytes(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes)
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

    #[test]
    fn strip_bom_bytes_drops_one_leading_bom_only() {
        assert_eq!(strip_bom_bytes(b"\xef\xbb\xbfx"), b"x");
        assert_eq!(strip_bom_bytes(b"x\xef\xbb\xbf"), b"x\xef\xbb\xbf");
        assert_eq!(
            strip_bom_bytes(b"\xef\xbb\xbf\xef\xbb\xbfx"),
            b"\xef\xbb\xbfx"
        );
        assert_eq!(strip_bom_bytes(b"\xef\xbbx"), b"\xef\xbbx");
        for text in ["", "x", "\u{feff}x", "\u{feff}\u{feff}x"] {
            assert_eq!(strip_bom_bytes(text.as_bytes()), strip_bom(text).as_bytes());
        }
    }

    /// Production files that still spell out BOM handling inline, waiting
    /// on #905 step 3 (they are changed by open PRs). Drop a file when you
    /// move it onto the helpers above.
    const PENDING_INLINE_BOMS: &[&str] = &[
        "patch/redirect/mod.rs",
        "patch/redirect/upstream/pypi.rs",
        "vendor/yarn_classic_lock.rs",
        "vex/discover/yarn.rs",
    ];

    /// Files whose inline BOM handling is deliberate, not a copy of the rule.
    const OWN_BOM_RULE: &[&str] = &[
        // `sbt_version` reads a Java properties file line by line and skips
        // a BOM on any line (its test pins a BOM after a comment line).
        "formats/sbt/build.rs",
        // An owned sbt file with any leading BOM is `Modified`, never
        // `Foreign`: the parser refuses to claim a file someone re-saved.
        "formats/sbt/owned_file.rs",
        // Output sanitizing drops U+FEFF anywhere as an invisible
        // formatting character; it is not a leading-BOM rule.
        "policy/mod.rs",
        // vlt cannot read a BOM lock, so the sniff refuses it unstripped.
        "vendor/vlt_lock_text.rs",
    ];

    /// No new production file decides for itself what a leading BOM is: it
    /// calls `split_bom`, `strip_bom` or `strip_bom_bytes`. The guard is
    /// one-sided (a pending file that loses its last inline BOM does not
    /// fail it), so another PR that migrates a file can never turn it red.
    /// Test modules and test-support files are exempt: fixtures spell BOMs.
    #[test]
    fn production_bom_handling_goes_through_the_helpers() {
        const INLINE: &[&str] = &[
            "\\u{feff}",
            "\\u{FEFF}",
            "0xEF, 0xBB, 0xBF",
            "0xef, 0xbb, 0xbf",
            "\\xef\\xbb\\xbf",
            "\\xEF\\xBB\\xBF",
        ];
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        let mut inline = Vec::new();
        for path in files {
            let rel = path
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "formats/text.rs"
                || rel.ends_with("tests.rs")
                || rel.contains("test_support")
                || PENDING_INLINE_BOMS.contains(&rel.as_str())
                || OWN_BOM_RULE.contains(&rel.as_str())
            {
                continue;
            }
            // Windows CI checks out with CRLF.
            let text = std::fs::read_to_string(&path)
                .unwrap()
                .replace("\r\n", "\n");
            let production = [
                "#[cfg(test)]\nmod tests",
                "#[cfg(test)]\npub(crate) mod tests",
                "#[cfg(test)]\nmod architecture_tests",
            ]
            .iter()
            .filter_map(|marker| text.find(marker))
            .min()
            .map_or(text.as_str(), |at| &text[..at]);
            if INLINE.iter().any(|p| production.contains(p)) {
                inline.push(rel);
            }
        }
        inline.sort();
        assert!(
            inline.is_empty(),
            "these files handle a UTF-8 BOM inline: {inline:?}. Call \
             crate::formats::text::{{split_bom, strip_bom, strip_bom_bytes}} \
             instead (#905). Do not add them to PENDING_INLINE_BOMS."
        );
    }
}
