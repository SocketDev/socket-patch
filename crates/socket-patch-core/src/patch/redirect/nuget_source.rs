//! Placement helpers for the hosted nuget.config rewrite.
//!
//! NuGet discards every entry above a `<clear/>` in `<packageSources>` or
//! `<packageSourceMapping>` (the file's own and every inherited one), so an
//! entry the rewriter places before one is dropped: the Socket source goes
//! undefined (NU1100) or the patched id falls back to `*` on nuget.org while
//! the lock pins the patched contentHash (NU1403). Entries land after the
//! section's last `<clear/>`, or right after its open tag when it has none.

use std::sync::LazyLock;

use regex::Regex;

/// `<clear/>` in either form NuGet accepts (self-closing, or an empty
/// open/close pair), any whitespace.
static NUGET_CLEAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<clear\s*(?:/>|>\s*</clear\s*>)").expect("static clear regex is valid")
});

/// The offset to insert a section child at: just past the last `<clear/>`
/// between `open_end` (the end of the section's open tag) and the section's
/// close tag (`close_prefix`, e.g. `"</packageSources"`, so whitespace
/// before its `>` is tolerated), else `open_end` itself.
pub(super) fn child_insert_at(text: &str, open_end: usize, close_prefix: &str) -> usize {
    let body_end = text[open_end..]
        .find(close_prefix)
        .map_or(text.len(), |rel| open_end + rel);
    NUGET_CLEAR_RE
        .find_iter(&text[open_end..body_end])
        .last()
        .map_or(open_end, |m| open_end + m.end())
}

/// The part of a section body NuGet keeps: everything after its last
/// `<clear/>` (the whole body when it has none).
pub(super) fn after_last_clear(body: &str) -> &str {
    NUGET_CLEAR_RE
        .find_iter(body)
        .last()
        .map_or(body, |m| &body[m.end()..])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::{rewrite_registry_redirect, DepOverride};
    use super::*;

    const FIXTURES: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/redirect/nuget/packages-lock"
    );

    fn fixture(case: &str, rel: &str) -> String {
        std::fs::read_to_string(format!("{FIXTURES}/{case}/{rel}"))
            .unwrap_or_else(|e| panic!("{case}/{rel}: {e}"))
    }

    fn overrides(case: &str) -> Vec<DepOverride> {
        serde_json::from_str(&fixture(case, "overrides.json")).expect("fixture overrides parse")
    }

    /// Re-running over a golden's own output is a no-op: the Socket source
    /// after the `<clear/>` reads as wired, the lock is already pinned.
    #[test]
    fn rerun_over_clear_goldens_changes_nothing() {
        for case in [
            "clear-sources",
            "clear-mapping",
            "clear-both",
            "clear-sources-only-cleared",
        ] {
            let mut files = BTreeMap::new();
            for rel in ["nuget.config", "packages.lock.json"] {
                files.insert(rel.to_string(), fixture(case, &format!("expected/{rel}")));
            }
            let r = rewrite_registry_redirect(&files, &overrides(case));
            assert!(r.files.is_empty(), "{case}: {:?}", r.files.keys());
            assert!(r.edits.is_empty(), "{case}: {:?}", r.edits);
        }
    }

    /// A Socket source an older rewrite left ABOVE a `<clear/>` is not
    /// wired (NuGet drops it), so the re-run adds it again after the clear.
    #[test]
    fn socket_source_above_a_clear_is_rewired_after_it() {
        let case = "clear-sources";
        let stale = fixture(case, "expected/nuget.config").replace(
            "    <clear />\n    <add key=\"socket",
            "    <add key=\"socket",
        );
        let stale = stale.replacen(
            "    <add key=\"nuget.org\"",
            "    <clear />\n    <add key=\"nuget.org\"",
            1,
        );
        let mut files = BTreeMap::new();
        files.insert("nuget.config".to_string(), stale);
        let r = rewrite_registry_redirect(&files, &overrides(case));
        let out = r.files.get("nuget.config").expect("config rewritten");
        let clear = out.find("<clear />").expect("clear kept");
        let socket = out
            .rfind("<add key=\"socket-patch-")
            .expect("socket source");
        assert!(socket > clear, "{out}");
    }

    #[test]
    fn insert_point_is_the_open_tag_without_a_clear() {
        let text = "<packageSources>\n    <add key=\"a\" value=\"u\" />\n  </packageSources>";
        let open_end = "<packageSources>".len();
        assert_eq!(
            child_insert_at(text, open_end, "</packageSources"),
            open_end
        );
    }

    #[test]
    fn insert_point_follows_the_last_clear_in_the_section_only() {
        let text = "<packageSources>\n    <clear />\n    <clear></clear>\n    <add key=\"a\" \
                    value=\"u\" />\n  </packageSources>\n  <packageSourceMapping>\n    <clear/>";
        let open_end = "<packageSources>".len();
        let at = child_insert_at(text, open_end, "</packageSources");
        assert!(text[..at].ends_with("<clear></clear>"), "{}", &text[..at]);
    }

    #[test]
    fn insert_point_tolerates_a_missing_close_tag() {
        let text = "<packageSources>\n    <clear />\n";
        let at = child_insert_at(text, "<packageSources>".len(), "</packageSources");
        assert!(text[..at].ends_with("<clear />"));
    }

    #[test]
    fn kept_body_drops_everything_above_the_last_clear() {
        assert_eq!(
            after_last_clear("<add key=\"a\" /><clear /><add key=\"b\" />"),
            "<add key=\"b\" />"
        );
        assert_eq!(after_last_clear("<add key=\"a\" />"), "<add key=\"a\" />");
        assert_eq!(after_last_clear("<add key=\"a\" /><clear\n/>"), "");
    }
}
