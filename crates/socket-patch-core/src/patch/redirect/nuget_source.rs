//! Placement helpers for the hosted nuget.config rewrite.
//!
//! NuGet discards every entry above a `<clear/>` in `<packageSources>` or
//! `<packageSourceMapping>` (the file's own and every inherited one), so an
//! entry the rewriter places before one is dropped: the Socket source goes
//! undefined (NU1100) or the patched id falls back to `*` on nuget.org while
//! the lock pins the patched contentHash (NU1403). Entries land after the
//! section's last `<clear/>`, or right after its open tag when it has none.
//!
//! NuGet never reads a comment, so every anchor is found in the
//! comment-blanked view ([`visible`], same offsets as the text): a
//! commented-out section must not capture an edit, and a commented-out
//! `<add>` is not a source.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::vendor::nuget_config::CONFIG_NAMES;

/// `<clear/>` in either form NuGet accepts (self-closing, or an empty
/// open/close pair), any whitespace.
static NUGET_CLEAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<clear\s*(?:/>|>\s*</clear\s*>)").expect("static clear regex is valid")
});

/// `<packageSourceMapping>` open tag, any whitespace or attributes.
static NUGET_MAPPING_OPEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<packageSourceMapping(?:\s[^>]*)?>")
        .expect("static packageSourceMapping open-tag regex is valid")
});

/// `text` with every comment blanked to spaces, offsets preserved (the
/// vendored backend's reader).
pub(super) fn visible(text: &str) -> String {
    crate::vendor::nuget_feed::blank_comments(text)
}

/// The end of the first `<packageSourceMapping …>` open tag in `visible`
/// (a self-closing form has no children span and does not count), or
/// `None` when the config has no mapping section.
pub(super) fn mapping_open_end(visible: &str) -> Option<usize> {
    NUGET_MAPPING_OPEN_RE
        .find_iter(visible)
        .find(|m| !m.as_str().ends_with("/>"))
        .map(|m| m.end())
}

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

/// The `<add>` line for a package source. A plain-http source on a loopback
/// host (a local patch-server stand-in) opts into `allowInsecureConnections`:
/// NuGet 6.12+ (.NET SDK 9+) refuses every http source without it (NU1302).
/// Any other URL is written exactly as before.
pub(super) fn source_add_line(key: &str, url: &str) -> String {
    let opt_in = if is_http_loopback(url) {
        " allowInsecureConnections=\"true\""
    } else {
        ""
    };
    format!("    <add key=\"{key}\" value=\"{url}\"{opt_in} />")
}

/// Whether `url` is `http://` to `localhost`, an IPv4 loopback address or
/// `[::1]`.
fn is_http_loopback(url: &str) -> bool {
    let Some(scheme_end) = url.find("://") else {
        return false;
    };
    if !url[..scheme_end].eq_ignore_ascii_case("http") {
        return false;
    }
    let rest = &url[scheme_end + 3..];
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        match bracketed.split_once(']') {
            Some((host, _)) => {
                return host
                    .parse::<std::net::Ipv6Addr>()
                    .is_ok_and(|ip| ip.is_loopback());
            }
            None => return false,
        }
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The project's nuget.config to edit: the first of NuGet's per-directory
/// spellings present in `files` (the order NuGet itself reads them in), so
/// the edit lands in the file NuGet reads instead of a new `nuget.config`
/// shadowing it on a case-sensitive filesystem. `nuget.config` when the
/// project has none (the rewriter then creates it).
pub(super) fn config_rel<V>(files: &BTreeMap<String, V>) -> &'static str {
    CONFIG_NAMES
        .into_iter()
        .find(|name| files.contains_key(*name))
        .unwrap_or(CONFIG_NAMES[0])
}

#[cfg(test)]
mod tests {
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
    /// (after any `<clear/>`, outside comments, in whichever config spelling)
    /// reads as wired and the lock is already pinned.
    #[test]
    fn rerun_over_goldens_changes_nothing() {
        for case in [
            "clear-sources",
            "clear-mapping",
            "clear-both",
            "clear-sources-only-cleared",
            "http-loopback",
            "spelling-mixed-case",
            "spelling-title-case",
            "commented-mapping",
            "spaced-open-tag",
            "commented-sources",
        ] {
            let mut files = BTreeMap::new();
            let expected = format!("{FIXTURES}/{case}/expected");
            for entry in std::fs::read_dir(&expected).expect("golden expected dir") {
                let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                files.insert(name.clone(), fixture(case, &format!("expected/{name}")));
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
    fn mapping_open_tag_ignores_comments_and_self_closing_forms() {
        let at = |text: &str| mapping_open_end(&visible(text));
        assert_eq!(at("<configuration>\n</configuration>"), None);
        assert_eq!(at("<!-- <packageSourceMapping> -->"), None);
        assert_eq!(at("<packageSourceMapping />"), None);
        let spaced = "<!-- <packageSourceMapping> --><packageSourceMapping >";
        assert_eq!(at(spaced), Some(spaced.len()));
        let attrs = "<packageSourceMapping\n  a=\"b\">";
        assert_eq!(at(attrs), Some(attrs.len()));
    }

    #[test]
    fn config_rel_follows_nugets_read_order() {
        let files = |names: &[&str]| -> BTreeMap<String, ()> {
            names.iter().map(|n| (n.to_string(), ())).collect()
        };
        assert_eq!(config_rel(&files(&[])), "nuget.config");
        assert_eq!(config_rel(&files(&["NuGet.Config"])), "NuGet.Config");
        assert_eq!(
            config_rel(&files(&["NuGet.Config", "NuGet.config"])),
            "NuGet.config"
        );
        assert_eq!(
            config_rel(&files(&["NuGet.Config", "nuget.config", "NuGet.config"])),
            "nuget.config"
        );
    }

    /// With several spellings present only the one NuGet reads is edited,
    /// and no `nuget.config` is created beside it.
    #[test]
    fn only_the_config_nuget_reads_is_rewritten() {
        let case = "spelling-mixed-case";
        let mut files = BTreeMap::new();
        files.insert(
            "NuGet.config".to_string(),
            fixture(case, "input/NuGet.config"),
        );
        files.insert(
            "NuGet.Config".to_string(),
            "<configuration />\n".to_string(),
        );
        let r = rewrite_registry_redirect(&files, &overrides(case));
        let changed: Vec<&str> = r.files.keys().map(String::as_str).collect();
        assert_eq!(changed, ["NuGet.config"]);
        assert!(r
            .edits
            .iter()
            .filter(|e| e.kind == "redirect_nuget_source")
            .all(|e| e.path == "NuGet.config" && e.action == "rewritten"));
    }

    #[test]
    fn http_loopback_detection() {
        for url in [
            "http://127.0.0.1:4010/patch-registry/nuget/t/u/index.json",
            "HTTP://LOCALHOST/index.json",
            "http://localhost:80",
            "http://[::1]:8080/index.json",
            "http://user:pw@127.1.2.3/index.json",
        ] {
            assert!(is_http_loopback(url), "{url}");
        }
        for url in [
            "https://127.0.0.1/index.json",
            "https://patch.socket.dev/patch-registry/nuget/t/u/index.json",
            "http://patch.socket.dev/index.json",
            "http://localhost.example.com/index.json",
            "http://127.0.0.1.example.com/index.json",
            "http://10.0.0.1/index.json",
            "http://[::2]/index.json",
            "http://[::1/index.json",
            "http://127.0.0.1@evil.example/index.json",
            "localhost/index.json",
            "",
        ] {
            assert!(!is_http_loopback(url), "{url}");
        }
    }

    #[test]
    fn only_http_loopback_sources_opt_into_insecure_connections() {
        assert_eq!(
            source_add_line("k", "https://patch.socket.dev/i.json"),
            "    <add key=\"k\" value=\"https://patch.socket.dev/i.json\" />"
        );
        assert_eq!(
            source_add_line("k", "http://127.0.0.1:9/i.json"),
            "    <add key=\"k\" value=\"http://127.0.0.1:9/i.json\" \
             allowInsecureConnections=\"true\" />"
        );
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
