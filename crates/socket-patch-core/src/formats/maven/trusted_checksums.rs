//! Maven Trusted Checksums: the `.mvn/checksums/checksums.sha256` summary
//! file and the `.mvn/maven.config` switch that makes it a pin. Pure: text
//! in, text out. Discovery, the hosted rewriter and its unwind all read
//! both files through here, so what one writes the others read alike.
//!
//! The summary file is written in Maven's own grammar, `<sha256>  <path>`
//! (two spaces; maven-resolver's `SummaryFileTrustedChecksumsSource` splits
//! on exactly that, skips `#` and empty lines, and lets a later line for a
//! path win). It is READ tolerantly, as `sha256sum`-style tools emit it:
//! any run of spaces/tabs, an optional `*` binary marker, CRLF. A line that
//! is not an entry (a comment, a BSD-style line, anything else) is kept
//! byte-for-byte by [`edit`], never dropped.

use std::collections::{BTreeMap, BTreeSet};

use super::maven_config_properties;
use crate::utils::digest::sha256_hex;

/// The resolver property that switches the Trusted Checksums
/// post-processor on.
pub(crate) const SWITCH_KEY: &str = "aether.artifactResolver.postProcessor.trustedChecksums";

/// Whether `.mvn/maven.config` switches Trusted Checksums on, i.e. whether
/// the summary file is a pin at all.
///
/// The one rule discovery, the hosted rewriter and its unwind share:
/// `maven.config` is read the way [`maven_config_properties`] reads it
/// (Maven 3.9+: one argument per line, `#` comments, `-Dk=v` /
/// `--define`, `-Dk` alone meaning `true`, a later definition winning),
/// and the switch's value is then judged as the resolver judges it
/// (`ConfigUtils.getBoolean` → Java `Boolean.parseBoolean`: `true` in any
/// case, nothing else). Only Maven 3.9.4+ enforces the pin at all, and that
/// line reads `maven.config` per line, so a token the whitespace split of
/// older Maven finds counts only where no line sets the key.
pub(crate) fn switch_on(config: &str) -> bool {
    maven_config_properties(config)
        .get(SWITCH_KEY)
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// One entry line of the summary file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry<'a> {
    /// The hex sha256 as written (either case).
    pub(crate) hash: &'a str,
    /// The local-repository-relative path, without a `*` binary marker.
    pub(crate) path: &'a str,
    /// The line is exactly `<hash>  <path>`, the only shape Maven itself
    /// honours: any other spelling Maven skips, or reads as another path.
    pub(crate) maven_reads: bool,
}

/// `line` (its `\n` excluded; a trailing `\r` is tolerated) as an entry:
/// a 64-digit hex hash, a run of spaces/tabs, an optional `*`, a non-empty
/// path. Surrounding blanks are ignored. `None` for anything else.
pub(crate) fn parse_line(line: &str) -> Option<Entry<'_>> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    let blank = |c: char| c == ' ' || c == '\t';
    let trimmed = line.trim_matches(blank);
    let (hash, rest) = trimmed.split_at(trimmed.find(blank)?);
    let rest = rest.trim_start_matches(blank);
    let path = rest.strip_prefix('*').unwrap_or(rest);
    if path.is_empty() || sha256_hex(hash).is_none() {
        return None;
    }
    let maven_reads = line.strip_prefix(hash).and_then(|r| r.strip_prefix("  ")) == Some(path);
    Some(Entry {
        hash,
        path,
        maven_reads,
    })
}

/// Every entry of `text`, in file order (tolerant: see [`parse_line`]).
pub(crate) fn entries(text: &str) -> impl Iterator<Item = Entry<'_>> {
    text.split('\n').filter_map(parse_line)
}

/// `path -> lowercase sha256` of the entries Maven enforces: only lines it
/// reads ([`Entry::maven_reads`]), a later line for a path winning, as in
/// the resolver. A tolerated spelling is recognised (and replaced, or
/// dropped, by [`edit`]) but pins nothing, so nothing attests it.
pub(crate) fn pinned(text: &str) -> BTreeMap<String, String> {
    entries(text)
        .filter(|e| e.maven_reads)
        .filter_map(|e| Some((e.path.to_string(), sha256_hex(e.hash)?)))
        .collect()
}

/// `text` with every entry for a path in `set` rewritten in place to
/// `<hash>  <path>` (its own line ending kept), every other entry whose
/// path `drop` names removed, and the `set` paths it lacks inserted in
/// `<hash>  <path>` form: each before the first later entry whose path
/// sorts after it (so a sorted file stays sorted), else appended, with the
/// file's line ending (`\n` for a new file). Every other line (a comment,
/// a blank line, an unparseable line, another path's entry) is kept
/// byte-for-byte.
pub(crate) fn edit(text: &str, drop: impl Fn(&str) -> bool, set: &[(String, String)]) -> String {
    let set: BTreeMap<&str, &str> = set.iter().map(|(p, h)| (p.as_str(), h.as_str())).collect();
    let present: BTreeSet<&str> = entries(text)
        .map(|e| e.path)
        .filter(|p| set.contains_key(p))
        .collect();
    let mut pending: BTreeMap<&str, &str> = set
        .iter()
        .filter(|(p, _)| !present.contains(*p))
        .map(|(p, h)| (*p, *h))
        .collect();
    let eol = match text.find('\n') {
        Some(at) if text[..at].ends_with('\r') => "\r\n",
        _ => "\n",
    };
    let mut out = String::with_capacity(text.len() + 160 * pending.len());
    let mut flush_before = |out: &mut String, path: Option<&str>| {
        while let Some((p, h)) = pending.first_key_value() {
            if path.is_some_and(|path| path <= *p) {
                break;
            }
            if !out.is_empty() && !out.ends_with('\n') {
                out.push_str(eol);
            }
            out.push_str(&format!("{h}  {p}{eol}"));
            pending.pop_first();
        }
    };
    for line in text.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let Some(entry) = parse_line(body) else {
            out.push_str(line);
            continue;
        };
        if let Some(hash) = set.get(entry.path) {
            flush_before(&mut out, Some(entry.path));
            let ending = &line[body.trim_end_matches('\r').len()..];
            out.push_str(&format!("{hash}  {}{ending}", entry.path));
        } else if !drop(entry.path) {
            flush_before(&mut out, Some(entry.path));
            out.push_str(line);
        }
    }
    flush_before(&mut out, None);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn set(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(p, h)| (p.to_string(), h.to_string()))
            .collect()
    }

    #[test]
    fn parse_line_accepts_sha256sum_spellings() {
        let upper = A.to_uppercase();
        for (line, path, maven_reads) in [
            (format!("{A}  a/b.jar"), "a/b.jar", true),
            (format!("{A}  a/b.jar\r"), "a/b.jar", true),
            (format!("{A} a/b.jar"), "a/b.jar", false),
            (format!("{A} *a/b.jar"), "a/b.jar", false),
            (format!("{A}  *a/b.jar"), "a/b.jar", false),
            (format!("{A}\ta/b.jar"), "a/b.jar", false),
            (format!("{A}   a/b.jar"), "a/b.jar", false),
            (format!("  {A}  a/b.jar "), "a/b.jar", false),
            (format!("{upper}  a/b.jar"), "a/b.jar", true),
        ] {
            let entry = parse_line(&line).unwrap_or_else(|| panic!("{line:?}"));
            assert_eq!(entry.path, path, "{line:?}");
            assert_eq!(entry.maven_reads, maven_reads, "{line:?}");
        }
        for line in [
            String::new(),
            "# comment".into(),
            format!("#{A}  a/b.jar"),
            A.to_string(),
            format!("{A}  "),
            format!("{A}  *"),
            format!("{}  a/b.jar", &A[1..]),
            format!("SHA256 (a/b.jar) = {A}"),
        ] {
            assert_eq!(parse_line(&line), None, "{line:?}");
        }
    }

    #[test]
    fn pinned_keeps_only_what_maven_reads_last_line_winning() {
        let upper = B.to_uppercase();
        let text =
            format!("# header\r\n{A}  x.jar\r\n{A} y.jar\n{A} *z.jar\n{B}  x.jar\n{upper}  w.jar");
        assert_eq!(
            pinned(&text),
            BTreeMap::from([
                ("w.jar".to_string(), B.to_string()),
                ("x.jar".to_string(), B.to_string()),
            ])
        );
        assert_eq!(
            entries(&text).map(|e| e.path).collect::<Vec<_>>(),
            ["x.jar", "y.jar", "z.jar", "x.jar", "w.jar"]
        );
    }

    #[test]
    fn edit_round_trips_untouched_text_byte_for_byte() {
        for text in [
            String::new(),
            "\n\n".into(),
            format!("# keep\r\n{A} *one.jar\r\n\r\nnot an entry\r\n{B}\ttwo.jar"),
            format!("{B}  z.jar\n{A}  a.jar\n"),
        ] {
            assert_eq!(edit(&text, |_| false, &[]), text);
            assert_eq!(edit(&text, |p| p == "absent.jar", &[]), text);
        }
    }

    #[test]
    fn edit_keeps_every_line_it_does_not_own() {
        // A user's single-space, `*` and tab lines, a comment and a stray
        // line, around one of ours being replaced and one being added.
        let text = format!(
            "# pins\n{A} c/user.jar\n{A} *d/user.jar\n{A}\te/user.jar\ngarbage\n{A}  m/ours.jar\n"
        );
        let out = edit(
            &text,
            |p| p == "never.jar",
            &set(&[("m/ours.jar", B), ("b/new.jar", B)]),
        );
        assert_eq!(
            out,
            format!(
                "# pins\n{B}  b/new.jar\n{A} c/user.jar\n{A} *d/user.jar\n{A}\te/user.jar\n\
                 garbage\n{B}  m/ours.jar\n"
            )
        );
        // Idempotent: a second pass changes nothing.
        assert_eq!(
            edit(
                &out,
                |_| false,
                &set(&[("m/ours.jar", B), ("b/new.jar", B)])
            ),
            out
        );
    }

    #[test]
    fn edit_replaces_a_tolerated_spelling_of_an_owned_path_in_place() {
        let text = format!("{A} *m/ours.jar\r\nkeep\r\n");
        assert_eq!(
            edit(&text, |_| false, &set(&[("m/ours.jar", B)])),
            format!("{B}  m/ours.jar\r\nkeep\r\n")
        );
    }

    #[test]
    fn edit_drops_only_named_entries_and_keeps_line_endings() {
        let text = format!("{A}  gone.jar\r\n# note\r\n{A} kept.jar\r\n{B} *gone.jar\r\n");
        assert_eq!(
            edit(&text, |p| p == "gone.jar", &[]),
            format!("# note\r\n{A} kept.jar\r\n")
        );
    }

    #[test]
    fn edit_appends_with_the_file_line_ending_after_an_unterminated_line() {
        assert_eq!(
            edit(
                &format!("{A}  a.jar\r\nlast"),
                |_| false,
                &set(&[("z.jar", B)])
            ),
            format!("{A}  a.jar\r\nlast\r\n{B}  z.jar\r\n")
        );
        assert_eq!(
            edit("", |_| false, &set(&[("z.jar", B), ("a.jar", A)])),
            format!("{A}  a.jar\n{B}  z.jar\n")
        );
    }

    #[test]
    fn switch_follows_maven_config_reading() {
        let on = format!("-D{SWITCH_KEY}=true");
        for (config, want) in [
            (on.clone(), true),
            (format!("{on}\r\n"), true),
            (format!("  {on}  "), true),
            (format!("-D{SWITCH_KEY}"), true),
            (format!("-D{SWITCH_KEY}=TRUE"), true),
            (format!("--define={SWITCH_KEY}=true"), true),
            (format!("-B -D{SWITCH_KEY}=true"), true),
            (format!("{on}\n-D{SWITCH_KEY}=false"), false),
            (format!("-D{SWITCH_KEY}=false\n{on}"), true),
            (format!("# {on}"), false),
            (format!("-D{SWITCH_KEY}=yes"), false),
            (format!("-D{SWITCH_KEY}.failIfMissing=true"), false),
            (String::new(), false),
        ] {
            assert_eq!(switch_on(&config), want, "{config:?}");
        }
    }
}
