//! Maven Trusted Checksums: the `.mvn/checksums/checksums.sha256` summary
//! file, the `.mvn/maven.config` settings that make Maven read it, and the
//! Maven release that enforces it. Pure: text in, text out. Discovery, the
//! hosted rewriter and its unwind all judge both files through here, so
//! what one writes, the others read and judge alike.
//!
//! The summary file is written in Maven's own grammar, `<sha256>  <path>`
//! (lowercase hex, two spaces). maven-resolver's
//! `SummaryFileTrustedChecksumsSource` splits on exactly two spaces, skips
//! `#` and empty lines, lets a later line for a path win, and compares the
//! hash to its own lowercase hex. It is READ tolerantly, as
//! `sha256sum`-style tools write it: any run of spaces/tabs, an optional
//! `*` binary marker, CRLF. [`edit`] keeps a line it does not own
//! byte-for-byte, never drops it.

use std::collections::{BTreeMap, BTreeSet};

use super::maven_config_line_properties;
use crate::utils::digest::{is_hex64_lower, sha256_hex};

// One literal per settings prefix, so the args written and the keys read
// cannot drift apart.
macro_rules! post_processor {
    () => {
        "aether.artifactResolver.postProcessor.trustedChecksums"
    };
}
macro_rules! summary_file {
    () => {
        "aether.trustedChecksumsSource.summaryFile"
    };
}
macro_rules! basedir {
    () => {
        "${session.rootDirectory}/.mvn/checksums"
    };
}

/// The resolver property that switches the Trusted Checksums
/// post-processor on.
pub(crate) const SWITCH_KEY: &str = post_processor!();
const ALGORITHMS_KEY: &str = concat!(post_processor!(), ".checksumAlgorithms");
const SUMMARY_FILE_KEY: &str = summary_file!();
const BASEDIR_KEY: &str = concat!(summary_file!(), ".basedir");
const ORIGIN_AWARE_KEY: &str = concat!(summary_file!(), ".originAware");

/// The `.mvn/maven.config` lines hosted mode writes, one argument each:
/// the post-processor on, checking SHA-256, `failIfMissing=false` (a
/// dependency without a committed checksum still resolves; only a MISMATCH
/// fails), and the summary-file source on, at `.mvn/checksums`, origin
/// unaware (one checksum matches the artifact from any repository).
pub(crate) const CONFIG_ARGS: &[&str] = &[
    concat!("-D", post_processor!(), "=true"),
    concat!("-D", post_processor!(), ".checksumAlgorithms=SHA-256"),
    concat!("-D", post_processor!(), ".failIfMissing=false"),
    concat!("-D", summary_file!(), "=true"),
    concat!("-D", summary_file!(), ".basedir=", basedir!()),
    concat!("-D", summary_file!(), ".originAware=false"),
];

/// Whether `.mvn/maven.config` makes Maven check artifacts against
/// `.mvn/checksums/checksums.sha256` — the one rule every mode shares.
///
/// `maven.config` is read as Maven 3.9+ reads it (the only line that
/// enforces Trusted Checksums at all): one argument per LINE, `#`
/// comments, `-Dk=v` / `--define`, `-Dk` alone meaning `true`, a later
/// definition winning ([`maven_config_line_properties`]); a `-Dk=v` token
/// inside a longer line is not an argument there. Each setting is then
/// judged as the resolver judges it, with its default when unset:
/// - the post-processor on (`ConfigUtils.getBoolean`, i.e. Java
///   `Boolean.parseBoolean`: `true` in any case; default off);
/// - its comma-separated `checksumAlgorithms` naming `SHA-256` (default
///   `SHA-1`, which never reads a `.sha256` file);
/// - the summary-file source on (default off);
/// - its `basedir` exactly the `.mvn/checksums` hosted mode writes (the
///   default is `.checksums` under the local repository; any other value is
///   not this file);
/// - `originAware` off (default on, which reads a per-repository
///   `checksums-<repo id>.sha256` instead).
///
/// `failIfMissing` does not decide whether a committed line is checked.
pub(crate) fn config_enforces(config: &str) -> bool {
    let props = maven_config_line_properties(config);
    let get = |key: &str| props.get(key).map(String::as_str);
    let is_true = |key: &str| get(key).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    is_true(SWITCH_KEY)
        && get(ALGORITHMS_KEY).is_some_and(|v| v.split(',').any(|a| a.trim() == "SHA-256"))
        && is_true(SUMMARY_FILE_KEY)
        && get(BASEDIR_KEY) == Some(basedir!())
        && get(ORIGIN_AWARE_KEY).is_some_and(|v| !v.eq_ignore_ascii_case("true"))
}

/// Whether any setting hosted mode writes is present in `config` (read as
/// [`config_enforces`] reads it), whatever its value.
pub(crate) fn config_has_written_settings(config: &str) -> bool {
    let props = maven_config_line_properties(config);
    CONFIG_ARGS
        .iter()
        .filter_map(|arg| arg.strip_prefix("-D")?.split_once('='))
        .any(|(key, _)| props.contains_key(key))
}

/// The first Maven release that enforces the `.mvn/*` Trusted Checksums
/// files (#258). 3.9.0 / 3.9.1 do not interpolate `${session.rootDirectory}`
/// in `maven.config`, so the summary file is never found; 3.9.2 / 3.9.3
/// ignore `checksumAlgorithms=SHA-256` and check SHA-1 only. Older lines have
/// no Trusted Checksums post-processor at all.
const MIN_MAVEN: [u32; 3] = [3, 9, 4];

/// The Apache Maven release a `maven-wrapper.properties` pins, taken from its
/// `distributionUrl` (`…/apache-maven-<version>-bin.zip` or `.tar.gz`). None
/// for a missing key or any other distribution (e.g. mvnd), which is then
/// taken to enforce.
pub(crate) fn wrapper_maven_version(props: &str) -> Option<String> {
    props.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('!') {
            return None;
        }
        let rest = line.strip_prefix("distributionUrl")?;
        if !rest.starts_with(|c: char| c == '=' || c == ':' || c.is_whitespace()) {
            return None;
        }
        let value = rest
            .trim_start()
            .strip_prefix(['=', ':'])
            .unwrap_or(rest)
            .trim();
        let file = value.rsplit('/').next()?;
        let version = file
            .strip_prefix("apache-maven-")?
            .strip_suffix(".zip")
            .or_else(|| file.strip_prefix("apache-maven-")?.strip_suffix(".tar.gz"))?
            .strip_suffix("-bin")?;
        (!version.is_empty()).then(|| version.to_string())
    })
}

/// Whether Maven `version` enforces the Trusted Checksums files (≥ 3.9.4;
/// pre-release suffixes such as `-rc-6` compare as their release).
pub(crate) fn maven_enforces(version: &str) -> bool {
    let mut parts = [0u32; 3];
    for (slot, part) in parts.iter_mut().zip(version.split(['.', '-'])) {
        *slot = part.parse().unwrap_or(0);
    }
    parts >= MIN_MAVEN
}

/// Whether the summary file is an enforced pin: [`config_enforces`], and a
/// Maven Wrapper (`wrapper`, its properties) that names no Apache Maven
/// release older than 3.9.4. No wrapper, or one naming another
/// distribution, is taken to enforce — the hosted rewriter's rule, which
/// warns only on a release it can name.
pub(crate) fn enforced(config: &str, wrapper: Option<&str>) -> bool {
    config_enforces(config)
        && wrapper
            .and_then(wrapper_maven_version)
            .is_none_or(|v| maven_enforces(&v))
}

/// One non-comment line of the summary file, read as two fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry<'a> {
    /// The first field as written (a hash, or whatever stands there).
    pub(crate) hash: &'a str,
    /// The local-repository-relative path, without a `*` binary marker.
    pub(crate) path: &'a str,
    /// The line is exactly `<64 lowercase hex>  <path>`, the only shape
    /// Maven checks an artifact against: any other spelling Maven skips,
    /// reads as another path, or fails the build on (an uppercase hash never
    /// equals its lowercase digest).
    pub(crate) maven_reads: bool,
}

/// Whether `line` (its `\n` excluded) is a comment, which Maven skips.
fn is_comment(line: &str) -> bool {
    line.trim_start_matches([' ', '\t']).starts_with('#')
}

/// `line` (its `\n` excluded; a trailing `\r` is tolerated) as an entry:
/// a first field, a run of spaces/tabs, an optional `*`, a non-empty path;
/// surrounding blanks ignored. The first field need not be a valid hash, so
/// a line for a path hosted mode owns is recognised (and replaced or
/// dropped) whatever its hash. `None` for a comment, a blank line, or a
/// single field.
pub(crate) fn parse_line(line: &str) -> Option<Entry<'_>> {
    let line = line.strip_suffix('\r').unwrap_or(line);
    if is_comment(line) {
        return None;
    }
    let blank = |c: char| c == ' ' || c == '\t';
    let trimmed = line.trim_matches(blank);
    let (hash, rest) = trimmed.split_at(trimmed.find(blank)?);
    let rest = rest.trim_start_matches(blank);
    let path = rest.strip_prefix('*').unwrap_or(rest);
    if path.is_empty() {
        return None;
    }
    let maven_reads = is_hex64_lower(hash)
        && line.strip_prefix(hash).and_then(|r| r.strip_prefix("  ")) == Some(path);
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

/// `path -> sha256` of the entries Maven checks: only lines it reads
/// ([`Entry::maven_reads`]), a later line for a path winning, as in the
/// resolver. A tolerated spelling is recognised (and replaced, or dropped,
/// by [`edit`]) but pins nothing, so nothing attests it.
pub(crate) fn pinned(text: &str) -> BTreeMap<String, String> {
    entries(text)
        .filter(|e| e.maven_reads)
        .map(|e| (e.path.to_string(), e.hash.to_string()))
        .collect()
}

/// The line ending most of `text`'s lines use (`\n` on a tie or none), so
/// an inserted line never adds an ending the file does not mostly use.
fn dominant_eol(text: &str) -> &'static str {
    let crlf = text.matches("\r\n").count();
    if crlf * 2 > text.matches('\n').count() {
        "\r\n"
    } else {
        "\n"
    }
}

/// `text` with the entries for the paths in `set` (`(path, sha256)`, the
/// hash 64 lowercase hex) made `<hash>  <path>`, and every other entry
/// whose path `drop` names removed.
///
/// A `set` path the file already names is rewritten where it first stands
/// (that line's ending kept) and any later line for it removed. One it
/// lacks is inserted before the first later checksum line whose path sorts
/// after it — ahead of the comment block directly above that line, which
/// stays with it — so a sorted file stays sorted; else appended. An
/// inserted line takes the file's dominant line ending. Every other line (a
/// comment, a blank line, an unparseable line, another path's entry in any
/// spelling) is kept byte-for-byte.
pub(crate) fn edit(text: &str, drop: impl Fn(&str) -> bool, set: &[(String, String)]) -> String {
    debug_assert!(set.iter().all(|(_, h)| is_hex64_lower(h)), "{set:?}");
    let set: BTreeMap<&str, &str> = set.iter().map(|(p, h)| (p.as_str(), h.as_str())).collect();
    // Which owned paths the file already names decides where each goes, so
    // it is known before the first line is written.
    let present: BTreeSet<&str> = entries(text)
        .map(|e| e.path)
        .filter(|p| set.contains_key(p))
        .collect();
    let mut pending: BTreeMap<&str, &str> = set
        .iter()
        .filter(|(p, _)| !present.contains(*p))
        .map(|(p, h)| (*p, *h))
        .collect();
    let eol = dominant_eol(text);
    let push_entry = |out: &mut String, hash: &str, path: &str, ending: &str| {
        out.push_str(hash);
        out.push_str("  ");
        out.push_str(path);
        out.push_str(ending);
    };
    let mut out = String::with_capacity(text.len() + 160 * pending.len());
    let mut written: BTreeSet<&str> = BTreeSet::new();
    // The comment lines directly above the line not yet reached.
    let mut held = String::new();
    for line in text.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        if is_comment(body) {
            held.push_str(line);
            continue;
        }
        let entry = parse_line(body);
        if let Some(e) = entry.as_ref().filter(|e| sha256_hex(e.hash).is_some()) {
            while let Some((p, h)) = pending.first_key_value().filter(|(p, _)| **p < e.path) {
                push_entry(&mut out, h, p, eol);
                pending.pop_first();
            }
        }
        out.push_str(&held);
        held.clear();
        match entry {
            Some(e) if set.contains_key(e.path) => {
                if written.insert(e.path) {
                    let ending = &line[body.trim_end_matches('\r').len()..];
                    push_entry(&mut out, set[e.path], e.path, ending);
                }
            }
            Some(e) if drop(e.path) => {}
            _ => out.push_str(line),
        }
    }
    out.push_str(&held);
    for (p, h) in pending {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(eol);
        }
        push_entry(&mut out, h, p, eol);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const OURS: &str = "org/x/1.0-socket.aaaaaaaa/x-1.0-socket.aaaaaaaa.jar";

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
            // maven-resolver compares against its lowercase digest: an
            // uppercase line fails the build, it pins nothing.
            (format!("{upper}  a/b.jar"), "a/b.jar", false),
            // A truncated or SRI hash is still a line for its path.
            (format!("{}  a/b.jar", &A[1..]), "a/b.jar", false),
            ("sha256-q83vEjRWeJA=  a/b.jar".to_string(), "a/b.jar", false),
        ] {
            let entry = parse_line(&line).unwrap_or_else(|| panic!("{line:?}"));
            assert_eq!(entry.path, path, "{line:?}");
            assert_eq!(entry.maven_reads, maven_reads, "{line:?}");
        }
        for line in [
            String::new(),
            "# comment".into(),
            format!("#{A}  a/b.jar"),
            format!(" # {A}  a/b.jar"),
            A.to_string(),
            format!("{A}  "),
            format!("{A}  *"),
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
            BTreeMap::from([("x.jar".to_string(), B.to_string())])
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
        let owned = set(&[("m/ours.jar", B), ("b/new.jar", B)]);
        let out = edit(&text, |p| p == "never.jar", &owned);
        assert_eq!(
            out,
            format!(
                "{B}  b/new.jar\n# pins\n{A} c/user.jar\n{A} *d/user.jar\n{A}\te/user.jar\n\
                 garbage\n{B}  m/ours.jar\n"
            )
        );
        // Idempotent: a second pass changes nothing.
        assert_eq!(edit(&out, |_| false, &owned), out);
    }

    #[test]
    fn edit_replaces_a_tolerated_spelling_of_an_owned_path_in_place() {
        let text = format!("{A} *m/ours.jar\r\nkeep\r\n");
        assert_eq!(
            edit(&text, |_| false, &set(&[("m/ours.jar", B)])),
            format!("{B}  m/ours.jar\r\nkeep\r\n")
        );
    }

    /// An owned line goes whatever its first field holds: a truncated or
    /// SRI hash a past writer left must not outlive the pin.
    #[test]
    fn edit_owns_a_path_whatever_its_hash() {
        for stale in [
            format!("sha256-q83vEjRWeJA=  {OURS}\n"),
            format!("{}  {OURS}\n", &A[1..]),
            format!("{}  {OURS}\n", A.to_uppercase()),
        ] {
            let text = format!("# keep\n{stale}");
            assert_eq!(edit(&text, |p| p == OURS, &[]), "# keep\n", "{stale:?}");
            assert_eq!(
                edit(&text, |_| false, &set(&[(OURS, B)])),
                format!("# keep\n{B}  {OURS}\n"),
                "{stale:?}"
            );
        }
    }

    #[test]
    fn edit_collapses_an_owned_path_to_one_line() {
        let text = format!("{A}  {OURS}\nkeep\n{A} *{OURS}\r\n{B}  {OURS}");
        assert_eq!(
            edit(&text, |_| false, &set(&[(OURS, B)])),
            format!("{B}  {OURS}\nkeep\n")
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

    /// A comment block directly above a line stays with it when an entry
    /// is inserted before that line; a blank line ends a block.
    #[test]
    fn edit_inserts_ahead_of_the_comment_block_above_a_line() {
        let text = format!("# about z\n# more\n{A}  z.jar\n");
        assert_eq!(
            edit(&text, |_| false, &set(&[("m.jar", B)])),
            format!("{B}  m.jar\n# about z\n# more\n{A}  z.jar\n")
        );
        let text = format!("# header\n\n{A}  z.jar\n# trailing\n");
        assert_eq!(
            edit(&text, |_| false, &set(&[("m.jar", B), ("zz.jar", B)])),
            format!("# header\n\n{B}  m.jar\n{A}  z.jar\n# trailing\n{B}  zz.jar\n")
        );
    }

    #[test]
    fn edit_inserts_with_the_dominant_line_ending() {
        assert_eq!(
            edit(
                &format!("{A}  a.jar\r\nlast"),
                |_| false,
                &set(&[("z.jar", B)])
            ),
            format!("{A}  a.jar\r\nlast\r\n{B}  z.jar\r\n")
        );
        // One CRLF line among LF lines does not make the file CRLF.
        let text = format!("{A}  a.jar\r\n{A}  b.jar\n{A}  c.jar\n");
        assert_eq!(
            edit(&text, |_| false, &set(&[("z.jar", B)])),
            format!("{text}{B}  z.jar\n")
        );
        let text = format!("x\r\n{A}  b.jar\r\n{A}  c.jar\n");
        assert_eq!(
            edit(&text, |_| false, &set(&[("a.jar", B)])),
            format!("x\r\n{B}  a.jar\r\n{A}  b.jar\r\n{A}  c.jar\n")
        );
        assert_eq!(
            edit("", |_| false, &set(&[("z.jar", B), ("a.jar", A)])),
            format!("{A}  a.jar\n{B}  z.jar\n")
        );
    }

    /// The rule decides on whole-line arguments only, and only when every
    /// setting Maven reads this file by is set as hosted mode writes it (or
    /// to an equivalent value).
    #[test]
    fn config_enforces_needs_every_setting_maven_reads_the_file_by() {
        let all = CONFIG_ARGS.join("\n");
        assert!(config_enforces(&all));
        assert!(config_enforces(&format!(
            "{}\r\n",
            CONFIG_ARGS.join("\r\n")
        )));
        let switch_line = format!("-D{SWITCH_KEY}=true");
        let with = |from: &str, to: &str| {
            assert!(all.contains(from), "{from}");
            all.replacen(from, to, 1)
        };
        for (config, want) in [
            (with(&switch_line, &format!("-D{SWITCH_KEY}")), true),
            (with(&switch_line, &format!("-D{SWITCH_KEY}=TRUE")), true),
            (
                with(
                    "checksumAlgorithms=SHA-256",
                    "checksumAlgorithms=SHA-1, SHA-256",
                ),
                true,
            ),
            (with("failIfMissing=false", "failIfMissing=true"), true),
            (with("originAware=false", "originAware=no"), true),
            (format!("{all}\n-D{SWITCH_KEY}=false"), false),
            (with(&switch_line, &format!("-D{SWITCH_KEY}=yes")), false),
            (
                with("checksumAlgorithms=SHA-256", "checksumAlgorithms=SHA-1"),
                false,
            ),
            (with("summaryFile=true", "summaryFile=false"), false),
            (with("/.mvn/checksums", "/.mvn/sums"), false),
            (with("originAware=false", "originAware=true"), false),
            // Maven 3.9+ reads an argument per line: a token inside a
            // longer line, or a commented line, is no setting.
            (with(&switch_line, &format!("-B {switch_line}")), false),
            (with(&switch_line, &format!("# {switch_line}")), false),
            (switch_line.clone(), false),
            (String::new(), false),
        ] {
            assert_eq!(config_enforces(&config), want, "{config}");
        }
        // Each setting but failIfMissing defaults to "not this file".
        for skip in CONFIG_ARGS.iter().filter(|a| !a.contains("failIfMissing")) {
            let config: Vec<&str> = CONFIG_ARGS.iter().copied().filter(|a| a != skip).collect();
            assert!(!config_enforces(&config.join("\n")), "without {skip}");
        }
        assert!(config_has_written_settings(&format!(
            "-D{SWITCH_KEY}=false"
        )));
        assert!(!config_has_written_settings(&format!("-B {switch_line}")));
    }

    #[test]
    fn enforced_follows_the_wrapper_maven() {
        let all = CONFIG_ARGS.join("\n");
        let wrapper = |v: &str| {
            format!("distributionUrl=https://repo/apache-maven/{v}/apache-maven-{v}-bin.zip\n")
        };
        assert!(enforced(&all, None));
        assert!(enforced(&all, Some(&wrapper("3.9.4"))));
        assert!(enforced(
            &all,
            Some("distributionUrl=https://x/maven-mvnd-1.0.2.zip\n")
        ));
        assert!(!enforced(&all, Some(&wrapper("3.9.3"))));
        assert!(!enforced("", None));
    }
}
