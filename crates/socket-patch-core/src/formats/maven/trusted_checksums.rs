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

use super::declared_maven::{launcher_root, session_root, DeclaredMaven, Reads};
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
// The summary file's directory, under the project's root directory.
macro_rules! checksums_dir {
    () => {
        "/.mvn/checksums"
    };
}
// The six lines, with the project's root directory named through the
// property `$root` expands to: one definition for both spellings.
macro_rules! config_args {
    ($root:ident) => {
        &[
            concat!("-D", post_processor!(), "=true"),
            concat!("-D", post_processor!(), ".checksumAlgorithms=SHA-256"),
            concat!("-D", post_processor!(), ".failIfMissing=false"),
            concat!("-D", summary_file!(), "=true"),
            concat!(
                "-D",
                summary_file!(),
                ".basedir=",
                $root!(),
                checksums_dir!()
            ),
            concat!("-D", summary_file!(), ".originAware=false"),
        ]
    };
}

/// The resolver property that switches the Trusted Checksums
/// post-processor on.
pub(crate) const SWITCH_KEY: &str = post_processor!();
const ALGORITHMS_KEY: &str = concat!(post_processor!(), ".checksumAlgorithms");
const SUMMARY_FILE_KEY: &str = summary_file!();
pub(crate) const BASEDIR_KEY: &str = concat!(summary_file!(), ".basedir");
const ORIGIN_AWARE_KEY: &str = concat!(summary_file!(), ".originAware");

/// How `.mvn/maven.config` spells the directory of the summary file:
/// `.mvn/checksums` under the project's root directory, named through one
/// of the two properties a config line can name that directory through
/// ([`RootDirectory`], where the measurements are). Maven reads a relative
/// `basedir` from the local repository, so the directory in the checkout
/// has to be named through a property, and no property is right on every
/// Maven.
///
/// What the spelling means for the pin, measured with a genuine and a
/// tampered artifact from the project root, from a module directory and
/// with `-f <project>/pom.xml` from outside the project:
///
/// * [`Basedir::Launcher`] breaks no build, and the pin is enforced from
///   Maven 3.9.4 on wherever the build is started. On Maven 4 the directory
///   is not found, nothing is enforced, and the build runs as if the line
///   were not there.
/// * [`Basedir::Session`] is enforced from Maven 3.9.4 on and on Maven 4,
///   wherever the property is defined; where it is not (`-f` from outside
///   the project on 3.9.2 to 3.9.8) Maven does not start.
///
/// A Maven that interpolates neither (before 3.9.2) reads no summary file
/// under either spelling.
pub(crate) use super::declared_maven::RootDirectory as Basedir;

/// The setting's value under `form`.
pub(crate) const fn basedir_value(form: Basedir) -> &'static str {
    match form {
        Basedir::Launcher => concat!(launcher_root!(), checksums_dir!()),
        Basedir::Session => concat!(session_root!(), checksums_dir!()),
    }
}

/// The form whose value is `value`.
pub(crate) fn basedir_of_value(value: &str) -> Option<Basedir> {
    [Basedir::Launcher, Basedir::Session]
        .into_iter()
        .find(|form| basedir_value(*form) == value)
}

/// The `.mvn/maven.config` lines hosted mode writes, one argument each:
/// the post-processor on, checking SHA-256, `failIfMissing=false` (a
/// dependency without a committed checksum still resolves; only a MISMATCH
/// fails), and the summary-file source on, at `.mvn/checksums`, origin
/// unaware (one checksum matches the artifact from any repository). The
/// directory is spelled as [`Basedir::Launcher`]; see [`config_args`].
pub(crate) const CONFIG_ARGS: &[&str] = config_args!(launcher_root);

/// Where the directory line stands among the six.
const BASEDIR_AT: usize = 4;

/// The lines hosted mode writes for a project whose form is `form`.
pub(crate) fn config_args(form: Basedir) -> &'static [&'static str] {
    match form {
        Basedir::Launcher => CONFIG_ARGS,
        Basedir::Session => config_args!(session_root),
    }
}

/// Each line of [`config_args`] as the `(key, value)` it sets.
pub(crate) fn config_settings(
    form: Basedir,
) -> impl Iterator<Item = (&'static str, &'static str, &'static str)> {
    config_args(form).iter().map(|arg| {
        let (key, value) = arg
            .strip_prefix("-D")
            .and_then(|def| def.split_once('='))
            .expect("every Trusted Checksums line hosted mode writes is -Dkey=value");
        (*arg, key, value)
    })
}

/// Whether `config` is exactly what hosted mode writes into a file of its
/// own, in either form: such a file is hosted mode's to remove.
pub(crate) fn is_written_config(config: &str) -> bool {
    [Basedir::Launcher, Basedir::Session]
        .into_iter()
        .any(|form| config == format!("{}\n", config_args(form).join("\n")))
}

/// `config` with the summary file's directory spelled as `form`, wherever
/// it holds the six lines hosted mode writes in the other form: that one
/// line of each such block is rewritten in place, every other byte kept.
/// `None` when there is nothing to change.
///
/// The six lines must stand together, in the order hosted mode writes
/// them, as it writes them into a config that set none of them: that block
/// is what tells hosted mode's settings from the user's, whatever else the
/// file holds and whatever a later line sets. A directory line that stands
/// apart was there before hosted mode came (it then appended only the
/// settings that were missing), or is spelled exactly as Maven's own
/// documentation spells it by a user who wrote it, and stays as written.
///
/// This is how a project wired by an earlier release, whose line stops
/// Maven 3.9.2 to 3.9.8 from starting with `-f` from outside the project,
/// is healed; and how a project that has since declared Maven 4 gets the
/// spelling Maven 4 reads.
pub(crate) fn heal_basedir(config: &str, form: Basedir) -> Option<String> {
    let written = config_args(form.other());
    // The cheap test first: almost no config holds the other spelling.
    if !config.contains(written[BASEDIR_AT]) {
        return None;
    }
    let lines: Vec<&str> = config.split_inclusive('\n').collect();
    let body = |line: &str| -> usize { line.trim_end_matches(['\r', '\n']).len() };
    let healed: BTreeSet<usize> = (0..(lines.len() + 1).checked_sub(written.len())?)
        .filter(|&at| {
            written
                .iter()
                .zip(&lines[at..])
                .all(|(arg, line)| &line[..body(line)] == *arg)
        })
        .map(|at| at + BASEDIR_AT)
        .collect();
    if healed.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(config.len() + 32);
    for (i, line) in lines.iter().enumerate() {
        if healed.contains(&i) {
            out.push_str(config_args(form)[BASEDIR_AT]);
            out.push_str(&line[body(line)..]);
        } else {
            out.push_str(line);
        }
    }
    Some(out)
}

/// Whether `config` holds the six lines hosted mode writes, standing
/// together, in either spelling: whether some project is healed out of it
/// ([`heal_basedir`]). A substring test for nearly every config, so a
/// caller asks this before it reads anything else to find out which
/// spelling the project takes.
pub(crate) fn holds_written_block(config: &str) -> bool {
    [Basedir::Launcher, Basedir::Session]
        .into_iter()
        .any(|form| heal_basedir(config, form).is_some())
}

/// The Trusted Checksums settings of a `.mvn/maven.config`, read once.
///
/// `maven.config` is read as Maven 3.9+ reads it (the only line that
/// enforces Trusted Checksums at all): one argument per LINE, `#`
/// comments, `-Dk=v` / `--define`, `-Dk` alone meaning `true`, a later
/// definition winning ([`maven_config_line_properties`]); a `-Dk=v` token
/// inside a longer line is not an argument there.
pub(crate) struct Settings(BTreeMap<String, String>);

impl Settings {
    /// Read `config`, a `.mvn/maven.config`'s text.
    pub(crate) fn read(config: &str) -> Settings {
        Settings(maven_config_line_properties(config))
    }

    /// What the config sets `key` to.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// The form the directory is spelled in, when it is one hosted mode
    /// writes.
    pub(crate) fn basedir(&self) -> Option<Basedir> {
        self.get(BASEDIR_KEY).and_then(basedir_of_value)
    }

    /// Whether the config makes Maven check artifacts against
    /// `.mvn/checksums/checksums.sha256` — the one rule every mode shares.
    ///
    /// Each setting is judged as the resolver judges it, with its default
    /// when unset:
    /// - the post-processor on (`ConfigUtils.getBoolean`, i.e. Java
    ///   `Boolean.parseBoolean`: `true` in any case; default off);
    /// - its comma-separated `checksumAlgorithms` naming `SHA-256` (default
    ///   `SHA-1`, which never reads a `.sha256` file);
    /// - the summary-file source on (default off);
    /// - its `basedir` exactly the `.mvn/checksums` hosted mode writes, in
    ///   either spelling ([`Basedir`]; the default is `.checksums` under
    ///   the local repository; any other value is not this file);
    /// - `originAware` off (default on, which reads a per-repository
    ///   `checksums-<repo id>.sha256` instead).
    ///
    /// `failIfMissing` does not decide whether a committed line is checked.
    /// Whether the Maven that builds the project then reads the directory
    /// is [`enforcement`]'s to say.
    pub(crate) fn enforce(&self) -> bool {
        let is_true = |key: &str| {
            self.get(key)
                .is_some_and(|v| v.eq_ignore_ascii_case("true"))
        };
        is_true(SWITCH_KEY)
            && self
                .get(ALGORITHMS_KEY)
                .is_some_and(|v| v.split(',').any(|a| a.trim() == "SHA-256"))
            && is_true(SUMMARY_FILE_KEY)
            && self.basedir().is_some()
            && self
                .get(ORIGIN_AWARE_KEY)
                .is_some_and(|v| !v.eq_ignore_ascii_case("true"))
    }
}

/// [`Settings::enforce`] of a config's text.
#[cfg(test)]
pub(crate) fn config_enforces(config: &str) -> bool {
    Settings::read(config).enforce()
}

/// Whether any setting hosted mode writes is present in `config`, whatever
/// its value, in any spelling some Maven reads (a whole line, or a token of
/// the pre-3.9 whitespace split): the rollback's "leftover settings"
/// warning keys on presence, not on enforcement.
pub(crate) fn config_has_written_settings(config: &str) -> bool {
    let props = crate::formats::maven::maven_config_properties(config);
    config_settings(Basedir::Launcher).any(|(_, key, _)| props.contains_key(key))
}

/// The first Maven release that enforces the `.mvn/*` Trusted Checksums
/// files (#258). 3.9.0 / 3.9.1 do not interpolate `${session.rootDirectory}`
/// in `maven.config`, so the summary file is never found; 3.9.2 / 3.9.3
/// ignore `checksumAlgorithms=SHA-256` and check SHA-1 only. Older lines have
/// no Trusted Checksums post-processor at all.
const MIN_MAVEN: [u32; 3] = [3, 9, 4];

/// Whether the summary file is an enforced pin, as far as the project
/// says which Maven builds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Enforcement {
    /// The config does not make Maven read the summary file
    /// ([`Settings::enforce`]).
    Off,
    /// The Maven Wrapper pins this Apache Maven release, which is older
    /// than 3.9.4 and enforces no such file.
    TooOld(String),
    /// The project declares Maven 4 and the directory is spelled as
    /// [`Basedir::Launcher`], which Maven 4 does not interpolate.
    UnreadByMaven4,
    /// The project declares no Maven and the directory is spelled as
    /// [`Basedir::Launcher`]: Maven 3.9.4 and later 3.x enforce the pin, a
    /// Maven 4 build does not. Nothing in the checkout says which builds
    /// it, so the pin is not known to be enforced.
    Maven3Only,
    /// The Maven the project declares enforces the pin; or it declares
    /// none, and the directory is spelled so that every Maven that
    /// enforces Trusted Checksums at all finds it.
    Enforced,
}

/// Whether the Maven the project declares (`maven`) enforces a pin whose
/// directory is spelled as `form`, in a config that otherwise enforces it
/// ([`Settings::enforce`]). The one answer to that question: the conflict
/// check, the heal, the unenforced warning and discovery all ask it here.
/// Never [`Enforcement::Off`].
pub(crate) fn form_enforcement(form: Basedir, maven: &DeclaredMaven) -> Enforcement {
    match form.read_by(maven, MIN_MAVEN) {
        Reads::TooOld(version) => Enforcement::TooOld(version),
        Reads::UnreadByMaven4 => Enforcement::UnreadByMaven4,
        Reads::Maven3Only => Enforcement::Maven3Only,
        Reads::Read => Enforcement::Enforced,
    }
}

/// Whether the summary file is an enforced pin under `settings` in a
/// project that declares `maven`.
pub(crate) fn enforcement(settings: &Settings, maven: &DeclaredMaven) -> Enforcement {
    match settings.basedir().filter(|_| settings.enforce()) {
        Some(form) => form_enforcement(form, maven),
        None => Enforcement::Off,
    }
}

/// Whether `text`, a `.mvn/checksums/checksums.sha256`, still names an
/// artifact hosted mode pins: a path under a `<base>-socket.<hex8>`
/// version, in any spelling of its line.
pub(crate) fn names_hosted_artifact(text: &str) -> bool {
    entries(text).any(|e| {
        e.path
            .split('/')
            .any(|seg| super::split_socket_version(seg).is_some())
    })
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
        // Presence, not enforcement: a token joined onto a longer line is
        // still a leftover the rollback warns about.
        assert!(config_has_written_settings(&format!("-B {switch_line}")));
        assert!(!config_has_written_settings(&format!("# {switch_line}")));
    }

    fn wrapper(version: &str) -> String {
        format!(
            "distributionUrl=https\\://repo.maven.apache.org/maven2/org/apache/maven/\
             apache-maven/{version}/apache-maven-{version}-bin.zip\n"
        )
    }

    fn pom(model: &str) -> String {
        format!(
            "<project xmlns=\"http://maven.apache.org/POM/{model}\">\n  \
             <modelVersion>{model}</modelVersion>\n</project>\n"
        )
    }

    /// The two spellings are one definition: they differ in the directory
    /// line alone, which stands where [`BASEDIR_AT`] says and names the
    /// property of its form.
    #[test]
    fn the_two_spellings_differ_in_the_directory_line_alone() {
        use Basedir::{Launcher, Session};
        let (launcher, session) = (config_args(Launcher), config_args(Session));
        assert_eq!(launcher, CONFIG_ARGS);
        assert_eq!(launcher.len(), session.len());
        for (i, (a, b)) in launcher.iter().zip(session).enumerate() {
            assert_eq!(a == b, i != BASEDIR_AT, "{a} / {b}");
        }
        for form in [Launcher, Session] {
            let line = config_args(form)[BASEDIR_AT];
            assert_eq!(line, format!("-D{BASEDIR_KEY}={}", basedir_value(form)));
            assert_eq!(
                basedir_value(form),
                format!("{}/.mvn/checksums", form.property())
            );
            assert_eq!(basedir_of_value(basedir_value(form)), Some(form));
            let keys: Vec<&str> = config_settings(form).map(|(_, key, _)| key).collect();
            assert_eq!(keys[BASEDIR_AT], BASEDIR_KEY);
            assert_eq!(keys.len(), 6);
        }
        assert_eq!(basedir_of_value(".mvn/checksums"), None);
    }

    /// One function answers whether the Maven a project declares enforces
    /// a spelling: from the wrapper AND the model.
    #[test]
    fn enforcement_follows_the_maven_the_project_declares() {
        use Basedir::{Launcher, Session};
        use Enforcement::{Enforced, Maven3Only, TooOld, UnreadByMaven4};
        let declared = |wrapper: Option<&str>, pom: Option<&str>| DeclaredMaven::of(wrapper, pom);
        let by_wrapper = |version: &str| declared(Some(&wrapper(version)), Some(&pom("4.0.0")));
        // Too old for Trusted Checksums, whatever the spelling.
        for old in ["3.6.3", "3.8.9", "3.9.0", "3.9.3"] {
            for form in [Launcher, Session] {
                assert_eq!(
                    form_enforcement(form, &by_wrapper(old)),
                    TooOld(old.to_string()),
                    "{old}"
                );
            }
        }
        // A Maven 3 that enforces reads either spelling.
        for maven_3 in ["3.9.4", "3.9.8", "3.9.16", "3.10.0-rc-1"] {
            for form in [Launcher, Session] {
                assert_eq!(form_enforcement(form, &by_wrapper(maven_3)), Enforced);
            }
        }
        // Maven 4 reads only the session property: declared by the wrapper,
        // by the model alone, or by the model under a Maven 3 wrapper that
        // cannot build it.
        for maven_4 in [
            by_wrapper("4.0.0"),
            by_wrapper("4.0.0-rc-7"),
            declared(None, Some(&pom("4.1.0"))),
            declared(Some(&wrapper("3.9.9")), Some(&pom("4.1.0"))),
            declared(Some(&wrapper("3.8.9")), Some(&pom("4.1.0"))),
        ] {
            assert_eq!(form_enforcement(Session, &maven_4), Enforced, "{maven_4:?}");
            assert_eq!(
                form_enforcement(Launcher, &maven_4),
                UnreadByMaven4,
                "{maven_4:?}"
            );
        }
        // Nothing declared (no wrapper, another distribution, a 4.0.0
        // model): the launcher spelling is enforced by Maven 3 only, and
        // which Maven builds the project is not known.
        let mvnd = "distributionUrl=https://x/maven-mvnd-1.0.2-bin.zip\n";
        for unknown in [
            declared(None, None),
            declared(None, Some(&pom("4.0.0"))),
            declared(Some(mvnd), Some(&pom("4.0.0"))),
        ] {
            assert_eq!(form_enforcement(Launcher, &unknown), Maven3Only);
            assert_eq!(form_enforcement(Session, &unknown), Enforced);
        }
    }

    #[test]
    fn enforcement_needs_a_config_that_reads_the_file() {
        use Basedir::{Launcher, Session};
        let written = |form| Settings::read(&config_args(form).join("\n"));
        let unknown = DeclaredMaven::default();
        assert_eq!(
            enforcement(&written(Launcher), &unknown),
            Enforcement::Maven3Only
        );
        assert_eq!(
            enforcement(&written(Session), &unknown),
            Enforcement::Enforced
        );
        let maven_3 = DeclaredMaven::of(Some(&wrapper("3.9.9")), None);
        assert_eq!(
            enforcement(&written(Launcher), &maven_3),
            Enforcement::Enforced
        );
        // A config that does not enforce is off whatever the Maven, and
        // never "too old": there is no pin for a Maven to ignore.
        let off = Settings::read(&format!(
            "{}\n-D{SWITCH_KEY}=false\n",
            CONFIG_ARGS.join("\n")
        ));
        let old = DeclaredMaven::of(Some(&wrapper("3.9.0")), None);
        for maven in [&unknown, &maven_3, &old] {
            assert_eq!(enforcement(&off, maven), Enforcement::Off);
            assert_eq!(enforcement(&Settings::read(""), maven), Enforcement::Off);
        }
        assert_eq!(
            enforcement(&written(Launcher), &old),
            Enforcement::TooOld("3.9.0".into())
        );
    }

    #[test]
    fn the_directory_is_spelled_for_the_maven_the_project_declares() {
        use Basedir::{Launcher, Session};
        let form = |wrapper: Option<&str>, pom: Option<&str>| {
            Basedir::for_maven(&DeclaredMaven::of(wrapper, pom))
        };
        assert_eq!(form(None, None), Launcher);
        assert_eq!(form(None, Some(&pom("4.0.0"))), Launcher);
        for maven_3 in ["3.6.3", "3.9.2", "3.9.8", "3.9.16"] {
            assert_eq!(
                form(Some(&wrapper(maven_3)), Some(&pom("4.0.0"))),
                Launcher,
                "{maven_3}"
            );
        }
        for maven_4 in ["4.0.0", "4.0.0-rc-7", "4.1.2"] {
            assert_eq!(
                form(Some(&wrapper(maven_4)), Some(&pom("4.0.0"))),
                Session,
                "{maven_4}"
            );
        }
        // A model only Maven 4 reads, named by the element or the namespace.
        assert_eq!(form(None, Some(&pom("4.1.0"))), Session);
        let by_namespace = "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n</project>\n";
        assert_eq!(form(None, Some(by_namespace)), Session);
        // A 4.0.0 model under the 4.1.0 namespace is a pom Maven 3.9.2 to
        // 3.9.8 build, so it must not get the line that stops them.
        let mixed = "<project xmlns=\"http://maven.apache.org/POM/4.1.0\">\n  \
                     <modelVersion>4.0.0</modelVersion>\n</project>\n";
        assert_eq!(form(None, Some(mixed)), Launcher);
        // A commented-out model is not the pom's.
        let commented = "<project>\n  <!-- <modelVersion>4.1.0</modelVersion> -->\n  \
                         <modelVersion>4.0.0</modelVersion>\n</project>\n";
        assert_eq!(form(None, Some(commented)), Launcher);
        assert_eq!(form(None, Some("not a pom")), Launcher);
    }

    #[test]
    fn either_spelling_is_hosted_modes_and_one_heals_into_the_other() {
        use Basedir::{Launcher, Session};
        let written = |form| format!("{}\n", config_args(form).join("\n"));
        for (form, other) in [(Launcher, Session), (Session, Launcher)] {
            let config = written(form);
            assert!(config_enforces(&config) && is_written_config(&config));
            assert_eq!(Settings::read(&config).basedir(), Some(form));
            assert_eq!(heal_basedir(&config, form), None);
            assert_eq!(
                heal_basedir(&config, other).as_deref(),
                Some(written(other).as_str())
            );
        }
        // The user's own lines, the line endings and a missing final line
        // break are kept: only the directory changes.
        let mixed = format!("-B\r\n{}\r\n# end", config_args(Session).join("\r\n"));
        assert_eq!(
            heal_basedir(&mixed, Launcher),
            Some(mixed.replace(basedir_value(Session), basedir_value(Launcher)))
        );
        // A directory line that stands apart from the other five was there
        // before hosted mode appended them: the user's, left as written.
        let theirs = format!("-D{BASEDIR_KEY}={}\n", basedir_value(Session));
        let appended: Vec<&str> = config_args(Session)
            .iter()
            .copied()
            .filter(|arg| !arg.contains(BASEDIR_KEY))
            .collect();
        let merged = format!("{theirs}{}\n", appended.join("\n"));
        assert!(config_enforces(&merged));
        assert_eq!(heal_basedir(&merged, Launcher), None);
        assert_eq!(heal_basedir(&theirs, Launcher), None);
        assert!(!holds_written_block(&merged) && !holds_written_block(&theirs));
        assert!(holds_written_block(&mixed) && holds_written_block(&written(Launcher)));
        assert!(!holds_written_block(""));
        assert!(!is_written_config(&merged));
        assert!(!is_written_config(&format!("-B\n{}", written(Launcher))));
    }

    /// The block is what marks the line as hosted mode's, not what the
    /// settings come to: the line stops Maven from starting whether or not
    /// the pin is enforced.
    #[test]
    fn the_block_is_healed_whatever_else_the_config_sets() {
        use Basedir::{Launcher, Session};
        let block = |form| config_args(form).join("\n");
        for extra in [
            // A later line switches the pin off, or names another directory.
            format!("-D{SWITCH_KEY}=false"),
            format!("-D{BASEDIR_KEY}=/opt/checksums"),
            "-Daether.trustedChecksumsSource.summaryFile.originAware=true".to_string(),
            "-T4".to_string(),
        ] {
            let config = format!("{}\n{extra}\n", block(Session));
            assert_eq!(
                heal_basedir(&config, Launcher),
                Some(format!("{}\n{extra}\n", block(Launcher))),
                "{extra}"
            );
        }
        // Every block in the file, when an earlier run left two.
        let twice = format!("{}\n-B\n{}\n", block(Session), block(Session));
        assert_eq!(
            heal_basedir(&twice, Launcher),
            Some(format!("{}\n-B\n{}\n", block(Launcher), block(Launcher)))
        );
        // Five of the six, or the six in another order, are not the block.
        let five = config_args(Session)[1..].join("\n");
        assert_eq!(heal_basedir(&five, Launcher), None);
        let mut shuffled = config_args(Session).to_vec();
        shuffled.swap(0, 1);
        assert_eq!(heal_basedir(&shuffled.join("\n"), Launcher), None);
        // An indented or quoted line is not the line hosted mode wrote.
        let indented = block(Session).replace(
            "-Daether.trustedChecksumsSource",
            " -Daether.trustedChecksumsSource",
        );
        assert_eq!(heal_basedir(&indented, Launcher), None);
    }

    #[test]
    fn a_checksum_file_names_a_hosted_artifact_by_its_suffixed_version() {
        assert!(names_hosted_artifact(&format!("{A}  {OURS}\n")));
        // In any spelling of the line: it is still hosted mode's path.
        assert!(names_hosted_artifact(&format!(
            "{}\t*{OURS}\r\n",
            A.to_uppercase()
        )));
        assert!(!names_hosted_artifact(&format!(
            "{A}  org/x/1.0/x-1.0.jar\n# {B}  {OURS}\n"
        )));
        assert!(!names_hosted_artifact(""));
    }
}
