//! The write-policy oracle: every path a run changed must be in a class
//! socket-patch may write in a Bazel repository (design 5.1, owner
//! decision D4). Anything it does not recognize is refused: a new kind of
//! write has to be added here, where a reviewer sees it.

use super::snapshot::{changes, Entry, Snapshot};

/// The classes of write socket-patch may make in a Bazel repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteClass {
    /// A native lock a hub reads, the manifest the native rewriter edits
    /// with it, or a side file: today's rewriter output. A side file
    /// exists already, except `pnpm-workspace.yaml`, which native hosted
    /// mode also creates (owner decision O14).
    NativeLock,
    /// A value in a file a tool generates: `maven_install*.json`,
    /// `paket.<group>.bzl`, an rules_js hash-file line, one existing
    /// `gem_checksums` digest.
    GeneratedValue,
    /// Socket-tree lines added to or removed from a Bazel root's
    /// `.bazelignore` (created if absent, deleted when nothing else is
    /// left in it).
    IgnoreLine,
    /// `.socket/bazel/index.json`, the one file socket-patch owns for Bazel.
    OwnedFile,
    /// The `.socket` state that exists today: vendored artifacts, agent Go
    /// trees (upstream BUILD files included), the manifest and ledgers.
    SocketState,
}

/// What a test declares about the tree it snapshots. Paths are relative to
/// the snapshot root.
#[derive(Debug, Clone, Copy)]
pub struct Layout<'a> {
    /// Requirements files a hub names: rules_python accepts any name, so
    /// no rule can know them.
    pub hub_locks: &'a [&'a str],
    /// The Bazel roots; `""` is the snapshot root. Bazel reads
    /// `.bazelignore` at a root and nowhere else.
    pub bazel_roots: &'a [&'a str],
}

impl Default for Layout<'_> {
    /// No label-addressed lock, and the snapshot root is the Bazel root.
    fn default() -> Self {
        Self {
            hub_locks: &[],
            bazel_roots: &[""],
        }
    }
}

/// Native locks and the files the native rewriters edit with them.
const NATIVE_LOCK_LEAVES: &[&str] = &[
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "package.json",
    "uv.lock",
    "poetry.lock",
    "pyproject.toml",
    "go.mod",
    "go.sum",
    "Cargo.lock",
    "Cargo.toml",
    "Gemfile.lock",
    "Gemfile",
    "packages.lock.json",
];

/// Never written, whatever a test declares as a hub lock: Bazel's own
/// locks and version pins, BUILD files, `.npmrc` (a created one fails
/// rules_js 3.x), and an npm or yarn lock: beside a governed pnpm lock no
/// hub reads one, and rules_js import mode is refused. `wp-ext-legacy`
/// (`H-NJ1`, wave 9) lifts the two lock names if that lane lands, since
/// `npm_install` / `yarn_install` hubs read them. Rc files (`*.bazelrc`)
/// and pip-compile sources (`*.in`) are matched by suffix.
const NEVER_LEAVES: &[&str] = &[
    "MODULE.bazel.lock",
    "cargo-bazel-lock.json",
    "BUILD",
    "BUILD.bazel",
    "REPO.bazel",
    "VENDOR.bazel",
    ".bazelversion",
    ".bazeliskrc",
    ".npmrc",
    "package-lock.json",
    "yarn.lock",
];

/// The class of one changed path after a run that wires, repairs or takes
/// over (`None` = absent on that side), or why the change is not allowed.
pub fn classify(
    rel: &str,
    before: Option<&Entry>,
    after: Option<&Entry>,
    layout: &Layout<'_>,
) -> Result<WriteClass, String> {
    leftover(rel, after)?;
    class_of(rel, before, after, layout)
}

/// [`classify`] for a run that restores (`rollback`, `remove`): the change
/// must be the inverse of an allowed write. A restore deletes what the
/// write created, such as a `pnpm-workspace.yaml` scaffold, so the forward
/// rules cannot judge it. The inverse cannot tell a file socket-patch
/// created from one the user had: a round trip also asserts
/// `assert_same_tree` against the snapshot taken before the wiring.
pub fn classify_restore(
    rel: &str,
    before: Option<&Entry>,
    after: Option<&Entry>,
    layout: &Layout<'_>,
) -> Result<WriteClass, String> {
    leftover(rel, after)?;
    class_of(rel, after, before, layout)
}

/// No completed run leaves a stage or saved-original file behind: both
/// are transient in core, and inside a tree Bazel consumes a leftover
/// becomes an action input wherever a directory is globbed (hazard HZ-27).
fn leftover(rel: &str, after: Option<&Entry>) -> Result<(), String> {
    let transient = |s: &str| s.starts_with(".socket-stage-") || s.starts_with(".socket-orig-");
    if after.is_some() && rel.split('/').any(transient) {
        return Err("a stage or saved-original file was left behind".into());
    }
    Ok(())
}

/// The class of a change from `before` to `after`, read as a write.
fn class_of(
    rel: &str,
    before: Option<&Entry>,
    after: Option<&Entry>,
    layout: &Layout<'_>,
) -> Result<WriteClass, String> {
    let segments: Vec<&str> = rel.split('/').collect();
    let leaf = segments.last().copied().unwrap_or_default();
    if segments.contains(&".socket-auto-manifest") {
        return Err("socket-cli's manifest directory is never written".into());
    }
    if let Some(at) = segments.iter().position(|s| *s == ".socket") {
        // A link in place of `.socket` or `.socket/bazel` would send the
        // owned index somewhere else, and the snapshot does not walk
        // below a link.
        let dir = |e: Option<&Entry>| matches!(e, None | Some(Entry::Dir));
        let file = |e: Option<&Entry>| matches!(e, None | Some(Entry::File { .. }));
        return match &segments[at + 1..] {
            [] if dir(before) && dir(after) => Ok(WriteClass::SocketState),
            [] => Err("`.socket` is a directory, never a file or a link".into()),
            ["bazel-manifests", ..] => Err("socket-cli's Bazel manifests are never written".into()),
            ["bazel"] if dir(before) && dir(after) => Ok(WriteClass::OwnedFile),
            ["bazel"] => Err("`.socket/bazel` is a directory, never a file or a link".into()),
            ["bazel", "index.json"] if file(before) && file(after) => Ok(WriteClass::OwnedFile),
            ["bazel", "index.json"] => Err("the owned index is a regular file".into()),
            ["bazel", ..] => Err("`index.json` is the only file under `.socket/bazel`".into()),
            _ => Ok(WriteClass::SocketState),
        };
    }
    // Outside `.socket` a write edits a regular file and keeps its mode.
    // No link or directory changes. The files that may appear are
    // `.bazelignore` and `pnpm-workspace.yaml`; the one that may go is a
    // `.bazelignore` that held nothing but socket-patch's lines.
    let (old, new) = (regular_file(before)?, regular_file(after)?);
    if let (Some((_, was)), Some((_, is))) = (old, new) {
        if was != is {
            return Err(format!("the file's mode changed from {was:o} to {is:o}"));
        }
    }
    let (old, new) = (old.map(|(bytes, _)| bytes), new.map(|(bytes, _)| bytes));
    if leaf == ".bazelignore" {
        let root = rel.rsplit_once('/').map_or("", |(dir, _)| dir);
        if !layout.bazel_roots.contains(&root) {
            return Err("Bazel reads `.bazelignore` at its root only, and this is not one".into());
        }
        return ignore_lines_changed(old, new).map(|()| WriteClass::IgnoreLine);
    }
    let (old, new) = match (old, new) {
        (Some(old), Some(new)) => (old, new),
        (None, Some(new)) if leaf == "pnpm-workspace.yaml" => (&[][..], new),
        _ => return Err("outside `.socket` only an existing file may change".into()),
    };
    if NEVER_LEAVES.contains(&leaf) || leaf.ends_with(".bazelrc") || leaf.ends_with(".in") {
        return Err(format!("`{leaf}` is never written"));
    }
    if generated_value_file(rel, leaf) {
        return Ok(WriteClass::GeneratedValue);
    }
    if leaf.ends_with(".bzl") {
        return Err("the only `.bzl` file ever written is a generated `paket.<group>.bzl`".into());
    }
    if leaf == "MODULE.bazel" || leaf.ends_with(".MODULE.bazel") || leaf.starts_with("WORKSPACE") {
        if one_gem_checksum_replaced(old, new) {
            return Ok(WriteClass::GeneratedValue);
        }
        return Err("only one existing `gem_checksums` value may be replaced in this file".into());
    }
    let cargo_config = rel.ends_with(".cargo/config.toml") || rel.ends_with(".cargo/config");
    let requirements = leaf.starts_with("requirements") && leaf.ends_with(".txt");
    if NATIVE_LOCK_LEAVES.contains(&leaf)
        || leaf.eq_ignore_ascii_case("nuget.config")
        || cargo_config
        || requirements
        || layout.hub_locks.contains(&rel)
    {
        return Ok(WriteClass::NativeLock);
    }
    Err("not a file of any write class".into())
}

/// The bytes and mode of a regular file, `None` for an absent path.
fn regular_file(entry: Option<&Entry>) -> Result<Option<(&[u8], u32)>, String> {
    match entry {
        None => Ok(None),
        Some(Entry::File { bytes, mode }) => Ok(Some((bytes, *mode))),
        Some(_) => Err("outside `.socket` only a regular file may change".into()),
    }
}

/// Files a tool generates and socket-patch splices one value into.
fn generated_value_file(rel: &str, leaf: &str) -> bool {
    let maven = leaf.starts_with("maven_install") && leaf.ends_with(".json");
    // The per-group data file. Not the single `paket.bzl` of old
    // rules_dotnet, and not the `paket.<group>_extension.bzl` that loads
    // the data file.
    let paket = leaf
        .strip_prefix("paket.")
        .and_then(|rest| rest.strip_suffix(".bzl"))
        .is_some_and(|group| !group.is_empty() && !group.ends_with("_extension"));
    let cache = ".aspect/rules/external_repository_action_cache/";
    let hash_file = leaf.starts_with("npm_translate_lock_")
        && (rel.starts_with(cache) || rel.contains(&format!("/{cache}")));
    maven || paket || hash_file
}

/// One line of a `.bazelignore` and the line ending after it (empty for a
/// last line that has none).
#[derive(PartialEq)]
struct Line<'a> {
    text: &'a [u8],
    eol: &'a [u8],
}

impl Line<'_> {
    /// Whether this is a line socket-patch writes (design 5.3):
    /// `<rel>/.socket/go-patches` or `<rel>/.socket/vendor` in the one
    /// spelling Bazel and gazelle read alike. Never a bare `.socket`, a
    /// leading `/` (a hard error for every command on Bazel 8.8 and
    /// later), an empty, `.` or `..` segment, a glob, a quote, a
    /// backslash, a control character or stray white space, and never a
    /// line Bazel does not read as that path: a `#` comment or the first
    /// line behind a BOM.
    fn hides_socket_tree(&self) -> bool {
        let Ok(line) = std::str::from_utf8(self.text) else {
            return false;
        };
        let segments: Vec<&str> = line.split('/').collect();
        let tree = matches!(segments[..], [.., ".socket", "go-patches" | "vendor"]);
        tree && !segments.iter().any(|s| matches!(*s, "" | "." | ".."))
            && !line.starts_with(['#', '\u{feff}'])
            && line.trim() == line
            && !line.contains(|c: char| c.is_control() || "\\*?[\"'".contains(c))
    }

    fn show(&self) -> String {
        String::from_utf8_lossy(self.text)
            .escape_debug()
            .to_string()
    }
}

/// The lines of a `.bazelignore` as Bazel splits them: on CRLF, on LF and
/// on a lone CR.
fn ignore_lines(bytes: &[u8]) -> Vec<Line<'_>> {
    let (mut out, mut start, mut at) = (Vec::new(), 0, 0);
    while at < bytes.len() {
        let len = match bytes[at] {
            b'\r' if bytes.get(at + 1) == Some(&b'\n') => 2,
            b'\r' | b'\n' => 1,
            _ => 0,
        };
        if len > 0 {
            let (text, eol) = (&bytes[start..at], &bytes[at..at + len]);
            out.push(Line { text, eol });
            start = at + len;
        }
        at += len.max(1);
    }
    if start < bytes.len() {
        let (text, eol) = (&bytes[start..], &bytes[..0]);
        out.push(Line { text, eol });
    }
    out
}

/// A `.bazelignore` changes by socket-tree lines and by nothing else
/// (design 5.3, 5.4 and 7). Every other line is the user's: it stays byte
/// for byte, line ending included, in order. A socket-tree line may be
/// added, with the file's own line ending, or removed (a takeover moves
/// one; the last tree a line covered is gone). The file may be created,
/// and it may be deleted when every line in it was a socket-tree line. A
/// file with a CR-only line end is never edited: it has no line ending the
/// writer could keep.
fn ignore_lines_changed(old: Option<&[u8]>, new: Option<&[u8]>) -> Result<(), String> {
    let old_lines = ignore_lines(old.unwrap_or_default());
    let new_lines = ignore_lines(new.unwrap_or_default());
    if old_lines.iter().any(|l| l.eol == b"\r") {
        return Err("a `.bazelignore` with a CR-only line end is never edited".into());
    }
    // The file's own line ending: CRLF or LF as the file has them, either
    // one in a file that mixes them, LF in a file with no line end yet.
    let crlf = old_lines.iter().any(|l| l.eol == b"\r\n");
    let lf = old_lines.iter().any(|l| l.eol == b"\n");
    let own_eol = |eol: &[u8]| (eol == b"\r\n" && crlf) || (eol == b"\n" && (lf || !crlf));

    let mut kept = new_lines.iter().filter(|l| !l.hides_socket_tree());
    for was in old_lines.iter().filter(|l| !l.hides_socket_tree()) {
        let Some(is) = kept.next().filter(|is| is.text == was.text) else {
            let fate = match new {
                Some(_) => "was removed, changed or moved",
                None => "went with the deleted file",
            };
            let line = was.show();
            return Err(format!(
                "the line `{line}`, which socket-patch did not write, {fate}"
            ));
        };
        // A missing final newline is added first, when a line follows it.
        let followed = new_lines.last().is_some_and(|last| !std::ptr::eq(last, is));
        if is.eol != was.eol && !(was.eol.is_empty() && own_eol(is.eol) && followed) {
            return Err(format!("the line ending of `{}` changed", was.show()));
        }
    }
    if let Some(extra) = kept.next() {
        let line = extra.show();
        return Err(format!(
            "`{line}` is not a line socket-patch adds to `.bazelignore`"
        ));
    }

    let added = surplus(&new_lines, &old_lines);
    if let Some(bad) = added.iter().find(|l| !own_eol(l.eol)) {
        let line = bad.show();
        return Err(format!(
            "`{line}` was added without the file's own line ending"
        ));
    }
    if added.is_empty() && surplus(&old_lines, &new_lines).is_empty() {
        return Err("`.bazelignore` changed and no socket-tree line was added or removed".into());
    }
    Ok(())
}

/// The socket-tree lines `lines` holds more often than `than` does.
fn surplus<'a, 'b>(lines: &'a [Line<'b>], than: &[Line<'_>]) -> Vec<&'a Line<'b>> {
    let count = |of: &[Line], line: &Line| of.iter().filter(|l| *l == line).count();
    let more = |l: &&Line| l.hides_socket_tree() && count(lines, l) > count(than, l);
    lines.iter().filter(more).collect()
}

/// Whether `new` is `old` with exactly one quoted 64-hex digest replaced
/// by another, and that digest is a value of a `gem_checksums` dict: the
/// only edit ever made to a `MODULE.bazel` or `WORKSPACE` file.
fn one_gem_checksum_replaced(old: &[u8], new: &[u8]) -> bool {
    if old.len() != new.len() {
        return false;
    }
    let differs = |i: &usize| old[*i] != new[*i];
    let (Some(first), Some(last)) = ((0..old.len()).find(differs), (0..old.len()).rfind(differs))
    else {
        return false;
    };
    // Every differing byte must sit inside one string literal, so widen
    // to the quotes around it. They are outside the differing span and
    // therefore the same bytes in both files.
    let open = old[..first].iter().rposition(|b| *b == b'"');
    let close = old[last + 1..].iter().position(|b| *b == b'"');
    let (Some(open), Some(close)) = (open, close.map(|i| last + 1 + i)) else {
        return false;
    };
    let digest = |text: &[u8]| {
        text.len() == 64 && text.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    };
    digest(&old[open + 1..close]) && digest(&new[open + 1..close]) && gem_checksums_value(old, open)
}

/// Whether the string literal that opens at `open` is a value of the dict
/// a call passes as `gem_checksums`: `gem_checksums = {..., "<key>":
/// "<value>"`. An `http_archive` or `archive_override` `sha256`, a value
/// of another attribute's dict and a digest inside a comment are not.
fn gem_checksums_value(text: &[u8], open: usize) -> bool {
    let line = text[..open].iter().rposition(|b| *b == b'\n');
    if text[line.map_or(0, |i| i + 1)..open].contains(&b'#') {
        return false;
    }
    // The index of the last byte before `end` that is not white space.
    let before = |end: usize| text[..end].iter().rposition(|b| !b.is_ascii_whitespace());
    // The innermost bracket still open at `end`.
    let unclosed = |end: usize, opens: u8, closes: u8| {
        let mut depth = 0usize;
        text[..end].iter().rposition(|b| {
            if *b == closes {
                depth += 1;
            } else if *b == opens && depth > 0 {
                depth -= 1;
            } else if *b == opens {
                return true;
            }
            false
        })
    };
    let Some(colon) = before(open).filter(|i| text[*i] == b':') else {
        return false;
    };
    if before(colon).map(|i| text[i]) != Some(b'"') {
        return false;
    }
    let Some(equals) = unclosed(colon, b'{', b'}')
        .and_then(before)
        .filter(|i| text[*i] == b'=')
    else {
        return false;
    };
    let name = b"gem_checksums";
    let Some(start) = before(equals).and_then(|end| (end + 1).checked_sub(name.len())) else {
        return false;
    };
    let word = |b: &u8| b.is_ascii_alphanumeric() || *b == b'_';
    text[start..].starts_with(name)
        && !text[..start].last().is_some_and(word)
        && unclosed(start, b'(', b')').is_some()
}

/// Panics unless every path that differs between the two snapshots is a
/// write socket-patch may make in a Bazel repository. Returns the writes
/// with their classes, so a test can also assert the exact set.
///
/// Take `after` right after socket-patch exits, before any Bazel command:
/// Bazel rewrites `MODULE.bazel.lock` itself, and this is where "socket-patch
/// never writes it" is asserted.
pub fn assert_write_policy(before: &Snapshot, after: &Snapshot) -> Vec<(String, WriteClass)> {
    assert_write_policy_with(before, after, &Layout::default())
}

/// [`assert_write_policy`] for a tree with label-addressed requirements
/// files or with Bazel roots below the snapshot root.
pub fn assert_write_policy_with(
    before: &Snapshot,
    after: &Snapshot,
    layout: &Layout<'_>,
) -> Vec<(String, WriteClass)> {
    assert_all(before, after, layout, classify)
}

/// [`assert_write_policy`] for a run that restores (`rollback`, `remove`):
/// every change must be the inverse of an allowed write, and nothing
/// transient is left. See [`classify_restore`].
pub fn assert_restore_policy(before: &Snapshot, after: &Snapshot) -> Vec<(String, WriteClass)> {
    assert_restore_policy_with(before, after, &Layout::default())
}

/// [`assert_restore_policy`] with a declared [`Layout`].
pub fn assert_restore_policy_with(
    before: &Snapshot,
    after: &Snapshot,
    layout: &Layout<'_>,
) -> Vec<(String, WriteClass)> {
    assert_all(before, after, layout, classify_restore)
}

type Classify = fn(&str, Option<&Entry>, Option<&Entry>, &Layout<'_>) -> Result<WriteClass, String>;

fn assert_all(
    before: &Snapshot,
    after: &Snapshot,
    layout: &Layout<'_>,
    classify: Classify,
) -> Vec<(String, WriteClass)> {
    let mut allowed = Vec::new();
    let mut refused = Vec::new();
    for (path, _) in changes(before, after) {
        match classify(&path, before.get(&path), after.get(&path), layout) {
            Ok(class) => allowed.push((path, class)),
            Err(why) => refused.push(format!("{path}: {why}")),
        }
    }
    assert!(
        refused.is_empty(),
        "socket-patch wrote outside the allowed classes:\n  {}",
        refused.join("\n  ")
    );
    allowed
}
