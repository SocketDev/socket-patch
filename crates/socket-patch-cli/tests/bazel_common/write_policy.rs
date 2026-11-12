//! The write-policy oracle: every path a run changed must be in a class
//! socket-patch may write in a Bazel repository (design 5.1, owner
//! decision D4). Anything it does not recognize is refused: a new kind of
//! write has to be added here, where a reviewer sees it.

use super::snapshot::{changes, Entry, Snapshot};

/// The classes of write socket-patch may make in a Bazel repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteClass {
    /// A native lock a hub reads, the manifest the native rewriter edits
    /// with it, or an existing side file: today's rewriter output.
    NativeLock,
    /// A value in a file a tool generates: `maven_install*.json`,
    /// `paket.<group>.bzl`, an rules_js hash-file line, one existing
    /// `gem_checksums` digest.
    GeneratedValue,
    /// Lines appended to a Bazel root's `.bazelignore` (created if absent).
    IgnoreLine,
    /// `.socket/bazel/index.json`, the one file socket-patch owns for Bazel.
    OwnedFile,
    /// The `.socket` state that exists today: vendored artifacts, agent Go
    /// trees (upstream BUILD files included), the manifest and ledgers.
    SocketState,
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
/// locks and version pins, and BUILD files. Rc files (`*.bazelrc`) and
/// pip-compile sources (`*.in`) are matched by suffix.
const NEVER_LEAVES: &[&str] = &[
    "MODULE.bazel.lock",
    "cargo-bazel-lock.json",
    "BUILD",
    "BUILD.bazel",
    "REPO.bazel",
    "VENDOR.bazel",
    ".bazelversion",
    ".bazeliskrc",
];

/// The class of one changed path (`None` = absent on that side), or why
/// the change is not allowed. `hub_locks` are root-relative requirements
/// files a hub names: rules_python accepts any name, so no rule can know
/// them.
pub fn classify(
    rel: &str,
    before: Option<&Entry>,
    after: Option<&Entry>,
    hub_locks: &[&str],
) -> Result<WriteClass, String> {
    let segments: Vec<&str> = rel.split('/').collect();
    let leaf = segments.last().copied().unwrap_or_default();
    if segments.contains(&".socket-auto-manifest") {
        return Err("socket-cli's manifest directory is never written".into());
    }
    if let Some(at) = segments.iter().position(|s| *s == ".socket") {
        return match &segments[at + 1..] {
            ["bazel-manifests", ..] => Err("socket-cli's Bazel manifests are never written".into()),
            ["bazel"] | ["bazel", "index.json"] => Ok(WriteClass::OwnedFile),
            ["bazel", ..] => Err("`index.json` is the only file under `.socket/bazel`".into()),
            _ => Ok(WriteClass::SocketState),
        };
    }
    // Outside `.socket` a write edits a file that already exists. Nothing
    // is removed, no link or directory changes, and the one file that may
    // appear is `.bazelignore`.
    let (old, new) = match (before, after) {
        (Some(Entry::File(old)), Some(Entry::File(new))) => (old.as_slice(), new.as_slice()),
        (None, Some(Entry::File(new))) if leaf == ".bazelignore" => (&[][..], new.as_slice()),
        _ => return Err("outside `.socket` only an existing file may change".into()),
    };
    if leaf == ".bazelignore" {
        return appended_ignore_lines(old, new).map(|()| WriteClass::IgnoreLine);
    }
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
        if one_digest_replaced(old, new) {
            return Ok(WriteClass::GeneratedValue);
        }
        return Err("only one existing sha256 value may be replaced in this file".into());
    }
    let cargo_config = rel.ends_with(".cargo/config.toml") || rel.ends_with(".cargo/config");
    let requirements = leaf.starts_with("requirements") && leaf.ends_with(".txt");
    if NATIVE_LOCK_LEAVES.contains(&leaf)
        || leaf.eq_ignore_ascii_case("nuget.config")
        || cargo_config
        || requirements
        || hub_locks.contains(&rel)
    {
        return Ok(WriteClass::NativeLock);
    }
    Err("not a file of any write class".into())
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

/// `.bazelignore` grows by whole lines that hide a `.socket` tree and by
/// nothing else (design 5.3): `<rel>/.socket/go-patches` or
/// `<rel>/.socket/vendor`, never a bare `.socket`, never a leading `/` (a
/// hard error for every command on Bazel 8.8 and later), `./`, a glob, a
/// backslash or stray whitespace.
fn appended_ignore_lines(old: &[u8], new: &[u8]) -> Result<(), String> {
    let added = new
        .strip_prefix(old)
        .filter(|added| !added.is_empty())
        .ok_or("lines may only be appended to `.bazelignore`")?;
    let added = std::str::from_utf8(added).map_err(|_| "a `.bazelignore` line is not UTF-8")?;
    if !old.is_empty() && !old.ends_with(b"\n") && !added.starts_with(['\n', '\r']) {
        return Err("the appended line is glued to the last existing line".into());
    }
    let lines = added.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    for line in lines.filter(|l| !l.is_empty()) {
        let hides_tree = [".socket/go-patches", ".socket/vendor"]
            .iter()
            .any(|tree| line == *tree || line.ends_with(&format!("/{tree}")));
        let spelled = !line.starts_with('/')
            && !line.starts_with("./")
            && line.trim() == line
            && !line.contains(['\\', '*', '?', '[', '"', '\'']);
        if !(hides_tree && spelled) {
            return Err(format!(
                "`{line}` is not a line socket-patch adds to `.bazelignore`"
            ));
        }
    }
    Ok(())
}

/// Whether `new` is `old` with exactly one quoted 64-hex digest replaced
/// by another: the only edit ever made to a `MODULE.bazel` or `WORKSPACE`
/// file, the repair of an existing `gem_checksums` value.
fn one_digest_replaced(old: &[u8], new: &[u8]) -> bool {
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
    digest(&old[open + 1..close]) && digest(&new[open + 1..close])
}

/// Panics unless every path that differs between the two snapshots is a
/// write socket-patch may make in a Bazel repository. Returns the writes
/// with their classes, so a test can also assert the exact set.
pub fn assert_write_policy(before: &Snapshot, after: &Snapshot) -> Vec<(String, WriteClass)> {
    assert_write_policy_with(before, after, &[])
}

/// [`assert_write_policy`] for a workspace whose hub names requirements
/// files of arbitrary names (`hub_locks`, root-relative).
pub fn assert_write_policy_with(
    before: &Snapshot,
    after: &Snapshot,
    hub_locks: &[&str],
) -> Vec<(String, WriteClass)> {
    let mut allowed = Vec::new();
    let mut refused = Vec::new();
    for (path, _) in changes(before, after) {
        match classify(&path, before.get(&path), after.get(&path), hub_locks) {
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
