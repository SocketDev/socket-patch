//! Lexical path normalization: the one place that resolves `.` and `..`
//! segments without touching the filesystem.
//!
//! Every normalizer in the crate folds segments through the same
//! [`Segments`] stack; they differ only in what a caller does with a `..`
//! that climbs above the floor (fail closed, or keep it so a later
//! containment check can report the escape) and in which spellings a
//! format refuses up front (absolute paths, backslashes, drive letters),
//! which stays with each format's own admission check.
//!
//! Symlinks are never resolved: a symlink inside a project pointing out
//! of it is a pre-existing trust decision of the project's own tree.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// A stack of plain path segments with a floor: a `..` pops one segment
/// while the stack is above the floor and otherwise counts as an escape.
struct Segments<T> {
    parts: Vec<T>,
    floor: usize,
    escapes: usize,
}

impl<T> Segments<T> {
    fn new(parts: Vec<T>, floor: usize) -> Self {
        Segments {
            parts,
            floor,
            escapes: 0,
        }
    }

    fn parent(&mut self) {
        if self.parts.len() > self.floor {
            self.parts.pop();
        } else {
            self.escapes += 1;
        }
    }
}

/// `rel` folded onto `base`, both split on either separator; empty and
/// `.` segments drop out.
fn fold_str<'a>(base: &'a str, rel: &'a str, floor: usize) -> Segments<&'a str> {
    let plain = |s: &&str| !s.is_empty() && *s != ".";
    let mut segments = Segments::new(base.split(['/', '\\']).filter(plain).collect(), floor);
    for seg in rel.split(['/', '\\']) {
        match seg {
            "" | "." => {}
            ".." => segments.parent(),
            other => segments.parts.push(other),
        }
    }
    segments
}

/// The relative path `rel` (either separator) resolved against `base`, a
/// `/`-separated relative directory (`""` for the root), as a `/`-joined
/// string (`""` for the root itself). `None` when a `..` would pop below
/// the first `floor` segments of `base`; a `floor` of `0` means "never
/// above the root `base` is relative to".
///
/// Absolute and drive-anchored spellings are NOT detected here: a caller
/// whose format can carry them refuses them first (each format has its
/// own rules — see [`is_anchored`] for the common one).
pub(crate) fn resolve_rel(base: &str, rel: &str, floor: usize) -> Option<String> {
    let segments = fold_str(base, rel, floor);
    (segments.escapes == 0).then(|| segments.parts.join("/"))
}

/// The relative or `/`-rooted path `path` (either separator) normalized
/// lexically, keeping what [`resolve_rel`] would refuse visible instead:
/// an escape above the root keeps one leading `../` per climbed level and
/// a rooted path keeps its leading `/` (`a/../../x` → `../x`,
/// `deps\..\dev.txt` → `dev.txt`), so a later containment check can tell
/// an out-of-root path from an in-root one and report it by name.
pub(crate) fn normalize_rel_keeping_escapes(path: &str) -> String {
    let rooted = path.starts_with(['/', '\\']);
    let segments = fold_str("", path, 0);
    let mut out = String::new();
    if rooted {
        out.push('/');
    }
    for _ in 0..segments.escapes {
        out.push_str("../");
    }
    out.push_str(&segments.parts.join("/"));
    out
}

/// Whether `rel` is anchored rather than relative: a leading `/` or `\`,
/// or (on Windows) a drive or UNC prefix, including the drive-relative
/// `C:foo`.
pub(crate) fn is_anchored(rel: &str) -> bool {
    rel.starts_with(['/', '\\'])
        || matches!(
            Path::new(rel).components().next(),
            Some(Component::Prefix(_) | Component::RootDir)
        )
}

/// `path`'s anchor (prefix and root components, as spelled) and its
/// remaining segments folded with a floor of `0`.
fn fold_path(path: &Path) -> (PathBuf, Segments<&OsStr>) {
    let mut anchor = PathBuf::new();
    let mut segments = Segments::new(Vec::new(), 0);
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => anchor.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => segments.parent(),
            Component::Normal(segment) => segments.parts.push(segment),
        }
    }
    (anchor, segments)
}

/// Resolve `.`/`..` in `path` without touching the filesystem, so a path
/// can be containment-checked BEFORE it is opened (a canonicalizing check
/// would have to stat the very path being validated, and would fail on
/// not-yet-existing directories). Returns `None` when `..` pops above the
/// path's own root (or, for a relative path, above its first segment):
/// nothing legitimate does that, so it fails closed.
pub(crate) fn normalize_lexically(path: &Path) -> Option<PathBuf> {
    let (mut out, segments) = fold_path(path);
    if segments.escapes > 0 {
        return None;
    }
    out.extend(segments.parts);
    Some(out)
}

/// [`normalize_lexically`] that never fails: a relative path keeps one
/// leading `..` per level it climbs above its start (`../../x` stays
/// `../../x`), and a `..` at a filesystem root stays at the root, as the
/// OS resolves it. For joining a recorded relative location onto a base
/// that may itself be relative (`--cwd ../app`), before a containment
/// check compares the two spellings.
pub(crate) fn normalize_lexically_keeping_escapes(path: &Path) -> PathBuf {
    let (mut out, segments) = fold_path(path);
    if out.as_os_str().is_empty() {
        for _ in 0..segments.escapes {
            out.push("..");
        }
    }
    out.extend(segments.parts);
    out
}

/// `path` made absolute against the working directory without touching
/// the filesystem (no symlink resolution), with `.`/`..` folded. The
/// empty path (the parent of a bare `node_modules`) is the working
/// directory, which `std::path::absolute` would reject.
///
/// For upward config walks: a relative path's lexical ancestors stop at
/// the working directory, so under the default `--cwd .` a parent's
/// `.yarnrc` or `pnpm-workspace.yaml` would never be read (#1902).
pub(crate) fn absolute_lexically(path: &Path) -> PathBuf {
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    normalize_lexically_keeping_escapes(&abs)
}

/// The directories at and above `dir`, nearest first, each as its
/// absolute path ([`absolute_lexically`]) paired with a spelling in
/// `dir`'s own terms, for an upward walk whose finds are reported the
/// way `dir` is spelled. A relative `dir` keeps its lexical ancestors
/// (`./packages/a`, `./packages`, `.`), then spells each level above the
/// working directory with `..` (`./..`, `./../..`). So one directory
/// gets one spelling whichever descendant the walk starts from. An
/// absolute `dir` walks its own lexical ancestors.
pub(crate) fn ancestors_keeping_spelling(dir: &Path) -> impl Iterator<Item = (PathBuf, PathBuf)> {
    let relative = !dir.is_absolute();
    let abs = if relative {
        absolute_lexically(dir)
    } else {
        dir.to_path_buf()
    };
    let abs_levels =
        std::iter::successors(Some(abs), |p: &PathBuf| p.parent().map(Path::to_path_buf));
    let spelled = std::iter::successors(Some(dir.to_path_buf()), move |p: &PathBuf| {
        if !relative {
            return p.parent().map(Path::to_path_buf);
        }
        match p.components().next_back() {
            Some(Component::Normal(_)) => p.parent().map(Path::to_path_buf),
            _ => Some(p.join("..")),
        }
    });
    abs_levels.zip(spelled)
}

#[cfg(test)]
mod tests {
    #[test]
    fn ancestors_keeping_spelling_climbs_past_the_working_directory() {
        let cwd = absolute_lexically(Path::new("."));
        let walk = |dir: &str| -> Vec<(PathBuf, PathBuf)> {
            ancestors_keeping_spelling(Path::new(dir)).take(4).collect()
        };
        let up = |n: usize| cwd.ancestors().nth(n).unwrap().to_path_buf();
        let p = PathBuf::from;
        // One directory, one spelling, from either start.
        assert_eq!(
            walk("./packages/a"),
            vec![
                (cwd.join("packages/a"), p("./packages/a")),
                (cwd.join("packages"), p("./packages")),
                (up(0), p(".")),
                (up(1), p("./..")),
            ]
        );
        assert_eq!(walk(".")[1], (up(1), p("./..")));
        // The parent of a bare `node_modules` is the empty path.
        assert_eq!(
            walk(""),
            vec![
                (up(0), p("")),
                (up(1), p("..")),
                (up(2), p("../..")),
                (up(3), p("../../..")),
            ]
        );
        assert_eq!(walk("../x")[1], (up(1), p("..")));
        assert_eq!(walk("../x")[2], (up(2), p("../..")));
        // An absolute start walks its own ancestors, ending at the root.
        let abs: Vec<_> = ancestors_keeping_spelling(&cwd).collect();
        assert_eq!(abs.len(), cwd.ancestors().count());
        assert!(abs.iter().all(|(a, s)| a == s));
    }

    use super::*;

    #[test]
    fn resolve_rel_folds_against_base_with_a_floor() {
        assert_eq!(resolve_rel("", "a/./b/../c", 0).as_deref(), Some("a/c"));
        assert_eq!(
            resolve_rel("crates/x", "../y", 0).as_deref(),
            Some("crates/y")
        );
        assert_eq!(
            resolve_rel("crates/x", "..\\..\\z", 0).as_deref(),
            Some("z")
        );
        assert_eq!(resolve_rel("crates/x", "../../..", 0), None);
        assert_eq!(resolve_rel("", "..", 0), None);
        assert_eq!(resolve_rel("a", "..", 0).as_deref(), Some(""));
        // The floor keeps the first `floor` base segments.
        assert_eq!(resolve_rel("sub/dir", "../x", 1).as_deref(), Some("sub/x"));
        assert_eq!(resolve_rel("sub/dir", "../../x", 1), None);
        // Empty segments drop out of both sides.
        assert_eq!(resolve_rel("a//b/", ".//c", 0).as_deref(), Some("a/b/c"));
    }

    #[test]
    fn keeping_escapes_reports_out_of_root_paths() {
        let n = normalize_rel_keeping_escapes;
        assert_eq!(n("deps/../dev.txt"), "dev.txt");
        assert_eq!(n("a/b/../../c"), "c");
        assert_eq!(n("deps/../../x"), "../x");
        assert_eq!(n("./a//b/./c"), "a/b/c");
        assert_eq!(n("../x"), "../x");
        assert_eq!(n("../../x"), "../../x");
        assert_eq!(n("/abs/../x"), "/x");
        assert_eq!(n("deps\\..\\dev.txt"), "dev.txt");
    }

    #[test]
    fn anchored_spellings() {
        assert!(is_anchored("/x"));
        assert!(is_anchored("\\x"));
        assert!(!is_anchored("x/y"));
        assert!(!is_anchored("../x"));
        assert!(!is_anchored(""));
        #[cfg(windows)]
        {
            assert!(is_anchored("C:\\x"));
            assert!(is_anchored("C:x"));
        }
    }

    #[test]
    fn normalize_lexically_fails_closed_on_escape() {
        let n = |p: &str| normalize_lexically(Path::new(p));
        assert_eq!(
            n("/a/b/composer/../monolog/monolog"),
            Some(PathBuf::from("/a/b/monolog/monolog"))
        );
        assert_eq!(n("/a/b/c/../../../web/x"), Some(PathBuf::from("/web/x")));
        assert_eq!(n("/a/../.."), None);
        assert_eq!(n("../x"), None);
        assert_eq!(n("a/b/../c"), Some(PathBuf::from("a/c")));
        assert_eq!(n(""), Some(PathBuf::new()));
    }

    /// Regression: the pnpm crawler's former private copy let a second
    /// leading `..` pop the first (`PathBuf::pop` removes a `..` segment
    /// like any other), so `../../x` collapsed to `x` and a store two
    /// levels up compared as a child of the importer's spelling.
    #[test]
    fn keeping_escapes_keeps_every_leading_parent() {
        let n = |p: &str| normalize_lexically_keeping_escapes(Path::new(p));
        assert_eq!(n("../../x"), PathBuf::from("../../x"));
        assert_eq!(n("../a/../../x"), PathBuf::from("../../x"));
        assert_eq!(n("a/../../x"), PathBuf::from("../x"));
        assert_eq!(n("a/./b/.."), PathBuf::from("a"));
        assert_eq!(n("/.."), PathBuf::from("/"));
        assert_eq!(n("/a/../../b"), PathBuf::from("/b"));
        assert_eq!(n(""), PathBuf::new());
    }
}
