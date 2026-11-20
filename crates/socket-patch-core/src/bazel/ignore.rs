//! The `.bazelignore` lines that keep patched Go module copies, and the
//! patched crates a crate hub builds, out of the packages of a Bazel
//! workspace.
//!
//! Vendored and agent mode patch a Go module by keeping a copy of it under
//! the project's `.socket` directory, which a `go.mod` `replace` points
//! at. Bazel and gazelle walk that copy like any directory of the
//! workspace: a BUILD file in it (one the module ships, or the one
//! `bazel run //:gazelle` writes there) is a package of the workspace,
//! gazelle's `go_deps` copies the directory with that file, and the build
//! fails to load rules_go from it. A `.bazelignore` line keeps both out.
//! Bazel reads the file at the root of the workspace only and takes each
//! line as a literal directory path from that root.
//!
//! Vendored mode keeps a patched crate under `.socket/vendor/cargo`, and a
//! rules_rust crate hub writes a `BUILD.bazel` into it
//! ([`super::cargo_bazel`]). The hub reads the crate by its path, and the
//! package that file makes names repositories only the hub sees, so a
//! command that analyses every target fails on it (`bazel cquery //...`,
//! `bazel query 'deps(//...)'`). With a line the build is the same and the
//! package is none. Only where the module files make such a hub of the
//! project's crates: other tools of the ruleset build a crate from that
//! package.

use std::path::{Path, PathBuf};

use super::{cargo_bazel, BazelRoot};
use crate::utils::fs::{atomic_write_sync, read_regular_to_bytes_sync, run_blocking};
use crate::vendor::cargo_config::CARGO_VENDOR_DIR;
use crate::vendor::go_mod_edit::{GO_PATCHES_DIR, GO_VENDOR_DIR};

/// The warning code of a `.bazelignore` that [`sync`] could not update.
pub const NOT_UPDATED: &str = "bazelignore_not_updated";

/// The directories [`sync`] keeps a line for, from the project, what the
/// copies in each are, and whether they are the crates, whose pair is
/// added only under a hub that builds them.
const COPIES: [(&str, &str, bool); 3] = [
    (GO_VENDOR_DIR, "Go module", false),
    (GO_PATCHES_DIR, "Go module", false),
    (CARGO_VENDOR_DIR, "crate", true),
];

/// The line above the line [`sync`] writes for a directory of `what`
/// copies.
fn comment(what: &str) -> String {
    format!(
        "{MARK} patched {what} copies, not Bazel packages (to opt out, comment out the next line)"
    )
}

/// How [`comment`] starts, in this wording and in any other. A line is
/// [`sync`]'s to remove only when it stands under a line that starts so,
/// and a user who puts a `#` before that line has declined it: [`sync`]
/// leaves both lines alone.
const MARK: &str = "# socket-patch:";

/// Make the `.bazelignore` at the Bazel root of `project` agree with the
/// copies of the project: for each of `.socket/vendor/golang`,
/// `.socket/go-patches` and `.socket/vendor/cargo` ([`COPIES`]), one line
/// under its comment line while the directory exists and the file neither
/// covers nor declines it ([`settled`]), and no such pair once it is gone.
/// A pair is added only for an ecosystem the run has in scope (`go`,
/// `cargo`), and for the crates only where the workspace has a hub of the
/// project's crates ([`cargo_bazel::hub`], whose files are read when a
/// pair for that directory is to be added and at no other time): elsewhere
/// a directory that exists keeps what the file says of it, as does one
/// that cannot be probed. A file left empty is deleted.
/// Outside a Bazel workspace ([`super::bazel_root`]) nothing is read or
/// written, and that lookup is all the call costs.
///
/// The pair follows the directory, not the `replace`: a rollback that
/// keeps the copy on disk keeps its BUILD files in the workspace too.
///
/// The file may belong to several projects, and the lock a command holds is
/// its project's, so the edit, from its read to its write, is made under a
/// lock of the root ([`lock`]).
///
/// `Ok(Some)` is the file, when it was changed, and whose lines came or
/// went: `Go module`, `crate`, or both, in that order. `Err` is the detail
/// of a
/// [`NOT_UPDATED`] warning: the file could not be read or written, or is a
/// link, which socket-patch does not write through. The command that asked
/// has done its work either way.
pub async fn sync(project: &Path, go: bool, cargo: bool) -> Result<Option<Changed>, String> {
    let project = project.to_path_buf();
    run_blocking(move || sync_blocking(&project, go, cargo)).await
}

/// The file [`sync`] changed, and the copies its changed lines are about.
pub type Changed = (PathBuf, Vec<&'static str>);

/// The directory `dir` of the project, from the Bazel root `root`, as
/// Bazel writes a path: its parts with `/` after each, on every system.
/// Empty for the root itself.
pub(crate) fn from_root(root: &BazelRoot, dir: &Path) -> String {
    (root.project.join(dir).components())
        .map(|part| format!("{}/", part.as_os_str().to_string_lossy()))
        .collect()
}

/// Whether a line of the `.bazelignore` at `root` makes Bazel skip `dir`,
/// a directory from the project ([`covers`]). A file that cannot be read
/// covers nothing.
pub(crate) fn ignores(root: &BazelRoot, dir: &Path) -> bool {
    let dir = from_root(root, dir);
    let file = read_regular_to_bytes_sync(&root.dir.join(".bazelignore"));
    file.is_ok_and(|file| covers(&file, dir.trim_end_matches('/')))
}

fn sync_blocking(project: &Path, go: bool, cargo: bool) -> Result<Option<Changed>, String> {
    let Some(root) = super::bazel_root(project) else {
        return Ok(None);
    };
    let from_root = from_root(&root, Path::new(""));
    let project = root.dir.join(&root.project);
    // `None`: it cannot be told (a directory above it that may not be
    // searched). Only a directory that is not found is gone.
    let exists = |dir: &str| match std::fs::metadata(project.join(dir)) {
        Ok(meta) => Some(meta.is_dir()),
        Err(e) => (e.kind() == std::io::ErrorKind::NotFound).then_some(false),
    };
    let mut wanted = COPIES.map(|(dir, what, crates)| {
        // A copy that is there gets a pair only from a run that has its
        // ecosystem in scope.
        let adds = if crates { cargo } else { go };
        let state = exists(dir).filter(|there| adds || !there);
        (format!("{from_root}{dir}"), state, what)
    });
    // And the crates only under a hub that builds them. Its files are read
    // once, and only when `text` would get a pair for the crates.
    let mut hub = None;
    let mut under_a_hub = |wanted: &mut [(String, Option<bool>, &'static str); 3], text: &[u8]| {
        for ((.., crates), (line, state, _)) in COPIES.iter().zip(wanted.iter_mut()) {
            let adds = *crates && *state == Some(true) && !settled(text, line);
            if adds && !*hub.get_or_insert_with(|| cargo_bazel::hub(&root)) {
                *state = None;
            }
        }
    };

    let file = root.dir.join(".bazelignore");
    let read = || match read_regular_to_bytes_sync(&file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        read => read,
    };
    // Most runs find nothing to change, and take no lock to find that. A
    // file that cannot be read is an edit only with a copy to name in it.
    let unlocked = read().unwrap_or_default();
    under_a_hub(&mut wanted, &unlocked);
    if edited(&unlocked, &wanted) == unlocked {
        return Ok(None);
    }
    let _lock = lock(&root.dir);
    let (old, unreadable) = match read() {
        Ok(old) => (old, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    under_a_hub(&mut wanted, &old);
    let new = edited(&old, &wanted);
    // The root is canonical: on Windows that spelling has a prefix no user
    // types and no tool prints.
    let shown = crate::utils::pnpm_workspace::without_verbatim_prefix(file.clone());
    let failed = match unreadable {
        Some(e) => e,
        None if new == old => return Ok(None),
        // The target of a link is not the workspace's file to change, and
        // a replacement would turn the link into a regular file.
        None if crate::utils::containment::is_link(&file) => std::io::Error::other(
            "it is a symbolic link, which socket-patch does not write through",
        ),
        None => match write(&file, &old, &new) {
            Ok(()) => {
                // Whose lines the file has more or fewer of than before.
                let lines = |text: &[u8], line: &str| {
                    let is = |l: &&[u8]| content(l) == line.as_bytes();
                    text.split(|byte| *byte == b'\n').filter(is).count()
                };
                let differs = |line: &str| lines(&old, line) != lines(&new, line);
                let whose = wanted.iter().filter(|(line, ..)| differs(line));
                let mut whose: Vec<_> = whose.map(|(.., what)| *what).collect();
                whose.dedup();
                return Ok(Some((shown, whose)));
            }
            Err(e) => e,
        },
    };
    // A missing line is what the user has to act on. A pair that stays
    // behind for a directory that is gone ignores nothing.
    let missing: Vec<String> = wanted
        .iter()
        .filter(|(line, state, _)| *state == Some(true) && !settled(&old, line))
        .map(|(line, ..)| format!("`{line}`"))
        .collect();
    let advice = if !missing.is_empty() {
        format!(
            "add {} to it on a line of its own, with no space before or after, so that Bazel \
             and gazelle do not read the patched copies there as packages (`bazel run \
             //:gazelle`, `bazel build //...` or `bazel cquery //...` can otherwise fail)",
            missing.join(" and ")
        )
    } else {
        "the lines under socket-patch's comment in it name directories that no longer exist \
         and can be deleted"
            .to_string()
    };
    Err(format!(
        "could not update {}: {failed}; {advice}",
        shown.display()
    ))
}

/// The lock of the `.bazelignore` at `root`, which a process holds from its
/// read of the file to its write: without it, a pair that one project adds
/// between the read and the replacement of another project's removal is
/// lost. It is an advisory lock on the root directory itself, so that no
/// lock file is made anywhere. `None` when the directory cannot be opened
/// (on Windows no directory can be, this way) or locked, or stays held for
/// a second: the edit is then made without it.
fn lock(root: &Path) -> Option<std::fs::File> {
    let dir = std::fs::File::open(root).ok()?;
    for _ in 0..200 {
        match fs2::FileExt::try_lock_exclusive(&dir) {
            Ok(()) => return Some(dir),
            Err(e) if crate::patch::apply_lock::is_lock_contended(&e) => {
                std::thread::sleep(std::time::Duration::from_millis(5))
            }
            Err(_) => break,
        }
    }
    None
}

/// Make `file`, which holds `old`, hold `new`. It is opened for appending
/// first, which creates it when it is missing (with the permission bits of
/// any new file), follows no link and fails for a read-only file, so that
/// such a file is neither replaced nor deleted. What is only added is then
/// one write at the end of that file, which is not replaced; a removal
/// replaces the file, or deletes it when nothing is left.
fn write(file: &Path, old: &[u8], new: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
    let mut end = options.open(file)?;
    let Some(added) = new.strip_prefix(old) else {
        drop(end);
        return match new.is_empty() {
            true => std::fs::remove_file(file),
            false => atomic_write_sync(file, new, true),
        };
    };
    end.write_all(added)?;
    end.sync_all()
}

/// A line of the file without its line break (`\n`, or `\r\n`).
fn content(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// `path` without one trailing `/` and a leading `./`: the same directory to Bazel.
fn plain(path: &[u8]) -> &[u8] {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    path.strip_prefix(b"./").unwrap_or(path)
}

/// Whether some line of `old` makes Bazel and gazelle skip the directory
/// `path`: the path itself or a directory above it, however spelled
/// ([`plain`]). Bazel takes a line literally, so one with a blank before or
/// after it, a `#` line, a pattern, or a mere string prefix of the path
/// does not.
fn covers(old: &[u8], path: &str) -> bool {
    old.split_inclusive(|byte| *byte == b'\n').any(|line| {
        let line = plain(content(line));
        let rest = path.as_bytes().strip_prefix(line);
        !line.is_empty() && rest.is_some_and(|rest| rest.is_empty() || rest[0] == b'/')
    })
}

/// Whether `old` needs no pair for the directory `path`: a line covers it
/// ([`covers`]), or the user declined the pair by commenting its path line
/// out: a [`MARK`] line, then a line of `#`, any blanks, and the [`plain`]
/// path.
fn settled(old: &[u8], path: &str) -> bool {
    let lines: Vec<&[u8]> = (old.split_inclusive(|byte| *byte == b'\n'))
        .map(content)
        .collect();
    let declined = |pair: &[&[u8]]| {
        let commented = pair[1].strip_prefix(b"#");
        pair[0].starts_with(MARK.as_bytes())
            && commented.is_some_and(|rest| plain(rest.trim_ascii_start()) == path.as_bytes())
    };
    covers(old, path) || lines.windows(2).any(declined)
}

/// `old` as [`sync`] leaves it for `wanted`, the line of each directory,
/// whether the directory exists (`None`: unknown, or not this run's to
/// add, and nothing changes for it) and what its copies are: without the
/// pairs of the directories that are gone, and with a pair at its end, in
/// the file's own line ending, for each directory that exists and is not
/// [`settled`]. A file whose last line has no line break gets one before
/// the pair and none after it, and loses that one (the comment line's own)
/// with a pair that ends the file that way, so that the file without the
/// pair is the file of before, byte for byte.
fn edited(old: &[u8], wanted: &[(String, Option<bool>, &str)]) -> Vec<u8> {
    let gone = |line: &[u8]| {
        wanted
            .iter()
            .any(|(l, exists, _)| *exists == Some(false) && l.as_bytes() == content(line))
    };
    let lines: Vec<&[u8]> = old.split_inclusive(|byte| *byte == b'\n').collect();
    let mut new = Vec::with_capacity(old.len());
    let mut at = 0;
    while at < lines.len() {
        match lines.get(at + 1).filter(|next| gone(next)) {
            Some(path) if lines[at].starts_with(MARK.as_bytes()) => {
                let nl = &lines[at][content(lines[at]).len()..];
                if !path.ends_with(b"\n") && new.ends_with(nl) {
                    new.truncate(new.len() - nl.len());
                }
                at += 2;
            }
            _ => {
                new.extend_from_slice(lines[at]);
                at += 1;
            }
        }
    }
    let nl = crate::utils::line_endings::terminator(&String::from_utf8_lossy(old));
    for (line, exists, what) in wanted {
        if *exists != Some(true) || settled(&new, line) {
            continue;
        }
        let comment = comment(what);
        let pair = match new.is_empty() || new.ends_with(b"\n") {
            true => format!("{comment}{nl}{line}{nl}"),
            false => format!("{nl}{comment}{nl}{line}"),
        };
        new.extend_from_slice(pair.as_bytes());
    }
    new
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const VENDOR: &str = ".socket/vendor/golang";
    const PATCHES: &str = ".socket/go-patches";
    const CRATES: &str = ".socket/vendor/cargo";
    /// The line above the line of a directory of Go module copies.
    const COMMENT: &str =
        "# socket-patch: patched Go module copies, not Bazel packages (to opt out, comment out the next line)";

    /// [`edited`] for the two directories of a project at the root, each
    /// existing or not.
    fn edit(old: &str, vendor: bool, patches: bool) -> String {
        let wanted = [(VENDOR, vendor), (PATCHES, patches)];
        let wanted = wanted.map(|(line, exists)| (line.to_string(), Some(exists), "Go module"));
        String::from_utf8(edited(old.as_bytes(), &wanted)).unwrap()
    }

    fn pair(line: &str) -> String {
        format!("{COMMENT}\n{line}\n")
    }

    /// What Bazel 9.3.2, 8.8.2 and 7.7.2 and gazelle 0.45.0 and 0.54.0 do
    /// with each form of line, for a project at the root and for one in
    /// `svc`.
    #[test]
    fn a_line_covers_the_path_or_a_directory_above_it_and_nothing_else() {
        let covering = [
            VENDOR,
            ".socket/vendor/golang/",
            "./.socket/vendor/golang",
            ".socket/vendor/golang\r",
            ".socket/vendor",
            ".socket",
            ".socket/",
            "./.socket/\r",
        ];
        for line in covering {
            let old = format!("node_modules\n{line}\nthird_party\n");
            assert!(covers(old.as_bytes(), VENDOR), "{line:?}");
            assert!(covers(line.as_bytes(), VENDOR), "{line:?}, no line break");
        }
        let not_covering = [
            " .socket/vendor/golang",
            ".socket/vendor/golang ",
            ".socket/vendor/golang\t",
            "#.socket/vendor/golang",
            "# .socket",
            ".socket/**",
            ".socket/*",
            ".socket/vendor/golan?",
            ".socket/vendor/[g]olang",
            ".socket/vendor/gol",
            ".sock",
            ".socket/vendor/golang/uuid",
            ".socket/go-patches",
            ".socket//",
            "/",
            "./",
            "",
        ];
        for line in not_covering {
            let old = format!("{line}\n");
            assert!(!covers(old.as_bytes(), VENDOR), "{line:?}");
        }
        // Below the root only a path from the root covers.
        let below = "svc/.socket/vendor/golang";
        for line in [below, "svc/.socket", "svc", "./svc/"] {
            assert!(covers(line.as_bytes(), below), "{line:?}");
        }
        for line in [VENDOR, ".socket", "sv", "svc/.sock", "other/.socket"] {
            assert!(!covers(line.as_bytes(), below), "{line:?}");
        }
    }

    #[test]
    fn a_pair_is_appended_once_for_each_directory_no_line_covers() {
        assert_eq!(edit("", false, false), "");
        assert_eq!(edit("", true, false), pair(VENDOR));
        assert_eq!(edit("", false, true), pair(PATCHES));
        let both = pair(VENDOR) + &pair(PATCHES);
        assert_eq!(edit("", true, true), both);
        // A second run leaves one pair of each.
        assert_eq!(edit(&both, true, true), both);
        assert_eq!(edit(&pair(VENDOR), true, true), both);
        // After the user's lines, in the line breaks of the file: Bazel
        // and gazelle read a line that ends in CRLF as the path.
        let crlf = pair(VENDOR).replace('\n', "\r\n");
        assert_eq!(
            edit("a\nb\n", true, false),
            format!("a\nb\n{}", pair(VENDOR))
        );
        assert_eq!(edit("a\r\nb\r\n", true, false), format!("a\r\nb\r\n{crlf}"));
        // A line of the user's that covers the directory is enough, and a
        // line that does not is not.
        for covered in [".socket\n", "./.socket/vendor/golang/\n", ".socket/vendor"] {
            assert_eq!(edit(covered, true, false), covered);
        }
        assert_eq!(
            edit(".socket/vendor/golang \n", true, false),
            format!(".socket/vendor/golang \n{}", pair(VENDOR))
        );
        assert_eq!(edit(".socket\n", true, true), ".socket\n");
    }

    #[test]
    fn only_a_pair_of_a_directory_that_is_gone_is_removed() {
        let both = pair(VENDOR) + &pair(PATCHES);
        assert_eq!(edit(&both, false, true), pair(PATCHES));
        assert_eq!(edit(&both, true, false), pair(VENDOR));
        // The user's lines stay byte for byte, around the pair and in
        // place of it: a line without the comment above it is theirs.
        let own = "# mine\n\n  indented\t\nnode_modules/\n";
        let around = format!("{own}{}{own}", pair(VENDOR));
        assert_eq!(edit(&around, false, false), format!("{own}{own}"));
        for theirs in [
            format!("{VENDOR}\n"),
            format!("{COMMENT}\n{VENDOR}/\n"),
            format!(" {COMMENT}\n{VENDOR}\n"),
            format!("# socket-patch\n{VENDOR}\n"),
            format!("#socket-patch: mine\n{VENDOR}\n"),
            format!("{COMMENT}\n\n{VENDOR}\n"),
            format!("{COMMENT}\n"),
        ] {
            assert_eq!(edit(&theirs, false, false), theirs);
        }
    }

    /// socket-patch knows its lines by the start of the comment line, so a
    /// pair under another wording of it (an earlier or a later release's) is
    /// still its own: it stays, alone, while the copy is there, goes with
    /// the copy, byte for byte, and is declined by a commented-out path line.
    #[test]
    fn a_pair_under_another_wording_of_the_comment_is_known() {
        assert!(COMMENT.starts_with(MARK));
        for comment in [MARK, "# socket-patch: said otherwise", "# socket-patch:\t"] {
            let reworded = format!("node_modules\n{comment}\n{VENDOR}\n");
            assert_eq!(edit(&reworded, true, false), reworded, "{comment:?}");
            assert_eq!(edit(&reworded, false, false), "node_modules\n");
            let ending = format!("node_modules\r\n{comment}\r\n{VENDOR}");
            assert_eq!(edit(&ending, false, false), "node_modules");
            let declined = format!("node_modules\n{comment}\n# {VENDOR}\n");
            for vendor in [true, false] {
                assert_eq!(edit(&declined, vendor, false), declined, "{comment:?}");
            }
        }
    }

    /// The pairs go as they came, one by one in either order or both at
    /// once: what is left is the file of before, byte for byte, also when
    /// its last line had no line break, or ended in a carriage return on
    /// its own. Lines the user wrote after a pair stay, with the line break
    /// that set the pair apart from the file.
    #[test]
    fn taking_the_pairs_away_leaves_the_file_of_before() {
        // Each file, and the line break it gets before its first pair.
        let files = [
            ("", ""),
            ("a\n", ""),
            ("a\nb", "\n"),
            ("a\r\nb\r\n", ""),
            ("a\r\nb", "\r\n"),
            ("# mine\n\n  x\t", "\n"),
            ("a\r", "\n"),
            ("a\n\r", "\n"),
            ("a\rb\rc\r", "\n"),
            ("x\r\ny\r", "\r\n"),
        ];
        for (old, nl) in files {
            let ended = old.is_empty() || old.ends_with('\n');
            assert_eq!(ended, nl.is_empty(), "{old:?}");
            let one = edit(old, true, false);
            assert!(one.starts_with(&format!("{old}{nl}{COMMENT}")), "{old:?}");
            let two = edit(&one, true, true);
            assert!(one.starts_with(old) && two.starts_with(&one), "{old:?}");
            assert_eq!(two, edit(old, true, true), "{old:?}");
            assert_eq!(two.ends_with('\n'), ended, "{old:?}");
            assert!(two.ends_with(PATCHES) || two.ends_with('\n'), "{old:?}");
            for first in [
                edit(&two, false, true),
                edit(&two, true, false),
                two.clone(),
            ] {
                assert_eq!(edit(&first, false, false), old, "{old:?} from {first:?}");
            }
            let more = format!("{one}{nl}mine\n");
            assert_eq!(edit(&more, false, false), format!("{old}{nl}mine\n"));
        }
        // A pair that ends the file without a line break goes with the
        // line break before it, whoever took its own away, when that is
        // the line break of its comment line: another one was not written
        // with the pair.
        assert_eq!(edit(&format!("a\n{COMMENT}\n{VENDOR}"), false, false), "a");
        let other = format!("a\r\n{COMMENT}\n{VENDOR}");
        assert_eq!(edit(&other, false, false), "a\r");
        let other = format!("a\n{COMMENT}\r\n{VENDOR}");
        assert_eq!(edit(&other, false, false), "a\n");
    }

    /// The user's "no": the comment line with the path line commented out
    /// under it. Nothing is added for that directory and the two lines
    /// stay, whether the directory is there or not, while the pair of the
    /// other directory comes and goes.
    #[test]
    fn a_commented_out_path_line_declines_the_pair() {
        let spellings = [
            format!("#{VENDOR}"),
            format!("# \t{VENDOR}"),
            format!("# {VENDOR}/"),
            format!("# ./{VENDOR}"),
        ];
        for path in spellings {
            let declined = format!("node_modules\n{COMMENT}\n{path}\n");
            for vendor in [true, false] {
                assert_eq!(edit(&declined, vendor, false), declined);
                let other = edit(&declined, vendor, true);
                assert_eq!(other, format!("{declined}{}", pair(PATCHES)));
                assert_eq!(edit(&other, vendor, false), declined);
            }
            assert!(settled(declined.as_bytes(), VENDOR));
            assert!(!settled(declined.as_bytes(), PATCHES));
        }
        // No "no": without the comment line above it (a commented-out
        // one included), or not that path.
        for other in [
            format!("#{VENDOR}\n"),
            format!("# {COMMENT}\n# {VENDOR}\n"),
            format!("{COMMENT}\n\n#{VENDOR}\n"),
            format!("{COMMENT}\n#{VENDOR}//\n"),
            format!("{COMMENT}\n#{VENDOR} \n"),
            format!("{COMMENT}\n #{VENDOR}\n"),
            format!("{COMMENT}\n##{VENDOR}\n"),
            format!("{COMMENT}\n# .socket\n"),
            format!("{COMMENT}\n#{PATCHES}\n"),
        ] {
            assert_eq!(edit(&other, true, false), other.clone() + &pair(VENDOR));
        }
    }

    /// A Bazel workspace with a checkout at its root and a project in
    /// `rel` of it (`""`: the root), which has the copy directory `dir`.
    fn project(rel: &str, dir: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let project = root.join(rel);
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(project.join(dir)).unwrap();
        fs::write(root.join("MODULE.bazel"), "").unwrap();
        (tmp, root, project)
    }

    /// [`super::sync`] for a run that has every ecosystem in scope.
    async fn sync(project: &Path) -> Result<Option<Changed>, String> {
        super::sync(project, true, true).await
    }

    /// The file [`sync`] says it changed, as the test spells it, for lines
    /// of Go module copies.
    fn changed(root: &Path) -> Result<Option<Changed>, String> {
        changed_for(root, "Go module")
    }

    fn changed_for(root: &Path, whose: &'static str) -> Result<Option<Changed>, String> {
        let file = root.join(".bazelignore");
        let file = crate::utils::pnpm_workspace::without_verbatim_prefix(file);
        Ok(Some((file, whose.split(" and ").collect())))
    }

    #[tokio::test]
    async fn the_file_at_the_root_follows_the_directories_of_the_project() {
        let (_tmp, root, project) = project("", VENDOR);
        let file = root.join(".bazelignore");
        assert_eq!(sync(&project).await, changed(&root));
        assert_eq!(sync(&project).await, Ok(None), "a second run");
        assert_eq!(fs::read_to_string(&file).unwrap(), pair(VENDOR));
        fs::create_dir_all(project.join(PATCHES)).unwrap();
        assert_eq!(sync(&project).await, changed(&root));
        let both = pair(VENDOR) + &pair(PATCHES);
        assert_eq!(fs::read_to_string(&file).unwrap(), both);
        fs::remove_dir_all(project.join(VENDOR)).unwrap();
        assert_eq!(sync(&project).await, changed(&root));
        assert_eq!(fs::read_to_string(&file).unwrap(), pair(PATCHES));
        // The file `sync` made goes with its last pair, and so does an
        // empty one the user had.
        fs::remove_dir_all(project.join(PATCHES)).unwrap();
        assert_eq!(sync(&project).await, changed(&root));
        assert!(!file.exists());
        fs::write(&file, "").unwrap();
        assert_eq!(sync(&project).await, Ok(None));
        assert_eq!(fs::read_to_string(&file).unwrap(), "", "nothing to change");
    }

    /// A pair is written at the end of the file that is there, whatever its
    /// last line break, and that file is not replaced: a hard link to it
    /// reads the pair too. A missing file is created, with the permission
    /// bits of any new file. Without the directory the file is the one of
    /// before again.
    #[tokio::test]
    async fn a_pair_is_appended_to_the_file_that_is_there() {
        let crlf = pair(VENDOR).replace('\n', "\r\n");
        let files = [
            (None, pair(VENDOR)),
            (Some(""), pair(VENDOR)),
            (Some("node_modules\n# mine\n"), pair(VENDOR)),
            (
                Some("node_modules\nthird_party"),
                format!("\n{COMMENT}\n{VENDOR}"),
            ),
            (Some("a\r\nb\r\n"), crlf.clone()),
            (Some("a\r\nb"), format!("\r\n{}", crlf.trim_end())),
        ];
        for (old, added) in files {
            let (_tmp, root, project) = project("", VENDOR);
            let (file, other) = (root.join(".bazelignore"), root.join("other"));
            if let Some(old) = old {
                fs::write(&file, old).unwrap();
                fs::hard_link(&file, &other).unwrap();
            }
            assert_eq!(sync(&project).await, changed(&root));
            let new = format!("{}{added}", old.unwrap_or(""));
            assert_eq!(fs::read_to_string(&file).unwrap(), new, "{old:?}");
            if old.is_some() {
                assert_eq!(fs::read_to_string(&other).unwrap(), new, "{old:?}");
            } else {
                fs::write(&other, "").unwrap();
                let bits = |path| fs::metadata(path).unwrap().permissions();
                assert_eq!(bits(&file), bits(&other));
            }
            fs::remove_dir_all(project.join(VENDOR)).unwrap();
            assert_eq!(sync(&project).await, changed(&root));
            let left = fs::read_to_string(&file).ok();
            assert_eq!(
                left.as_deref(),
                old.filter(|old| !old.is_empty()),
                "{old:?}"
            );
        }
    }

    /// A run that leaves Go out adds no pair for a copy that is there, and
    /// says nothing of one it cannot add; it takes the pair of a copy that
    /// is gone away, and says so when it cannot.
    #[tokio::test]
    async fn a_run_that_leaves_go_out_only_takes_pairs_away() {
        let (_tmp, root, project) = project("", VENDOR);
        let file = root.join(".bazelignore");
        let sync = |project: PathBuf| async move { super::sync(&project, false, true).await };
        assert_eq!(sync(project.clone()).await, Ok(None));
        assert!(!file.exists());
        fs::create_dir(&file).unwrap();
        assert_eq!(sync(project.clone()).await, Ok(None), "unreadable");
        fs::remove_dir(&file).unwrap();
        // The pair of the copy that is there stays, and the one of the copy
        // that is gone goes.
        let kept = format!("node_modules\n{}", pair(VENDOR));
        fs::write(&file, format!("{kept}{}", pair(PATCHES))).unwrap();
        assert_eq!(sync(project.clone()).await, changed(&root));
        assert_eq!(fs::read_to_string(&file).unwrap(), kept);
        fs::remove_dir_all(project.join(VENDOR)).unwrap();
        let mut bits = fs::metadata(&file).unwrap().permissions();
        bits.set_readonly(true);
        fs::set_permissions(&file, bits).unwrap();
        if fs::OpenOptions::new().append(true).open(&file).is_err() {
            let detail = sync(project.clone()).await.expect_err("read-only");
            assert!(detail.contains("can be deleted"), "{detail}");
            assert_eq!(fs::read_to_string(&file).unwrap(), kept);
        }
    }

    /// Two projects under one root share the file. What each does to it at
    /// the same moment as the other stays: two pairs added at once, and,
    /// under the lock of the root, which Windows does not have, a pair
    /// added while the other project's is removed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_projects_that_edit_at_once_both_have_their_way() {
        let (_tmp, root, a) = project("a", VENDOR);
        let (b, file) = (root.join("b"), root.join(".bazelignore"));
        fs::create_dir_all(b.join(PATCHES)).unwrap();
        let (pair_a, pair_b) = (
            pair("a/.socket/vendor/golang"),
            pair("b/.socket/go-patches"),
        );
        let at_once = || async {
            let runs = [a.clone(), b.clone()]
                .map(|project| tokio::spawn(async move { sync(&project).await.is_ok() }));
            for run in runs {
                assert!(run.await.unwrap());
            }
            fs::read_to_string(&file).unwrap()
        };
        for round in 0..25 {
            let _ = fs::remove_file(&file);
            let both = at_once().await;
            let either = [format!("{pair_a}{pair_b}"), format!("{pair_b}{pair_a}")];
            assert!(either.contains(&both), "round {round}: {both:?}");
            // `a` loses its copy while `b`, whose pair is not there, adds.
            if cfg!(unix) {
                fs::write(&file, &pair_a).unwrap();
                fs::remove_dir_all(a.join(VENDOR)).unwrap();
                assert_eq!(at_once().await, pair_b, "round {round}");
                fs::create_dir_all(a.join(VENDOR)).unwrap();
            }
        }
    }

    /// The vendored crates get their pair, under a comment line of their
    /// own, where the module files of the workspace make a crate hub and
    /// the run has Cargo in scope. Elsewhere a directory that is there
    /// keeps what the file says of it, and one that is gone loses its pair
    /// as any other does. The caller is told whose lines changed.
    #[tokio::test]
    async fn the_crates_get_a_pair_only_where_a_hub_builds_them() {
        use crate::bazel::cargo_bazel::tests::HUB;
        let crates = format!(
            "# socket-patch: patched crate copies, not Bazel packages (to opt out, comment out \
             the next line)\n{}\n",
            "svc/.socket/vendor/cargo"
        );
        let (_tmp, root, project) = project("svc", CRATES);
        let (file, module) = (root.join(".bazelignore"), root.join("MODULE.bazel"));
        // No hub: no pair, and the pair that is there stays.
        for old in [None, Some(crates.as_str())] {
            if let Some(old) = old {
                fs::write(&file, old).unwrap();
            }
            assert_eq!(sync(&project).await, Ok(None), "{old:?}");
            assert_eq!(fs::read_to_string(&file).ok().as_deref(), old);
        }
        fs::remove_file(&file).unwrap();
        // Nor under the hub of another Cargo workspace of the checkout.
        fs::write(&module, HUB).unwrap();
        assert_eq!(sync(&project).await, Ok(None), "the root's hub");
        assert!(!file.exists());
        let hub = HUB.replace("\"//:", "\"//svc:");
        fs::write(&module, &hub).unwrap();
        // A run that leaves Cargo out adds none either.
        assert_eq!(super::sync(&project, true, false).await, Ok(None));
        assert!(!file.exists());
        assert_eq!(sync(&project).await, changed_for(&root, "crate"));
        assert_eq!(fs::read_to_string(&file).unwrap(), crates);
        assert_eq!(sync(&project).await, Ok(None), "a second run");
        // With a Go copy beside them, and then without the crates.
        fs::create_dir_all(project.join(VENDOR)).unwrap();
        assert_eq!(sync(&project).await, changed(&root));
        let both = format!("{crates}{}", pair("svc/.socket/vendor/golang"));
        assert_eq!(fs::read_to_string(&file).unwrap(), both);
        fs::remove_dir_all(project.join(CRATES)).unwrap();
        fs::remove_dir_all(project.join(VENDOR)).unwrap();
        fs::write(&module, "").unwrap();
        let gone = super::sync(&project, false, false).await;
        assert_eq!(gone, changed_for(&root, "Go module and crate"));
        assert!(!file.exists());
        // A user's "no" holds for the crates as for any other directory.
        fs::write(&module, &hub).unwrap();
        fs::create_dir_all(project.join(CRATES)).unwrap();
        let declined = crates.replace("\nsvc/", "\n# svc/");
        fs::write(&file, &declined).unwrap();
        assert_eq!(sync(&project).await, Ok(None));
        assert_eq!(fs::read_to_string(&file).unwrap(), declined);
    }

    #[tokio::test]
    async fn a_project_below_the_root_is_named_from_the_root() {
        let (_tmp, root, project) = project("svc/go", PATCHES);
        assert_eq!(sync(&project).await, changed(&root));
        let file = fs::read_to_string(root.join(".bazelignore")).unwrap();
        assert_eq!(file, pair("svc/go/.socket/go-patches"));
        assert!(!project.join(".bazelignore").exists());
        // A line that names the directory from the project covers nothing
        // there, and a sibling's pair is not this project's to remove.
        let sibling = pair("svc/js/.socket/go-patches") + ".socket/go-patches\n";
        fs::write(root.join(".bazelignore"), &sibling).unwrap();
        assert_eq!(sync(&project).await, changed(&root));
        let file = fs::read_to_string(root.join(".bazelignore")).unwrap();
        assert_eq!(file, sibling.clone() + &pair("svc/go/.socket/go-patches"));
        fs::remove_dir_all(project.join(PATCHES)).unwrap();
        assert_eq!(sync(&project).await, changed(&root));
        assert_eq!(
            fs::read_to_string(root.join(".bazelignore")).unwrap(),
            sibling
        );
    }

    #[tokio::test]
    async fn outside_a_bazel_workspace_nothing_is_written() {
        let (_tmp, root, project) = project("", VENDOR);
        fs::remove_file(root.join("MODULE.bazel")).unwrap();
        fs::create_dir(root.join("WORKSPACE")).unwrap();
        fs::write(root.join(".bazelignore"), pair(PATCHES)).unwrap();
        assert_eq!(sync(&project).await, Ok(None));
        assert_eq!(
            fs::read_to_string(root.join(".bazelignore")).unwrap(),
            pair(PATCHES)
        );
    }

    /// A copy directory that cannot be probed, here below a directory that
    /// may not be searched, is not gone: its pair stays, and it gets none.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_directory_that_cannot_be_probed_keeps_what_the_file_says() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, root, project) = project("", VENDOR);
        let (file, above) = (root.join(".bazelignore"), project.join(".socket/vendor"));
        let search = |bits| fs::set_permissions(&above, fs::Permissions::from_mode(bits)).unwrap();
        search(0o000);
        let mut seen = Vec::new();
        for old in [pair(VENDOR), "node_modules\n".to_string()] {
            fs::write(&file, &old).unwrap();
            seen.push((sync(&project).await, fs::read_to_string(&file).ok(), old));
        }
        // Root searches any directory, and tells that the copy is there.
        let told = fs::metadata(project.join(VENDOR)).is_ok();
        search(0o755);
        for (said, left, old) in seen.into_iter().filter(|_| !told) {
            assert_eq!((said, left), (Ok(None), Some(old)));
        }
        // Not found is gone, as before.
        fs::remove_dir_all(project.join(VENDOR)).unwrap();
        fs::write(&file, pair(VENDOR)).unwrap();
        assert_eq!(sync(&project).await, changed(&root));
        assert!(!file.exists());
    }

    /// A file that cannot be read or replaced is the caller's warning, with
    /// the line to add, and stays as it is.
    #[tokio::test]
    async fn a_file_that_cannot_be_updated_is_reported_with_the_line() {
        let (_tmp, root, project) = project("", VENDOR);
        let file = root.join(".bazelignore");
        fs::create_dir(&file).unwrap();
        let detail = sync(&project)
            .await
            .expect_err("a directory in the file's place");
        assert!(
            detail.contains("add `.socket/vendor/golang` to it"),
            "{detail}"
        );
        let shown = crate::utils::pnpm_workspace::without_verbatim_prefix(file);
        let start = format!("could not update {}: ", shown.display());
        assert!(detail.starts_with(&start), "{detail}");
        // Nothing to add: nothing to report.
        fs::remove_dir_all(project.join(VENDOR)).unwrap();
        assert_eq!(sync(&project).await, Ok(None));
    }

    /// The lock is one on the root directory itself, and no file anywhere.
    /// An edit waits a second for whoever holds it and is then made without
    /// it. A run that has nothing to change takes none, and so does not
    /// wait: the file is as it should be, or it cannot be read and the
    /// project has no copy to name in it.
    #[cfg(unix)]
    #[tokio::test]
    async fn only_an_edit_takes_the_lock_of_the_root_directory() {
        let (_tmp, root, project) = project("", "");
        let (file, held) = (root.join(".bazelignore"), fs::File::open(&root).unwrap());
        fs2::FileExt::lock_exclusive(&held).unwrap();
        let start = std::time::Instant::now();
        for unreadable in [false, true] {
            if unreadable {
                fs::create_dir(&file).unwrap();
            }
            assert_eq!(sync(&project).await, Ok(None), "unreadable: {unreadable}");
        }
        fs::remove_dir(&file).unwrap();
        let idle = start.elapsed();
        fs::create_dir_all(project.join(VENDOR)).unwrap();
        let start = std::time::Instant::now();
        assert_eq!(sync(&project).await, changed(&root));
        let second = std::time::Duration::from_secs(1);
        // With a lock to take, each of the two idle runs waits that second.
        assert!(idle < 2 * second && start.elapsed() >= second, "{idle:?}");
        assert_eq!(fs::read_to_string(&file).unwrap(), pair(VENDOR));
        let mut names: Vec<_> = fs::read_dir(&root).unwrap().flatten().collect();
        names.sort_by_key(|entry| entry.file_name());
        let names: Vec<_> = names.iter().map(|entry| entry.file_name()).collect();
        assert_eq!(names, [".bazelignore", ".git", ".socket", "MODULE.bazel"]);
    }

    /// A read-only file stays as it is, bytes and permission bits: it is
    /// neither replaced to get a pair in or out, nor deleted with its last
    /// pair. What it lacks, or holds too much, is the caller's warning.
    #[tokio::test]
    async fn a_read_only_file_is_reported_and_stays() {
        let stale = "the lines under socket-patch's comment in it name directories that no longer";
        let files = [
            (
                "node_modules\n".to_string(),
                true,
                "add `.socket/vendor/golang` to it",
            ),
            (format!("node_modules\n{}", pair(VENDOR)), false, stale),
            (pair(VENDOR), false, stale),
        ];
        for (old, copy, advice) in files {
            let (_tmp, root, project) = project("", VENDOR);
            let file = root.join(".bazelignore");
            fs::write(&file, &old).unwrap();
            let mut bits = fs::metadata(&file).unwrap().permissions();
            bits.set_readonly(true);
            fs::set_permissions(&file, bits.clone()).unwrap();
            if fs::OpenOptions::new().append(true).open(&file).is_ok() {
                return; // A root process writes a read-only file.
            }
            if !copy {
                fs::remove_dir_all(project.join(VENDOR)).unwrap();
            }
            let detail = sync(&project).await.expect_err("a read-only file");
            assert!(detail.contains(advice), "{detail}");
            assert_eq!(fs::read_to_string(&file).unwrap(), old);
            assert_eq!(fs::metadata(&file).unwrap().permissions(), bits);
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_linked_file_is_not_written_through() {
        let (_tmp, root, project) = project("", VENDOR);
        let (file, target) = (root.join(".bazelignore"), root.join("shared-ignore"));
        std::os::unix::fs::symlink(&target, &file).unwrap();
        // A pair to add, and then one to take away.
        for (old, advice) in [
            (
                "node_modules\n".to_string(),
                "add `.socket/vendor/golang` to it",
            ),
            (pair(VENDOR), "can be deleted"),
        ] {
            fs::write(&target, &old).unwrap();
            let detail = sync(&project)
                .await
                .expect_err("a link in the file's place");
            assert!(detail.contains("symbolic link"), "{detail}");
            assert!(detail.contains(advice), "{detail}");
            assert!(fs::symlink_metadata(&file)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(fs::read_to_string(&target).unwrap(), old);
            let _ = fs::remove_dir_all(project.join(VENDOR));
        }
        // The user's own line through the link covers, and nothing is
        // written.
        fs::create_dir_all(project.join(VENDOR)).unwrap();
        fs::write(&target, ".socket\n").unwrap();
        assert_eq!(sync(&project).await, Ok(None));
    }
}
