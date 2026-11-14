//! The one writer anchored at the Bazel root (design 5.4, hazard HZ-04):
//! `.bazelignore` lines and their rows in the root's owned index.
//!
//! A `.socket/go-patches` tree, and a dir-shaped `.socket/vendor` tree, is
//! an unpacked upstream package with the BUILD and WORKSPACE files its
//! upstream ships. Under a Bazel root those join `//...`, where `build`,
//! `test` and `query` fail on them on every Bazel line (probe B3) and
//! gazelle rewires the user's own targets into the tree (probe S9). One
//! line in the root's `.bazelignore` hides the tree, and Bazel reads that
//! file at the root and nowhere else. Every other write seam is relative
//! to the project, which can sit below the root, so the line goes through
//! here and not through the vendor ledger or the group commit.
//!
//! - **Line first, then the tree.** A `before_*` call runs before a copy
//!   or a vendored unit is created. A line for a directory that does not
//!   exist is inert, and the `after_*` call that follows the write takes
//!   the line back out when the write left no tree it covers, so a run
//!   that is refused or fails afterwards leaves the root as it found it.
//!   A line that stays is reported with the result, failed or not: the
//!   root's files changed and are the user's to commit.
//! - **No line, no new copy.** Where the line is needed and cannot be
//!   written, creating a copy or a unit is refused and the refusal prints
//!   each line and the file it belongs in: several Bazel roots above the
//!   project, a root outside the directory socket-patch writes in, a
//!   `.bazelignore` with a lone-CR line end or one that cannot be read, a
//!   project path no line can spell for every reader, a label the line
//!   would delete. The decision is made per copy: other copies under the
//!   same `.socket/go-patches` or `.socket/vendor` do not let a new one
//!   through.
//! - **A copy that is already there is never refused.** When it is
//!   rebuilt and its line is missing and cannot be written, the run goes
//!   on and reports `bazel_workspace_ignore_line_needed`.
//! - **The label scan precedes the write** wherever the tree's directory
//!   exists and may hold a Bazel package: the line turns each label under
//!   it into "Package is considered deleted" (gazelle writes such labels,
//!   probe S9; a `maven.override` or a wheel label names a vendored
//!   archive, probes M3 and Y4). A bounded scan of the root's BUILD and
//!   `.bzl` files has to find none, or the line is not written.
//! - **Reported, not decided here.** A line of the user's with a leading
//!   `/` is dead on Bazel 7 and fails every command from 8.8.2 on: it is
//!   named and left as found (design 5.3). Outside any checkout a boundary
//!   file above the project is a root only when somebody builds there; a
//!   stray one refuses nothing and is named with the line it would need.
//! - **Removal by record.** [`after_removal`] takes a line out only when
//!   the index holds its row, by exact match, once no tree it covers is
//!   left. What the insert added to make room for the line goes with it,
//!   so a round trip is byte-identical. A recorded line that cannot be
//!   taken out is reported, never left in silence.
//!
//! Both files are replaced by stage and rename, never truncated, under one
//! lock per root (`.socket/bazel/apply.lock`, which exists only while it
//! is held), so two sub-projects of one root are applied in order, in one
//! run or in two. The lock is the bare one of `patch::apply_lock`
//! (`acquire_bare`): it does nothing but lock, because the root's
//! `.socket` is not a project's (the project lock also finishes an
//! interrupted vendored commit and sweeps stage entries there), and a run
//! that is interrupted inside an edit removes the file on its way out as
//! it removes the project's. No stage file is left beside either file: a
//! failed write removes its own, and the next edit removes what an
//! interrupted one left (hazard HZ-27). The writes bypass an open group
//! commit on purpose: the line must be on disk before the tree is.
//!
//! With no Bazel root above a project the cost is the root probe's stats;
//! nothing is read and nothing is written.

use std::io::{ErrorKind, Read as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::bazel::codes::Code;
use crate::bazel::ignore::{
    self, CannotEdit, IgnoreLine, IgnoreLineRow, IgnoreModel, Removal, SocketTree,
};
use crate::bazel::model::{Advisory, FileText, Lift, RootRef};
use crate::bazel::owned_index::{self, Index, Parsed, INDEX_PATH};
use crate::constants::npm_family::VLT_LOCK;
use crate::crawlers::bazel_root::{boundary_file_in, RootProbe, BOUNDARY_FILES};
use crate::patch::apply::ApplyResult;
use crate::patch::apply_lock::{self, LockError, LockGuard};
use crate::utils::containment::linked_level;
use crate::utils::fs::{atomic_write_sync, open_regular_file_sync, run_blocking};
use crate::utils::repo_root::{ReadBoundary, ReadScope};
use crate::utils::socket_dir::STAGE_PREFIX;
use crate::vendor::go_mod_edit::GO_PATCHES_DIR;
use crate::vendor::path::vendor_uuid_dir_rel;
use crate::vendor::{VendorOutcome, VendorWarning};

/// Every `details.token` this file reports (the convention of
/// `bazel::codes`).
pub const TOKENS: &[&str] = &["nested_bazel_roots", "bazel_root_outside_repository"];
/// Several Bazel roots lie above the project. Each reads its own
/// `.bazelignore`, and one root channel per run edits one of them.
pub const NESTED_BAZEL_ROOTS: &str = TOKENS[0];
/// The Bazel root is above the directory socket-patch writes in.
pub const BAZEL_ROOT_OUTSIDE_REPOSITORY: &str = TOKENS[1];

/// The ecosystem directories of `.socket/vendor` whose artifact is an
/// unpacked package. The others hold archives, which no BUILD file reaches.
const DIR_SHAPED: [&str; 4] = ["cargo", "composer", "gem", "golang"];
/// A `.bazelignore`, an index or a scanned BUILD file above this size is
/// not read: unreadable, never absent.
const MAX_BYTES: u64 = 1 << 20;
/// The bounds of the label scan. A repository past either one cannot be
/// proven free of labels, so the line is not written for a tree that may
/// hold a package.
const SCAN_FILES: usize = 512;
const SCAN_DIRS: usize = 4096;
/// How long an edit waits for another run's edit of the same root.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// Serializes the edits of one process; the lock file serializes processes.
static CHANNEL: Mutex<()> = Mutex::new(());

/// A copy or a unit that was not created. `detail` ends with the remedy
/// and "nothing was written".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The mode's refusal code where a `token` names the case, the
    /// vendored owned-file code for an index that fails the strict parse,
    /// else `bazel_workspace_ignore_line_needed`.
    pub code: Code,
    pub token: Option<&'static str>,
    pub detail: String,
    /// What would lift it: the edit the detail names, where one lets the
    /// next run through, else the decision that would.
    pub lift: Lift,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

/// Why an edit of a root's files did not happen, or not all of it.
struct Unwritten {
    why: String,
    /// The owned index fails the strict parse (design 5.2), which has a
    /// code of its own in vendored mode.
    index_modified: bool,
    /// A removal took the line out and left its row.
    row_only: bool,
}

impl From<String> for Unwritten {
    fn from(why: String) -> Self {
        Self {
            why,
            index_modified: false,
            row_only: false,
        }
    }
}

impl Unwritten {
    fn index_modified(index_path: &Path, what: &str) -> Self {
        Self {
            why: format!(
                "{} is not the index socket-patch wrote ({what}), and the line is recorded \
                 there for rollback",
                index_path.display()
            ),
            index_modified: true,
            row_only: false,
        }
    }
}

/// Why a line that is needed was not written, and what the user does.
struct Blocked {
    token: Option<&'static str>,
    /// The refusal's code where neither the token nor the default names
    /// the case.
    code: Option<Code>,
    why: String,
    /// What the user does about a tree that is there, and about a new one
    /// unless `route` says otherwise.
    remedy: String,
    /// What a refusal says where `remedy` does not let a new tree through.
    route: Option<String>,
    /// The remedy lets the next run through.
    rerun: bool,
}

impl Blocked {
    /// A line the user can add by hand, after which the next run finds
    /// the tree hidden.
    fn line(why: String, remedy: String) -> Self {
        Self {
            token: None,
            code: None,
            why,
            remedy,
            route: None,
            rerun: true,
        }
    }

    fn advisory(self, tree_dir: &Path) -> Advisory {
        let detail = format!(
            "{} is visible to Bazel's `//...`, where the upstream BUILD files in it break \
             the build, and socket-patch did not write the `.bazelignore` line that hides \
             it: {}. {}",
            tree_dir.display(),
            self.why,
            self.remedy
        );
        Advisory {
            code: Code::WorkspaceIgnoreLineNeeded,
            detail,
        }
    }

    /// `noted` is what else the user has to know about the files named
    /// (a line with a leading `/`), one sentence each.
    fn refusal(self, artifact: &Path, tree: SocketTree, noted: &[String]) -> Refusal {
        let code = match (self.code, self.token, tree) {
            (Some(code), ..) => code,
            (None, None, _) => Code::WorkspaceIgnoreLineNeeded,
            (None, Some(_), SocketTree::GoPatches) => Code::AgentGoUnsupported,
            (None, Some(_), SocketTree::Vendor) => Code::VendorRulesetUnsupported,
        };
        let noted: String = noted.iter().map(|note| format!("{note}. ")).collect();
        // The remedy is an edit of the user's wherever it lets the next
        // run through. Where no edit does (a root above the repository,
        // which is neither read nor written), the refusal stands until
        // the owner decides otherwise (design 11.3, decision O15).
        let lift = match self.rerun {
            true => Lift::UserEdit {
                file: ignore::BAZELIGNORE.to_string(),
                what: self.remedy.clone(),
            },
            false => Lift::Owner("O15"),
        };
        let detail = format!(
            "{} was not created: the upstream BUILD files in it would join Bazel's `//...` \
             and break the build, and the `.bazelignore` line that hides it could not be \
             written: {}. {noted}{}{}; nothing was written",
            artifact.display(),
            self.why,
            self.route.unwrap_or(self.remedy),
            if self.rerun { ", then run again" } else { "" }
        );
        Refusal {
            code,
            token: self.token,
            detail,
            lift,
        }
    }
}

/// A file socket-patch edits at a Bazel root, bounded. A link is followed,
/// as Bazel follows it; an edit refuses one separately.
fn read(path: &Path) -> FileText {
    let mut bytes = Vec::new();
    match open_regular_file_sync(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => FileText::Absent,
        Ok((file, meta)) if meta.len() <= MAX_BYTES => match (&file).read_to_end(&mut bytes) {
            Ok(_) => FileText::Bytes(bytes),
            Err(_) => FileText::Unreadable,
        },
        _ => FileText::Unreadable,
    }
}

/// `name` under the root-relative directory `dir` (`""` = the root).
fn below(dir: &str, name: &str) -> String {
    match dir {
        "" => name.to_string(),
        dir => format!("{dir}/{name}"),
    }
}

/// `tree` of the project at `project_rel`, relative to the Bazel root.
fn tree_rel(project_rel: &str, tree: SocketTree) -> String {
    below(project_rel, tree.rel())
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// The directories in `dir`, links left out; none when it cannot be listed.
fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let entries = std::fs::read_dir(dir).into_iter().flatten().flatten();
    let dirs = entries.filter(|e| e.file_type().is_ok_and(|kind| kind.is_dir()));
    dirs.map(|e| e.path()).collect()
}

/// Whether `dir` is a directory that holds anything. An empty one holds no
/// BUILD file: it is no tree yet, and what is put into it is created.
fn holds_entries(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// Whether the unit directory `unit` (`.socket/vendor/<eco>/<uuid>`) holds
/// an unpacked package. For npm that is vlt's layout and nothing else,
/// `[@scope/]<bare>-<version>/node_modules/` (`vendor::npm_dir`): a
/// tarball lies at the same levels (`[@scope/]<bare>-<version>.tgz`), so a
/// scope directory alone says nothing.
fn unpacked(eco: &str, unit: &Path) -> bool {
    if eco != "npm" {
        return DIR_SHAPED.contains(&eco) && holds_entries(unit);
    }
    let scope = |dir: &Path| {
        let name = dir.file_name().map(|name| name.to_string_lossy());
        name.is_some_and(|name| name.starts_with('@'))
    };
    let packages = subdirs(unit).into_iter().flat_map(|dir| match scope(&dir) {
        true => subdirs(&dir),
        false => vec![dir],
    });
    packages
        .into_iter()
        .any(|package| exists(&package.join("node_modules")))
}

/// Whether a tree the line of `tree` hides is on disk under `project`: a
/// Go copy, or an unpacked unit of `.socket/vendor`. A tarball, wheel or
/// jar is none, and neither is a directory with nothing in it.
fn tree_exists(project: &Path, tree: SocketTree) -> bool {
    let base = project.join(tree.rel());
    match tree {
        SocketTree::GoPatches => holds_entries(&base),
        SocketTree::Vendor => DIR_SHAPED.iter().chain(&["npm"]).any(|eco| {
            let units = subdirs(&base.join(eco));
            units.iter().any(|unit| unpacked(eco, unit))
        }),
    }
}

/// Whether `tree_dir` may hold a Bazel package: a `BUILD` or `BUILD.bazel`
/// file somewhere in it, in any case (a case-blind volume gives Bazel a
/// `build` file under either name), or more of it than this walk reads. A
/// package-form label needs a package to name, so a tree with none
/// (vendored archives and nothing else) has no label a line could delete,
/// and a repository that only vendors archives is not put through the
/// label scan.
fn may_hold_packages(tree_dir: &Path) -> bool {
    let build_file = |name: &std::ffi::OsStr| {
        let name = name.to_string_lossy();
        name.eq_ignore_ascii_case("BUILD") || name.eq_ignore_ascii_case("BUILD.bazel")
    };
    let (mut pending, mut dirs) = (vec![tree_dir.to_path_buf()], 0);
    while let Some(dir) = pending.pop() {
        dirs += 1;
        let listed = std::fs::read_dir(&dir).and_then(Iterator::collect);
        let Ok::<Vec<std::fs::DirEntry>, _>(entries) = listed else {
            return true;
        };
        for entry in entries {
            let path = entry.path();
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(path),
                // A link may lead to a directory that holds one.
                Ok(kind) if kind.is_symlink() => {
                    let leads_to_dir = std::fs::metadata(&path).map_or(true, |meta| meta.is_dir());
                    if leads_to_dir || build_file(&entry.file_name()) {
                        return true;
                    }
                }
                Ok(_) if build_file(&entry.file_name()) => return true,
                Ok(_) => {}
                Err(_) => return true,
            }
        }
        if dirs > SCAN_DIRS {
            return true;
        }
    }
    false
}

/// Whether the label scan comes before a line for `tree_dir`: it does
/// wherever a label could name a package under the directory. A copy base
/// that exists is always scanned (gazelle writes BUILD files into the
/// copies it finds, and may be about to); `.socket/vendor` only when it
/// holds a BUILD file, because it exists in every repository that vendors
/// an archive.
fn scan_first(tree_dir: &Path, tree: SocketTree) -> bool {
    exists(tree_dir)
        && match tree {
            SocketTree::GoPatches => true,
            SocketTree::Vendor => may_hold_packages(tree_dir),
        }
}

/// Why the line cannot be written for a tree that may hold a package: a
/// BUILD, `.bzl`, module or workspace file of the root names a label
/// under it, or the scan could not rule that out. Directories the root's
/// `.bazelignore` hides are not Bazel's to load and are skipped, as are
/// the tree itself and `.git`. No link is followed into a directory.
fn label_use(root: &Path, line: &IgnoreLine) -> Option<String> {
    let hidden = IgnoreModel::read(&read(&root.join(ignore::BAZELIGNORE)));
    let unproven = |what: &str| {
        let under = format!("no label under `//{}`", line.as_str());
        Some(format!("{what}, so {under} could be ruled out"))
    };
    let (mut pending, mut dirs, mut files) = (vec![String::new()], 0, 0);
    while let Some(dir) = pending.pop() {
        dirs += 1;
        let listed = std::fs::read_dir(root.join(&dir)).and_then(Iterator::collect);
        let Ok::<Vec<std::fs::DirEntry>, _>(mut entries) = listed else {
            let dir = root.join(&dir);
            return unproven(&format!("{} could not be listed", dir.display()));
        };
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue; // No label can name it.
            };
            let (child, path) = (below(&dir, &name), entry.path());
            let link = entry.file_type().map_or(true, |kind| kind.is_symlink());
            let is_dir = match link {
                true => std::fs::metadata(&path).is_ok_and(|meta| meta.is_dir()),
                false => entry.file_type().is_ok_and(|kind| kind.is_dir()),
            };
            if is_dir && link && !name.starts_with("bazel-") {
                return unproven(&format!("{} is a link to a directory", path.display()));
            } else if is_dir && !link {
                if name != ".git" && child != line.as_str() && !hidden.covers(&child) {
                    pending.push(child);
                }
            } else if !is_dir && ignore::is_label_scan_file(&name) {
                files += 1;
                let FileText::Bytes(text) = read(&path) else {
                    return unproven(&format!("{} could not be read", path.display()));
                };
                if let Some(hit) = line.label_hits(&text).first() {
                    return Some(format!(
                        "{}:{} names a label under `//{}`, which the line would delete \
                         (gazelle writes such labels when it finds the tree)",
                        path.display(),
                        hit.line,
                        line.as_str()
                    ));
                }
            }
        }
        if dirs > SCAN_DIRS || files > SCAN_FILES {
            return unproven(&format!(
                "{} holds more BUILD files than the scan reads",
                root.display()
            ));
        }
    }
    None
}

/// What the user has to know about the lines of `file` that start with a
/// `/`: Bazel rejects the whole file for them from 8.8.2 on and ignores
/// them before (probe B3), so a line socket-patch adds beside one does
/// not hide the tree there. They are the user's to fix and are never
/// edited (design 5.3).
fn slashed_lines(file: &Path, model: &IgnoreModel) -> Option<String> {
    let lines = model.absolute_lines();
    let shown: Vec<String> = lines
        .iter()
        .take(3)
        .map(|line| {
            let text: String = line.text.escape_debug().take(120).collect();
            format!("line {} (`{text}`)", line.number)
        })
        .collect();
    let more = match lines.len().saturating_sub(shown.len()) {
        0 => String::new(),
        more => format!(" and {more} more"),
    };
    (!lines.is_empty()).then(|| {
        format!(
            "{} has a line that starts with `/`: {}{more}. Bazel 8.8.2 and later reject the \
             whole file for every command, so nothing in it hides anything there, and earlier \
             releases ignore such a line. socket-patch left it as found; remove the leading `/`",
            file.display(),
            shown.join(", ")
        )
    })
}

/// The lock of one root's `.bazelignore` and index among processes: the
/// bare lock of `patch::apply_lock` on `apply.lock` in `owned`, the index's
/// directory (created when missing), waiting up to `wait` for a run that
/// holds it. The file exists only while the guard does.
///
/// Taking it does nothing else. The project lock would also treat the
/// directory above the one it locks as a project: finish a vendored commit
/// journal there, sweep stage entries, sync pending artifacts when it lets
/// go. Here that directory is the Bazel root's `.socket`, which is not a
/// project's, and no other file goes through this channel (design 5.4).
///
/// The guard is in the interrupt table like the project's, so a run that
/// is interrupted between the two renames of an edit takes the file out
/// as it dies. Only a kill nothing can catch leaves it: the kernel lets go
/// of a dead holder's lock, and the next edit of the root takes the file
/// over and removes it. Letting go also removes the index's directory and
/// the root's `.socket` when nothing is left in them: a root that had no
/// `.socket` before an edit has none after its undo.
fn take_lock(owned: &Path, wait: Duration) -> Result<LockGuard, String> {
    apply_lock::acquire_bare(owned, wait).map_err(|e| match e {
        LockError::Held => "another socket-patch run holds it".to_string(),
        LockError::Io { source, .. } => source.to_string(),
        // Only the project lock looks for a commit journal.
        pending @ LockError::CommitPending { .. } => pending.to_string(),
    })
}

/// Runs `edit` as the one writer of a root's `.bazelignore` and index: in
/// this process, and among processes through the lock file. What an
/// interrupted edit staged beside either file goes first, with no age
/// gate, because only a holder of this lock writes there and a leftover in
/// a tree Bazel globs becomes an action input (hazard HZ-27).
fn locked<T>(root: &Path, edit: impl FnOnce() -> T) -> Result<T, String> {
    let _serial = CHANNEL.lock().unwrap_or_else(PoisonError::into_inner);
    let index_path = root.join(INDEX_PATH);
    let owned = index_path.parent().unwrap_or(root);
    let lock = take_lock(owned, LOCK_WAIT);
    let done = match &lock {
        Err(e) => Err(format!(
            "the lock of {} was not taken ({e})",
            owned.display()
        )),
        Ok(_) => {
            for (dir, name) in [(root, ignore::BAZELIGNORE), (owned, "index.json")] {
                let staged = format!("{STAGE_PREFIX}{name}-");
                for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                    if entry.file_name().to_string_lossy().starts_with(&staged) {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
            Ok(edit())
        }
    };
    drop(lock);
    done
}

/// Adds `line` and its index row. `Ok(false)`: a line hides the tree by
/// now, and nothing was written.
fn insert_line(
    file: &Path,
    index_path: &Path,
    line: &IgnoreLine,
    dry_run: bool,
) -> Result<bool, Unwritten> {
    let shown = |path: &Path| path.display().to_string();
    let insertion = match ignore::insert(&read(file), std::slice::from_ref(line)) {
        Ok(None) => return Ok(false),
        Ok(Some(insertion)) => insertion,
        Err(CannotEdit::LoneCr) => {
            let why = "ends a line with a lone carriage return, which Bazel takes for a line \
                       end and gazelle does not, so it has no line ending an edit could keep";
            return Err(format!("{} {why}", shown(file)).into());
        }
        Err(CannotEdit::Unreadable) => {
            return Err(format!("{} exists and could not be read", shown(file)).into());
        }
    };
    let recorded = read(index_path);
    let mut index = match &recorded {
        FileText::Absent => Index::default(),
        FileText::Unreadable => {
            return Err(format!("{} exists and could not be read", shown(index_path)).into());
        }
        FileText::Bytes(bytes) => match owned_index::parse(bytes) {
            Parsed::Ours(index) => index,
            Parsed::Modified(what) => return Err(Unwritten::index_modified(index_path, &what)),
            Parsed::Foreign => {
                let own = "is not socket-patch's index, which records the line for rollback";
                return Err(format!("{} {own}; move it away", shown(index_path)).into());
            }
        },
    };
    index.record_lines(insertion.rows);
    let rendered = index.render().map_err(|invalid| invalid.to_string())?;
    if dry_run {
        return Ok(true);
    }
    let failed =
        |path: &Path, e: std::io::Error| format!("{} could not be written ({e})", shown(path));
    // The row first. A crash between the two leaves a row without its
    // line, which the next removal drops; a line without its row would
    // stay for good.
    atomic_write_sync(index_path, rendered.as_bytes(), true).map_err(|e| failed(index_path, e))?;
    let written = atomic_write_sync(file, &insertion.bytes, true).map_err(|e| failed(file, e));
    // The edit is read back: the tree must be hidden now, or the row goes.
    let hidden = |()| IgnoreModel::read(&read(file)).covers(line.as_str());
    let done = match written.map(hidden) {
        Ok(true) => Ok(true),
        Ok(false) => Err(format!("{} changed while it was written", shown(file))),
        Err(why) => Err(why),
    };
    if done.is_err() {
        let _ = match &recorded {
            FileText::Bytes(old) => atomic_write_sync(index_path, old, true),
            _ => std::fs::remove_file(index_path),
        };
    }
    Ok(done?)
}

/// The one root that governs the project and may be edited: writes the
/// line, or says why it cannot.
fn write_line(
    root: &RootRef,
    tree: SocketTree,
    dry_run: bool,
) -> Result<Option<Advisory>, Blocked> {
    let (file, index_path) = (
        root.root.join(ignore::BAZELIGNORE),
        root.root.join(INDEX_PATH),
    );
    let dir = tree_rel(&root.project_rel, tree);
    let line = IgnoreLine::new(&root.project_rel, tree).map_err(|unspellable| {
        Blocked::line(
            format!(
                "no line for `{dir}` is read the same way by every Bazel release and by \
                 gazelle ({unspellable:?})"
            ),
            format!(
                "Hide a directory above it with a line of your own in {}",
                file.display()
            ),
        )
    })?;
    let add = format!("Add the line `{}` to {}", line.as_str(), file.display());
    // socket-patch never replaces a link of the user's with a file, and a
    // linked `.socket` belongs to another project.
    let mut levels = [&file, &index_path].into_iter();
    if let Some(link) = levels.find_map(|path| linked_level(&root.root, path)) {
        let why = format!("{} is a symbolic link", link.display());
        return Err(Blocked::line(why, add));
    }
    let scan = scan_first(&root.root.join(&dir), tree);
    if let Some(why) = scan.then(|| label_use(&root.root, &line)).flatten() {
        let rewrite = "then rewrite each label under it (the project's gazelle target, for \
                       example `bazel run //:gazelle`, rewrites the ones gazelle wrote)";
        return Err(Blocked::line(why, format!("{add}, {rewrite}")));
    }
    let insert = |dry_run| insert_line(&file, &index_path, &line, dry_run);
    let written = match dry_run {
        true => insert(true),
        false => locked(&root.root, || insert(false))
            .map_err(Unwritten::from)
            .and_then(|written| written),
    };
    let written = written.map_err(|stopped| match stopped.index_modified {
        false => Blocked::line(stopped.why, add.clone()),
        true => Blocked {
            code: (tree == SocketTree::Vendor).then_some(Code::VendorOwnedFileModified),
            ..Blocked::line(
                stopped.why,
                format!(
                    "Restore it from version control, or add the line `{}` to {} yourself",
                    line.as_str(),
                    file.display()
                ),
            )
        },
    })?;
    Ok(written.then(|| Advisory {
        code: Code::WorkspaceIgnoreLineAdded,
        detail: format!(
            "{} the line `{}` to {}, which keeps {} and the upstream BUILD files in it out of \
             Bazel's `//...`; commit that file and `{INDEX_PATH}`, which records the line for \
             rollback",
            if dry_run { "would add" } else { "added" },
            line.as_str(),
            file.display(),
            root.root.join(&dir).display()
        ),
    }))
}

/// Whether somebody builds the root `root` above a project that is in no
/// checkout. There the probe takes every boundary file above the project
/// for a root, a stray `~/WORKSPACE` included, and leaves it to the
/// reader to say what such a file governs (`crawlers::bazel_root`). The
/// answer is the probe's own second signal, which it reports for a marker
/// above a read boundary: so it is asked with the boundary one level
/// below the root.
fn built(probe: &RootProbe, root: &RootRef) -> bool {
    let Some(level) = root.project_rel.split('/').next().filter(|l| !l.is_empty()) else {
        return true; // The project is the root.
    };
    let below = root.root.join(level);
    let bound = ReadBoundary::Workspace {
        root: below.clone(),
    };
    let above = probe.survey(&below, &bound).above;
    above.is_some_and(|above| above.confirmed && above.marker.parent() == Some(root.root.as_path()))
}

/// [`before_tree`], blocking. `artifact` is the directory the caller is
/// about to write, and `creates` says that it is not there yet.
///
/// The roots are the ones `bazel::probe` reports: every root from the
/// project up to the repository root, and a root somebody builds above
/// the repository. One of them that does not hide the tree is enough to
/// need a line. Outside any checkout a boundary file above the project
/// counts when somebody builds there ([`built`]); a stray one refuses
/// nothing and is reported.
fn guard(
    project: &Path,
    tree: SocketTree,
    artifact: &Path,
    creates: bool,
    dry_run: bool,
) -> Result<Vec<Advisory>, Refusal> {
    let reads = ReadBoundary::upward(ReadScope::Workspace, project);
    let writes = ReadBoundary::of(ReadScope::Workspace, project);
    let probe = RootProbe::new();
    let survey = probe.survey(project, &reads);
    // A stray boundary file above the repository governs nothing; one that
    // somebody builds does, and nothing is read there.
    let above = survey.above.as_ref().filter(|above| above.confirmed);
    let in_checkout = reads.root().is_some();
    // The roots that govern the project, the boundary file that makes
    // each a root, and what each one that does not hide the tree needs: a
    // refusal names both. `stray` is the same for a boundary file nobody
    // builds at, and `noted` what else is wrong with a file named.
    let (mut governing, mut markers, mut wanted) = (Vec::new(), Vec::new(), Vec::new());
    let (mut stray, mut noted) = (Vec::new(), Vec::new());
    for root in &survey.roots {
        let (dir, file) = (
            tree_rel(&root.project_rel, tree),
            root.root.join(ignore::BAZELIGNORE),
        );
        let marker = boundary_file_in(&root.root).unwrap_or_default();
        let marker = root.root.join(marker).display().to_string();
        let model = IgnoreModel::read(&read(&file));
        let line = (!model.covers(&dir)).then(|| format!("the line `{dir}` to {}", file.display()));
        noted.extend(line.as_ref().and_then(|_| slashed_lines(&file, &model)));
        if in_checkout || built(&probe, root) {
            governing.push(root);
            markers.push(marker);
            wanted.extend(line);
        } else if let Some(line) = line {
            stray.push((line, marker));
        }
    }
    if let Some(outer) = above.and_then(|above| above.marker.parent()) {
        let real = std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf());
        let rel = real.strip_prefix(outer).ok().and_then(Path::to_str);
        let dir = tree_rel(&rel.unwrap_or("<project>").replace('\\', "/"), tree);
        let file = outer.join(ignore::BAZELIGNORE);
        wanted.push(format!("the line `{dir}` to {}", file.display()));
        markers.extend(above.map(|above| above.marker.display().to_string()));
    }
    if wanted.is_empty() && stray.is_empty() {
        return Ok(Vec::new());
    }
    let add = format!("Add {}", wanted.join(" and "));
    let outcome = match (above, governing.as_slice()) {
        // Only a boundary file nobody builds at lacks the line.
        _ if wanted.is_empty() => Ok(None),
        (None, [root]) if writes.contains(&root.root) => write_line(root, tree, dry_run),
        (None, [_, _, ..]) => Err(Blocked {
            token: Some(NESTED_BAZEL_ROOTS),
            ..Blocked::line(
                format!(
                    "{} Bazel roots lie above it ({}) and each reads its own `.bazelignore` \
                     (`{NESTED_BAZEL_ROOTS}`)",
                    markers.len(),
                    markers.join(", ")
                ),
                add,
            )
        }),
        // With no repository around the project the root that somebody
        // builds above it is its workspace: read for coverage, and still
        // not socket-patch's to write.
        (None, _) => Err(Blocked {
            token: Some(BAZEL_ROOT_OUTSIDE_REPOSITORY),
            ..Blocked::line(
                format!(
                    "the Bazel root above it ({}) is outside the project, and with no \
                     repository around the project socket-patch writes nowhere else \
                     (`{BAZEL_ROOT_OUTSIDE_REPOSITORY}`)",
                    markers.join(", ")
                ),
                add,
            )
        }),
        // Neither read nor written, so no line the user adds there lets a
        // later run through: the refusal names the routes that do.
        (Some(above), _) => Err(Blocked {
            token: Some(BAZEL_ROOT_OUTSIDE_REPOSITORY),
            code: None,
            why: format!(
                "a Bazel root above it ({}) is outside the repository, where socket-patch \
                 neither reads nor writes (`{BAZEL_ROOT_OUTSIDE_REPOSITORY}`)",
                markers.join(", ")
            ),
            remedy: format!(
                "{add} from the repository that holds that Bazel root: a line above this \
                 repository is one socket-patch cannot see"
            ),
            route: Some(format!(
                "Adding {} does not let socket-patch through: it cannot see a line above \
                 this repository, so it cannot create this tree for a project in a checkout \
                 nested under a Bazel workspace it cannot read. Two routes work: where nobody \
                 builds {} with Bazel, remove {} (and any other of {} beside it) and run \
                 again; or patch from a project that is not a nested checkout, where \
                 socket-patch reads the workspace's `.bazelignore`",
                wanted.join(" and "),
                above.marker.parent().unwrap_or(&above.marker).display(),
                above.marker.display(),
                BOUNDARY_FILES.join(", ")
            )),
            rerun: false,
        }),
    };
    let tree_dir = project.join(tree.rel());
    let mut report: Vec<Advisory> = match outcome {
        Ok(added) => added.into_iter().collect(),
        Err(blocked) if !creates => vec![blocked.advisory(&tree_dir)],
        Err(blocked) => return Err(blocked.refusal(artifact, tree, &noted)),
    };
    if !stray.is_empty() {
        let (lines, files): (Vec<String>, Vec<String>) = stray.into_iter().unzip();
        report.push(Advisory {
            code: Code::WorkspaceIgnoreLineNeeded,
            detail: format!(
                "a Bazel workspace file lies above the project ({}) with nothing beside it \
                 that says anybody builds there. If somebody does, {} is in that workspace's \
                 `//...`, where the upstream BUILD files in it break the build: add {}. If \
                 nobody does, remove the file. With no repository around the project \
                 socket-patch writes nowhere else, so the run went on without the line",
                files.join(", "),
                tree_dir.display(),
                lines.join(" and ")
            ),
        });
    }
    report.extend(noted.into_iter().map(|detail| Advisory {
        code: Code::WorkspaceIgnoreLineNeeded,
        detail,
    }));
    Ok(report)
}

/// The row of `line` in the index at `index_path`. `Ok(None)`: no index,
/// an index of the user's, or no row for the line, so nothing here is
/// socket-patch's to take.
fn recorded(index_path: &Path, line: &IgnoreLine) -> Result<Option<(Index, usize)>, Unwritten> {
    let bytes = match read(index_path) {
        FileText::Absent => return Ok(None),
        FileText::Bytes(bytes) => bytes,
        FileText::Unreadable => {
            let unread = format!("{} exists and could not be read", index_path.display());
            return Err(unread.into());
        }
    };
    match owned_index::parse(&bytes) {
        Parsed::Foreign => Ok(None),
        Parsed::Modified(what) => Err(Unwritten::index_modified(index_path, &what)),
        Parsed::Ours(index) => {
            let at = index.ignore_lines.iter().position(|row| row.line == *line);
            Ok(at.map(|at| (index, at)))
        }
    }
}

/// Takes the row of `line` out of the index and the line out of the file.
/// `Ok(false)`: the index holds no row for it.
fn remove_line(file: &Path, index_path: &Path, line: &IgnoreLine) -> Result<bool, Unwritten> {
    let Some((mut index, at)) = recorded(index_path, line)? else {
        return Ok(false);
    };
    let row = index.ignore_lines.remove(at);
    let shown = |path: &Path| path.display().to_string();
    let failed =
        |path: &Path, e: std::io::Error| format!("{} could not be written ({e})", shown(path));
    match ignore::remove(&read(file), &row) {
        Ok(Removal::Missing) => {}
        Ok(Removal::Deleted) => std::fs::remove_file(file).map_err(|e| failed(file, e))?,
        Ok(Removal::Rewritten { bytes, carry }) => {
            atomic_write_sync(file, &bytes, true).map_err(|e| failed(file, e))?;
            carry.apply(&mut index.ignore_lines);
        }
        Err(CannotEdit::LoneCr) => {
            let why = "ends a line with a lone carriage return, so it has no line ending an \
                       edit could keep";
            return Err(format!("{} {why}", shown(file)).into());
        }
        Err(CannotEdit::Unreadable) => {
            return Err(format!("{} exists and could not be read", shown(file)).into());
        }
    }
    // The line is out. A row that outlives it is dropped by the next
    // removal, so a failure here is said and is not the line's.
    let rewritten = match index.is_empty() {
        true => std::fs::remove_file(index_path),
        false => match index.render() {
            Ok(rendered) => atomic_write_sync(index_path, rendered.as_bytes(), true),
            Err(invalid) => Err(std::io::Error::other(invalid.to_string())),
        },
    };
    rewritten.map_err(|e| Unwritten {
        why: format!(
            "the line is out of {}, and its row stayed: {}",
            shown(file),
            failed(index_path, e)
        ),
        index_modified: false,
        row_only: true,
    })?;
    Ok(true)
}

/// Whether `file` holds, byte for byte, the line socket-patch writes for
/// a tree (or cannot be read to say).
fn holds_line(file: &Path, line: &IgnoreLine) -> bool {
    let row = IgnoreLineRow {
        line: line.clone(),
        created_file: false,
        added_final_newline: false,
    };
    !matches!(ignore::remove(&read(file), &row), Ok(Removal::Missing))
}

/// [`after_removal`], blocking: whether a tree the line of `tree` covers
/// is left under `project`, and what could not be taken back when none
/// is. A line that stays hides a directory that is gone, so Bazel is not
/// affected, but the file keeps an edit the run reports as undone: the
/// caller says so.
fn release(project: &Path, tree: SocketTree) -> (bool, Vec<Advisory>) {
    if tree_exists(project, tree) {
        return (true, Vec::new());
    }
    let reads = ReadBoundary::upward(ReadScope::Workspace, project);
    let writes = ReadBoundary::of(ReadScope::Workspace, project);
    let survey = RootProbe::new().survey(project, &reads);
    let mut left = Vec::new();
    for root in survey
        .roots
        .iter()
        .filter(|root| writes.contains(&root.root))
    {
        let (file, index_path) = (
            root.root.join(ignore::BAZELIGNORE),
            root.root.join(INDEX_PATH),
        );
        let Ok(line) = IgnoreLine::new(&root.project_rel, tree) else {
            continue;
        };
        // A linked `.socket` belongs to another project, and so does what
        // its index records.
        if linked_level(&root.root, &index_path).is_some() {
            continue;
        }
        let taken = match recorded(&index_path, &line) {
            // No index, no row: nothing at this root is socket-patch's.
            Ok(None) => continue,
            Ok(Some(_)) => match linked_level(&root.root, &file) {
                Some(link) => Err(format!("{} is a symbolic link", link.display()).into()),
                None => locked(&root.root, || remove_line(&file, &index_path, &line))
                    .map_err(Unwritten::from)
                    .and_then(|taken| taken),
            },
            // The index cannot say whose the line is. Only a line that is
            // in the file is worth a report.
            Err(_) if !holds_line(&file, &line) => continue,
            Err(unknown) => Err(unknown),
        };
        let Err(stopped) = taken else {
            continue;
        };
        let remedy = match (stopped.index_modified, stopped.row_only) {
            (true, _) => "restore the index from version control and remove the line by hand",
            (false, true) => "the next rollback of this project drops the row",
            (false, false) => "remove the line by hand",
        };
        left.push(Advisory {
            code: match (stopped.index_modified, tree) {
                (true, SocketTree::Vendor) => Code::VendorOwnedFileModified,
                _ => Code::WorkspaceIgnoreLineNeeded,
            },
            detail: format!(
                "socket-patch added the line `{}` to {} and could not take all of it back, \
                 although no tree it hides is left: {}. What is left hides nothing; {remedy}",
                line.as_str(),
                file.display(),
                stopped.why
            ),
        });
    }
    (false, left)
}

/// Call before a directory `artifact` under `tree` of the project at
/// `project_root` is created or written into: a Go copy, a vendored unit.
/// `Ok` carries what the run reports (a line that was added, or one that
/// a copy which is already there needs and did not get); `Err` means the
/// directory must not be created. A dry run decides the same and writes
/// nothing. Follow a write that made no tree with [`after_removal`].
pub async fn before_tree(
    project_root: &Path,
    tree: SocketTree,
    artifact: &Path,
    dry_run: bool,
) -> Result<Vec<Advisory>, Refusal> {
    let (project, artifact) = (project_root.to_path_buf(), artifact.to_path_buf());
    run_blocking(move || {
        let creates = !holds_entries(&artifact);
        guard(&project, tree, &artifact, creates, dry_run)
    })
    .await
}

/// Call after trees of the project were removed, and after a write that
/// [`before_tree`] let through made none: when no tree that the line of
/// `tree` covers is left, the line socket-patch recorded goes, and with
/// it the file or the index it leaves empty. Returns what the caller adds
/// to its warnings: a recorded line that could not be taken out.
pub async fn after_removal(project_root: &Path, tree: SocketTree, dry_run: bool) -> Vec<Advisory> {
    if dry_run {
        return Vec::new();
    }
    let project = project_root.to_path_buf();
    run_blocking(move || release(&project, tree).1).await
}

/// What a `before_*` seam call decided, for the `after_*` call that
/// follows the write it guarded.
#[derive(Debug, Default)]
pub struct Guarded {
    /// `None`: the seam did not ask, because the write creates no tree
    /// Bazel could load.
    tree: Option<SocketTree>,
    advisories: Vec<Advisory>,
    dry_run: bool,
}

/// What the run reports of `guarded` once the write it guarded is over.
/// The line is there for a tree: when the write left none that the line
/// covers (it was refused, it failed and was torn down, it had nothing to
/// write), the line this run put in goes back out and nothing is reported
/// but what could not be taken back. When a copy keeps the line, the
/// report stays, on a failed result too, because the root's files changed
/// and are the user's to commit. A dry run that succeeded reports what
/// the real run would write.
async fn settle(project_root: &Path, guarded: &Guarded, succeeded: bool) -> Vec<Advisory> {
    let Some(tree) = guarded.tree else {
        return Vec::new();
    };
    let dry_run = guarded.dry_run;
    if dry_run && succeeded {
        return guarded.advisories.clone();
    }
    let project = project_root.to_path_buf();
    let (tree_left, left) = run_blocking(move || match dry_run {
        true => (tree_exists(&project, tree), Vec::new()),
        false => release(&project, tree),
    })
    .await;
    let mut report = match tree_left {
        true => guarded.advisories.clone(),
        false => Vec::new(),
    };
    report.extend(left);
    report
}

/// `note` joined to what a result already says.
fn with_note(said: Option<String>, note: Option<String>) -> Option<String> {
    match (said, note) {
        (Some(said), Some(note)) => Some(format!("{said}; {note}")),
        (said, note) => said.or(note),
    }
}

/// [`before_tree`] for the agent Go writer and its copy `copy_dir`, in a
/// wet run and in a dry one. `Err` is the refusal as it was decided: its
/// `Display` is the text of the failed result, and its code, token and
/// lift go on the result typed, so that the event needs no text match
/// (ROUTED R-024). Only the agent copy base is guarded here (the vendored
/// one goes through [`before_vendor_tree`]), and a copy that is in sync
/// is not written, so nothing is asked for it. Hand the value to
/// [`after_agent_go_tree`] with the result of the write.
pub async fn before_agent_go_tree(
    project_root: &Path,
    base_rel: &str,
    copy_dir: &Path,
    in_sync: bool,
    dry_run: bool,
) -> Result<Guarded, Refusal> {
    if base_rel != GO_PATCHES_DIR || in_sync {
        return Ok(Guarded::default());
    }
    let tree = SocketTree::GoPatches;
    let advisories = before_tree(project_root, tree, copy_dir, dry_run).await;
    Ok(Guarded {
        tree: Some(tree),
        advisories: advisories?,
        dry_run,
    })
}

/// The result of the agent Go writer with what [`before_agent_go_tree`]
/// decided (`settle`): on a successful result the note that
/// `patch::apply::advisory_warning_codes` turns into the run's warnings,
/// on a failed one what is left at the Bazel root, after the line this
/// run added for a copy that was not made is taken back.
pub async fn after_agent_go_tree(
    project_root: &Path,
    guarded: &Guarded,
    mut result: ApplyResult,
) -> ApplyResult {
    let report = settle(project_root, guarded, result.success).await;
    let notes: Vec<String> = report
        .iter()
        .map(|a| format!("{}: {}", a.code, a.detail))
        .collect();
    if !notes.is_empty() {
        result.error = with_note(result.error.take(), Some(notes.join("; ")));
    }
    result
}

/// [`before_tree`] for the vendor backend of ecosystem directory `eco`
/// and the unit `uuid`: `Err` is the refusal to return in the backend's
/// place. Only a backend whose artifact is an unpacked package asks. Hand
/// the value to [`after_vendor_tree`] with the backend's outcome.
pub async fn before_vendor_tree(
    project_root: &Path,
    eco: &str,
    uuid: &str,
    dry_run: bool,
) -> Result<Guarded, VendorOutcome> {
    let vlt = || exists(&project_root.join(VLT_LOCK));
    let unpacks = DIR_SHAPED.contains(&eco) || (eco == "npm" && vlt());
    if !unpacks {
        return Ok(Guarded::default());
    }
    let tree = SocketTree::Vendor;
    // A uuid that names no unit is the backend's to refuse.
    let unit = vendor_uuid_dir_rel(eco, uuid).map(|rel| project_root.join(rel));
    let unit = unit.unwrap_or_else(|| project_root.join(tree.rel()).join(eco));
    let (project, eco) = (project_root.to_path_buf(), eco.to_string());
    let guarded = run_blocking(move || {
        let creates = !unpacked(&eco, &unit);
        guard(&project, tree, &unit, creates, dry_run)
    })
    .await;
    match guarded {
        Ok(advisories) => Ok(Guarded {
            tree: Some(tree),
            advisories,
            dry_run,
        }),
        Err(refusal) => Err(VendorOutcome::Refused {
            code: refusal.code.as_str(),
            detail: refusal.detail,
        }),
    }
}

/// The backend's outcome with what [`before_vendor_tree`] decided
/// (`settle`): the warnings of a package that was vendored, and for one
/// that was not, what is left at the Bazel root after the line this run
/// added for it is taken back. A refusal has no warnings, so its detail
/// carries them.
pub async fn after_vendor_tree(
    project_root: &Path,
    guarded: Guarded,
    mut outcome: VendorOutcome,
) -> VendorOutcome {
    let vendored = matches!(&outcome, VendorOutcome::Done { result, .. } if result.success);
    let report = settle(project_root, &guarded, vendored).await;
    match &mut outcome {
        VendorOutcome::Done { warnings, .. } => {
            let warning = |a: Advisory| VendorWarning::new(a.code.as_str(), a.detail);
            warnings.extend(report.into_iter().map(warning));
        }
        VendorOutcome::Refused { detail, .. } => {
            for advisory in report {
                detail.push_str(&format!("; {}: {}", advisory.code, advisory.detail));
            }
        }
    }
    outcome
}

/// What [`before_plans`] decided, for the [`after_plans`] call that
/// follows the plans' writes.
#[derive(Debug, Default)]
pub struct PlanGuard {
    /// One per tree the plans rely on a line for.
    guarded: Vec<Guarded>,
    /// A dry run only: the root's `.bazelignore` as the real run would
    /// have left it by now.
    preview: Option<Vec<u8>>,
}

impl PlanGuard {
    /// What the run reports with the package the plans are for, once they
    /// are carried through: a line that was added (or would be).
    pub fn advisories(&self) -> impl Iterator<Item = &Advisory> {
        self.guarded.iter().flat_map(|guarded| &guarded.advisories)
    }

    /// A dry run that would add a line: the file the real run would have
    /// written before the plans are applied, by its root-relative path. A
    /// caller that previews the plans on a transaction stages it there, so
    /// the preview and the real run decide the same. `None` in a real run,
    /// where the line is on disk, and where no line would be added.
    pub fn preview(&self) -> Option<(&'static str, &[u8])> {
        let bytes = self.preview.as_deref()?;
        Some((ignore::BAZELIGNORE, bytes))
    }
}

/// The root's `.bazelignore` with the line of `tree` in it, for the dry
/// run of a guard that would add it. `held` is the file as an earlier
/// tree of the same call would leave it.
fn previewed(project: &Path, tree: SocketTree, held: Option<Vec<u8>>) -> Option<Vec<u8>> {
    let reads = ReadBoundary::upward(ReadScope::Workspace, project);
    let survey = RootProbe::new().survey(project, &reads);
    // A line is written only where one root governs the project.
    let [root] = survey.roots.as_slice() else {
        return held;
    };
    let Ok(line) = IgnoreLine::new(&root.project_rel, tree) else {
        return held;
    };
    let file = match held {
        Some(bytes) => FileText::Bytes(bytes),
        None => read(&root.root.join(ignore::BAZELIGNORE)),
    };
    match ignore::insert(&file, std::slice::from_ref(&line)) {
        Ok(Some(insertion)) => Some(insertion.bytes),
        _ => file.as_bytes().map(<[u8]>::to_vec),
    }
}

/// [`before_tree`] for the plans a lane made for the project at
/// `project_root`, which a seam carries out in a backend's place: call it
/// before the unit directory `unit` is created or written into, and before
/// the plans are handed to `bazel::exec::apply`, which requires that the
/// root's `.bazelignore` already hides every tree a plan relies on a line
/// for and never writes the line itself. Which trees those are is read
/// from the plans here, so that no seam looks into a plan's writes: a plan
/// that relies on no line asks for nothing, whatever its artifact is.
///
/// `Err` is the refusal for the package the plans are for; nothing stays
/// written. Hand the value to [`after_plans`] once it is known whether the
/// plans were carried through.
pub async fn before_plans(
    project_root: &Path,
    plans: &[crate::bazel::model::Plan],
    unit: &Path,
    dry_run: bool,
) -> Result<PlanGuard, Refusal> {
    use crate::bazel::model::PlannedWrite;
    let lines = plans.iter().flat_map(|plan| &plan.writes);
    let mut trees: Vec<SocketTree> = lines
        .filter_map(|write| match write {
            // A line socket-patch does not write is the executor's to
            // refuse.
            PlannedWrite::IgnoreLine { line } => IgnoreLine::parse(line).map(|line| line.tree()),
            _ => None,
        })
        .collect();
    trees.sort();
    trees.dedup();
    if trees.is_empty() {
        return Ok(PlanGuard::default());
    }
    let (project, unit) = (project_root.to_path_buf(), unit.to_path_buf());
    run_blocking(move || {
        let creates = !holds_entries(&unit);
        let mut decided = PlanGuard::default();
        for tree in trees {
            let advisories = match guard(&project, tree, &unit, creates, dry_run) {
                Ok(advisories) => advisories,
                Err(refusal) => {
                    // The lines this call put in for the trees before go
                    // back out with the refusal.
                    let done = decided.guarded.iter().filter(|_| !dry_run);
                    for tree in done.filter_map(|done| done.tree) {
                        release(&project, tree);
                    }
                    return Err(refusal);
                }
            };
            let adds = |advisory: &Advisory| advisory.code == Code::WorkspaceIgnoreLineAdded;
            if dry_run && advisories.iter().any(adds) {
                decided.preview = previewed(&project, tree, decided.preview.take());
            }
            decided.guarded.push(Guarded {
                tree: Some(tree),
                advisories,
                dry_run,
            });
        }
        Ok(decided)
    })
    .await
}

/// What the run reports of `guard` once the plans it guarded are settled.
/// `carried`: they were carried through (staged for a commit, or in place
/// already), so the lines they rely on stay, whatever shape the artifact
/// has: the lane said that it needs the line, and an archive unit is no
/// tree [`after_removal`] would keep it for. Otherwise the lines this run
/// put in go back out, unless a tree they cover is there, and what could
/// not be taken back is reported. Call it again with `false` when the
/// commit of carried plans did not land.
pub async fn after_plans(project_root: &Path, guard: &PlanGuard, carried: bool) -> Vec<Advisory> {
    let mut report = Vec::new();
    for guarded in &guard.guarded {
        match carried {
            true => report.extend(guarded.advisories.iter().cloned()),
            false => report.extend(settle(project_root, guarded, false).await),
        }
    }
    report
}

/// [`after_removal`] for a vendored revert: the warnings of its outcome.
pub async fn after_vendor_removal(project_root: &Path, dry_run: bool) -> Vec<VendorWarning> {
    let left = after_removal(project_root, SocketTree::Vendor, dry_run).await;
    let warning = |a: Advisory| VendorWarning::new(a.code.as_str(), a.detail);
    left.into_iter().map(warning).collect()
}

#[cfg(test)]
mod tests {
    use super::SocketTree::{GoPatches, Vendor};
    use super::*;
    use crate::vendor::common::synthesized_result;
    use std::collections::BTreeMap;

    const UUID: &str = "0b5e1c1e-5f0a-4c8e-9a51-6d1f3c2b7a90";
    const OTHER_UUID: &str = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f";
    /// The lock file of a root's `.bazelignore` and index, beside the
    /// index: the name `patch::apply_lock` gives every lock file.
    const LOCK_FILE: &str = "apply.lock";

    /// A checkout in a temporary directory: `.git` bounds every upward
    /// walk, so nothing above the test's own files is a Bazel root.
    struct Repo {
        _tmp: tempfile::TempDir,
        top: PathBuf,
    }

    impl Repo {
        fn new() -> Self {
            let tmp = tempfile::tempdir().expect("a temporary directory");
            let top = std::fs::canonicalize(tmp.path()).expect("its real path");
            let repo = Self { _tmp: tmp, top };
            repo.dir(".git");
            repo
        }

        /// A checkout whose root is the one Bazel root.
        fn workspace() -> Self {
            let repo = Self::new();
            repo.put("MODULE.bazel", b"module(name = \"ws\")\n");
            repo
        }

        fn dir(&self, rel: &str) -> PathBuf {
            std::fs::create_dir_all(self.top.join(rel)).expect("create a directory");
            self.top.join(rel)
        }

        fn put(&self, rel: &str, bytes: &[u8]) {
            let path = self.top.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).expect("create the parent");
            std::fs::write(path, bytes).expect("write a file");
        }

        /// `rel` as the code under test prints it: level by level, so the
        /// separators are the platform's.
        fn shown(&self, rel: &str) -> String {
            let path = rel
                .split('/')
                .fold(self.top.clone(), |at, level| at.join(level));
            path.display().to_string()
        }

        /// Every file (with its bytes) and directory but `.git`.
        fn tree(&self) -> BTreeMap<String, Option<Vec<u8>>> {
            let (mut out, mut pending) = (BTreeMap::new(), vec![self.top.clone()]);
            while let Some(dir) = pending.pop() {
                for entry in std::fs::read_dir(&dir).unwrap().map(Result::unwrap) {
                    let path = entry.path();
                    let rel = path.strip_prefix(&self.top).unwrap();
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    if rel == ".git" {
                    } else if entry.file_type().unwrap().is_dir() {
                        pending.push(path);
                        out.insert(rel, None);
                    } else {
                        out.insert(rel, Some(std::fs::read(&path).unwrap()));
                    }
                }
            }
            assert!(
                !out.keys().any(|path| path.contains(".socket-stage-")),
                "a stage file was left behind: {:?}",
                out.keys()
            );
            out
        }

        fn rows(&self) -> Vec<String> {
            let bytes = std::fs::read(self.top.join(INDEX_PATH)).expect("the index exists");
            let Parsed::Ours(index) = owned_index::parse(&bytes) else {
                panic!("the index is not canonical");
            };
            let line = |row: &ignore::IgnoreLineRow| row.line.as_str().to_string();
            index.ignore_lines.iter().map(line).collect()
        }
    }

    /// The guard for a copy or a unit of `tree` that is not there yet.
    fn create(project: &Path, tree: SocketTree, dry_run: bool) -> Result<Vec<Advisory>, Refusal> {
        let artifact = project.join(tree.rel()).join("new@v1");
        assert!(!artifact.exists());
        guard(project, tree, &artifact, true, dry_run)
    }

    /// The guard for the copy `artifact`, which is there and is written
    /// again.
    fn rebuild(project: &Path, tree: SocketTree, artifact: &str) -> Result<Vec<Advisory>, Refusal> {
        let artifact = project.join(artifact);
        assert!(holds_entries(&artifact), "{}", artifact.display());
        guard(project, tree, &artifact, false, false)
    }

    /// The one advisory of a guard that wrote (or would write) a line.
    fn added(outcome: Result<Vec<Advisory>, Refusal>) -> String {
        let advisories = outcome.expect("the tree may be created");
        let [advisory] = advisories.as_slice() else {
            panic!("one advisory, not {advisories:?}");
        };
        assert_eq!(advisory.code, Code::WorkspaceIgnoreLineAdded);
        advisory.detail.clone()
    }

    /// The one advisory of a run that went on without its line.
    fn needed(outcome: Result<Vec<Advisory>, Refusal>) -> String {
        let advisories = outcome.expect("the run goes on");
        let [advisory] = advisories.as_slice() else {
            panic!("one advisory, not {advisories:?}");
        };
        assert_eq!(advisory.code, Code::WorkspaceIgnoreLineNeeded);
        advisory.detail.clone()
    }

    /// What a removal that had nothing to report left: whether a tree is.
    fn released(project: &Path, tree: SocketTree) -> bool {
        let (tree_left, left) = release(project, tree);
        assert_eq!(left, Vec::new());
        tree_left
    }

    #[test]
    fn a_project_under_no_bazel_root_is_left_alone() {
        let repo = Repo::new();
        let project = repo.dir("svc");
        assert_eq!(create(&project, GoPatches, false), Ok(Vec::new()));
        assert_eq!(create(&project, Vendor, false), Ok(Vec::new()));
        assert!(!released(&project, GoPatches));
        assert_eq!(repo.tree().len(), 1, "only `svc`: {:?}", repo.tree());
    }

    #[test]
    fn the_line_goes_in_before_the_tree_and_out_after_it_byte_for_byte() {
        let files: [Option<&[u8]>; 6] = [
            None,
            Some(b""),
            Some(b"node_modules\n"),
            Some(b"node_modules\r\ndist\r\n"),
            Some(b"# mine\nnode_modules"),
            Some(b"a\r\nb"),
        ];
        for (rel, tree, made) in [
            ("", GoPatches, ".socket/go-patches/example.com/m@v1.0.0"),
            ("svc/api", GoPatches, ".socket/go-patches/m@v1"),
            ("svc/api", Vendor, ".socket/vendor/golang/u/m@v1"),
        ] {
            for original in files {
                let repo = Repo::workspace();
                let project = repo.dir(rel);
                if let Some(bytes) = original {
                    repo.put(".bazelignore", bytes);
                }
                let before = repo.tree();
                let line = tree_rel(rel, tree);

                let detail = added(create(&project, tree, false));
                assert!(
                    detail.contains(&format!("added the line `{line}`")),
                    "{detail}"
                );
                let text = std::fs::read(repo.top.join(".bazelignore")).unwrap();
                let old = original.unwrap_or_default();
                let eol = if old.windows(2).any(|w| w == b"\r\n") {
                    "\r\n"
                } else {
                    "\n"
                };
                let glue = if old.is_empty() || old.ends_with(b"\n") {
                    ""
                } else {
                    eol
                };
                let mut want = old.to_vec();
                want.extend_from_slice(format!("{glue}{line}{eol}").as_bytes());
                assert_eq!(text, want, "{rel:?} {tree:?} {original:?}");
                assert_eq!(repo.rows(), [line.as_str()]);
                // The tree was not there when the line was written, and a
                // second run has nothing to add.
                let wired = repo.tree();
                assert_eq!(create(&project, tree, false), Ok(Vec::new()));
                assert_eq!(repo.tree(), wired);

                // The line stays while a tree it covers is there.
                std::fs::create_dir_all(project.join(made)).unwrap();
                assert!(released(&project, tree));
                assert_eq!(std::fs::read(repo.top.join(".bazelignore")).unwrap(), want);
                std::fs::remove_dir_all(project.join(tree.rel())).unwrap();
                // What a rollback leaves of the project's own `.socket`
                // (at the root, the index is still in it).
                let _ = std::fs::remove_dir(project.join(".socket"));
                assert!(!released(&project, tree));
                assert_eq!(repo.tree(), before, "{rel:?} {tree:?} {original:?}");
            }
        }
    }

    #[test]
    fn two_projects_of_one_root_are_applied_in_order() {
        let repo = Repo::workspace();
        repo.put(".bazelignore", b"node_modules");
        let (a, b) = (repo.dir("a"), repo.dir("b/c"));
        let before = repo.tree();
        // At once, as two sub-projects of one run: neither edit is lost.
        std::thread::scope(|scope| {
            let first = scope.spawn(|| added(create(&a, GoPatches, false)));
            let second = scope.spawn(|| added(create(&b, Vendor, false)));
            (first.join().unwrap(), second.join().unwrap())
        });
        let mut lines = repo.rows();
        lines.sort();
        assert_eq!(lines, ["a/.socket/go-patches", "b/c/.socket/vendor"]);
        let text = std::fs::read_to_string(repo.top.join(".bazelignore")).unwrap();
        let mut written: Vec<&str> = text.lines().collect();
        written.sort();
        assert_eq!(
            written,
            ["a/.socket/go-patches", "b/c/.socket/vendor", "node_modules"]
        );

        // Each line goes with its own project, and what the first insert
        // added (the final newline) goes with the last of them.
        assert!(!released(&a, GoPatches));
        assert_eq!(repo.rows(), ["b/c/.socket/vendor"]);
        let text = std::fs::read_to_string(repo.top.join(".bazelignore")).unwrap();
        assert_eq!(text, "node_modules\nb/c/.socket/vendor\n");
        assert!(!released(&b, Vendor));
        assert_eq!(repo.tree(), before);
    }

    #[test]
    fn a_lone_cr_file_is_refused_and_left_byte_for_byte() {
        let repo = Repo::workspace();
        repo.put(".bazelignore", b"node_modules\rdist\r");
        let project = repo.dir("svc");
        let before = repo.tree();
        let refused = |tree: &BTreeMap<String, Option<Vec<u8>>>| {
            for dry_run in [true, false] {
                let refusal = create(&project, GoPatches, dry_run).expect_err("no line, no tree");
                assert_eq!(
                    (refusal.code, refusal.token),
                    (Code::WorkspaceIgnoreLineNeeded, None)
                );
                let remedy = format!(
                    "Add the line `svc/.socket/go-patches` to {}",
                    repo.shown(".bazelignore")
                );
                assert!(refusal.detail.contains("lone carriage return"), "{refusal}");
                assert!(refusal.detail.contains(&remedy), "{refusal}");
                assert!(refusal.detail.ends_with("nothing was written"), "{refusal}");
                assert_eq!(&repo.tree(), tree);
            }
        };
        refused(&before);
        // A directory with nothing in it is no tree: the copy is created.
        repo.dir("svc/.socket/go-patches");
        refused(&repo.tree());
        // A copy that is already there is reported, never refused, and a
        // new one beside it is refused like any other.
        repo.put("svc/.socket/go-patches/m@v1/m.go", b"package m\n");
        let found = repo.tree();
        let detail = needed(rebuild(&project, GoPatches, ".socket/go-patches/m@v1"));
        assert!(detail.contains("is visible to Bazel's `//...`"), "{detail}");
        assert_eq!(repo.tree(), found);
        refused(&found);
        // A line of the user's that hides the tree needs no edit at all.
        repo.put(".bazelignore", b"node_modules\rsvc\r");
        assert_eq!(create(&project, GoPatches, false), Ok(Vec::new()));
    }

    #[test]
    fn nested_roots_refuse_a_new_tree_and_name_each_line_and_file() {
        let repo = Repo::workspace();
        repo.put("svc/WORKSPACE", b"");
        let project = repo.dir("svc/api");
        let before = repo.tree();
        let outer = format!(
            "the line `svc/api/.socket/vendor` to {}",
            repo.shown(".bazelignore")
        );
        let inner = format!(
            "the line `api/.socket/vendor` to {}",
            repo.shown("svc/.bazelignore")
        );
        let refusal = create(&project, Vendor, false).expect_err("two roots");
        assert_eq!(refusal.code, Code::VendorRulesetUnsupported);
        assert_eq!(refusal.token, Some(NESTED_BAZEL_ROOTS));
        // The lines the user adds lift it, and the lift carries them.
        let Lift::UserEdit { file, what } = &refusal.lift else {
            panic!("an edit of the user's lifts it: {refusal:?}");
        };
        assert_eq!(file, ignore::BAZELIGNORE);
        assert!(what.contains(&outer) && what.contains(&inner), "{what}");
        // The boundary files, as the platform spells their paths.
        let markers = [repo.shown("MODULE.bazel"), repo.shown("svc/WORKSPACE")];
        for part in [&outer, &inner, &markers[0], &markers[1]] {
            assert!(refusal.detail.contains(part.as_str()), "{part}: {refusal}");
        }
        let agent = create(&project, GoPatches, false).expect_err("two roots");
        assert_eq!(agent.code, Code::AgentGoUnsupported);
        assert!(agent
            .to_string()
            .starts_with(Code::AgentGoUnsupported.as_str()));
        assert_eq!(repo.tree(), before);

        // The user adds the lines: one is not enough, both are.
        repo.put("svc/.bazelignore", b"api/.socket/vendor\n");
        let refusal = create(&project, Vendor, false).expect_err("the outer root");
        assert!(refusal.detail.contains(&outer) && !refusal.detail.contains(&inner));
        repo.put(".bazelignore", b"svc/api/.socket\n");
        assert_eq!(create(&project, Vendor, false), Ok(Vec::new()));
        // A copy that is already there gets the advisory with the lines.
        // Another module's copy beside it is still refused: the base
        // directory lets nothing through.
        repo.put("svc/api/.socket/go-patches/m@v1/m.go", b"package m\n");
        repo.put("svc/.bazelignore", b"");
        let found = repo.tree();
        let detail = needed(rebuild(&project, GoPatches, ".socket/go-patches/m@v1"));
        assert!(detail.contains("`api/.socket/go-patches`"), "{detail}");
        let agent = create(&project, GoPatches, false).expect_err("a new copy");
        assert_eq!(agent.token, Some(NESTED_BAZEL_ROOTS));
        assert!(agent.detail.contains("new@v1"), "{agent}");
        assert_eq!(repo.tree(), found);
    }

    #[test]
    fn a_root_outside_the_repository_is_never_written() {
        // A workspace that somebody builds above a nested checkout: its
        // `.bazelignore` is neither read nor written.
        let outer = Repo::workspace();
        std::fs::remove_dir(outer.top.join(".git")).unwrap();
        outer.put(".bazelversion", b"9.3.2\n");
        outer.put(".bazelignore", b"repo/.socket/go-patches\n");
        let project = outer.dir("repo");
        outer.dir("repo/.git");
        let before = outer.tree();
        let refusal = create(&project, GoPatches, false).expect_err("a root out of reach");
        assert_eq!(refusal.code, Code::AgentGoUnsupported);
        assert_eq!(refusal.token, Some(BAZEL_ROOT_OUTSIDE_REPOSITORY));
        // No edit of the user's lets a later run through.
        assert_eq!(refusal.lift, Lift::Owner("O15"));
        let line = format!(
            "the line `repo/.socket/go-patches` to {}",
            outer.shown(".bazelignore")
        );
        let marker = outer.shown("MODULE.bazel");
        // The line is there already, and socket-patch does not read it: the
        // refusal says so, and names the two routes that work instead of a
        // remedy the next run would not see.
        for part in [
            format!("Adding {line} does not let socket-patch through"),
            "cannot see a line above this repository".to_string(),
            format!("remove {marker} (and any other of "),
            "patch from a project that is not a nested checkout".to_string(),
        ] {
            assert!(refusal.detail.contains(&part), "{part}: {refusal}");
        }
        assert!(!refusal.detail.contains("then run again"), "{refusal}");
        assert!(!refusal.detail.contains("from there"), "{refusal}");
        assert!(refusal.detail.ends_with("nothing was written"), "{refusal}");
        assert_eq!(outer.tree(), before);
        // A copy that is already there is told where its line goes.
        outer.put("repo/.socket/go-patches/m@v1/m.go", b"package m\n");
        let detail = needed(rebuild(&project, GoPatches, ".socket/go-patches/m@v1"));
        assert!(detail.contains(&format!("Add {line} from the repository")));
        std::fs::remove_dir_all(project.join(".socket")).unwrap();

        // The first route, followed: nobody builds there, the boundary
        // file goes, and the tree may be created.
        std::fs::remove_file(outer.top.join("MODULE.bazel")).unwrap();
        assert_eq!(create(&project, GoPatches, false), Ok(Vec::new()));
        outer.put("MODULE.bazel", b"module(name = \"ws\")\n");
        // The second route, followed: the same project in the repository
        // that holds the root is no nested checkout. Its line is read, and
        // written when it is missing.
        std::fs::remove_dir(outer.top.join("repo/.git")).unwrap();
        outer.dir(".git");
        assert_eq!(create(&project, GoPatches, false), Ok(Vec::new()));
        let detail = added(create(&project, Vendor, false));
        assert!(detail.contains("added the line `repo/.socket/vendor`"));
        assert!(!released(&project, Vendor));
        std::fs::remove_dir(outer.top.join(".git")).unwrap();
        outer.dir("repo/.git");
        assert_eq!(outer.tree(), before);

        // A stray boundary file with nothing beside it governs nothing.
        std::fs::remove_file(outer.top.join(".bazelversion")).unwrap();
        assert_eq!(create(&project, GoPatches, false), Ok(Vec::new()));
    }

    #[test]
    fn outside_any_checkout_only_a_root_somebody_builds_refuses() {
        let outer = Repo::workspace();
        std::fs::remove_dir(outer.top.join(".git")).unwrap();
        let project = outer.dir("repo");
        let before = outer.tree();
        let line = format!(
            "the line `repo/.socket/vendor` to {}",
            outer.shown(".bazelignore")
        );
        // A boundary file with nothing beside it, as a stray `~/WORKSPACE`
        // is: the tree is created as it always was, and the run says what
        // to do if that directory is a workspace after all.
        for dry_run in [true, false] {
            let detail = needed(create(&project, Vendor, dry_run));
            for part in [
                outer.shown("MODULE.bazel"),
                "with nothing beside it that says anybody builds there".to_string(),
                format!("add {line}"),
                "the run went on without the line".to_string(),
            ] {
                assert!(detail.contains(&part), "{part}: {detail}");
            }
            assert_eq!(outer.tree(), before);
        }

        // With a second sign of Bazel the root above the project is its
        // workspace: read for coverage, and still not written.
        outer.put(".bazelversion", b"9.3.2\n");
        let before = outer.tree();
        let refusal = create(&project, Vendor, false).expect_err("above the project");
        assert_eq!(refusal.code, Code::VendorRulesetUnsupported);
        assert_eq!(refusal.token, Some(BAZEL_ROOT_OUTSIDE_REPOSITORY));
        assert!(refusal.detail.contains(&format!("Add {line}")), "{refusal}");
        assert!(refusal.detail.contains("then run again"), "{refusal}");
        assert!(matches!(refusal.lift, Lift::UserEdit { .. }), "{refusal:?}");
        assert_eq!(outer.tree(), before);
        outer.put(".bazelignore", b"repo/.socket/vendor\n");
        assert_eq!(create(&project, Vendor, false), Ok(Vec::new()));

        // A stray file further up does not make the workspace a nested
        // one, and a project that is itself the root is written to.
        let nested = Repo::new();
        std::fs::remove_dir(nested.top.join(".git")).unwrap();
        nested.put("WORKSPACE", b"");
        nested.put("ws/MODULE.bazel", b"");
        let root = nested.dir("ws");
        let both = guard(&root, GoPatches, &root.join("new"), true, false).expect("the root");
        let codes: Vec<Code> = both.iter().map(|advisory| advisory.code).collect();
        assert_eq!(
            codes,
            [
                Code::WorkspaceIgnoreLineAdded,
                Code::WorkspaceIgnoreLineNeeded
            ]
        );
        assert!(both[1].detail.contains(&nested.shown("WORKSPACE")));
        assert_eq!(
            std::fs::read(root.join(".bazelignore")).unwrap(),
            b".socket/go-patches\n"
        );
        assert!(!nested.top.join(".bazelignore").exists());
    }

    #[test]
    fn a_tree_that_exists_gets_its_line_only_when_no_label_names_it() {
        let repo = Repo::workspace();
        repo.put(".bazelignore", b"node_modules\n");
        let copy = ".socket/go-patches/example.com/m@v1.0.0";
        repo.put(&format!("{copy}/BUILD.bazel"), b"x()\n");
        // Inside the tree and under a hidden directory a label is no hit.
        repo.put(
            &format!("{copy}/sub/BUILD"),
            b"\"//.socket/go-patches/example.com/m@v1.0.0:m\"\n",
        );
        repo.put("node_modules/x/BUILD", b"\"//.socket/go-patches/y\"\n");
        let rewired =
            b"go_library(\n    deps = [\"//.socket/go-patches/example.com/m@v1.0.0:m\"],\n)\n";
        repo.put("app/BUILD.bazel", rewired);
        let before = repo.tree();
        let detail = needed(rebuild(&repo.top, GoPatches, copy));
        let hit = format!("{}:2 names a label", repo.shown("app/BUILD.bazel"));
        let parts = [
            hit.as_str(),
            "Add the line `.socket/go-patches`",
            "gazelle target",
        ];
        for part in parts {
            assert!(detail.contains(part), "{part}: {detail}");
        }
        assert_eq!(repo.tree(), before);
        // A new copy beside it would be loaded too, and the line that
        // hides it would delete the label: neither is written.
        let refusal = create(&repo.top, GoPatches, false).expect_err("no line, no copy");
        assert_eq!(
            (refusal.code, refusal.token),
            (Code::WorkspaceIgnoreLineNeeded, None)
        );
        for part in parts {
            assert!(refusal.detail.contains(part), "{part}: {refusal}");
        }
        assert!(refusal
            .detail
            .ends_with("then run again; nothing was written"));
        assert_eq!(repo.tree(), before);

        repo.put("app/BUILD.bazel", b"go_library(deps = [\"//lib\"])\n");
        added(rebuild(&repo.top, GoPatches, copy));
        assert_eq!(repo.rows(), [".socket/go-patches"]);
        // A directory behind a link cannot be scanned: no proof, no line.
        #[cfg(unix)]
        {
            std::fs::remove_file(repo.top.join(".bazelignore")).unwrap();
            std::os::unix::fs::symlink(repo.top.join("app"), repo.top.join("linked")).unwrap();
            let detail = needed(rebuild(&repo.top, GoPatches, copy));
            assert!(detail.contains("is a link to a directory"), "{detail}");
            assert!(!repo.top.join(".bazelignore").exists());
        }
    }

    #[test]
    fn a_label_on_a_vendored_archive_keeps_the_line_and_the_new_unit_out() {
        let repo = Repo::workspace();
        let wheel = format!(".socket/vendor/pypi/{UUID}/x-1.0-py3-none-any.whl");
        repo.put(&wheel, b"");
        let label = format!("//.socket/vendor/pypi/{UUID}:x-1.0-py3-none-any.whl");
        let user = format!("py_library(\n    name = \"app\",\n    deps = [\"{label}\"],\n)\n");
        repo.put("BUILD.bazel", user.as_bytes());
        // The user made the unit a package, and a target of theirs names
        // the wheel in it: the line for `.socket/vendor` would delete that
        // package, so it is not written and no unpacked unit is created.
        repo.put(
            &format!(".socket/vendor/pypi/{UUID}/BUILD"),
            b"exports_files(glob([\"*\"]))\n",
        );
        let before = repo.tree();
        for dry_run in [true, false] {
            let refusal = create(&repo.top, Vendor, dry_run).expect_err("no line, no unit");
            assert_eq!(
                (refusal.code, refusal.token),
                (Code::WorkspaceIgnoreLineNeeded, None)
            );
            let hit = format!("{}:3 names a label", repo.shown("BUILD.bazel"));
            for part in [
                hit.as_str(),
                "Add the line `.socket/vendor`",
                "then rewrite each label under it",
                "nothing was written",
            ] {
                assert!(refusal.detail.contains(part), "{part}: {refusal}");
            }
            assert_eq!(repo.tree(), before);
        }

        // With no BUILD file under `.socket/vendor` no label can name a
        // package there, whatever the root's files say: the tree is not
        // scanned, and a repository too large to scan gets its line.
        std::fs::remove_file(repo.top.join(format!(".socket/vendor/pypi/{UUID}/BUILD"))).unwrap();
        assert!(!may_hold_packages(&repo.top.join(".socket/vendor")));
        added(create(&repo.top, Vendor, false));
        assert_eq!(repo.rows(), [".socket/vendor"]);
    }

    #[test]
    fn a_repository_too_large_to_scan_gets_no_line_for_a_tree_that_exists() {
        let repo = Repo::workspace();
        let copy = ".socket/go-patches/m@v1";
        repo.put(&format!("{copy}/BUILD.bazel"), b"x()\n");
        for package in 0..=SCAN_FILES {
            repo.put(&format!("pkg/p{package}/BUILD.bazel"), b"x()\n");
        }
        let before = repo.tree();
        let detail = needed(rebuild(&repo.top, GoPatches, copy));
        for part in [
            "holds more BUILD files than the scan reads",
            "no label under `//.socket/go-patches` could be ruled out",
            "Add the line `.socket/go-patches`",
        ] {
            assert!(detail.contains(part), "{part}: {detail}");
        }
        let refusal = create(&repo.top, GoPatches, false).expect_err("no proof, no copy");
        assert_eq!(refusal.code, Code::WorkspaceIgnoreLineNeeded);
        assert_eq!(repo.tree(), before);
        // The user's own line is all it takes.
        repo.put(".bazelignore", b".socket/go-patches\n");
        assert_eq!(create(&repo.top, GoPatches, false), Ok(Vec::new()));
    }

    #[test]
    fn a_line_with_a_leading_slash_is_reported_and_left() {
        let repo = Repo::workspace();
        let theirs = b"/svc/.socket\n# mine\n/node_modules\n";
        repo.put(".bazelignore", theirs);
        let project = repo.dir("svc");
        // The line is dead on Bazel 7 and fatal from 8.8.2: it hides
        // nothing, so socket-patch adds its own, and says what it saw.
        let advisories = create(&project, GoPatches, false).expect("the copy may be created");
        let codes: Vec<Code> = advisories.iter().map(|advisory| advisory.code).collect();
        assert_eq!(
            codes,
            [
                Code::WorkspaceIgnoreLineAdded,
                Code::WorkspaceIgnoreLineNeeded
            ]
        );
        let detail = &advisories[1].detail;
        for part in [
            repo.shown(".bazelignore"),
            "line 1 (`/svc/.socket`), line 3 (`/node_modules`)".to_string(),
            "Bazel 8.8.2 and later reject the whole file".to_string(),
            "earlier releases ignore such a line".to_string(),
            "left it as found".to_string(),
        ] {
            assert!(detail.contains(&part), "{part}: {detail}");
        }
        let mut want = theirs.to_vec();
        want.extend_from_slice(b"svc/.socket/go-patches\n");
        assert_eq!(std::fs::read(repo.top.join(".bazelignore")).unwrap(), want);
        // Once the tree is hidden nothing is asked of the file again.
        assert_eq!(create(&project, GoPatches, false), Ok(Vec::new()));

        // A refusal says it too: the user is about to edit that file.
        repo.put("svc/WORKSPACE", b"");
        let refusal = create(&project, Vendor, false).expect_err("two roots");
        assert!(
            refusal.detail.contains("line 1 (`/svc/.socket`)"),
            "{refusal}"
        );
        assert!(refusal.detail.ends_with("nothing was written"), "{refusal}");
    }

    #[test]
    fn an_index_or_a_link_that_is_not_socket_patchs_blocks_the_edit() {
        let repo = Repo::workspace();
        let modified = b"{\"ignoreLines\": [], \"pins\": [], \"version\": 1}";
        // The vendored seam has a code for an index that fails the strict
        // parse; the agent seam has none of its own.
        for (index, tree, code, why) in [
            (
                &b"{}\n"[..],
                Vendor,
                Code::WorkspaceIgnoreLineNeeded,
                "is not socket-patch's index",
            ),
            (
                modified,
                Vendor,
                Code::VendorOwnedFileModified,
                "Restore it from version control, or add the line `.socket/vendor`",
            ),
            (
                modified,
                GoPatches,
                Code::WorkspaceIgnoreLineNeeded,
                "is not the index socket-patch wrote",
            ),
        ] {
            repo.put(INDEX_PATH, index);
            let before = repo.tree();
            let refusal = create(&repo.top, tree, false).expect_err("no record, no line");
            assert_eq!((refusal.code, refusal.token), (code, None), "{refusal}");
            assert!(refusal.detail.contains(why), "{refusal}");
            assert!(refusal
                .detail
                .ends_with("then run again; nothing was written"));
            assert_eq!(repo.tree(), before);
        }
        #[cfg(unix)]
        {
            std::fs::remove_dir_all(repo.top.join(".socket")).unwrap();
            repo.put("shared.bazelignore", b"node_modules\n");
            let link = repo.top.join(".bazelignore");
            std::os::unix::fs::symlink("shared.bazelignore", &link).unwrap();
            let refusal = create(&repo.top, GoPatches, false).expect_err("a link is the user's");
            assert!(refusal.detail.contains("is a symbolic link"), "{refusal}");
            assert!(std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
            assert!(!repo.top.join(".socket").exists());
            // Read through the link, as Bazel reads it: a covering line counts.
            repo.put("shared.bazelignore", b".socket\n");
            assert_eq!(create(&repo.top, GoPatches, false), Ok(Vec::new()));
        }
    }

    #[test]
    fn a_recorded_line_that_cannot_be_taken_out_is_reported() {
        let repo = Repo::workspace();
        let project = repo.dir("svc");
        added(create(&project, GoPatches, false));
        added(create(&project, Vendor, false));
        let (file, index) = (repo.top.join(".bazelignore"), repo.top.join(INDEX_PATH));
        let canonical = std::fs::read(&index).unwrap();

        // The index as another tool re-serialised it: the rows are there
        // and the bytes are not socket-patch's, so nothing is taken on its
        // word, and the rollback that leaves the line says so.
        let reindented = String::from_utf8(canonical.clone())
            .unwrap()
            .replace("\n  ", "\n    ");
        std::fs::write(&index, &reindented).unwrap();
        assert!(matches!(
            owned_index::parse(reindented.as_bytes()),
            Parsed::Modified(_)
        ));
        let modified = repo.tree();
        for (tree, code, line) in [
            (
                GoPatches,
                Code::WorkspaceIgnoreLineNeeded,
                "svc/.socket/go-patches",
            ),
            (Vendor, Code::VendorOwnedFileModified, "svc/.socket/vendor"),
        ] {
            let (tree_left, left) = release(&project, tree);
            assert!(!tree_left);
            let [advisory] = left.as_slice() else {
                panic!("one advisory, not {left:?}");
            };
            assert_eq!(advisory.code, code);
            for part in [
                format!("added the line `{line}` to {}", file.display()),
                "could not take all of it back".to_string(),
                format!("{} is not the index socket-patch wrote", index.display()),
                "restore the index from version control and remove the line by hand".to_string(),
            ] {
                assert!(advisory.detail.contains(&part), "{part}: {advisory:?}");
            }
            assert_eq!(repo.tree(), modified);
        }
        // A line the user took out already leaves nothing to report.
        std::fs::write(&file, b"svc/.socket/vendor\n").unwrap();
        assert!(!released(&project, GoPatches));

        // The file as a tool rewrote it with lone carriage returns: the
        // line is recorded and cannot be taken out of it.
        std::fs::write(&index, &canonical).unwrap();
        std::fs::write(&file, b"svc/.socket/go-patches\rsvc/.socket/vendor\r").unwrap();
        let (_, left) = release(&project, Vendor);
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0].code, Code::WorkspaceIgnoreLineNeeded);
        assert!(left[0].detail.contains("lone carriage return"), "{left:?}");
        assert_eq!(repo.rows().len(), 2, "the rows stay with their lines");
    }

    #[test]
    fn what_an_interrupted_edit_staged_goes_with_the_next_edit() {
        let repo = Repo::workspace();
        let staged = [
            ".socket-stage-.bazelignore-0b5e1c1e",
            ".socket/bazel/.socket-stage-index.json-0b5e1c1e",
        ];
        for rel in staged {
            repo.put(rel, b"half");
        }
        // Another file of that prefix is not this writer's to remove.
        repo.put(".socket-stage-other", b"theirs");
        added(create(&repo.top, GoPatches, false));
        for rel in staged {
            assert!(!repo.top.join(rel).exists(), "{rel}");
        }
        assert!(repo.top.join(".socket-stage-other").exists());
        std::fs::remove_file(repo.top.join(".socket-stage-other")).unwrap();
        assert!(!released(&repo.top, GoPatches));
        assert_eq!(repo.tree().len(), 1, "only MODULE.bazel: {:?}", repo.tree());
    }

    #[test]
    fn the_lock_of_a_root_does_nothing_but_lock() {
        let repo = Repo::workspace();
        // What the project lock would take for an interrupted vendored
        // commit of the project `<root>/.socket`, replay or set aside.
        let journal = ".socket/.socket/vendor/.commit-journal.json";
        repo.put(journal, b"not a journal");
        let project = repo.dir("svc");
        let before = repo.tree();
        added(create(&project, GoPatches, false));
        assert!(!released(&project, GoPatches));
        assert_eq!(
            repo.tree(),
            before,
            "the journal is in place, byte for byte"
        );

        // One holder at a time, and the file exists only while it is held.
        let owned = repo.top.join(".socket").join("bazel");
        let lock = owned.join(LOCK_FILE);
        let first = take_lock(&owned, Duration::ZERO).expect("free");
        assert!(lock.exists());
        let busy = take_lock(&owned, Duration::ZERO).err();
        assert_eq!(busy.as_deref(), Some("another socket-patch run holds it"));
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| take_lock(&owned, Duration::from_secs(30)));
            std::thread::sleep(Duration::from_millis(60));
            drop(first);
            let second = waiter.join().unwrap().expect("taken once it is free");
            assert!(lock.exists());
            drop(second);
        });
        // Letting go took the file and the index's directory with it.
        assert!(!owned.exists());
        assert_eq!(repo.tree(), before);
        // A file where the directory belongs is said, and not waited for.
        let squatted = Repo::workspace();
        squatted.put(".socket/bazel", b"");
        let refusal = create(&squatted.top, GoPatches, false).expect_err("no lock, no line");
        assert!(refusal.detail.contains("was not taken"), "{refusal}");
        assert_eq!(squatted.tree().len(), 3, "{:?}", squatted.tree());
    }

    /// A root that had no `.socket` gets none from an edit that writes
    /// nothing, and none from a lock that was not taken: the directories
    /// the lock made go with it.
    #[test]
    fn a_root_without_a_socket_directory_has_none_after_an_edit_that_wrote_nothing() {
        let repo = Repo::workspace();
        let before = repo.tree();
        let done = locked(&repo.top, || {
            assert!(repo.top.join(INDEX_PATH).with_file_name(LOCK_FILE).exists());
        });
        assert_eq!(done, Ok(()));
        assert_eq!(repo.tree(), before);
        // The edit of another run is waited for, then given up on, and
        // the holder's file is left to the holder.
        let owned = repo.top.join(".socket").join("bazel");
        let held = take_lock(&owned, Duration::ZERO).expect("free");
        let busy = take_lock(&owned, Duration::from_millis(50)).err();
        assert_eq!(busy.as_deref(), Some("another socket-patch run holds it"));
        assert!(owned.join(LOCK_FILE).exists());
        drop(held);
        assert_eq!(repo.tree(), before);
    }

    fn result(success: bool, error: Option<&str>) -> ApplyResult {
        let error = error.map(str::to_string);
        synthesized_result(
            "pkg:golang/m@v1",
            Path::new("m"),
            Vec::new(),
            success,
            error,
        )
    }

    #[tokio::test]
    async fn the_seams_ask_only_for_trees_bazel_could_load() {
        let repo = Repo::workspace();
        let before = repo.tree();
        let copy = repo.top.join(".socket/go-patches/m@v1");
        // A dry run says what it would do and writes nothing.
        let unit = repo.top.join(".socket/vendor/cargo").join(UUID);
        let detail = added(before_tree(&repo.top, Vendor, &unit, true).await);
        assert!(
            detail.starts_with("would add the line `.socket/vendor`"),
            "{detail}"
        );
        // An archive is no tree, and npm unpacks only under vlt.
        for eco in ["pypi", "nuget", "maven", "npm"] {
            let asked = before_vendor_tree(&repo.top, eco, UUID, false).await;
            assert!(asked.unwrap().tree.is_none(), "{eco}");
        }
        // The vendored Go copy is the vendor seam's, and a copy that is
        // in sync is not written at all.
        for (base, in_sync) in [(".socket/vendor/golang/u", false), (GO_PATCHES_DIR, true)] {
            let asked = before_agent_go_tree(&repo.top, base, &copy, in_sync, false).await;
            assert!(asked.unwrap().tree.is_none(), "{base}");
        }
        assert_eq!(repo.tree(), before);

        // The line goes in, the backend unpacks the crate, and the outcome
        // carries the line as the package's warning.
        let asked = before_vendor_tree(&repo.top, "cargo", UUID, false).await;
        let asked = asked.unwrap();
        assert_eq!(asked.advisories[0].code, Code::WorkspaceIgnoreLineAdded);
        repo.put(
            &format!(".socket/vendor/cargo/{UUID}/x-1.0.0/Cargo.toml"),
            b"",
        );
        let done = VendorOutcome::Done {
            result: result(true, None),
            entry: None,
            warnings: Vec::new(),
        };
        let VendorOutcome::Done { warnings, .. } = after_vendor_tree(&repo.top, asked, done).await
        else {
            panic!("the outcome keeps its kind");
        };
        assert_eq!(warnings[0].code, Code::WorkspaceIgnoreLineAdded.as_str());

        let asked = before_agent_go_tree(&repo.top, GO_PATCHES_DIR, &copy, false, false).await;
        repo.put(".socket/go-patches/m@v1/m.go", b"package m\n");
        let applied = after_agent_go_tree(&repo.top, &asked.unwrap(), result(true, None)).await;
        let note = applied.error.expect("the note of a successful result");
        // The CLI finds the code in the note of a successful result.
        let codes = crate::patch::apply::advisory_warning_codes(&note);
        assert_eq!(codes, [Code::WorkspaceIgnoreLineAdded.as_str()]);
        let both = with_note(Some("skipped".into()), Some(note.clone())).unwrap();
        assert_eq!(both, format!("skipped; {note}"));
        assert_eq!(with_note(None, None), None);
        assert_eq!(repo.rows(), [".socket/go-patches", ".socket/vendor"]);

        // What counts as a tree of `.socket/vendor`, for the removal too:
        // an archive is none, at the top of its unit or under a scope.
        std::fs::remove_dir_all(repo.top.join(".socket/vendor/cargo")).unwrap();
        repo.put(".socket/vendor/npm/u/x-1.0.0.tgz", b"");
        repo.put(".socket/vendor/npm/u/@s/x-1.0.0.tgz", b"");
        repo.put(".socket/vendor/maven/u/g/a/1/a-1.jar", b"");
        repo.dir(".socket/vendor/golang");
        assert!(!tree_exists(&repo.top, Vendor));
        repo.put("vlt-lock.json", b"{}");
        let asked = before_vendor_tree(&repo.top, "npm", UUID, false).await;
        let asked = asked.unwrap();
        assert!(asked.tree.is_some() && asked.advisories.is_empty());
        repo.dir(".socket/vendor/npm/u/@s/x-1.0.0/node_modules/@s/x");
        assert!(tree_exists(&repo.top, Vendor));
        std::fs::remove_dir_all(repo.top.join(".socket/vendor/npm/u/@s/x-1.0.0")).unwrap();
        repo.dir(".socket/vendor/npm/u/x-1.0.0/node_modules/x");
        assert!(tree_exists(&repo.top, Vendor));
        // A tree of each line is left, so neither line goes.
        assert_eq!(after_vendor_removal(&repo.top, false).await, Vec::new());
        assert_eq!(after_removal(&repo.top, GoPatches, false).await, Vec::new());
        assert_eq!(repo.rows().len(), 2);
        // The copies go: a dry run removes nothing, and the real one the
        // line of the copies alone.
        std::fs::remove_dir_all(repo.top.join(".socket/go-patches")).unwrap();
        assert_eq!(after_removal(&repo.top, GoPatches, true).await, Vec::new());
        assert_eq!(repo.rows().len(), 2);
        assert_eq!(after_removal(&repo.top, GoPatches, false).await, Vec::new());
        assert_eq!(repo.rows(), [".socket/vendor"]);
    }

    #[tokio::test]
    async fn a_new_unit_beside_an_archive_under_a_scope_is_still_refused() {
        // Two roots above the project: no new unit, whatever archives the
        // vendor directory holds already.
        let repo = Repo::workspace();
        repo.put("svc/WORKSPACE", b"");
        let project = repo.dir("svc/api");
        repo.put(
            &format!("svc/api/.socket/vendor/npm/{UUID}/@s/x-1.0.0.tgz"),
            b"",
        );
        repo.put("svc/api/vlt-lock.json", b"{}");
        let before = repo.tree();
        for (eco, uuid) in [("golang", OTHER_UUID), ("npm", UUID)] {
            let refused = before_vendor_tree(&project, eco, uuid, false).await;
            let Err(VendorOutcome::Refused { code, detail }) = refused else {
                panic!("{eco}: a new unit under two roots is refused");
            };
            assert_eq!(code, Code::VendorRulesetUnsupported.as_str());
            assert!(detail.contains("`nested_bazel_roots`"), "{detail}");
            assert_eq!(repo.tree(), before);
        }
        // The unpacked package of that unit is there: written again, it is
        // reported and not refused.
        repo.dir(&format!(
            "svc/api/.socket/vendor/npm/{UUID}/@s/x-1.0.0/node_modules/@s/x"
        ));
        let asked = before_vendor_tree(&project, "npm", UUID, false).await;
        let asked = asked.expect("a unit that is there");
        assert_eq!(asked.advisories[0].code, Code::WorkspaceIgnoreLineNeeded);
    }

    #[tokio::test]
    async fn a_write_that_fails_takes_its_line_back_unless_another_copy_keeps_it() {
        let repo = Repo::workspace();
        repo.put(".bazelignore", b"node_modules");
        let project = repo.dir("svc");
        let before = repo.tree();
        let copy = project.join(".socket/go-patches/m@v1");
        let refused = || VendorOutcome::Refused {
            code: "vendor_service_offline_conflict",
            detail: "offline".to_string(),
        };

        // The agent copy was not made, and the backend refused: the root
        // is as it was, and nothing is said about a line.
        let asked = before_agent_go_tree(&project, GO_PATCHES_DIR, &copy, false, false).await;
        let asked = asked.unwrap();
        assert_eq!(repo.rows(), ["svc/.socket/go-patches"]);
        let failed = after_agent_go_tree(&project, &asked, result(false, Some("boom"))).await;
        assert_eq!(failed.error.as_deref(), Some("boom"));
        assert_eq!(repo.tree(), before);
        let asked = before_vendor_tree(&project, "golang", UUID, false).await;
        assert_eq!(repo.rows(), ["svc/.socket/vendor"]);
        let VendorOutcome::Refused { detail, .. } =
            after_vendor_tree(&project, asked.unwrap(), refused()).await
        else {
            panic!("the outcome keeps its kind");
        };
        assert_eq!(detail, "offline");
        assert_eq!(repo.tree(), before);
        // A write that succeeded and had nothing to write (a patch with no
        // files) left no tree either: no line, and none reported.
        let asked = before_agent_go_tree(&project, GO_PATCHES_DIR, &copy, false, false).await;
        let empty = after_agent_go_tree(&project, &asked.unwrap(), result(true, None)).await;
        assert_eq!(empty.error, None);
        assert_eq!(repo.tree(), before);

        // Another unit keeps the line this run wrote: the files changed,
        // so the failed outcome says so, as a refusal's text and as a
        // failed result's warning.
        repo.put(
            &format!("svc/.socket/vendor/cargo/{OTHER_UUID}/x-1.0.0/Cargo.toml"),
            b"",
        );
        let told = "bazel_workspace_ignore_line_added: added the line `svc/.socket/vendor`";
        let asked = before_vendor_tree(&project, "golang", UUID, false).await;
        let VendorOutcome::Refused { detail, .. } =
            after_vendor_tree(&project, asked.unwrap(), refused()).await
        else {
            panic!("the outcome keeps its kind");
        };
        assert!(detail.starts_with(&format!("offline; {told}")), "{detail}");
        assert_eq!(repo.rows(), ["svc/.socket/vendor"]);
        // The line is there now, so a second failure has nothing to add.
        let asked = before_vendor_tree(&project, "golang", UUID, false).await;
        let failed = VendorOutcome::Done {
            result: result(false, Some("boom")),
            entry: None,
            warnings: Vec::new(),
        };
        let VendorOutcome::Done { warnings, .. } =
            after_vendor_tree(&project, asked.unwrap(), failed).await
        else {
            panic!("the outcome keeps its kind");
        };
        assert_eq!(warnings, Vec::new());

        // A dry run reports what the real run would leave: a failed copy
        // takes its line back, so there is nothing to say.
        let wired = repo.tree();
        let asked = before_agent_go_tree(&project, GO_PATCHES_DIR, &copy, false, true).await;
        let asked = asked.unwrap();
        assert!(asked.advisories[0].detail.starts_with("would add the line"));
        let failed = after_agent_go_tree(&project, &asked, result(false, Some("boom"))).await;
        assert_eq!(failed.error.as_deref(), Some("boom"));
        let applied = after_agent_go_tree(&project, &asked, result(true, None)).await;
        assert!(applied.error.unwrap().contains("would add the line"));
        assert_eq!(repo.tree(), wired);
    }

    /// A plan of a lane, with the writes it relies on.
    fn plan(writes: Vec<crate::bazel::model::PlannedWrite>) -> crate::bazel::model::Plan {
        use crate::bazel::model::{Anchor, AttestBasis, LaneId, Plan};
        Plan {
            uuid: UUID.to_string(),
            lane: LaneId::UNNAMED,
            writes,
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::LockPath,
            anchor: Anchor::Digest,
        }
    }

    /// The entry of a seam that carries out a lane's plan in a backend's
    /// place. The line a plan relies on goes in before the unit, whatever
    /// shape the artifact has, and stays once the plan is carried through
    /// (an archive is no tree a removal would keep it for); a plan that is
    /// not carried through takes it back, and so does a commit that did
    /// not land. A plan that relies on no line asks for nothing, and a dry
    /// run writes nothing and hands back the file the real run would have
    /// written.
    #[tokio::test]
    async fn a_plans_line_goes_in_before_its_unit_and_stays_while_the_plan_does() {
        use crate::bazel::model::PlannedWrite;
        let repo = Repo::workspace();
        let before = repo.tree();
        // An archive unit of an ecosystem no backend asks a line for.
        let unit = repo
            .top
            .join(vendor_uuid_dir_rel("npm", UUID).expect("a unit"));
        let line = || PlannedWrite::IgnoreLine {
            line: ".socket/vendor".to_string(),
        };

        let lock = PlannedWrite::NativeLock {
            path: "pnpm-lock.yaml".to_string(),
        };
        let asked = before_plans(&repo.top, &[plan(vec![lock])], &unit, false).await;
        let asked = asked.expect("nothing to refuse");
        assert_eq!((asked.advisories().count(), asked.preview()), (0, None));
        assert_eq!(after_plans(&repo.top, &asked, true).await, Vec::new());
        assert_eq!(repo.tree(), before, "no line was planned, none is written");

        // A dry run decides the same and writes nothing.
        let plans = [plan(vec![line()])];
        let dry = before_plans(&repo.top, &plans, &unit, true).await;
        let dry = dry.expect("the line can be written");
        let said: Vec<&Advisory> = dry.advisories().collect();
        assert!(said[0].detail.starts_with("would add the line"), "{said:?}");
        let preview = (ignore::BAZELIGNORE, &b".socket/vendor\n"[..]);
        assert_eq!(dry.preview(), Some(preview));
        assert_eq!(repo.tree(), before);

        // The real run: the line and its row, before any unit exists.
        let asked = before_plans(&repo.top, &plans, &unit, false).await;
        let asked = asked.expect("the line can be written");
        assert_eq!(asked.preview(), None, "the line is on disk");
        assert_eq!(repo.rows(), [".socket/vendor"]);
        let hidden = std::fs::read(repo.top.join(ignore::BAZELIGNORE)).expect("the file");
        assert_eq!(hidden, b".socket/vendor\n");
        // Not carried through: the root is as it was found.
        assert_eq!(after_plans(&repo.top, &asked, false).await, Vec::new());
        assert_eq!(repo.tree(), before);

        // Carried through with an archive artifact: the line stays, and
        // the run says that the root's files changed.
        let asked = before_plans(&repo.top, &plans, &unit, false).await;
        let asked = asked.expect("the line can be written");
        repo.put(
            &format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
            b"an archive",
        );
        let told = after_plans(&repo.top, &asked, true).await;
        assert_eq!(told.len(), 1, "{told:?}");
        assert_eq!(told[0].code, Code::WorkspaceIgnoreLineAdded);
        assert_eq!(repo.rows(), [".socket/vendor"]);
        // A second run finds the tree hidden and has nothing to add.
        let again = before_plans(&repo.top, &plans, &unit, false).await;
        let again = again.expect("already hidden");
        assert_eq!(again.advisories().count(), 0);
        // The commit of the carried plan did not land: the line goes.
        std::fs::remove_dir_all(repo.top.join(".socket").join("vendor")).expect("unwind");
        assert_eq!(after_plans(&repo.top, &asked, false).await, Vec::new());
        assert_eq!(repo.tree(), before);

        // Where the line cannot be written the plan's unit is refused,
        // with the channel's own code and remedy.
        let nested = Repo::workspace();
        nested.put("svc/MODULE.bazel", b"module(name = \"svc\")\n");
        let project = nested.dir("svc");
        let unit = project.join(vendor_uuid_dir_rel("npm", UUID).expect("a unit"));
        let wired = nested.tree();
        let refused = before_plans(&project, &[plan(vec![line()])], &unit, false).await;
        let refused = refused.expect_err("two roots, no line");
        assert_eq!(refused.token, Some(NESTED_BAZEL_ROOTS));
        assert_eq!(nested.tree(), wired);
    }
}
