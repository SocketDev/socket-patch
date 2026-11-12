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
//! - **Line first, then the tree.** [`before_tree`] runs before a tree is
//!   created. A line for a directory that does not exist is inert, so a
//!   run that fails afterwards leaves nothing harmful.
//! - **No line, no tree.** Where the line is needed and cannot be
//!   written, creating the tree is refused and the refusal prints each
//!   line and the file it belongs in: several Bazel roots above the
//!   project, a root outside the directory socket-patch writes in, a
//!   `.bazelignore` with a lone-CR line end or one that cannot be read, a
//!   project path no line can spell for every reader.
//! - **A tree that is already there is never refused.** Its line is
//!   written only after a bounded scan of the root's BUILD and `.bzl`
//!   files finds no label under it, because the line turns each such label
//!   into "Package is considered deleted" (gazelle writes them, probe S9).
//!   On a hit, and wherever else the line cannot be written, the run goes
//!   on and reports `bazel_workspace_ignore_line_needed`.
//! - **Removal by record.** [`after_removal`] takes a line out only when
//!   the index holds its row, by exact match, once no tree it covers is
//!   left. What the insert added to make room for the line goes with it,
//!   so a round trip is byte-identical.
//!
//! Both files are replaced by stage and rename, never truncated, under one
//! lock per root (`.socket/bazel/apply.lock`, which exists only while it
//! is held), so two sub-projects of one root are applied in order, in one
//! run or in two. No stage file is left beside either: a failed write
//! removes its own, and the next edit removes what an interrupted one
//! left (hazard HZ-27). The writes bypass an open group commit on purpose:
//! the line must be on disk before the tree is.
//!
//! With no Bazel root above a project the cost is the root probe's stats;
//! nothing is read and nothing is written.

use std::io::{ErrorKind, Read as _};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::bazel::codes::Code;
use crate::bazel::ignore::{self, CannotEdit, IgnoreLine, IgnoreModel, Removal, SocketTree};
use crate::bazel::model::{Advisory, FileText, RootRef};
use crate::bazel::owned_index::{self, Index, Parsed, INDEX_PATH};
use crate::constants::npm_family::VLT_LOCK;
use crate::crawlers::bazel_root::{boundary_file_in, RootProbe};
use crate::patch::apply_lock;
use crate::utils::containment::linked_level;
use crate::utils::fs::{atomic_write_sync, open_regular_file_sync, run_blocking};
use crate::utils::repo_root::{ReadBoundary, ReadScope};
use crate::utils::socket_dir::STAGE_PREFIX;
use crate::vendor::go_mod_edit::GO_PATCHES_DIR;
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
/// proven free of labels, so the line is not written for a found tree.
const SCAN_FILES: usize = 512;
const SCAN_DIRS: usize = 4096;
/// How long an edit waits for another run's edit of the same root.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// Serializes the edits of one process; the lock file serializes processes.
static CHANNEL: Mutex<()> = Mutex::new(());

/// A tree that was not created. `detail` ends with the remedy and
/// "nothing was written".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The mode's refusal code where a `token` names the case, else
    /// `bazel_workspace_ignore_line_needed`.
    pub code: Code,
    pub token: Option<&'static str>,
    pub detail: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

/// Why a line that is needed was not written, and what the user does.
struct Blocked {
    token: Option<&'static str>,
    why: String,
    remedy: String,
    /// The remedy lets the next run through. It does not where a root is
    /// above the repository: socket-patch cannot see a line added there.
    rerun: bool,
}

impl Blocked {
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

    fn refusal(self, tree_dir: &Path, tree: SocketTree) -> Refusal {
        let code = match (self.token, tree) {
            (None, _) => Code::WorkspaceIgnoreLineNeeded,
            (Some(_), SocketTree::GoPatches) => Code::AgentGoUnsupported,
            (Some(_), SocketTree::Vendor) => Code::VendorRulesetUnsupported,
        };
        let detail = format!(
            "{} was not created: the upstream BUILD files in it would join Bazel's `//...` \
             and break the build, and the `.bazelignore` line that hides it could not be \
             written: {}. {}{}; nothing was written",
            tree_dir.display(),
            self.why,
            self.remedy,
            if self.rerun { ", then run again" } else { "" }
        );
        Refusal {
            code,
            token: self.token,
            detail,
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

/// Whether a tree the line of `tree` hides is on disk under `project`.
/// For `.socket/vendor` that is a dir-shaped artifact: an unpacked npm
/// package (vlt) counts, a tarball, wheel or jar does not.
fn tree_exists(project: &Path, tree: SocketTree) -> bool {
    let base = project.join(tree.rel());
    let exists = |path: PathBuf| std::fs::symlink_metadata(path).is_ok();
    let dirs = |dir: &Path| -> Vec<PathBuf> {
        let entries = std::fs::read_dir(dir).into_iter().flatten().flatten();
        let dirs = entries.filter(|e| e.file_type().is_ok_and(|kind| kind.is_dir()));
        dirs.map(|e| e.path()).collect()
    };
    match tree {
        SocketTree::GoPatches => exists(base),
        SocketTree::Vendor => {
            let unpacked = DIR_SHAPED.iter().any(|eco| exists(base.join(eco)));
            unpacked
                || dirs(&base.join("npm"))
                    .iter()
                    .any(|uuid| !dirs(uuid).is_empty())
        }
    }
}

/// Why the line cannot be written for a tree that exists: a BUILD,
/// `.bzl`, module or workspace file of the root names a label under it,
/// or the scan could not rule that out. Directories the root's
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

/// Removes the directories of the owned index when nothing is left in
/// them: a root that had no `.socket` before an edit has none after its
/// undo. `remove_dir` leaves a directory that holds anything.
fn prune(root: &Path) {
    for dir in root.join(INDEX_PATH).ancestors().skip(1).take(2) {
        let _ = std::fs::remove_dir(dir);
    }
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
    let lock = apply_lock::acquire(owned, LOCK_WAIT);
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
    prune(root);
    done
}

/// Adds `line` and its index row. `Ok(false)`: a line hides the tree by
/// now, and nothing was written.
fn insert_line(
    file: &Path,
    index_path: &Path,
    line: &IgnoreLine,
    dry_run: bool,
) -> Result<bool, String> {
    let shown = |path: &Path| path.display().to_string();
    let insertion = match ignore::insert(&read(file), std::slice::from_ref(line)) {
        Ok(None) => return Ok(false),
        Ok(Some(insertion)) => insertion,
        Err(CannotEdit::LoneCr) => {
            let why = "ends a line with a lone carriage return, which Bazel takes for a line \
                       end and gazelle does not, so it has no line ending an edit could keep";
            return Err(format!("{} {why}", shown(file)));
        }
        Err(CannotEdit::Unreadable) => {
            return Err(format!("{} exists and could not be read", shown(file)));
        }
    };
    let recorded = read(index_path);
    let mut index = match &recorded {
        FileText::Absent => Index::default(),
        FileText::Unreadable => {
            return Err(format!(
                "{} exists and could not be read",
                shown(index_path)
            ));
        }
        FileText::Bytes(bytes) => match owned_index::parse(bytes) {
            Parsed::Ours(index) => index,
            Parsed::Modified(what) => {
                let fix = "restore it from version control";
                return Err(format!(
                    "{} is not the index socket-patch wrote ({what}); {fix}",
                    shown(index_path)
                ));
            }
            Parsed::Foreign => {
                let own = "is not socket-patch's index, which records the line for rollback";
                return Err(format!("{} {own}; move it away", shown(index_path)));
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
    done
}

/// The one root that governs the project and may be edited: writes the
/// line, or says why it cannot.
fn write_line(
    root: &RootRef,
    tree: SocketTree,
    found: bool,
    dry_run: bool,
) -> Result<Option<Advisory>, Blocked> {
    let (file, index_path) = (
        root.root.join(ignore::BAZELIGNORE),
        root.root.join(INDEX_PATH),
    );
    let dir = tree_rel(&root.project_rel, tree);
    let line = IgnoreLine::new(&root.project_rel, tree).map_err(|unspellable| Blocked {
        token: None,
        why: format!(
            "no line for `{dir}` is read the same way by every Bazel release and by gazelle \
             ({unspellable:?})"
        ),
        remedy: format!(
            "Hide a directory above it with a line of your own in {}",
            file.display()
        ),
        rerun: true,
    })?;
    let add = format!("Add the line `{}` to {}", line.as_str(), file.display());
    let blocked = |why: String| Blocked {
        token: None,
        why,
        remedy: add.clone(),
        rerun: true,
    };
    // socket-patch never replaces a link of the user's with a file, and a
    // linked `.socket` belongs to another project.
    let mut levels = [&file, &index_path].into_iter();
    if let Some(link) = levels.find_map(|path| linked_level(&root.root, path)) {
        return Err(blocked(format!("{} is a symbolic link", link.display())));
    }
    if let Some(why) = found.then(|| label_use(&root.root, &line)).flatten() {
        let gazelle = "then run the project's gazelle target (for example `bazel run \
                       //:gazelle`) so that it rewrites the label";
        return Err(Blocked {
            token: None,
            why,
            remedy: format!("{add}, {gazelle}"),
            rerun: true,
        });
    }
    let insert = |dry_run| insert_line(&file, &index_path, &line, dry_run);
    let written = match dry_run {
        true => insert(true),
        false => locked(&root.root, || insert(false)).and_then(|written| written),
    };
    Ok(written.map_err(blocked)?.then(|| Advisory {
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

/// [`before_tree`], blocking. The roots are the ones `bazel::probe`
/// reports: every root from the project up to the repository root, each
/// root above a project that is in no repository, and a root somebody
/// builds above the repository. One of them that does not hide the tree is
/// enough to need a line.
fn guard(project: &Path, tree: SocketTree, dry_run: bool) -> Result<Vec<Advisory>, Refusal> {
    let reads = ReadBoundary::upward(ReadScope::Workspace, project);
    let survey = RootProbe::new().survey(project, &reads);
    // A stray boundary file above the repository governs nothing; one that
    // somebody builds does, and nothing is read there.
    let above = survey.above.as_ref().filter(|above| above.confirmed);
    // What each root that does not hide the tree needs, and the boundary
    // file that makes it a root: a refusal names both.
    let (mut wanted, mut markers) = (Vec::new(), Vec::new());
    for root in &survey.roots {
        let (dir, file) = (
            tree_rel(&root.project_rel, tree),
            root.root.join(ignore::BAZELIGNORE),
        );
        if !IgnoreModel::read(&read(&file)).covers(&dir) {
            wanted.push(format!("the line `{dir}` to {}", file.display()));
        }
        let marker = boundary_file_in(&root.root).unwrap_or_default();
        markers.push(root.root.join(marker).display().to_string());
    }
    if let Some(outer) = above.and_then(|above| above.marker.parent()) {
        let real = std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf());
        let rel = real.strip_prefix(outer).ok().and_then(Path::to_str);
        let dir = tree_rel(&rel.unwrap_or("<project>").replace('\\', "/"), tree);
        let file = outer.join(ignore::BAZELIGNORE);
        wanted.push(format!("the line `{dir}` to {}", file.display()));
        markers.extend(above.map(|above| above.marker.display().to_string()));
    }
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    let found = tree_exists(project, tree);
    let writes = ReadBoundary::of(ReadScope::Workspace, project);
    let add = format!("Add {}", wanted.join(" and "));
    let outcome = match (above, survey.roots.as_slice()) {
        (None, [root]) if writes.contains(&root.root) => write_line(root, tree, found, dry_run),
        (None, [_, _, ..]) => Err(Blocked {
            token: Some(NESTED_BAZEL_ROOTS),
            why: format!(
                "{} Bazel roots lie above it ({}) and each reads its own `.bazelignore` \
                 (`{NESTED_BAZEL_ROOTS}`)",
                markers.len(),
                markers.join(", ")
            ),
            remedy: add,
            rerun: true,
        }),
        // With no repository around the project the root above it is its
        // workspace: read for coverage, and still not socket-patch's to
        // write.
        (None, _) => Err(Blocked {
            token: Some(BAZEL_ROOT_OUTSIDE_REPOSITORY),
            why: format!(
                "the Bazel root above it ({}) is outside the project, and with no repository \
                 around the project socket-patch writes nowhere else \
                 (`{BAZEL_ROOT_OUTSIDE_REPOSITORY}`)",
                markers.join(", ")
            ),
            remedy: add,
            rerun: true,
        }),
        (Some(_), _) => Err(Blocked {
            token: Some(BAZEL_ROOT_OUTSIDE_REPOSITORY),
            why: format!(
                "a Bazel root above it ({}) is outside the repository, where socket-patch \
                 neither reads nor writes (`{BAZEL_ROOT_OUTSIDE_REPOSITORY}`)",
                markers.join(", ")
            ),
            remedy: format!(
                "{add} from the repository that holds that Bazel root, and patch this project \
                 from there: a line above this repository is one socket-patch cannot see"
            ),
            rerun: false,
        }),
    };
    let tree_dir = project.join(tree.rel());
    match outcome {
        Ok(added) => Ok(added.into_iter().collect()),
        Err(blocked) if found => Ok(vec![blocked.advisory(&tree_dir)]),
        Err(blocked) => Err(blocked.refusal(&tree_dir, tree)),
    }
}

/// Takes the row of `line` out of the index and the line out of the file.
/// `None`: something could not be read or written, and what is left is a
/// line for a directory that is gone, which hides nothing.
fn remove_line(file: &Path, index_path: &Path, line: &IgnoreLine) -> Option<()> {
    let FileText::Bytes(bytes) = read(index_path) else {
        return None;
    };
    let Parsed::Ours(mut index) = owned_index::parse(&bytes) else {
        return None;
    };
    let at = index
        .ignore_lines
        .iter()
        .position(|row| row.line == *line)?;
    let row = index.ignore_lines.remove(at);
    match ignore::remove(&read(file), &row).ok()? {
        Removal::Missing => {}
        Removal::Deleted => std::fs::remove_file(file).ok()?,
        Removal::Rewritten { bytes, carry } => {
            atomic_write_sync(file, &bytes, true).ok()?;
            carry.apply(&mut index.ignore_lines);
        }
    }
    match index.is_empty() {
        true => std::fs::remove_file(index_path).ok(),
        false => atomic_write_sync(index_path, index.render().ok()?.as_bytes(), true).ok(),
    }
}

/// [`after_removal`], blocking. Silent: a line it cannot take back hides
/// a directory that is gone, and the next removal tries again.
fn release(project: &Path, tree: SocketTree) {
    if tree_exists(project, tree) {
        return;
    }
    let reads = ReadBoundary::upward(ReadScope::Workspace, project);
    let writes = ReadBoundary::of(ReadScope::Workspace, project);
    let survey = RootProbe::new().survey(project, &reads);
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
        // No index, no row: nothing at this root is socket-patch's to take.
        let mut levels = [&file, &index_path].into_iter();
        let linked = levels.any(|path| linked_level(&root.root, path).is_some());
        if linked || !matches!(read(&index_path), FileText::Bytes(_)) {
            continue;
        }
        let _ = locked(&root.root, || remove_line(&file, &index_path, &line));
    }
}

/// Call before `tree` of the project at `project_root` is created or
/// added to. `Ok` carries what the run reports (a line that was added, or
/// one an existing tree needs and did not get); `Err` means the tree must
/// not be created. A dry run decides the same and writes nothing.
pub async fn before_tree(
    project_root: &Path,
    tree: SocketTree,
    dry_run: bool,
) -> Result<Vec<Advisory>, Refusal> {
    let project = project_root.to_path_buf();
    run_blocking(move || guard(&project, tree, dry_run)).await
}

/// Call after trees of the project were removed: when none that the line
/// of `tree` covers is left, the line socket-patch recorded goes, and
/// with it the file or the index it leaves empty.
pub async fn after_removal(project_root: &Path, tree: SocketTree, dry_run: bool) {
    if !dry_run {
        let project = project_root.to_path_buf();
        run_blocking(move || release(&project, tree)).await;
    }
}

/// [`before_tree`] for the agent Go writer, whose result is text: the note
/// a successful result carries (`patch::apply::advisory_warning_codes`
/// turns it into the run's warnings), or the refusal. Only the agent copy
/// base is guarded here; the vendored one goes through
/// [`before_vendor_tree`].
pub async fn before_agent_go_tree(
    project_root: &Path,
    base_rel: &str,
) -> Result<Option<String>, String> {
    if base_rel != GO_PATCHES_DIR {
        return Ok(None);
    }
    let advisories = before_tree(project_root, SocketTree::GoPatches, false).await;
    let advisories = advisories.map_err(|refusal| refusal.to_string())?;
    let notes: Vec<String> = advisories
        .iter()
        .map(|a| format!("{}: {}", a.code, a.detail))
        .collect();
    Ok((!notes.is_empty()).then(|| notes.join("; ")))
}

/// `note` joined to what a successful result already says.
pub fn with_note(said: Option<String>, note: Option<String>) -> Option<String> {
    match (said, note) {
        (Some(said), Some(note)) => Some(format!("{said}; {note}")),
        (said, note) => said.or(note),
    }
}

/// [`before_tree`] for the vendor backend of ecosystem directory `eco`:
/// the warnings to attach to its outcome, or the refusal to return in its
/// place. Only a backend whose artifact is an unpacked package asks.
pub async fn before_vendor_tree(
    project_root: &Path,
    eco: &str,
    dry_run: bool,
) -> Result<Vec<VendorWarning>, VendorOutcome> {
    let vlt = || std::fs::symlink_metadata(project_root.join(VLT_LOCK)).is_ok();
    let unpacked = DIR_SHAPED.contains(&eco) || (eco == "npm" && vlt());
    if !unpacked {
        return Ok(Vec::new());
    }
    match before_tree(project_root, SocketTree::Vendor, dry_run).await {
        Ok(advisories) => {
            let warning = |a: Advisory| VendorWarning::new(a.code.as_str(), a.detail);
            Ok(advisories.into_iter().map(warning).collect())
        }
        Err(refusal) => Err(VendorOutcome::Refused {
            code: refusal.code.as_str(),
            detail: refusal.detail,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::SocketTree::{GoPatches, Vendor};
    use super::*;
    use std::collections::BTreeMap;

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

    /// The one advisory of a guard that wrote (or would write) a line.
    fn added(outcome: Result<Vec<Advisory>, Refusal>) -> String {
        let advisories = outcome.expect("the tree may be created");
        let [advisory] = advisories.as_slice() else {
            panic!("one advisory, not {advisories:?}");
        };
        assert_eq!(advisory.code, Code::WorkspaceIgnoreLineAdded);
        advisory.detail.clone()
    }

    #[test]
    fn a_project_under_no_bazel_root_is_left_alone() {
        let repo = Repo::new();
        let project = repo.dir("svc");
        assert_eq!(guard(&project, GoPatches, false), Ok(Vec::new()));
        assert_eq!(guard(&project, Vendor, false), Ok(Vec::new()));
        release(&project, GoPatches);
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

                let detail = added(guard(&project, tree, false));
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
                assert_eq!(guard(&project, tree, false), Ok(Vec::new()));
                assert_eq!(repo.tree(), wired);

                // The line stays while a tree it covers is there.
                std::fs::create_dir_all(project.join(made)).unwrap();
                release(&project, tree);
                assert_eq!(std::fs::read(repo.top.join(".bazelignore")).unwrap(), want);
                std::fs::remove_dir_all(project.join(tree.rel())).unwrap();
                // What a rollback leaves of the project's own `.socket`
                // (at the root, the index is still in it).
                let _ = std::fs::remove_dir(project.join(".socket"));
                release(&project, tree);
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
            let first = scope.spawn(|| added(guard(&a, GoPatches, false)));
            let second = scope.spawn(|| added(guard(&b, Vendor, false)));
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
        release(&a, GoPatches);
        assert_eq!(repo.rows(), ["b/c/.socket/vendor"]);
        let text = std::fs::read_to_string(repo.top.join(".bazelignore")).unwrap();
        assert_eq!(text, "node_modules\nb/c/.socket/vendor\n");
        release(&b, Vendor);
        assert_eq!(repo.tree(), before);
    }

    #[test]
    fn a_lone_cr_file_is_refused_and_left_byte_for_byte() {
        let repo = Repo::workspace();
        repo.put(".bazelignore", b"node_modules\rdist\r");
        let project = repo.dir("svc");
        let before = repo.tree();
        for dry_run in [true, false] {
            let refusal = guard(&project, GoPatches, dry_run).expect_err("no line, no tree");
            assert_eq!(
                (refusal.code, refusal.token),
                (Code::WorkspaceIgnoreLineNeeded, None)
            );
            let file = repo.top.join(".bazelignore");
            let remedy = format!(
                "Add the line `svc/.socket/go-patches` to {}",
                file.display()
            );
            assert!(refusal.detail.contains("lone carriage return"), "{refusal}");
            assert!(refusal.detail.contains(&remedy), "{refusal}");
            assert!(refusal.detail.ends_with("nothing was written"), "{refusal}");
            assert_eq!(repo.tree(), before);
        }
        // A tree that is already there is reported, never refused.
        repo.dir("svc/.socket/go-patches/m@v1");
        let found = repo.tree();
        let advisories = guard(&project, GoPatches, false).expect("the run goes on");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].code, Code::WorkspaceIgnoreLineNeeded);
        assert!(advisories[0]
            .detail
            .contains("is visible to Bazel's `//...`"));
        assert_eq!(repo.tree(), found);
        // A line of the user's that hides the tree needs no edit at all.
        repo.put(".bazelignore", b"node_modules\rsvc\r");
        assert_eq!(guard(&project, GoPatches, false), Ok(Vec::new()));
    }

    #[test]
    fn nested_roots_refuse_a_new_tree_and_name_each_line_and_file() {
        let repo = Repo::workspace();
        repo.put("svc/WORKSPACE", b"");
        let project = repo.dir("svc/api");
        let before = repo.tree();
        let outer = format!(
            "the line `svc/api/.socket/vendor` to {}",
            repo.top.join(".bazelignore").display()
        );
        let inner = format!(
            "the line `api/.socket/vendor` to {}",
            repo.top.join("svc/.bazelignore").display()
        );
        let refusal = guard(&project, Vendor, false).expect_err("two roots");
        assert_eq!(refusal.code, Code::VendorRulesetUnsupported);
        assert_eq!(refusal.token, Some(NESTED_BAZEL_ROOTS));
        for part in [
            outer.as_str(),
            inner.as_str(),
            "MODULE.bazel",
            "svc/WORKSPACE",
        ] {
            assert!(refusal.detail.contains(part), "{part}: {refusal}");
        }
        let agent = guard(&project, GoPatches, false).expect_err("two roots");
        assert_eq!(agent.code, Code::AgentGoUnsupported);
        assert!(agent
            .to_string()
            .starts_with(Code::AgentGoUnsupported.as_str()));
        assert_eq!(repo.tree(), before);

        // The user adds the lines: one is not enough, both are.
        repo.put("svc/.bazelignore", b"api/.socket/vendor\n");
        let refusal = guard(&project, Vendor, false).expect_err("the outer root");
        assert!(refusal.detail.contains(&outer) && !refusal.detail.contains(&inner));
        repo.put(".bazelignore", b"svc/api/.socket\n");
        assert_eq!(guard(&project, Vendor, false), Ok(Vec::new()));
        // A tree that is already there gets the advisory with the lines.
        repo.dir("svc/api/.socket/go-patches");
        repo.put("svc/.bazelignore", b"");
        let advisories = guard(&project, GoPatches, false).expect("the run goes on");
        assert_eq!(advisories[0].code, Code::WorkspaceIgnoreLineNeeded);
        assert!(advisories[0].detail.contains("`api/.socket/go-patches`"));
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
        let refusal = guard(&project, GoPatches, false).expect_err("a root out of reach");
        assert_eq!(refusal.code, Code::AgentGoUnsupported);
        assert_eq!(refusal.token, Some(BAZEL_ROOT_OUTSIDE_REPOSITORY));
        let line = format!(
            "the line `repo/.socket/go-patches` to {}",
            outer.top.join(".bazelignore").display()
        );
        assert!(refusal.detail.contains(&line), "{refusal}");
        assert!(refusal.detail.contains("MODULE.bazel"), "{refusal}");
        // No remedy that a second run would not see: the line is there
        // already, and socket-patch does not read it.
        assert!(refusal.detail.contains("cannot see"), "{refusal}");
        assert!(!refusal.detail.contains("then run again"), "{refusal}");
        assert_eq!(outer.tree(), before);
        // A stray boundary file with nothing beside it governs nothing.
        std::fs::remove_file(outer.top.join(".bazelversion")).unwrap();
        assert_eq!(guard(&project, GoPatches, false), Ok(Vec::new()));

        // No checkout at all: the root above the project is its workspace,
        // read for coverage and still not written.
        std::fs::remove_dir(outer.top.join("repo/.git")).unwrap();
        std::fs::remove_file(outer.top.join(".bazelignore")).unwrap();
        let before = outer.tree();
        let refusal = guard(&project, Vendor, false).expect_err("above the project");
        assert_eq!(refusal.code, Code::VendorRulesetUnsupported);
        assert_eq!(refusal.token, Some(BAZEL_ROOT_OUTSIDE_REPOSITORY));
        assert!(refusal.detail.contains("then run again"), "{refusal}");
        assert_eq!(outer.tree(), before);
        outer.put(".bazelignore", b"repo/.socket/vendor\n");
        assert_eq!(guard(&project, Vendor, false), Ok(Vec::new()));
    }

    #[test]
    fn a_tree_that_exists_gets_its_line_only_when_no_label_names_it() {
        let repo = Repo::workspace();
        repo.put(".bazelignore", b"node_modules\n");
        repo.put(
            ".socket/go-patches/example.com/m@v1.0.0/BUILD.bazel",
            b"x()\n",
        );
        // Inside the tree and under a hidden directory a label is no hit.
        repo.put(
            ".socket/go-patches/example.com/m@v1.0.0/sub/BUILD",
            b"\"//.socket/go-patches/example.com/m@v1.0.0:m\"\n",
        );
        repo.put("node_modules/x/BUILD", b"\"//.socket/go-patches/y\"\n");
        let rewired =
            b"go_library(\n    deps = [\"//.socket/go-patches/example.com/m@v1.0.0:m\"],\n)\n";
        repo.put("app/BUILD.bazel", rewired);
        let before = repo.tree();
        let advisories = guard(&repo.top, GoPatches, false).expect("the run goes on");
        assert_eq!(advisories[0].code, Code::WorkspaceIgnoreLineNeeded);
        let hit = format!(
            "{}:2 names a label",
            repo.top.join("app/BUILD.bazel").display()
        );
        for part in [
            hit.as_str(),
            "Add the line `.socket/go-patches`",
            "gazelle target",
        ] {
            assert!(
                advisories[0].detail.contains(part),
                "{part}: {:?}",
                advisories[0]
            );
        }
        assert_eq!(repo.tree(), before);

        repo.put("app/BUILD.bazel", b"go_library(deps = [\"//lib\"])\n");
        added(guard(&repo.top, GoPatches, false));
        assert_eq!(repo.rows(), [".socket/go-patches"]);
        // A directory behind a link cannot be scanned: no proof, no line.
        #[cfg(unix)]
        {
            std::fs::remove_file(repo.top.join(".bazelignore")).unwrap();
            std::os::unix::fs::symlink(repo.top.join("app"), repo.top.join("linked")).unwrap();
            let advisories = guard(&repo.top, GoPatches, false).expect("the run goes on");
            assert!(advisories[0].detail.contains("is a link to a directory"));
            assert!(!repo.top.join(".bazelignore").exists());
        }
    }

    #[test]
    fn an_index_or_a_link_that_is_not_socket_patchs_blocks_the_edit() {
        let repo = Repo::workspace();
        for (index, why) in [
            (&b"{}\n"[..], "is not socket-patch's index"),
            (
                b"{\"ignoreLines\": [], \"pins\": [], \"version\": 1}",
                "restore it from version control",
            ),
        ] {
            repo.put(INDEX_PATH, index);
            let before = repo.tree();
            let refusal = guard(&repo.top, Vendor, false).expect_err("no record, no line");
            assert_eq!(refusal.code, Code::WorkspaceIgnoreLineNeeded);
            assert!(refusal.detail.contains(why), "{refusal}");
            assert_eq!(repo.tree(), before);
        }
        #[cfg(unix)]
        {
            std::fs::remove_dir_all(repo.top.join(".socket")).unwrap();
            repo.put("shared.bazelignore", b"node_modules\n");
            let link = repo.top.join(".bazelignore");
            std::os::unix::fs::symlink("shared.bazelignore", &link).unwrap();
            let refusal = guard(&repo.top, GoPatches, false).expect_err("a link is the user's");
            assert!(refusal.detail.contains("is a symbolic link"), "{refusal}");
            assert!(std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
            assert!(!repo.top.join(".socket").exists());
            // Read through the link, as Bazel reads it: a covering line counts.
            repo.put("shared.bazelignore", b".socket\n");
            assert_eq!(guard(&repo.top, GoPatches, false), Ok(Vec::new()));
        }
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
        added(guard(&repo.top, GoPatches, false));
        for rel in staged {
            assert!(!repo.top.join(rel).exists(), "{rel}");
        }
        assert!(repo.top.join(".socket-stage-other").exists());
        std::fs::remove_file(repo.top.join(".socket-stage-other")).unwrap();
        release(&repo.top, GoPatches);
        assert_eq!(repo.tree().len(), 1, "only MODULE.bazel: {:?}", repo.tree());
    }

    #[tokio::test]
    async fn the_seams_ask_only_for_trees_bazel_could_load() {
        let repo = Repo::workspace();
        let before = repo.tree();
        // A dry run says what it would do and writes nothing.
        let detail = added(before_tree(&repo.top, Vendor, true).await);
        assert!(
            detail.starts_with("would add the line `.socket/vendor`"),
            "{detail}"
        );
        // An archive is no tree, and npm unpacks only under vlt.
        for eco in ["pypi", "nuget", "maven", "npm"] {
            assert!(before_vendor_tree(&repo.top, eco, false)
                .await
                .unwrap()
                .is_empty());
        }
        assert_eq!(
            before_agent_go_tree(&repo.top, ".socket/vendor/golang/u").await,
            Ok(None)
        );
        assert_eq!(repo.tree(), before);

        let warnings = before_vendor_tree(&repo.top, "cargo", false).await.unwrap();
        assert_eq!(warnings[0].code, Code::WorkspaceIgnoreLineAdded.as_str());
        let note = before_agent_go_tree(&repo.top, GO_PATCHES_DIR)
            .await
            .unwrap()
            .unwrap();
        // The CLI finds the code in the note of a successful result.
        let codes = crate::patch::apply::advisory_warning_codes(&note);
        assert_eq!(codes, [Code::WorkspaceIgnoreLineAdded.as_str()]);
        let both = with_note(Some("skipped".into()), Some(note.clone())).unwrap();
        assert_eq!(both, format!("skipped; {note}"));
        assert_eq!(with_note(None, None), None);
        assert_eq!(repo.rows(), [".socket/go-patches", ".socket/vendor"]);

        // What counts as a tree of `.socket/vendor`, for the removal too.
        repo.put(".socket/vendor/npm/u/x-1.0.0.tgz", b"");
        repo.put(".socket/vendor/maven/u/g/a/1/a-1.jar", b"");
        assert!(!tree_exists(&repo.top, Vendor));
        repo.put("vlt-lock.json", b"{}");
        assert!(before_vendor_tree(&repo.top, "npm", false)
            .await
            .unwrap()
            .is_empty());
        repo.dir(".socket/vendor/npm/u/x-1.0.0/node_modules/x");
        assert!(tree_exists(&repo.top, Vendor));
        after_removal(&repo.top, Vendor, false).await;
        after_removal(&repo.top, GoPatches, true).await;
        assert_eq!(
            repo.rows().len(),
            2,
            "a tree is left, and a dry run removes nothing"
        );
        after_removal(&repo.top, GoPatches, false).await;
        assert_eq!(repo.rows(), [".socket/vendor"]);
    }
}
