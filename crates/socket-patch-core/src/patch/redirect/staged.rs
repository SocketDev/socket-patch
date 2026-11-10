//! Staged, fail-closed file I/O for the hosted → upstream restore
//! ([`super::upstream`]).
//!
//! The restore resolves every pin against a STAGED view of the project and
//! lets nothing reach disk until all of them have resolved, so a refusal
//! leaves the project byte-identical. This module is that staging layer:
//! FIFO-safe reads of untrusted project files, the staged view, and one
//! all-or-nothing flush. [`preflight`] checks every staged file before the
//! first one is written (a dry run stops after it, so the preview predicts
//! the refusal), and [`flush`] puts the files it already wrote back when a
//! later one fails.
//!
//! The undo is the bytes [`preflight`] read, held in memory, not the
//! vendored run's roll-forward journal ([`crate::utils::group_commit`]):
//! that journal lives in `.socket/vendor/`, which a hosted project does not
//! have and a restore must not create, and a group captures neither the
//! Gradle wiring a restore rewrites under `.socket/gradle/` nor a file
//! reached through `..`. An error part-way is therefore undone; a process
//! killed between two writes still leaves the files written so far.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Files a revert has decided but not yet written: `Some(content)` to
/// write, `None` to delete.
pub(super) type Staged = BTreeMap<String, Option<String>>;

/// Native binary lockfiles staged after restoring their package snapshots.
pub(super) type StagedBytes = BTreeMap<String, Vec<u8>>;

/// `project_root.join(rel)` for a file the restore reads or writes, or why
/// it may not touch that file: its real path lies outside the repository
/// root. An absolute `rel` is an upward lookup's (a pnpm workspace root's
/// settings above the project), bounded as one: only inside a checkout.
fn bounded_path(project_root: &Path, rel: &str) -> Result<PathBuf, String> {
    use crate::utils::repo_root::{bounded_project_path, upward_bound, ReadScope};
    if crate::utils::relpath::is_anchored(rel) {
        let path = project_root.join(rel);
        return match upward_bound(ReadScope::Workspace, project_root) {
            Some(bound) if !bound.contains(&path) => Err(bound.refusal(&path)),
            _ => Ok(path),
        };
    }
    bounded_project_path(ReadScope::Workspace, project_root, rel)
        .map_err(|refused| refused.to_string())
}

/// Read a project file, distinguishing missing (`Ok(None)`) from unreadable.
///
/// FIFO-guarded: a planted FIFO, directory or device squatting a lockfile
/// path fails fast (`InvalidInput`) instead of wedging the revert on a
/// blocking open — the same posture as every other raw read in the patch
/// engine. Errors read `read <rel>: <cause>`.
pub(super) async fn read_rel(project_root: &Path, rel: &str) -> Result<Option<String>, String> {
    // A writer's read outside the repository root refuses rather than
    // reading as missing: what it would write next depends on it.
    let path =
        bounded_path(project_root, rel).map_err(|refused| format!("read {rel}: {refused}"))?;
    match crate::utils::fs::read_regular_to_string(&path).await {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {rel}: {e}")),
    }
}

/// One file the restore decided to write or delete.
pub(super) struct Pending<'a> {
    pub(super) rel: &'a str,
    /// The bytes to write; `None` deletes the file.
    pub(super) content: Option<&'a [u8]>,
    /// What the restore read at `rel` while it resolved the pins
    /// (`Some(None)`: no file there); `None` when it never read it.
    pub(super) read: Option<Option<&'a [u8]>>,
}

/// A [`Pending`] file that passed [`preflight`].
pub(super) struct Checked<'a> {
    rel: &'a str,
    path: PathBuf,
    content: Option<&'a [u8]>,
    /// The file's bytes when the flush starts (`None`: no file): what a
    /// failed flush puts back.
    before: Option<Vec<u8>>,
    /// Its permissions on disk then, for a deleted file that is put back
    /// as a new inode.
    permissions: Option<std::fs::Permissions>,
}

/// A flush that stopped part-way.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct FlushError {
    /// What failed, and the state every written file was left in.
    pub(super) message: String,
    /// The files that hold their restored state because putting them back
    /// failed as well; empty when the project is as it was.
    pub(super) left: Vec<String>,
}

/// Check, without writing, that every staged file can be flushed, so the
/// flush either starts with nothing in its way or does not start: a refusal
/// here leaves the project byte-identical (every message ends `nothing was
/// written`), and a dry run reports it as the wet run would.
///
/// For each file, in flush order:
///
/// * its real path is inside the repository root ([`bounded_path`]);
/// * the path holds a regular file or nothing. A rename-over would replace
///   a symbolic link with a detached regular file, and writing into a FIFO
///   blocks forever;
/// * its bytes are still the ones the restore resolved the pins from, so
///   an edit made in between is not written over;
/// * its directory takes the write. The writer stages a sibling and renames
///   it over the file, and a removal unlinks it, so both need the directory
///   rather than the file to be writable. Skipped for a file an open
///   [`crate::utils::group_commit::GroupCommit`] captures: that write only
///   reaches the disk at the group's commit, which creates the directory.
///
/// The bytes read for the comparison are kept as the flush's undo.
pub(super) async fn preflight<'a>(
    project_root: &Path,
    pending: Vec<Pending<'a>>,
) -> Result<Vec<Checked<'a>>, String> {
    let mut checked = Vec::with_capacity(pending.len());
    for file in pending {
        checked.push(check(project_root, file).await?);
    }
    Ok(checked)
}

async fn check<'a>(project_root: &Path, file: Pending<'a>) -> Result<Checked<'a>, String> {
    let rel = file.rel;
    let unwritten = |why: String| format!("{why}; nothing was written");
    let path = bounded_path(project_root, rel)
        .map_err(|refused| unwritten(format!("write {rel}: {refused}")))?;
    let permissions = match tokio::fs::symlink_metadata(&path).await {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(crate::hosted::engine::symlink_refusal(rel).message)
        }
        Ok(meta) if !meta.is_file() => {
            return Err(unwritten(format!("{rel} is not a regular file")))
        }
        Ok(meta) => Some(meta.permissions()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(unwritten(format!("write {rel}: {e}"))),
    };
    let before = match crate::utils::fs::read_regular_to_bytes(&path).await {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(unwritten(format!("read {rel}: {e}"))),
    };
    if file.read.is_some_and(|read| read != before.as_deref()) {
        return Err(unwritten(format!(
            "{rel} changed on disk while its restore was being worked out"
        )));
    }
    let touches_disk = file.content.is_some() || before.is_some();
    if touches_disk && !crate::utils::group_commit::is_capturing(&path) {
        let dir = match path.parent() {
            Some(dir) if !dir.as_os_str().is_empty() => dir,
            _ => Path::new("."),
        };
        if let Err(e) = entries_writable(dir) {
            let verb = if file.content.is_some() {
                "write"
            } else {
                "remove"
            };
            return Err(unwritten(format!(
                "{verb} {rel}: its directory cannot be written ({e})"
            )));
        }
    }
    Ok(Checked {
        rel,
        path,
        content: file.content,
        before,
        permissions,
    })
}

/// Whether this process may create, replace and remove entries in `dir`,
/// asked without writing (a dry run asks too).
#[cfg(unix)]
fn entries_writable(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;
    let dir = std::ffi::CString::new(dir.as_os_str().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // `access`, not `faccessat(AT_EACCESS)`, which Android's libc rejects.
    if unsafe { libc::access(dir.as_ptr(), libc::W_OK | libc::X_OK) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Off Unix a directory's writability is its ACL, which nothing here reads:
/// only a missing directory is caught up front, and any other failure by
/// the flush's put-back.
#[cfg(not(unix))]
fn entries_writable(dir: &Path) -> std::io::Result<()> {
    std::fs::metadata(dir).map(|_| ())
}

/// Write the checked files, all or none: when one fails, the files already
/// written are put back from the bytes [`preflight`] read (newest first),
/// and the error says so. Should putting one back fail as well, the error
/// names each such file and the state it is left in ([`FlushError::left`]).
///
/// Text and binary content go through the atomic mode-preserving writer, so
/// a crash or `ENOSPC` mid-write never leaves a torn lockfile and a `0600`
/// lock keeps its bits. The now-empty parent directory of a deleted file
/// (the `.cargo/` a registry block was written into) is pruned best-effort
/// once every file has landed, so a put-back still finds it; the project
/// root itself is never touched.
pub(super) async fn flush(checked: &[Checked<'_>]) -> Result<(), FlushError> {
    for (at, file) in checked.iter().enumerate() {
        if let Err(failure) = file.write().await {
            return Err(put_back(&checked[..at], failure).await);
        }
    }
    for file in checked.iter().filter(|file| file.content.is_none()) {
        let in_subdir = Path::new(file.rel)
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty());
        if in_subdir {
            if let Some(parent) = file.path.parent() {
                // `remove_dir` refuses a non-empty directory, so this only
                // ever removes the husk the revert emptied — after a
                // vendored run's group commit when the removal was captured.
                crate::utils::group_commit::remove_dir_after_commit(parent).await;
            }
        }
    }
    Ok(())
}

/// Undo `written` after the flush failed with `failure`, and word the
/// error the restore reports.
async fn put_back(written: &[Checked<'_>], failure: String) -> FlushError {
    let mut states = Vec::new();
    let mut left = Vec::new();
    let mut checkout = Vec::new();
    for file in written.iter().rev() {
        let Err(e) = file.put_back().await else {
            continue;
        };
        left.push(file.rel.to_string());
        states.push(match (file.content, &file.before) {
            (None, _) => {
                checkout.push(file.rel);
                format!("{} is left deleted ({e})", file.rel)
            }
            (Some(_), Some(_)) => {
                checkout.push(file.rel);
                format!("{} is left with its restored content ({e})", file.rel)
            }
            (Some(_), None) => format!("{} is left created ({e}); delete it", file.rel),
        });
    }
    let message = if !states.is_empty() {
        let remedy = if checkout.is_empty() {
            String::new()
        } else {
            format!(
                "; restore {} from version control (`git checkout -- {}`)",
                if checkout.len() == 1 { "it" } else { "them" },
                checkout.join(" ")
            )
        };
        format!(
            "{failure}; putting back what was already written failed as well, so the \
             restore is half applied: {}; every other file is unchanged{remedy}",
            states.join(", ")
        )
    } else if written.is_empty() {
        format!("{failure}; nothing was changed")
    } else {
        format!(
            "{failure}; the {} already written {} put back, so nothing was changed",
            if written.len() == 1 {
                "file".to_string()
            } else {
                format!("{} files", written.len())
            },
            if written.len() == 1 { "was" } else { "were" },
        )
    };
    FlushError { message, left }
}

impl Checked<'_> {
    /// Write (or delete) the file. Errors read `write <rel>: <cause>` /
    /// `remove <rel>: <cause>`.
    async fn write(&self) -> Result<(), String> {
        let rel = self.rel;
        if injected_failure(WRITE_FAILPOINT, rel) {
            return Err(format!("write {rel}: injected write failure"));
        }
        match self.content {
            Some(content) => {
                crate::utils::fs::atomic_write_bytes_preserving_mode(&self.path, content)
                    .await
                    .map_err(|e| format!("write {rel}: {e}"))
            }
            None => match crate::utils::fs::remove_file(&self.path).await {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(format!("remove {rel}: {e}"))
                }
                _ => Ok(()),
            },
        }
    }

    /// Put the file back to what it was when the flush started.
    async fn put_back(&self) -> std::io::Result<()> {
        if injected_failure(PUT_BACK_FAILPOINT, self.rel) {
            return Err(std::io::Error::other("injected put-back failure"));
        }
        match &self.before {
            Some(before) => {
                crate::utils::fs::atomic_write_bytes_preserving_mode(&self.path, before).await?;
                // The writer keeps the mode of the file it replaces; a file
                // the flush deleted comes back as a new inode instead.
                if let (None, Some(permissions)) = (self.content, &self.permissions) {
                    let _ = tokio::fs::set_permissions(&self.path, permissions.clone()).await;
                }
                Ok(())
            }
            None => match crate::utils::fs::remove_file(&self.path).await {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            },
        }
    }
}

/// The [`crate::utils::failpoint`] reached before each file is written (or
/// removed), and the one reached before each is put back.
const WRITE_FAILPOINT: &str = "hosted_restore_write";
const PUT_BACK_FAILPOINT: &str = "hosted_restore_put_back";

/// Whether a test asked for a failure at `point` for the file `rel`, as a
/// full disk would cause: a test of the built binary through the failpoint
/// itself, a unit test (whose process runs other restores at the same
/// time) by naming the file.
fn injected_failure(point: &str, rel: &str) -> bool {
    #[cfg(test)]
    {
        let named = if point == WRITE_FAILPOINT {
            &FAIL_WRITE
        } else {
            &FAIL_PUT_BACK
        };
        if named.with(std::cell::Cell::get) == Some(rel) {
            return true;
        }
    }
    #[cfg(not(test))]
    let _ = rel;
    crate::utils::failpoint::fails(point)
}

#[cfg(test)]
thread_local! {
    /// Unit tests: the root-relative file whose write (or removal) fails.
    static FAIL_WRITE: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
    /// Unit tests: the root-relative file whose put-back fails.
    static FAIL_PUT_BACK: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::{flush, preflight, read_rel, FlushError, Pending};
    use crate::patch::redirect::upstream::{
        restore_upstream, HostedPin, PinStatus, RestoreOptions, RestoreOutcome,
    };
    use std::collections::BTreeMap;
    use std::path::Path;

    const SUMS: &str = ".mvn/checksums/checksums.sha256";
    const CONFIG: &str = ".mvn/maven.config";
    const POM: &str = "pom.xml";

    /// A hosted Maven pin wired through three files, which the restore
    /// flushes in this order: [`SUMS`] (deleted), [`CONFIG`] (deleted),
    /// [`POM`] (rewritten).
    fn maven_project() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        for rel in [SUMS, CONFIG, POM] {
            let fixture = format!(
                "{}/tests/fixtures/redirect/maven/pom/basic/expected/{rel}",
                env!("CARGO_MANIFEST_DIR")
            );
            let path = tmp.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::copy(fixture, path).unwrap();
        }
        tmp
    }

    async fn restore(root: &Path, dry_run: bool) -> RestoreOutcome {
        let pins = [HostedPin {
            purl: "pkg:maven/org.slf4j/slf4j-api@1.7.36".into(),
            uuid: "77777777-7777-7777-7777-777777777777".into(),
            files: vec![POM.into()],
        }];
        let opts = RestoreOptions {
            dry_run,
            offline: true,
            ..RestoreOptions::default()
        };
        restore_upstream(root, &pins, &opts).await
    }

    /// Every file under `root` with its content (a link: its target).
    fn tree(root: &Path) -> BTreeMap<String, String> {
        walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| !e.file_type().is_dir())
            .map(|e| {
                let rel = e.path().strip_prefix(root).unwrap();
                let content = match std::fs::read_link(e.path()) {
                    Ok(target) => format!("-> {}", target.display()),
                    Err(_) => std::fs::read_to_string(e.path()).unwrap(),
                };
                (rel.to_string_lossy().replace('\\', "/"), content)
            })
            .collect()
    }

    /// A failed flush restored nothing: the error names `rel`, the tree is
    /// byte-identical to `before`, and no pin reads as restored.
    fn assert_refused_whole(
        outcome: &RestoreOutcome,
        root: &Path,
        before: &BTreeMap<String, String>,
        rel: &str,
    ) {
        let error = outcome.flush_error.as_deref().expect("the flush fails");
        assert!(error.contains(rel), "{error}");
        assert_eq!(&tree(root), before, "{error}");
        assert_eq!(outcome.restored().count(), 0, "no pin was restored");
        assert_eq!(outcome.pins[0].status, PinStatus::Unwritten);
        assert!(outcome.half_applied.is_empty(), "{error}");
        // What the restore would have written is still reported.
        assert_eq!(outcome.reverted_files, [SUMS, CONFIG, POM]);
    }

    /// The fixture restores cleanly: all three files are flushed.
    #[tokio::test]
    async fn the_three_file_restore_lands_whole() {
        let tmp = maven_project();
        let outcome = restore(tmp.path(), false).await;
        assert_eq!(outcome.flush_error, None);
        assert_eq!(outcome.restored().count(), 1);
        assert_eq!(outcome.reverted_files, [SUMS, CONFIG, POM]);
        let after = tree(tmp.path());
        assert_eq!(after.keys().collect::<Vec<_>>(), [POM], "{after:?}");
        assert!(!tmp.path().join(".mvn").exists(), "the emptied dirs go");
    }

    /// File 2 of 3 is a symbolic link: the restore is refused before file
    /// 1 is written, and a dry run predicts the refusal.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_file_refuses_the_restore_before_any_write() {
        for dry_run in [false, true] {
            let tmp = maven_project();
            let config = tmp.path().join(CONFIG);
            let shared = tmp.path().join("shared-maven.config");
            std::fs::rename(&config, &shared).unwrap();
            std::os::unix::fs::symlink(&shared, &config).unwrap();
            let before = tree(tmp.path());

            let outcome = restore(tmp.path(), dry_run).await;
            assert_refused_whole(&outcome, tmp.path(), &before, CONFIG);
            let error = outcome.flush_error.unwrap();
            assert!(
                error.contains("symbolic link") && error.ends_with("nothing was written"),
                "dry_run={dry_run}: {error}"
            );
        }
    }

    /// File 2 of 3 sits in a directory the run cannot write: refused
    /// before file 1 is written, and by a dry run.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unwritable_file_refuses_the_restore_before_any_write() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        for dry_run in [false, true] {
            let tmp = maven_project();
            let mvn = tmp.path().join(".mvn");
            let before = tree(tmp.path());
            std::fs::set_permissions(&mvn, std::fs::Permissions::from_mode(0o555)).unwrap();
            let outcome = restore(tmp.path(), dry_run).await;
            std::fs::set_permissions(&mvn, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_refused_whole(&outcome, tmp.path(), &before, CONFIG);
            let error = outcome.flush_error.unwrap();
            assert!(
                error.contains("its directory cannot be written")
                    && error.ends_with("nothing was written"),
                "dry_run={dry_run}: {error}"
            );
        }
    }

    /// A write that fails on file 2 of 3 puts file 1 back: the three files
    /// end byte-identical to the start and the restore reports the failure.
    #[tokio::test]
    async fn a_write_failure_midway_puts_the_written_files_back() {
        let tmp = maven_project();
        let before = tree(tmp.path());
        super::FAIL_WRITE.with(|f| f.set(Some(CONFIG)));
        let outcome = restore(tmp.path(), false).await;
        super::FAIL_WRITE.with(|f| f.set(None));
        assert_refused_whole(&outcome, tmp.path(), &before, CONFIG);
        assert_eq!(
            outcome.flush_error.unwrap(),
            format!(
                "write {CONFIG}: injected write failure; the file already written was put \
                 back, so nothing was changed"
            )
        );
    }

    fn pending<'a>(rel: &'a str, content: Option<&'a str>) -> Pending<'a> {
        Pending {
            rel,
            content: content.map(str::as_bytes),
            read: None,
        }
    }

    /// Flush `files` over `root`, failing the write of `fail_write` and the
    /// put-back of `fail_put_back`.
    async fn flush_failing(
        root: &Path,
        files: Vec<Pending<'_>>,
        fail_write: &'static str,
        fail_put_back: Option<&'static str>,
    ) -> FlushError {
        let checked = preflight(root, files).await.unwrap();
        super::FAIL_WRITE.with(|f| f.set(Some(fail_write)));
        super::FAIL_PUT_BACK.with(|f| f.set(fail_put_back));
        let result = flush(&checked).await;
        super::FAIL_WRITE.with(|f| f.set(None));
        super::FAIL_PUT_BACK.with(|f| f.set(None));
        result.unwrap_err()
    }

    /// Every kind of write is undone: a rewritten file gets its bytes back,
    /// a deleted one is recreated (in the directory the flush has not
    /// pruned yet, with its mode), and a created one is removed.
    #[tokio::test]
    async fn every_kind_of_write_is_put_back() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir(root.join("dir")).unwrap();
        std::fs::write(root.join("a.lock"), "a before\n").unwrap();
        std::fs::write(root.join("dir/b.config"), "b before\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let private = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(root.join("dir/b.config"), private).unwrap();
        }
        std::fs::write(root.join("d.lock"), "d before\n").unwrap();
        let before = tree(root);

        let files = vec![
            pending("a.lock", Some("a after\n")),
            pending("c.new", Some("c after\n")),
            pending("d.lock", Some("d after\n")),
            pending("dir/b.config", None),
        ];
        // The last file: the three before it were written.
        let error = flush_failing(root, files, "dir/b.config", None).await;
        assert_eq!(
            error,
            FlushError {
                message: "write dir/b.config: injected write failure; the 3 files already \
                          written were put back, so nothing was changed"
                    .to_string(),
                left: Vec::new(),
            }
        );
        assert_eq!(tree(root), before);

        // The same set with the deletion first: it is put back too.
        let files = vec![
            pending("dir/b.config", None),
            pending("a.lock", Some("a after\n")),
            pending("d.lock", Some("d after\n")),
        ];
        let error = flush_failing(root, files, "d.lock", None).await;
        assert!(error.left.is_empty(), "{}", error.message);
        assert_eq!(tree(root), before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.join("dir/b.config")).unwrap();
            assert_eq!(mode.permissions().mode() & 0o777, 0o600);
        }

        // A failure on the first file has nothing to undo.
        let files = vec![pending("a.lock", Some("a after\n"))];
        let error = flush_failing(root, files, "a.lock", None).await;
        assert_eq!(
            error.message,
            "write a.lock: injected write failure; nothing was changed"
        );
    }

    /// When a file cannot be put back either, the error names it and the
    /// state it is left in, and says the rest is unchanged.
    #[tokio::test]
    async fn a_failed_put_back_names_the_file_and_its_state() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for name in ["a.lock", "b.config", "c.lock"] {
            std::fs::write(root.join(name), format!("{name} before\n")).unwrap();
        }
        let files = vec![
            pending("a.lock", Some("a after\n")),
            pending("b.config", None),
            pending("c.lock", Some("c after\n")),
        ];
        let error = flush_failing(root, files, "c.lock", Some("b.config")).await;
        assert_eq!(
            error,
            FlushError {
                message: "write c.lock: injected write failure; putting back what was \
                          already written failed as well, so the restore is half applied: \
                          b.config is left deleted (injected put-back failure); every other \
                          file is unchanged; restore it from version control (`git checkout \
                          -- b.config`)"
                    .to_string(),
                left: vec!["b.config".to_string()],
            }
        );
        assert_eq!(
            tree(root),
            BTreeMap::from([
                ("a.lock".to_string(), "a.lock before\n".to_string()),
                ("c.lock".to_string(), "c.lock before\n".to_string()),
            ])
        );

        std::fs::write(root.join("b.config"), "b.config before\n").unwrap();
        let files = vec![
            pending("a.lock", Some("a after\n")),
            pending("new.toml", Some("new\n")),
            pending("c.lock", Some("c after\n")),
        ];
        let error = flush_failing(root, files, "c.lock", Some("a.lock")).await;
        assert!(
            error
                .message
                .contains("a.lock is left with its restored content"),
            "{}",
            error.message
        );
        assert_eq!(error.left, ["a.lock"]);
        let after = tree(root);
        assert_eq!(after["a.lock"], "a after\n");
        assert!(!after.contains_key("new.toml"), "{after:?}");

        let files = vec![
            pending("made.toml", Some("made\n")),
            pending("c.lock", Some("c after\n")),
        ];
        let error = flush_failing(root, files, "c.lock", Some("made.toml")).await;
        assert!(
            error.message.contains(
                "made.toml is left created (injected put-back failure); delete it; every \
                 other file is unchanged"
            ) && !error.message.contains("git checkout"),
            "{}",
            error.message
        );
    }

    /// A file edited between the restore's read and the flush is not
    /// written over, and neither is any other file of the set.
    #[tokio::test]
    async fn a_file_changed_since_it_was_read_refuses_the_flush() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.lock"), "a before\n").unwrap();
        std::fs::write(root.join("b.lock"), "b edited meanwhile\n").unwrap();
        let before = tree(root);
        let read = |text: &'static str| Some(Some(text.as_bytes()));
        let files = |b_read| {
            vec![
                Pending {
                    read: read("a before\n"),
                    ..pending("a.lock", Some("a after\n"))
                },
                Pending {
                    read: b_read,
                    ..pending("b.lock", Some("b after\n"))
                },
            ]
        };
        let refused = preflight(root, files(read("b before\n"))).await.err();
        assert_eq!(
            refused.as_deref(),
            Some(
                "b.lock changed on disk while its restore was being worked out; nothing \
                 was written"
            )
        );
        // A file the restore read as absent that exists now is the same.
        let refused = preflight(root, files(Some(None))).await.err();
        assert!(refused.is_some_and(|why| why.contains("b.lock changed")));
        assert_eq!(tree(root), before);

        let checked = preflight(root, files(read("b edited meanwhile\n")))
            .await
            .unwrap();
        flush(&checked).await.unwrap();
        assert_eq!(tree(root)["b.lock"], "b after\n");
    }

    /// The restore's reads stay inside the repository root: a file outside
    /// it refuses (the restore stops) instead of reading as missing. So do
    /// its writes.
    #[tokio::test]
    async fn reads_outside_the_repository_refuse() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let root = repo.join("app");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(repo.join(".npmrc"), "x=1\n").unwrap();
        std::fs::write(tmp.path().join(".npmrc"), "x=2\n").unwrap();
        assert_eq!(
            read_rel(&root, "../.npmrc").await,
            Ok(Some("x=1\n".to_string()))
        );
        assert_eq!(read_rel(&root, "../missing").await, Ok(None));
        assert!(preflight(&root, vec![pending("../.npmrc", None)])
            .await
            .is_ok());
        let above = tmp.path().join(".npmrc");
        for rel in ["../../.npmrc".to_string(), above.display().to_string()] {
            let err = read_rel(&root, &rel).await.unwrap_err();
            assert!(err.contains("outside the repository root"), "{rel}: {err}");
            let err = preflight(&root, vec![pending(&rel, None)])
                .await
                .err()
                .unwrap();
            assert!(
                err.starts_with(&format!("write {rel}: "))
                    && err.contains("outside the repository root")
                    && err.ends_with("nothing was written"),
                "{rel}: {err}"
            );
        }
        // Without a checkout an absolute path (an upward lookup's, the
        // pnpm workspace root's settings) is read as before.
        std::fs::remove_dir(repo.join(".git")).unwrap();
        assert_eq!(
            read_rel(&root, &above.display().to_string()).await,
            Ok(Some("x=2\n".to_string()))
        );
    }
}
