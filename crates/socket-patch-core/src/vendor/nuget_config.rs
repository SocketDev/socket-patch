//! NuGet config file selection: the per-directory names NuGet probes and a
//! stat-only same-file check (the routing reader is `formats::nuget`).

// ── file selection ──

/// The per-directory config names NuGet probes, in its own order (NuGet
/// `Settings.OrderedSettingsFileNames`); the first present one is read.
pub(crate) const CONFIG_NAMES: [&str; 3] = ["nuget.config", "NuGet.config", "NuGet.Config"];

/// Whether `a` and `b` are one file (a case-insensitive filesystem's two
/// spellings of it). Unix compares device + inode (stat only: never opens
/// a FIFO planted under a config name); Windows compares volume serial +
/// file index, which needs a handle, so it first refuses (answers `false`
/// for) anything but two regular, non-reparse-point files: opening a
/// device, pipe or link planted under a config name could block discovery
/// indefinitely. Elsewhere `false`. The worst case of a `false` is a
/// duplicate file name in recognition, never a lost one.
pub(crate) async fn same_file(a: &std::path::Path, b: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(x), Ok(y)) = (tokio::fs::metadata(a).await, tokio::fs::metadata(b).await) {
            return x.dev() == y.dev() && x.ino() == y.ino();
        }
        false
    }
    #[cfg(windows)]
    {
        let (a, b) = (a.to_path_buf(), b.to_path_buf());
        tokio::task::spawn_blocking(move || {
            regular_file(&a) && regular_file(&b) && same_file::is_same_file(a, b).unwrap_or(false)
        })
        .await
        .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (a, b);
        false
    }
}

/// `path` is a regular file itself (`lstat`: a symlink or junction to one
/// is not), so opening it cannot reach a pipe or device.
#[cfg(windows)]
fn regular_file(path: &std::path::Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
}

// ── project walk ──

/// Directories the project walk never enters: build output, the restore's
/// `obj/`, a legacy `packages/` folder and JS dependencies (hidden ones —
/// `.git`, `.socket` — are skipped too). The NuGet crawler's restore scope
/// skips the same set.
const SKIPPED_DIRS: [&str; 4] = ["bin", "obj", "packages", "node_modules"];

/// Directories the walk lists before giving up.
const WALK_DIR_BUDGET: usize = 10_000;

/// A project file larger than this is not an MSBuild project anyone wrote.
const MAX_PROJECT_BYTES: u64 = 4 * 1024 * 1024;

/// Every MSBuild project file under `root` (root-relative, `/`-separated,
/// sorted) with its text. Symlinked directories are not followed. `Err`
/// when the walk cannot see the whole tree (an unreadable directory or
/// project file, or more than [`WALK_DIR_BUDGET`] directories): a lock the
/// walk missed would keep its upstream hash under the wired mapping.
pub(crate) fn project_files(root: &std::path::Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    let mut pending = vec![String::new()];
    let mut listed = 0usize;
    while let Some(rel) = pending.pop() {
        listed += 1;
        if listed > WALK_DIR_BUDGET {
            return Err(format!(
                "more than {WALK_DIR_BUDGET} directories under the project root"
            ));
        }
        let dir = if rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(&rel)
        };
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("unreadable {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("unreadable {}: {e}", dir.display()))?;
            let raw = entry.file_name();
            let Some(name) = raw.to_str().map(str::to_string) else {
                // A project (or a directory that may hold one) this walk
                // cannot name is a lock it would miss: fail closed.
                let lossy = raw.to_string_lossy();
                if crate::formats::nuget::lock::is_project_file(&lossy)
                    || entry.file_type().is_ok_and(|k| k.is_dir())
                {
                    return Err(format!(
                        "{} has a name that is not UTF-8",
                        dir.join(&raw).display()
                    ));
                }
                continue;
            };
            let child = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            let kind = entry
                .file_type()
                .map_err(|e| format!("unreadable {}: {e}", entry.path().display()))?;
            // A symlinked directory is not entered (it may lead outside the
            // tree, or back into it); a symlinked project file is read
            // through the link, like MSBuild opens it.
            let is_project = crate::formats::nuget::lock::is_project_file(&name)
                && (kind.is_file()
                    || (kind.is_symlink()
                        && std::fs::metadata(entry.path()).is_ok_and(|m| m.is_file())));
            if kind.is_dir() {
                if !name.starts_with('.') && !SKIPPED_DIRS.contains(&name.as_str()) {
                    pending.push(child);
                }
            } else if is_project {
                let path = entry.path();
                if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_PROJECT_BYTES) {
                    return Err(format!("{} is too large to read", path.display()));
                }
                let text = crate::utils::fs::read_regular_to_string_sync(&path)
                    .map_err(|e| format!("unreadable {}: {e}", path.display()))?;
                out.push((child, text));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// [`crate::formats::nuget::lock::governed_locks`] of the project tree on
/// disk under `root`.
pub(crate) fn governed_locks_on_disk(
    root: &std::path::Path,
) -> Result<crate::formats::nuget::lock::GovernedLocks, String> {
    let projects = project_files(root)?;
    Ok(crate::formats::nuget::lock::governed_locks(
        &projects,
        |rel| lock_present(root, rel),
    ))
}

/// [`governed_locks_on_disk`] through a [`ProjectView`]: every listing, read
/// and probe goes through the view, so a recording [`DiskSnapshot`] read
/// cache fingerprints them like its own reads (asking it for its raw root
/// would end its recording, and with it the re-scan's reuse of the
/// discovery it guards). Same walk rules as [`project_files`].
///
/// [`ProjectView`]: crate::vendor::lock_inventory::ProjectView
/// [`DiskSnapshot`]: crate::vendor::lock_inventory::DiskSnapshot
pub(crate) async fn governed_locks_in(
    view: &crate::vendor::lock_inventory::ProjectView<'_>,
) -> Result<crate::formats::nuget::lock::GovernedLocks, String> {
    use crate::formats::nuget::lock::{governed_locks, is_project_file};
    let mut projects: Vec<(String, String)> = Vec::new();
    let mut pending = vec![String::new()];
    let mut listed = 0usize;
    while let Some(rel) = pending.pop() {
        listed += 1;
        if listed > WALK_DIR_BUDGET {
            return Err(format!(
                "more than {WALK_DIR_BUDGET} directories under the project root"
            ));
        }
        let entries = view.list_dir_strict(&rel).await.map_err(|e| {
            format!(
                "unreadable {}: {e}",
                if rel.is_empty() { "." } else { &rel }
            )
        })?;
        for entry in entries {
            let child = if rel.is_empty() {
                entry.name.clone()
            } else {
                format!("{rel}/{}", entry.name)
            };
            if entry.is_dir {
                if !entry.name.starts_with('.') && !SKIPPED_DIRS.contains(&entry.name.as_str()) {
                    pending.push(child);
                }
            } else if is_project_file(&entry.name) {
                let text = view
                    .read_text(&child)
                    .await
                    .map_err(|e| format!("unreadable {child}: {e}"))?;
                if text.len() as u64 > MAX_PROJECT_BYTES {
                    return Err(format!("{child} is too large to read"));
                }
                projects.push((child, text));
            }
        }
    }
    projects.sort();
    // Which lock paths the discovery asks about, then their answers.
    let asked = std::cell::RefCell::new(Vec::<String>::new());
    governed_locks(&projects, |rel| {
        asked.borrow_mut().push(rel.to_string());
        false
    });
    let mut present = std::collections::BTreeSet::new();
    for rel in asked.into_inner() {
        if !present.contains(&rel) && view.exists_no_follow(&rel).await {
            present.insert(rel);
        }
    }
    Ok(governed_locks(&projects, |rel| present.contains(rel)))
}

/// Whether something other than a directory sits at `root/rel` (`lstat`):
/// a FIFO or link under a lock name is then read, and refused, by the
/// FIFO-safe reader rather than taken for an absent lock.
pub(crate) fn lock_present(root: &std::path::Path, rel: &str) -> bool {
    std::fs::symlink_metadata(root.join(rel)).is_ok_and(|m| !m.is_dir())
}

#[cfg(test)]
mod tests {
    use super::same_file;

    /// Two names of one regular file are one file; distinct files are not.
    #[tokio::test]
    async fn two_names_of_one_regular_file_are_the_same_file() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b, c) = (
            tmp.path().join("nuget.config"),
            tmp.path().join("NuGet.Config.link"),
            tmp.path().join("other.config"),
        );
        std::fs::write(&a, "<configuration/>").unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        std::fs::write(&c, "<configuration/>").unwrap();
        assert_eq!(same_file(&a, &b).await, cfg!(any(unix, windows)));
        assert!(!same_file(&a, &c).await);
        assert!(!same_file(&a, &tmp.path().join("missing")).await);
    }

    /// Windows opens a handle to compare identities, so it compares only
    /// regular files: a directory (like a pipe, a device or a link planted
    /// under a config name) is never opened and never the same file. Unix
    /// compares by `stat` alone and needs no such guard.
    #[tokio::test]
    async fn windows_never_opens_a_non_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nuget.config");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(same_file(&dir, &dir).await, cfg!(unix));
    }

    /// The walk reads a symlinked project file, never enters build output
    /// or hidden dirs, and finds projects at any depth.
    #[cfg(unix)]
    #[test]
    fn project_walk_follows_project_links_and_skips_output() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for dir in ["src/App/obj", "src/Lib", ".git", "shared"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        std::fs::write(root.join("src/App/App.csproj"), "<Project />").unwrap();
        std::fs::write(root.join("src/App/obj/Gen.csproj"), "<Project />").unwrap();
        std::fs::write(root.join(".git/X.csproj"), "<Project />").unwrap();
        std::fs::write(root.join("shared/Lib.csproj"), "<Project>lib</Project>").unwrap();
        std::os::unix::fs::symlink(
            root.join("shared/Lib.csproj"),
            root.join("src/Lib/Lib.csproj"),
        )
        .unwrap();
        let found: Vec<String> = super::project_files(root)
            .unwrap()
            .into_iter()
            .map(|(rel, _)| rel)
            .collect();
        assert_eq!(
            found,
            [
                "shared/Lib.csproj",
                "src/App/App.csproj",
                "src/Lib/Lib.csproj"
            ]
        );
    }

    /// The view walk fails closed on a directory name it cannot spell, like
    /// the disk walk: a member project under it would otherwise drop out of
    /// the governed locks. (Linux: APFS refuses non-UTF-8 names.)
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn view_walk_fails_closed_on_a_non_utf8_dir() {
        use std::os::unix::ffi::OsStrExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let odd = root.join(std::ffi::OsStr::from_bytes(b"m\xffember"));
        std::fs::create_dir_all(&odd).unwrap();
        std::fs::write(odd.join("M.csproj"), "<Project />").unwrap();
        std::fs::write(root.join("App.csproj"), "<Project />").unwrap();
        assert!(super::project_files(root).is_err());
        let view = crate::vendor::lock_inventory::ProjectView::Disk(root);
        assert!(super::governed_locks_in(&view).await.is_err());
    }
}
