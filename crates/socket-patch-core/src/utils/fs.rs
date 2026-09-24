//! Filesystem helpers shared by the ecosystem crawlers, plus the
//! crate-wide atomic file writer ([`atomic_write_bytes`]).
//!
//! Each crawler walks one or more package directories and decides
//! whether each entry is a candidate package. The operations that
//! all eight crawlers repeat are:
//!
//! - listing entries in a directory while tolerating permission /
//!   I/O errors (we treat an unreadable directory as "no entries");
//! - asking whether an entry is a directory while tolerating
//!   `file_type()` failures (we treat a stat error as "not a dir");
//! - asking whether an arbitrary path is a directory while tolerating
//!   stat errors ([`is_dir`], same "not a dir" fallback).
//!
//! Centralizing both keeps each crawler free of the
//! `match read_dir { Ok(rd) => rd, Err(_) => return … }` boilerplate
//! and gives integration tests a single function to drive when they
//! want to exercise the read_dir Err arm via `chmod 000`.
//!
//! Both helpers are async because the rest of the crawler code is —
//! they delegate to `tokio::fs`.
//!
//! # Symlinks
//!
//! `entry_is_dir` follows symlinks: ordinary entries answer from the
//! `DirEntry`'s cached file type (no extra stat), and symlink entries are
//! resolved through [`is_dir`] (follow-links `metadata()`), so a link to a
//! directory reports `true` — matching the historical behavior of the
//! crawlers (pnpm's content-addressed store relies on resolving symlinks
//! into `node_modules/.pnpm/*`).

use std::path::{Path, PathBuf};

use std::fs::FileType;
use tokio::fs::DirEntry;

/// List the immediate children of `path`.
///
/// Returns an empty vector if the directory cannot be read (does not
/// exist, permission denied, etc.). If a later `next_entry` call
/// fails mid-iteration, the entries gathered so far are returned and
/// iteration stops. The crawlers treat all of these the same way:
/// surface whatever the readable portion of the subtree yields, but
/// don't abort the whole crawl.
pub(crate) async fn list_dir_entries(path: &Path) -> Vec<DirEntry> {
    let mut entries = match tokio::fs::read_dir(path).await {
        Ok(rd) => rd,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        out.push(entry);
    }
    out
}

/// Resolve whether `entry` is a directory, following symlinks.
///
/// Returns `false` if the stat fails (broken symlink, permission
/// error, etc.) — the caller then skips the entry rather than
/// aborting the walk.
///
/// `DirEntry::metadata()` does **not** traverse symlinks (it behaves
/// like `symlink_metadata`), so a symlink pointing at a directory
/// would wrongly report `false`. To honor the documented
/// symlink-following contract — which crawlers like deno/python/ruby
/// rely on for symlinked package directories — symlinks are resolved through
/// [`is_dir`]. Ordinary entries use their cached file type, avoiding an extra
/// stat for every directory visited by a crawler.
pub(crate) async fn entry_is_dir(entry: &DirEntry) -> bool {
    match entry.file_type().await {
        Ok(kind) if kind.is_symlink() => is_dir(&entry.path()).await,
        Ok(kind) => kind.is_dir(),
        Err(_) => false,
    }
}

/// Check whether `path` is a directory, following symlinks.
///
/// Returns `false` if the stat fails (missing path, broken symlink,
/// permission error, etc.) — the crawlers probe candidate package
/// roots and treat "can't stat" the same as "not there". The
/// `Path`-taking counterpart of [`entry_is_dir`]; previously
/// copy-pasted into every crawler.
pub(crate) async fn is_dir(path: &Path) -> bool {
    tokio::fs::metadata(path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

/// Check whether `path` is a regular file, following symlinks.
///
/// Returns `false` if the stat fails (missing path, broken symlink,
/// permission error, etc.) — the file-shaped sibling of [`is_dir`],
/// with the same "can't stat means not there" contract.
pub(crate) async fn is_file(path: &Path) -> bool {
    tokio::fs::metadata(path)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false)
}

/// Open `path` read-only, requiring a regular file.
///
/// Returns the open handle plus its `fstat` metadata. Deriving the
/// metadata from the open descriptor — rather than `stat`-ing the path
/// separately — means the size and any bytes subsequently read cannot
/// come from different inodes, even if the path is renamed/replaced
/// concurrently (the patch engine reads files an attacker may swap at
/// any moment).
///
/// On Unix the open itself is non-blocking (`O_NONBLOCK`): a plain
/// `open(2)` of a FIFO with `O_RDONLY` waits for a writer that may
/// never come, which would hang the patch engine forever before the
/// regular-file guard below ever runs. `O_NONBLOCK` has no effect on
/// regular-file reads; the handle-based `is_file` check then rejects
/// FIFOs/devices/directories with `InvalidInput` instead of reading
/// them (on some platforms a directory reads as zero bytes, which
/// would otherwise be silently hashed as the empty blob).
///
/// One blocking-pool hop: the open + fstat run together in
/// [`open_regular_file_sync`], the single copy of the guard.
pub(crate) async fn open_regular_file(
    path: &Path,
) -> std::io::Result<(tokio::fs::File, std::fs::Metadata)> {
    let path = path.to_path_buf();
    let (file, metadata) = asyncify(move || open_regular_file_sync(&path)).await?;
    Ok((tokio::fs::File::from_std(file), metadata))
}

/// Read a regular file to a `String` through the FIFO-safe opener
/// (non-blocking open, fstat regular-file check on the opened descriptor)
/// that the ecosystem modules had each re-declared privately. Follows a
/// symlink to a regular file; a FIFO, directory or socket fails fast with
/// `InvalidInput` instead of wedging in open(2). Open + read are one
/// blocking-pool hop (like tokio's own `fs::read_to_string`). `pub` so the
/// CLI crate's raw `read_to_string` sites can share it.
pub async fn read_regular_to_string(path: &Path) -> std::io::Result<String> {
    let path = path.to_path_buf();
    asyncify(move || read_regular_to_string_sync(&path)).await
}

/// Read a binary regular file through the same FIFO-safe opener as text
/// lockfiles. A malformed or non-regular lockfile never blocks discovery.
pub async fn read_regular_to_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
    let path = path.to_path_buf();
    asyncify(move || read_regular_to_bytes_sync(&path)).await
}

/// Run one blocking filesystem operation on tokio's blocking pool — the
/// same shape as tokio's internal `asyncify`, including its mapping of a
/// panicked/cancelled task to an `io::Error`.
async fn asyncify<T, F>(f: F) -> std::io::Result<T>
where
    F: FnOnce() -> std::io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::other("background task failed")),
    }
}

/// True when `path` ITSELF is a symbolic link (lstat; the link target is not
/// consulted, so a dangling link is still `true`). Writers that stage a
/// replacement next to `path` and rename over it would replace the link with
/// a regular file (leaving the target stale) — they use this to refuse
/// fail-closed before any write, mirroring the hosted replay guard.
pub async fn is_symlink(path: &Path) -> bool {
    tokio::fs::symlink_metadata(path)
        .await
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

/// Blocking twin of [`read_regular_to_string`] for the few synchronous
/// helpers that read project files (the hosted flow's pnpm-workspace probe):
/// same non-blocking open + fstat regular-file check, so a FIFO planted at
/// the path fails fast with `InvalidInput` instead of wedging in open(2).
/// Every other error keeps its kind (`NotFound`, `PermissionDenied`,
/// `InvalidData` from the UTF-8 decode) so callers can classify it.
pub fn read_regular_to_string_sync(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;

    let (mut file, metadata) = open_regular_file_sync(path)?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content)?;
    Ok(content)
}

/// Raw-bytes twin of [`read_regular_to_string_sync`] for BINARY project
/// files the CLI captures verbatim (the hosted flow's pre-migration
/// `bun.lockb` snapshot): same non-blocking open + fstat regular-file check,
/// so a FIFO squatting the path fails fast with `InvalidInput` instead of
/// wedging in open(2) — and the caller can refuse BEFORE spawning a tool
/// that would block on the same FIFO. No UTF-8 decode, so a binary lock
/// never fails with `InvalidData`; every other error keeps its kind.
pub fn read_regular_to_bytes_sync(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let (mut file, metadata) = open_regular_file_sync(path)?;
    let mut content = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut content)?;
    Ok(content)
}

/// The one regular-file guard: `O_NONBLOCK` open on Unix, then the
/// handle-based regular-file check. The async [`open_regular_file`] and every
/// reader above run this on the blocking pool; `pub(crate)` for the few
/// synchronous callers that must keep the handle (a `zip::ZipArchive` over a
/// committed wheel) rather than read it whole.
pub(crate) fn open_regular_file_sync(
    path: &Path,
) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path)?;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok((file, metadata))
}

/// The first of `rels` (root-relative, in the caller's order) that is a
/// symbolic link — see [`is_symlink`]. Rewriters that are about to
/// stage-and-rename over a whole file set use this to refuse the entire set
/// fail-closed before the first write; a missing path (a file the rewrite
/// would CREATE) is not a link.
pub async fn first_symlink<'a>(
    root: &Path,
    rels: impl IntoIterator<Item = &'a str>,
) -> Option<&'a str> {
    for rel in rels {
        if is_symlink(&root.join(rel)).await {
            return Some(rel);
        }
    }
    None
}

/// Return the raw `FileType` for `entry`, swallowing stat errors.
///
/// Use this instead of `entry_is_dir` when the caller needs to
/// distinguish real directories from symlinks (e.g. npm's pnpm
/// support: symlinks point into the content-addressed store and must
/// be treated as scannable-but-non-recurseable). The returned
/// `FileType` is the symlink-aware kind from `entry.file_type()`,
/// not the resolved-target kind from `metadata()`.
pub(crate) async fn entry_file_type(entry: &DirEntry) -> Option<FileType> {
    entry.file_type().await.ok()
}

/// Resolve the user's home directory: `HOME`, then `USERPROFILE`
/// (Windows), then a literal `"~"` — a harmless non-existent path so
/// downstream joins probe nothing rather than panic. A set-but-empty
/// variable counts as unset: honoring `""` would turn every
/// `home_dir().join(…)` probe into a CWD-relative path, pointing the
/// crawlers at directories inside the user's project. The shared
/// fallback chain for every crawler that scans well-known per-user
/// package roots (`~/.cargo`, `~/.m2`, `~/.nuget`, …) and for
/// telemetry's home-dir redaction; previously copy-pasted into each.
/// The go/composer crawlers deliberately use a stricter
/// no-home-means-no-path chain instead.
pub(crate) fn home_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var("USERPROFILE").ok().filter(|h| !h.is_empty()))
        .unwrap_or_else(|| "~".to_string());
    PathBuf::from(home)
}

/// Resolve `.`/`..` without touching the filesystem, so a path can be
/// containment-checked BEFORE it is opened (a canonicalizing check would
/// have to stat the very path being validated, and would fail on
/// not-yet-existing directories). Returns `None` when `..` pops above the
/// path's own root — nothing legitimate does that, so it fails closed.
///
/// Symlinks are not resolved: a symlink INSIDE the project pointing out
/// of it is a pre-existing trust decision of the project's own tree, the
/// same assumption the rest of the crawler layer makes.
///
/// Shared by the composer crawler's `install-path` containment guard and
/// the ruby crawler's config-sourced `BUNDLE_PATH` containment guard.
pub(crate) fn normalize_lexically(path: &Path) -> Option<PathBuf> {
    use std::path::Component;

    let mut out = PathBuf::new();
    let mut depth = 0usize;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if depth == 0 {
                    return None;
                }
                out.pop();
                depth -= 1;
            }
            Component::Normal(segment) => {
                out.push(segment);
                depth += 1;
            }
        }
    }
    Some(out)
}

/// Atomically commit `content` to `path` via stage + fsync + rename.
///
/// The single shared implementation of the hardened-writer pattern used for
/// every user-owned file socket-patch edits (`go.mod`, `package.json`,
/// `pyproject.toml`, lockfiles, `.socket/vendor/state.json`, …). A bare
/// `fs::write` truncates the target before writing, so a crash, power loss, or
/// `ENOSPC` mid-write would leave the file torn or empty. Instead we stage a
/// sibling file, fsync it, then rename over the target (atomic on the same
/// filesystem), so a reader or recovering process only ever sees the complete
/// old or the complete new bytes.
///
/// **Copy-on-write guarantee** (the single source of truth the patch engine's
/// comments point at): `rename(2)` replaces only the *directory entry*, never
/// the bytes behind the old inode. A hardlinked sibling — pnpm's
/// content-addressable store, the bun / uv caches, Go's module cache — keeps
/// the old inode and its old content untouched, and a symlink sitting at the
/// destination is replaced *as a link* by a private regular file, never
/// written through to its target. No separate hardlink-break step is needed;
/// the write path is CoW-safe by construction.
pub(crate) async fn atomic_write_bytes(path: &Path, content: &[u8]) -> std::io::Result<()> {
    atomic_write_bytes_as(path, content, None).await
}

/// [`atomic_write_bytes`], but the new inode keeps the destination's existing
/// permission bits (when the destination exists).
///
/// The rename swaps in a fresh stage inode created with umask defaults, so the
/// plain writer resets a user-owned file's mode — a 0600 private package.json
/// silently becomes 0644, a 0664 group-writable one locks the group out. Use
/// this variant for files the *user* owns and we merely edit (package.json,
/// Gemfile, …), matching npm's write-file-atomic. The patch engine keeps the
/// plain writer: `restore_file_permissions` re-applies pre-patch mode + uid/gid
/// itself after the rename. `pub` (not `pub(crate)`): the CLI's hosted
/// redirect writes user-owned lockfiles through it too.
pub async fn atomic_write_bytes_preserving_mode(
    path: &Path,
    content: &[u8],
) -> std::io::Result<()> {
    let perms = tokio::fs::metadata(path)
        .await
        .ok()
        .map(|m| m.permissions());
    atomic_write_bytes_as(path, content, perms).await
}

/// Create the stage file for [`atomic_write_bytes_as`]. On Unix, when the
/// destination's permissions are being preserved, the stage is CREATED with
/// those bits (narrowed further by the umask) rather than the 0666 & ~umask
/// default: the full new content — a `.npmrc` `_authToken`, a 0600 private
/// manifest — is written and fsynced into the stage before the final
/// chmod, so a default-mode stage would expose it to other local users for
/// the whole write, and leave a world-readable copy behind if the process
/// is killed before the rename.
async fn create_stage(
    stage: &Path,
    perms: Option<&std::fs::Permissions>,
) -> std::io::Result<tokio::fs::File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if let Some(p) = perms {
        use std::os::unix::fs::PermissionsExt;
        // Permission bits only (never setuid/setgid/sticky on a stage). A
        // read-only mode (0400) is fine: O_CREAT still hands back a
        // writable descriptor for the file it just created.
        options.mode(p.mode() & 0o777);
    }
    #[cfg(not(unix))]
    let _ = perms;
    options.open(stage).await
}

async fn atomic_write_bytes_as(
    path: &Path,
    content: &[u8],
    perms: Option<std::fs::Permissions>,
) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let stage = parent.join(format!(".socket-stage-{}-{}", stem, uuid::Uuid::new_v4()));

    // `create_new` failing leaves no stage to clean up; every step after it
    // does, so they share one error arm.
    let file = create_stage(&stage, perms.as_ref()).await?;
    if let Err(e) = commit_stage(file, content, perms, &stage, path).await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }

    // The rename only updated the parent directory entry; fsync the directory
    // so the rename itself survives a crash. Best-effort, Unix only.
    #[cfg(unix)]
    {
        if let Ok(dir) = tokio::fs::File::open(parent).await {
            let _ = dir.sync_all().await;
        }
    }

    Ok(())
}

/// Write, flush, fsync, (re-mode) and close the stage, then rename it over
/// `path`. Takes the handle by value so it is closed before the rename
/// (Windows refuses to rename an open file) and before the caller's
/// error-path unlink of the stage.
async fn commit_stage(
    mut file: tokio::fs::File,
    content: &[u8],
    perms: Option<std::fs::Permissions>,
    stage: &Path,
    path: &Path,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    file.write_all(content).await?;
    // `write_all` only buffers into tokio's background writer, and
    // `sync_all` stores an in-flight write error back into the handle
    // instead of returning it — this flush is the only point where a
    // failed stage write (ENOSPC, EIO, quota) actually surfaces. Without
    // it the truncated stage would be renamed over the intact target.
    file.flush().await?;
    file.sync_all().await?;
    // Set the preserved mode on the stage *before* the rename so the file
    // never appears at the destination with the wrong bits, even briefly.
    // The content is already written through the open handle, so a
    // restrictive mode (0400, 0000) cannot fail the write.
    if let Some(p) = perms {
        file.set_permissions(p).await?;
    }
    drop(file);
    tokio::fs::rename(stage, path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn list_dir_entries_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let entries = list_dir_entries(tmp.path()).await;
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn list_dir_entries_missing_path_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let entries = list_dir_entries(&tmp.path().join("does-not-exist")).await;
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn list_dir_entries_returns_children() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::create_dir(tmp.path().join("a")).await.unwrap();
        tokio::fs::create_dir(tmp.path().join("b")).await.unwrap();
        tokio::fs::write(tmp.path().join("c.txt"), b"")
            .await
            .unwrap();
        let mut names: Vec<String> = list_dir_entries(tmp.path())
            .await
            .into_iter()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        assert_eq!(names, vec!["a", "b", "c.txt"]);
    }

    #[tokio::test]
    async fn entry_is_dir_distinguishes_dir_and_file() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::create_dir(tmp.path().join("d")).await.unwrap();
        tokio::fs::write(tmp.path().join("f"), b"x").await.unwrap();
        let entries = list_dir_entries(tmp.path()).await;
        for entry in entries {
            let name = entry.file_name().to_string_lossy().to_string();
            let is_dir = entry_is_dir(&entry).await;
            match name.as_str() {
                "d" => assert!(is_dir),
                "f" => assert!(!is_dir),
                other => panic!("unexpected entry: {other}"),
            }
        }
    }

    /// Regression: `entry_is_dir` must follow symlinks. A symlink that
    /// points at a directory has to report `true`, otherwise crawlers
    /// silently skip symlinked package directories (pnpm stores,
    /// virtualenvs, vendored gems, etc.). `DirEntry::metadata()` does
    /// NOT traverse symlinks, so this guards against regressing back to
    /// it.
    #[cfg(unix)]
    #[tokio::test]
    async fn entry_is_dir_follows_symlink_to_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("real_dir");
        tokio::fs::create_dir(&target).await.unwrap();
        tokio::fs::symlink(&target, tmp.path().join("link_to_dir"))
            .await
            .unwrap();

        let entries = list_dir_entries(tmp.path()).await;
        let link = entries
            .into_iter()
            .find(|e| e.file_name().to_string_lossy() == "link_to_dir")
            .expect("symlink entry present");
        assert!(
            entry_is_dir(&link).await,
            "symlink pointing at a directory must resolve to is_dir = true"
        );
    }

    /// A symlink pointing at a regular file must report `false`, and a
    /// broken/dangling symlink must report `false` rather than panic.
    #[cfg(unix)]
    #[tokio::test]
    async fn entry_is_dir_symlink_to_file_and_broken_link() {
        let tmp = tempfile::tempdir().unwrap();
        let file_target = tmp.path().join("real_file");
        tokio::fs::write(&file_target, b"x").await.unwrap();
        tokio::fs::symlink(&file_target, tmp.path().join("link_to_file"))
            .await
            .unwrap();
        tokio::fs::symlink(
            tmp.path().join("missing_target"),
            tmp.path().join("dangling"),
        )
        .await
        .unwrap();

        for entry in list_dir_entries(tmp.path()).await {
            let name = entry.file_name().to_string_lossy().to_string();
            let is_dir = entry_is_dir(&entry).await;
            match name.as_str() {
                "real_file" | "link_to_file" | "dangling" => {
                    assert!(!is_dir, "{name} should not be a dir");
                }
                other => panic!("unexpected entry: {other}"),
            }
        }
    }

    /// `is_dir` reports directories, and falls back to `false` for
    /// files, missing paths, and (via `metadata`'s symlink-following)
    /// resolves links to their target kind.
    #[tokio::test]
    async fn is_dir_dir_file_and_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        tokio::fs::create_dir(&dir).await.unwrap();
        let file = tmp.path().join("f");
        tokio::fs::write(&file, b"x").await.unwrap();

        assert!(is_dir(&dir).await);
        assert!(!is_dir(&file).await);
        assert!(!is_dir(&tmp.path().join("missing")).await);
    }

    /// Regression: `list_dir_entries` must hit the `read_dir` Err arm
    /// when handed a path that is a regular file (not a directory) and
    /// return an empty vec rather than panic. Crawlers routinely probe
    /// candidate paths that may turn out to be files (e.g. a stray
    /// `node_modules` that is actually a file), and rely on this
    /// fail-soft behavior.
    #[tokio::test]
    async fn list_dir_entries_on_a_file_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("not_a_dir");
        tokio::fs::write(&file, b"x").await.unwrap();
        let entries = list_dir_entries(&file).await;
        assert!(
            entries.is_empty(),
            "read_dir on a regular file must yield no entries"
        );
    }

    /// Regression: `entry_is_dir` must resolve a *chain* of symlinks,
    /// not just a single hop. `link_a -> link_b -> real_dir` has to
    /// report `true`; otherwise a crawler walking through indirection
    /// (common in pnpm/virtualenv layouts) would silently skip the
    /// package directory.
    #[cfg(unix)]
    #[tokio::test]
    async fn entry_is_dir_follows_symlink_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real_dir");
        tokio::fs::create_dir(&real_dir).await.unwrap();
        let link_b = tmp.path().join("link_b");
        tokio::fs::symlink(&real_dir, &link_b).await.unwrap();
        // link_a points at link_b, which points at real_dir.
        tokio::fs::symlink(&link_b, tmp.path().join("link_a"))
            .await
            .unwrap();

        let link = list_dir_entries(tmp.path())
            .await
            .into_iter()
            .find(|e| e.file_name().to_string_lossy() == "link_a")
            .expect("chained symlink entry present");
        assert!(
            entry_is_dir(&link).await,
            "a chain of symlinks ending at a directory must resolve to is_dir = true"
        );
    }

    /// `entry_file_type` reports the plain kinds (dir / file) faithfully
    /// when no symlink is involved — it only diverges from
    /// `entry_is_dir` on links.
    #[tokio::test]
    async fn entry_file_type_reports_plain_dir_and_file() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::create_dir(tmp.path().join("d")).await.unwrap();
        tokio::fs::write(tmp.path().join("f"), b"x").await.unwrap();
        for entry in list_dir_entries(tmp.path()).await {
            let name = entry.file_name().to_string_lossy().to_string();
            let ft = entry_file_type(&entry).await.expect("file_type available");
            match name.as_str() {
                "d" => {
                    assert!(ft.is_dir() && !ft.is_symlink(), "d is a plain dir");
                }
                "f" => {
                    assert!(ft.is_file() && !ft.is_symlink(), "f is a plain file");
                }
                other => panic!("unexpected entry: {other}"),
            }
        }
    }

    /// The preserving writer re-applies the destination's mode to the new
    /// inode (0744's exec bit cannot come from a 0666-based create, so this
    /// is red under any umask if preservation regresses), while a missing
    /// destination is simply created with umask defaults.
    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_write_preserving_mode_keeps_dest_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("f");
        tokio::fs::write(&path, b"old").await.unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o744)).unwrap();

        atomic_write_bytes_preserving_mode(&path, b"new")
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), b"new");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o744, "existing mode must survive the rename");

        let fresh = tmp.path().join("fresh");
        atomic_write_bytes_preserving_mode(&fresh, b"x")
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(&fresh).await.unwrap(), b"x");
    }

    /// The stage of a mode-preserving write is CREATED with the preserved
    /// bits, never the 0666 & ~umask default: the full new content (a
    /// `.npmrc` auth token) is written and fsynced into it before the final
    /// chmod, and a killed process leaves it behind. Red before the fix:
    /// the 0600 destination's stage came out 0644 (umask 022).
    #[cfg(unix)]
    #[tokio::test]
    async fn preserving_stage_is_created_with_the_destination_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        for mode in [0o600, 0o400, 0o640] {
            let stage = tmp.path().join(format!(".socket-stage-npmrc-{mode:o}"));
            let perms = std::fs::Permissions::from_mode(mode);
            let mut file = create_stage(&stage, Some(&perms)).await.unwrap();
            use tokio::io::AsyncWriteExt;
            // A read-only preserved mode still yields a writable stage fd.
            file.write_all(b"//r/:_authToken=secret\n").await.unwrap();
            file.flush().await.unwrap();
            let got = std::fs::metadata(&stage).unwrap().permissions().mode() & 0o777;
            assert_eq!(got & !mode, 0, "stage {got:o} must not exceed {mode:o}");
            assert_eq!(
                got & 0o077 & !mode,
                0,
                "no group/other bits beyond {mode:o}"
            );
        }
        // No preserved mode: the plain umask default, as before.
        let plain = tmp.path().join(".socket-stage-plain");
        create_stage(&plain, None).await.unwrap();
        assert!(plain.is_file());
    }

    /// The post-rename parent-directory fsync is best-effort: when the
    /// parent can be traversed and written but not opened for read
    /// (mode 0o333 — the stage create, the stage write, and the rename
    /// all still work), `File::open(parent)` fails and the miss arm must
    /// swallow that failure. An otherwise fully-committed write has to
    /// return Ok, not surface the fsync-open error.
    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_write_tolerates_fsync_unreadable_parent_dir() {
        use std::os::unix::fs::PermissionsExt;

        // Root bypasses directory permission bits entirely, so the 0o333
        // parent would still open for read and the miss arm would never run.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, directory perms are not enforced");
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("d");
        tokio::fs::create_dir(&dir).await.unwrap();
        let path = dir.join("f");
        tokio::fs::write(&path, b"old").await.unwrap();

        // write+exec only: creating the stage, writing it, and renaming it
        // over the target all succeed, but open(dir, O_RDONLY) for the
        // directory fsync fails with EACCES.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o333)).unwrap();

        // Anti-vacuity: prove the fsync's open really is refused under
        // 0o333 — otherwise this test would pass without ever exercising
        // the miss arm it exists to pin.
        assert!(
            std::fs::File::open(&dir).is_err(),
            "0o333 must make the parent unopenable for read on this host"
        );

        let res = atomic_write_bytes(&path, b"new").await;

        // Restore before asserting (and before TempDir drop) so the
        // read-backs and the tempdir cleanup can list the directory again.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            res.is_ok(),
            "an fsync-inaccessible parent must not fail a committed write: {res:?}"
        );
        assert_eq!(
            tokio::fs::read(&path).await.unwrap(),
            b"new",
            "the rename must have committed the new bytes"
        );
        let leftovers: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "f")
            .collect();
        assert!(
            leftovers.is_empty(),
            "no stage files may leak on the success path, found: {leftovers:?}"
        );
    }

    /// Regression: a set-but-empty `HOME` (stripped CI/container/sudo
    /// environments) must be treated as unset, exactly like the documented
    /// no-home fallback. Honoring `""` made `home_dir()` return an empty
    /// `PathBuf`, so every `home_dir().join(".cargo")`-style probe became a
    /// CWD-relative path and the crawlers scanned directories inside the
    /// user's project as if they were the per-user package roots.
    #[test]
    #[serial_test::serial]
    fn home_dir_treats_empty_home_as_unset() {
        let prev_home = std::env::var("HOME").ok();
        let prev_profile = std::env::var("USERPROFILE").ok();
        std::env::set_var("HOME", "");
        std::env::set_var("USERPROFILE", "");
        let home = home_dir();
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match prev_profile {
            Some(v) => std::env::set_var("USERPROFILE", v),
            None => std::env::remove_var("USERPROFILE"),
        }
        assert_eq!(
            home,
            PathBuf::from("~"),
            "empty HOME/USERPROFILE must fall back to the harmless `~` sentinel"
        );
    }

    /// Regression: a failed stage write must fail the commit and leave the
    /// destination untouched. tokio's `File` runs writes on a background
    /// blocking task: `write_all` returns once the bytes are buffered (one
    /// chunk up to 2 MiB), and `sync_all`'s `complete_inflight` *stores* a
    /// background-write error back into the handle instead of returning it
    /// (tokio 1.50 `poll_complete_inflight`), after which the fsync of the
    /// never-written file succeeds. Without an explicit `flush()`, an
    /// ENOSPC/EIO/EFBIG during the stage write was therefore swallowed and
    /// the truncated stage renamed over the intact destination — silent
    /// data loss in the exact scenario the atomic writer exists to prevent.
    /// Reproduced by capping `RLIMIT_FSIZE` so the stage write dies at
    /// 256 KiB of a 1 MiB payload.
    ///
    /// The capped body runs in a CHILD PROCESS. `RLIMIT_FSIZE` (and the
    /// ignored `SIGXFSZ`) are process-wide, and `#[serial]` only serializes
    /// against other `#[serial]` tests — with the cap active in THIS
    /// process, every concurrently-running sibling test (and the libtest
    /// harness itself) that wrote a file larger than 256 KiB died with
    /// EFBIG, aborting the whole binary: observed as `cargo test
    /// --workspace` exiting 101 with ZERO failed tests and `io error when
    /// listing tests: … FileTooLarge`. The parent re-execs this test binary
    /// filtered to exactly this test with a marker env var selecting the
    /// capped body, so the blast radius is one single-test process. The
    /// payload/cap sizes cannot simply be raised out of siblings' range
    /// instead: the payload must fit tokio's single 2 MiB write chunk or
    /// `write_all` returns the error directly and the swallowed-`sync_all`
    /// path this test exists to pin is never exercised.
    ///
    /// A second case in the same capped child then triggers that direct
    /// `write_all` error on purpose — a 3 MiB payload exceeds the single
    /// 2 MiB chunk, so `write_all` has to wait on the in-flight first chunk
    /// and returns its EFBIG synchronously — pinning the `write_all`
    /// cleanup arm (remove stage, propagate error) as well.
    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_write_failed_stage_write_errors_and_keeps_target() {
        const CHILD_ENV: &str = "SOCKET_PATCH_CORE_TEST_FSIZE_CHILD";
        const TEST_NAME: &str =
            "utils::fs::tests::atomic_write_failed_stage_write_errors_and_keeps_target";
        if std::env::var_os(CHILD_ENV).is_none() {
            let exe = std::env::current_exe().expect("test binary path must resolve");
            let output = std::process::Command::new(exe)
                .args([TEST_NAME, "--exact", "--test-threads=1", "--nocapture"])
                .env(CHILD_ENV, "1")
                .output()
                .expect("the capped child test process must spawn");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "the capped child run failed:\nstdout:\n{stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr),
            );
            // Anti-vacuity: a renamed test would make the `--exact` filter
            // match nothing and the child exit 0 having proven nothing.
            assert!(
                stdout.contains("1 passed"),
                "the child run must execute exactly this test — filter drift \
                 after a rename? child stdout:\n{stdout}"
            );
            return;
        }

        struct FsizeGuard {
            prev: libc::rlimit,
            prev_handler: libc::sighandler_t,
        }
        impl Drop for FsizeGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::setrlimit(libc::RLIMIT_FSIZE, &self.prev);
                    libc::signal(libc::SIGXFSZ, self.prev_handler);
                }
            }
        }

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("target.json");
        tokio::fs::write(&path, b"old").await.unwrap();

        // Exceeding RLIMIT_FSIZE delivers SIGXFSZ (default: kill); ignore it
        // so the write fails with EFBIG instead. Guard restores both.
        let guard = unsafe {
            let mut prev = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut prev), 0);
            let prev_handler = libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let capped = libc::rlimit {
                rlim_cur: 256 * 1024,
                rlim_max: prev.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &capped), 0);
            FsizeGuard { prev, prev_handler }
        };

        // 1 MiB fits tokio's 2 MiB write buffer in one chunk, so `write_all`
        // buffers it and returns Ok before the background write hits EFBIG.
        let big = vec![0xABu8; 1024 * 1024];
        let res = atomic_write_bytes(&path, &big).await;

        // Second case, same capped child: 3 MiB exceeds tokio's single
        // 2 MiB write chunk, so `write_all` must wait on the in-flight
        // first chunk and returns its EFBIG directly — exercising the
        // `write_all` cleanup arm (remove stage, propagate error) instead
        // of the flush arm the 1 MiB case pins above.
        let res_write_all = atomic_write_bytes(&path, &vec![0xCDu8; 3 * 1024 * 1024]).await;
        drop(guard);

        assert!(
            res.is_err(),
            "a failed stage write must surface as an error"
        );
        assert!(
            res_write_all.is_err(),
            "a stage write failing inside write_all itself must surface as an error"
        );
        assert_eq!(
            tokio::fs::read(&path).await.unwrap(),
            b"old",
            "the destination must keep its old bytes when the stage write fails"
        );
        let leftovers: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "target.json")
            .collect();
        assert!(
            leftovers.is_empty(),
            "the failed stage file must be removed, found: {leftovers:?}"
        );
    }

    /// `entry_file_type` is the symlink-aware counterpart: it reports
    /// the link itself (`is_symlink`), never the resolved target.
    #[cfg(unix)]
    #[tokio::test]
    async fn entry_file_type_does_not_follow_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("real_dir");
        tokio::fs::create_dir(&target).await.unwrap();
        tokio::fs::symlink(&target, tmp.path().join("link_to_dir"))
            .await
            .unwrap();

        let entries = list_dir_entries(tmp.path()).await;
        let link = entries
            .into_iter()
            .find(|e| e.file_name().to_string_lossy() == "link_to_dir")
            .expect("symlink entry present");
        let ft = entry_file_type(&link).await.expect("file_type available");
        assert!(
            ft.is_symlink(),
            "entry_file_type must surface the link kind"
        );
        assert!(!ft.is_dir(), "entry_file_type must not resolve the target");
    }

    /// `read_regular_to_string_sync` keeps the error kinds its callers
    /// classify on (absent vs. unreadable vs. undecodable) and follows a
    /// symlink to a regular file like the async reader.
    #[test]
    fn read_regular_to_string_sync_classifies_like_the_async_reader() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = read_regular_to_string_sync(&tmp.path().join("absent")).unwrap_err();
        assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
        let dir = read_regular_to_string_sync(tmp.path()).unwrap_err();
        // Unix opens a directory read-only and the fstat check classifies it;
        // Windows' CreateFileW refuses the open outright with
        // ERROR_ACCESS_DENIED (PermissionDenied). Either way it is an error
        // the callers skip, never a wedge.
        #[cfg(unix)]
        assert_eq!(dir.kind(), std::io::ErrorKind::InvalidInput, "{dir}");
        #[cfg(not(unix))]
        assert!(
            matches!(
                dir.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::PermissionDenied
            ),
            "{dir}"
        );
        let file = tmp.path().join("ok.txt");
        std::fs::write(&file, "packages:\n").unwrap();
        assert_eq!(read_regular_to_string_sync(&file).unwrap(), "packages:\n");
        let invalid = tmp.path().join("bad.txt");
        std::fs::write(&invalid, b"\xff\xfe").unwrap();
        assert_eq!(
            read_regular_to_string_sync(&invalid).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        #[cfg(unix)]
        {
            let link = tmp.path().join("link.txt");
            std::os::unix::fs::symlink("ok.txt", &link).unwrap();
            assert_eq!(read_regular_to_string_sync(&link).unwrap(), "packages:\n");
        }
    }

    /// A FIFO at the path must fail fast (`InvalidInput`), never block in
    /// open(2) waiting for a writer.
    #[cfg(unix)]
    #[test]
    fn read_regular_to_string_sync_rejects_a_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("pnpm-workspace.yaml");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let probe = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_regular_to_string_sync(&probe).map_err(|e| e.kind()));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(result) => assert_eq!(result, Err(std::io::ErrorKind::InvalidInput)),
            Err(_) => {
                // Release the wedged opener so the suite can fail cleanly.
                let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
                panic!("the sync reader wedged in open(2) on a FIFO");
            }
        }
    }

    /// The bytes twin returns a binary file VERBATIM (no UTF-8 decode, so
    /// bytes that would be `InvalidData` for the string reader are fine),
    /// keeps `NotFound` for an absent path and classifies a directory like
    /// the string reader.
    #[test]
    fn read_regular_to_bytes_sync_returns_binary_verbatim_and_classifies_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = read_regular_to_bytes_sync(&tmp.path().join("absent")).unwrap_err();
        assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
        let dir = read_regular_to_bytes_sync(tmp.path()).unwrap_err();
        #[cfg(unix)]
        assert_eq!(dir.kind(), std::io::ErrorKind::InvalidInput, "{dir}");
        #[cfg(not(unix))]
        assert!(
            matches!(
                dir.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::PermissionDenied
            ),
            "{dir}"
        );
        let lockb = tmp.path().join("bun.lockb");
        let bytes: Vec<u8> = vec![0x00, 0xff, 0xfe, b'b', b'u', b'n', 0x00, 0x80];
        std::fs::write(&lockb, &bytes).unwrap();
        assert_eq!(read_regular_to_bytes_sync(&lockb).unwrap(), bytes);
        #[cfg(unix)]
        {
            let link = tmp.path().join("link.lockb");
            std::os::unix::fs::symlink("bun.lockb", &link).unwrap();
            assert_eq!(read_regular_to_bytes_sync(&link).unwrap(), bytes);
        }
    }

    /// A FIFO squatting `bun.lockb` must fail fast (`InvalidInput`), never
    /// block in open(2): binary discovery and patching must reject a
    /// non-regular lockfile without waiting for another process to write it.
    #[cfg(unix)]
    #[test]
    fn read_regular_to_bytes_sync_rejects_a_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("bun.lockb");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let probe = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(read_regular_to_bytes_sync(&probe).map_err(|e| e.kind()));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(result) => assert_eq!(result, Err(std::io::ErrorKind::InvalidInput)),
            Err(_) => {
                // Release the wedged opener so the suite can fail cleanly.
                let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
                panic!("the sync bytes reader wedged in open(2) on a FIFO");
            }
        }
    }

    /// `first_symlink` reports the first LINK in iteration order, treats
    /// absent paths (files a rewrite would create) as non-links and does not
    /// follow the link to judge its target.
    #[cfg(unix)]
    #[tokio::test]
    async fn first_symlink_reports_links_in_caller_order() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package-lock.json"), "{}").unwrap();
        std::fs::write(tmp.path().join("real.lock"), "x").unwrap();
        std::os::unix::fs::symlink("real.lock", tmp.path().join("uv.lock")).unwrap();
        std::os::unix::fs::symlink("missing", tmp.path().join("dangling.lock")).unwrap();
        assert_eq!(
            first_symlink(
                tmp.path(),
                ["package-lock.json", "pnpm-workspace.yaml", "real.lock"]
            )
            .await,
            None
        );
        assert_eq!(
            first_symlink(
                tmp.path(),
                ["package-lock.json", "uv.lock", "dangling.lock"]
            )
            .await,
            Some("uv.lock")
        );
        assert_eq!(
            first_symlink(tmp.path(), ["dangling.lock", "uv.lock"]).await,
            Some("dangling.lock"),
            "a dangling link is still a link the rename would replace"
        );
    }
}
