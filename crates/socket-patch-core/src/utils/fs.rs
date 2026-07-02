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
//! `entry_is_dir` follows symlinks (uses `metadata()`, not
//! `symlink_metadata()`), matching the historical behavior of the
//! crawlers (pnpm's content-addressed store relies on resolving
//! symlinks into `node_modules/.pnpm/*`).

use std::path::Path;

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
pub async fn list_dir_entries(path: &Path) -> Vec<DirEntry> {
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
/// rely on for symlinked package directories — we stat the resolved
/// `entry.path()` via `tokio::fs::metadata`, which does follow links.
pub async fn entry_is_dir(entry: &DirEntry) -> bool {
    tokio::fs::metadata(entry.path())
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

/// Check whether `path` is a directory, following symlinks.
///
/// Returns `false` if the stat fails (missing path, broken symlink,
/// permission error, etc.) — the crawlers probe candidate package
/// roots and treat "can't stat" the same as "not there". The
/// `Path`-taking counterpart of [`entry_is_dir`]; previously
/// copy-pasted into every crawler.
pub async fn is_dir(path: &Path) -> bool {
    tokio::fs::metadata(path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

/// Return the raw `FileType` for `entry`, swallowing stat errors.
///
/// Use this instead of `entry_is_dir` when the caller needs to
/// distinguish real directories from symlinks (e.g. npm's pnpm
/// support: symlinks point into the content-addressed store and must
/// be treated as scannable-but-non-recurseable). The returned
/// `FileType` is the symlink-aware kind from `entry.file_type()`,
/// not the resolved-target kind from `metadata()`.
pub async fn entry_file_type(entry: &DirEntry) -> Option<FileType> {
    entry.file_type().await.ok()
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
pub async fn atomic_write_bytes(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_string());
    let stage = parent.join(format!(".socket-stage-{}-{}", stem, uuid::Uuid::new_v4()));

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .await?;

    use tokio::io::AsyncWriteExt;
    if let Err(e) = file.write_all(content).await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }
    if let Err(e) = file.sync_all().await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }
    drop(file);

    if let Err(e) = tokio::fs::rename(&stage, path).await {
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
}
