//! Filesystem helpers shared by the ecosystem crawlers.
//!
//! Each crawler walks one or more package directories and decides
//! whether each entry is a candidate package. The two operations that
//! all eight crawlers repeat are:
//!
//! - listing entries in a directory while tolerating permission /
//!   I/O errors (we treat an unreadable directory as "no entries");
//! - asking whether an entry is a directory while tolerating
//!   `file_type()` failures (we treat a stat error as "not a dir").
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

use tokio::fs::DirEntry;
use std::fs::FileType;

/// List the immediate children of `path`.
///
/// Returns an empty vector if the directory cannot be read (does not
/// exist, permission denied, etc.) or if any individual `next_entry`
/// call fails. The crawlers treat both cases the same way: surface
/// no packages from the unreadable subtree, but don't abort the
/// whole crawl.
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
/// Returns `false` if `file_type()` errors — the caller then skips
/// the entry rather than aborting the walk.
pub async fn entry_is_dir(entry: &DirEntry) -> bool {
    entry
        .metadata()
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
        tokio::fs::write(tmp.path().join("c.txt"), b"").await.unwrap();
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
}
