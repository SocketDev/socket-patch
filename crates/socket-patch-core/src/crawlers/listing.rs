//! Directory listings for the crawlers' synchronous walks (the blocking
//! twins of `utils::fs::list_dir_entries` + `entry_is_dir`, which the async
//! walks used one runtime hop at a time).

use std::ffi::OsString;
use std::fs::FileType;
use std::path::Path;

use crate::utils::fs::{is_dir_sync, read_dir_entries_sync};

/// One listed entry of a directory being walked: its raw name plus the
/// `DirEntry`'s own (symlink-aware) file type, read while listing so the
/// directory stream is closed before the walk descends.
pub(crate) struct ListedEntry {
    pub(crate) name: OsString,
    pub(crate) file_type: Option<FileType>,
}

impl ListedEntry {
    /// Whether the entry is a directory, following symlinks: a symlinked
    /// entry is resolved through a stat of `dir/name`, and a failed
    /// `file_type`/stat means "not a dir" (`utils::fs::entry_is_dir`'s rule).
    pub(crate) fn is_dir(&self, dir: &Path) -> bool {
        match self.file_type {
            Some(kind) if kind.is_symlink() => is_dir_sync(&dir.join(&self.name)),
            Some(kind) => kind.is_dir(),
            None => false,
        }
    }
}

/// List `path` in readdir order: empty when it cannot be read, and
/// iteration stops at the first entry error — the tolerate-and-truncate
/// contract of `utils::fs::list_dir_entries`.
pub(crate) fn list_dir_sync(path: &Path) -> Vec<ListedEntry> {
    read_dir_entries_sync(path)
        .map(|(entries, _)| {
            entries
                .into_iter()
                .map(|entry| ListedEntry {
                    name: entry.file_name(),
                    file_type: entry.file_type().ok(),
                })
                .collect()
        })
        .unwrap_or_default()
}
