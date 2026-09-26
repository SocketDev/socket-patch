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
    list_dir_sync_complete(path).0
}

/// [`list_dir_sync`] plus whether the listing is the WHOLE directory: false
/// when `path` could not be read at all, or when iteration stopped early at
/// an entry error. A caller that answers "is child X here?" from the
/// listing can then tell a proven absence from an unread tail.
pub(crate) fn list_dir_sync_complete(path: &Path) -> (Vec<ListedEntry>, bool) {
    read_dir_entries_sync(path)
        .map(|(entries, complete)| {
            let listed = entries
                .into_iter()
                .map(|entry| ListedEntry {
                    name: entry.file_name(),
                    file_type: entry.file_type().ok(),
                })
                .collect();
            (listed, complete)
        })
        .unwrap_or_default()
}

/// A directory's entry names (lossy, in readdir order), listed at most
/// once per `cache` — but only a COMPLETE listing is kept. A truncated one
/// (unreadable directory, or an entry error mid-readdir) is handed to this
/// caller alone, so the next one lists again: the per-probe scans these
/// memos replace re-listed every time, and reusing a truncated listing
/// would turn one bad read into "absent" for every remaining probe.
pub(crate) fn names_memoized<'a>(
    dir: &Path,
    cache: &'a mut Option<Vec<String>>,
) -> std::borrow::Cow<'a, [String]> {
    if cache.is_none() {
        let (entries, complete) = list_dir_sync_complete(dir);
        let names: Vec<String> = entries
            .into_iter()
            .map(|entry| entry.name.to_string_lossy().into_owned())
            .collect();
        if !complete {
            return std::borrow::Cow::Owned(names);
        }
        *cache = Some(names);
    }
    std::borrow::Cow::Borrowed(cache.as_deref().expect("the listing was just cached"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete listing is kept and reused; an incomplete one (here: a
    /// directory that cannot be read at all) is not, so the next caller
    /// lists again and sees the directory once it is there.
    #[test]
    fn only_a_complete_listing_is_memoized() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("packages");
        let mut cache = None;

        assert!(names_memoized(&dir, &mut cache).is_empty());
        assert!(cache.is_none(), "an unread directory must not be kept");

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "a").unwrap();
        assert_eq!(&*names_memoized(&dir, &mut cache), ["a.txt".to_string()]);
        assert_eq!(cache.as_deref(), Some(&["a.txt".to_string()][..]));

        // Kept: the second ask does not re-list (the entry it names is
        // gone from disk).
        std::fs::remove_file(dir.join("a.txt")).unwrap();
        assert_eq!(&*names_memoized(&dir, &mut cache), ["a.txt".to_string()]);
    }
}
