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
}
