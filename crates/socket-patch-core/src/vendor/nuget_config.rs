//! NuGet config file selection: the per-directory names NuGet probes and a
//! stat-only same-file check (the routing reader is `formats::nuget`).

// ── file selection ──

/// The per-directory config names NuGet probes, in its own order (NuGet
/// `Settings.OrderedSettingsFileNames`); the first present one is read.
pub(crate) const CONFIG_NAMES: [&str; 3] = ["nuget.config", "NuGet.config", "NuGet.Config"];

/// Whether `a` and `b` are one file (a case-insensitive filesystem's two
/// spellings of it). Unix compares device + inode (stat only: never opens
/// a FIFO planted under a config name); Windows compares volume serial +
/// file index; elsewhere `false` (the worst case is a duplicate file name
/// in recognition, never a lost one).
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
        tokio::task::spawn_blocking(move || same_file::is_same_file(a, b).unwrap_or(false))
            .await
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (a, b);
        false
    }
}
