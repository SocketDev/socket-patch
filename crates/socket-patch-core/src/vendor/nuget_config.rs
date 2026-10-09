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

// ── inherited sources ──

/// The user-level `NuGet.Config` NuGet merges under every project config:
/// `%APPDATA%\\NuGet\\NuGet.Config` on Windows, else
/// `<home>/.nuget/NuGet/NuGet.Config`, where home is `DOTNET_CLI_HOME`
/// when set (the dotnet CLI's override) and `HOME` otherwise.
fn user_config_path() -> Option<std::path::PathBuf> {
    #[cfg(test)]
    {
        // Unit tests never read the developer's own user config.
        tests_support::USER_CONFIG.with(|c| c.borrow().clone())
    }
    #[cfg(not(test))]
    {
        let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty());
        if cfg!(windows) {
            return var("APPDATA").map(|d| {
                std::path::PathBuf::from(d)
                    .join("NuGet")
                    .join("NuGet.Config")
            });
        }
        var("DOTNET_CLI_HOME")
            .or_else(|| var("HOME"))
            .map(|h| std::path::PathBuf::from(h).join(".nuget/NuGet/NuGet.Config"))
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    thread_local! {
        /// The user config [`super::user_config_path`] answers in unit
        /// tests (`None`: none, so NuGet's implicit default).
        pub(crate) static USER_CONFIG: std::cell::RefCell<Option<std::path::PathBuf>> =
            const { std::cell::RefCell::new(None) };
    }
}

/// The package source keys every config NuGet merges BELOW the one in
/// `project_root` defines (#354): the user config (absent, NuGet's implicit
/// default — the `nuget.org` source it writes on first run), then each
/// parent directory's config from the filesystem root down, each `<clear />`
/// dropping the farther ones. A file that cannot be read or parsed is
/// skipped: it contributes nothing NuGet could use either.
pub(crate) async fn inherited_source_keys(project_root: &std::path::Path) -> Vec<String> {
    inherited_source_keys_traced(project_root).await.0
}

/// [`inherited_source_keys`] plus every path it probed or read (absolute),
/// for a read cache that fingerprints reads it did not mediate.
pub(crate) async fn inherited_source_keys_traced(
    project_root: &std::path::Path,
) -> (Vec<String>, Vec<std::path::PathBuf>) {
    use crate::formats::nuget::{effective_source_keys, parse_config, NugetConfig};
    let mut touched: Vec<std::path::PathBuf> = Vec::new();
    let mut chain: Vec<NugetConfig> = Vec::new();
    let user = match user_config_path() {
        Some(path) => {
            let read = crate::utils::fs::read_regular_to_string(&path).await;
            touched.push(path);
            read.ok()
                .and_then(|t| parse_config(crate::formats::text::strip_bom(&t)))
        }
        None => None,
    };
    chain.push(user.unwrap_or_else(|| NugetConfig {
        sources: vec![(
            "nuget.org".to_string(),
            "https://api.nuget.org/v3/index.json".to_string(),
        )],
        ..NugetConfig::default()
    }));
    let mut ancestors: Vec<&std::path::Path> = project_root.ancestors().skip(1).collect();
    ancestors.reverse();
    for dir in ancestors {
        for name in CONFIG_NAMES {
            let path = dir.join(name);
            let exists = crate::utils::fs::file_exists(&path).await;
            touched.push(path.clone());
            if !exists {
                continue;
            }
            if let Some(cfg) = crate::utils::fs::read_regular_to_string(&path)
                .await
                .ok()
                .and_then(|t| parse_config(crate::formats::text::strip_bom(&t)))
            {
                chain.push(cfg);
            }
            break;
        }
    }
    (effective_source_keys(&chain), touched)
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

    /// #354: the user config, then each parent directory's config from the
    /// root down; a `<clear />` drops the farther ones.
    #[tokio::test]
    async fn inherited_sources_follow_nugets_merge_order() {
        use super::{inherited_source_keys, tests_support::USER_CONFIG};
        let tmp = tempfile::tempdir().unwrap();
        // Not an ancestor of the project: the user config is only read as one.
        std::fs::create_dir_all(tmp.path().join("home")).unwrap();
        let user = tmp.path().join("home/NuGet.Config");
        std::fs::write(
            &user,
            "\u{feff}<configuration><packageSources><add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" /><add key=\"corp\" value=\"https://corp/v3/index.json\" /></packageSources></configuration>",
        )
        .unwrap();
        let project = tmp.path().join("repo/app");
        std::fs::create_dir_all(&project).unwrap();
        USER_CONFIG.with(|c| *c.borrow_mut() = Some(user.clone()));
        assert_eq!(inherited_source_keys(&project).await, ["nuget.org", "corp"]);
        // A repo-root config adds its own feed.
        std::fs::write(
            tmp.path().join("repo/NuGet.Config"),
            "<configuration><packageSources><add key=\"team\" value=\"https://team/\" /></packageSources></configuration>",
        )
        .unwrap();
        assert_eq!(
            inherited_source_keys(&project).await,
            ["nuget.org", "corp", "team"]
        );
        // ...or clears the user's for a mirror.
        std::fs::write(
            tmp.path().join("repo/NuGet.Config"),
            "<configuration><packageSources><clear /><add key=\"mirror\" value=\"https://mirror/\" /></packageSources></configuration>",
        )
        .unwrap();
        assert_eq!(inherited_source_keys(&project).await, ["mirror"]);
        // No user config at all: NuGet's implicit default.
        USER_CONFIG.with(|c| *c.borrow_mut() = None);
        std::fs::remove_file(tmp.path().join("repo/NuGet.Config")).unwrap();
        assert_eq!(inherited_source_keys(&project).await, ["nuget.org"]);
    }
}
