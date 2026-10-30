use std::path::{Path, PathBuf};

use super::go_mod_edit::{ReplaceEntry, ReplaceOwner};
use super::go_sum_edit::reinsert_lines;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};

const NAME: &str = ".upstream-go.sum";

async fn read(path: &Path) -> Result<String, String> {
    match read_regular_to_string(path).await {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

fn selected(text: &str, module: &str, version: &str) -> String {
    text.lines()
        .filter(|line| {
            let mut fields = line.split_whitespace();
            fields.next() == Some(module)
                && fields
                    .next()
                    .is_some_and(|v| v == version || v.strip_suffix("/go.mod") == Some(version))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether some line of `b` pins the same module and version as a line of
/// `a` with a different hash. Merging the two would leave go.sum with both.
fn conflicts(a: &str, b: &str) -> bool {
    b.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        a.lines().any(|other| {
            let other: Vec<_> = other.split_whitespace().collect();
            fields.len() == 3
                && other.len() == 3
                && other[..2] == fields[..2]
                && other[2] != fields[2]
        })
    })
}

pub(super) async fn save(
    root: &Path,
    base: &str,
    module: &str,
    version: &str,
) -> Result<(), String> {
    let mut sums = selected(&read(&root.join("go.sum")).await?, module, version);
    for entry in super::go_mod_edit::read_replace_entries(root).await {
        if entry.module == module && entry.version.as_deref() == Some(version) {
            if let Some(path) = backup(root, &entry) {
                let saved = selected(&read(&path).await?, module, version);
                if conflicts(&sums, &saved) {
                    return Err(format!(
                        "go.sum conflicts with the checksum saved in {} for {module} {version}",
                        path.display()
                    ));
                }
                if let Some(merged) = reinsert_lines(&sums, &saved) {
                    sums = merged;
                }
            }
        }
    }
    if sums.is_empty() {
        return Ok(());
    }
    let path = root.join(base).join(NAME);
    let old = read(&path).await?;
    if conflicts(&old, &sums) {
        return Err(format!(
            "go.sum conflicts with the checksum saved in {} for {module} {version}",
            path.display()
        ));
    }
    if let Some(new) = reinsert_lines(&old, &sums) {
        tokio::fs::create_dir_all(root.join(base))
            .await
            .map_err(|e| e.to_string())?;
        atomic_write_bytes_preserving_mode(&path, new.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn backup(root: &Path, entry: &ReplaceEntry) -> Option<PathBuf> {
    if !matches!(
        entry.owner,
        Some(ReplaceOwner::GoPatches | ReplaceOwner::Vendor)
    ) {
        return None;
    }
    let path = entry
        .path
        .as_deref()?
        .strip_prefix("./")
        .unwrap_or(entry.path.as_deref()?);
    if !crate::patch::apply::is_safe_relative_subpath(path) {
        return None;
    }
    let suffix = format!("/{}@{}", entry.module, entry.version.as_deref()?);
    Some(root.join(path.strip_suffix(&suffix)?).join(NAME))
}

/// Restore only this module's saved checksums, preserving unrelated sums and
/// refusing a conflicting live pin. The backup travels with the local copy.
/// A version the build no longer selects (go.mod now requires another one,
/// or a pruned graph no longer has the module) needs no checksums: restoring
/// them would leave go.sum untidy and make discovery see the old version
/// again. Returns the restored go.sum without writing it (`None`: no
/// change), so the caller writes it only once the directive is gone.
pub(super) async fn restore(
    root: &Path,
    entries: &[ReplaceEntry],
) -> Result<Option<String>, String> {
    use super::go_build_list::{project_selection, Selection};
    let path = root.join("go.sum");
    let mut sums = read(&path).await?;
    let original = sums.clone();
    for entry in entries {
        let (Some(backup), Some(version)) = (backup(root, entry), entry.version.as_deref()) else {
            continue;
        };
        if matches!(
            project_selection(root, &entry.module, version).await,
            Some(Selection::Other(_) | Selection::NotInGraph)
        ) {
            continue;
        }
        let saved = selected(&read(&backup).await?, &entry.module, version);
        if conflicts(&saved, &saved) {
            return Err(format!(
                "conflicting saved checksums in {}",
                backup.display()
            ));
        }
        for line in saved.lines() {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 3 || !fields[2].starts_with("h1:") {
                return Err(format!("invalid saved checksum in {}", backup.display()));
            }
            if sums.lines().any(|live| {
                let live: Vec<_> = live.split_whitespace().collect();
                live.len() == 3 && live[..2] == fields[..2] && live[2] != fields[2]
            }) {
                return Err(format!(
                    "go.sum conflicts with the saved checksum for {} {version}",
                    entry.module
                ));
            }
        }
        if let Some(new) = reinsert_lines(&sums, &saved) {
            sums = new;
        }
    }
    Ok((sums != original).then_some(sums))
}

/// Write the go.sum [`restore`] planned.
pub(super) async fn write(root: &Path, sums: &str) -> Result<(), String> {
    atomic_write_bytes_preserving_mode(&root.join("go.sum"), sums.as_bytes())
        .await
        .map_err(|e| e.to_string())
}

pub(crate) async fn forget(root: &Path, entries: &[ReplaceEntry]) {
    for entry in entries {
        let (Some(path), Some(version)) = (backup(root, entry), entry.version.as_deref()) else {
            continue;
        };
        let Ok(old) = read(&path).await else {
            continue;
        };
        let ours = selected(&old, &entry.module, version);
        let Some(new) = super::go_sum_edit::remove_lines(&old, &ours) else {
            continue;
        };
        if new.is_empty() {
            let _ = tokio::fs::remove_file(&path).await;
        } else {
            let _ = atomic_write_bytes_preserving_mode(&path, new.as_bytes()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::go_mod_edit::{drop_replace_entry, ensure_replace_entry, GO_PATCHES_DIR};

    const MODULE: &str = "example.com/upstream";
    const VERSION: &str = "v1.0.0";
    const SUMS: &str = "example.com/upstream v1.0.0 h1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\nexample.com/upstream v1.0.0/go.mod h1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\n";

    #[tokio::test]
    async fn preserves_sums_across_tidy_and_mode_takeover() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("go.mod"),
            "module consumer\ngo 1.21\nrequire example.com/upstream v1.0.0\n",
        )
        .await
        .unwrap();
        tokio::fs::write(root.join("go.sum"), SUMS).await.unwrap();
        ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, true)
            .await
            .unwrap();
        assert!(!root.join(GO_PATCHES_DIR).exists());
        ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
            .await
            .unwrap();
        tokio::fs::write(root.join("go.sum"), "example.com/other v1.0.0 h1:other\n")
            .await
            .unwrap();
        let vendor = ".socket/vendor/golang/11111111-2222-4333-8444-555555555555";
        ensure_replace_entry(root, MODULE, VERSION, vendor, false)
            .await
            .unwrap();
        tokio::fs::remove_dir_all(root.join(GO_PATCHES_DIR))
            .await
            .unwrap();
        drop_replace_entry(root, MODULE, ReplaceOwner::Vendor, false)
            .await
            .unwrap();
        assert_eq!(
            read(&root.join("go.sum")).await.unwrap(),
            format!("example.com/other v1.0.0 h1:other\n{SUMS}")
        );
        // Retained while the artifact is retained (hosted dry-run takeovers
        // temporarily remove and restore wiring without deleting artifacts).
        assert!(root.join(vendor).join(NAME).exists());
    }

    #[tokio::test]
    async fn conflicting_checksum_refuses_rollback_without_dropping_replace() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join("go.mod"), "module consumer\ngo 1.21\n")
            .await
            .unwrap();
        tokio::fs::write(root.join("go.sum"), SUMS).await.unwrap();
        ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
            .await
            .unwrap();
        let before = read(&root.join("go.mod")).await.unwrap();
        let conflict = SUMS.replace("h1:aaaa", "h1:zzzz");
        tokio::fs::write(root.join("go.sum"), &conflict)
            .await
            .unwrap();
        assert!(
            drop_replace_entry(root, MODULE, ReplaceOwner::GoPatches, false)
                .await
                .unwrap_err()
                .contains("conflicts")
        );
        assert_eq!(read(&root.join("go.mod")).await.unwrap(), before);
        assert_eq!(read(&root.join("go.sum")).await.unwrap(), conflict);
        // A dry run makes the same refusal, and writes nothing either.
        assert!(
            drop_replace_entry(root, MODULE, ReplaceOwner::GoPatches, true)
                .await
                .unwrap_err()
                .contains("conflicts")
        );
        assert_eq!(read(&root.join("go.mod")).await.unwrap(), before);
        assert_eq!(read(&root.join("go.sum")).await.unwrap(), conflict);
    }

    /// Re-pinning over a backup that saved a different hash refuses instead
    /// of keeping both, which a rollback after tidy would write to go.sum.
    #[tokio::test]
    async fn save_refuses_a_checksum_conflicting_with_the_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join("go.mod"), "module consumer\ngo 1.21\n")
            .await
            .unwrap();
        tokio::fs::write(root.join("go.sum"), SUMS).await.unwrap();
        save(root, GO_PATCHES_DIR, MODULE, VERSION).await.unwrap();
        let backup = root.join(GO_PATCHES_DIR).join(NAME);
        let saved = read(&backup).await.unwrap();
        tokio::fs::write(root.join("go.sum"), SUMS.replace("h1:aaaa", "h1:zzzz"))
            .await
            .unwrap();
        assert!(save(root, GO_PATCHES_DIR, MODULE, VERSION)
            .await
            .unwrap_err()
            .contains("conflicts"));
        assert_eq!(read(&backup).await.unwrap(), saved);
    }

    #[tokio::test]
    async fn restore_refuses_a_backup_with_conflicting_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("go.mod"),
            "module consumer\ngo 1.21\nrequire example.com/upstream v1.0.0\n",
        )
        .await
        .unwrap();
        tokio::fs::write(root.join("go.sum"), SUMS).await.unwrap();
        ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
            .await
            .unwrap();
        let backup = root.join(GO_PATCHES_DIR).join(NAME);
        let both = format!("{SUMS}{}", SUMS.replace("h1:aaaa", "h1:zzzz"));
        tokio::fs::write(&backup, both).await.unwrap();
        tokio::fs::write(root.join("go.sum"), "").await.unwrap();
        assert!(
            drop_replace_entry(root, MODULE, ReplaceOwner::GoPatches, false)
                .await
                .unwrap_err()
                .contains("conflicting")
        );
        assert_eq!(read(&root.join("go.sum")).await.unwrap(), "");
    }

    /// go.sum changes only after the directive is removed: a refused go.mod
    /// edit leaves both as they were.
    #[cfg(unix)]
    #[tokio::test]
    async fn failed_directive_edit_leaves_go_sum_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("go.mod"),
            "module consumer\ngo 1.21\nrequire example.com/upstream v1.0.0\n",
        )
        .await
        .unwrap();
        tokio::fs::write(root.join("go.sum"), SUMS).await.unwrap();
        ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
            .await
            .unwrap();
        tokio::fs::write(root.join("go.sum"), "").await.unwrap();
        let real = tmp.path().join("real.mod");
        tokio::fs::rename(root.join("go.mod"), &real).await.unwrap();
        std::os::unix::fs::symlink(&real, root.join("go.mod")).unwrap();
        assert!(
            drop_replace_entry(root, MODULE, ReplaceOwner::GoPatches, false)
                .await
                .is_err()
        );
        assert_eq!(read(&root.join("go.sum")).await.unwrap(), "");
    }

    #[tokio::test]
    async fn dry_run_drop_restores_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("go.mod"),
            "module consumer\ngo 1.21\nrequire example.com/upstream v1.0.0\n",
        )
        .await
        .unwrap();
        tokio::fs::write(root.join("go.sum"), SUMS).await.unwrap();
        ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
            .await
            .unwrap();
        // `go mod tidy` under the directory replace drops the sums.
        tokio::fs::write(root.join("go.sum"), "").await.unwrap();
        drop_replace_entry(root, MODULE, ReplaceOwner::GoPatches, true)
            .await
            .unwrap();
        assert_eq!(read(&root.join("go.sum")).await.unwrap(), "");
        drop_replace_entry(root, MODULE, ReplaceOwner::GoPatches, false)
            .await
            .unwrap();
        assert_eq!(read(&root.join("go.sum")).await.unwrap(), SUMS);
    }

    /// After `go get` moves the module to another version, the patched
    /// version's sums are not needed: restoring them would leave go.sum
    /// untidy and make discovery see the old version again.
    #[tokio::test]
    async fn restore_skips_a_version_the_build_no_longer_selects() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("go.mod"),
            "module consumer\ngo 1.21\nrequire example.com/upstream v1.0.0\n",
        )
        .await
        .unwrap();
        tokio::fs::write(root.join("go.sum"), SUMS).await.unwrap();
        ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
            .await
            .unwrap();
        let go_mod = read(&root.join("go.mod")).await.unwrap().replace(
            "require example.com/upstream v1.0.0",
            "require example.com/upstream v1.0.1",
        );
        tokio::fs::write(root.join("go.mod"), go_mod).await.unwrap();
        let bumped =
            "example.com/upstream v1.0.1 h1:ccccccccccccccccccccccccccccccccccccccccccc=\n";
        tokio::fs::write(root.join("go.sum"), bumped).await.unwrap();
        drop_replace_entry(root, MODULE, ReplaceOwner::GoPatches, false)
            .await
            .unwrap();
        assert_eq!(read(&root.join("go.sum")).await.unwrap(), bumped);
    }
}
