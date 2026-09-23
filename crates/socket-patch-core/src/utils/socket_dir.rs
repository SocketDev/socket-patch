//! Residue-free removal of socket-patch-owned state under `.socket/`.
//!
//! Every reversal path (an emptied ledger, a swept blob store, a reverted
//! vendored unit) used to hand-roll "delete the file, then `remove_dir` the
//! parents I created" — or forgot to, leaving empty `.socket/vendor/`,
//! `.socket/vendor/<eco>/` or `.socket/blobs/` husks behind. The helpers here
//! are the one implementation: delete, then climb the now-empty parents up
//! to but EXCLUDING `stop_dir` (normally the project's `.socket/`, which the
//! lock guard owns).
//!
//! Every prune is best-effort and non-recursive: `remove_dir` refuses a
//! non-empty directory, so anything still living there — vendored
//! artifacts, a sibling ecosystem's copies, the manifest, `apply.lock`, a
//! `redirect-state.json.corrupt` quarantine (the one sanctioned residue) —
//! keeps the directory and stops the climb. The climb is also confined to
//! `stop_dir`'s subtree, so a caller mistake can never rmdir its way out of
//! the project.

use std::path::Path;

use serde::Serialize;

use super::fs::{atomic_write_bytes, read_regular_to_bytes};

/// Best-effort: remove `dir` when it is empty, then each ancestor while it is
/// empty, stopping before `stop_dir` (never removed) or at the first
/// directory that is not empty. A missing `dir` (already unwound wholesale)
/// continues to its parents — they may be husks this run created. Nothing
/// outside `stop_dir`'s subtree is ever touched.
pub async fn prune_empty_dirs(dir: &Path, stop_dir: &Path) {
    let mut level = Some(dir);
    while let Some(d) = level {
        if d == stop_dir || !d.starts_with(stop_dir) {
            return;
        }
        match tokio::fs::remove_dir(d).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return,
        }
        level = d.parent();
    }
}

/// Remove the file at `path` (a missing file is fine), then prune its
/// now-empty parents up to but excluding `stop_dir`. Any unlink error other
/// than NotFound propagates BEFORE any pruning: a read-only parent leaves the
/// file — and the caller's fail-closed error — exactly where they were.
pub async fn remove_file_and_prune(path: &Path, stop_dir: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(parent) = path.parent() {
        prune_empty_dirs(parent, stop_dir).await;
    }
    Ok(())
}

/// Remove the tree at `dir` (a missing tree is fine; read-only directory
/// modes are relaxed like [`remove_tree`](crate::patch::copy_tree::remove_tree)),
/// then prune its now-empty parents up to but excluding `stop_dir`. The
/// per-unit vendored revert: `.socket/vendor/<eco>/<uuid>/` goes, then the
/// `<eco>/` and `vendor/` levels when that was their last unit. A removal
/// error propagates unchanged (callers surface it verbatim) and skips the
/// prune — the tree is still there.
pub async fn remove_tree_and_prune(dir: &Path, stop_dir: &Path) -> std::io::Result<()> {
    crate::patch::copy_tree::remove_tree(dir).await?;
    if let Some(parent) = dir.parent() {
        prune_empty_dirs(parent, stop_dir).await;
    }
    Ok(())
}

/// Persist a committed JSON ledger: pretty-printed with a trailing newline
/// (deterministic bytes), parent directory created on demand, staged +
/// fsync'd + renamed via [`atomic_write_bytes`]. A ledger already holding
/// these exact bytes is left untouched — an idempotent re-run must not churn
/// the mtime of a committed file or pay a needless fsync. The comparison
/// reads through the FIFO-safe opener; any read error (absent, unreadable,
/// not a regular file) simply falls through to the write, so failure paths
/// are exactly those of a plain write.
///
/// A failed write leaves no husk: when this call had to create the parent
/// (`.socket/vendor/` on a fresh project) and the write then fails
/// (ENOSPC, a squatter, …), the directories it created are pruned again up
/// to the nearest `.socket/` ancestor before the ORIGINAL error propagates.
/// Unlike [`remove_file_and_prune`], nothing was written here, so pruning
/// on the error path is the right asymmetry. A parent that already existed
/// (the user's, or another run's) is never removed.
pub(crate) async fn write_json_ledger<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    if matches!(read_regular_to_bytes(path).await, Ok(existing) if existing == bytes) {
        return Ok(());
    }
    let Some(parent) = path.parent() else {
        return atomic_write_bytes(path, &bytes).await;
    };
    let created_parent = tokio::fs::metadata(parent).await.is_err();
    tokio::fs::create_dir_all(parent).await?;
    match atomic_write_bytes(path, &bytes).await {
        Ok(()) => Ok(()),
        Err(e) => {
            if created_parent {
                if let Some(stop) = nearest_socket_dir(path) {
                    prune_empty_dirs(parent, stop).await;
                }
            }
            Err(e)
        }
    }
}

/// The nearest ancestor of `path` literally named `.socket` — the fence for
/// an error-path prune. `None` (a ledger that does not live under a
/// `.socket/`) means: never climb.
fn nearest_socket_dir(path: &Path) -> Option<&Path> {
    path.ancestors().skip(1).find(|a| {
        a.file_name()
            .is_some_and(|n| n == crate::constants::SOCKET_DIR)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The climb removes every empty level below `stop_dir`, never
    /// `stop_dir` itself, and continues past a level that is already gone.
    #[tokio::test]
    async fn prune_climbs_empty_levels_and_stops_before_stop_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        let uuid_dir = socket.join("vendor/npm/uuid");
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();

        // Start one level BELOW a dir that does not exist: NotFound must not
        // end the climb (the unwind paths remove the uuid dir wholesale
        // before pruning).
        prune_empty_dirs(&uuid_dir.join("gone"), &socket).await;

        assert!(!socket.join("vendor").exists(), "every empty level pruned");
        assert!(socket.exists(), "stop_dir is never removed");
        assert!(tmp.path().exists());
    }

    /// A non-empty level keeps itself and everything above it.
    #[tokio::test]
    async fn prune_stops_at_the_first_non_empty_level() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        let eco = socket.join("vendor/npm");
        tokio::fs::create_dir_all(eco.join("a")).await.unwrap();
        tokio::fs::write(eco.join("sibling.tgz"), b"x")
            .await
            .unwrap();

        prune_empty_dirs(&eco.join("a"), &socket).await;

        assert!(!eco.join("a").exists(), "the empty leaf goes");
        assert!(eco.join("sibling.tgz").exists(), "siblings are untouched");
        assert!(eco.exists() && socket.join("vendor").exists());
    }

    /// A `dir` outside `stop_dir`'s subtree is refused outright — the climb
    /// can never rmdir its way out of the project.
    #[tokio::test]
    async fn prune_never_leaves_the_stop_dir_subtree() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("elsewhere/empty");
        tokio::fs::create_dir_all(&elsewhere).await.unwrap();

        prune_empty_dirs(&elsewhere, &tmp.path().join(".socket")).await;

        assert!(elsewhere.exists(), "an out-of-subtree dir is left alone");
    }

    #[tokio::test]
    async fn remove_file_and_prune_unlinks_then_climbs() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        let ledger = socket.join("vendor/redirect-state.json");
        tokio::fs::create_dir_all(ledger.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&ledger, b"{}").await.unwrap();

        remove_file_and_prune(&ledger, &socket).await.unwrap();
        assert!(!socket.join("vendor").exists());
        assert!(socket.exists());

        // A missing file is fine, and still prunes a stale empty parent.
        tokio::fs::create_dir_all(socket.join("vendor"))
            .await
            .unwrap();
        remove_file_and_prune(&ledger, &socket).await.unwrap();
        assert!(!socket.join("vendor").exists());
    }

    /// The unlink error propagates verbatim and nothing is pruned — the
    /// caller's fail-closed error keeps the file exactly where it was.
    #[cfg(unix)]
    #[tokio::test]
    async fn remove_file_and_prune_propagates_unlink_errors_before_pruning() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        let dir = socket.join("vendor");
        let ledger = dir.join("state.json");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(&ledger, b"{}").await.unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::File::create(dir.join("probe")).is_ok() {
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755));
            eprintln!("skipping: running as root, 0555 does not block writes");
            return;
        }

        let err = remove_file_and_prune(&ledger, &socket).await.unwrap_err();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(ledger.exists(), "a failed unlink leaves the file in place");
    }

    #[tokio::test]
    async fn remove_tree_and_prune_removes_the_unit_and_its_empty_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        let uuid_dir = socket.join("vendor/npm/uuid");
        tokio::fs::create_dir_all(uuid_dir.join("package"))
            .await
            .unwrap();
        tokio::fs::write(uuid_dir.join("package/index.js"), b"x")
            .await
            .unwrap();
        // A sibling unit under another ecosystem keeps `vendor/`.
        let other = socket.join("vendor/pypi/other");
        tokio::fs::create_dir_all(&other).await.unwrap();

        remove_tree_and_prune(&uuid_dir, &socket).await.unwrap();

        assert!(!socket.join("vendor/npm").exists(), "unit + eco husk gone");
        assert!(other.exists() && socket.join("vendor").exists());

        // Missing tree: still Ok, still prunes.
        remove_tree_and_prune(&other, &socket).await.unwrap();
        remove_tree_and_prune(&other, &socket).await.unwrap();
        assert!(!socket.join("vendor").exists());
        assert!(socket.exists());
    }

    #[derive(Serialize)]
    struct Ledger {
        version: u32,
        entries: Vec<String>,
    }

    /// Bytes are pretty JSON plus a trailing newline; the parent is created
    /// on demand; an identical ledger is not rewritten (its inode survives).
    #[tokio::test]
    async fn write_json_ledger_is_deterministic_and_skips_identical_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".socket/vendor/state.json");
        let ledger = Ledger {
            version: 1,
            entries: vec!["a".into()],
        };
        write_json_ledger(&path, &ledger).await.unwrap();
        let text = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(
            text,
            format!("{}\n", serde_json::to_string_pretty(&ledger).unwrap())
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let before = std::fs::metadata(&path).unwrap().ino();
            write_json_ledger(&path, &ledger).await.unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().ino(),
                before,
                "an identical ledger must not be re-staged and renamed over"
            );
            let changed = Ledger {
                version: 1,
                entries: vec!["a".into(), "b".into()],
            };
            write_json_ledger(&path, &changed).await.unwrap();
            assert_ne!(
                std::fs::metadata(&path).unwrap().ino(),
                before,
                "a changed ledger is atomically replaced"
            );
        }
        // No stage litter either way.
        for entry in std::fs::read_dir(path.parent().unwrap()).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.starts_with(".socket-stage-"), "litter: {name}");
        }
    }

    /// A failed write on a fresh project prunes the `.socket/vendor/` this
    /// call created, keeps `.socket/` (the fence), and propagates the write
    /// error unchanged. The failure is forced by a stem long enough that the
    /// `.socket-stage-<stem>-<uuid>` staging name exceeds NAME_MAX.
    #[cfg(unix)]
    #[tokio::test]
    async fn write_json_ledger_failed_write_prunes_the_parent_it_created() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        tokio::fs::create_dir_all(&socket).await.unwrap();
        let stem = "x".repeat(250);
        let path = socket.join("vendor").join(format!("{stem}.json"));
        let ledger = Ledger {
            version: 1,
            entries: vec![],
        };

        let err = write_json_ledger(&path, &ledger).await.unwrap_err();
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
        assert!(
            !socket.join("vendor").exists(),
            "the vendor/ husk this call created is pruned on the error path"
        );
        assert!(socket.exists(), "the .socket/ fence is never removed");
    }

    /// A parent that already existed is NOT removed on a failed write, even
    /// when empty: only directories this call created are its husks.
    #[cfg(unix)]
    #[tokio::test]
    async fn write_json_ledger_failed_write_keeps_a_preexisting_parent() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let vendor = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&vendor).await.unwrap();
        std::fs::set_permissions(&vendor, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::File::create(vendor.join("probe")).is_ok() {
            let _ = std::fs::set_permissions(&vendor, std::fs::Permissions::from_mode(0o755));
            eprintln!("skipping: running as root, 0555 does not block writes");
            return;
        }
        let ledger = Ledger {
            version: 1,
            entries: vec!["a".into()],
        };

        let err = write_json_ledger(&vendor.join("state.json"), &ledger)
            .await
            .unwrap_err();
        std::fs::set_permissions(&vendor, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            vendor.exists(),
            "a pre-existing parent survives a failed write"
        );
    }
}
