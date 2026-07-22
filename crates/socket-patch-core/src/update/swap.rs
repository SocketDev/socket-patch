//! The swap: atomically replace the installed binary with a staged one.
//!
//! Unix: a plain `rename(2)` over a running executable is legal (the old
//! inode lives on until its last mmap goes away), so the swap is our own
//! mode-preserving rename — plus a refusal for setuid/setgid targets,
//! which an unprivileged rename would silently strip (see the
//! chown-clears-setuid ordering note in `patch/apply.rs`).
//!
//! Windows: a running `.exe` cannot be overwritten but can be *renamed*;
//! the `self-replace` crate owns that dance (rename the running exe aside,
//! move the new one in, schedule the old file's removal).
//!
//! Concurrency: one advisory `flock` on `<state-dir>/update.lock` makes
//! concurrent `--update` runs single-flight. The lock file lives in the
//! per-user state dir, never in the install dir (writing locks into
//! `/usr/local/bin` would demand privileges the check itself doesn't
//! need), and `flock` semantics release it when the process dies — there
//! is no stale-lock failure mode.

use std::path::{Path, PathBuf};

use fs2::FileExt;

use super::UpdateError;

/// Guard holding the exclusive update lock; dropping releases it.
pub struct UpdateLock {
    _file: std::fs::File,
}

/// Take the single-flight update lock, or fail with
/// [`UpdateError::InProgress`] if another update holds it.
pub fn acquire_update_lock() -> Result<Option<UpdateLock>, UpdateError> {
    let Some(dir) = super::state::state_dir() else {
        // No resolvable per-user dir: proceed unlocked rather than
        // refusing updates on exotic environments. The swap itself is
        // still a whole-file rename, so the race is benign duplicated
        // work, not a torn binary.
        return Ok(None);
    };
    std::fs::create_dir_all(&dir)
        .map_err(|e| UpdateError::SwapFailed(format!("cannot create {}: {e}", dir.display())))?;
    let path = dir.join("update.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| UpdateError::SwapFailed(format!("cannot open {}: {e}", path.display())))?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(UpdateLock { _file: file })),
        Err(_) => Err(UpdateError::InProgress),
    }
}

/// Resolve the path the swap must replace: the canonicalized current
/// executable. Canonicalizing matters twice — channel detection must see
/// the *real* location (macOS `current_exe` can return the symlink used to
/// exec), and the swap must replace the real file rather than turning a
/// symlink into a regular binary.
pub fn resolve_install_path() -> Result<PathBuf, UpdateError> {
    let exe = std::env::current_exe()
        .map_err(|e| UpdateError::SwapFailed(format!("cannot determine current executable: {e}")))?;
    std::fs::canonicalize(&exe).map_err(|e| {
        UpdateError::SwapFailed(format!("cannot canonicalize {}: {e}", exe.display()))
    })
}

/// Atomically replace `dest` with the staged binary at `staged`.
///
/// The caller guarantees `staged` sits in `dest`'s directory (same
/// filesystem ⇒ atomic rename) and has already passed its sanity exec.
/// On failure the stage file is removed; `dest` is never touched except by
/// the final atomic step.
pub fn swap_binary(staged: &Path, dest: &Path) -> Result<(), UpdateError> {
    let result = swap_binary_inner(staged, dest);
    if result.is_err() {
        let _ = std::fs::remove_file(staged);
    }
    result
}

#[cfg(unix)]
fn swap_binary_inner(staged: &Path, dest: &Path) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt;

    let dest_meta = std::fs::metadata(dest).map_err(|e| {
        UpdateError::SwapFailed(format!("cannot stat {}: {e}", dest.display()))
    })?;
    let mode = dest_meta.permissions().mode();
    if mode & 0o6000 != 0 {
        return Err(UpdateError::SwapFailed(format!(
            "refusing to replace {}: it carries setuid/setgid bits an update cannot restore; \
             reinstall manually",
            dest.display()
        )));
    }
    // Carry the destination's exact mode onto the staged inode before the
    // rename so a 0555 install never appears 0755, even briefly.
    std::fs::set_permissions(staged, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        UpdateError::SwapFailed(format!("cannot set mode on staged binary: {e}"))
    })?;
    std::fs::rename(staged, dest).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            UpdateError::PermissionDenied {
                path: dest.parent().unwrap_or(dest).to_path_buf(),
            }
        } else {
            UpdateError::SwapFailed(format!("rename onto {} failed: {e}", dest.display()))
        }
    })?;
    // The rename only updated the directory entry; fsync the directory so
    // the swap survives a crash. Best-effort (same posture as
    // atomic_write_bytes).
    if let Some(parent) = dest.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

#[cfg(windows)]
fn swap_binary_inner(staged: &Path, dest: &Path) -> Result<(), UpdateError> {
    // `self_replace` operates on the *current executable*; `dest` IS the
    // canonicalized current exe (resolve_install_path), so delegate the
    // rename dance to it. It renames the running exe aside and moves the
    // new file in; the parked old exe is cleaned up by the OS/helper, and
    // our start-of-run sweep removes any strays.
    let _ = dest; // dest == current_exe by contract; self_replace re-derives it
    self_replace::self_replace(staged).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            UpdateError::PermissionDenied {
                path: dest.parent().unwrap_or(dest).to_path_buf(),
            }
        } else {
            UpdateError::SwapFailed(format!("self-replace failed: {e}"))
        }
    })?;
    let _ = std::fs::remove_file(staged);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[cfg(unix)]
    #[test]
    fn swap_preserves_destination_mode_and_replaces_content() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("socket-patch");
        std::fs::write(&dest, b"old").unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o555)).unwrap();
        let staged = tmp.path().join(".socket-patch.stage-test");
        std::fs::write(&staged, b"new").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).unwrap();

        swap_binary(&staged, &dest).unwrap();

        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o555, "destination mode must be preserved");
        assert!(!staged.exists(), "stage must be consumed by the rename");
    }

    #[cfg(unix)]
    #[test]
    fn swap_refuses_setuid_target_and_removes_stage() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("socket-patch");
        std::fs::write(&dest, b"old").unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let staged = tmp.path().join(".socket-patch.stage-test");
        std::fs::write(&staged, b"new").unwrap();

        let err = swap_binary(&staged, &dest).unwrap_err();
        assert!(err.to_string().contains("setuid"), "{err}");
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"old",
            "refusal must leave the target untouched"
        );
        assert!(!staged.exists(), "failure path must clean the stage");
    }

    #[cfg(unix)]
    #[test]
    fn swap_missing_dest_is_error_not_create() {
        // The swap replaces an existing install; a vanished destination is
        // a bug upstream, not something to silently create.
        let tmp = tempfile::tempdir().unwrap();
        let staged = tmp.path().join(".socket-patch.stage-test");
        std::fs::write(&staged, b"new").unwrap();
        let err = swap_binary(&staged, &tmp.path().join("gone")).unwrap_err();
        assert!(err.to_string().contains("stat"), "{err}");
    }

    #[test]
    #[serial(update_state_dir_env)]
    fn update_lock_is_exclusive_and_released_on_drop() {
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("SOCKET_UPDATE_STATE_DIR");
        std::env::set_var("SOCKET_UPDATE_STATE_DIR", tmp.path());

        let first = acquire_update_lock().unwrap();
        assert!(first.is_some(), "state dir resolvable ⇒ a real lock");
        let second = acquire_update_lock();
        assert!(
            matches!(second, Err(UpdateError::InProgress)),
            "second concurrent acquire must report update-in-progress"
        );
        drop(first);
        assert!(
            acquire_update_lock().unwrap().is_some(),
            "lock must be reacquirable after release"
        );

        match prev {
            Some(v) => std::env::set_var("SOCKET_UPDATE_STATE_DIR", v),
            None => std::env::remove_var("SOCKET_UPDATE_STATE_DIR"),
        }
    }
}
