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
//! concurrent `--update` runs single-flight **per environment**. The lock
//! file lives in the per-user state dir, never in the install dir (writing
//! locks into `/usr/local/bin` would demand privileges the check itself
//! doesn't need), and `flock` semantics release it when the process dies —
//! there is no stale-lock failure mode. Two updaters whose state dirs
//! diverge (different `$HOME`s targeting one shared install) can race, but
//! every path to the destination is a whole-file rename and the stage
//! sweep is age-gated, so the worst case is duplicated work with a
//! complete binary winning — never a torn one.

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
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    // A FIFO planted at the lock path would wedge a plain O_WRONLY open(2)
    // forever waiting for a reader; O_NONBLOCK makes it return immediately
    // (ENXIO, or a handle the is_file check below rejects). A no-op for the
    // regular file this normally is — the fd is only ever flock(2)ed, never
    // read or written. Same guard as state.rs's read_state_bytes.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options
        .open(&path)
        .map_err(|e| UpdateError::SwapFailed(format!("cannot open {}: {e}", path.display())))?;
    let metadata = file
        .metadata()
        .map_err(|e| UpdateError::SwapFailed(format!("cannot stat {}: {e}", path.display())))?;
    if !metadata.is_file() {
        return Err(UpdateError::SwapFailed(format!(
            "update lock {} is not a regular file; remove it and retry",
            path.display()
        )));
    }
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
    let exe = std::env::current_exe().map_err(|e| {
        UpdateError::SwapFailed(format!("cannot determine current executable: {e}"))
    })?;
    std::fs::canonicalize(&exe)
        .map_err(|e| UpdateError::SwapFailed(format!("cannot canonicalize {}: {e}", exe.display())))
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

/// Linux file capabilities (`setcap`) live in the `security.capability`
/// xattr — the same class of privilege grant as setuid: a rename replaces
/// the inode and an unprivileged updater cannot restore them, so a target
/// carrying them is refused rather than silently stripped.
#[cfg(target_os = "linux")]
fn has_file_capabilities(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let ret = unsafe {
        libc::getxattr(
            cpath.as_ptr(),
            c"security.capability".as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    ret > 0
}

#[cfg(all(unix, not(target_os = "linux")))]
fn has_file_capabilities(_path: &Path) -> bool {
    false
}

#[cfg(unix)]
fn swap_binary_inner(staged: &Path, dest: &Path) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt;

    let dest_meta = std::fs::metadata(dest)
        .map_err(|e| UpdateError::SwapFailed(format!("cannot stat {}: {e}", dest.display())))?;
    let mode = dest_meta.permissions().mode();
    if mode & 0o6000 != 0 {
        return Err(UpdateError::SwapFailed(format!(
            "refusing to replace {}: it carries setuid/setgid bits an update cannot restore; \
             reinstall manually",
            dest.display()
        )));
    }
    if has_file_capabilities(dest) {
        return Err(UpdateError::SwapFailed(format!(
            "refusing to replace {}: it carries file capabilities (setcap) an update cannot \
             restore; reinstall manually and re-apply setcap",
            dest.display()
        )));
    }
    // Carry the destination's exact mode onto the staged inode before the
    // rename so a 0555 install never appears 0755, even briefly.
    std::fs::set_permissions(staged, std::fs::Permissions::from_mode(mode))
        .map_err(|e| UpdateError::SwapFailed(format!("cannot set mode on staged binary: {e}")))?;
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

    /// mkfifo(2) directly, not the /usr/bin/mkfifo binary: spawning a child
    /// flakes under heavy parallel load (fork/exec starvation) and the
    /// syscall needs no process at all.
    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A FIFO planted at the lock path must not wedge the updater: a plain
    /// `O_WRONLY` open(2) of a FIFO waits forever for a reader that never
    /// comes, hanging `--update` with no output before it does anything.
    /// Same class as the `read_state_bytes` guard one file over in
    /// state.rs — same directory, even.
    #[cfg(unix)]
    #[test]
    #[serial(update_state_dir_env)]
    fn update_lock_fifo_lock_file_errors_instead_of_wedging() {
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("SOCKET_UPDATE_STATE_DIR");
        std::env::set_var("SOCKET_UPDATE_STATE_DIR", tmp.path());
        let fifo = tmp.path().join("update.lock");
        mkfifo(&fifo);

        // acquire_update_lock is sync, so bound it with a helper thread +
        // timeout.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(acquire_update_lock());
        });
        let result = rx.recv_timeout(std::time::Duration::from_secs(5));
        match prev {
            Some(v) => std::env::set_var("SOCKET_UPDATE_STATE_DIR", v),
            None => std::env::remove_var("SOCKET_UPDATE_STATE_DIR"),
        }
        let Ok(acquired) = result else {
            // The open is wedged in the helper thread; connect a reader to
            // release it so the test can FAIL instead of hanging the suite.
            let _ = std::fs::File::open(&fifo);
            panic!("acquire_update_lock must complete promptly with a FIFO lock file");
        };
        match acquired {
            Err(UpdateError::SwapFailed(_)) => {}
            Err(other) => panic!("expected SwapFailed for a non-regular lock file, got: {other}"),
            Ok(Some(_)) => panic!("a FIFO lock path must not yield a lock"),
            Ok(None) => panic!("a FIFO lock path must not silently degrade to unlocked"),
        }
    }

    /// An OPENABLE non-regular lock file must be rejected by the
    /// handle-based `is_file` check. The FIFO test above never reaches that
    /// check — a reader-less FIFO fails the O_NONBLOCK open itself (ENXIO)
    /// — so this plants a symlink to `/dev/null` instead: the open follows
    /// the link and succeeds on the char device, and only the fstat
    /// rejection stands between that handle and a bogus flock.
    #[cfg(unix)]
    #[test]
    #[serial(update_state_dir_env)]
    fn update_lock_rejects_openable_non_regular_lock_file() {
        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("SOCKET_UPDATE_STATE_DIR");
        std::env::set_var("SOCKET_UPDATE_STATE_DIR", tmp.path());
        std::os::unix::fs::symlink("/dev/null", tmp.path().join("update.lock")).unwrap();

        let result = acquire_update_lock();

        match prev {
            Some(v) => std::env::set_var("SOCKET_UPDATE_STATE_DIR", v),
            None => std::env::remove_var("SOCKET_UPDATE_STATE_DIR"),
        }
        match result {
            Err(UpdateError::SwapFailed(msg)) => assert!(
                msg.contains("not a regular file"),
                "an openable non-regular lock must be caught by the is_file \
                 check, not the open error the FIFO test exercises: {msg}"
            ),
            Err(other) => panic!("expected SwapFailed for a device lock file, got: {other}"),
            Ok(Some(_)) => panic!("a /dev/null lock path must not yield a lock"),
            Ok(None) => panic!("a /dev/null lock path must not silently degrade to unlocked"),
        }
    }

    /// The rename-EACCES → `PermissionDenied { path: parent }` mapping —
    /// the error code the CLI turns into the sudo hint. The read-only
    /// install-dir e2e never reaches it: staging fails first (the stage
    /// file cannot be created in the read-only dir), so `swap_binary` is
    /// never called there. This is what a user sees when the install dir
    /// becomes unwritable between stage and swap.
    #[cfg(unix)]
    #[test]
    fn swap_rename_permission_denied_maps_to_parent_path() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        let dest = bin_dir.join("socket-patch");
        std::fs::write(&dest, b"old").unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
        let staged = bin_dir.join(".socket-patch.stage-test");
        std::fs::write(&staged, b"new").unwrap();
        std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        // Root ignores directory write bits: probe, don't assume.
        if std::fs::File::create(bin_dir.join("probe")).is_ok() {
            let _ = std::fs::remove_file(bin_dir.join("probe"));
            std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("skipping: running as root, read-only dir is not enforced");
            return;
        }

        // dest's stat succeeds, no setuid, and the file chmod at the
        // mode-carry step succeeds too (chmod needs ownership, not dir
        // write) — so this fails exactly at the rename.
        let result = swap_binary(&staged, &dest);

        // Restore writability BEFORE asserting so TempDir cleanup can't
        // wedge on a read-only dir.
        std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = result.unwrap_err();
        assert!(
            matches!(err, UpdateError::PermissionDenied { ref path } if *path == bin_dir),
            "rename EACCES must map to PermissionDenied on the parent dir: {err}"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"old",
            "a failed rename must leave the target untouched"
        );
        // No stage-cleanup assertion: the failure IS an unwritable dir, so
        // the best-effort remove cannot succeed — the age-gated
        // sweep_stale_stages owns that leftover by design.
    }

    /// A rename failure that is NOT permission-shaped (here: dest is an
    /// existing directory ⇒ EISDIR) must stay `SwapFailed` with the
    /// "rename onto" context — and must still clean the stage, proving the
    /// failure cleanup for a POST-refusal rename error in a writable dir
    /// (the setuid test only proves it for pre-rename refusals).
    #[cfg(unix)]
    #[test]
    fn swap_rename_onto_directory_is_swap_failed_and_cleans_stage() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("destdir");
        std::fs::create_dir(&dest).unwrap();
        let staged = tmp.path().join(".socket-patch.stage-test");
        std::fs::write(&staged, b"new").unwrap();

        let err = swap_binary(&staged, &dest).unwrap_err();

        assert!(
            matches!(err, UpdateError::SwapFailed(ref msg) if msg.contains("rename onto")),
            "a non-EACCES rename failure must stay SwapFailed: {err}"
        );
        assert!(
            dest.is_dir(),
            "the obstructing directory must be left alone"
        );
        assert!(
            !staged.exists(),
            "the failure path must clean the stage even when the rename \
             itself is what failed"
        );
    }

    /// Pins the canonicalization contract in-process: the swap target is
    /// the symlink-resolved current executable (macOS `current_exe` can
    /// return the symlink used to exec), not the raw `current_exe` value.
    #[test]
    fn resolve_install_path_is_canonicalized_current_exe() {
        let path = resolve_install_path().unwrap();
        assert!(path.is_absolute());
        assert_eq!(
            path,
            std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
            "the swap target must be the canonicalized current exe"
        );
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
