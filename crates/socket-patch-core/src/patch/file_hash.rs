use std::path::Path;

use crate::hash::git_sha256::compute_git_sha256_from_reader;
use crate::utils::fs::open_regular_file;

/// Compute Git-compatible SHA256 hash of file contents using streaming.
///
/// Opens the file *once* via [`open_regular_file`] (non-blocking on Unix,
/// regular files only — see its docs for the FIFO/special-file rationale) and
/// derives the size from that open handle (an `fstat`), then streams the same
/// handle through the hasher without loading the entire file into memory.
///
/// Deriving the size from the open file descriptor — rather than `stat`-ing the
/// path separately and then re-opening it — is what makes this safe under
/// concurrent mutation. The patch engine hashes files that other processes (or
/// an attacker) may rename/replace at any moment. If we measured the size of
/// one path resolution and read the bytes of another, a swap to a *same-sized*
/// file would slip past the size-mismatch guard in
/// [`compute_git_sha256_from_reader`] and produce a hash whose Git header (the
/// size) and body came from different inodes. Reading both from the same `fd`
/// makes that impossible.
pub(crate) async fn compute_file_git_sha256(
    filepath: impl AsRef<Path>,
) -> Result<String, std::io::Error> {
    let (file, metadata) = open_regular_file(filepath.as_ref()).await?;

    // Size comes from the open handle (fstat), so it and the bytes we hash are
    // guaranteed to refer to the same inode even if the path is replaced.
    let file_size = metadata.len();
    let reader = tokio::io::BufReader::new(file);

    compute_git_sha256_from_reader(file_size, reader).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;

    #[tokio::test]
    async fn test_compute_file_git_sha256_matches_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        let content = b"Hello, World!";
        tokio::fs::write(&file_path, content).await.unwrap();

        let file_hash = compute_file_git_sha256(&file_path).await.unwrap();
        let bytes_hash = compute_git_sha256_from_bytes(content);

        assert_eq!(file_hash, bytes_hash);
    }

    #[tokio::test]
    async fn test_compute_file_git_sha256_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("empty.txt");

        tokio::fs::write(&file_path, b"").await.unwrap();

        let file_hash = compute_file_git_sha256(&file_path).await.unwrap();
        let bytes_hash = compute_git_sha256_from_bytes(b"");

        assert_eq!(file_hash, bytes_hash);
    }

    #[tokio::test]
    async fn test_compute_file_git_sha256_not_found() {
        let result = compute_file_git_sha256("/nonexistent/file.txt").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_compute_file_git_sha256_large_content() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("large.bin");

        // Create a file larger than the 8192 byte buffer
        let content: Vec<u8> = (0..20000).map(|i| (i % 256) as u8).collect();
        tokio::fs::write(&file_path, &content).await.unwrap();

        let file_hash = compute_file_git_sha256(&file_path).await.unwrap();
        let bytes_hash = compute_git_sha256_from_bytes(&content);

        assert_eq!(file_hash, bytes_hash);
    }

    /// A directory must be rejected with an error, not silently hashed as the
    /// empty blob. On some platforms reading a directory descriptor yields zero
    /// bytes; without the `is_file` guard that would return the hash of `""`
    /// and the patch engine would compare a real file's expected hash against a
    /// directory's bogus one.
    #[tokio::test]
    async fn test_compute_file_git_sha256_rejects_directory() {
        let dir = tempfile::tempdir().unwrap();

        let result = compute_file_git_sha256(dir.path()).await;
        let err = result.expect_err("hashing a directory must error");

        // On Unix a directory opens successfully and the `is_file` guard
        // rejects it with `InvalidInput`. On Windows `File::open` on a
        // directory fails at the open call itself (a different OS error kind),
        // so we only pin the specific kind off-Windows. Either way the
        // contract that matters holds: it errors and never hashes.
        #[cfg(not(windows))]
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);

        // It must specifically NOT have returned the empty-blob hash.
        let empty_blob = compute_git_sha256_from_bytes(b"");
        assert_ne!(
            err.to_string(),
            empty_blob,
            "directory should error, never produce the empty-blob hash"
        );
    }

    /// A symlink to a regular file follows through `File::open` and hashes the
    /// target's contents (the size also comes from the resolved file via
    /// fstat), matching a direct byte hash of that content.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_compute_file_git_sha256_follows_symlink_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        let link = dir.path().join("link.txt");

        let content = b"symlinked content";
        tokio::fs::write(&target, content).await.unwrap();
        tokio::fs::symlink(&target, &link).await.unwrap();

        let link_hash = compute_file_git_sha256(&link).await.unwrap();
        let bytes_hash = compute_git_sha256_from_bytes(content);

        assert_eq!(link_hash, bytes_hash);
    }

    /// A symlink whose target is a directory must be rejected, exactly like a
    /// directory passed directly — the `is_file` check operates on the resolved
    /// open handle.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_compute_file_git_sha256_rejects_symlink_to_directory() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("subdir");
        let link = dir.path().join("dirlink");

        tokio::fs::create_dir(&subdir).await.unwrap();
        tokio::fs::symlink(&subdir, &link).await.unwrap();

        let result = compute_file_git_sha256(&link).await;
        let err = result.expect_err("symlink to a directory must error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// A FIFO at the hashed path must be rejected promptly with an error, not
    /// block forever. A plain `open(2)` with `O_RDONLY` on a FIFO waits for a
    /// writer that never comes, so without a non-blocking open the `is_file`
    /// guard is unreachable for exactly the special-file case it documents —
    /// a FIFO planted at a manifest-listed path would hang apply/rollback
    /// verification indefinitely.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_compute_file_git_sha256_rejects_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");

        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo must be runnable");
        assert!(status.success(), "mkfifo failed");

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            compute_file_git_sha256(&fifo),
        )
        .await;

        let Ok(result) = result else {
            // The open is wedged in a `spawn_blocking` thread that the runtime
            // waits for on shutdown; connect a writer to release it so this
            // test can FAIL instead of hanging the whole suite.
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
            panic!("hashing a FIFO must error promptly, not hang");
        };

        let err = result.expect_err("FIFO must be rejected, never hashed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// A broken symlink (dangling target) must surface the open error rather
    /// than panicking or returning a hash.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_compute_file_git_sha256_broken_symlink_errors() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("dangling");

        tokio::fs::symlink(dir.path().join("does-not-exist"), &link)
            .await
            .unwrap();

        let result = compute_file_git_sha256(&link).await;
        assert!(result.is_err(), "dangling symlink must error");
    }
}
