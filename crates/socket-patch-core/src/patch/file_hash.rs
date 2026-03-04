use std::path::Path;

use crate::hash::git_sha256::compute_git_sha256_from_reader;

/// Compute Git-compatible SHA256 hash of file contents using streaming.
///
/// Gets the file size first, then streams the file through the hasher
/// without loading the entire file into memory.
pub async fn compute_file_git_sha256(filepath: impl AsRef<Path>) -> Result<String, std::io::Error> {
    let filepath = filepath.as_ref();

    // Get file size first
    let metadata = tokio::fs::metadata(filepath).await?;
    let file_size = metadata.len();

    // Open file for streaming read
    let file = tokio::fs::File::open(filepath).await?;
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
}
