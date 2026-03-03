use sha2::{Digest, Sha256};
use std::io;
use tokio::io::AsyncReadExt;

/// Compute Git-compatible SHA256 hash for a byte slice.
///
/// Git hashes objects as: SHA256("blob <size>\0" + content)
pub fn compute_git_sha256_from_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    let header = format!("blob {}\0", data.len());
    hasher.update(header.as_bytes());
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute Git-compatible SHA256 hash from an async reader with known size.
///
/// This streams the content through the hasher without loading it all into memory.
pub async fn compute_git_sha256_from_reader<R: tokio::io::AsyncRead + Unpin>(
    size: u64,
    mut reader: R,
) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let header = format!("blob {}\0", size);
    hasher.update(header.as_bytes());

    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_content() {
        let hash = compute_git_sha256_from_bytes(b"");
        // SHA256("blob 0\0") - Git-compatible hash of empty content
        assert_eq!(hash.len(), 64);
        // Verify it's consistent
        assert_eq!(hash, compute_git_sha256_from_bytes(b""));
    }

    #[test]
    fn test_hello_world() {
        let content = b"Hello, World!";
        let hash = compute_git_sha256_from_bytes(content);
        assert_eq!(hash.len(), 64);

        // Manually compute expected: SHA256("blob 13\0Hello, World!")
        use sha2::{Digest, Sha256};
        let mut expected_hasher = Sha256::new();
        expected_hasher.update(b"blob 13\0Hello, World!");
        let expected = hex::encode(expected_hasher.finalize());
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_known_vector() {
        // Known test vector: SHA256("blob 0\0")
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"blob 0\0");
        let expected = hex::encode(hasher.finalize());
        assert_eq!(compute_git_sha256_from_bytes(b""), expected);
    }

    #[tokio::test]
    async fn test_async_reader_matches_sync() {
        let content = b"test content for async hashing";
        let sync_hash = compute_git_sha256_from_bytes(content);

        let cursor = tokio::io::BufReader::new(&content[..]);
        let async_hash =
            compute_git_sha256_from_reader(content.len() as u64, cursor)
                .await
                .unwrap();

        assert_eq!(sync_hash, async_hash);
    }
}
