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
///
/// The `size` is written into the Git object header *before* the body is read,
/// so it must match the number of bytes the reader actually yields. If it does
/// not (for example, the underlying file was truncated or extended between the
/// time its size was measured and the time it was read), the resulting hash
/// would correspond to no real Git object. Rather than silently return a
/// corrupt hash, this function reports an [`io::Error`] when the byte count
/// disagrees with `size`.
pub async fn compute_git_sha256_from_reader<R: tokio::io::AsyncRead + Unpin>(
    size: u64,
    mut reader: R,
) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let header = format!("blob {}\0", size);
    hasher.update(header.as_bytes());

    let mut buf = [0u8; 8192];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }

    if total != size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "git sha256: declared size {size} does not match {total} bytes read from stream"
            ),
        ));
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

    /// Known-answer vectors computed with the actual Git SHA256 object format
    /// (`SHA256("blob <size>\0<content>")`). These pin the algorithm to real
    /// Git output so a regression cannot hide behind the self-consistent
    /// reader-vs-bytes comparisons elsewhere in this module.
    #[test]
    fn test_git_known_answer_vectors() {
        // `printf 'blob 0\0' | shasum -a 256`
        assert_eq!(
            compute_git_sha256_from_bytes(b""),
            "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813",
        );
        // `printf 'blob 13\0Hello, World!' | shasum -a 256`
        assert_eq!(
            compute_git_sha256_from_bytes(b"Hello, World!"),
            "e118a058f018dda253bb692320c940091b15e4f19067e12fff110606a111f5da",
        );
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
        let async_hash = compute_git_sha256_from_reader(content.len() as u64, cursor)
            .await
            .unwrap();

        assert_eq!(sync_hash, async_hash);
    }

    /// Exercise the streaming loop across many buffer-sized reads (the 8192
    /// byte buffer is filled multiple times). Guards against off-by-one or
    /// partial-read mistakes in the chunked update loop.
    #[tokio::test]
    async fn test_async_reader_multiple_chunks() {
        let content: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let sync_hash = compute_git_sha256_from_bytes(&content);

        let cursor = tokio::io::BufReader::new(&content[..]);
        let async_hash = compute_git_sha256_from_reader(content.len() as u64, cursor)
            .await
            .unwrap();

        assert_eq!(sync_hash, async_hash);
    }

    /// A declared size larger than the stream (e.g. the file was truncated
    /// after its size was measured) must be reported as an error, not hashed
    /// into a silently-corrupt object id.
    #[tokio::test]
    async fn test_async_reader_size_too_large_errors() {
        let content = b"short";
        let cursor = tokio::io::BufReader::new(&content[..]);
        let result = compute_git_sha256_from_reader(content.len() as u64 + 100, cursor).await;

        let err = result.expect_err("size larger than stream must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// A declared size smaller than the stream (e.g. the file grew after its
    /// size was measured) must likewise be reported rather than producing a
    /// hash whose header disagrees with its body.
    #[tokio::test]
    async fn test_async_reader_size_too_small_errors() {
        let content = b"this stream is longer than declared";
        let cursor = tokio::io::BufReader::new(&content[..]);
        let result = compute_git_sha256_from_reader(4, cursor).await;

        let err = result.expect_err("size smaller than stream must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// An [`AsyncRead`] that yields at most one byte per `read` call, modelling
    /// a reader that never fills the buffer in a single call (sockets, pipes,
    /// rate-limited streams). The chunked update loop must reassemble the body
    /// correctly across many partial reads rather than assuming a single read
    /// fills the buffer.
    struct OneBytePerReadReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl tokio::io::AsyncRead for OneBytePerReadReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if self.pos < self.data.len() && buf.remaining() > 0 {
                let byte = self.data[self.pos];
                self.pos += 1;
                buf.put_slice(&[byte]);
            }
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn test_async_reader_short_reads_reassemble() {
        let content: Vec<u8> = (0..20_000u32).map(|i| (i % 97) as u8).collect();
        let sync_hash = compute_git_sha256_from_bytes(&content);

        let reader = OneBytePerReadReader {
            data: content.clone(),
            pos: 0,
        };
        let async_hash = compute_git_sha256_from_reader(content.len() as u64, reader)
            .await
            .unwrap();

        assert_eq!(sync_hash, async_hash);
    }

    /// Content whose length is an exact multiple of the 8192-byte internal
    /// buffer, so the final `read` returns 0 on a buffer boundary rather than
    /// on a partially-filled buffer. Guards the loop's EOF handling at the
    /// boundary case.
    #[tokio::test]
    async fn test_async_reader_exact_buffer_boundary() {
        let content: Vec<u8> = (0..16_384u32).map(|i| (i % 251) as u8).collect();
        let sync_hash = compute_git_sha256_from_bytes(&content);

        let cursor = tokio::io::BufReader::new(&content[..]);
        let async_hash = compute_git_sha256_from_reader(content.len() as u64, cursor)
            .await
            .unwrap();

        assert_eq!(sync_hash, async_hash);
    }

    /// A zero-length stream with a correctly-declared size of 0 must hash to
    /// the canonical Git empty-blob id, matching the byte-slice path.
    #[tokio::test]
    async fn test_async_reader_empty_stream() {
        let cursor = tokio::io::BufReader::new(&b""[..]);
        let async_hash = compute_git_sha256_from_reader(0, cursor).await.unwrap();
        assert_eq!(async_hash, compute_git_sha256_from_bytes(b""));
    }
}
