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
///
/// To avoid draining an arbitrarily large (or slow/unbounded) stream once the
/// hash is already known to be invalid, the loop bails out as soon as the bytes
/// read exceed `size`; it does not keep reading just to report a larger total.
pub(crate) async fn compute_git_sha256_from_reader<R: tokio::io::AsyncRead + Unpin>(
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
        if total > size {
            // The stream already yielded more bytes than declared, so the hash
            // can never match a real Git object. Stop now rather than draining
            // the (possibly unbounded) remainder just to report a bigger total.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "git sha256: declared size {size} is smaller than the stream (read at least {total} bytes)"
                ),
            ));
        }
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

    /// An effectively endless reader that records how many bytes it has served.
    /// Used to prove that the over-size path does not drain the whole stream
    /// once it knows the declared size is already exceeded.
    struct EndlessReader {
        served: std::sync::Arc<std::sync::atomic::AtomicU64>,
    }

    impl tokio::io::AsyncRead for EndlessReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let n = buf.remaining();
            // Fill the buffer with arbitrary non-EOF data.
            let chunk = vec![0xABu8; n];
            buf.put_slice(&chunk);
            self.served
                .fetch_add(n as u64, std::sync::atomic::Ordering::SeqCst);
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// With a tiny declared size against an endless stream, the loop must error
    /// out promptly rather than reading without bound. We allow it to overshoot
    /// by at most one internal buffer (8192 bytes) before noticing.
    #[tokio::test]
    async fn test_async_reader_oversize_bails_without_draining() {
        let served = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reader = EndlessReader {
            served: served.clone(),
        };

        let result = compute_git_sha256_from_reader(10, reader).await;
        let err = result.expect_err("endless stream vs tiny size must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // It must have stopped after detecting the overshoot, not kept reading.
        let total_served = served.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            total_served <= 8192,
            "reader was drained for {total_served} bytes; should bail within one buffer"
        );
    }

    /// A zero-length stream with a correctly-declared size of 0 must hash to
    /// the canonical Git empty-blob id, matching the byte-slice path.
    #[tokio::test]
    async fn test_async_reader_empty_stream() {
        let cursor = tokio::io::BufReader::new(&b""[..]);
        let async_hash = compute_git_sha256_from_reader(0, cursor).await.unwrap();
        assert_eq!(async_hash, compute_git_sha256_from_bytes(b""));
    }

    /// Pin the *reader* path directly to real Git SHA256 output rather than
    /// only transitively via `compute_git_sha256_from_bytes`. A regression in
    /// how the reader builds its `blob <size>\0` header (wrong keyword, missing
    /// NUL, size off-by-one) would slip past the reader-vs-bytes equality tests
    /// if the bytes path regressed identically; this anchors it independently.
    #[tokio::test]
    async fn test_async_reader_known_answer_vectors() {
        // `printf 'blob 0\0' | shasum -a 256`
        let empty = tokio::io::BufReader::new(&b""[..]);
        assert_eq!(
            compute_git_sha256_from_reader(0, empty).await.unwrap(),
            "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813",
        );
        // `printf 'blob 13\0Hello, World!' | shasum -a 256`
        let body = b"Hello, World!";
        let cursor = tokio::io::BufReader::new(&body[..]);
        assert_eq!(
            compute_git_sha256_from_reader(body.len() as u64, cursor)
                .await
                .unwrap(),
            "e118a058f018dda253bb692320c940091b15e4f19067e12fff110606a111f5da",
        );
    }

    /// The error path must trigger on the *first* over-size byte: a stream that
    /// yields exactly `size` bytes and then one more must be rejected, not
    /// accepted on a boundary. Guards the strict `>` (vs `>=`) comparison and
    /// the placement of the check after the total bookkeeping.
    #[tokio::test]
    async fn test_async_reader_one_byte_over_errors() {
        let content = b"exactly-this-many-bytes";
        let cursor = tokio::io::BufReader::new(&content[..]);
        // Declare one fewer byte than the stream actually holds.
        let result = compute_git_sha256_from_reader(content.len() as u64 - 1, cursor).await;
        let err = result.expect_err("one byte over declared size must error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
