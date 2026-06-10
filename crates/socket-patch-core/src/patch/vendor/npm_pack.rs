//! Deterministic npm tarball packing for the vendor backend.
//!
//! The tarball's sha512 lands in the committed lockfile's `integrity` field
//! ([`super::npm_lock`]), so packing the same patched tree MUST yield the
//! same bytes every time: any churn would dirty `package-lock.json` +
//! `.socket/vendor/` on every re-run and break the "re-vendor is a no-op"
//! idempotency contract. Determinism is achieved the same way `npm pack`
//! does it — fixed entry metadata (npm's well-known 1985 mtime, uid/gid 0,
//! normalized modes), entries sorted by path, and a gzip stream with a
//! zeroed header mtime and a pinned compression level.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::utils::fs::atomic_write_bytes;

/// npm's fixed tar entry mtime: `1985-10-26T08:15:00Z`. Every `npm pack`
/// tarball carries this timestamp (npm pins it for reproducible packs);
/// reusing it keeps our artifacts byte-deterministic AND familiar to any
/// tooling that special-cases the value.
const NPM_PACK_MTIME: u64 = 499_162_500;

/// Result of [`pack_deterministic`]: the identity facts of the written
/// tarball, computed over the FINAL on-disk bytes (exactly what npm hashes
/// when it verifies `integrity`).
pub struct PackedTarball {
    /// SRI string: `"sha512-" + base64(sha512(tgz bytes))`.
    pub integrity: String,
    /// Plain sha256 hex of the tgz bytes (the vendor ledger's artifact hash).
    pub sha256_hex: String,
    /// Plain sha1 hex of the tgz bytes (the checksum field yarn-classic and
    /// other legacy lockfile flavors record for tarballs).
    pub sha1_hex: String,
    /// Byte size of the tgz.
    pub size: u64,
}

/// Pack every regular file under `staged_dir` into an npm-conventional
/// `package/`-prefixed tar.gz at `dest`, deterministically (see module docs).
///
/// Entries are sorted lexicographically by full entry path bytes; symlinks
/// and special files are skipped (a registry npm package contains none, and
/// a symlink in a tarball npm extracts would be an escape hazard). The write
/// is atomic (stage + rename) so a crash never leaves a torn artifact that a
/// later `npm ci` would fail integrity-checking with a confusing error.
pub async fn pack_deterministic(staged_dir: &Path, dest: &Path) -> std::io::Result<PackedTarball> {
    let staged = staged_dir.to_path_buf();
    // tar + flate2 are synchronous; run the whole pack on the blocking pool.
    let bytes = tokio::task::spawn_blocking(move || pack_to_bytes(&staged))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))??;

    atomic_write_bytes(dest, &bytes).await?;

    let integrity = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes))
    );
    Ok(PackedTarball {
        integrity,
        sha256_hex: hex::encode(Sha256::digest(&bytes)),
        sha1_hex: hex::encode(Sha1::digest(&bytes)),
        size: bytes.len() as u64,
    })
}

/// Build the deterministic tar.gz in memory (vendored packages are small —
/// the same size class the apply pipeline already buffers per-file).
fn pack_to_bytes(staged_dir: &Path) -> std::io::Result<Vec<u8>> {
    let mut files = collect_regular_files(staged_dir)?;
    // Lexicographic byte order of the full entry path — the deterministic,
    // platform-independent ordering (String's Ord is byte-wise, but spell it
    // out so a future refactor can't accidentally switch to a locale sort).
    files.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

    // Pin the compression level explicitly: `Compression::default()` is 6
    // today, but a flate2 default bump would silently churn every committed
    // integrity hash, so the level must never float. flate2's GzEncoder
    // header is already deterministic (GzBuilder defaults: mtime = 0, OS
    // byte = 255 "unknown" — verified against flate2 1.1.9 source); the
    // determinism test below byte-compares two packs to lock that in.
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
    let mut builder = tar::Builder::new(gz);

    for (entry_path, abs_path, executable) in &files {
        let data = std::fs::read(abs_path)?;
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(data.len() as u64);
        // Normalized modes, like `npm pack`: 0o644, or 0o755 when the source
        // carries any exec bit (preserving WHICH user had exec would leak
        // host umask into the bytes).
        header.set_mode(if *executable { 0o755 } else { 0o644 });
        header.set_mtime(NPM_PACK_MTIME);
        header.set_uid(0);
        header.set_gid(0);
        // uname/gname stay empty (a GNU header is zero-initialized) — real
        // user names would differ per host and break determinism.
        builder.append_data(&mut header, entry_path, data.as_slice())?;
    }

    builder.into_inner()?.finish()
}

/// Walk `staged_dir` and return `(entry_path, abs_path, executable)` for
/// every regular file, with entry paths `package/`-prefixed and
/// forward-slashed (the npm tarball convention on every platform).
fn collect_regular_files(staged_dir: &Path) -> std::io::Result<Vec<(String, PathBuf, bool)>> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(staged_dir).follow_links(false) {
        let entry = entry.map_err(|e| std::io::Error::other(e.to_string()))?;
        // Regular files only: directories are implicit in member paths (npm
        // tarballs carry no dir entries), and symlinks/specials are skipped —
        // following one could read content from outside the staged tree.
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(staged_dir)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut parts = Vec::new();
        for component in rel.components() {
            match component {
                std::path::Component::Normal(seg) => {
                    parts.push(seg.to_str().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("non-UTF-8 file name in staged package: {rel:?}"),
                        )
                    })?);
                }
                // walkdir under strip_prefix yields only Normal components;
                // anything else means the path math broke — refuse rather
                // than emit a malformed entry path.
                other => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unexpected path component {other:?} in staged package"),
                    ));
                }
            }
        }
        let executable = is_executable(&entry.metadata().map_err(|e| {
            std::io::Error::other(e.to_string())
        })?);
        files.push((format!("package/{}", parts.join("/")), entry.into_path(), executable));
    }
    Ok(files)
}

fn is_executable(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    /// Build a small staged tree with nested dirs, an executable, and an
    /// empty directory (which must NOT produce a tar entry).
    async fn build_stage(root: &Path) {
        tokio::fs::create_dir_all(root.join("lib/nested")).await.unwrap();
        tokio::fs::create_dir_all(root.join("empty-dir")).await.unwrap();
        tokio::fs::write(root.join("package.json"), b"{\"name\":\"x\"}\n").await.unwrap();
        tokio::fs::write(root.join("index.js"), b"module.exports = 1;\n").await.unwrap();
        tokio::fs::write(root.join("lib/nested/deep.js"), b"deep\n").await.unwrap();
        tokio::fs::write(root.join("cli.sh"), b"#!/bin/sh\n").await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(
                root.join("cli.sh"),
                std::fs::Permissions::from_mode(0o755),
            )
            .await
            .unwrap();
        }
    }

    fn read_entries(tgz: &[u8]) -> Vec<(String, u64, u64, u64, u32, Vec<u8>)> {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tgz));
        let mut out = Vec::new();
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let header = entry.header();
            let (mtime, uid, gid, mode) = (
                header.mtime().unwrap(),
                header.uid().unwrap(),
                header.gid().unwrap(),
                header.mode().unwrap(),
            );
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            out.push((path, mtime, uid, gid, mode, data));
        }
        out
    }

    #[tokio::test]
    async fn pack_is_byte_deterministic_and_reports_true_hashes() {
        let tmp = tempfile::tempdir().unwrap();
        let stage = tmp.path().join("stage");
        build_stage(&stage).await;

        let dest1 = tmp.path().join("a.tgz");
        let dest2 = tmp.path().join("b.tgz");
        let packed1 = pack_deterministic(&stage, &dest1).await.unwrap();
        let packed2 = pack_deterministic(&stage, &dest2).await.unwrap();

        let bytes1 = tokio::fs::read(&dest1).await.unwrap();
        let bytes2 = tokio::fs::read(&dest2).await.unwrap();
        assert_eq!(bytes1, bytes2, "two packs of the same tree must be byte-identical");
        assert_eq!(packed1.sha256_hex, packed2.sha256_hex);
        assert_eq!(packed1.sha1_hex, packed2.sha1_hex, "sha1 stable across packs");
        assert_eq!(packed1.integrity, packed2.integrity);

        // The reported facts describe the final on-disk bytes.
        assert_eq!(packed1.size, bytes1.len() as u64);
        assert_eq!(packed1.sha256_hex, hex::encode(Sha256::digest(&bytes1)));
        assert_eq!(packed1.sha1_hex, hex::encode(Sha1::digest(&bytes1)));
        assert_eq!(packed1.sha1_hex.len(), 40, "sha1 hex is 40 chars");
        assert!(
            packed1.sha1_hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "sha1 hex must be hex digits only: {}",
            packed1.sha1_hex
        );
        let expected_integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes1))
        );
        assert_eq!(packed1.integrity, expected_integrity);

        // gzip header: mtime field (bytes 4..8) zeroed, OS byte 255 — the
        // two flate2 defaults our determinism depends on.
        assert_eq!(&bytes1[4..8], &[0, 0, 0, 0], "gzip header mtime must be 0");
        assert_eq!(bytes1[9], 255, "gzip header OS byte must be 255 (unknown)");
    }

    #[tokio::test]
    async fn entries_are_sorted_prefixed_and_normalized() {
        let tmp = tempfile::tempdir().unwrap();
        let stage = tmp.path().join("stage");
        build_stage(&stage).await;
        let dest = tmp.path().join("pkg.tgz");
        pack_deterministic(&stage, &dest).await.unwrap();

        let entries = read_entries(&tokio::fs::read(&dest).await.unwrap());
        let paths: Vec<&str> = entries.iter().map(|e| e.0.as_str()).collect();
        // Sorted by full entry path bytes; every path `package/`-prefixed;
        // no entry for the empty directory.
        assert_eq!(
            paths,
            vec![
                "package/cli.sh",
                "package/index.js",
                "package/lib/nested/deep.js",
                "package/package.json",
            ]
        );
        for (path, mtime, uid, gid, mode, data) in &entries {
            assert_eq!(*mtime, NPM_PACK_MTIME, "{path}: npm's fixed 1985 mtime");
            assert_eq!((*uid, *gid), (0, 0), "{path}: uid/gid must be 0");
            let expected_mode = if path == "package/cli.sh" && cfg!(unix) { 0o755 } else { 0o644 };
            assert_eq!(*mode, expected_mode, "{path}: normalized mode");
            assert!(!data.is_empty(), "{path}: content must round-trip");
        }
        // Content integrity spot check.
        let index = entries.iter().find(|e| e.0 == "package/index.js").unwrap();
        assert_eq!(index.5, b"module.exports = 1;\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        let stage = tmp.path().join("stage");
        build_stage(&stage).await;
        // An out-of-tree symlink: must neither appear nor be followed.
        tokio::fs::write(tmp.path().join("outside.txt"), b"outside").await.unwrap();
        std::os::unix::fs::symlink(tmp.path().join("outside.txt"), stage.join("link.txt"))
            .unwrap();

        let dest = tmp.path().join("pkg.tgz");
        pack_deterministic(&stage, &dest).await.unwrap();

        let entries = read_entries(&tokio::fs::read(&dest).await.unwrap());
        assert!(
            entries.iter().all(|e| !e.0.contains("link.txt") && !e.0.contains("outside")),
            "symlink leaked into the tarball: {:?}",
            entries.iter().map(|e| &e.0).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn write_is_atomic_no_stage_litter() {
        let tmp = tempfile::tempdir().unwrap();
        let stage = tmp.path().join("stage");
        build_stage(&stage).await;
        let dest_dir = tmp.path().join("out");
        tokio::fs::create_dir_all(&dest_dir).await.unwrap();
        pack_deterministic(&stage, &dest_dir.join("pkg.tgz")).await.unwrap();

        for entry in std::fs::read_dir(&dest_dir).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.starts_with(".socket-stage-"), "stage litter: {name}");
        }
    }
}
