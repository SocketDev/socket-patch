//! Package- and diff-archive tarball helpers.
//!
//! Both package archives (`.socket/packages/<uuid>.tar.gz`) and diff
//! archives (`.socket/diffs/<uuid>.tar.gz`) use the same on-disk format:
//! a gzipped tar containing one entry per patched file. The entry's path
//! matches the **normalized** relative file path (i.e. without the
//! `package/` prefix used by the API).
//!
//! For package archives, each entry holds the patched file's full bytes.
//! For diff archives, each entry holds a bsdiff delta that transforms the
//! corresponding `beforeHash` content into the `afterHash` content.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;
use tar::Archive;

use crate::manifest::schema::PatchFileInfo;

/// Maximum cumulative *decompressed* bytes we accept from a single
/// archive. Real socket-patch archives are tiny (kilobytes); 64 MiB is a
/// generous ceiling. Beyond this we assume gzip/tar bomb and refuse.
const MAX_TOTAL_DECOMPRESSED_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum size of any single archive entry, in bytes. Caps the buffer
/// we'll allocate per entry, defusing header-driven `with_capacity`
/// allocation attacks.
const MAX_ENTRY_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum number of entries in an archive. Defuses
/// "tar-of-a-million-empty-files" memory-exhaustion attacks against
/// the in-memory `HashMap`.
const MAX_ENTRIES: usize = 10_000;

/// Errors produced while reading a package/diff archive.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    #[error("archive I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("entry path {0:?} escapes the archive root")]
    UnsafePath(String),
    #[error("entry {path:?} is {size} bytes (max {max})")]
    EntryTooLarge { path: String, size: u64, max: u64 },
    #[error("archive contains more than {0} entries")]
    TooManyEntries(usize),
}

/// Strip the leading `package/` prefix from an entry path, matching the
/// convention used by `normalize_file_path` in `apply.rs`.
fn normalize_entry_path(path: &str) -> &str {
    path.strip_prefix("package/").unwrap_or(path)
}

/// Read a `.tar.gz` archive into a map of `normalized_path -> bytes`.
///
/// Returns an error if any entry path is absolute or contains `..`
/// components. Symlinks and other non-regular entries are silently
/// skipped. The reader is hard-capped against decompression-bomb /
/// memory-exhaustion attacks: cumulative decompressed bytes,
/// per-entry size, and entry count are all bounded.
///
/// Note: we never call `tar::Archive::unpack`; the bytes are buffered
/// and later written through `apply_file_patch` to an explicit
/// `pkg_path.join(normalized)`. That avoids the classic
/// symlink-followed-by-write class of tar-extraction attacks at the
/// extraction step itself — the on-disk write site is the single,
/// hash-verified path inside `apply_file_patch`.
pub fn read_archive_to_map(archive_path: &Path) -> Result<HashMap<String, Vec<u8>>, ArchiveError> {
    let file = std::fs::File::open(archive_path)?;
    // Hard-cap decompressed bytes to defuse gzip / tar bombs. Reads
    // beyond the limit yield EOF, which the tar parser surfaces as a
    // truncated-archive error.
    let bounded = GzDecoder::new(file).take(MAX_TOTAL_DECOMPRESSED_BYTES);
    let mut tar = Archive::new(bounded);

    let mut out: HashMap<String, Vec<u8>> = HashMap::new();
    let mut entry_count: usize = 0;
    for entry in tar.entries()? {
        let mut entry = entry?;

        entry_count += 1;
        if entry_count > MAX_ENTRIES {
            return Err(ArchiveError::TooManyEntries(MAX_ENTRIES));
        }

        // Only regular files. Skip directories, symlinks, hardlinks, etc.
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }

        let path = entry.path()?;
        let path_str = path.to_string_lossy().to_string();

        // Reject absolute paths or any `..` components.
        if path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(ArchiveError::UnsafePath(path_str));
        }

        // The header-declared size is attacker-controlled. Reject
        // oversize entries *before* allocating so a single u64::MAX
        // claim can't OOM the process via `Vec::with_capacity`.
        let size = entry.size();
        if size > MAX_ENTRY_BYTES {
            return Err(ArchiveError::EntryTooLarge {
                path: path_str,
                size,
                max: MAX_ENTRY_BYTES,
            });
        }

        let normalized = normalize_entry_path(&path_str).to_string();
        // `size` is bounded above by MAX_ENTRY_BYTES (16 MiB), so the
        // cast to `usize` is safe on all targets we support.
        let mut bytes = Vec::with_capacity(size as usize);
        entry.read_to_end(&mut bytes)?;
        out.insert(normalized, bytes);
    }

    Ok(out)
}

/// Subset of `read_archive_to_map` that only keeps entries whose normalized
/// path appears in `expected_files`. Anything else in the archive is
/// silently dropped — this is defense-in-depth so a malicious archive
/// cannot drop arbitrary files into the package directory.
pub fn read_archive_filtered(
    archive_path: &Path,
    expected_files: &HashMap<String, PatchFileInfo>,
) -> Result<HashMap<String, Vec<u8>>, ArchiveError> {
    let allowed: std::collections::HashSet<String> = expected_files
        .keys()
        .map(|k| normalize_entry_path(k).to_string())
        .collect();

    let all = read_archive_to_map(archive_path)?;
    Ok(all
        .into_iter()
        .filter(|(k, _)| allowed.contains(k))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    use tar::Builder;

    fn write_archive(path: &Path, entries: &[(&str, &[u8])]) {
        let file = std::fs::File::create(path).unwrap();
        let gz = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(gz);
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }

    fn write_archive_with_symlink(path: &Path, link_name: &str, target: &str) {
        let file = std::fs::File::create(path).unwrap();
        let gz = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_link(&mut header, link_name, target)
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }

    fn make_file_info() -> HashMap<String, PatchFileInfo> {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: "a".repeat(64),
                after_hash: "b".repeat(64),
            },
        );
        files.insert(
            "lib/util.js".to_string(),
            PatchFileInfo {
                before_hash: "c".repeat(64),
                after_hash: "d".repeat(64),
            },
        );
        files
    }

    #[test]
    fn test_read_archive_basic() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("arc.tar.gz");
        write_archive(
            &archive,
            &[
                ("package/index.js", b"patched index"),
                ("lib/util.js", b"patched util"),
            ],
        );

        let map = read_archive_to_map(&archive).unwrap();
        assert_eq!(map.len(), 2);
        // The "package/" prefix is stripped.
        assert_eq!(map.get("index.js").unwrap(), b"patched index");
        assert_eq!(map.get("lib/util.js").unwrap(), b"patched util");
    }

    /// Craft a single-entry ustar archive with `name` written verbatim
    /// into the header, bypassing the writer-side path validation that
    /// rejects absolute paths and `..`. This lets us exercise the
    /// defense-in-depth check inside [`read_archive_to_map`].
    fn write_raw_archive(path: &Path, name: &[u8], data: &[u8]) {
        let mut block = [0u8; 512];
        // Name (first 100 bytes).
        let copy_len = name.len().min(100);
        block[..copy_len].copy_from_slice(&name[..copy_len]);
        // Mode "0000644\0".
        block[100..108].copy_from_slice(b"0000644\0");
        // Size as octal in 11 chars + NUL.
        let size_str = format!("{:011o}", data.len());
        block[124..135].copy_from_slice(size_str.as_bytes());
        block[135] = 0;
        // mtime
        block[136..147].copy_from_slice(b"00000000000");
        block[147] = 0;
        // typeflag '0' = normal file
        block[156] = b'0';
        // ustar magic
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        // Checksum: spaces during compute.
        block[148..156].fill(b' ');
        let sum: u32 = block.iter().map(|&b| b as u32).sum();
        let sum_str = format!("{:06o}\0 ", sum);
        block[148..156].copy_from_slice(sum_str.as_bytes());

        let mut tar_bytes = Vec::new();
        tar_bytes.extend_from_slice(&block);
        tar_bytes.extend_from_slice(data);
        // Pad data to 512-byte boundary.
        let pad = (512 - (data.len() % 512)) % 512;
        tar_bytes.extend(std::iter::repeat_n(0u8, pad));
        // Two zero blocks mark end of archive.
        tar_bytes.extend([0u8; 1024]);

        let file = std::fs::File::create(path).unwrap();
        let mut gz = GzEncoder::new(file, Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap();
    }

    #[test]
    fn test_read_archive_rejects_absolute_paths() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("arc.tar.gz");
        write_raw_archive(&archive, b"/etc/passwd", b"evil");

        let err = read_archive_to_map(&archive).unwrap_err();
        assert!(matches!(err, ArchiveError::UnsafePath(_)));
    }

    #[test]
    fn test_read_archive_rejects_parent_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("arc.tar.gz");
        write_raw_archive(&archive, b"../../etc/passwd", b"evil");

        let err = read_archive_to_map(&archive).unwrap_err();
        assert!(matches!(err, ArchiveError::UnsafePath(_)));
    }

    #[test]
    fn test_read_archive_skips_non_regular_entries() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("arc.tar.gz");
        write_archive_with_symlink(&archive, "link", "target");
        // Symlink entries should be silently skipped.
        let map = read_archive_to_map(&archive).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn test_read_archive_filtered_drops_unexpected_entries() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("arc.tar.gz");
        write_archive(
            &archive,
            &[
                ("package/index.js", b"patched index"),
                ("lib/util.js", b"patched util"),
                ("bonus/extra.js", b"unwanted"),
            ],
        );

        let files = make_file_info();
        let map = read_archive_filtered(&archive, &files).unwrap();
        // Only the two expected paths survive.
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("index.js"));
        assert!(map.contains_key("lib/util.js"));
        assert!(!map.contains_key("bonus/extra.js"));
    }

    #[test]
    fn test_read_archive_missing_file() {
        let result = read_archive_to_map(Path::new("/nonexistent/archive.tar.gz"));
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_entry_path() {
        assert_eq!(normalize_entry_path("package/lib/x.js"), "lib/x.js");
        assert_eq!(normalize_entry_path("lib/x.js"), "lib/x.js");
        assert_eq!(normalize_entry_path("packagefoo/x.js"), "packagefoo/x.js");
    }

    #[test]
    fn test_read_archive_corrupt_gzip() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("bogus.tar.gz");
        std::fs::write(&archive, b"not actually gzipped").unwrap();
        let result = read_archive_to_map(&archive);
        assert!(result.is_err());
    }

    #[test]
    #[allow(clippy::needless_borrows_for_generic_args)]
    fn test_round_trip_via_builder() {
        // Confirms the helpers used to write tests actually work end-to-end.
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("rt.tar.gz");
        let original: &[u8] = b"hello world";
        write_archive(&archive, &[("only.txt", original)]);
        let map = read_archive_to_map(&archive).unwrap();
        assert_eq!(map.get("only.txt").map(|v| v.as_slice()), Some(original));
    }

    // ── Bomb defense tests ─────────────────────────────────────────────

    /// Build a raw tar entry whose header advertises a (potentially
    /// fake) `declared_size`, followed by `data` padded to the next 512
    /// boundary. Used to forge size-mismatched entries the writer would
    /// normally refuse.
    fn raw_entry(name: &[u8], declared_size: u64, data: &[u8]) -> Vec<u8> {
        let mut block = [0u8; 512];
        let copy_len = name.len().min(100);
        block[..copy_len].copy_from_slice(&name[..copy_len]);
        block[100..108].copy_from_slice(b"0000644\0");
        let size_str = format!("{:011o}", declared_size);
        block[124..135].copy_from_slice(size_str.as_bytes());
        block[135] = 0;
        block[136..147].copy_from_slice(b"00000000000");
        block[147] = 0;
        block[156] = b'0'; // regular file
        block[257..263].copy_from_slice(b"ustar\0");
        block[263..265].copy_from_slice(b"00");
        block[148..156].fill(b' ');
        let sum: u32 = block.iter().map(|&b| b as u32).sum();
        let sum_str = format!("{:06o}\0 ", sum);
        block[148..156].copy_from_slice(sum_str.as_bytes());

        let mut out = Vec::new();
        out.extend_from_slice(&block);
        out.extend_from_slice(data);
        let pad = if data.is_empty() {
            0
        } else {
            (512 - (data.len() % 512)) % 512
        };
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    fn write_raw_tar_gz(path: &Path, entries: &[Vec<u8>], trailer: bool) {
        let mut tar_bytes = Vec::new();
        for e in entries {
            tar_bytes.extend_from_slice(e);
        }
        if trailer {
            tar_bytes.extend([0u8; 1024]);
        }
        let file = std::fs::File::create(path).unwrap();
        let mut gz = GzEncoder::new(file, Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap();
    }

    #[test]
    fn test_read_archive_rejects_oversize_entry_header() {
        // Forge a header that claims a 1 GiB entry — well over
        // MAX_ENTRY_BYTES — backed by tiny actual data. Without the
        // size check, `Vec::with_capacity` would attempt the 1 GiB
        // allocation.
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("oversize.tar.gz");
        let entry = raw_entry(b"big.bin", 1024 * 1024 * 1024, b"tiny");
        write_raw_tar_gz(&archive, &[entry], true);

        let err = read_archive_to_map(&archive).unwrap_err();
        assert!(
            matches!(err, ArchiveError::EntryTooLarge { .. }),
            "expected EntryTooLarge, got {:?}",
            err
        );
    }

    #[test]
    fn test_read_archive_rejects_too_many_entries() {
        // Build an archive with one more entry than MAX_ENTRIES. Each
        // entry is empty so the archive itself is small.
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("many.tar.gz");
        let entries: Vec<Vec<u8>> = (0..(MAX_ENTRIES + 1))
            .map(|i| raw_entry(format!("f{i}").as_bytes(), 0, b""))
            .collect();
        write_raw_tar_gz(&archive, &entries, true);

        let err = read_archive_to_map(&archive).unwrap_err();
        assert!(
            matches!(err, ArchiveError::TooManyEntries(_)),
            "expected TooManyEntries, got {:?}",
            err
        );
    }

    #[test]
    fn test_read_archive_decompression_bomb_truncated() {
        // Build a tar containing one entry that legitimately fits
        // under MAX_ENTRY_BYTES but whose total content makes the
        // decompressed stream exceed MAX_TOTAL_DECOMPRESSED_BYTES.
        // We do this by chaining many MAX_ENTRY_BYTES-sized entries.
        //
        // The `Read::take(MAX_TOTAL_DECOMPRESSED_BYTES)` wrapper
        // truncates reads beyond the cap. After the cap is exhausted,
        // the next `entries()` iteration returns a malformed-archive
        // I/O error — which surfaces as `ArchiveError::Io`. We accept
        // either `Io` or `TooManyEntries` as evidence the bomb was
        // defused (whichever defense fires first).
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("bomb.tar.gz");

        // Two entries of (max - 1) MiB each = 30 MiB declared, but
        // gzip compresses zeroes ~1000x so the on-disk archive is small.
        // We don't need to *exceed* 64 MiB — the cap is enforced
        // strictly, so an entry that crosses it will be truncated.
        let chunk = vec![0u8; (MAX_ENTRY_BYTES - 1) as usize];
        let entry1 = raw_entry(b"a.bin", chunk.len() as u64, &chunk);
        let entry2 = raw_entry(b"b.bin", chunk.len() as u64, &chunk);
        let entry3 = raw_entry(b"c.bin", chunk.len() as u64, &chunk);
        let entry4 = raw_entry(b"d.bin", chunk.len() as u64, &chunk);
        // 4 * 15 MiB = 60 MiB declared, just under the 64 MiB cap.
        // Add a fifth to push us over.
        let entry5 = raw_entry(b"e.bin", chunk.len() as u64, &chunk);
        write_raw_tar_gz(&archive, &[entry1, entry2, entry3, entry4, entry5], true);

        let result = read_archive_to_map(&archive);
        // Either we get an Io error from truncation or the read
        // succeeds with the first ~4 entries — both prove the cap
        // prevented unbounded growth. Failure mode we want to RULE
        // OUT: reading all 5 entries (~75 MiB) without error.
        match result {
            Err(_) => { /* defused via Io / truncation */ }
            Ok(map) => {
                // If parsing didn't error, ensure we didn't ingest all 5.
                assert!(
                    map.len() < 5,
                    "decompression cap failed: ingested {} entries (~{} MiB)",
                    map.len(),
                    map.len() * (MAX_ENTRY_BYTES as usize - 1) / (1024 * 1024)
                );
            }
        }
    }
}
