//! Integration coverage for `socket_patch_core::patch::package`.
//!
//! Exercises both `read_archive_to_map` and `read_archive_filtered`
//! across the happy path, the `package/` prefix stripping rule,
//! the unsafe-path guards (absolute paths, parent traversal,
//! Windows-style backslash paths), and non-regular entry skipping
//! (symlinks). Lives in `tests/` so the coverage tool counts it
//! against the integration bar rather than the lib bar.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use flate2::write::GzEncoder;
use flate2::Compression;
use socket_patch_core::manifest::schema::PatchFileInfo;
use socket_patch_core::patch::package::{read_archive_filtered, read_archive_to_map, ArchiveError};
use tar::Builder;

/// Helper: write a small gzipped tar archive containing `(name,
/// bytes)` entries. Mirrors what the API serves for `package`-mode
/// downloads.
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

/// Helper: craft an archive with a single symlink entry. The
/// reader must silently skip non-regular entries to avoid
/// surfacing tarballs-as-symlinks attacks.
fn write_archive_with_symlink(path: &Path, link_name: &str, target: &str) {
    let file = std::fs::File::create(path).unwrap();
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(gz);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_link(&mut header, link_name, target).unwrap();
    builder.into_inner().unwrap().finish().unwrap();
}

/// Hand-craft a one-entry ustar header with `name` written verbatim
/// to bypass tar::Builder's path-validation guard (which rejects
/// absolute paths and `..`). This lets us drive
/// `read_archive_to_map`'s defense-in-depth check.
fn write_raw_archive(path: &Path, name: &[u8], data: &[u8]) {
    let mut block = [0u8; 512];
    let copy_len = name.len().min(100);
    block[..copy_len].copy_from_slice(&name[..copy_len]);
    block[100..108].copy_from_slice(b"0000644\0");
    let size_str = format!("{:011o}", data.len());
    block[124..135].copy_from_slice(size_str.as_bytes());
    block[135] = 0;
    block[136..147].copy_from_slice(b"00000000000");
    block[147] = 0;
    block[156] = b'0';
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    // Checksum: spaces during compute, then overwrite.
    block[148..156].fill(b' ');
    let sum: u32 = block.iter().map(|&b| b as u32).sum();
    let sum_str = format!("{:06o}\0 ", sum);
    block[148..156].copy_from_slice(sum_str.as_bytes());

    let mut tar_bytes = Vec::new();
    tar_bytes.extend_from_slice(&block);
    tar_bytes.extend_from_slice(data);
    let pad = (512 - (data.len() % 512)) % 512;
    tar_bytes.extend(std::iter::repeat_n(0u8, pad));
    tar_bytes.extend([0u8; 1024]);

    let file = std::fs::File::create(path).unwrap();
    let mut gz = GzEncoder::new(file, Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    gz.finish().unwrap();
}

// ── read_archive_to_map ────────────────────────────────────────────

#[test]
fn read_archive_to_map_strips_package_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_archive(
        &archive,
        &[
            ("package/index.js", b"patched index"),
            ("lib/util.js", b"patched util"),
        ],
    );

    let map = read_archive_to_map(&archive).unwrap();
    assert_eq!(map.len(), 2);
    // `package/` prefix removed; `lib/` kept verbatim.
    assert_eq!(map.get("index.js").unwrap(), b"patched index");
    assert_eq!(map.get("lib/util.js").unwrap(), b"patched util");
}

#[test]
fn read_archive_to_map_rejects_absolute_path() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"/etc/passwd", b"evil");

    let err = read_archive_to_map(&archive).unwrap_err();
    assert!(matches!(err, ArchiveError::UnsafePath(_)));
}

#[test]
fn read_archive_to_map_rejects_backslash_absolute_path() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"\\Windows\\System32\\evil.dll", b"evil");

    let err = read_archive_to_map(&archive).unwrap_err();
    assert!(matches!(err, ArchiveError::UnsafePath(_)));
}

#[test]
fn read_archive_to_map_rejects_parent_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"../../etc/passwd", b"evil");

    let err = read_archive_to_map(&archive).unwrap_err();
    assert!(matches!(err, ArchiveError::UnsafePath(_)));
}

#[test]
fn read_archive_to_map_skips_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_archive_with_symlink(&archive, "link", "target");
    let map = read_archive_to_map(&archive).unwrap();
    assert!(map.is_empty(), "symlink entries must be silently dropped");
}

#[test]
fn read_archive_to_map_handles_missing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let result = read_archive_to_map(&tmp.path().join("nope.tar.gz"));
    assert!(result.is_err(), "missing archive must surface as Err");
}

#[test]
fn read_archive_to_map_handles_corrupt_gzip() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    std::fs::write(&archive, b"not a gzip stream").unwrap();
    let result = read_archive_to_map(&archive);
    assert!(result.is_err());
}

// ── read_archive_filtered ──────────────────────────────────────────

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
fn read_archive_filtered_keeps_only_listed_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_archive(
        &archive,
        &[
            ("package/index.js", b"patched index"),
            ("lib/util.js", b"patched util"),
            ("bonus/extra.js", b"unwanted"),
        ],
    );

    let filtered = read_archive_filtered(&archive, &make_file_info()).unwrap();
    assert_eq!(filtered.len(), 2);
    assert!(filtered.contains_key("index.js"));
    assert!(filtered.contains_key("lib/util.js"));
    assert!(
        !filtered.contains_key("bonus/extra.js"),
        "filter must drop entries not listed in patch files map"
    );
}

#[test]
fn read_archive_filtered_propagates_unsafe_path_errors() {
    // If the underlying read trips an unsafe-path guard, filter
    // must propagate rather than swallow.
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"/etc/shadow", b"evil");
    let err = read_archive_filtered(&archive, &make_file_info()).unwrap_err();
    assert!(matches!(err, ArchiveError::UnsafePath(_)));
}
