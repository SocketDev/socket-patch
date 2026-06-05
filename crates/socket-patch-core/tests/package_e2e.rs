//! Integration coverage for `socket_patch_core::patch::package`.
//!
//! Exercises both `read_archive_to_map` and `read_archive_filtered`
//! across the happy path, the `package/` prefix stripping rule,
//! the unsafe-path guards (absolute paths, parent traversal,
//! Windows-style backslash paths), the validate-AFTER-normalize
//! guards (`package/`-prefixed escapes that only become unsafe once
//! the prefix is stripped), and non-regular entry skipping
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

/// Helper: craft an archive holding one regular file followed by one
/// symlink entry. Lets us prove the reader selectively drops the symlink
/// while preserving the regular file, rather than dropping everything.
fn write_archive_with_regular_and_symlink(
    path: &Path,
    file_name: &str,
    file_data: &[u8],
    link_name: &str,
    target: &str,
) {
    let file = std::fs::File::create(path).unwrap();
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(gz);

    let mut fhdr = tar::Header::new_gnu();
    fhdr.set_size(file_data.len() as u64);
    fhdr.set_mode(0o644);
    fhdr.set_cksum();
    builder.append_data(&mut fhdr, file_name, file_data).unwrap();

    let mut lhdr = tar::Header::new_gnu();
    lhdr.set_entry_type(tar::EntryType::Symlink);
    lhdr.set_size(0);
    lhdr.set_mode(0o644);
    lhdr.set_cksum();
    builder.append_link(&mut lhdr, link_name, target).unwrap();

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

/// Assert the error is `UnsafePath` AND its payload names the offending
/// entry path. Without the payload check, the guard could fire for the
/// wrong reason (e.g. a malformed header that happened to look unsafe)
/// and the test would still pass.
fn assert_unsafe_path_containing(err: ArchiveError, needle: &str) {
    match err {
        ArchiveError::UnsafePath(p) => assert!(
            p.contains(needle),
            "UnsafePath payload {p:?} must name the rejected entry containing {needle:?}"
        ),
        other => panic!("expected ArchiveError::UnsafePath, got {other:?}"),
    }
}

#[test]
fn read_archive_to_map_rejects_absolute_path() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"/etc/passwd", b"evil");

    let err = read_archive_to_map(&archive).unwrap_err();
    assert_unsafe_path_containing(err, "/etc/passwd");
}

#[test]
fn read_archive_to_map_rejects_backslash_absolute_path() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"\\Windows\\System32\\evil.dll", b"evil");

    let err = read_archive_to_map(&archive).unwrap_err();
    assert_unsafe_path_containing(err, "evil.dll");
}

#[test]
fn read_archive_to_map_rejects_parent_traversal() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"../../etc/passwd", b"evil");

    let err = read_archive_to_map(&archive).unwrap_err();
    assert_unsafe_path_containing(err, "../../etc/passwd");
}

#[test]
fn read_archive_to_map_rejects_double_slash_package_escape() {
    // Regression for the validate-AFTER-normalize fix. The raw entry
    // `package//etc/passwd` passes every PRE-strip check (not absolute,
    // no leading separator, the `//` collapses so there is no `..`), but
    // `strip_prefix("package/")` yields the absolute path `/etc/passwd`,
    // and `pkg_path.join("/etc/passwd")` discards the base — an arbitrary
    // out-of-tree write. The guard MUST run on the post-strip path.
    //
    // Unlike the bare-`/etc/passwd` test above, this case stays green
    // under the OLD (pre-strip) validation, so it is the one that
    // actually polices the fix.
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"package//etc/passwd", b"evil");

    let err = read_archive_to_map(&archive).unwrap_err();
    assert_unsafe_path_containing(err, "package//etc/passwd");
}

#[test]
fn read_archive_to_map_rejects_package_prefixed_backslash_escape() {
    // Sibling of the double-slash case: stripping `package/` from
    // `package/\evil` leaves `\evil`, a Windows root-relative path the
    // leading-separator guard must catch only post-normalization.
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"package/\\evil", b"evil");

    let err = read_archive_to_map(&archive).unwrap_err();
    assert_unsafe_path_containing(err, "package/\\evil");
}

#[test]
fn read_archive_to_map_rejects_package_prefixed_parent_traversal() {
    // A `..` that survives the `package/` strip must still be rejected
    // now that validation happens after normalization.
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"package/../../etc/passwd", b"evil");

    let err = read_archive_to_map(&archive).unwrap_err();
    assert_unsafe_path_containing(err, "package/../../etc/passwd");
}

#[test]
fn read_archive_to_map_skips_symlinks_but_keeps_regular_siblings() {
    // A blanket-empty assertion would also pass if the reader dropped
    // EVERYTHING (e.g. a regression that returned an empty map). Stage a
    // real regular file alongside the symlink and prove the symlink is
    // dropped while the regular file survives with its exact bytes.
    let tmp = tempfile::tempdir().unwrap();

    // Symlink-only archive: must yield an empty map.
    let link_only = tmp.path().join("link_only.tar.gz");
    write_archive_with_symlink(&link_only, "link", "target");
    let map = read_archive_to_map(&link_only).unwrap();
    assert!(map.is_empty(), "symlink entries must be silently dropped");

    // Mixed archive carrying both a regular file and a symlink.
    let mixed = tmp.path().join("mixed.tar.gz");
    write_archive_with_regular_and_symlink(&mixed, "real.js", b"real bytes", "link", "target");
    let map = read_archive_to_map(&mixed).unwrap();
    assert_eq!(map.len(), 1, "only the regular file survives: {map:?}");
    assert_eq!(
        map.get("real.js").map(|v| v.as_slice()),
        Some(b"real bytes".as_slice()),
        "regular file bytes must be preserved verbatim"
    );
    assert!(
        !map.contains_key("link"),
        "symlink entry must not appear in the map"
    );
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
    assert_eq!(filtered.len(), 2, "exactly the two listed entries survive: {filtered:?}");
    // The listed `package/index.js` key must match the normalized
    // `index.js` entry, carrying its exact bytes through the filter.
    assert_eq!(
        filtered.get("index.js").map(|v| v.as_slice()),
        Some(b"patched index".as_slice()),
        "package-prefixed listing must match normalized entry with intact bytes"
    );
    assert_eq!(
        filtered.get("lib/util.js").map(|v| v.as_slice()),
        Some(b"patched util".as_slice()),
        "non-prefixed listing must match verbatim with intact bytes"
    );
    assert!(
        !filtered.contains_key("bonus/extra.js"),
        "filter must drop entries not listed in patch files map"
    );
    // And it must not leak the unlisted bytes under any key.
    assert!(
        !filtered.values().any(|v| v.as_slice() == b"unwanted"),
        "unlisted entry bytes must never survive the filter: {filtered:?}"
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
    assert_unsafe_path_containing(err, "/etc/shadow");
}

#[test]
fn read_archive_filtered_propagates_package_prefixed_escape() {
    // The filter delegates to `read_archive_to_map`, so the post-strip
    // validation must propagate here too. `package//etc/shadow` would
    // escape the package dir if validation regressed to pre-strip.
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("arc.tar.gz");
    write_raw_archive(&archive, b"package//etc/shadow", b"evil");
    let err = read_archive_filtered(&archive, &make_file_info()).unwrap_err();
    assert_unsafe_path_containing(err, "package//etc/shadow");
}
