//! Deterministic tgz → yarn-berry cache-zip rebuild (`checksum: 10c0/…`).
//!
//! yarn berry verifies every install against the sha512 of the *converted
//! cache zip*, not of the tarball — so a committed vendored lock entry needs
//! that checksum computed offline, with no yarn on the machine. This module
//! is a byte-exact Rust port of `spikes/yarn-berry-nm/rebuild_zip.py`, the
//! spike-proven recipe that reproduces yarn 4.x cache zips bit-for-bit
//! (verified against yarn 4.12.0 and 4.6.0 output, TZ-insensitive, mode-probe
//! tarball included — see spike B2 in `spikes/PHASE0-V2-FINDINGS.txt`).
//!
//! Every constant below is pinned by that spike; the zip writer is
//! hand-rolled because the recipe's exact field bytes (no extra fields, no
//! data descriptors, libzip's version-made-by, DOS timestamps rendered as
//! UTC) are the whole point and must never float with a zip-crate default.
//!
//! The recipe (everything that is in the zip, nothing else):
//! * **name mapping** — strip the first path component of each tar entry
//!   (npm uses `package/`), prefix `node_modules/<ident>/`;
//! * **entry order** — tar order, with parent directory entries emitted on
//!   first need (mkdirp): `node_modules/` + `node_modules/<ident>/` appear
//!   before the first entry, deeper dirs at the tar position that first
//!   references them;
//! * **compression** — stored (method 0) for every entry — the `c0` in
//!   `10c0` (compressionLevel 0, the yarn 4 default; any other cacheKey is
//!   the caller's cue to refuse);
//! * **timestamps** — every entry dosdate `0x08D6` dostime `0xAE40`
//!   (= 1984-06-22 21:50:00, yarn's `SAFE_TIME` 456789000 rendered as UTC);
//! * **modes** — normalized by yarn, never copied from the tar: files
//!   `0o100644`, or `0o100755` iff the tar mode carries any exec bit; dirs
//!   always `0o40755`; `external_attr = mode << 16`, internal attrs 0;
//! * **headers** — version-needed 10 (files) / 20 (dirs), flags `0x0000`
//!   (no data descriptor, no UTF-8 flag — entry names must be ASCII),
//!   crc/sizes inline (0 for dirs), NO extra fields;
//! * **central dir** — version-made-by `0x033F` (UNIX, spec 6.3), no extra
//!   fields, no comments, one CDH per LFH in the same order;
//! * **EOCD** — single disk, no zip64, no archive comment.

use std::io::Read;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha512};

/// DOS time 21:50:00 — yarn `SAFE_TIME` 456789000 rendered as UTC.
const SAFE_DOS_TIME: u16 = 0xAE40;
/// DOS date 1984-06-22 — the other half of `SAFE_TIME`.
const SAFE_DOS_DATE: u16 = 0x08D6;
/// Central-dir version-made-by: UNIX (3) << 8 | zip spec 6.3 (63) — what
/// yarn's wasm libzip stamps.
const VERSION_MADE_BY: u16 = 0x033F;
/// Local/central version-needed-to-extract.
const VERSION_NEEDED_FILE: u16 = 10;
const VERSION_NEEDED_DIR: u16 = 20;
/// Normalized unix modes (yarn discards the tar's other permission bits).
const MODE_DIR: u32 = 0o40755;
const MODE_FILE: u32 = 0o100644;
const MODE_FILE_EXEC: u32 = 0o100755;

/// The committed lock checksum for a vendored tarball under cacheKey `10c0`:
/// `"10c0/" + sha512-hex` of the deterministic cache zip rebuilt from
/// `tgz_bytes` for `node_modules/<package_ident>/`.
///
/// Fail-closed: any tar shape the spiked recipe did not cover (symlinks,
/// hardlinks, non-ASCII names, single-component paths) is an `Err` — a wrong
/// checksum would brick the user's `yarn install` with a YN0018, so we never
/// guess.
pub(super) fn berry_cache_checksum_10c0(
    tgz_bytes: &[u8],
    package_ident: &str,
) -> Result<String, String> {
    let zip = rebuild_cache_zip(tgz_bytes, package_ident)?;
    Ok(format!("10c0/{}", hex::encode(Sha512::digest(&zip))))
}

/// One zip entry in emission order.
struct ZipEntry {
    /// ASCII name; directories carry the trailing `/`.
    name: String,
    is_dir: bool,
    /// Full unix mode (already normalized).
    mode: u32,
    data: Vec<u8>,
}

/// Rebuild the cache zip bytes (the checksum input). Exposed at module level
/// so the tests can byte-compare against the spike-captured yarn zips.
fn rebuild_cache_zip(tgz_bytes: &[u8], package_ident: &str) -> Result<Vec<u8>, String> {
    if package_ident.is_empty() || package_ident.starts_with('/') || package_ident.ends_with('/') {
        return Err(format!("invalid package ident `{package_ident}`"));
    }
    let entries = collect_entries(tgz_bytes, package_ident)?;
    write_zip(&entries)
}

/// Walk the tarball in tar order, mapping names and emitting mkdirp parent
/// directory entries on first need — the spike-pinned ordering rule.
fn collect_entries(tgz_bytes: &[u8], package_ident: &str) -> Result<Vec<ZipEntry>, String> {
    let prefix = format!("node_modules/{package_ident}");
    let mut entries: Vec<ZipEntry> = Vec::new();
    let mut seen_dirs: std::collections::HashSet<String> = std::collections::HashSet::new();

    // mkdirp: emit every missing ancestor of `dirpath` (no trailing slash),
    // shallowest first, exactly once.
    fn mkdirp(dirpath: &str, seen: &mut std::collections::HashSet<String>, out: &mut Vec<ZipEntry>) {
        let parts: Vec<&str> = dirpath.split('/').collect();
        for i in 1..=parts.len() {
            let d = format!("{}/", parts[..i].join("/"));
            if seen.insert(d.clone()) {
                out.push(ZipEntry { name: d, is_dir: true, mode: MODE_DIR, data: Vec::new() });
            }
        }
    }

    let mut archive = tar::Archive::new(GzDecoder::new(tgz_bytes));
    let iter = archive
        .entries()
        .map_err(|e| format!("cannot read tarball: {e}"))?;
    for entry in iter {
        let mut entry = entry.map_err(|e| format!("cannot read tarball entry: {e}"))?;
        let raw_name = String::from_utf8(entry.path_bytes().into_owned())
            .map_err(|_| "tar entry name is not UTF-8".to_string())?;
        // Flags 0x0000 assume ASCII names (yarn would set the UTF-8 flag
        // otherwise, changing the bytes) — refuse what we cannot reproduce.
        if !raw_name.is_ascii() {
            return Err(format!("tar entry name `{raw_name}` is not ASCII"));
        }
        // Strip the first path component (`package/` for npm packs).
        let stripped = raw_name
            .split('/')
            .skip(1)
            .collect::<Vec<_>>()
            .join("/");
        let stripped = stripped.trim_end_matches('/');

        let entry_type = entry.header().entry_type();
        match entry_type {
            tar::EntryType::Directory => {
                let dir = if stripped.is_empty() {
                    prefix.clone()
                } else {
                    format!("{prefix}/{stripped}")
                };
                mkdirp(&dir, &mut seen_dirs, &mut entries);
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                if stripped.is_empty() {
                    return Err(format!(
                        "tar file entry `{raw_name}` has no path under the package prefix"
                    ));
                }
                let target = format!("{prefix}/{stripped}");
                let parent = target.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                mkdirp(parent, &mut seen_dirs, &mut entries);
                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .map_err(|e| format!("cannot read `{raw_name}` from the tarball: {e}"))?;
                let tar_mode = entry
                    .header()
                    .mode()
                    .map_err(|e| format!("cannot read mode of `{raw_name}`: {e}"))?;
                let mode = if tar_mode & 0o111 != 0 { MODE_FILE_EXEC } else { MODE_FILE };
                entries.push(ZipEntry { name: target, is_dir: false, mode, data });
            }
            // Symlinks/hardlinks/devices never appear in `npm pack` output and
            // yarn's conversion of them is unverified — fail closed rather
            // than emit a checksum yarn would reject (see module docs).
            other => {
                return Err(format!(
                    "unsupported tar entry type {other:?} for `{raw_name}`; cannot rebuild the \
                     berry cache zip deterministically"
                ));
            }
        }
    }
    Ok(entries)
}

fn w16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn w32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn as_u32(n: usize, what: &str) -> Result<u32, String> {
    u32::try_from(n).map_err(|_| format!("{what} exceeds the zip32 limit (no zip64 in the recipe)"))
}

/// Serialize the entries per the pinned recipe: LFHs+data, central dir, EOCD.
fn write_zip(entries: &[ZipEntry]) -> Result<Vec<u8>, String> {
    let count =
        u16::try_from(entries.len()).map_err(|_| "too many entries for a zip32 EOCD".to_string())?;

    let mut blob: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(entries.len());

    for e in entries {
        offsets.push(as_u32(blob.len(), "local header offset")?);
        let crc = if e.is_dir {
            0
        } else {
            let mut crc = flate2::Crc::new();
            crc.update(&e.data);
            crc.sum()
        };
        let size = as_u32(e.data.len(), "entry size")?;
        let vneed = if e.is_dir { VERSION_NEEDED_DIR } else { VERSION_NEEDED_FILE };

        blob.extend_from_slice(b"PK\x03\x04");
        w16(&mut blob, vneed);
        w16(&mut blob, 0); // flags
        w16(&mut blob, 0); // method: stored
        w16(&mut blob, SAFE_DOS_TIME);
        w16(&mut blob, SAFE_DOS_DATE);
        w32(&mut blob, crc);
        w32(&mut blob, size); // compressed == uncompressed (stored)
        w32(&mut blob, size);
        w16(&mut blob, u16::try_from(e.name.len()).map_err(|_| "entry name too long".to_string())?);
        w16(&mut blob, 0); // extra len
        blob.extend_from_slice(e.name.as_bytes());
        blob.extend_from_slice(&e.data);

        central.extend_from_slice(b"PK\x01\x02");
        w16(&mut central, VERSION_MADE_BY);
        w16(&mut central, vneed);
        w16(&mut central, 0); // flags
        w16(&mut central, 0); // method
        w16(&mut central, SAFE_DOS_TIME);
        w16(&mut central, SAFE_DOS_DATE);
        w32(&mut central, crc);
        w32(&mut central, size);
        w32(&mut central, size);
        w16(&mut central, e.name.len() as u16);
        w16(&mut central, 0); // extra len
        w16(&mut central, 0); // comment len
        w16(&mut central, 0); // disk number start
        w16(&mut central, 0); // internal attrs
        w32(&mut central, e.mode << 16); // external attrs
        w32(&mut central, *offsets.last().expect("just pushed"));
        central.extend_from_slice(e.name.as_bytes());
    }

    let cd_size = as_u32(central.len(), "central directory size")?;
    let cd_offset = as_u32(blob.len(), "central directory offset")?;
    let mut out = blob;
    out.append(&mut central);
    out.extend_from_slice(b"PK\x05\x06");
    w16(&mut out, 0); // disk number
    w16(&mut out, 0); // central dir start disk
    w16(&mut out, count);
    w16(&mut out, count);
    w32(&mut out, cd_size);
    w32(&mut out, cd_offset);
    w16(&mut out, 0); // comment len
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// `spikes/yarn-berry-nm/fixtures/b2-zip-reproducibility/left-pad-1.3.0-patched.tgz`
    /// (base64) — the spike's patched left-pad tarball, the input yarn 4.12.0
    /// converted into cache zip `left-pad-file-8dfd6a0c16-10c0.zip`.
    const LEFT_PAD_PATCHED_TGZ_B64: &str = concat!(
        "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",
    );

    /// `spikes/yarn-berry-nm/fixtures/b2-zip-reproducibility/modeprobe.tgz`
    /// (base64) — the spike's odd-modes probe tarball (files 0755/0664/0600/
    /// 0444, dir 0700), pinning yarn's mode normalization.
    const MODEPROBE_TGZ_B64: &str = concat!(
        "H4sIAF9mKWoAA+2W3U6EMBCFud6nwHprSltom5j4MICjID8lFBRjfHeLC2aXGPRii4n0u5lACHPg5My0idMifoTAswghRHLu",
        "f1ZxrIa5Hi8oZ5QxEdJQ+oRGkWSez22Kmul1F7dGSpUXqozLVw11ob557iUDKFfec/5RviW1F6eZ/G/7GuvMTo8f/WfsxH9h",
        "/OeCCc8nduScs3P/r6+CJK8DnR0gzZSf5Ye/VuTYkjn/uk+s7YAx91M0fjn/OePUzf8tmP2fKn7Sqr50D/M/hIhW/I/kwn8h",
        "Rejm/xa8oTquAN2iSt1D06oE0A16hlbnqjZ3KSaYoHe3FP4rX/Mf0hY6E38LPcb8r85/RhfnP8Ekd/nfAhP7vgQMQ6PaTt9R",
        "l/R9cXr+e8Dd0FnoMW74aG3/E7bc/yyULv9bMLjAOxwOxy75AJ0RpNkAGAAA",
    );

    /// `spikes/yarn-berry-nm/fixtures/b2-zip-reproducibility/yarn-cache-modeprobe-file-10c0.zip`
    /// (base64) — yarn 4.12.0's OWN cache zip for modeprobe.tgz, byte-exact.
    const MODEPROBE_YARN_ZIP_B64: &str = concat!(
        "UEsDBBQAAAAAAECu1ggAAAAAAAAAAAAAAAANAAAAbm9kZV9tb2R1bGVzL1BLAwQUAAAAAABArtYIAAAAAAAAAAAAAAAAFwAA",
        "AG5vZGVfbW9kdWxlcy9tb2RlcHJvYmUvUEsDBAoAAAAAAECu1ggvOtrpEgAAABIAAAAdAAAAbm9kZV9tb2R1bGVzL21vZGVw",
        "cm9iZS9ydW4uc2gjIS9iaW4vc2gKZWNobyBoaQpQSwMEFAAAAAAAQK7WCAAAAAAAAAAAAAAAABsAAABub2RlX21vZHVsZXMv",
        "bW9kZXByb2JlL3N1Yi9QSwMECgAAAAAAQK7WCEilu+UnAAAAJwAAACMAAABub2RlX21vZHVsZXMvbW9kZXByb2JlL3BhY2th",
        "Z2UuanNvbnsibmFtZSI6Im1vZGVwcm9iZSIsInZlcnNpb24iOiIxLjAuMCJ9ClBLAwQKAAAAAABArtYIZbDR3REAAAARAAAA",
        "IAAAAG5vZGVfbW9kdWxlcy9tb2RlcHJvYmUvc2VjcmV0LmpzbW9kdWxlLmV4cG9ydHM9MQpQSwMECgAAAAAAQK7WCB8I6kYC",
        "AAAAAgAAACAAAABub2RlX21vZHVsZXMvbW9kZXByb2JlL3N1Yi9mLnR4dHgKUEsBAj8DFAAAAAAAQK7WCAAAAAAAAAAAAAAA",
        "AA0AAAAAAAAAAAAAAO1BAAAAAG5vZGVfbW9kdWxlcy9QSwECPwMUAAAAAABArtYIAAAAAAAAAAAAAAAAFwAAAAAAAAAAAAAA",
        "7UErAAAAbm9kZV9tb2R1bGVzL21vZGVwcm9iZS9QSwECPwMKAAAAAABArtYILzra6RIAAAASAAAAHQAAAAAAAAAAAAAA7YFg",
        "AAAAbm9kZV9tb2R1bGVzL21vZGVwcm9iZS9ydW4uc2hQSwECPwMUAAAAAABArtYIAAAAAAAAAAAAAAAAGwAAAAAAAAAAAAAA",
        "7UGtAAAAbm9kZV9tb2R1bGVzL21vZGVwcm9iZS9zdWIvUEsBAj8DCgAAAAAAQK7WCEilu+UnAAAAJwAAACMAAAAAAAAAAAAA",
        "AKSB5gAAAG5vZGVfbW9kdWxlcy9tb2RlcHJvYmUvcGFja2FnZS5qc29uUEsBAj8DCgAAAAAAQK7WCGWw0d0RAAAAEQAAACAA",
        "AAAAAAAAAAAAAKSBTgEAAG5vZGVfbW9kdWxlcy9tb2RlcHJvYmUvc2VjcmV0LmpzUEsBAj8DCgAAAAAAQK7WCB8I6kYCAAAA",
        "AgAAACAAAAAAAAAAAAAAAKSBnQEAAG5vZGVfbW9kdWxlcy9tb2RlcHJvYmUvc3ViL2YudHh0UEsFBgAAAAAHAAcAAQIAAN0B",
        "AAAAAA==",
    );

    /// Spike-captured lock checksum for the patched left-pad tarball: the
    /// verbatim `checksum:` value yarn 4.12.0 wrote in
    /// `spikes/yarn-berry-nm/fixtures/b3-vendored-resolutions/after/yarn.lock`
    /// (== sha512 of `yarn-cache-left-pad-file-8dfd6a0c16-10c0.zip`).
    const LEFT_PAD_SPIKE_CHECKSUM: &str = "10c0/7785879d9a7dc9bee6730ec55926a0ab9ed6bfe0eaee0cbcbcf00841d42488fddda51265c73eeddd54c5deca87d131e846ff66d27d890ef73f12720b458d7ca3";

    /// Spike-captured sha512 of `yarn-cache-modeprobe-file-10c0.zip` (yarn
    /// 4.12.0's own cache zip for the odd-modes probe tarball).
    const MODEPROBE_SPIKE_CHECKSUM: &str = "10c0/10507c38d64a0005a2aca03c1ee8c592fc17a53b97c1b87175374e61b95e1e214941c0f32dd476b69274e163dca4ae06d6d30f784eeb201006073694a35bba41";

    fn b64(data: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(data)
            .expect("embedded fixture base64 decodes")
    }

    #[test]
    fn left_pad_checksum_matches_the_spike_captured_lock_value() {
        let tgz = b64(LEFT_PAD_PATCHED_TGZ_B64);
        let got = berry_cache_checksum_10c0(&tgz, "left-pad").unwrap();
        // Oracle is the yarn-emitted lock value, never a self-computed one.
        assert_eq!(got, LEFT_PAD_SPIKE_CHECKSUM);
    }

    #[test]
    fn modeprobe_checksum_matches_the_spike_captured_zip_hash() {
        // Exercises every mode-normalization rule: 0755 keeps exec, 0664/
        // 0600/0444 all collapse to 0644, the 0700 dir becomes 0755.
        let tgz = b64(MODEPROBE_TGZ_B64);
        let got = berry_cache_checksum_10c0(&tgz, "modeprobe").unwrap();
        assert_eq!(got, MODEPROBE_SPIKE_CHECKSUM);
    }

    #[test]
    fn rebuilt_zip_is_byte_identical_to_yarns_own_cache_zip() {
        // The strongest pin: every header field (timestamps, version-made-by,
        // mkdirp ordering, external attrs, EOCD) byte-compared against the
        // zip yarn 4.12.0 itself produced for the same tarball.
        let tgz = b64(MODEPROBE_TGZ_B64);
        let ours = rebuild_cache_zip(&tgz, "modeprobe").unwrap();
        assert_eq!(ours, b64(MODEPROBE_YARN_ZIP_B64));
    }

    /// Build a tgz with file entries ONLY (no directory entries) — the shape
    /// `npm_pack::pack_deterministic` produces — and assert mkdirp still
    /// emits the parent dirs first, in tar order, all stored.
    #[test]
    fn mkdirp_covers_tarballs_without_directory_entries() {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
        let mut tar = tar::Builder::new(gz);
        for (path, data) in [
            ("package/package.json", &b"{}"[..]),
            ("package/lib/deep.js", &b"deep"[..]),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append_data(&mut h, path, data).unwrap();
        }
        let tgz = tar.into_inner().unwrap().finish().unwrap();

        let zip_bytes = rebuild_cache_zip(&tgz, "@scope/pkg").unwrap();
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).unwrap();
        let names: Vec<String> =
            (0..zip.len()).map(|i| zip.by_index(i).unwrap().name().to_string()).collect();
        assert_eq!(
            names,
            vec![
                "node_modules/",
                "node_modules/@scope/",
                "node_modules/@scope/pkg/",
                "node_modules/@scope/pkg/package.json",
                "node_modules/@scope/pkg/lib/",
                "node_modules/@scope/pkg/lib/deep.js",
            ]
        );
        for i in 0..zip.len() {
            let entry = zip.by_index(i).unwrap();
            assert_eq!(
                entry.compression(),
                zip::CompressionMethod::Stored,
                "{}: every entry stored (the c0)",
                entry.name()
            );
        }
    }

    #[test]
    fn unsupported_inputs_fail_closed() {
        // Not a gzip stream at all.
        assert!(berry_cache_checksum_10c0(b"not a tarball", "x").is_err());

        // A symlink entry: yarn's conversion is unverified — must Err, never
        // emit a checksum yarn might reject at install time.
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
        let mut tar = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        tar.append_link(&mut h, "package/evil", "/etc/passwd").unwrap();
        let tgz = tar.into_inner().unwrap().finish().unwrap();
        let err = berry_cache_checksum_10c0(&tgz, "x").unwrap_err();
        assert!(err.contains("unsupported tar entry type"), "{err}");

        // A non-ASCII name would need the UTF-8 flag (different bytes).
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
        let mut tar = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Regular);
        h.set_size(1);
        h.set_mode(0o644);
        h.set_cksum();
        tar.append_data(&mut h, "package/na\u{ef}ve.js", &b"x"[..]).unwrap();
        let tgz = tar.into_inner().unwrap().finish().unwrap();
        let err = berry_cache_checksum_10c0(&tgz, "x").unwrap_err();
        assert!(err.contains("not ASCII"), "{err}");

        // Bad idents.
        assert!(berry_cache_checksum_10c0(&[], "").is_err());
    }
}
