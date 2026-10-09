//! A `.nupkg`'s content hash: the `contentHash` NuGet writes into
//! `packages.lock.json` and `.nupkg.metadata` (#624).
//!
//! For an unsigned package it is the base64 SHA-512 of the file. For a
//! signed package — nuget.org repository-signs every package — NuGet hashes
//! the archive AS IF the `.signature.p7s` entry were absent
//! (`PackageArchiveReader.GetContentHash` →
//! `SignedPackageArchiveUtility.GetPackageContentHash`):
//!
//! 1. the bytes before the first (non-signature) local file entry;
//! 2. every non-signature file entry (local header, data, data
//!    descriptor), in archive order;
//! 3. every non-signature central directory record, in directory order,
//!    with its local-header offset moved back by the signature entry's size
//!    when the entry it points at follows the signature;
//! 4. the end-of-central-directory record with the entry counts one lower,
//!    the directory size less the signature's record and the directory
//!    offset less the signature entry's size, then the rest of the file.
//!
//! So the catalog `packageHash` (SHA-512 of the signed file as served) is
//! NOT a lock's `contentHash`, and pinning it fails every restore NU1403.
//! Zip64 archives are refused rather than guessed at.

use sha2::{Digest, Sha512};

/// The signature entry NuGet excludes (`SigningSpecifications.SignaturePath`).
const SIGNATURE_PATH: &[u8] = b".signature.p7s";

const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const CENTRAL_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;
const DESCRIPTOR_SIG: u32 = 0x0807_4b50;
const EOCD_LEN: usize = 22;

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| truncated(at))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| truncated(at))
}

fn truncated(at: usize) -> String {
    format!("the package archive is truncated at byte {at}")
}

/// One central directory record and the file entry it describes.
struct Record {
    /// Offset of the central directory record.
    position: usize,
    header_size: usize,
    local_offset: usize,
    /// Local header + data + data descriptor.
    entry_size: usize,
    is_signature: bool,
}

/// The base64 SHA-512 NuGet records as `contentHash` for `nupkg`.
pub(crate) fn package_content_hash(nupkg: &[u8]) -> Result<String, String> {
    use base64::Engine as _;
    let eocd = find_eocd(nupkg)?;
    if eocd >= 20 && u32_at(nupkg, eocd - 20)? == ZIP64_LOCATOR_SIG {
        return Err("zip64 package archives are not supported".to_string());
    }
    let entries_disk = u16_at(nupkg, eocd + 8)?;
    let entries = u16_at(nupkg, eocd + 10)?;
    let cd_size = u32_at(nupkg, eocd + 12)?;
    let cd_offset = u32_at(nupkg, eocd + 16)?;
    if entries == u16::MAX || cd_size == u32::MAX || cd_offset == u32::MAX {
        return Err("zip64 package archives are not supported".to_string());
    }
    if entries_disk != entries || u16_at(nupkg, eocd + 4)? != 0 || u16_at(nupkg, eocd + 6)? != 0 {
        return Err("multi-disk package archives are not supported".to_string());
    }
    let mut records = Vec::with_capacity(entries as usize);
    let mut at = cd_offset as usize;
    for _ in 0..entries {
        if u32_at(nupkg, at)? != CENTRAL_SIG {
            return Err(format!("no central directory record at byte {at}"));
        }
        let flags = u16_at(nupkg, at + 8)?;
        let compressed = u32_at(nupkg, at + 20)? as usize;
        let name_len = u16_at(nupkg, at + 28)? as usize;
        let extra_len = u16_at(nupkg, at + 30)? as usize;
        let comment_len = u16_at(nupkg, at + 32)? as usize;
        let local_offset = u32_at(nupkg, at + 42)? as usize;
        let name = nupkg
            .get(at + 46..at + 46 + name_len)
            .ok_or_else(|| truncated(at + 46))?;
        if u32_at(nupkg, local_offset)? != LOCAL_SIG {
            return Err(format!("no local file header at byte {local_offset}"));
        }
        let local_header = 30
            + u16_at(nupkg, local_offset + 26)? as usize
            + u16_at(nupkg, local_offset + 28)? as usize;
        let mut entry_size = local_header + compressed;
        if flags & 0x0008 != 0 {
            // A data descriptor follows the data, with or without its
            // optional signature.
            let d = local_offset + entry_size;
            entry_size += if u32_at(nupkg, d)? == DESCRIPTOR_SIG {
                16
            } else {
                12
            };
        }
        if local_offset + entry_size > nupkg.len() {
            return Err(truncated(local_offset + entry_size));
        }
        let header_size = 46 + name_len + extra_len + comment_len;
        records.push(Record {
            position: at,
            header_size,
            local_offset,
            entry_size,
            is_signature: name == SIGNATURE_PATH,
        });
        at += header_size;
    }
    let mut signatures = records.iter().filter(|r| r.is_signature);
    let signature = match (signatures.next(), signatures.next()) {
        (None, _) => return Ok(crate::utils::digest::sha512_base64_of(nupkg)),
        (Some(sig), None) => (sig.local_offset, sig.entry_size, sig.header_size),
        (Some(_), Some(_)) => return Err("the package has two signature entries".to_string()),
    };
    let (sig_offset, sig_entry_size, sig_header_size) = signature;
    let mut rest: Vec<&Record> = records.iter().filter(|r| !r.is_signature).collect();
    if rest.is_empty() {
        return Err("the package holds nothing but its signature".to_string());
    }

    let mut hash = Sha512::new();
    rest.sort_by_key(|r| r.local_offset);
    hash.update(&nupkg[..rest[0].local_offset]);
    for r in &rest {
        hash.update(&nupkg[r.local_offset..r.local_offset + r.entry_size]);
    }
    rest.sort_by_key(|r| r.position);
    for r in &rest {
        hash.update(&nupkg[r.position..r.position + 42]);
        let offset = if r.local_offset > sig_offset {
            r.local_offset - sig_entry_size
        } else {
            r.local_offset
        };
        hash.update((offset as u32).to_le_bytes());
        hash.update(&nupkg[r.position + 46..r.position + r.header_size]);
    }
    hash.update(&nupkg[eocd..eocd + 8]);
    hash.update((entries_disk - 1).to_le_bytes());
    hash.update((entries - 1).to_le_bytes());
    hash.update((cd_size - sig_header_size as u32).to_le_bytes());
    hash.update((cd_offset - sig_entry_size as u32).to_le_bytes());
    hash.update(&nupkg[eocd + 20..]);
    Ok(base64::engine::general_purpose::STANDARD.encode(hash.finalize()))
}

/// Offset of the end-of-central-directory record: the last signature whose
/// comment length reaches exactly to the end of the file.
fn find_eocd(b: &[u8]) -> Result<usize, String> {
    if b.len() < EOCD_LEN {
        return Err("the package is not a zip archive".to_string());
    }
    let floor = b.len().saturating_sub(EOCD_LEN + u16::MAX as usize);
    (floor..=b.len() - EOCD_LEN)
        .rev()
        .find(|&at| {
            u32_at(b, at) == Ok(EOCD_SIG)
                && u16_at(b, at + 20).is_ok_and(|c| at + EOCD_LEN + c as usize == b.len())
        })
        .ok_or_else(|| "the package is not a zip archive".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn zip(entries: &[(&str, &[u8])], descriptor_free: bool) -> Vec<u8> {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .last_modified_time(zip::DateTime::default())
            .compression_method(if descriptor_free {
                zip::CompressionMethod::Stored
            } else {
                zip::CompressionMethod::Deflated
            });
        for (name, data) in entries {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    const FILES: [(&str, &[u8]); 3] = [
        ("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>"),
        (
            "pkg.nuspec",
            b"<package><metadata><id>Pkg</id></metadata></package>",
        ),
        (
            "lib/net8.0/Pkg.dll",
            b"MZ-not-really-an-assembly-but-long-enough",
        ),
    ];

    #[test]
    fn unsigned_package_hashes_the_whole_file() {
        let bytes = zip(&FILES, true);
        assert_eq!(
            package_content_hash(&bytes).unwrap(),
            crate::utils::digest::sha512_base64_of(&bytes)
        );
    }

    /// A signature appended last (where NuGet places it) hashes exactly like
    /// the same archive written without it.
    #[test]
    fn signed_package_hashes_as_if_unsigned() {
        for stored in [true, false] {
            let unsigned = zip(&FILES, stored);
            let mut with_sig: Vec<(&str, &[u8])> = FILES.to_vec();
            with_sig.push((".signature.p7s", b"PKCS7-signature-bytes"));
            let signed = zip(&with_sig, stored);
            let hash = package_content_hash(&signed).unwrap();
            assert_ne!(hash, crate::utils::digest::sha512_base64_of(&signed));
            assert_eq!(hash, crate::utils::digest::sha512_base64_of(&unsigned));
        }
    }

    /// A signature that is not the last entry: the entries after it have
    /// their offsets moved back by its size.
    #[test]
    fn signature_in_the_middle_is_excluded_with_offsets_fixed() {
        let unsigned = zip(&FILES, true);
        let signed = zip(
            &[
                FILES[0],
                (".signature.p7s", b"PKCS7-signature-bytes"),
                FILES[1],
                FILES[2],
            ],
            true,
        );
        assert_eq!(
            package_content_hash(&signed).unwrap(),
            crate::utils::digest::sha512_base64_of(&unsigned)
        );
    }

    #[test]
    fn malformed_archives_are_refused() {
        assert!(package_content_hash(b"").is_err());
        assert!(package_content_hash(b"not a zip at all, just some bytes").is_err());
        let mut bytes = zip(&FILES, true);
        bytes.truncate(bytes.len() / 2);
        assert!(package_content_hash(&bytes).is_err());
    }
}
