//! Bounded, streaming reads of a JVM jar.
//!
//! The zip reader the vendored-artifact checks share
//! (`vendor::verify::read_zip_to_map`) was sized for Python wheels: 10,000
//! entries, 64 MiB inflated, every member held in memory. Released jars pass
//! both (`hive-exec-3.1.3.jar`: 23,728 entries, 93 MiB;
//! `poi-ooxml-full-5.2.5.jar`: 15,181 entries), so a patch for one could
//! never be applied, and comparing two jars through it held every member of
//! both at once.
//!
//! Here each member is inflated through a hasher and dropped, so one pass
//! holds a digest per member, whatever the jar's size.
//!
//! # What counts as a member
//!
//! Every entry a JVM can load: any entry whose name does not end in `/`,
//! **whatever its unix mode**. A class loader reads an entry's bytes by name
//! and never looks at the mode, so an entry carrying symlink mode bits is as
//! loadable as any other (the wheel reader skips those). Names are compared
//! as the raw bytes of the central directory, which is what the JVM matches
//! on. An archive with two entries of one name is read as its last one: the
//! `zip` crate and `java.util.zip.ZipFile` both resolve a name to the last
//! entry that carries it.
//!
//! Directory entries are not members: released service jars carry none,
//! newer ones keep upstream's, and no class loader resolves a class through
//! one. Signature files (`META-INF/*.SF`, `.RSA`, `.DSA`, `.EC`) are left
//! out of [`unpatched_difference`]: a repack that changes a member has to
//! drop them.
//!
//! # Limits
//!
//! The sizes an archive declares for its entries are the author's claim, so
//! the byte limits are on what is actually inflated. The entry count and
//! the central directory's size are read from the archive's end records
//! before the zip reader parses the directory, since the reader allocates
//! for whatever those records declare: a directory of millions of tiny
//! records is refused unread.
//!
//! * [`MAX_ENTRIES`]: 200,000 entries. Eight times the largest jar measured
//!   above; the jars a 128 MiB download can carry stay well under it.
//! * [`MAX_CENTRAL_DIRECTORY_BYTES`]: 64 MiB of central directory, some 300
//!   bytes for each of 200,000 entries (the largest measured is 2 MiB).
//! * [`MAX_INFLATED_BYTES`]: 1 GiB inflated in one pass over one jar. Eleven
//!   times the largest measured, and what a jar at the 128 MiB download cap
//!   inflates to at 8:1, above what class files and resources reach.
//! * [`MAX_INFLATE_RATIO`]: no more than 100 times the archive's own size,
//!   once past the [`RATIO_FLOOR_BYTES`] (64 MiB, the old limit) every
//!   archive may use. Deflate reaches 1000:1 on a crafted stream; jars sit
//!   around 2:1 to 10:1. This keeps a small hostile archive from spending
//!   the whole 1 GiB.
//!
//! A jar past a limit is [`JarError::TooLarge`], and the text says which
//! limit and by how much.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

use sha2::{Digest, Sha256};

use crate::hash::git_sha256::compute_git_sha256_from_std_reader;

/// Entries one jar may hold (see the module docs).
pub(crate) const MAX_ENTRIES: usize = 200_000;
/// Bytes the central directory of one jar may take.
pub(crate) const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 64 * 1024 * 1024;
/// Bytes one pass over one jar may inflate.
pub(crate) const MAX_INFLATED_BYTES: u64 = 1024 * 1024 * 1024;
/// Inflated bytes allowed per archive byte, past [`RATIO_FLOOR_BYTES`].
pub(crate) const MAX_INFLATE_RATIO: u64 = 100;
/// What any archive may inflate to, however small it is.
pub(crate) const RATIO_FLOOR_BYTES: u64 = 64 * 1024 * 1024;

/// Why a jar could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JarError {
    /// Not a zip archive, or a member whose stream is corrupt.
    Unreadable(String),
    /// Past a limit of the module docs; the text names it.
    TooLarge(String),
}

impl JarError {
    pub(crate) fn is_too_large(&self) -> bool {
        matches!(self, JarError::TooLarge(_))
    }
}

impl std::fmt::Display for JarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JarError::Unreadable(why) | JarError::TooLarge(why) => f.write_str(why),
        }
    }
}

fn mib(bytes: u64) -> u64 {
    bytes.div_ceil(1024 * 1024)
}

/// What one pass over an archive of `archive_len` bytes may inflate.
fn inflate_budget(archive_len: u64) -> u64 {
    MAX_INFLATED_BYTES.min(RATIO_FLOOR_BYTES.max(archive_len.saturating_mul(MAX_INFLATE_RATIO)))
}

/// One pass over a jar: the open archive and what is left of its inflate
/// budget.
pub(crate) struct Jar<R> {
    zip: zip::ZipArchive<R>,
    archive_len: u64,
    budget: u64,
    left: u64,
}

impl<'a> Jar<std::io::Cursor<&'a [u8]>> {
    /// A pass over the jar bytes `jar`.
    pub(crate) fn of_bytes(jar: &'a [u8]) -> Result<Self, JarError> {
        Jar::open(std::io::Cursor::new(jar), jar.len() as u64)
    }
}

impl<R: Read + Seek> Jar<R> {
    /// A pass over the archive `reader` holds, `archive_len` bytes long.
    pub(crate) fn open(mut reader: R, archive_len: u64) -> Result<Self, JarError> {
        check_declared_directory(&mut reader, archive_len)?;
        let zip = zip::ZipArchive::new(reader)
            .map_err(|e| JarError::Unreadable(format!("not a readable zip archive ({e})")))?;
        if zip.len() > MAX_ENTRIES {
            return Err(JarError::TooLarge(format!(
                "it holds {} entries, over the limit of {MAX_ENTRIES}",
                zip.len()
            )));
        }
        let budget = inflate_budget(archive_len);
        Ok(Jar {
            zip,
            archive_len,
            budget,
            left: budget,
        })
    }

    fn over_budget(&self) -> JarError {
        JarError::TooLarge(if self.budget < MAX_INFLATED_BYTES {
            format!(
                "it inflates to more than {} MiB, over {MAX_INFLATE_RATIO} times its own size \
                 ({} MiB) and the {} MiB every jar may use",
                mib(self.budget),
                mib(self.archive_len),
                mib(RATIO_FLOOR_BYTES)
            )
        } else {
            format!(
                "it inflates to more than {} MiB, over the limit for one jar",
                mib(MAX_INFLATED_BYTES)
            )
        })
    }

    /// The sha256 of every member's content, keyed by raw name (see the
    /// module docs for what a member is).
    pub(crate) fn content_digests(&mut self) -> Result<Digests, JarError> {
        let mut out = BTreeMap::new();
        let mut buf = vec![0u8; 64 * 1024];
        for i in 0..self.zip.len() {
            let mut entry = self
                .zip
                .by_index(i)
                .map_err(|e| JarError::Unreadable(format!("entry {i} cannot be read ({e})")))?;
            let name = entry.name_raw().to_vec();
            if name.last() == Some(&b'/') {
                continue;
            }
            let mut hasher = Sha256::new();
            loop {
                let n = entry.read(&mut buf).map_err(|e| {
                    JarError::Unreadable(format!(
                        "member `{}` cannot be inflated ({e})",
                        String::from_utf8_lossy(&name)
                    ))
                })?;
                if n == 0 {
                    break;
                }
                if n as u64 > self.left {
                    drop(entry);
                    return Err(self.over_budget());
                }
                self.left -= n as u64;
                hasher.update(&buf[..n]);
            }
            out.insert(name, hasher.finalize().into());
        }
        Ok(Digests(out))
    }

    /// Whether the jar holds a signature file (`META-INF/*.SF`, `.RSA`,
    /// `.DSA`, `.EC`).
    pub(crate) fn has_signature_file(&self) -> bool {
        self.zip.file_names().any(crate::vendor::jvm::is_signature)
    }

    /// Inflate the member `name` into `sink`, within the pass's budget.
    /// `false` when the jar has no such member.
    fn stream(&mut self, name: &str, mut sink: impl FnMut(&[u8])) -> Result<bool, JarError> {
        if name.ends_with('/') {
            return Ok(false);
        }
        let Some(index) = self.zip.index_for_name(name) else {
            return Ok(false);
        };
        let mut left = self.left;
        {
            let mut entry = self.zip.by_index(index).map_err(|e| {
                JarError::Unreadable(format!("member `{name}` cannot be read ({e})"))
            })?;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = entry.read(&mut buf).map_err(|e| {
                    JarError::Unreadable(format!("member `{name}` cannot be inflated ({e})"))
                })?;
                if n == 0 {
                    break;
                }
                if n as u64 > left {
                    drop(entry);
                    return Err(self.over_budget());
                }
                left -= n as u64;
                sink(&buf[..n]);
            }
        }
        self.left = left;
        Ok(true)
    }

    /// The bytes of the member `name` when it holds at most `cap` of them;
    /// `None` when the jar has no such member.
    pub(crate) fn member_bytes(
        &mut self,
        name: &str,
        cap: u64,
    ) -> Result<Option<Vec<u8>>, JarError> {
        let mut bytes = Vec::new();
        let mut over = false;
        let found = self.stream(name, |chunk| {
            over |= (bytes.len() + chunk.len()) as u64 > cap;
            if !over {
                bytes.extend_from_slice(chunk);
            }
        })?;
        if over {
            return Err(JarError::TooLarge(format!(
                "its member `{name}` holds more than {} MiB",
                mib(cap)
            )));
        }
        Ok(found.then_some(bytes))
    }

    /// The digest of the member `name` under `algorithm`, named as a jar
    /// manifest names it (`SHA-256`, `SHA1`, `SHA-512`, …); `None` when the
    /// jar has no such member.
    pub(crate) fn member_digest(
        &mut self,
        name: &str,
        algorithm: &str,
    ) -> Result<Option<Vec<u8>>, JarError> {
        enum Hasher {
            Sha1(sha1::Sha1),
            Sha256(Sha256),
            Sha384(sha2::Sha384),
            Sha512(sha2::Sha512),
            // No streaming MD5 here: the member is held, within the budget.
            Md5(Vec<u8>),
        }
        let mut hasher = match algorithm.replace('-', "").to_ascii_uppercase().as_str() {
            "SHA1" => Hasher::Sha1(Default::default()),
            "SHA256" => Hasher::Sha256(Default::default()),
            "SHA384" => Hasher::Sha384(Default::default()),
            "SHA512" => Hasher::Sha512(Default::default()),
            "MD5" => Hasher::Md5(Vec::new()),
            _ => {
                return Err(JarError::Unreadable(format!(
                    "the digest algorithm {algorithm} is not one this reads"
                )))
            }
        };
        let found = self.stream(name, |chunk| match &mut hasher {
            Hasher::Sha1(h) => h.update(chunk),
            Hasher::Sha256(h) => h.update(chunk),
            Hasher::Sha384(h) => h.update(chunk),
            Hasher::Sha512(h) => h.update(chunk),
            Hasher::Md5(held) => held.extend_from_slice(chunk),
        })?;
        Ok(found.then(|| match hasher {
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
            Hasher::Md5(held) => md5(&held).to_vec(),
        }))
    }

    /// The git-blob sha256 of the member `name`, `None` when the jar has no
    /// such member. Counts against the pass's budget.
    pub(crate) fn member_git_sha256(&mut self, name: &str) -> Result<Option<String>, JarError> {
        if name.ends_with('/') {
            return Ok(None);
        }
        let Some(index) = self.zip.index_for_name(name) else {
            return Ok(None);
        };
        let entry = self
            .zip
            .by_index(index)
            .map_err(|e| JarError::Unreadable(format!("member `{name}` cannot be read ({e})")))?;
        let size = entry.size();
        if size > self.left {
            drop(entry);
            return Err(self.over_budget());
        }
        self.left -= size;
        // The reader stops at `size`, so a stream longer than it declares
        // costs no more than the budget just taken.
        compute_git_sha256_from_std_reader(size, entry)
            .map(Some)
            .map_err(|e| JarError::Unreadable(format!("member `{name}` cannot be inflated ({e})")))
    }
}

/// RFC 1321 MD5, for the `MD5-Digest` attributes of old jar manifests (the
/// crate has no MD5 otherwise, and nothing else here should use one).
fn md5(input: &[u8]) -> [u8; 16] {
    const SHIFTS: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let constant = |i: usize| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32;
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut message = input.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&(input.len() as u64).wrapping_mul(8).to_le_bytes());
    for block in message.chunks(64) {
        let word = |i: usize| u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
        let [mut a, mut b, mut c, mut d] = state;
        for (i, shift) in SHIFTS.iter().enumerate() {
            let (mix, at) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let rotated = a
                .wrapping_add(mix)
                .wrapping_add(constant(i))
                .wrapping_add(word(at))
                .rotate_left(*shift);
            (a, d, c, b) = (d, c, b, b.wrapping_add(rotated));
        }
        for (sum, add) in state.iter_mut().zip([a, b, c, d]) {
            *sum = sum.wrapping_add(add);
        }
    }
    let mut out = [0u8; 16];
    for (bytes, word) in out.chunks_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Hold what an archive's end records declare of its central directory to
/// [`MAX_ENTRIES`] and [`MAX_CENTRAL_DIRECTORY_BYTES`], before the zip reader
/// parses (and allocates for) it. The reader may settle on any record that
/// looks like the end of the directory, so every `PK\x05\x06` in the last
/// 64 KiB is checked, with the zip64 record its locator points at and any
/// zip64 record in that tail.
fn check_declared_directory<R: Read + Seek>(reader: &mut R, len: u64) -> Result<(), JarError> {
    const END: &[u8] = b"PK\x05\x06";
    const END64: &[u8] = b"PK\x06\x06";
    const LOCATOR: &[u8] = b"PK\x06\x07";
    let unread = |e: std::io::Error| JarError::Unreadable(format!("its end cannot be read ({e})"));
    let le = |bytes: &[u8]| {
        bytes
            .iter()
            .rev()
            .fold(0u64, |n, b| (n << 8) | u64::from(*b))
    };
    let within = |entries: u64, directory: u64| {
        // A record declaring more than the archive can hold (a central
        // record is 46 bytes at least) is not its end record: bytes that
        // happen to spell the signature, which the reader passes over too.
        if directory > len || entries > len / 46 {
            return Ok(());
        }
        if entries > MAX_ENTRIES as u64 {
            return Err(JarError::TooLarge(format!(
                "it holds {entries} entries, over the limit of {MAX_ENTRIES}"
            )));
        }
        if directory > MAX_CENTRAL_DIRECTORY_BYTES {
            return Err(JarError::TooLarge(format!(
                "its central directory takes {} MiB, over the limit of {} MiB",
                mib(directory),
                mib(MAX_CENTRAL_DIRECTORY_BYTES)
            )));
        }
        Ok(())
    };
    // An end record, its comment (at most 64 KiB) and a zip64 locator and
    // record before it.
    let tail_len = len.min(22 + 65_535 + 20 + 56);
    reader
        .seek(SeekFrom::Start(len - tail_len))
        .map_err(unread)?;
    let mut tail = vec![0u8; tail_len as usize];
    reader.read_exact(&mut tail).map_err(unread)?;
    for at in 0..tail.len() {
        let rest = &tail[at..];
        if rest.len() >= 56 && rest.starts_with(END64) {
            within(le(&rest[32..40]), le(&rest[40..48]))?;
        }
        if rest.len() < 22 || !rest.starts_with(END) {
            continue;
        }
        within(le(&rest[10..12]), le(&rest[12..16]))?;
        if at < 20 || !tail[at - 20..].starts_with(LOCATOR) {
            continue;
        }
        let offset = le(&tail[at - 12..at - 4]);
        if offset.checked_add(56).is_some_and(|end| end <= len) {
            let mut record = [0u8; 56];
            reader.seek(SeekFrom::Start(offset)).map_err(unread)?;
            reader.read_exact(&mut record).map_err(unread)?;
            if record.starts_with(END64) {
                within(le(&record[32..40]), le(&record[40..48]))?;
            }
        }
    }
    reader.seek(SeekFrom::Start(0)).map_err(unread)?;
    Ok(())
}

/// The content digests of a jar's members ([`Jar::content_digests`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Digests(BTreeMap<Vec<u8>, [u8; 32]>);

impl Digests {
    /// [`Jar::content_digests`] of the jar bytes `jar`.
    pub(crate) fn of_bytes(jar: &[u8]) -> Result<Digests, JarError> {
        Jar::of_bytes(jar)?.content_digests()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// The digest of the member `name`.
    pub(crate) fn get(&self, name: &str) -> Option<&[u8; 32]> {
        self.0.get(name.as_bytes())
    }
}

/// How one jar's members differ from another's ([`unpatched_difference`]):
/// member names, lossily decoded and sorted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Difference {
    /// In the candidate only.
    pub added: Vec<String>,
    /// In the original only.
    pub missing: Vec<String>,
    /// In both, with other content.
    pub changed: Vec<String>,
    /// Why the manifest, when it is among `changed`, is not the original's
    /// as a re-signing leaves it ([`super::jar_manifest`]).
    pub manifest: Option<String>,
}

impl Difference {
    pub(crate) fn is_empty(&self) -> bool {
        self.added.is_empty() && self.missing.is_empty() && self.changed.is_empty()
    }

    /// `2 added (`a/X.class`, …), 1 changed (`a/B.class`)`: each kind with
    /// its count and its first names.
    pub(crate) fn describe(&self) -> String {
        const SHOWN: usize = 3;
        [
            ("added", &self.added),
            ("missing", &self.missing),
            ("changed", &self.changed),
        ]
        .iter()
        .filter(|(_, names)| !names.is_empty())
        .map(|(kind, names)| {
            let mut shown: Vec<String> =
                names.iter().take(SHOWN).map(|n| format!("`{n}`")).collect();
            if names.len() > SHOWN {
                shown.push("…".to_string());
            }
            format!("{} {kind} ({})", names.len(), shown.join(", "))
        })
        .chain(self.manifest.iter().map(|why| {
            format!("the manifest is not the original's with a re-signing's digests: {why}")
        }))
        .collect::<Vec<_>>()
        .join(", ")
    }
}

/// [`unpatched_difference`] of two jars `(bytes, members)` for the record
/// `files`, less a manifest that differs only as a re-signing of the
/// patched jar leaves it ([`super::jar_manifest::resigned_refusal`]): the
/// one member outside the patch whose content may change, and only so.
pub(crate) fn difference_outside_patch(
    original: (&[u8], &Digests),
    patched: (&[u8], &Digests),
    files: &std::collections::HashMap<String, crate::manifest::schema::PatchFileInfo>,
) -> Difference {
    use super::jar_manifest::{resigned_refusal, MANIFEST};
    let names: Vec<&str> = files
        .keys()
        .map(|key| crate::patch::apply::normalize_file_path(key))
        .collect();
    let mut difference = unpatched_difference(original.1, patched.1, &names);
    if let Some(at) = difference.changed.iter().position(|name| name == MANIFEST) {
        match resigned_refusal(original, patched, files, None) {
            None => {
                difference.changed.remove(at);
            }
            why => difference.manifest = why,
        }
    }
    difference
}

/// How `candidate` differs from `original` outside the members named in
/// `patched` (manifest keys, already normalized) and signature files:
/// empty when everything else a JVM would load is the same in both.
pub(crate) fn unpatched_difference(
    original: &Digests,
    candidate: &Digests,
    patched: &[&str],
) -> Difference {
    let compared = |name: &[u8]| {
        !patched.iter().any(|p| p.as_bytes() == name)
            && !std::str::from_utf8(name).is_ok_and(crate::vendor::jvm::is_signature)
    };
    let text = |name: &[u8]| String::from_utf8_lossy(name).into_owned();
    let mut difference = Difference::default();
    for (name, digest) in original.0.iter().filter(|(name, _)| compared(name)) {
        match candidate.0.get(name) {
            None => difference.missing.push(text(name)),
            Some(other) if other != digest => difference.changed.push(text(name)),
            Some(_) => {}
        }
    }
    difference.added = candidate
        .0
        .keys()
        .filter(|name| compared(name) && !original.0.contains_key(*name))
        .map(|name| text(name))
        .collect();
    difference
}

#[cfg(test)]
pub(crate) mod testing {
    use std::io::Write as _;

    /// A stored (uncompressed) jar of `members`, each `(name, bytes, unix
    /// mode)`; a name ending in `/` is a directory entry.
    pub(crate) fn jar_with_modes(members: &[(&str, &[u8], Option<u32>)]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes, mode) in members {
            let mut opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            if let Some(mode) = mode {
                opts = opts.unix_permissions(*mode);
            }
            if name.ends_with('/') {
                out.add_directory(*name, opts).unwrap();
            } else if mode.is_some_and(|m| m & 0o170000 == 0o120000) {
                out.add_symlink(*name, std::str::from_utf8(bytes).unwrap(), opts)
                    .unwrap();
            } else {
                out.start_file(*name, opts).unwrap();
                out.write_all(bytes).unwrap();
            }
        }
        out.finish().unwrap().into_inner()
    }

    /// [`jar_with_modes`] of plain files.
    pub(crate) fn jar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let members: Vec<(&str, &[u8], Option<u32>)> =
            members.iter().map(|(n, b)| (*n, *b, None)).collect();
        jar_with_modes(&members)
    }

    /// A jar over both of the wheel reader's old limits: `entries` stored
    /// members named `p/C<i>.class` whose contents total `bytes`, then
    /// `extra`. Each member's content is distinct.
    pub(crate) fn big_jar(entries: usize, bytes: u64, extra: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let each = (bytes / entries as u64) as usize;
        let mut body = vec![0x5au8; each.max(16)];
        for i in 0..entries {
            body[..8].copy_from_slice(&(i as u64).to_le_bytes());
            out.start_file(format!("p/C{i}.class"), opts).unwrap();
            out.write_all(&body).unwrap();
        }
        for (name, content) in extra {
            out.start_file(*name, opts).unwrap();
            out.write_all(content).unwrap();
        }
        out.finish().unwrap().into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{big_jar, jar, jar_with_modes};
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;

    /// The wheel reader's limits, which a jar must be able to pass.
    const OLD_ENTRIES: usize = 10_000;
    const OLD_BYTES: u64 = 64 * 1024 * 1024;

    /// A member's git hash is the buffered hash of its bytes, stored,
    /// deflated or empty; an absent member is `None`.
    #[test]
    fn a_member_hashes_as_its_bytes() {
        use std::io::Write as _;
        let members: [(&str, &[u8], zip::CompressionMethod); 3] = [
            ("stored.txt", b"hello world", zip::CompressionMethod::Stored),
            (
                "deflated.txt",
                &[b'a'; 100_000],
                zip::CompressionMethod::Deflated,
            ),
            ("empty.txt", b"", zip::CompressionMethod::Deflated),
        ];
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, bytes, method) in &members {
            let opts = zip::write::SimpleFileOptions::default().compression_method(*method);
            out.start_file(*name, opts).unwrap();
            out.write_all(bytes).unwrap();
        }
        let bytes = out.finish().unwrap().into_inner();
        let mut jar = Jar::of_bytes(&bytes).unwrap();
        for (name, content, _) in &members {
            assert_eq!(
                jar.member_git_sha256(name).unwrap().unwrap(),
                compute_git_sha256_from_bytes(content),
                "{name}"
            );
        }
        assert_eq!(jar.member_git_sha256("missing.txt").unwrap(), None);
    }

    #[test]
    fn a_jar_over_the_wheel_limits_is_read_member_by_member() {
        let bytes = big_jar(
            OLD_ENTRIES + 1,
            OLD_BYTES + 1024 * 1024,
            &[("a/B.class", b"code")],
        );
        // The reader this module replaces for jars refuses it.
        assert!(crate::vendor::verify::read_zip_bytes_to_map(&bytes).is_err());
        let digests = Digests::of_bytes(&bytes).unwrap();
        assert_eq!(digests.len(), OLD_ENTRIES + 2);
        let expected: [u8; 32] = Sha256::digest(b"code").into();
        assert_eq!(digests.get("a/B.class"), Some(&expected));
        assert_eq!(
            Jar::of_bytes(&bytes)
                .unwrap()
                .member_git_sha256("a/B.class")
                .unwrap(),
            Some(compute_git_sha256_from_bytes(b"code"))
        );
        assert_eq!(
            Jar::of_bytes(&bytes)
                .unwrap()
                .member_git_sha256("gone")
                .unwrap(),
            None
        );
    }

    #[test]
    fn member_digests_are_the_algorithms_a_manifest_names() {
        assert_eq!(hex::encode(md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(hex::encode(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        let bytes = jar(&[("a/B.class", b"abc")]);
        let digest = |algorithm: &str| {
            let mut jar = Jar::of_bytes(&bytes).unwrap();
            jar.member_digest("a/B.class", algorithm)
                .map(|d| d.map(hex::encode))
        };
        assert_eq!(
            digest("MD5").unwrap().unwrap(),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            digest("SHA-1").unwrap().unwrap(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(digest("SHA-256").unwrap().unwrap().len(), 64);
        assert!(digest("SHA-224").is_err());
        let mut jar = Jar::of_bytes(&bytes).unwrap();
        assert_eq!(
            jar.member_digest("a/Absent.class", "SHA-256").unwrap(),
            None
        );
    }

    #[test]
    fn the_entry_limit_names_the_count() {
        let members: Vec<(String, &[u8])> = (0..=MAX_ENTRIES)
            .map(|i| (format!("c/{i}"), b"".as_slice()))
            .collect();
        let members: Vec<(&str, &[u8])> = members.iter().map(|(n, b)| (n.as_str(), *b)).collect();
        let err = Digests::of_bytes(&jar(&members)).unwrap_err();
        assert!(err.is_too_large(), "{err:?}");
        assert_eq!(
            err.to_string(),
            format!(
                "it holds {} entries, over the limit of {MAX_ENTRIES}",
                MAX_ENTRIES + 1
            )
        );
    }

    /// The limits on the central directory are held to what the end records
    /// declare, before the zip reader parses (and allocates for) it: these
    /// archives have no directory to parse at all, so the refusal can only
    /// have come from the records.
    #[test]
    fn the_central_directory_is_bounded_before_it_is_parsed() {
        let end = |entries: u16, directory: u32| {
            let mut record = b"PK\x05\x06\0\0\0\0".to_vec();
            record.extend_from_slice(&entries.to_le_bytes());
            record.extend_from_slice(&entries.to_le_bytes());
            record.extend_from_slice(&directory.to_le_bytes());
            record.extend_from_slice(&[0; 6]);
            record
        };
        // Millions of 46-byte records fit a download: 200,001 of them here,
        // declared by a zip64 record and the locator that points at it.
        let entries = MAX_ENTRIES as u64 + 1;
        let mut many = vec![0u8; entries as usize * 46];
        let at = many.len() as u64;
        many.extend_from_slice(b"PK\x06\x06");
        many.extend_from_slice(&[0; 20]);
        many.extend_from_slice(&entries.to_le_bytes());
        many.extend_from_slice(&entries.to_le_bytes());
        many.extend_from_slice(&(entries * 46).to_le_bytes());
        many.extend_from_slice(&[0; 8]);
        many.extend_from_slice(b"PK\x06\x07\0\0\0\0");
        many.extend_from_slice(&at.to_le_bytes());
        many.extend_from_slice(&1u32.to_le_bytes());
        many.extend_from_slice(&end(u16::MAX, u32::MAX));
        let err = Jar::of_bytes(&many).err().expect("refused");
        assert_eq!(
            err.to_string(),
            format!("it holds {entries} entries, over the limit of {MAX_ENTRIES}")
        );
        assert!(err.is_too_large());

        // A directory of a few entries with 65 MiB of names and comments.
        let mut wide = vec![0u8; 65 * 1024 * 1024];
        wide.extend_from_slice(&end(3, 65 * 1024 * 1024));
        let err = Jar::of_bytes(&wide).err().expect("refused");
        assert_eq!(
            err.to_string(),
            "its central directory takes 65 MiB, over the limit of 64 MiB"
        );

        // Bytes that spell an end record but declare more than the archive
        // holds are not one: the real record decides.
        let lookalike = end(u16::MAX, u32::MAX);
        let real = jar(&[("a/B.class", &lookalike)]);
        assert_eq!(Digests::of_bytes(&real).unwrap().len(), 1);
    }

    /// What is inflated is bounded, whatever the entry declares: a deflated
    /// run of zeros is a few kilobytes of archive.
    #[test]
    fn the_inflate_limit_is_on_bytes_inflated_and_scales_with_the_archive() {
        use std::io::Write as _;
        let deflated = |size: u64| {
            let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            out.start_file("zeros.bin", opts).unwrap();
            std::io::copy(&mut std::io::repeat(0).take(size), &mut out).unwrap();
            out.start_file("a/B.class", opts).unwrap();
            out.write_all(b"code").unwrap();
            out.finish().unwrap().into_inner()
        };
        // At the floor: read.
        let at_floor = deflated(RATIO_FLOOR_BYTES - 4);
        assert!((at_floor.len() as u64) < RATIO_FLOOR_BYTES / MAX_INFLATE_RATIO);
        assert_eq!(Digests::of_bytes(&at_floor).unwrap().len(), 2);
        // One byte more than a small archive may inflate to: refused, by
        // both readers, with the ratio named.
        let over = deflated(RATIO_FLOOR_BYTES + 1);
        for err in [
            Digests::of_bytes(&over).unwrap_err(),
            Jar::of_bytes(&over)
                .unwrap()
                .member_git_sha256("zeros.bin")
                .unwrap_err(),
        ] {
            assert!(err.is_too_large(), "{err:?}");
            assert_eq!(
                err.to_string(),
                "it inflates to more than 64 MiB, over 100 times its own size (1 MiB) and the \
                 64 MiB every jar may use"
            );
        }
        assert_eq!(inflate_budget(0), RATIO_FLOOR_BYTES);
        assert_eq!(inflate_budget(2 * 1024 * 1024), 200 * 1024 * 1024);
        assert_eq!(inflate_budget(64 * 1024 * 1024), MAX_INFLATED_BYTES);
        assert_eq!(inflate_budget(u64::MAX), MAX_INFLATED_BYTES);
    }

    #[test]
    fn a_file_that_is_not_a_zip_is_unreadable() {
        let err = Digests::of_bytes(b"not a jar").unwrap_err();
        assert!(!err.is_too_large(), "{err:?}");
    }

    /// An entry with symlink mode bits is a member like any other: a JVM
    /// loads its bytes by name. Directory entries are not members.
    #[test]
    fn every_loadable_entry_is_a_member_whatever_its_mode() {
        let original = jar(&[("a/B.class", b"code"), ("META-INF/MANIFEST.MF", b"m")]);
        let smuggled = jar_with_modes(&[
            ("a/", b"", None),
            ("a/B.class", b"code", None),
            ("META-INF/MANIFEST.MF", b"m", None),
            ("a/Backdoor.class", b"evil", Some(0o120777)),
        ]);
        // The wheel reader does not see the entry at all.
        assert!(!crate::vendor::verify::read_zip_bytes_to_map(&smuggled)
            .unwrap()
            .contains_key("a/Backdoor.class"));
        let (original, smuggled) = (
            Digests::of_bytes(&original).unwrap(),
            Digests::of_bytes(&smuggled).unwrap(),
        );
        assert_eq!(smuggled.len(), 3, "the directory entry is not a member");
        let difference = unpatched_difference(&original, &smuggled, &[]);
        assert_eq!(difference.added, ["a/Backdoor.class"]);
        assert_eq!(difference.describe(), "1 added (`a/Backdoor.class`)");
    }

    #[test]
    fn the_difference_leaves_out_patched_members_and_signature_files() {
        let original = jar(&[
            ("META-INF/NOTICE.txt", b"pristine"),
            ("META-INF/SIGNER.SF", b"sig"),
            ("META-INF/SIGNER.RSA", b"sig"),
            ("a/B.class", b"code"),
            ("a/C.class", b"more"),
            ("a/Gone.class", b"gone"),
        ]);
        let candidate = jar(&[
            ("META-INF/NOTICE.txt", b"patched"),
            ("a/Added.class", b"added by the patch"),
            ("a/B.class", b"code"),
            ("a/C.class", b"changed"),
            ("a/New.class", b"new"),
        ]);
        let (original, candidate) = (
            Digests::of_bytes(&original).unwrap(),
            Digests::of_bytes(&candidate).unwrap(),
        );
        let patched = ["META-INF/NOTICE.txt", "a/Added.class"];
        let difference = unpatched_difference(&original, &candidate, &patched);
        assert_eq!(
            difference,
            Difference {
                added: vec!["a/New.class".into()],
                missing: vec!["a/Gone.class".into()],
                changed: vec!["a/C.class".into()],
                manifest: None,
            }
        );
        assert_eq!(
            difference.describe(),
            "1 added (`a/New.class`), 1 missing (`a/Gone.class`), 1 changed (`a/C.class`)"
        );
        assert!(unpatched_difference(&original, &original, &patched).is_empty());
        // Without the patch's names, its own members count.
        assert_eq!(
            unpatched_difference(&original, &candidate, &[]).changed,
            ["META-INF/NOTICE.txt", "a/C.class"]
        );
    }

    #[test]
    fn a_long_difference_shows_its_first_names() {
        let difference = Difference {
            added: (0..5).map(|i| format!("a/{i}")).collect(),
            ..Difference::default()
        };
        assert_eq!(difference.describe(), "5 added (`a/0`, `a/1`, `a/2`, …)");
    }
}
