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
//! the central directory's size are read from the archive's end record
//! before the zip reader parses the directory, since the reader allocates
//! for whatever that record declares: a directory of millions of tiny
//! records is refused unread.
//!
//! The reader does not take the end record from a fixed place. It looks
//! for one backwards from the end of the file, however much follows it,
//! finds a zip64 record forwards from where the locator points, and falls
//! back to an earlier end record when a directory does not parse. So
//! [`admit`] walks the same way: it finds the last end record the reader
//! can take, holds it to the limits, and hides everything below that
//! record's directory from the reader while the archive is opened
//! ([`Veiled`]). What the reader can then fall back to lies in the
//! directory itself, and each such record is held to the limits too. An
//! end record inside a member's data, as a jar stored inside a fat jar
//! has, is below the directory: the reader cannot take it, and it is not
//! looked at.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
    zip: zip::ZipArchive<Veiled<R>>,
    archive_len: u64,
    budget: u64,
    left: u64,
    /// Member indices by the raw bytes of their names; built on first use.
    names: Option<std::collections::HashMap<Vec<u8>, usize>>,
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
        let floor = Arc::new(AtomicU64::new(admit(&mut reader, archive_len)?));
        let veiled = Veiled {
            inner: reader,
            floor: Arc::clone(&floor),
        };
        let zip = zip::ZipArchive::new(veiled)
            .map_err(|e| JarError::Unreadable(format!("not a readable zip archive ({e})")))?;
        // The directory is parsed: the members are read from the real bytes.
        floor.store(0, Ordering::Relaxed);
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
            names: None,
        })
    }

    /// The index of the member `name`, matched on the raw bytes of the
    /// central directory, which is what a JVM matches on and what
    /// [`Self::content_digests`] keys by. The zip reader's own lookup is by
    /// a name it decodes as CP437 when the entry lacks the UTF-8 flag, so a
    /// UTF-8 name written without that flag would be missed. Of two entries
    /// with one name the last is the member.
    fn index_of(&mut self, name: &str) -> Option<usize> {
        if name.ends_with('/') {
            return None;
        }
        if self.names.is_none() {
            let mut names = std::collections::HashMap::new();
            for index in 0..self.zip.len() {
                if let Ok(entry) = self.zip.by_index_raw(index) {
                    names.insert(entry.name_raw().to_vec(), index);
                }
            }
            self.names = Some(names);
        }
        self.names.as_ref()?.get(name.as_bytes()).copied()
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
        let Some(index) = self.index_of(name) else {
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

    /// The bytes of the member `name`, read within the pass's budget (the
    /// only bound: a member a jar within the limits may hold is one that
    /// can be read); `None` when the jar has no such member.
    pub(crate) fn member_bytes(&mut self, name: &str) -> Result<Option<Vec<u8>>, JarError> {
        let mut bytes = Vec::new();
        let found = self.stream(name, |chunk| bytes.extend_from_slice(chunk))?;
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
            Md5(Md5),
        }
        let mut hasher = match algorithm.replace('-', "").to_ascii_uppercase().as_str() {
            "SHA1" => Hasher::Sha1(Default::default()),
            "SHA256" => Hasher::Sha256(Default::default()),
            "SHA384" => Hasher::Sha384(Default::default()),
            "SHA512" => Hasher::Sha512(Default::default()),
            "MD5" => Hasher::Md5(Md5::new()),
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
            Hasher::Md5(h) => h.update(chunk),
        })?;
        Ok(found.then(|| match hasher {
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
            Hasher::Md5(h) => h.finalize().to_vec(),
        }))
    }

    /// The git-blob sha256 of the member `name`, `None` when the jar has no
    /// such member. Counts against the pass's budget.
    pub(crate) fn member_git_sha256(&mut self, name: &str) -> Result<Option<String>, JarError> {
        let Some(index) = self.index_of(name) else {
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
/// crate has no MD5 otherwise, and nothing else here should use one). Fed
/// block by block, so a member is never held to be hashed.
struct Md5 {
    state: [u32; 4],
    block: [u8; 64],
    held: usize,
    length: u64,
}

impl Md5 {
    /// `floor(2^32 * abs(sin(i + 1)))`, as RFC 1321 tabulates it.
    const K: [u32; 64] = [
        0xd76a_a478,
        0xe8c7_b756,
        0x2420_70db,
        0xc1bd_ceee,
        0xf57c_0faf,
        0x4787_c62a,
        0xa830_4613,
        0xfd46_9501,
        0x6980_98d8,
        0x8b44_f7af,
        0xffff_5bb1,
        0x895c_d7be,
        0x6b90_1122,
        0xfd98_7193,
        0xa679_438e,
        0x49b4_0821,
        0xf61e_2562,
        0xc040_b340,
        0x265e_5a51,
        0xe9b6_c7aa,
        0xd62f_105d,
        0x0244_1453,
        0xd8a1_e681,
        0xe7d3_fbc8,
        0x21e1_cde6,
        0xc337_07d6,
        0xf4d5_0d87,
        0x455a_14ed,
        0xa9e3_e905,
        0xfcef_a3f8,
        0x676f_02d9,
        0x8d2a_4c8a,
        0xfffa_3942,
        0x8771_f681,
        0x6d9d_6122,
        0xfde5_380c,
        0xa4be_ea44,
        0x4bde_cfa9,
        0xf6bb_4b60,
        0xbebf_bc70,
        0x289b_7ec6,
        0xeaa1_27fa,
        0xd4ef_3085,
        0x0488_1d05,
        0xd9d4_d039,
        0xe6db_99e5,
        0x1fa2_7cf8,
        0xc4ac_5665,
        0xf429_2244,
        0x432a_ff97,
        0xab94_23a7,
        0xfc93_a039,
        0x655b_59c3,
        0x8f0c_cc92,
        0xffef_f47d,
        0x8584_5dd1,
        0x6fa8_7e4f,
        0xfe2c_e6e0,
        0xa301_4314,
        0x4e08_11a1,
        0xf753_7e82,
        0xbd3a_f235,
        0x2ad7_d2bb,
        0xeb86_d391,
    ];
    const SHIFTS: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    fn new() -> Self {
        Md5 {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            block: [0; 64],
            held: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.length = self.length.wrapping_add(input.len() as u64);
        while !input.is_empty() {
            let take = (64 - self.held).min(input.len());
            self.block[self.held..self.held + take].copy_from_slice(&input[..take]);
            self.held += take;
            input = &input[take..];
            if self.held == 64 {
                self.compress();
                self.held = 0;
            }
        }
    }

    fn compress(&mut self) {
        let block = self.block;
        let word = |i: usize| u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
        let [mut a, mut b, mut c, mut d] = self.state;
        for (i, (k, shift)) in Self::K.into_iter().zip(Self::SHIFTS).enumerate() {
            let (mix, at) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let rotated = a
                .wrapping_add(mix)
                .wrapping_add(k)
                .wrapping_add(word(at))
                .rotate_left(shift);
            (a, d, c, b) = (d, c, b, b.wrapping_add(rotated));
        }
        for (sum, add) in self.state.iter_mut().zip([a, b, c, d]) {
            *sum = sum.wrapping_add(add);
        }
    }

    fn finalize(mut self) -> [u8; 16] {
        let bits = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.held != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_le_bytes());
        let mut out = [0u8; 16];
        for (bytes, word) in out.chunks_mut(4).zip(self.state) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// A reader that shows zeros below `floor`, for as long as `floor` is set:
/// what the zip reader is given while it opens an archive, so that it
/// cannot take an end record [`admit`] did not look at.
pub(crate) struct Veiled<R> {
    inner: R,
    floor: Arc<AtomicU64>,
}

impl<R: Read + Seek> Read for Veiled<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let floor = self.floor.load(Ordering::Relaxed);
        if floor == 0 {
            return self.inner.read(buf);
        }
        let at = self.inner.stream_position()?;
        if at >= floor {
            return self.inner.read(buf);
        }
        let hidden = (floor - at).min(buf.len() as u64) as usize;
        buf[..hidden].fill(0);
        self.inner.seek(SeekFrom::Current(hidden as i64))?;
        Ok(hidden)
    }
}

impl<R: Seek> Seek for Veiled<R> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

/// End records [`admit`] passes over before it gives the archive up.
const MAX_RECORDS_PASSED_OVER: usize = 64;

const END: &[u8; 4] = b"PK\x05\x06";
const END64: &[u8; 4] = b"PK\x06\x06";
const LOCATOR: &[u8; 4] = b"PK\x06\x07";
const CENTRAL: &[u8; 4] = b"PK\x01\x02";

fn le(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0u64, |n, b| (n << 8) | u64::from(*b))
}

/// `bytes` at `at`, when the archive holds them.
fn read_at<R: Read + Seek, const N: usize>(
    reader: &mut R,
    at: u64,
    len: u64,
) -> std::io::Result<Option<[u8; N]>> {
    if at.checked_add(N as u64).is_none_or(|end| end > len) {
        return Ok(None);
    }
    let mut bytes = [0u8; N];
    reader.seek(SeekFrom::Start(at))?;
    reader.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

/// The offsets of `magic` in `[from, to)`, a window at a time: the last
/// first when `backwards`. `visit` returns `true` to stop.
fn scan<R: Read + Seek>(
    reader: &mut R,
    magic: &[u8; 4],
    (from, to): (u64, u64),
    backwards: bool,
    mut visit: impl FnMut(&mut R, u64) -> Result<bool, JarError>,
) -> Result<(), JarError> {
    const WINDOW: u64 = 64 * 1024;
    let unread = |e: std::io::Error| JarError::Unreadable(format!("it cannot be read ({e})"));
    let (mut low, mut high) = (from, to);
    while high.saturating_sub(low) >= 4 {
        // Windows overlap by three bytes, so a magic across an edge is seen.
        let (start, end) = match backwards {
            true => (high.saturating_sub(WINDOW).max(low), high),
            false => (low, low.saturating_add(WINDOW).min(high)),
        };
        let mut window = vec![0u8; (end - start) as usize];
        reader.seek(SeekFrom::Start(start)).map_err(unread)?;
        reader.read_exact(&mut window).map_err(unread)?;
        let mut hits: Vec<u64> = window
            .windows(4)
            .enumerate()
            .filter(|(_, bytes)| bytes == magic)
            .map(|(i, _)| start + i as u64)
            .collect();
        if backwards {
            hits.reverse();
        }
        for hit in hits {
            if visit(reader, hit)? {
                return Ok(());
            }
        }
        match backwards {
            true if start == low => break,
            true => high = start + 3,
            false if end == high => break,
            false => low = end - 3,
        }
    }
    Ok(())
}

/// Decide, before the zip reader parses anything, which end record it can
/// take from the archive `reader` holds, and hold what that record declares
/// to [`MAX_ENTRIES`] and [`MAX_CENTRAL_DIRECTORY_BYTES`]. Returns the
/// offset of that record's central directory: the reader is shown zeros
/// below it while it opens the archive ([`Veiled`]), so the only end
/// records it can fall back to are in the directory itself, and those are
/// held to the limits here as well.
///
/// The walk is the reader's own (`zip` 8.6, `find_central_directory`): end
/// records from the end of the file backwards, whatever follows them; a
/// zip32 record is taken when a central header is found forwards from the
/// offset it declares; a record that may be zip64 and has a locator before
/// it is taken with the first zip64 record, forwards from where the locator
/// points, that ends where the locator begins. A record the reader would
/// pass over is passed over here, up to [`MAX_RECORDS_PASSED_OVER`] of
/// them. An archive with no record it could take is handed over unveiled:
/// every end record in it was looked at.
fn admit<R: Read + Seek>(reader: &mut R, len: u64) -> Result<u64, JarError> {
    let unread = |e: std::io::Error| JarError::Unreadable(format!("its end cannot be read ({e})"));
    let within = |entries: u64, directory: u64| {
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
    // Nothing below `floor` is looked at once a record has been taken.
    let mut floor: Option<u64> = None;
    let mut passed_over = 0;
    scan(reader, END, (0, len), true, |reader, at| {
        let bottom = floor.unwrap_or(0);
        if at < bottom {
            return Ok(true);
        }
        // The record and its comment must fit the file.
        let Some(end) = read_at::<_, 22>(reader, at, len).map_err(unread)? else {
            return Ok(false);
        };
        if at + 22 + le(&end[20..22]) > len {
            return Ok(false);
        }
        let (on_disk, total) = (le(&end[8..10]), le(&end[10..12]));
        let (size, offset) = (le(&end[12..16]), le(&end[16..20]));
        let may_be_zip64 = total == 0xffff || size == 0xffff_ffff || offset == 0xffff_ffff;
        let locator = match at.checked_sub(20) {
            Some(before) if may_be_zip64 && before >= bottom => {
                read_at::<_, 20>(reader, before, len)
                    .map_err(unread)?
                    .filter(|bytes| bytes.starts_with(LOCATOR))
                    .map(|bytes| (before, le(&bytes[8..16])))
            }
            _ => None,
        };
        let mut directory = None;
        match locator {
            // zip64: the first record, forwards from where the locator
            // points, that ends where the locator begins.
            Some((locator_at, declared)) if declared < locator_at => {
                let range = (declared.max(bottom), locator_at);
                scan(reader, END64, range, false, |reader, x| {
                    let Some(record) = read_at::<_, 56>(reader, x, len).map_err(unread)? else {
                        return Ok(false);
                    };
                    if le(&record[4..12]).checked_add(12) != Some(locator_at - x) {
                        return Ok(false);
                    }
                    within(le(&record[32..40]), le(&record[40..48]))?;
                    // Prepended bytes move the directory with the record.
                    directory = le(&record[48..56]).checked_add(x - declared);
                    Ok(true)
                })?;
            }
            Some(_) => {}
            // An empty archive: nothing of a directory is read.
            None if total == 0 => directory = Some(at),
            // zip32: the first central header forwards from the offset.
            None if offset < at => {
                scan(
                    reader,
                    CENTRAL,
                    (offset.max(bottom), at),
                    false,
                    |_, header| {
                        directory = Some(header);
                        Ok(true)
                    },
                )?;
                if directory.is_some() {
                    within(on_disk.max(total), size)?;
                }
            }
            None => {}
        }
        match directory {
            Some(start) if floor.is_none() => floor = Some(start.min(at)),
            Some(_) => {}
            // Each record passed over costs a search of the file, here and
            // in the reader: an archive strewn with them is not a jar.
            None => {
                passed_over += 1;
                if passed_over > MAX_RECORDS_PASSED_OVER {
                    return Err(JarError::Unreadable(format!(
                        "it holds more than {MAX_RECORDS_PASSED_OVER} end records that lead to \
                         no central directory"
                    )));
                }
            }
        }
        Ok(false)
    })?;
    reader.seek(SeekFrom::Start(0)).map_err(unread)?;
    Ok(floor.unwrap_or(0))
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
    pub(crate) fn get(&self, name: impl AsRef<[u8]>) -> Option<&[u8; 32]> {
        self.0.get(name.as_ref())
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
    /// Why the manifest of a signed jar, when it is among `changed`, is not
    /// the original's as signing the jar again leaves it
    /// ([`super::jar_manifest`]). `None` for a jar that is not signed: its
    /// manifest is a changed member like any other.
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
            format!("the manifest is not the original's as signing the jar again leaves it: {why}")
        }))
        .collect::<Vec<_>>()
        .join(", ")
    }
}

/// [`unpatched_difference`] of two jars `(bytes, members)` for the record
/// `files`, less the manifest of a signed jar that differs only as signing
/// the patched jar again leaves it ([`super::jar_manifest::resigned`]): the
/// one member outside the patch whose content may change, and only so.
/// `Err` is a jar past a limit while its manifest was read.
pub(crate) fn difference_outside_patch(
    original: (&[u8], &Digests),
    patched: (&[u8], &Digests),
    files: &std::collections::HashMap<String, crate::manifest::schema::PatchFileInfo>,
) -> Result<Difference, JarError> {
    use super::jar_manifest::{resigned, Resigned, MANIFEST};
    let names: Vec<&str> = files
        .keys()
        .map(|key| crate::patch::apply::normalize_file_path(key))
        .collect();
    let mut difference = unpatched_difference(original.1, patched.1, &names);
    if let Some(at) = difference.changed.iter().position(|name| name == MANIFEST) {
        match resigned(original, patched, files)? {
            // Not signed: a base mismatch like any other member's.
            Resigned::Unsigned => {}
            Resigned::Accepted => {
                difference.changed.remove(at);
            }
            Resigned::Refused(why) => difference.manifest = Some(why),
        }
    }
    Ok(difference)
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

    /// `jar` with the UTF-8 flag cleared on every entry, as an archiver
    /// that writes UTF-8 names without announcing them leaves it. For jars
    /// whose member bytes do not spell a zip header.
    pub(crate) fn without_utf8_flag(mut jar: Vec<u8>) -> Vec<u8> {
        for at in 0..jar.len().saturating_sub(10) {
            match &jar[at..at + 4] {
                b"PK\x03\x04" => jar[at + 7] &= !0x08,
                b"PK\x01\x02" => jar[at + 9] &= !0x08,
                _ => {}
            }
        }
        jar
    }

    /// An archive whose end records declare `entries` 46-byte central
    /// records where a directory would be, and hold none: a zip64 record
    /// that ends where its locator begins, the locator (pointing `early`
    /// bytes before the record) and a zip32 record that defers to them.
    /// The zip reader takes these records, and would allocate for the
    /// directory they declare.
    pub(crate) fn declares_entries(entries: u64, early: u64) -> Vec<u8> {
        let mut archive = vec![0u8; entries as usize * 46];
        let at = archive.len() as u64;
        archive.extend_from_slice(b"PK\x06\x06");
        archive.extend_from_slice(&44u64.to_le_bytes());
        archive.extend_from_slice(&[0; 12]);
        archive.extend_from_slice(&entries.to_le_bytes());
        archive.extend_from_slice(&entries.to_le_bytes());
        archive.extend_from_slice(&(entries * 46).to_le_bytes());
        archive.extend_from_slice(&[0; 8]);
        archive.extend_from_slice(b"PK\x06\x07\0\0\0\0");
        archive.extend_from_slice(&(at - early).to_le_bytes());
        archive.extend_from_slice(&1u32.to_le_bytes());
        archive.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        archive.extend_from_slice(&[0xff; 12]);
        archive.extend_from_slice(&[0; 2]);
        archive
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

    /// A member is found by the raw bytes of its name. A UTF-8 name written
    /// without the UTF-8 flag is one the zip reader decodes as CP437, so its
    /// own lookup misses it; a JVM reads the bytes.
    #[test]
    fn a_member_is_found_by_the_raw_bytes_of_its_name() {
        const NAME: &str = "org/x/\u{dc}n\u{ef}.class";
        let bytes = testing::without_utf8_flag(jar(&[(NAME, b"code"), ("a/B.class", b"b")]));
        let decoded: Vec<String> = zip::ZipArchive::new(std::io::Cursor::new(&bytes))
            .unwrap()
            .file_names()
            .map(str::to_string)
            .collect();
        assert!(!decoded.iter().any(|name| name == NAME), "{decoded:?}");
        let mut jar = Jar::of_bytes(&bytes).unwrap();
        assert_eq!(
            jar.member_git_sha256(NAME).unwrap(),
            Some(compute_git_sha256_from_bytes(b"code"))
        );
        assert_eq!(
            jar.member_bytes(NAME).unwrap().as_deref(),
            Some(&b"code"[..])
        );
        assert!(jar.member_digest(NAME, "SHA-1").unwrap().is_some());
        assert!(Digests::of_bytes(&bytes).unwrap().get(NAME).is_some());
        assert_eq!(jar.member_git_sha256("org/x/absent.class").unwrap(), None);
    }

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
        // The RFC 1321 test suite, the multi-block vectors among them.
        let md5 = |input: &[u8]| {
            let mut whole = Md5::new();
            whole.update(input);
            let mut pieces = Md5::new();
            input.chunks(7).for_each(|piece| pieces.update(piece));
            let digest = hex::encode(whole.finalize());
            assert_eq!(digest, hex::encode(pieces.finalize()), "fed in pieces");
            digest
        };
        const LETTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let digits = b"1234567890".repeat(8);
        for (input, digest) in [
            (&b""[..], "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (LETTERS, "d174ab98d277d9f5a5611c2c9f419d9f"),
            (&digits, "57edf4a22be3c955ac49da2e2107b67a"),
        ] {
            assert_eq!(md5(input), digest, "{:?}", String::from_utf8_lossy(input));
        }
        // A member of more than one block, and of many.
        let long = b"1234567890".repeat(100_000);
        let big = jar(&[("a/Digits.class", &digits), ("a/Long.class", &long)]);
        let mut big = Jar::of_bytes(&big).unwrap();
        assert_eq!(
            big.member_digest("a/Digits.class", "MD5")
                .unwrap()
                .map(hex::encode)
                .unwrap(),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
        assert_eq!(
            big.member_digest("a/Long.class", "MD5")
                .unwrap()
                .map(hex::encode)
                .unwrap(),
            md5(&long)
        );
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

    /// The limits on the central directory are held to what the end record
    /// declares, before the zip reader parses (and allocates for) it,
    /// wherever in the file that record sits. These archives have no
    /// directory to parse at all, so the refusal can only have come from
    /// the record; and the reader would take each of them, since the
    /// records are consistent.
    #[test]
    fn the_central_directory_is_bounded_before_it_is_parsed() {
        let entries = MAX_ENTRIES as u64 + 1;
        let limit = format!("it holds {entries} entries, over the limit of {MAX_ENTRIES}");
        let refused = |archive: &[u8]| Jar::of_bytes(archive).err().expect("refused").to_string();
        // Millions of 46-byte records fit a download: 200,001 of them here.
        assert_eq!(refused(&testing::declares_entries(entries, 0)), limit);
        // The reader finds an end record however much follows it.
        let mut trailed = testing::declares_entries(entries, 0);
        trailed.extend_from_slice(&[0u8; 70_000]);
        assert_eq!(refused(&trailed), limit);
        let mut trailed = testing::declares_entries(entries, 0);
        trailed.extend_from_slice(&vec![0x20u8; 3 * 1024 * 1024]);
        assert_eq!(refused(&trailed), limit);
        // It finds the zip64 record forwards from where the locator points.
        let mut early = testing::declares_entries(entries, 100);
        assert_eq!(refused(&early), limit);
        early.extend_from_slice(&[0u8; 70_000]);
        assert_eq!(refused(&early), limit);

        // A directory of a few entries with 65 MiB of names and comments.
        let mut wide = vec![0u8; 65 * 1024 * 1024];
        wide[..4].copy_from_slice(b"PK\x01\x02");
        wide.extend_from_slice(b"PK\x05\x06\0\0\0\0\x03\0\x03\0");
        wide.extend_from_slice(&(65u32 * 1024 * 1024).to_le_bytes());
        wide.extend_from_slice(&[0; 6]);
        assert_eq!(
            refused(&wide),
            "its central directory takes 65 MiB, over the limit of 64 MiB"
        );

        // End records that lead nowhere are passed over, as the reader
        // passes over them; an archive strewn with them is given up.
        // (Each declares one entry at offset 0, where no central header is.)
        let nowhere = b"PK\x05\x06\0\0\0\0\x01\0\x01\0\0\0\0\0\0\0\0\0\0\0";
        assert_eq!(
            refused(&nowhere.repeat(MAX_RECORDS_PASSED_OVER + 1)),
            "it holds more than 64 end records that lead to no central directory"
        );
        assert!(refused(&nowhere.repeat(2)).starts_with("not a readable zip archive"));

        // Bytes that spell an end record in a member's data are not one.
        let lookalike = testing::declares_entries(entries, 0);
        let real = jar(&[("a/B.class", &lookalike[lookalike.len() - 98..])]);
        assert_eq!(Digests::of_bytes(&real).unwrap().len(), 1);
    }

    /// The same for a real archive of 200,001 entries, which the reader
    /// would parse whole: with bytes after it, the check before the parse
    /// still refuses it (the count after the parse would too, having paid
    /// for the parse).
    #[test]
    fn an_archive_past_the_limit_is_refused_unparsed_with_bytes_after_it() {
        let members: Vec<(String, &[u8])> = (0..=MAX_ENTRIES)
            .map(|i| (format!("c/{i}"), b"".as_slice()))
            .collect();
        let members: Vec<(&str, &[u8])> = members.iter().map(|(n, b)| (n.as_str(), *b)).collect();
        let mut archive = jar(&members);
        let limit = format!(
            "it holds {} entries, over the limit of {MAX_ENTRIES}",
            MAX_ENTRIES + 1
        );
        let admitted = |archive: &[u8]| {
            admit(&mut std::io::Cursor::new(archive), archive.len() as u64)
                .map_err(|e| e.to_string())
        };
        assert_eq!(admitted(&archive), Err(limit.clone()));
        archive.extend_from_slice(&[0u8; 70_000]);
        assert_eq!(admitted(&archive), Err(limit));
    }

    /// A fat jar holds other jars as stored members, end records and all.
    /// The reader cannot take a record below the outer directory, so a
    /// nested jar is not looked at, whatever its own end record declares:
    /// the outer directory is what counts, and the members read as ever.
    #[test]
    fn a_fat_jar_with_a_stored_nested_jar_is_accepted() {
        let small = jar(&[("inner/A.class", b"inner")]);
        let huge = testing::declares_entries(MAX_ENTRIES as u64 + 1, 0);
        for nested in [&small, &huge] {
            assert!(nested.windows(4).any(|bytes| bytes == END));
            let fat = jar(&[
                ("BOOT-INF/classes/App.class", b"app"),
                ("BOOT-INF/lib/first.jar", &small),
                ("BOOT-INF/lib/nested.jar", nested),
            ]);
            let digests = Digests::of_bytes(&fat).unwrap();
            assert_eq!(digests.len(), 3);
            let mut outer = Jar::of_bytes(&fat).unwrap();
            assert_eq!(
                outer.member_git_sha256("BOOT-INF/lib/nested.jar").unwrap(),
                Some(compute_git_sha256_from_bytes(nested))
            );
            // With bytes after the outer end record as well.
            let mut trailed = fat.clone();
            trailed.extend_from_slice(&[0u8; 70_000]);
            assert_eq!(Digests::of_bytes(&trailed).unwrap(), digests);
        }
        // On its own the nested archive is past the limit.
        assert!(Jar::of_bytes(&huge).is_err_and(|e| e.is_too_large()));
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
