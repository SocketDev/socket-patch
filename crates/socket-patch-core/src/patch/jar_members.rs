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
//! none of the limits trusts them: the count is the central directory's own,
//! and the byte limits are on what is actually inflated.
//!
//! * [`MAX_ENTRIES`]: 200,000 entries. Eight times the largest jar measured
//!   above; the jars a 128 MiB download can carry stay well under it.
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
use std::io::{Read, Seek};

use sha2::{Digest, Sha256};

use crate::hash::git_sha256::compute_git_sha256_from_std_reader;

/// Entries one jar may hold (see the module docs).
pub(crate) const MAX_ENTRIES: usize = 200_000;
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
    pub(crate) fn open(reader: R, archive_len: u64) -> Result<Self, JarError> {
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
    #[cfg(test)]
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
        .collect::<Vec<_>>()
        .join(", ")
    }
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
