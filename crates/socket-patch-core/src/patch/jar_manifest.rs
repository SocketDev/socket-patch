//! The one way a patched jar's `META-INF/MANIFEST.MF` may differ from the
//! original's: the per-entry digests of a re-signed jar.
//!
//! A signed jar's manifest holds a section per entry with the entry's
//! digests, and its signature files vouch for the manifest. Changing a class
//! therefore breaks the signature, and a JVM that requires one (a JCE
//! provider such as Bouncy Castle's) refuses the jar. So the patch service
//! re-signs such a jar with its own certificate: upstream's signature files
//! go, its own are added, and the manifest sections of the members the patch
//! touches get the digests of the patched members. Signature files are
//! already outside the "everything else is the original's" comparison
//! ([`super::jar_members::unpatched_difference`]); the manifest is a member
//! like any other, so that comparison refuses it.
//!
//! [`resigned_refusal`] accepts exactly that manifest and nothing else:
//!
//! * the patched jar carries at least one signature file (an unsigned jar
//!   has no reason for an edited manifest);
//! * the main section is byte for byte the original's;
//! * the section of every member the record does not touch is present on
//!   both sides, byte for byte the same;
//! * the section of a member the record changes differs only in the values
//!   of its `<ALG>-Digest` attributes (same attributes, same order), and
//!   every digest in it is the digest of the member in the patched jar;
//! * a section is added only for a member the record adds (holding its name
//!   and verified digests alone), and removed only for one it deletes.
//!
//! Sections are compared as the byte ranges the file holds, never as
//! re-serialised text. The file is read as the JAR specification lays it
//! out: lines end in `\r\n`, `\n` or `\r`, a line that starts with a space
//! continues the one before (lines wrap at 72 bytes), and a blank line ends
//! a section.

use std::collections::{BTreeMap, HashMap};

use base64::Engine as _;

use super::jar_members::Jar;
use crate::manifest::schema::PatchFileInfo;
use crate::patch::apply::normalize_file_path;

pub(crate) const MANIFEST: &str = "META-INF/MANIFEST.MF";
/// The largest manifest read. `bcprov-jdk18on`'s, with a section for each
/// of 4,000 classes, is under 1 MiB.
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// One attribute of a section: its name, its value with continuation lines
/// joined, and the bytes it takes in the file (terminators included).
struct Attribute<'a> {
    name: &'a [u8],
    value: Vec<u8>,
    raw: &'a [u8],
}

/// A manifest: the main section and the per-entry ones by entry name, each
/// as the bytes of its lines.
struct Sections<'a> {
    main: &'a [u8],
    entries: BTreeMap<Vec<u8>, &'a [u8]>,
}

/// The end of the line that starts at `at`: `(content end, next line)`.
fn line_end(text: &[u8], at: usize) -> (usize, usize) {
    let mut end = at;
    while end < text.len() && text[end] != b'\n' && text[end] != b'\r' {
        end += 1;
    }
    let next = match text.get(end) {
        Some(b'\r') if text.get(end + 1) == Some(&b'\n') => end + 2,
        Some(_) => end + 1,
        None => end,
    };
    (end, next)
}

/// The attributes of one section's bytes.
fn attributes(section: &[u8]) -> Result<Vec<Attribute<'_>>, String> {
    let mut out: Vec<Attribute<'_>> = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < section.len() {
        let (end, next) = line_end(section, at);
        let line = &section[at..end];
        if let Some(more) = line.strip_prefix(b" ") {
            let last = out.last_mut().ok_or("it starts with a continuation line")?;
            last.value.extend_from_slice(more);
            last.raw = &section[start..next];
        } else {
            let colon = line
                .windows(2)
                .position(|w| w == b": ")
                .ok_or("it holds a line that is not `Name: value`")?;
            start = at;
            out.push(Attribute {
                name: &line[..colon],
                value: line[colon + 2..].to_vec(),
                raw: &section[at..next],
            });
        }
        at = next;
    }
    Ok(out)
}

/// Split a manifest into its sections.
fn sections(manifest: &[u8]) -> Result<Sections<'_>, String> {
    let mut runs: Vec<&[u8]> = Vec::new();
    let mut start = None;
    let mut at = 0;
    let mut leading_blank = false;
    while at < manifest.len() {
        let (end, next) = line_end(manifest, at);
        if end == at {
            match start.take() {
                Some(from) => runs.push(&manifest[from..at]),
                None if runs.is_empty() => leading_blank = true,
                None => {}
            }
        } else if start.is_none() {
            start = Some(at);
        }
        at = next;
    }
    if let Some(from) = start {
        runs.push(&manifest[from..]);
    }
    let mut runs = runs.into_iter();
    // A manifest that opens with a blank line has an empty main section.
    let main = match leading_blank {
        true => &manifest[..0],
        false => runs.next().unwrap_or(&manifest[..0]),
    };
    let mut entries = BTreeMap::new();
    for run in runs {
        let name = match attributes(run)?.first() {
            Some(first) if first.name.eq_ignore_ascii_case(b"Name") => first.value.clone(),
            _ => return Err("a section does not start with `Name:`".to_string()),
        };
        let shown = String::from_utf8_lossy(&name).into_owned();
        if entries.insert(name, run).is_some() {
            return Err(format!("it holds two sections for `{shown}`"));
        }
    }
    Ok(Sections { main, entries })
}

/// The algorithm an attribute named `<ALG>-Digest` names.
fn digest_algorithm(attribute: &[u8]) -> Option<&[u8]> {
    const SUFFIX: &[u8] = b"-Digest";
    let at = attribute.len().checked_sub(SUFFIX.len())?;
    attribute[at..]
        .eq_ignore_ascii_case(SUFFIX)
        .then_some(&attribute[..at])
}

/// Every `<ALG>-Digest` of `section` is the digest of `member` in `jar`.
/// `Err` says which is not.
fn digests_hold<R: std::io::Read + std::io::Seek>(
    jar: &mut Jar<R>,
    member: &str,
    section: &[Attribute<'_>],
) -> Result<(), String> {
    let mut digests = 0;
    for attribute in section {
        let Some(algorithm) = digest_algorithm(attribute.name) else {
            continue;
        };
        digests += 1;
        let algorithm = String::from_utf8_lossy(algorithm);
        let actual = jar
            .member_digest(member, &algorithm)
            .map_err(|e| format!("`{member}` could not be hashed ({e})"))?
            .ok_or_else(|| {
                format!("it has a section for `{member}`, which the jar does not hold")
            })?;
        let declared = base64::engine::general_purpose::STANDARD
            .decode(&attribute.value)
            .ok();
        if declared.as_deref() != Some(actual.as_slice()) {
            return Err(format!(
                "its {algorithm} digest of `{member}` does not match the member in the jar"
            ));
        }
    }
    if digests == 0 {
        return Err(format!("its section for `{member}` holds no digest"));
    }
    Ok(())
}

/// Why `patched`'s manifest is not `original`'s as a re-signing of the
/// record `files` leaves it (see the module docs); `None` when it is.
pub(crate) fn resigned_refusal(
    original: &[u8],
    patched: &[u8],
    files: &HashMap<String, PatchFileInfo>,
) -> Option<String> {
    resigned(original, patched, files).err()
}

fn resigned(
    original: &[u8],
    patched: &[u8],
    files: &HashMap<String, PatchFileInfo>,
) -> Result<(), String> {
    let read = |jar: &[u8], whose: &str| -> Result<Vec<u8>, String> {
        Jar::of_bytes(jar)
            .and_then(|mut jar| jar.member_bytes(MANIFEST, MAX_MANIFEST_BYTES))
            .map_err(|e| format!("{whose} manifest cannot be read ({e})"))?
            .ok_or_else(|| format!("{whose} jar has no manifest"))
    };
    let mut jar = Jar::of_bytes(patched).map_err(|e| e.to_string())?;
    if !jar.has_signature_file() {
        return Err("the patched jar is not signed, so nothing accounts for it".to_string());
    }
    let (before, after) = (
        read(original, "the original")?,
        read(patched, "the patched")?,
    );
    let old = sections(&before).map_err(|why| format!("the original manifest: {why}"))?;
    let new = sections(&after).map_err(|why| format!("the patched manifest: {why}"))?;
    if old.main != new.main {
        return Err("its main attributes differ".to_string());
    }
    let touched: HashMap<&str, &PatchFileInfo> = files
        .iter()
        .map(|(key, info)| (normalize_file_path(key), info))
        .collect();
    let names: std::collections::BTreeSet<&Vec<u8>> =
        old.entries.keys().chain(new.entries.keys()).collect();
    for name in names {
        let member = String::from_utf8_lossy(name);
        let (was, is) = (old.entries.get(name), new.entries.get(name));
        let Some(info) = touched.get(member.as_ref()) else {
            match (was, is) {
                (Some(was), Some(is)) if was == is => continue,
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "its section for `{member}`, which the patch does not touch, differs"
                    ))
                }
                (None, _) => {
                    return Err(format!(
                        "it adds a section for `{member}`, which the patch does not add"
                    ))
                }
                (Some(_), None) => {
                    return Err(format!(
                        "it drops the section for `{member}`, which the patch does not delete"
                    ))
                }
            }
        };
        match (was, is) {
            (Some(_), None) if info.after_hash.is_empty() => {}
            (Some(_), None) => {
                return Err(format!(
                    "it drops the section for `{member}`, which the patch does not delete"
                ))
            }
            (None, Some(is)) if info.before_hash.is_empty() => {
                let is = attributes(is)?;
                if is
                    .iter()
                    .skip(1)
                    .any(|a| digest_algorithm(a.name).is_none())
                {
                    return Err(format!(
                        "its section for the added `{member}` holds more than digests"
                    ));
                }
                digests_hold(&mut jar, &member, &is)?;
            }
            (None, Some(_)) => {
                return Err(format!(
                    "it adds a section for `{member}`, which the patch does not add"
                ))
            }
            (Some(was), Some(is)) => {
                let (was, is) = (attributes(was)?, attributes(is)?);
                let same = was.len() == is.len()
                    && was.iter().zip(&is).all(|(was, is)| {
                        was.name == is.name
                            && (digest_algorithm(is.name).is_some() || was.raw == is.raw)
                    });
                if !same {
                    return Err(format!(
                        "its section for `{member}` differs in more than its digest values"
                    ));
                }
                digests_hold(&mut jar, &member, &is)?;
            }
            (None, None) => unreachable!("a name comes from one of the two manifests"),
        }
    }
    Ok(())
}

/// A real signed jar and its re-signed, patched twin, for the tests of the
/// comparisons that use the rule.
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use std::io::{Read as _, Write as _};

    /// A jar `jarsigner` signed (alias `upstream`, SHA-256 digests), and
    /// the same jar with `org/example/B.class` changed, upstream's
    /// signature files dropped and `jarsigner` run again under the alias
    /// `SOCKET`: what the patch service's re-signing produces. See
    /// `tests/data/resigned-provider/make.sh`.
    pub(crate) const UPSTREAM: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/resigned-provider/upstream.jar"
    ));
    pub(crate) const SERVED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/resigned-provider/served.jar"
    ));
    pub(crate) const CHANGED: &str = "org/example/B.class";
    const BEFORE: &[u8] = b"\xca\xfe\xba\xbe class B, vulnerable";
    const AFTER: &[u8] = b"\xca\xfe\xba\xbe class B, fixed";

    /// The record that changes [`CHANGED`].
    pub(crate) fn record() -> HashMap<String, PatchFileInfo> {
        HashMap::from([(
            CHANGED.to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(BEFORE),
                after_hash: compute_git_sha256_from_bytes(AFTER),
            },
        )])
    }

    /// `jar` rewritten: `keep` picks its entries, `manifest` rewrites the
    /// manifest's text, and `extra` members are appended.
    pub(crate) fn rewritten(
        jar: &[u8],
        keep: impl Fn(&str) -> bool,
        manifest: impl Fn(String) -> String,
        extra: &[(&str, &[u8])],
    ) -> Vec<u8> {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(jar)).unwrap();
        let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i).unwrap();
            let name = entry.name().to_string();
            if name.ends_with('/') || !keep(&name) {
                continue;
            }
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            if name == MANIFEST {
                bytes = manifest(String::from_utf8(bytes).unwrap()).into_bytes();
            }
            out.start_file(name, opts).unwrap();
            out.write_all(&bytes).unwrap();
        }
        for (name, bytes) in extra {
            out.start_file(*name, opts).unwrap();
            out.write_all(bytes).unwrap();
        }
        out.finish().unwrap().into_inner()
    }

    /// [`SERVED`] with its manifest's text rewritten.
    pub(crate) fn edited(manifest: impl Fn(String) -> String) -> Vec<u8> {
        rewritten(SERVED, |_| true, manifest, &[])
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::patch::jar_members::{difference_outside_patch, Digests};

    /// The `SHA-256-Digest` line of `member`'s section in `manifest`.
    fn digest_line(manifest: &str, member: &str) -> String {
        let at = manifest.find(&format!("Name: {member}\r\n")).unwrap();
        manifest[at..].lines().nth(1).unwrap().to_string()
    }

    #[test]
    fn the_fixture_is_a_resigned_jar() {
        let names = |jar: &[u8]| -> Vec<String> {
            let zip = zip::ZipArchive::new(std::io::Cursor::new(jar)).unwrap();
            let mut names: Vec<String> = zip.file_names().map(str::to_string).collect();
            names.retain(|n| n.starts_with("META-INF/") && !n.ends_with('/'));
            names.sort();
            names
        };
        assert_eq!(
            names(UPSTREAM),
            [
                "META-INF/MANIFEST.MF",
                "META-INF/UPSTREAM.RSA",
                "META-INF/UPSTREAM.SF"
            ]
        );
        assert_eq!(
            names(SERVED),
            [
                "META-INF/MANIFEST.MF",
                "META-INF/SOCKET.RSA",
                "META-INF/SOCKET.SF"
            ]
        );
    }

    /// The re-signed jar is accepted: against the installed jar as the
    /// agent swap compares them, and nothing is left of the difference.
    #[test]
    fn a_resigned_jar_with_one_class_changed_is_accepted() {
        assert_eq!(resigned_refusal(UPSTREAM, SERVED, &record()), None);
        let (original, patched) = (
            Digests::of_bytes(UPSTREAM).unwrap(),
            Digests::of_bytes(SERVED).unwrap(),
        );
        let difference =
            difference_outside_patch((UPSTREAM, &original), (SERVED, &patched), &record());
        assert!(difference.is_empty(), "{}", difference.describe());
        // Line endings and wrapping are the file's own: the same jar with
        // `\n` endings on both sides is accepted too.
        let unix = |jar: &[u8]| rewritten(jar, |_| true, |m| m.replace("\r\n", "\n"), &[]);
        assert_eq!(
            resigned_refusal(&unix(UPSTREAM), &unix(SERVED), &record()),
            None
        );
    }

    /// Everything else stays the coded refusal, with its reason.
    #[test]
    fn any_other_manifest_difference_is_refused() {
        let served_manifest = {
            let mut jar = Jar::of_bytes(SERVED).unwrap();
            String::from_utf8(jar.member_bytes(MANIFEST, 1 << 20).unwrap().unwrap()).unwrap()
        };
        let untouched = digest_line(&served_manifest, "org/example/C.class");
        let changed = digest_line(&served_manifest, CHANGED);
        let other = digest_line(&served_manifest, "org/example/A.class");
        let cases: Vec<(&str, Vec<u8>, HashMap<String, PatchFileInfo>, &str)> = vec![
            (
                "a main attribute changed",
                edited(|m| m.replace("Implementation-Version: 1.0", "Implementation-Version: 1.1")),
                record(),
                "its main attributes differ",
            ),
            (
                "an untouched member's digest changed",
                edited(|m| m.replace(&untouched, &other)),
                record(),
                "its section for `org/example/C.class`, which the patch does not touch, differs",
            ),
            (
                "a digest that is not the member's",
                edited(|m| m.replace(&changed, &other)),
                record(),
                "its SHA-256 digest of `org/example/B.class` does not match the member in the jar",
            ),
            (
                "an attribute beside the digest",
                edited(|m| m.replace(&changed, &format!("{changed}\r\nSealed: true"))),
                record(),
                "its section for `org/example/B.class` differs in more than its digest values",
            ),
            (
                "an extra section",
                rewritten(
                    SERVED,
                    |_| true,
                    |m| format!("{m}Name: org/example/Evil.class\r\n{other}\r\n\r\n"),
                    &[("org/example/Evil.class", b"evil")],
                ),
                record(),
                "it adds a section for `org/example/Evil.class`, which the patch does not add",
            ),
            (
                "a dropped section",
                edited(|m| {
                    m.replace(
                        &format!("Name: org/example/C.class\r\n{untouched}\r\n\r\n"),
                        "",
                    )
                }),
                record(),
                "it drops the section for `org/example/C.class`, which the patch does not delete",
            ),
            (
                "an unsigned jar with the edited manifest",
                rewritten(SERVED, |n| !n.starts_with("META-INF/SOCKET."), |m| m, &[]),
                record(),
                "the patched jar is not signed",
            ),
            (
                "a record that does not change the member",
                SERVED.to_vec(),
                HashMap::new(),
                "its section for `org/example/B.class`, which the patch does not touch, differs",
            ),
        ];
        for (what, served, files, why) in cases {
            let refusal = resigned_refusal(UPSTREAM, &served, &files);
            assert!(
                refusal.as_deref().is_some_and(|r| r.contains(why)),
                "{what}: {refusal:?}"
            );
            let (original, patched) = (
                Digests::of_bytes(UPSTREAM).unwrap(),
                Digests::of_bytes(&served).unwrap(),
            );
            let difference =
                difference_outside_patch((UPSTREAM, &original), (&served, &patched), &files);
            assert!(
                difference.describe().contains(MANIFEST) && difference.describe().contains(why),
                "{what}: {}",
                difference.describe()
            );
        }
    }

    /// A member the record adds may bring its section, and one it deletes
    /// may take its section along; the digests of the added one are checked.
    #[test]
    fn sections_follow_the_members_the_record_adds_and_deletes() {
        const ADDED: &str = "org/example/New.class";
        let digest = base64::engine::general_purpose::STANDARD
            .encode(<sha2::Sha256 as sha2::Digest>::digest(b"new class"));
        let add = |digest: &str| {
            let section = format!("Name: {ADDED}\r\nSHA-256-Digest: {digest}\r\n\r\n");
            rewritten(
                SERVED,
                |n| n != "org/example/A.class",
                |m| {
                    let at = m.find("Name: org/example/A.class").unwrap();
                    let end = at + m[at..].find("\r\n\r\n").unwrap() + 4;
                    format!("{}{}{section}", &m[..at], &m[end..])
                },
                &[(ADDED, b"new class")],
            )
        };
        let mut files = record();
        files.insert(
            ADDED.to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: compute_git_sha256_from_bytes(b"new class"),
            },
        );
        files.insert(
            "org/example/A.class".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"\xca\xfe\xba\xbe class A"),
                after_hash: String::new(),
            },
        );
        assert_eq!(resigned_refusal(UPSTREAM, &add(&digest), &files), None);
        let wrong = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        assert!(resigned_refusal(UPSTREAM, &add(&wrong), &files)
            .is_some_and(|why| why.contains("does not match the member in the jar")));
    }

    /// Lines wrap at 72 bytes with a leading space on the continuation, and
    /// may end in `\n` or `\r` alone: a section is its bytes, its name is
    /// the joined value.
    #[test]
    fn a_manifest_is_read_as_the_jar_specification_lays_it_out() {
        let long = format!("org/example/{}.class", "x".repeat(80));
        let (first, rest) = long.split_at(72 - "Name: ".len());
        let text = format!(
            "Manifest-Version: 1.0\nCreated-By: test\n\nName: {first}\n {rest}\nSHA-256-Digest: \
             AAAA\n\n\nName: b.class\rSHA-256-Digest: BBBB\r"
        );
        let parsed = sections(text.as_bytes()).unwrap();
        assert_eq!(parsed.main, b"Manifest-Version: 1.0\nCreated-By: test\n");
        assert_eq!(
            parsed.entries.keys().collect::<Vec<_>>(),
            [&b"b.class".to_vec(), &long.clone().into_bytes()]
        );
        let section = attributes(parsed.entries[long.as_bytes()]).unwrap();
        assert_eq!(section.len(), 2);
        assert_eq!(section[0].value, long.as_bytes());
        assert_eq!(section[1].name, b"SHA-256-Digest");
        assert_eq!(
            parsed.entries[b"b.class".as_slice()],
            b"Name: b.class\rSHA-256-Digest: BBBB\r"
        );
        for broken in [
            "Manifest-Version: 1.0\n\nSHA-256-Digest: AAAA\n",
            "Manifest-Version: 1.0\n\nName: a\n\nName: a\n",
            "Manifest-Version: 1.0\n\nName: a\nno colon here\n",
        ] {
            assert!(sections(broken.as_bytes()).is_err(), "{broken}");
        }
    }
}
