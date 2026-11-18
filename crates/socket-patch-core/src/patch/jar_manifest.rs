//! The one way a patched jar's `META-INF/MANIFEST.MF` may differ from the
//! original's: what signing the patched jar again does to it.
//!
//! A signed jar's manifest holds a section per entry with the entry's
//! digests, and its signature files vouch for the manifest. Changing a class
//! therefore breaks the signature, and a JVM that requires one (a JCE
//! provider such as Bouncy Castle's) refuses the jar. So the patch service
//! signs such a jar again, as a whole, the way `jarsigner` does: upstream's
//! signature files go, its own are added, and every file entry is listed
//! in the manifest under the signing digest. A current JDK ignores SHA-1
//! digests, so a jar whose manifest holds only those gets a SHA-256 line in
//! every section, and an entry upstream never listed gets a section of its
//! own. Signature files are already outside the "everything else is the
//! original's" comparison ([`super::jar_members::unpatched_difference`]);
//! the manifest is a member like any other, so that comparison refuses it.
//!
//! [`resigned`] accepts exactly that manifest and nothing wider.
//! The patched jar must carry a signature file, and against the original
//! manifest:
//!
//! 1. the main section is byte for byte the same;
//! 2. the section of a member the record does not touch keeps every line,
//!    byte for byte and in order; it may gain digest attributes, each of
//!    which must be the digest of that member in the patched jar (which
//!    also shows, under a second hash, that the member is unchanged);
//! 3. the section of a member the record changes may also change the
//!    values of its digest attributes; every digest in it must be the
//!    member's, and no other attribute may change;
//! 4. a section is added only for a member the record adds or changes, or
//!    for an entry both jars hold with the same bytes that the original
//!    manifest did not list; it holds a `Name` and verified digests alone;
//! 5. no section is removed.
//!
//! A record that lists the manifest itself is outside this: the manifest
//! is then a member the record changes, held to its `afterHash` like any
//! other, and a jar signed again does not carry that blob byte for byte.
//!
//! A digest attribute is one the JDK reads when it verifies a jar:
//! `SHA-256-Digest`, `SHA-384-Digest`, `SHA-512-Digest`, `SHA1-Digest`,
//! `SHA-1-Digest`, `MD5-Digest`. An added attribute of any other name is a
//! refusal.
//!
//! Sections are compared as the byte ranges the file holds, never as
//! re-serialised text. The file is read as the JAR specification lays it
//! out: lines end in `\r\n`, `\n` or `\r`, a line that starts with a space
//! continues the one before (lines wrap at 72 bytes), and a blank line ends
//! a section; blank lines themselves are not compared, so a terminator
//! added before appended sections changes nothing. A last line with no
//! terminator is one a JVM ignores, and is dropped from the original
//! before the comparison.

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::Engine as _;

use super::jar_members::{Digests, Jar, JarError};
use crate::manifest::schema::PatchFileInfo;
use crate::patch::apply::normalize_file_path;

pub(crate) const MANIFEST: &str = "META-INF/MANIFEST.MF";

/// One attribute of a section: its name, its value with continuation lines
/// joined, and the bytes it takes in the file (terminators included).
struct Attribute<'a> {
    name: &'a [u8],
    value: Vec<u8>,
    raw: &'a [u8],
}

/// One per-entry section: the bytes of its lines, and its attributes.
struct Section<'a> {
    raw: &'a [u8],
    attributes: Vec<Attribute<'a>>,
}

/// A manifest: the main section and the per-entry ones by entry name.
struct Sections<'a> {
    main: &'a [u8],
    entries: BTreeMap<Vec<u8>, Section<'a>>,
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

/// Split a manifest into its sections, each parsed once.
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
    for raw in runs {
        let attributes = attributes(raw)?;
        let name = match attributes.first() {
            Some(first) if first.name.eq_ignore_ascii_case(b"Name") => first.value.clone(),
            _ => return Err("a section does not start with `Name:`".to_string()),
        };
        let shown = String::from_utf8_lossy(&name).into_owned();
        if entries.insert(name, Section { raw, attributes }).is_some() {
            return Err(format!("it holds two sections for `{shown}`"));
        }
    }
    Ok(Sections { main, entries })
}

/// The algorithm of a digest attribute this reads, as
/// [`Jar::member_digest`] names it. The JDK reads a few more
/// (`SHA-224-Digest`, the SHA-3 ones); the patch service writes none of
/// them, and one that is added or changed is refused like any attribute
/// that is not a digest.
fn digest_algorithm(attribute: &[u8]) -> Option<&'static str> {
    [
        ("SHA-256-Digest", "SHA-256"),
        ("SHA-384-Digest", "SHA-384"),
        ("SHA-512-Digest", "SHA-512"),
        ("SHA1-Digest", "SHA-1"),
        ("SHA-1-Digest", "SHA-1"),
        ("MD5-Digest", "MD5"),
    ]
    .into_iter()
    .find(|(name, _)| attribute.eq_ignore_ascii_case(name.as_bytes()))
    .map(|(_, algorithm)| algorithm)
}

/// `manifest` without a last line that has no terminator (a JVM ignores it).
fn terminated(manifest: &[u8]) -> &[u8] {
    match manifest.iter().rposition(|b| *b == b'\n' || *b == b'\r') {
        Some(last) => &manifest[..=last],
        None => &manifest[..0],
    }
}

/// The digest attributes of `is` that must be the member's own, when `is`
/// is `was` as signing again leaves a section: every line of `was` kept in
/// order, digest attributes added, and, for a member the record `changes`,
/// digest values changed. Attribute names are matched as a manifest reads
/// them, without regard to case. `Err` says what else differs.
fn follows<'s, 'a>(
    was: &[Attribute<'a>],
    is: &'s [Attribute<'a>],
    changes: bool,
) -> Result<Vec<&'s Attribute<'a>>, String> {
    let mut kept = 0;
    let mut verify = Vec::new();
    for attribute in is {
        let digest = digest_algorithm(attribute.name).is_some();
        match was.get(kept) {
            Some(old) if old.raw == attribute.raw => {
                kept += 1;
                if changes && digest {
                    verify.push(attribute);
                }
            }
            Some(old) if changes && digest && old.name.eq_ignore_ascii_case(attribute.name) => {
                kept += 1;
                verify.push(attribute);
            }
            _ if digest => verify.push(attribute),
            _ => {
                return Err(format!(
                    "adds or changes `{}`, which is not a digest",
                    String::from_utf8_lossy(attribute.name)
                ))
            }
        }
    }
    match was.get(kept) {
        Some(old) => Err(format!(
            "changes or drops its `{}` line",
            String::from_utf8_lossy(old.name)
        )),
        None => Ok(verify),
    }
}

/// What a patched jar's manifest is to the original's.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Resigned {
    /// The patched jar carries no signature file: its manifest is a member
    /// like any other, and a difference in it an ordinary one.
    Unsigned,
    /// The manifest is the original's as signing the jar again leaves it.
    Accepted,
    /// It is not: why.
    Refused(String),
}

/// Why the comparison stopped: a jar past a limit, or a difference.
enum Stop {
    Limit(JarError),
    Why(String),
}

impl From<String> for Stop {
    fn from(why: String) -> Self {
        Stop::Why(why)
    }
}

/// A read that failed: a limit stays a limit, anything else is `why`.
fn stop(e: JarError, why: impl FnOnce(&JarError) -> String) -> Stop {
    match e.is_too_large() {
        true => Stop::Limit(e),
        false => Stop::Why(why(&e)),
    }
}

/// Each of `digests` is the digest of `member` in `jar`. Its SHA-256 is
/// the one the comparison already has (`known`); only another algorithm
/// inflates the member again.
fn digests_hold<R: std::io::Read + std::io::Seek>(
    jar: &mut Jar<R>,
    known: &Digests,
    member: &str,
    digests: &[&Attribute<'_>],
) -> Result<(), Stop> {
    for attribute in digests {
        let algorithm = digest_algorithm(attribute.name).expect("a digest attribute");
        let actual = match algorithm {
            "SHA-256" => known.get(member).map(|digest| digest.to_vec()),
            _ => jar
                .member_digest(member, algorithm)
                .map_err(|e| stop(e, |e| format!("`{member}` could not be hashed ({e})")))?,
        };
        let actual = actual.ok_or_else(|| {
            format!("it has a section for `{member}`, which the jar does not hold")
        })?;
        let declared = base64::engine::general_purpose::STANDARD
            .decode(&attribute.value)
            .ok();
        if declared.as_deref() != Some(actual.as_slice()) {
            return Err(Stop::Why(format!(
                "its {algorithm} digest of `{member}` does not match the member in the jar"
            )));
        }
    }
    Ok(())
}

/// Whether `patched`'s manifest is the original's as signing the patched
/// jar again leaves it, for the record `files` (see the module docs). Each
/// jar comes with its members' content digests. `Err` is a jar past a
/// limit: that is the caller's too-large refusal, never a difference.
pub(crate) fn resigned(
    original: (&[u8], &Digests),
    patched: (&[u8], &Digests),
    files: &HashMap<String, PatchFileInfo>,
) -> Result<Resigned, JarError> {
    let mut jar = Jar::of_bytes(patched.0)?;
    if !jar.has_signature_file() {
        return Ok(Resigned::Unsigned);
    }
    match compare(original, patched.1, &mut jar, files) {
        Ok(()) => Ok(Resigned::Accepted),
        Err(Stop::Why(why)) => Ok(Resigned::Refused(why)),
        Err(Stop::Limit(e)) => Err(e),
    }
}

fn compare<R: std::io::Read + std::io::Seek>(
    original: (&[u8], &Digests),
    members: &Digests,
    jar: &mut Jar<R>,
    files: &HashMap<String, PatchFileInfo>,
) -> Result<(), Stop> {
    let before = Jar::of_bytes(original.0)
        .and_then(|mut jar| jar.member_bytes(MANIFEST))
        .map_err(|e| stop(e, |e| format!("the original manifest cannot be read ({e})")))?
        .ok_or_else(|| "the original jar has no manifest".to_string())?;
    let after = jar
        .member_bytes(MANIFEST)
        .map_err(|e| stop(e, |e| format!("the patched manifest cannot be read ({e})")))?
        .ok_or_else(|| "the patched jar has no manifest".to_string())?;
    let old =
        sections(terminated(&before)).map_err(|why| format!("the original manifest: {why}"))?;
    let new = sections(&after).map_err(|why| format!("the patched manifest: {why}"))?;
    if old.main != new.main {
        return Err(Stop::Why("its main attributes differ".to_string()));
    }
    let touched: HashSet<&[u8]> = files
        .keys()
        .map(|key| normalize_file_path(key).as_bytes())
        .collect();
    let names: std::collections::BTreeSet<&Vec<u8>> =
        old.entries.keys().chain(new.entries.keys()).collect();
    for name in names {
        let member = String::from_utf8_lossy(name);
        // The record adds the member or changes its bytes.
        let changes = touched.contains(name.as_slice());
        match (old.entries.get(name), new.entries.get(name)) {
            (Some(_), None) => {
                return Err(Stop::Why(format!("it drops the section for `{member}`")))
            }
            (None, Some(is)) => {
                let unchanged = matches!(
                    (original.1.get(name), members.get(name)),
                    (Some(was), Some(is)) if was == is
                );
                if !changes && !unchanged {
                    return Err(Stop::Why(format!(
                        "it adds a section for `{member}`, which is neither a member the patch \
                         adds or changes nor an unchanged entry of the original jar"
                    )));
                }
                let digests: Vec<&Attribute<'_>> = is.attributes.iter().skip(1).collect();
                if digests.is_empty() || digests.iter().any(|a| digest_algorithm(a.name).is_none())
                {
                    return Err(Stop::Why(format!(
                        "its section for `{member}` is new and holds other than digests"
                    )));
                }
                digests_hold(jar, members, &member, &digests)?;
            }
            (Some(was), Some(is)) if was.raw == is.raw && !changes => {}
            (Some(was), Some(is)) => {
                let digests = follows(&was.attributes, &is.attributes, changes).map_err(|why| {
                    format!(
                        "its section for `{member}` {why}{}",
                        match changes {
                            true => "",
                            false => ", though the patch does not touch the member",
                        }
                    )
                })?;
                digests_hold(jar, members, &member, &digests)?;
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
    use crate::patch::jar_members::difference_outside_patch;

    /// What the patch service's signer made of five upstream jars (the
    /// patch changes `fixture/Plain.class` in each): `(upstream, served)`.
    macro_rules! service {
        ($name:literal) => {
            (
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/data/resigned-provider/service/",
                    $name,
                    ".upstream.jar"
                ))
                .as_slice(),
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/data/resigned-provider/service/",
                    $name,
                    ".jar"
                ))
                .as_slice(),
            )
        };
    }
    const PLAIN: &str = "fixture/Plain.class";
    const UNTOUCHED: &str = "fixture/Unicode.class";

    /// The record of a pair: `changed` members by their hashes in the two
    /// jars, `added` ones with no `beforeHash`.
    fn record_of(
        upstream: &[u8],
        served: &[u8],
        changed: &[&str],
        added: &[&str],
    ) -> HashMap<String, PatchFileInfo> {
        let hash = |jar: &[u8], member: &str| {
            let mut jar = Jar::of_bytes(jar).unwrap();
            jar.member_git_sha256(member).unwrap().unwrap()
        };
        let changed = changed.iter().map(|member| {
            let (before_hash, after_hash) = (hash(upstream, member), hash(served, member));
            (
                member.to_string(),
                PatchFileInfo {
                    before_hash,
                    after_hash,
                },
            )
        });
        let added = added.iter().map(|member| {
            let (before_hash, after_hash) = (String::new(), hash(served, member));
            (
                member.to_string(),
                PatchFileInfo {
                    before_hash,
                    after_hash,
                },
            )
        });
        changed.chain(added).collect()
    }

    fn manifest_of(jar: &[u8]) -> String {
        let mut jar = Jar::of_bytes(jar).unwrap();
        String::from_utf8(jar.member_bytes(MANIFEST).unwrap().unwrap()).unwrap()
    }

    fn refusal(
        upstream: &[u8],
        served: &[u8],
        files: &HashMap<String, PatchFileInfo>,
    ) -> Option<String> {
        let (was, is) = (
            Digests::of_bytes(upstream).unwrap(),
            Digests::of_bytes(served).unwrap(),
        );
        let verdict = resigned((upstream, &was), (served, &is), files).unwrap();
        // The comparison the swap and vendoring make agrees.
        let difference = difference_outside_patch((upstream, &was), (served, &is), files).unwrap();
        match verdict {
            Resigned::Accepted => {
                assert!(difference.is_empty(), "{}", difference.describe());
                None
            }
            Resigned::Refused(why) => {
                assert_eq!(difference.manifest.as_deref(), Some(why.as_str()));
                assert!(difference.changed.contains(&MANIFEST.to_string()));
                Some(why)
            }
            Resigned::Unsigned => {
                assert_eq!(difference.manifest, None);
                assert!(difference.changed.contains(&MANIFEST.to_string()));
                Some("the patched jar is not signed".to_string())
            }
        }
    }

    /// The line `attribute: …` of `member`'s section in `manifest`.
    fn line(manifest: &str, member: &str, attribute: &str) -> String {
        let at = manifest.find(&format!("Name: {member}\r\n")).unwrap();
        let section = &manifest[at..at + manifest[at..].find("\r\n\r\n").unwrap()];
        let line = section.lines().find(|l| l.starts_with(attribute));
        line.unwrap().to_string()
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

    /// What the service's signer produces is accepted, in each shape it
    /// takes: one digest value changed; a SHA-256 line inserted in every
    /// section of a SHA-1-only manifest; sections appended for entries the
    /// original never listed (the changed one among them); an unterminated
    /// last line dropped and a section appended for an added member.
    #[test]
    fn the_services_resigned_jars_are_accepted() {
        assert_eq!(refusal(UPSTREAM, SERVED, &record()), None);
        for ((upstream, served), added) in [
            (service!("sha256"), &[][..]),
            (service!("sha1-only"), &[]),
            (service!("unlisted"), &[]),
            (service!("unterminated-line"), &["com/fresh/Added.class"]),
        ] {
            let files = record_of(upstream, served, &[PLAIN], added);
            assert_eq!(refusal(upstream, served, &files), None);
        }
        // The shapes are the ones named above.
        let (upstream, served) = service!("sha1-only");
        assert!(!manifest_of(upstream).contains("SHA-256-Digest"));
        assert_eq!(manifest_of(served).matches("SHA-256-Digest").count(), 4);
        let (upstream, served) = service!("unlisted");
        assert!(!manifest_of(upstream).contains(UNTOUCHED));
        assert!(manifest_of(served).ends_with(&format!(
            "Name: {UNTOUCHED}\r\n{}\r\n\r\n",
            line(&manifest_of(served), UNTOUCHED, "SHA-256-Digest")
        )));
        let (upstream, _) = service!("unterminated-line");
        assert!(manifest_of(upstream).ends_with("X-Junk: no newline"));
        // Line endings are the file's own: `\n` on both sides is accepted.
        let unix = |jar: &[u8]| rewritten(jar, |_| true, |m| m.replace("\r\n", "\n"), &[]);
        assert_eq!(refusal(&unix(UPSTREAM), &unix(SERVED), &record()), None);
    }

    /// A record that lists the manifest itself is outside the rule: the
    /// manifest is then a member the record changes, held to its
    /// `afterHash`, and the served manifest (the record's blob with its
    /// digests completed) is not that blob. The swap and vendoring refuse
    /// such a jar at that check.
    #[test]
    fn a_record_that_lists_the_manifest_is_not_accepted_yet() {
        let (upstream, served) = service!("manifest-in-record");
        let blob = manifest_of(upstream).replacen("\r\n", "\r\nX-Patched: yes\r\n", 1);
        let mut files = record_of(upstream, served, &[PLAIN], &[]);
        files.insert(
            MANIFEST.to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(manifest_of(upstream).as_bytes()),
                after_hash: compute_git_sha256_from_bytes(blob.as_bytes()),
            },
        );
        assert_ne!(manifest_of(served), blob);
        assert!(!crate::vendor::common::zip_bytes_match_after_hashes(
            served, &files
        ));
    }

    /// A member is found by the raw bytes of its name, in the manifest rule
    /// as in the reader: a UTF-8 name written without the UTF-8 flag, which
    /// the zip reader decodes as something else, still has its digest.
    #[test]
    fn a_member_with_a_non_ascii_name_and_no_utf8_flag_is_verified() {
        use crate::patch::jar_members::testing::without_utf8_flag;
        const NAME: &str = "fixture/\u{dc}n\u{ef}code.class";
        let (upstream, served) = service!("sha256");
        let sha1 = base64::engine::general_purpose::STANDARD
            .encode(<sha1::Sha1 as sha1::Digest>::digest(b"unicode"));
        let extra: &[(&str, &[u8])] = &[(NAME, b"unicode")];
        let upstream = without_utf8_flag(rewritten(upstream, |_| true, |m| m, extra));
        let served = without_utf8_flag(rewritten(
            served,
            |_| true,
            |m| format!("{m}Name: {NAME}\r\nSHA1-Digest: {sha1}\r\n\r\n"),
            extra,
        ));
        let files = record_of(&upstream, &served, &[PLAIN], &[]);
        assert_eq!(refusal(&upstream, &served, &files), None);
    }

    /// A manifest larger than any cap of its own is read within the jar
    /// limits and accepted; a jar past a limit is the caller's too-large
    /// refusal, never a difference.
    #[test]
    fn a_large_manifest_is_read_and_a_limit_is_a_limit() {
        let (upstream, served) = service!("sha256");
        let pad = format!(
            "Manifest-Version: 1.0\r\nX-Pad: {}",
            "a".repeat(17 * 1024 * 1024)
        );
        let padded = |jar: &[u8]| {
            rewritten(
                jar,
                |_| true,
                |m| m.replacen("Manifest-Version: 1.0", &pad, 1),
                &[],
            )
        };
        let (big_upstream, big_served) = (padded(upstream), padded(served));
        let files = record_of(upstream, served, &[PLAIN], &[]);
        assert_eq!(refusal(&big_upstream, &big_served, &files), None);

        // A signed jar whose manifest inflates past what its size allows.
        use std::io::Read as _;
        let mut bomb = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        bomb.start_file(MANIFEST, opts).unwrap();
        std::io::copy(&mut std::io::repeat(0).take(65 * 1024 * 1024), &mut bomb).unwrap();
        bomb.start_file("META-INF/SOCKET.SF", opts).unwrap();
        let bomb = bomb.finish().unwrap().into_inner();
        let (was, is) = (
            Digests::of_bytes(upstream).unwrap(),
            Digests::of_bytes(served).unwrap(),
        );
        let limit = resigned((upstream, &was), (&bomb, &is), &files).unwrap_err();
        assert!(limit.is_too_large(), "{limit:?}");
        let limit = difference_outside_patch((upstream, &was), (&bomb, &is), &files).unwrap_err();
        assert!(limit.is_too_large(), "{limit:?}");
    }

    /// A member's SHA-256 is the one the comparison already holds, so a
    /// section that lists it beside another digest inflates the member once
    /// more, not twice: 40 MiB under SHA-1 fits what this jar may inflate,
    /// 80 MiB would not.
    #[test]
    fn a_sha256_digest_is_checked_without_inflating_the_member_again() {
        use std::io::Write as _;
        const BIG: &str = "big.bin";
        let zeros = vec![0u8; 40 * 1024 * 1024];
        let b64 = |digest: &[u8]| base64::engine::general_purpose::STANDARD.encode(digest);
        let sha1 = |bytes: &[u8]| b64(&<sha1::Sha1 as sha1::Digest>::digest(bytes));
        let sha256 = |bytes: &[u8]| b64(&<sha2::Sha256 as sha2::Digest>::digest(bytes));
        let jar = |manifest: String, big: &[u8], signature: &str| {
            let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let opts = zip::write::SimpleFileOptions::default();
            for (name, bytes) in [
                (MANIFEST, manifest.as_bytes()),
                (BIG, big),
                (signature, b"signature"),
            ] {
                out.start_file(name, opts).unwrap();
                out.write_all(bytes).unwrap();
            }
            out.finish().unwrap().into_inner()
        };
        let head = format!("Manifest-Version: 1.0\r\n\r\nName: {BIG}\r\n");
        let upstream = jar(
            format!("{head}SHA1-Digest: {}\r\n\r\n", sha1(b"before")),
            b"before",
            "META-INF/UPSTREAM.SF",
        );
        let served = jar(
            format!(
                "{head}SHA1-Digest: {}\r\nSHA-256-Digest: {}\r\n\r\n",
                sha1(&zeros),
                sha256(&zeros)
            ),
            &zeros,
            "META-INF/SOCKET.SF",
        );
        let files = record_of(&upstream, &served, &[BIG], &[]);
        assert_eq!(refusal(&upstream, &served, &files), None);
    }

    /// Attribute names are matched as a manifest reads them, without regard
    /// to case: upstream's `SHA-256-digest` is the line the service writes
    /// back as `SHA-256-Digest`.
    #[test]
    fn a_digest_attribute_is_matched_whatever_its_case() {
        let (upstream, served) = service!("sha256");
        let lower = rewritten(
            upstream,
            |_| true,
            |m| m.replacen("SHA-256-Digest: ", "SHA-256-digest: ", 1),
            &[],
        );
        assert!(manifest_of(&lower).contains(&format!("Name: {PLAIN}\r\nSHA-256-digest: ")));
        let files = record_of(upstream, served, &[PLAIN], &[]);
        assert_eq!(refusal(&lower, served, &files), None);
    }

    /// Re-signing is named only for a signed jar. An unsigned jar whose
    /// manifest differs is the ordinary wrong-base case, and reads as one.
    #[test]
    fn signing_is_named_only_for_a_signed_jar() {
        let created = |m: String| m.replace("Created-By: ", "Built-By: ");
        let describe = |served: &[u8]| {
            let (was, is) = (
                Digests::of_bytes(UPSTREAM).unwrap(),
                Digests::of_bytes(served).unwrap(),
            );
            difference_outside_patch((UPSTREAM, &was), (served, &is), &record())
                .unwrap()
                .describe()
        };
        let unsigned = rewritten(SERVED, |n| !n.starts_with("META-INF/SOCKET."), created, &[]);
        assert_eq!(describe(&unsigned), "1 changed (`META-INF/MANIFEST.MF`)");
        assert_eq!(
            describe(&edited(created)),
            "1 changed (`META-INF/MANIFEST.MF`), the manifest is not the original's as signing \
             the jar again leaves it: its main attributes differ"
        );
    }

    /// Everything else stays the coded refusal, with its reason.
    #[test]
    fn any_other_manifest_difference_is_refused() {
        let (upstream, served) = service!("sha1-only");
        let files = record_of(upstream, served, &[PLAIN], &[]);
        let manifest = manifest_of(served);
        let inserted = line(&manifest, UNTOUCHED, "SHA-256-Digest");
        let existing = line(&manifest, UNTOUCHED, "SHA1-Digest");
        let of_plain = line(&manifest, PLAIN, "SHA-256-Digest");
        let plain_sha1 = line(&manifest, PLAIN, "SHA1-Digest");
        let edit = |change: &dyn Fn(String) -> String| rewritten(served, |_| true, change, &[]);
        let evil = base64::engine::general_purpose::STANDARD
            .encode(<sha2::Sha256 as sha2::Digest>::digest(b"evil"));
        let cases: Vec<(&str, Vec<u8>, HashMap<String, PatchFileInfo>, &str)> = vec![
            (
                "an inserted digest that is not the member's",
                edit(&|m| m.replace(&inserted, &of_plain)),
                files.clone(),
                "its SHA-256 digest of `fixture/Unicode.class` does not match the member in the jar",
            ),
            (
                "an inserted attribute that is not a digest",
                edit(&|m| m.replace(&inserted, &format!("{inserted}\r\nSealed: true"))),
                files.clone(),
                "its section for `fixture/Unicode.class` adds or changes `Sealed`, which is not a \
                 digest, though the patch does not touch the member",
            ),
            (
                "an inserted digest the JDK does not read",
                edit(&|m| m.replace(&inserted, &format!("{inserted}\r\nSHA-224-Digest: AAAA"))),
                files.clone(),
                "adds or changes `SHA-224-Digest`, which is not a digest",
            ),
            (
                "a section for an entry the installed jar does not hold",
                rewritten(
                    served,
                    |_| true,
                    |m| format!("{m}Name: fixture/Evil.class\r\nSHA-256-Digest: {evil}\r\n\r\n"),
                    &[("fixture/Evil.class", b"evil")],
                ),
                files.clone(),
                "it adds a section for `fixture/Evil.class`, which is neither a member the patch \
                 adds or changes nor an unchanged entry of the original jar",
            ),
            (
                "an existing line of an untouched section changed",
                edit(&|m| m.replace(&existing, &plain_sha1)),
                files.clone(),
                "its section for `fixture/Unicode.class` changes or drops its `SHA1-Digest` line, \
                 though the patch does not touch the member",
            ),
            (
                "an attribute of the changed member that is not a digest",
                edit(&|m| m.replace(&of_plain, &format!("{of_plain}\r\nSealed: true"))),
                files.clone(),
                "its section for `fixture/Plain.class` adds or changes `Sealed`, which is not a digest",
            ),
            (
                "a stale digest of the changed member",
                edit(&|m| m.replace(&plain_sha1, &existing)),
                files.clone(),
                "its SHA-1 digest of `fixture/Plain.class` does not match the member in the jar",
            ),
            (
                "a main attribute changed",
                edit(&|m| m.replace("Manifest-Version: 1.0", "Manifest-Version: 1.0\r\nSealed: true")),
                files.clone(),
                "its main attributes differ",
            ),
            (
                "a dropped section",
                edit(&|m| m.replace(&format!("Name: {UNTOUCHED}\r\n{existing}\r\n{inserted}\r\n\r\n"), "")),
                files.clone(),
                "it drops the section for `fixture/Unicode.class`",
            ),
            (
                "an unsigned jar with the edited manifest",
                rewritten(served, |n| !n.starts_with("META-INF/SOCKET."), |m| m, &[]),
                files.clone(),
                "the patched jar is not signed",
            ),
            (
                "a record that does not change the member",
                served.to_vec(),
                HashMap::new(),
                "its section for `fixture/Plain.class` changes or drops its `SHA1-Digest` line, \
                 though the patch does not touch the member",
            ),
        ];
        for (what, served, files, why) in cases {
            let refusal = refusal(upstream, &served, &files);
            assert!(
                refusal.as_deref().is_some_and(|r| r.contains(why)),
                "{what}: {refusal:?}"
            );
        }
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
        let section = &parsed.entries[long.as_bytes()].attributes;
        assert_eq!(section.len(), 2);
        assert_eq!(section[0].value, long.as_bytes());
        assert_eq!(section[1].name, b"SHA-256-Digest");
        assert_eq!(
            parsed.entries[b"b.class".as_slice()].raw,
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
