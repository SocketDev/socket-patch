//! The same-GAV Coursier tree scala-cli resolves from.
//!
//! `.socket/vendor/coursier/<g/path>/<a>/<v>/` holds the patched
//! `<a>-<v>.jar`, the upstream `<a>-<v>.pom`, their `.sha1` files (Coursier
//! checks them on a `file:` repository: a wrong one fails the build) and a
//! `socket-patch.vendor.json` marker; [`INDEX_REL`] lists the jar and pom of
//! every patch with its sha256 (`g:a:v\trel\tsha256\tuuid`, sorted, under
//! [`INDEX_HEADER`]). The tree root's own `.gitignore` (`!*`, so a user's
//! `*.jar` rule cannot drop the jar from a fresh clone) and `.gitattributes`
//! (`* -text`) keep it intact through git.
//!
//! The tree keeps the upstream version: scala-cli has no override
//! directive, so the copy wins only by being found first (its repository
//! is listed before the defaults). The index is the liveness proof: a patch
//! is in the tree while the index lists its uuid.

use std::collections::BTreeSet;

use serde_json::json;

use super::{
    adopt, fragment, owned_file_with, safe_coordinates, sha1_hex, sha256_hex, Coords, FileWrite,
    JvmPatch, JvmRefusal, ReadFn, WiringAction, WiringRecord, COURSIER_INDEX_KIND,
};

/// The tree root.
pub const TREE_ROOT: &str = ".socket/vendor/coursier";
/// The index of every tree file.
pub const INDEX_REL: &str = ".socket/vendor/coursier-index.tsv";
/// The index's first line.
pub const INDEX_HEADER: &str = "#socket-patch-coursier-index 1";
/// The tree root's owned `.gitignore` and `.gitattributes`.
pub const GITIGNORE_REL: &str = ".socket/vendor/coursier/.gitignore";
pub const GITATTRIBUTES_REL: &str = ".socket/vendor/coursier/.gitattributes";
/// The `.gitignore` body: re-include everything below.
pub const GITIGNORE: &str = "!*\n";
/// The per-version marker (the name every JVM tree uses).
pub const MARKER_NAME: &str = "socket-patch.vendor.json";
/// Files under `.socket/` a group commit captures for this tree (plus the
/// vendored sbt tree's `.gitignore`).
pub const CAPTURED_FILES: &[&str] = &[
    INDEX_REL,
    GITIGNORE_REL,
    GITATTRIBUTES_REL,
    super::scala_cli::GUARD_REL,
    super::sbt::TREE_GITIGNORE_REL,
];

/// Paths whose presence without a vendor ledger means JVM artifacts were
/// orphaned (`vendor --check`'s `vendor_ledger_missing`).
pub const ORPHAN_PATHS: &[&str] = &[TREE_ROOT, INDEX_REL];

/// The patch's tree directory (same GAV).
pub fn tree_dir(c: &Coords<'_>) -> String {
    format!(
        "{TREE_ROOT}/{}/{}/{}",
        c.group_path(),
        c.artifact_id,
        c.version
    )
}

/// The committed tree of `c` as `(jar, pom, None)`. `None` when either is
/// missing.
pub fn committed(read: ReadFn<'_>, c: &Coords<'_>) -> Option<super::CommittedTree> {
    let dir = tree_dir(c);
    let (a, v) = (c.artifact_id, c.version);
    Some((
        read(&format!("{dir}/{a}-{v}.jar"))?,
        read(&format!("{dir}/{a}-{v}.pom"))?,
        None,
    ))
}

/// Plan the patch's tree files and index rows into `writes`; the records
/// (the index, the tree root's `.gitignore` and `.gitattributes`).
///
/// Refuses `vendor_coursier_tree_conflict` when the patch's version
/// directory already holds another patch's marker the index does not list
/// (an orphaned or hand-copied tree: replacing it would silently swap the
/// bytes a build already resolves), and a malformed index.
pub fn plan_tree(
    read: ReadFn<'_>,
    patch: &JvmPatch<'_>,
    writes: &mut Vec<FileWrite>,
) -> Result<Vec<WiringRecord>, JvmRefusal> {
    let c = patch.coords();
    let (g, a, v) = (patch.group_id, patch.artifact_id, patch.version);
    if !safe_coordinates(g, a, v) {
        return Err(JvmRefusal {
            code: "unsafe_coordinates",
            detail: format!("unsafe maven coordinates `{g}:{a}:{v}`"),
        });
    }
    let gav = format!("{g}:{a}:{v}");
    let existing_index = read(INDEX_REL);
    let rows = match existing_index.as_deref() {
        Some(bytes) => parse_index(bytes).map_err(index_refusal)?,
        None => Vec::new(),
    };
    let dir = tree_dir(&c);
    if let Some(marker) = read(&format!("{dir}/{MARKER_NAME}")) {
        let other = serde_json::from_slice::<serde_json::Value>(&marker)
            .ok()
            .and_then(|m| m.get("uuid")?.as_str().map(str::to_string));
        let indexed = |uuid: &str| rows.iter().any(|r| r.gav == gav && r.uuid == uuid);
        match other {
            Some(u) if u == patch.uuid || indexed(&u) => {}
            other => {
                return Err(JvmRefusal {
                    code: "vendor_coursier_tree_conflict",
                    detail: format!(
                        "{dir} already holds {} that {INDEX_REL} does not list; remove the \
                         directory (or restore the index from git) and re-run",
                        other.map_or("an unreadable marker".to_string(), |u| format!("patch {u}"))
                    ),
                });
            }
        }
    }

    let jar_name = format!("{a}-{v}.jar");
    let pom_name = format!("{a}-{v}.pom");
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, bytes) in [(&jar_name, patch.jar), (&pom_name, patch.upstream_pom)] {
        files.push((name.clone(), bytes.to_vec()));
        files.push((format!("{name}.sha1"), sha1_hex(bytes).into_bytes()));
    }
    files.sort();
    let mut new_rows: Vec<IndexRow> = Vec::new();
    for (name, bytes) in &files {
        writes.push(FileWrite {
            rel: format!("{dir}/{name}"),
            bytes: bytes.clone(),
            tree: true,
        });
        if !name.ends_with(".sha1") {
            new_rows.push(IndexRow {
                gav: gav.clone(),
                rel: format!("{}/{a}/{v}/{name}", c.group_path()),
                sha256: sha256_hex(bytes),
                uuid: patch.uuid.to_string(),
            });
        }
    }
    writes.push(FileWrite {
        rel: format!("{dir}/{MARKER_NAME}"),
        bytes: marker_json(patch, &files).into_bytes(),
        tree: true,
    });
    let mut all: Vec<IndexRow> = rows.into_iter().filter(|r| r.gav != gav).collect();
    all.extend(new_rows);
    // The index sits outside the tree's `* -text` rule: a CRLF checkout
    // (core.autocrlf) keeps its line endings, never re-rendered as drift.
    let crlf = existing_index
        .as_deref()
        .is_some_and(|b| b.windows(2).any(|w| w == b"\r\n"));
    writes.push(FileWrite {
        rel: INDEX_REL.to_string(),
        bytes: render_index_like(&all, crlf).into_bytes(),
        tree: false,
    });
    Ok(vec![
        if existing_index.is_some() {
            adopt(INDEX_REL, COURSIER_INDEX_KIND, "index")
        } else {
            fragment(
                INDEX_REL,
                COURSIER_INDEX_KIND,
                "index",
                WiringAction::Added,
                None,
                json!({ "op": "create" }),
            )
        },
        owned_file_with(read, GITIGNORE_REL, GITIGNORE.as_bytes(), writes),
        owned_file_with(
            read,
            GITATTRIBUTES_REL,
            super::TREE_GITATTRIBUTES.as_bytes(),
            writes,
        ),
    ])
}

/// One index row.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexRow {
    pub gav: String,
    /// Relative to [`TREE_ROOT`].
    pub rel: String,
    pub sha256: String,
    pub uuid: String,
}

/// The rows of an index; `Err` (why) when it is not one this module wrote.
pub fn parse_index(bytes: &[u8]) -> Result<Vec<IndexRow>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not UTF-8".to_string())?;
    let mut lines = text.lines().map(|l| l.strip_suffix('\r').unwrap_or(l));
    if lines.next() != Some(INDEX_HEADER) {
        return Err("unknown header".to_string());
    }
    let mut rows = Vec::new();
    for (n, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        rows.push(parse_row(line).ok_or_else(|| format!("malformed row {}", n + 2))?);
    }
    Ok(rows)
}

fn parse_row(line: &str) -> Option<IndexRow> {
    let cols: Vec<&str> = line.split('\t').collect();
    let [gav, rel, sha, uuid] = cols.as_slice() else {
        return None;
    };
    let parts: Vec<&str> = gav.split(':').collect();
    let [g, a, v] = parts.as_slice() else {
        return None;
    };
    let dir = format!("{}/{a}/{v}/", g.replace('.', "/"));
    let ok = safe_coordinates(g, a, v)
        && rel
            .strip_prefix(&dir)
            .is_some_and(|n| n.starts_with(&format!("{a}-{v}")) && !n.contains('/'))
        && sha.len() == 64
        && sha
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        && crate::patch::path_safety::is_canonical_uuid(uuid);
    ok.then(|| IndexRow {
        gav: gav.to_string(),
        rel: rel.to_string(),
        sha256: sha.to_string(),
        uuid: uuid.to_string(),
    })
}

/// The index holding `rows` (sorted, de-duplicated).
pub fn render_index(rows: &[IndexRow]) -> String {
    let sorted: BTreeSet<&IndexRow> = rows.iter().collect();
    let mut out = format!("{INDEX_HEADER}\n");
    for r in sorted {
        out.push_str(&format!("{}\t{}\t{}\t{}\n", r.gav, r.rel, r.sha256, r.uuid));
    }
    out
}

/// [`render_index`] with `\r\n` line endings when `crlf` (the existing
/// index's, kept on re-render).
pub fn render_index_like(rows: &[IndexRow], crlf: bool) -> String {
    let lf = render_index(rows);
    if crlf {
        lf.replace('\n', "\r\n")
    } else {
        lf
    }
}

/// Whether the index lists `c` (its GAV under its uuid). `Ok(false)` when
/// there is no index; `Err` when it is malformed.
pub fn indexed(read: ReadFn<'_>, c: &Coords<'_>) -> Result<bool, JvmRefusal> {
    let Some(bytes) = read(INDEX_REL) else {
        return Ok(false);
    };
    let gav = format!("{}:{}:{}", c.group_id, c.artifact_id, c.version);
    let rows = parse_index(&bytes).map_err(index_refusal)?;
    Ok(rows.iter().any(|r| r.gav == gav && r.uuid == c.uuid))
}

fn index_refusal(why: String) -> JvmRefusal {
    JvmRefusal {
        code: "vendor_jvm_shape_unsupported",
        detail: format!(
            "reason: coursier_index_unreadable: {INDEX_REL}: {why}; restore it from git"
        ),
    }
}

/// The marker: sorted keys, 2-space indent, trailing newline.
fn marker_json(patch: &JvmPatch<'_>, files: &[(String, Vec<u8>)]) -> String {
    let s = |v: &str| serde_json::to_string(v).unwrap_or_else(|_| "\"\"".to_string());
    let mut out = String::from("{\n  \"files\": {");
    for (n, (name, bytes)) in files.iter().enumerate() {
        out.push_str(if n == 0 { "\n" } else { ",\n" });
        out.push_str(&format!(
            "    {}: {{\n      \"sha256\": \"{}\",\n      \"size\": {}\n    }}",
            s(name),
            sha256_hex(bytes),
            bytes.len()
        ));
    }
    let purl = format!(
        "pkg:maven/{}/{}@{}",
        patch.group_id, patch.artifact_id, patch.version
    );
    out.push_str(&format!(
        "\n  }},\n  \"purl\": {},\n  \"schema\": 1,\n  \"tool\": \"coursier\",\n  \"uuid\": {},\n  \"version\": {}\n}}\n",
        s(&purl),
        s(patch.uuid),
        s(patch.version)
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const UUID: &str = "abcdef12-3456-4789-8abc-def012345678";
    const OTHER: &str = "12345678-3456-4789-8abc-def012345678";

    fn patch(uuid: &'static str) -> JvmPatch<'static> {
        JvmPatch {
            group_id: "com.typesafe",
            artifact_id: "config",
            version: "1.4.3",
            uuid,
            jar: b"PATCHED JAR",
            upstream_pom: b"<project/>\n",
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        }
    }

    fn reader(files: BTreeMap<String, Vec<u8>>) -> impl Fn(&str) -> Option<Vec<u8>> {
        move |p: &str| files.get(p).cloned()
    }

    fn apply(files: &mut BTreeMap<String, Vec<u8>>, writes: &[FileWrite]) {
        for w in writes {
            files.insert(w.rel.clone(), w.bytes.clone());
        }
    }

    #[test]
    fn tree_dir_is_same_gav() {
        let c = Coords {
            group_id: "org.apache.commons",
            artifact_id: "commons-lang3",
            version: "3.11",
            uuid: "abcdef12-3456-4789-8abc-def012345678",
        };
        assert_eq!(
            tree_dir(&c),
            ".socket/vendor/coursier/org/apache/commons/commons-lang3/3.11"
        );
    }

    #[test]
    fn owned_file_with_creates_once_then_adopts() {
        let mut writes = Vec::new();
        let none = |_: &str| None;
        let rec = owned_file_with(&none, GITIGNORE_REL, GITIGNORE.as_bytes(), &mut writes);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].bytes, b"!*\n");
        assert_eq!(super::super::op_of(&rec), "create");
        let present = |p: &str| (p == GITIGNORE_REL).then(Vec::new);
        let rec = owned_file_with(&present, GITIGNORE_REL, b"x", &mut writes);
        assert_eq!(writes.len(), 1);
        assert_eq!(super::super::op_of(&rec), "adopt");
    }

    /// The index lies outside the tree's `* -text` rule, so a
    /// `core.autocrlf` checkout gives it CRLF: a re-plan keeps that, so the
    /// in-sync index is no write (no `--check` drift, no churn).
    #[test]
    fn a_crlf_index_is_re_rendered_crlf() {
        let mut writes = Vec::new();
        plan_tree(&|_: &str| None, &patch(UUID), &mut writes).unwrap();
        let lf = writes
            .iter()
            .find(|w| w.rel == INDEX_REL)
            .unwrap()
            .bytes
            .clone();
        let crlf = String::from_utf8(lf).unwrap().replace('\n', "\r\n");
        let files: BTreeMap<String, Vec<u8>> = writes
            .iter()
            .map(|w| (w.rel.clone(), w.bytes.clone()))
            .chain([(INDEX_REL.to_string(), crlf.clone().into_bytes())])
            .collect();
        let read = reader(files);
        let mut again = Vec::new();
        plan_tree(&read, &patch(UUID), &mut again).unwrap();
        let index = &again.iter().find(|w| w.rel == INDEX_REL).unwrap().bytes;
        assert_eq!(index, crlf.as_bytes());
        assert_eq!(
            render_index_like(&parse_index(crlf.as_bytes()).unwrap(), true),
            crlf
        );
    }

    #[test]
    fn plans_the_probed_layout() {
        let mut writes = Vec::new();
        let records = plan_tree(&|_: &str| None, &patch(UUID), &mut writes).unwrap();
        let dir = ".socket/vendor/coursier/com/typesafe/config/1.4.3";
        let rels: Vec<&str> = writes.iter().map(|w| w.rel.as_str()).collect();
        assert_eq!(
            rels,
            [
                format!("{dir}/config-1.4.3.jar"),
                format!("{dir}/config-1.4.3.jar.sha1"),
                format!("{dir}/config-1.4.3.pom"),
                format!("{dir}/config-1.4.3.pom.sha1"),
                format!("{dir}/{MARKER_NAME}"),
                INDEX_REL.to_string(),
                GITIGNORE_REL.to_string(),
                GITATTRIBUTES_REL.to_string(),
            ]
        );
        let by = |rel: &str| &writes.iter().find(|w| w.rel == rel).unwrap().bytes;
        assert_eq!(
            by(&format!("{dir}/config-1.4.3.jar.sha1")),
            sha1_hex(b"PATCHED JAR").as_bytes(),
            "bare hex, no newline: what Coursier reads"
        );
        let index = String::from_utf8(by(INDEX_REL).clone()).unwrap();
        assert_eq!(
            index,
            format!(
                "{INDEX_HEADER}\n\
                 com.typesafe:config:1.4.3\tcom/typesafe/config/1.4.3/config-1.4.3.jar\t{}\t{UUID}\n\
                 com.typesafe:config:1.4.3\tcom/typesafe/config/1.4.3/config-1.4.3.pom\t{}\t{UUID}\n",
                sha256_hex(b"PATCHED JAR"),
                sha256_hex(b"<project/>\n")
            )
        );
        let marker: serde_json::Value =
            serde_json::from_slice(by(&format!("{dir}/{MARKER_NAME}"))).unwrap();
        assert_eq!(marker["tool"], "coursier");
        assert_eq!(marker["uuid"], UUID);
        assert_eq!(marker["schema"], 1);
        assert_eq!(marker["purl"], "pkg:maven/com.typesafe/config@1.4.3");
        assert_eq!(marker["files"].as_object().unwrap().len(), 4);
        assert!(writes
            .iter()
            .filter(|w| w.tree)
            .all(|w| w.rel.starts_with(dir)));
        let kinds: Vec<(&str, &str)> = records
            .iter()
            .map(|r| (r.file.as_str(), super::super::op_of(r)))
            .collect();
        assert_eq!(
            kinds,
            [
                (INDEX_REL, "create"),
                (GITIGNORE_REL, "create"),
                (GITATTRIBUTES_REL, "create")
            ]
        );
        assert_eq!(records[0].kind, COURSIER_INDEX_KIND);
    }

    #[test]
    fn replan_is_idempotent_and_merges_other_gavs() {
        let mut files = BTreeMap::new();
        let mut writes = Vec::new();
        plan_tree(&reader(files.clone()), &patch(UUID), &mut writes).unwrap();
        apply(&mut files, &writes);
        let mut again = Vec::new();
        let records = plan_tree(&reader(files.clone()), &patch(UUID), &mut again).unwrap();
        assert!(again.iter().all(|w| files.get(&w.rel) == Some(&w.bytes)));
        assert!(records.iter().all(|r| super::super::op_of(r) == "adopt"));
        // Another GAV joins the index, sorted, keeping this one's rows.
        let other = JvmPatch {
            group_id: "org.slf4j",
            artifact_id: "slf4j-api",
            version: "2.0.9",
            uuid: OTHER,
            ..patch(OTHER)
        };
        let mut w2 = Vec::new();
        plan_tree(&reader(files.clone()), &other, &mut w2).unwrap();
        let index = String::from_utf8(
            w2.iter()
                .find(|w| w.rel == INDEX_REL)
                .unwrap()
                .bytes
                .clone(),
        )
        .unwrap();
        let rows = parse_index(index.as_bytes()).unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].gav, "com.typesafe:config:1.4.3");
        assert_eq!(rows[3].gav, "org.slf4j:slf4j-api:2.0.9");
    }

    #[test]
    fn update_replaces_the_rows_of_an_indexed_uuid() {
        let mut files = BTreeMap::new();
        let mut writes = Vec::new();
        plan_tree(&reader(files.clone()), &patch(OTHER), &mut writes).unwrap();
        apply(&mut files, &writes);
        let mut w2 = Vec::new();
        plan_tree(&reader(files.clone()), &patch(UUID), &mut w2).unwrap();
        let index = w2.iter().find(|w| w.rel == INDEX_REL).unwrap();
        let rows = parse_index(&index.bytes).unwrap();
        assert!(rows.iter().all(|r| r.uuid == UUID), "{rows:?}");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn foreign_marker_is_a_conflict() {
        let dir = ".socket/vendor/coursier/com/typesafe/config/1.4.3";
        for marker in [format!("{{\"uuid\":\"{OTHER}\"}}"), "not json".to_string()] {
            let mut files = BTreeMap::new();
            files.insert(format!("{dir}/{MARKER_NAME}"), marker.into_bytes());
            let err = plan_tree(&reader(files), &patch(UUID), &mut Vec::new()).unwrap_err();
            assert_eq!(err.code, "vendor_coursier_tree_conflict", "{err:?}");
        }
        // Our own marker is not a conflict.
        let mut files = BTreeMap::new();
        files.insert(
            format!("{dir}/{MARKER_NAME}"),
            format!("{{\"uuid\":\"{UUID}\"}}").into_bytes(),
        );
        assert!(plan_tree(&reader(files), &patch(UUID), &mut Vec::new()).is_ok());
    }

    #[test]
    fn malformed_index_is_refused_not_rewritten() {
        let sha = "a".repeat(64);
        for bad in [
            "#other-header\n".to_string(),
            format!("{INDEX_HEADER}\nonly\ttwo\n"),
            format!("{INDEX_HEADER}\ng:a:1\tg/a/2/a-1.jar\t{sha}\t{UUID}\n"),
            format!("{INDEX_HEADER}\ng:a:1\tg/a/1/../a-1.jar\t{sha}\t{UUID}\n"),
            format!(
                "{INDEX_HEADER}\ng:a:1\tg/a/1/a-1.jar\t{}\t{UUID}\n",
                "A".repeat(64)
            ),
            format!("{INDEX_HEADER}\ng:a:1\tg/a/1/a-1.jar\t{sha}\tnot-a-uuid\n"),
            format!("{INDEX_HEADER}\ng:a:1+\tg/a/1+/a-1+.jar\t{sha}\t{UUID}\n"),
        ] {
            let mut files = BTreeMap::new();
            files.insert(INDEX_REL.to_string(), bad.clone().into_bytes());
            let err = plan_tree(&reader(files.clone()), &patch(UUID), &mut Vec::new()).unwrap_err();
            assert!(
                err.detail.contains("coursier_index_unreadable"),
                "{bad}: {err:?}"
            );
            assert!(indexed(&reader(files), &patch(UUID).coords()).is_err());
        }
        // CRLF and blank lines are tolerated.
        let ok = format!("{INDEX_HEADER}\r\n\r\ng:a:1\tg/a/1/a-1.jar\t{sha}\t{UUID}\r\n");
        assert_eq!(parse_index(ok.as_bytes()).unwrap().len(), 1);
    }

    #[test]
    fn indexed_needs_gav_and_uuid() {
        let mut files = BTreeMap::new();
        let mut writes = Vec::new();
        assert_eq!(
            indexed(&reader(files.clone()), &patch(UUID).coords()),
            Ok(false)
        );
        plan_tree(&reader(files.clone()), &patch(UUID), &mut writes).unwrap();
        apply(&mut files, &writes);
        assert_eq!(
            indexed(&reader(files.clone()), &patch(UUID).coords()),
            Ok(true)
        );
        assert_eq!(
            indexed(&reader(files.clone()), &patch(OTHER).coords()),
            Ok(false)
        );
        let (jar, pom, module) = committed(&reader(files), &patch(UUID).coords()).unwrap();
        assert_eq!(
            (jar.as_slice(), pom.as_slice(), module),
            (&b"PATCHED JAR"[..], &b"<project/>\n"[..], None)
        );
    }

    #[test]
    fn unsafe_coordinates_are_refused() {
        let bad = JvmPatch {
            version: "1.0--x",
            ..patch(UUID)
        };
        assert_eq!(
            plan_tree(&|_: &str| None, &bad, &mut Vec::new())
                .unwrap_err()
                .code,
            "unsafe_coordinates"
        );
    }
}
