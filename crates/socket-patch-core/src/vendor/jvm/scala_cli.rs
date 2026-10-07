//! Vendored scala-cli directory builds (`docs/design/sbt-support.md`,
//! "scala-cli vendored"). Only owned files are written: a root
//! [`ROOT_FILE`] that `//> using file`s the guard [`GUARD_REL`] inside the
//! tree, whose `//> using repository file://${.}` adds the same-GAV Coursier
//! tree (`super::coursier_tree`) as a repository (adding, not replacing, so
//! mirrors and `COURSIER_REPOSITORIES` survive). Deleting the tree deletes
//! the guard, so the build fails loudly (`File not found`) instead of
//! silently resolving upstream.
//!
//! Probed on scala-cli 1.17.1: `${.}` expands to the directory of the file
//! holding the directive, from any working directory and with or without
//! Bloop; a root `.scala` file is part of every directory build, while files
//! under `.socket/` are not (hence the `using file`). A repository another
//! input declares is consulted first and shadows the tree; the gate
//! (`super::coursier_gate`) refuses those builds.

use std::collections::BTreeMap;

use super::coursier_tree::{self, GITATTRIBUTES_REL, GITIGNORE, GITIGNORE_REL, INDEX_REL};
use super::{
    finish_writes, op_of, CommittedTree, Coords, JvmPatch, JvmPlan, JvmRefusal, JvmUnplan,
    JvmWarning, ReadFn, Shape, WiringRecord,
};

/// The root file scala-cli picks up in a directory build.
pub const ROOT_FILE: &str = "socket-patch.scala";
/// The guard inside the tree.
pub const GUARD_REL: &str = ".socket/vendor/coursier/socket-patch.scala";
/// The scala-cli project file (its presence warns
/// `vendor_scala_cli_directives_split`).
pub const PROJECT_FILE: &str = "project.scala";
/// [`ROOT_FILE`]'s bytes.
pub const ROOT_BYTES: &str =
    "// managed by socket-patch\n//> using file .socket/vendor/coursier/socket-patch.scala\n";
/// [`GUARD_REL`]'s bytes.
pub const GUARD_BYTES: &str = "// managed by socket-patch\n//> using repository file://${.}\n";

/// Whether a file at the root makes it another build tool's (they win: a
/// stray `project.scala` never turns a reactor or a Mill build into a
/// scala-cli one). `.mill-version` alone is not a Mill build file.
fn other_build_file(read: ReadFn<'_>) -> bool {
    use crate::patch::redirect::{
        gradle::GRADLE_ROOT_FILES as GRADLE_FILES, scala_guidance::MILL_MARKERS,
    };
    std::iter::once(&"pom.xml")
        .chain(GRADLE_FILES)
        .chain(MILL_MARKERS.iter().filter(|m| **m != ".mill-version"))
        .any(|f| read(f).is_some())
}

/// [`Shape::ScalaCli`] for a scala-cli directory build: `project.scala` or
/// the root `socket-patch.scala`, and no Maven, Gradle or Mill build file.
pub fn detect(read: ReadFn<'_>) -> Option<Shape> {
    let marked = read(PROJECT_FILE).is_some() || read(ROOT_FILE).is_some();
    (marked && !other_build_file(read)).then_some(Shape::ScalaCli)
}

/// Whether `rel` is a file this planner edits or owns.
pub fn is_wiring_file(rel: &str) -> bool {
    rel == ROOT_FILE || rel == GUARD_REL
}

/// Whether `rel` is a file this planner (or its tree) owns outright.
pub fn is_owned_file(rel: &str) -> bool {
    is_wiring_file(rel) || [INDEX_REL, GITIGNORE_REL, GITATTRIBUTES_REL].contains(&rel)
}

/// Whether `wiring` belongs to this planner.
pub fn owns(wiring: &[WiringRecord]) -> bool {
    wiring.iter().any(|w| {
        w.kind == super::COURSIER_INDEX_KIND
            || w.file == ROOT_FILE
            || w.file
                .starts_with(&format!("{}/", coursier_tree::TREE_ROOT))
    })
}

/// `bytes` are the owned text `expected` (a CRLF checkout of it counts).
fn is_ours(bytes: &[u8], expected: &str) -> bool {
    bytes == expected.as_bytes() || bytes == expected.replace('\n', "\r\n").as_bytes()
}

fn modified(rel: &str) -> JvmRefusal {
    JvmRefusal {
        code: "vendor_scala_cli_owned_file_modified",
        detail: format!(
            "{rel} exists but is not the file socket-patch writes; restore it from git or delete \
             it (vendoring rewrites it), then re-run"
        ),
    }
}

/// Plan vendoring `patch` into the scala-cli build `read` serves.
pub fn plan(read: ReadFn<'_>, patch: &JvmPatch<'_>) -> Result<JvmPlan, JvmRefusal> {
    if !crate::patch::path_safety::is_canonical_uuid(patch.uuid) {
        return Err(JvmRefusal {
            code: "unsafe_coordinates",
            detail: format!("non-canonical patch uuid {:?}", patch.uuid),
        });
    }
    for (rel, expected) in [(ROOT_FILE, ROOT_BYTES), (GUARD_REL, GUARD_BYTES)] {
        if read(rel).is_some_and(|b| !is_ours(&b, expected)) {
            return Err(modified(rel));
        }
    }
    let mut warnings = Vec::new();
    if read(PROJECT_FILE).is_some() {
        warnings.push(JvmWarning {
            code: "vendor_scala_cli_directives_split",
            detail: format!(
                "{PROJECT_FILE} exists, so scala-cli warns \"Using directives detected in \
                 multiple files\" about {ROOT_FILE}; socket-patch keeps its one directive in its \
                 own file and never edits {PROJECT_FILE}"
            ),
        });
    }
    let mut writes = Vec::new();
    let mut records = coursier_tree::plan_tree(read, patch, &mut writes)?;
    records.push(super::owned_file_with(
        read,
        GUARD_REL,
        GUARD_BYTES.as_bytes(),
        &mut writes,
    ));
    records.push(super::owned_file_with(
        read,
        ROOT_FILE,
        ROOT_BYTES.as_bytes(),
        &mut writes,
    ));
    let c = patch.coords();
    let tree_dir = coursier_tree::tree_dir(&c);
    Ok(JvmPlan {
        tree_files: super::tree_files(&writes),
        writes: finish_writes(read, writes),
        records,
        warnings,
        jar_rel: format!("{tree_dir}/{}-{}.jar", c.artifact_id, c.version),
        tree_dir,
    })
}

/// Plan the revert of the patch at `c`: its index rows go now; the index,
/// the root file, the guard and the tree root's git files once no other
/// patch has a row. A modified owned file is left alone (drifted); while the
/// root file left behind still includes the guard, the guard and the tree
/// stay too, so the build keeps resolving the vendored bytes.
pub fn unplan(read: ReadFn<'_>, c: &Coords<'_>, records: &[WiringRecord]) -> JvmUnplan {
    let mut drifted = Vec::new();
    let mut changes: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let index = read(INDEX_REL);
    let crlf = index
        .as_deref()
        .is_some_and(|b| b.windows(2).any(|w| w == b"\r\n"));
    let rows = match index {
        None => Vec::new(),
        Some(bytes) => match coursier_tree::parse_index(&bytes) {
            Ok(rows) => rows,
            Err(why) => {
                drifted.push(format!(
                    "{INDEX_REL} is malformed ({why}); its rows were left alone"
                ));
                return JvmUnplan {
                    changes: Vec::new(),
                    drifted,
                    still_wired: true,
                };
            }
        },
    };
    let others: Vec<_> = rows.iter().filter(|r| r.uuid != c.uuid).cloned().collect();
    let mut still_wired = false;
    if !others.is_empty() {
        if others.len() != rows.len() {
            changes.insert(
                INDEX_REL.to_string(),
                Some(coursier_tree::render_index_like(&others, crlf).into_bytes()),
            );
        }
    } else {
        if read(INDEX_REL).is_some() {
            changes.insert(INDEX_REL.to_string(), None);
        }
        let created = |rel: &str| {
            records
                .iter()
                .any(|w| w.file == rel && op_of(w) == "create")
        };
        let root = read(ROOT_FILE);
        let root_goes = root
            .as_deref()
            .is_some_and(|b| created(ROOT_FILE) && is_ours(b, ROOT_BYTES));
        let root_stays_wired = !root_goes
            && root.as_deref().is_some_and(|b| {
                String::from_utf8_lossy(b).contains(&format!("//> using file {GUARD_REL}"))
            });
        if root_stays_wired {
            drifted.push(format!(
                "{ROOT_FILE} still includes {GUARD_REL}; the guard and the vendored tree stay \
                 until it no longer does"
            ));
            still_wired = true;
        }
        for (rel, expected) in [
            (ROOT_FILE, ROOT_BYTES),
            (GUARD_REL, GUARD_BYTES),
            (GITIGNORE_REL, GITIGNORE),
            (GITATTRIBUTES_REL, super::TREE_GITATTRIBUTES),
        ] {
            if rel == GUARD_REL && root_stays_wired {
                continue;
            }
            let Some(bytes) = read(rel) else { continue };
            match (created(rel), is_ours(&bytes, expected)) {
                (true, true) => {
                    changes.insert(rel.to_string(), None);
                }
                (true, false) if rel != ROOT_FILE || !root_stays_wired => {
                    drifted.push(format!("{rel} was modified"));
                }
                _ => {}
            }
        }
    }
    JvmUnplan {
        changes: changes.into_iter().collect(),
        drifted,
        still_wired,
    }
}

/// Whether the build still wires the patch at `c`: the index lists it and
/// both the root file and the guard are in place.
pub fn wired_checked(read: ReadFn<'_>, c: &Coords<'_>) -> Result<bool, JvmRefusal> {
    let indexed = coursier_tree::indexed(read, c)?;
    let ours = |rel: &str, expected: &str| read(rel).is_some_and(|b| is_ours(&b, expected));
    Ok(indexed && ours(ROOT_FILE, ROOT_BYTES) && ours(GUARD_REL, GUARD_BYTES))
}

/// The committed tree bytes of the patch at `c`.
pub fn committed(read: ReadFn<'_>, c: &Coords<'_>) -> Option<CommittedTree> {
    coursier_tree::committed(read, c)
}

#[cfg(test)]
mod tests {
    use super::super::testing::{dirs, populate, revert, snapshot, vendor};
    use super::*;

    const UUID: &str = "abcdef12-3456-4789-8abc-def012345678";
    const OTHER: &str = "12345678-3456-4789-8abc-def012345678";
    const UPDATE: &str = "fedcba98-3456-4789-8abc-def012345678";

    fn patch(a: &'static str, uuid: &'static str, jar: &'static [u8]) -> JvmPatch<'static> {
        JvmPatch {
            group_id: "com.typesafe",
            artifact_id: a,
            version: "1.4.3",
            uuid,
            jar,
            upstream_pom: b"<project/>\n",
            upstream_module: None,
            extra_artifacts: &[],
            patched_members: &[],
        }
    }

    fn fs(files: &[(&str, &str)]) -> impl Fn(&str) -> Option<Vec<u8>> {
        let map: BTreeMap<String, Vec<u8>> = files
            .iter()
            .map(|(k, v)| (k.to_string(), v.as_bytes().to_vec()))
            .collect();
        move |p: &str| map.get(p).cloned()
    }

    #[test]
    fn detects_project_scala_or_root_file_without_other_builds() {
        assert_eq!(detect(&fs(&[(PROJECT_FILE, "")])), Some(Shape::ScalaCli));
        assert_eq!(
            detect(&fs(&[(ROOT_FILE, ROOT_BYTES)])),
            Some(Shape::ScalaCli)
        );
        assert_eq!(detect(&fs(&[("main.scala", "")])), None);
        // `.mill-version` alone is no Mill build.
        assert_eq!(
            detect(&fs(&[(PROJECT_FILE, ""), (".mill-version", "")])),
            Some(Shape::ScalaCli)
        );
        for other in [
            "pom.xml",
            "settings.gradle",
            "settings.gradle.kts",
            "build.gradle",
            "build.gradle.kts",
            "build.mill",
            "build.mill.yaml",
            "build.sc",
        ] {
            assert_eq!(
                detect(&fs(&[(PROJECT_FILE, ""), (other, "")])),
                None,
                "{other}"
            );
        }
        assert!(is_owned_file(GUARD_REL) && is_owned_file(INDEX_REL));
        assert!(!is_owned_file("project.scala"));
    }

    #[test]
    fn plans_owned_files_only() {
        let plan = plan(&fs(&[("main.scala", "x")]), &patch("config", UUID, b"J")).unwrap();
        let rels: Vec<&str> = plan.writes.iter().map(|w| w.rel.as_str()).collect();
        assert!(
            rels.contains(&ROOT_FILE) && rels.contains(&GUARD_REL),
            "{rels:?}"
        );
        assert!(rels
            .iter()
            .all(|r| *r == ROOT_FILE || r.starts_with(".socket/vendor/coursier")));
        let by = |rel: &str| {
            plan.writes
                .iter()
                .find(|w| w.rel == rel)
                .unwrap()
                .bytes
                .clone()
        };
        assert_eq!(by(ROOT_FILE), ROOT_BYTES.as_bytes());
        assert_eq!(by(GUARD_REL), GUARD_BYTES.as_bytes());
        assert_eq!(
            plan.jar_rel,
            ".socket/vendor/coursier/com/typesafe/config/1.4.3/config-1.4.3.jar"
        );
        assert!(plan.warnings.is_empty());
        assert!(owns(&plan.records));
        let with_project =
            super::plan(&fs(&[(PROJECT_FILE, "")]), &patch("config", UUID, b"J")).unwrap();
        assert_eq!(
            with_project
                .warnings
                .iter()
                .map(|w| w.code)
                .collect::<Vec<_>>(),
            ["vendor_scala_cli_directives_split"]
        );
    }

    #[test]
    fn modified_owned_files_are_refused() {
        for rel in [ROOT_FILE, GUARD_REL] {
            for body in [
                "// managed by socket-patch\n//> using dep x:y:1\n",
                "object Main\n",
            ] {
                let err = plan(&fs(&[(rel, body)]), &patch("config", UUID, b"J")).unwrap_err();
                assert_eq!(err.code, "vendor_scala_cli_owned_file_modified", "{rel}");
                assert!(err.detail.contains(rel));
            }
        }
        // A CRLF checkout of the owned text is still ours.
        let crlf = ROOT_BYTES.replace('\n', "\r\n");
        assert!(plan(&fs(&[(ROOT_FILE, &crlf)]), &patch("config", UUID, b"J")).is_ok());
    }

    #[test]
    fn non_canonical_uuid_is_refused() {
        let err = plan(&fs(&[]), &patch("config", "../x", b"J")).unwrap_err();
        assert_eq!(err.code, "unsafe_coordinates");
    }

    #[tokio::test]
    async fn vendor_then_revert_is_byte_exact_and_replan_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        populate(
            root,
            &[
                (PROJECT_FILE, "//> using scala 3.3.6\n"),
                ("main.scala", "x\n"),
            ],
        );
        let (pristine, pristine_dirs) = (snapshot(root), dirs(root));
        let mut ledger = BTreeMap::new();
        let p = patch("config", UUID, b"PATCHED");
        vendor(root, Shape::ScalaCli, &p, &mut ledger)
            .await
            .unwrap();
        let wired = snapshot(root);
        assert_eq!(wired[ROOT_FILE], ROOT_BYTES.as_bytes());
        assert_eq!(wired[GUARD_REL], GUARD_BYTES.as_bytes());
        assert_eq!(wired[GITIGNORE_REL], b"!*\n");
        let read = |rel: &str| super::super::apply::read_project_file(root, rel);
        assert_eq!(wired_checked(&read, &p.coords()), Ok(true));
        let again = plan(&read, &p).unwrap();
        assert!(again.writes.is_empty(), "{:?}", again.writes);
        assert_eq!(committed(&read, &p.coords()).unwrap().0, b"PATCHED");
        let out = revert(root, &p, &mut ledger).await;
        assert!(out.success && !out.kept_artifact, "{out:?}");
        assert_eq!(snapshot(root), pristine);
        assert_eq!(dirs(root), pristine_dirs);
    }

    #[tokio::test]
    async fn two_patches_revert_in_either_order() {
        for first_out in [0usize, 1] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            populate(root, &[(PROJECT_FILE, "")]);
            let (pristine, pristine_dirs) = (snapshot(root), dirs(root));
            let patches = [patch("config", UUID, b"ONE"), patch("other", OTHER, b"TWO")];
            let mut ledger = BTreeMap::new();
            for p in &patches {
                vendor(root, Shape::ScalaCli, p, &mut ledger).await.unwrap();
            }
            let read = |rel: &str| super::super::apply::read_project_file(root, rel);
            let rows = coursier_tree::parse_index(&read(INDEX_REL).unwrap()).unwrap();
            assert_eq!(rows.len(), 4);
            let (a, b) = (&patches[first_out], &patches[1 - first_out]);
            let out = revert(root, a, &mut ledger).await;
            assert!(out.success && !out.kept_artifact, "{out:?}");
            assert_eq!(wired_checked(&read, &a.coords()), Ok(false));
            assert_eq!(wired_checked(&read, &b.coords()), Ok(true));
            assert!(read(ROOT_FILE).is_some() && read(GUARD_REL).is_some());
            let out = revert(root, b, &mut ledger).await;
            assert!(out.success, "{out:?}");
            assert_eq!(snapshot(root), pristine, "first out: {first_out}");
            assert_eq!(dirs(root), pristine_dirs);
        }
    }

    #[tokio::test]
    async fn update_rewires_and_sweeps_then_reverts_to_pristine() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        populate(root, &[(PROJECT_FILE, "")]);
        let pristine = snapshot(root);
        let mut ledger = BTreeMap::new();
        vendor(
            root,
            Shape::ScalaCli,
            &patch("config", UUID, b"V1"),
            &mut ledger,
        )
        .await
        .unwrap();
        let v2 = patch("config", UPDATE, b"V2");
        vendor(root, Shape::ScalaCli, &v2, &mut ledger)
            .await
            .unwrap();
        let read = |rel: &str| super::super::apply::read_project_file(root, rel);
        assert_eq!(wired_checked(&read, &v2.coords()), Ok(true));
        let rows = coursier_tree::parse_index(&read(INDEX_REL).unwrap()).unwrap();
        assert!(rows.iter().all(|r| r.uuid == UPDATE));
        assert_eq!(committed(&read, &v2.coords()).unwrap().0, b"V2");
        let out = revert(root, &v2, &mut ledger).await;
        assert!(out.success && !out.kept_artifact, "{out:?}");
        assert_eq!(snapshot(root), pristine);
    }

    #[tokio::test]
    async fn drifted_root_file_keeps_the_guard_and_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        populate(root, &[(PROJECT_FILE, "")]);
        let mut ledger = BTreeMap::new();
        let p = patch("config", UUID, b"J");
        vendor(root, Shape::ScalaCli, &p, &mut ledger)
            .await
            .unwrap();
        let edited = format!("{ROOT_BYTES}//> using dep x:y:1\n");
        std::fs::write(root.join(ROOT_FILE), &edited).unwrap();
        let out = revert(root, &p, &mut ledger).await;
        assert!(out.success && out.kept_artifact, "{out:?}");
        assert!(out
            .warnings
            .iter()
            .any(|w| w.code == "vendor_lock_entry_drifted"));
        assert_eq!(
            std::fs::read_to_string(root.join(ROOT_FILE)).unwrap(),
            edited
        );
        assert!(root.join(GUARD_REL).exists());
        assert!(root.join(p_jar(&p)).exists());
    }

    fn p_jar(p: &JvmPatch<'_>) -> String {
        format!(
            "{}/{}-{}.jar",
            coursier_tree::tree_dir(&p.coords()),
            p.artifact_id,
            p.version
        )
    }

    #[test]
    fn unplan_leaves_a_malformed_index_and_modified_files() {
        let c = patch("config", UUID, b"J").coords();
        let out = unplan(&fs(&[(INDEX_REL, "garbage\n")]), &c, &[]);
        assert!(out.still_wired && out.changes.is_empty());
        assert_eq!(out.drifted.len(), 1);
        // Last out with a modified guard: the guard stays, drifted.
        let create = |rel: &str| {
            super::super::fragment(
                rel,
                super::super::OWNED_FILE_KIND,
                "owned",
                super::super::WiringAction::Added,
                None,
                serde_json::json!({ "op": "create" }),
            )
        };
        let records = vec![create(ROOT_FILE), create(GUARD_REL)];
        let out = unplan(
            &fs(&[(ROOT_FILE, ROOT_BYTES), (GUARD_REL, "// edited\n")]),
            &c,
            &records,
        );
        assert_eq!(out.changes, vec![(ROOT_FILE.to_string(), None)]);
        assert_eq!(out.drifted, [format!("{GUARD_REL} was modified")]);
        assert!(!out.still_wired);
        // A file never created by vendor is never deleted.
        let out = unplan(&fs(&[(ROOT_FILE, ROOT_BYTES)]), &c, &[]);
        assert!(out.still_wired, "the root file still includes the guard");
        assert!(out.changes.is_empty());
    }

    #[test]
    fn wired_checked_needs_index_root_and_guard() {
        let mut writes_files = BTreeMap::new();
        let p = patch("config", UUID, b"J");
        let plan = plan(&|_: &str| None, &p).unwrap();
        for w in &plan.writes {
            writes_files.insert(w.rel.clone(), w.bytes.clone());
        }
        for drop in [None, Some(ROOT_FILE), Some(GUARD_REL), Some(INDEX_REL)] {
            let mut files = writes_files.clone();
            if let Some(rel) = drop {
                files.remove(rel);
            }
            let read = move |p: &str| files.get(p).cloned();
            assert_eq!(
                wired_checked(&read, &p.coords()),
                Ok(drop.is_none()),
                "{drop:?}"
            );
        }
        let bad = fs(&[(INDEX_REL, "#nope\n")]);
        assert!(wired_checked(&bad, &p.coords()).is_err());
    }
}
