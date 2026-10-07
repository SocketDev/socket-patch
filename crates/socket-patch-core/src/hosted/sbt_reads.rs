//! The hosted engine's sbt reads: the build's resolution evidence,
//! distilled into one JSON document ([`ResolutionDoc`]) the pure sbt
//! rewriter reads from the candidate files under [`SBT_RESOLUTION_KEY`] (a
//! synthetic key, never a path, so the evidence never pollutes the files
//! map's real entries).
//!
//! A [`ProjectView::Disk`] / [`ProjectView::Snapshot`] reads the evidence
//! under its root (`crawlers::sbt_evidence`, on the blocking pool); a
//! [`ProjectView::Memory`] has no `target/` trees, so the in-memory engine
//! always reports "no evidence" and wires nothing for an sbt build.
//!
//! The document is written whenever the root can be walked, evidence or
//! not: the declared projects and the dependency digest come from the
//! build sources alone (an existing pin is re-verified against the
//! digest). Why evidence could not be read (a cap, a FIFO, a malformed
//! record) rides in [`ResolutionDoc::read_error`], for the rewriter's one
//! run-level `redirect_sbt_no_resolution_evidence` warning (raised by the
//! rewriter, which knows whether a new pin needed the evidence).
//!
//! [`SBT_RESOLUTION_KEY`]: crate::patch::redirect::sbt::SBT_RESOLUTION_KEY

use std::path::{Path, PathBuf};

use crate::crawlers::sbt_evidence;
use crate::formats::sbt::evidence::ResolutionDoc;
use crate::formats::sbt::owned_file::HOSTED_REPO_REL;
use crate::vendor::lock_inventory::ProjectView;

/// The distilled resolution JSON ([`ResolutionDoc::to_json`]) for the
/// view's build; `None` for an in-memory view.
pub async fn extra_resolution(view: &ProjectView<'_>) -> Option<String> {
    let root: PathBuf = match view {
        ProjectView::Disk(root) => root.to_path_buf(),
        ProjectView::Snapshot(snap) => snap.root.to_path_buf(),
        ProjectView::Memory(_) => return None,
    };
    let doc = tokio::task::spawn_blocking(move || sbt_evidence::distill(&root))
        .await
        .unwrap_or_else(|e| ResolutionDoc {
            read_error: Some(format!("the evidence walk failed: {e}")),
            ..Default::default()
        });
    Some(doc.to_json())
}

/// The hosted pin repository under `root` when it exists: the copies a
/// hosted sbt build consumes (`vex` consumed-copy lookup).
pub fn hosted_repo_dirs(root: &Path) -> Vec<PathBuf> {
    let dir = root.join(HOSTED_REPO_REL);
    if dir.is_dir() {
        vec![dir]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::formats::sbt::build::deps_digest;
    use crate::hosted::engine::{read_candidate_files, Candidate};
    use crate::patch::redirect::sbt::SBT_RESOLUTION_KEY;
    use crate::patch::redirect::{DepOverride, Integrity};
    use crate::vendor::lock_inventory::{DiskSnapshot, MemoryEntry, MemoryProject};

    /// The 1.9.9 probe matrix staged at `<tmp>/x`.
    fn staged() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("x");
        crate::crawlers::sbt_evidence::stage_fixture(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbt/evidence/1.9.9/matrix"),
            &root,
        );
        (tmp, root)
    }

    fn doc(json: Option<String>) -> ResolutionDoc {
        ResolutionDoc::from_json(&json.expect("a document")).expect("well-formed")
    }

    #[tokio::test]
    async fn disk_and_snapshot_views_distil_the_evidence() {
        let (_tmp, root) = staged();
        let json = extra_resolution(&ProjectView::Disk(&root)).await;
        let d = doc(json);
        assert_eq!(
            d.root,
            sbt_evidence::strip_verbatim(&std::fs::canonicalize(&root).unwrap())
        );
        assert_eq!(
            d.declared,
            Some([".", "a", "d", "e"].map(String::from).into())
        );
        let res = d.resolution.as_ref().unwrap();
        assert_eq!(res.projects_seen, d.declared.clone().unwrap());
        assert!(!d.stale && !d.wiring_newer && d.read_error.is_none());
        assert_eq!(d.deps_digest.len(), 8);

        let snap = DiskSnapshot::new(&root);
        let json = extra_resolution(&ProjectView::Snapshot(&snap)).await;
        assert_eq!(doc(json), d);
    }

    #[tokio::test]
    async fn memory_view_has_no_evidence() {
        let p = MemoryProject::default();
        assert_eq!(extra_resolution(&ProjectView::Memory(&p)).await, None);
    }

    #[tokio::test]
    async fn no_evidence_still_carries_the_build_facts() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("project")).unwrap();
        std::fs::write(
            tmp.path().join("project/build.properties"),
            "sbt.version=1.9.9\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("build.sbt"), "lazy val a = project\n").unwrap();
        let d = doc(extra_resolution(&ProjectView::Disk(tmp.path())).await);
        assert_eq!(d.resolution, None);
        assert_eq!(d.read_error, None);
        assert_eq!(d.declared, Some(["a", "."].map(String::from).into()));
        assert_eq!(
            d.deps_digest,
            deps_digest(&[
                ("build.sbt".into(), "lazy val a = project\n".into()),
                (
                    "project/build.properties".into(),
                    "sbt.version=1.9.9\n".into()
                ),
            ])
        );
    }

    #[tokio::test]
    async fn unreadable_evidence_is_reported_not_partial() {
        let (_tmp, root) = staged();
        let out = root.join("a/target/scala-2.12/update/update_cache_2.12/output");
        std::fs::write(&out, "{\"configurations\":").unwrap();
        let d = doc(extra_resolution(&ProjectView::Disk(&root)).await);
        assert_eq!(d.resolution, None);
        assert!(d.read_error.unwrap().contains("malformed"));

        let big = std::fs::OpenOptions::new().write(true).open(&out).unwrap();
        big.set_len(sbt_evidence::MAX_FILE_BYTES + 1).unwrap();
        let d = doc(extra_resolution(&ProjectView::Disk(&root)).await);
        assert_eq!((d.resolution, d.declared), (None, None));
        assert!(d.read_error.unwrap().contains("cap"));
    }

    #[tokio::test]
    async fn the_document_carries_subproject_findings() {
        // L3's findings ride the one document type: reassignments and a
        // lock in a subproject's own files, which the candidate-file map
        // never carries.
        let tmp = tempfile::tempdir().unwrap();
        let w = |rel: &str, text: &str| {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        };
        w(
            "build.sbt",
            "lazy val core = project.in(file(\"modules/core\"))\n",
        );
        w("project/build.properties", "sbt.version=1.9.9\n");
        w("modules/core/build.sbt", "dependencyOverrides := Nil\n");
        w("modules/core/build.sbt.lock", "{}\n");
        w("socket-patch.sbt", "dependencyOverrides := Nil\n");
        let d = doc(extra_resolution(&ProjectView::Disk(tmp.path())).await);
        assert_eq!(
            d.findings.overrides_assignment,
            ["modules/core/build.sbt:1"]
        );
        assert_eq!(d.findings.dependency_lock, ["modules/core/build.sbt.lock"]);
    }

    fn maven_candidate() -> Candidate {
        Candidate {
            purl: "pkg:maven/com.google.code.gson/gson@2.8.9".into(),
            dep: DepOverride {
                ecosystem: "maven".into(),
                name: "gson".into(),
                namespace: Some("com.google.code.gson".into()),
                version: "2.8.9".into(),
                token: "tok".into(),
                patch_uuid: "uuid".into(),
                artifact_url: String::new(),
                registry_override: None,
                integrity: Integrity::default(),
            },
        }
    }

    #[tokio::test]
    async fn the_engine_merges_the_document_for_maven_candidates_only() {
        let (_tmp, root) = staged();
        let view = ProjectView::Disk(&root);
        let read = read_candidate_files(&view, &BTreeSet::new(), &[maven_candidate()]).await;
        let json = read.files.get(SBT_RESOLUTION_KEY).cloned();
        assert!(doc(json).resolution.is_some());
        // The synthetic key is no read of a real file.
        assert!(!read
            .unreadable_reads
            .iter()
            .any(|k| k == SBT_RESOLUTION_KEY));
        assert!(!read.symlinked_reads.iter().any(|k| k == SBT_RESOLUTION_KEY));

        let read = read_candidate_files(&view, &BTreeSet::new(), &[]).await;
        assert!(!read.files.contains_key(SBT_RESOLUTION_KEY));

        // In memory: an sbt build, but never any evidence.
        let mut p = MemoryProject::default();
        p.insert("build.sbt", MemoryEntry::Text("".into()));
        p.insert(
            "project/build.properties",
            MemoryEntry::Text("sbt.version=1.9.9\n".into()),
        );
        let read = read_candidate_files(
            &ProjectView::Memory(&p),
            &BTreeSet::new(),
            &[maven_candidate()],
        )
        .await;
        assert!(read.files.contains_key("build.sbt"));
        assert!(!read.files.contains_key(SBT_RESOLUTION_KEY));
    }

    #[test]
    fn hosted_repo_dirs_lists_an_existing_repository() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(hosted_repo_dirs(tmp.path()).is_empty());
        std::fs::create_dir_all(tmp.path().join(HOSTED_REPO_REL)).unwrap();
        assert_eq!(
            hosted_repo_dirs(tmp.path()),
            [tmp.path().join(HOSTED_REPO_REL)]
        );
    }
}
