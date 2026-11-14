//! Goldens: the harness of the Bazel rewriter group, and the group's own
//! cases over the toy lane.
//!
//! The harness runs a case the way the hosted engine runs a project:
//! [`scan`] asks the whole seam (`rewrite_registry_redirect_under_bazel`:
//! the sweep, the gate, the native rewriter, the lane, the executor and
//! the confirmation) and lands the change set it returns; [`undo`] asks
//! the restore of the group and lands that. Neither reaches into a lane.
//! [`round_trip`] is the golden of a case directory,
//!
//! ```text
//! <case>/input/            the Bazel root
//! <case>/overrides.json    the grants, as the redirect goldens spell them
//! <case>/expected/         each file the run changes, with its new bytes
//! <case>/project           optional: the project below the root
//! ```
//!
//! and holds a lane to four things: the run changes exactly the files of
//! `expected/`, byte for byte, and each is a path the plans capture
//! (`exec::touched`); a second run changes nothing; the restore returns
//! `input/` byte for byte; and all of it holds again with the edited
//! files in CRLF.
//!
//! The cases below are the seam's own. They run the toy lane of
//! `toy_lane.rs` through the group, so the positive path (write, record,
//! confirm, sweep, restore) is executed before any real lane exists, and
//! lanes that misbehave in one way each (a pin on the upstream digest, a
//! pin on another digest or another release, a write off the plan, a
//! restore that drops a pin that is gone) show what the group does with
//! them. Roots with two projects, and with two locks in one project, hold
//! the group to its own project and to every lock of it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::json;
use socket_patch_core::bazel::exec;
use socket_patch_core::bazel::gate::{self, GateCx};
use socket_patch_core::bazel::java_hash::hash_bytes;
use socket_patch_core::bazel::lanes;
use socket_patch_core::bazel::model::{
    Actor, Anchor, ArtifactForm, ArtifactSpec, AttestBasis, BazelRef, BazelWorkspace, Code, Digest,
    FileText, FileView, Files, GateOutcome, HubId, Index, IndexRow, LaneCx, LaneId, LaneOps,
    LaneSpec, LaneTable, Lift, Mode, OwnedWrite, PatchRequest, PinSource, Plan, PlannedWrite,
    RestoreOutcome, RootRef, Ruleset, RunKind, RunRequired, TextRead, VexWithhold, WithholdKind,
    WriteClass,
};
use socket_patch_core::bazel::owned_index::{
    self, IndexCheck, IndexEdit, Parsed, ResolvedHash, INDEX_PATH,
};
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::origin::hosted_patch_uuid;
use socket_patch_core::patch::redirect::bazel::{BazelHost, BazelRewrite, Refused, Verdict};
use socket_patch_core::patch::redirect::upstream::bazel::{self as restore, Root, Undo, Undone};
use socket_patch_core::patch::redirect::upstream::{
    restore_upstream, restore_upstream_under_bazel, HostedPin, PinStatus, RestoreOptions,
};
use socket_patch_core::patch::redirect::{
    rewrite_registry_redirect, rewrite_registry_redirect_under_bazel, DepOverride, Integrity,
    RewriteResult,
};
use socket_patch_core::vendor::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};

use super::toy_lane::{
    edit, grant, lock_of, parse, pins_hash, set_member, sha_key, upstream_url, INPUT, LANE, LOCK,
    MODULE, PATCHED, PATCH_URL, PURL, TABLE, TOY, UPSTREAM, UUID,
};

// ── The harness ──────────────────────────────────────────────────────

/// The files of one Bazel root, in memory, by `/`-separated path.
#[derive(Clone, Default, PartialEq, Debug)]
pub(super) struct Tree(pub(super) BTreeMap<String, Vec<u8>>);

impl Tree {
    pub(super) fn of(files: &[(&str, &str)]) -> Self {
        let file = |(path, text): &(&str, &str)| (path.to_string(), text.as_bytes().to_vec());
        Self(files.iter().map(file).collect())
    }

    /// Every file below `dir`, by its path from there. The path is built
    /// from its components, so it is spelled with `/` on every system.
    pub(super) fn from_dir(dir: &Path) -> Self {
        fn walk(dir: &Path, at: &mut Vec<String>, out: &mut BTreeMap<String, Vec<u8>>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                at.push(entry.file_name().to_string_lossy().into_owned());
                match entry.path().is_dir() {
                    true => walk(&entry.path(), at, out),
                    false => {
                        let bytes = std::fs::read(entry.path()).expect("a fixture file");
                        out.insert(at.join("/"), bytes);
                    }
                }
                at.pop();
            }
        }
        let mut out = BTreeMap::new();
        walk(dir, &mut Vec::new(), &mut out);
        Self(out)
    }

    pub(super) fn text(&self, path: &str) -> String {
        let bytes = self.0.get(path);
        let bytes = bytes.unwrap_or_else(|| panic!("no file `{path}`"));
        String::from_utf8(bytes.clone()).expect("a text file")
    }

    /// Lands a change set.
    pub(super) fn apply(&mut self, changes: &BTreeMap<String, Option<Vec<u8>>>) {
        for (path, bytes) in changes {
            match bytes {
                Some(bytes) => drop(self.0.insert(path.clone(), bytes.clone())),
                None => drop(self.0.remove(path)),
            }
        }
    }

    /// The same root with the files of `paths` in CRLF.
    fn crlf(&self, paths: &BTreeSet<String>) -> Self {
        let mut out = self.clone();
        for path in paths.iter().filter(|path| self.0.contains_key(*path)) {
            let text = self.text(path).replace("\r\n", "\n").replace('\n', "\r\n");
            out.0.insert(path.clone(), text.into_bytes());
        }
        out
    }
}

impl FileView for Tree {
    fn read(&self, rel: &str) -> FileText {
        let found = self.0.get(rel);
        found.map_or(FileText::Absent, |bytes| FileText::Bytes(bytes.clone()))
    }

    fn list(&self, dir: &str) -> Option<Vec<String>> {
        let below = match dir {
            "" => String::new(),
            dir => format!("{dir}/"),
        };
        let mut names: Vec<String> = Vec::new();
        for rest in self.0.keys().filter_map(|path| path.strip_prefix(&below)) {
            let name = match rest.split_once('/') {
                Some((child, _)) => format!("{child}/"),
                None => rest.to_string(),
            };
            if !names.contains(&name) {
                names.push(name);
            }
        }
        Some(names)
    }
}

/// The model of the root, read for the project at `project_rel`.
pub(super) fn workspace(view: &dyn FileView, project_rel: &str) -> BazelWorkspace {
    let root = RootRef {
        root: PathBuf::from("repo"),
        project_rel: project_rel.to_string(),
        boundary_levels: 0,
    };
    socket_patch_core::bazel::detect(&root, view).expect("a Bazel workspace")
}

/// The owned index as the root's file holds it, which is how a run reads
/// it: the file is the record.
pub(super) fn index_of(tree: &Tree) -> Index {
    match FileView::read(tree, INDEX_PATH) {
        FileText::Absent => Index::default(),
        FileText::Bytes(bytes) => match owned_index::parse(&bytes) {
            Parsed::Ours(index) => index,
            other => panic!("the index file is not ours: {other:?}"),
        },
        FileText::Unreadable => panic!("the index file cannot be read"),
    }
}

/// The rows of an index in the order of the file: a held index keeps its
/// rows in the order they were recorded, which says nothing.
fn rows(index: &Index) -> Option<String> {
    index.render().ok()
}

fn below(project_rel: &str) -> String {
    match project_rel {
        "" => String::new(),
        project => format!("{project}/"),
    }
}

/// One hosted run for the project at `project_rel`, as the engine makes
/// it: the model and the index are read from the root as it is, the seam
/// decides, and what it returns is landed. Every path of the Bazel change
/// set must be one the plans capture, and the index the run reports must
/// be the one its change set leaves in the file.
pub(super) fn scan(
    tree: &mut Tree,
    table: &LaneTable,
    project_rel: &str,
    overrides: &[DepOverride],
) -> (RewriteResult, BazelRewrite) {
    let index = index_of(tree);
    let below = below(project_rel);
    let (result, bazel) = seam(tree, &*tree, &index, table, project_rel, overrides);
    let captured = exec::touched(&index, &bazel.plans);
    for path in bazel.changes.keys() {
        assert!(captured.contains(path), "`{path}` is in no capture list");
    }
    tree.apply(&bazel.changes);
    for (path, text) in &result.files {
        let bytes = text.clone().into_bytes();
        tree.0.insert(format!("{below}{path}"), bytes);
    }
    assert_eq!(
        rows(&index_of(tree)),
        rows(&bazel.index),
        "the index the run reports"
    );
    (result, bazel)
}

/// The seam alone, with nothing landed and nothing asserted: over `view`,
/// which shows the root (the tree itself, or the tree with a file nobody
/// can read), and with the index the run holds, which need not be what
/// the index file of the tree says. The project's own files are the text
/// files of `tree` below the project.
fn seam(
    tree: &Tree,
    view: &dyn FileView,
    index: &Index,
    table: &LaneTable,
    project_rel: &str,
    overrides: &[DepOverride],
) -> (RewriteResult, BazelRewrite) {
    let ws = workspace(view, project_rel);
    let below = below(project_rel);
    let own = |(path, bytes): (&String, &Vec<u8>)| {
        let text = String::from_utf8(bytes.clone()).ok()?;
        Some((path.strip_prefix(&below)?.to_string(), text))
    };
    let files: BTreeMap<String, String> = tree.0.iter().filter_map(own).collect();
    let host = BazelHost {
        cx: GateCx::new(Mode::Hosted, &ws, view, index),
        lanes: table,
    };
    rewrite_registry_redirect_under_bazel(&files, overrides, &host)
}

/// The restore of the group for the patches `uuids`, landed.
pub(super) fn undo(tree: &mut Tree, table: &LaneTable, uuids: &[&str]) -> Undo {
    let (ws, index) = (workspace(tree, ""), index_of(tree));
    let undone = {
        let root = Root {
            ws: &ws,
            files: &*tree,
            index: &index,
            lanes: table,
        };
        restore::revert(&root, uuids)
    };
    tree.apply(&undone.changes);
    assert_eq!(
        rows(&index_of(tree)),
        rows(&undone.index),
        "the index the undo reports"
    );
    undone
}

/// The golden of one case directory (the module docs), for a lane whose
/// pins the owned index records.
pub(super) fn round_trip(table: &LaneTable, case: &Path) {
    let input = Tree::from_dir(&case.join("input"));
    let expected = Tree::from_dir(&case.join("expected"));
    let overrides = std::fs::read_to_string(case.join("overrides.json")).expect("overrides.json");
    let overrides: Vec<DepOverride> = serde_json::from_str(&overrides).expect("the grants");
    let project = std::fs::read_to_string(case.join("project")).unwrap_or_default();
    let project = project.trim();
    let uuids: BTreeSet<String> = overrides.iter().map(|d| d.patch_uuid.clone()).collect();
    assert!(!input.0.is_empty() && !expected.0.is_empty() && !uuids.is_empty());

    // The record is socket-patch's own file, written with LF whatever the
    // user's files hold; every other expected file has a CRLF twin.
    let edited = expected.0.keys().filter(|path| *path != INDEX_PATH);
    let edited: BTreeSet<String> = edited.cloned().collect();
    for crlf in [false, true] {
        let (input, expected) = match crlf {
            true => (input.crlf(&edited), expected.crlf(&edited)),
            false => (input.clone(), expected.clone()),
        };
        let mut tree = input.clone();
        let (result, bazel) = scan(&mut tree, table, project, &overrides);
        assert_eq!(result.confirmed_bazel_uuids, uuids, "crlf={crlf}");
        assert!(result.refused_bazel_uuids.is_empty(), "crlf={crlf}");
        assert_eq!(bazel.governed(), uuids, "crlf={crlf}");

        let changed = |path: &&String| tree.0.get(*path) != input.0.get(*path);
        let changed: Vec<&String> = tree.0.keys().filter(changed).collect();
        let wanted: Vec<&String> = expected.0.keys().collect();
        assert_eq!(changed, wanted, "crlf={crlf}: the files the run changed");
        assert!(input.0.keys().all(|path| tree.0.contains_key(path)));
        for path in wanted {
            assert_eq!(tree.text(path), expected.text(path), "crlf={crlf}: {path}");
        }

        // A second run finds every pin in place.
        let mut again = tree.clone();
        let (result, bazel) = scan(&mut again, table, project, &overrides);
        assert!(bazel.changes.is_empty(), "crlf={crlf}: {:?}", bazel.changes);
        assert_eq!(result.confirmed_bazel_uuids, uuids, "crlf={crlf}");
        assert_eq!(again, tree, "crlf={crlf}: a second run is a no-op");

        let uuids: Vec<&str> = uuids.iter().map(String::as_str).collect();
        let undone = undo(&mut tree, table, &uuids);
        for patch in &undone.patches {
            let restored = matches!(patch.state, Undone::Restored { .. });
            assert!(restored, "crlf={crlf}: {patch:?}");
        }
        assert_eq!(tree, input, "crlf={crlf}: the restore is byte-exact");
    }
}

// ── The toy root ─────────────────────────────────────────────────────

/// The toy workspace on Bazel 9.3.2 with `lock` as its toy lock.
fn toy_tree(lock: &str) -> Tree {
    Tree::of(&[
        (".bazelversion", "9.3.2\n"),
        ("MODULE.bazel", MODULE),
        (LOCK, lock),
    ])
}

/// What the toy lane makes of [`INPUT`] for [`grant`].
fn pinned(input: &str) -> String {
    let lock = input
        .replace(&upstream_url("dep", "1.0.0"), PATCH_URL)
        .replace(UPSTREAM, PATCHED);
    let hash = pins_hash(&parse(&lock).expect("a toy lock")).expect("its pins");
    lock.replace("-1084610730", &hash.to_string())
}

/// A toy lock over `packages` (name, version, digest), in the layout of
/// [`INPUT`], with the derived value its pins give.
fn toy_lock(packages: &[(&str, &str, &str)]) -> String {
    let mut text = "{\n  \"lockVersion\": 1,\n  \"packages\": {\n".to_string();
    for (at, (name, version, sha256)) in packages.iter().enumerate() {
        let comma = if at + 1 < packages.len() { "," } else { "" };
        let url = upstream_url(name, version);
        text.push_str(&format!(
            "    \"{name}\": {{\n      \"version\": \"{version}\",\n      \"url\": \"{url}\",\n      \
             \"sha256\": \"{sha256}\"\n    }}{comma}\n"
        ));
    }
    text.push_str("  },\n  \"pinsHash\": 0\n}\n");
    let hash = pins_hash(&parse(&text).expect("a toy lock")).expect("its pins");
    text.replace("\"pinsHash\": 0", &format!("\"pinsHash\": {hash}"))
}

fn refusal_of<'a>(bazel: &'a BazelRewrite, uuid: &str) -> &'a Refused {
    let patch = bazel.decided.iter().find(|patch| patch.uuid == uuid);
    match &patch.expect("the patch was decided").verdict {
        Verdict::Refused(why) => why,
        Verdict::Confirmed => panic!("{uuid} is confirmed"),
    }
}

fn codes(result: &RewriteResult) -> Vec<&str> {
    result.warnings.iter().map(|w| w.code.as_str()).collect()
}

// ── The cases ────────────────────────────────────────────────────────

/// The harness reads a case from disk and holds it to the round trip,
/// LF and CRLF: the toy lane's case, written out the way a lane package
/// commits one.
#[test]
fn a_case_directory_round_trips_through_the_seam_lf_and_crlf() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let write = |rel: &[&str], text: &str| {
        // Component by component: one `join("a/b")` would spell the
        // path with the wrong separator for a walk on Windows.
        let path = rel
            .iter()
            .fold(dir.path().to_path_buf(), |at, name| at.join(name));
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, text).expect("write");
    };
    write(&["input", ".bazelversion"], "9.3.2\n");
    write(&["input", "MODULE.bazel"], MODULE);
    write(&["input", LOCK], INPUT);
    let overrides = json!([{
        "ecosystem": "maven", "name": "dep", "version": "1.0.0",
        "token": "tok_fixture_4f1c", "patchUuid": UUID, "artifactUrl": PATCH_URL,
        "integrity": { "sha256": PATCHED },
    }]);
    write(&["overrides.json"], &overrides.to_string());
    write(&["expected", LOCK], &pinned(INPUT));
    // The record: what was replaced, and never a URL.
    let hash = pins_hash(&parse(&pinned(INPUT)).unwrap()).unwrap();
    let mut index = Index::default();
    index.record_pin(IndexRow {
        uuid: UUID.to_string(),
        purl: PURL.to_string(),
        lane: LANE.0.to_string(),
        file: LOCK.to_string(),
        edits: vec![
            owned_index::IndexEdit {
                key: sha_key("dep"),
                original: UPSTREAM.to_string(),
                new: PATCHED.to_string(),
            },
            owned_index::IndexEdit {
                key: "pinsHash".to_string(),
                original: "-1084610730".to_string(),
                new: hash.to_string(),
            },
        ],
        check: None,
    });
    let record = index.render().expect("a record");
    assert!(!record.contains("://"), "{record}");
    write(&["expected", ".socket", "bazel", "index.json"], &record);
    round_trip(&TABLE, dir.path());
}

/// What the seam reports for a confirmed patch: the uuid sets, the plan,
/// the typed outcome and the edits by root-relative path. The native
/// result holds nothing: no native rewriter saw the patch.
#[test]
fn a_confirmed_patch_is_reported_once_with_its_plan_and_its_edits() {
    let mut tree = toy_tree(INPUT);
    let (result, bazel) = scan(&mut tree, &TABLE, "", &[grant()]);
    assert!(result.files.is_empty() && result.edits.is_empty());
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let uuid = BTreeSet::from([UUID.to_string()]);
    assert_eq!(result.confirmed_bazel_uuids, uuid);
    assert!(result.refused_bazel_uuids.is_empty());

    let [patch] = &bazel.decided[..] else {
        panic!("one patch: {:?}", bazel.decided);
    };
    assert_eq!(
        (patch.uuid.as_str(), patch.ecosystem, patch.name.as_str()),
        (UUID, Ecosystem::Maven, "dep")
    );
    assert_eq!(patch.verdict, Verdict::Confirmed);
    let GateOutcome::Proceed(plan) = &patch.outcome else {
        panic!("the gate's answer rides along: {:?}", patch.outcome);
    };
    assert_eq!(bazel.plans, std::slice::from_ref(plan));
    assert_eq!((plan.lane, plan.uuid.as_str()), (LANE, UUID));
    let changed: Vec<&String> = bazel.changes.keys().collect();
    assert_eq!(changed, [INDEX_PATH, LOCK]);
    let edited: Vec<(&str, Option<&str>)> = bazel
        .edits
        .iter()
        .map(|edit| (edit.path.as_str(), edit.key.as_deref()))
        .collect();
    let sha = sha_key("dep");
    assert_eq!(edited, [(LOCK, Some(&*sha)), (LOCK, Some("pinsHash"))]);
    let [row] = &bazel.index.pins[..] else {
        panic!("one row: {:?}", bazel.index.pins);
    };
    assert_eq!(
        (row.purl.as_str(), row.lane.as_str(), row.file.as_str()),
        (PURL, LANE.0, LOCK)
    );
    // No grant token reaches the record.
    assert!(!tree.text(INDEX_PATH).contains("tok_fixture"));
}

/// With the production table every lane is disabled: the toy hub is the
/// pinned rules_jvm_external shape, whose lane has not landed, so the
/// patch is refused with the lane to enable and nothing is written. The
/// expectation is computed, so the change that enables the lane does not
/// turn this red.
#[test]
fn the_production_table_refuses_the_hub_with_the_lane_to_enable() {
    let before = toy_tree(INPUT);
    let mut tree = before.clone();
    let ws = workspace(&tree, "");
    let cell = lanes::Cell::of(&ws, HubId(0), Mode::Hosted).expect("the hub's cell");
    let (result, bazel) = scan(&mut tree, &lanes::PRODUCTION, "", &[grant()]);
    if lanes::admits(&lanes::PRODUCTION, &cell) {
        return;
    }
    assert_eq!(tree, before, "a refusal writes nothing");
    assert!(result.files.is_empty() && bazel.changes.is_empty() && bazel.plans.is_empty());
    assert_eq!(
        result.refused_bazel_uuids,
        BTreeSet::from([UUID.to_string()])
    );
    let why = refusal_of(&bazel, UUID);
    assert_eq!(why.code, Code::RedirectRulesetUnsupported);
    assert_eq!(why.token, "lane_not_enabled");
    assert_eq!(why.lift, Lift::EnableLane(LaneId("H-MVN1")));
    assert_eq!(
        why.lift.details(),
        json!({ "kind": "enable_lane", "lane": "H-MVN1" })
    );
    assert!(
        why.detail.ends_with("; nothing was written"),
        "{}",
        why.detail
    );
    assert_eq!(codes(&result), [Code::RedirectRulesetUnsupported.as_str()]);
}

// A lane that takes the URL in the lock for the pin (ROUTED R-143). It
// writes the Socket URL and leaves the upstream digest, records the one
// thing it changed, finds its pin by the URL and vouches for it.

const URL_LANE: LaneId = LaneId("H-TOYURL");
const URL_SPEC: LaneSpec = LaneSpec {
    id: URL_LANE,
    ..TOY.lanes[0]
};

fn source_key(name: &str) -> String {
    format!("packages/{name}/source")
}

fn url_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    let plan = match (TOY.gate)(cx, req) {
        GateOutcome::Proceed(plan) => plan,
        other => return other,
    };
    let path = lock_of(cx).unwrap_or_default();
    let key = source_key(req.name);
    GateOutcome::Proceed(Plan {
        lane: URL_LANE,
        writes: vec![
            PlannedWrite::GeneratedValue { path, key },
            PlannedWrite::Owned(OwnedWrite::Index),
        ],
        ..plan
    })
}

fn url_rewrite(cx: &LaneCx<'_>, files: &mut Files, pins: &[PinSource], result: &mut RewriteResult) {
    let Some(lock) = lock_of(cx) else { return };
    let Some(mut text) = files.get(&lock).cloned() else {
        return;
    };
    for pin in pins {
        let PinSource::Hosted(dep) = pin else {
            continue;
        };
        let upstream = upstream_url(&dep.name, &dep.version);
        if set_member(&mut text, &dep.name, "url", &upstream, &dep.artifact_url) {
            let key = source_key(&dep.name);
            result.edits.push(edit(&lock, &key, "upstream", "socket"));
        }
    }
    files.insert(lock, text);
}

fn url_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
    let lock = lock_of(cx)?;
    let doc = parse(&read(&lock)?)?;
    let hosted = |row: &&IndexRow| {
        let name = row
            .edits
            .first()
            .and_then(|edit| edit.key.split('/').nth(1));
        let url = name.and_then(|name| doc["packages"][name]["url"].as_str());
        row.lane == URL_LANE.0
            && url.is_some_and(|url| url.starts_with("https://patch.socket.dev/"))
    };
    let pin = |row: &IndexRow| BazelRef {
        lane: URL_LANE,
        purl: row.purl.clone(),
        uuid: row.uuid.clone(),
        file: lock.clone(),
        basis: AttestBasis::BazelLock,
    };
    Some(cx.index.pins.iter().filter(hosted).map(pin).collect())
}

fn vouch(_: &LaneCx<'_>, _: &BazelRef) -> Result<(), VexWithhold> {
    Ok(())
}

const URL_OPS: LaneOps = LaneOps {
    lanes: &[URL_SPEC],
    gate: url_gate,
    rewrite_owned: url_rewrite,
    discover: url_discover,
    attest: vouch,
    ..LaneOps::disabled(&[])
};
const URL_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &URL_OPS)]);

/// A lock line with the Socket URL and the upstream digest builds the
/// upstream package from the repository cache (probe Y6), so "the lock
/// names the patch URL" confirms nothing. The lane finds its pin and
/// vouches for it; the group holds the digest the lock pins to the
/// grant's, refuses the patch, and leaves the root byte for byte.
#[test]
fn a_pin_on_the_upstream_digest_is_refused_and_nothing_is_left_written() {
    const OPS: LaneOps = LaneOps {
        inventory: TOY.inventory,
        ..URL_OPS
    };
    const TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    for input in [INPUT.to_string(), INPUT.replace('\n', "\r\n")] {
        let before = toy_tree(&input);
        let mut tree = before.clone();
        let (result, bazel) = scan(&mut tree, &TABLE, "", &[grant()]);
        assert_eq!(tree, before, "nothing of the refused pin is left");
        assert!(bazel.changes.is_empty() && bazel.plans.is_empty());
        assert!(bazel.index.is_empty() && bazel.edits.is_empty());
        assert!(result.confirmed_bazel_uuids.is_empty());
        assert_eq!(
            result.refused_bazel_uuids,
            BTreeSet::from([UUID.to_string()])
        );
        let why = refusal_of(&bazel, UUID);
        assert_eq!(why.code, Code::RedirectRulesetUnsupported);
        assert_eq!(why.lift, Lift::EnableLane(URL_LANE));
        assert!(
            why.detail.contains("is not the digest of the patch"),
            "{}",
            why.detail
        );
        assert!(
            why.detail.ends_with("; nothing was written"),
            "{}",
            why.detail
        );
        assert!(!format!("{why:?}").contains("tok_fixture"), "{why:?}");
        // The gate had passed the plan: the refusal is the confirmation's.
        let decided = &bazel.decided[0].outcome;
        assert!(matches!(decided, GateOutcome::Proceed(_)), "{decided:?}");
    }
    // Without a listing nothing anchors the pin either: a lane that lists
    // no digest for its lock cannot be confirmed in hosted mode.
    let mut tree = toy_tree(INPUT);
    let (result, bazel) = scan(&mut tree, &URL_TABLE, "", &[grant()]);
    assert!(result.confirmed_bazel_uuids.is_empty());
    assert!(bazel.changes.is_empty());
    assert_eq!(tree, toy_tree(INPUT));
}

const OTHER: &str = "0a1b2c3d-0000-4000-8000-0000000000a1";
const OTHER_UPSTREAM: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const OTHER_PATCHED: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const WRONG: &str = "3333333333333333333333333333333333333333333333333333333333333333";

fn other_grant() -> DepOverride {
    DepOverride {
        name: "other".to_string(),
        version: "2.0.0".to_string(),
        patch_uuid: OTHER.to_string(),
        artifact_url: "https://patch.socket.dev/toy/tok_fixture_4f1c/other-2.0.0.sh".to_string(),
        integrity: Integrity {
            sha256: Some(OTHER_PATCHED.to_string()),
            ..Integrity::default()
        },
        ..grant()
    }
}

/// The toy writer, but for the package `other` it pins a digest that is
/// not the grant's.
fn wrong_rewrite(
    cx: &LaneCx<'_>,
    files: &mut Files,
    pins: &[PinSource],
    result: &mut RewriteResult,
) {
    let wrong = |pin: &PinSource| match pin {
        PinSource::Hosted(dep) if dep.name == "other" => {
            let mut dep = dep.clone();
            dep.integrity.sha256 = Some(WRONG.to_string());
            PinSource::Hosted(dep)
        }
        pin => pin.clone(),
    };
    let pins: Vec<PinSource> = pins.iter().map(wrong).collect();
    (TOY.rewrite_owned)(cx, files, &pins, result);
}

/// Two patches of one lock, and the lane pins the second on a digest that
/// is not its grant's. The second is refused at its confirmation, after
/// both were staged; what is committed is the first patch alone, as if
/// the second had never been written: its digest, the derived value over
/// it and its row, and no byte of the refused one.
#[test]
fn a_patch_that_fails_its_confirmation_leaves_nothing_beside_the_ones_that_pass() {
    const OPS: LaneOps = LaneOps {
        rewrite_owned: wrong_rewrite,
        ..TOY
    };
    const WRONG_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    let packages = [
        ("dep", "1.0.0", UPSTREAM),
        ("other", "2.0.0", OTHER_UPSTREAM),
    ];
    let before = toy_tree(&toy_lock(&packages));
    let grants = [grant(), other_grant()];

    // The honest lane pins both, and the lock is the one with both pins.
    let mut both = before.clone();
    let (result, _) = scan(&mut both, &TABLE, "", &grants);
    assert_eq!(result.confirmed_bazel_uuids.len(), 2);
    let both_pinned = toy_lock(&[("dep", "1.0.0", PATCHED), ("other", "2.0.0", OTHER_PATCHED)]);
    let urls = |text: String| {
        text.replace(&upstream_url("dep", "1.0.0"), PATCH_URL)
            .replace(&upstream_url("other", "2.0.0"), &other_grant().artifact_url)
    };
    assert_eq!(both.text(LOCK), urls(both_pinned));
    assert_eq!(index_of(&both).pins.len(), 2);

    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &WRONG_TABLE, "", &grants);
    assert_eq!(
        result.confirmed_bazel_uuids,
        BTreeSet::from([UUID.to_string()])
    );
    assert_eq!(
        result.refused_bazel_uuids,
        BTreeSet::from([OTHER.to_string()])
    );
    let only_dep = toy_lock(&[
        ("dep", "1.0.0", PATCHED),
        ("other", "2.0.0", OTHER_UPSTREAM),
    ]);
    let only_dep = only_dep.replace(&upstream_url("dep", "1.0.0"), PATCH_URL);
    assert_eq!(
        tree.text(LOCK),
        only_dep,
        "the lock of the first patch alone"
    );
    assert!(!tree.text(LOCK).contains(WRONG) && !tree.text(INDEX_PATH).contains(WRONG));
    let rows: Vec<&str> = bazel.index.pins.iter().map(|row| &*row.uuid).collect();
    assert_eq!(rows, [UUID]);
    assert_eq!(bazel.plans.len(), 1);
    assert!(bazel
        .edits
        .iter()
        .all(|edit| edit.key != Some(sha_key("other"))));
    let why = refusal_of(&bazel, OTHER);
    assert!(why.detail.contains("`other` 2.0.0"), "{}", why.detail);
    assert!(
        why.detail.contains("is not the digest of the patch"),
        "{}",
        why.detail
    );
    assert_eq!(codes(&result), [Code::RedirectRulesetUnsupported.as_str()]);
    // What was committed restores to the input.
    let undone = undo(&mut tree, &WRONG_TABLE, &[UUID, OTHER]);
    assert!(undone.restored(UUID) && !undone.restored(OTHER));
    assert_eq!(tree, before);
}

/// The toy gate for a works-after lane: the same plan, and one command
/// that the user runs afterwards and that `vex` waits for.
fn pending_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    let plan = match (TOY.gate)(cx, req) {
        GateOutcome::Proceed(plan) => plan,
        other => return other,
    };
    let run = RunRequired {
        kind: RunKind::Lockfile,
        command: "bazel mod deps --lockfile_mode=update".to_string(),
        argv: Vec::new(),
        env: Vec::new(),
        outputs: Vec::new(),
        interim: socket_patch_core::bazel::model::Interim::Passing,
        actor: Actor::User,
        platforms: vec!["linux_amd64".to_string()],
        gates_vex: true,
    };
    GateOutcome::ProceedAfter(plan, run)
}

/// The toy proof, and then what a works-after lane says until committed
/// evidence shows its command ran.
fn pending_attest(cx: &LaneCx<'_>, pin: &BazelRef) -> Result<(), VexWithhold> {
    (TOY.attest)(cx, pin)?;
    Err(VexWithhold {
        kind: WithholdKind::RunPending,
        token: None,
        detail: "the lock was not refreshed yet".to_string(),
    })
}

/// A works-after plan is confirmed while its one command has not run:
/// the pin is written as planned, the run says which command is left, and
/// `vex` waits. "Run pending" is no cover for a wrong digest, though: the
/// lane's proof answers it before any digest is compared, so the group
/// compares the digest itself, and a pin on another digest than the
/// grant's is refused with nothing left written.
#[test]
fn a_works_after_plan_is_confirmed_with_its_command_and_still_held_to_the_digest() {
    const PENDING: LaneOps = LaneOps {
        gate: pending_gate,
        attest: pending_attest,
        ..TOY
    };
    const PENDING_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &PENDING)]);
    let mut tree = toy_tree(INPUT);
    let (result, bazel) = scan(&mut tree, &PENDING_TABLE, "", &[grant()]);
    assert_eq!(
        result.confirmed_bazel_uuids,
        BTreeSet::from([UUID.to_string()])
    );
    assert_eq!(tree.text(LOCK), pinned(INPUT));
    assert_eq!(codes(&result), [Code::RedirectRunRequired.as_str()]);
    let detail = &result.warnings[0].detail;
    assert!(
        detail.contains("`bazel mod deps --lockfile_mode=update`")
            && detail.contains("linux_amd64")
            && detail.contains("`vex` makes no statement"),
        "{detail}"
    );
    let outcome = &bazel.decided[0].outcome;
    assert!(
        matches!(outcome, GateOutcome::ProceedAfter(..)),
        "the seam hands the gate's answer to `finish`: {outcome:?}"
    );
    // A proof that is withheld for any other reason is no confirmation.
    fn stale(cx: &LaneCx<'_>, pin: &BazelRef) -> Result<(), VexWithhold> {
        let pending = pending_attest(cx, pin).expect_err("pending");
        Err(VexWithhold {
            kind: WithholdKind::DerivedStale,
            ..pending
        })
    }
    const STALE: LaneOps = LaneOps {
        attest: stale,
        ..PENDING
    };
    // The same lane, pinning `other` on a digest that is not its grant's.
    const WRONG: LaneOps = LaneOps {
        rewrite_owned: wrong_rewrite,
        ..PENDING
    };
    const STALE_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &STALE)]);
    const WRONG_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &WRONG)]);
    let packages = [("other", "2.0.0", OTHER_UPSTREAM)];
    for (table, grant, before) in [
        (&STALE_TABLE, grant(), toy_tree(INPUT)),
        (&WRONG_TABLE, other_grant(), toy_tree(&toy_lock(&packages))),
    ] {
        let mut tree = before.clone();
        let (result, bazel) = scan(&mut tree, table, "", std::slice::from_ref(&grant));
        assert!(result.confirmed_bazel_uuids.is_empty(), "{result:?}");
        assert!(bazel.changes.is_empty() && bazel.plans.is_empty());
        assert_eq!(tree, before);
        assert_eq!(codes(&result), [Code::RedirectRulesetUnsupported.as_str()]);
    }
}

/// The toy restore, which also drops a row whose pin is gone (revision 4,
/// 2.8 item 4 d): the lock no longer holds the digest the row wrote, so
/// there is nothing to put back.
fn gone_restore(cx: &LaneCx<'_>, files: &mut Files, row: &IndexRow) -> RestoreOutcome {
    let held = files.get(&row.file).and_then(|text| parse(text));
    let pinned = row.edits.first().is_some_and(|edit| {
        let name = edit.key.split('/').nth(1).unwrap_or_default();
        held.as_ref()
            .and_then(|doc| doc["packages"][name]["sha256"].as_str())
            == Some(&*edit.new)
    });
    match pinned {
        true => (TOY.restore)(cx, files, row),
        false => RestoreOutcome::Restored,
    }
}

/// The sweep before planning (revision 4, 2.8 item 5): a recorded pin
/// that is gone from its lock. Where the patch is granted again, the run
/// pins it again and the row is the new pin's. Where it is not, a lane
/// that can tell the pin is gone has its row dropped, and one that cannot
/// keeps its row and the run says the pin was erased. Nothing is written
/// on a guess.
#[test]
fn the_sweep_drops_or_reports_a_recorded_pin_that_is_gone_from_its_lock() {
    let mut wired = toy_tree(INPUT);
    scan(&mut wired, &TABLE, "", &[grant()]);
    // The ruleset's own tooling regenerated the lock.
    let mut erased = wired.clone();
    erased.0.insert(LOCK.to_string(), INPUT.as_bytes().to_vec());
    assert_eq!(index_of(&erased).pins.len(), 1, "the row outlives the pin");

    // Granted again: pinned again, and nothing is said about the old pin.
    let mut tree = erased.clone();
    let (result, bazel) = scan(&mut tree, &TABLE, "", &[grant()]);
    assert_eq!(
        result.confirmed_bazel_uuids,
        BTreeSet::from([UUID.to_string()])
    );
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    assert_eq!(tree, wired, "the pin and its row are the first run's");
    let changed: Vec<&String> = bazel.changes.keys().collect();
    assert_eq!(changed, [LOCK], "the row already records this pin");

    // Not granted, and the lane cannot tell what to put back: the row is
    // kept and reported.
    let mut tree = erased.clone();
    let (result, bazel) = scan(&mut tree, &TABLE, "", &[]);
    assert_eq!(tree, erased);
    assert!(bazel.changes.is_empty() && bazel.decided.is_empty());
    assert_eq!(codes(&result), [Code::RedirectPinErased.as_str()]);
    let detail = &result.warnings[0].detail;
    assert!(
        detail.contains(&format!("`{LOCK}`")) && detail.contains(PURL),
        "{detail}"
    );

    // Not granted, and the lane knows the pin is gone: the row goes, and
    // with the last row the record.
    const OPS: LaneOps = LaneOps {
        restore: gone_restore,
        ..TOY
    };
    const GONE_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    let mut tree = erased.clone();
    let (result, bazel) = scan(&mut tree, &GONE_TABLE, "", &[]);
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let changed: Vec<(&String, bool)> = bazel
        .changes
        .iter()
        .map(|(p, b)| (p, b.is_some()))
        .collect();
    assert_eq!(changed, [(&INDEX_PATH.to_string(), false)]);
    assert_eq!(tree, toy_tree(INPUT));

    // A pin that is in place is no business of the sweep's, granted or not.
    let mut tree = wired.clone();
    let (result, bazel) = scan(&mut tree, &GONE_TABLE, "", &[]);
    assert!(result.warnings.is_empty() && bazel.changes.is_empty());
    assert_eq!(tree, wired);
}

/// A project below the Bazel root: the lock is the project's, the record
/// is the root's, and the change set names both by their path from the
/// root. The native result, which is relative to the project, holds
/// neither.
#[test]
fn a_project_below_the_root_is_written_by_paths_from_the_root() {
    let module = MODULE.replace("//:toy.lock.json", "//svc:toy.lock.json");
    let lock = "svc/toy.lock.json";
    let before = Tree::of(&[
        (".bazelversion", "9.3.2\n"),
        ("MODULE.bazel", &module),
        (lock, INPUT),
    ]);
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &TABLE, "svc", &[grant()]);
    assert!(result.files.is_empty());
    assert_eq!(
        result.confirmed_bazel_uuids,
        BTreeSet::from([UUID.to_string()])
    );
    let changed: Vec<&String> = bazel.changes.keys().collect();
    assert_eq!(changed, [INDEX_PATH, lock]);
    assert_eq!(tree.text(lock), pinned(INPUT));
    assert_eq!(bazel.index.pins[0].file, lock);
    assert!(bazel.edits.iter().all(|edit| edit.path == lock));

    let undone = undo(&mut tree, &TABLE, &[UUID]);
    assert!(undone.restored(UUID));
    assert_eq!(tree, before);
}

// A native-lock lane for the rules_js hub: the pin is the native pnpm
// rewriter's, on the lock the hub names, and the lane only proves it.

const JS_LANE: LaneId = LaneId("H-TOYJS");
const JS_SPEC: LaneSpec = LaneSpec {
    id: JS_LANE,
    classes: &[WriteClass::NativeLock],
    ..TOY.lanes[0]
};
const JS_MODULE: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
    npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
    npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
    use_repo(npm, \"npm\")\n";

/// The `packages:` entries of a pnpm 9 lock: name, version, integrity and
/// the tarball URL where one is pinned.
fn pnpm_packages(text: &str) -> Vec<(String, String, String, Option<String>)> {
    let (mut out, mut key, mut inside) = (Vec::new(), None, false);
    for line in text.lines() {
        if !line.starts_with(' ') {
            inside = line.trim_end() == "packages:";
            continue;
        }
        let entry = line
            .strip_prefix("  ")
            .filter(|rest| !rest.starts_with(' '));
        if let Some(entry) = entry.filter(|_| inside) {
            let named = entry.trim_end().trim_end_matches(':').rsplit_once('@');
            key = named.map(|(name, version)| (name.to_string(), version.to_string()));
            continue;
        }
        let resolution = line.trim().strip_prefix("resolution: {");
        if let (true, Some((name, version)), Some(body)) = (inside, &key, resolution) {
            let body = body.trim_end_matches('}');
            let field = |name: &str| {
                let found = body.split(", ").find_map(|part| part.strip_prefix(name));
                found.map(str::to_string)
            };
            if let Some(integrity) = field("integrity: ") {
                out.push((name.clone(), version.clone(), integrity, field("tarball: ")));
            }
        }
    }
    out
}

fn js_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    let Some(path) = lock_of(cx) else {
        return GateOutcome::NotBazel;
    };
    let text = cx.files.read(&path);
    let locked = pnpm_packages(text.as_str().unwrap_or_default());
    if !locked
        .iter()
        .any(|(name, version, ..)| name == req.name && version == req.version)
    {
        return GateOutcome::NotBazel;
    }
    GateOutcome::Proceed(Plan {
        uuid: req.uuid.to_string(),
        lane: JS_LANE,
        writes: vec![PlannedWrite::NativeLock { path }],
        repositories: Vec::new(),
        artifacts: Vec::new(),
        advisories: Vec::new(),
        attest: AttestBasis::LockUrl,
        anchor: Anchor::Digest,
    })
}

fn js_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
    let entry = |(name, version, integrity, tarball): (String, String, String, Option<String>)| {
        LockfileEntry {
            ecosystem: "npm",
            purl: format!("pkg:npm/{name}@{version}"),
            name,
            version,
            resolved: tarball,
            integrity: LockIntegrity::Sri(integrity),
            source_kind: SourceKind::Unspecified,
            pnpm_env: false,
        }
    };
    let text = read(&lock_of(cx)?)?;
    Some(pnpm_packages(&text).into_iter().map(entry).collect())
}

fn js_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
    let file = lock_of(cx)?;
    let pin = |entry: LockfileEntry| {
        Some(BazelRef {
            lane: JS_LANE,
            uuid: hosted_patch_uuid(entry.resolved.as_deref()?, &[])?,
            purl: entry.purl,
            file: file.clone(),
            basis: AttestBasis::LockUrl,
        })
    };
    Some(
        js_inventory(cx, read)?
            .into_iter()
            .filter_map(pin)
            .collect(),
    )
}

/// The pin is still what the lock holds, and nothing bypasses the hub.
fn js_attest(cx: &LaneCx<'_>, pin: &BazelRef) -> Result<(), VexWithhold> {
    let withhold = |kind, detail: &str| VexWithhold {
        kind,
        token: None,
        detail: detail.to_string(),
    };
    let read = |rel: &str| cx.files.read(rel).as_str().map(str::to_string);
    let found = js_discover(cx, &read).unwrap_or_default();
    if !found.contains(pin) {
        return Err(withhold(
            WithholdKind::NotConsumed,
            "the lock holds no such pin",
        ));
    }
    let request = PatchRequest {
        ecosystem: Ecosystem::Npm,
        name: "",
        version: "",
        uuid: &pin.uuid,
        project_rel: "",
    };
    gate::no_bypass(cx.ws, cx.index, cx.hub, &request, JS_LANE, &[])
        .map_err(|refusal| withhold(WithholdKind::PinBypassed, &refusal.detail))
}

const JS_OPS: LaneOps = LaneOps {
    lanes: &[JS_SPEC],
    gate: js_gate,
    discover: js_discover,
    attest: js_attest,
    inventory: js_inventory,
    ..LaneOps::disabled(&[])
};
const JS_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJs, &JS_OPS)]);

fn redirect_fixture(case: &str, file: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redirect");
    let path = case.split('/').chain(file.split('/'));
    let path = path.fold(root, |at, name| at.join(name));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The native pure rewriter as a library, on the file set of the plan and
/// on nothing else: the pnpm lock the hub names is pinned exactly as the
/// native rewriter pins it (the shared redirect golden), while the
/// `package-lock.json` beside it, which no hub reads and which the native
/// rewrite of this project pins too, is left as found. The run says so
/// once.
#[test]
fn the_native_rewriter_pins_the_hub_lock_and_leaves_the_sibling_lock_as_found() {
    let pnpm = redirect_fixture("npm/pnpm/basic", "input/pnpm-lock.yaml");
    let npm = redirect_fixture("npm/package-lock-v3/basic", "input/package-lock.json");
    let expected = redirect_fixture("npm/pnpm/basic", "expected/pnpm-lock.yaml");
    let grants = redirect_fixture("npm/pnpm/basic", "overrides.json");
    let grants: Vec<DepOverride> = serde_json::from_str(&grants).expect("the grants");
    let uuids: BTreeSet<String> = grants.iter().map(|d| d.patch_uuid.clone()).collect();

    // Release 5.1, and any project Bazel does not build: both locks.
    let project: BTreeMap<String, String> = BTreeMap::from([
        ("pnpm-lock.yaml".to_string(), pnpm.clone()),
        ("package-lock.json".to_string(), npm.clone()),
    ]);
    let native = rewrite_registry_redirect(&project, &grants);
    let written: Vec<&String> = native.files.keys().collect();
    assert_eq!(written, ["package-lock.json", "pnpm-lock.yaml"]);

    let before = Tree::of(&[
        (".bazelversion", "9.3.2\n"),
        ("MODULE.bazel", JS_MODULE),
        ("pnpm-lock.yaml", &pnpm),
        ("package-lock.json", &npm),
    ]);
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &JS_TABLE, "", &grants);
    assert_eq!(result.confirmed_bazel_uuids, uuids);
    // `rewrittenFiles`: the native result holds no npm file at all.
    assert!(result.files.is_empty(), "{:?}", result.files.keys());
    let changed: Vec<&String> = bazel.changes.keys().collect();
    assert_eq!(
        changed,
        ["pnpm-lock.yaml"],
        "no record: a native lock has no row"
    );
    assert_eq!(
        tree.text("pnpm-lock.yaml"),
        expected,
        "the native golden, byte for byte"
    );
    assert_eq!(tree.text("package-lock.json"), npm);
    assert!(!tree.0.contains_key(".npmrc") && !tree.0.contains_key(INDEX_PATH));
    assert_eq!(codes(&result), [Code::RedirectSideFileSkipped.as_str()]);
    let detail = &result.warnings[0].detail;
    assert!(
        detail.contains("`package-lock.json` was left as found")
            && detail.contains("`pnpm-lock.yaml`"),
        "{detail}"
    );

    // A second run finds the pin in place and writes nothing.
    let mut again = tree.clone();
    let (result, bazel) = scan(&mut again, &JS_TABLE, "", &grants);
    assert_eq!(result.confirmed_bazel_uuids, uuids);
    assert!(bazel.changes.is_empty());
    assert_eq!(again, tree);

    // A grant whose digest the native rewriter cannot pin leaves no pin:
    // refused, and the lock is as it was. The run says what the native
    // rewriter said, as it does without Bazel, and then the refusal, which
    // carries that reason and names the lock. The lane is enabled and at
    // no fault, so nothing says it is to be enabled.
    let mut bare = grants.clone();
    bare[0].integrity = Integrity::default();
    // What the native rewriter says about the one file it is handed.
    let hub_lock = BTreeMap::from([("pnpm-lock.yaml".to_string(), pnpm.clone())]);
    let native = rewrite_registry_redirect(&hub_lock, &bare);
    let [declined] = &native.warnings[..] else {
        panic!("one native reason: {:?}", native.warnings);
    };
    assert_eq!(declined.code, "redirect_pnpm_missing_sha512");
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &JS_TABLE, "", &bare);
    assert_eq!(result.refused_bazel_uuids, uuids);
    assert!(bazel.changes.is_empty());
    assert_eq!(tree, before);
    let why = refusal_of(&bazel, &bare[0].patch_uuid);
    assert_eq!(why.code, Code::RedirectConsumerUndetermined);
    assert_eq!(why.token, "not_resolved_by_hub");
    let Lift::UserEdit { file, .. } = &why.lift else {
        panic!("the lane is enabled: {:?}", why.lift);
    };
    assert_eq!(file, "pnpm-lock.yaml");
    assert!(
        why.detail.contains(&declined.detail) && why.detail.contains("`pnpm-lock.yaml`"),
        "{}",
        why.detail
    );
    assert!(!why.detail.contains("not enabled"), "{}", why.detail);
    assert!(
        why.detail.ends_with("; nothing was written"),
        "{}",
        why.detail
    );
    assert_eq!(
        codes(&result)[..2],
        [
            "redirect_pnpm_missing_sha512",
            Code::RedirectConsumerUndetermined.as_str()
        ],
        "the native reason first: {:?}",
        result.warnings
    );
    assert_eq!(result.warnings[0], *declined);
}

/// A lane may author the files of its plan and no other: one that writes
/// a file beside them, or the record itself, is refused, and what it
/// staged is dropped with the rest of its patch.
#[test]
fn a_lane_that_writes_off_its_plan_is_refused_whole() {
    fn stray(cx: &LaneCx<'_>, files: &mut Files, pins: &[PinSource], result: &mut RewriteResult) {
        (TOY.rewrite_owned)(cx, files, pins, result);
        files.insert("BUILD.bazel".to_string(), "# not the lane's\n".to_string());
    }
    fn record(cx: &LaneCx<'_>, files: &mut Files, pins: &[PinSource], result: &mut RewriteResult) {
        (TOY.rewrite_owned)(cx, files, pins, result);
        files.insert(INDEX_PATH.to_string(), "{}\n".to_string());
    }
    /// The pin, and then the lock is gone from the candidate texts: a
    /// lane removes no file.
    fn lost(cx: &LaneCx<'_>, files: &mut Files, pins: &[PinSource], result: &mut RewriteResult) {
        (TOY.rewrite_owned)(cx, files, pins, result);
        files.remove(LOCK);
    }
    /// The pin, and a value of a file the plan does not name.
    fn unplanned(
        cx: &LaneCx<'_>,
        files: &mut Files,
        pins: &[PinSource],
        result: &mut RewriteResult,
    ) {
        (TOY.rewrite_owned)(cx, files, pins, result);
        let other = edit("other.lock.json", "packages/dep/sha256", UPSTREAM, PATCHED);
        result.edits.push(other);
    }
    const STRAY: LaneOps = LaneOps {
        rewrite_owned: stray,
        ..TOY
    };
    const RECORD: LaneOps = LaneOps {
        rewrite_owned: record,
        ..TOY
    };
    const LOST: LaneOps = LaneOps {
        rewrite_owned: lost,
        ..TOY
    };
    const UNPLANNED: LaneOps = LaneOps {
        rewrite_owned: unplanned,
        ..TOY
    };
    const BESIDE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &STRAY)]);
    const OWNED: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &RECORD)]);
    const REMOVED: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &LOST)]);
    const OFF_PLAN: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &UNPLANNED)]);
    let changed = "which its plan does not let it write";
    for (table, path, said) in [
        (&BESIDE, "BUILD.bazel", changed),
        (&OWNED, INDEX_PATH, changed),
        (&REMOVED, LOCK, changed),
        (&OFF_PLAN, "other.lock.json", "which its plan does not name"),
    ] {
        let before = toy_tree(INPUT);
        let mut tree = before.clone();
        let (result, bazel) = scan(&mut tree, table, "", &[grant()]);
        assert_eq!(tree, before, "{path}");
        assert!(bazel.changes.is_empty() && bazel.index.is_empty(), "{path}");
        assert_eq!(
            result.refused_bazel_uuids,
            BTreeSet::from([UUID.to_string()])
        );
        let why = refusal_of(&bazel, UUID);
        assert_eq!(why.code, Code::RedirectRulesetUnsupported, "{path}");
        assert!(
            why.detail.contains(&format!("`{path}`, {said}")),
            "{}",
            why.detail
        );
    }
}

/// The restore of the group: a patch is undone whole or not at all. One
/// whose lock no longer holds what was written is left exactly as it is,
/// with the file in its way named, and the patch beside it is undone.
#[test]
fn the_restore_undoes_each_patch_whole_and_names_the_file_in_the_way() {
    let packages = [
        ("dep", "1.0.0", UPSTREAM),
        ("other", "2.0.0", OTHER_UPSTREAM),
    ];
    let before = toy_tree(&toy_lock(&packages));
    let mut wired = before.clone();
    // One patch at a time, so that each row's derived value stands alone.
    scan(&mut wired, &TABLE, "", &[grant()]);
    let first = wired.clone();
    scan(&mut wired, &TABLE, "", &[other_grant()]);
    assert_eq!(index_of(&wired).pins.len(), 2);

    // The later pin goes first: its derived value is the lock's.
    let mut tree = wired.clone();
    let undone = undo(
        &mut tree,
        &TABLE,
        &[OTHER, "5e7d1a2b-3c4d-4e5f-8a6b-7c8d9e0f1a2b"],
    );
    assert!(undone.restored(OTHER));
    assert_eq!(undone.recorded(OTHER), [LOCK]);
    assert_eq!(undone.patches[1].state, Undone::NotRecorded);
    assert_eq!(tree, first);

    // The earlier pin cannot go while the later one stands on it: the
    // derived value is no longer the one its row wrote. Nothing changes.
    let mut tree = wired.clone();
    let undone = undo(&mut tree, &TABLE, &[UUID]);
    assert!(undone.changes.is_empty() && !undone.restored(UUID));
    let (files, why) = undone.incomplete(UUID).expect("incomplete");
    assert_eq!(files, [LOCK]);
    assert!(why.contains("`pinsHash`"), "{why}");
    assert_eq!(tree, wired);

    // Both, in an order that works: byte for byte the input.
    let mut tree = wired.clone();
    let undone = undo(&mut tree, &TABLE, &[OTHER, UUID]);
    assert!(undone.restored(OTHER) && undone.restored(UUID));
    assert_eq!(tree, before);
}

/// The restore driver under a Bazel root. A file the index records for a
/// pin is the Bazel side's whatever it is called: here the hub's lock has
/// the name of a requirements file, which the native restorer would open
/// by that name and refuse. The pin is restored by its row's lane, the
/// driver writes nothing (the commit at the root lands the change set),
/// and a pin that drifted is refused whole with its file named.
#[tokio::test]
async fn the_restore_driver_hands_recorded_files_to_the_lane_and_writes_nothing() {
    let lock = "pins.txt";
    let module = MODULE.replace("//:toy.lock.json", "//:pins.txt");
    let before = Tree::of(&[
        (".bazelversion", "9.3.2\n"),
        ("MODULE.bazel", &module),
        (lock, INPUT),
    ]);
    let mut wired = before.clone();
    scan(&mut wired, &TABLE, "", &[grant()]);
    let pin = HostedPin {
        purl: PURL.to_string(),
        uuid: UUID.to_string(),
        files: vec![lock.to_string()],
    };
    let opts = RestoreOptions {
        offline: true,
        ..RestoreOptions::default()
    };
    let project = tempfile::tempdir().expect("a temp dir");
    let listed = || {
        std::fs::read_dir(project.path())
            .expect("the project")
            .count()
    };

    // Without the Bazel root the file is a requirements file nobody can
    // read, and the pin is refused.
    let native = restore_upstream(project.path(), std::slice::from_ref(&pin), &opts).await;
    assert!(
        matches!(native.pins[0].status, PinStatus::Refused(_)),
        "{native:?}"
    );
    assert!(native.bazel.is_none() && !native.commit_pending());

    let (ws, index) = (workspace(&wired, ""), index_of(&wired));
    let root = Root {
        ws: &ws,
        files: &wired,
        index: &index,
        lanes: &TABLE,
    };
    let pins = std::slice::from_ref(&pin);
    let outcome = restore_upstream_under_bazel(project.path(), pins, &opts, &root).await;
    assert_eq!(outcome.pins[0].status, PinStatus::Restored, "{outcome:?}");
    assert!(outcome.commit_pending() && outcome.flush_error.is_none());
    assert_eq!(outcome.reverted_files, [INDEX_PATH, lock]);
    assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    assert!(outcome.staged_text.is_empty() && outcome.staged_bytes.is_empty());
    assert_eq!(listed(), 0, "the driver wrote nothing");
    let mut tree = wired.clone();
    tree.apply(&outcome.bazel.expect("the Bazel side").changes);
    assert_eq!(
        tree, before,
        "the commit of the change set restores the input"
    );

    // The lock no longer holds what the row wrote: refused whole.
    let mut drifted = wired.clone();
    drifted
        .0
        .insert(lock.to_string(), INPUT.as_bytes().to_vec());
    let (ws, index) = (workspace(&drifted, ""), index_of(&drifted));
    let root = Root {
        ws: &ws,
        files: &drifted,
        index: &index,
        lanes: &TABLE,
    };
    let outcome = restore_upstream_under_bazel(project.path(), pins, &opts, &root).await;
    let PinStatus::Refused(why) = &outcome.pins[0].status else {
        panic!("a drifted pin was restored: {outcome:?}");
    };
    assert!(why.contains("git checkout -- pins.txt"), "{why}");
    assert!(!outcome.commit_pending() && outcome.reverted_files.is_empty());
    let [(code, detail)] = &outcome.warnings[..] else {
        panic!("one advisory: {:?}", outcome.warnings);
    };
    assert_eq!(*code, Code::RedirectRevertIncomplete.as_str());
    assert!(
        detail.contains("`pins.txt`") && detail.contains(PURL),
        "{detail}"
    );
    assert_eq!(listed(), 0);
}

// ── One root, several projects, several locks ────────────────────────

/// Two projects of one root, each with a hub of its own over its own toy
/// lock.
const TWO_PROJECTS: &str = "module(name = \"toy_ws\")\n\
    bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
    maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
    maven.install(name = \"maven_a\", artifacts = [\"toy:dep:1.0.0\"], \
    lock_file = \"//a:toy.lock.json\")\n\
    maven.install(name = \"maven_b\", artifacts = [\"toy:dep:1.0.0\"], \
    lock_file = \"//b:toy.lock.json\")\n\
    use_repo(maven, \"maven_a\", \"maven_b\")\n";

/// One project with two hubs, each over a toy lock of its own.
const TWO_LOCKS: &str = "module(name = \"toy_ws\")\n\
    bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
    maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
    maven.install(name = \"maven_a\", artifacts = [\"toy:dep:1.0.0\"], \
    lock_file = \"//:a.lock.json\")\n\
    maven.install(name = \"maven_b\", artifacts = [\"toy:dep:1.0.0\"], \
    lock_file = \"//:b.lock.json\")\n\
    use_repo(maven, \"maven_a\", \"maven_b\")\n";

fn two(module: &str, a: &str, b: &str) -> Tree {
    Tree::of(&[
        (".bazelversion", "9.3.2\n"),
        ("MODULE.bazel", module),
        (a, INPUT),
        (b, INPUT),
    ])
}

/// The toy lane with a restore that drops a row whose pin is gone.
const DROPS: LaneOps = LaneOps {
    restore: gone_restore,
    ..TOY
};
const DROPS_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &DROPS)]);

fn row_of(tree: &Tree, file: &str) -> Option<IndexRow> {
    index_of(tree).pins.into_iter().find(|row| row.file == file)
}

fn confirmed(result: &RewriteResult) -> bool {
    result.confirmed_bazel_uuids == BTreeSet::from([UUID.to_string()])
        && result.refused_bazel_uuids.is_empty()
}

fn refused(result: &RewriteResult) -> bool {
    result.refused_bazel_uuids == BTreeSet::from([UUID.to_string()])
        && result.confirmed_bazel_uuids.is_empty()
}

/// The undo of a patch takes every row of it under the root, so the sweep
/// of one project undoes a patch only when every row of it is a stale row
/// of that project. Two projects hold the same patch; the lock of `a` is
/// regenerated. A scan of `a` never touches the lock or the row of `b`,
/// whose pin is live: not granted, it writes nothing and says which file
/// lost its pin; granted, it pins `a` again and that is all it changes.
#[test]
fn the_sweep_of_one_project_never_takes_a_live_pin_out_of_another() {
    let (a, b) = ("a/toy.lock.json", "b/toy.lock.json");
    let mut wired = two(TWO_PROJECTS, a, b);
    for project in ["a", "b"] {
        let (result, _) = scan(&mut wired, &DROPS_TABLE, project, &[grant()]);
        assert!(confirmed(&result), "{project}: {result:?}");
    }
    assert_eq!(wired.text(a), pinned(INPUT));
    assert_eq!(wired.text(b), pinned(INPUT));
    assert_eq!(index_of(&wired).pins.len(), 2, "one row per lock");
    // The ruleset's own tooling regenerated the lock of `a`.
    let mut erased = wired.clone();
    erased.0.insert(a.to_string(), INPUT.as_bytes().to_vec());

    let mut tree = erased.clone();
    let (result, bazel) = scan(&mut tree, &DROPS_TABLE, "a", &[]);
    assert!(bazel.changes.is_empty(), "{:?}", bazel.changes.keys());
    assert_eq!(
        tree, erased,
        "nothing is written for a patch `b` still pins"
    );
    assert_eq!(codes(&result), [Code::RedirectPinErased.as_str()]);
    let detail = &result.warnings[0].detail;
    assert!(
        detail.contains(&format!("`{a}`")) && !detail.contains(b),
        "{detail}"
    );

    let mut tree = erased.clone();
    let (result, bazel) = scan(&mut tree, &DROPS_TABLE, "a", &[grant()]);
    assert!(confirmed(&result), "{result:?}");
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let changed: Vec<&String> = bazel.changes.keys().collect();
    assert_eq!(changed, [a], "the lock of `a`, and nothing of `b`");
    assert_eq!(tree.text(b), wired.text(b));
    assert_eq!(row_of(&tree, b), row_of(&wired, b));
    assert_eq!(tree, wired, "the pin and its row are the first run's");

    // A scan of `b` does not judge the row of `a` at all.
    let mut tree = erased.clone();
    let (result, bazel) = scan(&mut tree, &DROPS_TABLE, "b", &[]);
    assert!(result.warnings.is_empty() && bazel.changes.is_empty());
    assert_eq!(tree, erased);
}

/// The same within one project: two hubs, two locks, one patch, and one
/// of the locks is regenerated. The lock that still holds its pin keeps
/// it and its row, granted or not.
#[test]
fn the_sweep_keeps_every_row_of_a_patch_while_one_of_its_locks_holds_the_pin() {
    let (a, b) = ("a.lock.json", "b.lock.json");
    let before = two(TWO_LOCKS, a, b);
    let mut wired = before.clone();
    let (result, bazel) = scan(&mut wired, &DROPS_TABLE, "", &[grant()]);
    assert!(confirmed(&result), "{result:?}");
    let changed: Vec<&String> = bazel.changes.keys().collect();
    assert_eq!(changed, [INDEX_PATH, a, b], "every lock that resolves it");
    assert_eq!(index_of(&wired).pins.len(), 2, "one patch, a row per lock");
    let mut erased = wired.clone();
    erased.0.insert(a.to_string(), INPUT.as_bytes().to_vec());

    let mut tree = erased.clone();
    let (result, bazel) = scan(&mut tree, &DROPS_TABLE, "", &[]);
    assert!(bazel.changes.is_empty(), "{:?}", bazel.changes.keys());
    assert_eq!(tree, erased);
    assert_eq!(codes(&result), [Code::RedirectPinErased.as_str()]);
    let detail = &result.warnings[0].detail;
    assert!(
        detail.contains(&format!("`{a}`")) && !detail.contains(b),
        "{detail}"
    );

    let mut tree = erased.clone();
    let (result, bazel) = scan(&mut tree, &DROPS_TABLE, "", &[grant()]);
    assert!(confirmed(&result), "{result:?}");
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let changed: Vec<&String> = bazel.changes.keys().collect();
    assert_eq!(changed, [a]);
    assert_eq!(tree, wired);

    // With every lock regenerated the patch is gone: its rows go, and
    // with the last row the record.
    let mut tree = before.clone();
    tree.0
        .insert(INDEX_PATH.to_string(), wired.0[INDEX_PATH].clone());
    let (result, bazel) = scan(&mut tree, &DROPS_TABLE, "", &[]);
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    let changed: Vec<(&String, bool)> = bazel
        .changes
        .iter()
        .map(|(path, bytes)| (path, bytes.is_some()))
        .collect();
    assert_eq!(changed, [(&INDEX_PATH.to_string(), false)]);
    assert_eq!(tree, before);

    // The undo of the patch takes both rows, whole.
    let mut tree = wired.clone();
    let undone = undo(&mut tree, &DROPS_TABLE, &[UUID]);
    assert!(undone.restored(UUID));
    assert_eq!(undone.recorded(UUID), [a, b]);
    assert_eq!(tree, before);
}

/// The toy gate for the first lock of [`TWO_LOCKS`], and "my lock does
/// not resolve the release" for the second, which does resolve it.
fn first_lock_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    match lock_of(cx).as_deref() {
        Some("b.lock.json") => GateOutcome::NotBazel,
        _ => (TOY.gate)(cx, req),
    }
}

/// Every lock of a governing hub that resolves the release holds the pin,
/// or the patch is not confirmed: one lock left on the upstream entry is
/// a build of the upstream package. The lane here plans and pins the
/// first lock alone, and the group refuses the patch whole.
#[test]
fn a_lock_left_on_the_upstream_entry_refuses_the_patch_whole() {
    const OPS: LaneOps = LaneOps {
        gate: first_lock_gate,
        ..TOY
    };
    const FIRST: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    let before = two(TWO_LOCKS, "a.lock.json", "b.lock.json");
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &FIRST, "", &[grant()]);
    assert!(refused(&result), "{result:?}");
    assert!(bazel.changes.is_empty() && bazel.plans.is_empty());
    assert_eq!(tree, before, "both locks byte for byte");
    let why = refusal_of(&bazel, UUID);
    assert!(
        why.detail
            .contains("`maven_b` resolves the release and holds no pin"),
        "{}",
        why.detail
    );
    // The gate had planned the first lock.
    let decided = &bazel.decided[0].outcome;
    assert!(matches!(decided, GateOutcome::Proceed(_)), "{decided:?}");
}

fn second_lock_blind(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
    match lock_of(cx).as_deref() {
        Some("b.lock.json") => None,
        _ => (TOY.discover)(cx, read),
    }
}

fn blind(_: &LaneCx<'_>, _: TextRead<'_>) -> Option<Vec<BazelRef>> {
    None
}

/// "Cannot tell" is never "pinned" and never "gone". A hub whose lane
/// cannot tell its pins confirms nothing, though the other hub's pin is
/// found; and a recorded pin of such a hub is left alone by the sweep,
/// whose lane would drop the row of a pin that is gone.
#[test]
fn a_hub_that_cannot_tell_its_pins_confirms_nothing_and_is_not_swept() {
    const HALF: LaneOps = LaneOps {
        discover: second_lock_blind,
        ..TOY
    };
    const HALF_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &HALF)]);
    let before = two(TWO_LOCKS, "a.lock.json", "b.lock.json");
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &HALF_TABLE, "", &[grant()]);
    assert!(refused(&result), "{result:?}");
    assert!(bazel.changes.is_empty());
    assert_eq!(tree, before);
    let why = refusal_of(&bazel, UUID);
    assert!(
        why.detail
            .contains("the pins of the hub `maven_b` are not known"),
        "{}",
        why.detail
    );

    const BLIND: LaneOps = LaneOps {
        discover: blind,
        ..DROPS
    };
    const BLIND_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &BLIND)]);
    let mut wired = toy_tree(INPUT);
    scan(&mut wired, &TABLE, "", &[grant()]);
    let mut erased = wired.clone();
    erased.0.insert(LOCK.to_string(), INPUT.as_bytes().to_vec());
    let mut tree = erased.clone();
    let (result, bazel) = scan(&mut tree, &BLIND_TABLE, "", &[]);
    assert!(bazel.changes.is_empty(), "{:?}", bazel.changes.keys());
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    assert_eq!(tree, erased, "the row stays the record");
    // The lane that can tell drops it: the blind one is what kept it.
    let mut tree = erased.clone();
    let (_, bazel) = scan(&mut tree, &DROPS_TABLE, "", &[]);
    assert!(bazel.changes.contains_key(INDEX_PATH));
}

/// The pending gate, with a command `vex` does not wait for.
fn unwaited_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    match pending_gate(cx, req) {
        GateOutcome::ProceedAfter(plan, run) => {
            let run = RunRequired {
                gates_vex: false,
                ..run
            };
            GateOutcome::ProceedAfter(plan, run)
        }
        other => other,
    }
}

/// "Run pending" confirms a pin only where the plan itself leaves a
/// command that `vex` waits for. Under a plain plan, and under one whose
/// command gates no statement, a proof that says "run pending" is a proof
/// that is withheld: refused, with nothing left written.
#[test]
fn run_pending_confirms_only_a_plan_whose_command_vex_waits_for() {
    const PLAIN: LaneOps = LaneOps {
        attest: pending_attest,
        ..TOY
    };
    const UNWAITED: LaneOps = LaneOps {
        gate: unwaited_gate,
        attest: pending_attest,
        ..TOY
    };
    const PLAIN_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &PLAIN)]);
    const UNWAITED_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &UNWAITED)]);
    for (table, after) in [(&PLAIN_TABLE, false), (&UNWAITED_TABLE, true)] {
        let before = toy_tree(INPUT);
        let mut tree = before.clone();
        let (result, bazel) = scan(&mut tree, table, "", &[grant()]);
        let planned = &bazel.decided[0].outcome;
        assert_eq!(
            matches!(planned, GateOutcome::ProceedAfter(..)),
            after,
            "{planned:?}"
        );
        assert!(refused(&result), "after={after}: {result:?}");
        assert!(bazel.changes.is_empty() && bazel.plans.is_empty());
        assert_eq!(tree, before, "after={after}");
        let why = refusal_of(&bazel, UUID);
        assert!(
            why.detail.contains("the lock was not refreshed yet"),
            "{}",
            why.detail
        );
    }
}

// ── A patch is judged by its own pins ────────────────────────────────

/// The toy writer for every lock but the one of project `a`, where it
/// reports the values of a pin and writes none.
fn hollow_rewrite(
    cx: &LaneCx<'_>,
    files: &mut Files,
    pins: &[PinSource],
    result: &mut RewriteResult,
) {
    let lock = lock_of(cx).unwrap_or_default();
    if !lock.starts_with("a/") {
        return (TOY.rewrite_owned)(cx, files, pins, result);
    }
    let digest = edit(&lock, &sha_key("dep"), UPSTREAM, PATCHED);
    result.edits.push(digest);
    result
        .edits
        .push(edit(&lock, "pinsHash", "-1084610730", "7"));
}

/// The pins of a patch are the ones in the locks of the hubs that govern
/// this project. A pin of the same patch in another project neither
/// withholds the confirmation here (its derived value went stale) nor
/// stands in for a pin this project does not have.
#[test]
fn a_patch_is_judged_by_the_pins_of_its_own_project() {
    let (a, b) = ("a/toy.lock.json", "b/toy.lock.json");
    let before = two(TWO_PROJECTS, a, b);
    let mut wired = before.clone();
    let (result, _) = scan(&mut wired, &TABLE, "b", &[grant()]);
    assert!(confirmed(&result), "{result:?}");

    // The lock of `b` no longer loads. That is `b`'s to say.
    let hash = pins_hash(&parse(&pinned(INPUT)).unwrap()).unwrap();
    let stale = wired
        .text(b)
        .replace(&format!("\"pinsHash\": {hash}"), "\"pinsHash\": 7");
    assert_ne!(stale, wired.text(b));
    let mut tree = wired.clone();
    tree.0.insert(b.to_string(), stale.clone().into_bytes());
    let (result, bazel) = scan(&mut tree, &TABLE, "a", &[grant()]);
    assert!(confirmed(&result), "{result:?}");
    assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    assert_eq!(tree.text(a), pinned(INPUT));
    assert_eq!(tree.text(b), stale, "the lock of `b` is not this run's");
    let changed: Vec<&String> = bazel.changes.keys().collect();
    assert_eq!(changed, [INDEX_PATH, a]);

    // `b` holds the pin and the write for `a` leaves none: the pin of `b`
    // is no pin of `a`.
    const OPS: LaneOps = LaneOps {
        rewrite_owned: hollow_rewrite,
        ..TOY
    };
    const HOLLOW: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    let mut tree = wired.clone();
    let (result, bazel) = scan(&mut tree, &HOLLOW, "a", &[grant()]);
    assert!(refused(&result), "{result:?}");
    assert!(bazel.changes.is_empty(), "{:?}", bazel.changes.keys());
    assert_eq!(tree, wired);
    let why = refusal_of(&bazel, UUID);
    assert!(
        why.detail.contains("the lane finds no pin of the release"),
        "{}",
        why.detail
    );
}

fn other_entry_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    let other = PatchRequest {
        name: "other",
        version: "2.0.0",
        ..*req
    };
    (TOY.gate)(cx, &other)
}

fn other_entry_rewrite(
    cx: &LaneCx<'_>,
    files: &mut Files,
    pins: &[PinSource],
    result: &mut RewriteResult,
) {
    let moved = |pin: &PinSource| match pin {
        PinSource::Hosted(dep) => {
            let mut dep = dep.clone();
            dep.name = "other".to_string();
            dep.version = "2.0.0".to_string();
            PinSource::Hosted(dep)
        }
        pin => pin.clone(),
    };
    let pins: Vec<PinSource> = pins.iter().map(moved).collect();
    (TOY.rewrite_owned)(cx, files, &pins, result);
}

/// What the lane pinned, said truthfully: the entry of `other`.
fn other_entry_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
    let mut pins = (TOY.discover)(cx, read)?;
    for pin in &mut pins {
        pin.purl = "pkg:maven/other@2.0.0".to_string();
    }
    Some(pins)
}

/// A pin is a pin of the patch only on the release the patch is of. A
/// lane that pins another entry with the grant, and says so, proves
/// nothing about the entry the build resolves the release from, which is
/// still on its upstream digest: refused, and the root is byte for byte.
#[test]
fn a_pin_on_another_release_does_not_confirm_the_patch() {
    const OPS: LaneOps = LaneOps {
        gate: other_entry_gate,
        rewrite_owned: other_entry_rewrite,
        discover: other_entry_discover,
        ..TOY
    };
    const OTHER_ENTRY: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    let packages = [
        ("dep", "1.0.0", UPSTREAM),
        ("other", "2.0.0", OTHER_UPSTREAM),
    ];
    let before = toy_tree(&toy_lock(&packages));
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &OTHER_ENTRY, "", &[grant()]);
    assert!(refused(&result), "{result:?}");
    assert!(bazel.changes.is_empty() && bazel.index.is_empty());
    assert_eq!(tree, before);
    let why = refusal_of(&bazel, UUID);
    assert!(
        why.detail.contains("the lane finds no pin of the release"),
        "{}",
        why.detail
    );
}

// ── A patch granted as several artifacts ─────────────────────────────

const SDIST: &str = "4444444444444444444444444444444444444444444444444444444444444444";

fn sdist_grant() -> DepOverride {
    DepOverride {
        artifact_url: "https://patch.socket.dev/toy/tok_fixture_4f1c/dep-1.0.0.tar.gz".to_string(),
        integrity: Integrity {
            sha256: Some(SDIST.to_string()),
            ..Integrity::default()
        },
        ..grant()
    }
}

/// The toy listing, with the pinned entry listing `more` beside the
/// digest it holds, as a uv or poetry entry lists a wheel's digest and an
/// sdist's.
fn listing(cx: &LaneCx<'_>, read: TextRead<'_>, more: &str) -> Option<Vec<LockfileEntry>> {
    let mut entries = (TOY.inventory)(cx, read)?;
    for entry in &mut entries {
        if entry.integrity == LockIntegrity::Sha256Hex(PATCHED.to_string()) {
            let both = vec![PATCHED.to_string(), more.to_string()];
            entry.integrity = LockIntegrity::Sha256AnyOf(both);
        }
    }
    Some(entries)
}

fn both_artifacts(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
    listing(cx, read, SDIST)
}

fn a_foreign_digest(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
    listing(cx, read, WRONG)
}

fn first_artifact(
    cx: &LaneCx<'_>,
    files: &mut Files,
    pins: &[PinSource],
    result: &mut RewriteResult,
) {
    (TOY.rewrite_owned)(cx, files, &pins[..1], result);
}

/// One patch, granted as two artifacts: the lock entry lists the digest
/// of each, and every listed digest is an artifact of the patch, so the
/// patch is confirmed. A listed digest that is no artifact of the patch
/// is a build that may fetch something else: refused.
#[test]
fn an_entry_that_lists_a_digest_per_artifact_is_held_to_every_artifact_of_the_patch() {
    const BOTH: LaneOps = LaneOps {
        inventory: both_artifacts,
        rewrite_owned: first_artifact,
        ..TOY
    };
    const FOREIGN: LaneOps = LaneOps {
        inventory: a_foreign_digest,
        ..BOTH
    };
    const BOTH_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &BOTH)]);
    const FOREIGN_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &FOREIGN)]);
    let grants = [grant(), sdist_grant()];
    let mut tree = toy_tree(INPUT);
    let (result, bazel) = scan(&mut tree, &BOTH_TABLE, "", &grants);
    assert!(confirmed(&result), "{result:?}");
    assert_eq!(bazel.decided.len(), 1, "two artifacts are one patch");
    assert_eq!(tree.text(LOCK), pinned(INPUT));
    // One artifact alone does not cover the entry.
    let mut tree = toy_tree(INPUT);
    let (result, _) = scan(&mut tree, &BOTH_TABLE, "", &[grant()]);
    assert!(refused(&result), "{result:?}");
    assert_eq!(tree, toy_tree(INPUT));

    let mut tree = toy_tree(INPUT);
    let (result, bazel) = scan(&mut tree, &FOREIGN_TABLE, "", &grants);
    assert!(refused(&result), "{result:?}");
    assert!(bazel.changes.is_empty());
    assert_eq!(tree, toy_tree(INPUT));
    let why = refusal_of(&bazel, UUID);
    assert!(
        why.detail.contains("is not the digest of the patch"),
        "{}",
        why.detail
    );
}

// ── A pin that is completed ──────────────────────────────────────────

// A lane with two recorded values per package beside the derived one.

fn alt_key(name: &str) -> String {
    format!("packages/{name}/alt")
}

const ALT_LOCK: &str = "{\n  \"lockVersion\": 1,\n  \"packages\": {\n    \"dep\": {\n      \
    \"version\": \"1.0.0\",\n      \
    \"url\": \"https://registry.toy.invalid/dep/-/dep-1.0.0.sh\",\n      \
    \"sha256\": \"5b850ef1c5b6c9c45330badb880dce1bcf31390ea60f25800a142825327121b8\",\n      \
    \"alt\": \"alt-upstream\"\n    \
    }\n  },\n  \"pinsHash\": -1084610730\n}\n";

/// Plans every value of the package (`all`), or only the values that are
/// not what the recorded row wrote (revision 4, 2.8 item 1: an existing
/// key is a no-op).
fn alt_plan(cx: &LaneCx<'_>, req: &PatchRequest<'_>, all: bool) -> GateOutcome {
    let plan = match (TOY.gate)(cx, req) {
        GateOutcome::Proceed(plan) => plan,
        other => return other,
    };
    let path = lock_of(cx).unwrap_or_default();
    let doc = cx.files.read(&path).as_str().and_then(parse);
    let rows = cx.index.pins.iter();
    let row = rows
        .clone()
        .find(|row| row.uuid == req.uuid && row.file == path);
    let held = |key: &str, member: &str| {
        let doc = doc.as_ref();
        let now = doc.and_then(|doc| doc["packages"][req.name][member].as_str());
        let wrote = |row: &IndexRow| {
            let mut edits = row.edits.iter();
            edits.any(|edit| edit.key == key && Some(edit.new.as_str()) == now)
        };
        row.is_some_and(wrote)
    };
    let value = |key: String| PlannedWrite::GeneratedValue {
        path: path.clone(),
        key,
    };
    let mut writes = Vec::new();
    if all || !held(&sha_key(req.name), "sha256") {
        writes.push(value(sha_key(req.name)));
        writes.push(value("pinsHash".to_string()));
    }
    if all || !held(&alt_key(req.name), "alt") {
        writes.push(value(alt_key(req.name)));
    }
    writes.push(PlannedWrite::Owned(OwnedWrite::Index));
    GateOutcome::Proceed(Plan { writes, ..plan })
}

fn alt_gate_all(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    alt_plan(cx, req, true)
}

fn alt_gate_missing(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    alt_plan(cx, req, false)
}

fn alt_rewrite(cx: &LaneCx<'_>, files: &mut Files, pins: &[PinSource], result: &mut RewriteResult) {
    (TOY.rewrite_owned)(cx, files, pins, result);
    let Some(lock) = lock_of(cx) else { return };
    let Some(mut text) = files.get(&lock).cloned() else {
        return;
    };
    for pin in pins {
        let PinSource::Hosted(dep) = pin else {
            continue;
        };
        if set_member(&mut text, &dep.name, "alt", "alt-upstream", "alt-patched") {
            let key = alt_key(&dep.name);
            let replaced = edit(&lock, &key, "alt-upstream", "alt-patched");
            result.edits.push(replaced);
        }
    }
    files.insert(lock, text);
}

/// A pin is a row of the lane whose package the lock serves from the
/// patch host: found by what the lock holds, as a native-lock lane finds
/// its pins.
fn alt_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
    let lock = lock_of(cx)?;
    let doc = parse(&read(&lock)?)?;
    let hosted = |row: &&IndexRow| {
        let first = row.edits.first();
        let name = first.and_then(|edit| edit.key.split('/').nth(1));
        let url = name.and_then(|name| doc["packages"][name]["url"].as_str());
        let socket = url.is_some_and(|url| url.starts_with("https://patch.socket.dev/"));
        row.lane == LANE.0 && row.file == lock && socket
    };
    let pin = |row: &IndexRow| BazelRef {
        lane: LANE,
        purl: row.purl.clone(),
        uuid: row.uuid.clone(),
        file: lock.clone(),
        basis: AttestBasis::BazelLock,
    };
    Some(cx.index.pins.iter().filter(hosted).map(pin).collect())
}

fn alt_restore(cx: &LaneCx<'_>, files: &mut Files, row: &IndexRow) -> RestoreOutcome {
    let mut rest = row.clone();
    rest.edits.retain(|edit| !edit.key.ends_with("/alt"));
    for edit in row.edits.iter().filter(|edit| edit.key.ends_with("/alt")) {
        let name = edit.key.split('/').nth(1).unwrap_or_default();
        let Some(text) = files.get_mut(&row.file) else {
            return RestoreOutcome::Drifted("the lock is gone".to_string());
        };
        if !set_member(text, name, "alt", &edit.new, &edit.original) {
            let why = format!("`{}` is not the value written", edit.key);
            return RestoreOutcome::Drifted(why);
        }
    }
    match rest.edits.is_empty() {
        true => RestoreOutcome::Restored,
        false => (TOY.restore)(cx, files, &rest),
    }
}

const ALT_ALL: LaneOps = LaneOps {
    gate: alt_gate_all,
    rewrite_owned: alt_rewrite,
    discover: alt_discover,
    attest: vouch,
    restore: alt_restore,
    ..TOY
};
const ALT_MISSING: LaneOps = LaneOps {
    gate: alt_gate_missing,
    ..ALT_ALL
};
const ALT_ALL_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &ALT_ALL)]);
const ALT_MISSING_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &ALT_MISSING)]);

fn recorded_keys(tree: &Tree) -> Vec<Vec<String>> {
    let keys = |row: &IndexRow| row.edits.iter().map(|edit| edit.key.clone()).collect();
    index_of(tree).pins.iter().map(keys).collect()
}

/// One of three recorded values of a pin is reset by hand, and the next
/// run pins it again. The lane reports that one value, and the index
/// holds one row per pin and file: the row keeps the two values that were
/// left in place, whether the lane's plan names every value or the
/// missing one alone. So the patch is confirmed, and the restore is
/// byte-exact: nothing of the pin is left in the lock with no record.
#[test]
fn a_pin_that_is_completed_keeps_the_record_of_the_values_left_in_place() {
    for (name, table) in [
        ("plans every value", &ALT_ALL_TABLE),
        ("plans the missing value", &ALT_MISSING_TABLE),
    ] {
        let before = toy_tree(ALT_LOCK);
        let mut tree = before.clone();
        let (result, _) = scan(&mut tree, table, "", &[grant()]);
        assert!(confirmed(&result), "{name}: {result:?}");
        let first = recorded_keys(&tree);
        let all = [sha_key("dep"), alt_key("dep"), "pinsHash".to_string()];
        assert_eq!(first, [all.to_vec()], "{name}");
        let whole = tree.clone();

        // One of the values is taken out again (a tool, a merge).
        let mut text = tree.text(LOCK);
        assert!(set_member(
            &mut text,
            "dep",
            "alt",
            "alt-patched",
            "alt-upstream"
        ));
        tree.0.insert(LOCK.to_string(), text.into_bytes());
        let (result, bazel) = scan(&mut tree, table, "", &[grant()]);
        assert!(confirmed(&result), "{name}: {:?}", result.warnings);
        assert_eq!(
            tree.text(LOCK),
            whole.text(LOCK),
            "{name}: pinned whole again"
        );
        let reported: Vec<Option<&str>> = bazel.edits.iter().map(|e| e.key.as_deref()).collect();
        assert_eq!(
            reported,
            [Some(&*alt_key("dep"))],
            "{name}: one value was written"
        );
        let [row] = &recorded_keys(&tree)[..] else {
            panic!("{name}: one row per pin and file");
        };
        let mut keys = row.clone();
        keys.sort();
        let mut wanted = all.to_vec();
        wanted.sort();
        assert_eq!(keys, wanted, "{name}: the row lost a value left in place");
        let recorded = index_of(&tree).pins[0].edits.clone();
        let digest = recorded.iter().find(|edit| edit.key == sha_key("dep"));
        let digest = digest.expect("the digest is on record");
        assert_eq!((&*digest.original, &*digest.new), (UPSTREAM, PATCHED));

        let undone = undo(&mut tree, table, &[UUID]);
        assert!(undone.restored(UUID), "{name}: {undone:?}");
        assert_eq!(tree, before, "{name}: the restore is byte-exact");
    }
}

// ── What a lane may hand over, and what it is handed ─────────────────

/// A plan for the toy lock that reads no lock, as a lane's gate that
/// tests a declaration alone.
fn unread_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    let path = lock_of(cx).unwrap_or_default();
    let key = sha_key(req.name);
    GateOutcome::Proceed(Plan {
        uuid: req.uuid.to_string(),
        lane: LANE,
        writes: vec![
            PlannedWrite::GeneratedValue { path, key },
            PlannedWrite::Owned(OwnedWrite::Index),
        ],
        repositories: Vec::new(),
        artifacts: Vec::new(),
        advisories: Vec::new(),
        attest: AttestBasis::BazelLock,
        anchor: Anchor::Digest,
    })
}

/// A writer that creates the lock where it is handed none, as the native
/// rewriters create a side file.
fn creating_rewrite(
    cx: &LaneCx<'_>,
    files: &mut Files,
    _: &[PinSource],
    result: &mut RewriteResult,
) {
    let Some(lock) = lock_of(cx) else { return };
    if files.contains_key(&lock) {
        return;
    }
    files.insert(lock.clone(), pinned(INPUT));
    let digest = edit(&lock, &sha_key("dep"), UPSTREAM, PATCHED);
    result.edits.push(digest);
}

/// The root with one file nobody can read.
struct Unreadable<'a> {
    tree: &'a Tree,
    path: &'a str,
}

impl FileView for Unreadable<'_> {
    fn read(&self, rel: &str) -> FileText {
        match rel == self.path {
            true => FileText::Unreadable,
            false => self.tree.read(rel),
        }
    }

    fn list(&self, dir: &str) -> Option<Vec<String>> {
        self.tree.list(dir)
    }
}

/// A file the plan names that exists and is no UTF-8 text is not a file
/// that is absent. Handed over as absent, a writer that creates what it
/// does not find replaces the user's lock; so the patch is refused, with
/// the file to make readable, and the lock is left byte for byte.
#[test]
fn a_file_of_the_plan_that_is_no_text_is_never_handed_over_as_absent() {
    const OPS: LaneOps = LaneOps {
        gate: unread_gate,
        rewrite_owned: creating_rewrite,
        ..TOY
    };
    const CREATING: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    let refused_unreadable = |result: &RewriteResult, bazel: &BazelRewrite| {
        assert!(refused(result), "{result:?}");
        assert!(bazel.changes.is_empty(), "{:?}", bazel.changes.keys());
        let why = refusal_of(bazel, UUID);
        assert_eq!(why.code, Code::WorkspaceUnreadable);
        assert_eq!(why.token, "workspace_unreadable");
        let lift = Lift::UserEdit {
            file: LOCK.to_string(),
            what: "make the file readable UTF-8 text".to_string(),
        };
        assert_eq!(why.lift, lift);
        assert!(
            why.detail.ends_with("; nothing was written"),
            "{}",
            why.detail
        );
        assert_eq!(codes(result), [Code::WorkspaceUnreadable.as_str()]);
    };
    // The user's lock, saved as UTF-16 with a byte-order mark.
    let mut utf16: Vec<u8> = vec![0xFF, 0xFE];
    for unit in INPUT.encode_utf16() {
        utf16.extend(unit.to_le_bytes());
    }
    let mut before = toy_tree(INPUT);
    before.0.insert(LOCK.to_string(), utf16);
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &CREATING, "", &[grant()]);
    refused_unreadable(&result, &bazel);
    assert_eq!(tree, before);

    // A lock that is there and cannot be read.
    let tree = toy_tree(INPUT);
    let view = Unreadable {
        tree: &tree,
        path: LOCK,
    };
    let (result, bazel) = seam(&tree, &view, &Index::default(), &CREATING, "", &[grant()]);
    refused_unreadable(&result, &bazel);
}

/// The toy fixups, and the derived value a restore of the lock must land
/// on, reported beside the edits as a lane reports the check of its row.
fn checked_fixups(cx: &LaneCx<'_>, files: &mut Files, plan: &Plan, result: &mut RewriteResult) {
    (TOY.fixups)(cx, files, plan, result);
    let Some(lock) = lock_of(cx) else { return };
    let derived = |edit: &&socket_patch_core::patch::redirect::FileEdit| {
        edit.path == lock && edit.key.as_deref() == Some("pinsHash")
    };
    let Some(derived) = result.edits.iter().find(derived) else {
        return;
    };
    let hash = |value: &Option<serde_json::Value>| {
        let text = value.as_ref().and_then(|value| value.as_str());
        ResolvedHash::Int(text.and_then(|text| text.parse().ok()).unwrap_or_default())
    };
    let check = IndexCheck {
        resolved_hash_before: hash(&derived.original),
        resolved_hash_after: hash(&derived.new),
        flavor: "toy".to_string(),
    };
    result.bazel_checks.insert(lock, check);
}

/// A lane reports the check of a row beside its edits, and the group puts
/// it into the row of its file: never an edit, kept by a run that writes
/// nothing, and gone with the row when the pin is undone.
#[test]
fn the_check_a_lane_reports_rides_the_row_of_its_file() {
    const OPS: LaneOps = LaneOps {
        fixups: checked_fixups,
        ..TOY
    };
    const CHECKED: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    let before = toy_tree(INPUT);
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &CHECKED, "", &[grant()]);
    assert!(confirmed(&result), "{result:?}");
    let hash = pins_hash(&parse(&pinned(INPUT)).unwrap()).unwrap();
    let check = IndexCheck {
        resolved_hash_before: ResolvedHash::Int(-1_084_610_730),
        resolved_hash_after: ResolvedHash::Int(hash),
        flavor: "toy".to_string(),
    };
    let [row] = &index_of(&tree).pins[..] else {
        panic!("one row");
    };
    assert_eq!(row.check, Some(check.clone()));
    let keys: Vec<&str> = row.edits.iter().map(|edit| &*edit.key).collect();
    assert_eq!(keys, [&*sha_key("dep"), "pinsHash"], "the check is no edit");
    assert_eq!(bazel.edits.len(), 2);
    assert!(tree.text(INDEX_PATH).contains("\"flavor\": \"toy\""));
    // The native result carries no check out of the group.
    assert!(result.bazel_checks.is_empty());

    let mut again = tree.clone();
    let (result, bazel) = scan(&mut again, &CHECKED, "", &[grant()]);
    assert!(confirmed(&result) && bazel.changes.is_empty());
    assert_eq!(index_of(&again).pins[0].check, Some(check));

    let undone = undo(&mut tree, &CHECKED, &[UUID]);
    assert!(undone.restored(UUID));
    assert_eq!(tree, before);
}

/// The toy gate, with a vendored artifact in the plan.
fn artifact_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    let plan = match (TOY.gate)(cx, req) {
        GateOutcome::Proceed(plan) => plan,
        other => return other,
    };
    let artifact = ArtifactSpec {
        uuid: req.uuid.to_string(),
        form: ArtifactForm::NativeFile,
        dir: format!(".socket/vendor/maven/{}", req.uuid),
        leaf: "dep-1.0.0.sh".to_string(),
        digest: Digest::Sha256(PATCHED.to_string()),
    };
    GateOutcome::Proceed(Plan {
        artifacts: vec![artifact],
        ..plan
    })
}

/// A hosted run produces no artifact, so a plan that needs one in place
/// before its pin is not carried out: its pin would name bytes nobody
/// committed.
#[test]
fn a_hosted_plan_that_needs_a_vendored_artifact_is_refused() {
    const OPS: LaneOps = LaneOps {
        gate: artifact_gate,
        ..TOY
    };
    const VENDORS: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    let before = toy_tree(INPUT);
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &VENDORS, "", &[grant()]);
    assert!(refused(&result), "{result:?}");
    assert!(bazel.changes.is_empty() && bazel.index.is_empty());
    assert_eq!(tree, before);
    let why = refusal_of(&bazel, UUID);
    assert_eq!(why.code, Code::RedirectRulesetUnsupported);
    assert!(why.detail.contains("vendored artifact"), "{}", why.detail);
    let planned = &bazel.decided[0].outcome;
    assert!(matches!(planned, GateOutcome::Proceed(_)), "{planned:?}");
}

// A native-lock lane over a `pom.xml`, which the native Maven rewriter
// pins together with two files under `.mvn/` that it creates.

const POM_LANE: LaneId = LaneId("H-TOYPOM");
const POM_SPEC: LaneSpec = LaneSpec {
    id: POM_LANE,
    classes: &[WriteClass::NativeLock],
    ..TOY.lanes[0]
};

fn pom_gate(_: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    GateOutcome::Proceed(Plan {
        uuid: req.uuid.to_string(),
        lane: POM_LANE,
        writes: vec![PlannedWrite::NativeLock {
            path: "pom.xml".to_string(),
        }],
        repositories: Vec::new(),
        artifacts: Vec::new(),
        advisories: Vec::new(),
        attest: AttestBasis::LockUrl,
        anchor: Anchor::Digest,
    })
}

/// The native rewriter is handed the native locks of the plan, and
/// nothing is taken from it but those files: a file it creates beside
/// them (a `.npmrc`, the Maven checksum files) is off the plan, and the
/// patch is refused before anything of it is staged.
#[test]
fn a_file_the_native_rewriter_writes_beside_the_plan_refuses_the_patch() {
    const OPS: LaneOps = LaneOps {
        lanes: &[POM_SPEC],
        gate: pom_gate,
        ..LaneOps::disabled(&[])
    };
    const POM_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    let pom = redirect_fixture("maven/pom/basic", "input/pom.xml");
    let grants = redirect_fixture("maven/pom/basic", "overrides.json");
    let grants: Vec<DepOverride> = serde_json::from_str(&grants).expect("the grants");
    // Without Bazel the rewrite creates files beside the pom.
    let project = BTreeMap::from([("pom.xml".to_string(), pom.clone())]);
    let native = rewrite_registry_redirect(&project, &grants);
    let beside = native.files.keys().find(|path| path.starts_with(".mvn/"));
    assert!(beside.is_some(), "{:?}", native.files.keys());

    let mut before = toy_tree(INPUT);
    before.0.insert("pom.xml".to_string(), pom.into_bytes());
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &POM_TABLE, "", &grants);
    assert_eq!(result.refused_bazel_uuids.len(), 1, "{result:?}");
    assert!(result.files.is_empty() && bazel.changes.is_empty());
    assert_eq!(tree, before);
    let why = refusal_of(&bazel, &grants[0].patch_uuid);
    assert!(
        why.detail
            .contains("the native rewriter would write `.mvn/"),
        "{}",
        why.detail
    );
}

/// A keyed edit of the native lock, reported by a native-lock lane.
fn keyed_fixups(cx: &LaneCx<'_>, _: &mut Files, _: &Plan, result: &mut RewriteResult) {
    if let Some(lock) = lock_of(cx) {
        let keyed = edit(&lock, "packages/x/integrity", "a", "b");
        result.edits.push(keyed);
    }
}

/// A native lock keeps no record: its restorer re-derives the upstream
/// entry. A lane that reports a recorded value of one would stage the
/// index for a plan that captures none, and would hand the lock to its
/// own restore, away from the native restorer. Refused, and the lock is
/// as it was.
#[test]
fn a_recorded_value_of_a_native_lock_is_refused() {
    const OPS: LaneOps = LaneOps {
        fixups: keyed_fixups,
        ..JS_OPS
    };
    const KEYED: LaneTable = LaneTable(&[(Ruleset::RulesJs, &OPS)]);
    let pnpm = redirect_fixture("npm/pnpm/basic", "input/pnpm-lock.yaml");
    let grants = redirect_fixture("npm/pnpm/basic", "overrides.json");
    let grants: Vec<DepOverride> = serde_json::from_str(&grants).expect("the grants");
    let before = Tree::of(&[
        (".bazelversion", "9.3.2\n"),
        ("MODULE.bazel", JS_MODULE),
        ("pnpm-lock.yaml", &pnpm),
    ]);
    // The lane without the edit pins the lock, and captures it alone.
    let mut pinned = before.clone();
    let (result, bazel) = scan(&mut pinned, &JS_TABLE, "", &grants);
    assert_eq!(result.confirmed_bazel_uuids.len(), 1);
    let captured = exec::touched(&Index::default(), &bazel.plans);
    assert_eq!(captured, ["pnpm-lock.yaml"]);

    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &KEYED, "", &grants);
    assert_eq!(result.refused_bazel_uuids.len(), 1, "{result:?}");
    assert!(bazel.changes.is_empty() && bazel.index.is_empty());
    assert_eq!(tree, before);
    let why = refusal_of(&bazel, &grants[0].patch_uuid);
    assert!(why.detail.contains("keeps no record"), "{}", why.detail);
}

/// A grant the toy lane cannot pin: it carries no SHA-256.
fn bare_grant() -> DepOverride {
    DepOverride {
        integrity: Integrity::default(),
        ..grant()
    }
}

/// Two states in which a lane has nothing to write and the pin cannot be
/// confirmed, neither of them the lane's fault, and neither said as a
/// lane to enable. The pin is in the lock and the owned index is gone:
/// the refusal names the index to restore, and the lock. No rewriter can
/// pin the grant: the refusal names the lock.
#[test]
fn a_refusal_that_is_no_fault_of_the_lane_names_the_edit_that_lifts_it() {
    let mut wired = toy_tree(INPUT);
    scan(&mut wired, &TABLE, "", &[grant()]);
    let mut before = wired.clone();
    before.0.remove(INDEX_PATH);
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &TABLE, "", &[grant()]);
    assert!(refused(&result), "{result:?}");
    assert!(bazel.changes.is_empty());
    assert_eq!(tree, before);
    let why = refusal_of(&bazel, UUID);
    assert_eq!(why.code, Code::RedirectOwnedFileModified);
    assert_eq!(why.token, "owned_file_missing");
    let Lift::UserEdit { file, what } = &why.lift else {
        panic!("{:?}", why.lift);
    };
    assert_eq!(file, INDEX_PATH);
    assert!(
        what.contains("version control") && what.contains(LOCK),
        "{what}"
    );
    assert!(
        why.detail
            .contains(&format!("`{LOCK}` already holds the pin")),
        "{}",
        why.detail
    );
    assert!(!why.detail.contains("not enabled"), "{}", why.detail);
    assert_eq!(
        why.lift.details()["kind"],
        json!("user_edit"),
        "{:?}",
        why.lift
    );

    let before = toy_tree(INPUT);
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &TABLE, "", &[bare_grant()]);
    assert!(refused(&result), "{result:?}");
    assert_eq!(tree, before);
    let why = refusal_of(&bazel, UUID);
    assert_eq!(why.code, Code::RedirectConsumerUndetermined);
    assert_eq!(why.token, "not_resolved_by_hub");
    let Lift::UserEdit { file, .. } = &why.lift else {
        panic!("{:?}", why.lift);
    };
    assert_eq!(file, LOCK);
    assert!(
        why.detail.contains("`dep` 1.0.0 is not pinned") && !why.detail.contains("not enabled"),
        "{}",
        why.detail
    );
    assert!(
        why.detail.ends_with("; nothing was written"),
        "{}",
        why.detail
    );
}

// ── The index nobody can rely on, and the order of an undo ───────────

/// The owned index is the record of every undo. Where the file is not one
/// socket-patch wrote, nothing is undone from the rows a run still
/// holds: the sweep does not run (a lane that drops the row of a pin
/// that is gone would write from a record nobody can trust), every patch
/// is refused with the index to put right, and the restore leaves every
/// patch as it is.
#[test]
fn an_index_file_nobody_can_rely_on_stops_the_sweep_and_the_undo() {
    let mut wired = toy_tree(INPUT);
    scan(&mut wired, &TABLE, "", &[grant()]);
    let held = index_of(&wired);
    assert_eq!(held.pins.len(), 1);
    // The lock was regenerated, so the row is stale; and the index file
    // is a file of somebody else's.
    let mut tree = wired.clone();
    tree.0.insert(LOCK.to_string(), INPUT.as_bytes().to_vec());
    tree.0
        .insert(INDEX_PATH.to_string(), b"{ not ours".to_vec());

    let (result, bazel) = seam(&tree, &tree, &held, &DROPS_TABLE, "", &[grant()]);
    assert!(refused(&result), "{result:?}");
    assert!(bazel.changes.is_empty(), "{:?}", bazel.changes.keys());
    assert_eq!(
        codes(&result),
        [Code::RedirectOwnedFileModified.as_str()],
        "no sweep, so no pin is reported erased: {:?}",
        result.warnings
    );
    let why = refusal_of(&bazel, UUID);
    assert!(matches!(why.lift, Lift::UserEdit { .. }), "{:?}", why.lift);
    // Not granted: nothing is decided, and still nothing is swept.
    let (result, bazel) = seam(&tree, &tree, &held, &DROPS_TABLE, "", &[]);
    assert!(result.warnings.is_empty() && bazel.changes.is_empty());

    let ws = workspace(&tree, "");
    let root = Root {
        ws: &ws,
        files: &tree,
        index: &held,
        lanes: &DROPS_TABLE,
    };
    let undone = restore::revert(&root, &[UUID]);
    assert!(undone.changes.is_empty() && !undone.restored(UUID));
    let (files, why) = undone.incomplete(UUID).expect("incomplete");
    assert_eq!(files, [INDEX_PATH]);
    assert!(why.contains("not socket-patch's index"), "{why}");
    assert_eq!(undone.recorded(UUID), [LOCK]);
}

/// The caller of a restore does not choose the order of its pins (the
/// driver orders them by purl), so the undo may not depend on it. Two
/// pins of one toy lock, whose derived value each of them changed: in
/// either order both are undone and the root is byte for byte the input.
/// A pin asked about alone is still held to what its row wrote.
#[tokio::test]
async fn two_pins_of_one_lock_are_undone_in_either_order() {
    let packages = [
        ("dep", "1.0.0", UPSTREAM),
        ("other", "2.0.0", OTHER_UPSTREAM),
    ];
    let before = toy_tree(&toy_lock(&packages));
    let mut wired = before.clone();
    let (result, _) = scan(&mut wired, &TABLE, "", &[grant(), other_grant()]);
    assert_eq!(result.confirmed_bazel_uuids.len(), 2);
    for order in [[UUID, OTHER], [OTHER, UUID]] {
        let mut tree = wired.clone();
        let undone = undo(&mut tree, &TABLE, &order);
        assert!(
            undone.restored(UUID) && undone.restored(OTHER),
            "{order:?}: {:?}",
            undone.patches
        );
        let asked: Vec<&str> = undone.patches.iter().map(|patch| &*patch.uuid).collect();
        assert_eq!(asked, order, "one entry per patch, in the order asked");
        assert_eq!(tree, before, "{order:?}");
    }

    let pin = |purl: &str, uuid: &str| HostedPin {
        purl: purl.to_string(),
        uuid: uuid.to_string(),
        files: vec![LOCK.to_string()],
    };
    let (dep, other) = (pin(PURL, UUID), pin("pkg:maven/other@2.0.0", OTHER));
    let opts = RestoreOptions {
        offline: true,
        ..RestoreOptions::default()
    };
    let project = tempfile::tempdir().expect("a temp dir");
    let (ws, index) = (workspace(&wired, ""), index_of(&wired));
    let root = Root {
        ws: &ws,
        files: &wired,
        index: &index,
        lanes: &TABLE,
    };
    for pins in [[dep.clone(), other.clone()], [other, dep]] {
        let outcome = restore_upstream_under_bazel(project.path(), &pins, &opts, &root).await;
        for pin in &outcome.pins {
            assert_eq!(pin.status, PinStatus::Restored, "{outcome:?}");
        }
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let mut tree = wired.clone();
        tree.apply(&outcome.bazel.expect("the Bazel side").changes);
        assert_eq!(tree, before);
    }
}

// ── The restore driver: two sides, one commit ────────────────────────

const SBT_FILE: &str = "socket-patch.sbt";
const SBT_TEXT_UUID: &str = "12345678-0000-4000-8000-000000000002";
const SBT_TEXT_PURL: &str = "pkg:maven/org.apache.commons/commons-text@1.9";

fn sbt_fixture(name: &str) -> String {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = ["tests", "fixtures", "sbt", "owned_file", name];
    let path = path
        .iter()
        .fold(root.to_path_buf(), |at, part| at.join(part));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn offline() -> RestoreOptions {
    RestoreOptions {
        offline: true,
        ..RestoreOptions::default()
    }
}

/// The hosted sbt file with two pins, of which the restore takes one out
/// offline: a native file the native restorer rewrites.
fn sbt_pin() -> HostedPin {
    HostedPin {
        purl: SBT_TEXT_PURL.to_string(),
        uuid: SBT_TEXT_UUID.to_string(),
        files: vec![SBT_FILE.to_string()],
    }
}

fn toy_pin() -> HostedPin {
    HostedPin {
        purl: PURL.to_string(),
        uuid: UUID.to_string(),
        files: vec![LOCK.to_string()],
    }
}

/// While the Bazel side has anything to land, the driver writes nothing:
/// not the index, not the lock a row records, and not the native file of
/// another pin, which it would flush at once without a Bazel side. What
/// the native restorer staged is in the outcome, and the one change set
/// the caller commits at the Bazel root holds both sides.
#[tokio::test]
async fn the_restore_driver_writes_no_native_file_while_a_commit_is_pending() {
    let (two_pins, one_pin) = (
        sbt_fixture("hosted-1-2pin.sbt"),
        sbt_fixture("hosted-1-1pin.sbt"),
    );
    let project = tempfile::tempdir().expect("a temp dir");
    let on_disk = project.path().join(SBT_FILE);
    std::fs::write(&on_disk, &two_pins).expect("write");
    let before = {
        let mut tree = toy_tree(INPUT);
        tree.0
            .insert(SBT_FILE.to_string(), two_pins.clone().into_bytes());
        tree
    };
    let mut wired = before.clone();
    scan(&mut wired, &TABLE, "", &[grant()]);
    let (ws, index) = (workspace(&wired, ""), index_of(&wired));
    let root = Root {
        ws: &ws,
        files: &wired,
        index: &index,
        lanes: &TABLE,
    };
    let pins = [sbt_pin(), toy_pin()];
    let outcome = restore_upstream_under_bazel(project.path(), &pins, &offline(), &root).await;
    for pin in &outcome.pins {
        assert_eq!(pin.status, PinStatus::Restored, "{outcome:?}");
    }
    assert!(outcome.commit_pending() && outcome.flush_error.is_none());
    assert_eq!(
        std::fs::read_to_string(&on_disk).expect("read"),
        two_pins,
        "nothing is written here while a commit is pending"
    );
    assert_eq!(
        outcome.staged_text.get(SBT_FILE),
        Some(&Some(one_pin.clone())),
        "the native side is planned"
    );
    assert_eq!(outcome.reverted_files, [INDEX_PATH, SBT_FILE, LOCK]);
    assert!(outcome.outside_bazel_root.is_empty());
    // One change set, by path from the Bazel root, with both sides in it.
    let undo = outcome.bazel.expect("the Bazel side");
    let changed: Vec<&String> = undo.changes.keys().collect();
    assert_eq!(changed, [INDEX_PATH, SBT_FILE, LOCK]);
    assert_eq!(
        undo.changes[SBT_FILE].as_deref(),
        Some(one_pin.as_bytes()),
        "the native file is part of the commit"
    );
    let mut tree = wired.clone();
    tree.apply(&undo.changes);
    let mut restored = before.clone();
    restored
        .0
        .insert(SBT_FILE.to_string(), one_pin.into_bytes());
    assert_eq!(tree, restored);

    // With no Bazel side to land, the native file is flushed here as it
    // is without Bazel, and there is nothing to commit at the root.
    let outcome =
        restore_upstream_under_bazel(project.path(), &[sbt_pin()], &offline(), &root).await;
    assert_eq!(outcome.pins[0].status, PinStatus::Restored, "{outcome:?}");
    assert!(!outcome.commit_pending());
    assert!(outcome.bazel.expect("the Bazel side").changes.is_empty());
    let flushed = std::fs::read_to_string(&on_disk).expect("read");
    assert_eq!(flushed, sbt_fixture("hosted-1-1pin.sbt"));
}

/// A pin with a native file and a recorded file is restored on both sides
/// or on neither. Here the native restorer refuses the pin (a file whose
/// upstream entry nobody can re-derive), so the Bazel side is planned
/// again without it: the change set holds the undo of the other pin and
/// nothing of the refused one, whose remedy names both of its files.
#[tokio::test]
async fn a_pin_the_native_restorer_refuses_is_left_out_of_the_bazel_side() {
    let packages = [
        ("dep", "1.0.0", UPSTREAM),
        ("other", "2.0.0", OTHER_UPSTREAM),
    ];
    let mut wired = toy_tree(&toy_lock(&packages));
    scan(&mut wired, &TABLE, "", &[grant()]);
    let first = wired.clone();
    scan(&mut wired, &TABLE, "", &[other_grant()]);
    let (ws, index) = (workspace(&wired, ""), index_of(&wired));
    let root = Root {
        ws: &ws,
        files: &wired,
        index: &index,
        lanes: &TABLE,
    };
    let stuck = HostedPin {
        files: vec!["weird.lock".to_string(), LOCK.to_string()],
        ..toy_pin()
    };
    let other = HostedPin {
        purl: "pkg:maven/other@2.0.0".to_string(),
        uuid: OTHER.to_string(),
        files: vec![LOCK.to_string()],
    };
    let project = tempfile::tempdir().expect("a temp dir");
    let pins = [stuck.clone(), other];
    let outcome = restore_upstream_under_bazel(project.path(), &pins, &offline(), &root).await;
    let PinStatus::Refused(why) = &outcome.pins[0].status else {
        panic!("a pin nobody can restore natively was restored: {outcome:?}");
    };
    assert!(
        why.contains("weird.lock") && why.contains(LOCK),
        "the remedy names both files: {why}"
    );
    assert_eq!(outcome.pins[1].status, PinStatus::Restored, "{outcome:?}");
    assert!(outcome.commit_pending());
    let undo = outcome.bazel.expect("the Bazel side");
    assert!(undo.restored(OTHER) && !undo.restored(UUID));
    let asked: Vec<&str> = undo.patches.iter().map(|patch| &*patch.uuid).collect();
    assert_eq!(asked, [OTHER], "the refused pin was not planned again");
    let mut tree = wired.clone();
    tree.apply(&undo.changes);
    assert_eq!(tree, first, "the pin of `dep` is exactly as it was");

    // Alone, it leaves nothing to commit.
    let outcome = restore_upstream_under_bazel(project.path(), &[stuck], &offline(), &root).await;
    assert!(matches!(outcome.pins[0].status, PinStatus::Refused(_)));
    assert!(!outcome.commit_pending() && outcome.reverted_files.is_empty());
    assert!(outcome.bazel.expect("the Bazel side").changes.is_empty());
}

// A lane whose recorded value is derived from the bytes of a native file,
// as the hash line `update_pnpm_lock` keeps over a `pnpm-lock.yaml`.

const DERIVED_LANE: LaneId = LaneId("H-TOYDERIVED");
const DERIVED_SPEC: LaneSpec = LaneSpec {
    id: DERIVED_LANE,
    ..TOY.lanes[0]
};

/// The value the lock holds for the native file as `file` shows it.
fn native_mark(file: &FileText) -> String {
    match file.as_bytes() {
        Some(bytes) => hash_bytes(bytes).to_string(),
        None => "absent".to_string(),
    }
}

fn derived_lock(mark: &str) -> String {
    format!("{{\n  \"of\": \"{SBT_FILE}\",\n  \"nativeHash\": \"{mark}\"\n}}\n")
}

/// The value is computed again from the native file as the transaction
/// shows it. The recorded original is never written back: a hash of the
/// file as it was before the pin is wrong for the file a restore leaves.
fn derived_restore(cx: &LaneCx<'_>, files: &mut Files, row: &IndexRow) -> RestoreOutcome {
    let Some(text) = files.get_mut(&row.file) else {
        return RestoreOutcome::Drifted("the lock is gone".to_string());
    };
    let now = native_mark(&cx.files.read(SBT_FILE));
    for edit in &row.edits {
        if !text.contains(&derived_lock(&edit.new)) {
            let why = format!("`{}` is no longer the value socket-patch wrote", edit.key);
            return RestoreOutcome::Drifted(why);
        }
        *text = derived_lock(&now);
    }
    RestoreOutcome::Restored
}

/// The native side of a restore is planned first and the Bazel side over
/// it, so a lane's restore reads the native file as the native restorer
/// leaves it. A value derived from that file lands on the value of the
/// restored bytes: not on the value of the pinned file, which is what the
/// lane would compute from the root as it is, and not on the recorded
/// original.
#[tokio::test]
async fn a_recorded_value_derived_from_a_native_file_lands_on_the_restored_file() {
    const OPS: LaneOps = LaneOps {
        lanes: &[DERIVED_SPEC],
        restore: derived_restore,
        ..LaneOps::disabled(&[])
    };
    const DERIVED: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &OPS)]);
    let (two_pins, one_pin) = (
        sbt_fixture("hosted-1-2pin.sbt"),
        sbt_fixture("hosted-1-1pin.sbt"),
    );
    let hosted = native_mark(&FileText::Bytes(two_pins.clone().into_bytes()));
    let restored = native_mark(&FileText::Bytes(one_pin.clone().into_bytes()));
    assert_ne!(hosted, restored);
    let mut index = Index::default();
    index.record_pin(IndexRow {
        uuid: SBT_TEXT_UUID.to_string(),
        purl: SBT_TEXT_PURL.to_string(),
        lane: DERIVED_LANE.0.to_string(),
        file: LOCK.to_string(),
        edits: vec![IndexEdit {
            key: "nativeHash".to_string(),
            original: "recorded-before-the-pin".to_string(),
            new: hosted.clone(),
        }],
        check: None,
    });
    let wired = Tree::of(&[
        (".bazelversion", "9.3.2\n"),
        ("MODULE.bazel", MODULE),
        (LOCK, &derived_lock(&hosted)),
        (SBT_FILE, &two_pins),
        (INDEX_PATH, &index.render().expect("a record")),
    ]);
    let project = tempfile::tempdir().expect("a temp dir");
    let on_disk = project.path().join(SBT_FILE);
    std::fs::write(&on_disk, &two_pins).expect("write");
    let (ws, index) = (workspace(&wired, ""), index_of(&wired));
    let root = Root {
        ws: &ws,
        files: &wired,
        index: &index,
        lanes: &DERIVED,
    };
    // One pin, wired in the native file and in the value derived from it.
    let pin = HostedPin {
        files: vec![SBT_FILE.to_string(), LOCK.to_string()],
        ..sbt_pin()
    };
    let pins = std::slice::from_ref(&pin);
    let outcome = restore_upstream_under_bazel(project.path(), pins, &offline(), &root).await;
    assert_eq!(outcome.pins[0].status, PinStatus::Restored, "{outcome:?}");
    assert!(outcome.commit_pending());
    assert_eq!(std::fs::read_to_string(&on_disk).expect("read"), two_pins);
    let undo = outcome.bazel.expect("the Bazel side");
    let mut tree = wired.clone();
    tree.apply(&undo.changes);
    assert_eq!(tree.text(SBT_FILE), one_pin);
    assert_eq!(
        tree.text(LOCK),
        derived_lock(&restored),
        "the value of the restored native file"
    );
    assert!(!tree.0.contains_key(INDEX_PATH), "the last row is gone");
}

/// A restore whose native files may not be written has nothing to
/// commit: the driver refuses the flush before anything is written (here
/// one of the files is a symbolic link, which is why this runs where a
/// test can make one without a privilege), every pin is unwritten, and
/// the Bazel side's change set is withdrawn with them. A caller that
/// lands whatever change set it is handed lands nothing, and no derived
/// value goes to upstream beside a lock that still names the patch.
#[cfg(unix)]
#[tokio::test]
async fn a_restore_that_may_not_be_written_has_nothing_to_commit() {
    let project = tempfile::tempdir().expect("a temp dir");
    let at = |rel: &str| {
        let parts = rel.split('/');
        parts.fold(project.path().to_path_buf(), |at, part| at.join(part))
    };
    for rel in [
        ".mvn/checksums/checksums.sha256",
        ".mvn/maven.config",
        "pom.xml",
    ] {
        let text = redirect_fixture("maven/pom/basic", &format!("expected/{rel}"));
        std::fs::create_dir_all(at(rel).parent().expect("a parent")).expect("mkdir");
        std::fs::write(at(rel), text).expect("write");
    }
    let (config, shared) = (at(".mvn/maven.config"), at("shared-maven.config"));
    std::fs::rename(&config, &shared).expect("rename");
    std::os::unix::fs::symlink(&shared, &config).expect("a link");
    let pom = std::fs::read_to_string(at("pom.xml")).expect("read");

    let mut wired = toy_tree(INPUT);
    scan(&mut wired, &TABLE, "", &[grant()]);
    let (ws, index) = (workspace(&wired, ""), index_of(&wired));
    let root = Root {
        ws: &ws,
        files: &wired,
        index: &index,
        lanes: &TABLE,
    };
    let maven = HostedPin {
        purl: "pkg:maven/org.slf4j/slf4j-api@1.7.36".to_string(),
        uuid: "77777777-7777-7777-7777-777777777777".to_string(),
        files: vec!["pom.xml".to_string()],
    };
    let pins = [maven, toy_pin()];
    let outcome = restore_upstream_under_bazel(project.path(), &pins, &offline(), &root).await;
    let error = outcome
        .flush_error
        .as_deref()
        .expect("the flush is refused");
    assert!(error.contains("symbolic link"), "{error}");
    for pin in &outcome.pins {
        assert_eq!(pin.status, PinStatus::Unwritten, "{outcome:?}");
    }
    assert!(!outcome.commit_pending());
    let undo = outcome.bazel.as_ref().expect("the Bazel side");
    assert!(undo.changes.is_empty(), "{:?}", undo.changes.keys());
    assert!(!undo.restored(UUID));
    assert!(
        outcome.reverted_files.contains(&LOCK.to_string()),
        "what the restore would have changed is still reported: {:?}",
        outcome.reverted_files
    );
    assert_eq!(std::fs::read_to_string(at("pom.xml")).expect("read"), pom);
    assert!(std::fs::symlink_metadata(&config)
        .expect("the link")
        .file_type()
        .is_symlink());
}
