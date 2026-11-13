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
//! pin on another digest, a restore that drops a pin that is gone) show
//! what the group does with them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::json;
use socket_patch_core::bazel::exec;
use socket_patch_core::bazel::gate::{self, GateCx};
use socket_patch_core::bazel::lanes;
use socket_patch_core::bazel::model::{
    Actor, Anchor, AttestBasis, BazelRef, BazelWorkspace, Code, FileText, FileView, Files,
    GateOutcome, HubId, Index, IndexRow, LaneCx, LaneId, LaneOps, LaneSpec, LaneTable, Lift, Mode,
    OwnedWrite, PatchRequest, PinSource, Plan, PlannedWrite, RestoreOutcome, RootRef, Ruleset,
    RunKind, RunRequired, TextRead, VexWithhold, WithholdKind, WriteClass,
};
use socket_patch_core::bazel::owned_index::{self, Parsed, INDEX_PATH};
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
pub(super) fn workspace(tree: &Tree, project_rel: &str) -> BazelWorkspace {
    let root = RootRef {
        root: PathBuf::from("repo"),
        project_rel: project_rel.to_string(),
        boundary_levels: 0,
    };
    socket_patch_core::bazel::detect(&root, tree).expect("a Bazel workspace")
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
    let (ws, index) = (workspace(tree, project_rel), index_of(tree));
    let below = below(project_rel);
    let own = |(path, bytes): (&String, &Vec<u8>)| {
        let text = String::from_utf8(bytes.clone()).ok()?;
        Some((path.strip_prefix(&below)?.to_string(), text))
    };
    let files: BTreeMap<String, String> = tree.0.iter().filter_map(own).collect();
    let (result, bazel) = {
        let host = BazelHost {
            cx: GateCx::new(Mode::Hosted, &ws, &*tree, &index),
            lanes: table,
        };
        rewrite_registry_redirect_under_bazel(&files, overrides, &host)
    };
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
    // refused, and the lock is as it was.
    let mut bare = grants.clone();
    bare[0].integrity = Integrity::default();
    let mut tree = before.clone();
    let (result, bazel) = scan(&mut tree, &JS_TABLE, "", &bare);
    assert_eq!(result.refused_bazel_uuids, uuids);
    assert!(bazel.changes.is_empty());
    assert_eq!(tree, before);
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
    const STRAY: LaneOps = LaneOps {
        rewrite_owned: stray,
        ..TOY
    };
    const RECORD: LaneOps = LaneOps {
        rewrite_owned: record,
        ..TOY
    };
    const BESIDE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &STRAY)]);
    const OWNED: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &RECORD)]);
    for (table, path) in [(&BESIDE, "BUILD.bazel"), (&OWNED, INDEX_PATH)] {
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
        assert!(why.detail.contains(&format!("`{path}`")), "{}", why.detail);
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
