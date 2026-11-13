//! Goldens: a test-only lane over a JSON lock, which runs the gate, the
//! write, the executor, discovery, attestation and the restore before any
//! real lane exists (design 2.12; revision 4, section 5 item 6).
//!
//! The lock is the one the toy extension of the `core/` fixture reads:
//!
//! ```text
//! {"lockVersion": 1,
//!  "packages": {"<name>": {"version": "...", "url": "...", "sha256": "..."}},
//!  "pinsHash": <int>}
//! ```
//!
//! `pinsHash` is a derived value: Starlark `hash()` of one `<name>
//! <sha256>` line per package, in name order. A lock whose pins changed
//! without it fails to load, as a `maven_install.json` with a stale
//! resolved hash does, so the lane has a pin (`rewrite_owned`), a derived
//! value (`fixups`) and an index row (`restore`).
//!
//! No `Ruleset` exists for the toy and none is added: the table below
//! serves the hub the rules_jvm_external recognizer reads (which opens no
//! lock) with the toy lane, and the shipped binary cannot reach it. Every
//! write goes through `exec::apply`, every undo through `exec::revert`
//! and every repair through `exec::reconcile`; the lane has no write path
//! of its own.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{json, Value};
use socket_patch_core::bazel::exec::{self, Kept, Overlay, Scope, Selector, Txn};
use socket_patch_core::bazel::gate::{self, gate, GateCx};
use socket_patch_core::bazel::inventory;
use socket_patch_core::bazel::java_hash::hash_bytes;
use socket_patch_core::bazel::lanes::{self, refuse};
use socket_patch_core::bazel::model::{
    Anchor, AttestBasis, BazelRef, BazelWorkspace, CellClaim, ClaimSystem, Code, FileText,
    FileView, Files, GateOutcome, Governance, HubId, Index, IndexRow, LaneCx, LaneId, LaneOps,
    LaneSpec, LaneTable, Lift, Mode, OwnedWrite, PatchRequest, PinSource, Plan, PlannedWrite,
    Reason, RestoreOutcome, RootRef, Ruleset, RunPolicy, TextRead, TokenSurface, VexWithhold,
    WithholdKind, WriteClass,
};
use socket_patch_core::bazel::owned_index::{IndexEdit, INDEX_PATH};
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::patch::redirect::{DepOverride, FileEdit, Integrity, RewriteResult};
use socket_patch_core::vendor::lock_inventory::{LockIntegrity, LockfileEntry, SourceKind};

const LANE: LaneId = LaneId("H-TOY1");
const LOCK: &str = "toy.lock.json";
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const PURL: &str = "pkg:maven/toy/dep@1.0.0";
const UPSTREAM: &str = "5b850ef1c5b6c9c45330badb880dce1bcf31390ea60f25800a142825327121b8";
const PATCHED: &str = "0f4e2bd7a1c38e6f95d7b21a4c60e8f3b9d5a7c1e2f4068a9bc3d5e7f1a2b4c6";
const PATCH_URL: &str = "https://patch.socket.dev/toy/tok_fixture_4f1c/dep-1.0.0.sh";

const MODULE: &str = "module(name = \"toy_ws\")\n\
    bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
    maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
    maven.install(name = \"maven\", artifacts = [\"toy:dep:1.0.0\"], \
    lock_file = \"//:toy.lock.json\")\n\
    use_repo(maven, \"maven\")\n";

/// The lock of the `core/` fixture, byte for byte.
const INPUT: &str = "{\n  \"lockVersion\": 1,\n  \"packages\": {\n    \"dep\": {\n      \
    \"version\": \"1.0.0\",\n      \
    \"url\": \"https://registry.toy.invalid/dep/-/dep-1.0.0.sh\",\n      \
    \"sha256\": \"5b850ef1c5b6c9c45330badb880dce1bcf31390ea60f25800a142825327121b8\"\n    \
    }\n  },\n  \"pinsHash\": -1084610730\n}\n";

const CLAIMS: &[CellClaim] = &[CellClaim {
    lo: "7.2.0",
    hi: "9.3.2",
    system: ClaimSystem::Bzlmod,
}];
const SPEC: LaneSpec = LaneSpec {
    enabled: true,
    supported: CLAIMS,
    token_surfaces: &[TokenSurface::LockFile],
    classes: &[WriteClass::GeneratedValue, WriteClass::Owned],
    ..LaneSpec::stub("H-TOY1", Mode::Hosted, &["X2"])
};
const TOY: LaneOps = LaneOps {
    lanes: &[SPEC],
    gate: toy_gate,
    rewrite_owned: toy_rewrite,
    fixups: toy_fixups,
    discover: toy_discover,
    attest: toy_attest,
    restore: toy_restore,
    inventory: toy_inventory,
};
const TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &TOY)]);

// ── The toy lock ─────────────────────────────────────────────────────

/// The toy registry's URL of a release: what a restore puts back. The
/// index never holds a URL, so the original is derived, not recorded.
fn upstream_url(name: &str, version: &str) -> String {
    format!("https://registry.toy.invalid/{name}/-/{name}-{version}.sh")
}

fn member<'a>(doc: &'a Value, name: &str, key: &str) -> Option<&'a str> {
    doc.get("packages")?.get(name)?.get(key)?.as_str()
}

/// The value the toy extension computes for `pinsHash`.
fn pins_hash(doc: &Value) -> Option<i64> {
    let packages = doc.get("packages")?.as_object()?;
    let mut names: Vec<&String> = packages.keys().collect();
    names.sort();
    let mut pins = String::new();
    for name in names {
        pins.push_str(&format!(
            "{name} {}\n",
            packages[name].get("sha256")?.as_str()?
        ));
    }
    Some(i64::from(hash_bytes(pins.as_bytes())))
}

fn parse(text: &str) -> Option<Value> {
    let doc: Value = serde_json::from_str(text).ok()?;
    (doc.get("lockVersion")?.as_i64()? == 1 && doc.get("pinsHash")?.is_i64()).then_some(doc)
}

/// Replaces one string member of a package in place: only the bytes of
/// the value change, so the file's layout, line endings and final newline
/// stay the user's.
fn set_member(text: &mut String, name: &str, key: &str, old: &str, new: &str) -> bool {
    let Some(package) = text.find(&format!("\"{name}\": {{")) else {
        return false;
    };
    let wanted = format!("\"{key}\": \"{old}\"");
    let Some(at) = text[package..].find(&wanted) else {
        return false;
    };
    let value = package + at + wanted.len() - old.len() - 1;
    text.replace_range(value..value + old.len(), new);
    true
}

fn set_pins_hash(text: &mut String, new: i64) -> bool {
    let key = "\"pinsHash\": ";
    let Some(at) = text.find(key).map(|at| at + key.len()) else {
        return false;
    };
    let digits = |c: char| !(c.is_ascii_digit() || c == '-');
    let end = text[at..].find(digits).map_or(text.len(), |end| at + end);
    text.replace_range(at..end, &new.to_string());
    true
}

fn lock_of(cx: &LaneCx<'_>) -> Option<String> {
    cx.ws.hubs.get(cx.hub.0)?.locks.first()?.path.clone()
}

fn sha_key(name: &str) -> String {
    format!("packages/{name}/sha256")
}

// ── The lane ─────────────────────────────────────────────────────────

fn toy_gate(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
    let cannot = |token: &'static str, why: &str| {
        GateOutcome::Refuse(refuse(
            Reason::RulesetUnsupported,
            token,
            why,
            Lift::EnableLane(LANE),
        ))
    };
    let hub = &cx.ws.hubs[cx.hub.0];
    if let Err(refusal) = gate::version_gate(hub, "6.0", "rules_jvm_external 6.0") {
        return GateOutcome::Refuse(refusal);
    }
    let Some(lock) = lock_of(cx) else {
        return cannot("lock_format", "the hub names no lock");
    };
    let found = cx.files.read(&lock);
    let Some(doc) = found.as_str().and_then(parse) else {
        return cannot("lock_format", "the lock is not a toy lock");
    };
    // The lock of this hub does not resolve the release: the hub is no
    // part of the lock set, and the other hubs decide.
    if member(&doc, req.name, "version") != Some(req.version) {
        return GateOutcome::NotBazel;
    }
    // A derived value that is wrong before the edit is not ours to fix.
    if pins_hash(&doc) != doc["pinsHash"].as_i64() {
        let why = "`pinsHash` did not match the pins before the edit";
        let lift = Lift::EnableLane(LANE);
        return GateOutcome::Refuse(refuse(
            Reason::DerivedUnrepairable,
            "hash_file_mismatch",
            why,
            lift,
        ));
    }
    let value = |key: String| PlannedWrite::GeneratedValue {
        path: lock.clone(),
        key,
    };
    GateOutcome::Proceed(Plan {
        uuid: req.uuid.to_string(),
        lane: LANE,
        writes: vec![
            value(sha_key(req.name)),
            value("pinsHash".to_string()),
            PlannedWrite::Owned(OwnedWrite::Index),
        ],
        repositories: Vec::new(),
        artifacts: Vec::new(),
        advisories: Vec::new(),
        attest: AttestBasis::BazelLock,
        anchor: Anchor::Digest,
    })
}

fn edit(path: &str, key: &str, original: &str, new: &str) -> FileEdit {
    FileEdit {
        path: path.to_string(),
        kind: "toy-lock".to_string(),
        action: "set".to_string(),
        key: Some(key.to_string()),
        original: Some(json!(original)),
        new: Some(json!(new)),
    }
}

/// The pin: the package's URL and digest become the patch's.
fn toy_rewrite(cx: &LaneCx<'_>, files: &mut Files, pins: &[PinSource], result: &mut RewriteResult) {
    let Some(lock) = lock_of(cx) else { return };
    let Some(mut text) = files.get(&lock).cloned() else {
        return;
    };
    // A hosted lane: a vendored pin is not this writer's.
    let hosted = pins.iter().filter_map(|pin| match pin {
        PinSource::Hosted(dep) => Some(dep),
        PinSource::Vendored(_) => None,
    });
    for dep in hosted {
        let (Some(doc), Some(sha256)) = (parse(&text), dep.integrity.sha256.as_deref()) else {
            continue;
        };
        let locked = |key| member(&doc, &dep.name, key).map(str::to_string);
        let (Some(url), Some(old)) = (locked("url"), locked("sha256")) else {
            continue;
        };
        if locked("version").as_deref() != Some(dep.version.as_str()) || old == sha256 {
            continue;
        }
        let pinned = set_member(&mut text, &dep.name, "url", &url, &dep.artifact_url)
            && set_member(&mut text, &dep.name, "sha256", &old, sha256);
        if pinned {
            result
                .edits
                .push(edit(&lock, &sha_key(&dep.name), &old, sha256));
        }
    }
    if files.get(&lock) != Some(&text) {
        result.files.insert(lock.clone(), text.clone());
        files.insert(lock, text);
    }
}

/// The derived value, recomputed from the pins the rewrite left.
fn toy_fixups(cx: &LaneCx<'_>, files: &mut Files, plan: &Plan, result: &mut RewriteResult) {
    let Some(lock) = lock_of(cx) else { return };
    let planned = PlannedWrite::GeneratedValue {
        path: lock.clone(),
        key: "pinsHash".to_string(),
    };
    let Some(text) = files
        .get_mut(&lock)
        .filter(|_| plan.writes.contains(&planned))
    else {
        return;
    };
    let Some(doc) = parse(text) else { return };
    let (Some(old), Some(new)) = (doc["pinsHash"].as_i64(), pins_hash(&doc)) else {
        return;
    };
    if old != new && set_pins_hash(text, new) {
        result
            .edits
            .push(edit(&lock, "pinsHash", &old.to_string(), &new.to_string()));
        result.files.insert(lock, text.clone());
    }
}

/// The digest a row put into the lock for its package.
fn pinned_digest(row: &IndexRow) -> Option<(&str, &str)> {
    row.edits.iter().find_map(|edit| {
        let name = edit
            .key
            .strip_prefix("packages/")?
            .strip_suffix("/sha256")?;
        Some((name, edit.new.as_str()))
    })
}

/// A pin is a row whose digest the lock still holds. A pin the ruleset's
/// own tooling erased is not listed; a lock that cannot be read is
/// "cannot tell".
fn toy_discover(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<BazelRef>> {
    let lock = lock_of(cx)?;
    let doc = parse(&read(&lock)?)?;
    let rows = cx
        .index
        .pins
        .iter()
        .filter(|row| row.lane == LANE.0 && row.file == lock);
    let held = rows.filter(|row| {
        pinned_digest(row)
            .is_some_and(|(name, digest)| member(&doc, name, "sha256") == Some(digest))
    });
    let pin = |row: &IndexRow| BazelRef {
        lane: LANE,
        purl: row.purl.clone(),
        uuid: row.uuid.clone(),
        file: lock.clone(),
        basis: AttestBasis::BazelLock,
    };
    Some(held.map(pin).collect())
}

/// The consumer proof, re-run at discovery: the lock still loads (its
/// derived value matches), it holds the digest the row recorded, and
/// nothing bypasses the hub now.
fn toy_attest(cx: &LaneCx<'_>, pin: &BazelRef) -> Result<(), VexWithhold> {
    let withhold = |kind, detail: &str| VexWithhold {
        kind,
        token: None,
        detail: detail.to_string(),
    };
    let doc = cx.files.read(&pin.file).as_str().and_then(parse);
    let Some(doc) = doc else {
        return Err(withhold(
            WithholdKind::ConsumerUndetermined,
            "the lock cannot be read",
        ));
    };
    let row = cx
        .index
        .pins
        .iter()
        .find(|row| row.uuid == pin.uuid && row.file == pin.file);
    let Some((name, digest)) = row.and_then(pinned_digest) else {
        return Err(withhold(
            WithholdKind::NotConsumed,
            "no index row records the pin",
        ));
    };
    if member(&doc, name, "sha256") != Some(digest) {
        return Err(withhold(
            WithholdKind::DerivedStale,
            "the pinned digest is not the patch's",
        ));
    }
    if pins_hash(&doc) != doc["pinsHash"].as_i64() {
        return Err(withhold(
            WithholdKind::DerivedStale,
            "`pinsHash` disagrees with the pins",
        ));
    }
    let request = PatchRequest {
        ecosystem: Ecosystem::Maven,
        name,
        version: member(&doc, name, "version").unwrap_or_default(),
        uuid: &pin.uuid,
        project_rel: "",
    };
    // The toy hub is the one repository the package is built from: the
    // plan names no other, and neither does the proof.
    gate::no_bypass(cx.ws, cx.index, cx.hub, &request, LANE, &[])
        .map_err(|refusal| withhold(WithholdKind::PinBypassed, &refusal.detail))
}

/// The offline undo of one row: each value goes back only from the value
/// the row wrote, and the result must be a lock that loads.
fn toy_restore(_: &LaneCx<'_>, files: &mut Files, row: &IndexRow) -> RestoreOutcome {
    let drifted = |what: &str| RestoreOutcome::Drifted(format!("{}: {what}", row.file));
    let Some(mut text) = files.get(&row.file).cloned() else {
        return drifted("the lock is gone");
    };
    for edit in row.edits.iter().rev() {
        let Some(doc) = parse(&text) else {
            return drifted("it is not a toy lock");
        };
        let restored = match edit
            .key
            .strip_prefix("packages/")
            .and_then(|key| key.strip_suffix("/sha256"))
        {
            None if edit.key == "pinsHash" => {
                doc["pinsHash"]
                    .as_i64()
                    .map(|now| now.to_string())
                    .as_deref()
                    == Some(edit.new.as_str())
                    && edit
                        .original
                        .parse()
                        .is_ok_and(|original| set_pins_hash(&mut text, original))
            }
            None => false,
            Some(name) => {
                let (url, version) = (member(&doc, name, "url"), member(&doc, name, "version"));
                let (Some(url), Some(version)) = (url.map(str::to_string), version) else {
                    return drifted("the package is gone");
                };
                let upstream = upstream_url(name, version);
                set_member(&mut text, name, "sha256", &edit.new, &edit.original)
                    && set_member(&mut text, name, "url", &url, &upstream)
            }
        };
        if !restored {
            return drifted(&format!(
                "`{}` is no longer the value socket-patch wrote",
                edit.key
            ));
        }
    }
    let loads = parse(&text).is_some_and(|doc| pins_hash(&doc) == doc["pinsHash"].as_i64());
    if !loads {
        return drifted("the restored lock would not load");
    }
    files.insert(row.file.clone(), text);
    RestoreOutcome::Restored
}

fn toy_inventory(cx: &LaneCx<'_>, read: TextRead<'_>) -> Option<Vec<LockfileEntry>> {
    let doc = parse(&read(&lock_of(cx)?)?)?;
    let packages = doc.get("packages")?.as_object()?;
    let entry = |(name, package): (&String, &Value)| {
        let version = package.get("version")?.as_str()?;
        Some(LockfileEntry {
            ecosystem: "maven",
            name: name.clone(),
            version: version.to_string(),
            purl: format!("pkg:maven/toy/{name}@{version}"),
            resolved: package.get("url")?.as_str().map(str::to_string),
            integrity: LockIntegrity::Sha256Hex(package.get("sha256")?.as_str()?.to_string()),
            source_kind: SourceKind::Unspecified,
            pnpm_env: false,
        })
    };
    packages.iter().map(entry).collect()
}

// ── The harness ──────────────────────────────────────────────────────

/// The files of one root, in memory.
#[derive(Clone, Default, PartialEq, Debug)]
struct Tree(BTreeMap<String, Vec<u8>>);

impl Tree {
    fn of(files: &[(&str, &str)]) -> Self {
        let file = |(path, text): &(&str, &str)| (path.to_string(), text.as_bytes().to_vec());
        Self(files.iter().map(file).collect())
    }

    fn text(&self, path: &str) -> String {
        String::from_utf8(self.0[path].clone()).expect("a text file")
    }

    /// Lands what a transaction staged.
    fn commit(&mut self, staged: &BTreeMap<String, Option<Vec<u8>>>) {
        for (path, bytes) in staged {
            match bytes {
                Some(bytes) => drop(self.0.insert(path.clone(), bytes.clone())),
                None => drop(self.0.remove(path)),
            }
        }
    }
}

impl FileView for Tree {
    fn read(&self, rel: &str) -> FileText {
        self.0
            .get(rel)
            .map_or(FileText::Absent, |bytes| FileText::Bytes(bytes.clone()))
    }

    fn list(&self, dir: &str) -> Option<Vec<String>> {
        let prefix = if dir.is_empty() {
            String::new()
        } else {
            format!("{dir}/")
        };
        let mut names: Vec<String> = Vec::new();
        for rest in self.0.keys().filter_map(|path| path.strip_prefix(&prefix)) {
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

fn workspace(tree: &Tree) -> BazelWorkspace {
    let root = RootRef {
        root: PathBuf::from("repo"),
        project_rel: String::new(),
        boundary_levels: 0,
    };
    socket_patch_core::bazel::detect(&root, tree).expect("a Bazel workspace")
}

/// The toy workspace on Bazel 9.3.2 with `lock` as its toy lock.
fn toy_tree(lock: &str, extra: &[(&str, &str)]) -> Tree {
    let mut files = vec![
        (".bazelversion", "9.3.2\n"),
        ("MODULE.bazel", MODULE),
        (LOCK, lock),
    ];
    files.extend_from_slice(extra);
    Tree::of(&files)
}

fn request() -> PatchRequest<'static> {
    PatchRequest {
        ecosystem: Ecosystem::Maven,
        name: "dep",
        version: "1.0.0",
        uuid: UUID,
        project_rel: "",
    }
}

fn grant() -> DepOverride {
    DepOverride {
        ecosystem: "maven".to_string(),
        name: "dep".to_string(),
        namespace: None,
        version: "1.0.0".to_string(),
        token: "tok_fixture_4f1c".to_string(),
        patch_uuid: UUID.to_string(),
        artifact_url: PATCH_URL.to_string(),
        registry_override: None,
        integrity: Integrity {
            sha256: Some(PATCHED.to_string()),
            ..Integrity::default()
        },
    }
}

fn ask(tree: &Tree, ws: &BazelWorkspace, index: &Index) -> GateOutcome {
    let cx = GateCx {
        patch_url: Some(PATCH_URL),
        ..GateCx::new(Mode::Hosted, ws, tree, index)
    };
    gate(&cx, &TABLE, &request())
}

fn lane_cx<'a>(tree: &'a Tree, ws: &'a BazelWorkspace, index: &'a Index) -> LaneCx<'a> {
    LaneCx {
        mode: Mode::Hosted,
        files: tree,
        ws,
        hub: HubId(0),
        index,
        run: RunPolicy::Never,
    }
}

/// The forward path of a hosted write, as the rewriter group will run it:
/// the gate, the lane's rewrite and fixups on the candidate texts, the
/// `pins` row from the edits they report, then the executor.
fn wire(tree: &mut Tree, index: &mut Index) -> Plan {
    let ws = workspace(tree);
    let plan = match ask(tree, &ws, index) {
        GateOutcome::Proceed(plan) => plan,
        other => panic!("the gate did not pass the toy lane: {other:?}"),
    };
    let mut files: Files = [(LOCK.to_string(), tree.text(LOCK))].into();
    let mut result = RewriteResult::default();
    {
        let cx = lane_cx(tree, &ws, index);
        (TOY.rewrite_owned)(&cx, &mut files, &[PinSource::Hosted(grant())], &mut result);
        (TOY.fixups)(&cx, &mut files, &plan, &mut result);
    }
    let text = |value: &Option<Value>| value.as_ref().and_then(Value::as_str).unwrap().to_string();
    let edits = result.edits.iter().map(|edit| IndexEdit {
        key: edit.key.clone().unwrap(),
        original: text(&edit.original),
        new: text(&edit.new),
    });
    index.record_pin(IndexRow {
        uuid: UUID.to_string(),
        purl: PURL.to_string(),
        lane: LANE.0.to_string(),
        file: LOCK.to_string(),
        edits: edits.collect(),
        check: None,
    });
    let staged = {
        let mut txn = Overlay::new(&*tree);
        for (path, text) in &result.files {
            txn.write(path, text.clone().into_bytes());
        }
        let applied =
            exec::apply(&ws, index, std::slice::from_ref(&plan), &mut txn).expect("apply");
        assert_eq!(
            applied.written,
            [INDEX_PATH],
            "the executor stages the record, the lane its lock"
        );
        txn.changes().clone()
    };
    tree.commit(&staged);
    plan
}

fn revert(tree: &mut Tree, index: &mut Index, scope: Scope) -> exec::Reverted {
    let ws = workspace(tree);
    let before = index.clone();
    let (reverted, staged) = {
        let pins = lanes::Restore {
            lanes: &TABLE,
            ws: &ws,
            files: &*tree,
            index: &before,
        };
        let mut txn = Overlay::new(&*tree);
        let which = Selector { scope, pins: &pins };
        let reverted = exec::revert(&ws, index, &which, &mut txn);
        (reverted, txn.changes().clone())
    };
    tree.commit(&staged);
    reverted
}

// ── The cases ────────────────────────────────────────────────────────

/// Gate, rewrite, fixups, executor, discovery, attestation, inventory,
/// repair and restore over the toy lock, with LF and with CRLF line
/// endings: the wire changes exactly the pin and its derived value, and
/// the restore returns the input byte for byte.
#[test]
fn the_toy_lane_wires_attests_and_restores_byte_for_byte() {
    for input in [INPUT.to_string(), INPUT.replace('\n', "\r\n")] {
        let crlf = input.contains('\r');
        let before = toy_tree(&input, &[]);
        let (mut tree, mut index) = (before.clone(), Index::default());
        let plan = wire(&mut tree, &mut index);
        assert_eq!(
            (plan.lane, plan.attest, plan.anchor),
            (LANE, AttestBasis::BazelLock, Anchor::Digest)
        );

        // Exactly the URL, the digest and the derived value changed.
        let wired = tree.text(LOCK);
        let expected = input
            .replace(&upstream_url("dep", "1.0.0"), PATCH_URL)
            .replace(UPSTREAM, PATCHED)
            .replace(
                "-1084610730",
                &pins_hash(&parse(&wired).unwrap()).unwrap().to_string(),
            );
        assert_eq!(wired, expected, "crlf={crlf}");
        assert_ne!(wired, input);
        assert_eq!(wired.contains("\r\n"), crlf);
        // The record holds digests and the derived value, never the URL.
        let record = tree.text(INDEX_PATH);
        assert!(
            record.contains(PATCHED) && record.contains(UPSTREAM) && !record.contains("://"),
            "{record}"
        );
        let changed: Vec<&String> = tree
            .0
            .keys()
            .filter(|path| tree.0.get(*path) != before.0.get(*path))
            .collect();
        assert_eq!(changed, [INDEX_PATH, LOCK]);

        // Discovery, the consumer proof and the inventory, from committed state.
        let ws = workspace(&tree);
        let read = |path: &str| tree.read(path).as_str().map(str::to_string);
        let found = lanes::discover(&TABLE, &ws, &tree, &index, &read);
        assert!(found.is_complete(), "the lane can tell: {found:?}");
        let [pin] = &found.pins[..] else {
            panic!("one pin: {found:?}")
        };
        assert_eq!(
            (
                pin.lane,
                pin.purl.as_str(),
                pin.uuid.as_str(),
                pin.file.as_str()
            ),
            (LANE, PURL, UUID, LOCK)
        );
        let cx = lane_cx(&tree, &ws, &index);
        assert_eq!((TOY.attest)(&cx, pin), Ok(()));
        let listed = (TOY.inventory)(&cx, &read).expect("the lock lists its packages");
        assert_eq!(listed.len(), 1);
        assert_eq!(
            listed[0].integrity,
            LockIntegrity::Sha256Hex(PATCHED.to_string())
        );
        // A second run finds the pin in place and plans the same writes,
        // and the rewrite changes nothing.
        assert_eq!(ask(&tree, &ws, &index), GateOutcome::Proceed(plan.clone()));
        let (mut files, mut again) = (
            Files::from([(LOCK.to_string(), wired.clone())]),
            RewriteResult::default(),
        );
        (TOY.rewrite_owned)(&cx, &mut files, &[PinSource::Hosted(grant())], &mut again);
        (TOY.fixups)(&cx, &mut files, &plan, &mut again);
        assert!(again.edits.is_empty() && again.files.is_empty() && files[LOCK] == wired);

        // Repair has nothing to do. A record that is gone is reported and
        // never rendered back from memory: the rows live in the file.
        let mut txn = Overlay::new(&tree);
        assert_eq!(
            exec::reconcile(&ws, &index, &mut txn),
            exec::Reconciled::default()
        );
        let mut lost = tree.clone();
        lost.0.remove(INDEX_PATH);
        let mut txn = Overlay::new(&lost);
        let repaired = exec::reconcile(&ws, &index, &mut txn);
        let gone = exec::Finding {
            path: INDEX_PATH.to_string(),
            state: exec::OwnedState::Index(exec::IndexFault::Missing),
        };
        assert_eq!((repaired.written.len(), repaired.findings), (0, vec![gone]));
        assert!(txn.changes().is_empty());

        // The undo goes through the executor and the lane's restore.
        let reverted = revert(&mut tree, &mut index, Scope::Uuid(UUID.to_string()));
        assert_eq!((reverted.dropped, &reverted.kept), (1, &Vec::new()));
        assert_eq!(reverted.written, [LOCK, INDEX_PATH]);
        assert_eq!(tree, before, "crlf={crlf}: the restore is byte-exact");
        assert!(index.is_empty());
        let ws = workspace(&tree);
        let read = |path: &str| tree.read(path).as_str().map(str::to_string);
        assert_eq!(
            lanes::discover(&TABLE, &ws, &tree, &index, &read),
            lanes::Discovered::default()
        );
    }
}

/// What is wired stops being attested, and is not undone on a guess, once
/// the committed state no longer is what the lane wrote.
#[test]
fn a_tampered_or_drifted_toy_lock_is_not_attested_and_not_restored() {
    let (mut tree, mut index) = (toy_tree(INPUT, &[]), Index::default());
    wire(&mut tree, &mut index);
    let wired = tree.clone();
    let pin = BazelRef {
        lane: LANE,
        purl: PURL.to_string(),
        uuid: UUID.to_string(),
        file: LOCK.to_string(),
        basis: AttestBasis::BazelLock,
    };
    let verdict = |tree: &Tree, index: &Index| {
        let ws = workspace(tree);
        (TOY.attest)(&lane_cx(tree, &ws, index), &pin).map_err(|withheld| withheld.kind)
    };
    let with_lock = |text: String| {
        let mut tree = wired.clone();
        tree.0.insert(LOCK.to_string(), text.into_bytes());
        tree
    };
    assert_eq!(verdict(&wired, &index), Ok(()));
    // The ruleset's own tooling put the upstream digest back.
    let erased = with_lock(wired.text(LOCK).replace(PATCHED, UPSTREAM));
    assert_eq!(verdict(&erased, &index), Err(WithholdKind::DerivedStale));
    let ws = workspace(&erased);
    let read = |path: &str| erased.read(path).as_str().map(str::to_string);
    assert_eq!(
        lanes::discover(&TABLE, &ws, &erased, &index, &read),
        lanes::Discovered::default()
    );
    // The digest is the patch's and the derived value is not: the lock would not load.
    let hash = pins_hash(&parse(&wired.text(LOCK)).unwrap())
        .unwrap()
        .to_string();
    let stale = with_lock(wired.text(LOCK).replace(&hash, "7"));
    assert_eq!(verdict(&stale, &index), Err(WithholdKind::DerivedStale));
    // No row, an unreadable lock, and a bypass that appeared after the write.
    assert_eq!(
        verdict(&wired, &Index::default()),
        Err(WithholdKind::NotConsumed)
    );
    assert_eq!(
        verdict(&with_lock("{".to_string()), &index),
        Err(WithholdKind::ConsumerUndetermined)
    );
    let mut overridden = wired.clone();
    overridden.0.insert(
        ".bazelrc".to_string(),
        b"common --override_repository=maven=/elsewhere\n".to_vec(),
    );
    assert_eq!(verdict(&overridden, &index), Err(WithholdKind::PinBypassed));
    let unreadable = with_lock("{".to_string());
    let ws = workspace(&unreadable);
    let read = |path: &str| unreadable.read(path).as_str().map(str::to_string);
    let found = lanes::discover(&TABLE, &ws, &unreadable, &index, &read);
    assert_eq!(
        (found.pins.len(), found.unknown_for(Ecosystem::Maven)),
        (0, Some(HubId(0))),
        "cannot tell, never no pin"
    );

    // A restore over a value socket-patch did not write keeps the row and the file.
    for drifted in [erased, stale] {
        let (mut tree, mut held) = (drifted.clone(), index.clone());
        let reverted = revert(&mut tree, &mut held, Scope::All);
        assert_eq!(reverted.dropped, 0);
        assert!(
            matches!(
                &reverted.kept[..],
                [Kept::Pin {
                    outcome: RestoreOutcome::Drifted(_),
                    ..
                }]
            ),
            "{reverted:?}"
        );
        assert!(reverted.written.is_empty());
        assert_eq!((tree, held), (drifted, index.clone()));
    }
}

/// The toy lane is refused wherever the gate or the lane cannot prove
/// the write, and nothing is planned.
#[test]
fn the_gate_refuses_the_toy_lane_where_the_write_cannot_be_proven() {
    let refused = |tree: &Tree| {
        let ws = workspace(tree);
        match ask(tree, &ws, &Index::default()) {
            GateOutcome::Refuse(refusal) => {
                assert!(
                    refusal.detail.ends_with("; nothing was written"),
                    "{refusal:?}"
                );
                assert!(
                    !format!("{refusal:?}").contains("tok_fixture"),
                    "{refusal:?}"
                );
                assert!(!refusal.lift.is_final());
                (refusal.reason, refusal.token)
            }
            other => panic!("not refused: {other:?}"),
        }
    };
    // The lane's own gates: the derived value was wrong before the edit,
    // the release is not the locked one, the lock is another format.
    let mismatch = toy_tree(&INPUT.replace("-1084610730", "12"), &[]);
    assert_eq!(
        refused(&mismatch),
        (Reason::DerivedUnrepairable, "hash_file_mismatch")
    );
    // The one hub does not resolve the release: refused, and never
    // passed on as "not a Bazel matter".
    let other = toy_tree(&INPUT.replace("\"1.0.0\"", "\"2.0.0\""), &[]);
    assert_eq!(
        refused(&other),
        (Reason::ConsumerUndetermined, gate::NOT_RESOLVED_BY_HUB)
    );
    assert_eq!(
        refused(&toy_tree("{}\n", &[])),
        (Reason::RulesetUnsupported, "lock_format")
    );
    // The gate's: a bypass, a blocked patch host, a frozen lock that records the file.
    let bypassed = toy_tree(
        INPUT,
        &[(
            ".bazelrc",
            "common --override_repository=rules_jvm_external++maven+maven=/d\n",
        )],
    );
    assert_eq!(refused(&bypassed), (Reason::PinBypassed, "repo_override"));
    let config = [
        (".bazelrc", "common --downloader_config=dl.cfg\n"),
        ("dl.cfg", "block patch.socket.dev\n"),
    ];
    assert_eq!(
        refused(&toy_tree(INPUT, &config)),
        (Reason::FetchBlocked, "downloader_config")
    );
    // The production table has the designed lane for the hub, disabled.
    let tree = toy_tree(INPUT, &[]);
    let (ws, index) = (workspace(&tree), Index::default());
    let cx = GateCx {
        patch_url: Some(PATCH_URL),
        ..GateCx::new(Mode::Hosted, &ws, &tree, &index)
    };
    // The expectation is computed (`lanes::admits`), so the change that
    // enables H-MVN1 does not turn this red.
    let cell = lanes::Cell::of(&ws, HubId(0), Mode::Hosted).unwrap();
    assert!(lanes::admits(&TABLE, &cell));
    let not_enabled = ("lane_not_enabled", Lift::EnableLane(LaneId("H-MVN1")));
    match gate(&cx, &lanes::PRODUCTION, &request()) {
        GateOutcome::Refuse(refusal) if !lanes::admits(&lanes::PRODUCTION, &cell) => {
            assert_eq!((refusal.token, refusal.lift), not_enabled);
        }
        GateOutcome::Refuse(refusal) => {
            assert_ne!(
                (refusal.token, refusal.lift),
                not_enabled,
                "an admitted cell"
            );
        }
        _ => assert!(lanes::admits(&lanes::PRODUCTION, &cell)),
    }
    // A lane that edits the lock and does not recompute its derived value
    // is refused by the gate: the resolved hash would be stale.
    fn careless(cx: &LaneCx<'_>, req: &PatchRequest<'_>) -> GateOutcome {
        let path = lock_of(cx).unwrap_or_default();
        GateOutcome::Proceed(Plan {
            uuid: req.uuid.to_string(),
            lane: LANE,
            writes: vec![PlannedWrite::NativeLock { path }],
            repositories: Vec::new(),
            artifacts: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::BazelLock,
            anchor: Anchor::Digest,
        })
    }
    const NATIVE: LaneSpec = LaneSpec {
        classes: &[WriteClass::NativeLock],
        ..SPEC
    };
    const CARELESS: LaneOps = LaneOps {
        lanes: &[NATIVE],
        gate: careless,
        ..TOY
    };
    const CARELESS_TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJvmExternal, &CARELESS)]);
    let GateOutcome::Refuse(refusal) = gate(&cx, &CARELESS_TABLE, &request()) else {
        panic!("a stale derived value passed the gate");
    };
    assert_eq!(
        (refusal.reason, refusal.lift),
        (Reason::DerivedUnrepairable, Lift::EnableLane(LANE))
    );
    assert!(
        refusal.detail.contains("ResolvedHash"),
        "{}",
        refusal.detail
    );
}

// ── Several hubs ─────────────────────────────────────────────────────

/// Two hubs of the toy ruleset over the root project, a lock each.
const TWO_HUBS: &str = "module(name = \"toy_ws\")\n\
    bazel_dep(name = \"rules_jvm_external\", version = \"6.7\")\n\
    maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
    maven.install(name = \"maven\", artifacts = [\"toy:dep:1.0.0\"], \
    lock_file = \"//:toy.lock.json\")\n\
    maven.install(name = \"maven_tools\", artifacts = [\"toy:other:2.0.0\"], \
    lock_file = \"//:tools.lock.json\")\n\
    use_repo(maven, \"maven\", \"maven_tools\")\n";
const TOOLS_LOCK: &str = "tools.lock.json";

/// A hand-written jar pin: a hub of the ecosystem that names no lock.
const HTTP_JAR: &str = "http_jar = use_repo_rule(\
    \"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_jar\")\n\
    http_jar(name = \"some_jar\", url = \"https://repo.toy.invalid/a.jar\")\n";

/// The toy lock with its one package renamed, and the derived value
/// those pins give.
fn toy_lock(name: &str, version: &str) -> String {
    let mut text = INPUT
        .replace("\"dep\"", &format!("\"{name}\""))
        .replace("\"1.0.0\"", &format!("\"{version}\""));
    let hash = pins_hash(&parse(&text).expect("a toy lock")).expect("its pins");
    assert!(set_pins_hash(&mut text, hash));
    text
}

/// The locks a plan writes values in, each once, in plan order.
fn locks_of(plan: &Plan) -> Vec<&str> {
    let mut paths: Vec<&str> = Vec::new();
    for write in &plan.writes {
        if let PlannedWrite::GeneratedValue { path, .. } = write {
            if !paths.contains(&path.as_str()) {
                paths.push(path);
            }
        }
    }
    paths
}

/// The lock set is the hubs that pin the package (design 6,
/// `lock_set_partial`): "every lock that pins a package is rewritten or
/// none is". A hub whose lock does not resolve the release holds nothing
/// up, whether its lane says so or the gate refused it before the lane
/// was asked; a hub that pins it and cannot be rewritten refuses all.
#[test]
fn the_lock_set_is_the_hubs_whose_locks_resolve_the_release() {
    let tree = |tools: &str, rc: &str| {
        Tree::of(&[
            (".bazelversion", "9.3.2\n"),
            (".bazelrc", rc),
            ("MODULE.bazel", TWO_HUBS),
            (LOCK, INPUT),
            (TOOLS_LOCK, tools),
        ])
    };
    let outcome = |tree: &Tree| {
        let ws = workspace(tree);
        let governed = gate::governed(&ws, "");
        let maven = governed.iter().find(|(e, _)| *e == Ecosystem::Maven);
        assert_eq!(
            maven.map(|(_, governance)| governance),
            Some(&Governance::Governed(vec![HubId(0), HubId(1)])),
            "both hubs govern the root"
        );
        ask(tree, &ws, &Index::default())
    };
    let refusal_of = |outcome: GateOutcome| match outcome {
        GateOutcome::Refuse(refusal) => {
            assert!(
                !format!("{refusal:?}").contains("tok_fixture"),
                "{refusal:?}"
            );
            (refusal.reason, refusal.token)
        }
        other => panic!("not refused: {other:?}"),
    };
    let other = toy_lock("other", "2.0.0");

    // The package is pinned in one of the two locks: that lock alone is
    // planned. The lane of the second hub answers "not here".
    let GateOutcome::Proceed(plan) = outcome(&tree(&other, "")) else {
        panic!("a hub that does not pin the package held the other up");
    };
    assert_eq!(locks_of(&plan), [LOCK]);
    assert!(plan.advisories.is_empty());
    // Pinned in both: one plan over both locks.
    let GateOutcome::Proceed(plan) = outcome(&tree(INPUT, "")) else {
        panic!("two hubs that pin the package are one plan");
    };
    assert_eq!(locks_of(&plan), [LOCK, TOOLS_LOCK]);
    // Pinned in both, and one of the two cannot be rewritten: none is.
    let broken = INPUT.replace("-1084610730", "12");
    assert_eq!(
        refusal_of(outcome(&tree(&broken, ""))),
        (Reason::LockSetPartial, "hash_file_mismatch")
    );
    // Pinned in neither: no hub resolves the release.
    let neither = Tree::of(&[
        (".bazelversion", "9.3.2\n"),
        ("MODULE.bazel", TWO_HUBS),
        (LOCK, &other),
        (TOOLS_LOCK, &other),
    ]);
    assert_eq!(
        refusal_of(outcome(&neither)),
        (Reason::ConsumerUndetermined, gate::NOT_RESOLVED_BY_HUB)
    );

    // The second hub is bypassed, so the gate refuses it before its lane
    // is asked. What its lock resolves, as the lane lists it, decides
    // whether that holds the first hub up.
    let bypassed = "common --override_repository=maven_tools=/elsewhere\n";
    let GateOutcome::Proceed(plan) = outcome(&tree(&other, bypassed)) else {
        panic!("a bypassed hub that does not pin the package held the other up");
    };
    assert_eq!(locks_of(&plan), [LOCK]);
    assert_eq!(
        refusal_of(outcome(&tree(INPUT, bypassed))),
        (Reason::LockSetPartial, "repo_override")
    );
    // A lock nobody can list may resolve anything.
    assert_eq!(
        refusal_of(outcome(&tree("{", bypassed))),
        (Reason::LockSetPartial, "repo_override")
    );
}

/// A hand-written jar pin is a hub of the ecosystem at the root. It
/// names no lock, so nothing could be rewritten for it: it is left out
/// of the write set with an advisory, and does not refuse every Maven
/// patch of a workspace that has one. `vex` still withholds, because
/// what the pin fetches cannot be listed.
#[test]
fn a_hand_written_pin_is_left_out_of_the_write_set_with_an_advisory() {
    let module = format!("{MODULE}{HTTP_JAR}");
    let tree = Tree::of(&[
        (".bazelversion", "9.3.2\n"),
        ("MODULE.bazel", &module),
        (LOCK, INPUT),
    ]);
    let (ws, index) = (workspace(&tree), Index::default());
    let shapes: Vec<Ruleset> = ws.hubs.iter().map(|hub| hub.ruleset).collect();
    assert_eq!(shapes, [Ruleset::RulesJvmExternal, Ruleset::ReportOnly]);
    let GateOutcome::Proceed(plan) = ask(&tree, &ws, &index) else {
        panic!("one hand-written pin refused the patch of the hub's lock");
    };
    assert_eq!(locks_of(&plan), [LOCK]);
    let [advisory] = &plan.advisories[..] else {
        panic!("one advisory: {:?}", plan.advisories);
    };
    assert_eq!(advisory.code, Code::WorkspaceOutOfScope);
    assert!(
        advisory.detail.contains("`some_jar`") && advisory.detail.contains("`dep`"),
        "{}",
        advisory.detail
    );
    let listed = inventory::inventory(&ws, &TABLE, &tree, &index);
    let unlisted = listed.cannot_enumerate(Ecosystem::Maven);
    assert_eq!(unlisted.and_then(|hub| hub.hub), Some(HubId(1)));
    // Discovery has nothing to say about it: no lane writes a pin there.
    let read = |path: &str| tree.read(path).as_str().map(str::to_string);
    assert!(lanes::discover(&TABLE, &ws, &tree, &index, &read).is_complete());

    // Alone, it refuses under its own token, and so it does when the
    // hub beside it does not resolve the release.
    for lock in ["{}\n".to_string(), toy_lock("other", "2.0.0")] {
        let alone = Tree::of(&[
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", &module),
            (LOCK, &lock),
        ]);
        let ws = workspace(&alone);
        let GateOutcome::Refuse(refusal) = ask(&alone, &ws, &index) else {
            panic!("nothing takes the patch");
        };
        let lock_format = lock.starts_with("{}");
        let want = match lock_format {
            true => (Reason::RulesetUnsupported, "lock_format"),
            false => (Reason::RulesetUnsupported, "report_only"),
        };
        assert_eq!((refusal.reason, refusal.token), want);
    }
}
