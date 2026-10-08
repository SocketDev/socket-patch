//! Disk side of the JVM backend: write a [`JvmPlan`], record it,
//! and revert it.
//!
//! Records: the planners' fragment records, plus
//! * [`TREE_KIND`] — one per vendored artifact file, `new` = its sha256.
//!   Revert deletes it while the hash still matches;
//! * [`CREATED_DIR_KIND`] — a directory vendor created; removed on revert
//!   once empty.
//!
//! SECURITY: state.json is committed and tamper-able, so every recorded path
//! must be one a planner can produce for the entry's own coordinates, and
//! every path is resolved component by component: a symlink leaving the
//! checkout fails closed (`build_file_outside_root`), one inside it is
//! followed, so a symlinked build file is edited through its link.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::patch::path_safety::is_canonical_uuid;
use crate::utils::fs::{
    atomic_write_bytes_preserving_mode, read_regular_to_bytes_sync, remove_file,
};
use crate::utils::group_commit;
use crate::utils::purl::parse_maven_purl;

use super::super::state::{VendorEntry, WiringAction, WiringRecord};
use super::super::{RevertOpts, RevertOutcome, VendorWarning};
use super::{
    coursier_tree, gradle, layout, maven_reactor, op_of, op_str, sbt, scala_cli, sha256_hex,
    Coords, JvmPlan, JvmUnplan, Shape, CONFIG_LINE_KIND, COURSIER_INDEX_KIND, CREATED_DIR_KIND,
    DERIVED_METADATA_KIND, KINDS, OWNED_FILE_KIND, POM_FRAGMENT_KIND, SBT_FRAGMENT_KIND,
    SETTINGS_FRAGMENT_KIND, TREE_KIND, VERIFICATION_FRAGMENT_KIND,
};

/// Whether `entry` was written by this backend: it has wiring and every
/// record is one of this backend's kinds.
pub fn is_jvm_entry(entry: &VendorEntry) -> bool {
    !entry.wiring.is_empty()
        && entry
            .wiring
            .iter()
            .all(|w| KINDS.contains(&w.kind.as_str()))
}

/// Offline inputs have not been authenticated by independent registry checksums.
pub fn upstream_unverified(entry: &VendorEntry) -> bool {
    is_jvm_entry(entry)
        && !entry
            .wiring
            .iter()
            .any(|w| w.kind == super::UPSTREAM_KIND && op_of(w) == "registry_verified")
}

/// The validated `(group, artifact, version)` of a JVM entry: a maven purl
/// in the JVM coordinate grammar and a canonical uuid.
pub fn entry_gav(entry: &VendorEntry) -> Result<(String, String, String), String> {
    if !is_canonical_uuid(&entry.uuid) {
        return Err(format!("non-canonical patch uuid {:?}", entry.uuid));
    }
    let (g, a, v) = parse_maven_purl(&entry.base_purl)
        .ok_or_else(|| format!("not a maven purl: {:?}", entry.base_purl))?;
    if !layout::safe_coordinates(&g, &a, &v) {
        return Err(format!("unsafe maven coordinates in {:?}", entry.base_purl));
    }
    Ok((g.into_owned(), a.into_owned(), v.into_owned()))
}

/// A project-relative path with no `..`, no empty or absolute segment and
/// no `.git` segment.
fn safe_rel(rel: &str) -> bool {
    !rel.is_empty()
        && !rel.starts_with('/')
        && !rel.contains('\\')
        && !rel.contains(':')
        && rel
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != ".." && !s.eq_ignore_ascii_case(".git"))
}

/// A text file some planner edits or owns.
fn is_wiring_file(rel: &str) -> bool {
    let under_owned = rel.starts_with(".socket/") || rel.starts_with(".mvn/");
    rel == maven_reactor::MAVEN_CONFIG
        || is_owned_file(rel)
        || gradle::is_derived_metadata_path(rel)
        || sbt::is_wiring_file(rel)
        || scala_cli::is_wiring_file(rel)
        || (!under_owned && (rel.ends_with(".xml") || layout::is_gradle_settings(rel)))
}

fn is_owned_file(rel: &str) -> bool {
    [
        maven_reactor::GITATTRIBUTES_REL,
        gradle::GITATTRIBUTES_REL,
        gradle::SCRIPT_GITATTRIBUTES_REL,
        gradle::VENDOR_GITATTRIBUTES_REL,
        gradle::SCRIPT_REL,
        gradle::INDEX_REL,
    ]
    .contains(&rel)
        || sbt::is_owned_file(rel)
        || scala_cli::is_owned_file(rel)
}

/// A file directly in `c`'s own Maven or Gradle version directory.
fn is_own_tree_file(rel: &str, c: &Coords<'_>) -> bool {
    [
        maven_reactor::tree_dir(c),
        gradle::tree_dir(c),
        coursier_tree::tree_dir(c),
    ]
    .iter()
    .any(|dir| {
        rel.strip_prefix(dir.as_str())
            .and_then(|r| r.strip_prefix('/'))
            .is_some_and(|name| !name.is_empty() && !name.contains('/'))
    })
}

/// A directory a plan may create.
fn is_creatable_dir(rel: &str) -> bool {
    rel == ".mvn" || rel == ".socket" || rel.starts_with(".socket/")
}

/// Whether record `w` of the entry for `c` names a path its kind allows.
fn record_allowed(w: &WiringRecord, c: &Coords<'_>) -> bool {
    let rel = w.file.as_str();
    safe_rel(rel)
        && match w.kind.as_str() {
            POM_FRAGMENT_KIND => {
                rel.ends_with(".xml") && !rel.starts_with(".socket/") && !rel.starts_with(".mvn/")
            }
            CONFIG_LINE_KIND => rel == maven_reactor::MAVEN_CONFIG,
            SETTINGS_FRAGMENT_KIND => {
                layout::is_gradle_settings(rel) && !rel.starts_with(".socket/")
            }
            VERIFICATION_FRAGMENT_KIND => rel == gradle::VERIFICATION_REL,
            OWNED_FILE_KIND => is_owned_file(rel),
            DERIVED_METADATA_KIND => rel == gradle::derived_metadata_rel(c.group_id, c.artifact_id),
            SBT_FRAGMENT_KIND => sbt::is_wiring_file(rel),
            COURSIER_INDEX_KIND => {
                rel == coursier_tree::INDEX_REL || scala_cli::is_wiring_file(rel)
            }
            TREE_KIND | super::UPSTREAM_KIND => is_own_tree_file(rel, c),
            CREATED_DIR_KIND => is_creatable_dir(rel),
            _ => false,
        }
}

/// Reads project files for the planners, resolving every path inside the
/// checkout (see the module doc) and honouring an open group commit. The
/// first path that resolved outside the checkout is kept for the caller's
/// refusal.
pub struct ProjectReader {
    root: PathBuf,
    canonical: Option<PathBuf>,
    escaped: RefCell<Option<String>>,
    read_error: RefCell<Option<String>>,
}

impl ProjectReader {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            canonical: std::fs::canonicalize(root).ok(),
            escaped: RefCell::new(None),
            read_error: RefCell::new(None),
        }
    }

    /// Regular files only; a directory, special file or unsafe path reads
    /// as missing.
    pub fn read(&self, rel: &str) -> Option<Vec<u8>> {
        let path = match self.resolve(rel) {
            Ok(path) => path,
            Err(e) => {
                self.read_error.borrow_mut().get_or_insert(e);
                return None;
            }
        };
        match group_commit::read(&path).unwrap_or_else(|| read_regular_to_bytes_sync(&path)) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                self.read_error
                    .borrow_mut()
                    .get_or_insert(format!("{rel}: {e}"));
                None
            }
        }
    }

    /// The children of the project directory `rel` (`""` = the root) for
    /// the script graph: names, directories ending in `/`. Resolved like
    /// [`Self::read`]; anything unsafe or unreadable lists as empty.
    pub fn list(&self, rel: &str) -> Vec<String> {
        let path = if rel.is_empty() {
            match &self.canonical {
                Some(c) => c.clone(),
                None => return Vec::new(),
            }
        } else {
            match self.resolve(rel.trim_end_matches('/')) {
                Ok(path) => path,
                Err(_) => return Vec::new(),
            }
        };
        let mut out: Vec<String> = std::fs::read_dir(path)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                // Followed like `read` (in-checkout links only).
                let dir = e.metadata().ok()?.is_dir()
                    || (e.file_type().ok()?.is_symlink() && e.path().is_dir());
                Some(if dir { format!("{name}/") } else { name })
            })
            .collect();
        out.sort();
        out
    }

    /// The first path that resolved outside the checkout.
    pub fn escaped(&self) -> Option<String> {
        self.escaped.borrow().clone()
    }

    /// `rel` under the canonical root, following in-checkout symlinks.
    fn resolve(&self, rel: &str) -> Result<PathBuf, String> {
        if !safe_rel(rel) {
            return Err(format!("unsafe path {rel:?}"));
        }
        let Some(canonical) = &self.canonical else {
            return Err(format!(
                "cannot resolve project root {}",
                self.root.display()
            ));
        };
        let segments: Vec<&str> = rel.split('/').collect();
        let mut cur = canonical.clone();
        for (i, seg) in segments.iter().enumerate() {
            let next = cur.join(seg);
            match std::fs::symlink_metadata(&next) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(segments[i + 1..].iter().fold(next, |p, s| p.join(s)));
                }
                Err(e) => return Err(format!("cannot inspect {}: {e}", next.display())),
                Ok(meta) if meta.file_type().is_symlink() => {
                    let target = std::fs::canonicalize(&next)
                        .ok()
                        .filter(|t| t.starts_with(canonical));
                    let Some(target) = target else {
                        let at = segments[..=i].join("/");
                        self.escaped.borrow_mut().get_or_insert(at.clone());
                        return Err(format!(
                            "{at} is a symlink that leaves the project (or dangles)"
                        ));
                    };
                    cur = target;
                }
                Ok(_) => cur = next,
            }
        }
        Ok(cur)
    }
}

/// Read a project file for the planners (see [`ProjectReader::read`]).
pub fn read_project_file(root: &Path, rel: &str) -> Option<Vec<u8>> {
    ProjectReader::new(root).read(rel)
}

/// The `build_file_outside_root` refusal detail for `rel`.
pub fn outside_root_detail(rel: &str) -> String {
    format!(
        "reason: build_file_outside_root: {rel} is a symlink that leaves the project (or \
         dangles); vendoring only edits files inside the checkout"
    )
}

/// Whether `existing` at the tree path `rel` is a file an earlier vendoring
/// wrote: listed with its hash in the directory's marker, or the marker.
fn is_vendored_tree_file(reader: &ProjectReader, rel: &str, existing: &[u8]) -> bool {
    let Some((dir, name)) = rel.rsplit_once('/') else {
        return false;
    };
    let parse = |bytes: &[u8]| serde_json::from_slice::<Value>(bytes).ok();
    if name == layout::MARKER_FILE {
        return parse(existing)
            .is_some_and(|m| m.get("uuid").is_some() && m.get("schema").is_some());
    }
    reader
        .read(&format!("{dir}/{}", layout::MARKER_FILE))
        .and_then(|m| parse(&m))
        .and_then(|m| {
            m.get("files")?
                .get(name)?
                .get("sha256")?
                .as_str()
                .map(str::to_string)
        })
        .is_some_and(|sha| sha == sha256_hex(existing))
}

/// Write `plan` under `root` and return its records: the plan's fragment
/// records, then the created directories and the tree files. Nothing is
/// written for a plan that fails validation.
pub async fn write_plan(root: &Path, plan: &JvmPlan) -> Result<Vec<WiringRecord>, String> {
    let state = super::super::state::load_state(root)
        .await
        .map_err(|e| format!("vendor_state_unreadable: {e}"))?;
    let reader = ProjectReader::new(root);
    let mut targets = Vec::new();
    for w in &plan.writes {
        let allowed = if w.tree {
            layout::VENDOR_TREES
                .iter()
                .any(|tree| w.rel.strip_prefix(tree).is_some_and(|r| r.starts_with('/')))
        } else {
            is_wiring_file(&w.rel)
        };
        if !allowed || !safe_rel(&w.rel) {
            return Err(format!(
                "refusing to write {:?}: not a vendoring path",
                w.rel
            ));
        }
        let path = reader.resolve(&w.rel)?;
        match reader.read(&w.rel) {
            Some(existing) if w.tree && existing != w.bytes => {
                let owned = state.entries.values().any(|e| {
                    let Ok((g, a, v)) = entry_gav(e) else {
                        return false;
                    };
                    let c = Coords {
                        group_id: &g,
                        artifact_id: &a,
                        version: &v,
                        uuid: &e.uuid,
                    };
                    is_jvm_entry(e)
                        && e.wiring.iter().any(|r| {
                            r.kind == TREE_KIND && r.file == w.rel && record_allowed(r, &c)
                        })
                });
                if !owned && !is_vendored_tree_file(&reader, &w.rel, &existing) {
                    return Err(format!(
                        "{} already exists and was not written by socket-patch; refusing to \
                         overwrite it",
                        w.rel
                    ));
                }
            }
            None if path.exists() => {
                return Err(format!(
                    "{} is not a regular file; refusing to edit it",
                    w.rel
                ));
            }
            _ => {}
        }
        targets.push((w, path));
    }

    let mut created_dirs: Vec<String> = Vec::new();
    for w in &plan.writes {
        let mut prefix = String::new();
        let segments: Vec<&str> = w.rel.split('/').collect();
        for seg in &segments[..segments.len() - 1] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(seg);
            if created_dirs.contains(&prefix) || reader.resolve(&prefix)?.is_dir() {
                continue;
            }
            if !is_creatable_dir(&prefix) {
                return Err(format!("refusing to create directory {prefix:?}"));
            }
            created_dirs.push(prefix.clone());
        }
    }

    let mut records = plan.records.clone();
    records.extend(created_dirs.into_iter().map(|dir| WiringRecord {
        file: dir,
        kind: CREATED_DIR_KIND.to_string(),
        action: WiringAction::Added,
        key: None,
        original: None,
        new: None,
    }));
    // Artifacts first: nothing names them until the wiring lands.
    targets.sort_by_key(|(w, _)| !w.tree);
    for (w, path) in targets {
        write_bytes(&path, &w.bytes)
            .await
            .map_err(|e| format!("failed to write {}: {e}", w.rel))?;
    }
    let mut tree: Vec<(String, String)> = plan.tree_files.clone();
    tree.extend(
        plan.writes
            .iter()
            .filter(|w| w.tree)
            .map(|w| (w.rel.clone(), sha256_hex(&w.bytes))),
    );
    tree.sort();
    tree.dedup();
    records.extend(tree.into_iter().map(|(file, sha)| WiringRecord {
        file,
        kind: TREE_KIND.to_string(),
        action: WiringAction::Added,
        key: None,
        original: None,
        new: Some(Value::String(sha)),
    }));
    Ok(records)
}

async fn write_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    atomic_write_bytes_preserving_mode(path, bytes).await
}

/// Complete `records` from other JVM entries: an `adopt` record takes
/// the creation record of the peer that wrote that shared fragment, a
/// rewrite of another patch's suffixed version takes its pristine
/// `original`, and the directories a peer created that this entry now
/// relies on are listed too. The ledger entry this one replaces is a peer.
pub fn inherit_peer_records<'e>(
    records: &mut Vec<WiringRecord>,
    peers: impl IntoIterator<Item = &'e VendorEntry>,
) {
    let peer_records: Vec<&WiringRecord> = peers
        .into_iter()
        .filter(|e| is_jvm_entry(e))
        .flat_map(|e| &e.wiring)
        .collect();
    let same =
        |p: &WiringRecord, r: &WiringRecord| p.file == r.file && p.kind == r.kind && p.key == r.key;
    for r in records.iter_mut() {
        if op_of(r) == "adopt" {
            if let Some(p) = peer_records
                .iter()
                .find(|p| same(p, r) && op_of(p) != "adopt")
            {
                *r = (*p).clone();
            }
        } else if r.kind == POM_FRAGMENT_KIND
            && r.action == WiringAction::Rewritten
            && r.original.is_none()
        {
            if let Some(p) = peer_records
                .iter()
                .find(|p| same(p, r) && p.original.is_some())
            {
                r.original = p.original.clone();
            }
        } else if r.kind == VERIFICATION_FRAGMENT_KIND && op_str(r, "from").is_none() {
            let from = peer_records
                .iter()
                .find(|p| same(p, r))
                .and_then(|p| op_str(p, "from"));
            if let (Some(from), Some(op)) = (from, r.new.as_mut().and_then(Value::as_object_mut)) {
                op.insert("from".to_string(), Value::String(from.to_string()));
            }
        }
    }
    let mut needed: BTreeSet<String> = BTreeSet::new();
    for r in records.iter().filter(|r| r.kind != CREATED_DIR_KIND) {
        let mut dir = r.file.as_str();
        while let Some((parent, _)) = dir.rsplit_once('/') {
            needed.insert(parent.to_string());
            dir = parent;
        }
    }
    for p in peer_records.iter().filter(|p| p.kind == CREATED_DIR_KIND) {
        let listed = records
            .iter()
            .any(|r| r.kind == CREATED_DIR_KIND && r.file == p.file);
        if needed.contains(&p.file) && !listed {
            records.push((*p).clone());
        }
    }
}

fn drifted(detail: String) -> VendorWarning {
    VendorWarning::new("vendor_lock_entry_drifted", format!("{detail}; left alone"))
}

/// Which planners wrote the wiring: `(maven, gradle)`. A mixed root's
/// entry has both (#395).
fn sides(wiring: &[WiringRecord]) -> (bool, bool) {
    let gradle = is_gradle(wiring);
    let maven = wiring.iter().any(|w| {
        matches!(w.kind.as_str(), POM_FRAGMENT_KIND | CONFIG_LINE_KIND)
            || w.file.starts_with(&format!("{}/", layout::MAVEN2_TREE))
    });
    (maven || !gradle, gradle)
}

/// The shape a recorded entry was planned for.
fn shape_of(wiring: &[WiringRecord]) -> Shape {
    if sbt::owns(wiring) {
        return Shape::Sbt;
    }
    if scala_cli::owns(wiring) {
        return Shape::ScalaCli;
    }
    match sides(wiring) {
        (true, true) => Shape::Mixed,
        (false, true) => Shape::Gradle,
        _ => Shape::MavenReactor,
    }
}

/// Merge the revert plans of a mixed root's two halves.
fn merge_unplans(a: JvmUnplan, b: JvmUnplan) -> JvmUnplan {
    let mut changes = a.changes;
    changes.extend(b.changes);
    changes.sort_by(|x, y| x.0.cmp(&y.0));
    let mut drifted = a.drifted;
    drifted.extend(b.drifted);
    JvmUnplan {
        changes,
        drifted,
        still_wired: a.still_wired || b.still_wired,
    }
}

/// Whether the wiring belongs to the Gradle planner.
fn is_gradle(wiring: &[WiringRecord]) -> bool {
    wiring.iter().any(|w| {
        matches!(
            w.kind.as_str(),
            SETTINGS_FRAGMENT_KIND | VERIFICATION_FRAGMENT_KIND
        ) || w.file == gradle::INDEX_REL
            || w.file == gradle::SCRIPT_REL
            || w.file.starts_with(&format!("{}/", layout::GRADLE_TREE))
    })
}

/// Revert the JVM `entry`: its own fragments now, shared fragments
/// only once no other patch references them, so peers stay wired whatever
/// the revert order. A fragment still present but in a shape vendor did
/// not write is left alone with `vendor_lock_entry_drifted`; while it still
/// references the tree, the tree is kept too (`kept_artifact`).
pub async fn revert(root: &Path, entry: &VendorEntry, opts: RevertOpts) -> RevertOutcome {
    let (g, a, v) = match entry_gav(entry) {
        Ok(gav) => gav,
        Err(e) => return RevertOutcome::failed(format!("refusing revert: {e}")),
    };
    let c = Coords {
        group_id: &g,
        artifact_id: &a,
        version: &v,
        uuid: &entry.uuid,
    };
    if let Some(w) = entry.wiring.iter().find(|w| !record_allowed(w, &c)) {
        return RevertOutcome::failed(format!(
            "refusing revert: recorded {} path {:?} is not one vendoring writes for {}",
            w.kind, w.file, entry.base_purl
        ));
    }
    let reader = ProjectReader::new(root);
    let read = |rel: &str| reader.read(rel);
    let peers = match super::super::state::load_state(root).await {
        Ok(state) => state,
        Err(e) => return RevertOutcome::failed(format!("vendor_state_unreadable: {e}")),
    };
    let records: Vec<_> = entry
        .wiring
        .iter()
        .filter(|w| {
            !(w.kind == VERIFICATION_FRAGMENT_KIND
                && w.key.as_deref().is_some_and(|k| k.starts_with("metadata:"))
                && peers.entries.values().any(|peer| {
                    peer.base_purl != entry.base_purl
                        && entry_references(root, peer)
                        && peer
                            .wiring
                            .iter()
                            .any(|p| p.kind == w.kind && p.file == w.file && p.key == w.key)
                }))
        })
        .cloned()
        .collect();
    let unplan: JvmUnplan = if sbt::owns(&entry.wiring) {
        sbt::unplan(&read, &c, &records)
    } else if scala_cli::owns(&entry.wiring) {
        scala_cli::unplan(&read, &c, &records)
    } else {
        let (maven, gradle) = sides(&entry.wiring);
        let mut unplan = JvmUnplan::default();
        if gradle {
            unplan = merge_unplans(unplan, gradle::unplan(&read, &c, &records));
        }
        if maven {
            unplan = merge_unplans(unplan, maven_reactor::unplan(&read, &c, &entry.wiring));
        }
        unplan
    };
    if let Some(rel) = reader.escaped() {
        return RevertOutcome::failed(format!(
            "refusing revert: {rel} is a symlink that leaves the project"
        ));
    }
    let mut warnings: Vec<VendorWarning> = unplan.drifted.into_iter().map(drifted).collect();
    let mut kept = unplan.still_wired;
    let mut present = Vec::new();
    if !kept && !opts.keep_artifact {
        for w in entry.wiring.iter().filter(|w| w.kind == TREE_KIND) {
            let Some(bytes) = reader.read(&w.file) else {
                continue;
            };
            if w.new.as_ref().and_then(Value::as_str) != Some(sha256_hex(&bytes).as_str()) {
                warnings.push(drifted(format!("{} was modified", w.file)));
                kept = true;
            }
            present.push(w);
        }
    }
    if opts.dry_run {
        return RevertOutcome {
            success: true,
            warnings,
            error: None,
            kept_artifact: kept,
        };
    }
    let fail = |warnings: Vec<VendorWarning>, e: String| RevertOutcome {
        success: false,
        warnings,
        error: Some(e),
        kept_artifact: false,
    };

    let mut removed: Vec<String> = Vec::new();
    for (rel, bytes) in &unplan.changes {
        if !is_wiring_file(rel) {
            return fail(
                warnings,
                format!("refusing revert: {rel:?} is not a vendoring path"),
            );
        }
        let path = match reader.resolve(rel) {
            Ok(path) => path,
            Err(e) => return fail(warnings, format!("refusing revert: {e}")),
        };
        let res = match bytes {
            Some(bytes) => write_bytes(&path, bytes).await,
            None => {
                removed.push(rel.clone());
                remove_file(&path).await
            }
        };
        if let Err(e) = res {
            return fail(warnings, format!("failed to restore {rel}: {e}"));
        }
    }

    if !kept && !opts.keep_artifact {
        // One modified file keeps the whole tree: a partial artifact is
        // worse than a kept one.
        for w in present.into_iter().filter(|_| !kept) {
            let res = match reader.resolve(&w.file) {
                Ok(path) => remove_file(&path).await.map_err(|e| e.to_string()),
                Err(e) => Err(e),
            };
            if let Err(e) = res {
                return fail(warnings, format!("failed to remove {}: {e}", w.file));
            }
            removed.push(w.file.clone());
        }
    }
    prune_dirs(&reader, &entry.wiring, &removed).await;
    RevertOutcome {
        success: true,
        warnings,
        error: None,
        kept_artifact: kept,
    }
}

/// The committed JVM layout only a JVM ledger entry ([`is_jvm_entry`]) can
/// own (see [`layout::LEDGER_OWNED_PATHS`]).
pub use super::layout::LEDGER_OWNED_PATHS;

/// Owned directories pruned once empty, up to and including themselves.
const OWNED_DIRS: &[&str] = &[
    layout::MAVEN2_TREE,
    layout::GRADLE_TREE,
    ".socket/gradle",
    layout::COURSIER_TREE,
];

/// Remove, deepest first and only when empty, the parents of `removed` up to
/// their owned root, and every directory `wiring` records as created.
async fn prune_dirs(reader: &ProjectReader, wiring: &[WiringRecord], removed: &[String]) {
    let mut dirs: BTreeSet<String> = wiring
        .iter()
        .filter(|w| w.kind == CREATED_DIR_KIND)
        .map(|w| w.file.clone())
        .collect();
    for rel in removed {
        let mut dir = rel.as_str();
        while let Some((parent, _)) = dir.rsplit_once('/') {
            if !OWNED_DIRS
                .iter()
                .any(|o| parent == *o || parent.starts_with(&format!("{o}/")))
            {
                break;
            }
            dirs.insert(parent.to_string());
            dir = parent;
        }
    }
    let mut dirs: Vec<String> = dirs.into_iter().collect();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.matches('/').count()));
    for dir in dirs {
        if let Ok(path) = reader.resolve(&dir) {
            group_commit::remove_dir_after_commit(&path).await;
        }
    }
}

/// After a patch update replaced `prev`, delete its tree files that no live
/// entry records (a Maven update moves to a new suffixed-version directory;
/// a Gradle one rewrote the same paths). `Ok(true)` when anything went.
pub async fn sweep_replaced_tree<'e>(
    root: &Path,
    prev: &VendorEntry,
    live: impl IntoIterator<Item = &'e VendorEntry>,
) -> Result<bool, String> {
    let (g, a, v) = entry_gav(prev)?;
    let c = Coords {
        group_id: &g,
        artifact_id: &a,
        version: &v,
        uuid: &prev.uuid,
    };
    let live_files: BTreeSet<&str> = live
        .into_iter()
        .flat_map(|e| &e.wiring)
        .filter(|w| w.kind == TREE_KIND)
        .map(|w| w.file.as_str())
        .collect();
    let reader = ProjectReader::new(root);
    let mut removed = Vec::new();
    for w in prev.wiring.iter().filter(|w| w.kind == TREE_KIND) {
        if !record_allowed(w, &c) || live_files.contains(w.file.as_str()) {
            continue;
        }
        let Some(bytes) = reader.read(&w.file) else {
            continue;
        };
        if w.new.as_ref().and_then(Value::as_str) != Some(sha256_hex(&bytes).as_str()) {
            continue;
        }
        let path = reader.resolve(&w.file)?;
        remove_file(&path)
            .await
            .map_err(|e| format!("failed to remove {}: {e}", w.file))?;
        removed.push(w.file.clone());
    }
    prune_dirs(&reader, &[], &removed).await;
    Ok(!removed.is_empty())
}

/// Whether the project still wires the JVM `entry` for `vex` (see
/// [`entry_wired_checked`]).
pub fn entry_wired(root: &Path, entry: &VendorEntry) -> bool {
    // Failure to read does not prove that deleting a tree is safe. Attestation
    // uses the checked variant and reports the diagnostic instead.
    entry_wired_checked(root, entry).unwrap_or(true)
}

/// Whether the project still references the JVM `entry`'s tree (its
/// suffixed version in a reactor pom; its index rows plus the root apply
/// line for Gradle): what a revert must not pull from under a peer.
/// Fails closed: a file that exists but cannot be read or parsed (or
/// resolves outside the checkout) proves nothing absent, so the answer is
/// `true` — the `scan --prune` GC reverts on `false`.
pub fn entry_references(root: &Path, entry: &VendorEntry) -> bool {
    let Ok((g, a, v)) = entry_gav(entry) else {
        return true;
    };
    let c = Coords {
        group_id: &g,
        artifact_id: &a,
        version: &v,
        uuid: &entry.uuid,
    };
    let reader = ProjectReader::new(root);
    let read = |rel: &str| reader.read(rel);
    let referenced = if sbt::owns(&entry.wiring) {
        sbt::wired_checked(&read, &c).unwrap_or(true)
    } else if scala_cli::owns(&entry.wiring) {
        scala_cli::wired_checked(&read, &c).unwrap_or(true)
    } else {
        let (maven, gradle) = sides(&entry.wiring);
        (maven && maven_reactor::wired_checked(&read, &c).unwrap_or(true))
            || (gradle && gradle::references_checked(&read, &c).unwrap_or(true))
    };
    // `read` answers `None` for an unreadable file as for a missing one;
    // the error it recorded is what tells the two apart.
    referenced || reader.read_error.borrow().is_some()
}

/// The liveness proof `vex` needs: every half of the entry is wired, and
/// a Gradle half's script is intact and re-plans with no refusal and no
/// degraded warning (a conflicting rule or unchecked build logic added
/// since vendoring withholds attestation).
pub fn entry_wired_checked(root: &Path, entry: &VendorEntry) -> Result<bool, String> {
    let (g, a, v) = entry_gav(entry)?;
    let c = Coords {
        group_id: &g,
        artifact_id: &a,
        version: &v,
        uuid: &entry.uuid,
    };
    let reader = ProjectReader::new(root);
    let read = |rel: &str| reader.read(rel);
    let list = |dir: &str| reader.list(dir);
    let wired = if sbt::owns(&entry.wiring) {
        sbt::wired_checked(&read, &c).map_err(|e| e.detail)
    } else if scala_cli::owns(&entry.wiring) {
        scala_cli::wired_checked(&read, &c).map_err(|e| e.detail)
    } else {
        let (maven, gradle) = sides(&entry.wiring);
        let mut wired = Ok(true);
        if gradle {
            wired = gradle::wired_checked(&read, &list, &c).map_err(|e| e.detail);
        }
        if maven && wired == Ok(true) {
            wired = maven_reactor::wired_checked(&read, &c).map_err(|e| e.detail);
        }
        wired
    };
    if let Some(e) = reader.read_error.borrow().as_ref() {
        return Err(e.clone());
    }
    wired
}

/// Verify every recorded file plus the effective wiring, without writes or network I/O.
pub fn check_entry(
    root: &Path,
    entry: &VendorEntry,
    local_repo: Option<&Path>,
) -> Result<(), String> {
    let (g, a, v) = entry_gav(entry)?;
    let c = Coords {
        group_id: &g,
        artifact_id: &a,
        version: &v,
        uuid: &entry.uuid,
    };
    let reader = ProjectReader::new(root);
    let read = |rel: &str| reader.read(rel);
    for w in &entry.wiring {
        if !record_allowed(w, &c) {
            return Err(format!("unsafe wiring record: {}", w.file));
        }
        if w.kind == TREE_KIND {
            let bytes = read(&w.file).ok_or_else(|| format!("missing or unreadable {}", w.file))?;
            if w.new.as_ref().and_then(Value::as_str) != Some(sha256_hex(&bytes).as_str()) {
                return Err(format!("hash mismatch: {}", w.file));
            }
        }
        if w.kind == VERIFICATION_FRAGMENT_KIND
            && w.key.as_deref().is_some_and(|k| k.starts_with("metadata:"))
        {
            let bytes = read(&w.file).ok_or_else(|| format!("missing {}", w.file))?;
            let text = std::str::from_utf8(&bytes).map_err(|e| e.to_string())?;
            if !gradle::metadata_record_present(text, w) {
                return Err(format!(
                    "upstream verification entry drifted: {}",
                    w.key.as_deref().unwrap_or("")
                ));
            }
        }
    }
    let (sbt_entry, scala_cli_entry) = (sbt::owns(&entry.wiring), scala_cli::owns(&entry.wiring));
    // An sbt / scala-cli entry has neither a Maven-reactor nor a Gradle half.
    let (maven, gradle) = if sbt_entry || scala_cli_entry {
        (false, false)
    } else {
        sides(&entry.wiring)
    };
    let list = |dir: &str| reader.list(dir);
    let (jar, pom, module) = if sbt_entry {
        sbt::committed(&read, &c)
    } else if scala_cli_entry {
        scala_cli::committed(&read, &c)
    } else if gradle {
        gradle::committed(&read, &c)
    } else {
        maven_reactor::committed(&read, &c).map(|(j, p)| (j, p, None))
    }
    .ok_or_else(|| "committed JVM tree is incomplete".to_string())?;
    let extras = if gradle {
        gradle::committed_extras(&read, &c)
            .ok_or_else(|| "committed JVM tree is incomplete".to_string())?
    } else {
        Vec::new()
    };
    let patched = if gradle {
        gradle::committed_patched(&read, &c)
    } else {
        Vec::new()
    };
    let patch = super::JvmPatch {
        group_id: &g,
        artifact_id: &a,
        version: &v,
        uuid: &entry.uuid,
        jar: &jar,
        upstream_pom: &pom,
        upstream_module: module.as_deref(),
        extra_artifacts: &extras,
        patched_members: &patched,
    };
    let config = !entry.wiring.iter().any(|w| op_of(w) == "config_none");
    let plan = super::plan_with_config(shape_of(&entry.wiring), &read, &list, &patch, config)
        .map_err(|e| e.detail)?;
    if let Some(w) = plan.writes.first() {
        return Err(format!("vendored wiring or metadata drifted: {}", w.rel));
    }
    let referenced = if sbt_entry || scala_cli_entry {
        entry_wired_checked(root, entry)?
    } else {
        (!maven || maven_reactor::wired_checked(&read, &c).map_err(|e| e.detail)?)
            && (!gradle || gradle::references(&read, &c))
    };
    if !referenced {
        return Err("vendored artifact is no longer wired into the build".into());
    }
    let mut tree_dirs = vec![plan.tree_dir.clone()];
    if maven && gradle {
        tree_dirs.push(gradle::tree_dir(&c));
    }
    for tree_dir in tree_dirs {
        let dir = reader.resolve(&tree_dir)?;
        for item in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
            let item = item.map_err(|e| e.to_string())?;
            let rel = format!("{tree_dir}/{}", item.file_name().to_string_lossy());
            if !entry
                .wiring
                .iter()
                .any(|w| w.kind == TREE_KIND && w.file == rel)
            {
                return Err(format!("unindexed vendored file: {rel}"));
            }
        }
    }
    // The sbt tree is the reactor's suffixed layout, so a Maven local
    // repository may cache the same suffixed GAV.
    if maven || sbt_entry {
        if let Some(repo) = local_repo {
            for ext in ["jar", "pom"] {
                let sv = c.suffixed_version();
                let name = format!("{a}-{sv}.{ext}");
                let cached = repo.join(c.group_path()).join(&a).join(&sv).join(&name);
                if cached.exists() {
                    let bytes = read_regular_to_bytes_sync(&cached).map_err(|e| e.to_string())?;
                    if Some(bytes) != read(&format!("{}/{name}", plan.tree_dir)) {
                        return Err(format!(
                            "local Maven cache conflicts with vendored bytes: {}",
                            cached.display()
                        ));
                    }
                }
            }
        }
    }
    if let Some(rel) = reader.escaped() {
        return Err(outside_root_detail(&rel));
    }
    Ok(())
}

/// The vendored jar of the JVM `entry` for `uuid`, project-relative: the
/// artifact path must be the entry's own tree jar (the Maven directory
/// carries the uuid; the Gradle one's marker must name it).
pub(crate) fn checked_tree_jar_path(
    root: &Path,
    entry: &VendorEntry,
    uuid: &str,
) -> Result<String, String> {
    let unsafe_path = || "vendor_path_unsafe".to_string();
    if !is_jvm_entry(entry) {
        return Err(unsafe_path());
    }
    let (g, a, v) = entry_gav(entry).map_err(|_| unsafe_path())?;
    if entry.uuid != uuid {
        return Err("vendor_uuid_mismatch".to_string());
    }
    let c = Coords {
        group_id: &g,
        artifact_id: &a,
        version: &v,
        uuid,
    };
    let rel = entry.artifact.path.as_str();
    ProjectReader::new(root)
        .resolve(rel)
        .map_err(|_| unsafe_path())?;
    let maven = format!(
        "{}/{a}-{}.jar",
        maven_reactor::tree_dir(&c),
        c.suffixed_version()
    );
    let gradle_jar = format!("{}/{a}-{v}.jar", gradle::tree_dir(&c));
    if rel == maven {
        return Ok(maven);
    }
    // The scala-cli Coursier tree is same-GAV like Gradle's: its marker
    // names the uuid (checked by `checked_tree_jar`).
    let coursier_jar = format!("{}/{a}-{v}.jar", coursier_tree::tree_dir(&c));
    if rel == coursier_jar {
        return Ok(coursier_jar);
    }
    if rel != gradle_jar {
        return Err(unsafe_path());
    }
    Ok(gradle_jar)
}

pub fn checked_tree_jar(root: &Path, entry: &VendorEntry, uuid: &str) -> Result<String, String> {
    let rel = checked_tree_jar_path(root, entry, uuid)?;
    // The jar alone does not make a usable tree: a missing classifier jar,
    // pom or derived metadata file fails resolution, so `repair` restores
    // it from the same download (#533, #511).
    let (g, a, v) = entry_gav(entry).map_err(|_| "vendor_path_unsafe")?;
    let c = Coords {
        group_id: &g,
        artifact_id: &a,
        version: &v,
        uuid,
    };
    let reader = ProjectReader::new(root);
    for w in &entry.wiring {
        let needed = w.kind == TREE_KIND || w.kind == DERIVED_METADATA_KIND;
        if needed && record_allowed(w, &c) && reader.read(&w.file).is_none() {
            // A tree reached through a link out of the checkout is no
            // missing file a repair may restore there.
            if reader.escaped().is_some() {
                return Err("vendor_path_unsafe".into());
            }
            return Err("vendor_artifact_missing".into());
        }
    }
    if rel.starts_with(&format!("{}/", layout::MAVEN2_TREE)) {
        return Ok(rel);
    }
    let marker_path = format!(
        "{}/{}",
        rel.rsplit_once('/').ok_or("vendor_path_unsafe")?.0,
        layout::MARKER_FILE
    );
    let reader = ProjectReader::new(root);
    let bytes = reader.read(&marker_path).ok_or("vendor_artifact_missing")?;
    if reader.escaped().is_some() {
        return Err("vendor_path_unsafe".into());
    }
    let marker: Value = serde_json::from_slice(&bytes).map_err(|_| "vendor_artifact_unreadable")?;
    match marker.get("uuid").and_then(Value::as_str) {
        Some(u) if u == uuid => Ok(rel),
        Some(_) => Err("vendor_uuid_mismatch".into()),
        None => Err("vendor_artifact_unreadable".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::FileWrite;
    use super::*;

    const UUID: &str = "1d3c1fd2-5e6f-4a7b-8c9d-0e1f2a3b4c5d";

    fn coords() -> Coords<'static> {
        Coords {
            group_id: "g",
            artifact_id: "a",
            version: "1",
            uuid: UUID,
        }
    }

    fn entry(wiring: Vec<WiringRecord>) -> VendorEntry {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "maven",
            "basePurl": "pkg:maven/g/a@1",
            "uuid": UUID,
            "artifact": { "path": ".socket/vendor/maven2/g/a/1-socket.1d3c1fd2/a-1-socket.1d3c1fd2.jar", "sha256": "" },
            "wiring": serde_json::to_value(wiring).unwrap(),
        }))
        .unwrap()
    }

    fn record(kind: &str, file: &str) -> WiringRecord {
        WiringRecord {
            file: file.to_string(),
            kind: kind.to_string(),
            action: WiringAction::Added,
            key: Some("owned".into()),
            original: None,
            new: Some(serde_json::json!({ "op": "create" })),
        }
    }

    fn tree_file(name: &str) -> String {
        format!(".socket/vendor/maven2/g/a/1-socket.1d3c1fd2/{name}")
    }

    fn plan(writes: Vec<FileWrite>) -> JvmPlan {
        JvmPlan {
            writes,
            ..JvmPlan::default()
        }
    }

    /// The `scan --prune` GC reverts when [`entry_references`] says
    /// `false`, so a Gradle file that exists but cannot be read or parsed
    /// must answer `true` (keep), as the maven/sbt/scala-cli arms do.
    #[test]
    fn gradle_references_fail_closed_on_unreadable_files() {
        let gradle_entry = || {
            entry(vec![
                record(SETTINGS_FRAGMENT_KIND, "settings.gradle"),
                record(TREE_KIND, ".socket/vendor/gradle/g/a/1/a-1.jar"),
            ])
        };
        assert!(is_jvm_entry(&gradle_entry()));
        // The root settings file still applies the script.
        let settings = |dir: &Path| {
            std::fs::write(
                dir.join("settings.gradle"),
                "apply from: '.socket/gradle/socket-patch.settings.gradle' // socket-patch\n",
            )
            .unwrap()
        };
        // Decidable: applied, but no index lists the entry — unreferenced.
        let dir = tempfile::tempdir().unwrap();
        settings(dir.path());
        assert!(!entry_references(dir.path(), &gradle_entry()));
        // A malformed index proves nothing absent.
        let dir = tempfile::tempdir().unwrap();
        settings(dir.path());
        std::fs::create_dir_all(dir.path().join(".socket/vendor")).unwrap();
        std::fs::write(dir.path().join(gradle::INDEX_REL), "garbage\n").unwrap();
        assert!(entry_references(dir.path(), &gradle_entry()));
        // An index the reader cannot read (here: a link out of the checkout).
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().unwrap();
            let outside = tempfile::tempdir().unwrap();
            settings(dir.path());
            std::fs::create_dir_all(dir.path().join(".socket/vendor")).unwrap();
            std::fs::write(outside.path().join("index.tsv"), "x").unwrap();
            std::os::unix::fs::symlink(
                outside.path().join("index.tsv"),
                dir.path().join(gradle::INDEX_REL),
            )
            .unwrap();
            assert!(entry_references(dir.path(), &gradle_entry()));
        }
    }

    #[test]
    fn recorded_paths_are_whitelisted_per_kind() {
        let c = coords();
        let ok = [
            (POM_FRAGMENT_KIND, "a/pom.xml"),
            (POM_FRAGMENT_KIND, "mod/custom.xml"),
            (CONFIG_LINE_KIND, ".mvn/maven.config"),
            (SETTINGS_FRAGMENT_KIND, "settings.gradle"),
            (SETTINGS_FRAGMENT_KIND, "build-logic/settings.gradle.kts"),
            (
                VERIFICATION_FRAGMENT_KIND,
                "gradle/verification-metadata.xml",
            ),
            (
                OWNED_FILE_KIND,
                ".socket/gradle/socket-patch.settings.gradle",
            ),
            (OWNED_FILE_KIND, ".socket/vendor/maven2/.gitattributes"),
            (OWNED_FILE_KIND, ".socket/gradle/.gitattributes"),
            (OWNED_FILE_KIND, ".socket/vendor/.gitattributes"),
            (
                DERIVED_METADATA_KIND,
                ".socket/vendor/gradle/g/a/maven-metadata.xml",
            ),
            (TREE_KIND, ".socket/vendor/gradle/g/a/1/a-1-tests.jar"),
            (
                TREE_KIND,
                ".socket/vendor/maven2/g/a/1-socket.1d3c1fd2/a-1-socket.1d3c1fd2.jar",
            ),
            (TREE_KIND, ".socket/vendor/gradle/g/a/1/a-1.jar"),
            (CREATED_DIR_KIND, ".mvn"),
            (CREATED_DIR_KIND, ".socket/vendor/maven2/g"),
        ];
        for (kind, file) in ok {
            assert!(record_allowed(&record(kind, file), &c), "{kind} {file}");
        }
        let bad = [
            (POM_FRAGMENT_KIND, ".git/config"),
            (POM_FRAGMENT_KIND, "src/Main.java"),
            (POM_FRAGMENT_KIND, ".GIT/x.xml"),
            (POM_FRAGMENT_KIND, "a/.git/x.xml"),
            (POM_FRAGMENT_KIND, ".socket/vendor/x.xml"),
            (POM_FRAGMENT_KIND, "../x/pom.xml"),
            (POM_FRAGMENT_KIND, "/etc/pom.xml"),
            (CONFIG_LINE_KIND, ".mvn/jvm.config"),
            (SETTINGS_FRAGMENT_KIND, "build.gradle"),
            (VERIFICATION_FRAGMENT_KIND, "gradle/other.xml"),
            (OWNED_FILE_KIND, ".socket/vendor/state.json"),
            (OWNED_FILE_KIND, ".gitattributes"),
            (
                DERIVED_METADATA_KIND,
                ".socket/vendor/gradle/g/b/maven-metadata.xml",
            ),
            (
                DERIVED_METADATA_KIND,
                ".socket/vendor/gradle/g/a/1/maven-metadata.xml",
            ),
            (DERIVED_METADATA_KIND, "maven-metadata.xml"),
            (
                TREE_KIND,
                ".socket/vendor/maven2/g/a/1-socket.99999999/a.jar",
            ),
            (
                TREE_KIND,
                ".socket/vendor/maven2/g/a/1-socket.1d3c1fd2/x/a.jar",
            ),
            (TREE_KIND, ".socket/vendor/gradle/g/b/1/b-1.jar"),
            (TREE_KIND, "src/Main.java"),
            (CREATED_DIR_KIND, "src"),
            (CREATED_DIR_KIND, ".git"),
            ("jvm_file_snapshot", "pom.xml"),
        ];
        for (kind, file) in bad {
            assert!(!record_allowed(&record(kind, file), &c), "{kind} {file}");
        }
    }

    #[test]
    fn jvm_entries_need_only_jvm_kinds_and_a_canonical_uuid() {
        let tree = WiringRecord {
            kind: TREE_KIND.into(),
            ..record(TREE_KIND, &tree_file("a-1-socket.1d3c1fd2.jar"))
        };
        assert!(is_jvm_entry(&entry(vec![tree.clone()])));
        assert!(!is_jvm_entry(&entry(vec![])));
        let legacy = record("maven_pom_repository", "pom.xml");
        assert!(!is_jvm_entry(&entry(vec![tree.clone(), legacy])));
        let mut bad = entry(vec![tree]);
        bad.uuid = "../../../NOT-A-UUID".into();
        assert!(entry_gav(&bad).is_err());
        bad.uuid = UUID.into();
        bad.base_purl = "pkg:maven/com.ex&ample/a@1".into();
        assert!(entry_gav(&bad).is_err());
    }

    #[tokio::test]
    async fn tampered_records_fail_closed_before_any_write() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".git/config"), "[core]\n").unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/Main.java"), "class Main {}\n").unwrap();
        let forged = [
            WiringRecord {
                new: Some(Value::String(sha256_hex(b"class Main {}\n"))),
                ..record(TREE_KIND, "src/Main.java")
            },
            WiringRecord {
                original: Some(Value::String("[core]\n\tfsmonitor = x\n".into())),
                new: Some(serde_json::json!({ "op": "replace", "from": "x", "to": "[core]\n" })),
                ..record(POM_FRAGMENT_KIND, ".git/config")
            },
        ];
        for w in forged {
            let out = revert(root, &entry(vec![w]), RevertOpts::new(false)).await;
            assert!(!out.success, "{out:?}");
        }
        assert_eq!(
            std::fs::read(root.join(".git/config")).unwrap(),
            b"[core]\n"
        );
        assert!(root.join("src/Main.java").is_file());
        let mut e = entry(vec![record(
            OWNED_FILE_KIND,
            ".socket/gradle/socket-patch.settings.gradle",
        )]);
        e.uuid = "../../../NOT-A-UUID".into();
        assert!(!revert(root, &e, RevertOpts::new(false)).await.success);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinks_leaving_the_checkout_are_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(outside.path().join("pom.xml"), "<project/>").unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("lnk")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join(".mvn")).unwrap();
        let reader = ProjectReader::new(root);
        assert_eq!(reader.read("lnk/pom.xml"), None);
        assert_eq!(reader.escaped().as_deref(), Some("lnk"));
        // Writing through a symlinked `.mvn` or `.socket` is refused.
        let p = plan(vec![FileWrite {
            rel: ".mvn/maven.config".into(),
            bytes: b"-Da=b\n".to_vec(),
            tree: false,
        }]);
        assert!(write_plan(root, &p).await.is_err());
        assert!(!outside.path().join("maven.config").exists());
        std::os::unix::fs::symlink(outside.path(), root.join(".socket")).unwrap();
        let p = plan(vec![FileWrite {
            rel: ".socket/vendor/maven2/g/a/1/a.jar".into(),
            bytes: b"JAR".to_vec(),
            tree: true,
        }]);
        assert!(write_plan(root, &p).await.is_err());
        assert!(!outside.path().join("vendor").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_in_checkout_symlinked_file_is_edited_through_its_link() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("a/real.xml"), "<project/>\n").unwrap();
        std::os::unix::fs::symlink("real.xml", root.join("a/pom.xml")).unwrap();
        let reader = ProjectReader::new(root);
        assert_eq!(
            reader.read("a/pom.xml").as_deref(),
            Some(&b"<project/>\n"[..])
        );
        assert_eq!(reader.escaped(), None);
        let p = plan(vec![FileWrite {
            rel: "a/pom.xml".into(),
            bytes: b"<project><x/></project>\n".to_vec(),
            tree: false,
        }]);
        write_plan(root, &p).await.unwrap();
        let meta = std::fs::symlink_metadata(root.join("a/pom.xml")).unwrap();
        assert!(meta.file_type().is_symlink());
        assert_eq!(
            std::fs::read(root.join("a/real.xml")).unwrap(),
            b"<project><x/></project>\n"
        );
    }

    #[tokio::test]
    async fn unresolved_root_never_disables_confinement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("missing");
        let reader = ProjectReader::new(&root);
        assert!(reader.resolve("pom.xml").is_err());
        let p = plan(vec![FileWrite {
            rel: "pom.xml".into(),
            bytes: b"<project/>".to_vec(),
            tree: false,
        }]);
        assert!(write_plan(&root, &p).await.is_err());
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn dry_run_reports_tree_retained_for_live_drift() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join(gradle::INDEX_REL);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "MALFORMED\n").unwrap();
        let out = revert(
            temp.path(),
            &entry(vec![record(OWNED_FILE_KIND, gradle::INDEX_REL)]),
            RevertOpts::new(true),
        )
        .await;
        assert!(
            out.success && out.kept_artifact && out.drift_skipped(),
            "{out:?}"
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), "MALFORMED\n");
    }

    #[tokio::test]
    async fn write_plan_rejects_paths_outside_the_vendoring_set() {
        let dir = tempfile::tempdir().unwrap();
        for (rel, tree) in [
            ("../evil", false),
            ("src/Main.java", false),
            (".git/config", false),
            ("src/lib.jar", true),
            (".socket/vendor/state.json", false),
            ("newdir/pom.xml", false),
        ] {
            let p = plan(vec![FileWrite {
                rel: rel.into(),
                bytes: Vec::new(),
                tree,
            }]);
            assert!(write_plan(dir.path(), &p).await.is_err(), "{rel}");
        }
        assert!(!dir.path().join("newdir").exists());
    }

    #[tokio::test]
    async fn tree_files_never_overwrite_foreign_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let jar = tree_file("a-1-socket.1d3c1fd2.jar");
        std::fs::create_dir_all(root.join(&jar).parent().unwrap()).unwrap();
        std::fs::write(root.join(&jar), b"FOREIGN").unwrap();
        let p = plan(vec![FileWrite {
            rel: jar.clone(),
            bytes: b"JAR".to_vec(),
            tree: true,
        }]);
        assert!(write_plan(root, &p).await.is_err());
        assert_eq!(std::fs::read(root.join(&jar)).unwrap(), b"FOREIGN");
        // Listed in the directory's marker: an earlier vendoring's bytes.
        let marker = serde_json::json!({
            "files": { "a-1-socket.1d3c1fd2.jar": { "sha256": sha256_hex(b"FOREIGN"), "size": 7 } },
            "schema": 1,
            "uuid": UUID,
        });
        std::fs::write(
            root.join(tree_file(layout::MARKER_FILE)),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        write_plan(root, &p).await.unwrap();
        assert_eq!(std::fs::read(root.join(&jar)).unwrap(), b"JAR");
    }

    #[test]
    fn peer_records_fill_adopts_originals_and_created_dirs() {
        let created = WiringRecord {
            file: ".mvn/maven.config".into(),
            kind: CONFIG_LINE_KIND.into(),
            action: WiringAction::Added,
            key: Some("config".into()),
            original: None,
            new: Some(serde_json::json!({ "op": "config", "created": true, "appended": "x\n" })),
        };
        let version = |original: Option<&str>| WiringRecord {
            file: "a/pom.xml".into(),
            kind: POM_FRAGMENT_KIND.into(),
            action: WiringAction::Rewritten,
            key: Some("version:g:a:dependencies:0".into()),
            original: original.map(|o| Value::String(o.into())),
            new: Some(serde_json::json!({ "op": "version", "to": "1-socket.1d3c1fd2" })),
        };
        let mvn_dir = WiringRecord {
            file: ".mvn".into(),
            kind: CREATED_DIR_KIND.into(),
            action: WiringAction::Added,
            key: None,
            original: None,
            new: None,
        };
        let other_dir = WiringRecord {
            file: ".socket/gradle".into(),
            ..mvn_dir.clone()
        };
        let peer = entry(vec![
            created.clone(),
            version(Some("${ct}")),
            mvn_dir.clone(),
            other_dir,
        ]);
        let mut records = vec![
            super::super::adopt(".mvn/maven.config", CONFIG_LINE_KIND, "config"),
            super::super::adopt("pom.xml", POM_FRAGMENT_KIND, "repository"),
            version(None),
        ];
        inherit_peer_records(&mut records, [&peer]);
        assert_eq!(records[0], created);
        assert_eq!(op_of(&records[1]), "adopt", "no peer wrote it");
        assert_eq!(records[2], version(Some("${ct}")));
        assert_eq!(records[3], mvn_dir);
        assert_eq!(
            records.len(),
            4,
            "a directory this entry does not use is not inherited"
        );
    }

    #[tokio::test]
    async fn revert_of_a_tree_keeps_modified_files_and_prunes_empty_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let p = plan(vec![
            FileWrite {
                rel: tree_file("a-1-socket.1d3c1fd2.jar"),
                bytes: b"JAR".to_vec(),
                tree: true,
            },
            FileWrite {
                rel: tree_file("a-1-socket.1d3c1fd2.pom"),
                bytes: b"POM".to_vec(),
                tree: true,
            },
        ]);
        let records = write_plan(root, &p).await.unwrap();
        // Created dirs listed first (as a carried-forward entry would):
        // they are still pruned after the files.
        let mut first_dirs = records.clone();
        first_dirs.sort_by_key(|r| r.kind != CREATED_DIR_KIND);
        let out = revert(root, &entry(first_dirs.clone()), RevertOpts::new(false)).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert!(!root.join(".socket").exists());

        write_plan(root, &p).await.unwrap();
        std::fs::write(root.join(tree_file("a-1-socket.1d3c1fd2.pom")), b"EDITED").unwrap();
        let out = revert(root, &entry(first_dirs.clone()), RevertOpts::new(false)).await;
        assert!(
            out.success && out.drift_skipped() && out.kept_artifact,
            "{out:?}"
        );
        assert!(root.join(tree_file("a-1-socket.1d3c1fd2.pom")).is_file());

        let out = revert(
            root,
            &entry(first_dirs),
            RevertOpts {
                dry_run: false,
                keep_artifact: true,
            },
        )
        .await;
        assert!(out.success && !out.kept_artifact, "{out:?}");
        assert!(
            root.join(tree_file("a-1-socket.1d3c1fd2.jar")).is_file(),
            "--preserve-state keeps the tree"
        );
    }

    #[tokio::test]
    async fn sweep_replaced_tree_spares_live_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let p = plan(vec![
            FileWrite {
                rel: tree_file("a-1-socket.1d3c1fd2.jar"),
                bytes: b"JAR".to_vec(),
                tree: true,
            },
            FileWrite {
                rel: tree_file("a-1-socket.1d3c1fd2.pom"),
                bytes: b"POM".to_vec(),
                tree: true,
            },
        ]);
        let records = write_plan(root, &p).await.unwrap();
        let prev = entry(records.clone());
        let live = entry(
            records
                .into_iter()
                .filter(|r| r.file.ends_with(".pom"))
                .collect(),
        );
        assert!(sweep_replaced_tree(root, &prev, [&live]).await.unwrap());
        assert!(!root.join(tree_file("a-1-socket.1d3c1fd2.jar")).exists());
        assert!(root.join(tree_file("a-1-socket.1d3c1fd2.pom")).is_file());
        assert!(!sweep_replaced_tree(root, &prev, [&live]).await.unwrap());
    }
}
