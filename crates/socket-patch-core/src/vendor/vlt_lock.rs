//! vlt vendor backend: `vlt-lock.json` + importer `package.json` surgery
//! for a direct dependency (DESIGN §4.5).
//!
//! The target's default-registry node becomes a `file` node naming the
//! directory artifact ([`super::npm_dir`]); its importer edges and the
//! importers' package.json specs move to `file:<path relative to the
//! importer>`, and its own outgoing edges are re-keyed to the new DepID.
//! Every other line of the lock stays byte-identical, and the moved entries
//! are placed where vlt's own serializer puts them (§4.5.4), so `vlt ci`
//! keeps the lock byte-stable.
//!
//! Transitive targets are refused: vlt re-resolves a non-importer edge to a
//! `file` node away on the next `install`, `update` or workspace edit, and
//! nothing tells the user.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::Value;

use crate::constants::npm_family::VLT_LOCK;
use crate::constants::SOCKET_DIR;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::patch::path_safety::is_safe_multi_segment;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};
use crate::utils::socket_dir::remove_tree_and_prune;

use super::common::{already_patched_result, done, refused};
use super::npm_common::{done_failure_unstage, guard_coordinates, guard_revert_uuid_dir};
use super::npm_dir::{dependency_token, replace_dependency_token, stage_patch_dir, SpanError};
use super::state::{
    load_state, write_marker_or_warn, VendorArtifact, VendorEntry, VendorMarker, WiringAction,
    WiringRecord,
};
use super::vlt_lock_text::{
    edges_block, entry_text, file_dep_id, is_default_registry, is_importer_dep_id, nodes_block,
    parse_edge_entry_text, parse_edge_line, parse_node_entry_text, parse_node_line,
    parse_vendored_dir_path, render_entry_line, render_tuple_with_slots, sniff_lock, split_dep_id,
    split_lines, vendored_dir_rel, vlt_collate, vlt_edge_cmp, DepIdEra, DepIdKind, LockSniff,
    ParsedLock, SectionSpan,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorWarning};

/// The flavor string vlt entries record.
pub const FLAVOR: &str = "vlt";

const KIND_PKG_DEP: &str = "vlt_pkg_dep";
const KIND_LOCK_NODE: &str = "vlt_lock_node";
const KIND_LOCK_EDGE: &str = "vlt_lock_edge";

const PACKAGE_JSON: &str = "package.json";
const UNSUPPORTED: &str = "vendor_lock_entry_unsupported";
const OUT_OF_SYNC: &str = "vendor_vlt_lock_out_of_sync";
const NOT_CANONICAL: &str =
    "vlt-lock.json is not in vlt's canonical layout; re-save it with `vlt install`";

/// A refusal: a stable code and its detail.
pub type Refusal = (&'static str, String);

/// DESIGN §4.1 lock sniff: a BOM-less JSON object with `lockfileVersion` 0
/// or 1. The `Err` detail goes with `vendor_lockfile_version_unsupported`.
pub(crate) fn sniff_vendor_lock(text: &str) -> Result<ParsedLock, String> {
    match sniff_lock(text) {
        LockSniff::Readable(lock) if lock.version.is_some() => Ok(lock),
        LockSniff::Readable(_) => Err(
            "vlt-lock.json has no lockfileVersion (vlt ≤ 0.0.0-18); re-lock with vlt ≥ 1.0.0"
                .to_string(),
        ),
        LockSniff::UnsupportedVersion(raw) => Err(format!(
            "vlt-lock.json has lockfileVersion {raw}; update socket-patch"
        )),
        LockSniff::Bom => Err(
            "vlt-lock.json starts with a byte-order mark; re-save vlt-lock.json with `vlt install`"
                .to_string(),
        ),
        LockSniff::NotJsonObject => Err(
            "vlt-lock.json is not a JSON object; re-save vlt-lock.json with `vlt install`"
                .to_string(),
        ),
    }
}

// ── lock document ────────────────────────────────────────────────────────

/// One node or edge line: key, raw value, and its own `\r`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    key: String,
    value: String,
    cr: bool,
}

impl Entry {
    fn text(&self) -> String {
        entry_text(&self.key, &self.value)
    }

    fn from_text(text: &str, cr: bool, node: bool) -> Option<Self> {
        let (key, value) = if node {
            let entry = parse_node_entry_text(text)?;
            (entry.key.to_string(), entry.tuple.to_string())
        } else {
            let entry = parse_edge_entry_text(text)?;
            (entry.key.to_string(), entry.raw_value.to_string())
        };
        Some(Entry { key, value, cr })
    }

    fn edge_from(&self) -> &str {
        self.key.split_once(' ').map_or("", |(from, _)| from)
    }

    fn edge_dep(&self) -> &str {
        self.key.split_once(' ').map_or("", |(_, dep)| dep)
    }
}

#[derive(Debug, Clone)]
struct Block {
    span: Option<SectionSpan>,
    entries: Vec<Entry>,
}

/// A lock in vlt's canonical one-entry-per-line layout.
struct LockDoc {
    lines: Vec<String>,
    parsed: ParsedLock,
    era: DepIdEra,
    nodes: Block,
    edges: Block,
}

fn parse_block(
    lines: &[&str],
    span: Option<SectionSpan>,
    expected: usize,
    node: bool,
) -> Option<Block> {
    let Some(span) = span else {
        return (expected == 0).then(|| Block {
            span: None,
            entries: Vec::new(),
        });
    };
    let range = span.entry_lines();
    let last = range.end.checked_sub(1);
    let mut entries = Vec::new();
    for i in range {
        let (key, value, comma, cr) = if node {
            let line = parse_node_line(lines[i])?;
            (
                line.entry.key.to_string(),
                line.entry.tuple.to_string(),
                line.comma,
                line.cr,
            )
        } else {
            let line = parse_edge_line(lines[i])?;
            (
                line.entry.key.to_string(),
                line.entry.raw_value.to_string(),
                line.comma,
                line.cr,
            )
        };
        if comma == (Some(i) == last) {
            return None;
        }
        entries.push(Entry { key, value, cr });
    }
    let unique: BTreeSet<&str> = entries.iter().map(|e| e.key.as_str()).collect();
    (entries.len() == expected && unique.len() == expected).then_some(Block {
        span: Some(span),
        entries,
    })
}

fn parse_doc(text: &str) -> Result<LockDoc, Refusal> {
    let parsed = sniff_vendor_lock(text).map_err(|d| ("vendor_lockfile_version_unsupported", d))?;
    let lines = split_lines(text);
    let not_canonical = || {
        (
            "vendor_lockfile_version_unsupported",
            NOT_CANONICAL.to_string(),
        )
    };
    let node_count = parsed.nodes().map_or(0, |n| n.len());
    let edge_count = parsed.edges().map_or(0, |e| e.len());
    let nodes =
        parse_block(&lines, nodes_block(&lines), node_count, true).ok_or_else(not_canonical)?;
    let edges =
        parse_block(&lines, edges_block(&lines), edge_count, false).ok_or_else(not_canonical)?;
    Ok(LockDoc {
        era: parsed.new_id_era(),
        lines: lines.into_iter().map(str::to_string).collect(),
        parsed,
        nodes,
        edges,
    })
}

fn render_block(out: &mut Vec<String>, header: &str, entries: &[Entry], inline_comma: bool) {
    if entries.is_empty() {
        out.push(header.to_string());
        return;
    }
    let open = header.trim_end_matches(['\r']).trim_end_matches(',');
    let cr = header.ends_with('\r');
    out.push(format!(
        "{}{}",
        open.trim_end_matches('}'),
        if cr { "\r" } else { "" }
    ));
    let last = entries.len() - 1;
    for (i, e) in entries.iter().enumerate() {
        out.push(render_entry_line(&e.text(), i != last, e.cr));
    }
    out.push(format!(
        "  }}{}{}",
        if inline_comma { "," } else { "" },
        if cr { "\r" } else { "" }
    ));
}

impl LockDoc {
    fn render(&self) -> String {
        let mut spans: Vec<(SectionSpan, &Block)> = [&self.nodes, &self.edges]
            .into_iter()
            .filter_map(|b| b.span.map(|s| (s, b)))
            .collect();
        spans.sort_by_key(|(s, _)| match s {
            SectionSpan::Inline { line } => *line,
            SectionSpan::Block { open, .. } => *open,
        });
        let mut out = Vec::with_capacity(self.lines.len() + 4);
        let mut i = 0;
        for (span, block) in spans {
            match span {
                SectionSpan::Block { open, close } => {
                    out.extend(self.lines[i..=open].iter().cloned());
                    let last = block.entries.len().saturating_sub(1);
                    for (j, e) in block.entries.iter().enumerate() {
                        out.push(render_entry_line(&e.text(), j != last, e.cr));
                    }
                    i = close;
                }
                SectionSpan::Inline { line } => {
                    out.extend(self.lines[i..line].iter().cloned());
                    let header = &self.lines[line];
                    let comma = header.trim_end_matches('\r').ends_with(',');
                    render_block(&mut out, header, &block.entries, comma);
                    i = line + 1;
                }
            }
        }
        out.extend(self.lines[i..].iter().cloned());
        out.join("\n")
    }

    fn options(&self) -> Option<&serde_json::Map<String, Value>> {
        self.parsed.options()
    }

    fn legacy_default_keys(&self) -> bool {
        self.nodes.entries.iter().any(|e| e.key.starts_with("··"))
    }
}

// ── placement (§4.5.4) ───────────────────────────────────────────────────

fn node_cmp(a: &Entry, b: &Entry) -> Option<Ordering> {
    vlt_collate(&a.key, &b.key)
}

fn edge_cmp(a: &Entry, b: &Entry) -> Option<Ordering> {
    let a_text = a.text();
    let b_text = b.text();
    let a = parse_edge_entry_text(&a_text)?;
    let b = parse_edge_entry_text(&b_text)?;
    vlt_edge_cmp(a.sort_key(), b.sort_key())
}

/// Replace the entries at the touched indices with their replacements:
/// untouched entries keep their order, and each replacement (in the given
/// order) goes before the first entry it sorts below. When any comparison
/// is outside the collation table, every replacement stays in place.
fn place(
    entries: &[Entry],
    touched: &[(usize, Entry)],
    cmp: fn(&Entry, &Entry) -> Option<Ordering>,
) -> Vec<Entry> {
    let touched_at: BTreeSet<usize> = touched.iter().map(|(i, _)| *i).collect();
    let mut list: Vec<Entry> = entries
        .iter()
        .enumerate()
        .filter(|(i, _)| !touched_at.contains(i))
        .map(|(_, e)| e.clone())
        .collect();
    for (_, new) in touched {
        let mut at = list.len();
        for (i, e) in list.iter().enumerate() {
            match cmp(new, e) {
                Some(Ordering::Less) => {
                    at = i;
                    break;
                }
                Some(_) => {}
                None => {
                    let mut in_place = entries.to_vec();
                    for (i, replacement) in touched {
                        in_place[*i] = replacement.clone();
                    }
                    return in_place;
                }
            }
        }
        list.insert(at, new.clone());
    }
    list
}

// ── target analysis (§4.5.1) ─────────────────────────────────────────────

/// An importer edge into the target.
#[derive(Debug, Clone)]
struct ImporterEdge {
    index: usize,
    edge_type: String,
    spec: String,
    dep: String,
    /// `""` for the root, else the workspace path.
    dir: String,
    field: &'static str,
}

impl ImporterEdge {
    fn pkg_rel(&self) -> String {
        if self.dir.is_empty() {
            PACKAGE_JSON.to_string()
        } else {
            format!("{}/{PACKAGE_JSON}", self.dir)
        }
    }
}

/// The target's current node and its importer edges.
#[derive(Debug, Clone)]
struct Target {
    index: usize,
    key: String,
    /// The node is already one of socket-patch's vendored dirs.
    ours: bool,
    importers: Vec<ImporterEdge>,
}

fn field_for(edge_type: &str) -> Option<&'static str> {
    match edge_type {
        "prod" => Some("dependencies"),
        "dev" => Some("devDependencies"),
        "optional" => Some("optionalDependencies"),
        _ => None,
    }
}

fn importer_dir(from: &str) -> Option<String> {
    if from == "file~_d" || from == "file·." {
        return Some(String::new());
    }
    let dep_id = split_dep_id(from)?;
    (dep_id.kind == DepIdKind::Workspace && is_safe_multi_segment(&dep_id.first))
        .then_some(dep_id.first)
}

fn find_target(doc: &LockDoc, name: &str, version: &str) -> Result<Target, Refusal> {
    let options = doc.options();
    let mut defaults = Vec::new();
    let mut foreign = Vec::new();
    let mut ours = Vec::new();
    for (i, e) in doc.nodes.entries.iter().enumerate() {
        let Some(dep_id) = split_dep_id(&e.key) else {
            continue;
        };
        match dep_id.kind {
            DepIdKind::Registry if dep_id.registry_identity() == Some((name, version)) => {
                if is_default_registry(&dep_id.first, options) {
                    defaults.push((i, dep_id.extra.is_some()));
                } else {
                    foreign.push(i);
                }
            }
            DepIdKind::File => {
                let named = parse_node_entry_text(&e.text())
                    .and_then(|n| n.name())
                    .is_some_and(|n| n == name);
                let vendored = parse_vendored_dir_path(&dep_id.first)
                    .is_some_and(|p| p.name == name && p.version == version);
                if named && vendored {
                    ours.push(i);
                }
            }
            _ => {}
        }
    }
    let key = |i: usize| doc.nodes.entries[i].key.clone();
    if let Some(&i) = foreign.first() {
        return Err((
            UNSUPPORTED,
            format!(
                "vlt-lock.json resolves {name}@{version} as {}, which is not from vlt's default \
                 registry; vendoring rewires only default-registry packages",
                key(i)
            ),
        ));
    }
    let (index, is_ours) = match (defaults.as_slice(), ours.as_slice()) {
        ([(i, false)], []) => (*i, false),
        ([], [i]) => (*i, true),
        ([], []) => {
            return Err((
                "vendor_lock_entry_not_found",
                format!(
                    "vlt-lock.json has no default-registry entry for {name}@{version}; run `vlt \
                     install` first"
                ),
            ))
        }
        _ => {
            let ids: Vec<String> = defaults
                .iter()
                .map(|(i, _)| key(*i))
                .chain(ours.iter().map(|i| key(*i)))
                .collect();
            return Err((
                UNSUPPORTED,
                format!(
                    "vlt-lock.json holds {} ({}): peer/modifier variants; use --mode hosted",
                    if ids.len() == 1 {
                        "a variant instance".to_string()
                    } else {
                        format!("{} instances", ids.len())
                    },
                    ids.join(", ")
                ),
            ));
        }
    };
    let target_key = key(index);
    let mut importers = Vec::new();
    for (i, e) in doc.edges.entries.iter().enumerate() {
        let text = e.text();
        let Some(edge) = parse_edge_entry_text(&text) else {
            continue;
        };
        if edge.target() != target_key {
            continue;
        }
        if !is_importer_dep_id(edge.from()) {
            return Err((
                "vendor_vlt_transitive_unsupported",
                format!(
                    "{name}@{version} is a transitive dependency ({} depends on it); vendored \
                     mode rewires only direct dependencies of the root or a workspace — use \
                     --mode hosted",
                    edge.from()
                ),
            ));
        }
        let Some(field) = field_for(edge.edge_type()) else {
            return Err((
                UNSUPPORTED,
                format!(
                    "`{}` reaches {name}@{version} through a {} peer edge; use --mode hosted",
                    edge.key,
                    edge.edge_type()
                ),
            ));
        };
        let Some(dir) = importer_dir(edge.from()) else {
            return Err((
                UNSUPPORTED,
                format!(
                    "vlt-lock.json importer `{}` is not a safe workspace path",
                    edge.from()
                ),
            ));
        };
        importers.push(ImporterEdge {
            index: i,
            edge_type: edge.edge_type().to_string(),
            spec: edge.spec().to_string(),
            dep: edge.dep_name().to_string(),
            dir,
            field,
        });
    }
    if importers.is_empty() {
        return Err((
            UNSUPPORTED,
            format!("no root or workspace importer depends on {name}@{version} in vlt-lock.json"),
        ));
    }
    Ok(Target {
        index,
        key: target_key,
        ours: is_ours,
        importers,
    })
}

/// `posix_relative(from_dir, to)` for project-relative forward-slashed
/// paths (`""` is the root).
fn posix_relative(from_dir: &str, to: &str) -> String {
    let from: Vec<&str> = from_dir.split('/').filter(|s| !s.is_empty()).collect();
    let to: Vec<&str> = to.split('/').filter(|s| !s.is_empty()).collect();
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    let mut parts: Vec<&str> = vec![".."; from.len() - common];
    parts.extend(&to[common..]);
    parts.join("/")
}

/// The `file:` spec an importer at `dir` declares for `rel`.
fn importer_spec(dir: &str, rel: &str) -> String {
    let r = posix_relative(dir, rel);
    if r.starts_with("../") {
        format!("file:{r}")
    } else {
        format!("file:./{r}")
    }
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).expect("a str serializes to JSON infallibly")
}

/// DESIGN §4.5.1 declaration checks on the importers' package.json files.
fn check_declarations(
    target: &Target,
    pkgs: &BTreeMap<String, String>,
    rel: &str,
) -> Result<(), Refusal> {
    for edge in &target.importers {
        let pkg_rel = edge.pkg_rel();
        let text = pkgs.get(&pkg_rel).ok_or_else(|| {
            (
                OUT_OF_SYNC,
                format!("{pkg_rel} is missing; run `vlt install` first"),
            )
        })?;
        let value: Value = serde_json::from_str(crate::package_json::detect::strip_bom(text))
            .map_err(|_| (OUT_OF_SYNC, format!("{pkg_rel} is not valid JSON")))?;
        let declared = ["dependencies", "devDependencies", "optionalDependencies"]
            .iter()
            .filter(|f| value.get(**f).and_then(|t| t.get(&edge.dep)).is_some())
            .count();
        if declared > 1 {
            return Err((
                UNSUPPORTED,
                format!(
                    "{} is declared in multiple dependency fields of {pkg_rel}; keep it in one \
                     and re-run `vlt install`",
                    edge.dep
                ),
            ));
        }
        let current = value
            .get(edge.field)
            .and_then(|t| t.get(&edge.dep))
            .and_then(Value::as_str);
        let ours = importer_spec(&edge.dir, rel);
        if current != Some(edge.spec.as_str()) && current != Some(ours.as_str()) {
            return Err((
                OUT_OF_SYNC,
                format!(
                    "{pkg_rel} declares {}.{} as {}, but vlt-lock.json locks `{}`; run `vlt \
                     install` first",
                    edge.field,
                    edge.dep,
                    current.map_or_else(|| "nothing".to_string(), |c| format!("`{c}`")),
                    edge.spec
                ),
            ));
        }
        match dependency_token(text, edge.field, &edge.dep) {
            Ok(_) => {}
            Err(SpanError::Duplicate(what)) => {
                return Err((
                    UNSUPPORTED,
                    format!("{pkg_rel} declares {what} more than once"),
                ))
            }
            Err(_) => {
                return Err((
                    OUT_OF_SYNC,
                    format!("{pkg_rel} has no string {}.{}", edge.field, edge.dep),
                ))
            }
        }
    }
    Ok(())
}

async fn read_importer_pkgs(project_root: &Path, target: &Target) -> BTreeMap<String, String> {
    let mut pkgs = BTreeMap::new();
    for edge in &target.importers {
        let rel = edge.pkg_rel();
        if pkgs.contains_key(&rel) {
            continue;
        }
        if let Ok(text) = read_regular_to_string(&project_root.join(&rel)).await {
            pkgs.insert(rel, text);
        }
    }
    pkgs
}

/// Everything the vendored wiring decides before touching the artifact:
/// the parsed lock, the target, and the importer package.json texts.
struct Analysis {
    doc: LockDoc,
    target: Target,
    pkgs: BTreeMap<String, String>,
    rel: String,
}

async fn analyze(
    project_root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
) -> Result<Analysis, Refusal> {
    let text = read_regular_to_string(&project_root.join(VLT_LOCK))
        .await
        .map_err(|e| {
            (
                "vendor_lockfile_missing",
                format!("cannot read {VLT_LOCK}: {e} — run `vlt install` first"),
            )
        })?;
    let doc = parse_doc(&text)?;
    let target = find_target(&doc, name, version)?;
    let pkgs = read_importer_pkgs(project_root, &target).await;
    let rel = vendored_dir_rel(uuid, name, version);
    check_declarations(&target, &pkgs, &rel)?;
    Ok(Analysis {
        doc,
        target,
        pkgs,
        rel,
    })
}

/// The read-only vendored-mode refusals vlt can decide before any write:
/// the lock sniff and layout, the target analysis with its declaration
/// checks, the installed store copy's `bundleDependencies` and duplicate
/// `devDependencies`, and a git ignore rule covering the would-be marker
/// (DESIGN §4.6, core part).
pub async fn vlt_vendor_preflight(
    project_root: &Path,
    purl: &str,
    uuid: &str,
) -> Result<(), Refusal> {
    let Some((name, version)) = super::npm_common::parse_npm_purl(purl) else {
        return Err((
            "unsafe_coordinates",
            format!("cannot parse an npm name@version out of `{purl}`"),
        ));
    };
    let analysis = analyze(project_root, &name, &version, uuid).await?;
    if analysis.target.ours {
        return Ok(());
    }
    let store = project_root
        .join(crate::constants::npm_family::VLT_STORE_DIR)
        .join(&analysis.target.key)
        .join("node_modules")
        .join(&name)
        .join(PACKAGE_JSON);
    if let Ok(text) = read_regular_to_string(&store).await {
        if let Ok(pkg) =
            serde_json::from_str::<Value>(crate::package_json::detect::strip_bom(&text))
        {
            if super::npm_common::declares_bundled_deps(&pkg) {
                return Err((
                    "vendor_bundled_deps_unsupported",
                    format!("{name}@{version} declares bundleDependencies; vendoring would drop its bundled node_modules and break installs"),
                ));
            }
        }
        if let Err(SpanError::Duplicate(_)) = super::npm_dir::strip_dev_dependencies(&text) {
            return Err((
                UNSUPPORTED,
                format!("{name}@{version}'s package.json declares duplicate devDependencies"),
            ));
        }
    }
    if let Some(uuid_dir) = super::path::vendor_uuid_dir_rel("npm", uuid) {
        let marker = format!("{uuid_dir}/{}", super::state::VENDOR_MARKER_FILE);
        if let Some(rules) = super::npm_dir::gitignored(project_root, &[marker]).await {
            return Err((
                super::npm_dir::GITIGNORED,
                super::npm_dir::gitignored_detail(&analysis.rel, &rules),
            ));
        }
    }
    Ok(())
}

// ── wiring ───────────────────────────────────────────────────────────────

/// A planned edit: the record plus the in-memory change behind it.
struct Wiring {
    records: Vec<WiringRecord>,
    pkgs: BTreeMap<String, String>,
    lock: Option<String>,
}

fn wiring_record(file: &str, kind: &str, key: &str, original: String, new: String) -> WiringRecord {
    WiringRecord {
        file: file.to_string(),
        kind: kind.to_string(),
        action: WiringAction::Rewritten,
        key: Some(key.to_string()),
        original: Some(Value::String(original)),
        new: Some(Value::String(new)),
    }
}

/// The prior entry's `original` for a record of this file and kind whose
/// key satisfies `matches`.
fn prior_original<'p>(
    prior: Option<&'p VendorEntry>,
    file: &str,
    kind: &str,
    matches: impl Fn(&str) -> bool,
) -> Option<&'p WiringRecord> {
    prior?
        .wiring
        .iter()
        .find(|r| r.file == file && r.kind == kind && r.key.as_deref().is_some_and(&matches))
}

fn original_text(rec: Option<&WiringRecord>) -> Option<String> {
    rec.and_then(|r| r.original.as_ref())
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// A re-vendor over our own dir carries the prior record's key and
/// original forward; without them the new records could never be reverted.
fn carried(
    target: &Target,
    rec: Option<&WiringRecord>,
    what: &str,
) -> Result<(String, String), Refusal> {
    match (rec.and_then(|r| r.key.clone()), original_text(rec)) {
        (Some(key), Some(original)) => Ok((key, original)),
        _ => Err((
            "vendor_wiring_unknown",
            format!(
                "vlt-lock.json already resolves this package through {}, but the vendor ledger \
                 records no pre-vendor {what} to carry forward (it was likely reconstructed by \
                 `socket-patch repair`); restore the registry spec in package.json, run `vlt \
                 install`, then vendor again",
                target.key
            ),
        )),
    }
}

/// DESIGN §4.5.2–§4.5.4: the records and the new surfaces, or `None` when
/// every surface already names `rel`.
fn plan_wiring(
    analysis: &Analysis,
    prior: Option<&VendorEntry>,
) -> Result<Option<Wiring>, Refusal> {
    let Analysis {
        doc,
        target,
        pkgs,
        rel,
    } = analysis;
    let file_id = file_dep_id(rel, doc.era);
    let node = &doc.nodes.entries[target.index];
    let node_text = node.text();
    let node_entry = parse_node_entry_text(&node_text).ok_or_else(|| {
        (
            "vendor_lockfile_version_unsupported",
            NOT_CANONICAL.to_string(),
        )
    })?;
    let file_tuple =
        render_tuple_with_slots(&node_entry.elems, Some("null"), Some(&json_string(rel)));
    let new_node = Entry {
        key: file_id.clone(),
        value: file_tuple,
        cr: node.cr,
    };

    let mut records = Vec::new();
    let mut new_pkgs = BTreeMap::new();
    let mut importers = target.importers.clone();
    importers.sort_by(|a, b| (&a.dir, a.field, &a.dep).cmp(&(&b.dir, b.field, &b.dep)));
    for edge in &importers {
        let pkg_rel = edge.pkg_rel();
        let text = new_pkgs
            .get(&pkg_rel)
            .or_else(|| pkgs.get(&pkg_rel))
            .cloned()
            .unwrap_or_default();
        let current = dependency_token(&text, edge.field, &edge.dep).map_err(|_| {
            (
                OUT_OF_SYNC,
                format!("{pkg_rel} has no string {}.{}", edge.field, edge.dep),
            )
        })?;
        let new = json_string(&importer_spec(&edge.dir, rel));
        if current == new {
            continue;
        }
        let key = format!("{}/{}", edge.field, edge.dep);
        let original = if target.ours {
            let rec = prior_original(prior, &pkg_rel, KIND_PKG_DEP, |k| k == key);
            carried(target, rec, &format!("{pkg_rel} {key} spec"))?.1
        } else {
            current
        };
        let edited = replace_dependency_token(&text, edge.field, &edge.dep, &new)
            .map_err(|_| (OUT_OF_SYNC, format!("cannot edit {pkg_rel}")))?;
        new_pkgs.insert(pkg_rel.clone(), edited);
        records.push(wiring_record(&pkg_rel, KIND_PKG_DEP, &key, original, new));
    }

    let mut node_touch = Vec::new();
    if *node != new_node {
        let (key, original) = if target.ours {
            let rec = prior_original(prior, VLT_LOCK, KIND_LOCK_NODE, |_| true);
            carried(target, rec, "registry node")?
        } else {
            (node.key.clone(), node.text())
        };
        records.push(wiring_record(
            VLT_LOCK,
            KIND_LOCK_NODE,
            &key,
            original,
            new_node.text(),
        ));
        node_touch.push((target.index, new_node));
    }

    let mut edge_touch = Vec::new();
    let mut edge_order: Vec<usize> = target.importers.iter().map(|e| e.index).collect();
    edge_order.sort_unstable();
    for index in edge_order {
        let edge = target
            .importers
            .iter()
            .find(|e| e.index == index)
            .expect("importer index");
        let current = &doc.edges.entries[index];
        let spec = importer_spec(&edge.dir, rel);
        let new = Entry {
            key: current.key.clone(),
            value: json_string(&format!("{} {spec} {file_id}", edge.edge_type)),
            cr: current.cr,
        };
        if *current == new {
            continue;
        }
        let original = if target.ours {
            let rec = prior_original(prior, VLT_LOCK, KIND_LOCK_EDGE, |k| k == current.key);
            carried(target, rec, &format!("edge `{}`", current.key))?.1
        } else {
            current.text()
        };
        records.push(wiring_record(
            VLT_LOCK,
            KIND_LOCK_EDGE,
            &current.key,
            original,
            new.text(),
        ));
        edge_touch.push((index, new));
    }
    for (index, current) in doc.edges.entries.iter().enumerate() {
        if current.edge_from() != target.key || target.key == file_id {
            continue;
        }
        let new = Entry {
            key: format!("{file_id} {}", current.edge_dep()),
            value: current.value.clone(),
            cr: current.cr,
        };
        let (key, original) = if target.ours {
            let dep = current.edge_dep().to_string();
            let rec = prior_original(prior, VLT_LOCK, KIND_LOCK_EDGE, |k| {
                k.split_once(' ')
                    .is_some_and(|(from, d)| d == dep && !is_importer_dep_id(from))
            });
            carried(target, rec, &format!("edge `{}`", current.key))?
        } else {
            (current.key.clone(), current.text())
        };
        records.push(wiring_record(
            VLT_LOCK,
            KIND_LOCK_EDGE,
            &key,
            original,
            new.text(),
        ));
        edge_touch.push((index, new));
    }

    if records.is_empty() {
        return Ok(None);
    }
    let lock = if node_touch.is_empty() && edge_touch.is_empty() {
        None
    } else {
        let next = LockDoc {
            lines: doc.lines.clone(),
            parsed: doc.parsed.clone(),
            era: doc.era,
            nodes: Block {
                span: doc.nodes.span,
                entries: place(&doc.nodes.entries, &node_touch, node_cmp),
            },
            edges: Block {
                span: doc.edges.span,
                entries: place(&doc.edges.entries, &edge_touch, edge_cmp),
            },
        };
        Some(next.render())
    };
    Ok(Some(Wiring {
        records,
        pkgs: new_pkgs,
        lock,
    }))
}

/// Write every changed package.json (path order), then the lock; a lock
/// write failure puts the package.json files back.
async fn commit(
    project_root: &Path,
    wiring: &Wiring,
    originals: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut written: Vec<&String> = Vec::new();
    for (rel, text) in &wiring.pkgs {
        if let Err(e) =
            atomic_write_bytes_preserving_mode(&project_root.join(rel), text.as_bytes()).await
        {
            unwind(project_root, &written, originals).await;
            return Err(format!("cannot write {rel}: {e}"));
        }
        written.push(rel);
    }
    if let Some(lock) = &wiring.lock {
        if let Err(e) =
            atomic_write_bytes_preserving_mode(&project_root.join(VLT_LOCK), lock.as_bytes()).await
        {
            unwind(project_root, &written, originals).await;
            return Err(format!(
                "cannot write {VLT_LOCK}: {e} (package.json files restored to their original bytes)"
            ));
        }
    }
    Ok(())
}

async fn unwind(project_root: &Path, written: &[&String], originals: &BTreeMap<String, String>) {
    for rel in written {
        if let Some(text) = originals.get(*rel) {
            let _ =
                atomic_write_bytes_preserving_mode(&project_root.join(rel), text.as_bytes()).await;
        }
    }
}

/// The ledger entry this project already has for `purl` under vlt.
async fn prior_vlt_entry(project_root: &Path, purl: &str) -> Option<VendorEntry> {
    let state = load_state(project_root).await.ok()?;
    state.entries.into_iter().find_map(|(key, entry)| {
        (entry.ecosystem == "npm"
            && entry.flavor.as_deref() == Some(FLAVOR)
            && entry.covers_purl(&key, purl))
        .then_some(entry)
    })
}

/// Vendor one installed npm package into a vlt project (see the module
/// doc). Same contract as the other npm backends: refuse-early / wire-last,
/// `entry` present iff `result.success` and not a dry run, and an in-sync
/// re-run synthesizes AlreadyPatched with no entry.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn vendor_vlt(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&super::VendorServiceConfig>,
) -> VendorOutcome {
    let coords = match guard_coordinates(purl, record) {
        Ok(coords) => coords,
        Err(outcome) => return *outcome,
    };
    let (name, version) = (coords.name.as_str(), coords.version.as_str());
    let analysis = match analyze(project_root, name, version, &record.uuid).await {
        Ok(analysis) => analysis,
        Err((code, detail)) => return refused(code, detail),
    };
    let mut warnings = Vec::new();
    if analysis.doc.legacy_default_keys() {
        warnings.push(VendorWarning::new(
            "vendor_vlt_legacy_lockfile",
            "vlt-lock.json was written by vlt 0.0.0-19 … 1.0.0-rc.8 (`··` ids); those releases \
             install the vendored lock but fail if it is deleted and re-created — upgrade vlt",
        ));
    }
    let prior = prior_vlt_entry(project_root, purl).await;
    let wiring = match plan_wiring(&analysis, prior.as_ref()) {
        Ok(wiring) => wiring,
        Err((code, detail)) => return refused(code, detail),
    };

    let (staged, result) = match stage_patch_dir(
        purl,
        installed_dir,
        project_root,
        record,
        sources,
        dry_run,
        force,
        &mut warnings,
        service,
    )
    .await
    {
        Ok(pair) => pair,
        Err(outcome) => return *outcome,
    };
    let Some(staged) = staged else {
        return done(result, None, warnings);
    };
    if staged.staged_pkg_json.is_some() {
        warnings.push(VendorWarning::new(
            "vendor_dep_manifest_stale",
            format!(
                "the patch rewrites {name}@{version}'s package.json; vlt-lock.json keeps the \
                 node's recorded dependency edges — if the patch changed dependency ranges, run \
                 `vlt install` to re-resolve them"
            ),
        ));
    }
    let entry_for = |wiring: Vec<WiringRecord>| VendorEntry {
        ecosystem: "npm".to_string(),
        base_purl: coords.base_purl.clone(),
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: staged.rel_dir.clone(),
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: Some(staged.inventory.clone()),
        },
        wiring,
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: Some(FLAVOR.to_string()),
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    };
    let marker = VendorMarker::new("npm", &coords.base_purl, record, vendored_at);
    let uuid_dir = project_root.join(&coords.uuid_dir_rel);

    let Some(wiring) = wiring else {
        if staged.reused {
            let rel_abs = project_root.join(&staged.rel_dir);
            return done(
                already_patched_result(purl, &rel_abs, &record.files),
                None,
                warnings,
            );
        }
        let relink = if staged.links_dropped {
            "; its node_modules/ held more than vlt's dependency links and was discarded, so \
             run `vlt install` to re-link its dependencies"
        } else {
            ""
        };
        warnings.push(VendorWarning::new(
            "vendor_artifact_rebuilt",
            format!(
                "the committed vendored dir for {name}@{version} was missing or stale; rebuilt \
                 at {} (vlt-lock.json and package.json untouched){relink}",
                staged.rel_dir
            ),
        ));
        write_marker_or_warn(&uuid_dir, &marker, &mut warnings).await;
        return done(result, Some(entry_for(Vec::new())), warnings);
    };
    if let Err(e) = commit(project_root, &wiring, &analysis.pkgs).await {
        return done_failure_unstage(
            purl,
            e,
            project_root,
            &coords.uuid_dir_rel,
            staged.uuid_dir_preexisted,
        )
        .await;
    }
    write_marker_or_warn(&uuid_dir, &marker, &mut warnings).await;
    done(result, Some(entry_for(wiring.records)), warnings)
}

/// Rewrite a vlt entry's `<uuid>/.gitignore` and `<uuid>/.gitattributes`
/// when absent or changed (DESIGN §4.8 health: neither is part of the
/// artifact, so repairing them is no rebuild).
pub async fn restore_vlt_uuid_metadata(
    entry: &VendorEntry,
    project_root: &Path,
) -> std::io::Result<()> {
    let Some(uuid_dir) = super::path::vendor_uuid_dir_rel("npm", &entry.uuid) else {
        return Err(std::io::Error::other(format!(
            "`{}` is not a canonical patch uuid",
            entry.uuid
        )));
    };
    super::npm_dir::restore_uuid_metadata(&project_root.join(uuid_dir)).await
}

/// Whether `text` passes the §4.1 router sniff (a BOM-less JSON object
/// with `lockfileVersion` 0 or 1).
pub fn vlt_lock_sniff_ok(text: &str) -> bool {
    sniff_vendor_lock(text).is_ok()
}

/// The importer package.json files of the project's canonical
/// `vlt-lock.json`, project-relative: the root one plus every workspace
/// importer its edges name. Just the root one when the lock is missing or
/// not canonical.
pub async fn vlt_importer_package_jsons(project_root: &Path) -> Vec<String> {
    let doc = read_regular_to_string(&project_root.join(VLT_LOCK))
        .await
        .ok()
        .and_then(|text| parse_doc(&text).ok());
    let mut dirs: BTreeSet<String> = BTreeSet::from([String::new()]);
    for e in doc.iter().flat_map(|d| &d.edges.entries) {
        if let Some(dir) = importer_dir(e.edge_from()) {
            dirs.insert(dir);
        }
    }
    dirs.into_iter().map(|d| pkg_json_rel(&d)).collect()
}

fn pkg_json_rel(dir: &str) -> String {
    if dir.is_empty() {
        PACKAGE_JSON.to_string()
    } else {
        format!("{dir}/{PACKAGE_JSON}")
    }
}

// ── in use ───────────────────────────────────────────────────────────────

fn lock_has_file_node_under(text: &str, uuid: &str) -> Option<bool> {
    let LockSniff::Readable(lock) = sniff_lock(text) else {
        return None;
    };
    let prefix = format!(".socket/vendor/npm/{uuid}/");
    Some(lock.nodes().is_some_and(|nodes| {
        nodes.keys().any(|id| {
            split_dep_id(id)
                .is_some_and(|d| d.kind == DepIdKind::File && d.first.starts_with(&prefix))
        })
    }))
}

/// Is this vlt-vendored entry still consumed? Structural: `true` iff some
/// `file` node's decoded path is under `.socket/vendor/npm/<uuid>/`.
/// `None` when the lock is missing or unreadable.
pub async fn vlt_entry_in_use(entry: &VendorEntry, project_root: &Path) -> Option<bool> {
    let text = read_regular_to_string(&project_root.join(VLT_LOCK))
        .await
        .ok()?;
    lock_has_file_node_under(&text, &entry.uuid)
}

// ── revert (§4.7) ────────────────────────────────────────────────────────

fn drifted(detail: impl Into<String>) -> VendorWarning {
    VendorWarning::new("vendor_lock_entry_drifted", detail.into())
}

async fn guard_unwired(
    project_root: &Path,
    entry: &VendorEntry,
    uuid_dir_rel: &str,
) -> Option<RevertOutcome> {
    let clause = match vlt_entry_in_use(entry, project_root).await {
        Some(false) => return None,
        Some(true) => format!("{VLT_LOCK} still resolves through it"),
        None => match tokio::fs::try_exists(project_root.join(VLT_LOCK)).await {
            Ok(false) => return None,
            _ => format!(
                "{VLT_LOCK} exists but could not be read to prove it no longer references it"
            ),
        },
    };
    let detail = format!(
        "refusing to remove {uuid_dir_rel}: the ledger entry records no pre-vendor wiring to \
         replay (it was likely reconstructed by `socket-patch repair`) and {clause} — deleting \
         the artifact would make every subsequent install fail; restore the registry \
         dependency in package.json, run `vlt install`, then re-run `vendor --revert`"
    );
    Some(RevertOutcome {
        success: false,
        warnings: vec![VendorWarning::new(
            "vendor_wiring_unknown_revert_blocked",
            detail.clone(),
        )],
        error: Some(detail),
        kept_artifact: false,
    })
}

fn fragment(v: &Option<Value>) -> Option<&str> {
    v.as_ref().and_then(Value::as_str)
}

/// The recorded key's dependency field and name (`"<F>/<N>"`; the name may
/// itself contain `/`).
fn split_pkg_key(key: &str) -> Option<(&str, &str)> {
    let (field, name) = key.split_once('/')?;
    matches!(
        field,
        "dependencies" | "devDependencies" | "optionalDependencies"
    )
    .then_some((field, name))
}

/// The package.json files a revert may write: the root one, and those of
/// workspace importers the live lock or the entry's own edge records name.
fn allowed_pkg_files(doc: Option<&LockDoc>, entry: &VendorEntry) -> BTreeSet<String> {
    let mut dirs: BTreeSet<String> = BTreeSet::from([String::new()]);
    let mut add = |from: &str| {
        if let Some(dir) = importer_dir(from) {
            dirs.insert(dir);
        }
    };
    if let Some(doc) = doc {
        for e in &doc.edges.entries {
            add(e.edge_from());
        }
    }
    for rec in entry.wiring.iter().filter(|r| r.kind == KIND_LOCK_EDGE) {
        if let Some((from, _)) = rec.key.as_deref().and_then(|k| k.split_once(' ')) {
            add(from);
        }
    }
    dirs.into_iter().map(|d| pkg_json_rel(&d)).collect()
}

/// The lock being reverted: each block's entries, restored in place, and
/// the indices restored so far (re-placed when rendering).
struct Staged {
    nodes: Vec<Entry>,
    edges: Vec<Entry>,
    touched_nodes: Vec<usize>,
    touched_edges: Vec<usize>,
    /// Vendored entries dropped in favor of a live registry twin.
    merged_nodes: BTreeSet<usize>,
    merged_edges: BTreeSet<usize>,
}

enum Step {
    Applied,
    AlreadyReverted,
    Drift(String),
}

fn slot_value(raw: Option<&str>) -> Option<Value> {
    raw.filter(|s| *s != "null")
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
}

fn registry_slots(entry: &Entry) -> Option<(Option<Value>, Option<Value>)> {
    let text = entry.text();
    parse_node_entry_text(&text).map(|n| (slot_value(n.slot(2)), slot_value(n.slot(3))))
}

fn revert_node(staged: &mut Staged, rec: &WiringRecord) -> Step {
    let (Some(new), Some(original)) = (fragment(&rec.new), fragment(&rec.original)) else {
        return Step::Drift("the vlt_lock_node record has no pre-vendor original".into());
    };
    let (Some(new), Some(original)) = (parse_node_entry_text(new), parse_node_entry_text(original))
    else {
        return Step::Drift("the vlt_lock_node record is not vlt node entry text".into());
    };
    if let Some(i) = staged.nodes.iter().position(|e| e.key == new.key) {
        let current = staged.nodes[i].clone();
        let current_text = current.text();
        let Some(live) = parse_node_entry_text(&current_text) else {
            return Step::Drift(format!("{} is outside vlt's node grammar", new.key));
        };
        if live.slot(2) != Some("null") || slot_value(live.slot(3)) != slot_value(new.slot(3)) {
            return Step::Drift(format!("{} drifted from the vendored wiring", new.key));
        }
        let wanted = (slot_value(original.slot(2)), slot_value(original.slot(3)));
        if let Some(twin) = staged.nodes.iter().find(|e| e.key == original.key) {
            if registry_slots(twin) != Some(wanted) {
                return Step::Drift(format!(
                    "vlt-lock.json holds both {} and a different {}",
                    new.key, original.key
                ));
            }
            staged.merged_nodes.insert(i);
            return Step::Applied;
        }
        let tuple = render_tuple_with_slots(
            &live.elems,
            original.slot(2).filter(|s| *s != "null"),
            original.slot(3).filter(|s| *s != "null"),
        );
        staged.nodes[i] = Entry {
            key: original.key.to_string(),
            value: tuple,
            cr: current.cr,
        };
        staged.touched_nodes.push(i);
        return Step::Applied;
    }
    let restored = staged
        .nodes
        .iter()
        .find(|e| e.key == original.key)
        .and_then(registry_slots);
    if restored == Some((slot_value(original.slot(2)), slot_value(original.slot(3)))) {
        Step::AlreadyReverted
    } else {
        Step::Drift(format!("vlt-lock.json no longer has {}", new.key))
    }
}

fn revert_edge(staged: &mut Staged, rec: &WiringRecord) -> Step {
    let (Some(new), Some(original)) = (fragment(&rec.new), fragment(&rec.original)) else {
        return Step::Drift("the vlt_lock_edge record has no pre-vendor original".into());
    };
    let (Some(new), Some(original)) = (
        Entry::from_text(new, false, false),
        Entry::from_text(original, false, false),
    ) else {
        return Step::Drift("the vlt_lock_edge record is not vlt edge entry text".into());
    };
    let find = |key: &str| staged.edges.iter().position(|e| e.key == key);
    if is_importer_dep_id(original.edge_from()) {
        return match find(&new.key) {
            Some(i) if staged.edges[i].value == new.value => {
                let cr = staged.edges[i].cr;
                staged.edges[i] = Entry { cr, ..original };
                staged.touched_edges.push(i);
                Step::Applied
            }
            Some(i) if staged.edges[i].value == original.value => Step::AlreadyReverted,
            Some(_) => Step::Drift(format!(
                "vlt-lock.json edge `{}` changed since vendoring",
                new.key
            )),
            None => Step::Drift(format!(
                "vlt-lock.json no longer has the edge `{}`",
                new.key
            )),
        };
    }
    match (find(&new.key), find(&original.key)) {
        (Some(i), Some(j)) if staged.edges[i].value == staged.edges[j].value => {
            staged.merged_edges.insert(i);
            Step::Applied
        }
        (Some(_), Some(_)) => Step::Drift(format!(
            "vlt-lock.json holds both `{}` and a different `{}`",
            new.key, original.key
        )),
        (Some(i), None) => {
            staged.edges[i].key = original.key.clone();
            staged.touched_edges.push(i);
            Step::Applied
        }
        (None, Some(_)) => Step::AlreadyReverted,
        (None, None) => Step::Drift(format!(
            "vlt-lock.json no longer has the edge `{}`",
            new.key
        )),
    }
}

fn revert_pkg(pkgs: &mut BTreeMap<String, String>, rec: &WiringRecord) -> Step {
    let (Some(new), Some(original)) = (fragment(&rec.new), fragment(&rec.original)) else {
        return Step::Drift(format!(
            "the {} record has no pre-vendor original",
            rec.file
        ));
    };
    let Some((field, name)) = rec.key.as_deref().and_then(split_pkg_key) else {
        return Step::Drift(format!("unknown vlt_pkg_dep key in {}", rec.file));
    };
    let Some(text) = pkgs.get(&rec.file) else {
        return Step::Drift(format!("{} is missing", rec.file));
    };
    match dependency_token(text, field, name) {
        Ok(token) if token == new => match replace_dependency_token(text, field, name, original) {
            Ok(edited) => {
                pkgs.insert(rec.file.clone(), edited);
                Step::Applied
            }
            Err(_) => Step::Drift(format!("cannot edit {}", rec.file)),
        },
        Ok(token) if token == original => Step::AlreadyReverted,
        _ => Step::Drift(format!(
            "{} {field}.{name} changed since vendoring",
            rec.file
        )),
    }
}

/// The DESIGN §4.7 cross-grammar drift detail: the user re-created the lock
/// under the other DepID grammar while package.json still names our dir.
fn cross_grammar_detail(entry: &VendorEntry, doc: &LockDoc) -> Option<String> {
    let node = entry.wiring.iter().find(|r| r.kind == KIND_LOCK_NODE)?;
    let recorded = fragment(&node.new).and_then(parse_node_entry_text)?;
    let recorded_era = split_dep_id(recorded.key)?.era;
    if recorded_era == doc.era
        || !doc
            .nodes
            .entries
            .iter()
            .any(|e| e.key != recorded.key && lock_key_under(&e.key, &entry.uuid))
    {
        return None;
    }
    let pkg = entry.wiring.iter().find(|r| r.kind == KIND_PKG_DEP)?;
    let (_, name) = pkg.key.as_deref().and_then(split_pkg_key)?;
    let original = fragment(&pkg.original)
        .and_then(|raw| serde_json::from_str::<String>(raw).ok())
        .unwrap_or_default();
    Some(format!(
        "vlt-lock.json was re-created by a different vlt lockfile grammar; set {name} in {} back \
         to {original}, run `vlt install`, then re-run `socket-patch vendor --revert` to remove \
         the artifact",
        pkg.file
    ))
}

fn lock_key_under(key: &str, uuid: &str) -> bool {
    let prefix = format!(".socket/vendor/npm/{uuid}/");
    split_dep_id(key).is_some_and(|d| d.kind == DepIdKind::File && d.first.starts_with(&prefix))
}

/// Undo one vlt-vendored package: every record through its §4.5.3 inverse,
/// all or nothing, then remove the artifact.
pub async fn revert_vlt_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    let RevertOpts {
        dry_run,
        keep_artifact,
    } = opts;
    let uuid_dir_rel = match guard_revert_uuid_dir(&entry.uuid) {
        Ok(d) => d,
        Err(outcome) => return outcome,
    };
    if !keep_artifact && entry.wiring.is_empty() {
        if let Some(blocked) = guard_unwired(project_root, entry, &uuid_dir_rel).await {
            return blocked;
        }
    }
    if dry_run {
        return RevertOutcome::ok();
    }
    let mut outcome = RevertOutcome::ok();

    let lock_text = match read_regular_to_string(&project_root.join(VLT_LOCK)).await {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return RevertOutcome::failed(format!("cannot read {VLT_LOCK}: {e}")),
    };
    let doc = match lock_text.as_deref().map(parse_doc).transpose() {
        Ok(doc) => doc,
        Err((_, detail)) => return RevertOutcome::failed(detail),
    };
    let allowed = allowed_pkg_files(doc.as_ref(), entry);
    let mut pkgs: BTreeMap<String, String> = BTreeMap::new();
    for rec in &entry.wiring {
        let known =
            rec.file == VLT_LOCK || (rec.kind == KIND_PKG_DEP && allowed.contains(&rec.file));
        if !known {
            outcome.warnings.push(drifted(format!(
                "ignoring wiring record `{}` for non-allowlisted file `{}`",
                rec.kind, rec.file
            )));
            continue;
        }
        if rec.kind == KIND_PKG_DEP && !pkgs.contains_key(&rec.file) {
            match read_regular_to_string(&project_root.join(&rec.file)).await {
                Ok(text) => {
                    pkgs.insert(rec.file.clone(), text);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return RevertOutcome::failed(format!("cannot read {}: {e}", rec.file)),
            }
        }
    }
    if outcome.drift_skipped() {
        outcome.keep_artifact(&uuid_dir_rel);
        return outcome;
    }

    let wired_lock = doc.as_ref().is_some_and(|d| {
        d.nodes
            .entries
            .iter()
            .any(|e| lock_key_under(&e.key, &entry.uuid))
    });
    let wired_pkg = entry
        .wiring
        .iter()
        .filter(|r| r.kind == KIND_PKG_DEP)
        .any(|rec| {
            let (Some(new), Some((field, name))) = (
                fragment(&rec.new),
                rec.key.as_deref().and_then(split_pkg_key),
            ) else {
                return false;
            };
            pkgs.get(&rec.file)
                .and_then(|t| dependency_token(t, field, name).ok())
                .is_some_and(|t| t == new)
        });
    let already_reverted = !wired_lock && !wired_pkg;

    if !already_reverted {
        let mut staged = doc.as_ref().map(|d| Staged {
            nodes: d.nodes.entries.clone(),
            edges: d.edges.entries.clone(),
            touched_nodes: Vec::new(),
            touched_edges: Vec::new(),
            merged_nodes: BTreeSet::new(),
            merged_edges: BTreeSet::new(),
        });
        let mut new_pkgs = pkgs.clone();
        let mut drift: Option<String> = None;
        for rec in entry.wiring.iter().rev() {
            let step = match (rec.kind.as_str(), staged.as_mut()) {
                (KIND_PKG_DEP, _) => revert_pkg(&mut new_pkgs, rec),
                (KIND_LOCK_NODE, Some(staged)) => revert_node(staged, rec),
                (KIND_LOCK_EDGE, Some(staged)) => revert_edge(staged, rec),
                (KIND_LOCK_NODE | KIND_LOCK_EDGE, None) => {
                    Step::Drift(format!("{VLT_LOCK} no longer exists"))
                }
                (other, _) => Step::Drift(format!("unknown vlt wiring kind `{other}`")),
            };
            if let Step::Drift(detail) = step {
                drift = Some(detail);
                break;
            }
        }
        if let Some(detail) = drift {
            let detail = doc
                .as_ref()
                .and_then(|d| cross_grammar_detail(entry, d))
                .unwrap_or(detail);
            outcome.warnings.push(drifted(detail));
            outcome.keep_artifact(&uuid_dir_rel);
            return outcome;
        }
        let new_lock = match (doc.as_ref(), staged) {
            (Some(doc), Some(staged)) => Some(render_restored(doc, staged)),
            _ => None,
        };
        if let Some(lock) = new_lock.filter(|l| Some(l) != lock_text.as_ref()) {
            if let Err(e) =
                atomic_write_bytes_preserving_mode(&project_root.join(VLT_LOCK), lock.as_bytes())
                    .await
            {
                return RevertOutcome::failed(format!("cannot write {VLT_LOCK}: {e}"));
            }
        }
        for (rel, text) in &new_pkgs {
            if pkgs.get(rel) == Some(text) {
                continue;
            }
            if let Err(e) =
                atomic_write_bytes_preserving_mode(&project_root.join(rel), text.as_bytes()).await
            {
                return RevertOutcome::failed(format!("cannot write {rel}: {e}"));
            }
        }
    }

    if !keep_artifact {
        let uuid_dir = project_root.join(&uuid_dir_rel);
        if let Err(e) = remove_tree_and_prune(&uuid_dir, &project_root.join(SOCKET_DIR)).await {
            return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
        }
    }
    outcome
}

/// A block without its merged entries, the restored ones re-placed
/// (§4.5.4) in the forward record order.
fn restored_block(
    entries: &[Entry],
    touched: &[usize],
    merged: &BTreeSet<usize>,
    cmp: fn(&Entry, &Entry) -> Option<Ordering>,
) -> Vec<Entry> {
    let kept: Vec<Entry> = entries
        .iter()
        .enumerate()
        .filter(|(i, _)| !merged.contains(i))
        .map(|(_, e)| e.clone())
        .collect();
    let touched: Vec<(usize, Entry)> = touched
        .iter()
        .rev()
        .map(|&i| (i - merged.range(..i).count(), entries[i].clone()))
        .collect();
    place(&kept, &touched, cmp)
}

fn render_restored(doc: &LockDoc, staged: Staged) -> String {
    let nodes = restored_block(
        &staged.nodes,
        &staged.touched_nodes,
        &staged.merged_nodes,
        node_cmp,
    );
    let edges = restored_block(
        &staged.edges,
        &staged.touched_edges,
        &staged.merged_edges,
        edge_cmp,
    );
    LockDoc {
        lines: doc.lines.clone(),
        parsed: doc.parsed.clone(),
        era: doc.era,
        nodes: Block {
            span: doc.nodes.span,
            entries: nodes,
        },
        edges: Block {
            span: doc.edges.span,
            entries: edges,
        },
    }
    .render()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::vendor::state::{save_state, VendorState};
    use std::collections::HashMap;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const UUID2: &str = "0a1b2c3d-4e5f-4a7b-8c9d-0e1f2a3b4c5d";
    const ORIG: &[u8] = b"module.exports = 'orig';\n";
    const PATCHED: &[u8] = b"module.exports = 'patched';\n";
    const PURL: &str = "pkg:npm/left-pad@1.3.0";
    const REG: &str = "~npm~left-pad@1.3.0";
    const REG_NODE: &str = r#""~npm~left-pad@1.3.0": [0,"left-pad","sha512-REG==","https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"]"#;

    fn render(version: u8, nodes: &[&str], edges: &[&str]) -> String {
        let block = |entries: &[&str]| {
            if entries.is_empty() {
                return "{}".to_string();
            }
            let lines: Vec<String> = entries
                .iter()
                .enumerate()
                .map(|(i, e)| format!("    {e}{}", if i + 1 < entries.len() { "," } else { "" }))
                .collect();
            format!("{{\n{}\n  }}", lines.join("\n"))
        };
        format!(
            "{{\n  \"lockfileVersion\": {version},\n  \"options\": {{}},\n  \"nodes\": {},\n  \"edges\": {}\n}}\n",
            block(nodes),
            block(edges)
        )
    }

    fn basic_lock() -> String {
        render(
            1,
            &[
                r#""~npm~a@1.0.0": [0,"a","sha512-A=="]"#,
                REG_NODE,
                r#""~npm~z@1.0.0": [0,"z","sha512-Z=="]"#,
            ],
            &[
                r#""file~_d a": "prod 1.0.0 ~npm~a@1.0.0""#,
                r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#,
                r#""~npm~left-pad@1.3.0 z": "prod ^1.0.0 ~npm~z@1.0.0""#,
            ],
        )
    }

    const ROOT_PKG: &str =
        "{\n  \"name\": \"root\",\n  \"dependencies\": {\n    \"a\": \"1.0.0\",\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";

    struct Fx {
        _tmp: tempfile::TempDir,
        root: std::path::PathBuf,
        installed: std::path::PathBuf,
        blobs: std::path::PathBuf,
    }

    async fn fx(lock: &str, pkgs: &[(&str, &str)]) -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("p");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join(VLT_LOCK), lock).await.unwrap();
        for (rel, text) in pkgs {
            let path = root.join(rel);
            tokio::fs::create_dir_all(path.parent().unwrap())
                .await
                .unwrap();
            tokio::fs::write(path, text).await.unwrap();
        }
        let installed = tmp.path().join("installed");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        tokio::fs::write(
            installed.join(PACKAGE_JSON),
            "{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"devDependencies\":{\"t\":\"1\"}}",
        )
        .await
        .unwrap();
        tokio::fs::write(installed.join("index.js"), ORIG)
            .await
            .unwrap();
        let blobs = tmp.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(compute_git_sha256_from_bytes(PATCHED)), PATCHED)
            .await
            .unwrap();
        Fx {
            _tmp: tmp,
            root,
            installed,
            blobs,
        }
    }

    fn record(uuid: &str) -> PatchRecord {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(ORIG),
                after_hash: compute_git_sha256_from_bytes(PATCHED),
            },
        );
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: String::new(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    async fn run(fx: &Fx, uuid: &str, dry_run: bool) -> VendorOutcome {
        let sources = PatchSources::blobs_only(&fx.blobs);
        vendor_vlt(
            PURL,
            &fx.installed,
            &fx.root,
            &record(uuid),
            &sources,
            "t",
            dry_run,
            false,
            None,
        )
        .await
    }

    fn refusal(outcome: VendorOutcome) -> (&'static str, String) {
        match outcome {
            VendorOutcome::Refused { code, detail } => (code, detail),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn entry_of(outcome: VendorOutcome) -> (VendorEntry, Vec<VendorWarning>) {
        match outcome {
            VendorOutcome::Done {
                result,
                entry: Some(entry),
                warnings,
            } if result.success => (entry, warnings),
            other => panic!("expected a wired entry, got {other:?}"),
        }
    }

    async fn read(fx: &Fx, rel: &str) -> String {
        tokio::fs::read_to_string(fx.root.join(rel)).await.unwrap()
    }

    async fn persist(fx: &Fx, entry: &VendorEntry) {
        let mut state = VendorState::new();
        state.entries.insert(PURL.into(), entry.clone());
        save_state(&fx.root, &state).await.unwrap();
    }

    fn entry(key: &str) -> Entry {
        Entry {
            key: key.into(),
            value: "[0,\"x\"]".into(),
            cr: false,
        }
    }

    #[test]
    fn placement_inserts_among_untouched_entries_and_falls_back_in_place() {
        let entries = vec![
            entry("~npm~b@1.0.0"),
            entry("~npm~d@1.0.0"),
            entry("~npm~f@1.0.0"),
        ];
        let placed = place(&entries, &[(0, entry("~npm~e@1.0.0"))], node_cmp);
        let keys: Vec<&str> = placed.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, ["~npm~d@1.0.0", "~npm~e@1.0.0", "~npm~f@1.0.0"]);
        let placed = place(&entries, &[(1, entry("~npm~z@1.0.0"))], node_cmp);
        assert_eq!(placed.last().unwrap().key, "~npm~z@1.0.0");

        // `é` is outside the collation table: every replacement stays put.
        let placed = place(&entries, &[(0, entry("file~é"))], node_cmp);
        let keys: Vec<&str> = placed.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, ["file~é", "~npm~d@1.0.0", "~npm~f@1.0.0"]);
    }

    #[test]
    fn posix_relative_specs_from_every_importer() {
        let rel = format!(".socket/vendor/npm/{UUID}/a-1.0.0/node_modules/a");
        assert_eq!(importer_spec("", &rel), format!("file:./{rel}"));
        assert_eq!(
            importer_spec("packages/a", &rel),
            format!("file:../../{rel}")
        );
        assert_eq!(
            importer_spec(".socket", &rel),
            format!("file:./{}", &rel[8..])
        );
    }

    #[tokio::test]
    async fn wires_the_node_edges_and_package_json_in_vlt_order() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, warnings) = entry_of(run(&fx, UUID, false).await);
        assert!(warnings.is_empty(), "{warnings:?}");
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad");
        let file_id =
            format!("file~.socket+vendor+npm+{UUID}+left-pad-1.3.0+node__modules+left-pad");
        assert_eq!(
            read(&fx, VLT_LOCK).await,
            render(
                1,
                &[
                    r#""~npm~a@1.0.0": [0,"a","sha512-A=="]"#,
                    r#""~npm~z@1.0.0": [0,"z","sha512-Z=="]"#,
                    &format!(r#""{file_id}": [0,"left-pad",null,"{rel}"]"#),
                ],
                &[
                    r#""file~_d a": "prod 1.0.0 ~npm~a@1.0.0""#,
                    &format!(r#""file~_d left-pad": "prod file:./{rel} {file_id}""#),
                    &format!(r#""{file_id} z": "prod ^1.0.0 ~npm~z@1.0.0""#),
                ],
            )
        );
        assert_eq!(
            read(&fx, PACKAGE_JSON).await,
            ROOT_PKG.replace(
                "\"left-pad\": \"1.3.0\"",
                &format!("\"left-pad\": \"file:./{rel}\"")
            )
        );
        let kinds: Vec<(&str, Option<&str>)> = entry
            .wiring
            .iter()
            .map(|r| (r.kind.as_str(), r.key.as_deref()))
            .collect();
        assert_eq!(
            kinds,
            [
                (KIND_PKG_DEP, Some("dependencies/left-pad")),
                (KIND_LOCK_NODE, Some(REG)),
                (KIND_LOCK_EDGE, Some("file~_d left-pad")),
                (KIND_LOCK_EDGE, Some("~npm~left-pad@1.3.0 z")),
            ]
        );
        assert_eq!(fragment(&entry.wiring[0].original), Some("\"1.3.0\""));
        assert_eq!(fragment(&entry.wiring[1].original), Some(REG_NODE));
        assert_eq!(entry.artifact.path, rel);
        assert!(entry.artifact.sha256.is_empty());
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        match run(&fx, UUID, true).await {
            VendorOutcome::Done {
                result,
                entry: None,
                ..
            } => assert!(result.success),
            other => panic!("{other:?}"),
        }
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
        assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG);
        assert!(!fx.root.join(".socket").exists());
    }

    #[tokio::test]
    async fn target_analysis_refusals() {
        let url_node = r#""~npm~left-pad@1.3.0~peer.1": [0,"left-pad","sha512-P=="]"#;
        let cases: Vec<(String, &str, &str, &str)> = vec![
            (
                render(1, &[r#""~acme~left-pad@1.3.0": [0,"left-pad","sha512-A=="]"#], &[r#""file~_d left-pad": "prod 1.3.0 ~acme~left-pad@1.3.0""#]),
                ROOT_PKG,
                UNSUPPORTED,
                "not from vlt's default registry",
            ),
            (
                render(1, &[REG_NODE, url_node], &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#]),
                ROOT_PKG,
                UNSUPPORTED,
                "peer/modifier variants; use --mode hosted",
            ),
            (
                render(1, &[url_node], &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0~peer.1""#]),
                ROOT_PKG,
                UNSUPPORTED,
                "peer/modifier variants",
            ),
            (
                render(1, &[r#""~npm~a@1.0.0": [0,"a"]"#], &[]),
                ROOT_PKG,
                "vendor_lock_entry_not_found",
                "no default-registry entry for left-pad@1.3.0",
            ),
            (
                render(1, &[r#""~npm~a@1.0.0": [0,"a"]"#, REG_NODE], &[r#""file~_d a": "prod 1.0.0 ~npm~a@1.0.0""#, r#""~npm~a@1.0.0 left-pad": "prod ^1 ~npm~left-pad@1.3.0""#]),
                ROOT_PKG,
                "vendor_vlt_transitive_unsupported",
                "~npm~a@1.0.0 depends on it",
            ),
            (
                render(1, &[REG_NODE], &[r#""file~_d left-pad": "peer ^1 ~npm~left-pad@1.3.0""#]),
                ROOT_PKG,
                UNSUPPORTED,
                "peer edge",
            ),
            (
                render(1, &[REG_NODE], &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#]),
                "{\"dependencies\":{\"left-pad\":\"1.3.0\"},\"devDependencies\":{\"left-pad\":\"1.3.0\"}}",
                UNSUPPORTED,
                "declared in multiple dependency fields",
            ),
            (
                render(1, &[REG_NODE], &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#]),
                "{\"dependencies\":{\"left-pad\":\"^1.3.0\"}}",
                OUT_OF_SYNC,
                "declares dependencies.left-pad as `^1.3.0`",
            ),
            (
                render(1, &[REG_NODE], &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#]),
                "{\"devDependencies\":{\"left-pad\":\"1.3.0\"}}",
                OUT_OF_SYNC,
                "as nothing",
            ),
            (
                serde_json::to_string_pretty(&serde_json::from_str::<Value>(&basic_lock()).unwrap()).unwrap(),
                ROOT_PKG,
                "vendor_lockfile_version_unsupported",
                "canonical layout",
            ),
            (
                format!("\u{feff}{}", basic_lock()),
                ROOT_PKG,
                "vendor_lockfile_version_unsupported",
                "byte-order mark",
            ),
        ];
        for (lock, pkg, code, needle) in cases {
            let fx = fx(&lock, &[(PACKAGE_JSON, pkg)]).await;
            let (got, detail) = refusal(run(&fx, UUID, false).await);
            assert_eq!(got, code, "{lock}: {detail}");
            assert!(detail.contains(needle), "{detail}");
            assert_eq!(read(&fx, VLT_LOCK).await, lock);
            assert!(!fx.root.join(".socket").exists());
        }
    }

    #[tokio::test]
    async fn a_peer_range_beside_the_dev_edge_is_left_untouched() {
        let lock = render(
            1,
            &[REG_NODE],
            &[r#""file~_d left-pad": "dev 1.3.0 ~npm~left-pad@1.3.0""#],
        );
        let pkg = "{\n  \"devDependencies\": {\n    \"left-pad\": \"1.3.0\"\n  },\n  \"peerDependencies\": {\n    \"left-pad\": \"^1\"\n  }\n}\n";
        let fx = fx(&lock, &[(PACKAGE_JSON, pkg)]).await;
        entry_of(run(&fx, UUID, false).await);
        let after = read(&fx, PACKAGE_JSON).await;
        assert!(
            after.contains("\"peerDependencies\": {\n    \"left-pad\": \"^1\""),
            "{after}"
        );
        assert!(
            after.contains("\"left-pad\": \"file:./.socket/vendor/npm/"),
            "{after}"
        );
    }

    #[tokio::test]
    async fn the_legacy_era_warns_and_wires_with_its_own_grammar() {
        let lock = render(
            0,
            &[r#""··left-pad@1.3.0": [0,"left-pad","sha512-REG=="]"#],
            &[r#""file·. left-pad": "prod 1.3.0 ··left-pad@1.3.0""#],
        );
        let fx = fx(&lock, &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (_, warnings) = entry_of(run(&fx, UUID, false).await);
        assert_eq!(warnings[0].code, "vendor_vlt_legacy_lockfile");
        let wired = read(&fx, VLT_LOCK).await;
        assert!(
            wired.contains(&format!(
                "\"file·.socket§vendor§npm§{UUID}§left-pad-1.3.0§node_modules§left-pad\": [0,\"left-pad\",null,"
            )),
            "{wired}"
        );
    }

    #[tokio::test]
    async fn revert_restores_slots_under_a_changed_flag_and_refuses_drift() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let wired = read(&fx, VLT_LOCK).await;
        let reflagged = wired.replace("[0,\"left-pad\",null,", "[2,\"left-pad\",null,");
        tokio::fs::write(fx.root.join(VLT_LOCK), &reflagged)
            .await
            .unwrap();
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(
            read(&fx, VLT_LOCK).await,
            basic_lock().replace(
                "[0,\"left-pad\",\"sha512-REG==\"",
                "[2,\"left-pad\",\"sha512-REG==\""
            )
        );
        assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG);

        let fx = self::fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let wired = read(&fx, VLT_LOCK).await;
        let drifted = wired.replace("\"prod file:./", "\"dev file:./");
        tokio::fs::write(fx.root.join(VLT_LOCK), &drifted)
            .await
            .unwrap();
        let pkg = read(&fx, PACKAGE_JSON).await;
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(
            out.success && out.drift_skipped() && out.kept_artifact,
            "{out:?}"
        );
        assert_eq!(read(&fx, VLT_LOCK).await, drifted, "a drift writes nothing");
        assert_eq!(read(&fx, PACKAGE_JSON).await, pkg);
        assert!(fx.root.join(&entry.artifact.path).exists());
    }

    #[tokio::test]
    async fn revert_after_the_user_already_undid_the_wiring_only_removes_the_artifact() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let relocked = basic_lock()
            .replace("\"sha512-REG==\"", "\"sha512-NEW==\"")
            .replace("prod 1.3.0 ~npm~left-pad", "prod ^1.3.0 ~npm~left-pad");
        tokio::fs::write(fx.root.join(VLT_LOCK), &relocked)
            .await
            .unwrap();
        let pkg = ROOT_PKG.replace("\"left-pad\": \"1.3.0\"", "\"left-pad\": \"^1.3.0\"");
        tokio::fs::write(fx.root.join(PACKAGE_JSON), &pkg)
            .await
            .unwrap();
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(read(&fx, VLT_LOCK).await, relocked);
        assert_eq!(read(&fx, PACKAGE_JSON).await, pkg);
        assert!(!fx.root.join(format!(".socket/vendor/npm/{UUID}")).exists());
    }

    #[tokio::test]
    async fn a_cross_grammar_relock_names_the_manual_step() {
        let lock = render(
            0,
            &[r#""·npm·left-pad@1.3.0": [0,"left-pad","sha512-REG=="]"#],
            &[r#""file·. left-pad": "prod 1.3.0 ·npm·left-pad@1.3.0""#],
        );
        let fx = fx(&lock, &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let rel = entry.artifact.path.clone();
        let file_id =
            format!("file~.socket+vendor+npm+{UUID}+left-pad-1.3.0+node__modules+left-pad");
        let relocked = render(
            1,
            &[&format!(r#""{file_id}": [0,"left-pad",null,"{rel}"]"#)],
            &[&format!(
                r#""file~_d left-pad": "prod file:./{rel} {file_id}""#
            )],
        );
        tokio::fs::write(fx.root.join(VLT_LOCK), &relocked)
            .await
            .unwrap();
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.kept_artifact, "{out:?}");
        let detail = &out.warnings[0].detail;
        assert!(
            detail.contains("re-created by a different vlt lockfile grammar")
                && detail.contains("set left-pad in package.json back to 1.3.0"),
            "{detail}"
        );

        tokio::fs::write(fx.root.join(PACKAGE_JSON), ROOT_PKG)
            .await
            .unwrap();
        tokio::fs::write(fx.root.join(VLT_LOCK), basic_lock())
            .await
            .unwrap();
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && !out.kept_artifact, "{out:?}");
    }

    #[tokio::test]
    async fn a_new_uuid_rewires_our_dir_and_keeps_the_pristine_originals() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (first, _) = entry_of(run(&fx, UUID, false).await);
        persist(&fx, &first).await;
        let (second, _) = entry_of(run(&fx, UUID2, false).await);
        let lock = read(&fx, VLT_LOCK).await;
        assert!(lock.contains(UUID2) && !lock.contains(UUID), "{lock}");
        assert_eq!(second.wiring.len(), first.wiring.len());
        for (a, b) in first.wiring.iter().zip(&second.wiring) {
            assert_eq!(
                (&a.kind, &a.key, &a.original),
                (&b.kind, &b.key, &b.original)
            );
        }
        let out = revert_vlt_opts(&second, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
        assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG);
    }

    #[tokio::test]
    async fn uuid_metadata_is_restored_for_the_entry() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let gitignore = fx
            .root
            .join(format!(".socket/vendor/npm/{UUID}/.gitignore"));
        tokio::fs::remove_file(&gitignore).await.unwrap();
        restore_vlt_uuid_metadata(&entry, &fx.root).await.unwrap();
        assert_eq!(
            tokio::fs::read_to_string(&gitignore).await.unwrap(),
            super::super::npm_dir::UUID_GITIGNORE
        );
    }

    #[tokio::test]
    async fn an_unwired_entry_refuses_while_the_lock_still_names_its_dir() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (mut entry, _) = entry_of(run(&fx, UUID, false).await);
        entry.wiring.clear();
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(!out.success);
        assert_eq!(out.warnings[0].code, "vendor_wiring_unknown_revert_blocked");
        assert!(fx.root.join(&entry.artifact.path).exists());
        assert_eq!(vlt_entry_in_use(&entry, &fx.root).await, Some(true));
    }

    #[tokio::test]
    async fn a_lock_write_failure_puts_package_json_back() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let wiring = Wiring {
            records: Vec::new(),
            pkgs: BTreeMap::from([(PACKAGE_JSON.to_string(), "{}".to_string())]),
            lock: Some("{}".to_string()),
        };
        tokio::fs::remove_file(fx.root.join(VLT_LOCK))
            .await
            .unwrap();
        tokio::fs::create_dir_all(fx.root.join(VLT_LOCK).join("occupied"))
            .await
            .unwrap();
        let originals = BTreeMap::from([(PACKAGE_JSON.to_string(), ROOT_PKG.to_string())]);
        let err = commit(&fx.root, &wiring, &originals).await.unwrap_err();
        assert!(err.contains("package.json files restored"), "{err}");
        assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG);
    }

    #[tokio::test]
    async fn a_manifest_patch_warns_that_the_lock_keeps_its_edges() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let patched_pkg =
            b"{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"devDependencies\":{\"t\":\"1\"},\"main\":\"i.js\"}";
        tokio::fs::write(
            fx.blobs.join(compute_git_sha256_from_bytes(patched_pkg)),
            patched_pkg,
        )
        .await
        .unwrap();
        let mut rec = record(UUID);
        rec.files.insert(
            "package/package.json".into(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: compute_git_sha256_from_bytes(patched_pkg),
            },
        );
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_vlt(
            PURL,
            &fx.installed,
            &fx.root,
            &rec,
            &sources,
            "t",
            false,
            true,
            None,
        )
        .await;
        let (entry, warnings) = entry_of(outcome);
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_dep_manifest_stale"),
            "{warnings:?}"
        );
        let committed = read(&fx, &format!("{}/package.json", entry.artifact.path)).await;
        assert_eq!(
            committed,
            "{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"main\":\"i.js\"}"
        );
        crate::vendor::verify::verify_vendored_patch_record(&fx.root, &entry, &rec)
            .await
            .expect("the inventory pin verifies the stripped manifest without the blob");
        let local_blobs = fx.root.join(".socket/blobs");
        tokio::fs::create_dir_all(&local_blobs).await.unwrap();
        tokio::fs::write(
            local_blobs.join(compute_git_sha256_from_bytes(patched_pkg)),
            patched_pkg,
        )
        .await
        .unwrap();
        crate::vendor::verify::verify_vendored_patch_record(&fx.root, &entry, &rec)
            .await
            .expect("and with the blob");
        tokio::fs::write(
            fx.root.join(&entry.artifact.path).join(PACKAGE_JSON),
            "{\"name\":\"left-pad\",\"version\":\"6.6.6\"}",
        )
        .await
        .unwrap();
        assert_eq!(
            crate::vendor::verify::verify_vendored_patch_record(&fx.root, &entry, &rec).await,
            Err("vendor_hash_mismatch".to_string())
        );
    }

    #[tokio::test]
    async fn a_ledgerless_entry_verifies_a_stripped_manifest_by_its_blob() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let patched_pkg =
            b"{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"devDependencies\":{\"t\":\"1\"},\"main\":\"i.js\"}";
        let stripped = "{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"main\":\"i.js\"}";
        let after_hash = compute_git_sha256_from_bytes(patched_pkg);
        tokio::fs::write(fx.blobs.join(&after_hash), patched_pkg)
            .await
            .unwrap();
        let mut rec = record(UUID);
        rec.files.insert(
            "package/package.json".into(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: after_hash.clone(),
            },
        );
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_vlt(
            PURL,
            &fx.installed,
            &fx.root,
            &rec,
            &sources,
            "t",
            false,
            true,
            None,
        )
        .await;
        let (mut entry, _) = entry_of(outcome);
        entry.artifact.file_inventory = None;
        let copy = fx.root.join("copy");
        tokio::fs::create_dir_all(&copy).await.unwrap();
        tokio::fs::write(copy.join("index.js"), PATCHED)
            .await
            .unwrap();
        tokio::fs::write(copy.join(PACKAGE_JSON), stripped)
            .await
            .unwrap();
        let verify = || crate::vendor::verify::verify_vendored_patch_record(&fx.root, &entry, &rec);
        let copy_matches =
            || crate::vendor::verify::vlt_installed_copy_matches(&fx.root, &copy, &entry, &rec);
        assert_eq!(
            verify().await,
            Err("vendor_manifest_unverifiable".to_string())
        );
        assert!(!copy_matches().await);

        let local_blobs = fx.root.join(".socket/blobs");
        tokio::fs::create_dir_all(&local_blobs).await.unwrap();
        tokio::fs::write(local_blobs.join(&after_hash), patched_pkg)
            .await
            .unwrap();
        assert_eq!(verify().await, Ok(()));
        assert!(copy_matches().await);

        tokio::fs::write(
            fx.root.join(&entry.artifact.path).join(PACKAGE_JSON),
            "{\"name\":\"left-pad\",\"version\":\"6.6.6\"}",
        )
        .await
        .unwrap();
        tokio::fs::write(copy.join(PACKAGE_JSON), patched_pkg)
            .await
            .unwrap();
        assert_eq!(verify().await, Err("vendor_hash_mismatch".to_string()));
        assert!(
            copy_matches().await,
            "the untransformed manifest is at its afterHash"
        );
    }

    #[tokio::test]
    async fn the_preflight_decides_every_refusal_without_writing() {
        let fx = fx(
            &render(
                1,
                &[REG_NODE],
                &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#],
            ),
            &[(PACKAGE_JSON, ROOT_PKG)],
        )
        .await;
        assert_eq!(vlt_vendor_preflight(&fx.root, PURL, UUID).await, Ok(()));
        tokio::fs::write(
            fx.root.join(PACKAGE_JSON),
            "{\"dependencies\":{\"left-pad\":\"^1\"}}",
        )
        .await
        .unwrap();
        let (code, _) = vlt_vendor_preflight(&fx.root, PURL, UUID)
            .await
            .unwrap_err();
        assert_eq!(code, OUT_OF_SYNC);
        tokio::fs::write(fx.root.join(PACKAGE_JSON), ROOT_PKG)
            .await
            .unwrap();
        let store = fx
            .root
            .join("node_modules/.vlt")
            .join(REG)
            .join("node_modules/left-pad");
        tokio::fs::create_dir_all(&store).await.unwrap();
        tokio::fs::write(store.join(PACKAGE_JSON), "{\"bundleDependencies\":true}")
            .await
            .unwrap();
        let (code, _) = vlt_vendor_preflight(&fx.root, PURL, UUID)
            .await
            .unwrap_err();
        assert_eq!(code, "vendor_bundled_deps_unsupported");
        tokio::fs::write(
            store.join(PACKAGE_JSON),
            "{\"devDependencies\":{},\"devDependencies\":{}}",
        )
        .await
        .unwrap();
        let (code, detail) = vlt_vendor_preflight(&fx.root, PURL, UUID)
            .await
            .unwrap_err();
        assert_eq!(code, UNSUPPORTED);
        assert!(detail.contains("duplicate devDependencies"), "{detail}");
    }

    fn service_tgz(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, kind, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            if *kind == tar::EntryType::Symlink {
                header.set_link_name("/etc/passwd").unwrap();
            }
            header.set_cksum();
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    async fn run_with(fx: &Fx, cfg: &crate::vendor::VendorServiceConfig) -> VendorOutcome {
        let sources = PatchSources::blobs_only(&fx.blobs);
        vendor_vlt(
            PURL,
            &fx.installed,
            &fx.root,
            &record(UUID),
            &sources,
            "t",
            false,
            false,
            Some(cfg),
        )
        .await
    }

    #[tokio::test]
    async fn the_service_tree_is_extracted_under_any_first_component_and_transformed() {
        use crate::vendor::test_support::{mount_granted, request_count, service_cfg};
        use crate::vendor::VendorSource;
        let server = wiremock::MockServer::start().await;
        let tgz = service_tgz(&[
            (
                "left-pad/package.json",
                tar::EntryType::Regular,
                b"{\"name\":\"left-pad\",\"devDependencies\":{\"x\":\"1\"},\"version\":\"1.3.0\"}",
            ),
            ("left-pad/index.js", tar::EntryType::Regular, PATCHED),
            ("left-pad/README.md", tar::EntryType::Regular, b"service"),
        ]);
        mount_granted(&server, UUID, "left-pad-1.3.0.tgz", &tgz).await;
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let cfg = service_cfg(&server.uri(), VendorSource::Auto, false);
        let (entry, warnings) = entry_of(run_with(&fx, &cfg).await);
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
        assert_eq!(
            read(&fx, &format!("{}/package.json", entry.artifact.path)).await,
            "{\"name\":\"left-pad\",\"version\":\"1.3.0\"}"
        );
        assert_eq!(
            read(&fx, &format!("{}/README.md", entry.artifact.path)).await,
            "service"
        );
        persist(&fx, &entry).await;
        let before = request_count(&server).await;
        match run_with(&fx, &cfg).await {
            VendorOutcome::Done {
                entry: None,
                result,
                ..
            } => assert!(result.success),
            other => panic!("the rerun reuses the committed dir: {other:?}"),
        }
        assert_eq!(
            request_count(&server).await,
            before,
            "reuse never calls the service"
        );
    }

    #[tokio::test]
    async fn service_failures_follow_the_tarball_policy() {
        use crate::vendor::test_support::{mount_503, mount_granted, service_cfg};
        use crate::vendor::VendorSource;

        let server = wiremock::MockServer::start().await;
        mount_503(&server).await;
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (_, warnings) =
            entry_of(run_with(&fx, &service_cfg(&server.uri(), VendorSource::Auto, false)).await);
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_prebuilt_unavailable"),
            "{warnings:?}"
        );

        let fx = self::fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        match run_with(
            &fx,
            &service_cfg(&server.uri(), VendorSource::Service, false),
        )
        .await
        {
            VendorOutcome::Done { result, entry, .. } => {
                assert!(!result.success && entry.is_none(), "{:?}", result.error)
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
        assert!(!fx.root.join(".socket/vendor").exists());

        let server = wiremock::MockServer::start().await;
        let bad = service_tgz(&[
            ("package/index.js", tar::EntryType::Regular, PATCHED),
            ("package/link", tar::EntryType::Symlink, b""),
        ]);
        mount_granted(&server, UUID, "left-pad-1.3.0.tgz", &bad).await;
        let fx = self::fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        match run_with(&fx, &service_cfg(&server.uri(), VendorSource::Auto, false)).await {
            VendorOutcome::Done { result, entry, .. } => {
                assert!(!result.success && entry.is_none());
                assert!(result.error.unwrap().contains("unsafe"));
            }
            other => panic!("{other:?}"),
        }
        assert!(!fx.root.join(".socket/vendor").exists());
    }

    fn file_id() -> String {
        format!("file~.socket+vendor+npm+{UUID}+left-pad-1.3.0+node__modules+left-pad")
    }

    fn uuid_dir(fx: &Fx, uuid: &str) -> std::path::PathBuf {
        fx.root.join(format!(".socket/vendor/npm/{uuid}"))
    }

    type DoneParts = (
        (bool, Option<String>),
        Option<VendorEntry>,
        Vec<VendorWarning>,
    );

    fn done_parts(outcome: VendorOutcome) -> DoneParts {
        match outcome {
            VendorOutcome::Done {
                result,
                entry,
                warnings,
            } => ((result.success, result.error), entry, warnings),
            other => panic!("expected Done, got {other:?}"),
        }
    }

    fn codes(warnings: &[VendorWarning]) -> Vec<&str> {
        warnings.iter().map(|w| w.code).collect()
    }

    #[tokio::test]
    async fn revert_beside_a_registry_twin_merges_into_it_or_drifts() {
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad");
        let file_id = file_id();
        let file_node = format!(r#""{file_id}": [0,"left-pad",null,"{rel}"]"#);
        let file_edge = format!(r#""file~_d left-pad": "prod file:./{rel} {file_id}""#);
        let file_out = format!(r#""{file_id} z": "prod ^1.0.0 ~npm~z@1.0.0""#);
        let ws_edge = r#""workspace~packages+a left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#;
        let a_node = r#""~npm~a@1.0.0": [0,"a","sha512-A=="]"#;
        let z_node = r#""~npm~z@1.0.0": [0,"z","sha512-Z=="]"#;
        let a_edge = r#""file~_d a": "prod 1.0.0 ~npm~a@1.0.0""#;
        let reg_out = r#""~npm~left-pad@1.3.0 z": "prod ^1.0.0 ~npm~z@1.0.0""#;
        let cases = [
            (REG_NODE.to_string(), reg_out.to_string(), true),
            (
                REG_NODE.replace("sha512-REG==", "sha512-OTHER=="),
                reg_out.to_string(),
                false,
            ),
            (
                REG_NODE.to_string(),
                reg_out.replace("~npm~z@1.0.0", "~npm~z@1.0.1"),
                false,
            ),
        ];
        for (twin_node, twin_out, merges) in cases {
            let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
            let (entry, _) = entry_of(run(&fx, UUID, false).await);
            let twin = render(
                1,
                &[a_node, &twin_node, z_node, &file_node],
                &[a_edge, &file_edge, ws_edge, &file_out, &twin_out],
            );
            tokio::fs::write(fx.root.join(VLT_LOCK), &twin)
                .await
                .unwrap();
            let pkg = read(&fx, PACKAGE_JSON).await;
            let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
            if merges {
                assert!(out.success && out.warnings.is_empty(), "{out:?}");
                assert_eq!(
                    read(&fx, VLT_LOCK).await,
                    render(
                        1,
                        &[a_node, REG_NODE, z_node],
                        &[
                            a_edge,
                            r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#,
                            ws_edge,
                            reg_out,
                        ],
                    )
                );
                assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG);
                assert!(!uuid_dir(&fx, UUID).exists());
                assert!(parse_doc(&read(&fx, VLT_LOCK).await).is_ok());
            } else {
                assert!(
                    out.success && out.drift_skipped() && out.kept_artifact,
                    "{out:?}"
                );
                assert!(
                    out.warnings[0].detail.contains("holds both"),
                    "{:?}",
                    out.warnings
                );
                assert_eq!(read(&fx, VLT_LOCK).await, twin, "a drift writes nothing");
                assert_eq!(read(&fx, PACKAGE_JSON).await, pkg);
                assert!(fx.root.join(&entry.artifact.path).exists());
            }
        }
    }

    #[tokio::test]
    async fn revert_finishes_a_partial_revert_record_by_record() {
        let file_id = file_id();
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad");
        let wired_pkg = ROOT_PKG.replace(
            "\"left-pad\": \"1.3.0\"",
            &format!("\"left-pad\": \"file:./{rel}\""),
        );
        type Undo = fn(&str, &str) -> (Option<String>, bool);
        let undos: [(&str, Undo); 3] = [
            ("the lock was already restored", |_, _| {
                (Some(basic_lock()), false)
            }),
            (
                "only the outgoing edge was re-keyed back",
                |wired, file_id| {
                    (
                        Some(
                            wired.replace(&format!("\"{file_id} z\""), "\"~npm~left-pad@1.3.0 z\""),
                        ),
                        false,
                    )
                },
            ),
            ("package.json was already restored", |_, _| (None, true)),
        ];
        for (label, undo) in undos {
            let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
            let (entry, _) = entry_of(run(&fx, UUID, false).await);
            assert_eq!(read(&fx, PACKAGE_JSON).await, wired_pkg);
            let wired = read(&fx, VLT_LOCK).await;
            let (lock, pkg_restored) = undo(&wired, &file_id);
            if let Some(lock) = lock {
                tokio::fs::write(fx.root.join(VLT_LOCK), lock)
                    .await
                    .unwrap();
            }
            if pkg_restored {
                tokio::fs::write(fx.root.join(PACKAGE_JSON), ROOT_PKG)
                    .await
                    .unwrap();
            }
            let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
            assert!(out.success && out.warnings.is_empty(), "{label}: {out:?}");
            assert_eq!(read(&fx, VLT_LOCK).await, basic_lock(), "{label}");
            assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG, "{label}");
            assert!(!uuid_dir(&fx, UUID).exists(), "{label}");
        }
    }

    #[tokio::test]
    async fn revert_never_follows_a_record_outside_the_importer_allowlist() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (mut entry, _) = entry_of(run(&fx, UUID, false).await);
        let pkg_rec = entry.wiring[0].clone();
        let new = fragment(&pkg_rec.new).unwrap().to_string();
        let planted = format!("{{\"dependencies\":{{\"left-pad\":{new}}}}}");
        let outside = ["vendor/x/package.json", "../escape/package.json"];
        for rel in outside {
            let path = fx.root.join(rel);
            tokio::fs::create_dir_all(path.parent().unwrap())
                .await
                .unwrap();
            tokio::fs::write(&path, &planted).await.unwrap();
            entry.wiring.insert(
                0,
                WiringRecord {
                    file: rel.to_string(),
                    ..pkg_rec.clone()
                },
            );
        }
        let lock = read(&fx, VLT_LOCK).await;
        let pkg = read(&fx, PACKAGE_JSON).await;
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.drift_skipped() && out.kept_artifact, "{out:?}");
        for rel in outside {
            assert!(
                out.warnings
                    .iter()
                    .any(|w| w.code == "vendor_lock_entry_drifted"
                        && w.detail.contains("non-allowlisted")
                        && w.detail.contains(rel)),
                "{rel}: {:?}",
                out.warnings
            );
            assert_eq!(read(&fx, rel).await, planted, "{rel} is never written");
        }
        assert_eq!(read(&fx, VLT_LOCK).await, lock);
        assert_eq!(read(&fx, PACKAGE_JSON).await, pkg);
        assert!(fx.root.join(&entry.artifact.path).exists());
    }

    #[tokio::test]
    async fn a_dry_run_revert_writes_nothing() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let lock = read(&fx, VLT_LOCK).await;
        let pkg = read(&fx, PACKAGE_JSON).await;
        let inventory = crate::vendor::verify::compute_package_dir_inventory(
            &fx.root.join(&entry.artifact.path),
        )
        .await
        .unwrap();
        let out = revert_vlt_opts(
            &entry,
            &fx.root,
            RevertOpts {
                dry_run: true,
                keep_artifact: false,
            },
        )
        .await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(read(&fx, VLT_LOCK).await, lock);
        assert_eq!(read(&fx, PACKAGE_JSON).await, pkg);
        assert_eq!(
            crate::vendor::verify::compute_package_dir_inventory(
                &fx.root.join(&entry.artifact.path)
            )
            .await
            .unwrap(),
            inventory
        );
        assert!(uuid_dir(&fx, UUID).join(".gitignore").is_file());
    }

    #[tokio::test]
    async fn a_new_uuid_over_an_unwired_prior_refuses_before_any_write() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (mut first, _) = entry_of(run(&fx, UUID, false).await);
        first.wiring.clear();
        persist(&fx, &first).await;
        let lock = read(&fx, VLT_LOCK).await;
        let pkg = read(&fx, PACKAGE_JSON).await;
        let (code, detail) = refusal(run(&fx, UUID2, false).await);
        assert_eq!(code, "vendor_wiring_unknown", "{detail}");
        assert!(
            detail.contains("run `vlt install`") && detail.contains(&file_id()),
            "{detail}"
        );
        assert_eq!(read(&fx, VLT_LOCK).await, lock);
        assert_eq!(read(&fx, PACKAGE_JSON).await, pkg);
        assert!(!uuid_dir(&fx, UUID2).exists());

        let fx = self::fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (mut partial, _) = entry_of(run(&fx, UUID, false).await);
        partial.wiring[1].original = None;
        persist(&fx, &partial).await;
        let (code, _) = refusal(run(&fx, UUID2, false).await);
        assert_eq!(code, "vendor_wiring_unknown");
        assert!(!uuid_dir(&fx, UUID2).exists());
    }

    #[tokio::test]
    async fn a_stale_committed_dir_is_rebuilt_under_in_sync_wiring() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (first, _) = entry_of(run(&fx, UUID, false).await);
        persist(&fx, &first).await;
        let lock = read(&fx, VLT_LOCK).await;
        let pkg = read(&fx, PACKAGE_JSON).await;
        let index = fx.root.join(&first.artifact.path).join("index.js");
        tokio::fs::remove_file(&index).await.unwrap();

        let (result, entry, warnings) = done_parts(run(&fx, UUID, false).await);
        assert!(result.0, "{result:?}");
        let mut entry = entry.expect("a rebuild returns its entry");
        assert_eq!(codes(&warnings), ["vendor_artifact_rebuilt"]);
        assert!(!warnings[0].detail.contains("vlt install"), "{warnings:?}");
        assert_eq!(tokio::fs::read(&index).await.unwrap(), PATCHED);
        assert_eq!(read(&fx, VLT_LOCK).await, lock);
        assert_eq!(read(&fx, PACKAGE_JSON).await, pkg);
        assert_eq!(entry.artifact.path, first.artifact.path);
        assert_eq!(entry.artifact.file_inventory, first.artifact.file_inventory);
        assert!(entry.wiring.is_empty());
        crate::vendor::state::carry_forward_wiring(&first, &mut entry);
        assert_eq!(entry.wiring, first.wiring);
    }

    #[tokio::test]
    async fn a_rebuild_clears_strays_beside_the_package_dir_and_ends_healthy() {
        use crate::vendor::verify::{check_vendored_artifact, ArtifactHealth};
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (first, _) = entry_of(run(&fx, UUID, false).await);
        persist(&fx, &first).await;
        let rec = record(UUID);
        let leaf = uuid_dir(&fx, UUID).join("left-pad-1.3.0");
        tokio::fs::write(leaf.join("node_modules/.DS_Store"), b"x")
            .await
            .unwrap();
        tokio::fs::write(leaf.join("stray.txt"), b"x")
            .await
            .unwrap();
        assert_eq!(
            check_vendored_artifact(&fx.root, &first, &rec).await,
            ArtifactHealth::Corrupt {
                reason: "vendor_inventory_mismatch".into()
            }
        );
        let (result, entry, warnings) = done_parts(run(&fx, UUID, false).await);
        assert!(result.0, "{result:?}");
        assert_eq!(codes(&warnings), ["vendor_artifact_rebuilt"]);
        let mut entry = entry.unwrap();
        crate::vendor::state::carry_forward_wiring(&first, &mut entry);
        persist(&fx, &entry).await;
        assert_eq!(
            check_vendored_artifact(&fx.root, &entry, &rec).await,
            ArtifactHealth::Healthy
        );
        assert!(!leaf.join("node_modules/.DS_Store").exists());
        assert!(!leaf.join("stray.txt").exists());
        let (result, entry, warnings) = done_parts(run(&fx, UUID, false).await);
        assert!(
            result.0 && entry.is_none() && warnings.is_empty(),
            "{warnings:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_rebuild_keeps_vlt_links_and_says_to_reinstall_when_it_cannot() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (first, _) = entry_of(run(&fx, UUID, false).await);
        persist(&fx, &first).await;
        let rel_abs = fx.root.join(&first.artifact.path);
        let links = rel_abs.join("node_modules");
        tokio::fs::create_dir_all(links.join(".bin")).await.unwrap();
        std::os::unix::fs::symlink(
            "../../../../../../../../node_modules/.vlt/z",
            links.join("z"),
        )
        .unwrap();
        tokio::fs::write(links.join(".bin/tool"), b"#!/bin/sh\n")
            .await
            .unwrap();
        tokio::fs::remove_file(rel_abs.join("index.js"))
            .await
            .unwrap();

        let (_, entry, warnings) = done_parts(run(&fx, UUID, false).await);
        assert!(entry.is_some());
        assert_eq!(codes(&warnings), ["vendor_artifact_rebuilt"]);
        assert!(!warnings[0].detail.contains("vlt install"), "{warnings:?}");
        assert_eq!(
            std::fs::read_link(links.join("z")).unwrap(),
            std::path::Path::new("../../../../../../../../node_modules/.vlt/z")
        );
        assert!(links.join(".bin/tool").is_file());
        assert_eq!(
            tokio::fs::read(rel_abs.join("index.js")).await.unwrap(),
            PATCHED
        );

        tokio::fs::write(links.join("planted.js"), b"x")
            .await
            .unwrap();
        let (_, entry, warnings) = done_parts(run(&fx, UUID, false).await);
        assert!(entry.is_some());
        assert_eq!(codes(&warnings), ["vendor_artifact_rebuilt"]);
        assert!(
            warnings[0].detail.contains("run `vlt install`"),
            "{warnings:?}"
        );
        assert!(!links.exists());
    }

    #[tokio::test]
    async fn an_in_sync_rerun_restores_the_uuid_metadata() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (first, _) = entry_of(run(&fx, UUID, false).await);
        persist(&fx, &first).await;
        let dir = uuid_dir(&fx, UUID);
        tokio::fs::write(dir.join(".gitignore"), b"*\n")
            .await
            .unwrap();
        tokio::fs::remove_file(dir.join(".gitattributes"))
            .await
            .unwrap();
        let (result, entry, warnings) = done_parts(run(&fx, UUID, false).await);
        assert!(
            result.0 && entry.is_none() && warnings.is_empty(),
            "{warnings:?}"
        );
        assert_eq!(
            tokio::fs::read_to_string(dir.join(".gitignore"))
                .await
                .unwrap(),
            super::super::npm_dir::UUID_GITIGNORE
        );
        assert_eq!(
            tokio::fs::read_to_string(dir.join(".gitattributes"))
                .await
                .unwrap(),
            super::super::npm_dir::UUID_GITATTRIBUTES
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_gitignored_payload_refuses_and_unwinds() {
        let Some(git) = crate::utils::process::resolve_tool("git") else {
            return;
        };
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let status = std::process::Command::new(&git)
            .args(["init", "-q"])
            .current_dir(&fx.root)
            .status()
            .unwrap();
        assert!(status.success());
        tokio::fs::write(fx.root.join(".gitignore"), ".socket/\n")
            .await
            .unwrap();
        let (code, detail) = refusal(run(&fx, UUID, false).await);
        assert_eq!(code, "vendor_artifact_gitignored", "{detail}");
        assert!(detail.contains(".gitignore:1:.socket/"), "{detail}");
        assert!(!uuid_dir(&fx, UUID).exists());
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
        assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG);
    }

    #[tokio::test]
    async fn a_bundling_package_refuses_on_the_local_build() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        tokio::fs::write(
            fx.installed.join(PACKAGE_JSON),
            "{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"bundleDependencies\":[\"x\"]}",
        )
        .await
        .unwrap();
        let (code, _) = refusal(run(&fx, UUID, false).await);
        assert_eq!(code, "vendor_bundled_deps_unsupported");
        assert!(!fx.root.join(".socket").exists());
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
    }

    #[tokio::test]
    async fn the_service_tree_is_pruned_and_a_bundling_one_refuses() {
        use crate::vendor::test_support::{mount_granted, service_cfg};
        use crate::vendor::verify::{check_vendored_artifact, ArtifactHealth};
        use crate::vendor::VendorSource;
        let server = wiremock::MockServer::start().await;
        let tgz = service_tgz(&[
            (
                "package/package.json",
                tar::EntryType::Regular,
                b"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}",
            ),
            ("package/index.js", tar::EntryType::Regular, PATCHED),
            (
                "package/node_modules/x/index.js",
                tar::EntryType::Regular,
                b"bundled",
            ),
        ]);
        mount_granted(&server, UUID, "left-pad-1.3.0.tgz", &tgz).await;
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let cfg = service_cfg(&server.uri(), VendorSource::Auto, false);
        let (entry, warnings) = entry_of(run_with(&fx, &cfg).await);
        assert!(
            codes(&warnings).contains(&"vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
        assert!(!fx
            .root
            .join(&entry.artifact.path)
            .join("node_modules")
            .exists());
        assert_eq!(
            check_vendored_artifact(&fx.root, &entry, &record(UUID)).await,
            ArtifactHealth::Healthy
        );

        let server = wiremock::MockServer::start().await;
        let tgz = service_tgz(&[
            (
                "package/package.json",
                tar::EntryType::Regular,
                b"{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"bundleDependencies\":[\"x\"]}",
            ),
            ("package/index.js", tar::EntryType::Regular, PATCHED),
            (
                "package/node_modules/x/index.js",
                tar::EntryType::Regular,
                b"bundled",
            ),
        ]);
        mount_granted(&server, UUID, "left-pad-1.3.0.tgz", &tgz).await;
        let fx = self::fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let cfg = service_cfg(&server.uri(), VendorSource::Auto, false);
        let (code, _) = refusal(run_with(&fx, &cfg).await);
        assert_eq!(code, "vendor_bundled_deps_unsupported");
        assert!(!fx.root.join(".socket/vendor").exists());
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
    }

    #[tokio::test]
    async fn a_service_tree_without_the_patched_files_falls_back_or_fails_closed() {
        use crate::vendor::test_support::{mount_granted, service_cfg};
        use crate::vendor::VendorSource;
        let server = wiremock::MockServer::start().await;
        let tgz = service_tgz(&[
            (
                "package/package.json",
                tar::EntryType::Regular,
                b"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}",
            ),
            (
                "package/index.js",
                tar::EntryType::Regular,
                b"not the patch",
            ),
        ]);
        mount_granted(&server, UUID, "left-pad-1.3.0.tgz", &tgz).await;

        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let cfg = service_cfg(&server.uri(), VendorSource::Auto, false);
        let (entry, warnings) = entry_of(run_with(&fx, &cfg).await);
        assert!(
            codes(&warnings).contains(&"vendor_prebuilt_layout_mismatch"),
            "{warnings:?}"
        );
        assert_eq!(
            tokio::fs::read(fx.root.join(&entry.artifact.path).join("index.js"))
                .await
                .unwrap(),
            PATCHED,
            "the local build replaced the service tree"
        );

        let fx = self::fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let cfg = service_cfg(&server.uri(), VendorSource::Service, false);
        let (result, entry, _) = done_parts(run_with(&fx, &cfg).await);
        assert!(!result.0 && entry.is_none(), "{result:?}");
        assert!(
            result
                .1
                .unwrap()
                .contains("does not carry the patched files"),
            "fails closed"
        );
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
        assert!(!fx.root.join(".socket/vendor").exists());
    }
}
