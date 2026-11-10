//! vlt vendor backend: `vlt-lock.json` + importer `package.json` surgery
//! for a direct dependency.
//!
//! The target's default-registry node becomes a `file` node naming the
//! directory artifact ([`super::npm_dir`]), without the peer-context extra
//! a single-context node may carry (vlt never gives a `file` node one, and
//! keeps its peer edges); its importer edges and the
//! importers' package.json specs move to `file:<path relative to the
//! importer>`, and its own outgoing edges are re-keyed to the new DepID.
//! Every other line of the lock stays byte-identical, and the moved entries
//! are placed where vlt's own serializer puts them, so `vlt ci`
//! keeps the lock byte-stable.
//!
//! Transitive targets are refused: vlt re-resolves a non-importer edge to a
//! `file` node away on the next `install`, `update` or workspace edit, and
//! nothing tells the user.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::constants::npm_family::{VLT_LOCK, VLT_STORE_DIR};
use crate::constants::SOCKET_DIR;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::PatchSources;
use crate::patch::path_safety::is_safe_multi_segment;
use crate::utils::fs::{atomic_write_bytes_preserving_mode, read_regular_to_string};
use crate::utils::socket_dir::remove_tree_and_prune;

use super::common::{already_patched_result, done, refused};
use super::npm_common::{
    done_failure_unstage, finish_vendored, guard_coordinates, guard_revert_uuid_dir, parse_npm_purl,
};
use super::npm_dir::{dependency_token, replace_dependency_token, stage_patch_dir, SpanError};
use super::source::PackageSource;
use super::state::{load_state, VendorArtifact, VendorEntry, WiringAction, WiringRecord};
use super::vlt_lock_text::{
    brotli_for_slot3, edges_block, encode_segment, entry_text, file_dep_id, has_brotli_flag,
    installs_outside_registry, is_default_registry, is_importer_dep_id, is_registry_url_segment,
    nodes_block, parse_edge_entry_text, parse_edge_line, parse_node_entry_text, parse_node_line,
    parse_vendored_dir_path, render_entry_line, render_tuple_with_slots, section_value_span,
    sniff_lock, split_dep_id, split_lines, top_level_value_spans, vendored_dir_rel, vlt_collate,
    vlt_edge_cmp, DepIdEra, DepIdKind, EdgeSortKey, LockSniff, ParsedLock, SectionSpan,
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

/// Lock sniff: a BOM-less JSON object with `lockfileVersion` 0
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
    // The sections were found by the shape of their lines. Every edit is to
    // those lines, so they must be where JSON puts the top-level `nodes`
    // and `edges`: a member of that name nested elsewhere and written at
    // the same indent has the same shape (and can have as many entries).
    let members = top_level_value_spans(text).ok_or_else(not_canonical)?;
    for (name, block) in [("nodes", &nodes), ("edges", &edges)] {
        let top_level = match (block.span, members.get(name)) {
            (Some(span), Some(member)) => section_value_span(&lines, span) == *member,
            (Some(_), None) => false,
            (None, _) => true,
        };
        if !top_level {
            return Err(not_canonical());
        }
    }
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

/// The lock's lines with its two sections replaced by `nodes` and `edges`.
fn render_lock(lines: &[String], nodes: &Block, edges: &Block) -> String {
    let mut spans: Vec<(SectionSpan, &Block)> = [nodes, edges]
        .into_iter()
        .filter_map(|b| b.span.map(|s| (s, b)))
        .collect();
    spans.sort_by_key(|(s, _)| match s {
        SectionSpan::Inline { line } => *line,
        SectionSpan::Block { open, .. } => *open,
    });
    let mut out = Vec::with_capacity(lines.len() + 4);
    let mut i = 0;
    for (span, block) in spans {
        match span {
            SectionSpan::Block { open, close } => {
                out.extend(lines[i..=open].iter().cloned());
                let last = block.entries.len().saturating_sub(1);
                for (j, e) in block.entries.iter().enumerate() {
                    out.push(render_entry_line(&e.text(), j != last, e.cr));
                }
                i = close;
            }
            SectionSpan::Inline { line } => {
                out.extend(lines[i..line].iter().cloned());
                let header = &lines[line];
                let comma = header.trim_end_matches('\r').ends_with(',');
                render_block(&mut out, header, &block.entries, comma);
                i = line + 1;
            }
        }
    }
    out.extend(lines[i..].iter().cloned());
    out.join("\n")
}

impl LockDoc {
    fn options(&self) -> Option<&serde_json::Map<String, Value>> {
        self.parsed.options()
    }

    /// An era-A lock (0.0.0-19 … 1.0.0-rc.8): a `··` id, or default-registry
    /// ids that are URL segments equal to a scalar `options.registry` with
    /// no `·npm·` id beside them (era B spells the default registry `npm`
    /// whatever the scalar).
    fn is_era_a(&self) -> bool {
        if self.era != DepIdEra::Legacy {
            return false;
        }
        let mut url_segment = false;
        for e in &self.nodes.entries {
            if e.key.starts_with("··") {
                return true;
            }
            let Some(dep_id) = split_dep_id(&e.key) else {
                continue;
            };
            if dep_id.kind != DepIdKind::Registry || dep_id.era != DepIdEra::Legacy {
                continue;
            }
            if dep_id.first == "npm" {
                return false;
            }
            url_segment |= is_registry_url_segment(&dep_id.first, self.options());
        }
        url_segment
    }
}

// ── placement ────────────────────────────────────────────────────────────

/// What a node sorts by: its DepID.
struct NodeKey(String);

fn node_key(entry: &Entry) -> Option<NodeKey> {
    Some(NodeKey(entry.key.clone()))
}

fn node_cmp(a: &NodeKey, b: &NodeKey) -> Option<Ordering> {
    vlt_collate(&a.0, &b.0)
}

/// What an edge sorts by (`from`, type and target, see [`vlt_edge_cmp`]).
/// `None` for text outside the edge grammar, which compares as Unknown.
struct EdgeKey {
    from: String,
    edge_type: String,
    to: String,
}

#[cfg(test)]
thread_local! {
    /// [`edge_key`] calls this thread made. Each one decodes an edge, so a
    /// placement must make one per entry, not one per comparison (VBV-P1).
    static EDGE_KEYS_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn edge_key(entry: &Entry) -> Option<EdgeKey> {
    #[cfg(test)]
    EDGE_KEYS_READ.with(|read| read.set(read.get() + 1));
    let text = entry.text();
    let edge = parse_edge_entry_text(&text)?;
    let EdgeSortKey {
        from,
        edge_type,
        to,
    } = edge.sort_key();
    Some(EdgeKey {
        from: from.to_string(),
        edge_type: edge_type.to_string(),
        to: to.to_string(),
    })
}

impl EdgeKey {
    fn sort_key(&self) -> EdgeSortKey<'_> {
        EdgeSortKey {
            from: &self.from,
            edge_type: &self.edge_type,
            to: &self.to,
        }
    }
}

fn edge_cmp(a: &EdgeKey, b: &EdgeKey) -> Option<Ordering> {
    vlt_edge_cmp(a.sort_key(), b.sort_key())
}

/// Replace the entries at the touched indices with their replacements:
/// untouched entries keep their order, and each replacement (in the given
/// order) goes before the first entry it sorts below. When any comparison
/// is outside the collation table, every replacement stays in place.
///
/// `key` reads what an entry sorts by, once per entry: a lock has tens of
/// thousands of entries, each replacement is compared with every one ahead
/// of its place, and decoding an edge per comparison made that the cost of
/// vendoring into a large lock.
fn place<K>(
    entries: &[Entry],
    touched: &[(usize, Entry)],
    key: fn(&Entry) -> Option<K>,
    cmp: fn(&K, &K) -> Option<Ordering>,
) -> Vec<Entry> {
    let touched_at: BTreeSet<usize> = touched.iter().map(|(i, _)| *i).collect();
    let mut list: Vec<Entry> = entries
        .iter()
        .enumerate()
        .filter(|(i, _)| !touched_at.contains(i))
        .map(|(_, e)| e.clone())
        .collect();
    let mut keys: Vec<Option<K>> = list.iter().map(key).collect();
    for (_, new) in touched {
        let new_key = key(new);
        let mut at = list.len();
        for (i, other) in keys.iter().enumerate() {
            let order = match (&new_key, other) {
                (Some(new), Some(other)) => cmp(new, other),
                _ => None,
            };
            match order {
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
        keys.insert(at, new_key);
    }
    list
}

// ── target analysis ──────────────────────────────────────────────────────

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

/// Why the importer manifest `pkg_rel` must not be written, when its
/// directory is reached through a symbolic link (or cannot be told from
/// one): a workspace directory linked out of the project leads to a
/// `package.json` that is not this project's to edit. The root's own
/// manifest has no level to check.
fn linked_importer(project_root: &Path, pkg_rel: &str) -> Option<String> {
    let dir = Path::new(pkg_rel)
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())?;
    match crate::utils::containment::try_linked_level(project_root, &project_root.join(dir)) {
        Ok(None) => None,
        Ok(Some(link)) => Some(format!(
            "{pkg_rel} is reached through the symbolic link {}, and its target is not \
             socket-patch's to change; make the workspace a real directory of the project first",
            link.strip_prefix(project_root).unwrap_or(&link).display()
        )),
        Err(e) => Some(format!(
            "cannot tell whether {pkg_rel} is reached through a symbolic link: {e}"
        )),
    }
}

/// The one default-registry instance of `name@version` (plain or with only
/// a peer-context extra) or our own vendored node, with its importer edges.
fn find_target(doc: &LockDoc, name: &str, version: &str) -> Result<Target, Refusal> {
    let options = doc.options();
    let mut defaults = Vec::new();
    let mut foreign = Vec::new();
    let mut ours = Vec::new();
    let mut outside = Vec::new();
    for (i, e) in doc.nodes.entries.iter().enumerate() {
        let Some(dep_id) = split_dep_id(&e.key) else {
            continue;
        };
        let slot1 = parse_node_entry_text(&e.text()).and_then(|n| n.name());
        if slot1
            .as_deref()
            .is_some_and(|slot1| installs_outside_registry(&dep_id, slot1, name, version))
        {
            outside.push(i);
        }
        match dep_id.kind {
            DepIdKind::Registry if dep_id.registry_identity() == Some((name, version)) => {
                if is_default_registry(&dep_id.first, options) {
                    let variant = dep_id.extra.is_some() && !dep_id.has_peer_extra_only();
                    defaults.push((i, variant));
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
                 registry; vendoring rewires only default-registry packages, so use agent mode",
                key(i)
            ),
        ));
    }
    if let Some(&i) = outside.first() {
        return Err((
            UNSUPPORTED,
            format!(
                "vlt-lock.json also installs {name} from {}, a git, remote tarball or local \
                 directory dependency that vendoring cannot rewire and whose version vlt does \
                 not record; remove that dependency, or use agent mode",
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
                        "a modifier variant instance".to_string()
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

/// Declaration checks on the importers' package.json files.
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
        let value: Value = serde_json::from_str(crate::formats::text::strip_bom(text))
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
    for edge in &target.importers {
        if let Some(detail) = linked_importer(project_root, &edge.pkg_rel()) {
            return Err((UNSUPPORTED, detail));
        }
    }
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
/// `devDependencies`, and a git rule ignoring the would-be uuid dir. The
/// dir form matches only directory
/// exclusions: every other rule is overridden by the `!*` the engine
/// writes into that dir.
pub async fn vlt_vendor_preflight(
    project_root: &Path,
    purl: &str,
    uuid: &str,
) -> Result<(), Refusal> {
    if let Some(refusal) = super::npm_flavor::member_stray_lock_refusal(project_root).await {
        return Err(refusal);
    }
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
        if let Ok(pkg) = serde_json::from_str::<Value>(crate::formats::text::strip_bom(&text)) {
            if super::npm_common::declares_bundled_deps(&pkg) {
                return Err((
                    "vendor_bundled_deps_unsupported",
                    format!("{name}@{version} declares bundleDependencies; vendoring would drop its bundled node_modules and break installs"),
                ));
            }
            let gyp = match store.parent() {
                Some(dir) => tokio::fs::symlink_metadata(dir.join(super::npm_dir::BINDING_GYP))
                    .await
                    .is_ok(),
                None => false,
            };
            let steps = super::npm_dir::vlt_build_steps(&pkg, gyp);
            if !steps.is_empty() {
                return Err((
                    super::npm_dir::BUILD_STEPS_UNSUPPORTED,
                    super::npm_dir::build_steps_detail(&name, &version, &steps),
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
        if let Some(rules) =
            super::npm_dir::gitignored(project_root, &[format!("{uuid_dir}/")]).await
        {
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
    /// The lock entries to replace, by index in their block.
    node_touch: Vec<(usize, Entry)>,
    edge_touch: Vec<(usize, Entry)>,
}

impl Wiring {
    /// The new lock text, or `None` when the lock stays as it is. Placing
    /// and rendering is the expensive half of a plan and decides nothing,
    /// so only the run that writes the lock asks for it.
    fn lock(&self, doc: &LockDoc) -> Option<String> {
        if self.node_touch.is_empty() && self.edge_touch.is_empty() {
            return None;
        }
        let nodes = Block {
            span: doc.nodes.span,
            entries: place(&doc.nodes.entries, &self.node_touch, node_key, node_cmp),
        };
        let edges = Block {
            span: doc.edges.span,
            entries: place(&doc.edges.entries, &self.edge_touch, edge_key, edge_cmp),
        };
        Some(render_lock(&doc.lines, &nodes, &edges))
    }
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

/// The wiring records and the new surfaces, or `None` when
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
    let rel_slot = json_string(rel);
    let file_tuple = render_tuple_with_slots(
        &node_entry.elems,
        brotli_for_slot3(Some(&rel_slot)),
        Some("null"),
        Some(&rel_slot),
    );
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
    Ok(Some(Wiring {
        records,
        pkgs: new_pkgs,
        node_touch,
        edge_touch,
    }))
}

/// Write every changed package.json (path order), then the lock; a lock
/// write failure puts the package.json files back.
async fn commit(
    project_root: &Path,
    wiring: &Wiring,
    lock: Option<&str>,
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
    if let Some(lock) = lock {
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

pub const REINSTALL_REQUIRED: &str = "vendor_vlt_reinstall_required";

/// The importer edges whose `node_modules/<dep>` still resolves into vlt's
/// store, i.e. to an installed registry copy rather than the vendored dir.
async fn stale_links<'t>(project_root: &Path, target: &'t Target) -> Vec<&'t ImporterEdge> {
    let Ok(store) = tokio::fs::canonicalize(project_root.join(VLT_STORE_DIR)).await else {
        return Vec::new();
    };
    let mut stale = Vec::new();
    for edge in &target.importers {
        if importer_link_target(project_root, edge)
            .await
            .is_some_and(|real| real.starts_with(&store))
        {
            stale.push(edge);
        }
    }
    stale
}

async fn importer_link_target(project_root: &Path, edge: &ImporterEdge) -> Option<PathBuf> {
    let link = project_root
        .join(&edge.dir)
        .join("node_modules")
        .join(&edge.dep);
    tokio::fs::canonicalize(&link).await.ok()
}

/// Importer links that resolve into another uuid's vendored dir, which a
/// re-vendor to `uuid` removes: they dangle until vlt relinks them.
async fn superseded_links<'t>(
    project_root: &Path,
    target: &'t Target,
    uuid: &str,
) -> Vec<&'t ImporterEdge> {
    let Some(vendor_npm) = super::path::vendor_uuid_dir_rel("npm", uuid)
        .and_then(|rel| Path::new(&rel).parent().map(Path::to_path_buf))
    else {
        return Vec::new();
    };
    let Ok(vendor_npm) = tokio::fs::canonicalize(project_root.join(vendor_npm)).await else {
        return Vec::new();
    };
    let current = vendor_npm.join(uuid);
    let mut superseded = Vec::new();
    for edge in &target.importers {
        if importer_link_target(project_root, edge)
            .await
            .is_some_and(|real| real.starts_with(&vendor_npm) && !real.starts_with(&current))
        {
            superseded.push(edge);
        }
    }
    superseded
}

fn link_names(edges: &[&ImporterEdge]) -> String {
    edges
        .iter()
        .map(|e| {
            if e.dir.is_empty() {
                format!("node_modules/{}", e.dep)
            } else {
                format!("{}/node_modules/{}", e.dir, e.dep)
            }
        })
        .collect::<Vec<String>>()
        .join(", ")
}

/// `vendor_vlt_reinstall_required`: from 0.0.0-30 a plain `vlt install`
/// keeps an installed optional dependency whose spec moved to a `file:`
/// dir, so every rewired or still-stale optional edge needs `vlt ci`; a
/// stale link of any other edge needs a reinstall.
async fn reinstall_advisory(
    project_root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
    target: &Target,
    rewired: bool,
) -> Option<VendorWarning> {
    let stale = stale_links(project_root, target).await;
    let superseded = superseded_links(project_root, target, uuid).await;
    let optional = target.importers.iter().any(|e| {
        e.edge_type == "optional"
            && (rewired || stale.iter().chain(&superseded).any(|s| s.index == e.index))
    });
    if optional {
        return Some(VendorWarning::new(
            REINSTALL_REQUIRED,
            format!(
                "{name}@{version} is an optional dependency: `vlt install` (vlt 0.0.0-30 and \
                 later) keeps an installed upstream copy of an optional dependency whose spec \
                 moved to a vendored `file:` directory, so run `vlt ci` (or delete node_modules \
                 and run `vlt install`) to link the vendored copy. vlt 0.0.0-30 … 1.0.4 \
                 install no optional dependency from the lock of a project that declares only \
                 optional dependencies: upgrade vlt to 1.0.5 or later first."
            ),
        ));
    }
    let mut details = Vec::new();
    if !stale.is_empty() {
        details.push(format!(
            "{} still links {name}@{version} to its installed upstream copy",
            link_names(&stale)
        ));
    }
    if !superseded.is_empty() {
        details.push(format!(
            "{} links {name}@{version} to the vendored dir of the patch this one replaces, \
             which is removed, so requiring it fails",
            link_names(&superseded)
        ));
    }
    if details.is_empty() {
        return None;
    }
    Some(VendorWarning::new(
        REINSTALL_REQUIRED,
        format!(
            "{}; run `vlt install` (or `vlt ci`) to link the vendored copy",
            details.join("; ")
        ),
    ))
}

/// `vendor_vlt_reinstall_required` for a rebuilt dir that lost vlt's
/// links to its dependencies. A plain `vlt install` does not put them back
/// (measured on rc.14 through 1.2.0); `vlt ci` does.
fn links_dropped_warning(name: &str, version: &str) -> VendorWarning {
    VendorWarning::new(
        REINSTALL_REQUIRED,
        format!(
            "the rebuilt vendored dir for {name}@{version} has none of vlt's links to its \
             dependencies (its old node_modules/ held more than those links and was \
             discarded), so requiring them fails; run `vlt ci` (or delete node_modules and run \
             `vlt install`) to re-link them, as a plain `vlt install` does not"
        ),
    )
}

/// Repair's set-aside moves a whole uuid dir away before the rebuild, vlt's
/// links to the package's dependencies (`<dir>/node_modules/`) included.
/// After a successful rebuild at `project_root`, move them back from
/// `kept_uuid_dir` when they are only links; otherwise the rebuilt dir has
/// none, and the returned advisory says how to re-link them.
pub async fn keep_vlt_links(
    entry: &VendorEntry,
    kept_uuid_dir: &Path,
    project_root: &Path,
) -> Option<VendorWarning> {
    if entry.flavor.as_deref() != Some(FLAVOR) {
        return None;
    }
    let uuid_rel = super::path::vendor_uuid_dir_rel("npm", &entry.uuid)?;
    let within = entry
        .artifact
        .path
        .strip_prefix(uuid_rel.as_str())?
        .strip_prefix('/')?;
    if !is_safe_multi_segment(within) {
        return None;
    }
    let kept_rel = kept_uuid_dir.join(within);
    let old_links = kept_rel.join("node_modules");
    tokio::fs::symlink_metadata(&old_links).await.ok()?;
    let live_links = project_root.join(&entry.artifact.path).join("node_modules");
    let (name, version) = super::npm_common::parse_npm_purl(&entry.base_purl).unwrap_or_default();
    if tokio::fs::symlink_metadata(&live_links).await.is_ok()
        || !super::npm_dir::node_modules_holds_only_links(&kept_rel).await
        || tokio::fs::rename(&old_links, &live_links).await.is_err()
    {
        return Some(links_dropped_warning(&name, &version));
    }
    None
}

/// Vendor one installed npm package into a vlt project (see the module
/// doc). Same contract as the other npm backends: refuse-early / wire-last,
/// `entry` present iff `result.success` and not a dry run, and an in-sync
/// re-run synthesizes AlreadyPatched with no entry.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn vendor_vlt<'a>(
    purl: &str,
    _installed_dir: impl Into<PackageSource<'a>>,
    project_root: &Path,
    record: &PatchRecord,
    _sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    _force: bool,
    service: Option<&super::VendorServiceConfig>,
) -> VendorOutcome {
    let coords = match guard_coordinates(purl, record) {
        Ok(coords) => coords,
        Err(outcome) => return *outcome,
    };
    let (name, version) = (coords.name.as_str(), coords.version.as_str());
    // A bundled copy of the package (#471) has no lock node, so no rewire
    // reaches it: it stays unpatched beside whatever this run wires.
    let bundled = match crate::utils::purl::npm_purl(name, version) {
        Some(key) => super::vlt_bundled::bundled_copies(project_root)
            .await
            .remove(&key),
        None => None,
    };
    let analysis = match analyze(project_root, name, version, &record.uuid).await {
        Ok(analysis) => analysis,
        Err(("vendor_lock_entry_not_found", _)) if bundled.is_some() => {
            // The package IS installed, so "run `vlt install`" would be
            // wrong twice over: name the real reason.
            return refused(
                "vendor_lock_entry_not_rewritable",
                super::vlt_bundled::bundled_copy_detail(
                    name,
                    version,
                    bundled.as_deref().unwrap_or_default(),
                ),
            );
        }
        Err((code, detail)) => return refused(code, detail),
    };
    let mut warnings = Vec::new();
    if let Some(location) = &bundled {
        warnings.push(VendorWarning::new(
            "vendor_bundled_instance_skipped",
            super::vlt_bundled::bundled_copy_detail(name, version, location),
        ));
    }
    if analysis.doc.is_era_a() {
        warnings.push(VendorWarning::new(
            "vendor_vlt_legacy_lockfile",
            "vlt-lock.json was written by vlt 0.0.0-19 … 1.0.0-rc.8 (`··` or scalar-registry URL \
             ids); vlt 0.0.0-31 … 1.0.0-rc.5 install the vendored lock but fail to reinstall \
             the vendored `file:` dependency if vlt-lock.json is deleted and re-created — \
             upgrade vlt",
        ));
    }
    let prior = prior_vlt_entry(project_root, purl).await;
    let wiring = match plan_wiring(&analysis, prior.as_ref()) {
        Ok(wiring) => wiring,
        Err((code, detail)) => return refused(code, detail),
    };

    let reinstall = reinstall_advisory(
        project_root,
        name,
        version,
        &record.uuid,
        &analysis.target,
        wiring.is_some(),
    )
    .await;

    let (staged, result) =
        match stage_patch_dir(purl, project_root, record, dry_run, &mut warnings, service).await {
            Ok(pair) => pair,
            Err(outcome) => return *outcome,
        };
    if result.success {
        warnings.extend(reinstall);
    }
    let Some(staged) = staged else {
        return done(result, None, warnings);
    };
    if staged.links_dropped {
        warnings.push(links_dropped_warning(name, version));
    }
    let entry_for = |wiring: Vec<WiringRecord>| {
        VendorEntry::npm(
            coords.base_purl.clone(),
            record.uuid.clone(),
            VendorArtifact::dir(staged.rel_dir.clone(), staged.inventory.clone()),
            wiring,
            Some(FLAVOR),
        )
    };

    if wiring.is_none() && staged.reused {
        // In sync: the committed dir was reused and the wiring already
        // points at it. Record nothing.
        let rel_abs = project_root.join(&staged.rel_dir);
        return done(
            already_patched_result(purl, &rel_abs, &record.files),
            None,
            warnings,
        );
    }
    // Once per run that records an entry, after the in-sync return (the
    // tarball flavors' rule, see `npm_common::vendor_npm_family`).
    if staged.staged_pkg_json.is_some() {
        warnings.push(VendorWarning::new(
            "vendor_dep_manifest_stale",
            format!(
                "the patch rewrites {name}@{version}'s package.json; vlt-lock.json keeps the \
                 node's recorded dependency edges, and `vlt install` and `vlt ci` install from \
                 them — if the patch changed dependency ranges, run `vlt update` to re-resolve \
                 them (it resolves every dependency of the project from scratch)"
            ),
        ));
    }
    let Some(wiring) = wiring else {
        warnings.push(VendorWarning::new(
            "vendor_artifact_rebuilt",
            format!(
                "the committed vendored dir for {name}@{version} was missing or stale; rebuilt \
                 at {} (vlt-lock.json and package.json untouched)",
                staged.rel_dir
            ),
        ));
        let entry = entry_for(Vec::new());
        return finish_vendored(
            project_root,
            &coords,
            record,
            vendored_at,
            result,
            entry,
            warnings,
        )
        .await;
    };
    let lock = wiring.lock(&analysis.doc);
    if let Err(e) = commit(project_root, &wiring, lock.as_deref(), &analysis.pkgs).await {
        return done_failure_unstage(
            purl,
            e,
            project_root,
            &coords.uuid_dir_rel,
            staged.uuid_dir_preexisted,
        )
        .await;
    }
    let entry = entry_for(wiring.records);
    finish_vendored(
        project_root,
        &coords,
        record,
        vendored_at,
        result,
        entry,
        warnings,
    )
    .await
}

/// Which of `packages` [`vendor_vlt`] would refuse before it first asks
/// the patch service (see `npm_flavor::preflight_packages`): the flavor
/// change, the coordinates guard, the lock analysis with its declaration
/// checks and the wiring plan — every gate ahead of [`stage_patch_dir`],
/// in the backend's order, against the project as it is now.
pub(super) async fn preflight_packages(
    project_root: &Path,
    packages: &[(&str, &PatchRecord)],
) -> Vec<Result<(), &'static str>> {
    let mut verdicts = Vec::with_capacity(packages.len());
    for (purl, record) in packages {
        verdicts.push(preflight_package(project_root, purl, record).await);
    }
    verdicts
}

async fn preflight_package(
    project_root: &Path,
    purl: &str,
    record: &PatchRecord,
) -> Result<(), &'static str> {
    if let Ok(state) = super::state::load_state_shared(project_root).await {
        if super::npm_flavor::vlt_flavor_change_refusal(&state.entries, purl).is_some() {
            return Err("vendor_flavor_changed");
        }
    }
    let coords =
        guard_coordinates(purl, record).map_err(|o| super::npm_common::refusal_code(&o))?;
    let analysis = analyze(project_root, &coords.name, &coords.version, &record.uuid)
        .await
        .map_err(|(code, _)| code)?;
    let prior = prior_vlt_entry(project_root, purl).await;
    plan_wiring(&analysis, prior.as_ref()).map_err(|(code, _)| code)?;
    Ok(())
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

// ── revert ───────────────────────────────────────────────────────────────

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
            has_brotli_flag(original.elems[0]),
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

/// The cross-grammar drift detail: the user re-created the lock
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

/// A revert's `vendor_vlt_reinstall_required`: an importer's
/// `node_modules/<dep>` still resolving into the vendored dir outlives the
/// revert, and a plain `vlt install` keeps it for an optional dependency
/// whose spec moved back from the `file:` dir, so that one needs `vlt ci`.
async fn revert_reinstall_advisory(
    project_root: &Path,
    entry: &VendorEntry,
    uuid_dir: &Path,
    restored_optional: bool,
) -> Option<VendorWarning> {
    let vendored = tokio::fs::canonicalize(uuid_dir).await.ok();
    let mut stale: Vec<String> = Vec::new();
    let mut stale_optional = false;
    for rec in entry.wiring.iter().filter(|r| r.kind == KIND_PKG_DEP) {
        let (Some(vendored), Some((field, name))) = (
            vendored.as_ref(),
            rec.key.as_deref().and_then(split_pkg_key),
        ) else {
            continue;
        };
        let dir = rec.file.strip_suffix(PACKAGE_JSON).unwrap_or_default();
        let link = format!("{dir}node_modules/{name}");
        if stale.contains(&link) {
            continue;
        }
        if tokio::fs::canonicalize(project_root.join(&link))
            .await
            .is_ok_and(|real| real.starts_with(vendored))
        {
            stale_optional |= field == "optionalDependencies";
            stale.push(link);
        }
    }
    let label = parse_npm_purl(&entry.base_purl)
        .map_or_else(|| entry.base_purl.clone(), |(n, v)| format!("{n}@{v}"));
    if restored_optional || stale_optional {
        return Some(VendorWarning::new(
            REINSTALL_REQUIRED,
            format!(
                "{label} is an optional dependency: `vlt install` (vlt 0.0.0-30 and later) \
                 keeps node_modules linked to the vendored `file:` directory of an optional \
                 dependency whose spec moved back from it, so run `vlt ci` (or delete \
                 node_modules and run `vlt install`) to link the restored copy. vlt 0.0.0-30 \
                 … 1.0.4 install no optional dependency from the lock of a project that \
                 declares only optional dependencies: upgrade vlt to 1.0.5 or later first."
            ),
        ));
    }
    if stale.is_empty() {
        return None;
    }
    Some(VendorWarning::new(
        REINSTALL_REQUIRED,
        format!(
            "{} still links {label} to its vendored copy; run `vlt install` (or `vlt ci`) to \
             link the restored copy",
            stale.join(", ")
        ),
    ))
}

/// The first lock entry (an edge before a node) whose key or value names
/// one of `needles`, which are lowercase. A uuid, and a vendored path in
/// either DepID spelling, read the same wherever the lock writes them: in
/// a node key, an edge's source, its `file:` spec and its target.
fn lock_entry_naming<'e>(
    nodes: &[&'e Entry],
    edges: &[&'e Entry],
    needles: &[String],
) -> Option<&'e Entry> {
    let names = |entry: &&&Entry| {
        let (key, value) = (
            entry.key.to_ascii_lowercase(),
            entry.value.to_ascii_lowercase(),
        );
        needles
            .iter()
            .any(|needle| key.contains(needle) || value.contains(needle))
    };
    edges
        .iter()
        .find(names)
        .or(nodes.iter().find(names))
        .copied()
}

/// How an unrecorded lock entry reads in a warning: an edge with the
/// `package.json` that declares it, or a node.
fn unrecorded_entry(entry: &Entry) -> String {
    match entry.key.split_once(' ') {
        Some((from, _)) => match importer_dir(from) {
            Some(dir) => format!("edge `{}` (declared in {})", entry.key, pkg_json_rel(&dir)),
            None => format!("edge `{}`", entry.key),
        },
        None => format!("node `{}`", entry.key),
    }
}

/// What names the entry's own vendored node in a lock: the directory's
/// path below the vendor root, its DepID in both grammars, and the node
/// key the ledger recorded. All lowercase.
fn own_node_needles(entry: &VendorEntry) -> Vec<String> {
    let path = entry.artifact.path.as_str();
    let mut needles = vec![
        path.strip_prefix(".socket/vendor/npm/")
            .unwrap_or(path)
            .to_string(),
        encode_segment(path, DepIdEra::Tilde),
        encode_segment(path, DepIdEra::Legacy),
    ];
    needles.extend(
        entry
            .wiring
            .iter()
            .filter(|r| r.kind == KIND_LOCK_NODE)
            .filter_map(|r| fragment(&r.new).and_then(parse_node_entry_text))
            .map(|node| node.key.to_string()),
    );
    needles.iter().map(|n| n.to_ascii_lowercase()).collect()
}

/// Whether a `package.json` still names the uuid dir, in any string it
/// holds (a file that is not JSON is searched as text).
fn manifest_names_uuid(text: &str, uuid: &str) -> bool {
    fn names(value: &Value, needle: &str) -> bool {
        match value {
            Value::String(s) => s.to_ascii_lowercase().contains(needle),
            Value::Array(items) => items.iter().any(|v| names(v, needle)),
            Value::Object(map) => map
                .iter()
                .any(|(k, v)| k.to_ascii_lowercase().contains(needle) || names(v, needle)),
            _ => false,
        }
    }
    let needle = uuid.to_ascii_lowercase();
    match serde_json::from_str::<Value>(crate::formats::text::strip_bom(text)) {
        Ok(value) => names(&value, &needle),
        Err(_) => text.to_ascii_lowercase().contains(&needle),
    }
}

/// Undo one vlt-vendored package: every record through its inverse,
/// all or nothing, then remove the artifact.
///
/// The artifact goes only when nothing the project installs from still
/// names it. A lock entry the ledger never recorded that still reaches the
/// vendored node (the edge of a workspace pointed at the directory after
/// vendoring) leaves the whole revert alone, as drift: undoing the node
/// under it would leave that edge dangling. Anything else that still names
/// the uuid dir (an importer `package.json`, the wiring of another package
/// vendored under the same uuid) keeps the directory and the ledger entry
/// (`vendor_revert_residual_reference`) with the recorded wiring restored.
/// A dry run does all of this but the writes, so it reports what the real
/// run would.
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
        if rec.kind == KIND_PKG_DEP {
            if let Some(detail) = linked_importer(project_root, &rec.file) {
                outcome.warnings.push(drifted(detail));
                continue;
            }
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

    // The lock and the manifests as the revert leaves them.
    let mut new_pkgs = pkgs.clone();
    let mut staged = None;
    if !already_reverted {
        staged = doc.as_ref().map(|d| Staged {
            nodes: d.nodes.entries.clone(),
            edges: d.edges.entries.clone(),
            touched_nodes: Vec::new(),
            touched_edges: Vec::new(),
            merged_nodes: BTreeSet::new(),
            merged_edges: BTreeSet::new(),
        });
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
        if let Some(staged) = staged.as_mut() {
            drop_unrecorded_file_edges(staged, entry);
        }
    }
    fn left<'e>(entries: &'e [Entry], merged: &BTreeSet<usize>) -> Vec<&'e Entry> {
        let entries = entries.iter().enumerate();
        entries
            .filter(|(i, _)| !merged.contains(i))
            .map(|(_, e)| e)
            .collect()
    }
    let (nodes, edges) = match (&staged, &doc) {
        (Some(staged), _) => (
            left(&staged.nodes, &staged.merged_nodes),
            left(&staged.edges, &staged.merged_edges),
        ),
        (None, Some(doc)) => (
            doc.nodes.entries.iter().collect(),
            doc.edges.entries.iter().collect(),
        ),
        (None, None) => (Vec::new(), Vec::new()),
    };
    let fix = "point it back at the registry release, run `vlt install`, then re-run \
               `socket-patch vendor --revert`";
    if let Some(unrecorded) = lock_entry_naming(&nodes, &edges, &own_node_needles(entry)) {
        outcome.warnings.push(drifted(format!(
            "{VLT_LOCK} {} still installs from {uuid_dir_rel} and the vendor ledger has no \
             record of wiring it; {fix}",
            unrecorded_entry(unrecorded)
        )));
        outcome.keep_artifact(&uuid_dir_rel);
        return outcome;
    }
    // What still names the uuid dir once the records are undone, and so
    // keeps it: nothing of this entry's to restore, nothing to delete
    // under.
    let mut naming = Vec::new();
    if !keep_artifact {
        let uuid = [entry.uuid.to_ascii_lowercase()];
        if let Some(other) = lock_entry_naming(&nodes, &edges, &uuid) {
            naming.push(format!("{VLT_LOCK} {}", unrecorded_entry(other)));
        }
        for rel in &allowed {
            let text = match new_pkgs.get(rel) {
                Some(text) => Some(text.clone()),
                None => read_regular_to_string(&project_root.join(rel)).await.ok(),
            };
            if text.is_some_and(|text| manifest_names_uuid(&text, &entry.uuid)) {
                naming.push(rel.clone());
            }
        }
    }
    let new_lock = match (doc.as_ref(), staged) {
        (Some(doc), Some(staged)) => Some(render_restored(doc, staged)),
        _ => None,
    }
    .filter(|lock| Some(lock) != lock_text.as_ref());

    if !dry_run {
        if let Some(lock) = &new_lock {
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

    let uuid_dir = project_root.join(&uuid_dir_rel);
    let restored_optional = !already_reverted
        && entry.wiring.iter().any(|r| {
            r.kind == KIND_PKG_DEP
                && r.key
                    .as_deref()
                    .and_then(split_pkg_key)
                    .is_some_and(|(field, _)| field == "optionalDependencies")
        });
    let reinstall =
        revert_reinstall_advisory(project_root, entry, &uuid_dir, restored_optional).await;
    if !naming.is_empty() {
        outcome.warnings.push(VendorWarning::new(
            super::RESIDUAL_REFERENCE_CODE,
            format!(
                "{} still {} {uuid_dir_rel}, which this entry's records do not cover; {fix}",
                naming.join(", "),
                if naming.len() == 1 { "names" } else { "name" },
            ),
        ));
        outcome.keep_artifact_for_reference(&uuid_dir_rel);
    } else if !dry_run && !keep_artifact {
        if let Err(e) = remove_tree_and_prune(&uuid_dir, &project_root.join(SOCKET_DIR)).await {
            return RevertOutcome::failed(format!("cannot remove {uuid_dir_rel}: {e}"));
        }
    }
    outcome.warnings.extend(reinstall);
    outcome
}

/// Edges vlt added from the vendored `file` node after vendoring (a `vlt
/// update` resolving a dependency the patch added) have no wiring record
/// and would dangle from the node the revert removes: drop them, and every
/// node that only they kept in the lock.
fn drop_unrecorded_file_edges(staged: &mut Staged, entry: &VendorEntry) {
    let live = |staged: &Staged, id: &str| {
        staged
            .nodes
            .iter()
            .enumerate()
            .any(|(i, e)| e.key == id && !staged.merged_nodes.contains(&i))
    };
    let mut gone: Vec<String> = entry
        .wiring
        .iter()
        .filter(|r| r.kind == KIND_LOCK_NODE)
        .filter_map(|r| fragment(&r.new).and_then(parse_node_entry_text))
        .map(|n| n.key.to_string())
        .filter(|id| !live(staged, id))
        .collect();
    let target_of = |e: &Entry| parse_edge_entry_text(&e.text()).map(|x| x.target().to_string());
    while let Some(id) = gone.pop() {
        let mut targets = Vec::new();
        for (i, e) in staged.edges.iter().enumerate() {
            if e.edge_from() == id && staged.merged_edges.insert(i) {
                targets.extend(target_of(e));
            }
        }
        for target in targets {
            let referenced = staged.edges.iter().enumerate().any(|(i, e)| {
                !staged.merged_edges.contains(&i) && target_of(e).as_deref() == Some(&target)
            });
            if referenced {
                continue;
            }
            if let Some(i) = staged.nodes.iter().position(|e| e.key == target) {
                if staged.merged_nodes.insert(i) {
                    gone.push(target);
                }
            }
        }
    }
}

/// A block without its merged entries, the restored ones re-placed
/// in the forward record order.
fn restored_block<K>(
    entries: &[Entry],
    touched: &[usize],
    merged: &BTreeSet<usize>,
    key: fn(&Entry) -> Option<K>,
    cmp: fn(&K, &K) -> Option<Ordering>,
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
    place(&kept, &touched, key, cmp)
}

fn render_restored(doc: &LockDoc, staged: Staged) -> String {
    let nodes = restored_block(
        &staged.nodes,
        &staged.touched_nodes,
        &staged.merged_nodes,
        node_key,
        node_cmp,
    );
    let edges = restored_block(
        &staged.edges,
        &staged.touched_edges,
        &staged.merged_edges,
        edge_key,
        edge_cmp,
    );
    let nodes = Block {
        span: doc.nodes.span,
        entries: nodes,
    };
    let edges = Block {
        span: doc.edges.span,
        entries: edges,
    };
    render_lock(&doc.lines, &nodes, &edges)
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
        crate::vendor::test_support::vendor_vlt(
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
        let placed = place(&entries, &[(0, entry("~npm~e@1.0.0"))], node_key, node_cmp);
        let keys: Vec<&str> = placed.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, ["~npm~d@1.0.0", "~npm~e@1.0.0", "~npm~f@1.0.0"]);
        let placed = place(&entries, &[(1, entry("~npm~z@1.0.0"))], node_key, node_cmp);
        assert_eq!(placed.last().unwrap().key, "~npm~z@1.0.0");

        // `é` is outside the collation table: every replacement stays put.
        let placed = place(&entries, &[(0, entry("file~é"))], node_key, node_cmp);
        let keys: Vec<&str> = placed.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, ["file~é", "~npm~d@1.0.0", "~npm~f@1.0.0"]);
    }

    /// `place` as first written: every comparison of two edges formats and
    /// decodes both.
    fn place_reference(
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

    fn node_cmp_reference(a: &Entry, b: &Entry) -> Option<Ordering> {
        vlt_collate(&a.key, &b.key)
    }

    fn edge_cmp_reference(a: &Entry, b: &Entry) -> Option<Ordering> {
        let a_text = a.text();
        let b_text = b.text();
        let a = parse_edge_entry_text(&a_text)?;
        let b = parse_edge_entry_text(&b_text)?;
        vlt_edge_cmp(a.sort_key(), b.sort_key())
    }

    /// Every `vlt-lock.json` under the test fixtures that is in vlt's
    /// canonical layout.
    fn fixture_docs() -> Vec<(String, LockDoc)> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let mut docs = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.file_name().is_some_and(|name| name == VLT_LOCK) {
                    let text = std::fs::read_to_string(&path).unwrap();
                    if let Ok(doc) = parse_doc(&text) {
                        let label = path.strip_prefix(&root).unwrap().display().to_string();
                        docs.push((label, doc));
                    }
                }
            }
        }
        docs.sort_by(|a, b| a.0.cmp(&b.0));
        docs
    }

    /// VBV-P1: placing over sort keys read once per entry gives, entry for
    /// entry, what comparing by decoding both edges each time gave: for
    /// the nodes and the edges of every fixture lock, with one and with two
    /// replacements that move to the front, the middle, the end, the `file`
    /// range, stay where they are, or cannot be compared at all (a key
    /// outside the collation table, text that is no edge).
    #[test]
    fn placement_agrees_with_the_per_comparison_decoding_it_replaces() {
        let file = format!("file~.socket+vendor+npm+{UUID}+a-1.0.0+node__modules+a");
        let node_keys = [
            file.clone(),
            "~npm~a@0.0.1".to_string(),
            "~npm~zzzz@9.0.0".to_string(),
            "·npm·m@1.0.0".to_string(),
            "~npm~M@1.0.0".to_string(),
            "file~é".to_string(),
        ];
        let edges = [
            (
                format!("{file} dep"),
                "\"prod ^1.0.0 ~npm~a@1.0.0\"".to_string(),
            ),
            (
                "file~_d zz".to_string(),
                format!("\"prod file:./x {file}\""),
            ),
            (
                "file~_d a".to_string(),
                "\"dev 1.0.0 ~npm~a@1.0.0\"".to_string(),
            ),
            (
                "workspace~packages+a a".to_string(),
                "\"optional 1.0.0 MISSING\"".to_string(),
            ),
            (
                "~npm~zzzz@9.0.0 a".to_string(),
                "\"peer * ~npm~a@1.0.0\"".to_string(),
            ),
            (
                "~npm~é@1.0.0 a".to_string(),
                "\"prod 1.0.0 ~npm~a@1.0.0\"".to_string(),
            ),
            ("~npm~a@1.0.0 a".to_string(), "\"not an edge\"".to_string()),
        ];
        let docs = fixture_docs();
        assert!(docs.len() >= 20, "{} canonical fixture locks", docs.len());
        let (mut compared, mut fell_back) = (0, 0);
        for (label, doc) in &docs {
            for (block, is_nodes) in [(&doc.nodes, true), (&doc.edges, false)] {
                let len = block.entries.len();
                for seed in 0..14 {
                    let replacement = |at: usize, pick: usize| {
                        let current = &block.entries[at];
                        if pick % 8 == 7 {
                            return current.clone();
                        }
                        let (key, value) = if is_nodes {
                            (
                                node_keys[pick % node_keys.len()].clone(),
                                current.value.clone(),
                            )
                        } else {
                            edges[pick % edges.len()].clone()
                        };
                        Entry {
                            key,
                            value,
                            cr: current.cr,
                        }
                    };
                    let mut touched = Vec::new();
                    if len > 0 {
                        let first = (seed * 7 + 1) % len;
                        touched.push((first, replacement(first, seed)));
                        let second = (seed * 13 + 5) % len;
                        if seed % 2 == 1 && second != first {
                            touched.push((second, replacement(second, seed / 2)));
                        }
                    }
                    let (placed, reference) = if is_nodes {
                        (
                            place(&block.entries, &touched, node_key, node_cmp),
                            place_reference(&block.entries, &touched, node_cmp_reference),
                        )
                    } else {
                        (
                            place(&block.entries, &touched, edge_key, edge_cmp),
                            place_reference(&block.entries, &touched, edge_cmp_reference),
                        )
                    };
                    assert_eq!(placed, reference, "{label}, nodes: {is_nodes}, seed {seed}");
                    compared += 1;
                    let mut in_place = block.entries.clone();
                    for (at, entry) in &touched {
                        in_place[*at] = entry.clone();
                    }
                    fell_back += usize::from(placed == in_place && !touched.is_empty());
                }
            }
        }
        assert!(compared >= 500 && fell_back >= 50, "{compared} {fell_back}");
    }

    /// VBV-P1: an edge is decoded once per placement, not once per
    /// comparison. Two replacements among 2,000 edges used to decode about
    /// 7,000 edges; now it is 2,000, the 1,998 that stay and the two
    /// replacements.
    #[test]
    fn a_placement_decodes_each_edge_once() {
        let edges: Vec<Entry> = (0..2000)
            .map(|i| Entry {
                key: format!("file~_d p{i:04}"),
                value: format!("\"prod 1.0.0 ~npm~p{i:04}@1.0.0\""),
                cr: false,
            })
            .collect();
        let moved = |i: usize, to: &str| Entry {
            value: format!("\"prod file:./x {to}\""),
            ..edges[i].clone()
        };
        let touched = [
            (10, moved(10, "~npm~p1500@9.0.0")),
            (1990, moved(1990, "file~z")),
        ];
        EDGE_KEYS_READ.with(|read| read.set(0));
        let placed = place(&edges, &touched, edge_key, edge_cmp);
        assert_eq!(EDGE_KEYS_READ.with(|read| read.get()), edges.len());
        assert_eq!(
            placed,
            place_reference(&edges, &touched, edge_cmp_reference)
        );
        assert_eq!(placed.len(), edges.len());
        assert_eq!(placed[1499].key, "file~_d p1500");
        assert_eq!(placed[1500].key, "file~_d p0010", "after p1500's edge");
        assert_eq!(placed.last().unwrap().key, "file~_d p1990");
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

    /// REGRESSION (#471): package `a` bundles `left-pad@1.3.0`, which vlt
    /// unpacks into `a`'s store entry with no lock node. Vendoring wires
    /// the regular node but must say loudly that the bundled copy stays
    /// unpatched; with the bundled copy as the only install, it refuses
    /// with that reason instead of "run `vlt install`".
    #[tokio::test]
    async fn a_bundled_store_copy_is_reported_not_silently_left_unpatched() {
        let bundled = (
            "node_modules/.vlt/~npm~a@1.0.0/node_modules/a/node_modules/left-pad/package.json",
            r#"{"name":"left-pad","version":"1.3.0"}"#,
        );
        let parent = (
            "node_modules/.vlt/~npm~a@1.0.0/node_modules/a/package.json",
            r#"{"name":"a","version":"1.0.0","bundleDependencies":["left-pad"]}"#,
        );
        let both = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG), parent, bundled]).await;
        let (entry, warnings) = entry_of(run(&both, UUID, false).await);
        assert!(!entry.wiring.is_empty());
        let warning = warnings
            .iter()
            .find(|w| w.code == "vendor_bundled_instance_skipped")
            .unwrap_or_else(|| panic!("{warnings:?}"));
        assert!(
            warning.detail.contains("~npm~a@1.0.0") && warning.detail.contains("UNPATCHED"),
            "{}",
            warning.detail
        );

        let only_bundled = render(
            1,
            &[r#""~npm~a@1.0.0": [0,"a","sha512-A=="]"#],
            &[r#""file~_d a": "prod 1.0.0 ~npm~a@1.0.0""#],
        );
        let only = fx(&only_bundled, &[(PACKAGE_JSON, ROOT_PKG), parent, bundled]).await;
        let (code, detail) = refusal(run(&only, UUID, false).await);
        assert_eq!(code, "vendor_lock_entry_not_rewritable", "{detail}");
        assert!(detail.contains("UNPATCHED"), "{detail}");
    }

    #[tokio::test]
    async fn wires_the_node_edges_and_package_json_in_vlt_order() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, warnings) = entry_of(run(&fx, UUID, false).await);
        assert!(
            warnings
                .iter()
                .all(|w| w.code == "vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
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
        let modifier_node =
            r#""~npm~left-pad@1.3.0~_croot_s_g_s#left-pad": [0,"left-pad","sha512-M=="]"#;
        let cases: Vec<(String, &str, &str, &str)> = vec![
            (
                render(1, &[r#""~acme~left-pad@1.3.0": [0,"left-pad","sha512-A=="]"#], &[r#""file~_d left-pad": "prod 1.3.0 ~acme~left-pad@1.3.0""#]),
                ROOT_PKG,
                UNSUPPORTED,
                "not from vlt's default registry; vendoring rewires only default-registry \
                 packages, so use agent mode",
            ),
            (
                render(1, &[r#""remote~https_c++registry.npmjs.org+left-pad+-+left-pad-1.3.0.tgz": [0,"left-pad","sha512-R=="]"#, REG_NODE], &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#, r#""file~_d lp2": "prod https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz remote~https_c++registry.npmjs.org+left-pad+-+left-pad-1.3.0.tgz""#]),
                ROOT_PKG,
                UNSUPPORTED,
                "also installs left-pad from remote~https_c++registry.npmjs.org+left-pad+-+left-pad-1.3.0.tgz",
            ),
            (
                render(1, &[r#""git~github_cfoo+left-pad~v1.3.0": [0,"left-pad"]"#, REG_NODE], &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#, r#""file~_d lp2": "prod github:foo/left-pad#v1.3.0 git~github_cfoo+left-pad~v1.3.0""#]),
                ROOT_PKG,
                UNSUPPORTED,
                "a git, remote tarball or local directory dependency",
            ),
            (
                render(1, &[REG_NODE, url_node], &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#]),
                ROOT_PKG,
                UNSUPPORTED,
                "peer/modifier variants; use --mode hosted",
            ),
            (
                render(1, &[modifier_node], &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0~_croot_s_g_s#left-pad""#]),
                ROOT_PKG,
                UNSUPPORTED,
                "a modifier variant instance (~npm~left-pad@1.3.0~_croot_s_g_s#left-pad): peer/modifier variants",
            ),
            (
                render(1, &[REG_NODE.replace("~npm~left-pad@1.3.0", "~npm~left-pad@1.3.0~peer.2").as_str(), url_node], &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0~peer.1""#, r#""workspace~packages+a left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0~peer.2""#]),
                ROOT_PKG,
                UNSUPPORTED,
                "2 instances",
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
    async fn a_single_peer_context_is_vendored_without_its_extra() {
        let member_pkg =
            "{\n  \"name\": \"a\",\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";
        let rows = [
            (
                1,
                "~npm~left-pad@1.3.0~peer.0df72515a50372ba",
                "file~_d",
                "~npm~z@1.0.0",
                "",
            ),
            (
                1,
                "~npm~left-pad@1.3.0~peer.1",
                "workspace~packages+a",
                "~npm~z@1.0.0",
                "packages/a",
            ),
            (
                0,
                "·npm·left-pad@1.3.0·%E1%B9%97%3A3",
                "file·.",
                "·npm·z@1.0.0",
                "",
            ),
        ];
        for (version, reg, importer, z, dir) in rows {
            let lock = render(
                version,
                &[
                    &format!(
                        r#""{reg}": [0,"left-pad","sha512-REG==","https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"]"#
                    ),
                    &format!(r#""{z}": [0,"z","sha512-Z=="]"#),
                ],
                &[
                    &format!(r#""{importer} left-pad": "prod 1.3.0 {reg}""#),
                    &format!(r#""{reg} z": "peer ^1.0.0 {z}""#),
                ],
            );
            let pkg_rel = if dir.is_empty() {
                PACKAGE_JSON.to_string()
            } else {
                format!("{dir}/{PACKAGE_JSON}")
            };
            let pkg = if dir.is_empty() { ROOT_PKG } else { member_pkg };
            let fx = fx(&lock, &[(pkg_rel.as_str(), pkg)]).await;
            let (entry, _) = entry_of(run(&fx, UUID, false).await);
            let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad");
            let era = if version == 1 {
                DepIdEra::Tilde
            } else {
                DepIdEra::Legacy
            };
            let file_id = file_dep_id(&rel, era);
            let spec = importer_spec(dir, &rel);
            assert_eq!(
                read(&fx, VLT_LOCK).await,
                render(
                    version,
                    &[
                        &format!(r#""{z}": [0,"z","sha512-Z=="]"#),
                        &format!(r#""{file_id}": [0,"left-pad",null,"{rel}"]"#),
                    ],
                    &[
                        &format!(r#""{importer} left-pad": "prod {spec} {file_id}""#),
                        &format!(r#""{file_id} z": "peer ^1.0.0 {z}""#),
                    ],
                ),
                "{reg}"
            );
            assert!(read(&fx, &pkg_rel)
                .await
                .contains(&format!("\"left-pad\": \"{spec}\"")));
            assert_eq!(entry.wiring[1].key.as_deref(), Some(reg), "{reg}");
            let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
            assert!(out.success && out.warnings.is_empty(), "{reg}: {out:?}");
            assert_eq!(
                read(&fx, VLT_LOCK).await,
                lock,
                "{reg}: revert restores the extra"
            );
            assert_eq!(read(&fx, &pkg_rel).await, pkg, "{reg}");
        }
    }

    #[tokio::test]
    async fn a_scalar_registry_era_a_lock_warns_like_an_empty_segment_one() {
        let url_id = "·https%3A§§registry.yarnpkg.com§·left-pad@1.3.0";
        let lock = |registry: &str, extra_node: Option<&str>| {
            let mut nodes = vec![format!(r#""{url_id}": [0,"left-pad","sha512-REG=="]"#)];
            nodes.extend(extra_node.map(str::to_string));
            let nodes: Vec<&str> = nodes.iter().map(String::as_str).collect();
            render(
                0,
                &nodes,
                &[&format!(r#""file·. left-pad": "prod 1.3.0 {url_id}""#)],
            )
            .replace(
                "\"options\": {}",
                &format!("\"options\": {{\"registry\": \"{registry}\"}}"),
            )
        };
        let cases = [
            (lock("https://registry.yarnpkg.com", None), true),
            (lock("https://registry.yarnpkg.com/", None), true),
            (lock("https://registry.npmjs.org/", None), false),
            (
                lock(
                    "https://registry.yarnpkg.com/",
                    Some(r#""·npm·a@1.0.0": [0,"a","sha512-A=="]"#),
                ),
                false,
            ),
        ];
        for (lock, warns) in cases {
            let fx = fx(&lock, &[(PACKAGE_JSON, ROOT_PKG)]).await;
            let outcome = run(&fx, UUID, false).await;
            if lock.contains("registry.npmjs.org") {
                let (code, _) = refusal(outcome);
                assert_eq!(code, UNSUPPORTED, "{lock}");
                continue;
            }
            let (_, warnings) = entry_of(outcome);
            assert_eq!(
                codes(&warnings).contains(&"vendor_vlt_legacy_lockfile"),
                warns,
                "{lock}: {warnings:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_optional_or_stale_linked_edge_asks_for_vlt_ci() {
        let optional_lock = basic_lock().replace(
            "\"file~_d left-pad\": \"prod 1.3.0",
            "\"file~_d left-pad\": \"optional 1.3.0",
        );
        let optional_pkg = "{\n  \"name\": \"root\",\n  \"dependencies\": {\n    \"a\": \"1.0.0\"\n  },\n  \"optionalDependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";
        let fx = fx(&optional_lock, &[(PACKAGE_JSON, optional_pkg)]).await;
        let (entry, warnings) = entry_of(run(&fx, UUID, false).await);
        let advisory: Vec<&VendorWarning> = warnings
            .iter()
            .filter(|w| w.code == REINSTALL_REQUIRED)
            .collect();
        assert_eq!(advisory.len(), 1, "{warnings:?}");
        assert!(
            advisory[0].detail.starts_with(
                "left-pad@1.3.0 is an optional dependency: `vlt install` (vlt 0.0.0-30 and later) \
                 keeps an installed upstream copy"
            ),
            "{}",
            advisory[0].detail
        );
        assert!(advisory[0].detail.contains("run `vlt ci`"));
        persist(&fx, &entry).await;
        let rerun = run(&fx, UUID, false).await;
        let VendorOutcome::Done { warnings, .. } = rerun else {
            panic!("{rerun:?}");
        };
        assert!(
            !codes(&warnings).contains(&REINSTALL_REQUIRED),
            "{warnings:?}"
        );

        let store = fx
            .root
            .join(VLT_STORE_DIR)
            .join(REG)
            .join("node_modules/left-pad");
        std::fs::create_dir_all(&store).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&store, fx.root.join("node_modules/left-pad")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&store, fx.root.join("node_modules/left-pad")).unwrap();
        let VendorOutcome::Done { warnings, .. } = run(&fx, UUID, false).await else {
            panic!("rerun");
        };
        assert!(
            warnings.iter().any(|w| w.code == REINSTALL_REQUIRED
                && w.detail
                    .starts_with("left-pad@1.3.0 is an optional dependency")),
            "an in-sync rerun with the upstream copy still linked: {warnings:?}"
        );

        let fx = self::fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (_, warnings) = entry_of(run(&fx, UUID, false).await);
        assert!(
            !codes(&warnings).contains(&REINSTALL_REQUIRED),
            "{warnings:?}"
        );
        let fx = self::fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let store = fx
            .root
            .join(VLT_STORE_DIR)
            .join(REG)
            .join("node_modules/left-pad");
        std::fs::create_dir_all(&store).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&store, fx.root.join("node_modules/left-pad")).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&store, fx.root.join("node_modules/left-pad")).unwrap();
        let (_, warnings) = entry_of(run(&fx, UUID, false).await);
        let advisory: Vec<&VendorWarning> = warnings
            .iter()
            .filter(|w| w.code == REINSTALL_REQUIRED)
            .collect();
        assert_eq!(advisory.len(), 1, "{warnings:?}");
        assert_eq!(
            advisory[0].detail,
            "node_modules/left-pad still links left-pad@1.3.0 to its installed upstream copy; run \
             `vlt install` (or `vlt ci`) to link the vendored copy"
        );
    }

    fn link(target: &std::path::Path, link: &std::path::Path) {
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(target, link).unwrap();
    }

    fn store_copy(fx: &Fx) -> std::path::PathBuf {
        let store = fx
            .root
            .join(VLT_STORE_DIR)
            .join(REG)
            .join("node_modules/left-pad");
        std::fs::create_dir_all(&store).unwrap();
        store
    }

    const OPTIONAL_PKG: &str = "{\n  \"name\": \"root\",\n  \"dependencies\": {\n    \"a\": \"1.0.0\"\n  },\n  \"optionalDependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";

    fn optional_lock() -> String {
        render(
            1,
            &[
                r#""~npm~a@1.0.0": [0,"a","sha512-A=="]"#,
                REG_NODE,
                r#""~npm~z@1.0.0": [0,"z","sha512-Z=="]"#,
            ],
            &[
                r#""file~_d left-pad": "optional 1.3.0 ~npm~left-pad@1.3.0""#,
                r#""file~_d a": "prod 1.0.0 ~npm~a@1.0.0""#,
                r#""~npm~left-pad@1.3.0 z": "prod ^1.0.0 ~npm~z@1.0.0""#,
            ],
        )
    }

    #[tokio::test]
    async fn the_reinstall_advisory_follows_dry_runs_members_and_failed_patches() {
        let fx = fx(&optional_lock(), &[(PACKAGE_JSON, OPTIONAL_PKG)]).await;
        let VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        } = run(&fx, UUID, true).await
        else {
            panic!("dry run");
        };
        assert!(result.success);
        assert!(
            warnings.iter().any(|w| w.code == REINSTALL_REQUIRED
                && w.detail
                    .starts_with("left-pad@1.3.0 is an optional dependency")),
            "{warnings:?}"
        );
        assert_eq!(read(&fx, VLT_LOCK).await, optional_lock());
        assert_eq!(read(&fx, PACKAGE_JSON).await, OPTIONAL_PKG);
        assert!(!fx.root.join(".socket").exists());

        let fx = self::fx(&optional_lock(), &[(PACKAGE_JSON, OPTIONAL_PKG)]).await;
        tokio::fs::remove_file(fx.blobs.join(compute_git_sha256_from_bytes(PATCHED)))
            .await
            .unwrap();
        let VendorOutcome::Done {
            result, warnings, ..
        } = run(&fx, UUID, false).await
        else {
            panic!("failed patch");
        };
        assert!(!result.success, "{result:?}");
        assert!(
            !codes(&warnings).contains(&REINSTALL_REQUIRED),
            "{warnings:?}"
        );
        assert_eq!(read(&fx, VLT_LOCK).await, optional_lock());
        assert_eq!(read(&fx, PACKAGE_JSON).await, OPTIONAL_PKG);

        let lock = render(
            1,
            &[REG_NODE],
            &[r#""workspace~packages+a left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#],
        );
        let member_pkg =
            "{\n  \"name\": \"a\",\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";
        let fx = self::fx(&lock, &[("packages/a/package.json", member_pkg)]).await;
        link(
            &store_copy(&fx),
            &fx.root.join("packages/a/node_modules/left-pad"),
        );
        let (_, warnings) = entry_of(run(&fx, UUID, false).await);
        let advisory: Vec<&VendorWarning> = warnings
            .iter()
            .filter(|w| w.code == REINSTALL_REQUIRED)
            .collect();
        assert_eq!(advisory.len(), 1, "{warnings:?}");
        assert_eq!(
            advisory[0].detail,
            "packages/a/node_modules/left-pad still links left-pad@1.3.0 to its installed upstream \
             copy; run `vlt install` (or `vlt ci`) to link the vendored copy"
        );
    }

    #[tokio::test]
    async fn a_revert_asks_for_a_reinstall_while_a_link_or_an_optional_spec_moves_back() {
        let committed = |fx: &Fx| uuid_dir(fx, UUID).join("left-pad-1.3.0/node_modules/left-pad");

        let fx = fx(&optional_lock(), &[(PACKAGE_JSON, OPTIONAL_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success, "{out:?}");
        let advisory: Vec<&VendorWarning> = out
            .warnings
            .iter()
            .filter(|w| w.code == REINSTALL_REQUIRED)
            .collect();
        assert_eq!(advisory.len(), 1, "{out:?}");
        assert!(
            advisory[0].detail.starts_with(
                "left-pad@1.3.0 is an optional dependency: `vlt install` (vlt 0.0.0-30 and \
                 later) keeps node_modules linked to the vendored `file:` directory"
            ),
            "{}",
            advisory[0].detail
        );
        assert!(advisory[0].detail.contains("run `vlt ci`"));
        assert_eq!(read(&fx, VLT_LOCK).await, optional_lock());
        assert!(!uuid_dir(&fx, UUID).exists());

        let fx = self::fx(&optional_lock(), &[(PACKAGE_JSON, OPTIONAL_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        tokio::fs::write(fx.root.join(VLT_LOCK), optional_lock())
            .await
            .unwrap();
        tokio::fs::write(fx.root.join(PACKAGE_JSON), OPTIONAL_PKG)
            .await
            .unwrap();
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");

        let fx = self::fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");

        let fx = self::fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        link(&committed(&fx), &fx.root.join("node_modules/left-pad"));
        // The preview names the reinstall the real run will ask for.
        let dry = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(true)).await;
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(dry.success && out.success, "{dry:?} {out:?}");
        assert_eq!(dry.warnings, out.warnings);
        assert_eq!(
            out.warnings,
            vec![VendorWarning::new(
                REINSTALL_REQUIRED,
                "node_modules/left-pad still links left-pad@1.3.0 to its vendored copy; run `vlt \
                 install` (or `vlt ci`) to link the restored copy"
            )]
        );
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
        assert!(!uuid_dir(&fx, UUID).exists());
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
        assert!(
            warnings[0]
                .detail
                .contains("vlt 0.0.0-31 … 1.0.0-rc.5 install the vendored lock but fail"),
            "only the measured lockless-reinstall window fails: {}",
            warnings[0].detail
        );
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

    /// #372: vlt 1.3 sets the brotli bit (4) on nodes that resolved the
    /// registry's `.tar.br` alternate. Vendoring wires such a lock (the
    /// vendored directory is no Brotli tarball, so the wired node drops
    /// bit 4) and the revert puts the pristine brotli entry back.
    #[tokio::test]
    async fn a_vlt_1_3_brotli_lock_is_vendored_and_reverted_exactly() {
        let brotli = basic_lock()
            .replace("[0,\"a\",", "[6,\"a\",")
            .replace(
                "[0,\"left-pad\",\"sha512-REG==\",\"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\"]",
                "[4,\"left-pad\",\"sha512-REG==\",\"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tar.br\"]",
            );
        assert!(brotli.contains("[4,\"left-pad\""));
        let fx = fx(&brotli, &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad");
        let wired = read(&fx, VLT_LOCK).await;
        assert!(
            wired.contains(&format!("[0,\"left-pad\",null,\"{rel}\"]")),
            "{wired}"
        );
        assert!(wired.contains("[6,\"a\",\"sha512-A==\"]"), "{wired}");

        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(read(&fx, VLT_LOCK).await, brotli);
        assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG);
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
    async fn revert_drops_the_edges_vlt_added_from_the_vendored_node() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        persist(&fx, &entry).await;
        let lock = read(&fx, VLT_LOCK).await;
        let file_id = lock
            .lines()
            .find_map(|l| {
                l.trim_start()
                    .strip_prefix('"')
                    .and_then(|l| l.split_once("\": ["))
                    .map(|(id, _)| id.to_string())
                    .filter(|id| id.starts_with("file~.socket"))
            })
            .expect("the vendored file node");
        let insert_before = |text: &str, before: &str, line: String| {
            let at = text.find(before).expect(before);
            let at = text[..at].rfind('\n').unwrap() + 1;
            format!("{}    {line},\n{}", &text[..at], &text[at..])
        };
        let updated = insert_before(
            &lock,
            "\"~npm~z@1.0.0\": [",
            r#""~npm~escape-html@1.0.3": [0,"escape-html","sha512-E=="]"#.to_string(),
        );
        let updated = insert_before(
            &updated,
            &format!("\"{file_id} z\": "),
            format!(r#""{file_id} escape-html": "prod 1.0.3 ~npm~escape-html@1.0.3""#),
        );
        let updated = insert_before(
            &updated,
            &format!("\"{file_id} escape-html\": "),
            format!(r#""{file_id} a": "prod 1.0.0 ~npm~a@1.0.0""#),
        );
        tokio::fs::write(fx.root.join(VLT_LOCK), &updated)
            .await
            .unwrap();
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
    }

    #[tokio::test]
    async fn a_new_uuid_warns_about_links_into_the_replaced_dir() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (first, _) = entry_of(run(&fx, UUID, false).await);
        persist(&fx, &first).await;
        link(
            &fx.root.join(&first.artifact.path),
            &fx.root.join("node_modules/left-pad"),
        );
        let (_, warnings) = entry_of(run(&fx, UUID2, false).await);
        let advisory: Vec<&VendorWarning> = warnings
            .iter()
            .filter(|w| w.code == REINSTALL_REQUIRED)
            .collect();
        assert_eq!(advisory.len(), 1, "{warnings:?}");
        assert_eq!(
            advisory[0].detail,
            "node_modules/left-pad links left-pad@1.3.0 to the vendored dir of the patch this \
             one replaces, which is removed, so requiring it fails; run `vlt install` (or `vlt \
             ci`) to link the vendored copy"
        );
    }

    #[tokio::test]
    async fn uuid_metadata_is_restored_for_the_entry() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let gitignore = fx
            .root
            .join(format!(".socket/vendor/npm/{UUID}/.gitignore"));
        tokio::fs::remove_file(&gitignore).await.unwrap();
        crate::vendor::redownload::restore_npm_uuid_metadata(&entry, &fx.root)
            .await
            .unwrap();
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
            node_touch: Vec::new(),
            edge_touch: Vec::new(),
        };
        tokio::fs::remove_file(fx.root.join(VLT_LOCK))
            .await
            .unwrap();
        tokio::fs::create_dir_all(fx.root.join(VLT_LOCK).join("occupied"))
            .await
            .unwrap();
        let originals = BTreeMap::from([(PACKAGE_JSON.to_string(), ROOT_PKG.to_string())]);
        let err = commit(&fx.root, &wiring, Some("{}"), &originals)
            .await
            .unwrap_err();
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
        let outcome = crate::vendor::test_support::vendor_vlt(
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
                .any(|w| w.code == "vendor_dep_manifest_stale"
                    && w.detail.contains("run `vlt update` to re-resolve them")),
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

    /// #920: the `package.json` advisory is emitted once, by the run that
    /// wires — an in-sync re-run of a manifest-rewriting patch is a quiet
    /// AlreadyPatched.
    #[tokio::test]
    async fn manifest_rewriting_rerun_is_in_sync_without_the_manifest_warning() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let patched_pkg = b"{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"main\":\"i.js\"}";
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
        let vendor = || {
            crate::vendor::test_support::vendor_vlt(
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
        };
        let manifest_warnings = |w: &[VendorWarning]| {
            w.iter()
                .filter(|w| w.code.starts_with("vendor_dep_manifest"))
                .count()
        };
        let (entry, warnings) = entry_of(vendor().await);
        assert_eq!(manifest_warnings(&warnings), 1, "{warnings:?}");
        persist(&fx, &entry).await;

        let VendorOutcome::Done {
            result,
            entry,
            warnings,
        } = vendor().await
        else {
            panic!("expected Done");
        };
        assert!(result.success && entry.is_none(), "{:?}", result.error);
        assert_eq!(manifest_warnings(&warnings), 0, "{warnings:?}");
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
        let outcome = crate::vendor::test_support::vendor_vlt(
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
            "{\"scripts\":{\"postinstall\":\"node install.js\"}}",
        )
        .await
        .unwrap();
        let (code, detail) = vlt_vendor_preflight(&fx.root, PURL, UUID)
            .await
            .unwrap_err();
        assert_eq!(code, crate::vendor::npm_dir::BUILD_STEPS_UNSUPPORTED);
        assert!(detail.contains("a `postinstall` script"), "{detail}");
        for script in ["preprepare", "postprepare"] {
            tokio::fs::write(
                store.join(PACKAGE_JSON),
                format!("{{\"scripts\":{{\"{script}\":\"node build.js\"}}}}"),
            )
            .await
            .unwrap();
            let (code, detail) = vlt_vendor_preflight(&fx.root, PURL, UUID)
                .await
                .unwrap_err();
            assert_eq!(code, crate::vendor::npm_dir::BUILD_STEPS_UNSUPPORTED);
            assert!(detail.contains(&format!("a `{script}` script")), "{detail}");
        }
        tokio::fs::write(store.join(PACKAGE_JSON), "{}")
            .await
            .unwrap();
        tokio::fs::write(store.join("binding.gyp"), "{}")
            .await
            .unwrap();
        let (code, detail) = vlt_vendor_preflight(&fx.root, PURL, UUID)
            .await
            .unwrap_err();
        assert_eq!(code, crate::vendor::npm_dir::BUILD_STEPS_UNSUPPORTED);
        assert!(detail.contains("node-gyp"), "{detail}");
        tokio::fs::remove_file(store.join("binding.gyp"))
            .await
            .unwrap();
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

    #[cfg(unix)]
    #[tokio::test]
    async fn the_preflight_refuses_only_rules_the_uuid_gitignore_cannot_undo() {
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
        let ignore = fx.root.join(".gitignore");
        tokio::fs::write(&ignore, "*.json\n!package.json\n!vlt-lock.json\n")
            .await
            .unwrap();
        assert_eq!(vlt_vendor_preflight(&fx.root, PURL, UUID).await, Ok(()));
        for rule in [".socket/", ".socket/vendor/", "npm/", UUID] {
            tokio::fs::write(&ignore, format!("*.json\n{rule}\n"))
                .await
                .unwrap();
            let (code, detail) = vlt_vendor_preflight(&fx.root, PURL, UUID)
                .await
                .unwrap_err();
            assert_eq!(code, super::super::npm_dir::GITIGNORED, "{rule}");
            assert!(detail.contains(&format!(".gitignore:2:{rule}")), "{detail}");
            assert!(!detail.contains("*.json"), "{detail}");
        }
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
        crate::vendor::test_support::vendor_vlt(
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
        let cfg = service_cfg(&server.uri(), VendorSource::Service, false);
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
        match run_with(
            &fx,
            &service_cfg(&server.uri(), VendorSource::Service, false),
        )
        .await
        {
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
        warnings
            .iter()
            .filter(|w| w.code != "vendor_prebuilt_downloaded")
            .map(|w| w.code)
            .collect()
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

    // ── VBV-S3, VBV-D2, VBV-U1, VBV-D4 ───────────────────────────────────

    const MEMBER_LOCK_EDGE: &str =
        r#""workspace~packages+a left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#;
    const MEMBER_PKG: &str =
        "{\n  \"name\": \"a\",\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";

    /// REGRESSION (VBV-S3): a workspace directory that is a symbolic link
    /// leads out of the project, and vendoring rewrote the `package.json`
    /// it found there. Vendoring refuses such an importer before anything
    /// is staged (the download plan's gate too), and a revert leaves a
    /// record for one alone as drift, on a dry run as well.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlinked_workspace_directory_is_never_written_through() {
        let lock = render(1, &[REG_NODE], &[MEMBER_LOCK_EDGE]);
        let fx = self::fx(&lock, &[]).await;
        let outside = fx._tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join(PACKAGE_JSON), MEMBER_PKG).unwrap();
        std::fs::create_dir_all(fx.root.join("packages")).unwrap();
        std::os::unix::fs::symlink(&outside, fx.root.join("packages/a")).unwrap();
        for dry_run in [true, false] {
            let (code, detail) = refusal(run(&fx, UUID, dry_run).await);
            assert_eq!(code, UNSUPPORTED, "{detail}");
            assert!(
                detail.contains("symbolic link") && detail.contains("packages/a"),
                "{detail}"
            );
        }
        assert_eq!(
            preflight_packages(&fx.root, &[(PURL, &record(UUID))]).await,
            [Err(UNSUPPORTED)]
        );
        assert_eq!(
            std::fs::read_to_string(outside.join(PACKAGE_JSON)).unwrap(),
            MEMBER_PKG
        );
        assert_eq!(read(&fx, VLT_LOCK).await, lock);
        assert!(!fx.root.join(".socket").exists(), "nothing staged");

        // Vendored as a real directory, which then becomes a link.
        let fx = self::fx(&lock, &[("packages/a/package.json", MEMBER_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let vendored_pkg = read(&fx, "packages/a/package.json").await;
        let vendored_lock = read(&fx, VLT_LOCK).await;
        assert_ne!(vendored_pkg, MEMBER_PKG);
        let outside = fx._tmp.path().join("outside");
        std::fs::rename(fx.root.join("packages/a"), &outside).unwrap();
        std::os::unix::fs::symlink(&outside, fx.root.join("packages/a")).unwrap();
        for dry_run in [true, false] {
            let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(dry_run)).await;
            assert!(out.success && out.kept_artifact, "{out:?}");
            assert!(
                out.warnings
                    .iter()
                    .any(|w| w.code == "vendor_lock_entry_drifted"
                        && w.detail.contains("symbolic link")),
                "{out:?}"
            );
            assert_eq!(
                std::fs::read_to_string(outside.join(PACKAGE_JSON)).unwrap(),
                vendored_pkg
            );
            assert_eq!(read(&fx, VLT_LOCK).await, vendored_lock);
            assert!(fx.root.join(&entry.artifact.path).exists());
        }
    }

    /// The vendored `basic_lock` project after `packages/a` was pointed at
    /// the vendored copy too (its `package.json` line copied from the
    /// root's, then `vlt install`): an importer edge and a manifest spec
    /// the ledger has no record of. Returns the lock and the member spec.
    async fn late_importer(fx: &Fx, entry: &VendorEntry) -> (String, String) {
        let spec = importer_spec("packages/a", &entry.artifact.path);
        let vendored = read(fx, VLT_LOCK).await;
        let root_edge = vendored
            .lines()
            .find(|line| line.contains("\"file~_d left-pad\""))
            .unwrap();
        let member_edge = format!(
            "    \"workspace~packages+a left-pad\": \"prod {spec} {}\",",
            file_id()
        );
        let lock = vendored.replacen(root_edge, &format!("{root_edge}\n{member_edge}"), 1);
        assert_ne!(lock, vendored);
        tokio::fs::write(fx.root.join(VLT_LOCK), &lock)
            .await
            .unwrap();
        let pkg = MEMBER_PKG.replace("\"1.3.0\"", &json_string(&spec));
        tokio::fs::create_dir_all(fx.root.join("packages/a"))
            .await
            .unwrap();
        tokio::fs::write(fx.root.join("packages/a/package.json"), pkg)
            .await
            .unwrap();
        (lock, spec)
    }

    /// REGRESSION (VBV-D2): a workspace that came to depend on the vendored
    /// directory after vendoring has an edge to the vendored node and a
    /// `file:` spec the ledger never recorded. The revert used to restore
    /// the recorded surfaces and delete the directory, leaving that edge
    /// dangling and the spec pointing at nothing. It now leaves everything
    /// as it is, as drift naming the edge and the manifest.
    #[tokio::test]
    async fn a_revert_is_left_alone_while_an_unrecorded_importer_edge_reaches_the_node() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let root_pkg = read(&fx, PACKAGE_JSON).await;
        let (lock, _) = late_importer(&fx, &entry).await;
        let member_pkg = read(&fx, "packages/a/package.json").await;
        for dry_run in [true, false] {
            let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(dry_run)).await;
            assert!(out.success && out.kept_artifact, "{out:?}");
            let drift = out
                .warnings
                .iter()
                .find(|w| w.code == "vendor_lock_entry_drifted")
                .unwrap_or_else(|| panic!("{out:?}"));
            assert!(
                drift.detail.contains("`workspace~packages+a left-pad`")
                    && drift.detail.contains("packages/a/package.json"),
                "{}",
                drift.detail
            );
            assert_eq!(read(&fx, VLT_LOCK).await, lock);
            assert_eq!(read(&fx, PACKAGE_JSON).await, root_pkg);
            assert_eq!(read(&fx, "packages/a/package.json").await, member_pkg);
            assert!(fx.root.join(&entry.artifact.path).exists());
        }

        // The workspace goes back to the registry release: the revert ends.
        tokio::fs::write(
            fx.root.join(VLT_LOCK),
            lock.replace(
                &format!(
                    "{}\n",
                    lock.lines()
                        .find(|l| l.contains("workspace~packages+a"))
                        .unwrap()
                ),
                "",
            ),
        )
        .await
        .unwrap();
        tokio::fs::write(fx.root.join("packages/a/package.json"), MEMBER_PKG)
            .await
            .unwrap();
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && !out.kept_artifact, "{out:?}");
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
        assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG);
        assert!(!uuid_dir(&fx, UUID).exists());
    }

    /// VBV-D2, the manifest half: an importer's `package.json` that names
    /// the vendored directory with no lock edge behind it yet (the line was
    /// added, `vlt install` not run). The lock no longer needs the
    /// directory, so the recorded wiring is restored, but the artifact and
    /// the ledger entry stay, with `vendor_revert_residual_reference`
    /// naming the file, until the line is gone.
    #[tokio::test]
    async fn a_revert_keeps_the_artifact_while_an_importer_manifest_names_it() {
        let member_edge = r#""workspace~packages+a a": "prod 1.0.0 ~npm~a@1.0.0""#;
        let root_edge = "    \"file~_d left-pad\": \"prod 1.3.0 ~npm~left-pad@1.3.0\",\n";
        let lock = basic_lock().replacen(root_edge, &format!("{root_edge}    {member_edge},\n"), 1);
        assert_ne!(lock, basic_lock());
        let member = "{\n  \"name\": \"a\",\n  \"dependencies\": {\n    \"a\": \"1.0.0\"\n  }\n}\n";
        let fx = fx(
            &lock,
            &[
                (PACKAGE_JSON, ROOT_PKG),
                ("packages/a/package.json", member),
            ],
        )
        .await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let spec = importer_spec("packages/a", &entry.artifact.path);
        let naming = member.replace(
            "\"a\": \"1.0.0\"",
            &format!(
                "\"a\": \"1.0.0\",\n    \"left-pad\": {}",
                json_string(&spec)
            ),
        );
        tokio::fs::write(fx.root.join("packages/a/package.json"), &naming)
            .await
            .unwrap();
        let vendored_lock = read(&fx, VLT_LOCK).await;

        for dry_run in [true, false] {
            let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(dry_run)).await;
            assert!(out.success && out.kept_artifact, "{out:?}");
            assert!(out.kept_for_residual_reference(), "{out:?}");
            let reference = out
                .warnings
                .iter()
                .find(|w| w.code == crate::vendor::RESIDUAL_REFERENCE_CODE)
                .unwrap_or_else(|| panic!("{out:?}"));
            assert!(
                reference.detail.contains("packages/a/package.json"),
                "{}",
                reference.detail
            );
            assert_eq!(
                read(&fx, VLT_LOCK).await,
                if dry_run {
                    vendored_lock.clone()
                } else {
                    lock.clone()
                }
            );
            assert_eq!(read(&fx, "packages/a/package.json").await, naming);
            assert!(fx.root.join(&entry.artifact.path).exists());
        }
        assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG);

        tokio::fs::write(fx.root.join("packages/a/package.json"), member)
            .await
            .unwrap();
        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && !out.kept_artifact, "{out:?}");
        assert!(!uuid_dir(&fx, UUID).exists());
    }

    /// VBV-D2: what blocks the restore is a reference to this entry's own
    /// node. Another package's vendored directory under the same uuid is
    /// not one: this entry's wiring is restored, and only the directory
    /// they share is kept, until that package is reverted too.
    #[tokio::test]
    async fn another_directory_under_the_uuid_keeps_it_without_blocking_the_restore() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let other = format!("file~.socket+vendor+npm+{UUID}+a-1.0.0+node__modules+a");
        let vendored = read(&fx, VLT_LOCK).await;
        let shared = vendored
            .replace(
                r#""~npm~a@1.0.0": [0,"a","sha512-A=="]"#,
                &format!(r#""{other}": [0,"a"]"#),
            )
            .replace(
                r#""file~_d a": "prod 1.0.0 ~npm~a@1.0.0""#,
                &format!(
                    r#""file~_d a": "prod file:./.socket/vendor/npm/{UUID}/a-1.0.0/node_modules/a {other}""#
                ),
            );
        assert_eq!(shared.matches(&other).count(), 2);
        tokio::fs::write(fx.root.join(VLT_LOCK), &shared)
            .await
            .unwrap();

        let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(false)).await;
        assert!(out.success && out.kept_artifact, "{out:?}");
        assert!(out.kept_for_residual_reference(), "{out:?}");
        assert!(
            out.warnings
                .iter()
                .any(|w| w.detail.contains("`file~_d a`")),
            "{out:?}"
        );
        let lock = read(&fx, VLT_LOCK).await;
        assert!(
            lock.contains(REG_NODE) && !lock.contains(&file_id()),
            "{lock}"
        );
        assert_eq!(lock.matches(&other).count(), 2, "{lock}");
        assert_eq!(read(&fx, PACKAGE_JSON).await, ROOT_PKG);
        assert!(uuid_dir(&fx, UUID).exists());
    }

    /// REGRESSION (VBV-U1): `vendor --revert --dry-run` returned before it
    /// read the lock, so it promised a revert the real run then kept as
    /// drift. The dry run replays the same records and reports the same
    /// keep, and the same failure for a lock it cannot edit, writing
    /// nothing.
    #[tokio::test]
    async fn a_dry_run_revert_reports_what_the_real_one_would_keep() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let vendored = read(&fx, VLT_LOCK).await;
        // The importer edge changed since vendoring.
        let drifted = vendored.replacen("\"prod file:./", "\"dev file:./", 1);
        assert_ne!(drifted, vendored);
        tokio::fs::write(fx.root.join(VLT_LOCK), &drifted)
            .await
            .unwrap();
        let pkg = read(&fx, PACKAGE_JSON).await;
        let mut outcomes = Vec::new();
        for dry_run in [true, false] {
            let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(dry_run)).await;
            assert!(
                out.success && out.kept_artifact,
                "dry run {dry_run}: {out:?}"
            );
            assert!(out.drift_skipped(), "dry run {dry_run}: {out:?}");
            assert_eq!(read(&fx, VLT_LOCK).await, drifted);
            assert_eq!(read(&fx, PACKAGE_JSON).await, pkg);
            assert!(fx.root.join(&entry.artifact.path).exists());
            outcomes.push(out.warnings);
        }
        assert_eq!(outcomes[0], outcomes[1], "the preview is the real verdict");

        tokio::fs::write(fx.root.join(VLT_LOCK), "{ not a lock")
            .await
            .unwrap();
        for dry_run in [true, false] {
            let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(dry_run)).await;
            assert!(!out.success, "dry run {dry_run}: {out:?}");
            assert!(fx.root.join(&entry.artifact.path).exists());
        }
    }

    /// REGRESSION (VBV-D4): the section a line edit targets was found by
    /// the shape of its lines and tied to the parsed lock by its entry
    /// count alone. A `nodes` member nested in `options`, written at the
    /// top level's indent ahead of the real one, was edited in its place:
    /// "Vendored 1 package", with the node every reader installs
    /// untouched. Such a lock is refused before any write, by the
    /// vendoring, its gate and the revert alike.
    #[tokio::test]
    async fn a_nested_member_shaped_like_a_section_is_not_edited_in_its_place() {
        let honest = render(
            1,
            &[REG_NODE],
            &[r#""file~_d left-pad": "prod 1.3.0 ~npm~left-pad@1.3.0""#],
        );
        let decoy = |lock: &str| {
            let with = lock.replacen(
                "  \"options\": {},\n",
                "  \"options\": {\n  \"nodes\": {\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-DECOY==\"]\n  }\n  },\n",
                1,
            );
            assert_ne!(with, lock);
            assert!(serde_json::from_str::<Value>(&with).is_ok());
            with
        };
        let pkg = "{\n  \"name\": \"root\",\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";
        let lock = decoy(&honest);
        for dry_run in [true, false] {
            let fx = fx(&lock, &[(PACKAGE_JSON, pkg)]).await;
            let (code, detail) = refusal(run(&fx, UUID, dry_run).await);
            assert_eq!(code, "vendor_lockfile_version_unsupported", "{detail}");
            assert_eq!(detail, NOT_CANONICAL);
            assert_eq!(
                preflight_packages(&fx.root, &[(PURL, &record(UUID))]).await,
                [Err("vendor_lockfile_version_unsupported")]
            );
            assert_eq!(read(&fx, VLT_LOCK).await, lock);
            assert_eq!(read(&fx, PACKAGE_JSON).await, pkg);
            assert!(!fx.root.join(".socket").exists());
        }

        // The same member appears in a lock that was vendored honestly.
        let fx = fx(&honest, &[(PACKAGE_JSON, pkg)]).await;
        let (entry, _) = entry_of(run(&fx, UUID, false).await);
        let vendored = decoy(&read(&fx, VLT_LOCK).await);
        tokio::fs::write(fx.root.join(VLT_LOCK), &vendored)
            .await
            .unwrap();
        for dry_run in [true, false] {
            let out = revert_vlt_opts(&entry, &fx.root, RevertOpts::new(dry_run)).await;
            assert!(!out.success, "{out:?}");
            assert_eq!(out.error.as_deref(), Some(NOT_CANONICAL));
            assert_eq!(read(&fx, VLT_LOCK).await, vendored);
            assert!(fx.root.join(&entry.artifact.path).exists());
        }
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
        assert_eq!(
            codes(&warnings),
            [REINSTALL_REQUIRED, "vendor_artifact_rebuilt"]
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.code == REINSTALL_REQUIRED && w.detail.contains("run `vlt ci`")),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .filter(|w| w.code == "vendor_artifact_rebuilt")
                .all(|w| !w.detail.contains("vlt install")),
            "{warnings:?}"
        );
        assert!(!links.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn repair_moves_vlt_links_back_from_the_set_aside_dir() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (first, _) = entry_of(run(&fx, UUID, false).await);
        persist(&fx, &first).await;
        let live = uuid_dir(&fx, UUID);
        let kept = live.with_file_name(format!("{UUID}.pre-rebuild"));
        let within = first
            .artifact
            .path
            .strip_prefix(&format!(".socket/vendor/npm/{UUID}/"))
            .unwrap()
            .to_string();
        let target = "../../../../../../../../node_modules/.vlt/z";
        let plant = |planted: bool| {
            let links = kept.join(&within).join("node_modules");
            std::fs::create_dir_all(links.join(".bin")).unwrap();
            std::os::unix::fs::symlink(target, links.join("z")).unwrap();
            if planted {
                std::fs::write(links.join("planted.js"), b"x").unwrap();
            }
        };

        plant(false);
        assert_eq!(keep_vlt_links(&first, &kept, &fx.root).await, None);
        let live_links = fx.root.join(&first.artifact.path).join("node_modules");
        assert_eq!(
            std::fs::read_link(live_links.join("z")).unwrap(),
            std::path::Path::new(target)
        );
        assert!(!kept.join(&within).join("node_modules").exists());

        std::fs::remove_dir_all(&live_links).unwrap();
        plant(true);
        let warning = keep_vlt_links(&first, &kept, &fx.root).await.unwrap();
        assert_eq!(warning.code, REINSTALL_REQUIRED);
        assert!(
            warning.detail.contains("run `vlt ci`"),
            "the planted-link advisory names `vlt ci`"
        );
        assert!(!live_links.exists());

        std::fs::remove_dir_all(&kept).unwrap();
        assert_eq!(keep_vlt_links(&first, &kept, &fx.root).await, None);
        let mut npm = first.clone();
        npm.flavor = None;
        plant(false);
        assert_eq!(keep_vlt_links(&npm, &kept, &fx.root).await, None);
    }

    #[tokio::test]
    async fn a_dir_vendored_with_a_postprepare_script_refuses_on_reuse() {
        // An earlier release vendored a postprepare-only package (#1633);
        // the installed copy here has no script, so only the reuse check
        // can refuse.
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        let (mut first, _) = entry_of(run(&fx, UUID, false).await);
        let dir = fx.root.join(&first.artifact.path);
        tokio::fs::write(
            dir.join(PACKAGE_JSON),
            "{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"scripts\":{\"postprepare\":\"node build.js\"}}",
        )
        .await
        .unwrap();
        first.artifact.file_inventory = Some(
            crate::vendor::verify::compute_package_dir_inventory(&dir)
                .await
                .unwrap(),
        );
        persist(&fx, &first).await;
        let lock = read(&fx, VLT_LOCK).await;
        for dry_run in [true, false] {
            let (code, detail) = refusal(run(&fx, UUID, dry_run).await);
            assert_eq!(code, crate::vendor::npm_dir::BUILD_STEPS_UNSUPPORTED);
            assert!(detail.contains("a `postprepare` script"), "{detail}");
            assert_eq!(read(&fx, VLT_LOCK).await, lock);
            assert!(dir.join(PACKAGE_JSON).exists());
        }
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
    async fn a_package_vlt_would_build_in_place_refuses_on_the_local_build() {
        let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
        tokio::fs::write(
            fx.installed.join(PACKAGE_JSON),
            "{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"scripts\":{\"install\":\"node-gyp rebuild\"}}",
        )
        .await
        .unwrap();
        let (code, detail) = refusal(run(&fx, UUID, false).await);
        assert_eq!(code, crate::vendor::npm_dir::BUILD_STEPS_UNSUPPORTED);
        assert!(detail.ends_with("use --mode hosted"), "{detail}");
        assert!(!fx.root.join(".socket").exists());
        assert_eq!(read(&fx, VLT_LOCK).await, basic_lock());
    }

    #[tokio::test]
    async fn a_prepare_family_only_package_refuses_on_the_local_build() {
        // vlt runs `preprepare` and `postprepare` for a `file:` directory
        // even with no `prepare` beside them, rewriting the artifact (#1633).
        for script in ["preprepare", "postprepare"] {
            let fx = fx(&basic_lock(), &[(PACKAGE_JSON, ROOT_PKG)]).await;
            tokio::fs::write(
                fx.installed.join(PACKAGE_JSON),
                format!(
                    "{{\"name\":\"left-pad\",\"version\":\"1.3.0\",\"scripts\":{{\"{script}\":\"node build.js\"}}}}"
                ),
            )
            .await
            .unwrap();
            let (code, detail) = refusal(run(&fx, UUID, false).await);
            assert_eq!(
                code,
                crate::vendor::npm_dir::BUILD_STEPS_UNSUPPORTED,
                "{script}"
            );
            assert!(detail.contains(&format!("a `{script}` script")), "{detail}");
            assert!(!fx.root.join(".socket").exists(), "{script}");
            assert_eq!(read(&fx, VLT_LOCK).await, basic_lock(), "{script}");
        }
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
        let cfg = service_cfg(&server.uri(), VendorSource::Service, false);
        let (entry, warnings) = entry_of(run_with(&fx, &cfg).await);
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_prebuilt_downloaded"),
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
        let cfg = service_cfg(&server.uri(), VendorSource::Service, false);
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
