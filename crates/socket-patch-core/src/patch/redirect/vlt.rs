//! vlt `vlt-lock.json` hosted rewriter, the byte-for-byte twin of the TS
//! `registry-rewrite/vlt.ts`.
//!
//! A default-registry node keeps its DepID and has only slot [2] (the
//! patched sha512) and slot [3] (the hosted URL) spliced into its one-line
//! tuple; nothing else in the lock changes. The ledger records entry text
//! (`"<DepID>": <tuple>`, no indent, comma or `\r`), because vlt moves
//! commas and re-lays flags and trailing slots on later saves, so the
//! revert ([`revert_vlt_slots`]) works slot by slot.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value};

use super::{full_name, DepOverride, FileEdit, RewriteResult, RewriteWarning};
use crate::constants::npm_family::{BUN_LOCKB, VLT_CONFIG, VLT_HIDDEN_LOCK_REL, VLT_LOCK};
use crate::formats::governing_locks::{npm_locks_outside, NpmLockFamily};
use crate::vendor::vlt_lock_text::{
    brotli_for_slot3, entry_text, has_brotli_flag, installs_outside_registry, is_default_registry,
    is_registry_url_segment, nodes_block, parse_node_line, parse_vendored_path, render_entry_line,
    render_tuple_with_slots, sniff_lock, split_dep_id, split_lines, DepId, DepIdKind, LockSniff,
    ParsedLock, SectionSpan,
};

/// The ledger kind of a hosted vlt node splice.
pub const KIND: &str = "redirect_vlt_lock_node";

/// The other npm-family locks present, in the shared precedence order
/// ([`npm_locks_outside`]). `bun_lockb_present` reports a `bun.lockb` on
/// disk, which a caller holding its bytes keeps out of `files`.
fn sibling_locks(files: &BTreeMap<String, String>, bun_lockb_present: bool) -> Vec<&'static str> {
    npm_locks_outside(NpmLockFamily::Vlt, |lock| {
        files.contains_key(lock) || (lock == BUN_LOCKB && bun_lockb_present)
    })
}

/// Does vlt drive hosted confirmation and the artifact preflight?
/// `vlt-lock.json` must be present, and either vlt's install state (the
/// `node_modules/.vlt-lock.json` sentinel) is too, or no other npm-family
/// lock is (`bun_lockb_present`: see [`sibling_locks`]). Otherwise both
/// locks are rewritten and neither decides alone.
pub fn vlt_drives(files: &BTreeMap<String, String>, bun_lockb_present: bool) -> bool {
    files.contains_key(VLT_LOCK)
        && (files.contains_key(VLT_HIDDEN_LOCK_REL)
            || sibling_locks(files, bun_lockb_present).is_empty())
}

fn lock_unsupported(detail: &str) -> RewriteWarning {
    RewriteWarning {
        code: "redirect_vlt_lock_unsupported".into(),
        detail: format!(
            "vlt-lock.json {detail}; re-save it with a current vlt (`vlt install`) or update \
             socket-patch"
        ),
    }
}

/// A lock that passed the lock-level parse, with its nodes section located
/// and its node ids split once.
pub(super) struct HostedLock {
    parsed: ParsedLock,
    nodes: Option<SectionSpan>,
    index: NodeIndex,
}

/// A node whose id splits.
struct IndexedNode {
    id: String,
    dep_id: DepId,
}

/// The lock's nodes with their ids split once per scan rather than once per
/// override (#1570). Positions point into `nodes`, which keeps the lock's
/// key order; a node whose id does not split is left out, as it matches no
/// override.
#[derive(Default)]
struct NodeIndex {
    nodes: Vec<IndexedNode>,
    /// Registry nodes by `(name, version)`, from any registry segment.
    registry: HashMap<(String, String), Vec<usize>>,
    /// Git, file and remote nodes by slot [1].
    non_registry: HashMap<String, Vec<usize>>,
}

impl NodeIndex {
    fn new(nodes: Option<&Map<String, Value>>) -> Self {
        let mut index = NodeIndex::default();
        for (id, tuple) in nodes.into_iter().flatten() {
            let Some(dep_id) = split_dep_id(id) else {
                continue;
            };
            let at = index.nodes.len();
            match dep_id.kind {
                DepIdKind::Registry => {
                    if let Some((name, version)) = dep_id.registry_identity() {
                        let key = (name.to_string(), version.to_string());
                        index.registry.entry(key).or_default().push(at);
                    }
                }
                DepIdKind::Git | DepIdKind::File | DepIdKind::Remote => {
                    if let Some(slot1) = tuple.get(1).and_then(Value::as_str) {
                        let entry = index.non_registry.entry(slot1.to_string());
                        entry.or_default().push(at);
                    }
                }
                DepIdKind::Workspace => {}
            }
            index.nodes.push(IndexedNode {
                id: id.clone(),
                dep_id,
            });
        }
        index
    }

    fn at<'a>(&'a self, map: Option<&'a Vec<usize>>) -> impl Iterator<Item = &'a IndexedNode> {
        map.into_iter().flatten().map(|&i| &self.nodes[i])
    }

    fn registry(&self, name: &str, version: &str) -> impl Iterator<Item = &IndexedNode> {
        self.at(self.registry.get(&(name.to_string(), version.to_string())))
    }

    /// The git, file and remote nodes whose slot [1] is `name`.
    fn non_registry(&self, name: &str) -> impl Iterator<Item = &IndexedNode> {
        self.at(self.non_registry.get(name))
    }
}

pub(super) fn parse_hosted_lock(text: &str) -> Result<HostedLock, RewriteWarning> {
    let parsed = match sniff_lock(text) {
        LockSniff::Readable(parsed) => parsed,
        LockSniff::Bom => {
            return Err(lock_unsupported(
                "starts with a UTF-8 BOM, which vlt cannot read",
            ))
        }
        LockSniff::NotJsonObject => return Err(lock_unsupported("is not a JSON object")),
        LockSniff::UnsupportedVersion(raw) => {
            return Err(lock_unsupported(&format!("has lockfileVersion {raw}")))
        }
    };
    let lines = split_lines(text);
    let nodes = nodes_block(&lines);
    let one_node_per_line = nodes.is_some_and(|span| {
        matches!(span, SectionSpan::Inline { .. })
            || span
                .entry_lines()
                .any(|i| parse_node_line(lines[i]).is_some())
    });
    if !one_node_per_line && parsed.nodes().is_some_and(|n| !n.is_empty()) {
        return Err(lock_unsupported(
            "nodes section is not in vlt's canonical layout",
        ));
    }
    let index = NodeIndex::new(parsed.nodes());
    Ok(HostedLock {
        parsed,
        nodes,
        index,
    })
}

/// The default-registry and the foreign registry node ids of
/// `name@version`, in the lock's key order.
fn partition_instances<'a>(
    lock: &'a HostedLock,
    name: &str,
    version: &str,
) -> (Vec<&'a str>, Vec<&'a str>) {
    let options = lock.parsed.options();
    let mut defaults = Vec::new();
    let mut foreign = Vec::new();
    for node in lock.index.registry(name, version) {
        if is_default_registry(&node.dep_id.first, options) {
            defaults.push(node.id.as_str());
        } else {
            foreign.push(node.id.as_str());
        }
    }
    (defaults, foreign)
}

/// The git, remote and local-directory node ids that also install
/// `name@version`, in the lock's key order.
fn outside_instances<'a>(lock: &'a HostedLock, name: &str, version: &str) -> Vec<&'a str> {
    // `non_registry(name)` holds only nodes whose slot [1] is `name`.
    lock.index
        .non_registry(name)
        .filter(|node| installs_outside_registry(&node.dep_id, name, name, version))
        .map(|node| node.id.as_str())
        .collect()
}

/// The default-registry node ids of `dep` in a lock that passed the
/// lock-level parse.
pub(super) fn default_instances<'a>(lock: &'a HostedLock, dep: &DepOverride) -> Vec<&'a str> {
    partition_instances(lock, &full_name(dep), &dep.version).0
}

/// Does `dep` have a node of socket-patch's vendored vlt shape in a
/// lock that passed the lock-level parse?
pub(super) fn has_vendored_instance(lock: &HostedLock, dep: &DepOverride) -> bool {
    has_vendored_node(lock, &full_name(dep), &dep.version)
}

/// The lock-level warnings that say vlt may discard the lock's pins:
/// neither in-run nor standalone VEX attests a hosted pin of such a lock
/// from the lock alone.
pub const DISCARDING_LOCK_CODES: [&str; 3] = [
    VERSION_MISSING,
    OLD_LOCKFILE_IGNORED,
    SCALAR_REGISTRY_IGNORED,
];

const VERSION_MISSING: &str = "redirect_vlt_lockfile_version_missing";
const OLD_LOCKFILE_IGNORED: &str = "redirect_vlt_old_lockfile_ignored";
const SCALAR_REGISTRY_IGNORED: &str = "redirect_vlt_scalar_registry_ignored";

fn is_old_lockfile_ignored<'a>(
    version: Option<u64>,
    options: Option<&Map<String, Value>>,
    mut ids: impl Iterator<Item = &'a DepId>,
    vlt_config: Option<&str>,
) -> bool {
    if version == Some(1) {
        return false;
    }
    let has_legacy_default = ids.any(|dep_id| {
        dep_id.kind == DepIdKind::Registry
            && (dep_id.first.is_empty() || is_registry_url_segment(&dep_id.first, options))
    });
    let declares_modifiers = vlt_config.is_some_and(|text| {
        serde_json::from_str::<Value>(crate::formats::text::strip_bom(text))
            .ok()
            .and_then(|v| v.as_object().map(|o| o.contains_key("modifiers")))
            .unwrap_or(false)
    });
    has_legacy_default && !declares_modifiers
}

fn is_scalar_registry_ignored(version: Option<u64>, options: Option<&Map<String, Value>>) -> bool {
    let scalar = options
        .and_then(|o| o.get("registry"))
        .is_some_and(Value::is_string);
    let registries_npm = options
        .and_then(|o| o.get("registries"))
        .and_then(|r| r.get("npm"))
        .is_some_and(Value::is_string);
    scalar && (version != Some(1) || !registries_npm)
}

/// Which of [`DISCARDING_LOCK_CODES`] hold, in that order, for a lock of
/// `version` and `options` whose node ids are `ids`, given `vlt.json`'s
/// text.
pub(crate) fn discarding_lock_codes<'a>(
    version: Option<u64>,
    options: Option<&Map<String, Value>>,
    ids: impl Iterator<Item = &'a DepId>,
    vlt_config: Option<&str>,
) -> Vec<&'static str> {
    let mut codes = Vec::new();
    if version.is_none() {
        codes.push(VERSION_MISSING);
    }
    if is_old_lockfile_ignored(version, options, ids, vlt_config) {
        codes.push(OLD_LOCKFILE_IGNORED);
    }
    if is_scalar_registry_ignored(version, options) {
        codes.push(SCALAR_REGISTRY_IGNORED);
    }
    codes
}

/// Why vlt may discard the lock, for one of [`DISCARDING_LOCK_CODES`].
pub(crate) fn discarding_lock_detail(code: &str) -> &'static str {
    match code {
        VERSION_MISSING => {
            "vlt-lock.json has no lockfileVersion; vlt ≥ 1.0.0-rc.15 silently re-resolves it on \
             `vlt install` (and `vlt ci` fails); re-lock with a current vlt"
        }
        OLD_LOCKFILE_IGNORED => {
            "vlt 0.0.0-16 … 0.0.0-24 ignore vlt-lock.json unless vlt.json declares \
             \"modifiers\": {}; upgrade vlt or add \"modifiers\": {} to vlt.json"
        }
        _ => {
            "vlt 1.0.0-rc.7 … rc.29 ignore vlt-lock.json when a scalar `registry` is configured; \
             upgrade vlt to ≥ 1.0.0-rc.30"
        }
    }
}

fn lock_level_warnings(
    lock: &HostedLock,
    files: &BTreeMap<String, String>,
    bun_lockb_present: bool,
) -> Vec<RewriteWarning> {
    let mut warnings: Vec<RewriteWarning> = discarding_lock_codes(
        lock.parsed.version,
        lock.parsed.options(),
        lock.index.nodes.iter().map(|node| &node.dep_id),
        files.get(VLT_CONFIG).map(String::as_str),
    )
    .into_iter()
    .map(|code| RewriteWarning {
        code: code.into(),
        detail: discarding_lock_detail(code).into(),
    })
    .collect();
    if !vlt_drives(files, bun_lockb_present) {
        let others = sibling_locks(files, bun_lockb_present);
        warnings.push(RewriteWarning {
            code: "redirect_vlt_sibling_lockfiles".into(),
            detail: format!(
                "vlt-lock.json and {} are both present; socket-patch rewrote both — delete the \
                 lock your installs do not use",
                others.join(", ")
            ),
        });
    }
    warnings
}

fn npm_purl(name: &str, version: &str) -> String {
    format!("pkg:npm/{}@{version}", name.replacen('@', "%40", 1))
}

/// A `file` node of socket-patch's vendored vlt shape for `name@version`.
fn has_vendored_node(lock: &HostedLock, name: &str, version: &str) -> bool {
    lock.index.non_registry(name).any(|node| {
        node.dep_id.kind == DepIdKind::File
            && parse_vendored_path(&node.dep_id.first, name).is_some_and(|p| p.version == version)
    })
}

/// The ledger key of an instance: `<name>@<version>`, plus `~` and the raw
/// extra segment for a peer or modifier variant, in either era.
fn ledger_key(name: &str, version: &str, extra: Option<&str>) -> String {
    match extra {
        Some(extra) => format!("{name}@{version}~{extra}"),
        None => format!("{name}@{version}"),
    }
}

/// The one nodes-section line index keyed `id` that parses under the node
/// grammar with slot [1] naming `name`; `None` when there are zero or
/// several lines with that key, or the one line is outside the grammar.
fn instance_line(
    lines: &[String],
    span: Option<SectionSpan>,
    id: &str,
    name: &str,
) -> Option<usize> {
    let span = span?;
    let prefix = format!("    \"{id}\": ");
    let mut found = span
        .entry_lines()
        .filter(|&i| lines[i].starts_with(prefix.as_str()));
    let idx = found.next()?;
    if found.next().is_some() {
        return None;
    }
    let line = parse_node_line(&lines[idx])?;
    (line.entry.key == id && line.entry.name().as_deref() == Some(name)).then_some(idx)
}

/// The residual gate: re-parsed, every instance carries the patched slots.
/// `text` must be a lock [`parse_hosted_lock`] read, with only node lines
/// re-rendered (see [`parse_nodes_of`]).
fn every_instance_pinned(text: &str, ids: &[&str], sha512: &str, url: &str) -> bool {
    parse_nodes_of(text, ids).is_some_and(|nodes| instances_pinned(&nodes, ids, sha512, url))
}

/// The nodes of `ids` in `text`'s `nodes` object, as `serde_json::Value`
/// would read them (the last `nodes` and the last duplicate key win).
/// The whole document is still parsed, so broken JSON anywhere is refused,
/// but every other value is skipped instead of built: the gate runs once
/// per override, and building a 1500-node lock each time was most of a
/// hosted vlt scan (#1570). Skipping does not range-check numbers or pair
/// `\u` surrogates; the text it reads is a lock `sniff_lock` already read
/// whole, with only node lines re-rendered. `None` when `text` is not a
/// JSON object or its `nodes` is not an object.
fn parse_nodes_of(text: &str, ids: &[&str]) -> Option<Map<String, Value>> {
    use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
    use std::fmt;

    struct Lock<'a>(&'a [&'a str]);
    struct Nodes<'a>(&'a [&'a str]);

    impl<'de> Visitor<'de> for Lock<'_> {
        type Value = Option<Map<String, Value>>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut nodes = None;
            while let Some(key) = map.next_key::<String>()? {
                if key == "nodes" {
                    nodes = map.next_value_seed(Nodes(self.0))?;
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(nodes)
        }
    }

    impl<'de> DeserializeSeed<'de> for Nodes<'_> {
        type Value = Option<Map<String, Value>>;

        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
            d.deserialize_any(self)
        }
    }

    impl<'de> Visitor<'de> for Nodes<'_> {
        type Value = Option<Map<String, Value>>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("any JSON value")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut nodes = Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if self.0.contains(&key.as_str()) {
                    nodes.insert(key, map.next_value::<Value>()?);
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(Some(nodes))
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(None)
        }

        fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
    }

    let mut de = serde_json::Deserializer::from_str(text);
    let nodes = serde::Deserializer::deserialize_map(&mut de, Lock(ids)).ok()?;
    de.end().ok()?;
    nodes
}

/// Does every node of `ids` carry the patched sha512 and URL?
fn instances_pinned(nodes: &Map<String, Value>, ids: &[&str], sha512: &str, url: &str) -> bool {
    ids.iter().all(|id| {
        let tuple = nodes.get(*id).and_then(Value::as_array);
        tuple.is_some_and(|t| {
            t.get(2).and_then(Value::as_str) == Some(sha512)
                && t.get(3).and_then(Value::as_str) == Some(url)
        })
    })
}

/// Did an earlier run pin every one of `ids`? Reads the lock as parsed,
/// not its text again.
pub(super) fn already_pinned(lock: &HostedLock, ids: &[&str], sha512: &str, url: &str) -> bool {
    lock.parsed
        .nodes()
        .is_some_and(|nodes| instances_pinned(nodes, ids, sha512, url))
}

struct Splice {
    line: usize,
    text: String,
    edit: FileEdit,
}

fn unsupported_key(result: &mut RewriteResult, dep: &DepOverride, id: &str) {
    result.warnings.push(RewriteWarning {
        code: "redirect_vlt_unsupported_lock_key".into(),
        detail: format!(
            "vlt-lock.json entry {id} cannot be rewritten safely; re-save the lock with `vlt \
             install`"
        ),
    });
    result.refused_vlt_uuids.insert(dep.patch_uuid.clone());
}

/// Rewrite one override's default-registry instances, or none of them.
/// Returns whether any line changed.
fn rewrite_dep(
    lock: &HostedLock,
    lines: &mut [String],
    dep: &DepOverride,
    result: &mut RewriteResult,
) -> bool {
    let name = full_name(dep);
    let version = dep.version.as_str();

    let (defaults, foreign) = partition_instances(lock, &name, version);
    if !foreign.is_empty() {
        result.vlt_foreign_uuids.insert(dep.patch_uuid.clone());
        result.warnings.push(RewriteWarning {
            code: "redirect_vlt_custom_registry_skipped".into(),
            detail: format!(
                "hosted mode only redirects packages from vlt's default registry; {} left \
                 unchanged (use --mode vendored or agent mode)",
                foreign.join(", ")
            ),
        });
    }
    let outside = outside_instances(lock, &name, version);
    if !outside.is_empty() {
        result.vlt_foreign_uuids.insert(dep.patch_uuid.clone());
        result.warnings.push(RewriteWarning {
            code: "redirect_vlt_custom_registry_skipped".into(),
            detail: format!(
                "hosted mode only redirects registry packages; {} also install {name} from git, \
                 a remote tarball or a local directory and stay unpatched (use agent mode)",
                outside.join(", ")
            ),
        });
    }
    let Some(sha512) = dep.integrity.sha512.as_deref().filter(|s| !s.is_empty()) else {
        result.warnings.push(RewriteWarning {
            code: "redirect_vlt_missing_sha512".into(),
            detail: format!(
                "hosted artifact for {} has no sha512 integrity; retry later",
                npm_purl(&name, version)
            ),
        });
        result.refused_vlt_uuids.insert(dep.patch_uuid.clone());
        return false;
    };
    if defaults.is_empty() {
        let warning = if has_vendored_node(lock, &name, version) {
            RewriteWarning {
                code: "redirect_vlt_entry_vendored".into(),
                detail: format!(
                    "{name}@{version} is vendored; re-run `socket-patch scan --mode hosted` from \
                     a ledger that owns it, or `socket-patch vendor --revert`"
                ),
            }
        } else {
            RewriteWarning {
                code: "redirect_vlt_entry_not_found".into(),
                detail: format!(
                    "vlt-lock.json has no default-registry entry for {name}@{version}; run `vlt \
                     install` first"
                ),
            }
        };
        result.warnings.push(warning);
        return false;
    }

    let mut located: Vec<(usize, &str)> = Vec::new();
    for id in &defaults {
        match instance_line(lines, lock.nodes, id, &name) {
            Some(idx) => located.push((idx, id)),
            None => {
                unsupported_key(result, dep, id);
                return false;
            }
        }
    }
    located.sort_unstable();

    let s2 = serde_json::to_string(sha512).expect("a str serializes to JSON infallibly");
    let s3 = serde_json::to_string(&dep.artifact_url).expect("a str serializes to JSON infallibly");
    let mut splices: Vec<Splice> = Vec::new();
    for &(idx, id) in &located {
        let line = parse_node_line(&lines[idx]).expect("instance_line parsed this line");
        let elems = &line.entry.elems;
        // The hosted artifact is a `.tgz`, so a node that resolved vlt
        // 1.3's `.tar.br` alternate drops the brotli bit with its URL, as
        // `vlt install` would save it (#372).
        let brotli = brotli_for_slot3(Some(&s3));
        if elems.len() >= 4
            && elems[2] == s2
            && elems[3] == s3
            && has_brotli_flag(elems[0]) == brotli
        {
            continue;
        }
        let tuple = render_tuple_with_slots(elems, brotli, Some(&s2), Some(&s3));
        let new_text = entry_text(id, &tuple);
        let extra = split_dep_id(id).and_then(|dep_id| dep_id.extra);
        splices.push(Splice {
            line: idx,
            text: render_entry_line(&new_text, line.comma, line.cr),
            edit: FileEdit {
                path: VLT_LOCK.into(),
                kind: KIND.into(),
                action: "rewritten".into(),
                key: Some(ledger_key(&name, version, extra.as_deref())),
                original: Some(Value::String(line.entry.entry_text())),
                new: Some(Value::String(new_text)),
            },
        });
    }

    let mut candidate: Vec<String> = lines.to_vec();
    for splice in &splices {
        candidate[splice.line].clone_from(&splice.text);
    }
    let ids: Vec<&str> = located.iter().map(|(_, id)| *id).collect();
    if !every_instance_pinned(&candidate.join("\n"), &ids, sha512, &dep.artifact_url) {
        unsupported_key(result, dep, ids[0]);
        return false;
    }

    result.confirmed_vlt_uuids.insert(dep.patch_uuid.clone());
    let changed = !splices.is_empty();
    for splice in splices {
        lines[splice.line] = splice.text;
        result.edits.push(splice.edit);
    }
    changed
}

/// The hosted vlt rewrite: lock-level refusal and advisories, then each
/// npm override's default-registry instances.
pub(super) fn rewrite_vlt_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    bun_lockb_present: bool,
    result: &mut RewriteResult,
) {
    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() {
        return;
    }
    let Some(text) = files.get(VLT_LOCK) else {
        if files.contains_key(VLT_CONFIG) || files.contains_key(VLT_HIDDEN_LOCK_REL) {
            result.warnings.push(RewriteWarning {
                code: "redirect_vlt_no_lockfile".into(),
                detail: "vlt project has no vlt-lock.json; run `vlt install` and commit \
                         vlt-lock.json"
                    .into(),
            });
        }
        return;
    };
    let lock = match parse_hosted_lock(text) {
        Ok(lock) => lock,
        Err(warning) => {
            result.warnings.push(warning);
            return;
        }
    };
    result
        .warnings
        .extend(lock_level_warnings(&lock, files, bun_lockb_present));

    let mut lines: Vec<String> = split_lines(text).into_iter().map(str::to_string).collect();
    let mut changed = false;
    for dep in npm {
        changed |= rewrite_dep(&lock, &mut lines, dep, result);
    }
    if changed {
        result.files.insert(VLT_LOCK.into(), lines.join("\n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rewriter's lock-level refusal alone. An absent lock passes.
    fn lock_level_refusal(files: &BTreeMap<String, String>) -> Result<(), RewriteWarning> {
        match files.get(VLT_LOCK) {
            Some(text) => parse_hosted_lock(text).map(|_| ()),
            None => Ok(()),
        }
    }

    const SHA: &str = "sha512-PATCHED==";
    const URL: &str = "https://patch.socket.dev/patch/npm/t/u/left-pad-1.3.0.tgz";
    const REG_SHA: &str = "sha512-REGISTRY==";
    const REG_URL: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";

    fn files(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn dep(name: &str, version: &str, sha512: Option<&str>) -> DepOverride {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "npm",
            "name": name,
            "version": version,
            "token": "t",
            "patchUuid": format!("uuid-{name}"),
            "artifactUrl": URL,
            "integrity": { "sha512": sha512 },
        }))
        .unwrap()
    }

    fn lock_with(node_lines: &[&str]) -> String {
        let mut out =
            String::from("{\n  \"lockfileVersion\": 1,\n  \"options\": {},\n  \"nodes\": {\n");
        for (i, line) in node_lines.iter().enumerate() {
            out.push_str("    ");
            out.push_str(line);
            if i + 1 < node_lines.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  },\n  \"edges\": {}\n}\n");
        out
    }

    fn rewrite(lock: &str, deps: &[DepOverride]) -> RewriteResult {
        let mut result = RewriteResult::default();
        rewrite_vlt_lock(&files(&[(VLT_LOCK, lock)]), deps, false, &mut result);
        result
    }

    fn codes(result: &RewriteResult) -> Vec<&str> {
        result.warnings.iter().map(|w| w.code.as_str()).collect()
    }

    const ID: &str = "~npm~left-pad@1.3.0";

    fn registry_entry() -> String {
        format!("\"{ID}\": [0,\"left-pad\",\"{REG_SHA}\",\"{REG_URL}\"]")
    }

    #[test]
    fn vlt_drives_needs_the_lock_and_the_sentinel_or_no_sibling() {
        let sentinel = (VLT_HIDDEN_LOCK_REL, "");
        let lock = (VLT_LOCK, "{}");
        assert!(!vlt_drives(&files(&[]), false));
        assert!(!vlt_drives(&files(&[sentinel, (VLT_CONFIG, "{}")]), false));
        assert!(vlt_drives(&files(&[lock]), false));
        assert!(vlt_drives(&files(&[lock, (VLT_CONFIG, "{}")]), false));
        for sibling in npm_locks_outside(NpmLockFamily::Vlt, |_| true) {
            let other = (sibling, "x");
            assert!(!vlt_drives(&files(&[lock, other]), false), "{sibling}");
            assert!(
                vlt_drives(&files(&[lock, other, sentinel]), false),
                "{sibling}"
            );
        }
        assert!(!vlt_drives(
            &files(&[lock, ("package-lock.json", "x"), ("bun.lockb", "x")]),
            false
        ));
        assert!(vlt_drives(
            &files(&[lock, ("packages/a/package-lock.json", "x")]),
            false
        ));
    }

    #[test]
    fn a_bun_lockb_on_disk_is_a_sibling_outside_files() {
        let lock = (VLT_LOCK, "{}");
        assert!(!vlt_drives(&files(&[lock]), true));
        assert!(vlt_drives(&files(&[lock, (VLT_HIDDEN_LOCK_REL, "")]), true));
        assert!(!vlt_drives(&files(&[]), true));

        let text = lock_with(&[&registry_entry()]);
        let deps = [dep("left-pad", "1.3.0", Some(SHA))];
        let mut result = RewriteResult::default();
        rewrite_vlt_lock(&files(&[(VLT_LOCK, &text)]), &deps, true, &mut result);
        assert_eq!(codes(&result), ["redirect_vlt_sibling_lockfiles"]);
        assert!(result.warnings[0].detail.contains("and bun.lockb are both"));
        assert!(result.confirmed_vlt_uuids.contains("uuid-left-pad"));
    }

    #[test]
    fn old_lockfile_ignored_counts_only_empty_and_registry_url_segments() {
        let r = "https://registry.example.com/";
        let v0 = |options: &str, id: &str| {
            format!(
                "{{\n  \"lockfileVersion\": 0,\n  \"options\": {options},\n  \"nodes\": {{\n    \"{id}\": [0,\"left-pad\",\"{REG_SHA}\"]\n  }},\n  \"edges\": {{}}\n}}\n"
            )
        };
        let old_lockfile = |lock: &str| {
            codes(&rewrite(lock, &[dep("left-pad", "1.3.0", Some(SHA))]))
                .contains(&"redirect_vlt_old_lockfile_ignored")
        };
        assert!(old_lockfile(&v0("{}", "··left-pad@1.3.0")));
        let url_segment = format!(
            "·{}·left-pad@1.3.0",
            r.replace(':', "%3A").replace('/', "§")
        );
        assert!(old_lockfile(&v0(
            &format!("{{\"registry\": \"{r}\"}}"),
            &url_segment
        )));
        assert!(!old_lockfile(&v0("{}", "·npm·left-pad@1.3.0")));
        assert!(!old_lockfile(&v0(
            "{\"default-registry-alias\": \"corp\"}",
            "·corp·left-pad@1.3.0"
        )));
        assert!(!old_lockfile(&v0(
            &format!("{{\"registry\": \"{r}\", \"registries\": {{\"acme\": \"{r}\"}}}}"),
            "·acme·left-pad@1.3.0"
        )));
    }

    /// `vlt.json`'s `modifiers` probe reads past exactly one leading BOM
    /// (`formats::text::strip_bom`): a second one is content, so the file
    /// is not JSON and declares nothing.
    #[test]
    fn modifiers_probe_reads_past_one_vlt_json_bom_only() {
        let lock = "{\n  \"lockfileVersion\": 0,\n  \"options\": {},\n  \"nodes\": {\n    \"··left-pad@1.3.0\": [0,\"left-pad\",\"sha512-REGISTRY==\"]\n  },\n  \"edges\": {}\n}\n";
        let old_lockfile = |config: &str| {
            let mut result = RewriteResult::default();
            rewrite_vlt_lock(
                &files(&[(VLT_LOCK, lock), (VLT_CONFIG, config)]),
                &[dep("left-pad", "1.3.0", Some(SHA))],
                false,
                &mut result,
            );
            codes(&result).contains(&"redirect_vlt_old_lockfile_ignored")
        };
        assert!(!old_lockfile("{\"modifiers\": {}}"));
        assert!(!old_lockfile("\u{feff}{\"modifiers\": {}}"));
        assert!(old_lockfile("\u{feff}\u{feff}{\"modifiers\": {}}"));
        assert!(old_lockfile("{}"));
    }

    #[test]
    fn ledger_keys_carry_the_raw_extra_after_a_tilde() {
        let lock = lock_with(&[
            &format!("\"·npm·left-pad@1.3.0·%E1%B9%97%3A3\": [0,\"left-pad\",\"{REG_SHA}\"]"),
            &format!("\"~npm~left-pad@1.3.0~_croot_s_g_s#x\": [0,\"left-pad\",\"{REG_SHA}\"]"),
            &format!("\"~npm~left-pad@1.3.0~peer.2\": [0,\"left-pad\",\"{REG_SHA}\"]"),
            &format!("\"{ID}\": [0,\"left-pad\",\"{REG_SHA}\"]"),
        ]);
        let result = rewrite(&lock, &[dep("left-pad", "1.3.0", Some(SHA))]);
        let keys: Vec<&str> = result
            .edits
            .iter()
            .map(|e| e.key.as_deref().unwrap())
            .collect();
        assert_eq!(
            keys,
            [
                "left-pad@1.3.0~%E1%B9%97%3A3",
                "left-pad@1.3.0~_croot_s_g_s#x",
                "left-pad@1.3.0~peer.2",
                "left-pad@1.3.0",
            ]
        );
        assert!(result.confirmed_vlt_uuids.contains("uuid-left-pad"));
    }

    /// The index answers every per-override question exactly as a scan
    /// of every node does: same ids, same key order, same eras.
    #[test]
    fn the_node_index_matches_a_scan_of_every_node() {
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        let lock = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{\"registries\": {{\"corp\": \"https://corp.example/\"}}}},\n  \"nodes\": {{\n{}\n  }}\n}}\n",
            [
                format!("\"~corp~left-pad@1.3.0\": [0,\"left-pad\",\"{REG_SHA}\"]"),
                format!("\"{ID}~peer.1\": [0,\"left-pad\",\"{REG_SHA}\"]"),
                format!("\"·npm·left-pad@1.3.0\": [0,\"left-pad\",\"{REG_SHA}\"]"),
                format!("\"~npm~ms@2.1.3\": [0,\"ms\",\"{REG_SHA}\"]"),
                format!("\"{ID}\": [0,\"left-pad\",\"{REG_SHA}\"]"),
                format!("\"~npm~left-pad@1.2.0\": [0,\"left-pad\",\"{REG_SHA}\"]"),
                "\"git~github:a+b~abc\": [0,\"left-pad\"]".into(),
                "\"remote~https_c++x.example+left-pad-1.3.0.tgz\": [0,\"left-pad\"]".into(),
                "\"remote~https_c++x.example+left-pad-1.2.0.tgz\": [0,\"left-pad\"]".into(),
                "\"file~packages+lp\": [0,\"left-pad\"]".into(),
                "\"file~packages+other\": [0,\"ms\"]".into(),
                format!("\"file~.socket+vendor+npm+{uuid}+left-pad-1.3.0+node__modules+left-pad\": [0,\"left-pad\"]"),
                format!("\"file~.socket+vendor+npm+{uuid}+ms-2.1.3+node__modules+ms\": [0,\"ms\"]"),
                "\"workspace~left-pad\": [0,\"left-pad\"]".into(),
                "\"not-a-dep-id\": [0,\"left-pad\"]".into(),
            ]
            .map(|line| format!("    {line}"))
            .join(",\n")
        );
        let hosted = parse_hosted_lock(&lock).unwrap();
        let nodes = hosted.parsed.nodes().unwrap();
        let options = hosted.parsed.options();
        let scan = |name: &str, version: &str| {
            let mut defaults = Vec::new();
            let mut foreign = Vec::new();
            let mut outside = Vec::new();
            let mut vendored = false;
            for (id, tuple) in nodes {
                let Some(dep_id) = split_dep_id(id) else {
                    continue;
                };
                let slot1 = tuple.get(1).and_then(Value::as_str).unwrap_or_default();
                if dep_id.registry_identity() == Some((name, version)) {
                    if is_default_registry(&dep_id.first, options) {
                        defaults.push(id.as_str());
                    } else {
                        foreign.push(id.as_str());
                    }
                }
                if installs_outside_registry(&dep_id, slot1, name, version) {
                    outside.push(id.as_str());
                }
                vendored |= dep_id.kind == DepIdKind::File
                    && slot1 == name
                    && parse_vendored_path(&dep_id.first, name)
                        .is_some_and(|p| p.version == version);
            }
            (defaults, foreign, outside, vendored)
        };
        let indexed = |name: &str, version: &str| {
            let (defaults, foreign) = partition_instances(&hosted, name, version);
            let outside = outside_instances(&hosted, name, version);
            (
                defaults,
                foreign,
                outside,
                has_vendored_node(&hosted, name, version),
            )
        };
        for (name, version) in [
            ("left-pad", "1.3.0"),
            ("left-pad", "1.2.0"),
            ("ms", "2.1.3"),
            ("absent", "1.0.0"),
        ] {
            assert_eq!(
                indexed(name, version),
                scan(name, version),
                "{name}@{version}"
            );
        }
        let (defaults, foreign, outside, vendored) = indexed("left-pad", "1.3.0");
        assert_eq!(
            defaults,
            [format!("{ID}~peer.1").as_str(), "·npm·left-pad@1.3.0", ID]
        );
        assert_eq!(foreign, ["~corp~left-pad@1.3.0"]);
        assert_eq!(outside.len(), 3, "{outside:?}");
        assert!(vendored);
        assert_eq!(hosted.index.nodes.len(), nodes.len() - 1);
    }

    /// The gate's skipping parse reads exactly the nodes a full
    /// `serde_json::Value` parse would, and refuses what it refuses.
    #[test]
    fn the_gate_parse_matches_a_full_value_parse() {
        let ids = ["a", "b"];
        let full = |text: &str| -> Option<Map<String, Value>> {
            let json: Value = serde_json::from_str(text).ok()?;
            let nodes = json.get("nodes")?.as_object()?;
            Some(
                nodes
                    .iter()
                    .filter(|(id, _)| ids.contains(&id.as_str()))
                    .map(|(id, tuple)| (id.clone(), tuple.clone()))
                    .collect(),
            )
        };
        for text in [
            r#"{"nodes": {"a": [0, "a", "s", "u"], "c": [0, "c"], "b": 1}}"#,
            r#"{"lockfileVersion": 1, "options": {"x": [1.5, -2, null, true, {"y": "z"}]}, "nodes": {"a": [0, "a"]}, "edges": {"e": "f"}}"#,
            r#"{"nodes": {"a": [0, "old"]}, "nodes": {"a": [0, "new"]}}"#,
            r#"{"nodes": {"a": [0, "first"], "a": [0, "last"]}}"#,
            r#"{"nodes": {"a": [0, "a"]}, "nodes": []}"#,
            r#"{"nodes": [], "nodes": {"b": [0, "b"]}}"#,
            r#"{"nodes": {"a": [0, "a"]}}"#,
            r#"{"nodes": "x"}"#,
            r#"{"nodes": null}"#,
            r#"{"nodes": 7}"#,
            r#"{"nodes": -7.5}"#,
            r#"{"nodes": false}"#,
            r#"{"other": {}}"#,
            r#"{}"#,
            "  {\"nodes\": {}}\r\n",
            r#"{"nodes": {"a": [0, "a"]}, "edges": {"e": }}"#,
            r#"{"nodes": {"a": [0, "a"]}} trailing"#,
            r#"{"nodes": {"a": [0, "a"],}}"#,
            r#"{"nodes": {"a": [0, "a"]}, "x": "\q"}"#,
            r#"{"nodes": {"a": [0, "a"]}"#,
            r#"[{"nodes": {}}]"#,
            r#""nodes""#,
            "",
        ] {
            assert_eq!(parse_nodes_of(text, &ids), full(text), "{text}");
        }
    }

    #[test]
    fn residual_gate_refuses_when_the_parsed_node_is_not_the_spliced_line() {
        let entry = format!("    \"{ID}\": [0,\"left-pad\",\"{REG_SHA}\"]");
        let lock = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"nodes\": {{\n{entry}\n  }},\n  \"nodes\": {{\n{entry}\n  }}\n}}\n"
        );
        let result = rewrite(&lock, &[dep("left-pad", "1.3.0", Some(SHA))]);
        assert_eq!(codes(&result), ["redirect_vlt_unsupported_lock_key"]);
        assert!(result.files.is_empty() && result.edits.is_empty());
        assert!(result.refused_vlt_uuids.contains("uuid-left-pad"));
        assert!(result.confirmed_vlt_uuids.is_empty());
    }

    #[test]
    fn an_unsupported_instance_refuses_every_instance_of_the_dep_only() {
        let lock = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"nodes\": {{\n    \"{ID}\": [0,\"left-pad\",\"{REG_SHA}\"],\n    \"~npm~left-pad@1.3.0~peer.1\": [0, \"left-pad\"],\n    \"~npm~ms@2.1.3\": [0,\"ms\",\"{REG_SHA}\"]\n  }}\n}}\n"
        );
        let result = rewrite(
            &lock,
            &[
                dep("left-pad", "1.3.0", Some(SHA)),
                dep("ms", "2.1.3", Some(SHA)),
            ],
        );
        assert_eq!(codes(&result), ["redirect_vlt_unsupported_lock_key"]);
        assert_eq!(result.edits.len(), 1);
        assert_eq!(result.edits[0].key.as_deref(), Some("ms@2.1.3"));
        assert!(result.refused_vlt_uuids.contains("uuid-left-pad"));
        assert!(result.confirmed_vlt_uuids.contains("uuid-ms"));
    }

    #[test]
    fn a_name_mismatch_in_slot_one_is_unsupported() {
        let lock = lock_with(&[&format!("\"{ID}\": [0,\"other\",\"{REG_SHA}\"]")]);
        let result = rewrite(&lock, &[dep("left-pad", "1.3.0", Some(SHA))]);
        assert_eq!(codes(&result), ["redirect_vlt_unsupported_lock_key"]);
    }

    #[test]
    fn lock_level_parse_refusals() {
        let refused = |text: &str| {
            lock_level_refusal(&files(&[(VLT_LOCK, text)]))
                .unwrap_err()
                .detail
        };
        assert!(refused("\u{feff}{}").contains("UTF-8 BOM"));
        assert!(refused("[]").contains("not a JSON object"));
        assert!(refused("{\"lockfileVersion\": 1.0}").contains("lockfileVersion 1.0"));
        let pretty = format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"nodes\": {{\n    \"{ID}\": [\n      0,\n      \"left-pad\"\n    ]\n  }}\n}}\n"
        );
        assert!(refused(&pretty).contains("canonical layout"));
        assert!(lock_level_refusal(&files(&[])).is_ok());
        assert!(lock_level_refusal(&files(&[(VLT_LOCK, "{\"nodes\": {}}")])).is_ok());
        let ok = lock_with(&[&registry_entry()]);
        assert!(lock_level_refusal(&files(&[(VLT_LOCK, &ok)])).is_ok());
    }

    #[test]
    fn a_git_remote_or_file_install_of_the_package_is_withheld() {
        let remote = "\"remote~https_c++registry.npmjs.org+left-pad+-+left-pad-1.3.0.tgz\": \
                      [0,\"left-pad\",\"sha512-r\"]";
        let lock = lock_with(&[remote, &registry_entry()]);
        let result = rewrite(&lock, &[dep("left-pad", "1.3.0", Some(SHA))]);
        assert_eq!(codes(&result), ["redirect_vlt_custom_registry_skipped"]);
        assert!(result.warnings[0].detail.contains("remote~https_c++"));
        assert!(result.vlt_foreign_uuids.contains("uuid-left-pad"));
        assert!(result.confirmed_vlt_uuids.contains("uuid-left-pad"));
        assert_eq!(result.edits.len(), 1);

        let older = remote.replace("1.3.0.tgz", "1.2.0.tgz");
        let lock = lock_with(&[&older, &registry_entry()]);
        let result = rewrite(&lock, &[dep("left-pad", "1.3.0", Some(SHA))]);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert!(result.vlt_foreign_uuids.is_empty());
    }

    #[test]
    fn missing_sha512_and_empty_sha512_refuse() {
        let lock = lock_with(&[&registry_entry()]);
        for sha in [None, Some("")] {
            let result = rewrite(&lock, &[dep("left-pad", "1.3.0", sha)]);
            assert_eq!(codes(&result), ["redirect_vlt_missing_sha512"]);
            assert!(result.refused_vlt_uuids.contains("uuid-left-pad"));
        }
    }

    #[test]
    fn non_npm_overrides_leave_everything_alone() {
        let mut other = dep("left-pad", "1.3.0", Some(SHA));
        other.ecosystem = "pypi".into();
        let mut result = RewriteResult::default();
        rewrite_vlt_lock(&files(&[(VLT_CONFIG, "{}")]), &[other], false, &mut result);
        assert!(result.warnings.is_empty());
    }

    /// #372: vlt 1.3 records the brotli bit (4) on a node that resolved
    /// the registry's `.tar.br` alternate. Such a lock is canonical; the
    /// pin points the node at the hosted `.tgz`, so it clears bit 4 (and
    /// keeps dev/optional), which is what `vlt install` saves for it.
    #[test]
    fn a_vlt_1_3_brotli_lock_is_pinned_with_the_brotli_bit_cleared() {
        const BR_URL: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tar.br";
        let peer = "~npm~left-pad@1.3.0~peer.1";
        let lock = lock_with(&[
            &format!("\"{ID}\": [4,\"left-pad\",\"{REG_SHA}\",\"{BR_URL}\"]"),
            &format!("\"{peer}\": [6,\"left-pad\",\"{REG_SHA}\",\"{BR_URL}\"]"),
            "\"~npm~other@1.0.0\": [5,\"other\",\"sha512-O==\"]",
        ]);
        assert!(lock_level_refusal(&files(&[(VLT_LOCK, &lock)])).is_ok());

        let result = rewrite(&lock, &[dep("left-pad", "1.3.0", Some(SHA))]);
        assert!(codes(&result).is_empty(), "{:?}", result.warnings);
        assert!(result.confirmed_vlt_uuids.contains("uuid-left-pad"));
        let written = &result.files[VLT_LOCK];
        assert!(written.contains(&format!("\"{ID}\": [0,\"left-pad\",\"{SHA}\",\"{URL}\"]")));
        assert!(written.contains(&format!("\"{peer}\": [2,\"left-pad\",\"{SHA}\",\"{URL}\"]")));
        assert!(written.contains("\"~npm~other@1.0.0\": [5,\"other\",\"sha512-O==\"]"));
        let originals: Vec<_> = result.edits.iter().map(|e| e.original.clone()).collect();
        assert!(originals.contains(&Some(Value::String(format!(
            "\"{ID}\": [4,\"left-pad\",\"{REG_SHA}\",\"{BR_URL}\"]"
        )))));

        // A re-run over its own pin is a no-op.
        let again = rewrite(written, &[dep("left-pad", "1.3.0", Some(SHA))]);
        assert!(again.edits.is_empty(), "{:?}", again.edits);
    }
}
