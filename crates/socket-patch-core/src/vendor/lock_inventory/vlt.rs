//! `vlt-lock.json`: the entry model lockfile discovery shares
//! ([`vlt_lock_nodes`]) and the registry view (DESIGN §4.8).

use std::path::Path;

use serde_json::{Map, Value};

use crate::constants::npm_family::VLT_LOCK;
use crate::utils::fs::read_regular_to_string;
use crate::vendor::vlt_lock_text::{
    is_default_registry, sniff_lock, split_dep_id, DepId, DepIdKind, LockSniff,
};

use super::{http_url, LockIntegrity, LockfileEntry};

// ── entry model ──

/// One node of a readable `vlt-lock.json`: its raw DepID key and split,
/// slot [1] (the package name) and the raw slot [2] integrity and slot [3]
/// location.
#[derive(Debug, Clone)]
pub(crate) struct VltLockNode {
    pub(crate) key: String,
    pub(crate) dep_id: DepId,
    pub(crate) name: String,
    pub(crate) integrity: Option<String>,
    pub(crate) location: Option<String>,
}

/// A readable `vlt-lock.json`: its `options` and every node whose id splits.
#[derive(Debug, Clone)]
pub(crate) struct VltLock {
    pub(crate) options: Option<Map<String, Value>>,
    pub(crate) nodes: Vec<VltLockNode>,
}

/// The nodes of a readable lock; `None` for a BOM-prefixed, unparseable or
/// unknown-version lock (never BOM-stripped).
pub(crate) fn vlt_lock_nodes(text: &str) -> Option<VltLock> {
    vlt_lock_model(text).ok()
}

/// [`vlt_lock_nodes`], with why the lock is not read as the error.
pub(crate) fn vlt_lock_model(text: &str) -> Result<VltLock, String> {
    let lock = match sniff_lock(text) {
        LockSniff::Readable(lock) => lock,
        LockSniff::Bom => return Err("starts with a UTF-8 BOM, which vlt cannot read".into()),
        LockSniff::NotJsonObject => {
            return Err("is not a JSON object socket-patch can parse".into())
        }
        LockSniff::UnsupportedVersion(raw) => {
            return Err(format!(
                "has lockfileVersion {raw}, which this socket-patch does not read"
            ))
        }
    };
    let string_slot = |tuple: &[Value], i: usize| {
        tuple
            .get(i)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    let nodes = lock
        .nodes()
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|(id, tuple)| {
                    let tuple = tuple.as_array()?;
                    Some(VltLockNode {
                        key: id.clone(),
                        dep_id: split_dep_id(id)?,
                        name: tuple.get(1)?.as_str()?.to_string(),
                        integrity: string_slot(tuple, 2),
                        location: string_slot(tuple, 3),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(VltLock {
        options: lock.options().cloned(),
        nodes,
    })
}

fn with_slash(url: &str) -> String {
    if url.ends_with('/') {
        url.to_string()
    } else {
        format!("{url}/")
    }
}

/// The registry base a node's segment names: the segment URL itself, the
/// alias's `options.registries` URL, or for the default registry
/// `options.registry`, `options.registries.npm`, else the public registry.
/// `None` for an alias the options do not map.
fn registry_base(segment: &str, options: Option<&Map<String, Value>>) -> Option<String> {
    let option = |path: &[&str]| {
        let mut value = options.map(|o| Value::Object(o.clone()))?;
        for key in path {
            value = value.get(*key)?.clone();
        }
        value.as_str().map(str::to_string)
    };
    if segment.starts_with("https://") || segment.starts_with("http://") {
        return Some(with_slash(segment));
    }
    if is_default_registry(segment, options) {
        let base = option(&["registry"])
            .or_else(|| option(&["registries", "npm"]))
            .unwrap_or_else(|| "https://registry.npmjs.org/".to_string());
        return Some(with_slash(&base));
    }
    option(&["registries", segment]).map(|base| with_slash(&base))
}

/// The registry entries of a readable lock: every registry node whose slot
/// [1] is its DepID name. The location is slot [3] when it is an http(s)
/// URL (a Socket-hosted pin included: it is the installed pair), else the
/// conventional tarball URL of its registry.
pub(crate) fn vlt_registry_entries(lock: &VltLock) -> Vec<LockfileEntry> {
    let options = lock.options.as_ref();
    lock.nodes
        .iter()
        .filter(|node| node.dep_id.kind == DepIdKind::Registry)
        .filter_map(|node| {
            let (name, version) = node.dep_id.registry_identity()?;
            if node.name != name {
                return None;
            }
            let bare = name.rsplit('/').next().unwrap_or(name);
            let resolved = node.location.as_deref().and_then(http_url).or_else(|| {
                registry_base(&node.dep_id.first, options)
                    .map(|base| format!("{base}{name}/-/{bare}-{version}.tgz"))
            });
            let integrity = node
                .integrity
                .clone()
                .map_or(LockIntegrity::None, LockIntegrity::Sri);
            Some(LockfileEntry::npm(name, version, resolved, integrity))
        })
        .collect()
}

// ── registry view ──

/// Inventory the root `vlt-lock.json`. Vendored `file` nodes are not
/// registry nodes and never appear; hosted pins stay (pnpm parity).
pub(super) async fn inventory_vlt(root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&root.join(VLT_LOCK)).await.ok()?;
    vlt_lock_nodes(&text).map(|lock| vlt_registry_entries(&lock))
}
