//! `package-lock.json` / `npm-shrinkwrap.json`: the shared entry walk
//! ([`npm_lock_nodes`]) and its registry view.

use std::path::Path;

use serde_json::Value;

use crate::constants::npm_family::NPM_LOCKS;
use crate::utils::digest::is_sri_pin;
use crate::utils::fs::read_regular_to_bytes;
use crate::vendor::path::parse_vendor_path;

use super::{http_url, LockIntegrity, LockfileEntry};

// ── entry model ──

/// One install entry of a `package-lock.json` / `npm-shrinkwrap.json`, as
/// npm reads it (see [`npm_lock_nodes`]).
pub(crate) struct NpmLockNode<'a> {
    /// The entry's `name` field when present (npm writes it for aliases —
    /// the key is then the ALIAS), else the `packages` key's trailing path
    /// or the legacy `dependencies` key.
    pub(crate) name: &'a str,
    pub(crate) version: Option<&'a str>,
    pub(crate) resolved: Option<&'a str>,
    pub(crate) integrity: Option<&'a str>,
}

/// Bound on the legacy `dependencies` tree depth — the lock is tamper-able
/// input and the walk recurses (real trees are a handful of levels deep).
const MAX_LEGACY_NPM_DEPTH: usize = 64;

/// Every install entry of a parsed npm lock, the ONE walk the inventory and
/// lockfile discovery (`vex::discover::npm`) share:
///
/// * `packages` (lockfileVersion 2/3) whenever it exists — skipping the root
///   `""`, workspace members (keys without `node_modules/` are source dirs;
///   mirrors `npm_lock::scan_lock_matches`' member rule) and `link: true` /
///   `inBundle: true` entries, which npm installs from elsewhere. A v2
///   lock's `dependencies` is a legacy mirror npm 7+ never reads when
///   `packages` exists, so it is ignored there;
/// * otherwise the lockfileVersion 1 `dependencies` tree, recursive
///   through nested `dependencies`, `bundled: true` entries skipped (their
///   nested trees are still walked).
pub(crate) fn npm_lock_nodes(doc: &Value) -> Vec<NpmLockNode<'_>> {
    let mut out = Vec::new();
    if let Some(packages) = doc.get("packages").and_then(Value::as_object) {
        for (key, node) in packages {
            let Some((_, key_name)) = key.rsplit_once("node_modules/") else {
                continue;
            };
            if npm_flag(node, "link") || npm_flag(node, "inBundle") {
                continue;
            }
            let name = node.get("name").and_then(Value::as_str).unwrap_or(key_name);
            out.push(NpmLockNode::of(name, node));
        }
    } else if let Some(deps) = doc.get("dependencies").and_then(Value::as_object) {
        walk_npm_legacy_dependencies(deps, 0, &mut out);
    }
    out
}

impl<'a> NpmLockNode<'a> {
    /// The entry's `integrity` when it is an SRI pin ([`is_sri_pin`]) —
    /// lockfile discovery's rule; the registry view records any value.
    pub(crate) fn sri_pin(&self) -> Option<&'a str> {
        self.integrity.filter(|sri| is_sri_pin(sri))
    }

    fn of(name: &'a str, node: &'a Value) -> Self {
        let field = |key: &str| node.get(key).and_then(Value::as_str);
        NpmLockNode {
            name,
            version: field("version"),
            resolved: field("resolved"),
            integrity: field("integrity"),
        }
    }
}

fn npm_flag(node: &Value, key: &str) -> bool {
    node.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// The v1 `dependencies` tree: `{name: {version, resolved, integrity,
/// dependencies: {…}}}`.
fn walk_npm_legacy_dependencies<'a>(
    deps: &'a serde_json::Map<String, Value>,
    depth: usize,
    out: &mut Vec<NpmLockNode<'a>>,
) {
    if depth > MAX_LEGACY_NPM_DEPTH {
        return;
    }
    for (name, node) in deps {
        if !npm_flag(node, "bundled") {
            out.push(NpmLockNode::of(name, node));
        }
        if let Some(nested) = node.get("dependencies").and_then(Value::as_object) {
            walk_npm_legacy_dependencies(nested, depth + 1, out);
        }
    }
}

// ── registry view ──

pub(super) async fn inventory_package_lock(root: &Path) -> Option<Vec<LockfileEntry>> {
    // Shrinkwrap wins, mirroring `npm_lock::select_lockfile`.
    let mut bytes = None;
    for lock in NPM_LOCKS {
        if let Ok(b) = read_regular_to_bytes(&root.join(lock)).await {
            bytes = Some(b);
            break;
        }
    }
    let doc: Value = serde_json::from_slice(&bytes?).ok()?;
    // v1 legacy locks have no `packages` map — no inventory (documented).
    doc.get("packages")?.as_object()?;

    let mut out = Vec::new();
    for node in npm_lock_nodes(&doc) {
        let Some(version) = node.version else {
            continue;
        };
        // Our own vendored spec: not a registry dependency.
        if node
            .resolved
            .is_some_and(|r| parse_vendor_path(r).is_some())
        {
            continue;
        }
        let integrity = node
            .integrity
            .map(|i| LockIntegrity::Sri(i.to_string()))
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry::npm(
            node.name,
            version,
            node.resolved.and_then(http_url),
            integrity,
        ));
    }
    Some(out)
}
