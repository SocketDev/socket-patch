//! `package-lock.json` / `npm-shrinkwrap.json`: the shared entry walk
//! ([`npm_lock_nodes`]) and its registry view.

#[cfg(test)]
use std::path::Path;

use serde_json::Value;

use crate::constants::npm_family::NPM_LOCKS;
use crate::utils::digest::is_sri_pin;
use crate::vendor::path::parse_vendor_path;

use super::view::ProjectView;
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
    walk_npm_lock(doc, Bundled::Skip)
        .into_iter()
        .map(|(_, node)| node)
        .collect()
}

/// The BUNDLED entries of a parsed npm lock, each with where the lock puts
/// it: `inBundle: true` in `packages` (lockfileVersion 2/3; the location is
/// the `packages` key), `bundled: true` in the v1 `dependencies` tree (the
/// location is the `>`-joined chain of dependency names). These are exactly
/// the entries [`npm_lock_nodes`] skips for being bundled, read from the
/// same tree npm reads. npm unpacks them from the parent package's own
/// tarball, so a Socket rewire never reaches them: a bundled copy of a
/// patched `name@version` stays unpatched in the install (the rewriters
/// warn `*_bundled_instance_skipped`), and lockfile discovery
/// (`vex::discover::npm`) weighs it against the rewired entries.
pub(crate) fn npm_lock_bundled_nodes(doc: &Value) -> Vec<(String, NpmLockNode<'_>)> {
    walk_npm_lock(doc, Bundled::Only)
}

/// Which side of the bundled split [`walk_npm_lock`] returns.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Bundled {
    Skip,
    Only,
}

/// [`npm_lock_nodes`] / [`npm_lock_bundled_nodes`]: one walk, split on the
/// bundled flag. Locations are built only for [`Bundled::Only`] (empty
/// otherwise), so the common walk allocates nothing extra.
fn walk_npm_lock(doc: &Value, bundled: Bundled) -> Vec<(String, NpmLockNode<'_>)> {
    let mut out = Vec::new();
    if let Some(packages) = doc.get("packages").and_then(Value::as_object) {
        for (key, node) in packages {
            let Some((_, key_name)) = key.rsplit_once("node_modules/") else {
                continue;
            };
            if npm_flag(node, "link") || npm_flag(node, "inBundle") != (bundled == Bundled::Only) {
                continue;
            }
            let name = node.get("name").and_then(Value::as_str).unwrap_or(key_name);
            let location = match bundled {
                Bundled::Only => key.clone(),
                Bundled::Skip => String::new(),
            };
            out.push((location, NpmLockNode::of(name, node)));
        }
    } else if let Some(deps) = doc.get("dependencies").and_then(Value::as_object) {
        walk_npm_legacy_dependencies(deps, 0, bundled, "", &mut out);
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
    bundled: Bundled,
    parent: &str,
    out: &mut Vec<(String, NpmLockNode<'a>)>,
) {
    if depth > MAX_LEGACY_NPM_DEPTH {
        return;
    }
    for (name, node) in deps {
        let location = match bundled {
            Bundled::Only if parent.is_empty() => name.clone(),
            Bundled::Only => format!("{parent} > {name}"),
            Bundled::Skip => String::new(),
        };
        if npm_flag(node, "bundled") == (bundled == Bundled::Only) {
            out.push((location.clone(), NpmLockNode::of(name, node)));
        }
        if let Some(nested) = node.get("dependencies").and_then(Value::as_object) {
            walk_npm_legacy_dependencies(nested, depth + 1, bundled, &location, out);
        }
    }
}

// ── registry view ──

#[cfg(test)]
pub(super) async fn inventory_package_lock(root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_package_lock_in(&ProjectView::Disk(root)).await
}

pub(super) async fn inventory_package_lock_in(
    view: &ProjectView<'_>,
) -> Option<Vec<LockfileEntry>> {
    // Shrinkwrap wins, mirroring `npm_lock::select_lockfile`.
    let mut bytes = None;
    for lock in NPM_LOCKS {
        if let Ok(b) = view.read_bytes(lock).await {
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
        // A non-registry resolution (`file:`, `git+…`) records the integrity
        // of an artifact no registry serves: nothing a registry fetch could
        // verify against.
        let resolved = node.resolved.and_then(http_url);
        let integrity = match (&resolved, node.resolved) {
            (None, Some(_)) => LockIntegrity::None,
            _ => node
                .integrity
                .map(|i| LockIntegrity::Sri(i.to_string()))
                .unwrap_or(LockIntegrity::None),
        };
        out.push(LockfileEntry::npm(node.name, version, resolved, integrity));
    }
    Some(out)
}
