//! `package-lock.json` / `npm-shrinkwrap.json`: the one addressed entry
//! walk ([`npm_lock_entries`]), the install view built on it
//! ([`npm_lock_nodes`]) and its registry view.

#[cfg(test)]
use std::path::Path;

use std::borrow::Cow;

use serde_json::Value;

use crate::constants::npm_family::NPM_LOCKS;
use crate::utils::digest::is_sri_pin;
use crate::vendor::npm_origin::legacy_packages_key;
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
/// input and the walk recurses (real trees are a handful of levels deep;
/// serde_json's 128-level parse limit already caps a parsed lock near 62).
const MAX_LEGACY_NPM_DEPTH: usize = 64;

/// The `packages` key segment that marks an installed dependency.
const NODE_MODULES_SEG: &str = "node_modules/";

/// Which half of an npm lock an [`NpmLockEntry`] lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NpmLockSection {
    /// The lockfileVersion 2/3 `packages` map.
    Packages,
    /// The legacy `dependencies` tree: the install tree of a
    /// lockfileVersion 1 lock, the npm 6 mirror of a v2 one.
    Legacy,
}

/// One entry of a parsed `package-lock.json` / `npm-shrinkwrap.json`, with
/// its address in the document. [`npm_lock_entries`] yields every entry,
/// unfiltered; each reader and rewriter applies its own skip policy over
/// the flags and edits the entry through `Value::pointer_mut(pointer)`.
pub(crate) struct NpmLockEntry<'a> {
    pub(crate) section: NpmLockSection,
    /// The map key: the `packages` key, or the legacy dependency name
    /// (the ALIAS for an alias node).
    pub(crate) key: &'a str,
    /// RFC 6901 pointer to the entry (`/packages/<key>`, or
    /// `/dependencies/<a>/dependencies/<b>` for a legacy node).
    pub(crate) pointer: String,
    /// The `packages` key npm gives the install: the key itself, or the
    /// legacy node's derived one ([`legacy_packages_key`]).
    pub(crate) packages_key: Cow<'a, str>,
    /// Where diagnostics place the entry: the `packages` key, or the
    /// `>`-joined chain of legacy dependency names.
    pub(crate) location: Cow<'a, str>,
    /// The entry's JSON value (any type; a non-object has no fields).
    pub(crate) value: &'a Value,
    /// The package and version the entry installs.
    pub(crate) node: NpmLockNode<'a>,
    /// `link: true` (a `packages` entry npm links from a source dir).
    pub(crate) link: bool,
    /// `inBundle: true` in `packages`, `bundled: true` in the legacy tree:
    /// npm unpacks it from the parent package's own tarball.
    pub(crate) bundled: bool,
}

impl NpmLockEntry<'_> {
    /// An installed dependency rather than the project's own source: every
    /// legacy node, and a `packages` key with a `node_modules/` segment
    /// (`""` is the root, other bare keys are workspace members / `file:`
    /// directories).
    pub(crate) fn is_dependency(&self) -> bool {
        self.section == NpmLockSection::Legacy || self.key.contains(NODE_MODULES_SEG)
    }

    /// A legacy node npm 6 installs through an npm alias (its key is not
    /// the package it stands for).
    pub(crate) fn is_legacy_alias(&self) -> bool {
        self.section == NpmLockSection::Legacy && self.node.name != self.key
    }
}

/// Every entry of a parsed npm lock, the ONE walk the inventory, lockfile
/// discovery, the vendored and hosted rewriters and the upstream restore
/// share: the `packages` map in document order (when it is an object),
/// then the legacy `dependencies` tree depth-first, parent before its
/// nested `dependencies` (when it is an object, whether or not `packages`
/// exists), bounded at [`MAX_LEGACY_NPM_DEPTH`].
///
/// Identity is one rule: a `packages` entry is its `name` field when
/// present (npm writes it for aliases — the key is then the ALIAS), else
/// the path after the LAST `node_modules/` (nesting and scopes), else the
/// key's basename (workspace-member keys, for classification only); a
/// legacy node decodes an alias spec ([`npm_legacy_identity`]).
pub(crate) fn npm_lock_entries(doc: &Value) -> Vec<NpmLockEntry<'_>> {
    let mut out = Vec::new();
    walk_npm_packages(doc, &mut out);
    walk_npm_legacy(doc, &mut out);
    out
}

/// The section npm reads to install: `packages` whenever it is an object
/// (npm >= 7 never reads the legacy mirror then), else `dependencies`.
fn npm_lock_install_section(doc: &Value) -> NpmLockSection {
    match doc.get("packages").and_then(Value::as_object) {
        Some(_) => NpmLockSection::Packages,
        None => NpmLockSection::Legacy,
    }
}

fn walk_npm_packages<'a>(doc: &'a Value, out: &mut Vec<NpmLockEntry<'a>>) {
    let Some(packages) = doc.get("packages").and_then(Value::as_object) else {
        return;
    };
    for (key, value) in packages {
        let name = match value.get("name").and_then(Value::as_str) {
            Some(name) => name,
            None => match key.rfind(NODE_MODULES_SEG) {
                Some(idx) => &key[idx + NODE_MODULES_SEG.len()..],
                None => key.rsplit('/').next().unwrap_or(key),
            },
        };
        out.push(NpmLockEntry {
            section: NpmLockSection::Packages,
            key,
            pointer: format!("/packages/{}", escape_pointer_token(key)),
            packages_key: Cow::Borrowed(key),
            location: Cow::Borrowed(key),
            value,
            node: NpmLockNode::of(name, value),
            link: npm_flag(value, "link"),
            bundled: npm_flag(value, "inBundle"),
        });
    }
}

fn walk_npm_legacy<'a>(doc: &'a Value, out: &mut Vec<NpmLockEntry<'a>>) {
    if let Some(deps) = doc.get("dependencies").and_then(Value::as_object) {
        walk_npm_legacy_dependencies(deps, 0, "/dependencies", "", "", out);
    }
}

/// The legacy tree: `{name: {version, resolved, integrity, dependencies:
/// {…}}}`, `pointer` / `parent_key` / `chain` being the enclosing node's.
fn walk_npm_legacy_dependencies<'a>(
    deps: &'a serde_json::Map<String, Value>,
    depth: usize,
    pointer_base: &str,
    parent_key: &str,
    chain: &str,
    out: &mut Vec<NpmLockEntry<'a>>,
) {
    if depth > MAX_LEGACY_NPM_DEPTH {
        return;
    }
    for (key, value) in deps {
        let pointer = format!("{pointer_base}/{}", escape_pointer_token(key));
        let packages_key = legacy_packages_key(parent_key, key);
        let location = match chain {
            "" => key.clone(),
            _ => format!("{chain} > {key}"),
        };
        // The nested tree is walked after its parent, from the parent's
        // address (taken before the entry owns it).
        let nested = value
            .get("dependencies")
            .and_then(Value::as_object)
            .map(|nested| {
                let nested_pointer = format!("{pointer}/dependencies");
                (
                    nested,
                    nested_pointer,
                    packages_key.clone(),
                    location.clone(),
                )
            });
        out.push(NpmLockEntry {
            section: NpmLockSection::Legacy,
            key,
            pointer,
            packages_key: Cow::Owned(packages_key),
            location: Cow::Owned(location),
            value,
            node: NpmLockNode::legacy(key, value),
            link: false,
            bundled: npm_flag(value, "bundled"),
        });
        if let Some((nested, nested_pointer, nested_key, nested_chain)) = nested {
            walk_npm_legacy_dependencies(
                nested,
                depth + 1,
                &nested_pointer,
                &nested_key,
                &nested_chain,
                out,
            );
        }
    }
}

/// RFC 6901 token escaping (`~` → `~0`, `/` → `~1`).
fn escape_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Every install entry of a parsed npm lock, as npm reads it — the view
/// the inventory and lockfile discovery (`vex::discover::npm`) share:
///
/// * `packages` (lockfileVersion 2/3) whenever it exists — skipping the root
///   `""`, workspace members ([`NpmLockEntry::is_dependency`]) and
///   `link: true` / `inBundle: true` entries, which npm installs from
///   elsewhere. A v2 lock's `dependencies` is a legacy mirror npm 7+ never
///   reads when `packages` exists, so it is ignored there;
/// * otherwise the lockfileVersion 1 `dependencies` tree, recursive
///   through nested `dependencies`, `bundled: true` entries skipped (their
///   nested trees are still walked), alias nodes decoded
///   ([`npm_legacy_identity`]).
pub(crate) fn npm_lock_nodes(doc: &Value) -> Vec<NpmLockNode<'_>> {
    npm_install_entries(doc, false)
        .map(|entry| entry.node)
        .collect()
}

/// [`npm_lock_nodes`], each with where the lock puts it (the `packages`
/// key, or the `>`-joined v1 dependency chain — the
/// [`npm_lock_bundled_nodes`] spelling), for diagnostics that must name
/// the entry.
pub(crate) fn npm_lock_located_nodes(doc: &Value) -> Vec<(String, NpmLockNode<'_>)> {
    npm_install_entries(doc, false)
        .map(|entry| (entry.location.into_owned(), entry.node))
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
    npm_install_entries(doc, true)
        .map(|entry| (entry.location.into_owned(), entry.node))
        .collect()
}

/// The non-bundled nodes of a lockfileVersion 2 lock's legacy
/// `dependencies` mirror: the tree npm 6 installs from, which
/// [`npm_lock_nodes`] ignores because npm >= 7 reads `packages`. Empty for
/// a lock without `packages` (there the tree IS what [`npm_lock_nodes`]
/// walks). Lockfile discovery weighs these against the `packages` refs.
pub(crate) fn npm_lock_legacy_mirror_nodes(doc: &Value) -> Vec<NpmLockNode<'_>> {
    let mut out = Vec::new();
    if npm_lock_install_section(doc) == NpmLockSection::Packages {
        walk_npm_legacy(doc, &mut out);
    }
    out.into_iter()
        .filter(|entry| !entry.bundled)
        .map(|entry| entry.node)
        .collect()
}

/// The install section's entries on one side of the bundled split, minus
/// the root, workspace members and links (the [`npm_lock_nodes`] rule).
/// Only the install section is walked.
fn npm_install_entries(doc: &Value, bundled: bool) -> impl Iterator<Item = NpmLockEntry<'_>> {
    let mut entries = Vec::new();
    match npm_lock_install_section(doc) {
        NpmLockSection::Packages => walk_npm_packages(doc, &mut entries),
        NpmLockSection::Legacy => walk_npm_legacy(doc, &mut entries),
    }
    entries
        .into_iter()
        .filter(move |entry| entry.is_dependency() && !entry.link && entry.bundled == bundled)
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

    /// A legacy `dependencies` node keyed `key`, with an npm alias decoded
    /// ([`npm_legacy_identity`]).
    fn legacy(key: &'a str, node: &'a Value) -> Self {
        let mut out = NpmLockNode::of(key, node);
        let (name, version) = npm_legacy_identity(key, out.version);
        out.name = name;
        out.version = version;
        out
    }
}

/// The package a legacy `dependencies` node (lockfileVersion 1, and the v2
/// mirror) stands for. npm 6 keys the node by the name it installs under
/// and, for an alias install (`npm i lp@npm:left-pad@1.3.0`), spells the
/// target in `version`: `"lp": {"version": "npm:left-pad@1.3.0"}` is an
/// install of `left-pad@1.3.0` (the `packages` entries carry a `name` field
/// instead). Anything else is the key at its own `version`. Every reader and
/// writer of the legacy tree identifies nodes through this one rule (#432).
pub(crate) fn npm_legacy_identity<'a>(
    key: &'a str,
    version: Option<&'a str>,
) -> (&'a str, Option<&'a str>) {
    let alias = version
        .and_then(|v| v.strip_prefix("npm:"))
        // `@` at index 0 opens a scope; the version follows the LAST `@`.
        .and_then(|spec| {
            spec.rfind('@')
                .filter(|&at| at > 0)
                .map(|at| spec.split_at(at))
        })
        .map(|(name, at_version)| (name, &at_version[1..]))
        .filter(|(_, v)| !v.is_empty());
    match alias {
        Some((name, version)) => (name, Some(version)),
        None => (key, version),
    }
}

fn npm_flag(node: &Value, key: &str) -> bool {
    node.get(key).and_then(Value::as_bool).unwrap_or(false)
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
    let doc: Value = crate::vendor::common::parse_json_manifest(&bytes?).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// One lock with an alias, a scoped package, a `~` / `/` key, a nested
    /// legacy tree, a link, a bundled copy and a git entry: the one walk
    /// addresses every entry, and each caller's view is a filter over it
    /// (#663).
    #[test]
    fn npm_lock_entries_address_every_entry_once() {
        let doc = serde_json::json!({
            "lockfileVersion": 2,
            "packages": {
                "": { "name": "root", "version": "0.0.0" },
                "packages/ws": { "name": "ws-member", "version": "1.0.0" },
                "node_modules/ws-member": { "resolved": "packages/ws", "link": true },
                "node_modules/@scope/pkg": {
                    "version": "2.0.0",
                    "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz",
                    "integrity": "sha512-AAAA"
                },
                "node_modules/@scope/pkg/node_modules/t~x": { "version": "0.1.0" },
                "node_modules/lp": { "name": "left-pad", "version": "1.3.0" },
                "node_modules/host": { "version": "1.0.0" },
                "node_modules/host/node_modules/inner": { "version": "1.0.0", "inBundle": true },
                "node_modules/g": {
                    "version": "1.0.0",
                    "resolved": "git+ssh://git@github.com/x/g.git#abc"
                }
            },
            "dependencies": {
                "@scope/pkg": {
                    "version": "2.0.0",
                    "dependencies": { "t~x": { "version": "0.1.0" } }
                },
                "lp": { "version": "npm:left-pad@1.3.0" },
                "host": {
                    "version": "1.0.0",
                    "dependencies": { "inner": { "version": "1.0.0", "bundled": true } }
                }
            }
        });
        let entries = npm_lock_entries(&doc);
        // (section, key, pointer, packages_key, location, name, version,
        //  link, bundled, is_dependency, is_legacy_alias)
        type Row<'a> = (
            NpmLockSection,
            &'a str,
            &'a str,
            &'a str,
            &'a str,
            &'a str,
            Option<&'a str>,
            bool,
            bool,
            bool,
            bool,
        );
        use NpmLockSection::{Legacy as L, Packages as P};
        let expected: Vec<Row<'_>> = vec![
            (
                P,
                "",
                "/packages/",
                "",
                "",
                "root",
                Some("0.0.0"),
                false,
                false,
                false,
                false,
            ),
            (
                P,
                "packages/ws",
                "/packages/packages~1ws",
                "packages/ws",
                "packages/ws",
                "ws-member",
                Some("1.0.0"),
                false,
                false,
                false,
                false,
            ),
            (
                P,
                "node_modules/ws-member",
                "/packages/node_modules~1ws-member",
                "node_modules/ws-member",
                "node_modules/ws-member",
                "ws-member",
                None,
                true,
                false,
                true,
                false,
            ),
            (
                P,
                "node_modules/@scope/pkg",
                "/packages/node_modules~1@scope~1pkg",
                "node_modules/@scope/pkg",
                "node_modules/@scope/pkg",
                "@scope/pkg",
                Some("2.0.0"),
                false,
                false,
                true,
                false,
            ),
            (
                P,
                "node_modules/@scope/pkg/node_modules/t~x",
                "/packages/node_modules~1@scope~1pkg~1node_modules~1t~0x",
                "node_modules/@scope/pkg/node_modules/t~x",
                "node_modules/@scope/pkg/node_modules/t~x",
                "t~x",
                Some("0.1.0"),
                false,
                false,
                true,
                false,
            ),
            (
                P,
                "node_modules/lp",
                "/packages/node_modules~1lp",
                "node_modules/lp",
                "node_modules/lp",
                "left-pad",
                Some("1.3.0"),
                false,
                false,
                true,
                false,
            ),
            (
                P,
                "node_modules/host",
                "/packages/node_modules~1host",
                "node_modules/host",
                "node_modules/host",
                "host",
                Some("1.0.0"),
                false,
                false,
                true,
                false,
            ),
            (
                P,
                "node_modules/host/node_modules/inner",
                "/packages/node_modules~1host~1node_modules~1inner",
                "node_modules/host/node_modules/inner",
                "node_modules/host/node_modules/inner",
                "inner",
                Some("1.0.0"),
                false,
                true,
                true,
                false,
            ),
            (
                P,
                "node_modules/g",
                "/packages/node_modules~1g",
                "node_modules/g",
                "node_modules/g",
                "g",
                Some("1.0.0"),
                false,
                false,
                true,
                false,
            ),
            (
                L,
                "@scope/pkg",
                "/dependencies/@scope~1pkg",
                "node_modules/@scope/pkg",
                "@scope/pkg",
                "@scope/pkg",
                Some("2.0.0"),
                false,
                false,
                true,
                false,
            ),
            (
                L,
                "t~x",
                "/dependencies/@scope~1pkg/dependencies/t~0x",
                "node_modules/@scope/pkg/node_modules/t~x",
                "@scope/pkg > t~x",
                "t~x",
                Some("0.1.0"),
                false,
                false,
                true,
                false,
            ),
            (
                L,
                "lp",
                "/dependencies/lp",
                "node_modules/lp",
                "lp",
                "left-pad",
                Some("1.3.0"),
                false,
                false,
                true,
                true,
            ),
            (
                L,
                "host",
                "/dependencies/host",
                "node_modules/host",
                "host",
                "host",
                Some("1.0.0"),
                false,
                false,
                true,
                false,
            ),
            (
                L,
                "inner",
                "/dependencies/host/dependencies/inner",
                "node_modules/host/node_modules/inner",
                "host > inner",
                "inner",
                Some("1.0.0"),
                false,
                true,
                true,
                false,
            ),
        ];
        let actual: Vec<Row<'_>> = entries
            .iter()
            .map(|e| {
                (
                    e.section,
                    e.key,
                    e.pointer.as_str(),
                    e.packages_key.as_ref(),
                    e.location.as_ref(),
                    e.node.name,
                    e.node.version,
                    e.link,
                    e.bundled,
                    e.is_dependency(),
                    e.is_legacy_alias(),
                )
            })
            .collect();
        assert_eq!(actual, expected);
        // Every pointer addresses its own entry, so a caller can edit it
        // through `Value::pointer_mut`.
        for e in &entries {
            assert!(
                std::ptr::eq(doc.pointer(&e.pointer).unwrap(), e.value),
                "{}",
                e.pointer
            );
        }
        // A legacy mirror node's derived `packages_key` names its twin.
        for e in entries.iter().filter(|e| e.section == L) {
            let twin = entries
                .iter()
                .find(|p| p.section == P && p.key == e.packages_key)
                .unwrap();
            assert_eq!((twin.node.name, twin.bundled), (e.node.name, e.bundled));
        }

        // The install views npm >= 7 reads: `packages`, minus the root,
        // the member, the link, and (split out) the bundled copy.
        fn names<'a>(nodes: Vec<NpmLockNode<'a>>) -> Vec<&'a str> {
            nodes.into_iter().map(|n| n.name).collect()
        }
        assert_eq!(
            names(npm_lock_nodes(&doc)),
            ["@scope/pkg", "t~x", "left-pad", "host", "g"]
        );
        let located: Vec<(String, &str)> = npm_lock_located_nodes(&doc)
            .into_iter()
            .map(|(at, n)| (at, n.name))
            .collect();
        assert_eq!(
            located[1],
            ("node_modules/@scope/pkg/node_modules/t~x".into(), "t~x")
        );
        let bundled: Vec<(String, &str)> = npm_lock_bundled_nodes(&doc)
            .into_iter()
            .map(|(at, n)| (at, n.name))
            .collect();
        assert_eq!(
            bundled,
            [("node_modules/host/node_modules/inner".into(), "inner")]
        );
        // The v2 mirror npm 6 reads: alias decoded, bundled copy skipped.
        assert_eq!(
            names(npm_lock_legacy_mirror_nodes(&doc)),
            ["@scope/pkg", "t~x", "left-pad", "host"]
        );

        // A lockfileVersion 1 lock: the legacy tree IS the install tree,
        // located by its `>` chain, and has no mirror.
        let v1 = serde_json::json!({
            "lockfileVersion": 1,
            "dependencies": doc["dependencies"].clone()
        });
        assert_eq!(
            names(npm_lock_nodes(&v1)),
            ["@scope/pkg", "t~x", "left-pad", "host"]
        );
        let bundled: Vec<(String, &str)> = npm_lock_bundled_nodes(&v1)
            .into_iter()
            .map(|(at, n)| (at, n.name))
            .collect();
        assert_eq!(bundled, [("host > inner".into(), "inner")]);
        assert!(npm_lock_legacy_mirror_nodes(&v1).is_empty());
    }

    /// The legacy walk stops at the depth bound instead of recursing on a
    /// tamper-crafted tree (built in memory: serde_json's parser would
    /// refuse it first).
    #[test]
    fn npm_lock_entries_bound_the_legacy_depth() {
        let mut node = serde_json::json!({ "version": "1.0.0" });
        for _ in 0..(MAX_LEGACY_NPM_DEPTH + 10) {
            node = serde_json::json!({ "version": "1.0.0", "dependencies": { "d": node } });
        }
        let doc = serde_json::json!({ "dependencies": { "d": node } });
        assert_eq!(npm_lock_entries(&doc).len(), MAX_LEGACY_NPM_DEPTH + 1);
    }
}
