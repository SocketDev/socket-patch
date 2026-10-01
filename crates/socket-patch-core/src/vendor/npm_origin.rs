//! Which `package-lock.json` / `npm-shrinkwrap.json` entries npm installs
//! from the registry, and which it installs from somewhere else.
//!
//! npm installs a git (`github:user/repo`, `git+ssh://…`), remote-tarball
//! (`https://…/x.tgz`) or local (`file:…`) dependency from the DEPENDENT's
//! spec, not from the lock entry's `resolved`: rewriting that entry's
//! `resolved` / `integrity` changes nothing at install time (`npm ci` fetches
//! the git checkout or the URL again, and the next `npm install` writes the
//! original `resolved` back). The hosted rewriter
//! (`patch::redirect::rewrite_one_npm_lock`), the vendored backend
//! (`vendor::npm_lock`) and lockfile discovery (`vex::discover::npm`) all
//! share [`npm_non_registry_entries`], so a copy the rewriters refuse is
//! never attested either.
//!
//! An entry is non-registry when EITHER
//!
//! * an inbound dependency spec that resolves to it is not a registry spec
//!   ([`npm_spec_is_registry`]). The edges are the `dependencies`,
//!   `optionalDependencies`, `devDependencies` and `peerDependencies` of
//!   every `packages` entry (the root `""`, workspace members and installed
//!   packages alike), resolved with node's lookup order: the dependent's own
//!   `node_modules/`, then each ancestor directory's;
//! * or its own `resolved` names a git or `file:` source. socket-patch's own
//!   vendored wiring (`file:.socket/vendor/…`) is not one: the vendored
//!   backend only rewrites `resolved`, never the dependent's spec.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::constants::SOCKET_DIR;

/// The dependency maps whose specs npm resolves against `packages` entries.
const EDGE_FIELDS: [&str; 4] = [
    "dependencies",
    "optionalDependencies",
    "devDependencies",
    "peerDependencies",
];

/// The `packages` key a lockfileVersion 2 legacy `dependencies` node
/// mirrors: `parent` is the mirrored key of the enclosing node (`""` at the
/// top of the tree), `name` the node's key in its `dependencies` map.
pub(crate) fn legacy_packages_key(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        format!("node_modules/{name}")
    } else {
        format!("{parent}/node_modules/{name}")
    }
}

/// Every `packages` key npm installs from a non-registry source, mapped to
/// the reason (for the skip warnings). Empty for a lock without `packages`:
/// in a lockfileVersion 1 `dependencies` tree a git / URL / `file:` entry's
/// `version` is that spec, so it never matches a patch's `name@version`.
pub(crate) fn npm_non_registry_entries(lock: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(packages) = lock.get("packages").and_then(Value::as_object) else {
        return out;
    };
    for (key, entry) in packages {
        if !key.contains("node_modules/") {
            continue;
        }
        if let Some(resolved) = entry.get("resolved").and_then(Value::as_str) {
            if resolved_is_non_registry(resolved) {
                out.insert(key.clone(), format!("it resolves to {resolved:?}"));
            }
        }
    }
    for (from, entry) in packages {
        for field in EDGE_FIELDS {
            let Some(deps) = entry.get(field).and_then(Value::as_object) else {
                continue;
            };
            for (dep_name, spec) in deps {
                let Some(spec) = spec.as_str() else {
                    continue;
                };
                if npm_spec_is_registry(spec) {
                    continue;
                }
                let Some(target) = resolve_edge(packages, from, dep_name) else {
                    continue;
                };
                let dependent = if from.is_empty() {
                    "the project".to_string()
                } else {
                    format!("`{from}`")
                };
                out.entry(target).or_insert_with(|| {
                    format!(
                        "{dependent} depends on it as {spec:?}, which npm installs from that spec"
                    )
                });
            }
        }
    }
    out
}

/// The `packages` key node's module lookup picks for `dep_name` required
/// from the package at `from`: `<from>/node_modules/<dep>`, then the same
/// under each ancestor directory, up to the project root.
fn resolve_edge(
    packages: &serde_json::Map<String, Value>,
    from: &str,
    dep_name: &str,
) -> Option<String> {
    let mut dir = from;
    loop {
        let candidate = if dir.is_empty() {
            format!("node_modules/{dep_name}")
        } else {
            format!("{dir}/node_modules/{dep_name}")
        };
        if packages.contains_key(&candidate) {
            return Some(candidate);
        }
        if dir.is_empty() {
            return None;
        }
        dir = dir.rsplit_once('/').map_or("", |(parent, _)| parent);
    }
}

/// A lock `resolved` that is a git or local source rather than a tarball
/// url (see the module docs for socket-patch's own `file:` wiring).
fn resolved_is_non_registry(resolved: &str) -> bool {
    const GIT: [&str; 7] = [
        "git+",
        "git:",
        "git@",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
    ];
    if GIT.iter().any(|p| resolved.starts_with(p)) {
        return true;
    }
    match resolved.strip_prefix("file:") {
        Some(path) => {
            let path = path.trim_start_matches("./");
            !path.starts_with(&format!("{SOCKET_DIR}/vendor/"))
        }
        None => false,
    }
}

/// Whether npm resolves `spec` against the registry: a version, a semver
/// range, a dist-tag, or an `npm:` alias of one. Everything else (git,
/// GitHub shorthand, a url, a path, a tarball file name) is installed from
/// the spec itself. Mirrors npm-package-arg's classification.
pub(crate) fn npm_spec_is_registry(spec: &str) -> bool {
    let spec = spec.trim();
    if let Some(alias) = spec.strip_prefix("npm:") {
        // `npm:name`, `npm:name@range`, `npm:@scope/name@range`.
        let unscoped = alias.strip_prefix('@').unwrap_or(alias);
        return match unscoped.split_once('@') {
            Some((_, range)) => npm_spec_is_registry(range),
            None => true,
        };
    }
    // A scheme (`git+ssh:`, `github:`, `https:`, `file:`, a `C:` drive), a
    // path (`./x`, `../x`, `/x`, `~/x`), GitHub shorthand (`user/repo`) or
    // a tarball file name. No semver range or dist-tag contains ':' or '/'.
    if spec.contains(':') || spec.contains('/') || spec.contains('\\') {
        return false;
    }
    if spec.starts_with('.') {
        return false;
    }
    let lower = spec.to_ascii_lowercase();
    !(lower.ends_with(".tgz") || lower.ends_with(".tar.gz") || lower.ends_with(".tar"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn registry_specs_are_recognized() {
        for spec in [
            "",
            "*",
            "1.3.0",
            "^1.3.0",
            "~1.3.0",
            ">=1 <2",
            "1.x || 2",
            "latest",
            "next",
            "npm:left-pad@1.3.0",
            "npm:@scope/pad@^1",
            "npm:left-pad",
        ] {
            assert!(npm_spec_is_registry(spec), "{spec:?} is a registry spec");
        }
    }

    #[test]
    fn non_registry_specs_are_recognized() {
        for spec in [
            "github:stevemao/left-pad#v1.3.0",
            "stevemao/left-pad",
            "stevemao/left-pad#v1.3.0",
            "git+ssh://git@github.com/stevemao/left-pad.git#ff8e7ba",
            "git+https://github.com/stevemao/left-pad.git",
            "git://github.com/stevemao/left-pad.git",
            "gitlab:user/repo",
            "bitbucket:user/repo",
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "http://example.com/left-pad.tgz",
            "file:../left-pad-1.3.0.tgz",
            "file:vendor/left-pad",
            "./left-pad",
            "../left-pad",
            "/abs/left-pad",
            "~/left-pad",
            "left-pad-1.3.0.tgz",
            "C:\\pkgs\\left-pad.tgz",
            "npm:left-pad@github:stevemao/left-pad",
        ] {
            assert!(
                !npm_spec_is_registry(spec),
                "{spec:?} is not a registry spec"
            );
        }
    }

    fn lock(packages: Value) -> Value {
        json!({ "lockfileVersion": 3, "packages": packages })
    }

    #[test]
    fn a_direct_git_dependency_is_non_registry() {
        let lock = lock(json!({
            "": { "dependencies": { "left-pad": "github:stevemao/left-pad#v1.3.0" } },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "git+ssh://git@github.com/stevemao/left-pad.git#ff8e7ba"
            }
        }));
        let found = npm_non_registry_entries(&lock);
        assert!(found.contains_key("node_modules/left-pad"), "{found:?}");
    }

    #[test]
    fn a_rewired_git_dependency_is_still_non_registry_by_its_spec() {
        // After a rewrite the entry's `resolved` is a hosted url or our own
        // `file:.socket/vendor/…` tarball; the dependent's spec still says git.
        for resolved in [
            "https://patch.socket.dev/npm/left-pad/-/left-pad-1.3.0.tgz",
            "file:.socket/vendor/npm/11111111-2222-4333-8444-555555555555/left-pad-1.3.0.tgz",
        ] {
            let lock = lock(json!({
                "": { "dependencies": { "left-pad": "github:stevemao/left-pad#v1.3.0" } },
                "node_modules/left-pad": { "version": "1.3.0", "resolved": resolved }
            }));
            assert!(npm_non_registry_entries(&lock).contains_key("node_modules/left-pad"));
        }
    }

    #[test]
    fn a_remote_tarball_dependency_is_non_registry() {
        // The url is the registry's own tarball, but npm installs it from
        // the spec: only the dependent's spec tells the two apart.
        let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        let lock = lock(json!({
            "": { "dependencies": { "left-pad": url } },
            "node_modules/left-pad": { "version": "1.3.0", "resolved": url }
        }));
        assert!(npm_non_registry_entries(&lock).contains_key("node_modules/left-pad"));
    }

    #[test]
    fn a_file_tarball_dependency_is_non_registry() {
        let lock = lock(json!({
            "": { "dependencies": { "left-pad": "file:../left-pad-1.3.0.tgz" } },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "file:../left-pad-1.3.0.tgz"
            }
        }));
        assert!(npm_non_registry_entries(&lock).contains_key("node_modules/left-pad"));
    }

    #[test]
    fn transitive_edges_resolve_with_node_lookup_order() {
        // `a` depends on left-pad from git and gets its own nested copy;
        // the hoisted copy the root depends on is a registry install.
        let lock = lock(json!({
            "": { "dependencies": { "a": "^1.0.0", "left-pad": "^1.3.0" } },
            "node_modules/a": {
                "version": "1.0.0",
                "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                "dependencies": { "left-pad": "github:stevemao/left-pad#v1.3.0" }
            },
            "node_modules/a/node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "git+ssh://git@github.com/stevemao/left-pad.git#ff8e7ba"
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            }
        }));
        let found = npm_non_registry_entries(&lock);
        assert!(found.contains_key("node_modules/a/node_modules/left-pad"));
        assert!(!found.contains_key("node_modules/left-pad"), "{found:?}");
        assert!(!found.contains_key("node_modules/a"));
    }

    #[test]
    fn a_workspace_member_edge_walks_up_to_the_hoisted_copy() {
        let url = "https://example.com/left-pad-1.3.0.tgz";
        let lock = lock(json!({
            "": { "workspaces": ["packages/*"] },
            "packages/app": { "dependencies": { "left-pad": url } },
            "node_modules/app": { "resolved": "packages/app", "link": true },
            "node_modules/left-pad": { "version": "1.3.0", "resolved": url }
        }));
        assert!(npm_non_registry_entries(&lock).contains_key("node_modules/left-pad"));
    }

    #[test]
    fn registry_dependencies_are_not_flagged() {
        let lock = lock(json!({
            "": { "dependencies": { "left-pad": "1.3.0", "alias": "npm:left-pad@1.3.0" } },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            },
            "node_modules/alias": {
                "name": "left-pad",
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
            }
        }));
        assert!(npm_non_registry_entries(&lock).is_empty());
    }
}
