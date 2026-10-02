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
//!
//! An inbound spec the project's `overrides` replace with a registry spec
//! does not count (#490): npm installs the override, and the lock records
//! the registry tarball while the dependent's entry keeps its own raw
//! spec. npm doesn't record `overrides` in the lock, so they come from the
//! root `package.json` ([`NpmOverrides`]). Only overrides that clearly apply
//! to the edge clear it (see [`NpmOverrides::replacement`]). In any unclear
//! case the edge keeps counting, which leaves the copy unpatched and
//! reported rather than wrongly attested.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::constants::SOCKET_DIR;

/// The root `package.json` fields that decide what npm installs for an
/// overridden edge: its `overrides` and its own dependency specs (for the
/// `$name` references an override value may use). Empty (no override
/// applies) when the manifest is absent or unparseable.
#[derive(Debug, Clone, Default)]
pub(crate) struct NpmOverrides {
    rules: Map<String, Value>,
    root_deps: Map<String, Value>,
}

impl NpmOverrides {
    /// From the parsed root `package.json`.
    pub(crate) fn from_manifest(manifest: &Value) -> Self {
        let rules = manifest
            .get("overrides")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut root_deps = Map::new();
        // npm resolves `$name` against the root's direct dependencies.
        for field in EDGE_FIELDS {
            if let Some(deps) = manifest.get(field).and_then(Value::as_object) {
                for (name, spec) in deps {
                    root_deps
                        .entry(name.clone())
                        .or_insert_with(|| spec.clone());
                }
            }
        }
        NpmOverrides { rules, root_deps }
    }

    /// From the root `package.json` text (a leading BOM is skipped, as npm
    /// does); empty when it isn't valid JSON.
    pub(crate) fn from_manifest_text(text: &str) -> Self {
        super::common::parse_json_text(text)
            .map(|manifest| Self::from_manifest(&manifest))
            .unwrap_or_default()
    }

    /// From `<project_root>/package.json`; empty when it can't be read.
    pub(crate) async fn read(project_root: &std::path::Path) -> Self {
        match crate::utils::fs::read_regular_to_bytes(&project_root.join("package.json")).await {
            Ok(bytes) => super::common::parse_json_manifest(&bytes)
                .map(|manifest| Self::from_manifest(&manifest))
                .unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// The spec an override makes npm install for the edge `dep_name@spec`
    /// whose dependent sits at the lock key `from`, or `None` when no
    /// override clearly applies.
    ///
    /// A rule applies when its key names `dep_name` with no selector (or
    /// with `spec` itself as the selector), and every enclosing rule names
    /// the dependent or one of its physical ancestors (outermost first),
    /// with no selector or that package's exact version. As in npm, the
    /// rule scoped to the closest ancestor wins (then the most deeply
    /// nested one), and a winning `*` or empty value is a no-op that leaves
    /// the dependent's own spec in effect.
    ///
    /// Anything this can't decide exactly makes the answer unclear, and
    /// then no override applies: two equally close rules that disagree, a
    /// target selector other than `spec`, or an enclosing selector that is
    /// a range (it may match the ancestor, so a rule beneath it may be the
    /// one npm picks).
    fn replacement(
        &self,
        packages: &Map<String, Value>,
        from: &str,
        dep_name: &str,
        spec: &str,
    ) -> Option<String> {
        if self.rules.is_empty() {
            return None;
        }
        let chain = dependent_chain(packages, from);
        let mut search = RuleSearch::default();
        self.visit(&self.rules, &chain, 0, 0, dep_name, spec, &mut search);
        if search.unclear {
            return None;
        }
        let best = search.best.filter(|b| !b.contested)?;
        // npm ignores a `*` (or empty) replacement: the raw spec stays.
        let value = best.value.trim();
        (!value.is_empty() && value != "*").then(|| best.value)
    }

    /// Search `rules` (nested `depth` levels deep; the enclosing rules
    /// matched ancestors up to `chain[from_ix - 1]`) for the edge's rule.
    #[allow(clippy::too_many_arguments)]
    fn visit(
        &self,
        rules: &Map<String, Value>,
        chain: &[(String, Option<String>)],
        from_ix: usize,
        depth: usize,
        dep_name: &str,
        spec: &str,
        search: &mut RuleSearch,
    ) {
        for (key, value) in rules {
            if key == "." {
                continue;
            }
            let (name, selector) = split_selector(key);
            // A rule for the edge's own package.
            if name == dep_name {
                match selector {
                    None => self.offer(value, (from_ix, depth), search),
                    Some(sel) if sel == spec => self.offer(value, (from_ix, depth), search),
                    // npm matches other selectors against the spec by
                    // semver intersection, which isn't modelled here.
                    Some(_) => search.unclear = true,
                }
            }
            // A rule scoped to a package on the dependent's chain: every
            // matching ancestor, so the closest one is ranked too.
            if let Some(children) = value.as_object() {
                for (ix, (anc_name, anc_version)) in chain.iter().enumerate().skip(from_ix) {
                    if anc_name != name {
                        continue;
                    }
                    let applies = match selector {
                        None => true,
                        Some(sel) if anc_version.as_deref() == Some(sel) => true,
                        // Another exact version: the rule can't apply.
                        Some(sel) if is_exact_version(sel) && anc_version.is_some() => false,
                        // A range (or an unknown ancestor version): it may
                        // apply, so a rule for the edge beneath it may be
                        // the one npm picks.
                        Some(_) => {
                            if mentions(children, dep_name) {
                                search.unclear = true;
                            }
                            false
                        }
                    };
                    if applies {
                        self.visit(children, chain, ix + 1, depth + 1, dep_name, spec, search);
                    }
                }
            }
        }
    }

    /// Rank a rule for the edge; one whose value can't be resolved (a
    /// `$name` the root doesn't declare, a non-string) makes it unclear.
    fn offer(&self, value: &Value, rank: (usize, usize), search: &mut RuleSearch) {
        match self.rule_value(value) {
            Some(replacement) => BestRule::offer(&mut search.best, rank, replacement),
            // An object with only nested rules overrides nothing itself,
            // but still shadows a farther rule: a no-op, like `*`.
            None if value.as_object().is_some_and(|o| !o.contains_key(".")) => {
                BestRule::offer(&mut search.best, rank, String::new())
            }
            None => search.unclear = true,
        }
    }

    /// A rule's replacement spec: the string itself, or an object's `"."`,
    /// with a `$name` reference resolved against the root's dependencies.
    fn rule_value(&self, value: &Value) -> Option<String> {
        let raw = match value {
            Value::String(s) => s.as_str(),
            Value::Object(obj) => obj.get(".")?.as_str()?,
            _ => return None,
        };
        match raw.strip_prefix('$') {
            Some(reference) => self.root_deps.get(reference)?.as_str().map(str::to_string),
            None => Some(raw.to_string()),
        }
    }
}

/// What [`NpmOverrides::visit`] has found for one edge.
#[derive(Debug, Default)]
struct RuleSearch {
    best: Option<BestRule>,
    /// A rule that may apply couldn't be evaluated exactly.
    unclear: bool,
}

/// Whether `rules` (at any depth) holds a rule keyed by `dep_name`.
fn mentions(rules: &Map<String, Value>, dep_name: &str) -> bool {
    rules.iter().any(|(key, value)| {
        split_selector(key).0 == dep_name
            || value
                .as_object()
                .is_some_and(|children| mentions(children, dep_name))
    })
}

/// A plain `major.minor.patch` version, optionally with a prerelease or
/// build suffix: never a range.
fn is_exact_version(selector: &str) -> bool {
    let core_end = selector.find(['-', '+']).unwrap_or(selector.len());
    let (core, suffix) = selector.split_at(core_end);
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && suffix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'+' | b'.'))
}

/// The winning override rule so far: ranked by how close its innermost
/// enclosing ancestor is to the dependent (`chain` entries consumed), then
/// by nesting depth. `contested` when an equally ranked rule disagrees.
#[derive(Debug)]
struct BestRule {
    rank: (usize, usize),
    value: String,
    contested: bool,
}

impl BestRule {
    fn offer(best: &mut Option<BestRule>, rank: (usize, usize), value: String) {
        match best {
            Some(b) if rank < b.rank => {}
            Some(b) if rank == b.rank => b.contested |= b.value != value,
            _ => {
                *best = Some(BestRule {
                    rank,
                    value,
                    contested: false,
                })
            }
        }
    }
}

/// `name` or `name@selector` (a scoped `@scope/name` keeps its leading `@`).
fn split_selector(key: &str) -> (&str, Option<&str>) {
    let (scope_at, rest) = match key.strip_prefix('@') {
        Some(rest) => (1, rest),
        None => (0, key),
    };
    match rest.split_once('@') {
        Some((name, selector)) => (&key[..scope_at + name.len()], Some(selector)),
        None => (key, None),
    }
}

/// The packages on the path from the project root to the lock key `from`,
/// outermost first, as `(name, version)`: each `node_modules/<name>`
/// segment's entry (its `name` field for an alias, else the segment). The
/// root and workspace members contribute nothing.
fn dependent_chain(packages: &Map<String, Value>, from: &str) -> Vec<(String, Option<String>)> {
    let mut chain = Vec::new();
    let mut rest = from;
    let mut prefix = String::new();
    while let Some(ix) = rest.find("node_modules/") {
        let after = &rest[ix + "node_modules/".len()..];
        // A package segment runs to the next nested `node_modules/`.
        let seg_len = after.find("/node_modules/").unwrap_or(after.len());
        let consumed = ix + "node_modules/".len() + seg_len;
        prefix.push_str(&rest[..consumed]);
        let segment = &after[..seg_len];
        let entry = packages.get(&prefix);
        let name = entry
            .and_then(|e| e.get("name"))
            .and_then(Value::as_str)
            .unwrap_or(segment)
            .to_string();
        let version = entry
            .and_then(|e| e.get("version"))
            .and_then(Value::as_str)
            .map(str::to_string);
        chain.push((name, version));
        rest = &rest[consumed..];
    }
    chain
}

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
pub(crate) fn npm_non_registry_entries(
    lock: &Value,
    overrides: &NpmOverrides,
) -> BTreeMap<String, String> {
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
                // An override that swaps the spec for a registry one makes
                // npm install the registry release instead (#490).
                if overrides
                    .replacement(packages, from, dep_name, spec)
                    .is_some_and(|replacement| npm_spec_is_registry(&replacement))
                {
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
        let found = npm_non_registry_entries(&lock, &NpmOverrides::default());
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
            assert!(npm_non_registry_entries(&lock, &NpmOverrides::default())
                .contains_key("node_modules/left-pad"));
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
        assert!(npm_non_registry_entries(&lock, &NpmOverrides::default())
            .contains_key("node_modules/left-pad"));
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
        assert!(npm_non_registry_entries(&lock, &NpmOverrides::default())
            .contains_key("node_modules/left-pad"));
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
        let found = npm_non_registry_entries(&lock, &NpmOverrides::default());
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
        assert!(npm_non_registry_entries(&lock, &NpmOverrides::default())
            .contains_key("node_modules/left-pad"));
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
        assert!(npm_non_registry_entries(&lock, &NpmOverrides::default()).is_empty());
    }

    /// The #490 lock: `pkga` depends on left-pad from git, the project
    /// overrides it, and npm installs the registry release.
    fn overridden_git_lock(left_pad_resolved: &str) -> Value {
        lock(json!({
            "": { "dependencies": { "pkga": "file:pkga-1.0.0.tgz" } },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": left_pad_resolved,
                "integrity": "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
            },
            "node_modules/pkga": {
                "version": "1.0.0",
                "resolved": "file:pkga-1.0.0.tgz",
                "dependencies": { "left-pad": "github:stevemao/left-pad#v1.3.0" }
            }
        }))
    }

    fn manifest(overrides: Value) -> NpmOverrides {
        NpmOverrides::from_manifest(&json!({
            "name": "app",
            "dependencies": { "pkga": "file:pkga-1.0.0.tgz", "left-pad": "1.3.0" },
            "overrides": overrides
        }))
    }

    const REGISTRY_TGZ: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";

    #[test]
    fn issue_490_a_registry_override_of_a_git_edge_is_a_registry_install() {
        // Fresh lock, and the lock after a hosted redirect.
        for resolved in [
            REGISTRY_TGZ,
            "https://patch.socket.dev/npm/left-pad/-/left-pad-1.3.0.tgz",
        ] {
            let lock = overridden_git_lock(resolved);
            for overrides in [
                json!({ "left-pad": "1.3.0" }),
                json!({ "left-pad": "^1.3.0" }),
                json!({ "left-pad": { ".": "1.3.0" } }),
                json!({ "left-pad": "$left-pad" }),
                json!({ "pkga": { "left-pad": "1.3.0" } }),
                json!({ "pkga@1.0.0": { "left-pad": "1.3.0" } }),
                json!({ "left-pad@github:stevemao/left-pad#v1.3.0": "1.3.0" }),
            ] {
                let found = npm_non_registry_entries(&lock, &manifest(overrides.clone()));
                assert!(
                    !found.contains_key("node_modules/left-pad"),
                    "{overrides} / {resolved}: {found:?}"
                );
                // The dependent itself is still a `file:` install.
                assert!(found.contains_key("node_modules/pkga"), "{found:?}");
            }
        }
    }

    #[test]
    fn issue_490_overrides_that_do_not_clearly_apply_keep_the_edge() {
        let lock = overridden_git_lock(REGISTRY_TGZ);
        for overrides in [
            // No override at all (the #326 case).
            json!({}),
            // Scoped under a package that isn't on the dependent's chain.
            json!({ "other": { "left-pad": "1.3.0" } }),
            // A parent selector for another version of the dependent.
            json!({ "pkga@2.0.0": { "left-pad": "1.3.0" } }),
            // A selector naming a different spec.
            json!({ "left-pad@1.2.0": "1.3.0" }),
            // An override to another non-registry source.
            json!({ "left-pad": "github:someone/left-pad" }),
            json!({ "left-pad": "file:../left-pad" }),
            // A `$` reference to a dependency the root doesn't declare.
            json!({ "left-pad": "$missing" }),
            // An object rule without its own `"."` spec.
            json!({ "left-pad": { "other": "1.0.0" } }),
            // A different package's override.
            json!({ "right-pad": "1.0.0" }),
        ] {
            let found = npm_non_registry_entries(&lock, &manifest(overrides.clone()));
            assert!(
                found.contains_key("node_modules/left-pad"),
                "{overrides}: {found:?}"
            );
        }
    }

    #[test]
    fn issue_490_the_innermost_override_wins() {
        let lock = overridden_git_lock(REGISTRY_TGZ);
        // Top level says registry, but the rule scoped to pkga says git.
        let found = npm_non_registry_entries(
            &lock,
            &manifest(json!({
                "left-pad": "1.3.0",
                "pkga": { "left-pad": "github:someone/left-pad" }
            })),
        );
        assert!(found.contains_key("node_modules/left-pad"), "{found:?}");
        // And the other way round.
        let found = npm_non_registry_entries(
            &lock,
            &manifest(json!({
                "left-pad": "github:someone/left-pad",
                "pkga": { "left-pad": "1.3.0" }
            })),
        );
        assert!(!found.contains_key("node_modules/left-pad"), "{found:?}");
    }

    #[test]
    fn issue_490_the_closest_ancestor_rule_wins_whatever_the_key_order() {
        // `@scope/b` under `a` depends on left-pad from git. Rules scoped to
        // `a` (farther) and `@scope/b` (closer) sit at the same nesting
        // depth; the closer one decides, in either key order.
        let lock = lock(json!({
            "": { "dependencies": { "a": "^1.0.0" } },
            "node_modules/a": { "version": "1.0.0", "resolved": REGISTRY_TGZ },
            "node_modules/a/node_modules/@scope/b": {
                "version": "2.0.0",
                "resolved": REGISTRY_TGZ,
                "dependencies": { "left-pad": "github:stevemao/left-pad#v1.3.0" }
            },
            "node_modules/a/node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": REGISTRY_TGZ
            }
        }));
        let key = "node_modules/a/node_modules/left-pad";
        let found = |overrides: Value| {
            npm_non_registry_entries(
                &lock,
                &NpmOverrides::from_manifest(&json!({ "overrides": overrides })),
            )
            .contains_key(key)
        };
        for (closer, farther, non_registry) in [
            ("github:someone/left-pad", "1.3.0", true),
            ("1.3.0", "github:someone/left-pad", false),
        ] {
            // `@scope/b` sorts before `a`, so the farther rule is visited
            // last; swapping which ancestor holds the registry spec covers
            // both outcomes.
            assert_eq!(
                found(json!({
                    "@scope/b": { "left-pad": closer },
                    "a": { "left-pad": farther }
                })),
                non_registry,
                "closer {closer} / farther {farther}"
            );
        }
    }

    #[test]
    fn issue_490_equally_close_rules_that_disagree_keep_the_edge() {
        let lock = overridden_git_lock(REGISTRY_TGZ);
        // `pkga` and `pkga@1.0.0` both scope to the dependent at the same
        // depth: npm's pick between them isn't modelled, so stay cautious.
        let found = npm_non_registry_entries(
            &lock,
            &manifest(json!({
                "pkga": { "left-pad": "1.3.0" },
                "pkga@1.0.0": { "left-pad": "github:someone/left-pad" }
            })),
        );
        assert!(found.contains_key("node_modules/left-pad"), "{found:?}");
        // Agreeing rules are fine.
        let found = npm_non_registry_entries(
            &lock,
            &manifest(json!({
                "pkga": { "left-pad": "1.3.0" },
                "pkga@1.0.0": { "left-pad": "1.3.0" }
            })),
        );
        assert!(!found.contains_key("node_modules/left-pad"), "{found:?}");
    }

    #[test]
    fn issue_490_wildcard_and_empty_overrides_leave_the_raw_spec() {
        // npm ignores a `*` (or empty) replacement, so the dependent's URL
        // or git spec stays in effect (npm 10.9.4 `edge.js`). Covered for a
        // remote-tarball spec and a git spec, with `"."` objects too.
        let url = REGISTRY_TGZ;
        let url_lock = lock(json!({
            "": { "dependencies": { "left-pad": url } },
            "node_modules/left-pad": { "version": "1.3.0", "resolved": url }
        }));
        let git_lock = overridden_git_lock(REGISTRY_TGZ);
        for value in [json!("*"), json!(""), json!(" * "), json!({ ".": "*" })] {
            for (lock, label) in [(&url_lock, "url"), (&git_lock, "git")] {
                let found =
                    npm_non_registry_entries(lock, &manifest(json!({ "left-pad": value.clone() })));
                assert!(
                    found.contains_key("node_modules/left-pad"),
                    "{label} / {value}: {found:?}"
                );
            }
        }
        // A closer no-op shadows a farther registry rule, as in npm.
        let found = npm_non_registry_entries(
            &git_lock,
            &manifest(json!({ "left-pad": "1.3.0", "pkga": { "left-pad": "*" } })),
        );
        assert!(found.contains_key("node_modules/left-pad"), "{found:?}");
        let found = npm_non_registry_entries(
            &git_lock,
            &manifest(json!({
                "left-pad": "1.3.0",
                "pkga": { "left-pad": { "nested": "1.0.0" } }
            })),
        );
        assert!(found.contains_key("node_modules/left-pad"), "{found:?}");
    }

    #[test]
    fn issue_490_range_selectors_that_may_apply_keep_the_edge() {
        let lock = overridden_git_lock(REGISTRY_TGZ);
        let tgz = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
        for scoped in ["pkga@^1", "pkga@1.x", "pkga@>=1", "pkga@*", "pkga@1"] {
            // npm picks the narrower rule under `pkga@^1` (here a URL) over
            // the top-level registry rule, so the broader one can't clear
            // the edge while the selector is unevaluated.
            let found = npm_non_registry_entries(
                &lock,
                &manifest(json!({ "left-pad": "1.3.0", scoped: { "left-pad": tgz } })),
            );
            assert!(
                found.contains_key("node_modules/left-pad"),
                "{scoped}: {found:?}"
            );
        }
        // A range selector whose subtree never names the dependency, and an
        // exact selector for another version, don't block the clear.
        for overrides in [
            json!({ "left-pad": "1.3.0", "pkga@^1": { "other": "1.0.0" } }),
            json!({ "left-pad": "1.3.0", "pkga@2.0.0": { "left-pad": tgz } }),
        ] {
            let found = npm_non_registry_entries(&lock, &manifest(overrides.clone()));
            assert!(
                !found.contains_key("node_modules/left-pad"),
                "{overrides}: {found:?}"
            );
        }
        // A target selector other than the edge's own spec is unclear too.
        let found = npm_non_registry_entries(
            &lock,
            &manifest(json!({ "left-pad": "1.3.0", "left-pad@^1": "github:x/y" })),
        );
        assert!(found.contains_key("node_modules/left-pad"), "{found:?}");
    }

    #[test]
    fn exact_versions_are_told_from_ranges() {
        for exact in ["1.0.0", "10.2.33", "1.0.0-beta.1", "1.0.0+build.5"] {
            assert!(is_exact_version(exact), "{exact}");
        }
        for range in [
            "^1",
            "1",
            "1.x",
            "1.0",
            "~1.0.0",
            ">=1.0.0",
            "*",
            "1.0.0 || 2.0.0",
            "v1.0.0",
        ] {
            assert!(!is_exact_version(range), "{range}");
        }
    }

    #[test]
    fn issue_490_a_nested_dependent_matches_its_physical_ancestors() {
        // `@scope/b` under `a` depends on left-pad from git; the override is
        // scoped to `a`, two levels up.
        let lock = lock(json!({
            "": { "dependencies": { "a": "^1.0.0" } },
            "node_modules/a": { "version": "1.0.0", "resolved": REGISTRY_TGZ },
            "node_modules/a/node_modules/@scope/b": {
                "version": "2.0.0",
                "resolved": REGISTRY_TGZ,
                "dependencies": { "left-pad": "github:stevemao/left-pad#v1.3.0" }
            },
            "node_modules/a/node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": REGISTRY_TGZ
            }
        }));
        let scoped = |overrides: Value| {
            npm_non_registry_entries(
                &lock,
                &NpmOverrides::from_manifest(&json!({ "overrides": overrides })),
            )
        };
        let key = "node_modules/a/node_modules/left-pad";
        assert!(!scoped(json!({ "a": { "left-pad": "1.3.0" } })).contains_key(key));
        assert!(!scoped(json!({ "a": { "@scope/b": { "left-pad": "1.3.0" } } })).contains_key(key));
        assert!(!scoped(json!({ "@scope/b@2.0.0": { "left-pad": "1.3.0" } })).contains_key(key));
        // Out of order: `@scope/b` isn't an ancestor of `a`.
        assert!(scoped(json!({ "@scope/b": { "a": { "left-pad": "1.3.0" } } })).contains_key(key));
    }

    #[test]
    fn overrides_parse_from_manifest_text() {
        let lock = overridden_git_lock(REGISTRY_TGZ);
        let text = "\u{feff}{\"overrides\":{\"left-pad\":\"1.3.0\"}}";
        let found = npm_non_registry_entries(&lock, &NpmOverrides::from_manifest_text(text));
        assert!(!found.contains_key("node_modules/left-pad"), "{found:?}");
        // Unparseable: no overrides.
        let found = npm_non_registry_entries(&lock, &NpmOverrides::from_manifest_text("{"));
        assert!(found.contains_key("node_modules/left-pad"), "{found:?}");
    }

    #[test]
    fn selectors_split_scoped_names() {
        assert_eq!(split_selector("left-pad"), ("left-pad", None));
        assert_eq!(split_selector("left-pad@1"), ("left-pad", Some("1")));
        assert_eq!(split_selector("@s/pad"), ("@s/pad", None));
        assert_eq!(split_selector("@s/pad@^2"), ("@s/pad", Some("^2")));
    }
}
