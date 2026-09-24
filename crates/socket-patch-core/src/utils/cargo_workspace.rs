//! The manifests of a cargo workspace beside its root `Cargo.toml`: every
//! `[workspace] members` glob (minus `exclude`) plus every path dependency
//! reachable from them, as repo-relative `<dir>/Cargo.toml` keys.
//!
//! The hosted cargo rewriter pins a patched crate in EVERY manifest that
//! declares it — a member's own `cfg-if = "1"` resolves exactly like the
//! root's, so leaving it unpinned makes the repointed Cargo.lock entry
//! unsatisfiable. Only manifests inside the project root are returned: a
//! file outside it is not the project's to rewrite.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use toml_edit::{DocumentMut, Item, Table};

/// Upper bound on discovered manifests — a runaway glob (or a hostile tree)
/// must not turn one scan into an unbounded walk.
const MAX_MANIFESTS: usize = 4096;

/// Repo-relative `<dir>/Cargo.toml` keys of the workspace members and
/// in-root path dependencies of the project at `root`, sorted. Empty when
/// `root/Cargo.toml` is absent or unparseable.
pub fn member_manifests(root: &Path) -> Vec<String> {
    let Some(doc) = read_manifest(&root.join("Cargo.toml")) else {
        return Vec::new();
    };
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<(String, DocumentMut)> = Vec::new();

    if let Some(ws) = doc.get("workspace").and_then(Item::as_table_like) {
        let patterns = |key: &str| -> Vec<String> {
            ws.get(key)
                .and_then(Item::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let excluded: BTreeSet<String> = patterns("exclude")
            .iter()
            .flat_map(|p| expand_glob(root, p))
            .collect();
        for pattern in patterns("members") {
            for dir in expand_glob(root, &pattern) {
                if !excluded.contains(&dir) {
                    enqueue(root, dir, &mut dirs, &mut queue);
                }
            }
        }
    }
    for dep_dir in path_dependencies(&doc) {
        if let Some(dir) = normalize_rel("", &dep_dir) {
            enqueue(root, dir, &mut dirs, &mut queue);
        }
    }
    while let Some((dir, doc)) = queue.pop() {
        for dep_dir in path_dependencies(&doc) {
            if let Some(dep) = normalize_rel(&dir, &dep_dir) {
                enqueue(root, dep, &mut dirs, &mut queue);
            }
        }
    }
    dirs.into_iter()
        .map(|dir| format!("{dir}/Cargo.toml"))
        .collect()
}

fn read_manifest(path: &Path) -> Option<DocumentMut> {
    if !path.is_file() {
        return None;
    }
    std::fs::read_to_string(path).ok()?.parse().ok()
}

fn enqueue(
    root: &Path,
    dir: String,
    dirs: &mut BTreeSet<String>,
    queue: &mut Vec<(String, DocumentMut)>,
) {
    if dir.is_empty() || dirs.len() >= MAX_MANIFESTS || dirs.contains(&dir) {
        return;
    }
    let Some(doc) = read_manifest(&root.join(&dir).join("Cargo.toml")) else {
        return;
    };
    dirs.insert(dir.clone());
    queue.push((dir, doc));
}

/// Every `path = "…"` of a dependency declaration: the dependency tables
/// (plain and per-target), `[workspace.dependencies]` and `[patch.*]`.
fn path_dependencies(doc: &DocumentMut) -> Vec<String> {
    fn dep_paths(table: Option<&Item>, out: &mut Vec<String>) {
        let Some(table) = table.and_then(Item::as_table_like) else {
            return;
        };
        for (_, entry) in table.iter() {
            let path = match entry {
                Item::Table(t) => t.get("path").and_then(Item::as_str),
                Item::Value(v) => v
                    .as_inline_table()
                    .and_then(|t| t.get("path"))
                    .and_then(|p| p.as_str()),
                _ => None,
            };
            if let Some(path) = path {
                out.push(path.to_string());
            }
        }
    }
    fn dep_tables(table: &Table, out: &mut Vec<String>) {
        for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
            dep_paths(table.get(kind), out);
        }
    }
    let mut out = Vec::new();
    dep_tables(doc.as_table(), &mut out);
    if let Some(targets) = doc.get("target").and_then(Item::as_table) {
        for (_, target) in targets.iter() {
            if let Some(target) = target.as_table() {
                dep_tables(target, &mut out);
            }
        }
    }
    if let Some(ws) = doc.get("workspace").and_then(Item::as_table) {
        dep_paths(ws.get("dependencies"), &mut out);
    }
    if let Some(patch) = doc.get("patch").and_then(Item::as_table) {
        for (_, source) in patch.iter() {
            dep_paths(Some(source), &mut out);
        }
    }
    out
}

/// `base/rel` lexically normalized to a repo-relative slash path; `None`
/// when it is absolute or climbs out of the root.
fn normalize_rel(base: &str, rel: &str) -> Option<String> {
    let rel = rel.replace('\\', "/");
    if rel.starts_with('/') || Path::new(&rel).is_absolute() {
        return None;
    }
    let mut parts: Vec<String> = base
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    for component in Path::new(&rel).components() {
        match component {
            Component::Normal(seg) => parts.push(seg.to_str()?.to_string()),
            Component::CurDir => {}
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    Some(parts.join("/"))
}

/// Expand a cargo `members` / `exclude` glob (`*`, `?`, `**`) to the
/// repo-relative directories it names.
fn expand_glob(root: &Path, pattern: &str) -> Vec<String> {
    let Some(normalized) = normalize_rel("", pattern.trim_end_matches('/')) else {
        return Vec::new();
    };
    let segments: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    let mut out = Vec::new();
    expand_from(root, PathBuf::new(), &segments, &mut out);
    out.sort();
    out.dedup();
    out
}

fn expand_from(root: &Path, at: PathBuf, rest: &[&str], out: &mut Vec<String>) {
    if out.len() >= MAX_MANIFESTS {
        return;
    }
    let Some((seg, tail)) = rest.split_first() else {
        out.push(at.to_string_lossy().replace('\\', "/"));
        return;
    };
    if !seg.contains(['*', '?']) {
        let next = at.join(seg);
        if root.join(&next).is_dir() {
            expand_from(root, next, tail, out);
        }
        return;
    }
    let Ok(entries) = std::fs::read_dir(root.join(&at)) else {
        return;
    };
    let mut children: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|name| !name.starts_with('.') && name != "target")
        .collect();
    children.sort();
    if *seg == "**" {
        expand_from(root, at.clone(), tail, out);
        for child in children {
            expand_from(root, at.join(child), rest, out);
        }
        return;
    }
    for child in children {
        if wildcard_match(seg.as_bytes(), child.as_bytes()) {
            expand_from(root, at.join(child), tail, out);
        }
    }
}

fn wildcard_match(pattern: &[u8], name: &[u8]) -> bool {
    match (pattern.first(), name.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            wildcard_match(&pattern[1..], name)
                || (!name.is_empty() && wildcard_match(pattern, &name[1..]))
        }
        (Some(b'?'), Some(_)) => wildcard_match(&pattern[1..], &name[1..]),
        (Some(p), Some(n)) if p == n => wildcard_match(&pattern[1..], &name[1..]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn pkg(name: &str) -> String {
        format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n")
    }

    #[test]
    fn members_globs_excludes_and_path_dependencies() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"crates/*\"]\nexclude = [\"crates/skip\"]\n",
        );
        write(
            root,
            "app/Cargo.toml",
            &format!(
                "{}[dependencies]\nhelper = {{ path = \"../libs/helper\" }}\n",
                pkg("app")
            ),
        );
        write(root, "crates/a/Cargo.toml", &pkg("a"));
        write(root, "crates/skip/Cargo.toml", &pkg("skip"));
        write(root, "crates/no-manifest/README", "");
        write(
            root,
            "libs/helper/Cargo.toml",
            &format!(
                "{}[target.'cfg(unix)'.dependencies]\nleaf = {{ path = \"../leaf\" }}\n\
                 outside = {{ path = \"../../../elsewhere\" }}\n",
                pkg("helper")
            ),
        );
        write(root, "libs/leaf/Cargo.toml", &pkg("leaf"));
        assert_eq!(
            member_manifests(root),
            vec![
                "app/Cargo.toml",
                "crates/a/Cargo.toml",
                "libs/helper/Cargo.toml",
                "libs/leaf/Cargo.toml",
            ]
        );
    }

    #[test]
    fn a_package_without_workspace_still_reaches_its_path_dependencies() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "Cargo.toml",
            &format!("{}[dependencies.inner]\npath = \"inner\"\n", pkg("root")),
        );
        write(root, "inner/Cargo.toml", &pkg("inner"));
        assert_eq!(member_manifests(root), vec!["inner/Cargo.toml"]);
    }

    #[test]
    fn recursive_globs_and_missing_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(member_manifests(root).is_empty());
        write(root, "Cargo.toml", "[workspace]\nmembers = [\"**/m?\"]\n");
        write(root, "x/y/m1/Cargo.toml", &pkg("m1"));
        write(root, "m2/Cargo.toml", &pkg("m2"));
        write(root, "target/m3/Cargo.toml", &pkg("m3"));
        assert_eq!(
            member_manifests(root),
            vec!["m2/Cargo.toml", "x/y/m1/Cargo.toml"]
        );
    }

    #[test]
    fn wildcard_matching() {
        assert!(wildcard_match(b"a*c", b"abbc"));
        assert!(wildcard_match(b"*", b""));
        assert!(wildcard_match(b"a?c", b"abc"));
        assert!(!wildcard_match(b"a?c", b"ac"));
        assert!(!wildcard_match(b"a*d", b"abc"));
    }
}
