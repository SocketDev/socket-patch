//! Hatch workspaces (Hatch 1.16+, #505): an environment's
//! `workspace.members` installs each member editable together with the
//! member's `[project]` dependencies and the optional dependencies of the
//! member's `features`. For a member whose dependencies are static, Hatch
//! reads those strings from the member's `pyproject.toml` raw, without
//! context formatting, so a `{root:uri}` reference there reaches pip
//! unexpanded and every sync of the workspace environment fails. This
//! module finds the workspace environments that consume a project that
//! way, read the way Hatch 1.18's `Workspace.members` resolves them.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Component, Path, PathBuf};

use toml_edit::{DocumentMut, Item, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::hatch::HATCH_FILES;
use crate::vendor::common::pep508_name;

/// A workspace environment that installs a member's dependencies raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawConsumer {
    /// The directory of the project declaring the workspace.
    pub root: PathBuf,
    /// The environment whose `workspace.members` lists the member.
    pub env: String,
}

/// The first workspace environment, declared in an ancestor of `member`
/// (up to the nearest directory holding `.git`), that installs `name` from
/// the member's static `[project]` dependencies or the optional
/// dependencies of the features it selects. `member_files` are the
/// member's [`HATCH_FILES`]. `None` when no workspace reads `name` raw,
/// including when the member's dependencies are dynamic: Hatch then builds
/// the metadata through the backend, which expands `{root:uri}`.
pub fn raw_consumer(
    member: &Path,
    member_files: &BTreeMap<String, String>,
    name: &str,
) -> Option<RawConsumer> {
    let document: DocumentMut = member_files.get(HATCH_FILES[0])?.parse().ok()?;
    let project = document.get("project")?;
    let dynamic = strings(project.get("dynamic"));
    if dynamic
        .iter()
        .any(|field| matches!(*field, "dependencies" | "optional-dependencies"))
    {
        return None;
    }
    let member = lexical_absolute(member)?;
    for ancestor in member.ancestors().skip(1) {
        for (env, features) in workspace_features(ancestor, &member) {
            if consumed(project, &features).contains(&canonicalize_pypi_name(name)) {
                return Some(RawConsumer {
                    root: ancestor.to_path_buf(),
                    env,
                });
            }
        }
        if ancestor.join(".git").exists() {
            break;
        }
    }
    None
}

/// `path` made absolute and normalized lexically (`.` dropped, `..` popped),
/// the way Python's `os.path.abspath` / `normpath` read it: Hatch compares
/// member paths without resolving symlinks.
fn lexical_absolute(path: &Path) -> Option<PathBuf> {
    let absolute = std::path::absolute(path).ok()?;
    let mut out = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    Some(out)
}

fn strings(item: Option<&Item>) -> Vec<&str> {
    item.and_then(Item::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn parse(dir: &Path, file: &str) -> Option<DocumentMut> {
    std::fs::read_to_string(dir.join(file)).ok()?.parse().ok()
}

/// For each environment of the project at `root` whose workspace lists
/// `member`: the environment name and the member's selected features
/// (normalized). The environments are hatch.toml's `envs` when it has that
/// key, else pyproject's `[tool.hatch.envs]` (Hatch merges an external
/// config by top-level key).
fn workspace_features(root: &Path, member: &Path) -> Vec<(String, Vec<String>)> {
    let external = parse(root, HATCH_FILES[1]).filter(|doc| doc.contains_key("envs"));
    let project = match external {
        Some(_) => None,
        None => parse(root, HATCH_FILES[0]),
    };
    let envs = match (&external, &project) {
        (Some(doc), _) => doc.get("envs"),
        (None, Some(doc)) => doc
            .get("tool")
            .and_then(|tool| tool.get("hatch"))
            .and_then(|hatch| hatch.get("envs")),
        (None, None) => None,
    };
    let Some(envs) = envs.and_then(Item::as_table_like) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (env, config) in envs.iter() {
        let Some(workspace) = config.get("workspace") else {
            continue;
        };
        let exclude = strings(workspace.get("exclude"));
        let Some(members) = workspace.get("members").and_then(Item::as_array) else {
            continue;
        };
        for entry in members.iter() {
            let (path, features) = match entry {
                Value::String(path) => (path.value().as_str(), Vec::new()),
                Value::InlineTable(table) => {
                    let Some(path) = table.get("path").and_then(Value::as_str) else {
                        continue;
                    };
                    let features = table
                        .get("features")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(canonicalize_pypi_name)
                        .collect();
                    (path, features)
                }
                _ => continue,
            };
            if lists(root, path, &exclude, member) {
                found.push((env.to_string(), features));
            }
        }
    }
    found
}

/// Whether the member spec `spec` of the workspace at `root` lists
/// `member`, as Hatch's `find_members` resolves it: the spec is joined to
/// the root and normalized, the part below the root and the spec's shared
/// prefix is matched one component at a time (a component with `*`, `?` or
/// `[` as an fnmatch pattern Python searches for, so it may match a suffix
/// of the directory name), and a member any `exclude` pattern matches, by
/// its path relative to that prefix or its absolute path, is dropped. A
/// spec using context formatting (`{root}`, `{env:..}`) is not resolved.
fn lists(root: &Path, spec: &str, exclude: &[&str], member: &Path) -> bool {
    if spec.is_empty() || spec.contains('{') {
        return false;
    }
    let Some(target) = lexical_absolute(&root.join(spec)) else {
        return false;
    };
    let prefix: PathBuf = root
        .components()
        .zip(target.components())
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect();
    let (Ok(pattern), Ok(relative)) = (target.strip_prefix(&prefix), member.strip_prefix(&prefix))
    else {
        return false;
    };
    let pattern: Vec<String> = pattern.iter().map(|c| c.to_string_lossy().into()).collect();
    let relative: Vec<String> = relative
        .iter()
        .map(|c| c.to_string_lossy().into())
        .collect();
    if pattern.len() != relative.len()
        || !pattern.iter().zip(&relative).all(|(pattern, name)| {
            if pattern.contains(['*', '?', '[']) {
                let name: Vec<char> = name.chars().collect();
                let pattern: Vec<char> = pattern.chars().collect();
                (0..=name.len()).any(|start| fnmatch(&pattern, &name[start..]))
            } else {
                pattern == name
            }
        })
    {
        return false;
    }
    let relative = relative.join(std::path::MAIN_SEPARATOR_STR);
    let absolute = member.to_string_lossy();
    !exclude.iter().any(|pattern| {
        let pattern: Vec<char> = pattern.chars().collect();
        [relative.as_str(), &absolute]
            .iter()
            .any(|text| fnmatch(&pattern, &text.chars().collect::<Vec<_>>()))
    })
}

/// Python's `fnmatch.fnmatchcase` over the whole of `text`: `*` matches
/// any run (separators included), `?` one character, `[..]` a class
/// (`[!..]` negated, `a-z` ranges); an unclosed `[` is literal.
fn fnmatch(pattern: &[char], text: &[char]) -> bool {
    match pattern.first() {
        None => text.is_empty(),
        Some('*') => (0..=text.len()).any(|skip| fnmatch(&pattern[1..], &text[skip..])),
        Some('?') => !text.is_empty() && fnmatch(&pattern[1..], &text[1..]),
        Some('[') => match class(&pattern[1..]) {
            Some((set, rest)) => {
                text.first().is_some_and(|&c| set(c)) && fnmatch(&pattern[rest + 1..], &text[1..])
            }
            None => text.first() == Some(&'[') && fnmatch(&pattern[1..], &text[1..]),
        },
        Some(&c) => text.first() == Some(&c) && fnmatch(&pattern[1..], &text[1..]),
    }
}

/// The class starting after a `[`: its predicate and the length consumed
/// up to and including the closing `]`, or `None` when it never closes.
#[allow(clippy::type_complexity)]
fn class(body: &[char]) -> Option<(Box<dyn Fn(char) -> bool>, usize)> {
    let negated = body.first() == Some(&'!');
    let start = usize::from(negated);
    // A `]` right after the opening (or `[!`) is a member, not the close.
    let close = body
        .iter()
        .enumerate()
        .skip(start + 1)
        .find(|(_, c)| **c == ']')
        .map(|(i, _)| i)?;
    let items = body[start..close].to_vec();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < items.len() {
        if i + 2 < items.len() && items[i + 1] == '-' {
            ranges.push((items[i], items[i + 2]));
            i += 3;
        } else {
            ranges.push((items[i], items[i]));
            i += 1;
        }
    }
    let set = move |c: char| ranges.iter().any(|(lo, hi)| *lo <= c && c <= *hi) != negated;
    Some((Box::new(set), close + 1))
}

/// The canonical names of the dependencies a workspace installs from a
/// member's static `[project]` table: its `dependencies`, plus the optional
/// dependencies of `features`, following the member's references to its
/// own extras (`lib[other]`) the way Hatch's `resolve_extras` does.
fn consumed(project: &Item, features: &[String]) -> BTreeSet<String> {
    let own = project
        .get("name")
        .and_then(Item::as_str)
        .map(canonicalize_pypi_name);
    let groups: BTreeMap<String, Vec<&str>> = project
        .get("optional-dependencies")
        .and_then(Item::as_table_like)
        .into_iter()
        .flat_map(|table| table.iter())
        .map(|(key, group)| (canonicalize_pypi_name(key), strings(Some(group))))
        .collect();
    let mut names = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut queue: VecDeque<&str> = strings(project.get("dependencies")).into();
    for feature in features {
        if seen.insert(feature.clone()) {
            queue.extend(groups.get(feature).into_iter().flatten());
        }
    }
    while let Some(spec) = queue.pop_front() {
        let name = canonicalize_pypi_name(pep508_name(spec));
        if own.as_deref() != Some(name.as_str()) {
            names.insert(name);
            continue;
        }
        for extra in extras(spec) {
            if seen.insert(extra.clone()) {
                queue.extend(groups.get(&extra).into_iter().flatten());
            }
        }
    }
    names
}

/// The normalized extras of a PEP 508 spec (`name[a, b]`).
fn extras(spec: &str) -> Vec<String> {
    let rest = spec.trim_start()[pep508_name(spec).len()..].trim_start();
    rest.strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
        .map(|(list, _)| {
            list.split(',')
                .map(str::trim)
                .filter(|extra| !extra.is_empty())
                .map(canonicalize_pypi_name)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "[project]\nname = \"app\"\nversion = \"0.1.0\"\n";
    const MEMBER: &str =
        "[project]\nname = \"lib1\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n\
         [project.optional-dependencies]\nsec = [\"urllib3==1.26.18\"]\n\
         all = [\"lib1[sec]\", \"idna==3.4\"]\n";

    /// A workspace at `<temp>/ws` (a git checkout) with `root` as its
    /// pyproject and `hatch` as its hatch.toml, and the member `member`.
    fn layout(root: &str, hatch: Option<&str>, member: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir_all(ws.join(".git")).unwrap();
        std::fs::write(ws.join("pyproject.toml"), root).unwrap();
        if let Some(hatch) = hatch {
            std::fs::write(ws.join("hatch.toml"), hatch).unwrap();
        }
        let dir = ws.join(member);
        std::fs::create_dir_all(&dir).unwrap();
        (temp, dir)
    }

    fn consumer(dir: &Path, member: &str, name: &str) -> Option<String> {
        let files = BTreeMap::from([("pyproject.toml".to_string(), member.to_string())]);
        raw_consumer(dir, &files, name).map(|found| found.env)
    }

    /// #505: a member listed by a glob, a plain path or a `{path = ..}`
    /// table is consumed for its `[project]` dependencies; a project the
    /// workspace does not list, or none at all, is not.
    #[test]
    fn members_listed_by_glob_path_or_table() {
        for members in [
            "[\"libs/*\"]",
            "[\"libs/lib1\"]",
            "[\"./libs/../libs/lib1/\"]",
            "[{ path = \"libs/lib1\" }]",
            "[\"libs/l?b[0-9]\"]",
        ] {
            let root = format!("{ROOT}[tool.hatch.envs.default.workspace]\nmembers = {members}\n");
            let (_temp, dir) = layout(&root, None, "libs/lib1");
            assert_eq!(
                consumer(&dir, MEMBER, "six").as_deref(),
                Some("default"),
                "{members}"
            );
            assert_eq!(consumer(&dir, MEMBER, "Six").as_deref(), Some("default"));
        }
        for members in ["[\"other/*\"]", "[\"libs\"]", "[\"libs/*/x\"]", "[]"] {
            let root = format!("{ROOT}[tool.hatch.envs.default.workspace]\nmembers = {members}\n");
            let (_temp, dir) = layout(&root, None, "libs/lib1");
            assert_eq!(consumer(&dir, MEMBER, "six"), None, "{members}");
        }
        let (_temp, dir) = layout(ROOT, None, "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six"), None);
    }

    /// #505: optional dependencies are consumed only through the member's
    /// `features`, including extras the feature reaches through the
    /// member's references to itself.
    #[test]
    fn optional_dependencies_follow_member_features() {
        let with = |features: &str| {
            format!(
                "{ROOT}[tool.hatch.envs.default.workspace]\n\
                 members = [{{ path = \"libs/lib1\", features = {features} }}]\n"
            )
        };
        let (_temp, dir) = layout(&with("[\"sec\"]"), None, "libs/lib1");
        assert_eq!(
            consumer(&dir, MEMBER, "urllib3").as_deref(),
            Some("default")
        );
        assert_eq!(consumer(&dir, MEMBER, "idna"), None);
        let (_temp, dir) = layout(&with("[\"ALL\"]"), None, "libs/lib1");
        assert_eq!(
            consumer(&dir, MEMBER, "urllib3").as_deref(),
            Some("default")
        );
        assert_eq!(consumer(&dir, MEMBER, "idna").as_deref(), Some("default"));
        let (_temp, dir) = layout(&with("[]"), None, "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "urllib3"), None);
        assert_eq!(consumer(&dir, MEMBER, "six").as_deref(), Some("default"));
    }

    /// #505: a workspace declared in hatch.toml counts, and a hatch.toml
    /// `envs` table hides pyproject's environments.
    #[test]
    fn hatch_toml_workspaces_replace_pyproject_envs() {
        let hatch = "[envs.test.workspace]\nmembers = [\"libs/*\"]\n";
        let (_temp, dir) = layout(ROOT, Some(hatch), "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six").as_deref(), Some("test"));
        let root = format!("{ROOT}[tool.hatch.envs.default.workspace]\nmembers = [\"libs/*\"]\n");
        let (_temp, dir) = layout(&root, Some("[envs.lint]\n"), "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six"), None);
        let (_temp, dir) = layout(&root, Some("[build]\n"), "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six").as_deref(), Some("default"));
    }

    /// `exclude` drops a listed member; dynamic member dependencies are
    /// built by the backend, which expands `{root:uri}`.
    #[test]
    fn excluded_and_dynamic_members_are_not_raw() {
        let root = format!(
            "{ROOT}[tool.hatch.envs.default.workspace]\nmembers = [\"libs/*\"]\nexclude = [\"libs/lib1\"]\n"
        );
        let (_temp, dir) = layout(&root, None, "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six"), None);
        let root = format!("{ROOT}[tool.hatch.envs.default.workspace]\nmembers = [\"libs/*\"]\n");
        let (_temp, dir) = layout(&root, None, "libs/lib1");
        let dynamic = MEMBER.replace(
            "version = ",
            "dynamic = [\"optional-dependencies\"]\nversion = ",
        );
        assert_eq!(consumer(&dir, &dynamic, "six"), None);
    }

    /// The walk stops at the checkout root: a workspace above `.git` is
    /// not read.
    #[test]
    fn ancestors_stop_at_the_checkout_root() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("pyproject.toml"),
            format!("{ROOT}[tool.hatch.envs.default.workspace]\nmembers = [\"repo/lib1\"]\n"),
        )
        .unwrap();
        let dir = temp.path().join("repo/lib1");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(consumer(&dir, MEMBER, "six").as_deref(), Some("default"));
        std::fs::create_dir_all(temp.path().join("repo/.git")).unwrap();
        assert_eq!(consumer(&dir, MEMBER, "six"), None);
    }

    #[test]
    fn fnmatch_reads_python_patterns() {
        let m = |p: &str, t: &str| {
            fnmatch(
                &p.chars().collect::<Vec<_>>(),
                &t.chars().collect::<Vec<_>>(),
            )
        };
        assert!(m("pkg-*", "pkg-a"));
        assert!(m("*", "a/b"));
        assert!(m("[!x]y", "ay"));
        assert!(!m("[!x]y", "xy"));
        assert!(m("[a-c]", "b"));
        assert!(m("[]]", "]"));
        assert!(m("a[", "a["));
        assert!(!m("a?", "a"));
    }
}
