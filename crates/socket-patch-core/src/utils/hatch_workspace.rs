//! Hatch workspaces (Hatch 1.16+, #505): an environment's
//! `workspace.members` installs each member editable together with the
//! member's `[project]` dependencies, and its raw optional dependencies
//! whenever the member's `features` or any requirement the environment
//! installs names one of them (`lib[extra]`, expanded transitively across
//! the root and every member by `resolve_extras`). For a member whose
//! dependencies are static, Hatch reads those strings from the member's
//! `pyproject.toml` raw, without context formatting, so a `{root:uri}`
//! reference there reaches pip unexpanded and every sync of the workspace
//! environment fails. This module finds the workspace environments that
//! list a project, read the way Hatch 1.18's `Workspace.members` resolves
//! them. Which extras an environment ends up installing depends on the
//! whole workspace (environment templates, dependency groups, the root's
//! and every member's extras), so every optional dependency of a listed
//! member counts as read raw: a refusal leaves hosted and agent mode, a
//! missed one breaks the workspace.

use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item, TableLike, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::read_regular_to_string_sync;
use crate::utils::hatch::{environments, HATCH_FILES};
use crate::utils::repo_root;
use crate::vendor::common::pep508_name;

/// How deep below the checkout root a workspace root is looked for.
const MAX_DEPTH: usize = 8;

/// A workspace environment that installs a member's dependencies raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawConsumer {
    /// The directory of the project declaring the workspace.
    pub root: PathBuf,
    /// The environment whose `workspace.members` lists the member.
    pub env: String,
}

/// The first workspace environment that lists the member and so may
/// install `name` raw from its static `[project]` dependencies or optional
/// dependencies, read from `member_pyproject`. Workspace roots are looked
/// for in the member's ancestors and, when the member sits in a git
/// checkout, in every project of that checkout (a root can list a sibling
/// through a `../` spec); the walk never leaves the checkout. `None` when
/// the member does not declare `name` there or no workspace lists it,
/// including when its dependencies are dynamic: Hatch then builds the
/// metadata through the backend, which expands `{root:uri}`.
pub fn raw_consumer(member: &Path, member_pyproject: &str, name: &str) -> Option<RawConsumer> {
    let document: DocumentMut = member_pyproject.parse().ok()?;
    let project = document.get("project")?;
    if strings(project.get("dynamic"))
        .iter()
        .any(|field| matches!(*field, "dependencies" | "optional-dependencies"))
    {
        return None;
    }
    let name = canonicalize_pypi_name(name);
    let declared = strings(project.get("dependencies"))
        .into_iter()
        .chain(
            project
                .get("optional-dependencies")
                .and_then(Item::as_table_like)
                .into_iter()
                .flat_map(|groups| groups.iter())
                .flat_map(|(_, group)| strings(Some(group))),
        )
        .any(|spec| canonicalize_pypi_name(pep508_name(spec)) == name);
    if !declared {
        return None;
    }
    // Hatch reaches a member through symlinks without resolving them, so
    // roots are looked for above both spellings and found members are
    // compared by their real path.
    let lexical = absolute(member)?;
    let member = std::fs::canonicalize(&lexical).unwrap_or_else(|_| lexical.clone());
    roots(&member, &lexical).into_iter().find_map(|root| {
        listing_environments(&root, &member)
            .into_iter()
            .next()
            .map(|env| RawConsumer { root, env })
    })
}

/// `path` made absolute and normalized lexically, the way Python's
/// `os.path.abspath` reads it.
fn absolute(path: &Path) -> Option<PathBuf> {
    crate::utils::relpath::normalize_lexically(&std::path::absolute(path).ok()?)
}

/// The directories that may declare a workspace listing the member at
/// `real` (its canonical path) or `lexical` (as spelled): their ancestors
/// as far as a repository lookup goes ([`repo_root::search_dirs`]: through
/// the checkout root, never into the home directory or past a
/// `GIT_CEILING_DIRECTORIES` entry), then the other projects of the
/// checkout.
fn roots(real: &Path, lexical: &Path) -> Vec<PathBuf> {
    let home = repo_root::home();
    let mut roots: Vec<PathBuf> = repo_root::search_dirs(real).into_iter().skip(1).collect();
    let at_checkout = lexical.join(".git").exists();
    for dir in lexical.ancestors().skip(1).take_while(|_| !at_checkout) {
        if home.as_deref() == Some(dir) {
            break;
        }
        if !roots.iter().any(|root| root == dir) {
            roots.push(dir.to_path_buf());
        }
        if dir.join(".git").exists() {
            break;
        }
    }
    let Some(checkout) = repo_root::find_git_repo(real).map(|repo| repo.root) else {
        return roots;
    };
    let walk = ignore::WalkBuilder::new(&checkout)
        .max_depth(Some(MAX_DEPTH))
        .require_git(false)
        .filter_entry(|entry| {
            !matches!(
                entry.file_name().to_str(),
                Some("node_modules" | "__pypackages__" | "site-packages")
            )
        })
        .build();
    for entry in walk.flatten() {
        let path = entry.path();
        let Some(dir) = path.parent() else { continue };
        if !HATCH_FILES
            .iter()
            .any(|file| path.file_name() == Some(file.as_ref()))
            || dir == real
            || roots.iter().any(|root| root == dir)
        {
            continue;
        }
        if read_regular_to_string_sync(path).is_ok_and(|text| text.contains("workspace")) {
            roots.push(dir.to_path_buf());
        }
    }
    roots
}

fn strings(item: Option<&Item>) -> Vec<&str> {
    item.and_then(Item::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn parse(dir: &Path, file: &str) -> Option<DocumentMut> {
    read_regular_to_string_sync(&dir.join(file))
        .ok()?
        .parse()
        .ok()
}

/// The environments of the project at `root` whose workspace lists
/// `member` (a canonical path). Members are a string array, an array of
/// inline tables or an array of tables (`[[...workspace.members]]`), each
/// table naming its `path`. An environment that inherits a workspace from
/// its template lists the same members as the template, which is found.
fn listing_environments(root: &Path, member: &Path) -> Vec<String> {
    let external = parse(root, HATCH_FILES[1]);
    let project = parse(root, HATCH_FILES[0]);
    let (_, envs) = environments(project.as_ref(), external.as_ref());
    let Some(envs) = envs.and_then(Item::as_table_like) else {
        return Vec::new();
    };
    let path_of = |table: &dyn TableLike| table.get("path")?.as_str().map(str::to_owned);
    let mut found = Vec::new();
    for (env, config) in envs.iter() {
        let Some(workspace) = config.get("workspace") else {
            continue;
        };
        let exclude = strings(workspace.get("exclude"));
        let specs: Vec<String> = match workspace.get("members") {
            Some(Item::Value(Value::Array(members))) => members
                .iter()
                .filter_map(|entry| match entry {
                    Value::String(path) => Some(path.value().clone()),
                    Value::InlineTable(table) => path_of(table),
                    _ => None,
                })
                .collect(),
            Some(Item::ArrayOfTables(members)) => {
                members.iter().filter_map(|table| path_of(table)).collect()
            }
            _ => continue,
        };
        let lists = specs.iter().any(|spec| {
            members_of(root, spec, &exclude)
                .iter()
                .any(|path| std::fs::canonicalize(path).ok().as_deref() == Some(member))
        });
        if lists {
            found.push(env.to_string());
        }
    }
    found
}

/// A member spec with the context fields Hatch formats in it (`{root}`,
/// `{home}`) filled in; `None` when another field remains.
fn expand(root: &Path, spec: &str) -> Option<String> {
    let mut spec = spec.replace("{root}", &root.to_string_lossy());
    if spec.contains("{home}") {
        let home = crate::utils::fs::home_dir()?;
        spec = spec.replace("{home}", &home.to_string_lossy());
    }
    (!spec.contains('{')).then_some(spec)
}

/// The members (directories, as reached) the member spec `spec` of the
/// workspace at `root` lists, as Hatch's `find_members` resolves it: the
/// spec is joined to the root and normalized, and the part below the root
/// and the spec's shared prefix is matched one directory level at a time
/// (a component with `*`, `?` or `[` as an fnmatch pattern Python searches
/// for, so it may match a suffix of the directory name; symlinked
/// directories are followed), less any an `exclude` pattern matches by
/// its path relative to that prefix or its absolute path.
fn members_of(root: &Path, spec: &str, exclude: &[&str]) -> Vec<PathBuf> {
    let Some(spec) = expand(root, spec).filter(|spec| !spec.is_empty()) else {
        return Vec::new();
    };
    let Some(target) = absolute(&root.join(spec)) else {
        return Vec::new();
    };
    let prefix: PathBuf = root
        .components()
        .zip(target.components())
        .take_while(|(a, b)| a == b)
        .map(|(a, _)| a)
        .collect();
    let Ok(pattern) = target.strip_prefix(&prefix) else {
        return Vec::new();
    };
    let mut found = vec![prefix.clone()];
    for component in pattern.iter().map(|c| c.to_string_lossy().into_owned()) {
        let globbed = component.contains(['*', '?', '[']);
        let search = format!("*{component}");
        let mut next = Vec::new();
        for dir in &found {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                let matched = if globbed {
                    fnmatch(&search, &name)
                } else {
                    name == component
                };
                if matched && entry.path().is_dir() {
                    next.push(entry.path());
                }
            }
        }
        found = next;
    }
    // `fnmatch.fnmatch` applies `os.path.normcase` to both sides.
    let normcase = |text: &str| {
        if cfg!(windows) {
            text.to_lowercase().replace('/', "\\")
        } else {
            text.to_owned()
        }
    };
    found.retain(|path| {
        let relative = path
            .strip_prefix(&prefix)
            .map(|rel| rel.to_string_lossy().into_owned())
            .unwrap_or_default();
        let absolute = path.to_string_lossy();
        !exclude.iter().any(|pattern| {
            let pattern = normcase(pattern);
            [relative.as_str(), &absolute]
                .iter()
                .any(|text| fnmatch(&pattern, &normcase(text)))
        })
    });
    found
}

enum Token {
    Star,
    Any,
    Class(Vec<(char, char)>, bool),
    Literal(char),
}

/// Python's `fnmatch.fnmatchcase` over the whole of `text`: `*` matches
/// any run (separators included), `?` one character, `[..]` a class
/// (`[!..]` negated, `a-z` ranges); an unclosed `[` is literal. Matched
/// greedily, backtracking only to the last `*`, so time stays linear in
/// the number of stars.
fn fnmatch(pattern: &str, text: &str) -> bool {
    let tokens = tokenize(&pattern.chars().collect::<Vec<_>>());
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let mut resume: Option<(usize, usize)> = None;
    while t < text.len() {
        let step = match tokens.get(p) {
            Some(Token::Star) => {
                resume = Some((p, t));
                p += 1;
                continue;
            }
            Some(Token::Any) => true,
            Some(Token::Class(ranges, negated)) => {
                ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&text[t])) != *negated
            }
            Some(Token::Literal(c)) => *c == text[t],
            None => false,
        };
        if step {
            p += 1;
            t += 1;
        } else if let Some((star, from)) = resume {
            p = star + 1;
            t = from + 1;
            resume = Some((star, from + 1));
        } else {
            return false;
        }
    }
    tokens[p..].iter().all(|token| matches!(token, Token::Star))
}

fn tokenize(pattern: &[char]) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            '*' => tokens.push(Token::Star),
            '?' => tokens.push(Token::Any),
            '[' => {
                let negated = pattern.get(i + 1) == Some(&'!');
                let start = i + 1 + usize::from(negated);
                // A `]` right after the opening (or `[!`) is a member.
                match (start + 1..pattern.len()).find(|&j| pattern[j] == ']') {
                    Some(close) => {
                        let items = &pattern[start..close];
                        let mut ranges = Vec::new();
                        let mut k = 0;
                        while k < items.len() {
                            if k + 2 < items.len() && items[k + 1] == '-' {
                                ranges.push((items[k], items[k + 2]));
                                k += 3;
                            } else {
                                ranges.push((items[k], items[k]));
                                k += 1;
                            }
                        }
                        tokens.push(Token::Class(ranges, negated));
                        i = close;
                    }
                    None => tokens.push(Token::Literal('[')),
                }
            }
            c => tokens.push(Token::Literal(c)),
        }
        i += 1;
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "[project]\nname = \"app\"\nversion = \"0.1.0\"\n";
    const MEMBER: &str =
        "[project]\nname = \"lib1\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n\
         [project.optional-dependencies]\nsec = [\"urllib3==1.26.18\"]\n\
         all = [\"lib1[sec]\", \"idna==3.4\"]\nSpaced_Out = [\"certifi==1\"]\n";

    /// A git checkout at `<temp>/ws` with `root` as the pyproject and
    /// `hatch` as the hatch.toml of the workspace at `<temp>/ws/<at>`, and
    /// the member directory `member`.
    fn layout_at(
        at: &str,
        root: &str,
        hatch: Option<&str>,
        member: &str,
    ) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let ws = temp.path().join("ws");
        std::fs::create_dir_all(ws.join(".git")).unwrap();
        let declaring = ws.join(at);
        std::fs::create_dir_all(&declaring).unwrap();
        std::fs::write(declaring.join("pyproject.toml"), root).unwrap();
        if let Some(hatch) = hatch {
            std::fs::write(declaring.join("hatch.toml"), hatch).unwrap();
        }
        let dir = ws.join(member);
        std::fs::create_dir_all(&dir).unwrap();
        (temp, dir)
    }

    fn layout(root: &str, hatch: Option<&str>, member: &str) -> (tempfile::TempDir, PathBuf) {
        layout_at("", root, hatch, member)
    }

    fn consumer(dir: &Path, member: &str, name: &str) -> Option<String> {
        raw_consumer(dir, member, name).map(|found| found.env)
    }

    fn workspace(members: &str) -> String {
        format!("{ROOT}[tool.hatch.envs.default.workspace]\nmembers = {members}\n")
    }

    /// #505: a member listed by a glob, a plain path, a `{path = ..}`
    /// table, an array of tables or a `{root}` spec is consumed for its
    /// `[project]` dependencies; a project the workspace does not list, or
    /// none at all, is not.
    #[test]
    fn members_listed_by_glob_path_or_table() {
        for members in [
            "[\"libs/*\"]",
            "[\"libs/lib1\"]",
            "[\"./libs/../libs/lib1/\"]",
            "[{ path = \"libs/lib1\" }]",
            "[\"libs/l?b[0-9]\"]",
            // Python searches a component pattern, so it may match a
            // suffix of the directory name.
            "[\"libs/b[1]\"]",
            "[\"{root}/libs/lib1\"]",
        ] {
            let (_temp, dir) = layout(&workspace(&members), None, "libs/lib1");
            assert_eq!(
                consumer(&dir, MEMBER, "six").as_deref(),
                Some("default"),
                "{members}"
            );
            assert_eq!(consumer(&dir, MEMBER, "Six").as_deref(), Some("default"));
        }
        let tables =
            format!("{ROOT}[[tool.hatch.envs.default.workspace.members]]\npath = \"libs/lib1\"\n");
        let (_temp, dir) = layout(&tables, None, "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six").as_deref(), Some("default"));
        for members in [
            "[\"other/*\"]",
            "[\"libs\"]",
            "[\"libs/*/x\"]",
            "[]",
            "[\"{env:X}/libs/lib1\"]",
        ] {
            let (_temp, dir) = layout(&workspace(members), None, "libs/lib1");
            assert_eq!(consumer(&dir, MEMBER, "six"), None, "{members}");
        }
        let (_temp, dir) = layout(ROOT, None, "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six"), None);
    }

    /// #505 (review): a workspace root beside the member, listing it
    /// through a `../` spec, is found anywhere in the checkout.
    #[test]
    fn sibling_roots_listing_the_member_through_parent_specs() {
        let (_temp, dir) = layout_at(
            "apps/web",
            &workspace("[\"../../libs/*\"]"),
            None,
            "libs/lib1",
        );
        assert_eq!(consumer(&dir, MEMBER, "six").as_deref(), Some("default"));
        let (_temp, dir) = layout_at("apps/web", &workspace("[\"../x/*\"]"), None, "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six"), None);
    }

    /// #505 and review: once a workspace lists the member, every optional
    /// dependency counts as read raw, whatever reaches it (the entry's
    /// `features`, a `lib1[sec]` in an environment, its template, a
    /// dependency group, the root or another member, a mixed-case key);
    /// a package the member does not declare is never refused.
    #[test]
    fn every_optional_dependency_of_a_listed_member_counts() {
        for root in [
            workspace("[\"libs/*\"]"),
            workspace("[{ path = \"libs/lib1\", features = [\"sec\"] }]"),
            format!(
                "{ROOT}[tool.hatch.envs.default]\ndependencies = [\"lib1[Spaced_Out]\"]\n\
                 [tool.hatch.envs.test.workspace]\nmembers = [\"libs/*\"]\n"
            ),
        ] {
            let (_temp, dir) = layout(&root, None, "libs/lib1");
            for name in ["six", "urllib3", "idna", "certifi"] {
                assert!(consumer(&dir, MEMBER, name).is_some(), "{root}: {name}");
            }
            assert_eq!(consumer(&dir, MEMBER, "requests"), None, "{root}");
        }
    }

    /// #505: a workspace declared in hatch.toml counts, and a hatch.toml
    /// `envs` table hides pyproject's environments.
    #[test]
    fn hatch_toml_workspaces_replace_pyproject_envs() {
        let hatch = "[envs.test.workspace]\nmembers = [\"libs/*\"]\n";
        let (_temp, dir) = layout(ROOT, Some(hatch), "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six").as_deref(), Some("test"));
        let root = workspace("[\"libs/*\"]");
        let (_temp, dir) = layout(&root, Some("[envs.lint]\n"), "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six"), None);
        let (_temp, dir) = layout(&root, Some("[build]\n"), "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six").as_deref(), Some("default"));
    }

    /// `exclude` drops a listed member; dynamic member dependencies are
    /// built by the backend, which expands `{root:uri}`.
    #[test]
    fn excluded_and_dynamic_members_are_not_raw() {
        let root = format!("{}exclude = [\"libs/lib1\"]\n", workspace("[\"libs/*\"]"));
        let (_temp, dir) = layout(&root, None, "libs/lib1");
        assert_eq!(consumer(&dir, MEMBER, "six"), None);
        let (_temp, dir) = layout(&workspace("[\"libs/*\"]"), None, "libs/lib1");
        let dynamic = MEMBER.replace(
            "version = ",
            "dynamic = [\"optional-dependencies\"]\nversion = ",
        );
        assert_eq!(consumer(&dir, &dynamic, "six"), None);
    }

    /// The walk stops at the checkout root, including when the member is
    /// that root: a workspace above `.git` is not read.
    #[test]
    fn ancestors_stop_at_the_checkout_root() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("pyproject.toml"),
            workspace("[\"repo/lib1\", \"top\"]"),
        )
        .unwrap();
        let dir = temp.path().join("repo/lib1");
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(consumer(&dir, MEMBER, "six").as_deref(), Some("default"));
        std::fs::create_dir_all(temp.path().join("repo/.git")).unwrap();
        assert_eq!(consumer(&dir, MEMBER, "six"), None);
        let top = temp.path().join("top");
        std::fs::create_dir_all(&top).unwrap();
        assert_eq!(consumer(&top, MEMBER, "six").as_deref(), Some("default"));
        std::fs::create_dir_all(top.join(".git")).unwrap();
        assert_eq!(consumer(&top, MEMBER, "six"), None);
    }

    /// Bugbot: a member Hatch reaches through a symlinked directory is
    /// still listed, whichever spelling the scan was given.
    #[cfg(unix)]
    #[test]
    fn members_reached_through_symlinks_are_listed() {
        let (temp, real) = layout(&workspace("[\"libs/*\"]"), None, "vendor/lib1");
        let ws = temp.path().join("ws");
        std::fs::create_dir_all(ws.join("libs")).unwrap();
        std::os::unix::fs::symlink(&real, ws.join("libs/lib1")).unwrap();
        assert_eq!(consumer(&real, MEMBER, "six").as_deref(), Some("default"));
        assert_eq!(
            consumer(&ws.join("libs/lib1"), MEMBER, "six").as_deref(),
            Some("default")
        );
        let (_temp, real) = layout(&workspace("[\"other/*\"]"), None, "vendor/lib1");
        assert_eq!(consumer(&real, MEMBER, "six"), None);
    }

    /// A FIFO squatting an ancestor's or a checkout project's
    /// pyproject.toml / hatch.toml is skipped, never opened blocking.
    #[cfg(unix)]
    #[test]
    fn fifos_in_place_of_workspace_files_never_block() {
        let (temp, dir) = layout(ROOT, None, "libs/lib1");
        let ws = temp.path().join("ws");
        std::fs::remove_file(ws.join("pyproject.toml")).unwrap();
        std::fs::create_dir_all(ws.join("apps/web")).unwrap();
        for fifo in [
            ws.join("pyproject.toml"),
            ws.join("hatch.toml"),
            ws.join("apps/web/pyproject.toml"),
        ] {
            let status = std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap();
            assert!(status.success());
        }
        assert_eq!(consumer(&dir, MEMBER, "six"), None);
    }

    #[test]
    fn fnmatch_reads_python_patterns() {
        assert!(fnmatch("pkg-*", "pkg-a"));
        assert!(fnmatch("*", "a/b"));
        assert!(fnmatch("*a*b", "xxaxxb"));
        assert!(!fnmatch("*a*b", "xxaxxbc"));
        assert!(fnmatch("[!x]y", "ay"));
        assert!(!fnmatch("[!x]y", "xy"));
        assert!(fnmatch("[a-c]", "b"));
        assert!(fnmatch("[]]", "]"));
        assert!(fnmatch("a[", "a["));
        assert!(!fnmatch("a?", "a"));
        assert!(fnmatch("a**", "a"));
        // Many stars against a long miss stays fast.
        let text = "x".repeat(200);
        assert!(!fnmatch("*/*/*/*/*/*/*/*/legacy", &text));
    }
}
