//! Which installed packages belong to a Python project that has no
//! environment of its own.
//!
//! A project with a `requirements.txt` or a `pyproject.toml` and no
//! virtualenv installs into the interpreter on `PATH`, and that interpreter
//! is shared: the distro's own packages, Homebrew's formulae and every
//! other project installed there sit in the same site-packages. A package
//! being installed there says nothing about whether this project uses it,
//! so the crawl keeps only the packages the project declares and the
//! installed packages those require. This is the Python counterpart of the
//! Maven local-repository scope ([`maven_scope`](super::super::maven_scope)).
//!
//! The scope applies only when every dependency declaration of the project
//! is one this module reads in full: pip requirements files, and the
//! PEP 621 / PEP 735 tables of `pyproject.toml`. Anything else (`setup.py`,
//! another manager's lock, a requirement on a local directory) leaves the
//! crawl unscoped, as it was before the scope existed.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item};

use super::{canonicalize_pypi_name, read_egg_info_metadata_sync, read_python_metadata_sync};
use crate::crawlers::listing::list_dir_sync;
use crate::utils::fs::{is_dir_sync, read_regular_to_string_sync, run_blocking};
use crate::utils::relpath::normalize_rel_keeping_escapes;
use crate::utils::requirements::{
    archive_filename_coords, editable_location, egg_name, has_env_reference, logical_lines,
    names_before_at, parse_requirement, pip_reads_as_path, requirement_name, strip_comment,
    strip_path_extras,
};
use crate::vendor::lock_inventory::ProjectView;
use crate::vendor::pypi_requirements::{
    decode_requirements, requirements_includes, NOT_READER_DIRS,
};

/// The canonical names of the packages that belong to the project at `cwd`
/// among the distributions installed in `sites`: the ones it declares and,
/// transitively, the ones those require, plus the ones its patch manifest
/// records ([`recorded_names`]). `None` when the project declares
/// dependencies in a way this module does not read in full, or in no place
/// this module reads; the crawl then stays unscoped.
pub(super) async fn project_scope(cwd: &Path, sites: &[PathBuf]) -> Option<HashSet<String>> {
    let declared = declared_names(cwd).await?;
    let sites = sites.to_vec();
    let mut scope = run_blocking(move || required_closure(declared, &sites)).await;
    scope.extend(recorded_names(cwd).await);
    Some(scope)
}

/// The canonical names of the PyPI packages the project's patch manifest
/// (`.socket/manifest.json`) records. A recorded patch names its package:
/// `get <name>` patched it on purpose, or an earlier scan did, so it stays
/// one of the project's packages whether or not a requirements file names
/// it. Left out of the scope, it would get no newer patch and `scan
/// --prune` would report its record as one to roll back. Only the package
/// itself counts: what it requires is not the project's on its account. A
/// manifest kept elsewhere (`--manifest-path`) is not read here, and its
/// packages are judged by the project's declarations alone.
async fn recorded_names(cwd: &Path) -> Vec<String> {
    let path = cwd.join(crate::constants::DEFAULT_PATCH_MANIFEST_PATH);
    let Ok(Some(manifest)) = crate::manifest::operations::read_manifest(&path).await else {
        return Vec::new();
    };
    manifest
        .patches
        .keys()
        .filter_map(|purl| crate::utils::purl::parse_pypi_purl(purl))
        .map(|(name, _)| canonicalize_pypi_name(&name))
        .collect()
}

/// What a project declares: the canonical name of each package, and the
/// extras of it the project asks for (`requests[socks]`), canonical too.
type Declared = BTreeMap<String, BTreeSet<String>>;

/// Records in `declared` that the project asks for `name`, with the extras
/// spelled between the brackets of its requirement (`socks, security`).
fn declare(declared: &mut Declared, name: &str, extras: Option<&str>) {
    declared
        .entry(canonicalize_pypi_name(name))
        .or_default()
        .extend(extras_of(extras));
}

/// The canonical names of the extras spelled between a requirement's
/// brackets.
fn extras_of(extras: Option<&str>) -> impl Iterator<Item = String> + '_ {
    extras
        .into_iter()
        .flat_map(|extras| extras.split(','))
        .map(canonicalize_pypi_name)
        .filter(|extra| !extra.is_empty())
}

/// Files that decide a project's dependencies in a way this module does
/// not read: setuptools code and its legacy config, Hatch's environment
/// file, and the locks of the managers whose projects can still install
/// into the shared interpreter (Poetry with `virtualenvs.create = false`,
/// PDM without a venv). A `uv.lock` and the PEP 751 / PEP 723 locks are
/// found by name pattern in [`declared_names`].
const UNREAD_DECLARATIONS: &[&str] = &[
    "setup.py",
    "setup.cfg",
    "hatch.toml",
    "poetry.lock",
    "pdm.lock",
];

/// `pyproject.toml` tables, under `[tool]`, where a manager keeps
/// dependencies in its own format instead of the PEP 621 `[project]` table.
/// A Hatch environment of `type = "system"` installs its `dependencies`
/// into the shared interpreter, so those tables count too.
const UNREAD_TOOL_TABLES: &[&[&str]] = &[
    &["poetry", "dependencies"],
    &["poetry", "dev-dependencies"],
    &["poetry", "group"],
    &["pdm", "dev-dependencies"],
    &["uv", "dev-dependencies"],
    &["flit", "metadata"],
    &["hatch", "envs"],
    &["rye", "dev-dependencies"],
];

/// The packages the project at `cwd` declares as dependencies, over all of
/// its requirements files and its `pyproject.toml`. `None` when one of its
/// declarations is not read in full (see the module docs), and when nothing
/// that states dependencies was found: a project whose only marker is a
/// `pyproject.toml` that configures tools keeps its requirements somewhere
/// this module does not look (`deploy/docker/requirements.txt`), if it has
/// any. A requirements file with no requirement in it is a statement: the
/// project declares none.
async fn declared_names(cwd: &Path) -> Option<Declared> {
    let view = ProjectView::Disk(cwd);
    for name in UNREAD_DECLARATIONS {
        if view.exists_no_follow(name).await {
            return None;
        }
    }
    // A `uv.lock`, PEP 751 or PEP 723 lock lists a resolved set this module
    // does not read either.
    if crate::utils::python_lock::python_lock_paths(cwd).is_ok_and(|locks| !locks.is_empty()) {
        return None;
    }
    let mut names = Declared::new();
    let mut states_dependencies = false;
    match view.read_text("pyproject.toml").await {
        Ok(text) => states_dependencies |= pyproject_declares(&text, &mut names)?,
        // A read that fails on a file that is there (a link leaving the
        // repository, which reads as not found) hides its declarations.
        Err(_) if view.exists_no_follow("pyproject.toml").await => return None,
        Err(_) => {}
    }
    let files = requirements_files(&view).await?;
    states_dependencies |= !files.is_empty();
    requirements_declare(&view, files, &mut names).await?;
    states_dependencies.then_some(names)
}

/// The pip requirements files the project keeps: every `*.txt` or `*.in`
/// file with `requirements` in its name (`requirements.txt`,
/// `requirements-dev.txt`, `dev-requirements.txt`, `requirements.in`) at the
/// top level and one directory down (`docs/requirements.txt`,
/// `tests/requirements.txt`), and every `*.txt` or `*.in` file in a
/// top-level `requirements/` directory, whatever its name. A project
/// installs from several of them, so a package any of them names is one of
/// its packages. Hidden directories and [`NOT_READER_DIRS`] hold installed
/// packages and build output, not the project's own files. `None` when the
/// project directory, or its `requirements/` directory, cannot be listed.
async fn requirements_files(view: &ProjectView<'_>) -> Option<Vec<String>> {
    let named = |name: &str, any_name: bool| {
        let lower = name.to_ascii_lowercase();
        (lower.ends_with(".txt") || lower.ends_with(".in"))
            && (any_name || lower.contains("requirements"))
    };
    let mut files = Vec::new();
    for entry in view.list_dir("").await.ok()? {
        // A link to a directory is one too (`requirements -> ../shared`).
        let is_dir = entry.is_dir
            || view
                .disk_root()
                .is_some_and(|root| root.join(&entry.name).is_dir());
        if !is_dir {
            if named(&entry.name, false) {
                files.push(entry.name);
            }
            continue;
        }
        if entry.name.starts_with('.') || NOT_READER_DIRS.contains(&entry.name.as_str()) {
            continue;
        }
        let requirements_dir = entry.name == "requirements";
        let children = match view.list_dir(&entry.name).await {
            Ok(children) => children,
            Err(_) if requirements_dir => return None,
            // Any other directory is only searched as a courtesy.
            Err(_) => continue,
        };
        for child in children {
            if !child.is_dir && named(&child.name, requirements_dir) {
                files.push(format!("{}/{}", entry.name, child.name));
            }
        }
    }
    Some(files)
}

/// Adds to `names` every package `files` and their `-r` includes name.
/// `None` when a file cannot be read (a missing or out-of-root include, an
/// encoding pip's rules do not decode) or holds a line whose package cannot
/// be told ([`line_declares`]).
async fn requirements_declare(
    view: &ProjectView<'_>,
    files: Vec<String>,
    names: &mut Declared,
) -> Option<()> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut pending = files;
    while let Some(rel) = pending.pop() {
        if !visited.insert(rel.clone()) {
            continue;
        }
        let content = view
            .read_bytes(&rel)
            .await
            .and_then(decode_requirements)
            .ok()?;
        for line in logical_lines(&content) {
            line_declares(strip_comment(&line.text), &rel, names)?;
        }
        pending.extend(requirements_includes(&rel, &content));
    }
    Some(())
}

/// Adds to `names` the package one line (comment stripped) of the
/// requirements file `rel` installs. `None` when the line installs
/// something whose name cannot be told from the file.
fn line_declares(code: &str, rel: &str, names: &mut Declared) -> Option<()> {
    let code = code.trim();
    if code.is_empty() {
        return Some(());
    }
    // pip expands `${NAME}` where it runs, so what the line installs is
    // not knowable here.
    if has_env_reference(code) {
        return None;
    }
    if let Some(location) = editable_location(code) {
        return location_declares(location, rel, names);
    }
    // Every other option line installs nothing itself: the walk follows
    // `-r`, `-c` only constrains, and the rest configure pip.
    if code.starts_with('-') {
        return Some(());
    }
    let token = code.split_whitespace().next()?;
    if !names_before_at(token) && (token.contains("://") || pip_reads_as_path(token)) {
        return location_declares(token, rel, names);
    }
    let requirement = parse_requirement(code)?;
    declare(names, requirement.name, requirement.extras);
    Some(())
}

/// Adds to `names` the package a path, archive or url requirement of the
/// requirements file `rel` installs: the one its `#egg=` fragment or its
/// wheel file name gives. The project directory itself adds nothing here,
/// since its dependencies are the ones `pyproject.toml` declares. pip
/// resolves a relative path against the directory it runs in, which is the
/// project root (`-e .`, `.[dev]`) or the directory of the file
/// (`docs/requirements.txt` holding `-e ..`), so a path that reaches the
/// project root from either is the project. `None` for any other location:
/// a sibling source directory, whose metadata this module does not read,
/// and an sdist or forge archive, which is named however its author chose
/// (`…/archive/release-1.0.zip` installs no package called `release`).
fn location_declares(location: &str, rel: &str, names: &mut Declared) -> Option<()> {
    if let Some(name) = egg_name(location) {
        declare(names, name, None);
        return Some(());
    }
    let with_extras = location.split(['#', '?', ';']).next().unwrap_or(location);
    let path = strip_path_extras(with_extras);
    // `wheels/six-….whl[socks]`: the text `strip_path_extras` took off.
    let extras = with_extras[path.len()..]
        .strip_prefix('[')
        .and_then(|extras| extras.strip_suffix(']'));
    if !path.is_empty() && !path.contains("://") {
        let from_file = match rel.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/{path}"),
            None => path.to_string(),
        };
        if [path, from_file.as_str()]
            .iter()
            .any(|path| normalize_rel_keeping_escapes(path).is_empty())
        {
            return Some(());
        }
    }
    let leaf = path.rsplit(['/', '\\']).next()?;
    if !leaf.ends_with(".whl") {
        return None;
    }
    let (distribution, _) = archive_filename_coords(leaf)?;
    declare(names, distribution, extras);
    Some(())
}

/// Adds to `names` what a `pyproject.toml` declares: the PEP 621 `[project]`
/// name, `dependencies` and `optional-dependencies`, and the PEP 735
/// `[dependency-groups]`. `Some(false)` for a file with none of those
/// tables (linter and formatter configuration only): it says nothing about
/// dependencies. `None` for a file that does not parse, a dependency list
/// the build backend fills in at build time (`dynamic`), an entry that is
/// not a PEP 508 requirement, and dependencies kept in a tool's own table
/// ([`UNREAD_TOOL_TABLES`]).
fn pyproject_declares(text: &str, names: &mut Declared) -> Option<bool> {
    let document: DocumentMut = text.parse().ok()?;
    let root = document.as_item();
    let unread = UNREAD_TOOL_TABLES
        .iter()
        .any(|path| lookup(root, &[&["tool"][..], *path].concat()).is_some());
    if unread {
        return None;
    }
    if let Some(project) = root.get("project") {
        let project = project.as_table_like()?;
        if let Some(dynamic) = project.get("dynamic") {
            for field in dynamic.as_array()? {
                if matches!(field.as_str()?, "dependencies" | "optional-dependencies") {
                    return None;
                }
            }
        }
        if let Some(name) = project.get("name").and_then(Item::as_str) {
            declare(names, name, None);
        }
        if let Some(dependencies) = project.get("dependencies") {
            array_declares(dependencies, names)?;
        }
        if let Some(optional) = project.get("optional-dependencies") {
            for (_, extra) in optional.as_table_like()?.iter() {
                array_declares(extra, names)?;
            }
        }
    }
    if let Some(groups) = root.get("dependency-groups") {
        for (_, group) in groups.as_table_like()?.iter() {
            array_declares(group, names)?;
        }
    }
    Some(root.get("project").is_some() || root.get("dependency-groups").is_some())
}

/// The item at `path` under `item`, each step through a table.
fn lookup<'a>(item: &'a Item, path: &[&str]) -> Option<&'a Item> {
    path.iter()
        .try_fold(item, |item, key| item.as_table_like()?.get(key))
}

/// Adds to `names` the PEP 508 requirements of a TOML array. A PEP 735
/// `{include-group = "…"}` entry names another group of the same table,
/// which is read on its own. `None` when `item` is not an array or holds an
/// entry that is neither.
fn array_declares(item: &Item, names: &mut Declared) -> Option<()> {
    for entry in item.as_array()? {
        if entry.is_inline_table() {
            continue;
        }
        let requirement = parse_requirement(entry.as_str()?)?;
        declare(names, requirement.name, requirement.extras);
    }
    Some(())
}

/// One requirement of an installed distribution.
#[derive(Debug, PartialEq, Eq)]
struct Requires {
    /// The canonical name of the required package.
    name: String,
    /// The extras of that package the requirement asks for.
    extras: Vec<String>,
    /// The extras of the requiring distribution that turn the requirement
    /// on (`; extra == "socks"`). Empty when it applies without one.
    gates: Vec<String>,
}

/// The names in `declared`, plus every package the distributions installed
/// in `sites` under those names require, transitively. A requirement behind
/// an extra is followed only when that extra was asked for, by a
/// declaration (`requests[socks]`) or by the requirement that led to the
/// package. Every other marker is taken to hold: a requirement that
/// applies only on another platform is followed too, which errs toward
/// keeping a package, as the crawl did before the scope existed.
fn required_closure(declared: Declared, sites: &[PathBuf]) -> HashSet<String> {
    let mut requires: HashMap<String, Vec<Requires>> = HashMap::new();
    for site in sites {
        for entry in list_dir_sync(site) {
            let file_name = entry.name.to_string_lossy();
            let path = site.join(&*file_name);
            let installed = if file_name.ends_with(".dist-info") {
                read_python_metadata_sync(&path).map(|(name, _)| (name, dist_info_requires(&path)))
            } else if file_name.ends_with(".egg-info") {
                read_egg_info_metadata_sync(&path).map(|(name, _)| (name, egg_info_requires(&path)))
            } else {
                None
            };
            if let Some((name, required)) = installed {
                requires
                    .entry(canonicalize_pypi_name(&name))
                    .or_default()
                    .extend(required);
            }
        }
    }
    let mut scope = HashSet::new();
    // What is asked of a package: itself (`None`), or one of its extras.
    let mut pending: Vec<(String, Option<String>)> = Vec::new();
    for (name, extras) in declared {
        pending.extend(extras.into_iter().map(|extra| (name.clone(), Some(extra))));
        pending.push((name, None));
    }
    let mut asked: HashSet<(String, Option<String>)> = HashSet::new();
    while let Some((name, extra)) = pending.pop() {
        if !asked.insert((name.clone(), extra.clone())) {
            continue;
        }
        for requirement in requires.get(&name).into_iter().flatten() {
            let applies = match &extra {
                None => requirement.gates.is_empty(),
                Some(extra) => requirement.gates.contains(extra),
            };
            if applies {
                pending.push((requirement.name.clone(), None));
                pending.extend(
                    requirement
                        .extras
                        .iter()
                        .map(|extra| (requirement.name.clone(), Some(extra.clone()))),
                );
            }
        }
        scope.insert(name);
    }
    scope
}

/// The requirements in a `.dist-info` directory's `METADATA`.
fn dist_info_requires(dist_info: &Path) -> Vec<Requires> {
    read_regular_to_string_sync(&dist_info.join("METADATA"))
        .map(|content| metadata_requires(&content))
        .unwrap_or_default()
}

/// The requirements of a legacy `.egg-info` entry: the `Requires-Dist`
/// headers of its `PKG-INFO` (the entry itself when it is a bare file) and,
/// for a directory, the lines of its `requires.txt`.
fn egg_info_requires(egg_info: &Path) -> Vec<Requires> {
    let requires_of = |path: &Path| {
        read_regular_to_string_sync(path)
            .map(|content| metadata_requires(&content))
            .unwrap_or_default()
    };
    if !is_dir_sync(egg_info) {
        return requires_of(egg_info);
    }
    let mut required = requires_of(&egg_info.join("PKG-INFO"));
    if let Ok(content) = read_regular_to_string_sync(&egg_info.join("requires.txt")) {
        required.extend(requires_txt(&content));
    }
    required
}

/// The requirements in the `Requires-Dist` headers of a core-metadata file.
/// The header block ends at the first empty line, as an email parser reads
/// it: a whitespace-only line continues the header before it (a multi-line
/// `License`), so it does not hide the requirements after it.
fn metadata_requires(content: &str) -> Vec<Requires> {
    content
        .lines()
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.strip_prefix("Requires-Dist:"))
        .filter_map(|requirement| requires(requirement, None))
        .collect()
}

/// The requirements in a setuptools `requires.txt`. A `[extra]` or
/// `[extra:marker]` section header puts the lines under it behind that
/// extra; `[:marker]` and the lines before any header apply without one.
fn requires_txt(content: &str) -> Vec<Requires> {
    let mut section: Option<String> = None;
    let mut required = Vec::new();
    for line in content.lines().map(str::trim) {
        if let Some(header) = line.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            let extra = canonicalize_pypi_name(header.split(':').next().unwrap_or(header));
            section = Some(extra).filter(|extra| !extra.is_empty());
        } else {
            required.extend(requires(line, section.as_deref()));
        }
    }
    required
}

/// One PEP 508 requirement of an installed distribution, behind `section`
/// (a `requires.txt` extra) or behind the extras its own marker tests. A
/// text this grammar does not read as a requirement still names its
/// package, and applies without an extra.
fn requires(requirement: &str, section: Option<&str>) -> Option<Requires> {
    let (name, extras, marker) = match parse_requirement(requirement) {
        Some(parsed) => (parsed.name, parsed.extras, parsed.marker),
        None => (requirement_name(requirement)?, None, None),
    };
    let gates = match section {
        Some(extra) => vec![extra.to_string()],
        None => marker.map(marker_gates).unwrap_or_default(),
    };
    Some(Requires {
        name: canonicalize_pypi_name(name),
        extras: extras_of(extras).collect(),
        gates,
    })
}

/// The extras of the requiring distribution that turn on a requirement
/// with `marker`; empty when it can apply without one. The marker is read
/// as its ` or ` branches: a branch that tests `extra == "<name>"` holds
/// with that extra, and any other branch can hold on its own, which makes
/// the requirement unconditional. A branch cut inside parentheses, a
/// negated test or a reversed one (`"x" == extra`) reads as one that can
/// hold on its own, so a misread only ever follows a requirement.
fn marker_gates(marker: &str) -> Vec<String> {
    let mut gates = Vec::new();
    for branch in marker.split(" or ") {
        match branch_extra(branch) {
            Some(extra) => gates.push(extra),
            None => return Vec::new(),
        }
    }
    gates
}

/// The extra a marker branch tests with `extra == "<name>"`, canonical.
fn branch_extra(branch: &str) -> Option<String> {
    let mut rest = branch;
    while let Some(at) = rest.find("extra") {
        let (before, after) = (&rest[..at], &rest[at + "extra".len()..]);
        rest = after;
        // `extra` is the whole variable, not the tail of another name.
        if before.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let Some(value) = after.trim_start().strip_prefix("==") else {
            continue;
        };
        let value = value.trim_start();
        let Some(quote) = value.chars().next().filter(|c| matches!(c, '"' | '\'')) else {
            continue;
        };
        if let Some(end) = value[1..].find(quote) {
            return Some(canonicalize_pypi_name(&value[1..1 + end]));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|name| name.to_string()).collect()
    }

    /// A `.dist-info` install of `name` requiring `requires` (each a full
    /// `Requires-Dist` value).
    fn install(site: &Path, name: &str, version: &str, requires: &[&str]) {
        let mut metadata = format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n");
        for requirement in requires {
            metadata.push_str(&format!("Requires-Dist: {requirement}\n"));
        }
        metadata.push_str("\nRequires-Dist: body-text-is-not-a-header\n");
        write(
            site,
            &format!("{name}-{version}.dist-info/METADATA"),
            &metadata,
        );
    }

    /// What the project made of `files` declares, extras included.
    async fn declares(files: &[(&str, &str)]) -> Option<Declared> {
        let project = tempfile::tempdir().unwrap();
        for (rel, content) in files {
            write(project.path(), rel, content);
        }
        declared_names(project.path()).await
    }

    /// The names of [`declares`].
    async fn declared(files: &[(&str, &str)]) -> Option<BTreeSet<String>> {
        Some(declares(files).await?.into_keys().collect())
    }

    /// A declaration of `packages`, each with the extras asked of it.
    fn asking(packages: &[(&str, &[&str])]) -> Declared {
        packages
            .iter()
            .map(|(name, extras)| (name.to_string(), names(extras)))
            .collect()
    }

    /// The closure of `declared` over `sites`, sorted.
    fn closure(declared: Declared, sites: &[PathBuf]) -> Vec<String> {
        let mut scope: Vec<_> = required_closure(declared, sites).into_iter().collect();
        scope.sort();
        scope
    }

    #[tokio::test]
    async fn requirements_lines_name_their_packages() {
        let content = "\
# a comment, then a blank line

Requests[security]>=2.0 ; python_version >= '3.8'  # trailing comment
zope.interface==6.0 \\
    --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000
six @ https://patch.socket.dev/six-1.16.0-py2.py3-none-any.whl#sha256=00
idna@https://example.test/idna-3.7-py3-none-any.whl
./wheels/typing_extensions-4.12.0-py3-none-any.whl
https://example.test/packages/attrs-23.2.0-py3-none-any.whl
git+https://example.test/org/repo.git@v1#egg=Private_Lib
-e .
.[dev]
--index-url https://example.test/simple
--extra-index-url https://example.test/extra
-c constraints.txt
";
        assert_eq!(
            declared(&[
                ("requirements.txt", content),
                // A constraints file adds no requirement.
                ("constraints.txt", "urllib3==2.0.0\n"),
            ])
            .await,
            Some(names(&[
                "attrs",
                "idna",
                "private-lib",
                "requests",
                "six",
                "typing-extensions",
                "zope-interface",
            ]))
        );
    }

    #[tokio::test]
    async fn a_requirements_file_with_no_requirement_declares_nothing() {
        assert_eq!(
            declared(&[("requirements.txt", "# only stdlib\n\n# (json, sys)\n")]).await,
            Some(BTreeSet::new())
        );
    }

    #[tokio::test]
    async fn includes_and_sibling_requirements_files_are_read() {
        assert_eq!(
            declared(&[
                ("requirements.txt", "-r requirements/base.txt\nflask\n"),
                ("requirements/base.txt", "-r ../shared.txt\nclick\n"),
                ("shared.txt", "jinja2\n"),
                ("requirements/test.txt", "pytest\n"),
                ("requirements/README.md", "not-a-requirement\n"),
                ("requirements-dev.txt", "ruff\n"),
                ("dev-requirements.txt", "mypy\n"),
                ("requirements.in", "flask\n"),
                // One directory down. `-e ..` there is the project itself,
                // as pip reads it when run from that directory.
                ("docs/requirements.txt", "-e ..\nsphinx\n"),
                ("tests/Requirements-Test.TXT", "-e .[test]\ncoverage\n"),
                // Not a requirements file by name: never read.
                ("notes.txt", "this is not pip syntax ===\n"),
                ("docs/notes.txt", "this is not pip syntax ===\n"),
                // Two directories down, installed packages and hidden
                // directories: never read.
                ("docs/api/requirements.txt", "too-deep\n"),
                ("node_modules/requirements.txt", "not-the-projects\n"),
                (".tox/requirements.txt", "not-the-projects\n"),
            ])
            .await,
            Some(names(&[
                "click", "coverage", "flask", "jinja2", "mypy", "pytest", "ruff", "sphinx"
            ]))
        );
    }

    #[tokio::test]
    async fn an_include_cycle_ends() {
        assert_eq!(
            declared(&[
                ("requirements.txt", "-r requirements-dev.txt\nflask\n"),
                ("requirements-dev.txt", "-r requirements.txt\nruff\n"),
            ])
            .await,
            Some(names(&["flask", "ruff"]))
        );
    }

    #[tokio::test]
    async fn a_declaration_that_is_not_read_in_full_leaves_the_crawl_unscoped() {
        let requirements = ("requirements.txt", "flask\n");
        for unread in [
            ("setup.py", "from setuptools import setup\nsetup()\n"),
            ("setup.cfg", "[options]\ninstall_requires = six\n"),
            ("poetry.lock", ""),
            ("pdm.lock", ""),
            ("uv.lock", "version = 1\n"),
            ("pylock.toml", "lock-version = \"1.0\"\n"),
            // Not valid TOML.
            ("pyproject.toml", "[project\n"),
            (
                "pyproject.toml",
                "[project]\nname = \"app\"\ndynamic = [\"dependencies\"]\n",
            ),
            (
                "pyproject.toml",
                "[project]\nname = \"app\"\ndynamic = [\"version\", \"optional-dependencies\"]\n",
            ),
            (
                "pyproject.toml",
                "[tool.poetry.dependencies]\nflask = \"^3\"\n",
            ),
            (
                "pyproject.toml",
                "[tool.poetry.group.dev.dependencies]\nruff = \"*\"\n",
            ),
            (
                "pyproject.toml",
                "[tool.pdm.dev-dependencies]\ntest = [\"pytest\"]\n",
            ),
            (
                "pyproject.toml",
                "[tool.uv]\ndev-dependencies = [\"ruff\"]\n",
            ),
            (
                "pyproject.toml",
                "[tool.flit.metadata]\nrequires = [\"six\"]\n",
            ),
            // A Hatch environment can install into the shared interpreter.
            (
                "pyproject.toml",
                "[tool.hatch.envs.default]\ndependencies = [\"six\"]\n",
            ),
            ("hatch.toml", "[envs.default]\ndependencies = [\"six\"]\n"),
            (
                "pyproject.toml",
                "[tool.rye]\ndev-dependencies = [\"ruff\"]\n",
            ),
            // Not a PEP 508 requirement.
            (
                "pyproject.toml",
                "[project]\ndependencies = [\"./local\"]\n",
            ),
            ("pyproject.toml", "[project]\ndependencies = \"flask\"\n"),
        ] {
            assert_eq!(declared(&[requirements, unread]).await, None, "{unread:?}");
        }
        for line in [
            // Another source directory: its metadata is not read.
            "-e ./libs/shared",
            "../shared",
            "-e ..",
            // A url that names no package.
            "https://example.test/download/latest",
            "git+https://example.test/org/repo.git",
            // An archive is named however its author chose: only a wheel's
            // file name is its distribution's.
            "https://example.test/org/mylib/archive/release-1.0.zip",
            "https://example.test/packages/attrs-23.2.0.tar.gz",
            "./dist/mylib-1.0.tar.gz",
            // pip expands these where it runs.
            "flask==${FLASK_VERSION}",
            "-r ${REQUIREMENTS_DIR}/base.txt",
            // A missing include is pip's error; what it held is unknown.
            "-r missing.txt",
            // Not a requirement pip reads.
            "flask/extra",
        ] {
            let content = format!("six\n{line}\n");
            assert_eq!(
                declared(&[("requirements.txt", content.as_str())]).await,
                None,
                "{line:?}"
            );
        }
        // An unreadable sibling requirements file counts too, at the top
        // level and one directory down.
        for sibling in ["requirements-dev.txt", "docs/requirements.txt"] {
            assert_eq!(
                declared(&[requirements, (sibling, "-r missing.txt\n")]).await,
                None,
                "{sibling}"
            );
        }
    }

    /// A declaration reached through a link is read, or leaves the crawl
    /// unscoped when the link leaves the repository. It is never taken for
    /// absent, which would drop the packages it declares.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_linked_declaration_is_never_taken_for_absent() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let (project, shared) = (tmp.path().join("project"), tmp.path().join("shared"));
        write(
            &shared,
            "pyproject.toml",
            "[project]\nname = \"app\"\ndependencies = [\"flask\"]\n",
        );
        write(&shared, "requirements/base.txt", "click\n");
        write(&project, "requirements.txt", "six\n");

        symlink(
            shared.join("pyproject.toml"),
            project.join("pyproject.toml"),
        )
        .unwrap();
        let declared = declared_names(&project).await;
        assert!(
            declared
                .as_ref()
                .is_none_or(|names| names.contains_key("flask")),
            "{declared:?}"
        );

        std::fs::remove_file(project.join("pyproject.toml")).unwrap();
        symlink(shared.join("requirements"), project.join("requirements")).unwrap();
        let declared = declared_names(&project).await;
        assert!(
            declared
                .as_ref()
                .is_none_or(|names| names.contains_key("click")),
            "{declared:?}"
        );
    }

    #[tokio::test]
    async fn pyproject_declares_its_pep_621_and_pep_735_tables() {
        let pyproject = r#"
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "My_App"
dynamic = ["version"]
dependencies = [
    "Flask>=3",
    "requests[socks] ; python_version >= '3.9'",
]

[project.optional-dependencies]
postgres = ["psycopg>=3"]

[dependency-groups]
test = ["pytest", { include-group = "lint" }]
lint = ["ruff"]

[tool.ruff]
line-length = 100
"#;
        assert_eq!(
            declared(&[("pyproject.toml", pyproject)]).await,
            Some(names(&[
                "flask", "my-app", "psycopg", "pytest", "requests", "ruff"
            ]))
        );
        // Tool configuration alone declares nothing, and does not stop the
        // requirements files from being read.
        assert_eq!(
            declared(&[
                ("pyproject.toml", "[tool.black]\nline-length = 100\n"),
                ("requirements.txt", "flask\n"),
            ])
            .await,
            Some(names(&["flask"]))
        );
        // A `[project]` table with no dependencies states that there are
        // none.
        assert_eq!(
            declared(&[("pyproject.toml", "[project]\nname = \"app\"\n")]).await,
            Some(names(&["app"]))
        );
        // Tool configuration and nothing else: the project's dependencies
        // are stated somewhere this module does not look, if anywhere, so
        // the crawl is not scoped.
        assert_eq!(
            declared(&[(
                "pyproject.toml",
                "[tool.poetry-dynamic-versioning]\nenable = true\n"
            )])
            .await,
            None
        );
    }

    #[test]
    fn the_closure_follows_installed_requirements() {
        let tmp = tempfile::tempdir().unwrap();
        let (system, user) = (tmp.path().join("system"), tmp.path().join("user"));
        install(
            &system,
            "requests",
            "2.32.0",
            &[
                "charset_normalizer<4,>=2",
                "idna (<4,>=2.5)",
                "urllib3<3,>=1.21.1",
                // Another platform's requirement is followed: only `extra`
                // is evaluated.
                "certifi>=2017.4.17; sys_platform == \"win32\"",
                "PySocks!=1.5.7,>=1.5.6; extra == \"socks\"",
            ],
        );
        install(&system, "urllib3", "2.2.0", &[]);
        install(&system, "PySocks", "1.7.1", &[]);
        // The requirement is met from another site dir of the interpreter.
        install(&user, "certifi", "2024.2.2", &[]);
        // A cycle.
        install(&system, "idna", "3.7", &["requests"]);
        // Installed, required by nothing the project declares.
        install(&system, "setuptools", "70.0.0", &[]);
        install(&system, "anyio", "4.13.0", &["sniffio>=1.1"]);
        install(&system, "sniffio", "1.3.1", &[]);
        // Asks for an extra of what it requires.
        install(&system, "proxy-client", "1.0", &["Requests[SOCKS]>=2"]);
        let sites = [system, user];

        let without_extra = [
            "certifi",
            // Required, not installed: a name, never a crawled package.
            "charset-normalizer",
            "idna",
            "not-installed",
            "requests",
            "urllib3",
        ];
        assert_eq!(
            closure(asking(&[("requests", &[]), ("not-installed", &[])]), &sites),
            without_extra
        );
        // The extra's requirement counts once the extra is asked for, by
        // the project or by a package it requires.
        let mut with_extra = without_extra.to_vec();
        with_extra.insert(4, "pysocks");
        assert_eq!(
            closure(
                asking(&[("requests", &["socks"]), ("not-installed", &[])]),
                &sites
            ),
            with_extra
        );
        with_extra.remove(3);
        with_extra.insert(3, "proxy-client");
        assert_eq!(
            closure(asking(&[("proxy-client", &[])]), &sites),
            with_extra
        );
        assert!(closure(Declared::new(), &sites).is_empty());
    }

    #[test]
    fn the_closure_reads_legacy_egg_info_requirements() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path();
        write(
            site,
            "old_app-1.0.egg-info/PKG-INFO",
            "Metadata-Version: 1.1\nName: old-app\nVersion: 1.0\n",
        );
        write(
            site,
            "old_app-1.0.egg-info/requires.txt",
            "six>=1.0\n\n[socks]\nPySocks\n\n[:python_version < \"3\"]\nenum34\n\n\
             [tls:sys_platform == \"win32\"]\nwincertstore\n",
        );
        // A bare-file `.egg-info` is its own PKG-INFO.
        write(
            site,
            "six-1.16.0.egg-info",
            "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\nRequires-Dist: typing\n",
        );
        let sites = [site.to_path_buf()];
        assert_eq!(
            closure(asking(&[("old-app", &[])]), &sites),
            ["enum34", "old-app", "six", "typing"]
        );
        assert_eq!(
            closure(asking(&[("old-app", &["socks", "tls"])]), &sites),
            [
                "enum34",
                "old-app",
                "pysocks",
                "six",
                "typing",
                "wincertstore"
            ]
        );
    }

    #[test]
    fn requirements_after_a_folded_header_are_read() {
        let metadata = "Metadata-Version: 2.1\nName: app\nVersion: 1.0\nLicense: MIT\n        \n        Permission is hereby granted\nRequires-Dist: six\n\nRequires-Dist: body\n";
        let names: Vec<String> = metadata_requires(metadata)
            .into_iter()
            .map(|requirement| requirement.name)
            .collect();
        assert_eq!(names, ["six"]);
    }

    #[test]
    fn a_marker_gates_a_requirement_only_on_the_extras_it_tests() {
        let gates = |marker: &str| marker_gates(marker);
        assert_eq!(gates("extra == \"socks\""), ["socks"]);
        assert_eq!(gates("extra=='Use_Chardet.On-Py3'"), ["use-chardet-on-py3"]);
        assert_eq!(
            gates("python_version >= \"3.8\" and extra == 'test'"),
            ["test"]
        );
        assert_eq!(gates("extra == \"a\" or extra == \"b\""), ["a", "b"]);
        // A branch that can hold without an extra makes it unconditional,
        // and so does anything this reader does not take for the test.
        for unconditional in [
            "sys_platform == \"win32\"",
            "extra == \"a\" or sys_platform == \"win32\"",
            "extra != \"a\"",
            "\"a\" == extra",
            "extras == \"a\"",
            "my_extra == \"a\"",
            "extra == a",
            "extra == \"a",
            "(extra == \"a\" or os_name == \"nt\") and python_version < \"3\"",
        ] {
            assert!(gates(unconditional).is_empty(), "{unconditional}");
        }
        assert_eq!(
            requires("PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'", None),
            Some(Requires {
                name: "pysocks".into(),
                extras: vec![],
                gates: vec!["socks".into()],
            })
        );
        assert_eq!(
            requires("urllib3[brotli,socks]>=2", None),
            Some(Requires {
                name: "urllib3".into(),
                extras: vec!["brotli".into(), "socks".into()],
                gates: vec![],
            })
        );
        // Not a requirement this grammar reads: the name still counts.
        assert_eq!(
            requires("odd-name ???", None).map(|requirement| requirement.name),
            Some("odd-name".into())
        );
    }

    #[tokio::test]
    async fn declarations_keep_the_extras_they_ask_for() {
        let declared = declares(&[
            (
                "requirements.txt",
                "Requests[Security, socks]>=2\n./wheels/httpx-0.27.0-py3-none-any.whl[http2]\n",
            ),
            (
                "pyproject.toml",
                "[project]\nname = \"app\"\ndependencies = [\"requests[use_chardet_on_py3]\"]\n",
            ),
        ])
        .await
        .unwrap();
        assert_eq!(
            declared,
            asking(&[
                ("app", &[]),
                ("httpx", &["http2"]),
                ("requests", &["security", "socks", "use-chardet-on-py3"]),
            ])
        );
    }

    #[tokio::test]
    async fn project_scope_joins_the_declaration_and_the_closure() {
        let tmp = tempfile::tempdir().unwrap();
        let (project, site) = (tmp.path().join("project"), tmp.path().join("site"));
        write(&project, "requirements.txt", "flask\n");
        install(&site, "Flask", "3.0.0", &["Werkzeug>=3.0.0"]);
        install(&site, "werkzeug", "3.0.1", &[]);
        install(&site, "certifi", "2026.7.22", &[]);
        let scope = project_scope(&project, std::slice::from_ref(&site))
            .await
            .unwrap();
        assert_eq!(
            scope,
            HashSet::from(["flask".to_string(), "werkzeug".to_string()])
        );
        write(&project, "setup.py", "");
        assert_eq!(project_scope(&project, &[site]).await, None);
    }

    /// A package the project's patch manifest records stays the project's
    /// when no requirements file names it: `get <name>` patched it on
    /// purpose. Only that package: what it requires is not.
    #[tokio::test]
    async fn a_recorded_patch_keeps_its_package_in_the_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let (project, site) = (tmp.path().join("project"), tmp.path().join("site"));
        write(&project, "requirements.txt", "flask\n");
        install(&site, "Flask", "3.0.0", &[]);
        install(&site, "requests", "2.32.0", &["urllib3<3"]);
        install(&site, "urllib3", "2.2.0", &[]);
        let record = r#"{
            "uuid": "11111111-1111-4111-8111-111111111111",
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "seed",
            "license": "MIT",
            "tier": "free"
        }"#;
        write(
            &project,
            ".socket/manifest.json",
            &format!(
                r#"{{"patches": {{
                    "pkg:pypi/Requests@2.32.0?artifact_id=py3-none-any-whl": {record},
                    "pkg:npm/left-pad@1.3.0": {record}
                }}}}"#
            ),
        );
        let scope = project_scope(&project, &[site]).await.unwrap();
        assert_eq!(
            scope,
            HashSet::from(["flask".to_string(), "requests".to_string()])
        );
    }
}
