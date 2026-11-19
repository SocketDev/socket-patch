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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item};

use super::{canonicalize_pypi_name, read_egg_info_metadata_sync, read_python_metadata_sync};
use crate::crawlers::listing::list_dir_sync;
use crate::utils::fs::{is_dir_sync, read_regular_to_string_sync, run_blocking};
use crate::utils::requirements::{
    archive_filename_coords, editable_location, egg_name, has_env_reference, logical_lines,
    names_before_at, parse_requirement, pip_reads_as_path, requirement_name, strip_comment,
    strip_path_extras,
};
use crate::vendor::lock_inventory::ProjectView;
use crate::vendor::pypi_requirements::{decode_requirements, requirements_includes};

/// The canonical names of the packages that belong to the project at `cwd`
/// among the distributions installed in `sites`: the ones it declares and,
/// transitively, the ones those require. `None` when the project declares
/// dependencies in a way this module does not read in full; the crawl then
/// stays unscoped.
pub(super) async fn project_scope(cwd: &Path, sites: &[PathBuf]) -> Option<HashSet<String>> {
    let declared = declared_names(cwd).await?;
    let sites = sites.to_vec();
    Some(run_blocking(move || required_closure(declared, &sites)).await)
}

/// Files that decide a project's dependencies in a way this module does
/// not read: setuptools code and its legacy config, and the locks of the
/// managers whose projects can still install into the shared interpreter
/// (Poetry with `virtualenvs.create = false`, PDM without a venv).
const UNREAD_DECLARATIONS: &[&str] = &[
    "setup.py",
    "setup.cfg",
    "uv.lock",
    "poetry.lock",
    "pdm.lock",
];

/// `pyproject.toml` tables, under `[tool]`, where a manager keeps
/// dependencies in its own format instead of the PEP 621 `[project]` table.
const UNREAD_TOOL_TABLES: &[&[&str]] = &[
    &["poetry", "dependencies"],
    &["poetry", "dev-dependencies"],
    &["poetry", "group"],
    &["pdm", "dev-dependencies"],
    &["uv", "dev-dependencies"],
    &["flit", "metadata"],
];

/// The canonical names the project at `cwd` declares as dependencies, over
/// all of its requirements files and its `pyproject.toml`. `None` when one
/// of its declarations is not read in full (see the module docs).
async fn declared_names(cwd: &Path) -> Option<BTreeSet<String>> {
    let view = ProjectView::Disk(cwd);
    for name in UNREAD_DECLARATIONS {
        if view.exists_no_follow(name).await {
            return None;
        }
    }
    // A PEP 751 or PEP 723 lock lists a resolved set this module does not
    // read either.
    if crate::utils::python_lock::python_lock_paths(cwd).is_ok_and(|locks| !locks.is_empty()) {
        return None;
    }
    let mut names = BTreeSet::new();
    match view.read_text("pyproject.toml").await {
        Ok(text) => pyproject_declares(&text, &mut names)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return None,
    }
    let files = requirements_files(&view).await?;
    requirements_declare(&view, files, &mut names).await?;
    Some(names)
}

/// The pip requirements files the project keeps: every top-level `*.txt` or
/// `*.in` file with `requirements` in its name (`requirements.txt`,
/// `requirements-dev.txt`, `dev-requirements.txt`, `requirements.in`) and
/// every `*.txt` or `*.in` file in a top-level `requirements/` directory,
/// whatever its name. A project installs from several of them, so a
/// package any of them names is one of its packages. `None` when the
/// project directory cannot be listed.
async fn requirements_files(view: &ProjectView<'_>) -> Option<Vec<String>> {
    let pip_reads = |name: &str| {
        let lower = name.to_ascii_lowercase();
        lower.ends_with(".txt") || lower.ends_with(".in")
    };
    let mut files = Vec::new();
    for entry in view.list_dir("").await.ok()? {
        if entry.is_dir {
            if entry.name == "requirements" {
                for child in view.list_dir(&entry.name).await.ok()? {
                    if !child.is_dir && pip_reads(&child.name) {
                        files.push(format!("{}/{}", entry.name, child.name));
                    }
                }
            }
        } else if pip_reads(&entry.name) && entry.name.to_ascii_lowercase().contains("requirements")
        {
            files.push(entry.name);
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
    names: &mut BTreeSet<String>,
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
            line_declares(strip_comment(&line.text), names)?;
        }
        pending.extend(requirements_includes(&rel, &content));
    }
    Some(())
}

/// Adds to `names` the package one requirements line (comment stripped)
/// installs. `None` when the line installs something whose name cannot be
/// told from the file.
fn line_declares(code: &str, names: &mut BTreeSet<String>) -> Option<()> {
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
        return location_declares(location, names);
    }
    // Every other option line installs nothing itself: the walk follows
    // `-r`, `-c` only constrains, and the rest configure pip.
    if code.starts_with('-') {
        return Some(());
    }
    let token = code.split_whitespace().next()?;
    if !names_before_at(token) && (token.contains("://") || pip_reads_as_path(token)) {
        return location_declares(token, names);
    }
    names.insert(canonicalize_pypi_name(parse_requirement(code)?.name));
    Some(())
}

/// Adds to `names` the package a path, archive or url requirement installs:
/// the one its `#egg=` fragment or its archive file name gives. The project
/// directory itself (`.`, `-e .`, `.[dev]`) adds nothing here, since its
/// dependencies are the ones `pyproject.toml` declares. `None` for any other
/// location, such as a sibling source directory, whose metadata this module
/// does not read.
fn location_declares(location: &str, names: &mut BTreeSet<String>) -> Option<()> {
    if let Some(name) = egg_name(location) {
        names.insert(canonicalize_pypi_name(name));
        return Some(());
    }
    let path = location.split(['#', '?', ';']).next().unwrap_or(location);
    let path = strip_path_extras(path);
    if path.trim_end_matches(['/', '\\']) == "." {
        return Some(());
    }
    let leaf = path.rsplit(['/', '\\']).next()?;
    let (distribution, _) = archive_filename_coords(leaf)?;
    names.insert(canonicalize_pypi_name(distribution));
    Some(())
}

/// Adds to `names` what a `pyproject.toml` declares: the PEP 621 `[project]`
/// name, `dependencies` and `optional-dependencies`, and the PEP 735
/// `[dependency-groups]`. A file with none of those tables (linter and
/// formatter configuration only) declares nothing. `None` for a file that
/// does not parse, a dependency list the build backend fills in at build
/// time (`dynamic`), an entry that is not a PEP 508 requirement, and
/// dependencies kept in a tool's own table ([`UNREAD_TOOL_TABLES`]).
fn pyproject_declares(text: &str, names: &mut BTreeSet<String>) -> Option<()> {
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
            names.insert(canonicalize_pypi_name(name));
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
    Some(())
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
fn array_declares(item: &Item, names: &mut BTreeSet<String>) -> Option<()> {
    for entry in item.as_array()? {
        if entry.is_inline_table() {
            continue;
        }
        names.insert(canonicalize_pypi_name(
            parse_requirement(entry.as_str()?)?.name,
        ));
    }
    Some(())
}

/// `declared`, plus every package the distributions installed in `sites`
/// under those names require, transitively. Markers and extras are not
/// evaluated: a requirement that applies only on another platform, or only
/// with an extra nobody asked for, is followed too. That errs toward
/// keeping a package, which is what the crawl did before the scope existed.
fn required_closure(declared: BTreeSet<String>, sites: &[PathBuf]) -> HashSet<String> {
    let mut requires: HashMap<String, Vec<String>> = HashMap::new();
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
    let mut pending: Vec<String> = declared.into_iter().collect();
    while let Some(name) = pending.pop() {
        if !scope.insert(name.clone()) {
            continue;
        }
        if let Some(required) = requires.get(&name) {
            pending.extend(required.iter().cloned());
        }
    }
    scope
}

/// The canonical names a `.dist-info` directory's `METADATA` requires.
fn dist_info_requires(dist_info: &Path) -> Vec<String> {
    read_regular_to_string_sync(&dist_info.join("METADATA"))
        .map(|content| metadata_requires(&content))
        .unwrap_or_default()
}

/// The canonical names a legacy `.egg-info` entry requires: the
/// `Requires-Dist` headers of its `PKG-INFO` (the entry itself when it is a
/// bare file) and, for a directory, every line of its `requires.txt`, whose
/// `[extra]` and `[:marker]` section headers name no package.
fn egg_info_requires(egg_info: &Path) -> Vec<String> {
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
        required.extend(
            content
                .lines()
                .filter_map(requirement_name)
                .map(canonicalize_pypi_name),
        );
    }
    required
}

/// The canonical names in the `Requires-Dist` headers of a core-metadata
/// file. The header block ends at the first empty line, as an email parser
/// reads it: a whitespace-only line continues the header before it (a
/// multi-line `License`), so it does not hide the requirements after it.
fn metadata_requires(content: &str) -> Vec<String> {
    content
        .lines()
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.strip_prefix("Requires-Dist:"))
        .filter_map(requirement_name)
        .map(canonicalize_pypi_name)
        .collect()
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

    async fn declared(files: &[(&str, &str)]) -> Option<BTreeSet<String>> {
        let project = tempfile::tempdir().unwrap();
        for (rel, content) in files {
            write(project.path(), rel, content);
        }
        declared_names(project.path()).await
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
https://example.test/packages/attrs-23.2.0.tar.gz
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
                // Not a requirements file by name: never read.
                ("notes.txt", "this is not pip syntax ===\n"),
            ])
            .await,
            Some(names(&[
                "click", "flask", "jinja2", "mypy", "pytest", "ruff"
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
            // A url that names no package.
            "https://example.test/download/latest",
            "git+https://example.test/org/repo.git",
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
        // An unreadable sibling requirements file counts too.
        assert_eq!(
            declared(&[requirements, ("requirements-dev.txt", "-r missing.txt\n")]).await,
            None
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
        assert_eq!(
            declared(&[(
                "pyproject.toml",
                "[tool.poetry-dynamic-versioning]\nenable = true\n"
            )])
            .await,
            Some(BTreeSet::new())
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
                "certifi>=2017.4.17",
                // An extra nobody asked for is followed too.
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
        let sites = [system, user];

        let scope = required_closure(names(&["requests", "not-installed"]), &sites);
        let mut scope: Vec<_> = scope.into_iter().collect();
        scope.sort();
        assert_eq!(
            scope,
            [
                "certifi",
                // Required, not installed: a name, never a crawled package.
                "charset-normalizer",
                "idna",
                "not-installed",
                "pysocks",
                "requests",
                "urllib3",
            ]
        );
        assert!(required_closure(BTreeSet::new(), &sites).is_empty());
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
            "six>=1.0\n\n[socks]\nPySocks\n\n[:python_version < \"3\"]\nenum34\n",
        );
        // A bare-file `.egg-info` is its own PKG-INFO.
        write(
            site,
            "six-1.16.0.egg-info",
            "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\nRequires-Dist: typing\n",
        );
        let mut scope: Vec<_> = required_closure(names(&["old-app"]), &[site.to_path_buf()])
            .into_iter()
            .collect();
        scope.sort();
        assert_eq!(scope, ["enum34", "old-app", "pysocks", "six", "typing"]);
    }

    #[test]
    fn requirements_after_a_folded_header_are_read() {
        let metadata = "Metadata-Version: 2.1\nName: app\nVersion: 1.0\nLicense: MIT\n        \n        Permission is hereby granted\nRequires-Dist: six\n\nRequires-Dist: body\n";
        assert_eq!(metadata_requires(metadata), ["six"]);
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
}
