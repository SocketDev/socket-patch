//! Where pixi keeps a project's environments.
//!
//! pixi (<https://pixi.sh>) installs a workspace's conda and PyPI packages
//! into conda prefixes of its own, one per environment. `pixi run`, `pixi
//! shell` and `pixi install` never use `./.venv`, an activated
//! `VIRTUAL_ENV` or the interpreter on `PATH`. Measured on pixi 0.84:
//!
//! - an environment lives at `<workspace root>/.pixi/envs/<name>`
//!   (`default` when the manifest declares no `[environments]`), and is a
//!   conda prefix: it has a `conda-meta/` directory, where pixi also writes
//!   a `pixi` record naming the manifest and the environment;
//! - with `detached-environments` set in pixi's configuration the
//!   environments live under pixi's cache (or the configured directory),
//!   and on Unix pixi leaves `.pixi/envs` as a symbolic link to them, which
//!   the lookup here follows. Windows gets no such link, so a detached
//!   environment is found there only while it is activated;
//! - `pixi run` and `pixi shell` export the workspace root
//!   (`PIXI_PROJECT_ROOT`, `PIXI_WORKSPACE_ROOT`) and the activated
//!   environment's prefix (`CONDA_PREFIX`). pixi finds the workspace by
//!   walking up from the working directory, so both are also set for a
//!   command run from a directory below the root (a workspace member).
//!
//! Python packages sit in the prefix's `site-packages` whichever way pixi
//! installed them: a conda package's files are linked from pixi's package
//! cache (`INSTALLER` says `conda`), a PyPI wheel's are written by uv
//! (`uv-pixi`). Both carry `.dist-info` or `.egg-info` metadata.

use std::path::{Path, PathBuf};

/// The manifest and lock pixi alone writes. A `pyproject.toml` with a
/// `[tool.pixi]` table is a pixi manifest too, but other tools install
/// such a project as well, so only its `pixi.lock` says pixi does.
pub const PIXI_FILES: [&str; 2] = ["pixi.toml", "pixi.lock"];

/// One pixi environment of a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PixiEnvironment {
    /// The name `pixi run -e <name>` takes (`default` unless the manifest
    /// declares more). The directory name of an activated environment
    /// found outside `.pixi/envs`.
    pub name: String,
    /// The conda prefix (the directory holding `conda-meta/`).
    pub prefix: PathBuf,
}

/// The files pip installs a project from, which pixi never reads. With one
/// beside pixi's files, another installer may put the project's packages
/// into the interpreter on `PATH` (a container image that runs `pip
/// install -r requirements.txt`), so pixi does not own the project's
/// environment alone. A `pyproject.toml` counts when it has a
/// `[build-system]` (see [`pixi_owns_project_env`]).
pub const PIP_INSTALL_FILES: [&str; 3] = ["requirements.txt", "setup.py", "setup.cfg"];

/// Whether pixi installs the project at `cwd`: it has a `pixi.toml` or a
/// `pixi.lock`.
pub fn is_pixi_project(cwd: &Path) -> bool {
    PIXI_FILES.iter().any(|name| cwd.join(name).is_file())
}

/// Whether only pixi installs the project at `cwd`, so its packages are
/// only ever in pixi's own environments and one with none installed yet
/// has nothing installed: a pixi project (see [`is_pixi_project`]) that
/// nothing shows pip installing too. pip installs from a
/// `requirements.txt`, a `setup.py` or `setup.cfg`, and a `pyproject.toml`
/// that declares a `[build-system]` (a library that keeps pixi for its
/// development environments and is `pip install`ed elsewhere). A
/// `pyproject.toml` that only holds project metadata or tool settings is
/// not something pip installs dependencies from.
pub async fn pixi_owns_project_env(cwd: &Path) -> bool {
    is_pixi_project(cwd)
        && !PIP_INSTALL_FILES.iter().any(|name| cwd.join(name).exists())
        && !pyproject_declares_build_system(cwd).await
}

/// Whether `cwd/pyproject.toml` has a `[build-system]` table.
async fn pyproject_declares_build_system(cwd: &Path) -> bool {
    let Ok(text) = crate::utils::fs::read_regular_to_string(&cwd.join("pyproject.toml")).await
    else {
        return false;
    };
    text.parse::<toml_edit::DocumentMut>()
        .is_ok_and(|document| document.get("build-system").is_some())
}

/// The existing pixi environments of the project at `cwd`, by name. Empty
/// when pixi has installed none.
pub async fn pixi_environments(cwd: &Path) -> Vec<PixiEnvironment> {
    let var = |name: &str| std::env::var(name).ok();
    pixi_environments_with(cwd, &var).await
}

/// [`pixi_environments`] over an explicit environment.
pub(crate) async fn pixi_environments_with(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Vec<PixiEnvironment> {
    let mut found: Vec<PixiEnvironment> = Vec::new();
    // `.pixi/envs` is a project's only beside pixi's own files: in the
    // home directory the same path holds the tool environments of `pixi
    // global install`, which are no project's.
    if is_pixi_project(cwd) {
        let envs_dir = cwd.join(".pixi").join("envs");
        for entry in crate::utils::fs::list_dir_entries(&envs_dir).await {
            let prefix = envs_dir.join(entry.file_name());
            if is_conda_prefix(&prefix) {
                found.push(PixiEnvironment {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    prefix,
                });
            }
        }
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    if let Some(active) = activated_environment(cwd, var, !found.is_empty()) {
        let known = |env: &PixiEnvironment| same_dir(&env.prefix, &active.prefix);
        if !found.iter().any(known) {
            found.push(active);
        }
    }
    found
}

/// The environment `pixi run` / `pixi shell` activated for the project at
/// `cwd`: `CONDA_PREFIX`, when pixi's own variables name a workspace root
/// that is `cwd` or a directory above it. At the root it is how a detached
/// environment is reached where pixi leaves no `.pixi/envs` link. Below
/// the root it counts only for a workspace member: a directory with pixi
/// files of its own (a member's `pixi.toml`) and no environments of its
/// own (`has_own_envs`), whose packages pixi installs into the
/// workspace's environments. Any other directory below the root (a uv or
/// Poetry project that happens to sit in the workspace's tree, a plain
/// subdirectory) keeps the answer it has without pixi. An activated
/// environment of an unrelated project, or a conda environment pixi did
/// not activate, is never this project's.
fn activated_environment(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
    has_own_envs: bool,
) -> Option<PixiEnvironment> {
    let set = |name: &str| var(name).filter(|value| !value.trim().is_empty());
    let root = set("PIXI_WORKSPACE_ROOT").or_else(|| set("PIXI_PROJECT_ROOT"))?;
    let root = Path::new(&root);
    let member = !has_own_envs && is_pixi_project(cwd) && is_below(cwd, root);
    if !same_dir(root, cwd) && !member {
        return None;
    }
    // A `conda activate` run inside `pixi shell` leaves pixi's variables
    // set over a prefix pixi did not install: that one is not the
    // workspace's.
    let prefix = PathBuf::from(set("CONDA_PREFIX")?);
    if !is_conda_prefix(&prefix) || !is_pixi_prefix(&prefix) {
        return None;
    }
    let name = set("PIXI_ENVIRONMENT_NAME").unwrap_or_else(|| {
        prefix
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    });
    Some(PixiEnvironment { name, prefix })
}

/// Whether `prefix` is a conda prefix: every one has a `conda-meta/`
/// directory, which is where conda, mamba and pixi record what they
/// installed.
pub fn is_conda_prefix(prefix: &Path) -> bool {
    prefix.join("conda-meta").is_dir()
}

/// The conda prefix an installed file or directory sits in, when it sits in
/// one: the nearest ancestor of `path` (or `path` itself) with a
/// `conda-meta/` directory. A `site-packages` is two or three levels below
/// its prefix (`Lib\site-packages`, `lib/python3.X/site-packages`).
pub fn conda_prefix_of(path: &Path) -> Option<&Path> {
    path.ancestors().take(5).find(|dir| is_conda_prefix(dir))
}

/// Whether pixi manages the conda prefix `prefix`: pixi writes its own
/// records into the `conda-meta/` of every environment it installs
/// (`pixi_env_prefix` since 0.20 at least, `pixi` in later releases), and
/// conda and mamba never do.
pub fn is_pixi_prefix(prefix: &Path) -> bool {
    let meta = prefix.join("conda-meta");
    ["pixi", "pixi_env_prefix"]
        .iter()
        .any(|record| meta.join(record).is_file())
}

/// Whether `dir` is inside `root`, however either is spelled.
fn is_below(dir: &Path, root: &Path) -> bool {
    match (std::fs::canonicalize(dir), std::fs::canonicalize(root)) {
        (Ok(dir), Ok(root)) => dir != root && dir.starts_with(&root),
        _ => false,
    }
}

/// Whether two paths name one directory, however either is spelled (a
/// detached environment is reached through the `.pixi/envs` link, and
/// macOS spells `/var` as `/private/var`).
fn same_dir(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn env_of(pairs: &[(&str, &Path)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string_lossy().into_owned()))
            .collect();
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
    }

    /// A conda prefix at `prefix` as pixi leaves one.
    fn conda_prefix(prefix: &Path) {
        std::fs::create_dir_all(prefix.join("conda-meta")).unwrap();
        std::fs::write(prefix.join("conda-meta").join("pixi"), "{}").unwrap();
    }

    fn names(envs: &[PixiEnvironment]) -> Vec<&str> {
        envs.iter().map(|env| env.name.as_str()).collect()
    }

    #[test]
    fn a_pixi_project_is_named_by_pixis_own_manifest_or_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        assert!(!is_pixi_project(project));
        // A `[tool.pixi]` pyproject is not enough: pip, uv and Poetry
        // install such a project too.
        std::fs::write(
            project.join("pyproject.toml"),
            "[tool.pixi.workspace]\nchannels = [\"conda-forge\"]\n",
        )
        .unwrap();
        assert!(!is_pixi_project(project));
        std::fs::write(project.join("pixi.lock"), "version: 6\n").unwrap();
        assert!(is_pixi_project(project));
        std::fs::remove_file(project.join("pixi.lock")).unwrap();
        std::fs::write(project.join("pixi.toml"), "[workspace]\n").unwrap();
        assert!(is_pixi_project(project));
        // A directory of that name is not a manifest.
        let other = tmp.path().join("other");
        std::fs::create_dir_all(other.join("pixi.toml")).unwrap();
        assert!(!is_pixi_project(&other));
    }

    /// pixi alone installs a project that has only pixi's files, with or
    /// without a `pyproject.toml` of metadata and tool settings. A file
    /// pip installs from beside them, a `pyproject.toml` with a
    /// `[build-system]` among them, means another installer may fill the
    /// interpreter on `PATH`.
    #[tokio::test]
    async fn pixi_owns_the_environment_unless_pip_installs_the_project_too() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        assert!(!pixi_owns_project_env(project).await, "not a pixi project");
        std::fs::write(project.join("pixi.toml"), "[workspace]\n").unwrap();
        assert!(pixi_owns_project_env(project).await);
        let metadata =
            "[project]\nname = \"a\"\nversion = \"0.1.0\"\n\n[tool.ruff]\nline-length = 100\n";
        std::fs::write(project.join("pyproject.toml"), metadata).unwrap();
        assert!(pixi_owns_project_env(project).await);
        for pip_file in ["requirements.txt", "setup.py", "setup.cfg"] {
            std::fs::write(project.join(pip_file), "").unwrap();
            assert!(!pixi_owns_project_env(project).await, "{pip_file}");
            std::fs::remove_file(project.join(pip_file)).unwrap();
        }
        assert!(pixi_owns_project_env(project).await);

        // A library packaged with a build backend is `pip install`ed too.
        let packaged = format!(
            "{metadata}\n[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n"
        );
        std::fs::write(project.join("pyproject.toml"), packaged).unwrap();
        assert!(!pixi_owns_project_env(project).await);
        // One that does not parse shows nothing.
        std::fs::write(project.join("pyproject.toml"), "[build-system\n").unwrap();
        assert!(pixi_owns_project_env(project).await);
    }

    #[tokio::test]
    async fn every_installed_environment_is_found_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        std::fs::write(project.join("pixi.toml"), "[workspace]\n").unwrap();
        assert!(pixi_environments_with(project, &no_env).await.is_empty());
        let envs = project.join(".pixi").join("envs");
        conda_prefix(&envs.join("test"));
        conda_prefix(&envs.join("default"));
        // Not environments: a directory that is no conda prefix, and a file.
        std::fs::create_dir_all(envs.join("half-made")).unwrap();
        std::fs::write(envs.join("notes.txt"), "").unwrap();
        let found = pixi_environments_with(project, &no_env).await;
        assert_eq!(names(&found), ["default", "test"]);
        assert_eq!(found[0].prefix, envs.join("default"));
    }

    /// `~/.pixi/envs` holds the tool environments of `pixi global
    /// install`. A run from the home directory, which has no pixi manifest
    /// or lock, must not take them for a project's.
    #[tokio::test]
    async fn envs_under_a_directory_without_pixi_files_are_no_projects() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        conda_prefix(&home.join(".pixi").join("envs").join("ruff"));
        assert!(pixi_environments_with(home, &no_env).await.is_empty());
        std::fs::write(home.join("pixi.lock"), "version: 6\n").unwrap();
        assert_eq!(
            names(&pixi_environments_with(home, &no_env).await),
            ["ruff"]
        );
    }

    /// `detached-environments`: pixi keeps the environments elsewhere and
    /// leaves `.pixi/envs` as a link to them.
    #[cfg(unix)]
    #[tokio::test]
    async fn detached_environments_are_reached_through_the_envs_link() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let detached = tmp.path().join("cache").join("envs").join("project-1234");
        conda_prefix(&detached.join("envs").join("default"));
        std::fs::create_dir_all(project.join(".pixi")).unwrap();
        std::fs::write(project.join("pixi.toml"), "[workspace]\n").unwrap();
        std::os::unix::fs::symlink(detached.join("envs"), project.join(".pixi").join("envs"))
            .unwrap();
        let found = pixi_environments_with(&project, &no_env).await;
        assert_eq!(names(&found), ["default"]);
        assert!(is_conda_prefix(&found[0].prefix));
    }

    /// Where pixi leaves no link (Windows), `pixi run` still names the
    /// workspace and the prefix it activated.
    #[tokio::test]
    async fn an_activated_environment_of_this_project_is_found_without_a_link() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        let prefix = tmp.path().join("cache").join("envs").join("lint");
        conda_prefix(&prefix);
        for root_var in ["PIXI_WORKSPACE_ROOT", "PIXI_PROJECT_ROOT"] {
            let var = env_of(&[(root_var, project.as_path()), ("CONDA_PREFIX", &prefix)]);
            let found = pixi_environments_with(&project, &var).await;
            assert_eq!(names(&found), ["lint"], "{root_var}");
            assert_eq!(found[0].prefix, prefix);
        }
        // pixi's own name for the environment wins over the directory's.
        let var = |name: &str| match name {
            "PIXI_WORKSPACE_ROOT" => Some(project.to_string_lossy().into_owned()),
            "CONDA_PREFIX" => Some(prefix.to_string_lossy().into_owned()),
            "PIXI_ENVIRONMENT_NAME" => Some("checks".to_string()),
            _ => None,
        };
        assert_eq!(
            names(&pixi_environments_with(&project, &var).await),
            ["checks"]
        );
    }

    /// pixi finds the workspace by walking up, so `pixi run` from a member
    /// directory (which may hold a `pixi.toml` of its own, for its
    /// package) activates the workspace's environment: that one is the
    /// member's. A directory below the root with environments of its own
    /// is a workspace of its own.
    #[tokio::test]
    async fn an_environment_activated_from_a_member_directory_is_the_members() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("workspace");
        let prefix = root.join(".pixi").join("envs").join("default");
        conda_prefix(&prefix);
        let member = root.join("packages").join("foo");
        std::fs::create_dir_all(&member).unwrap();
        std::fs::write(member.join("pixi.toml"), "[package]\nname = \"foo\"\n").unwrap();
        let var = env_of(&[
            ("PIXI_PROJECT_ROOT", root.as_path()),
            ("CONDA_PREFIX", &prefix),
        ]);

        let found = pixi_environments_with(&member, &var).await;
        assert_eq!(names(&found), ["default"]);
        assert_eq!(found[0].prefix, prefix);
        // Not activated: the member holds no environment of its own.
        assert!(pixi_environments_with(&member, &no_env).await.is_empty());

        // A nested workspace keeps to its own environments.
        let nested = root.join("vendor").join("tool");
        let own = nested.join(".pixi").join("envs").join("default");
        conda_prefix(&own);
        std::fs::write(nested.join("pixi.toml"), "[workspace]\n").unwrap();
        let found = pixi_environments_with(&nested, &var).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].prefix, own);

        // A project of another tool that sits in the workspace's tree (a
        // uv service with its own `.venv`) is no member: the workspace's
        // environment is not its, activated or not.
        let service = root.join("services").join("api");
        std::fs::create_dir_all(service.join(".venv")).unwrap();
        std::fs::write(service.join("uv.lock"), "version = 1\n").unwrap();
        assert!(pixi_environments_with(&service, &var).await.is_empty());
        // Nor is a plain subdirectory.
        let scripts = root.join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        assert!(pixi_environments_with(&scripts, &var).await.is_empty());

        // A directory outside the activated workspace is not its member.
        let outside = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        assert!(pixi_environments_with(&outside, &var).await.is_empty());
    }

    #[tokio::test]
    async fn an_activated_environment_is_not_listed_twice() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        std::fs::write(project.join("pixi.toml"), "[workspace]\n").unwrap();
        let prefix = project.join(".pixi").join("envs").join("default");
        conda_prefix(&prefix);
        let var = env_of(&[("PIXI_PROJECT_ROOT", project), ("CONDA_PREFIX", &prefix)]);
        let found = pixi_environments_with(project, &var).await;
        assert_eq!(names(&found), ["default"]);
    }

    /// Another project's activated environment, a conda environment pixi
    /// did not activate, and a prefix that is not one are not this
    /// project's.
    #[tokio::test]
    async fn an_environment_activated_for_something_else_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let other = tmp.path().join("other");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let prefix = tmp.path().join("conda").join("envs").join("science");
        conda_prefix(&prefix);

        let other_project = env_of(&[("PIXI_PROJECT_ROOT", &other), ("CONDA_PREFIX", &prefix)]);
        assert!(pixi_environments_with(&project, &other_project)
            .await
            .is_empty());

        let conda_only = env_of(&[("CONDA_PREFIX", &prefix)]);
        assert!(pixi_environments_with(&project, &conda_only)
            .await
            .is_empty());

        let not_a_prefix = env_of(&[
            ("PIXI_PROJECT_ROOT", project.as_path()),
            ("CONDA_PREFIX", &other),
        ]);
        assert!(pixi_environments_with(&project, &not_a_prefix)
            .await
            .is_empty());

        // pixi's variables still set over a conda environment pixi did not
        // install (`conda activate` inside `pixi shell`).
        let plain = tmp.path().join("miniconda").join("envs").join("plain");
        std::fs::create_dir_all(plain.join("conda-meta")).unwrap();
        let conda_over_pixi = env_of(&[
            ("PIXI_PROJECT_ROOT", project.as_path()),
            ("CONDA_PREFIX", &plain),
        ]);
        assert!(pixi_environments_with(&project, &conda_over_pixi)
            .await
            .is_empty());

        let blank = |name: &str| match name {
            "PIXI_PROJECT_ROOT" => Some("  ".to_string()),
            "CONDA_PREFIX" => Some(prefix.to_string_lossy().into_owned()),
            _ => None,
        };
        assert!(pixi_environments_with(&project, &blank).await.is_empty());
    }

    #[test]
    fn the_conda_prefix_of_a_site_packages_is_found_in_both_layouts() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tmp.path().join("env");
        conda_prefix(&prefix);
        let unix = prefix.join("lib").join("python3.13").join("site-packages");
        let windows = prefix.join("Lib").join("site-packages");
        std::fs::create_dir_all(&unix).unwrap();
        std::fs::create_dir_all(&windows).unwrap();
        assert_eq!(conda_prefix_of(&unix), Some(prefix.as_path()));
        assert_eq!(conda_prefix_of(&windows), Some(prefix.as_path()));
        assert_eq!(conda_prefix_of(&prefix), Some(prefix.as_path()));
        assert!(is_pixi_prefix(&prefix));
        // pixi 0.20 writes only `pixi_env_prefix`.
        let old_pixi = tmp
            .path()
            .join("old")
            .join(".pixi")
            .join("envs")
            .join("default");
        std::fs::create_dir_all(old_pixi.join("conda-meta")).unwrap();
        std::fs::write(old_pixi.join("conda-meta").join("pixi_env_prefix"), "").unwrap();
        assert!(is_pixi_prefix(&old_pixi));

        // A venv is not a conda prefix, and a conda prefix pixi did not
        // make is not pixi's.
        let venv = tmp.path().join(".venv").join("lib").join("python3.13");
        std::fs::create_dir_all(venv.join("site-packages")).unwrap();
        assert_eq!(conda_prefix_of(&venv.join("site-packages")), None);
        let conda = tmp.path().join("miniconda3");
        std::fs::create_dir_all(conda.join("conda-meta")).unwrap();
        assert!(is_conda_prefix(&conda));
        assert!(!is_pixi_prefix(&conda));
    }
}
