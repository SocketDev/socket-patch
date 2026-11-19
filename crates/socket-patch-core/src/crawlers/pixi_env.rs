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
//!   environment's prefix (`CONDA_PREFIX`).
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

/// Whether pixi installs the project at `cwd`: it has a `pixi.toml` or a
/// `pixi.lock`. Such a project's packages are only ever in pixi's own
/// environments, so one with none installed yet has nothing installed.
pub fn is_pixi_project(cwd: &Path) -> bool {
    PIXI_FILES.iter().any(|name| cwd.join(name).is_file())
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
    found.sort_by(|a, b| a.name.cmp(&b.name));
    if let Some(active) = activated_environment(cwd, var) {
        let known = |env: &PixiEnvironment| same_dir(&env.prefix, &active.prefix);
        if !found.iter().any(known) {
            found.push(active);
        }
    }
    found
}

/// The environment `pixi run` / `pixi shell` activated for the project at
/// `cwd`: `CONDA_PREFIX`, when pixi's own variables name `cwd` as the
/// workspace root. It is how a detached environment is reached where pixi
/// leaves no `.pixi/envs` link. An activated environment of any other
/// project, or a conda environment pixi did not activate, is not this
/// project's.
fn activated_environment(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Option<PixiEnvironment> {
    let set = |name: &str| var(name).filter(|value| !value.trim().is_empty());
    let root = set("PIXI_WORKSPACE_ROOT").or_else(|| set("PIXI_PROJECT_ROOT"))?;
    if !same_dir(Path::new(&root), cwd) {
        return None;
    }
    let prefix = PathBuf::from(set("CONDA_PREFIX")?);
    if !is_conda_prefix(&prefix) {
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

    #[tokio::test]
    async fn every_installed_environment_is_found_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
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

    #[tokio::test]
    async fn an_activated_environment_is_not_listed_twice() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
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
