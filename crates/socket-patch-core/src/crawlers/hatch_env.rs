//! Where Hatch keeps a project's virtual environments.
//!
//! Hatch never uses `./.venv`: `hatch run` / `hatch shell` / `hatch test`
//! install into envs under its data directory, keyed by the project name and
//! a hash of the project root. Modelled on `hatch/env/virtual.py`,
//! `hatch/cli/application.py::get_env_directory` and
//! `hatch/utils/fs.py::Path.id`, unchanged in layout from Hatch 1.0 through
//! 1.18 except where noted:
//!
//! - env type directory: `[dirs.env] virtual` from Hatch's config file
//!   (absolute, else relative to the project), else
//!   `<data dir>/env/virtual`; the data dir is `HATCH_DATA_DIR`, else
//!   `dirs.data` from the config file, else the platform data dir;
//! - an env with an explicit `path` (`[tool.hatch.envs.<env>] path`,
//!   `hatch.toml`'s `[envs.<env>] path`, or `HATCH_ENV_TYPE_VIRTUAL_PATH`)
//!   lives exactly there;
//! - when the env type directory is `~/.virtualenvs` or inside the project,
//!   envs sit flat in it (`<dir>/<env name>`);
//! - Hatch 1.0 - 1.2 keep every env at `<dir>/<project name>-<project
//!   id>/<env name>`;
//! - otherwise `<dir>/<project name>/<project id>/<env name>`, where the
//!   project name is the PEP 503-normalized `[project] name` (or
//!   `<id>-unmanaged` without a `[project]` table), the id is the first 8
//!   chars of the URL-safe base64 sha256 of the project root (casefolded on
//!   Windows, and on macOS from Hatch 1.10), and the `default` env is named
//!   after the project.

use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item};

/// The verified remedy for a Hatch env still holding the upstream release
/// after its dependency was rewired. Hatch only syncs a changed dependency
/// with `pip install` (keeps a same-version release that is already
/// installed) or, before Hatch 1.16, accepts the installed release as
/// satisfying the new reference outright; either way it then records the
/// env as synced and never retries. Only recreating the env helps.
pub fn stale_install_remedy(env_name: &str) -> String {
    format!(
        "Hatch does not reinstall a release that is already present in an existing \
         environment (its pip installer keeps the installed bytes, uv before Hatch 1.16 \
         skips the sync, and Hatch then records the environment as synced), so the \
         rewired dependency only reaches fresh environments. Recreate this one with \
         `hatch env remove {env_name}` (the next `hatch run` rebuilds it), or run `hatch \
         env prune` for every environment of the project; then `socket-patch vex` \
         re-verifies the installed files."
    )
}

/// The Hatch env among `envs` whose tree holds `site`, however either is
/// spelled (an activated `VIRTUAL_ENV` may name the env through a symlink,
/// e.g. macOS's `/var` -> `/private/var`).
pub fn environment_of<'e>(
    envs: &'e [HatchEnvironment],
    site: &Path,
) -> Option<&'e HatchEnvironment> {
    if let Some(env) = envs.iter().find(|env| site.starts_with(&env.prefix)) {
        return Some(env);
    }
    let site = std::fs::canonicalize(site).ok()?;
    envs.iter()
        .find(|env| std::fs::canonicalize(&env.prefix).is_ok_and(|prefix| site.starts_with(prefix)))
}

/// One Hatch virtual environment of a project, as Hatch names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HatchEnvironment {
    /// The env name `hatch env remove <name>` takes (`default` for the
    /// env named after the project).
    pub name: String,
    /// The venv root (the directory holding `pyvenv.cfg`).
    pub prefix: PathBuf,
}

/// The existing Hatch virtual environments of the project at `cwd`. Empty
/// when `cwd` has neither `pyproject.toml` nor `hatch.toml`, or Hatch has
/// created none.
pub async fn hatch_environments(cwd: &Path) -> Vec<HatchEnvironment> {
    let var = |name: &str| std::env::var(name).ok();
    hatch_environments_with(cwd, &var).await
}

/// [`hatch_environments`] over an explicit environment.
pub(crate) async fn hatch_environments_with(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Vec<HatchEnvironment> {
    let pyproject = read_toml(&cwd.join("pyproject.toml")).await;
    let hatch_toml = read_toml(&cwd.join("hatch.toml")).await;
    if pyproject.is_none() && hatch_toml.is_none() {
        return Vec::new();
    }
    let root = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let config = read_config(var).await;
    let configured = configured_envs(pyproject.as_ref(), hatch_toml.as_ref());
    let project_name = pyproject.as_ref().and_then(project_name);

    let mut found: Vec<HatchEnvironment> = Vec::new();
    let mut push = |name: String, prefix: PathBuf| {
        if prefix.join("pyvenv.cfg").is_file() && !found.iter().any(|e| e.prefix == prefix) {
            found.push(HatchEnvironment { name, prefix });
        }
    };

    // Explicit paths win for the env they name.
    let override_path = var("HATCH_ENV_TYPE_VIRTUAL_PATH").filter(|v| !v.trim().is_empty());
    for env in &configured {
        if let Some(path) = override_path.as_deref().or(env.path.as_deref()) {
            push(env.name.clone(), resolve_env_path(&root, path));
        }
    }
    if override_path.is_some() && configured.iter().all(|e| e.name != "default") {
        push(
            "default".to_string(),
            resolve_env_path(&root, override_path.as_deref().unwrap()),
        );
    }

    let Some(env_dir) = virtual_env_dir(&root, config.as_ref(), var) else {
        return found;
    };
    let in_project = env_dir.starts_with(&root)
        || std::fs::canonicalize(&env_dir).is_ok_and(|d| d.starts_with(&root));
    let shared_flat = home_dir(var).is_some_and(|h| same_path(&env_dir, &h.join(".virtualenvs")));

    for id in project_ids(&root) {
        // Hatch 1.0 - 1.2: `<dir>/<project name>-<id>/<env name>`, whatever
        // the directory (no flat or unmanaged layouts yet).
        if let Some(name) = &project_name {
            for (dir_name, prefix) in subdirs(&env_dir.join(format!("{name}-{id}"))) {
                push(env_name_for(&dir_name, name), prefix);
            }
        }
        let name = project_name
            .clone()
            .unwrap_or_else(|| format!("{id}-unmanaged"));
        if in_project {
            // A directory inside the project holds only this project's envs.
            for (dir_name, prefix) in subdirs(&env_dir) {
                push(env_name_for(&dir_name, &name), prefix);
            }
            break;
        }
        if shared_flat {
            // `~/.virtualenvs` is shared, so only the names this project
            // configures are taken from it.
            push("default".to_string(), env_dir.join(&name));
            for env in configured.iter().filter(|e| e.name != "default") {
                push(env.name.clone(), env_dir.join(&env.name));
            }
            break;
        }
        let storage = env_dir.join(&name).join(&id);
        for (dir_name, prefix) in subdirs(&storage) {
            push(env_name_for(&dir_name, &name), prefix);
        }
    }
    found
}

/// `default` is stored under the project's name; every other env under its
/// own.
fn env_name_for(dir_name: &str, project_name: &str) -> String {
    if dir_name == project_name {
        "default".to_string()
    } else {
        dir_name.to_string()
    }
}

/// An env Hatch's project config declares, with its explicit `path`.
struct ConfiguredEnv {
    name: String,
    path: Option<String>,
}

/// `[tool.hatch.envs.*]` from pyproject, unless hatch.toml carries `envs`
/// (Hatch then reads hatch.toml's `[envs.*]` only). Envs whose `type` is
/// not `virtual` are left out.
fn configured_envs(
    pyproject: Option<&DocumentMut>,
    hatch_toml: Option<&DocumentMut>,
) -> Vec<ConfiguredEnv> {
    let table = hatch_toml
        .and_then(|doc| doc.get("envs"))
        .or_else(|| {
            pyproject
                .and_then(|doc| doc.get("tool"))
                .and_then(|tool| tool.get("hatch"))
                .and_then(|hatch| hatch.get("envs"))
        })
        .and_then(Item::as_table_like);
    let Some(table) = table else {
        return Vec::new();
    };
    table
        .iter()
        .filter_map(|(name, item)| {
            let env = item.as_table_like()?;
            if env
                .get("type")
                .and_then(Item::as_str)
                .is_some_and(|kind| kind != "virtual")
            {
                return None;
            }
            Some(ConfiguredEnv {
                name: name.to_string(),
                path: env
                    .get("path")
                    .and_then(Item::as_str)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string),
            })
        })
        .collect()
}

/// The PEP 503-normalized `[project] name` (hatchling's
/// `normalize_project_name`). `None` without a `[project]` table; a table
/// without a name is not a project Hatch can load, so `None` too.
fn project_name(pyproject: &DocumentMut) -> Option<String> {
    let name = pyproject.get("project")?.get("name")?.as_str()?;
    let mut out = String::with_capacity(name.len());
    let mut in_run = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !in_run {
                out.push('-');
            }
            in_run = true;
        } else {
            out.extend(c.to_lowercase());
            in_run = false;
        }
    }
    Some(out)
}

/// The project ids Hatch may have used for `root`: the hash of the path as
/// written, and of its casefolded form where some Hatch release casefolds
/// (Windows always; macOS from Hatch 1.10).
fn project_ids(root: &Path) -> Vec<String> {
    let text = strip_windows_verbatim_prefix(&root.to_string_lossy());
    let mut ids = Vec::new();
    if cfg!(windows) || cfg!(target_os = "macos") {
        ids.push(path_id(&text.to_lowercase()));
    }
    let raw = path_id(&text);
    if !ids.contains(&raw) {
        ids.push(raw);
    }
    ids
}

/// `hatch.utils.fs.Path.id` over an already normalized path string.
fn path_id(text: &str) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(text.as_bytes());
    let encoded = base64::engine::general_purpose::URL_SAFE.encode(digest);
    encoded[..8].to_string()
}

/// `\\?\C:\x` -> `C:\x`, `\\?\UNC\srv\share` -> `\\srv\share` (Python's
/// `Path.cwd()` never carries the verbatim prefix `canonicalize` adds).
fn strip_windows_verbatim_prefix(text: &str) -> String {
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        text.to_string()
    }
}

/// The env type directory for `virtual` (see the module docs).
fn virtual_env_dir(
    root: &Path,
    config: Option<&DocumentMut>,
    var: &impl Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    let dirs = config.and_then(|c| c.get("dirs"));
    if let Some(configured) = dirs
        .and_then(|d| d.get("env"))
        .and_then(|e| e.get("virtual"))
        .and_then(Item::as_str)
    {
        return Some(absolutize(root, &expand(configured, var)));
    }
    let data = var("HATCH_DATA_DIR")
        .filter(|v| !v.trim().is_empty())
        .map(|v| expand(&v, var))
        .or_else(|| {
            dirs.and_then(|d| d.get("data"))
                .and_then(Item::as_str)
                .map(|v| expand(v, var))
        })
        .map(PathBuf::from)
        .or_else(|| default_data_dir(var))?;
    Some(data.join("env").join("virtual"))
}

/// Hatch's config file: `HATCH_CONFIG`, else `config.toml` in
/// `platformdirs.user_config_dir("hatch")`.
async fn read_config(var: &impl Fn(&str) -> Option<String>) -> Option<DocumentMut> {
    let path = var("HATCH_CONFIG")
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| default_config_dir(var).map(|d| d.join("config.toml")))?;
    read_toml(&path).await
}

/// `platformdirs.user_data_dir("hatch", appauthor=False)`.
fn default_data_dir(var: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if cfg!(windows) {
        local_app_data(var).map(|d| d.join("hatch"))
    } else if cfg!(target_os = "macos") {
        Some(
            home_dir(var)?
                .join("Library")
                .join("Application Support")
                .join("hatch"),
        )
    } else {
        Some(
            xdg(var, "XDG_DATA_HOME")
                .or_else(|| home_dir(var).map(|h| h.join(".local").join("share")))?
                .join("hatch"),
        )
    }
}

/// `platformdirs.user_config_dir("hatch", appauthor=False)`.
fn default_config_dir(var: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if cfg!(windows) {
        local_app_data(var).map(|d| d.join("hatch"))
    } else if cfg!(target_os = "macos") {
        Some(
            home_dir(var)?
                .join("Library")
                .join("Application Support")
                .join("hatch"),
        )
    } else {
        Some(
            xdg(var, "XDG_CONFIG_HOME")
                .or_else(|| home_dir(var).map(|h| h.join(".config")))?
                .join("hatch"),
        )
    }
}

fn local_app_data(var: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    var("LOCALAPPDATA")
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| home_dir(var).map(|h| h.join("AppData").join("Local")))
}

/// An XDG base directory, honoured only when absolute (as platformdirs).
fn xdg(var: &impl Fn(&str) -> Option<String>, name: &str) -> Option<PathBuf> {
    var(name)
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn home_dir(var: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    var("HOME")
        .or_else(|| var("USERPROFILE"))
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
}

/// Hatch's `Path.expand`: `~` and `$VAR` / `${VAR}` (`%VAR%` on Windows
/// is left to the shell that set it and not modelled).
fn expand(text: &str, var: &impl Fn(&str) -> Option<String>) -> String {
    let text = match text.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') || rest.starts_with('\\') => {
            match home_dir(var) {
                Some(home) => format!("{}{rest}", home.display()),
                None => text.to_string(),
            }
        }
        _ => text.to_string(),
    };
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let (name, tail) = if let Some(braced) = after.strip_prefix('{') {
            match braced.find('}') {
                Some(end) => (&braced[..end], &braced[end + 1..]),
                None => ("", after),
            }
        } else {
            let end = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            (&after[..end], &after[end..])
        };
        match (!name.is_empty()).then(|| var(name)).flatten() {
            Some(value) => out.push_str(&value),
            None => {
                // Python's expandvars leaves an unknown variable as written.
                out.push('$');
                out.push_str(&after[..after.len() - tail.len()]);
            }
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// `path` against the project root, as Hatch joins it.
fn absolutize(root: &Path, path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

/// An env's explicit `path`, resolved like Hatch's `(root / path).resolve()`.
fn resolve_env_path(root: &Path, path: &str) -> PathBuf {
    let joined = absolutize(root, path);
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// The subdirectories of `dir` by name (none when it is missing).
fn subdirs(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())))
        .collect();
    out.sort();
    out
}

/// A regular file's TOML (a FIFO or device planted at the path is never
/// opened, so discovery cannot block on it).
async fn read_toml(path: &Path) -> Option<DocumentMut> {
    crate::utils::fs::read_regular_to_string(path)
        .await
        .ok()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, String)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        move |name: &str| map.get(name).cloned()
    }

    fn make_venv(prefix: &Path) {
        std::fs::create_dir_all(prefix).unwrap();
        std::fs::write(prefix.join("pyvenv.cfg"), "home = /usr/bin\n").unwrap();
    }

    const PYPROJECT: &str = "[project]\nname = \"My_App.Core\"\nversion = \"0.1.0\"\n";

    /// Hatch 1.18.1 computes `Path("/home/user/app").id` as `zrSR0Z2A`
    /// (`urlsafe_b64encode(sha256(b"/home/user/app").digest())[:8]`).
    #[test]
    fn path_id_matches_hatch() {
        assert_eq!(path_id("/home/user/app"), "zrSR0Z2A");
    }

    #[test]
    fn project_name_is_pep503_normalized() {
        let doc: DocumentMut = PYPROJECT.parse().unwrap();
        assert_eq!(project_name(&doc).as_deref(), Some("my-app-core"));
    }

    #[tokio::test]
    async fn finds_default_and_named_envs_under_the_data_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("pyproject.toml"), PYPROJECT).unwrap();
        let data = tmp.path().join("data");
        let root = std::fs::canonicalize(&project).unwrap();
        let id = project_ids(&root).pop().unwrap();
        let storage = data.join("env/virtual/my-app-core").join(&id);
        make_venv(&storage.join("my-app-core"));
        make_venv(&storage.join("test"));
        // Another project's env with the same name is not ours.
        make_venv(&data.join("env/virtual/my-app-core/XXXXXXXX/my-app-core"));

        let var = env_of(&[
            ("HATCH_DATA_DIR", data.display().to_string()),
            ("HOME", tmp.path().join("home").display().to_string()),
        ]);
        let found = hatch_environments_with(&project, &var).await;
        assert_eq!(
            found,
            vec![
                HatchEnvironment {
                    name: "default".into(),
                    prefix: storage.join("my-app-core")
                },
                HatchEnvironment {
                    name: "test".into(),
                    prefix: storage.join("test")
                },
            ]
        );
    }

    /// Hatch 1.0 - 1.2 (`hatch/env/virtual.py` there): `<name>-<id>`.
    #[tokio::test]
    async fn legacy_hatch_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("pyproject.toml"), PYPROJECT).unwrap();
        let data = tmp.path().join("data");
        let root = std::fs::canonicalize(&project).unwrap();
        let id = project_ids(&root).pop().unwrap();
        let prefix = data
            .join("env/virtual")
            .join(format!("my-app-core-{id}"))
            .join("my-app-core");
        make_venv(&prefix);
        let var = env_of(&[("HATCH_DATA_DIR", data.display().to_string())]);
        assert_eq!(
            hatch_environments_with(&project, &var).await,
            vec![HatchEnvironment {
                name: "default".into(),
                prefix
            }]
        );
    }

    #[tokio::test]
    async fn default_data_dir_and_config_dirs_env_virtual() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("pyproject.toml"), PYPROJECT).unwrap();
        let root = std::fs::canonicalize(&project).unwrap();
        let id = project_ids(&root).pop().unwrap();
        let var = env_of(&[
            ("HOME", home.display().to_string()),
            ("LOCALAPPDATA", home.join("lad").display().to_string()),
        ]);
        let data = default_data_dir(&var).unwrap();
        let prefix = data
            .join("env/virtual/my-app-core")
            .join(&id)
            .join("my-app-core");
        make_venv(&prefix);
        let found = hatch_environments_with(&project, &var).await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].prefix, prefix);

        // `[dirs.env] virtual` moves the env type directory.
        let config_dir = default_config_dir(&var).unwrap();
        std::fs::create_dir_all(&config_dir).unwrap();
        let elsewhere = tmp.path().join("envs");
        std::fs::write(
            config_dir.join("config.toml"),
            format!("[dirs.env]\nvirtual = '{}'\n", elsewhere.display()),
        )
        .unwrap();
        assert!(hatch_environments_with(&project, &var).await.is_empty());
        let moved = elsewhere.join("my-app-core").join(&id).join("lint");
        make_venv(&moved);
        let found = hatch_environments_with(&project, &var).await;
        assert_eq!(
            found,
            vec![HatchEnvironment {
                name: "lint".into(),
                prefix: moved
            }]
        );
    }

    #[tokio::test]
    async fn in_project_env_dir_is_flat_and_explicit_paths_win() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            format!("{PYPROJECT}\n[tool.hatch.envs.docs]\npath = \"envs/docs\"\n"),
        )
        .unwrap();
        let config = tmp.path().join("hatch-config.toml");
        std::fs::write(&config, "[dirs.env]\nvirtual = \".hatch\"\n").unwrap();
        make_venv(&project.join(".hatch/my-app-core"));
        make_venv(&project.join(".hatch/test"));
        make_venv(&project.join("envs/docs"));
        let var = env_of(&[("HATCH_CONFIG", config.display().to_string())]);
        let found = hatch_environments_with(&project, &var).await;
        let root = std::fs::canonicalize(&project).unwrap();
        let names: Vec<_> = found
            .iter()
            .map(|e| (e.name.as_str(), e.prefix.clone()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("docs", root.join("envs/docs")),
                ("default", root.join(".hatch/my-app-core")),
                ("test", root.join(".hatch/test")),
            ]
        );
    }

    #[tokio::test]
    async fn unmanaged_project_and_no_project_files() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        let data = tmp.path().join("data");
        let var = env_of(&[("HATCH_DATA_DIR", data.display().to_string())]);
        assert!(hatch_environments_with(&project, &var).await.is_empty());

        std::fs::write(project.join("hatch.toml"), "[envs.default]\n").unwrap();
        let root = std::fs::canonicalize(&project).unwrap();
        let id = project_ids(&root).pop().unwrap();
        let name = format!("{id}-unmanaged");
        let prefix = data.join("env/virtual").join(&name).join(&id).join(&name);
        make_venv(&prefix);
        let found = hatch_environments_with(&project, &var).await;
        assert_eq!(
            found,
            vec![HatchEnvironment {
                name: "default".into(),
                prefix
            }]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_configuration_never_blocks() {
        for filename in ["pyproject.toml", "hatch.toml", "config.toml"] {
            let tmp = tempfile::tempdir().unwrap();
            let project = tmp.path().join("app");
            std::fs::create_dir_all(&project).unwrap();
            if filename != "pyproject.toml" {
                std::fs::write(project.join("pyproject.toml"), PYPROJECT).unwrap();
            }
            let fifo = if filename == "config.toml" {
                tmp.path().join(filename)
            } else {
                project.join(filename)
            };
            assert!(std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success());
            let var = env_of(&[
                ("HATCH_CONFIG", fifo.display().to_string()),
                (
                    "HATCH_DATA_DIR",
                    tmp.path().join("data").display().to_string(),
                ),
            ]);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                hatch_environments_with(&project, &var),
            )
            .await;
            if result.is_err() {
                drop(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&fifo)
                        .unwrap(),
                );
            }
            assert!(result.unwrap().is_empty(), "{filename}");
        }
    }

    /// macOS spells temp dirs `/var/...` and `/private/var/...`: an
    /// activated env named through a symlink is still that Hatch env.
    #[cfg(unix)]
    #[test]
    fn environment_of_sees_through_symlinked_spellings() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        let site = real.join("env/lib/python3.12/site-packages");
        std::fs::create_dir_all(&site).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let envs = vec![HatchEnvironment {
            name: "default".into(),
            prefix: real.join("env"),
        }];
        let via_link = link.join("env/lib/python3.12/site-packages");
        assert_eq!(environment_of(&envs, &via_link).unwrap().name, "default");
        assert_eq!(environment_of(&envs, &site).unwrap().name, "default");
        assert!(environment_of(&envs, tmp.path()).is_none());
    }

    #[test]
    fn expand_matches_python() {
        let var = env_of(&[("HOME", "/h".to_string()), ("X", "ex".to_string())]);
        assert_eq!(expand("~/a/$X/${X}b/$NOPE/c", &var), "/h/a/ex/exb/$NOPE/c");
        assert_eq!(expand("~user/a", &var), "~user/a");
    }
}

/// [`project_ids`] for tests elsewhere in the crate.
#[cfg(test)]
pub(crate) fn project_ids_for_tests(root: &Path) -> Vec<String> {
    project_ids(root)
}
