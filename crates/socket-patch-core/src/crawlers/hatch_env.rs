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
    let (configured, matrix_cut) = configured_envs(pyproject.as_ref(), hatch_toml.as_ref());
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
    // Hatch: `root in data_directory.resolve().parents`, so `..` is
    // resolved first and the project root itself is not "inside".
    let resolved_env_dir = resolve(&env_dir);
    let in_project = resolved_env_dir != root && resolved_env_dir.starts_with(&root);
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
            // configures are taken from it, matrix variants included.
            push("default".to_string(), env_dir.join(&name));
            for env in &configured {
                for generated in env.generated_names() {
                    if generated != "default" {
                        push(generated.clone(), env_dir.join(&generated));
                    }
                }
            }
            // The matrix names are the only way into this directory, so
            // the ones not read are environments not looked at.
            if let Some(file) = matrix_cut {
                warn_matrix_cut(&cwd.join(file), &env_dir);
            }
            // `hatch test` (Hatch 1.10+) installs the project into the
            // internal `hatch-test.<python>` matrix, whose default Python
            // list varies by Hatch release. A project's
            // `[tool.hatch.envs.hatch-test]` is layered over that default,
            // so the default matrix stays unless the project sets its own.
            let own_test_matrix = configured
                .iter()
                .any(|e| e.name == "hatch-test" && e.has_matrix);
            if !own_test_matrix {
                for (dir_name, prefix) in subdirs(&env_dir) {
                    if dir_name.starts_with("hatch-test.") {
                        push(dir_name, prefix);
                    }
                }
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

/// Say once (muted only by `--silent`) that `file`'s matrices name more
/// environments than were looked for in the shared `env_dir`, instead of
/// reporting the ones read as all there are.
fn warn_matrix_cut(file: &Path, env_dir: &Path) {
    static SHOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    crate::utils::notice::notice_once(crate::utils::notice::Notice::Warning, &SHOWN, || {
        format!(
            "Warning: {} declares more than {MAX_MATRIX_ENVS} Hatch matrix environments. Only \
             the first {MAX_MATRIX_ENVS} were looked for in {}, so packages installed in the \
             others were not scanned.",
            file.display(),
            env_dir.display()
        )
    });
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
    /// Whether its `matrix` generates env names: Hatch then creates
    /// those, not the env itself.
    has_matrix: bool,
    /// The names its `matrix` generates ([`matrix_names`]), as far as the
    /// project's [`MAX_MATRIX_ENVS`] reaches.
    matrix_names: Vec<String>,
}

impl ConfiguredEnv {
    /// The env names Hatch creates from this entry: the matrix variants,
    /// or the env itself without a matrix.
    fn generated_names(&self) -> Vec<String> {
        if self.has_matrix {
            self.matrix_names.clone()
        } else {
            vec![self.name.clone()]
        }
    }
}

/// Most matrix combinations read from one project's Hatch config. A matrix
/// is a product, so ten lines of TOML can name billions of environments;
/// each one is a virtualenv Hatch has to build on disk (a `pip install`
/// and tens of megabytes apiece), and the widest matrices projects keep
/// are a few dozen (five Pythons by a handful of dependency versions).
const MAX_MATRIX_ENVS: usize = 1024;

/// Longest env name read from a matrix, in bytes. The name is a directory
/// name, and no filesystem this runs on holds a longer one.
const MAX_ENV_NAME_LEN: usize = 255;

/// Longest `matrix-name-format`, with its `{variable}` filled in, that a
/// name is rendered from: a format repeating its placeholders would
/// otherwise multiply a long value into gigabytes.
const MAX_NAME_FORMAT_LEN: usize = 4096;

/// `[tool.hatch.envs.*]` from pyproject, unless hatch.toml carries `envs`
/// (Hatch then reads hatch.toml's `[envs.*]` only). Envs whose `type` is
/// not `virtual` are left out. With them, the file whose matrices name
/// more than [`MAX_MATRIX_ENVS`] combinations, the ones past that left
/// out of [`ConfiguredEnv::matrix_names`].
fn configured_envs(
    pyproject: Option<&DocumentMut>,
    hatch_toml: Option<&DocumentMut>,
) -> (Vec<ConfiguredEnv>, Option<&'static str>) {
    let (file, envs) = match hatch_toml.and_then(|doc| doc.get("envs")) {
        Some(envs) => ("hatch.toml", Some(envs)),
        None => (
            "pyproject.toml",
            pyproject
                .and_then(|doc| doc.get("tool"))
                .and_then(|tool| tool.get("hatch"))
                .and_then(|hatch| hatch.get("envs")),
        ),
    };
    let Some(table) = envs.and_then(Item::as_table_like) else {
        return (Vec::new(), None);
    };
    let mut combinations = MAX_MATRIX_ENVS;
    let mut cut = false;
    let envs = table
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
            let matrix = matrix_names(name, env, &mut combinations);
            cut |= matrix.cut;
            Some(ConfiguredEnv {
                name: name.to_string(),
                path: env
                    .get("path")
                    .and_then(Item::as_str)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string),
                has_matrix: matrix.generates,
                matrix_names: matrix.names,
            })
        })
        .collect();
    (envs, cut.then_some(file))
}

/// What an env's `matrix` generates ([`matrix_names`]).
#[derive(Default)]
struct Matrix {
    /// Some matrix table has variables, each with a value: the matrix
    /// names at least one env.
    generates: bool,
    names: Vec<String>,
    /// The project's combinations ran out before this matrix was read
    /// through.
    cut: bool,
}

/// The env names an env's `matrix` generates, as
/// `hatch/project/config.py::envs` builds them: per matrix table, the
/// product of its variables' values, a `py`/`python` variable first as
/// `py<value>`, the rest through `matrix-name-format` (default
/// `{value}`), joined with `-` and prefixed `<env>.` unless the env is
/// `default`. A format set by overrides or inherited through `template`
/// is not modelled.
///
/// The product is walked one combination at a time, each taking one of
/// the project's `combinations` ([`MAX_MATRIX_ENVS`]), and stops when
/// they run out. A name longer than [`MAX_ENV_NAME_LEN`] names no
/// directory, so it is not built.
fn matrix_names(
    env_name: &str,
    env: &dyn toml_edit::TableLike,
    combinations: &mut usize,
) -> Matrix {
    let format = env
        .get("matrix-name-format")
        .and_then(Item::as_str)
        .filter(|f| f.contains("{value}"))
        .unwrap_or("{value}");
    let tables: Vec<&dyn toml_edit::TableLike> = match env.get("matrix") {
        Some(Item::ArrayOfTables(tables)) => tables
            .iter()
            .map(|t| t as &dyn toml_edit::TableLike)
            .collect(),
        Some(Item::Value(toml_edit::Value::Array(array))) => array
            .iter()
            .filter_map(|v| v.as_inline_table())
            .map(|t| t as &dyn toml_edit::TableLike)
            .collect(),
        _ => return Matrix::default(),
    };
    let prefix = if env_name == "default" {
        String::new()
    } else {
        format!("{env_name}.")
    };
    let mut matrix = Matrix::default();
    for table in tables {
        let mut variables: Vec<(&str, Vec<&str>)> = table
            .iter()
            .filter_map(|(variable, values)| {
                let values: Vec<&str> = values
                    .as_array()?
                    .iter()
                    .filter_map(|v| v.as_str())
                    .collect();
                Some((variable, values))
            })
            .collect();
        let python = variables
            .iter()
            .position(|(variable, _)| matches!(*variable, "py" | "python"));
        if let Some(index) = python {
            let entry = variables.remove(index);
            variables.insert(0, entry);
        }
        // No variable, or one without a value: the product is empty.
        if variables.is_empty() || variables.iter().any(|(_, values)| values.is_empty()) {
            continue;
        }
        matrix.generates = true;
        // A name holds a `-` between every two parts, so more variables
        // than that make every name too long.
        if variables.len() > MAX_ENV_NAME_LEN + 1 {
            continue;
        }
        // Each value as the part of a name it becomes; `None` for one too
        // long to be in any.
        let rendered: Vec<Vec<Option<String>>> = variables
            .iter()
            .enumerate()
            .map(|(position, (variable, values))| {
                if position == 0 && python.is_some() {
                    return values
                        .iter()
                        .map(|value| {
                            (value.len() <= MAX_ENV_NAME_LEN).then(|| {
                                if value.starts_with("py") {
                                    value.to_string()
                                } else {
                                    format!("py{value}")
                                }
                            })
                        })
                        .collect();
                }
                let named = replace_within(format, "{variable}", variable, MAX_NAME_FORMAT_LEN);
                values
                    .iter()
                    .map(|value| {
                        replace_within(named.as_deref()?, "{value}", value, MAX_ENV_NAME_LEN)
                    })
                    .collect()
            })
            .collect();
        // The combination being read: an index into each variable's
        // values, the last variable's turning fastest.
        let mut at = vec![0usize; rendered.len()];
        'combinations: loop {
            let Some(left) = combinations.checked_sub(1) else {
                matrix.cut = true;
                return matrix;
            };
            *combinations = left;
            let parts: Option<Vec<&str>> = at
                .iter()
                .zip(&rendered)
                .map(|(&value, values)| values[value].as_deref())
                .collect();
            if let Some(parts) = parts {
                let len =
                    prefix.len() + parts.iter().map(|p| p.len()).sum::<usize>() + parts.len() - 1;
                if len <= MAX_ENV_NAME_LEN {
                    matrix.names.push(format!("{prefix}{}", parts.join("-")));
                }
            }
            for position in (0..at.len()).rev() {
                at[position] += 1;
                if at[position] < rendered[position].len() {
                    continue 'combinations;
                }
                at[position] = 0;
            }
            break;
        }
    }
    matrix
}

/// `text` with every `from` replaced by `to`, or `None` when the result
/// is longer than `max` bytes (found out before it is built).
fn replace_within(text: &str, from: &str, to: &str, max: usize) -> Option<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(from) {
        if out.len() + at + to.len() > max {
            return None;
        }
        out.push_str(&rest[..at]);
        out.push_str(to);
        rest = &rest[at + from.len()..];
    }
    (out.len() + rest.len() <= max).then(|| {
        out.push_str(rest);
        out
    })
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
        return path;
    }
    // Push component by component: a canonical Windows root is a
    // verbatim `\\?\` path, where `/` would not separate components.
    let mut out = root.to_path_buf();
    for part in path.components() {
        out.push(part);
    }
    out
}

/// An env's explicit `path`, resolved like Hatch's `(root / path).resolve()`.
fn resolve_env_path(root: &Path, path: &str) -> PathBuf {
    resolve(&absolutize(root, path))
}

/// Python's `Path.resolve()` (non-strict), with `.` / `..` folded first so
/// verbatim Windows paths (where the OS does not fold them) resolve too;
/// symlinks are then followed in the longest existing prefix.
fn resolve(path: &Path) -> PathBuf {
    let mut folded = PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                folded.pop();
            }
            other => folded.push(other),
        }
    }
    let mut existing = folded.clone();
    let mut rest = Vec::new();
    loop {
        if let Ok(real) = std::fs::canonicalize(&existing) {
            let mut out = real;
            for name in rest.into_iter().rev() {
                out.push(name);
            }
            return out;
        }
        match existing.file_name().map(|n| n.to_os_string()) {
            Some(name) if existing.pop() => rest.push(name),
            _ => return folded,
        }
    }
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

/// [`project_ids`] for tests elsewhere in the crate.
#[cfg(test)]
pub(crate) fn project_ids_for_tests(root: &Path) -> Vec<String> {
    project_ids(root)
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

    /// `~/.virtualenvs` holds every project's envs flat, so only the names
    /// this project's config generates are taken from it, matrix
    /// variants included (`hatch/project/config.py::envs`).
    #[tokio::test]
    async fn shared_virtualenvs_dir_takes_configured_and_matrix_names() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            format!(
                "{PYPROJECT}\n\
                 [[tool.hatch.envs.default.matrix]]\npy = [\"3.10\"]\n\n\
                 [tool.hatch.envs.test]\n\
                 matrix = [{{ version = [\"a\"], python = [\"3.11\", \"py3.12\"] }}]\n\n\
                 [tool.hatch.envs.lint]\n\
                 matrix-name-format = \"{{variable}}_{{value}}\"\n\
                 [[tool.hatch.envs.lint.matrix]]\ntool = [\"ruff\"]\n\n\
                 [tool.hatch.envs.hatch-test]\nextra-dependencies = [\"rich\"]\n"
            ),
        )
        .unwrap();
        let config = tmp.path().join("hatch-config.toml");
        std::fs::write(&config, "[dirs.env]\nvirtual = \"~/.virtualenvs\"\n").unwrap();
        let shared = home.join(".virtualenvs");
        for name in [
            "my-app-core",
            "py3.10",
            "test.py3.11-a",
            "test.py3.12-a",
            "lint.tool_ruff",
            "hatch-test.py3.13",
            // Another project's envs share the directory.
            "test.py3.9-a",
            "other",
        ] {
            make_venv(&shared.join(name));
        }
        let var = env_of(&[
            ("HATCH_CONFIG", config.display().to_string()),
            ("HOME", home.display().to_string()),
        ]);
        let mut names: Vec<_> = hatch_environments_with(&project, &var)
            .await
            .into_iter()
            .map(|e| {
                assert_eq!(e.prefix.file_name().unwrap(), {
                    let dir = if e.name == "default" {
                        "my-app-core"
                    } else {
                        &e.name
                    };
                    std::ffi::OsString::from(dir)
                });
                e.name
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            [
                "default",
                "hatch-test.py3.13",
                "lint.tool_ruff",
                "py3.10",
                "test.py3.11-a",
                "test.py3.12-a"
            ]
        );
    }

    /// `count` values `v0`, `v1`, … as a TOML array.
    fn values(count: usize) -> String {
        let quoted: Vec<String> = (0..count).map(|i| format!("\"v{i}\"")).collect();
        format!("[{}]", quoted.join(", "))
    }

    /// A matrix is a product: five variables of twelve values name
    /// 248,832 environments (and eight of sixteen, four billion). Only the
    /// first [`MAX_MATRIX_ENVS`] combinations are looked for in the shared
    /// `~/.virtualenvs`, in Hatch's order, so the list a project file
    /// costs is bounded.
    #[tokio::test]
    async fn shared_virtualenvs_dir_reads_a_matrix_up_to_the_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        let twelve = values(12);
        std::fs::write(
            project.join("pyproject.toml"),
            format!(
                "{PYPROJECT}\n[tool.hatch.envs.test]\n\
                 matrix = [{{ a = {twelve}, b = {twelve}, c = {twelve}, d = {twelve}, \
                 e = {twelve} }}]\n\n\
                 [tool.hatch.envs.docs]\n"
            ),
        )
        .unwrap();
        let config = tmp.path().join("hatch-config.toml");
        std::fs::write(&config, "[dirs.env]\nvirtual = \"~/.virtualenvs\"\n").unwrap();
        let shared = home.join(".virtualenvs");
        // The first combination, the last one inside the cap (1,024 =
        // 7 × 144 + 1 × 12 + 4), the one after it, and the very last.
        for name in [
            "test.v0-v0-v0-v0-v0",
            "test.v0-v0-v7-v1-v3",
            "test.v0-v0-v7-v1-v4",
            "test.v11-v11-v11-v11-v11",
            "docs",
        ] {
            make_venv(&shared.join(name));
        }
        let var = env_of(&[
            ("HATCH_CONFIG", config.display().to_string()),
            ("HOME", home.display().to_string()),
        ]);
        let names: Vec<String> = hatch_environments_with(&project, &var)
            .await
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(
            names,
            ["test.v0-v0-v0-v0-v0", "test.v0-v0-v7-v1-v3", "docs"]
        );
    }

    /// The names a config's matrices generate, per env, and the file named
    /// as cut.
    fn generated(
        pyproject: &str,
        hatch_toml: Option<&str>,
    ) -> (Vec<Vec<String>>, Option<&'static str>) {
        let pyproject: DocumentMut = pyproject.parse().unwrap();
        let hatch_toml: Option<DocumentMut> = hatch_toml.map(|text| text.parse().unwrap());
        let (envs, cut) = configured_envs(Some(&pyproject), hatch_toml.as_ref());
        (
            envs.iter().map(ConfiguredEnv::generated_names).collect(),
            cut,
        )
    }

    /// The cap is the project's, not each matrix's: the combinations are
    /// counted across every env and matrix table of the file, in order,
    /// and the file that holds them is the one named.
    #[test]
    fn matrix_combinations_are_counted_across_the_project() {
        // 16^5 combinations in one table.
        let sixteen = values(16);
        let wide = format!(
            "[tool.hatch.envs.default]\n\
             matrix = [{{ a = {sixteen}, b = {sixteen}, c = {sixteen}, d = {sixteen}, \
             e = {sixteen} }}]\n"
        );
        let (names, cut) = generated(&wide, None);
        assert_eq!(names[0].len(), MAX_MATRIX_ENVS);
        assert_eq!(names[0][0], "v0-v0-v0-v0-v0");
        assert_eq!(names[0][MAX_MATRIX_ENVS - 1], "v0-v0-v3-v15-v15");
        assert_eq!(cut, Some("pyproject.toml"));

        // Exactly the cap is read whole.
        let (names, cut) = generated(
            &format!(
                "[tool.hatch.envs.a]\nmatrix = [{{ x = {}, y = {} }}]\n",
                values(32),
                values(32)
            ),
            None,
        );
        assert_eq!((names[0].len(), cut), (MAX_MATRIX_ENVS, None));
        assert_eq!(names[0][MAX_MATRIX_ENVS - 1], "a.v31-v31");

        // One past it, in a later env's second table, is cut; an env
        // after the cut generates nothing, and is still not looked for
        // under its own name (Hatch creates its matrix names only).
        let spread = format!(
            "[envs.a]\nmatrix = [{{ x = {}, y = {} }}, {{ z = {} }}]\n\n\
             [envs.b]\nmatrix = [{{ x = {} }}, {{ y = {} }}]\n\n\
             [envs.c]\nmatrix = [{{ x = {} }}]\n\n[envs.plain]\n",
            values(30),
            values(30),
            values(100),
            values(20),
            values(5),
            values(3),
        );
        let (names, cut) = generated("[project]\nname = \"x\"\n", Some(&spread));
        let counts: Vec<usize> = names.iter().map(Vec::len).collect();
        assert_eq!(counts, [1000, 24, 0, 1]);
        assert_eq!(names[1][23], "b.v3");
        assert_eq!(names[3], ["plain"]);
        assert_eq!(cut, Some("hatch.toml"));
    }

    /// A name longer than a directory name is not built, however it comes
    /// about: a long value, a format that repeats its placeholders, or
    /// more variables than a name has room for. Each combination still
    /// counts, so a matrix of nothing but such names ends at the cap too.
    #[test]
    fn matrix_names_longer_than_a_directory_name_are_not_built() {
        let long = "x".repeat(300);
        let (names, cut) = generated(
            &format!(
                "[tool.hatch.envs.test]\n\
                 matrix = [{{ python = [\"3.12\", \"{long}\"], dep = [\"a\", \"{long}\"] }}]\n"
            ),
            None,
        );
        assert_eq!(names, [["test.py3.12-a"]]);
        assert_eq!(cut, None);

        // 2,000 `{value}` of a 2,000-byte value would be a 4 MB name per
        // value, and `{variable}` filled in the same way.
        let value = "y".repeat(2_000);
        let repeated = format!(
            "[tool.hatch.envs.test]\n\
             matrix-name-format = \"{}\"\n\
             matrix = [{{ {} = [\"{value}\", \"ok\"] }}]\n",
            "{variable}{value}".repeat(2_000),
            "v".repeat(2_000),
        );
        let (names, cut) = generated(&repeated, None);
        assert_eq!(names, [Vec::<String>::new()]);
        assert_eq!(cut, None);

        // 300 one-value variables: a 599-byte name, once.
        let variables: Vec<String> = (0..300).map(|i| format!("k{i} = [\"a\"]")).collect();
        let (names, cut) = generated(
            &format!(
                "[tool.hatch.envs.test]\nmatrix = [{{ {} }}]\n",
                variables.join(", ")
            ),
            None,
        );
        assert_eq!(names, [Vec::<String>::new()]);
        assert_eq!(cut, None);

        // Too long in every combination: the walk still ends at the cap.
        let (names, cut) = generated(
            &format!(
                "[tool.hatch.envs.{long}]\nmatrix = [{{ a = {}, b = {} }}]\n",
                values(100),
                values(100)
            ),
            None,
        );
        assert_eq!(names, [Vec::<String>::new()]);
        assert_eq!(cut, Some("pyproject.toml"));
    }

    /// Hatch decides "inside the project" on the resolved directory
    /// (`root in data_directory.resolve().parents`), so `../envs` is an
    /// outside directory with the nested `<name>/<id>/<env>` layout.
    #[tokio::test]
    async fn parent_relative_env_dir_is_not_in_project() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("pyproject.toml"), PYPROJECT).unwrap();
        let config = tmp.path().join("hatch-config.toml");
        std::fs::write(&config, "[dirs.env]\nvirtual = \"../envs\"\n").unwrap();
        let root = std::fs::canonicalize(&project).unwrap();
        let id = project_ids(&root).pop().unwrap();
        let envs = tmp.path().join("envs");
        let ours = envs.join("my-app-core").join(&id).join("my-app-core");
        make_venv(&ours);
        // Some other project's flat venv in the same directory.
        make_venv(&envs.join("other"));
        let var = env_of(&[
            ("HATCH_CONFIG", config.display().to_string()),
            ("HOME", tmp.path().join("home").display().to_string()),
        ]);
        let found = hatch_environments_with(&project, &var).await;
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].name, "default");
        assert_eq!(
            std::fs::canonicalize(&found[0].prefix).unwrap(),
            std::fs::canonicalize(&ours).unwrap()
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
