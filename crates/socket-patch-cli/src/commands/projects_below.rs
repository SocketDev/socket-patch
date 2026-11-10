//! The project directories of a checkout at and below `--cwd`.
//!
//! A bare hosted or vendored `scan` covers every one of them
//! ([`discovered`]): the in-memory engine's root detection over a walk of
//! the checkout, less what the socket.yml path policy (its built-in test
//! and fixture ignores included) leaves out of a discovered set.

use std::path::{Path, PathBuf};

use socket_patch_core::policy::{
    find_repo_root_with_warnings, repo_relative_checked, DiskPolicyFs, PolicyError,
    PolicyOverrides, PolicyWarning, Root, SelectionPolicy,
};

use crate::args::GlobalArgs;
use crate::hosted_memory::roots::{marker_ecosystem, roots_below, UNSUPPORTED_MARKERS};

/// A repository's socket.yml policy and the root it was read from.
pub(crate) struct RepoPolicy {
    pub policy: SelectionPolicy,
    pub repo_root: PathBuf,
    pub warnings: Vec<PolicyWarning>,
    /// Whether `repo_root` is a git checkout (rather than `--cwd` standing
    /// in for one). Project directories are searched for only inside a
    /// checkout: its root bounds the walk.
    pub in_git_repo: bool,
}

impl RepoPolicy {
    /// Read the policy of the repository holding `cwd` (canonical): the
    /// root socket.yml of the trusted git checkout around it, else of `cwd`.
    pub(crate) fn load(cwd: &Path, overrides: &PolicyOverrides) -> Result<Self, PolicyError> {
        let (repo_root, mut warnings) = find_repo_root_with_warnings(cwd);
        let in_git_repo = socket_patch_core::utils::repo_root::find_git_repo(cwd)
            .is_some_and(|repo| repo.trusted && repo.root == repo_root);
        let (policy, load_warnings) =
            SelectionPolicy::load(&DiskPolicyFs::new(&repo_root), overrides)?;
        warnings.extend(load_warnings);
        Ok(Self {
            policy,
            repo_root,
            warnings,
            in_git_repo,
        })
    }
}

/// The marker files of a disk project root: the same lock markers the
/// in-memory engine detects roots by, plus the maven/nuget markers disk
/// scans support. When a directory has none of those, its manifests
/// ([`MANIFEST_MARKERS`] and the JVM build files) are its markers instead;
/// the in-memory engine has no such fallback (manifests alone never make
/// a root there), so for a lockless directory the two engines disagree.
pub(crate) fn dir_markers(dir: &Path) -> Vec<String> {
    let mut markers = lock_markers(dir);
    if markers.is_empty() {
        // No lockfile: the manifests say what the project is. Every name
        // here, JVM build files included, must be a regular file: the
        // root-marker report lists files, so it deliberately keeps
        // `is_file` rather than `layout::marker_present` (which lets a
        // directory named like a build file mark a JVM build).
        markers = MANIFEST_MARKERS
            .iter()
            .chain(socket_patch_core::vendor::jvm::layout::JVM_PROJECT_MARKERS)
            .filter(|name| dir.join(name).is_file())
            .map(|name| name.to_string())
            .collect();
    }
    markers.sort();
    markers
}

/// The lockfile markers in `dir` (unsorted): what makes a directory a
/// project root of its own rather than a member of an enclosing one.
pub(crate) fn lock_markers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_ok_and(|t| t.is_file() || t.is_symlink()))
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|name| {
                    marker_ecosystem(name).is_some()
                        || UNSUPPORTED_MARKERS
                            .iter()
                            .any(|(_, names)| names.contains(&name.as_str()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Manifests that stand in as markers for a root with no lockfile (plus
/// every JVM build file, `layout::JVM_PROJECT_MARKERS`).
const MANIFEST_MARKERS: [&str; 6] = [
    "package.json",
    "pyproject.toml",
    "setup.py",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
];

/// The project directories at and below `--cwd`, found by [`discovered`].
pub(crate) struct DiscoveredDirs {
    /// `--cwd` (when it is a project) and every project root below it,
    /// sorted; the flag says whether the user named the directory: only
    /// `--cwd` is explicit.
    pub dirs: Vec<(PathBuf, bool)>,
    /// Roots the socket.yml path policy (its built-in test and fixture
    /// ignores included) left out.
    pub ignored: usize,
    /// The walk gave up before it had seen the whole tree.
    pub truncated: bool,
}

/// The projects at and below `--cwd`: the roots the in-memory engine
/// detects for the same checkout (`roots_below`), less the ones the
/// socket.yml path `policy` (read from `repo_root`) leaves out of a
/// discovered set. `--cwd` itself is the user's choice, so it is explicit
/// and stays in whenever it is a project at all (a lockless one included).
pub(crate) async fn discovered(
    common: &GlobalArgs,
    policy: &SelectionPolicy,
    repo_root: &Path,
) -> DiscoveredDirs {
    let cwd = &common.cwd;
    // The socket.yml path policy's verdict on a root (`""` is `--cwd`,
    // which the user named).
    let admitted = |rel: &str| {
        let dir = if rel.is_empty() {
            cwd.clone()
        } else {
            cwd.join(rel)
        };
        let resolved = std::fs::canonicalize(&dir).unwrap_or_else(|_| dir.clone());
        let Some(project) = repo_relative_checked(repo_root, &resolved) else {
            return false;
        };
        policy
            .admits_root(&Root {
                rel_dir: &project,
                markers: &dir_markers(&dir),
                explicit: rel.is_empty(),
            })
            .is_ok()
    };
    let found = roots_below(cwd, common.ecosystems.as_deref(), admitted).await;
    let mut dirs = Vec::new();
    let mut ignored = 0;
    if found.governs_members || !dir_markers(cwd).is_empty() {
        dirs.push((cwd.clone(), true));
    }
    for rel in found.roots.iter().filter(|rel| !rel.is_empty()) {
        if admitted(rel) {
            dirs.push((cwd.join(rel), false));
        } else {
            ignored += 1;
        }
    }
    DiscoveredDirs {
        dirs,
        ignored,
        truncated: found.truncated,
    }
}

/// A discovered project directory as a run names it: relative to `--cwd`,
/// `/`-separated.
pub(crate) fn shown_project_dir(cwd: &Path, dir: &Path) -> String {
    dir.strip_prefix(cwd)
        .unwrap_or(dir)
        .to_string_lossy()
        .replace('\\', "/")
}

/// The heading a run prints above one project directory's output.
pub(crate) fn heading(shown: &str) -> String {
    format!("\n== {shown} ==")
}
