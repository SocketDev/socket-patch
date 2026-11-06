//! The walk from a directory up to its enclosing git checkout.
//!
//! [`search_dirs`] / [`find_git_repo`] follow the rules git itself uses:
//!
//! - the nearest ancestor (inclusive) holding `.git` wins — a directory,
//!   or a FILE as in linked worktrees and submodules (`gitdir: …`), or a
//!   symlink to either;
//! - the walk never enters the home directory unless it starts there, so a
//!   dotfiles repository at `~` never claims every project below it;
//! - the walk never moves into a `GIT_CEILING_DIRECTORIES` entry.

use std::path::{Path, PathBuf};

/// The checkout [`find_git_repo`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRepo {
    /// The working-tree root: the directory holding `.git`.
    pub root: PathBuf,
    /// Whether `.git` belongs to a trusted owner ([`owner_trusted`]). An
    /// untrusted checkout is still the boundary of the walk, but nothing
    /// in it should be read as the repository's own configuration (git
    /// refuses it the same way, `safe.directory`).
    pub trusted: bool,
}

impl GitRepo {
    /// The checkout's git `config` file: `.git/config` for a plain
    /// checkout; for a `.git` FILE (`gitdir: <dir>`, relative to the
    /// root), the config of that git dir — or, for a linked worktree whose
    /// git dir names a `commondir`, the shared repository's config, which
    /// is where `git worktree add` keeps the remotes. `None` when it
    /// cannot be resolved to a regular file.
    pub fn config_path(&self) -> Option<PathBuf> {
        let dot_git = self.root.join(".git");
        let git_dir = if dot_git.is_dir() {
            dot_git
        } else {
            let text = crate::utils::fs::read_regular_to_string_sync(&dot_git).ok()?;
            let pointer = text
                .lines()
                .find_map(|line| line.trim().strip_prefix("gitdir:"))?
                .trim();
            if pointer.is_empty() {
                return None;
            }
            self.root.join(pointer)
        };
        let common = match crate::utils::fs::read_regular_to_string_sync(&git_dir.join("commondir"))
        {
            Ok(text) if !text.trim().is_empty() => git_dir.join(text.trim()),
            _ => git_dir,
        };
        let config = common.join("config");
        std::fs::metadata(&config)
            .is_ok_and(|m| m.is_file())
            .then_some(config)
    }
}

/// `start` (canonicalized when it exists) and its ancestors, nearest
/// first, as far as a repository lookup from `start` may look: through the
/// first directory holding `.git` (inclusive), never into the home
/// directory unless `start` is it, and never into a
/// `GIT_CEILING_DIRECTORIES` entry.
pub fn search_dirs(start: &Path) -> Vec<PathBuf> {
    search_dirs_with(start, home().as_deref(), &ceiling_dirs(), true)
}

/// The ancestors of `start` (canonicalized when it exists) that
/// [`search_dirs`] would visit if a checkout AT `start` did not end the
/// walk: for a project that may itself be a checkout (a submodule) and
/// still belong to a build above it. Nearest first; `start` itself is not
/// included.
pub fn ancestor_search_dirs(start: &Path) -> Vec<PathBuf> {
    let mut dirs = search_dirs_with(start, home().as_deref(), &ceiling_dirs(), false);
    if !dirs.is_empty() {
        dirs.remove(0);
    }
    dirs
}

/// The home directory as git's own home rule reads it (`HOME` on Unix,
/// `USERPROFILE` on Windows: an MSYS/Cygwin `HOME` does not move the
/// stop), when set and rooted, canonicalized so it compares with canonical
/// walks.
pub(crate) fn home() -> Option<PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| crate::utils::fs::is_usable_home(p))
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
}

/// [`search_dirs`] with the home directory and the ceilings injected;
/// `start_git_ends` false walks on past a checkout at `start` itself.
fn search_dirs_with(
    start: &Path,
    home: Option<&Path>,
    ceilings: &[PathBuf],
    start_git_ends: bool,
) -> Vec<PathBuf> {
    let start = std::fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    let mut dirs = Vec::new();
    let mut dir: &Path = &start;
    loop {
        if dir != start && home == Some(dir) {
            break;
        }
        dirs.push(dir.to_path_buf());
        if (start_git_ends || dir != start) && dot_git_metadata(dir).is_some() {
            break;
        }
        let Some(parent) = dir.parent() else { break };
        if ceilings.iter().any(|c| c == parent) {
            break;
        }
        dir = parent;
    }
    dirs
}

/// The git checkout enclosing `start` (see the module rules), or `None`.
pub fn find_git_repo(start: &Path) -> Option<GitRepo> {
    repo_at_end_of(search_dirs(start))
}

/// Which project files a run may read, chosen ONCE from the CLI mode and
/// passed to every bounded read (never inferred from the filesystem).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadScope {
    /// A project run (the default `--cwd` project): project files are read
    /// only inside the repository root ([`ReadBoundary::Workspace`]).
    Workspace,
    /// A global run (`--global` / `--global-prefix`): global installs,
    /// caches and their settings are read wherever they live on the system
    /// ([`ReadBoundary::Unbounded`]).
    Global,
}

impl ReadScope {
    /// The scope of a run whose global flag (`--global` or
    /// `--global-prefix`) is `global`.
    pub fn of_global(global: bool) -> Self {
        if global {
            ReadScope::Global
        } else {
            ReadScope::Workspace
        }
    }
}

/// The directory no read of a PROJECT file may leave in a
/// [`ReadScope::Workspace`] run: the git checkout enclosing the project
/// ([`find_git_repo`]), else the project itself. A
/// [`ReadScope::Global`] run reads anywhere ([`ReadBoundary::Unbounded`]).
///
/// Every reader and writer that follows a project file's reference
/// (an ancestor `go.work`, a `-r ../x.txt` include, a parent
/// `nuget.config`, a `file:../x` dependency) asks [`ReadBoundary::contains`]
/// before opening it: a refused read behaves like a missing file for a
/// reader, and a writer refuses with a diagnostic instead of guessing.
/// Machine-level tool configuration (`~/.npmrc`, the user NuGet.Config,
/// the `GOENV` file, `$CARGO_HOME`) is not a project file and is not
/// bounded by this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadBoundary {
    /// Reads stay at or below `root` (canonical when it exists).
    Workspace { root: PathBuf },
    /// A global run: every path is readable.
    Unbounded,
}

impl ReadBoundary {
    /// The boundary of a `scope` run for the project at `project_root`.
    pub fn of(scope: ReadScope, project_root: &Path) -> Self {
        match scope {
            ReadScope::Global => ReadBoundary::Unbounded,
            ReadScope::Workspace => {
                let project = canonical_or_lexical(project_root);
                let root = find_git_repo(&project).map_or(project, |repo| repo.root);
                ReadBoundary::Workspace { root }
            }
        }
    }

    /// The boundary of an UPWARD lookup from `start` (see [`upward_bound`])
    /// as a [`ReadBoundary`]: the enclosing checkout in a workspace run,
    /// [`ReadBoundary::Unbounded`] in a global run or outside any checkout,
    /// where the lookup reads as it always has.
    pub fn upward(scope: ReadScope, start: &Path) -> Self {
        upward_bound(scope, start).unwrap_or(ReadBoundary::Unbounded)
    }

    /// The boundary directory; `None` when unbounded.
    pub fn root(&self) -> Option<&Path> {
        match self {
            ReadBoundary::Workspace { root } => Some(root),
            ReadBoundary::Unbounded => None,
        }
    }

    /// Whether `path` lies at or below the boundary (always, unbounded).
    /// `path` is made absolute against the working directory, `..`
    /// folded, and its deepest existing level canonicalized, so neither a
    /// `..` nor a symlinked level inside the tree reaches outside it.
    pub fn contains(&self, path: &Path) -> bool {
        match self {
            ReadBoundary::Workspace { root } => canonical_or_lexical(path).starts_with(root),
            ReadBoundary::Unbounded => true,
        }
    }

    /// The user-facing reason a read of `path` was refused.
    pub fn refusal(&self, path: &Path) -> String {
        format!(
            "{} is outside the repository root {}; socket-patch does not read project \
             files outside it",
            path.display(),
            self.shown_root()
        )
    }

    /// The nearest file named one of `names` in a directory ABOVE the
    /// boundary, nearest directory first and `names` in order (`None`
    /// unbounded: nothing is above). Stat only: the file is never opened.
    /// Like git's own lookup it never reaches the home directory or
    /// anything above it, so a stray `~/package.json` governs nothing.
    pub fn marker_above(&self, names: &[&str]) -> Option<PathBuf> {
        let ReadBoundary::Workspace { root } = self else {
            return None;
        };
        let home = home();
        root.ancestors()
            .skip(1)
            .take_while(|dir| !at_or_above_home(dir, home.as_deref()))
            .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
            .find(|path| std::fs::metadata(path).is_ok())
    }

    /// The reason an upward lookup stopped at the boundary although the
    /// tool it models would read `marker` above it.
    pub fn marker_refusal(&self, marker: &Path) -> String {
        format!(
            "{} exists above the repository root {}, and socket-patch does not read \
             project files outside the repository, so it cannot tell whether that file \
             governs this project",
            marker.display(),
            self.shown_root()
        )
    }

    fn shown_root(&self) -> std::path::Display<'_> {
        self.root().unwrap_or(Path::new("/")).display()
    }
}

/// Whether `dir` is the home directory or one of its ancestors: never
/// read as a marker above a checkout (git's own home rule).
pub(crate) fn at_or_above_home(dir: &Path, home: Option<&Path>) -> bool {
    home.is_some_and(|home| home.starts_with(dir))
}

/// The bound of an UPWARD lookup from `start` (a workspace root, an
/// inherited config, a settings file the package manager searches its
/// ancestors for) in a `scope` run: in a [`ReadScope::Workspace`] run
/// inside a git checkout the lookup never reads above the checkout's
/// root, and a caller asks [`ReadBoundary::marker_above`] whether the tool
/// would have found something there (a writer then refuses, a reader
/// withholds). `None` in a [`ReadScope::Global`] run, and outside any
/// checkout, where the lookup walks on as it always has: stopping it at
/// the project would silently treat a workspace member as standalone.
pub fn upward_bound(scope: ReadScope, start: &Path) -> Option<ReadBoundary> {
    match scope {
        ReadScope::Global => None,
        ReadScope::Workspace => find_git_repo(&canonical_or_lexical(start))
            .map(|repo| ReadBoundary::Workspace { root: repo.root }),
    }
}

/// Whether an upward lookup from `start` may read `path` in a `scope` run
/// ([`upward_bound`]): always in a global run or outside a checkout, else
/// only inside it.
pub fn upward_readable(scope: ReadScope, start: &Path, path: &Path) -> bool {
    upward_bound(scope, start).is_none_or(|bound| bound.contains(path))
}

/// `project_root.join(rel)` for a project file named by a root-relative
/// `rel` (which may climb, `../shared/requirements.txt`, be absolute, or
/// pass through a symlinked level); `Err` of kind `NotFound` (a refused
/// read reads as a missing file) carrying [`ReadBoundary::refusal`] when,
/// in a [`ReadScope::Workspace`] run, its REAL path lies outside the
/// boundary ([`ReadBoundary::of`]). Every name is checked: an in-tree
/// spelling through a link out of the repository is refused like a `..`.
/// A path that resolves inside the project itself (the common case) needs
/// no repository lookup.
pub fn bounded_project_path(
    scope: ReadScope,
    project_root: &Path,
    rel: &str,
) -> std::io::Result<PathBuf> {
    let path = project_root.join(rel);
    if scope == ReadScope::Global {
        return Ok(path);
    }
    let real = canonical_or_lexical(&path);
    if real.starts_with(canonical_or_lexical(project_root)) {
        return Ok(path);
    }
    let bound = ReadBoundary::of(scope, project_root);
    if !bound.contains(&real) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            OutsideRepoRoot(bound.refusal(&path)),
        ));
    }
    Ok(path)
}

/// The payload of a read [`bounded_project_path`] refused.
#[derive(Debug)]
struct OutsideRepoRoot(String);

impl std::fmt::Display for OutsideRepoRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OutsideRepoRoot {}

/// Whether `e` is a read [`bounded_project_path`] refused. It reads as
/// `NotFound` (missing) to a reader; a writer, which must not proceed as
/// if the file were absent, refuses on it instead.
pub fn is_refused_read(e: &std::io::Error) -> bool {
    e.get_ref()
        .is_some_and(|inner| inner.is::<OutsideRepoRoot>())
}

/// `path` made absolute and resolved the way the OS resolves it, one
/// component at a time: every existing level is canonicalized (a symlink
/// is followed) before the next component applies, so a `..` climbs from
/// the real directory a link points at, never from the link's spelling.
/// Components past the deepest existing level fold lexically (nothing on
/// disk can redirect them).
fn canonical_or_lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    // The OS resolves an existing path physically in one call.
    if let Ok(real) = std::fs::canonicalize(&abs) {
        return real;
    }
    let mut out = PathBuf::new();
    for component in abs.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            // `out` is canonical while it exists: its parent is the
            // physical one.
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => {
                out.push(name);
                if let Ok(real) = std::fs::canonicalize(&out) {
                    out = real;
                }
            }
        }
    }
    out
}

/// The checkout AT the home directory that a lookup from `start` stopped
/// short of (the home rule), if there is one: for callers that should say
/// why a repository the user may expect was not used.
pub fn home_repo_not_entered(start: &Path) -> Option<PathBuf> {
    home_repo_beyond(&search_dirs(start), home().as_deref())
}

/// The home directory when it holds `.git` and is the directory just above
/// a `dirs` walk that ended without a checkout.
fn home_repo_beyond(dirs: &[PathBuf], home: Option<&Path>) -> Option<PathBuf> {
    let last = dirs.last()?;
    if dot_git_metadata(last).is_some() {
        return None;
    }
    let parent = last.parent()?;
    (home == Some(parent) && dot_git_metadata(parent).is_some()).then(|| parent.to_path_buf())
}

/// The checkout at the last directory of a [`search_dirs`] walk, if the
/// walk ended on one.
fn repo_at_end_of(mut dirs: Vec<PathBuf>) -> Option<GitRepo> {
    let root = dirs.pop()?;
    let meta = dot_git_metadata(&root)?;
    Some(GitRepo {
        root,
        trusted: trusted_owner(&meta),
    })
}

/// `<dir>/.git`'s metadata when it is a directory or a regular file;
/// `metadata` follows a `.git` symlink, as git does.
fn dot_git_metadata(dir: &Path) -> Option<std::fs::Metadata> {
    std::fs::metadata(dir.join(".git"))
        .ok()
        .filter(|meta| meta.is_dir() || meta.is_file())
}

fn ceiling_dirs() -> Vec<PathBuf> {
    std::env::var_os("GIT_CEILING_DIRECTORIES")
        .map(|v| {
            std::env::split_paths(&v)
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(unix)]
fn trusted_owner(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let sudo_uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok());
    // SAFETY: geteuid has no preconditions and cannot fail.
    owner_trusted(meta.uid(), unsafe { libc::geteuid() }, sudo_uid)
}

/// `.git` is trusted when it belongs to the invoking user, to root, or
/// (under sudo) to the user sudo ran for. Root trusts every owner: a root
/// process is exposed to the whole filesystem anyway, and CI containers
/// commonly run as root over a checkout owned by another uid, where
/// distrust would silently drop the repository's own settings.
#[cfg(unix)]
fn owner_trusted(owner: u32, euid: u32, sudo_uid: Option<u32>) -> bool {
    euid == 0 || owner == euid || owner == 0 || sudo_uid == Some(owner)
}

#[cfg(not(unix))]
fn trusted_owner(_meta: &std::fs::Metadata) -> bool {
    true
}

#[cfg(test)]
#[path = "repo_root_upward_tests.rs"]
mod upward_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn find(start: &Path, home: Option<&Path>, ceilings: &[PathBuf]) -> Option<PathBuf> {
        repo_at_end_of(search_dirs_with(start, home, ceilings, true)).map(|r| r.root)
    }

    #[test]
    fn nearest_git_dir_or_file_wins() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let outer = base.join("outer");
        fs::create_dir_all(outer.join(".git")).unwrap();
        let sub = outer.join("sub");
        fs::create_dir_all(sub.join("deep")).unwrap();
        fs::write(sub.join(".git"), "gitdir: ../.git/modules/sub\n").unwrap();
        assert_eq!(find(&sub.join("deep"), None, &[]), Some(sub.clone()));
        assert_eq!(
            search_dirs_with(&sub.join("deep"), None, &[], true),
            vec![sub.join("deep"), sub.clone()]
        );
        assert_eq!(find(&outer, None, &[]), Some(outer.clone()));
        // No checkout at all: the walk reaches the filesystem root.
        let plain = base.join("plain");
        fs::create_dir_all(&plain).unwrap();
        let dirs = search_dirs_with(&plain, Some(&base), &[], true);
        assert_eq!(dirs, vec![plain.clone()]);
        assert_eq!(find(&plain, Some(&base), &[]), None);
    }

    /// A dotfiles repository at `$HOME` must not become the repository of
    /// every project below it.
    #[test]
    fn walk_never_enters_home_unless_it_starts_there() {
        let tmp = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(tmp.path()).unwrap();
        fs::create_dir_all(home.join(".git")).unwrap();
        let project = home.join("code/app");
        fs::create_dir_all(&project).unwrap();
        assert_eq!(find(&project, Some(&home), &[]), None);
        assert_eq!(
            search_dirs_with(&project, Some(&home), &[], true),
            vec![project.clone(), home.join("code")]
        );
        assert_eq!(find(&home, Some(&home), &[]), Some(home.clone()));
        // The skipped home checkout is reported, so callers can say why.
        let walk = search_dirs_with(&project, Some(&home), &[], true);
        assert_eq!(home_repo_beyond(&walk, Some(&home)), Some(home.clone()));
        assert_eq!(home_repo_beyond(&walk, None), None);
        fs::create_dir_all(project.join(".git")).unwrap();
        let walk = search_dirs_with(&project, Some(&home), &[], true);
        assert_eq!(home_repo_beyond(&walk, Some(&home)), None);
    }

    #[test]
    fn ancestor_walk_passes_a_checkout_at_the_start() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        fs::create_dir_all(base.join("outer/.git")).unwrap();
        let sub = base.join("outer/sub");
        fs::create_dir_all(sub.join(".git")).unwrap();
        let mut dirs = search_dirs_with(&sub, None, &[], false);
        dirs.remove(0);
        assert_eq!(dirs, vec![base.join("outer")]);
        // Home still bounds it: a project directly under home never
        // reads home itself.
        let mut dirs = search_dirs_with(&sub, Some(&base.join("outer")), &[], false);
        dirs.remove(0);
        assert!(dirs.is_empty(), "{dirs:?}");
    }

    #[test]
    fn read_boundary_is_the_checkout_else_the_project() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let repo = base.join("repo");
        let project = repo.join("packages/app");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(&project).unwrap();
        let bound = ReadBoundary::of(ReadScope::Workspace, &project);
        assert_eq!(bound.root(), Some(repo.as_path()));
        assert!(bound.contains(&project.join("../../go.work")));
        assert!(bound.contains(&repo.join("not/yet/created.txt")));
        assert!(!bound.contains(&project.join("../../../go.work")));
        assert!(!bound.contains(&base.join("sibling/.socket/vendor")));
        // No checkout: the project itself is the boundary.
        let plain = base.join("plain/app");
        fs::create_dir_all(&plain).unwrap();
        let bound = ReadBoundary::of(ReadScope::Workspace, &plain);
        assert_eq!(bound.root(), Some(plain.as_path()));
        assert!(!bound.contains(&plain.join("../go.work")));
        // A project file named by a climbing path: refused as missing.
        let err = bounded_project_path(ReadScope::Workspace, &plain, "../go.work").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(is_refused_read(&err));
        assert_eq!(
            bounded_project_path(ReadScope::Workspace, &plain, "sub/go.work").unwrap(),
            plain.join("sub/go.work")
        );
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(!is_refused_read(&missing));
        // A global run is unbounded: it reads anywhere on the system.
        let global = ReadBoundary::of(ReadScope::Global, &project);
        assert_eq!(global, ReadBoundary::Unbounded);
        assert!(global.contains(&base.join("sibling/.socket/vendor")));
        assert_eq!(global.marker_above(&["go.work"]), None);
        assert_eq!(
            bounded_project_path(ReadScope::Global, &plain, "../go.work").unwrap(),
            plain.join("../go.work")
        );
        assert_eq!(upward_bound(ReadScope::Global, &project), None);
        assert!(upward_readable(
            ReadScope::Global,
            &project,
            &base.join("x")
        ));
    }

    /// A symlink inside the tree that points out of it does not carry a
    /// read across the boundary.
    #[cfg(unix)]
    #[test]
    fn read_boundary_sees_through_links() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let repo = base.join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        std::os::unix::fs::symlink(base.join("outside"), repo.join("link")).unwrap();
        let bound = ReadBoundary::of(ReadScope::Workspace, &repo);
        assert!(!bound.contains(&repo.join("link/requirements.txt")));
        assert!(bound.contains(&repo.join("requirements.txt")));
    }

    /// Review finding 1: a `..` after a symlinked level climbs from the
    /// link's TARGET, as the OS resolves it, never from the link's
    /// spelling.
    #[cfg(unix)]
    #[test]
    fn dot_dot_after_a_link_resolves_physically() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let repo = base.join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(base.join("outside/dir")).unwrap();
        fs::write(base.join("outside/secret.txt"), "x").unwrap();
        fs::write(repo.join("secret.txt"), "in").unwrap();
        std::os::unix::fs::symlink(base.join("outside/dir"), repo.join("link")).unwrap();
        let bound = ReadBoundary::of(ReadScope::Workspace, &repo);
        assert!(!bound.contains(&repo.join("link/../secret.txt")));
        assert!(!bound.contains(&repo.join("link/../missing/x.txt")));
        assert!(bound.contains(&repo.join("sub/../secret.txt")));
        let err = bounded_project_path(ReadScope::Workspace, &repo, "link/../secret.txt");
        assert!(err.is_err_and(|e| is_refused_read(&e)));
    }

    /// Review finding 2: an in-tree name read through a symlinked level
    /// that points out of the repository is refused too, not only a
    /// climbing (`..`) or absolute one.
    #[cfg(unix)]
    #[test]
    fn in_tree_names_through_an_outward_link_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let repo = base.join("repo");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(base.join("other")).unwrap();
        fs::write(base.join("other/base.txt"), "six==1.16.0\n").unwrap();
        std::os::unix::fs::symlink(base.join("other"), repo.join("shared")).unwrap();
        let refused = bounded_project_path(ReadScope::Workspace, &repo, "shared/base.txt");
        assert!(refused.is_err_and(|e| is_refused_read(&e)));
        assert!(bounded_project_path(ReadScope::Workspace, &repo, "requirements.txt").is_ok());
        assert!(bounded_project_path(ReadScope::Global, &repo, "shared/base.txt").is_ok());
        // The project view (discovery, the lock inventory, the
        // requirements walks) reads through it: missing to a reader.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let view = crate::vendor::lock_inventory::ProjectView::Disk(&repo);
        let read = rt.block_on(view.read_text("shared/base.txt")).unwrap_err();
        assert!(is_refused_read(&read));
        let snap = crate::vendor::lock_inventory::DiskSnapshot::new(&repo);
        let snapshot = crate::vendor::lock_inventory::ProjectView::Snapshot(&snap);
        let read = rt
            .block_on(snapshot.read_text("shared/base.txt"))
            .unwrap_err();
        assert!(is_refused_read(&read));
    }

    #[test]
    fn walk_stops_at_ceiling_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        fs::create_dir_all(base.join(".git")).unwrap();
        let cwd = base.join("ceiling/cwd");
        fs::create_dir_all(&cwd).unwrap();
        assert_eq!(find(&cwd, None, &[base.join("ceiling")]), None);
        assert_eq!(find(&cwd, None, &[]), Some(base));
    }

    #[test]
    fn config_of_a_plain_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git/config"), "").unwrap();
        let repo = GitRepo {
            root: root.clone(),
            trusted: true,
        };
        assert_eq!(repo.config_path(), Some(root.join(".git/config")));
    }

    #[test]
    fn config_of_a_submodule_follows_its_gitdir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let modules = root.join(".git/modules/sub");
        fs::create_dir_all(&modules).unwrap();
        fs::write(modules.join("config"), "").unwrap();
        let sub = root.join("sub");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(".git"), "gitdir: ../.git/modules/sub\n").unwrap();
        let repo = GitRepo {
            root: sub,
            trusted: true,
        };
        assert_eq!(
            repo.config_path(),
            Some(root.join("sub/../.git/modules/sub/config"))
        );
    }

    #[test]
    fn config_of_a_linked_worktree_is_the_common_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        let main_git = base.join("main/.git");
        let wt_git = main_git.join("worktrees/wt");
        fs::create_dir_all(&wt_git).unwrap();
        fs::write(main_git.join("config"), "").unwrap();
        fs::write(wt_git.join("commondir"), "../..\n").unwrap();
        let wt = base.join("wt");
        fs::create_dir_all(&wt).unwrap();
        fs::write(wt.join(".git"), format!("gitdir: {}\n", wt_git.display())).unwrap();
        let repo = GitRepo {
            root: wt,
            trusted: true,
        };
        let config = repo.config_path().unwrap();
        assert_eq!(
            fs::canonicalize(config).unwrap(),
            fs::canonicalize(main_git.join("config")).unwrap()
        );
        // A dangling pointer resolves to nothing.
        fs::write(repo.root.join(".git"), "gitdir: /nonexistent/x\n").unwrap();
        assert_eq!(repo.config_path(), None);
    }

    #[cfg(unix)]
    #[test]
    fn owner_rule() {
        assert!(owner_trusted(1000, 1000, None));
        assert!(owner_trusted(0, 1000, None));
        assert!(!owner_trusted(1001, 1000, None));
        assert!(
            owner_trusted(1001, 1000, Some(1001)),
            "sudo's invoking user"
        );
        assert!(owner_trusted(1001, 0, None), "root trusts every owner");
    }
}
