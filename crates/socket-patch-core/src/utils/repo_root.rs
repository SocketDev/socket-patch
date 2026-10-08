//! The one walk from a directory up to its enclosing git checkout.
//!
//! Every feature that needs "the repository this directory belongs to"
//! (`socket.yml` lookup, VEX product detection, the JVM build-root check)
//! goes through [`search_dirs`] / [`find_git_repo`], so they agree on the
//! rules git itself uses:
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
    /// The `.git` entry at the root.
    pub fn dot_git(&self) -> PathBuf {
        self.root.join(".git")
    }

    /// The checkout's git `config` file: `.git/config` for a plain
    /// checkout; for a `.git` FILE (`gitdir: <dir>`, relative to the
    /// root), the config of that git dir — or, for a linked worktree whose
    /// git dir names a `commondir`, the shared repository's config, which
    /// is where `git worktree add` keeps the remotes. `None` when it
    /// cannot be resolved to a regular file.
    pub fn config_path(&self) -> Option<PathBuf> {
        let dot_git = self.dot_git();
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

    /// B22: a dotfiles repository at `$HOME` must not become the
    /// repository of every project below it.
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
        fs::write(repo.dot_git(), "gitdir: /nonexistent/x\n").unwrap();
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
