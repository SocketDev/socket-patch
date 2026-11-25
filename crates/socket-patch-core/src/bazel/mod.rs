//! What socket-patch knows about Bazel workspaces.

/// The files that mark the root of a Bazel workspace: the names Bazel's own
/// client looks for from the working directory up (7.7.2, 8.8.2 and 9.3.2,
/// `WorkspaceLayout::InWorkspace`). Only a regular file of one of these
/// names counts (a link to a file is followed); a directory does not: on a
/// disk that folds case, a directory `workspace` answers for `WORKSPACE`.
/// A regular file `workspace` or `Module.bazel` counts on such a disk, as
/// it does for Bazel's client, which tests that the name exists: a
/// workspace is seen where Bazel sees one. [`OFF_ENV`] is the way out for
/// a checkout where such a file is none.
pub const WORKSPACE_FILES: [&str; 4] =
    ["MODULE.bazel", "REPO.bazel", "WORKSPACE", "WORKSPACE.bazel"];

/// The variable that switches off everything socket-patch does because a
/// project is in a Bazel workspace: for a project that sits in such a
/// checkout and that Bazel does not build. It is read from the environment
/// alone, in the words of every such switch
/// ([`env_truthy`](crate::utils::socket_cli_config::env_truthy): `1`,
/// `true`, `yes`, `on`, `y` or `t`, in any case), and a run that honours
/// it says nothing.
///
/// A child process inherits it
/// ([`CHILD_ENV_SCRUB`](crate::utils::process::CHILD_ENV_SCRUB) does not
/// list it): it is the user's word about the checkout, no credential and
/// no flag of this run, and a socket-patch that a spawned program starts
/// there has to give the same run.
pub const OFF_ENV: &str = "SOCKET_NO_BAZEL";

/// Whether the user switched the Bazel support off ([`OFF_ENV`]). Then
/// [`bazel_root`] finds no workspace on disk, the view of files handed
/// over in memory holds none ([`workspace::memory`]), and the in-memory
/// path selection asks for none ([`ruby::is_workspace_file`]): one gate
/// for each way a workspace is come by, so that what judges one need not
/// ask. The judgements of vendored mode that go by the block of
/// `MODULE.bazel` without the lookup ask here through one read of it
/// ([`crate::vendor::maven_repo`]). What an earlier run wrote for Bazel
/// is still listed and undone.
pub fn off() -> bool {
    crate::utils::socket_cli_config::truthy(&off_env().unwrap_or_default())
}

#[cfg(not(test))]
fn off_env() -> Option<String> {
    std::env::var(OFF_ENV).ok()
}

/// The unit tests see the variable only while a guard holds it
/// ([`crate::test_env`]): hundreds of them look a workspace up, and none
/// is to change with what the developer's shell exports. None of them
/// sets it either, since every other test would see it meanwhile: what
/// the switch does is held by tests that start a process of their own.
#[cfg(test)]
fn off_env() -> Option<String> {
    crate::test_env::guarded_var(OFF_ENV)
}

pub mod built;
pub mod cargo;
pub(crate) mod cargo_bazel;
pub mod distdir;
pub mod ignore;
pub mod maven;
pub mod nuget;
pub mod pnpm;
pub mod rc;
pub mod ruby;
pub mod starlark;
pub mod workspace;

use std::path::{Path, PathBuf};

use crate::utils::repo_root::{repo_at_end_of, search_dirs, GitRepo};

/// The Bazel workspace a project is in.
#[derive(Debug, Clone, PartialEq)]
pub struct BazelRoot {
    /// The root: the nearest directory, from the project up, that holds one
    /// of [`WORKSPACE_FILES`]. Canonical.
    pub dir: PathBuf,
    /// The project's directory from `dir`: empty for a project at the root.
    pub project: PathBuf,
}

/// The Bazel workspace the project at `project` is in, from one walk
/// ([`search_dirs`], whose bounds and canonical paths these are): the
/// project's own directory, or one up to the root of its git checkout. That
/// is the checkout [`crate::utils::repo_root::find_git_repo`] finds, when
/// its `.git` belongs to a trusted owner; in no such checkout only the
/// project's own directory is looked at. So nothing above the checkout, or
/// above a project outside one, is read, and no file is written there.
/// None for a user who switched the Bazel support off ([`off`]).
pub fn bazel_root(project: &Path) -> Option<BazelRoot> {
    (!off()).then(|| root_of(project)).flatten()
}

/// [`bazel_root`] whatever the switch says: for the one caller that takes
/// away what an earlier run wrote for Bazel ([`ignore::sync`]).
pub(crate) fn root_of(project: &Path) -> Option<BazelRoot> {
    let dirs = search_dirs(project);
    root_in(&dirs, repo_at_end_of(dirs.clone()))
}

/// [`root_of`] for the walk `dirs`, which ended at the checkout `repo`.
fn root_in(dirs: &[PathBuf], repo: Option<GitRepo>) -> Option<BazelRoot> {
    let within = repo.filter(|repo| repo.trusted).map_or(1, |_| dirs.len());
    let at = dirs.iter().take(within).position(|dir| {
        let marks = |name| std::fs::metadata(dir.join(name)).is_ok_and(|meta| meta.is_file());
        WORKSPACE_FILES.into_iter().any(marks)
    })?;
    Some(BazelRoot {
        dir: dirs[at].clone(),
        project: dirs[0].strip_prefix(&dirs[at]).ok()?.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A temp directory, canonical, holding the directories `dirs` and the
    /// empty files `files`.
    fn tree(dirs: &[&str], files: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        for dir in dirs {
            fs::create_dir_all(base.join(dir)).unwrap();
        }
        for file in files {
            fs::write(base.join(file), "").unwrap();
        }
        (tmp, base)
    }

    /// The root of `project`'s workspace.
    fn root(project: &Path) -> Option<PathBuf> {
        bazel_root(project).map(|found| found.dir)
    }

    #[test]
    fn the_root_is_the_nearest_directory_with_a_workspace_file() {
        let (_tmp, base) = tree(&["repo/.git", "repo/svc/app"], &["repo/MODULE.bazel"]);
        let (repo, app) = (base.join("repo"), base.join("repo/svc/app"));
        // The project at the root, and one below it.
        let at_root = bazel_root(&repo).unwrap();
        assert_eq!(
            (at_root.dir, at_root.project),
            (repo.clone(), PathBuf::new())
        );
        let below = bazel_root(&app).unwrap();
        assert_eq!(
            (below.dir, below.project),
            (repo.clone(), PathBuf::from("svc/app"))
        );
        // The nearest wins, under each name.
        for name in ["WORKSPACE", "WORKSPACE.bazel", "REPO.bazel", "MODULE.bazel"] {
            let file = base.join("repo/svc").join(name);
            fs::write(&file, "").unwrap();
            assert_eq!(root(&app), Some(base.join("repo/svc")), "{name}");
            fs::remove_file(&file).unwrap();
        }
        fs::remove_file(repo.join("MODULE.bazel")).unwrap();
        assert_eq!(bazel_root(&app), None);
    }

    #[test]
    fn a_workspace_file_above_the_checkout_is_not_seen() {
        let (_tmp, base) = tree(&["repo/.git", "repo/app"], &["MODULE.bazel", "WORKSPACE"]);
        assert_eq!(bazel_root(&base.join("repo/app")), None);
        assert_eq!(bazel_root(&base.join("repo")), None);
    }

    /// `<checkout>/workspace/proj`: where the disk folds case, the directory
    /// `workspace` is what a lookup of `WORKSPACE` in the checkout finds.
    #[test]
    fn a_directory_named_like_a_workspace_file_is_no_root() {
        let dirs = [".git", "workspace/proj", "sub/MODULE.bazel", "sub/proj"];
        let (_tmp, base) = tree(&dirs, &[]);
        assert_eq!(bazel_root(&base.join("workspace/proj")), None);
        assert_eq!(bazel_root(&base.join("sub/proj")), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_counts_when_it_leads_to_a_file() {
        use std::os::unix::fs::symlink;
        let (_tmp, base) = tree(&["repo/.git", "repo/app", "dir"], &["module"]);
        let (repo, name) = (base.join("repo"), base.join("repo/MODULE.bazel"));
        symlink(base.join("dir"), &name).unwrap();
        assert_eq!(bazel_root(&repo.join("app")), None, "a link to a directory");
        fs::remove_file(&name).unwrap();
        symlink(base.join("missing"), &name).unwrap();
        assert_eq!(bazel_root(&repo.join("app")), None, "a link to nothing");
        fs::remove_file(&name).unwrap();
        symlink(base.join("module"), &name).unwrap();
        assert_eq!(root(&repo.join("app")), Some(repo));
    }

    /// `tmp/.git` and `tmp/MODULE.bazel` of another user, and a project of
    /// one's own in `tmp/job/proj`: a checkout whose `.git` belongs to an
    /// owner that is not trusted is none, and a project in no checkout is
    /// looked for in its own directory only, whatever lies above it.
    #[test]
    fn only_a_trusted_checkout_reaches_above_the_project() {
        let (_tmp, base) = tree(&[".git", "job/proj"], &["MODULE.bazel"]);
        let proj = base.join("job/proj");
        let dirs = search_dirs(&proj);
        assert_eq!(dirs.last(), Some(&base));
        let found = |trusted: Option<bool>| {
            let repo = repo_at_end_of(dirs.clone()).expect("the checkout");
            let repo = trusted.map(|trusted| GitRepo { trusted, ..repo });
            root_in(&dirs, repo).map(|found| (found.dir, found.project))
        };
        assert_eq!(found(Some(true)), Some((base, PathBuf::from("job/proj"))));
        for none in [Some(false), None] {
            assert_eq!(found(none), None, "{none:?}");
            fs::write(proj.join("WORKSPACE.bazel"), "").unwrap();
            assert_eq!(found(none), Some((proj.clone(), PathBuf::new())));
            fs::remove_file(proj.join("WORKSPACE.bazel")).unwrap();
        }
    }
}
