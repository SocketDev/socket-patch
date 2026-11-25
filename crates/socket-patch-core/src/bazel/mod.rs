//! What socket-patch knows about Bazel workspaces.

/// The files that mark the root of a Bazel workspace: the names Bazel's own
/// client looks for from the working directory up (7.7.2, 8.8.2 and 9.3.2,
/// `WorkspaceLayout::InWorkspace`). Only a regular file counts (a link to
/// a file is followed), and only under the name its directory lists it by:
/// on a disk that folds case, a directory `workspace` or a file
/// `Module.bazel` answers for `WORKSPACE` or `MODULE.bazel`, and is none.
///
/// For a file, that is stricter than Bazel, whose client only tests that
/// the name exists and so takes a file `Module.bazel` on such a disk. A
/// workspace whose file is spelled in another case gets nothing of what
/// socket-patch does for Bazel until the file has Bazel's spelling. Such
/// a workspace builds on no disk that tells the cases apart, so a stray
/// file is the likelier reason for the name.
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
/// ask. The judgements of vendored mode that read the block of
/// `MODULE.bazel` without the lookup ask here themselves
/// ([`crate::vendor::maven_repo::hub_alone`]). What an earlier run wrote
/// for Bazel is still listed and undone.
pub fn off() -> bool {
    crate::utils::socket_cli_config::env_truthy(OFF_ENV)
}

pub mod built;
pub mod cargo;
pub(crate) mod cargo_bazel;
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
#[derive(Debug, PartialEq)]
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
    (!off()).then(|| roots_of(project).0).flatten()
}

/// The roots of the project at `project` whatever the switch says, for the
/// one caller that takes away what an earlier run wrote for Bazel
/// ([`ignore::sync`]): the root [`bazel_root`] finds without the switch,
/// and the root that a release found which took a workspace file by a stat
/// alone, where that is another directory. Such a release wrote there, so
/// what it wrote is undone there.
pub(crate) fn roots_of(project: &Path) -> (Option<BazelRoot>, Option<BazelRoot>) {
    let dirs = search_dirs(project);
    roots_in(&dirs, repo_at_end_of(dirs.clone()))
}

/// [`roots_of`] for the walk `dirs`, which ended at the checkout `repo`.
/// The second root is the first directory, before the first, whose
/// workspace file the disk answers for under another spelling only.
fn roots_in(dirs: &[PathBuf], repo: Option<GitRepo>) -> (Option<BazelRoot>, Option<BazelRoot>) {
    let within = repo.filter(|repo| repo.trusted).map_or(1, |_| dirs.len());
    let root = |at: usize| {
        let project = dirs[0].strip_prefix(&dirs[at]).ok()?.to_path_buf();
        let dir = dirs[at].clone();
        Some(BazelRoot { dir, project })
    };
    let mut folded = None;
    for (at, dir) in dirs.iter().take(within).enumerate() {
        match marked(dir) {
            Some(true) => return (root(at), folded.and_then(root)),
            Some(false) => folded = folded.or(Some(at)),
            None => {}
        }
    }
    (None, folded.and_then(root))
}

/// Whether `dir` holds a workspace file. `None` when no stat finds a
/// regular file under one of [`WORKSPACE_FILES`]: four stats, which is all
/// a directory with none costs. Else whether one of the names found is the
/// name of a file there ([`listed`]), and not only a spelling the disk
/// answers to.
fn marked(dir: &Path) -> Option<bool> {
    let file = |name: &&str| std::fs::metadata(dir.join(name)).is_ok_and(|meta| meta.is_file());
    let found: Vec<&str> = WORKSPACE_FILES.iter().copied().filter(file).collect();
    (!found.is_empty()).then(|| listed(dir, &found))
}

/// Whether `dir` lists an entry under exactly one of `names`, each of which
/// a stat found there. Where the disk has nothing under a name in lower
/// case, which no name of a workspace file is, the stat was of that very
/// name and nothing is listed: so it is on every disk that tells the cases
/// apart. Else the directory is listed, once for all the names. One that
/// cannot be listed keeps the stat's word.
pub(crate) fn listed(dir: &Path, names: &[&str]) -> bool {
    let folds = |name: &&str| std::fs::symlink_metadata(dir.join(name.to_lowercase())).is_ok();
    if !names.iter().any(folds) {
        return true;
    }
    let named = |entry: std::fs::DirEntry| names.iter().any(|name| entry.file_name() == *name);
    std::fs::read_dir(dir).map_or(true, |entries| entries.flatten().any(named))
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

    /// A regular file whose name is one of the four in another case: on a
    /// disk that folds case a stat of `WORKSPACE` finds the file
    /// `workspace`, and the directory lists it as it is. On a disk that
    /// does not fold case the stat finds nothing. The test asks the disk
    /// which of the two it runs on and says so.
    #[test]
    fn a_file_named_in_another_case_is_no_root() {
        let spelled = ["workspace", "Workspace.bazel", "Module.bazel", "repo.BAZEL"];
        let (_tmp, base) = tree(&[".git", "proj"], &spelled);
        let folds = fs::metadata(base.join("WORKSPACE")).is_ok();
        println!("a file named `workspace`: the disk folds case: {folds}");
        assert_eq!(bazel_root(&base.join("proj")), None);
        assert_eq!(bazel_root(&base), None);
        // Beside the file under its own name the directory is a root.
        if !folds {
            fs::write(base.join("WORKSPACE"), "").unwrap();
            assert_eq!(root(&base.join("proj")), Some(base));
        }
    }

    /// What the undo of a `.bazelignore` pair is given ([`roots_of`]): the
    /// root of today, and the root a release found that took a workspace
    /// file by a stat alone, where that is another directory. On a disk
    /// that folds case a file `workspace` marked such a root, and what
    /// that release wrote is there; on a disk that tells the cases apart
    /// no stat finds the file, and there is no such root.
    #[test]
    fn the_root_a_stat_alone_found_is_given_beside_the_root_of_today() {
        let (_tmp, base) = tree(&["repo/.git", "repo/svc/app"], &["repo/svc/workspace"]);
        let (repo, svc) = (base.join("repo"), base.join("repo/svc"));
        let app = svc.join("app");
        let folds = fs::metadata(svc.join("WORKSPACE")).is_ok();
        println!("a file named `workspace`: the disk folds case: {folds}");
        let found = |project: &Path| {
            let (root, before) = roots_of(project);
            let before = before.map(|root| (root.dir, root.project));
            (root.map(|root| root.dir), before)
        };
        let before = folds.then(|| (svc.clone(), PathBuf::from("app")));
        assert_eq!(found(&app), (None, before.clone()));
        assert_eq!(bazel_root(&app), None);
        // Below a root of today it is still where that release wrote.
        fs::write(repo.join("MODULE.bazel"), "").unwrap();
        assert_eq!(found(&app), (Some(repo.clone()), before));
        assert_eq!(root(&app), Some(repo));
        // A directory that holds a file under its own name is the one
        // root, on either disk, whatever else it holds.
        fs::write(svc.join("REPO.bazel"), "").unwrap();
        assert_eq!(found(&app), (Some(svc.clone()), None));
        assert_eq!(found(&svc), (Some(svc), None));
    }

    /// A name is listed as the directory spells it, and a directory is
    /// only asked where the disk answers to the name in the other case.
    #[test]
    fn a_name_counts_as_the_directory_lists_it() {
        let (_tmp, base) = tree(&[], &["MODULE.bazel", "workspace"]);
        assert!(listed(&base, &["MODULE.bazel"]));
        assert!(listed(&base, &["WORKSPACE", "MODULE.bazel"]));
        assert!(!listed(&base, &["WORKSPACE"]));
        assert!(!listed(&base, &["WORKSPACE", "REPO.bazel"]));
        // Nothing under the name in either case: the stat's word stands.
        assert!(listed(&base, &["WORKSPACE.bazel"]));
    }

    /// A directory that may be searched and not listed, as a directory of
    /// another user above the project can be: the stat finds the file, the
    /// names cannot be read, and the file counts as it did.
    #[cfg(unix)]
    #[test]
    fn a_directory_that_cannot_be_listed_keeps_its_workspace_file() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, base) = tree(&["repo/.git", "repo/app"], &["repo/MODULE.bazel"]);
        let repo = base.join("repo");
        fs::set_permissions(&repo, fs::Permissions::from_mode(0o311)).unwrap();
        let listed = fs::read_dir(&repo).is_ok();
        let found = root(&repo.join("app"));
        fs::set_permissions(&repo, fs::Permissions::from_mode(0o755)).unwrap();
        // The superuser lists every directory: the stat alone is not shown.
        println!("a directory without read permission: it can be listed: {listed}");
        assert_eq!(found, Some(repo));
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
            let found = roots_in(&dirs, repo).0;
            found.map(|found| (found.dir, found.project))
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
