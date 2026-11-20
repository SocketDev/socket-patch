//! Composer vendored mode in a Bazel workspace: declined unless the user
//! allows it.
//!
//! Vendored mode points the lock entry at the committed copy by a path
//! from the directory Composer runs in
//! (`.socket/vendor/composer/<uuid>/<vendor>/<name>@<version>`). No Bazel
//! ruleset builds PHP, so a project under Bazel brings its packages into
//! the build with a few lines of its own: a repository rule or a genrule
//! that runs `composer install` from the committed lock, in a directory of
//! Bazel's that holds the two Composer files and nothing else. There the
//! path names nothing: Composer fails (`Source path "..." is not found for
//! package ...`) and the build with it, after a command that exited 0
//! (Bazel 9.3.2, 8.8.2 and 7.7.2).
//!
//! Whether a workspace has such a rule cannot be read from its files. A
//! rule may take the lock through a glob, or live in another module. A
//! committed `vendor/` tree shows that Composer has run in the project's
//! directory, not that no rule runs it elsewhere as well: a workspace with
//! both fails the same way (Bazel 9.3.2). So every Composer project in a
//! Bazel workspace is declined, and the user's word is the one exception.

use std::path::Path;

use crate::utils::env_compat::env_flag;
use crate::utils::fs::run_blocking;
use crate::vendor::refusals::ALLOW_IN_BAZEL_ENV;

/// The code of [`refusal`].
pub const CODE: &str = "vendor_composer_bazel_workspace";

/// Why vendored mode declines the Composer project at `project`, or `None`
/// when it goes on. It declines a project in a Bazel workspace
/// ([`crate::bazel::bazel_root`]) unless the user allowed it
/// ([`ALLOW_IN_BAZEL_ENV`]). Read-only: the lookup of the root is all it
/// does, and it starts no program.
pub async fn refusal(project: &Path) -> Option<(&'static str, String)> {
    refusal_unless(project, env_flag(ALLOW_IN_BAZEL_ENV)).await
}

/// [`refusal`] for a user who `allowed` it or did not.
async fn refusal_unless(project: &Path, allowed: bool) -> Option<(&'static str, String)> {
    if allowed {
        return None;
    }
    let dir = project.to_path_buf();
    let root = run_blocking(move || crate::bazel::bazel_root(&dir)).await?;
    Some((
        CODE,
        format!(
            "the project is in the Bazel workspace at {}, and vendored mode makes composer.lock \
             name the patched copy by a path relative to the directory Composer runs in: a \
             Bazel rule that runs `composer install` anywhere else does not find it, and the \
             build fails; use `--mode hosted`, which names the patched archive by a URL that \
             Composer fetches from any directory, or pass `--allow-vendored-in-bazel` if \
             Composer only runs in the project's directory",
            root.dir.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A temp directory, canonical, holding the directories `dirs` and the
    /// empty files `files`.
    fn tree(dirs: &[&str], files: &[&str]) -> (tempfile::TempDir, std::path::PathBuf) {
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

    /// The code of [`refusal_unless`] for a user who did not allow it.
    async fn code(project: &Path) -> Option<&'static str> {
        refusal_unless(project, false).await.map(|(code, _)| code)
    }

    #[tokio::test]
    async fn a_project_in_a_bazel_workspace_is_declined_and_no_other() {
        let (_tmp, base) = tree(&["repo/.git", "repo/services/api", "plain"], &[]);
        let (repo, api) = (base.join("repo"), base.join("repo/services/api"));
        assert_eq!(code(&api).await, None);
        // A workspace file in the project's directory, and one at the root
        // of its checkout, under each name Bazel looks for.
        for name in crate::bazel::WORKSPACE_FILES {
            for dir in [&api, &repo] {
                fs::write(dir.join(name), "").unwrap();
                let (code, detail) = refusal_unless(&api, false).await.expect(name);
                assert_eq!(code, CODE, "{name}");
                // The root, not the project below it: the comma ends it.
                let named = [
                    &*format!("the Bazel workspace at {},", dir.display()),
                    "`--mode hosted`",
                    "`--allow-vendored-in-bazel`",
                ];
                assert!(named.iter().all(|part| detail.contains(part)), "{detail}");
                // The user's word lifts it.
                assert_eq!(refusal_unless(&api, true).await, None, "{name}");
                fs::remove_file(dir.join(name)).unwrap();
            }
        }
        // A workspace beside the project is not the project's.
        fs::write(base.join("plain/MODULE.bazel"), "").unwrap();
        assert_eq!(code(&api).await, None);
    }
}
