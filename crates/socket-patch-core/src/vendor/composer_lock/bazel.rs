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
//!
//! What is declined is the write of that path. A package whose lock entry
//! already names the copy of the same patch is let through: the run leaves
//! the lock as it is, so a project that was vendored before (by an earlier
//! release, or with the flag) keeps passing its in-sync runs.

use std::path::Path;

use crate::formats::composer::composer_lock_packages;
use crate::utils::env_compat::env_flag;
use crate::utils::fs::{read_regular_to_string, run_blocking};
use crate::utils::pnpm_workspace::without_verbatim_prefix;
use crate::utils::purl::parse_composer_purl;
use crate::vendor::common::parse_json_text;
use crate::vendor::refusals::ALLOW_IN_BAZEL_ENV;

use super::{COMPOSER_LOCK, LOCK_MEMO};

/// The code of [`refusals`].
pub const CODE: &str = "vendor_composer_bazel_workspace";

/// The Composer `candidates` (`(purl, uuid)` pairs) that vendored mode
/// declines in the project at `project`, each with [`CODE`] and the detail.
/// It declines a project in a Bazel workspace
/// ([`crate::bazel::bazel_root`]) unless the user allowed it
/// ([`ALLOW_IN_BAZEL_ENV`]), and lets through a package the lock already
/// names by the copy of that patch. Read-only: it looks for the root, reads
/// the lock, and starts no program.
pub async fn refusals<'a>(
    project: &Path,
    candidates: &[(&'a str, &str)],
) -> Vec<(&'a str, &'static str, String)> {
    refusals_unless(project, candidates, env_flag(ALLOW_IN_BAZEL_ENV)).await
}

/// [`refusals`] for a user who `allowed` it or did not.
async fn refusals_unless<'a>(
    project: &Path,
    candidates: &[(&'a str, &str)],
    allowed: bool,
) -> Vec<(&'a str, &'static str, String)> {
    if allowed || candidates.is_empty() {
        return Vec::new();
    }
    let dir = project.to_path_buf();
    let Some(root) = run_blocking(move || crate::bazel::bazel_root(&dir)).await else {
        return Vec::new();
    };
    // The root is canonical: on Windows that spelling has a prefix no user
    // types and no tool prints.
    let detail = format!(
        "the project is in the Bazel workspace at {}, and vendored mode makes composer.lock \
         name the patched copy by a path relative to the directory Composer runs in: a \
         Bazel rule that runs `composer install` anywhere else does not find it, and the \
         build fails; use `--mode hosted`, which names the patched archive by a URL that \
         Composer fetches from any directory, or pass `--allow-vendored-in-bazel` if \
         Composer only runs in the project's directory",
        without_verbatim_prefix(root.dir).display()
    );
    // A lock that cannot be read wires nothing: the backend says so itself.
    let lock = match read_regular_to_string(&project.join(COMPOSER_LOCK)).await {
        Ok(text) => LOCK_MEMO
            .parse(text.as_bytes(), || parse_json_text(&text))
            .ok(),
        Err(_) => None,
    };
    let wired = |purl: &str, uuid: &str| {
        let (Some(lock), Some(((vendor, name), _))) = (&lock, parse_composer_purl(purl)) else {
            return false;
        };
        let pkg = format!("{vendor}/{name}");
        composer_lock_packages(lock)
            .into_iter()
            .any(|p| p.name.is_some_and(|n| n.eq_ignore_ascii_case(&pkg)) && p.wired_to(uuid))
    };
    candidates
        .iter()
        .filter(|(purl, uuid)| !wired(purl, uuid))
        .map(|(purl, _)| (*purl, CODE, detail.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const PURL: &str = "pkg:composer/acme/widget@1.0.0";
    const UUID: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_UUID: &str = "33333333-3333-4333-8333-333333333333";

    /// The purls [`refusals_unless`] declines for a user who did not allow
    /// it.
    async fn declined<'a>(project: &Path, candidates: &[(&'a str, &str)]) -> Vec<&'a str> {
        let refused = refusals_unless(project, candidates, false).await;
        refused.into_iter().map(|(purl, _, _)| purl).collect()
    }

    #[tokio::test]
    async fn a_project_in_a_bazel_workspace_is_declined_and_no_other() {
        let tmp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(tmp.path()).unwrap();
        for dir in ["repo/.git", "repo/services/api", "plain"] {
            fs::create_dir_all(base.join(dir)).unwrap();
        }
        let (repo, api) = (base.join("repo"), base.join("repo/services/api"));
        let one = [(PURL, UUID)];
        assert!(declined(&api, &one).await.is_empty());
        // A workspace file in the project's directory, and one at the root
        // of its checkout, under each name Bazel looks for.
        for name in crate::bazel::WORKSPACE_FILES {
            for dir in [&api, &repo] {
                fs::write(dir.join(name), "").unwrap();
                let refused = refusals_unless(&api, &one, false).await;
                let [(purl, code, detail)] = &refused[..] else {
                    panic!("{name}: {refused:?}");
                };
                assert_eq!((*purl, *code), (PURL, CODE), "{name}");
                // The root, not the project below it: the comma ends it.
                let shown = without_verbatim_prefix(dir.clone());
                let named = [
                    &*format!("the Bazel workspace at {},", shown.display()),
                    "`--mode hosted`",
                    "`--allow-vendored-in-bazel`",
                ];
                assert!(named.iter().all(|part| detail.contains(part)), "{detail}");
                // The user's word lifts it.
                assert!(refusals_unless(&api, &one, true).await.is_empty(), "{name}");
                fs::remove_file(dir.join(name)).unwrap();
            }
        }
        // A workspace beside the project is not the project's.
        fs::write(base.join("plain/MODULE.bazel"), "").unwrap();
        assert!(declined(&api, &one).await.is_empty());
    }

    /// A package the lock already names by the copy of the same patch is
    /// let through: the run would leave the lock as it is. Another patch of
    /// that package, another package, and a lock that holds the registry
    /// entry or cannot be read are declined.
    #[tokio::test]
    async fn a_package_the_lock_already_wires_to_the_patch_is_let_through() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        fs::write(project.join("MODULE.bazel"), "").unwrap();
        let other = "pkg:composer/acme/gadget@2.0.0";
        let candidates = [(PURL, UUID), (other, UUID)];
        let lock = |dist: serde_json::Value| {
            let entries = serde_json::json!([
                { "name": "Acme/Widget", "version": "1.0.0", "dist": dist },
                { "name": "acme/gadget", "version": "2.0.0",
                  "dist": { "type": "zip", "url": "https://registry.example/gadget.zip" } },
            ]);
            let text = serde_json::json!({ "packages": entries, "packages-dev": [] });
            fs::write(project.join("composer.lock"), text.to_string()).unwrap();
        };
        let copy = format!(".socket/vendor/composer/{UUID}/acme/widget@1.0.0");
        lock(serde_json::json!({ "type": "path", "url": copy, "reference": UUID }));
        assert_eq!(declined(project, &candidates).await, [other]);
        assert_eq!(declined(project, &[(PURL, OTHER_UUID)]).await, [PURL]);
        lock(serde_json::json!({ "type": "zip", "url": "https://registry.example/widget.zip" }));
        assert_eq!(declined(project, &candidates).await, [PURL, other]);
        fs::write(project.join("composer.lock"), "{").unwrap();
        assert_eq!(declined(project, &candidates).await, [PURL, other]);
        fs::remove_file(project.join("composer.lock")).unwrap();
        assert_eq!(declined(project, &candidates).await, [PURL, other]);
    }
}
