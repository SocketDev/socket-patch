//! PyPI and RubyGems vendored mode for a project whose lock a Bazel hub
//! reads: declined unless the user allows it, or the package is a gem that
//! can be committed for the hub as its archive ([`super::gem::bazel`]).
//!
//! rules_python's `pip.parse` and rules_ruby's `ruby.bundle_fetch` build
//! the packages of a lock in repositories of Bazel's own. Vendored mode
//! makes the lock name the patched copy by a path under `.socket/vendor`,
//! and neither ruleset builds from that. rules_python 2.5.0-rc4 makes the
//! name of a repository from the path of a requirements line (`invalid
//! user-provided repo name 'pip_311__/_socket/vendor/pypi/...'`).
//! rules_ruby 1.0.0-rc2 runs `bundle install` in a repository that holds
//! the Gemfile and its lock and not the copy (`The path ... does not
//! exist.`). Either fails the build of everything the hub serves, after a
//! command that exited 0 (Bazel 9.3.2, 8.8.2 and 7.7.2).
//!
//! Which lock a hub reads is in the files of the workspace
//! ([`crate::bazel::built::reader`]), so the refusal is for a package whose
//! run may write a file that one reads and for no other. The requirements
//! files of a project count as one set there, since a file the hub reads
//! can bring in the rewritten one with `-r`. A project
//! beside a workspace whose calls name other files is vendored as it is
//! without Bazel, and so is a package whose run leaves the file the hub
//! reads alone: one of a Poetry or PDM project, whose lock is wired alone,
//! beside a hub that reads the requirements file exported from it
//! ([`super::pypi::hub_files`]). Where the files of the workspace cannot be
//! read with certainty and a call of the hub may be behind that, the
//! package is declined as well. Going on there can break a build;
//! declining costs a vendored run that the user's word brings back.
//!
//! What is declined is the write of that path into the lock the hub reads.
//! A package that this lock already names by the copy of the same patch is
//! let through: the run adds nothing to what the hub reads, so a project
//! that was vendored before (by an earlier release, or with the flag) keeps
//! passing its in-sync runs. Where the reading is in doubt no lock is known
//! to be the hub's, and nothing is let through.

use std::path::Path;

use crate::bazel::built::{from_root, lock_text, reader, Unbuilt};
use crate::bazel::workspace::Doubt;
use crate::bazel::BazelRoot;
use crate::crawlers::Ecosystem;
use crate::utils::env_compat::env_flag;
use crate::utils::fs::run_blocking;
use crate::utils::pnpm_workspace::without_verbatim_prefix;
use crate::utils::purl::parse_gem_purl;
use crate::vendor::gem::bazel as gem_hub;
use crate::vendor::path::vendor_uuid_dir_rel;
use crate::vendor::refusals::ALLOW_IN_BAZEL_ENV;

/// The codes of [`refusals`], one per ecosystem.
pub const PYPI_CODE: &str = "vendor_pypi_bazel_hub";
pub const GEM_CODE: &str = "vendor_gem_bazel_hub";

/// The PyPI and RubyGems `candidates` (`(purl, uuid)` pairs) that vendored
/// mode declines in the project at `project`, each with its code and the
/// detail. It declines a package whose hub may read a file of the project
/// that the run would rewrite, unless the user allowed it
/// ([`ALLOW_IN_BAZEL_ENV`]), and lets through a package the hub's lock
/// already names by the copy of that patch. Nothing is declined outside a
/// Bazel workspace ([`crate::bazel::bazel_root`]). Read-only, and it starts
/// no program.
pub async fn refusals<'a>(
    project: &Path,
    candidates: &[(&'a str, &str)],
) -> Vec<(&'a str, &'static str, String)> {
    refusals_unless(project, candidates, env_flag(ALLOW_IN_BAZEL_ENV)).await
}

/// What stands between vendored mode and a list of files of a project
/// ([`standing`]): what was read of the workspace, the text of the lock the
/// hub reads where a call names one, and for a call that names a gem's
/// files whether a gem can be committed for it as its archive
/// ([`gem_hub::gate`]). `None` where nothing stands in the way.
type Standing = Option<(String, Option<String>, Option<Result<gem_hub::Hub, String>>)>;

/// What rules_ruby builds of a hosted pin: the `sha256` of a gem that the
/// call lists holds the build to the registry's gem.
const GEM_HOSTED: &str = " where its call passes no `gem_checksums`";

/// [`refusals`] for a user who `allowed` it or did not.
async fn refusals_unless<'a>(
    project: &Path,
    candidates: &[(&'a str, &str)],
    allowed: bool,
) -> Vec<(&'a str, &'static str, String)> {
    let mut refused = Vec::new();
    // The code, the type of the purls, the ruleset, and what its hosted
    // pin takes.
    let hub = |purl: &str| match Ecosystem::from_purl(purl)? {
        Ecosystem::Pypi => Some((PYPI_CODE, "pypi", "rules_python", "")),
        Ecosystem::Gem => Some((GEM_CODE, "gem", "rules_ruby", GEM_HOSTED)),
        _ => None,
    };
    if allowed || !candidates.iter().any(|(purl, _)| hub(purl).is_some()) {
        return refused;
    }
    let dir = project.to_path_buf();
    let Some(root) = run_blocking(move || crate::bazel::bazel_root(&dir)).await else {
        return refused;
    };
    // What stands in the way of each list of files, asked once per list.
    let mut asked: Vec<(_, Standing)> = Vec::new();
    for (purl, uuid) in candidates {
        let Some((code, purls, ruleset, hosted)) = hub(purl) else {
            continue;
        };
        // The files a hub can be given that the run for this package would
        // point at a copy. With none, no hub stands in its way.
        let locks = match Ecosystem::from_purl(purl) {
            Some(Ecosystem::Pypi) => super::pypi::hub_files(project, purl).await,
            Some(Ecosystem::Gem) => [super::gem::GEMFILE, super::gem::GEMFILE_LOCK]
                .map(String::from)
                .to_vec(),
            _ => continue,
        };
        if locks.is_empty() {
            continue;
        }
        let list = (purls, locks);
        let at = match asked.iter().position(|(of, _)| *of == list) {
            Some(at) => at,
            None => {
                let stands = standing(&root, purls, ruleset, list.1.clone()).await;
                asked.push((list, stands));
                asked.len() - 1
            }
        };
        let Some((reads, lock, gem)) = &asked[at].1 else {
            continue;
        };
        // A lock names the copy of a patch by the copy's directory, outside
        // a comment (`#` starts one in each of these files).
        let copy = vendor_uuid_dir_rel(purls, uuid).map(|dir| format!("{dir}/"));
        let names = |lock: &Option<String>| match (lock, &copy) {
            (Some(lock), Some(copy)) => {
                let names = |line: &str| line.split('#').next().is_some_and(|l| l.contains(copy));
                lock.lines().any(names)
            }
            _ => false,
        };
        let mut wired = names(lock);
        // The first file a call names says nothing of a second one. Another
        // file of the list that a call names, or may name where the reading
        // is in doubt, stands in the way when it holds the package and not
        // by the copy (a `uv.lock` locked again beside a vendored
        // requirements file): the run would rewrite it. One that cannot be
        // read may hold it.
        let name = purl
            .rsplit('/')
            .next()
            .and_then(|rest| rest.split('@').next());
        let squash = |text: &str| text.to_ascii_lowercase().replace(['_', '.'], "-");
        let name = squash(name.unwrap_or_default());
        let holds = |text: &Option<String>| match text {
            Some(text) => squash(text).contains(&name),
            None => true,
        };
        let files = &asked[at].0 .1;
        let several = wired && files.len() > 1;
        for file in files.iter().filter(|_| several) {
            if !wired {
                break;
            }
            if reader(&root, purls, vec![file.clone()]).await.is_some() {
                let (dir, file) = (root.dir.clone(), from_root(&root, file));
                let text = run_blocking(move || lock_text(&dir, &file)).await;
                wired = names(&text) || !holds(&text);
            }
        }
        if wired {
            continue;
        }
        // A gem is committed as its archive where the hub is known to
        // build that: only where it is not is the gem declined.
        let committed = gem.as_ref().map(|hub| {
            let (name, version) = parse_gem_purl(purl).unwrap_or_default();
            let hub = hub.as_ref().map_err(String::clone)?;
            hub.declines(&name, &version).map_or(Ok(()), Err)
        });
        let fails = match committed {
            Some(Ok(())) => continue,
            Some(Err(why)) => format!(
                "vendored mode commits the patched gem for such a call and names it by a \
                 relative `file:` URL, which is not known to build here: {why}"
            ),
            None => format!(
                "vendored mode makes the lock name the patched copy by a path under \
                 .socket/vendor, and {ruleset} fails the build on such a lock"
            ),
        };
        let detail = format!(
            "{reads}; {fails}; use `--mode hosted`, which names the patched package by a URL \
             that {ruleset} fetches{hosted}, or pass `--allow-vendored-in-bazel` if no build \
             takes the packages of this project from {ruleset}"
        );
        refused.push((*purl, code, detail));
    }
    refused
}

/// The [`Standing`] of the files `locks` of the project of `root`, for the
/// packages of `ruleset` (purls of the type `purls`).
async fn standing(
    root: &BazelRoot,
    purls: &'static str,
    ruleset: &str,
    locks: Vec<String>,
) -> Standing {
    // The root is canonical: on Windows that spelling has a prefix no user
    // types and no tool prints.
    let at = without_verbatim_prefix(root.dir.clone());
    let at = at.display();
    let (reads, lock, gem) = match reader(root, purls, locks).await? {
        Ok(Unbuilt {
            call,
            file,
            line,
            lock,
            ..
        }) => {
            let reads =
                format!("`{call}` ({file}:{line}) of the Bazel workspace at {at} names {lock}");
            // Read as a lock of the workspace is: within its bound, and
            // not through a link that leads out of the Bazel root.
            let dir = root.dir.clone();
            let lock = run_blocking(move || lock_text(&dir, &lock)).await;
            let gem = match purls {
                "gem" => Some(gem_hub::gate(root).await),
                _ => None,
            };
            (reads, lock, gem)
        }
        Err(Doubt { file, line, why }) => {
            let line = match line {
                0 => String::new(),
                line => format!(":{line}"),
            };
            let reads = format!(
                "the files of the Bazel workspace at {at} cannot be read with certainty, so a \
                 call of {ruleset} may name a lock of this project ({file}{line}: {why})"
            );
            (reads, None, None)
        }
    };
    Some((reads, lock, gem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const UUID: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_UUID: &str = "33333333-3333-4333-8333-333333333333";

    /// A checkout whose root `MODULE.bazel` is `module`, canonical, with
    /// the files `files`.
    fn checkout(module: &str, files: &[(&str, &str)]) -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let all = [
            (".git/HEAD", "ref: refs/heads/main\n"),
            ("MODULE.bazel", module),
        ];
        for (path, text) in all.iter().chain(files) {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        (tmp, root)
    }

    const HUBS: &str = r#"pip = use_extension("@rules_python//python/extensions:pip.bzl", "pip")
pip.parse(hub_name = "pypi", python_version = "3.11", requirements_lock = "//api:base.txt")
ruby = use_extension("@rules_ruby//ruby:extensions.bzl", "ruby")
ruby.bundle_fetch(name = "bundle", gemfile = "//api:Gemfile", gemfile_lock = "//api:Gemfile.lock")
"#;

    /// The refusal of one package of `ecosystem` in `project`, for a user
    /// who `allowed` it or did not: its code and detail.
    async fn asked(
        project: &Path,
        ecosystem: Ecosystem,
        allowed: bool,
    ) -> Option<(&'static str, String)> {
        let purl = format!("pkg:{}/x@1.0.0", ecosystem.cli_name());
        let refused = refusals_unless(project, &[(&purl, UUID)], allowed).await;
        refused.into_iter().map(|(_, code, why)| (code, why)).next()
    }

    async fn declined(project: &Path, ecosystem: Ecosystem) -> (&'static str, String) {
        asked(project, ecosystem, false).await.unwrap_or_default()
    }

    #[tokio::test]
    async fn a_project_whose_lock_a_hub_reads_is_declined_and_no_other() {
        let requirements = ("api/requirements.txt", "-r base.txt\nidna==3.7\n");
        let (_tmp, root) = checkout(HUBS, &[requirements, ("web/requirements.txt", "")]);
        let (api, web) = (root.join("api"), root.join("web"));
        let shown = without_verbatim_prefix(root.clone());
        let at = format!("of the Bazel workspace at {} names", shown.display());
        // The requirements file the hub is given is one the project's own
        // brings in; the Gemfile and its lock are the project's.
        for (ecosystem, code, names) in [
            (
                Ecosystem::Pypi,
                PYPI_CODE,
                [
                    "`pip.parse` (MODULE.bazel:2)",
                    "names api/base.txt; ",
                    "and rules_python fails the build",
                ],
            ),
            (
                Ecosystem::Gem,
                GEM_CODE,
                [
                    "`ruby.bundle_fetch` (MODULE.bazel:4)",
                    "names api/Gemfile.lock; ",
                    "which is not known to build here: the project is not the root",
                ],
            ),
        ] {
            let (declined, detail) = declined(&api, ecosystem).await;
            assert_eq!(declined, code);
            let named = [&at, "`--mode hosted`", "`--allow-vendored-in-bazel`"];
            let mut named = named.iter().chain(&names);
            assert!(named.all(|part| detail.contains(part)), "{detail}");
            // The user's word lifts it, and a project whose files no call
            // names is not declined: one beside it, and the root.
            assert_eq!(asked(&api, ecosystem, true).await, None);
            assert_eq!(asked(&web, ecosystem, false).await, None);
            assert_eq!(asked(&root, ecosystem, false).await, None);
        }
        // No other ecosystem has such a hub.
        for other in [Ecosystem::Npm, Ecosystem::Composer, Ecosystem::Cargo] {
            assert_eq!(asked(&api, other, false).await, None, "{other:?}");
        }
        // The Gemfile alone is a file the run rewrites, and hosted mode is
        // named with what rules_ruby builds of it.
        let alone = HUBS.replace(", gemfile_lock = \"//api:Gemfile.lock\"", "");
        fs::write(root.join("MODULE.bazel"), alone).unwrap();
        let (code, detail) = declined(&api, Ecosystem::Gem).await;
        assert_eq!(code, GEM_CODE);
        let named = [
            "names api/Gemfile; ",
            "that rules_ruby fetches where its call passes no `gem_checksums`, or pass",
        ];
        assert!(named.iter().all(|part| detail.contains(part)), "{detail}");
        let (_, detail) = declined(&api, Ecosystem::Pypi).await;
        assert!(
            detail.contains("that rules_python fetches, or pass"),
            "{detail}"
        );
        // Without the workspace file nothing is declined.
        fs::remove_file(root.join("MODULE.bazel")).unwrap();
        assert_eq!(asked(&api, Ecosystem::Pypi, false).await, None);
        assert_eq!(asked(&api, Ecosystem::Gem, false).await, None);
    }

    /// A package that the lock the hub reads already names by the copy of
    /// the same patch is let through: the run adds nothing to what the hub
    /// reads. A package whose patch that lock does not name is declined,
    /// and so is one whose copy is named only in a comment or only in
    /// another file than the one the call names, and every package of a
    /// hub that is in doubt.
    #[tokio::test]
    async fn a_package_the_hub_s_lock_already_names_by_the_patch_s_copy_is_let_through() {
        let (_tmp, root) = checkout(HUBS, &[("api/requirements.txt", "-r base.txt\n")]);
        let api = root.join("api");
        let (wheel, other, gem) = ("pkg:pypi/a@1.0.0", "pkg:pypi/c@2.0.0", "pkg:gem/b@1.0.0");
        let candidates = [(wheel, UUID), (other, OTHER_UUID), (gem, UUID)];
        let declined = || async {
            let refused = refusals_unless(&api, &candidates, false).await;
            refused
                .into_iter()
                .map(|(purl, _, _)| purl)
                .collect::<Vec<_>>()
        };
        let line = format!("./.socket/vendor/pypi/{UUID}/a-1.0.0-py3-none-any.whl  # a==1.0.0\n");
        let path = format!("PATH\n  remote: .socket/vendor/gem/{UUID}/b-1.0.0\n");
        let gemfile = path.replace("remote:", "gem 'b', path:");
        fs::write(api.join("base.txt"), &line).unwrap();
        fs::write(api.join("Gemfile"), &gemfile).unwrap();
        fs::write(api.join("Gemfile.lock"), &path).unwrap();
        assert_eq!(declined().await, [other]);
        // The other file the call names is read too: a Gemfile that cannot
        // be read may hold the gem by the registry.
        fs::remove_file(api.join("Gemfile")).unwrap();
        assert_eq!(declined().await, [other, gem]);
        fs::write(api.join("Gemfile"), &gemfile).unwrap();
        // The lock is read as a file of the workspace is: one that is a
        // link out of the Bazel root lets nothing through.
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            let named = outside.path().join("base.txt");
            fs::write(&named, &line).unwrap();
            fs::remove_file(api.join("base.txt")).unwrap();
            std::os::unix::fs::symlink(&named, api.join("base.txt")).unwrap();
            assert_eq!(declined().await, [wheel, other]);
            fs::remove_file(api.join("base.txt")).unwrap();
        }
        // Named in a comment, the copy is not what the lock installs.
        fs::write(api.join("base.txt"), format!("a==1.0.0  # was {line}")).unwrap();
        assert_eq!(declined().await, [wheel, other]);
        // Named by the Gemfile alone: the lock is the file the call names
        // first, and it still holds the registry's gem.
        fs::write(api.join("Gemfile.lock"), "GEM\n  specs:\n    b (1.0.0)\n").unwrap();
        assert_eq!(declined().await, [wheel, other, gem]);
        // A hub whose file is not written out: no lock is known to be its.
        fs::write(api.join("base.txt"), &line).unwrap();
        let unwritten = HUBS.replace("\"//api:base.txt\"", "LOCK");
        fs::write(root.join("MODULE.bazel"), unwritten).unwrap();
        assert_eq!(declined().await, [wheel, other, gem]);
        // A second file that the hub reads: the uv lock, locked again
        // beside the vendored requirements file. It holds the package by
        // the registry's wheel, so the run would rewrite it.
        let both = "\"//api:base.txt\", uv_lock = \"//api:uv.lock\"";
        fs::write(
            root.join("MODULE.bazel"),
            HUBS.replace("\"//api:base.txt\"", both),
        )
        .unwrap();
        let entry =
            |source: &str| format!("[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n{source}");
        fs::write(api.join("uv.lock"), entry("")).unwrap();
        assert_eq!(declined().await, [wheel, other, gem]);
        // Held by the copy there too, or not held at all: let through.
        let copy = format!("source = {{ path = \".socket/vendor/pypi/{UUID}/a.whl\" }}\n");
        fs::write(api.join("uv.lock"), entry(&copy)).unwrap();
        assert_eq!(declined().await, [other, gem]);
        fs::write(api.join("uv.lock"), "").unwrap();
        assert_eq!(declined().await, [other, gem]);
        // A second attribute that is not written out may name the uv lock:
        // it is read as one the call names. (The hub names the vendored
        // requirements file itself here: `-r base.txt` would hold `a`.)
        fs::write(api.join("requirements.txt"), &line).unwrap();
        let unwritten = "\"//api:requirements.txt\", requirements_by_platform = PLATFORMS";
        fs::write(
            root.join("MODULE.bazel"),
            HUBS.replace("\"//api:base.txt\"", unwritten),
        )
        .unwrap();
        fs::write(api.join("uv.lock"), entry("")).unwrap();
        assert_eq!(declined().await, [wheel, other, gem]);
        fs::write(api.join("uv.lock"), entry(&copy)).unwrap();
        assert_eq!(declined().await, [other, gem]);
    }

    /// A requirements file the hub reads that brings the project's own in
    /// with `-r` hands the hub every file the run would write: declined.
    #[tokio::test]
    async fn a_hub_file_that_includes_the_project_s_requirements_is_declined() {
        let hub = HUBS.replace("//api:base.txt", "//api:all.txt");
        let files = [
            ("api/all.txt", "-r requirements.txt\n"),
            ("api/requirements.txt", "x==1.0.0\n"),
        ];
        let (_tmp, root) = checkout(&hub, &files);
        let (code, detail) = declined(&root.join("api"), Ecosystem::Pypi).await;
        assert_eq!(code, PYPI_CODE);
        assert!(detail.contains("names api/all.txt; "), "{detail}");
        // Without the include, the hub reads a file the run leaves alone.
        fs::write(root.join("api/all.txt"), "y==1.0.0\n").unwrap();
        assert_eq!(asked(&root.join("api"), Ecosystem::Pypi, false).await, None);
    }

    /// The uv lock of the project is a file a hub can be given, and a hub
    /// whose files are not written out declines every project of its
    /// ecosystem that a run would write, with the place and the reason.
    #[tokio::test]
    async fn a_uv_lock_counts_and_a_hub_that_cannot_be_read_declines() {
        let uv = HUBS.replace(
            "requirements_lock = \"//api:base.txt\"",
            "uv_lock = \"//api:uv.lock\"",
        );
        let (_tmp, root) = checkout(&uv, &[("api/uv.lock", "")]);
        let (code, detail) = declined(&root.join("api"), Ecosystem::Pypi).await;
        assert_eq!(code, PYPI_CODE);
        assert!(detail.contains("names api/uv.lock; "), "{detail}");

        let unwritten = HUBS.replace("\"//api:base.txt\"", "LOCK");
        let web = ("web/requirements.txt", "");
        let (_tmp, root) = checkout(&unwritten, &[web]);
        let (code, detail) = declined(&root.join("web"), Ecosystem::Pypi).await;
        assert_eq!(code, PYPI_CODE);
        let named = [
            "cannot be read with certainty, so a call of rules_python may name a lock of this \
             project (MODULE.bazel:2: the files `pip.parse` names are not all written out); ",
            "`--mode hosted`",
            "`--allow-vendored-in-bazel`",
        ];
        assert!(named.iter().all(|part| detail.contains(part)), "{detail}");
        // The doubt is about the Python hub alone.
        assert_eq!(asked(&root.join("web"), Ecosystem::Gem, false).await, None);
        // A file the root includes is missing: the doubt is about a file.
        let included = format!("{HUBS}include(\"//api:more.MODULE.bazel\")\n");
        let (_tmp, root) = checkout(&included, &[]);
        let (_, detail) = declined(&root.join("web"), Ecosystem::Gem).await;
        assert!(
            detail.contains("(api/more.MODULE.bazel: it does not exist"),
            "{detail}"
        );
    }

    /// The requirements file a hub reads is one the run writes where it is
    /// what is wired, and where it names the package beside a uv, Pipenv or
    /// Python lock. A Poetry or PDM lock is wired alone: the package of
    /// such a project is not declined beside a hub that reads the
    /// requirements file exported from the lock, whatever the hub's files
    /// leave open. Nor is a package the requirements file beside a uv lock
    /// does not name.
    #[tokio::test]
    async fn a_package_whose_run_leaves_the_hub_s_file_alone_is_not_declined() {
        let hub = HUBS.replace("//api:base.txt", "//api:requirements.txt");
        let (_tmp, root) = checkout(&hub, &[("api/requirements.txt", "x==1.0.0\n")]);
        let api = root.join("api");
        let pypi = || async {
            let asked = asked(&api, Ecosystem::Pypi, false).await;
            asked.map(|(code, _)| code)
        };
        assert_eq!(pypi().await, Some(PYPI_CODE));
        let unwritten = hub.replace("\"//api:requirements.txt\"", "LOCK");
        // A lock that resolves the package. One that resolves none is no
        // install source beside a `requirements.txt`, which is then what
        // the run writes: the package is declined as without the lock.
        let resolved = "[[package]]\nname = \"x\"\nversion = \"1.0.0\"\n";
        for lock in ["poetry.lock", "pdm.lock"] {
            fs::write(api.join(lock), "").unwrap();
            assert_eq!(pypi().await, Some(PYPI_CODE), "{lock}, with no package");
            fs::write(api.join(lock), resolved).unwrap();
            assert_eq!(pypi().await, None, "{lock}");
            fs::write(root.join("MODULE.bazel"), &unwritten).unwrap();
            assert_eq!(pypi().await, None, "{lock}, a hub in doubt");
            fs::write(root.join("MODULE.bazel"), &hub).unwrap();
            // But for a hosted pin of the requirements file: a run that
            // takes it over restores the line the hub reads.
            let hosted = "x @ https://h/x-1.0.0-py3-none-any.whl\n";
            fs::write(api.join("requirements.txt"), hosted).unwrap();
            assert_eq!(pypi().await, Some(PYPI_CODE), "{lock}, a hosted pin");
            fs::write(api.join("requirements.txt"), "x==1.0.0\n").unwrap();
            fs::remove_file(api.join(lock)).unwrap();
        }
        // A uv or Pipenv lock is wired with the pin of the requirements
        // file, also one that hosted mode made or an earlier patch.
        for lock in ["uv.lock", "Pipfile.lock"] {
            fs::write(api.join(lock), "").unwrap();
            let vendored = format!("./.socket/vendor/pypi/{OTHER_UUID}/x-1.0.0-py3-none-any.whl\n");
            for names in [
                "x==1.0.0\n",
                "x @ https://h/x-1.0.0-py3-none-any.whl\n",
                &vendored,
            ] {
                fs::write(api.join("requirements.txt"), names).unwrap();
                assert_eq!(pypi().await, Some(PYPI_CODE), "{lock}: {names}");
            }
            fs::write(api.join("requirements.txt"), "y==1.0.0\n").unwrap();
            assert_eq!(pypi().await, None, "{lock}");
            fs::remove_file(api.join(lock)).unwrap();
        }
    }
}
