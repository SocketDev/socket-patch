//! Whether the Bazel build of a workspace takes the copy of a package that
//! socket-patch patched.
//!
//! Three rulesets hand the packages of an ecosystem to Bazel through one
//! tag of a module extension, a hub: aspect_rules_js reads a pnpm lock
//! (`npm.npm_translate_lock`), rules_python reads requirements files
//! (`pip.parse`) and rules_ruby reads a Gemfile and its lock
//! (`ruby.bundle_fetch`). Each fetches what those files name into
//! repositories of Bazel's own and builds from there. None of them reads
//! what a package manager installed in the checkout (`node_modules`, a
//! virtualenv, a gem home), so a patch that is only in such a copy is not
//! in the build. And rules_python builds no package from a line that
//! points at a copy committed under `.socket/vendor`: 2.5.0-rc4 takes the
//! path for the name of a project and fails the build of everything the
//! hub serves (Bazel 9.3.2, 8.8.2 and 7.7.2). rules_js does build a
//! vendored tarball. What rules_ruby does with a vendored gem no build has
//! shown, so a vendored gem is not judged.
//!
//! [`unbuilt`] names, for a patched package, the call that builds it from a
//! file without its patch. It says so only when the files of the workspace
//! show it: the reader's answer is certain ([`Workspace::doubts`] and the
//! [`Tags::doubts`] of the hub are empty), no `WORKSPACE` file defines
//! anything beside the module files ([`Workspace::legacy`]), the call names
//! the file as a plain string, and the file can be read and says so
//! plainly. In every other case it says nothing, and what socket-patch
//! says of the package is what it says without Bazel.
//!
//! For an installed copy the file must be the project's own lock: the one
//! in the project's directory, or the lock of a pnpm workspace above it
//! that names that directory among its importers. A lock elsewhere that
//! lists the same package (in a directory beside the project, below it, or
//! above it without naming it) is the lock of another project, and says
//! nothing of this one: a project of the checkout that Bazel does not
//! build keeps what socket-patch says of it.
//!
//! Only a call that is a statement of its own counts ([`Call::whole`]):
//! it runs, once. One in a comprehension, behind an `and`, in a
//! conditional or in the arguments of another call may never run, and is
//! passed over. So is a call that passes `*` or `**`, whose arguments are
//! not all written out, and a `pip.parse` with `uv_lock`: rules_python
//! (2.2.0 and later) can take the packages of such a call from that file
//! alone, which is not read here.
//!
//! A lock is read like a file of the workspace ([`disk`]): never through a
//! link that leads out of the Bazel root, although Bazel follows such a
//! link. It is read only when it lies where the project's own lock can
//! lie, once however many calls name it, and up to 64 MiB; its text is
//! searched once for the patches of all the packages, and not kept. Of a
//! pnpm lock the project documents are read, for their keys alone:
//! rules_js links nothing of the document pnpm 11 keeps for its own
//! configuration.
//!
//! Not looked at: what a `--override_repository` or an rc file changes,
//! BUILD files, and hubs of other rulesets.
//!
//! [`Tags::doubts`]: super::workspace::Tags::doubts

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Component, Path};

use aho_corasick::AhoCorasick;

use super::starlark::{Call, Value};
use super::workspace::{disk, Extension, Repo, Workspace};
use crate::formats::gem::locked_specs;
use crate::formats::pnpm::grammar::documents;
use crate::formats::pnpm::workspace::lock_text_member_importers;
use crate::formats::pnpm::{pnpm_registry_key, PnpmDocument, PnpmLock};
use crate::utils::fs::{open_regular_file_sync, run_blocking};
use crate::utils::group_commit;
use crate::utils::purl::purl_parts;
use crate::utils::purl_key::PurlKey;
use crate::utils::requirements::{exact_pin, logical_lines, strip_comment};

/// A package that socket-patch patched in a project, and where the patch
/// is.
#[derive(Debug, Clone)]
pub struct Patched {
    /// `pkg:npm/left-pad@1.3.0`, in any spelling.
    pub purl: String,
    /// The id of the patch.
    pub uuid: String,
    /// `None`: the patch is in the copy a package manager installed.
    /// `Some`: it is a copy committed under `.socket/vendor`, and these
    /// files of the project point at it, each by its path from the project
    /// with `/` between its parts.
    pub pins: Option<Vec<String>>,
}

/// The call that builds a package from a file without its patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unbuilt {
    /// The tag, as a workspace file writes it: `npm.npm_translate_lock`.
    pub call: String,
    /// The file the call is in, from the Bazel root, and its line.
    pub file: String,
    pub line: usize,
    /// The file the call names for the package, from the Bazel root: for an
    /// installed copy the lock that lists the package, for a committed copy
    /// the file that points at it.
    pub lock: String,
}

/// The tag of a module extension that names the files a ruleset builds the
/// packages of an ecosystem from.
struct Hub {
    /// The type of the ecosystem's purls.
    ecosystem: &'static str,
    extension: Extension<'static>,
    tag: &'static str,
    /// The attributes that name such a file: a label, or a dict with a
    /// label as each key.
    files: &'static [&'static str],
    /// The packages a file lists plainly, each as its name and version.
    lists: fn(&str) -> Vec<(String, String)>,
    /// The directories below a file's own whose lock the file is as well,
    /// each from that directory: the members of a pnpm workspace.
    members: fn(&str) -> Vec<String>,
    /// Whether a call of the tag may build a package from a line that
    /// points at a copy under `.socket/vendor`: rules_js does, and of
    /// rules_ruby no build has shown that it does not.
    builds_vendored: bool,
}

const HUBS: [Hub; 3] = [
    Hub {
        ecosystem: "npm",
        extension: Extension {
            module: "aspect_rules_js",
            file: "//npm:extensions.bzl",
            name: "npm",
        },
        tag: "npm_translate_lock",
        files: &["pnpm_lock"],
        lists: |text| {
            let project = documents(text).into_iter();
            let project = project.filter(|(_, kind)| *kind == PnpmDocument::Project);
            let locks = project.map(|(span, _)| PnpmLock::parse_keys(&text[span]));
            let locks: Vec<_> = locks.collect();
            let keys = locks.iter().flat_map(|lock| lock.packages());
            owned(keys.filter_map(|package| pnpm_registry_key(package.key)))
        },
        members: lock_text_member_importers,
        builds_vendored: true,
    },
    Hub {
        ecosystem: "pypi",
        extension: Extension {
            module: "rules_python",
            file: "//python/extensions:pip.bzl",
            name: "pip",
        },
        tag: "parse",
        files: &[
            "requirements_lock",
            "requirements_by_platform",
            "requirements_darwin",
            "requirements_linux",
            "requirements_windows",
        ],
        lists: |text| {
            let lines = logical_lines(text);
            owned(
                lines
                    .iter()
                    .filter_map(|line| exact_pin(strip_comment(&line.text))),
            )
        },
        members: |_| Vec::new(),
        builds_vendored: false,
    },
    Hub {
        ecosystem: "gem",
        extension: Extension {
            module: "rules_ruby",
            file: "//ruby:extensions.bzl",
            name: "ruby",
        },
        tag: "bundle_fetch",
        files: &["gemfile_lock", "gemfile"],
        lists: |text| owned(locked_specs(text).into_iter()),
        members: |_| Vec::new(),
        builds_vendored: true,
    },
];

fn owned<'a>(listed: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<(String, String)> {
    listed
        .map(|(name, version)| (name.to_string(), version.to_string()))
        .collect()
}

/// The type of a purl, when it has a name and a version.
fn ecosystem(purl: &str) -> Option<String> {
    purl_parts(purl).map(|(ecosystem, _, _)| ecosystem)
}

/// For each of `packages`, patched in the project at `project`: the call of
/// the project's Bazel workspace that builds the package from a file
/// without the patch, or `None` when the files of the workspace show no
/// such call (see the module docs for what that takes).
///
/// Nothing is read for packages no hub is known for, nor outside a Bazel
/// workspace ([`super::bazel_root`], whose bounds these are).
pub async fn unbuilt(project: &Path, packages: Vec<Patched>) -> Vec<Option<Unbuilt>> {
    let hub = |package: &Patched| {
        let of = ecosystem(&package.purl);
        HUBS.iter().any(|hub| of.as_deref() == Some(hub.ecosystem))
    };
    if !packages.iter().any(hub) {
        return vec![None; packages.len()];
    }
    let project = project.to_path_buf();
    run_blocking(move || {
        let Some(root) = super::bazel_root(&project) else {
            return vec![None; packages.len()];
        };
        let workspace = Workspace::read(&disk(&root.dir));
        let read = |file: &str| lock_text(&root.dir, file);
        // Bazel has `/` between the parts of a path on every system.
        let parts = root.project.components();
        let parts: Vec<_> = parts
            .map(|part| part.as_os_str().to_string_lossy())
            .collect();
        judge(&workspace, &parts.join("/"), &read, &packages)
    })
    .await
}

/// The most of a lock that is read: the lock of a large pnpm workspace has
/// some tens of MiB. A larger file decides nothing.
const MAX_LOCK: u64 = 64 << 20;

/// The text of the lock `file` of the workspace at `root`, a canonical
/// path, read as [`disk`] reads a file of the workspace: a file this run
/// wrote and has not committed yet as the run left it, when `file` names it
/// in plain parts, and nothing through a link that leads out of the
/// workspace. `None` for that, for what is no file (a directory, which
/// Windows does not even open, like any other) or not UTF-8, and for a
/// file over [`MAX_LOCK`].
fn lock_text(root: &Path, file: &str) -> Option<String> {
    let path = root.join(file);
    let mut bytes = Vec::new();
    let plain = |part| matches!(part, Component::Normal(_));
    let plain = Path::new(file).components().all(plain);
    match plain.then(|| group_commit::read(&path)).flatten() {
        Some(pending) => bytes = pending.ok()?,
        None => {
            let real = std::fs::canonicalize(&path).ok()?;
            let inside = real.starts_with(root).then_some(real)?;
            let (file, _) = open_regular_file_sync(&inside).ok()?;
            file.take(MAX_LOCK + 1).read_to_end(&mut bytes).ok()?;
        }
    }
    let whole = bytes.len() as u64 <= MAX_LOCK;
    whole.then(|| String::from_utf8(bytes).ok())?
}

/// [`unbuilt`] for the workspace `workspace` and the project in its
/// directory `project` (empty: the root itself), with `read` for the text
/// of a file of the workspace.
fn judge(
    workspace: &Workspace,
    project: &str,
    read: &dyn Fn(&str) -> Option<String>,
    packages: &[Patched],
) -> Vec<Option<Unbuilt>> {
    let mut found = vec![None; packages.len()];
    if !workspace.doubts.is_empty() || workspace.legacy.is_some() {
        return found;
    }
    for hub in &HUBS {
        let ours = |at: &usize| ecosystem(&packages[*at].purl).as_deref() == Some(hub.ecosystem);
        let ours: Vec<usize> = (0..packages.len()).filter(ours).collect();
        if ours.is_empty() {
            continue;
        }
        let tags = workspace.tags(&hub.extension, hub.tag);
        if !tags.doubts.is_empty() {
            continue;
        }
        // What a file lists, and which patches of the packages its text
        // names: read when a package first asks and once for all the calls
        // that name it, and the text is not kept. `None` for a file that
        // is not the project's lock or cannot be read.
        let mut listed = HashMap::new();
        let elsewhere = |call: &Call| call.unpacks() || call.arg("uv_lock").is_some();
        for tag in (tags.calls.iter()).filter(|tag| tag.call.whole && !elsewhere(tag.call)) {
            for lock in files(workspace, tag.call, hub.files) {
                for &at in &ours {
                    let package = &packages[at];
                    let unpatched = match &package.pins {
                        Some(pins) => {
                            !hub.builds_vendored
                                && pins.iter().any(|pin| below(project, pin) == lock)
                        }
                        None => {
                            let listed = listed.entry(lock.clone()).or_insert_with(|| {
                                let member = from_lock(project, &lock)?;
                                let text = read(&lock)?;
                                let named = || (hub.members)(&text).iter().any(|m| m == member);
                                if !(member.is_empty() || named()) {
                                    return None;
                                }
                                let listed = (hub.lists)(&text).into_iter();
                                let key = |(name, version)| {
                                    PurlKey::new(&format!("pkg:{}/{name}@{version}", hub.ecosystem))
                                };
                                // One pass over the text for all the patches.
                                let uuid = |at: usize| packages[at].uuid.as_str();
                                let ids = ours.iter().map(|at| uuid(*at));
                                let named = AhoCorasick::new(ids).ok()?;
                                let named = named.find_overlapping_iter(&text);
                                let named = named.map(|id| uuid(ours[id.pattern()]));
                                Some((listed.map(key).collect(), named.collect()))
                            });
                            // A file that names the patch may hold it.
                            let lists = |(listed, named): &(HashSet<_>, HashSet<_>)| {
                                listed.contains(&PurlKey::new(&package.purl))
                                    && !named.contains(package.uuid.as_str())
                            };
                            listed.as_ref().is_some_and(lists)
                        }
                    };
                    if unpatched && found[at].is_none() {
                        found[at] = Some(Unbuilt {
                            call: format!("{}.{}", hub.extension.name, hub.tag),
                            file: tag.file.to_string(),
                            line: tag.call.line,
                            lock: lock.clone(),
                        });
                    }
                }
            }
        }
    }
    found
}

/// The files of the main repository that `call` names under `attributes`,
/// each by its path from the Bazel root. An attribute that is not written
/// out as a string, or as a dict with strings as keys, names none.
fn files(workspace: &Workspace, call: &Call, attributes: &[&str]) -> Vec<String> {
    let mut labels: Vec<&str> = Vec::new();
    for attribute in attributes {
        match call.arg(attribute) {
            Some(Value::Str(label)) => labels.push(label),
            Some(Value::Dict(entries)) => {
                labels.extend(entries.iter().map(|(label, _)| label.as_str()))
            }
            _ => {}
        }
    }
    let main = |label: &&str| {
        let label = workspace
            .label(label)
            .filter(|label| label.repo == Repo::Main);
        label.map(|label| label.path())
    };
    labels.iter().filter_map(main).collect()
}

/// The path from the Bazel root of `file`, a path from the project in the
/// directory `project`.
fn below(project: &str, file: &str) -> String {
    let file = file.trim_start_matches("./");
    match project {
        "" => file.to_string(),
        project => format!("{project}/{file}"),
    }
}

/// The directory `project` from the directory of the workspace's file
/// `lock`: empty for the project the file lies in, `apps/web` for one that
/// far below it. `None` for a project that is neither: no file beside the
/// project, or below it, is its lock.
fn from_lock<'a>(project: &'a str, lock: &str) -> Option<&'a str> {
    let directory = lock.rsplit_once('/').map_or("", |(directory, _)| directory);
    match project.strip_prefix(directory)? {
        rest if directory.is_empty() || rest.is_empty() => Some(rest),
        rest => rest.strip_prefix('/'),
    }
}

#[cfg(test)]
mod tests {
    use super::super::workspace::Entry;
    use super::*;

    const UUID: &str = "7a11e000-0000-4000-8000-0000000000b1";

    /// A workspace with the three hubs: the npm one of `web`, two Python
    /// ones (one with a file per platform) and the Ruby one in a file the
    /// root includes.
    const ROOT: &str = r#"module(name = "shop", version = "0.0.0")

bazel_dep(name = "aspect_rules_js", version = "3.6.0")
bazel_dep(name = "rules_python", version = "2.5.0-rc4")
bazel_dep(name = "rules_ruby", version = "1.0.0-rc2")

npm = use_extension("@aspect_rules_js//npm:extensions.bzl", "npm")
npm.npm_translate_lock(
    name = "npm",
    pnpm_lock = "//web:pnpm-lock.yaml",
)
use_repo(npm, "npm")

pip = use_extension("@rules_python//python/extensions:pip.bzl", "pip")
pip.parse(
    hub_name = "pypi",
    python_version = "3.11",
    requirements_lock = "//api:requirements.txt",
)
pip.parse(
    hub_name = "tools",
    python_version = "3.11",
    requirements_by_platform = {
        "//tools:requirements_linux.txt": "linux_*",
        "//tools:requirements_darwin.txt": "osx_*",
    },
)
use_repo(pip, "pypi", "tools")

include("//billing:ruby.MODULE.bazel")
"#;

    const RUBY: &str = r#"ruby = use_extension("@rules_ruby//ruby:extensions.bzl", "ruby")
ruby.bundle_fetch(
    name = "bundle",
    gemfile = "//billing:Gemfile",
    gemfile_lock = "//billing:Gemfile.lock",
)
use_repo(ruby, "bundle")
"#;

    const PNPM_LOCK: &str =
        "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      \
        left-pad:\n        specifier: 1.3.0\n        version: 1.3.0\n\npackages:\n\n  \
        '@shop/ui@2.0.0':\n    resolution: {integrity: sha512-AAAA}\n\n  \
        left-pad@1.3.0:\n    resolution: {integrity: sha512-BBBB}\n\nsnapshots:\n\n  \
        '@shop/ui@2.0.0': {}\n\n  left-pad@1.3.0: {}\n";

    const REQUIREMENTS: &str = "# pip-compile\nFlask_Cors==4.0.0 \\\n    \
        --hash=sha256:aaaa\nrequests>=2.31.0\n# idna==3.6\n";

    const GEMFILE_LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    \
        nokogiri (1.16.5-arm64-darwin)\n    rack (2.2.8)\n\nPLATFORMS\n  arm64-darwin\n\n\
        DEPENDENCIES\n  nokogiri\n  rack\n";

    const SHOP: [(&str, &str); 8] = [
        ("MODULE.bazel", ROOT),
        ("billing/ruby.MODULE.bazel", RUBY),
        ("web/pnpm-lock.yaml", PNPM_LOCK),
        ("api/requirements.txt", REQUIREMENTS),
        ("tools/requirements_linux.txt", "idna==3.6\n"),
        ("tools/requirements_darwin.txt", "idna==3.7\n"),
        (
            "billing/Gemfile",
            "source \"https://rubygems.org\"\ngem \"rack\"\n",
        ),
        ("billing/Gemfile.lock", GEMFILE_LOCK),
    ];

    /// What [`judge`] says of one package of the project in `project`, in
    /// the workspace of `files`: `call file:line lock`.
    fn said(files: &[(&str, &str)], project: &str, purl: &str, pins: Option<&[&str]>) -> String {
        read_and_said(files, project, purl, pins).1
    }

    /// The locks [`judge`] read, in order, and what it [`said`].
    fn read_and_said(
        files: &[(&str, &str)],
        project: &str,
        purl: &str,
        pins: Option<&[&str]>,
    ) -> (Vec<String>, String) {
        let text = |path: &str| {
            files
                .iter()
                .find(|(name, _)| *name == path)
                .map(|(_, text)| *text)
        };
        let workspace = Workspace::read(&|path| match text(path) {
            Some(text) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        });
        let package = Patched {
            purl: purl.to_string(),
            uuid: UUID.to_string(),
            pins: pins.map(|pins| pins.iter().map(|pin| pin.to_string()).collect()),
        };
        let asked = std::cell::RefCell::new(Vec::new());
        let read = |path: &str| {
            asked.borrow_mut().push(path.to_string());
            text(path).map(str::to_string)
        };
        let found = judge(&workspace, project, &read, &[package]).remove(0);
        let show = |found: Unbuilt| {
            format!(
                "{} {}:{} {}",
                found.call, found.file, found.line, found.lock
            )
        };
        (asked.into_inner(), found.map(show).unwrap_or_default())
    }

    /// The shop with `text` in the place of the file `path`, or as a new
    /// file.
    fn with(path: &'static str, text: &'static str) -> Vec<(&'static str, &'static str)> {
        let mut files: Vec<_> = SHOP.into_iter().filter(|(name, _)| *name != path).collect();
        files.push((path, text));
        files
    }

    const NPM: &str = "npm.npm_translate_lock MODULE.bazel:8 web/pnpm-lock.yaml";

    #[test]
    fn an_installed_copy_is_not_what_a_hub_builds() {
        let installed = |project, purl| said(&SHOP, project, purl, None);
        // The lock of the project, in every spelling of the package.
        assert_eq!(installed("web", "pkg:npm/left-pad@1.3.0"), NPM);
        assert_eq!(installed("web", "pkg:npm/%40shop/ui@2.0.0"), NPM);
        assert_eq!(installed("web", "pkg:npm/@shop/ui@2.0.0?x=1"), NPM);
        // A pin with hashes, a name pip folds.
        let pypi = "pip.parse MODULE.bazel:15 api/requirements.txt";
        assert_eq!(installed("api", "pkg:pypi/flask-cors@4.0.0"), pypi);
        assert_eq!(installed("api", "pkg:pypi/Flask_Cors@4.0.0"), pypi);
        // A file per platform: each is one the hub builds from.
        let linux = "pip.parse MODULE.bazel:20 tools/requirements_linux.txt";
        assert_eq!(installed("tools", "pkg:pypi/idna@3.6"), linux);
        let darwin = "pip.parse MODULE.bazel:20 tools/requirements_darwin.txt";
        assert_eq!(installed("tools", "pkg:pypi/idna@3.7"), darwin);
        // A hub in an included file, and a gem of one platform.
        let gem = "ruby.bundle_fetch billing/ruby.MODULE.bazel:2 billing/Gemfile.lock";
        assert_eq!(installed("billing", "pkg:gem/rack@2.2.8"), gem);
        let platform = "pkg:gem/nokogiri@1.16.5?platform=arm64-darwin";
        assert_eq!(installed("billing", platform), gem);
    }

    /// The lock of a pnpm workspace is the lock of each member it names
    /// among its importers, in either spelling of the key, and of no other
    /// directory below it.
    #[test]
    fn the_lock_of_a_pnpm_workspace_is_the_lock_of_its_members() {
        let shared = |importers: &str| {
            let lock = PNPM_LOCK.replace("packages:\n", &format!("{importers}\npackages:\n"));
            assert_ne!(lock, PNPM_LOCK);
            let lock: &'static str = Box::leak(lock.into_boxed_str());
            with("web/pnpm-lock.yaml", lock)
        };
        let member =
            |files: &[(&str, &str)], project| said(files, project, "pkg:npm/left-pad@1.3.0", None);
        for importers in [
            "  apps/admin:\n    dependencies: {}\n",
            "  'apps/admin': {}\n",
        ] {
            let files = shared(importers);
            assert_eq!(member(&files, "web/apps/admin"), NPM, "{importers}");
            assert_eq!(member(&files, "web"), NPM, "{importers}");
            for other in [
                "web/apps",
                "web/apps/admin/src",
                "web/admin",
                "apps/admin",
                "",
            ] {
                assert_eq!(member(&files, other), "", "{importers} {other}");
            }
        }
        // A lock that names no member is the lock of its directory alone.
        assert_eq!(member(&SHOP, "web/apps/admin"), "");
        // Only a pnpm lock has members.
        let nested = "pkg:pypi/flask-cors@4.0.0";
        assert_ne!(said(&SHOP, "api", nested, None), "");
        assert_eq!(said(&SHOP, "api/worker", nested, None), "");
    }

    /// A lock is read only where the project's own lock can lie, and once
    /// however many calls name it.
    #[test]
    fn a_lock_is_read_once_and_only_where_the_project_s_lock_can_lie() {
        let twice: &'static str = Box::leak(
            format!(
                "{ROOT}npm.npm_translate_lock(name = \"again\", pnpm_lock = \"//web:pnpm-lock.yaml\")\n\
                 npm.npm_translate_lock(name = \"below\", pnpm_lock = \"//web/site:pnpm-lock.yaml\")\n"
            )
            .into_boxed_str(),
        );
        let mut files = with("MODULE.bazel", twice);
        files.push(("web/site/pnpm-lock.yaml", PNPM_LOCK));
        let read = |project| read_and_said(&files, project, "pkg:npm/left-pad@1.3.0", None);
        assert_eq!(
            read("web"),
            (vec!["web/pnpm-lock.yaml".to_string()], NPM.to_string())
        );
        // From a directory below it a lock is read for its importers.
        let below = vec!["web/pnpm-lock.yaml", "web/site/pnpm-lock.yaml"];
        assert_eq!(read("web/site/app").0, below);
        assert_eq!(read("mobile"), (vec![], String::new()));
        assert_eq!(read(""), (vec![], String::new()));
    }

    #[test]
    fn a_package_no_hub_is_shown_to_build_is_left_alone() {
        let installed = |project, purl| said(&SHOP, project, purl, None);
        // The lock of another project, also one whose name starts alike.
        assert_eq!(installed("mobile", "pkg:npm/left-pad@1.3.0"), "");
        assert_eq!(installed("webby", "pkg:npm/left-pad@1.3.0"), "");
        assert_eq!(installed("web", "pkg:gem/rack@2.2.8"), "");
        // A lock below the project, and one above it that does not name
        // it: the project has a lock of its own, or none.
        assert_eq!(installed("", "pkg:npm/left-pad@1.3.0"), "");
        assert_eq!(installed("web/admin", "pkg:npm/left-pad@1.3.0"), "");
        assert_eq!(installed("", "pkg:gem/rack@2.2.8"), "");
        assert_eq!(installed("billing/app", "pkg:gem/rack@2.2.8"), "");
        // Another version, another package, a range, a comment.
        assert_eq!(installed("web", "pkg:npm/left-pad@1.2.0"), "");
        assert_eq!(installed("web", "pkg:npm/right-pad@1.3.0"), "");
        assert_eq!(installed("api", "pkg:pypi/requests@2.31.0"), "");
        assert_eq!(installed("api", "pkg:pypi/idna@3.6"), "");
        // An ecosystem without a hub here, and no purl at all.
        assert_eq!(installed("web", "pkg:cargo/serde@1.0.0"), "");
        assert_eq!(installed("web", "pkg:golang/example.com/m@v1.0.0"), "");
        assert_eq!(installed("web", "left-pad"), "");
    }

    #[test]
    fn a_committed_copy_is_not_built_from_a_line_that_points_at_it() {
        let vendored = |project, purl, pins: &[&str]| said(&SHOP, project, purl, Some(pins));
        let pypi = "pip.parse MODULE.bazel:15 api/requirements.txt";
        let requests = "pkg:pypi/requests@2.31.0";
        assert_eq!(vendored("api", requests, &["requirements.txt"]), pypi);
        assert_eq!(vendored("api", requests, &["./requirements.txt"]), pypi);
        // rules_js builds a committed tarball. What rules_ruby does with a
        // committed gem no build has shown: it is not judged, in the
        // Gemfile or in its lock, while an installed one is.
        let (npm, gem) = ("pkg:npm/left-pad@1.3.0", "pkg:gem/rack@2.2.8");
        assert_eq!(vendored("web", npm, &["pnpm-lock.yaml"]), "");
        assert_eq!(vendored("billing", gem, &["Gemfile", "Gemfile.lock"]), "");
        assert_eq!(vendored("billing", gem, &["Gemfile"]), "");
        assert_ne!(said(&SHOP, "billing", gem, None), "");
        // Not judged yet: a copy that files point at which no hub reads,
        // while the lock the hub does read lists the registry's package.
        let listed = "pkg:pypi/flask-cors@4.0.0";
        assert_ne!(said(&SHOP, "api", listed, None), "");
        assert_eq!(vendored("api", listed, &["pyproject.toml", "uv.lock"]), "");
        assert_eq!(vendored("web", npm, &["package-lock.json"]), "");
        // The same name in another project, and no file at all.
        assert_eq!(vendored("mobile", requests, &["requirements.txt"]), "");
        assert_eq!(vendored("api", "pkg:pypi/flask-cors@4.0.0", &[]), "");
    }

    #[test]
    fn a_lock_that_names_the_patch_is_left_alone() {
        let hosted: &'static str = Box::leak(
            PNPM_LOCK
                .replace(
                    "sha512-BBBB",
                    &format!("sha512-CCCC, tarball: https://h/patch/{UUID}/a.tgz"),
                )
                .into_boxed_str(),
        );
        assert_ne!(hosted, PNPM_LOCK);
        let files = with("web/pnpm-lock.yaml", hosted);
        assert_eq!(said(&files, "web", "pkg:npm/left-pad@1.3.0", None), "");
        // The lock without it is judged as before.
        assert_eq!(said(&SHOP, "web", "pkg:npm/left-pad@1.3.0", None), NPM);

        // Each package is judged by its own patch, also where two share
        // one, and a package the lock does not list by none.
        let other = "7a11e000-0000-4000-8000-0000000000b2";
        let patched = |files: &[(&'static str, &'static str)], uuids: [&str; 3]| {
            let text = |path: &str| files.iter().find(|(name, _)| *name == path);
            let workspace = Workspace::read(&|path| match text(path) {
                Some((_, text)) => Entry::Text(text.to_string()),
                None => Entry::Absent,
            });
            let purls = [
                "pkg:npm/left-pad@1.3.0",
                "pkg:npm/@shop/ui@2.0.0",
                "pkg:npm/is-odd@3.0.1",
            ];
            let packages: Vec<_> = (purls.iter().zip(uuids))
                .map(|(purl, uuid)| Patched {
                    purl: purl.to_string(),
                    uuid: uuid.to_string(),
                    pins: None,
                })
                .collect();
            let read = |path: &str| text(path).map(|(_, text)| text.to_string());
            let found = judge(&workspace, "web", &read, &packages);
            found.iter().map(Option::is_some).collect::<Vec<_>>()
        };
        assert_eq!(patched(&files, [UUID, other, UUID]), [false, true, false]);
        assert_eq!(patched(&files, [UUID, UUID, other]), [false, false, false]);
        assert_eq!(patched(&files, [other, other, UUID]), [true, true, false]);
        assert_eq!(patched(&SHOP, [UUID, UUID, UUID]), [true, true, false]);
    }

    #[test]
    fn nothing_is_said_of_a_workspace_that_is_not_read_with_certainty() {
        let npm = |files: &[(&str, &str)]| said(files, "web", "pkg:npm/left-pad@1.3.0", None);
        let gem = |files: &[(&str, &str)]| said(files, "billing", "pkg:gem/rack@2.2.8", None);
        assert_eq!(npm(&SHOP), NPM);
        // A file the root includes is missing: a doubt on every answer.
        let missing: Vec<_> = SHOP
            .into_iter()
            .filter(|(name, _)| !name.ends_with("ruby.MODULE.bazel"))
            .collect();
        assert_eq!(
            (npm(&missing), gem(&missing)),
            (String::new(), String::new())
        );
        // A `WORKSPACE` file that defines something, in each of its names;
        // one that only names the workspace is none.
        let rule = "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n";
        for name in ["WORKSPACE", "WORKSPACE.bazel", "WORKSPACE.bzlmod"] {
            assert_eq!(npm(&with(name, rule)), "", "{name}");
            assert_eq!(
                npm(&with(name, "workspace(name = \"shop\")\n")),
                NPM,
                "{name}"
            );
        }
        assert_eq!(npm(&with("WORKSPACE", "http_archive(\n")), "");
        // A proxy that is handed on: a doubt on that hub alone.
        let handed: &'static str = Box::leak(format!("{ROOT}print(npm)\n").into_boxed_str());
        let files = with("MODULE.bazel", handed);
        assert_eq!(npm(&files), "");
        assert_ne!(gem(&files), "");
        // No module file at all.
        assert_eq!(npm(&SHOP[1..]), "");
    }

    /// Only a call that is a statement of its own is known to run. One in
    /// a comprehension, behind an `and`, in a conditional or in the
    /// arguments of another call may never run: it withholds nothing, for
    /// an installed copy and for a committed one.
    #[test]
    fn a_call_that_may_not_run_withholds_nothing() {
        let hub = "npm.npm_translate_lock(\n    name = \"npm\",\n    pnpm_lock = \"//web:pnpm-lock.yaml\",\n)\n";
        let npm = |call: &str| {
            let root = ROOT.replace(hub, &format!("{call}\n"));
            assert_ne!(root, ROOT, "{call}");
            let root: &'static str = Box::leak(root.into_boxed_str());
            let files = with("MODULE.bazel", root);
            said(&files, "web", "pkg:npm/left-pad@1.3.0", None)
        };
        let call = "npm.npm_translate_lock(pnpm_lock = \"//web:pnpm-lock.yaml\")";
        assert_eq!(npm(call), NPM);
        assert_eq!(npm(&format!("hub = {call}")), NPM);
        for may_not_run in [
            format!("[{call} for version in []]"),
            format!("ENABLE and {call}"),
            format!("{call} if ENABLE else None"),
            format!("print({call})"),
        ] {
            assert_eq!(npm(&may_not_run), "", "{may_not_run}");
        }
        let pip = "pip.parse(\n    hub_name = \"pypi\",\n    python_version = \"3.11\",\n    requirements_lock = \"//api:requirements.txt\",\n)\n";
        let looped =
            "[pip.parse(requirements_lock = \"//api:requirements.txt\") for version in []]\n";
        let root = ROOT.replace(pip, looped);
        assert_ne!(root, ROOT);
        let root: &'static str = Box::leak(root.into_boxed_str());
        let files = with("MODULE.bazel", root);
        let requests = "pkg:pypi/requests@2.31.0";
        assert_eq!(
            said(&files, "api", requests, Some(&["requirements.txt"])),
            ""
        );
        assert_eq!(said(&files, "api", "pkg:pypi/flask-cors@4.0.0", None), "");
        // A call of the same hub that does run is judged as before.
        assert_ne!(said(&files, "tools", "pkg:pypi/idna@3.6", None), "");
    }

    /// A call whose arguments are not all written out is passed over, and
    /// so is a `pip.parse` with `uv_lock`: rules_python can take the
    /// packages of such a call from that file, whatever the requirements
    /// file lists or points at.
    #[test]
    fn a_call_that_may_read_another_file_withholds_nothing() {
        let lock = "    requirements_lock = \"//api:requirements.txt\",\n";
        let pypi = |argument: &str| {
            let root = ROOT.replace(lock, &format!("{lock}    {argument},\n"));
            assert_ne!(root, ROOT, "{argument}");
            let root: &'static str = Box::leak(root.into_boxed_str());
            let files = with("MODULE.bazel", root);
            let pins = ["requirements.txt"];
            [
                said(&files, "api", "pkg:pypi/flask-cors@4.0.0", None),
                said(&files, "api", "pkg:pypi/requests@2.31.0", Some(&pins)),
            ]
        };
        let judged = "pip.parse MODULE.bazel:15 api/requirements.txt".to_string();
        assert_eq!(pypi("quiet = False"), [judged.clone(), judged]);
        for elsewhere in ["uv_lock = \"//api:uv.lock\"", "**COMMON", "*LOCKS"] {
            assert_eq!(
                pypi(elsewhere),
                [String::new(), String::new()],
                "{elsewhere}"
            );
        }
    }

    /// pnpm 11 keeps the packages of its own configuration in a first
    /// document of the lock. rules_js links what the project documents
    /// list: a package of that document alone is not one the hub builds.
    #[test]
    fn a_package_of_the_env_document_of_a_pnpm_lock_is_not_listed() {
        let env =
            "---\nlockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    configDependencies:\n      \
            is-odd:\n        specifier: 3.0.1\n        version: 3.0.1\n\npackages:\n\n  \
            is-odd@3.0.1:\n    resolution: {integrity: sha512-DDDD}\n\nsnapshots:\n\n  \
            is-odd@3.0.1: {}\n\n---\n";
        let lock: &'static str = Box::leak(format!("{env}{PNPM_LOCK}").into_boxed_str());
        let files = with("web/pnpm-lock.yaml", lock);
        assert_eq!(said(&files, "web", "pkg:npm/is-odd@3.0.1", None), "");
        assert_eq!(said(&files, "web", "pkg:npm/left-pad@1.3.0", None), NPM);
        // The same entry in a lock of one document is a package of the
        // project.
        let one = lock
            .replace("---\n", "")
            .replace("configDependencies", "dependencies");
        let one: &'static str = Box::leak(one.into_boxed_str());
        let files = with("web/pnpm-lock.yaml", one);
        assert_eq!(said(&files, "web", "pkg:npm/is-odd@3.0.1", None), NPM);
    }

    #[test]
    fn only_a_label_written_out_in_the_main_repository_names_a_file() {
        let npm = |label: &str| {
            let root = ROOT.replace("\"//web:pnpm-lock.yaml\"", label);
            assert_ne!(root, ROOT, "{label}");
            let root: &'static str = Box::leak(root.into_boxed_str());
            said(
                &with("MODULE.bazel", root),
                "web",
                "pkg:npm/left-pad@1.3.0",
                None,
            )
        };
        for main in [
            "\"@//web:pnpm-lock.yaml\"",
            "\"@@//web:pnpm-lock.yaml\"",
            "\"@shop//web:pnpm-lock.yaml\"",
        ] {
            assert_eq!(npm(main), NPM, "{main}");
        }
        // A relative label is read from the root, where there is no lock.
        for none in [
            "\"pnpm-lock.yaml\"",
            "\":pnpm-lock.yaml\"",
            "\"@other//web:pnpm-lock.yaml\"",
            "\"//web:missing.yaml\"",
            "LOCK",
            "\"//web:\" + \"pnpm-lock.yaml\"",
            "Label(\"//web:pnpm-lock.yaml\")",
        ] {
            assert_eq!(npm(none), "", "{none}");
        }
    }

    #[test]
    fn a_project_is_in_the_directory_of_a_lock_or_below_it_or_neither() {
        for (project, lock, from) in [
            ("", "pnpm-lock.yaml", Some("")),
            ("a/b", "pnpm-lock.yaml", Some("a/b")),
            ("a/b", "a/pnpm-lock.yaml", Some("b")),
            ("a/b", "a/b/pnpm-lock.yaml", Some("")),
            ("", "a/b/pnpm-lock.yaml", None),
            ("a/b", "a/b/c/pnpm-lock.yaml", None),
            ("a/b", "a/c/pnpm-lock.yaml", None),
            ("a/b", "a/bc/pnpm-lock.yaml", None),
            ("a/bc", "a/b/pnpm-lock.yaml", None),
            ("a", "b/pnpm-lock.yaml", None),
        ] {
            assert_eq!(from_lock(project, lock), from, "{project:?} {lock}");
        }
        assert_eq!(below("", "./requirements.txt"), "requirements.txt");
        assert_eq!(below("a/b", "requirements.txt"), "a/b/requirements.txt");
    }

    /// On disk: the Bazel root is found from the project, the files are
    /// read there, and nothing is looked for when no package has a hub or
    /// no workspace is around the project.
    #[tokio::test]
    async fn the_workspace_of_a_project_on_disk_is_read() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let write = |path: &str, text: &str| {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write(".git/HEAD", "ref: refs/heads/main\n");
        for (path, text) in SHOP {
            write(path, text);
        }
        let package = |purl: &str, pins: Option<Vec<String>>| Patched {
            purl: purl.to_string(),
            uuid: UUID.to_string(),
            pins,
        };
        let packages = vec![
            package("pkg:cargo/serde@1.0.0", None),
            package("pkg:npm/left-pad@1.3.0", None),
            package("pkg:npm/left-pad@1.2.0", None),
        ];
        let found = unbuilt(&root.join("web"), packages.clone()).await;
        let locks: Vec<_> = found
            .iter()
            .map(|found| found.as_ref().map(|found| found.lock.as_str()))
            .collect();
        assert_eq!(locks, [None, Some("web/pnpm-lock.yaml"), None]);
        let pins = Some(vec!["requirements.txt".to_string()]);
        let vendored = vec![package("pkg:pypi/requests@2.31.0", pins)];
        let found = unbuilt(&root.join("api"), vendored.clone()).await;
        assert_eq!(found[0].as_ref().map(|found| found.line), Some(15));
        // A directory is no lock, on every system.
        assert_eq!(
            lock_text(&root, "web/pnpm-lock.yaml").as_deref(),
            Some(PNPM_LOCK)
        );
        assert_eq!(lock_text(&root, "web"), None);

        // No package of a hub: the project is not even looked for.
        let found = unbuilt(&root.join("no/such/project"), packages[..1].to_vec()).await;
        assert_eq!(found, [None]);
        // No workspace file: every statement stays.
        std::fs::remove_file(root.join("MODULE.bazel")).unwrap();
        assert_eq!(
            unbuilt(&root.join("web"), packages).await,
            [None, None, None]
        );
        assert_eq!(unbuilt(&root.join("api"), vendored).await, [None]);
    }

    /// On disk a lock is read as a file of the workspace is: through a
    /// link that stays inside the Bazel root and not through one that
    /// leads out of it, not past its bound, and as the run left a file it
    /// has not committed yet.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_lock_is_read_inside_the_workspace_and_within_its_bound() {
        use crate::utils::fs::atomic_write_bytes;
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("repo");
        let write = |path: &str, text: &str| {
            let path = base.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("repo/.git/HEAD", "ref: refs/heads/main\n");
        for (path, text) in SHOP {
            write(&format!("repo/{path}"), text);
        }
        write("repo/locks/pnpm-lock.yaml", PNPM_LOCK);
        write("outside/pnpm-lock.yaml", PNPM_LOCK);
        let name = "web/pnpm-lock.yaml";
        let lock = root.join(name);
        let package = vec![Patched {
            purl: "pkg:npm/left-pad@1.3.0".to_string(),
            uuid: UUID.to_string(),
            pins: None,
        }];
        // The project as a caller names it, which need not be its real
        // path: the root that locks are held to is the real one.
        let project = tmp.path().join("repo/web");
        let withheld = || async { unbuilt(&project, package.clone()).await[0].is_some() };
        assert!(withheld().await);

        std::fs::remove_file(&lock).unwrap();
        symlink("../locks/pnpm-lock.yaml", &lock).unwrap();
        assert!(withheld().await, "a link inside the root");
        std::fs::remove_file(&lock).unwrap();
        symlink(base.join("outside/pnpm-lock.yaml"), &lock).unwrap();
        assert!(!withheld().await, "a link that leads out of the root");
        assert_eq!(lock_text(&root, name), None);
        std::fs::remove_file(&lock).unwrap();

        // One byte past the bound, a directory, and bytes that are no text.
        let large = std::fs::File::create(&lock).unwrap();
        large.set_len(MAX_LOCK + 1).unwrap();
        assert_eq!(lock_text(&root, name), None);
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();
        assert_eq!(lock_text(&root, name), None);
        std::fs::remove_dir(&lock).unwrap();
        std::fs::write(&lock, b"caf\xe9").unwrap();
        assert_eq!(lock_text(&root, name), None);
        std::fs::write(&lock, PNPM_LOCK).unwrap();
        assert_eq!(lock_text(&root, name).as_deref(), Some(PNPM_LOCK));

        // A run that has pinned the patch in the lock, before its commit.
        let run = crate::utils::group_commit::GroupCommit::begin(&root);
        let pinned = PNPM_LOCK.replace("sha512-BBBB", &format!("sha512-CCCC, tarball: {UUID}"));
        atomic_write_bytes(&lock, pinned.as_bytes()).await.unwrap();
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), PNPM_LOCK);
        assert!(!withheld().await, "the lock as the run left it");
        // Only a path of plain parts is asked of the run, as for every
        // file of the workspace: another spelling reads the disk.
        assert_eq!(lock_text(&root, name).as_deref(), Some(pinned.as_str()));
        let dotted = "./web/pnpm-lock.yaml";
        assert_eq!(lock_text(&root, dotted).as_deref(), Some(PNPM_LOCK));
        drop(run);
        assert!(withheld().await);
    }
}
