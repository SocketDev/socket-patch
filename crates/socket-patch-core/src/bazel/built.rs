//! Whether the Bazel build of a workspace takes the copy of a package that
//! socket-patch patched.
//!
//! Five rulesets hand the packages of an ecosystem to Bazel through one
//! tag of a module extension, a hub: aspect_rules_js reads a pnpm lock
//! (`npm.npm_translate_lock`), rules_python reads requirements files
//! (`pip.parse`), rules_ruby reads a Gemfile and its lock
//! (`ruby.bundle_fetch`), rules_rust reads a `Cargo.lock`
//! (`crate.from_cargo`) and rules_csharp reads a `packages.lock.json`
//! (`nuget.from_lock`). Each fetches what those files name into
//! repositories of Bazel's own and builds from there. None of them reads
//! what a package manager installed (`node_modules`, a virtualenv, a gem
//! home, a cargo home, NuGet's packages folder), so a patch that is only
//! in such a copy is not in the build. And rules_python builds no package
//! from a line that points at a copy committed under `.socket/vendor`:
//! 2.5.0-rc4 takes the path for the name of a project and fails the build
//! of everything the hub serves (Bazel 9.3.2, 8.8.2 and 7.7.2). rules_js
//! does build a vendored tarball, and rules_rust a vendored crate.
//! rules_ruby 1.0.0-rc2 fails the build on a vendored gem (same three
//! releases) unless the call lists every file of the copy among its
//! `srcs`, which it copies beside the Gemfile: `srcs` is not read here, so
//! a vendored gem is not judged. rules_csharp builds a vendored package
//! through the block that vendored mode keeps in `MODULE.bazel`
//! ([`super::nuget`]), which is not read here either.
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
//! build keeps what socket-patch says of it. A `packages.lock.json` below
//! the project's directory is the project's own as well ([`Hub::nested`]).
//!
//! Only a call that is a statement of its own counts ([`Call::whole`]):
//! it runs, once. One in a comprehension, behind an `and`, in a
//! conditional or in the arguments of another call may never run, and is
//! passed over. So is a call that passes `*` or `**`, whose arguments are
//! not all written out, and one that can take its packages from a file
//! that is not read here ([`Hub::elsewhere`]). A `crate.from_cargo` without
//! `cargo_lockfile` names no lock, so nothing is said: rules_rust 0.75.0
//! has its cargo resolve the manifests anew, and no file says which
//! versions it builds.
//!
//! A lock is read like a file of the workspace ([`disk`]): never through a
//! link that leads out of the Bazel root, although Bazel follows such a
//! link. It is read only when it lies where the project's own lock can
//! lie, once however many calls name it, and up to 64 MiB; its text is
//! searched once for the patches of all the packages, and not kept. Of a
//! pnpm lock the project documents are read, for their keys alone:
//! rules_js links nothing of the document pnpm 11 keeps for its own
//! configuration. Of a `Cargo.lock` the packages of a registry are read:
//! the hub has Bazel download the crate file of each, and takes no other
//! from a cargo home. A `packages.lock.json` never names a patch (a pin
//! there is a hash, and its source is in `nuget.config`), and rules_csharp
//! makes one hub of all its `nuget.from_lock` calls: the sources of the
//! last call that has any serve every package, and the first lock that
//! names a package pins it. So the config of every such call is searched
//! with the lock ([`Hub::beside`]), and nothing is said of the hub when
//! one of them is not a plain label of the main repository or a call
//! passes `*` or `**`. The locks are still read one call at a time, and `feeds` and
//! `local_package_dirs` are not read. Whether a hub takes a hosted pin of
//! the project itself is not judged here: [`super::cargo`] and
//! [`super::nuget`] say that to hosted mode, and the caller hands over no
//! package that has one.
//!
//! [`reader`] answers the question vendored mode asks before it writes:
//! does a call of the hub name a file that the run would make point at a
//! copy under `.socket/vendor`? Where [`unbuilt`] says nothing when it is
//! in doubt, this one says so, because there a wrong "no" breaks a build.
//! Every call of the hub counts, also one that may not run, and so does a
//! call of a `WORKSPACE` file that passes one of the hub's files, which is
//! how the older form of the ruleset is called there (`pip_parse`,
//! `rb_bundle_fetch`). A `WORKSPACE` file counts unless the checkout names
//! a Bazel release of 9 or later, which never reads one
//! ([`workspace_as_built`]): there it holds no call and is no doubt,
//! whatever it says. And where something of the workspace cannot be read
//! with certainty and a call of the hub may be behind it, the answer is
//! that doubt: the workspace calls the hub, or a file that was read names
//! its ruleset, or the root module file or the `WORKSPACE` file could not
//! be read at all. A file with one byte that is not UTF-8 is such a file,
//! and Bazel builds it.
//!
//! Not looked at: what a `--override_repository` or an rc file changes,
//! BUILD files, the `.bzl` files a `WORKSPACE` file loads, and hubs of
//! other rulesets.
//!
//! [`Tags::doubts`]: super::workspace::Tags::doubts

use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Component, Path};

use aho_corasick::AhoCorasick;

use super::rc::reads_workspace_file;
use super::starlark::{Call, File, Value};
use super::workspace::{disk, Doubt, Entry, Extension, Repo, Tag, Workspace};
use super::BazelRoot;
use crate::formats::cargo::CargoLock;
use crate::formats::gem::locked_specs;
use crate::formats::nuget::lock::{nuget_lock_entries, parse_lock};
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
    /// What to run so that the build holds the patch of an installed copy
    /// ([`Hub::remedy`]).
    pub remedy: &'static str,
}

/// The tag of a module extension that names the files a ruleset builds the
/// packages of an ecosystem from.
struct Hub {
    /// The type of the ecosystem's purls.
    ecosystem: &'static str,
    /// The extension, by each file of the ruleset that defines it.
    extensions: &'static [Extension<'static>],
    tag: &'static str,
    /// The attributes that name such a file: a label, or a dict with a
    /// label as each key. `uv_lock` is one for [`reader`] alone: [`judge`]
    /// passes over a call that has it.
    files: &'static [&'static str],
    /// The attributes with which a call can take its packages from a file
    /// that is not read here, whatever its lock lists.
    elsewhere: &'static [&'static str],
    /// The packages a file lists plainly, each as its name and version.
    lists: fn(&str) -> Vec<(String, String)>,
    /// The directories below a file's own whose lock the file is as well,
    /// each from that directory: the members of a pnpm workspace.
    members: fn(&str) -> Vec<String>,
    /// Whether a lock below the project's directory is the project's own
    /// as well. A NuGet project is every project file below the directory
    /// of a run, each with a lock beside it: agent mode patches what any of
    /// them restored, and hosted mode pins in each of their locks.
    nested: bool,
    /// Whether a call of the tag may build a package from a line that
    /// points at a copy under `.socket/vendor`: rules_js and rules_rust
    /// do, rules_ruby does when the call lists the files of the copy, and
    /// rules_csharp does through the block of vendored mode.
    builds_vendored: bool,
    /// The attributes that name a file beside the lock, where a pin in
    /// the lock does not name its patch. The calls of such a tag make one
    /// hub, so the file of every call is searched with a lock for the id
    /// of a patch.
    beside: &'static [&'static str],
    /// What to run so that the build holds a patch that is only in the
    /// installed copy: the modes that a test builds patched on real Bazel
    /// under this hub, with what hosted mode needs of the call.
    remedy: &'static str,
}

/// Hosted mode, which pins a patch in the lock the hub reads.
const HOSTED: &str = "Run `socket-patch scan --mode hosted` in the directory of that lock to pin \
    the patch there.";

const HUBS: [Hub; 5] = [
    Hub {
        ecosystem: "npm",
        extensions: &[Extension {
            module: "aspect_rules_js",
            file: "//npm:extensions.bzl",
            name: "npm",
        }],
        tag: "npm_translate_lock",
        files: &["pnpm_lock"],
        elsewhere: &[],
        lists: |text| {
            let project = documents(text).into_iter();
            let project = project.filter(|(_, kind)| *kind == PnpmDocument::Project);
            let locks = project.map(|(span, _)| PnpmLock::parse_keys(&text[span]));
            let locks: Vec<_> = locks.collect();
            let keys = locks.iter().flat_map(|lock| lock.packages());
            owned(keys.filter_map(|package| pnpm_registry_key(package.key)))
        },
        members: lock_text_member_importers,
        nested: false,
        builds_vendored: true,
        beside: &[],
        remedy: HOSTED,
    },
    Hub {
        ecosystem: "pypi",
        extensions: &[Extension {
            module: "rules_python",
            file: "//python/extensions:pip.bzl",
            name: "pip",
        }],
        tag: "parse",
        files: &[
            "requirements_lock",
            "requirements_by_platform",
            "requirements_darwin",
            "requirements_linux",
            "requirements_windows",
            "uv_lock",
        ],
        // rules_python 2.2.0 and later.
        elsewhere: &["uv_lock"],
        lists: |text| {
            let lines = logical_lines(text);
            owned(
                lines
                    .iter()
                    .filter_map(|line| exact_pin(strip_comment(&line.text))),
            )
        },
        members: |_| Vec::new(),
        nested: false,
        builds_vendored: false,
        beside: &[],
        remedy: HOSTED,
    },
    Hub {
        ecosystem: "gem",
        extensions: &[Extension {
            module: "rules_ruby",
            file: "//ruby:extensions.bzl",
            name: "ruby",
        }],
        tag: "bundle_fetch",
        files: &["gemfile_lock", "gemfile"],
        elsewhere: &[],
        lists: |text| owned(locked_specs(text).into_iter()),
        members: |_| Vec::new(),
        nested: false,
        builds_vendored: true,
        beside: &[],
        remedy: HOSTED,
    },
    Hub {
        ecosystem: "cargo",
        extensions: &super::cargo::EXTENSIONS,
        tag: "from_cargo",
        files: &["cargo_lockfile"],
        // The lock of rules_rust's own tool, which a hub renders its crates
        // from until a repin, and which is not held to the `Cargo.lock`
        // (0.75.0).
        elsewhere: &["lockfile"],
        lists: |text| {
            let lock = CargoLock::parse(text).ok();
            let packages = lock.iter().flat_map(|lock| lock.packages());
            let fetched = packages.filter(|package| package.is_from_registry());
            let built = fetched.filter(|package| package.replace.is_none());
            owned(built.map(|package| (package.name.as_str(), package.version.as_str())))
        },
        members: |_| Vec::new(),
        nested: false,
        builds_vendored: true,
        beside: &[],
        remedy: "Run `socket-patch scan --mode hosted` in the directory of that lock to pin \
            the patch there (the call has to name the project's cargo config, \
            `cargo_config`), or `socket-patch scan --mode vendored` to commit a patched copy \
            of the crate.",
    },
    Hub {
        ecosystem: "nuget",
        extensions: &[super::nuget::EXTENSION],
        tag: "from_lock",
        files: &["packages_lock_json"],
        elsewhere: &[],
        lists: |text| {
            let lock = parse_lock(text).ok();
            let entries = lock.iter().flat_map(nuget_lock_entries);
            owned(entries.map(|entry| (entry.id, entry.resolved)))
        },
        members: |_| Vec::new(),
        nested: true,
        builds_vendored: true,
        beside: &["nuget_config"],
        remedy: "Run `socket-patch scan --mode hosted` in the directory of that lock to pin \
            the patch there (the call has to name the project's nuget.config, \
            `nuget_config`).",
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
        judge(&workspace, &slashed(&root.project), &read, &packages)
    })
    .await
}

/// `path` with `/` between its parts, as Bazel has it on every system.
fn slashed(path: &Path) -> String {
    let parts = path.components();
    let parts: Vec<_> = parts
        .map(|part| part.as_os_str().to_string_lossy())
        .collect();
    parts.join("/")
}

/// What stands between vendored mode and the locks of a project
/// ([`reader`]). `Ok`: this call of the hub names one of them, `lock`.
/// `Err`: this is why the files of the workspace are not read with
/// certainty, where a call of the hub that names such a lock may be behind
/// that.
pub type Reader = Result<Unbuilt, Doubt>;

/// The call of the workspace `root` that hands Bazel one of `locks`: files
/// of the project in that workspace, each by its path from the project,
/// which vendored mode would rewrite for a package of `ecosystem` (the type
/// of its purls), or the doubt that leaves that open. A requirements file
/// that a call names hands Bazel each file its `-r` includes reach as
/// well, and is then the file returned. `None` when the
/// calls of the hub are read with certainty and name other files, and when
/// nothing shows that the workspace may call it: no call of the hub and no
/// file that names its ruleset, with a root module file and a `WORKSPACE`
/// file that were read or are not there. A `WORKSPACE` file that the Bazel
/// of the checkout does not read is not there ([`workspace_as_built`]).
pub async fn reader(
    root: &BazelRoot,
    ecosystem: &'static str,
    locks: Vec<String>,
) -> Option<Reader> {
    let (dir, project) = (root.dir.clone(), slashed(&root.project));
    run_blocking(move || {
        let read = |file: &str| lock_text(&dir, file);
        let workspace = workspace_as_built(&disk(&dir));
        reads(&workspace, &project, ecosystem, &locks, &read)
    })
    .await
}

/// The workspace of `view` as the Bazel that the checkout names reads it:
/// without its `WORKSPACE` file ([`Workspace::legacy`]) where that Bazel
/// reads none, which is a release of 9 or later
/// ([`reads_workspace_file`]). A checkout that names an older release, or
/// none as three numbers, keeps the file: a Bazel 7 or 8 may build it.
///
/// For a question whose wrong "yes" costs a run that worked: a
/// `WORKSPACE` file that a migration left behind can still name a lock,
/// and stands in no build's way.
pub(crate) fn workspace_as_built(view: &dyn Fn(&str) -> Entry) -> Workspace {
    let mut workspace = Workspace::read(view);
    if !reads_workspace_file(view) {
        workspace.legacy = None;
    }
    workspace
}

/// The path from the Bazel root `root` of `file`, a path from its project.
pub(crate) fn from_root(root: &BazelRoot, file: &str) -> String {
    below(&slashed(&root.project), file)
}

/// [`reader`] for the workspace `workspace` and the project in its
/// directory `project` (empty: the root itself), with `read` for the text
/// of a file of the workspace.
fn reads(
    workspace: &Workspace,
    project: &str,
    ecosystem: &str,
    locks: &[String],
    read: &dyn Fn(&str) -> Option<String>,
) -> Option<Reader> {
    let hub = HUBS.iter().find(|hub| hub.ecosystem == ecosystem)?;
    let tags = |extension| workspace.tags(extension, hub.tag);
    let tags: Vec<_> = hub.extensions.iter().map(tags).collect();
    let tag = format!("{}.{}", hub.extensions[0].name, hub.tag);
    let tagged = tags.iter().flat_map(|tags| &tags.calls);
    let tagged = tagged.map(|at| (at.file, at.call, tag.as_str()));
    // In a `WORKSPACE` file, the calls that pass one of the hub's files.
    let legacy = workspace
        .legacy
        .as_ref()
        .and_then(|read| read.as_ref().ok());
    let passes = |call: &&Call| hub.files.iter().any(|file| call.arg(file).is_some());
    let legacy = legacy.into_iter().flat_map(|(name, file)| {
        // `workspace(name = "shop")` makes `@shop//` the main repository
        // for the labels of that file.
        let main = file.calls.iter().find_map(workspace_name);
        let calls = file.calls.iter().filter(passes);
        calls.map(move |call| (name.as_str(), call, call.callee.as_str(), main))
    });
    let tagged = tagged.map(|(file, call, name)| (file, call, name, None));
    let mut doubt = tags.iter().find_map(|tags| tags.doubts.first()).cloned();
    let mut called = doubt.is_some();
    for (file, call, name, main) in tagged.chain(legacy) {
        called = true;
        let own = |lock: &String| locks.iter().any(|own| below(project, own) == *lock);
        let named = files(workspace, call, hub.files, main);
        // A requirements file that brings one of the locks in with `-r`
        // hands the hub that lock as well.
        let includes = |lock: &&String| ecosystem == "pypi" && includes_one(lock, &own, read);
        let found = named.iter().find(|lock| own(lock));
        if let Some(lock) = found.or_else(|| named.iter().find(includes)) {
            return Some(Ok(Unbuilt {
                call: name.to_string(),
                file: file.to_string(),
                line: call.line,
                lock: lock.clone(),
                remedy: hub.remedy,
            }));
        }
        let written = |file: &&str| {
            let value = call.arg(file);
            matches!(value, None | Some(Value::Str(_) | Value::Dict(_)))
        };
        if doubt.is_none() && (call.unpacks() || !hub.files.iter().all(written)) {
            doubt = Some(Doubt {
                file: file.to_string(),
                line: call.line,
                why: format!("the files `{name}` names are not all written out"),
            });
        }
    }
    // What could not be read of the workspace may hide a call of the hub
    // where the hub is seen to be called, where a file that was read names
    // its ruleset (as a dependency, or by the file of its extension under
    // any name of the repository), and where the root module file was not
    // read at all. So may a `WORKSPACE` file that could not be read.
    let names = |call: &Call| match (call.callee.as_str(), call.arg("name"), call.positional(0)) {
        ("bazel_dep", Some(Value::Str(name)), _) => {
            let ruleset = |extension: &Extension| name == extension.module;
            hub.extensions.iter().any(ruleset)
        }
        ("use_extension", _, Some(Value::Str(file))) => {
            let defines = |extension: &Extension| file.ends_with(extension.file);
            hub.extensions.iter().any(defines)
        }
        _ => false,
    };
    let named = |(_, file): &(String, File)| file.calls.iter().any(names);
    let may = || called || workspace.files.is_empty() || workspace.files.iter().any(named);
    let hidden = || workspace.doubts.first().filter(|_| may());
    let unread = || workspace.legacy.as_ref()?.as_ref().err();
    doubt.or_else(|| hidden().or_else(unread).cloned()).map(Err)
}

/// Whether the requirements file `start` (a path from the Bazel root)
/// brings in a file for which `own` holds, through its `-r` includes and
/// theirs, each read with `read`. An include that cannot be read brings in
/// nothing that can be seen.
fn includes_one(
    start: &str,
    own: &dyn Fn(&String) -> bool,
    read: &dyn Fn(&str) -> Option<String>,
) -> bool {
    let mut seen = HashSet::new();
    let mut stack = vec![start.to_string()];
    while let Some(file) = stack.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let Some(text) = read(&file) else {
            continue;
        };
        for include in crate::vendor::pypi_requirements::requirements_includes(&file, &text) {
            if own(&include) {
                return true;
            }
            stack.push(include);
        }
    }
    false
}

/// The name a `workspace(name = ...)` call gives the main repository.
fn workspace_name(call: &Call) -> Option<&str> {
    match (call.callee.as_str(), call.arg("name")) {
        ("workspace", Some(Value::Str(name))) => Some(name.as_str()),
        _ => None,
    }
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
pub(crate) fn lock_text(root: &Path, file: &str) -> Option<String> {
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
        let tags = |extension| workspace.tags(extension, hub.tag);
        let tags: Vec<_> = hub.extensions.iter().map(tags).collect();
        if tags.iter().any(|tags| !tags.doubts.is_empty()) {
            continue;
        }
        let calls = || tags.iter().flat_map(|tags| &tags.calls);
        // The files beside the locks, of every call of the tag: the calls
        // with such a file make one hub (rules_csharp), where the file of
        // one call says where the packages of every lock come from. So
        // the file of any call may name the patch, and one that a call
        // does not give as a plain label of the main repository, or may
        // pass unseen, may name any.
        let plain = |value: &Value| match value {
            Value::Str(label) => file(workspace, label, None),
            _ => None,
        };
        let beside = |tag: &Tag| {
            let given = hub.beside.iter().filter_map(|name| tag.call.arg(name));
            given.map(plain).collect::<Option<Vec<String>>>()
        };
        let beside: Option<Vec<Vec<String>>> = calls().map(beside).collect();
        let unseen = !hub.beside.is_empty() && calls().any(|tag| tag.call.unpacks());
        let Some(beside) = beside.filter(|_| !unseen) else {
            continue;
        };
        // Their text, read when a lock first asks and once for the hub.
        let beside = beside.concat();
        let texts = || beside.iter().map(|file| read(file)).collect();
        let configs: OnceCell<Option<String>> = OnceCell::new();
        // What a file lists, and which patches of the packages its text
        // names, with the text of the files beside it: read when a package
        // first asks and once for all the calls that name it, and the
        // text is not kept. `None` for a file that is not the project's
        // lock, or when one of them cannot be read.
        let mut listed = HashMap::new();
        let named = |call: &Call| hub.elsewhere.iter().any(|name| call.arg(name).is_some());
        let elsewhere = |call: &Call| call.unpacks() || named(call);
        for tag in calls().filter(|tag| tag.call.whole && !elsewhere(tag.call)) {
            for lock in files(workspace, tag.call, hub.files, None) {
                for &at in &ours {
                    let package = &packages[at];
                    let unpatched = match &package.pins {
                        Some(pins) => {
                            !hub.builds_vendored
                                && pins.iter().any(|pin| below(project, pin) == lock)
                        }
                        None => {
                            let listed = listed.entry(lock.clone()).or_insert_with(|| {
                                let nested = hub.nested && inside(project, &lock);
                                let member = from_lock(project, &lock).or(nested.then_some(""))?;
                                let mut text = read(&lock)?;
                                let named = || (hub.members)(&text).iter().any(|m| m == member);
                                if !(member.is_empty() || named()) {
                                    return None;
                                }
                                let listed = (hub.lists)(&text).into_iter();
                                text.push_str(configs.get_or_init(texts).as_deref()?);
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
                            call: format!("{}.{}", hub.extensions[0].name, hub.tag),
                            file: tag.file.to_string(),
                            line: tag.call.line,
                            lock: lock.clone(),
                            remedy: hub.remedy,
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
/// out as a string, or as a dict with strings as keys, names none. `main`
/// is the name a `WORKSPACE` file gives the main repository, for a call of
/// that file: `@<main>//` is then the main repository too.
fn files(
    workspace: &Workspace,
    call: &Call,
    attributes: &[&str],
    main: Option<&str>,
) -> Vec<String> {
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
    let ours = labels
        .iter()
        .filter_map(|label| file(workspace, label, main));
    ours.collect()
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

/// The file of the main repository that `label` names, by its path from
/// the Bazel root. `main` is the name a `WORKSPACE` file gives the main
/// repository, for a label of that file: `@<main>//` is then the main
/// repository too.
fn file(workspace: &Workspace, label: &str, main: Option<&str>) -> Option<String> {
    let label = workspace.label(label)?;
    let ours = match &label.repo {
        Repo::Main => true,
        Repo::Apparent(repo) => main == Some(repo.as_str()),
        Repo::Canonical(_) => false,
    };
    ours.then(|| label.path())
}

/// Whether the workspace's file `lock` lies in a directory below the
/// directory `project`.
fn inside(project: &str, lock: &str) -> bool {
    let rest = lock.strip_prefix(project);
    rest.is_some_and(|rest| project.is_empty() || rest.starts_with('/'))
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
        // An ecosystem whose hub this workspace does not call, one without
        // a hub, and no purl at all.
        assert_eq!(installed("web", "pkg:cargo/serde@1.0.0"), "");
        assert_eq!(installed("web", "pkg:golang/example.com/m@v1.0.0"), "");
        assert_eq!(installed("web", "left-pad"), "");
    }

    /// A workspace with the hubs of rules_rust and rules_csharp, each over
    /// the lock of one directory.
    const CRATES: &str = r#"module(name = "shop", version = "0.0.0")

bazel_dep(name = "rules_rust", version = "0.75.0")
bazel_dep(name = "rules_csharp", version = "0.5.0")

crate = use_extension("@rules_rust//crate_universe:extensions.bzl", "crate")
crate.from_cargo(
    name = "crates",
    cargo_lockfile = "//engine:Cargo.lock",
    manifests = ["//engine:Cargo.toml"],
)
use_repo(crate, "crates")

nuget = use_extension("@rules_csharp//csharp:extensions.bzl", "nuget")
nuget.from_lock(
    nuget_config = "//desk:nuget.config",
    packages_lock_json = "//desk:packages.lock.json",
)
use_repo(nuget, "nuget")
"#;

    /// A registry crate, one of another registry, one from git, one from a
    /// path, and one that a `[replace]` swaps out.
    const CARGO_LOCK: &str = r#"version = 4

[[package]]
name = "engine"
version = "0.1.0"
dependencies = ["serde", "tokens", "fork", "local", "swapped"]

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[[package]]
name = "tokens"
version = "0.3.0"
source = "sparse+https://crates.example/index/"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[[package]]
name = "fork"
version = "2.0.0"
source = "git+https://git.example/fork#0123456789abcdef0123456789abcdef01234567"

[[package]]
name = "local"
version = "0.2.0"

[[package]]
name = "swapped"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
replace = "swapped 3.0.0"
"#;

    const NUGET_LOCK: &str = r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "AAAA"
      },
      "Shop.Core": { "type": "Project" }
    }
  }
}
"#;

    const NUGET_CONFIG: &str = "<configuration>\n  <packageSources>\n    <add key=\"nuget.org\" \
        value=\"https://api.nuget.org/v3/index.json\" />\n  </packageSources>\n</configuration>\n";

    const BUILT: [(&str, &str); 4] = [
        ("MODULE.bazel", CRATES),
        ("engine/Cargo.lock", CARGO_LOCK),
        ("desk/packages.lock.json", NUGET_LOCK),
        ("desk/nuget.config", NUGET_CONFIG),
    ];

    const CARGO: &str = "crate.from_cargo MODULE.bazel:7 engine/Cargo.lock";
    const NUGET: &str = "nuget.from_lock MODULE.bazel:15 desk/packages.lock.json";
    const SERDE: &str = "pkg:cargo/serde@1.0.200";
    const JSON: &str = "pkg:nuget/newtonsoft.json@13.0.3";

    /// [`BUILT`] with `text` in the place of the file `path`, and with
    /// `from` of that text replaced by `to`.
    fn built_with(path: &str, from: &str, to: &str) -> Vec<(&'static str, &'static str)> {
        let changed = |(name, text): (&'static str, &'static str)| match name == path {
            true => {
                assert!(text.contains(from), "{path}: no {from:?}");
                let text: &'static str = Box::leak(text.replace(from, to).into_boxed_str());
                (name, text)
            }
            false => (name, text),
        };
        BUILT.into_iter().map(changed).collect()
    }

    /// A crate in a cargo home and a package in NuGet's folder are not
    /// what `crate.from_cargo` and `nuget.from_lock` build: each has Bazel
    /// download what the lock of the project lists.
    #[test]
    fn an_installed_crate_or_nuget_package_is_not_what_a_hub_builds() {
        let installed = |project, purl| said(&BUILT, project, purl, None);
        // A crate of crates.io and one of another registry.
        assert_eq!(installed("engine", SERDE), CARGO);
        assert_eq!(installed("engine", "pkg:cargo/tokens@0.3.0"), CARGO);
        // The id as the lock spells it and as NuGet's folder does, and a
        // version with a fourth part.
        assert_eq!(installed("desk", JSON), NUGET);
        assert_eq!(
            installed("desk", "pkg:nuget/Newtonsoft.Json@13.0.3.0"),
            NUGET
        );
        // What the hub does not download: a crate from git, from a path or
        // behind a `[replace]`, the workspace's own, a project reference.
        for other in [
            "pkg:cargo/fork@2.0.0",
            "pkg:cargo/local@0.2.0",
            "pkg:cargo/swapped@3.0.0",
            "pkg:cargo/engine@0.1.0",
            "pkg:cargo/serde@1.0.199",
        ] {
            assert_eq!(installed("engine", other), "", "{other}");
        }
        assert_eq!(installed("desk", "pkg:nuget/shop.core@1.0.0"), "");
        assert_eq!(installed("desk", "pkg:nuget/newtonsoft.json@13.0.2"), "");
        // The lock of another project: beside it, above it, below it.
        for (project, purl) in [("desk", SERDE), ("", SERDE), ("engine/cli", SERDE)] {
            assert_eq!(installed(project, purl), "", "{project:?}");
        }
        for project in ["engine", "desk/tests", "des"] {
            assert_eq!(installed(project, JSON), "", "{project:?}");
        }
        // But a NuGet project is every project file below the directory of
        // the run, each with its lock: the lock of `desk` is the root's.
        assert_eq!(installed("", JSON), NUGET);
        assert!(inside("shop", "shop/desk/packages.lock.json"));
        assert!(!inside("shop/desk/tests", "shop/desk/packages.lock.json"));
        // A copy committed under `.socket/vendor` is not judged.
        let pins = ["Cargo.toml", "Cargo.lock"];
        assert_eq!(said(&BUILT, "engine", SERDE, Some(&pins)), "");
        let pins = ["nuget.config", "packages.lock.json"];
        assert_eq!(said(&BUILT, "desk", JSON, Some(&pins)), "");
    }

    /// What to run is the hub's: hosted mode under every hub, with what it
    /// needs of a `crate.from_cargo` and a `nuget.from_lock`, and vendored
    /// mode for a crate, which alone of the two is built from a committed
    /// copy.
    #[test]
    fn a_hub_names_the_modes_that_patch_what_it_builds() {
        let remedy = |files: &[(&str, &str)], project: &str, purl: &str| {
            let text = |path: &str| files.iter().find(|(name, _)| *name == path);
            let workspace = Workspace::read(&|path| match text(path) {
                Some((_, text)) => Entry::Text(text.to_string()),
                None => Entry::Absent,
            });
            let package = Patched {
                purl: purl.to_string(),
                uuid: UUID.to_string(),
                pins: None,
            };
            let read = |path: &str| text(path).map(|(_, text)| text.to_string());
            let found = judge(&workspace, project, &read, &[package]).remove(0);
            found.expect("a call that builds the package").remedy
        };
        assert_eq!(remedy(&SHOP, "web", "pkg:npm/left-pad@1.3.0"), HOSTED);
        assert_eq!(remedy(&SHOP, "api", "pkg:pypi/flask-cors@4.0.0"), HOSTED);
        assert_eq!(remedy(&SHOP, "billing", "pkg:gem/rack@2.2.8"), HOSTED);
        let pins = HOSTED.trim_end_matches('.');
        let cargo = remedy(&BUILT, "engine", SERDE);
        let vendored = "), or `socket-patch scan --mode vendored` to commit";
        let names = cargo.contains("`cargo_config`") && cargo.contains(vendored);
        assert!(cargo.starts_with(pins) && names, "{cargo}");
        let nuget = remedy(&BUILT, "desk", JSON);
        let names = nuget.contains("`nuget_config`") && !nuget.contains("vendored");
        assert!(nuget.starts_with(pins) && names, "{nuget}");
    }

    /// A call that names more than the lock: nothing is said where its
    /// packages can come from a file that is not read, or where a file
    /// beside the lock names the patch or cannot be read.
    #[test]
    fn a_crate_or_nuget_call_that_may_build_something_else_withholds_nothing() {
        let lock = "    cargo_lockfile = \"//engine:Cargo.lock\",\n";
        let cargo = |argument: &str| {
            let files = built_with("MODULE.bazel", lock, &format!("{lock}    {argument},\n"));
            said(&files, "engine", SERDE, None)
        };
        assert_eq!(
            cargo("cargo_config = \"//engine:.cargo/config.toml\""),
            CARGO
        );
        // The lock of rules_rust's own tool, and arguments not written out.
        assert_eq!(cargo("lockfile = \"//engine:cargo-bazel-lock.json\""), "");
        assert_eq!(cargo("**COMMON"), "");
        // `manifests` alone names no lock.
        let files = built_with("MODULE.bazel", lock, "");
        assert_eq!(said(&files, "engine", SERDE, None), "");
        // The extension by the older name of its file is the same one.
        let files = built_with(
            "MODULE.bazel",
            "universe:extensions.bzl",
            "universe:extension.bzl",
        );
        assert_eq!(said(&files, "engine", SERDE, None), CARGO);
        // A lock that names the patch: the registry of a hosted pin.
        let source = "registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aaaa";
        let pinned = format!("sparse+https://patch.example/{UUID}/index/\"\nchecksum = \"cccc");
        let files = built_with("engine/Cargo.lock", source, &pinned);
        assert_eq!(said(&files, "engine", SERDE, None), "");

        let config = "    nuget_config = \"//desk:nuget.config\",\n";
        let nuget = |files: &[(&str, &str)]| said(files, "desk", JSON, None);
        assert_eq!(nuget(&BUILT), NUGET);
        // No config: the hub asks nuget.org alone.
        assert_eq!(nuget(&built_with("MODULE.bazel", config, "")), NUGET);
        // The config names the patch: the source of a hosted pin, whose
        // hash the lock holds without a word of it.
        let org = "<add key=\"nuget.org\"";
        let source =
            format!("<add key=\"socket-patch-{UUID}\" value=\"https://h/x\" />\n    {org}");
        let files = built_with("desk/nuget.config", org, &source);
        assert_eq!(nuget(&files), "");
        // The config is not named plainly, or is not there.
        let computed = "    nuget_config = CONFIG,\n";
        assert_eq!(nuget(&built_with("MODULE.bazel", config, computed)), "");
        assert_eq!(nuget(&BUILT[..3]), "");

        // rules_csharp makes one hub of every call: the config of the call
        // for another project's lock may be the one this project's package
        // comes through. Nothing is said when it names the patch, is not
        // named plainly, or may be passed unseen.
        let hosted: &'static str = Box::leak(NUGET_CONFIG.replace(org, &source).into_boxed_str());
        let beside = |call: &str| {
            let hub = "use_repo(nuget, \"nuget\")\n";
            let call = format!("nuget.from_lock({call})\n{hub}");
            let mut files = built_with("MODULE.bazel", hub, &call);
            let till = [
                ("till/packages.lock.json", NUGET_LOCK),
                ("till/nuget.config", hosted),
            ];
            files.extend(till);
            nuget(&files)
        };
        let lock = "packages_lock_json = \"//till:packages.lock.json\"";
        assert_eq!(beside(lock), NUGET);
        let upstream = format!("{lock}, nuget_config = \"//desk:nuget.config\"");
        assert_eq!(beside(&upstream), NUGET);
        for other in [
            "nuget_config = \"//till:nuget.config\"",
            "nuget_config = \"//till:missing.config\"",
            "nuget_config = CONFIG",
            "nuget_config = {\"//desk:nuget.config\": \"desk\"}",
            "**TILL",
        ] {
            assert_eq!(beside(&format!("{lock}, {other}")), "", "{other}");
        }

        // A proxy that is handed on: a doubt on that hub alone, by either
        // file of its extension.
        let files = built_with("MODULE.bazel", CRATES, &format!("{CRATES}print(crate)\n"));
        assert_eq!(said(&files, "engine", SERDE, None), "");
        assert_eq!(said(&files, "desk", JSON, None), NUGET);
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
                said(&files, "tools", "pkg:pypi/idna@3.6", None),
            ]
        };
        let judged = "pip.parse MODULE.bazel:15 api/requirements.txt".to_string();
        // The other call of the hub is judged whatever this one passes.
        let other = "pip.parse MODULE.bazel:21 tools/requirements_linux.txt".to_string();
        let both = [judged.clone(), judged, other.clone()];
        assert_eq!(pypi("quiet = False"), both);
        for elsewhere in ["uv_lock = \"//api:uv.lock\"", "**COMMON", "*LOCKS"] {
            let passed_over = [String::new(), String::new(), other.clone()];
            assert_eq!(pypi(elsewhere), passed_over, "{elsewhere}");
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

    /// What [`reads`] says of the locks `locks` of the project in
    /// `project`, in the workspace of `files`: `call file:line lock`, or
    /// `? file:line why` for a doubt. A file whose text starts with
    /// [`UNREADABLE`] is one that cannot be read, for the reason after it.
    fn reader_of(files: &[(&str, &str)], project: &str, ecosystem: &str, locks: &[&str]) -> String {
        let text = |path: &str| files.iter().find(|(name, _)| *name == path);
        let workspace = workspace_as_built(&|path| match text(path) {
            Some((_, text)) => match text.strip_prefix(UNREADABLE) {
                Some(why) => Entry::Unreadable(why.to_string()),
                None => Entry::Text(text.to_string()),
            },
            None => Entry::Absent,
        });
        let locks: Vec<String> = locks.iter().map(|lock| lock.to_string()).collect();
        let read = |path: &str| text(path).map(|(_, text)| text.to_string());
        match reads(&workspace, project, ecosystem, &locks, &read) {
            Some(Ok(by)) => format!("{} {}:{} {}", by.call, by.file, by.line, by.lock),
            Some(Err(doubt)) => format!("? {}:{} {}", doubt.file, doubt.line, doubt.why),
            None => String::new(),
        }
    }

    /// The shop with `new` in the place of `old` in its root module.
    fn shop_with(old: &str, new: &str) -> Vec<(&'static str, &'static str)> {
        let root = ROOT.replace(old, new);
        assert_ne!(root, ROOT, "{old}");
        with("MODULE.bazel", Box::leak(root.into_boxed_str()))
    }

    const UNREADABLE: &str = "unreadable: ";
    const PIP: &str = "    requirements_lock = \"//api:requirements.txt\",\n";
    const UNWRITTEN: &str = "the files `pip.parse` names are not all written out";

    /// A call of the hub that names a file vendored mode would rewrite is
    /// found, under each attribute, and a project whose files no call
    /// names has none.
    #[test]
    fn the_call_that_reads_a_lock_of_the_project_is_found() {
        let pypi = |project, locks: &[&str]| reader_of(&SHOP, project, "pypi", locks);
        let api = "pip.parse MODULE.bazel:15 api/requirements.txt";
        assert_eq!(pypi("api", &["requirements.txt"]), api);
        assert_eq!(pypi("api", &["base.txt", "./requirements.txt"]), api);
        let darwin = "pip.parse MODULE.bazel:20 tools/requirements_darwin.txt";
        assert_eq!(
            pypi("tools", &["uv.lock", "requirements_darwin.txt"]),
            darwin
        );
        let gem = |project, locks: &[&str]| reader_of(&SHOP, project, "gem", locks);
        let lock = "ruby.bundle_fetch billing/ruby.MODULE.bazel:2 billing/Gemfile.lock";
        assert_eq!(gem("billing", &["Gemfile", "Gemfile.lock"]), lock);
        let gemfile = "ruby.bundle_fetch billing/ruby.MODULE.bazel:2 billing/Gemfile";
        assert_eq!(gem("billing", &["Gemfile"]), gemfile);
        // A call that may not run counts, and so does a `uv_lock`.
        let looped = "[pip.parse(requirements_lock = \"//api:requirements.txt\") for v in V]\n";
        let files = shop_with(
            "pip.parse(\n    hub_name = \"pypi\",",
            &format!("{looped}pip.parse("),
        );
        let looped = "pip.parse MODULE.bazel:15 api/requirements.txt";
        assert_eq!(
            reader_of(&files, "api", "pypi", &["requirements.txt"]),
            looped
        );
        let files = shop_with(PIP, "    uv_lock = \"//api:uv.lock\",\n");
        let uv = "pip.parse MODULE.bazel:15 api/uv.lock";
        assert_eq!(reader_of(&files, "api", "pypi", &["uv.lock"]), uv);

        // Other files of the project, another project, a file of another
        // repository, another ecosystem, and one without a hub.
        assert_eq!(pypi("api", &["requirements-dev.txt", "uv.lock"]), "");
        assert_eq!(pypi("mobile", &["requirements.txt"]), "");
        assert_eq!(pypi("", &["requirements.txt"]), "");
        assert_eq!(pypi("api/worker", &["requirements.txt"]), "");
        let files = shop_with(
            "\"//api:requirements.txt\"",
            "\"@other//api:requirements.txt\"",
        );
        assert_eq!(reader_of(&files, "api", "pypi", &["requirements.txt"]), "");
        assert_eq!(gem("api", &["requirements.txt"]), "");
        assert_eq!(reader_of(&SHOP, "api", "cargo", &["requirements.txt"]), "");
    }

    /// A requirements file a call names that brings a lock of the project
    /// in with `-r`, directly or through another include, hands the hub
    /// that lock: the call is found, with the file it names. An include
    /// that reaches no lock of the project, or a Gemfile, is not.
    #[test]
    fn a_hub_file_that_includes_a_lock_of_the_project_is_found() {
        let parent = "api/requirements.txt";
        let mut files = with(parent, "-r requirements/all.txt\n");
        files.push(("api/requirements/all.txt", "-r ../base.txt\n-r dev.txt\n"));
        files.push(("api/requirements/dev.txt", "-r all.txt\n"));
        let api = "pip.parse MODULE.bazel:15 api/requirements.txt";
        assert_eq!(reader_of(&files, "api", "pypi", &["base.txt"]), api);
        let all = ["requirements/all.txt"];
        assert_eq!(reader_of(&files, "api", "pypi", &all), api);
        assert_eq!(reader_of(&files, "api", "pypi", &["other.txt"]), "");
        let mut files = with("billing/Gemfile.lock", "-r Gemfile.other\n");
        files.push(("billing/Gemfile", "-r Gemfile.other\n"));
        assert_eq!(reader_of(&files, "billing", "gem", &["Gemfile.other"]), "");
    }

    /// Where the workspace calls the hub and what a call names cannot be
    /// read, the answer is the doubt, for every project. A doubt of a
    /// workspace that does not call the hub is none.
    #[test]
    fn a_hub_that_is_not_read_with_certainty_is_a_doubt() {
        let pypi = |files: &[(&str, &str)], project| {
            reader_of(files, project, "pypi", &["requirements.txt"])
        };
        let unwritten = format!("? MODULE.bazel:15 {UNWRITTEN}");
        for argument in ["    requirements_lock = LOCK,\n", "    **COMMON\n"] {
            let files = shop_with(PIP, argument);
            assert_eq!(pypi(&files, "api"), unwritten, "{argument}");
            assert_eq!(pypi(&files, "mobile"), unwritten, "{argument}");
            // A call that names a lock of the project is the answer all
            // the same.
            let darwin = "pip.parse MODULE.bazel:20 tools/requirements_darwin.txt";
            let named = reader_of(&files, "tools", "pypi", &["requirements_darwin.txt"]);
            assert_eq!(named, darwin, "{argument}");
        }
        // The proxy is handed on: other calls of the hub may be made.
        let handed = with(
            "MODULE.bazel",
            Box::leak(format!("{ROOT}print(pip)\n").into_boxed_str()),
        );
        let said = "? MODULE.bazel:31 `pip` is used other than to call a tag";
        assert_eq!(pypi(&handed, "mobile"), said);
        assert_eq!(
            pypi(&handed, "api"),
            "pip.parse MODULE.bazel:15 api/requirements.txt"
        );
        assert_eq!(reader_of(&handed, "mobile", "gem", &["Gemfile"]), "");

        // A file of the workspace is missing: it may hold a call of the
        // Python hub, which is called, and one of the Ruby hub, which is
        // not seen while the root names its ruleset.
        let missing: Vec<_> = SHOP
            .into_iter()
            .filter(|(name, _)| !name.ends_with("ruby.MODULE.bazel"))
            .collect();
        let hidden = "? billing/ruby.MODULE.bazel:0 it does not exist; MODULE.bazel:30 includes it";
        assert_eq!(pypi(&missing, "mobile"), hidden);
        let gem = reader_of(&missing, "billing", "gem", &["Gemfile", "Gemfile.lock"]);
        assert_eq!(gem, hidden);
    }

    /// A file that cannot be read may hold a call of a hub that no file
    /// shows. Bazel builds one with a byte that is not UTF-8, so the answer
    /// is a doubt where the root module file or the `WORKSPACE` file is
    /// such a file, and where another is while a file that was read names
    /// the ruleset. A doubt of a workspace that names neither ruleset is
    /// none.
    #[test]
    fn a_file_that_cannot_be_read_may_hold_a_call_of_the_hub() {
        let asked = |files: &[(&str, &str)], ecosystem| {
            reader_of(files, "svc", ecosystem, &["requirements.txt", "Gemfile"])
        };
        let unread = "unreadable: it is not UTF-8";
        let why = "it cannot be read: it is not UTF-8";
        let root = [("MODULE.bazel", unread)];
        for ecosystem in ["pypi", "gem"] {
            assert_eq!(asked(&root, ecosystem), format!("? MODULE.bazel:0 {why}"));
        }
        // An included file, under a root that names the Python ruleset: as
        // a dependency, or by the file of its extension under a name that
        // the unread file gives the repository.
        let include = "include(\"//py:deps.MODULE.bazel\")\n";
        let said = format!("? py/deps.MODULE.bazel:0 {why}; MODULE.bazel:2 includes it");
        for names in [
            "bazel_dep(name = \"rules_python\", version = \"2.5.0-rc4\")\n",
            "pip = use_extension(\"@py//python/extensions:pip.bzl\", \"pip\")\n",
        ] {
            let root = format!("{names}{include}");
            let files = [
                ("MODULE.bazel", root.as_str()),
                ("py/deps.MODULE.bazel", unread),
            ];
            assert_eq!(asked(&files, "pypi"), said, "{names}");
            assert_eq!(asked(&files, "gem"), "", "{names}");
        }
        let neither = "bazel_dep(name = \"rules_go\", version = \"0.65.0\")\n";
        let root = format!("{neither}{include}");
        let files = [
            ("MODULE.bazel", root.as_str()),
            ("py/deps.MODULE.bazel", unread),
        ];
        assert_eq!(
            (asked(&files, "pypi"), asked(&files, "gem")),
            Default::default()
        );
        // The `WORKSPACE` file, beside a `MODULE.bazel` that is read or
        // alone.
        let module = ("MODULE.bazel", "module(name = \"shop\")\n");
        for files in [
            vec![module, ("WORKSPACE.bazel", unread)],
            vec![("WORKSPACE", unread)],
        ] {
            let said = format!("? {}:0 {why}", files.last().unwrap().0);
            for ecosystem in ["pypi", "gem"] {
                assert_eq!(asked(&files, ecosystem), said);
            }
        }
    }

    /// A call of a `WORKSPACE` file that passes one of the hub's files is
    /// a call of the ruleset's older form, with or without a `MODULE.bazel`.
    #[test]
    fn a_workspace_file_that_names_the_lock_counts() {
        let legacy = "load(\"@rules_python//python:pip.bzl\", \"pip_parse\")\n\
            pip_parse(\n    name = \"pypi\",\n    requirements_lock = \"//svc:requirements.txt\",\n)\n\
            rb_bundle_fetch(name = \"bundle\", gemfile = \"//svc:Gemfile\", gemfile_lock = LOCK)\n\
            http_archive(name = \"x\", requirements = \"//other:requirements.txt\")\n";
        for files in [with("WORKSPACE", legacy), vec![("WORKSPACE.bazel", legacy)]] {
            let name = files.last().unwrap().0;
            let asked =
                |project, ecosystem, locks: &[&str]| reader_of(&files, project, ecosystem, locks);
            let pip = format!("pip_parse {name}:2 svc/requirements.txt");
            assert_eq!(asked("svc", "pypi", &["requirements.txt"]), pip);
            assert_eq!(asked("other", "pypi", &["requirements.txt"]), "");
            let gemfile = format!("rb_bundle_fetch {name}:6 svc/Gemfile");
            assert_eq!(asked("svc", "gem", &["Gemfile", "Gemfile.lock"]), gemfile);
            let doubt =
                format!("? {name}:6 the files `rb_bundle_fetch` names are not all written out");
            assert_eq!(asked("other", "gem", &["Gemfile", "Gemfile.lock"]), doubt);
        }
        // A file that calls neither says nothing of them.
        let rule = "http_archive(name = \"x\", urls = [LOCK])\n";
        let files = [("WORKSPACE", rule)];
        assert_eq!(reader_of(&files, "svc", "pypi", &["requirements.txt"]), "");
        // The name the file gives the main repository names it in a label
        // of that file; without that call the label is another
        // repository's.
        let call =
            "pip_parse(name = \"pypi\", requirements_lock = \"@shop//svc:requirements.txt\")\n";
        let named = format!("workspace(name = \"shop\")\n{call}");
        let files = [("WORKSPACE", named.as_str())];
        let pip = "pip_parse WORKSPACE:2 svc/requirements.txt";
        assert_eq!(reader_of(&files, "svc", "pypi", &["requirements.txt"]), pip);
        let files = [("WORKSPACE", call)];
        assert_eq!(reader_of(&files, "svc", "pypi", &["requirements.txt"]), "");
    }

    /// A `WORKSPACE` file is not read by a Bazel of 9 or later. Where the
    /// checkout names such a release, a call of that file that names the
    /// lock is no reader of it, one that is not written out is no doubt,
    /// and neither is a file that cannot be read. A checkout that names an
    /// older release, none, or something that is no release keeps all
    /// three, and a call of a module file counts under every release.
    #[test]
    fn a_workspace_file_counts_unless_the_checkout_names_bazel_9_or_later() {
        let module = ("MODULE.bazel", "module(name = \"shop\")\n");
        let legacy = "pip_parse(name = \"pypi\", requirements_lock = \"//svc:requirements.txt\")\n\
            rb_bundle_fetch(name = \"bundle\", gemfile = \"//svc:Gemfile\", gemfile_lock = LOCK)\n";
        let asked = |files: &[(&str, &str)], project, ecosystem| {
            let locks: &[&str] = match ecosystem {
                "pypi" => &["requirements.txt"],
                _ => &["Gemfile", "Gemfile.lock"],
            };
            reader_of(files, project, ecosystem, locks)
        };
        let pip = "pip_parse WORKSPACE:1 svc/requirements.txt";
        let gemfile = "rb_bundle_fetch WORKSPACE:2 svc/Gemfile";
        let unwritten = "? WORKSPACE:2 the files `rb_bundle_fetch` names are not all written out";
        let unread = "? WORKSPACE:0 it cannot be read: it is not UTF-8";
        // What names the release, and whether the file then counts.
        let rows: [(&[(&str, &str)], bool); 9] = [
            (&[], true),
            (&[(".bazelversion", "7.7.2\n")], true),
            (&[(".bazelversion", "8.8.2\n")], true),
            (&[(".bazelversion", "latest\n")], true),
            (&[(".bazelversion", "9.3.2rc1\n")], true),
            (&[(".bazelversion", "9.0.0\n")], false),
            (&[(".bazelversion", "9.3.2\n")], false),
            (&[(".bazelversion", "10.0.0\n")], false),
            (
                &[
                    (".bazeliskrc", "USE_BAZEL_VERSION=8.8.2\n"),
                    (".bazelversion", "9.3.2\n"),
                ],
                true,
            ),
        ];
        for (release, counts) in rows {
            let with = |workspace: &'static str| {
                let mut files = vec![module, ("WORKSPACE", workspace)];
                files.extend_from_slice(release);
                files
            };
            let said = |yes: &str| counts.then_some(yes).unwrap_or_default().to_string();
            let files = with(legacy);
            assert_eq!(asked(&files, "svc", "pypi"), said(pip), "{release:?}");
            assert_eq!(asked(&files, "svc", "gem"), said(gemfile), "{release:?}");
            let other = asked(&files, "other", "gem");
            assert_eq!(other, said(unwritten), "{release:?}");
            let files = with("unreadable: it is not UTF-8");
            for ecosystem in ["pypi", "gem"] {
                assert_eq!(asked(&files, "svc", ecosystem), said(unread), "{release:?}");
            }
        }
        // A call of a module file is the hub's under Bazel 9 as under any.
        let mut files = SHOP.to_vec();
        files.push(("WORKSPACE", legacy));
        files.push((".bazelversion", "9.3.2\n"));
        let api = "pip.parse MODULE.bazel:15 api/requirements.txt";
        assert_eq!(asked(&files, "api", "pypi"), api);
        assert_eq!(asked(&files, "svc", "pypi"), "");
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
            package("pkg:golang/example.com/m@v1.0.0", None),
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
