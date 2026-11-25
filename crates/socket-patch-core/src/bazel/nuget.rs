//! Whether the Bazel build of a workspace takes what hosted mode writes
//! for a NuGet package, and what makes it take the copy that vendored mode
//! commits.
//!
//! rules_csharp hands NuGet packages to Bazel through one tag of a module
//! extension. `nuget.from_lock(packages_lock_json = ...)` downloads every
//! package of a `packages.lock.json` and fails the build on a file that
//! does not match the lock's `contentHash`. All the tags of the extension
//! make one hub (`_nuget_impl` in `csharp/extensions.bzl` at 0.5.0):
//!
//! - It has one list of package sources, asked before nuget.org. Each tag
//!   in turn puts its `feeds` in the place of the list, and then the
//!   sources of the `nuget.config` it names as `nuget_config`, when that
//!   file has any. So the last tag with either decides.
//! - It holds a package to the `contentHash` of the first lock that names
//!   it.
//!
//! Hosted mode re-pins the `contentHash` of a patched package in the
//! project's locks and names the Socket source of the patch in the
//! project's `nuget.config`. A hub that reads a re-pinned lock and not
//! that file downloads the upstream package and refuses it; one that reads
//! the file and has the package from a lock this run does not re-pin
//! downloads the patched package and refuses that. Either way the command
//! exited 0 and the next `bazel build` failed (measured on Bazel 9.3.2).
//! So [`withheld`] reads what the hub makes of a project, and
//! [`Hub::against`] tells hosted mode when to write nothing for a package,
//! and what to say instead.
//!
//! Vendored mode commits the patched package and names its folder as a
//! package source in `nuget.config`, which NuGet takes. The hub reads that
//! line as the URL of a feed, and the next `bazel build` failed: Bazel
//! 9.3.2 crashed in the module extension, 8.8.2 and 7.7.2 refused the URL
//! (`Bad URL`). What the hub does take is a feed `file:<folder>`, which
//! Bazel reads from the root of the workspace, with the package at
//! `<folder>/<id>/<version>/<id>.<version>.nupkg`. So vendored mode keeps
//! one block at the end of the root `MODULE.bazel` ([`BEGIN`]): a
//! `nuget.from_lock` of its own, after every tag of the user's, whose
//! `feeds` are the folders of the vendored packages and then the sources
//! the hub has without it. [`vendored`] says whether that block can be
//! shown to work in a checkout, [`with_folder`] writes a folder into it and
//! [`without_folder`] takes one out, the block with the last.
//!
//! The answer is read from the checkout through [`super::workspace`]:
//! `MODULE.bazel` and the files it includes, and the locks the tags name.
//! Nothing is evaluated and no Bazel is run. The ruleset has no
//! `WORKSPACE` form, so that file is not looked at.

use std::ops::Range;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::block::{self, Found, END};
use super::maven::{asked, names, proxy, Asked};
use super::rc::{declared_release, mentions, ModuleLock, Release};
use super::starlark::{How, Value};
use super::workspace::{disk, disk_up_to, Doubt, Entry, Extension, Repo, Tag, Tags, Workspace};
use super::BazelRoot;
use crate::formats::nuget::lock::{locked_at, nuget_lock_entries, parse_lock};
use crate::formats::nuget::parse_config;
use crate::patch::redirect::NUGET_CONFIG_FILE_NAMES as NAMES;

/// The extension whose `from_lock` tags make the hub.
pub const EXTENSION: Extension<'static> = Extension {
    module: "rules_csharp",
    file: "//csharp:extensions.bzl",
    name: "nuget",
};

/// The warnings of a hosted run for a NuGet package it wrote nothing for:
/// the hub would not download from the Socket source, or it has the
/// package from a lock that the run does not re-pin.
pub const CONFIG_UNDECLARED: &str = "redirect_bazel_nuget_config_undeclared";
pub const LOCK_NOT_REPINNED: &str = "redirect_bazel_nuget_lock_not_repinned";

/// The key under which a hosted run hands the answer of [`withheld`] to
/// the NuGet rewriter among its candidate files: no path of a file.
pub const WITHHELD_KEY: &str = "<socket-patch:bazel-nuget-withheld>";

/// The most a lock that a tag names may hold, to be read.
const MAX_LOCK: usize = 16 << 20;

/// What stands against a tag that is not written out, and what a warning
/// ends with in a workspace where a tag has `local_package_dirs`.
const NOT_PLAIN: &str = "is not a call of its own that names its `nuget_config` in a plain string";
const DIRS: &str = "; rules_csharp asks the directories of `local_package_dirs` before every \
                    source, so the upstream package must not lie in one";
/// What the build does with a re-pinned lock and without the Socket source.
const WITHOUT: &str =
    ", where hosted mode names the Socket source of a patch; without that source \
                       rules_csharp downloads the upstream package, and the Bazel build fails on \
                       the `contentHash` that hosted mode re-pins in the lock";

/// What a lock warning says of a tag whose lock is not named plainly
/// beside one that names the project's, and the way on of each kind.
const UNNAMED: &str = "names its lock in no plain string, so that lock may hold the package and \
                       may be one this run does not re-pin";
const NAME_IT: &str = "Write its `packages_lock_json` as a label in a plain string and run this \
                       command again";
const ABOVE_BOTH: &str = "Run this command in a directory above both locks that holds a solution \
                          file or a `nuget.config` (`--cwd`): there it re-pins the lock of every \
                          project";

/// What the hub of a Bazel workspace makes of one project.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Hub {
    /// Why the hub does not take its package sources from the project's
    /// `nuget.config`, as the warning of a package says it after its name.
    /// `None`: the tags show that it does.
    pub why: Option<String>,
    /// [`Self::why`] stands against every package of the run, not only
    /// against one that a lock the hub reads holds: the hub does read the
    /// config, which must not get a source yet.
    pub every: bool,
    /// The lock of each tag that names one this reader can tell, in the
    /// order of the tags.
    pub locks: Vec<Read>,
    /// That order is the one the hub reads them in: every tag is in one
    /// file, where the reader lists the calls as Bazel runs them.
    pub ordered: bool,
}

/// The lock a tag reads.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum Read {
    /// A lock of the project, as the project names it: one this run
    /// re-pins.
    Ours(String),
    /// Another file of the checkout: where its tag is, its path from the
    /// Bazel root, and its text (`None`: it cannot be read).
    Other(String, String, Option<String>),
    /// A label that cannot be read, and where its tag is: any lock. Where
    /// no tag names a lock of the project it is taken for the project's;
    /// beside a tag that does, it is another lock, which cannot be read.
    Any(String),
}

impl Hub {
    /// Why hosted mode writes nothing for the package `id` at the
    /// normalized version `version`, whose patched `contentHash` is
    /// `hash`: the code of the warning, and what it says after the
    /// package's name. `None`: it writes what it writes without Bazel.
    /// `pinned` says whether a lock of the project (`None`: any of them)
    /// holds the package at that version, which is what the run re-pins.
    ///
    /// First the locks this run does not re-pin: one that holds the
    /// package at that version with another `contentHash`, or cannot be
    /// read, stands against the pin, unless the hub has the package from
    /// a lock before it. That is asked for every package, also where the
    /// hub does not read the config yet: the run names the package's
    /// source in the config that the other warning says to put on a tag,
    /// and the hub would then take the patched package against that lock.
    /// Then the config ([`Self::why`]), for a package that the run re-pins
    /// in a lock the hub reads. A package in no such lock is not the
    /// hub's: its pin changes nothing a build reads.
    ///
    /// `docs` are [`Self::docs`], read once for all the packages of a run.
    pub fn against(
        &self,
        docs: &[Option<serde_json::Value>],
        pinned: &dyn Fn(Option<&str>) -> bool,
        id: &str,
        version: &str,
        hash: &str,
    ) -> Option<(&'static str, String)> {
        let named = self.locks.iter().any(|lock| matches!(lock, Read::Ours(_)));
        let (mut read, mut first) = (false, false);
        for (lock, doc) in self.locks.iter().zip(docs) {
            let (at, reads, way) = match lock {
                Read::Any(_) if !named => {
                    read |= pinned(None);
                    continue;
                }
                Read::Ours(lock) => {
                    let ours = pinned(Some(lock));
                    (read, first) = (read || ours, first || ours);
                    continue;
                }
                _ if first && self.ordered => continue,
                Read::Any(at) => (at, UNNAMED.to_string(), NAME_IT),
                Read::Other(at, path, _) => {
                    let state = match doc {
                        None => "cannot be read and may hold the package",
                        Some(doc)
                            if locked_at(doc, id, version)
                                .any(|e| e.content_hash != Some(hash)) =>
                        {
                            "holds the package as well"
                        }
                        Some(doc) => {
                            first |= nuget_lock_entries(doc).any(|e| e.id.eq_ignore_ascii_case(id));
                            continue;
                        }
                    };
                    let reads =
                        format!("reads {path}, which {state} and which this run does not re-pin");
                    (at, reads, ABOVE_BOTH)
                }
            };
            let why = format!(
                "{at}: this `nuget.from_lock` {reads}; rules_csharp holds a package to the \
                 `contentHash` of the first lock that names it, so the Bazel build can fail on \
                 the patched package. So hosted mode wrote nothing for it. {way}"
            );
            return Some((LOCK_NOT_REPINNED, why));
        }
        let why = self.why.clone().filter(|_| read || self.every)?;
        Some((CONFIG_UNDECLARED, why))
    }

    /// The locks of the other tags as documents, one for each of
    /// [`Self::locks`]: `None` for one that is not such a lock, has no
    /// text or is no JSON.
    pub fn docs(&self) -> Vec<Option<serde_json::Value>> {
        let doc = |lock: &Read| match lock {
            Read::Other(_, _, Some(text)) => parse_lock(text).ok(),
            _ => None,
        };
        self.locks.iter().map(doc).collect()
    }
}

/// What the rules_csharp hub of the Bazel workspace makes of the project
/// at `project`, whose `nuget.config` is `config` and whose locks are
/// `locks` (paths from the project, with `/` between their parts): a
/// [`Hub`] as JSON, for [`WITHHELD_KEY`]. `None`: hosted mode writes what
/// it writes without Bazel.
///
/// `None` for a project in no Bazel workspace ([`super::bazel_root`]) and
/// for one without a lock. `None` as well unless a `nuget.from_lock` call
/// that the reader lists names one of the locks, or names its lock in a
/// way that cannot be read (a computed label, a `**` dict): a project
/// whose lock no tag reads is not Bazel's to build.
///
/// `config` is taken as the project's directory spells it: a disk that
/// folds case answers to every spelling, and a label has to name the file
/// as a disk that does not would. A label that differs from it only in
/// case names the same file, unless the directory holds both, or holds a
/// spelling that is not NuGet's on a disk that does not fold case, where
/// the rewriter writes a file of its own beside it.
///
/// Not seen: a tag of another Bazel module, whose sources and locks the
/// hub takes as well; a tag that an unreadable part of the workspace
/// hides; a lock of another repository; and what a directory of
/// `local_package_dirs` holds, which the hub asks before every source.
pub fn withheld(project: &Path, config: &str, locks: &[String]) -> Option<String> {
    if locks.is_empty() {
        return None;
    }
    let root = super::bazel_root(project)?;
    let dir = prefix(&root);
    let listed = std::fs::read_dir(project).into_iter().flatten().flatten();
    let spelled: Vec<String> = listed
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.eq_ignore_ascii_case(config))
        .collect();
    let exact = spelled.iter().any(|name| name == config);
    // A spelling in another case is the file the rewriter writes only
    // where the disk folds case: there its own name finds the file.
    let folds = !exact && project.join(config).exists();
    let strict = spelled.len() > 1 || !(exact || folds || spelled.is_empty());
    let config = spelled
        .first()
        .filter(|_| folds)
        .map_or(config, |name| name);
    let read = disk_up_to(&root.dir, MAX_LOCK);
    let sources = match read(&format!("{dir}{config}")) {
        Entry::Text(text) => parse_config(&text).is_some_and(|c| !c.sources.is_empty()),
        _ => false,
    };
    let workspace = Workspace::read(&disk(&root.dir));
    let mut hub = judge(&workspace, &dir, config, locks, strict, sources)?;
    for lock in &mut hub.locks {
        if let Read::Other(_, path, text) = lock {
            *text = match read(path) {
                Entry::Text(text) => Some(text),
                _ => None,
            };
        }
    }
    serde_json::to_string(&hub).ok()
}

/// The directory of the project of `root` from the Bazel root: empty, or
/// with a `/` at its end. Bazel has `/` between the parts of a path on
/// every system.
fn prefix(root: &BazelRoot) -> String {
    let parts = root.project.components();
    parts
        .map(|part| format!("{}/", part.as_os_str().to_string_lossy()))
        .collect()
}

/// The lock that `tag` reads, for the project in `dir` whose locks are
/// `locks`. `None`: it names none.
fn reads(ws: &Workspace, tag: &Tag, dir: &str, locks: &[String]) -> Option<Read> {
    let at = format!("{}:{}", tag.file, tag.call.line);
    match tag.call.arg("packages_lock_json") {
        Some(Value::Str(label)) => Some(match named(ws, label, dir, locks)? {
            Ok(lock) => Read::Ours(lock.clone()),
            Err(path) => Read::Other(at, path, None),
        }),
        Some(_) => Some(Read::Any(at)),
        None => tag.call.unpacks().then_some(Read::Any(at)),
    }
}

/// The file of the checkout that the label `label` names: the lock of
/// `locks` it is for the project in `dir`, or else its path from the Bazel
/// root. `None`: it names no file of the main repository.
fn named<'a>(
    ws: &Workspace,
    label: &str,
    dir: &str,
    locks: &'a [String],
) -> Option<Result<&'a String, String>> {
    let label = ws.label(label).filter(|label| label.repo == Repo::Main);
    let path = label?.path();
    let ours = |lock: &&String| path.eq_ignore_ascii_case(&format!("{dir}{lock}"));
    Some(locks.iter().find(ours).ok_or(path))
}

/// [`withheld`] for the workspace `ws` and the project in its directory
/// `dir` (empty, or with a `/` at its end), before the locks of the other
/// tags are read. `exact`: a label names `config` only in its own case.
/// `sources`: `config` has package sources of its own.
///
/// The hub reads `config` when the last tag that has a `nuget_config` or
/// `feeds` names it, as a label in a string; where the tags are in more
/// than one file, their order is not known, and every tag that has either
/// must name it. A tag that is not a plain call of its own, or whose
/// `nuget_config` is no string, makes that uncertain, and an uncertain
/// reading withholds: a build that may break outranks a patch that is
/// missed and explained. A doubt of the reader elsewhere in the files can
/// only hide a tag, and changes nothing here.
///
/// A config without a package source does not replace the `feeds` of the
/// tags (`if parsed_sources: feeds = parsed_sources`), and it would once
/// hosted mode names the Socket source in it: where a tag has `feeds`,
/// that is withheld as well, until the config names them.
fn judge(
    ws: &Workspace,
    dir: &str,
    config: &str,
    locks: &[String],
    exact: bool,
    sources: bool,
) -> Option<Hub> {
    let tags = ws.tags(&EXTENSION, "from_lock");
    let given = |tag: &Tag, attribute: &str| tag.call.arg(attribute).is_some();
    // The file of the checkout that a tag names in a plain string.
    let file = |tag: &Tag, attribute: &str| match tag.call.arg(attribute) {
        Some(Value::Str(label)) => ws.label(label).filter(|label| label.repo == Repo::Main),
        _ => None,
    };
    let at = |tag: &Tag| format!("{}:{}", tag.file, tag.call.line);
    let read = |tag: &Tag| reads(ws, tag, dir, locks);
    let reads: Vec<Option<Read>> = tags.calls.iter().map(read).collect();
    let mine = |read: &Option<Read>| matches!(read, Some(Read::Ours(_) | Read::Any(_)));
    let reader = &tags.calls[reads.iter().position(mine)?];

    let config = format!("{dir}{config}");
    let ours = |tag: &&Tag| {
        let named = file(tag, "nuget_config").map(|label| label.path());
        named.is_some_and(|path| path == config || !exact && path.eq_ignore_ascii_case(&config))
    };
    let sets = |tag: &&Tag| given(tag, "nuget_config") || given(tag, "feeds");
    let ordered = tags.calls.iter().all(|tag| tag.file == reader.file);
    // The tag that stands against the config: the last that gives the hub
    // its sources, or the first of them where the order is not known.
    let other = match tags.calls.iter().rfind(sets) {
        Some(last) if ordered => Some(last).filter(|tag| !ours(tag)),
        _ => tags.calls.iter().filter(sets).find(|tag| !ours(tag)),
    };
    let plain = |tag: &&Tag| {
        let config = matches!(tag.call.arg("nuget_config"), None | Some(Value::Str(_)));
        tag.call.whole && !tag.call.unpacks() && config
    };
    let vague = tags.calls.iter().find(|tag| !plain(tag));
    let shown = other.is_none() && tags.calls.iter().any(|tag| sets(&tag));
    // The tag whose `feeds` the config would replace once it has a source.
    let fed = tags.calls.iter().find(|tag| given(tag, "feeds"));
    let fed = fed.filter(|_| shown && !sources);
    let locks: Vec<Read> = reads.into_iter().flatten().collect();
    let every = vague.is_none() && fed.is_some();
    let hub = |why, locks| Hub {
        why,
        every,
        locks,
        ordered,
    };
    if vague.is_none() && shown && fed.is_none() {
        // The config is read: only another lock can stand against a pin.
        return (locks.len() > 1).then(|| hub(None, locks));
    }

    // The label of `config` for the tag, in the package of the lock, when
    // the tag names the lock plainly and `config` lies in that package:
    // one that Bazel reads already. Elsewhere the package of `config` is
    // not known, and the answer names the file.
    let package = file(reader, "packages_lock_json").map(|label| label.package);
    let inside = |package: &String| match config.strip_prefix(package.as_str()) {
        Some(rest) => package.is_empty() || rest.starts_with('/'),
        None => false,
    };
    let attribute = match package.as_ref().filter(|package| inside(package)) {
        Some(package) => {
            let name = config[package.len()..].trim_start_matches('/');
            format!("`nuget_config = \"//{package}:{name}\"`")
        }
        None => format!("a `nuget_config` that names {config}"),
    };
    let put = format!("Put {attribute} on that tag");
    let again = format!(
        " and run this command again: it then names the source in {config}, which it creates \
         where there is none"
    );
    let unread = format!("so rules_csharp does not read {config}");
    let tag = vague.or(other).or(fed).unwrap_or(reader);
    let mut harm = WITHOUT.to_string();
    let (why, way) = match tag.call.arg("nuget_config") {
        _ if vague.is_some() => (
            format!("{NOT_PLAIN}, so socket-patch cannot tell whether rules_csharp reads {config}"),
            format!("Write that plainly, with {attribute} on the tag,{again}"),
        ),
        _ if other.is_none() && fed.is_some() => {
            harm = format!(
                ": with the Socket source that hosted mode names there, rules_csharp takes the \
                 package sources of {config} in place of those `feeds`, and the Bazel build \
                 cannot download a package that only they hold"
            );
            (
                format!("has `feeds`, and {config} names no package source"),
                format!("Name those `feeds` in {config} and run this command again"),
            )
        }
        // The tag of the block: its feeds are the hub's, as of the last
        // vendored run.
        _ if tag.call.callee.split('.').next() == Some(PROXY) => (
            format!(
                "is the one vendored mode keeps for the vendored NuGet packages of this project, \
                 and its `feeds` stand in the place of the package sources of {config}"
            ),
            "Vendor this package as well (`--mode vendored`), or take the vendored ones out \
             (`socket-patch vendor --revert`), and run this command again"
                .to_string(),
        ),
        Some(Value::Str(theirs)) => {
            // A config of NuGet's in a directory above the project's is
            // one the same command writes, when it runs there.
            let above = file(tag, "nuget_config").is_some_and(|label| {
                let path = label.path();
                let (up, name) = path.split_at(path.rfind('/').map_or(0, |slash| slash + 1));
                let nuget = NAMES.iter().any(|nuget| nuget.eq_ignore_ascii_case(name));
                nuget && dir.len() > up.len() && dir.starts_with(up)
            });
            let way = match above {
                true => "Run this command in the directory of that file (`--cwd`): it then names \
                         the source there"
                    .to_string(),
                false => format!(
                    "{put}, name in {config} the package sources of `{theirs}` that the build \
                     needs (rules_csharp takes its package sources from one file){again}"
                ),
            };
            let why = format!("names `{theirs}` as its `nuget_config`, not {config}");
            (why, way)
        }
        _ if given(tag, "feeds") => (
            format!("has `feeds` and no `nuget_config`, {unread}"),
            format!(
                "{put}, name its `feeds` in {config} (rules_csharp takes the package sources of a \
                 `nuget_config` in place of `feeds`){again}"
            ),
        ),
        _ => (
            format!("names no `nuget_config`, {unread}"),
            format!("{put}{again}"),
        ),
    };
    // What a directory holds is asked before every source, and not seen.
    let held = |tag: &Tag| given(tag, "local_package_dirs");
    let dirs = tags.calls.iter().any(held);
    let dirs = if dirs { DIRS } else { "" };
    let why = format!(
        "{}: this `nuget.from_lock` {why}{harm}. So hosted mode wrote nothing for it. {way}, and \
         the Bazel build takes the patched package{dirs}",
        at(tag)
    );
    Some(hub(Some(why), locks))
}

/// The code with which vendored mode declines a NuGet package of a project
/// whose lock the hub reads, where the block cannot be shown to work.
pub const VENDOR_DECLINED: &str = "vendor_nuget_bazel_workspace";

/// The file of the block of vendored mode, and the first line of the block.
pub const FILE: &str = super::maven::FILE;
pub const BEGIN: &str = "# >>> socket-patch: NuGet patches for Bazel (managed block: socket-patch \
                         writes and removes it) >>>";
/// The name the block gives its `use_extension`, and how a feed of the
/// block starts that is a folder of vendored mode.
const PROXY: &str = "socket_patch_nuget";
const FOLDER: &str = "file:.socket/vendor/nuget/";

/// The release of rules_csharp and the releases of Bazel the block was
/// built on, with the patch host unreachable. It rests on Bazel reading a
/// relative `file:` URL from the root of the workspace, which no document
/// of Bazel's promises: 9.1.0 has other code for such a URL than 9.0.2 and
/// 9.1.1 (`DownloadManager.java`), so no release is taken for its
/// neighbour's sake.
const RULESET: &str = "0.5.0";
const BAZELS: [Release; 3] = [(7, 7, 2), (8, 8, 2), (9, 3, 2)];
const BUILT_ON: &str = "the block was built on Bazel 7.7.2, 8.8.2 and 9.3.2 alone";

/// The arguments of a tag beside which the block was built, or which
/// change nothing for it.
const ARGUMENTS: [&str; 6] = [
    "directory_packages_props",
    "feeds",
    "name",
    "nuget_config",
    "packages_lock_json",
    "use_public_sources",
];

/// What the block holds besides the folders of vendored mode, read from
/// the one tag of the workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feeds {
    /// The label of the tag's `use_extension`, as it is written.
    label: String,
    /// The name the tag gives the hub, where it gives one: a tag without
    /// one would give the hub the name `nuget`.
    name: Option<String>,
    /// The tag's `packages_lock_json`, as it is written.
    lock: String,
    /// The package sources the hub has without the block, in its order.
    sources: Vec<String>,
}

/// What vendored mode does for the NuGet packages of a project.
#[derive(Debug, PartialEq, Eq)]
pub enum Vendored {
    /// What it does without Bazel: the project is in no Bazel workspace,
    /// or no `nuget.from_lock` reads a lock of it and none that does can
    /// be hidden.
    Plain,
    /// Nothing: the hub reads a lock of the project, or may, and this is
    /// why the block cannot be shown to work.
    Declined(String),
    /// It keeps the package where a feed of the hub has one, and its
    /// folder in the block.
    Block(Feeds),
}

/// What vendored mode does for the NuGet packages of the project at
/// `project`, whose locks are `locks` (paths from the project, with `/`
/// between their parts).
///
/// The block is written only where the checkout shows that it works: the
/// project is the root of its Bazel workspace, and no workspace lies above
/// it in the checkout; the workspace has one `nuget.from_lock`, a call of
/// its own with every argument written out and none but [`ARGUMENTS`], on
/// a `use_extension` that the block can share, and whose `feeds` no run
/// of vendored mode replaces (a `nuget_config` without a package source
/// gets one); Bazel selected rules_csharp [`RULESET`], and the checkout
/// names one of [`BAZELS`]; no rc file names
/// `--repository_disable_download`, `--vendor_dir` or a remote downloader,
/// and no directory at the root is a vendor directory of Bazel's (it holds
/// `VENDOR.bazel`); and `MODULE.bazel` is a file whose block, if it has
/// one, is as socket-patch wrote it.
///
/// A project whose lock no tag reads is vendored as without Bazel, unless
/// a hub may read the lock all the same. That is declined too: a package
/// in the folder of its patch alone is in no feed of such a hub, whose
/// build then fails on the re-pinned lock. The block is there and the tag
/// it was written beside is gone, so the block's own tag still hands the
/// lock to the hub; or a tag may not have been read ([`gate`]).
///
/// Not seen: a tag of another Bazel module, whose sources the hub takes
/// after the block's; a module that depends on this one, where Bazel reads
/// the folder from another root; a vendor directory below the first level;
/// `--nofetch`, in an rc file as on the command line; and whatever else
/// the command line tells Bazel.
pub fn vendored(project: &Path, locks: &[String]) -> Vendored {
    let Some(root) = super::bazel_root(project).filter(|_| !locks.is_empty()) else {
        return Vendored::Plain;
    };
    let on_disk = disk(&root.dir);
    let module = match on_disk(FILE) {
        Entry::Text(module) => module,
        _ => String::new(),
    };
    // The block is socket-patch's own: the tags are read without it.
    let found = find(&module);
    let view = |path: &str| match &found {
        Block::Ours(at, ..) if path == FILE => Entry::Text(block::hidden(&module, at.clone())),
        _ => on_disk(path),
    };
    let files = disk_up_to(&root.dir, MAX_LOCK);
    let (ws, dir) = (Workspace::read(&view), prefix(&root));
    let feeds = match (gate(&ws, &files, &dir, locks), &found) {
        // The tag the block was written beside is gone, and the block's
        // own still hands the lock to the hub: what the hub is to hold
        // for another package is no longer known.
        (Vendored::Plain, Block::Ours(at, kept, _))
            if matches!(named(&ws, &kept.lock, &dir, locks), Some(Ok(_))) =>
        {
            let line = module[..at.start].matches('\n').count() + 1;
            return Vendored::Declined(format!(
                "{FILE}:{line}: the block that socket-patch keeps there still reads `{}` for the \
                 hub, and the `nuget.from_lock` it was written beside is gone, so a package \
                 vendored now would not be among the block's feeds: put that tag back, or take \
                 the vendored packages out (`socket-patch vendor --revert`), and run this command \
                 again",
                kept.lock
            ));
        }
        (Vendored::Plain, _) => return Vendored::Plain,
        // Its tag reads as one of the user's: said as what it is.
        (_, Block::Edited(line)) => {
            let edited = "the block that socket-patch keeps there was changed by hand";
            return Vendored::Declined(format!("{FILE}:{line}: {edited}"));
        }
        (Vendored::Block(feeds), _) => feeds,
        (declined, _) => return declined,
    };
    let link = std::fs::symlink_metadata(root.dir.join(FILE)).is_ok_and(|meta| meta.is_symlink());
    let listed = std::fs::read_dir(&root.dir).into_iter().flatten().flatten();
    let vendor = { listed }.find(|entry| entry.path().join("VENDOR.bazel").is_file());
    let why = match (vendor, super::root_above(project)) {
        _ if link => {
            format!("{FILE} is a symbolic link, which socket-patch does not write through")
        }
        (Some(vendor), _) => format!(
            "{}/VENDOR.bazel: the checkout holds a vendor directory of Bazel's, from which Bazel \
             can build the unpatched package",
            vendor.file_name().to_string_lossy()
        ),
        (_, Some(above)) => format!(
            "{} holds a Bazel workspace above this one, and a build from there reads the block's \
             folder from that root",
            crate::utils::pnpm_workspace::without_verbatim_prefix(above).display()
        ),
        _ => return Vendored::Block(feeds),
    };
    Vendored::Declined(why)
}

/// [`vendored`] for the workspace `ws`, read without the block, and the
/// project in its directory `dir` (empty, or with a `/` at its end), by
/// what `files` holds beside it: before the checkout itself is looked at.
///
/// Where no tag that was read reads a lock of the project, one that was
/// not read still may. A doubt of the reader declines the package in a
/// workspace that has to do with the ruleset: a call of a file that was
/// read names it ([`names`]), as the `bazel_dep` of every workspace does
/// that uses the extension. In a workspace of other rulesets such a doubt
/// is about no hub, and only a file that is there and was not read as a
/// whole declines ([`Workspace::unread`]): it may be the one that names
/// the ruleset.
fn gate(ws: &Workspace, files: &dyn Fn(&str) -> Entry, dir: &str, locks: &[String]) -> Vendored {
    let tags = ws.tags(&EXTENSION, "from_lock");
    let mine = |tag: &&Tag| {
        let read = reads(ws, tag, dir, locks);
        matches!(read, Some(Read::Ours(_) | Read::Any(_)))
    };
    match tags.calls.iter().find(mine) {
        // A tag that was not read may read the lock. The doubt that says
        // so: the first one in a workspace that has to do with the
        // ruleset, else the one about a file that was not read.
        None => {
            let first = ws.doubts.iter().chain(&tags.doubts).next();
            let doubt = first.filter(|_| names(ws, EXTENSION.module));
            let doubt = doubt.or(ws.unread.as_ref());
            doubt.map_or(Vendored::Plain, |doubt| Vendored::Declined(unsure(doubt)))
        }
        Some(tag) => match feeds(ws, files, &tags, tag, dir) {
            Ok(feeds) => Vendored::Block(feeds),
            Err(why) => Vendored::Declined(why),
        },
    }
}

/// What `doubt` of the reader stands against: the tags of the workspace
/// are not all known.
fn unsure(Doubt { file, line, why }: &Doubt) -> String {
    let place = match line {
        0 => file.clone(),
        line => format!("{file}:{line}"),
    };
    format!(
        "{place}: {why}, so socket-patch cannot tell which `nuget.from_lock` tags the workspace has"
    )
}

/// What the block holds for the hub of `tag`, the tag of `tags` that reads
/// a lock of the project in `dir`, or why it cannot be shown to work.
fn feeds(
    ws: &Workspace,
    files: &dyn Fn(&str) -> Entry,
    tags: &Tags,
    tag: &Tag,
    dir: &str,
) -> Result<Feeds, String> {
    let place = |file: &str, line: usize| match line {
        0 => file.to_string(),
        line => format!("{file}:{line}"),
    };
    let here = format!("{}: this `nuget.from_lock`", place(tag.file, tag.call.line));
    if !dir.is_empty() {
        return Err(format!(
            "{here} reads the lock of a project below the root of its Bazel workspace, and the \
             block was built for a project at the root alone"
        ));
    }
    if let Some(doubt) = ws.doubts.iter().chain(&tags.doubts).next() {
        return Err(unsure(doubt));
    }
    if let Some(other) = tags.calls.iter().find(|other| *other != tag) {
        return Err(format!(
            "{}: the workspace has more than one `nuget.from_lock`, and the block was built \
             beside one alone",
            place(other.file, other.call.line)
        ));
    }
    let written = "is not a call of its own with every argument written out";
    let against = tag.call.args.iter().find_map(|arg| match &arg.how {
        How::Keyword(name) if ARGUMENTS.contains(&name.as_str()) => None,
        How::Keyword(name) if name == "local_package_dirs" => Some(
            "has `local_package_dirs`, which rules_csharp asks before every feed: with the \
             upstream package in one, the Bazel build fails on the re-pinned `contentHash`"
                .to_string(),
        ),
        How::Keyword(name) => Some(format!("has `{name}`, which the block was not built with")),
        _ => Some(written.to_string()),
    });
    let against = against.or((!tag.call.whole).then(|| written.to_string()));
    if let Some(against) = against {
        return Err(format!("{here} {against}"));
    }
    // What can stand in a string of the block as it is.
    let plain = |text: &str| {
        let quoted = |b: u8| !b.is_ascii_graphic() || b == b'"' || b == b'\\';
        !text.is_empty() && !text.bytes().any(quoted)
    };
    let string = |name: &str| match tag.call.arg(name) {
        None => Ok(None),
        Some(Value::Str(text)) if plain(text) => Ok(Some(text.clone())),
        Some(_) => Err(format!("{here} has a `{name}` that is no plain string")),
    };
    let (Some(lock), name) = (string("packages_lock_json")?, string("name")?) else {
        return Err(format!("{here} {written}"));
    };
    let Some(label) = proxy(ws, tag).filter(|_| tag.dev_dependency == Some(false)) else {
        return Err(format!(
            "{here} is called on a `use_extension` that is isolated, a dev dependency or not \
             written plainly, which a block of its own does not share"
        ));
    };
    // The sources of the tag's config, where it has any, stand in the
    // place of its feeds: without the folders vendored mode names there.
    let feeds = match tag.call.arg("feeds") {
        None => Vec::new(),
        Some(Value::List(feeds)) => feeds.clone(),
        Some(_) => {
            return Err(format!(
                "{here} has `feeds` that are no list of plain strings"
            ))
        }
    };
    let named = string("nuget_config")?;
    let config = match &named {
        None => Vec::new(),
        Some(named) => {
            let file = ws.label(named).filter(|label| label.repo == Repo::Main);
            match file.map(|label| files(&label.path())) {
                Some(Entry::Text(config)) => sources(&config),
                _ => {
                    let unread = "as its `nuget_config`, which cannot be read";
                    return Err(format!("{here} names `{named}` {unread}"));
                }
            }
        }
    };
    let own = |source: &String| !source.starts_with(&FOLDER["file:".len()..]);
    let config: Vec<String> = config.into_iter().filter(own).collect();
    // A config without a source gets one with the folder of the patch
    // (nuget.org beside it, where NuGet had that by default): read on the
    // next run, the file's sources would stand in the place of the feeds.
    if let Some(named) = named.filter(|_| config.is_empty() && !feeds.is_empty()) {
        return Err(format!(
            "{here} has `feeds`, and its `nuget_config` `{named}` names no package source, where \
             vendored mode names its folder: rules_csharp would then take the sources of that \
             file in place of those `feeds`, so name those `feeds` in that file"
        ));
    }
    let sources = if config.is_empty() { feeds } else { config };
    if !sources.iter().all(|source| plain(source)) {
        return Err(format!(
            "{here} has a package source that cannot stand in a string of {FILE}"
        ));
    }

    let module = EXTENSION.module;
    let selected = match files("MODULE.bazel.lock") {
        Entry::Text(lock) => ModuleLock::parse(&lock),
        _ => ModuleLock::default(),
    };
    let asked = asked(ws, module);
    match (&asked, &selected.selected(module)[..]) {
        (Asked::Unknown(at), _) => Err(format!(
            "{at} of {module} socket-patch cannot tell which release of the ruleset Bazel builds \
             with, and the block was built with {module} {RULESET} alone"
        )),
        (_, [selected]) if asked.stale(selected) => Err(format!(
            "{FILE} asks for {module} {} and MODULE.bazel.lock holds {selected}: build once so \
             that Bazel updates its lock",
            asked.wanted()
        )),
        (_, [selected]) if *selected != RULESET => Err(format!(
            "Bazel selected {module} {selected}, and the block was built with {module} {RULESET} \
             alone"
        )),
        (_, [_]) => Ok(()),
        _ => Err(format!(
            "MODULE.bazel.lock does not say which release of {module} Bazel selected: build once \
             so that Bazel writes its lock"
        )),
    }?;
    match declared_release(files) {
        Some(release) if BAZELS.contains(&release) => Ok(()),
        Some((major, minor, patch)) => Err(format!(
            "the checkout names Bazel {major}.{minor}.{patch} (`.bazeliskrc` or `.bazelversion`), \
             and {BUILT_ON}"
        )),
        None => Err(format!(
            "no file of the checkout names the Bazel release that builds it, and {BUILT_ON}: \
             name the release in `.bazelversion`"
        )),
    }?;
    let unfetched = "under which Bazel may not take the committed package";
    let remote = "which the block was not built with: a remote downloader takes no `file:` feed";
    let words = [
        "repository_disable_download",
        "vendor_dir",
        "remote_downloader",
    ];
    match mentions(files, &words) {
        Ok(named) => named
            .into_iter()
            .next()
            .map_or(Ok(()), |(file, line, word)| {
                let why = match word.contains(words[2]) {
                    true => remote,
                    false => unfetched,
                };
                Err(format!("{file}:{line} names `{word}`, {why}"))
            }),
        Err(file) => Err(format!(
            "the rc file {file} cannot be read, and may name an option {unfetched}"
        )),
    }?;
    Ok(Feeds {
        label,
        name,
        lock,
        sources,
    })
}

/// The package sources of the `nuget.config` text `config` as rules_csharp
/// reads them (`_parse_nuget_config` in `csharp/extensions.bzl` at 0.5.0):
/// between the first `<packageSources>` and the `</packageSources>` after
/// it, line by line, the `value` of each line that starts with `<add`, in
/// double quotes or else in single ones, as it is written; a `<clear`
/// drops those before it. No comment is passed over, and no entity is
/// decoded.
fn sources(config: &str) -> Vec<String> {
    let inside = config.split_once("<packageSources>");
    let inside = inside.and_then(|(_, rest)| rest.split_once("</packageSources>"));
    let mut sources = Vec::new();
    for line in inside.map_or("", |(inside, _)| inside).split(['\n', '\r']) {
        let line = line.trim();
        let value = |quote: char| {
            let (_, value) = line.split_once(&format!("value={quote}"))?;
            Some(value.split_once(quote)?.0.to_string())
        };
        if line.starts_with("<clear") || line.contains("<clear/>") || line.contains("<clear />") {
            sources.clear();
        } else if line.starts_with("<add") {
            let value = value('"').or_else(|| value('\''));
            sources.extend(value.filter(|value| !value.is_empty()));
        }
    }
    sources
}

/// The block for `feeds` and `folders`, the folders of the vendored
/// packages from the Bazel root, from [`BEGIN`] to [`END`], with a line
/// feed between its lines. The folders come first: the hub asks its feeds
/// in their order. `bazel mod tidy` keeps this text.
fn render(feeds: &Feeds, folders: &[String]) -> String {
    let folders = folders.iter().map(|folder| format!("file:{folder}"));
    let listed: String = folders
        .chain(feeds.sources.iter().cloned())
        .map(|feed| format!("        \"{feed}\",\n"))
        .collect();
    let name = feeds
        .name
        .as_ref()
        .map(|name| format!("    name = \"{name}\",\n"));
    format!(
        "{BEGIN}\n{PROXY} = use_extension(\"{}\", \"nuget\")\n{PROXY}.from_lock(\n    \
         feeds = [\n{listed}    ],\n{}    packages_lock_json = \"{}\",\n)\n{END}",
        feeds.label,
        name.unwrap_or_default(),
        feeds.lock
    )
}

/// What a `MODULE.bazel` holds of the block.
#[derive(Debug, PartialEq, Eq)]
enum Block {
    None,
    /// The block as socket-patch writes it: where it is, and what it
    /// holds, the folders apart.
    Ours(Range<usize>, Feeds, Vec<String>),
    /// A block that is not what socket-patch writes for what it names:
    /// the line of its [`BEGIN`].
    Edited(usize),
}

fn find(text: &str) -> Block {
    let (at, line) = match block::find(text, BEGIN) {
        Found::None => return Block::None,
        Found::Edited(line) => return Block::Edited(line),
        Found::At(at, line) => (at, line),
    };
    let lines: Vec<&str> = text[at.clone()].lines().collect();
    let between = |open: &str, close: &str| {
        let inside = |line: &&str| Some(line.strip_prefix(open)?.strip_suffix(close)?.to_string());
        lines.iter().filter_map(inside).collect::<Vec<String>>()
    };
    let one = |open: &str, close: &str| between(open, close).into_iter().next();
    let label = one(&format!("{PROXY} = use_extension(\""), "\", \"nuget\")");
    let lock = one("    packages_lock_json = \"", "\",");
    let listed = between("        \"", "\",").into_iter();
    let (folders, sources): (Vec<String>, Vec<String>) =
        listed.partition(|feed| feed.starts_with(FOLDER));
    let folders: Vec<String> = folders
        .iter()
        .map(|feed| feed["file:".len()..].into())
        .collect();
    let ours = label.zip(lock).map(|(label, lock)| Feeds {
        label,
        name: one("    name = \"", "\","),
        lock,
        sources,
    });
    let ours = ours.filter(|feeds| block::is(text, &at, &render(feeds, &folders)));
    ours.map_or(Block::Edited(line), |feeds| Block::Ours(at, feeds, folders))
}

/// `module`, the text of the root `MODULE.bazel`, with the folder `folder`
/// of a vendored package (from the Bazel root) in the block for `feeds`:
/// in the block that is there, which then holds what `feeds` holds now, or
/// in a new one at the end of the file ([`block::put`]). The folders of
/// `superseded`, those of earlier patches of the same package, go out of
/// the block: the hub asks its feeds in their order, and such a folder no
/// longer holds what the lock pins. `None` when the block that is there
/// was changed by hand.
pub fn with_folder(
    module: &str,
    feeds: &Feeds,
    folder: &str,
    superseded: &[String],
) -> Option<String> {
    let (at, mut folders) = match find(module) {
        Block::Edited(_) => return None,
        Block::None => (None, Vec::new()),
        Block::Ours(at, _, folders) => (Some(at), folders),
    };
    folders.retain(|other| other != folder && !superseded.contains(other));
    folders.push(folder.to_string());
    folders.sort();
    Some(block::put(module, at, &render(feeds, &folders)))
}

/// `module` without the folder `folder` in its block. With the last folder
/// the block goes, and what [`with_folder`] put before it: the file is then
/// byte for byte what it was before its first folder. A file without a
/// block is given as it is. `Err` when the block was changed by hand: the
/// line of the file at which it starts.
pub fn without_folder(module: &str, folder: &str) -> Result<String, usize> {
    let (at, feeds, mut folders) = match find(module) {
        Block::Edited(line) => return Err(line),
        Block::None => return Ok(module.to_string()),
        Block::Ours(at, feeds, folders) => (at, feeds, folders),
    };
    folders.retain(|other| other != folder);
    Ok(match folders.is_empty() {
        true => block::cut(module, at),
        false => block::put(module, Some(at), &render(&feeds, &folders)),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::starlark::MAX_BYTES;
    use super::super::workspace::Entry;
    use super::*;

    /// The tag of the fixture that hosted mode patches on a real Bazel, and
    /// the same tag without its `nuget_config`.
    pub(crate) const WIRED: &str = r#"nuget.from_lock(
    nuget_config = "//:nuget.config",
    packages_lock_json = "//:packages.lock.json",
)"#;
    const BARE: &str = "nuget.from_lock(packages_lock_json = \"//:packages.lock.json\")";
    /// How a file that asks for the extension starts.
    const PROXY: &str =
        "nuget = use_extension(\"@rules_csharp//csharp:extensions.bzl\", \"nuget\")\n";

    /// A root `MODULE.bazel` that asks for the extension as `nuget` and
    /// goes on with `rest`.
    fn module(rest: &str) -> String {
        format!(
            "module(name = \"shop\", version = \"0.0.0\")\n\
             bazel_dep(name = \"rules_csharp\", version = \"0.5.0\")\n\
             {PROXY}{rest}\nuse_repo(nuget, \"nuget\")\n"
        )
    }

    /// What [`judge`] makes of the project in the directory `dir` (empty,
    /// or with a `/` at its end), with its `nuget.config` and its one
    /// lock, in the workspace of `files`.
    fn hub(files: &[(&str, &str)], dir: &str) -> Option<Hub> {
        let view = |path: &str| match files.iter().find(|(name, _)| *name == path) {
            Some((_, text)) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        };
        let lock = ["packages.lock.json".to_string()];
        judge(
            &Workspace::read(&view),
            dir,
            "nuget.config",
            &lock,
            false,
            true,
        )
    }

    /// What stands against the config there ([`Hub::why`]).
    fn said(files: &[(&str, &str)], dir: &str) -> Option<String> {
        hub(files, dir)?.why
    }

    /// [`said`] for the project at the root of a workspace whose
    /// `MODULE.bazel` is [`module`] with `rest`.
    fn at_root(rest: &str) -> Option<String> {
        said(&[("MODULE.bazel", &module(rest))], "")
    }

    /// How every answer goes on after what stands against the config, and
    /// how one ends that has the same command write the project's config.
    const WHERE: &str = ", where hosted mode names the Socket source of a patch; without that \
                         source rules_csharp downloads the upstream package, and the Bazel build \
                         fails on the `contentHash` that hosted mode re-pins in the lock. So \
                         hosted mode wrote nothing for it. ";
    const AGAIN: &str = " and run this command again: it then names the source in nuget.config, \
                         which it creates where there is none, and the Bazel build takes the \
                         patched package";
    const ATTRIBUTE: &str = "`nuget_config = \"//:nuget.config\"`";

    #[test]
    fn hosted_mode_writes_where_the_hub_reads_the_config_or_no_tag_reads_the_lock() {
        let another = "nuget.from_lock(packages_lock_json = \"//api:packages.lock.json\")";
        let theirs = WIRED.replace("//:", "//api:");
        let feeds = "feeds = [\"https://feed.example/v3/index.json\"],\n    nuget_config";
        for rest in [
            // The tag names the config: as the fixture has it, by the name
            // of the root module, by the main repository, in another case.
            WIRED.to_string(),
            WIRED.replace("//:nuget", "@shop//:nuget"),
            WIRED.replace("//:nuget", "@//:nuget"),
            WIRED.replace("nuget.config", "NuGet.Config"),
            // And with a lock that cannot be read.
            WIRED.replace("\"//:packages.lock.json\"", "LOCK"),
            // No tag reads the lock: there is none, it reads the lock of
            // another project or of another repository, or it names none.
            String::new(),
            another.to_string(),
            BARE.replace("//:", "@other//:"),
            "nuget.from_lock()".to_string(),
            // A doubt of the reader can only hide a tag: it changes
            // nothing, whether a tag reads the lock or not.
            format!("{another}\nMORE = [nuget]"),
            format!("{WIRED}\nMORE = [nuget]"),
            format!("{WIRED}\ninclude(NAME)"),
            format!("{WIRED}\ninclude(\"//:gone.MODULE.bazel\")"),
            // One list of sources for the whole extension, and the last
            // tag that has any decides: another tag names the config, the
            // project's own tag comes after one that names another file,
            // and the config of a tag stands in the place of its feeds.
            format!("{BARE}\n{}", WIRED.replace("//:p", "//api:p")),
            format!("{theirs}\n{WIRED}"),
            format!("{}\n{WIRED}", another.replace(")", ", feeds = [])")),
            WIRED.replace("nuget_config", feeds),
            // What a directory holds is not seen.
            WIRED.replace(
                "nuget_config",
                "local_package_dirs = [\"/opt\"],\n    nuget_config",
            ),
        ] {
            assert_eq!(at_root(&rest), None, "{rest}");
        }
        // A `bazel_dep` that cannot be read, beside the fixture's tag.
        let renamed = module(WIRED).replace(
            "\"0.5.0\")",
            "\"0.5.0\", repo_name = \"rules_\" + \"csharp\")",
        );
        assert_eq!(said(&[("MODULE.bazel", &renamed)], ""), None);
        // Another extension of that name, and a workspace with no tag of
        // the extension, with a `WORKSPACE` file beside it.
        let theirs = module(BARE).replace("@rules_csharp//csharp", "@rules_other//csharp");
        assert_eq!(hub(&[("MODULE.bazel", &theirs)], ""), None);
        let legacy = [
            ("MODULE.bazel", ""),
            ("WORKSPACE", "nuget_repo(name = \"nuget\")\n"),
        ];
        assert_eq!(hub(&legacy, ""), None);
    }

    #[test]
    fn a_tag_that_reads_the_lock_without_the_config_withholds_and_names_the_way_on() {
        let none = "this `nuget.from_lock` names no `nuget_config`, so rules_csharp does not read \
                    nuget.config";
        let bare = format!("MODULE.bazel:4: {none}{WHERE}Put {ATTRIBUTE} on that tag{AGAIN}");
        assert_eq!(at_root(BARE), Some(bare.clone()));
        // A tag whose lock cannot be read may read the project's. The
        // package of the config is then not known, and the file is named.
        let computed = BARE.replace("\"//:packages.lock.json\"", "LOCK");
        let file = bare.replace(ATTRIBUTE, "a `nuget_config` that names nuget.config");
        assert_ne!(file, bare);
        assert_eq!(at_root(&computed), Some(file));
        // What a directory of the tag holds is asked before every source.
        let dirs = BARE.replace(")", ", local_package_dirs = [\"/opt/packages\"])");
        let first = "; rules_csharp asks the directories of `local_package_dirs` before every \
                     source, so the upstream package must not lie in one";
        assert_eq!(at_root(&dirs), Some(bare + first));

        // A tag with feeds: the config would stand in their place.
        let feeds = BARE.replace(")", ", feeds = [\"https://feed.example/v3/index.json\"])");
        let has = "this `nuget.from_lock` has `feeds` and no `nuget_config`, so rules_csharp \
                   does not read nuget.config";
        let way = format!(
            "Put {ATTRIBUTE} on that tag, name its `feeds` in nuget.config (rules_csharp takes \
             the package sources of a `nuget_config` in place of `feeds`){AGAIN}"
        );
        let answer = at_root(&feeds).expect("feeds");
        assert_eq!(answer, format!("MODULE.bazel:4: {has}{WHERE}{way}"));
        // Also when it reads another lock, after the project's own tag.
        let later = feeds.replace("//:", "//api:");
        let answer = at_root(&format!("{WIRED}\n{later}")).expect("later feeds");
        assert_eq!(answer, format!("MODULE.bazel:8: {has}{WHERE}{way}"));

        // A tag that names another file, in this repository or in another:
        // the answer names it as it is written, and where. Its sources
        // have to go with the tag.
        let names = |other: &str| {
            format!(
                "this `nuget.from_lock` names `{other}` as its `nuget_config`, not nuget.config"
            )
        };
        let way = |other: &str| {
            format!(
                "Put {ATTRIBUTE} on that tag, name in nuget.config the package sources of \
                 `{other}` that the build needs (rules_csharp takes its package sources from one \
                 file){AGAIN}"
            )
        };
        for other in [
            "//config:nuget.config",
            "@other//:nuget.config",
            ":nuget.config.in",
        ] {
            let answer = at_root(&WIRED.replace("//:nuget.config", other)).expect(other);
            let whole = format!("MODULE.bazel:4: {}{WHERE}{}", names(other), way(other));
            assert_eq!(answer, whole);
        }
        // The last tag that has sources decides: one that reads another
        // lock and names another config, after the project's own tag.
        let theirs = WIRED.replace("//:", "//api:");
        let other = "//api:nuget.config";
        let last = format!("MODULE.bazel:8: {}{WHERE}{}", names(other), way(other));
        assert_eq!(at_root(&format!("{WIRED}\n{theirs}")), Some(last));
        // In two files their order is not known: the tag that names another
        // config stands against the pin wherever it is.
        let included = format!("{PROXY}{WIRED}\n");
        let root = module(&format!("{theirs}\ninclude(\"//:more.MODULE.bazel\")"));
        let files = [
            ("MODULE.bazel", root.as_str()),
            ("more.MODULE.bazel", included.as_str()),
        ];
        let first = format!("MODULE.bazel:4: {}{WHERE}{}", names(other), way(other));
        assert_eq!(said(&files, ""), Some(first));
    }

    #[test]
    fn a_config_above_the_project_is_written_by_a_run_in_its_directory() {
        let tag = |config: &str| {
            let lock = "packages_lock_json = \"//svc/app:packages.lock.json\"";
            module(&format!(
                "nuget.from_lock(nuget_config = \"{config}\", {lock})"
            ))
        };
        let there = "Run this command in the directory of that file (`--cwd`): it then names the \
                     source there, and the Bazel build takes the patched package";
        for (config, above) in [
            ("//:nuget.config", true),
            ("//svc:NuGet.Config", true),
            ("//:svc/nuget.config", true),
            // Beside the project, below it, and no config of NuGet's.
            ("//svc/web:nuget.config", false),
            ("//svc/app/obj:nuget.config", false),
            ("//:nuget.config.in", false),
        ] {
            let said = said(&[("MODULE.bazel", &tag(config))], "svc/app/").expect(config);
            let names = format!(
                "MODULE.bazel:4: this `nuget.from_lock` names `{config}` as its `nuget_config`, \
                 not svc/app/nuget.config{WHERE}"
            );
            assert!(said.starts_with(&names), "{said}");
            assert_eq!(said.ends_with(&format!(". {there}")), above, "{said}");
            let put = "Put `nuget_config = \"//svc/app:nuget.config\"` on that tag, name in \
                       svc/app/nuget.config the package sources of";
            assert_eq!(said.contains(put), !above, "{said}");
        }
    }

    #[test]
    fn the_config_is_named_by_a_label_of_the_workspace() {
        // A project below the root whose directory is a package of its
        // own, part of the root package, and part of the package above it;
        // the tag in a file the root includes.
        for (lock, label) in [
            ("//svc/app:packages.lock.json", "//svc/app:nuget.config"),
            ("//:svc/app/packages.lock.json", "//:svc/app/nuget.config"),
            ("//svc:app/packages.lock.json", "//svc:app/nuget.config"),
        ] {
            let tag = format!("nuget.from_lock(packages_lock_json = \"{lock}\")");
            let included = format!("{PROXY}{tag}\n");
            let root = ("MODULE.bazel", "include(\"//svc:nuget.MODULE.bazel\")\n");
            let files = [root, ("svc/nuget.MODULE.bazel", included.as_str())];
            let answer = said(&files, "svc/app/").expect(lock);
            let starts = "svc/nuget.MODULE.bazel:2: this `nuget.from_lock` names no";
            assert!(answer.starts_with(starts), "{answer}");
            let names = "does not read svc/app/nuget.config, where";
            assert!(answer.contains(names), "{answer}");
            let way = format!(". Put `nuget_config = \"{label}\"` on that tag and run");
            assert!(answer.contains(&way), "{lock}: {answer}");
            // With it, nothing is withheld, and neither is the project
            // beside it, whose lock no tag reads.
            let wired = tag.replace("(", &format!("(nuget_config = \"{label}\", "));
            let included = included.replace(&tag, &wired);
            let files = [root, ("svc/nuget.MODULE.bazel", included.as_str())];
            for dir in ["svc/app/", "svc/web/", ""] {
                assert_eq!(hub(&files, dir), None, "{lock} {dir}");
            }
        }
        // A lock below the config's directory, in a package of its own.
        let tag = "nuget.from_lock(packages_lock_json = \"//svc/app:packages.lock.json\")";
        let view = |path: &str| match path {
            "MODULE.bazel" => Entry::Text(module(tag)),
            _ => Entry::Absent,
        };
        let (ws, lock) = (
            Workspace::read(&view),
            ["app/packages.lock.json".to_string()],
        );
        let said = judge(&ws, "svc/", "nuget.config", &lock, false, true).expect("withheld");
        let way = "Put a `nuget_config` that names svc/nuget.config on that tag";
        assert!(said.why.expect("why").contains(way));
        // A label in another case names the config, unless the directory
        // holds both spellings.
        let view = |path: &str| match path {
            "MODULE.bazel" => Entry::Text(module(&WIRED.replace("nuget.config", "NuGet.Config"))),
            _ => Entry::Absent,
        };
        let (ws, lock) = (Workspace::read(&view), ["packages.lock.json".to_string()]);
        assert_eq!(judge(&ws, "", "nuget.config", &lock, false, true), None);
        let said = judge(&ws, "", "nuget.config", &lock, true, true).and_then(|hub| hub.why);
        let said = said.expect("another file");
        let names = "names `//:NuGet.Config` as its `nuget_config`, not nuget.config";
        assert!(said.contains(names), "{said}");
        assert!(
            said.contains(&format!(". Put {ATTRIBUTE} on that tag, name in")),
            "{said}"
        );
    }

    #[test]
    fn a_tag_that_is_not_written_out_withholds_and_says_so() {
        for rest in [
            WIRED.replace("\"//:nuget.config\"", "CONFIG"),
            "nuget.from_lock(**TAG)".to_string(),
            format!("[{} for _ in [0]]", WIRED.replace('\n', " ")),
            format!("True and {}", WIRED.replace('\n', " ")),
            // Also beside the project's own tag, which names the config.
            format!("{WIRED}\nnuget.from_lock(**TAG)"),
        ] {
            let said = at_root(&rest).unwrap_or_else(|| panic!("not withheld: {rest}"));
            let line = 4 + rest.matches(WIRED).count() * 4;
            // The tag that reads the lock names it plainly, or none does.
            let attribute = match rest.contains("//:packages.lock.json") {
                true => ATTRIBUTE,
                false => "a `nuget_config` that names nuget.config",
            };
            let whole = format!(
                "MODULE.bazel:{line}: this `nuget.from_lock` {NOT_PLAIN}, so socket-patch cannot \
                 tell whether rules_csharp reads nuget.config{WHERE}Write that plainly, with \
                 {attribute} on the tag,{AGAIN}"
            );
            assert_eq!(said, whole, "{rest}");
        }
    }

    /// A lock that resolves `id` to version 1.0.0 with `hash`.
    fn lock(id: &str, hash: &str) -> Option<String> {
        let entry = format!("{{\"resolved\": \"1.0.0\", \"contentHash\": \"{hash}\"}}");
        Some(format!(
            "{{\"dependencies\": {{\"net8.0\": {{\"{id}\": {entry}}}}}}}"
        ))
    }

    #[test]
    fn the_locks_of_the_other_tags_are_listed_in_the_order_of_the_hub() {
        let lib = WIRED.replace("//:p", "//lib:p");
        let other = |line: usize| {
            let at = format!("MODULE.bazel:{line}");
            Read::Other(at, "lib/packages.lock.json".to_string(), None)
        };
        let ours = || Read::Ours("packages.lock.json".to_string());
        let read = |rest: &str| hub(&[("MODULE.bazel", &module(rest))], "").expect(rest);
        // The config is read: the answer is about the other lock alone.
        let computed = BARE.replace("\"//:packages.lock.json\"", "LOCK");
        let listed = read(&format!("{lib}\n{WIRED}\n{computed}"));
        assert_eq!((listed.why, listed.ordered), (None, true));
        let unnamed = Read::Any("MODULE.bazel:12".to_string());
        assert_eq!(listed.locks, [other(4), ours(), unnamed]);
        // And about the config as well.
        let listed = read(&format!("{BARE}\n{}", lib.replace("//:n", "//lib:n")));
        assert_eq!((listed.why.is_some(), listed.ordered), (true, true));
        assert_eq!(listed.locks, [ours(), other(5)]);
        // Two files: the order of their tags is not known.
        let included = format!("{PROXY}{lib}\n");
        let root = module(&format!("{WIRED}\ninclude(\"//:more.MODULE.bazel\")"));
        let files = [
            ("MODULE.bazel", root.as_str()),
            ("more.MODULE.bazel", included.as_str()),
        ];
        assert!(!hub(&files, "").expect("two files").ordered);
    }

    #[test]
    fn a_package_that_another_lock_of_the_hub_holds_unpinned_is_withheld() {
        let other = |text: Option<String>| Read::Other("M:4".into(), "lib/p.json".into(), text);
        let ours = || Read::Ours("p.json".to_string());
        // What the run re-pins: the package in the project's lock, or not.
        let against = |locks: Vec<Read>, ordered: bool, pinned: bool| {
            let why = Some("why".to_string());
            let hub = Hub {
                why,
                every: false,
                locks,
                ordered,
            };
            let said = hub.against(&hub.docs(), &|_| pinned, "newtonsoft.json", "1.0.0", "NEW");
            said.map(|(code, why)| (code, why.starts_with("M:4: ") || why == "why"))
        };
        let any = || Read::Any("M:4".to_string());
        let (config, elsewhere) = (
            Some((CONFIG_UNDECLARED, true)),
            Some((LOCK_NOT_REPINNED, true)),
        );
        let upstream = || lock("Newtonsoft.Json", "OLD");
        for (locks, ordered, pinned, said) in [
            // The hub has the package from the other lock first.
            (vec![other(upstream()), ours()], true, true, elsewhere),
            // From the project's lock first, when the order is known.
            (vec![ours(), other(upstream())], true, true, config),
            (vec![ours(), other(upstream())], false, true, elsewhere),
            // The project's lock does not hold it: the other is the first.
            (vec![ours(), other(upstream())], true, false, elsewhere),
            (vec![any(), other(upstream())], true, true, elsewhere),
            // A lock that cannot be read may hold it.
            (vec![other(None), ours()], true, true, elsewhere),
            (vec![other(Some("{".into())), ours()], true, true, elsewhere),
            // The other lock holds the patched package, another package,
            // or another version, which is then the one the hub takes
            // whatever a later lock holds.
            (
                vec![other(lock("Newtonsoft.Json", "NEW")), ours()],
                true,
                true,
                config,
            ),
            (
                vec![other(lock("Other", "OLD")), ours()],
                true,
                true,
                config,
            ),
            (
                vec![
                    other(upstream().map(|l| l.replace("1.0.0", "2.0.0"))),
                    other(upstream()),
                ],
                true,
                false,
                None,
            ),
            // A package in no lock that the hub reads and the run re-pins
            // is written as without Bazel.
            (vec![ours()], true, false, None),
            (vec![any()], true, false, None),
            (vec![any()], true, true, config),
            // Beside a tag that names the project's lock, a tag whose lock
            // cannot be read reads another one, which may hold the package
            // first.
            (vec![any(), ours()], true, true, elsewhere),
            (vec![ours(), any()], true, true, config),
            (vec![ours(), any()], true, false, elsewhere),
            (vec![ours(), any()], false, true, elsewhere),
        ] {
            assert_eq!(against(locks, ordered, pinned), said);
        }
        let hub = Hub {
            why: None,
            every: false,
            locks: vec![other(None), ours()],
            ordered: true,
        };
        let (_, said) = hub
            .against(&hub.docs(), &|_| true, "a", "1.0.0", "NEW")
            .expect("withheld");
        assert_eq!(
            said,
            "M:4: this `nuget.from_lock` reads lib/p.json, which cannot be read and may hold the \
             package and which this run does not re-pin; rules_csharp holds a package to the \
             `contentHash` of the first lock that names it, so the Bazel build can fail on the \
             patched package. So hosted mode wrote nothing for it. Run this command in a \
             directory above both locks that holds a solution file or a `nuget.config` (`--cwd`): \
             there it re-pins the lock of every project"
        );
        // Where the config is read and no other lock stands against it,
        // nothing is withheld.
        let read = Hub {
            locks: vec![ours()],
            ..hub
        };
        assert_eq!(read.against(&[None], &|_| true, "a", "1.0.0", "NEW"), None);
        // The tag whose lock is not named, before the project's own.
        let unnamed = Hub {
            locks: vec![any(), ours()],
            ..read
        };
        let (code, said) = unnamed
            .against(&unnamed.docs(), &|_| true, "a", "1.0.0", "NEW")
            .expect("withheld");
        assert_eq!(code, LOCK_NOT_REPINNED);
        assert_eq!(
            said,
            "M:4: this `nuget.from_lock` names its lock in no plain string, so that lock may \
             hold the package and may be one this run does not re-pin; rules_csharp holds a \
             package to the `contentHash` of the first lock that names it, so the Bazel build \
             can fail on the patched package. So hosted mode wrote nothing for it. Write its \
             `packages_lock_json` as a label in a plain string and run this command again"
        );
    }

    #[test]
    fn a_config_without_a_source_does_not_take_the_place_of_feeds() {
        let feeds = "feeds = [\"https://feed.example/v3/index.json\"]";
        let both = WIRED.replace("nuget_config", &format!("{feeds},\n    nuget_config"));
        let earlier = format!(
            "nuget.from_lock({feeds}, packages_lock_json = \"//api:packages.lock.json\")\n{WIRED}"
        );
        let judged = |rest: &str, sources: bool| {
            let view = |path: &str| match path {
                "MODULE.bazel" => Entry::Text(module(rest)),
                _ => Entry::Absent,
            };
            let lock = ["packages.lock.json".to_string()];
            judge(
                &Workspace::read(&view),
                "",
                "nuget.config",
                &lock,
                false,
                sources,
            )
        };
        let why = |rest: &str, sources: bool| judged(rest, sources).and_then(|hub| hub.why);
        // The config has a source: it stands in the place of the feeds
        // already, and hosted mode adds its own.
        assert_eq!(judged(&both, true), None);
        assert_eq!(why(&earlier, true), None);
        // No tag has feeds: the hub has nuget.org alone, with or without it.
        assert_eq!(judged(WIRED, false), None);
        // It has none: the first source in it would drop the feeds.
        for rest in [&both, &earlier] {
            assert_eq!(
                why(rest, false).expect("withheld"),
                "MODULE.bazel:4: this `nuget.from_lock` has `feeds`, and nuget.config names no \
                 package source: with the Socket source that hosted mode names there, \
                 rules_csharp takes the package sources of nuget.config in place of those \
                 `feeds`, and the Bazel build cannot download a package that only they hold. So \
                 hosted mode wrote nothing for it. Name those `feeds` in nuget.config and run \
                 this command again, and the Bazel build takes the patched package"
            );
        }
        // The config is the hub's: no package of the run may put a source
        // in it, also one that no lock the hub reads holds.
        let hub = judged(&both, false).expect("withheld");
        let said = hub.against(&hub.docs(), &|_| false, "a", "1.0.0", "NEW");
        assert_eq!(said.map(|(code, _)| code), Some(CONFIG_UNDECLARED));
        let hub = Hub {
            every: false,
            ..hub
        };
        assert_eq!(
            hub.against(&hub.docs(), &|_| false, "a", "1.0.0", "NEW"),
            None
        );
    }

    #[test]
    fn a_project_is_read_from_its_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let project = root.join("svc/app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir(root.join(".git")).unwrap();
        let lock = ["packages.lock.json".to_string()];
        // The config as the rewriter names it: the first of NuGet's
        // spellings that the directory answers to.
        let read = |project: &Path| {
            let named = NAMES.iter().find(|name| project.join(name).exists());
            let hub = withheld(project, named.unwrap_or(&NAMES[0]), &lock)?;
            Some(serde_json::from_str::<Hub>(&hub).expect("a hub"))
        };
        // No Bazel workspace.
        assert_eq!(read(&project), None);
        let tag = "nuget.from_lock(packages_lock_json = \"//svc/app:packages.lock.json\")";
        let lib = tag.replace("svc/app", "lib");
        std::fs::write(root.join("MODULE.bazel"), module(&format!("{tag}\n{lib}"))).unwrap();
        let hub = read(&project).expect("withheld");
        let said = hub.why.expect("why");
        assert!(
            said.contains("does not read svc/app/nuget.config"),
            "{said}"
        );
        // The lock of the other tag is read, when there is one.
        let other = |text: Option<&str>| {
            let (at, path) = ("MODULE.bazel:5", "lib/packages.lock.json");
            Read::Other(at.into(), path.into(), text.map(String::from))
        };
        assert_eq!(hub.locks, [Read::Ours(lock[0].clone()), other(None)]);
        std::fs::create_dir(root.join("lib")).unwrap();
        std::fs::write(root.join("lib/packages.lock.json"), "{}").unwrap();
        assert_eq!(
            read(&project).expect("withheld").locks[1],
            other(Some("{}"))
        );
        // The config is named as the directory spells it.
        std::fs::write(project.join("NuGet.Config"), "").unwrap();
        let said = read(&project).and_then(|hub| hub.why).expect("withheld");
        let spelled = "does not read svc/app/NuGet.Config, where";
        assert!(said.contains(spelled), "{said}");
        let label = "Put `nuget_config = \"//svc/app:NuGet.Config\"` on that tag";
        assert!(said.contains(label), "{said}");
        // Where the disk holds two spellings, a tag that names the other
        // one does not name the config.
        std::fs::write(project.join("nuget.config"), "").unwrap();
        let wired = tag.replace("(", "(nuget_config = \"//svc/app:NuGet.Config\", ");
        std::fs::write(root.join("MODULE.bazel"), module(&wired)).unwrap();
        let two = std::fs::read_dir(&project).unwrap().count() == 2;
        assert_eq!(read(&project).is_some(), two);
        // A spelling that is not NuGet's is the rewriter's file only on a
        // disk that folds case; elsewhere the rewriter writes a file of
        // its own, and a tag that names the other one does not read it.
        for name in ["nuget.config", "NuGet.Config"] {
            std::fs::remove_file(project.join(name)).ok();
        }
        std::fs::write(project.join("Nuget.Config"), "").unwrap();
        let folds = project.join("nuget.config").exists();
        let odd = wired.replace("NuGet.Config", "Nuget.Config");
        std::fs::write(root.join("MODULE.bazel"), module(&odd)).unwrap();
        assert_eq!(read(&project).is_some(), !folds);
        // The config has no source: a tag with `feeds` keeps them until
        // it has.
        let fed = odd.replace("(", "(feeds = [\"https://feed.example/v3/index.json\"], ");
        std::fs::write(root.join("MODULE.bazel"), module(&fed)).unwrap();
        let said = read(&project).and_then(|hub| hub.why).expect("withheld");
        let stands = match folds {
            true => "has `feeds`, and svc/app/Nuget.Config names no package source",
            false => "as its `nuget_config`, not svc/app/nuget.config",
        };
        assert!(said.contains(stands), "{said}");
        let source = "<configuration><packageSources><add key=\"a\" value=\"https://a.example\" />\
                      </packageSources></configuration>";
        std::fs::write(project.join("Nuget.Config"), source).unwrap();
        assert_eq!(read(&project).is_some(), !folds);
        // The project at the root, whose lock the tag does not read. And
        // a project without a lock, which no tag can read: not the one
        // whose name cannot be read either.
        assert_eq!(read(&root), None);
        let computed = "nuget.from_lock(packages_lock_json = LOCK)";
        std::fs::write(root.join("MODULE.bazel"), module(computed)).unwrap();
        assert!(read(&root).is_some());
        assert_eq!(withheld(&root, "nuget.config", &[]), None);
    }

    /// What a checkout holds beside its `MODULE.bazel` where the block can
    /// be shown to work: Bazel's lock, which says that rules_csharp 0.5.0
    /// was selected, the release of the Bazel that builds it, and the
    /// config the fixture's tag names.
    const SELECTED: &str = r#"{"lockFileVersion": 28, "registryFileHashes": {
        "https://bcr.bazel.build/modules/rules_csharp/0.5.0/source.json": "sum"}}"#;
    const CONFIG: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
"#;
    const NUGET_ORG: &str = "https://api.nuget.org/v3/index.json";
    /// A config whose one source is a folder of vendored mode.
    const OWN: &str = "<packageSources>\n<add key=\"socket-patch-x\" \
                       value=\".socket/vendor/nuget/x/a/1.0.0\" />\n</packageSources>";
    const LABEL: &str = "@rules_csharp//csharp:extensions.bzl";

    /// For the tests of what vendors a package elsewhere: makes `dir` the
    /// root of a Bazel workspace whose one tag reads the project's lock and
    /// config, where the block can be shown to work. Gives its
    /// `MODULE.bazel`.
    pub(crate) fn checkout(dir: &Path) -> String {
        let module = module(WIRED);
        let files = [
            (FILE, module.as_str()),
            ("MODULE.bazel.lock", SELECTED),
            (".bazelversion", "9.3.2\n"),
        ];
        for (name, text) in files {
            std::fs::write(dir.join(name), text).unwrap();
        }
        module
    }

    /// What [`gate`] makes of the project at the root of the workspace
    /// whose `MODULE.bazel` is [`module`] with `rest`, beside the files of
    /// a checkout whose block works, with `more` in the place of those of
    /// the same name (`None`: the file is not there).
    fn gated(rest: &str, more: &[(&str, Option<&str>)]) -> Vendored {
        let module = module(rest);
        let files = [
            (FILE, module.as_str()),
            ("MODULE.bazel.lock", SELECTED),
            (".bazelversion", "9.3.2\n"),
            ("nuget.config", CONFIG),
        ];
        let view = |path: &str| {
            let given = more.iter().find(|(name, _)| *name == path);
            let text = match given {
                Some((_, text)) => *text,
                None => files.iter().find(|(name, _)| *name == path).map(|f| f.1),
            };
            text.map_or(Entry::Absent, |text| Entry::Text(text.to_string()))
        };
        let lock = ["packages.lock.json".to_string()];
        gate(&Workspace::read(&view), &view, "", &lock)
    }

    /// The block of [`gated`], when it is one.
    fn block_of(rest: &str, more: &[(&str, Option<&str>)]) -> Feeds {
        match gated(rest, more) {
            Vendored::Block(feeds) => feeds,
            other => panic!("{rest}: {other:?}"),
        }
    }

    fn feeds(name: Option<&str>, sources: &[&str]) -> Feeds {
        Feeds {
            label: LABEL.to_string(),
            name: name.map(String::from),
            lock: "//:packages.lock.json".to_string(),
            sources: sources.iter().map(|source| source.to_string()).collect(),
        }
    }

    #[test]
    fn the_block_holds_what_the_hub_has_without_it() {
        // The sources of the tag's config, as the fixture has them.
        assert_eq!(block_of(WIRED, &[]), feeds(None, &[NUGET_ORG]));
        // A tag without a config, and one with feeds: nothing, the feeds.
        assert_eq!(block_of(BARE, &[]), feeds(None, &[]));
        let fed = BARE.replace(")", ", feeds = [\"https://a.example/v3/index.json\"])");
        let a = ["https://a.example/v3/index.json"];
        assert_eq!(block_of(&fed, &[]), feeds(None, &a));
        // The sources of a config stand in the place of the feeds. The
        // folders vendored mode names there are none of the hub's.
        let both = WIRED.replace(
            "nuget_config",
            "feeds = [\"https://a.example\"],\n    nuget_config",
        );
        assert_eq!(block_of(&both, &[]), feeds(None, &[NUGET_ORG]));
        let only_own = [("nuget.config", Some(OWN))];
        assert_eq!(block_of(WIRED, &only_own), feeds(None, &[]));
        let none = WIRED.replace("nuget_config", "feeds = [],\n    nuget_config");
        assert_eq!(block_of(&none, &only_own), feeds(None, &[]));
        // The name of the hub goes with it, and what changes nothing for
        // the block is passed over.
        let named = WIRED.replace(
            "nuget_config",
            "name = \"packages\",\n    use_public_sources = False,\n    nuget_config",
        );
        assert_eq!(block_of(&named, &[]), feeds(Some("packages"), &[NUGET_ORG]));
        // The label of the extension is the one the tag is called on.
        let renamed = module(WIRED)
            .replace("\"0.5.0\")", "\"0.5.0\", repo_name = \"csharp\")")
            .replace("@rules_csharp//", "@csharp//");
        let view = |path: &str| match path {
            FILE => Entry::Text(renamed.clone()),
            "MODULE.bazel.lock" => Entry::Text(SELECTED.to_string()),
            ".bazelversion" => Entry::Text("7.7.2\n".to_string()),
            "nuget.config" => Entry::Text(CONFIG.to_string()),
            _ => Entry::Absent,
        };
        let lock = ["packages.lock.json".to_string()];
        let Vendored::Block(read) = gate(&Workspace::read(&view), &view, "", &lock) else {
            panic!("no block");
        };
        assert_eq!(read.label, "@csharp//csharp:extensions.bzl");
    }

    #[test]
    fn a_project_whose_lock_no_tag_reads_is_vendored_as_without_bazel() {
        for rest in [
            String::new(),
            BARE.replace("//:", "//api:"),
            BARE.replace("//:", "@other//:"),
            "nuget.from_lock()".to_string(),
        ] {
            assert_eq!(gated(&rest, &[]), Vendored::Plain, "{rest}");
            // Also where the block could not be shown to work.
            let unnamed = [(".bazelversion", None)];
            assert_eq!(gated(&rest, &unnamed), Vendored::Plain, "{rest}");
        }
    }

    /// What was not read may hide the tag that reads the lock, and a
    /// package vendored as without Bazel is not among the feeds of that
    /// hub: its build would fail on the re-pinned lock. So where no tag
    /// is found, a doubt of the reader declines the package in a workspace
    /// that has to do with the ruleset, and a file that is there and was
    /// not read as a whole declines it in any workspace: that file may be
    /// the one that names the ruleset. A doubt in a workspace of other
    /// rulesets whose files were all read is about no hub, and a
    /// `WORKSPACE` file is never one of those files.
    #[test]
    fn a_tag_that_may_be_hidden_declines_where_none_is_found() {
        let lock = ["packages.lock.json".to_string()];
        let gated = |files: &[(&str, Entry)]| {
            let view = |path: &str| {
                let found = files.iter().find(|(name, _)| *name == path);
                found.map_or(Entry::Absent, |(_, entry)| entry.clone())
            };
            gate(&Workspace::read(&view), &view, "", &lock)
        };
        let text = |text: &str| Entry::Text(text.to_string());
        let tells = "so socket-patch cannot tell which `nuget.from_lock` tags the workspace has";
        let declined = |says: &str| Vendored::Declined(format!("{says}, {tells}"));
        // In a workspace of the ruleset: a use of the proxy that may call
        // a tag, and an included file that is not there.
        let include = "include(\"//:more.MODULE.bazel\")";
        let elsewhere = BARE.replace("//:", "//api:");
        for (rest, says) in [
            (
                format!("{elsewhere}\nMORE = [nuget]"),
                "MODULE.bazel:5: `nuget` is used other than to call a tag",
            ),
            (
                include.to_string(),
                "more.MODULE.bazel: it does not exist; MODULE.bazel:4 includes it",
            ),
        ] {
            let read = gated(&[(FILE, text(&module(&rest)))]);
            assert_eq!(read, declined(says), "{rest}");
        }
        // The same include where nothing names the ruleset.
        let go = format!("bazel_dep(name = \"rules_go\", version = \"0.50.1\")\n{include}\n");
        assert_eq!(gated(&[(FILE, text(&go))]), Vendored::Plain);
        // A file that is there and is not read: the included one, and the
        // root file itself.
        let binary = Entry::Unreadable("it is not UTF-8".to_string());
        let files = [(FILE, text(&go)), ("more.MODULE.bazel", binary.clone())];
        let says = "more.MODULE.bazel: it cannot be read: it is not UTF-8; MODULE.bazel:2 \
                    includes it";
        assert_eq!(gated(&files), declined(says));
        let says = "MODULE.bazel: it cannot be read: it is not UTF-8";
        assert_eq!(gated(&[(FILE, binary.clone())]), declined(says));
        // A `WORKSPACE` file hides no tag: rules_csharp has no form for
        // that file, and what the reader makes of it is kept apart from
        // its doubts. One that cannot be read, and one that defines
        // something, decline nothing where no tag is found and change
        // nothing beside a tag, whether the Bazel the checkout names reads
        // such a file (7.7.2) or not (9.3.2).
        let bare = [(FILE, text(&module("")))];
        let wired = [
            (FILE, text(&module(WIRED))),
            ("MODULE.bazel.lock", text(SELECTED)),
            ("nuget.config", text(CONFIG)),
        ];
        for release in ["9.3.2\n", "7.7.2\n"] {
            for legacy in [binary.clone(), text("nuget_repo(name = \"nuget\")\n")] {
                let beside = [("WORKSPACE", legacy), (".bazelversion", text(release))];
                let read = gated(&[&bare[..], &beside].concat());
                assert_eq!(read, Vendored::Plain, "{release}");
                let read = gated(&[&wired[..], &beside].concat());
                let block = Vendored::Block(feeds(None, &[NUGET_ORG]));
                assert_eq!(read, block, "{release}");
            }
        }
    }

    #[test]
    fn the_block_is_declined_where_it_cannot_be_shown_to_work() {
        let with =
            |more: &str| WIRED.replace("nuget_config", &format!("{more},\n    nuget_config"));
        let isolated = module(WIRED).replace("\"nuget\")", "\"nuget\", isolate = True)");
        let dev = module(WIRED).replace("\"nuget\")", "\"nuget\", dev_dependency = True)");
        let quoted = "<packageSources>\n<add key='a' value='https://a.example/\"b\"' />\n\
                      </packageSources>";
        let pinned = "single_version_override(module_name = \"rules_csharp\", version = \"0.4.0\")";
        let archive = "archive_override(module_name = \"rules_csharp\", urls = [\"https://a\"])";
        let newer = SELECTED.replace("0.5.0", "0.6.0");
        // What the workspace holds after its module line, the files beside
        // it, and what the reason says.
        type Row<'a> = (String, Vec<(&'a str, Option<&'a str>)>, &'a str);
        let rows: Vec<Row> =
            vec![
            // The tags.
            (
                format!("{WIRED}\n{}", BARE.replace("//:", "//api:")),
                vec![],
                "MODULE.bazel:8: the workspace has more than one `nuget.from_lock`",
            ),
            (
                format!("{WIRED}\nMORE = [nuget]"),
                vec![],
                "MODULE.bazel:8: `nuget` is used other than to call a tag, so socket-patch cannot \
                 tell which `nuget.from_lock` tags the workspace has",
            ),
            (
                "nuget.from_lock(**TAG)".to_string(),
                vec![],
                "MODULE.bazel:4: this `nuget.from_lock` is not a call of its own with every \
                 argument written out",
            ),
            (
                format!("True and {}", WIRED.replace('\n', " ")),
                vec![],
                "is not a call of its own with every argument written out",
            ),
            (
                WIRED.replace("\"//:packages.lock.json\"", "LOCK"),
                vec![],
                "has a `packages_lock_json` that is no plain string",
            ),
            (
                with("local_package_dirs = [\"/opt/packages\"]"),
                vec![],
                "MODULE.bazel:4: this `nuget.from_lock` has `local_package_dirs`, which \
                 rules_csharp asks before every feed",
            ),
            (
                with("netrc = \"//:.netrc\""),
                vec![],
                "has `netrc`, which the block was not built with",
            ),
            (
                with("feeds = FEEDS"),
                vec![],
                "has `feeds` that are no list of plain strings",
            ),
            (
                WIRED.to_string(),
                vec![("nuget.config", None)],
                "names `//:nuget.config` as its `nuget_config`, which cannot be read",
            ),
            (
                WIRED.to_string(),
                vec![("nuget.config", Some(quoted))],
                "has a package source that cannot stand in a string of MODULE.bazel",
            ),
            // Feeds beside a config that vendored mode gives its first
            // source: an empty one, and one that holds a folder of its own.
            (
                with("feeds = [\"https://a.example\"]"),
                vec![("nuget.config", Some("<packageSources>\n<clear />\n</packageSources>"))],
                "MODULE.bazel:4: this `nuget.from_lock` has `feeds`, and its `nuget_config` \
                 `//:nuget.config` names no package source, where vendored mode names its \
                 folder",
            ),
            (
                with("feeds = [\"https://a.example\"]"),
                vec![("nuget.config", Some(OWN))],
                "so name those `feeds` in that file",
            ),
            (
                WIRED.to_string(),
                vec![(FILE, Some(&isolated))],
                "is called on a `use_extension` that is isolated, a dev dependency or not \
                 written plainly",
            ),
            (
                WIRED.to_string(),
                vec![(FILE, Some(&dev))],
                "is called on a `use_extension` that is isolated, a dev dependency or not \
                 written plainly",
            ),
            // The release of the ruleset.
            (
                WIRED.to_string(),
                vec![("MODULE.bazel.lock", Some(&newer))],
                "Bazel selected rules_csharp 0.6.0, and the block was built with rules_csharp \
                 0.5.0 alone",
            ),
            (
                format!("{WIRED}\n{pinned}"),
                vec![],
                "MODULE.bazel asks for rules_csharp 0.4.0 and MODULE.bazel.lock holds 0.5.0",
            ),
            (
                WIRED.to_string(),
                vec![("MODULE.bazel.lock", None)],
                "MODULE.bazel.lock does not say which release of rules_csharp Bazel selected: \
                 build once so that Bazel writes its lock",
            ),
            (
                format!("{WIRED}\n{archive}"),
                vec![],
                "MODULE.bazel:8: with this `archive_override` of rules_csharp socket-patch cannot \
                 tell which release of the ruleset Bazel builds with",
            ),
            // The release of Bazel.
            (
                WIRED.to_string(),
                vec![(".bazelversion", Some("9.1.0\n"))],
                "the checkout names Bazel 9.1.0 (`.bazeliskrc` or `.bazelversion`), and the block \
                 was built on Bazel 7.7.2, 8.8.2 and 9.3.2 alone",
            ),
            (
                WIRED.to_string(),
                vec![(".bazelversion", None)],
                "no file of the checkout names the Bazel release that builds it, and the block \
                 was built on Bazel 7.7.2, 8.8.2 and 9.3.2 alone: name the release in \
                 `.bazelversion`",
            ),
            // The rc files.
            (
                WIRED.to_string(),
                vec![(".bazelrc", Some("build --jobs=4\ncommon --vendor_dir=third_party\n"))],
                ".bazelrc:2 names `--vendor_dir=third_party`, under which Bazel may not take the \
                 committed package",
            ),
            (
                WIRED.to_string(),
                vec![(".bazelrc", Some("fetch --repository_disable_download\n"))],
                ".bazelrc:1 names `--repository_disable_download`",
            ),
            (
                WIRED.to_string(),
                vec![(".bazelrc", Some("common --experimental_remote_downloader=grpcs://a\n"))],
                ".bazelrc:1 names `--experimental_remote_downloader=grpcs://a`, which the block \
                 was not built with: a remote downloader takes no `file:` feed",
            ),
            (
                WIRED.to_string(),
                vec![(".bazelrc", Some("build 'unclosed\n"))],
                "the rc file .bazelrc:1 cannot be read",
            ),
        ];
        for (rest, more, says) in rows {
            let Vendored::Declined(why) = gated(&rest, &more) else {
                panic!("not declined: {rest} {more:?}");
            };
            assert!(why.contains(says), "{rest}: {why}");
        }
        // A project below the root of its workspace.
        let below = module(&WIRED.replace("//:", "//svc/app:"));
        let view = |path: &str| match path {
            FILE => Entry::Text(below.clone()),
            _ => Entry::Absent,
        };
        let lock = ["packages.lock.json".to_string()];
        let Vendored::Declined(why) = gate(&Workspace::read(&view), &view, "svc/app/", &lock)
        else {
            panic!("not declined below the root");
        };
        let says = "MODULE.bazel:4: this `nuget.from_lock` reads the lock of a project below the \
                    root of its Bazel workspace";
        assert!(why.starts_with(says), "{why}");
    }

    #[test]
    fn the_sources_of_a_config_are_read_as_the_ruleset_reads_them() {
        let config = |inside: &str| format!("<packageSources>\n{inside}\n</packageSources>");
        for (inside, read) in [
            ("<add key=\"a\" value=\"https://a\" />", vec!["https://a"]),
            ("  <add key='a' value='https://a'/>\r\n<add key=\"b\" value=\"b\" />", vec!["https://a", "b"]),
            // A `<clear` drops what stands before it, and an empty value
            // and a line that does not start with `<add` are no source.
            ("<add key=\"a\" value=\"https://a\" />\n<clear />\n<add key=\"b\" value=\"https://b\" />", vec!["https://b"]),
            ("<add key=\"a\" value=\"\" />\n<!-- <add key=\"b\" value=\"https://b\" /> -->", vec![]),
            // No comment is passed over and no entity decoded.
            ("<!--\n<add key=\"a\" value=\"https://a?x=1&amp;y=2\" />\n-->", vec!["https://a?x=1&amp;y=2"]),
        ] {
            assert_eq!(sources(&config(inside)), read, "{inside}");
        }
        assert_eq!(sources("<configuration />"), [""; 0]);
        assert_eq!(sources("<packageSources>\n<add value=\"a\" />"), [""; 0]);
    }

    /// The block as it was built on Bazel 9.3.2, 8.8.2 and 7.7.2, for the
    /// patch `7e57ce11-...`.
    const FOLDER_A: &str = ".socket/vendor/nuget/7e57ce11-0000-4000-8000-5184602cd3cc";
    const FOLDER_B: &str = ".socket/vendor/nuget/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const BLOCK: &str = r#"# >>> socket-patch: NuGet patches for Bazel (managed block: socket-patch writes and removes it) >>>
socket_patch_nuget = use_extension("@rules_csharp//csharp:extensions.bzl", "nuget")
socket_patch_nuget.from_lock(
    feeds = [
        "file:.socket/vendor/nuget/7e57ce11-0000-4000-8000-5184602cd3cc",
        "https://api.nuget.org/v3/index.json",
    ],
    packages_lock_json = "//:packages.lock.json",
)
# <<< socket-patch <<<"#;

    #[test]
    fn a_folder_is_added_once_and_taken_out_to_the_byte() {
        let fixture = feeds(None, &[NUGET_ORG]);
        let base = module(WIRED);
        let ends = ["\n", "", "\n\n"].map(|end| format!("{}{end}", base.trim_end()));
        let crlf = ends[0].replace('\n', "\r\n");
        for module in ends.iter().chain([&crlf]) {
            let eol = if module.contains('\r') { "\r\n" } else { "\n" };
            let one = with_folder(module, &fixture, FOLDER_A, &[]).expect("a block");
            let block = BLOCK.replace('\n', eol);
            let expected = match module.ends_with('\n') {
                true => format!("{module}{eol}{block}{eol}"),
                false => format!("{module}{eol}{eol}{block}"),
            };
            assert_eq!(one, expected);
            // Once more: the same text.
            assert_eq!(
                with_folder(&one, &fixture, FOLDER_A, &[]),
                Some(one.clone())
            );
            // A second folder, in the order of their names, and the name
            // of a hub that has one.
            let named = feeds(Some("packages"), &[NUGET_ORG]);
            let two = with_folder(&one, &named, FOLDER_B, &[]).expect("two folders");
            let both =
                format!("        \"file:{FOLDER_A}\",{eol}        \"file:{FOLDER_B}\",{eol}");
            assert!(two.contains(&both), "{two}");
            let name = format!("    ],{eol}    name = \"packages\",{eol}    packages_lock_json");
            assert!(two.contains(&name), "{two}");
            // The first one out: the block stays for the second, and goes
            // with it. The file is then the one of before.
            let left = without_folder(&two, FOLDER_A).expect("one folder");
            assert!(
                !left.contains(FOLDER_A) && left.contains(FOLDER_B),
                "{left}"
            );
            assert_eq!(without_folder(&left, FOLDER_B).as_ref(), Ok(module));
            assert_eq!(without_folder(&one, FOLDER_A).as_ref(), Ok(module));
            // A later patch of the same package takes the place of the
            // folder it supersedes, and the block goes with it alone.
            let later = with_folder(&one, &fixture, FOLDER_B, &[FOLDER_A.to_string()]);
            let later = later.expect("the folder of the later patch");
            assert!(
                !later.contains(FOLDER_A) && later.contains(FOLDER_B),
                "{later}"
            );
            assert_eq!(without_folder(&later, FOLDER_B).as_ref(), Ok(module));
            // A folder that is not there, and a file without a block.
            assert_eq!(without_folder(&one, FOLDER_B), Ok(one.clone()));
            assert_eq!(without_folder(module, FOLDER_A).as_ref(), Ok(module));
        }
    }

    #[test]
    fn a_block_that_was_changed_by_hand_is_left_alone() {
        let fixture = feeds(None, &[NUGET_ORG]);
        let one = with_folder(&module(WIRED), &fixture, FOLDER_A, &[]).expect("a block");
        for edited in [
            one.replace("\"https://api.nuget.org/v3/index.json\",\n", ""),
            one.replace("    feeds = [", "    feeds = [  # ours"),
            one.replace("# <<< socket-patch <<<", ""),
            one.replace(") >>>", ") >>> "),
            format!("{one}{BLOCK}\n"),
        ] {
            assert_ne!(edited, one);
            assert_eq!(
                with_folder(&edited, &fixture, FOLDER_B, &[]),
                None,
                "{edited}"
            );
            assert_eq!(without_folder(&edited, FOLDER_A), Err(10), "{edited}");
        }
    }

    #[test]
    fn a_checkout_is_read_without_the_block_it_holds() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("repo");
        std::fs::create_dir_all(root.join("svc")).unwrap();
        std::fs::create_dir(base.join(".git")).unwrap();
        let lock = ["packages.lock.json".to_string()];
        // No Bazel workspace, and a project without a lock.
        assert_eq!(vendored(&root, &lock), Vendored::Plain);
        let module = checkout(&root);
        assert_eq!(vendored(&root, &[]), Vendored::Plain);
        // The tag names a config that is not there yet.
        let unread = "as its `nuget_config`, which cannot be read";
        let declined = |why: &str| match vendored(&root, &lock) {
            Vendored::Declined(said) => assert!(said.contains(why), "{said}"),
            other => panic!("{why}: {other:?}"),
        };
        declined(unread);
        std::fs::write(root.join("nuget.config"), CONFIG).unwrap();
        let Vendored::Block(read) = vendored(&root, &lock) else {
            panic!("no block");
        };
        assert_eq!(read, feeds(None, &[NUGET_ORG]));
        // With its own block in the file the workspace reads as before:
        // the block's tag is no second tag.
        let wired = with_folder(&module, &read, FOLDER_A, &[]).expect("a block");
        std::fs::write(root.join(FILE), &wired).unwrap();
        assert_eq!(vendored(&root, &lock), Vendored::Block(read));
        // A block that was changed by hand.
        std::fs::write(
            root.join(FILE),
            wired.replace("    feeds = [", "    feeds = [ "),
        )
        .unwrap();
        declined("MODULE.bazel:10: the block that socket-patch keeps there was changed by hand");
        std::fs::write(root.join(FILE), &module).unwrap();
        // A vendor directory of Bazel's, and a workspace above this one.
        std::fs::write(root.join("svc/VENDOR.bazel"), "").unwrap();
        declined("svc/VENDOR.bazel: the checkout holds a vendor directory of Bazel's");
        std::fs::remove_file(root.join("svc/VENDOR.bazel")).unwrap();
        std::fs::write(base.join("MODULE.bazel"), "").unwrap();
        declined("holds a Bazel workspace above this one");
        assert_eq!(crate::bazel::root_above(&root), Some(base.clone()));
        std::fs::remove_file(base.join("MODULE.bazel")).unwrap();
        assert_eq!(crate::bazel::root_above(&root), None);
        // A project below the root, whose lock the tag does not read.
        assert_eq!(vendored(&root.join("svc"), &lock), Vendored::Plain);
        // The file is a link to a file of the workspace.
        #[cfg(unix)]
        {
            std::fs::rename(root.join(FILE), root.join("svc/module")).unwrap();
            std::os::unix::fs::symlink(root.join("svc/module"), root.join(FILE)).unwrap();
            declined("MODULE.bazel is a symbolic link");
        }
    }

    /// A hub can read the lock while no tag of the checkout is found: the
    /// tag is gone and the block that was written beside it still reads
    /// the lock, or the root file cannot be read. Vendored as without
    /// Bazel, a package would not be among the feeds of that hub, and its
    /// build would fail on the re-pinned lock: the package is declined. A
    /// project whose lock neither the tag nor the block reads is vendored
    /// as without Bazel.
    #[test]
    fn a_hub_that_no_tag_of_the_checkout_shows_is_declined() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("repo");
        let below = root.join("svc");
        std::fs::create_dir_all(&below).unwrap();
        std::fs::create_dir(base.join(".git")).unwrap();
        let lock = ["packages.lock.json".to_string()];
        let module = checkout(&root);
        std::fs::write(root.join("nuget.config"), CONFIG).unwrap();
        let Vendored::Block(read) = vendored(&root, &lock) else {
            panic!("no block");
        };
        let declined = |why: &str| Vendored::Declined(why.to_string());

        // The block of an earlier run, without the tag it was written
        // beside.
        let wired = with_folder(&module, &read, FOLDER_A, &[]).expect("a block");
        let orphaned = wired.replace(WIRED, "");
        assert_ne!(orphaned, wired);
        std::fs::write(root.join(FILE), &orphaned).unwrap();
        let says = "MODULE.bazel:7: the block that socket-patch keeps there still reads \
                    `//:packages.lock.json` for the hub, and the `nuget.from_lock` it was written \
                    beside is gone, so a package vendored now would not be among the block's \
                    feeds: put that tag back, or take the vendored packages out (`socket-patch \
                    vendor --revert`), and run this command again";
        assert_eq!(vendored(&root, &lock), declined(says));
        // The block reads the lock of the project at the root alone, with
        // its tag and without it.
        assert_eq!(vendored(&below, &lock), Vendored::Plain);
        std::fs::write(root.join(FILE), &wired).unwrap();
        assert_eq!(vendored(&below, &lock), Vendored::Plain);

        // The root file is larger than the reader takes: for every project
        // of the workspace.
        let tells = "so socket-patch cannot tell which `nuget.from_lock` tags the workspace has";
        let large = format!("{module}{}", "#\n".repeat(MAX_BYTES / 2));
        std::fs::write(root.join(FILE), large).unwrap();
        let says = format!("MODULE.bazel: it cannot be read: it is larger than 1 MiB, {tells}");
        assert_eq!(vendored(&root, &lock), declined(&says));
        assert_eq!(vendored(&below, &lock), declined(&says));
        // Or it is a link that leads out of the workspace.
        #[cfg(unix)]
        {
            std::fs::write(base.join("module"), &module).unwrap();
            std::fs::remove_file(root.join(FILE)).unwrap();
            std::os::unix::fs::symlink(base.join("module"), root.join(FILE)).unwrap();
            let out = "MODULE.bazel: it cannot be read: it leads out of the Bazel workspace";
            assert_eq!(vendored(&root, &lock), declined(&format!("{out}, {tells}")));
        }
    }

    #[test]
    fn a_hosted_pin_beside_the_block_of_vendored_mode_is_withheld() {
        let wired = with_folder(&module(WIRED), &feeds(None, &[NUGET_ORG]), FOLDER_A, &[]);
        let said = said(&[("MODULE.bazel", &wired.expect("a block"))], "").expect("withheld");
        let starts = "MODULE.bazel:12: this `nuget.from_lock` is the one vendored mode keeps for \
                      the vendored NuGet packages of this project, and its `feeds` stand in the \
                      place of the package sources of nuget.config";
        assert!(said.starts_with(starts), "{said}");
        let way = "So hosted mode wrote nothing for it. Vendor this package as well (`--mode \
                   vendored`), or take the vendored ones out (`socket-patch vendor --revert`), and \
                   run this command again";
        assert!(said.contains(way), "{said}");
    }
}
