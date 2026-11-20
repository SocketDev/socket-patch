//! Whether the Bazel build of a workspace takes what hosted mode writes
//! for a NuGet package.
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
//! The answer is read from the checkout through [`super::workspace`]:
//! `MODULE.bazel` and the files it includes, and the locks the tags name.
//! Nothing is evaluated and no Bazel is run. The ruleset has no
//! `WORKSPACE` form, so that file is not looked at.

use std::path::Path;

use serde::{Deserialize, Serialize};

use super::starlark::Value;
use super::workspace::{disk, disk_up_to, Entry, Extension, Repo, Tag, Workspace};
use crate::formats::nuget::lock::{locked_at, nuget_lock_entries, parse_lock};
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

/// What the hub of a Bazel workspace makes of one project.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Hub {
    /// Why the hub does not take its package sources from the project's
    /// `nuget.config`, as the warning of a package says it after its name.
    /// `None`: the tags show that it does.
    pub why: Option<String>,
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
    /// A label that cannot be read: any lock, the project's among them.
    Any,
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
    /// a lock before it. Then the config ([`Self::why`]), for a package
    /// that the run re-pins in a lock the hub reads. A package in no such
    /// lock is not the hub's: its pin changes nothing a build reads.
    pub fn against(
        &self,
        pinned: &dyn Fn(Option<&str>) -> bool,
        id: &str,
        version: &str,
        hash: &str,
    ) -> Option<(&'static str, String)> {
        let (mut read, mut first) = (false, false);
        for lock in &self.locks {
            let (at, path, text) = match lock {
                Read::Any => {
                    read |= pinned(None);
                    continue;
                }
                Read::Ours(lock) => {
                    let ours = pinned(Some(lock));
                    (read, first) = (read || ours, first || ours);
                    continue;
                }
                Read::Other(..) if first && self.ordered => continue,
                Read::Other(at, path, text) => (at, path, text),
            };
            let doc = text.as_deref().and_then(|text| parse_lock(text).ok());
            let state = match &doc {
                None => "cannot be read and may hold the package",
                Some(doc) if locked_at(doc, id, version).any(|e| e.content_hash != Some(hash)) => {
                    "holds the package as well"
                }
                Some(doc) => {
                    first |= nuget_lock_entries(doc).any(|e| e.id.eq_ignore_ascii_case(id));
                    continue;
                }
            };
            let why = format!(
                "{at}: this `nuget.from_lock` reads {path}, which {state} and which this run \
                 does not re-pin; rules_csharp holds a package to the `contentHash` of the first \
                 lock that names it, so the Bazel build can fail on the patched package. So \
                 hosted mode wrote nothing for it. Run this command in a directory above both \
                 locks that holds a solution file or a `nuget.config` (`--cwd`): there it re-pins \
                 the lock of every project"
            );
            return Some((LOCK_NOT_REPINNED, why));
        }
        let why = self.why.clone().filter(|_| read)?;
        Some((CONFIG_UNDECLARED, why))
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
/// case names the same file, unless the directory holds both.
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
    // Bazel has `/` between the parts of a path on every system.
    let dir = root.project.components();
    let dir: String = dir
        .map(|part| format!("{}/", part.as_os_str().to_string_lossy()))
        .collect();
    let listed = std::fs::read_dir(project).into_iter().flatten().flatten();
    let spelled: Vec<String> = listed
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.eq_ignore_ascii_case(config))
        .collect();
    let exact = spelled.iter().find(|name| *name == config);
    let config = exact.or(spelled.first()).map_or(config, |name| name);
    let workspace = Workspace::read(&disk(&root.dir));
    let mut hub = judge(&workspace, &dir, config, locks, spelled.len() > 1)?;
    let read = disk_up_to(&root.dir, MAX_LOCK);
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

/// [`withheld`] for the workspace `ws` and the project in its directory
/// `dir` (empty, or with a `/` at its end), before the locks of the other
/// tags are read. `exact`: a label names `config` only in its own case.
///
/// The hub reads `config` when the last tag that has a `nuget_config` or
/// `feeds` names it, as a label in a string; where the tags are in more
/// than one file, their order is not known, and every tag that has either
/// must name it. A tag that is not a plain call of its own, or whose
/// `nuget_config` is no string, makes that uncertain, and an uncertain
/// reading withholds: a build that may break outranks a patch that is
/// missed and explained. A doubt of the reader elsewhere in the files can
/// only hide a tag, and changes nothing here.
fn judge(ws: &Workspace, dir: &str, config: &str, locks: &[String], exact: bool) -> Option<Hub> {
    let tags = ws.tags(&EXTENSION, "from_lock");
    let given = |tag: &Tag, attribute: &str| tag.call.arg(attribute).is_some();
    // The file of the checkout that a tag names in a plain string.
    let file = |tag: &Tag, attribute: &str| match tag.call.arg(attribute) {
        Some(Value::Str(label)) => ws.label(label).filter(|label| label.repo == Repo::Main),
        _ => None,
    };
    let at = |tag: &Tag| format!("{}:{}", tag.file, tag.call.line);
    let read = |tag: &Tag| match tag.call.arg("packages_lock_json") {
        Some(Value::Str(_)) => {
            let path = file(tag, "packages_lock_json")?.path();
            let ours = |lock: &&String| path.eq_ignore_ascii_case(&format!("{dir}{lock}"));
            Some(match locks.iter().find(ours) {
                Some(lock) => Read::Ours(lock.clone()),
                None => Read::Other(at(tag), path, None),
            })
        }
        Some(_) => Some(Read::Any),
        None => tag.call.unpacks().then_some(Read::Any),
    };
    let reads: Vec<Option<Read>> = tags.calls.iter().map(read).collect();
    let mine = |read: &Option<Read>| matches!(read, Some(Read::Ours(_) | Read::Any));
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
    let locks: Vec<Read> = reads.into_iter().flatten().collect();
    let hub = |why, locks| Hub {
        why,
        locks,
        ordered,
    };
    if vague.is_none() && shown {
        // The config is read: only another lock can stand against a pin.
        let others = locks.iter().any(|lock| matches!(lock, Read::Other(..)));
        return others.then(|| hub(None, locks));
    }

    // The label of `config` for the tag: in the package of the lock, when
    // the tag names the lock plainly and `config` lies in that package,
    // else in the package of its own directory.
    let package = file(reader, "packages_lock_json").map(|label| label.package);
    let inside = |package: &String| match config.strip_prefix(package.as_str()) {
        Some(rest) => package.is_empty() || rest.starts_with('/'),
        None => false,
    };
    let (package, name) = match package.as_ref().filter(|package| inside(package)) {
        Some(package) => (&**package, config[package.len()..].trim_start_matches('/')),
        None => config.rsplit_once('/').unwrap_or(("", &config)),
    };
    let attribute = format!("`nuget_config = \"//{package}:{name}\"`");
    let put = format!("Put {attribute} on that tag");
    let again = format!(
        " and run this command again: it then names the source in {config}, which it creates \
         where there is none"
    );
    let unread = format!("so rules_csharp does not read {config}");
    let tag = vague.or(other).unwrap_or(reader);
    let (why, way) = match tag.call.arg("nuget_config") {
        _ if vague.is_some() => (
            format!("{NOT_PLAIN}, so socket-patch cannot tell whether rules_csharp reads {config}"),
            format!("Write that plainly, with {attribute} on the tag,{again}"),
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
        "{}: this `nuget.from_lock` {why}, where hosted mode names the Socket source of a patch; \
         without that source rules_csharp downloads the upstream package, and the Bazel build \
         fails on the `contentHash` that hosted mode re-pins in the lock. So hosted mode wrote \
         nothing for it. {way}, and the Bazel build takes the patched package{dirs}",
        at(tag)
    );
    Some(hub(Some(why), locks))
}

#[cfg(test)]
mod tests {
    use super::super::workspace::Entry;
    use super::*;

    /// The tag of the fixture that hosted mode patches on a real Bazel, and
    /// the same tag without its `nuget_config`.
    const WIRED: &str = r#"nuget.from_lock(
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
        judge(&Workspace::read(&view), dir, "nuget.config", &lock, false)
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
        // A tag whose lock cannot be read may read the project's.
        let computed = BARE.replace("\"//:packages.lock.json\"", "LOCK");
        assert_eq!(at_root(&computed), Some(bare.clone()));
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
        let said = judge(&ws, "svc/", "nuget.config", &lock, false).expect("withheld");
        let way = "Put `nuget_config = \"//svc:nuget.config\"` on that tag";
        assert!(said.why.expect("why").contains(way));
        // A label in another case names the config, unless the directory
        // holds both spellings.
        let view = |path: &str| match path {
            "MODULE.bazel" => Entry::Text(module(&WIRED.replace("nuget.config", "NuGet.Config"))),
            _ => Entry::Absent,
        };
        let (ws, lock) = (Workspace::read(&view), ["packages.lock.json".to_string()]);
        assert_eq!(judge(&ws, "", "nuget.config", &lock, false), None);
        let said = judge(&ws, "", "nuget.config", &lock, true).and_then(|hub| hub.why);
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
            let whole = format!(
                "MODULE.bazel:{line}: this `nuget.from_lock` {NOT_PLAIN}, so socket-patch cannot \
                 tell whether rules_csharp reads nuget.config{WHERE}Write that plainly, with \
                 {ATTRIBUTE} on the tag,{AGAIN}"
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
        assert_eq!(listed.locks, [other(4), ours(), Read::Any]);
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
                locks,
                ordered,
            };
            let said = hub.against(&|_| pinned, "newtonsoft.json", "1.0.0", "NEW");
            said.map(|(code, why)| (code, why.starts_with("M:4: ") || why == "why"))
        };
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
            (vec![Read::Any, other(upstream())], true, true, elsewhere),
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
            (vec![Read::Any], true, false, None),
            (vec![Read::Any], true, true, config),
        ] {
            assert_eq!(against(locks, ordered, pinned), said);
        }
        let hub = Hub {
            why: None,
            locks: vec![other(None), ours()],
            ordered: true,
        };
        let (_, said) = hub
            .against(&|_| true, "a", "1.0.0", "NEW")
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
        assert_eq!(read.against(&|_| true, "a", "1.0.0", "NEW"), None);
    }

    #[test]
    fn a_project_is_read_from_its_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let project = root.join("svc/app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir(root.join(".git")).unwrap();
        let lock = ["packages.lock.json".to_string()];
        let read = |project: &Path| {
            let hub = withheld(project, "nuget.config", &lock)?;
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
        // The project at the root, whose lock the tag does not read. And
        // a project without a lock, which no tag can read: not the one
        // whose name cannot be read either.
        assert_eq!(read(&root), None);
        let computed = "nuget.from_lock(packages_lock_json = LOCK)";
        std::fs::write(root.join("MODULE.bazel"), module(computed)).unwrap();
        assert!(read(&root).is_some());
        assert_eq!(withheld(&root, "nuget.config", &[]), None);
    }
}
