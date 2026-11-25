//! What a rules_jvm_external hub of a Bazel workspace builds.
//!
//! Under Bzlmod a hub is the tags of the ruleset's `maven` extension that
//! share a `name` (`maven` when none is given): `install`, and `artifact`
//! and `from_toml`, which add artifacts. A hub whose `install` gives a
//! `lock_file` is pinned: Bazel fetches each jar the lock names, at the
//! sha256 the lock holds, and reads no `pom.xml` and no Gradle file. A
//! lock with `m2local` takes a jar that none of its repositories lists
//! from the Maven local repository, at that sha256 too. So a patch that
//! socket-patch puts in a `pom.xml`, a Gradle build or a jar does not
//! reach what Bazel builds, and [`notices`] says so for each artifact a
//! hub builds.
//!
//! Hosted mode patches a pinned hub. The hub fetches each jar through a
//! repository of its own, named after the group, the artifact and the
//! version, and Bazel's `override_repo` (7.4.0 and later) puts another
//! repository in its place. So socket-patch keeps one block at the end of
//! the root `MODULE.bazel` ([`BEGIN`]): per patch a repository that
//! downloads the patched jar at its sha256, and an `override_repo` of the
//! hub's one. The hub, its lock, every label and `MODULE.bazel.lock` stay
//! as they are. [`jars`] are the patches of a run that a hub can take,
//! [`site`] says for each whether its entry may be written, [`rewrite`]
//! writes it, [`pins`] reads the block for `list`, `rollback`, `remove`
//! and `vex`, and [`without`] takes an entry out. [`hub_jars`] are the
//! jars a hosted scan looks for patches of: those the pinned hubs fetch.
//!
//! Vendored mode patches a pinned hub through the same block. Its entry
//! names no host: the repository is a directory of the checkout,
//! `.socket/vendor/maven/<patch id>` ([`Patch::unit`]), which holds the
//! patched jar and the two files that make the directory a repository
//! with the one target the hub takes a jar by ([`unit_files`]), and which
//! Bazel's `local_repository` links to, where it is. Bazel checks no digest
//! of such a directory: `socket-patch vendor --check` holds the committed
//! jar to the patch.
//!
//! The block is recognised by its text alone: one that is not, byte for
//! byte, what socket-patch writes for its entries was changed by hand, and
//! is neither written to nor trusted.
//!
//! Everything is read from the checkout through [`super::workspace`]: the
//! root `MODULE.bazel` with the files it includes, the locks its hubs
//! name, the `WORKSPACE` file, what names the Bazel release and the rc
//! files. Nothing is evaluated and no Bazel is run. What cannot be read
//! with certainty is said as such ([`UNREADABLE`]) and never guessed: a
//! jar whose entry cannot be shown to work is declined with a reason.
//!
//! Not seen: a hub or an override that another Bazel module declares, a
//! `maven_install` inside a function of a `.bzl` file, a jar that reaches
//! Bazel without a hub, and what a flag or an rc file outside the checkout
//! tells Bazel.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ops::Range;
use std::path::Path;
use std::rc::Rc;

use super::rc::{declared_release, mentions, ModuleLock};
use super::starlark::{Bound, Call, How, Value};
use super::workspace::{disk, disk_up_to, Doubt, Entry, Extension, Repo, Tag, Workspace};
use crate::formats::maven::is_variant;
use crate::patch::redirect::{
    bare_sha256_hex, maven_coordinates, DepOverride, RewriteResult, RewriteWarning,
};
use crate::utils::digest::is_hex64_lower;
use crate::utils::fs::run_blocking;
use crate::utils::line_endings::terminator;
use crate::utils::purl::{build_maven_purl, parse_maven_purl, purl_qualifier};
use crate::vendor::jvm::layout::artifact_path;

/// The extension whose tags make a hub.
pub const EXTENSION: Extension<'static> = Extension {
    module: "rules_jvm_external",
    file: "//:extensions.bzl",
    name: "maven",
};

/// The warning for an artifact that a pinned hub builds: no patch of a
/// socket-patch command reaches that build.
pub const HUB_UNPATCHED: &str = "maven_bazel_hub_unpatched";
/// The warning for an artifact when the hubs of the workspace cannot be
/// read: a hub may build it.
pub const UNREADABLE: &str = "maven_bazel_unreadable";
/// The warning of a hosted run that looks for the packages of a project
/// ([`hub_jars`]) when not every hub of the workspace could be read: the
/// jars of a hub that was not read are not among them.
pub const HUB_NOT_READ: &str = "maven_bazel_hub_not_read";

/// The warnings of a hosted run for a jar that a hub builds, or may
/// build, and whose entry it does not write. Each says why, and that the
/// Bazel build keeps the upstream jar. With [`UNREADABLE`]:
///
/// - the project is below the root of its Bazel workspace, where the
///   block belongs;
pub const NOT_AT_ROOT: &str = "maven_bazel_not_at_root";
/// - a hub has no lock, so Bazel resolves its jars when it builds;
pub const NOT_PINNED: &str = "maven_bazel_not_pinned";
/// - the Bazel that builds the checkout may have no `override_repo`, or
///   the release of the ruleset, which names the repository, is not known;
pub const RELEASE: &str = "maven_bazel_release";
/// - the repository of this jar cannot be named, or the patch lacks what
///   an entry holds;
pub const ARTIFACT: &str = "maven_bazel_artifact";
/// - the build would pass on the upstream jar with the entry in place;
pub const NO_EFFECT: &str = "maven_bazel_no_effect";
/// - Bazel may not be able to download the patched jar.
pub const DOWNLOAD: &str = "maven_bazel_download";

/// The file of the block, and the key under which a hosted run hands
/// [`Site`] to [`rewrite`] among its candidate files: no path of a file.
pub const FILE: &str = "MODULE.bazel";
pub const SITE_KEY: &str = "<socket-patch:bazel-maven>";

/// The first and the last line of the block.
pub const BEGIN: &str = "# >>> socket-patch: Maven patches for Bazel (managed block: socket-patch \
                         writes and removes it) >>>";
const END: &str = "# <<< socket-patch <<<";

/// The releases of rules_jvm_external whose way to name the repository of
/// a jar was read: `escape(coordinates)` in
/// `private/extensions/download_pinned_deps.bzl` from 6.4 to 6.7 and
/// `to_repository_name` in `private/coursier_utilities.bzl` from 6.8 on.
/// No older release is here: none was read for the name or built. The
/// extension is marked reproducible, which keeps it out of
/// `MODULE.bazel.lock`, from 6.2 (`private/extensions/maven.bzl`), and
/// not at 6.0 and 6.1.
const RULESETS: [&str; 10] = [
    "6.4", "6.5", "6.6", "6.7", "6.8", "6.9", "6.10", "7.0", "7.1", "7.2",
];

/// What a doubt about a hub without a lock ends with.
const NO_LOCK: &str = "has no `lock_file`";

/// The largest lock that is read, each lock once for every hub that names
/// it, and how many bytes of locks a scan takes its packages from in one
/// workspace ([`hub_jars`]): the first lock that does not fit is the last
/// one read.
const MAX_LOCK: usize = 16 << 20;
const MAX_LOCKS: usize = 4 * MAX_LOCK;

/// The tags that make a hub of their `name` or add to it, `install`
/// first: the ruleset's `private/extensions/maven.bzl` has `artifact` at
/// 6.5, 6.9 and 7.2 and `from_toml` at 6.9 and 7.2. Its two other tags,
/// `override` and `amend_artifact`, make no hub.
const MAKE_A_HUB: [&str; 3] = ["install", "artifact", "from_toml"];

/// The tag that pins a hub, as a warning and an action statement name it.
pub const INSTALL: &str = "maven.install";

/// A hub of the root module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hub {
    pub name: String,
    /// Where its first `maven.install` is, or without one the first tag
    /// that makes it: the file, from the Bazel root, and the line.
    pub file: String,
    pub line: usize,
    /// The lock its tags name, from the Bazel root. `None`: the hub is not
    /// pinned, and Bazel resolves what it builds when it builds.
    pub lock: Option<String>,
    /// The label of the `use_extension` that its first tag is called on,
    /// as it is written there. `None` when one of its tags is called on a
    /// usage that cannot be read or is isolated: an `override_repo` on
    /// another usage does not reach the repositories of that one.
    pub proxy: Option<String>,
}

/// The label of the `use_extension` call behind the proxy that `tag` is
/// called on, when that usage is shared with every other one of the
/// extension (`isolate` is not given, or is `False`) and its label holds
/// nothing a string of the block would have to escape.
fn proxy(ws: &Workspace, tag: &Tag) -> Option<String> {
    let (_, file) = ws.files.iter().find(|(path, _)| path == tag.file)?;
    let Bound::Call(made) = file.binds.get(tag.call.bind?)?.to else {
        return None;
    };
    let made = file.calls.get(made)?;
    let shared = match made.arg("isolate") {
        None => true,
        Some(Value::Name(isolate)) => isolate == "False",
        Some(_) => false,
    };
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"@/:._-+~".contains(&b);
    match made.positional(0) {
        Some(Value::Str(label)) if shared && label.bytes().all(plain) => Some(label.clone()),
        _ => None,
    }
}

const NOT_A_FILE: &str = "the `lock_file` of this hub is not a file of this repository";

/// The name of the hub that `call`, a `tag` of [`MAKE_A_HUB`], adds to,
/// and the lock it names for it, which only an `install` can, or why they
/// cannot be read.
fn install(ws: &Workspace, tag: &str, call: &Call) -> Result<(String, Option<String>), String> {
    if !call.whole || call.unpacks() {
        return Err(format!("this `maven.{tag}` is not a plain call of its own"));
    }
    // What a repository name is made of: Bazel takes no other name, and
    // a warning prints this one.
    let named = |b: u8| b.is_ascii_alphanumeric() || b"_.-+".contains(&b);
    let name = match call.arg("name") {
        None => "maven",
        Some(Value::Str(name)) if name.bytes().all(named) => name,
        Some(_) => {
            return Err("the `name` of this hub is not a repository name in a string".into())
        }
    };
    let lock = match call.arg("lock_file") {
        None => None,
        Some(Value::Str(label)) => match ws.label(label) {
            Some(file) if file.repo == Repo::Main => Some(file.path()),
            _ => return Err(NOT_A_FILE.into()),
        },
        Some(_) => return Err(NOT_A_FILE.into()),
    };
    Ok((name.to_string(), lock))
}

/// The hubs of the workspace, and what makes the list uncertain: the
/// doubts of the reader, a tag that cannot be read, and `install` tags of
/// one hub that name different locks. The ruleset takes the lock of the
/// last root `install` (`private/extensions/maven.bzl` at 6.5 and 7.2), so
/// such a hub is left out instead of given one of them. And no hub at all
/// is given when an `install` cannot be read or the reader may have missed
/// one: that tag may be the last one of any hub. A hub that only the other
/// tags of [`MAKE_A_HUB`] make has no lock.
pub fn hubs(ws: &Workspace) -> (Vec<Hub>, Vec<Doubt>) {
    // What the reader doubts is about the extension: the same for each tag.
    let tags = MAKE_A_HUB.map(|tag| ws.tags(&EXTENSION, tag));
    let mut doubts: Vec<Doubt> = ws.doubts.iter().chain(&tags[0].doubts).cloned().collect();
    let mut every_tag_read = doubts.is_empty();
    let (mut hubs, mut split): (Vec<Hub>, Vec<String>) = Default::default();
    let calls = MAKE_A_HUB.iter().zip(&tags);
    let calls = calls.flat_map(|(class, tags)| tags.calls.iter().map(move |tag| (*class, tag)));
    for (class, tag) in calls {
        let (file, line, pins) = (tag.file.to_string(), tag.call.line, class == "install");
        let (name, lock) = match install(ws, class, tag.call) {
            Ok(read) => read,
            Err(why) => {
                // Only an `install` names a lock: without one that was
                // not read, the hubs that were read stay.
                every_tag_read &= !pins;
                doubts.push(Doubt { file, line, why });
                continue;
            }
        };
        let proxy = proxy(ws, tag);
        let Some(hub) = hubs.iter_mut().find(|hub| hub.name == name) else {
            hubs.push(Hub {
                name,
                file,
                line,
                lock,
                proxy,
            });
            continue;
        };
        hub.proxy = hub.proxy.take().filter(|_| proxy.is_some());
        if pins && hub.lock != lock {
            let (first, at) = (&hub.file, hub.line);
            let why = format!("this tag and the one at {first}:{at} name different locks");
            doubts.push(Doubt { file, line, why });
            split.push(name);
        }
    }
    hubs.retain(|hub| every_tag_read && !split.contains(&hub.name));
    (hubs, doubts)
}

/// The jar of an artifact in a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    pub version: String,
    /// The sha256 the lock holds for it. `None`: the lock has none.
    pub jar_sha256: Option<String>,
    /// The hub fetches it: the lock has its sha256 and does not skip it,
    /// and a repository of the lock lists it or, under `m2local`, the hub
    /// takes it from the Maven local repository.
    pub fetched: bool,
}

/// A hub's lock, `maven_install.json`, in format 2 (rules_jvm_external 6.5
/// and 6.9 write it) or 3 (7.2 does).
#[derive(Debug)]
pub struct Lock {
    pub format: u8,
    /// The jar without a classifier of each `group:artifact`.
    jars: HashMap<String, Pinned>,
    /// The `group:artifact` that a repository of the lock lists. For a jar
    /// that only `m2local` gives, the ruleset makes a repository on a
    /// machine whose Maven local repository holds the jar, and none on
    /// another (`download_pinned_deps` at 6.5 and 7.2).
    listed: HashSet<String>,
}

impl Lock {
    /// Reads a lock. An empty file (the hub is not pinned yet), text that
    /// is no JSON of this shape (a merge conflict), and any other format
    /// are an error: the reason.
    pub fn parse(text: &str) -> Result<Lock, String> {
        #[derive(serde::Deserialize)]
        struct Artifact {
            version: String,
            #[serde(default)]
            shasums: HashMap<String, Option<String>>,
        }
        #[derive(serde::Deserialize)]
        struct Raw {
            version: Option<String>,
            #[serde(default)]
            artifacts: HashMap<String, Artifact>,
            #[serde(default)]
            repositories: HashMap<String, HashSet<String>>,
            #[serde(default)]
            skipped: HashSet<String>,
            #[serde(default)]
            m2local: bool,
        }
        if text.trim().is_empty() {
            return Err("it is empty: the hub is not pinned yet".to_string());
        }
        let raw: Raw = serde_json::from_str(text).map_err(|e| format!("it is no lock ({e})"))?;
        let format = match raw.version.as_deref() {
            Some("2") => 2,
            Some("3") => 3,
            _ => return Err("it is not a lock of format 2 or 3".to_string()),
        };
        let jar = |(key, mut artifact): (String, Artifact)| {
            // A third part of the key is a packaging other than `jar`, and
            // every other name among the sums is a classifier.
            let sum = artifact.shasums.remove("jar")?;
            let lists = |keys: &HashSet<String>| keys.contains(&key);
            let listed = raw.m2local || raw.repositories.values().any(lists);
            let pinned = Pinned {
                version: artifact.version,
                fetched: sum.is_some() && listed && !raw.skipped.contains(&key),
                jar_sha256: sum,
            };
            (key.matches(':').count() == 1).then_some((key, pinned))
        };
        let jars = raw.artifacts.into_iter().filter_map(jar).collect();
        let listed = raw.repositories.into_values().flatten().collect();
        Ok(Lock {
            format,
            jars,
            listed,
        })
    }

    /// The jar of `group:artifact` without a classifier, when the lock
    /// holds one.
    pub fn plain_jar(&self, group: &str, artifact: &str) -> Option<&Pinned> {
        self.jars.get(&format!("{group}:{artifact}"))
    }
}

/// The name a hub gives the target of an artifact: `escape` in the
/// ruleset's `private/coursier_utilities.bzl` at 6.5, 6.9 and 7.2. An
/// override replaces the artifact whose target has the name of its
/// `coordinates`.
fn target(coordinates: &str) -> String {
    let first = coordinates.split(',').next().unwrap_or_default();
    let named = first.replace(['.', '-', ':', '/', '+', '$'], "_");
    named.replace(['[', ']'], "")
}

/// Why a hub that fetches a jar may not build it.
const OVERRIDDEN: &str = "a `maven.override` gives this artifact another target";

/// What kind of doubt one is: a hosted run gives its warning by it. What
/// the reader itself doubts is [`Kind::Unread`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind<'a> {
    /// Something could not be read.
    Unread,
    /// The hub of this name has no lock.
    Unpinned(&'a str),
    /// A `maven.override` may put another target in the jar's place.
    Overridden,
}

/// Whether Bazel builds an artifact through a hub of the workspace.
#[derive(Debug, PartialEq, Eq)]
pub enum Built<'a> {
    /// No hub does, and every hub was read.
    No,
    /// These pinned hubs fetch its jar at that version.
    Yes(Vec<(&'a Hub, &'a Pinned)>),
    /// It is not known. No hub that was read fetches its jar and this
    /// could not be read, or one does and this `maven.override` may put
    /// another target in the jar's place.
    Unknown(&'a Doubt, Kind<'a>),
}

/// What the root module says of the release of the ruleset that Bazel
/// builds with. Bazel takes an override from the root module alone, and
/// before any `bazel_dep` (`applyOverrides`: InterimModule.java at 7.4.0,
/// Discovery.java lines 158 and 159 at 7.7.2, 178 and 179 at 8.8.2 and
/// 9.3.2).
#[derive(Debug, PartialEq, Eq)]
enum Asked {
    /// No version is given.
    Nothing,
    /// A `bazel_dep` asks for this release: Bazel selects it or a newer
    /// one that another module asks for.
    AtLeast(String),
    /// A `single_version_override` pins this release, whatever is asked.
    Exactly(String),
    /// An override takes the ruleset from no registry (`archive_override`,
    /// `git_override`, `local_path_override`), keeps more than one release
    /// of it (`multiple_version_override`) or pins a version that is no
    /// string: where it is, for a warning.
    Unknown(String),
}

/// A version of a Bazel module in the order Bazel has for them
/// (`Version.java` of `bazel/bzlmod`, the same order at 7.4.0, 7.7.2,
/// 8.8.2 and 9.3.2): by the identifiers between the dots of its release,
/// a number before a word and by its value; a release before a longer one
/// that starts with it; a prerelease before its release; and nothing of
/// what follows a `+`.
fn ordered(version: &str) -> impl Ord + '_ {
    fn identifiers(part: &str) -> Vec<(bool, u64, &str)> {
        let parts = part.split('.').filter(|id| !id.is_empty());
        let identifier = |id| match str::parse::<u64>(id) {
            Ok(number) => (false, number, id),
            Err(_) => (true, 0, id),
        };
        parts.map(identifier).collect()
    }
    let version = version.split('+').next().unwrap_or(version);
    let (release, pre) = version.split_once('-').unwrap_or((version, ""));
    (identifiers(release), pre.is_empty(), identifiers(pre))
}

/// What the root module of `ws` says of the ruleset's release: by its
/// calls that name the ruleset, a `bazel_dep` and the overrides, which are
/// the functions whose name ends in `_override`.
fn asked(ws: &Workspace) -> Asked {
    let named = Some(&Value::Str(EXTENSION.module.to_string()));
    let names = |call: &&Call| {
        call.bind.is_none() && [call.arg("name"), call.arg("module_name")].contains(&named)
    };
    let mut calls = Vec::new();
    for (file, read) in &ws.files {
        calls.extend(read.calls.iter().filter(names).map(|call| (file, call)));
    }
    let version = |callee: &str| {
        let call = calls.iter().find(|(_, call)| call.callee == callee);
        call.and_then(|(_, call)| call.arg("version"))
    };
    let pin = "single_version_override";
    let unknown = |(_, call): &&(&String, &Call)| {
        let read = matches!(call.arg("version"), None | Some(Value::Str(_)));
        call.callee.ends_with("_override") && (call.callee != pin || !read)
    };
    if let Some((file, call)) = calls.iter().find(unknown) {
        let at = format!("{file}:{}: with this `{}`", call.line, call.callee);
        return Asked::Unknown(at);
    }
    match (version(pin), version("bazel_dep")) {
        (Some(Value::Str(pinned)), _) if !pinned.is_empty() => Asked::Exactly(pinned.clone()),
        (_, Some(Value::Str(least))) if !least.is_empty() => Asked::AtLeast(least.clone()),
        _ => Asked::Nothing,
    }
}

/// What the hubs of a workspace build: read once, asked per artifact.
#[derive(Debug)]
pub struct Hubs {
    pinned: Vec<(Hub, Rc<Lock>)>,
    /// The `override` tags of the root module: the [`target`] each
    /// replaces (`None`: its `coordinates` are no string, so any), and
    /// where it is. The tag's `name` is not asked for: the ruleset at 6.5
    /// takes an override for every hub.
    overrides: Vec<(Option<String>, Doubt)>,
    /// The first thing that could not be read.
    doubt: Option<Doubt>,
    /// The hub whose missing lock that doubt is, when it is one.
    lockless: Option<String>,
    /// The patches of the block in the root `MODULE.bazel`. None when the
    /// block was changed by hand, which is a doubt.
    pub block: Vec<Patch>,
    /// The line of a block that was changed by hand.
    edited: Option<usize>,
    /// What the root says of the release of the ruleset.
    asked: Asked,
    /// Whether the workspace has to do with the ruleset: a call of a file
    /// that was read names it, its `WORKSPACE` file calls `maven_install`,
    /// or a `maven_install.json` lies at the root. In another workspace a
    /// doubt is about no hub ([`hub_jars`]).
    ruleset: bool,
    /// Whether a `WORKSPACE` file of the root defines anything
    /// ([`Workspace::legacy`]), which is what a Bazel before 7.0 builds.
    legacy: bool,
}

impl Hubs {
    /// Reads the hubs of the workspace behind `view` and the overrides,
    /// and the lock of each hub through `locks`, a view of the same
    /// workspace that may hand out a larger file. A hub without a lock, a
    /// lock that cannot be read, and a `WORKSPACE` file that calls
    /// `maven_install` or cannot be read while Bazel may read it (the
    /// workspace names no release, or one before 9) are doubts.
    pub fn read(view: &dyn Fn(&str) -> Entry, locks: &dyn Fn(&str) -> Entry) -> Hubs {
        Hubs::read_within(view, locks, usize::MAX)
    }

    /// [`Hubs::read`] with at most `room` bytes of locks in all: the lock
    /// that does not fit is a doubt, and so is every lock after it, which
    /// is not read.
    fn read_within(
        view: &dyn Fn(&str) -> Entry,
        locks: &dyn Fn(&str) -> Entry,
        mut room: usize,
    ) -> Hubs {
        // The block is socket-patch's own: the workspace is read without
        // it, as the user wrote it, and with every line where it was. A
        // block that was changed by hand is read like any other text.
        let (mut block, mut edited, mut hidden) = (Vec::new(), None, None);
        if let Entry::Text(module) = view(FILE) {
            match find(&module) {
                Block::None => {}
                Block::Edited(line) => edited = Some(line),
                Block::Ours(at, _, patches) => {
                    let lines = "\n".repeat(module[at.clone()].matches('\n').count());
                    let (head, tail) = (&module[..at.start], &module[at.end..]);
                    hidden = Some(format!("{head}{lines}{tail}"));
                    block = patches;
                }
            }
        }
        let view = |path: &str| match &hidden {
            Some(module) if path == FILE => Entry::Text(module.clone()),
            _ => view(path),
        };
        let view: &dyn Fn(&str) -> Entry = &view;
        let ws = Workspace::read(view);
        let (hubs, mut doubts) = hubs(&ws);
        doubts.splice(
            0..0,
            edited.map(|line| Doubt {
                file: FILE.to_string(),
                line,
                why: "the block that socket-patch keeps there was changed by hand".to_string(),
            }),
        );
        let asked = asked(&ws);
        let overrides = ws.tags(&EXTENSION, "override").calls.into_iter();
        let overrides = overrides.map(|Tag { file, call, .. }| {
            let (replaced, why) = match call.arg("coordinates") {
                Some(Value::Str(artifact)) => (Some(target(artifact)), OVERRIDDEN),
                _ => (None, "this `maven.override` cannot be read"),
            };
            let (file, line, why) = (file.to_string(), call.line, why.to_string());
            (replaced, Doubt { file, line, why })
        });
        let overrides = overrides.collect();
        let (mut pinned, mut lockless) = (Vec::new(), None);
        let mut read_locks = HashMap::new();
        let past = || {
            let bound = MAX_LOCKS >> 20;
            Err(format!(
                "the locks of the workspace are larger than {bound} MiB in all"
            ))
        };
        for hub in hubs {
            // Where a doubt about its lock is: the lock, or the tag.
            let (file, line) = match &hub.lock {
                Some(lock) => (lock.clone(), 0),
                None => (hub.file.clone(), hub.line),
            };
            let lock = match &hub.lock {
                None => Err(format!("hub \"{}\" {NO_LOCK}", hub.name)),
                Some(path) => {
                    let parsed = || match (room > 0).then(|| locks(path)) {
                        None => past(),
                        Some(Entry::Text(text)) if text.len() > room => {
                            room = 0;
                            past()
                        }
                        Some(Entry::Text(text)) => {
                            room -= text.len();
                            Lock::parse(&text).map(Rc::new)
                        }
                        Some(Entry::Absent) => Err("it does not exist".to_string()),
                        Some(Entry::Unreadable(why)) => Err(format!("it cannot be read: {why}")),
                    };
                    let lock = read_locks.entry(path.clone()).or_insert_with(parsed);
                    lock.clone()
                }
            };
            match lock {
                Ok(lock) => pinned.push((hub, lock)),
                Err(why) => {
                    let first = hub.lock.is_none() && doubts.is_empty();
                    lockless = lockless.or(first.then(|| hub.name.clone()));
                    doubts.push(Doubt { file, line, why });
                }
            }
        }
        let module = Value::Str(EXTENSION.module.to_string());
        let names =
            |call: &Call| [call.arg("name"), call.arg("module_name")].contains(&Some(&module));
        let named = ws
            .files
            .iter()
            .any(|(_, file)| file.calls.iter().any(names));
        let (calls, defined) = (matches!(ws.legacy, Some(Ok(_))), ws.legacy.is_some());
        let before_9 = || declared_release(view).is_none_or(|release| release < (9, 0, 0));
        let legacy = match ws.legacy.filter(|_| before_9()) {
            Some(Ok((file, read))) => {
                // By its own name, or by one that a `load` gives it.
                let symbol = Value::Str("maven_install".to_string());
                let loads = read.calls.iter().filter(|call| call.callee == "load");
                let args = loads.flat_map(|load| &load.args);
                let aliases = args.filter_map(|arg| match &arg.how {
                    How::Keyword(alias) if arg.value == symbol => Some(alias.as_str()),
                    _ => None,
                });
                let names: Vec<_> = aliases.chain(["maven_install"]).collect();
                let installs = |call: &&Call| names.contains(&call.callee.as_str());
                read.calls.iter().find(installs).map(|call| Doubt {
                    file,
                    line: call.line,
                    why: "a `maven_install` of a WORKSPACE file is not read".to_string(),
                })
            }
            unread => unread.and_then(Result::err),
        };
        let ruleset =
            named || (calls && legacy.is_some()) || view("maven_install.json") != Entry::Absent;
        doubts.extend(legacy);
        Hubs {
            pinned,
            overrides,
            doubt: doubts.into_iter().next(),
            lockless,
            block,
            edited,
            asked,
            ruleset,
            legacy: defined,
        }
    }

    /// Whether Bazel builds the jar of `group:artifact` at `version`.
    pub fn built(&self, group: &str, artifact: &str, version: &str) -> Built<'_> {
        let mut by = Vec::new();
        for (hub, lock) in &self.pinned {
            let jar = lock.plain_jar(group, artifact);
            let fetched = jar.filter(|jar| jar.fetched && jar.version == version);
            by.extend(fetched.map(|jar| (hub, jar)));
        }
        // In the place of a jar that a hub fetches, an override puts the
        // target it names: what that one builds is not read.
        let named = Some(target(&format!("{group}:{artifact}")));
        let over = |(of, _): &&(Option<String>, Doubt)| of.is_none() || *of == named;
        match self.overrides.iter().find(over) {
            _ if by.is_empty() => self
                .doubt()
                .map_or(Built::No, |(doubt, kind)| Built::Unknown(doubt, kind)),
            Some((Some(_), tag)) => Built::Unknown(tag, Kind::Overridden),
            Some((None, tag)) => Built::Unknown(tag, Kind::Unread),
            None => Built::Yes(by),
        }
    }

    /// The first thing that could not be read, and its kind.
    fn doubt(&self) -> Option<(&Doubt, Kind<'_>)> {
        let unpinned = self.lockless.as_deref().map(Kind::Unpinned);
        Some((self.doubt.as_ref()?, unpinned.unwrap_or(Kind::Unread)))
    }

    /// [`Hubs::built`] for a run that writes an entry or trusts one: not
    /// known either beside a hub that fetches the jar, when anything was
    /// not read. That may be another hub that builds the upstream one.
    fn sure(&self, group: &str, artifact: &str, version: &str) -> Built<'_> {
        match (self.built(group, artifact, version), self.doubt()) {
            (Built::Yes(_), Some((doubt, kind))) => Built::Unknown(doubt, kind),
            (built, _) => built,
        }
    }

    /// The id of the patch whose entry the block holds for the jar of
    /// `group:artifact` at `version`: where the block is in effect, Bazel
    /// takes that entry's jar in the place of a hub's.
    fn held(&self, group: &str, artifact: &str, version: &str) -> Option<&str> {
        let jar = |patch: &&Patch| {
            (&*patch.group, &*patch.artifact, &*patch.version) == (group, artifact, version)
        };
        self.block.iter().find(jar).map(|patch| &*patch.uuid)
    }
}

/// One patch in the block: the jar that takes the place of the one a hub
/// fetches for `group:artifact` at `version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    pub group: String,
    pub artifact: String,
    pub version: String,
    pub uuid: String,
    /// The sha256 of the patched jar, which Bazel checks its download by,
    /// and the URL of that jar on the patch host. Both are empty in the
    /// entry of vendored mode, whose jar is in the checkout
    /// ([`Patch::unit`]).
    pub sha256: String,
    pub url: String,
}

/// The directory of the checkout that holds the directory of each patch
/// that vendored mode keeps for a hub, and the file that makes such a
/// directory a repository.
pub const UNITS: &str = ".socket/vendor/maven";
pub const REPO: &str = "REPO.bazel";

impl Patch {
    pub fn purl(&self) -> String {
        let (group, artifact) = (&self.group, &self.artifact);
        format!("pkg:maven/{group}/{artifact}@{}", self.version)
    }

    /// The directory of a vendored entry, from the Bazel root, which is
    /// the repository of its jar. `None` for the entry of hosted mode.
    pub fn unit(&self) -> Option<String> {
        self.url
            .is_empty()
            .then(|| format!("{UNITS}/{}", self.uuid))
    }

    /// The patched jar in [`Patch::unit`], under the name of the upstream
    /// jar.
    pub fn jar(&self) -> Option<String> {
        let (unit, artifact, version) = (self.unit()?, &self.artifact, &self.version);
        Some(format!("{unit}/file/{artifact}-{version}.jar"))
    }

    fn repository(&self) -> String {
        repository_name(&self.group, &self.artifact, &self.version).unwrap_or_default()
    }
}

/// The name of the repository through which a hub fetches the jar of
/// `group:artifact` at `version`, on every release of [`RULESETS`]: the
/// three joined by `_`, with `_` for each `.` and `-`. `None` for a
/// coordinate with any character but letters, digits, `.`, `_` and `-`:
/// the ruleset's two functions agree, and were read, for those alone.
pub fn repository_name(group: &str, artifact: &str, version: &str) -> Option<String> {
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"._-".contains(&b);
    let parts = [group, artifact, version];
    let named = |part: &&str| !part.is_empty() && part.bytes().all(plain);
    let named = parts.iter().all(named);
    named.then(|| parts.join("_").replace(['.', '-'], "_"))
}

/// The block for `patches` under the label of the hub's `use_extension`,
/// from [`BEGIN`] to [`END`], with a line feed between its lines: the
/// patches by the name of their repository, each with an `override_repo`
/// of its own, so that Bazel names the line of the one entry whose jar
/// the hub's lock no longer pins. `bazel mod tidy` keeps this text.
fn render(label: &str, patches: &[Patch]) -> String {
    let entry = |patch: &Patch| {
        let (group, artifact, version) = (&patch.group, &patch.artifact, &patch.version);
        let (name, purl, uuid) = (patch.repository(), patch.purl(), &patch.uuid);
        let (sha256, url) = (&patch.sha256, &patch.url);
        let file = artifact_path(group, artifact, version, None, "jar");
        let repository = match patch.unit() {
            Some(unit) => format!(
                "socket_patch_local_repository(\n    \
                 name = \"socket_patch_{name}\",\n    \
                 path = \"{unit}\",\n)"
            ),
            None => format!(
                "socket_patch_http_file(\n    \
                 name = \"socket_patch_{name}\",\n    \
                 downloaded_file_path = \"v1/{file}\",\n    \
                 sha256 = \"{sha256}\",\n    \
                 urls = [\"{url}\"],\n)"
            ),
        };
        format!(
            "# {purl}, Socket patch {uuid}\n\
             {repository}\n\n\
             # If Bazel stops at the next line (\"does not generate repository\"), the hub's \
             lock no longer pins\n\
             # {group}:{artifact} at {version}: run `socket-patch rollback {purl}`.\n\
             # Do not change it to inject_repo(): the build would pass without the patch.\n\
             override_repo(\n    socket_patch_maven,\n    \
             {name} = \"socket_patch_{name}\",\n)\n"
        )
    };
    let mut patches: Vec<&Patch> = patches.iter().collect();
    patches.sort_by_key(|patch| patch.repository());
    // The rule of each kind of entry there is, hosted first.
    let rules = [
        ("http", "http_file", false),
        ("local", "local_repository", true),
    ];
    let used = |(_, _, vendored): &&(&str, &str, bool)| {
        patches
            .iter()
            .any(|patch| patch.url.is_empty() == *vendored)
    };
    let rule = |(file, rule, _): &(&str, &str, bool)| {
        format!(
            "socket_patch_{rule} = use_repo_rule(\
             \"@bazel_tools//tools/build_defs/repo:{file}.bzl\", \"{rule}\")\n"
        )
    };
    let rules: String = rules.iter().filter(used).map(rule).collect();
    let entries: Vec<String> = patches.into_iter().map(entry).collect();
    format!(
        "{BEGIN}\n{rules}\n\
         socket_patch_maven = use_extension(\"{label}\", \"maven\")\n\n{}{END}",
        entries.join("\n")
    )
}

/// The label and the patches that the lines of a block name, when each
/// patch has every field.
fn parse(body: &str) -> Option<(String, Vec<Patch>)> {
    let lines: Vec<&str> = body.lines().collect();
    let between = |line: &str, open: &str, close: &str| {
        Some(line.strip_prefix(open)?.strip_suffix(close)?.to_string())
    };
    let proxy = ("socket_patch_maven = use_extension(\"", "\", \"maven\")");
    let label = lines
        .iter()
        .find_map(|line| between(line, proxy.0, proxy.1))?;
    let mut patches = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let Some(named) = line.strip_prefix("# pkg:maven/") else {
            continue;
        };
        let (coordinates, uuid) = named.split_once(", Socket patch ")?;
        let (name, version) = coordinates.rsplit_once('@')?;
        let (group, artifact) = name.split_once('/')?;
        let field = |open: &str, close: &str| {
            let below = lines.get(at + 1..)?.iter().take(6);
            below.copied().find_map(|line| between(line, open, close))
        };
        // The entry of vendored mode names a directory, and nothing of
        // a host: which directory, [`find`] holds it to.
        let hosted = field("    path = \"", "\",").is_none();
        let of_host = |open: &str, close: &str| match hosted {
            true => field(open, close),
            false => Some(String::new()),
        };
        patches.push(Patch {
            group: group.to_string(),
            artifact: artifact.to_string(),
            version: version.to_string(),
            uuid: uuid.to_string(),
            sha256: of_host("    sha256 = \"", "\",")?,
            url: of_host("    urls = [\"", "\"],")?,
        });
    }
    Some((label, patches))
}

/// What a `MODULE.bazel` holds of the block.
#[derive(Debug, PartialEq, Eq)]
enum Block {
    None,
    /// The block as socket-patch writes it: where it is, from the first
    /// byte of [`BEGIN`] to the last of [`END`], its label and its patches.
    Ours(Range<usize>, String, Vec<Patch>),
    /// A block that is not what socket-patch writes for the patches it
    /// names: the line of its [`BEGIN`].
    Edited(usize),
}

/// Whether `line` is the first line of a block, as it is written or
/// touched (a blank after it, another end): [`BEGIN`] up to its bracket.
/// A file without such a line holds no block.
pub fn begins(line: &str) -> bool {
    let mark = BEGIN.split(" (").next().unwrap_or(BEGIN);
    line.trim_start().starts_with(mark)
}

fn find(text: &str) -> Block {
    let (mut at, mut begin, mut end) = (0, None, None);
    for (line, whole) in text.split_inclusive('\n').enumerate() {
        let bare = whole.strip_suffix('\n').unwrap_or(whole);
        let bare = bare.strip_suffix('\r').unwrap_or(bare);
        match (bare, begin, end) {
            (BEGIN, None, _) => begin = Some((at, line + 1)),
            // A second first line, or one that is not as it is written.
            _ if begins(bare) => {
                return Block::Edited(begin.map_or(line + 1, |(_, first)| first));
            }
            (END, Some(_), None) => end = Some(at + bare.len()),
            _ => {}
        }
        at += whole.len();
    }
    let Some((start, line)) = begin else {
        return Block::None;
    };
    // In the line break of its own lines, whatever the rest of a file
    // with both has.
    let ours = end.and_then(|end| {
        let (label, entries) = parse(&text[start..end])?;
        let written = render(&label, &entries).replace('\n', terminator(&text[start..end]));
        (written == text[start..end]).then_some((start..end, label, entries))
    });
    ours.map_or(Block::Edited(line), |(at, label, patches)| {
        Block::Ours(at, label, patches)
    })
}

/// `module` with `patch` in its block, in the place of any patch for the
/// same repository: in the block that is there, in the line break of its
/// lines, or in a new one at the end of the file, after one blank line,
/// in the line break of the file ([`terminator`]: the more frequent one
/// of a file with both). A file whose last line has no line break gets a
/// block without one, so that [`without`] can tell. `None` when the block
/// that is there was changed by hand.
pub fn with_patch(module: &str, label: &str, patch: Patch) -> Option<String> {
    let (at, mut patches) = match find(module) {
        Block::Edited(_) => return None,
        Block::None => (None, Vec::new()),
        Block::Ours(at, _, patches) => (Some(at), patches),
    };
    patches.retain(|other| other.repository() != patch.repository());
    patches.push(patch);
    let ended = module.is_empty() || module.ends_with('\n');
    let eol = terminator(at.as_ref().map_or(module, |at| &module[at.clone()]));
    let block = render(label, &patches).replace('\n', eol);
    Some(match at {
        Some(at) => format!("{}{block}{}", &module[..at.start], &module[at.end..]),
        None if ended => format!("{module}{eol}{block}{eol}"),
        None => format!("{module}{eol}{eol}{block}"),
    })
}

/// The patches of the block of `module`: none when it has no block, or one
/// that was changed by hand.
pub fn entries(module: &str) -> Vec<Patch> {
    match find(module) {
        Block::Ours(_, _, patches) => patches,
        _ => Vec::new(),
    }
}

/// The files of a vendored entry's directory ([`Patch::unit`]), each by
/// its path from the Bazel root: the file that makes the directory a
/// repository, the package `file` with the one target `file`, by which a
/// hub takes the jar of the repository it fetches (`@<repository>//file`
/// in the ruleset's `private/dependency_tree_parser.bzl` at 6.5, 6.9 and
/// 7.2), the jar, and a `.gitignore` that takes back a rule of the
/// checkout that ignores jars, so that git commits this one. `None` for
/// the entry of hosted mode.
pub fn unit_files(patch: &Patch, jar: Vec<u8>) -> Option<[(String, Vec<u8>); 4]> {
    let (unit, path) = (patch.unit()?, patch.jar()?);
    let name = path.rsplit('/').next().unwrap_or_default();
    let (purl, uuid) = (patch.purl(), &patch.uuid);
    let repo = format!(
        "# The jar of {purl} with Socket patch {uuid}, which the block of\n\
         # socket-patch in MODULE.bazel puts in the place of the one a hub fetches.\n\
         # `socket-patch vendor --check` holds the jar to the patch.\n"
    );
    let build = format!(
        "filegroup(\n    name = \"file\",\n    srcs = [\"{name}\"],\n    \
         visibility = [\"//visibility:public\"],\n)\n"
    );
    Some([
        (format!("{unit}/{REPO}"), repo.into_bytes()),
        (format!("{unit}/file/BUILD.bazel"), build.into_bytes()),
        (path, jar),
        (format!("{unit}/.gitignore"), b"!*\n".to_vec()),
    ])
}

/// What a decline says after its reason: what the block of `file` holds
/// for the jar, when `held` is the id of the patch of its entry there,
/// after a run for the patch `uuid` wrote nothing for the reason `code`.
fn left(held: Option<&str>, uuid: &str, code: &str, file: &str) -> String {
    match held {
        None => KEEPS.to_string(),
        Some(held) if held == uuid && code == NO_EFFECT => format!(
            "socket-patch left the entry that {file} holds for it as it is, and while that \
             stands the entry has no effect: the Bazel build keeps the upstream jar"
        ),
        Some(held) if held == uuid => {
            format!("socket-patch left the entry that {file} holds for it as it is")
        }
        Some(held) => format!(
            "socket-patch wrote nothing to {file} for it: the entry of patch {held} remains \
             there, and where the block is in effect the Bazel build takes that patch's jar"
        ),
    }
}

/// What a vendored run in `project` writes to the block for the patch
/// `uuid` of `purl`: the label and the entry, or the code of a decline and
/// what the run says of it (the detail of the patch's refusal, which names
/// the purl itself). `None` for a patch whose jar no hub builds or may
/// build, in no Bazel workspace, and for a jar with a classifier or of
/// another packaging: such a run is the one it was.
pub fn vendored(
    project: &Path,
    purl: &str,
    uuid: &str,
) -> Option<Result<(String, Patch), Declined>> {
    let (group, artifact, version) = parse_maven_purl(purl).filter(|_| plain(purl))?;
    let [group, artifact, version] = [group, artifact, version].map(|part| part.to_string());
    let jar: Jar = (uuid.to_string(), group, artifact, version);
    let (_, entry, held) = verdicts(project, None, std::slice::from_ref(&jar), true).pop()?;
    let (uuid, group, artifact, version) = jar;
    let patch = Patch {
        group,
        artifact,
        version,
        uuid,
        sha256: String::new(),
        url: String::new(),
    };
    Some(match entry {
        Ok(label) => Ok((label, patch)),
        Err((code, why)) => {
            let ends = left(held.as_deref(), &patch.uuid, code, FILE);
            Err((code, format!("{why}. {ends}")))
        }
    })
}

/// `module` without the patches of its block that `gone` names. With the
/// last one the block goes, and what [`with_patch`] put before it: the
/// file is then byte for byte what it was before its first patch. `None`
/// when the block is not there as socket-patch writes it.
pub fn without(module: &str, gone: &mut dyn FnMut(&Patch) -> bool) -> Option<String> {
    let Block::Ours(at, label, mut entries) = find(module) else {
        return None;
    };
    entries.retain(|patch| !gone(patch));
    let (head, tail) = (&module[..at.start], &module[at.end..]);
    if !entries.is_empty() {
        let block = render(&label, &entries).replace('\n', terminator(&module[at]));
        return Some(format!("{head}{block}{tail}"));
    }
    // The line break before the block and, when it ends a blank line, that
    // line; then the block's own line break or, for a block that ends the
    // file without one, the one that was added to the last line. A line
    // break is one of either kind: a file can have both.
    let cut =
        |text: &str| text.len() - text.ends_with('\n') as usize - text.ends_with("\r\n") as usize;
    let blank = |head: &str| cut(head) == 0 || head[..cut(head)].ends_with('\n');
    let after = tail.strip_prefix('\r').unwrap_or(tail).strip_prefix('\n');
    let (head, tail) = match after {
        Some(tail) if blank(head) => (&head[..cut(head)], tail),
        None if tail.is_empty() && blank(head) => (&head[..cut(&head[..cut(head)])], tail),
        Some(tail) => (head, tail),
        None => (head, tail),
    };
    Some(format!("{head}{tail}"))
}

/// What a hosted run does in the root `MODULE.bazel` for one patch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Verdict {
    /// Its entry is written, under this label for the block's
    /// `use_extension`; or nothing is written: the code of the warning,
    /// and why.
    pub entry: Result<String, (String, String)>,
    /// The id of the patch whose entry the block of the root holds for
    /// the jar of this one, when it holds one.
    pub held: Option<String>,
}

/// The verdict for each patch whose jar a hub builds or may build, by the
/// id of the patch. A patch whose jar no hub builds has none, and neither
/// has one that is not among the [`jars`] of the run.
pub type Site = BTreeMap<String, Verdict>;

/// A patch of the plain jar of an artifact: its id, and the group, the
/// artifact and the version of the jar.
pub type Jar = (String, String, String, String);

/// A code of this module, and why.
pub type Declined = (&'static str, String);

/// What a warning says after the reason, when the block holds no entry
/// for the jar.
const KEEPS: &str = "socket-patch wrote nothing to MODULE.bazel for it, so the Bazel build keeps \
                     the upstream jar";

/// Where a doubt is: its file, with its line when it is about one.
fn at(doubt: &Doubt) -> String {
    match doubt.line {
        0 => doubt.file.clone(),
        line => format!("{}:{line}", doubt.file),
    }
}

/// Why no entry is written for a jar that a hub may build.
fn unknown(doubt: &Doubt, kind: Kind) -> Declined {
    let (at, why) = (at(doubt), &doubt.why);
    match kind {
        Kind::Unpinned(hub) => {
            let why = format!(
                "{at}: {why}, so Bazel resolves its jars when it builds and none can be \
                 replaced: give the hub a `lock_file` and pin it (`REPIN=1 bazel run \
                 @{hub}//:pin`)"
            );
            (NOT_PINNED, why)
        }
        Kind::Overridden => {
            let remedy = "patch that target, or remove the override";
            let why = format!("{at}: {why}, so Bazel would not build a patched jar: {remedy}");
            (NO_EFFECT, why)
        }
        Kind::Unread => {
            let why = format!(
                "socket-patch could not tell whether Bazel takes this artifact from a \
                 rules_jvm_external hub: {at}: {why}"
            );
            (UNREADABLE, why)
        }
    }
}

/// What in the rc files of the checkout stands against an entry, for the
/// Bazel `release` the checkout names, in the order it is read: an option
/// that leaves the entry without effect ([`NO_EFFECT`]) or its jar out of
/// reach ([`DOWNLOAD`]), or an rc file that cannot be read
/// ([`UNREADABLE`]), which may hold either.
fn rc(view: &dyn Fn(&str) -> Entry, release: Option<super::rc::Release>) -> Vec<Declined> {
    let flags = [
        "ignore_dev_dependency",
        "enable_bzlmod",
        "downloader_config",
        "repository_disable_download",
        "vendor_dir",
    ];
    let against = |(file, line, word): (String, usize, String)| {
        // On or off as Bazel reads a boolean option (`BooleanConverter`
        // in Converters.java at 7.4.0, 7.7.2, 8.8.2 and 9.3.2): by a `no`
        // before its name, or by a value, in any case.
        let (name, value) = word.split_once('=').unwrap_or((&word, ""));
        let (given, value) = (word.contains('='), value.to_ascii_lowercase());
        let is = |values: [&str; 5]| values.contains(&&*value);
        let no = name.starts_with("--no");
        let on = name.starts_with("--") && !no && (!given || is(["true", "1", "yes", "t", "y"]));
        let off = (no && !given) || (!no && is(["false", "0", "no", "f", "n"]));
        let bzlmod = word.contains(flags[1]);
        let valued = word.contains(flags[2]) || word.contains(flags[4]);
        // What changes nothing: Bzlmod switched on, which Bazel 9 always
        // has, and another option switched off. A word that is neither
        // for certain is taken for the one that does harm.
        let always = release.is_some_and(|r| r >= (9, 0, 0));
        if (bzlmod && (on || always)) || (!bzlmod && !valued && off) {
            return None;
        }
        let (code, why) = match (bzlmod, word.contains(flags[0])) {
            (true, _) => (
                NO_EFFECT,
                "which switches off the file an entry is written to",
            ),
            (_, true) => (NO_EFFECT, "under which Bazel can drop the tags of a hub"),
            _ => (
                DOWNLOAD,
                "under which Bazel may not download the patched jar from the Socket patch host",
            ),
        };
        Some((code, format!("{file}:{line} names `{word}`, {why}")))
    };
    match mentions(view, &flags) {
        Ok(found) => found.into_iter().filter_map(against).collect(),
        Err(file) => {
            let why = format!("the rc file {file} cannot be read, and may switch an entry off");
            vec![(UNREADABLE, why)]
        }
    }
}

/// What must hold of the workspace at `root` for any entry: the file can
/// be written, Bazel has `override_repo`, the release of the ruleset is
/// one of [`RULESETS`], and no rc file switches an entry off.
fn settings(
    root: &Path,
    view: &dyn Fn(&str) -> Entry,
    locks: &dyn Fn(&str) -> Entry,
    asked: &Asked,
    vendored: bool,
) -> Result<(), Declined> {
    let link = std::fs::symlink_metadata(root.join(FILE)).is_ok_and(|meta| meta.is_symlink());
    if link {
        let why = format!("{FILE} is a symbolic link, which socket-patch does not write through");
        return Err((UNREADABLE, why));
    }
    let lock = match locks("MODULE.bazel.lock") {
        Entry::Text(lock) => ModuleLock::parse(&lock),
        _ => ModuleLock::default(),
    };
    let release = declared_release(view);
    match release {
        Some((major, minor, patch)) if (major, minor, patch) < (7, 4, 0) => {
            let why = format!(
                "the checkout names Bazel {major}.{minor}.{patch} (`.bazeliskrc` or \
                 `.bazelversion`), and an entry needs `override_repo`, which Bazel has from 7.4.0"
            );
            return Err((RELEASE, why));
        }
        None if lock.version.is_none_or(|version| version < 13) => {
            let why = "no file of the checkout says that Bazel 7.4.0 or later builds it, and an \
                       older Bazel fails on the `override_repo` an entry needs: name the release \
                       in `.bazelversion`";
            return Err((RELEASE, why.to_string()));
        }
        _ => {}
    }
    // A lock that holds another release than the root now takes is one
    // that Bazel has not written since: older than what is asked for, or
    // any other than the one a `single_version_override` pins.
    let module = EXTENSION.module;
    let stale = |selected: &str| match asked {
        Asked::Exactly(pinned) => ordered(pinned) != ordered(selected),
        Asked::AtLeast(least) => ordered(least) > ordered(selected),
        Asked::Nothing | Asked::Unknown(_) => false,
    };
    let wanted = match asked {
        Asked::Exactly(wanted) | Asked::AtLeast(wanted) => wanted.as_str(),
        Asked::Nothing | Asked::Unknown(_) => "",
    };
    let why = match (asked, &lock.selected(module)[..]) {
        (Asked::Unknown(at), _) => format!(
            "{at} of {module} socket-patch cannot tell which release of the ruleset Bazel \
             builds with, and the name of a jar's repository depends on it"
        ),
        (_, [selected]) if !RULESETS.contains(selected) => format!(
            "Bazel selected {module} {selected}, and how the ruleset names the repository of a \
             jar is known for its releases 6.4 to 7.2: update socket-patch"
        ),
        (_, [selected]) if stale(selected) => format!(
            "{FILE} asks for {module} {wanted} and MODULE.bazel.lock holds {selected}: build once \
             so that Bazel updates its lock"
        ),
        // The jar of a vendored entry is in the checkout: no option about
        // downloads stands against it.
        (_, [_]) => {
            let against = |(code, _): &Declined| !vendored || *code != DOWNLOAD;
            return rc(view, release)
                .into_iter()
                .find(against)
                .map_or(Ok(()), Err);
        }
        _ => format!(
            "MODULE.bazel.lock does not say which release of {module} Bazel selected, and the \
             name of a jar's repository depends on it: build once so that Bazel writes its lock"
        ),
    };
    Err((RELEASE, why))
}

impl Hubs {
    /// The label for the block of the jar of `group:artifact` at
    /// `version`, which a pinned hub fetches, or why no entry for it can
    /// be written.
    fn label(&self, group: &str, artifact: &str, version: &str) -> Result<String, Declined> {
        let (key, mut label) = (format!("{group}:{artifact}"), None);
        if repository_name(group, artifact, version).is_none() {
            let why = format!(
                "the repository a hub fetches {key}:{version} through has a name socket-patch \
                 knows only for coordinates of letters, digits, `.`, `_` and `-`"
            );
            return Err((ARTIFACT, why));
        }
        let fetches = |lock: &Lock| {
            let jar = lock.plain_jar(group, artifact);
            jar.is_some_and(|jar| jar.fetched && jar.version == version)
        };
        for (hub, lock) in self.pinned.iter().filter(|(_, lock)| fetches(lock)) {
            let from = hub.lock.as_deref().unwrap_or_default();
            if !lock.listed.contains(&key) {
                let why = format!(
                    "{from} lists no repository for {key}: the hub takes the jar from the Maven \
                     local repository, and on a machine without it there is no repository for \
                     an entry to replace"
                );
                return Err((ARTIFACT, why));
            }
            let Some(proxy) = &hub.proxy else {
                let why = format!(
                    "{}:{}: a tag of hub \"{}\" is called on a `use_extension` that is isolated \
                     or cannot be read, which no `override_repo` of another usage reaches",
                    hub.file, hub.line, hub.name
                );
                return Err((UNREADABLE, why));
            };
            label.get_or_insert_with(|| proxy.clone());
        }
        label.ok_or_else(|| (UNREADABLE, format!("no hub that fetches {key} was read")))
    }
}

/// Whether the Maven purl names the jar a lock names by group and
/// artifact alone: one without a classifier, of no other packaging.
fn plain(purl: &str) -> bool {
    !is_variant(
        purl_qualifier(purl, "type"),
        purl_qualifier(purl, "classifier"),
    )
}

/// The plain jars among the patches of a hosted run, each given by its
/// purl and its grant, under the group and the artifact the pom lane pins
/// ([`maven_coordinates`]). A patch of a jar with a classifier, or of
/// another packaging, is none: [`site`] has no verdict for it, so
/// [`rewrite`] writes no entry for it and the hub confirms nothing of it,
/// whatever patch of the plain jar runs beside it.
pub fn jars<'a>(patches: impl Iterator<Item = (&'a str, &'a DepOverride)>) -> Vec<Jar> {
    let jar = |(purl, dep): (&str, &DepOverride)| {
        let (_, group, artifact) = maven_coordinates(dep);
        let jar = (dep.patch_uuid.clone(), group, artifact, dep.version.clone());
        (dep.ecosystem == "maven" && plain(purl)).then_some(jar)
    };
    patches.filter_map(jar).collect()
}

/// What a hosted run in `project` may write for each of `jars`, or with
/// `vendored` a vendored one: read once per run from the checkout.
/// `module` is the text of the project's own
/// `MODULE.bazel` as the run has it, when it has read it. Empty for a
/// project in no Bazel workspace and when no hub builds, or may build,
/// any of the jars: nothing changes for such a run. An entry is written
/// only when nothing of the workspace's hubs is in doubt: a hub without a
/// lock, or one that could not be read, may build the upstream jar beside
/// the hub that would get the patched one. A project below the root gets
/// no entry: the root is read all the same, for what its block holds.
pub fn site(project: &Path, module: Option<&str>, jars: &[Jar], vendored: bool) -> Site {
    let verdict = |(uuid, entry, held): (String, Result<String, Declined>, _)| {
        let entry = entry.map_err(|(code, why)| (code.to_string(), why));
        (uuid, Verdict { entry, held })
    };
    let read = verdicts(project, module, jars, vendored).into_iter();
    read.map(verdict).collect()
}

/// [`site`], with the code of a decline as this module has it: for each
/// jar that a hub builds or may build, the id of its patch, the label to
/// write its entry under or why none is written, and the id of the patch
/// whose entry the block holds for the jar.
fn verdicts(
    project: &Path,
    module: Option<&str>,
    jars: &[Jar],
    vendored: bool,
) -> Vec<(String, Result<String, Declined>, Option<String>)> {
    let mut site = Vec::new();
    let Some(root) = super::bazel_root(project) else {
        return site;
    };
    let at_root = root.project.as_os_str().is_empty();
    let on_disk = disk(&root.dir);
    let view = |path: &str| match module {
        Some(module) if at_root && path == FILE => Entry::Text(module.to_string()),
        _ => on_disk(path),
    };
    let locks = disk_up_to(&root.dir, MAX_LOCK);
    let hubs = Hubs::read(&view, &locks);
    // What holds for every jar is asked once, and only for a jar a hub builds.
    let mut workspace = None;
    for (uuid, group, artifact, version) in jars {
        let entry = match hubs.sure(group, artifact, version) {
            Built::No => continue,
            Built::Unknown(doubt, kind) => Err(unknown(doubt, kind)),
            Built::Yes(_) if !at_root => {
                let why = format!(
                    "a hub of the Bazel workspace at {} builds this artifact, and this project \
                     is not its root, where the patch of a hub is written: run the command there",
                    root.dir.display()
                );
                Err((NOT_AT_ROOT, why))
            }
            Built::Yes(_) => hubs.label(group, artifact, version).and_then(|label| {
                let all = workspace.get_or_insert_with(|| {
                    settings(&root.dir, &view, &locks, &hubs.asked, vendored)
                });
                all.clone().map(|()| label)
            }),
        };
        let held = hubs.held(group, artifact, version).map(str::to_string);
        site.push((uuid.clone(), entry, held));
    }
    site
}

/// The [`Site`] among the candidate files of a hosted run: empty without
/// one. The pom lane asks it which patches a hub decides, and says "no
/// pom.xml" of the others alone.
pub fn handed(files: &BTreeMap<String, String>) -> Site {
    let site = files.get(SITE_KEY).map(|site| serde_json::from_str(site));
    site.and_then(Result::ok).unwrap_or_default()
}

/// The hosted lane for the hubs of a Bazel workspace, after the pom lane:
/// for each patch of `overrides` that the [`Site`] among `files` has a
/// verdict for, its entry in the block of `MODULE.bazel`, or the warning
/// that says why there is none and what the block holds for the jar. A
/// patch whose entry is in the block, written now or before, is
/// confirmed. Without a site nothing is done.
pub fn rewrite(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let site = handed(files);
    let mut module = files.get(FILE).cloned();
    // The file of the block: not the project's own below the Bazel root.
    let file = match module {
        Some(_) => FILE.to_string(),
        None => format!("the {FILE} at the root"),
    };
    for dep in overrides {
        let Some(verdict) = site.get(&dep.patch_uuid) else {
            continue;
        };
        let (maven2, group, artifact) = maven_coordinates(dep);
        let purl = format!("pkg:maven/{group}/{artifact}@{}", dep.version);
        let written = verdict.entry.clone().and_then(|label| {
            let incomplete = |what: &str| (ARTIFACT.to_string(), what.to_string());
            let suffixed = maven2.and_then(|ov| ov.identifiers.maven_suffixed_version.as_deref());
            let sha256 = dep.integrity.sha256.as_deref().map(bare_sha256_hex);
            let sha256 = sha256.filter(|sum| is_hex64_lower(sum));
            let (Some(ov), Some(suffixed), Some(sha256)) = (maven2, suffixed, sha256) else {
                let what = "the patch comes without the version its jar is served under, or \
                            without the jar's sha256";
                return Err(incomplete(what));
            };
            let file = artifact_path(&group, &artifact, suffixed, None, "jar");
            let url = format!("{}/{file}", ov.index_url.trim_end_matches('/'));
            let quoted = |b: u8| !b.is_ascii_graphic() || b == b'"' || b == b'\\';
            if url.bytes().chain(dep.patch_uuid.bytes()).any(quoted) {
                return Err(incomplete(
                    "the URL of the patched jar cannot stand in a string",
                ));
            }
            let patch = Patch {
                group: group.clone(),
                artifact: artifact.clone(),
                version: dep.version.clone(),
                uuid: dep.patch_uuid.clone(),
                sha256,
                url,
            };
            let module = module
                .as_deref()
                .and_then(|module| with_patch(module, &label, patch));
            module.ok_or_else(|| incomplete("the block there cannot be written to"))
        });
        let (code, why) = match written {
            Ok(text) => {
                module = Some(text);
                result
                    .confirmed_bazel_maven_uuids
                    .insert(dep.patch_uuid.clone());
                continue;
            }
            Err(declined) => declined,
        };
        // What the Bazel build has of the jar: nothing of socket-patch's,
        // the entry of this patch from an earlier run, which is still its
        // pin, or the entry of another patch, which is not this run's to
        // take out. An entry that the reason of the decline leaves without
        // effect is no pin: the patch is not reported as applied for it.
        let held = verdict.held.as_deref();
        // A vendored entry of the same patch is not this run's pin: the
        // run wrote nothing, and the checkout stays a vendored one.
        let vendored = |patch: &Patch| patch.uuid == dep.patch_uuid && patch.unit().is_some();
        let vendored = files
            .get(FILE)
            .is_some_and(|text| entries(text).iter().any(vendored));
        if held == Some(&dep.patch_uuid) && code != NO_EFFECT && !vendored {
            let uuid = dep.patch_uuid.clone();
            result.confirmed_bazel_maven_uuids.insert(uuid);
        }
        let ends = left(held, &dep.patch_uuid, &code, &file);
        let detail = format!("{purl}: {why}. {ends}");
        result.warnings.push(RewriteWarning { code, detail });
    }
    if let Some(module) = module.filter(|module| Some(module) != files.get(FILE)) {
        result.files.insert(FILE.to_string(), module);
    }
}

/// A patch of the block, as lockfile discovery reads it.
#[derive(Debug, PartialEq, Eq)]
pub struct Pin {
    pub patch: Patch,
    /// Why a Bazel build may pass without the jar of this entry: no pinned
    /// hub fetches the artifact at that version any more (Bazel then
    /// stops at the entry), it cannot be read whether one does, or an rc
    /// file switches the entry off, or cannot be read and so may. `None`:
    /// a build takes the patched jar, or fails.
    pub unbuilt: Option<String>,
}

/// How [`Pin::unbuilt`] ends for an entry that only the undo takes out.
pub const STOPS: &str = "so Bazel stops at its entry";

/// The patches in the block of `module`, the text of the `MODULE.bazel`
/// at the Bazel root `root`, or why the block is no record of any: it was
/// changed by hand.
pub fn pins(root: &Path, module: &str) -> Result<Vec<Pin>, String> {
    let on_disk = disk(root);
    let view = |path: &str| match path {
        FILE => Entry::Text(module.to_string()),
        _ => on_disk(path),
    };
    let hubs = Hubs::read(&view, &disk_up_to(root, MAX_LOCK));
    if let Some(line) = hubs.edited {
        return Err(format!(
            "{FILE}:{line}: the block that socket-patch keeps there was changed by hand"
        ));
    }
    // Everything the rc files hold is read: an option under which a
    // download may fail leaves a build that takes the patched jar or
    // fails, and the first of the others is why an entry is not built.
    let against = rc(&view, declared_release(&view)).into_iter();
    let off = { against }.find_map(|(code, why)| (code != DOWNLOAD).then_some(why));
    let pin = |patch: &Patch| {
        let Patch {
            group,
            artifact,
            version,
            ..
        } = patch;
        let unbuilt = match hubs.sure(group, artifact, version) {
            Built::Yes(_) => off.clone(),
            Built::Unknown(doubt, kind) => Some(unknown(doubt, kind).1),
            Built::No => Some(format!(
                "no pinned hub takes {group}:{artifact} at {version} any more, {STOPS}"
            )),
        };
        let patch = patch.clone();
        Pin { patch, unbuilt }
    };
    Ok(hubs.block.iter().map(pin).collect())
}

/// What a hosted scan takes from the hubs of a Bazel workspace
/// ([`hub_jars`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct HubJars {
    /// The purl of each plain jar that a pinned hub fetches, at the
    /// version its lock holds.
    pub jars: Vec<String>,
    /// The warning ([`HUB_NOT_READ`]) for the first thing that was not
    /// read.
    pub unread: Option<(&'static str, String)>,
    /// The entries of hosted mode in the block whose jar no pinned hub
    /// fetches any more, when every hub was read: the purl and the id of
    /// the patch of each. Bazel stops at such an entry. An entry of
    /// vendored mode in that state is not among them: its directory and
    /// its ledger entry are vendored mode's to take out, which `rollback`,
    /// `remove` and `vendor --revert` do, and `vendor --check` names it.
    pub stale: Vec<(String, String)>,
}

/// What a hosted run takes for packages of `project` beside the ones it
/// finds installed, when `project` is the root of a Bazel workspace: the
/// purl of each plain jar that a pinned hub fetches, at the version its
/// lock holds. That is the version Bazel builds, whatever a `pom.xml`
/// beside the hub selects. With them, one warning ([`HUB_NOT_READ`]) for
/// the first thing that was not read: no jar is guessed for a hub without
/// a lock, or for one whose tags or lock cannot be read. In a workspace
/// that has nothing to do with the ruleset there is no hub to read, and
/// no warning. And the entries of hosted mode in the block that are
/// stale, for the run to take out. Nothing for a project below the root,
/// where no entry is written either, and for one in no Bazel workspace.
pub async fn hub_jars(project: &Path) -> HubJars {
    let project = project.to_path_buf();
    run_blocking(move || hub_jars_blocking(&project)).await
}

fn hub_jars_blocking(project: &Path) -> HubJars {
    let root = super::bazel_root(project).filter(|root| root.project.as_os_str().is_empty());
    let Some(root) = root else {
        return HubJars::default();
    };
    let locks = disk_up_to(&root.dir, MAX_LOCK);
    let hubs = Hubs::read_within(&disk(&root.dir), &locks, MAX_LOCKS);
    // Each lock once, however many hubs name it.
    let (mut purls, mut seen) = (BTreeSet::new(), HashSet::new());
    let locks = hubs.pinned.iter().map(|(_, lock)| lock);
    let locks = locks.filter(|lock| seen.insert(Rc::as_ptr(lock)));
    for (key, jar) in locks.flat_map(|lock| &lock.jars) {
        let (group, artifact) = key.split_once(':').unwrap_or_default();
        if jar.fetched {
            purls.insert(build_maven_purl(group, artifact, &jar.version));
        }
    }
    let unread = hubs.doubt().filter(|_| hubs.ruleset).map(|(doubt, kind)| {
        let pin = match kind {
            Kind::Unpinned(hub) => format!(
                ". Give the hub a `lock_file` and pin it (`REPIN=1 bazel run @{hub}//:pin`)"
            ),
            Kind::Unread | Kind::Overridden => String::new(),
        };
        let detail = format!(
            "{}: {}, so socket-patch does not know every Maven artifact that Bazel builds here \
             through a rules_jvm_external hub: it looks for patches of the ones in the hub \
             locks it read, and of no other{pin}",
            at(doubt),
            doubt.why
        );
        (HUB_NOT_READ, detail)
    });
    let stale = |patch: &&Patch| {
        patch.unit().is_none()
            && hubs.built(&patch.group, &patch.artifact, &patch.version) == Built::No
    };
    let stale = hubs.block.iter().filter(stale);
    HubJars {
        jars: purls.into_iter().collect(),
        unread,
        stale: stale
            .map(|patch| (patch.purl(), patch.uuid.clone()))
            .collect(),
    }
}

/// The warnings for the patches `purls` of a command that ran in
/// `project`: a code and a detail for each Maven jar that a hub of the
/// project's Bazel workspace builds ([`HUB_UNPATCHED`]) or may build
/// ([`UNREADABLE`]). Nothing for a project in no Bazel workspace, and
/// nothing is looked for without a Maven purl among them.
///
/// A `vendored` run patches a hub: its warnings are for the jars whose
/// entry the block does not hold after it, each with the reason vendored
/// mode writes none ([`site`]), under the code a hosted run gives it.
pub async fn notices(
    project: &Path,
    purls: Vec<String>,
    vendored: bool,
) -> Vec<(&'static str, String)> {
    let project = project.to_path_buf();
    run_blocking(move || notices_blocking(&project, purls, vendored)).await
}

fn notices_blocking(
    project: &Path,
    mut purls: Vec<String>,
    vendored: bool,
) -> Vec<(&'static str, String)> {
    purls.sort();
    purls.dedup();
    let jar = |purl| Some((purl, parse_maven_purl(purl).filter(|_| plain(purl))?));
    let jars: Vec<_> = purls.iter().map(String::as_str).filter_map(jar).collect();
    if vendored {
        // A warning names the purl: it stands where a run has the patch's id.
        let by_purl = |(purl, (group, artifact, version)): &(&str, _)| -> Jar {
            let [group, artifact, version] = [group, artifact, version].map(ToString::to_string);
            (purl.to_string(), group, artifact, version)
        };
        let jars: Vec<Jar> = jars.iter().map(by_purl).collect();
        let said = |(purl, entry, held): (String, Result<String, Declined>, Option<String>)| {
            let (code, why) = match (held, entry) {
                // The entry is there and the checkout leaves it without
                // effect (an rc file that switches the block off, an
                // override of the jar): the build takes the upstream jar
                // past it, which is said as a hosted run says it.
                (Some(held), Err((code, why))) if code == NO_EFFECT => {
                    let ends = left(Some(&held), &held, code, FILE);
                    return Some((code, format!("{purl}: {why}. {ends}")));
                }
                // Any other entry stands: the hub takes its jar.
                (Some(_), _) => return None,
                (None, Err(declined)) => declined,
                (None, Ok(_)) => {
                    let why = "a rules_jvm_external hub of the Bazel workspace builds this \
                               artifact from its lock, and this run vendored nothing for it";
                    (HUB_UNPATCHED, why.to_string())
                }
            };
            Some((code, format!("{purl}: {why}. {KEEPS}")))
        };
        let read = verdicts(project, None, &jars, true).into_iter();
        return read.filter_map(said).collect();
    }
    let root = (!jars.is_empty()).then(|| super::bazel_root(project));
    let Some(root) = root.flatten() else {
        return Vec::new();
    };
    let hubs = Hubs::read(&disk(&root.dir), &disk_up_to(&root.dir, MAX_LOCK));
    let mut said = Vec::new();
    for (purl, (group, artifact, version)) in jars {
        let (code, detail) = match hubs.built(&group, &artifact, &version) {
            Built::No => continue,
            // Bazel takes the jar of the block's entry.
            Built::Yes(_) if hubs.held(&group, &artifact, &version).is_some() => continue,
            Built::Yes(by) => {
                let from = |(hub, _): &(&Hub, &Pinned)| {
                    let (lock, name) = (hub.lock.as_deref().unwrap_or_default(), &hub.name);
                    let (file, line) = (&hub.file, hub.line);
                    format!("{lock} (hub \"{name}\", `{INSTALL}` at {file}:{line})")
                };
                let from = by.iter().map(from).collect::<Vec<_>>().join(" and ");
                let detail = format!(
                    "Bazel takes this artifact from {from}, which pins the upstream jar, and \
                     this command does not patch a rules_jvm_external hub: the Bazel build \
                     stays unpatched whatever it did for another build of the checkout. {} \
                     patches a pinned hub",
                    command(&group, &artifact, &version)
                );
                (HUB_UNPATCHED, detail)
            }
            Built::Unknown(doubt, _) => {
                let detail = format!(
                    "socket-patch could not tell whether Bazel takes this artifact from \
                     a rules_jvm_external hub: {}: {}",
                    at(doubt),
                    doubt.why
                );
                (UNREADABLE, detail)
            }
        };
        said.push((code, format!("{purl}: {detail}")));
    }
    said
}

/// The command of hosted mode that patches a pinned hub, as a warning and
/// an action statement name it: by the coordinates of the jar, without
/// what a purl may carry after them (`?type=jar`), which a shell reads.
fn command(group: &str, artifact: &str, version: &str) -> String {
    let purl = build_maven_purl(group, artifact, version);
    format!("`socket-patch get {purl} --mode hosted` at the Bazel root")
}

/// For each of `patches`, the purl of a Maven jar and the id of its patch,
/// whichever mode recorded it (the jar a build tool installed, a pin or a
/// vendored copy of a Maven or Gradle build): the pinned hub of the
/// workspace at the Bazel root `root` that fetches the plain jar of that
/// artifact at that version, the first of them, and what to do about it.
/// Bazel then takes the jar at the sha256 the lock of that hub pins: from
/// a repository, or under `m2local` from the Maven local repository, where
/// a patched jar is not one of that sha256. The lock's sha256 is not
/// compared with the patch: a lock that pins the patched jar's bytes is
/// read as any other.
///
/// It is said only when it is certain of that hub, whatever is not known
/// of another one: the hub and its lock were read and no `maven.override`
/// names the artifact ([`Hubs::built`]), the block was not changed by
/// hand, and it holds no entry of this patch for the jar. `None`
/// otherwise, and where the checkout does not say that Bazel reads
/// `MODULE.bazel` as it stands: it names a Bazel before 7.0, or none
/// while a `WORKSPACE` file defines something, or an rc file names an
/// option that switches Bzlmod off or drops tags of the root (on whatever
/// line: it may hold for one `--config` alone), or cannot be read. `None`
/// too for what is no plain jar of a Maven artifact; without one among
/// `patches` nothing is read.
///
/// What to do is the command that writes an entry for the jar at the
/// root, or why hosted and vendored mode write none there, with the code
/// and in the words of their warning ([`verdicts`]). The entry of another
/// patch is named first: Bazel takes that one's jar until the command has
/// put this one's in its place.
pub fn upstream(root: &Path, patches: &[(&str, &str)]) -> Vec<Option<(Hub, String)>> {
    let jar = |purl| parse_maven_purl(purl).filter(|_| plain(purl));
    let jars: Vec<_> = patches.iter().map(|&(purl, _)| jar(purl)).collect();
    let none = || vec![None; patches.len()];
    if jars.iter().all(Option::is_none) {
        return none();
    }
    let (view, locks) = (disk(root), disk_up_to(root, MAX_LOCK));
    let hubs = Hubs::read(&view, &locks);
    let release = declared_release(&view);
    let read = release.map_or(!hubs.legacy, |release| release >= (7, 0, 0));
    let off = || rc(&view, release).iter().any(|(code, _)| *code != DOWNLOAD);
    if hubs.pinned.is_empty() || hubs.edited.is_some() || !read || off() {
        return none();
    }
    // What holds for every jar is asked once, as for a run that writes.
    let mut workspace = None;
    let fetched = jars.into_iter().zip(patches).map(|(jar, (_, uuid))| {
        let (group, artifact, version) = jar?;
        let Built::Yes(by) = hubs.built(&group, &artifact, &version) else {
            return None;
        };
        let held = hubs.held(&group, &artifact, &version);
        if held == Some(*uuid) {
            return None;
        }
        let entry = match hubs.sure(&group, &artifact, &version) {
            Built::Unknown(doubt, kind) => Err(unknown(doubt, kind)),
            _ => hubs.label(&group, &artifact, &version).and_then(|_| {
                let all = || settings(root, &view, &locks, &hubs.asked, true);
                workspace.get_or_insert_with(all).clone()
            }),
        };
        let other = held.map_or_else(String::new, |held| {
            format!(
                "{FILE} holds the entry of patch {held} for this jar, and where the block is \
                 in effect the Bazel build takes that patch's jar. "
            )
        });
        let remedy = match entry {
            Ok(()) => format!(
                "{other}Run {} to patch the hub, or with `--mode vendored` to commit the \
                 patched jar.",
                command(&group, &artifact, &version)
            ),
            Err((code, why)) => format!(
                "{other}Hosted and vendored mode write no entry for this hub (`{code}`): {why}."
            ),
        };
        Some((by[0].0.clone(), remedy))
    });
    fetched.collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// For the tests of what reads the block elsewhere: the `MODULE.bazel`
    /// of a checkout whose pinned hub fetches netty's jar, the lock of
    /// that hub, and the same `MODULE.bazel` with the block for a patch
    /// `uuid` of that jar.
    pub(crate) fn sample(uuid: &str) -> [String; 3] {
        let patch = patch("netty-tcnative-classes", uuid);
        let ours = with_patch(PINNED, LABEL, patch).expect("a block");
        [PINNED.to_string(), lock_72(), ours]
    }

    /// A pinned hub, as teams write one.
    const PINNED: &str = r#"bazel_dep(name = "rules_jvm_external", version = "7.2")

maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")
maven.install(
    artifacts = ["io.netty:netty-tcnative-boringssl-static:2.0.61.Final"],
    lock_file = "//:maven_install.json",
)
use_repo(maven, "maven")
"#;

    // The ruleset's own `maven_install.json` at its tags 6.9 and 7.2, cut
    // down to two artifacts: format 2 as 6.9 wrote it, format 3 as 7.2
    // did.
    const NETTY: &str = r#"
  "artifacts": {
    "io.netty:netty-tcnative-boringssl-static": {
      "shasums": {
        "jar": "b6f974972c44cd6f9cecabc255290286faac40b6393c66c3c3c0db7f421cc28e",
        "linux-x86_64": "4ff9d14f1ec6ccee35b78f53a6f3d9c7c54535aa2a76138311c2f619c5e150e1",
        "osx-aarch_64": "58e0302c9fde3db984c3ff7ee7ec7159dc0320bdb91533cc290e12e40911cd1a"
      },
      "version": "2.0.61.Final"
    },
    "io.netty:netty-tcnative-classes": {
      "shasums": {"jar": "9b970eccd844bfae175a5cbbf7bf94891894add06d6ccbe1abf2250cd64080f6"},
      "version": "2.0.61.Final"
    }
  },
  "dependencies": {
    "io.netty:netty-tcnative-boringssl-static": [
      "io.netty:netty-tcnative-boringssl-static:jar:linux-x86_64",
      "io.netty:netty-tcnative-boringssl-static:jar:osx-aarch_64",
      "io.netty:netty-tcnative-classes"
    ]
  },
  "repositories": {
    "https://repo1.maven.org/maven2/": [
      "io.netty:netty-tcnative-boringssl-static",
      "io.netty:netty-tcnative-boringssl-static:jar:linux-x86_64",
      "io.netty:netty-tcnative-boringssl-static:jar:osx-aarch_64",
      "io.netty:netty-tcnative-classes"
    ]
  },
"#;
    const NETTY_JAR: &str = "b6f974972c44cd6f9cecabc255290286faac40b6393c66c3c3c0db7f421cc28e";

    fn lock_69() -> String {
        let signed =
            r#""__INPUT_ARTIFACTS_HASH": 1448912684, "__RESOLVED_ARTIFACTS_HASH": 771049556,"#;
        format!("{{{signed}{NETTY}\"version\": \"2\"}}\n")
    }

    fn lock_72() -> String {
        let signed = r#""__INPUT_ARTIFACTS_HASH": {"repositories": -1949687017},
  "__RESOLVED_ARTIFACTS_HASH": {"io.netty:netty-tcnative-classes": 1239547355},"#;
        format!("{{{signed}{NETTY}\"version\": \"3\"}}\n")
    }

    /// From `regression_testing_maven_install.json` of the ruleset's tests
    /// at 7.2: an artifact the lock skips, and a packaging other than jar.
    const LOCK_SKIPS: &str = r#"{
  "artifacts": {
    "org.codehaus.plexus:plexus": {"shasums": {"jar": null}, "version": "1.0.4"},
    "com.almworks.sqlite4java:libsqlite4java-osx:dylib": {
      "shasums": {"jar": "b84122142173f33137c76d05dd6c80cc96f619ead3dc476c12d6ea46ef12dd05"},
      "version": "1.0.392"
    },
    "com.almworks.sqlite4java:sqlite4java": {
      "shasums": {"jar": "243a64470fda0e86a6fddeb0af4c7aa9426ce84e68cbfe18d75ee5da4b7e0b92"},
      "version": "1.0.392"
    },
    "org.example:only-sources": {"shasums": {"sources": "00"}, "version": "1.0"},
    "org.example:unlisted": {"shasums": {"jar": "11"}, "version": "1.0"}
  },
  "dependencies": {},
  "repositories": {
    "https://repo1.maven.org/maven2/": [
      "com.almworks.sqlite4java:libsqlite4java-osx:dylib",
      "com.almworks.sqlite4java:sqlite4java",
      "org.codehaus.plexus:plexus",
      "org.example:only-sources:jar:sources"
    ],
    "https://maven.google.com/": []
  },
  "skipped": ["org.codehaus.plexus:plexus"],
  "version": "3"
}
"#;

    /// [`super::notices_blocking`] for a run that patches no hub.
    fn notices_blocking(project: &Path, purls: Vec<String>) -> Vec<(&'static str, String)> {
        super::notices_blocking(project, purls, false)
    }

    /// The view of the files `files`, held in memory.
    fn view<'a>(files: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Entry + 'a {
        move |path| match files.iter().find(|(name, _)| *name == path) {
            Some((_, text)) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        }
    }

    /// Each hub as `name file:line lock`, and each doubt as
    /// `file:line: why`.
    fn listed(files: &[(&str, &str)]) -> (Vec<String>, Vec<String>) {
        let (hubs, doubts) = hubs(&Workspace::read(&view(files)));
        let hub = |hub: Hub| {
            let lock = hub.lock.unwrap_or_else(|| "-".to_string());
            format!("{} {}:{} {lock}", hub.name, hub.file, hub.line)
        };
        let doubt = |doubt: Doubt| format!("{}:{}: {}", doubt.file, doubt.line, doubt.why);
        (
            hubs.into_iter().map(hub).collect(),
            doubts.into_iter().map(doubt).collect(),
        )
    }

    /// The hubs and the doubts of one `MODULE.bazel`.
    fn module(text: &str) -> (Vec<String>, Vec<String>) {
        listed(&[("MODULE.bazel", text)])
    }

    /// The hubs of the workspace with the files `files`.
    fn read(files: &[(&str, &str)]) -> Hubs {
        let view = view(files);
        Hubs::read(&view, &view)
    }

    /// What [`Hubs::built`] says of netty's jar at the version the locks
    /// above hold, in a word, with the doubt of an `Unknown`.
    fn built(files: &[(&str, &str)]) -> String {
        let hubs = read(files);
        let said = match hubs.built("io.netty", "netty-tcnative-classes", "2.0.61.Final") {
            Built::No => "no".to_string(),
            Built::Yes(by) => format!("yes, {}", by.len()),
            Built::Unknown(doubt, _) => format!("{}:{}: {}", doubt.file, doubt.line, doubt.why),
        };
        said
    }

    #[test]
    fn a_hub_is_a_tag_of_the_rulesets_maven_extension() {
        assert_eq!(
            module(PINNED),
            (
                vec!["maven MODULE.bazel:4 maven_install.json".to_string()],
                vec![]
            )
        );
        // Under another name for the proxy and for the ruleset, in a file
        // the root includes, and beside an extension called `maven` that
        // another module defines. The `artifact` tag there gives no name,
        // so it makes the hub `maven`, which has no lock.
        let root = r#"bazel_dep(name = "rules_jvm_external", version = "6.9", repo_name = "rje")
bazel_dep(name = "rules_other", version = "1.0")
include("//third_party:jvm.MODULE.bazel")
other = use_extension("@rules_other//:extensions.bzl", "maven")
other.install(name = "not_a_hub", lock_file = "//:other.json")
"#;
        let included = r#"jvm = use_extension("@rje//:extensions.bzl", "maven", dev_dependency = True)
jvm.install(name = "deps", lock_file = "@//third_party:deps_install.json")
jvm.artifact(group = "com.example", artifact = "a", version = "1")
"#;
        let files = [
            ("MODULE.bazel", root),
            ("third_party/jvm.MODULE.bazel", included),
        ];
        let hubs = [
            "deps third_party/jvm.MODULE.bazel:2 third_party/deps_install.json",
            "maven third_party/jvm.MODULE.bazel:3 -",
        ];
        assert_eq!(listed(&files), (hubs.map(String::from).to_vec(), vec![]));
        assert_eq!(module("module(name = 'no_java')\n"), (vec![], vec![]));
    }

    #[test]
    fn the_lock_of_a_hub_is_the_plain_label_its_tags_agree_on() {
        let hub = |tags: &str| {
            let proxy = "maven = use_extension('@rules_jvm_external//:extensions.bzl', 'maven')";
            module(&format!("{proxy}\n{tags}\n"))
        };
        // The default name, with and without a lock; two tags of one hub
        // that agree; two hubs.
        for (tags, hubs) in [
            ("maven.install()", vec!["maven MODULE.bazel:2 -"]),
            (
                "maven.install(lock_file = '//:a.json')\nmaven.install(lock_file = ':a.json')",
                vec!["maven MODULE.bazel:2 a.json"],
            ),
            (
                "maven.install(lock_file = '//:a.json')\nmaven.install(name = 'b')",
                vec!["maven MODULE.bazel:2 a.json", "b MODULE.bazel:3 -"],
            ),
        ] {
            assert_eq!(
                hub(tags),
                (hubs.iter().map(|h| h.to_string()).collect(), vec![]),
                "{tags}"
            );
        }
        // What cannot be read is a doubt, and gives no hub.
        let plain = "MODULE.bazel:2: this `maven.install` is not a plain call of its own";
        let label = "MODULE.bazel:2: the `lock_file` of this hub is not a file of this repository";
        let name = "MODULE.bazel:2: the `name` of this hub is not a repository name in a string";
        for (tags, doubt) in [
            ("maven.install(lock_file = LOCK)", label),
            ("maven.install(lock_file = '@other//:a.json')", label),
            ("maven.install(lock_file = '//:a' + '.json')", label),
            ("maven.install(name = NAME)", name),
            // Nothing Bazel takes for a name, and a line of its own in a
            // warning.
            ("maven.install(name = 'a\\nb')", name),
            ("maven.install(**ARGS)", plain),
            ("PINNED and maven.install(lock_file = '//:a.json')", plain),
            // A tag that cannot be read may be the last one of a hub that
            // another tag made: its lock is not known either.
            (
                "maven.install(name = NAME)\nmaven.install(lock_file = '//:a.json')",
                name,
            ),
        ] {
            assert_eq!(hub(tags), (vec![], vec![doubt.to_string()]), "{tags}");
        }
        // Two tags of one hub with different locks: the ruleset takes the
        // last one's, so neither is taken here.
        let split =
            "maven.install(lock_file = '//:a.json')\nmaven.install()\nmaven.install(name = 'b')";
        let doubt = "MODULE.bazel:3: this tag and the one at MODULE.bazel:2 name different locks";
        assert_eq!(
            hub(split),
            (
                vec!["b MODULE.bazel:4 -".to_string()],
                vec![doubt.to_string()]
            )
        );
    }

    /// `artifact` and `from_toml` tags make a hub or add to one as
    /// `install` does (`_process_module_tags` in the ruleset's
    /// `private/extensions/maven.bzl`: 7.2 lines 379 to 475, 6.9 lines 394
    /// to 499; at 6.5, which has no `from_toml`, lines 237 to 345). Only
    /// an `install` names a lock (7.2 lines 609 to 649), and `override`
    /// and `amend_artifact` make no hub.
    #[test]
    fn an_artifact_or_a_from_toml_tag_makes_a_hub_too() {
        let hub = |tags: &str| {
            let proxy = "maven = use_extension('@rules_jvm_external//:extensions.bzl', 'maven')";
            module(&format!("{proxy}\n{tags}\n"))
        };
        let artifact = "maven.artifact(group = 'g', artifact = 'a', version = '1')";
        let toml = "maven.from_toml(name = 'libs', libs_versions_toml = '//:libs.versions.toml')";
        let pinned = "maven.install(lock_file = '//:a.json')";
        let none = "maven.amend_artifact(coordinates = 'g:a')\n\
                    maven.override(coordinates = 'g:a', target = '//:a')";
        for (tags, hubs) in [
            (artifact.to_string(), vec!["maven MODULE.bazel:2 -"]),
            (toml.to_string(), vec!["libs MODULE.bazel:2 -"]),
            // A pinned hub stays what it is, at its `install`, wherever
            // the tag that adds to it stands.
            (
                format!("{pinned}\n{artifact}"),
                vec!["maven MODULE.bazel:2 a.json"],
            ),
            (
                format!("{artifact}\n{pinned}"),
                vec!["maven MODULE.bazel:3 a.json"],
            ),
            (
                format!("{pinned}\n{toml}"),
                vec!["maven MODULE.bazel:2 a.json", "libs MODULE.bazel:3 -"],
            ),
            (none.to_string(), vec![]),
        ] {
            assert_eq!(
                hub(&tags),
                (hubs.iter().map(|h| h.to_string()).collect(), vec![]),
                "{tags}"
            );
        }
        // One that cannot be read is a doubt. It names no lock, so the
        // hubs that were read stay.
        let name = "MODULE.bazel:3: the `name` of this hub is not a repository name in a string";
        let plain = "MODULE.bazel:3: this `maven.from_toml` is not a plain call of its own";
        for (tag, doubt) in [
            (
                "maven.artifact(name = NAME, group = 'g', artifact = 'a')",
                name,
            ),
            ("maven.from_toml(**ARGS)", plain),
        ] {
            assert_eq!(
                hub(&format!("{pinned}\n{tag}")),
                (
                    vec!["maven MODULE.bazel:2 a.json".to_string()],
                    vec![doubt.to_string()]
                ),
                "{tag}"
            );
        }
        // Such a hub has no lock, as an `install` without `lock_file` has
        // none: Bazel resolves what it builds when it builds.
        let add = |tag: &str| format!("{PINNED}maven.{tag}\n");
        let artifact = "group = \"io.netty\", artifact = \"netty-tcnative-classes\"";
        let tools = add(&format!("artifact(name = \"tools\", {artifact})"));
        let libs = add("from_toml(name = \"libs\", libs_versions_toml = \"//:libs.toml\")");
        let unnamed = add(&format!("artifact(name = NAME, {artifact})"));
        let own = add(&format!("artifact({artifact}, version = \"2.0.61.Final\")"));
        let (netty, other) = (lock_72(), LOCK_SKIPS);
        let no_lock = |hub: &str| format!("MODULE.bazel:9: hub \"{hub}\" has no `lock_file`");
        for (module, lock, said) in [
            (&tools, other, no_lock("tools")),
            (&libs, other, no_lock("libs")),
            (
                &unnamed,
                other,
                name.replace("MODULE.bazel:3", "MODULE.bazel:9"),
            ),
            // A hub that holds the jar is an answer beside each of them,
            // and so is the pinned hub that a tag adds an artifact to.
            (&tools, &netty, "yes, 1".to_string()),
            (&unnamed, &netty, "yes, 1".to_string()),
            (&own, &netty, "yes, 1".to_string()),
            (&own, other, "no".to_string()),
        ] {
            let files = [
                ("MODULE.bazel", module.as_str()),
                ("maven_install.json", lock),
            ];
            assert_eq!(built(&files), said, "{module}");
        }
    }

    /// Under `m2local` a hub takes a jar that no repository of its lock
    /// lists from the Maven local repository, at the sha256 of the lock:
    /// `download_pinned_deps` in the ruleset's
    /// `private/extensions/download_pinned_deps.bzl` (lines 23 to 28 at
    /// 6.5, 24 to 29 at 6.9, 27 to 32 at 7.2) with `has_m2local` of
    /// `v2_lock_file.bzl` (6.5 line 29, 6.9 line 31) and `v3_lock_file.bzl`
    /// (7.2 line 37).
    #[test]
    fn under_m2local_a_jar_no_repository_lists_is_fetched() {
        for (format, flag, fetched) in [
            ("2", "\"m2local\": true,", true),
            ("3", "\"m2local\": true,", true),
            ("3", "\"m2local\": false,", false),
        ] {
            let version = format!("{flag}\n  \"version\": \"{format}\"");
            let text = LOCK_SKIPS.replace("\"version\": \"3\"", &version);
            let lock = Lock::parse(&text).unwrap();
            let unlisted = lock.plain_jar("org.example", "unlisted").unwrap();
            assert_eq!(unlisted.fetched, fetched, "{format} {flag}");
            // Not one the lock skips, which has no sum either.
            let plexus = lock.plain_jar("org.codehaus.plexus", "plexus").unwrap();
            assert!(!plexus.fetched, "{format} {flag}");
            let hubs = read(&[("MODULE.bazel", PINNED), ("maven_install.json", &text)]);
            let built = hubs.built("org.example", "unlisted", "1.0");
            assert_eq!(matches!(built, Built::Yes(_)), fetched, "{format} {flag}");
        }
        // A flag that is no boolean is no lock.
        let odd = LOCK_SKIPS.replace("\"version\"", "\"m2local\": \"yes\", \"version\"");
        assert!(Lock::parse(&odd)
            .unwrap_err()
            .starts_with("it is no lock ("));
    }

    #[test]
    fn a_v2_and_a_v3_lock_give_the_version_and_the_jar_sum() {
        for (lock, format) in [(lock_69(), 2), (lock_72(), 3)] {
            let lock = Lock::parse(&lock).unwrap();
            // The jar without a classifier, beside two with one.
            let jar = lock
                .plain_jar("io.netty", "netty-tcnative-boringssl-static")
                .unwrap();
            let pinned = Pinned {
                version: "2.0.61.Final".to_string(),
                jar_sha256: Some(NETTY_JAR.to_string()),
                fetched: true,
            };
            assert_eq!((lock.format, jar), (format, &pinned));
            assert_eq!(lock.plain_jar("io.netty", "netty"), None);
        }
    }

    #[test]
    fn a_classifier_or_a_packaging_key_is_not_the_plain_jar() {
        let lock = Lock::parse(LOCK_SKIPS).unwrap();
        assert!(
            lock.plain_jar("com.almworks.sqlite4java", "sqlite4java")
                .unwrap()
                .fetched
        );
        for (group, artifact) in [
            ("com.almworks.sqlite4java", "libsqlite4java-osx"),
            ("com.almworks.sqlite4java", "libsqlite4java-osx:dylib"),
            ("org.example", "only-sources"),
        ] {
            assert_eq!(lock.plain_jar(group, artifact), None, "{artifact}");
        }
    }

    #[test]
    fn a_skipped_or_unlisted_artifact_is_not_fetched() {
        let lock = Lock::parse(LOCK_SKIPS).unwrap();
        let plexus = lock.plain_jar("org.codehaus.plexus", "plexus").unwrap();
        assert_eq!(
            (plexus.version.as_str(), &plexus.jar_sha256, plexus.fetched),
            ("1.0.4", &None, false)
        );
        let unlisted = lock.plain_jar("org.example", "unlisted").unwrap();
        assert_eq!(
            (unlisted.jar_sha256.as_deref(), unlisted.fetched),
            (Some("11"), false)
        );
        // Listed with a sum, and skipped all the same.
        let skipped = LOCK_SKIPS.replace(
            r#"["org.codehaus.plexus:plexus"]"#,
            r#"["org.example:unlisted", "com.almworks.sqlite4java:sqlite4java"]"#,
        );
        let lock = Lock::parse(&skipped).unwrap();
        assert!(
            !lock
                .plain_jar("com.almworks.sqlite4java", "sqlite4java")
                .unwrap()
                .fetched
        );
    }

    #[test]
    fn an_empty_v1_conflicted_or_broken_lock_is_not_read() {
        let conflicted = lock_72().replace("\"artifacts\"", "<<<<<<< HEAD\n\"artifacts\"");
        let other = "it is not a lock of format 2 or 3";
        for (text, why) in [
            ("", "it is empty: the hub is not pinned yet"),
            (" \n", "it is empty: the hub is not pinned yet"),
            (r#"{"dependency_tree": {"dependencies": []}}"#, other),
            (r#"{"artifacts": {}, "version": "4"}"#, other),
            (r#"{"artifacts": {}, "version": 3}"#, "it is no lock ("),
            (
                r#"{"artifacts": {"a:b": {"shasums": {}}}, "version": "3"}"#,
                "it is no lock (",
            ),
            (r#"{"artifacts": [], "version": "3"}"#, "it is no lock ("),
            (&conflicted, "it is no lock ("),
            ("[]", "it is no lock ("),
        ] {
            let said = Lock::parse(text).unwrap_err();
            assert!(said.starts_with(why), "{text:?}: {said}");
        }
    }

    #[test]
    fn built_is_yes_only_at_the_locked_version() {
        let lock = lock_72();
        let hubs = read(&[("MODULE.bazel", PINNED), ("maven_install.json", &lock)]);
        let built = |artifact, version| hubs.built("io.netty", artifact, version);
        let Built::Yes(by) = built("netty-tcnative-classes", "2.0.61.Final") else {
            panic!("not built");
        };
        let [(hub, jar)] = by[..] else {
            panic!("{by:?}");
        };
        assert_eq!(
            (hub.name.as_str(), hub.line, jar.version.as_str()),
            ("maven", 4, "2.0.61.Final")
        );
        for (artifact, version) in [
            ("netty-tcnative-classes", "2.0.62.Final"),
            ("netty-tcnative-classes", "2.0.61.Final-socket.0a1b2c3d"),
            ("netty-tcnative-classes", ""),
            ("netty-tcnative", "2.0.61.Final"),
        ] {
            assert_eq!(built(artifact, version), Built::No, "{artifact} {version}");
        }
        // Not what the lock holds without a jar to fetch.
        let hubs = read(&[("MODULE.bazel", PINNED), ("maven_install.json", LOCK_SKIPS)]);
        assert_eq!(
            hubs.built("org.codehaus.plexus", "plexus", "1.0.4"),
            Built::No
        );
        assert_eq!(hubs.built("org.example", "unlisted", "1.0"), Built::No);
    }

    #[test]
    fn built_is_no_when_every_hub_is_pinned_and_none_holds_it() {
        let second =
            format!("{PINNED}maven.install(name = \"tools\", lock_file = \"//:tools.json\")\n");
        let (netty, other) = (lock_69(), LOCK_SKIPS);
        for (files, said) in [
            (vec![], "no"),
            (vec![("MODULE.bazel", "module(name = 'no_java')\n")], "no"),
            (
                vec![("MODULE.bazel", PINNED), ("maven_install.json", other)],
                "no",
            ),
            (
                vec![
                    ("MODULE.bazel", &second),
                    ("maven_install.json", other),
                    ("tools.json", other),
                ],
                "no",
            ),
            (
                vec![
                    ("MODULE.bazel", &second),
                    ("maven_install.json", other),
                    ("tools.json", &netty),
                ],
                "yes, 1",
            ),
            (
                vec![
                    ("MODULE.bazel", &second),
                    ("maven_install.json", &netty),
                    ("tools.json", &netty),
                ],
                "yes, 2",
            ),
        ] {
            assert_eq!(
                built(&files),
                said,
                "{:?}",
                files.iter().map(|f| f.0).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn a_lockless_hub_or_a_doubt_is_unknown() {
        let lockless = PINNED.replace("    lock_file = \"//:maven_install.json\",\n", "");
        let computed = PINNED.replace("\"//:maven_install.json\"", "LOCK");
        let beside = format!("{PINNED}maven.install(name = \"tools\")\n");
        let odd = format!("{PINNED}print(use_repo)\n");
        // A second tag of the hub that the ruleset takes the lock from,
        // and one that may be of any hub.
        let later = format!("{PINNED}LOCK = \"//:b.json\"\nmaven.install(lock_file = LOCK)\n");
        let unnamed = format!("{PINNED}maven.install(name = NAME, lock_file = \"//:b.json\")\n");
        let over = |tag: &str| format!("{PINNED}maven.override({tag}, target = \"//lib:netty\")\n");
        let overridden = over("coordinates = \"io.netty:netty-tcnative-classes\"");
        // As the ruleset matches it: by the name of the artifact's target,
        // for every hub at 6.5.
        let by_target = over("name = \"tools\", coordinates = \"io_netty_netty-tcnative.classes\"");
        let another = over("coordinates = \"io.netty:netty-tcnative-boringssl-static\"");
        let unread = over("coordinates = NETTY");
        let (netty, other) = (lock_72(), LOCK_SKIPS);
        let gives = "MODULE.bazel:9: a `maven.override` gives this artifact another target";
        for (module, lock, said) in [
            (
                lockless.as_str(),
                None,
                "MODULE.bazel:4: hub \"maven\" has no `lock_file`",
            ),
            (
                &computed,
                None,
                "MODULE.bazel:4: the `lock_file` of this hub is not a file of this repository",
            ),
            (PINNED, None, "maven_install.json:0: it does not exist"),
            (
                PINNED,
                Some(""),
                "maven_install.json:0: it is empty: the hub is not pinned yet",
            ),
            (
                PINNED,
                Some("{}"),
                "maven_install.json:0: it is not a lock of format 2 or 3",
            ),
            (
                &beside,
                Some(other),
                "MODULE.bazel:9: hub \"tools\" has no `lock_file`",
            ),
            // A hub that holds the jar is an answer, whatever another hub
            // leaves unread.
            (&beside, Some(&netty), "yes, 1"),
            // Not when the tags of the hub itself may be others than the
            // ones read: the ruleset takes the lock of the last.
            (
                &odd,
                Some(&netty),
                "MODULE.bazel:9: `use_repo` is used other than to call it",
            ),
            (
                &later,
                Some(&netty),
                "MODULE.bazel:10: the `lock_file` of this hub is not a file of this repository",
            ),
            (
                &unnamed,
                Some(&netty),
                "MODULE.bazel:9: the `name` of this hub is not a repository name in a string",
            ),
            // And not when an override puts another target in its place,
            // which matters only for a jar that a hub fetches.
            (&overridden, Some(&netty), gives),
            (&by_target, Some(&netty), gives),
            (
                &unread,
                Some(&netty),
                "MODULE.bazel:9: this `maven.override` cannot be read",
            ),
            (&another, Some(&netty), "yes, 1"),
            (&overridden, Some(other), "no"),
            (&unread, Some(other), "no"),
        ] {
            let mut files = vec![("MODULE.bazel", module)];
            files.extend(lock.map(|lock| ("maven_install.json", lock)));
            assert_eq!(built(&files), said, "{module}");
        }
        // The view's own reason for a lock it does not hand out: the one
        // of the two views that the locks are read through.
        let files = [("MODULE.bazel", PINNED)];
        let unreadable = |_: &str| Entry::Unreadable("it is larger than 16 MiB".to_string());
        let hubs = Hubs::read(&view(&files), &unreadable);
        let Built::Unknown(doubt, Kind::Unread) =
            hubs.built("io.netty", "netty-tcnative-classes", "2.0.61.Final")
        else {
            panic!("read");
        };
        assert_eq!(
            (doubt.file.as_str(), doubt.why.as_str()),
            (
                "maven_install.json",
                "it cannot be read: it is larger than 16 MiB"
            )
        );
    }

    #[test]
    fn a_workspace_file_that_calls_maven_install_is_unknown_below_bazel_9() {
        let direct = "load('@rules_jvm_external//:defs.bzl', 'maven_install')\n\nmaven_install(\n    artifacts = [],\n)\n";
        let renamed =
            "load('@rules_jvm_external//:defs.bzl', pin = 'maven_install')\npin(artifacts = [])\n";
        let none =
            "workspace(name = 'w')\nmaven_install = 1\nhttp_archive(name = 'maven_install')\n";
        let why = "a `maven_install` of a WORKSPACE file is not read";
        for (name, text, line) in [
            ("WORKSPACE", direct, 3),
            ("WORKSPACE.bazel", direct, 3),
            ("WORKSPACE.bzlmod", renamed, 2),
        ] {
            let said = format!("{name}:{line}: {why}");
            for (release, expected) in [
                (None, said.as_str()),
                (Some("7.7.2\n"), &said),
                (Some("8.8.2\n"), &said),
                (Some("latest\n"), &said),
                (Some("9.0.0\n"), "no"),
                (Some("9.3.2\n"), "no"),
            ] {
                let mut files = vec![(name, text)];
                files.extend(release.map(|release| (".bazelversion", release)));
                assert_eq!(built(&files), expected, "{name} {release:?}");
                // Beside a hub that holds the jar, the hub answers.
                let lock = lock_72();
                files.extend([
                    ("MODULE.bazel", PINNED),
                    ("maven_install.json", lock.as_str()),
                ]);
                assert_eq!(built(&files), "yes, 1", "{name} {release:?}");
            }
        }
        // A file without the call says nothing, and of the three Bazel
        // reads the first that is there, alone.
        let shadowed = [
            ("WORKSPACE.bzlmod", none),
            ("WORKSPACE.bazel", direct),
            ("WORKSPACE", direct),
        ];
        assert_eq!(built(&shadowed[..1]), "no");
        assert_eq!(built(&shadowed), "no");
        assert_eq!(built(&shadowed[1..]), format!("WORKSPACE.bazel:3: {why}"));
        // One that cannot be read may call it, unless Bazel 9 leaves it.
        let open = [
            ("WORKSPACE", "maven_install(\n"),
            (".bazelversion", "9.0.0\n"),
        ];
        assert_eq!(built(&open[..1]), "WORKSPACE:1: a bracket is never closed");
        assert_eq!(built(&open), "no");
    }

    /// A project directory with the files `files`, in a checkout of its
    /// own.
    fn project(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".git")).unwrap();
        for (path, text) in files {
            std::fs::write(dir.path().join(path), text).unwrap();
        }
        dir
    }

    const NETTY_PURL: &str = "pkg:maven/io.netty/netty-tcnative-classes@2.0.61.Final";

    #[test]
    fn a_notice_names_the_lock_and_the_hub_or_what_was_not_read() {
        // A lock larger than the 1 MiB of a Starlark file.
        let lock = lock_72() + &" ".repeat(1 << 20);
        let dir = project(&[("MODULE.bazel", PINNED), ("maven_install.json", &lock)]);
        let purls = |purls: &[&str]| purls.iter().map(|purl| purl.to_string()).collect();
        // Once per jar, whatever else the command patched, and not for a
        // version, a classifier or a packaging the lock does not hold.
        let asked = purls(&[
            NETTY_PURL,
            "pkg:npm/left-pad@1.3.0",
            "pkg:maven/io.netty/netty-tcnative-classes@2.0.62.Final",
            "pkg:maven/io.netty/netty-tcnative-classes@2.0.61.Final?classifier=sources",
            "pkg:maven/io.netty/netty-tcnative-classes@2.0.61.Final?type=aar",
            NETTY_PURL,
        ]);
        let said = notices_blocking(dir.path(), asked);
        let detail = format!(
            "{NETTY_PURL}: Bazel takes this artifact from maven_install.json (hub \"maven\", \
             `maven.install` at MODULE.bazel:4), which pins the upstream jar, and this command \
             does not patch a rules_jvm_external hub: the Bazel build stays unpatched whatever \
             it did for another build of the checkout. `socket-patch get {NETTY_PURL} --mode \
             hosted` at the Bazel root patches a pinned hub"
        );
        assert_eq!(said, [(HUB_UNPATCHED, detail.clone())]);
        // The same for a project below the Bazel root of its checkout.
        let below = dir.path().join("services/billing");
        std::fs::create_dir_all(&below).unwrap();
        let said = notices_blocking(&below, purls(&[NETTY_PURL]));
        assert_eq!(said, [(HUB_UNPATCHED, detail)]);
        // What cannot be read is said for every Maven jar of the run.
        std::fs::write(dir.path().join("maven_install.json"), "").unwrap();
        let said = notices_blocking(dir.path(), purls(&[NETTY_PURL, "pkg:maven/a.b/c@1"]));
        let why = "could not tell whether Bazel takes this artifact from a \
                   rules_jvm_external hub: maven_install.json: it is empty: the hub is not \
                   pinned yet";
        let expected = ["pkg:maven/a.b/c@1", NETTY_PURL]
            .map(|purl| (UNREADABLE, format!("{purl}: socket-patch {why}")));
        assert_eq!(said, expected);
        // And a lock over the bound is not read.
        let large = lock + &" ".repeat(MAX_LOCK);
        std::fs::write(dir.path().join("maven_install.json"), large).unwrap();
        let said = notices_blocking(dir.path(), purls(&[NETTY_PURL]));
        let why = "hub: maven_install.json: it cannot be read: it is larger than 16 MiB";
        assert!(said[0].1.ends_with(why), "{said:?}");
        std::fs::remove_file(dir.path().join("maven_install.json")).unwrap();
        let lockless = PINNED.replace("    lock_file = \"//:maven_install.json\",\n", "");
        std::fs::write(dir.path().join("MODULE.bazel"), lockless).unwrap();
        let said = notices_blocking(dir.path(), purls(&[NETTY_PURL]));
        assert!(
            said[0]
                .1
                .ends_with("hub: MODULE.bazel:4: hub \"maven\" has no `lock_file`"),
            "{said:?}"
        );
        // A directory that has the name of a `WORKSPACE` file is none, as
        // for Bazel, and a file that cannot be read is said with its reason.
        let odd = project(&[("MODULE.bazel", "module(name = 'no_java')\n")]);
        std::fs::create_dir(odd.path().join("WORKSPACE")).unwrap();
        assert_eq!(notices_blocking(odd.path(), purls(&[NETTY_PURL])), []);
        std::fs::write(odd.path().join("WORKSPACE.bazel"), "maven_install(\n").unwrap();
        let said = notices_blocking(odd.path(), purls(&[NETTY_PURL]));
        assert!(
            said[0]
                .1
                .ends_with("hub: WORKSPACE.bazel:1: a bracket is never closed"),
            "{said:?}"
        );
    }

    /// The files of the workspace keep the reader's bound of 1 MiB,
    /// whatever a lock may hold: one over it is not read, with the
    /// reader's own reason, and names no release either.
    #[test]
    fn a_file_of_the_workspace_over_1_mib_is_not_read() {
        let (lock, filler) = (lock_72(), "#".repeat(1 << 20));
        let large = format!("{PINNED}{filler}\n");
        let dir = project(&[("MODULE.bazel", &large), ("maven_install.json", &lock)]);
        let said = notices_blocking(dir.path(), vec![NETTY_PURL.to_string()]);
        let why = "hub: MODULE.bazel: it cannot be read: it is larger than 1 MiB";
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(
            said[0].0 == UNREADABLE && said[0].1.ends_with(why),
            "{said:?}"
        );
        // `.bazelversion` begins with a release that reads no `WORKSPACE`
        // file, and is not read to say so.
        let release = format!("9.3.2\n{filler}");
        let legacy = project(&[
            ("WORKSPACE", "maven_install(artifacts = [])\n"),
            (".bazelversion", &release),
        ]);
        let said = notices_blocking(legacy.path(), vec![NETTY_PURL.to_string()]);
        let why = "hub: WORKSPACE:1: a `maven_install` of a WORKSPACE file is not read";
        assert!(said.len() == 1 && said[0].1.ends_with(why), "{said:?}");
    }

    #[test]
    fn outside_a_bazel_workspace_or_without_a_maven_patch_nothing_is_said() {
        let lock = lock_72();
        let maven = vec![NETTY_PURL.to_string()];
        // A Maven project with a lock of that name and no workspace file,
        // and one below a workspace that its checkout does not reach.
        let plain = project(&[("pom.xml", "<project/>"), ("maven_install.json", &lock)]);
        assert_eq!(notices_blocking(plain.path(), maven.clone()), []);
        let outer = project(&[("MODULE.bazel", PINNED), ("maven_install.json", &lock)]);
        let inner = outer.path().join("inner");
        std::fs::create_dir_all(inner.join(".git")).unwrap();
        assert_eq!(notices_blocking(&inner, maven.clone()), []);
        // In the workspace: a hub that cannot be read says nothing for a
        // run without a Maven jar.
        let broken = project(&[("MODULE.bazel", PINNED)]);
        assert_eq!(notices_blocking(broken.path(), maven).len(), 1);
        let others = [
            "pkg:npm/a@1",
            "pkg:maven/a/b@1?classifier=tests",
            "pkg:maven/broken",
        ];
        let others = others.map(String::from).to_vec();
        assert_eq!(notices_blocking(broken.path(), others), []);
        assert_eq!(notices_blocking(broken.path(), Vec::new()), []);
    }

    /// [`upstream`] names the hub of a patched jar only where that is
    /// certain of the hub: a pinned hub that was read fetches the plain jar
    /// at that version, the block was not changed by hand and holds no
    /// entry of the patch, and nothing of the checkout says that Bazel may
    /// pass over `MODULE.bazel`. With the hub it says what to do: the
    /// command that writes the entry, or why no mode writes one.
    #[test]
    fn an_installed_jar_is_upstream_where_a_pinned_hub_surely_fetches_it() {
        let uuid = "7a11e000-0000-4000-8000-0000000000b1";
        let [_, lock, patched] = sample(uuid);
        // In a checkout where a run may write, with `files`: the hub of
        // `purl`, patched by `uuid`, and what to do.
        let said = |files: &[(&str, &str)], purl: &str| {
            let dir = checkout(files);
            let patches = [("pkg:npm/left-pad@1.3.0", uuid), (purl, uuid)];
            let mut found = upstream(dir.path(), &patches);
            assert_eq!((found.len(), &found[0]), (2, &None), "{purl}");
            let (hub, remedy) = found.remove(1).unzip();
            let hub = hub.map(|hub: Hub| {
                let lock = hub.lock.unwrap_or_default();
                format!("{} {}:{} {lock}", hub.name, hub.file, hub.line)
            });
            (hub.unwrap_or_default(), remedy.unwrap_or_default())
        };
        let hub = "maven MODULE.bazel:4 maven_install.json";
        let run = format!(
            "Run `socket-patch get {NETTY_PURL} --mode hosted` at the Bazel root to patch the \
             hub, or with `--mode vendored` to commit the patched jar."
        );
        let fetched = (hub.to_string(), run.clone());
        let nothing = (String::new(), String::new());
        // The hub, where hosted and vendored mode write no entry for it:
        // the code of their warning, and how its reason ends.
        let declined = |files: &[(&str, &str)], code: &str, ends: &str| {
            let (found, remedy) = said(files, NETTY_PURL);
            let begins =
                format!("Hosted and vendored mode write no entry for this hub (`{code}`): ");
            let whole = remedy.starts_with(&begins) && remedy.ends_with(&format!("{ends}."));
            assert!(found == hub && whole, "{files:?}: {found:?} {remedy:?}");
        };
        assert_eq!(said(&[], NETTY_PURL), fetched);
        // The command names the jar by its coordinates: nothing of what a
        // purl carries after them, which a shell would read, is in it.
        let qualified = format!("{NETTY_PURL}?type=jar&repository_url=x");
        assert_eq!(said(&[], &qualified), fetched);
        // The warning of an agent run names the same command.
        let warned = notices_blocking(checkout(&[]).path(), vec![qualified.clone()]);
        let command = run.split(" to patch").next().expect("the command");
        let command = command.trim_start_matches("Run ");
        let names = |(_, detail): &(_, String)| detail.contains(&format!("{command} patches"));
        assert!(warned.len() == 1 && names(&warned[0]), "{warned:?}");
        // Not another version, a classifier or a packaging of the jar.
        let others = [
            NETTY_PURL.replace("61", "62"),
            format!("{NETTY_PURL}?classifier=sources"),
            format!("{NETTY_PURL}?type=aar"),
        ];
        for purl in others {
            assert_eq!(said(&[], &purl), nothing, "{purl}");
        }
        // Also a jar that no repository of the lock lists: under `m2local`
        // the hub takes it from the Maven local repository, at that sha256,
        // and no entry can take its place.
        let local = lock.replace("\"repositories\"", "\"m2local\": true, \"mirrors\"");
        let local = [("maven_install.json", local.as_str())];
        declined(
            &local,
            ARTIFACT,
            "there is no repository for an entry to replace",
        );
        // The block's entry of the patch is the jar Bazel takes, and a
        // block that was changed by hand may hold one. The entry of another
        // patch is not this one's: it is named, and the command replaces
        // it. An entry for another version is the entry of another jar.
        fn module(text: &str) -> [(&str, &str); 1] {
            [("MODULE.bazel", text)]
        }
        assert_eq!(said(&module(&patched), NETTY_PURL), nothing);
        let by_hand = patched.replace("# Do not change", "# Do change");
        assert_eq!(said(&module(&by_hand), NETTY_PURL), nothing);
        let another = patch("netty-tcnative-classes", OTHER_UUID);
        let another = with_patch(PINNED, LABEL, another).expect("a block");
        let names = format!(
            "MODULE.bazel holds the entry of patch {OTHER_UUID} for this jar, and where the \
             block is in effect the Bazel build takes that patch's jar. {run}"
        );
        let replaced = (hub.to_string(), names);
        assert_eq!(said(&module(&another), NETTY_PURL), replaced);
        let mut earlier = patch("netty-tcnative-classes", uuid);
        earlier.version = "2.0.60.Final".to_string();
        let earlier = with_patch(PINNED, LABEL, earlier).expect("a block");
        assert_eq!(said(&module(&earlier), NETTY_PURL), fetched);
        // What is not known of another hub leaves this one as it is, and
        // says why no entry is written: a hub without a lock, and a
        // `maven_install` of a `WORKSPACE` file that Bazel 7 reads. An
        // override of the jar is about this hub.
        let lockless = "maven.artifact(name = 'more', artifact = 'a', group = 'g', version = '1')";
        let over = "maven.override(coordinates = 'io.netty:netty-tcnative-classes', target = ':a')";
        let [lockless, over] = [lockless, over].map(|more| format!("{PINNED}{more}\n"));
        declined(
            &module(&lockless),
            NOT_PINNED,
            "(`REPIN=1 bazel run @more//:pin`)",
        );
        assert_eq!(said(&module(&over), NETTY_PURL), nothing);
        let (bazel_6, bazel_7) = ((".bazelversion", "6.5.0\n"), (".bazelversion", "7.7.2\n"));
        let bazel_9 = (".bazelversion", "9.3.2\n");
        let legacy = ("WORKSPACE", "maven_install(artifacts = [])\n");
        let not_read = "WORKSPACE:1: a `maven_install` of a WORKSPACE file is not read";
        declined(&[legacy, bazel_7], UNREADABLE, not_read);
        assert_eq!(said(&[legacy, bazel_9], NETTY_PURL), fetched);
        // Nothing where the checkout does not say that Bazel reads
        // `MODULE.bazel`: it names a Bazel before 7.0, or none beside a
        // `WORKSPACE` file that defines anything.
        let other = ("WORKSPACE", "http_archive(name = 'zlib', urls = [])\n");
        assert_eq!(said(&[bazel_6], NETTY_PURL), nothing);
        for file in [legacy, other] {
            assert_eq!(said(&[file], NETTY_PURL), nothing, "{file:?}");
        }
        assert_eq!(said(&[other, bazel_7], NETTY_PURL), fetched);
        // Nor where an rc file names an option that switches Bzlmod off or
        // drops tags of the root, on whatever line, or cannot be read:
        // with it the hub, and an entry of the block, may be out of the
        // build. An option about downloads leaves the hub as it is.
        let unread = [
            (".bazelrc", "import %workspace%/ci.bazelrc\n"),
            ("ci.bazelrc/a", ""),
        ];
        let rc = |text: &'static str| [(".bazelrc", text), bazel_7];
        for files in [
            &rc("build:legacy --noenable_bzlmod\n")[..],
            &rc("common --ignore_dev_dependency\n"),
            &unread,
        ] {
            assert_eq!(said(files, NETTY_PURL), nothing, "{files:?}");
        }
        let offline = rc("build --repository_disable_download\n");
        assert_eq!(said(&offline, NETTY_PURL), fetched);
        // A Bazel without `override_repo`, and a hub on a usage that no
        // entry reaches: the hub fetches the jar, and no mode patches it.
        let old = [(".bazelversion", "7.3.0\n")];
        declined(&old, RELEASE, "which Bazel has from 7.4.0");
        let isolated = PINNED.replace("\"maven\")", "\"maven\", isolate = True)");
        declined(&module(&isolated), UNREADABLE, "reaches");
    }

    /// What the warning for a hub that was not read says after where and
    /// why.
    const NOT_READ: &str = "so socket-patch does not know every Maven artifact that Bazel builds \
                            here through a rules_jvm_external hub: it looks for patches of the \
                            ones in the hub locks it read, and of no other";

    #[test]
    fn a_hosted_scan_takes_the_plain_jars_that_pinned_hubs_fetch() {
        let netty = |artifact| format!("pkg:maven/io.netty/netty-tcnative-{artifact}@2.0.61.Final");
        let netty = [netty("boringssl-static"), netty("classes")];
        let netty: Vec<&str> = netty.iter().map(String::as_str).collect();
        let sqlite = "pkg:maven/com.almworks.sqlite4java/sqlite4java@1.0.392";
        let local = LOCK_SKIPS.replace(
            "\"version\": \"3\"",
            "\"m2local\": true, \"version\": \"3\"",
        );
        // A version and an artifact that no repository can be named for:
        // the run that finds a patch of one says so (`maven_bazel_artifact`).
        let odd = r#"{"artifacts": {
            "a.b:c": {"shasums": {"jar": "00"}, "version": "1.0+local"},
            "a.b:d@e": {"shasums": {"jar": "11"}, "version": "1.0"},
            "a.b:f": {"shasums": {"jar": "22"}, "version": "1.0"}},
          "repositories": {"https://repo.example/": ["a.b:c", "a.b:d@e", "a.b:f"]},
          "version": "3"}"#;
        let odd_jars =
            ["c@1.0+local", "d@e@1.0", "f@1.0"].map(|jar| format!("pkg:maven/a.b/{jar}"));
        let two =
            format!("{PINNED}maven.install(name = \"tools\", lock_file = \"//:tools.json\")\n");
        let lockless = format!("{PINNED}maven.install(name = \"tools\")\n");
        let (v2, v3) = (lock_69(), lock_72());
        // A lock larger than the 1 MiB of a Starlark file.
        let large = lock_72() + &" ".repeat(1 << 20);
        let main = "maven_install.json";
        let pin = ". Give the hub a `lock_file` and pin it (`REPIN=1 bazel run @tools//:pin`)";
        // A file the reader cannot have, in a workspace with a hub and in
        // one that names no ruleset of Maven's.
        let gone = "more.MODULE.bazel: it does not exist; MODULE.bazel";
        let more = format!("{PINNED}include(\"//:more.MODULE.bazel\")\n");
        let go = "bazel_dep(name = \"rules_go\", version = \"0.50.1\")\n\
                  include(\"//:more.MODULE.bazel\")\n";
        // The block of an earlier run, for netty's jar.
        let entry = patch("netty-tcnative-classes", NETTY_UUID);
        let patched = with_patch(PINNED, LABEL, entry).expect("a block");
        let patched_lockless = format!("{patched}\nmaven.install(name = \"tools\")\n");
        let rows: [(&str, &[(&str, &str)], Vec<&str>, Option<String>, bool); 19] = [
            // The jar without a classifier of each artifact, in each format.
            (PINNED, &[(main, &v2)], netty.clone(), None, false),
            (PINNED, &[(main, &v3)], netty.clone(), None, false),
            (PINNED, &[(main, &large)], netty.clone(), None, false),
            // Not one the lock skips or has no sum of, not another
            // packaging, and not one that no repository lists,
            (PINNED, &[(main, LOCK_SKIPS)], vec![sqlite], None, false),
            // unless the hub takes it from the Maven local repository.
            (
                PINNED,
                &[(main, &local)],
                vec![sqlite, "pkg:maven/org.example/unlisted@1.0"],
                None,
                false,
            ),
            (
                PINNED,
                &[(main, odd)],
                odd_jars.iter().map(String::as_str).collect(),
                None,
                false,
            ),
            // Every pinned hub, and a jar that two of them fetch once.
            (
                &two,
                &[(main, &v3), ("tools.json", LOCK_SKIPS)],
                [&[sqlite], &netty[..]].concat(),
                None,
                false,
            ),
            (
                &two,
                &[(main, &v3), ("tools.json", &v2)],
                netty.clone(),
                None,
                false,
            ),
            // What was not read is said, once, and guessed at nowhere:
            // the hubs that were read still count.
            (
                &lockless,
                &[(main, &v3)],
                netty.clone(),
                Some(format!(
                    "MODULE.bazel:9: hub \"tools\" has no `lock_file`, {NOT_READ}{pin}"
                )),
                false,
            ),
            (
                &two,
                &[(main, &v3)],
                netty.clone(),
                Some(format!("tools.json: it does not exist, {NOT_READ}")),
                false,
            ),
            (
                PINNED,
                &[],
                vec![],
                Some(format!("maven_install.json: it does not exist, {NOT_READ}")),
                false,
            ),
            (
                &more,
                &[],
                vec![],
                Some(format!("{gone}:9 includes it, {NOT_READ}")),
                false,
            ),
            // Not in a workspace that has nothing to do with the ruleset:
            // what its reader could not have is about no hub. A lock at
            // the root says that it may have one, and so does a
            // `maven_install` of its `WORKSPACE` file.
            (go, &[], vec![], None, false),
            (
                go,
                &[(main, &v3)],
                vec![],
                Some(format!("{gone}:2 includes it, {NOT_READ}")),
                false,
            ),
            (
                "module(name = \"app\")\n",
                &[("WORKSPACE", "maven_install(artifacts = [])\n")],
                vec![],
                Some(format!(
                    "WORKSPACE:1: a `maven_install` of a WORKSPACE file is not read, {NOT_READ}"
                )),
                false,
            ),
            // An entry of the block is stale once every hub was read and
            // none fetches its jar at that version any more.
            (&patched, &[(main, &v3)], netty.clone(), None, false),
            (&patched, &[(main, LOCK_SKIPS)], vec![sqlite], None, true),
            (
                &patched_lockless,
                &[(main, LOCK_SKIPS)],
                vec![sqlite],
                Some(format!(
                    "MODULE.bazel:32: hub \"tools\" has no `lock_file`, {NOT_READ}{pin}"
                )),
                false,
            ),
            (
                &patched,
                &[],
                vec![],
                Some(format!("maven_install.json: it does not exist, {NOT_READ}")),
                false,
            ),
        ];
        for (module, locks, jars, unread, stale) in rows {
            let dir = project(&[&[("MODULE.bazel", module)], locks].concat());
            let expected = HubJars {
                jars: jars.into_iter().map(String::from).collect(),
                unread: unread.map(|detail| (HUB_NOT_READ, detail)),
                stale: Vec::from_iter(stale.then(|| (NETTY_PURL.into(), NETTY_UUID.into()))),
            };
            assert_eq!(hub_jars_blocking(dir.path()), expected, "{module}");
        }
        // A stale entry of vendored mode is not on the list: a hosted run
        // has no way to take its directory and its ledger entry with it.
        let mut vendored = patch("netty-tcnative-classes", NETTY_UUID);
        (vendored.sha256, vendored.url) = (String::new(), String::new());
        let module = with_patch(PINNED, LABEL, vendored).expect("a block");
        let dir = project(&[("MODULE.bazel", &module), (main, LOCK_SKIPS)]);
        assert!(hub_jars_blocking(dir.path()).stale.is_empty());
        // Only for the root of a workspace, where an entry is written:
        // not below it, whatever its hubs are, and not without one.
        for module in [PINNED, &lockless] {
            let dir = project(&[("MODULE.bazel", module), (main, &v3)]);
            assert!(!hub_jars_blocking(dir.path()).jars.is_empty(), "{module}");
            let below = dir.path().join("services/billing");
            std::fs::create_dir_all(&below).unwrap();
            assert_eq!(hub_jars_blocking(&below), HubJars::default(), "{module}");
        }
        let plain = project(&[("pom.xml", "<project/>"), (main, &v3)]);
        assert_eq!(hub_jars_blocking(plain.path()), HubJars::default());
    }

    /// A lock is read once for all the hubs that name it. A scan takes
    /// the locks of one workspace within a bound: the lock past it is a
    /// doubt, like one that is too large by itself, and no lock after it
    /// is read. Every other reader takes them all, as before.
    #[test]
    fn the_locks_of_a_workspace_are_read_once_and_within_a_bound() {
        let hub = |name: &str, lock: &str| {
            format!("maven.install(name = \"{name}\", lock_file = \"//:{lock}.json\")\n")
        };
        let hubs = [
            ("a", "a"),
            ("b", "a"),
            ("c", "c"),
            ("d", "d"),
            ("e", "e"),
            ("f", "f"),
        ];
        let module = hubs
            .iter()
            .fold(PINNED.to_string(), |module, (name, lock)| {
                module + &hub(name, lock)
            });
        let full = lock_72() + &" ".repeat(MAX_LOCK - lock_72().len());
        let asked = std::cell::RefCell::new(Vec::new());
        let view = |path: &str| {
            asked.borrow_mut().push(path.to_string());
            match path {
                "MODULE.bazel" => Entry::Text(module.clone()),
                "maven_install.json" | "f.json" => Entry::Text(lock_72()),
                "a.json" | "c.json" | "d.json" | "e.json" => Entry::Text(full.clone()),
                _ => Entry::Absent,
            }
        };
        let names = |(hub, _): &(Hub, Rc<Lock>)| hub.name.clone();
        let read = Hubs::read_within(&view, &view, MAX_LOCKS);
        let pinned: Vec<String> = read.pinned.iter().map(names).collect();
        assert_eq!(pinned, ["maven", "a", "b", "c", "d"]);
        let doubt = read.doubt.expect("a doubt");
        let why = "the locks of the workspace are larger than 64 MiB in all";
        assert_eq!((doubt.file.as_str(), doubt.why.as_str()), ("e.json", why));
        let times = |lock: &str| asked.borrow().iter().filter(|path| *path == lock).count();
        assert_eq!(
            ["a.json", "c.json", "e.json", "f.json"].map(times),
            [1, 1, 1, 0]
        );

        asked.borrow_mut().clear();
        let read = Hubs::read(&view, &view);
        let pinned: Vec<String> = read.pinned.iter().map(names).collect();
        assert_eq!(pinned, ["maven", "a", "b", "c", "d", "e", "f"]);
        assert!(read.doubt.is_none());
        assert_eq!(["a.json", "e.json", "f.json"].map(times), [1, 1, 1]);
    }

    // The block, and what a hosted run writes of it.

    const NETTY_UUID: &str = "0e77a000-0000-4000-8000-0000000000a1";
    const OTHER_UUID: &str = "0e77a000-0000-4000-8000-0000000000b2";

    /// A patch of `io.netty:<artifact>` at the version of the locks.
    fn patch(artifact: &str, uuid: &str) -> Patch {
        let served = format!("2.0.61.Final-socket.{}", &uuid[..8]);
        Patch {
            group: "io.netty".to_string(),
            artifact: artifact.to_string(),
            version: "2.0.61.Final".to_string(),
            uuid: uuid.to_string(),
            sha256: "5".repeat(64),
            url: format!(
                "https://patch.socket.dev/patch-registry/maven/token/{uuid}/maven2/io/netty/\
                 {artifact}/{served}/{artifact}-{served}.jar"
            ),
        }
    }

    fn netty() -> Patch {
        patch("netty-tcnative-classes", NETTY_UUID)
    }

    /// The block of [`netty`], as it stands in a file: the measured text,
    /// with the remedy that this release has for a stale entry.
    const BLOCK: &str = r#"# >>> socket-patch: Maven patches for Bazel (managed block: socket-patch writes and removes it) >>>
socket_patch_http_file = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

socket_patch_maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")

# pkg:maven/io.netty/netty-tcnative-classes@2.0.61.Final, Socket patch 0e77a000-0000-4000-8000-0000000000a1
socket_patch_http_file(
    name = "socket_patch_io_netty_netty_tcnative_classes_2_0_61_Final",
    downloaded_file_path = "v1/io/netty/netty-tcnative-classes/2.0.61.Final/netty-tcnative-classes-2.0.61.Final.jar",
    sha256 = "5555555555555555555555555555555555555555555555555555555555555555",
    urls = ["https://patch.socket.dev/patch-registry/maven/token/0e77a000-0000-4000-8000-0000000000a1/maven2/io/netty/netty-tcnative-classes/2.0.61.Final-socket.0e77a000/netty-tcnative-classes-2.0.61.Final-socket.0e77a000.jar"],
)

# If Bazel stops at the next line ("does not generate repository"), the hub's lock no longer pins
# io.netty:netty-tcnative-classes at 2.0.61.Final: run `socket-patch rollback pkg:maven/io.netty/netty-tcnative-classes@2.0.61.Final`.
# Do not change it to inject_repo(): the build would pass without the patch.
override_repo(
    socket_patch_maven,
    io_netty_netty_tcnative_classes_2_0_61_Final = "socket_patch_io_netty_netty_tcnative_classes_2_0_61_Final",
)
# <<< socket-patch <<<"#;

    const LABEL: &str = "@rules_jvm_external//:extensions.bzl";

    /// `escape` of the ruleset's `download_pinned_deps.bzl` (6.4 to 6.7)
    /// and `to_repository_name` of `coursier_utilities.bzl` (6.8 to 7.2)
    /// give one name for a jar whose coordinates hold letters, digits,
    /// `.`, `_` and `-`. Another character has no name here: the two
    /// differ over `$`, and none was read for the rest.
    #[test]
    fn a_repository_is_named_only_where_every_ruleset_release_agrees() {
        for ((group, artifact, version), name) in [
            (
                ("dev.socket.fixture", "victim", "1.10.0"),
                Some("dev_socket_fixture_victim_1_10_0"),
            ),
            (
                ("com.google.guava", "guava", "31.1-jre"),
                Some("com_google_guava_guava_31_1_jre"),
            ),
            (
                ("org.scala-lang", "scala_library", "2.13.12"),
                Some("org_scala_lang_scala_library_2_13_12"),
            ),
            (("g", "a$b", "1"), None),
            (("g", "a", "1+build.2"), None),
            (("g", "a", "[1,2)"), None),
            (("g", "a:jar:tests", "1"), None),
            (("g", "a b", "1"), None),
            (("g\u{e9}", "a", "1"), None),
            (("g", "", "1"), None),
            (("", "a", "1"), None),
            (("g", "a", ""), None),
        ] {
            let named = repository_name(group, artifact, version);
            assert_eq!(named.as_deref(), name, "{group}:{artifact}:{version}");
        }
    }

    /// The text of the block is fixed: it is how the block is recognised.
    #[test]
    fn the_block_is_written_as_it_was_measured() {
        assert_eq!(render(LABEL, &[netty()]), BLOCK);
        assert_eq!(
            parse(BLOCK),
            Some((LABEL.to_string(), vec![netty()])),
            "what is written is what is read"
        );
        // Each patch has its own `override_repo`, and they stand by the
        // name of their repository whatever the order they came in.
        let other = patch("netty-tcnative-boringssl-static", OTHER_UUID);
        let both = render("@rje//:extensions.bzl", &[netty(), other.clone()]);
        assert_eq!(both, render("@rje//:extensions.bzl", &[other, netty()]));
        let at = |text: &str| both.find(text).expect(text);
        assert!(at(OTHER_UUID) < at(NETTY_UUID), "{both}");
        assert_eq!(both.matches("\noverride_repo(\n").count(), 2, "{both}");
        assert_eq!(both.matches("use_repo_rule(").count(), 1, "{both}");
        assert!(
            both.contains("use_extension(\"@rje//:extensions.bzl\", \"maven\")"),
            "{both}"
        );
    }

    /// The files a block is added to: with and without a last line break,
    /// with blank lines at the end, with either line break, and with
    /// both: the other one on the first line, or on the last.
    fn modules() -> Vec<String> {
        let ends = ["\n", "", "\n\n\n"].map(|end| format!("{}{end}", PINNED.trim_end()));
        let crlf = ends.iter().map(|module| module.replace('\n', "\r\n"));
        let first = ends[..2]
            .iter()
            .map(|module| module.replacen('\n', "\r\n", 1));
        let last = [format!("{}\r\n", PINNED.trim_end())];
        let both = first.chain(last);
        ends.iter().cloned().chain(crlf).chain(both).collect()
    }

    #[test]
    fn a_patch_is_added_once_and_taken_out_to_the_byte() {
        for module in modules() {
            let eol = terminator(&module);
            let one = with_patch(&module, LABEL, netty()).expect("a block");
            // After one blank line, in the line break of the file: the
            // more frequent one of a file with both.
            let block = BLOCK.replace('\n', eol);
            let ended = module.ends_with('\n');
            let expected = match ended {
                true => format!("{module}{eol}{block}{eol}"),
                false => format!("{module}{eol}{eol}{block}"),
            };
            assert_eq!(one, expected, "{module:?}");
            let crlf = module.matches("\r\n").count();
            let more = crlf > module.matches('\n').count() - crlf;
            assert_eq!(more, eol == "\r\n", "{module:?}");
            let added = &one[module.len()..];
            assert_eq!(
                added.matches('\n').count(),
                added.matches(eol).count(),
                "{module:?}"
            );
            // Again, and with the same patch under a newer id: one entry.
            assert_eq!(with_patch(&one, LABEL, netty()), Some(one.clone()));
            let newer = with_patch(&one, LABEL, patch("netty-tcnative-classes", OTHER_UUID));
            let newer = newer.expect("a block");
            assert!(
                !newer.contains(NETTY_UUID) && newer.contains(OTHER_UUID),
                "{newer}"
            );
            assert_eq!(newer.matches(BEGIN).count(), 1, "{newer}");
            // A second patch, then out again in either order.
            let other = patch("netty-tcnative-boringssl-static", OTHER_UUID);
            let two = with_patch(&one, LABEL, other.clone()).expect("a block");
            let gone = |uuid: &'static str| move |patch: &Patch| patch.uuid == uuid;
            assert_eq!(
                without(&two, &mut gone(OTHER_UUID)),
                Some(one.clone()),
                "{module:?}"
            );
            let left = without(&two, &mut gone(NETTY_UUID)).expect("a block");
            assert_eq!(
                Some(left.clone()),
                with_patch(&module, LABEL, other),
                "{module:?}"
            );
            for last in [
                without(&left, &mut gone(OTHER_UUID)),
                without(&one, &mut gone(NETTY_UUID)),
                without(&two, &mut |_| true),
            ] {
                assert_eq!(last.as_deref(), Some(module.as_str()), "{module:?}");
            }
            // Nothing to take out leaves the file as it is.
            assert_eq!(without(&one, &mut |_| false), Some(one.clone()));
            // What the user wrote below the block stays below it.
            let below = format!("{one}{}bazel_dep(name = \"x\", version = \"1\"){eol}", {
                match ended {
                    true => "",
                    false => eol,
                }
            });
            let kept = without(&below, &mut |_| true).expect("a block");
            assert!(
                kept.starts_with(module.trim_end()) && kept.ends_with(&format!("\"1\"){eol}")),
                "{kept:?}"
            );
            assert!(!kept.contains("socket"), "{kept:?}");
        }
        assert_eq!(without(PINNED, &mut |_| true), None, "no block");
        // A block keeps its own line break in a file that gets the other
        // one on another line afterwards.
        let one = with_patch(PINNED, LABEL, netty()).expect("a block");
        let (other, plain) = (
            one.replacen('\n', "\r\n", 1),
            PINNED.replacen('\n', "\r\n", 1),
        );
        assert_eq!(with_patch(&other, LABEL, netty()), Some(other.clone()));
        assert_eq!(without(&other, &mut |_| true), Some(plain));
    }

    /// A block that is not what socket-patch writes for the patches it
    /// names is never written to, and is a doubt about what a hub builds.
    #[test]
    fn a_block_that_was_changed_by_hand_is_left_alone() {
        let lock = lock_72();
        let ours = with_patch(PINNED, LABEL, netty()).expect("a block");
        let line = PINNED.lines().count() + 2;
        // The first thing that could not be read of a workspace.
        let doubt = |module: &str| {
            let files = [("MODULE.bazel", module), ("maven_install.json", &lock)];
            let doubt = read(&files).doubt;
            doubt.map(|Doubt { file, line, why }| format!("{file}:{line}: {why}"))
        };
        assert_eq!(doubt(&ours), None);
        for (edited, what) in [
            (
                ours.replace("override_repo(", "inject_repo("),
                "another call",
            ),
            (
                ours.replace("# Do not change it", "# do not change it"),
                "a comment",
            ),
            (ours.replace(END, "# <<< socket-patch"), "no last line"),
            (ours.replace("    socket_patch_maven,\n", ""), "a line less"),
            (format!("{ours}{BEGIN}\n{END}\n"), "a second block"),
            (
                ours.replace(".jar\"],\n)", ".jar\"],\n    integrity = \"\",\n)"),
                "a line more",
            ),
            (ours.replace("\n# <<<", "\n\n# <<<"), "a blank line"),
            (
                ours.replace(BEGIN, &format!("{BEGIN} ")),
                "a blank after the first line",
            ),
            (
                ours.replace(BEGIN, &BEGIN.replace("(managed", "(my")),
                "another first line",
            ),
        ] {
            assert_ne!(edited, ours, "{what}");
            assert_eq!(find(&edited), Block::Edited(line), "{what}");
            assert_eq!(with_patch(&edited, LABEL, netty()), None, "{what}");
            assert_eq!(without(&edited, &mut |_| true), None, "{what}");
            let why = "the block that socket-patch keeps there was changed by hand";
            let said = Some(format!("MODULE.bazel:{line}: {why}"));
            assert_eq!(doubt(&edited), said, "{what}");
        }
        // Without its first line it is no block: text of the user's, which
        // hands a proxy to `override_repo`.
        let unmarked = ours.replace(BEGIN, "# mine now");
        assert_eq!(find(&unmarked), Block::None);
        let said = doubt(&unmarked).unwrap_or_default();
        assert!(said.ends_with("is used other than to call a tag"), "{said}");
    }

    /// With the block in place the workspace reads as the user wrote it:
    /// the same hubs on the same lines, and no doubt about a proxy that is
    /// handed to `override_repo`.
    #[test]
    fn the_workspace_reads_as_it_did_before_the_block() {
        let lock = lock_72();
        let below = "\nmaven.install(name = \"tools\", lock_file = \"//:maven_install.json\")\n";
        let ours = with_patch(PINNED, LABEL, netty()).expect("a block") + below;
        let plain = format!("{PINNED}{}{below}", "\n".repeat(BLOCK.lines().count() + 1));
        let hubs = |module: &str| {
            let files = [("MODULE.bazel", module), ("maven_install.json", &lock)];
            let read = read(&files);
            let hub = |(hub, _): &(Hub, _)| format!("{} {}:{}", hub.name, hub.file, hub.line);
            let hubs: Vec<String> = read.pinned.iter().map(hub).collect();
            (hubs, read.doubt, built(&files))
        };
        let line = PINNED.lines().count() + BLOCK.lines().count() + 3;
        let both = [
            "maven MODULE.bazel:4".to_string(),
            format!("tools MODULE.bazel:{line}"),
        ];
        assert_eq!(hubs(&ours), (both.to_vec(), None, "yes, 2".to_string()));
        assert_eq!(hubs(&ours), hubs(&plain));
        assert_eq!(read(&[("MODULE.bazel", ours.as_str())]).block, [netty()]);
        assert_eq!(read(&[("MODULE.bazel", PINNED)]).block, []);
    }

    /// A checkout with the files `files`, where a hosted run may write.
    fn checkout(files: &[(&str, &str)]) -> tempfile::TempDir {
        let lock = lock_72();
        let bcr = "https://bcr.bazel.build/modules/rules_jvm_external";
        let module_lock = format!(
            "{{\"lockFileVersion\": 13, \"registryFileHashes\": {{\"{bcr}/6.5/MODULE.bazel\": \
             \"0\", \"{bcr}/7.2/MODULE.bazel\": \"1\", \"{bcr}/7.2/source.json\": \"2\"}}}}"
        );
        let base = [
            ("MODULE.bazel", PINNED),
            ("maven_install.json", &lock),
            ("MODULE.bazel.lock", &module_lock),
        ];
        let dir = project(&base);
        for (path, text) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        dir
    }

    /// The patch [`NETTY_UUID`] of the jar `io.netty:<artifact>` at
    /// `version`.
    fn jar(artifact: &str, version: &str) -> Vec<Jar> {
        let jar = [NETTY_UUID, "io.netty", artifact, version].map(String::from);
        vec![jar.into()]
    }

    fn netty_jar() -> Vec<Jar> {
        jar("netty-tcnative-classes", "2.0.61.Final")
    }

    /// What [`site`] says of netty's jar in the checkout: `write <label>`,
    /// `<code>: <why>`, or `-`.
    fn verdict(dir: &Path) -> String {
        match site(dir, None, &netty_jar(), false).remove(NETTY_UUID) {
            None => "-".to_string(),
            Some(Verdict { entry, held }) => {
                assert_eq!(held, None);
                match entry {
                    Ok(label) => format!("write {label}"),
                    Err((code, why)) => format!("{code}: {why}"),
                }
            }
        }
    }

    #[test]
    fn an_entry_is_written_for_a_jar_that_a_pinned_hub_fetches() {
        let write = format!("write {LABEL}");
        assert_eq!(verdict(checkout(&[]).path()), write);
        // The label is the user's own, under the name the checkout has
        // for the ruleset, also for a hub in a file the root includes and
        // for a proxy of development dependencies.
        let renamed = PINNED
            .replace(
                "version = \"7.2\")",
                "version = \"7.2\", repo_name = \"rje\")",
            )
            .replace("@rules_jvm_external//", "@rje//");
        let (root, hub) = renamed.split_once("\n\n").expect("two parts");
        let root = format!("{root}\ninclude(\"//third_party:jvm.MODULE.bazel\")\n");
        let dev = hub.replace("\"maven\")", "\"maven\", dev_dependency = True)");
        for files in [
            vec![("MODULE.bazel", renamed.as_str())],
            vec![
                ("MODULE.bazel", root.as_str()),
                ("third_party/jvm.MODULE.bazel", hub),
            ],
            vec![
                ("MODULE.bazel", root.as_str()),
                ("third_party/jvm.MODULE.bazel", &dev),
            ],
        ] {
            assert_eq!(
                verdict(checkout(&files).path()),
                "write @rje//:extensions.bzl"
            );
        }
        // Each of these says enough of the Bazel that builds the checkout.
        let old_lock = "{\"lockFileVersion\": 11, \"registryFileHashes\": {\"https://bcr.bazel.\
                        build/modules/rules_jvm_external/6.5/source.json\": \"0\"}}";
        let asks_65 = PINNED.replace("\"7.2\"", "\"6.5\"");
        for files in [
            vec![
                (".bazelversion", "7.4.0\n"),
                ("MODULE.bazel.lock", old_lock),
                ("MODULE.bazel", asks_65.as_str()),
            ],
            vec![(".bazeliskrc", "USE_BAZEL_VERSION=9.3.2\n")],
            // Options that leave an entry in effect.
            vec![(
                ".bazelrc",
                "common --enable_bzlmod\nbuild --noignore_dev_dependency\n",
            )],
            vec![(
                ".bazelrc",
                "# common --noenable_bzlmod\nbuild --norepository_disable_download\n",
            )],
            vec![(
                ".bazelrc",
                "common --enable_bzlmod=True --experimental_enable_bzlmod=1\n\
                 build --ignore_dev_dependency=F --repository_disable_download=no\n",
            )],
            vec![
                (".bazelrc", "common --noenable_bzlmod\n"),
                (".bazelversion", "9.3.2\n"),
            ],
        ] {
            assert_eq!(verdict(checkout(&files).path()), write, "{files:?}");
        }
        // What the root asks of the ruleset, and a lock that agrees with
        // it: a release that a `single_version_override` pins below the
        // one the `bazel_dep` names, an override without a version, which
        // leaves the release to the graph, a `bazel_dep` of three numbers
        // below the release Bazel selected, and an override of another
        // module.
        let bcr = "https://bcr.bazel.build/modules/rules_jvm_external";
        let lock_69 = format!(
            "{{\"lockFileVersion\": 13, \"registryFileHashes\": {{\"{bcr}/6.9/source.json\": \
             \"0\"}}}}"
        );
        let over = |rest: &str| format!("{PINNED}single_version_override(module_name = {rest})\n");
        let pins_69 = over("\"rules_jvm_external\", version = \"6.9\"");
        let patched = over("\"rules_jvm_external\", patches = [\"//:rje.patch\"]");
        let asks_715 = PINNED.replace("\"7.2\"", "\"7.1.5\"");
        let other = format!("{PINNED}archive_override(module_name = \"rules_java\", urls = [])\n");
        for files in [
            vec![
                ("MODULE.bazel", pins_69.as_str()),
                ("MODULE.bazel.lock", lock_69.as_str()),
            ],
            vec![("MODULE.bazel", patched.as_str())],
            vec![("MODULE.bazel", asks_715.as_str())],
            vec![("MODULE.bazel", other.as_str())],
        ] {
            assert_eq!(verdict(checkout(&files).path()), write, "{files:?}");
        }
        // A jar that no hub fetches has no verdict at all, and neither has
        // any jar outside a Bazel workspace.
        let elsewhere = checkout(&[("maven_install.json", LOCK_SKIPS)]);
        assert_eq!(
            site(elsewhere.path(), None, &netty_jar(), false),
            Site::new()
        );
        let plain = project(&[("pom.xml", "<project/>")]);
        assert_eq!(site(plain.path(), None, &netty_jar(), false), Site::new());
        // The text the run has of `MODULE.bazel` is the one that is read.
        let lockless = PINNED.replace("    lock_file = \"//:maven_install.json\",\n", "");
        let dir = checkout(&[]);
        let said = site(dir.path(), Some(&lockless), &netty_jar(), false);
        let declined = |verdict: &Verdict| verdict.entry.is_err();
        assert!(said.values().next().is_some_and(declined), "{said:?}");
    }

    /// One row per reason for which no entry is written.
    #[test]
    fn each_decline_has_its_code_and_says_why() {
        let lockless = PINNED.replace("    lock_file = \"//:maven_install.json\",\n", "");
        let beside = format!("{PINNED}maven.install(name = \"tools\")\n");
        let computed = PINNED.replace("\"//:maven_install.json\"", "LOCK");
        let isolated = PINNED.replace("\"maven\")", "\"maven\", isolate = True)");
        let maybe = PINNED.replace("\"maven\")", "\"maven\", isolate = not SHARED)");
        // A name for the ruleset that could not stand in a string of the
        // block: the reader takes no such label for the extension.
        let quoted = PINNED
            .replace("\"7.2\")", "\"7.2\", repo_name = \"r\\\"je\")")
            .replace("@rules_jvm_external//", "@r\\\"je//");
        let over = format!(
            "{PINNED}maven.override(coordinates = \"io.netty:netty-tcnative-classes\", target = \
             \"//:own\")\n"
        );
        let edited = with_patch(PINNED, LABEL, netty())
            .expect("a block")
            .replace("# Do", "# do");
        let asks_73 = PINNED.replace("\"7.2\"", "\"7.3\"");
        let asks_721 = PINNED.replace("\"7.2\"", "\"7.2.1\"");
        let pins = |version: &str| {
            let dep = PINNED.replace("\"7.2\"", "\"6.5\"");
            format!(
                "{dep}single_version_override(module_name = \"rules_jvm_external\", version = \
                 \"{version}\")\n"
            )
        };
        let (pins_69, pins_72) = (pins("6.9"), pins("7.2"));
        // An override that takes the ruleset from no registry, keeps more
        // than one release of it, or pins a version that is no string.
        let replaced = |call: &str| format!("{PINNED}{call}\n");
        let unknown_release = |callee: &str| {
            format!(
                "{RELEASE}: MODULE.bazel:9: with this `{callee}` of rules_jvm_external \
                 socket-patch cannot tell which release of the ruleset Bazel builds with, and \
                 the name of a jar's repository depends on it"
            )
        };
        let overrides = [
            (
                "archive_override",
                "urls = [\"https://example.com/rje.tar.gz\"]",
            ),
            (
                "git_override",
                "remote = \"https://example.com/rje.git\", commit = \"0\"",
            ),
            ("local_path_override", "path = \"third_party/rje\""),
            ("multiple_version_override", "versions = [\"6.5\", \"7.2\"]"),
            ("single_version_override", "version = RJE"),
        ]
        .map(|(callee, rest)| {
            let call = format!("{callee}(module_name = \"rules_jvm_external\", {rest})");
            (replaced(&call), unknown_release(callee))
        });
        let bcr = "https://bcr.bazel.build/modules/rules_jvm_external";
        let selected = |release: &str| {
            format!(
                "{{\"lockFileVersion\": 13, \"registryFileHashes\": {{\"{bcr}/{release}/source.\
                 json\": \"0\"}}}}"
            )
        };
        let (newer, older, lock_69) = (selected("7.3"), selected("6.3"), selected("6.9"));
        let two = format!(
            "{{\"lockFileVersion\": 13, \"registryFileHashes\": {{\"{bcr}/7.1/source.json\": \
             \"0\", \"{bcr}/7.2/source.json\": \"1\"}}}}"
        );
        let local = lock_72()
            .replace(
                "\"io.netty:netty-tcnative-classes\"\n    ]",
                "\"x:y\"\n    ]",
            )
            .replace(
                "\"version\": \"3\"",
                "\"m2local\": true, \"version\": \"3\"",
            );
        let release = "no file of the checkout says that Bazel 7.4.0 or later builds it, and an \
                       older Bazel fails on the `override_repo` an entry needs: name the release \
                       in `.bazelversion`";
        let unknown = "socket-patch could not tell whether Bazel takes this artifact from a \
                       rules_jvm_external hub";
        let rows: Vec<(Vec<(&str, &str)>, String)> = vec![
            (
                vec![("MODULE.bazel", &lockless)],
                format!(
                    "{NOT_PINNED}: MODULE.bazel:4: hub \"maven\" has no `lock_file`, so Bazel \
                     resolves its jars when it builds and none can be replaced: give the hub a \
                     `lock_file` and pin it (`REPIN=1 bazel run @maven//:pin`)"
                ),
            ),
            // Also beside the pinned hub that fetches the jar.
            (
                vec![("MODULE.bazel", &beside)],
                format!(
                    "{NOT_PINNED}: MODULE.bazel:9: hub \"tools\" has no `lock_file`, so Bazel \
                     resolves its jars when it builds and none can be replaced: give the hub a \
                     `lock_file` and pin it (`REPIN=1 bazel run @tools//:pin`)"
                ),
            ),
            (
                vec![("MODULE.bazel", &computed)],
                format!(
                    "{UNREADABLE}: {unknown}: MODULE.bazel:4: the `lock_file` of this hub is \
                     not a file of this repository"
                ),
            ),
            (
                vec![("maven_install.json", "")],
                format!(
                    "{UNREADABLE}: {unknown}: maven_install.json: it is empty: the hub is not \
                     pinned yet"
                ),
            ),
            (
                vec![("WORKSPACE", "maven_install(artifacts = [])\n")],
                format!(
                    "{UNREADABLE}: {unknown}: WORKSPACE:1: a `maven_install` of a WORKSPACE \
                     file is not read"
                ),
            ),
            (
                vec![("MODULE.bazel", &edited)],
                format!(
                    "{UNREADABLE}: {unknown}: MODULE.bazel:{}: the block that socket-patch \
                     keeps there was changed by hand",
                    PINNED.lines().count() + 2
                ),
            ),
            (
                vec![("MODULE.bazel", &isolated)],
                format!(
                    "{UNREADABLE}: MODULE.bazel:4: a tag of hub \"maven\" is called on a \
                     `use_extension` that is isolated or cannot be read, which no \
                     `override_repo` of another usage reaches"
                ),
            ),
            (
                vec![("MODULE.bazel", &maybe)],
                format!(
                    "{UNREADABLE}: MODULE.bazel:4: a tag of hub \"maven\" is called on a \
                     `use_extension` that is isolated or cannot be read, which no \
                     `override_repo` of another usage reaches"
                ),
            ),
            (
                vec![("MODULE.bazel", &quoted)],
                format!("{UNREADABLE}: {unknown}: MODULE.bazel:3: this `use_extension` cannot be read"),
            ),
            (
                vec![(".bazelrc", "import %workspace%/ci.bazelrc\n"), ("ci.bazelrc/a", "")],
                format!("{UNREADABLE}: the rc file ci.bazelrc cannot be read, and may switch an entry off"),
            ),
            // A line that Bazel reads in a way its own source calls an
            // oversight: the file, and that line.
            (
                vec![(".bazelrc", "build --jobs=4\ncommon '--noenable_bzlmod\n")],
                format!("{UNREADABLE}: the rc file .bazelrc:2 cannot be read, and may switch an entry off"),
            ),
            (
                vec![("MODULE.bazel", &over)],
                format!(
                    "{NO_EFFECT}: MODULE.bazel:9: a `maven.override` gives this artifact \
                     another target, so Bazel would not build a patched jar: patch that target, \
                     or remove the override"
                ),
            ),
            (
                vec![(".bazelrc", "build:ci --ignore_dev_dependency\n")],
                format!(
                    "{NO_EFFECT}: .bazelrc:1 names `--ignore_dev_dependency`, under which Bazel \
                     can drop the tags of a hub"
                ),
            ),
            (
                vec![(".bazelrc", "\ntry-import %workspace%/tools/ci.bazelrc\n"), ("tools/ci.bazelrc", "common --enable_bzlmod=false\n")],
                format!(
                    "{NO_EFFECT}: tools/ci.bazelrc:1 names `--enable_bzlmod=false`, which \
                     switches off the file an entry is written to"
                ),
            ),
            (
                vec![(".bazelrc", "common --noenable_bzlmod\n"), (".bazelversion", "8.8.2\n")],
                format!(
                    "{NO_EFFECT}: .bazelrc:1 names `--noenable_bzlmod`, which switches off the \
                     file an entry is written to"
                ),
            ),
            // An import that only a newer Bazel takes, and one that Bazel
            // opens from where it runs.
            (
                vec![
                    (".bazelrc", "try-import-if-bazel-version >=8.0.0 %workspace%/new.bazelrc\n"),
                    ("new.bazelrc", "common --noenable_bzlmod\n"),
                ],
                format!(
                    "{NO_EFFECT}: new.bazelrc:1 names `--noenable_bzlmod`, which switches off the \
                     file an entry is written to"
                ),
            ),
            (
                vec![
                    (".bazelrc", "import tools/ci.bazelrc\n"),
                    ("tools/ci.bazelrc", "common --downloader_config=dl.cfg\n"),
                ],
                format!(
                    "{DOWNLOAD}: tools/ci.bazelrc:1 names `--downloader_config=dl.cfg`, under \
                     which Bazel may not download the patched jar from the Socket patch host"
                ),
            ),
            (
                vec![(".bazelrc", "common --experimental_downloader_config=mirror.cfg\n")],
                format!(
                    "{DOWNLOAD}: .bazelrc:1 names `--experimental_downloader_config=mirror.cfg`, \
                     under which Bazel may not download the patched jar from the Socket patch \
                     host"
                ),
            ),
            (
                vec![(".bazelrc", "\n\nfetch --repository_disable_download\n")],
                format!(
                    "{DOWNLOAD}: .bazelrc:3 names `--repository_disable_download`, under which \
                     Bazel may not download the patched jar from the Socket patch host"
                ),
            ),
            (
                vec![(".bazelrc", "common --vendor_dir=third_party/bazel\n")],
                format!(
                    "{DOWNLOAD}: .bazelrc:1 names `--vendor_dir=third_party/bazel`, under which \
                     Bazel may not download the patched jar from the Socket patch host"
                ),
            ),
            (
                vec![(".bazelversion", "7.3.2\n")],
                format!(
                    "{RELEASE}: the checkout names Bazel 7.3.2 (`.bazeliskrc` or \
                     `.bazelversion`), and an entry needs `override_repo`, which Bazel has \
                     from 7.4.0"
                ),
            ),
            (vec![("MODULE.bazel.lock", "{\"lockFileVersion\": 11}")], format!("{RELEASE}: {release}")),
            (vec![("MODULE.bazel.lock", "")], format!("{RELEASE}: {release}")),
            (vec![(".bazelversion", "8.x\n"), ("MODULE.bazel.lock", "{}")], format!("{RELEASE}: {release}")),
            (
                vec![("MODULE.bazel.lock", &newer)],
                format!(
                    "{RELEASE}: Bazel selected rules_jvm_external 7.3, and how the ruleset \
                     names the repository of a jar is known for its releases 6.4 to 7.2: update \
                     socket-patch"
                ),
            ),
            (
                vec![("MODULE.bazel.lock", &older)],
                format!(
                    "{RELEASE}: Bazel selected rules_jvm_external 6.3, and how the ruleset \
                     names the repository of a jar is known for its releases 6.4 to 7.2: update \
                     socket-patch"
                ),
            ),
            (
                vec![("MODULE.bazel", &asks_73)],
                format!(
                    "{RELEASE}: MODULE.bazel asks for rules_jvm_external 7.3 and \
                     MODULE.bazel.lock holds 7.2: build once so that Bazel updates its lock"
                ),
            ),
            // A `single_version_override` pins the release whatever the
            // `bazel_dep` asks for: a lock that holds another one, older
            // or newer, is one Bazel has not written since.
            (
                vec![("MODULE.bazel", &pins_69)],
                format!(
                    "{RELEASE}: MODULE.bazel asks for rules_jvm_external 6.9 and \
                     MODULE.bazel.lock holds 7.2: build once so that Bazel updates its lock"
                ),
            ),
            (
                vec![("MODULE.bazel", &pins_72), ("MODULE.bazel.lock", &lock_69)],
                format!(
                    "{RELEASE}: MODULE.bazel asks for rules_jvm_external 7.2 and \
                     MODULE.bazel.lock holds 6.9: build once so that Bazel updates its lock"
                ),
            ),
            // Three numbers are above two that they start with.
            (
                vec![("MODULE.bazel", &asks_721)],
                format!(
                    "{RELEASE}: MODULE.bazel asks for rules_jvm_external 7.2.1 and \
                     MODULE.bazel.lock holds 7.2: build once so that Bazel updates its lock"
                ),
            ),
            (
                vec![("MODULE.bazel.lock", "{\"lockFileVersion\": 13}")],
                format!(
                    "{RELEASE}: MODULE.bazel.lock does not say which release of \
                     rules_jvm_external Bazel selected, and the name of a jar's repository \
                     depends on it: build once so that Bazel writes its lock"
                ),
            ),
            (
                vec![("MODULE.bazel.lock", &two)],
                format!(
                    "{RELEASE}: MODULE.bazel.lock does not say which release of \
                     rules_jvm_external Bazel selected, and the name of a jar's repository \
                     depends on it: build once so that Bazel writes its lock"
                ),
            ),
            (
                vec![("maven_install.json", &local)],
                format!(
                    "{ARTIFACT}: maven_install.json lists no repository for \
                     io.netty:netty-tcnative-classes: the hub takes the jar from the Maven \
                     local repository, and on a machine without it there is no repository for \
                     an entry to replace"
                ),
            ),
        ];
        // Every wrong row in one message: what it says, and what it should.
        let mut wrong = Vec::new();
        let replaced = overrides.iter();
        let replaced =
            replaced.map(|(module, said)| (vec![("MODULE.bazel", &**module)], said.clone()));
        for (files, said) in rows.into_iter().chain(replaced) {
            let verdict = verdict(checkout(&files).path());
            wrong.extend((verdict != said).then_some((verdict, said)));
        }
        // Each way Bazel reads "off" for Bzlmod, and a word that is not
        // "on" for certain. The option is named as Bazel reads it: without
        // its quotes, and joined over a line that ends in `\`.
        for (written, read) in [
            ("--enable_bzlmod=False", "--enable_bzlmod=False"),
            ("--enable_bzlmod=f", "--enable_bzlmod=f"),
            ("--enable_bzlmod=N", "--enable_bzlmod=N"),
            ("--enable_bzlmod=0", "--enable_bzlmod=0"),
            ("--enable_bzlmod=no", "--enable_bzlmod=no"),
            ("--enable_bzlmod=", "--enable_bzlmod="),
            ("\"--noenable_bzlmod\"", "--noenable_bzlmod"),
            ("--noenable_\"bzl\"mod", "--noenable_bzlmod"),
            ("--noenable_\\\nbzlmod", "--noenable_bzlmod"),
            ("--enable_bzlmod='fal'se", "--enable_bzlmod=false"),
        ] {
            let rc = format!("common {written}\n");
            let verdict = verdict(checkout(&[(".bazelrc", &rc)]).path());
            let said = format!(
                "{NO_EFFECT}: .bazelrc:1 names `{read}`, which switches off the file an entry is \
                 written to"
            );
            wrong.extend((verdict != said).then_some((verdict, said)));
        }
        // A project below the root of its workspace, whose file is not its
        // own to write.
        let dir = checkout(&[]);
        let below = dir.path().join("services/billing");
        std::fs::create_dir_all(&below).unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let said = format!(
            "{NOT_AT_ROOT}: a hub of the Bazel workspace at {} builds this artifact, and this \
             project is not its root, where the patch of a hub is written: run the command there",
            root.display()
        );
        wrong.extend((verdict(&below) != said).then(|| (verdict(&below), said)));
        assert_eq!(wrong, []);
        // The root is read for such a project too: the verdict says what
        // its block holds for the jar, as it does for a project at the
        // root.
        let ours = with_patch(PINNED, LABEL, netty()).expect("a block");
        std::fs::write(dir.path().join("MODULE.bazel"), &ours).unwrap();
        for project in [dir.path(), below.as_path()] {
            let held = site(project, None, &netty_jar(), false).remove(NETTY_UUID);
            let held = held.and_then(|verdict| verdict.held);
            assert_eq!(held.as_deref(), Some(NETTY_UUID), "{project:?}");
        }
        // A coordinate whose repository has no known name.
        let odd = lock_72().replace(
            "\"version\": \"2.0.61.Final\"\n    }\n  }",
            "\"version\": \"2.0.61+b\"\n    }\n  }",
        );
        let dir = checkout(&[("maven_install.json", &odd)]);
        let said = site(
            dir.path(),
            None,
            &jar("netty-tcnative-classes", "2.0.61+b"),
            false,
        );
        let Some(Err((code, why))) = said.values().next().map(|verdict| &verdict.entry) else {
            panic!("{said:?}");
        };
        assert_eq!(code, ARTIFACT);
        assert!(
            why.contains("only for coordinates of letters, digits, `.`, `_` and `-`"),
            "{why}"
        );
    }

    /// The label of a hub's `use_extension` is copied into a string of the
    /// block, so only one that holds nothing a string would have to
    /// escape is taken, whatever the reader takes for the extension.
    #[test]
    fn a_label_is_copied_only_where_it_can_stand_in_a_string() {
        let label = |written: &str| {
            let module = format!("maven = use_extension({written}, \"maven\")\nmaven.install()\n");
            let files = [("MODULE.bazel", module.as_str())];
            let ws = Workspace::read(&view(&files));
            let (file, read) = &ws.files[0];
            let install = |call: &&Call| call.callee == "maven.install";
            let call = read.calls.iter().find(install).expect("the tag");
            let tag = Tag {
                file,
                call,
                dev_dependency: Some(false),
            };
            proxy(&ws, &tag)
        };
        for plain in [
            "@rje//:extensions.bzl",
            "@@rules_jvm_external+//:extensions.bzl",
        ] {
            assert_eq!(label(&format!("\"{plain}\"")).as_deref(), Some(plain));
        }
        for odd in [
            "\"@r je//:extensions.bzl\"",
            "\"@rje//:ext$(x).bzl\"",
            "\"@rje//:ext'.bzl\"",
            "\"@rje//:ext\\\".bzl\"",
            "\"@rje//:ext\u{e9}.bzl\"",
            "LABEL",
            "\"@rje//:extensions.bzl\", isolate = True",
        ] {
            assert_eq!(label(odd), None, "{odd}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_module_file_that_is_a_link_is_not_written_through() {
        let dir = checkout(&[]);
        let module = dir.path().join("MODULE.bazel");
        std::fs::rename(&module, dir.path().join("real.MODULE.bazel")).unwrap();
        std::os::unix::fs::symlink("real.MODULE.bazel", &module).unwrap();
        let said = verdict(dir.path());
        let why = "MODULE.bazel is a symbolic link, which socket-patch does not write through";
        assert_eq!(said, format!("{UNREADABLE}: {why}"));
    }

    /// The grant of [`netty`], as a hosted run has it.
    fn granted() -> DepOverride {
        let patch = netty();
        let index = patch.url.split_once("/io/netty/").expect("a path").0;
        serde_json::from_value(serde_json::json!({
            "ecosystem": "maven",
            "name": patch.artifact,
            "namespace": patch.group,
            "version": patch.version,
            "token": "token",
            "patchUuid": patch.uuid,
            "artifactUrl": "https://patch.socket.dev/patch/maven/token/x.jar",
            "integrity": { "sha256": patch.sha256 },
            "registryOverride": { "kind": "maven2", "indexUrl": index, "identifiers": {
                "name": "io.netty/netty-tcnative-classes",
                "version": patch.version,
                "mavenGroupId": patch.group,
                "mavenArtifactId": patch.artifact,
                "mavenSuffixedVersion": "2.0.61.Final-socket.0e77a000",
            } },
        }))
        .expect("a grant")
    }

    /// The candidate files of a run: `module`, the project's own
    /// `MODULE.bazel` when it has one, and a site whose verdict for the
    /// patch [`NETTY_UUID`] is `entry`, beside a block that holds the
    /// entry of the patch `held` for its jar.
    fn candidates(
        module: Option<&str>,
        entry: Result<&str, (&str, &str)>,
        held: Option<&str>,
    ) -> BTreeMap<String, String> {
        let verdict = Verdict {
            entry: entry
                .map(String::from)
                .map_err(|(code, why)| (code.to_string(), why.to_string())),
            held: held.map(String::from),
        };
        let site = Site::from([(NETTY_UUID.to_string(), verdict)]);
        let site = (SITE_KEY, serde_json::to_string(&site).unwrap());
        let files = module.map(|module| (FILE, module.to_string()));
        let files = files.into_iter().chain([site]);
        files.map(|(path, text)| (path.to_string(), text)).collect()
    }

    /// What the lane does for `deps` with the candidate files `files`.
    fn ran(files: &BTreeMap<String, String>, deps: &[DepOverride]) -> RewriteResult {
        let mut result = RewriteResult::default();
        rewrite(files, deps, &mut result);
        result
    }

    /// The patch ids the lane confirmed.
    fn confirmed(result: &RewriteResult) -> Vec<&str> {
        let confirmed = result.confirmed_bazel_maven_uuids.iter();
        confirmed.map(String::as_str).collect()
    }

    #[test]
    fn the_lane_writes_the_entry_or_says_why_not() {
        let write = Ok(LABEL);
        let ours = with_patch(PINNED, LABEL, netty()).expect("a block");
        // The entry is written, and the patch is confirmed.
        let result = ran(&candidates(Some(PINNED), write, None), &[granted()]);
        assert_eq!(
            result.files,
            BTreeMap::from([(FILE.to_string(), ours.clone())])
        );
        assert_eq!(
            (&result.warnings, confirmed(&result)),
            (&vec![], vec![NETTY_UUID])
        );
        // Already there: confirmed, and nothing to write.
        let files = candidates(Some(&ours), write, Some(NETTY_UUID));
        let again = ran(&files, &[granted()]);
        assert_eq!(
            (again.files.len(), confirmed(&again)),
            (0, vec![NETTY_UUID])
        );
        // A patch that lacks what an entry holds.
        for broken in ["mavenSuffixedVersion", "sha256", "url"] {
            let mut dep = granted();
            let ov = dep.registry_override.as_mut().unwrap();
            match broken {
                "mavenSuffixedVersion" => ov.identifiers.maven_suffixed_version = None,
                "sha256" => dep.integrity.sha256 = Some("sha256-AAAA".to_string()),
                _ => ov.index_url = "https://patch.socket.dev/a\"b".to_string(),
            }
            let result = ran(&candidates(Some(PINNED), write, None), &[dep]);
            let codes: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
            assert_eq!((result.files.len(), codes), (0, vec![ARTIFACT]), "{broken}");
            assert_eq!(confirmed(&result), [""; 0], "{broken}");
            let detail = &result.warnings[0].detail;
            assert!(
                detail.starts_with(NETTY_PURL) && detail.ends_with(KEEPS),
                "{detail}"
            );
        }
        // A run without a site is not touched at all.
        let mut files = candidates(Some(PINNED), write, None);
        files.remove(SITE_KEY);
        assert!(ran(&files, &[granted()]) == RewriteResult::default());
    }

    /// A lock names the plain jar by group and artifact alone, and the
    /// site has a verdict for its patch alone. Another patch of the same
    /// coordinates in the run, as that of a jar with a classifier is, gets
    /// no entry, takes no entry and is not confirmed, whichever comes
    /// first.
    #[test]
    fn a_patch_that_is_not_of_the_plain_jar_gets_nothing_of_the_hub() {
        let ours = with_patch(PINNED, LABEL, netty()).expect("a block");
        let mut variant = granted();
        variant.patch_uuid = OTHER_UUID.to_string();
        variant.integrity.sha256 = Some("6".repeat(64));
        let files = candidates(Some(PINNED), Ok(LABEL), None);
        for deps in [[granted(), variant.clone()], [variant.clone(), granted()]] {
            let result = ran(&files, &deps);
            assert_eq!(result.files.get(FILE), Some(&ours));
            assert_eq!(
                (&result.warnings, confirmed(&result)),
                (&vec![], vec![NETTY_UUID])
            );
        }
        assert!(ran(&files, &[variant.clone()]) == RewriteResult::default());
        // The jars of a run: by the purl of each patch, not its grant.
        let purl = |qualifiers: &str| format!("{NETTY_PURL}{qualifiers}");
        let plain = [purl(""), purl("?type=jar"), purl("?type=pom")];
        let variants = [purl("?classifier=tests"), purl("?type=test-jar")];
        let patches = plain
            .iter()
            .chain(&variants)
            .map(|purl| (purl.as_str(), &variant));
        let jar = [
            OTHER_UUID,
            "io.netty",
            "netty-tcnative-classes",
            "2.0.61.Final",
        ];
        let jar: Jar = jar.map(String::from).into();
        assert_eq!(jars(patches), vec![jar; 3]);
        let mut npm = granted();
        npm.ecosystem = "npm".to_string();
        assert_eq!(jars([(NETTY_PURL, &npm)].into_iter()), []);
    }

    /// A decline is the warning of the site, and it ends with what the
    /// block holds for the jar: nothing; the entry of this patch from an
    /// earlier run, which stays its pin; or the entry of another patch,
    /// which is not this run's to take out. Below the Bazel root the
    /// project has no `MODULE.bazel` of its own, and the file is named as
    /// the root's.
    #[test]
    fn a_decline_says_what_the_block_holds_for_the_jar() {
        let ours = with_patch(PINNED, LABEL, netty()).expect("a block");
        let remains = |file: &str| {
            format!(
                "socket-patch wrote nothing to {file} for it: the entry of patch {OTHER_UUID} \
                 remains there, and where the block is in effect the Bazel build takes that \
                 patch's jar"
            )
        };
        let left =
            |file: &str| format!("socket-patch left the entry that {file} holds for it as it is");
        let (root, own) = ("the MODULE.bazel at the root", [NETTY_UUID]);
        for (module, held, pinned, ends) in [
            (Some(PINNED), None, &own[..0], KEEPS.to_string()),
            (
                Some(&*ours),
                Some(NETTY_UUID),
                &own[..],
                left("MODULE.bazel"),
            ),
            (
                Some(&*ours),
                Some(OTHER_UUID),
                &own[..0],
                remains("MODULE.bazel"),
            ),
            (None, None, &own[..0], KEEPS.to_string()),
            (None, Some(NETTY_UUID), &own[..], left(root)),
            (None, Some(OTHER_UUID), &own[..0], remains(root)),
        ] {
            let files = candidates(module, Err((RELEASE, "why")), held);
            let result = ran(&files, &[granted()]);
            let warning = RewriteWarning {
                code: RELEASE.into(),
                detail: format!("{NETTY_PURL}: why. {ends}"),
            };
            assert_eq!(result.warnings, [warning]);
            assert_eq!(
                (result.files.len(), confirmed(&result)),
                (0, pinned.to_vec())
            );
        }
        // A vendored entry of the same patch is not the hosted run's pin:
        // the run wrote nothing, and the patch is not confirmed as hosted.
        let vendored = with_patch(PINNED, LABEL, vendored_netty()).expect("a block");
        let files = candidates(Some(&vendored), Err((RELEASE, "why")), Some(NETTY_UUID));
        let result = ran(&files, &[granted()]);
        assert_eq!(result.warnings.len(), 1, "{:?}", result.warnings);
        assert_eq!((result.files.len(), confirmed(&result)), (0, vec![]));
        // An entry that the reason of the decline leaves without effect (an
        // rc file that switches the block off, an override of the jar) is
        // not this patch's pin: the build takes the upstream jar, and the
        // patch is not confirmed for it.
        for (module, file) in [(Some(&*ours), "MODULE.bazel"), (None, root)] {
            let files = candidates(module, Err((NO_EFFECT, "why")), Some(NETTY_UUID));
            let result = ran(&files, &[granted()]);
            let detail = format!(
                "{NETTY_PURL}: why. socket-patch left the entry that {file} holds for it as it \
                 is, and while that stands the entry has no effect: the Bazel build keeps the \
                 upstream jar"
            );
            let code = NO_EFFECT.into();
            assert_eq!(result.warnings, [RewriteWarning { code, detail }]);
            assert_eq!((result.files.len(), confirmed(&result)), (0, vec![]));
        }
        // And so does a patch that lacks what an entry holds.
        let mut dep = granted();
        dep.integrity.sha256 = None;
        let files = candidates(Some(&ours), Ok(LABEL), Some(OTHER_UUID));
        let result = ran(&files, &[dep]);
        assert_eq!(result.warnings.len(), 1, "{result:?}");
        assert!(result.warnings[0]
            .detail
            .ends_with(&remains("MODULE.bazel")));
    }

    /// The pom lane says "no pom.xml" of a Maven patch in a tree without
    /// one, and not of a patch that a hub decides: the lane of the hubs
    /// writes its entry or says why not.
    #[test]
    fn no_pom_is_said_only_of_a_patch_that_no_hub_decides() {
        let codes = |files: &BTreeMap<String, String>, deps: &[DepOverride]| {
            let result = crate::patch::redirect::rewrite_registry_redirect(files, deps);
            let codes = result.warnings.into_iter().map(|warning| warning.code);
            codes.collect::<Vec<_>>()
        };
        let mut other = granted();
        other.patch_uuid = OTHER_UUID.to_string();
        let no_pom = "redirect_maven_no_pom";
        let written = candidates(Some(PINNED), Ok(LABEL), None);
        let declined = candidates(Some(PINNED), Err((RELEASE, "why")), None);
        assert_eq!(codes(&written, &[granted()]), [""; 0]);
        assert_eq!(codes(&declined, &[granted()]), [RELEASE]);
        for deps in [[granted(), other.clone()], [other.clone(), granted()]] {
            assert_eq!(codes(&written, &deps), [no_pom]);
        }
        let mut plain = written.clone();
        plain.remove(SITE_KEY);
        assert_eq!(codes(&plain, &[granted()]), [no_pom]);
    }

    /// What discovery reads of the block: a patch whose jar a pinned hub
    /// still fetches is built, and any other is said not to be.
    #[test]
    fn a_pin_is_built_while_a_pinned_hub_fetches_its_jar() {
        let ours = with_patch(PINNED, LABEL, netty()).expect("a block");
        let unbuilt = |files: &[(&str, &str)], module: &str| {
            let read = pins(checkout(files).path(), module).expect("the block");
            assert_eq!(read.len(), 1, "{read:?}");
            assert_eq!(read[0].patch, netty());
            read.into_iter().next().and_then(|pin| pin.unbuilt)
        };
        assert_eq!(unbuilt(&[], &ours), None);
        // Whatever names the Bazel or the ruleset: a wrong one fails the
        // build, and none builds the upstream jar.
        assert_eq!(unbuilt(&[("MODULE.bazel.lock", "")], &ours), None);
        assert_eq!(
            unbuilt(&[(".bazelrc", "build --vendor_dir=v\n")], &ours),
            None
        );
        let moved = unbuilt(&[("maven_install.json", LOCK_SKIPS)], &ours);
        let why = "no pinned hub takes io.netty:netty-tcnative-classes at 2.0.61.Final any more, \
                   so Bazel stops at its entry";
        assert_eq!(moved.as_deref(), Some(why));
        let off = unbuilt(&[(".bazelrc", "common --ignore_dev_dependency\n")], &ours);
        assert!(off.is_some_and(|why| why.starts_with(".bazelrc:1 names")));
        // Every line is read: an option that leaves the entry in effect
        // does not hide one below it that switches it off. And an rc file
        // that cannot be read, or a line of one, may switch it off.
        for (files, why) in [
            (
                [
                    (
                        ".bazelrc",
                        "build --vendor_dir=v\ncommon --noenable_bzlmod\n",
                    ),
                    ("", ""),
                ],
                ".bazelrc:2 names `--noenable_bzlmod`, which switches off the file an entry is \
                 written to",
            ),
            (
                [
                    (".bazelrc", "import %workspace%/ci.bazelrc\n"),
                    ("ci.bazelrc/a", ""),
                ],
                "the rc file ci.bazelrc cannot be read, and may switch an entry off",
            ),
            (
                [
                    (".bazelrc", "build --jobs=4\ncommon \"--enable_bzlmod\n"),
                    ("", ""),
                ],
                "the rc file .bazelrc:2 cannot be read, and may switch an entry off",
            ),
        ] {
            let files: Vec<_> = files
                .into_iter()
                .filter(|file| !file.0.is_empty())
                .collect();
            assert_eq!(unbuilt(&files, &ours).as_deref(), Some(why));
        }
        let unread = unbuilt(&[("maven_install.json", "")], &ours);
        assert!(unread.is_some_and(|why| why.contains("could not tell")));
        let over = ours.replace(
            "use_repo(maven, \"maven\")\n",
            "use_repo(maven, \"maven\")\nmaven.override(coordinates = \
             \"io.netty:netty-tcnative-classes\", target = \"//:own\")\n",
        );
        assert!(unbuilt(&[], &over).is_some_and(|why| why.contains("maven.override")));
        // A block that was changed by hand is no record of a patch.
        let edited = ours.replace("# Do", "# do");
        let said = pins(checkout(&[]).path(), &edited);
        let line = PINNED.lines().count() + 2;
        let why = format!(
            "MODULE.bazel:{line}: the block that socket-patch keeps there was changed by hand"
        );
        assert_eq!(said, Err(why));
        assert_eq!(pins(checkout(&[]).path(), PINNED), Ok(vec![]));
    }

    /// [`netty`] as vendored mode keeps it: no host, and a directory.
    fn vendored_netty() -> Patch {
        Patch {
            sha256: String::new(),
            url: String::new(),
            ..netty()
        }
    }

    /// The entry of [`vendored_netty`], between the proxy of the block and
    /// its `override_repo`, which are those of [`BLOCK`].
    const VENDORED_ENTRY: &str = r#"socket_patch_local_repository(
    name = "socket_patch_io_netty_netty_tcnative_classes_2_0_61_Final",
    path = ".socket/vendor/maven/0e77a000-0000-4000-8000-0000000000a1",
)
"#;

    /// The entry of vendored mode names the directory of the patch, under
    /// a rule of its own, and nothing of a host. A block holds an entry of
    /// either mode for a jar, never both, and binds the rule of each mode
    /// it has an entry of, hosted first.
    #[test]
    fn a_vendored_entry_names_the_directory_of_its_patch() {
        let local = "socket_patch_local_repository = use_repo_rule(\
                     \"@bazel_tools//tools/build_defs/repo:local.bzl\", \"local_repository\")\n";
        let (http, hosted) = {
            let from = BLOCK.find("socket_patch_http_file(").expect("the entry");
            let to = BLOCK.find("\n# If Bazel stops").expect("its end");
            let rule = BLOCK.lines().nth(1).expect("the rule");
            (format!("{rule}\n"), &BLOCK[from..to])
        };
        let block = BLOCK.replace(&http, local).replace(hosted, VENDORED_ENTRY);
        assert_eq!(render(LABEL, &[vendored_netty()]), block);
        assert_eq!(
            parse(&block),
            Some((LABEL.to_string(), vec![vendored_netty()]))
        );
        let ours = vendored_netty();
        let unit = ".socket/vendor/maven/0e77a000-0000-4000-8000-0000000000a1";
        let jar = format!("{unit}/file/netty-tcnative-classes-2.0.61.Final.jar");
        assert_eq!(
            (ours.unit(), ours.jar()),
            (Some(unit.to_string()), Some(jar.clone()))
        );
        assert_eq!((netty().unit(), netty().jar()), (None, None));
        // Its directory: the jar, the two files that make it a repository
        // with the target a hub takes the jar by, and what keeps the jar
        // in a commit.
        let files = unit_files(&ours, b"jar".to_vec()).expect("a vendored entry");
        let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
        let named = ["REPO.bazel", "file/BUILD.bazel", "", ".gitignore"].map(|file| match file {
            "" => jar.clone(),
            file => format!("{unit}/{file}"),
        });
        assert_eq!(names, named);
        let text = |at: usize| String::from_utf8(files[at].1.clone()).expect("text");
        assert!(
            text(0).lines().all(|line| line.starts_with("# ")),
            "{}",
            text(0)
        );
        let build = "filegroup(\n    name = \"file\",\n    srcs = \
                     [\"netty-tcnative-classes-2.0.61.Final.jar\"],\n    visibility = \
                     [\"//visibility:public\"],\n)\n";
        assert_eq!(
            (text(1), text(2), text(3)),
            (build.into(), "jar".into(), "!*\n".into())
        );
        assert_eq!(unit_files(&netty(), Vec::new()), None);

        // One entry per jar: the other mode's takes its place, and with
        // the last entry the file is the one of before, to the byte.
        for module in modules() {
            let vendored = with_patch(&module, LABEL, vendored_netty()).expect("a block");
            let hosted = with_patch(&module, LABEL, netty()).expect("a block");
            assert_eq!(
                with_patch(&hosted, LABEL, vendored_netty()).as_ref(),
                Some(&vendored)
            );
            assert_eq!(
                with_patch(&vendored, LABEL, netty()).as_ref(),
                Some(&hosted)
            );
            assert_eq!(entries(&vendored), [vendored_netty()], "{module:?}");
            let out = without(&vendored, &mut |_| true);
            assert_eq!(out.as_deref(), Some(module.as_str()), "{module:?}");
        }
        // Beside the hosted entry of another jar: both rules, hosted first.
        let other = patch("netty-tcnative-boringssl-static", OTHER_UUID);
        let both = render(LABEL, &[vendored_netty(), other.clone()]);
        let rules: Vec<&str> = both
            .lines()
            .filter(|line| line.contains("use_repo_rule("))
            .collect();
        assert_eq!(rules, [http.trim_end(), local.trim_end()], "{both}");
        assert_eq!(
            parse(&both),
            Some((LABEL.to_string(), vec![other, vendored_netty()]))
        );
        // A block that names another directory for the patch is not the
        // one socket-patch writes.
        let moved = with_patch(PINNED, LABEL, vendored_netty()).expect("a block");
        let moved = moved.replace("0000000000a1\",", "0000000000b2\",");
        assert!(matches!(find(&moved), Block::Edited(_)), "{moved}");
        assert_eq!(entries(&moved), []);
    }

    /// What vendored mode writes for a patch is decided as for hosted
    /// mode, with one difference: its jar is in the checkout, so an option
    /// about downloads does not stand against it.
    #[test]
    fn a_vendored_entry_is_declined_as_a_hosted_one_but_for_downloads() {
        let verdict = |dir: &Path, vendored: bool| {
            let verdict = site(dir, None, &netty_jar(), vendored).remove(NETTY_UUID);
            match verdict.expect("a hub builds the jar").entry {
                Ok(label) => format!("write {label}"),
                Err((code, _)) => code,
            }
        };
        let write = format!("write {LABEL}");
        for (rc, hosted, vendored) in [
            ("", write.as_str(), write.as_str()),
            (
                "common --experimental_downloader_config=mirror.cfg\n",
                DOWNLOAD,
                &write,
            ),
            ("build --repository_disable_download\n", DOWNLOAD, &write),
            ("common --vendor_dir=third_party\n", DOWNLOAD, &write),
            ("common --ignore_dev_dependency\n", NO_EFFECT, NO_EFFECT),
            (
                "common --vendor_dir=v\ncommon --noenable_bzlmod\n",
                DOWNLOAD,
                NO_EFFECT,
            ),
        ] {
            let dir = checkout(&[(".bazelrc", rc)]);
            let said = (verdict(dir.path(), false), verdict(dir.path(), true));
            assert_eq!(said, (hosted.to_string(), vendored.to_string()), "{rc:?}");
        }

        // The one patch of a vendored run: the label and the entry, or the
        // decline with what the block holds for the jar.
        let dir = checkout(&[]);
        let read = |dir: &Path, purl: &str| super::vendored(dir, purl, NETTY_UUID);
        assert_eq!(
            read(dir.path(), NETTY_PURL),
            Some(Ok((LABEL.to_string(), vendored_netty())))
        );
        let no_bazel = checkout(&[(".bazelrc", "common --ignore_dev_dependency\n")]);
        let (code, why) = read(no_bazel.path(), NETTY_PURL)
            .expect("a hub")
            .expect_err("off");
        assert_eq!(code, NO_EFFECT);
        assert!(
            why.starts_with(".bazelrc:1 names") && why.ends_with(KEEPS),
            "{why}"
        );
        // Beside the entry of this patch, which stays, and of another.
        for (uuid, ends) in [
            (
                NETTY_UUID,
                "has no effect: the Bazel build keeps the upstream jar",
            ),
            (OTHER_UUID, "the Bazel build takes that patch's jar"),
        ] {
            let held = patch("netty-tcnative-classes", uuid);
            let module = with_patch(PINNED, LABEL, held).expect("a block");
            std::fs::write(no_bazel.path().join(FILE), module).unwrap();
            let (_, why) = read(no_bazel.path(), NETTY_PURL)
                .expect("a hub")
                .expect_err("off");
            assert!(why.ends_with(ends), "{why}");
        }
        // A jar no hub builds, a jar with a classifier, and a project in
        // no Bazel workspace: nothing of the hub lane.
        let other = "pkg:maven/io.netty/netty-all@4.1.0";
        let classified = format!("{NETTY_PURL}?classifier=linux-x86_64");
        assert_eq!(read(dir.path(), other), None);
        assert_eq!(read(dir.path(), &classified), None);
        assert_eq!(read(project(&[]).path(), NETTY_PURL), None);
    }

    /// A vendored run is warned of the jars a hub builds that it wrote no
    /// entry for: with the reason, under the code a hosted run gives, or
    /// that nothing was vendored for a jar it could have patched. Nothing
    /// is said of a jar whose entry the block holds.
    #[test]
    fn a_vendored_run_is_warned_of_the_jars_it_wrote_no_entry_for() {
        let said = |dir: &Path| super::notices_blocking(dir, vec![NETTY_PURL.to_string()], true);
        let dir = checkout(&[]);
        let nothing = format!(
            "{NETTY_PURL}: a rules_jvm_external hub of the Bazel workspace builds this artifact \
             from its lock, and this run vendored nothing for it. {KEEPS}"
        );
        assert_eq!(said(dir.path()), [(HUB_UNPATCHED, nothing)]);
        let declined = checkout(&[(".bazelrc", "common --ignore_dev_dependency\n")]);
        let warned = said(declined.path());
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert_eq!(warned[0].0, NO_EFFECT);
        assert!(warned[0].1.ends_with(KEEPS), "{warned:?}");
        for held in [vendored_netty(), netty()] {
            let module = with_patch(PINNED, LABEL, held).expect("a block");
            std::fs::write(dir.path().join(FILE), &module).unwrap();
            assert_eq!(said(dir.path()), []);
            // The same entry in a checkout whose rc file switches the block
            // off: the build takes the upstream jar past it, and the run
            // says so although the entry is there.
            std::fs::write(declined.path().join(FILE), module).unwrap();
            let warned = said(declined.path());
            assert_eq!(warned.len(), 1, "{warned:?}");
            assert_eq!(warned[0].0, NO_EFFECT);
            let ends = "left the entry that MODULE.bazel holds for it as it is, and while that \
                        stands the entry has no effect: the Bazel build keeps the upstream jar";
            assert!(warned[0].1.ends_with(ends), "{warned:?}");
        }
        assert_eq!(said(project(&[]).path()), []);
    }

    /// A jar that the block patches is not said to be unpatched.
    #[test]
    fn no_notice_for_a_jar_whose_entry_is_in_the_block() {
        let lock = lock_72();
        let ours = with_patch(PINNED, LABEL, netty()).expect("a block");
        let dir = project(&[("MODULE.bazel", &ours), ("maven_install.json", &lock)]);
        let other = "pkg:maven/io.netty/netty-tcnative-boringssl-static@2.0.61.Final";
        let said = notices_blocking(dir.path(), vec![NETTY_PURL.to_string(), other.to_string()]);
        assert_eq!(said.len(), 1, "{said:?}");
        assert!(
            said[0].0 == HUB_UNPATCHED && said[0].1.starts_with(other),
            "{said:?}"
        );
    }
}
