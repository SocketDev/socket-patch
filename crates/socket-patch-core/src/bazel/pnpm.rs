//! Whether the pnpm that Bazel runs for a rules_js hub reads the setting
//! that hosted mode pins a pnpm lock with.
//!
//! `npm.npm_translate_lock(update_pnpm_lock = True)` has aspect_rules_js
//! run a pnpm of its own during the build, whenever the lock or a
//! `package.json` differs from the hashes it keeps under `.aspect/`:
//! `pnpm install --lockfile-only`, in a directory that holds the lock, the
//! `package.json` of each importer and the files the call lists as `data`,
//! and nothing else of the checkout (3.6.0,
//! `npm/private/npm_translate_lock_state.bzl`). Hosted mode names the
//! patch server in the lock and writes `trustLockfile: true` to the
//! `pnpm-workspace.yaml` beside it, without which pnpm 11 and later reject
//! such a lock. A hub that does not list that file hides the setting from
//! its pnpm, and the build fails with `ERR_PNPM_TARBALL_URL_MISMATCH`
//! (Bazel 9.3.2, rules_js 3.6.0, pnpm 11.28.10). pnpm 10 has no such check
//! and builds the pinned lock, and so does pnpm 11 once the file is listed.
//!
//! [`hubs`] finds such a hub for a project ([`Hubs::hidden`]), and hosted
//! mode then writes nothing for the project's root pnpm lock. One call of the tag must name
//! the project's `pnpm-lock.yaml` in a plain string and, as far as it is
//! written out, keep it up to date, not list the `pnpm-workspace.yaml`
//! beside it, and run a pnpm that may be 11 or later.
//!
//! Told not to write to that file (`--no-trust-lockfile-config`), hosted
//! mode writes no setting for such a pnpm to read, so a hub that lists the
//! file gets nothing either unless the file holds `trustLockfile: true`
//! already ([`Hubs::unset`]). That answer is about a pin: a scan that
//! crawls nothing adds none, and takes out what a route left as it does
//! without Bazel.
//!
//! The same read says whether a lock may be routed through the named
//! registries of `pnpm-workspace.yaml` in place of that setting
//! ([`Hubs::reader`]): only where every call that reads it is written out
//! in a shape whose build takes a routed lock ([`Reader`]).
//!
//! A hub that lists the file is passed over only where the pin would be
//! one the build takes and an undo leaves standing. It is not where hosted
//! mode does not write the setting to the file (the file sets
//! `trustLockfile` to something else, or is YAML that a line cannot be
//! added to: the hub's pnpm would reject the lock all the same), and not
//! where the file would hold only what hosted mode writes (none, an empty
//! one, one with the root-only `packages` alone): `rollback` removes such
//! a file with the pin, and a call that names a missing file fails the
//! build.
//!
//! The pnpm of a call is the repository its `use_pnpm` names, `@pnpm`
//! without one. A `pnpm.pnpm` tag of that `name` in the root module makes
//! it, from its `pnpm_version` or from the `packageManager` of the
//! `package.json` that its `pnpm_version_from` names, and of several the
//! newest (`npm/private/pnpm_extension.bzl` at 3.6.0; 2.9.3 has both
//! attributes, 2.0.0 the first). Where no tag states a release, rules_js
//! runs one of its own choice: its newest pnpm 10 at 3.x and 4.0.0-alpha.1,
//! its newest pnpm 8 at 2.x. Neither rejects the lock, so nothing is
//! withheld for a release of the ruleset whose choice was read
//! ([`picks_an_older_pnpm`]); for any other the choice is not known and
//! counts as a pnpm that may be 11 or later. A pnpm release that another
//! module of the build asks for is not seen.
//!
//! A `use_pnpm` is a label of the root module, so its repository is one
//! the root module has a name for. It is followed to a tag only where a
//! `use_repo` takes the repository by position, under the name the
//! extension made it with, and, unless that name is `pnpm`, a tag makes
//! it. A `use_repo` that gives the name to another repository
//! (`eleven = "pnpm"`), and a repository of another extension or of a
//! repository rule, can be any pnpm (the first measured: Bazel 9.3.2 runs
//! the pnpm 11 of the tag `pnpm` under the name `eleven`).
//!
//! The route asks for more than the pin does, because a release that is
//! taken for 11.20 or later and is not the one the hub runs loses the
//! patch or fails the build: the repository has to be one of the use of
//! the pnpm extension that every module shares ([`Pnpm::Stated`]). A
//! `use_repo` on another extension's proxy can take a repository of the
//! same name as a tag, a use with `isolate` has tags and repositories of
//! its own, and an `inject_repo` on the extension is not read: each keeps
//! the hub off the route and changes nothing for the pin. Only a `use_repo`
//! on a name of the extension's proxy is followed for it. And the release
//! has to be the hub's in every build: a use of the extension with
//! `dev_dependency` is one whose tags Bazel drops under
//! `--ignore_dev_dependency` (`ModuleFileGlobals.useExtension` at 7.7.2,
//! 8.8.2 and 9.3.2), and the hub then runs the pnpm that rules_js picks.
//! So a release that such a use states does not count for the route. Nor
//! does one whose tag Bazel may not run as it is written: a tag that is
//! no statement of its own (behind a condition, in a comprehension) may
//! not run, and one whose `name` is not written out in a plain string may
//! make another repository. The `use_repo` that takes the repository and
//! the call of the hub itself have to be statements of their own as well.
//! The pin reads each of these as it is written, as it did, and builds
//! either way: its setting is in the file the hub lists, for whichever
//! pnpm asks for it.
//!
//! In memory the workspace is the project's own files: path selection
//! asks for the `MODULE.bazel` beside a `pnpm-lock.yaml` or a
//! `pnpm-workspace.yaml`, for the files one can include and for the
//! `WORKSPACE` files, and the answer is the one of a checkout with the
//! same files. A Bazel root above the project is not seen there, for
//! either answer of this module: a project in a directory of a Bazel
//! workspace is pinned, and routed, in memory as if it were in none. A
//! `pnpm_version_from` file that was not handed in (one outside the
//! project's own manifests) and `MODULE.bazel.lock` are not there either:
//! the first reads as a release that is not written out, so a lock that a
//! checkout pins can be left as it is in memory, and one that a checkout
//! routes can be pinned there.
//!
//! What is not written out counts against writing, because a broken build
//! outranks a missed patch that a warning explains: an `update_pnpm_lock`
//! that is not the name `False`, a `data` that is not a list of strings,
//! an attribute a `**` may pass, a release that is no version (`latest`, a
//! name, a `package.json` that cannot be read), a `use_pnpm` that is not
//! followed or a use of the pnpm extension that cannot be, and a call that
//! is not a statement of its own. What the reader may not have seen at all
//! ([`Workspace::doubts`], a `WORKSPACE` file) withholds nothing: a
//! project whose lock no listed call names is left as it is.

use std::cell::OnceCell;

use super::rc::ModuleLock;
use super::starlark::{Arg, Call, File, How, Value};
use super::workspace::{disk, memory, Doubt, Entry, Extension, Label, Repo, Tag, Tags, Workspace};
use crate::formats::text::strip_bom;
use crate::hosted::guidance::{is_trust_scaffold, plan_workspace_trust, TrustPlan};
use crate::patch::redirect::RewriteWarning;
use crate::utils::fs::run_blocking;
use crate::utils::package_manager::pinned_version;
use crate::vendor::lock_inventory::ProjectView;

/// The code of the warning with which hosted mode leaves a pnpm lock as it
/// is because of such a hub.
pub const HIDDEN: &str = "redirect_pnpm_bazel_workspace_hidden";

const LOCK: &str = "pnpm-lock.yaml";
const SETTINGS: &str = "pnpm-workspace.yaml";

/// An extension of `@aspect_rules_js//npm:extensions.bzl`.
fn extension(name: &'static str) -> Extension<'static> {
    Extension {
        module: "aspect_rules_js",
        file: "//npm:extensions.bzl",
        name,
    }
}

/// What the Bazel workspace of a project says of its pnpm locks: both
/// answers of this module, from one read of the workspace ([`hubs`]).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Hubs {
    /// The warning ([`HIDDEN`]) when a hub hides the project's
    /// `pnpm-workspace.yaml` from a pnpm that may be 11 or later (the
    /// module docs): hosted mode then writes nothing for the root pnpm
    /// lock.
    pub hidden: Option<RewriteWarning>,
    /// That warning for a run that is told not to write to
    /// `pnpm-workspace.yaml` (`--no-trust-lockfile-config`), where
    /// [`Self::hidden`] is none: the hub lists the file, its pnpm may be
    /// 11 or later, and the file does not hold `trustLockfile: true`,
    /// which this run would not write. The pin would be one that the pnpm
    /// of the build rejects, so such a run writes nothing for the root
    /// lock either ([`Self::hides`]).
    pub unset: Option<RewriteWarning>,
    /// The hub that reads one of the project's pnpm locks ([`Reader`]):
    /// hosted mode then routes them through named registries only where
    /// the build of every such hub takes a routed lock.
    pub reader: Option<Reader>,
}

impl Hubs {
    /// The warning with which a run leaves the root lock as it is: one
    /// that writes its setting to `pnpm-workspace.yaml` (`writes`), or one
    /// that is told not to.
    pub fn hides(&self, writes: bool) -> Option<&RewriteWarning> {
        let unset = self.unset.as_ref().filter(|_| !writes);
        self.hidden.as_ref().or(unset)
    }
}

/// A rules_js hub that reads a pnpm lock of the project.
///
/// Hosted mode asks before it routes a patched release through a named
/// registry of pnpm-workspace.yaml. It does where the build of every hub
/// that reads a lock takes a routed lock ([`Self::Takes`]), and keeps the
/// project on the pin with `trustLockfile` everywhere else, where the
/// warning says what kept the hub off the route.
///
/// Two shapes of a call take one, for a project at the root of the Bazel
/// workspace whose root lock is its one pnpm lock, which the call names in
/// a plain string, and which is a statement of its own that passes
/// nothing but the attributes those calls had ([`BUILT`]) (measured on
/// Bazel 9.3.2, 8.8.2 and 7.7.2 with rules_js 3.6.0: the build holds the
/// patched bytes, a second build changes no file, and `rollback` brings
/// the upstream build back):
///
/// - No `update_pnpm_lock`, or `False`: no pnpm runs, and the lock reader
///   of rules_js builds a routed lock.
/// - `update_pnpm_lock = True`, a `data` that lists the pnpm-workspace.yaml
///   beside the lock, and a pnpm that the root module states as a release
///   of 11.20.0 or later, in a repository of the use of the pnpm extension
///   that every module shares, by no use that is a dev dependency and in
///   tags that Bazel runs as they are written ([`release`]). That pnpm
///   runs in a directory that holds the lock, the `package.json` files and
///   the `data` of the call, reads the registries there, and writes the
///   lock back as it is. Without the file it fails the build
///   (`ERR_PNPM_MISSING_NAMED_REGISTRY`). A pnpm below 11.20 builds the
///   routed lock as long as it does not resolve again; once a
///   `package.json` asks for another package, pnpm 11.19.0 puts the
///   upstream release back and pnpm 10.34.9 fails the build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reader {
    /// The call (`MODULE.bazel:7`) that names one of the locks in a plain
    /// string, or whose `pnpm_lock` is not written out as one, which may.
    /// With what keeps it off the route, as a clause of the warning. For
    /// a project below the Bazel root the text says that its paths are
    /// from that root, here and in [`Self::Unseen`], as the warning of
    /// [`Hubs::hidden`] does: a run in the project's directory has no file
    /// of that name beside it.
    Call(String, String),
    /// Every call that reads a lock was read, and each is in a shape whose
    /// build takes a routed lock: the first of them. The workspace file
    /// still has to stay where it is, for the `data` that may name it.
    Takes(String),
    /// No such call was read, and the workspace was not read whole: what
    /// could not be read of it, where a hub may be. A doubt of the reader
    /// ([`Workspace::doubts`], the doubts of the hub's tags) as `file:line:
    /// why`, or the file of the older `WORKSPACE` system
    /// ([`Workspace::legacy`]) where it cannot be read or brings in
    /// rules_js: the repositories it defines are in no tag.
    ///
    /// [`Hubs::hidden`] passes over what was not seen, because withholding
    /// there would take a patch from projects that are patched today. Not
    /// taking the route costs no patch: the project gets the pin it gets
    /// today. So the route is taken only where it is certain which hubs
    /// read a lock, also beside a call that takes a routed one.
    ///
    /// Certain of the files that were read, that is. On disk those are the
    /// files of the Bazel workspace the project is in. In memory they are
    /// the project's own, so a hub in a Bazel root above the project is
    /// seen by neither answer there (the module docs).
    Unseen(String),
}

/// What the Bazel workspace says of the pnpm locks of the project of
/// `view`, as hosted mode acts on it: of its root `pnpm-lock.yaml` (`root`:
/// whether the project has one that was read) and of the members' own
/// locks (`members`, paths from the project).
///
/// The one place that decides it, for every caller. A project with no
/// pnpm lock is asked nothing: no Bazel file is read for it. And
/// [`Hubs::hidden`] is about a pin in the root lock, so a project without
/// that lock has none, whatever the hub names.
pub async fn hubs(view: &ProjectView<'_>, root: bool, members: &[String]) -> Hubs {
    if !root && members.is_empty() {
        return Hubs::default();
    }
    let mut locks = vec![LOCK.to_string()];
    locks.extend(members.iter().cloned());
    let mut hubs = read(view, &locks).await;
    if !root {
        (hubs.hidden, hubs.unset) = (None, None);
    }
    hubs
}

/// What the Bazel workspace the project of `view` is in says of its pnpm
/// locks `locks` (paths from the project): on disk the workspace of
/// [`super::bazel_root`], read off the async runtime, in memory the
/// project itself, whose files are all there is. Nothing outside a Bazel
/// workspace, and nothing for a user who switched the Bazel support off:
/// on disk no root is found then, and in memory the view holds no file
/// ([`memory`]).
async fn read(view: &ProjectView<'_>, locks: &[String]) -> Hubs {
    match *view {
        ProjectView::Memory(project) => answer(&memory(project), "", locks),
        _ => {
            let Some(project) = view.disk_root().map(std::path::Path::to_path_buf) else {
                return Hubs::default();
            };
            let locks = locks.to_vec();
            run_blocking(move || {
                let Some(root) = super::bazel_root(&project) else {
                    return Hubs::default();
                };
                // Bazel has `/` between the parts of a path on every system.
                let below = root.project.to_string_lossy();
                let below = below.replace(std::path::MAIN_SEPARATOR, "/");
                let read = disk(&root.dir);
                answer(&read, &below, &locks)
            })
            .await
        }
    }
}

/// [`Hubs::hidden`] of a project with a root lock, and nothing else.
pub async fn hidden(view: &ProjectView<'_>) -> Option<RewriteWarning> {
    hubs(view, true, &[]).await.hidden
}

/// [`hubs`] for the project in the directory `project` (from the Bazel
/// root, empty for the root) of the workspace behind `view`.
fn answer(view: &dyn Fn(&str) -> Entry, project: &str, locks: &[String]) -> Hubs {
    let ws = Workspace::read(view);
    let hubs = ws.tags(&extension("npm"), "npm_translate_lock");
    // What the three answers ask for is read once, when the first of them
    // does: the pnpm-workspace.yaml beside the lock, and the pnpm of a hub.
    let beside = OnceCell::new();
    let beside = || beside.get_or_init(|| view(&below(project, SETTINGS)));
    let read: Vec<_> = hubs.calls.iter().map(|_| OnceCell::new()).collect();
    let pnpm = |at: usize| read[at].get_or_init(|| release(&ws, view, hubs.calls[at].call));
    let warning = |detail| RewriteWarning {
        code: HIDDEN.into(),
        detail,
    };
    let said = |writes| judge(&ws, &beside, project, &hubs, &pnpm, writes).map(warning);
    let hidden = said(true);
    let unset = match hidden {
        Some(_) => None,
        None => said(false),
    };
    Hubs {
        hidden,
        unset,
        reader: reader(&ws, project, locks, &hubs, &pnpm),
    }
}

/// A path of the project in the directory `project`, from the Bazel root.
fn below(project: &str, file: &str) -> String {
    match project {
        "" => file.to_string(),
        project => format!("{project}/{file}"),
    }
}

/// What a text says after the place it names, for the project in the
/// directory `project`: every path of such a text is one from the Bazel
/// root, which is not the directory of a project below it.
fn from_root(project: &str) -> &'static str {
    match project {
        "" => "",
        _ => ", with paths from the root of the Bazel workspace",
    }
}

/// The lock a call of `npm.npm_translate_lock` names.
enum Named {
    /// A file of the main repository, in a plain string.
    File(Label),
    /// Another repository's file, or no lock at all.
    Elsewhere,
    /// Not written out as a label in a plain string: it may be any lock.
    Unwritten,
}

/// The lock that the hub `call` names in `pnpm_lock`.
fn names(ws: &Workspace, call: &Call) -> Named {
    match call.arg("pnpm_lock") {
        Some(Value::Str(label)) => match ws.label(label) {
            Some(label) if label.repo == Repo::Main => Named::File(label),
            Some(_) => Named::Elsewhere,
            None => Named::Unwritten,
        },
        Some(_) => Named::Unwritten,
        None if call.unpacks() => Named::Unwritten,
        None => Named::Elsewhere,
    }
}

/// Whether the `data` of the hub `call` lists `settings`, the
/// pnpm-workspace.yaml beside its lock: `None` where it does, else whether
/// `data` is written out, so that the label is one to add to it.
fn unlisted(ws: &Workspace, call: &Call, settings: &str) -> Option<bool> {
    let main = |label: &str| ws.label(label).filter(|label| label.repo == Repo::Main);
    let listed = |label: &String| main(label).is_some_and(|label| label.path() == settings);
    match call.arg("data") {
        Some(Value::List(labels)) if labels.iter().any(listed) => None,
        Some(Value::List(_)) => Some(true),
        None => Some(!call.unpacks()),
        _ => Some(false),
    }
}

/// The attributes of the calls that were built with a routed lock
/// ([`Reader`]). Any other can change what the hub makes of the lock. A
/// routed lock has the patched release under another version
/// (`socket-<id>:1.0.0`), so a `patches` entry that is keyed by the
/// package's name and version names no package of it, and rules_js fails
/// the build on such an entry (3.6.0, `npm_translate_lock_helpers.bzl`;
/// measured on Bazel 9.3.2, 8.8.2 and 7.7.2). With `npm_package_lock`,
/// `yarn_lock` or `preupdate` a pnpm writes the lock anew, which no build
/// was run for.
const BUILT: [&str; 5] = ["name", "pnpm_lock", "data", "update_pnpm_lock", "use_pnpm"];

/// What keeps the hub `call`, which reads the lock `named`, off the route
/// through named registries, as a clause of the warning: `None` for the
/// two shapes whose build takes a routed lock ([`Reader`]). `several`: the
/// project has other pnpm locks than its root lock. `pnpm`: the pnpm the
/// hub runs ([`release`]).
fn off_route<'a>(
    ws: &Workspace,
    project: &str,
    call: &Call,
    named: &Named,
    several: bool,
    pnpm: &dyn Fn() -> &'a Pnpm,
) -> Option<String> {
    let settings = below(project, SETTINGS);
    match named {
        Named::File(lock) if lock.path() == below(project, LOCK) => {}
        Named::File(_) => return Some("the lock it reads is a workspace member's own".into()),
        _ => return Some("its `pnpm_lock` is not written out in a plain string".into()),
    }
    if !project.is_empty() {
        return Some("the project is not at the root of the Bazel workspace".into());
    }
    // The route records its overrides in every lock of the project, and
    // the pnpm of a hub resolves beside the one lock its call names.
    if several {
        return Some(
            "the project has workspace members with pnpm locks of their own, a layout that no \
             routed lock was built with"
                .into(),
        );
    }
    // Behind a condition or in a comprehension it may not run as it is
    // written, which is no shape that a routed lock was built with.
    if !call.whole {
        return Some("it is not a statement of its own, so it may not run as it is written".into());
    }
    let unbuilt = call.args.iter().find_map(|arg| match &arg.how {
        How::Keyword(name) if BUILT.contains(&name.as_str()) => None,
        How::Keyword(name) => Some(format!(
            "its `{name}` is an attribute that no routed lock was built with"
        )),
        _ => Some("it passes arguments that are not written out".into()),
    });
    if unbuilt.is_some() {
        return unbuilt;
    }
    match call.arg("update_pnpm_lock") {
        Some(Value::Name(written)) if written == "False" => return None,
        None => return None,
        Some(Value::Name(written)) if written == "True" => {}
        _ => return Some("its `update_pnpm_lock` is not written out as `True` or `False`".into()),
    }
    if unlisted(ws, call, &settings).is_some() {
        return Some(format!(
            "its `data` is not written out as a list of strings that holds `//:{settings}`"
        ));
    }
    let stated = match pnpm() {
        Pnpm::Stated(_, version, Some(unshown)) => {
            return Some(format!(
                "the pnpm it runs for `update_pnpm_lock` is not shown to be the one the root \
                 module states (pnpm {version}): {unshown}"
            ))
        }
        // A release in full: a prerelease of 11.20.0 is older than it, and
        // a number of fewer parts is none that a build was run with.
        Pnpm::Stated(numbers, version, _) if *numbers >= (11, 20, 0) => {
            let (major, minor, patch) = numbers;
            if *version == format!("{major}.{minor}.{patch}") {
                return None;
            }
            format!(" (pnpm {version}, which is not a release of three numbers)")
        }
        Pnpm::Stated(_, version, _) => format!(" (pnpm {version})"),
        _ => String::new(),
    };
    Some(format!(
        "the pnpm it runs for `update_pnpm_lock` is not stated as 11.20 or later{stated}"
    ))
}

/// [`Hubs::reader`] for the locks `locks` of the project in the directory
/// `project` of the workspace `ws`: of its hubs `hubs`, each of which runs
/// the pnpm that `pnpm` gives for its place in that list.
fn reader<'a>(
    ws: &Workspace,
    project: &str,
    locks: &[String],
    hubs: &Tags,
    pnpm: &dyn Fn(usize) -> &'a Pnpm,
) -> Option<Reader> {
    let from = from_root(project);
    let mut takes = None;
    for (at, tag) in hubs.calls.iter().enumerate() {
        let named = names(ws, tag.call);
        let reads = match &named {
            Named::File(label) => locks
                .iter()
                .any(|lock| label.path() == below(project, lock)),
            Named::Elsewhere => false,
            Named::Unwritten => true,
        };
        if !reads {
            continue;
        }
        let call = format!("{}:{}{from}", tag.file, tag.call.line);
        match off_route(ws, project, tag.call, &named, locks.len() > 1, &|| pnpm(at)) {
            Some(why) => return Some(Reader::Call(call, why)),
            None => takes = takes.or(Some(Reader::Takes(call))),
        }
    }
    // No call that was read keeps the lock off the route. That is the
    // answer only where every call was read.
    let doubt = |doubt: &Doubt| match doubt.line {
        0 => format!("{}: {}{from}", doubt.file, doubt.why),
        line => format!("{}:{line}: {}{from}", doubt.file, doubt.why),
    };
    if let Some(unread) = ws.doubts.first().or(hubs.doubts.first()) {
        return Some(Reader::Unseen(doubt(unread)));
    }
    match &ws.legacy {
        Some(Ok((file, legacy))) => brings_in_rules_js(legacy).map(|line| {
            Reader::Unseen(format!(
                "{file}:{line}: it brings in rules_js, and a hub that this file defines is \
                 not read{from}"
            ))
        }),
        Some(Err(unread)) => Some(Reader::Unseen(doubt(unread))),
        None => None,
    }
    .or(takes)
}

/// The line on which the file of the older `WORKSPACE` system brings in
/// rules_js: a `load` from the ruleset's repository, a `load` of its hub
/// rule from anywhere, or a call of that rule, by its own name or by one a
/// `load` gives it. `None` for a file that plainly does none of these: an
/// `http_archive` of something else defines no hub of a pnpm lock.
///
/// Not looked at, as for the other rulesets: a macro of a `.bzl` file that
/// makes the call, and a repository of the ruleset under another name
/// whose hub rule the file does not load itself.
fn brings_in_rules_js(legacy: &File) -> Option<usize> {
    const RULE: &str = "npm_translate_lock";
    let rule = Value::Str(RULE.to_string());
    let loads = legacy.calls.iter().filter(|call| call.callee == "load");
    let names: Vec<&str> = loads
        .flat_map(|load| &load.args)
        .filter_map(|arg| match &arg.how {
            How::Keyword(alias) if arg.value == rule => Some(alias.as_str()),
            _ => None,
        })
        .chain([RULE])
        .collect();
    let brings = |call: &&Call| match call.callee.as_str() {
        "load" => {
            let ruleset = |label: &str| {
                let repository = label.trim_start_matches('@');
                repository.starts_with("aspect_rules_js//")
            };
            matches!(call.positional(0), Some(Value::Str(label)) if ruleset(label))
                || call.args.iter().any(|arg| arg.value == rule)
        }
        callee => names.contains(&callee),
    };
    legacy.calls.iter().find(brings).map(|call| call.line)
}

/// The text of [`Hubs::hidden`] for the project in the directory `project`
/// (from the Bazel root, empty for the root) of the workspace `ws`: for a
/// run that writes its setting to pnpm-workspace.yaml (`writes`), or for
/// one that is told not to ([`Hubs::unset`]). `beside` reads that file,
/// and `pnpm` the pnpm of a hub, by its place in `hubs` ([`release`]).
fn judge<'a>(
    ws: &Workspace,
    beside: &dyn Fn() -> &'a Entry,
    project: &str,
    hubs: &Tags,
    pnpm: &dyn Fn(usize) -> &'a Pnpm,
    writes: bool,
) -> Option<String> {
    let (lock, settings) = (below(project, LOCK), below(project, SETTINGS));
    for (at, tag) in hubs.calls.iter().enumerate() {
        let (file, call) = (tag.file, tag.call);
        let named = match names(ws, call) {
            Named::File(named) if named.path() == lock => named,
            _ => continue,
        };
        let (has, how) = match call.arg("update_pnpm_lock") {
            Some(Value::Name(written)) if written == "True" => ("has", "`update_pnpm_lock`"),
            Some(Value::Name(written)) if written == "False" => continue,
            None if !call.unpacks() => continue,
            _ => (
                "may have",
                "its `update_pnpm_lock` is not written out as `True` or `False`",
            ),
        };
        let written = unlisted(ws, call, &settings);
        // What the file needs before a pin in the lock is one the build
        // takes and an undo leaves standing.
        let own = format!(
            "put a comment line in {settings} (create the file where there is none: `rollback` \
             removes one that holds only what hosted mode writes, and the call would then name a \
             missing file)"
        );
        let (fix, unset) = match beside() {
            Entry::Absent => (Some(own), false),
            Entry::Text(text) => match plan_workspace_trust(Some(text)) {
                TrustPlan::UserSet(value) => (
                    Some(format!(
                        "set `trustLockfile: true` in {settings} or take the line out (it says \
                         `trustLockfile: {value}`, which hosted mode leaves as it is)"
                    )),
                    true,
                ),
                TrustPlan::Unsupported(why) => (
                    Some(format!(
                        "write `trustLockfile: true` to {settings} yourself (hosted mode does \
                         not add it there: {why})"
                    )),
                    true,
                ),
                _ if removed_with_the_pin(text) => (Some(own), false),
                TrustPlan::AlreadyTrue => (None, false),
                _ if writes => (None, false),
                // Told not to write to the file, the run leaves it
                // without the setting. Said so that it holds for a caller
                // that is no command line.
                _ => (
                    Some(format!(
                        "let hosted mode write to {settings} (this run was told not to, which \
                         is `--no-trust-lockfile-config` on the command line, so it writes \
                         neither the setting nor the registries that take its place) or set \
                         `trustLockfile: true` there yourself"
                    )),
                    true,
                ),
            },
            Entry::Unreadable(_) => (None, false),
        };
        if written.is_none() && fix.is_none() {
            continue;
        }
        let Some(pnpm) = pnpm(at).may_reject() else {
            continue;
        };
        // The label of the file beside the lock, in the lock's own package.
        let beside = match named.name.rsplit_once('/') {
            Some((directory, _)) => format!("{directory}/{SETTINGS}"),
            None => SETTINGS.to_string(),
        };
        let label = format!("`//{}:{beside}`", named.package);
        let rejects = "pnpm 11 and later reject a lock that names the patch server \
                       (ERR_PNPM_TARBALL_URL_MISMATCH): `bazel build` would fail";
        // A `data` that is not written out may hold the label already: it
        // is the call that has to show it.
        let (why, list) = match written {
            Some(true) => (
                format!(
                    "its `data` does not list {settings}. That pnpm reads only the lock, the \
                     `package.json` files and the `data` of the call, so it would not see the \
                     `trustLockfile: true` that hosted mode writes to {settings}, and without \
                     it {rejects}"
                ),
                Some(format!("list {label} in the `data` of that call")),
            ),
            Some(false) => (
                format!(
                    "its `data` is not written out as a list of strings, so it is not known to \
                     list {settings}. That pnpm reads only the lock, the `package.json` files \
                     and the `data` of the call, so it may not see the `trustLockfile: true` \
                     that hosted mode writes to {settings}, and without it {rejects}"
                ),
                Some(format!(
                    "write the `data` of that call out as a list of strings that holds {label}"
                )),
            ),
            None if unset => (
                format!(
                    "hosted mode does not write `trustLockfile: true` to the {settings} that \
                     its `data` lists. Without that setting {rejects}"
                ),
                None,
            ),
            None => (
                format!(
                    "the {settings} that its `data` lists would hold only what hosted mode \
                     writes. A later `rollback` removes such a file, the call would then name \
                     a missing file, and `bazel build` would fail"
                ),
                None,
            ),
        };
        let steps: Vec<String> = fix.into_iter().chain(list).collect();
        let from = from_root(project);
        return Some(format!(
            "{file}:{}{from}: this `{}` {has} Bazel run {pnpm} to keep {lock} up to date \
             ({how}), and {why}; {lock} was not rewritten — {} and re-run",
            call.line,
            call.callee,
            steps.join(", ")
        ));
    }
    None
}

/// Whether `rollback` removes a `pnpm-workspace.yaml` of this text with a
/// hosted pin: with the setting in it, the file is byte for byte the one
/// hosted mode creates, which the undo cannot tell from the user's own
/// (`cleanup_side_config` of the npm restore).
///
/// A file an earlier run made for a route through named registries is one
/// too: the run that pins the lock takes the route's entries out
/// ([`Hubs::reader`]), and what is left is that file. Any registry of the
/// shape counts, as nothing here says which host is a patch server's.
fn removed_with_the_pin(text: &str) -> bool {
    use crate::formats::pnpm::named_registries::{unwind, Owned, Unwound};

    let text = match unwind(text, &Owned::of(Some(text), &|_| true), &[]) {
        Unwound::Delete => return true,
        Unwound::Rewrite(without, _) => without,
        Unwound::Unchanged => text.to_string(),
    };
    match plan_workspace_trust(Some(&text)) {
        TrustPlan::Append(pinned) | TrustPlan::Scaffold(pinned) => is_trust_scaffold(&pinned),
        TrustPlan::AlreadyTrue => is_trust_scaffold(&text),
        _ => false,
    }
}

/// The pnpm that a hub runs, as far as the workspace states it.
enum Pnpm {
    /// The newest release that the tags of its repository state, each of
    /// them read as a version: its numbers, and as it is written. And
    /// what keeps it from being shown as the pnpm the hub runs in every
    /// build, which the route asks for ([`ELSEWHERE`], [`ASIDE`],
    /// [`UNNAMED`], [`DROPPED`]): none where it is shown.
    Stated((u64, u64, u64), String, Option<&'static str>),
    /// One that may be 11 or later, in the words of a warning: a release
    /// that is not written out, or the one a release of rules_js picks
    /// whose choice is not known (the module docs).
    May(String),
    /// The one rules_js picks where nothing is stated, which is older than
    /// 11 ([`picks_an_older_pnpm`]).
    Older,
}

impl Pnpm {
    /// The pnpm in the words of a warning, when it may be 11 or later and
    /// so reject a pinned lock: `None` for one that is known to be older.
    fn may_reject(&self) -> Option<String> {
        match self {
            Pnpm::Stated((11.., ..), version, _) => Some(format!("pnpm {version}")),
            Pnpm::Stated(..) | Pnpm::Older => None,
            Pnpm::May(what) => Some(what.clone()),
        }
    }
}

/// Why a stated release is not shown to be the pnpm of the hub: its
/// repository may be another than the one the tags make.
const ELSEWHERE: &str = "its repository is not taken from the pnpm extension as every module \
                         uses it, or that extension has an isolated use or an `inject_repo`";

/// Why a stated release is not the pnpm of the hub for certain: Bazel may
/// not run the tag that states it, or the tag may make another repository,
/// and the hub then runs the pnpm that rules_js picks.
const ASIDE: &str = "a tag that states a release for it is not a statement of its own, so it \
                     may not run as it is written";
const UNNAMED: &str = "a tag that states a release for it has a `name` that is not written out \
                       in a plain string, so it may make another repository";

/// Why a stated release is not the pnpm of the hub in every build: without
/// the tag the hub runs the pnpm that rules_js picks.
const DROPPED: &str = "a use of the pnpm extension with `dev_dependency` states a release for \
                       it, and Bazel drops such a use under `--ignore_dev_dependency`";

/// The pnpm that the hub `hub` runs ([`Pnpm`]).
fn release(ws: &Workspace, view: &dyn Fn(&str) -> Entry, hub: &Call) -> Pnpm {
    let unread = || {
        Pnpm::May(
            "a pnpm whose release is not written out as a version (it may be 11 or later)".into(),
        )
    };
    // Whether `call` names the repository `repo` by position.
    let named = |repo: &String, call: &Call| {
        let is = |arg: &Arg| arg.how == How::Positional && arg.value == Value::Str(repo.clone());
        call.args.iter().any(is)
    };
    // Whether a `use_repo` takes the repository `repo` under that very name.
    let taken = |repo: &String| {
        let takes = |call: &&Call| call.bind.is_none() && call.callee == "use_repo";
        let calls = ws.files.iter().flat_map(|(_, file)| &file.calls);
        calls.filter(takes).any(|call| named(repo, call))
    };
    let repo = match hub.arg("use_pnpm") {
        None if !hub.unpacks() => "pnpm".to_string(),
        Some(Value::Str(label)) => match ws.label(label).map(|label| label.repo) {
            Some(Repo::Apparent(repo)) if taken(&repo) => repo,
            _ => return unread(),
        },
        _ => return unread(),
    };
    let tags = ws.tags(&extension("pnpm"), "pnpm");
    // For the route: the repository is one of the shared use, which the
    // hub runs by default and a `use_repo` of that use takes by its name.
    let handed = |callee: &'static str| {
        let calls = tags.handed.iter();
        calls.filter(move |taken| taken.call.callee == callee)
    };
    let by_name =
        |taken: &Tag| taken.isolate == Some(false) && taken.call.whole && named(&repo, taken.call);
    let mut shared = hub.arg("use_pnpm").is_none() || handed("use_repo").any(by_name);
    shared &= handed("inject_repo").next().is_none();
    // And no use that is a dev dependency states a release for it: Bazel
    // drops the tags of such a use under `--ignore_dev_dependency`.
    let mut dropped = false;
    // And every tag that states a release for it runs as it is written,
    // and makes this repository: the first that may not is why.
    let mut unsure = None;
    // Without a tag, the repository `pnpm` is the one rules_js makes.
    let (mut newest, mut made) = (None::<((u64, u64, u64), String)>, repo == "pnpm");
    let mut read = tags.doubts.is_empty();
    for tag in &tags.calls {
        let call = tag.call;
        // A tag of an isolated use makes a repository of that use alone.
        shared &= tag.isolate == Some(false);
        match call.arg("name") {
            None if !call.unpacks() && repo != "pnpm" => continue,
            Some(Value::Str(name)) if *name != repo => continue,
            _ => made = true,
        }
        let stated = match (call.arg("pnpm_version_from"), call.arg("pnpm_version")) {
            // A tag that states no release asks for the one rules_js picks.
            (None, None) if !call.unpacks() => continue,
            (None, Some(Value::Str(version))) if version.is_empty() => continue,
            (None, Some(Value::Str(version))) => Some(version.clone()),
            (Some(Value::Str(label)), _) => {
                let file = ws.label(label).filter(|label| label.repo == Repo::Main);
                let text = match file.map(|file| view(&file.path())) {
                    Some(Entry::Text(text)) => text,
                    _ => String::new(),
                };
                let json = serde_json::from_str::<serde_json::Value>(strip_bom(&text)).ok();
                let spec = json
                    .as_ref()
                    .and_then(|json| json["packageManager"].as_str());
                spec.and_then(|spec| pinned_version(spec, "pnpm"))
                    .map(str::to_string)
            }
            _ => None,
        };
        dropped |= tag.dev_dependency != Some(false);
        let plain = match call.arg("name") {
            None => !call.unpacks(),
            name => matches!(name, Some(Value::Str(_))),
        };
        let uncertain = (!call.whole).then_some(ASIDE);
        unsure = unsure.or(uncertain).or((!plain).then_some(UNNAMED));
        // The numbers of a release: rules_js runs the newest of several.
        let numbers = |version: &String| {
            let release = version.split(['-', '+']).next().unwrap_or(version);
            let mut parts = release.split('.').map(|part| part.parse::<u64>().ok());
            let major = parts.next()??;
            let rest = |part: Option<Option<u64>>| part.flatten().unwrap_or(0);
            Some((major, rest(parts.next()), rest(parts.next())))
        };
        match stated.as_ref().and_then(numbers) {
            Some(new) if newest.as_ref().is_none_or(|(old, _)| new > *old) => {
                newest = stated.map(|version| (new, version));
            }
            Some(_) => {}
            None => read = false,
        }
    }
    let unshown = match (shared, dropped) {
        (false, _) => Some(ELSEWHERE),
        (true, _) if unsure.is_some() => unsure,
        (true, true) => Some(DROPPED),
        (true, false) => None,
    };
    match newest {
        // A tag that states a release also makes the repository.
        Some((numbers, version)) if read => Pnpm::Stated(numbers, version, unshown),
        Some(((11.., ..), version)) => Pnpm::May(format!("pnpm {version}")),
        Some(_) => unread(),
        None if !read || !made => unread(),
        None if picks_an_older_pnpm(ws, view) => Pnpm::Older,
        None => Pnpm::May(
            "the pnpm that aspect_rules_js picks itself, at a release of the ruleset whose \
             choice is not known here (it may be 11 or later)"
                .into(),
        ),
    }
}

/// Whether the pnpm that rules_js runs where no tag states a release is
/// known to be older than 11. Its releases pick the newest pnpm 8 they
/// carry through 2.9.3 and the newest pnpm 10 from 3.0.0 through 3.6.0 and
/// at 4.0.0-alpha.0 and 4.0.0-alpha.1 (`DEFAULT_PNPM_VERSION` in
/// `npm/private/pnpm_repository.bzl`; 1.42.3 its last pnpm 8). So it is
/// known for a release of 1, 2 or 3 and for those two, which is what the
/// root module has to ask for, by `bazel_dep` or a `single_version_override`
/// with a version, and what `MODULE.bazel.lock`, where there is one, has to
/// have selected. An override that takes the ruleset from elsewhere, a
/// version that is no string and any later release are not known.
fn picks_an_older_pnpm(ws: &Workspace, view: &dyn Fn(&str) -> Entry) -> bool {
    const RULESET: &str = "aspect_rules_js";
    let module = Some(&Value::Str(RULESET.to_string()));
    let names = |call: &&Call| {
        call.bind.is_none() && [call.arg("name"), call.arg("module_name")].contains(&module)
    };
    let calls = ws.files.iter().flat_map(|(_, file)| &file.calls);
    let calls: Vec<&Call> = calls.filter(names).collect();
    let pin = "single_version_override";
    let version = |callee: &str| {
        let call = calls.iter().find(|call| call.callee == callee);
        call.and_then(|call| call.arg("version"))
    };
    let elsewhere = |call: &&Call| call.callee.ends_with("_override") && call.callee != pin;
    let asked = match (version(pin), version("bazel_dep")) {
        _ if calls.iter().any(elsewhere) => return false,
        (Some(Value::Str(pinned)), _) if !pinned.is_empty() => pinned.clone(),
        (None | Some(Value::Str(_)), Some(Value::Str(least))) => least.clone(),
        _ => return false,
    };
    let known = |release: &str| {
        let release = release.split('+').next().unwrap_or(release);
        let major = release
            .split(['.', '-'])
            .next()
            .and_then(|major| major.parse::<u64>().ok());
        matches!(major, Some(1..=3)) || ["4.0.0-alpha.0", "4.0.0-alpha.1"].contains(&release)
    };
    let selected = match view("MODULE.bazel.lock") {
        Entry::Text(lock) => ModuleLock::parse(&lock)
            .selected(RULESET)
            .iter()
            .all(|r| known(r)),
        _ => true,
    };
    known(&asked) && selected
}

/// What the tests of this crate write as the `MODULE.bazel` of a workspace
/// with a rules_js hub.
#[cfg(test)]
pub(crate) mod fixtures {
    /// A `MODULE.bazel` whose `npm.npm_translate_lock` (line 3) has `call`
    /// as its arguments, with a tag that states pnpm 11.28.10 as the pnpm
    /// Bazel runs.
    pub(crate) fn rules_js_hub(call: &str) -> String {
        format!(
            "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
             npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
             npm.npm_translate_lock({call})\n\
             pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
             pnpm.pnpm(name = \"pnpm\", pnpm_version = \"11.28.10\")\n"
        )
    }

    /// The arguments of the hub of [`super::Hubs::hidden`]: it keeps the
    /// root lock up to date with a pnpm 11 that does not see
    /// pnpm-workspace.yaml.
    pub(crate) const HIDING_HUB_CALL: &str =
        "pnpm_lock = \"//:pnpm-lock.yaml\", update_pnpm_lock = True";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::lock_inventory::MemoryProject;

    /// The root module of a workspace whose hub is `hub`, on line 4, with
    /// the lines `pnpm` after the proxy of the pnpm extension.
    fn module(hub: &str, pnpm: &str) -> String {
        format!(
            "module(name = \"app\")\n\
             bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
             npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
             npm.npm_translate_lock({hub})\n\
             pnpm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\")\n\
             {pnpm}\n"
        )
    }

    /// The hub of the measured build: it names the lock at the root
    /// ([`LOCKED`]), keeps it up to date and lists nothing.
    const HUB: &str = "pnpm_lock = \"//:pnpm-lock.yaml\", update_pnpm_lock = True";
    const LOCKED: &str = "pnpm_lock = \"//:pnpm-lock.yaml\"";
    /// The tag that states the pnpm of that build.
    const ELEVEN: &str = "pnpm.pnpm(name = \"pnpm\", pnpm_version = \"11.28.10\")";

    /// The files `files`, and nothing else, as a workspace is read.
    fn holding<'a>(files: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Entry + 'a {
        |path| match files.iter().find(|(name, _)| *name == path) {
            Some((_, text)) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        }
    }

    /// The text of [`Hubs::hidden`] for the project in `project` of the
    /// workspace that holds `files` and nothing else.
    fn said(files: &[(&str, &str)], project: &str) -> Option<String> {
        answered(files, project).hidden.map(|hidden| hidden.detail)
    }

    /// [`answer`] about the root lock of that project.
    fn answered(files: &[(&str, &str)], project: &str) -> Hubs {
        let view = holding(files);
        answer(&view, project, &[LOCK.to_string()])
    }

    /// [`said`] for the root project of a workspace with `module` and a
    /// `pnpm-workspace.yaml` of the user's own.
    fn root(hub: &str, pnpm: &str) -> Option<String> {
        said(
            &[("MODULE.bazel", &module(hub, pnpm)), (SETTINGS, "# own\n")],
            "",
        )
    }

    /// The step for a file that would hold only what hosted mode writes.
    const OWN: &str = "put a comment line in pnpm-workspace.yaml (create the file where there \
                       is none: `rollback` removes one that holds only what hosted mode writes, \
                       and the call would then name a missing file)";

    #[test]
    fn the_warning_names_the_call_and_the_line_to_add() {
        let module = module(HUB, ELEVEN);
        let said_of = |files: &[(&str, &str)]| said(files, "").expect("withheld");
        // The project has a `pnpm-workspace.yaml`: one line is the way on.
        let listed = said_of(&[("MODULE.bazel", &module), (SETTINGS, "packages: []\n")]);
        assert_eq!(
            listed,
            "MODULE.bazel:4: this `npm.npm_translate_lock` has Bazel run pnpm 11.28.10 to keep \
             pnpm-lock.yaml up to date (`update_pnpm_lock`), and its `data` does not list \
             pnpm-workspace.yaml. That pnpm reads only the lock, the `package.json` files and \
             the `data` of the call, so it would not see the `trustLockfile: true` that hosted \
             mode writes to pnpm-workspace.yaml, and without it pnpm 11 and later reject a lock \
             that names the patch server (ERR_PNPM_TARBALL_URL_MISMATCH): `bazel build` would \
             fail; pnpm-lock.yaml was not rewritten — list `//:pnpm-workspace.yaml` in the \
             `data` of that call and re-run"
        );
        // The call is named as the file writes it.
        let other = module
            .replace("\nnpm = use_extension", "\njs = use_extension")
            .replace("\nnpm.npm_translate_lock(", "\njs.npm_translate_lock(");
        assert!(other.contains("\njs.npm_translate_lock(") && other.contains("\npnpm = "));
        let written = said_of(&[("MODULE.bazel", &other), (SETTINGS, "packages: []\n")]);
        assert_eq!(
            written,
            listed.replace("`npm.npm_translate_lock`", "`js.npm_translate_lock`")
        );
        // It has none, or one that the undo of the pin would remove because
        // with the setting it is the file hosted mode creates: a line of
        // the user's own comes first, so that no undo leaves the call with
        // a missing file.
        let (reason, way_on) = listed.split_once(" — ").expect("the way on");
        let absent = said_of(&[("MODULE.bazel", &module)]);
        assert_eq!(absent, format!("{reason} — {OWN}, {way_on}"));
        let scaffold = "packages:\n  - '.'\ntrustLockfile: true\n";
        assert!(is_trust_scaffold(scaffold));
        let cases = [
            ("", true),
            ("packages:\n  - '.'\n", true),
            ("packages:\r\n  - '.'\r\n", true),
            (scaffold, true),
            ("# mine\npackages:\n  - '.'\n", false),
            ("packages:\n  - 'apps/*'\n", false),
        ];
        for (text, removed) in cases {
            let said = said_of(&[("MODULE.bazel", &module), (SETTINGS, text)]);
            let more = if removed {
                format!("{OWN}, ")
            } else {
                String::new()
            };
            assert_eq!(said, format!("{reason} — {more}{way_on}"), "{text:?}");
        }
        // It has one that hosted mode does not write the setting to: with
        // the label alone the next run would still pin nothing.
        let off = "packages:\n  - '.'\ntrustLockfile: false\n";
        let said = said_of(&[("MODULE.bazel", &module), (SETTINGS, off)]);
        let set = "set `trustLockfile: true` in pnpm-workspace.yaml or take the line out (it \
                   says `trustLockfile: false`, which hosted mode leaves as it is)";
        assert_eq!(said, format!("{reason} — {set}, {way_on}"));
        let flow = said_of(&[("MODULE.bazel", &module), (SETTINGS, "{packages: ['.']}\n")]);
        let write = " — write `trustLockfile: true` to pnpm-workspace.yaml yourself (hosted \
                     mode does not add it there: ";
        assert!(flow.starts_with(reason) && flow.contains(write), "{flow}");
        assert!(flow.ends_with(&format!("), {way_on}")), "{flow}");
    }

    /// A hub that lists the file is passed over only where the pin is one
    /// the build takes and an undo leaves standing.
    #[test]
    fn a_listed_file_has_to_hold_the_setting_and_a_line_of_the_users_own() {
        let hub = format!("{HUB}, data = [\"//:pnpm-workspace.yaml\"]");
        let with = |pnpm: &str, text: Option<&str>| {
            let module = module(&hub, pnpm);
            let mut files = vec![("MODULE.bazel", module.as_str())];
            files.extend(text.map(|text| (SETTINGS, text)));
            said(&files, "")
        };
        let start = "MODULE.bazel:4: this `npm.npm_translate_lock` has Bazel run pnpm 11.28.10 \
                     to keep pnpm-lock.yaml up to date (`update_pnpm_lock`), and ";
        // `rollback` would remove it with the pin, and the call names it.
        let gone = format!(
            "{start}the pnpm-workspace.yaml that its `data` lists would hold only what hosted \
             mode writes. A later `rollback` removes such a file, the call would then name a \
             missing file, and `bazel build` would fail; pnpm-lock.yaml was not rewritten — \
             {OWN} and re-run"
        );
        let scaffold = "packages:\n  - '.'\ntrustLockfile: true\n";
        // The file of an earlier run that routed a release through a named
        // registry: the run that pins the lock takes the route out of it.
        let patch = "58f14d5a-0000-4000-8000-000000000000";
        let routed = format!(
            "packages:\n  - '.'\nnamedRegistries:\n  socket-58f14d5a: \
             https://patch.test/patch/npm/leaf/1.0.0/t/{patch}/\n\
             overrides:\n  'leaf@1.0.0': 'socket-58f14d5a:1.0.0'\n"
        );
        for text in [
            None,
            Some(""),
            Some("packages:\n  - '.'\n"),
            Some(scaffold),
            Some(routed.as_str()),
        ] {
            assert_eq!(with(ELEVEN, text), Some(gone.clone()), "{text:?}");
        }
        // With a line of the user's own it is a file that stays.
        assert_eq!(with(ELEVEN, Some(&format!("# mine\n{routed}"))), None);
        // Hosted mode does not write the setting to it: the pnpm of the
        // hub would reject the pinned lock although it reads the file.
        let unset = format!(
            "{start}hosted mode does not write `trustLockfile: true` to the pnpm-workspace.yaml \
             that its `data` lists. Without that setting pnpm 11 and later reject a lock that \
             names the patch server (ERR_PNPM_TARBALL_URL_MISMATCH): `bazel build` would fail; \
             pnpm-lock.yaml was not rewritten — "
        );
        let off = with(ELEVEN, Some("# mine\ntrustLockfile: false\n")).expect("withheld");
        let set = "set `trustLockfile: true` in pnpm-workspace.yaml or take the line out (it \
                   says `trustLockfile: false`, which hosted mode leaves as it is) and re-run";
        assert_eq!(off, format!("{unset}{set}"));
        let flow = with(ELEVEN, Some("{packages: ['.']}\n")).expect("withheld");
        let write = "write `trustLockfile: true` to pnpm-workspace.yaml yourself (hosted mode \
                     does not add it there: ";
        assert!(flow.starts_with(&format!("{unset}{write}")), "{flow}");
        assert!(flow.ends_with(") and re-run"), "{flow}");
        // A file with a line of the user's own that takes the setting, or
        // has it: pinned as without the hub. And a pnpm that rejects no
        // lock is not asked about the file at all.
        for text in [
            "# mine\n",
            "packages:\n  - 'apps/*'\n",
            "# mine\npackages:\n  - '.'\ntrustLockfile: true\n",
        ] {
            assert_eq!(with(ELEVEN, Some(text)), None, "{text:?}");
        }
        let ten = "pnpm.pnpm(name = \"pnpm\", pnpm_version = \"10.34.9\")";
        assert_eq!(with(ten, None), None);
        assert_eq!(with("", Some("")), None);
    }

    /// Where no tag states a release, rules_js runs a pnpm of its own
    /// choice, which is known for the releases it was read in and for no
    /// other.
    #[test]
    fn the_choice_of_rules_js_is_known_for_the_releases_it_was_read_in() {
        let dep = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n";
        let asking = |ask: &str, lock: Option<&str>| {
            let module = module(HUB, "").replace(dep, ask);
            assert!(!module.contains("3.6.0") || ask.contains("3.6.0"), "{ask}");
            let mut files = vec![("MODULE.bazel", module.as_str()), (SETTINGS, "# own\n")];
            files.extend(lock.map(|lock| ("MODULE.bazel.lock", lock)));
            said(&files, "")
        };
        let at =
            |version: &str| format!("bazel_dep(name = \"aspect_rules_js\", version = {version})\n");
        for known in [
            "1.42.3",
            "2.9.3",
            "3.0.0",
            "3.6.0",
            "4.0.0-alpha.0",
            "4.0.0-alpha.1",
        ] {
            assert_eq!(asking(&at(&format!("\"{known}\"")), None), None, "{known}");
        }
        let unknown = "has Bazel run the pnpm that aspect_rules_js picks itself, at a release of \
                       the ruleset whose choice is not known here (it may be 11 or later) to keep";
        let pinned = |version: &str| {
            format!(
                "{dep}single_version_override(module_name = \"aspect_rules_js\", version = \
                 {version})\n"
            )
        };
        let elsewhere = format!(
            "{dep}git_override(module_name = \"aspect_rules_js\", remote = \"https://example\")\n"
        );
        for ask in [
            at("\"4.0.0\""),
            at("\"4.1.2\""),
            at("\"5.0.0-rc.1\""),
            at("RULES_JS"),
            at("\"\""),
            pinned("\"4.0.0\""),
            pinned("PIN"),
            elsewhere,
        ] {
            let said = asking(&ask, None).unwrap_or_else(|| panic!("{ask}: not withheld"));
            assert!(said.contains(unknown), "{ask}: {said}");
        }
        // A pin decides whatever is asked for, and one without a version
        // leaves the release to what is asked for.
        assert_eq!(
            asking(&pinned("\"3.5.2\"").replace("3.6.0", "4.0.0"), None),
            None
        );
        let unpinned = format!("{dep}single_version_override(module_name = \"aspect_rules_js\")\n");
        assert_eq!(asking(&unpinned, None), None);
        // What Bazel selected, where its lock says: another module of the
        // build can ask for a later release than the root does.
        let lock = |release: &str| {
            format!(
                "{{\"lockFileVersion\": 28, \"registryFileHashes\": {{\
                 \"https://bcr.bazel.build/modules/aspect_rules_js/{release}/source.json\": \"x\"}}}}"
            )
        };
        assert_eq!(asking(dep, Some(&lock("3.6.0"))), None);
        let later = asking(dep, Some(&lock("4.2.0"))).expect("withheld");
        assert!(later.contains(unknown), "{later}");
        // A release that a tag states is the one rules_js runs, whatever
        // its own choice would be.
        let ten = "pnpm.pnpm(name = \"pnpm\", pnpm_version = \"10.34.9\")";
        let stated = module(HUB, ten).replace(dep, &at("\"4.1.2\""));
        assert_eq!(
            said(&[("MODULE.bazel", &stated), (SETTINGS, "# own\n")], ""),
            None
        );
    }

    #[test]
    fn nothing_is_withheld_where_the_build_takes_the_pinned_lock() {
        let listing = |label: &str| format!("{HUB}, data = [\"//:package.json\", \"{label}\"]");
        let ten = "pnpm.pnpm(name = \"pnpm\", pnpm_version = \"10.34.9\")";
        let other = "pnpm.pnpm(name = \"eleven\", pnpm_version = \"11.28.10\")";
        let named = "pnpm.pnpm(pnpm_version = \"11.28.10\")\n\
                     pnpm.pnpm(name = \"ten\", pnpm_version = \"10.34.9\")\n\
                     use_repo(pnpm, \"pnpm\", \"ten\")";
        let by_label = format!("{HUB}, use_pnpm = \"@pnpm//:package/bin/pnpm.cjs\"");
        let cases = [
            ("no update", LOCKED.to_string(), ELEVEN),
            (
                "update off",
                format!("{LOCKED}, update_pnpm_lock = False"),
                ELEVEN,
            ),
            ("listed", listing("//:pnpm-workspace.yaml"), ELEVEN),
            (
                "listed, in the package",
                listing(":pnpm-workspace.yaml"),
                ELEVEN,
            ),
            (
                "listed, by its name",
                listing("pnpm-workspace.yaml"),
                ELEVEN,
            ),
            (
                "listed, with `@`",
                listing("@//:pnpm-workspace.yaml"),
                ELEVEN,
            ),
            (
                "listed, with the module",
                listing("@app//:pnpm-workspace.yaml"),
                ELEVEN,
            ),
            ("pnpm 10", HUB.to_string(), ten),
            ("no release", HUB.to_string(), ""),
            (
                "a tag without a release",
                HUB.to_string(),
                "pnpm.pnpm(name = \"pnpm\")",
            ),
            (
                "an empty release",
                HUB.to_string(),
                "pnpm.pnpm(pnpm_version = \"\")",
            ),
            ("pnpm 11 in another repository", HUB.to_string(), other),
            (
                "the lock of another project",
                HUB.replace("//:", "//web:"),
                ELEVEN,
            ),
            (
                "the lock of another repository",
                HUB.replace("//:", "@other//:"),
                ELEVEN,
            ),
            (
                "pnpm 10 in the repository the hub names",
                format!("{HUB}, use_pnpm = \"@ten//:package/bin/pnpm.cjs\""),
                named,
            ),
            (
                "the pnpm of rules_js by its label",
                by_label.clone(),
                "use_repo(pnpm, \"pnpm\")",
            ),
            (
                "pnpm 10 by its label",
                by_label,
                "pnpm.pnpm(pnpm_version = \"10.34.9\")\nuse_repo(pnpm, \"pnpm\")",
            ),
            (
                "a lock that is no string",
                HUB.replace("\"//:pnpm-lock.yaml\"", "LOCK"),
                ELEVEN,
            ),
        ];
        for (case, hub, pnpm) in cases {
            assert_eq!(root(&hub, pnpm), None, "{case}");
        }
        // No workspace file, one that asks for another ruleset's extension,
        // and a project that is not the one whose lock the hub names.
        assert_eq!(said(&[], ""), None);
        let other = module(HUB, ELEVEN).replace("@aspect_rules_js//npm", "@rules_other//npm");
        assert_eq!(said(&[("MODULE.bazel", &other)], ""), None);
        assert_eq!(said(&[("MODULE.bazel", &module(HUB, ELEVEN))], "web"), None);
        // A part of the workspace that cannot be read withholds nothing by
        // itself: the call that is read builds the pinned lock.
        let unread = format!("{}include(\"//:missing.MODULE.bazel\")\n", module(HUB, ten));
        assert_eq!(said(&[("MODULE.bazel", &unread)], ""), None);
    }

    #[test]
    fn what_is_not_written_out_counts_against_writing() {
        let eleven = "has Bazel run pnpm 11.28.10 to keep";
        let may = "may have Bazel run pnpm 11.28.10 to keep";
        let unlisted = "is not written out as a list of strings, so it is not known to list";
        let unread = "Bazel run a pnpm whose release is not written out as a version (it may be";
        let also = |more: &str| format!("{HUB}, {more}");
        let two = "pnpm.pnpm(pnpm_version = \"10.34.9\")\n";
        let named = "pnpm.pnpm(name = \"eleven\", pnpm_version = \"11.28.10\")\n\
                     use_repo(pnpm, \"eleven\")";
        let by_label = |repo: &str| also(&format!("use_pnpm = \"@{repo}//:package/bin/pnpm.cjs\""));
        let other = "tools = use_extension(\"//:tools.bzl\", \"tools\")\nuse_repo(tools, \"mine\")";
        let renamed = format!(
            "{ELEVEN}\npnpm.pnpm(name = \"ten\", pnpm_version = \"10.34.9\")\n\
             use_repo(pnpm, ten = \"pnpm\")"
        );
        let cases = [
            ("the measured hub", HUB.to_string(), ELEVEN, eleven),
            (
                "an update that is a name",
                format!("{LOCKED}, update_pnpm_lock = UP"),
                ELEVEN,
                may,
            ),
            (
                "an update that `**` may pass",
                format!("{LOCKED}, **COMMON"),
                ELEVEN,
                "may have Bazel run a pnpm whose release is not written out",
            ),
            (
                "data that `**` may pass",
                also("**COMMON"),
                ELEVEN,
                unlisted,
            ),
            ("data that is a name", also("data = DATA"), ELEVEN, unlisted),
            (
                "data that is a sum",
                also("data = [\"//:pnpm-workspace.yaml\"] + MORE"),
                ELEVEN,
                unlisted,
            ),
            (
                "data without the file",
                also("data = [\"//web:pnpm-workspace.yaml\", \"@other//:pnpm-workspace.yaml\"]"),
                ELEVEN,
                "does not list",
            ),
            (
                "the newest release",
                HUB.to_string(),
                "pnpm.pnpm(pnpm_version = \"latest\")",
                unread,
            ),
            (
                "a release that is a name",
                HUB.to_string(),
                "pnpm.pnpm(pnpm_version = PNPM)",
                unread,
            ),
            (
                "a tag that passes `**`",
                HUB.to_string(),
                "pnpm.pnpm(**PNPM)",
                unread,
            ),
            (
                "a file that is not there",
                HUB.to_string(),
                "pnpm.pnpm(pnpm_version_from = \"//:package.json\")",
                unread,
            ),
            (
                "a proxy that is used otherwise",
                HUB.to_string(),
                "TOOLS = [pnpm]",
                unread,
            ),
            (
                "an entry point of the checkout",
                also("use_pnpm = \"//tools:pnpm.cjs\""),
                "",
                unread,
            ),
            (
                "an entry point that is a name",
                also("use_pnpm = PNPM"),
                "",
                unread,
            ),
            (
                "a tag whose name is a name",
                HUB.to_string(),
                "pnpm.pnpm(name = NAME, pnpm_version = \"11.28.10\")",
                eleven,
            ),
            (
                "the newest of two tags",
                HUB.to_string(),
                &format!("{two}{ELEVEN}"),
                eleven,
            ),
            (
                "the newest of two tags of one major",
                HUB.to_string(),
                &format!("pnpm.pnpm(pnpm_version = \"11.3.0\")\n{ELEVEN}"),
                eleven,
            ),
            (
                "the newest of two tags, the first",
                HUB.to_string(),
                &format!("{ELEVEN}\npnpm.pnpm(pnpm_version = \"11.3.0\")"),
                eleven,
            ),
            (
                "the repository the hub names",
                by_label("eleven"),
                &format!("{two}{named}"),
                eleven,
            ),
            // Bazel 9.3.2 runs the pnpm 11 of this tag for this hub.
            (
                "a repository under another name",
                by_label("eleven"),
                &format!("{ELEVEN}\nuse_repo(pnpm, eleven = \"pnpm\")"),
                unread,
            ),
            // The name is that of a tag which makes another repository.
            (
                "a repository under the name of a tag",
                by_label("ten"),
                &renamed,
                unread,
            ),
            (
                "a repository of another extension",
                by_label("mine"),
                other,
                unread,
            ),
            (
                "a repository no `use_repo` takes",
                by_label("pnpm"),
                "",
                unread,
            ),
        ];
        let out = "write the `data` of that call out as a list of strings that holds \
                   `//:pnpm-workspace.yaml` and re-run";
        for (case, hub, pnpm, part) in cases {
            let said = root(&hub, pnpm).unwrap_or_else(|| panic!("{case}: not withheld"));
            assert!(said.contains(part), "{case}: {said}");
            assert!(said.starts_with("MODULE.bazel:4: "), "{case}: {said}");
            // Only a `data` that is written out is one to add the label to.
            let written_out = said.ends_with(out);
            assert_eq!(said.contains(unlisted), written_out, "{case}: {said}");
        }
        // A call that may not run, one of a proxy that Bazel drops under
        // `--ignore_dev_dependency`, and one beside a file that cannot be
        // read are taken as they are written.
        let module = module(HUB, ELEVEN);
        let hub = format!("npm.npm_translate_lock({HUB})");
        let behind = module.replace(&hub, &format!("UPDATE and {hub}"));
        let dev = module.replace("\"npm\")", "\"npm\", dev_dependency = True)");
        let unread = format!("{module}include(\"//:missing.MODULE.bazel\")\n");
        for (case, module) in [
            ("a condition", behind),
            ("a dev proxy", dev),
            ("a missing file", unread),
        ] {
            assert_ne!(module, self::module(HUB, ELEVEN), "{case}");
            let said = said(&[("MODULE.bazel", &module)], "");
            assert!(said.is_some_and(|said| said.contains(eleven)), "{case}");
        }
    }

    #[test]
    fn the_release_of_a_package_json_is_its_package_manager() {
        let from = "pnpm.pnpm(pnpm_version_from = \"//:package.json\")";
        let module = module(HUB, from);
        let with = |manifest: &str| {
            let files = [
                ("MODULE.bazel", module.as_str()),
                ("package.json", manifest),
            ];
            said(&files, "")
        };
        let pinned = |pin: &str| with(&format!("{{\"packageManager\": \"{pin}\"}}"));
        let eleven = pinned("pnpm@11.2.0+sha512.abc").expect("withheld");
        assert!(
            eleven.contains("has Bazel run pnpm 11.2.0 to keep"),
            "{eleven}"
        );
        assert_eq!(pinned("pnpm@10.34.9"), None);
        // rules_js fails on each of these; none is read as a release.
        for manifest in ["{\"packageManager\": \"yarn@4.0.0\"}", "{}", "no JSON"] {
            let said = with(manifest).expect("withheld");
            assert!(
                said.contains("is not written out as a version"),
                "{manifest}: {said}"
            );
        }
    }

    #[test]
    fn a_project_below_the_root_is_named_from_the_root() {
        let hub = |lock: &str, data: &str| {
            let hub = format!("pnpm_lock = \"{lock}\", update_pnpm_lock = True{data}");
            let module = module(&hub, ELEVEN);
            said(
                &[
                    ("MODULE.bazel", &module),
                    ("web/pnpm-workspace.yaml", "# own\n"),
                ],
                "web",
            )
        };
        let said = hub("//web:pnpm-lock.yaml", "").expect("withheld");
        // Its paths are not the ones of a run in the project's directory.
        let from = "MODULE.bazel:4, with paths from the root of the Bazel workspace: this \
                    `npm.npm_translate_lock` has Bazel run";
        assert!(said.starts_with(from), "{said}");
        assert!(
            said.contains("to keep web/pnpm-lock.yaml up to date"),
            "{said}"
        );
        assert!(
            said.contains("; web/pnpm-lock.yaml was not rewritten — "),
            "{said}"
        );
        assert!(
            said.contains("does not list web/pnpm-workspace.yaml."),
            "{said}"
        );
        assert!(
            said.contains(" — list `//web:pnpm-workspace.yaml` in"),
            "{said}"
        );
        // The label is one of the package the call takes the lock from.
        let said = hub("//:web/pnpm-lock.yaml", "").expect("withheld");
        assert!(
            said.contains(" — list `//:web/pnpm-workspace.yaml` in"),
            "{said}"
        );
        // The file of the root is not the one beside the lock.
        assert!(hub(
            "//web:pnpm-lock.yaml",
            ", data = [\"//:pnpm-workspace.yaml\"]"
        )
        .is_some());
        for listed in ["//web:pnpm-workspace.yaml", "//:web/pnpm-workspace.yaml"] {
            let data = format!(", data = [\"{listed}\"]");
            assert_eq!(hub("//web:pnpm-lock.yaml", &data), None, "{listed}");
        }
        assert_eq!(hub("//:pnpm-lock.yaml", ""), None, "the lock of the root");
    }

    /// [`Hubs::reader`] for the locks `locks` of the project in `project`
    /// of the workspace whose root module has the hub `hub` and the lines
    /// `pnpm`, beside a `pnpm-workspace.yaml` of the user's own.
    fn reads(hub: &str, pnpm: &str, project: &str, locks: &[&str]) -> Option<Reader> {
        let module = module(hub, pnpm);
        let settings = below(project, SETTINGS);
        let files = [("MODULE.bazel", module.as_str()), (&settings, "# own\n")];
        let view = holding(&files);
        let locks: Vec<String> = locks.iter().map(|lock| lock.to_string()).collect();
        answer(&view, project, &locks).reader
    }

    /// The hub of a build that takes a routed lock with a pnpm of its own:
    /// it keeps the root lock up to date and lists the workspace file.
    const LISTING: &str = "pnpm_lock = \"//:pnpm-lock.yaml\", update_pnpm_lock = True, \
                           data = [\"//:pnpm-workspace.yaml\"]";
    /// The arguments of a `use_extension` of the pnpm extension.
    const PNPM_EXTENSION: &str = "\"@aspect_rules_js//npm:extensions.bzl\", \"pnpm\"";

    /// The two shapes of a hub whose build takes a routed lock
    /// ([`Reader::Takes`]): one that runs no pnpm, and one whose pnpm sees
    /// the workspace file and is stated as 11.20 or later, in each way a
    /// release is read as written out. Another repository's lock, another
    /// project's and a workspace with no hub have no reader at all.
    #[test]
    fn a_hub_takes_a_routed_lock_in_the_two_shapes_that_were_built() {
        let takes = Some(Reader::Takes("MODULE.bazel:4".to_string()));
        let off = format!("{LOCKED}, update_pnpm_lock = False");
        let unlisted_off = format!("{LOCKED}, data = DATA");
        let named_hub = format!("name = \"npm\", {LOCKED}");
        for hub in [LOCKED, off.as_str(), unlisted_off.as_str(), &named_hub] {
            // No pnpm runs, whatever the workspace states of one.
            for pnpm in ["", ELEVEN, "pnpm.pnpm(pnpm_version = \"10.34.9\")"] {
                assert_eq!(reads(hub, pnpm, "", &[LOCK]), takes, "{hub}: {pnpm}");
            }
        }
        let by_label = format!("{LISTING}, use_pnpm = \"@eleven//:package/bin/pnpm.cjs\"");
        let named = "pnpm.pnpm(name = \"eleven\", pnpm_version = \"11.28.10\")\n\
                     use_repo(pnpm, \"eleven\")";
        for (hub, pnpm) in [
            (LISTING, ELEVEN),
            (LISTING, "pnpm.pnpm(pnpm_version = \"11.20.0\")"),
            (LISTING, "pnpm.pnpm(pnpm_version = \"12.17.0\")"),
            // The newest of two is the one rules_js runs.
            (
                LISTING,
                "pnpm.pnpm(pnpm_version = \"10.34.9\")\npnpm.pnpm(pnpm_version = \"11.20.0\")",
            ),
            (by_label.as_str(), named),
            // A use that says it is not isolated is the one every module
            // shares, as Bazel takes it.
            (
                by_label.as_str(),
                &format!(
                    "same = use_extension({PNPM_EXTENSION}, isolate = False)\n\
                     same.pnpm(name = \"eleven\", pnpm_version = \"11.28.10\")\n\
                     use_repo(same, \"eleven\")"
                ),
            ),
        ] {
            assert_eq!(reads(hub, pnpm, "", &[LOCK]), takes, "{hub}: {pnpm}");
        }
        // By the `packageManager` of the file the tag names.
        let from = module(
            LISTING,
            "pnpm.pnpm(pnpm_version_from = \"//:package.json\")",
        );
        let pinned = |pin: &str| {
            let manifest = format!("{{\"packageManager\": \"{pin}\"}}");
            let files = [
                ("MODULE.bazel", from.as_str()),
                ("package.json", manifest.as_str()),
                (SETTINGS, "# own\n"),
            ];
            answered(&files, "").reader
        };
        assert_eq!(pinned("pnpm@11.28.10+sha512.abc"), takes);
        assert!(matches!(
            pinned("pnpm@11.19.0"),
            Some(Reader::Call(_, why)) if why.ends_with("(pnpm 11.19.0)")
        ));

        // No reader: the lock of another repository, of another project,
        // of a member that was not asked about, and no hub.
        let member = "pnpm_lock = \"//packages/a:pnpm-lock.yaml\"";
        for (hub, project) in [
            ("pnpm_lock = \"@other//:pnpm-lock.yaml\"", ""),
            (LOCKED, "packages/a"),
            (member, ""),
        ] {
            assert_eq!(reads(hub, ELEVEN, project, &[LOCK]), None, "{hub}");
        }
        let none = |_: &str| Entry::Absent;
        assert_eq!(answer(&none, "", &[LOCK.to_string()]), Hubs::default());
    }

    /// Every other hub that reads a lock keeps it off the route, and
    /// [`Reader::Call`] says what did, after the place of the call: what
    /// is not written out, a pnpm that is not stated as 11.20 or later, a
    /// `data` without the workspace file, the lock of a member, and a
    /// project below the root of the Bazel workspace, whose text also says
    /// where its paths are from. One such call is enough beside one that
    /// takes a routed lock.
    #[test]
    fn what_keeps_a_hub_off_the_route_is_named() {
        let unlisted = "its `data` is not written out as a list of strings that holds \
                        `//:pnpm-workspace.yaml`";
        let unstated = "the pnpm it runs for `update_pnpm_lock` is not stated as 11.20 or later";
        let other = format!("{HUB}, data = [\"//web:pnpm-workspace.yaml\"]");
        let named = format!("{LISTING}, use_pnpm = \"@eleven//:package/bin/pnpm.cjs\"");
        let cases = [
            (
                "pnpm_lock = LOCK",
                ELEVEN,
                "its `pnpm_lock` is not written out in a plain string",
            ),
            (
                "**hub",
                ELEVEN,
                "its `pnpm_lock` is not written out in a plain string",
            ),
            (
                "pnpm_lock = \"//:pnpm-lock.yaml\", update_pnpm_lock = UP",
                ELEVEN,
                "its `update_pnpm_lock` is not written out as `True` or `False`",
            ),
            // A `**` may pass any attribute, also beside one that is off.
            (
                "pnpm_lock = \"//:pnpm-lock.yaml\", **MORE",
                ELEVEN,
                "it passes arguments that are not written out",
            ),
            (
                "pnpm_lock = \"//:pnpm-lock.yaml\", update_pnpm_lock = False, **MORE",
                ELEVEN,
                "it passes arguments that are not written out",
            ),
            (HUB, ELEVEN, unlisted),
            (other.as_str(), ELEVEN, unlisted),
            (
                "pnpm_lock = \"//:pnpm-lock.yaml\", update_pnpm_lock = True, data = DATA",
                ELEVEN,
                unlisted,
            ),
            (LISTING, "", unstated),
            (LISTING, "pnpm.pnpm(pnpm_version = \"latest\")", unstated),
            (
                LISTING,
                "pnpm.pnpm(pnpm_version_from = \"//:package.json\")",
                unstated,
            ),
            // A tag whose release is not read may ask for any.
            (
                LISTING,
                "pnpm.pnpm(pnpm_version = \"11.28.10\")\npnpm.pnpm(pnpm_version = PNPM)",
                unstated,
            ),
            // The repository is the one of the tag `pnpm`, under a name
            // the reader does not follow.
            (
                named.as_str(),
                "pnpm.pnpm(pnpm_version = \"11.28.10\")\nuse_repo(pnpm, eleven = \"pnpm\")",
                unstated,
            ),
        ];
        for (hub, pnpm, why) in cases {
            let call = Reader::Call("MODULE.bazel:4".to_string(), why.to_string());
            assert_eq!(reads(hub, pnpm, "", &[LOCK]), Some(call), "{hub}: {pnpm}");
        }
        // A release in full, 11.20.0 or later: a prerelease of it is older,
        // and a number of fewer parts is none that a build was run with.
        let short = "which is not a release of three numbers";
        for (release, said) in [
            ("11.19.0", "11.19.0".to_string()),
            ("10.34.9", "10.34.9".to_string()),
            ("11", "11".to_string()),
            ("11.20", format!("11.20, {short}")),
            ("12", format!("12, {short}")),
            ("11.20.0-rc.1", format!("11.20.0-rc.1, {short}")),
            ("12.0.0-alpha.3", format!("12.0.0-alpha.3, {short}")),
        ] {
            let pnpm = format!("pnpm.pnpm(pnpm_version = \"{release}\")");
            let why = format!("{unstated} (pnpm {said})");
            let call = Reader::Call("MODULE.bazel:4".to_string(), why);
            assert_eq!(reads(LISTING, &pnpm, "", &[LOCK]), Some(call), "{release}");
        }

        // What else a call says: only the attributes of the calls that
        // were built keep a hub on the route, whether it runs a pnpm or
        // not. A `patches` that is keyed by a version names no package of
        // a routed lock, and the other three have a pnpm write the lock.
        let patches = "patches = {\"left-pad@1.3.0\": [\"//:own.patch\"]}";
        for (more, name) in [
            (patches, "patches"),
            (
                "npm_package_lock = \"//:package-lock.json\"",
                "npm_package_lock",
            ),
            ("yarn_lock = \"//:yarn.lock\"", "yarn_lock"),
            ("preupdate = [\"//:fix.js\"]", "preupdate"),
            ("npmrc = \"//:.npmrc\"", "npmrc"),
            ("bins = {\"left-pad@1.3.0\": [\"pad=./bin.js\"]}", "bins"),
        ] {
            let why = format!("its `{name}` is an attribute that no routed lock was built with");
            for hub in [LOCKED, LISTING] {
                let call = Reader::Call("MODULE.bazel:4".to_string(), why.clone());
                let hub = format!("{hub}, {more}");
                assert_eq!(reads(&hub, ELEVEN, "", &[LOCK]), Some(call), "{hub}");
            }
        }
        // The warning names every attribute that was built.
        let call = Reader::Call("MODULE.bazel:4".to_string(), String::new());
        let reason = crate::hosted::guidance::pnpm_registry_bazel_reason(&call).expect("a clause");
        for name in BUILT {
            assert!(reason.contains(&format!("`{name}`")), "{name}: {reason}");
        }

        // The pnpm a tag states is the one the hub runs only where its
        // repository is one of the use of the pnpm extension that every
        // module shares. A repository of another extension under the name
        // of a tag, an isolated use with tags of its own and an
        // `inject_repo` on the extension keep the hub off the route.
        let unshown = "the pnpm it runs for `update_pnpm_lock` is not shown to be the one the \
                       root module states (pnpm 11.28.10): its repository is not taken from the \
                       pnpm extension as every module uses it, or that extension has an isolated \
                       use or an `inject_repo`";
        let by_label =
            |repo: &str| format!("{LISTING}, use_pnpm = \"@{repo}//:package/bin/pnpm.cjs\"");
        let other = "other = use_extension(\"//:ext.bzl\", \"other\")";
        let isolated = format!("iso = use_extension({PNPM_EXTENSION}, isolate = True)");
        for (case, hub, pnpm) in [
            (
                "another extension's `pnpm`",
                by_label("pnpm"),
                format!("{ELEVEN}\n{other}\nuse_repo(other, \"pnpm\")"),
            ),
            (
                "another extension's repository under the name of a tag",
                by_label("eleven"),
                format!(
                    "pnpm.pnpm(name = \"eleven\", pnpm_version = \"11.28.10\")\n{other}\n\
                     use_repo(other, \"eleven\")"
                ),
            ),
            // Only a name of a proxy is followed, and an `isolate` that is
            // not written out as `False` counts as an isolated use.
            (
                "the use of the extension as it stands",
                by_label("eleven"),
                format!(
                    "pnpm.pnpm(name = \"eleven\", pnpm_version = \"11.28.10\")\n\
                     use_repo(use_extension({PNPM_EXTENSION}), \"eleven\")"
                ),
            ),
            (
                "a use that may be isolated",
                by_label("eleven"),
                format!(
                    "same = use_extension({PNPM_EXTENSION}, isolate = ISOLATE)\n\
                     same.pnpm(name = \"eleven\", pnpm_version = \"11.28.10\")\n\
                     use_repo(same, \"eleven\")"
                ),
            ),
            (
                "a tag of an isolated use",
                LISTING.to_string(),
                format!("{isolated}\niso.pnpm(pnpm_version = \"11.28.10\")"),
            ),
            (
                "a repository of an isolated use",
                by_label("pnpm"),
                format!(
                    "{isolated}\niso.pnpm(pnpm_version = \"11.28.10\")\nuse_repo(iso, \"pnpm\")"
                ),
            ),
            (
                "a repository that only an isolated use takes",
                by_label("eleven"),
                format!(
                    "pnpm.pnpm(name = \"eleven\", pnpm_version = \"11.28.10\")\n{isolated}\n\
                     use_repo(iso, \"eleven\")"
                ),
            ),
            (
                "a repository that is injected",
                LISTING.to_string(),
                format!("{ELEVEN}\ninject_repo(pnpm, \"tools\")"),
            ),
        ] {
            let call = Reader::Call("MODULE.bazel:4".to_string(), unshown.to_string());
            assert_eq!(reads(&hub, &pnpm, "", &[LOCK]), Some(call), "{case}");
        }
        // An `override_repo` on the extension leaves its release unread.
        let overridden = format!("{ELEVEN}\noverride_repo(pnpm, pnpm = \"mine\")");
        let call = Reader::Call("MODULE.bazel:4".to_string(), unstated.to_string());
        assert_eq!(reads(LISTING, &overridden, "", &[LOCK]), Some(call));
        // None of this changes what a pin is withheld for: the pnpm 11 of
        // each is one that may reject it, as before.
        for pnpm in [
            format!("{ELEVEN}\n{other}\nuse_repo(other, \"pnpm\")"),
            format!("{isolated}\niso.pnpm(pnpm_version = \"11.28.10\")"),
        ] {
            let said = root(HUB, &pnpm).expect("withheld");
            assert!(
                said.contains("has Bazel run pnpm 11.28.10 to keep"),
                "{said}"
            );
        }

        // Nor does a release that a use of the extension states as a dev
        // dependency count: under `--ignore_dev_dependency` Bazel drops
        // the tag, and the hub runs the pnpm that rules_js picks. Written
        // as `True` or not written out, on the one use or beside a use
        // that every build has.
        let dropped = "the pnpm it runs for `update_pnpm_lock` is not shown to be the one the \
                       root module states (pnpm 11.28.10): a use of the pnpm extension with \
                       `dev_dependency` states a release for it, and Bazel drops such a use \
                       under `--ignore_dev_dependency`";
        let dev = |how: &str| {
            format!(
                "dev = use_extension({PNPM_EXTENSION}, dev_dependency = {how})\n\
                 dev.pnpm(pnpm_version = \"11.28.10\")"
            )
        };
        let on_the_one_use = module(LISTING, ELEVEN).replace(
            &format!("pnpm = use_extension({PNPM_EXTENSION})"),
            &format!("pnpm = use_extension({PNPM_EXTENSION}, dev_dependency = True)"),
        );
        assert_ne!(on_the_one_use, module(LISTING, ELEVEN));
        let files = [
            ("MODULE.bazel", on_the_one_use.as_str()),
            (SETTINGS, "# own\n"),
        ];
        let call = Reader::Call("MODULE.bazel:4".to_string(), dropped.to_string());
        assert_eq!(answered(&files, "").reader, Some(call.clone()));
        for (case, pnpm) in [
            ("a dev dependency", dev("True")),
            ("one that may be", dev("DEV")),
            (
                "beside a use that every build has",
                format!("pnpm.pnpm(pnpm_version = \"11.20.0\")\n{}", dev("True")),
            ),
        ] {
            assert_eq!(
                reads(LISTING, &pnpm, "", &[LOCK]),
                Some(call.clone()),
                "{case}"
            );
            // A hub that runs no pnpm is routed whatever a tag states, and
            // the pin is withheld for such a release as it was.
            assert!(
                matches!(reads(LOCKED, &pnpm, "", &[LOCK]), Some(Reader::Takes(_))),
                "{case}"
            );
            let said = root(HUB, &pnpm).expect("withheld");
            assert!(
                said.contains("has Bazel run pnpm 11.28.10 to keep"),
                "{case}: {said}"
            );
        }
        // A use that says it is none, and a dev tag that states no release
        // or makes another repository, change nothing.
        for pnpm in [
            dev("False"),
            format!(
                "{ELEVEN}\ndev = use_extension({PNPM_EXTENSION}, dev_dependency = True)\n\
                 dev.pnpm(name = \"pnpm\")\ndev.pnpm(name = \"ten\", pnpm_version = \"10.34.9\")"
            ),
        ] {
            assert!(
                matches!(reads(LISTING, &pnpm, "", &[LOCK]), Some(Reader::Takes(_))),
                "{pnpm}"
            );
        }

        // Nor does a release count that a tag states which Bazel may not
        // run as it is written. A tag behind a condition or in a
        // comprehension may not run at all, and one whose `name` is not
        // written out in a plain string, or may come from a `**`, may make
        // another repository: the hub then runs the pnpm that rules_js
        // picks, as it does under a dev dependency. Alone or beside a tag
        // that is plain.
        let shown = |why: &str| {
            let why = format!(
                "the pnpm it runs for `update_pnpm_lock` is not shown to be the one the root \
                 module states (pnpm 11.28.10): {why}"
            );
            Some(Reader::Call("MODULE.bazel:4".to_string(), why))
        };
        let aside = "a tag that states a release for it is not a statement of its own, so it may \
                     not run as it is written";
        let unnamed = "a tag that states a release for it has a `name` that is not written out \
                       in a plain string, so it may make another repository";
        let eleven = "pnpm.pnpm(pnpm_version = \"11.28.10\")";
        for (case, pnpm, why) in [
            (
                "behind a condition",
                format!("{eleven} if False else None"),
                aside,
            ),
            ("behind an `and`", format!("ON and {eleven}"), aside),
            (
                "in a comprehension",
                format!("[{eleven} for _ in ONCE]"),
                aside,
            ),
            (
                "beside a plain tag of an older release",
                format!("pnpm.pnpm(pnpm_version = \"10.34.9\")\nON and {eleven}"),
                aside,
            ),
            (
                "a name that is a name",
                "pnpm.pnpm(name = NAME, pnpm_version = \"11.28.10\")".to_string(),
                unnamed,
            ),
            (
                "a name that `**` may pass",
                "pnpm.pnpm(pnpm_version = \"11.28.10\", **MORE)".to_string(),
                unnamed,
            ),
            (
                "a name that is a name, beside a plain tag",
                format!(
                    "pnpm.pnpm(pnpm_version = \"11.20.0\")\n{}",
                    eleven.replace("(", "(name = NAME, ")
                ),
                unnamed,
            ),
        ] {
            assert_eq!(reads(LISTING, &pnpm, "", &[LOCK]), shown(why), "{case}");
            // A hub that runs no pnpm is routed whatever a tag states.
            assert!(
                matches!(reads(LOCKED, &pnpm, "", &[LOCK]), Some(Reader::Takes(_))),
                "{case}"
            );
            // The pin reads such a tag as it is written, as before: a pnpm
            // 11 that the hub hides the file from withholds it.
            let said = root(HUB, &pnpm).expect("withheld");
            assert!(
                said.contains("has Bazel run pnpm 11.28.10 to keep"),
                "{case}: {said}"
            );
        }
        // A tag that may not run and states no release, or makes another
        // repository by a plain name, changes nothing.
        for more in [
            "ON and pnpm.pnpm(name = \"pnpm\")",
            "ON and pnpm.pnpm(name = \"ten\", pnpm_version = \"10.34.9\")",
        ] {
            let pnpm = format!("{ELEVEN}\n{more}");
            assert!(
                matches!(reads(LISTING, &pnpm, "", &[LOCK]), Some(Reader::Takes(_))),
                "{more}"
            );
        }
        // The `use_repo` that takes the repository of a `use_pnpm` has to
        // run as it is written too: behind a condition, another may take
        // the name.
        let taken = "pnpm.pnpm(name = \"eleven\", pnpm_version = \"11.28.10\")\n\
                     ON and use_repo(pnpm, \"eleven\")";
        let call = Reader::Call("MODULE.bazel:4".to_string(), unshown.to_string());
        assert_eq!(reads(&by_label("eleven"), taken, "", &[LOCK]), Some(call));
        // And so has the call of the hub itself, in either shape: one that
        // may not run is no shape that a routed lock was built with.
        for hub in [LOCKED, LISTING] {
            let module = module(hub, ELEVEN).replace(
                "\nnpm.npm_translate_lock(",
                "\nON and npm.npm_translate_lock(",
            );
            assert_ne!(module, self::module(hub, ELEVEN));
            let files = [("MODULE.bazel", module.as_str()), (SETTINGS, "# own\n")];
            let call = Reader::Call(
                "MODULE.bazel:4".to_string(),
                "it is not a statement of its own, so it may not run as it is written".to_string(),
            );
            assert_eq!(answered(&files, "").reader, Some(call), "{hub}");
        }

        // The lock of a member, by a hub that runs no pnpm.
        let member = "pnpm_lock = \"//packages/a:pnpm-lock.yaml\"";
        let own = Reader::Call(
            "MODULE.bazel:4".to_string(),
            "the lock it reads is a workspace member's own".to_string(),
        );
        let locks = [LOCK, "packages/a/pnpm-lock.yaml"];
        assert_eq!(reads(member, ELEVEN, "", &locks), Some(own));
        // The root lock, beside the members' own
        // (`sharedWorkspaceLockfile: false`): the route records its
        // overrides in every lock, and no build was run of a hub that reads
        // one of several. Whichever of the two shapes the call is in.
        let several = Reader::Call(
            "MODULE.bazel:4".to_string(),
            "the project has workspace members with pnpm locks of their own, a layout that no \
             routed lock was built with"
                .to_string(),
        );
        for hub in [LOCKED, LISTING] {
            assert_eq!(
                reads(hub, ELEVEN, "", &locks),
                Some(several.clone()),
                "{hub}"
            );
        }
        // A project below the Bazel root: its call is in a file of that
        // root, not of the project.
        let below_root = Reader::Call(
            "MODULE.bazel:4, with paths from the root of the Bazel workspace".to_string(),
            "the project is not at the root of the Bazel workspace".to_string(),
        );
        assert_eq!(
            reads(member, ELEVEN, "packages/a", &[LOCK]),
            Some(below_root)
        );

        // Two hubs of the one lock: the one that is off the route decides,
        // whichever comes first.
        let two = |first: &str, second: &str| {
            let module = module(first, ELEVEN);
            let module = format!("{module}npm.npm_translate_lock({second})\n");
            answered(&[("MODULE.bazel", &module), (SETTINGS, "# own\n")], "").reader
        };
        assert!(matches!(two(LOCKED, LOCKED), Some(Reader::Takes(_))));
        for (first, second, line) in [(LOCKED, HUB, 7), (HUB, LOCKED, 4)] {
            let call = Reader::Call(format!("MODULE.bazel:{line}"), unlisted.to_string());
            assert_eq!(two(first, second), Some(call), "{first}");
        }
    }

    /// The pin reads a tag that Bazel may not run as it is written as the
    /// tag is written, as it did before the route looked at such tags: a
    /// pnpm 11 that the hub hides the file from withholds the pin, and a
    /// pnpm 10 withholds none. Taking the release of such a tag for one
    /// that is not written out would withhold the second pin too, which
    /// main writes.
    #[test]
    fn a_tag_that_may_not_run_as_written_changes_no_pin() {
        for tag in [
            "ON and pnpm.pnpm(pnpm_version = \"{}\")",
            "pnpm.pnpm(name = NAME, pnpm_version = \"{}\")",
            "pnpm.pnpm(pnpm_version = \"{}\", **MORE)",
        ] {
            let said = root(HUB, &tag.replace("{}", "11.28.10")).expect("withheld");
            assert!(
                said.contains("has Bazel run pnpm 11.28.10 to keep"),
                "{tag}: {said}"
            );
            assert_eq!(root(HUB, &tag.replace("{}", "10.34.9")), None, "{tag}");
        }
    }

    /// A run that is told not to write to `pnpm-workspace.yaml` gives the
    /// pnpm of a hub no setting to read ([`Hubs::unset`]). Where a hub
    /// lists a file of the user's own that would take the setting, such a
    /// run is told to write nothing for the root lock, and what to do; a
    /// run that writes the setting is told nothing. A file that holds the
    /// setting already, a pnpm 10 and a hub that runs no pnpm withhold
    /// nothing from either, and a hub that hides the file withholds from
    /// both alike.
    #[test]
    fn a_run_told_not_to_write_the_setting_leaves_the_lock_of_a_listing_hub() {
        let asked = |hub: &str, pnpm: &str, settings: &str| {
            let module = module(hub, pnpm);
            answered(&[("MODULE.bazel", &module), (SETTINGS, settings)], "")
        };
        let hubs = asked(LISTING, ELEVEN, "# own\n");
        assert_eq!(hubs.hidden, None);
        assert_eq!(hubs.hides(true), None);
        let unset = hubs.hides(false).expect("withheld");
        assert_eq!(unset.code, HIDDEN);
        assert_eq!(
            unset.detail,
            "MODULE.bazel:4: this `npm.npm_translate_lock` has Bazel run pnpm 11.28.10 to keep \
             pnpm-lock.yaml up to date (`update_pnpm_lock`), and hosted mode does not write \
             `trustLockfile: true` to the pnpm-workspace.yaml that its `data` lists. Without \
             that setting pnpm 11 and later reject a lock that names the patch server \
             (ERR_PNPM_TARBALL_URL_MISMATCH): `bazel build` would fail; pnpm-lock.yaml was not \
             rewritten — let hosted mode write to pnpm-workspace.yaml (this run was told not \
             to, which is `--no-trust-lockfile-config` on the command line, so it writes \
             neither the setting nor the registries that take its place) or set \
             `trustLockfile: true` there yourself and re-run"
        );
        // The hub still takes a routed lock: a run that writes is routed.
        assert!(matches!(hubs.reader, Some(Reader::Takes(_))));

        let ten = "pnpm.pnpm(pnpm_version = \"10.34.9\")";
        for (case, hub, pnpm, settings) in [
            (
                "the setting is there",
                LISTING,
                ELEVEN,
                "# own\ntrustLockfile: true\n",
            ),
            ("pnpm 10", LISTING, ten, "# own\n"),
            ("the pnpm rules_js picks", LISTING, "", "# own\n"),
            ("no pnpm runs", LOCKED, ELEVEN, "# own\n"),
        ] {
            let hubs = asked(hub, pnpm, settings);
            assert_eq!(
                (hubs.hides(true), hubs.hides(false)),
                (None, None),
                "{case}"
            );
        }
        // Hidden from the pnpm of the hub: the one warning for both runs.
        for (hub, settings) in [(HUB, "# own\n"), (LISTING, "trustLockfile: false\n")] {
            let hubs = asked(hub, ELEVEN, settings);
            assert!(hubs.hidden.is_some() && hubs.unset.is_none(), "{hub}");
            assert_eq!(hubs.hides(false), hubs.hidden.as_ref(), "{hub}");
        }
        // Two hubs of the one lock. The first that leaves the file without
        // the setting is the answer for the run that is told not to write,
        // and a later one that hides the file is the answer for both.
        let two = |second: &str| {
            let module = module(LISTING, ELEVEN);
            let module = format!("{module}npm.npm_translate_lock({second})\n");
            answered(&[("MODULE.bazel", &module), (SETTINGS, "# own\n")], "")
        };
        let both = two(LISTING);
        assert_eq!(both.hidden, None);
        let first = both.unset.expect("withheld").detail;
        assert!(first.starts_with("MODULE.bazel:4: "), "{first}");
        let hiding = two(HUB);
        let hidden = hiding.hidden.expect("withheld").detail;
        assert!(hidden.starts_with("MODULE.bazel:7: "), "{hidden}");
        assert_eq!(hiding.unset, None);
    }

    /// One answer asks for each file once, whichever of its three parts
    /// needs it: the `pnpm-workspace.yaml` beside the lock, the
    /// `package.json` that a tag takes its release from, and
    /// `MODULE.bazel.lock`, which says what rules_js picks where no tag
    /// states a release and can be several MiB.
    #[test]
    fn one_answer_asks_for_each_file_once() {
        let from = "pnpm.pnpm(pnpm_version_from = \"//:package.json\")";
        let eleven = "{\"packageManager\": \"pnpm@11.28.10\"}";
        for (pnpm, manifest, want) in [(from, eleven, [1, 1, 0]), ("", "{}", [1, 0, 1])] {
            let module = module(LISTING, pnpm);
            let files = [
                ("MODULE.bazel", module.as_str()),
                (SETTINGS, "# own\n"),
                ("package.json", manifest),
                ("MODULE.bazel.lock", "{}"),
            ];
            let (held, asked) = (holding(&files), std::cell::RefCell::new(Vec::new()));
            let view = |path: &str| {
                asked.borrow_mut().push(path.to_string());
                held(path)
            };
            let hubs = answer(&view, "", &[LOCK.to_string()]);
            // Every part was asked: the pin of a run that writes the
            // setting, the one of a run that does not, and the route.
            assert_eq!(hubs.hidden, None, "{pnpm}");
            assert_eq!(hubs.unset.is_some(), !pnpm.is_empty(), "{pnpm}");
            assert_eq!(
                matches!(hubs.reader, Some(Reader::Takes(_))),
                !pnpm.is_empty(),
                "{pnpm}"
            );
            let asked = asked.borrow();
            let times = |file: &str| asked.iter().filter(|path| *path == file).count();
            assert_eq!(
                [SETTINGS, "package.json", "MODULE.bazel.lock"].map(times),
                want,
                "{pnpm}: {asked:?}"
            );
        }
    }

    /// Where no call that was read reads the lock, the answer is "no hub
    /// reads it" only if the workspace was read whole. A file that
    /// `MODULE.bazel` includes and that is not there, a proxy of the
    /// extension that is handed to something else, and a `WORKSPACE` file
    /// that brings in rules_js each leave a hub that may read the lock, and
    /// say what was not read. A call that does read the lock is named
    /// first. A workspace that is read whole, with a hub of another lock or
    /// with no rules_js at all, has no reader, and neither has one whose
    /// `WORKSPACE` file is about something else.
    #[test]
    fn what_the_reader_may_not_have_seen_counts_as_a_hub_that_may_read_the_lock() {
        let reader = |files: &[(&str, &str)]| {
            let view = |path: &str| match files.iter().find(|(name, _)| *name == path) {
                Some((_, text)) => Entry::Text(text.to_string()),
                None => Entry::Absent,
            };
            answer(&view, "", &[LOCK.to_string()]).reader
        };
        let unseen = |files: &[(&str, &str)]| match reader(files) {
            Some(Reader::Unseen(what)) => what,
            other => panic!("{files:?}: {other:?}"),
        };
        let elsewhere = module("pnpm_lock = \"//tools:pnpm-lock.yaml\"", ELEVEN);
        assert_eq!(reader(&[("MODULE.bazel", &elsewhere)]), None);
        let java = "bazel_dep(name = \"rules_java\", version = \"8.0.0\")\n";
        assert_eq!(reader(&[("MODULE.bazel", java)]), None);

        // A file that is included and not there.
        let including = format!("{elsewhere}include(\"//tools:npm.MODULE.bazel\")\n");
        let what = unseen(&[("MODULE.bazel", &including)]);
        assert!(
            what.starts_with("tools/npm.MODULE.bazel: ") && what.contains("MODULE.bazel:7"),
            "{what}"
        );
        // The same file, there: read, and its hub is the reader, in a
        // shape that takes a routed lock.
        let hub = "npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
                   npm.npm_translate_lock(pnpm_lock = \"//:pnpm-lock.yaml\")\n";
        assert_eq!(
            reader(&[
                ("MODULE.bazel", &including),
                ("tools/npm.MODULE.bazel", hub)
            ]),
            Some(Reader::Takes("tools/npm.MODULE.bazel:2".to_string()))
        );
        // Beside a call that takes a routed lock, what was not read still
        // counts: a hub in it may read the lock in another shape.
        let taking = module(LOCKED, ELEVEN);
        let beside = format!("{taking}include(\"//tools:npm.MODULE.bazel\")\n");
        let what = unseen(&[("MODULE.bazel", &beside)]);
        assert!(what.starts_with("tools/npm.MODULE.bazel: "), "{what}");
        let rule = "npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n";
        let what = unseen(&[("MODULE.bazel", &taking), ("WORKSPACE", rule)]);
        assert!(what.starts_with("WORKSPACE:1: it brings in"), "{what}");
        // A proxy of the extension that is not only called.
        let handed = format!("{elsewhere}register(npm)\n");
        let what = unseen(&[("MODULE.bazel", &handed)]);
        assert!(what.starts_with("MODULE.bazel:7: "), "{what}");
        // The file of the older system, beside module files or alone.
        let rule = "npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n";
        for files in [
            &[("MODULE.bazel", elsewhere.as_str()), ("WORKSPACE", rule)][..],
            &[("WORKSPACE.bazel", rule)],
        ] {
            let what = unseen(files);
            let file = files.last().expect("a file").0;
            assert_eq!(
                what,
                format!(
                    "{file}:1: it brings in rules_js, and a hub that this file defines is not \
                     read"
                )
            );
        }
        // The file brings in rules_js by a `load` from its repository, by a
        // `load` of the hub rule from anywhere, or by a call of the rule
        // under the name a `load` gave it.
        let other = "http_archive(name = \"other\", urls = [\"https://example.test/o.tgz\"])\n";
        for (text, line) in [
            (
                "load(\"@aspect_rules_js//js:repositories.bzl\", \"rules_js_dependencies\")\n",
                1,
            ),
            (
                "load(\"@js//npm:repositories.bzl\", \"npm_translate_lock\")\n",
                1,
            ),
            (
                "load(\"//tools:js.bzl\", lock = \"npm_translate_lock\")\n\nlock(name = \"npm\")\n",
                1,
            ),
        ] {
            let text = format!("{other}{text}");
            let what = unseen(&[("WORKSPACE", text.as_str())]);
            assert!(
                what.starts_with(&format!("WORKSPACE:{}: it brings in rules_js", line + 1)),
                "{text}: {what}"
            );
        }
        // One that only names the workspace defines nothing, and one that
        // defines something else defines no hub of a pnpm lock.
        let named = "workspace(name = \"app\")\n";
        let unrelated = format!("{named}{other}load(\"@other//:deps.bzl\", \"deps\")\n\ndeps()\n");
        for text in [named, unrelated.as_str()] {
            assert_eq!(
                reader(&[("MODULE.bazel", &elsewhere), ("WORKSPACE", text)]),
                None,
                "{text}"
            );
        }
        // One that cannot be read may define anything.
        let unread = |path: &str| match path {
            "WORKSPACE" => Entry::Unreadable("it is not UTF-8".to_string()),
            _ => Entry::Absent,
        };
        let what = answer(&unread, "", &[LOCK.to_string()]).reader;
        assert!(
            matches!(&what, Some(Reader::Unseen(what)) if what.starts_with("WORKSPACE: ")),
            "{what:?}"
        );
        // A lock that is no label may be any.
        let odd = module("pnpm_lock = \"//:a:b\"", ELEVEN);
        assert!(matches!(
            reader(&[("MODULE.bazel", &odd)]),
            Some(Reader::Call(call, _)) if call == "MODULE.bazel:4"
        ));
    }

    /// A checkout and a project in memory with the same files get the same
    /// warning, and a checkout that is no Bazel workspace gets none.
    #[tokio::test]
    async fn a_checkout_and_a_project_in_memory_are_told_the_same() {
        let module = module(HUB, ELEVEN);
        let dir = tempfile::tempdir().expect("a directory");
        let mut project = MemoryProject::new();
        assert_eq!(hidden(&ProjectView::Disk(dir.path())).await, None);
        assert_eq!(hidden(&ProjectView::Memory(&project)).await, None);
        for (name, text) in [
            ("MODULE.bazel", module.as_str()),
            (LOCK, "lockfileVersion: '9.0'\n"),
        ] {
            std::fs::write(dir.path().join(name), text).expect("write");
            project.insert_text(name, text);
        }
        let on_disk = hidden(&ProjectView::Disk(dir.path()))
            .await
            .expect("withheld");
        assert_eq!(on_disk.code, HIDDEN);
        assert!(
            on_disk.detail.starts_with("MODULE.bazel:4: "),
            "{}",
            on_disk.detail
        );
        assert_eq!(hidden(&ProjectView::Memory(&project)).await, Some(on_disk));
        // One read answers both questions, on disk and in memory alike.
        let disk = hubs(&ProjectView::Disk(dir.path()), true, &[]).await;
        assert!(matches!(
            &disk.reader,
            Some(Reader::Call(call, _)) if call == "MODULE.bazel:4"
        ));
        assert_eq!(disk.hidden, hidden(&ProjectView::Disk(dir.path())).await);
        assert_eq!(hubs(&ProjectView::Memory(&project), true, &[]).await, disk);
        // No root lock: nothing to keep out of a run, and the call is
        // still the reader of a member's lock, which a hub of the root lock
        // keeps off the route. No pnpm lock: nothing asked.
        let member = ["packages/a/pnpm-lock.yaml".to_string()];
        let lockless = hubs(&ProjectView::Memory(&project), false, &member).await;
        assert_eq!(lockless.hidden, None);
        assert!(matches!(
            &lockless.reader,
            Some(Reader::Call(call, why))
                if call == "MODULE.bazel:4" && why.starts_with("the project has workspace members")
        ));
        // The same of a run that is told not to write the setting.
        let listing = self::module(LISTING, ELEVEN);
        for (name, text) in [("MODULE.bazel", listing.as_str()), (SETTINGS, "# own\n")] {
            project.insert_text(name, text);
        }
        let view = ProjectView::Memory(&project);
        assert!(hubs(&view, true, &member).await.hides(false).is_some());
        assert_eq!(hubs(&view, false, &member).await.hides(false), None);
        let none = hubs(&ProjectView::Memory(&project), false, &[]).await;
        assert_eq!(none, Hubs::default());
    }
}
