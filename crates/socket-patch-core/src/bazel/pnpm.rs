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
//! In memory the workspace is the project's own files: path selection
//! asks for the `MODULE.bazel` beside a `pnpm-lock.yaml`, for the files
//! one can include and for the `WORKSPACE` files, and the answer is the
//! one of a checkout with the same files. A Bazel root above the project
//! is not seen there. A
//! `pnpm_version_from` file that was not handed in (one outside the
//! project's own manifests) and `MODULE.bazel.lock` are not there either:
//! the first reads as a release that is not written out, so a lock that a
//! checkout pins can be left as it is in memory.
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

use super::rc::ModuleLock;
use super::starlark::{Arg, Call, How, Value};
use super::workspace::{disk, Doubt, Entry, Extension, Label, Repo, Workspace};
use crate::formats::text::strip_bom;
use crate::hosted::guidance::{is_trust_scaffold, plan_workspace_trust, TrustPlan};
use crate::patch::redirect::RewriteWarning;
use crate::utils::fs::run_blocking;
use crate::utils::package_manager::pinned_version;
use crate::vendor::lock_inventory::{MemoryEntry, MemoryProject, ProjectView};

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

/// The files of an in-memory project, as the workspace reader takes them.
fn memory(project: &MemoryProject) -> impl Fn(&str) -> Entry + '_ {
    |path| match project.get(path) {
        Some(MemoryEntry::Text(text)) => Entry::Text(text.to_string()),
        Some(_) => Entry::Unreadable("it was not handed in as text".to_string()),
        None => Entry::Absent,
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
    /// The hub that reads one of the project's pnpm locks ([`Reader`]):
    /// hosted mode then routes none of them through a named registry.
    pub reader: Option<Reader>,
}

/// A rules_js hub that reads a pnpm lock of the project.
///
/// Hosted mode asks before it routes a patched release through a named
/// registry of pnpm-workspace.yaml, and keeps such a project on the pin
/// that the Bazel legs build, whatever else the call says: with or without
/// `update_pnpm_lock`, and whatever pnpm it runs.
///
/// The lock reader of rules_js is not what holds the route back: it takes
/// a routed lock (measured on macOS: rules_js 3.6.0 on Bazel 9.3.2 builds
/// one, a hub without `update_pnpm_lock`, and the packages it builds hold
/// the patched bytes; so does rules_js 2.9.3 on Bazel 8.8.2). The pnpm of
/// a hub with `update_pnpm_lock` is: it runs in a directory that holds the
/// lock, the `package.json` files and the `data` of the call, so it sees
/// the registries only where the call lists pnpm-workspace.yaml, and
/// without them pnpm 11.28.13 and 12.22.0 reject a routed lock
/// (`ERR_PNPM_MISSING_NAMED_REGISTRY`, measured with
/// `pnpm install --lockfile-only`). It may also be older than the pnpm
/// 11.20 that reads such a lock: rules_js picks a pnpm 10 where the
/// workspace states none. No Bazel leg builds a routed lock with
/// `update_pnpm_lock` yet, and a hub can turn that attribute on at any
/// time, so the answer is the same for every hub that reads the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reader {
    /// The call (`MODULE.bazel:7`) that names one of the locks in a plain
    /// string, or whose `pnpm_lock` is not written out as one, which may.
    /// For a project below the Bazel root the text says that its paths are
    /// from that root, here and in [`Self::Unseen`], as the warning of
    /// [`Hubs::hidden`] does: a run in the project's directory has no file
    /// of that name beside it.
    Call(String),
    /// No such call was read, and the workspace was not read whole: what
    /// could not be read of it, where a hub may be. A doubt of the reader
    /// ([`Workspace::doubts`], the doubts of the hub's tags) as `file:line:
    /// why`, or the `WORKSPACE` file that says more than `workspace(...)`
    /// ([`Workspace::legacy`]), whose repositories no tag lists.
    ///
    /// [`Hubs::hidden`] passes over what was not seen, because withholding
    /// there would take a patch from projects that are patched today. Not
    /// taking the route costs no patch: the project gets the pin it gets
    /// today. So the route is taken only where it is certain that no hub
    /// reads a lock.
    Unseen(String),
}

/// What the Bazel workspace the project of `view` is in says of its pnpm
/// locks `locks` (paths from the project): on disk the workspace of
/// [`super::bazel_root`], read off the async runtime, in memory the
/// project itself, whose files are all there is. Nothing outside a Bazel
/// workspace.
pub async fn hubs(view: &ProjectView<'_>, locks: &[String]) -> Hubs {
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

/// [`Hubs::hidden`] alone, for a caller that asks nothing else.
pub async fn hidden(view: &ProjectView<'_>) -> Option<RewriteWarning> {
    hubs(view, &[]).await.hidden
}

/// [`hubs`] for the project in the directory `project` (from the Bazel
/// root, empty for the root) of the workspace behind `view`.
fn answer(view: &dyn Fn(&str) -> Entry, project: &str, locks: &[String]) -> Hubs {
    let ws = Workspace::read(view);
    let hidden = judge(&ws, view, project).map(|detail| RewriteWarning {
        code: HIDDEN.into(),
        detail,
    });
    let reader = reader(&ws, project, locks);
    Hubs { hidden, reader }
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

/// [`Hubs::reader`] for the locks `locks` of the project in the directory
/// `project` of the workspace `ws`.
fn reader(ws: &Workspace, project: &str, locks: &[String]) -> Option<Reader> {
    let hubs = ws.tags(&extension("npm"), "npm_translate_lock");
    let from = from_root(project);
    let call = hubs.calls.iter().find_map(|tag| {
        let reads = match names(ws, tag.call) {
            Named::File(label) => locks
                .iter()
                .any(|lock| label.path() == below(project, lock)),
            Named::Elsewhere => false,
            Named::Unwritten => true,
        };
        reads.then(|| Reader::Call(format!("{}:{}{from}", tag.file, tag.call.line)))
    });
    if call.is_some() {
        return call;
    }
    // No call that was read reads a lock. That is the answer only where
    // every call was read.
    let doubt = |doubt: &Doubt| match doubt.line {
        0 => format!("{}: {}{from}", doubt.file, doubt.why),
        line => format!("{}:{line}: {}{from}", doubt.file, doubt.why),
    };
    if let Some(unread) = ws.doubts.first().or(hubs.doubts.first()) {
        return Some(Reader::Unseen(doubt(unread)));
    }
    match &ws.legacy {
        Some(Ok((file, _))) => Some(Reader::Unseen(format!(
            "{file} defines repositories of its own, and a hub among them is not looked \
             for{from}"
        ))),
        Some(Err(unread)) => Some(Reader::Unseen(doubt(unread))),
        None => None,
    }
}

/// The text of [`Hubs::hidden`] for the project in the directory `project`
/// (from the Bazel root, empty for the root) of the workspace `ws`, whose
/// other files are read through `view`.
fn judge(ws: &Workspace, view: &dyn Fn(&str) -> Entry, project: &str) -> Option<String> {
    let (lock, settings) = (below(project, LOCK), below(project, SETTINGS));
    let main = |label: &str| ws.label(label).filter(|label| label.repo == Repo::Main);
    let hubs = ws.tags(&extension("npm"), "npm_translate_lock");
    for (file, call) in hubs.calls.iter().map(|tag| (tag.file, tag.call)) {
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
        let listed = |label: &String| main(label).is_some_and(|label| label.path() == settings);
        // `None`: the call lists the file. Else whether its `data` is
        // written out, so that the label is one to add to it.
        let written = match call.arg("data") {
            Some(Value::List(labels)) if labels.iter().any(listed) => None,
            Some(Value::List(_)) => Some(true),
            None => Some(!call.unpacks()),
            _ => Some(false),
        };
        // What the file needs before a pin in the lock is one the build
        // takes and an undo leaves standing.
        let own = format!(
            "put a comment line in {settings} (create the file where there is none: `rollback` \
             removes one that holds only what hosted mode writes, and the call would then name a \
             missing file)"
        );
        let (fix, unset) = match view(&settings) {
            Entry::Absent => (Some(own), false),
            Entry::Text(text) => match plan_workspace_trust(Some(&text)) {
                TrustPlan::UserSet(value) => (
                    Some(format!(
                        "set `trustLockfile: true` in {settings} (it says `trustLockfile: \
                         {value}`, which hosted mode leaves as it is)"
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
                _ if removed_with_the_pin(&text) => (Some(own), false),
                _ => (None, false),
            },
            Entry::Unreadable(_) => (None, false),
        };
        if written.is_none() && fix.is_none() {
            continue;
        }
        let Some(pnpm) = release(ws, view, call) else {
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

/// The pnpm that the hub `hub` runs, when it may be 11 or later: the newest
/// release a tag of its repository states, or that one is not written out,
/// or the one a release of rules_js picks whose choice is not known (the
/// module docs). `None` when all that is stated is older, and when nothing
/// is and [`picks_an_older_pnpm`].
fn release(ws: &Workspace, view: &dyn Fn(&str) -> Entry, hub: &Call) -> Option<String> {
    let unread = "a pnpm whose release is not written out as a version (it may be 11 or later)";
    // Whether a `use_repo` takes the repository `repo` under that very name.
    let taken = |repo: &String| {
        let takes = |call: &&Call| call.bind.is_none() && call.callee == "use_repo";
        let named = |arg: &Arg| arg.how == How::Positional && arg.value == Value::Str(repo.clone());
        let calls = ws.files.iter().flat_map(|(_, file)| &file.calls);
        calls.filter(takes).any(|call| call.args.iter().any(named))
    };
    let repo = match hub.arg("use_pnpm") {
        None if !hub.unpacks() => "pnpm".to_string(),
        Some(Value::Str(label)) => match ws.label(label).map(|label| label.repo) {
            Some(Repo::Apparent(repo)) if taken(&repo) => repo,
            _ => return Some(unread.to_string()),
        },
        _ => return Some(unread.to_string()),
    };
    let tags = ws.tags(&extension("pnpm"), "pnpm");
    // Without a tag, the repository `pnpm` is the one rules_js makes.
    let (mut newest, mut made) = (None::<((u64, u64, u64), String)>, repo == "pnpm");
    let mut read = tags.doubts.is_empty();
    for call in tags.calls.iter().map(|tag| tag.call) {
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
    match newest {
        Some(((major, ..), version)) if major >= 11 => Some(format!("pnpm {version}")),
        _ if !read || !made => Some(unread.to_string()),
        Some(_) => None,
        None if picks_an_older_pnpm(ws, view) => None,
        None => Some(
            "the pnpm that aspect_rules_js picks itself, at a release of the ruleset whose \
             choice is not known here (it may be 11 or later)"
                .to_string(),
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

    /// [`judge`] for the project in `project` of the workspace that holds
    /// `files` and nothing else.
    fn said(files: &[(&str, &str)], project: &str) -> Option<String> {
        let view = |path: &str| match files.iter().find(|(name, _)| *name == path) {
            Some((_, text)) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        };
        judge(&Workspace::read(&view), &view, project)
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
        let set = "set `trustLockfile: true` in pnpm-workspace.yaml (it says `trustLockfile: \
                   false`, which hosted mode leaves as it is)";
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
        let set = "set `trustLockfile: true` in pnpm-workspace.yaml (it says `trustLockfile: \
                   false`, which hosted mode leaves as it is) and re-run";
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

    /// [`Hubs::reader`] names the call of a hub that reads one of the locks
    /// asked about, whatever else the call says, and a call whose lock is
    /// not written out, which may be one of them. A hub that reads another
    /// lock, another repository's, or no hub at all is no reader.
    #[test]
    fn a_hub_reads_the_lock_it_names_whatever_else_it_says() {
        let reads = |hub: &str, project: &str, locks: &[&str]| {
            let module = module(hub, ELEVEN);
            let view = |path: &str| match path {
                "MODULE.bazel" => Entry::Text(module.clone()),
                _ => Entry::Absent,
            };
            let locks: Vec<String> = locks.iter().map(|lock| lock.to_string()).collect();
            answer(&view, project, &locks).reader
        };
        let call = Some(Reader::Call("MODULE.bazel:4".to_string()));
        let listed = format!("{HUB}, data = [\"//:pnpm-workspace.yaml\"]");
        for hub in [LOCKED, HUB, listed.as_str(), "pnpm_lock = LOCK", "**hub"] {
            assert_eq!(reads(hub, "", &[LOCK]), call, "{hub}");
        }
        // The lock of a member, and a project below the Bazel root.
        let member = "pnpm_lock = \"//packages/a:pnpm-lock.yaml\"";
        assert_eq!(reads(member, "", &[LOCK]), None);
        assert_eq!(
            reads(member, "", &[LOCK, "packages/a/pnpm-lock.yaml"]),
            call
        );
        // Its call is in a file of the Bazel root, not of the project.
        let from_root = "MODULE.bazel:4, with paths from the root of the Bazel workspace";
        assert_eq!(
            reads(member, "packages/a", &[LOCK]),
            Some(Reader::Call(from_root.to_string()))
        );
        assert_eq!(reads(LOCKED, "packages/a", &[LOCK]), None);
        // Another repository's lock, and a workspace with no hub.
        assert_eq!(
            reads("pnpm_lock = \"@other//:pnpm-lock.yaml\"", "", &[LOCK]),
            None
        );
        let none = |_: &str| Entry::Absent;
        assert_eq!(answer(&none, "", &[LOCK.to_string()]), Hubs::default());
    }

    /// Where no call that was read reads the lock, the answer is "no hub
    /// reads it" only if the workspace was read whole. A file that
    /// `MODULE.bazel` includes and that is not there, a proxy of the
    /// extension that is handed to something else, and a `WORKSPACE` file
    /// that says more than `workspace(...)` each leave a hub that may read
    /// the lock, and say what was not read. A call that does read the lock
    /// is named first. A workspace that is read whole, with a hub of
    /// another lock or with no rules_js at all, has no reader.
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
        // The same file, there: read, and its hub is the reader.
        let hub = "npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
                   npm.npm_translate_lock(pnpm_lock = \"//:pnpm-lock.yaml\")\n";
        assert_eq!(
            reader(&[
                ("MODULE.bazel", &including),
                ("tools/npm.MODULE.bazel", hub)
            ]),
            Some(Reader::Call("tools/npm.MODULE.bazel:2".to_string()))
        );
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
                    "{file} defines repositories of its own, and a hub among them is not \
                     looked for"
                )
            );
        }
        // One that only names the workspace defines none.
        let named = "workspace(name = \"app\")\n";
        assert_eq!(
            reader(&[("MODULE.bazel", &elsewhere), ("WORKSPACE", named)]),
            None
        );
        // A lock that is no label may be any.
        let odd = module("pnpm_lock = \"//:a:b\"", ELEVEN);
        assert_eq!(
            reader(&[("MODULE.bazel", &odd)]),
            Some(Reader::Call("MODULE.bazel:4".to_string()))
        );
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
        let locks = [LOCK.to_string()];
        let disk = hubs(&ProjectView::Disk(dir.path()), &locks).await;
        assert_eq!(
            disk.reader,
            Some(Reader::Call("MODULE.bazel:4".to_string()))
        );
        assert_eq!(disk.hidden, hidden(&ProjectView::Disk(dir.path())).await);
        assert_eq!(hubs(&ProjectView::Memory(&project), &locks).await, disk);
    }
}
