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
//! [`hidden`] finds such a hub for a project, and hosted mode then writes
//! nothing for the project's pnpm lock. One call of the tag must name the
//! project's `pnpm-lock.yaml` in a plain string and, as far as it is
//! written out, keep it up to date, not list the `pnpm-workspace.yaml`
//! beside it, and run a pnpm that may be 11 or later.
//!
//! The pnpm of a call is the repository its `use_pnpm` names, `@pnpm`
//! without one. A `pnpm.pnpm` tag of that `name` in the root module makes
//! it, from its `pnpm_version` or from the `packageManager` of the
//! `package.json` that its `pnpm_version_from` names, and of several the
//! newest (`npm/private/pnpm_extension.bzl` at 3.6.0; 2.9.3 has both
//! attributes, 2.0.0 the first). Where no tag states a release, rules_js
//! runs one of its own choice: its newest pnpm 10 at 3.x and 4.0.0-alpha.1,
//! its newest pnpm 8 at 2.x. Neither rejects the lock, so nothing is
//! withheld there. A release that another module of the build asks for is
//! not seen.
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
//! asks for the `MODULE.bazel` beside a `pnpm-lock.yaml`, and the answer is
//! the one of a checkout with the same files. A hub in a file that one
//! includes, and a Bazel root above the project, are not seen there.
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

use super::starlark::{Arg, Call, How, Value};
use super::workspace::{disk, Entry, Extension, Repo, Workspace};
use crate::formats::text::strip_bom;
use crate::hosted::guidance::{plan_workspace_trust, TrustPlan, TRUST_SCAFFOLD_LINES};
use crate::patch::redirect::RewriteWarning;
use crate::utils::fs::run_blocking;
use crate::utils::line_endings::eol_eq;
use crate::utils::package_manager::pinned_version;
use crate::vendor::lock_inventory::{MemoryEntry, ProjectView};

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

/// The warning for the project of `view` when a hub hides its
/// `pnpm-workspace.yaml` from a pnpm that may be 11 or later (the module
/// docs), read from the Bazel workspace the project is in: on disk the one
/// of [`super::bazel_root`], in memory the project itself, whose files are
/// all there is. `None` in every other case, and outside a Bazel workspace.
pub async fn hidden(view: &ProjectView<'_>) -> Option<RewriteWarning> {
    let detail = match *view {
        ProjectView::Memory(project) => {
            let read = |path: &str| match project.get(path) {
                Some(MemoryEntry::Text(text)) => Entry::Text(text.to_string()),
                Some(_) => Entry::Unreadable("it was not handed in as text".to_string()),
                None => Entry::Absent,
            };
            judge(&read, "")
        }
        _ => {
            let project = view.disk_root()?.to_path_buf();
            run_blocking(move || {
                let root = super::bazel_root(&project)?;
                // Bazel has `/` between the parts of a path on every system.
                let below = root.project.to_string_lossy();
                let below = below.replace(std::path::MAIN_SEPARATOR, "/");
                let read = disk(&root.dir);
                judge(&read, &below)
            })
            .await
        }
    };
    detail.map(|detail| RewriteWarning {
        code: HIDDEN.into(),
        detail,
    })
}

/// The text of [`hidden`] for the project in the directory `project` (from
/// the Bazel root, empty for the root) of the workspace behind `view`.
fn judge(view: &dyn Fn(&str) -> Entry, project: &str) -> Option<String> {
    let ws = Workspace::read(view);
    let below = |file: &str| match project {
        "" => file.to_string(),
        project => format!("{project}/{file}"),
    };
    let (lock, settings) = (below(LOCK), below(SETTINGS));
    let main = |label: &str| ws.label(label).filter(|label| label.repo == Repo::Main);
    let hubs = ws.tags(&extension("npm"), "npm_translate_lock");
    for (file, call) in hubs.calls.iter().map(|tag| (tag.file, tag.call)) {
        let named = match call.arg("pnpm_lock") {
            Some(Value::Str(label)) => main(label).filter(|label| label.path() == lock),
            _ => None,
        };
        let Some(named) = named else {
            continue;
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
        let written = match call.arg("data") {
            Some(Value::List(labels)) if labels.iter().any(listed) => continue,
            Some(Value::List(_)) => true,
            None => !call.unpacks(),
            _ => false,
        };
        let Some(pnpm) = release(&ws, view, call) else {
            continue;
        };
        // The label of the file beside the lock, in the lock's own package.
        let beside = match named.name.rsplit_once('/') {
            Some((directory, _)) => format!("{directory}/{SETTINGS}"),
            None => SETTINGS.to_string(),
        };
        let label = format!("`//{}:{beside}`", named.package);
        // A `data` that is not written out may hold the label already: it
        // is the call that has to show it.
        let (lists, list) = if written {
            (
                "does not list",
                format!("list {label} in the `data` of that call"),
            )
        } else {
            (
                "is not written out as a list of strings, so it is not known to list",
                format!(
                    "write the `data` of that call out as a list of strings that holds {label}"
                ),
            )
        };
        // A hub that lists the file fails the build once the file is gone,
        // and the undo of a hosted pin removes a file that holds only what
        // hosted mode writes: the file is to hold a line of the user's own.
        let undone = "the call would then name a missing file";
        let create = match view(&settings) {
            Entry::Absent => format!(
                "create {settings} (a comment line is enough; `rollback` removes one that \
                 hosted mode created, and {undone}), "
            ),
            Entry::Text(text) if removed_with_the_pin(&text) => format!(
                "add a comment line to {settings} (`rollback` removes a file that holds only \
                 what hosted mode writes, and {undone}), "
            ),
            _ => String::new(),
        };
        return Some(format!(
            "{file}:{}: this `npm.npm_translate_lock` {has} Bazel run {pnpm} to keep {lock} up \
             to date ({how}), and its `data` {lists} {settings}. That pnpm reads only the lock, \
             the `package.json` files and the `data` of the call, so it would not see the \
             `trustLockfile: true` that hosted mode writes to {settings}, and without it pnpm \
             11 and later reject a lock that names the patch server \
             (ERR_PNPM_TARBALL_URL_MISMATCH): `bazel build` would fail; no pnpm lock was \
             rewritten — {create}{list} and re-run",
            call.line
        ));
    }
    None
}

/// Whether `rollback` removes a `pnpm-workspace.yaml` of this text with a
/// hosted pin: with the setting in it, the file is byte for byte the one
/// hosted mode creates, which the undo cannot tell from the user's own
/// (`cleanup_side_config` of the npm restore).
fn removed_with_the_pin(text: &str) -> bool {
    let pinned = match plan_workspace_trust(Some(text)) {
        TrustPlan::Append(pinned) | TrustPlan::Scaffold(pinned) => pinned,
        TrustPlan::AlreadyTrue => text.to_string(),
        _ => return false,
    };
    let created = format!("{}\n", TRUST_SCAFFOLD_LINES.join("\n"));
    eol_eq(pinned.as_bytes(), created.as_bytes())
}

/// The pnpm that the hub `hub` runs, when it may be 11 or later: the newest
/// release a tag of its repository states, or that one is not written out
/// (the module docs). `None` when no tag states one and when all are older.
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
    let (mut newest, mut made) = (None::<(u64, String)>, repo == "pnpm");
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
        let major = |version: &String| version.split('.').next()?.parse::<u64>().ok();
        match stated.as_ref().and_then(major) {
            Some(major) if newest.as_ref().is_none_or(|(old, _)| major > *old) => {
                newest = stated.map(|version| (major, version));
            }
            Some(_) => {}
            None => read = false,
        }
    }
    match newest {
        Some((major, version)) if major >= 11 => Some(format!("pnpm {version}")),
        _ if !read || !made => Some(unread.to_string()),
        _ => None,
    }
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
        judge(&view, project)
    }

    /// [`said`] for the root project of a workspace with `module` alone.
    fn root(hub: &str, pnpm: &str) -> Option<String> {
        said(&[("MODULE.bazel", &module(hub, pnpm))], "")
    }

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
             fail; no pnpm lock was rewritten — list `//:pnpm-workspace.yaml` in the `data` of \
             that call and re-run"
        );
        // It has none: the file comes first, so that no undo leaves the
        // call with a missing one.
        let (reason, way_on) = listed.split_once(" — ").expect("the way on");
        let created = "create pnpm-workspace.yaml (a comment line is enough; `rollback` removes \
                       one that hosted mode created, and the call would then name a missing \
                       file), ";
        let absent = said_of(&[("MODULE.bazel", &module)]);
        assert_eq!(absent, format!("{reason} — {created}{way_on}"));
        // It has one that the undo of the pin would remove, because with
        // the setting it is the file hosted mode creates: a line first.
        let own = "add a comment line to pnpm-workspace.yaml (`rollback` removes a file that \
                   holds only what hosted mode writes, and the call would then name a missing \
                   file), ";
        let scaffold = format!("{}\n", TRUST_SCAFFOLD_LINES.join("\n"));
        let cases = [
            ("", true),
            ("packages:\n  - '.'\n", true),
            ("packages:\r\n  - '.'\r\n", true),
            (scaffold.as_str(), true),
            ("# mine\npackages:\n  - '.'\n", false),
            ("packages:\n  - 'apps/*'\n", false),
            ("packages:\n  - '.'\ntrustLockfile: false\n", false),
            ("{packages: ['.']}\n", false),
        ];
        for (text, removed) in cases {
            let said = said_of(&[("MODULE.bazel", &module), (SETTINGS, text)]);
            let more = if removed { own } else { "" };
            assert_eq!(said, format!("{reason} — {more}{way_on}"), "{text:?}");
        }
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
        assert!(
            said.contains("to keep web/pnpm-lock.yaml up to date"),
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
    }
}
