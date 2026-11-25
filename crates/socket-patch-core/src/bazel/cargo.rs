//! Whether a rules_rust hub of a Bazel workspace would fail on the registry
//! that hosted mode pins a crate to.
//!
//! A crate_universe hub is a `crate.from_cargo` tag under Bzlmod, or a
//! `crates_repository` call in a `WORKSPACE` file. Its tool, cargo-bazel,
//! links what stands beside each `Cargo.toml` the hub names into a
//! directory of its own, writes a root manifest of its own there and runs
//! cargo there, with the `Cargo.lock` the hub names (`symlink_roots` and
//! `write_root_manifest` in `crate_universe/src/splicing/splicer.rs`). Of
//! the cargo configs of the checkout that cargo is given one, the file the
//! hub names as `cargo_config`, and none when it names none
//! (`setup_cargo_config` in the same file; all of it the same at rules_rust
//! 0.56.0 and 0.75.0). Hosted mode names a registry of its own on the
//! dependency in `Cargo.toml` and defines it in the project's cargo config.
//! A hub that reads the manifest and not that config fails on it
//! (``registry index was not found in any configuration:
//! `socket-patch-<uuid>` ``), and with it every Bazel build that needs the
//! hub: measured on Bazel 9.3.2 (rules_rust 0.75.0) and 7.7.2 (0.56.0) for
//! the hub as the rules_rust README has it, which names no `cargo_config`.
//!
//! [`unread`] finds such a hub for a project, so that the cargo rewriter
//! writes no pin there. It answers from the calls it can see, through
//! [`super::workspace`]:
//!
//! - A hub concerns the project when a label of its `cargo_lockfile` or its
//!   `manifests` is a Cargo file of the project, and also when one of the
//!   two is not written out as a string or a list of strings, or is left
//!   to a `**`: it may read them.
//! - Such a hub is in the way unless its `cargo_config` is one string, the
//!   label of the config the rewriter writes. A config that cannot be read
//!   is not taken for the right one.
//! - A hub that names that config is in the way while the file is there
//!   and holds nothing: `rollback` deletes a config it leaves empty, and
//!   the hub then names a missing file, on which it fails. A comment line
//!   keeps the file. A file that is not there yet is created by the pin.
//! - A call counts whether or not it is a statement of its own
//!   ([`Call::whole`]): one that may run is one that may fail.
//! - When the workspace uses a name bound to the extension in a way that
//!   may hide a call ([`super::workspace::Tags::doubts`]), a hub may read
//!   the project's files, and that is in the way too. The way on is then
//!   that line: there may be no hub to give an attribute.
//! - The calls of a `WORKSPACE` file count when no tag of the module files
//!   concerns the project and the checkout does not name a Bazel from
//!   9.0.0 on, which never reads that file. Bazel 7 reads it beside the
//!   module files, and Bazel 8 when it is told to. Beside a tag that
//!   concerns the project, the file is taken for what a move to Bzlmod
//!   left behind.
//!
//! So a reading that is not certain withholds the pin wherever a hub, or a
//! use of the extension through a name bound to it, is seen: the cost is a
//! patch that waits for one line of the user's, against a build that fails.
//! Where nothing of the kind is seen the answer is `None` and a run is the
//! one it was: a project in no Bazel workspace, a workspace without a
//! crate_universe hub, and a hub whose labels are all written out and name
//! other files.
//!
//! Not seen, and there a hub without the config fails as before:
//!
//! - a hub that another Bazel module declares, and a `crates_repository` in
//!   a `.bzl` file that the `WORKSPACE` file loads or under a name that no
//!   `load` of that file gives it;
//! - a tag called on `use_extension(...)` itself, with no name bound to it,
//!   a `MODULE.bazel` that cannot be read (a link that leads out of the
//!   Bazel root, a file past the reader's bounds), and whatever else the
//!   files of the workspace hide from every answer ([`Workspace::doubts`]),
//!   where no hub is seen;
//! - what Bazel is told by flags and rc files, none of which is read:
//!   `--noenable_bzlmod` has it read the `WORKSPACE` file in place of
//!   module files that make a hub;
//! - a Bazel root above a project that is in no git checkout
//!   ([`super::bazel_root`] looks at the project's own directory there).
//!
//! What the hub's `cargo_config` holds is not looked at either: the
//! registry is defined in the file the rewriter writes, so the hub has to
//! name that file.

use std::path::Path;

use super::rc::declared_release;
use super::starlark::{Call, How, Value};
use super::workspace::{disk, Entry, Extension, Label, Repo, Workspace};

/// The key under which a hosted run hands what [`unread`] says to the
/// cargo rewriter, among its candidate files: no path of a file.
pub const KEY: &str = "<socket-patch:bazel-cargo>";

/// The warning for a crate that hosted mode does not pin because of it.
pub const UNREAD: &str = "redirect_cargo_bazel_config_unread";

/// The module extension whose `from_cargo` tag makes a hub, by the two
/// files that define it at rules_rust 0.56.0 and 0.75.0: `extension.bzl`
/// hands on the `crate` of `extensions.bzl`.
pub(super) const EXTENSIONS: [Extension<'static>; 2] = [
    Extension {
        module: "rules_rust",
        file: "//crate_universe:extensions.bzl",
        name: "crate",
    },
    Extension {
        module: "rules_rust",
        file: "//crate_universe:extension.bzl",
        name: "crate",
    },
];

/// Why hosted mode must not pin a crate of the project at `project`, and
/// what to do about it: a rules_rust hub of the project's Bazel workspace
/// reads, or may read, one of `files` (the `Cargo.lock` and the manifests
/// the rewriter writes, each from the project) and is not seen to name
/// `config`, the cargo config the rewriter writes, from the project too.
/// `None` when no such hub is seen (the module docs say what is), and for a
/// project in no Bazel workspace ([`super::bazel_root`], whose bounds these
/// are), for which nothing is read.
pub fn unread(project: &Path, files: &[String], config: &str) -> Option<String> {
    let root = super::bazel_root(project)?;
    // Bazel has `/` between the parts of a path on every system.
    let parts = root.project.components();
    let parts: Vec<_> = parts
        .map(|part| part.as_os_str().to_string_lossy())
        .collect();
    let view = disk(&root.dir);
    judge(&view, &parts.join("/"), files, config)
}

/// The labels of files of the main repository that `call` gives the
/// attribute `name`: none for an attribute it does not pass. `None` when
/// they are not written out: the attribute is no string and no list of
/// strings, or it is not written and the call passes `**`.
///
/// `own` is the name a `WORKSPACE` file gives the main repository, for a
/// call of that file: `workspace(name = "shop")` makes `@shop//` the main
/// repository there (`WorkspaceGlobals.workspace`, Bazel 7.7.2 and 8.8.2).
/// Under a name that is not written out, any `@name//` may be it.
fn named(ws: &Workspace, own: Option<&Value>, call: &Call, name: &str) -> Option<Vec<Label>> {
    let labels: Vec<&String> = match call.arg(name) {
        None if call.unpacks() => return None,
        None => Vec::new(),
        Some(Value::Str(label)) => vec![label],
        Some(Value::List(labels)) => labels.iter().collect(),
        Some(_) => return None,
    };
    let main = |label: &&String| {
        let label = ws.label(label)?;
        let main = match (&label.repo, own) {
            (Repo::Main, _) => true,
            (Repo::Apparent(repo), Some(Value::Str(own))) => repo == own,
            (Repo::Apparent(_), Some(_)) => true,
            _ => false,
        };
        main.then_some(label)
    };
    Some(labels.iter().filter_map(main).collect())
}

/// What a call that makes a hub says of a project.
enum Hub {
    /// It reads none of the project's Cargo files.
    Other,
    /// It reads them, or may, and names the config the rewriter writes.
    Named,
    /// It is in the way, and this is the warning's text.
    InTheWay(String),
}

/// [`unread`] for the workspace that `view` shows and the project in its
/// directory `project` (empty: the root itself).
fn judge(
    view: &dyn Fn(&str) -> Entry,
    project: &str,
    files: &[String],
    config: &str,
) -> Option<String> {
    let below = |file: &str| match project {
        "" => file.to_string(),
        project => format!("{project}/{file}"),
    };
    let (files, written) = (files.iter().map(|file| below(file)), below(config));
    let files: Vec<String> = files.collect();
    // What stands after the reason, whatever it is, around the first way
    // on, which is the reason's own.
    let withheld = |why: String, way: String| {
        format!(
            "{why}. cargo-bazel hands the cargo it runs no cargo config but the one its hub \
             names, and without {written}, where hosted mode defines the patch registry, that \
             cargo fails on the pinned Cargo.toml (`registry index was not found in any \
             configuration`) and `bazel build` with it; dependency skipped (nothing rewritten). \
             {way}; or use `--mode vendored`, which commits the patched crate and needs no \
             registry"
        )
    };
    let workspace = Workspace::read(view);
    // What the hub that `call` of `file` makes says of the project. `own`
    // is the name a `WORKSPACE` file gives the main repository, for a call
    // of that file.
    let says = |file: &str, call: &Call, own: Option<&Value>| {
        let read = ["cargo_lockfile", "manifests"].map(|name| named(&workspace, own, call, name));
        let ours = |label: &&Label| files.contains(&label.path());
        let first = read.iter().flatten().flatten().find(ours);
        let (reads, how) = match first {
            Some(_) => ("reads", ""),
            None if read.iter().all(Option::is_some) => return Hub::Other,
            None => (
                "may read",
                " (its `cargo_lockfile` or its `manifests` is not written out)",
            ),
        };
        let hub = format!(
            "the rules_rust hub at {file}:{} {reads} the Cargo files of this project{how}",
            call.line
        );
        // A name that is not written out widens what a hub may read, never
        // what names the project's config.
        let own = own.filter(|own| matches!(own, Value::Str(_)));
        let one = matches!(call.arg("cargo_config"), Some(Value::Str(_)));
        let given = named(&workspace, own, call, "cargo_config").unwrap_or_default();
        if one && given.iter().map(Label::path).eq([written.clone()]) {
            // `rollback` deletes a config it leaves empty, and a hub that
            // names a missing file fails.
            return match view(&written) {
                Entry::Text(text) if text.trim().is_empty() => Hub::InTheWay(format!(
                    "{hub} and names {written}, which holds nothing: the `rollback` of a pin \
                     deletes a cargo config it leaves empty, and the hub then fails on the \
                     missing file, and `bazel build` with it; dependency skipped (nothing \
                     rewritten). Put a comment line in {written} and run this command again; \
                     or use `--mode vendored`, which commits the patched crate and needs no \
                     registry"
                )),
                _ => Hub::Named,
            };
        }
        let names = match call.arg("cargo_config") {
            None if !call.unpacks() => "it names no `cargo_config`".to_string(),
            _ => format!(
                "its `cargo_config` is not the label of {written} as one string (the settings \
                 of another file it names belong in {written})"
            ),
        };
        // The label as the hub writes its own: the package of the first of
        // the project's files it names may not be the project's directory.
        let within = |package: &str| match package {
            "" => Some(written.as_str()),
            package => written.strip_prefix(package)?.strip_prefix('/'),
        };
        let label = first.and_then(|label| {
            let name = within(&label.package)?;
            Some(format!("//{}:{name}", label.package))
        });
        let label = label.unwrap_or_else(|| format!("//{project}:{config}"));
        // The file first: a hub that names a missing one fails.
        let way = format!(
            "Commit {written} (where the project has none, create it with a comment line in it: \
             `rollback` deletes a config it leaves empty, and a hub that names a missing file \
             fails), give the hub `cargo_config = \"{label}\"`, the label of that file as one \
             string, and run this command again"
        );
        Hub::InTheWay(withheld(format!("{hub}, and {names}"), way))
    };
    // The tags that make a hub, and the first doubt about one that may be
    // hidden.
    let (mut concerned, mut hidden) = (false, None);
    for extension in &EXTENSIONS {
        let tags = workspace.tags(extension, "from_cargo");
        for tag in &tags.calls {
            match says(tag.file, tag.call, None) {
                Hub::InTheWay(why) => return Some(why),
                Hub::Named => concerned = true,
                Hub::Other => {}
            }
        }
        hidden = hidden.or(tags.doubts.into_iter().next());
    }
    // The calls of a `WORKSPACE` file, where no tag concerns the project
    // and none may be hidden: by the rule's own name, or by one that a
    // `load` gives it.
    if let (false, None, Some(Ok((file, legacy)))) = (concerned, &hidden, &workspace.legacy) {
        let read = declared_release(view).is_none_or(|release| release < (9, 0, 0));
        let rule = Value::Str("crates_repository".to_string());
        let loads = legacy.calls.iter().filter(|call| call.callee == "load");
        let aliases = loads
            .flat_map(|load| &load.args)
            .filter_map(|arg| match &arg.how {
                How::Keyword(alias) if arg.value == rule => Some(alias.as_str()),
                _ => None,
            });
        let names: Vec<&str> = aliases.chain(["crates_repository"]).collect();
        let naming = legacy.calls.iter().find(|call| call.callee == "workspace");
        let own = naming.and_then(|call| call.arg("name"));
        let hubs = legacy
            .calls
            .iter()
            .filter(|call| read && names.contains(&&*call.callee));
        for call in hubs {
            if let Hub::InTheWay(why) = says(file, call, own) {
                return Some(why);
            }
        }
    }
    hidden.map(|doubt| {
        let why = format!(
            "{}:{}: {}, so a rules_rust hub that socket-patch cannot read may take the Cargo \
             files of this project",
            doubt.file, doubt.line, doubt.why
        );
        // No hub to give an attribute: one that is seen may name the config.
        let way = "Write that line as the call of a tag (`crate.from_cargo(...)`) or as \
                   `use_repo(...)` and run this command again: it then pins the crate, or names \
                   the hub that is in the way";
        withheld(why, way.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = ".cargo/config.toml";

    /// The files the rewriter writes for a project with one member.
    fn project_files() -> Vec<String> {
        ["Cargo.lock", "Cargo.toml", "member/Cargo.toml"]
            .map(String::from)
            .to_vec()
    }

    /// A root module that asks for the extension, and `hub` after it.
    fn module(hub: &str) -> String {
        format!(
            "module(name = \"shop\", version = \"0.0.0\")\n\
             bazel_dep(name = \"rules_rust\", version = \"0.75.0\")\n\
             crate = use_extension(\"@rules_rust//crate_universe:extensions.bzl\", \"crate\")\n\
             {hub}\nuse_repo(crate, \"crates\")\n"
        )
    }

    /// A `crate.from_cargo` with `attributes`, each on a line of its own.
    fn hub(attributes: &[&str]) -> String {
        format!("crate.from_cargo(\n    {},\n)", attributes.join(",\n    "))
    }

    /// The attributes of the hub of the rules_rust README.
    const README: [&str; 3] = [
        "name = \"crates\"",
        "cargo_lockfile = \"//:Cargo.lock\"",
        "manifests = [\"//:Cargo.toml\"]",
    ];

    /// What [`judge`] says of the project in `project` of a workspace with
    /// the files `files`.
    fn said(files: &[(&str, &str)], project: &str) -> Option<String> {
        let view = |path: &str| {
            let file = files.iter().find(|(name, _)| *name == path);
            file.map_or(Entry::Absent, |(_, text)| Entry::Text(text.to_string()))
        };
        judge(&view, project, &project_files(), CONFIG)
    }

    /// [`said`] for the root project of a workspace whose `MODULE.bazel`
    /// has the one hub of `attributes`.
    fn of_hub(attributes: &[&str]) -> Option<String> {
        said(&[("MODULE.bazel", &module(&hub(attributes)))], "")
    }

    /// The README hub with `more` attributes.
    fn readme_with<'a>(more: &[&'a str]) -> Vec<&'a str> {
        README.iter().chain(more).copied().collect()
    }

    #[test]
    fn the_hub_of_the_readme_is_in_the_way_and_the_warning_names_both_ways_on() {
        let why = of_hub(&README).expect("the README hub");
        // The call is on line 4 of the file; the attribute, the file to
        // commit and the other mode are named.
        for part in [
            "the rules_rust hub at MODULE.bazel:4 reads the Cargo files of this project, and it \
             names no `cargo_config`. ",
            "where hosted mode defines the patch registry",
            "`registry index was not found in any configuration`",
            "dependency skipped (nothing rewritten)",
            "Commit .cargo/config.toml (where the project has none, create it with a comment \
             line in it: `rollback` deletes a config it leaves empty",
            "give the hub `cargo_config = \"//:.cargo/config.toml\"`, the label of that file as \
             one string, and run this command again; or use `--mode vendored`",
        ] {
            assert!(why.contains(part), "no {part:?} in {why}");
        }
    }

    #[test]
    fn a_hub_that_names_the_config_as_one_string_is_not_in_the_way() {
        for label in [
            "//:.cargo/config.toml",
            ":.cargo/config.toml",
            ".cargo/config.toml",
            "@//:.cargo/config.toml",
            "@@//:.cargo/config.toml",
            // The name the root module has for itself.
            "@shop//:.cargo/config.toml",
        ] {
            let named = format!("cargo_config = \"{label}\"");
            assert_eq!(of_hub(&readme_with(&[&named])), None, "{label}");
        }
        // The legacy file, when that is the one the rewriter writes.
        let files = [(
            "MODULE.bazel",
            &*module(&hub(&readme_with(&["cargo_config = \"//:.cargo/config\""]))),
        )];
        let view = |path: &str| match files.iter().find(|(name, _)| *name == path) {
            Some((_, text)) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        };
        assert_eq!(judge(&view, "", &project_files(), ".cargo/config"), None);
        let other = judge(&view, "", &project_files(), CONFIG).expect("another file");
        assert!(other.contains("its `cargo_config` is not the label of .cargo/config.toml"));
    }

    #[test]
    fn a_config_that_is_another_file_or_cannot_be_read_is_not_taken_for_the_right_one() {
        for config in [
            // Another file, another repository, and no label at all.
            "cargo_config = \"//bazel:cargo.toml\"",
            "cargo_config = \"@other//:.cargo/config.toml\"",
            "cargo_config = \"//:.cargo/../config.toml\"",
            // Not one string.
            "cargo_config = CONFIG",
            "cargo_config = \"//:.cargo/\" + \"config.toml\"",
            "cargo_config = [\"//:.cargo/config.toml\"]",
            "**settings",
        ] {
            let why = of_hub(&readme_with(&[config])).unwrap_or_else(|| panic!("{config}"));
            let said = "reads the Cargo files of this project, and its `cargo_config` is not the \
                        label of .cargo/config.toml as one string (the settings of another file \
                        it names belong in .cargo/config.toml). ";
            assert!(why.contains(said), "{config}: {why}");
        }
    }

    #[test]
    fn a_hub_concerns_the_project_whose_files_it_names_and_no_other() {
        let lock = "cargo_lockfile = \"//:Cargo.lock\"";
        let elsewhere = "cargo_lockfile = \"//third_party:Cargo.lock\"";
        // Each file the rewriter writes, named alone: the lock, the root
        // manifest, a member's, and the lock by the root module's own name.
        for attributes in [
            vec![lock, "manifests = []"],
            vec![elsewhere, "manifests = [\"//:Cargo.toml\"]"],
            vec![
                elsewhere,
                "manifests = [\"//x:Cargo.toml\", \"//member:Cargo.toml\"]",
            ],
            vec![elsewhere, "manifests = [\"//:member/Cargo.toml\"]"],
            vec!["cargo_lockfile = \"@shop//:Cargo.lock\""],
            vec!["manifests = [\"Cargo.toml\"]"],
        ] {
            let why = of_hub(&attributes).unwrap_or_else(|| panic!("{attributes:?}"));
            assert!(
                why.contains(":4 reads the Cargo files"),
                "{attributes:?}: {why}"
            );
        }
        // Other files, the same names in another repository, and a hub
        // that names no file.
        for attributes in [
            vec![elsewhere, "manifests = [\"//third_party:Cargo.toml\"]"],
            vec![
                elsewhere,
                "manifests = [\"//other:Cargo.toml\", \"//:Cargo.Bazel.toml\"]",
            ],
            vec![
                "cargo_lockfile = \"@dep//:Cargo.lock\"",
                "manifests = [\"@dep//:Cargo.toml\"]",
            ],
            vec!["cargo_lockfile = \"@@dep+//:Cargo.lock\""],
            vec!["name = \"crates\""],
        ] {
            assert_eq!(of_hub(&attributes), None, "{attributes:?}");
        }
        // The same hub, seen from each project of the workspace: the one
        // in the directory it names, and its neighbours.
        let nested = hub(&[
            "cargo_lockfile = \"//svc/app:Cargo.lock\"",
            "manifests = [\"//:svc/app/Cargo.toml\"]",
        ]);
        let files = [("MODULE.bazel", &*module(&nested))];
        let why = said(&files, "svc/app").expect("the project of the hub");
        assert!(why.contains("give the hub `cargo_config = \"//svc/app:.cargo/config.toml\"`"));
        assert!(
            why.contains("Commit svc/app/.cargo/config.toml (where"),
            "{why}"
        );
        assert!(
            why.contains("without svc/app/.cargo/config.toml, where"),
            "{why}"
        );
        for project in ["", "svc", "svc/app/tool", "svc/application"] {
            assert_eq!(said(&files, project), None, "{project:?}");
        }
        let right = nested.replace(
            ")",
            "    cargo_config = \"//svc/app:.cargo/config.toml\",\n)",
        );
        assert_eq!(said(&[("MODULE.bazel", &*module(&right))], "svc/app"), None);
        let roots = nested.replace(")", "    cargo_config = \"//:.cargo/config.toml\",\n)");
        assert!(said(&[("MODULE.bazel", &*module(&roots))], "svc/app").is_some());
        // The label the warning gives is written as the hub writes its own:
        // where the hub names the project's files from the root package,
        // the project's directory is no package of its own.
        let flat = hub(&[
            "cargo_lockfile = \"//:svc/app/Cargo.lock\"",
            "manifests = [\"//:svc/app/Cargo.toml\"]",
        ]);
        let why = said(&[("MODULE.bazel", &*module(&flat))], "svc/app").expect("the flat hub");
        let label = "give the hub `cargo_config = \"//:svc/app/.cargo/config.toml\"`";
        assert!(why.contains(label), "{why}");
        let named = flat.replace(
            ")",
            "    cargo_config = \"//:svc/app/.cargo/config.toml\",\n)",
        );
        assert_eq!(said(&[("MODULE.bazel", &*module(&named))], "svc/app"), None);
    }

    /// A hub that names the config is still in the way while that file
    /// holds nothing: the `rollback` of a pin deletes a config it leaves
    /// empty, and the hub then names a missing file. A file with a comment
    /// line stays, and a file that is not there yet is created by the pin,
    /// as before.
    #[test]
    fn a_named_config_that_holds_nothing_is_in_the_way() {
        let right = module(&hub(&readme_with(&[
            "cargo_config = \"//:.cargo/config.toml\"",
        ])));
        for blank in ["", "\n", "  \n\t\n"] {
            let why = said(&[("MODULE.bazel", &right), (CONFIG, blank)], "");
            let why = why.unwrap_or_else(|| panic!("{blank:?}"));
            let said_ = "the rules_rust hub at MODULE.bazel:4 reads the Cargo files of this \
                         project and names .cargo/config.toml, which holds nothing: the \
                         `rollback` of a pin deletes a cargo config it leaves empty, and the hub \
                         then fails on the missing file, and `bazel build` with it; dependency \
                         skipped (nothing rewritten). Put a comment line in .cargo/config.toml \
                         and run this command again; or use `--mode vendored`";
            assert!(why.starts_with(said_), "{blank:?}: {why}");
        }
        for kept in ["# The cargo settings of this project.\n", "[net]\n"] {
            let files = [("MODULE.bazel", &*right), (CONFIG, kept)];
            assert_eq!(said(&files, ""), None, "{kept:?}");
        }
        assert_eq!(said(&[("MODULE.bazel", &right)], ""), None, "no file yet");
    }

    #[test]
    fn a_hub_whose_files_are_not_written_out_may_read_the_project() {
        for attributes in [
            vec!["cargo_lockfile = LOCK", "manifests = [\"//x:Cargo.toml\"]"],
            vec![
                "cargo_lockfile = \"//x:Cargo.lock\"",
                "manifests = MANIFESTS",
            ],
            vec!["manifests = [\"//x:Cargo.toml\"] + MORE"],
            vec!["manifests = [\"//x:Cargo.toml\", MEMBER]"],
            vec!["**hub"],
        ] {
            let why = of_hub(&attributes).unwrap_or_else(|| panic!("{attributes:?}"));
            let said = ":4 may read the Cargo files of this project (its `cargo_lockfile` or \
                        its `manifests` is not written out), and ";
            assert!(why.contains(said), "{attributes:?}: {why}");
            // With the config named as one string it is not in the way.
            let mut named = attributes.clone();
            named.push("cargo_config = \"//:.cargo/config.toml\"");
            assert_eq!(of_hub(&named), None, "{named:?}");
        }
    }

    #[test]
    fn every_call_that_makes_a_hub_counts() {
        let readme = hub(&README);
        let right = hub(&readme_with(&["cargo_config = \"//:.cargo/config.toml\""]));
        let in_the_way = |module: &str, at: &str| {
            let why = said(&[("MODULE.bazel", module)], "");
            let why = why.unwrap_or_else(|| panic!("{module}"));
            assert!(
                why.starts_with(&format!("the rules_rust hub at {at} reads")),
                "{why}"
            );
        };
        // The second of two hubs, one in an included file, one that may
        // not run, and one on a proxy of a dev dependency.
        in_the_way(&module(&format!("{right}\n{readme}")), "MODULE.bazel:10");
        let included = format!(
            "{}include(\"//rust:crates.MODULE.bazel\")\n",
            module(&right)
        );
        let part = module(&readme).replace("module(name = \"shop\", version = \"0.0.0\")\n", "");
        let files = [
            ("MODULE.bazel", &*included),
            ("rust/crates.MODULE.bazel", &*part),
        ];
        let why = said(&files, "").expect("the included hub");
        assert!(
            why.starts_with("the rules_rust hub at rust/crates.MODULE.bazel:3 reads"),
            "{why}"
        );
        in_the_way(&module(&format!("ON and {readme}")), "MODULE.bazel:4");
        let dev = module(&readme).replace("\"crate\")", "\"crate\", dev_dependency = True)");
        in_the_way(&dev, "MODULE.bazel:4");
        // The file that hands the extension on, and another name for the
        // ruleset's repository.
        in_the_way(
            &module(&readme).replace("extensions.bzl", "extension.bzl"),
            "MODULE.bazel:4",
        );
        let renamed = module(&readme)
            .replace(
                "version = \"0.75.0\")",
                "version = \"0.75.0\", repo_name = \"rr\")",
            )
            .replace("@rules_rust//", "@rr//");
        in_the_way(&renamed, "MODULE.bazel:4");
        // Both hubs name the config: none is in the way.
        assert_eq!(
            said(
                &[("MODULE.bazel", &module(&format!("{right}\n{right}")))],
                ""
            ),
            None
        );
    }

    #[test]
    fn a_tag_of_another_extension_is_no_hub() {
        // rules_rs has a tag of the same name, which reads the config of
        // the checkout itself; so may any other module's.
        let rules_rs = "bazel_dep(name = \"rules_rs\", version = \"0.2.2\")\n\
                        crate = use_extension(\"@rules_rs//rs:extensions.bzl\", \"crate\")\n\
                        crate.from_cargo(\n    name = \"crates\",\n    cargo_lock = \
                        \"//:Cargo.lock\",\n    cargo_toml = \"//:Cargo.toml\",\n)\n";
        assert_eq!(said(&[("MODULE.bazel", rules_rs)], ""), None);
        for other in [
            module(&hub(&README)).replace("@rules_rust//", "@rules_other//"),
            module(&hub(&README)).replace("\"crate\")", "\"other\")"),
            module(&hub(&README))
                .replace("//crate_universe:extensions.bzl", "//rust:extensions.bzl"),
            module(&hub(&README)).replace("crate.from_cargo", "crate.from_specs"),
            module("crate.spec(package = \"cfg-if\", version = \"1.0.0\")"),
        ] {
            assert_eq!(said(&[("MODULE.bazel", &other)], ""), None, "{other}");
        }
    }

    #[test]
    fn a_use_of_the_extension_that_may_hide_a_call_is_in_the_way() {
        let right = hub(&readme_with(&["cargo_config = \"//:.cargo/config.toml\""]));
        for (hidden, doubt) in [
            (
                "make = crate.from_cargo",
                "`crate` is used other than to call a tag",
            ),
            (
                "crate.from_cargo.again()",
                "`crate.from_cargo.again` is no call of a tag",
            ),
        ] {
            let why = said(
                &[("MODULE.bazel", &module(&format!("{right}\n{hidden}")))],
                "",
            );
            let why = why.unwrap_or_else(|| panic!("{hidden}"));
            let said = format!(
                "MODULE.bazel:10: {doubt}, so a rules_rust hub that socket-patch cannot read may \
                 take the Cargo files of this project. "
            );
            assert!(why.starts_with(&said), "{hidden}: {why}");
            // The hub that is seen names the config already, and there may
            // be no other: the way on is that line, not an attribute.
            let way = "Write that line as the call of a tag (`crate.from_cargo(...)`) or as \
                       `use_repo(...)` and run this command again: it then pins the crate, or \
                       names the hub that is in the way; or use `--mode vendored`";
            assert!(why.contains(way), "{hidden}: {why}");
            assert!(!why.contains("ive the hub"), "{hidden}: {why}");
        }
    }

    #[test]
    fn nothing_is_said_where_no_hub_is_seen() {
        // No file, a workspace that asks for the extension and makes no
        // hub, and files that cannot be read where no hub is seen.
        assert_eq!(said(&[], ""), None);
        assert_eq!(said(&[("MODULE.bazel", &module(""))], ""), None);
        assert_eq!(said(&[("REPO.bazel", "")], ""), None);
        let doubtful = "module(name = \"shop\")\ninclude(\"//rust:missing.MODULE.bazel\")\n\
                        use_extension(NAME, \"crate\")\n";
        assert_eq!(said(&[("MODULE.bazel", doubtful)], ""), None);
    }

    #[test]
    fn a_workspace_file_counts_where_bazel_may_read_it() {
        let call = |more: &str| {
            format!(
                "workspace(name = \"shop\")\nload(\"@rules_rust//crate_universe:defs.bzl\", \
                 \"crates_repository\")\ncrates_repository(\n    name = \"crates\",\n    \
                 cargo_lockfile = \"//:Cargo.lock\",\n    manifests = [\"//:Cargo.toml\"],\n{more})\n"
            )
        };
        let (readme, right) = (
            call(""),
            call("    cargo_config = \"//:.cargo/config.toml\",\n"),
        );
        for name in ["WORKSPACE", "WORKSPACE.bazel", "WORKSPACE.bzlmod"] {
            let why = said(&[(name, &readme)], "").unwrap_or_else(|| panic!("{name}"));
            let said_ = format!("the rules_rust hub at {name}:3 reads the Cargo files");
            assert!(why.starts_with(&said_), "{why}");
            assert_eq!(said(&[(name, &right)], ""), None, "{name}");
        }
        // Bazel 7 and 8 may read the file, an unnamed release may be one of
        // them, and Bazel 9 never reads it.
        for (release, read) in [
            ("7.7.2", true),
            ("8.8.2", true),
            ("9.3.2", false),
            ("9.x", true),
        ] {
            let files = [("WORKSPACE", &*readme), (".bazelversion", release)];
            assert_eq!(said(&files, "").is_some(), read, "{release}");
        }
        // Beside module files that make a hub the file is what a move to
        // Bzlmod left behind; beside ones that make none it counts.
        let hub_ = hub(&readme_with(&["cargo_config = \"//:.cargo/config.toml\""]));
        let files = [("MODULE.bazel", &*module(&hub_)), ("WORKSPACE", &*readme)];
        assert_eq!(said(&files, ""), None);
        let files = [("MODULE.bazel", &*module("")), ("WORKSPACE", &*readme)];
        assert!(said(&files, "").is_some());
        // A module hub over another project's files leaves the question to
        // the `WORKSPACE` file too: Bazel 7 reads both.
        let tools = hub(&[
            "cargo_lockfile = \"//tools:Cargo.lock\"",
            "manifests = [\"//tools:Cargo.toml\"]",
        ]);
        let files = [("MODULE.bazel", &*module(&tools)), ("WORKSPACE", &*readme)];
        let why = said(&files, "").expect("the WORKSPACE hub beside another project's");
        assert!(
            why.starts_with("the rules_rust hub at WORKSPACE:3 reads"),
            "{why}"
        );
        // `@shop//` is the main repository there, by the name the file
        // gives it; under a name that is not written out any `@name//` may
        // be. Another repository's files are not the project's.
        let own = readme.replace("\"//:", "\"@shop//:");
        let why = said(&[("WORKSPACE", &own)], "").expect("the workspace's own name");
        assert!(
            why.starts_with("the rules_rust hub at WORKSPACE:3 reads"),
            "{why}"
        );
        let own_config = call("    cargo_config = \"@shop//:.cargo/config.toml\",\n");
        assert_eq!(said(&[("WORKSPACE", &own_config)], ""), None);
        let other = readme.replace("\"//:", "\"@other//:");
        assert_eq!(said(&[("WORKSPACE", &other)], ""), None);
        let unnamed = other.replace("name = \"shop\"", "name = NAME");
        assert!(said(&[("WORKSPACE", &unnamed)], "").is_some());
        // That doubt widens what a hub may read, never what names the
        // project's config: there only the checkout by a name that is
        // written out counts.
        let shared = "    cargo_config = \"@shared//:.cargo/config.toml\",\n";
        let unnamed = call(shared).replace("name = \"shop\"", "name = NAME");
        let why = said(&[("WORKSPACE", &unnamed)], "").expect("another repository's config");
        assert!(
            why.contains("its `cargo_config` is not the label of .cargo/config.toml"),
            "{why}"
        );
        // The rule under the name a `load` gives it is the rule.
        let alias = readme
            .replace("\"crates_repository\")", "crates = \"crates_repository\")")
            .replace("crates_repository(", "crates(");
        let why = said(&[("WORKSPACE", &alias)], "").expect("the rule by its loaded name");
        assert!(
            why.starts_with("the rules_rust hub at WORKSPACE:3 reads"),
            "{why}"
        );
        // Not seen: the rule under a name no `load` gives it, and a file
        // that only loads the `.bzl` file that calls it.
        let renamed = readme.replace("crates_repository(", "crates(");
        assert_eq!(said(&[("WORKSPACE", &renamed)], ""), None);
        let loads = "load(\"//:deps.bzl\", \"rust_deps\")\nrust_deps()\n";
        assert_eq!(
            said(&[("WORKSPACE", loads), ("deps.bzl", &readme)], ""),
            None
        );
    }

    /// On disk: the project's own directory, one below the Bazel root of
    /// its checkout, and a project in no Bazel workspace, for which
    /// nothing is read.
    #[test]
    fn the_workspace_of_a_project_is_read_from_its_checkout() {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let write = |rel: &str, text: &str| {
            let path = base.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("repo/.git/HEAD", "ref: refs/heads/main\n");
        write("repo/svc/app/Cargo.toml", "");
        let nested = hub(&[
            "cargo_lockfile = \"//svc/app:Cargo.lock\"",
            "manifests = [\"//svc/app:Cargo.toml\"]",
        ]);
        let (repo, app) = (base.join("repo"), base.join("repo/svc/app"));
        assert_eq!(
            unread(&app, &project_files(), CONFIG),
            None,
            "no workspace file"
        );
        write("repo/MODULE.bazel", &module(&nested));
        let why = unread(&app, &project_files(), CONFIG).expect("the project of the hub");
        assert!(
            why.starts_with("the rules_rust hub at MODULE.bazel:4 reads"),
            "{why}"
        );
        assert_eq!(
            unread(&repo, &project_files(), CONFIG),
            None,
            "the root is another project"
        );
        assert_eq!(unread(&repo.join("svc"), &project_files(), CONFIG), None);
        // A workspace file above the checkout is not this project's.
        write("MODULE.bazel", &module(&hub(&README)));
        std::fs::remove_file(repo.join("MODULE.bazel")).unwrap();
        assert_eq!(
            unread(&repo, &project_files(), CONFIG),
            None,
            "above the checkout"
        );
    }
}
