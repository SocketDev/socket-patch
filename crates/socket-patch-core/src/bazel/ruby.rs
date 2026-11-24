//! The sha256 a rules_ruby hub holds a gem to, beside the project's lock.
//!
//! rules_ruby's `ruby.bundle_fetch` tag downloads every gem of its
//! `gemfile_lock` through Bazel's downloader, from the remote the lock
//! names. Its `gem_checksums` is a dict from `<name>-<version>` (the words
//! of the gem's line of the lock, so `<version>-<platform>` for a platform
//! build) to a sha256, and Bazel is given the sha256 of a gem the dict
//! names (`bundle_fetch.bzl` at 1.0.0-rc2). The lock's `CHECKSUMS` section
//! is not Bazel's: Bundler holds the downloaded archives to it afterwards,
//! in the `bundle install` action of the build.
//!
//! Hosted mode points a gem of the lock at the patch registry and puts the
//! sha256 of the patched archive in `CHECKSUMS`. A call that still names
//! the sha256 of the upstream archive then fails the build: Bazel takes
//! the upstream archive from its repository cache under that sha256, and
//! Bundler refuses it for the one of the lock; with an empty cache Bazel
//! refuses the patched archive itself; and with a lock that has no
//! `CHECKSUMS` section the build passes on the upstream gem. With the
//! sha256 of the patched archive in the entry the build takes the patched
//! gem, and so it does without the entry, whatever other gems the dict
//! names (all of it on Bazel 9.3.2, 8.8.2 and 7.7.2).
//!
//! So [`handed`] gives the gem rewriter the `gem_checksums` of every call
//! that may read the project's lock, and [`stands_against`] tells it which
//! gem to leave alone. socket-patch never edits the call.
//!
//! Nothing is evaluated, so some of this is read without certainty, and
//! one rule decides: what is seen of a call that may hold the gem to
//! another sha256 stands against the redirect, because a build that fails
//! outranks a patch that is missed and explained; and what is not seen
//! changes nothing, because withholding wherever a part of the workspace
//! cannot be read would take hosted mode from projects it patches today.
//!
//! - A call counts whether or not it is a statement of its own
//!   ([`Call::whole`]): one in a comprehension or a conditional may run.
//! - A call whose `gemfile_lock` is no label in a plain string may read
//!   any lock, this one too. One that names another file does not count.
//! - A `gem_checksums` that is no dict of strings written out in the call
//!   (a constant, an expression, a `**` argument) may name every gem.
//! - The doubts of the reader ([`Workspace::doubts`], the hub's
//!   [`Tags::doubts`]) say that a call may be hidden. They are not looked
//!   at: a project whose lock no call that is read may read is rewritten
//!   as it is without Bazel.
//! - `rb_bundle_fetch` in the file of the older `WORKSPACE` system
//!   ([`Workspace::legacy`]) is the same rule under that name. Its calls
//!   count unless a tag of the module files names the lock in a plain
//!   string: beside such a tag, Bazel 8 and 9 build from the tag and the
//!   file is a leftover. Which Bazel runs is not known here, so they count
//!   on every release, also where Bazel no longer reads the file. In that
//!   file `workspace(name = "shop")` makes `@shop//` the main repository,
//!   and `@__main__//` is that repository where no name is given.
//! - An entry that is an empty string holds nothing: rules_ruby hands
//!   Bazel no sha256 for it.
//!
//! Not looked at: a call of another Bazel module, a macro of a `.bzl` file
//! that makes the call, a name other than `rb_bundle_fetch` that a
//! `WORKSPACE` file loads the rule under, an `rb_bundle_fetch` beside a tag
//! that names the lock (Bazel 7 reads both files, and a target may use the
//! hub of either), and what the command line or an rc file tells Bazel.
//!
//! [`Tags::doubts`]: super::workspace::Tags::doubts

use std::collections::BTreeMap;
use std::path::Path;

use super::starlark::{Call, Value};
use super::workspace::{disk, Entry, Extension, Repo, Workspace, LEGACY};

/// The code of the warning for a gem that is left alone.
pub const PINNED: &str = "redirect_bazel_gem_checksums_pinned";

/// The key under which the hosted engine hands [`handed`] to the gem
/// rewriter, among the project's files.
pub const KEY: &str = "<socket-patch:bazel-gem-checksums>";

const HUB: Extension<'static> = Extension {
    module: "rules_ruby",
    file: "//ruby:extensions.bzl",
    name: "ruby",
};

/// A call that may read the lock: how a warning names it, and its
/// `gem_checksums`, each gem with its sha256. `None` for one that is not
/// written out.
pub type Held = (String, Option<BTreeMap<String, String>>);

/// Whether the reader asks for the file `path` of a workspace, by its path
/// from the Bazel root: `MODULE.bazel`, a file that one can include, and
/// the names of the `WORKSPACE` file.
pub fn is_workspace_file(path: &str) -> bool {
    path == "MODULE.bazel" || path.ends_with(".MODULE.bazel") || LEGACY.contains(&path)
}

/// Whether `call` reads the lock at `lock`, a path from the Bazel root.
/// `None` when the call does not say so in a plain string. `own` is the
/// name a `WORKSPACE` file gives the main repository, for a call of that
/// file: `@<that name>//` is the main repository there, and under a name
/// that is not written out any repository may be.
fn reads(workspace: &Workspace, call: &Call, lock: &str, own: Option<&Value>) -> Option<bool> {
    match call.arg("gemfile_lock") {
        Some(Value::Str(label)) => {
            let label = workspace.label(label)?;
            if label.path() != lock {
                return Some(false);
            }
            match (&label.repo, own) {
                (Repo::Main, _) => Some(true),
                (Repo::Apparent(repo), Some(Value::Str(own))) => Some(repo == own),
                (Repo::Apparent(_), Some(_)) => None,
                _ => Some(false),
            }
        }
        None if !call.unpacks() => Some(false),
        _ => None,
    }
}

/// The calls of `workspace` that may read the lock at `lock` and have a
/// `gem_checksums`.
fn held(workspace: &Workspace, lock: &str) -> Vec<Held> {
    let tags = workspace.tags(&HUB, "bundle_fetch");
    let read = |call: &Call| reads(workspace, call, lock, None);
    let tags = tags.calls.iter().map(|tag| (tag.file, tag.call));
    let tags: Vec<_> = tags.map(|(file, call)| (file, call, read(call))).collect();
    let named = tags.iter().any(|(.., reads)| *reads == Some(true));
    let may = tags.into_iter().filter(|(.., reads)| *reads != Some(false));
    let mut calls: Vec<(&str, &Call)> = may.map(|(file, call, _)| (file, call)).collect();
    if let Some(Ok((file, legacy))) = workspace.legacy.as_ref().filter(|_| !named) {
        let free = |call: &&Call| call.bind.is_none();
        let naming = legacy
            .calls
            .iter()
            .filter(free)
            .find(|call| call.callee == "workspace");
        // Without a name Bazel calls the main repository `__main__`; one
        // that `**` may pass is not known.
        let (main, unknown) = (Value::Str("__main__".into()), Value::Other);
        let own = match naming {
            Some(call) if call.unpacks() => Some(call.arg("name").unwrap_or(&unknown)),
            Some(call) => Some(call.arg("name").unwrap_or(&main)),
            None => Some(&main),
        };
        let fetches = legacy.calls.iter().filter(free);
        let fetches = fetches.filter(|call| call.callee == "rb_bundle_fetch");
        calls.extend(
            fetches
                .filter(|call| reads(workspace, call, lock, own) != Some(false))
                .map(|call| (file.as_str(), call)),
        );
    }
    let held = |(file, call): (&str, &Call)| {
        let sums = match call.arg("gem_checksums") {
            Some(Value::Dict(sums)) => {
                let sum = |sum: &Value| match sum {
                    Value::Str(sum) => sum.clone(),
                    // Bazel takes no list here: no sha256 of a gem.
                    _ => String::new(),
                };
                Some(
                    sums.iter()
                        .map(|(gem, held)| (gem.clone(), sum(held)))
                        .collect(),
                )
            }
            None if !call.unpacks() => return None,
            _ => None,
        };
        Some((format!("`{}` at {file}:{}", call.callee, call.line), sums))
    };
    calls.into_iter().filter_map(held).collect()
}

/// What the gem rewriter is handed under [`KEY`] for the lock at `lock`, a
/// path from the Bazel root, of the workspace whose files `view` has: the
/// calls that may read the lock, each with its `gem_checksums`, as JSON.
/// `None` when there is no such call.
pub fn handed(view: &dyn Fn(&str) -> Entry, lock: &str) -> Option<String> {
    let held = held(&Workspace::read(view), lock);
    (!held.is_empty()).then(|| serde_json::to_string(&held).expect("strings are JSON"))
}

/// [`handed`] for the lock `lock` in the directory of the project at
/// `project`, read from the checkout. `None` also for a project in no
/// Bazel workspace ([`super::bazel_root`], whose bounds these are).
pub fn handed_on_disk(project: &Path, lock: &str) -> Option<String> {
    let root = super::bazel_root(project)?;
    // Bazel has `/` between the parts of a path on every system.
    let parts = root.project.components();
    let parts = parts.map(|part| part.as_os_str().to_string_lossy());
    let lock: Vec<_> = parts.chain([lock.into()]).collect();
    let view = disk(&root.dir);
    handed(&view, &lock.join("/"))
}

/// The calls that the hosted engine handed over among `files` under
/// [`KEY`]: none for a project it handed none for.
pub fn handed_over(files: &BTreeMap<String, String>) -> Vec<Held> {
    let held = files
        .get(KEY)
        .and_then(|held| serde_json::from_str(held).ok());
    held.unwrap_or_default()
}

/// Why hosted mode leaves version `version` of the gem `name` as it is,
/// with what a warning says of the way on: `None` when none of the calls
/// `held` ([`handed_over`]) stands against the redirect. `builds` is each
/// build of the gem that the redirect pins in the lock `lock`, as the words
/// of its line (`<version>` for the ruby-platform gem, the one build hosted
/// mode redirects; `<version>-<platform>` is a platform build's), with the
/// sha256 of its patched archive.
/// `checked` says that the lock has a `CHECKSUMS` section, and `pinned`
/// that an earlier run pinned the gem already: that pin stays, and the
/// warning says so in place of a redirect that was skipped.
///
/// A call stands against the redirect when it holds one of the builds to
/// another sha256, or has a `gem_checksums` that is not written out. A
/// sha256 is the same one in either case of its letters, as it is for
/// Bazel, and an empty one is none: rules_ruby gives Bazel no sha256 for
/// it. The way on is that sha256 in the entry. To delete the entry is
/// one too where the lock is `checked`: Bundler then holds the gem to that
/// section. Without the section nothing would, so it is not offered. The
/// warning words the way on for the first such call and names the others.
pub fn stands_against(
    held: &[Held],
    name: &str,
    version: &str,
    builds: &[(String, String)],
    lock: &str,
    (checked, pinned): (bool, bool),
) -> Option<String> {
    let entry = |build: &String| format!("{name}-{build}");
    let stale = |sums: &Option<BTreeMap<String, String>>| {
        let stale = builds.iter().filter(|(build, sum)| match sums {
            Some(sums) => {
                let held = sums.get(&entry(build)).filter(|held| !held.is_empty());
                held.is_some_and(|held| !held.eq_ignore_ascii_case(sum))
            }
            None => true,
        });
        stale
            .map(|(build, sum)| (entry(build), sum))
            .collect::<Vec<_>>()
    };
    let standing = held.iter().map(|(call, sums)| (call, sums, stale(sums)));
    let mut standing = standing.filter(|(.., stale)| !stale.is_empty());
    if let Some((call, sums, stale)) = standing.next() {
        let others: Vec<&str> = standing.map(|(call, ..)| call.as_str()).collect();
        let also = match others.is_empty() {
            true => String::new(),
            false => format!(
                ". The same holds for {}: change it there too",
                others.join(" and ")
            ),
        };
        let listed = |each: &dyn Fn(&(String, &String)) -> String| {
            stale.iter().map(each).collect::<Vec<_>>().join(" and ")
        };
        let named = listed(&|(entry, _)| format!("`{entry}`"));
        let change = listed(&|(entry, sum)| format!("`{entry}` to `{sum}`"));
        let (holds, would, way) = match sums {
            Some(_) => (
                format!(
                    "holds {named} to another sha256 in `gem_checksums` than the patched gem has"
                ),
                "would",
                format!("change {change} there"),
            ),
            None => (
                format!(
                    "has a `gem_checksums` that is not written out as a dict of strings, which \
                     may hold {named} to the sha256 of the upstream gem"
                ),
                "could",
                format!("write the dict out in the call and change {change}"),
            ),
        };
        let delete = match checked {
            true => format!(
                ", or delete the gem from the dict (Bundler holds it to the CHECKSUMS section \
                 of {lock}),"
            ),
            false => String::new(),
        };
        // The pin is named as `rollback` selects it, by the gem's base purl:
        // a bare `rollback` would unwind every patch of the project.
        let (left, to, undo) = match pinned {
            false => ("redirect skipped", "patch it", String::new()),
            true => (
                "the pin an earlier run wrote is left as it is",
                "build it patched",
                format!(
                    "; or take that pin out with `socket-patch rollback pkg:gem/{name}@{version}`"
                ),
            ),
        };
        return Some(format!(
            "{name}@{version}: {call} {holds}, so the next Bazel build {would} fail on the \
             patched gem or keep the upstream one; {left} (nothing rewritten). To {to}, \
             {way}{delete} and re-run the hosted scan{undo}. A later `rollback` does not touch \
             the call: put the old sha256 back in a changed entry then{also}"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A root module that asks for the hub under the name `ruby`: a call
    /// after it is on line 4.
    const HEAD: &str = "module(name = \"app\")\n\
                        bazel_dep(name = \"rules_ruby\", version = \"1.0.0-rc2\")\n\
                        ruby = use_extension(\"@rules_ruby//ruby:extensions.bzl\", \"ruby\")\n";
    const LOCK: &str = "gemfile_lock = \"//:Gemfile.lock\"";
    const SUMS: &str = "gem_checksums = {\"a-1.0\": \"11\", \"b-2.0-arm64-darwin\": \"22\"}";
    const TAG: &str = "`ruby.bundle_fetch` at MODULE.bazel:4";
    const RULE: &str = "load(\"@rules_ruby//ruby:deps.bzl\", \"rb_bundle_fetch\")\n\
                        rb_bundle_fetch(name = \"bundle\", gemfile_lock = \"//:Gemfile.lock\", \
                        gem_checksums = {\"a-1.0\": \"11\"})\n";

    /// `HEAD` and one `ruby.bundle_fetch` call with `arguments`.
    fn hub(arguments: &str) -> String {
        format!("{HEAD}ruby.bundle_fetch(name = \"bundle\", {arguments})\n")
    }

    /// What is handed over for `lock` in a workspace of `files`, each a
    /// path and its text.
    fn held_in(files: &[(&str, &str)], lock: &str) -> Vec<Held> {
        let text = |path: &str| files.iter().find(|(name, _)| *name == path);
        let view = |path: &str| match text(path) {
            Some((_, text)) => Entry::Text(text.to_string()),
            None => Entry::Absent,
        };
        let handed = handed(&view, lock);
        handed.map_or(Vec::new(), |handed| serde_json::from_str(&handed).unwrap())
    }

    fn sums(sums: &[(&str, &str)]) -> Option<BTreeMap<String, String>> {
        let owned = |(gem, sum): &(&str, &str)| (gem.to_string(), sum.to_string());
        Some(sums.iter().map(owned).collect())
    }

    #[test]
    fn a_call_is_handed_over_when_it_may_read_the_lock_and_has_gem_checksums() {
        let handed = |arguments: &str, lock: &str| {
            let module = hub(arguments);
            let held = held_in(&[("MODULE.bazel", &module)], lock);
            assert!(held.iter().all(|(call, _)| call == TAG), "{arguments}");
            held.into_iter().map(|(_, sums)| sums).collect::<Vec<_>>()
        };
        // The label of the call's lock, a lock, and whether it is that one:
        // a project below the root, and the spellings of a label.
        let both = sums(&[("a-1.0", "11"), ("b-2.0-arm64-darwin", "22")]);
        for (label, lock, reads) in [
            ("//:Gemfile.lock", "Gemfile.lock", true),
            ("//:Gemfile.lock", "svc/Gemfile.lock", false),
            ("//svc:Gemfile.lock", "svc/Gemfile.lock", true),
            (":Gemfile.lock", "Gemfile.lock", true),
            ("Gemfile.lock", "Gemfile.lock", true),
            ("@//:Gemfile.lock", "Gemfile.lock", true),
            ("@app//:Gemfile.lock", "Gemfile.lock", true),
            ("@other//:Gemfile.lock", "Gemfile.lock", false),
        ] {
            let held = handed(&format!("gemfile_lock = \"{label}\", {SUMS}"), lock);
            let wanted = if reads {
                vec![both.clone()]
            } else {
                Vec::new()
            };
            assert_eq!(held, wanted, "{label} for {lock}");
        }
        // Other arguments, and the `gem_checksums` that are handed over.
        let (one, list) = (sums(&[("a-1.0", "11")]), sums(&[("a-1.0", "")]));
        for (arguments, held) in [
            // No lock, and no `gem_checksums`: the call holds no gem.
            (SUMS.to_string(), None),
            (LOCK.to_string(), None),
            // A lock that is not written out may be this one.
            (
                "gemfile_lock = NAME, gem_checksums = {\"a-1.0\": \"11\"}".into(),
                Some(&one),
            ),
            (
                "gemfile_lock = \"//:\" + N, gem_checksums = {\"a-1.0\": \"11\"}".into(),
                Some(&one),
            ),
            // A `gem_checksums` that is not written out may name every gem.
            (format!("{LOCK}, gem_checksums = HELD"), Some(&None)),
            (
                format!("{LOCK}, gem_checksums = {{\"a-1.0\": HELD}}"),
                Some(&None),
            ),
            (
                format!("{LOCK}, gem_checksums = {{\"a-1.0\": \"11\"}} | HELD"),
                Some(&None),
            ),
            (format!("{LOCK}, **more"), Some(&None)),
            ("**more".to_string(), Some(&None)),
            // A list is no sha256.
            (
                format!("{LOCK}, gem_checksums = {{\"a-1.0\": [\"11\"]}}"),
                Some(&list),
            ),
        ] {
            let held: Vec<_> = held.into_iter().cloned().collect();
            assert_eq!(handed(&arguments, "Gemfile.lock"), held, "{arguments}");
        }
    }

    /// A call that is no statement of its own may run, and counts. The hub
    /// is known by the module and the file that define it, and named as
    /// the file writes it; a tag of another ruleset is none.
    #[test]
    fn a_call_counts_wherever_it_stands_and_under_the_name_of_its_file() {
        let call = format!("ruby.bundle_fetch(name = n, {LOCK}, {SUMS})");
        for statement in [
            format!("[{call} for n in NAMES]"),
            format!("FLAG and {call}"),
        ] {
            let module = format!("{HEAD}{statement}\n");
            let held = held_in(&[("MODULE.bazel", &module)], "Gemfile.lock");
            assert_eq!(held.len(), 1, "{statement}");
            assert_eq!(held[0].0, TAG, "{statement}");
        }
        let included = format!(
            "rb = use_extension(\"@rules_ruby//ruby:extensions.bzl\", \"ruby\")\n\n\
             rb.bundle_fetch({LOCK}, {SUMS})\n"
        );
        let root = "bazel_dep(name = \"rules_ruby\", version = \"1.0.0-rc2\")\n\
                    include(\"//pkg:gems.MODULE.bazel\")\n";
        let files = [("MODULE.bazel", root), ("pkg/gems.MODULE.bazel", &included)];
        let held = held_in(&files, "Gemfile.lock");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].0, "`rb.bundle_fetch` at pkg/gems.MODULE.bazel:3");
        let other = hub(&format!("{LOCK}, {SUMS}")).replace("rules_ruby", "rules_other");
        assert_eq!(held_in(&[("MODULE.bazel", &other)], "Gemfile.lock"), []);
    }

    /// The `rb_bundle_fetch` calls of a `WORKSPACE` file count unless a
    /// tag of the module files names the lock: beside such a tag the file
    /// is a leftover, and the gem stays one that hosted mode patches.
    #[test]
    fn the_workspace_file_counts_unless_a_tag_names_the_lock() {
        let rule = |file: &str| {
            vec![(
                format!("`rb_bundle_fetch` at {file}:2"),
                sums(&[("a-1.0", "11")]),
            )]
        };
        for file in ["WORKSPACE", "WORKSPACE.bazel", "WORKSPACE.bzlmod"] {
            assert_eq!(
                held_in(&[(file, RULE)], "Gemfile.lock"),
                rule(file),
                "{file}"
            );
            assert_eq!(held_in(&[(file, RULE)], "svc/Gemfile.lock"), [], "{file}");
        }
        // The module files, and whether the rule of `WORKSPACE` counts.
        let elsewhere = hub("gemfile_lock = \"//svc:Gemfile.lock\"");
        for (module, counts) in [
            ("module(name = \"app\")\n", true),
            (HEAD, true),
            (elsewhere.as_str(), true),
            (hub(LOCK).as_str(), false),
            // A tag that only may read the lock is no sign of a leftover.
            (hub("gemfile_lock = NAME").as_str(), true),
        ] {
            let files = [("MODULE.bazel", module), ("WORKSPACE", RULE)];
            let handed = if counts {
                rule("WORKSPACE")
            } else {
                Vec::new()
            };
            assert_eq!(held_in(&files, "Gemfile.lock"), handed, "{module}");
        }
        // A name the file binds is not the rule.
        let bound = format!("rb_bundle_fetch = other\n{RULE}");
        assert_eq!(held_in(&[("WORKSPACE", &bound)], "Gemfile.lock"), []);
    }

    /// In a `WORKSPACE` file the name `workspace(name = ...)` gives is the
    /// main repository; one that is not written out may be any name.
    #[test]
    fn a_workspace_file_names_the_main_repository_itself() {
        let fetch = |label: &str| {
            format!("rb_bundle_fetch(gemfile_lock = \"{label}\", gem_checksums = {{\"a-1.0\": \"11\"}})\n")
        };
        // What the file says before the call, the label, and whether the
        // call may read the root's lock.
        for (naming, label, counts) in [
            ("workspace(name = \"shop\")\n", "@shop//:Gemfile.lock", true),
            (
                "workspace(name = \"shop\")\n",
                "@other//:Gemfile.lock",
                false,
            ),
            (
                "workspace(name = \"shop\")\n",
                "@shop//svc:Gemfile.lock",
                false,
            ),
            ("workspace(name = NAME)\n", "@other//:Gemfile.lock", true),
            (
                "workspace(name = NAME)\n",
                "@other//svc:Gemfile.lock",
                false,
            ),
            ("", "@shop//:Gemfile.lock", false),
            // Bazel's own name for a main repository that is not named.
            ("", "@__main__//:Gemfile.lock", true),
            ("workspace()\n", "@__main__//:Gemfile.lock", true),
            ("", "@__main__//svc:Gemfile.lock", false),
            ("workspace(**kw)\n", "@other//:Gemfile.lock", true),
            // A name the file binds is not the call that names it.
            (
                "workspace = other\nworkspace(name = \"shop\")\n",
                "@shop//:Gemfile.lock",
                false,
            ),
        ] {
            let file = format!("{naming}{}", fetch(label));
            let held = held_in(&[("WORKSPACE", &file)], "Gemfile.lock");
            assert_eq!(held.len(), usize::from(counts), "{naming}{label}");
        }
        // A tag is not a call of that file: the module's own name alone is
        // the main repository there.
        let module = hub(&format!("gemfile_lock = \"@shop//:Gemfile.lock\", {SUMS}"));
        let files = [
            ("MODULE.bazel", module.as_str()),
            (
                "WORKSPACE",
                "workspace(name = \"shop\")\nload(\"//:x.bzl\", \"x\")\n",
            ),
        ];
        assert_eq!(held_in(&files, "Gemfile.lock"), []);
    }

    /// What the reader cannot read may hide a call. A call that is read
    /// counts beside it, and where none is read nothing is handed over.
    #[test]
    fn a_doubt_of_the_reader_changes_nothing() {
        let doubtful = |module: String| {
            let module = format!("{module}include(\"//:missing.MODULE.bazel\")\n");
            let files = [("MODULE.bazel", module.as_str())];
            let view = |path: &str| match path {
                "MODULE.bazel" => Entry::Text(module.clone()),
                _ => Entry::Absent,
            };
            assert_eq!(Workspace::read(&view).doubts.len(), 1, "{module}");
            held_in(&files, "Gemfile.lock")
        };
        assert_eq!(doubtful(hub(&format!("{LOCK}, {SUMS}"))).len(), 1);
        assert_eq!(doubtful(hub(LOCK)), []);
        assert_eq!(doubtful(HEAD.to_string()), []);
    }

    #[test]
    fn a_gem_is_left_alone_while_a_call_holds_it_to_another_sha256() {
        // The rewriter gets the calls as the engine handed them over.
        let files = |held: &[Held]| {
            let held = serde_json::to_string(held).unwrap();
            BTreeMap::from([(KEY.to_string(), held)])
        };
        let said = |held: &[Held], builds: &[(&str, &str)], said: (bool, bool)| {
            let owned = |(build, sum): &(&str, &str)| (build.to_string(), sum.to_string());
            let builds: Vec<_> = builds.iter().map(owned).collect();
            let held = handed_over(&files(held));
            stands_against(&held, "a", "1.0", &builds, "Gemfile.lock", said)
        };
        let against = |held: &[Held], builds: &[(&str, &str)], checked: bool| {
            said(held, builds, (checked, false))
        };
        let call = |held: &[(&str, &str)]| (TAG.to_string(), sums(held));
        let ruby = [("1.0", "99")];

        // The entry of another gem, of another build, and one that holds
        // the patched sha256 already, in either case of its letters.
        for held in [
            vec![],
            vec![call(&[])],
            vec![call(&[
                ("b-1.0", "11"),
                ("a-1.0-java", "11"),
                ("a-1.1", "11"),
            ])],
            vec![call(&[("a-1.0", "99")])],
            // An empty entry holds the gem to nothing.
            vec![call(&[("a-1.0", "")])],
        ] {
            assert_eq!(against(&held, &ruby, true), None, "{held:?}");
        }
        let lower = [("1.0", "9a")];
        assert_eq!(against(&[call(&[("a-1.0", "9A")])], &lower, true), None);
        assert!(against(&[call(&[("a-1.0", "9B")])], &lower, true).is_some());
        // A project the engine handed nothing for, and what is no JSON.
        assert_eq!(handed_over(&BTreeMap::new()), []);
        let broken = BTreeMap::from([(KEY.to_string(), "[".to_string())]);
        assert_eq!(handed_over(&broken), []);

        let stale = against(&[call(&[("a-1.0", "11")])], &ruby, true).unwrap();
        assert_eq!(
            stale,
            "a@1.0: `ruby.bundle_fetch` at MODULE.bazel:4 holds `a-1.0` to another sha256 in \
             `gem_checksums` than the patched gem has, so the next Bazel build would fail on \
             the patched gem or keep the upstream one; redirect skipped (nothing rewritten). To \
             patch it, change `a-1.0` to `99` there, or delete the gem from the dict (Bundler \
             holds it to the CHECKSUMS section of Gemfile.lock), and re-run the hosted scan. A \
             later `rollback` does not touch the call: put the old sha256 back in a changed \
             entry then"
        );
        // A pin that an earlier run wrote is not a redirect that was
        // skipped: it stays, and `rollback` takes it out.
        let pinned = said(&[call(&[("a-1.0", "11")])], &ruby, (true, true)).unwrap();
        assert_eq!(
            pinned,
            "a@1.0: `ruby.bundle_fetch` at MODULE.bazel:4 holds `a-1.0` to another sha256 in \
             `gem_checksums` than the patched gem has, so the next Bazel build would fail on \
             the patched gem or keep the upstream one; the pin an earlier run wrote is left as \
             it is (nothing rewritten). To build it patched, change `a-1.0` to `99` there, or \
             delete the gem from the dict (Bundler holds it to the CHECKSUMS section of \
             Gemfile.lock), and re-run the hosted scan; or take that pin out with \
             `socket-patch rollback pkg:gem/a@1.0`. A later `rollback` does not touch the call: put the old \
             sha256 back in a changed entry then"
        );
        // Without the section of the lock nothing but the entry holds the
        // gem to a sha256: to delete it is not offered.
        let unchecked = against(&[call(&[("a-1.0", "11")])], &ruby, false).unwrap();
        assert_eq!(unchecked, stale.replace(", or delete the gem from the dict (Bundler holds it to the CHECKSUMS section of Gemfile.lock),", ""));
        assert!(!unchecked.contains("delete"), "{unchecked}");

        // The first call that stands against it is worded, with every
        // build it holds to another sha256 and no other, and each further
        // call that stands against it is named.
        let builds = [
            ("1.0", "99"),
            ("1.0-java", "88"),
            ("1.0-arm64-darwin", "77"),
        ];
        let held = [
            call(&[("a-1.0", "99")]),
            (
                "`rb_bundle_fetch` at WORKSPACE:2".to_string(),
                sums(&[
                    ("a-1.0", "99"),
                    ("a-1.0-java", "11"),
                    ("a-1.0-arm64-darwin", "11"),
                ]),
            ),
        ];
        let stale = against(&held, &builds, false).unwrap();
        assert!(stale.starts_with("a@1.0: `rb_bundle_fetch` at WORKSPACE:2 holds `a-1.0-java` and `a-1.0-arm64-darwin` to another sha256"), "{stale}");
        assert!(
            stale.contains(
                "change `a-1.0-java` to `88` and `a-1.0-arm64-darwin` to `77` there and re-run"
            ),
            "{stale}"
        );
        assert!(stale.ends_with("in a changed entry then"), "{stale}");
        let third = |at: &str, sums| (format!("`rb.bundle_fetch` at {at}"), sums);
        let more = [
            held[1].clone(),
            third("a.MODULE.bazel:3", sums(&[("a-1.0", "99")])),
            third("b.MODULE.bazel:3", None),
            third("c.MODULE.bazel:3", sums(&[("a-1.0", "11")])),
        ];
        let stale = against(&more, &builds, false).unwrap();
        assert!(
            stale.ends_with(
                "in a changed entry then. The same holds for `rb.bundle_fetch` at \
                 b.MODULE.bazel:3 and `rb.bundle_fetch` at c.MODULE.bazel:3: change it there too"
            ),
            "{stale}"
        );

        // A `gem_checksums` that is not written out may hold every build.
        let unread = against(&[(TAG.to_string(), None)], &ruby, true).unwrap();
        assert_eq!(
            unread,
            "a@1.0: `ruby.bundle_fetch` at MODULE.bazel:4 has a `gem_checksums` that is not \
             written out as a dict of strings, which may hold `a-1.0` to the sha256 of the \
             upstream gem, so the next Bazel build could fail on the patched gem or keep the \
             upstream one; redirect skipped (nothing rewritten). To patch it, write the dict \
             out in the call and change `a-1.0` to `99`, or delete the gem from the dict \
             (Bundler holds it to the CHECKSUMS section of Gemfile.lock), and re-run the hosted \
             scan. A later `rollback` does not touch the call: put the old sha256 back in a \
             changed entry then"
        );
    }

    /// On disk the lock is the one in the project's directory, by its path
    /// from the Bazel root, and a project in no Bazel workspace has none.
    #[test]
    fn a_checkout_is_read_from_its_bazel_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(root.join("svc/api")).unwrap();
        assert_eq!(handed_on_disk(&root.join("svc/api"), "Gemfile.lock"), None);
        let module = hub(&format!("gemfile_lock = \"//svc/api:gems.locked\", {SUMS}"));
        std::fs::write(root.join("MODULE.bazel"), module).unwrap();
        let handed = |project: &str, lock: &str| handed_on_disk(&root.join(project), lock);
        assert!(handed("svc/api", "gems.locked").is_some_and(|held| held.contains(TAG)));
        assert_eq!(handed("svc/api", "Gemfile.lock"), None);
        assert_eq!(handed("svc", "gems.locked"), None);
        assert_eq!(handed("", "gems.locked"), None);
    }

    #[test]
    fn the_files_of_a_workspace_are_known_by_name() {
        for file in [
            "MODULE.bazel",
            "gems.MODULE.bazel",
            "a/b/gems.MODULE.bazel",
            "WORKSPACE",
            "WORKSPACE.bazel",
            "WORKSPACE.bzlmod",
        ] {
            assert!(is_workspace_file(file), "{file}");
        }
        for file in [
            "a/MODULE.bazel",
            "a/WORKSPACE",
            "MODULE.bazel.lock",
            "BUILD.bazel",
            "REPO.bazel",
        ] {
            assert!(!is_workspace_file(file), "{file}");
        }
    }
}
