//! The workspace reader (design 2.2): one Bazel root, read through a
//! [`FileView`] into one [`BazelWorkspace`].
//!
//! The order is the order of the dependencies between the readers. The
//! launcher files, the lock's `lockFileVersion` and the API shapes of
//! `MODULE.bazel` and the rc files give the Bazel line; the line gives the
//! effective rc flags; line and flags give the dependency system; the
//! recognizers turn the file models into hubs; `govern::settle` then
//! decides each hub's liveness and ruleset version. Nothing is evaluated
//! and nothing is guessed: what a reader could not read is in
//! `completeness`, and a gap can refuse a write and never permits one.
//!
//! The model is read once per root and project: the Bazel line is the span
//! over the launcher files from the project directory up to the read
//! boundary (design 2.4), so a model answers for that project and the
//! directories above it and for no other (`govern::governance`). Reads go
//! through the view, which the disk side memoizes
//! (`crawlers::bazel_workspace`): the models of several projects of one
//! root, read through one view, read each file once. Each recognizer opens
//! lock headers and scans BUILD files only where its ruleset is declared,
//! so a workspace pays for the rulesets it uses.
//!
//! Nested roots are read one at a time: every path of a model is relative
//! to its own root. `govern::governance_over` combines their answers.

use super::govern::{self, Standing, RC_IMPORT_UNREADABLE, WORKSPACE_UNREADABLE};
use super::ignore::{IgnoreModel, BAZELIGNORE};
use super::model::{
    BazelWorkspace, BoundaryFiles, CommittedVendorDirs, Completeness, DeclSystem, FileText,
    FileView, Gap, Hub, Liveness, ModuleLock, ModuleModel, OutOfScope, RootRef, RulesetSignal,
    Tier, WorkspaceModel,
};
use super::rc;
use super::rulesets::{self, RecognizeInput};
use super::version::{self, ApiShape, BazelVersion, DepSystem};
use super::workspace_file::WORKSPACE_FILES;

/// What a root holds under the name of a boundary file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Entry {
    /// A file. One that cannot be read is a file too: unreadable is not
    /// absent.
    File,
    /// A directory. It is no boundary file, and Bazel builds beside a
    /// `WORKSPACE/` as beside a `docs/` wherever it does not read the
    /// path (`detect`).
    Directory,
    Absent,
}

/// What the root holds under the boundary name `name`. A read that fails
/// names a directory when the root lists a directory of the name and no
/// file of it. The directory is matched without case: on a disk that
/// folds case `workspace/` answers a read of `WORKSPACE`, and it is
/// listed as it is spelled. With no listing nothing says it is a
/// directory, so it is a file that cannot be read.
fn entry(files: &dyn FileView, name: &str) -> Entry {
    match files.read(name) {
        FileText::Bytes(_) => Entry::File,
        FileText::Absent => Entry::Absent,
        FileText::Unreadable => {
            let listed = files.list("").unwrap_or_default();
            let file = listed.iter().any(|entry| entry == name);
            let directory = |entry: &String| {
                let dir = entry.strip_suffix('/');
                dir.is_some_and(|dir| dir.eq_ignore_ascii_case(name))
            };
            match !file && listed.iter().any(directory) {
                true => Entry::Directory,
                false => Entry::File,
            }
        }
    }
}

/// The vendor directories committed at the root, as the view shows them:
/// each first-level directory that holds a `VENDOR.bazel` or a
/// `.vendorignore` (design 2.6; `bazel vendor` writes one of the two into
/// every directory it fills, probe C11). A marker that is there and
/// cannot be read is a test that went unanswered, as is a root that
/// cannot be listed: a directory behind a link out of the read boundary
/// reads so, and only the disk reader can look there
/// (`crawlers::bazel_workspace`).
fn vendor_dirs(files: &dyn FileView) -> CommittedVendorDirs {
    let Some(listed) = files.list("") else {
        return CommittedVendorDirs {
            dirs: Vec::new(),
            cannot_tell: true,
        };
    };
    let mut found = CommittedVendorDirs::default();
    for dir in listed.iter().filter_map(|entry| entry.strip_suffix('/')) {
        let markers = ["VENDOR.bazel", ".vendorignore"];
        let read = markers.map(|marker| files.read(&format!("{dir}/{marker}")));
        if read
            .iter()
            .any(|marker| matches!(marker, FileText::Bytes(_)))
        {
            found.dirs.push(dir.to_string());
        } else if read.contains(&FileText::Unreadable) {
            found.cannot_tell = true;
        }
    }
    found.dirs.sort();
    found
}

/// The lower bounds `MODULE.bazel` puts on the Bazel line (design 2.4 row
/// 3): an older Bazel stops on each of these.
fn api_shapes(module: Option<&ModuleModel>) -> Vec<ApiShape> {
    let Some(module) = module else {
        return Vec::new();
    };
    let used = [
        (ApiShape::UseRepoRule, !module.repo_rules.is_empty()),
        (ApiShape::Include, module.files.len() > 1),
        (ApiShape::OverrideRepo, !module.repo_overrides.is_empty()),
    ];
    let used = used.into_iter().filter(|(_, used)| *used);
    used.map(|(shape, _)| shape).collect()
}

/// The weakest tier of the file families that declare something Bazel may
/// evaluate; of every family that declares anything when none is live;
/// of the files that exist when nothing is declared. A signal declares
/// something only where Bazel may evaluate its statement: a hub rule
/// nobody followed in a `WORKSPACE` left beside `MODULE.bazel` on Bazel 9
/// must not make the workspace one whose `WORKSPACE` was removed.
///
/// Bazel may evaluate a hub that is live under one of the dependency
/// systems the workspace may run and dead under another, and one that a
/// `MODULE.bazel` statement nobody read may shadow. A `WORKSPACE` hub
/// whose one doubt is the line nobody pinned is left out: governance
/// answers `Undetermined` for it, and its family would make the whole
/// workspace `Refused(LineUnknown)`, which refuses the `MODULE.bazel`
/// hubs that design 8 lets through on an unknown line.
fn tier(ws: &BazelWorkspace) -> Tier {
    let may_run = |hub: &&Hub| match govern::standing(ws, hub) {
        Standing::Is(Liveness::Dead { .. }) => false,
        Standing::Is(_) | Standing::Contested(_) => true,
        Standing::Unknown(gap) => gap.token != govern::BAZEL_LINE_UNKNOWN,
    };
    let live = ws.hubs.iter().filter(may_run);
    let mut families: Vec<DeclSystem> = live.map(|hub| hub.decl.site.system).collect();
    if families.is_empty() {
        families.extend(ws.hubs.iter().map(|hub| hub.decl.site.system));
        let evaluated = |signal: &&RulesetSignal| govern::may_evaluate(ws, &signal.site);
        let signals = ws.signals.iter().filter(evaluated);
        families.extend(signals.map(|signal| signal.site.system));
    }
    if families.is_empty() {
        families.push(match ws.boundary.module_bazel {
            true => DeclSystem::Bzlmod,
            false => DeclSystem::Workspace,
        });
    }
    let rank = |tier: &Tier| match tier {
        Tier::Refused(_) => 0,
        Tier::Legacy => 1,
        Tier::Beta => 2,
        Tier::Supported => 3,
    };
    let tiers = families
        .iter()
        .map(|family| version::tier(&ws.line, *family, &ws.flags));
    tiers.min_by_key(rank).unwrap_or(Tier::Beta)
}

/// Reads the workspace at `root` through `files`. `Err` when the view
/// shows no boundary file there: the root the probe found cannot be read,
/// and "no model" must never be taken for "no Bazel".
pub fn detect(root: &RootRef, files: &dyn FileView) -> Result<BazelWorkspace, Gap> {
    // Each name is classified once. A directory of the name is no
    // boundary file, and has no model unless Bazel stops on it (below).
    let is_file = |name: &str| entry(files, name) == Entry::File;
    let (module_entry, workspace_entry) = (entry(files, "MODULE.bazel"), entry(files, "WORKSPACE"));
    let boundary = BoundaryFiles {
        module_bazel: module_entry == Entry::File,
        repo_bazel: is_file("REPO.bazel"),
        workspace_bazel: is_file("WORKSPACE.bazel"),
        workspace: workspace_entry == Entry::File,
        workspace_bzlmod: is_file("WORKSPACE.bzlmod"),
    };
    let BoundaryFiles {
        module_bazel,
        repo_bazel,
        workspace_bazel,
        workspace,
        ..
    } = boundary;
    if !(module_bazel || repo_bazel || workspace_bazel || workspace) {
        return Err(Gap {
            token: WORKSPACE_UNREADABLE,
            file: String::new(),
            detail: format!(
                "{} holds no MODULE.bazel, REPO.bazel, WORKSPACE.bazel or WORKSPACE that can be \
                 read, so its Bazel workspace is not known",
                root.root.display()
            ),
        });
    }
    let mut module = module_bazel.then(|| ModuleModel::read(files)).flatten();
    let held = [
        boundary.workspace_bazel,
        workspace,
        boundary.workspace_bzlmod,
    ];
    let held = WORKSPACE_FILES.iter().zip(held).filter(|(_, file)| *file);
    let mut workspace_files: Vec<WorkspaceModel> = held
        .filter_map(|(path, _)| WorkspaceModel::read(files, path))
        .collect();
    let module_lock = ModuleLock::read(files);
    let rc = rc::read(files);
    let declared = version::read_declared(root, files);
    let mut shapes = rc.api_shapes();
    shapes.extend(api_shapes(module.as_ref()));
    let line = version::line(&declared, module_lock.lock_file_version(), &shapes);
    let flags = rc.effective(&line);
    let system = version::dep_system(&line, &flags);
    // The directories that count are the ones Bazel stops on. It takes
    // `WORKSPACE.bazel` and `WORKSPACE.bzlmod` only when they are files,
    // opens the path `WORKSPACE` where neither outranks it, and stops on
    // a directory there (`WORKSPACE (Is a directory)` on 7.7.2). From
    // Bazel 7 it reads the path `MODULE.bazel` whatever the dependency
    // system, and stops on a directory (`MODULE.bazel expected but not
    // found`: 7.7.2 with and without `--noenable_bzlmod`, and 9.3.2);
    // Bazel 6 reads it only with Bzlmod on, and builds beside the
    // directory without (6.6.0). The model of such a path says that it
    // was not read, and holds every ecosystem up. Wherever Bazel does not
    // read the path it builds, and the directory means nothing.
    if module_entry == Entry::Directory || workspace_entry == Entry::Directory {
        let worlds = govern::worlds_of(&line, &flags, &system);
        let since_7 = line.hi.is_none_or(|hi| hi >= BazelVersion::new(7, 0, 0));
        if module_entry == Entry::Directory && (since_7 || govern::reads_module(&worlds)) {
            module = ModuleModel::read(files);
        }
        let opened = BoundaryFiles {
            workspace: true,
            ..boundary
        };
        let stops =
            workspace_entry == Entry::Directory && govern::evaluates(&worlds, &opened, "WORKSPACE");
        let unread = WorkspaceModel::read(files, "WORKSPACE").filter(|_| stops);
        let after = usize::from(boundary.workspace_bazel);
        workspace_files.splice(after..after, unread);
    }

    let (mut hubs, mut signals, mut ruleset_gaps) = (Vec::new(), Vec::new(), Vec::new());
    let mut out_of_scope = OutOfScope::default();
    {
        let input = RecognizeInput {
            module: module.as_ref(),
            workspace_files: &workspace_files,
            module_lock: Some(&module_lock).filter(|lock| !matches!(lock, ModuleLock::Absent)),
            flags: Some(&flags),
            line: Some(&line),
            files,
        };
        for (ruleset, recognize) in rulesets::ALL {
            let mut found = recognize(&input);
            hubs.append(&mut found.hubs);
            signals.append(&mut found.signals);
            ruleset_gaps.extend(found.gaps.into_iter().map(|gap| (*ruleset, gap)));
            out_of_scope.bazel_modules += found.out_of_scope.bazel_modules;
            out_of_scope.source_archives += found.out_of_scope.source_archives;
            out_of_scope.report_only_pins += found.out_of_scope.report_only_pins;
        }
    }
    // A macro file is read for every `WORKSPACE`-family file that loads
    // it, and a recognizer walks each of their models: a statement that
    // two of the files run is found twice, as two equal hubs. One
    // declaration is one hub.
    let mut found: Vec<Hub> = Vec::with_capacity(hubs.len());
    for hub in hubs {
        if !found.contains(&hub) {
            found.push(hub);
        }
    }
    let hubs = found;

    let mut gaps = govern::model_gaps(module.as_ref(), &workspace_files, &boundary);
    let hard = flags.gaps().into_iter().filter(|gap| gap.hard);
    gaps.extend(hard.map(|gap| Gap {
        token: RC_IMPORT_UNREADABLE,
        file: gap.file.clone(),
        detail: format!("{} {}", gap.file, gap.detail),
    }));
    if let (DepSystem::Unknown { why }, true) = (&system, gaps.is_empty()) {
        // Bazel itself stops on the tracked rc flags.
        gaps.push(Gap {
            token: WORKSPACE_UNREADABLE,
            file: String::new(),
            detail: why.clone(),
        });
    }
    gaps.extend(ruleset_gaps.iter().map(|(_, gap)| gap.clone()));
    let mut ws = BazelWorkspace {
        root: root.clone(),
        boundary,
        tier: Tier::Beta,
        ignore: IgnoreModel::read(&files.read(BAZELIGNORE)),
        line,
        flags,
        system,
        module,
        workspace_files,
        module_lock,
        hubs,
        signals,
        out_of_scope,
        completeness: match gaps.is_empty() {
            true => Completeness::Exact,
            false => Completeness::Incomplete(gaps),
        },
        ruleset_gaps,
        vendor_dirs: vendor_dirs(files),
        // Links are the disk's to resolve (`crawlers::bazel_workspace`).
        lock_real_dirs: std::collections::BTreeMap::new(),
    };
    govern::settle(&mut ws, files);
    ws.tier = tier(&ws);
    Ok(ws)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::bazel::govern::tests::{read, read_at, JS_MODULE, JS_WORKSPACE, PNPM_LOCK};
    use crate::bazel::model::{FlagState, Governance, HubId, Ruleset};
    use crate::bazel::rc::testing::Files;
    use crate::bazel::version::{BazelVersion, LineEvidence, TierRefusal};
    use crate::crawlers::types::Ecosystem;

    fn tokens(ws: &BazelWorkspace) -> Vec<&'static str> {
        match &ws.completeness {
            Completeness::Exact => Vec::new(),
            Completeness::Incomplete(gaps) => gaps.iter().map(|gap| gap.token).collect(),
        }
    }

    /// "No model" is an error, never an empty workspace: the caller would
    /// take an empty one for a root Bazel governs nothing in.
    #[test]
    fn a_root_without_a_boundary_file_is_an_error() {
        let root = RootRef {
            root: PathBuf::from("/repo/ws"),
            project_rel: String::new(),
            boundary_levels: 0,
        };
        let none = Files::of(&[("BUILD.bazel", ""), ("WORKSPACE.bzlmod", "")]);
        let gap = detect(&root, &none).expect_err("no boundary file");
        assert_eq!(gap.token, WORKSPACE_UNREADABLE);
        assert!(gap.detail.contains("/repo/ws"), "{gap:?}");
        // A directory of the name is no boundary file.
        let dir = Files::of(&[("WORKSPACE/BUILD", "")]).with("WORKSPACE", FileText::Unreadable);
        assert!(detect(&root, &dir).is_err());
        // A file that cannot be read is one, and the model says so.
        let unread = Files::of(&[]).with("MODULE.bazel", FileText::Unreadable);
        let ws = detect(&root, &unread).expect("a root");
        assert!(ws.boundary.module_bazel && !ws.boundary.workspace);
        assert_eq!(tokens(&ws), [WORKSPACE_UNREADABLE]);

        let all = read(&[
            ("MODULE.bazel", ""),
            ("REPO.bazel", ""),
            ("WORKSPACE.bazel", ""),
            ("WORKSPACE", ""),
            ("WORKSPACE.bzlmod", ""),
        ]);
        let BoundaryFiles {
            module_bazel,
            repo_bazel,
            workspace_bazel,
            workspace,
            workspace_bzlmod,
        } = all.boundary;
        assert!(module_bazel && repo_bazel && workspace_bazel && workspace && workspace_bzlmod);
        assert_eq!(
            (all.completeness, all.workspace_files.len()),
            (Completeness::Exact, 3)
        );
    }

    /// A root that holds a directory where a boundary file is looked for:
    /// the read of `name` fails, and the listing spells the directory as
    /// it is on the disk, which on one that folds case need not be how
    /// Bazel spells the file.
    struct Directory<'a> {
        files: Files,
        name: &'a str,
    }

    impl FileView for Directory<'_> {
        fn read(&self, rel: &str) -> FileText {
            match rel == self.name {
                true => FileText::Unreadable,
                false => self.files.read(rel),
            }
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            self.files.list(dir)
        }
    }

    fn beside_directory<'a>(files: &[(&str, &str)], name: &'a str, listed: &str) -> Directory<'a> {
        let inside = format!("{listed}/README.md");
        let files = Files::of(&[files, &[(inside.as_str(), "")]].concat());
        Directory { files, name }
    }

    fn detected(files: &dyn FileView) -> BazelWorkspace {
        let root = RootRef {
            root: PathBuf::from("/repo"),
            project_rel: String::new(),
            boundary_levels: 0,
        };
        detect(&root, files).expect("a workspace")
    }

    /// A directory named like a boundary file is no boundary file. Real
    /// Bazel 9.3.2 builds beside `WORKSPACE/` and beside `workspace/`,
    /// 8.8.2 beside `workspace/`, and 7.7.2 beside `WORKSPACE/` where a
    /// `WORKSPACE.bazel` or a `WORKSPACE.bzlmod` file outranks it. On a
    /// disk that folds case the read of `WORKSPACE` fails for
    /// `workspace/` too, and the listing spells it as it is.
    #[test]
    fn a_directory_named_like_a_workspace_file_is_no_boundary_file() {
        let npm = |ws: &BazelWorkspace| govern::governance(ws, Ecosystem::Npm, "");
        let governed = Governance::Governed(vec![HubId(0)]);
        let module = [
            (".bazelversion", "9.3.2\n"),
            ("MODULE.bazel", JS_MODULE),
            PNPM_LOCK,
        ];
        for (name, listed) in [
            ("WORKSPACE", "WORKSPACE"),
            ("WORKSPACE", "workspace"),
            ("WORKSPACE.bzlmod", "workspace.bzlmod"),
            ("WORKSPACE.bazel", "Workspace.Bazel"),
            ("REPO.bazel", "repo.bazel"),
        ] {
            let ws = detected(&beside_directory(&module, name, listed));
            let what = format!("`{listed}/` on 9.3.2");
            let only = BoundaryFiles {
                module_bazel: true,
                ..BoundaryFiles::default()
            };
            assert_eq!(ws.boundary, only, "{what}");
            assert_eq!(ws.workspace_files, [], "{what}");
            assert_eq!(ws.completeness, Completeness::Exact, "{what}");
            assert_eq!(npm(&ws), governed, "{what}");
            let pypi = govern::governance(&ws, Ecosystem::Pypi, "");
            assert_eq!(pypi, Governance::NotGoverned, "{what}");
        }
        // A `MODULE.bazel/` is no module file either. Bazel 6.6.0 reads
        // no module file unless Bzlmod is switched on, and builds from
        // the `WORKSPACE` beside the directory.
        let files = [
            (".bazelversion", "6.6.0\n"),
            (".bazelrc", ""),
            ("WORKSPACE", JS_WORKSPACE),
            PNPM_LOCK,
        ];
        let ws = detected(&beside_directory(&files, "MODULE.bazel", "module.bazel"));
        assert!(!ws.boundary.module_bazel && ws.module.is_none());
        assert_eq!(ws.completeness, Completeness::Exact);
        assert_eq!(npm(&ws), governed);
        // From Bazel 7 the path is read whatever the dependency system,
        // and Bazel stops on the directory (`MODULE.bazel expected but
        // not found`: 7.7.2 with and without `--noenable_bzlmod`, 9.3.2).
        // So it does wherever Bazel 6 may run with Bzlmod on.
        for (version, rc) in [
            ("7.7.2\n", ""),
            ("7.7.2\n", "common --noenable_bzlmod\n"),
            ("9.3.2\n", ""),
            ("6.6.0\n", "common:mod --enable_bzlmod\n"),
        ] {
            let what = format!("Bazel {} with {rc:?}", version.trim());
            let pinned = [(".bazelversion", version), (".bazelrc", rc)];
            let files = [&pinned[..], &files[2..]].concat();
            let ws = detected(&beside_directory(&files, "MODULE.bazel", "MODULE.bazel"));
            assert!(!ws.boundary.module_bazel, "{what}");
            assert_eq!(tokens(&ws), [WORKSPACE_UNREADABLE], "{what}");
            let Governance::Undetermined(gaps) = npm(&ws) else {
                panic!("{what}: Bazel stops on `MODULE.bazel/`");
            };
            assert_eq!(gaps[0].file, "MODULE.bazel", "{what}");
            assert!(gaps[0].detail.contains("is a directory"), "{:?}", gaps[0]);
        }

        // Bazel 7 takes `WORKSPACE.bazel` and never opens `WORKSPACE`.
        let files = [
            (".bazelversion", "7.7.2\n"),
            ("WORKSPACE.bazel", JS_WORKSPACE),
            PNPM_LOCK,
        ];
        for listed in ["WORKSPACE", "workspace"] {
            let ws = detected(&beside_directory(&files, "WORKSPACE", listed));
            assert!(ws.boundary.workspace_bazel && !ws.boundary.workspace);
            assert_eq!(ws.workspace_files.len(), 1, "`{listed}/`");
            assert_eq!(ws.completeness, Completeness::Exact, "`{listed}/`");
            assert_eq!(npm(&ws), governed, "`{listed}/`");
        }

        // The one case Bazel itself stops on: it reads the family, no
        // `WORKSPACE.bazel` or `WORKSPACE.bzlmod` file outranks the path,
        // and the path is a directory (`WORKSPACE (Is a directory)` on
        // 7.7.2).
        let hybrid = [
            (".bazelversion", "7.7.2\n"),
            ("MODULE.bazel", JS_MODULE),
            PNPM_LOCK,
        ];
        for listed in ["WORKSPACE", "workspace"] {
            let ws = detected(&beside_directory(&hybrid, "WORKSPACE", listed));
            assert!(!ws.boundary.workspace, "`{listed}/`");
            assert_eq!(tokens(&ws), [WORKSPACE_UNREADABLE], "`{listed}/`");
            for ecosystem in [Ecosystem::Npm, Ecosystem::Pypi] {
                let found = govern::governance(&ws, ecosystem, "");
                let Governance::Undetermined(gaps) = &found else {
                    panic!("`{listed}/`: {found:?}");
                };
                let [gap] = &gaps[..] else {
                    panic!("`{listed}/`: one gap, not {gaps:?}");
                };
                assert_eq!(
                    (gap.token, gap.file.as_str()),
                    (WORKSPACE_UNREADABLE, "WORKSPACE")
                );
                assert!(gap.detail.contains("is a directory"), "{gap:?}");
            }
        }
        // Under a config that may switch the family on, likewise.
        let maybe = [
            &module[1..],
            &[
                (".bazelversion", "8.8.2\n"),
                (".bazelrc", "common:ws --enable_workspace\n"),
            ],
        ]
        .concat();
        let ws = detected(&beside_directory(&maybe, "WORKSPACE", "WORKSPACE"));
        assert_eq!(tokens(&ws), [WORKSPACE_UNREADABLE]);
        assert!(matches!(npm(&ws), Governance::Undetermined(_)));
        // With `WORKSPACE.bzlmod` Bazel 7 does not open the path at all
        // while Bzlmod is on.
        let replaced = [&hybrid[..], &[("WORKSPACE.bzlmod", "")]].concat();
        let ws = detected(&beside_directory(&replaced, "WORKSPACE", "WORKSPACE"));
        assert_eq!(ws.completeness, Completeness::Exact);
        assert_eq!(npm(&ws), governed);

        // A file of the name that cannot be read is a boundary file, and
        // so is a name the root cannot be asked about.
        let unread = Files::of(&hybrid).with("WORKSPACE", FileText::Unreadable);
        let ws = detected(&unread);
        assert!(ws.boundary.workspace);
        assert_eq!(tokens(&ws), [WORKSPACE_UNREADABLE]);
        let Governance::Undetermined(gaps) = npm(&ws) else {
            panic!("an unreadable WORKSPACE on 7.7.2");
        };
        assert!(gaps[0].detail.contains("cannot be read"), "{:?}", gaps[0]);
        let unlisted = Unlisted(beside_directory(&hybrid, "WORKSPACE", "WORKSPACE"));
        let root = RootRef {
            root: PathBuf::from("/repo"),
            project_rel: String::new(),
            boundary_levels: 0,
        };
        let ws = detect(&root, &unlisted).expect("a workspace");
        assert!(ws.boundary.workspace);
        assert!(matches!(npm(&ws), Governance::Undetermined(_)));
    }

    /// A view whose root cannot be listed.
    struct Unlisted<V: FileView>(V);

    impl<V: FileView> FileView for Unlisted<V> {
        fn read(&self, rel: &str) -> FileText {
            self.0.read(rel)
        }

        fn list(&self, dir: &str) -> Option<Vec<String>> {
            self.0.list(dir).filter(|_| !dir.is_empty())
        }
    }

    /// Design 2.6: a committed vendor directory is read through the view,
    /// so a model read from memory answers as one read from disk does.
    /// "Nobody looked" must never read as "there is none".
    #[test]
    fn committed_vendor_directories_are_read_through_the_view() {
        let fixed = [(".bazelversion", "9.3.2\n"), ("MODULE.bazel", "")];
        let with = |files: &[(&str, &str)]| Files::of(&[&fixed[..], files].concat());
        let none = detected(&with(&[("src/BUILD.bazel", ""), ("VENDOR.bazel", "")]));
        assert_eq!(none.vendor_dirs, CommittedVendorDirs::default());
        assert_eq!(govern::vendor_dir(&none), FlagState::NotSeen);

        // `VENDOR.bazel` from 7.3, `.vendorignore` alone before it.
        let ws = detected(&with(&[
            ("third_party/VENDOR.bazel", ""),
            ("vendor_src/.vendorignore", ""),
            ("src/deep/VENDOR.bazel", ""),
        ]));
        assert_eq!(ws.vendor_dirs.dirs, ["third_party", "vendor_src"]);
        assert!(!ws.vendor_dirs.cannot_tell);
        let FlagState::Possible(readings) = govern::vendor_dir(&ws) else {
            panic!("a committed vendor directory is `Possible`");
        };
        let dirs: Vec<&String> = readings.values().collect();
        assert_eq!(dirs, ["third_party", "vendor_src"]);

        // A marker that is there and cannot be read, and a root that
        // cannot be listed: the question went unanswered.
        let unread = with(&[]).with("deps/VENDOR.bazel", FileText::Unreadable);
        let unlisted = Unlisted(with(&[("third_party/VENDOR.bazel", "")]));
        let root = RootRef {
            root: PathBuf::from("/repo"),
            project_rel: String::new(),
            boundary_levels: 0,
        };
        for ws in [detected(&unread), detect(&root, &unlisted).unwrap()] {
            assert_eq!(ws.vendor_dirs.dirs, Vec::<String>::new());
            assert!(ws.vendor_dirs.cannot_tell);
            let FlagState::Possible(readings) = govern::vendor_dir(&ws) else {
                panic!("an unanswered marker test is `Possible`");
            };
            assert_eq!(readings.values().collect::<Vec<_>>(), ["?"]);
        }
    }

    /// Design 2.4: the launcher files, then the lock's token, then the
    /// API shapes; and the flags are read as that line reads them.
    #[test]
    fn the_line_is_read_before_the_flags_and_the_system() {
        let line = |files: &[(&str, &str)]| {
            let ws = read(files);
            (
                ws.line.lo.map(|v| v.to_string()),
                ws.line.hi.map(|v| v.to_string()),
            )
        };
        let exact = |v: &str| (Some(v.to_string()), Some(v.to_string()));
        let module = ("MODULE.bazel", "");
        assert_eq!(
            line(&[module, (".bazelversion", "8.8.2\r\n")]),
            exact("8.8.2")
        );
        let rc = (".bazeliskrc", "USE_BAZEL_VERSION = 7.7.2\n");
        assert_eq!(
            line(&[module, (".bazelversion", "8.8.2\n"), rc]),
            exact("7.7.2")
        );
        assert_eq!(line(&[module]), (None, None));
        // Row 2: the releases that write the lock's token.
        let lock =
            "{\"lockFileVersion\": 13, \"registryFileHashes\": {}, \"moduleExtensions\": {}}\n";
        let lock = ("MODULE.bazel.lock", lock);
        assert_eq!(
            line(&[module, lock]),
            (Some("7.5.0".to_string()), Some("7.x".to_string()))
        );
        // Row 3: an older Bazel stops on each of these.
        let rule = ("MODULE.bazel", "r = use_repo_rule(\"//:r.bzl\", \"r\")\n");
        assert_eq!(line(&[rule]).0.as_deref(), Some("7.0.0"));
        let include = ("MODULE.bazel", "include(\"//:a.MODULE.bazel\")\n");
        assert_eq!(
            line(&[include, ("a.MODULE.bazel", "")]).0.as_deref(),
            Some("7.2.0")
        );
        let over = "e = use_extension(\"//:e.bzl\", \"e\")\noverride_repo(e, \"a\")\n";
        assert_eq!(line(&[("MODULE.bazel", over)]).0.as_deref(), Some("7.4.0"));
        assert_eq!(
            line(&[module, (".bazelrc", "common --noenable_workspace\n")])
                .0
                .as_deref(),
            Some("7.1.0")
        );

        // The same rc file under two lines: `always` exists from 6.3.0.
        let always = (".bazelrc", "always --enable_bzlmod\n");
        let workspace = ("WORKSPACE", "");
        assert_eq!(
            read(&[workspace, always, (".bazelversion", "6.2.1\n")]).system,
            DepSystem::Workspace
        );
        assert_eq!(
            read(&[workspace, always, (".bazelversion", "6.6.0\n")]).system,
            DepSystem::Hybrid
        );
        assert_eq!(
            read(&[module, (".bazelversion", "9.3.2\n")]).system,
            DepSystem::Bzlmod
        );

        // A launcher wrapper runs in place of the declared version: a
        // blind spot, recorded beside the line (probe C15).
        let wrapped = read(&[
            module,
            (".bazelversion", "9.3.2\n"),
            ("tools/bazel", "#!/bin/sh\n"),
        ]);
        let wrapper = LineEvidence::Wrapper("tools/bazel".to_string());
        assert!(
            wrapped.line.evidence.contains(&wrapper),
            "{:?}",
            wrapped.line.evidence
        );
        assert_eq!(wrapped.line.exact(), Some(BazelVersion::new(9, 3, 2)));
        // A file above the root applies when the root has none.
        let root = RootRef {
            root: PathBuf::from("/repo/ws"),
            project_rel: String::new(),
            boundary_levels: 1,
        };
        let above = Files::of(&[module, ("../.bazelversion", "8.8.2\n")]).boundary(1);
        assert_eq!(
            detect(&root, &above).unwrap().line.exact(),
            Some(BazelVersion::new(8, 8, 2))
        );
    }

    /// Unreadable is not absent: each file a reader could not follow is a
    /// gap of the model, with the token of its case.
    #[test]
    fn what_was_not_read_is_in_completeness() {
        let pin = (".bazelversion", "9.3.2\n");
        let module = ("MODULE.bazel", JS_MODULE);
        assert_eq!(
            read(&[pin, module, PNPM_LOCK]).completeness,
            Completeness::Exact
        );
        // A plain `import` Bazel is sure to follow, of a file not there.
        let ws = read(&[
            pin,
            module,
            PNPM_LOCK,
            (".bazelrc", "import %workspace%/ci.bazelrc\n"),
        ]);
        assert_eq!(tokens(&ws), [RC_IMPORT_UNREADABLE]);
        // An optional one is a blind spot, not a gap.
        let soft = (".bazelrc", "try-import %workspace%/user.bazelrc\n");
        let ws = read(&[pin, module, PNPM_LOCK, soft]);
        assert_eq!(ws.completeness, Completeness::Exact);
        assert_eq!(ws.flags.gaps().len(), 1);
        // A segment Bazel would stop on, and a computed lock label.
        let ws = read(&[pin, ("MODULE.bazel", "include(\"//:gone.MODULE.bazel\")\n")]);
        assert_eq!(tokens(&ws), [WORKSPACE_UNREADABLE]);
        let computed = JS_MODULE.replace("\"//:pnpm-lock.yaml\"", "lock()");
        let ws = read(&[pin, ("MODULE.bazel", &computed), PNPM_LOCK]);
        assert!(
            tokens(&ws).contains(&govern::LABEL_NOT_LITERAL),
            "{:?}",
            ws.completeness
        );
        assert!(ws
            .ruleset_gaps
            .iter()
            .all(|(ruleset, _)| *ruleset == Ruleset::RulesJs));
        assert!(!ws.ruleset_gaps.is_empty());
    }

    /// Every recognizer runs over the one model, and each hub leaves with
    /// its liveness and version decided.
    #[test]
    fn hubs_of_both_file_families_are_recognized_and_settled() {
        let ws = read_at(
            &[
                (".bazelversion", "7.7.2\n"),
                ("MODULE.bazel", JS_MODULE),
                ("WORKSPACE", &JS_WORKSPACE.replace("\"npm\"", "\"npm_ws\"")),
                PNPM_LOCK,
                (".bazelignore", "node_modules\n"),
            ],
            "",
        );
        let found: Vec<_> = ws
            .hubs
            .iter()
            .map(|hub| (hub.ruleset, hub.decl.site.system))
            .collect();
        let js = Ruleset::RulesJs;
        assert_eq!(
            found,
            [(js, DeclSystem::Bzlmod), (js, DeclSystem::Workspace)]
        );
        assert!(
            ws.hubs.iter().all(|hub| hub.liveness == Liveness::Live),
            "{:?}",
            ws.hubs
        );
        // Hybrid: the root module sees `aspect_rules_js`, so both hubs run
        // the module's rule, whatever archive the WORKSPACE defines.
        for hub in &ws.hubs {
            let version = &hub.ruleset_version;
            assert!(
                version.at_least("3.6.0") && !version.at_least("3.6.1"),
                "{version:?}"
            );
        }
        assert_eq!(
            (ws.system.clone(), ws.tier),
            (DepSystem::Hybrid, Tier::Beta)
        );
        assert!(ws.ignore.covers("node_modules/x") && ws.signals.is_empty());
        assert_eq!(ws.out_of_scope.bazel_modules, 1);
        assert_eq!(ws.vendor_dirs, CommittedVendorDirs::default());
    }

    /// The reader is total: a workspace whose files were cut short or had
    /// bytes replaced reads to some model, and every question of it has
    /// an answer. A hub such a read calls live is one its lock names.
    #[test]
    fn truncated_and_mutated_workspaces_never_panic() {
        const BYTES: &[u8] = b"\"'\\#()[]{},=:;.*+-\n\r\t \0\x80devcommon--noenable_bzlmod7.9";
        let files = [
            (".bazelversion", "7.7.2\n"),
            (
                ".bazelrc",
                "common:ci --ignore_dev_dependency\nbuild --enable_workspace\n",
            ),
            ("MODULE.bazel", JS_MODULE),
            ("WORKSPACE", JS_WORKSPACE),
            (
                "MODULE.bazel.lock",
                "{\"lockFileVersion\": 13, \"registryFileHashes\": {}}\n",
            ),
            PNPM_LOCK,
        ];
        let root = RootRef {
            root: PathBuf::from("/repo"),
            project_rel: "app".to_string(),
            boundary_levels: 0,
        };
        let mut rng = crate::test_rng::Rng::new(0x3d);
        let (mut read, mut live) = (0, 0);
        for _ in 0..400 {
            let mut mutated = Files::default();
            for (path, text) in files {
                let mut bytes = text.as_bytes().to_vec();
                if rng.chance(15) {
                    bytes.truncate(rng.below(bytes.len() + 1));
                }
                for _ in 0..rng.below(3) {
                    let at = rng.below(bytes.len() + 1);
                    let byte = BYTES[rng.below(BYTES.len())];
                    match rng.below(3) {
                        0 => bytes.insert(at, byte),
                        1 if at < bytes.len() => bytes[at] = byte,
                        _ if at < bytes.len() => drop(bytes.remove(at)),
                        _ => {}
                    }
                }
                mutated = mutated.with(path, FileText::Bytes(bytes));
            }
            let Ok(ws) = detect(&root, &mutated) else {
                continue;
            };
            read += 1;
            for ecosystem in crate::crawlers::types::Ecosystem::all() {
                for project in ["", "app"] {
                    let found = govern::governance(&ws, *ecosystem, project);
                    if let crate::bazel::model::Governance::Governed(hubs) = found {
                        live += 1;
                        let hubs = hubs.iter().map(|id| &ws.hubs[id.0]);
                        assert!(hubs.clone().all(|hub| hub.liveness == Liveness::Live));
                        assert!(hubs.clone().all(|hub| hub.ecosystem == *ecosystem));
                    }
                }
            }
            let _ = govern::vendor_dir(&ws);
        }
        // The mutations leave most workspaces readable, and some governed.
        assert!(read > 300 && live > 20, "{read} read, {live} governed");
    }

    /// Design 8: the tier is that of the file families Bazel may read.
    #[test]
    fn the_tier_is_the_weakest_of_the_live_file_families() {
        let tier = |version: &str, files: &[(&str, &str)]| {
            read(&[&[(".bazelversion", version), PNPM_LOCK][..], files].concat()).tier
        };
        let (module, workspace) = (("MODULE.bazel", JS_MODULE), ("WORKSPACE", JS_WORKSPACE));
        assert_eq!(tier("9.3.2", &[module]), Tier::Supported);
        // A leftover WORKSPACE that Bazel 9 never reads changes nothing.
        assert_eq!(tier("9.3.2", &[module, workspace]), Tier::Supported);
        assert_eq!(
            tier("9.3.2", &[workspace]),
            Tier::Refused(TierRefusal::WorkspaceRemoved)
        );
        assert_eq!(tier("7.7.2", &[workspace]), Tier::Beta);
        assert_eq!(tier("7.1.2", &[module]), Tier::Beta);
        assert_eq!(tier("6.6.0", &[workspace]), Tier::Legacy);
        assert_eq!(
            tier("4.2.4", &[workspace]),
            Tier::Refused(TierRefusal::TooOld)
        );
        // Nothing declared: the family of the boundary file.
        assert_eq!(tier("9.3.2", &[("MODULE.bazel", "")]), Tier::Supported);
        assert_eq!(tier("8.8.2", &[("WORKSPACE", "")]), Tier::Beta);
        let unpinned = read(&[workspace, PNPM_LOCK]).tier;
        assert_eq!(unpinned, Tier::Refused(TierRefusal::LineUnknown));

        // A hub that is live under one of the systems the workspace may
        // run counts: a flag under a config leaves the WORKSPACE hub live
        // on every default command, and its family is the weaker one.
        let renamed = JS_WORKSPACE.replace("name = \"npm\"", "name = \"npm_ws\"");
        let both = [module, ("WORKSPACE", renamed.as_str())];
        for (version, rc) in [
            ("7.7.2", "common:ci --noenable_workspace\n"),
            ("8.x", "build:ws --enable_workspace\n"),
        ] {
            let files = [
                &both[..],
                &[(".bazelversion", version), (".bazelrc", rc), PNPM_LOCK],
            ];
            let ws = read(&files.concat());
            let workspace_hub = &ws.hubs[1];
            assert_eq!(workspace_hub.decl.site.system, DeclSystem::Workspace);
            assert!(
                matches!(workspace_hub.liveness, Liveness::Undecided { .. }),
                "{version}: {:?}",
                workspace_hub.liveness
            );
            assert_eq!(ws.tier, Tier::Beta, "{version} with {rc:?}");
            // The same as the WORKSPACE family alone.
            assert_eq!(tier(version, &[both[1], (".bazelrc", rc)]), Tier::Beta);
        }
        assert_eq!(tier("7.7.2", &both), Tier::Beta);
        // A hub Bazel never evaluates does not.
        assert_eq!(tier("9.3.2", &both), Tier::Supported);
        // Nor does a WORKSPACE hub whose one doubt is the line nobody
        // pinned: governance answers `Undetermined` for it, and design 8
        // lets the `MODULE.bazel` hubs through on an unknown line.
        let unpinned = read(&[&both[..], &[PNPM_LOCK]].concat());
        assert!(matches!(
            unpinned.hubs[1].liveness,
            Liveness::Undecided { .. }
        ));
        assert_eq!(unpinned.tier, Tier::Supported);

        // A signal counts for its family only where Bazel may evaluate
        // its statement. A hub rule nobody followed in a `WORKSPACE` left
        // beside a `MODULE.bazel` that declares no hub: Bazel 9 never
        // opens the file, and the workspace is a Bzlmod one.
        let loaded = "load(\"@aspect_rules_js//npm:repositories.bzl\", \"npm_translate_lock\")\n";
        let leftover = [
            ("MODULE.bazel", "module(name = \"app\")\n"),
            ("WORKSPACE", loaded),
        ];
        let read_at = |version: &str| {
            let ws = read(&[&leftover[..], &[(".bazelversion", version)]].concat());
            assert!(ws.hubs.is_empty(), "{:?}", ws.hubs);
            let files: Vec<&str> = ws.signals.iter().map(|s| s.site.file.as_str()).collect();
            assert_eq!(files, ["WORKSPACE"], "Bazel {version}");
            ws.tier
        };
        assert_eq!(read_at("9.3.2"), Tier::Supported);
        assert_eq!(read_at("8.8.2"), Tier::Supported);
        // Bazel 7 evaluates it beside the module file.
        assert_eq!(read_at("7.7.2"), Tier::Beta);
    }
}
