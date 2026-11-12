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
//! The model is read once per root. Reads go through the view, which the
//! disk side memoizes (`crawlers::bazel_workspace`), and each recognizer
//! opens lock headers and scans BUILD files only where its ruleset is
//! declared, so a workspace pays for the rulesets it uses.
//!
//! Nested roots are read one at a time: every path of a model is relative
//! to its own root. `govern::governance_over` combines their answers.

use super::govern::{self, RC_IMPORT_UNREADABLE, WORKSPACE_UNREADABLE};
use super::ignore::{IgnoreModel, BAZELIGNORE};
use super::model::{
    BazelWorkspace, BoundaryFiles, CommittedVendorDirs, Completeness, DeclSystem, FileText,
    FileView, Gap, Liveness, ModuleLock, ModuleModel, OutOfScope, RootRef, Tier, WorkspaceModel,
};
use super::rc;
use super::rulesets::{self, RecognizeInput};
use super::version::{self, ApiShape, DepSystem};
use super::workspace_file::WORKSPACE_FILES;

/// Whether the root holds the file `name`. A directory of that name is no
/// boundary file, and a file that cannot be read is one: unreadable is not
/// absent.
fn present(files: &dyn FileView, name: &str) -> bool {
    match files.read(name) {
        FileText::Bytes(_) => true,
        FileText::Absent => false,
        FileText::Unreadable => {
            let listed = files.list("").unwrap_or_default();
            !listed
                .iter()
                .any(|entry| entry.strip_suffix('/') == Some(name))
        }
    }
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
/// of the files that exist when nothing is declared.
fn tier(ws: &BazelWorkspace) -> Tier {
    let live = ws
        .hubs
        .iter()
        .filter(|hub| !matches!(hub.liveness, Liveness::Dead { .. }));
    let mut families: Vec<DeclSystem> = live.map(|hub| hub.decl.site.system).collect();
    if families.is_empty() {
        families.extend(ws.hubs.iter().map(|hub| hub.decl.site.system));
        families.extend(ws.signals.iter().map(|signal| signal.site.system));
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
    let boundary = BoundaryFiles {
        module_bazel: present(files, "MODULE.bazel"),
        repo_bazel: present(files, "REPO.bazel"),
        workspace_bazel: present(files, "WORKSPACE.bazel"),
        workspace: present(files, "WORKSPACE"),
        workspace_bzlmod: present(files, "WORKSPACE.bzlmod"),
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
    let module = ModuleModel::read(files);
    let workspace_files: Vec<WorkspaceModel> = WORKSPACE_FILES
        .iter()
        .filter_map(|path| WorkspaceModel::read(files, path))
        .collect();
    let module_lock = ModuleLock::read(files);
    let rc = rc::read(files);
    let declared = version::read_declared(root, files);
    let mut shapes = rc.api_shapes();
    shapes.extend(api_shapes(module.as_ref()));
    let line = version::line(&declared, module_lock.lock_file_version(), &shapes);
    let flags = rc.effective(&line);
    let system = version::dep_system(&line, &flags);

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

    let mut gaps = govern::model_gaps(module.as_ref(), &workspace_files);
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
        vendor_dirs: CommittedVendorDirs::default(),
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
    use crate::bazel::model::Ruleset;
    use crate::bazel::rc::testing::Files;
    use crate::bazel::version::{BazelVersion, LineEvidence, TierRefusal};

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
        assert!(
            ws.vendor_dirs.dirs.is_empty(),
            "only the disk shows a vendor directory"
        );
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
    }
}
