//! Real-Bazel test of the liveness verdict
//! (`socket_patch_core::bazel::govern::liveness`): which declaration of a
//! hub Bazel builds from, read off the committed files, against what Bazel
//! itself builds.
//!
//! The workspace is the hybrid toy fixture: `MODULE.bazel` and `WORKSPACE`
//! each declare a hub named `toy` over a lock of its own (the package at
//! 1.0.0 and at 0.9.0), and `WORKSPACE` alone declares `toy_ws`. So the
//! bytes of two probe targets say which file Bazel read, and whether the
//! Bzlmod name hides the `WORKSPACE` repository.
//!
//! Each flag set of the mode table (design 2.5) is written to the
//! workspace `.bazelrc`, where both readers find it: socket-patch's model
//! and Bazel, which gets no dependency-system flag on its command line.
//! The flag sets a line does not know (`--enable_workspace` before 7.1.0)
//! have no cell: every Bazel command exits 2 on them. Bazel 9 never reads
//! a `WORKSPACE`, so its cell is the Bzlmod fixture with the hybrid one's
//! `WORKSPACE` and second lock copied beside it.

use std::path::Path;

use serde_json::json;
use socket_patch_core::bazel::govern::{liveness, DeclRef, Standing};
use socket_patch_core::bazel::model::{BazelWorkspace, DeclSystem, Liveness, RootRef};
use socket_patch_core::crawlers::bazel_workspace::{read_workspace, DiskView};

use crate::bazel_build_common::env::{System, Version};
use crate::bazel_build_common::invoke::{Bazel, Options};
use crate::bazel_build_common::isolation::Scratch;
use crate::bazel_build_common::proof::PROBE;
use crate::bazel_build_common::toy::{self, Toy, DEP, DEP_WS};
use crate::bazel_build_common::workspace::fixtures_root;

const TEST: &str = "bazel_core_liveness_matches_bazel";
/// The probe of `@toy_ws`, which only the `WORKSPACE` declares.
const WS_PROBE: &str = "//ws:socket_probe";
const DEP_OUT: &str = "dep.sh";
/// The files the hybrid fixture has beside the Bzlmod one.
const WORKSPACE_SIDE: [&str; 3] = ["WORKSPACE", "ws/BUILD.bazel", "ws/toy.lock.json"];

/// The rows of the mode table a line accepts, as the options of one
/// `common` line; `""` is the line's default.
fn flag_sets(version: &Version) -> &'static [&'static str] {
    match version.major {
        6 => &["", "--enable_bzlmod", "--noenable_bzlmod"],
        // 7.0.x has no `--enable_workspace`.
        7 if !version.at_least(7, 1, 0) => &["", "--noenable_bzlmod"],
        7 => &[
            "",
            "--noenable_workspace",
            "--noenable_bzlmod",
            "--noenable_bzlmod --noenable_workspace",
        ],
        8 => &[
            "",
            "--enable_workspace",
            "--noenable_bzlmod --enable_workspace",
            // A Bazel error: both systems are off.
            "--noenable_bzlmod",
        ],
        // From 9 both flags are accepted and do nothing.
        _ => &[
            "",
            "--enable_workspace",
            "--noenable_bzlmod --enable_workspace",
        ],
    }
}

/// The dependency system a cell of `version` is opened as: the hybrid
/// fixture wherever the line can read a `WORKSPACE`.
fn fixture_system(version: &Version) -> System {
    match version.system_flags(System::Hybrid) {
        Some(_) => System::Hybrid,
        None => System::Bzlmod,
    }
}

/// The model of the cell's workspace copy as it is on disk.
fn model(workspace: &Path) -> BazelWorkspace {
    let root = RootRef {
        root: std::fs::canonicalize(workspace).expect("resolve the workspace copy"),
        project_rel: String::new(),
        boundary_levels: 0,
    };
    read_workspace(&root, &DiskView::new(&root)).expect("the workspace copy is a Bazel root")
}

/// The three declarations of the fixture: `toy` in `MODULE.bazel`, and
/// `toy` and `toy_ws` in `WORKSPACE`.
fn standings(ws: &BazelWorkspace) -> [Standing; 3] {
    let decl = |system, file, name| DeclRef {
        system,
        file,
        name: Some(name),
        imported: Some(true),
        dev: false,
        non_root: false,
        build_rule: false,
    };
    [
        decl(DeclSystem::Bzlmod, "MODULE.bazel", "toy"),
        decl(DeclSystem::Workspace, "WORKSPACE", "toy"),
        decl(DeclSystem::Workspace, "WORKSPACE", "toy_ws"),
    ]
    .map(|decl| liveness(ws, &decl))
}

/// The package file `target` builds from, or Bazel's first error line
/// when the build fails.
fn built(toy: &Toy, options: &Options, target: &str) -> Result<Vec<u8>, String> {
    let cell = &toy.cell;
    let build = cell.bazel_with(options, "build", &[target]);
    if !build.ok() {
        let stderr = build.stderr();
        let errors: Vec<&str> = stderr
            .lines()
            .filter(|line| line.contains("ERROR"))
            .collect();
        assert!(!errors.is_empty(), "{TEST}: {}", build.dump());
        return Err(errors.join("\n"));
    }
    let output = cell.probe_output(options, target, DEP_OUT);
    Ok(std::fs::read(&output).unwrap_or_else(|e| panic!("read {}: {e}", output.display())))
}

const NO_BUILD: &str = "no build";

/// Which lock a built package file comes from.
fn marker(built: &Result<Vec<u8>, String>) -> &'static str {
    match built {
        Err(_) => NO_BUILD,
        Ok(bytes) if *bytes == DEP.upstream() => "MODULE.bazel lock (1.0.0)",
        Ok(bytes) if *bytes == DEP_WS.upstream() => "WORKSPACE lock (0.9.0)",
        Ok(_) => "other bytes",
    }
}

/// Whether a failed build failed for the reason under test: Bazel cannot
/// resolve the repository (`No repository visible as '@toy_ws'`), or it
/// loads no external repository at all because both systems are off
/// (`error loading package 'external'`, on 7.7.2 and 8.8.2). Any other
/// failure (a fetch, the fixture) would agree with a dead declaration by
/// accident.
fn failed_on_the_system(built: &Result<Vec<u8>, String>, repository: &str) -> bool {
    let error = built.as_ref().err().map(String::as_str).unwrap_or_default();
    error.contains(&format!("'{repository}'")) || error.contains("package 'external'")
}

#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_liveness_matches_bazel() {
    // The fixture depends on the line, which only Bazel itself tells. A
    // machine with no Bazel is reported by `toy::open` below.
    let probe = Scratch::new();
    let version = Bazel::detect(&probe).ok().map(|bazel| bazel.version);
    drop(probe);
    let system = version.as_ref().map_or(System::Hybrid, fixture_system);
    let Some(mut toy) = toy::open(TEST, system, false) else {
        return;
    };
    let version = toy.cell.bazel.version.clone();
    if system == System::Bzlmod {
        let hybrid = fixtures_root().join("core/hybrid/e8");
        for rel in WORKSPACE_SIDE {
            let path = hybrid.join(rel);
            let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            toy.cell.write(rel, bytes);
        }
    }
    // The launcher is told the release by the harness; the model reads it
    // where a repository states it.
    toy.cell
        .write(".bazelversion", format!("{}\n", version.text));
    // The rc file decides the system, as it does in a user's repository.
    let options = Options {
        system: None,
        ..toy.cell.options.clone()
    };

    let mut rows = Vec::new();
    for flags in flag_sets(&version) {
        let what = format!("{TEST}: Bazel {} with `common {flags}`", version.text);
        let rc = match flags.is_empty() {
            true => String::new(),
            false => format!("common {flags}\n"),
        };
        toy.cell.write(".bazelrc", rc);

        let ws = model(&toy.cell.scratch.workspace);
        assert_eq!(
            ws.line.exact().map(|v| v.to_string()),
            Some(version.text.clone()),
            "{what}"
        );
        let found = standings(&ws);
        let (main, ws_probe) = (
            built(&toy, &options, PROBE),
            built(&toy, &options, WS_PROBE),
        );
        let real = [marker(&main), marker(&ws_probe)];
        let live = |standing: &Standing| *standing == Standing::Is(Liveness::Live);
        let [module_toy, workspace_toy, workspace_only] = &found;

        for (built, repository) in [(&main, "toy"), (&ws_probe, "toy_ws")] {
            let on_system = built.is_ok() || failed_on_the_system(built, repository);
            assert!(on_system, "{what}: an unrelated failure: {built:?}");
        }
        if found
            .iter()
            .all(|standing| matches!(standing, Standing::Unknown(_)))
        {
            // Bazel stops on the flag set, so no file is known to be read.
            assert_eq!(real, [NO_BUILD, NO_BUILD], "{what}: {:?}", ws.system);
        } else {
            // Under one line and one unconditional flag set every
            // declaration has one answer.
            for standing in &found {
                assert!(matches!(standing, Standing::Is(_)), "{what}: {standing:?}");
            }
            // `@toy` is the repository of the one live declaration of the
            // name, and nothing where neither is live.
            let want = match (live(module_toy), live(workspace_toy)) {
                (true, false) => "MODULE.bazel lock (1.0.0)",
                (false, true) => "WORKSPACE lock (0.9.0)",
                (false, false) => NO_BUILD,
                (true, true) => panic!("{what}: two live declarations of `toy`"),
            };
            assert_eq!(real[0], want, "{what}: {PROBE} against {found:?}");
            // `@toy_ws` exists exactly where the WORKSPACE is read.
            let want = match live(workspace_only) {
                true => "WORKSPACE lock (0.9.0)",
                false => NO_BUILD,
            };
            assert_eq!(real[1], want, "{what}: {WS_PROBE} against {found:?}");
            // Where both files are read, the Bzlmod name hides the
            // WORKSPACE repository of the same name and no other.
            if live(module_toy) && live(workspace_only) {
                let shadowed = matches!(workspace_toy, Standing::Is(Liveness::Shadowed { .. }));
                assert!(shadowed, "{what}: {workspace_toy:?}");
            }
        }
        let short = |standing: &Standing| match standing {
            Standing::Is(Liveness::Live) => "live",
            Standing::Is(Liveness::Shadowed { .. }) => "shadowed",
            Standing::Is(_) => "dead",
            Standing::Contested(_) => "contested",
            Standing::Unknown(_) => "unknown",
        };
        let failed = [&main, &ws_probe]
            .into_iter()
            .filter_map(|built| built.as_ref().err());
        // The first line names the cause; the rest repeat it per target.
        let errors: Vec<&str> = failed.filter_map(|error| error.lines().next()).collect();
        rows.push(json!({
            "flags": flags,
            "system": format!("{:?}", ws.system),
            "static": found.iter().map(short).collect::<Vec<_>>(),
            "bazel": real,
            "errors": errors,
        }));
    }
    assert!(
        rows.len() >= 2,
        "{TEST}: a line has its default and one more flag set"
    );
    toy.cell.report.detail("flag_sets", rows);
    toy.finish();
}
