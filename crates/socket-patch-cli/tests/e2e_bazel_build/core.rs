//! Real-Bazel tests on the toy core fixture (`fixtures/bazel/core`): what
//! Bazel itself does with a pin, with no ruleset and no lane in the way.
//!
//! No lane exists yet, so a pin is applied by hand, as a hosted lane will
//! write it: the lock's URL moves to the Socket host and its sha256 and
//! derived hash follow. The tests then show, with Bazel's own output, that
//! a build consumes the pinned bytes, that other bytes at the pinned URL
//! fail the build, that a pin without its derived hash does not load, that
//! a `.bazelignore` line is what keeps a tree out of `//...`, which lock
//! governs a hub that two dependency systems declare, and that the fixture
//! builds with no network at all. Every later `bazel_core_` test stands on
//! these.
//!
//! The first four tests run no Bazel: they keep the fixture copies, the
//! committed payloads, `MATRIX.json` and the registry manifest in step.

use std::path::{Path, PathBuf};

use crate::bazel_build_common::env::{System, Version};
use crate::bazel_build_common::invoke::Options;
use crate::bazel_build_common::probe_report;
use crate::bazel_build_common::proof::{Anchor, CONSUMER, PROBE};
use crate::bazel_build_common::toy::{self, DEP, DEP_WS, INDEXED};
use crate::bazel_build_common::workspace::{fixtures_root, MODULE_LOCK};
use crate::bazel_common::snapshot::PLACEHOLDER_MODULE_BAZEL;
use crate::bazel_common::{assert_same_tree_but_bazel_owned, snapshot};

/// The toy lock of the hub `toy`, and the probe output of its package.
const LOCK: &str = "toy.lock.json";
const DEP_OUT: &str = "dep.sh";
/// Tier 0 names the package file by this part of its label, whatever the
/// line calls the spoke repository (`toy_dep`, `_main~toy~toy_dep`, `+toy+toy_dep`).
const DEP_LABEL: &str = "toy_dep//file:";
/// Where every proxy of a zero-network cell points: nothing listens there.
const CLOSED_PORT: &str = "http://127.0.0.1:9";

/// Every fixture workspace: `core/<system>/e<major>`.
fn fixture_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for system in ["bzlmod", "workspace", "hybrid"] {
        let eras = std::fs::read_dir(fixtures_root().join("core").join(system));
        dirs.extend(
            eras.expect("read the era directories")
                .map(|e| e.unwrap().path()),
        );
    }
    dirs.sort();
    dirs
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The fixture is one toy ruleset in several workspaces: a copy that
/// drifted would make a cell test something no other cell does.
#[test]
fn core_fixture_copies_agree() {
    let dirs = fixture_dirs();
    assert_eq!(dirs.len(), 7, "{dirs:?}");
    let reference = fixtures_root().join("core/bzlmod/e9");
    for dir in &dirs {
        for shared in ["toy.bzl", "BUILD.bazel", LOCK] {
            let (copy, original) = (read(&dir.join(shared)), read(&reference.join(shared)));
            assert!(
                copy == original,
                "{}/{shared} differs from e9's",
                dir.display()
            );
        }
        // The era is the Bazel major the workspace is written for.
        let era = dir.file_name().unwrap().to_string_lossy().into_owned();
        let pinned = read(&dir.join(".bazelversion"));
        let version = Version::parse(pinned.trim()).expect("a .bazelversion");
        assert_eq!(era, format!("e{}", version.major), "{}", dir.display());
        // A fixture never ships the lock Bazel owns at its root.
        assert!(!dir.join(MODULE_LOCK).exists(), "{}", dir.display());
    }
}

/// Every committed toy lock pins a committed upstream payload by its real
/// digest and carries the derived hash `toy.bzl` checks, and the hand pin
/// changes those three values and nothing else.
#[test]
fn toy_locks_pin_the_committed_payloads() {
    let mut locks = 0;
    for dir in fixture_dirs() {
        for rel in [LOCK, "ws/toy.lock.json", "facts/toy.lock.json"] {
            let path = dir.join(rel);
            if !path.is_file() {
                continue;
            }
            locks += 1;
            let text = read(&path);
            let json: serde_json::Value = serde_json::from_str(&text).expect("a toy lock");
            assert_eq!(
                json["pinsHash"],
                toy::pins_hash(&text),
                "{}",
                path.display()
            );
            for (name, entry) in json["packages"].as_object().expect("packages") {
                let known = [DEP, DEP_WS, INDEXED].into_iter().find(|package| {
                    package.name == name.as_str() && entry["version"] == package.version
                });
                let package = known.unwrap_or_else(|| panic!("{}: {name}", path.display()));
                assert_eq!(entry["url"], package.upstream_url(), "{}", path.display());
                let digest = toy::sha256_hex(&package.upstream());
                assert_eq!(entry["sha256"], digest, "{}", path.display());
            }
        }
    }
    assert_eq!(locks, 11, "toy locks found");

    let lock = read(&fixtures_root().join("core/bzlmod/e9").join(LOCK));
    let pinned = toy::pin(&lock, DEP);
    let differing: Vec<(&str, &str)> = lock
        .lines()
        .zip(pinned.lines())
        .filter(|(before, after)| before != after)
        .collect();
    let [(_, url), (_, sha256), (_, derived)] = differing[..] else {
        panic!("the pin changed other lines: {differing:?}");
    };
    assert_eq!(lock.lines().count(), pinned.lines().count());
    assert!(url.contains(&DEP.hosted_url()), "{url}");
    assert!(
        sha256.contains(&toy::sha256_hex(&DEP.patched())),
        "{sha256}"
    );
    assert_eq!(
        derived.trim(),
        format!("\"pinsHash\": {}", toy::pins_hash(&pinned))
    );
}

/// `core/MATRIX.json` names fixtures that exist, Bazel versions the
/// installer pins, and tests this suite has.
#[test]
fn core_matrix_names_real_fixtures_versions_and_tests() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let matrix: serde_json::Value =
        serde_json::from_str(&read(&fixtures_root().join("core/MATRIX.json")))
            .expect("MATRIX.json");
    let pins = read(&manifest.join("../../scripts/bazel-pins.txt"));
    let mut fixtures = Vec::new();
    for cell in matrix["cells"].as_array().expect("cells") {
        let bazel = cell["bazel"].as_str().expect("bazel");
        assert!(
            pins.contains(&format!("bazel {bazel} ")),
            "Bazel {bazel} is not pinned"
        );
        for fixture in cell["fixtures"].as_object().expect("fixtures").values() {
            let fixture = fixtures_root().join(fixture.as_str().expect("a fixture path"));
            assert!(fixture.is_dir(), "{}", fixture.display());
            fixtures.push(fixture);
        }
    }
    fixtures.sort();
    fixtures.dedup();
    assert_eq!(fixtures, fixture_dirs(), "every fixture has a cell");

    let suite = manifest.join("tests/e2e_bazel_build");
    let sources: String = std::fs::read_dir(&suite)
        .expect("read the suite")
        .map(|entry| read(&entry.unwrap().path()))
        .collect();
    let tests = matrix["tests"].as_object().expect("tests");
    assert!(!tests.is_empty());
    for (name, claim) in tests {
        assert!(
            name.starts_with(matrix["filter"].as_str().expect("filter")),
            "{name}"
        );
        assert!(sources.contains(&format!("fn {name}()")), "no test {name}");
        // A test is claimed only on a line whose cell has a fixture of its system.
        let system = claim["system"].as_str().expect("system");
        for bazel in claim["bazel"].as_array().expect("bazel") {
            let cells = matrix["cells"].as_array().unwrap().iter();
            let has_fixture = |cell: &serde_json::Value| {
                cell["bazel"] == *bazel && (system == "any" || !cell["fixtures"][system].is_null())
            };
            let mut claimed = cells.filter(|cell| has_fixture(cell)).peekable();
            assert!(
                claimed.peek().is_some(),
                "{name}: no {system} cell on {bazel}"
            );
            // A claim holds on every OS of its cells, unless it names the
            // ones it holds on: those are then OSes each of its cells has.
            let Some(scope) = claim.get("os") else {
                continue;
            };
            let scope = scope.as_array().expect("os");
            assert!(!scope.is_empty(), "{name}: an empty os list claims nothing");
            for cell in claimed {
                let runs_on = cell["os"].as_array().expect("a cell's os");
                let stray: Vec<_> = scope.iter().filter(|os| !runs_on.contains(os)).collect();
                assert!(stray.is_empty(), "{name}: no {bazel} cell on {stray:?}");
            }
        }
    }
    // The test that kills the server with SIGKILL reports `skipped` off
    // Unix (launch.rs), so it claims no Windows cell.
    let unix_only = &tests["bazel_core_shutdown_after_the_server_was_killed"]["os"];
    let unix_only = unix_only
        .as_array()
        .expect("the SIGKILL test names its OSes");
    assert!(
        !unix_only.iter().any(|os| os == "windows-latest"),
        "{unix_only:?}"
    );
    // And the reverse for this file: each of its real-Bazel tests is listed.
    for line in read(&suite.join("core.rs")).lines() {
        if let Some(name) = line.strip_prefix("fn bazel_core_") {
            let name = format!("bazel_core_{}", name.trim_end_matches("() {"));
            assert!(tests.contains_key(&name), "{name} is not in MATRIX.json");
        }
    }
}

/// Every cell of `core/MATRIX.json` can open its toy tests: its Bazel
/// version is in the registry manifest, and where the module archives are
/// not committed the manifest names them for each dependency system the
/// cell has a fixture for, which is what a cold cell is given from the
/// repository cache. No list names a toy package.
#[test]
fn every_core_cell_has_its_registry_mirror_and_archives() {
    let json = |rel: &str| -> serde_json::Value {
        serde_json::from_str(&read(&fixtures_root().join(rel))).expect(rel)
    };
    let (matrix, manifest) = (json("core/MATRIX.json"), json("registry/MANIFEST.json"));
    let packages = toy::payload_digests();
    assert!(!packages.is_empty(), "no toy package under core/payloads");
    let mut gated = 0;
    for cell in matrix["cells"].as_array().expect("cells") {
        let bazel = cell["bazel"].as_str().expect("bazel");
        let version = Version::parse(bazel).expect("a Bazel version");
        for system in [System::Bzlmod, System::Workspace, System::Hybrid] {
            let fixture = cell["fixtures"].get(system.name());
            let present = fixture.is_some();
            if let Some(fixture) = fixture {
                assert_eq!(*fixture, toy::fixture_of(&version, system), "{bazel}");
            }
            let digests = match toy::gate(&version, system, &manifest, present, false) {
                toy::Gate::Run(toy::Mirror::Committed) => continue,
                toy::Gate::Run(toy::Mirror::Cached(digests)) => digests,
                // A line without the system has no fixture of it either.
                toy::Gate::NotApplicable(_) if !present => continue,
                other => panic!("{bazel} {}: {other:?}", system.name()),
            };
            assert!(!digests.is_empty(), "{bazel} {}", system.name());
            let named: Vec<_> = digests.iter().filter(|d| packages.contains(d)).collect();
            assert!(
                named.is_empty(),
                "{bazel}: a list names toy packages {named:?}"
            );
            gated += 1;
        }
    }
    assert!(gated > 0, "no cell runs on cached archives: is 8.8.2 gone?");
}

/// The scenario of design 9.3 with the pin applied by hand: baseline,
/// pin, proof ladder, do no harm, undo.
fn toy_pin_consumed(test: &str, system: System) {
    let Some(toy) = toy::open(test, system, false) else {
        return;
    };
    let cell = &toy.cell;
    let (upstream, patched) = (DEP.upstream(), DEP.patched());
    let anchor = |bytes: &[u8]| toy::sha256_hex(bytes);

    // 1. Baseline: the build consumes what the committed lock pins.
    cell.baseline(&["//..."], false);
    cell.tier0(Anchor::Sha256 {
        label: DEP_LABEL,
        sha256: &anchor(&upstream),
    });
    assert_eq!(cell.tier1_file(DEP_OUT), upstream, "baseline");
    let before = snapshot(&cell.scratch.workspace);

    // 2. The pin, in the toy lock and nowhere else.
    let committed = toy.read(LOCK);
    toy.pin(LOCK, DEP, patched.clone());
    let pinned = snapshot(&cell.scratch.workspace);

    // 3. Proof ladder: the repository Bazel materialised, an action input
    //    on a warm and on a restarted server, and the package when run.
    cell.tier0(Anchor::Sha256 {
        label: DEP_LABEL,
        sha256: &anchor(&patched),
    });
    assert_eq!(cell.tier1_file(DEP_OUT), patched, "warm server");
    cell.shutdown();
    assert_eq!(cell.tier1_file(DEP_OUT), patched, "restarted server");
    if cfg!(unix) {
        cell.tier2(&DEP.marker(true));
    }

    // 4. Do no harm: everything still builds, and Bazel wrote nothing
    //    into the workspace but its own files.
    cell.bazel_ok("build", &["//..."]);
    assert_same_tree_but_bazel_owned(&pinned, &snapshot(&cell.scratch.workspace));

    // 5. Undo: the committed lock again, and the build is unpatched.
    cell.write(LOCK, committed);
    assert_eq!(cell.tier1_file(DEP_OUT), upstream, "after the undo");
    assert_same_tree_but_bazel_owned(&before, &snapshot(&cell.scratch.workspace));
    toy.finish();
}

#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_toy_pin_consumed_bzlmod() {
    toy_pin_consumed("bazel_core_toy_pin_consumed_bzlmod", System::Bzlmod);
}

#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_toy_pin_consumed_workspace() {
    toy_pin_consumed("bazel_core_toy_pin_consumed_workspace", System::Workspace);
}

/// The tamper twin: the pinned URL serves bytes with one bit flipped (the
/// same length: an appended byte is not a tamper every ruleset rejects).
/// Bazel must fail the fetch with its own checksum error. On an empty
/// repository cache, or the pin would be a cache hit and the host never asked.
fn toy_pin_tamper_twin(test: &str, system: System) {
    let Some(toy) = toy::open(test, system, true) else {
        return;
    };
    let patched = DEP.patched();
    let mut tampered = patched.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 0x01;
    toy.pin(LOCK, DEP, tampered.clone());
    let (got, want) = (toy::sha256_hex(&tampered), toy::sha256_hex(&patched));
    // Neither digest is cached, before the build and after it: the pin is
    // a request the host answers, and nothing is kept under it.
    let cached = toy
        .cell
        .scratch
        .repository_cache
        .join("content_addressable/sha256");
    let neither_cached = || !cached.join(&want).exists() && !cached.join(&got).exists();
    assert!(neither_cached(), "{test}: the repository cache is not cold");
    let early = toy.server.requests();
    assert!(
        early.is_empty(),
        "{test}: requests before the one build: {early:?}"
    );

    let run = toy.cell.failing_fetch("build", &[PROBE]);
    assert!(!run.ok(), "the tampered pin built:\n{}", run.dump());
    let refusal = format!("Checksum was {got} but wanted {want}");
    assert!(run.stderr().contains(&refusal), "{}", run.dump());
    let requests = toy.server.assert_requested(&DEP.hosted_url(), test);
    assert!(
        requests.iter().all(|request| request.status == 200),
        "{requests:?}"
    );
    assert!(neither_cached(), "{test}: the tampered download was kept");
    toy.finish();
}

#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_toy_pin_tamper_twin_bzlmod() {
    toy_pin_tamper_twin("bazel_core_toy_pin_tamper_twin_bzlmod", System::Bzlmod);
}

#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_toy_pin_tamper_twin_workspace() {
    toy_pin_tamper_twin(
        "bazel_core_toy_pin_tamper_twin_workspace",
        System::Workspace,
    );
}

/// The derived value is enforced: a toy lock whose sha256 changed while
/// `pinsHash` stayed does not load, on any entry point (`_packages` in
/// `toy.bzl` is shared by all three; Bzlmod is the one run here). Every
/// test that rewrites a pin relies on this check to show that the derived
/// hash it wrote is the right one. The message carries both values, so
/// this is also Starlark's `hash()` against the product's own.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_toy_lock_needs_its_derived_hash() {
    const TEST: &str = "bazel_core_toy_lock_needs_its_derived_hash";
    let Some(toy) = toy::open(TEST, System::Bzlmod, false) else {
        return;
    };
    let lock = toy.read(LOCK);
    let (upstream, patched) = (DEP.upstream(), DEP.patched());
    let (from, to) = (toy::sha256_hex(&upstream), toy::sha256_hex(&patched));
    assert_eq!(lock.matches(&from).count(), 1, "{lock}");
    let edited = lock.replace(&from, &to);
    toy.cell.write(LOCK, &edited);

    let run = toy.cell.failing_fetch("build", &[PROBE]);
    assert!(!run.ok(), "the half-edited lock built:\n{}", run.dump());
    let refusal = format!(
        "toy lock: pinsHash is {} but the pins hash to {}",
        toy::pins_hash(&lock),
        toy::pins_hash(&edited)
    );
    assert!(run.stderr().contains(&refusal), "{}", run.dump());
    toy.finish();
}

/// A tree under `.socket` that holds a BUILD file Bazel cannot load (an
/// upstream BUILD file names repositories this workspace does not have)
/// breaks `//...`, and one `.bazelignore` line is what hides it: on a warm
/// server, on a restarted one, and not without the line.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_bazelignore_hides_tree() {
    const TEST: &str = "bazel_core_bazelignore_hides_tree";
    const TREE: &str = ".socket/tree";
    let Some(toy) = toy::open(TEST, System::Bzlmod, false) else {
        return;
    };
    let cell = &toy.cell;
    cell.baseline(&["//..."], false);
    let stray = format!("{TREE}/pkg/BUILD.bazel");
    cell.write(
        &stray,
        "load(\"@no_such_repository//:defs.bzl\", \"thing\")\n",
    );
    let broken = |when: &str| {
        let run = cell.bazel("build", &["//..."]);
        assert!(
            !run.ok(),
            "{when}: //... built over the tree:\n{}",
            run.dump()
        );
        assert!(
            run.stderr().contains(&format!("{TREE}/pkg")),
            "{when}: {}",
            run.dump()
        );
    };
    broken("no .bazelignore");

    cell.write(".bazelignore", format!("{TREE}\n"));
    cell.bazel_ok("build", &["//..."]);
    let packages = cell.bazel_ok("query", &["//..."]).stdout();
    assert!(!packages.contains(".socket"), "{packages}");
    assert!(packages.contains(PROBE), "{packages}");
    cell.shutdown();
    cell.bazel_ok("build", &["//..."]);

    // A line for another tree hides nothing here.
    cell.write(".bazelignore", ".socket/other\n");
    broken("a line for another tree");
    toy.finish();
}

/// The fixture builds with no network at all: an empty repository cache,
/// the committed registry and archives, the committed lock in `error`
/// mode, and every proxy at a closed port. The fixture server's log is
/// the proof: Bazel asked it for the toy packages and for nothing it
/// could not answer from a committed file.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_zero_network() {
    const TEST: &str = "bazel_core_zero_network";
    let Some(mut toy) = toy::open_offline(TEST, System::Bzlmod) else {
        return;
    };
    // The fixture's one committed lock: `locks/v<lockFileVersion>/`.
    let locks = toy.cell.scratch.workspace.join("locks");
    let committed: Vec<PathBuf> = std::fs::read_dir(&locks)
        .expect("the fixture's committed locks")
        .map(|entry| entry.unwrap().path().join(MODULE_LOCK))
        .collect();
    let [committed] = &committed[..] else {
        panic!("{TEST}: one committed lock per fixture, found {committed:?}");
    };
    let lock = std::fs::read(committed).expect("read the committed lock");
    toy.cell.write_module_lock(&lock);
    toy.cell.options.lockfile_mode = "error";
    // The condition the claim names. In a healthy run every request is
    // rewritten to loopback, which `NO_PROXY` exempts, so no outcome below
    // would notice a cell that left the proxies alone: it is asserted on
    // the command every build of this cell is made from.
    assert!(
        toy.cell.options.closed_proxies,
        "{TEST}: the proxies are open"
    );
    assert!(
        toy.cell.options.downloader_config.is_some(),
        "{TEST}: no downloader rewrite"
    );
    let build = toy
        .cell
        .command_with(&toy.cell.options, "build", &["//..."]);
    for proxy in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        let value = build.get_envs().find(|(name, _)| *name == proxy);
        let value = value.and_then(|(_, value)| value);
        assert_eq!(value, Some(CLOSED_PORT.as_ref()), "{TEST}: {proxy}");
    }
    toy.cell.report.detail("closed_proxies", true);
    let cell = &toy.cell;

    cell.bazel_ok("build", &["//..."]);
    assert_eq!(cell.tier1_file(DEP_OUT), DEP.upstream());
    if cfg!(unix) {
        cell.bazel_ok("run", &[CONSUMER]);
    }
    assert_eq!(
        cell.module_lock().as_deref(),
        Some(&lock[..]),
        "`error` mode wrote the lock"
    );

    toy.server.assert_requested(&DEP.upstream_url(), TEST);
    let unanswered: Vec<String> = toy
        .server
        .requests()
        .into_iter()
        .filter(|request| request.status != 200)
        .map(|request| request.url)
        .collect();
    assert_eq!(
        unanswered,
        Vec::<String>::new(),
        "Bazel asked for files that are not committed"
    );
    let mut expected = vec!["registry.toy.invalid"];
    if cell.options.registry.is_none() {
        expected.insert(0, "bcr.bazel.build");
    }
    assert_eq!(toy.server.hosts(), expected);
    toy.finish();
}

/// The hybrid fixture declares the hub `toy` in MODULE.bazel and, from an
/// older lock, in WORKSPACE, and `toy_ws` in WORKSPACE alone. Where Bazel
/// reads both files the Bzlmod hub wins the shared name and the
/// WORKSPACE-only hub is live; read as WORKSPACE only, the same tree
/// builds the older pin. The package version each build yields is the marker.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_hybrid_hub_names_resolve_per_system() {
    const TEST: &str = "bazel_core_hybrid_hub_names_resolve_per_system";
    let Some(toy) = toy::open(TEST, System::Hybrid, false) else {
        return;
    };
    let cell = &toy.cell;
    let hybrid = &cell.options;
    let built = |options: &Options, target: &str| {
        let output = cell.probe_output(options, target, DEP_OUT);
        std::fs::read(&output).unwrap_or_else(|e| panic!("read {}: {e}", output.display()))
    };
    assert_eq!(built(hybrid, PROBE), DEP.upstream(), "both files: @toy");
    assert_eq!(
        built(hybrid, "//ws:socket_probe"),
        DEP_WS.upstream(),
        "both files: @toy_ws"
    );

    let workspace_only = Options {
        system: Some(System::Workspace),
        ..hybrid.clone()
    };
    assert_eq!(
        built(&workspace_only, PROBE),
        DEP_WS.upstream(),
        "WORKSPACE only: @toy"
    );
    toy.finish();
}

/// Bazel 7 and later write a placeholder `MODULE.bazel` into a workspace
/// that has only a WORKSPACE file as soon as a command runs with Bzlmod
/// on, even one that fails, and a lock once there is something to record
/// (under the committed `file://` registry that differs per line). Under
/// the flags of a WORKSPACE cell they write neither, and both are in the
/// set the tree comparisons leave out.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_workspace_only_gets_a_placeholder_module_file() {
    const TEST: &str = "bazel_core_workspace_only_gets_a_placeholder_module_file";
    let Some(mut toy) = toy::open(TEST, System::Workspace, false) else {
        return;
    };
    let cell = &toy.cell;
    let workspace = &cell.scratch.workspace;
    cell.baseline(&[PROBE], false);
    let before = snapshot(workspace);
    for owned in ["MODULE.bazel", MODULE_LOCK] {
        assert!(
            !workspace.join(owned).exists(),
            "{owned} under the WORKSPACE flags"
        );
    }

    // The line's default flags turn Bzlmod on. The query passes on 7.7.2;
    // on 8.8.2 it fails, because loading a package there needs module
    // archives this WORKSPACE cell never fetched (the fixture server
    // answers 404 for one on github.com). The placeholder appears either way.
    let defaults = Options {
        system: None,
        ..cell.options.clone()
    };
    let query = cell.bazel_with(&defaults, "query", &["//:all"]).ok();
    let placeholder = std::fs::read_to_string(workspace.join("MODULE.bazel"));
    assert_eq!(placeholder.ok().as_deref(), Some(PLACEHOLDER_MODULE_BAZEL));
    assert_same_tree_but_bazel_owned(&before, &snapshot(workspace));
    let lock_written = cell.module_lock().is_some();
    toy.cell
        .report
        .detail("default_flags_query_passed", query)
        .detail("module_lock_written", lock_written);
    toy.finish();
}

/// The facts-bearing hub (`toy_facts`, eras 8 and 9): Bazel records no
/// input for it, only one fact per package the toy registry serves. A pin
/// turns the package into a direct reference, so its fact goes: an
/// `error`-mode build of a target on the hub then fails on the facts, an
/// `update`-mode build consumes the pin and drops the fact, and the
/// recorded hub beside it is not disturbed.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_toy_facts_go_stale() {
    const TEST: &str = "bazel_core_toy_facts_go_stale";
    const FACTS_PROBE: &str = "//facts:socket_probe";
    const EXTENSION: &str = "//:toy.bzl%toy_facts";
    let Some(toy) = toy::open(TEST, System::Bzlmod, false) else {
        return;
    };
    let cell = &toy.cell;
    if !cell.scratch.workspace.join("facts").is_dir() {
        // `extension_metadata(facts = ...)` exists in Bazel 8.5.0 and later
        // (probed from 8.6.0; 8.4.2 rejects the keyword).
        probe_report::skip_na(&cell.report, "this era's fixture has no facts hub");
        return;
    }
    let lock = || -> serde_json::Value {
        let bytes = cell.module_lock().expect("Bazel wrote a lock");
        serde_json::from_slice(&bytes).expect("the lock is JSON")
    };
    cell.baseline(&["//..."], false);
    let recorded = lock();
    let digest = toy::sha256_hex(&INDEXED.upstream());
    assert_eq!(recorded["facts"][EXTENSION][INDEXED.name]["sha256"], digest);
    assert!(
        recorded["moduleExtensions"].get(EXTENSION).is_none(),
        "{recorded}"
    );
    assert!(
        recorded["moduleExtensions"].get("//:toy.bzl%toy").is_some(),
        "{recorded}"
    );
    assert!(cell.error_mode_build(&[FACTS_PROBE]).ok(), "a current lock");

    toy.pin("facts/toy.lock.json", INDEXED, INDEXED.patched());
    let stale = cell.error_mode_build(&[FACTS_PROBE]);
    assert!(!stale.ok(), "{}", stale.dump());
    assert!(
        stale.stderr().contains("has changed its facts"),
        "{}",
        stale.dump()
    );
    let other_hub = cell.error_mode_build(&[PROBE]);
    assert!(other_hub.ok(), "{}", other_hub.dump());

    let output = cell.probe_output(&cell.options, FACTS_PROBE, "indexed.sh");
    assert_eq!(
        std::fs::read(output).expect("read the probe output"),
        INDEXED.patched()
    );
    assert!(lock()["facts"].get(EXTENSION).is_none(), "{}", lock());
    assert!(
        cell.error_mode_build(&[FACTS_PROBE]).ok(),
        "the repaired lock"
    );
    toy.finish();
}
