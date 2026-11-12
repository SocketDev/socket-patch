//! Real-Bazel test of the derived-state verdict (`socket_patch_core::bazel::derived`):
//! what socket-patch predicts from `MODULE.bazel.lock` and the files on disk
//! against what Bazel itself does with them.
//!
//! The oracle is an `error`-mode build of a target that consumes the hub
//! (lock rule 3): `bazel mod deps --lockfile_mode=error` fails on a healthy
//! lock that builds made, and a green build of an unrelated target proves
//! nothing. Every lock under test was written by a build, never by `mod
//! deps`, because that is the lock a project commits when it only builds.
//!
//! No lane exists yet, so the edit is applied by hand, as a hosted lane
//! will write it (`toy::pin`): forward, and then the restoring edit that
//! puts the committed bytes back.
//!
//! A lock is never written onto an output base that evaluated other
//! inputs (lock rule 2: Bazel 8.6 to 9.2 then hide stale facts). The cell
//! that makes the locks only ever edits the inputs and lets Bazel write;
//! every state is then replayed in a fresh workspace copy with a fresh
//! output base, which is also what a CI machine sees.

use std::path::Path;

use serde_json::{json, Value};
use socket_patch_core::bazel::derived::{
    self, DerivedState, Edit, Evidence, ExtRef, FactsEdit, FactsOf, LockUse, Proof, Write,
};
use socket_patch_core::bazel::model::{BazelLine, FileText, FileView};
use socket_patch_core::bazel::module_lock::{ModuleLock, GENERAL};
use socket_patch_core::bazel::remedy;
use socket_patch_core::bazel::version::BazelVersion;

use crate::bazel_build_common::env::System;
use crate::bazel_build_common::invoke::Options;
use crate::bazel_build_common::proof::PROBE;
use crate::bazel_build_common::toy::{self, Toy, DEP, INDEXED};

const TEST: &str = "bazel_core_stale_verdict_matches_bazel";
/// The input of the hub `toy`, which Bazel records in the lock.
const LOCK: &str = "toy.lock.json";
/// The input of the hub `toy_facts` (eras 8 and 9), for which Bazel
/// records nothing but one fact per package of the toy registry.
const FACTS_LOCK: &str = "facts/toy.lock.json";
const FACTS_PROBE: &str = "//facts:socket_probe";
const TOY_EXTENSION: ExtRef<'static> = ExtRef {
    label: "//:toy.bzl",
    name: "toy",
};
const FACTS_EXTENSION: ExtRef<'static> = ExtRef {
    label: "//:toy.bzl",
    name: "toy_facts",
};
/// What every Bazel line prints for a stale lock, whatever follows it.
const STALE_LOCK: &str = "is no longer up-to-date";
/// The start of the line for stale facts. The rest holds both fact dicts
/// in full.
const STALE_FACTS: &str = "has changed its facts";

/// The workspace copy of a cell as the pure layer reads files.
struct Disk<'a>(&'a Path);

impl FileView for Disk<'_> {
    fn read(&self, rel: &str) -> FileText {
        match std::fs::read(self.0.join(rel)) {
            Ok(bytes) => FileText::Bytes(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileText::Absent,
            Err(_) => FileText::Unreadable,
        }
    }

    fn list(&self, _: &str) -> Option<Vec<String>> {
        None
    }
}

/// The two toy locks of the fixture, as committed and with the hosted pin.
struct Inputs {
    committed: String,
    pinned: String,
    /// The same pair for the facts hub; `None` on an era without one.
    facts: Option<(String, String)>,
}

/// One state a repository can be committed in: which input holds the pin,
/// and the `MODULE.bazel.lock` beside it.
struct State {
    name: &'static str,
    pinned: bool,
    facts_pinned: bool,
    module_lock: Vec<u8>,
    /// What [`derived::evidence`] must say about the pin; `""` where the
    /// input holds none.
    evidence: &'static str,
}

/// Compares the static verdict for the workspace as it is on disk with an
/// `error`-mode build of each hub's consumer. Returns what both said, for
/// the report.
fn check(toy: &Toy, inputs: &Inputs, state: &State, when: &str) -> Value {
    let cell = &toy.cell;
    let what = format!("{TEST}: {} ({when})", state.name);
    let files = Disk(&cell.scratch.workspace);
    let lock = ModuleLock::read(&files);
    assert!(
        matches!(lock, ModuleLock::FamilyA(_) | ModuleLock::FamilyB(_)),
        "{what}: Bazel wrote a lock this reader does not know: {lock:?}"
    );
    let version = BazelVersion::parse(&cell.bazel.version.text).expect("a pinned release");
    let line = BazelLine::of(version);
    let cx = remedy::Cx {
        line: &line,
        strict_repo_env: false,
        facts_in_lock: false,
        query_hub: Some("toy"),
    };

    // The recorded hub: the verdict is exact.
    let on_disk = toy.read(LOCK);
    let written = [Write::bytes(LOCK, on_disk.as_bytes())];
    let edit = Edit {
        writes: &written,
        ..Edit::default()
    };
    let rows = derived::stale(&lock, &edit);
    let recorded = DerivedState::RecordedInput {
        path: LOCK.to_string(),
        extension: "//:toy.bzl%toy".to_string(),
        platform: GENERAL.to_string(),
    };
    let stale = !rows.is_empty();
    assert!(!stale || rows == [recorded], "{what}: {rows:?}");
    let build = cell.error_mode_build(&[PROBE]);
    assert_eq!(
        build.ok(),
        !stale,
        "{what}: the static verdict is stale = {stale} and Bazel disagrees:\n{}",
        build.dump()
    );
    assert!(
        build.ok() || build.stderr().contains(STALE_LOCK),
        "{}",
        build.dump()
    );
    // The three outcomes follow the same verdict.
    let decided = |lock_use| derived::decide(&lock, &edit, lock_use, &cx);
    assert_eq!(decided(LockUse::Frozen).builds_fail(), stale, "{what}");
    let advisory = decided(LockUse::Refreshed).run_required();
    assert_eq!(advisory.is_some_and(|run| run.gates_vex), stale, "{what}");
    // An edit whose bytes are not known yet stales every record of the
    // file: what the gate predicts before a lane writes.
    let planned = [Write::changed(LOCK)];
    let planned = Edit {
        writes: &planned,
        ..Edit::default()
    };
    assert_eq!(derived::stale(&lock, &planned).len(), 1, "{what}");

    // Where the input holds the pin: is the lock evidence that the refresh
    // ran, and which bytes does a passing build consume?
    if state.pinned {
        let pin = toy::sha256_hex(&DEP.patched());
        let proof = Proof {
            inputs: &[LOCK],
            hub: &[TOY_EXTENSION],
            pin: Some(&pin),
            digest_function: false,
        };
        let evidence = derived::evidence(&lock, &files, &proof);
        let found = match &evidence {
            Evidence::Holds => "holds",
            Evidence::Pending { .. } => "pending",
            Evidence::DerivedStale { .. } => "derived stale",
        };
        assert_eq!(found, state.evidence, "{what}: {evidence:?}");
        if build.ok() {
            // A forged digest passes `error` mode on the unpatched
            // package: the reason the repository specs are part of the
            // evidence (probe L1.d).
            let error_mode = Options {
                lockfile_mode: "error",
                ..cell.options.clone()
            };
            let output = cell.probe_output(&error_mode, PROBE, "dep.sh");
            let built = std::fs::read(&output).expect("read the probe output");
            let (patched, upstream) = (built == DEP.patched(), built == DEP.upstream());
            let holds = evidence == Evidence::Holds;
            assert!(
                patched == holds && upstream != holds,
                "{what}: the evidence is {found:?} and the build is patched = {patched}"
            );
        }
    }

    // The facts hub: "possibly stale" is all a static read can say, and
    // both Bazel results are accepted for it. "Not stale" is exact.
    let mut facts_hub = Value::Null;
    if inputs.facts.is_some() {
        let on_disk = toy.read(FACTS_LOCK);
        let written = [Write::bytes(FACTS_LOCK, on_disk.as_bytes())];
        // The pin turned the one index package into a direct reference,
        // which has no fact; the restoring edit puts it back.
        let (key, none): (&[&str], &[&str]) = (&[INDEXED.name], &[]);
        let (removed, added) = if state.facts_pinned {
            (key, none)
        } else {
            (none, key)
        };
        let facts = FactsEdit {
            extension: FACTS_EXTENSION,
            of: FactsOf::Keyed,
            removed,
            added,
        };
        let edit = Edit {
            writes: &written,
            facts: Some(facts),
            ..Edit::default()
        };
        let rows = derived::stale(&lock, &edit);
        let possibly = !rows.is_empty();
        let only_facts = |row: &DerivedState| matches!(row, DerivedState::Facts { .. });
        assert!(rows.iter().all(only_facts), "{what}: {rows:?}");
        // Facts alone never refuse a lock that builds refresh, and `vex`
        // does not wait for them.
        let decision = derived::decide(&lock, &edit, LockUse::Refreshed, &cx);
        let gates_vex = decision.run_required().map(|run| run.gates_vex);
        assert_eq!(gates_vex, possibly.then_some(false), "{what}");
        assert!(!decision.builds_fail(), "{what}");

        let build = cell.error_mode_build(&[FACTS_PROBE]);
        assert!(
            possibly || build.ok(),
            "{what}: no fact is predicted stale and Bazel failed:\n{}",
            build.dump()
        );
        assert!(
            build.ok() || build.stderr().contains(STALE_FACTS),
            "{}",
            build.dump()
        );
        facts_hub = json!({"possibly_stale": possibly, "error_mode_build_passed": build.ok()});
    }
    // `error` mode never writes the lock.
    assert_eq!(
        cell.module_lock().as_deref(),
        Some(&state.module_lock[..]),
        "{what}: an `error`-mode build changed MODULE.bazel.lock"
    );
    json!({"stale": stale, "error_mode_build_passed": build.ok(), "facts_hub": facts_hub})
}

/// Write the inputs of `state` into the cell (not the lock).
fn write_inputs(toy: &Toy, inputs: &Inputs, state: &State) {
    let pick = |pinned: bool, committed, with_pin| if pinned { with_pin } else { committed };
    let toy_lock: &String = pick(state.pinned, &inputs.committed, &inputs.pinned);
    toy.cell.write(LOCK, toy_lock);
    if let Some((committed, pinned)) = &inputs.facts {
        let facts_lock: &String = pick(state.facts_pinned, committed, pinned);
        toy.cell.write(FACTS_LOCK, facts_lock);
    }
}

/// Open a cell on the Bzlmod toy fixture with the pinned packages served.
fn open() -> Option<Toy> {
    let toy = toy::open(TEST, System::Bzlmod, false)?;
    for package in [DEP, INDEXED] {
        toy.server.serve(&package.hosted_url(), package.patched());
    }
    Some(toy)
}

/// End a cell that is not the test's last one, with every check of
/// [`Toy::finish`] and without its report: a report of status `ran` is the
/// evidence a claim rests on, and only the whole test may leave one.
fn finish_without_report(toy: Toy) {
    let report = toy.cell.report.path();
    toy.finish();
    std::fs::remove_file(&report).unwrap_or_else(|e| panic!("remove {}: {e}", report.display()));
}

/// The static verdict equals Bazel's, on a lock made by builds: as
/// committed, after the forward edit, after Bazel refreshed the lock, after
/// the restoring edit, and for a lock whose digest was forged by hand.
/// Each state is checked where it arose (a warm output base that never saw
/// a lock it did not write) and again in a fresh workspace copy with a
/// fresh output base.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn bazel_core_stale_verdict_matches_bazel() {
    let Some(toy) = open() else {
        return;
    };
    let has_facts = toy.cell.scratch.workspace.join("facts").is_dir();
    let committed = toy.read(LOCK);
    let facts = has_facts.then(|| toy.read(FACTS_LOCK));
    let inputs = Inputs {
        pinned: toy::pin(&committed, DEP),
        committed,
        facts: facts.map(|committed| {
            let pinned = toy::pin(&committed, INDEXED);
            (committed, pinned)
        }),
    };
    let module_lock = |toy: &Toy| toy.cell.module_lock().expect("Bazel wrote a lock");
    let state = |name, pinned: bool, module_lock: &[u8], evidence| State {
        name,
        pinned,
        facts_pinned: pinned && has_facts,
        module_lock: module_lock.to_vec(),
        evidence,
    };
    let mut warm = serde_json::Map::new();
    let mut note = |state: &State, found: Value| warm.insert(state.name.to_string(), found);

    // The cell that makes the locks. It never writes MODULE.bazel.lock.
    toy.cell.baseline(&["//..."], false);
    let first = module_lock(&toy);
    let fresh = state("fresh", false, &first, "");
    note(&fresh, check(&toy, &inputs, &fresh, "where it arose"));

    let forward = state("forward", true, &first, "pending");
    write_inputs(&toy, &inputs, &forward);
    note(&forward, check(&toy, &inputs, &forward, "where it arose"));

    // The works-after command, as a build runs it.
    toy.cell.bazel_ok("build", &["//..."]);
    let second = module_lock(&toy);
    assert_ne!(first, second, "{TEST}: the refresh left the lock as it was");
    let refreshed = state("refreshed", true, &second, "holds");
    note(
        &refreshed,
        check(&toy, &inputs, &refreshed, "where it arose"),
    );

    let reverse = state("reverse", false, &second, "");
    write_inputs(&toy, &inputs, &reverse);
    note(&reverse, check(&toy, &inputs, &reverse, "where it arose"));
    finish_without_report(toy);

    // The forged lock: the first lock with the recorded digest of the
    // input replaced by the pinned file's, and nothing else.
    let digest = |text: &str| toy::sha256_hex(text.as_bytes());
    let text = String::from_utf8(first.clone()).expect("the lock is UTF-8");
    let (before, after) = (digest(&inputs.committed), digest(&inputs.pinned));
    assert_eq!(text.matches(&before).count(), 1, "{TEST}: {text}");
    let forged = text.replace(&before, &after);
    let forged = State {
        facts_pinned: false,
        ..state("forged", true, forged.as_bytes(), "derived stale")
    };

    // Each state again, in a fresh workspace copy with a fresh output base.
    let mut cold = serde_json::Map::new();
    let states = [fresh, forward, refreshed, reverse, forged];
    for (index, state) in states.iter().enumerate() {
        let Some(mut toy) = open() else {
            return;
        };
        write_inputs(&toy, &inputs, state);
        toy.cell.write_module_lock(&state.module_lock);
        let found = check(&toy, &inputs, state, "fresh output base");
        cold.insert(state.name.to_string(), found);
        if index + 1 < states.len() {
            finish_without_report(toy);
            continue;
        }
        let report = &mut toy.cell.report;
        report.detail("facts_hub", has_facts);
        report.detail("where_it_arose", warm.clone());
        report.detail("fresh_output_base", cold.clone());
        toy.finish();
    }
}
