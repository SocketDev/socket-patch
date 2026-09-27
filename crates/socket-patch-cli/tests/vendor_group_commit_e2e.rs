//! Group commit of a vendored run (see
//! `socket_patch_core::utils::group_commit`): every lockfile, manifest,
//! config and ledger edit of the run is written once, after the loop,
//! through a roll-forward journal.
//!
//! * **Equivalence.** For every ecosystem, a completed run ends in exactly
//!   the tree the per-package commits produce — the debug build's
//!   `SOCKET_PATCH_SWITCH_OFF=group_commit` switch runs that path as the
//!   oracle — including a run where one package fails and the other
//!   succeeds, and the `--revert` that follows.
//! * **Crash safety.** The debug build's failpoints crash the binary mid-loop,
//!   at the artifact barrier, right after the journal is written, and after
//!   the first journaled file is replaced. Before the journal, the project's
//!   lockfiles and ledger are exactly the pre-run ones; after it, the next
//!   locked command finishes the commit; either way the next run ends in
//!   the uninterrupted run's tree. A journal that no longer matches the
//!   files (a hand edit after the crash) is set aside whole, never
//!   half-applied.

#[path = "vendor_ecosystem_fixtures/mod.rs"]
mod fx;

use fx::{masked_tree, Fixture};

const OFF: (&str, &str) = ("SOCKET_PATCH_SWITCH_OFF", "group_commit");

fn events(stdout: &str) -> Vec<(String, String, String)> {
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("envelope JSON: {e}\n{stdout}"));
    v["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|e| {
            (
                e["purl"].as_str().unwrap_or_default().to_string(),
                e["action"].as_str().unwrap_or_default().to_string(),
                e["errorCode"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// The paths whose bytes differ between two trees (or exist in one only).
fn differing(a: &[(String, String)], b: &[(String, String)]) -> Vec<String> {
    let mut out: Vec<String> = a
        .iter()
        .filter(|entry| !b.contains(entry))
        .chain(b.iter().filter(|entry| !a.contains(entry)))
        .map(|(rel, _)| rel.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A completed run commits the same tree as committing after every package,
/// for every ecosystem, and the revert that follows restores the same tree.
#[test]
fn group_commit_ends_where_per_package_commits_end_for_every_ecosystem() {
    for eco in fx::ALL {
        let grouped = Fixture::new(eco);
        let oracle = Fixture::new(eco);
        let pristine = masked_tree(&grouped.root);

        let (code, stdout, stderr) = grouped.vendor(&[], &[]);
        let (oracle_code, oracle_stdout, oracle_stderr) = oracle.vendor(&[], &[OFF]);
        assert_eq!(code, 0, "{eco}: {stdout}\n{stderr}");
        assert_eq!(
            oracle_code, 0,
            "{eco} (oracle): {oracle_stdout}\n{oracle_stderr}"
        );
        let applied: Vec<_> = events(&stdout)
            .into_iter()
            .filter(|(_, action, _)| action == "applied")
            .map(|(purl, ..)| purl)
            .collect();
        assert_eq!(
            applied.len(),
            grouped.patches.len(),
            "{eco}: both packages vendor: {stdout}"
        );
        assert_eq!(
            events(&stdout),
            events(&oracle_stdout),
            "{eco}: same events"
        );
        assert_eq!(
            masked_tree(&grouped.root),
            masked_tree(&oracle.root),
            "{eco}: same committed tree"
        );
        assert!(
            !grouped
                .root
                .join(".socket/vendor/.commit-journal.json")
                .exists(),
            "{eco}: a completed commit leaves no journal"
        );

        // In sync: a re-run writes nothing.
        let before = masked_tree(&grouped.root);
        let (code, stdout, _) = grouped.vendor(&[], &[]);
        assert_eq!(code, 0, "{eco}: {stdout}");
        assert_eq!(masked_tree(&grouped.root), before, "{eco}: in-sync re-run");

        let (code, stdout, stderr) = grouped.vendor(&["--revert"], &[]);
        let (oracle_code, ..) = oracle.vendor(&["--revert"], &[OFF]);
        assert_eq!(code, 0, "{eco} revert: {stdout}\n{stderr}");
        assert_eq!(oracle_code, 0, "{eco} revert (oracle)");
        assert_eq!(
            masked_tree(&grouped.root),
            masked_tree(&oracle.root),
            "{eco}: same tree after --revert"
        );
        // Two ecosystems keep scaffolding their revert does not remove when
        // TWO packages were vendored (the emptied pnpm override tables and
        // workspace file; the catch-all `<packageSourceMapping>` nuget adds
        // to a config that had none). That predates the group commit — the
        // oracle leaves the same bytes, asserted just above — so only the
        // others are held to a byte-exact round trip here.
        if !["pnpm", "nuget"].contains(eco) {
            let after = masked_tree(&grouped.root);
            assert!(
                after == pristine,
                "{eco}: --revert restores the pre-vendor project byte for byte; differing: {:?}",
                differing(&after, &pristine)
            );
        }
    }
}

/// One package fails (its patch target is missing from the installed copy,
/// which fails closed without `--force`), the other succeeds: the success is
/// committed, the failure leaves nothing, and the tree is the per-package
/// commits' tree.
#[test]
fn a_partial_failure_commits_the_packages_that_succeeded() {
    for (eco, target) in [
        ("npm", "proj:node_modules/beta/index.js"),
        (
            "cargo",
            "store:cargo-home/registry/src/index.crates.io-6f17d22bba15001f/beta-1.0.0/src/lib.rs",
        ),
        ("gem", "proj:vendor/bundle/gems/beta-1.0.0/lib/beta.rb"),
        ("golang", "store:modcache/github.com/fx/beta@v1.0.0/beta.go"),
    ] {
        let grouped = Fixture::new(eco);
        let oracle = Fixture::new(eco);
        for f in [&grouped, &oracle] {
            let path = match target.split_once(':') {
                Some(("proj", rel)) => f.root.join(rel),
                Some((_, rel)) => f.store.join(rel),
                None => unreachable!(),
            };
            std::fs::remove_file(path).unwrap();
        }
        let (code, stdout, _) = grouped.vendor(&[], &[]);
        let (oracle_code, oracle_stdout, _) = oracle.vendor(&[], &[OFF]);
        assert_eq!(code, oracle_code, "{eco}: {stdout}\n{oracle_stdout}");
        assert_ne!(code, 0, "{eco}: the failed package fails the run");
        let ev = events(&stdout);
        assert!(
            ev.iter()
                .any(|(p, a, _)| *p == grouped.patches[0].purl && a == "applied"),
            "{eco}: {stdout}"
        );
        assert!(
            !ev.iter()
                .any(|(p, a, _)| *p == grouped.patches[1].purl && a == "applied"),
            "{eco}: {stdout}"
        );
        assert_eq!(ev, events(&oracle_stdout), "{eco}: same events");
        assert_eq!(
            masked_tree(&grouped.root),
            masked_tree(&oracle.root),
            "{eco}: same committed tree"
        );
        let state = std::fs::read_to_string(grouped.root.join(".socket/vendor/state.json"))
            .unwrap_or_else(|e| panic!("{eco}: the success is committed: {e}"));
        assert!(state.contains(&grouped.patches[0].purl), "{eco}");
        assert!(!state.contains(&grouped.patches[1].purl), "{eco}");
    }
}

/// The files a crash before the journal must leave exactly as they were.
fn commit_points(f: &Fixture) -> Vec<(String, Vec<u8>)> {
    f.tree()
        .into_iter()
        .filter(|(rel, _)| !rel.starts_with(".socket/vendor/") || rel.ends_with("state.json"))
        .collect()
}

/// Crash at `failpoint`, then let the next run finish; returns the crashed
/// fixture's final tree next to an uninterrupted run's.
fn crash_then_rerun(eco: &str, failpoint: &str, before_journal: bool) {
    let clean = Fixture::new(eco);
    let (code, stdout, _) = clean.vendor(&[], &[]);
    assert_eq!(code, 0, "{eco}: {stdout}");

    let f = Fixture::new(eco);
    let pre = commit_points(&f);
    let (code, stdout, stderr) = f.vendor(&[], &[("SOCKET_PATCH_FAILPOINT", failpoint)]);
    assert_eq!(
        code, 86,
        "{eco}/{failpoint}: the crash fires: {stdout}\n{stderr}"
    );
    let journal = f.root.join(".socket/vendor/.commit-journal.json");
    if before_journal {
        assert_eq!(
            commit_points(&f),
            pre,
            "{eco}/{failpoint}: no commit point is written before the journal"
        );
        assert!(!journal.exists(), "{eco}/{failpoint}");
    } else {
        assert!(
            journal.is_file(),
            "{eco}/{failpoint}: the journal is the commit"
        );
    }

    let (code, stdout, stderr) = f.vendor(&[], &[]);
    assert_eq!(
        code, 0,
        "{eco}/{failpoint}: the next run completes: {stdout}\n{stderr}"
    );
    assert!(
        !journal.exists(),
        "{eco}/{failpoint}: the journal is consumed"
    );
    assert_eq!(
        masked_tree(&f.root),
        masked_tree(&clean.root),
        "{eco}/{failpoint}: the next run ends where an uninterrupted run ends"
    );
}

#[test]
fn a_crash_mid_loop_leaves_the_pre_run_commit_points() {
    for eco in ["npm", "pnpm", "cargo", "nuget"] {
        crash_then_rerun(eco, "vendor_package_recorded@1", true);
    }
}

#[test]
fn a_crash_at_the_artifact_barrier_leaves_the_pre_run_commit_points() {
    for eco in ["pnpm", "golang", "maven"] {
        crash_then_rerun(eco, "durability_barrier", true);
    }
}

#[test]
fn a_crash_after_the_journal_is_rolled_forward_by_the_next_locked_command() {
    for eco in ["pnpm", "cargo", "gem", "pypi-requirements"] {
        crash_then_rerun(eco, "group_commit_journal", false);
        crash_then_rerun(eco, "group_commit_file@1", false);
    }
}

/// The roll-forward runs under ANY command's lock, not just `vendor`: a
/// `vendor --revert` after the crash first finishes the commit, then
/// reverts the fully-wired project byte for byte.
#[test]
fn the_roll_forward_runs_before_any_locked_command_reads_the_files() {
    let f = Fixture::new("npm");
    let pristine = masked_tree(&f.root);
    let (code, ..) = f.vendor(&[], &[("SOCKET_PATCH_FAILPOINT", "group_commit_file@1")]);
    assert_eq!(code, 86);
    let (code, stdout, stderr) = f.vendor(&["--revert"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(masked_tree(&f.root), pristine);
}

/// A file the journal covers was edited by hand after the crash: the
/// journal matches neither side of it, so it is set aside whole (with a
/// warning), nothing of it is applied, and the run proceeds over the
/// project as it stands.
#[test]
fn a_journal_the_files_no_longer_match_is_set_aside_not_half_applied() {
    let f = Fixture::new("pnpm");
    let (code, ..) = f.vendor(&[], &[("SOCKET_PATCH_FAILPOINT", "group_commit_journal")]);
    assert_eq!(code, 86);
    let lock_before = std::fs::read(f.root.join("pnpm-lock.yaml")).unwrap();
    let pkg = f.root.join("package.json");
    let mut edited = std::fs::read_to_string(&pkg).unwrap();
    edited.push('\n');
    std::fs::write(&pkg, &edited).unwrap();

    let (code, stdout, stderr) = f.run(&["vendor", "--json", "--offline", "--dry-run"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stderr.contains("set aside"),
        "the set-aside is reported: {stderr}"
    );
    assert!(!f.root.join(".socket/vendor/.commit-journal.json").exists());
    let aside: Vec<_> = std::fs::read_dir(f.root.join(".socket/vendor"))
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".commit-journal.set-aside-")
        })
        .collect();
    assert_eq!(aside.len(), 1, "the journal is kept for inspection");
    assert_eq!(
        std::fs::read(f.root.join("pnpm-lock.yaml")).unwrap(),
        lock_before,
        "no file of the set-aside journal is applied"
    );
    assert_eq!(std::fs::read_to_string(&pkg).unwrap(), edited);
}
