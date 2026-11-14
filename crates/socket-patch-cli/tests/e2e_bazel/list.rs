//! Hermetic CLI tests: `list` under a Bazel root (design 7). Each event of
//! a package that a ruleset builds says what the Bazel build makes of the
//! pin in `details.bazel`; an event of any other package, and every event
//! under no Bazel root, is what it always was. `list` only reads, so it is
//! never refused for where it runs (owner decision O16).
//!
//! The built binary has no enabled lane and proves nothing consumed: its
//! state is `withheld`. What an event says once a lane proves the pin is
//! shown in process, over the lane table of the hosted seam's tests.

use serde_json::{json, Value};
use socket_patch_cli::bazel_gate::commands;
use socket_patch_cli::json_envelope::{Command, Envelope, PatchAction, PatchEvent};
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::owned_index::{Index, IndexEdit, IndexRow, INDEX_PATH};
use socket_patch_core::vendor::state::VendorArtifact;
use socket_patch_core::vendor::{VendorEntry, VendorState, WiringRecord};
use wiremock::MockServer;

use crate::bazel_common::{assert_same_tree, snapshot};
use crate::common::envelope::event_for;
use crate::common::{git_sha256, write_minimal_manifest, PatchEntry};
use crate::rollback::{common, hosted_lock, lane, run, Checkout};

/// A hosted pin in the lock a hub reads is listed with what the build
/// makes of it: the ruleset and the lock, and `withheld`, because no
/// enabled lane proves the build consumes it. The same pin under no Bazel
/// root carries no such member. Nothing is written by either run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pin_under_a_hub_says_what_the_build_makes_of_it() {
    let server = MockServer::start().await;
    for bazel in [true, false] {
        let ws = Checkout::new(bazel);
        ws.put(lane::LOCK, hosted_lock());
        let before = snapshot(&ws.root);
        let (code, envelope) = run(&ws.root, &["list", "--json"], &server).await;
        assert_eq!(code, 0, "{envelope:#}");
        let event = event_for(&envelope, lane::PURL);
        assert_eq!(event["action"], "discovered", "{envelope:#}");
        assert_eq!(event["details"]["mode"], "hosted", "{envelope:#}");
        let said = json!({ "state": "withheld", "ruleset": "rules_js", "lock": lane::LOCK });
        let expected = if bazel { said } else { Value::Null };
        assert_eq!(event["details"]["bazel"], expected, "{envelope:#}");
        assert_same_tree(&before, &snapshot(&ws.root));
    }
}

/// Over a lane that proves the pin, the event of the record says
/// `consumed` with the lane and its anchor, and a pin `apply` routed to a
/// vendored lane says so. An event of a package Bazel does not build gets
/// no member.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proven_pin_is_consumed_and_a_routed_one_says_its_route() {
    let ws = Checkout::new(true);
    ws.put(
        lane::LOCK,
        lane::LOCK_TEXT.replace(lane::UPSTREAM, &lane::pinned()),
    );
    let mut index = Index::default();
    index.record_pin(IndexRow {
        uuid: lane::UUID.to_string(),
        purl: lane::PURL.to_string(),
        lane: lane::LANE.0.to_string(),
        file: lane::LOCK.to_string(),
        edits: vec![IndexEdit {
            key: "packages/left-pad@1.3.0/resolution".to_string(),
            original: lane::UPSTREAM_SRI.to_string(),
            new: lane::PATCHED.to_string(),
        }],
        check: None,
    });
    ws.put(INDEX_PATH, index.render().expect("an index that renders"));
    let listing = || {
        let mut env = Envelope::new(Command::List);
        for purl in [lane::PURL, "pkg:composer/vendor/other@1.0.0"] {
            let event = PatchEvent::new(PatchAction::Discovered, purl);
            env.record(
                event
                    .with_uuid(lane::UUID)
                    .with_details(json!({ "tier": "free" })),
            );
        }
        env
    };
    let args = common(&ws, false);

    let mut env = listing();
    commands::list(&args, &mut env, None, &lane::TABLE).await;
    let details: Vec<Value> = env
        .events
        .iter()
        .filter_map(|e| e.details.clone())
        .collect();
    let consumed = json!({
        "state": "consumed", "ruleset": "rules_js", "lock": lane::LOCK,
        "lane": lane::LANE.0, "anchor": "digest",
    });
    assert_eq!(details[0], json!({ "tier": "free", "bazel": consumed }));
    assert_eq!(
        details[1],
        json!({ "tier": "free" }),
        "Bazel builds no composer package"
    );

    // The ledger says `apply` routed the package to a vendored lane.
    let artifact = VendorArtifact {
        yarn_berry10c0: None,
        path: ".socket/vendor/npm/x/left-pad-1.3.0.tgz".to_string(),
        sha256: String::new(),
        size: None,
        platform_locked: None,
        file_inventory: None,
    };
    let wiring = vec![WiringRecord::bazel_index("", lane::UUID, true)];
    let (eco, purl, uuid) = (
        "npm".to_string(),
        lane::PURL.to_string(),
        lane::UUID.to_string(),
    );
    let entry = VendorEntry::new(eco, purl, uuid, artifact, wiring);
    let mut ledger = VendorState::default();
    ledger.entries.insert(lane::PURL.to_string(), entry);
    let mut env = listing();
    commands::list(&args, &mut env, Some(&ledger), &lane::TABLE).await;
    let bazel = &env.events[0].details.as_ref().expect("details")["bazel"];
    assert_eq!(bazel["route"], "vendored", "{bazel:#}");

    // The shipped lanes prove nothing: the same pin is withheld.
    let mut env = listing();
    commands::list(&args, &mut env, None, &commands::PRODUCTION).await;
    let bazel = &env.events[0].details.as_ref().expect("details")["bazel"];
    assert_eq!(bazel["state"], "withheld", "{bazel:#}");
    assert_eq!(
        bazel["lane"],
        lane::LANE.0,
        "the row names its lane: {bazel:#}"
    );
}

/// `list` is the one command of owner decision O16 that is not refused in
/// a tree Bazel owns: with `--cwd` inside an output base, and run from
/// inside it, it exits 0 and lists the manifest's patch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_is_not_refused_in_a_tree_bazel_owns() {
    let server = MockServer::start().await;
    let ws = Checkout::new(true);
    let marker = ws.root.to_string_lossy().into_owned();
    ws.put("out/DO_NOT_BUILD_HERE", &marker);
    ws.put("out/execroot/DO_NOT_BUILD_HERE", &marker);
    let project = ws.at("out/external/npm__left-pad__1.3.0");
    let entry = PatchEntry {
        file_name: "package/index.js",
        before_hash: &git_sha256(b"upstream\n"),
        after_hash: &git_sha256(b"patched\n"),
    };
    write_minimal_manifest(&project.join(".socket"), lane::PURL, lane::UUID, &[entry]);
    let before = snapshot(&ws.root);
    let named = project.to_string_lossy();
    let forms = [
        (project.as_path(), &["list", "--json"][..]),
        (ws.root.as_path(), &["list", "--json", "--cwd", &*named][..]),
    ];
    for (cwd, args) in forms {
        let (code, envelope) = run(cwd, args, &server).await;
        assert_eq!(code, 0, "{args:?}: {envelope:#}");
        assert_eq!(envelope["error"], Value::Null, "{args:?}: {envelope:#}");
        let event = event_for(&envelope, lane::PURL);
        assert_eq!(event["uuid"], lane::UUID, "{args:?}: {envelope:#}");
    }
    assert_same_tree(&before, &snapshot(&ws.root));
}

/// `apply --check` and the owned index. A record that was never wired
/// adds no drift, whatever the index holds for another patch, and neither
/// does a row whose pins no enabled lane can tell: cannot tell is not
/// drift. An index that is not the one socket-patch wrote is drift, by
/// name: nothing can be said of the wiring it records.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_check_fails_on_a_mangled_index_and_not_on_what_no_lane_can_tell() {
    let server = MockServer::start().await;
    let args = ["apply", "--check", "--json", "--offline"];
    let ws = Checkout::new(true);
    ws.record();
    let mut index = Index::default();
    for uuid in ["0a1b2c3d-0000-4000-8000-0000000000a1", lane::UUID] {
        // First a row of another patch, then one of the record's own.
        index.record_pin(IndexRow {
            uuid: uuid.to_string(),
            purl: lane::PURL.to_string(),
            lane: lane::LANE.0.to_string(),
            file: lane::LOCK.to_string(),
            edits: vec![IndexEdit {
                key: "packages/left-pad@1.3.0/resolution".to_string(),
                original: lane::UPSTREAM_SRI.to_string(),
                new: lane::PATCHED.to_string(),
            }],
            check: None,
        });
        ws.put(INDEX_PATH, index.render().expect("an index that renders"));
        let before = snapshot(&ws.root);
        let (code, envelope) = run(&ws.root, &args, &server).await;
        assert_eq!(code, 0, "{uuid}: {envelope:#}");
        assert_same_tree(&before, &snapshot(&ws.root));
    }
    // A row no socket-patch wrote: its lane is no lane ID.
    let rendered = index.render().expect("an index");
    ws.put(INDEX_PATH, rendered.replace(lane::LANE.0, "toy"));
    let (code, envelope) = run(&ws.root, &args, &server).await;
    assert_eq!(code, 1, "{envelope:#}");
    let drift = event_for(&envelope, INDEX_PATH);
    let modified = Code::RedirectOwnedFileModified.as_str();
    assert_eq!(drift["errorCode"], modified, "{envelope:#}");

    // Beside such an index a rollback keeps the record of a package the
    // hub builds: which rows the index holds for it is not known.
    let before = snapshot(&ws.root);
    let (code, envelope) = run(
        &ws.root,
        &["rollback", "--json", "--yes", "--offline"],
        &server,
    )
    .await;
    assert_eq!(code, 1, "{envelope:#}");
    let kept = event_for(&envelope, lane::PURL);
    assert_eq!(kept["details"]["bazel"]["state"], "kept", "{envelope:#}");
    assert_same_tree(&before, &snapshot(&ws.root));
}
