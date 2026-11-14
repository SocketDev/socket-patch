//! Hermetic CLI tests: a mode takeover under a Bazel hub (design 7). The
//! target mode's gate is asked before any step that touches the source
//! mode's wiring, so a refused takeover leaves the source mode byte for
//! byte: a vendored entry is never reverted for a hosted pin the gate
//! refuses, and a hosted pin is never restored for a vendored artifact it
//! refuses. Every production lane is disabled, so the built binary
//! refuses both under a hub; the expectations are computed with
//! `Code::refusal`. Under no Bazel root neither run reports a Bazel code.
//!
//! No Bazel and no network: a loopback server stands in for the Socket
//! API.

#[path = "../hosted_memory_common/mod.rs"]
mod hosted_memory_common;

use std::collections::BTreeMap;

use serde_json::json;
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::model::{Mode, Reason};
use socket_patch_core::bazel::owned_index::INDEX_PATH;
use wiremock::MockServer;

use crate::bazel_common::{assert_same_tree, snapshot};
use crate::common::envelope::event_for;
use crate::rollback::{bazel_codes, hosted_lock, lane, registries, run, Checkout, ORG};
use hosted_memory_common::{mount_api, run_disk_in, Patch};

const ARTIFACT: &str = ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz";
const LEDGER: &str = ".socket/vendor/state.json";

/// The files of an npm project whose `left-pad` is vendored (a ledger
/// entry and its artifact), and (`bazel`) the rules_js hub over its lock.
fn vendored(bazel: bool) -> BTreeMap<String, Vec<u8>> {
    let entry = json!({
        "ecosystem": "npm",
        "basePurl": lane::PURL,
        "uuid": lane::UUID,
        "artifact": { "path": ARTIFACT },
        "wiring": [{ "file": lane::LOCK, "kind": "pnpm-lock", "action": "rewritten" }],
    });
    let ledger = json!({ "version": 1, "entries": { lane::PURL: entry } });
    let deps = r#"{"name": "p", "version": "0.0.0", "dependencies": {"left-pad": "1.3.0"}}"#;
    let module = lane::MODULE.replace("LOCK_LABEL", "//:pnpm-lock.yaml");
    let mut files = vec![
        (lane::LOCK, lane::LOCK_TEXT.to_string()),
        ("package.json", deps.to_string()),
        (LEDGER, format!("{ledger:#}\n")),
        (ARTIFACT, "a vendored tarball\n".to_string()),
    ];
    if bazel {
        files.push((".bazelversion", lane::BAZELVERSION.to_string()));
        files.push(("MODULE.bazel", module));
    }
    let bytes = |(rel, text): (&str, String)| (rel.to_string(), text.into_bytes());
    files.into_iter().map(bytes).collect()
}

/// The patch of `left-pad` as the fake Socket API grants it.
fn patch() -> Patch {
    let artifact = json!({
        "kind": "tarball", "url": lane::URL, "integrity": { "sha512": lane::PATCHED },
    });
    let reference = json!({
        "status": "granted", "url": lane::URL, "purl": null, "artifacts": [artifact],
        "registryOverride": null,
    });
    Patch {
        purl: lane::PURL.to_string(),
        uuid: lane::UUID.to_string(),
        reference,
    }
}

/// Vendored to hosted: the hosted gate refuses the pin under the hub, so
/// the revert of the vendored entry is never staged. The package is
/// skipped under the code of the hosted refusal and the run writes
/// nothing: the ledger, the artifact and the lock are what they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_hosted_takeover_leaves_the_entry_vendored() {
    let api = MockServer::start().await;
    mount_api(&api, &[patch()]).await;
    let refusal = Code::refusal(Mode::Hosted, Reason::RulesetUnsupported).expect("a code");
    for dry_run in [true, false] {
        let run = run_disk_in(&api, &vendored(true), "", dry_run);
        let envelope = &run.envelope;
        assert_eq!(
            run.changed,
            BTreeMap::new(),
            "dry_run={dry_run}: {envelope:#}"
        );
        let event = event_for(envelope, lane::PURL);
        assert_eq!(event["action"], "skipped", "{envelope:#}");
        assert_eq!(event["errorCode"], refusal.as_str(), "{envelope:#}");
        let reason = event["reason"].as_str().unwrap_or_default();
        assert!(reason.ends_with("nothing was written"), "{event:#}");
        // The refusal is mapped as every gate refusal is: the token and
        // what would lift it ride the event, beside what Bazel builds
        // the package from.
        let details = &event["details"];
        let token = details["token"].as_str().unwrap_or_default();
        assert!(!token.is_empty(), "{event:#}");
        assert!(details["lift"]["kind"].is_string(), "{event:#}");
        let bazel = &details["bazel"];
        assert_eq!(bazel["state"], "refused", "{event:#}");
        assert_eq!(bazel["ruleset"], "rules_js", "{event:#}");
        assert_eq!(bazel["lock"], lane::LOCK, "{event:#}");
        assert_eq!(bazel["lane"], details["lift"]["lane"], "{event:#}");
        assert_eq!(details["mode"], "hosted", "{event:#}");
        // The run says the refusal as a warning too, and no code of an
        // undo: nothing was staged to take back.
        let codes = bazel_codes(envelope);
        let said = codes.iter().filter(|code| *code == refusal.as_str());
        assert_eq!(said.count(), 2, "{codes:?}");
        let undone = Code::RedirectRevertIncomplete.as_str();
        assert!(!codes.iter().any(|code| code == undone), "{codes:?}");
    }
    // The same project under no Bazel root: the takeover is the native
    // one, which stages the revert of this hand-made entry and fails at
    // it. So the run above never reached that step, and no Bazel code is
    // reported here.
    let plain = run_disk_in(&api, &vendored(false), "", true);
    assert_eq!(bazel_codes(&plain.envelope), Vec::<String>::new());
    let event = event_for(&plain.envelope, lane::PURL);
    assert_eq!(event["errorCode"], "vendored_revert_failed", "{event:#}");
}

/// Vendored to hosted beside an owned index that is not the one
/// socket-patch wrote: no lane writes beside it, so the takeover is
/// refused before the vendored entry is touched, under the code of an
/// owned file somebody edited, with the index as the file to restore.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_takeover_beside_a_faulty_index_is_refused_and_changes_nothing() {
    let api = MockServer::start().await;
    mount_api(&api, &[patch()]).await;
    let mut files = vendored(true);
    let mangled = b"{\"version\": 1, \"pins\": [], \"ignoreLines\": \"oops\"}\n";
    files.insert(INDEX_PATH.to_string(), mangled.to_vec());
    let refusal = Code::RedirectOwnedFileModified.as_str();
    for dry_run in [true, false] {
        let run = run_disk_in(&api, &files, "", dry_run);
        let envelope = &run.envelope;
        assert_eq!(
            run.changed,
            BTreeMap::new(),
            "dry_run={dry_run}: {envelope:#}"
        );
        let event = event_for(envelope, lane::PURL);
        assert_eq!(event["action"], "skipped", "{envelope:#}");
        assert_eq!(event["errorCode"], refusal, "{envelope:#}");
        let details = &event["details"];
        assert!(details["token"].is_string(), "{event:#}");
        assert_eq!(details["lift"]["file"], INDEX_PATH, "{event:#}");
        assert_eq!(details["bazel"]["state"], "refused", "{event:#}");
    }
}

/// Hosted to vendored: the vendored gate refuses the artifact under the
/// hub before the hosted pin is restored, so the lock keeps the pin byte
/// for byte and no artifact is fetched or vendored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_vendored_takeover_leaves_the_hosted_pin() {
    let server = MockServer::start().await;
    mount_api(&server, &[patch()]).await;
    // The eject plans the restore of the pin before it vendors anything.
    registries(&server).await;
    let ws = Checkout::new(true);
    ws.put(lane::LOCK, hosted_lock());
    ws.record();
    let before = snapshot(&ws.root);
    let uri = server.uri();
    let api = ["--org", ORG, "--api-token", "fake-token", "--api-url", &uri];
    let args = [&["vendor", "--json"][..], &api[..]].concat();
    let (code, envelope) = run(&ws.root, &args, &server).await;
    assert_eq!(code, 1, "{envelope:#}");
    let refusal = Code::refusal(Mode::Vendored, Reason::RulesetUnsupported).expect("a code");
    let codes = bazel_codes(&envelope);
    assert!(
        codes.iter().any(|code| code == refusal.as_str()),
        "{envelope:#}"
    );
    assert_same_tree(&before, &snapshot(&ws.root));
    let asked = server.received_requests().await.unwrap_or_default();
    let fetched = |r: &&wiremock::Request| r.url.path().contains("/patch/");
    assert_eq!(
        asked.iter().filter(fetched).count(),
        0,
        "no artifact was fetched"
    );
}
