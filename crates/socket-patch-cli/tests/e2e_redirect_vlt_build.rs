//! Real-vlt hosted capstone (suite `hosted`, DESIGN §8.3).
//!
//! Every leg installs a project with the REAL vlt under test against the
//! harness's local npm registry, publishes a patch on the mock patch
//! service (its artifact built from the registry bytes), runs the real
//! `socket-patch` hosted flow, and then lets vlt itself install from the
//! rewritten `vlt-lock.json`. Each leg is `vlt_pinned_matrix_hosted_<leg>`
//! and prints one `VLT-LEG` line (see `vlt_e2e_common`). The legs each era
//! skips, and why, are the `hosted` rows of `vlt-leg-manifest.json`.
//!
//! Run: `SOCKET_PATCH_VLT_E2E_JS=<vlt.js> cargo test -p socket-patch-cli
//! --test e2e_redirect_vlt_build -- --include-ignored vlt_pinned_matrix`.

use std::path::Path;

use serde_json::{json, Value};

#[path = "vlt_e2e_common/mod.rs"]
mod vlt_e2e_common;
#[path = "vex_e2e_common/vlt.rs"]
mod vlt_vex;

use vlt_e2e_common::fixture::*;
use vlt_e2e_common::*;

const SUITE: &str = "hosted";

fn hosted_leg(name: &'static str) -> Option<Leg> {
    Leg::start(SUITE, name)
}

// ── drivers and fresh checkouts ───────────────────────────────────────────

/// `scan --mode hosted --vex`: the lock pins the artifact (one preflight
/// GET), in-run VEX attests it unless a lock-level warning withholds it,
/// and a fresh checkout's locked install lands the patched bytes with the
/// lock byte-stable.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_scan_fresh_ci() {
    let Some(leg) = hosted_leg("scan_fresh_ci") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    let out = fx.scan_vex(&[]);
    let doc = out.json();
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    fx.assert_lock_warnings(&doc);
    fx.assert_in_run_vex(&out, fx.t(), fx.in_run_vex_attests());
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    assert_eq!(fx.svc.artifact_hits(fx.t()).await, 1, "one preflight GET");
    fx.assert_fresh_locked_install("fresh-ci");
    fx.leg.ran();
}

/// The fresh checkout's frozen install and `vlt ci` succeed with every
/// registry route answering 404: the patched bytes come from the hosted
/// URL alone.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_frozen_dead_registry() {
    let Some(leg) = hosted_leg("frozen_dead_registry") else {
        return;
    };
    if !leg.at_least(HAS_CI_FROM) {
        return leg.skip("no-vlt-ci");
    }
    if !hermetic_registry(leg.version()) {
        return leg.skip("non-hermetic-registry");
    }
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    fx.scan(&[]);
    fx.reg.kill().await;
    for (name, args) in [
        ("frozen", vec!["install", "--frozen-lockfile"]),
        ("ci", vec!["ci"]),
    ] {
        let co = fx.checkout(name);
        let before = lock_bytes(&co);
        fx.vlt_ok_profile(&co, &args, name);
        assert_eq!(state(&co, fx.t()), State::Patched, "{name}");
        assert_eq!(lock_bytes(&co), before, "{name} keeps the lock");
    }
    assert!(
        fx.reg.requests().await.is_empty(),
        "the dead registry saw requests: {:?}",
        fx.reg.requests().await
    );
    fx.leg.ran();
}

/// A plain `vlt install` of the fresh checkout installs the patched bytes
/// and leaves the rewritten lock byte-identical.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_ordinary_install_stable() {
    let Some(leg) = hosted_leg("ordinary_install_stable") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    fx.scan(&[]);
    let co = fx.checkout("ordinary");
    let before = lock_bytes(&co);
    fx.vlt_ok_profile(&co, &["install"], "ordinary");
    assert_eq!(state(&co, fx.t()), State::Patched);
    assert_eq!(
        String::from_utf8_lossy(&lock_bytes(&co)),
        String::from_utf8_lossy(&before)
    );
    fx.leg.ran();
}

/// `get <uuid> --mode hosted` lands the same rewrite; no manifest or
/// blobs are written.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_get_uuid_fresh_ci() {
    let Some(leg) = hosted_leg("get_uuid_fresh_ci") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    let doc = get_hosted(&fx.proj, &fx.svc, UUID, &[]);
    assert_eq!(doc["redirect"]["mode"], "hosted", "{doc:#}");
    assert!(warning_detail(&doc, ADVISORY).starts_with("vlt-lock.json pins"));
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    assert!(!fx.proj.join(".socket/manifest.json").exists());
    assert!(!fx.proj.join(".socket/blobs").exists());
    fx.assert_fresh_locked_install("fresh-get");
    fx.leg.ran();
}

/// The artifact URL serves different (valid) bytes than the pinned
/// sha512: a cold-cache locked install fails `EINTEGRITY`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_tamper_cold_eintegrity() {
    let Some(leg) = hosted_leg("tamper_cold_eintegrity") else {
        return;
    };
    if !integrity_enforced(leg.version()) {
        return leg.skip("integrity-unenforced");
    }
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    fx.scan(&[]);
    let t = fx.t().clone();
    let mut files = t.patched_files();
    files.insert(
        t.file.clone(),
        [TAMPER_MARKER, t.before.as_slice()].concat(),
    );
    fx.svc.serve_artifact(&t, build_tgz(&files), 1).await;
    let co = fx.checkout("tampered");
    let out = fx.vlt_profile(&co, &fx.leg.locked_install_args(), "tampered-cold");
    assert!(
        !out.status.success(),
        "a tampered artifact must fail the install: {}",
        out_text(&out)
    );
    let text = out_text(&out);
    assert!(
        text.contains("EINTEGRITY") || text.to_lowercase().contains("integrity"),
        "{text}"
    );
    assert_ne!(state(&co, &t), State::Tampered, "tampered bytes installed");
    fx.leg.ran();
}

// ── rollback, rerun, heal ─────────────────────────────────────────────────

/// Rollback restores the lock byte-for-byte, heals the patched store copy
/// (and nothing else), and the next `vlt install` is pristine.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_rollback_byte_exact() {
    let Some(leg) = hosted_leg("rollback_byte_exact") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander()).await;
    fx.scan(&[]);
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    let ids = fx.store_ids(fx.t());
    let snap = fx.snapshot(&fx.proj, &ids);
    let out = rollback(&fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    let doc = out.json();
    assert_eq!(
        String::from_utf8_lossy(&lock_bytes(&fx.proj)),
        String::from_utf8_lossy(&fx.lock_before),
        "rollback restores vlt-lock.json byte-for-byte"
    );
    assert!(fx.ledger().is_none(), "the ledger is gone");
    fx.assert_advisory(&doc, &advisory_rolled_back(1));
    for id in &ids {
        assert!(!store_entry(&fx.proj, id).exists(), "{id} healed");
    }
    snap.assert_same(&fx.snapshot(&fx.proj, &ids), "the rollback heal");
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), State::Pristine);
    fx.leg.ran();
}

/// A second scan of an already-patched, installed project changes
/// nothing: the lock and ledger stay byte-identical and nothing is healed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_rerun_noop() {
    let Some(leg) = hosted_leg("rerun_noop") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander()).await;
    fx.scan(&[]);
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    let lock = lock_bytes(&fx.proj);
    let ledger = fx.ledger();
    let snap = fx.snapshot(&fx.proj, &[]);
    let doc = fx.scan(&[]);
    assert_eq!(lock_bytes(&fx.proj), lock, "rerun keeps the lock");
    assert_eq!(fx.ledger(), ledger, "rerun keeps the ledger");
    fx.assert_advisory(&doc, &advisory_nothing_stale());
    snap.assert_same(&fx.snapshot(&fx.proj, &[]), "a healthy rerun");
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    fx.leg.ran();
}

/// A warm pristine tree: the scan removes the stale store entry and the
/// hidden lock (nothing else), and a plain `vlt install` is then patched.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_warm_tree_invalidates() {
    let Some(leg) = hosted_leg("warm_tree_invalidates") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    let ids = fx.store_ids(fx.t());
    let snap = fx.snapshot(&fx.proj, &ids);
    let doc = fx.scan(&[]);
    fx.assert_advisory(&doc, &advisory_invalidated(ids.len()));
    for id in &ids {
        assert!(!store_entry(&fx.proj, id).exists(), "{id} invalidated");
    }
    assert!(!hidden_lock_exists(&fx.proj), "hidden lock removed");
    snap.assert_same(&fx.snapshot(&fx.proj, &ids), "the heal");
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    fx.leg.ran();
}

/// `--no-vlt-install-cleanup`: the stale copy stays, advisory (iii),
/// in-run VEX withheld, a plain `vlt install` keeps it stale (vlt trusts
/// its hidden lock), and `vlt ci` installs the patch.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_no_cleanup_stays_stale() {
    let Some(leg) = hosted_leg("no_cleanup_stays_stale") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad().warm()).await;
    let out = fx.scan_vex(&["--no-vlt-install-cleanup"]);
    let doc = out.json();
    fx.assert_advisory(&doc, &advisory_cleanup_skipped(1));
    fx.assert_in_run_vex(&out, fx.t(), false);
    for id in fx.store_ids(fx.t()) {
        assert!(store_entry(&fx.proj, &id).exists(), "{id} kept");
    }
    fx.vlt_ok(&fx.proj, &["install"]);
    let want = if plain_install_refreshes_stale(fx.leg.version()) {
        State::Patched
    } else {
        State::Pristine
    };
    assert_eq!(
        state(&fx.proj, fx.t()),
        want,
        "vlt install does not refresh a stale installed copy (0.0.0-14 does)"
    );
    if fx.leg.at_least(HAS_CI_FROM) {
        fx.vlt_ok(&fx.proj, &["ci"]);
        assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    }
    fx.leg.ran();
}

/// Heal rule (b): the hidden lock parses but has no node for the target.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_heal_rule_b_hidden_lock_without_node() {
    let Some(leg) = hosted_leg("heal_rule_b_hidden_lock_without_node") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    if !hidden_lock_exists(&fx.proj) {
        panic!(
            "vlt {} wrote no hidden lock; the manifest must skip this leg",
            fx.leg.tc.raw
        );
    }
    let ids = fx.store_ids(fx.t());
    let hidden = fx.proj.join(HIDDEN_LOCK);
    let mut doc: Value = serde_json::from_slice(&std::fs::read(&hidden).unwrap()).unwrap();
    for id in &ids {
        doc["nodes"].as_object_mut().unwrap().remove(id);
    }
    std::fs::write(&hidden, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    let snap = fx.snapshot(&fx.proj, &ids);
    let out = fx.scan(&["--no-vlt-install-cleanup"]);
    fx.assert_advisory(&out, &advisory_cleanup_skipped(ids.len()));
    snap.assert_same(&fx.snapshot(&fx.proj, &ids), "the skipped cleanup");
    let out = fx.scan(&[]);
    fx.assert_advisory(&out, &advisory_invalidated(ids.len()));
    for id in &ids {
        assert!(!store_entry(&fx.proj, id).exists(), "{id} invalidated");
    }
    snap.assert_same(&fx.snapshot(&fx.proj, &ids), "the rule (b) heal");
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    fx.leg.ran();
}

/// Heal rule (c): no hidden lock, the record's afterHash decides.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_heal_rule_c_no_hidden_lock() {
    let Some(leg) = hosted_leg("heal_rule_c_no_hidden_lock") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::with_bystander().warm()).await;
    let _ = std::fs::remove_file(fx.proj.join(HIDDEN_LOCK));
    let ids = fx.store_ids(fx.t());
    let snap = fx.snapshot(&fx.proj, &ids);
    let doc = fx.scan(&[]);
    fx.assert_advisory(&doc, &advisory_invalidated(ids.len()));
    for id in &ids {
        assert!(!store_entry(&fx.proj, id).exists(), "{id} invalidated");
    }
    snap.assert_same(&fx.snapshot(&fx.proj, &ids), "the rule (c) heal");
    assert!(
        store_entry(&fx.proj, &node_id(&read_lock(&fx.proj), MS.0, MS.1)).exists(),
        "the bystander is healthy"
    );
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    fx.leg.ran();
}

/// Heal rule (c) with no patch record (the view route fails): the
/// preflight-downloaded artifact bytes decide.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_heal_rule_c_no_record() {
    let Some(leg) = hosted_leg("heal_rule_c_no_record") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad().warm()).await;
    let _ = std::fs::remove_file(fx.proj.join(HIDDEN_LOCK));
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(format!(
            "/v0/orgs/{ORG}/patches/view/{UUID}"
        )))
        .respond_with(wiremock::ResponseTemplate::new(404))
        .with_priority(1)
        .mount(&fx.svc.server)
        .await;
    let ids = fx.store_ids(fx.t());
    let snap = fx.snapshot(&fx.proj, &ids);
    let doc = fx.scan(&[]);
    fx.assert_advisory(&doc, &advisory_invalidated(ids.len()));
    for id in &ids {
        assert!(!store_entry(&fx.proj, id).exists(), "{id} invalidated");
    }
    snap.assert_same(&fx.snapshot(&fx.proj, &ids), "the artifact-bytes heal");
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    fx.leg.ran();
}

// ── package shapes ────────────────────────────────────────────────────────

/// A scoped package (`@isaacs/string-locale-compare`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_scoped() {
    let Some(leg) = hosted_leg("scoped") else {
        return;
    };
    let shape = Shape {
        deps: vec![SCOPED],
        pins: vec![SCOPED],
        targets: vec![(SCOPED.0, SCOPED.1, UUID_SCOPED, "index.js")],
        ..Shape::left_pad()
    };
    let fx = Fixture::build(leg, shape).await;
    let doc = fx.scan(&[]);
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    fx.assert_fresh_locked_install("fresh-scoped");
    fx.leg.ran();
}

/// Two workspaces depend on `use-sync-external-store` beside react 17 and
/// react 18: vlt dedupes them into exactly one shared peer instance on
/// every measured release (no real-vlt shape yields several instances of
/// one name@version), it is pinned, and both workspaces install the
/// patched bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_peer_workspace_instances() {
    let Some(leg) = hosted_leg("peer_workspace_instances") else {
        return;
    };
    let usx = ("use-sync-external-store", "1.2.0");
    let shape = Shape {
        deps: vec![],
        pins: vec![
            usx,
            ("react", "17.0.2"),
            ("react", "18.2.0"),
            ("loose-envify", "1.4.0"),
            ("js-tokens", "4.0.0"),
            ("object-assign", "4.1.1"),
        ],
        targets: vec![(usx.0, usx.1, UUID_USX, "index.js")],
        vlt_json: VltJson {
            workspaces: Some(json!("packages/*")),
            ..VltJson::default()
        },
        files: vec![
            (
                "packages/a/package.json".into(),
                package_json("a", &[usx, ("react", "17.0.2")]),
            ),
            (
                "packages/b/package.json".into(),
                package_json("b", &[usx, ("react", "18.2.0")]),
            ),
        ],
        ..Shape::left_pad()
    };
    let fx = Fixture::build(leg, shape).await;
    let t = fx.t().clone();
    let ids = fx.store_ids(&t);
    assert_eq!(
        ids.len(),
        1,
        "one shared instance: {}",
        String::from_utf8_lossy(&fx.lock_before)
    );
    let doc = fx.scan(&[]);
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    assert_pinned(&fx.proj, &fx.svc, &t);
    let co = fx.checkout("fresh-peers");
    fx.vlt_ok_profile(&co, &fx.leg.locked_install_args(), "fresh-peers");
    for ws in ["packages/a", "packages/b"] {
        let dir = importer_dir(&co, ws, &t.name);
        assert_eq!(state_at(&dir, &t), State::Patched, "{ws}");
    }
    fx.leg.ran();
}

// ── lock re-saves ─────────────────────────────────────────────────────────

/// `vlt install <newdep>` keeps the redirect.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_install_newdep_preserves() {
    let Some(leg) = hosted_leg("install_newdep_preserves") else {
        return;
    };
    let shape = Shape {
        pins: vec![LP, MS],
        ..Shape::left_pad()
    };
    let fx = Fixture::build(leg, shape).await;
    fx.scan(&[]);
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    fx.vlt_ok(&fx.proj, &["install", "ms@2.1.3"]);
    assert_eq!(node_ids(&read_lock(&fx.proj), MS.0, MS.1).len(), 1);
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    if resave_drops_hosted_url(fx.leg.version()) {
        assert_url_dropped(&fx);
        let co = fx.checkout("fresh-dropped");
        let out = fx.vlt_profile(&co, &fx.leg.locked_install_args(), "fresh-dropped");
        assert!(
            !out.status.success() && out_text(&out).to_lowercase().contains("integrity"),
            "the registry bytes fail the kept patched integrity: {}",
            out_text(&out)
        );
        fx.scan(&[]);
    }
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    fx.assert_fresh_locked_install("fresh-newdep");
    fx.leg.ran();
}

/// rc.6 … rc.17 re-save a default-registry node without slot [3]: the
/// patched integrity stays, the hosted URL is gone.
fn assert_url_dropped(fx: &Fixture) {
    let lock = read_lock(&fx.proj);
    for id in node_ids(&lock, LP.0, LP.1) {
        let tuple = &lock["nodes"][&id];
        assert_eq!(tuple[2], fx.t().sri(), "{id}: {lock:#}");
        assert!(tuple[3].is_null(), "{id} keeps no URL: {lock:#}");
    }
}

/// `vlt update` from 1.0.8 re-resolves from the registry and drops the
/// redirect (the lock is back on the registry integrity, and a standalone
/// `vex` no longer attests the patch); from 0.0.0-20 (the first `update`)
/// through 1.0.7 it keeps the pinned lock and the patch stays attested.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_update_drops() {
    let Some(leg) = hosted_leg("update_drops") else {
        return;
    };
    if !leg.at_least(VLT_UPDATE_FROM) {
        return leg.skip("no-vlt-update");
    }
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    fx.scan(&[]);
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    fx.vlt_ok(&fx.proj, &["update"]);
    let drops = fx.leg.at_least(UPDATE_RERESOLVES_FROM);
    if drops {
        assert_not_pinned(&fx.proj, fx.t());
    } else {
        assert_pinned(&fx.proj, &fx.svc, fx.t());
    }
    let out = standalone_vex(&fx);
    assert_eq!(
        vex_doc_attests(&fx.proj.join("out.vex.json"), fx.t()),
        !drops,
        "{out}"
    );
    fx.leg.ran();
}

/// Re-save after the scan (`vlt install <new>`: commas move, a CRLF lock
/// comes back LF): rollback restores the registry pin, keeps the new
/// dependency, and a following `vlt ci` installs the registry bytes.
async fn resave_install_rollback(name: &'static str, crlf: bool) {
    let Some(leg) = hosted_leg(name) else {
        return;
    };
    let shape = Shape {
        pins: vec![LP, MS],
        ..Shape::left_pad()
    };
    let fx = Fixture::build(leg, shape).await;
    if crlf {
        std::fs::write(fx.proj.join(VLT_LOCK), to_crlf(&fx.lock_before)).unwrap();
    }
    fx.scan(&[]);
    if crlf {
        assert!(lock_bytes(&fx.proj).windows(2).any(|w| w == b"\r\n"));
    }
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    fx.vlt_ok(&fx.proj, &["install", "ms@2.1.3"]);
    if crlf {
        assert!(
            !lock_bytes(&fx.proj).windows(2).any(|w| w == b"\r\n"),
            "vlt re-saves LF"
        );
    }
    if resave_drops_hosted_url(fx.leg.version()) {
        assert_url_dropped(&fx);
        let dropped = lock_bytes(&fx.proj);
        let out = rollback(&fx.proj, &[]);
        assert_eq!(out.code, 1, "{out}");
        let failed = out.json()["hosted"]["failed"][0]["error"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            failed.contains("drifted from the recorded redirect")
                && failed.contains("re-run `socket-patch scan --mode hosted` and then roll back"),
            "{out}"
        );
        assert_eq!(lock_bytes(&fx.proj), dropped, "drift: no write");
        fx.scan(&[]);
    }
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    let out = rollback(&fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_not_pinned(&fx.proj, fx.t());
    let lock = read_lock(&fx.proj);
    let before: Value = serde_json::from_slice(&fx.lock_before).unwrap();
    let id = node_id(&lock, LP.0, LP.1);
    assert_eq!(lock["nodes"][&id][2], before["nodes"][&id][2]);
    assert_eq!(node_ids(&lock, MS.0, MS.1).len(), 1, "the new dep stays");
    if fx.leg.at_least(HAS_CI_FROM) {
        let co = fx.checkout("after-rollback");
        fx.vlt_ok_profile(&co, &["ci"], "after-rollback");
        assert_eq!(state(&co, fx.t()), State::Pristine);
        assert!(installed(&co, MS.0, "index.js").is_some());
    }
    fx.leg.ran();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_resave_install_rollback() {
    resave_install_rollback("resave_install_rollback", false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_resave_crlf_rollback() {
    resave_install_rollback("resave_crlf_rollback", true).await;
}

/// scan → `vlt update` → rollback: already reverted, and the patched store
/// copy the update left behind is invalidated (r-vlt L3).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_resave_update_rollback() {
    let Some(leg) = hosted_leg("resave_update_rollback") else {
        return;
    };
    if !leg.at_least(VLT_UPDATE_FROM) {
        return leg.skip("no-vlt-update");
    }
    let fx = Fixture::build(leg, Shape::with_bystander()).await;
    fx.scan(&[]);
    fx.vlt_ok(&fx.proj, &fx.leg.locked_install_args());
    fx.vlt_ok(&fx.proj, &["update"]);
    let drops = fx.leg.at_least(UPDATE_RERESOLVES_FROM);
    if drops {
        assert_not_pinned(&fx.proj, fx.t());
    }
    assert_eq!(
        state(&fx.proj, fx.t()),
        State::Patched,
        "vlt update leaves the patched store copy"
    );
    let lock = lock_bytes(&fx.proj);
    let ids = fx.store_ids(fx.t());
    let snap = fx.snapshot(&fx.proj, &ids);
    let out = rollback(&fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    if drops {
        assert_eq!(
            lock_bytes(&fx.proj),
            lock,
            "already reverted: no lock write"
        );
    } else {
        assert_not_pinned(&fx.proj, fx.t());
    }
    fx.assert_advisory(&out.json(), &advisory_rolled_back(1));
    for id in &ids {
        assert!(!store_entry(&fx.proj, id).exists(), "{id} invalidated");
    }
    snap.assert_same(&fx.snapshot(&fx.proj, &ids), "the rollback heal");
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), State::Pristine);
    fx.leg.ran();
}

/// A CRLF lock: the rewritten line keeps its `\r`, and a fresh checkout
/// installs the patch.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_crlf_lock() {
    let Some(leg) = hosted_leg("crlf_lock") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    let crlf = to_crlf(&fx.lock_before);
    std::fs::write(fx.proj.join(VLT_LOCK), &crlf).unwrap();
    fx.scan(&[]);
    let text = String::from_utf8(lock_bytes(&fx.proj)).unwrap();
    assert!(
        !text.replace("\r\n", "").contains('\n'),
        "every line keeps CRLF"
    );
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    let co = fx.checkout("fresh-crlf");
    fx.vlt_ok_profile(&co, &fx.leg.locked_install_args(), "fresh-crlf");
    assert_eq!(state(&co, fx.t()), State::Patched);
    let out = rollback(&fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(
        lock_bytes(&fx.proj),
        crlf,
        "rollback restores the CRLF lock"
    );
    fx.leg.ran();
}

// ── registry shapes ───────────────────────────────────────────────────────

/// `registries.npm` pointing at a mirror (≥ rc.33): `~npm~` DepIDs with
/// the mirror's tarball URLs, rewritten like the default registry.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_mirror_registries_npm() {
    let Some(leg) = hosted_leg("mirror_registries_npm") else {
        return;
    };
    if !leg.at_least(REGISTRIES_NPM_ROUTES_FROM) {
        return leg.skip("registries-npm-ignored");
    }
    let shape =
        Shape::left_pad().vlt_json_fn(|_, r| json!({ "config": { "registries": { "npm": r } } }));
    let fx = Fixture::build(leg, shape).await;
    let lock = read_lock(&fx.proj);
    assert_eq!(
        lock["options"]["registries"]["npm"],
        fx.reg.url(),
        "{lock:#}"
    );
    assert_eq!(node_id(&lock, LP.0, LP.1), "~npm~left-pad@1.3.0");
    fx.scan(&[]);
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    fx.assert_fresh_locked_install("fresh-mirror");
    fx.leg.ran();
}

/// A scalar `registry` (URL-segment DepIDs; on ≥ rc.33 beside
/// `registries.npm`): the default-registry predicate pins the URL segment.
/// rc.7 … rc.29 warn `redirect_vlt_scalar_registry_ignored` and a locked
/// install silently re-resolves from public npm (pinned: unpatched).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_scalar_registry() {
    let Some(leg) = hosted_leg("scalar_registry") else {
        return;
    };
    let v = leg.version();
    let shape = Shape::left_pad().vlt_json_fn(|v, r| {
        let mut config = json!({ "registry": r });
        if v >= REGISTRIES_NPM_ROUTES_FROM {
            config["registries"] = json!({ "npm": "https://registry.npmjs.org/" });
        }
        let mut doc = if flat_vlt_json(v) {
            config
        } else {
            json!({ "config": config })
        };
        if lock_ignored_without_modifiers(v) {
            doc["modifiers"] = json!({});
        }
        doc
    });
    let fx = Fixture::build(leg, shape).await;
    let lock = read_lock(&fx.proj);
    let id = node_id(&lock, LP.0, LP.1);
    assert_eq!(
        id.contains("127.0.0.1"),
        v >= REGISTRY_DEP_IDS_FROM,
        "a scalar registry writes a URL segment from 0.0.0-14: {id}"
    );
    let doc = fx.scan(&[]);
    fx.assert_lock_warnings(&doc);
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    let co = fx.checkout("fresh-scalar");
    fx.vlt_ok_profile(&co, &fx.leg.locked_install_args(), "fresh-scalar");
    let want = if scalar_registry_ignored(v) {
        State::Pristine
    } else {
        State::Patched
    };
    assert_eq!(state(&co, fx.t()), want, "{id}");
    fx.leg.ran();
}

/// A named alias registry (`acme:left-pad@1.3.0`) beside the default one:
/// only the default instance is pinned, the alias instance is skipped with
/// `redirect_vlt_custom_registry_skipped`, and in-run VEX is withheld.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_named_alias_untouched() {
    let Some(leg) = hosted_leg("named_alias_untouched") else {
        return;
    };
    if !leg.at_least(REGISTRY_DEP_IDS_FROM) {
        return leg.skip("no-named-registry-specs");
    }
    let acme = Registry::start(&[LP]).await;
    let acme_url = acme.url();
    let mut shape = Shape::left_pad()
        .vlt_json_fn(move |v, r| with_registries(v, r, json!({ "acme": acme_url }), &[]));
    shape.deps.push(("lp-acme", "acme:left-pad@1.3.0"));
    let fx = Fixture::build(leg, shape).await;
    let lock = read_lock(&fx.proj);
    let ids = node_ids(&lock, LP.0, LP.1);
    assert_eq!(
        ids.iter().filter(|i| i.contains("acme")).count(),
        1,
        "one acme instance: {ids:?}"
    );
    let out = fx.scan_vex(&[]);
    let doc = out.json();
    assert!(
        has_warning(&doc, "redirect_vlt_custom_registry_skipped"),
        "{doc:#}"
    );
    let after = read_lock(&fx.proj);
    for id in &ids {
        let pinned = after["nodes"][id][2] == fx.t().sri();
        assert_eq!(pinned, !id.contains("acme"), "{id}: {after:#}");
    }
    fx.assert_in_run_vex(&out, fx.t(), false);
    fx.leg.ran();
}

/// A scoped registry (`scoped-registries`): the scope's instance is
/// foreign, skipped with `redirect_vlt_custom_registry_skipped`, never
/// pinned; the default-registry target beside it is.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_scoped_registry_untouched() {
    let Some(leg) = hosted_leg("scoped_registry_untouched") else {
        return;
    };
    if !leg.at_least(REGISTRY_DEP_IDS_FROM) {
        return leg.skip("registry-not-in-dep-id");
    }
    let scope_reg = Registry::start(&[SCOPED]).await;
    let scope_url = scope_reg.url();
    let shape = Shape {
        deps: vec![LP, SCOPED],
        pins: vec![LP],
        targets: vec![
            (LP.0, LP.1, UUID, "index.js"),
            (SCOPED.0, SCOPED.1, UUID_SCOPED, "index.js"),
        ],
        ..Shape::left_pad()
    }
    .vlt_json_fn(move |v, r| {
        with_registries(
            v,
            r,
            json!({}),
            &[(
                if v >= SCOPED_REGISTRIES_KEY_FROM {
                    "scoped-registries"
                } else {
                    "scope-registries"
                },
                json!({ "@isaacs": scope_url }),
            )],
        )
    });
    let fx = Fixture::build_with(leg, shape, &[&scope_reg]).await;
    let out = fx.scan_vex(&[]);
    let doc = out.json();
    assert!(
        has_warning(&doc, "redirect_vlt_custom_registry_skipped"),
        "{doc:#}"
    );
    let scoped = fx.svc.target(SCOPED.0).clone();
    assert_not_pinned(&fx.proj, &scoped);
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    fx.assert_in_run_vex(&out, &scoped, false);
    fx.leg.ran();
}

/// A jsr dependency (`jsr:@vlte2e/jpkg@1.0.0`: vlt records the jsr
/// registry's npm-compat package `@jsr/vlte2e__jpkg` under `~jsr~`) beside
/// the npm instance of that package: only the npm instance is pinned; the
/// jsr node is skipped with `redirect_vlt_custom_registry_skipped` and
/// in-run VEX is withheld.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_jsr_untouched() {
    let Some(leg) = hosted_leg("jsr_untouched") else {
        return;
    };
    if !leg.at_least(REGISTRY_DEP_IDS_FROM) {
        return leg.skip("registry-not-in-dep-id");
    }
    if !leg.at_least(JSR_REGISTRIES_ROUTE_FROM) {
        return leg.skip("jsr-registry-not-configurable");
    }
    if !hermetic_registry(leg.version()) || npm_alias_to_public_npm(leg.version()) {
        return leg.skip("non-hermetic-registry");
    }
    let jpkg = || {
        synthetic_pkg(
            json!({ "name": "@jsr/vlte2e__jpkg", "version": "1.0.0", "main": "index.js" }),
            &[("index.js", b"module.exports = 'jpkg';\n")],
        )
    };
    let jsr = Registry::start_with(&[], vec![jpkg()]).await;
    let jsr_url = jsr.url();
    let mut shape = Shape {
        deps: vec![
            ("@vlte2e/jpkg", "jsr:@vlte2e/jpkg@1.0.0"),
            ("jpkg-npm", "npm:@jsr/vlte2e__jpkg@1.0.0"),
        ],
        pins: vec![],
        synthetic: vec![jpkg()],
        targets: vec![("@jsr/vlte2e__jpkg", "1.0.0", UUID_SCOPED, "index.js")],
        ..Shape::left_pad()
    };
    shape = shape.vlt_json_fn(move |v, r| {
        with_registries(
            v,
            r,
            json!({ "npm": r }),
            &[("jsr-registries", json!({ "jsr": jsr_url }))],
        )
    });
    let fx = Fixture::build(leg, shape).await;
    let lock = read_lock(&fx.proj);
    let ids = node_ids(&lock, "@jsr/vlte2e__jpkg", "1.0.0");
    assert!(
        ids.iter()
            .any(|i| i.starts_with("~jsr~") || i.starts_with("·jsr·")),
        "a jsr instance: {lock:#}"
    );
    let out = fx.scan_vex(&[]);
    let doc = out.json();
    assert!(
        has_warning(&doc, "redirect_vlt_custom_registry_skipped"),
        "{doc:#}"
    );
    let after = read_lock(&fx.proj);
    for id in &ids {
        let pinned = after["nodes"][id][2] == fx.t().sri();
        let foreign = id.starts_with("~jsr~") || id.starts_with("·jsr·");
        assert_eq!(pinned, !foreign, "{id}: {after:#}");
    }
    fx.assert_in_run_vex(&out, fx.t(), false);
    fx.leg.ran();
}

/// `default-registry-alias` naming another alias: its `~<alias>~` DepIDs
/// are the default registry and are pinned.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_default_registry_alias() {
    let Some(leg) = hosted_leg("default_registry_alias") else {
        return;
    };
    if !leg.at_least(REGISTRIES_NPM_ROUTES_FROM) {
        return leg.skip("no-default-registry-alias");
    }
    let shape = Shape::left_pad().vlt_json_fn(|_, r| {
        json!({ "config": {
            "registries": { "acme": r },
            "default-registry-alias": "acme"
        } })
    });
    let fx = Fixture::build(leg, shape).await;
    let lock = read_lock(&fx.proj);
    let id = node_id(&lock, LP.0, LP.1);
    assert!(id.starts_with("~acme~"), "{id}");
    let doc = fx.scan(&[]);
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    fx.assert_fresh_locked_install("fresh-alias");
    fx.leg.ran();
}

/// The registry comes from `VLT_REGISTRIES` / `VLT_REGISTRY` in the
/// environment instead of vlt.json.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_registry_from_env() {
    let Some(leg) = hosted_leg("registry_from_env") else {
        return;
    };
    let v = leg.version();
    let mut shape = Shape::left_pad();
    shape.vlt_json.no_registry = true;
    shape.vlt_env = if scalar_registry_ignored(v) {
        vec![("VLT_REGISTRY".into(), "https://registry.npmjs.org/".into())]
    } else if v >= REGISTRIES_NPM_ROUTES_FROM {
        vec![("VLT_REGISTRIES".into(), "npm={R}".into())]
    } else {
        vec![("VLT_REGISTRY".into(), "{R}".into())]
    };
    let fx = Fixture::build(leg, shape).await;
    let doc = fx.scan(&[]);
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    fx.assert_fresh_locked_install("fresh-env");
    fx.leg.ran();
}

/// The registry comes from the user config `$XDG_CONFIG_HOME/vlt/vlt.json`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_registry_from_user_config() {
    let Some(leg) = hosted_leg("registry_from_user_config") else {
        return;
    };
    let mut shape = Shape::left_pad();
    shape.vlt_json.no_registry = true;
    shape.user_config = vec!["default", "fresh-user"];
    let fx = Fixture::build(leg, shape).await;
    let doc = fx.scan(&[]);
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc:#}");
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    fx.assert_fresh_locked_install("fresh-user");
    fx.leg.ran();
}

/// The artifact comes back `Content-Encoding: gzip` (patch.socket.dev
/// before the `no-transform` fix): refused, nothing written.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_content_encoding_refused() {
    let Some(leg) = hosted_leg("content_encoding_refused") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    fx.svc.serve_artifact_gzip_encoded(fx.t()).await;
    let out = socket_api(&fx.proj, &fx.svc, &["scan", "--mode", "hosted"], &[]);
    let doc = out.json();
    let detail = warning_detail(&doc, UNVERIFIABLE);
    assert!(
        detail.contains("content-encoding gzip") && detail.contains("nothing was written"),
        "{detail}"
    );
    assert_eq!(lock_bytes(&fx.proj), fx.lock_before, "no lock write");
    assert!(fx.ledger().is_none(), "no ledger");
    fx.leg.ran();
}

/// 0.0.0-16 … 24 without `"modifiers": {}` ignore the lock: the warning
/// fires and the install is silently unpatched (pinned).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_old_lockfile_ignored() {
    let Some(leg) = hosted_leg("old_lockfile_ignored") else {
        return;
    };
    if !lock_ignored_without_modifiers(leg.version()) {
        return leg.skip("lock-not-ignored");
    }
    let mut shape = Shape::left_pad();
    shape.vlt_json.no_modifiers = true;
    let fx = Fixture::build(leg, shape).await;
    let doc = fx.scan(&[]);
    assert!(
        has_warning(&doc, "redirect_vlt_old_lockfile_ignored"),
        "{doc:#}"
    );
    assert_pinned(&fx.proj, &fx.svc, fx.t());
    let co = fx.checkout("ignored");
    fx.vlt_ok_profile(&co, &fx.leg.locked_install_args(), "ignored");
    assert_eq!(state(&co, fx.t()), State::Pristine, "the lock was ignored");
    fx.leg.ran();
}

/// A warm cache keyed by URL serves stale bytes when the same URL starts
/// serving different ones (the documented hazard; hosted URLs are
/// immutable per artifact). rc.27 … 1.0.2 re-fetch and fail the integrity
/// check instead.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_warm_cache_hazard() {
    let Some(leg) = hosted_leg("warm_cache_hazard") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    fx.scan(&[]);
    let a = fx.checkout("warm-a");
    fx.vlt_ok_profile(&a, &fx.leg.locked_install_args(), "warm");
    assert_eq!(state(&a, fx.t()), State::Patched);
    let t = fx.t().clone();
    let mut files = t.patched_files();
    files.insert(
        t.file.clone(),
        [TAMPER_MARKER, t.before.as_slice()].concat(),
    );
    fx.svc.serve_artifact(&t, build_tgz(&files), 1).await;
    let hits = fx.svc.artifact_hits(&t).await;
    let b = fx.checkout("warm-b");
    if warm_cache_reverifies(fx.leg.version()) {
        let out = fx.vlt_profile(&b, &["install"], "warm");
        assert!(
            !out.status.success() && out_text(&out).to_lowercase().contains("integrity"),
            "rc.27 … 1.0.2 re-fetch and verify: {}",
            out_text(&out)
        );
        assert!(fx.svc.artifact_hits(&t).await > hits, "a refetch");
    } else {
        fx.vlt_ok_profile(&b, &["install"], "warm");
        assert_eq!(state(&b, &t), State::Patched, "the warm cache wins");
        assert_eq!(fx.svc.artifact_hits(&t).await, hits, "no refetch");
    }
    fx.leg.ran();
}

/// `get <uuid> --mode hosted` twice and `rollback` twice: zero churn.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_idempotence() {
    let Some(leg) = hosted_leg("idempotence") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    get_hosted(&fx.proj, &fx.svc, UUID, &[]);
    let lock = lock_bytes(&fx.proj);
    let ledger = fx.ledger();
    get_hosted(&fx.proj, &fx.svc, UUID, &[]);
    assert_eq!(lock_bytes(&fx.proj), lock);
    assert_eq!(fx.ledger(), ledger);
    let out = rollback(&fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(lock_bytes(&fx.proj), fx.lock_before);
    assert!(fx.ledger().is_none());
    let files = package_files(&fx.proj);
    let out = rollback(&fx.proj, &[]);
    assert_eq!(
        (out.code, out.json()["error"].as_str()),
        (1, Some("Manifest not found")),
        "a second rollback finds no state: {out}"
    );
    assert_eq!(package_files(&fx.proj), files, "and writes nothing");
    fx.leg.ran();
}

/// The manifest-less VEX tail on the hosted project (`vex_e2e_common/vlt`).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_manifestless_vex() {
    let Some(leg) = hosted_leg("manifestless_vex") else {
        return;
    };
    let fx = Fixture::build(leg, Shape::left_pad()).await;
    fx.scan(&[]);
    let t = fx.t().clone();
    let cve = [t.cve.as_str()];
    let vulns = vec![(t.ghsa.as_str(), &cve[..])];
    let case = vlt_vex::VltVexCase {
        tag: "hosted",
        mode: vlt_vex::VltMode::Hosted,
        purl: &t.purl(),
        uuid: &t.uuid,
        files: t.vex_files(),
        vulns: &vulns,
        registry_lock: fx.lock_before.clone(),
        registry_manifests: vec![],
        patch_server_url: Some(fx.svc.uri()),
    };
    let leg = &fx.leg;
    let run = fx.run.clone();
    vlt_vex::run_vlt_vex_matrix(&fx.proj, &leg.root, &case, |co| {
        let out = leg.vlt_with(co, &leg.locked_install_args(), &{
            let mut r = run.clone();
            r.profile = Some("vex".into());
            r
        });
        assert_ok(&out, "vex checkout locked install");
        assert_eq!(state(co, &t), State::Patched);
    });
    fx.leg.ran();
}

/// The TS twin's golden output for `basic` (the server's PR-flow lock and
/// ledger) is reverted by SP `rollback`, and `vlt ci` then installs the
/// registry bytes.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_ts_written_lock() {
    let Some(leg) = hosted_leg("ts_written_lock") else {
        return;
    };
    if !leg.at_least(REGISTRIES_NPM_REQUIRED_FROM) {
        return leg.skip("golden-grammar");
    }
    let golden = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/redirect/npm/vlt/basic");
    let reg = Registry::start(&[LP, MS]).await;
    let proj = leg.dir("proj");
    let npm = "https://registry.npmjs.org/";
    let sub = |s: String| s.replace(npm, &reg.url());
    let input = sub(std::fs::read_to_string(golden.join("input/vlt-lock.json")).unwrap());
    let expected = sub(std::fs::read_to_string(golden.join("expected/vlt-lock.json")).unwrap());
    let edits: Value = serde_json::from_str(&sub(std::fs::read_to_string(
        golden.join("expected-edits.json"),
    )
    .unwrap()))
    .unwrap();
    write(
        &proj.join("package.json"),
        package_json("vlt-e2e-app", &[LP, MS]),
    );
    write_vlt_json(&proj, leg.version(), &reg.url(), &VltJson::default());
    write(&proj.join(VLT_LOCK), &expected);
    let ledger = json!({
        "version": 1,
        "mode": "hosted",
        "edits": edits,
        "records": {
            "pkg:npm/left-pad@1.3.0": {
                "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {},
                "vulnerabilities": {},
                "description": "server-written",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    write(
        &proj.join(".socket/vendor/redirect-state.json"),
        serde_json::to_vec_pretty(&ledger).unwrap(),
    );
    let out = rollback(&proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    assert_eq!(
        String::from_utf8_lossy(&lock_bytes(&proj)),
        input,
        "SP reverts the TS-written lock to its input"
    );
    leg.vlt_ok(&proj, &["ci"]);
    let lp = reg.pkg(LP.0, LP.1);
    assert_eq!(
        installed(&proj, LP.0, "index.js"),
        tgz_files(&lp.tgz).get("index.js").cloned(),
        "registry bytes"
    );
    assert_eq!(String::from_utf8_lossy(&lock_bytes(&proj)), input);
    leg.ran();
}

// ── optional dependencies (SP-4b) ─────────────────────────────────────────

fn optional_shape(optional_only: bool) -> Shape {
    let darwin = cfg!(target_os = "macos");
    let mut optional = vec![MS];
    let mut pins = vec![MS];
    let mut targets = vec![(MS.0, MS.1, UUID_MS, "index.js")];
    if darwin && !optional_only {
        optional.push(FSEVENTS);
        pins.push(FSEVENTS);
        targets.push((FSEVENTS.0, FSEVENTS.1, UUID_FSEVENTS, "fsevents.js"));
    }
    let mut deps = vec![];
    if !optional_only {
        deps.push(LP);
        pins.push(LP);
        targets.insert(0, (LP.0, LP.1, UUID, "index.js"));
    }
    Shape {
        deps,
        optional,
        pins,
        targets,
        ..Shape::left_pad()
    }
}

/// The heal never removes a stale optional copy (vlt would not reinstall
/// it): left-pad's entry and the hidden lock go, ms (and fsevents on
/// macOS) stay pristine and linked, the advisory says so, and in-run VEX
/// withholds them. A plain `vlt install` patches left-pad only; `vlt ci`
/// patches the optional ones with the lock byte-stable. Rollback keeps the
/// patched optional copies the same way. An optional-only project installs
/// nothing from the lock before 1.0.5 (pinned vlt limitation).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_optional_dependency_heal() {
    let Some(leg) = hosted_leg("optional_dependency_heal") else {
        return;
    };
    if !leg.at_least(HAS_CI_FROM) {
        return leg.skip("no-vlt-ci");
    }
    let fx = Fixture::build(leg, optional_shape(false).warm()).await;
    let n_opt = fx.svc.targets.len() - 1;
    let lp = fx.svc.target(LP.0).clone();
    let ms = fx.svc.target(MS.0).clone();
    let lp_ids = fx.store_ids(&lp);
    let snap = fx.snapshot(&fx.proj, &lp_ids);
    let out = fx.scan_vex(&[]);
    let doc = out.json();
    snap.assert_same(
        &fx.snapshot(&fx.proj, &lp_ids),
        "the heal keeps the optional copies",
    );
    let held = format!(
        "node_modules also still holds {n_opt} unpatched copies of optional dependencies; \
         {OPTIONAL_KEPT}"
    );
    fx.assert_advisory(
        &doc,
        &format!("{} {held}{VLT_UPDATE_NOTE}", invalidated_head(lp_ids.len())),
    );
    for id in &lp_ids {
        assert!(!store_entry(&fx.proj, id).exists());
    }
    assert!(!hidden_lock_exists(&fx.proj));
    for t in fx.svc.targets.iter().filter(|t| t.name != LP.0) {
        for id in fx.store_ids(t) {
            assert!(store_entry(&fx.proj, &id).exists(), "{id} kept");
        }
        assert_eq!(state(&fx.proj, t), State::Pristine, "{} linked", t.name);
        assert!(!fx.vex_attested(t), "{} not attested", t.name);
    }
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, &lp), State::Patched);
    assert_eq!(
        state(&fx.proj, &ms),
        State::Pristine,
        "vlt install keeps it"
    );
    let before_ci = lock_bytes(&fx.proj);
    fx.vlt_ok(&fx.proj, &["ci"]);
    for t in &fx.svc.targets {
        assert_eq!(state(&fx.proj, t), State::Patched, "{} after ci", t.name);
    }
    assert_eq!(lock_bytes(&fx.proj), before_ci, "ci keeps the lock");
    let snap = fx.snapshot(&fx.proj, &lp_ids);
    let out = rollback(&fx.proj, &[]);
    assert_eq!(out.code, 0, "{out}");
    snap.assert_same(
        &fx.snapshot(&fx.proj, &lp_ids),
        "the rollback heal keeps the patched optional copies",
    );
    let want = format!(
        "restored registry pins for {} packages; removed {} patched installed copies, so \
         node_modules is incomplete until you run `vlt install` (or `vlt ci`). node_modules \
         also still holds {n_opt} patched copies of optional dependencies; {OPTIONAL_KEPT}",
        fx.svc.targets.len(),
        lp_ids.len()
    );
    fx.assert_advisory(&out.json(), &want);
    for id in &lp_ids {
        assert!(!store_entry(&fx.proj, id).exists());
    }
    assert_eq!(
        state(&fx.proj, &ms),
        State::Patched,
        "patched optional kept"
    );
    fx.vlt_ok(&fx.proj, &["ci"]);
    for t in &fx.svc.targets {
        assert_eq!(state(&fx.proj, t), State::Pristine, "{} after ci", t.name);
    }
    let Fixture { leg, .. } = fx;
    optional_only_leg(&leg).await;
    leg.ran();
}

async fn optional_only_leg(leg: &Leg) {
    let reg = Registry::start(&[MS]).await;
    let proj = leg.dir("optional-only");
    write(
        &proj.join("package.json"),
        package_json_fields("vlt-e2e-opt", &[("optionalDependencies", &[MS])]),
    );
    write_vlt_json(&proj, leg.version(), &reg.url(), &VltJson::default());
    leg.vlt_ok(&proj, &["install"]);
    let behavior = optional_only(leg.version());
    let ms = PatchTarget::from_pkg(reg.pkg(MS.0, MS.1), UUID_MS, "index.js");
    if behavior == OptionalOnly::NoLock {
        assert!(!proj.join(VLT_LOCK).exists(), "no lock is written");
        assert_eq!(state(&proj, &ms), State::Absent, "nothing is installed");
        return;
    }
    assert_eq!(state(&proj, &ms), State::Pristine);
    let svc = PatchService::start(vec![ms.clone()]).await;
    remove_tree(&proj);
    scan_hosted(&proj, &svc, &[]);
    assert_pinned(&proj, &svc, &ms);
    let want = match behavior {
        OptionalOnly::Installs => State::Patched,
        _ => State::Absent,
    };
    let lock = lock_bytes(&proj);
    leg.vlt_ok_with(&proj, &["ci"], &VltRun::profile("optional-only"));
    assert_eq!(state(&proj, &ms), want, "optional-only vlt ci");
    assert_eq!(
        lock_bytes(&proj),
        lock,
        "optional-only vlt ci keeps the lock"
    );
    remove_tree(&proj);
    leg.vlt_ok_with(
        &proj,
        &["install"],
        &VltRun::profile("optional-only-install"),
    );
    assert_eq!(state(&proj, &ms), want, "optional-only locked vlt install");
    assert_eq!(
        lock_bytes(&proj),
        lock,
        "optional-only locked vlt install keeps the lock"
    );
}

/// Hosted pin of an optional dependency, warm install, then `scan --mode
/// vendored` takes over: the hosted store copy and the hidden lock stay,
/// the takeover advisory names the kept optional copy, a plain `vlt
/// install` keeps the importer linked to the hosted copy, and `vlt ci`
/// links the vendored dir (mixed projects on every era; optional-only from
/// 1.0.5, before which `vlt ci` leaves it absent). The mixed project's
/// warm tree is the hosted `vlt ci`; the optional-only one's is the
/// registry install whose optional copy the hosted heal kept (`vlt ci`
/// would install nothing there before 1.0.5). 0.0.0-19 … 0.0.0-29 already
/// relink the vendored dir on the plain install.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_then_vendored_optional_takeover() {
    let Some(leg) = hosted_leg("then_vendored_optional_takeover") else {
        return;
    };
    if !leg.at_least(HAS_CI_FROM) {
        return leg.skip("no-vlt-ci");
    }
    for optional_only in [false, true] {
        let kind = if optional_only { "optonly" } else { "mixed" };
        let reg = Registry::start(&[LP, MS]).await;
        let proj = leg.dir(kind);
        let mut fields: Vec<(&str, &[(&str, &str)])> = vec![("optionalDependencies", &[MS])];
        if !optional_only {
            fields.push(("dependencies", &[LP]));
        }
        write(
            &proj.join("package.json"),
            package_json_fields("vlt-e2e-app", &fields),
        );
        write_vlt_json(&proj, leg.version(), &reg.url(), &VltJson::default());
        leg.vlt_ok(&proj, &["install"]);
        if optional_only && optional_only_kind(&leg) == OptionalOnly::NoLock {
            assert!(!proj.join(VLT_LOCK).exists(), "no lock is written");
            continue;
        }
        let ms = PatchTarget::from_pkg(reg.pkg(MS.0, MS.1), UUID_MS, "index.js");
        let svc = PatchService::start(vec![ms.clone()]).await;
        scan_hosted(&proj, &svc, &[]);
        assert_pinned(&proj, &svc, &ms);
        let hosted_id = node_id(&read_lock(&proj), MS.0, MS.1);
        if optional_only {
            assert_eq!(
                state(&proj, &ms),
                State::Pristine,
                "{kind}: the heal keeps the optional copy"
            );
        } else {
            leg.vlt_ok(&proj, &["ci"]);
            assert_eq!(state(&proj, &ms), State::Patched, "{kind}: hosted ci");
        }
        assert!(
            hidden_lock_exists(&proj),
            "{kind}: the warm tree has a hidden lock"
        );
        let out = socket_api(&proj, &svc, &["scan", "--mode", "vendored"], &[]);
        assert_eq!(out.code, 0, "{kind}: {out}");
        let doc = out.json();
        let detail = event_reason(&doc, ADVISORY);
        assert_eq!(
            detail,
            format!(
                "vendored 1 hosted-pinned packages, but node_modules still holds 1 installed \
                 copies of the vendored optional dependencies; {OPTIONAL_KEPT}"
            ),
            "{kind}"
        );
        assert!(
            store_entry(&proj, &hosted_id).exists(),
            "{kind}: hosted copy kept"
        );
        assert!(hidden_lock_exists(&proj), "{kind}: hidden lock kept");
        let link = |proj: &Path| {
            std::fs::read_link(proj.join("node_modules/ms"))
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default()
        };
        leg.vlt_ok(&proj, &["install"]);
        let installed_link = link(&proj);
        if takeover_install_relinks(leg.version()) {
            assert!(
                installed_link.contains(".socket/vendor/npm/"),
                "{kind}: 0.0.0-19 … 0.0.0-29 relink on a plain install: {installed_link}"
            );
        } else {
            assert!(
                installed_link.contains(&format!(".vlt/{hosted_id}/")),
                "{kind}: install keeps the hosted link: {installed_link}"
            );
        }
        leg.vlt_ok(&proj, &["ci"]);
        if !optional_only || optional_only_kind(&leg) == OptionalOnly::Installs {
            let ci_link = link(&proj);
            assert!(
                ci_link.contains(".socket/vendor/npm/"),
                "{kind}: ci links the vendored dir: {ci_link}"
            );
            assert_eq!(state(&proj, &ms), State::Patched, "{kind}");
        } else {
            assert_eq!(
                state(&proj, &ms),
                State::Absent,
                "{kind}: vlt ci installs no optional dependency of an optional-only project \
                 before 1.0.5"
            );
        }
    }
    leg.ran();
}

fn optional_only_kind(leg: &Leg) -> OptionalOnly {
    optional_only(leg.version())
}

/// A platform-skipped optional dependency (never installed here) and a
/// lingering `.VLT.DELETE.*` staging dir: the heal and the crawler ignore
/// both.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "real vlt: SOCKET_PATCH_VLT_E2E_JS"]
async fn vlt_pinned_matrix_hosted_platform_optional_skipped() {
    let Some(leg) = hosted_leg("platform_optional_skipped") else {
        return;
    };
    if platform_optional_install_bug(leg.version()) {
        return leg.skip("vlt-platform-optional-bug");
    }
    let other = if cfg!(target_os = "macos") {
        ("@parcel/watcher-linux-x64-glibc", "2.4.1")
    } else {
        FSEVENTS
    };
    let mut shape = Shape::with_bystander().warm();
    shape.optional = vec![other];
    shape.pins.push(other);
    let fx = Fixture::build(leg, shape).await;
    let lock = read_lock(&fx.proj);
    let other_id = node_id(&lock, other.0, other.1);
    assert!(
        !store_entry(&fx.proj, &other_id).exists(),
        "platform-skipped"
    );
    let lp_id = node_id(&lock, LP.0, LP.1);
    let staging = fx
        .proj
        .join("node_modules/.vlt")
        .join(format!(".VLT.DELETE.1a2b.{lp_id}"));
    write(
        &staging.join("node_modules/left-pad/index.js"),
        &fx.t().before,
    );
    write(
        &staging.join("node_modules/left-pad/package.json"),
        r#"{"name":"left-pad","version":"1.3.0"}"#,
    );
    let healed = vec![lp_id.clone()];
    let snap = fx.snapshot(&fx.proj, &healed);
    let doc = fx.scan(&[]);
    fx.assert_advisory(&doc, &advisory_invalidated(1));
    assert!(staging.exists(), "the heal never touches staging dirs");
    snap.assert_same(&fx.snapshot(&fx.proj, &healed), "the heal");
    fx.vlt_ok(&fx.proj, &["install"]);
    assert_eq!(state(&fx.proj, fx.t()), State::Patched);
    let out = socket_api(&fx.proj, &fx.svc, &["scan"], &[]);
    let listed = out.json().to_string();
    assert!(
        !listed.contains(".VLT.DELETE"),
        "the crawler never reports staging dirs: {listed}"
    );
    fx.leg.ran();
}
