//! `scan`'s `--json` contracts for the paths the rest of the suite never
//! drove (#1089): exit code, `status`, `error.code`, `events[]` actions and
//! `errorCode`s, `warnings[]` codes, the mock API's request log and the
//! bytes on disk. A message is read only for what it must name (a flag, a
//! purl, a file). The human output of the same paths is pinned in
//! `scan_render.rs`.
//!
//!   1. the early errors (`--offline`, usage errors);
//!   2. hosted `--prune` and the paid-tier counters;
//!   3. detail-fetch failures (total and partial) and empty detail answers;
//!   4. vendor-owned purls, report-only runs and the `--sync` GC;
//!   5. the agent-mode envelope: events, dry runs, nested apply failures,
//!      mismatch and retained-wiring warnings, the lock and the manifest;
//!   6. corrupt `bun.lockb` inventories;
//!   7. vlt vendored ledgers.

use std::path::Path;

use wiremock::MockServer;

use crate::common::envelope::{
    assert_envelope_invariants, envelope_error_code, envelope_error_message, event_purls,
    event_triples, events, find_event, parse_json_envelope, warning_codes,
};
use crate::scan_fixture::*;
use crate::{vlt_hosted_common as hosted, vlt_vendored};

/// `scan --json` against the mock API; returns the exit code and the parsed
/// envelope (after checking the shared envelope invariants).
fn run_json(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, serde_json::Value) {
    let mut args = vec!["--json"];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_scan_api(cwd, api_url, &args);
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "scan");
    assert!(
        !stdout.contains("Warning:"),
        "human warning lines must not leak into the JSON stream: {stdout}\nstderr={stderr}"
    );
    (code, v)
}

/// `--offline` and usage errors print the full envelope too.
#[test]
fn scan_json_early_errors_print_full_envelopes() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, _) = run_scan(tmp.path(), &["--offline", "--json"]);
    assert_eq!(code, 1);
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "scan");
    assert_eq!(
        envelope_error_code(&v),
        Some("offline_unsupported"),
        "{v:#}"
    );
    assert_eq!(v["summary"]["applied"], 0);

    let (code, stdout, _) = run_scan(tmp.path(), &["--sync", "--mode", "hosted", "--json"]);
    assert_eq!(code, 2);
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "scan");
    assert_eq!(envelope_error_code(&v), Some("invalid_args"), "{v:#}");
}

/// Global installs have no project lockfile: `--mode hosted --global` is a
/// self-enforced usage error, so `--json` prints the coded error on stdout
/// (v5.0; clap's own parse errors still print nothing there).
#[test]
fn scan_hosted_global_json_is_global_scope_unsupported() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, _) = run_scan(tmp.path(), &["--mode", "hosted", "--global", "--json"]);
    assert_eq!(code, 2, "{stdout}");
    let v = parse_json_envelope(&stdout);
    assert_envelope_invariants(&v, "scan");
    assert_eq!(v["status"], "error", "{v}");
    assert_eq!(
        envelope_error_code(&v),
        Some("global_scope_unsupported"),
        "{v}"
    );
    let message = envelope_error_message(&v).unwrap_or_default();
    assert!(
        message.contains("--global") && message.contains("--mode hosted"),
        "the error must name both flags: {v}"
    );
}

// ---------------------------------------------------------------------------
// Hosted --prune and the paid-tier counters
// ---------------------------------------------------------------------------

/// Zero-package hosted run: `redirect_prune_ignored` rides the envelope's
/// top-level `warnings[]`, and the empty crawl never queries the API.
#[tokio::test]
async fn scan_hosted_prune_zero_package_json_carries_the_warning() {
    let mock = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--mode", "hosted", "--prune"]);
    assert_eq!(code, 0, "{v:#}");
    assert_eq!(v["status"], "success");
    assert_eq!(
        v["scannedPackages"], 0,
        "classic keys stay schema-consistent"
    );
    assert_eq!(v["redirect"]["mode"], "hosted");
    assert_eq!(v["summary"]["applied"], 0, "nothing pinned: {v}");
    assert!(
        hosted::warning_detail(&v, "redirect_prune_ignored").contains("--prune"),
        "the warning must name the ignored flag: {v:#}"
    );
    assert!(
        batch_bodies(&recorded(&mock).await).is_empty(),
        "empty project must not query"
    );
}

/// The paid counter: the discovery payload carries the patch's `paid` tier
/// and `canAccessPaidPatches`.
#[tokio::test]
async fn scan_json_counts_paid_patches_separately() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "paid", &[], false).await;
    let tmp = minimist_project(b"x\n");

    let (code, v) = run_json(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "{v:#}");
    // v5.0: the tier counts derive from the discovery payload.
    let tiers: Vec<&str> = v["packages"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|p| p["patches"].as_array().unwrap())
        .map(|p| p["tier"].as_str().unwrap())
        .collect();
    assert_eq!(tiers, ["paid"], "{v}");
    assert_eq!(v["canAccessPaidPatches"], false);
}

// ---------------------------------------------------------------------------
// Detail-fetch failures
// ---------------------------------------------------------------------------

/// Every detail fetch failing fails an agent-mode scan: exit 1,
/// `patch_details_failed`, nothing downloaded.
#[tokio::test]
async fn scan_agent_json_total_detail_failure_is_patch_details_failed() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "paid", &[], true).await;
    mount_by_package_500(&mock, MINIMIST).await;
    let tmp = minimist_project(b"x\n");

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--mode", "agent"]);
    assert_eq!(code, 1, "{v:#}");
    assert_eq!(
        envelope_error_code(&v),
        Some("patch_details_failed"),
        "{v:#}"
    );
    assert_eq!(view_gets(&recorded(&mock).await), 0, "{v:#}");
    assert!(!tmp.path().join(".socket").exists());
}

/// A partial detail-fetch failure warns once per failed package and goes
/// on with the packages that did resolve.
#[tokio::test]
async fn scan_agent_json_partial_detail_failure_warns_per_package() {
    let mock = MockServer::start().await;
    let bad = "pkg:npm/lodash@4.17.20";
    mount_batch_free(
        &mock,
        &[
            (MINIMIST, UUID),
            (bad, "33333333-3333-4333-8333-333333333333"),
        ],
    )
    .await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    mount_by_package_500(&mock, bad).await;
    let tmp = minimist_project(b"x\n");
    write_npm_package(tmp.path(), "lodash", "4.17.20", b"x\n");

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--mode", "agent", "--dry-run"]);
    assert_eq!(code, 0, "a partial failure is not an error: {v:#}");
    assert_eq!(envelope_error_code(&v), None, "{v:#}");
    let failed: Vec<_> = v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["code"] == "patch_details_failed")
        .collect();
    assert_eq!(failed.len(), 1, "one warning per failed package: {v:#}");
    assert!(
        failed[0]["detail"]
            .as_str()
            .is_some_and(|d| d.contains(bad)),
        "the warning names the failed purl: {v:#}"
    );
    assert_eq!(
        event_purls(&v, "verified"),
        [MINIMIST],
        "the resolved package still goes through: {v:#}"
    );
}

/// #1062: when every detail query succeeds but returns no records, scan
/// has nothing to select. That is a successful run with no applicable
/// patches in every mode (a successful empty answer is not a failure), so
/// the human arm exits like the `--json` arm (0), and neither reports a
/// fetch failure.
#[tokio::test]
async fn scan_empty_detail_results_exit_alike_in_human_and_json() {
    // `--prune` alone is report-only (no mode); `--dry-run` keeps every
    // mode read-only.
    let modes: [&[&str]; 4] = [
        &["--mode", "agent"],
        &["--mode", "vendored"],
        &["--mode", "hosted"],
        &["--prune"],
    ];
    for mode in modes {
        for dry in [false, true] {
            let mock = MockServer::start().await;
            mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
            mount_by_package_empty(&mock, MINIMIST).await;
            let mut extra: Vec<&str> = mode.to_vec();
            if dry {
                extra.push("--dry-run");
            }

            let tmp = minimist_project(b"x\n");
            let (human, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &extra);
            assert!(
                !stderr.contains("Error:"),
                "{extra:?}: no query failed, so no fetch failure; stdout={stdout}\nstderr={stderr}"
            );

            let tmp = minimist_project(b"x\n");
            let (json, v) = run_json(tmp.path(), &mock.uri(), &extra);
            assert_ne!(v["status"], "error", "{extra:?}: {v}");
            assert_eq!(v["events"], serde_json::json!([]), "{extra:?}: {v}");
            assert!(
                !warning_codes(&v).contains(&"patch_details_failed".to_string()),
                "{extra:?}: {v:#}"
            );
            assert_eq!(
                human, json,
                "{mode:?} dry={dry}: human and --json exit alike\n\
                 human stdout={stdout}\nhuman stderr={stderr}\njson={v:#}"
            );
            assert_eq!(human, 0, "{mode:?} dry={dry}: nothing to do is a success");
        }
    }
}

/// #1062: report-only `scan --prune` fetches the detail records in both
/// outputs whenever a patch is downloadable, so every detail query failing
/// fails both alike (exit 1; the JSON arm used to skip the fetch and exit
/// 0).
#[tokio::test]
async fn scan_report_only_detail_failure_exits_alike_in_human_and_json() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package_500(&mock, MINIMIST).await;
    let extra = ["--prune", "--dry-run"];

    let tmp = minimist_project(b"x\n");
    let (human, _, stderr) = run_scan_api(tmp.path(), &mock.uri(), &extra);
    let tmp = minimist_project(b"x\n");
    let (json, v) = run_json(tmp.path(), &mock.uri(), &extra);
    assert_eq!(
        envelope_error_code(&v),
        Some("patch_details_failed"),
        "{v:#}"
    );
    assert_eq!(human, json, "human and --json exit alike: {stderr}\n{v:#}");
    assert_eq!(json, 1, "every detail query failing is a failure: {v:#}");
}

/// #1062: some detail queries fail and the rest succeed with no records:
/// the `--json` arm adds a `patch_details_failed` warning and both outputs
/// exit alike. The human warning line is pinned in `scan_render.rs`.
#[tokio::test]
async fn scan_partial_failure_with_empty_results_exits_alike() {
    let bad = "pkg:npm/lodash@4.17.20";
    let mock = MockServer::start().await;
    mount_batch_free(&mock, &[(MINIMIST, UUID), (bad, UUID)]).await;
    mount_by_package_empty(&mock, MINIMIST).await;
    mount_by_package_500(&mock, bad).await;
    let extra = ["--mode", "agent", "--dry-run"];

    let project = || {
        let tmp = minimist_project(b"x\n");
        write_npm_package(tmp.path(), "lodash", "4.17.20", b"x\n");
        tmp
    };
    let tmp = project();
    let (human, _, stderr) = run_scan_api(tmp.path(), &mock.uri(), &extra);
    let tmp = project();
    let (json, v) = run_json(tmp.path(), &mock.uri(), &extra);
    assert!(
        hosted::warning_detail(&v, "patch_details_failed").contains(bad),
        "{v:#}"
    );
    assert_eq!(human, json, "human and --json exit alike: {stderr}\n{v:#}");
}

// ---------------------------------------------------------------------------
// Vendor-owned purls, report-only runs and the GC
// ---------------------------------------------------------------------------

/// A purl the vendored ledger owns is skipped by an agent-mode scan: one
/// `skipped` event coded `vendored`, no download and no manifest.
#[tokio::test]
async fn scan_agent_json_skips_vendored_purls_without_downloading() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    let tmp = minimist_project(b"x\n");
    seed_vendored_entry(tmp.path(), MINIMIST);

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--mode", "agent", "--yes"]);
    assert_eq!(code, 0, "{v:#}");
    assert_eq!(
        event_triples(&v)
            .into_iter()
            .filter(|(purl, _, _)| purl == MINIMIST)
            .map(|(_, action, code)| (action, code))
            .collect::<Vec<_>>(),
        [("skipped".to_string(), "vendored".to_string())],
        "a vendor-owned purl is only skipped, with the `vendored` code: {v:#}"
    );
    assert_eq!(v["summary"]["applied"], 0, "{v:#}");
    assert_eq!(view_gets(&recorded(&mock).await), 0, "{v:#}");
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "a fully-skipped run must not create the manifest"
    );
}

/// `--prune` with no mode only reports: no view fetch, no `.socket/`, the
/// installed file untouched, and no apply event.
#[tokio::test]
async fn scan_prune_without_a_mode_json_is_report_only() {
    let mock = MockServer::start().await;
    mount_one_patch_api(&mock, MINIMIST, b"x\n").await;
    let tmp = minimist_project(b"x\n");

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--prune"]);
    assert_eq!(code, 0, "report-only is a success: {v:#}");
    assert_eq!(v["summary"]["applied"], 0, "{v:#}");
    assert!(event_purls(&v, "applied").is_empty(), "{v:#}");
    assert!(!tmp.path().join(".socket").exists(), "{v:#}");
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/minimist/index.js")).unwrap(),
        b"x\n"
    );
    assert_eq!(view_gets(&recorded(&mock).await), 0, "{v:#}");
}

/// Each spelling of apply-and-collect (`--sync`, `--mode agent --prune`)
/// applies the patch, records it, prunes the orphan manifest entry and
/// sweeps its blob, and reports the GC.
#[tokio::test]
async fn scan_sync_json_applies_and_collects() {
    for flags in [
        &["--sync", "--yes"][..],
        &["--mode", "agent", "--prune"][..],
    ] {
        let mock = MockServer::start().await;
        let tmp = orphans_project(&mock, &[("pkg:npm/gone@1.0.0", OLD_UUID, 'c')]).await;

        let (code, v) = run_json(tmp.path(), &mock.uri(), flags);
        assert_eq!(code, 0, "{flags:?}: {v:#}");
        assert_eq!(
            event_purls(&v, "applied"),
            [SILENT_TARGET],
            "{flags:?}: {v:#}"
        );
        assert!(v["gc"].is_object(), "{flags:?}: {v:#}");
        let manifest = read_manifest(tmp.path());
        assert!(
            manifest["patches"]["pkg:npm/gone@1.0.0"].is_null(),
            "{flags:?}: the orphan entry must be pruned: {manifest}"
        );
        assert_eq!(
            manifest["patches"][SILENT_TARGET]["uuid"], UUID,
            "{flags:?}: the applied patch must be recorded: {manifest}"
        );
        assert!(
            !tmp.path()
                .join(".socket/blobs")
                .join(orphan_blob_name('c'))
                .exists(),
            "{flags:?}: the orphan blob must be swept"
        );
    }
}

/// #1062: a `--dry-run --prune` previews the GC in agent, report-only and
/// vendored mode alike: a `verified` event (`details.manifest`) for the
/// stale entry and `gc`; nothing is written. The human preview line is
/// pinned in `scan_render.rs`.
#[tokio::test]
async fn scan_dry_run_prune_json_previews_gc() {
    let stale = "pkg:npm/left-pad@1.3.0";
    for mode in [
        &["--mode", "agent"][..],
        &[][..],
        &["--mode", "vendored"][..],
    ] {
        let mock = MockServer::start().await;
        mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
        mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
        let tmp = minimist_project(b"x\n");
        // A recorded patch for a package that is not installed: the GC
        // would prune its entry.
        seed_manifest(tmp.path(), &[(stale, OLD_UUID)]);
        let manifest = tmp.path().join(".socket/manifest.json");
        let before = std::fs::read(&manifest).unwrap();
        let mut extra: Vec<&str> = mode.to_vec();
        extra.extend(["--prune", "--dry-run", "--yes"]);

        let (code, v) = run_json(tmp.path(), &mock.uri(), &extra);
        assert_eq!(code, 0, "{extra:?}: {v:#}");
        let pruned = events(&v)
            .iter()
            .find(|e| e["purl"] == stale)
            .unwrap_or_else(|| panic!("{extra:?}: no prune preview: {v:#}"));
        assert_eq!(pruned["action"], "verified", "{v:#}");
        assert_eq!(pruned["details"]["manifest"], true, "{v:#}");
        assert!(v["gc"].is_object(), "{extra:?}: {v:#}");
        assert_eq!(
            std::fs::read(&manifest).unwrap(),
            before,
            "{extra:?}: a dry run writes nothing"
        );
    }
}

// ---------------------------------------------------------------------------
// v5.0 envelope: `scan --json` prints one shared Envelope
// ---------------------------------------------------------------------------

/// A wet agent-mode `scan --json`: one envelope (`command: "scan"`), the
/// download as a `downloaded` event carrying the patch metadata, the nested
/// apply as an `applied` event, `summary` equal to the event counts, the
/// discovery payload beside them, and none of the retired keys.
#[tokio::test]
async fn scan_agent_json_is_one_envelope_with_events() {
    let mock = MockServer::start().await;
    mount_one_patch_api(&mock, MINIMIST, b"before\n").await;
    let tmp = minimist_project(b"before\n");

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--mode", "agent"]);
    assert_eq!(code, 0, "{v:#}");
    assert_eq!(v["status"], "success", "{v:#}");
    assert_eq!(v["dryRun"], false);
    assert_eq!(
        event_triples(&v),
        vec![
            (
                MINIMIST.to_string(),
                "downloaded".to_string(),
                String::new()
            ),
            (MINIMIST.to_string(), "applied".to_string(), String::new()),
        ],
        "{v:#}"
    );
    let downloaded = find_event(&v, "downloaded", None);
    assert_eq!(downloaded["uuid"], UUID);
    assert_eq!(downloaded["details"]["tier"], "free", "{v:#}");
    assert!(
        downloaded["details"].get("mode").is_none(),
        "agent events carry no mode"
    );
    assert_eq!(v["scannedPackages"], 1);
    assert_eq!(v["packages"][0]["purl"], MINIMIST);
    for retired in [
        "apply",
        "totalPatches",
        "freePatches",
        "paidPatches",
        "packagesWithPatches",
        "patches",
        "found",
    ] {
        assert!(v.get(retired).is_none(), "retired key {retired}: {v:#}");
    }
}

/// An agent-mode dry run previews without writing: a `verified` event per
/// patch a wet run would record, top-level `dryRun`, no nested one.
#[tokio::test]
async fn scan_agent_json_dry_run_previews_verified_events() {
    let mock = MockServer::start().await;
    mount_one_patch_api(&mock, MINIMIST, b"before\n").await;
    let tmp = minimist_project(b"before\n");
    seed_manifest(tmp.path(), &[(MINIMIST, OLD_UUID)]);

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--mode", "agent", "--dry-run"]);
    assert_eq!(code, 0, "{v:#}");
    assert_eq!(v["dryRun"], true);
    let e = find_event(&v, "verified", None);
    assert_eq!(e["purl"], MINIMIST);
    assert_eq!(e["uuid"], UUID);
    assert_eq!(
        e["oldUuid"], OLD_UUID,
        "a would-be update names the uuid it replaces"
    );
    assert_eq!(v["summary"]["verified"], 1);
}

/// `scan --mode agent --json` whose nested apply fails (the installed copy
/// is a symlink to a first-party `packages/` directory, which apply refuses
/// to patch): the envelope must carry the per-patch failure (a `failed`
/// event with `errorCode` and `error`) and count it in `summary.failed`,
/// not report the patch as cleanly applied (#424).
#[cfg(unix)]
#[tokio::test]
async fn scan_agent_json_nested_apply_failure_reaches_the_apply_block() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/apply-fails@1.0.0";
    mount_one_patch_api(&mock, purl, b"before\n").await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "apply-fails", "1.0.0", b"before\n");
    let member = tmp.path().join("packages/apply-fails");
    std::fs::create_dir_all(member.parent().unwrap()).unwrap();
    std::fs::rename(tmp.path().join("node_modules/apply-fails"), &member).unwrap();
    std::os::unix::fs::symlink(
        "../packages/apply-fails",
        tmp.path().join("node_modules/apply-fails"),
    )
    .unwrap();

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--mode", "agent"]);
    assert_eq!(code, 1, "{v:#}");
    assert_eq!(v["status"], "partialFailure", "{v}");
    assert_eq!(
        v["summary"]["failed"], 1,
        "the apply failure must be counted: {v}"
    );
    assert_eq!(v["summary"]["applied"], 0, "{v}");
    let rec = find_event(&v, "failed", Some("apply_failed"));
    assert_eq!(rec["purl"], purl, "{v}");
    assert!(
        rec["error"].as_str().is_some_and(|e| !e.is_empty()),
        "the apply error text must reach the envelope: {v}"
    );
    assert_eq!(std::fs::read(member.join("index.js")).unwrap(), b"before\n");
}

/// `scan --mode agent --json` over an installed file a local edit changed
/// (neither beforeHash nor afterHash): the default policy overwrites it,
/// and `warnings[]` must report that overwrite with the same
/// `content_mismatch_overwritten` code `apply --json` uses instead of
/// dropping it (#1004).
#[tokio::test]
async fn scan_agent_json_mismatch_overwrite_reaches_the_apply_block() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/locally-edited@1.0.0";
    mount_one_patch_api(&mock, purl, b"before\n").await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(
        tmp.path(),
        "locally-edited",
        "1.0.0",
        b"before\n// local edit\n",
    );

    let (code, v) = run_json(
        tmp.path(),
        &mock.uri(),
        &["--mode", "agent", "--allow-patch-conflicts"],
    );
    assert_eq!(code, 0, "{v:#}");
    assert_eq!(v["summary"]["applied"], 1, "{v}");
    let detail = hosted::warning_detail(&v, "content_mismatch_overwritten");
    assert!(
        detail.contains(purl) && detail.contains("package/index.js"),
        "the overwrite must name the purl and the file: {v:#}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/locally-edited/index.js")).unwrap(),
        b"after\n"
    );
}

/// An in-place apply over LIVE hosted wiring (a lockfile still resolving
/// the purl to the hosted patch server) proceeds, and warns that the
/// conversion did not complete.
#[tokio::test]
async fn scan_agent_json_over_live_hosted_wiring_warns_retained() {
    let mock = MockServer::start().await;
    let before = b"before\n";
    mount_one_patch_api(&mock, SILENT_TARGET, before).await;
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", before);
    // v5: the lock pin is the whole hosted state (no ledger).
    write_live_hosted_lock(tmp.path());

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--mode", "agent", "--yes"]);
    assert_eq!(code, 0, "{v:#}");
    assert!(
        hosted::warning_detail(&v, "hosted_wiring_retained").contains(SILENT_TARGET),
        "the warning names the package: {v:#}"
    );
    assert_eq!(event_purls(&v, "applied"), [SILENT_TARGET], "{v:#}");
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/silent-target/index.js")).unwrap(),
        b"after\n",
        "the in-place apply proceeds despite the warning"
    );
}

/// Agent mode with the apply lock held: the engine's hard error is the
/// run's ONE JSON document (v5.0 fixes a run that printed the engine's
/// error and then scan's own result).
#[tokio::test]
async fn scan_agent_json_lock_held_prints_one_document() {
    let mock = MockServer::start().await;
    mount_one_patch_api(&mock, MINIMIST, b"before\n").await;
    let tmp = minimist_project(b"before\n");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let _lock =
        socket_patch_core::patch::apply_lock::acquire(&socket, std::time::Duration::ZERO).unwrap();

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--mode", "agent"]);
    assert_eq!(code, 1, "{v:#}");
    assert_eq!(v["status"], "error");
    assert_eq!(envelope_error_code(&v), Some("lock_held"), "{v:#}");
}

/// Agent mode over a manifest that exists but does not parse fails closed
/// before any query, in both outputs: `manifest_invalid` (the shared code),
/// exit 1; report-only mode warns with the same code and goes on.
#[tokio::test]
async fn scan_unparseable_manifest_fails_agent_mode_and_warns_otherwise() {
    let mock = MockServer::start().await;
    mount_one_patch_api(&mock, MINIMIST, b"before\n").await;
    let tmp = minimist_project(b"before\n");
    std::fs::create_dir_all(tmp.path().join(".socket")).unwrap();
    std::fs::write(tmp.path().join(".socket/manifest.json"), "{ not json").unwrap();

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--mode", "agent"]);
    assert_eq!(code, 1, "{v:#}");
    assert_eq!(envelope_error_code(&v), Some("manifest_invalid"), "{v:#}");
    assert_eq!(v["events"], serde_json::json!([]));
    let (code, _, stderr) = run_scan_agent(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 1, "the human arm fails alike: {stderr}");

    let (code, v) = run_json(tmp.path(), &mock.uri(), &["--prune", "--dry-run"]);
    assert_eq!(code, 0, "{v:#}");
    assert!(
        warning_codes(&v).contains(&"manifest_invalid".to_string()),
        "{v:#}"
    );
}

// ---------------------------------------------------------------------------
// Corrupt binary lockfiles report a format error in every scan mode
// ---------------------------------------------------------------------------

/// A corrupt `bun.lockb` stays visible as `bun_lockb_invalid` (naming the
/// file) on the zero-package path, including when hosted mode has nothing
/// to redirect.
#[test]
fn scan_invalid_bun_lockb_warns_instead_of_silent_success() {
    for mode in [None, Some("vendored"), Some("hosted")] {
        let tmp = tempfile::tempdir().unwrap();
        write_invalid_bun_lockb_project(tmp.path());
        let mut args = vec!["--json"];
        if let Some(mode) = mode {
            args.extend(["--mode", mode]);
        }
        let (code, stdout, stderr) = run_scan(tmp.path(), &args);
        assert_eq!(
            code, 0,
            "mode={mode:?}: refusals never flip the exit; stdout={stdout}; stderr={stderr}"
        );
        let v = parse_json_envelope(&stdout);
        assert_eq!(v["status"], "success", "mode={mode:?}: {v}");
        assert_eq!(v["scannedPackages"], 0, "mode={mode:?}: {v}");
        assert_eq!(v["lockfileOnlyPackages"], 0, "mode={mode:?}: {v}");
        assert!(
            hosted::warning_detail(&v, "bun_lockb_invalid").contains("bun.lockb"),
            "mode={mode:?}: the format error must name its file: {v:#}"
        );
        assert!(
            !stdout.contains("Warning:"),
            "mode={mode:?}: the human warning line must not leak into the JSON stream: {stdout}"
        );
    }
}

/// Installed dependencies do not suppress the binary format diagnosis in
/// any mode, including when hosted mode finds no patches to redirect.
#[tokio::test]
async fn scan_nonempty_keeps_the_bun_lockb_discovery_warning_in_every_mode() {
    let mock = MockServer::start().await;
    mount_empty_batch(&mock).await;

    for mode in [None, Some("vendored"), Some("hosted")] {
        let tmp = tempfile::tempdir().unwrap();
        write_invalid_bun_lockb_project(tmp.path());
        write_npm_package(tmp.path(), "minimist", "1.2.2", b"module.exports = 1;\n");
        let mut args = vec![];
        if let Some(mode) = mode {
            args.extend(["--mode", mode]);
        }
        let (code, v) = run_json(tmp.path(), &mock.uri(), &args);
        assert_eq!(code, 0, "mode={mode:?}: {v:#}");
        assert_eq!(v["scannedPackages"], 1, "mode={mode:?}: {v}");
        assert_eq!(v["status"], "success", "mode={mode:?}: {v}");
        assert!(
            hosted::warning_detail(&v, "bun_lockb_invalid").contains("bun.lockb"),
            "mode={mode:?}: {v:#}"
        );
    }
}

// ---------------------------------------------------------------------------
// vlt vendored ledgers: the GC probe and the degraded-ledger `~` boundary
// ---------------------------------------------------------------------------

/// `scan --mode vendored --prune`: the lock-driven GC keeps the vlt entry
/// `vlt-lock.json` still resolves to its dir (the in-use verdict is
/// structural: a `file` node under the uuid) and reclaims one it does not.
#[tokio::test]
async fn scan_prune_keeps_a_wired_vlt_uuid_and_sweeps_an_unwired_one() {
    let server = MockServer::start().await;
    hosted::mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vlt_vendored::vendored_project(root, false);
    let unwired = UUID_B;
    let other = "pkg:npm/right-pad@1.0.0";
    let other_rel = format!(".socket/vendor/npm/{unwired}/right-pad-1.0.0/node_modules/right-pad");
    std::fs::create_dir_all(root.join(&other_rel)).unwrap();
    std::fs::write(root.join(&other_rel).join("index.js"), "x\n").unwrap();
    let mut state = vlt_vendored::state(root);
    let mut entry = state["entries"][hosted::PURL].clone();
    entry["basePurl"] = serde_json::json!(other);
    entry["uuid"] = serde_json::json!(unwired);
    entry["artifact"]["path"] = serde_json::json!(other_rel);
    entry["artifact"]["fileInventory"] = serde_json::json!({ "index.js": "0" });
    entry["wiring"] = serde_json::json!([]);
    state["entries"][other] = entry;
    std::fs::write(
        root.join(".socket/vendor/state.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();

    let cwd = root.to_str().unwrap().to_string();
    let uri = server.uri();
    let (code, env, stderr) = hosted::run_json(
        root,
        &[
            "scan",
            "--mode",
            "vendored",
            "--prune",
            "--yes",
            "--cwd",
            &cwd,
            "--api-url",
            &uri,
            "--org",
            hosted::ORG,
            "--api-token",
            "fake",
        ],
        &[],
    );
    assert!(code == 0 || code == 1, "{env:#}\n{stderr}");
    let after = vlt_vendored::state(root);
    assert!(
        after["entries"][hosted::PURL].is_object(),
        "the wired entry stays: {after:#}\n{env:#}"
    );
    assert!(root.join(vlt_vendored::rel()).join("index.js").is_file());
    assert!(
        after["entries"].get(other).is_none(),
        "the unwired entry is reclaimed: {after:#}\n{env:#}"
    );
    assert!(
        !root.join(format!(".socket/vendor/npm/{unwired}")).exists(),
        "{env:#}"
    );
}

/// A pre-v5 redirect ledger holding only a vlt node edit keyed at a peer
/// variant of the vendored package's DepID is IGNORED by a vendored scan:
/// v5 has no `vendor_supersedes_redirect` reconciliation (once the lock
/// routes a package to `.socket/vendor/`, no hosted state is left), so no
/// warning fires at either side of the `~` boundary and the legacy file is
/// left byte-identical.
#[tokio::test]
async fn scan_vendored_ignores_a_degraded_pre_v5_vlt_ledger_edit() {
    use socket_patch_core::patch::redirect::{FileEdit, RedirectState};
    for key in ["left-pad@1.3.0~peer.2", "left-pad@1.3.00~peer.2"] {
        let server = MockServer::start().await;
        hosted::mock_all(&server).await;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        vlt_vendored::vendored_project(root, false);
        let mut ledger = RedirectState::new();
        ledger.edits = vec![FileEdit {
            path: "vlt-lock.json".to_string(),
            kind: socket_patch_core::patch::redirect::vlt::KIND.to_string(),
            action: "modified".to_string(),
            key: Some(key.to_string()),
            original: None,
            new: None,
        }];
        let bytes = serde_json::to_string_pretty(&ledger).unwrap();
        std::fs::write(hosted::ledger_path(root), &bytes).unwrap();
        let cwd = root.to_str().unwrap().to_string();
        let uri = server.uri();
        let (code, env, stderr) = hosted::run_json(
            root,
            &[
                "scan",
                "--mode",
                "vendored",
                "--yes",
                "--cwd",
                &cwd,
                "--api-url",
                &uri,
                "--org",
                hosted::ORG,
                "--api-token",
                "fake",
            ],
            &[],
        );
        assert_eq!(code, 0, "{key}: {env:#}\n{stderr}");
        assert!(
            !env.to_string().contains("vendor_supersedes_redirect"),
            "{key}: the v5 vendored scan never reconciles a hosted ledger: {env:#}"
        );
        assert_eq!(
            std::fs::read_to_string(hosted::ledger_path(root)).unwrap(),
            bytes,
            "{key}: the pre-v5 ledger is left byte-identical: {env:#}"
        );
    }
}

#[tokio::test]
async fn scan_skips_user_patches_in_every_mode_before_querying_or_writing() {
    let mock = MockServer::start().await;
    for mode in ["agent", "hosted", "vendored"] {
        let tmp = minimist_project(b"before\n");
        let declaration = r#"{"dependencies":{"minimist":"1.2.8"},"pnpm":{"patchedDependencies":{"minimist":"missing.patch"}}}"#;
        std::fs::write(tmp.path().join("package.json"), declaration).unwrap();
        let (code, json) = run_json(tmp.path(), &mock.uri(), &["--mode", mode, "--yes"]);
        assert_eq!(code, 0, "{mode}: {json}");
        assert!(
            json["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|w| w["code"] == "user_patch_conflict"),
            "{json}"
        );
        assert!(!tmp.path().join(".socket").exists());
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("package.json")).unwrap(),
            declaration
        );
        assert_eq!(
            std::fs::read(tmp.path().join("node_modules/minimist/index.js")).unwrap(),
            b"before\n"
        );
    }
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn scan_still_patches_unrelated_packages_and_forwards_explicit_consent() {
    for allowed in [false, true] {
        let mock = MockServer::start().await;
        let purl = "pkg:npm/example@1.0.0";
        mount_one_patch_api(&mock, purl, b"before\n").await;
        let tmp = tempfile::tempdir().unwrap();
        write_root_package_json(tmp.path());
        write_npm_package(tmp.path(), "example", "1.0.0", b"before\n");
        std::fs::create_dir(tmp.path().join("patches")).unwrap();
        if !allowed {
            write_npm_package(tmp.path(), "unrelated", "1.0.0", b"before\n");
        }
        let patched_name = if allowed { "example" } else { "unrelated" };
        std::fs::write(
            tmp.path()
                .join(format!("patches/{patched_name}+1.0.0.patch")),
            "user diff",
        )
        .unwrap();
        let mut args = vec!["--mode", "agent"];
        if allowed {
            args.push("--allow-patch-conflicts");
        }
        let (code, json) = run_json(tmp.path(), &mock.uri(), &args);
        assert_eq!(code, 0, "{json}");
        if !allowed {
            assert_eq!(
                std::fs::read(tmp.path().join("node_modules/unrelated/index.js")).unwrap(),
                b"before\n"
            );
            assert!(mock
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| !String::from_utf8_lossy(&request.body)
                    .contains("pkg:npm/unrelated@")));
        }
        assert_eq!(
            std::fs::read(tmp.path().join("node_modules/example/index.js")).unwrap(),
            b"after\n"
        );
    }
}
