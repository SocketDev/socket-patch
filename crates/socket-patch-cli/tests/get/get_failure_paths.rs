//! `get`'s `--json` contracts for the paths the rest of the suite never
//! drove (#1089): exit code, `status`, `error.code`, `events[]`
//! `errorCode`s, `warnings[]` codes and the bytes on disk. A message is read
//! only for what it must name (a path, which narrowing arm fired). The human
//! output of the same paths is pinned in `get_render.rs`.
//!
//!   1. `run()` flag validation and the uuid save path's failure ladder;
//!   2. the package-name path's `noMatch` terminal;
//!   3. the agent download engine's failure branches;
//!   4. release-variant narrowing fallbacks (fabricated PyPI venv);
//!   5. the search-path `--mode vendored` flow;
//!   6. vendor-step error arms (uuid and search paths);
//!   7. the hosted and vendored lock-held refusals;
//!   8. agent dry runs, forced identifier types and the proxy 403;
//!   9. nested apply failures and mismatch warnings in the envelope.

use serial_test::serial;
use socket_patch_cli::commands::get::run;
use socket_patch_cli::commands::scan::ScanMode;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common;
use crate::common::envelope::{
    envelope_error_code, envelope_error_message, events, find_event, parse_json_envelope,
};
use crate::get_fixture::*;

/// Two identifier type flags together must be rejected up front: exit 1,
/// nothing fetched, nothing written (the `type_flags > 1` guard).
#[tokio::test]
#[serial]
async fn get_conflicting_type_flags_rejected_before_any_network() {
    // Live trap mock so "rejected before any fetch" is provable.
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = Some(server.uri());
    args.id = true;
    args.cve = true;

    let code = run(args).await;
    assert_eq!(code, 2, "conflicting --id/--cve is a usage error (exit 2)");
    assert_no_manifest(tmp.path());
    assert!(
        received_paths(&server).await.is_empty(),
        "the conflict must be rejected before any API call"
    );
}

/// The uuid save path's no-applicable-files guardrail: a view whose files
/// all lack an `afterHash` must exit 1 with the guardrail error and write
/// NO manifest — never `applied: 1` over an empty record.
#[tokio::test]
async fn get_uuid_view_without_after_hashes_fails_no_applicable_files() {
    let server = MockServer::start().await;
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": { "beforeHash": "e".repeat(64), "afterHash": null }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, _stderr) =
        run_get_bin(tmp.path(), &server.uri(), &[UUID, "--save-only", "--json"]);
    assert_eq!(code, 1, "guardrail must exit 1; stdout={stdout}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "error", "stdout={stdout}");
    assert_eq!(
        envelope_error_code(&v),
        Some("patch_no_applicable_files"),
        "the guardrail's code; stdout={stdout}"
    );
    assert_no_manifest(tmp.path());
}

/// The uuid save path's blob-failure ladder: a traversal `afterHash` must
/// fail the blob write with the `blob_write_failed` envelope, exit 1, and
/// leave no manifest and no escaped file. The human stderr line is pinned
/// in `get_render.rs`.
#[tokio::test]
async fn get_uuid_traversal_after_hash_fails_blob_write() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, traversal_files()).await;
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, _stderr) =
        run_get_bin(tmp.path(), &server.uri(), &[UUID, "--save-only", "--json"]);
    assert_eq!(code, 1, "blob failure must exit 1; stdout={stdout}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "error", "stdout={stdout}");
    assert_eq!(
        envelope_error_code(&v),
        Some("blob_write_failed"),
        "stdout={stdout}"
    );
    let failed = find_event(&v, "failed", Some("blob_write_failed"));
    assert_eq!(failed["purl"], PURL, "stdout={stdout}");
    assert_no_manifest(tmp.path());
    assert!(
        !tmp.path().join("covgap-escape").exists()
            && !tmp.path().join(".socket/covgap-escape").exists(),
        "the traversal hash must never produce a file outside blobs/"
    );
}

/// A regular FILE squatting on the `.socket` path must fail the run
/// fail-closed in BOTH uuid modes without destroying the file: the agent
/// save's apply-lock acquire refuses (`.socket` cannot be created), and the
/// vendored run's vendor step refuses the same way (its download phase
/// writes nothing).
#[tokio::test]
#[serial]
async fn get_uuid_socket_path_occupied_by_file_fails_closed() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let uri = server.uri();

    // Agent mode: the lock acquire inside the save refuses.
    {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".socket"), b"not a dir").unwrap();
        let mut args = default_args(UUID, tmp.path());
        args.common.api_url = Some(uri.clone());
        let code = run(args).await;
        assert_eq!(code, 1, "agent save must fail when .socket is a file");
        assert_eq!(
            std::fs::read(tmp.path().join(".socket")).unwrap(),
            b"not a dir",
            "the squatting file must be left untouched"
        );
    }

    // Vendored mode: the vendor step's `.socket` create / lock refuses.
    {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".socket"), b"not a dir").unwrap();
        let mut args = default_args(UUID, tmp.path());
        args.common.api_url = Some(uri.clone());
        args.save_only = false;
        args.mode = Some(ScanMode::Vendored);
        args.common.vendor_source = "service".to_string();
        let code = run(args).await;
        assert_eq!(code, 1, "vendored run must fail when .socket is a file");
        assert_eq!(
            std::fs::read(tmp.path().join(".socket")).unwrap(),
            b"not a dir",
            "the squatting file must be left untouched"
        );
    }
}

/// Manifest-write failure on the uuid save path: a read-only `.socket` dir
/// (blobs dir kept writable, lock file pre-staged so the acquire succeeds)
/// must fail the run with exit 1 and leave the pre-existing manifest
/// byte-identical.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn get_uuid_readonly_socket_dir_fails_manifest_write_preserving_manifest() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    // A DIFFERENT uuid is recorded, so the save classifies as `updated`
    // and must attempt the manifest write.
    seed_manifest_with(tmp.path(), PURL, UUID_B);
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    prestage_lock_file(&socket);
    let before = std::fs::read_to_string(socket.join("manifest.json")).unwrap();

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !readonly_dir_enforced(&socket) {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = Some(server.uri());
    let code = run(args).await;

    // Restore before asserting so the tempdir can always be cleaned up.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(code, 1, "a failed manifest write must exit 1");
    let after = std::fs::read_to_string(socket.join("manifest.json")).unwrap();
    assert_eq!(
        before, after,
        "the original manifest must survive the failed write"
    );
    let m: serde_json::Value = serde_json::from_str(&after).unwrap();
    assert_eq!(m["patches"][PURL]["uuid"], UUID_B, "old uuid must remain");
}

/// Human-mode uuid path: an update prints `Updated: 1 (replacing …)`, and
/// a same-uuid re-get lands on the `already has this patch recorded` note —
/// both exiting 0 with the manifest converged on the fetched uuid.
#[tokio::test]
#[serial]
async fn get_uuid_human_update_then_rerun_skips_preserving_manifest() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let uri = server.uri();

    let tmp = tempfile::tempdir().unwrap();
    seed_manifest_with(tmp.path(), PURL, UUID_B);

    // First run: replaces UUID_B with UUID (the human `[update]` print).
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = Some(uri.clone());
    args.common.json = false;
    assert_eq!(run(args).await, 0, "the update run must succeed");
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);

    // Second run: same uuid → the human "already recorded" note; still exit 0
    // and the manifest still records the same uuid.
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = Some(uri);
    args.common.json = false;
    assert_eq!(run(args).await, 0, "a same-uuid re-get is a benign skip");
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);
}

/// Human-mode uuid path WITHOUT --save-only over an empty project: the
/// nested apply runs, finds nothing to patch, and fails — the run must
/// print the failure note and exit 1 (`partial_failure`), with the record
/// still saved (download succeeded; only the apply degraded).
#[tokio::test]
#[serial]
async fn get_uuid_human_nested_apply_failure_is_partial_failure() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = Some(server.uri());
    args.common.json = false;
    args.save_only = false;

    let code = run(args).await;
    assert_eq!(
        code, 1,
        "a failed nested apply must degrade the run to exit 1"
    );
    // The record itself was saved before apply ran.
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);
}

/// `--package --global` with an EMPTY `--global-prefix`: the
/// `noPackages` terminal exits 0 before any network and writes nothing.
/// The human message is pinned in `get_render.rs`.
#[tokio::test]
async fn global_package_search_empty_prefix_is_no_packages() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let prefix = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[
            "some-package",
            "--package",
            "--global",
            "--global-prefix",
            prefix.path().to_str().unwrap(),
            "--save-only",
            "--json",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "noPackages", "stdout={stdout}");
    assert!(events(&v).is_empty(), "stdout={stdout}");
    assert_no_manifest(tmp.path());
    assert!(
        received_paths(&server).await.is_empty(),
        "no API call may happen for an empty global prefix"
    );
}

/// Installed packages that match NOTHING (exactly or nearly): the
/// `noMatch` terminal exits 0 with an empty envelope and zero API calls.
/// The human message is pinned in `get_render.rs`.
#[tokio::test]
async fn package_search_without_a_match_is_no_match() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    install_npm_fixture(tmp.path(), "leftpad", "1.0.0");
    let (code, stdout, _stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &["zzqxjvwq", "--package", "--save-only", "--json"],
    );
    assert_eq!(code, 0, "no_match is a clean exit; stdout={stdout}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "noMatch", "stdout={stdout}");
    assert!(events(&v).is_empty(), "stdout={stdout}");
    assert!(
        received_paths(&server).await.is_empty(),
        "no_match must be decided before any API call"
    );
}

/// The agent download loop's no-applicable-files guardrail: a fetched view
/// with NO recordable files is a per-patch failure — exit 1,
/// `partial_failure` — and, since nothing was recorded, no manifest is
/// written and the `.socket/` the lock created is pruned again.
#[tokio::test]
#[serial]
async fn engine_no_applicable_files_is_failed_and_unrecorded() {
    let server = MockServer::start().await;
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": { "beforeHash": "e".repeat(64), "afterHash": null }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) =
        download_and_apply_patches(&selected, &engine_params(tmp.path()), &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "partialFailure", "json={json}");
    assert_eq!(json["summary"]["failed"], 1, "json={json}");
    assert_eq!(json["summary"]["downloaded"], 0, "json={json}");
    assert_eq!(json["events"][0]["action"], "failed", "json={json}");
    assert_eq!(
        json["events"][0]["errorCode"], "patch_no_applicable_files",
        "json={json}"
    );
    assert_no_manifest(tmp.path());
    assert!(
        !tmp.path().join(".socket").exists(),
        "a run that records nothing leaves no .socket/ behind"
    );
}

/// The agent download loop's blob-failure branch: an invalid (traversal)
/// afterHash fails the blob write — `blob_write_failed`, purl
/// unrecorded (no manifest), and nothing written outside `.socket/blobs`.
#[tokio::test]
#[serial]
async fn engine_invalid_blob_hash_is_failed_and_unrecorded() {
    let server = MockServer::start().await;
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": {
                "beforeHash": "0".repeat(64),
                "afterHash": "../covgap-escaped",
                "blobContent": "cGF0Y2hlZAo=",
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) =
        download_and_apply_patches(&selected, &engine_params(tmp.path()), &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["summary"]["failed"], 1, "json={json}");
    assert_eq!(
        json["events"][0]["errorCode"], "blob_write_failed",
        "json={json}"
    );
    assert_no_manifest(tmp.path());
    assert!(
        !tmp.path().join("covgap-escaped").exists()
            && !tmp.path().join(".socket/covgap-escaped").exists(),
        "the traversal hash must never escape the blobs dir"
    );
}

/// The agent download loop's fetch-miss branch: a 404 view is `Ok(None)` —
/// recorded as a `download_failed` event, never a panic or a silent skip.
#[tokio::test]
#[serial]
async fn engine_view_404_is_download_failed() {
    let server = MockServer::start().await; // no view mounted -> 404
    let tmp = tempfile::tempdir().unwrap();
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) =
        download_and_apply_patches(&selected, &engine_params(tmp.path()), &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["summary"]["failed"], 1, "json={json}");
    assert_eq!(
        json["events"][0]["errorCode"], "download_failed",
        "json={json}"
    );
    // A fetch `Err` records `download_failed` too, with the error's own
    // text: this fixed reason is the only mark of the `Ok(None)` arm.
    assert_eq!(
        json["events"][0]["error"], "could not fetch details",
        "json={json}"
    );
    assert_no_manifest(tmp.path());
}

/// `.socket` occupied by a regular file: the engine's apply-lock acquire
/// (the first thing it does — the manifest RMW runs under the lock) must
/// fail before ANY fetch with an `error`-status envelope carrying the
/// stable `lock_io` code.
#[tokio::test]
#[serial]
async fn engine_socket_path_occupied_fails_before_any_fetch() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(".socket"), b"not a dir").unwrap();

    let selected = vec![search_result(UUID, PURL)];
    let (code, json) =
        download_and_apply_patches(&selected, &engine_params(tmp.path()), &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "error", "json={json}");
    assert_eq!(json["error"]["code"], "lock_io", "json={json}");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains(".socket"),
        "the error must name the directory; json={json}"
    );
    assert_eq!(
        requests_containing(&server, "/patches/view/").await,
        0,
        "the engine must fail before any fetch"
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".socket")).unwrap(),
        b"not a dir",
        "the squatting file must be left untouched"
    );
}

/// Read-only `.socket`: the engine cannot create its lock file, so it fails
/// closed with the `lock_io` error envelope before any fetch — nothing is
/// downloaded into a directory it could not record in.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn engine_readonly_socket_fails_closed_before_any_fetch() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !readonly_dir_enforced(&socket) {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let selected = vec![search_result(UUID, PURL)];
    let (code, json) =
        download_and_apply_patches(&selected, &engine_params(tmp.path()), &server.uri()).await;

    // A refused acquire prunes the EMPTY `.socket/` it could not lock (no
    // residue), so there is normally nothing left to restore.
    if socket.exists() {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "error", "json={json}");
    assert_eq!(json["error"]["code"], "lock_io", "json={json}");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains(".socket"),
        "the error must name the lock path; json={json}"
    );
    assert_eq!(requests_containing(&server, "/patches/view/").await, 0);
    assert!(
        !socket.exists(),
        "a refused lock leaves no empty .socket/ behind (D1: the failed acquire prunes it)"
    );
}

/// Read-only `.socket` with the lock file pre-staged (so the acquire
/// succeeds) and no blobs to write (`persist_blobs: false`): the fetched
/// record's manifest write is the first write — its failure must surface as
/// the `manifest_write_failed` envelope, with no manifest materializing.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn engine_readonly_socket_fails_manifest_write() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    prestage_lock_file(&socket);
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !readonly_dir_enforced(&socket) {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let selected = vec![search_result(UUID, PURL)];
    let mut params = engine_params(tmp.path());
    params.persist_blobs = false;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "error", "json={json}");
    assert_eq!(
        envelope_error_code(&json),
        Some("manifest_write_failed"),
        "json={json}"
    );
    assert!(
        !socket.join("manifest.json").exists(),
        "no manifest may materialize through a read-only dir"
    );
}

/// The blobs an agent-mode run wrote before its manifest write failed have
/// no record pointing at them: the engine unwinds exactly those (a
/// pre-existing blob — some other record's revert data — survives) and
/// prunes what it can. The read-only `.socket/` keeps `blobs/` itself from
/// being removed (rmdir needs write on the parent), but it must be EMPTY of
/// this run's blobs.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn engine_manifest_write_failure_unwinds_the_blobs_it_wrote() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    // A blob some other record owns: never this run's to remove.
    let foreign = blobs.join("f".repeat(64));
    std::fs::write(&foreign, b"someone else's revert data").unwrap();
    prestage_lock_file(&socket);
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !readonly_dir_enforced(&socket) {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let selected = vec![search_result(UUID, PURL)];
    let params = engine_params(tmp.path());
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(code, 1, "json={json}");
    assert_eq!(
        envelope_error_code(&json),
        Some("manifest_write_failed"),
        "json={json}"
    );
    let mut left: Vec<String> = std::fs::read_dir(&blobs)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec!["f".repeat(64)],
        "only the pre-existing blob survives; this run's blobs are unwound"
    );
    assert_eq!(
        std::fs::read(&foreign).unwrap(),
        b"someone else's revert data",
        "a blob this run did not create is never touched"
    );
}

/// Release-narrowing warnings must ride the agent envelope: two qualified
/// PyPI variants of an UNINSTALLED base are both kept (the keep-all
/// fallback) and the `warnings` key explains why.
#[tokio::test]
#[serial]
async fn engine_uninstalled_variant_base_keeps_all_with_warning() {
    let server = MockServer::start().await; // views 404 -> both fail
    let tmp = tempfile::tempdir().unwrap();
    let base = "pkg:pypi/covgap-sixish@1.0.0";
    let selected = vec![
        search_result(UUID, &format!("{base}?artifact_id=wheel")),
        search_result(UUID_B, &format!("{base}?artifact_id=sdist")),
    ];
    let mut params = engine_params(tmp.path());
    params.all_releases = false;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(
        json["events"].as_array().unwrap().len(),
        2,
        "both variants must be kept; json={json}"
    );
    assert_eq!(json["summary"]["failed"], 2, "json={json}");
    let warnings = json["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("keep-all fallback must surface warnings; json={json}"));
    assert!(
        warnings.iter().any(|w| w["code"] == "release_narrowing"
            && w["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("not installed locally")),
        "json={json}"
    );
}

/// Human-mode engine run: a same-uuid `[skip]` plus a failed fetch must
/// print the skip line and the `Failed:` summary while the envelope keeps
/// the exact counts (`skipped:1, failed:1, partial_failure`).
#[tokio::test]
#[serial]
async fn engine_human_mode_skip_and_failed_summary() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    // UUID_V2's view stays unmounted -> 404 -> failed.

    let tmp = tempfile::tempdir().unwrap();
    seed_manifest_with(tmp.path(), PURL, UUID);

    let selected = vec![search_result(UUID, PURL), search_result(UUID_V2, PURL_V2)];
    let mut params = engine_params(tmp.path());
    params.json = false;
    params.silent = false;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "partialFailure", "json={json}");
    assert_eq!(
        json["summary"]["skipped"], 1,
        "same-uuid entry is skipped; json={json}"
    );
    assert_eq!(json["summary"]["failed"], 1, "json={json}");
    assert_eq!(json["summary"]["downloaded"], 0, "json={json}");
    // The skipped purl's record is untouched.
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);
    assert!(manifest_json(tmp.path())["patches"][PURL_V2].is_null());
}

/// Installed base, but NO variant's beforeHash matches the on-disk file:
/// the narrowing must fall back to keeping ALL variants (with the
/// "No release variant" warning) rather than silently dropping the package.
/// Human mode (json:false, silent:false) so the `[note]` loop executes.
#[tokio::test]
#[serial]
async fn engine_variant_no_hash_match_keeps_all_variants_with_note() {
    let _env = EnvVarGuard::scrub(&["VIRTUAL_ENV"]);
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    fake_pypi_venv(tmp.path(), "covgapsix", "1.0.0", b"real on-disk content\n");

    let base = "pkg:pypi/covgapsix@1.0.0";
    let purl_wheel = format!("{base}?artifact_id=wheel");
    let purl_sdist = format!("{base}?artifact_id=sdist");

    // Both variants describe a DIFFERENT distribution's bytes.
    let other_before = b"some other distribution\n".as_slice();
    let other_after = b"some other distribution patched\n".as_slice();
    let mismatch_files = serde_json::json!({
        "covgapsix.py": {
            "beforeHash": git_hash(other_before),
            "afterHash": git_hash(other_after),
            "blobContent": b64(other_after),
        }
    });
    mount_view_files(&server, UUID, &purl_wheel, mismatch_files.clone()).await;
    mount_view_files(&server, UUID_B, &purl_sdist, mismatch_files).await;

    let selected = vec![
        search_result(UUID, &purl_wheel),
        search_result(UUID_B, &purl_sdist),
    ];
    let mut params = engine_params(tmp.path());
    params.all_releases = false;
    params.json = false;
    params.silent = false;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(
        code, 0,
        "keep-all downloads must still succeed; json={json}"
    );
    assert_eq!(json["summary"]["downloaded"], 2, "json={json}");
    let warnings = json["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("no-match fallback must warn; json={json}"));
    assert!(
        warnings.iter().any(|w| w["code"] == "release_narrowing"
            && w["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("No release variant")),
        "json={json}"
    );
    // Keep-all is observable in the manifest: BOTH qualified purls recorded.
    let manifest = manifest_json(tmp.path());
    assert!(manifest["patches"][&purl_wheel].is_object(), "{manifest}");
    assert!(manifest["patches"][&purl_sdist].is_object(), "{manifest}");
}

/// A variant whose view FETCH fails during narrowing gets an empty candidate
/// map — a vacuous match — so it is KEPT for the main loop to record the
/// failure (the documented keep-the-variant contract), while a hash-mismatch
/// sibling is dropped.
#[tokio::test]
#[serial]
async fn engine_variant_view_fetch_error_keeps_errored_variant() {
    let _env = EnvVarGuard::scrub(&["VIRTUAL_ENV"]);
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    fake_pypi_venv(tmp.path(), "covgapsix", "1.0.0", b"real on-disk content\n");

    let base = "pkg:pypi/covgapsix@1.0.0";
    let purl_erroring = format!("{base}?artifact_id=wheel");
    let purl_mismatch = format!("{base}?artifact_id=sdist");

    // The erroring variant's view 500s (both in narrowing and in the loop).
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    // The sibling fetches fine but mismatches the installed file.
    let other = b"different distribution\n".as_slice();
    mount_view_files(
        &server,
        UUID_B,
        &purl_mismatch,
        serde_json::json!({
            "covgapsix.py": {
                "beforeHash": git_hash(other),
                "afterHash": git_hash(b"different distribution patched\n"),
                "blobContent": b64(b"different distribution patched\n"),
            }
        }),
    )
    .await;

    let selected = vec![
        search_result(UUID, &purl_erroring),
        search_result(UUID_B, &purl_mismatch),
    ];
    let mut params = engine_params(tmp.path());
    params.all_releases = false;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(
        code, 1,
        "the kept variant's failure must surface; json={json}"
    );
    assert_eq!(
        json["events"].as_array().unwrap().len(),
        1,
        "only the fetch-error variant may be kept (vacuous match); json={json}"
    );
    assert_eq!(json["summary"]["failed"], 1, "json={json}");
    assert_eq!(
        json["events"][0]["purl"], purl_erroring,
        "the KEPT variant must be the one whose view errored; json={json}"
    );
    // The mismatching sibling was narrowed out entirely.
    assert!(
        !json["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["purl"] == purl_mismatch.as_str()),
        "json={json}"
    );
    // Neither variant was recorded: the only kept one failed, so no
    // manifest is written at all.
    assert_no_manifest(tmp.path());
}

/// `get <GHSA> --mode vendored` (search path): scan's vendored posture end
/// to end. The narrowed fan-out's installed version is recorded as a
/// detached ledger entry (vendored mode is manifest-free), the artifact
/// committed, the lock rewired — and NO manifest, NO blobs (content stays in
/// memory).
#[tokio::test]
#[serial]
async fn get_ghsa_vendored_search_commits_artifact_and_wires_lock() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let code = run(vendored_args(GHSA, tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "search-path vendored get should succeed");

    assert_vendored_detached(tmp.path(), PURL, UUID);
    let state = vendor_state(tmp.path());
    assert!(
        state["entries"][PURL_V2].is_null(),
        "the uninstalled version must be narrowed out; state={state}"
    );
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(
        artifact.is_file(),
        "the patched artifact must be committed at {}",
        artifact.display()
    );
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(".socket/vendor/npm/"),
        "the lock must be rewired to the vendored artifact; got:\n{lock}"
    );
}

/// The search-path vendored dry-run: classification preview only — exit 0,
/// no download, no `.socket`, lock untouched.
#[tokio::test]
#[serial]
async fn get_ghsa_vendored_search_dry_run_writes_nothing() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();

    let mut args = vendored_args(GHSA, tmp.path(), server.uri());
    args.common.dry_run = true;
    let code = run(args).await;
    assert_eq!(code, 0);

    assert!(!tmp.path().join(".socket").exists(), "no .socket writes");
    assert_eq!(
        lock_before,
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        "dry-run must not touch the lock"
    );
    assert_eq!(
        requests_containing(&server, "/patches/view/").await,
        0,
        "a dry-run must not download patch views"
    );
}

/// `get <uuid> --mode vendored --json` over a purl the ledger already
/// vendors at a DIFFERENT uuid (an earlier vendored get): the envelope's
/// record is `downloaded` with `oldUuid` naming the superseded entry —
/// derived from the ledger, vendored mode having no manifest — and the
/// ledger converges on the new uuid (subprocess: the envelope is the
/// contract).
#[tokio::test]
async fn get_uuid_vendored_superseding_action_carries_old_uuid() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID_B, PURL).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) =
        run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID_B));
    assert_eq!(code, 0, "first vendoring: stdout={stdout}\nstderr={stderr}");
    assert_vendored_detached(tmp.path(), PURL, UUID_B);

    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID));
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["summary"]["downloaded"], 1, "stdout={stdout}");
    assert_eq!(v["events"][0]["action"], "downloaded", "stdout={stdout}");
    assert_eq!(
        v["events"][0]["details"]["mode"], "vendored",
        "stdout={stdout}"
    );
    assert_eq!(
        v["events"][0]["details"]["oldUuid"], UUID_B,
        "stdout={stdout}"
    );
    // The vendor engine's events follow (no nested `vendor` envelope).
    assert!(v.get("vendor").is_none(), "stdout={stdout}");
    assert!(
        v["summary"]["applied"].as_u64().unwrap() >= 1,
        "stdout={stdout}"
    );
    assert_vendored_detached(tmp.path(), PURL, UUID);
}

/// `get <uuid> --mode vendored --json` whose vendor step dies at staging:
/// exit 1, ONE JSON document with `status: error`, `error.code`, the
/// demoted vendor envelope carried in `result.vendor` — and the legacy
/// manifest record + unselected ledger entry byte-identical.
#[tokio::test]
async fn get_uuid_vendored_vendor_step_error_leaves_legacy_state_alone() {
    let server = MockServer::start().await;
    mount_contentless_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    let (manifest_before, state_before) = seed_legacy_state(tmp.path());

    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID));
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_vendor_error_envelope(&v);
    assert_legacy_state_untouched(tmp.path(), &manifest_before, &state_before);
}

/// The SEARCH-path flavor of the same error arm: a GHSA-selected vendored
/// run must emit the identical single-document error envelope and leave the
/// legacy state alone. `--all-releases` keeps the uninstalled fixture
/// package out of the narrowing's way.
#[tokio::test]
async fn get_search_vendored_vendor_step_error_leaves_legacy_state_alone() {
    let server = MockServer::start().await;
    mount_ghsa_single(&server).await;
    mount_contentless_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    let (manifest_before, state_before) = seed_legacy_state(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[
            GHSA,
            "--mode",
            "vendored",
            "--vendor-source",
            "service",
            "--all-releases",
            "--json",
        ],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_vendor_error_envelope(&v);
    assert_legacy_state_untouched(tmp.path(), &manifest_before, &state_before);
}

/// Human-mode (json=false) engine run with `--silent`: the
/// no-applicable-files failure is an ERROR, exempt from --silent — the
/// envelope still degrades to partial_failure and the purl stays
/// unrecorded, exactly like the --json flavor.
#[tokio::test]
#[serial]
async fn engine_human_silent_no_applicable_files_still_fails() {
    let server = MockServer::start().await;
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": { "beforeHash": "e".repeat(64), "afterHash": null }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let selected = vec![search_result(UUID, PURL)];
    let mut params = engine_params(tmp.path());
    params.json = false;
    params.silent = true;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "partialFailure", "json={json}");
    assert_eq!(json["summary"]["failed"], 1, "json={json}");
    assert_no_manifest(tmp.path());
}

/// Human-mode (json=false) twin of the manifest-write-failure envelope: the
/// error goes to stderr instead of stdout, and the returned envelope still
/// carries `status: error` for the caller's early-return guard.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn engine_human_readonly_socket_manifest_write_failure_still_errors() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    prestage_lock_file(&socket);
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !readonly_dir_enforced(&socket) {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let selected = vec![search_result(UUID, PURL)];
    let mut params = engine_params(tmp.path());
    params.persist_blobs = false;
    params.json = false;
    params.silent = true;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "error", "json={json}");
    assert_eq!(
        envelope_error_code(&json),
        Some("manifest_write_failed"),
        "json={json}"
    );
    assert!(!socket.join("manifest.json").exists());
}

/// A corrupt committed `.socket/manifest.json` does not block a vendored
/// get: vendored mode never reads the manifest (the download phase records
/// in memory, the vendor step verifies from the ledger), so the run
/// succeeds — ONE JSON document — and the corrupt bytes are preserved,
/// never clobbered.
#[tokio::test]
async fn vendored_search_ignores_corrupt_manifest_and_vendors() {
    let server = MockServer::start().await;
    mount_ghsa_single(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    std::fs::create_dir_all(tmp.path().join(".socket")).unwrap();
    std::fs::write(tmp.path().join(".socket/manifest.json"), b"{ corrupt").unwrap();

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[
            GHSA,
            "--mode",
            "vendored",
            "--vendor-source",
            "service",
            "--all-releases",
            "--json",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["events"][0]["action"], "downloaded", "stdout={stdout}");
    assert_eq!(v["summary"]["applied"], 1, "stdout={stdout}");
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap(),
        b"{ corrupt",
        "the corrupt manifest must be preserved, never clobbered"
    );
    let state = vendor_state(tmp.path());
    assert_eq!(state["entries"][PURL]["uuid"], UUID, "state={state}");
    assert_eq!(state["entries"][PURL]["detached"], true, "state={state}");
}

/// Search-path vendored run where one patch's download FAILS but the vendor
/// step itself succeeds: the run demotes to `partial_failure` (exit 1)
/// while the nested vendor envelope stays `success` — the download failure
/// alone must degrade the run.
#[tokio::test]
async fn vendored_search_json_download_failure_with_clean_vendor_is_partial_failure() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;
    // UUID_V2's view stays unmounted -> 404 -> per-patch download failure.

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[
            GHSA,
            "--mode",
            "vendored",
            "--vendor-source",
            "service",
            "--all-releases",
            "--json",
        ],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "partialFailure", "stdout={stdout}");
    assert_eq!(v["summary"]["failed"], 1, "stdout={stdout}");
    // The only failure is the download's: the vendor step itself was clean.
    let failed: Vec<&serde_json::Value> = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "failed")
        .collect();
    assert_eq!(failed.len(), 1, "stdout={stdout}");
    assert_eq!(failed[0]["errorCode"], "download_failed", "stdout={stdout}");
    // The successfully-downloaded patch was still vendored.
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(artifact.is_file(), "stdout={stdout}");
}

/// Vendor step dying BEFORE any reconcile (the apply lock is held by
/// another process): the error envelope carries `lock_held` and — with no
/// pre-failure vendor envelope to hand over — NO `vendor` key at all, in
/// both the uuid and search flavors. The human `Error (lock_held):` line is
/// pinned in `get_render.rs`.
#[tokio::test]
async fn vendored_lock_held_vendor_step_errors_without_vendor_envelope() {
    use std::time::Duration;

    // (a) uuid path, --json: the record is fetched into memory (the
    // lock-free download phase), then the vendor step refuses on the held
    // lock.
    {
        let server = MockServer::start().await;
        mount_view_files(&server, UUID, PURL, good_files()).await;
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        std::fs::create_dir_all(&socket).unwrap();
        let _lock = socket_patch_core::patch::apply_lock::acquire(&socket, Duration::ZERO).unwrap();

        let (code, stdout, stderr) =
            run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID));
        assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
        let v = parse_json_envelope(&stdout);
        assert_eq!(v["status"], "error", "stdout={stdout}");
        assert_eq!(v["error"]["code"], "lock_held", "stdout={stdout}");
        assert!(
            v.get("vendor").is_none(),
            "no pre-failure vendor envelope exists to carry; stdout={stdout}"
        );
        assert_eq!(
            v["events"][0]["action"], "downloaded",
            "the download phase preceded the refusal; stdout={stdout}"
        );
        assert_no_manifest(tmp.path());
    }

    // (b) search path, --json: same refusal after the download phase.
    {
        let server = MockServer::start().await;
        mount_ghsa_single(&server).await;
        mount_view_files(&server, UUID, PURL, good_files()).await;
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        std::fs::create_dir_all(&socket).unwrap();
        let _lock = socket_patch_core::patch::apply_lock::acquire(&socket, Duration::ZERO).unwrap();

        let (code, stdout, stderr) = run_get_bin(
            tmp.path(),
            &server.uri(),
            &[
                GHSA,
                "--mode",
                "vendored",
                "--vendor-source",
                "service",
                "--all-releases",
                "--json",
            ],
        );
        assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
        let v = parse_json_envelope(&stdout);
        assert_eq!(v["status"], "error", "stdout={stdout}");
        assert_eq!(v["error"]["code"], "lock_held", "stdout={stdout}");
        assert!(v.get("vendor").is_none(), "stdout={stdout}");
    }
}

/// Hosted twin of `vendored_lock_held_vendor_step_errors_without_vendor_envelope`
/// (and of `scan/hosted_failure_paths.rs`'s `hosted_lock_held_refuses_before_any_write`):
/// `get <uuid> --mode hosted` folds its result into the HOSTED error
/// envelope, so a held apply lock surfaces as the top-level
/// `error: {code: "lock_held", message}` object (v5.0: no top-level
/// `errorCode`) — exit 1, nothing written. A `--dry-run` never contends:
/// it previews the redirect under the held lock and exits 0. The human
/// arm's lock error line and wait hint are pinned in `get_render.rs`.
#[tokio::test]
async fn hosted_lock_held_get_errors_with_top_level_error_code() {
    let (server, tmp, _lock) = hosted_project_with_held_lock().await;
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    // Wet --json: get's envelope fold keeps the hosted shape.
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "hosted", "--json"],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "error", "stdout={stdout}");
    assert_eq!(
        envelope_error_code(&v),
        Some("lock_held"),
        "the hosted envelope carries the `{{code, message}}` error object; stdout={stdout}"
    );
    assert!(
        v.get("errorCode").is_none(),
        "no top-level `errorCode` (v5.0); stdout={stdout}"
    );
    assert!(
        v.get("redirect").is_none(),
        "nothing was rewritten, so no redirect payload (v5.0); stdout={stdout}"
    );

    // --dry-run under the held lock: a preview never locks, so it previews
    // the redirect instead of contending.
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "hosted", "--json", "--dry-run"],
    );
    assert_eq!(
        code, 0,
        "a dry run never contends; stdout={stdout}\nstderr={stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["dryRun"], true, "stdout={stdout}");
    assert_eq!(
        v["summary"]["verified"], 1,
        "the pin is previewed; stdout={stdout}"
    );

    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "none of the runs may touch the lockfile"
    );
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .exists());
    assert_no_manifest(tmp.path());
}

/// A ledger entry the vendored get did not select — here one from an
/// ecosystem this build cannot even revert — is left alone: the detached
/// vendor step vendors exactly the selected records and never reconciles
/// the ledger against a manifest, so the run is a clean `success` and the
/// foreign entry survives untouched beside the new one.
#[tokio::test]
async fn vendored_uuid_json_leaves_unselected_ledger_entries_alone() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let foreign_purl = "pkg:covgapeco/gone@1.0.0";
    let vendor = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(
        vendor.join("state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { foreign_purl: {
                "ecosystem": "covgapeco",
                "basePurl": foreign_purl,
                "uuid": UNSELECTED_UUID,
                "artifact": {
                    "path": format!(".socket/vendor/covgapeco/{UNSELECTED_UUID}/gone-1.0.0.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID));
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "stdout={stdout}");
    let events = v["events"]
        .as_array()
        .unwrap_or_else(|| panic!("vendor events must be carried; stdout={stdout}"));
    assert!(
        !events.iter().any(|e| e["purl"] == foreign_purl),
        "an unselected ledger entry must not be touched or reported; stdout={stdout}"
    );
    let state = vendor_state(tmp.path());
    assert_eq!(
        state["entries"][foreign_purl]["uuid"], UNSELECTED_UUID,
        "the foreign entry must survive: {state}"
    );
    assert_vendored_detached(tmp.path(), PURL, UUID);
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(artifact.is_file(), "stdout={stdout}\nstderr={stderr}");
}

/// Agent-mode `--dry-run --json` (uuid path): one envelope with
/// `dryRun: true` and a `would_update` record carrying `oldUuid`; the
/// manifest bytes stay untouched.
#[tokio::test]
async fn agent_uuid_dry_run_json_classifies_against_the_manifest() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    seed_manifest_with(tmp.path(), PURL, UUID_B);
    let before = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();

    let (code, stdout, stderr) =
        run_get_bin(tmp.path(), &server.uri(), &[UUID, "--dry-run", "--json"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["dryRun"], true, "{v}");
    assert_eq!(v["summary"]["applied"], 0, "{v}");
    assert_eq!(v["events"][0]["action"], "verified", "{v}");
    assert_eq!(v["events"][0]["oldUuid"], UUID_B, "{v}");
    assert_eq!(
        before,
        std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap()
    );
}

/// A forced `--id` / `--cve` / `--ghsa` identifier is shape-checked before
/// any network call: an `identifier_invalid` usage error (exit 2) whose
/// message names the expected kind, with zero requests. The human line is
/// pinned in `get_render.rs`.
#[tokio::test]
async fn forced_identifier_type_is_validated_locally() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    for (flag, kind) in [
        ("--id", "patch UUID"),
        ("--cve", "CVE ID"),
        ("--ghsa", "GHSA ID"),
    ] {
        let (code, stdout, stderr) =
            run_get_bin(tmp.path(), &server.uri(), &["lodash", flag, "--json"]);
        assert_eq!(code, 2, "{flag}: stdout={stdout}\nstderr={stderr}");
        let v = parse_json_envelope(&stdout);
        assert_eq!(v["status"], "error", "{v}");
        assert_eq!(envelope_error_code(&v), Some("identifier_invalid"), "{v}");
        assert!(
            envelope_error_message(&v).is_some_and(|m| m.contains(kind)),
            "{flag}: the message must name the expected kind; {v}"
        );
    }
    assert!(
        received_paths(&server).await.is_empty(),
        "no request may be sent"
    );
}

/// The public proxy answers a paid patch with 403: that is the same clean
/// `paid_required` outcome (exit 0) as a tier=paid view, not a raw
/// "Forbidden" error. The human upgrade message is pinned in
/// `get_render.rs`.
#[tokio::test]
async fn proxy_403_on_uuid_is_paid_required() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let uri = server.uri();
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_via_proxy(tmp.path(), &uri, &[UUID, "--json"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "paidRequired", "{v}");
    assert_eq!(v["events"][0]["action"], "skipped", "{v}");
    assert_eq!(v["events"][0]["errorCode"], "paid_required", "{v}");
    assert_eq!(v["events"][0]["uuid"], UUID, "{v}");
    assert!(
        v["events"][0].get("purl").is_none(),
        "the proxy never named it: {v}"
    );
    assert_eq!(v["events"][0]["details"]["tier"], "paid", "{v}");

    assert!(!tmp.path().join(".socket").exists());
}

/// Agent `--dry-run` runs the same per-release variant narrowing as the
/// wet run: of two PyPI variants of one installed version, only the one
/// matching the installed distribution is previewed.
#[tokio::test]
async fn agent_dry_run_previews_only_the_installed_release_variant() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let installed = b"installed wheel bytes\n".as_slice();
    fake_pypi_venv(tmp.path(), "covgapsix", "1.0.0", installed);
    let venv = tmp.path().join(".venv");

    let base = "pkg:pypi/covgapsix@1.0.0";
    let purl_wheel = format!("{base}?artifact_id=wheel");
    let purl_sdist = format!("{base}?artifact_id=sdist");
    let files_for = |before: &[u8]| {
        serde_json::json!({
            "covgapsix.py": {
                "beforeHash": git_hash(before),
                "afterHash": git_hash(b"patched\n"),
                "blobContent": b64(b"patched\n"),
            }
        })
    };
    mount_view_files(&server, UUID, &purl_wheel, files_for(installed)).await;
    mount_view_files(&server, UUID_B, &purl_sdist, files_for(b"other dist\n")).await;
    let patch = |uuid: &str, purl: &str| {
        serde_json::json!({
            "uuid": uuid, "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "description": "x", "license": "MIT", "tier": "free",
            "vulnerabilities": {}
        })
    };
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-ghsa/{GHSA}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [patch(UUID, &purl_wheel), patch(UUID_B, &purl_sdist)],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let venv_str = venv.to_string_lossy().into_owned();
    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &[
            "get",
            GHSA,
            "--mode",
            "agent",
            "--dry-run",
            "--json",
            "--api-url",
            &server.uri(),
            "--api-token",
            "fake-token-for-tests",
            "--org",
            ORG,
            "--yes",
        ],
        &[
            ("SOCKET_TELEMETRY_DISABLED", "1"),
            ("VIRTUAL_ENV", venv_str.as_str()),
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["dryRun"], true, "{v}");
    let adds: Vec<&serde_json::Value> = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["action"] == "verified")
        .collect();
    assert_eq!(adds.len(), 1, "only the installed variant; {v}");
    assert_eq!(adds[0]["purl"], purl_wheel.as_str(), "{v}");
    assert!(!tmp.path().join(".socket").exists());
}

/// The agent engine with the nested apply ON, over a project whose
/// installed copy apply refuses to patch (a first-party link): the
/// apply step fails, and the envelope must say so per patch — the same
/// `{action: "failed", errorCode, error}` a standalone `apply --json`
/// reports — with `failed` counting it and nothing counted as applied.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn engine_nested_apply_failure_reaches_the_json_envelope() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_first_party_link_project(tmp.path());
    let mut params = engine_params(tmp.path());
    params.save_only = false;
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "partialFailure", "json={json}");
    assert_eq!(
        json["summary"]["downloaded"], 1,
        "the download itself worked: {json}"
    );
    assert_eq!(json["events"][0]["action"], "downloaded", "json={json}");
    assert_eq!(
        json["summary"]["failed"], 1,
        "the apply failure must be counted: {json}"
    );
    assert_eq!(json["summary"]["applied"], 0, "json={json}");
    let rec = &json["events"][1];
    assert_eq!(rec["purl"], PURL, "json={json}");
    assert_eq!(rec["uuid"], UUID, "json={json}");
    assert_eq!(rec["action"], "failed", "json={json}");
    assert_eq!(rec["errorCode"], "apply_failed", "json={json}");
    assert!(
        rec["error"].as_str().is_some_and(|e| !e.is_empty()),
        "the apply error text must reach the envelope: {json}"
    );
    // The record stays saved: only the apply degraded.
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);
    assert_eq!(
        std::fs::read(tmp.path().join("packages").join(NAME).join("index.js")).unwrap(),
        BEFORE_BYTES,
        "a failed apply leaves the first-party bytes alone"
    );
}

/// Nested apply over a project with nothing installed: apply fails because
/// the recorded patch has no installed package. The envelope names that
/// patch and the reason instead of reporting it as a clean `added`.
#[tokio::test]
#[serial]
async fn engine_nested_apply_not_installed_reaches_the_json_envelope() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    let mut params = engine_params(tmp.path());
    params.save_only = false;
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "partialFailure", "json={json}");
    assert_eq!(json["summary"]["failed"], 1, "json={json}");
    assert_eq!(json["summary"]["applied"], 0, "json={json}");
    let rec = &json["events"][1];
    assert_eq!(rec["action"], "failed", "json={json}");
    assert_eq!(rec["purl"], PURL, "json={json}");
    assert_eq!(rec["errorCode"], "package_not_installed", "json={json}");
    assert!(
        rec["error"].as_str().is_some_and(|e| !e.is_empty()),
        "json={json}"
    );
}

/// A successful nested apply still reports a clean envelope: the patch
/// keeps its `added` action and counts as applied.
#[tokio::test]
#[serial]
async fn engine_nested_apply_success_keeps_added_and_counts_applied() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let mut params = engine_params(tmp.path());
    params.save_only = false;
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["status"], "success", "json={json}");
    assert_eq!(json["summary"]["failed"], 0, "json={json}");
    assert_eq!(json["summary"]["applied"], 1, "json={json}");
    assert_eq!(json["events"][0]["action"], "downloaded", "json={json}");
    assert_eq!(json["events"][1]["action"], "applied", "json={json}");
    assert!(json["events"][0].get("errorCode").is_none(), "json={json}");
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules").join(NAME).join("index.js")).unwrap(),
        AFTER_BYTES,
    );
}

/// The selection was eligible, then a user patch appeared while its view was
/// being fetched. The locked apply must preserve the bytes and report a skip,
/// including when scan suppressed warnings already seen during selection or a
/// different selected package fails its apply.
#[tokio::test]
#[serial]
async fn engine_nested_apply_preserves_conflicts_introduced_during_fetch() {
    const OTHER: &str = "pkg:npm/other@1.0.0";
    for sibling_fails in [false, true] {
        for skips_reported in [false, true] {
            let server = MockServer::start().await;
            let tmp = tempfile::tempdir().unwrap();
            write_project(tmp.path());
            let patch = tmp.path().join(format!("patches/{NAME}+1.0.0.patch"));
            let patch_at_fetch = patch.clone();
            let response = view_json(
                UUID,
                PURL,
                serde_json::json!({
                    "package/index.js": {
                        "beforeHash": git_hash(BEFORE_BYTES),
                        "afterHash": git_hash(AFTER_BYTES),
                        "blobContent": b64(AFTER_BYTES)
                    }
                }),
            );
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
                .respond_with(move |_: &wiremock::Request| {
                    std::fs::create_dir_all(patch_at_fetch.parent().unwrap()).unwrap();
                    std::fs::write(&patch_at_fetch, "user diff").unwrap();
                    ResponseTemplate::new(200).set_body_json(&response)
                })
                .mount(&server)
                .await;
            let mut selected = vec![search_result(UUID, PURL)];
            if sibling_fails {
                let pkg = tmp.path().join("node_modules/other");
                std::fs::create_dir_all(&pkg).unwrap();
                std::fs::write(
                    pkg.join("package.json"),
                    r#"{"name":"other","version":"1.0.0"}"#,
                )
                .unwrap();
                std::fs::write(pkg.join("index.js"), "local edit").unwrap();
                mount_real_view(&server, UUID_B, OTHER).await;
                selected.push(search_result(UUID_B, OTHER));
            }
            let mut params = engine_params(tmp.path());
            params.save_only = false;
            params.user_patch_skips_reported = skips_reported;
            let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;
            assert_eq!(code, i32::from(sibling_fails), "{json}");
            let skip = find_event(&json, "skipped", Some("user_patch_conflict"));
            assert_eq!(skip["purl"], PURL);
            assert_eq!(skip["uuid"], UUID);
            assert!(skip["reason"]
                .as_str()
                .unwrap()
                .contains(patch.to_str().unwrap()));
            assert_eq!(json["summary"]["applied"], 0, "{json}");
            assert_eq!(json["summary"]["skipped"], 1, "{json}");
            assert_eq!(
                json["summary"]["failed"],
                usize::from(sibling_fails),
                "{json}"
            );
            assert_eq!(
                std::fs::read(tmp.path().join(format!("node_modules/{NAME}/index.js"))).unwrap(),
                BEFORE_BYTES
            );
            assert_eq!(std::fs::read_to_string(patch).unwrap(), "user diff");
            assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);
        }
    }
}

/// `get <uuid> --json` (the single-patch path) with the nested apply ON
/// over a first-party link: one JSON document whose patch record carries
/// the apply failure, and `failed: 1`.
#[cfg(unix)]
#[tokio::test]
async fn get_uuid_json_nested_apply_failure_names_the_patch() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_first_party_link_project(tmp.path());
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID, "--json"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let json = parse_json_envelope(&stdout);
    assert_eq!(json["status"], "partialFailure", "json={json}");
    assert_eq!(json["summary"]["failed"], 1, "json={json}");
    assert_eq!(json["summary"]["applied"], 0, "json={json}");
    let rec = &json["events"][1];
    assert_eq!(rec["action"], "failed", "json={json}");
    assert_eq!(rec["errorCode"], "apply_failed", "json={json}");
    assert!(
        rec["error"].as_str().is_some_and(|e| !e.is_empty()),
        "json={json}"
    );
}

/// The agent engine (`scan --mode agent --json`'s path) over an installed
/// file a local edit changed: the opted-in policy overwrites it, and the
/// envelope must say so — the warning `apply --json` reports as a
/// `content_mismatch_overwritten` event — while the patch still counts as
/// applied.
#[tokio::test]
#[serial]
async fn engine_nested_apply_mismatch_overwrite_reaches_the_json_envelope() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let installed = tmp.path().join("node_modules").join(NAME).join("index.js");
    std::fs::write(&installed, LOCAL_EDIT_BYTES).unwrap();
    let mut params = engine_params(tmp.path());
    params.save_only = false;
    params.allow_patch_conflicts = true;
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["status"], "success", "json={json}");
    assert_eq!(json["summary"]["applied"], 1, "json={json}");
    assert_eq!(json["events"][0]["action"], "downloaded", "json={json}");
    assert!(
        has_mismatch_warning(&json, PURL),
        "the overwrite must be reported: {json}"
    );
    assert_eq!(std::fs::read(&installed).unwrap(), AFTER_BYTES);
}

/// A clean apply carries no mismatch warning.
#[tokio::test]
#[serial]
async fn engine_nested_apply_clean_has_no_mismatch_warning() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let mut params = engine_params(tmp.path());
    params.save_only = false;
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;
    assert_eq!(code, 0, "json={json}");
    assert!(json.get("warnings").is_none(), "json={json}");
}

/// `get <uuid> --json` over a locally edited installed file: one JSON
/// document whose `warnings[]` names the overwrite, and nothing on stderr
/// (the envelope is the JSON caller's channel).
#[tokio::test]
async fn get_uuid_json_mismatch_overwrite_is_reported() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let installed = tmp.path().join("node_modules").join(NAME).join("index.js");
    std::fs::write(&installed, LOCAL_EDIT_BYTES).unwrap();
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--json", "--allow-patch-conflicts"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let json = parse_json_envelope(&stdout);
    assert_eq!(json["status"], "success", "json={json}");
    assert_eq!(json["summary"]["applied"], 1, "json={json}");
    assert!(
        has_mismatch_warning(&json, PURL),
        "the overwrite must be reported: {json}"
    );
    assert!(!stderr.contains("did not match"), "stderr={stderr}");
    assert_eq!(std::fs::read(&installed).unwrap(), AFTER_BYTES);
}

#[tokio::test]
async fn get_uuid_requires_specific_consent_in_every_mode_before_persisting() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;
    for extra in [
        vec![UUID, "--json", "--mode", "agent"],
        vec![UUID, "--json", "--mode", "hosted"],
        vec![UUID, "--json", "--mode", "vendored"],
        vec![UUID, "--json", "--save-only"],
        vec![UUID, "--json", "--mode", "agent", "--dry-run"],
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_project(tmp.path());
        std::fs::create_dir(tmp.path().join("patches")).unwrap();
        std::fs::write(
            tmp.path().join(format!("patches/{NAME}+1.0.0.patch")),
            "user diff",
        )
        .unwrap();
        let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &extra);
        let json = parse_json_envelope(&stdout);
        assert_eq!(code, 1, "{extra:?}: {stdout} {stderr}");
        assert_eq!(json["error"]["code"], "user_patch_conflict", "{json}");
        assert!(!tmp.path().join(".socket/manifest.json").exists());
        assert_eq!(
            std::fs::read(tmp.path().join(format!("node_modules/{NAME}/index.js"))).unwrap(),
            BEFORE_BYTES
        );
    }
}

#[tokio::test]
async fn get_uuid_forwards_explicit_consent_to_nested_apply() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    std::fs::create_dir(tmp.path().join("patches")).unwrap();
    let patch = tmp.path().join(format!("patches/{NAME}+1.0.0.patch"));
    std::fs::write(&patch, "user diff").unwrap();
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--json", "--mode", "agent", "--allow-patch-conflicts"],
    );
    assert_eq!(code, 0, "{stdout} {stderr}");
    assert_eq!(
        std::fs::read(tmp.path().join(format!("node_modules/{NAME}/index.js"))).unwrap(),
        AFTER_BYTES
    );
    assert_eq!(std::fs::read_to_string(patch).unwrap(), "user diff");
    let json = parse_json_envelope(&stdout);
    assert!(json["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|w| w["code"] == "user_patch_override"));
}
