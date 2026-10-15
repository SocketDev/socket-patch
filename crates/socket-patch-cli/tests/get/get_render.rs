//! `get`'s render suite (#1089): the human-mode (no `--json`) and
//! `--silent` output of `commands/get.rs`. Behavior is asserted through
//! `--json` codes in `get_failure_paths.rs`; the sentence checks here are
//! the render checks, one per message family.

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::get_fixture::*;
use crate::{vlt_hosted_common, vlt_vendored};

/// `--package --global` with an EMPTY `--global-prefix`: exits 0 before any
/// network with the dedicated "No global packages found." message.
#[tokio::test]
async fn human_global_package_search_empty_prefix_prints_no_global_packages() {
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
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("No global packages found."),
        "global no-packages must use its dedicated message; stdout={stdout}"
    );
    assert_no_manifest(tmp.path());
    assert!(
        received_paths(&server).await.is_empty(),
        "no API call may happen for an empty global prefix"
    );
}

/// The package path's search-API error arm: a matched package whose
/// by-package search 500s must exit 1 via `report_fetch_failure`, after
/// printing the "checking for available patches" progress line.
#[tokio::test]
async fn human_package_search_api_error_reports_fetch_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    install_npm_fixture(tmp.path(), NAME, "1.0.0");
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[NAME, "--package", "--save-only"],
    );
    assert_eq!(
        code, 1,
        "a 500 from the package search must exit 1; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains(&format!("Matched: pkg:npm/{NAME}@1.0.0\n")),
        "the matched-packages line must print first; stderr={stderr}"
    );
    assert!(
        stderr.contains("Error:"),
        "human mode reports the fetch failure on stderr; stderr={stderr}"
    );
    assert_no_manifest(tmp.path());
    assert_eq!(
        requests_containing(&server, "/patches/by-package/").await,
        1,
        "the search endpoint must actually have been consulted"
    );
}

/// Human vendored-uuid dry-run line (the same count flavor as the search
/// path — both identifier kinds share one preview).
#[tokio::test]
async fn human_vendored_uuid_dry_run_prints_line() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "vendored", "--dry-run"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("[dry-run] Would download and vendor 1 patch. No changes made."),
        "stdout={stdout}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

/// Human search-path vendored dry-run line (the pluralized count flavor).
#[tokio::test]
async fn human_vendored_search_dry_run_prints_count() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[GHSA, "--mode", "vendored", "--dry-run"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("[dry-run] Would download and vendor 1 patch. No changes made."),
        "the narrowed selection is exactly one patch; stdout={stdout}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

/// Human flavor of the vendored-uuid run over legacy state: stderr carries
/// the engine's `[fetch]` line and — the vendor step failing at staging —
/// the `Error (no_local_source)` line; nothing claims a manifest save and no
/// whole-manifest note prints (vendored mode has no manifest scope).
#[tokio::test]
async fn human_vendored_uuid_prints_fetch_and_vendor_error_without_manifest_note() {
    let server = MockServer::start().await;
    mount_contentless_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    let (manifest_before, state_before) = seed_legacy_state(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "vendored", "--vendor-source", "service"],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains(&format!("[fetch] {PURL}")),
        "the detached download phase reports the fetched record; stderr={stderr}"
    );
    assert!(
        !stdout.contains("Patch record saved to") && !stdout.contains("Added: 1"),
        "nothing is saved to a manifest in vendored mode; stdout={stdout}"
    );
    assert!(
        !stderr.contains("whole manifest"),
        "there is no whole-manifest scope to warn about; stderr={stderr}"
    );
    assert!(
        stderr.contains("no package-lock.json"),
        "the vendor-step error must explain the missing lockfile; stderr={stderr}"
    );
    assert_legacy_state_untouched(tmp.path(), &manifest_before, &state_before);
}

/// Human twin of the paid-via-proxy uuid envelope test: the upgrade message.
#[tokio::test]
async fn human_uuid_paid_via_proxy_prints_upgrade_message() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": "pkg:npm/paid-by-uuid@1.0.0",
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "Paid patch fetched by UUID",
            "license": "MIT",
            "tier": "paid",
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_via_proxy(tmp.path(), &mock.uri(), &[UUID, "--save-only"]);
    assert_eq!(
        code, 0,
        "paid_required is exit 0; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("requires a paid Socket plan"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("https://socket.dev/pricing"),
        "the upgrade pointer must print; stdout={stdout}"
    );
    assert_no_manifest(tmp.path());
}

/// Human twin of the uuid-404 test: the not-found message, exit 0.
#[tokio::test]
async fn human_uuid_not_found_prints_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID, "--save-only"]);
    assert_eq!(
        code, 0,
        "not-found is exit 0; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(&format!("No patch found with UUID: {UUID}")),
        "stdout={stdout}"
    );
    assert_no_manifest(tmp.path());
}

/// Human CVE search with no results: the per-type not-found message prints
/// on stdout, while the transient `Searching patches for …` status line
/// never reaches a pipe.
#[tokio::test]
async fn human_cve_search_empty_prints_search_label_and_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/v0/orgs/{ORG}/patches/by-cve/.+$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &["CVE-2099-40990", "--save-only"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    // The search progress is a transient stderr status line: it never
    // lands on stdout (or in a pipe at all).
    assert!(
        !stdout.contains("Searching patches for") && !stderr.contains("Searching patches for"),
        "stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("No patches found for CVE: CVE-2099-40990"),
        "stdout={stdout}"
    );
}

/// Human search listing: a paid patch a free user cannot access shows
/// `[PAID] (no access)`; the accessible free patch shows `[FREE]` and its
/// vulnerability summary on the `Fixes:` line.
#[tokio::test]
async fn human_search_results_show_paid_access_and_fixes_lines() {
    let server = MockServer::start().await;
    let cve = "CVE-2024-4242";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                {
                    "uuid": UUID, "purl": PURL,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "free patch", "license": "MIT", "tier": "free",
                    "vulnerabilities": {
                        "GHSA-free-fix": {
                            "cves": [cve], "summary": "s",
                            "severity": "high", "description": "d"
                        }
                    }
                },
                {
                    "uuid": UUID_B, "purl": "pkg:npm/other-pkg@1.0.0",
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "paid patch", "license": "MIT", "tier": "paid",
                    "vulnerabilities": {}
                }
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[cve, "--save-only"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.contains("[FREE]"), "stdout={stdout}");
    assert!(
        stdout.contains("[PAID] (no access)"),
        "an inaccessible paid patch must be labeled; stdout={stdout}"
    );
    assert!(
        stdout.contains(&format!("Fixes: {cve} (high)")),
        "the vulnerability summary must print; stdout={stdout}"
    );
    // The free patch was still fetched and saved.
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);
}

/// Human paid-only search: the subscription message, exit 0, no download.
#[tokio::test]
async fn human_paid_only_search_prints_subscription_message() {
    let server = MockServer::start().await;
    let cve = "CVE-2024-9999";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID_B, "purl": "pkg:npm/paid-only@1.0.0",
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "paid", "license": "MIT", "tier": "paid",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[cve, "--save-only"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("All available patches require a paid Socket plan."),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("https://socket.dev/pricing"),
        "stdout={stdout}"
    );
    assert_no_manifest(tmp.path());
    assert_eq!(
        requests_containing(&server, "/patches/view/").await,
        0,
        "a paywalled patch must never be downloaded"
    );
}

/// Human twin of the vendored-uuid-drift warning (the json flavor is pinned
/// by get_edge_cases_e2e): the `[note]` goes to stderr.
#[tokio::test]
async fn human_vendored_drift_note_prints_on_stderr() {
    let server = MockServer::start().await;
    let purl = "pkg:npm/vendored-drift@1.0.0";
    mount_view_files(&server, UUID_B, purl, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    // The vendor ledger wires the purl at UUID (an older patch).
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { purl: {
                "ecosystem": "npm",
                "basePurl": purl,
                "uuid": UUID,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{UUID}/vendored-drift-1.0.0.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) =
        run_get_bin(tmp.path(), &server.uri(), &[UUID_B, "--id", "--save-only"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains("[note]") && stderr.contains("is vendored at patch"),
        "the drift note must print on stderr in human mode; stderr={stderr}"
    );
    assert!(
        stderr.contains("socket-patch vendor"),
        "the note must point at the remedy; stderr={stderr}"
    );
}

/// Human twin of the all-uninstalled narrowing envelope: the plain
/// (non-PnP) message with the --all-releases advice.
#[tokio::test]
async fn human_ghsa_all_uninstalled_advises_all_releases() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;

    // Empty project: neither found version installed.
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[GHSA]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("none of them are installed here")
            && stdout.contains("Use --all-releases to fetch them anyway."),
        "stdout={stdout}"
    );
    // The terminal message already says it: no per-version [skip] flood
    // unless --verbose asks for the detail.
    assert!(
        !stderr.contains("[skip]"),
        "per-version [skip] lines are verbose-only; stderr={stderr}"
    );
    let (code, _stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[GHSA, "--verbose"]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        stderr.contains("(version not installed)"),
        "--verbose prints the per-version [skip] lines; stderr={stderr}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

/// `--silent` twin of the all-uninstalled narrowing terminal: a clean
/// no-op run must print NOTHING — no advise message on stdout, no per-
/// version `[skip]` lines on stderr — while still exiting 0.
#[tokio::test]
async fn silent_ghsa_all_uninstalled_prints_nothing() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[GHSA, "--silent"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.trim().is_empty(),
        "--silent must mute the advise message; stdout={stdout}"
    );
    assert!(
        !stderr.contains("[skip]") && !stderr.contains("installed here"),
        "--silent must mute the per-version skip lines; stderr={stderr}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

/// The human search listing's `Fixes:` line falls back to the advisory id
/// when the vulnerability has no CVE assigned yet.
#[tokio::test]
async fn human_search_fixes_line_falls_back_to_advisory_id_without_cves() {
    let server = MockServer::start().await;
    let cve = "CVE-2024-31337";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "no cve assigned yet", "license": "MIT", "tier": "free",
                "vulnerabilities": {
                    "GHSA-nocv-1111-2222": {
                        "cves": [], "summary": "s",
                        "severity": "high", "description": "d"
                    }
                }
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    // Empty project + --all-releases (no installed-version narrowing, so
    // the listing — the surface under test — prints) + --dry-run (stop
    // at the preview: no view fetch, no writes).
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[cve, "--all-releases", "--dry-run"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("Fixes: GHSA-nocv-1111-2222 (high)"),
        "a CVE-less advisory must be summarized by its id; stdout={stdout}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

/// Human search-path vendored SUCCESS: the vendored flow commits the
/// artifact and rewires the lock in human mode too — and no whole-manifest
/// blast-radius note prints (the detached vendor step touches exactly the
/// selected records; there is no manifest scope).
#[tokio::test]
async fn human_vendored_search_success_commits_artifact_without_blast_radius_note() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[GHSA, "--mode", "vendored", "--vendor-source", "service"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(
        artifact.is_file(),
        "the artifact must be committed; stdout={stdout}\nstderr={stderr}"
    );
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(".socket/vendor/npm/"),
        "lock must be rewired:\n{lock}"
    );
    assert!(
        !stderr.contains("whole manifest"),
        "no blast-radius note without a pre-existing manifest; stderr={stderr}"
    );
}

/// Human vendored-uuid over a purl the ledger already vendors at a
/// DIFFERENT uuid: the engine's `[fetch] … (replacing …)` line names the
/// superseded short uuid (ledger-derived — there is no manifest), then a
/// clean vendor step — exit 0 with the artifact committed at the new uuid.
#[tokio::test]
async fn human_vendored_uuid_supersede_prints_replacing_and_vendors() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID_B, PURL).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, stdout, stderr) =
        run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID_B));
    assert_eq!(code, 0, "first vendoring: stdout={stdout}\nstderr={stderr}");

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "vendored", "--vendor-source", "service"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains(&format!("[fetch] {PURL} (replacing 22222222)")),
        "the fetch line must carry the short superseded uuid; stderr={stderr}"
    );
    assert!(
        !stdout.contains("Patch record saved to"),
        "nothing is saved to a manifest in vendored mode; stdout={stdout}"
    );
    assert_vendored_detached(tmp.path(), PURL, UUID);
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(artifact.is_file(), "stdout={stdout}\nstderr={stderr}");
}

/// Human vendored-uuid re-get of an ALREADY-VENDORED uuid: the download
/// phase reuses the ledger's detached record (`[skip] … (already vendored)`,
/// no manifest anywhere) and the vendor step still runs (and succeeds) over
/// it — the artifact survives.
#[tokio::test]
async fn human_vendored_uuid_rerun_prints_already_vendored_skip() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID));
    assert_eq!(code, 0, "first vendoring: stdout={stdout}\nstderr={stderr}");

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "vendored", "--vendor-source", "service"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains(&format!("[skip] {PURL} (already vendored)")),
        "stderr={stderr}"
    );
    assert!(
        !stdout.contains("Skipped: 1 (already exists)"),
        "the manifest-vocabulary summary is gone with the manifest; stdout={stdout}"
    );
    assert_vendored_detached(tmp.path(), PURL, UUID);
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(artifact.is_file(), "stdout={stdout}\nstderr={stderr}");
}

/// Agent-mode `--dry-run` (search path) previews and writes NOTHING: no
/// `.socket/`, no view fetch, no prompt, exit 0.
#[tokio::test]
async fn agent_search_dry_run_writes_nothing() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let index_before = std::fs::read(tmp.path().join("node_modules/covgap-pkg/index.js")).unwrap();

    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[GHSA, "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains(&format!("  [would-add] {PURL}\n"))
            && stdout.contains("[dry-run] Would download and apply 1 patch. No changes made."),
        "stdout={stdout}"
    );
    // The listing shows only the installed version; the other one is
    // summarized once on stderr.
    assert!(
        stdout.contains("Found 1 patch:") && !stdout.contains(PURL_V2),
        "stdout={stdout}"
    );
    assert!(
        stderr.contains(
            "Skipped 1 patch for 1 package version not installed here \
             (use --all-releases to include it)."
        ),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("[Y/n]"),
        "a dry run never prompts; stderr={stderr}"
    );
    assert!(!tmp.path().join(".socket").exists());
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/covgap-pkg/index.js")).unwrap(),
        index_before
    );
    assert!(
        !received_paths(&server)
            .await
            .iter()
            .any(|p| p.contains("/patches/view/")),
        "a dry run must not fetch patch views"
    );
}

/// `--silent` is "errors only", never "nothing": a failed nested apply
/// still says why the run exits 1.
#[tokio::test]
async fn silent_apply_failure_still_prints_an_error() {
    let server = MockServer::start().await;
    // A view whose beforeHash matches nothing on disk and whose file is
    // missing: the nested apply fails.
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/missing.js": {
                "beforeHash": "0".repeat(64),
                "afterHash": git_hash(AFTER_BYTES),
                "blobContent": b64(AFTER_BYTES),
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID, "--silent"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.is_empty(), "stdout={stdout}");
    // The per-package reason prints even under --silent, so the closing
    // line needs no "re-run without --silent" hint.
    assert!(
        stderr.contains(&format!("Error: Failed to patch {PURL}: ")),
        "stderr={stderr}"
    );
    assert!(
        stderr.ends_with("Error: Some patches could not be applied.\n"),
        "stderr={stderr}"
    );

    // --json: the envelope is the only channel; the nested apply's
    // per-package error lines stay off stderr too.
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID, "--json"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(!stderr.contains("Error"), "stderr={stderr}");
    serde_json::from_str::<serde_json::Value>(&stdout).expect("one JSON envelope");

    // Loud twin: the same closing line.
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, _stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID]);
    assert_eq!(code, 1, "stderr={stderr}");
    assert!(
        stderr.contains("Error: Some patches could not be applied.\n"),
        "stderr={stderr}"
    );
}

/// The nested apply's `Patched packages:` block puts its leading blank
/// line on stderr: stdout gets no blank line of its own before it, and
/// never two in a row.
#[tokio::test]
async fn nested_apply_block_starts_stdout_without_a_blank_line() {
    let server = MockServer::start().await;
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": {
                "beforeHash": git_hash(BEFORE_BYTES),
                "afterHash": git_hash(AFTER_BYTES),
                "blobContent": b64(AFTER_BYTES),
            }
        }),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.starts_with(&format!("Patched packages:\n  {PURL}")),
        "stdout={stdout:?}"
    );
    assert!(!stdout.contains("\n\n\n"), "stdout={stdout:?}");
}

/// A free user's CVE search: a free patch for one installed package and a
/// paid patch for ANOTHER installed package. The narrowed listing must
/// still show the paid fix as `[PAID] (no access)` (an installed package's
/// fix is never silently hidden), while a paid patch for a version that is
/// not installed stays out of it. No `Selected:` block (the one free patch
/// was the only candidate), and stdout starts with the result itself.
#[tokio::test]
async fn narrowed_listing_keeps_installed_paid_no_access_patch() {
    let server = MockServer::start().await;
    let cve = "CVE-2024-5151";
    let paid = |uuid: &str, purl: &str| {
        serde_json::json!({
            "uuid": uuid, "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "description": "paid", "license": "MIT", "tier": "paid",
            "vulnerabilities": {}
        })
    };
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                {
                    "uuid": UUID, "purl": PURL,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "free", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                },
                paid(UUID_B, "pkg:npm/covgap-paid-other@2.0.0"),
                paid(UUID_V2, "pkg:npm/covgap-paid-other@9.0.0"),
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    install_npm_fixture(tmp.path(), "covgap-paid-other", "2.0.0");
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[cve, "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.starts_with("Found 2 patches:\n"),
        "stdout must start with the listing; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("pkg:npm/covgap-paid-other@2.0.0 [PAID] (no access)"),
        "stdout={stdout}"
    );
    assert!(
        !stdout.contains("covgap-paid-other@9.0.0"),
        "a paid patch for an uninstalled version must not be listed; stdout={stdout}"
    );
    assert!(!stdout.contains("Selected:"), "stdout={stdout}");
    assert!(
        stdout.contains(&format!("  [would-add] {PURL}\n")),
        "stdout={stdout}"
    );
    // The paid skip is not the user's to act on: no skip summary counts it.
    assert!(!stderr.contains("Skipped "), "stderr={stderr}");
    assert!(!tmp.path().join(".socket").exists());
}

/// Human `get --mode vendored` whose every download fails: no record
/// reaches the vendor step, the vendor engine is quiet about an empty record
/// set, and the scan vendor step (in its `get` flavor) closes the run with
/// "No vendorable patches in scope." instead of ending with no summary.
#[tokio::test]
async fn human_vendored_search_all_downloads_failed_prints_empty_run_line() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    // No views mounted -> every view fetch 404s.

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
        ],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("No vendorable patches in scope."),
        "stdout={stdout}\nstderr={stderr}"
    );
}

/// The human vendored dry run of `get <purl>` on a vlt project the vlt
/// preflight refuses (a transitive target) prints the code-tagged
/// `[would-refuse]` line and writes nothing.
#[tokio::test]
async fn get_vendored_dry_run_human_prints_the_vlt_would_refuse_line() {
    use vlt_hosted_common as hosted;
    let server = wiremock::MockServer::start().await;
    hosted::mock_all(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vlt_vendored::write_project(root);
    let lock = format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n    \
         \"~npm~has@1.0.0\": [0,\"has\",\"sha512-H==\"],\n    {}\n  }},\n  \"edges\": {{\n    \
         \"file~_d has\": \"prod 1.0.0 ~npm~has@1.0.0\",\n    \"~npm~has@1.0.0 left-pad\": \
         \"prod 1.3.0 {}\"\n  }}\n}}\n",
        hosted::registry_node(hosted::TILDE_ID),
        hosted::TILDE_ID
    );
    std::fs::write(root.join("vlt-lock.json"), &lock).unwrap();
    std::fs::write(
        root.join("package.json"),
        "{\n  \"dependencies\": {\n    \"has\": \"1.0.0\"\n  }\n}\n",
    )
    .unwrap();
    let cwd = root.to_str().unwrap().to_string();
    let uri = server.uri();
    let out = hosted::scrubbed_cli()
        .args([
            "get",
            hosted::PURL,
            "--mode",
            "vendored",
            "--dry-run",
            "--yes",
            "--cwd",
            &cwd,
            "--api-url",
            &uri,
            "--org",
            hosted::ORG,
            "--api-token",
            "fake",
        ])
        .current_dir(root)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "[would-refuse] {} (vendor_vlt_transitive_unsupported)",
            hosted::PURL
        )),
        "{stdout}"
    );
    assert_eq!(hosted::read(root, "vlt-lock.json"), lock);
    assert!(!root.join(".socket").exists());
}

// ═══════════ halves of the `--json` failure-path tests ═══════════

/// Human twin of `get_uuid_traversal_after_hash_fails_blob_write`: the
/// blob failure goes to stderr, naming the purl.
#[tokio::test]
async fn human_uuid_blob_write_failure_names_the_purl() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, traversal_files()).await;
    let tmp = tempfile::tempdir().unwrap();
    let (code, _stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID, "--save-only"]);
    assert_eq!(code, 1, "blob failure must exit 1; stderr={stderr}");
    assert!(
        stderr.contains(&format!(
            "Error: Blob decode or write failed for patch {PURL}"
        )),
        "human mode must report the blob failure on stderr; stderr={stderr}"
    );
    assert_no_manifest(tmp.path());
}

/// Human twin of `package_search_without_a_match_is_no_match`: the
/// `noMatch` message on stdout, and the crawl progress as stderr
/// narration.
#[tokio::test]
async fn human_package_search_without_a_match_prints_no_match() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    install_npm_fixture(tmp.path(), "leftpad", "1.0.0");
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &["zzqxjvwq", "--package", "--save-only"],
    );
    assert_eq!(code, 0, "stdout={stdout}");
    assert!(
        stdout.contains("No packages matching \"zzqxjvwq\" found."),
        "human no_match message; stdout={stdout}"
    );
    // The transient "Enumerating packages..." line never reaches a pipe,
    // the result line does (singular for one package).
    assert!(
        !stdout.contains("Enumerating packages") && stderr.contains("Found 1 package\n"),
        "the crawl progress prints must appear; stdout={stdout}"
    );
    assert!(received_paths(&server).await.is_empty());
}

/// Human twin of `vendored_lock_held_vendor_step_errors_without_vendor_envelope`:
/// the shared vendor-step formatter prints `Error (lock_held): …`,
/// capitalized and period-terminated, plus the wait hint every other lock
/// error carries.
#[tokio::test]
async fn human_vendored_lock_held_prints_coded_error_and_wait_hint() {
    let server = MockServer::start().await;
    mount_ghsa_single(&server).await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let _lock =
        socket_patch_core::patch::apply_lock::acquire(&socket, std::time::Duration::ZERO).unwrap();

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
        ],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let lines: Vec<&str> = stderr.lines().collect();
    let line = lines
        .iter()
        .position(|l| l.starts_with("Error (lock_held): "))
        .unwrap_or_else(|| panic!("no coded vendor-step error; stderr={stderr}"));
    assert_eq!(
        lines[line],
        "Error (lock_held): Another socket-patch process is operating in this directory.",
        "stderr={stderr}"
    );
    assert_eq!(
        lines.get(line + 1).copied(),
        Some("  Wait for it to finish, or retry with --lock-timeout <secs> to wait for the lock."),
        "stderr={stderr}"
    );
}

/// Human twin of `hosted_lock_held_get_errors_with_top_level_error_code`:
/// the shared lock error line and the wait hint.
#[tokio::test]
async fn human_hosted_lock_held_prints_error_and_wait_hint() {
    let (server, tmp, _lock) = hosted_project_with_held_lock().await;
    let (code, stdout, stderr) =
        run_get_bin(tmp.path(), &server.uri(), &[UUID, "--mode", "hosted"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains("Error: Another socket-patch process is operating in this directory\n"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("--lock-timeout"),
        "the wait hint must accompany a live holder; stderr={stderr}"
    );
}

/// Human twin of `forced_identifier_type_is_validated_locally`: the
/// readable usage error, exit 2.
#[tokio::test]
async fn human_forced_identifier_type_prints_expected_form() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    for (flag, what) in [
        ("--id", "is not a valid patch UUID"),
        ("--cve", "is not a valid CVE ID"),
        ("--ghsa", "is not a valid GHSA ID"),
    ] {
        let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &["lodash", flag]);
        assert_eq!(code, 2, "{flag}: stdout={stdout}\nstderr={stderr}");
        assert!(
            stderr.contains(&format!("Error: The identifier {what} (expected ")),
            "{flag}: stderr={stderr}"
        );
    }
    assert!(received_paths(&server).await.is_empty());
}

/// Human twin of `proxy_403_on_uuid_is_paid_required`: the upgrade
/// message, never a raw "Forbidden".
#[tokio::test]
async fn human_proxy_403_on_uuid_prints_upgrade_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_via_proxy(tmp.path(), &server.uri(), &[UUID]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains(&format!(
            "This patch requires a paid Socket plan.\n  Patch: {UUID}\n\
             Upgrade to a paid Socket plan to access all patches: https://socket.dev/pricing"
        )),
        "stdout={stdout}"
    );
    assert!(!stderr.contains("Forbidden"), "stderr={stderr}");
    assert!(!tmp.path().join(".socket").exists());
}
