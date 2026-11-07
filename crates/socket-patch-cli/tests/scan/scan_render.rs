//! `scan`'s human output (#1089): one check per message family, plus the
//! disk state the human arm (its own code path) leaves behind. The
//! `--json` contracts of the same paths are pinned in
//! `scan_failure_paths.rs`; scan on a real terminal is `scan_tty.rs`.
//!
//!   1. terminals reachable without a network: `--offline`, hosted
//!      `--prune`, an empty `--global-prefix`, `--ecosystems`, usage errors;
//!   2. the paid-tier table column, summaries and nudge;
//!   3. the results table: `[UPDATE]`, `(+N)`, full purls, the preview's
//!      vulnerability lines, and the detail-fetch warning and error;
//!   4. `[skip]`, `[re-apply]` and `[would-refuse]` lines;
//!   5. report-only runs and their hints, agent-mode applies, the GC line
//!      and the retained-wiring warning;
//!   6. hosted mode's table, per-directory runs and corrupt `bun.lockb`.

use std::path::Path;

use wiremock::MockServer;

use crate::scan_fixture::*;

// ---------------------------------------------------------------------------
// Terminals reachable without a network
// ---------------------------------------------------------------------------

/// `scan --offline`: hard error on stderr, exit 1, nothing on stdout.
#[test]
fn scan_offline_human_path_errors_on_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_scan(tmp.path(), &["--offline"]);
    assert_eq!(code, 1, "offline scan must fail; stderr={stderr:?}");
    assert!(
        stderr.contains("scan requires network access"),
        "the strict-airgap refusal must reach stderr; got {stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "the human offline error must not print a JSON envelope; got {stdout:?}"
    );
}

/// `scan --mode hosted --prune`: the no-GC warning fires BEFORE the crawl,
/// so an empty project suffices (no network at all).
#[test]
fn scan_hosted_prune_human_warns_prune_is_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, _stdout, stderr) = run_scan(tmp.path(), &["--mode", "hosted", "--prune"]);
    assert_eq!(
        code, 0,
        "hosted --prune stays accepted (never a usage error)"
    );
    assert!(
        stderr.contains("Warning: --prune has no effect with --mode hosted"),
        "the ignored-prune warning must reach stderr; got {stderr:?}"
    );
}

/// `--global-prefix <empty dir>`: the global-flavored empty-scan hint.
#[test]
fn scan_empty_global_prefix_prints_global_hint() {
    let tmp = tempfile::tempdir().unwrap();
    let prefix = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &["--global-prefix", prefix.path().to_str().unwrap()],
    );
    assert_eq!(code, 0, "an empty global scan succeeds; stderr={stderr:?}");
    assert!(
        stdout.contains("No global packages found."),
        "the global empty-scan hint must print; got {stdout:?}"
    );
    assert!(
        !stdout.contains("No packages found. Run"),
        "the local-flavored hint must not print on a global scan; got {stdout:?}"
    );
}

/// An empty crawl never prunes (too destructive), but says so instead of
/// silently dropping `--prune`; `--silent` keeps it quiet.
#[test]
fn scan_prune_on_empty_crawl_warns_the_gc_was_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_scan(tmp.path(), &["--prune"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(
        stderr.contains("Warning: --prune skipped: no installed packages were found"),
        "{stderr:?}"
    );
    assert!(stdout.contains("No packages found."), "{stdout:?}");
    let (code, stdout, stderr) = run_scan(tmp.path(), &["--prune", "--silent"]);
    assert_eq!(code, 0);
    assert!(
        stdout.is_empty() && stderr.is_empty(),
        "{stdout:?} {stderr:?}"
    );
}

/// `--ecosystems` that filters everything out names the filter instead of
/// telling the user to run `cargo install`/`go install`.
#[test]
fn scan_empty_after_ecosystem_filter_names_the_filter() {
    let tmp = minimist_project(b"x\n");
    let (code, stdout, stderr) = run_scan(tmp.path(), &["-e", "pypi"]);
    assert_eq!(code, 0, "stderr={stderr:?}");
    assert!(stdout.contains("No pypi packages found."), "{stdout:?}");
}

/// Global installs have no project lockfile: `--mode hosted` with
/// `--global` or `--global-prefix` is a usage error naming the flag, not a
/// silent "redirected 0 packages". The `--json` code is pinned in
/// `scan_failure_paths.rs`.
#[test]
fn scan_hosted_rejects_global() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_scan(tmp.path(), &["--mode", "hosted", "--global"]);
    assert_eq!(code, 2, "stderr={stderr:?}");
    assert!(
        stderr.starts_with(
            "Error: --global cannot be used with --mode hosted: global installs have no \
             project lockfile to redirect"
        ),
        "{stderr:?}"
    );
    assert!(stdout.is_empty());
    let prefix = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run_scan(
        tmp.path(),
        &[
            "--mode",
            "hosted",
            "--global-prefix",
            prefix.path().to_str().unwrap(),
        ],
    );
    assert_eq!(code, 2);
    assert!(
        stderr.starts_with("Error: --global-prefix cannot be used with --mode hosted"),
        "{stderr:?}"
    );
}

/// Usage errors from scan's own flag checks use the capitalized `Error:`
/// prefix like every other error line, and name no hidden flag.
#[test]
fn scan_mode_conflict_error_is_capitalized_and_names_no_hidden_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, _, stderr) = run_scan(tmp.path(), &["--mode", "hosted", "--sync"]);
    assert_eq!(code, 2);
    assert!(
        stderr.starts_with("Error: --mode hosted cannot be used with --sync"),
        "{stderr:?}"
    );
    assert!(!stderr.contains("--redirect"), "{stderr:?}");
}

// ---------------------------------------------------------------------------
// Paid tier: no other fixture sends tier: "paid"
// ---------------------------------------------------------------------------

/// Paid patch, NO paid access: the `free+paid` table column, the free-only
/// summary, the paid-plan nudge with the pricing URL, and the "No
/// downloadable patches" terminal (exit 0, no detail fetch attempted).
#[tokio::test]
async fn scan_paid_patch_without_access_nudges_and_downloads_nothing() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "paid", &["CVE-2024-0001"], false).await;
    let tmp = minimist_project(b"x\n");

    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("0+1"),
        "the table column must render free+paid counts; got {stdout:?}"
    );
    assert!(
        stdout.contains("Summary: 1 package with 0 free patches"),
        "the no-access summary counts FREE patches only; got {stdout:?}"
    );
    assert!(
        stdout.contains("+ 1 additional patch is available with a paid Socket plan"),
        "the paid nudge must print; got {stdout:?}"
    );
    assert!(
        stdout.contains("https://socket.dev/pricing"),
        "the pricing URL must print; got {stdout:?}"
    );
    assert!(
        stdout.contains("No downloadable patches: every patch found requires a paid Socket plan."),
        "the gated-catalog terminal must print; got {stdout:?}"
    );
    assert_eq!(
        by_package_gets(&recorded(&mock).await),
        0,
        "no detail fetch may happen when nothing is downloadable"
    );
}

/// Paid patch WITH paid access: the summary counts ALL patches (the
/// can-access arm) and no nudge prints. The deliberately failing detail
/// fetch then fails the run (its error line is pinned below).
#[tokio::test]
async fn scan_paid_patch_with_access_counts_all_patches() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "paid", &[], true).await;
    mount_by_package_500(&mock, MINIMIST).await;
    let tmp = minimist_project(b"x\n");

    let (code, stdout, stderr) = run_scan_agent(tmp.path(), &mock.uri(), &[]);
    assert_eq!(
        code, 1,
        "a failed detail fetch fails the scan; stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stdout.contains("Summary: 1 package with 1 available patch"),
        "the can-access summary counts all patches; got {stdout:?}"
    );
    assert!(
        stdout.contains("0+1"),
        "the free+paid column renders for paid-access users too; got {stdout:?}"
    );
    assert!(
        !stdout.contains("paid Socket plan"),
        "no nudge for a subscriber; got {stdout:?}"
    );
}

// ---------------------------------------------------------------------------
// The results table and the per-patch preview
// ---------------------------------------------------------------------------

/// The `[UPDATE]` marker and newer-patches summary (the manifest's OLD uuid
/// against the batch's NEW uuid), the `(+N)` vuln overflow, and the
/// dry-run terminal before any confirm.
#[tokio::test]
async fn scan_human_table_renders_update_marker_and_vuln_overflow() {
    let mock = MockServer::start().await;
    mount_batch_one(
        &mock,
        MINIMIST,
        UUID,
        "free",
        &["CVE-2024-0003", "CVE-2024-0001", "CVE-2024-0002"],
        false,
    )
    .await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    let tmp = minimist_project(b"x\n");
    seed_manifest(tmp.path(), &[(MINIMIST, OLD_UUID)]);

    // --dry-run keeps the run read-only past the table (the download and
    // apply never run), so no view/blob mocks are needed.
    let (code, stdout, stderr) = run_scan_agent(tmp.path(), &mock.uri(), &["--dry-run", "--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("[UPDATE]"),
        "the human update marker must render; got {stdout:?}"
    );
    assert!(
        stdout.contains("1 package has a newer patch available."),
        "the newer-patches summary must print; got {stdout:?}"
    );
    // collect_vuln_ids sorts CVEs, so the first two sorted ids show and the
    // third folds into (+1).
    assert!(
        stdout.contains("CVE-2024-0001, CVE-2024-0002 (+1)"),
        "3+ vuln ids must truncate to two plus (+N); got {stdout:?}"
    );
    assert!(
        stdout.contains("[dry-run] Would download and apply 1 patch. No changes made."),
        "dry-run must stop before the confirm; got {stdout:?}"
    );
}

/// The table's PACKAGE column grows to fit the PURL (a fixed-width cut
/// would drop the version), and the rule matches the table.
#[tokio::test]
async fn scan_human_table_shows_full_purl_with_version() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/@typescript-eslint/typescript-estree@6.0.0";
    mount_batch_one(&mock, purl, UUID, "free", &["CVE-2024-1"], false).await;
    mount_by_package(&mock, purl, UUID, serde_json::json!({})).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    let pkg_dir = tmp
        .path()
        .join("node_modules/@typescript-eslint/typescript-estree");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "@typescript-eslint/typescript-estree", "version": "6.0.0" }"#,
    )
    .unwrap();
    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &["--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let row = stdout
        .lines()
        .find(|l| l.contains("CVE-2024-1") && l.starts_with("pkg:npm/"))
        .unwrap_or_else(|| panic!("no table row in {stdout:?}"));
    assert!(row.starts_with(&format!("{purl}  ")), "{row:?}");
    let header = stdout.lines().find(|l| l.starts_with("PACKAGE")).unwrap();
    // The right-aligned count ends where the PATCHES header ends.
    assert_eq!(
        header.find("PATCHES").map(|i| i + "PATCHES".len()),
        row.find(" 1  ").map(|i| i + 2),
        "PATCHES header sits over the count: {stdout}"
    );
    // The rule is exactly as wide as the widest table line.
    let rule = stdout.lines().find(|l| l.starts_with("===")).unwrap();
    assert_eq!(rule.len(), header.len().max(row.len()), "{stdout}");
}

/// Per-patch vulnerability rendering in the "Patches to apply" preview.
/// Every other human-path fixture ships `vulnerabilities: {}`, so the
/// CVE/GHSA fold, the "Fixes:" line, and the per-vuln summary lines had
/// never executed.
#[tokio::test]
async fn scan_human_preview_renders_vulnerability_details() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package(
        &mock,
        MINIMIST,
        UUID,
        serde_json::json!({
            "GHSA-aaaa-bbbb-cccc": {
                "cves": ["CVE-2024-9999"],
                "summary": "heap overflow in parse",
                "severity": "HIGH",
                "description": "d"
            },
            "GHSA-dddd-eeee-ffff": {
                "cves": [],
                "summary": "no-cve issue",
                "severity": "LOW",
                "description": "d"
            }
        }),
    )
    .await;
    let tmp = minimist_project(b"x\n");

    let (code, stdout, stderr) = run_scan_agent(tmp.path(), &mock.uri(), &["--dry-run", "--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let fixes = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("Fixes: "))
        .unwrap_or_else(|| panic!("the Fixes line must print; got {stdout:?}"));
    assert!(
        fixes.contains("CVE-2024-9999") && fixes.contains("GHSA-dddd-eeee-ffff"),
        "a vuln WITH CVEs contributes its CVE ids, a CVE-less one its GHSA id: {fixes:?}"
    );
    for line in [
        "- CVE-2024-9999: heap overflow in parse",
        "- GHSA-dddd-eeee-ffff: no-cve issue",
    ] {
        assert!(
            stdout.lines().any(|l| l.trim() == line),
            "each vuln's summary is labeled with its CVE or advisory id ({line:?}); got {stdout:?}"
        );
    }
}

/// When every detail fetch fails, the human path prints ONE Error line that
/// names the package and the cause (no per-package Warning repeating it).
#[tokio::test]
async fn scan_human_detail_fetch_failure_errors_once() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package_500(&mock, MINIMIST).await;
    let tmp = minimist_project(b"x\n");

    let (code, stdout, stderr) = run_scan_agent(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 1, "stdout={stdout}; stderr={stderr}");
    assert!(
        stderr.contains(&format!(
            "Error: could not fetch patch details for {MINIMIST}: "
        )),
        "the terminal error names the purl and the cause; got {stderr:?}"
    );
    assert!(
        !stderr.contains("Warning: could not fetch details"),
        "a total failure must not repeat the cause as a Warning first; got {stderr:?}"
    );
}

/// A partial detail-fetch failure warns once per failed package on stderr
/// and is not an error, whether the packages that did resolve have patches
/// or (#1062) came back empty.
#[tokio::test]
async fn scan_human_partial_detail_fetch_failure_warns_per_package() {
    let bad = "pkg:npm/lodash@4.17.20";
    for other_has_patches in [true, false] {
        let mock = MockServer::start().await;
        mount_batch_free(
            &mock,
            &[
                (MINIMIST, UUID),
                (bad, "33333333-3333-4333-8333-333333333333"),
            ],
        )
        .await;
        if other_has_patches {
            mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
        } else {
            mount_by_package_empty(&mock, MINIMIST).await;
        }
        mount_by_package_500(&mock, bad).await;
        let tmp = minimist_project(b"x\n");
        write_npm_package(tmp.path(), "lodash", "4.17.20", b"x\n");

        let (code, stdout, stderr) = run_scan_agent(tmp.path(), &mock.uri(), &["--dry-run"]);
        assert_eq!(
            stderr
                .matches(&format!("Warning: could not fetch details for {bad}: "))
                .count(),
            1,
            "other_has_patches={other_has_patches}: one warning naming the failed purl; \
             stdout={stdout}; stderr={stderr:?}"
        );
        assert!(
            !stderr.contains("Error:"),
            "other_has_patches={other_has_patches}: a partial failure is not an error: {stderr:?}"
        );
        assert_eq!(code, 0, "other_has_patches={other_has_patches}: {stderr}");
    }
}

// ---------------------------------------------------------------------------
// [skip], [re-apply] and [would-refuse] lines
// ---------------------------------------------------------------------------

/// A purl the vendored ledger owns gets a `[skip]` line naming it and the
/// remedy, and with everything vendor-owned nothing is selected.
#[tokio::test]
async fn scan_human_skips_vendored_purls_without_downloading() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    let tmp = minimist_project(b"x\n");
    seed_vendored_entry(tmp.path(), MINIMIST);

    let (code, stdout, stderr) = run_scan_agent(tmp.path(), &mock.uri(), &["--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains(&format!(
            "[skip] {MINIMIST} (vendored; run `socket-patch scan --mode vendored` to update it)"
        )),
        "the vendored skip line must name the purl and the remedy; got {stdout:?}"
    );
    assert!(
        stdout.contains("No patches selected."),
        "with everything vendor-owned nothing is selected; got {stdout:?}"
    );
    assert_eq!(
        view_gets(&recorded(&mock).await),
        0,
        "vendor-owned purls must not download"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "a fully-skipped run must not create the manifest"
    );
}

/// #732: a human-output `scan --mode agent` / `scan --sync` re-applies a
/// patch the manifest already records once a reinstall has put the
/// pristine bytes back (the `--json` path has done so since #454).
#[tokio::test]
async fn scan_human_reapplies_an_already_recorded_patch_after_reinstall() {
    for flags in [&["--mode", "agent"][..], &["--sync"][..]] {
        let mock = MockServer::start().await;
        let before = b"before\n";
        mount_one_patch_api(&mock, MINIMIST, before).await;
        let tmp = minimist_project(before);
        let index = tmp.path().join("node_modules/minimist/index.js");

        let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), flags);
        assert_eq!(code, 0, "flags={flags:?}: stdout={stdout}; stderr={stderr}");
        assert_eq!(
            std::fs::read(&index).unwrap(),
            b"after\n",
            "flags={flags:?}"
        );

        // `npm ci` / `rm -rf node_modules && npm install`.
        std::fs::write(&index, before).unwrap();

        let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), flags);
        assert_eq!(code, 0, "flags={flags:?}: stdout={stdout}; stderr={stderr}");
        assert_eq!(
            std::fs::read(&index).unwrap(),
            b"after\n",
            "flags={flags:?}: the recorded patch must be re-applied; stdout={stdout}; stderr={stderr}"
        );
        assert!(
            stdout.contains(&format!(
                "[re-apply] {MINIMIST} (already recorded: 11111111)"
            )),
            "flags={flags:?}: {stdout:?}"
        );
        assert!(
            !stdout.contains("run `socket-patch apply` to re-apply them"),
            "flags={flags:?}: {stdout:?}"
        );
        assert_eq!(
            read_manifest(tmp.path())["patches"][MINIMIST]["uuid"],
            UUID,
            "flags={flags:?}"
        );
    }
}

/// #732: when a run also has a new patch, the recorded-but-reverted one
/// is re-applied alongside it rather than dropped from the selection.
#[tokio::test]
async fn scan_human_reapplies_recorded_patch_alongside_a_new_one() {
    let b = "pkg:npm/left-pad@1.3.0";
    let before = b"before\n";
    let tmp = minimist_project(before);
    write_npm_package(tmp.path(), "left-pad", "1.3.0", before);
    let index_a = tmp.path().join("node_modules/minimist/index.js");
    let index_b = tmp.path().join("node_modules/left-pad/index.js");

    // First run: only minimist has a patch.
    let first = MockServer::start().await;
    mount_patch_api(&first, &[(MINIMIST, UUID)], before).await;
    let (code, stdout, stderr) = run_scan_agent(tmp.path(), &first.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert_eq!(std::fs::read(&index_a).unwrap(), b"after\n");
    assert_eq!(std::fs::read(&index_b).unwrap(), before);

    // Reinstall, then a patch for left-pad is published.
    std::fs::write(&index_a, before).unwrap();
    let second = MockServer::start().await;
    mount_patch_api(&second, &[(MINIMIST, UUID), (b, UUID_B)], before).await;
    let (code, stdout, stderr) = run_scan_agent(tmp.path(), &second.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert_eq!(
        std::fs::read(&index_b).unwrap(),
        b"after\n",
        "new patch applied; stdout={stdout}; stderr={stderr}"
    );
    assert_eq!(
        std::fs::read(&index_a).unwrap(),
        b"after\n",
        "recorded patch re-applied; stdout={stdout}; stderr={stderr}"
    );
    assert!(stdout.contains("Patches to apply:"), "{stdout:?}");
    assert!(
        stdout.contains(&format!(
            "[re-apply] {MINIMIST} (already recorded: 11111111)"
        )),
        "{stdout:?}"
    );
}

/// `--dry-run` stays a non-mutating preview: an already-recorded
/// selection is neither downloaded nor re-applied, and the message says a
/// wet run re-applies it.
#[tokio::test]
async fn scan_human_dry_run_previews_reapply_of_a_recorded_patch() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    let tmp = minimist_project(b"x\n");
    seed_manifest(tmp.path(), &[(MINIMIST, UUID)]);
    let manifest_before = std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap();

    let (code, stdout, stderr) = run_scan_agent(tmp.path(), &mock.uri(), &["--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains(&format!("[skip] {MINIMIST} (already recorded: 11111111)")),
        "{stdout:?}"
    );
    assert!(
        stdout.contains("a run without --dry-run re-applies them"),
        "{stdout:?}"
    );
    assert!(!stdout.contains("Patches to apply:"), "{stdout:?}");
    assert_eq!(
        view_gets(&recorded(&mock).await),
        0,
        "nothing is downloaded"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/minimist/index.js")).unwrap(),
        b"x\n"
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap(),
        manifest_before
    );
}

/// A report-only `scan --prune --dry-run` never applies, so it must not
/// say that dropping `--dry-run` re-applies a recorded patch.
#[tokio::test]
async fn scan_report_only_dry_run_points_recorded_patch_at_apply() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    let tmp = minimist_project(b"x\n");
    seed_manifest(tmp.path(), &[(MINIMIST, UUID)]);

    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &["--prune", "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains(&format!("[skip] {MINIMIST} (already recorded: 11111111)")),
        "{stdout:?}"
    );
    assert!(
        !stdout.contains("a run without --dry-run re-applies them"),
        "{stdout:?}"
    );
    assert!(!stdout.contains("[re-apply]"), "{stdout:?}");
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/minimist/index.js")).unwrap(),
        b"x\n"
    );
}

/// Human `--mode vendored --dry-run` names what the wet run would refuse
/// with `[would-refuse]` lines, like `get --mode vendored --dry-run`: both
/// commands share the printer. `--silent` keeps the preview quiet.
#[tokio::test]
async fn scan_human_vendored_dry_run_names_would_refuse_records() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    let tmp = minimist_project(b"x\n");
    write_bun_v1_workspace_lock(tmp.path());

    let (code, stdout, stderr) = run_scan_api(
        tmp.path(),
        &mock.uri(),
        &["--mode", "vendored", "--dry-run"],
    );
    assert_eq!(
        code, 0,
        "a preview never flips the exit; stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stdout.contains("[dry-run] Would download and vendor 0 of 1 patch (1 would be refused). No changes made."),
        "the count line stays; got {stdout:?}"
    );
    let refusal = stdout
        .lines()
        .find(|l| {
            l.starts_with(&format!(
                "  [would-refuse] {MINIMIST} (vendor_bun_workspace_unsupported): "
            ))
        })
        .unwrap_or_else(|| panic!("the preview must name the refusal; got {stdout:?}"));
    assert!(
        refusal.contains("--mode hosted"),
        "the engine's detail (with its remedy) rides along: {refusal:?}"
    );
    // Nothing written: no manifest, no blobs, no vendor ledger.
    assert!(
        !tmp.path().join(".socket").exists(),
        "a dry run writes nothing"
    );

    let (code, stdout, _) = run_scan_api(
        tmp.path(),
        &mock.uri(),
        &["--mode", "vendored", "--dry-run", "--silent"],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.trim().is_empty(),
        "silent dry run prints nothing:\n{stdout}"
    );
}

/// #1850: on a project already vendored at this uuid, the human
/// `--mode vendored --dry-run` says so instead of offering to download and
/// vendor the patch: the headline leaves it out, as the JSON's
/// `already_vendored` row and the wet run's "nothing to do" do, and the
/// wet run's `[skip] … (already vendored)` line names it.
#[tokio::test]
async fn scan_human_vendored_dry_run_skips_already_vendored() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    let tmp = minimist_project(b"x\n");
    seed_vendored_entry(tmp.path(), MINIMIST);
    let ledger = std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap();

    let (code, stdout, stderr) = run_scan_api(
        tmp.path(),
        &mock.uri(),
        &["--mode", "vendored", "--dry-run"],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains(
            "[dry-run] Would download and vendor 0 of 1 patch (1 already vendored). \
             No changes made."
        ),
        "the headline must not count the in-sync patch as work; got {stdout:?}"
    );
    assert!(
        stderr.contains(&format!("  [skip] {MINIMIST} (already vendored)")),
        "the in-sync patch is named as skipped; stderr={stderr:?}"
    );
    assert!(!stdout.contains("[would-refuse]"), "{stdout:?}");
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap(),
        ledger,
        "a dry run writes nothing"
    );
}

// ---------------------------------------------------------------------------
// Report-only runs, agent-mode applies, GC and wiring warnings
// ---------------------------------------------------------------------------

/// One installed package, a batch response with no patches: the result is
/// said once, on stdout; the status line ends without repeating it.
#[tokio::test]
async fn scan_human_empty_batch_reports_no_patches_once() {
    let mock = MockServer::start().await;
    mount_empty_batch(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.5", b"module.exports = {};\n");

    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert_eq!(stdout, "\nNo patches available for installed packages.\n");
    assert!(!stderr.contains("No patches"), "stderr={stderr:?}");
    assert!(
        stderr.lines().any(|l| l == "Found 1 package (1 npm)"),
        "stderr={stderr:?}"
    );
    assert_eq!(batch_bodies(&recorded(&mock).await).len(), 1);
}

/// An empty discovery stops every human mode at the same result line with
/// exit 0 and no `.socket/`: vendored mode does not fall through to its
/// vendor step, and hosted mode does not enter its engine.
#[tokio::test]
async fn scan_human_empty_discovery_stops_in_every_mode() {
    let mock = MockServer::start().await;
    mount_empty_batch(&mock).await;
    for flags in [
        &[][..],
        &["--mode", "vendored"][..],
        &["--mode", "hosted"][..],
        &["--mode", "agent"][..],
    ] {
        let tmp = minimist_project(b"x\n");
        let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), flags);
        assert_eq!(code, 0, "flags={flags:?}: stdout={stdout}; stderr={stderr}");
        assert!(
            stdout
                .lines()
                .any(|l| l == "No patches available for installed packages."),
            "flags={flags:?}: got {stdout:?}"
        );
        assert!(
            !tmp.path().join(".socket").exists(),
            "flags={flags:?}: an empty discovery must create nothing"
        );
    }
    assert_eq!(reference_posts(&recorded(&mock).await), 0);
}

/// `--prune` with no mode: the discovery, table and per-patch preview
/// print (the report IS the value), then the run stops with the
/// agent-mode hint, writing nothing and downloading nothing.
#[tokio::test]
async fn scan_prune_without_a_mode_is_report_only() {
    let mock = MockServer::start().await;
    mount_one_patch_api(&mock, MINIMIST, b"x\n").await;
    let tmp = minimist_project(b"x\n");

    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &["--prune"]);
    assert_eq!(
        code, 0,
        "report-only is a success; stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stdout.contains("Patches to apply:") && stdout.contains(MINIMIST),
        "the per-patch preview still prints; got {stdout:?}"
    );
    assert!(
        stdout.contains("To apply these patches in place, run:")
            && stdout.contains("socket-patch scan --mode agent"),
        "the agent-mode hint must print; got {stdout:?}"
    );
    assert!(
        !stderr.contains("Non-interactive mode detected"),
        "scan never prompts; got {stderr:?}"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "a report-only scan must not create .socket/"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/minimist/index.js")).unwrap(),
        b"x\n",
        "a report-only scan must not patch the installed file"
    );
    assert_eq!(
        view_gets(&recorded(&mock).await),
        0,
        "a report-only scan must not download the patch"
    );
}

/// #464: a report-only global scan hints at commands that keep the global
/// scope. Run verbatim without `--global-prefix`, the hint would scan the
/// cwd project and leave the global copy unpatched.
#[tokio::test]
async fn scan_global_report_only_hint_keeps_the_global_scope() {
    let mock = MockServer::start().await;
    mount_one_patch_api(&mock, MINIMIST, b"x\n").await;

    let tmp = tempfile::tempdir().unwrap();
    // A prefix with a space: the hint must quote it to stay runnable.
    let prefix = tmp.path().join("global lib").join("node_modules");
    let pkg_dir = prefix.join("minimist");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "minimist", "version": "1.2.2" }"#,
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), b"x\n").unwrap();
    let cwd = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&cwd).unwrap();

    let prefix_arg = prefix.to_str().unwrap();
    let (code, stdout, stderr) = run_scan_api(&cwd, &mock.uri(), &["--global-prefix", prefix_arg]);
    assert_eq!(
        code, 0,
        "report-only is a success; stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stdout.contains("Patches to apply:") && stdout.contains(MINIMIST),
        "the global scan must find the patch; got {stdout:?}"
    );
    let quoted = if cfg!(windows) {
        format!("\"{prefix_arg}\"")
    } else {
        format!("'{prefix_arg}'")
    };
    for command in [
        format!("  socket-patch scan --mode agent --global-prefix {quoted}"),
        format!("  socket-patch get --global-prefix {quoted} <package-name-or-purl-or-CVE-ID>"),
    ] {
        assert!(
            stdout.lines().any(|line| line == command),
            "the hint must keep the global scope ({command:?}); got {stdout:?}"
        );
    }
    assert_eq!(
        std::fs::read(pkg_dir.join("index.js")).unwrap(),
        b"x\n",
        "a report-only scan must not patch the global copy"
    );
}

/// Each spelling that selects `--mode agent` applies without prompting.
#[tokio::test]
async fn scan_human_agent_mode_applies_without_prompting() {
    for flags in [&["--mode", "agent"][..], &["--sync"][..]] {
        let mock = MockServer::start().await;
        let before = b"before\n";
        mount_one_patch_api(&mock, SILENT_TARGET, before).await;
        let tmp = tempfile::tempdir().unwrap();
        write_root_package_json(tmp.path());
        write_npm_package(tmp.path(), "silent-target", "1.0.0", before);

        let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), flags);
        assert_eq!(code, 0, "flags={flags:?}: stdout={stdout}; stderr={stderr}");
        assert!(
            !stderr.contains("Non-interactive mode detected"),
            "flags={flags:?}: scan never prompts; got {stderr:?}"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("node_modules/silent-target/index.js")).unwrap(),
            b"after\n",
            "flags={flags:?}: the apply must proceed"
        );
        assert_eq!(
            read_manifest(tmp.path())["patches"][SILENT_TARGET]["uuid"],
            UUID,
            "flags={flags:?}"
        );
    }
}

/// The post-apply GC line, both pluralization arms, for each spelling of
/// apply-and-collect (`--sync`, `--mode agent --prune`). The pruned
/// manifest and swept blobs are pinned in `scan_failure_paths.rs`.
#[tokio::test]
async fn scan_human_gc_line_pluralizes() {
    let one: &[Orphan] = &[("pkg:npm/gone@1.0.0", OLD_UUID, 'c')];
    let two: &[Orphan] = &[
        ("pkg:npm/gone@1.0.0", OLD_UUID, 'c'),
        (
            "pkg:npm/also-gone@2.0.0",
            "88888888-8888-4888-8888-888888888888",
            'd',
        ),
    ];
    for (orphans, flags, line) in [
        (
            one,
            &["--sync", "--yes"][..],
            "GC: pruned 1 manifest entry and removed 1 orphan file (",
        ),
        (
            two,
            &["--sync", "--yes"][..],
            "GC: pruned 2 manifest entries and removed 2 orphan files (",
        ),
        (
            one,
            &["--mode", "agent", "--prune"][..],
            "GC: pruned 1 manifest entry and removed 1 orphan file (",
        ),
    ] {
        let mock = MockServer::start().await;
        let (code, stdout, stderr, tmp) = run_apply_with_orphans(&mock, orphans, flags).await;
        assert_eq!(code, 0, "{flags:?}: stdout={stdout}; stderr={stderr}");
        assert!(
            stdout.lines().any(|l| l.starts_with(line)),
            "{flags:?}: the GC line must print {line:?}; got {stdout:?}"
        );
        assert!(
            read_manifest(tmp.path())["patches"]["pkg:npm/gone@1.0.0"].is_null(),
            "{flags:?}: the line reports real work"
        );
    }
}

/// `scan --prune` with nothing to apply still garbage-collects, like the
/// JSON path, and a `--dry-run` previews it without touching the manifest.
#[tokio::test]
async fn scan_human_prune_runs_gc_even_when_no_patches_are_available() {
    let mock = MockServer::start().await;
    mount_empty_batch(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.5", b"x\n");
    seed_manifest(tmp.path(), &[("pkg:npm/gone@1.0.0", OLD_UUID)]);

    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &["--prune", "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("[dry-run] GC would prune 1 manifest entry and remove 0 orphan files"),
        "the dry run previews the GC; got {stdout:?}"
    );
    assert!(
        !read_manifest(tmp.path())["patches"]["pkg:npm/gone@1.0.0"].is_null(),
        "a preview must not prune"
    );

    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &["--prune"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("GC: pruned 1 manifest entry and removed 0 orphan files"),
        "the GC must run on the early exit; got {stdout:?}"
    );
    assert!(read_manifest(tmp.path())["patches"]["pkg:npm/gone@1.0.0"].is_null());
}

/// #1062: a `--dry-run --prune` prints the GC preview line exactly once in
/// agent, report-only and vendored mode alike, and writes nothing.
#[tokio::test]
async fn scan_dry_run_prune_previews_gc_once() {
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
        seed_manifest(tmp.path(), &[(stale, OLD_UUID)]);
        let manifest = tmp.path().join(".socket/manifest.json");
        let before = std::fs::read(&manifest).unwrap();
        let mut extra: Vec<&str> = mode.to_vec();
        extra.extend(["--prune", "--dry-run", "--yes"]);

        let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &extra);
        assert_eq!(code, 0, "{extra:?}: stdout={stdout}; stderr={stderr}");
        assert_eq!(
            stdout
                .lines()
                .filter(|l| l.starts_with("[dry-run] GC would prune 1 manifest entry"))
                .count(),
            1,
            "{extra:?}: the human dry run previews the GC once; stdout={stdout}"
        );
        assert_eq!(std::fs::read(&manifest).unwrap(), before, "{extra:?}");
    }
}

/// After an in-place apply over LIVE hosted wiring (a lockfile still
/// resolving the purl to the hosted patch server), the human path warns
/// that the conversion did not complete, naming the package.
#[tokio::test]
async fn scan_human_apply_over_live_hosted_wiring_warns_retained() {
    let mock = MockServer::start().await;
    let before = b"before\n";
    mount_one_patch_api(&mock, SILENT_TARGET, before).await;
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", before);
    write_live_hosted_lock(tmp.path());

    let (code, stdout, stderr) = run_scan_agent(tmp.path(), &mock.uri(), &["--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let warning = stderr
        .lines()
        .find(|l| l.starts_with("Warning: agent-mode scan left the hosted wiring live"))
        .unwrap_or_else(|| panic!("the retained-wiring warning must reach stderr; got {stderr:?}"));
    assert!(
        warning.contains(SILENT_TARGET),
        "the warning must name the package; got {warning:?}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/silent-target/index.js")).unwrap(),
        b"after\n",
        "the in-place apply proceeds despite the warning"
    );
}

// ---------------------------------------------------------------------------
// VEX lines
// ---------------------------------------------------------------------------

/// `scan --dry-run --vex`: the embedded VEX is skipped with the same note
/// apply, vendor and hosted scan print, and no document is written.
#[tokio::test]
async fn scan_human_dry_run_vex_prints_the_shared_skip_line() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    let tmp = minimist_project(b"x\n");

    let (code, stdout, stderr) = run_scan_agent(
        tmp.path(),
        &mock.uri(),
        &["--dry-run", "--yes", "--vex", "out.vex.json"],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout
            .lines()
            .any(|l| l == "Skipping VEX generation (--dry-run: nothing was applied)."),
        "got {stdout:?}"
    );
    assert!(!tmp.path().join("out.vex.json").exists());
}

/// The human `--vex` success line names the statement count and the
/// output path. With `--vex-no-verify` the manifest is trusted, so the
/// empty-crawl early return still writes the document (no network at all).
#[test]
fn scan_human_vex_success_prints_wrote_line() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    // Manifest with one vulnerable record; nothing installed.
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "patches": {
                "pkg:npm/vuln-pkg@1.0.0": {
                    "uuid": UUID,
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {
                        "package/index.js": {
                            "beforeHash": "a".repeat(64),
                            "afterHash": "b".repeat(64),
                        }
                    },
                    "vulnerabilities": {
                        "GHSA-aaaa-bbbb-cccc": {
                            "cves": ["CVE-2024-0001"],
                            "summary": "s",
                            "severity": "high",
                            "description": "d"
                        }
                    },
                    "description": "seed",
                    "license": "MIT",
                    "tier": "free",
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let vex_path = tmp.path().join("scan.vex.json");

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &[
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-no-verify",
            "--vex-product",
            "pkg:npm/my-app@1.0.0",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let wrote = stdout
        .lines()
        .find(|l| l.starts_with("Wrote OpenVEX document with 1 statement to"))
        .unwrap_or_else(|| panic!("the human VEX success line must print; got {stdout:?}"));
    assert!(
        wrote.contains(vex_path.to_str().unwrap()),
        "the success line must name the output path; got {wrote:?}"
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vex_path).expect("VEX doc written"))
            .expect("valid OpenVEX JSON");
    assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
    assert_eq!(doc["statements"].as_array().map(|s| s.len()), Some(1));
}

// ---------------------------------------------------------------------------
// Hosted mode, layout refusals and corrupt lockfiles
// ---------------------------------------------------------------------------

/// The hosted human arm shares the table/update block with the
/// agent/vendored arms, then runs the engine without prompting (scan never
/// prompts), dry run or not.
#[tokio::test]
async fn scan_hosted_human_prints_table_updates_and_redirects() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &["CVE-2024-0001"], false).await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    mount_forbidden_reference(&mock, MINIMIST).await;
    let tmp = minimist_project(b"x\n");
    // The lock pins an OLDER hosted patch: the shared update detection must
    // flag the newer offer in hosted mode too.
    seed_hosted_pin(tmp.path(), MINIMIST, OLD_UUID);

    // v5: a bare scan is hosted.
    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.contains("VULNERABILITIES") && stdout.contains("CVE-2024-0001"),
        "the results table must print in hosted mode; got {stdout:?}"
    );
    assert!(
        stdout.contains("Summary: 1 package with 1 free patch"),
        "the summary must print in hosted mode; got {stdout:?}"
    );
    assert!(
        stdout.contains("[UPDATE]"),
        "update detection must run in hosted mode; got {stdout:?}"
    );
    assert!(
        !stderr.contains("Non-interactive mode detected"),
        "scan never prompts; got {stderr:?}"
    );
    // Two reference posts: the withdrawn-pin sweep checks the pinned
    // OLD_UUID first (forbidden here, so the pin is kept), then the engine
    // resolves the offered UUID.
    let reqs = recorded(&mock).await;
    assert_eq!(
        reference_posts(&reqs),
        2,
        "the withdrawn sweep and the engine each resolved a reference"
    );
    let reference_bodies: Vec<String> = reqs
        .iter()
        .filter(|r| format!("{}", r.method) == "POST" && r.url.path().ends_with("/patches/package"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert!(
        reference_bodies.iter().any(|b| b.contains(OLD_UUID)),
        "the withdrawn sweep checked the pinned uuid; got {reference_bodies:?}"
    );
    assert!(
        reference_bodies.iter().any(|b| b.contains(UUID)),
        "the engine resolved the offered uuid; got {reference_bodies:?}"
    );

    // `--dry-run` previews without confirming (the engine honors it itself).
    let (code, _stdout, stderr) =
        run_scan_api(tmp.path(), &mock.uri(), &["--mode", "hosted", "--dry-run"]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        !stderr.contains("Non-interactive mode detected"),
        "a hosted dry run never prompts; got {stderr:?}"
    );
}

/// Hosted PATHs name project directories: each runs as its own scan (its
/// own discovery and redirect), under a `== <dir> ==` header.
#[tokio::test]
async fn scan_hosted_paths_run_once_per_project_directory() {
    let mock = MockServer::start().await;
    mount_batch_one(&mock, MINIMIST, UUID, "free", &[], false).await;
    mount_by_package(&mock, MINIMIST, UUID, serde_json::json!({})).await;
    mount_forbidden_reference(&mock, MINIMIST).await;

    let tmp = tempfile::tempdir().unwrap();
    for app in ["apps/a", "apps/b"] {
        let dir = tmp.path().join(app);
        std::fs::create_dir_all(&dir).unwrap();
        write_root_package_json(&dir);
        write_npm_package(&dir, "minimist", "1.2.2", b"x\n");
    }

    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &["apps/*"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    // glob rebuilds matches with the native separator (`apps\a` on Windows).
    for app in ["a", "b"] {
        let header = format!("== {} ==", Path::new("apps").join(app).display());
        assert!(stdout.contains(&header), "missing {header:?}: {stdout}");
    }
    assert_eq!(
        stdout
            .matches("Switched 0 packages to hosted patches")
            .count(),
        2,
        "{stdout}"
    );
    let reqs = recorded(&mock).await;
    assert_eq!(batch_bodies(&reqs).len(), 2, "one discovery per directory");
    assert_eq!(reference_posts(&reqs), 2, "one redirect per directory");
}

/// The PnP layout refusal rides a NON-empty human scan (polyglot repo):
/// another ecosystem's discovery does not silently bless the structurally
/// invisible npm half.
#[tokio::test]
async fn scan_human_pnp_refusal_prints_alongside_other_ecosystems() {
    let mock = MockServer::start().await;
    mount_empty_batch(&mock).await;

    let tmp = tempfile::tempdir().unwrap();
    // yarn-berry PnP shape: yarn.lock + .pnp.cjs, no node_modules.
    write_root_package_json(tmp.path());
    std::fs::write(tmp.path().join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
    std::fs::write(tmp.path().join(".pnp.cjs"), "// stub PnP loader\n").unwrap();
    // …plus one installed gem so the scan is NON-empty.
    std::fs::create_dir_all(
        tmp.path()
            .join("vendor/bundle/ruby/3.0.0/gems/rack-2.2.0/lib"),
    )
    .unwrap();

    let (code, stdout, stderr) = run_scan_api(tmp.path(), &mock.uri(), &[]);
    assert_eq!(
        code, 0,
        "refusals never flip the exit; stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains("Found 1 package ("),
        "the gem must be discovered (non-empty path); got {stderr:?}"
    );
    assert!(
        stderr
            .lines()
            .any(|l| l.starts_with("Warning: ") && l.contains("Plug'n'Play")),
        "the PnP refusal must print on the non-empty path, naming the layout; got {stderr:?}"
    );

    // The scan genuinely queried for the gem: the other ecosystem's
    // discovery ran while the npm half was refused.
    let bodies = batch_bodies(&recorded(&mock).await);
    assert_eq!(bodies.len(), 1, "one batch POST for the gem");
    assert!(
        bodies[0].contains("pkg:gem/rack@2.2.0"),
        "the batch body must carry the crawled gem purl; got {}",
        bodies[0]
    );
}

/// A corrupt `bun.lockb` is a stderr warning naming the file, exit 0, on
/// the empty default scan (where the generic "No packages found" hint
/// still prints) and on a non-empty hosted scan before the driver runs.
/// The `bun_lockb_invalid` code is pinned in `scan_failure_paths.rs`.
#[tokio::test]
async fn scan_human_invalid_bun_lockb_warns_on_stderr() {
    let mock = MockServer::start().await;
    mount_empty_batch(&mock).await;
    for installed in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        write_invalid_bun_lockb_project(tmp.path());
        let (code, stdout, stderr) = if installed {
            write_npm_package(tmp.path(), "minimist", "1.2.2", b"module.exports = 1;\n");
            run_scan_api(tmp.path(), &mock.uri(), &["--mode", "hosted"])
        } else {
            run_scan(tmp.path(), &[])
        };
        assert_eq!(
            code, 0,
            "installed={installed}: stdout={stdout}; stderr={stderr}"
        );
        assert!(
            stderr
                .lines()
                .any(|l| l.starts_with("Warning: ") && l.contains("bun.lockb")),
            "installed={installed}: the warning must name the file; got {stderr:?}"
        );
        if !installed {
            assert!(stdout.contains("No packages found"), "{stdout:?}");
        }
    }
}
