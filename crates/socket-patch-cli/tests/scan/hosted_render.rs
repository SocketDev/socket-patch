//! `scan --mode hosted`'s render suite (#1089): the human-mode (no
//! `--json`) output of `commands/scan/hosted.rs`. Behavior is asserted
//! through `--json` codes in `hosted_failure_paths.rs`; the sentence checks
//! here are the render checks, one per message family.

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::hosted_fixture::*;

/// The human twin of `wet_takeover_refuses_unrevertable_vendored_flavor_fail_closed`:
/// the takeover pre-warning loop prints the `redirect_vendored_revert_failed`
/// refusal to stderr, and the skipped list names the purl with its reason
/// under the `No patches could be switched to hosted:` headline.
#[tokio::test]
async fn human_takeover_refusal_lists_the_purl_and_the_revert_warning() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    write_vendor_state(
        tmp.path(),
        PURL,
        "33333333-3333-4333-8333-333333333333",
        "no-such-flavor",
    );
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, _stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "human refusal run exits 0; stderr=\n{stderr}");
    assert!(
        stderr.contains(&format!(
            "No patches could be switched to hosted:\n  {PURL}: its vendored state could not be \
             reverted (see the warning)"
        )),
        "the human skipped line must name purl + reason; stderr=\n{stderr}"
    );
    assert!(
        stderr
            .lines()
            .any(|l| l.starts_with("Warning: ") && l.contains("vendor --revert")),
        "the takeover pre-warning must reach human stderr; stderr=\n{stderr}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before
    );
}

/// The human twin of `hosted_lock_held_refuses_before_any_write`: a wet run
/// under a held apply lock prints the shared contention line plus the
/// `--lock-timeout` hint and exits 1.
#[tokio::test]
async fn human_lock_held_prints_the_contention_line_and_the_wait_hint() {
    use std::time::Duration;

    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    let _holder =
        socket_patch_core::patch::apply_lock::acquire(&root.join(".socket"), Duration::ZERO)
            .unwrap();

    let (code, _stdout, stderr) = scan_hosted(root, &server.uri(), &[], &[]);
    assert_eq!(code, 1, "stderr=\n{stderr}");
    assert!(
        stderr.contains("Error: Another socket-patch process is operating in this directory\n"),
        "stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("--lock-timeout"),
        "the wait hint must accompany a live holder; stderr=\n{stderr}"
    );
}

/// The human twin of `hosted_lock_io_when_a_file_squats_on_socket_dir`: the
/// shared `Error: Failed to open lock file at …` line, WITHOUT the
/// `--lock-timeout` hint (that is a live-holder remedy).
#[tokio::test]
async fn human_lock_io_prints_the_open_failure_without_the_wait_hint() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    std::fs::write(root.join(".socket"), b"not a dir").unwrap();

    let (code, _stdout, stderr) = scan_hosted(root, &server.uri(), &[], &[]);
    assert_eq!(code, 1, "stderr=\n{stderr}");
    assert!(
        stderr.contains("Error: Failed to open lock file at"),
        "stderr=\n{stderr}"
    );
    assert!(
        !stderr.contains("--lock-timeout"),
        "the wait hint belongs to a live holder only; stderr=\n{stderr}"
    );
}

/// Human `scan --mode hosted` on a project whose discovery is EMPTY returns
/// before the engine (exit 0, `No patches available…`). A malformed pre-v5
/// redirect ledger is ignored there like everywhere else in v5 scan: no
/// advisory (with or without `--silent`), never moved, no lock taken.
#[tokio::test]
async fn hosted_human_empty_discovery_ignores_a_malformed_pre_v5_ledger() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    let ledger = root.join(".socket/vendor/redirect-state.json");
    std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
    const TORN: &[u8] = b"{ torn";
    std::fs::write(&ledger, TORN).unwrap();

    for extra in [&[][..], &["--silent"][..]] {
        let (code, stdout, stderr) = scan_hosted(root, &server.uri(), extra, &[]);
        assert_eq!(
            code, 0,
            "{extra:?}: an empty discovery exits 0; stderr=\n{stderr}"
        );
        if extra.is_empty() {
            assert!(
                stdout.contains("No patches available for installed packages."),
                "{stdout}"
            );
        }
        assert!(
            !stderr.contains("malformed") && !stderr.contains("redirect ledger"),
            "{extra:?}: a pre-v5 ledger is never read; stderr=\n{stderr}"
        );
        assert_eq!(std::fs::read(&ledger).unwrap(), TORN, "left in place");
        assert!(!root
            .join(".socket/vendor/redirect-state.json.corrupt")
            .exists());
        assert!(!root.join(".socket/apply.lock").exists());
    }
}

/// A free-tier org whose every discovered hosted offer is paid-tier: the
/// human hosted arm stops with the same `No downloadable patches (paid
/// subscription required).` line the agent/vendored arms print (after the
/// table's paid nudge), exits 0, and never enters the engine — no reference
/// grant is requested and no `Redirected 0 package(s)` line is printed.
#[tokio::test]
async fn hosted_human_paid_only_discovery_stops_with_the_paid_hint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "paid",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "covgap hosted paid fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    // Neither the detail fetch nor the reference grant may be reached.
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    let lock_before = std::fs::read(root.join("package-lock.json")).unwrap();

    let (code, stdout, stderr) = scan_hosted(root, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains("No downloadable patches: every patch found requires a paid Socket plan."),
        "stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 additional patch is available with a paid Socket plan"),
        "the table's paid nudge still prints; stdout=\n{stdout}"
    );
    assert!(
        !stdout.contains("Switched"),
        "the engine is never entered; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(root.join("package-lock.json")).unwrap(),
        lock_before
    );
    assert!(!root.join(".socket").exists(), "nothing is created");
    server.verify().await;
}

/// The human twin of `live_hosted_overlap_fires_redirect_supersedes_vendored`:
/// the takeover-warning loop prints the supersedes headline naming X.
#[tokio::test]
async fn human_supersedes_warning_names_the_superseded_package() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_superseded_vendored_project(root);

    let psu = ["--patch-server-url", "http://patch.test"];
    let (code, _stdout, stderr) = scan_hosted(root, &server.uri(), &psu, &[]);
    assert_eq!(code, 0, "human overlap run exits 0; stderr=\n{stderr}");
    assert!(
        stderr.contains("Warning: Hosted wiring superseded the vendored ledger for:")
            && stderr.contains(SUPER_X_PURL),
        "the supersedes warning must reach human stderr; stderr=\n{stderr}"
    );
}

// ───────────────────────── human-output lines ─────────────────────────

/// Human `--dry-run` output: the summary uses the "would rewrite" verb, the
/// requested VEX is skipped with the explicit `--dry-run` notice (and no
/// document is written), and the pnpm trust guidance reaches stderr through
/// the pnpm warning loop.
#[tokio::test]
async fn human_dry_run_prints_would_rewrite_pnpm_guidance_and_vex_skip() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let lock_before = std::fs::read(tmp.path().join("pnpm-lock.yaml")).unwrap();

    let (code, stdout, stderr) = scan_hosted(
        tmp.path(),
        &server.uri(),
        &[
            "--dry-run",
            "--vex",
            "out.vex.json",
            "--vex-product",
            "pkg:npm/consumer@0.0.0",
        ],
        &[],
    );
    assert_eq!(
        code, 0,
        "dry-run exits 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains(
            "Would switch 1 package to hosted patches and rewrite 2 files (--dry-run: nothing was changed)."
        ),
        "the dry-run summary must use the preview verb; stdout=\n{stdout}"
    );
    assert!(
        stderr.contains("Skipping VEX generation (--dry-run: nothing was rewritten)."),
        "the requested-but-skipped VEX must be announced; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Warning: ") && stderr.contains("trustLockfile"),
        "the pnpm trust guidance must reach human stderr; stderr=\n{stderr}"
    );
    assert!(
        !tmp.path().join("out.vex.json").exists(),
        "dry-run must not write the VEX document"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("pnpm-lock.yaml")).unwrap(),
        lock_before,
        "dry-run must leave the lock byte-identical"
    );
}

/// Human `--vex` success summary: statement count, the document path, and
/// the attested-from-the-ledger caveat all reach stderr, and the document
/// itself parses with the one redirected statement — a live execution of
/// the `vex_statements Some ⇒ vex path Some` invariant.
#[tokio::test]
async fn human_vex_success_summary_names_statements_path_and_ledger_caveat() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);

    let (code, stdout, stderr) = scan_hosted(
        tmp.path(),
        &server.uri(),
        &[
            "--vex",
            "out.vex.json",
            "--vex-product",
            "pkg:npm/consumer@0.0.0",
        ],
        &[],
    );
    assert_eq!(
        code, 0,
        "scan --vex exits 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        std::fs::read_to_string(tmp.path().join("package-lock.json"))
            .unwrap()
            .contains(HOSTED_URL),
        "anchor: the wet run rewrote the lock; stdout=\n{stdout}"
    );
    assert!(
        stderr.contains("Wrote OpenVEX document with 1 statement to")
            && stderr.contains("out.vex.json"),
        "the VEX summary must name the count and the path; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains("attested from their patch records"),
        "the no-verify caveat is load-bearing; stderr=\n{stderr}"
    );
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(tmp.path().join("out.vex.json")).unwrap())
            .unwrap();
    assert_eq!(
        doc["statements"].as_array().map(Vec::len),
        Some(1),
        "the summary's count must match the document: {doc}"
    );
    assert_eq!(doc["statements"][0]["vulnerability"]["name"], GHSA);
}

/// Human Rush run: the `redirect_rush_repo_state_stale` detail reaches
/// stderr through the rush warning loop (the JSON twin is pinned in
/// in_process_redirect.rs).
#[tokio::test]
async fn human_rush_run_prints_the_repo_state_stale_warning_line() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_rush_project(tmp.path());

    let (code, stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(
        code, 0,
        "rush run exits 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        std::fs::read_to_string(tmp.path().join("common/config/rush/pnpm-lock.yaml"))
            .unwrap()
            .contains(HOSTED_URL),
        "anchor: the rush lock must be rewritten; stdout=\n{stdout}"
    );
    assert!(
        stderr.contains(
            "Warning: pnpm-lock.yaml was edited outside \
             `rush update`"
        ),
        "the rush repo-state warning must reach human stderr; stderr=\n{stderr}"
    );
}

// ───────────── human-output wording (terminal UI polish) ─────────────

/// A failed reference resolution prints one `Error: ...` line (capitalized,
/// with a retry hint) and exits 1 without touching the project.
#[tokio::test]
async fn human_reference_failure_prints_an_error_line_and_exits_1() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({ "error": "boom" })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let line = stderr
        .lines()
        .find(|l| l.contains("resolve patch references"))
        .unwrap_or_else(|| panic!("no error line; stderr=\n{stderr}"));
    assert!(
        line.starts_with("Error: Failed to resolve patch references: ")
            && line.ends_with("(nothing was changed; re-run to retry)"),
        "{line}"
    );
    assert!(!stdout.contains("Switched"), "stdout=\n{stdout}");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before
    );

    // --silent keeps the error (errors only, never nothing).
    let (code, _stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &["--silent"], &[]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("Error: Failed to resolve patch references: "),
        "stderr=\n{stderr}"
    );
}

/// A malformed pre-v5 redirect ledger no longer aborts anything: the human
/// dry run proceeds (exit 0, the preview summary) with no `Error:` line.
#[tokio::test]
async fn human_malformed_pre_v5_ledger_does_not_abort_the_run() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    std::fs::create_dir_all(tmp.path().join(".socket/vendor")).unwrap();
    std::fs::write(
        tmp.path().join(".socket/vendor/redirect-state.json"),
        "{bad",
    )
    .unwrap();

    let (code, stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &["--dry-run"], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        engine_stdout(&stdout).starts_with("Would switch "),
        "the dry run reaches the preview summary; stdout=\n{stdout}"
    );
    assert!(
        !stderr.lines().any(|l| l.starts_with("Error:")) && !stderr.contains("malformed"),
        "stderr=\n{stderr}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap(),
        b"{bad"
    );
}

/// Wet run, then an idempotent re-run: the first prints the singular
/// summary plus next steps on stdout; the second says the package is
/// already redirected instead of "Redirected 1 package(s); rewrote 0
/// file(s)", and prints no next steps. The first run's files include the
/// project `.npmrc` the npm 12 `allow-remote=all` auto-config creates, so
/// the commit line names it beside the lock.
#[tokio::test]
async fn human_rerun_says_already_redirected_and_first_run_prints_next_steps() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);

    let (code, stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "stderr=\n{stderr}");
    assert_eq!(
        engine_stdout(&stdout),
        "Switched 1 package to hosted patches; rewrote 2 files.\n\
         Next steps:\n  \
         1. Commit .npmrc and package-lock.json to keep the hosted patches.\n  \
         2. Reinstall from the updated lockfile (e.g. `npm ci`) so the installed packages pick \
         up the patched artifacts, then run `socket-patch vex` to verify the installed \
         patches.\n",
        "stderr=\n{stderr}"
    );

    let (code, stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "stderr=\n{stderr}");
    assert_eq!(
        engine_stdout(&stdout),
        "1 package is already on hosted patches; nothing to rewrite.\n",
        "stderr=\n{stderr}"
    );
    let (code, stdout, _) = scan_hosted(tmp.path(), &server.uri(), &["--dry-run"], &[]);
    assert_eq!(code, 0);
    assert_eq!(
        engine_stdout(&stdout),
        "1 package is already on hosted patches; nothing to rewrite.\n"
    );
}

/// A granted patch whose package has no lock entry is listed by purl on
/// stderr (not just hinted at by a raw rewriter warning), under a
/// `No patches could be redirected:` headline when nothing was.
#[tokio::test]
async fn human_unconfirmed_purl_is_listed_with_a_headline() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    // A lock with no entry for the installed package: nothing pins it.
    std::fs::write(
        tmp.path().join("package-lock.json"),
        r#"{ "name": "consumer", "version": "0.0.0", "lockfileVersion": 3, "requires": true,
  "packages": { "": { "name": "consumer", "version": "0.0.0" } } }
"#,
    )
    .unwrap();

    let (code, stdout, stderr) = scan_hosted(tmp.path(), &server.uri(), &["--dry-run"], &[]);
    assert_eq!(code, 0, "a no-op redirect still exits 0; stderr=\n{stderr}");
    assert!(
        engine_stdout(&stdout).starts_with("Would switch "),
        "stdout=\n{stdout}"
    );
    assert!(
        stderr.contains(&format!(
            "No patches could be switched to hosted:\n  {PURL}: no lockfile entry pinning it \
             could be rewritten"
        )),
        "stderr=\n{stderr}"
    );
}

/// The pnpm trust guidance across runs. The first wet run prints the full
/// guidance (a headline plus `  - ` bullets); an idempotent re-run that
/// changed nothing pnpm-related prints exactly the one-line reminder on
/// stderr while `--json` still carries the full detail; and deleting
/// pnpm-workspace.yaml (the heal path re-creates it) brings the full
/// guidance back.
#[tokio::test]
async fn human_pnpm_rerun_prints_only_the_reminder_and_heal_restores_guidance() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_pnpm_project(root);
    const REMINDER: &str = "Warning: pnpm-lock.yaml already uses \
        hosted patches and pnpm-workspace.yaml already sets `trustLockfile: true`; keep both \
        committed, and never rebuild the lockfile (`pnpm clean --lockfile`), which discards \
        the hosted patches\n";

    let (code, stdout, stderr) = scan_hosted(root, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        engine_stdout(&stdout)
            .starts_with("Switched 1 package to hosted patches; rewrote 2 files.\n"),
        "{stdout}"
    );
    // Everything from the pnpm warning on (the lines above it are the
    // token-format notice and discovery progress).
    let pnpm_part = |stderr: &str| -> String {
        stderr
            .find("Warning: pnpm-lock.yaml")
            .map(|i| stderr[i..].to_string())
            .unwrap_or_default()
    };
    assert!(
        pnpm_part(&stderr).contains("\n  - ") && pnpm_part(&stderr) != REMINDER,
        "the first run prints the full guidance; stderr=\n{stderr}"
    );
    assert!(root.join("pnpm-workspace.yaml").is_file());

    let (code, stdout, stderr) = scan_hosted(root, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert_eq!(
        engine_stdout(&stdout),
        "1 package is already on hosted patches; nothing to rewrite.\n"
    );
    assert_eq!(
        pnpm_part(&stderr),
        REMINDER,
        "a no-op re-run prints only the reminder; stderr=\n{stderr}"
    );

    let (code, doc) = scan_hosted_json(root, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    let detail = warning_detail(&doc, "redirect_pnpm_trust_lockfile");
    assert!(
        detail.contains("trustLockfile: true") && detail.contains("--store-dir"),
        "--json keeps the full guidance on a re-run: {detail}"
    );

    std::fs::remove_file(root.join("pnpm-workspace.yaml")).unwrap();
    let (code, stdout, stderr) = scan_hosted(root, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        root.join("pnpm-workspace.yaml").is_file(),
        "the heal re-creates it"
    );
    assert!(
        pnpm_part(&stderr).contains("\n  - ") && pnpm_part(&stderr) != REMINDER,
        "the heal run prints the full guidance again; stderr=\n{stderr}"
    );
}
