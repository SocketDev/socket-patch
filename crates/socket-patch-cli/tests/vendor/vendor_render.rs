//! `vendor`'s render suite (#1089): the human-mode (no `--json`, no
//! `--silent`) output of `commands/vendor.rs`. Behavior is asserted
//! through `--json` codes in `vendor_failure_paths.rs`; the sentence
//! checks here are the render checks, one per message family.

use std::process::Command;

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::hermetic;
use crate::npm_fixture::*;
use crate::prebuilt_common;
use crate::vlt_vendored;

// ─────────────────────────────────────────────────────────────────────
// 1. human-mode output surface (no --json, no --silent)
// ─────────────────────────────────────────────────────────────────────

/// Human happy path: the summary line, the committables hint, and the
/// npm reinstall hint (package-lock flavor).
#[test]
fn human_vendor_prints_summary_committables_and_reinstall_hint() {
    let fx = npm_fixture();
    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Vendored 1 package."),
        "summary line: {stdout}"
    );
    assert!(
        stdout.contains("Commit .socket/vendor/ and the updated lockfiles"),
        "committables hint: {stdout}"
    );
    assert!(
        stdout.contains("Run `npm install`"),
        "package-lock reinstall hint: {stdout}"
    );
}

/// An npm-only run never opens the project's composer.lock for the
/// Composer reinstall hint: a FIFO planted there would block the open(2)
/// after the lock and ledger are written, and a lock naming vendored
/// composer copies this run did not wire gets no composer hint.
#[cfg(unix)]
#[test]
fn npm_only_human_vendor_does_not_read_composer_lock() {
    use std::time::{Duration, Instant};
    let fx = npm_fixture();
    let fifo = fx.root().join("composer.lock");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let fixture = prebuilt_common::Server::project(fx.root());
    let mut child = hermetic::binary_command()
        .env("SOCKET_VENDOR_URL", &fixture.uri)
        .args(["vendor", "--cwd", fx.root().to_str().unwrap()])
        .current_dir(fx.root())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn socket-patch binary");
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(60) {
            let _ = child.kill();
            panic!("vendor blocked opening the composer.lock FIFO");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    assert!(stdout.contains("Vendored 1 package."), "{stdout}");

    let fx = npm_fixture();
    std::fs::write(
        fx.root().join("composer.lock"),
        json!({"packages": [{"name": "psr/log", "version": "3.0.2", "dist": {
            "type": "path",
            "url": format!(".socket/vendor/composer/{UUID}/psr/log@3.0.2"),
            "reference": UUID}}]})
        .to_string(),
    )
    .unwrap();
    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("Run `npm install`"), "{stdout}");
    assert!(!stdout.contains("composer install"), "{stdout}");
}

/// Human `--dry-run`: the `Would vendor` verb and NO commit/reinstall
/// hints (nothing was written). A dry-run success is translated to a
/// `Verified` event (counted under `summary.verified`, not `applied`); the
/// human line counts it as a would-vendor package, and the JSON
/// cross-check below anchors where the package actually lands.
#[test]
fn human_dry_run_prints_would_vendor_and_no_commit_hints() {
    let fx = npm_fixture();
    let (code, stdout, stderr) = human_vendor(&fx, &["--dry-run"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Would vendor 1 package."),
        "dry-run verb, counting the Verified preview event: {stdout}"
    );
    let (json_code, env) = vendor_cli(fx.root(), &["--dry-run"]);
    assert_eq!(json_code, 0, "{env:#}");
    assert_eq!(
        env["summary"]["verified"], 1,
        "the dry-run success is counted as verified: {env:#}"
    );
    assert!(
        !stdout.contains("Commit .socket/vendor/"),
        "a dry run has nothing to commit: {stdout}"
    );
    assert!(
        !stdout.contains("Run `"),
        "a dry run needs no reinstall: {stdout}"
    );
    assert!(!fx.vendor_dir().exists(), "dry run writes nothing");
}

/// Human not-installed skip: the `Cannot vendor …` stderr line with the
/// on-disk cause, while the installed package still vendors (and the
/// summary counts both honestly).
#[test]
fn human_not_installed_prints_cannot_vendor_to_stderr() {
    let fx = npm_fixture_with_purls(&[PURL, "pkg:npm/right-pad@9.9.9"]);
    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Cannot vendor"),
        "stderr names the skip: {stderr}"
    );
    assert!(
        stderr.contains("lock"),
        "stderr carries the on-disk cause: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 1 package; 1 failed."),
        "summary counts the skip: {stdout}"
    );
}

/// Human `--revert` summary after a completed revert.
#[tokio::test]
async fn human_revert_prints_reverted_summary() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Reverted 1 vendored package."),
        "revert summary: {stdout}"
    );
    assert!(
        !stdout.contains("Kept"),
        "nothing drifted, so no drift explainer: {stdout}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
}

/// Human `--revert` over a drifted lock: no `Reverted …` line, only the
/// `Kept 1 drifted package` explainer (counts come from the drift-skip
/// keep, not advisory warnings).
#[tokio::test]
async fn human_revert_drift_keep_prints_kept_explainer() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    // Third-party drift: neither ours nor the recorded pre-vendor original.
    let mut drifted: Value = serde_json::from_slice(&fx.lock_bytes()).unwrap();
    drifted["packages"]["node_modules/left-pad"]["resolved"] =
        Value::String("https://example.com/their-fork.tgz".to_string());
    let mut drifted_lock = serde_json::to_vec_pretty(&drifted).unwrap();
    drifted_lock.push(b'\n');
    std::fs::write(fx.lock_path(), &drifted_lock).unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 0, "a drift keep is not an error:\n{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Reverted"),
        "nothing reverted, so no package line: {stdout}"
    );
    assert!(
        stdout.contains("Kept 1 drifted package:"),
        "the drift-keep explainer: {stdout}"
    );
    assert!(fx.tgz_path().is_file(), "kept artifacts survive");
    assert_eq!(fx.lock_bytes(), drifted_lock, "drifted lock left alone");
}

/// Human `--revert` with a `.socket/` present but an empty ledger: the
/// calm no-op line (complements the no-`.socket`-dir no-op pinned in
/// in_process_vendor.rs).
#[test]
fn human_revert_empty_ledger_prints_nothing_to_revert() {
    let fx = npm_fixture();
    assert!(!fx.state_path().exists(), "fixture starts unvendored");

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Nothing vendored to revert."),
        "the empty-ledger no-op line: {stdout}"
    );
}

/// Human plain vendor with no manifest at all: the clean no-op message,
/// exit 0 (same contract as apply). The line names the MANIFEST — the
/// fixture's `.socket/` (blobs) very much exists, as it does on every
/// hosted-only or vendored-mode project.
#[test]
fn human_missing_manifest_prints_nothing_to_vendor() {
    let fx = npm_fixture();
    std::fs::remove_file(fx.manifest_path()).unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("No manifest found, nothing to vendor."),
        "the no-manifest no-op line: {stdout}"
    );
    assert!(
        !stdout.contains(".socket folder"),
        "never claims .socket/ is missing: {stdout}"
    );
    assert!(!fx.vendor_dir().exists(), "nothing written");
    assert!(
        !fx.root().join(".socket/apply.lock").exists(),
        "the no-op path takes no lock"
    );
}

/// Human plain vendor on a LEDGER-tracked project with no manifest — the
/// shape every `scan`/`get --mode vendored` project has (`.socket/vendor/`
/// exists, `.socket/manifest.json` does not): still the clean exit-0
/// no-op (nothing locked, reverted or written), but the line says what IS
/// vendored and points at `repair` instead of implying nothing is set up.
#[tokio::test]
async fn human_missing_manifest_with_ledger_names_the_tracked_entries() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    std::fs::remove_file(fx.manifest_path()).unwrap();
    let wired_lock = fx.lock_bytes();
    let state_before = std::fs::read(fx.state_path()).unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("No manifest to vendor from; 1 vendored entry is tracked in the ledger"),
        "the ledger-aware no-op line: {stdout}"
    );
    assert!(
        stdout.contains("`socket-patch repair`"),
        "points at repair as the verification path: {stdout}"
    );
    assert!(!stdout.contains(".socket folder"), "{stdout}");
    assert!(fx.tgz_path().is_file(), "no-op: the artifact survives");
    assert_eq!(
        fx.lock_bytes(),
        wired_lock,
        "no-op: the wiring is untouched"
    );
    assert_eq!(
        std::fs::read(fx.state_path()).unwrap(),
        state_before,
        "no-op: the ledger is untouched"
    );
    assert!(
        !fx.root().join(".socket/apply.lock").exists(),
        "the no-op path takes no lock"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 2. pnpm committables hint (pnpm >=11 workspace-file portability)
// ─────────────────────────────────────────────────────────────────────

/// A pnpm project (lockfileVersion 9.0): package.json + pnpm-lock.yaml +
/// installed node_modules/left-pad + the same staged `.socket` blob as the
/// npm fixture. The lock grammar mirrors core's pnpm_lock spike fixtures.
fn pnpm_fixture() -> NpmFixture {
    let fx = npm_fixture();
    std::fs::remove_file(fx.lock_path()).unwrap();
    let lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}

snapshots:

  left-pad@1.3.0: {}
";
    std::fs::write(fx.root().join("pnpm-lock.yaml"), lock).unwrap();
    fx
}

/// pnpm-wired human run: the committables line must name
/// pnpm-workspace.yaml (pnpm >=11 reads overrides only from there — losing
/// it silently unvendors on the next install) and the reinstall hint must
/// say `pnpm install`.
#[test]
fn human_pnpm_vendor_names_workspace_committable_and_pnpm_install() {
    let fx = pnpm_fixture();
    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("pnpm-workspace.yaml"),
        "the pnpm committables line names the workspace file: {stdout}"
    );
    assert!(
        stdout.contains("pnpm >=11"),
        "…and says why (pnpm >=11 override source): {stdout}"
    );
    assert!(
        stdout.contains("Run `pnpm install`"),
        "the pnpm reinstall hint: {stdout}"
    );
    assert!(
        !stdout.contains("Run `npm install`"),
        "only the wired flavor's install is suggested: {stdout}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3. human-mode error/refusal stderr surfaces (no --json, no --silent)
//
// Section 1 covered the human happy paths; every test here pins one of
// the human-only eprintln lines that ride beside a JSON contract
// `vendor_failure_paths.rs` pins (same fixture shapes, human runner).
// ─────────────────────────────────────────────────────────────────────

/// Human corrupt-manifest surface: the `Error: could not read manifest`
/// stderr line beside the `manifest_invalid` exit contract `vendor_failure_paths.rs` pins
/// under --json.
#[test]
fn human_corrupt_manifest_prints_could_not_read() {
    let fx = npm_fixture();
    std::fs::write(fx.manifest_path(), b"{broken").unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Error: Could not read manifest:"),
        "the human explanation for the flipped exit code: {stderr}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}

/// Human corrupt-committed-artifact surface (fresh clone, ledger sha
/// mismatch): the `Cannot vendor …` stderr line still carries the
/// `socket-patch repair` remedy.
#[tokio::test]
async fn human_corrupt_committed_artifact_prints_repair_hint() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    std::fs::remove_dir_all(fx.root().join("node_modules")).unwrap();
    std::fs::write(fx.tgz_path(), b"corrupt bytes").unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &["--offline"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("pkg:npm/left-pad@1.3.0"),
        "stderr names the purl: {stderr}"
    );
    assert!(
        stderr.contains("offline"),
        "the human line must carry the repair remedy: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 0 packages; 1 failed."),
        "the summary counts the failure: {stdout}"
    );
}

/// Human registry-fetch-failure surface: a lockfile-resolved missing
/// package whose registry serves a 500 prints the
/// `Cannot vendor …: fetch failed: …` stderr line (the human twin of the
/// `vendor_fetch_failed` event scan_vendor_e2e pins under --json).
#[tokio::test]
async fn human_fetch_failure_prints_fetch_failed() {
    let fx = npm_fixture();
    std::fs::remove_dir_all(fx.root().join("node_modules")).unwrap();
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    // Re-point the lock at the mock registry with a VALID SRI: the ladder
    // reaches the download (an SRI-less entry would stop at Unverifiable)
    // and the 500 lands in `PristineFetch::Failed`.
    let mut lock: Value = serde_json::from_slice(&fx.lock_bytes()).unwrap();
    lock["packages"]["node_modules/left-pad"]["resolved"] =
        Value::String(format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri()));
    lock["packages"]["node_modules/left-pad"]["integrity"] =
        Value::String(sri_of(b"pristine bytes the mock never serves"));
    std::fs::write(fx.lock_path(), serde_json::to_vec_pretty(&lock).unwrap()).unwrap();

    // Non-offline (the fetch must actually run), anonymous (no other
    // network path opens), human mode (no --json).
    let (code, stdout, stderr) = run_cli(
        fx.root(),
        &[
            "vendor",
            "--vendor-url",
            &mock.uri(),
            "--cwd",
            fx.root().to_str().unwrap(),
        ],
        &[("SOCKET_NO_API_TOKEN", "1")],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("pkg:npm/left-pad@1.3.0") && stderr.contains("request"),
        "the human fetch-failure line: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 0 packages; 1 failed."),
        "a fetch failure is counted as failed, not skipped: {stdout}"
    );
    assert!(
        !fx.vendor_dir().exists(),
        "nothing may be vendored from a failed fetch"
    );
}

/// Human unrestorable-hosted-pin surface: an offline run over a hosted pin
/// prints the `Cannot vendor …: cannot restore the upstream entry` line and
/// counts the refusal.
#[test]
fn human_unrestorable_hosted_pin_prints_cannot_restore() {
    let fx = npm_fixture();
    let hosted_lock = pin_hosted(&fx);

    let (code, stdout, stderr) =
        human_vendor(&fx, &["--offline", "--patch-server-url", HOSTED_ORIGIN]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Cannot vendor pkg:npm/left-pad@1.3.0:")
            && stderr.contains("cannot restore the upstream entry"),
        "the human takeover-refusal line: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 0 packages; 1 failed."),
        "the fail-closed refusal is counted: {stdout}"
    );
    assert_eq!(fx.lock_bytes(), hosted_lock, "lock untouched");
}
/// Human backend-refusal surface: an installed package with NO lockfile of
/// any flavor is a non-benign `vendor_lockfile_missing` refusal — the
/// `Cannot vendor …` stderr line carries the backend's remedy.
#[test]
fn human_lockfile_missing_refusal_prints_cannot_vendor() {
    let fx = npm_fixture();
    std::fs::remove_file(fx.lock_path()).unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Cannot vendor pkg:npm/left-pad@1.3.0:")
            && stderr.contains("vendoring rewires the lockfile"),
        "the refusal detail surfaces verbatim: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 0 packages; 1 failed."),
        "a non-benign refusal is counted as failed: {stdout}"
    );
}

/// Human corrupt-ledger `--revert` surface: the
/// `Error: Could not read the vendor ledger` stderr line beside
/// the `vendor_state_unreadable` exit contract `vendor_failure_paths.rs` pins under --json.
#[test]
fn human_corrupt_state_revert_prints_could_not_read() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    std::fs::write(fx.state_path(), b"not json{").unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Error: Could not read the vendor ledger"),
        "the human explanation for the flipped exit code: {stderr}"
    );
}

/// Human `--revert` failure surface: a ledger entry with no revert backend
/// prints the `Failed to revert <purl>` stderr line, and the summary
/// counts it.
#[tokio::test]
async fn human_revert_failure_prints_failed_to_revert() {
    let fx = npm_fixture();
    write_ledger_entry(fx.root(), "frobnicate").await;

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Failed to revert pkg:npm/left-pad@1.3.0"),
        "stderr names the failed purl: {stderr}"
    );
    assert!(
        stdout.contains("Reverted 0 vendored packages; 1 failed."),
        "the summary counts the failure: {stdout}"
    );
}

/// Human `--revert --dry-run`: the `Would revert` verb, and NOTHING is
/// mutated — the ledger keeps its entry, the wired lock and the artifact
/// stay exactly as vendored.
#[tokio::test]
async fn human_revert_dry_run_prints_would_revert_and_mutates_nothing() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    let state_before = std::fs::read(fx.state_path()).unwrap();
    let wired_lock = fx.lock_bytes();

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert", "--dry-run"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Would revert 1 vendored package."),
        "the dry-run verb and count: {stdout}"
    );
    assert_eq!(
        std::fs::read(fx.state_path()).unwrap(),
        state_before,
        "a dry revert must not touch the ledger"
    );
    assert_eq!(
        fx.lock_bytes(),
        wired_lock,
        "a dry revert must not touch the wired lock"
    );
    assert!(fx.tgz_path().is_file(), "a dry revert keeps the artifact");
}

/// Human `--dry-run --vex`: the VEX skip line — a dry run vendors nothing,
/// so generating (and verifying the untouched tree) would spuriously fail;
/// the file must NOT be written.
#[test]
fn human_dry_run_with_vex_prints_skip_and_writes_no_vex() {
    let fx = npm_fixture();
    let vex_path = fx.root().join("attestation.vex.json");

    let (code, stdout, stderr) =
        human_vendor(&fx, &["--dry-run", "--vex", vex_path.to_str().unwrap()]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Skipping VEX generation (--dry-run: nothing was vendored)."),
        "the human VEX-skip explanation: {stdout}"
    );
    assert!(
        !vex_path.exists(),
        "no attestation may be written during --dry-run"
    );
}

/// Human run-level classic→berry migration advisory: a classic `yarn.lock`
/// carrying vendored wiring (and no yarn@1 corepack pin) warns on stderr at
/// envelope-finalize time — pinned through the `--revert` no-op path, which
/// exercises the state-based probe without any vendoring in the run itself.
#[test]
fn human_classic_migration_risk_prints_stderr_warning() {
    let fx = npm_fixture();
    std::fs::write(
        fx.root().join("yarn.lock"),
        "# yarn lockfile v1\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n  \
         resolved \"file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz\"\n",
    )
    .unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Nothing vendored to revert."),
        "the revert itself is the calm no-op: {stdout}"
    );
    assert!(
        stderr.contains("Warning: yarn.lock is yarn-classic"),
        "the run-level advisory prints for humans: {stderr}"
    );
}

/// The vlt twin of the pnpm committables line: a vlt-wired run names
/// package.json (and workspace package.json files), vlt-lock.json and
/// `.socket/vendor/`, points CI at `vlt ci`, and names `vlt install` as
/// the reinstall; `vendor --revert` names `vlt install` too.
#[test]
fn human_vlt_vendor_names_vlt_committables_and_vlt_install() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vlt_vendored::write_project(root);
    vlt_vendored::seed_manifest(root);
    let cwd = root.to_str().unwrap();
    let (code, stdout, stderr) = run_cli(root, &["vendor", "--cwd", cwd], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains(
            "Commit package.json (and workspace package.json files), vlt-lock.json and \
             .socket/vendor/ (the .gitignore there re-includes the payload and keeps vlt's \
             node_modules links out of git); CI: `vlt ci`."
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains("Run `vlt install` to update the installed tree"),
        "{stdout}"
    );
    let (code, stdout, stderr) = run_cli(root, &["vendor", "--revert", "--cwd", cwd], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("Run `vlt install` to resync"), "{stdout}");
}
