//! Coverage-gap tests for `commands/apply.rs` (2026-09 audit).
//!
//! The uncovered surface of apply.rs is dominated by HUMAN-mode output —
//! nearly every existing apply test passes `--json` and/or `--silent` — plus
//! two never-fired go-drift variants, the whole Bun layout arm, the
//! `--check --json` envelopes, and the mismatch-blob prefetch messages.
//! Themes:
//!
//!   1. `apply --check --json`: the in-sync success envelope and the
//!      machine-readable drift envelope (`go_redirect_drift` Failed events);
//!   2. the `WrongReplacePath` and `OrphanReplace` go-drift variants
//!      (hand-built `go.mod` fixtures — the other variants are covered);
//!   3. `reconcile_local_go`'s human report (`Removed` / `Would remove`
//!      N stale go patch redirect(s));
//!   4. mismatch-blob prefetch messages: the `--offline` warning, the
//!      "Downloading N full patched blob(s)" line, and the broken-TMPDIR
//!      transient-stage failure warning;
//!   5. human-mode output block: "No patches to apply.", the no-matching-
//!      packages warning, the npm per-package failure line, the dry-run
//!      "already patched" count, `--verbose` per-file labels, the pnpm/bun
//!      layout notes, and the corrupt-manifest-under-PnP fall-through;
//!   6. gem fallback-home skip surfacing on human stderr;
//!   7. apply-loop wiring: a vendored release-variant base with its
//!      installed tree PRESENT is skipped (not re-patched), and a qualified
//!      singleton whose record holds only NEW files (no representative)
//!      is treated as installed and applied.
//!
//! Binary-driven throughout (`common::run_with_env`, `SOCKET_*`-scrubbed
//! children), hand-written camelCase manifests, git-sha256 oracle,
//! `--offline` wherever the network is not the subject under test.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

use common::{git_sha256, parse_json_envelope, run_with_env};

// ───────────────────────── shared fixture helpers ─────────────────────────

/// Run `socket-patch apply <args>` in `cwd` with the ambient `SOCKET_*`
/// environment scrubbed (see `common::run_with_env`), telemetry disabled,
/// and `extra_env` landing last (so tests can inject API URLs / TMPDIR).
fn run_apply(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
    let mut argv: Vec<&str> = vec!["apply"];
    argv.extend_from_slice(args);
    let mut env: Vec<(&str, &str)> = vec![("SOCKET_TELEMETRY_DISABLED", "1")];
    env.extend_from_slice(extra_env);
    run_with_env(cwd, &argv, &env)
}

/// One camelCase manifest record (the TS-compatible on-disk schema).
fn patch_record(uuid: &str, files: Value) -> Value {
    json!({
        "uuid": uuid,
        "exportedAt": "2024-01-01T00:00:00Z",
        "files": files,
        "vulnerabilities": {},
        "description": "covgap apply fixture",
        "license": "MIT",
        "tier": "free"
    })
}

/// Write `.socket/manifest.json` (creating `.socket/blobs/` alongside so
/// blob-emptiness assertions have a stable target).
fn write_manifest(root: &Path, patches: Value) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).expect("create .socket/blobs");
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).unwrap(),
    )
    .expect("write manifest");
}

fn stage_blob(root: &Path, hash: &str, content: &[u8]) {
    let blobs = root.join(".socket").join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(hash), content).expect("stage blob");
}

/// Install a fake npm package at `<root>/node_modules/<name>` with the
/// given `index.js` bytes; returns the index.js path.
fn install_npm_pkg(root: &Path, name: &str, version: &str, index_js: &[u8]) -> PathBuf {
    let pkg_dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).expect("create pkg dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .expect("write package.json");
    let index = pkg_dir.join("index.js");
    std::fs::write(&index, index_js).expect("write index.js");
    index
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-apply-root", "version": "0.0.0" }"#,
    )
    .expect("write root package.json");
}

/// Synthesize an installed gem under the cwd's vendor/bundle tree (the
/// layout the ruby crawler scans in local mode — same shape as
/// `cli_gem_variant_mismatch_policy.rs`). Returns the patchable file path.
fn install_gem(root: &Path, leaf: &str, file_rel: &str, contents: &[u8]) -> PathBuf {
    let gem_dir = root
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.4.0")
        .join("gems")
        .join(leaf);
    let file = gem_dir.join(file_rel);
    std::fs::create_dir_all(file.parent().unwrap()).expect("create gem dir");
    std::fs::write(&file, contents).expect("write gem file");
    file
}

/// Write a cached `.socket/diffs/<uuid>.tar.gz` whose mere existence makes
/// the stage step conclude nothing needs downloading (default
/// `--download-mode diff`) — its content is never consulted for a
/// mismatched file, which can only take the full blob.
fn write_diff_archive(root: &Path, uuid: &str) {
    use std::io::Write as _;
    let diffs = root.join(".socket").join("diffs");
    std::fs::create_dir_all(&diffs).unwrap();
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        std::fs::File::create(diffs.join(format!("{uuid}.tar.gz"))).unwrap(),
        flate2::Compression::default(),
    ));
    let mut header = tar::Header::new_gnu();
    let bytes = b"unrelated";
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "other.js", &bytes[..])
        .unwrap();
    builder
        .into_inner()
        .unwrap()
        .finish()
        .unwrap()
        .flush()
        .unwrap();
}

// ═══════════════════ 1. `--check --json` envelopes ═══════════════════

const GO_PURL: &str = "pkg:golang/example.com/mod@v1.0.0";

/// Valid manifest with one golang patch and NO committed copy / `go.mod` —
/// `--check` reports MissingCopy + MissingReplace drift (the
/// `cli_apply_silent.rs::write_drifted_go_manifest` shape).
fn write_drifted_go_manifest(root: &Path) {
    write_manifest(
        root,
        json!({
            GO_PURL: patch_record(
                "60606060-6060-4060-8060-606060606060",
                json!({ "file.go": {
                    "beforeHash": "a".repeat(64),
                    "afterHash": "b".repeat(64),
                }}),
            )
        }),
    );
}

/// `apply --check --json` WITH drift: the machine-readable envelope carries
/// one Failed event per drift with `errorCode: go_redirect_drift`, status
/// `partialFailure`, exit 1. (Every prior drift run was human/silent —
/// the envelope had never been serialized.)
#[test]
fn check_json_with_drift_emits_failed_events_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    write_drifted_go_manifest(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--check", "--json"], &[]);
    assert_eq!(code, 1, "drift must exit 1; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(env["command"], "apply", "envelope: {env}");
    assert_eq!(env["status"], "partialFailure", "envelope: {env}");
    let events = env["events"].as_array().expect("events array");
    assert!(
        !events.is_empty(),
        "drift must be reported as events: {env}"
    );
    for e in events {
        assert_eq!(e["action"], "failed", "envelope: {env}");
        assert_eq!(e["errorCode"], "go_redirect_drift", "envelope: {env}");
        assert_eq!(e["purl"], GO_PURL, "envelope: {env}");
    }
}

/// `apply --check --json` with NO drift: the in-sync success envelope
/// (a single JSON object, status success, exit 0) — never serialized by
/// any prior test.
#[test]
fn check_json_in_sync_emits_success_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--check", "--json"], &[]);
    assert_eq!(code, 0, "in-sync check must exit 0; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(env["command"], "apply", "envelope: {env}");
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert!(
        env["events"].as_array().map_or(true, |e| e.is_empty()),
        "an in-sync check reports no drift events: {env}"
    );
}

// ══════════════ 2. WrongReplacePath / OrphanReplace drift ══════════════

/// `--check` with a socket-owned `replace` for a module the manifest no
/// longer patches: the `OrphanReplace` drift variant (never fired before).
/// Its drift-id extraction routes through the module (not a purl).
#[test]
fn check_reports_orphan_replace_drift() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));
    std::fs::write(
        tmp.path().join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\n\
         replace example.com/other v1.2.3 => ./.socket/go-patches/example.com/other@v1.2.3\n",
    )
    .unwrap();

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--check"], &[]);
    assert_eq!(code, 1, "an orphan replace is drift; stderr={stderr}");
    assert!(
        stderr.contains("OUT OF SYNC"),
        "drift must print the out-of-sync report; stderr={stderr}"
    );
    assert!(
        stderr.contains("orphan go.mod `replace` for `example.com/other`"),
        "the OrphanReplace detail must name the module; stderr={stderr}"
    );
}

/// `--check` with a healthy copy but a socket-owned `replace` pinned at the
/// WRONG target path: the `WrongReplacePath` drift variant (never fired
/// before). The copy hashes clean, so this drift is the only finding —
/// pinning that a silently-ignored directive (go keys `replace` by
/// module+version+path) is caught even when the copy checks pass.
#[test]
fn check_reports_wrong_replace_path_drift() {
    let patched = b"patched go content\n";
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(
        tmp.path(),
        json!({
            GO_PURL: patch_record(
                "61616161-6161-4161-8161-616161616161",
                json!({ "file.go": {
                    "beforeHash": git_sha256(b"original go content\n"),
                    "afterHash": git_sha256(patched),
                }}),
            )
        }),
    );
    // Committed copy whose file hashes exactly to afterHash — no
    // MissingCopy/StaleCopy noise.
    let copy_dir = tmp
        .path()
        .join(".socket/go-patches/example.com/mod@v1.0.0");
    std::fs::create_dir_all(&copy_dir).unwrap();
    std::fs::write(copy_dir.join("file.go"), patched).unwrap();
    // Socket-owned directive (target under .socket/go-patches/) pointing at
    // the WRONG version's copy.
    std::fs::write(
        tmp.path().join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\n\
         replace example.com/mod v1.0.0 => ./.socket/go-patches/example.com/mod@v0.0.9\n",
    )
    .unwrap();

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--check"], &[]);
    assert_eq!(code, 1, "a mispointed replace is drift; stderr={stderr}");
    assert!(
        stderr.contains("points at ./.socket/go-patches/example.com/mod@v0.0.9"),
        "the WrongReplacePath detail must name the found target; stderr={stderr}"
    );
    assert!(
        stderr.contains("should be ./.socket/go-patches/example.com/mod@v1.0.0"),
        "the WrongReplacePath detail must name the expected target; stderr={stderr}"
    );
    // Fixture sharpness: the copy validated, so the ONLY drift is the
    // directive — a fixture regression that broke the copy would show up
    // as extra findings here.
    assert!(
        !stderr.contains("missing patched copy") && !stderr.contains("stale copy"),
        "the copy must verify clean (WrongReplacePath must be the only drift); stderr={stderr}"
    );
}

// ═══════════ 3. reconcile_local_go human report (Removed / Would remove) ═══════════

/// Stale-redirect fixture: a socket-owned `replace` + committed copy for a
/// module the (empty) manifest no longer patches.
fn write_stale_go_redirect(root: &Path) -> String {
    write_manifest(root, json!({}));
    let go_mod = "module example.com/app\n\ngo 1.21\n\n\
                  replace example.com/mod v1.0.0 => ./.socket/go-patches/example.com/mod@v1.0.0\n";
    std::fs::write(root.join("go.mod"), go_mod).unwrap();
    let copy_dir = root.join(".socket/go-patches/example.com/mod@v1.0.0");
    std::fs::create_dir_all(&copy_dir).unwrap();
    std::fs::write(copy_dir.join("file.go"), b"patched\n").unwrap();
    go_mod.to_string()
}

/// A wet human-mode apply prunes the orphaned redirect and ANNOUNCES it —
/// "Removed 1 stale go patch redirect(s):" plus the purl — before the
/// clean-no-op "No patches to apply." exit.
#[test]
fn reconcile_announces_removed_stale_go_redirect_in_human_mode() {
    let tmp = tempfile::tempdir().unwrap();
    write_stale_go_redirect(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "pruning an orphan is a clean no-op; stderr={stderr}");
    assert!(
        stdout.contains("Removed 1 stale go patch redirect(s):"),
        "the removal must be announced; stdout={stdout}"
    );
    assert!(
        stdout.contains(GO_PURL),
        "the announcement must name the pruned purl; stdout={stdout}"
    );
    let go_mod = std::fs::read_to_string(tmp.path().join("go.mod")).unwrap();
    assert!(
        !go_mod.contains("replace"),
        "the orphaned directive must actually be dropped; go.mod={go_mod}"
    );
    assert!(
        !tmp.path()
            .join(".socket/go-patches/example.com/mod@v1.0.0")
            .exists(),
        "the orphaned copy dir must be pruned"
    );
}

/// `--dry-run` uses the "Would remove" verb and mutates NOTHING: `go.mod`
/// stays byte-identical and the copy dir survives.
#[test]
fn reconcile_dry_run_says_would_remove_and_touches_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let original_go_mod = write_stale_go_redirect(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--dry-run"], &[]);
    assert_eq!(code, 0, "dry-run reconcile is a clean no-op; stderr={stderr}");
    assert!(
        stdout.contains("Would remove 1 stale go patch redirect(s):"),
        "dry-run must use the conditional verb; stdout={stdout}"
    );
    assert!(stdout.contains(GO_PURL), "stdout={stdout}");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("go.mod")).unwrap(),
        original_go_mod,
        "dry-run must leave go.mod byte-identical"
    );
    assert!(
        tmp.path()
            .join(".socket/go-patches/example.com/mod@v1.0.0")
            .exists(),
        "dry-run must keep the copy dir"
    );
}

// ═══════════ 4. mismatch-blob prefetch messages ═══════════

const MM_BEFORE: &[u8] = b"pristine content\n";
const MM_AFTER: &[u8] = b"patched content\n";
const MM_LOCAL: &[u8] = b"locally modified content\n";
const MM_UUID: &str = "62626262-6262-4262-8262-626262626262";

/// npm package whose only patched file matches NEITHER hash, a cached diff
/// archive (so staging succeeds with direct `.socket/` paths), and an
/// EMPTY blobs dir — the shape that forces the on-demand afterHash-blob
/// prefetch. Returns the drifted file's path.
fn mismatch_prefetch_fixture(root: &Path, pkg: &str) -> PathBuf {
    write_root_package_json(root);
    let file = install_npm_pkg(root, pkg, "1.0.0", MM_LOCAL);
    write_manifest(
        root,
        json!({
            format!("pkg:npm/{pkg}@1.0.0"): patch_record(
                MM_UUID,
                json!({ "package/index.js": {
                    "beforeHash": git_sha256(MM_BEFORE),
                    "afterHash": git_sha256(MM_AFTER),
                }}),
            )
        }),
    );
    write_diff_archive(root, MM_UUID);
    // Fixture sanity: the on-disk bytes must match neither hash, or the
    // mismatch-prefetch path under test is never taken.
    assert_ne!(git_sha256(MM_LOCAL), git_sha256(MM_BEFORE));
    assert_ne!(git_sha256(MM_LOCAL), git_sha256(MM_AFTER));
    file
}

/// `--offline` + a mismatched file whose afterHash blob is not staged:
/// human mode warns that the blob cannot be fetched, the file fails to
/// apply (per-package failure line — the npm-branch human failure output),
/// and the drifted bytes stay untouched.
#[test]
fn offline_mismatch_blob_gap_warns_and_fails_in_human_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let file = mismatch_prefetch_fixture(tmp.path(), "mmoff");

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 1, "the blob-less mismatch must fail; stderr={stderr}");
    assert!(
        stderr.contains("need their full patched blob, but --offline prevents fetching"),
        "the offline prefetch warning must print; stderr={stderr}"
    );
    assert!(
        stderr.contains("Failed to patch pkg:npm/mmoff@1.0.0"),
        "the npm-branch human failure line must name the package; stderr={stderr}"
    );
    assert_eq!(
        std::fs::read(&file).unwrap(),
        MM_LOCAL,
        "a failed apply must leave the drifted bytes untouched"
    );
}

/// Online, human mode: the "Downloading N full patched blob(s)..."
/// progress line prints before the prefetch, the blob is fetched from the
/// API into a transient overlay (never `.socket/blobs/`), and the mismatch
/// is warn-overwritten with the verified patched bytes.
#[tokio::test]
async fn online_mismatch_prefetch_prints_download_line_in_human_mode() {
    let after_hash = git_sha256(MM_AFTER);
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/test-org/patches/blob/{after_hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(MM_AFTER.to_vec()))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let file = mismatch_prefetch_fixture(tmp.path(), "mmnet");

    let (code, _stdout, stderr) = run_apply(
        tmp.path(),
        &[],
        &[
            ("SOCKET_API_URL", &mock.uri()),
            ("SOCKET_API_TOKEN", "fake-token-for-test"),
            ("SOCKET_ORG_SLUG", "test-org"),
        ],
    );
    assert_eq!(
        code, 0,
        "the default policy warn-overwrites the mismatch; stderr={stderr}"
    );
    assert!(
        stderr.contains("Downloading 1 full patched blob(s) for mismatched file(s)"),
        "the human progress line must print before the prefetch; stderr={stderr}"
    );
    assert!(
        stderr.contains("content_mismatch_overwritten"),
        "the overwrite must be surfaced as the mismatch warning; stderr={stderr}"
    );
    assert_eq!(
        std::fs::read(&file).unwrap(),
        MM_AFTER,
        "the mismatched file must carry the verified patched bytes"
    );
    // Apply stays read-only against the persistent cache.
    let blobs: Vec<_> = std::fs::read_dir(tmp.path().join(".socket/blobs"))
        .unwrap()
        .collect();
    assert!(
        blobs.is_empty(),
        "the on-demand blob must land in a transient overlay, never .socket/blobs/: {blobs:?}"
    );
}

/// When the transient blob overlay cannot be staged (tempdir creation
/// fails — TMPDIR points at a nonexistent dir), apply prints the
/// diagnostic warning instead of failing silently, then the mismatched
/// file fails to apply. Unix-only: TMPDIR drives `env::temp_dir()`.
#[cfg(unix)]
#[test]
fn broken_tmpdir_surfaces_transient_blob_stage_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let file = mismatch_prefetch_fixture(tmp.path(), "mmtmp");
    let broken_tmpdir = tmp.path().join("no-such-tmpdir");
    assert!(!broken_tmpdir.exists());

    // Online (not --offline) so the run reaches writable_blobs(); the API
    // URL is a dead loopback port, but the else-branch returns before any
    // fetch is attempted.
    let (code, _stdout, stderr) = run_apply(
        tmp.path(),
        &[],
        &[
            ("TMPDIR", broken_tmpdir.to_str().unwrap()),
            ("SOCKET_API_URL", "http://127.0.0.1:1"),
        ],
    );
    assert_eq!(code, 1, "the blob-less mismatch must fail; stderr={stderr}");
    assert!(
        stderr.contains("could not stage a transient blob directory"),
        "the staging failure must be diagnosed, not silent; stderr={stderr}"
    );
    assert!(
        stderr.contains("Failed to patch pkg:npm/mmtmp@1.0.0"),
        "stderr={stderr}"
    );
    assert_eq!(
        std::fs::read(&file).unwrap(),
        MM_LOCAL,
        "a failed apply must leave the drifted bytes untouched"
    );
}

// ═══════════ 5. human-mode apply output block ═══════════

/// The empty-scope clean success prints "No patches to apply." — the
/// postinstall-hook UX for fresh projects (previously covered only in
/// json/silent modes, where the line is suppressed).
#[test]
fn empty_manifest_prints_no_patches_to_apply_in_human_mode() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "an empty manifest is a clean no-op; stderr={stderr}");
    assert!(
        stdout.contains("No patches to apply."),
        "the human no-op line must print; stdout={stdout}"
    );
}

/// Zero packages match any in-scope patch (crawl found nothing): the
/// human warning block prints — with the in-scope count and the
/// check-your-cwd hint — and the run exits 1.
#[test]
fn no_matching_packages_prints_warning_block_and_fails() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    // One npm patch in the manifest, blob staged (so staging succeeds
    // offline), but NO node_modules at all.
    write_manifest(
        tmp.path(),
        json!({
            "pkg:npm/ghost@1.0.0": patch_record(
                "63636363-6363-4363-8363-636363636363",
                json!({ "package/index.js": {
                    "beforeHash": git_sha256(MM_BEFORE),
                    "afterHash": git_sha256(MM_AFTER),
                }}),
            )
        }),
    );
    stage_blob(tmp.path(), &git_sha256(MM_AFTER), MM_AFTER);

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(
        code, 1,
        "an in-scope patch with no installed package fails the run; stderr={stderr}"
    );
    assert!(
        stderr.contains("Warning: No packages found that match available patches"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("1 targeted manifest patch(es) were in scope"),
        "the warning must carry the in-scope count; stderr={stderr}"
    );
    assert!(
        stderr.contains("--cwd points to the right directory"),
        "the warning must carry the remediation hint; stderr={stderr}"
    );
}

/// Applying then dry-running the same fixture reports the package under
/// "already patched" in the dry-run human summary (the count line had
/// never rendered with a non-empty already_patched set).
#[test]
fn dry_run_after_apply_reports_already_patched_count() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    let file = install_npm_pkg(tmp.path(), "twice", "1.0.0", MM_BEFORE);
    write_manifest(
        tmp.path(),
        json!({
            "pkg:npm/twice@1.0.0": patch_record(
                "64646464-6464-4464-8464-646464646464",
                json!({ "package/index.js": {
                    "beforeHash": git_sha256(MM_BEFORE),
                    "afterHash": git_sha256(MM_AFTER),
                }}),
            )
        }),
    );
    stage_blob(tmp.path(), &git_sha256(MM_AFTER), MM_AFTER);

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "the wet apply must succeed; stderr={stderr}");
    assert_eq!(
        std::fs::read(&file).unwrap(),
        MM_AFTER,
        "the wet apply must patch the file"
    );

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--dry-run"], &[]);
    assert_eq!(code, 0, "the dry-run re-check must succeed; stderr={stderr}");
    assert!(
        stdout.contains("Patch verification complete:"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("1 package(s) already patched"),
        "the no-op package must be counted as already patched; stdout={stdout}"
    );
    assert!(
        stdout.contains("0 package(s) can be patched"),
        "an already-patched package must not double-count as patchable; stdout={stdout}"
    );
}

/// `--verbose` detailed verification: the already-patched / hash-mismatch /
/// not-found labels, the per-file `message:` line, and the `expected:`
/// hash line — pinned with three single-file packages so `--strict`'s
/// first-failure early return stays deterministic.
#[test]
fn verbose_dry_run_prints_per_file_labels_and_hashes() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    // Already at afterHash.
    install_npm_pkg(tmp.path(), "valready", "1.0.0", MM_AFTER);
    // Matches neither hash.
    install_npm_pkg(tmp.path(), "vmismatch", "1.0.0", MM_LOCAL);
    // Package present, patched file missing.
    let missing_dir = tmp.path().join("node_modules").join("vmissing");
    std::fs::create_dir_all(&missing_dir).unwrap();
    std::fs::write(
        missing_dir.join("package.json"),
        r#"{ "name": "vmissing", "version": "1.0.0" }"#,
    )
    .unwrap();

    let before = git_sha256(MM_BEFORE);
    let after = git_sha256(MM_AFTER);
    let files = json!({ "package/index.js": { "beforeHash": before, "afterHash": after } });
    write_manifest(
        tmp.path(),
        json!({
            "pkg:npm/valready@1.0.0":
                patch_record("65656565-6565-4565-8565-656565656565", files.clone()),
            "pkg:npm/vmismatch@1.0.0":
                patch_record("66666666-6666-4666-8666-666666666666", files.clone()),
            "pkg:npm/vmissing@1.0.0":
                patch_record("67676767-6767-4767-8767-676767676767", files),
        }),
    );
    stage_blob(tmp.path(), &after, MM_AFTER);

    let (code, stdout, stderr) = run_apply(
        tmp.path(),
        &["--offline", "--dry-run", "--verbose", "--strict"],
        &[],
    );
    assert_eq!(
        code, 1,
        "strict must fail the mismatched and missing packages; stderr={stderr}"
    );
    assert!(
        stdout.contains("Detailed verification:"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("package/index.js [already patched]"),
        "the already-patched label must render; stdout={stdout}"
    );
    assert!(
        stdout.contains("package/index.js [hash mismatch]"),
        "the hash-mismatch label must render; stdout={stdout}"
    );
    assert!(
        stdout.contains("package/index.js [not found]"),
        "the not-found label must render; stdout={stdout}"
    );
    assert!(
        stdout.contains("message: File hash does not match expected value"),
        "the mismatch engine message must render; stdout={stdout}"
    );
    assert!(
        stdout.contains("message: File not found"),
        "the not-found engine message must render; stdout={stdout}"
    );
    assert!(
        stdout.contains(&format!("expected: {before}")),
        "the expected-hash line must render for the mismatch; stdout={stdout}"
    );
    // The npm-branch per-package human failure lines ride along.
    assert!(
        stderr.contains("Failed to patch pkg:npm/vmismatch@1.0.0"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("Failed to patch pkg:npm/vmissing@1.0.0"),
        "stderr={stderr}"
    );
}

/// A pnpm store layout gets the informational stderr note in human mode
/// (previously detected only under json/silent, where the note is muted).
#[test]
fn pnpm_layout_prints_informational_note_in_human_mode() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));
    std::fs::create_dir_all(tmp.path().join("node_modules").join(".pnpm")).unwrap();

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        stderr.contains("Note: pnpm layout detected."),
        "the pnpm layout note must print on human stderr; stderr={stderr}"
    );
    assert!(
        stderr.contains("Copy-on-write will keep the global store untouched."),
        "the note must explain the CoW guarantee; stderr={stderr}"
    );
    assert!(stdout.contains("No patches to apply."), "stdout={stdout}");
}

/// The Bun layout arm — never executed by any test before: a `bun.lock` +
/// `node_modules/` tree routes to the Bun match arm and prints its
/// informational note (non-fatal, exit 0).
#[test]
fn bun_layout_prints_informational_note_in_human_mode() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));
    std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();
    std::fs::write(tmp.path().join("bun.lock"), "{}\n").unwrap();

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "the bun note is informational only; stderr={stderr}");
    assert!(
        stderr.contains("Note: bun layout detected."),
        "the bun layout note must print on human stderr; stderr={stderr}"
    );
    assert!(
        stderr.contains("Copy-on-write will keep ~/.bun/install/cache/ untouched."),
        "the note must explain the CoW guarantee; stderr={stderr}"
    );
    assert!(stdout.contains("No patches to apply."), "stdout={stdout}");
}

/// A corrupt manifest under a yarn-PnP layout must fall through to the
/// ordinary manifest-unreadable error — NOT the misdirected
/// `yarn_pnp_unsupported` refusal (`manifest_targets_npm`'s `_ => false`
/// arm). Anti-vacuity: the same layout WITH a valid npm-targeting manifest
/// does refuse.
#[test]
fn corrupt_manifest_under_pnp_layout_reports_manifest_error_not_refusal() {
    // (a) corrupt manifest → ordinary manifest error.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".socket")).unwrap();
    std::fs::write(tmp.path().join(".socket/manifest.json"), "{ not json").unwrap();
    std::fs::write(tmp.path().join(".pnp.cjs"), "// pnp loader stub\n").unwrap();

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 1, "a corrupt manifest must fail; stderr={stderr}");
    assert!(
        stderr.contains("Error"),
        "the manifest error must be reported; stderr={stderr}"
    );
    assert!(
        !stderr.contains("Plug'n'Play"),
        "an unreadable manifest must not be misreported as a PnP refusal; stderr={stderr}"
    );

    // (b) anti-vacuity: same layout, valid npm-targeting manifest → the
    // PnP refusal fires (proving the layout marker is live in fixture (a)).
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(
        tmp.path(),
        json!({
            "pkg:npm/blocked@1.0.0": patch_record(
                "68686868-6868-4868-8868-686868686868",
                json!({ "package/index.js": {
                    "beforeHash": git_sha256(MM_BEFORE),
                    "afterHash": git_sha256(MM_AFTER),
                }}),
            )
        }),
    );
    std::fs::write(tmp.path().join(".pnp.cjs"), "// pnp loader stub\n").unwrap();
    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 1, "PnP + npm patch must refuse; stderr={stderr}");
    assert!(
        stderr.contains("Plug'n'Play layout is not supported"),
        "the refusal must fire when the manifest IS readable and targets npm; stderr={stderr}"
    );
}

// ═══════════ 6. gem fallback-home skip on human stderr ═══════════

/// Unix-only: the fallback home comes from a fake `gem` binary on PATH
/// (the `in_process_gem_fallback_home.rs` fixture shape, re-run in HUMAN
/// mode — every prior run passed `--json`, so the stderr warning line had
/// never printed).
#[cfg(unix)]
mod gem_fallback_home_human {
    use super::*;
    use std::process::Command;

    const QUALIFIED_PURL: &str = "pkg:gem/rack@3.1.0?platform=ruby";
    const ORIGINAL: &[u8] = b"module Rack\n  VERSION = 'VULNERABLE'\nend\n";
    const MARKER: &[u8] = b"# SOCKET-PATCHED-FALLBACK\n";

    fn patched_bytes() -> Vec<u8> {
        let mut v = ORIGINAL.to_vec();
        v.extend_from_slice(MARKER);
        v
    }

    /// Fake `gem` answering `env gemdir` with `home`, so the crawler's
    /// fallback resolves to exactly one gem home.
    fn install_fake_gem(bin_dir: &Path, home: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let script = format!(
            "#!/bin/sh\nif [ \"$1\" = env ] && [ \"$2\" = gemdir ]; then\n  printf '%s\\n' \"{}\"\n  exit 0\nfi\nexit 1\n",
            home.display()
        );
        let bin = bin_dir.join("gem");
        std::fs::write(&bin, script).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Stage a gem copy (`<root>/gems/rack-3.1.0/lib/rack.rb` = `bytes`)
    /// plus the `specifications/` marker; returns the staged file path.
    fn stage_copy(root: &Path, bytes: &[u8]) -> PathBuf {
        let file = root
            .join("gems")
            .join("rack-3.1.0")
            .join("lib")
            .join("rack.rb");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, bytes).unwrap();
        std::fs::create_dir_all(root.join("specifications")).unwrap();
        file
    }

    /// Human-mode apply with SOCKET_*/BUNDLE_* scrubbed, PATH = the
    /// fake-gem bin dir only, BUNDLE_PATH = the store root.
    fn run_apply_human(
        project: &Path,
        bin_dir: &Path,
        store_root: &Path,
    ) -> (i32, String, String) {
        let mut cmd = Command::new(common::binary());
        cmd.args(["apply", "--offline", "--ecosystems", "gem", "--cwd"])
            .arg(project);
        for (key, _) in std::env::vars_os() {
            let k = key.to_string_lossy();
            if (k.starts_with("SOCKET_") && k != "SOCKET_NO_CONFIG") || k.starts_with("BUNDLE_") {
                cmd.env_remove(&key);
            }
        }
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
        cmd.env("PATH", bin_dir);
        cmd.env("BUNDLE_PATH", store_root);
        let out = cmd.output().expect("run socket-patch apply");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// Store copy patched + home copy matching NO variant: human mode
    /// prints the per-copy `Warning (gem_fallback_home_skipped):` stderr
    /// line naming the copy path — non-fatal (exit 0), store copy patched,
    /// home copy untouched.
    #[test]
    fn mismatched_fallback_home_copy_warns_on_human_stderr() {
        let foreign = b"totally different bytes\n";
        let project = tempfile::tempdir().unwrap();
        let root = project.path();
        std::fs::write(root.join("Gemfile"), b"source 'https://rubygems.org'\n").unwrap();

        let store_root = root.join("bundle-store");
        let store_file = stage_copy(&store_root, ORIGINAL);
        let home = root.join("gem-home");
        let home_file = stage_copy(&home, foreign);
        let bin_dir = root.join("fake-bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        install_fake_gem(&bin_dir, &home);

        let before_hash = git_sha256(ORIGINAL);
        let after_hash = git_sha256(&patched_bytes());
        write_manifest(
            root,
            json!({
                QUALIFIED_PURL: patch_record(
                    "69696969-6969-4969-8969-696969696969",
                    json!({ "lib/rack.rb": {
                        "beforeHash": before_hash,
                        "afterHash": after_hash,
                    }}),
                )
            }),
        );
        stage_blob(root, &after_hash, &patched_bytes());

        let (code, _stdout, stderr) = run_apply_human(root, &bin_dir, &store_root);
        assert_eq!(
            code, 0,
            "a mismatched fallback-home copy must not fail the run; stderr={stderr}"
        );
        assert!(
            stderr.contains("Warning (gem_fallback_home_skipped):"),
            "the best-effort skip must print its human warning; stderr={stderr}"
        );
        assert!(
            stderr.contains("gem-env home copy at"),
            "the warning must describe the skipped copy; stderr={stderr}"
        );
        assert!(
            stderr.contains(&home.display().to_string()),
            "the warning must name the fallback-home path; stderr={stderr}"
        );
        assert!(
            stderr.contains("bundle-path copy — the one bundler loads — is patched"),
            "the warning must explain why the skip is safe; stderr={stderr}"
        );
        assert_eq!(
            std::fs::read(&store_file).unwrap(),
            patched_bytes(),
            "the bundle-store copy must be patched"
        );
        assert_eq!(
            std::fs::read(&home_file).unwrap(),
            foreign,
            "the mismatched home copy must be left untouched"
        );
    }
}

// ═══════════ 7. apply-loop wiring: vendored base skip + new-file-only variant ═══════════

const GEM_BASE_PURL: &str = "pkg:gem/rack@3.1.0";
const GEM_PRISTINE: &[u8] = b"module Rack\n  VERSION = '3.1.0'\nend\n";

/// A vendored release-variant base WITH its installed tree present must be
/// skipped by the apply loop — only the synthesized `Skipped`/`vendored`
/// event, no re-patch of the installed bytes, no `package_not_installed`
/// noise. (Prior vendored-purl tests only covered the npm-branch skip or
/// an absent installed tree.)
#[test]
fn vendored_gem_base_with_installed_tree_is_skipped_not_repatched() {
    let patched = {
        let mut v = GEM_PRISTINE.to_vec();
        v.extend_from_slice(b"# SOCKET-VENDORED-PATCH\n");
        v
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let file = install_gem(root, "rack-3.1.0", "lib/rack.rb", GEM_PRISTINE);
    let uuid = "70707070-7070-4070-8070-707070707070";
    write_manifest(
        root,
        json!({
            GEM_BASE_PURL: patch_record(
                uuid,
                json!({ "lib/rack.rb": {
                    "beforeHash": git_sha256(GEM_PRISTINE),
                    "afterHash": git_sha256(&patched),
                }}),
            )
        }),
    );
    stage_blob(root, &git_sha256(&patched), &patched);
    // Vendor ledger claiming the purl — the entries shape from
    // `in_process_rollback_vendored.rs`.
    let vendor_dir = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("state.json"),
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "entries": {
                GEM_BASE_PURL: {
                    "ecosystem": "gem",
                    "basePurl": GEM_BASE_PURL,
                    "uuid": uuid,
                    "artifact": { "path": format!(".socket/vendor/gem/{uuid}/rack-3.1.0.gem") },
                    "wiring": []
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = run_apply(root, &["--offline", "--ecosystems", "gem", "--json"], &[]);
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(
        code, 0,
        "a vendor-owned base is a clean skip; envelope={env}\nstderr={stderr}"
    );
    assert_eq!(env["status"], "success", "envelope: {env}");
    let events = env["events"].as_array().expect("events array");
    assert_eq!(
        events.len(),
        1,
        "exactly one synthesized event for the vendored base: {env}"
    );
    assert_eq!(events[0]["action"], "skipped", "envelope: {env}");
    assert_eq!(events[0]["errorCode"], "vendored", "envelope: {env}");
    assert_eq!(events[0]["purl"], GEM_BASE_PURL, "envelope: {env}");
    assert!(
        !events
            .iter()
            .any(|e| e["errorCode"] == "package_not_installed"),
        "a vendored base must never be reported as not installed: {env}"
    );
    assert_eq!(
        std::fs::read(&file).unwrap(),
        GEM_PRISTINE,
        "the loop-level skip must prevent a re-patch of the installed tree"
    );
}

/// A QUALIFIED gem singleton whose record holds only NEW files (empty
/// `beforeHash` ⇒ no representative file) has nothing to disqualify it:
/// the gated apply loop must treat it as installed, attempt it, and
/// CREATE the new file from the staged blob.
#[test]
fn qualified_singleton_with_only_new_files_is_attempted_and_applied() {
    const QUALIFIED_PURL: &str = "pkg:gem/rack@3.1.0?platform=ruby";
    const SHIM: &[u8] = b"# security shim injected by socket-patch\n";
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // Installed gem WITHOUT the new file (lib/rack.rb only anchors the
    // crawler's discovery — it is not in the record).
    let gem_file = install_gem(root, "rack-3.1.0", "lib/rack.rb", GEM_PRISTINE);
    let shim_path = gem_file.parent().unwrap().join("new_shim.rb");
    assert!(!shim_path.exists());
    let after_hash = git_sha256(SHIM);
    write_manifest(
        root,
        json!({
            QUALIFIED_PURL: patch_record(
                "71717171-7171-4171-8171-717171717171",
                json!({ "lib/new_shim.rb": {
                    "beforeHash": "",
                    "afterHash": after_hash,
                }}),
            )
        }),
    );
    stage_blob(root, &after_hash, SHIM);

    let (code, stdout, stderr) = run_apply(root, &["--offline", "--ecosystems", "gem", "--json"], &[]);
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(
        code, 0,
        "a no-representative variant must apply cleanly; envelope={env}\nstderr={stderr}"
    );
    assert_eq!(env["status"], "success", "envelope: {env}");
    let events = env["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == QUALIFIED_PURL),
        "the qualified singleton must be reported applied: {env}"
    );
    assert_eq!(
        std::fs::read(&shim_path).unwrap(),
        SHIM,
        "the new file must be created with the staged blob's bytes"
    );
    assert_eq!(
        std::fs::read(&gem_file).unwrap(),
        GEM_PRISTINE,
        "the untouched anchor file must stay pristine"
    );
}

// ═══════════ 8. dry-run --vex skip message ═══════════

/// `apply --dry-run --vex <path>` in human mode: nothing was applied, so
/// VEX generation is skipped WITH the explanatory message, and no
/// attestation file is written.
#[test]
fn dry_run_with_vex_skips_generation_and_writes_no_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let file = install_gem(root, "rack-3.1.0", "lib/rack.rb", GEM_PRISTINE);
    let patched = {
        let mut v = GEM_PRISTINE.to_vec();
        v.extend_from_slice(b"# SOCKET-VEX-PATCH\n");
        v
    };
    write_manifest(
        root,
        json!({
            GEM_BASE_PURL: patch_record(
                "72727272-7272-4272-8272-727272727272",
                json!({ "lib/rack.rb": {
                    "beforeHash": git_sha256(GEM_PRISTINE),
                    "afterHash": git_sha256(&patched),
                }}),
            )
        }),
    );
    stage_blob(root, &git_sha256(&patched), &patched);
    let vex_path = root.join("out.vex.json");

    let (code, stdout, stderr) = run_apply(
        root,
        &[
            "--offline",
            "--ecosystems",
            "gem",
            "--dry-run",
            "--vex",
            vex_path.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(code, 0, "the dry-run verify must succeed; stderr={stderr}");
    assert!(
        stdout.contains("Skipping VEX generation (--dry-run: nothing was applied)."),
        "the skip must be announced; stdout={stdout}"
    );
    assert!(
        !vex_path.exists(),
        "a dry run must never write an attestation file"
    );
    assert_eq!(
        std::fs::read(&file).unwrap(),
        GEM_PRISTINE,
        "a dry run must not modify the package"
    );
}
