//! `scan --mode hosted`'s `--json` contracts for the branches of
//! `commands/scan/hosted.rs` the rest of the suite never drove (#1089):
//! exit code, `status`, `error.code`, hosted `skipped` events and their
//! `errorCode`s, `warnings[]` codes and the bytes on disk. A message is read
//! only for what it must name (a purl, a path, a remedy). The human output
//! of the same paths is pinned in `hosted_render.rs`.
//!
//!   1. the `bad_purl` / `no_url` reference skips;
//!   2. the WET takeover refusal (vendored revert fails closed), its
//!      refused-purl cleanup and the symlinked-wiring pre-check;
//!   3. the apply lock (held, I/O fault, zero-grant and success footprints);
//!   4. the cargo socket-owned-wiring-without-ledger refusal;
//!   5. the bun.lockb arms (native rewrite, malformed, unreadable, FIFO,
//!      beside a package-lock.json or pnpm-lock.yaml sibling);
//!   6. the live unreadable pnpm-workspace.yaml fallback and the
//!      hosted-direction `redirect_supersedes_vendored` warning;
//!   7. the `--vex` block's warnings and the ledger-save failure;
//!   8. vlt, npm-shrinkwrap.json and the yarn classic berry advisory.

use std::path::Path;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::hosted_fixture::*;
use crate::{common, rollback_json};

// ───────────────────── reference-skip reasons ─────────────────────

/// A granted reference whose purl fails `parse_purl_simple` is skipped with
/// reason `bad_purl` — never redirected, never recorded — and the project is
/// left byte-untouched.
#[tokio::test]
async fn granted_reference_with_unparseable_purl_is_skipped_as_bad_purl() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_reference_results(
        &server,
        json!({
            UUID: {
                "status": "granted",
                "url": HOSTED_URL,
                "purl": "not-a-purl",
                "artifacts": [{
                    "kind": "tarball",
                    "url": HOSTED_URL,
                    "integrity": { "sha512": PATCHED_SHA512 }
                }],
                "registryOverride": null
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "a fully-skipped redirect still exits 0: {doc:#}");
    assert_eq!(
        Value::Array(hosted_skipped(&doc)),
        json!([{ "purl": "not-a-purl", "uuid": UUID, "reason": "bad_purl" }]),
        "the skipped entry must carry the SERVED purl and the bad_purl reason: {doc:#}"
    );
    assert_eq!(hosted_pins(&doc).len(), 0, "envelope: {doc:#}");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "a bad-purl grant must leave the lockfile byte-identical"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "a zero-redirect run must not write a redirect ledger"
    );
}

/// A granted reference with `url: null` is skipped with reason `no_url` —
/// a grant without an artifact URL must never be redirected with an empty
/// URL.
#[tokio::test]
async fn granted_reference_without_url_is_skipped_as_no_url() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_reference_results(
        &server,
        json!({
            UUID: {
                "status": "granted",
                "url": null,
                "purl": PURL,
                "artifacts": [],
                "registryOverride": null
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "a fully-skipped redirect still exits 0: {doc:#}");
    assert_eq!(
        Value::Array(hosted_skipped(&doc)),
        json!([{ "purl": PURL, "uuid": UUID, "reason": "no_url" }]),
        "the skipped entry must carry the no_url reason: {doc:#}"
    );
    assert_eq!(hosted_pins(&doc).len(), 0, "envelope: {doc:#}");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "a url-less grant must leave the lockfile byte-identical"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "a zero-redirect run must not write a redirect ledger"
    );
}

// ──────────────── wet takeover refusal + refused-purl cleanup ────────────────

/// WET-run takeover refusal (the fail-closed half of the takeover contract):
/// a vendored ledger entry whose flavor names a backend this build lacks
/// makes `dispatch_revert_one` fail closed, so the purl is refused —
/// `redirect_vendored_revert_failed` warning, a `vendored_revert_failed`
/// skip, `redirected: 0` — and the refused-purl cleanup drops its override
/// so the rewrite can never land. The vendored ledger and the lockfile stay
/// byte-identical. The human render is pinned in `hosted_render.rs`.
#[tokio::test]
async fn wet_takeover_refuses_unrevertable_vendored_flavor_fail_closed() {
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
    let state_before = std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap();
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "a refused takeover still exits 0: {doc:#}");
    let detail = warning_detail(&doc, "redirect_vendored_revert_failed");
    assert!(
        detail.contains(PURL) && detail.contains("vendor --revert"),
        "the refusal must name the purl and the manual remedy: {detail}"
    );
    assert!(
        hosted_skipped(&doc).iter().any(|e| e["purl"] == PURL
            && e["uuid"] == UUID
            && e["reason"] == "vendored_revert_failed"),
        "the refusal must be accounted as skipped: {doc:#}"
    );
    assert_eq!(
        hosted_pins(&doc).len(),
        0,
        "a refused purl is never counted redirected: {doc:#}"
    );
    // The refused-purl cleanup dropped the override: the rewrite landed
    // nothing, so the lock is byte-identical and hosted-URL-free.
    let lock_after = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(
        lock_after, lock_before,
        "the retained-out override must never reach the rewriters"
    );
    assert!(
        !String::from_utf8_lossy(&lock_after).contains(HOSTED_URL),
        "the hosted URL must never appear in a refused lock"
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap(),
        state_before,
        "a failed revert must leave the vendored ledger byte-identical"
    );
}

// ──────────── takeover symlink pre-check (before any revert dispatches) ────────────

/// A vendored→hosted takeover must NOT revert a vendored purl whose recorded
/// wiring file is a symbolic link: the npm revert stages and renames over
/// package-lock.json exactly like the rewriters do, so it would DETACH the
/// link (and remove the committed artifact) before the general symlink
/// guard — which runs after the takeover — could refuse. The pre-check
/// refuses the whole run first, with the guard's own code, under
/// `--dry-run` too: the link, its target, the
/// vendored ledger and the artifact stay byte-identical, no redirect ledger
/// appears, and the apply lock the wet run took is gone again.
#[cfg(unix)]
#[tokio::test]
async fn takeover_refuses_symlinked_wiring_file_before_reverting() {
    const VUUID: &str = "77777777-7777-4777-8777-777777777777";
    const CODE: &str = "redirect_symlinked_file_unsupported";
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    // The vendored shape the revert restores from: the live lock entry
    // resolves through the committed artifact; the wiring records the
    // registry original the revert would write back.
    let registry_resolved = format!("https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz");
    let vendored_resolved = format!("file:.socket/vendor/npm/{VUUID}/{NAME}-{VERSION}.tgz");
    let vendored_lock = std::fs::read_to_string(root.join("package-lock.json"))
        .unwrap()
        .replace(&registry_resolved, &vendored_resolved)
        .replace(UPSTREAM_SHA512, PATCHED_SHA512);
    write_vendor_state_wired(
        root,
        PURL,
        VUUID,
        "package-lock",
        json!([{
            "file": "package-lock.json",
            "kind": "npm_lock_entry",
            "action": "rewritten",
            "key": format!("node_modules/{NAME}"),
            "original": {
                "version": VERSION, "resolved": registry_resolved, "integrity": UPSTREAM_SHA512
            },
            "new": {
                "version": VERSION, "resolved": vendored_resolved, "integrity": PATCHED_SHA512
            }
        }]),
    );
    let artifact = root
        .join(".socket/vendor/npm")
        .join(VUUID)
        .join(format!("{NAME}-{VERSION}.tgz"));
    std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
    std::fs::write(&artifact, b"tgz").unwrap();
    // The lock lives in a shared dir; the project holds a relative symlink.
    let shared = root.join("shared");
    std::fs::create_dir_all(&shared).unwrap();
    std::fs::write(shared.join("package-lock.json"), &vendored_lock).unwrap();
    std::fs::remove_file(root.join("package-lock.json")).unwrap();
    std::os::unix::fs::symlink("shared/package-lock.json", root.join("package-lock.json")).unwrap();
    let state_before = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();

    let is_symlink = |p: &Path| {
        std::fs::symlink_metadata(p)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
    };
    let assert_untouched = |doc: &Value| {
        assert!(
            is_symlink(&root.join("package-lock.json")),
            "the link must survive — a revert's rename-over would have detached it: {doc:#}"
        );
        assert_eq!(
            std::fs::read_to_string(shared.join("package-lock.json")).unwrap(),
            vendored_lock,
            "the link target must be byte-identical: {doc:#}"
        );
        assert_eq!(
            std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
            state_before,
            "the vendored ledger must be byte-identical: {doc:#}"
        );
        assert!(
            artifact.is_file(),
            "the committed artifact must survive: {doc:#}"
        );
        assert!(
            !root.join(".socket/vendor/redirect-state.json").exists(),
            "no redirect ledger may be written: {doc:#}"
        );
        assert!(
            !root.join(".socket/apply.lock").exists(),
            "the apply lock never outlives the run: {doc:#}"
        );
    };

    for dry_run in [false, true] {
        let extra: &[&str] = if dry_run { &["--dry-run"] } else { &[] };
        let (code, doc) = scan_hosted_json(root, &server.uri(), extra, &[]);
        assert_eq!(
            code, 1,
            "dry_run={dry_run}: a symlinked revert target fails the run: {doc:#}"
        );
        assert_eq!(doc["status"], "error", "dry_run={dry_run}: {doc:#}");
        assert_eq!(doc["error"]["code"], CODE, "dry_run={dry_run}: {doc:#}");
        let error = doc["error"]["message"].as_str().unwrap_or_default();
        assert!(
            error.starts_with("package-lock.json "),
            "dry_run={dry_run}: the refusal names the link: {error}"
        );
        assert_untouched(&doc);
    }

    // Human arm: the guard's stderr line, same code.
    let (code, _stdout, stderr) = scan_hosted(root, &server.uri(), &[], &[]);
    assert_eq!(code, 1, "stderr=\n{stderr}");
    assert!(
        stderr.contains(&format!("Error ({CODE}): package-lock.json ")),
        "the human refusal must carry the stable code; stderr=\n{stderr}"
    );
    assert_untouched(&json!(null));
}

// ───────────────────── apply lock (hosted holds it, lazily) ─────────────────────

/// `scan --mode hosted` takes the same `.socket/apply.lock` every other
/// mutating command holds — but only when it could write. A WET run with a
/// granted reference refuses a held lock with `lock_held` (the hosted
/// envelope's top-level `error.code`, exit 1) BEFORE the ledger load or any
/// file write (the human line is pinned in `hosted_render.rs`; its wording
/// in `lock_cli.rs`'s unit tests). A `--dry-run`,
/// and a wet run whose references are all skipped, never contend: nothing
/// they do touches `.socket/`, so they succeed under the held lock. Once the
/// holder releases, `.socket/` is gone — the hosted runs created nothing.
#[tokio::test]
async fn hosted_lock_held_refuses_before_any_write() {
    use std::time::Duration;

    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    // Same discovery, but the reference endpoint grants nothing: every
    // selection is skipped as `not_found`, so the run has nothing to write.
    let no_grant = MockServer::start().await;
    mock_discovery(&no_grant, PURL, UUID).await;
    mock_reference_results(&no_grant, json!({})).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    let lock_before = std::fs::read(root.join("package-lock.json")).unwrap();
    let holder =
        socket_patch_core::patch::apply_lock::acquire(&root.join(".socket"), Duration::ZERO)
            .unwrap();

    // Wet --json: refused before anything is written.
    let (code, doc) = scan_hosted_json(root, &server.uri(), &[], &[]);
    assert_eq!(code, 1, "a held lock refuses the wet run: {doc:#}");
    assert_eq!(doc["status"], "error", "{doc:#}");
    assert_eq!(doc["error"]["code"], "lock_held", "{doc:#}");
    let message = envelope_error_message(&doc).unwrap_or_default();
    assert!(
        !message.is_empty() && !message.contains("waited"),
        "a contention message, and with no --lock-timeout no waited clause; {doc:#}"
    );
    assert_eq!(
        doc.get("redirect"),
        None,
        "a hosted error envelope has no redirect payload (nothing was rewritten): {doc:#}"
    );

    // --dry-run under the held lock: a preview never locks (it writes
    // nothing), so it previews the rewrite instead of contending.
    let (code, doc) = scan_hosted_json(root, &server.uri(), &["--dry-run"], &[]);
    assert_eq!(code, 0, "a dry run never contends: {doc:#}");
    assert_eq!(doc["dryRun"], true, "{doc:#}");
    assert_eq!(hosted_pins(&doc).len(), 1, "{doc:#}");

    // Zero grants under the held lock: nothing to write, so no lock taken.
    let (code, doc) = scan_hosted_json(root, &no_grant.uri(), &[], &[]);
    assert_eq!(code, 0, "an all-skipped run never contends: {doc:#}");
    assert_eq!(hosted_pins(&doc).len(), 0, "{doc:#}");
    assert!(
        Some(&hosted_skipped(&doc)).is_some_and(|s| s.iter().any(|e| e["reason"] == "not_found")),
        "{doc:#}"
    );

    assert_eq!(
        std::fs::read(root.join("package-lock.json")).unwrap(),
        lock_before,
        "none of the runs may touch the lockfile"
    );
    assert!(!root.join(".socket/vendor/redirect-state.json").exists());
    drop(holder);
    assert!(
        !root.join(".socket").exists(),
        "the hosted runs created nothing under .socket/, so the released lock leaves no dir"
    );
}

/// A zero-grant wet run over a project holding a MALFORMED pre-v5 redirect
/// ledger: v5 scan never reads that ledger, so it is neither an error nor
/// quarantined — the run succeeds (nothing granted, nothing written) under a
/// lock held by another process and with no holder alike, and the torn file
/// stays byte-identical in place. The human arm never mentions it either.
#[tokio::test]
async fn zero_grant_wet_run_ignores_a_malformed_pre_v5_ledger() {
    use std::time::Duration;

    let no_grant = MockServer::start().await;
    mock_discovery(&no_grant, PURL, UUID).await;
    mock_reference_results(&no_grant, json!({})).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    let ledger = root.join(".socket/vendor/redirect-state.json");
    std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
    const TORN: &[u8] = b"{ torn";
    std::fs::write(&ledger, TORN).unwrap();
    let lock_before = std::fs::read(root.join("package-lock.json")).unwrap();

    let assert_ignored = |code: i32, doc: &Value, label: &str| {
        assert_eq!(
            code, 0,
            "{label}: a pre-v5 ledger is never an error: {doc:#}"
        );
        assert_eq!(doc["status"], "success", "{label}: {doc:#}");
        assert!(
            !doc.to_string().contains("redirect-state.json"),
            "{label}: the envelope never mentions the legacy ledger: {doc:#}"
        );
        assert_eq!(
            std::fs::read(&ledger).unwrap(),
            TORN,
            "{label}: the ledger stays byte-identical in place"
        );
        assert!(
            !root
                .join(".socket/vendor/redirect-state.json.corrupt")
                .exists(),
            "{label}: never quarantined"
        );
        assert_eq!(
            std::fs::read(root.join("package-lock.json")).unwrap(),
            lock_before,
            "{label}: the lockfile is untouched"
        );
    };

    // Under a lock held by another process: a zero-grant run writes nothing,
    // so it never contends.
    let holder =
        socket_patch_core::patch::apply_lock::acquire(&root.join(".socket"), Duration::ZERO)
            .unwrap();
    let (code, doc) = scan_hosted_json(root, &no_grant.uri(), &[], &[]);
    assert_ne!(
        doc["error"]["code"], "lock_held",
        "a zero-grant run never contends: {doc:#}"
    );
    assert_ignored(code, &doc, "held lock");
    drop(holder);

    let (code, doc) = scan_hosted_json(root, &no_grant.uri(), &[], &[]);
    assert_ignored(code, &doc, "no holder");
    assert!(
        !root.join(".socket/apply.lock").exists(),
        "no lock was taken, none is left behind"
    );

    let (code, _stdout, stderr) = scan_hosted(root, &no_grant.uri(), &[], &[]);
    assert_eq!(code, 0, "stderr=\n{stderr}");
    assert!(
        !stderr.contains("malformed") && !stderr.contains("redirect ledger"),
        "stderr=\n{stderr}"
    );
    assert_eq!(std::fs::read(&ledger).unwrap(), TORN);
}

/// The hosted `lock_io` envelope (CLI_CONTRACT.md "Lock lifecycle (v5.0)" and
/// the hosted-mode "Lock (v5.0)" clause): a regular file
/// squatting on `.socket/` makes the wet run's lock acquire fail with an I/O
/// fault, not contention — top-level `error.code: "lock_io"`, an
/// `error.message` naming the squatting path, no `redirect` payload, exit 1,
/// refused BEFORE the ledger is read or written. The squatting file is never
/// removed or truncated. The human line is pinned in `hosted_render.rs`.
/// (A `--dry-run` never locks, but it still reads the ledger strictly and
/// reports the squatted `.socket/` as an unreadable ledger location — a
/// different, pre-existing refusal, not pinned here.)
#[tokio::test]
async fn hosted_lock_io_when_a_file_squats_on_socket_dir() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    const SQUATTER: &[u8] = b"not a dir";
    std::fs::write(root.join(".socket"), SQUATTER).unwrap();
    let lock_before = std::fs::read(root.join("package-lock.json")).unwrap();

    let (code, doc) = scan_hosted_json(root, &server.uri(), &[], &[]);
    assert_eq!(code, 1, "{doc:#}");
    assert_eq!(doc["status"], "error", "{doc:#}");
    assert_eq!(doc["error"]["code"], "lock_io", "{doc:#}");
    let error = doc["error"]["message"].as_str().unwrap_or_default();
    assert!(
        error.contains(".socket"),
        "the fault names the squatting path: {error}"
    );
    assert_eq!(
        doc.get("redirect"),
        None,
        "a hosted error envelope has no redirect payload (nothing was rewritten): {doc:#}"
    );

    assert_eq!(
        std::fs::read(root.join(".socket")).unwrap(),
        SQUATTER,
        "the squatting file is never removed or truncated"
    );
    assert_eq!(
        std::fs::read(root.join("package-lock.json")).unwrap(),
        lock_before
    );
}

/// The footprint of a SUCCESSFUL wet hosted run (G6 / lock lifecycle): after
/// `scan --mode hosted --yes` (human) and `scan --mode hosted --json`, each
/// on a fresh project, `.socket/` holds NOTHING (v5 hosted mode writes no
/// ledger; the lockfile is the whole record) — no `apply.lock` outlives the
/// run, and nothing else is created. The human run also never prints the `Non-interactive mode
/// detected` auto-accept line: scan never prompts.
#[tokio::test]
async fn successful_wet_hosted_run_leaves_nothing_under_socket() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let socket_listing = |root: &Path| -> Vec<String> {
        let Ok(dir) = std::fs::read_dir(root.join(".socket")) else {
            return Vec::new();
        };
        let mut names: Vec<String> = dir
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };

    // Human arm.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    let (code, stdout, stderr) = scan_hosted(root, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        std::fs::read_to_string(root.join("package-lock.json"))
            .unwrap()
            .contains(HOSTED_URL),
        "the run must have redirected (and therefore locked); stdout=\n{stdout}"
    );
    assert!(
        !stderr.contains("Non-interactive mode detected"),
        "--yes skips the prompt outright; stderr=\n{stderr}"
    );
    assert!(!root.join(".socket/vendor/redirect-state.json").exists());
    assert!(
        !root.join(".socket/apply.lock").exists(),
        "apply.lock never outlives the run"
    );
    assert_eq!(
        socket_listing(root),
        Vec::<String>::new(),
        "a v5 hosted run writes nothing under .socket/"
    );

    // `--json` arm on a fresh project (a second run over the redirected
    // state would be all-skipped and never lock).
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    let (code, doc) = scan_hosted_json(root, &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(hosted_pins(&doc).len(), 1, "{doc:#}");
    assert!(
        !root.join(".socket/apply.lock").exists(),
        "apply.lock never outlives the run"
    );
    assert_eq!(socket_listing(root), Vec::<String>::new());
}

// ───────────── cargo wiring-without-ledger refusal ─────────────

/// A cargo purl with SOCKET-OWNED `[patch.crates-io]` wiring — pre-v5 in
/// .cargo/config.toml, or v5 in the root Cargo.toml — but NO vendored ledger
/// must be refused: the originals needed to revert are unrecoverable, so
/// redirecting on top would wedge the project. The refusal happens before
/// any rewrite — manifest, config and lock stay byte-identical.
#[tokio::test]
async fn cargo_socket_owned_wiring_without_ledger_refuses_the_redirect() {
    ledgerless_cargo_wiring_refuses(false).await;
}

#[tokio::test]
async fn cargo_socket_owned_manifest_wiring_without_ledger_refuses_the_redirect() {
    ledgerless_cargo_wiring_refuses(true).await;
}

/// The missing-ledger probe is version-scoped: Socket-owned wiring for
/// ANOTHER version of the crate (vendored alongside, with its own ledger
/// entry) must not refuse redirecting this one.
#[tokio::test]
async fn cargo_other_version_vendored_wiring_does_not_refuse_the_redirect() {
    const CNAME: &str = "covgap-cargo-dep";
    const CPURL: &str = "pkg:cargo/covgap-cargo-dep@1.0.0";
    const CUUID: &str = "44444444-4444-4444-8444-444444444444";
    let server = MockServer::start().await;
    mock_discovery(&server, CPURL, CUUID).await;
    let hosted_url = format!(
        "{}/patch/cargo/{CNAME}/1.0.0/55555555-5555-4555-8555-555555555555/{CUUID}/{CNAME}-1.0.0.crate",
        server.uri()
    );
    let cksum = "a".repeat(64);
    mock_reference_results(
        &server,
        json!({
            CUUID: {
                "status": "granted",
                "url": hosted_url,
                "purl": CPURL,
                "artifacts": [{
                    "kind": "tarball",
                    "url": hosted_url,
                    "integrity": { "sha256": cksum }
                }],
                "registryOverride": {
                    "kind": "cargo-sparse",
                    "indexUrl": format!("sparse+{}/index/", server.uri()),
                    "identifiers": {
                        "name": CNAME,
                        "version": "1.0.0",
                        "cargoCksumSha256": cksum,
                    }
                }
            }
        }),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\n{CNAME} = \"1.0.0\"\n\n[patch.crates-io]\n\
             {CNAME}-socket-66666666 = {{ package = \"{CNAME}\", path = \
             \".socket/vendor/cargo/66666666-6666-4666-8666-666666666666/{CNAME}-0.9.0\" }}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        format!(
            "version = 3\n\n[[package]]\nname = \"consumer\"\nversion = \"0.1.0\"\ndependencies = [\n \"{CNAME}\",\n]\n\n[[package]]\nname = \"{CNAME}\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{cksum}\"\n"
        ),
    )
    .unwrap();
    let cargo_home = root.join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();
    let cargo_home_s = cargo_home.to_str().unwrap().to_string();
    let (_, doc) = scan_hosted_json(
        root,
        &server.uri(),
        &[],
        &[("CARGO_HOME", cargo_home_s.as_str())],
    );
    let codes: Vec<&str> = doc["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert!(
        !codes.contains(&"redirect_vendored_revert_failed"),
        "another version's wiring is not this version's lost ledger: {doc:#}"
    );
    assert!(
        !Some(&hosted_skipped(&doc))
            .is_some_and(|s| s.iter().any(|e| e["reason"] == "vendored_revert_failed")),
        "{doc:#}"
    );
}

async fn ledgerless_cargo_wiring_refuses(manifest_wiring: bool) {
    const CNAME: &str = "covgap-cargo-dep";
    const CPURL: &str = "pkg:cargo/covgap-cargo-dep@1.0.0";
    const CUUID: &str = "44444444-4444-4444-8444-444444444444";
    let server = MockServer::start().await;
    mock_discovery(&server, CPURL, CUUID).await;
    let hosted_url = format!(
        "{}/patch/cargo/{CNAME}/1.0.0/55555555-5555-4555-8555-555555555555/{CUUID}/{CNAME}-1.0.0.crate",
        server.uri()
    );
    let cksum = "a".repeat(64);
    mock_reference_results(
        &server,
        json!({
            CUUID: {
                "status": "granted",
                "url": hosted_url,
                "purl": CPURL,
                "artifacts": [{
                    "kind": "tarball",
                    "url": hosted_url,
                    "integrity": { "sha256": cksum }
                }],
                "registryOverride": {
                    "kind": "cargo-sparse",
                    "indexUrl": format!("sparse+{}/index/", server.uri()),
                    "identifiers": {
                        "name": CNAME,
                        "version": "1.0.0",
                        "cargoCksumSha256": cksum,
                    }
                }
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let patch = format!(
        "[patch.crates-io]\n{CNAME} = {{ path = \".socket/vendor/cargo/{CUUID}/{CNAME}-1.0.0\" }}\n"
    );
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{CNAME} = \"1.0.0\"\n{}",
            if manifest_wiring { format!("\n{patch}") } else { String::new() }
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        format!(
            "version = 3\n\n[[package]]\nname = \"consumer\"\nversion = \"0.1.0\"\ndependencies = [\n \"{CNAME}\",\n]\n\n[[package]]\nname = \"{CNAME}\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{cksum}\"\n"
        ),
    )
    .unwrap();
    // Socket-owned [patch.crates-io] wiring — but NO .socket/vendor/state.json.
    if !manifest_wiring {
        std::fs::create_dir_all(root.join(".cargo")).unwrap();
        std::fs::write(root.join(".cargo/config.toml"), &patch).unwrap();
    }
    let config_before = std::fs::read(root.join(".cargo/config.toml")).ok();
    let lock_before = std::fs::read(root.join("Cargo.lock")).unwrap();
    let manifest_before = std::fs::read(root.join("Cargo.toml")).unwrap();

    // Hermetic CARGO_HOME so the cargo crawler never scans the host's real
    // registry cache.
    let cargo_home = root.join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();
    let cargo_home_s = cargo_home.to_str().unwrap().to_string();
    let (code, doc) = scan_hosted_json(
        root,
        &server.uri(),
        &[],
        &[("CARGO_HOME", cargo_home_s.as_str())],
    );

    assert_eq!(code, 0, "a refused cargo takeover still exits 0: {doc:#}");
    let detail = warning_detail(&doc, "redirect_vendored_revert_failed");
    assert!(
        detail.contains(CPURL) && detail.contains(".socket/vendor/state.json"),
        "the refusal must name the purl and the missing ledger: {detail}"
    );
    assert!(
        Some(&hosted_skipped(&doc)).is_some_and(|s| s
            .iter()
            .any(|e| e["purl"] == CPURL && e["reason"] == "vendored_revert_failed")),
        "the refusal must be accounted as skipped: {doc:#}"
    );
    assert_eq!(hosted_pins(&doc).len(), 0, "envelope: {doc:#}");
    assert_eq!(
        std::fs::read(root.join(".cargo/config.toml")).ok(),
        config_before,
        "the socket-owned wiring must be left for manual recovery"
    );
    assert_eq!(
        std::fs::read(root.join("Cargo.lock")).unwrap(),
        lock_before,
        "the lock must stay byte-identical"
    );
    assert_eq!(
        std::fs::read(root.join("Cargo.toml")).unwrap(),
        manifest_before,
        "the manifest must stay byte-identical"
    );
}

// ───────────────────────── bun.lockb arms ─────────────────────────

/// Dry-run and apply use the same native binary rewrite, with no Bun
/// executable or installed dependencies. A fresh clone works immediately.
/// No run writes a redirect ledger (v5), and `rollback` cannot restore a
/// binary `bun.lockb` pin to its upstream entry: it refuses the pin
/// (`rollback_failed`, exit 1) naming the `git checkout` remedy and leaves
/// the lock byte-identical.
#[tokio::test]
async fn native_bun_lockb_hosting_dry_run_rerun_and_rollback_without_bun() {
    let purl = "pkg:npm/minimist@1.2.2";
    // A standard hosted URL shape (grant token, then the patch uuid), so
    // lockfile discovery recognizes the pin under `--patch-server-url`.
    let url = &format!(
        "https://patch.test/patch/npm/minimist/1.2.2/22222222-2222-4222-8222-222222222222/{UUID}/minimist-1.2.2.tgz"
    );
    let sri = format!("sha512-{}", "A".repeat(86) + "==");
    let server = MockServer::start().await;
    mock_discovery(&server, purl, UUID).await;
    mock_reference_results(
        &server,
        json!({ UUID: {
            "status": "granted", "url": url, "purl": purl,
            "artifacts": [{"kind": "tarball", "url": url, "integrity": {"sha512": sri}}],
            "registryOverride": null,
        }}),
    )
    .await;
    mock_view(&server, UUID, purl).await;
    let tmp = tempfile::tempdir().unwrap();
    let original =
        include_bytes!("../../../socket-patch-core/tests/fixtures/bun-lockb/1.1.45/bun.lockb");
    std::fs::write(tmp.path().join("bun.lockb"), original).unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        include_bytes!("../../../socket-patch-core/tests/fixtures/bun-lockb/1.1.45/package.json"),
    )
    .unwrap();
    let env = [("PATH", "")];

    let (code, preview) = scan_hosted_json(tmp.path(), &server.uri(), &["--dry-run"], &env);
    assert_eq!(code, 0, "{preview:#}");
    assert_eq!(hosted_pins(&preview).len(), 1, "{preview:#}");
    assert!(preview["redirect"]["rewrittenFiles"]
        .as_array()
        .unwrap()
        .contains(&json!("bun.lockb")));
    assert_eq!(
        std::fs::read(tmp.path().join("bun.lockb")).unwrap(),
        original
    );
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .exists());

    let (code, applied) = scan_hosted_json(tmp.path(), &server.uri(), &[], &env);
    assert_eq!(code, 0, "{applied:#}");
    assert_eq!(hosted_pins(&applied).len(), 1, "{applied:#}");
    let patched = std::fs::read(tmp.path().join("bun.lockb")).unwrap();
    assert_ne!(patched, original);
    assert!(patched
        .windows(url.len())
        .any(|bytes| bytes == url.as_bytes()));
    assert!(!tmp.path().join("bun.lock").exists());
    assert!(!tmp.path().join("node_modules").exists());
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .exists());

    let (code, rerun) = scan_hosted_json(tmp.path(), &server.uri(), &[], &env);
    assert_eq!(code, 0, "{rerun:#}");
    assert_eq!(hosted_pins(&rerun).len(), 1, "{rerun:#}");
    assert_eq!(
        std::fs::read(tmp.path().join("bun.lockb")).unwrap(),
        patched
    );
    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &[
            "rollback",
            "--json",
            "--yes",
            "--patch-server-url",
            "https://patch.test",
            "--cwd",
            tmp.path().to_str().unwrap(),
        ],
        &env,
    );
    assert_eq!(
        code, 1,
        "a binary bun.lockb pin is refused: {stdout}\n{stderr}"
    );
    let doc: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
    // The refused pin is the only outcome: a total failure (#1066).
    assert_eq!(doc["status"], "error", "{doc:#}");
    assert_eq!(doc["error"]["code"], "rollback_failed", "{doc:#}");
    assert_eq!(doc["summary"]["failed"], 1, "{doc:#}");
    let failed_view = rollback_json::hosted_failed(&doc);
    let failed = failed_view.as_array().unwrap_or_else(|| panic!("{doc:#}"));
    assert_eq!(failed.len(), 1, "{doc:#}");
    assert_eq!(failed[0]["purl"], purl, "{doc:#}");
    let error = failed[0]["error"].as_str().unwrap_or_default();
    assert!(
        error.contains(purl) && error.contains("bun.lockb") && error.contains("git checkout"),
        "the refusal names the pin, the lock and the remedy: {error}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("bun.lockb")).unwrap(),
        patched,
        "nothing is written for a refused pin"
    );
    assert!(!tmp.path().join("bun.lock").exists());
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .exists());
}

#[cfg(unix)]
#[tokio::test]
async fn malformed_bun_lockb_reports_format_error_without_spawning_bun() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_lockb_project(tmp.path());
    let original = std::fs::read(tmp.path().join("bun.lockb")).unwrap();
    let (path, marker) = install_marker_bun_shim(tmp.path());
    for extra in [&["--dry-run"][..], &[][..]] {
        let (code, doc) =
            scan_hosted_json(tmp.path(), &server.uri(), extra, &[("PATH", path.as_str())]);
        assert_eq!(code, 0, "{doc:#}");
        assert_eq!(hosted_pins(&doc).len(), 0, "{doc:#}");
        assert!(warning_detail(&doc, "redirect_bun_lockb_invalid").contains("bun.lockb"));
        assert_eq!(
            std::fs::read(tmp.path().join("bun.lockb")).unwrap(),
            original
        );
        assert!(!tmp.path().join("bun.lock").exists());
        assert!(!marker.exists());
    }
    let (code, _, stderr) = scan_hosted(tmp.path(), &server.uri(), &[], &[("PATH", path.as_str())]);
    assert_eq!(code, 0, "{stderr}");
    assert!(stderr.contains("bun.lockb"), "{stderr}");
}

#[cfg(unix)]
#[tokio::test]
async fn unreadable_bun_lockb_is_preserved_and_reports_the_io_error() {
    use std::os::unix::fs::PermissionsExt;
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_lockb_project(tmp.path());
    let lock = tmp.path().join("bun.lockb");
    let original = std::fs::read(&lock).unwrap();
    let (path, marker) = install_marker_bun_shim(tmp.path());
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&lock).is_ok() {
        return;
    }
    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[("PATH", path.as_str())]);
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(hosted_pins(&doc).len(), 0, "{doc:#}");
    assert!(warning_detail(&doc, "redirect_bun_lockb_invalid").contains("cannot read bun.lockb"));
    assert_eq!(std::fs::read(&lock).unwrap(), original);
    assert!(!tmp.path().join("bun.lock").exists());
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .exists());
    assert!(!marker.exists());
}

/// A FIFO squatting bun.lockb fails fast through the guarded binary read,
/// in live and dry-run modes. No installer is spawned and no file changes.
#[cfg(unix)]
#[tokio::test]
async fn fifo_bun_lockb_refuses_before_spawning_bun_and_never_wedges() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_bun_lockb_project(tmp.path());
    let fifo = tmp.path().join("bun.lockb");
    std::fs::remove_file(&fifo).unwrap();
    mkfifo(&fifo);
    let (path_value, marker) = install_marker_bun_shim(tmp.path());
    let env = [("PATH", path_value.as_str())];

    for extra in [&["--dry-run"][..], &[][..]] {
        let (code, doc) =
            scan_hosted_json_or_release_fifo(tmp.path(), &server.uri(), extra, &env, &fifo);
        assert_eq!(
            code, 0,
            "{extra:?}: the refusal is a warning, not an error: {doc:#}"
        );
        let detail = warning_detail(&doc, "redirect_bun_lockb_invalid");
        // The FIFO-safe opener's refusal, not the generic format error.
        assert!(
            detail.contains("bun.lockb") && detail.contains("regular file"),
            "{extra:?}: {detail}"
        );
        let codes = codes_in(&doc["warnings"]);
        assert_eq!(
            codes
                .iter()
                .filter(|c| *c == "redirect_bun_lockb_invalid")
                .count(),
            1,
            "{extra:?}: exactly one binary-format warning: {codes:?}"
        );
        assert!(
            !codes.contains(&"redirect_npm_no_lockfile".to_string()),
            "{extra:?}: the existing binary lock must not be reported missing: {codes:?}"
        );
        assert_eq!(hosted_pins(&doc).len(), 0, "{extra:?}: {doc:#}");
        assert!(
            !marker.exists(),
            "{extra:?}: bun must never be spawned on a FIFO bun.lockb (it blocks on it too)"
        );
        let meta = std::fs::symlink_metadata(&fifo).unwrap();
        assert!(
            std::os::unix::fs::FileTypeExt::is_fifo(&meta.file_type()),
            "{extra:?}: the FIFO is left in place, never replaced or removed"
        );
        assert!(
            !tmp.path().join("bun.lock").exists(),
            "{extra:?}: no text lock may appear"
        );
    }
}

/// A malformed primary binary lock refuses the npm redirect before any
/// sibling lock can be changed or confirmed.
#[cfg(unix)]
fn assert_sibling_lock_outcome(
    doc: &Value,
    root: &Path,
    sibling: &str,
    lockb_before: &[u8],
    marker: &Path,
    dry_run: bool,
) {
    assert!(warning_detail(doc, "redirect_bun_lockb_invalid").contains("bun.lockb"));
    assert_eq!(doc["dryRun"], dry_run, "{doc:#}");
    assert_eq!(
        hosted_pins(doc).len(),
        0,
        "a failed primary binary lock must never be confirmed by {sibling}: {doc:#}"
    );
    assert!(
        doc["redirect"]["rewrittenFiles"]
            .as_array()
            .unwrap()
            .is_empty(),
        "{doc:#}"
    );
    assert!(!root.join(".socket/vendor/redirect-state.json").exists());
    assert!(!marker.exists());
    assert_eq!(std::fs::read(root.join("bun.lockb")).unwrap(), lockb_before);
    assert!(!root.join("bun.lock").exists());
}

/// A malformed binary lock beside package-lock.json reports its error
/// while preserving both the original binary and sibling bytes.
#[cfg(unix)]
#[tokio::test]
async fn malformed_bun_lockb_beside_package_lock_is_not_confirmed() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    let lockb_before = b"\x00stale-bun-lockb-debris".to_vec();
    std::fs::write(tmp.path().join("bun.lockb"), &lockb_before).unwrap();
    let (path_value, marker) = install_marker_bun_shim(tmp.path());
    let env = [("PATH", path_value.as_str())];

    // Dry-run reports the same binary-format error.
    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &["--dry-run"], &env);
    assert_eq!(code, 0, "dry-run exits 0: {doc:#}");
    assert_sibling_lock_outcome(
        &doc,
        tmp.path(),
        "package-lock.json",
        &lockb_before,
        &marker,
        true,
    );
    let lock_before = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        !lock_before.contains(HOSTED_URL),
        "dry-run must not rewrite the sibling lock"
    );

    // Live: both lockfiles stay unchanged and no process is spawned.
    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &env);
    assert_eq!(code, 0, "live run exits 0: {doc:#}");
    assert_sibling_lock_outcome(
        &doc,
        tmp.path(),
        "package-lock.json",
        &lockb_before,
        &marker,
        false,
    );
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(
        lock, lock_before,
        "a malformed primary binary must leave its sibling unchanged"
    );

    // Human leg (fresh project so the warning fires again): the
    // binary-warning loop prints the format detail.
    let tmp2 = tempfile::tempdir().unwrap();
    write_npm_project(tmp2.path(), NAME);
    std::fs::write(tmp2.path().join("bun.lockb"), &lockb_before).unwrap();
    let (path_value2, marker2) = install_marker_bun_shim(tmp2.path());
    let (code, _stdout, stderr) = scan_hosted(
        tmp2.path(),
        &server.uri(),
        &[],
        &[("PATH", path_value2.as_str())],
    );
    assert_eq!(code, 0, "human run exits 0; stderr=\n{stderr}");
    assert!(
        stderr.contains("bun.lockb"),
        "the sibling-lock detail must reach human stderr; stderr=\n{stderr}"
    );
    assert!(!marker2.exists(), "human leg: bun must never be spawned");
    assert_eq!(
        std::fs::read(tmp2.path().join("bun.lockb")).unwrap(),
        lockb_before
    );
}

/// A malformed primary binary likewise prevents changes to a pnpm sibling.
#[cfg(unix)]
#[tokio::test]
async fn malformed_bun_lockb_beside_pnpm_lock_is_not_confirmed() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let lock_before = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    let lockb_before = b"\x00stale-bun-lockb-debris".to_vec();
    std::fs::write(tmp.path().join("bun.lockb"), &lockb_before).unwrap();
    let (path_value, marker) = install_marker_bun_shim(tmp.path());
    let env = [("PATH", path_value.as_str())];

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &["--dry-run"], &env);
    assert_eq!(code, 0, "dry-run exits 0: {doc:#}");
    assert_sibling_lock_outcome(
        &doc,
        tmp.path(),
        "pnpm-lock.yaml",
        &lockb_before,
        &marker,
        true,
    );

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &env);
    assert_eq!(code, 0, "live run exits 0: {doc:#}");
    assert_sibling_lock_outcome(
        &doc,
        tmp.path(),
        "pnpm-lock.yaml",
        &lockb_before,
        &marker,
        false,
    );
    let lock = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    assert_eq!(
        lock, lock_before,
        "a malformed primary binary must leave its sibling unchanged"
    );
}

// ───────────── live unreadable pnpm-workspace.yaml fallback ─────────────

/// Production wiring of the present-but-unreadable pnpm-workspace.yaml arm
/// (the exact seam where a Create once overwrote the user's workspace file):
/// a LIVE hosted run over a v9 pnpm lock with an unreadable workspace file
/// must still rewrite the lock, fall back to warning-only guidance naming
/// the file and the error, and leave the user's workspace bytes untouched.
#[cfg(unix)]
#[tokio::test]
async fn unreadable_pnpm_workspace_gets_warning_only_guidance_in_a_live_run() {
    use std::os::unix::fs::PermissionsExt;
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let ws = tmp.path().join("pnpm-workspace.yaml");
    let user_bytes = "packages:\n  - 'apps/*'\n";
    std::fs::write(&ws, user_bytes).unwrap();
    std::fs::set_permissions(&ws, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&ws).is_ok() {
        println!("SKIP: running as root — chmod 000 cannot make the workspace unreadable");
        return;
    }

    let (code, doc) =
        scan_hosted_json(tmp.path(), &server.uri(), &["--allow-patch-conflicts"], &[]);
    // Restore before asserting so the tempdir cleans up and the bytes can
    // be read back.
    std::fs::set_permissions(&ws, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        code, 0,
        "the fallback is warning-only, never an error: {doc:#}"
    );
    let detail = warning_detail(&doc, "redirect_pnpm_trust_lockfile");
    assert!(
        detail.contains("pnpm-workspace.yaml")
            && detail.contains(&std::io::Error::from_raw_os_error(libc::EACCES).to_string()),
        "the fallback must name the unreadable file and its read error: {detail}"
    );
    // The lock rewrite itself still landed.
    let lock = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    assert!(
        lock.contains(&format!("tarball: {HOSTED_URL}")),
        "the redirect must land despite the workspace fallback:\n{lock}"
    );
    assert_eq!(hosted_pins(&doc).len(), 1, "envelope: {doc:#}");
    // FINDING-5 seam: the user's workspace file was NOT overwritten with the
    // root-only scaffold.
    assert_eq!(
        std::fs::read_to_string(&ws).unwrap(),
        user_bytes,
        "the unreadable workspace file must be left byte-identical"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "v5 hosted mode writes no redirect ledger"
    );
}

// ──────────── redirect_supersedes_vendored (+ human) ────────────

/// The hosted-direction takeover warning: a LIVE lock routing package X to
/// its hosted artifact (a lockfile hosted pin — v5 hosted state) while the
/// vendored ledger still claims X must fire `redirect_supersedes_vendored` naming X — the
/// only signal that X's vendored ledger entry and committed tarball are now
/// orphaned. A DIFFERENT package Y is granted this run so the takeover
/// pre-revert never consumes X's vendored entry. The human render is pinned
/// in `hosted_render.rs`.
#[tokio::test]
async fn live_hosted_overlap_fires_redirect_supersedes_vendored() {
    const XPURL: &str = SUPER_X_PURL;
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await; // grants Y (= NAME) only
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_superseded_vendored_project(root);

    let psu = ["--patch-server-url", "http://patch.test"];
    let (code, doc) = scan_hosted_json(root, &server.uri(), &psu, &[]);
    assert_eq!(
        code, 0,
        "the overlap warning never flips the exit code: {doc:#}"
    );
    assert_eq!(
        hosted_pins(&doc).len(),
        1,
        "anchor: Y must redirect normally: {doc:#}"
    );
    let detail = warning_detail(&doc, "redirect_supersedes_vendored");
    assert!(
        detail.contains(XPURL),
        "the superseded package must be named: {detail}"
    );
    assert!(
        detail.contains("socket-patch remove"),
        "the per-package remediation must be prescribed: {detail}"
    );
    // Warn-only contract: the stale vendored ledger is NOT deleted.
    let state = std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap();
    assert!(
        state.contains(XPURL),
        "the takeover warning must not delete the other mode's ledger: {state}"
    );
}

/// `--json` `--vex` run: VEX advisories are muted on stderr under --json,
/// so the hosted envelope's `vex.warnings` must carry them (after the
/// `vex_hosted_unverified` advisory every hosted attestation carries).
#[tokio::test]
async fn json_vex_block_carries_the_vex_run_warnings() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);

    let (code, v) = scan_hosted_json(
        tmp.path(),
        &server.uri(),
        &["--vex", "out.vex.json", "--vex-product", "consumer"],
        &[],
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["vex"]["statements"], 1, "{v}");
    let warnings = v["vex"]["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("{v}"));
    // v5.0: a hosted attestation always leads with `vex_hosted_unverified`
    // (its pins are attested from their records, not hash-verified).
    assert_eq!(warnings.len(), 2, "{v}");
    assert_eq!(warnings[0]["code"], "vex_hosted_unverified", "{v}");
    assert_eq!(warnings[1]["code"], "product_not_iri", "{v}");
    let detail = warnings[1]["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("\"consumer\"") && detail.contains("--vex-product"),
        "the advisory names the value and the flag: {v}"
    );

    // A clean product: no `warnings` key at all.
    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    let (code, v) = scan_hosted_json(
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
    assert_eq!(code, 0, "{v}");
    let codes: Vec<&str> = v["vex"]["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("{v}"))
        .iter()
        .filter_map(|w| w["code"].as_str())
        .collect();
    assert_eq!(codes, ["vex_hosted_unverified"], "{v}");
}

// ───────── ledger save failure after a successful revert ─────────

/// The vendored ledger cannot be updated (`.socket/vendor` itself is
/// read-only, 0o555): the takeover's revert, the hosted pin and the ledger
/// are one commit, which then fails before it replaces anything. The run
/// fails (exit 1) and NOTHING changed — the lock, the ledger and the
/// artifact are byte-identical, so the package stays vendored and patched.
/// Before the staged takeover, the revert was already on disk, leaving the
/// package unpatched in both modes.
#[cfg(unix)]
#[tokio::test]
async fn ledger_save_failure_after_successful_revert_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    /// Restore the vendor dir's mode even on assertion panic, so the
    /// tempdir can clean up.
    struct ModeGuard(std::path::PathBuf);
    impl Drop for ModeGuard {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }

    const VUUID: &str = "99999999-9999-4999-8999-999999999999";
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, NAME);
    write_vendor_state(root, PURL, VUUID, "package-lock");
    // The artifact dir the successful revert removes (its parent
    // `.socket/vendor/npm` stays writable).
    let artifact_dir = root.join(".socket/vendor/npm").join(VUUID);
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join(format!("{NAME}-{VERSION}.tgz")), b"tgz").unwrap();
    let lock_before = std::fs::read(root.join("package-lock.json")).unwrap();
    let state_before = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();

    let vendor_dir = root.join(".socket/vendor");
    std::fs::set_permissions(&vendor_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let _guard = ModeGuard(vendor_dir.clone());
    // Root ignores mode bits: probe with a real write attempt.
    if std::fs::write(vendor_dir.join(".covgap-write-probe"), b"x").is_ok() {
        let _ = std::fs::remove_file(vendor_dir.join(".covgap-write-probe"));
        println!("SKIP: running as root — chmod 555 cannot make the ledger unwritable");
        return;
    }

    let (code, doc) = scan_hosted_json(root, &server.uri(), &[], &[]);

    assert_eq!(code, 1, "the failed commit fails the run: {doc:#}");
    assert_eq!(doc["status"], "error", "envelope: {doc:#}");
    assert_eq!(
        envelope_error_code(&doc),
        Some("lockfile_write_failed"),
        "{doc:#}"
    );
    assert!(
        !all_codes(&doc)
            .iter()
            .any(|c| c == "redirect_takeover_unpatched"),
        "{doc:#}"
    );
    assert_eq!(
        std::fs::read(root.join("package-lock.json")).unwrap(),
        lock_before,
        "no redirect lands"
    );
    assert_eq!(
        std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
        state_before,
        "the ledger still claims the package"
    );
    assert!(
        artifact_dir.join(format!("{NAME}-{VERSION}.tgz")).exists(),
        "the artifact is kept"
    );
}

// ───────────────────────────── vlt ─────────────────────────────

/// A vendored vlt entry over a lock vlt cannot read (here a BOM) is never
/// taken over: the staged revert refuses the unreadable lock itself, so the
/// purl is skipped and the vendored ledger and the lock stay byte-identical.
#[tokio::test]
async fn vlt_takeover_refusal_before_revert() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    std::fs::remove_file(tmp.path().join("package-lock.json")).unwrap();
    let lock = format!(
        "\u{feff}{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n    \
         \"~npm~{NAME}@{VERSION}\": [0,\"{NAME}\",\"{UPSTREAM_SHA512}\",\"https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz\"]\n  }},\n  \"edges\": {{}}\n}}\n"
    );
    std::fs::write(tmp.path().join("vlt-lock.json"), &lock).unwrap();
    write_vendor_state(tmp.path(), PURL, UUID, "vlt");
    let state_before = std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap();

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);

    assert_eq!(code, 0, "{doc:#}");
    assert_eq!(hosted_pins(&doc).len(), 0, "{doc:#}");
    assert!(
        Some(&hosted_skipped(&doc)).is_some_and(|s| s
            .iter()
            .any(|e| e["purl"] == PURL && e["reason"] == "vendored_revert_failed")),
        "{doc:#}"
    );
    assert!(warning_detail(&doc, "redirect_vendored_revert_failed").contains("vlt-lock.json"));
    assert!(
        !codes_in(&doc["warnings"]).contains(&"redirect_takeover_reverted_vendored".to_string())
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap(),
        state_before
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("vlt-lock.json")).unwrap(),
        lock
    );
}

/// With `bun.lockb` beside a vlt-driven `vlt-lock.json`, the vlt rules
/// decide npm confirmation before the binary-bun rule: the binary rewrite
/// lands, but the vlt rewriter refused the dep, so it is not confirmed.
#[tokio::test]
async fn vlt_decides_before_binary_bun_and_a_refused_uuid_is_never_confirmed() {
    use base64::Engine as _;
    use sha2::Digest as _;
    let purl = "pkg:npm/minimist@1.2.2";
    let body = b"minimist tarball".to_vec();
    let sri = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&body))
    );
    let server = MockServer::start().await;
    let url = format!("{}/patch/npm/minimist-1.2.2.tgz", server.uri());
    mock_discovery(&server, purl, UUID).await;
    mock_reference_results(
        &server,
        json!({ UUID: {
            "status": "granted", "url": url, "purl": purl,
            "artifacts": [{"kind": "tarball", "url": url, "integrity": {"sha512": sri}}],
            "registryOverride": null,
        }}),
    )
    .await;
    mock_view(&server, UUID, purl).await;
    Mock::given(method("GET"))
        .and(path("/patch/npm/minimist-1.2.2.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(&server)
        .await;

    let run = |off_grammar: bool| {
        let tmp = tempfile::tempdir().unwrap();
        let original =
            include_bytes!("../../../socket-patch-core/tests/fixtures/bun-lockb/1.1.45/bun.lockb");
        std::fs::write(tmp.path().join("bun.lockb"), original).unwrap();
        std::fs::write(
            tmp.path().join("package.json"),
            include_bytes!(
                "../../../socket-patch-core/tests/fixtures/bun-lockb/1.1.45/package.json"
            ),
        )
        .unwrap();
        let space = if off_grammar { " " } else { "" };
        std::fs::write(
            tmp.path().join("vlt-lock.json"),
            format!(
                "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n    \
                 \"~npm~is-number@7.0.0\": [0,\"is-number\"],\n    \
                 \"~npm~minimist@1.2.2\": [0,{space}\"minimist\",\"{UPSTREAM_SHA512}\",\"https://registry.npmjs.org/minimist/-/minimist-1.2.2.tgz\"]\n  }},\n  \"edges\": {{}}\n}}\n"
            ),
        )
        .unwrap();
        let pkg = tmp.path().join("node_modules/minimist");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{ "name": "minimist", "version": "1.2.2" }"#,
        )
        .unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules/.vlt")).unwrap();
        let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[("PATH", "")]);
        assert_eq!(code, 0, "{doc:#}");
        (doc, tmp)
    };

    let (refused, tmp) = run(true);
    assert!(
        codes_in(&refused["warnings"]).contains(&"redirect_vlt_unsupported_lock_key".to_string()),
        "{refused:#}"
    );
    assert!(
        refused["redirect"]["rewrittenFiles"]
            .as_array()
            .unwrap()
            .contains(&json!("bun.lockb")),
        "the binary lock is still rewritten: {refused:#}"
    );
    assert_eq!(hosted_pins(&refused).len(), 0, "{refused:#}");
    drop(tmp);

    let (confirmed, _tmp) = run(false);
    assert_eq!(hosted_pins(&confirmed).len(), 1, "{confirmed:#}");
}

/// REGRESSION (#899): npm 12 never reads npm-shrinkwrap.json. A project
/// whose only npm lock is the shrinkwrap is still redirected (npm <= 11
/// installs from it), but the run warns `redirect_npm_shrinkwrap_only` —
/// in `--json` and on human stderr — and the in-run `--vex` attests nothing
/// for it (`vex_npm_shrinkwrap_only`), as a lockfile-only `vex` does.
#[tokio::test]
async fn shrinkwrap_only_project_warns_npm12_ignores_it_and_vex_omits_it() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    mock_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    mock_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path(), NAME);
    std::fs::rename(
        tmp.path().join("package-lock.json"),
        tmp.path().join("npm-shrinkwrap.json"),
    )
    .unwrap();

    let (code, doc) = scan_hosted_json(
        tmp.path(),
        &server.uri(),
        &[
            "--vex",
            "out.vex.json",
            "--vex-product",
            "pkg:npm/consumer@0.0.0",
            "--patch-server-url",
            "http://patch.test",
        ],
        &[],
    );
    // Still redirected: npm <= 11 installs from the shrinkwrap.
    assert_eq!(hosted_pins(&doc).len(), 1, "{doc:#}");
    let lock = std::fs::read_to_string(tmp.path().join("npm-shrinkwrap.json")).unwrap();
    assert!(lock.contains(HOSTED_URL), "{lock}");
    assert!(
        !tmp.path().join("package-lock.json").exists(),
        "no package-lock.json is invented"
    );
    let detail = warning_detail(&doc, "redirect_npm_shrinkwrap_only");
    for needle in ["covgap-hosted@1.0.0", "npm >= 12", "no package-lock.json"] {
        assert!(detail.contains(needle), "{needle}: {detail}");
    }
    // The in-run VEX omits it, so the requested VEX fails the run.
    assert_eq!(code, 1, "{doc:#}");
    assert_eq!(doc["error"]["code"], "no_applicable_patches", "{doc:#}");
    assert!(
        doc["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w["code"] == "vex_npm_shrinkwrap_only"
                && w["detail"].as_str().is_some_and(|d| d.contains(PURL)))),
        "{doc:#}"
    );
    assert!(!tmp.path().join("out.vex.json").exists());

    // With the package-lock.json twin npm 12 reads, the re-run rewires it
    // too, the warning is gone and the in-run VEX attests.
    std::fs::copy(
        tmp.path().join("npm-shrinkwrap.json"),
        tmp.path().join("package-lock.json"),
    )
    .unwrap();
    let (code, doc) = scan_hosted_json(
        tmp.path(),
        &server.uri(),
        &[
            "--vex",
            "out.vex.json",
            "--vex-product",
            "pkg:npm/consumer@0.0.0",
            "--patch-server-url",
            "http://patch.test",
        ],
        &[],
    );
    assert_eq!(code, 0, "{doc:#}");
    assert!(
        !codes_in(&doc["warnings"]).contains(&"redirect_npm_shrinkwrap_only".to_string()),
        "{doc:#}"
    );
    assert_eq!(doc["vex"]["statements"], 1, "{doc:#}");
}

// ───────────────── yarn classic berry-migration advisory ─────────────────

/// #907: a hosted pin in a classic yarn.lock is dropped by the next yarn 2+
/// (berry) install exactly like vendored wiring, so `scan --mode hosted`
/// must warn `redirect_yarn_classic_berry_migration_risk` — on a dry run, on
/// the wet run and on an idempotent re-run — when package.json declares no
/// package manager or a berry one.
#[tokio::test]
async fn hosted_yarn_classic_pin_warns_berry_migration_risk() {
    for package_manager in [None, Some("yarn@4.18.1")] {
        let server = MockServer::start().await;
        mock_discovery(&server, PURL, UUID).await;
        let hosted_url = mock_served_classic_reference(&server).await;
        mock_view(&server, UUID, PURL).await;
        let tmp = tempfile::tempdir().unwrap();
        write_yarn_classic_project(tmp.path(), package_manager);

        for (label, extra) in [
            ("dry run", &["--dry-run"][..]),
            ("wet run", &[][..]),
            ("re-run", &[][..]),
        ] {
            let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), extra, &[]);
            assert_eq!(code, 0, "{package_manager:?} {label}: {doc:#}");
            let codes = codes_in(&doc["warnings"]);
            assert_eq!(
                codes
                    .iter()
                    .filter(|c| *c == "redirect_yarn_classic_berry_migration_risk")
                    .count(),
                1,
                "{package_manager:?} {label}: exactly one advisory: {codes:?}"
            );
            let detail = warning_detail(&doc, "redirect_yarn_classic_berry_migration_risk");
            assert!(detail.contains("yarn 2+"), "{detail}");
        }
        let lock = std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap();
        assert!(
            lock.contains(&hosted_url),
            "the warning never blocks the pin: {lock}"
        );
    }
}

/// #907: a corepack `packageManager: yarn@1…` pin makes a stray berry
/// install refuse instead of migrate, so hosted stays silent, as vendored
/// does.
#[tokio::test]
async fn hosted_yarn_classic_pin_with_yarn1_package_manager_stays_silent() {
    let server = MockServer::start().await;
    mock_discovery(&server, PURL, UUID).await;
    let hosted_url = mock_served_classic_reference(&server).await;
    mock_view(&server, UUID, PURL).await;
    let tmp = tempfile::tempdir().unwrap();
    write_yarn_classic_project(tmp.path(), Some("yarn@1.22.22"));

    let (code, doc) = scan_hosted_json(tmp.path(), &server.uri(), &[], &[]);
    assert_eq!(code, 0, "{doc:#}");
    let codes = codes_in(&doc["warnings"]);
    assert!(
        !codes
            .iter()
            .any(|c| c == "redirect_yarn_classic_berry_migration_risk"),
        "a yarn 1 pin suppresses the advisory: {codes:?}"
    );
    let lock = std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap();
    assert!(lock.contains(&hosted_url), "{lock}");
}
