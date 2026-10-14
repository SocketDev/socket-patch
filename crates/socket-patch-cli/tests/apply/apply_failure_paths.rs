//! `apply`'s `--json` contracts for the paths the rest of the suite never
//! drove (#1089): exit code, `status`, `error.code`, `events[]` and the
//! bytes on disk. A message is read only for what it must name (a module,
//! a path, which drift arm fired). The human output of the same paths is
//! pinned in `apply_render.rs`.
//!
//!   1. `apply --check --json`: the in-sync success envelope and the
//!      `go_redirect_drift` Failed events, including the `OrphanReplace`
//!      and `WrongReplacePath` arms;
//!   2. `reconcile_local_go` pruning (or, dry, keeping) a stale redirect;
//!   3. the empty-manifest no-op, the no-matching-package skip, the
//!      dry-run `already_patched` skip, the per-package `apply_failed`
//!      events and the yarn-PnP refusal next to a corrupt manifest;
//!   4. apply-loop wiring: a vendored release-variant base with its
//!      installed tree PRESENT is skipped (not re-patched), a qualified
//!      singleton whose record holds only NEW files is applied, and a
//!      ledger-only vendored project is the `noManifest` no-op;
//!   5. `apply --dry-run --vex` writes no attestation.

use serde_json::json;

use crate::apply_fixture::*;
use crate::common::envelope::{
    envelope_error_code, event_triples, events, find_event, has_event, json_string,
    parse_json_envelope,
};
use crate::common::git_sha256;

/// The `reason` of an `OrphanReplace` drift event: it shares
/// `go_redirect_drift` with the other drift arms.
const ORPHAN_REPLACE: &str = "orphan go.mod `replace`";

// ═══════════════════ 1. `--check --json` envelopes ═══════════════════

/// `apply --check --json` WITH drift: one Failed event per drift with
/// `errorCode: go_redirect_drift`, status `partialFailure`, exit 1.
#[test]
fn check_json_with_drift_emits_failed_events_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    write_drifted_go_manifest(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--check", "--json"], &[]);
    assert_eq!(code, 1, "drift must exit 1; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(json_string(&env, "command"), Some("apply"), "{env}");
    assert_eq!(json_string(&env, "status"), Some("partialFailure"), "{env}");
    let triples = event_triples(&env);
    assert!(
        !triples.is_empty(),
        "drift must be reported as events: {env}"
    );
    for (purl, action, code) in triples {
        assert_eq!(
            (purl.as_str(), action.as_str(), code.as_str()),
            (GO_PURL, "failed", "go_redirect_drift"),
            "{env}"
        );
    }
}

/// `apply --check --json` with NO drift: the in-sync success envelope.
#[test]
fn check_json_in_sync_emits_success_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--check", "--json"], &[]);
    assert_eq!(code, 0, "in-sync check must exit 0; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(json_string(&env, "command"), Some("apply"), "{env}");
    assert_eq!(json_string(&env, "status"), Some("success"), "{env}");
    assert!(events(&env).is_empty(), "no drift, no events: {env}");
}

/// A socket-owned `replace` for a module the manifest no longer patches:
/// the `OrphanReplace` arm. Its event is keyed by the module, not a purl.
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

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--check", "--json"], &[]);
    assert_eq!(code, 1, "an orphan replace is drift; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(
        event_triples(&env),
        vec![(
            "example.com/other".to_string(),
            "failed".to_string(),
            "go_redirect_drift".to_string()
        )],
        "{env}"
    );
    let reason = events(&env)[0]["reason"].as_str().unwrap_or_default();
    assert!(reason.contains(ORPHAN_REPLACE), "{env}");
}

/// A healthy copy but a socket-owned `replace` pinned at the WRONG target
/// path: the `WrongReplacePath` arm. The copy hashes clean, so this drift
/// is the only finding: go keys `replace` by module+version+path and would
/// silently ignore the directive.
#[test]
fn check_reports_wrong_replace_path_drift() {
    let patched = b"patched go content\n";
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(
        tmp.path(),
        json!({
            GO_PURL: patch_record(
                "61616161-6161-4161-8161-616161616161",
                one_file("file.go", b"original go content\n", patched),
            )
        }),
    );
    let copy_dir = tmp.path().join(GO_COPY_DIR);
    std::fs::create_dir_all(&copy_dir).unwrap();
    std::fs::write(copy_dir.join("file.go"), patched).unwrap();
    std::fs::write(
        tmp.path().join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\n\
         replace example.com/mod v1.0.0 => ./.socket/go-patches/example.com/mod@v0.0.9\n",
    )
    .unwrap();

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--check", "--json"], &[]);
    assert_eq!(code, 1, "a mispointed replace is drift; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    // The copy validated, so the directive is the ONLY drift: a fixture
    // regression that broke the copy would add MissingCopy/StaleCopy events.
    assert_eq!(
        event_triples(&env),
        vec![(
            GO_PURL.to_string(),
            "failed".to_string(),
            "go_redirect_drift".to_string()
        )],
        "{env}"
    );
    let reason = events(&env)[0]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("./.socket/go-patches/example.com/mod@v0.0.9"),
        "the event must name the found target: {env}"
    );
    assert!(
        reason.contains("./.socket/go-patches/example.com/mod@v1.0.0"),
        "the event must name the expected target: {env}"
    );
}

// ═══════════ 2. reconcile_local_go: stale redirect pruning ═══════════

/// A wet apply prunes the orphaned redirect: the directive leaves `go.mod`
/// and the copy dir is deleted, as a clean no-op.
#[test]
fn reconcile_prunes_stale_go_redirect() {
    let tmp = tempfile::tempdir().unwrap();
    write_stale_go_redirect(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--json"], &[]);
    assert_eq!(
        code, 0,
        "pruning an orphan is a clean no-op; stderr={stderr}"
    );
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(json_string(&env, "status"), Some("success"), "{env}");
    let go_mod = std::fs::read_to_string(tmp.path().join("go.mod")).unwrap();
    assert!(
        !go_mod.contains("replace"),
        "the orphaned directive must be dropped; go.mod={go_mod}"
    );
    assert!(
        !tmp.path().join(GO_COPY_DIR).exists(),
        "the orphaned copy dir must be pruned"
    );
}

/// `--dry-run` mutates NOTHING: `go.mod` stays byte-identical and the
/// copy dir survives.
#[test]
fn reconcile_dry_run_touches_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let original_go_mod = write_stale_go_redirect(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--dry-run", "--json"], &[]);
    assert_eq!(
        code, 0,
        "dry-run reconcile is a clean no-op; stderr={stderr}"
    );
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(json_string(&env, "status"), Some("success"), "{env}");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("go.mod")).unwrap(),
        original_go_mod,
        "dry-run must leave go.mod byte-identical"
    );
    assert!(
        tmp.path().join(GO_COPY_DIR).exists(),
        "dry-run must keep the copy dir"
    );
}

// ═══════════ 3. no-op, skip and failure envelopes ═══════════

/// An empty manifest is the clean no-op: success, no events, exit 0.
#[test]
fn empty_manifest_is_a_clean_no_op() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), json!({}));

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--json"], &[]);
    assert_eq!(
        code, 0,
        "an empty manifest is a clean no-op; stderr={stderr}"
    );
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(json_string(&env, "status"), Some("success"), "{env}");
    assert!(events(&env).is_empty(), "{env}");
}

/// Zero packages match an in-scope patch (nothing installed): the patch
/// is skipped as `package_not_installed` and the run exits 1.
#[test]
fn no_matching_package_is_skipped_and_fails_the_run() {
    let tmp = tempfile::tempdir().unwrap();
    write_npm_patch(tmp.path(), "ghost", "63636363-6363-4363-8363-636363636363");

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--json"], &[]);
    assert_eq!(
        code, 1,
        "an in-scope patch with no installed package fails the run; stderr={stderr}"
    );
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(json_string(&env, "status"), Some("partialFailure"), "{env}");
    assert!(
        has_event(
            &env,
            "skipped",
            "package_not_installed",
            "pkg:npm/ghost@1.0.0"
        ),
        "{env}"
    );
}

/// Applying then dry-running the same fixture skips the package as
/// `already_patched` and applies nothing.
#[test]
fn dry_run_after_apply_skips_already_patched() {
    let tmp = tempfile::tempdir().unwrap();
    write_npm_patch(tmp.path(), "twice", "64646464-6464-4464-8464-646464646464");
    let file = install_npm_pkg(tmp.path(), "twice", "1.0.0", Some(MM_BEFORE));

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--json"], &[]);
    assert_eq!(code, 0, "the wet apply must succeed; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    find_event(&env, "applied", None);
    assert_eq!(
        std::fs::read(&file).unwrap(),
        MM_AFTER,
        "the wet apply must patch the file"
    );

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--dry-run", "--json"], &[]);
    assert_eq!(
        code, 0,
        "the dry-run re-check must succeed; stderr={stderr}"
    );
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(
        event_triples(&env),
        vec![(
            "pkg:npm/twice@1.0.0".to_string(),
            "skipped".to_string(),
            "already_patched".to_string()
        )],
        "{env}"
    );
    assert_eq!(env["summary"]["applied"], 0, "{env}");
}

/// `--dry-run --strict` over three single-file packages: the
/// already-patched one is skipped, the hash-mismatched and file-missing
/// ones fail with `apply_failed`, and nothing on disk changes.
#[test]
fn strict_dry_run_fails_mismatched_and_missing_packages() {
    let tmp = tempfile::tempdir().unwrap();
    write_three_state_npm_project(tmp.path());

    let (code, stdout, stderr) = run_apply(
        tmp.path(),
        &["--offline", "--dry-run", "--strict", "--json"],
        &[],
    );
    assert_eq!(code, 1, "strict must fail the run; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(json_string(&env, "status"), Some("partialFailure"), "{env}");
    assert!(
        has_event(&env, "skipped", "already_patched", "pkg:npm/valready@1.0.0"),
        "{env}"
    );
    assert!(
        has_event(&env, "failed", "apply_failed", "pkg:npm/vmismatch@1.0.0"),
        "{env}"
    );
    assert!(
        has_event(&env, "failed", "apply_failed", "pkg:npm/vmissing@1.0.0"),
        "{env}"
    );
    let index = |name: &str| tmp.path().join("node_modules").join(name).join("index.js");
    assert_eq!(std::fs::read(index("vmismatch")).unwrap(), MM_LOCAL);
    assert!(!index("vmissing").exists());
}

/// A corrupt manifest under a yarn-PnP layout falls through to the
/// ordinary `manifest_invalid` error, NOT the misdirected
/// `yarn_pnp_unsupported` refusal (`manifest_targets_npm`'s `_ => false`
/// arm). Anti-vacuity: the same layout WITH a readable npm-targeting
/// manifest does refuse, and so does `--check`.
#[test]
fn corrupt_manifest_under_pnp_layout_reports_manifest_error_not_refusal() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".socket")).unwrap();
    std::fs::write(tmp.path().join(".socket/manifest.json"), "{ not json").unwrap();
    std::fs::write(tmp.path().join(".pnp.cjs"), "// pnp loader stub\n").unwrap();

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--json"], &[]);
    assert_eq!(code, 1, "a corrupt manifest must fail; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(envelope_error_code(&env), Some("manifest_invalid"), "{env}");

    let tmp = tempfile::tempdir().unwrap();
    write_pnp_npm_project(tmp.path());
    for extra in [None, Some("--check")] {
        let mut args = vec!["--offline", "--json"];
        args.extend(extra);
        let (code, stdout, stderr) = run_apply(tmp.path(), &args, &[]);
        assert_eq!(
            code, 1,
            "{args:?}: PnP + npm patch must refuse; stderr={stderr}"
        );
        let env = parse_json_envelope(stdout.trim());
        assert_eq!(
            envelope_error_code(&env),
            Some("yarn_pnp_unsupported"),
            "{args:?}: {env}"
        );
    }
}

// ═══════════ 4. apply-loop wiring ═══════════

/// A vendored release-variant base WITH its installed tree present must be
/// skipped by the apply loop: only the synthesized `skipped`/`vendored`
/// event, no re-patch of the installed bytes, no `package_not_installed`
/// noise.
#[test]
fn vendored_gem_base_with_installed_tree_is_skipped_not_repatched() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let uuid = "70707070-7070-4070-8070-707070707070";
    let file = write_gem_patch(root, uuid, b"# SOCKET-VENDORED-PATCH\n");
    // Vendor ledger claiming the purl: the entries shape from
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

    let (code, stdout, stderr) =
        run_apply(root, &["--offline", "--ecosystems", "gem", "--json"], &[]);
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(
        code, 0,
        "a vendor-owned base is a clean skip; {env}\nstderr={stderr}"
    );
    assert_eq!(json_string(&env, "status"), Some("success"), "{env}");
    assert_eq!(
        event_triples(&env),
        vec![(
            GEM_BASE_PURL.to_string(),
            "skipped".to_string(),
            "vendored".to_string()
        )],
        "exactly one synthesized event for the vendored base: {env}"
    );
    assert_eq!(
        std::fs::read(&file).unwrap(),
        GEM_PRISTINE,
        "the loop-level skip must prevent a re-patch of the installed tree"
    );
}

/// Vendored mode is manifest-free: a project vendored by `scan`/`get --mode
/// vendored` has ONLY `.socket/vendor/state.json` (detached entries with
/// embedded records) and no manifest. The hooked `apply` on such a project
/// is the calm `noManifest` no-op: it never reads the ledger, never takes
/// the lock (so never creates `apply.lock`) and leaves `.socket/` exactly as
/// it found it.
#[test]
fn apply_on_ledger_only_vendored_project_is_a_no_manifest_no_op() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_root_package_json(root);
    let uuid = "80808080-8080-4080-8080-808080808080";
    let vendor_dir = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    let ledger = serde_json::to_vec_pretty(&json!({
        "version": 1,
        "entries": { "pkg:npm/vend-only@1.0.0": {
            "ecosystem": "npm",
            "basePurl": "pkg:npm/vend-only@1.0.0",
            "uuid": uuid,
            "artifact": { "path": format!(".socket/vendor/npm/{uuid}/vend-only-1.0.0.tgz") },
            "wiring": [],
            "detached": true,
            "record": patch_record(uuid, one_file("package/index.js", MM_BEFORE, MM_AFTER)),
        }}
    }))
    .unwrap();
    std::fs::write(vendor_dir.join("state.json"), &ledger).unwrap();

    let (code, stdout, stderr) = run_apply(root, &["--json"], &[]);
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(code, 0, "{env}\nstderr={stderr}");
    assert_eq!(json_string(&env, "status"), Some("noManifest"), "{env}");
    assert!(events(&env).is_empty(), "{env}");

    let mut names: Vec<String> = std::fs::read_dir(root.join(".socket"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["vendor"],
        "apply must not touch .socket/ on a manifest-less project (no manifest, \
         no blobs/, no apply.lock)"
    );
    assert_eq!(
        std::fs::read(vendor_dir.join("state.json")).unwrap(),
        ledger,
        "the ledger survives byte-identical"
    );
}

/// A QUALIFIED gem singleton whose record holds only NEW files (empty
/// `beforeHash` ⇒ no representative file) has nothing to disqualify it:
/// the gated apply loop must treat it as installed, attempt it, and
/// CREATE the new file from the staged blob.
#[test]
fn qualified_singleton_with_only_new_files_is_attempted_and_applied() {
    const SHIM: &[u8] = b"# security shim injected by socket-patch\n";
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // Installed gem WITHOUT the new file (lib/rack.rb only anchors the
    // crawler's discovery; it is not in the record).
    let gem_file = install_gem(root, "rack-3.1.0", "lib/rack.rb", GEM_PRISTINE);
    let shim_path = gem_file.parent().unwrap().join("new_shim.rb");
    assert!(!shim_path.exists());
    let after_hash = git_sha256(SHIM);
    write_manifest(
        root,
        json!({
            GEM_QUALIFIED_PURL: patch_record(
                "71717171-7171-4171-8171-717171717171",
                json!({ "lib/new_shim.rb": { "beforeHash": "", "afterHash": after_hash } }),
            )
        }),
    );
    stage_blob(root, &after_hash, SHIM);

    let (code, stdout, stderr) =
        run_apply(root, &["--offline", "--ecosystems", "gem", "--json"], &[]);
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(
        code, 0,
        "a no-representative variant must apply cleanly; {env}\nstderr={stderr}"
    );
    assert_eq!(json_string(&env, "status"), Some("success"), "{env}");
    assert!(
        events(&env)
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == GEM_QUALIFIED_PURL),
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

// ═══════════ 5. dry-run --vex ═══════════

/// `apply --dry-run --vex <path>`: nothing was applied, so no attestation
/// file is written and the package is left alone.
#[test]
fn dry_run_with_vex_writes_no_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let file = write_gem_patch(
        root,
        "72727272-7272-4272-8272-727272727272",
        b"# SOCKET-VEX-PATCH\n",
    );
    let vex_path = root.join("out.vex.json");

    let (code, stdout, stderr) = run_apply(
        root,
        &[
            "--offline",
            "--ecosystems",
            "gem",
            "--dry-run",
            "--json",
            "--vex",
            vex_path.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(code, 0, "the dry-run verify must succeed; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(json_string(&env, "status"), Some("success"), "{env}");
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
