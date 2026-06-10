//! End-to-end: `socket-patch apply` against a yarn-berry PnP layout
//! must refuse with a clear `errorCode: yarn_pnp_unsupported`.
//!
//! yarn-berry's Plug'n'Play mode keeps packages inside
//! `.yarn/cache/*.zip` and resolves them via a custom Node loader
//! (`.pnp.cjs`). socket-patch cannot rewrite bytes inside a zip in
//! place; the right move is to refuse with a clear pointer to
//! `yarn patch`.
//!
//! The matching unit tests
//! (`crates/socket-patch-core/src/crawlers/pkg_managers.rs`) pin the
//! detection table. This test composes the detection with the apply
//! CLI to verify the end-to-end refusal.
//!
//! Network: no. Toolchain: no. NOT `#[ignore]` — runs on every PR.

use std::path::{Path, PathBuf};

#[path = "common/mod.rs"]
mod common;

use common::{
    assert_run_ok, envelope_error_code, envelope_error_message, git_sha256, json_string,
    parse_json_envelope, run, write_blob, write_minimal_manifest, PatchEntry,
};

const PURL: &str = "pkg:npm/dummy@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const ORIGINAL_BYTES: &[u8] = b"module.exports = function() { return 'before'; };\n";
const PATCHED_BYTES: &[u8] = b"module.exports = function() { return 'after'; };\n";

/// Stage a *fully patchable, offline-ready* npm package under `cwd`:
///   * `node_modules/dummy/{package.json,index.js}` matching [`PURL`],
///   * `.socket/manifest.json` recording the real before/after Git
///     hashes of [`ORIGINAL_BYTES`] → [`PATCHED_BYTES`], and
///   * the after-hash blob staged under `.socket/blobs/` so `apply`
///     can run to completion with no network.
///
/// This is the load-bearing part of the refusal tests: because the
/// package is genuinely applicable, a `socket-patch apply` that did
/// NOT refuse on the yarn-PnP layout would actually rewrite
/// `index.js`. The refusal tests therefore assert the file stays
/// byte-identical — proving the refusal short-circuits *before* the
/// patch engine touches anything, not merely that apply found nothing
/// to do.
///
/// Returns the absolute path to the patchable `index.js`.
fn stage_applicable_package(cwd: &Path) -> PathBuf {
    let pkg = cwd.join("node_modules").join("dummy");
    std::fs::create_dir_all(&pkg).expect("create node_modules/dummy");
    std::fs::write(
        pkg.join("package.json"),
        r#"{"name":"dummy","version":"1.0.0"}"#,
    )
    .expect("write dummy package.json");
    let index = pkg.join("index.js");
    std::fs::write(&index, ORIGINAL_BYTES).expect("write index.js");

    let socket = cwd.join(".socket");
    let before_hash = git_sha256(ORIGINAL_BYTES);
    let after_hash = git_sha256(PATCHED_BYTES);
    write_minimal_manifest(
        &socket,
        PURL,
        UUID,
        &[PatchEntry {
            file_name: "package/index.js",
            before_hash: &before_hash,
            after_hash: &after_hash,
        }],
    );
    write_blob(&socket, &after_hash, PATCHED_BYTES);
    index
}

/// Stage the minimum filesystem layout the detector classifies as
/// yarn-berry PnP: a `.pnp.cjs` file at the project root plus a
/// `.yarn/cache/` directory. The presence of `.pnp.cjs` alone is
/// enough for the detector, but ship the cache dir too so the
/// fixture mirrors what an actual yarn-berry checkout looks like.
fn make_yarn_berry_project(cwd: &Path) {
    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"yarn-berry-fixture","version":"0.0.0","private":true}"#,
    )
    .expect("write package.json");
    std::fs::write(cwd.join(".pnp.cjs"), b"// stub PnP loader\n").expect("write .pnp.cjs");
    std::fs::create_dir_all(cwd.join(".yarn").join("cache")).expect("create .yarn/cache");
}

/// Manifest-only helper for the `list`-discovery guard test. The
/// hashes are irrelevant there — `list` never resolves them — so use
/// fixed sentinels rather than the real round-trip hashes.
fn write_synthetic_manifest(socket_dir: &Path) {
    write_minimal_manifest(
        socket_dir,
        PURL,
        UUID,
        &[PatchEntry {
            file_name: "package/index.js",
            before_hash: "a".repeat(64).as_str(),
            after_hash: "b".repeat(64).as_str(),
        }],
    );
}

/// Assert the refusal envelope did NO patch work: every summary
/// counter is zero and no patch events were recorded. This is what
/// catches a regression where the yarn-PnP guard moves *after* the
/// crawl/apply step (so apply would discover/patch the staged package
/// first and only then report the error).
fn assert_no_work_done(env: &serde_json::Value) {
    let summary = env
        .get("summary")
        .unwrap_or_else(|| panic!("envelope missing summary: {env}"));
    for k in [
        "discovered",
        "downloaded",
        "applied",
        "updated",
        "skipped",
        "failed",
        "removed",
        "verified",
    ] {
        assert_eq!(
            summary.get(k).and_then(|v| v.as_u64()),
            Some(0),
            "yarn-PnP refusal must short-circuit before any work; summary.{k} != 0.\nenvelope: {env}"
        );
    }
    let events = env
        .get("events")
        .and_then(|e| e.as_array())
        .unwrap_or_else(|| panic!("envelope missing events array: {env}"));
    assert!(
        events.is_empty(),
        "yarn-PnP refusal must record no patch events.\nenvelope: {env}"
    );
}

/// Assert apply left no stage/CoW temp files behind in `pkg_dir`, and
/// that the package's own files are still present (so we know we
/// scanned the right, non-empty directory).
fn assert_pristine_package_dir(pkg_dir: &Path) {
    let names: Vec<String> = std::fs::read_dir(pkg_dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", pkg_dir.display()))
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        names.iter().any(|n| n == "package.json") && names.iter().any(|n| n == "index.js"),
        "package dir {} missing expected files, got: {names:?}",
        pkg_dir.display()
    );
    for name in &names {
        assert!(
            !name.starts_with(".socket-cow-") && !name.starts_with(".socket-stage-"),
            "yarn-PnP refusal must not leave stage/CoW litter in {}: {name}",
            pkg_dir.display()
        );
    }
}

/// The headline test: yarn-berry PnP project + apply = exit 1 with
/// `errorCode: yarn_pnp_unsupported`. JSON envelope so consumers can
/// branch deterministically on the error code.
#[test]
fn yarn_pnp_refuses_with_error_code() {
    let dir = tempfile::tempdir().unwrap();
    make_yarn_berry_project(dir.path());
    // Stage a genuinely-applicable package: if the refusal regressed,
    // apply WOULD rewrite this file. We assert below that it doesn't.
    let index = stage_applicable_package(dir.path());

    let (code, stdout, stderr) = run(dir.path(), &["apply", "--json"]);
    assert_eq!(
        code, 1,
        "expected exit 1.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let env = parse_json_envelope(&stdout);
    assert_eq!(
        json_string(&env, "command"),
        Some("apply"),
        "envelope must be the apply command's.\nenvelope: {env}"
    );
    assert_eq!(
        envelope_error_code(&env),
        Some("yarn_pnp_unsupported"),
        "expected error.code=yarn_pnp_unsupported.\nenvelope: {env}"
    );
    assert_eq!(
        json_string(&env, "status"),
        Some("error"),
        "expected status=error.\nenvelope: {env}"
    );
    // The refusal must be a clean pre-apply bail: no work counters,
    // no events, and the on-disk package left byte-identical.
    assert_no_work_done(&env);
    assert_eq!(
        std::fs::read(&index).unwrap(),
        ORIGINAL_BYTES,
        "yarn-PnP refusal must NOT patch the on-disk file; apply ran the patch engine anyway"
    );
    assert_pristine_package_dir(index.parent().unwrap());
    // The error message must mention `yarn patch` so the user knows
    // the workaround. Contract: this is part of the public CLI
    // output — don't loosen the assertion without intent.
    //
    // Require the message field to actually be PRESENT (not just
    // default to "" via `unwrap_or`, which would let a missing
    // message slip through) AND to name both the workaround
    // (`yarn patch`) and the specific layout (`Plug'n'Play`). The
    // pair pins this as the yarn-pnp refusal, not some unrelated
    // error that happens to contain the substring "yarn patch".
    let error_msg = envelope_error_message(&env)
        .unwrap_or_else(|| panic!("error.message missing from envelope: {env}"));
    assert!(
        error_msg.contains("yarn patch"),
        "error message should point at `yarn patch`, got: {error_msg}"
    );
    assert!(
        error_msg.contains("Plug'n'Play"),
        "error message should name the yarn-berry Plug'n'Play layout, got: {error_msg}"
    );
}

/// Human-output mode: same project, no `--json`. Apply still exits
/// 1; the stderr stream must mention `yarn patch` so a human reader
/// gets the same workaround pointer.
#[test]
fn yarn_pnp_refuses_in_human_mode() {
    let dir = tempfile::tempdir().unwrap();
    make_yarn_berry_project(dir.path());
    let index = stage_applicable_package(dir.path());

    let (code, stdout, stderr) = run(dir.path(), &["apply"]);
    assert_eq!(
        code, 1,
        "expected exit 1.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Human mode must not leak a JSON envelope onto stdout — the
    // refusal is a human-readable message on stderr. (Guards against
    // a regression that always prints JSON regardless of `--json`.)
    assert!(
        !stdout.contains("\"status\"") && !stdout.contains("yarn_pnp_unsupported"),
        "human mode must not emit a JSON envelope on stdout, got:\n{stdout}"
    );
    // The stderr message must be the yarn-pnp refusal specifically:
    // name both the layout (`Plug'n'Play`) and the workaround
    // (`yarn patch`). A bare `contains("yarn patch")` would accept an
    // unrelated exit-1 failure that merely mentioned the command.
    assert!(
        stderr.contains("Plug'n'Play"),
        "stderr should name the yarn-berry Plug'n'Play layout, got:\n{stderr}"
    );
    assert!(
        stderr.contains("yarn patch"),
        "stderr should point at `yarn patch`, got:\n{stderr}"
    );
    // Same pre-apply-bail guarantee as the JSON path: the genuinely
    // patchable file must be left byte-identical, with no temp litter.
    assert_eq!(
        std::fs::read(&index).unwrap(),
        ORIGINAL_BYTES,
        "yarn-PnP refusal (human mode) must NOT patch the on-disk file"
    );
    assert_pristine_package_dir(index.parent().unwrap());
}

/// Negative control: a plain npm layout (no `.pnp.cjs`) must NOT
/// surface the yarn-pnp error code. The apply may still fail for
/// unrelated reasons (no matching packages on disk, etc.) — we
/// specifically assert the error code is NOT
/// `yarn_pnp_unsupported`.
#[test]
fn npm_layout_does_not_trigger_yarn_pnp_refusal() {
    let dir = tempfile::tempdir().unwrap();
    // Plain npm: package.json + a real, fully-staged patchable
    // package under node_modules/ — no .pnp.cjs, no .yarn/cache/.
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"npm-fixture","version":"0.0.0","private":true}"#,
    )
    .unwrap();
    let index = stage_applicable_package(dir.path());

    let (code, stdout, stderr) = run(dir.path(), &["apply", "--json"]);

    // `apply --json` ALWAYS emits exactly one JSON envelope on
    // stdout — parse it. A "may or may not parse" escape hatch would
    // let an empty/garbled stdout pass vacuously, so a regression that
    // crashed apply before detection (or printed nothing) would still
    // be "green". Requiring a valid envelope proves apply ran.
    let env = parse_json_envelope(&stdout);

    // The decisive negative assertion: the yarn-pnp refusal must NOT
    // fire for a plain npm layout. Check the structured field, not
    // just a substring — this is what catches an always-on detector
    // (which would make every positive test pass while silently
    // breaking npm).
    assert_ne!(
        envelope_error_code(&env),
        Some("yarn_pnp_unsupported"),
        "npm layout must not trigger yarn-pnp refusal.\nenvelope: {env}"
    );
    // Belt-and-braces: the marker string must be absent from both
    // streams entirely.
    assert!(
        !stdout.contains("yarn_pnp_unsupported") && !stderr.contains("yarn_pnp_unsupported"),
        "npm layout should not mention yarn-pnp anywhere.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Far stronger than pinning a no-match `partialFailure`: with a
    // genuinely-applicable package on disk, the npm path must run to
    // COMPLETION and patch the file. This proves both that yarn-pnp
    // did not fire AND that the npm apply path itself still works (an
    // always-on detector that silently broke npm would fail here, not
    // pass vacuously on "nothing to do").
    assert_eq!(
        code, 0,
        "npm layout with a staged applicable package must apply cleanly (exit 0).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        json_string(&env, "status"),
        Some("success"),
        "npm layout apply should report success.\nenvelope: {env}"
    );
    assert_eq!(
        env.get("summary")
            .and_then(|s| s.get("applied"))
            .and_then(|v| v.as_u64()),
        Some(1),
        "npm layout apply should patch exactly the one staged file.\nenvelope: {env}"
    );
    // And the file on disk must actually carry the patched bytes — the
    // ultimate proof the npm path executed end to end.
    assert_eq!(
        std::fs::read(&index).unwrap(),
        PATCHED_BYTES,
        "npm layout apply must rewrite index.js to the patched bytes"
    );
}

/// `.pnp.loader.mjs` (the ESM variant) also triggers the same
/// refusal. Pinning this in case the detection table drifts and
/// only the `.cjs` form keeps working.
#[test]
fn yarn_pnp_loader_mjs_also_refuses() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"yarn-berry-esm","version":"0.0.0","private":true}"#,
    )
    .unwrap();
    // ESM PnP loader variant — newer yarn-berry installs ship this
    // instead of `.pnp.cjs`.
    std::fs::write(
        dir.path().join(".pnp.loader.mjs"),
        b"// stub PnP ESM loader\n",
    )
    .unwrap();
    let index = stage_applicable_package(dir.path());

    let (code, stdout, stderr) = run(dir.path(), &["apply", "--json"]);
    assert_eq!(
        code, 1,
        "expected exit 1.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        envelope_error_code(&env),
        Some("yarn_pnp_unsupported"),
        "`.pnp.loader.mjs` should trigger the same refusal as `.pnp.cjs`.\nenvelope: {env}"
    );
    // Full parity with the `.cjs` headline test: status + message
    // must match, so the ESM variant can't pass on the code alone
    // while emitting a degraded envelope.
    assert_eq!(
        json_string(&env, "status"),
        Some("error"),
        "expected status=error.\nenvelope: {env}"
    );
    let error_msg = envelope_error_message(&env)
        .unwrap_or_else(|| panic!("error.message missing from envelope: {env}"));
    assert!(
        error_msg.contains("yarn patch") && error_msg.contains("Plug'n'Play"),
        "error message should name `yarn patch` and the Plug'n'Play layout, got: {error_msg}"
    );
    // Pre-apply-bail parity too: no work done, staged file untouched.
    assert_no_work_done(&env);
    assert_eq!(
        std::fs::read(&index).unwrap(),
        ORIGINAL_BYTES,
        "`.pnp.loader.mjs` refusal must NOT patch the on-disk file"
    );
    assert_pristine_package_dir(index.parent().unwrap());
}

/// A guard test asserting the helper itself produced a manifest
/// the CLI can find. Without this, a refactor that breaks
/// `write_minimal_manifest` would make every other test in this
/// file pass by accident (apply would exit on "no manifest" rather
/// than on yarn-pnp detection). Running `apply` against a plain
/// project where the manifest exists but yarn-pnp markers are
/// absent should NOT report "no manifest".
#[test]
fn synthetic_manifest_is_discovered_by_cli() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"plain","version":"0.0.0","private":true}"#,
    )
    .unwrap();
    write_synthetic_manifest(&dir.path().join(".socket"));

    // `list` doesn't apply, doesn't acquire the lock, doesn't
    // detect package managers — it just reads the manifest. If
    // our synthetic manifest is well-formed, list prints it.
    let (stdout, _stderr) = assert_run_ok(dir.path(), &["list", "--json"], "list --json");
    // Parse rather than substring-match: a bare `contains(purl)`
    // would pass even if list emitted an *error* envelope that merely
    // echoed the purl. We need to prove the manifest was genuinely
    // discovered and read.
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        json_string(&env, "status"),
        Some("success"),
        "list should succeed on a well-formed manifest.\nenvelope: {env}"
    );
    assert_eq!(
        env.get("summary").and_then(|s| s.get("discovered")),
        Some(&serde_json::json!(1)),
        "list should discover exactly the one synthetic entry.\nenvelope: {env}"
    );
    // And the discovered entry must be ours — pin the purl + uuid in
    // the structured event, not just anywhere in the text.
    let events = env
        .get("events")
        .and_then(|e| e.as_array())
        .unwrap_or_else(|| panic!("envelope missing events array: {env}"));
    let found = events.iter().any(|ev| {
        json_string(ev, "purl") == Some("pkg:npm/dummy@1.0.0")
            && json_string(ev, "uuid") == Some("11111111-1111-4111-8111-111111111111")
    });
    assert!(
        found,
        "list should surface our synthetic manifest entry (purl + uuid).\nenvelope: {env}"
    );
}
