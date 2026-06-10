//! End-to-end CoW coverage that doesn't require pnpm.
//!
//! `e2e_safety_pnpm.rs` proves the CoW defense against a real pnpm
//! install — but that test is `#[ignore]`-gated, network-dependent,
//! and only exercises a single scenario (symlinked store +
//! hardlinked files). This file fills the integration-coverage gap
//! around `crates/socket-patch-core/src/patch/cow.rs` with
//! hand-rolled hardlink and symlink topologies that run fast and
//! deterministically:
//!
//!   * a hardlink pair (no pnpm) — apply mutates one side, the
//!     other stays byte-identical. The single most important CoW
//!     invariant for content-addressed package stores.
//!   * a symlink into an outside file — apply replaces the symlink
//!     with a private regular file; the target stays put.
//!   * a multi-file patch where every patched file is hardlinked.
//!   * regular files (no hardlink, no symlink) — CoW must be a
//!     no-op, no `.socket-cow-*` litter in the parent directory.
//!
//! These tests use the npm crawler against a synthetic
//! `node_modules/<pkg>/` layout (no real npm install needed). The
//! manifest and after-hash blob are staged under `.socket/` so apply
//! runs fully offline.
//!
//! Network: no. Toolchain: no. NOT `#[ignore]`. Unix-only (the
//! cow.rs hardlink path is `#[cfg(unix)]`); symlink scenarios on
//! Windows are covered by the pnpm e2e on the Windows runner.

#![cfg(unix)]

use std::path::{Path, PathBuf};

#[path = "common/mod.rs"]
mod common;

use common::{
    git_sha256, git_sha256_file, json_string, parse_json_envelope, run, write_blob,
    write_minimal_manifest, PatchEntry,
};

// ── Envelope assertions ────────────────────────────────────────────────
//
// `assert_run_ok` only proves exit==0; a regression could exit 0 while
// skipping the patch entirely. These helpers run `apply --json` and pin
// the *structured* outcome so the CoW tests fail loudly if apply ever
// stops actually applying (or applies the wrong files).

/// Run `socket-patch apply --json` in `root`, assert exit 0 and a clean
/// `status:"success"` envelope, and return the parsed envelope.
fn apply_json_ok(root: &Path) -> serde_json::Value {
    let (code, stdout, stderr) = run(root, &["apply", "--json"]);
    assert_eq!(
        code, 0,
        "apply --json must exit 0.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        json_string(&env, "status"),
        Some("success"),
        "apply must report status=success, got:\n{stdout}"
    );
    env
}

/// Assert the envelope carries one `applied` event for `purl` whose
/// `files[].path` set equals `expected_paths`, each `verified:true` and
/// `appliedVia:"blob"`, and that `summary.applied >= 1` / `failed == 0`.
/// This pins that apply genuinely took the patch-write path (a skip or
/// no-op would surface a different action / zero count).
fn assert_applied(env: &serde_json::Value, purl: &str, expected_paths: &[&str]) {
    let events = env
        .get("events")
        .and_then(|e| e.as_array())
        .unwrap_or_else(|| panic!("envelope missing events array: {env}"));
    let ev = events
        .iter()
        .find(|e| json_string(e, "purl") == Some(purl))
        .unwrap_or_else(|| panic!("no event for purl {purl} in {env}"));
    assert_eq!(
        json_string(ev, "action"),
        Some("applied"),
        "expected `applied` action for {purl}, got: {ev}"
    );
    let files = ev
        .get("files")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("applied event missing files array: {ev}"));
    let mut got: Vec<String> = files
        .iter()
        .map(|f| {
            assert_eq!(
                f.get("verified").and_then(|v| v.as_bool()),
                Some(true),
                "patched file must report verified:true, got: {f}"
            );
            assert_eq!(
                json_string(f, "appliedVia"),
                Some("blob"),
                "patched file must be applied via the staged blob, got: {f}"
            );
            json_string(f, "path")
                .unwrap_or_else(|| panic!("file event missing path: {f}"))
                .to_string()
        })
        .collect();
    got.sort();
    let mut want: Vec<String> = expected_paths.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(got, want, "applied file set mismatch for {purl}");

    let summary = env
        .get("summary")
        .unwrap_or_else(|| panic!("envelope missing summary: {env}"));
    assert!(
        summary.get("applied").and_then(|v| v.as_u64()).unwrap_or(0) >= 1,
        "summary.applied must be >=1: {env}"
    );
    assert_eq!(
        summary.get("failed").and_then(|v| v.as_u64()),
        Some(0),
        "summary.failed must be 0 on a clean apply: {env}"
    );
}

/// Assert no patch-time temp files leaked into `pkg_dir`.
///
/// Two distinct stagers write into the package directory:
///   * the atomic writer (`apply::write_atomic`) stages `.socket-stage-*`,
///   * **CoW** (`cow::write_via_stage_rename`, the hardlink and symlink
///     branches) stages `.socket-cow-*`.
/// Both must be renamed-over on success or unlinked on failure, so a
/// completed apply — success OR clean failure — must leave neither prefix
/// behind.
///
/// Crucially, this is the assertion that actually polices CoW's stage
/// cleanup: only the hardlink/symlink/multi-file scenarios drive
/// `write_via_stage_rename` and thus ever create a `.socket-cow-*` file.
/// The regular-file scenario takes the `AlreadyPrivate` fast path, which
/// never stages a CoW copy — so a CoW stage-file leak is invisible there
/// and only catchable from the link scenarios.
fn assert_no_patch_litter(pkg_dir: &Path) {
    let names: Vec<String> = std::fs::read_dir(pkg_dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", pkg_dir.display()))
        .map(|e| {
            e.unwrap_or_else(|e| panic!("dir entry error in {}: {e}", pkg_dir.display()))
                .file_name()
                .to_string_lossy()
                .to_string()
        })
        .collect();
    // Sanity: the package's own files are present, so we know we scanned
    // the right (non-empty) directory rather than passing vacuously over
    // an empty/wrong path.
    assert!(
        names.iter().any(|n| n == "package.json") && names.iter().any(|n| n == "index.js"),
        "package dir {} listing missing expected files, got: {names:?}",
        pkg_dir.display()
    );
    for name in &names {
        assert!(
            !name.starts_with(".socket-cow-") && !name.starts_with(".socket-stage-"),
            "stage / cow temp file leaked into package directory {}: {name}",
            pkg_dir.display()
        );
    }
}

const TEST_PURL: &str = "pkg:npm/cow-fixture@1.0.0";
const TEST_UUID: &str = "33333333-3333-4333-8333-333333333333";

const ORIGINAL_BYTES: &[u8] = b"module.exports = function() { return 'before'; };\n";
const PATCHED_BYTES: &[u8] = b"module.exports = function() { return 'after'; };\n";

// ── Fixture ───────────────────────────────────────────────────────────

/// Build a tempdir with `node_modules/cow-fixture/{package.json,index.js}`
/// matching `TEST_PURL`, and a `.socket/manifest.json` + after-hash
/// blob ready for `socket-patch apply` to run offline.
///
/// Returns `(project_root, index_js_path)` so callers can inspect
/// the file's hash and apply through the CLI.
struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg = dir.path().join("node_modules/cow-fixture");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{"name":"cow-fixture","version":"1.0.0"}"#,
        )
        .unwrap();
        // Note: callers materialize index.js themselves so they can
        // hardlink/symlink to it before apply runs.

        Fixture { root: dir }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }

    fn index_js(&self) -> PathBuf {
        self.root.path().join("node_modules/cow-fixture/index.js")
    }

    /// Stage the patch manifest + after-hash blob under `.socket/`.
    fn stage_patch(&self) -> (String, String) {
        let before_hash = git_sha256(ORIGINAL_BYTES);
        let after_hash = git_sha256(PATCHED_BYTES);
        let socket = self.root.path().join(".socket");
        write_minimal_manifest(
            &socket,
            TEST_PURL,
            TEST_UUID,
            &[PatchEntry {
                file_name: "package/index.js",
                before_hash: &before_hash,
                after_hash: &after_hash,
            }],
        );
        write_blob(&socket, &after_hash, PATCHED_BYTES);
        (before_hash, after_hash)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

/// **Headline invariant**: a hardlinked file outside the package
/// stays byte-identical when its sibling inside the package is
/// patched. This is exactly the pnpm content-store isolation
/// guarantee, but exercised without a pnpm dependency.
#[test]
fn apply_breaks_hardlink_before_patching() {
    let fx = Fixture::new();
    // Materialize index.js as a hardlink to an outside file. The
    // outside file represents "the pnpm content store entry" or
    // "another project's view." Without CoW, mutating index.js
    // would mutate the outside file too.
    let outside = fx.root().join("outside-store-entry.js");
    std::fs::write(&outside, ORIGINAL_BYTES).unwrap();
    std::fs::hard_link(&outside, fx.index_js()).unwrap();

    // Sanity: both files share the same inode and bytes.
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        std::fs::metadata(&outside).unwrap().nlink(),
        2,
        "hardlink fixture should produce nlink=2"
    );
    assert_eq!(git_sha256_file(&fx.index_js()), git_sha256(ORIGINAL_BYTES));

    fx.stage_patch();
    let env = apply_json_ok(fx.root());
    assert_applied(&env, TEST_PURL, &["package/index.js"]);

    // index.js (inside the package) is patched.
    assert_eq!(
        git_sha256_file(&fx.index_js()),
        git_sha256(PATCHED_BYTES),
        "package's index.js should now match the patched bytes"
    );
    // outside-store-entry.js (the shared sibling) is byte-unchanged.
    // CoW broke the link before the patch wrote.
    assert_eq!(
        git_sha256_file(&outside),
        git_sha256(ORIGINAL_BYTES),
        "the hardlinked sibling MUST stay byte-identical; CoW failure"
    );
    // The outside file is now a single-link inode.
    assert_eq!(
        std::fs::metadata(&outside).unwrap().nlink(),
        1,
        "after CoW, the outside file should be a single-link inode"
    );
    // CoW broke the link via a `.socket-cow-*` stage + rename; that
    // stage file (and the atomic-writer's `.socket-stage-*`) must be
    // gone. This is the only scenario class that exercises the CoW
    // stager, so this is where a stage-cleanup regression would show.
    assert_no_patch_litter(&fx.root().join("node_modules/cow-fixture"));
}

/// `node_modules/<pkg>/index.js` is a symlink to an outside file —
/// e.g. pnpm's `.pnpm/<pkg>@<ver>/node_modules/<pkg>` pattern,
/// minimally reproduced. After apply, the symlink is replaced with
/// a private regular file holding the patched bytes; the original
/// target stays untouched.
#[test]
fn apply_replaces_symlink_with_private_file() {
    let fx = Fixture::new();
    let outside = fx.root().join("outside-target.js");
    std::fs::write(&outside, ORIGINAL_BYTES).unwrap();
    std::os::unix::fs::symlink(&outside, fx.index_js()).unwrap();

    // Sanity: index.js is a symlink, both paths report the same bytes.
    let lstat = std::fs::symlink_metadata(fx.index_js()).unwrap();
    assert!(
        lstat.file_type().is_symlink(),
        "fixture must produce a symlink"
    );
    assert_eq!(git_sha256_file(&fx.index_js()), git_sha256(ORIGINAL_BYTES));

    fx.stage_patch();
    let env = apply_json_ok(fx.root());
    assert_applied(&env, TEST_PURL, &["package/index.js"]);

    // The link has been replaced with a regular file (CoW).
    let post = std::fs::symlink_metadata(fx.index_js()).unwrap();
    assert!(
        post.file_type().is_file() && !post.file_type().is_symlink(),
        "index.js must be a regular file after apply, not a symlink"
    );
    // Patched content on the package side.
    assert_eq!(git_sha256_file(&fx.index_js()), git_sha256(PATCHED_BYTES));
    // Original outside target untouched.
    assert_eq!(
        git_sha256_file(&outside),
        git_sha256(ORIGINAL_BYTES),
        "the symlink target must NOT have been mutated; CoW must replace the link with a private file"
    );
    // The symlink branch of CoW also stages a `.socket-cow-*` private
    // copy and renames it over the link; no litter may remain.
    assert_no_patch_litter(&fx.root().join("node_modules/cow-fixture"));
}

/// A package with TWO patched files, each hardlinked to a separate
/// outside sibling. Both inside copies should patch, both outside
/// siblings should stay byte-identical. Exercises the per-file CoW
/// in a loop.
#[test]
fn apply_breaks_hardlinks_on_multi_file_patch() {
    let fx = Fixture::new();
    let pkg = fx.root().join("node_modules/cow-fixture");
    // Two patched files: index.js + lib/helper.js, each hardlinked
    // to a sibling in the project root.
    std::fs::create_dir_all(pkg.join("lib")).unwrap();
    let outside_a = fx.root().join("outside-a.js");
    let outside_b = fx.root().join("outside-b.js");
    std::fs::write(&outside_a, b"AAA original\n").unwrap();
    std::fs::write(&outside_b, b"BBB original\n").unwrap();
    std::fs::hard_link(&outside_a, pkg.join("index.js")).unwrap();
    std::fs::hard_link(&outside_b, pkg.join("lib/helper.js")).unwrap();

    // Sanity: both fixtures are genuinely hardlinked (nlink==2) before
    // apply, so the post-apply nlink==1 checks below prove a real break
    // rather than a fixture that was never linked.
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::fs::metadata(&outside_a).unwrap().nlink(), 2);
    assert_eq!(std::fs::metadata(&outside_b).unwrap().nlink(), 2);
    let (ino_a_pre, ino_b_pre) = (
        std::fs::metadata(&outside_a).unwrap().ino(),
        std::fs::metadata(&outside_b).unwrap().ino(),
    );

    let before_a = git_sha256(b"AAA original\n");
    let after_a = git_sha256(b"AAA patched!\n");
    let before_b = git_sha256(b"BBB original\n");
    let after_b = git_sha256(b"BBB patched!\n");
    let socket = fx.root().join(".socket");
    write_minimal_manifest(
        &socket,
        TEST_PURL,
        TEST_UUID,
        &[
            PatchEntry {
                file_name: "package/index.js",
                before_hash: &before_a,
                after_hash: &after_a,
            },
            PatchEntry {
                file_name: "package/lib/helper.js",
                before_hash: &before_b,
                after_hash: &after_b,
            },
        ],
    );
    write_blob(&socket, &after_a, b"AAA patched!\n");
    write_blob(&socket, &after_b, b"BBB patched!\n");

    let env = apply_json_ok(fx.root());
    assert_applied(
        &env,
        TEST_PURL,
        &["package/index.js", "package/lib/helper.js"],
    );

    // Both inside files patched.
    assert_eq!(
        std::fs::read(pkg.join("index.js")).unwrap(),
        b"AAA patched!\n"
    );
    assert_eq!(
        std::fs::read(pkg.join("lib/helper.js")).unwrap(),
        b"BBB patched!\n"
    );
    // Both outside siblings UNCHANGED — the CoW invariant must hold
    // for every patched file, not just the first.
    assert_eq!(std::fs::read(&outside_a).unwrap(), b"AAA original\n");
    assert_eq!(std::fs::read(&outside_b).unwrap(), b"BBB original\n");

    // Each link was broken: both outside siblings are now single-link
    // inodes and retain their original inode (the inside copy moved to a
    // fresh inode, not the sibling). This pins per-file CoW for the
    // second file too — a loop that broke only the first link would
    // leave outside_b at nlink==2.
    assert_eq!(std::fs::metadata(&outside_a).unwrap().nlink(), 1);
    assert_eq!(std::fs::metadata(&outside_b).unwrap().nlink(), 1);
    assert_eq!(std::fs::metadata(&outside_a).unwrap().ino(), ino_a_pre);
    assert_eq!(std::fs::metadata(&outside_b).unwrap().ino(), ino_b_pre);
    assert_ne!(
        std::fs::metadata(pkg.join("index.js")).unwrap().ino(),
        ino_a_pre,
        "patched index.js must live in a new private inode"
    );
    assert_ne!(
        std::fs::metadata(pkg.join("lib/helper.js")).unwrap().ino(),
        ino_b_pre,
        "patched lib/helper.js must live in a new private inode"
    );

    // No CoW/stage litter in EITHER directory the per-file stagers
    // touched: index.js stages in `pkg/`, lib/helper.js stages in
    // `pkg/lib/`.
    assert_no_patch_litter(&pkg);
    let lib_litter: Vec<String> = std::fs::read_dir(pkg.join("lib"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        lib_litter.iter().any(|n| n == "helper.js"),
        "lib/ listing missing helper.js, got: {lib_litter:?}"
    );
    for name in &lib_litter {
        assert!(
            !name.starts_with(".socket-cow-") && !name.starts_with(".socket-stage-"),
            "stage / cow temp file leaked into lib/: {name}"
        );
    }
}

/// Regular files (no hardlink, no symlink) are the common case.
/// CoW must be a no-op fast path: no stage litter in the parent
/// directory, no extra inodes created, the file is rewritten in
/// place via the atomic-write path. This pins the
/// `CowAction::AlreadyPrivate` route.
#[test]
fn apply_against_regular_file_leaves_no_cow_litter() {
    let fx = Fixture::new();
    std::fs::write(fx.index_js(), ORIGINAL_BYTES).unwrap();
    fx.stage_patch();

    let env = apply_json_ok(fx.root());
    assert_applied(&env, TEST_PURL, &["package/index.js"]);

    // File patched.
    assert_eq!(git_sha256_file(&fx.index_js()), git_sha256(PATCHED_BYTES));

    // No `.socket-cow-*` or `.socket-stage-*` litter in the package
    // directory after a successful apply. (For a regular file the
    // `AlreadyPrivate` path never stages a `.socket-cow-*` copy, so this
    // mainly guards the atomic writer's `.socket-stage-*` cleanup here;
    // the hardlink/symlink tests are what cover the CoW stager.)
    assert_no_patch_litter(&fx.root().join("node_modules/cow-fixture"));
}

/// CoW happens before the atomic write — so on a hash-mismatch
/// failure (where apply errors out without writing), the hardlink
/// pair must NOT have been broken either. The original outside
/// file's inode and content must be byte-identical AND still
/// share the same inode as the package file.
///
/// Without this, a failed apply would still leave the package
/// directory in a transient "private inode but unpatched content"
/// state — semantically OK but observably different. This test
/// pins the "no observable state change on failure" promise.
#[test]
fn apply_failure_does_not_cow_or_modify() {
    let fx = Fixture::new();
    let outside = fx.root().join("outside.js");
    std::fs::write(&outside, ORIGINAL_BYTES).unwrap();
    std::fs::hard_link(&outside, fx.index_js()).unwrap();
    use std::os::unix::fs::MetadataExt;
    let pre_inode = std::fs::metadata(&outside).unwrap().ino();

    // Stage a manifest whose `after_hash` references a blob whose
    // bytes don't actually match (we write WRONG bytes under the
    // claimed hash). Apply will fail the in-memory hash check
    // BEFORE attempting any disk write or CoW.
    let before_hash = git_sha256(ORIGINAL_BYTES);
    let claimed_after_hash = git_sha256(PATCHED_BYTES);
    let socket = fx.root().join(".socket");
    write_minimal_manifest(
        &socket,
        TEST_PURL,
        TEST_UUID,
        &[PatchEntry {
            file_name: "package/index.js",
            before_hash: &before_hash,
            after_hash: &claimed_after_hash,
        }],
    );
    // Wrong bytes under the claimed hash — apply will reject.
    write_blob(&socket, &claimed_after_hash, b"deliberately wrong bytes\n");

    let (code, stdout, stderr) = run(fx.root(), &["apply", "--json"]);
    assert_eq!(
        code, 1,
        "hash-mismatch apply must exit non-zero.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // The exit code alone is not enough: a package-not-found or
    // manifest-read failure ALSO exits 1 and would leave the files
    // untouched, so the inode/content asserts below would pass
    // vacuously against a totally broken apply. Pin that the failure
    // was specifically the pre-write hash-verification gate firing —
    // that is the precondition for "CoW did not run".
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        json_string(&env, "status"),
        Some("partialFailure"),
        "hash-mismatch apply must report partialFailure: {stdout}"
    );
    let summary = env.get("summary").expect("envelope summary");
    assert_eq!(
        summary.get("applied").and_then(|v| v.as_u64()),
        Some(0),
        "nothing must have been applied: {stdout}"
    );
    assert_eq!(
        summary.get("failed").and_then(|v| v.as_u64()),
        Some(1),
        "exactly the one patch must be reported failed: {stdout}"
    );
    let ev = env
        .get("events")
        .and_then(|e| e.as_array())
        .and_then(|a| a.iter().find(|e| json_string(e, "purl") == Some(TEST_PURL)))
        .unwrap_or_else(|| panic!("no event for {TEST_PURL}: {stdout}"));
    assert_eq!(
        json_string(ev, "action"),
        Some("failed"),
        "the patch event must be a failure, not a skip: {ev}"
    );
    assert_eq!(
        json_string(ev, "errorCode"),
        Some("apply_failed"),
        "failure must be an apply-time failure (not package_not_installed): {ev}"
    );
    let err = json_string(ev, "error").unwrap_or("");
    assert!(
        err.contains("Hash verification failed before patch"),
        "failure must be the pre-write hash-verification gate, got error: {err:?}"
    );

    // Content unchanged on both sides of the hardlink.
    assert_eq!(git_sha256_file(&fx.index_js()), git_sha256(ORIGINAL_BYTES));
    assert_eq!(git_sha256_file(&outside), git_sha256(ORIGINAL_BYTES));
    // Same inode — CoW did not run because the hash check fired
    // first. The "no observable state change on failure" promise.
    assert_eq!(
        std::fs::metadata(&outside).unwrap().ino(),
        std::fs::metadata(fx.index_js()).unwrap().ino(),
        "failed apply must not break the hardlink"
    );
    assert_eq!(pre_inode, std::fs::metadata(&outside).unwrap().ino());

    // A failed apply must also leave no half-written stage/cow litter
    // behind: the hash gate fires before any stager runs, so the package
    // directory must be exactly as clean as on success.
    assert_no_patch_litter(&fx.root().join("node_modules/cow-fixture"));
}
