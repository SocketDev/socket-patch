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
    assert_run_ok, git_sha256, git_sha256_file, run, write_blob, write_minimal_manifest,
    PatchEntry,
};

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
    assert_run_ok(fx.root(), &["apply"], "socket-patch apply");

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
    assert_run_ok(fx.root(), &["apply"], "socket-patch apply");

    // The link has been replaced with a regular file (CoW).
    let post = std::fs::symlink_metadata(fx.index_js()).unwrap();
    assert!(
        post.file_type().is_file() && !post.file_type().is_symlink(),
        "index.js must be a regular file after apply, not a symlink"
    );
    // Patched content on the package side.
    assert_eq!(
        git_sha256_file(&fx.index_js()),
        git_sha256(PATCHED_BYTES)
    );
    // Original outside target untouched.
    assert_eq!(
        git_sha256_file(&outside),
        git_sha256(ORIGINAL_BYTES),
        "the symlink target must NOT have been mutated; CoW must replace the link with a private file"
    );
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

    assert_run_ok(fx.root(), &["apply"], "socket-patch apply multi-file");

    // Both inside files patched.
    assert_eq!(std::fs::read(pkg.join("index.js")).unwrap(), b"AAA patched!\n");
    assert_eq!(
        std::fs::read(pkg.join("lib/helper.js")).unwrap(),
        b"BBB patched!\n"
    );
    // Both outside siblings UNCHANGED — the CoW invariant must hold
    // for every patched file, not just the first.
    assert_eq!(std::fs::read(&outside_a).unwrap(), b"AAA original\n");
    assert_eq!(std::fs::read(&outside_b).unwrap(), b"BBB original\n");
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

    assert_run_ok(fx.root(), &["apply"], "socket-patch apply");

    // File patched.
    assert_eq!(git_sha256_file(&fx.index_js()), git_sha256(PATCHED_BYTES));

    // No `.socket-cow-*` or `.socket-stage-*` litter in the package
    // directory after a successful apply. Stage files are unlinked
    // after rename; CoW files are unlinked after CoW completes.
    let pkg_dir = fx.root().join("node_modules/cow-fixture");
    let mut entries = std::fs::read_dir(&pkg_dir).unwrap();
    while let Some(Ok(entry)) = entries.next() {
        let name = entry.file_name().to_string_lossy().to_string();
        assert!(
            !name.starts_with(".socket-cow-") && !name.starts_with(".socket-stage-"),
            "stage / cow temp file leaked into package directory: {name}"
        );
    }
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

    let (code, _stdout, _stderr) = run(fx.root(), &["apply"]);
    assert_eq!(code, 1, "hash-mismatch apply must exit non-zero");

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
}
